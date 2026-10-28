//! Shared macOS bundle update primitives: bounded archive validation, Apple
//! signature identity checks, transactional replacement and crash recovery.
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct Identity {
    pub bundle_id: &'static str,
    pub team_id: &'static str,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleInfo {
    pub identifier: String,
    pub version: String,
    pub build: String,
    pub executable: String,
}

pub fn info(bundle: &Path) -> Result<BundleInfo, String> {
    if std::fs::symlink_metadata(bundle)
        .map_err(|e| e.to_string())?
        .file_type()
        .is_symlink()
    {
        return Err("应用包不能是符号链接".into());
    }
    let value = plist::Value::from_file(bundle.join("Contents/Info.plist"))
        .map_err(|_| "应用包缺少有效 Info.plist")?;
    let dict = value.as_dictionary().ok_or("应用包信息格式无效")?;
    let field = |key: &str| {
        dict.get(key)
            .and_then(|v| v.as_string())
            .map(str::to_owned)
            .ok_or_else(|| format!("应用包缺少 {key}"))
    };
    let executable = field("CFBundleExecutable")?;
    if Path::new(&executable).components().count() != 1 || executable.starts_with('.') {
        return Err("应用可执行文件名无效".into());
    }
    Ok(BundleInfo {
        identifier: field("CFBundleIdentifier")?,
        version: field("CFBundleShortVersionString")?,
        build: field("CFBundleVersion")?,
        executable,
    })
}
pub fn numeric_version(value: &str) -> Result<Vec<u64>, String> {
    if value.is_empty() || value.len() > 80 {
        return Err("版本号无效".into());
    }
    value
        .trim_start_matches('v')
        .split('.')
        .map(|p| p.parse::<u64>().map_err(|_| "版本号必须由数字组成".into()))
        .collect()
}
pub fn newer(candidate: &str, installed: &str) -> Result<bool, String> {
    let mut left = numeric_version(candidate)?;
    let mut right = numeric_version(installed)?;
    let length = left.len().max(right.len());
    left.resize(length, 0);
    right.resize(length, 0);
    Ok(left > right)
}
fn success(mut command: Command, stage: &str) -> Result<(), String> {
    let output = command.output().map_err(|e| format!("{stage}：{e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{stage}失败（退出码 {:?}），未安装更新",
            output.status.code()
        ))
    }
}
fn verify_minimum_system(
    value: &plist::Value,
    architecture: &str,
    system_version: &str,
) -> Result<(), String> {
    let dict = value.as_dictionary().ok_or("应用包信息格式无效")?;
    let per_architecture = dict
        .get("LSMinimumSystemVersionByArchitecture")
        .and_then(plist::Value::as_dictionary)
        .and_then(|versions| versions.get(architecture));
    let minimum = per_architecture.or_else(|| dict.get("LSMinimumSystemVersion"));
    if let Some(minimum) = minimum {
        let required = minimum.as_string().ok_or("应用最低系统版本格式无效")?;
        if newer(required, system_version)? {
            return Err(format!("更新要求 macOS {required} 或更新系统，未安装"));
        }
    }
    Ok(())
}
pub fn verify_vendor(bundle: &Path, identity: &Identity) -> Result<BundleInfo, String> {
    let metadata = info(bundle)?;
    if metadata.identifier != identity.bundle_id {
        return Err("更新包身份与预期应用不符".into());
    }
    let requirement = format!(
        "=anchor apple generic and certificate leaf[subject.OU] = \"{}\" and identifier \"{}\"",
        identity.team_id, identity.bundle_id
    );
    let mut codesign = Command::new("/usr/bin/codesign");
    codesign
        .args(["--verify", "--deep", "--strict", "-R", &requirement])
        .arg(bundle);
    success(codesign, "开发者签名与应用身份校验")?;
    let mut gatekeeper = Command::new("/usr/sbin/spctl");
    gatekeeper
        .args(["--assess", "--type", "execute"])
        .arg(bundle);
    success(gatekeeper, "系统信任校验")?;
    let binary = bundle.join("Contents/MacOS").join(&metadata.executable);
    let output = Command::new("/usr/bin/lipo")
        .arg("-archs")
        .arg(binary)
        .output()
        .map_err(|e| e.to_string())?;
    let architecture = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "x86_64"
    };
    if !output.status.success()
        || !String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .any(|s| s == architecture)
    {
        return Err("更新包不支持本机架构".into());
    }
    let value = plist::Value::from_file(bundle.join("Contents/Info.plist"))
        .map_err(|_| "应用包信息无法读取")?;
    let system = Command::new("/usr/bin/sw_vers")
        .arg("-productVersion")
        .output()
        .map_err(|e| e.to_string())?;
    if !system.status.success() {
        return Err("无法确定当前 macOS 版本，未安装更新".into());
    }
    verify_minimum_system(
        &value,
        architecture,
        String::from_utf8_lossy(&system.stdout).trim(),
    )?;
    Ok(metadata)
}
pub fn running(bundle: &Path) -> bool {
    let path = bundle
        .canonicalize()
        .unwrap_or_else(|_| bundle.to_path_buf());
    let mut system = sysinfo::System::new();
    system.refresh_processes();
    system
        .processes()
        .values()
        .any(|p| p.exe().is_some_and(|exe| exe.starts_with(&path)))
}
fn relative_inside(path: &Path) -> bool {
    let mut depth = 0usize;
    for component in path.components() {
        match component {
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            Component::ParentDir if depth > 0 => depth -= 1,
            _ => return false,
        }
    }
    true
}
/// 只读校验更新包目录：路径越界、符号链接逃逸、重复路径、展开体积都挡在这里。
///
/// 这里刻意不走 `ZipArchive::extract()` / `ZipStreamReader::extract()`——那两个 API
/// 正是 2026 年三条 zip 公告（RUSTSEC-2026-0367 / -0368 / -0369）的攻击面，而本项目的
/// 解压走系统 `/usr/bin/ditto -x -k`（见 [`extract`]），zip 只用来读条目元数据。
/// 依赖已随公告对齐到 9.x（修补版本线），但「不调用 extract()」这条仍然成立：
/// 一旦改成调用 `extract()`，解压侧的路径与权限校验就得整段重做。
pub fn validate_archive(path: &Path) -> Result<(), String> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut archive = zip::ZipArchive::new(file).map_err(|_| "不是有效的 ZIP 更新包")?;
    if archive.len() > 100_000 {
        return Err("更新包文件数量超限".into());
    }
    let mut total = 0u64;
    let mut paths = std::collections::HashSet::new();
    let mut links = Vec::new();
    for index in 0..archive.len() {
        let mut item = archive.by_index(index).map_err(|_| "无法读取更新包目录")?;
        let enclosed = item.enclosed_name().ok_or("更新包包含越界路径")?;
        let has_backslash = item
            .name()
            .map_err(|_| "无法读取更新包目录")?
            .contains('\\');
        if !relative_inside(&enclosed) || has_backslash {
            return Err("更新包路径不安全".into());
        }
        // Normalise before duplicate/ancestor checks; extraction tools may follow
        // a previously created directory symlink even when both paths look safe.
        let mut normal = PathBuf::new();
        for component in enclosed.components() {
            match component {
                Component::Normal(part) => normal.push(part),
                Component::ParentDir => {
                    normal.pop();
                }
                _ => {}
            }
        }
        if !paths.insert(normal.clone()) {
            return Err("更新包包含重复路径".into());
        }
        total = total.checked_add(item.size()).ok_or("更新包大小溢出")?;
        if total > 6 * 1024 * 1024 * 1024 {
            return Err("更新包展开大小超限".into());
        }
        if item.unix_mode().is_some_and(|m| m & 0o170000 == 0o120000) {
            links.push(normal);
            let mut bytes = Vec::new();
            item.by_ref()
                .take(4097)
                .read_to_end(&mut bytes)
                .map_err(|_| "无法读取符号链接")?;
            if bytes.len() > 4096 {
                return Err("更新包符号链接超长".into());
            }
            let link = std::str::from_utf8(&bytes).map_err(|_| "更新包符号链接无效")?;
            let combined = enclosed.parent().unwrap_or(Path::new("")).join(link);
            if !relative_inside(&combined) || Path::new(link).is_absolute() {
                return Err("更新包符号链接指向包外".into());
            }
        }
    }
    if paths.iter().any(|path| {
        links
            .iter()
            .any(|link| path != link && path.starts_with(link))
    }) {
        return Err("更新包尝试通过符号链接写入文件".into());
    }
    Ok(())
}
pub fn extract(archive: &Path, directory: &Path) -> Result<PathBuf, String> {
    validate_archive(archive)?;
    let mut command = Command::new("/usr/bin/ditto");
    command.args(["-x", "-k"]).arg(archive).arg(directory);
    success(command, "解压更新包")?;
    let bundles: Vec<PathBuf> = std::fs::read_dir(directory)
        .map_err(|e| e.to_string())?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "app"))
        .collect();
    if bundles.len() != 1 {
        return Err("更新包必须包含且仅包含一个顶层 .app".into());
    }
    Ok(bundles[0].clone())
}
#[derive(Debug, Serialize, Deserialize)]
struct Journal {
    destination: PathBuf,
    backup: PathBuf,
    phase: String,
}
/// macOS atomically exchanges nonempty bundle directories. Unsupported volumes
/// fail without falling back to a sequence that makes the application disappear.
fn rename_native(from: &Path, to: &Path, flags: libc::c_uint) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;
    let from =
        std::ffi::CString::new(from.as_os_str().as_bytes()).map_err(|_| "更新路径包含空字符")?;
    let to = std::ffi::CString::new(to.as_os_str().as_bytes()).map_err(|_| "更新路径包含空字符")?;
    // Both C strings are owned by this call and valid for its duration.
    let result = unsafe { libc::renamex_np(from.as_ptr(), to.as_ptr(), flags) };
    if result == 0 {
        Ok(())
    } else {
        Err(format!(
            "原子更新操作失败：{}",
            std::io::Error::last_os_error()
        ))
    }
}
fn save_journal(path: &Path, journal: &Journal) -> Result<(), String> {
    let temporary = path.with_extension("tmp");
    let bytes = serde_json::to_vec_pretty(journal).map_err(|e| e.to_string())?;
    let mut file = std::fs::File::create(&temporary).map_err(|e| e.to_string())?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())?;
    std::fs::rename(temporary, path).map_err(|e| e.to_string())
}
/// Recover only the exact app and sibling backup recorded by this updater.
pub fn recover(
    journal_path: &Path,
    destination: &Path,
    verify: impl Fn(&Path) -> Result<(), String>,
) -> Result<(), String> {
    if !journal_path.exists() {
        return Ok(());
    }
    let journal: Journal =
        serde_json::from_slice(&std::fs::read(journal_path).map_err(|e| e.to_string())?)
            .map_err(|_| "更新恢复记录损坏；未操作应用")?;
    if journal.destination != destination
        || journal.backup.parent() != destination.parent()
        || !journal
            .backup
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with(".claudeguard-backup-"))
    {
        return Err("更新恢复记录路径不匹配；未操作应用".into());
    }
    if !destination.exists() && journal.backup.exists() {
        verify(&journal.backup)?;
        std::fs::rename(&journal.backup, destination).map_err(|e| e.to_string())?;
    } else if destination.exists() {
        if let Err(error) = verify(destination) {
            if !journal.backup.exists() {
                return Err(error);
            }
            verify(&journal.backup)?;
            rename_native(&journal.backup, destination, libc::RENAME_SWAP)?;
            // The invalid candidate remains at the recorded backup path for
            // diagnosis; never erase either application during crash recovery.
        }
    } else {
        return Err("更新应用与备份均缺失，需要人工恢复".into());
    }
    std::fs::remove_file(journal_path).map_err(|e| e.to_string())
}
pub fn replace(
    candidate: &Path,
    destination: &Path,
    journal_path: &Path,
    verify: impl Fn(&Path) -> Result<(), String>,
    is_running: impl Fn(&Path) -> bool,
) -> Result<PathBuf, String> {
    recover(journal_path, destination, &verify)?;
    verify(candidate)?;
    verify(destination)?;
    if is_running(destination) {
        return Err("应用仍在运行，等待其自行退出；不会强制结束".into());
    }
    let parent = destination.parent().ok_or("安装路径无效")?;
    let staging = tempfile::Builder::new()
        .prefix(".claudeguard-stage-")
        .tempdir_in(parent)
        .map_err(|_| "应用目录不可写，未修改已安装版本")?;
    let stage = staging.path().join("Candidate.app");
    let mut command = Command::new("/usr/bin/ditto");
    command.arg(candidate).arg(&stage);
    success(command, "准备更新副本")?;
    verify(&stage)?;
    verify(destination)?;
    if is_running(destination) {
        return Err("应用在更新准备期间启动或更新条件改变；已取消替换".into());
    }
    let name = staging
        .path()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .replace(".claudeguard-stage-", ".claudeguard-backup-");
    let backup = parent.join(format!("{name}.app"));
    let mut journal = Journal {
        destination: destination.to_path_buf(),
        backup: backup.clone(),
        phase: "prepared".into(),
    };
    save_journal(journal_path, &journal)?;
    // First reserve a unique sibling containing the candidate. Then swap it
    // atomically with the installed bundle, preserving an executable app at the
    // destination even if the process or machine stops at either boundary.
    rename_native(&stage, &backup, libc::RENAME_EXCL)?;
    if is_running(destination) {
        let _ = std::fs::rename(&backup, &stage);
        let _ = std::fs::remove_file(journal_path);
        return Err("最终安装前应用启动或更新条件改变；已取消替换".into());
    }
    rename_native(&backup, destination, libc::RENAME_SWAP)?;
    journal.phase = "swapped".into();
    let install = save_journal(journal_path, &journal).and_then(|()| verify(destination));
    if let Err(error) = install {
        rename_native(&backup, destination, libc::RENAME_SWAP)
            .map_err(|e| format!("{error}；自动回滚失败：{e}；旧版本备份仍保留"))?;
        let _ = std::fs::rename(&backup, staging.path().join("Rejected.app"));
        let _ = std::fs::remove_file(journal_path);
        return Err(error);
    }
    std::fs::remove_file(journal_path).map_err(|e| e.to_string())?;
    Ok(backup) // Deliberately retain the previous version; never erase a user's backup.
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fake_bundle(path: &Path, version: &str) {
        std::fs::create_dir_all(path.join("Contents")).unwrap();
        let mut dict = plist::Dictionary::new();
        for (k, v) in [
            ("CFBundleIdentifier", "test.bundle"),
            ("CFBundleVersion", version),
            ("CFBundleShortVersionString", version),
            ("CFBundleExecutable", "test"),
        ] {
            dict.insert(k.into(), v.into());
        }
        plist::Value::Dictionary(dict)
            .to_file_xml(path.join("Contents/Info.plist"))
            .unwrap();
    }
    #[test]
    fn replace_retains_backup_and_blocks_running_app() {
        let temp = tempfile::tempdir().unwrap();
        let old = temp.path().join("Old.app");
        let new = temp.path().join("New.app");
        let journal = temp.path().join("update.json");
        fake_bundle(&old, "1.0");
        fake_bundle(&new, "2.0");
        let verify = |p: &Path| info(p).map(|_| ());
        assert!(replace(&new, &old, &journal, verify, |_| true).is_err());
        assert_eq!(info(&old).unwrap().version, "1.0");
        let backup = replace(&new, &old, &journal, verify, |_| false).unwrap();
        assert_eq!(info(&old).unwrap().version, "2.0");
        assert_eq!(info(&backup).unwrap().version, "1.0");
        assert!(!journal.exists());
    }
    #[test]
    #[ignore = "atomically swaps the installed Claude app with a verified older backup, injects post-swap failure, and verifies rollback"]
    fn real_installed_claude_rolls_back_after_post_swap_failure() {
        let destination = Path::new("/Applications/Claude.app");
        let candidate = std::env::var_os("CG_REAL_ROLLBACK_CANDIDATE")
            .map(PathBuf::from)
            .expect("set CG_REAL_ROLLBACK_CANDIDATE to a signed older Claude.app");
        let identity = Identity {
            bundle_id: "com.anthropic.claudefordesktop",
            team_id: "Q6L2SF6YDW",
        };
        let before = verify_vendor(destination, &identity).unwrap();
        let older = verify_vendor(&candidate, &identity).unwrap();
        assert!(newer(&before.version, &older.version).unwrap());
        assert!(
            !running(destination),
            "Claude must be closed before rollback test"
        );
        let temp = tempfile::tempdir().unwrap();
        let journal = temp.path().join("real-rollback.json");
        let checks = std::sync::atomic::AtomicUsize::new(0);
        let result = replace(
            &candidate,
            destination,
            &journal,
            |path| {
                let count = checks.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                if count == 5 {
                    return Err("intentional post-swap verification failure".into());
                }
                verify_vendor(path, &identity).map(|_| ())
            },
            |_| false,
        );
        assert!(result.is_err(), "injected post-swap failure must surface");
        assert_eq!(
            verify_vendor(destination, &identity).unwrap().version,
            before.version
        );
        assert!(!journal.exists());
    }
    #[test]
    fn interrupted_swap_recovers_old_version_and_rejects_foreign_record() {
        let temp = tempfile::tempdir().unwrap();
        let old = temp.path().join("App.app");
        let backup = temp.path().join(".claudeguard-backup-test.app");
        let journal = temp.path().join("update.json");
        fake_bundle(&backup, "1.0");
        save_journal(
            &journal,
            &Journal {
                destination: old.clone(),
                backup: backup.clone(),
                phase: "old_moved".into(),
            },
        )
        .unwrap();
        recover(&journal, &old, |p| info(p).map(|_| ())).unwrap();
        assert!(old.exists());
        assert!(!backup.exists());
        save_journal(
            &journal,
            &Journal {
                destination: temp.path().join("Other.app"),
                backup,
                phase: "old_moved".into(),
            },
        )
        .unwrap();
        assert!(recover(&journal, &old, |_| Ok(())).is_err());
    }
    #[test]
    fn rejects_unsafe_paths_versions_and_unsigned_vendor_bundle() {
        assert!(!relative_inside(Path::new("../../escape")));
        assert!(!relative_inside(Path::new("/tmp/escape")));
        assert!(relative_inside(Path::new(
            "A.app/Contents/Frameworks/X.framework/Versions/Current/../A"
        )));
        assert!(newer("2.0", "1.99").unwrap());
        assert!(!newer("2.0", "2.0.0").unwrap());
        assert!(newer("bad", "1").is_err());
        let temp = tempfile::tempdir().unwrap();
        let fake = temp.path().join("Fake.app");
        fake_bundle(&fake, "1");
        assert!(verify_vendor(
            &fake,
            &Identity {
                bundle_id: "test.bundle",
                team_id: "Q6L2SF6YDW"
            }
        )
        .is_err());
    }
    #[test]
    fn archives_reject_traversal_and_symlink_escape_and_extract_valid_bundle() {
        use zip::write::SimpleFileOptions;
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("bundle.zip");
        let mut writer = zip::ZipWriter::new(std::fs::File::create(&archive).unwrap());
        writer
            .start_file("../escape", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"x").unwrap();
        writer.finish().unwrap();
        assert!(validate_archive(&archive).is_err());
        let mut writer = zip::ZipWriter::new(std::fs::File::create(&archive).unwrap());
        writer
            .add_symlink(
                "App.app/Contents/link",
                "../../../escape",
                SimpleFileOptions::default(),
            )
            .unwrap();
        writer.finish().unwrap();
        assert!(validate_archive(&archive).is_err());
        let fake = temp.path().join("Source.app");
        fake_bundle(&fake, "2.0");
        let mut writer = zip::ZipWriter::new(std::fs::File::create(&archive).unwrap());
        writer
            .start_file("App.app/Contents/Info.plist", SimpleFileOptions::default())
            .unwrap();
        writer
            .write_all(&std::fs::read(fake.join("Contents/Info.plist")).unwrap())
            .unwrap();
        writer
            .start_file(
                "App.app/Contents/Frameworks/X.framework/Versions/A/test",
                SimpleFileOptions::default(),
            )
            .unwrap();
        writer.write_all(b"test").unwrap();
        writer
            .add_symlink(
                "App.app/Contents/Frameworks/X.framework/Versions/Current",
                "A",
                SimpleFileOptions::default(),
            )
            .unwrap();
        writer.finish().unwrap();
        let extracted = extract(&archive, &temp.path().join("unpacked")).unwrap();
        assert_eq!(info(&extracted).unwrap().version, "2.0");
        assert_eq!(
            std::fs::read(extracted.join("Contents/Frameworks/X.framework/Versions/Current/test"))
                .unwrap(),
            b"test"
        );
    }
    #[test]
    fn failed_post_install_verification_rolls_back() {
        let temp = tempfile::tempdir().unwrap();
        let old = temp.path().join("Installed.app");
        let new = temp.path().join("Candidate.app");
        let journal = temp.path().join("journal.json");
        fake_bundle(&old, "1.0");
        fake_bundle(&new, "2.0");
        let verify = |p: &Path| {
            let metadata = info(p)?;
            if p == old && metadata.version == "2.0" {
                Err("injected final verification failure".into())
            } else {
                Ok(())
            }
        };
        assert!(replace(&new, &old, &journal, verify, |_| false).is_err());
        assert_eq!(info(&old).unwrap().version, "1.0");
        assert!(!journal.exists());
    }
    #[test]
    fn recovery_restores_verified_backup_after_installed_candidate_corruption() {
        let temp = tempfile::tempdir().unwrap();
        let destination = temp.path().join("App.app");
        let backup = temp.path().join(".claudeguard-backup-good.app");
        let journal = temp.path().join("journal.json");
        fake_bundle(&destination, "2.0");
        fake_bundle(&backup, "1.0");
        save_journal(
            &journal,
            &Journal {
                destination: destination.clone(),
                backup: backup.clone(),
                phase: "old_moved".into(),
            },
        )
        .unwrap();
        recover(&journal, &destination, |path| {
            if info(path)?.version == "1.0" {
                Ok(())
            } else {
                Err("corrupted candidate".into())
            }
        })
        .unwrap();
        assert_eq!(info(&destination).unwrap().version, "1.0");
        assert!(!journal.exists());
    }
    #[test]
    fn replacement_cancels_if_conditions_change_during_staging() {
        let temp = tempfile::tempdir().unwrap();
        let old = temp.path().join("Old.app");
        let new = temp.path().join("New.app");
        fake_bundle(&old, "1.0");
        fake_bundle(&new, "2.0");
        let checks = std::cell::Cell::new(0);
        let result = replace(
            &new,
            &old,
            &temp.path().join("journal.json"),
            |p| info(p).map(|_| ()),
            |_| {
                checks.set(checks.get() + 1);
                checks.get() >= 2
            },
        );
        assert!(result.is_err());
        assert_eq!(info(&old).unwrap().version, "1.0");
    }
    #[test]
    fn archive_rejects_entries_descending_from_symlinks() {
        use zip::write::SimpleFileOptions;
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("attack.zip");
        let mut writer = zip::ZipWriter::new(std::fs::File::create(&archive).unwrap());
        writer
            .add_symlink("A.app/link", "directory", SimpleFileOptions::default())
            .unwrap();
        writer
            .start_file("A.app/link/overwrite", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"unsafe").unwrap();
        writer.finish().unwrap();
        assert!(validate_archive(&archive).is_err());
    }
    #[test]
    fn atomic_exchange_always_keeps_destination_present_and_preserves_both_versions() {
        let temp = tempfile::tempdir().unwrap();
        let destination = temp.path().join("Installed.app");
        let candidate = temp.path().join("Candidate.app");
        let reserved = temp.path().join("Reserved.app");
        fake_bundle(&destination, "1.0");
        fake_bundle(&candidate, "2.0");
        rename_native(&candidate, &reserved, libc::RENAME_EXCL).unwrap();
        assert!(destination.exists());
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread_stop = stop.clone();
        let thread_observed = observed.clone();
        let watched = destination.clone();
        let reader = std::thread::spawn(move || {
            while !thread_stop.load(std::sync::atomic::Ordering::SeqCst) {
                if !watched.exists() {
                    thread_observed.store(true, std::sync::atomic::Ordering::SeqCst);
                }
            }
        });
        for _ in 0..1000 {
            rename_native(&reserved, &destination, libc::RENAME_SWAP).unwrap();
        }
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        reader.join().unwrap();
        assert!(!observed.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(info(&destination).unwrap().version, "1.0");
        assert_eq!(info(&reserved).unwrap().version, "2.0");
    }
    #[test]
    fn vendor_system_requirement_honors_architecture_override() {
        let mut dict = plist::Dictionary::new();
        dict.insert("LSMinimumSystemVersion".into(), "15.0".into());
        assert!(
            verify_minimum_system(&plist::Value::Dictionary(dict.clone()), "arm64", "14.0")
                .is_err()
        );
        assert!(
            verify_minimum_system(&plist::Value::Dictionary(dict.clone()), "arm64", "26.0").is_ok()
        );
        let mut architectures = plist::Dictionary::new();
        architectures.insert("arm64".into(), "13.0".into());
        dict.insert(
            "LSMinimumSystemVersionByArchitecture".into(),
            plist::Value::Dictionary(architectures),
        );
        assert!(
            verify_minimum_system(&plist::Value::Dictionary(dict.clone()), "arm64", "14.0").is_ok()
        );
        assert!(verify_minimum_system(&plist::Value::Dictionary(dict), "x86_64", "14.0").is_err());
    }
}
