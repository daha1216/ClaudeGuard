//! Authenticated macOS self updates. A release must supply a Minisign-signed
//! manifest and a complete ZIP. The trust root is compiled in, never downloaded.
use super::{Asset, Release};
use crate::{config::Config, macos::package};
use minisign_verify::{PublicKey, Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const LIMIT: u64 = 1024 * 1024 * 1024;
const ID: &str = "com.daha.claudeguard";
#[derive(Debug, Serialize, Deserialize)]
struct Manifest {
    version: String,
    architecture: String,
    url: String,
    size: u64,
    sha256: String,
}
fn architecture() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "x86_64"
    }
}
fn public_key() -> Result<PublicKey, String> {
    let encoded = option_env!("CG_MACOS_UPDATE_PUBLIC_KEY")
        .filter(|s| !s.trim().is_empty())
        .ok_or("macOS 自更新未配置维护者 Minisign 公钥；请手动安装经过验证的版本")?;
    PublicKey::from_base64(encoded.trim()).map_err(|_| "内置更新公钥无效".into())
}
fn name(release: &Release) -> String {
    format!(
        "ClaudeGuard-v{}-macos-{}.zip",
        release.version(),
        architecture()
    )
}
pub fn asset(release: &Release) -> Option<&Asset> {
    public_key().ok()?;
    let name = name(release);
    release
        .assets
        .iter()
        .find(|a| a.name == name && a.size > 0 && a.size <= LIMIT)
        .filter(|_| {
            release
                .assets
                .iter()
                .any(|a| a.name == format!("{name}.json"))
        })
        .filter(|_| {
            release
                .assets
                .iter()
                .any(|a| a.name == format!("{name}.json.minisig"))
        })
}
pub fn unavailable_reason() -> String {
    public_key()
        .err()
        .unwrap_or_else(|| "发布页缺少本架构完整 Mac ZIP、已签名清单或签名文件".into())
}
fn allowed_url(value: &str) -> Result<(), String> {
    let url = url::Url::parse(value).map_err(|_| "更新 URL 无效")?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port_or_known_default() != Some(443)
        || url.fragment().is_some()
    {
        return Err("更新地址必须是不带凭据的 HTTPS 官方源".into());
    }
    match url.host_str() {
        Some("github.com")
            if url
                .path()
                .starts_with("/daha1216/ClaudeGuard/releases/download/") =>
        {
            Ok(())
        }
        Some("release-assets.githubusercontent.com" | "objects.githubusercontent.com") => Ok(()),
        _ => Err("更新地址不属于维护者仓库或 GitHub 官方下载 CDN".into()),
    }
}
fn response(agent: &ureq::Agent, location: &str) -> Result<ureq::Response, String> {
    let mut location = location.to_owned();
    for _ in 0..6 {
        allowed_url(&location)?;
        let response = agent
            .get(&location)
            .set("User-Agent", super::USER_AGENT)
            .timeout(Duration::from_secs(300))
            .call()
            .map_err(|_| "请求 Mac 更新资源失败")?;
        if (300..400).contains(&response.status()) {
            location = response
                .header("Location")
                .ok_or("更新下载重定向缺少地址")?
                .to_owned();
        } else {
            return Ok(response);
        }
    }
    Err("更新下载重定向次数超限".into())
}
fn small(agent: &ureq::Agent, url: &str) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    response(agent, url)?
        .into_reader()
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 65536 {
        return Err("更新清单或签名过大".into());
    }
    Ok(bytes)
}
fn authenticated_manifest(
    bytes: &[u8],
    signature: &[u8],
    key: &PublicKey,
) -> Result<Manifest, String> {
    if bytes.len() > 65536 || signature.len() > 65536 {
        return Err("更新清单或签名过大".into());
    }
    let sig = Signature::decode(std::str::from_utf8(signature).map_err(|_| "更新签名编码无效")?)
        .map_err(|_| "更新签名格式无效")?;
    key.verify(bytes, &sig, false)
        .map_err(|_| "维护者更新签名校验失败，未安装")?;
    let manifest: Manifest = serde_json::from_slice(bytes).map_err(|_| "已签名更新清单格式无效")?;
    package::numeric_version(&manifest.version)?;
    allowed_url(&manifest.url)?;
    if manifest.architecture != architecture()
        || manifest.size == 0
        || manifest.size > LIMIT
        || manifest.sha256.len() != 64
        || !manifest.sha256.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("已签名更新清单架构、大小或摘要无效".into());
    }
    Ok(manifest)
}
fn verify_archive(path: &Path, manifest: &Manifest) -> Result<(), String> {
    let mut file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    if file.metadata().map_err(|e| e.to_string())?.len() != manifest.size {
        return Err("更新包大小不符".into());
    }
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let size = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if size == 0 {
            break;
        }
        hash.update(&buffer[..size]);
    }
    if crate::update::hex_lower(&hash.finalize()) != manifest.sha256.to_ascii_lowercase() {
        return Err("更新包 SHA256 校验失败".into());
    }
    Ok(())
}
fn transfer(
    mut reader: impl Read,
    archive: &Path,
    manifest: &Manifest,
    mut progress: impl FnMut(u64, u64),
) -> Result<(), String> {
    let mut file = std::fs::File::create(archive).map_err(|e| e.to_string())?;
    let mut done = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let count = reader.read(&mut buffer).map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        done += count as u64;
        if done > manifest.size {
            return Err("更新下载超出已签名大小".into());
        }
        file.write_all(&buffer[..count])
            .map_err(|e| e.to_string())?;
        progress(done, manifest.size);
    }
    file.sync_all().map_err(|e| e.to_string())?;
    verify_archive(archive, manifest)
}
pub fn download(
    cfg: &Config,
    requested_url: &str,
    requested_size: u64,
    mut progress: impl FnMut(u64, u64),
) -> Result<PathBuf, String> {
    let key = public_key()?;
    // Recheck upstream: a renderer-provided URL alone never authorizes installation.
    let release = super::check_latest(cfg)?;
    let asset = asset(&release).ok_or_else(unavailable_reason)?;
    if asset.browser_download_url != requested_url || asset.size != requested_size {
        return Err("更新资源已变化，请重新检查更新".into());
    }
    let manifest_url = release
        .assets
        .iter()
        .find(|a| a.name == format!("{}.json", asset.name))
        .unwrap()
        .browser_download_url
        .clone();
    let signature_url = release
        .assets
        .iter()
        .find(|a| a.name == format!("{}.json.minisig", asset.name))
        .unwrap()
        .browser_download_url
        .clone();
    let fetch = |agent: &ureq::Agent,
                 progress: &mut dyn FnMut(u64, u64)|
     -> Result<PathBuf, String> {
        let bytes = small(agent, &manifest_url)?;
        let signature = small(agent, &signature_url)?;
        let manifest = authenticated_manifest(&bytes, &signature, &key)?;
        if manifest.url != asset.browser_download_url
            || manifest.size != asset.size
            || manifest.version != release.version()
            || !package::newer(&manifest.version, super::current_version())?
        {
            return Err("已签名清单与发布资产不符或版本不更新".into());
        }
        let directory = tempfile::Builder::new()
            .prefix("claudeguard-self-update-")
            .tempdir()
            .map_err(|e| e.to_string())?;
        let archive = directory.path().join("update.zip");
        transfer(
            response(agent, &manifest.url)?.into_reader(),
            &archive,
            &manifest,
            progress,
        )?;
        std::fs::write(directory.path().join("manifest.json"), bytes).map_err(|e| e.to_string())?;
        std::fs::write(directory.path().join("manifest.minisig"), signature)
            .map_err(|e| e.to_string())?;
        let _ = directory.keep();
        Ok(archive)
    };
    let direct = || {
        ureq::AgentBuilder::new()
            .redirects(0)
            .timeout_connect(Duration::from_secs(10))
            .try_proxy_from_env(false)
    };
    if let Ok(proxy) = ureq::Proxy::new(format!("http://{}:{}", cfg.proxy_host, cfg.proxy_port)) {
        if let Ok(path) = fetch(&direct().proxy(proxy).build(), &mut progress) {
            return Ok(path);
        }
    }
    fetch(&direct().build(), &mut progress)
}
fn verify_bundle(path: &Path) -> Result<(), String> {
    if package::info(path)?.identifier != ID {
        return Err("更新应用身份错误".into());
    }
    let status = Command::new("/usr/bin/codesign")
        .args(["--verify", "--deep", "--strict"])
        .arg(path)
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err("完整应用包代码签名校验失败".into());
    }
    let binary = path
        .join("Contents/MacOS")
        .join(package::info(path)?.executable);
    let output = Command::new("/usr/bin/lipo")
        .arg("-archs")
        .arg(binary)
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success()
        || !String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .any(|a| a == architecture())
    {
        return Err("更新包不支持本机架构".into());
    }
    Ok(())
}
fn install(
    archive: &Path,
    destination: &Path,
    key: &PublicKey,
    is_running: impl Fn(&Path) -> bool,
) -> Result<PathBuf, String> {
    install_verified(archive, destination, key, is_running, verify_bundle)
}
fn install_verified(
    archive: &Path,
    destination: &Path,
    key: &PublicKey,
    is_running: impl Fn(&Path) -> bool,
    verify: impl Fn(&Path) -> Result<(), String>,
) -> Result<PathBuf, String> {
    let directory = archive.parent().ok_or("更新缓存路径无效")?;
    let manifest = authenticated_manifest(
        &std::fs::read(directory.join("manifest.json")).map_err(|e| e.to_string())?,
        &std::fs::read(directory.join("manifest.minisig")).map_err(|e| e.to_string())?,
        key,
    )?;
    verify_archive(archive, &manifest)?;
    let staging = tempfile::tempdir().map_err(|e| e.to_string())?;
    let candidate = package::extract(archive, staging.path())?;
    let info = package::info(&candidate)?;
    if info.version != manifest.version
        || !package::newer(&info.version, &package::info(destination)?.version)?
    {
        return Err("应用包版本与签名清单不符或不是升级".into());
    }
    package::replace(
        &candidate,
        destination,
        &destination
            .parent()
            .ok_or("应用目录无效")?
            .join(".claudeguard-self-update.json"),
        verify,
        is_running,
    )
}
static INSTALL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
struct CacheCleanup<'a>(&'a Path);
impl Drop for CacheCleanup<'_> {
    fn drop(&mut self) {
        cleanup_cache(self.0);
    }
}
pub fn apply_update(archive: &Path, spawn_new: bool) -> Result<(), String> {
    let _lock = INSTALL_LOCK
        .try_lock()
        .map_err(|_| "自身更新或恢复正在执行，请稍后再试")?;
    let _cleanup = CacheCleanup(archive);
    let current = std::env::current_exe().map_err(|e| e.to_string())?;
    let destination = current
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .filter(|p| p.extension().is_some_and(|e| e == "app"))
        .ok_or("必须从完整已安装 .app 运行才能自更新")?;
    let pid = std::process::id();
    let birth = if spawn_new {
        Some(process_birth(pid)?)
    } else {
        None
    };
    install(archive, destination, &public_key()?, |bundle| {
        let mut system = sysinfo::System::new();
        system.refresh_processes();
        system.processes().iter().any(|(p, proc)| {
            p.as_u32() != pid && proc.exe().is_some_and(|exe| exe.starts_with(bundle))
        })
    })?;
    if let Some(birth) = birth {
        spawn_relaunch(destination, pid, &birth)?;
    }
    Ok(())
}
/// Read the parent identity once, before any bundle replacement.
fn process_birth(pid: u32) -> Result<String, String> {
    let output = Command::new("/bin/ps")
        .args(["-p", &pid.to_string(), "-o", "lstart="])
        .output()
        .map_err(|e| e.to_string())?;
    // macOS ps pads lstart with trailing spaces. Shell $(...) removes only
    // newlines, so trim_end() here would make every live identity mismatch.
    let birth = String::from_utf8(output.stdout)
        .map_err(|_| "进程身份编码无效")?
        .trim_end_matches(['\r', '\n'])
        .to_owned();
    if !output.status.success() || birth.trim().is_empty() {
        return Err("无法确认自身进程身份，未安装更新".into());
    }
    Ok(birth)
}
/// Wait for this exact process instance to exit, then ask LaunchServices to
/// launch the complete application once. A reused PID is never signalled.
fn spawn_relaunch(bundle: &Path, pid: u32, birth: &str) -> Result<std::process::Child, String> {
    spawn_relaunch_with_timeout(bundle, pid, birth, 60)
}
fn spawn_relaunch_with_timeout(
    bundle: &Path,
    pid: u32,
    birth: &str,
    seconds: u32,
) -> Result<std::process::Child, String> {
    if pid <= 1
        || birth.trim().is_empty()
        || birth.contains(['\n', '\r', '\0'])
        || !(1..=60).contains(&seconds)
    {
        return Err("重启助手进程身份或等待期限无效".into());
    }
    let bundle = bundle
        .canonicalize()
        .map_err(|e| format!("重启应用路径无效：{e}"))?;
    if bundle
        .extension()
        .is_none_or(|extension| extension != "app")
    {
        return Err("重启需要完整.app路径".into());
    }
    package::info(&bundle)?;
    // Positional arguments avoid treating application paths/identities as shell
    // source. Exit 75 signals a live parent that did not exit within the limit.
    Command::new("/bin/sh")
        .arg("-c")
        .arg(include_str!("../../native/relaunch.sh"))
        .arg("claudeguard-relaunch")
        .arg(pid.to_string())
        .arg(birth)
        .arg(bundle)
        .arg(seconds.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("更新已安装但重启助手启动失败：{e}；请手动打开"))
}
fn cleanup_cache(archive: &Path) {
    if let Some(directory) = archive.parent() {
        let parent_ok = directory.parent().and_then(|p| p.canonicalize().ok())
            == std::env::temp_dir().canonicalize().ok();
        let name_ok = directory
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with("claudeguard-self-update-"));
        if parent_ok
            && name_ok
            && directory
                .symlink_metadata()
                .is_ok_and(|m| !m.file_type().is_symlink())
        {
            let _ = std::fs::remove_dir_all(directory);
        }
    }
}
pub fn recover_current() -> Result<(), String> {
    let _lock = INSTALL_LOCK
        .try_lock()
        .map_err(|_| "自身更新正在执行，暂不恢复")?;
    let current = std::env::current_exe().map_err(|e| e.to_string())?;
    let Some(bundle) = current
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .filter(|p| p.extension().is_some_and(|e| e == "app"))
    else {
        return Ok(());
    };
    package::recover(
        &bundle
            .parent()
            .ok_or("应用目录无效")?
            .join(".claudeguard-self-update.json"),
        bundle,
        verify_bundle,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    pub(super) fn signed_manifest(
        manifest: &Manifest,
        pair: &minisign::KeyPair,
    ) -> (Vec<u8>, Vec<u8>) {
        let bytes = serde_json::to_vec(manifest).unwrap();
        let signature = minisign::sign(
            Some(&pair.pk),
            &pair.sk,
            Cursor::new(&bytes),
            Some("ClaudeGuard ephemeral test"),
            None,
        )
        .unwrap()
        .into_string();
        (bytes, signature.into_bytes())
    }
    fn key(pair: &minisign::KeyPair) -> PublicKey {
        PublicKey::from_base64(&pair.pk.to_base64()).unwrap()
    }
    fn manifest() -> Manifest {
        Manifest {
        version:"999.0.0".into(), architecture:architecture().into(),
        url:"https://github.com/daha1216/ClaudeGuard/releases/download/v999.0.0/ClaudeGuard-test.zip".into(),
        size:1,sha256:"0".repeat(64),
    }
    }
    #[test]
    fn pinned_signature_rejects_tampering_wrong_key_and_unsafe_addresses() {
        // Ephemeral test-only signing keys remain in memory and are never output.
        let pair = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let other = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let (mut bytes, sig) = signed_manifest(&manifest(), &pair);
        assert!(authenticated_manifest(&bytes, &sig, &key(&pair)).is_ok());
        assert!(authenticated_manifest(&bytes, &sig, &key(&other)).is_err());
        bytes[0] ^= 1;
        assert!(authenticated_manifest(&bytes, &sig, &key(&pair)).is_err());
        for address in [
            "http://github.com/daha1216/ClaudeGuard/releases/download/v1/a",
            "https://example.com/a",
            "https://github.com/other/repo/releases/download/v1/a",
            "https://user@github.com/daha1216/ClaudeGuard/releases/download/v1/a",
            "https://github.com:444/daha1216/ClaudeGuard/releases/download/v1/a",
        ] {
            let mut data = manifest();
            data.url = address.into();
            let (bytes, sig) = signed_manifest(&data, &pair);
            assert!(
                authenticated_manifest(&bytes, &sig, &key(&pair)).is_err(),
                "{address}"
            );
        }
        let mut data = manifest();
        data.architecture = "unsupported".into();
        let (bytes, sig) = signed_manifest(&data, &pair);
        assert!(authenticated_manifest(&bytes, &sig, &key(&pair)).is_err());
    }
    fn bundle(path: &Path, version: &str) {
        std::fs::create_dir_all(path.join("Contents/MacOS")).unwrap();
        let mut compiler = Command::new("/usr/bin/clang")
            .args(["-x", "c", "-", "-arch", architecture(), "-o"])
            .arg(path.join("Contents/MacOS/test"))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        compiler
            .stdin
            .take()
            .unwrap()
            .write_all(b"int main(void) { return 0; }\n")
            .unwrap();
        assert!(compiler.wait().unwrap().success());
        let mut fields = plist::Dictionary::new();
        for (k, v) in [
            ("CFBundleIdentifier", ID),
            ("CFBundleShortVersionString", version),
            ("CFBundleVersion", version),
            ("CFBundleExecutable", "test"),
        ] {
            fields.insert(k.into(), v.into());
        }
        plist::Value::Dictionary(fields)
            .to_file_xml(path.join("Contents/Info.plist"))
            .unwrap();
        assert!(Command::new("/usr/bin/codesign")
            .args(["--force", "--deep", "--sign", "-", "--timestamp=none"])
            .arg(path)
            .output()
            .unwrap()
            .status
            .success());
    }
    fn fixture(directory: &Path, pair: &minisign::KeyPair) -> PathBuf {
        let source = directory.join("source/ClaudeGuard.app");
        bundle(&source, "999.0.0");
        let archive = directory.join("update.zip");
        assert!(Command::new("/usr/bin/ditto")
            .args(["-c", "-k", "--keepParent"])
            .arg(&source)
            .arg(&archive)
            .status()
            .unwrap()
            .success());
        let data = std::fs::read(&archive).unwrap();
        let mut manifest = manifest();
        manifest.size = data.len() as u64;
        manifest.sha256 = crate::update::hex_lower(&Sha256::digest(&data));
        let (bytes, sig) = signed_manifest(&manifest, pair);
        std::fs::write(directory.join("manifest.json"), bytes).unwrap();
        std::fs::write(directory.join("manifest.minisig"), sig).unwrap();
        archive
    }
    #[test]
    fn signed_complete_bundle_installs_retains_backup_and_refuses_running_or_downgrade() {
        let directory = tempfile::tempdir().unwrap();
        let pair = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let archive = fixture(directory.path(), &pair);
        let installed = directory.path().join("Installed.app");
        bundle(&installed, "1.0.0");
        assert!(install(&archive, &installed, &key(&pair), |_| true).is_err());
        assert_eq!(package::info(&installed).unwrap().version, "1.0.0");
        let backup = install(&archive, &installed, &key(&pair), |_| false).unwrap();
        assert_eq!(package::info(&installed).unwrap().version, "999.0.0");
        assert_eq!(package::info(&backup).unwrap().version, "1.0.0");
        verify_bundle(&installed).unwrap();
        verify_bundle(&backup).unwrap();
        assert!(install(&archive, &installed, &key(&pair), |_| false).is_err());
    }
    #[test]
    fn corrupt_download_or_signed_wrong_version_never_replaces_application() {
        let directory = tempfile::tempdir().unwrap();
        let pair = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let archive = fixture(directory.path(), &pair);
        let installed = directory.path().join("Installed.app");
        bundle(&installed, "1.0.0");
        let original = std::fs::read(&archive).unwrap();
        let mut corrupt = original.clone();
        corrupt[20] ^= 0xff;
        std::fs::write(&archive, corrupt).unwrap();
        assert!(install(&archive, &installed, &key(&pair), |_| false).is_err());
        assert_eq!(package::info(&installed).unwrap().version, "1.0.0");
        std::fs::write(&archive, &original).unwrap();
        let mut data = manifest();
        data.version = "998.0.0".into();
        data.size = original.len() as u64;
        data.sha256 = crate::update::hex_lower(&Sha256::digest(&original));
        let (bytes, sig) = signed_manifest(&data, &pair);
        std::fs::write(directory.path().join("manifest.json"), bytes).unwrap();
        std::fs::write(directory.path().join("manifest.minisig"), sig).unwrap();
        assert!(install(&archive, &installed, &key(&pair), |_| false).is_err());
        assert_eq!(package::info(&installed).unwrap().version, "1.0.0");
    }
    #[test]
    fn manifest_requires_official_source_and_trust_root() {
        // No runtime environment variable can replace the compiled trust root.
        if option_env!("CG_MACOS_UPDATE_PUBLIC_KEY").is_none() {
            assert!(public_key().is_err());
        }
        assert!(allowed_url("https://release-assets.githubusercontent.com/a").is_ok());
        assert!(allowed_url("file:///tmp/update.zip").is_err());
    }
    #[test]
    fn authenticated_install_failure_restores_previous_signed_bundle() {
        let directory = tempfile::tempdir().unwrap();
        let pair = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let archive = fixture(directory.path(), &pair);
        let installed = directory.path().join("Installed.app");
        bundle(&installed, "1.0.0");
        let result = install_verified(
            &archive,
            &installed,
            &key(&pair),
            |_| false,
            |path| {
                verify_bundle(path)?;
                if path == installed && package::info(path)?.version == "999.0.0" {
                    return Err("injected post-install integrity failure".into());
                }
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(package::info(&installed).unwrap().version, "1.0.0");
        verify_bundle(&installed).unwrap();
        assert!(!directory
            .path()
            .join(".claudeguard-self-update.json")
            .exists());
    }
}

#[cfg(test)]
mod delivery_tests {
    use super::*;
    #[test]
    fn bounded_http_download_rejects_truncation_and_oversize() {
        let directory = tempfile::tempdir().unwrap();
        let body = b"isolated self update download fixture";
        let manifest = Manifest {
            version: "999.0.0".into(),
            architecture: architecture().into(),
            url: "https://github.com/daha1216/ClaudeGuard/releases/download/v999.0.0/test.zip"
                .into(),
            size: body.len() as u64,
            sha256: crate::update::hex_lower(&Sha256::digest(body)),
        };
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = [0u8; 4096];
            assert!(socket.read(&mut request).unwrap() > 0);
            write!(
                socket,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            socket.write_all(body).unwrap();
        });
        // Loopback transport exercises streaming; production URL policy is never relaxed.
        let response = ureq::AgentBuilder::new()
            .try_proxy_from_env(false)
            .build()
            .get(&format!("http://{address}/fixture"))
            .call()
            .unwrap();
        let archive = directory.path().join("received.zip");
        let mut progress = 0;
        transfer(response.into_reader(), &archive, &manifest, |done, _| {
            progress = done
        })
        .unwrap();
        assert_eq!(progress, manifest.size);
        server.join().unwrap();
        assert!(transfer(&body[..body.len() - 1], &archive, &manifest, |_, _| {}).is_err());
        let mut extra = body.to_vec();
        extra.push(0);
        assert!(transfer(extra.as_slice(), &archive, &manifest, |_, _| {}).is_err());
    }
}

#[cfg(test)]
#[path = "../../tests/macos-relaunch/acceptance.rs"]
mod relaunch_tests;
