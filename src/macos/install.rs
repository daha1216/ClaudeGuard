//! User-scoped bundle installation and LaunchAgent login startup; no root or shell.
use std::path::{Path, PathBuf};
use std::process::Command;
fn home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}
pub(crate) fn bundle_of(exe: &Path) -> Option<&Path> {
    let macos = exe.parent()?;
    let contents = macos.parent()?;
    let bundle = contents.parent()?;
    (macos.file_name()? == "MacOS"
        && contents.file_name()? == "Contents"
        && bundle.extension()? == "app")
        .then_some(bundle)
}
pub fn is_installed() -> bool {
    std::env::current_exe()
        .ok()
        .and_then(|p| bundle_of(&p).map(Path::to_path_buf))
        .is_some_and(|p| {
            p.starts_with("/Applications")
                || home().is_some_and(|h| p.starts_with(h.join("Applications")))
        })
}
pub fn install() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let src =
        bundle_of(&exe).ok_or("请先运行打包后的 ClaudeGuard.app；不支持把裸二进制作为应用安装")?;
    let dst = home()
        .ok_or("无法找到用户目录")?
        .join("Applications/ClaudeGuard.app");
    install_bundle(src, &dst)
}
fn validate_bundle(bundle: &Path) -> Result<(), String> {
    if std::fs::symlink_metadata(bundle)
        .map_err(|e| e.to_string())?
        .file_type()
        .is_symlink()
    {
        return Err("应用包是符号链接，未安装".into());
    }
    let output = Command::new("/usr/bin/codesign")
        .args(["--verify", "--deep", "--strict"])
        .arg(bundle)
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err("应用包签名校验失败，未安装；请重新打包完整应用".into());
    }
    Ok(())
}
fn install_bundle(src: &Path, dst: &Path) -> Result<PathBuf, String> {
    validate_bundle(src)?;
    if src == dst {
        return Ok(dst.to_path_buf());
    }
    // symlink_metadata catches dangling links too. Final publication also refuses
    // replacement atomically, including a destination created while ditto runs.
    match std::fs::symlink_metadata(dst) {
        Ok(_) => {
            return Err("安装目标已存在；请退出旧版本并在 Finder 中手动替换，未覆盖任何文件".into())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.to_string()),
    }
    let parent = dst.parent().ok_or("安装目标目录无效")?;
    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let staging = tempfile::Builder::new()
        .prefix(".claudeguard-install-")
        .tempdir_in(parent)
        .map_err(|e| e.to_string())?;
    let staged = staging.path().join("ClaudeGuard.app");
    let out = Command::new("/usr/bin/ditto")
        .arg(src)
        .arg(&staged)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err("复制应用失败，请检查目标目录权限；未留下不完整应用".into());
    }
    validate_bundle(&staged)?;
    publish_exclusive(&staged, dst)?;
    Ok(dst.to_path_buf())
}
fn publish_exclusive(src: &Path, dst: &Path) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;
    let source =
        std::ffi::CString::new(src.as_os_str().as_bytes()).map_err(|_| "应用路径含无效字符")?;
    let destination =
        std::ffi::CString::new(dst.as_os_str().as_bytes()).map_err(|_| "安装路径含无效字符")?;
    if unsafe { libc::renamex_np(source.as_ptr(), destination.as_ptr(), libc::RENAME_EXCL) } == 0 {
        Ok(())
    } else {
        Err(format!(
            "无法完成安装（{}）；未覆盖目标",
            std::io::Error::last_os_error()
        ))
    }
}

pub fn uninstall() -> Result<(), String> {
    let _ = crate::netcut::restore();
    let _ = crate::guard::firewall_release();
    crate::macos::autostart::set_enabled(false).map_err(|error| {
        format!(
            "登录自启未移除：{error}。请先解决登录项问题，再在 Finder 删除应用；配置与日志保留。"
        )
    })?;
    println!("已移除登录自启。请退出后在 Finder 删除 ClaudeGuard.app；配置与日志保留。");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bundle_install_is_complete_and_never_overwrites() {
        let temporary = tempfile::tempdir().unwrap();
        let src = temporary.path().join("源 & source.app");
        let contents = src.join("Contents");
        std::fs::create_dir_all(contents.join("MacOS")).unwrap();
        std::fs::write(contents.join("Info.plist"), r#"<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.daha.claudeguard.install-test</string><key>CFBundleExecutable</key><string>fixture</string><key>CFBundlePackageType</key><string>APPL</string></dict></plist>"#).unwrap();
        std::fs::copy("/bin/echo", contents.join("MacOS/fixture")).unwrap();
        assert!(Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-"])
            .arg(&src)
            .output()
            .unwrap()
            .status
            .success());
        let dst = temporary.path().join("Applications/ClaudeGuard.app");
        assert_eq!(install_bundle(&src, &dst).unwrap(), dst);
        assert!(dst.join("Contents/MacOS/fixture").is_file());
        validate_bundle(&dst).unwrap();
        assert!(install_bundle(&src, &dst).is_err());
        assert_eq!(install_bundle(&dst, &dst).unwrap(), dst);
        let link = temporary.path().join("dangling.app");
        std::os::unix::fs::symlink("missing", &link).unwrap();
        assert!(install_bundle(&src, &link).is_err());
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        let race_source = temporary.path().join("race-source");
        std::fs::create_dir(&race_source).unwrap();
        assert!(publish_exclusive(&race_source, &dst).is_err());
        assert!(race_source.exists());
        // A broken source is rejected before creating any destination.
        std::fs::write(contents.join("MacOS/fixture"), b"damaged").unwrap();
        let broken = temporary.path().join("broken.app");
        assert!(install_bundle(&src, &broken).is_err());
        assert!(!broken.exists());
        assert_eq!(std::fs::read_dir(dst.parent().unwrap()).unwrap().count(), 1);
    }
}
