//! Transactional user LaunchAgent. launchd manages `open`, never the guard process,
//! so disabling this job cannot kill the application before cleanup.
use std::path::{Path, PathBuf};
use std::process::Command;
const LABEL: &str = "com.daha.claudeguard";

fn domain() -> String {
    format!("gui/{}", unsafe { libc::getuid() })
}
fn target(label: &str) -> String {
    format!("{}/{label}", domain())
}
fn registered(label: &str) -> bool {
    Command::new("/bin/launchctl")
        .args(["print", &target(label)])
        .output()
        .is_ok_and(|o| o.status.success())
}
fn launchctl(args: &[&str]) -> Result<(), String> {
    let output = Command::new("/bin/launchctl")
        .args(args)
        .output()
        .map_err(|e| format!("无法运行 launchctl：{e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "登录项操作失败（launchctl 退出码 {:?}）；请检查系统设置的登录项权限",
            output.status.code()
        ))
    }
}
fn definition(label: &str, arguments: &[String]) -> plist::Value {
    let mut values = plist::Dictionary::new();
    values.insert("Label".into(), label.into());
    values.insert(
        "ProgramArguments".into(),
        plist::Value::Array(arguments.iter().map(|a| a.as_str().into()).collect()),
    );
    values.insert("RunAtLoad".into(), true.into());
    values.insert("KeepAlive".into(), false.into());
    values.insert("ProcessType".into(), "Background".into());
    plist::Value::Dictionary(values)
}
fn write_atomic(path: &Path, value: &plist::Value) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let parent = path.parent().ok_or("登录项路径无效")?;
    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().unwrap().to_string_lossy(),
        std::process::id()
    ));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|e| e.to_string())?;
        value.to_writer_xml(&mut file).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        std::fs::rename(&temporary, path).map_err(|e| e.to_string())
    })();
    if temporary.exists() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}
fn remove_registration(label: &str) -> Result<(), String> {
    if registered(label) {
        launchctl(&["bootout", &target(label)])?;
    }
    if registered(label) {
        return Err("登录项仍处于注册状态，未报告关闭成功".into());
    }
    Ok(())
}
fn apply(path: &Path, label: &str, arguments: &[String], enabled: bool) -> Result<(), String> {
    // Internal callers supply the label; never unload an arbitrary user's agent.
    if !label.starts_with("com.daha.claudeguard") {
        return Err("登录项标识无效".into());
    }
    let old = match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err("登录项文件是符号链接，未修改".into())
        }
        Ok(_) => Some(std::fs::read(path).map_err(|e| e.to_string())?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.to_string()),
    };
    let was_registered = registered(label);
    // Old previews launched the binary directly. Don't unload a legacy job that
    // may own this process: that could terminate it during the transaction.
    if was_registered {
        let old_plist = old
            .as_ref()
            .and_then(|bytes| plist::Value::from_reader(std::io::Cursor::new(bytes)).ok());
        let launcher = old_plist
            .as_ref()
            .and_then(|p| p.as_dictionary())
            .and_then(|d| d.get("ProgramArguments"))
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|v| v.as_string());
        if launcher != Some("/usr/bin/open") && label == LABEL {
            return Err("旧版登录任务直接托管守护器。请先退出旧版并移除旧登录项，再重新开启；未终止当前应用".into());
        }
    }
    if !enabled {
        remove_registration(label)?;
        if path.exists() {
            std::fs::remove_file(path).map_err(|e| e.to_string())?;
        }
        return Ok(());
    }
    let next = definition(label, arguments);
    let operation = (|| {
        remove_registration(label)?;
        write_atomic(path, &next)?;
        let path_text = path.to_str().ok_or("登录项路径不是 UTF-8")?;
        launchctl(&["bootstrap", &domain(), path_text])?;
        if !registered(label) {
            return Err("登录项未完成注册".into());
        }
        Ok(())
    })();
    if let Err(error) = operation {
        let _ = remove_registration(label);
        match old {
            Some(bytes) => {
                let _ = std::fs::write(path, bytes);
                if was_registered {
                    let _ = launchctl(&["bootstrap", &domain(), &path.to_string_lossy()]);
                }
            }
            None => {
                let _ = std::fs::remove_file(path);
            }
        }
        return Err(error);
    }
    Ok(())
}
pub fn set_enabled(enabled: bool) -> Result<(), String> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _lock = LOCK.lock().map_err(|_| "登录项操作锁不可用")?;
    let home = PathBuf::from(std::env::var_os("HOME").ok_or("无法找到用户目录")?);
    let path = home
        .join("Library/LaunchAgents")
        .join(format!("{LABEL}.plist"));
    if !enabled {
        return apply(&path, LABEL, &[], false);
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let bundle = crate::install::bundle_of(&exe).ok_or("请从已安装的 .app 启用登录自启")?;
    if !bundle.starts_with("/Applications") && !bundle.starts_with(home.join("Applications")) {
        return Err(
            "请先将应用安装到 Applications，再开启登录自启，避免构建目录清理后自启失效".into(),
        );
    }
    let arguments: Vec<String> = [
        "/usr/bin/open",
        "-g",
        "-a",
        &bundle.to_string_lossy(),
        "--args",
        "--tray",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    apply(&path, LABEL, &arguments, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plist_preserves_spaces_and_xml_special_characters() {
        let value = definition(
            "com.daha.claudeguard.test",
            &["/usr/bin/open".into(), "/Users/A & B/应用.app".into()],
        );
        let mut bytes = Vec::new();
        value.to_writer_xml(&mut bytes).unwrap();
        let parsed = plist::Value::from_reader(std::io::Cursor::new(bytes)).unwrap();
        assert_eq!(parsed, value);
    }
    #[test]
    #[ignore = "registers and removes an isolated launchd test job; no real login item or app is changed"]
    fn real_launchd_registration_execution_and_disable() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("cg-login-{nonce}"));
        std::fs::create_dir(&dir).unwrap();
        let label = format!("com.daha.claudeguard.test.{nonce}");
        struct Cleanup {
            label: String,
            dir: PathBuf,
        }
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = remove_registration(&self.label);
                let _ = std::fs::remove_dir_all(&self.dir);
            }
        }
        let cleanup = Cleanup {
            label: label.clone(),
            dir: dir.clone(),
        };
        let path = dir.join(format!("{label}.plist"));
        let marker = dir.join("executed");
        let args = vec![
            "/usr/bin/touch".into(),
            marker.to_string_lossy().into_owned(),
        ];
        apply(&path, &label, &args, true).unwrap();
        for _ in 0..50 {
            if marker.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(marker.exists(), "launchd must actually execute the job");
        assert!(registered(&label));
        apply(&path, &label, &args, false).unwrap();
        assert!(!registered(&label));
        assert!(!path.exists());
        apply(&path, &label, &args, false).unwrap(); // repeated disable is idempotent
        drop(cleanup);
    }
}
