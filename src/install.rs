//! 自安装/卸载：复制到 %LOCALAPPDATA%\Programs\ClaudeGuard，创建快捷方式，
//! 写入注册表卸载项与开机自启项。

use crate::guard::log_line;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const APP_NAME: &str = "ClaudeGuard";
pub const UNINST_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\ClaudeGuard";
pub const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

pub fn install_dir() -> PathBuf {
    let local = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".into());
    PathBuf::from(local).join("Programs").join(APP_NAME)
}

pub fn installed_exe() -> PathBuf {
    install_dir().join("ClaudeGuard.exe")
}

pub fn is_installed() -> bool {
    std::env::current_exe()
        .map(|p| p == installed_exe())
        .unwrap_or(false)
}

/// 复制自身到安装目录，返回安装后的 exe 路径
pub fn install() -> Result<PathBuf, String> {
    let src = std::env::current_exe().map_err(|e| e.to_string())?;
    let dir = install_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let dst = installed_exe();
    std::fs::copy(&src, &dst).map_err(|e| e.to_string())?;
    log_line(&format!(
        "installed: {} -> {}",
        src.display(),
        dst.display()
    ));

    // 快捷方式（桌面 + 开始菜单），目标直接指向 exe
    create_shortcuts(&dst);

    // 注册表卸载项
    write_uninstall_key(&dst);

    Ok(dst)
}

fn run_ps(script: &str) -> bool {
    Command::new(crate::guard::sys32(
        r"WindowsPowerShell\v1.0\powershell.exe",
    ))
    .args([
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
    ])
    .output()
    .map(|o| o.status.success())
    .unwrap_or(false)
}

fn create_shortcuts(exe: &Path) {
    let exe_s = exe.to_string_lossy().to_string().replace('\'', "''");
    let work = exe
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default()
        .replace('\'', "''");
    let mk = |dir_var: &str| {
        format!(
            "$d=[Environment]::GetFolderPath('{dir_var}'); $w=New-Object -ComObject WScript.Shell; \
             $l=$w.CreateShortcut((Join-Path $d 'ClaudeGuard.lnk')); \
             $l.TargetPath='{exe_s}'; $l.WorkingDirectory='{work}'; \
             $l.Description='Claude 守护器：校验代理出口并守护运行'; $l.Save()"
        )
    };
    let a = run_ps(&mk("Desktop"));
    let b = run_ps(&mk("Programs"));
    log_line(&format!("shortcuts: desktop={a} startmenu={b}"));
}

fn write_uninstall_key(exe: &Path) {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok((key, _)) = hkcu.create_subkey(UNINST_KEY) {
        let exe_s = exe.to_string_lossy().to_string();
        let _ = key.set_value("DisplayName", &"Claude 守护器 (ClaudeGuard)");
        let _ = key.set_value("DisplayVersion", &env!("CARGO_PKG_VERSION"));
        let _ = key.set_value("Publisher", &"ClaudeGuard");
        let _ = key.set_value(
            "InstallLocation",
            &exe.parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default(),
        );
        let _ = key.set_value("DisplayIcon", &exe_s);
        let _ = key.set_value("UninstallString", &format!("\"{exe_s}\" --uninstall"));
        let _ = key.set_value("NoModify", &1u32);
        let _ = key.set_value("NoRepair", &1u32);
    }
    log_line("uninstall registry key written");
}

/// 开机自启开关（当前安装路径）
pub fn set_autostart(enabled: bool) -> bool {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let Ok(key) = hkcu.open_subkey_with_flags(RUN_KEY, winreg::enums::KEY_SET_VALUE) else {
        return false;
    };
    if enabled {
        let exe = installed_exe().to_string_lossy().to_string();
        key.set_value(APP_NAME, &format!("\"{exe}\" --tray"))
            .is_ok()
    } else {
        let _ = key.delete_value(APP_NAME);
        true
    }
}

/// 卸载：解除防火墙隔离 -> 删除快捷方式/注册表 -> 延迟自删
pub fn uninstall() {
    // 解除可能存在的隔离
    let _ = crate::guard::firewall_release();
    // 关闭自启
    let _ = set_autostart(false);
    // 删除快捷方式
    let rm = |dir_var: &str| {
        let script = format!(
            "$d=[Environment]::GetFolderPath('{dir_var}'); Remove-Item (Join-Path $d 'ClaudeGuard.lnk') -Force -ErrorAction SilentlyContinue",
            dir_var = dir_var
        );
        let _ = run_ps(&script);
    };
    rm("Desktop");
    rm("Programs");
    // 删除卸载项
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey(UNINST_KEY);
    // 删除配置目录（保留日志？一并删除）
    let _ = std::fs::remove_dir_all(crate::config::config_dir());
    log_line("uninstalled registry/shortcuts/config removed");
    // 延迟自删安装目录（ping 做延迟：timeout 在无控制台环境会立即退出不等）
    let dir = install_dir().to_string_lossy().to_string();
    let _ = Command::new(crate::guard::sys32("cmd.exe"))
        .args([
            "/C",
            &format!("ping -n 4 127.0.0.1 >nul & rmdir /s /q \"{dir}\""),
        ])
        .spawn();
}
