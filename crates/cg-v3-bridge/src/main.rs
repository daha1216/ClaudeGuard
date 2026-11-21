#![cfg_attr(not(test), windows_subsystem = "windows")]

//! Seamless ClaudeGuard v3 -> v4 self-update bridge binary.
//!
//! Why this exists:
//! - Legacy v3 (`src/update.rs`) is a single-exe updater whose `Release::exe_asset()` only accepts
//!   `.exe` assets containing `"ClaudeGuard"` and NOT containing `"-setup"`, and replaces
//!   `{app}\ClaudeGuard.exe` in place before executing it.
//! - Directly renaming the v4 Inno Setup installer to `ClaudeGuard-v4.0.0.exe` would fail because
//!   v4 `claude-guard.iss` executes `taskkill /F /IM ClaudeGuard.exe` during `PrepareToInstall`.
//! - This bridge satisfies v3's asset & SHA-256 verification rules, copies legacy `%APPDATA%`
//!   configuration into `%ProgramData%\ClaudeGuard` when absent, extracts the embedded v4
//!   installer into a staging directory, spawns a staging-side waiter outside `{app}`, exits
//!   immediately so `{app}\ClaudeGuard.exe` is unlocked, waits for installation completion, and
//!   cleans up legacy `{app}\ClaudeGuard.exe` + `.exe.old` artifacts once v4 is installed.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(cg_has_embedded_setup)]
const EMBEDDED_SETUP: &[u8] = include_bytes!(env!("CG_EMBEDDED_SETUP_PATH"));
#[cfg(not(cg_has_embedded_setup))]
const EMBEDDED_SETUP: &[u8] = &[];

const WAITER_FLAG: &str = "--cg-wait";
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Debug, PartialEq, Eq)]
struct WaiterArgs {
    app_exe: PathBuf,
    old_exe: PathBuf,
    setup_exe: PathBuf,
}

fn parse_waiter_args(args: &[String]) -> Option<WaiterArgs> {
    if args.len() != 4 || args[0] != WAITER_FLAG {
        return None;
    }
    Some(WaiterArgs {
        app_exe: PathBuf::from(&args[1]),
        old_exe: PathBuf::from(&args[2]),
        setup_exe: PathBuf::from(&args[3]),
    })
}

fn non_empty_env_dir(var_name: &str) -> Option<PathBuf> {
    std::env::var_os(var_name)
        .filter(|v| !v.to_string_lossy().trim().is_empty())
        .map(PathBuf::from)
}

/// Picks a staging directory (`%ProgramData%\ClaudeGuard\staging` first, else `%TEMP%\ClaudeGuard-upgrade`).
fn pick_staging_dir(program_data: Option<PathBuf>, temp_dir: PathBuf) -> PathBuf {
    if let Some(pd) = program_data {
        return pd.join("ClaudeGuard").join("staging");
    }
    temp_dir.join("ClaudeGuard-upgrade")
}

/// Resolves and ensures a writable staging directory.
fn ensure_staging_dir() -> Result<PathBuf, String> {
    let primary = pick_staging_dir(non_empty_env_dir("ProgramData"), std::env::temp_dir());
    if fs::create_dir_all(&primary).is_ok() {
        return Ok(primary);
    }
    let fallback = std::env::temp_dir().join("ClaudeGuard-upgrade");
    fs::create_dir_all(&fallback)
        .map_err(|e| format!("无法创建升级暂存目录（{}）：{e}", fallback.display()))?;
    Ok(fallback)
}

/// Copies legacy v3 `%APPDATA%\ClaudeGuard\config.json` into `%ProgramData%\ClaudeGuard\config.json`
/// ONLY when the destination does not already exist, preserving the original `%APPDATA%` file.
fn migrate_config_if_absent(appdata_dir: Option<&Path>, programdata_dir: Option<&Path>) -> bool {
    let (Some(src_base), Some(dst_base)) = (appdata_dir, programdata_dir) else {
        return false;
    };
    let src = src_base.join("ClaudeGuard").join("config.json");
    let dst_dir = dst_base.join("ClaudeGuard");
    let dst = dst_dir.join("config.json");

    if !src.is_file() || dst.exists() {
        return false;
    }
    let Ok(bytes) = fs::read(&src) else {
        return false;
    };
    if bytes.iter().all(|b| b.is_ascii_whitespace()) {
        return false;
    }
    if fs::create_dir_all(&dst_dir).is_err() {
        return false;
    }
    let tmp = dst_dir.join(format!("config.json.v3mig.{}.tmp", process::id()));
    let Ok(mut file) = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp)
    else {
        return false;
    };
    if file.write_all(&bytes).is_err() || file.sync_all().is_err() {
        drop(file);
        let _ = fs::remove_file(&tmp);
        return false;
    }
    drop(file);
    if fs::rename(&tmp, &dst).is_err() {
        let _ = fs::remove_file(&tmp);
        return false;
    }
    true
}

fn unique_tag() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    format!("{}-{:08x}", process::id(), nanos & 0xffff_ffff)
}

fn write_unique_file(dir: &Path, prefix: &str, ext: &str, bytes: &[u8]) -> Result<PathBuf, String> {
    let pid = process::id();
    for attempt in 0..8u32 {
        let path = dir.join(format!("{prefix}-{pid}-{attempt}-{}.{ext}", unique_tag()));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                file.write_all(bytes)
                    .map_err(|e| format!("写入临时文件失败（{}）：{e}", path.display()))?;
                file.sync_all()
                    .map_err(|e| format!("落盘临时文件失败（{}）：{e}", path.display()))?;
                return Ok(path);
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(format!("创建临时文件失败（{}）：{e}", path.display(), e = err)),
        }
    }
    Err("创建临时升级文件失败：重试次数耗尽".into())
}

fn remove_file_with_retry(path: &Path) {
    for attempt in 0..6 {
        match fs::remove_file(path) {
            Ok(()) => return,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return,
            Err(_) if attempt < 5 => thread::sleep(Duration::from_millis(250)),
            Err(_) => return,
        }
    }
}

fn cleanup_post_install(args: &WaiterArgs, setup_succeeded: bool) {
    remove_file_with_retry(&args.setup_exe);
    let gui_installed = args
        .app_exe
        .parent()
        .map(|dir| dir.join("claudeguard-gui.exe").is_file())
        .unwrap_or(false);
    if setup_succeeded || gui_installed {
        remove_file_with_retry(&args.app_exe);
        remove_file_with_retry(&args.old_exe);
    }
}

#[cfg(windows)]
mod win_api {
    use std::ffi::{OsStr, c_void};
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    const MB_OK: u32 = 0x0000_0000;
    const MB_ICONERROR: u32 = 0x0000_0010;
    const MOVEFILE_DELAY_UNTIL_REBOOT: u32 = 0x0000_0004;
    const SW_SHOWNORMAL: i32 = 1;

    #[link(name = "user32")]
    unsafe extern "system" {
        fn MessageBoxW(hwnd: *mut c_void, text: *const u16, caption: *const u16, utype: u32) -> i32;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(existing: *const u16, new_name: *const u16, flags: u32) -> i32;
    }

    #[link(name = "shell32")]
    unsafe extern "system" {
        fn ShellExecuteW(
            hwnd: *mut c_void,
            operation: *const u16,
            file: *const u16,
            parameters: *const u16,
            directory: *const u16,
            show_cmd: i32,
        ) -> isize;
    }

    fn wide_null(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    pub fn show_error(title: &str, msg: &str) {
        let t = wide_null(OsStr::new(title));
        let m = wide_null(OsStr::new(msg));
        unsafe {
            MessageBoxW(std::ptr::null_mut(), m.as_ptr(), t.as_ptr(), MB_OK | MB_ICONERROR);
        }
    }

    pub fn schedule_delete_on_reboot(path: &Path) {
        let p = wide_null(path.as_os_str());
        unsafe {
            MoveFileExW(p.as_ptr(), std::ptr::null(), MOVEFILE_DELAY_UNTIL_REBOOT);
        }
    }

    pub fn launch_elevated_setup(setup_exe: &Path) -> Result<(), String> {
        let op = wide_null(OsStr::new("runas"));
        let file = wide_null(setup_exe.as_os_str());
        let params = wide_null(OsStr::new("/SP-"));
        let res = unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                op.as_ptr(),
                file.as_ptr(),
                params.as_ptr(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            )
        };
        if res > 32 {
            Ok(())
        } else {
            Err(format!(
                "无法以管理员权限启动安装程序（ShellExecuteW={res}），请手动运行安装包：{}" ,
                setup_exe.display()
            ))
        }
    }
}

#[cfg(not(windows))]
mod win_api {
    use std::path::Path;
    pub fn show_error(title: &str, msg: &str) {
        eprintln!("{title}: {msg}");
    }
    pub fn schedule_delete_on_reboot(_path: &Path) {}
    pub fn launch_elevated_setup(_setup_exe: &Path) -> Result<(), String> {
        Err("仅支持 Windows 平台".into())
    }
}

fn spawn_detached(cmd: &mut Command) -> std::io::Result<process::Child> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}

fn run_waiter(args: WaiterArgs) -> Result<(), String> {
    // Allow brief window for the launching bridge (`ClaudeGuard.exe`) and old v3 daemon to exit.
    thread::sleep(Duration::from_millis(350));

    match Command::new(&args.setup_exe)
        .arg("/SP-")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(mut child) => {
            let status = child
                .wait()
                .map_err(|e| format!("等待安装程序完成失败：{e}"))?;
            cleanup_post_install(&args, status.success());
            Ok(())
        }
        Err(err) if err.raw_os_error() == Some(740) => {
            // Non-elevated manual double-click fallback: prompt UAC via ShellExecuteW("runas").
            win_api::launch_elevated_setup(&args.setup_exe)
        }
        Err(err) => Err(format!(
            "启动安装程序失败（{}）：{err}",
            args.setup_exe.display()
        )),
    }
}

fn run_primary() -> Result<(), String> {
    let cur_exe = std::env::current_exe()
        .map_err(|e| format!("无法定位当前升级程序路径：{e}"))?;
    let app_dir = cur_exe
        .parent()
        .ok_or_else(|| "无法识别安装目录".to_string())?;
    let old_exe = cur_exe.with_extension("exe.old");

    // If v4 is already installed alongside this file (e.g. legacy shortcut left behind),
    // clean up v3 `.old` residue and hand off directly to `claudeguard-gui.exe`.
    let gui_exe = app_dir.join("claudeguard-gui.exe");
    if gui_exe.is_file() {
        remove_file_with_retry(&old_exe);
        let _ = spawn_detached(&mut Command::new(&gui_exe));
        win_api::schedule_delete_on_reboot(&cur_exe);
        return Ok(());
    }

    if EMBEDDED_SETUP.is_empty() {
        return Err("当前升级引导包未内嵌安装包正文，请从 GitHub Releases 下载完整 setup.exe 安装。".into());
    }

    // Preserve existing v3 settings from `%APPDATA%\ClaudeGuard\config.json` into `%ProgramData%\ClaudeGuard\config.json`.
    let appdata = non_empty_env_dir("APPDATA");
    let programdata = non_empty_env_dir("ProgramData");
    let _ = migrate_config_if_absent(appdata.as_deref(), programdata.as_deref());

    let staging = ensure_staging_dir()?;
    let setup_path = write_unique_file(
        &staging,
        &format!("ClaudeGuard-v{APP_VERSION}-setup"),
        "exe",
        EMBEDDED_SETUP,
    )?;

    // Copy this bridge binary out of `{app}\ClaudeGuard.exe` into staging so `{app}` stays unlocked
    // and Inno Setup's `taskkill /IM ClaudeGuard.exe` never hits the waiter.
    let waiter_path = staging.join(format!("cg-v3-waiter-{}.exe", unique_tag()));
    if fs::copy(&cur_exe, &waiter_path).is_ok() {
        let mut cmd = Command::new(&waiter_path);
        cmd.arg(WAITER_FLAG)
            .arg(&cur_exe)
            .arg(&old_exe)
            .arg(&setup_path);
        if spawn_detached(&mut cmd).is_ok() {
            win_api::schedule_delete_on_reboot(&waiter_path);
            return Ok(());
        }
        let _ = fs::remove_file(&waiter_path);
    }

    // Direct fallback if waiter copy could not be spawned.
    match spawn_detached(Command::new(&setup_path).arg("/SP-")) {
        Ok(_) => Ok(()),
        Err(err) if err.raw_os_error() == Some(740) => win_api::launch_elevated_setup(&setup_path),
        Err(err) => Err(format!(
            "启动安装程序失败（{}）：{err}",
            setup_path.display()
        )),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let res = if let Some(waiter) = parse_waiter_args(&args) {
        let r = run_waiter(waiter);
        if let Ok(waiter_exe) = std::env::current_exe() {
            win_api::schedule_delete_on_reboot(&waiter_exe);
        }
        r
    } else {
        run_primary()
    };

    if let Err(msg) = res {
        win_api::show_error(&format!("ClaudeGuard v{APP_VERSION} 升级引导"), &msg);
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_waiter_args_with_spaces_and_unicode() {
        let args = vec![
            WAITER_FLAG.to_string(),
            r"C:\Program Files\ClaudeGuard\ClaudeGuard.exe".to_string(),
            r"C:\Program Files\ClaudeGuard\ClaudeGuard.exe.old".to_string(),
            r"C:\ProgramData\ClaudeGuard\staging\安装包 v4.0.0.exe".to_string(),
        ];
        let parsed = parse_waiter_args(&args).expect("waiter args should parse");
        assert_eq!(
            parsed.app_exe,
            PathBuf::from(r"C:\Program Files\ClaudeGuard\ClaudeGuard.exe")
        );
        assert_eq!(
            parsed.setup_exe,
            PathBuf::from(r"C:\ProgramData\ClaudeGuard\staging\安装包 v4.0.0.exe")
        );
        assert!(parse_waiter_args(&["--other".to_string()]).is_none());
    }

    #[test]
    fn migrates_v3_config_only_when_v4_config_is_absent() {
        let base = std::env::temp_dir().join(format!("cg-v3-bridge-mig-{}", unique_tag()));
        let appdata = base.join("roaming");
        let progdata = base.join("progdata");
        fs::create_dir_all(appdata.join("ClaudeGuard")).unwrap();
        let legacy_cfg = br#"{"version":3,"proxy_port":7890,"first_run":false}"#;
        fs::write(appdata.join("ClaudeGuard").join("config.json"), legacy_cfg).unwrap();

        assert!(migrate_config_if_absent(Some(&appdata), Some(&progdata)));
        let migrated = fs::read(progdata.join("ClaudeGuard").join("config.json")).unwrap();
        assert_eq!(migrated, legacy_cfg);
        assert!(appdata.join("ClaudeGuard").join("config.json").is_file());

        // Never overwrites an already-existing v4 config.json.
        let newer_cfg = br#"{"version":4,"proxy_port":17890}"#;
        fs::write(progdata.join("ClaudeGuard").join("config.json"), newer_cfg).unwrap();
        assert!(!migrate_config_if_absent(Some(&appdata), Some(&progdata)));
        assert_eq!(
            fs::read(progdata.join("ClaudeGuard").join("config.json")).unwrap(),
            newer_cfg
        );

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn post_install_cleanup_preserves_bridge_on_cancel_and_removes_on_install() {
        let base = std::env::temp_dir().join(format!("cg-v3-bridge-clean-{}", unique_tag()));
        let app = base.join("app");
        let stage = base.join("staging");
        fs::create_dir_all(&app).unwrap();
        fs::create_dir_all(&stage).unwrap();

        let app_exe = app.join("ClaudeGuard.exe");
        let old_exe = app.join("ClaudeGuard.exe.old");
        let setup_exe = stage.join("setup.exe");
        fs::write(&app_exe, b"bridge").unwrap();
        fs::write(&old_exe, b"old-v3").unwrap();
        fs::write(&setup_exe, b"setup").unwrap();

        let waiter_args = WaiterArgs {
            app_exe: app_exe.clone(),
            old_exe: old_exe.clone(),
            setup_exe: setup_exe.clone(),
        };

        // Canceled install (non-zero status and no claudeguard-gui.exe): delete setup, keep bridge.
        cleanup_post_install(&waiter_args, false);
        assert!(!setup_exe.exists());
        assert!(app_exe.is_file());
        assert!(old_exe.is_file());

        // Completed install (setup succeeded or claudeguard-gui.exe present): clean legacy residue.
        fs::write(&setup_exe, b"setup").unwrap();
        cleanup_post_install(&waiter_args, true);
        assert!(!setup_exe.exists());
        assert!(!app_exe.exists());
        assert!(!old_exe.exists());

        let _ = fs::remove_dir_all(&base);
    }
}
