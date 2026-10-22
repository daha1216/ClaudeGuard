use crate::config::NotifyPrefs;
use std::ffi::{CStr, CString};

pub fn ensure_identity() -> Result<(), String> {
    library_path().map(|_| ())
}
fn library_path() -> Result<std::path::PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let path = exe
        .parent()
        .and_then(|p| p.parent())
        .ok_or("应用路径无效")?
        .join("Frameworks/CGNotifications.dylib");
    if path.is_file() {
        Ok(path)
    } else {
        Err("原生通知组件缺失，请使用完整打包后的 .app".into())
    }
}
fn invoke(request: serde_json::Value) -> Result<serde_json::Value, String> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _lock = LOCK.lock().map_err(|_| "通知请求锁不可用")?;
    let encoded = CString::new(serde_json::to_vec(&request).map_err(|e| e.to_string())?)
        .map_err(|_| "通知内容无效")?;
    // The packaged, signed library exports exactly this C ABI. It stays loaded for
    // the application's lifetime because UNUserNotificationCenter retains its delegate.
    static LIBRARY: std::sync::OnceLock<libloading::Library> = std::sync::OnceLock::new();
    if LIBRARY.get().is_none() {
        let library = unsafe { libloading::Library::new(library_path()?) }
            .map_err(|_| "无法载入原生通知组件")?;
        let _ = LIBRARY.set(library);
    }
    let library = LIBRARY.get().ok_or("通知组件不可用")?;
    let value: serde_json::Value = unsafe {
        let call: libloading::Symbol<
            unsafe extern "C" fn(*const libc::c_char) -> *mut libc::c_char,
        > = library
            .get(b"cg_notification")
            .map_err(|_| "通知接口缺失")?;
        let free: libloading::Symbol<unsafe extern "C" fn(*mut libc::c_char)> = library
            .get(b"cg_notification_free")
            .map_err(|_| "通知接口缺失")?;
        let result = call(encoded.as_ptr());
        if result.is_null() {
            return Err("通知组件未返回状态".into());
        }
        let bytes = CStr::from_ptr(result).to_bytes().to_vec();
        free(result);
        serde_json::from_slice(&bytes).map_err(|_| "通知组件未返回有效状态")?
    };
    if value["ok"] != true {
        return Err(format!("原生通知未发送（{}）；请在系统设置 → 通知中允许 ClaudeGuard，首次可点击发送测试申请权限", value["permission"].as_str().unwrap_or("component_error")));
    }
    Ok(value)
}
pub fn status() -> Result<serde_json::Value, String> {
    invoke(serde_json::json!({"operation":"status"}))
}
pub fn send_blocking(title: &str, body: &str) -> Result<(), String> {
    deliver(title, body, false)
}
pub fn test_blocking(title: &str, body: &str) -> Result<(), String> {
    deliver(&format!("{title}（测试）"), body, true)
}
fn deliver(title: &str, body: &str, request_permission: bool) -> Result<(), String> {
    let value = invoke(
        serde_json::json!({"operation":"send", "title":title, "body":body, "requestPermission":request_permission}),
    )?;
    if value["delivered"] == true {
        Ok(())
    } else {
        Err("系统已接收通知，但未确认在通知中心送达；请检查通知权限与专注模式".into())
    }
}

/// 按分类开关异步发通知（失败只记日志）。返回是否真正尝试发送。
pub fn send(prefs: &NotifyPrefs, class: &str, title: &str, body: &str) -> bool {
    if !prefs.is_on(class) {
        return false;
    }
    let class = class.to_string();
    let title = title.to_string();
    let body = body.to_string();
    std::thread::spawn(move || {
        if let Err(err) = send_blocking(&title, &body) {
            crate::guard::log_line(&format!("notify[{class}]: 发送失败：{err}"));
        }
    });
    true
}

/// `--notify-test <kind>` 用的样例文案。
pub fn test_message(kind: &str) -> (&'static str, String) {
    match kind {
        "recover" => (
            "ClaudeGuard 已恢复",
            "出口检查通过，进程守护已恢复；可手动启动应用。".to_string(),
        ),
        "launch_blocked" => (
            "ClaudeGuard 已阻止启动",
            "当前出口不在白名单内，已阻止 Claude 启动。".to_string(),
        ),
        "warning" => (
            "ClaudeGuard 检查未通过",
            "出口检查连续失败，再失败一次将熔断。".to_string(),
        ),
        "client_update" => (
            "Claude 有新版本",
            "客户端更新已就绪，打开主窗口即可安装。".to_string(),
        ),
        "self_update" => (
            "ClaudeGuard 有新版本",
            "v3.5.0 已发布，打开 设置 → 更新 一键升级。".to_string(),
        ),
        _ => (
            "ClaudeGuard 已熔断",
            "出口不符合白名单，已执行配置的进程关闭操作；请等待出口恢复后手动启动应用。"
                .to_string(),
        ),
    }
}
