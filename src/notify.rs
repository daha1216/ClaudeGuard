//! 桌面通知：Windows Toast（powershell.exe + WinRT），不引入额外 crate。
//!
//! `tauri-plugin-notification` 不在离线 crate 缓存里，而项目要求零 node 构建、
//! 尽量少依赖；这里用一条隐藏的 PowerShell 进程发 Toast。失败只写日志，不影响守护。

use crate::config::NotifyPrefs;
use base64::Engine;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Toast 的 AUMID。安装版由 Inno 快捷方式登记同名 AppUserModelID；
/// 便携/调试模式下 Windows 仍会显示，只是可能显示为通用来源。
pub const AUMID: &str = "ClaudeGuard";

/// XML 转义（Toast 内容是 XML）。
pub fn escape_xml(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

/// 生成要交给 powershell.exe -EncodedCommand 的脚本（纯函数，可测）。
pub fn build_script(title: &str, body: &str) -> String {
    let title = escape_xml(title);
    let body = escape_xml(body);
    format!(
        "$ErrorActionPreference='Stop'\n\
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null\n\
[Windows.UI.Notifications.ToastNotification, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null\n\
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom, ContentType = WindowsRuntime] | Out-Null\n\
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument\n\
$xml.LoadXml('<toast><visual><binding template=\"ToastGeneric\"><text>{title}</text><text>{body}</text></binding></visual></toast>')\n\
$toast = New-Object Windows.UI.Notifications.ToastNotification $xml\n\
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{AUMID}').Show($toast)\n"
    )
}

/// UTF-16LE base64，供 -EncodedCommand 使用。
pub fn encode_command(script: &str) -> String {
    let mut bytes = Vec::with_capacity(script.len() * 2);
    for unit in script.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn powershell_path() -> std::path::PathBuf {
    crate::guard::sys32(r"WindowsPowerShell\v1.0\powershell.exe")
}

/// 同步发送一条 Toast；阻塞最多 8 秒。
pub fn send_blocking(title: &str, body: &str) -> Result<(), String> {
    let script = build_script(title, body);
    let encoded = encode_command(&script);
    let mut cmd = Command::new(powershell_path());
    cmd.args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-WindowStyle",
        "Hidden",
        "-EncodedCommand",
        &encoded,
    ]);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("无法启动 powershell：{e}"))?;
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return if status.success() {
                    Ok(())
                } else {
                    Err(format!("Toast 进程退出码 {:?}", status.code()))
                };
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    return Err("Toast 发送超时".into());
                }
                std::thread::sleep(Duration::from_millis(80));
            }
            Err(err) => return Err(format!("等待 Toast 进程失败：{err}")),
        }
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
            "出口检查通过，已解除隔离并恢复网络。".to_string(),
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
        _ => (
            "ClaudeGuard 已熔断",
            "出口不符合白名单，已结束相关应用并切断网络。".to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_xml_specials() {
        assert_eq!(
            escape_xml("a&b<c>d\"e'f"),
            "a&amp;b&lt;c&gt;d&quot;e&apos;f"
        );
        assert_eq!(escape_xml("中文 ok"), "中文 ok");
    }

    #[test]
    fn script_contains_title_body_and_aumid() {
        let script = build_script("ClaudeGuard 已熔断", "出口 1.2.3.4 不在白名单");
        assert!(script.contains("<text>ClaudeGuard 已熔断</text>"));
        assert!(script.contains("出口 1.2.3.4 不在白名单"));
        assert!(script.contains(AUMID));
        assert!(script.contains("ToastNotificationManager"));
    }

    #[test]
    fn script_escapes_injected_markup() {
        let script = build_script("a<b>", "&''");
        assert!(script.contains("a&lt;b&gt;"));
        assert!(!script.contains("<b>"));
    }

    #[test]
    fn encoded_command_is_utf16le_base64() {
        let encoded = encode_command("ab");
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        assert_eq!(bytes, vec![b'a', 0, b'b', 0]);
    }

    #[test]
    fn prefs_gate_each_class() {
        let mut prefs = NotifyPrefs::default();
        assert!(prefs.is_on("trip"));
        prefs.trip = false;
        assert!(!prefs.is_on("trip"));
        prefs.enabled = false;
        assert!(!prefs.is_on("recover"));
    }

    #[test]
    fn test_messages_reflect_kind() {
        assert!(test_message("trip").0.contains("熔断"));
        assert!(test_message("recover").0.contains("恢复"));
        assert!(test_message("unknown").0.contains("熔断"));
    }
}
