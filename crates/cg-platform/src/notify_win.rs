//! Native Windows WinRT Toast notifications (`ToastNotificationManager` + `XmlDocument`).
//!
//! Zero `powershell.exe` spawning: invokes WinRT APIs directly from Rust and idempotently
//! ensures `HKCU\Software\Classes\AppUserModelId\ClaudeGuard` exists so Windows never silently
//! drops notifications.

use crate::traits::{PlatformError, PlatformResult};

/// Registered Application User Model ID for ClaudeGuard toast notifications.
pub const AUMID: &str = "ClaudeGuard";

/// Registry path under `HKEY_CURRENT_USER` for AUMID registration.
pub fn aumid_key_path() -> String {
    format!(r"Software\Classes\AppUserModelId\{AUMID}")
}

/// Escape XML special characters so arbitrary notification text cannot break or inject Toast markup.
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

/// Build safe WinRT Toast XML payload (`ToastGeneric` template).
pub fn build_toast_xml(title: &str, body: &str) -> String {
    let title = escape_xml(title);
    let body = escape_xml(body);
    format!(
        "<toast><visual><binding template=\"ToastGeneric\"><text>{title}</text><text>{body}</text></binding></visual></toast>"
    )
}

/// Idempotently register the `ClaudeGuard` AUMID under `HKCU\Software\Classes\AppUserModelId`.
#[cfg(windows)]
pub fn ensure_identity() -> PlatformResult<()> {
    let exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .map_err(|e| PlatformError::Io(format!("current_exe failed: {e}")))?;
    ensure_identity_with_icon("ClaudeGuard", &exe)
}

#[cfg(windows)]
pub fn ensure_identity_with_icon(display_name: &str, icon_uri: &str) -> PlatformResult<()> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (key, _) = hkcu
        .create_subkey(aumid_key_path())
        .map_err(|e| PlatformError::Io(format!("create AUMID registry key failed: {e}")))?;
    key.set_value("DisplayName", &display_name)
        .map_err(|e| PlatformError::Io(format!("write AUMID DisplayName failed: {e}")))?;
    if !icon_uri.trim().is_empty() {
        key.set_value("IconUri", &icon_uri)
            .map_err(|e| PlatformError::Io(format!("write AUMID IconUri failed: {e}")))?;
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn ensure_identity() -> PlatformResult<()> {
    Err(PlatformError::unsupported(
        "toast_notifications",
        "WinRT Toast AUMID registration is only supported on Windows",
    ))
}

/// Deliver a native WinRT Toast notification synchronously (0 subprocesses).
#[cfg(windows)]
pub fn send_toast(title: &str, body: &str) -> PlatformResult<()> {
    use crate::com::{map_win_err, ComGuard};
    use std::sync::OnceLock;
    use windows::core::HSTRING;
    use windows::Data::Xml::Dom::XmlDocument;
    use windows::UI::Notifications::{ToastNotification, ToastNotificationManager};

    if crate::access_win::is_session_zero() {
        return Ok(());
    }

    static AUMID_READY: OnceLock<()> = OnceLock::new();
    if AUMID_READY.get().is_none() {
        ensure_identity()?;
        let _ = AUMID_READY.set(());
    }
    let _com = ComGuard::init_mta()?;

    let xml_doc = XmlDocument::new().map_err(|e| map_win_err(e, "XmlDocument::new"))?;
    let xml = build_toast_xml(title, body);
    xml_doc
        .LoadXml(&HSTRING::from(xml))
        .map_err(|e| map_win_err(e, "XmlDocument::LoadXml"))?;

    let toast = ToastNotification::CreateToastNotification(&xml_doc)
        .map_err(|e| map_win_err(e, "ToastNotification::CreateToastNotification"))?;
    let notifier = ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(AUMID))
        .map_err(|e| map_win_err(e, "ToastNotificationManager::CreateToastNotifierWithId"))?;
    notifier
        .Show(&toast)
        .map_err(|e| map_win_err(e, "ToastNotifier::Show"))?;
    Ok(())
}

#[cfg(not(windows))]
pub fn send_toast(_title: &str, _body: &str) -> PlatformResult<()> {
    Err(PlatformError::unsupported(
        "toast_notifications",
        "WinRT Toast notifications are only supported on Windows",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_escaping_prevents_markup_injection() {
        assert_eq!(
            escape_xml("a&b<c>d\"e'f"),
            "a&amp;b&lt;c&gt;d&quot;e&apos;f"
        );
        assert_eq!(escape_xml("中文正常内容"), "中文正常内容");

        let xml = build_toast_xml("Title <script>", "Body & 'test' \"ok\"");
        assert!(xml.contains("<text>Title &lt;script&gt;</text>"));
        assert!(xml.contains("<text>Body &amp; &apos;test&apos; &quot;ok&quot;</text>"));
        assert!(!xml.contains("<script>"));
    }

    #[test]
    fn aumid_key_path_matches_windows_app_id() {
        assert_eq!(
            aumid_key_path(),
            r"Software\Classes\AppUserModelId\ClaudeGuard"
        );
        assert_eq!(AUMID, "ClaudeGuard");
    }

    #[cfg(windows)]
    #[test]
    fn winrt_xml_document_parses_escaped_toast_payload_natively() {
        use crate::com::ComGuard;
        use windows::core::HSTRING;
        use windows::Data::Xml::Dom::XmlDocument;

        let _com = ComGuard::init_mta().expect("MTA init");
        let doc = XmlDocument::new().expect("XmlDocument::new");
        let payload = build_toast_xml("ClaudeGuard <Test>", "A&B \"C\" 'D'");
        doc.LoadXml(&HSTRING::from(payload))
            .expect("WinRT XmlDocument::LoadXml must accept escaped toast XML");
    }
}
