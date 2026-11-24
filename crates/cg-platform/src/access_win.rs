//! Native Windows access path & elevation inspection.
//!
//! Zero `net.exe` / `powershell.exe`:
//! - Admin elevation uses `OpenProcessToken` + `GetTokenInformation(TokenElevation)`.
//! - Proxy settings read `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`.
//! - TUN detection uses `IpHelper::GetAdaptersAddresses` (`IfOperStatusUp`).

use serde::{Deserialize, Serialize};

/// Keywords matching virtual TUN adapters (lowercase substring against description/friendly name).
const TUN_KEYWORDS: &[&str] = &[
    "mihomo",
    "clash",
    "meta",
    "sing-box",
    "singbox",
    "sing-tun",
    "flclash",
    "verge",
    "nyanpasu",
    "sparkle",
    "nekobox",
    "nekoray",
    "throne",
    "karing",
    "hiddify",
    "shadowsocks",
    "surfboard",
    "warp",
    "wintun",
    "wireguard",
    "openvpn",
    "tap-windows",
    "tun2socks",
    "bettbox",
    "hysteria",
    "juicity",
    "v2ray",
    "xray",
];

/// Split-tunnel / hypervisor / capture / transition adapters that do not route default AI traffic.
const TUN_EXCLUDES: &[&str] = &[
    "tailscale",
    "zerotier",
    "easytier",
    "netbird",
    "radmin",
    "hamachi",
    "vethernet",
    "wsl",
    "hyper-v",
    "vmware",
    "virtualbox",
    "npcap",
    "loopback",
    "teredo",
    "isatap",
    "6to4",
];

/// Service domain suffixes whose appearance in `ProxyOverride` implies direct leak risk.
const SENSITIVE_SUFFIXES: [&str; 8] = [
    "anthropic.com",
    "claude.ai",
    "openai.com",
    "chatgpt.com",
    "oaistatic.com",
    "oaiusercontent.com",
    "googleapis.com",
    "google.com",
];

/// Raw registry evidence read from Windows Internet Settings.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessEvidenceRaw {
    pub enable: bool,
    pub server: Option<String>,
    pub autoconfig: Option<String>,
    pub overrides: Option<String>,
}

/// Parsed `ProxyServer` value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyParse {
    /// Reusable HTTP proxy endpoint (`host:port`).
    Http(String),
    /// Unsupported protocol (`socks=`, missing port, etc.).
    Unsupported(&'static str),
    /// Empty or unset.
    Empty,
}

/// Resolved application egress access path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AccessPath {
    SystemProxy { addr: String },
    Tun { adapter: String },
    Uncovered,
    Unknown { reason: String },
}

/// Snapshot-friendly access path summary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessInfo {
    /// `system_proxy` | `tun` | `uncovered` | `unknown` | `skipped`
    pub path: String,
    pub note: String,
}

impl AccessInfo {
    pub fn is_uncovered(&self) -> bool {
        self.path == "uncovered"
    }

    pub fn is_unknown(&self) -> bool {
        self.path == "unknown"
    }

    pub fn is_known(&self) -> bool {
        self.path == "system_proxy" || self.path == "tun"
    }
}

impl From<&AccessPath> for AccessInfo {
    fn from(path: &AccessPath) -> Self {
        match path {
            AccessPath::SystemProxy { addr } => Self {
                path: "system_proxy".into(),
                note: format!("系统代理 {addr}"),
            },
            AccessPath::Tun { adapter } => Self {
                path: "tun".into(),
                note: format!("TUN 直连（{}）", adapter.trim()),
            },
            AccessPath::Uncovered => Self {
                path: "uncovered".into(),
                note: "系统代理未开启且未检测到 TUN 网卡，应用会直连真实出口".into(),
            },
            AccessPath::Unknown { reason } => Self {
                path: "unknown".into(),
                note: reason.clone(),
            },
        }
    }
}

impl AccessPath {
    /// Converts this resolved OS access path into the canonical `cg_protocol::AccessEvidence`.
    pub fn to_protocol_evidence(
        &self,
        observed_at: u64,
        revision: u64,
    ) -> cg_protocol::AccessEvidence {
        let info = AccessInfo::from(self);
        match self {
            AccessPath::SystemProxy { addr } => cg_protocol::AccessEvidence {
                level: cg_protocol::AccessLevel::SystemProxy,
                proxy_addr: Some(addr.clone()),
                tun_iface: None,
                route_hint: true,
                observed_at,
                revision,
                note: info.note,
            },
            AccessPath::Tun { adapter } => cg_protocol::AccessEvidence {
                level: cg_protocol::AccessLevel::Tun,
                proxy_addr: None,
                tun_iface: Some(adapter.trim().to_string()),
                route_hint: true,
                observed_at,
                revision,
                note: info.note,
            },
            AccessPath::Uncovered => cg_protocol::AccessEvidence {
                level: cg_protocol::AccessLevel::Uncovered,
                proxy_addr: None,
                tun_iface: None,
                route_hint: false,
                observed_at,
                revision,
                note: info.note,
            },
            AccessPath::Unknown { reason } => cg_protocol::AccessEvidence {
                level: cg_protocol::AccessLevel::Unknown,
                proxy_addr: None,
                tun_iface: None,
                route_hint: false,
                observed_at,
                revision,
                note: reason.clone(),
            },
        }
    }
}

impl From<&cg_protocol::AccessEvidence> for AccessInfo {
    fn from(ev: &cg_protocol::AccessEvidence) -> Self {
        Self {
            path: ev.path_tag().to_string(),
            note: ev.note.clone(),
        }
    }
}

/// Decode UTF-16 code units by unit count (never byte count; T01-01).
pub fn wide_to_string(units: &[u16]) -> String {
    String::from_utf16_lossy(units)
}

fn is_tun_excluded(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    TUN_EXCLUDES.iter().any(|kw| lower.contains(kw))
}

fn has_bounded_tun_token(lower: &str) -> bool {
    lower == "tun"
        || lower.ends_with("-tun")
        || lower.ends_with("_tun")
        || lower.ends_with(" tun")
        || lower.strip_prefix("tun").is_some_and(|s| {
            s.starts_with(['-', '_', ' '])
                || (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        })
}

/// Whether an adapter description or friendly name identifies a full-tunnel TUN interface.
pub fn is_tun_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if TUN_EXCLUDES.iter().any(|kw| lower.contains(kw)) {
        return false;
    }
    lower.starts_with("utun")
        || has_bounded_tun_token(&lower)
        || TUN_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

/// Select the first active (`Up`) TUN adapter from `(description, friendly_name, is_up)` tuples.
pub fn select_tun(adapters: &[(String, String, bool)]) -> Option<String> {
    for (desc, friendly, up) in adapters {
        if !*up {
            continue;
        }
        if is_tun_excluded(desc) || is_tun_excluded(friendly) {
            continue;
        }
        if is_tun_name(desc) {
            return Some(desc.clone());
        }
        if is_tun_name(friendly) {
            return Some(friendly.clone());
        }
    }
    None
}

fn strip_scheme(value: &str) -> (Option<&str>, &str) {
    match value.find("://") {
        Some(idx) => (Some(&value[..idx]), &value[idx + 3..]),
        None => (None, value),
    }
}

fn has_host_and_port(addr: &str) -> bool {
    if let Some(rest) = addr.strip_prefix('[') {
        let Some((host, after)) = rest.split_once(']') else {
            return false;
        };
        if host.is_empty() {
            return false;
        }
        let Some(port) = after.strip_prefix(':') else {
            return false;
        };
        !port.is_empty() && port.chars().all(|c| c.is_ascii_digit())
    } else {
        let Some((host, port)) = addr.rsplit_once(':') else {
            return false;
        };
        !host.is_empty() && !port.is_empty() && port.chars().all(|c| c.is_ascii_digit())
    }
}

fn clean_addr(value: &str) -> Option<String> {
    let (scheme, rest) = strip_scheme(value.trim());
    let rest = rest.trim().trim_end_matches('/');
    if rest.is_empty() {
        return None;
    }
    if let Some(scheme) = scheme {
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return None;
        }
    }
    if !has_host_and_port(rest) {
        return None;
    }
    Some(rest.to_string())
}

/// Parse Windows `ProxyServer` registry value (`host:port`, `http=h:p;https=h:p`, or URL form).
pub fn parse_proxy_server(raw: Option<&str>) -> ProxyParse {
    let Some(raw) = raw.map(str::trim).filter(|v| !v.is_empty()) else {
        return ProxyParse::Empty;
    };
    if raw.contains(';') {
        let mut https = None;
        let mut http = None;
        let mut other = false;
        for part in raw.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let lower = part.to_ascii_lowercase();
            if lower.starts_with("https=") {
                if let Some(addr) = clean_addr(&part["https=".len()..]) {
                    https.get_or_insert(addr);
                } else {
                    other = true;
                }
            } else if lower.starts_with("http=") {
                if let Some(addr) = clean_addr(&part["http=".len()..]) {
                    http.get_or_insert(addr);
                } else {
                    other = true;
                }
            } else if lower.contains('=') {
                other = true;
            } else if let Some(addr) = clean_addr(part) {
                http.get_or_insert(addr);
            } else {
                other = true;
            }
        }
        if let Some(addr) = https.or(http) {
            return ProxyParse::Http(addr);
        }
        return if other {
            ProxyParse::Unsupported("仅配置了不支持的代理协议")
        } else {
            ProxyParse::Empty
        };
    }
    let lower = raw.to_ascii_lowercase();
    if lower.starts_with("socks") {
        return ProxyParse::Unsupported("仅配置了 SOCKS 代理");
    }
    match clean_addr(raw) {
        Some(addr) => ProxyParse::Http(addr),
        None => ProxyParse::Unsupported("代理地址缺少端口或协议不受支持"),
    }
}

fn bypass_entries(raw: Option<&str>) -> Vec<String> {
    raw.unwrap_or_default()
        .split(';')
        .map(|v| v.trim().to_ascii_lowercase())
        .filter(|v| !v.is_empty())
        .collect()
}

/// Wildcard `*` bypasses all hosts -> equivalent to uncovered direct egress.
pub fn bypass_all(raw: Option<&str>) -> bool {
    bypass_entries(raw).iter().any(|v| v == "*")
}

fn entry_domain(entry: &str) -> String {
    entry
        .trim()
        .trim_start_matches('*')
        .trim_start_matches('.')
        .to_string()
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p = pattern.as_bytes();
    let t = text.as_bytes();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_pi, mut star_ti) = (None, 0usize);
    while ti < t.len() {
        if pi < p.len() && p[pi] == b'*' {
            star_pi = Some(pi);
            star_ti = ti;
            pi += 1;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// Whether a `ProxyOverride` entry covers only loopback / RFC1918 / link-local ranges.
pub fn bypass_local_entry(entry: &str) -> bool {
    let e = entry.trim().to_ascii_lowercase();
    let host_part = if !e.starts_with('[') {
        e.split(':').next().unwrap_or(&e)
    } else {
        e.as_str()
    };
    if matches!(
        host_part,
        "<local>"
            | "<-loopback>"
            | "*."
            | "localhost"
            | "localhost.*"
            | "*.localhost"
            | "*.local"
            | "*.localdomain"
            | "127.0.0.1"
            | "[::1]"
            | "::1"
    ) || e == "::1"
        || e.starts_with("[::1]:")
        || e.starts_with("fe80:")
        || e.starts_with("[fe80:")
    {
        return true;
    }
    if let Ok(v4) = host_part.parse::<std::net::Ipv4Addr>() {
        return v4.is_loopback() || v4.is_private() || v4.is_link_local();
    }
    let mut prefix = host_part;
    let mut stripped = false;
    while let Some(p) = prefix.strip_suffix(".*") {
        prefix = p;
        stripped = true;
    }
    if !stripped || prefix.is_empty() {
        return false;
    }
    let Some(octets) = prefix
        .split('.')
        .map(|v| v.parse::<u8>().ok())
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    if octets.len() > 3 {
        return false;
    }
    match octets.as_slice() {
        [10, ..] | [127, ..] => true,
        [192, 168, ..] | [169, 254, ..] => true,
        [172, second, ..] => (16..=31).contains(second),
        _ => false,
    }
}

/// Whether a bypass entry matches a target host or its subdomains.
pub fn bypass_hits_host(entry: &str, host: &str) -> bool {
    let e = entry.trim().to_ascii_lowercase();
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if e.is_empty() || e == "." || e == "<-loopback>" || host.is_empty() {
        return false;
    }
    if e == "*." {
        return !host.contains('.');
    }
    let domain = entry_domain(&e).trim_end_matches('.').to_string();
    if domain.is_empty() || domain == "*" {
        return true;
    }
    if !domain.contains('*') && (host == domain || host.ends_with(&format!(".{domain}"))) {
        return true;
    }
    wildcard_match(&e, &host) || wildcard_match(&e, &format!("sub.{host}"))
}

/// Check if `ProxyOverride` contains any rule that could bypass the proxy for monitored AI hosts.
pub fn bypass_risk(raw: Option<&str>, hosts: &[String]) -> Option<String> {
    for entry in bypass_entries(raw) {
        if entry == "*" || bypass_local_entry(&entry) {
            continue;
        }
        if hosts.iter().any(|h| bypass_hits_host(&entry, h)) {
            return Some(entry);
        }
        if SENSITIVE_SUFFIXES
            .iter()
            .any(|suffix| bypass_hits_host(&entry, suffix))
        {
            return Some(entry);
        }
    }
    None
}

/// Extract normalized hostnames from HTTPS anchor URLs for bypass-risk matching.
pub fn monitored_hosts_from_urls<'a>(urls: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut out = Vec::new();
    for url in urls {
        let Some(rest) = url.trim().strip_prefix("https://") else {
            continue;
        };
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        let host = authority.rsplit('@').next().unwrap_or(authority);
        let host = host.split(':').next().unwrap_or(host).to_ascii_lowercase();
        if !host.is_empty() && !out.contains(&host) {
            out.push(host);
        }
    }
    out
}

/// Determine `AccessPath` purely from registry evidence, TUN state, and monitored hostnames.
pub fn verdict(
    evidence: &AccessEvidenceRaw,
    tun_adapter: Option<String>,
    hosts: &[String],
) -> AccessPath {
    if let Some(pac) = evidence
        .autoconfig
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        return AccessPath::Unknown {
            reason: format!("检测到 PAC 自动配置（{pac}），无法确认应用实际出口"),
        };
    }
    if !evidence.enable {
        return match tun_adapter {
            Some(adapter) => AccessPath::Tun { adapter },
            None => AccessPath::Uncovered,
        };
    }
    match parse_proxy_server(evidence.server.as_deref()) {
        ProxyParse::Http(addr) => {
            if bypass_all(evidence.overrides.as_deref()) {
                AccessPath::Uncovered
            } else if let Some(entry) = bypass_risk(evidence.overrides.as_deref(), hosts) {
                AccessPath::Unknown {
                    reason: format!("代理绕过列表含 {entry}，被监控流量可能直连"),
                }
            } else {
                AccessPath::SystemProxy { addr }
            }
        }
        ProxyParse::Unsupported(why) => match tun_adapter {
            Some(adapter) => AccessPath::Tun { adapter },
            None => AccessPath::Unknown {
                reason: format!("系统代理配置无法等价复用：{why}"),
            },
        },
        ProxyParse::Empty => match tun_adapter {
            Some(adapter) => AccessPath::Tun { adapter },
            None => AccessPath::Unknown {
                reason: "系统代理已开启但未读到代理地址".into(),
            },
        },
    }
}

// ---------- Windows Native Implementations ----------

/// Microsecond process elevation check via `OpenProcessToken` + `GetTokenInformation(TokenElevation)`.
#[cfg(windows)]
pub fn is_elevated() -> crate::traits::PlatformResult<bool> {
    use core::ffi::c_void;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    struct HandleGuard(HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    let mut raw_token = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) }
        .map_err(|e| crate::traits::PlatformError::Io(format!("OpenProcessToken failed: {e}")))?;
    let _token = HandleGuard(raw_token);

    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned: u32 = 0;
    let size = core::mem::size_of::<TOKEN_ELEVATION>() as u32;
    unsafe {
        GetTokenInformation(
            raw_token,
            TokenElevation,
            Some((&mut elevation as *mut TOKEN_ELEVATION).cast::<c_void>()),
            size,
            &mut returned,
        )
    }
    .map_err(|e| {
        crate::traits::PlatformError::Io(format!("GetTokenInformation(TokenElevation) failed: {e}"))
    })?;

    Ok(elevation.TokenIsElevated != 0)
}

#[cfg(not(windows))]
pub fn is_elevated() -> crate::traits::PlatformResult<bool> {
    Err(crate::traits::PlatformError::unsupported(
        "elevation",
        "Windows TokenElevation check is only supported on Windows",
    ))
}

/// Returns true if a registry SID string under `HKEY_USERS` / `ProfileList` represents an
/// interactive local/AD (`S-1-5-21-...`) or Entra ID / Azure AD (`S-1-12-1-...`) user, excluding `*_Classes`.
pub fn is_interactive_user_sid(name: &str) -> bool {
    let trimmed = name.trim();
    (trimmed.starts_with("S-1-5-21-") || trimmed.starts_with("S-1-12-1-"))
        && !trimmed.ends_with("_Classes")
        && !trimmed.to_ascii_lowercase().ends_with("_classes")
}

/// Returns true when running inside Windows Session 0 (e.g., `LocalSystem` Windows Service).
#[cfg(windows)]
pub fn is_session_zero() -> bool {
    use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    use windows::Win32::System::Threading::GetCurrentProcessId;

    let mut sid: u32 = 0;
    let ok = unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut sid) }.is_ok();
    ok && sid == 0
}

#[cfg(not(windows))]
pub fn is_session_zero() -> bool {
    false
}

#[cfg(windows)]
fn sid_for_wts_session(session_id: u32) -> Option<String> {
    use core::ffi::c_void;
    use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_USER};
    use windows::Win32::System::RemoteDesktop::WTSQueryUserToken;

    if session_id == u32::MAX || session_id == 0 {
        return None;
    }
    let mut token = HANDLE::default();
    if unsafe { WTSQueryUserToken(session_id, &mut token) }.is_err() {
        return None;
    }

    struct HandleGuard(HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
    let _token = HandleGuard(token);

    let mut needed: u32 = 0;
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut needed) };
    if needed == 0 || needed > 64 * 1024 {
        return None;
    }
    let mut buf = vec![0u8; needed as usize];
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr().cast::<c_void>()),
            needed,
            &mut needed,
        )
    }
    .is_err()
    {
        return None;
    }
    let user = unsafe { &*(buf.as_ptr().cast::<TOKEN_USER>()) };
    let mut sid_pwstr = windows::core::PWSTR::null();
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid_pwstr) }.is_err() {
        return None;
    }
    let sid_str = wide_to_string(&unsafe { pwstr_units(sid_pwstr) });
    unsafe {
        let _ = LocalFree(HLOCAL(sid_pwstr.0.cast::<c_void>()));
    }
    if is_interactive_user_sid(&sid_str) {
        Some(sid_str)
    } else {
        None
    }
}

/// Resolves the SID string (`S-1-5-21-...` or `S-1-12-1-...`) of the currently active interactive user.
///
/// Works under `LocalSystem` (Session 0 service) via `WTSGetActiveConsoleSessionId`, falling back
/// to `WTSEnumerateSessionsW` (`WTSActive`) so headless RDP sessions resolve cleanly.
#[cfg(windows)]
pub fn active_interactive_user_sid() -> Option<String> {
    use core::ffi::c_void;
    use windows::Win32::System::RemoteDesktop::{
        WTSActive, WTSEnumerateSessionsW, WTSFreeMemory, WTSGetActiveConsoleSessionId,
        WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW,
    };

    let console_id = unsafe { WTSGetActiveConsoleSessionId() };
    if let Some(sid) = sid_for_wts_session(console_id) {
        return Some(sid);
    }

    let mut sessions_ptr: *mut WTS_SESSION_INFOW = core::ptr::null_mut();
    let mut count: u32 = 0;
    if unsafe {
        WTSEnumerateSessionsW(
            WTS_CURRENT_SERVER_HANDLE,
            0,
            1,
            &mut sessions_ptr,
            &mut count,
        )
    }
    .is_err()
        || sessions_ptr.is_null()
    {
        return None;
    }

    struct WtsMemGuard(*mut c_void);
    impl Drop for WtsMemGuard {
        fn drop(&mut self) {
            unsafe {
                WTSFreeMemory(self.0);
            }
        }
    }
    let _guard = WtsMemGuard(sessions_ptr.cast::<c_void>());

    let sessions = unsafe { core::slice::from_raw_parts(sessions_ptr, count as usize) };
    for info in sessions {
        if info.SessionId != 0 && info.SessionId != console_id && info.State == WTSActive {
            if let Some(sid) = sid_for_wts_session(info.SessionId) {
                return Some(sid);
            }
        }
    }
    None
}

#[cfg(not(windows))]
pub fn active_interactive_user_sid() -> Option<String> {
    None
}

/// Opens a per-user registry subkey for the interactive desktop user.
///
/// - When running in an interactive user session (`Session > 0`), opens `HKCU\<subpath>` directly.
/// - When running in Session 0 (`LocalSystem` Windows Service), opens
///   `HKEY_USERS\<ActiveConsoleUserSID>\<subpath>`, falling back to the first loaded interactive
///   `S-1-5-21-*` hive under `HKEY_USERS` (so RDP/multi-session hosts still resolve cleanly), and
///   finally `HKCU\<subpath>`.
#[cfg(windows)]
pub fn open_interactive_user_subkey(subpath: &str) -> Option<winreg::RegKey> {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_USERS, KEY_READ};
    use winreg::RegKey;

    if !is_session_zero() {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        return hkcu.open_subkey_with_flags(subpath, KEY_READ).ok();
    }

    let hku = RegKey::predef(HKEY_USERS);
    if let Some(sid) = active_interactive_user_sid() {
        let full = format!("{sid}\\{subpath}");
        if let Ok(key) = hku.open_subkey_with_flags(&full, KEY_READ) {
            return Some(key);
        }
    }

    // Fallback: enumerate loaded interactive user hives in HKEY_USERS (`S-1-5-21-*`, non-`_Classes`).
    let mut first_match: Option<RegKey> = None;
    for sub in hku.enum_keys().flatten() {
        if !is_interactive_user_sid(&sub) {
            continue;
        }
        let full = format!("{sub}\\{subpath}");
        if let Ok(key) = hku.open_subkey_with_flags(&full, KEY_READ) {
            let proxy_on: u32 = key.get_value("ProxyEnable").unwrap_or(0);
            if proxy_on != 0 {
                return Some(key);
            }
            if first_match.is_none() {
                first_match = Some(key);
            }
        }
    }
    if first_match.is_some() {
        return first_match;
    }

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    hkcu.open_subkey_with_flags(subpath, KEY_READ).ok()
}

/// Returns `false` when `Connections\DefaultConnectionSettings` explicitly indicates
/// `PROXY_TYPE_AUTO_PROXY_URL` (`0x04` at byte 8) is disabled, guarding against stale `AutoConfigURL`.
pub(crate) fn is_autoconfig_flag_enabled(default_conn_settings: Option<&[u8]>) -> bool {
    match default_conn_settings {
        Some(bytes) if bytes.len() >= 9 => (bytes[8] & 0x04) != 0,
        _ => true,
    }
}

/// Read `Software\Microsoft\Windows\CurrentVersion\Internet Settings` for the active desktop user
/// (Session-0 `LocalSystem`-safe via `HKEY_USERS\<ActiveUserSID>`).
#[cfg(windows)]
pub fn read_proxy_evidence() -> AccessEvidenceRaw {
    let Some(settings) = open_interactive_user_subkey(
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
    ) else {
        return AccessEvidenceRaw::default();
    };
    let enabled: u32 = settings.get_value("ProxyEnable").unwrap_or(0);
    let read_opt = |name: &str| -> Option<String> {
        let value: String = settings.get_value(name).ok()?;
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(value)
        }
    };
    let mut autoconfig = read_opt("AutoConfigURL");
    if autoconfig.is_some() {
        let conn_bytes = settings
            .open_subkey_with_flags("Connections", winreg::enums::KEY_READ)
            .ok()
            .and_then(|conn| conn.get_raw_value("DefaultConnectionSettings").ok())
            .map(|v| v.bytes);
        if !is_autoconfig_flag_enabled(conn_bytes.as_deref()) {
            autoconfig = None;
        }
    }
    AccessEvidenceRaw {
        enable: enabled != 0,
        server: read_opt("ProxyServer"),
        autoconfig,
        overrides: read_opt("ProxyOverride"),
    }
}

#[cfg(not(windows))]
pub fn read_proxy_evidence() -> AccessEvidenceRaw {
    AccessEvidenceRaw::default()
}

#[cfg(windows)]
unsafe fn pwstr_units(p: windows::core::PWSTR) -> Vec<u16> {
    if p.is_null() {
        return Vec::new();
    }
    let mut len = 0usize;
    while len < 4096 && *p.0.add(len) != 0 {
        len += 1;
    }
    core::slice::from_raw_parts(p.0, len).to_vec()
}

/// Returns `true` if a unicast IP on a candidate TUN interface is routable (excluding unspecified,
/// loopback, IPv4 APIPA `169.254.0.0/16`, IPv6 link-local `fe80::/10`, and multicast/broadcast).
pub(crate) fn is_usable_tun_unicast_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            !v4.is_unspecified()
                && !v4.is_loopback()
                && !v4.is_link_local()
                && !v4.is_multicast()
                && !v4.is_broadcast()
        }
        std::net::IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_usable_tun_unicast_ip(std::net::IpAddr::V4(v4));
            }
            let seg0 = v6.segments()[0];
            !v6.is_unspecified()
                && !v6.is_loopback()
                && !v6.is_multicast()
                && (seg0 & 0xffc0) != 0xfe80
        }
    }
}

#[cfg(windows)]
unsafe fn adapter_has_usable_unicast(
    mut cur: *mut windows::Win32::NetworkManagement::IpHelper::IP_ADAPTER_UNICAST_ADDRESS_LH,
) -> bool {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    let mut guard = 0usize;
    while !cur.is_null() && guard < 256 {
        guard += 1;
        let ua = &*cur;
        let ptr = ua.Address.lpSockaddr.cast::<u8>();
        let len = ua.Address.iSockaddrLength as usize;
        if !ptr.is_null() && len >= 2 {
            let bytes = core::slice::from_raw_parts(ptr, len);
            let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
            if family == AF_INET.0 && len >= 8 {
                let v4 = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
                if is_usable_tun_unicast_ip(IpAddr::V4(v4)) {
                    return true;
                }
            } else if family == AF_INET6.0 && len >= 24 {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&bytes[8..24]);
                let v6 = Ipv6Addr::from(octets);
                if is_usable_tun_unicast_ip(IpAddr::V6(v6)) {
                    return true;
                }
            }
        }
        cur = ua.Next;
    }
    false
}

/// Detect active Up TUN adapter with at least one usable unicast IP using `IpHelper::GetAdaptersAddresses`.
#[cfg(windows)]
pub fn detect_tun_adapter() -> Option<String> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
        GAA_FLAG_SKIP_MULTICAST, GET_ADAPTERS_ADDRESSES_FLAGS, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;

    const FAMILY_UNSPEC: u32 = 0;
    const ERROR_BUFFER_OVERFLOW: u32 = 111;

    let flags = GET_ADAPTERS_ADDRESSES_FLAGS(
        GAA_FLAG_SKIP_ANYCAST.0 | GAA_FLAG_SKIP_MULTICAST.0 | GAA_FLAG_SKIP_DNS_SERVER.0,
    );
    let mut size: u32 = 32 * 1024;
    for _ in 0..4 {
        let mut buffer: Vec<u64> = vec![0; (size as usize).div_ceil(8)];
        let rc = unsafe {
            GetAdaptersAddresses(
                FAMILY_UNSPEC,
                flags,
                None,
                Some(buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>()),
                &mut size,
            )
        };
        if rc == 0 {
            let mut candidates: Vec<(String, String, bool)> = Vec::new();
            let mut current = buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
            while !current.is_null() {
                let adapter = unsafe { &*current };
                let desc = wide_to_string(&unsafe { pwstr_units(adapter.Description) });
                let friendly = wide_to_string(&unsafe { pwstr_units(adapter.FriendlyName) });
                let is_up = adapter.OperStatus == IfOperStatusUp
                    && unsafe { adapter_has_usable_unicast(adapter.FirstUnicastAddress) };
                candidates.push((desc, friendly, is_up));
                current = adapter.Next;
            }
            return select_tun(&candidates);
        }
        if rc != ERROR_BUFFER_OVERFLOW {
            return None;
        }
    }
    None
}

#[cfg(not(windows))]
pub fn detect_tun_adapter() -> Option<String> {
    None
}

/// Resolve current Windows access path (registry proxy + TUN adapter).
#[cfg(windows)]
pub fn inspect_access_path(monitored_hosts: &[String]) -> (AccessPath, AccessInfo) {
    let evidence = read_proxy_evidence();
    let tun = detect_tun_adapter();
    let path = verdict(&evidence, tun, monitored_hosts);
    let info = AccessInfo::from(&path);
    (path, info)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hosts() -> Vec<String> {
        vec!["claude.ai".into(), "chatgpt.com".into()]
    }

    fn ev(enable: bool, server: Option<&str>) -> AccessEvidenceRaw {
        AccessEvidenceRaw {
            enable,
            server: server.map(str::to_string),
            autoconfig: None,
            overrides: None,
        }
    }

    #[test]
    fn proxyserver_forms_and_ipv6_loopback() {
        assert_eq!(parse_proxy_server(None), ProxyParse::Empty);
        assert_eq!(parse_proxy_server(Some("  ")), ProxyParse::Empty);
        assert_eq!(
            parse_proxy_server(Some("127.0.0.1:7890")),
            ProxyParse::Http("127.0.0.1:7890".into())
        );
        assert_eq!(
            parse_proxy_server(Some("[::1]:7890")),
            ProxyParse::Http("[::1]:7890".into())
        );
        assert_eq!(
            parse_proxy_server(Some(
                "http=127.0.0.1:80;https=127.0.0.1:7891;ftp=127.0.0.1:21"
            )),
            ProxyParse::Http("127.0.0.1:7891".into())
        );
        assert_eq!(
            parse_proxy_server(Some("http=127.0.0.1:80;ftp=127.0.0.1:21")),
            ProxyParse::Http("127.0.0.1:80".into())
        );
        assert_eq!(
            parse_proxy_server(Some("http://127.0.0.1:7890")),
            ProxyParse::Http("127.0.0.1:7890".into())
        );
        assert_eq!(
            parse_proxy_server(Some("HTTPS://127.0.0.1:7891/")),
            ProxyParse::Http("127.0.0.1:7891".into())
        );
    }

    #[test]
    fn unsupported_and_incomplete_proxy_forms_are_rejected() {
        assert!(matches!(
            parse_proxy_server(Some("socks=127.0.0.1:1080")),
            ProxyParse::Unsupported(_)
        ));
        assert!(matches!(
            parse_proxy_server(Some("socks5://127.0.0.1:1080")),
            ProxyParse::Unsupported(_)
        ));
        assert!(matches!(
            parse_proxy_server(Some("127.0.0.1")),
            ProxyParse::Unsupported(_)
        ));
        assert!(matches!(
            parse_proxy_server(Some("[::1]")),
            ProxyParse::Unsupported(_)
        ));
        assert!(matches!(
            parse_proxy_server(Some("127.0.0.1:abc")),
            ProxyParse::Unsupported(_)
        ));
        assert!(matches!(
            verdict(&ev(true, None), None, &[]),
            AccessPath::Unknown { .. }
        ));
    }

    #[test]
    fn pac_forces_unknown_regardless_of_proxy_enable() {
        let mut e = ev(true, Some("127.0.0.1:7890"));
        e.autoconfig = Some("http://127.0.0.1:7890/pac".into());
        assert!(matches!(
            verdict(&e, None, &hosts()),
            AccessPath::Unknown { .. }
        ));

        let mut off = ev(false, None);
        off.autoconfig = Some("http://127.0.0.1:7890/pac".into());
        assert!(matches!(
            verdict(&off, Some("Mihomo".into()), &hosts()),
            AccessPath::Unknown { .. }
        ));
    }

    #[test]
    fn bypass_semantics_preserve_local_and_flag_ai_suffixes() {
        let mut e = ev(true, Some("127.0.0.1:7890"));
        let expected = AccessPath::SystemProxy {
            addr: "127.0.0.1:7890".into(),
        };
        e.overrides =
            Some("localhost;*.local;127.*;10.*;192.168.*;172.16.*;172.31.*;<local>".into());
        assert_eq!(verdict(&e, None, &hosts()), expected);

        e.overrides = Some("<local>;*example.org".into());
        assert_eq!(verdict(&e, None, &hosts()), expected);

        e.overrides = Some("<local>;*claude.ai".into());
        assert!(matches!(
            verdict(&e, None, &hosts()),
            AccessPath::Unknown { .. }
        ));

        e.overrides = Some("*.anthropic.com".into());
        assert!(matches!(
            verdict(&e, None, &hosts()),
            AccessPath::Unknown { .. }
        ));

        e.overrides = Some("*".into());
        assert_eq!(verdict(&e, None, &hosts()), AccessPath::Uncovered);
    }

    #[test]
    fn wide_string_and_tun_selection_rules() {
        let name = "Wintun Userspace Tunnel";
        let units: Vec<u16> = name.encode_utf16().collect();
        assert_eq!(wide_to_string(&units), name);

        assert!(is_tun_name("Mihomo"));
        assert!(is_tun_name("sing-box tun0"));
        assert!(!is_tun_name("Tailscale Tunnel"));
        assert!(!is_tun_name("Realtek PCIe GbE Family Controller"));

        assert_eq!(
            select_tun(&[("Mihomo".into(), "Mihomo".into(), false)]),
            None
        );
        assert_eq!(
            select_tun(&[("Ethernet 2".into(), "Clash TUN".into(), true)]).as_deref(),
            Some("Clash TUN")
        );
        // Split-tunnel mesh VPNs using generic Wintun description must NEVER bypass exclusion!
        assert_eq!(
            select_tun(&[
                ("Wintun Userspace Tunnel".into(), "Tailscale".into(), true),
                (
                    "Wintun Userspace Tunnel".into(),
                    "ZeroTier One".into(),
                    true
                ),
                ("Wintun Userspace Tunnel".into(), "EasyTier".into(), true),
                ("Wintun Userspace Tunnel".into(), "Sparkle TUN".into(), true),
            ])
            .as_deref(),
            Some("Wintun Userspace Tunnel")
        );
        assert!(is_tun_name("sing-tun"));
        assert!(is_tun_name("tun0"));
        assert!(is_tun_name("tun"));
        assert!(!is_tun_name("iTunes"));
    }

    #[test]
    fn entra_id_sid_stale_pac_apipa_unicast_and_simultaneous_socks_tun() {
        use std::net::{IpAddr, Ipv4Addr};

        // 1. Entra ID / Azure AD SID (`S-1-12-1-*`) + AD/local (`S-1-5-21-*`)
        assert!(is_interactive_user_sid("S-1-5-21-123456-789-1001"));
        assert!(is_interactive_user_sid(
            "S-1-12-1-2045678901-1098765432-2345678901-3456789012"
        ));
        assert!(!is_interactive_user_sid("S-1-12-1-2045678901_Classes"));
        assert!(!is_interactive_user_sid("S-1-5-18"));

        // 2. Stale `AutoConfigURL` cleared when `DefaultConnectionSettings[8] & 0x04 == 0`
        let mut blob_off = [0u8; 12];
        blob_off[0] = 0x46;
        blob_off[8] = 0x03; // DIRECT | PROXY, AUTO_PROXY_URL (0x04) cleared
        assert!(!is_autoconfig_flag_enabled(Some(&blob_off)));

        let mut blob_on = blob_off;
        blob_on[8] = 0x05; // DIRECT | AUTO_PROXY_URL
        assert!(is_autoconfig_flag_enabled(Some(&blob_on)));
        assert!(is_autoconfig_flag_enabled(Some(&[0x46, 0x00])));
        assert!(is_autoconfig_flag_enabled(None));

        // 3. Dead TAP-Windows APIPA (`169.254.x.x`) & IPv6 link-local (`fe80::`) rejected
        assert!(!is_usable_tun_unicast_ip(IpAddr::V4(Ipv4Addr::new(
            169, 254, 12, 34
        ))));
        assert!(!is_usable_tun_unicast_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!is_usable_tun_unicast_ip("fe80::1".parse().unwrap()));
        assert!(!is_usable_tun_unicast_ip("::1".parse().unwrap()));
        assert!(is_usable_tun_unicast_ip(IpAddr::V4(Ipv4Addr::new(
            198, 18, 0, 1
        ))));
        assert!(is_usable_tun_unicast_ip(
            "fdfe:dcba:9876::1".parse().unwrap()
        ));

        // 4. Simultaneous SOCKS-only / empty ProxyServer + active TUN -> AccessPath::Tun
        assert_eq!(
            verdict(
                &ev(true, Some("socks=127.0.0.1:1080")),
                Some("Mihomo".into()),
                &hosts()
            ),
            AccessPath::Tun {
                adapter: "Mihomo".into()
            }
        );
        assert_eq!(
            verdict(&ev(true, None), Some("sing-tun".into()), &hosts()),
            AccessPath::Tun {
                adapter: "sing-tun".into()
            }
        );

        // 5. Chromium `<-loopback>` and `*.` local rules do not trigger bypass risk
        let mut e = ev(true, Some("127.0.0.1:7890"));
        e.overrides = Some("<local>;<-loopback>;*.;127.0.0.1;192.168.1.*".into());
        assert_eq!(
            verdict(&e, None, &hosts()),
            AccessPath::SystemProxy {
                addr: "127.0.0.1:7890".into()
            }
        );
        assert!(!bypass_hits_host("*.", "claude.ai"));
        assert!(bypass_hits_host("*.*", "claude.ai"));
    }

    #[test]
    fn verdict_and_access_info_matrix() {
        assert_eq!(
            verdict(
                &ev(true, Some("127.0.0.1:7890")),
                Some("Mihomo".into()),
                &[]
            ),
            AccessPath::SystemProxy {
                addr: "127.0.0.1:7890".into()
            }
        );
        assert_eq!(
            verdict(&ev(false, None), Some("Mihomo".into()), &[]),
            AccessPath::Tun {
                adapter: "Mihomo".into()
            }
        );
        assert_eq!(verdict(&ev(false, None), None, &[]), AccessPath::Uncovered);

        let uncovered = AccessInfo::from(&AccessPath::Uncovered);
        assert!(uncovered.is_uncovered());
        assert!(!uncovered.is_known());
        let tun = AccessInfo::from(&AccessPath::Tun {
            adapter: "Wintun".into(),
        });
        assert!(tun.is_known());
    }

    #[test]
    fn monitored_hosts_parses_https_urls_only() {
        let list = monitored_hosts_from_urls([
            "https://claude.ai/cdn-cgi/trace",
            "https://chatgpt.com/cdn-cgi/trace",
            "https://claude.ai/other",
            "http://insecure.example/ignore",
        ]);
        assert_eq!(list, vec!["claude.ai", "chatgpt.com"]);
    }

    #[cfg(windows)]
    #[test]
    fn elevation_and_registry_and_tun_queries_do_not_panic() {
        let _elevated = is_elevated().expect("OpenProcessToken/GetTokenInformation should succeed");
        let _ev = read_proxy_evidence();
        let _tun = detect_tun_adapter();
    }
}
