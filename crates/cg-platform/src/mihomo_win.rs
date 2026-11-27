//! Local Mihomo / Clash Meta External Controller discovery, status polling, and node switching.
//!
//! Security boundary: strictly restricted to loopback endpoints (`127.0.0.1` / `localhost` / `[::1]`)
//! so controller queries and secrets NEVER leave the host machine.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use cg_protocol::{MihomoNodeInfo, MihomoStatus};

const DEFAULT_LOOPBACK_PORTS: [u16; 3] = [9090, 9097, 9091];
const DEFAULT_NAMED_PIPES: [&str; 2] = [r"\\.\pipe\verge-mihomo", r"\\.\pipe\mihomo"];
const WELL_KNOWN_LOCAL_PROXY_PORTS: [u16; 8] = [7897, 7890, 7891, 10809, 10808, 2080, 20171, 1080];
const MAX_CANDIDATE_NODES: usize = 64;
const MAX_PIPE_HTTP_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const PREFERRED_GROUPS: [&str; 9] = [
    "claude",
    "ai",
    "openai",
    "proxy",
    "节点选择",
    "代理选择",
    "手动切换",
    "select",
    "global",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControllerEndpoint {
    pub base_url: String,
    pub secret: Option<String>,
}

fn strip_ascii_prefix_ci<'a>(s: &'a str, prefix_ascii: &str) -> Option<&'a str> {
    if !prefix_ascii.is_ascii() {
        return None;
    }
    let head = s.as_bytes().get(..prefix_ascii.len())?;
    head.eq_ignore_ascii_case(prefix_ascii.as_bytes())
        .then(|| s.get(prefix_ascii.len()..))
        .flatten()
}

/// Validates and normalizes an `external-controller` value into a loopback HTTP base URL.
pub fn normalize_loopback_controller(raw: &str) -> Option<String> {
    let mut trimmed = raw.trim().trim_matches('"').trim_matches('\'').trim();
    if let Some(rest) = strip_ascii_prefix_ci(trimmed, "http://")
        .or_else(|| strip_ascii_prefix_ci(trimmed, "https://"))
    {
        trimmed = rest;
    }
    let trimmed = trimmed.trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let normalized = if let Some(port) = trimmed.strip_prefix(":::") {
        format!("[::1]:{port}")
    } else if let Some(port) = trimmed.strip_prefix("[::]:") {
        format!("[::1]:{port}")
    } else if let Some(port) = trimmed.strip_prefix(':') {
        format!("127.0.0.1:{port}")
    } else if let Some(rest) = trimmed.strip_prefix("0.0.0.0:") {
        format!("127.0.0.1:{rest}")
    } else if strip_ascii_prefix_ci(trimmed, "127.0.0.1:").is_some()
        || strip_ascii_prefix_ci(trimmed, "localhost:").is_some()
        || strip_ascii_prefix_ci(trimmed, "[::1]:").is_some()
    {
        trimmed.to_ascii_lowercase()
    } else {
        return None;
    };
    let port_str = normalized.rsplit_once(':')?.1;
    let port: u16 = port_str.parse().ok()?;
    if port == 0 {
        return None;
    }
    Some(format!("http://{normalized}"))
}

fn parse_yaml_scalar(raw: &str) -> String {
    let s = raw.trim();
    if let Some(after_quote) = s.strip_prefix('"') {
        let mut out = String::new();
        let mut chars = after_quote.chars();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                if let Some(esc) = chars.next() {
                    out.push(esc);
                }
            } else if ch == '"' {
                return out;
            } else {
                out.push(ch);
            }
        }
        return out;
    }
    if let Some(after_quote) = s.strip_prefix('\'') {
        let mut out = String::new();
        let mut chars = after_quote.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '\'' {
                if chars.peek() == Some(&'\'') {
                    let _ = chars.next();
                    out.push('\'');
                } else {
                    return out;
                }
            } else {
                out.push(ch);
            }
        }
        return out;
    }
    if s.starts_with('#') {
        return String::new();
    }
    let mut end = s.len();
    for (idx, ch) in s.char_indices() {
        if ch == '#' && idx > 0 && s.as_bytes()[idx - 1].is_ascii_whitespace() {
            end = idx;
            break;
        }
    }
    s.get(..end).unwrap_or(s).trim().to_string()
}

/// Lightweight zero-dependency YAML line parser for `external-controller` and `secret`.
pub fn parse_clash_yaml_controller(content: &str) -> Option<ControllerEndpoint> {
    let content = content.strip_prefix('\u{feff}').unwrap_or(content);
    let mut ctrl: Option<String> = None;
    let mut secret: Option<String> = None;

    for raw_line in content.lines() {
        let raw_line = raw_line.strip_prefix('\u{feff}').unwrap_or(raw_line);
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Only inspect top-level keys (no leading indent in raw_line)
        if raw_line.starts_with(' ') || raw_line.starts_with('\t') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("external-controller:") {
            let val = parse_yaml_scalar(rest);
            if let Some(url) = normalize_loopback_controller(&val) {
                ctrl = Some(url);
            }
        } else if let Some(rest) = line.strip_prefix("secret:") {
            let val = parse_yaml_scalar(rest);
            if !val.is_empty() {
                secret = Some(val);
            }
        }
    }

    ctrl.map(|base_url| ControllerEndpoint { base_url, secret })
}

/// Validates and normalizes a Windows local Named Pipe controller path (`\\.\pipe\<segment>`),
/// strictly rejecting UNC remote hosts, path traversal, or multi-segment paths.
pub fn normalize_windows_named_pipe(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_matches('"').trim_matches('\'').trim();
    if trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("null")
        || trimmed.eq_ignore_ascii_case("~")
        || trimmed.eq_ignore_ascii_case("false")
    {
        return None;
    }
    let norm = trimmed.replace('/', "\\");
    let seg = if let Some(rest) = strip_ascii_prefix_ci(&norm, r"\\.\pipe\") {
        rest
    } else if !norm.contains('\\') && !norm.contains(':') {
        norm.as_str()
    } else {
        return None;
    };
    let seg = seg.trim();
    if seg.is_empty()
        || seg.len() > 128
        || seg == "."
        || seg == ".."
        || seg.contains("..")
        || !seg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return None;
    }
    Some(format!(r"\\.\pipe\{seg}"))
}

/// Extracts a standalone top-level `secret:` token from Clash/Mihomo/Verge YAML even when
/// `external-controller:` is omitted, disabled, or replaced by `external-controller-pipe:`.
pub fn parse_clash_yaml_secret(content: &str) -> Option<String> {
    let content = content.strip_prefix('\u{feff}').unwrap_or(content);
    let mut secret: Option<String> = None;
    for raw_line in content.lines() {
        let raw_line = raw_line.strip_prefix('\u{feff}').unwrap_or(raw_line);
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if raw_line.starts_with(' ') || raw_line.starts_with('\t') {
            continue;
        }
        for key in ["secret:", "clash_secret:", "verge_secret:"] {
            if let Some(rest) = line.strip_prefix(key) {
                let val = parse_yaml_scalar(rest);
                if !val.is_empty()
                    && !val.eq_ignore_ascii_case("null")
                    && !val.eq_ignore_ascii_case("~")
                {
                    secret = Some(val);
                }
            }
        }
    }
    secret
}

/// Extracts configured local HTTP/mixed/SOCKS proxy ports from Clash/Mihomo/Verge YAML files,
/// ordered with HTTP/mixed ports ahead of SOCKS-only ports.
pub fn parse_clash_yaml_proxy_ports(content: &str) -> Vec<u16> {
    let content = content.strip_prefix('\u{feff}').unwrap_or(content);
    let mut mixed_or_http = Vec::new();
    let mut socks = Vec::new();

    for raw_line in content.lines() {
        let raw_line = raw_line.strip_prefix('\u{feff}').unwrap_or(raw_line);
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if raw_line.starts_with(' ') || raw_line.starts_with('\t') {
            continue;
        }
        for key in ["mixed-port:", "verge_mixed_port:", "port:", "verge_port:"] {
            if let Some(rest) = line.strip_prefix(key) {
                if let Ok(p) = parse_yaml_scalar(rest).parse::<u16>() {
                    if p > 0 && !mixed_or_http.contains(&p) {
                        mixed_or_http.push(p);
                    }
                }
            }
        }
        for key in ["socks-port:", "verge_socks_port:"] {
            if let Some(rest) = line.strip_prefix(key) {
                if let Ok(p) = parse_yaml_scalar(rest).parse::<u16>() {
                    if p > 0 && !socks.contains(&p) {
                        socks.push(p);
                    }
                }
            }
        }
    }

    for p in socks {
        if !mixed_or_http.contains(&p) {
            mixed_or_http.push(p);
        }
    }
    mixed_or_http
}

/// Detects whether a Clash/Mihomo YAML config defines a non-empty `external-controller-pipe:`
/// (e.g. Clash Verge Rev v2+ Named Pipe mode when TCP `external-controller` is disabled).
pub fn parse_clash_yaml_pipe(content: &str) -> Option<String> {
    let content = content.strip_prefix('\u{feff}').unwrap_or(content);
    let mut pipe: Option<String> = None;
    for raw_line in content.lines() {
        let raw_line = raw_line.strip_prefix('\u{feff}').unwrap_or(raw_line);
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if raw_line.starts_with(' ') || raw_line.starts_with('\t') {
            continue;
        }
        for key in ["external-controller-pipe:", "verge_ctrl_pipe:"] {
            if let Some(rest) = line.strip_prefix(key) {
                let val = parse_yaml_scalar(rest);
                if let Some(norm) = normalize_windows_named_pipe(&val) {
                    pipe = Some(norm);
                }
            }
        }
    }
    pipe
}

pub(crate) fn candidate_config_paths_for_homes(homes: &[PathBuf]) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for home in homes {
        let roaming = home.join("AppData").join("Roaming");
        let local = home.join("AppData").join("Local");

        for app_base in [&roaming, &local] {
            paths.push(
                app_base
                    .join("io.github.clash-verge-rev.clash-verge-rev")
                    .join("clash-verge.yaml"),
            );
            paths.push(
                app_base
                    .join("io.github.clash-verge-rev.clash-verge-rev")
                    .join("verge.yaml"),
            );
            paths.push(
                app_base
                    .join("io.github.clash-verge-rev.clash-verge-rev")
                    .join("config.yaml"),
            );
            paths.push(app_base.join("clash-verge").join("clash-verge.yaml"));
            paths.push(app_base.join("clash-verge").join("verge.yaml"));
            paths.push(app_base.join("clash-verge").join("config.yaml"));
            paths.push(app_base.join("clash-nyanpasu").join("clash-config.yaml"));
            paths.push(app_base.join("clash-nyanpasu").join("config.yaml"));
            paths.push(
                app_base
                    .join("mihomo-party")
                    .join("work")
                    .join("mihomo.yaml"),
            );
            paths.push(
                app_base
                    .join("mihomo-party")
                    .join("work")
                    .join("config.yaml"),
            );
            paths.push(app_base.join("mihomo-party").join("mihomo.yaml"));
            paths.push(app_base.join("mihomo-party").join("config.yaml"));
            paths.push(app_base.join("sparkle").join("work").join("sparkle.yaml"));
            paths.push(app_base.join("sparkle").join("work").join("config.yaml"));
            paths.push(app_base.join("sparkle").join("sparkle.yaml"));
            paths.push(app_base.join("sparkle").join("config.yaml"));
            paths.push(
                app_base
                    .join("com.follow")
                    .join("flclash")
                    .join("config.yaml"),
            );
            paths.push(
                app_base
                    .join("com.follow")
                    .join("clash")
                    .join("config.yaml"),
            );
            paths.push(app_base.join("flclash").join("config.yaml"));
            paths.push(app_base.join("mihomo").join("config.yaml"));
        }
        paths.push(home.join(".config").join("mihomo").join("config.yaml"));
        paths.push(home.join(".config").join("clash").join("config.yaml"));
    }
    paths
}

fn candidate_config_paths() -> Vec<PathBuf> {
    candidate_config_paths_for_homes(&crate::process_win::user_home_dirs())
}

pub(crate) fn dedup_endpoints_with_secrets(
    from_configs: Vec<ControllerEndpoint>,
    extra_secrets: &[String],
) -> Vec<ControllerEndpoint> {
    let mut found = Vec::new();
    for ep in from_configs {
        if !found.contains(&ep) {
            found.push(ep);
        }
    }
    for port in DEFAULT_LOOPBACK_PORTS {
        let base_url = format!("http://127.0.0.1:{port}");
        for sec in extra_secrets {
            let candidate = ControllerEndpoint {
                base_url: base_url.clone(),
                secret: Some(sec.clone()),
            };
            if !found.contains(&candidate) {
                found.push(candidate);
            }
        }
        let fallback = ControllerEndpoint {
            base_url,
            secret: None,
        };
        if !found.contains(&fallback) {
            found.push(fallback);
        }
    }
    found
}

#[cfg(test)]
pub(crate) fn dedup_endpoints(from_configs: Vec<ControllerEndpoint>) -> Vec<ControllerEndpoint> {
    dedup_endpoints_with_secrets(from_configs, &[])
}

struct DiscoveredControllers {
    endpoints: Vec<ControllerEndpoint>,
    pipes: Vec<String>,
    pipe_hint: Option<String>,
    secrets: Vec<String>,
}

fn discover_controllers() -> DiscoveredControllers {
    let mut raw = Vec::new();
    let mut pipe_hint: Option<String> = None;
    let mut pipes = Vec::new();
    let mut secrets = Vec::new();

    for path in candidate_config_paths() {
        if let Ok(text) = fs::read_to_string(&path) {
            if let Some(sec) = parse_clash_yaml_secret(&text) {
                if !secrets.contains(&sec) {
                    secrets.push(sec);
                }
            }
            if let Some(ep) = parse_clash_yaml_controller(&text) {
                if let Some(ref sec) = ep.secret {
                    if !secrets.contains(sec) {
                        secrets.push(sec.clone());
                    }
                }
                raw.push(ep);
            }
            if let Some(p) = parse_clash_yaml_pipe(&text) {
                if pipe_hint.is_none() {
                    pipe_hint = Some(p.clone());
                }
                if !pipes.contains(&p) {
                    pipes.push(p);
                }
            }
        }
    }
    for def_pipe in DEFAULT_NAMED_PIPES {
        let s = def_pipe.to_string();
        if !pipes.contains(&s) {
            pipes.push(s);
        }
    }

    DiscoveredControllers {
        endpoints: dedup_endpoints_with_secrets(raw, &secrets),
        pipes,
        pipe_hint,
        secrets,
    }
}

/// Returns all TCP ports currently in `LISTEN` state on loopback (`127.0.0.0/8`, `::1`) or
/// wildcard (`0.0.0.0`, `::`) interfaces via `GetExtendedTcpTable` (zero socket handshake noise).
#[cfg(windows)]
pub(crate) fn listening_loopback_tcp_ports() -> std::collections::HashSet<u16> {
    use std::collections::HashSet;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use windows::Win32::Foundation::{BOOL, ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID,
        MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_LISTENER,
    };
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    const MIB_TCP_STATE_LISTEN: u32 = 2;

    fn fetch_table(af: u32) -> Option<Vec<u64>> {
        for _ in 0..3 {
            let mut size: u32 = 0;
            unsafe {
                GetExtendedTcpTable(
                    None,
                    &mut size,
                    BOOL(0),
                    af,
                    TCP_TABLE_OWNER_PID_LISTENER,
                    0,
                );
            }
            if size == 0 {
                return None;
            }
            let mut buf: Vec<u64> = vec![0u64; (size as usize + 256).div_ceil(8)];
            let mut out_size = (buf.len() * 8) as u32;
            let rc = unsafe {
                GetExtendedTcpTable(
                    Some(buf.as_mut_ptr().cast()),
                    &mut out_size,
                    BOOL(0),
                    af,
                    TCP_TABLE_OWNER_PID_LISTENER,
                    0,
                )
            };
            if rc == ERROR_INSUFFICIENT_BUFFER.0 {
                continue;
            }
            return (rc == NO_ERROR.0).then_some(buf);
        }
        None
    }

    let port_from_dw = |dw_port: u32| -> u16 {
        let b = dw_port.to_ne_bytes();
        u16::from_be_bytes([b[0], b[1]])
    };

    let mut set = HashSet::new();
    if let Some(buf) = fetch_table(AF_INET.0 as u32) {
        let byte_len = buf.len() * 8;
        if byte_len >= core::mem::size_of::<u32>() {
            let table = unsafe { &*buf.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>() };
            let count = table.dwNumEntries as usize;
            let header = core::mem::offset_of!(MIB_TCPTABLE_OWNER_PID, table);
            let row_sz = core::mem::size_of::<MIB_TCPROW_OWNER_PID>();
            if byte_len >= header.saturating_add(count.saturating_mul(row_sz)) {
                let rows = unsafe { core::slice::from_raw_parts(table.table.as_ptr(), count) };
                for row in rows {
                    if row.dwState != MIB_TCP_STATE_LISTEN {
                        continue;
                    }
                    let ip = Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes());
                    if ip.is_loopback() || ip.is_unspecified() {
                        let p = port_from_dw(row.dwLocalPort);
                        if p > 0 {
                            set.insert(p);
                        }
                    }
                }
            }
        }
    }
    if let Some(buf) = fetch_table(AF_INET6.0 as u32) {
        let byte_len = buf.len() * 8;
        if byte_len >= core::mem::size_of::<u32>() {
            let table = unsafe { &*buf.as_ptr().cast::<MIB_TCP6TABLE_OWNER_PID>() };
            let count = table.dwNumEntries as usize;
            let header = core::mem::offset_of!(MIB_TCP6TABLE_OWNER_PID, table);
            let row_sz = core::mem::size_of::<MIB_TCP6ROW_OWNER_PID>();
            if byte_len >= header.saturating_add(count.saturating_mul(row_sz)) {
                let rows = unsafe { core::slice::from_raw_parts(table.table.as_ptr(), count) };
                for row in rows {
                    if row.dwState != MIB_TCP_STATE_LISTEN {
                        continue;
                    }
                    let ip = Ipv6Addr::from(row.ucLocalAddr);
                    if ip.is_loopback() || ip.is_unspecified() {
                        let p = port_from_dw(row.dwLocalPort);
                        if p > 0 {
                            set.insert(p);
                        }
                    }
                }
            }
        }
    }
    set
}

#[cfg(not(windows))]
pub(crate) fn listening_loopback_tcp_ports() -> std::collections::HashSet<u16> {
    use std::net::{SocketAddr, TcpStream};
    let mut set = std::collections::HashSet::new();
    for port in WELL_KNOWN_LOCAL_PROXY_PORTS {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        if TcpStream::connect_timeout(&addr, Duration::from_millis(40)).is_ok() {
            set.insert(port);
        }
    }
    set
}

/// Discovers active local loopback proxy ports in priority order:
/// 1. Ports configured in Clash Verge Rev / Mihomo / FlClash / Mihomo Party / Sparkle YAML files
///    that are currently listening on loopback.
/// 2. Well-known Windows proxy client ports (`7897`, `7890`, `7891`, `10809`, `10808`, `2080`, `20171`, `1080`)
///    currently listening on loopback.
pub fn discover_local_proxy_ports() -> Vec<u16> {
    let listening = listening_loopback_tcp_ports();
    if listening.is_empty() {
        return Vec::new();
    }

    let mut candidates = Vec::new();
    for path in candidate_config_paths() {
        if let Ok(text) = fs::read_to_string(&path) {
            for p in parse_clash_yaml_proxy_ports(&text) {
                if !candidates.contains(&p) {
                    candidates.push(p);
                }
            }
        }
    }
    for p in WELL_KNOWN_LOCAL_PROXY_PORTS {
        if !candidates.contains(&p) {
            candidates.push(p);
        }
    }

    candidates
        .into_iter()
        .filter(|p| listening.contains(p))
        .collect()
}

fn decode_chunked_http_body(raw: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0usize;
    let mut out = Vec::new();
    while pos < raw.len() {
        let line_end = raw[pos..].windows(2).position(|w| w == b"\r\n")?;
        let size_line = core::str::from_utf8(&raw[pos..pos + line_end]).ok()?;
        let hex_part = size_line.split(';').next().unwrap_or("").trim();
        let chunk_len = usize::from_str_radix(hex_part, 16).ok()?;
        pos += line_end + 2;
        if chunk_len == 0 {
            return Some(out);
        }
        let end = pos.checked_add(chunk_len)?;
        if end > raw.len() || out.len().saturating_add(chunk_len) > MAX_PIPE_HTTP_RESPONSE_BYTES {
            return None;
        }
        out.extend_from_slice(&raw[pos..end]);
        pos = end;
        if raw.get(pos..pos + 2) == Some(b"\r\n") {
            pos += 2;
        }
    }
    None
}

fn parse_raw_http_response(buf: &[u8]) -> Option<(u16, String, bool)> {
    let hdr_end = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let hdr_str = core::str::from_utf8(&buf[..hdr_end]).ok()?;
    let mut lines = hdr_str.lines();
    let status_line = lines.next()?.trim();
    let status_code: u16 = status_line.split_whitespace().nth(1)?.parse().ok()?;

    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse::<usize>().ok();
            } else if k.trim().eq_ignore_ascii_case("transfer-encoding")
                && v.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            }
        }
    }

    let body_slice = &buf[hdr_end + 4..];
    if matches!(status_code, 100..=199 | 204 | 304) {
        return Some((status_code, String::new(), true));
    }
    if let Some(cl) = content_length {
        if body_slice.len() >= cl {
            let text = String::from_utf8_lossy(&body_slice[..cl]).into_owned();
            return Some((status_code, text, true));
        }
        return Some((status_code, String::new(), false));
    }
    if chunked {
        if let Some(decoded) = decode_chunked_http_body(body_slice) {
            return Some((
                status_code,
                String::from_utf8_lossy(&decoded).into_owned(),
                true,
            ));
        }
        return Some((status_code, String::new(), false));
    }
    Some((
        status_code,
        String::from_utf8_lossy(body_slice).into_owned(),
        false,
    ))
}

/// Zero-dependency HTTP/1.1 client exchange over a local Windows Named Pipe (`\\.\pipe\<name>`),
/// opened strictly with `SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS` so a user-mode pipe server
/// can NEVER impersonate `LocalSystem`.
#[cfg(windows)]
pub(crate) fn send_named_pipe_http_request(
    pipe_path: &str,
    method: &str,
    path: &str,
    secret: Option<&str>,
    json_body: Option<&str>,
) -> Result<(u16, String), String> {
    use std::io::{Read, Write};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{FromRawHandle, RawHandle};
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_NONE, OPEN_EXISTING,
        SECURITY_ANONYMOUS, SECURITY_SQOS_PRESENT,
    };

    const HRESULT_PIPE_BUSY: i32 = 0x8007_00E7u32 as i32;
    const ERROR_BROKEN_PIPE_RAW: i32 = 109;

    let safe_pipe = normalize_windows_named_pipe(pipe_path)
        .ok_or_else(|| format!("非法的命名管道路径：{pipe_path}"))?;
    let wide: Vec<u16> = std::ffi::OsStr::new(&safe_pipe)
        .encode_wide()
        .chain(Some(0))
        .collect();

    let mut handle_opt = None;
    for attempt in 0..4 {
        match unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS,
                None,
            )
        } {
            Ok(h) if h != INVALID_HANDLE_VALUE && !h.0.is_null() => {
                handle_opt = Some(h);
                break;
            }
            Ok(_) => break,
            Err(e) if e.code().0 == HRESULT_PIPE_BUSY && attempt < 3 => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => {
                return Err(format!(
                    "无法连接命名管道控制接口（external-controller-pipe: {safe_pipe}）：{e}"
                ));
            }
        }
    }
    let handle = handle_opt.ok_or_else(|| {
        format!("命名管道控制接口忙或不可用（external-controller-pipe: {safe_pipe}）")
    })?;
    let mut pipe_file = unsafe { std::fs::File::from_raw_handle(handle.0 as RawHandle) };

    let body_bytes = json_body.map(str::as_bytes).unwrap_or(&[]);
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    if let Some(sec) = secret.map(str::trim).filter(|s| !s.is_empty()) {
        req.push_str(&format!("Authorization: Bearer {sec}\r\n"));
    }
    if json_body.is_some() {
        req.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body_bytes.len()
        ));
    }
    req.push_str("\r\n");

    let mut wire = req.into_bytes();
    wire.extend_from_slice(body_bytes);

    pipe_file
        .write_all(&wire)
        .map_err(|e| format!("写入命名管道请求失败：{e}"))?;
    let _ = pipe_file.flush();

    let mut raw_resp = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        match pipe_file.read(&mut chunk) {
            Ok(0) => break,
            Ok(read_n) => {
                raw_resp.extend_from_slice(&chunk[..read_n]);
                if raw_resp.len() > MAX_PIPE_HTTP_RESPONSE_BYTES {
                    return Err("命名管道响应超出 2MiB 安全上限".into());
                }
                if let Some((code, text, complete)) = parse_raw_http_response(&raw_resp) {
                    if complete {
                        return Ok((code, text));
                    }
                }
            }
            Err(e) if e.raw_os_error() == Some(ERROR_BROKEN_PIPE_RAW) => break,
            Err(e) => return Err(format!("读取命名管道响应失败：{e}")),
        }
    }

    if let Some((code, text, _)) = parse_raw_http_response(&raw_resp) {
        Ok((code, text))
    } else {
        Err("命名管道未返回有效的 HTTP 响应".into())
    }
}

#[cfg(not(windows))]
pub(crate) fn send_named_pipe_http_request(
    pipe_path: &str,
    _method: &str,
    _path: &str,
    _secret: Option<&str>,
    _json_body: Option<&str>,
) -> Result<(u16, String), String> {
    Err(format!(
        "Windows Named Pipe controller ({pipe_path}) is only supported on Windows"
    ))
}

fn pipe_only_diagnostic_note(pipe_name: &str) -> String {
    format!(
        "检测到命名管道控制接口配置（external-controller-pipe: {pipe_name}），但管道当前未响应且未开启本地 HTTP 控制端口"
    )
}

fn build_loopback_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_millis(150))
        .timeout_read(Duration::from_millis(1000))
        .timeout_write(Duration::from_millis(1000))
        .max_idle_connections(0)
        .try_proxy_from_env(false)
        .build()
}

fn apply_auth(req: ureq::Request, secret: Option<&str>) -> ureq::Request {
    if let Some(sec) = secret.map(str::trim).filter(|s| !s.is_empty()) {
        req.set("Authorization", &format!("Bearer {sec}"))
    } else {
        req
    }
}

fn contains_ascii_word(haystack_lower: &str, word: &str) -> bool {
    let hb = haystack_lower.as_bytes();
    let wb = word.as_bytes();
    if wb.is_empty() || hb.len() < wb.len() {
        return false;
    }
    for start in 0..=(hb.len() - wb.len()) {
        if &hb[start..start + wb.len()] == wb {
            let prev_alpha = start > 0 && hb[start - 1].is_ascii_alphabetic();
            let end = start + wb.len();
            let next_alpha = end < hb.len() && hb[end].is_ascii_alphabetic();
            if !prev_alpha && !next_alpha {
                return true;
            }
        }
    }
    false
}

fn group_matches_pref(name_lower: &str, pref: &str) -> bool {
    if name_lower == pref {
        return true;
    }
    if pref.is_ascii() && pref.len() <= 3 {
        return contains_ascii_word(name_lower, pref);
    }
    name_lower.contains(pref)
}

/// Parses Clash/Mihomo `GET /proxies` JSON into active Selector group, node, delay, and candidates.
pub fn parse_proxies_json(
    controller_url: &str,
    core_name: &str,
    body: &str,
) -> Option<MihomoStatus> {
    let root: serde_json::Value = serde_json::from_str(body).ok()?;
    let proxies = root.get("proxies")?.as_object()?;

    let mut selectors: Vec<(&String, &serde_json::Value)> = proxies
        .iter()
        .filter(|(_, v)| {
            v.get("type")
                .and_then(|t| t.as_str())
                .is_some_and(|t| t.eq_ignore_ascii_case("Selector"))
        })
        .collect();

    if selectors.is_empty() {
        return Some(MihomoStatus {
            available: true,
            controller_url: controller_url.to_string(),
            core_name: core_name.to_string(),
            note: "已连接本地代理内核，但未找到可手动切换的 Selector 策略组".into(),
            ..MihomoStatus::default()
        });
    }

    selectors.sort_by_key(|(name, _)| {
        let low = name.to_ascii_lowercase();
        PREFERRED_GROUPS
            .iter()
            .position(|pref| group_matches_pref(&low, pref))
            .unwrap_or(99)
    });

    let (group_name, group_val) = selectors[0];
    let active_node = group_val
        .get("now")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let node_delay = |node_name: &str| -> Option<u32> {
        let history = proxies.get(node_name)?.get("history")?.as_array()?;
        let last = history.last()?;
        let d = last.get("delay")?.as_u64()?;
        if d > 0 {
            Some(d as u32)
        } else {
            None
        }
    };

    let active_delay_ms = node_delay(&active_node);
    let mut candidates = Vec::new();
    if let Some(all) = group_val.get("all").and_then(|v| v.as_array()) {
        for item in all {
            if let Some(name) = item.as_str() {
                if name.eq_ignore_ascii_case("DIRECT") || name.eq_ignore_ascii_case("REJECT") {
                    continue;
                }
                candidates.push(MihomoNodeInfo {
                    name: name.to_string(),
                    delay_ms: node_delay(name),
                });
                if candidates.len() >= MAX_CANDIDATE_NODES {
                    break;
                }
            }
        }
    }
    if !active_node.is_empty()
        && !active_node.eq_ignore_ascii_case("DIRECT")
        && !active_node.eq_ignore_ascii_case("REJECT")
        && !candidates.iter().any(|c| c.name == active_node)
    {
        if candidates.len() >= MAX_CANDIDATE_NODES {
            let _ = candidates.pop();
        }
        candidates.push(MihomoNodeInfo {
            name: active_node.clone(),
            delay_ms: active_delay_ms,
        });
    }

    let note = if active_node.is_empty() {
        format!("已连接 {core_name}（组：{group_name}）")
    } else if let Some(ms) = active_delay_ms {
        format!("{core_name} · 组 [{group_name}] 当前节点：{active_node}（{ms}ms）")
    } else {
        format!("{core_name} · 组 [{group_name}] 当前节点：{active_node}")
    };

    Some(MihomoStatus {
        available: true,
        controller_url: controller_url.to_string(),
        core_name: core_name.to_string(),
        active_group: group_name.clone(),
        active_node,
        active_delay_ms,
        candidates,
        note,
    })
}

fn core_name_from_version_json(ver_text: &str) -> Option<String> {
    let ver_json: serde_json::Value = serde_json::from_str(ver_text).ok()?;
    let ver_str = ver_json.get("version")?.as_str()?;
    if ver_str.trim().is_empty() {
        return None;
    }
    let is_meta = ver_json
        .get("meta")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    Some(if is_meta {
        format!("Mihomo {ver_str}").trim().to_string()
    } else {
        format!("Clash {ver_str}")
    })
}

pub(crate) fn inspect_mihomo_on_pipes(
    pipes: &[String],
    secrets: &[String],
) -> Option<MihomoStatus> {
    let mut secret_opts: Vec<Option<&str>> = vec![None];
    for s in secrets {
        secret_opts.push(Some(s.as_str()));
    }

    for pipe in pipes {
        for &sec in &secret_opts {
            let Ok((code, ver_text)) =
                send_named_pipe_http_request(pipe, "GET", "/version", sec, None)
            else {
                break;
            };
            if matches!(code, 401 | 403) {
                continue;
            }
            if code != 200 {
                break;
            }
            let Some(core_name) = core_name_from_version_json(&ver_text) else {
                break;
            };
            if let Ok((pcode, prox_body)) =
                send_named_pipe_http_request(pipe, "GET", "/proxies", sec, None)
            {
                if pcode == 200 {
                    if let Some(status) = parse_proxies_json(pipe, &core_name, &prox_body) {
                        return Some(status);
                    }
                }
            }
        }
    }
    None
}

/// Probes discovered Named Pipe and loopback HTTP Mihomo/Clash controllers and returns live node status.
pub fn inspect_mihomo() -> MihomoStatus {
    let discovered = discover_controllers();

    // 1. Prefer Named Pipe controllers first (zero Firewall popups; default on Clash Verge Rev v2+).
    if let Some(pipe_status) = inspect_mihomo_on_pipes(&discovered.pipes, &discovered.secrets) {
        return pipe_status;
    }

    // 2. Probe loopback HTTP external-controller endpoints.
    let agent = build_loopback_agent();
    let mut saw_auth_error = false;

    for ep in discovered.endpoints {
        let ver_url = format!("{}/version", ep.base_url);
        let ver_resp = match apply_auth(agent.get(&ver_url), ep.secret.as_deref()).call() {
            Ok(r) if r.status() == 200 => r,
            Ok(r) if matches!(r.status(), 401 | 403) => {
                saw_auth_error = true;
                continue;
            }
            Err(ureq::Error::Status(401 | 403, _)) => {
                saw_auth_error = true;
                continue;
            }
            _ => continue,
        };
        let ver_text = ver_resp.into_string().unwrap_or_default();
        let core_name =
            core_name_from_version_json(&ver_text).unwrap_or_else(|| "Clash / Mihomo".into());

        let prox_url = format!("{}/proxies", ep.base_url);
        if let Ok(prox_resp) = apply_auth(agent.get(&prox_url), ep.secret.as_deref()).call() {
            if let Ok(body) = prox_resp.into_string() {
                if let Some(status) = parse_proxies_json(&ep.base_url, &core_name, &body) {
                    return status;
                }
            }
        }
    }

    let note = if saw_auth_error {
        "检测到本机 Mihomo / Clash 控制接口，但鉴权失败（secret 不匹配）".into()
    } else if let Some(pipe_name) = discovered.pipe_hint {
        pipe_only_diagnostic_note(&pipe_name)
    } else {
        "未检测到本机 Mihomo / Clash 外部控制接口（支持 \\\\.\\pipe\\verge-mihomo 与 127.0.0.1:9090/9097 自动发现）"
            .into()
    };
    MihomoStatus {
        available: false,
        note,
        ..MihomoStatus::default()
    }
}

fn percent_encode_segment(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() * 3);
    for b in raw.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(*b, b'-' | b'_' | b'.' | b'~') {
            out.push(*b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub(crate) fn switch_mihomo_node_on_pipes(
    pipes: &[String],
    secrets: &[String],
    group: &str,
    node: &str,
    close_connections: bool,
) -> Result<Option<String>, String> {
    let mut secret_opts: Vec<Option<&str>> = vec![None];
    for s in secrets {
        secret_opts.push(Some(s.as_str()));
    }
    let put_path = format!("/proxies/{}", percent_encode_segment(group));
    let payload = serde_json::json!({ "name": node }).to_string();
    let mut last_pipe_err: Option<String> = None;

    for pipe in pipes {
        for &sec in &secret_opts {
            let Ok((code, ver_body)) =
                send_named_pipe_http_request(pipe, "GET", "/version", sec, None)
            else {
                break;
            };
            if matches!(code, 401 | 403) {
                last_pipe_err = Some("命名管道控制接口鉴权失败（secret 不匹配）".into());
                continue;
            }
            if code != 200 || core_name_from_version_json(&ver_body).is_none() {
                break;
            }
            match send_named_pipe_http_request(pipe, "PUT", &put_path, sec, Some(&payload)) {
                Ok((pcode, _)) if (200..300).contains(&pcode) => {
                    let mut closed_note = String::new();
                    if close_connections
                        && send_named_pipe_http_request(pipe, "DELETE", "/connections", sec, None)
                            .is_ok_and(|(dc, _)| (200..300).contains(&dc))
                    {
                        closed_note = "并已断开旧连接".to_string();
                    }
                    return Ok(Some(format!(
                        "已将策略组 [{group}] 切换至节点「{node}」{closed_note}"
                    )));
                }
                Ok((pcode, _)) => {
                    last_pipe_err = Some(format!("命名管道切换节点返回 HTTP {pcode}"));
                }
                Err(e) => {
                    last_pipe_err = Some(e);
                }
            }
        }
    }

    match last_pipe_err {
        Some(err) => Err(err),
        None => Ok(None),
    }
}

pub(crate) fn switch_mihomo_node_on_endpoints(
    endpoints: &[ControllerEndpoint],
    pipe_hint: Option<&str>,
    group: &str,
    node: &str,
    close_connections: bool,
) -> Result<String, String> {
    if group.trim().is_empty() || node.trim().is_empty() {
        return Err("策略组名称与目标节点名称均不能为空".into());
    }
    if let Some(hint) = pipe_hint {
        let pipes = vec![hint.to_string()];
        match switch_mihomo_node_on_pipes(&pipes, &[], group, node, close_connections) {
            Ok(Some(msg)) => return Ok(msg),
            Ok(None) => {}
            Err(err) if endpoints.is_empty() => return Err(err),
            Err(_) => {}
        }
    }

    let agent = build_loopback_agent();
    let mut last_err = match pipe_hint {
        Some(pipe_name) => pipe_only_diagnostic_note(pipe_name),
        None => "未检测到可用的本机 Mihomo / Clash 外部控制接口".to_string(),
    };

    for ep in endpoints {
        // Verify this loopback endpoint actually speaks Clash/Mihomo `GET /version` == 200
        // before sending `PUT /proxies/{group}` or `DELETE /connections` with `Authorization`.
        let ver_url = format!("{}/version", ep.base_url);
        let ver_resp = match apply_auth(agent.get(&ver_url), ep.secret.as_deref()).call() {
            Ok(r) if r.status() == 200 => r,
            Err(ureq::Error::Status(401 | 403, _)) => {
                last_err = "控制接口鉴权失败（secret 不匹配）".to_string();
                continue;
            }
            _ => continue,
        };
        let ver_body = ver_resp.into_string().unwrap_or_default();
        if core_name_from_version_json(&ver_body).is_none() {
            continue;
        }

        let put_url = format!("{}/proxies/{}", ep.base_url, percent_encode_segment(group));
        let payload = serde_json::json!({ "name": node }).to_string();
        match apply_auth(agent.put(&put_url), ep.secret.as_deref())
            .set("Content-Type", "application/json")
            .send_string(&payload)
        {
            Ok(resp) if (200..300).contains(&resp.status()) => {
                let mut closed_note = String::new();
                if close_connections {
                    let del_url = format!("{}/connections", ep.base_url);
                    if apply_auth(agent.delete(&del_url), ep.secret.as_deref())
                        .call()
                        .is_ok()
                    {
                        closed_note = "并已断开旧连接".to_string();
                    }
                }
                return Ok(format!(
                    "已将策略组 [{group}] 切换至节点「{node}」{closed_note}"
                ));
            }
            Ok(resp) => {
                last_err = format!("切换节点返回 HTTP {}", resp.status());
            }
            Err(ureq::Error::Status(code, _)) => {
                last_err = format!("控制接口拒绝切换（HTTP {code}）");
            }
            Err(_) => continue,
        }
    }

    Err(last_err)
}

/// Switches the active proxy node in a Selector group and optionally closes active connections
/// (`DELETE /connections`) so leaked sockets terminate immediately.
pub fn switch_mihomo_node(
    group: &str,
    node: &str,
    close_connections: bool,
) -> Result<String, String> {
    if group.trim().is_empty() || node.trim().is_empty() {
        return Err("策略组名称与目标节点名称均不能为空".into());
    }
    let discovered = discover_controllers();
    let pipe_err = match switch_mihomo_node_on_pipes(
        &discovered.pipes,
        &discovered.secrets,
        group,
        node,
        close_connections,
    ) {
        Ok(Some(msg)) => return Ok(msg),
        Ok(None) => None,
        Err(e) => Some(e),
    };

    switch_mihomo_node_on_endpoints(
        &discovered.endpoints,
        discovered.pipe_hint.as_deref(),
        group,
        node,
        close_connections,
    )
    .map_err(|tcp_err| pipe_err.unwrap_or(tcp_err))
}

/// Inspects a single YAML config file path (primarily for unit tests).
pub fn parse_yaml_file(path: &Path) -> Option<ControllerEndpoint> {
    let raw = fs::read_to_string(path).ok()?;
    parse_clash_yaml_controller(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_loopback_controller_yaml_and_rejects_remote_hosts() {
        let yaml = r#"
port: 7890
external-controller: 127.0.0.1:9097
secret: "my-local-secret"
"#;
        let ep = parse_clash_yaml_controller(yaml).expect("parse yaml");
        assert_eq!(ep.base_url, "http://127.0.0.1:9097");
        assert_eq!(ep.secret.as_deref(), Some("my-local-secret"));

        assert_eq!(
            normalize_loopback_controller("0.0.0.0:9090").as_deref(),
            Some("http://127.0.0.1:9090")
        );
        assert_eq!(
            normalize_loopback_controller(":9090").as_deref(),
            Some("http://127.0.0.1:9090")
        );
        assert!(normalize_loopback_controller("192.168.1.5:9090").is_none());
    }

    #[test]
    fn parses_mihomo_proxies_json_and_picks_preferred_selector() {
        let sample = r#"{
            "proxies": {
                "US-LAX-01": { "type": "Shadowsocks", "history": [{"delay": 58}] },
                "SG-02": { "type": "VMess", "history": [{"delay": 42}] },
                "Proxy": { "type": "Selector", "now": "US-LAX-01", "all": ["DIRECT", "US-LAX-01", "SG-02"] }
            }
        }"#;
        let st = parse_proxies_json("http://127.0.0.1:9090", "Mihomo v1.19", sample)
            .expect("parse proxies");
        assert!(st.available);
        assert_eq!(st.active_group, "Proxy");
        assert_eq!(st.active_node, "US-LAX-01");
        assert_eq!(st.active_delay_ms, Some(58));
        assert_eq!(st.candidates.len(), 2);
        assert_eq!(st.candidates[0].name, "US-LAX-01");
        assert_eq!(st.candidates[1].delay_ms, Some(42));
    }

    #[test]
    fn quoted_hash_secret_dedup_by_secret_word_boundary_ai_and_client_paths() {
        // 1. Quoted YAML secret containing `#` + trailing `# comment`
        let yaml_dq =
            "external-controller: \"127.0.0.1:9097\" # inline\nsecret: \"p@ss#word#1\" # comment\n";
        let ep_dq = parse_clash_yaml_controller(yaml_dq).expect("double-quoted secret");
        assert_eq!(ep_dq.base_url, "http://127.0.0.1:9097");
        assert_eq!(ep_dq.secret.as_deref(), Some("p@ss#word#1"));

        let yaml_sq = "external-controller: ':9090'\nsecret: 's3cr#t''key' # comment\n";
        let ep_sq = parse_clash_yaml_controller(yaml_sq).expect("single-quoted secret");
        assert_eq!(ep_sq.base_url, "http://127.0.0.1:9090");
        assert_eq!(ep_sq.secret.as_deref(), Some("s3cr#t'key"));

        // 2. Dedup by `(base_url, secret)` preserves distinct secrets on the same port
        let deduped = dedup_endpoints(vec![
            ControllerEndpoint {
                base_url: "http://127.0.0.1:9090".into(),
                secret: Some("stale-sec".into()),
            },
            ControllerEndpoint {
                base_url: "http://127.0.0.1:9090".into(),
                secret: Some("active-sec".into()),
            },
            ControllerEndpoint {
                base_url: "http://127.0.0.1:9090".into(),
                secret: Some("active-sec".into()),
            },
        ]);
        assert!(deduped.contains(&ControllerEndpoint {
            base_url: "http://127.0.0.1:9090".into(),
            secret: Some("stale-sec".into()),
        }));
        assert!(deduped.contains(&ControllerEndpoint {
            base_url: "http://127.0.0.1:9090".into(),
            secret: Some("active-sec".into()),
        }));
        assert!(deduped.contains(&ControllerEndpoint {
            base_url: "http://127.0.0.1:9090".into(),
            secret: None,
        }));

        // 3. `"Taiwan"` / `"Mainland"` must NOT match `"ai"`, whereas `"🤖 AI 专线"` DOES match `"ai"`
        let taiwan_vs_proxy = r#"{
            "proxies": {
                "TW-01": { "type": "Trojan", "history": [{"delay": 35}] },
                "US-01": { "type": "Trojan", "history": [{"delay": 110}] },
                "🇹🇼 Taiwan": { "type": "Selector", "now": "TW-01", "all": ["TW-01"] },
                "Mainland": { "type": "Selector", "now": "DIRECT", "all": ["DIRECT"] },
                "节点选择": { "type": "Selector", "now": "US-01", "all": ["US-01", "TW-01"] }
            }
        }"#;
        let st = parse_proxies_json("http://127.0.0.1:9090", "Mihomo", taiwan_vs_proxy).unwrap();
        assert_eq!(st.active_group, "节点选择");

        let real_ai_group = r#"{
            "proxies": {
                "US-AI": { "type": "VLESS", "history": [{"delay": 95}] },
                "节点选择": { "type": "Selector", "now": "US-AI", "all": ["US-AI"] },
                "🤖 AI 专线": { "type": "Selector", "now": "US-AI", "all": ["US-AI"] }
            }
        }"#;
        let st_ai = parse_proxies_json("http://127.0.0.1:9090", "Mihomo", real_ai_group).unwrap();
        assert_eq!(st_ai.active_group, "🤖 AI 专线");

        // 4. Candidate config paths cover FlClash, Mihomo Party, Sparkle, Nyanpasu, and Verge Local
        let paths = candidate_config_paths_for_homes(&[PathBuf::from(r"C:\Users\Alice")]);
        let joined: Vec<String> = paths
            .iter()
            .map(|p| p.to_string_lossy().to_ascii_lowercase())
            .collect();
        for expected_suffix in [
            r"roaming\com.follow\clash\config.yaml",
            r"roaming\mihomo-party\work\config.yaml",
            r"roaming\mihomo-party\config.yaml",
            r"roaming\sparkle\work\config.yaml",
            r"roaming\clash-nyanpasu\clash-config.yaml",
            r"local\io.github.clash-verge-rev.clash-verge-rev\config.yaml",
        ] {
            assert!(
                joined.iter().any(|p| p.ends_with(expected_suffix)),
                "missing candidate config path suffix {expected_suffix}"
            );
        }
    }

    #[test]
    fn bom_ipv6_wildcard_pipe_note_64_candidates_and_version_gated_untrimmed_switch() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        // 1. UTF-8 BOM on first line + `[::]:port` / `:::port`
        let bom_yaml = "\u{feff}external-controller: \"[::]:9097\"\nsecret: \"bom-sec\"\n";
        let ep_bom = parse_clash_yaml_controller(bom_yaml).expect("parse BOM yaml");
        assert_eq!(ep_bom.base_url, "http://[::1]:9097");
        assert_eq!(ep_bom.secret.as_deref(), Some("bom-sec"));
        assert_eq!(
            normalize_loopback_controller(":::9090").as_deref(),
            Some("http://[::1]:9090")
        );

        // 2. Named pipe diagnostic detection (`external-controller-pipe:`)
        let pipe_yaml = "\u{feff}external-controller-pipe: \\\\.\\pipe\\verge-mihomo\n";
        assert_eq!(
            parse_clash_yaml_pipe(pipe_yaml).as_deref(),
            Some(r"\\.\pipe\verge-mihomo")
        );
        assert_eq!(
            normalize_windows_named_pipe("verge-mihomo").as_deref(),
            Some(r"\\.\pipe\verge-mihomo")
        );
        assert!(normalize_windows_named_pipe(r"\\evil-host\pipe\mihomo").is_none());
        assert!(normalize_windows_named_pipe(r"\\.\pipe\..\evil").is_none());
        let pipe_err = switch_mihomo_node_on_endpoints(
            &[],
            Some(r"\\.\pipe\cg-nonexistent-mihomo-test-pipe"),
            "Proxy",
            "US-01",
            false,
        )
        .unwrap_err();
        assert!(pipe_err.contains("external-controller-pipe"));

        // 2b. Standalone secret pairing & Verge/Mihomo-Party/FlClash/Sparkle paths & port parser
        let sec_only = "mixed-port: 7897\nsocks-port: 7898\nsecret: \"verge-sec\"\n";
        assert_eq!(
            parse_clash_yaml_secret(sec_only).as_deref(),
            Some("verge-sec")
        );
        assert_eq!(parse_clash_yaml_proxy_ports(sec_only), vec![7897, 7898]);
        let paired = dedup_endpoints_with_secrets(vec![], &["verge-sec".to_string()]);
        assert_eq!(
            paired[0],
            ControllerEndpoint {
                base_url: "http://127.0.0.1:9090".into(),
                secret: Some("verge-sec".into()),
            }
        );
        let all_paths: Vec<String> =
            candidate_config_paths_for_homes(&[PathBuf::from(r"C:\Users\Bob")])
                .into_iter()
                .map(|p| p.to_string_lossy().to_ascii_lowercase())
                .collect();
        for suffix in [
            r"io.github.clash-verge-rev.clash-verge-rev\verge.yaml",
            r"com.follow\flclash\config.yaml",
            r"mihomo-party\mihomo.yaml",
            r"sparkle\sparkle.yaml",
        ] {
            assert!(
                all_paths.iter().any(|p| p.ends_with(suffix)),
                "missing {suffix}"
            );
        }

        // 3. Candidate limit 64 + active_node beyond #64 is always included
        let mut all_nodes = vec!["\"DIRECT\"".to_string()];
        for i in 1..=70 {
            all_nodes.push(format!("\"Node-{i:02}\""));
        }
        let big_json = format!(
            r#"{{"proxies":{{"Node-70":{{"type":"VLESS","history":[{{"delay":31}}]}},"Proxy":{{"type":"Selector","now":"Node-70","all":[{}]}}}}}}"#,
            all_nodes.join(",")
        );
        let st = parse_proxies_json("http://127.0.0.1:9090", "Mihomo", &big_json).unwrap();
        assert_eq!(st.candidates.len(), 64);
        assert!(
            st.candidates
                .iter()
                .any(|c| c.name == "Node-70" && c.delay_ms == Some(31)),
            "active_node must always be included even past index 64"
        );

        // 4. `switch_mihomo_node` checks `GET /version` before `PUT` and preserves untrimmed spaces
        let non_mihomo = TcpListener::bind("127.0.0.1:0").unwrap();
        let non_mihomo_addr = non_mihomo.local_addr().unwrap();
        let h_non = std::thread::spawn(move || {
            let mut req_count = 0usize;
            if let Ok((mut sock, _)) = non_mihomo.accept() {
                req_count += 1;
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf);
                let _ = sock.write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
            req_count
        });

        let real_mihomo = TcpListener::bind("127.0.0.1:0").unwrap();
        let real_addr = real_mihomo.local_addr().unwrap();
        let h_real = std::thread::spawn(move || {
            let mut put_req = String::new();
            for step in 0..2 {
                if let Ok((mut sock, _)) = real_mihomo.accept() {
                    let _ = sock.set_read_timeout(Some(Duration::from_secs(2)));
                    let mut raw_bytes = Vec::new();
                    let mut buf = [0u8; 2048];
                    loop {
                        match sock.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                raw_bytes.extend_from_slice(&buf[..n]);
                                let cur = String::from_utf8_lossy(&raw_bytes);
                                if step == 0 && cur.contains("\r\n\r\n") {
                                    break;
                                }
                                if step == 1 && cur.contains("\r\n\r\n") && cur.ends_with('}') {
                                    break;
                                }
                            }
                        }
                    }
                    let raw = String::from_utf8_lossy(&raw_bytes).into_owned();
                    if step == 0 {
                        let body = r#"{"meta":true,"version":"v1.19.0"}"#;
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = sock.write_all(resp.as_bytes());
                    } else {
                        put_req = raw;
                        let _ = sock.write_all(
                            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                    }
                }
            }
            put_req
        });

        let msg = switch_mihomo_node_on_endpoints(
            &[
                ControllerEndpoint {
                    base_url: format!("http://{non_mihomo_addr}"),
                    secret: Some("sec-1".into()),
                },
                ControllerEndpoint {
                    base_url: format!("http://{real_addr}"),
                    secret: Some("sec-2".into()),
                },
            ],
            None,
            " 节点选择 ",
            " US 01 ",
            false,
        )
        .expect("switch on verified Mihomo endpoint");
        assert!(msg.contains("[ 节点选择 ]") && msg.contains("「 US 01 」"));
        assert_eq!(
            h_non.join().unwrap(),
            1,
            "non-Mihomo server must never receive PUT"
        );
        let captured_put = h_real.join().unwrap();
        assert!(
            captured_put.contains("PUT /proxies/%20%E8%8A%82%E7%82%B9%E9%80%89%E6%8B%A9%20 "),
            "group leading/trailing spaces must be preserved: {captured_put}"
        );
        assert!(
            captured_put.contains(r#"{"name":" US 01 "}"#),
            "node leading/trailing spaces must be preserved: {captured_put}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn named_pipe_controller_chunked_http_and_local_proxy_port_discovery_work() {
        use std::io::{Read, Write};
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::io::{FromRawHandle, RawHandle};

        #[link(name = "kernel32")]
        extern "system" {
            fn CreateNamedPipeW(
                lp_name: *const u16,
                dw_open_mode: u32,
                dw_pipe_mode: u32,
                n_max_instances: u32,
                n_out_buffer_size: u32,
                n_in_buffer_size: u32,
                n_default_time_out: u32,
                lp_security_attributes: *const core::ffi::c_void,
            ) -> isize;
            fn ConnectNamedPipe(h_named_pipe: isize, lp_overlapped: *mut core::ffi::c_void) -> i32;
            fn FlushFileBuffers(h_file: isize) -> i32;
            fn DisconnectNamedPipe(h_named_pipe: isize) -> i32;
        }

        // 1. Chunked HTTP/1.1 & 204 parser check
        let raw_chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n7\r\n{\"meta\"\r\n15\r\n:true,\"version\":\"v1\"}\r\n0\r\n\r\n";
        let (code, body, complete) = parse_raw_http_response(raw_chunked).expect("parse chunked");
        assert_eq!(code, 200);
        assert!(complete);
        assert_eq!(body, r#"{"meta":true,"version":"v1"}"#);

        // 2. GetExtendedTcpTable listener discovery check
        let _ports = discover_local_proxy_ports();

        // 3. End-to-end HTTP over Win32 Named Pipe (`inspect` + `switch`)
        let pipe_name = format!(
            r"\\.\pipe\cg-test-mihomo-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let pipe_name_srv = pipe_name.clone();
        let srv = std::thread::spawn(move || {
            let wide: Vec<u16> = std::ffi::OsStr::new(&pipe_name_srv)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            for step in 0..4 {
                let h = unsafe {
                    CreateNamedPipeW(
                        wide.as_ptr(),
                        0x0000_0003, // PIPE_ACCESS_DUPLEX
                        0,           // PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT
                        4,
                        16 * 1024,
                        16 * 1024,
                        2000,
                        core::ptr::null(),
                    )
                };
                assert!(h != -1 && h != 0, "CreateNamedPipeW failed");
                let connected = unsafe { ConnectNamedPipe(h, core::ptr::null_mut()) };
                let last_err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                // ERROR_PIPE_CONNECTED == 535
                assert!(connected != 0 || last_err == 535);

                let mut pipe_file = unsafe { std::fs::File::from_raw_handle(h as RawHandle) };
                let mut req_buf = [0u8; 2048];
                let n = pipe_file.read(&mut req_buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&req_buf[..n]);
                let resp = match step {
                    0 | 2 => {
                        let b = r#"{"meta":true,"version":"v1.19.2"}"#;
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
                            b.len()
                        )
                    }
                    1 => {
                        let b = r#"{"proxies":{"US-Pipe":{"type":"VLESS","history":[{"delay":42}]},"Proxy":{"type":"Selector","now":"US-Pipe","all":["US-Pipe"]}}}"#;
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
                            b.len()
                        )
                    }
                    _ => {
                        assert!(req.starts_with("PUT /proxies/Proxy "));
                        "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_string()
                    }
                };
                let _ = pipe_file.write_all(resp.as_bytes());
                unsafe {
                    let _ = FlushFileBuffers(h);
                    let _ = DisconnectNamedPipe(h);
                }
            }
        });

        std::thread::sleep(Duration::from_millis(25));
        let st =
            inspect_mihomo_on_pipes(std::slice::from_ref(&pipe_name), &[]).expect("pipe inspect");
        assert!(st.available, "pipe inspect failed: {}", st.note);
        assert_eq!(st.active_node, "US-Pipe");

        let sw = switch_mihomo_node_on_endpoints(&[], Some(&pipe_name), "Proxy", "US-Pipe", false)
            .expect("switch over named pipe");
        assert!(sw.contains("US-Pipe"));
        srv.join().unwrap();
    }
}
