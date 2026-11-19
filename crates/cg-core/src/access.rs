//! Pure access path evaluation (`ProxyEvidence` + TUN adapter -> `AccessEvidence` + `ProbeRoute`).

use cg_protocol::{AccessEvidence, AccessLevel, Config};

const TUN_KEYWORDS: [&str; 15] = [
    "mihomo",
    "clash",
    "meta",
    "sing-box",
    "singbox",
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

const TUN_EXCLUDES: [&str; 1] = ["tailscale"];

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

/// Windows registry proxy configuration snapshot.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProxyEvidence {
    pub enable: bool,
    pub server: Option<String>,
    pub autoconfig: Option<String>,
    pub overrides: Option<String>,
}

/// Parsed `ProxyServer` value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyParse {
    Http(String),
    Unsupported(&'static str),
    Empty,
}

/// Planned probe routing decision derived from [`AccessEvidence`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeRoute {
    Proxy(String),
    Direct,
    Skip,
}

/// Checks whether a network adapter name/description looks like a full-tunnel TUN device.
pub fn is_tun_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    if TUN_EXCLUDES.iter().any(|kw| lower.contains(kw)) {
        return false;
    }
    lower.starts_with("utun") || TUN_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

/// Picks the first active (`up = true`) TUN adapter from `(description, friendly_name, is_up)`.
pub fn select_tun(adapters: &[(String, String, bool)]) -> Option<String> {
    for (desc, friendly, up) in adapters {
        if !*up {
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

/// Decodes UTF-16 code units by unit count (not byte count, guarding T01-01).
pub fn wide_to_string(units: &[u16]) -> String {
    String::from_utf16_lossy(units)
}

fn strip_scheme(value: &str) -> (Option<&str>, &str) {
    match value.find("://") {
        Some(idx) => (Some(&value[..idx]), &value[idx + 3..]),
        None => (None, value),
    }
}

fn clean_addr(value: &str) -> Option<String> {
    let (scheme, rest) = strip_scheme(value.trim());
    let rest = rest.trim().trim_end_matches('/');
    if rest.is_empty() {
        return None;
    }
    if let Some(scheme) = scheme {
        let lower = scheme.to_ascii_lowercase();
        if lower != "http" && lower != "https" {
            return None;
        }
    }
    if !rest.contains(':') {
        return None;
    }
    Some(rest.to_string())
}

/// Parses Windows `ProxyServer` strings (`host:port`, `http=...;https=...`, or scheme-prefixed).
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
    if raw.to_ascii_lowercase().starts_with("socks") {
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

/// Returns true for local/loopback/RFC1918 bypass entries that never leak public AI traffic.
pub fn bypass_local_entry(entry: &str) -> bool {
    let e = entry.trim().to_ascii_lowercase();
    match e.as_str() {
        "<local>" | "localhost" | "localhost.*" | "*.localhost" | "*.local" | "[::1]" | "::1" => {
            return true;
        }
        _ => {}
    }
    let Some(prefix) = e.strip_suffix(".*") else {
        return false;
    };
    let octets: Vec<u8> = prefix
        .split('.')
        .map(|v| v.parse::<u8>().ok())
        .collect::<Option<Vec<_>>>()
        .unwrap_or_default();
    match octets.as_slice() {
        [10] | [127] | [192, 168] | [169, 254] => true,
        [172, second] => (16..=31).contains(second),
        _ => false,
    }
}

pub fn bypass_hits_host(entry: &str, host: &str) -> bool {
    let domain = entry_domain(entry);
    if domain.is_empty() {
        return true;
    }
    let host = host.trim().to_ascii_lowercase();
    host == domain || host.ends_with(&format!(".{domain}"))
}

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

pub fn monitored_hosts(cfg: &Config) -> Vec<String> {
    let mut out = Vec::new();
    for target in cfg.enabled_targets() {
        let host = target.host();
        let clean = host
            .rsplit('@')
            .next()
            .unwrap_or(&host)
            .split(':')
            .next()
            .unwrap_or(&host)
            .to_ascii_lowercase();
        if !clean.is_empty() && !out.contains(&clean) {
            out.push(clean);
        }
    }
    out
}

/// Evaluates proxy evidence + TUN adapter presence into a protocol [`AccessEvidence`].
pub fn evaluate_access(
    evidence: &ProxyEvidence,
    tun_adapter: Option<String>,
    hosts: &[String],
    observed_at: u64,
    revision: u64,
) -> AccessEvidence {
    if let Some(pac) = evidence
        .autoconfig
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        return AccessEvidence {
            level: AccessLevel::Unknown,
            observed_at,
            revision,
            note: format!("检测到 PAC 自动配置（{pac}），无法确认应用实际出口"),
            ..AccessEvidence::default()
        };
    }
    if !evidence.enable {
        return match tun_adapter {
            Some(adapter) => {
                let clean = adapter.trim().to_string();
                AccessEvidence {
                    level: AccessLevel::Tun,
                    tun_iface: Some(clean.clone()),
                    route_hint: true,
                    observed_at,
                    revision,
                    note: format!("TUN 直连（{clean}）"),
                    ..AccessEvidence::default()
                }
            }
            None => AccessEvidence {
                level: AccessLevel::Uncovered,
                observed_at,
                revision,
                note: "系统代理未开启且未检测到 TUN 网卡，应用会直连真实出口".into(),
                ..AccessEvidence::default()
            },
        };
    }
    match parse_proxy_server(evidence.server.as_deref()) {
        ProxyParse::Http(addr) => {
            if bypass_all(evidence.overrides.as_deref()) {
                AccessEvidence {
                    level: AccessLevel::Uncovered,
                    observed_at,
                    revision,
                    note: "代理绕过列表为 *，应用全部直连".into(),
                    ..AccessEvidence::default()
                }
            } else if let Some(entry) = bypass_risk(evidence.overrides.as_deref(), hosts) {
                AccessEvidence {
                    level: AccessLevel::Unknown,
                    observed_at,
                    revision,
                    note: format!("代理绕过列表含 {entry}，被监控流量可能直连"),
                    ..AccessEvidence::default()
                }
            } else {
                AccessEvidence {
                    level: AccessLevel::SystemProxy,
                    proxy_addr: Some(addr.clone()),
                    route_hint: true,
                    observed_at,
                    revision,
                    note: format!("系统代理 {addr}"),
                    ..AccessEvidence::default()
                }
            }
        }
        ProxyParse::Unsupported(why) => AccessEvidence {
            level: AccessLevel::Unknown,
            observed_at,
            revision,
            note: format!("系统代理配置无法等价复用：{why}"),
            ..AccessEvidence::default()
        },
        ProxyParse::Empty => AccessEvidence {
            level: AccessLevel::Unknown,
            observed_at,
            revision,
            note: "系统代理已开启但未读到代理地址".into(),
            ..AccessEvidence::default()
        },
    }
}

/// Determines the outbound probe route from [`AccessEvidence`]; `Uncovered`/`Unknown` never probes directly.
pub fn plan_route(access: &AccessEvidence) -> ProbeRoute {
    match access.level {
        AccessLevel::SystemProxy => match access.proxy_addr.as_deref() {
            Some(addr) if !addr.trim().is_empty() => ProbeRoute::Proxy(format!("http://{addr}")),
            _ => ProbeRoute::Skip,
        },
        AccessLevel::Tun => ProbeRoute::Direct,
        AccessLevel::Uncovered | AccessLevel::Unknown => ProbeRoute::Skip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluates_proxy_tun_pac_socks_and_bypass_correctly() {
        let hosts = vec!["claude.ai".into(), "chatgpt.com".into()];
        let ev_ok = ProxyEvidence {
            enable: true,
            server: Some("http=127.0.0.1:80;https=127.0.0.1:7890".into()),
            autoconfig: None,
            overrides: Some("<local>;127.*;192.168.*;*jd.com".into()),
        };
        let acc = evaluate_access(&ev_ok, None, &hosts, 100, 1);
        assert_eq!(acc.level, AccessLevel::SystemProxy);
        assert_eq!(acc.proxy_addr.as_deref(), Some("127.0.0.1:7890"));
        assert_eq!(
            plan_route(&acc),
            ProbeRoute::Proxy("http://127.0.0.1:7890".into())
        );

        // PAC -> Unknown + Skip
        let ev_pac = ProxyEvidence {
            enable: true,
            server: Some("127.0.0.1:7890".into()),
            autoconfig: Some("http://127.0.0.1:7890/pac".into()),
            overrides: None,
        };
        let acc_pac = evaluate_access(&ev_pac, None, &hosts, 100, 1);
        assert_eq!(acc_pac.level, AccessLevel::Unknown);
        assert_eq!(plan_route(&acc_pac), ProbeRoute::Skip);

        // Missing server -> Unknown
        let ev_empty = ProxyEvidence {
            enable: true,
            server: None,
            autoconfig: None,
            overrides: None,
        };
        assert_eq!(
            evaluate_access(&ev_empty, None, &hosts, 100, 1).level,
            AccessLevel::Unknown
        );

        // Uncovered -> Skip
        let ev_off = ProxyEvidence::default();
        let acc_off = evaluate_access(&ev_off, None, &hosts, 100, 1);
        assert_eq!(acc_off.level, AccessLevel::Uncovered);
        assert_eq!(plan_route(&acc_off), ProbeRoute::Skip);

        // TUN active when proxy off -> Tun + Direct
        let acc_tun = evaluate_access(&ev_off, Some("Mihomo".into()), &hosts, 100, 1);
        assert_eq!(acc_tun.level, AccessLevel::Tun);
        assert_eq!(plan_route(&acc_tun), ProbeRoute::Direct);
    }

    #[test]
    fn wide_string_and_tun_selection_and_bypass_risk_rules() {
        let name = "Wintun Userspace Tunnel";
        let units: Vec<u16> = name.encode_utf16().collect();
        assert_eq!(wide_to_string(&units), name);

        let adapters = vec![
            ("Tailscale Tunnel".into(), "Tailscale".into(), true),
            ("Mihomo".into(), "Mihomo".into(), false),
            ("Ethernet 2".into(), "Clash Verge TUN".into(), true),
        ];
        assert_eq!(select_tun(&adapters).as_deref(), Some("Clash Verge TUN"));

        let hosts = vec!["claude.ai".into()];
        assert_eq!(
            bypass_risk(
                Some("<local>;127.*;10.*;172.16.*;192.168.*;*jd.com"),
                &hosts
            ),
            None
        );
        assert_eq!(
            bypass_risk(Some("<local>;*.anthropic.com"), &hosts).as_deref(),
            Some("*.anthropic.com")
        );
        assert!(matches!(
            parse_proxy_server(Some("socks=127.0.0.1:1080")),
            ProxyParse::Unsupported(_)
        ));
        assert!(matches!(
            parse_proxy_server(Some("127.0.0.1")),
            ProxyParse::Unsupported(_)
        ));
    }
}
