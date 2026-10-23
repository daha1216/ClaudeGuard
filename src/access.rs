//! 应用接入路径检查（v3.7 引入；v3.10 R03 加固）。
//!
//! Claude 等桌面应用只认系统代理——系统代理没开时它们直连真实出口，守护器测代理
//! 出口测得再准也管不到应用本体。因此每轮探测前先解析接入方式：
//!
//! - 系统代理开且地址可等价复用 → 探测跟随它指向的地址（测到的就是应用真实出口）；
//! - 系统代理关 + 有 TUN 网卡（接口 Up）→ 探测直连（被 TUN 接管，与应用同路）；
//! - 系统代理关 + 无 TUN → **未接入**：应用直连真实出口，计入熔断阈值；
//! - PAC / 仅 socks / 地址缺失 / 绕过列表含非本地条目 → **无法确认**：不猜测、
//!   不发起直连探测、不熔断，但禁止通过守护器启动应用。
//!
//! [`parse_proxy_server`] / [`verdict`] / [`select_tun`] / [`wide_to_string`] 是纯函数，
//! 单测不发网络；[`read_proxy_evidence`] / [`detect_tun_adapter`] 只读本机注册表与网卡表。

use crate::config::Config;
use serde::Serialize;

/// TUN 虚拟网卡关键词（小写子串匹配适配器描述/友好名）。
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
/// 排除项：默认不是全隧道的虚拟网卡，命中不算 TUN 接入。
const TUN_EXCLUDES: [&str; 1] = ["tailscale"];
/// 被监控应用实际会连的服务域名后缀：绕过列表命中这些才算"可能直连"。
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

/// 适配器描述/友好名是否像 TUN 虚拟网卡。
pub fn is_tun_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    if TUN_EXCLUDES.iter().any(|kw| lower.contains(kw)) {
        return false;
    }
    lower.starts_with("utun") || TUN_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

/// 从候选适配器里挑出正在 Up 的 TUN 网卡（纯函数，便于单测 T01-06）。
/// 入参为（描述，友好名，是否 Up）；返回命中的名字。
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

/// UTF-16 码元转字符串。长度按**码元数**取，不按字节数（T01-01 回归点）。
pub fn wide_to_string(units: &[u16]) -> String {
    String::from_utf16_lossy(units)
}

/// 注册表里读到的代理配置（纯数据，便于单测 T01-02/T01-03/T01-04/T01-05）。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProxyEvidence {
    /// `ProxyEnable`。
    pub enable: bool,
    /// `ProxyServer` 原始值。
    pub server: Option<String>,
    /// `AutoConfigURL`（PAC 脚本地址）。
    pub autoconfig: Option<String>,
    /// `ProxyOverride`（绕过列表）。
    pub overrides: Option<String>,
}

/// `ProxyServer` 解析结果。
#[derive(Clone, Debug, PartialEq)]
pub enum ProxyParse {
    /// 可等价复用：去协议前缀后的 `host:port`。
    Http(String),
    /// 只配了不支持的协议 / 缺少端口等无法等价复用的形式。
    Unsupported(&'static str),
    /// 没有可用值。
    Empty,
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
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return None;
        }
    }
    // 代理地址必须带端口：缺端口时无法保证与应用同路，按不支持处理。
    if !rest.contains(':') {
        return None;
    }
    Some(rest.to_string())
}

/// 解析注册表 `ProxyServer`：支持 `host:port`、`http=h:p;https=h:p` 与带协议前缀的形式。
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
            if let Some(rest) = lower.strip_prefix("https=") {
                let _ = rest;
                if let Some(addr) = clean_addr(&part["https=".len()..]) {
                    https.get_or_insert(addr);
                } else {
                    other = true;
                }
            } else if let Some(rest) = lower.strip_prefix("http=") {
                let _ = rest;
                if let Some(addr) = clean_addr(&part["http=".len()..]) {
                    http.get_or_insert(addr);
                } else {
                    other = true;
                }
            } else if lower.contains('=') {
                // socks= / ftp= / file= 等：Windows 会按协议分流，无法等价复用到探测。
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

/// 绕过列表是 `*`：所有流量都直连，等价于未接入。
pub fn bypass_all(raw: Option<&str>) -> bool {
    bypass_entries(raw).iter().any(|v| v == "*")
}

/// 去掉通配前缀，取出条目里的域名部分（`*.claude.ai`、`*claude.ai` → `claude.ai`）。
fn entry_domain(entry: &str) -> String {
    entry
        .trim()
        .trim_start_matches('*')
        .trim_start_matches('.')
        .to_string()
}

/// 条目是否只覆盖本机 / 私网 / 链路本地——这类地址不可能让公网流量直连。
pub fn bypass_local_entry(entry: &str) -> bool {
    let e = entry.trim().to_ascii_lowercase();
    match e.as_str() {
        "<local>" | "localhost" | "localhost.*" | "*.localhost" | "*.local" | "[::1]" | "::1" => {
            return true
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
        [10] | [127] => true,
        [192, 168] | [169, 254] => true,
        [172, second] => (16..=31).contains(second),
        _ => false,
    }
}

/// 绕过条目是否会命中给定主机名（`*` 由 `bypass_all` 单独处理）。
pub fn bypass_hits_host(entry: &str, host: &str) -> bool {
    let domain = entry_domain(entry);
    if domain.is_empty() {
        return true;
    }
    let host = host.trim().to_ascii_lowercase();
    host == domain || host.ends_with(&format!(".{domain}"))
}

/// 绕过列表里是否存在会让被监控流量直连的条目；返回该条目。
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

/// 从探测地址里取主机名（小写）。
fn host_of(url: &str) -> Option<String> {
    let rest = url.trim().strip_prefix("https://")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = host.split(':').next().unwrap_or(host).to_ascii_lowercase();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// 当前启用目标实际会访问的主机名，用于判断绕过列表是否真的会造成直连。
pub fn monitored_hosts(cfg: &Config) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for target in cfg.targets.iter().filter(|t| t.enabled) {
        if let Some(host) = host_of(&target.anchor_url) {
            if !out.contains(&host) {
                out.push(host);
            }
        }
    }
    out
}

/// 应用当前的接入方式判定（纯函数，供单测）。
#[derive(Clone, Debug, PartialEq)]
pub enum AccessPath {
    /// 系统代理开启且地址可等价复用。
    SystemProxy { addr: String },
    /// 系统代理关闭，但存在 Up 的 TUN 虚拟网卡（adapter=匹配到的适配器名）。
    Tun { adapter: String },
    /// 系统代理关闭且无 TUN：应用直连真实出口。
    Uncovered,
    /// 配置不足以确认应用实际走哪条路（PAC / socks / 缺地址 / 绕过列表）。
    Unknown { reason: String },
}

/// 推给 UI / `--check` 的接入快照。
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessInfo {
    /// system_proxy | tun | uncovered | unknown | skipped
    pub path: String,
    pub note: String,
}

impl AccessInfo {
    /// 未接入（系统代理关 + 无 TUN）——v3.7 熔断条件。
    pub fn is_uncovered(&self) -> bool {
        self.path == "uncovered"
    }

    /// 接入路径无法确认（不熔断，但禁止启动）。
    pub fn is_unknown(&self) -> bool {
        self.path == "unknown"
    }

    /// 已确认接入（系统代理或 TUN）。
    pub fn is_known(&self) -> bool {
        self.path == "system_proxy" || self.path == "tun"
    }
}

/// 由注册表证据 + TUN 探测结果判定接入方式。
///
/// `hosts` 是被监控目标实际会访问的主机名：只有绕过列表命中它们（或命中 AI 服务后缀）
/// 才算"可能直连"。仅含本机/私网/无关域名（如购物站）的绕过列表不影响判定——
/// Windows 上几乎每台机器都有 `127.*;10.*;192.168.*;<local>` 之类的条目，
/// 把它们一律当作"无法确认"会让守护器永远拒绝启动。
pub fn verdict(
    evidence: &ProxyEvidence,
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
                // 全部绕过代理 = 应用直连，与未接入同义。
                AccessPath::Uncovered
            } else if let Some(entry) = bypass_risk(evidence.overrides.as_deref(), hosts) {
                AccessPath::Unknown {
                    reason: format!("代理绕过列表含 {entry}，被监控流量可能直连"),
                }
            } else {
                AccessPath::SystemProxy { addr }
            }
        }
        ProxyParse::Unsupported(why) => AccessPath::Unknown {
            reason: format!("系统代理配置无法等价复用：{why}"),
        },
        ProxyParse::Empty => AccessPath::Unknown {
            reason: "系统代理已开启但未读到代理地址".into(),
        },
    }
}

impl From<&AccessPath> for AccessInfo {
    fn from(path: &AccessPath) -> Self {
        match path {
            AccessPath::SystemProxy { addr } => AccessInfo {
                path: "system_proxy".into(),
                note: format!("系统代理 {addr}"),
            },
            AccessPath::Tun { adapter } => AccessInfo {
                path: "tun".into(),
                note: format!("TUN 直连（{}）", adapter.trim()),
            },
            AccessPath::Uncovered => AccessInfo {
                path: "uncovered".into(),
                note: "系统代理未开启且未检测到 TUN 网卡，应用会直连真实出口".into(),
            },
            AccessPath::Unknown { reason } => AccessInfo {
                path: "unknown".into(),
                note: reason.clone(),
            },
        }
    }
}

/// 每轮探测的路由决定。
#[derive(Clone, Debug, PartialEq)]
pub enum ProbeRoute {
    /// 经该代理地址探测（"http://host:port"）。
    Proxy(String),
    /// 直连探测（TUN 接管，与应用同路）。
    Direct,
    /// 不探测——守护器自身流量绝不带着家宽 IP 出机器，
    /// 判定与熔断完全靠注册表/TUN 的确定性检查。
    Skip,
}

/// 由接入方式决定探测路由（纯函数；T01-07 断言未接入/无法确认时零出站）。
pub fn plan_route(path: &AccessPath, cfg: &Config) -> ProbeRoute {
    match path {
        AccessPath::SystemProxy { addr } => ProbeRoute::Proxy(format!("http://{addr}")),
        AccessPath::Tun { .. } => ProbeRoute::Direct,
        AccessPath::Uncovered | AccessPath::Unknown { .. } => {
            let _ = cfg;
            ProbeRoute::Skip
        }
    }
}

/// 每轮探测前调用：返回（探测路由，接入快照）。
pub fn resolve(cfg: &Config) -> (ProbeRoute, AccessInfo) {
    #[cfg(target_os = "windows")]
    {
        let evidence = read_proxy_evidence();
        let tun = if evidence.enable || evidence.autoconfig.is_some() {
            None
        } else {
            detect_tun_adapter()
        };
        let path = verdict(&evidence, tun, &monitored_hosts(cfg));
        (plan_route(&path, cfg), AccessInfo::from(&path))
    }
    #[cfg(not(target_os = "windows"))]
    {
        // macOS 移植为进程守护模式，保持按配置端口探测、不检查接入路径。
        (
            ProbeRoute::Proxy(cfg.proxy_url()),
            AccessInfo {
                path: "skipped".into(),
                note: "非 Windows：按配置端口探测".into(),
            },
        )
    }
}

// ---------- Windows 系统读取 ----------

#[cfg(target_os = "windows")]
fn read_proxy_evidence() -> ProxyEvidence {
    use winreg::enums::KEY_READ;
    use winreg::RegKey;
    let hkcu = RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
    let Ok(settings) = hkcu.open_subkey_with_flags(
        r"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
        KEY_READ,
    ) else {
        return ProxyEvidence::default();
    };
    let enabled: u32 = settings.get_value("ProxyEnable").unwrap_or(0);
    let read = |name: &str| -> Option<String> {
        let value: String = settings.get_value(name).ok()?;
        if value.trim().is_empty() {
            None
        } else {
            Some(value)
        }
    };
    ProxyEvidence {
        enable: enabled != 0,
        server: read("ProxyServer"),
        autoconfig: read("AutoConfigURL"),
        overrides: read("ProxyOverride"),
    }
}

/// 读取 PWSTR 的 UTF-16 码元（到 NUL 为止），长度按码元数而非字节数。
#[cfg(target_os = "windows")]
unsafe fn pwstr_units(p: windows::core::PWSTR) -> Vec<u16> {
    if p.is_null() {
        return Vec::new();
    }
    let mut len = 0usize;
    while len < 4096 && *p.0.add(len) != 0 {
        len += 1;
    }
    std::slice::from_raw_parts(p.0, len).to_vec()
}

#[cfg(target_os = "windows")]
pub fn detect_tun_adapter() -> Option<String> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
        GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST, GET_ADAPTERS_ADDRESSES_FLAGS,
        IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    // family=0(AF_UNSPEC)；跳过所有地址信息，只看适配器元数据。
    const FAMILY_UNSPEC: u32 = 0;
    let flags = GET_ADAPTERS_ADDRESSES_FLAGS(
        GAA_FLAG_SKIP_UNICAST.0
            | GAA_FLAG_SKIP_ANYCAST.0
            | GAA_FLAG_SKIP_MULTICAST.0
            | GAA_FLAG_SKIP_DNS_SERVER.0,
    );
    let mut size: u32 = 15 * 1024;
    for _ in 0..4 {
        // 用 u64 数组保证结构体对齐。
        let mut buffer: Vec<u64> = vec![0; (size as usize).div_ceil(8)];
        let result = unsafe {
            GetAdaptersAddresses(
                FAMILY_UNSPEC,
                flags,
                None,
                Some(buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>()),
                &mut size,
            )
        };
        if result == 0 {
            let mut candidates: Vec<(String, String, bool)> = Vec::new();
            let mut current = buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
            while !current.is_null() {
                let adapter = unsafe { &*current };
                let desc = wide_to_string(&unsafe { pwstr_units(adapter.Description) });
                let friendly = wide_to_string(&unsafe { pwstr_units(adapter.FriendlyName) });
                candidates.push((desc, friendly, adapter.OperStatus == IfOperStatusUp));
                current = adapter.Next;
            }
            return select_tun(&candidates);
        }
        // ERROR_BUFFER_OVERFLOW (111) → size 已被更新，扩容重试；其他错误直接放弃。
        if result != 111 {
            return None;
        }
        buffer.clear();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 被监控目标的代表主机名（真实默认目标的锚点）。
    fn hosts() -> Vec<String> {
        vec!["claude.ai".to_string(), "chatgpt.com".to_string()]
    }

    fn evidence(enable: bool, server: Option<&str>) -> ProxyEvidence {
        ProxyEvidence {
            enable,
            server: server.map(str::to_string),
            autoconfig: None,
            overrides: None,
        }
    }

    #[test]
    fn proxyserver_forms() {
        assert_eq!(parse_proxy_server(None), ProxyParse::Empty);
        assert_eq!(parse_proxy_server(Some("  ")), ProxyParse::Empty);
        assert_eq!(
            parse_proxy_server(Some("127.0.0.1:7890")),
            ProxyParse::Http("127.0.0.1:7890".into())
        );
        // T01-03：分号形式取 https 优先，不把键名拼进地址。
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
        // T01-03：带协议前缀时剥掉 scheme。
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
    fn unsupported_proxy_forms_are_not_guessed() {
        // T01-04：socks / 缺端口都不冒充可复用地址。
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
        assert_eq!(
            verdict(&evidence(true, Some("socks=127.0.0.1:1080")), None, &[]),
            AccessPath::Unknown {
                reason: "系统代理配置无法等价复用：仅配置了 SOCKS 代理".into()
            }
        );
    }

    #[test]
    fn missing_address_is_unknown() {
        // T01-02：ProxyEnable=1 但 ProxyServer 缺失 → Unknown，不得判已接入。
        assert_eq!(
            verdict(&evidence(true, None), None, &[]),
            AccessPath::Unknown {
                reason: "系统代理已开启但未读到代理地址".into()
            }
        );
    }

    #[test]
    fn pac_is_unknown() {
        // T01-05：PAC 存在时无论 ProxyEnable 取值都不猜测。
        let mut ev = evidence(true, Some("127.0.0.1:7890"));
        ev.autoconfig = Some("http://127.0.0.1:7890/pac".into());
        assert!(matches!(
            verdict(&ev, None, &hosts()),
            AccessPath::Unknown { .. }
        ));
        let mut off = evidence(false, None);
        off.autoconfig = Some("http://127.0.0.1:7890/pac".into());
        assert!(matches!(
            verdict(&off, Some("Mihomo".into()), &hosts()),
            AccessPath::Unknown { .. }
        ));
    }

    #[test]
    fn bypass_list_semantics() {
        let mut ev = evidence(true, Some("127.0.0.1:7890"));
        let proxy = AccessPath::SystemProxy {
            addr: "127.0.0.1:7890".into(),
        };
        ev.overrides = Some("<local>".into());
        assert_eq!(verdict(&ev, None, &hosts()), proxy);

        // Windows 上常见的本机/私网条目不影响判定（否则等于永远拒绝启动）。
        ev.overrides = Some("localhost;*.local;127.*;10.*;192.168.*;172.16.*;172.31.*".into());
        assert_eq!(verdict(&ev, None, &hosts()), proxy);

        // 与被监控域名无关的公网绕过项同样不影响。
        ev.overrides = Some("<local>;*jd.com;*zhihu.com".into());
        assert_eq!(verdict(&ev, None, &hosts()), proxy);

        // 命中被监控主机、或命中 AI 服务后缀，才判"无法确认"。
        ev.overrides = Some("<local>;*.corp.example;*claude.ai".into());
        assert!(matches!(
            verdict(&ev, None, &hosts()),
            AccessPath::Unknown { .. }
        ));
        ev.overrides = Some("*.anthropic.com".into());
        assert!(matches!(
            verdict(&ev, None, &hosts()),
            AccessPath::Unknown { .. }
        ));

        ev.overrides = Some("*".into());
        assert_eq!(verdict(&ev, None, &hosts()), AccessPath::Uncovered);
    }

    #[test]
    fn bypass_local_and_host_matching() {
        for entry in [
            "<local>",
            "localhost",
            "localhost.*",
            "*.local",
            "127.*",
            "10.*",
            "192.168.*",
            "169.254.*",
            "172.16.*",
            "172.31.*",
            "[::1]",
        ] {
            assert!(bypass_local_entry(entry), "{entry} 应视为本地");
        }
        for entry in ["172.15.*", "172.32.*", "8.8.8.*", "*.claude.ai", "jd.com"] {
            assert!(!bypass_local_entry(entry), "{entry} 不应视为本地");
        }
        assert!(bypass_hits_host("*.claude.ai", "claude.ai"));
        assert!(bypass_hits_host("*claude.ai", "api.claude.ai"));
        assert!(!bypass_hits_host("*.claude.ai", "claude.ai.evil.test"));
        assert_eq!(bypass_risk(Some("<local>;127.*;*jd.com"), &hosts()), None);
        assert_eq!(
            bypass_risk(Some("<local>;*.openai.com"), &hosts()),
            Some("*.openai.com".to_string())
        );
    }

    #[test]
    fn tun_name_matching() {
        assert!(is_tun_name("Wintun Userspace Tunnel"));
        assert!(is_tun_name("Mihomo"));
        assert!(is_tun_name("Clash Verge TUN"));
        assert!(is_tun_name("sing-box tun0"));
        assert!(is_tun_name("utun3"));
        assert!(!is_tun_name("Tailscale Tunnel"));
        assert!(!is_tun_name("Realtek PCIe GbE Family Controller"));
        assert!(!is_tun_name("Intel(R) Wi-Fi 6 AX201 160MHz"));
    }

    #[test]
    fn wide_string_keeps_full_name() {
        // T01-01：按码元数解码，长度减半会截断名称并误判"未接入"。
        let name = "Wintun Userspace Tunnel";
        let units: Vec<u16> = name.encode_utf16().collect();
        assert_eq!(wide_to_string(&units), name);
        let half = wide_to_string(&units[..units.len() / 2]);
        assert_ne!(half, name);
        assert!(!is_tun_name(&half) || half.len() < name.len());
    }

    #[test]
    fn select_tun_requires_up() {
        // T01-06：名称匹配但接口 Down 不算 TUN 接入。
        let down = vec![("Mihomo".to_string(), "Mihomo".to_string(), false)];
        assert_eq!(select_tun(&down), None);
        let up = vec![(
            "Wintun Userspace Tunnel".to_string(),
            "Mihomo".to_string(),
            true,
        )];
        assert_eq!(select_tun(&up).as_deref(), Some("Wintun Userspace Tunnel"));
        let friendly_only = vec![("Ethernet 2".to_string(), "Clash TUN".to_string(), true)];
        assert_eq!(select_tun(&friendly_only).as_deref(), Some("Clash TUN"));
    }

    #[test]
    fn verdict_matrix() {
        assert_eq!(
            verdict(&evidence(true, Some("127.0.0.1:7890")), None, &hosts()),
            AccessPath::SystemProxy {
                addr: "127.0.0.1:7890".into()
            }
        );
        assert_eq!(
            verdict(&evidence(false, None), Some("Mihomo".into()), &[]),
            AccessPath::Tun {
                adapter: "Mihomo".into()
            }
        );
        assert_eq!(
            verdict(&evidence(false, None), None, &[]),
            AccessPath::Uncovered
        );
        // 系统代理开优先于 TUN。
        assert_eq!(
            verdict(&evidence(true, Some("a:1")), Some("Mihomo".into()), &[]),
            AccessPath::SystemProxy { addr: "a:1".into() }
        );
    }

    #[test]
    fn covered_semantics() {
        let info_on = AccessInfo::from(&AccessPath::SystemProxy {
            addr: "127.0.0.1:7890".into(),
        });
        let info_tun = AccessInfo::from(&AccessPath::Tun {
            adapter: "x".into(),
        });
        let info_off = AccessInfo::from(&AccessPath::Uncovered);
        let info_unknown = AccessInfo::from(&AccessPath::Unknown {
            reason: "PAC".into(),
        });
        assert!(!info_on.is_uncovered());
        assert!(info_on.is_known());
        assert!(!info_tun.is_uncovered());
        assert!(info_tun.is_known());
        assert!(info_off.is_uncovered());
        assert!(!info_off.is_known());
        assert!(info_unknown.is_unknown());
        assert!(!info_unknown.is_known());
        assert_eq!(info_tun.note, "TUN 直连（x）");
        assert_eq!(info_unknown.note, "PAC");
    }
}
