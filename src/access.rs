//! 应用接入路径检查（v3.7）：探测流量跟随系统代理，系统代理关闭时靠 TUN 网卡兜底判定。
//!
//! Claude 等桌面应用只认系统代理——系统代理没开时它们直连真实出口，守护器测代理
//! 出口测得再准也管不到应用本体。因此每轮探测前先解析接入方式：
//!
//! - 系统代理开 → 探测跟随它指向的地址（哪怕是别的代理软件，测到的就是应用真实出口）；
//! - 系统代理关 + 有 TUN 网卡 → 探测直连（被 TUN 接管，与应用同路）；
//! - 系统代理关 + 无 TUN → **未接入**：应用直连真实出口，计入熔断阈值。
//!
//! [`parse_sys_proxyserver`] / [`is_tun_name`] / [`verdict`] 是纯函数，单测不发网络；
//! [`read_system_proxy`] / [`detect_tun_adapter`] 只在本机注册表与网卡表上读取。

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

/// 适配器描述/友好名是否像 TUN 虚拟网卡。
pub fn is_tun_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    if TUN_EXCLUDES.iter().any(|kw| lower.contains(kw)) {
        return false;
    }
    lower.starts_with("utun") || TUN_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

/// 解析注册表 `ProxyServer` 值：支持 `host:port` 与 `http=h:p;https=h:p` 分号形式。
pub fn parse_sys_proxyserver(raw: Option<&str>) -> Option<String> {
    let raw = raw?.trim();
    if raw.is_empty() {
        return None;
    }
    if raw.contains(';') {
        let https = raw.split(';').find_map(|part| {
            let part = part.trim();
            part.strip_prefix("https=")
                .map(str::trim)
                .filter(|v| !v.is_empty())
        });
        let http = raw.split(';').find_map(|part| {
            let part = part.trim();
            part.strip_prefix("http=")
                .map(str::trim)
                .filter(|v| !v.is_empty())
        });
        return https.or(http).map(str::to_string);
    }
    Some(raw.to_string())
}

/// 应用当前的接入方式判定（纯函数，供单测）。
#[derive(Clone, Debug, PartialEq)]
pub enum AccessPath {
    /// 系统代理开启（addr=None 表示 ProxyServer 没读到，按已接入处理）。
    SystemProxy { addr: Option<String> },
    /// 系统代理关闭，但存在 TUN 虚拟网卡（adapter=匹配到的适配器名）。
    Tun { adapter: String },
    /// 系统代理关闭且无 TUN：应用直连真实出口。
    Uncovered,
}

impl AccessInfo {
    /// 未接入（系统代理关 + 无 TUN）——v3.7 熔断条件。
    pub fn is_uncovered(&self) -> bool {
        self.path == "uncovered"
    }
}

pub fn verdict(
    sys_enabled: bool,
    sys_addr: Option<String>,
    tun_adapter: Option<String>,
) -> AccessPath {
    if sys_enabled {
        AccessPath::SystemProxy { addr: sys_addr }
    } else if let Some(adapter) = tun_adapter {
        AccessPath::Tun { adapter }
    } else {
        AccessPath::Uncovered
    }
}

/// 推给 UI / `--check` 的接入快照。
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessInfo {
    /// system_proxy | tun | uncovered | skipped
    pub path: String,
    pub note: String,
}

impl From<&AccessPath> for AccessInfo {
    fn from(path: &AccessPath) -> Self {
        match path {
            AccessPath::SystemProxy { addr: Some(addr) } => AccessInfo {
                path: "system_proxy".into(),
                note: format!("系统代理 {addr}"),
            },
            AccessPath::SystemProxy { addr: None } => AccessInfo {
                path: "system_proxy".into(),
                note: "系统代理已开启（地址未读到，回退配置端口探测）".into(),
            },
            AccessPath::Tun { adapter } => AccessInfo {
                path: "tun".into(),
                note: format!("TUN 直连（{adapter}）"),
            },
            AccessPath::Uncovered => AccessInfo {
                path: "uncovered".into(),
                note: "系统代理未开启且未检测到 TUN 网卡，应用会直连真实出口".into(),
            },
        }
    }
}

/// 每轮探测前调用：返回（探测要拨的代理地址；`None` = 直连，接入快照）。
pub fn resolve(cfg: &Config) -> (Option<String>, AccessInfo) {
    #[cfg(target_os = "windows")]
    {
        let (enabled, server) = read_system_proxy();
        let tun = if enabled { None } else { detect_tun_adapter() };
        let path = verdict(enabled, parse_sys_proxyserver(server.as_deref()), tun);
        let info = AccessInfo::from(&path);
        let proxy = match &path {
            AccessPath::SystemProxy { addr: Some(addr) } => Some(format!("http://{addr}")),
            // 系统代理开着但地址读不到：按已接入，探测回退配置端口。
            AccessPath::SystemProxy { addr: None } => Some(cfg.proxy_url()),
            _ => None,
        };
        (proxy, info)
    }
    #[cfg(not(target_os = "windows"))]
    {
        // macOS 移植为进程守护模式，保持按配置端口探测、不检查接入路径。
        (
            Some(cfg.proxy_url()),
            AccessInfo {
                path: "skipped".into(),
                note: "非 Windows：按配置端口探测".into(),
            },
        )
    }
}

// ---------- Windows 系统读取 ----------

#[cfg(target_os = "windows")]
fn read_system_proxy() -> (bool, Option<String>) {
    use winreg::enums::KEY_READ;
    use winreg::RegKey;
    let hkcu = RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
    let Ok(settings) = hkcu.open_subkey_with_flags(
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        KEY_READ,
    ) else {
        return (false, None);
    };
    let enabled: u32 = settings.get_value("ProxyEnable").unwrap_or(0);
    let server: String = settings.get_value("ProxyServer").unwrap_or_default();
    (
        enabled != 0,
        if server.is_empty() {
            None
        } else {
            Some(server)
        },
    )
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
            let mut current = buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
            while !current.is_null() {
                let adapter = unsafe { &*current };
                if adapter.OperStatus == IfOperStatusUp {
                    let desc = String::from_utf16_lossy(unsafe {
                        std::slice::from_raw_parts(
                            adapter.Description.as_ptr(),
                            adapter.Description.len() / 2,
                        )
                    });
                    let friendly = String::from_utf16_lossy(unsafe {
                        std::slice::from_raw_parts(
                            adapter.FriendlyName.as_ptr(),
                            adapter.FriendlyName.len() / 2,
                        )
                    });
                    if is_tun_name(&desc) {
                        return Some(desc);
                    }
                    if is_tun_name(&friendly) {
                        return Some(friendly);
                    }
                }
                current = adapter.Next;
            }
            return None;
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

    #[test]
    fn proxyserver_forms() {
        assert_eq!(parse_sys_proxyserver(None), None);
        assert_eq!(parse_sys_proxyserver(Some("  ")), None);
        assert_eq!(
            parse_sys_proxyserver(Some("127.0.0.1:7890")).as_deref(),
            Some("127.0.0.1:7890")
        );
        assert_eq!(
            parse_sys_proxyserver(Some(
                "http=127.0.0.1:80;https=127.0.0.1:7891;ftp=127.0.0.1:21"
            ))
            .as_deref(),
            Some("127.0.0.1:7891")
        );
        assert_eq!(
            parse_sys_proxyserver(Some("http=127.0.0.1:80;ftp=127.0.0.1:21")).as_deref(),
            Some("127.0.0.1:80")
        );
        assert_eq!(
            parse_sys_proxyserver(Some("ftp=127.0.0.1:21")).as_deref(),
            Some("ftp=127.0.0.1:21")
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
    fn verdict_matrix() {
        assert_eq!(
            verdict(true, Some("127.0.0.1:7890".into()), None),
            AccessPath::SystemProxy {
                addr: Some("127.0.0.1:7890".into())
            }
        );
        assert_eq!(
            verdict(true, None, None),
            AccessPath::SystemProxy { addr: None }
        );
        assert_eq!(
            verdict(false, None, Some("Mihomo".into())),
            AccessPath::Tun {
                adapter: "Mihomo".into()
            }
        );
        assert_eq!(verdict(false, None, None), AccessPath::Uncovered);
        // 系统代理开优先于 TUN。
        assert_eq!(
            verdict(true, Some("a:1".into()), Some("Mihomo".into())),
            AccessPath::SystemProxy {
                addr: Some("a:1".into())
            }
        );
    }

    #[test]
    fn covered_semantics() {
        let info_on = AccessInfo::from(&AccessPath::SystemProxy { addr: None });
        let info_tun = AccessInfo::from(&AccessPath::Tun {
            adapter: "x".into(),
        });
        let info_off = AccessInfo::from(&AccessPath::Uncovered);
        assert!(!info_on.is_uncovered());
        assert!(!info_tun.is_uncovered());
        assert!(info_off.is_uncovered());
        assert_eq!(info_tun.note, "TUN 直连（x）");
    }
}
