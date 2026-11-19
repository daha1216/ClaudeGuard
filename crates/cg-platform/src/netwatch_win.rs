//! Native IPv4/IPv6 socket leak inspector via `IpHelper::GetExtendedTcpTable`.
//!
//! Only inspects guarded PIDs in `SystemProxy` mode:
//! - Loopback on configured `proxy_port` -> `Remote::Proxy` (expected)
//! - Loopback / RFC1918 / link-local / CGNAT / ULA / `198.18.0.0/15` fake-ip -> `Remote::Local`
//! - Any `198.18.0.0/15` (or `::ffff:198.18.0.0/15`) connection triggers `applicable = false`
//!   and reports TUN fake-ip takeover so Clash/Mihomo/sing-box users are never falsely tripped.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub use cg_protocol::{LeakConn, LeakReport};

use crate::access_win::AccessInfo;

/// Maximum direct connection records included in a single report.
pub const MAX_LISTED: usize = 8;

/// Peer classification for an ESTABLISHED TCP socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Remote {
    Proxy,
    Local,
    Public,
}

/// Active TCP connection row (IPv4 or IPv6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpConn {
    pub pid: u32,
    pub remote: IpAddr,
    pub port: u16,
}

/// TUN fake-ip range: `198.18.0.0/15` (RFC 2544 benchmarking block used by Clash/Mihomo/sing-box).
pub fn is_fake_ip_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 198 && (o[1] == 18 || o[1] == 19)
}

/// Normalize dual-stack IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to `IpAddr::V4` when possible.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
    }
}

/// Whether `ip` (including `::ffff:198.18.0.0/15`) falls in the TUN fake-ip block.
pub fn is_fake_ip_addr(ip: IpAddr) -> bool {
    match canonical_ip(ip) {
        IpAddr::V4(v4) => is_fake_ip_v4(v4),
        IpAddr::V6(_) => false,
    }
}

/// Private / loopback / link-local / CGNAT / unspecified IPv4 check.
pub fn is_local_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (o[0] == 100 && (64..=127).contains(&o[1]))
        || o[0] == 0
}

/// Private / loopback / link-local (`fe80::/10`) / ULA (`fc00::/7`) / unspecified IPv6 check.
pub fn is_local_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_local_v4(v4);
    }
    let seg0 = ip.segments()[0];
    let is_ula = (seg0 & 0xfe00) == 0xfc00;
    let is_link_local = (seg0 & 0xffc0) == 0xfe80;
    ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || is_ula || is_link_local
}

/// Unified IPv4/IPv6 local address check (excludes loopback, RFC1918, ULA, link-local, fake-ip).
pub fn is_local_addr(ip: IpAddr) -> bool {
    match canonical_ip(ip) {
        IpAddr::V4(v4) => is_local_v4(v4) || is_fake_ip_v4(v4),
        IpAddr::V6(v6) => is_local_v6(v6),
    }
}

/// Classify a TCP peer relative to the local proxy port.
pub fn classify(remote: IpAddr, port: u16, proxy_port: u16) -> Remote {
    let ip = canonical_ip(remote);
    if proxy_port > 0 && ip.is_loopback() && port == proxy_port {
        Remote::Proxy
    } else if is_local_addr(ip) {
        Remote::Local
    } else {
        Remote::Public
    }
}

/// Detects whether a guarded agent/process label corresponds to an MCP plugin or helper subprocess
/// (e.g., `github-mcp-server`, `cowork-svc`, `uvx`, `npx`, `node`, `python`, `deno`).
pub fn is_mcp_agent_label(label: &str) -> bool {
    let low = label.to_ascii_lowercase();
    low.contains("mcp")
        || low.contains("cowork")
        || low.contains("uvx")
        || low.contains("npx")
        || low.contains("node")
        || low.contains("python")
        || low.contains("deno")
}

/// Fold TCP connections + guarded agent PID map into a `LeakReport`.
pub fn fold(
    conns: &[TcpConn],
    agents: &HashMap<u32, String>,
    proxy_port: u16,
    access: &AccessInfo,
    checked_at: u64,
) -> LeakReport {
    let applicable = access.path == "system_proxy";
    let mut report = LeakReport {
        applicable,
        mode: access.path.clone(),
        checked_at,
        agent_conns: 0,
        proxied: 0,
        local: 0,
        direct: Vec::new(),
        direct_total: 0,
        note: String::new(),
    };
    if !applicable {
        report.note = match access.path.as_str() {
            "tun" => {
                "TUN 模式：对端是公网地址属正常（流量被虚拟网卡接管），不做直连判定".to_string()
            }
            "uncovered" => "未接入代理：应用本来就在直连，直连判定无意义".to_string(),
            "unknown" => "接入路径无法确认：不猜测，不做直连判定".to_string(),
            _ => "尚未完成接入路径检查".to_string(),
        };
        return report;
    }

    let mut fake_ip = 0usize;
    for c in conns {
        let Some(agent) = agents.get(&c.pid) else {
            continue;
        };
        report.agent_conns += 1;
        let ip = canonical_ip(c.remote);
        if is_fake_ip_addr(ip) {
            fake_ip += 1;
        }
        match classify(ip, c.port, proxy_port) {
            Remote::Proxy => report.proxied += 1,
            Remote::Local => report.local += 1,
            Remote::Public => {
                report.direct_total += 1;
                if report.direct.len() < MAX_LISTED {
                    report.direct.push(LeakConn {
                        pid: c.pid,
                        agent: agent.clone(),
                        remote: ip.to_string(),
                        port: c.port,
                        is_mcp: is_mcp_agent_label(agent),
                    });
                }
            }
        }
    }

    // Any observed 198.18.0.0/15 fake-ip connection means a TUN stack has taken over DNS/routing:
    // mark inspection non-applicable and never raise false direct-leak positives.
    if fake_ip > 0 {
        report.applicable = false;
        report.direct.clear();
        report.direct_total = 0;
        report.note = format!("检测到 TUN 接管（{fake_ip} 条 fake-ip 连接），不判定直连");
        return report;
    }

    report.note = if report.direct_total > 0 {
        format!(
            "发现 {} 条直连（未经本地代理端口 {}）",
            report.direct_total, proxy_port
        )
    } else if report.agent_conns == 0 {
        "被守护应用当前没有已建立的连接".to_string()
    } else {
        format!("{} 条连接全部经本地代理", report.proxied)
    };
    report
}

/// High-level scan helper using pre-computed cached agent PIDs (zero process rescanning).
pub fn scan_with_cached_agents(
    leak_watch_enabled: bool,
    access: &AccessInfo,
    agents: &HashMap<u32, String>,
    proxy_port: u16,
    checked_at: u64,
) -> LeakReport {
    if !leak_watch_enabled {
        return LeakReport::not_applicable(&access.path, "直连泄露观察已关闭", checked_at);
    }
    if access.path != "system_proxy" {
        return fold(&[], agents, proxy_port, access, checked_at);
    }
    if agents.is_empty() {
        return LeakReport::not_applicable(&access.path, "被守护应用未在运行", checked_at);
    }
    let conns = established_conns();
    fold(&conns, agents, proxy_port, access, checked_at)
}

/// Read all ESTABLISHED IPv4 and IPv6 TCP connections with owning PIDs via `GetExtendedTcpTable`.
#[cfg(windows)]
pub fn established_conns() -> Vec<TcpConn> {
    let mut out = established_v4();
    out.extend(established_v6());
    out
}

#[cfg(windows)]
fn port_from_dw(dw_port: u32) -> u16 {
    let bytes = dw_port.to_ne_bytes();
    u16::from_be_bytes([bytes[0], bytes[1]])
}

#[cfg(windows)]
fn call_extended_tcp_table(af: u32) -> Option<Vec<u64>> {
    use windows::Win32::Foundation::{BOOL, ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, TCP_TABLE_OWNER_PID_ALL,
    };

    for _ in 0..3 {
        let mut size: u32 = 0;
        unsafe {
            GetExtendedTcpTable(None, &mut size, BOOL(0), af, TCP_TABLE_OWNER_PID_ALL, 0);
        }
        if size == 0 {
            return None;
        }
        let alloc_bytes = size as usize + 256;
        let mut buf: Vec<u64> = vec![0u64; alloc_bytes.div_ceil(8)];
        let mut out_size = (buf.len() * 8) as u32;
        let rc = unsafe {
            GetExtendedTcpTable(
                Some(buf.as_mut_ptr().cast()),
                &mut out_size,
                BOOL(0),
                af,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if rc == ERROR_INSUFFICIENT_BUFFER.0 {
            continue;
        }
        if rc != NO_ERROR.0 {
            return None;
        }
        return Some(buf);
    }
    None
}

#[cfg(windows)]
fn established_v4() -> Vec<TcpConn> {
    use windows::Win32::NetworkManagement::IpHelper::{
        MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    };
    use windows::Win32::Networking::WinSock::AF_INET;

    const MIB_TCP_STATE_ESTAB: u32 = 5;
    let Some(buf) = call_extended_tcp_table(AF_INET.0 as u32) else {
        return Vec::new();
    };
    let byte_len = buf.len() * 8;
    if byte_len < core::mem::size_of::<u32>() {
        return Vec::new();
    }
    let table = unsafe { &*buf.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>() };
    let count = table.dwNumEntries as usize;
    let header = core::mem::offset_of!(MIB_TCPTABLE_OWNER_PID, table);
    let row_size = core::mem::size_of::<MIB_TCPROW_OWNER_PID>();
    if byte_len < header.saturating_add(count.saturating_mul(row_size)) {
        return Vec::new();
    }
    let rows = unsafe { core::slice::from_raw_parts(table.table.as_ptr(), count) };
    let mut out = Vec::with_capacity(count);
    for row in rows {
        if row.dwState != MIB_TCP_STATE_ESTAB || row.dwRemoteAddr == 0 {
            continue;
        }
        let remote = Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes());
        out.push(TcpConn {
            pid: row.dwOwningPid,
            remote: IpAddr::V4(remote),
            port: port_from_dw(row.dwRemotePort),
        });
    }
    out
}

#[cfg(windows)]
fn established_v6() -> Vec<TcpConn> {
    use windows::Win32::NetworkManagement::IpHelper::{
        MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    };
    use windows::Win32::Networking::WinSock::AF_INET6;

    const MIB_TCP_STATE_ESTAB: u32 = 5;
    let Some(buf) = call_extended_tcp_table(AF_INET6.0 as u32) else {
        return Vec::new();
    };
    let byte_len = buf.len() * 8;
    if byte_len < core::mem::size_of::<u32>() {
        return Vec::new();
    }
    let table = unsafe { &*buf.as_ptr().cast::<MIB_TCP6TABLE_OWNER_PID>() };
    let count = table.dwNumEntries as usize;
    let header = core::mem::offset_of!(MIB_TCP6TABLE_OWNER_PID, table);
    let row_size = core::mem::size_of::<MIB_TCP6ROW_OWNER_PID>();
    if byte_len < header.saturating_add(count.saturating_mul(row_size)) {
        return Vec::new();
    }
    let rows = unsafe { core::slice::from_raw_parts(table.table.as_ptr(), count) };
    let mut out = Vec::with_capacity(count);
    for row in rows {
        if row.dwState != MIB_TCP_STATE_ESTAB {
            continue;
        }
        let v6 = Ipv6Addr::from(row.ucRemoteAddr);
        if v6.is_unspecified() {
            continue;
        }
        let remote = canonical_ip(IpAddr::V6(v6));
        if remote == IpAddr::V4(Ipv4Addr::UNSPECIFIED) {
            continue;
        }
        out.push(TcpConn {
            pid: row.dwOwningPid,
            remote,
            port: port_from_dw(row.dwRemotePort),
        });
    }
    out
}

#[cfg(not(windows))]
pub fn established_conns() -> Vec<TcpConn> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn access(path: &str) -> AccessInfo {
        AccessInfo {
            path: path.into(),
            note: String::new(),
        }
    }

    fn conn_v4(pid: u32, ip: [u8; 4], port: u16) -> TcpConn {
        TcpConn {
            pid,
            remote: IpAddr::V4(Ipv4Addr::from(ip)),
            port,
        }
    }

    fn conn_v6(pid: u32, ip: Ipv6Addr, port: u16) -> TcpConn {
        TcpConn {
            pid,
            remote: IpAddr::V6(ip),
            port,
        }
    }

    #[test]
    fn classifies_ipv4_and_ipv6_proxy_local_and_public() {
        assert_eq!(
            classify(IpAddr::V4(Ipv4Addr::LOCALHOST), 7890, 7890),
            Remote::Proxy
        );
        assert_eq!(
            classify(IpAddr::V6(Ipv6Addr::LOCALHOST), 7890, 7890),
            Remote::Proxy
        );
        assert_eq!(
            classify(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000, 7890),
            Remote::Local
        );
        assert_eq!(
            classify(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), 443, 7890),
            Remote::Local
        );
        assert_eq!(
            classify(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)), 443, 7890),
            Remote::Local
        );
        assert_eq!(
            classify(IpAddr::V4(Ipv4Addr::new(172, 16, 3, 3)), 443, 7890),
            Remote::Local
        );
        assert_eq!(
            classify(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)), 443, 7890),
            Remote::Local
        );
        assert_eq!(
            classify(IpAddr::V6("fe80::1".parse().unwrap()), 443, 7890),
            Remote::Local
        );
        assert_eq!(
            classify(IpAddr::V6("fd00::1".parse().unwrap()), 443, 7890),
            Remote::Local
        );
        // RFC 5737 TEST-NET-2 & RFC 3849 documentation IPv6 -> Public
        assert_eq!(
            classify(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 98)), 443, 7890),
            Remote::Public
        );
        assert_eq!(
            classify(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 45)), 443, 7890),
            Remote::Public
        );
        assert_eq!(
            classify(IpAddr::V6("2001:db8::1".parse().unwrap()), 443, 7890),
            Remote::Public
        );
    }

    #[test]
    fn fake_ip_198_18_0_0_slash_15_and_mapped_v6_are_excluded() {
        assert!(is_fake_ip_v4(Ipv4Addr::new(198, 18, 0, 34)));
        assert!(is_fake_ip_v4(Ipv4Addr::new(198, 19, 255, 254)));
        assert!(!is_fake_ip_v4(Ipv4Addr::new(198, 20, 0, 1)));
        assert!(!is_fake_ip_v4(Ipv4Addr::new(198, 51, 100, 98)));

        let mapped_fake: Ipv6Addr = "::ffff:198.18.0.5".parse().unwrap();
        assert!(is_fake_ip_addr(IpAddr::V6(mapped_fake)));
        assert_eq!(classify(IpAddr::V6(mapped_fake), 443, 7890), Remote::Local);

        // Dual-stack IPv4-mapped loopback, RFC1918, and TEST-NET-2 public
        assert_eq!(
            classify(IpAddr::V6("::ffff:127.0.0.1".parse().unwrap()), 7890, 7890),
            Remote::Proxy
        );
        assert_eq!(
            classify(
                IpAddr::V6("::ffff:192.168.1.10".parse().unwrap()),
                443,
                7890
            ),
            Remote::Local
        );
        assert_eq!(
            classify(
                IpAddr::V6("::ffff:198.51.100.98".parse().unwrap()),
                443,
                7890
            ),
            Remote::Public
        );
    }

    #[test]
    fn scan_with_cached_agents_respects_toggle_and_empty_agents() {
        let sys = access("system_proxy");
        let disabled = scan_with_cached_agents(false, &sys, &HashMap::new(), 7890, 42);
        assert!(!disabled.applicable);
        assert!(disabled.note.contains("关闭"));

        let idle = scan_with_cached_agents(true, &sys, &HashMap::new(), 7890, 42);
        assert!(!idle.applicable);
        assert!(idle.note.contains("未在运行"));
    }

    #[test]
    fn fold_marks_non_applicable_and_clears_direct_when_fake_ip_seen() {
        let mut agents = HashMap::new();
        agents.insert(100u32, "Claude".to_string());
        let conns = vec![
            conn_v4(100, [198, 18, 0, 4], 443),
            conn_v4(100, [198, 51, 100, 98], 443),
        ];
        let r = fold(&conns, &agents, 7890, &access("system_proxy"), 1000);
        assert!(!r.applicable, "fake-ip must mark report not applicable");
        assert_eq!(r.direct_total, 0);
        assert!(r.direct.is_empty());
        assert!(r.note.contains("TUN 接管"), "note={}", r.note);

        // Also test ::ffff:198.18.0.5 mapped IPv6 fake-ip.
        let conns_v6 = vec![conn_v6(100, "::ffff:198.19.0.9".parse().unwrap(), 443)];
        let r6 = fold(&conns_v6, &agents, 7890, &access("system_proxy"), 1000);
        assert!(!r6.applicable);
        assert!(r6.note.contains("TUN 接管"));
    }

    #[test]
    fn fold_detects_ipv4_and_ipv6_public_leaks_and_caps_listed() {
        let mut agents = HashMap::new();
        agents.insert(100u32, "Claude".to_string());
        let conns = vec![
            conn_v4(100, [127, 0, 0, 1], 7890),
            conn_v4(100, [192, 168, 1, 2], 53),
            conn_v4(100, [198, 51, 100, 98], 443),
            conn_v6(100, "2001:db8::45".parse().unwrap(), 443),
            conn_v4(999, [203, 0, 113, 45], 443), // unguarded PID ignored
        ];
        let r = fold(&conns, &agents, 7890, &access("system_proxy"), 2000);
        assert!(r.applicable);
        assert_eq!(r.agent_conns, 4);
        assert_eq!(r.proxied, 1);
        assert_eq!(r.local, 1);
        assert_eq!(r.direct_total, 2);
        assert_eq!(r.direct[0].remote, "198.51.100.98");
        assert_eq!(r.direct[1].remote, "2001:db8::45");
        assert!(r.leaked());

        let many: Vec<TcpConn> = (1..=20)
            .map(|i| conn_v4(100, [203, 0, 113, i], 443))
            .collect();
        let capped = fold(&many, &agents, 7890, &access("system_proxy"), 2000);
        assert_eq!(capped.direct_total, 20);
        assert_eq!(capped.direct.len(), MAX_LISTED);
    }

    #[test]
    fn non_system_proxy_modes_are_not_applicable() {
        let mut agents = HashMap::new();
        agents.insert(1u32, "Claude".to_string());
        let conns = vec![conn_v4(1, [198, 51, 100, 98], 443)];
        for path in ["tun", "uncovered", "unknown", "skipped"] {
            let r = fold(&conns, &agents, 7890, &access(path), 3000);
            assert!(!r.applicable, "{path} must not be applicable");
            assert_eq!(r.direct_total, 0);
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_extended_tcp_table_v4_and_v6_succeed() {
        let _conns = established_conns();
    }
}
