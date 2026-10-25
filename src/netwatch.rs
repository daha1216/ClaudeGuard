//! 直连泄露观察（v3.12 引入）。
//!
//! [`crate::access`] 判断的是"系统代理开没开、有没有 TUN"——那是**根据配置推断**接入方式。
//! 它回答不了更实际的问题：被守护的应用此刻到底连到哪去了？如果某个进程绕过了系统代理
//! 直连公网，配置看着一切正常，出口校验也照样通过，但应用本体已经在用真实 IP 说话。
//!
//! 这里补上这条证据链：读全机 TCP 连接表（`GetExtendedTcpTable`，带 owning pid），
//! 挑出属于被守护 agent 的 ESTABLISHED 连接，按对端地址分三类：
//!
//! - 对端是 `127.0.0.1:<代理端口>` → 走代理（正常）；
//! - 对端是回环/私网/链路本地 → 本地通信（正常，不算泄露）；
//! - 对端是公网 → **直连**，这就是硬证据。
//!
//! 只在「系统代理」模式下判定：TUN 模式下应用的对端本来就是公网地址（流量被虚拟网卡
//! 接管），此时把公网对端当成泄露会全线误报。
//!
//! 两个已知边界，写在这里免得后来者当成 bug：
//! 1. 只看 TCP。走 UDP/QUIC 的直连看不见（`GetExtendedUdpTable` 拿不到可靠的连接态）。
//! 2. 只看被守护的 agent 进程本身，不看它们的子进程（WebView2 渲染进程会自己连微软域名，
//!    算进来就是噪声）。代价是子进程里的泄露漏检。

use std::collections::HashMap;
use std::net::Ipv4Addr;

use serde::Serialize;

use crate::access::AccessInfo;
use crate::config::Config;
use crate::model::now;

/// 单条直连记录。`remote` 只用于展示，不落日志全文以外的任何地方。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LeakConn {
    pub pid: u32,
    pub agent: String,
    pub remote: String,
    pub port: u16,
}

/// 一次观察的结论。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LeakReport {
    /// 本次是否具备判定条件（只有系统代理模式才判）。
    pub applicable: bool,
    /// 判定时的接入方式：system_proxy / tun / uncovered / unknown / skipped。
    pub mode: String,
    pub checked_at: u64,
    /// 被守护 agent 的 ESTABLISHED 连接总数。
    pub agent_conns: usize,
    /// 其中走本地代理端口的条数。
    pub proxied: usize,
    /// 其中连本地/私网地址的条数。
    pub local: usize,
    /// 直连公网的记录（最多保留 [`MAX_LISTED`] 条，总数见 `direct_total`）。
    pub direct: Vec<LeakConn>,
    pub direct_total: usize,
    pub note: String,
}

impl LeakReport {
    /// 空的"不适用"报告，用于启动初期或非系统代理模式。
    pub fn not_applicable(mode: &str, note: &str) -> Self {
        LeakReport {
            applicable: false,
            mode: mode.to_string(),
            checked_at: now(),
            agent_conns: 0,
            proxied: 0,
            local: 0,
            direct: Vec::new(),
            direct_total: 0,
            note: note.to_string(),
        }
    }

    /// 是否发现了直连。
    pub fn leaked(&self) -> bool {
        self.direct_total > 0
    }
}

/// 直连列表最多保留多少条（避免一个疯狂重连的进程把状态撑爆）。
pub const MAX_LISTED: usize = 8;

/// 对端地址分类。纯函数，单测不碰系统。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Remote {
    /// 本地代理端口。
    Proxy,
    /// 回环/私网/链路本地——本地通信。
    Local,
    /// 公网——直连。
    Public,
}

/// TUN 代理的 fake-ip 地址段：`198.18.0.0/15`（RFC 2544 基准测试段）。
///
/// mihomo/Clash/sing-box 在 TUN + fake-ip 模式下把应用的目标地址换成本段里的地址，
/// 由虚拟网卡接管后再按域名转发。所以这些连接**不是直连**，而是被代理接管了——
/// v3.12.0 没排除这一段，实测在用户机器上把 3 条 fake-ip 连接报成了"直连泄露"。
pub fn is_fake_ip_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 198 && (o[1] == 18 || o[1] == 19)
}

/// 私网/本地地址判断（IPv4）。
pub fn is_local_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        // 100.64.0.0/10 运营商级 NAT（Tailscale 等也常用）
        || (o[0] == 100 && (64..=127).contains(&o[1]))
        // 0.0.0.0/8
        || o[0] == 0
}

/// 纯函数：给一条连接的对端分类。
pub fn classify(remote: Ipv4Addr, port: u16, proxy_port: u16) -> Remote {
    if remote.is_loopback() && port == proxy_port {
        Remote::Proxy
    } else if is_local_v4(remote) || is_fake_ip_v4(remote) {
        Remote::Local
    } else {
        Remote::Public
    }
}

/// 一条 TCP 连接（只保留判定需要的字段）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpConn {
    pub pid: u32,
    pub remote: Ipv4Addr,
    pub port: u16,
}

/// 读全机 IPv4 TCP 连接表里处于 ESTABLISHED 的连接。
///
/// 失败（权限、表在两次调用间变大）返回空表：观察功能宁可少报，不能因此熔断。
#[cfg(windows)]
pub fn established_conns() -> Vec<TcpConn> {
    use windows::Win32::Foundation::{BOOL, ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, TCP_TABLE_OWNER_PID_ALL,
    };
    use windows::Win32::Networking::WinSock::AF_INET;

    const ESTABLISHED: u32 = 5;
    let mut out = Vec::new();
    for _ in 0..2 {
        let mut size: u32 = 0;
        unsafe {
            GetExtendedTcpTable(
                None::<*mut core::ffi::c_void>,
                &mut size,
                BOOL(0),
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
        }
        if size == 0 {
            return out;
        }
        // 多留一行余量：表在两次调用之间可能刚好变大。
        let mut buf = vec![0u8; size as usize + 64];
        let mut size2 = buf.len() as u32;
        let rc = unsafe {
            GetExtendedTcpTable(
                Some(buf.as_mut_ptr().cast::<core::ffi::c_void>()),
                &mut size2,
                BOOL(0),
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if rc == ERROR_INSUFFICIENT_BUFFER.0 {
            continue; // 表变大了，按新的 size 再来一次
        }
        if rc != NO_ERROR.0 {
            return out;
        }
        let entries = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        // 每行 24 字节：state/local_addr/local_port/remote_addr/remote_port/pid
        let row = 24usize;
        let need = 4 + entries * row;
        if buf.len() < need {
            return out;
        }
        for i in 0..entries {
            let p = 4 + i * row;
            let state = u32::from_le_bytes([buf[p], buf[p + 1], buf[p + 2], buf[p + 3]]);
            if state != ESTABLISHED {
                continue;
            }
            let remote_raw =
                u32::from_le_bytes([buf[p + 12], buf[p + 13], buf[p + 14], buf[p + 15]]);
            let port_raw = u32::from_le_bytes([buf[p + 16], buf[p + 17], buf[p + 18], buf[p + 19]]);
            let pid = u32::from_le_bytes([buf[p + 20], buf[p + 21], buf[p + 22], buf[p + 23]]);
            if remote_raw == 0 {
                continue;
            }
            out.push(TcpConn {
                pid,
                remote: Ipv4Addr::from(remote_raw.to_be()),
                // 端口字段是网络字节序放在低 16 位
                port: (((port_raw & 0xff) << 8) | ((port_raw >> 8) & 0xff)) as u16,
            });
        }
        return out;
    }
    out
}

#[cfg(not(windows))]
pub fn established_conns() -> Vec<TcpConn> {
    Vec::new()
}

/// 被守护的 agent 进程：pid → 展示名。
///
/// 用与熔断同一套指纹（[`crate::guard::gui_agent_matches`] / `cli_agent_matches`），
/// 保证"谁算被守护对象"在两处口径一致。
pub fn agent_pids(cfg: &Config) -> HashMap<u32, String> {
    use sysinfo::System;
    let mut out = HashMap::new();
    let guarded = &cfg.guarded_agents;
    if guarded.is_empty() {
        return out;
    }
    let claude_dir_l = crate::guard::find_claude_dir().map(|d| d.to_string_lossy().to_lowercase());
    let mut sys = System::new();
    sys.refresh_processes();
    for (pid, p) in sys.processes() {
        let name_l = p.name().to_string().to_lowercase();
        let path_l = p
            .exe()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        let cmd_l = p
            .cmd()
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase();
        for a in crate::guard::GUI_AGENTS {
            if !guarded.iter().any(|g| g == a.id) {
                continue;
            }
            if crate::guard::gui_agent_matches(a.id, &name_l, &path_l, claude_dir_l.as_deref()) {
                out.insert(pid.as_u32(), a.name.to_string());
                break;
            }
        }
        if guarded.iter().any(|g| g == "claude")
            && crate::guard::cli_agent_matches("claude-code", &name_l, &path_l, &cmd_l)
        {
            out.entry(pid.as_u32())
                .or_insert_with(|| "Claude Code".to_string());
        }
    }
    out
}

/// 纯函数：把连接表 + agent pid 表 + 代理端口，折成一份报告。
pub fn fold(
    conns: &[TcpConn],
    agents: &HashMap<u32, String>,
    proxy_port: u16,
    access: &AccessInfo,
) -> LeakReport {
    let applicable = access.path == "system_proxy";
    let mut report = LeakReport {
        applicable,
        mode: access.path.clone(),
        checked_at: now(),
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
        if is_fake_ip_v4(c.remote) {
            fake_ip += 1;
        }
        match classify(c.remote, c.port, proxy_port) {
            Remote::Proxy => report.proxied += 1,
            Remote::Local => report.local += 1,
            Remote::Public => {
                report.direct_total += 1;
                if report.direct.len() < MAX_LISTED {
                    report.direct.push(LeakConn {
                        pid: c.pid,
                        agent: agent.clone(),
                        remote: c.remote.to_string(),
                        port: c.port,
                    });
                }
            }
        }
    }
    // 观察到 fake-ip 说明 TUN 正在接管应用流量：此时"公网对端"可能是被接管后的真实目标，
    // 也可能是硬编码 IP，按地址判直连已不可靠——放弃判定，只如实说明。
    if fake_ip > 0 {
        report.applicable = false;
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

/// 执行一次观察。
pub fn scan(cfg: &Config, access: &AccessInfo) -> LeakReport {
    if !cfg.leak_watch {
        return LeakReport::not_applicable(&access.path, "直连泄露观察已关闭");
    }
    if access.path != "system_proxy" {
        return LeakReport::not_applicable(&access.path, "");
    }
    let agents = agent_pids(cfg);
    if agents.is_empty() {
        return LeakReport::not_applicable(&access.path, "被守护应用未在运行");
    }
    let conns = established_conns();
    fold(&conns, &agents, cfg.proxy_port, access)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::AccessInfo;

    fn access(path: &str) -> AccessInfo {
        AccessInfo {
            path: path.to_string(),
            note: String::new(),
        }
    }

    fn conn(pid: u32, ip: [u8; 4], port: u16) -> TcpConn {
        TcpConn {
            pid,
            remote: Ipv4Addr::from(ip),
            port,
        }
    }

    #[test]
    fn loopback_on_proxy_port_is_proxied() {
        assert_eq!(classify(Ipv4Addr::LOCALHOST, 7890, 7890), Remote::Proxy);
        // 回环但端口不同：本地服务，不是代理
        assert_eq!(classify(Ipv4Addr::LOCALHOST, 5000, 7890), Remote::Local);
    }

    #[test]
    fn private_and_special_ranges_are_local() {
        assert_eq!(
            classify(Ipv4Addr::new(192, 168, 1, 5), 443, 7890),
            Remote::Local
        );
        assert_eq!(
            classify(Ipv4Addr::new(10, 0, 0, 9), 443, 7890),
            Remote::Local
        );
        assert_eq!(
            classify(Ipv4Addr::new(172, 16, 3, 3), 443, 7890),
            Remote::Local
        );
        assert_eq!(
            classify(Ipv4Addr::new(169, 254, 1, 1), 443, 7890),
            Remote::Local
        );
        assert_eq!(
            classify(Ipv4Addr::new(100, 64, 0, 1), 443, 7890),
            Remote::Local
        );
        assert_eq!(
            classify(Ipv4Addr::new(0, 0, 0, 0), 443, 7890),
            Remote::Local
        );
    }

    #[test]
    fn public_address_is_public() {
        assert_eq!(
            classify(Ipv4Addr::new(1, 1, 1, 1), 443, 7890),
            Remote::Public
        );
        assert_eq!(
            classify(Ipv4Addr::new(8, 8, 8, 8), 443, 7890),
            Remote::Public
        );
        // 100.128 已经出了 100.64/10 的右边界
        assert_eq!(
            classify(Ipv4Addr::new(100, 128, 0, 1), 443, 7890),
            Remote::Public
        );
    }

    #[test]
    fn fake_ip_is_not_direct() {
        // 198.18.0.0/15 是 TUN fake-ip 段：被接管，不是直连
        assert!(is_fake_ip_v4(Ipv4Addr::new(198, 18, 0, 34)));
        assert!(is_fake_ip_v4(Ipv4Addr::new(198, 19, 255, 1)));
        assert!(!is_fake_ip_v4(Ipv4Addr::new(198, 20, 0, 1)));
        assert_eq!(
            classify(Ipv4Addr::new(198, 18, 0, 34), 443, 7890),
            Remote::Local
        );
    }

    #[test]
    fn fold_gives_up_when_tun_fake_ip_seen() {
        // 实测踩过：TUN fake-ip 下 3 条连接被报成"直连泄露"
        let mut agents = HashMap::new();
        agents.insert(100u32, "Claude".to_string());
        let conns = vec![
            conn(100, [198, 18, 0, 4], 443),
            conn(100, [198, 18, 0, 5], 443),
            conn(100, [198, 18, 0, 6], 443),
        ];
        let r = fold(&conns, &agents, 7890, &access("system_proxy"));
        assert!(!r.applicable, "看到 fake-ip 就不能再判直连");
        assert_eq!(r.direct_total, 0);
        assert!(r.note.contains("TUN 接管"), "note={}", r.note);
    }

    #[test]
    fn fold_counts_and_lists_direct() {
        let mut agents = HashMap::new();
        agents.insert(100u32, "Claude".to_string());
        let conns = vec![
            conn(100, [127, 0, 0, 1], 7890), // 代理
            conn(100, [127, 0, 0, 1], 7890), // 代理
            conn(100, [192, 168, 1, 2], 53), // 本地
            conn(100, [1, 1, 1, 1], 443),    // 直连
            conn(999, [8, 8, 8, 8], 443),    // 不是 agent，忽略
        ];
        let r = fold(&conns, &agents, 7890, &access("system_proxy"));
        assert!(r.applicable);
        assert_eq!(r.agent_conns, 4);
        assert_eq!(r.proxied, 2);
        assert_eq!(r.local, 1);
        assert_eq!(r.direct_total, 1);
        assert_eq!(r.direct[0].agent, "Claude");
        assert_eq!(r.direct[0].remote, "1.1.1.1");
        assert!(r.leaked());
        assert!(r.note.contains("1 条直连"));
    }

    #[test]
    fn fold_caps_listed_but_counts_all() {
        let mut agents = HashMap::new();
        agents.insert(1u32, "Claude".to_string());
        let conns: Vec<TcpConn> = (0..20)
            .map(|i| conn(1, [9, 9, 9, i as u8 + 1], 443))
            .collect();
        let r = fold(&conns, &agents, 7890, &access("system_proxy"));
        assert_eq!(r.direct_total, 20);
        assert_eq!(r.direct.len(), MAX_LISTED);
    }

    #[test]
    fn tun_mode_never_judges() {
        let mut agents = HashMap::new();
        agents.insert(1u32, "Claude".to_string());
        let conns = vec![conn(1, [1, 1, 1, 1], 443)];
        let r = fold(&conns, &agents, 7890, &access("tun"));
        assert!(!r.applicable);
        assert_eq!(r.direct_total, 0);
        assert!(r.note.contains("TUN"));
    }

    #[test]
    fn uncovered_and_unknown_are_not_applicable() {
        for path in ["uncovered", "unknown", "skipped"] {
            let r = fold(&[], &HashMap::new(), 7890, &access(path));
            assert!(!r.applicable, "{path} 不该判定");
        }
    }

    #[test]
    fn clean_report_says_all_proxied() {
        let mut agents = HashMap::new();
        agents.insert(7u32, "Claude".to_string());
        let conns = vec![conn(7, [127, 0, 0, 1], 7890)];
        let r = fold(&conns, &agents, 7890, &access("system_proxy"));
        assert!(!r.leaked());
        assert!(r.note.contains("全部经本地代理"));
    }

    #[test]
    fn no_connections_reports_idle() {
        let mut agents = HashMap::new();
        agents.insert(7u32, "Claude".to_string());
        let r = fold(&[], &agents, 7890, &access("system_proxy"));
        assert!(!r.leaked());
        assert!(r.note.contains("没有已建立的连接"));
    }
}
