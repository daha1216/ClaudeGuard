//! Pure direct-connection leak classifier excluding loopback, RFC1918, and `198.18.0.0/15` TUN fake-ip.

use cg_protocol::{AccessEvidence, AccessLevel, LeakConn, LeakReport};
use std::collections::HashMap;
use std::net::Ipv4Addr;

pub const MAX_LISTED: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteKind {
    Proxy,
    Local,
    Public,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpConn {
    pub pid: u32,
    pub remote: Ipv4Addr,
    pub port: u16,
}

/// Returns true if `ip` is in `198.18.0.0/15` (RFC 2544 TUN fake-ip pool used by Clash/Mihomo/sing-box).
pub fn is_fake_ip_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 198 && (o[1] == 18 || o[1] == 19)
}

/// Returns true for loopback, RFC1918, link-local, CGNAT (`100.64.0.0/10`), and `0.0.0.0/8`.
pub fn is_local_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || (o[0] == 100 && (64..=127).contains(&o[1]))
        || o[0] == 0
}

pub fn classify(remote: Ipv4Addr, port: u16, proxy_port: u16) -> RemoteKind {
    if remote.is_loopback() && port == proxy_port {
        RemoteKind::Proxy
    } else if is_local_v4(remote) || is_fake_ip_v4(remote) {
        RemoteKind::Local
    } else {
        RemoteKind::Public
    }
}

/// Folds raw ESTABLISHED TCP connections and guarded PID map into a [`LeakReport`].
pub fn fold(
    conns: &[TcpConn],
    agents: &HashMap<u32, String>,
    proxy_port: u16,
    access: &AccessEvidence,
    now_secs: u64,
) -> LeakReport {
    let mode = access.path_tag().to_string();
    if access.level != AccessLevel::SystemProxy {
        let note = match access.level {
            AccessLevel::Tun => {
                "TUN 模式：对端是公网地址属正常（流量被虚拟网卡接管），不做直连判定"
            }
            AccessLevel::Uncovered => "未接入代理：应用本来就在直连，直连判定无意义",
            AccessLevel::Unknown => "接入路径无法确认：不猜测，不做直连判定",
            AccessLevel::SystemProxy => unreachable!(),
        };
        return LeakReport::not_applicable(&mode, note, now_secs);
    }

    let mut report = LeakReport {
        applicable: true,
        mode,
        checked_at: now_secs,
        agent_conns: 0,
        proxied: 0,
        local: 0,
        direct: Vec::new(),
        direct_total: 0,
        note: String::new(),
    };
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
            RemoteKind::Proxy => report.proxied += 1,
            RemoteKind::Local => report.local += 1,
            RemoteKind::Public => {
                report.direct_total += 1;
                if report.direct.len() < MAX_LISTED {
                    let low = agent.to_ascii_lowercase();
                    let is_mcp = low.contains("mcp")
                        || low.contains("cowork")
                        || low.contains("uvx")
                        || low.contains("npx")
                        || low.contains("node")
                        || low.contains("python")
                        || low.contains("deno");
                    report.direct.push(LeakConn {
                        pid: c.pid,
                        agent: agent.clone(),
                        remote: c.remote.to_string(),
                        port: c.port,
                        is_mcp,
                    });
                }
            }
        }
    }
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
        "被守护应用当前没有已建立的连接".into()
    } else {
        format!("{} 条连接全部经本地代理", report.proxied)
    };
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excludes_tun_fake_ip_range() {
        let mut agents = HashMap::new();
        agents.insert(42, "Claude".into());
        let conns = vec![
            TcpConn {
                pid: 42,
                remote: Ipv4Addr::new(198, 18, 0, 5),
                port: 443,
            },
            TcpConn {
                pid: 42,
                remote: Ipv4Addr::new(198, 51, 100, 98),
                port: 443,
            },
        ];
        let access = AccessEvidence {
            level: AccessLevel::SystemProxy,
            proxy_addr: Some("127.0.0.1:7890".into()),
            ..AccessEvidence::default()
        };
        let report = fold(&conns, &agents, 7890, &access, 1_700_000_000);
        assert!(!report.applicable);
        assert_eq!(report.direct_total, 0);
        assert!(report.note.contains("TUN 接管"));
    }

    #[test]
    fn detects_direct_leak_in_system_proxy_mode() {
        let mut agents = HashMap::new();
        agents.insert(42, "Claude".into());
        let conns = vec![
            TcpConn {
                pid: 42,
                remote: Ipv4Addr::LOCALHOST,
                port: 7890,
            },
            TcpConn {
                pid: 42,
                remote: Ipv4Addr::new(198, 51, 100, 98),
                port: 443,
            },
        ];
        let access = AccessEvidence {
            level: AccessLevel::SystemProxy,
            proxy_addr: Some("127.0.0.1:7890".into()),
            ..AccessEvidence::default()
        };
        let report = fold(&conns, &agents, 7890, &access, 1_700_000_000);
        assert!(report.applicable);
        assert!(report.leaked());
        assert_eq!(report.proxied, 1);
        assert_eq!(report.direct_total, 1);
        assert_eq!(report.direct[0].remote, "198.51.100.98");
    }

    #[test]
    fn non_proxy_modes_not_applicable_and_direct_list_capped() {
        let mut agents = HashMap::new();
        agents.insert(1, "Claude".into());
        for lvl in [
            AccessLevel::Tun,
            AccessLevel::Uncovered,
            AccessLevel::Unknown,
        ] {
            let acc = AccessEvidence {
                level: lvl,
                ..AccessEvidence::default()
            };
            let r = fold(
                &[TcpConn {
                    pid: 1,
                    remote: Ipv4Addr::new(198, 51, 100, 98),
                    port: 443,
                }],
                &agents,
                7890,
                &acc,
                100,
            );
            assert!(!r.applicable);
            assert_eq!(r.direct_total, 0);
        }

        let conns: Vec<TcpConn> = (1..=15)
            .map(|i| TcpConn {
                pid: 1,
                remote: Ipv4Addr::new(198, 51, 100, i),
                port: 443,
            })
            .collect();
        let sys_proxy = AccessEvidence {
            level: AccessLevel::SystemProxy,
            proxy_addr: Some("127.0.0.1:7890".into()),
            ..AccessEvidence::default()
        };
        let r = fold(&conns, &agents, 7890, &sys_proxy, 100);
        assert_eq!(r.direct_total, 15);
        assert_eq!(r.direct.len(), MAX_LISTED);
    }
}
