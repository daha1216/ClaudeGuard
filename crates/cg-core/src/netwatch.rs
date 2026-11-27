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

/// Returns true if `ip` is in `198.18.0.0/15` (RFC 2544 TUN fake-ip pool used by Clash/Mihomo/sing-box/Surge).
pub fn is_fake_ip_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 198 && (o[1] == 18 || o[1] == 19)
}

/// Returns true for loopback, RFC1918, link-local, multicast, Class E/broadcast (`240.0.0.0/4`), CGNAT (`100.64.0.0/10`), and `0.0.0.0/8`.
pub fn is_local_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (o[0] == 100 && (64..=127).contains(&o[1]))
        || o[0] == 0
        || o[0] >= 240
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

fn parse_proxy_v4_endpoint(raw: &str) -> Option<(Ipv4Addr, u16)> {
    let trimmed = raw.trim();
    let rest = match trimmed.find("://") {
        Some(idx) => &trimmed[idx + 3..],
        None => trimmed,
    };
    let rest = rest.trim().trim_end_matches('/');
    let (host, port_str) = rest.split_once(':')?;
    let port = port_str.trim().parse::<u16>().ok().filter(|&p| p > 0)?;
    let host_trim = host.trim();
    let ip = if host_trim.eq_ignore_ascii_case("localhost") {
        Ipv4Addr::LOCALHOST
    } else {
        host_trim.parse::<Ipv4Addr>().ok()?
    };
    Some((ip, port))
}

fn classify_for_access(
    remote: Ipv4Addr,
    port: u16,
    proxy_port: u16,
    active_proxy: Option<(Ipv4Addr, u16)>,
    extra_loopback_ports: &[u16],
) -> RemoteKind {
    if active_proxy == Some((remote, port)) {
        return RemoteKind::Proxy;
    }
    if remote.is_loopback()
        && (port == proxy_port
            || extra_loopback_ports.contains(&port)
            || active_proxy.is_some_and(|(ip, p)| ip.is_loopback() && p == port))
    {
        return RemoteKind::Proxy;
    }
    if is_local_v4(remote) || is_fake_ip_v4(remote) {
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
    fold_with_extra_proxy_ports(conns, agents, proxy_port, &[], access, now_secs)
}

/// Folds raw ESTABLISHED TCP connections into a [`LeakReport`], honoring `access.proxy_addr`
/// (including LAN / CGNAT / remote proxy endpoints) and any additional dedicated Vault proxy ports.
pub fn fold_with_extra_proxy_ports(
    conns: &[TcpConn],
    agents: &HashMap<u32, String>,
    proxy_port: u16,
    extra_proxy_ports: &[u16],
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

    let active_proxy = access
        .proxy_addr
        .as_deref()
        .and_then(parse_proxy_v4_endpoint);
    let display_port = active_proxy.map(|(_, p)| p).unwrap_or(proxy_port);

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
        match classify_for_access(
            c.remote,
            c.port,
            proxy_port,
            active_proxy,
            extra_proxy_ports,
        ) {
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
    if fake_ip > 0 && report.direct_total == 0 {
        report.applicable = false;
        report.note = format!("检测到 TUN 接管（{fake_ip} 条 fake-ip 连接），不判定直连");
        return report;
    }
    report.note = if report.direct_total > 0 {
        format!(
            "发现 {} 条直连（未经代理端口 {}）",
            report.direct_total, display_port
        )
    } else if report.agent_conns == 0 {
        "被守护应用当前没有已建立的连接".into()
    } else if report.proxied == 0 && report.local > 0 {
        format!(
            "{} 条本地/内网连接（未命中代理端口 {}，无公网直连）",
            report.local, display_port
        )
    } else if active_proxy.is_some_and(|(ip, _)| !ip.is_loopback()) {
        format!("{} 条连接全部经配置代理转发", report.proxied)
    } else {
        format!("{} 条连接全部经本地代理", report.proxied)
    };
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excludes_tun_fake_ip_range_without_hiding_genuine_public_leaks() {
        let mut agents = HashMap::new();
        agents.insert(42, "Claude".into());
        let access = AccessEvidence {
            level: AccessLevel::SystemProxy,
            proxy_addr: Some("127.0.0.1:7890".into()),
            ..AccessEvidence::default()
        };

        // Pure fake-ip traffic (no non-fake public leak) -> treated as TUN takeover (not applicable).
        let pure_fake = vec![TcpConn {
            pid: 42,
            remote: Ipv4Addr::new(198, 18, 0, 5),
            port: 443,
        }];
        let r_fake = fold(&pure_fake, &agents, 7890, &access, 1_700_000_000);
        assert!(!r_fake.applicable);
        assert_eq!(r_fake.local, 1);
        assert_eq!(r_fake.direct_total, 0);
        assert!(r_fake.note.contains("TUN 接管"));

        // Fake-ip alongside a genuine public TCP leak MUST preserve the genuine leak!
        let mixed = vec![
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
        let r_mixed = fold(&mixed, &agents, 7890, &access, 1_700_000_000);
        assert!(r_mixed.applicable);
        assert_eq!(r_mixed.local, 1);
        assert_eq!(r_mixed.direct_total, 1);
        assert_eq!(r_mixed.direct[0].remote, "198.51.100.98");
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

    #[test]
    fn treats_28_slash_8_as_public_and_excludes_reserved_class_e_v4() {
        assert!(!is_fake_ip_v4(Ipv4Addr::new(28, 0, 0, 1)));
        assert!(!is_fake_ip_v4(Ipv4Addr::new(28, 255, 255, 254)));
        assert!(is_fake_ip_v4(Ipv4Addr::new(198, 18, 0, 1)));
        assert!(is_fake_ip_v4(Ipv4Addr::new(198, 19, 255, 254)));
        assert!(is_local_v4(Ipv4Addr::new(240, 0, 0, 1)));
        assert!(is_local_v4(Ipv4Addr::new(255, 255, 255, 255)));
        assert_eq!(
            classify(Ipv4Addr::new(240, 0, 0, 1), 443, 7890),
            RemoteKind::Local
        );
        assert_eq!(
            classify(Ipv4Addr::new(28, 0, 1, 9), 443, 7890),
            RemoteKind::Public
        );

        let mut agents = HashMap::new();
        agents.insert(7, "Claude".into());
        let conns = vec![TcpConn {
            pid: 7,
            remote: Ipv4Addr::new(28, 0, 1, 9),
            port: 443,
        }];
        let access = AccessEvidence {
            level: AccessLevel::SystemProxy,
            proxy_addr: Some("127.0.0.1:7890".into()),
            ..AccessEvidence::default()
        };
        let report = fold(&conns, &agents, 7890, &access, 500);
        assert!(report.applicable);
        assert_eq!(report.direct_total, 1);
        assert_eq!(report.direct[0].remote, "28.0.1.9");

        // LAN proxy endpoint (e.g. 192.168.1.2:7897) and extra Vault ports count as proxied, not false leaks.
        let lan_access = AccessEvidence {
            level: AccessLevel::SystemProxy,
            proxy_addr: Some("192.168.1.2:7897".into()),
            ..AccessEvidence::default()
        };
        let lan_conns = vec![
            TcpConn {
                pid: 7,
                remote: Ipv4Addr::new(192, 168, 1, 2),
                port: 7897,
            },
            TcpConn {
                pid: 7,
                remote: Ipv4Addr::LOCALHOST,
                port: 17890,
            },
        ];
        let lan_report =
            fold_with_extra_proxy_ports(&lan_conns, &agents, 7890, &[17890], &lan_access, 600);
        assert!(!lan_report.leaked());
        assert_eq!(lan_report.proxied, 2);
    }
}
