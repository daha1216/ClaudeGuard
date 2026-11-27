//! M3: Zero-dependency native RFC 5389 UDP STUN WebRTC exposure probe.
//!
//! Sends a standard 20-byte RFC 5389 `Binding Request` over an ephemeral UDP socket to detect
//! whether direct outbound UDP exposes a public server-reflexive IP that diverges from the
//! configured proxy egress (WebRTC / STUN leak).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use cg_protocol::StunLeakReport;

const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_SUCCESS: u16 = 0x0101;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

const DEFAULT_STUN_TIMEOUT_MS: u64 = 1200;
const MIN_STUN_TIMEOUT_MS: u64 = 200;
const MAX_STUN_TIMEOUT_MS: u64 = 5000;

/// Public RFC 5389 STUN servers probed sequentially within the bounded timeout budget.
pub const STUN_ENDPOINTS: &[&str] = &["stun.cloudflare.com:3478", "stun.l.google.com:19302"];

/// Outcome of a single direct UDP STUN Binding Request probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StunProbeOutcome {
    /// Direct UDP was blocked (e.g. by WFP/firewall) or timed out without exposing a reflexive IP.
    BlockedOrUnreachable,
    /// Direct UDP reached a STUN responder and received a server-reflexive address.
    ReflexiveIp(IpAddr),
}

/// Construct a standard 20-byte RFC 5389 STUN `Binding Request` packet with zero attributes.
pub fn encode_binding_request(tx_id: [u8; 12]) -> [u8; 20] {
    let mut pkt = [0u8; 20];
    pkt[0..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    pkt[2..4].copy_from_slice(&0u16.to_be_bytes()); // Message Length = 0
    pkt[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    pkt[8..20].copy_from_slice(&tx_id);
    pkt
}

/// Parse an RFC 5389 STUN `Binding Success Response`, preferring `XOR-MAPPED-ADDRESS` (IPv4 & IPv6)
/// and falling back to `MAPPED-ADDRESS` when no XOR attribute is present.
pub fn decode_binding_response(buf: &[u8], expected_tx_id: &[u8; 12]) -> Option<IpAddr> {
    if buf.len() < 20 {
        return None;
    }
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let end = 20usize.checked_add(msg_len)?;
    if msg_type != STUN_BINDING_SUCCESS
        || cookie != STUN_MAGIC_COOKIE
        || &buf[8..20] != expected_tx_id
        || buf.len() < end
    {
        return None;
    }

    let mut fallback_mapped: Option<IpAddr> = None;
    let mut offset = 20usize;

    while offset + 4 <= end {
        let attr_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let attr_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
        offset += 4;
        let val_end = offset.checked_add(attr_len)?;
        if val_end > end {
            break;
        }
        let val = &buf[offset..val_end];

        if attr_type == ATTR_XOR_MAPPED_ADDRESS && val.len() >= 8 {
            let family = val[1];
            if family == 0x01 {
                let x_addr = u32::from_be_bytes([val[4], val[5], val[6], val[7]]);
                return Some(IpAddr::V4(Ipv4Addr::from(x_addr ^ STUN_MAGIC_COOKIE)));
            } else if family == 0x02 && val.len() >= 20 {
                let mut mask = [0u8; 16];
                mask[0..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
                mask[4..16].copy_from_slice(expected_tx_id);
                let mut raw_v6 = [0u8; 16];
                for i in 0..16 {
                    raw_v6[i] = val[4 + i] ^ mask[i];
                }
                return Some(IpAddr::V6(Ipv6Addr::from(raw_v6)));
            }
        } else if attr_type == ATTR_MAPPED_ADDRESS && val.len() >= 8 {
            let family = val[1];
            if family == 0x01 {
                fallback_mapped = Some(IpAddr::V4(Ipv4Addr::new(val[4], val[5], val[6], val[7])));
            } else if family == 0x02 && val.len() >= 20 {
                let mut raw_v6 = [0u8; 16];
                raw_v6.copy_from_slice(&val[4..20]);
                fallback_mapped = Some(IpAddr::V6(Ipv6Addr::from(raw_v6)));
            }
        }

        // RFC 5389 attributes are padded to 4-byte boundaries.
        let padded = (attr_len.checked_add(3)?) & !3usize;
        offset = match offset.checked_add(padded) {
            Some(next) => next,
            None => break,
        };
    }

    fallback_mapped
}

fn resolve_endpoint_dual_stack_bounded(
    endpoint: &str,
    timeout: Duration,
) -> (Option<std::net::SocketAddr>, Option<std::net::SocketAddr>) {
    if let Ok(sa) = endpoint.parse::<std::net::SocketAddr>() {
        return if sa.is_ipv4() {
            (Some(sa), None)
        } else {
            (None, Some(sa))
        };
    }
    if timeout.is_zero() {
        return (None, None);
    }
    let owned = endpoint.to_string();
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut v4 = None;
        let mut v6 = None;
        if let Ok(iter) = owned.to_socket_addrs() {
            for addr in iter {
                if addr.is_ipv4() && v4.is_none() {
                    v4 = Some(addr);
                } else if addr.is_ipv6() && v6.is_none() {
                    v6 = Some(addr);
                }
                if v4.is_some() && v6.is_some() {
                    break;
                }
            }
        }
        let _ = tx.send((v4, v6));
    });
    rx.recv_timeout(timeout).ok().unwrap_or((None, None))
}

fn probe_single_stun_socket(
    sock: &UdpSocket,
    target: std::net::SocketAddr,
    req: &[u8; 20],
    tx_id: &[u8; 12],
    io_budget: Duration,
) -> Option<IpAddr> {
    let _ = sock.set_read_timeout(Some(io_budget));
    let _ = sock.set_write_timeout(Some(io_budget));
    sock.send_to(req, target).ok()?;
    let mut resp = [0u8; 512];
    let (n, _) = sock.recv_from(&mut resp).ok()?;
    decode_binding_response(&resp[..n], tx_id)
}

/// Probes both IPv4 (`0.0.0.0:0`) and IPv6 (`[::]:0`) STUN endpoints within a single bounded
/// `timeout` budget so domestic dual-stack IPv6 WebRTC leaks are caught even when IPv4 is clean.
pub fn probe_stun_dual_stack_with_timeout(
    tx_seed: u64,
    timeout: Duration,
) -> (Option<IpAddr>, Option<IpAddr>) {
    let bounded_total = timeout.clamp(
        Duration::from_millis(MIN_STUN_TIMEOUT_MS),
        Duration::from_millis(MAX_STUN_TIMEOUT_MS),
    );
    let deadline = std::time::Instant::now() + bounded_total;

    let mut tx_v4 = [0u8; 12];
    tx_v4[0..8].copy_from_slice(&tx_seed.to_le_bytes());
    tx_v4[8..12].copy_from_slice(&0xC6_05_53_89u32.to_be_bytes());
    let req_v4 = encode_binding_request(tx_v4);

    let mut tx_v6 = tx_v4;
    tx_v6[11] ^= 0x66;
    let req_v6 = encode_binding_request(tx_v6);

    let sock_v4 = UdpSocket::bind("0.0.0.0:0").ok();
    let sock_v6 = UdpSocket::bind("[::]:0").ok();
    if sock_v4.is_none() && sock_v6.is_none() {
        return (None, None);
    }

    let mut found_v4: Option<IpAddr> = None;
    let mut found_v6: Option<IpAddr> = None;

    let total_eps = STUN_ENDPOINTS.len().max(1);
    for (idx, endpoint) in STUN_ENDPOINTS.iter().enumerate() {
        if found_v4.is_some() && (found_v6.is_some() || sock_v6.is_none()) {
            break;
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let eps_left = (total_eps - idx).max(1) as u32;
        let step_budget = (remaining / eps_left)
            .max(Duration::from_millis(100))
            .min(remaining);

        let (target_v4, target_v6) = resolve_endpoint_dual_stack_bounded(endpoint, step_budget);

        let after_dns = deadline.saturating_duration_since(std::time::Instant::now());
        if after_dns.is_zero() {
            break;
        }
        let io_budget = (after_dns / (eps_left * 2).max(1))
            .max(Duration::from_millis(80))
            .min(after_dns);

        if found_v4.is_none() {
            if let (Some(ref s4), Some(t4)) = (&sock_v4, target_v4) {
                found_v4 = probe_single_stun_socket(s4, t4, &req_v4, &tx_v4, io_budget);
            }
        }
        if found_v6.is_none() {
            let rem6 = deadline.saturating_duration_since(std::time::Instant::now());
            if !rem6.is_zero() {
                let io6 = io_budget.min(rem6);
                if let (Some(ref s6), Some(t6)) = (&sock_v6, target_v6) {
                    found_v6 = probe_single_stun_socket(s6, t6, &req_v6, &tx_v6, io6);
                }
            }
        }
    }

    (found_v4, found_v6)
}

/// Execute a single non-intrusive UDP STUN reflection probe within a strict overall `timeout`
/// wall-clock budget (including bounded dual-stack DNS resolution across all fallback endpoints).
pub fn probe_stun_reflexive_ip_with_timeout(tx_seed: u64, timeout: Duration) -> StunProbeOutcome {
    let (v4, v6) = probe_stun_dual_stack_with_timeout(tx_seed, timeout);
    match v4.or(v6) {
        Some(ip) => StunProbeOutcome::ReflexiveIp(ip),
        None => StunProbeOutcome::BlockedOrUnreachable,
    }
}

/// Execute a single non-intrusive UDP STUN reflection probe (1.2s per-endpoint timeout).
pub fn probe_stun_reflexive_ip(tx_seed: u64) -> StunProbeOutcome {
    probe_stun_reflexive_ip_with_timeout(tx_seed, Duration::from_millis(DEFAULT_STUN_TIMEOUT_MS))
}

fn ip_matches_expected(observed: IpAddr, expected_raw: &str) -> bool {
    let trimmed = expected_raw.trim();
    if trimmed.is_empty() {
        return false;
    }
    let canon_obs = crate::netwatch_win::canonical_ip(observed);
    if let Ok(exp_ip) = trimmed.parse::<IpAddr>() {
        return canon_obs == crate::netwatch_win::canonical_ip(exp_ip);
    }
    canon_obs.to_string().eq_ignore_ascii_case(trimmed)
}

/// Pure classifier translating a raw `StunProbeOutcome` and optional expected proxy egress IP
/// into a protocol `StunLeakReport`.
pub fn evaluate_stun_outcome(
    outcome: StunProbeOutcome,
    expected_proxy_ip: Option<&str>,
    now_secs: u64,
) -> StunLeakReport {
    match outcome {
        StunProbeOutcome::BlockedOrUnreachable => StunLeakReport {
            checked_at: now_secs,
            stun_reachable_direct: false,
            leaked: false,
            reflexive_ip: None,
            reflexive_country: None,
            summary: "直连 UDP STUN 已被阻断或不可达，未检测到 WebRTC 真实 IP 暴露".to_string(),
        },
        StunProbeOutcome::ReflexiveIp(raw_ip) => {
            let ip = crate::netwatch_win::canonical_ip(raw_ip);
            if crate::netwatch_win::is_local_addr(ip) {
                return StunLeakReport {
                    checked_at: now_secs,
                    stun_reachable_direct: true,
                    leaked: false,
                    reflexive_ip: Some(ip.to_string()),
                    reflexive_country: None,
                    summary: "STUN 仅返回本地/内网保留地址，未暴露公网宽带出口".to_string(),
                };
            }

            let expected = expected_proxy_ip.map(str::trim).filter(|s| !s.is_empty());
            match expected {
                Some(exp) if ip_matches_expected(ip, exp) => StunLeakReport {
                    checked_at: now_secs,
                    stun_reachable_direct: true,
                    leaked: false,
                    reflexive_ip: Some(ip.to_string()),
                    reflexive_country: None,
                    summary: "UDP STUN 反射出口与当前代理出口一致（TUN 全隧道覆盖），无真实 IP 泄漏"
                        .to_string(),
                },
                Some(_) => StunLeakReport {
                    checked_at: now_secs,
                    stun_reachable_direct: true,
                    leaked: true,
                    reflexive_ip: Some(ip.to_string()),
                    reflexive_country: None,
                    summary:
                        "检测到直连 UDP STUN 反射公网 IP 与当前代理出口不一致，存在 WebRTC 真实宽带暴露风险"
                            .to_string(),
                },
                None => StunLeakReport {
                    checked_at: now_secs,
                    stun_reachable_direct: true,
                    leaked: true,
                    reflexive_ip: Some(ip.to_string()),
                    reflexive_country: None,
                    summary:
                        "直连 UDP STUN 可达并暴露公网反射地址，建议开启 WFP 防护或 Chromium WebRTC 策略锁"
                            .to_string(),
                },
            }
        }
    }
}

/// Probe direct dual-stack (IPv4 + IPv6) UDP STUN reachability and evaluate whether WebRTC can
/// expose a real ISP IPv4 or native carrier IPv6 diverging from `expected_proxy_ip`.
pub fn probe_webrtc_stun_leak(
    expected_proxy_ip: Option<&str>,
    timeout_ms: u64,
    now_secs: u64,
) -> StunLeakReport {
    let clamped = timeout_ms.clamp(MIN_STUN_TIMEOUT_MS, MAX_STUN_TIMEOUT_MS);
    let seed = now_secs ^ 0x5389_A442_0000_0001;
    let (v4_opt, v6_opt) = probe_stun_dual_stack_with_timeout(seed, Duration::from_millis(clamped));

    if let Some(v4) = v4_opt {
        let rep4 = evaluate_stun_outcome(
            StunProbeOutcome::ReflexiveIp(v4),
            expected_proxy_ip,
            now_secs,
        );
        if rep4.leaked {
            return rep4;
        }
        // IPv4 was clean/TUN-covered — check whether native IPv6 bypassed the IPv4 tunnel!
        if let Some(v6) = v6_opt {
            let rep6 = evaluate_stun_outcome(
                StunProbeOutcome::ReflexiveIp(v6),
                expected_proxy_ip,
                now_secs,
            );
            if rep6.leaked {
                return rep6;
            }
        }
        return rep4;
    }

    match v6_opt {
        Some(v6) => evaluate_stun_outcome(
            StunProbeOutcome::ReflexiveIp(v6),
            expected_proxy_ip,
            now_secs,
        ),
        None => evaluate_stun_outcome(
            StunProbeOutcome::BlockedOrUnreachable,
            expected_proxy_ip,
            now_secs,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_stun_response(tx_id: [u8; 12], attrs: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(20 + attrs.len());
        out.extend_from_slice(&STUN_BINDING_SUCCESS.to_be_bytes());
        out.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        out.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        out.extend_from_slice(&tx_id);
        out.extend_from_slice(attrs);
        out
    }

    fn build_xor_mapped_v4_attr(ip: Ipv4Addr, port: u16) -> Vec<u8> {
        let mut attr = Vec::with_capacity(12);
        attr.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        attr.extend_from_slice(&8u16.to_be_bytes());
        attr.push(0x00); // reserved
        attr.push(0x01); // IPv4
        let x_port = port ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
        attr.extend_from_slice(&x_port.to_be_bytes());
        let x_ip = u32::from(ip) ^ STUN_MAGIC_COOKIE;
        attr.extend_from_slice(&x_ip.to_be_bytes());
        attr
    }

    fn build_xor_mapped_v6_attr(ip: Ipv6Addr, port: u16, tx_id: &[u8; 12]) -> Vec<u8> {
        let mut attr = Vec::with_capacity(24);
        attr.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        attr.extend_from_slice(&20u16.to_be_bytes());
        attr.push(0x00); // reserved
        attr.push(0x02); // IPv6
        let x_port = port ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
        attr.extend_from_slice(&x_port.to_be_bytes());
        let mut mask = [0u8; 16];
        mask[0..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        mask[4..16].copy_from_slice(tx_id);
        let octets = ip.octets();
        for i in 0..16 {
            attr.push(octets[i] ^ mask[i]);
        }
        attr
    }

    #[test]
    fn encodes_valid_20_byte_rfc5389_binding_request() {
        let tx_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let pkt = encode_binding_request(tx_id);
        assert_eq!(pkt.len(), 20);
        assert_eq!(&pkt[0..2], &[0x00, 0x01]);
        assert_eq!(&pkt[2..4], &[0x00, 0x00]);
        assert_eq!(&pkt[4..8], &[0x21, 0x12, 0xA4, 0x42]);
        assert_eq!(&pkt[8..20], &tx_id);
    }

    #[test]
    fn decodes_xor_mapped_ipv4_and_ipv6_and_padded_fallback() {
        let tx_id = [0xAA, 0xBB, 0xCC, 0xDD, 1, 2, 3, 4, 5, 6, 7, 8];

        // 1. IPv4 XOR-MAPPED-ADDRESS
        let v4 = Ipv4Addr::new(203, 0, 113, 42);
        let resp_v4 = build_stun_response(tx_id, &build_xor_mapped_v4_attr(v4, 54321));
        assert_eq!(
            decode_binding_response(&resp_v4, &tx_id),
            Some(IpAddr::V4(v4))
        );

        // 2. IPv6 XOR-MAPPED-ADDRESS
        let v6: Ipv6Addr = "2001:db8:85a3::8a2e:370:7334".parse().unwrap();
        let resp_v6 = build_stun_response(tx_id, &build_xor_mapped_v6_attr(v6, 44321, &tx_id));
        assert_eq!(
            decode_binding_response(&resp_v6, &tx_id),
            Some(IpAddr::V6(v6))
        );

        // 3. Odd-length unknown attribute (5 bytes + 3 padding) followed by MAPPED-ADDRESS fallback
        let mut attrs = Vec::new();
        attrs.extend_from_slice(&0x8022u16.to_be_bytes()); // SOFTWARE
        attrs.extend_from_slice(&5u16.to_be_bytes());
        attrs.extend_from_slice(b"HELLO");
        attrs.extend_from_slice(&[0, 0, 0]); // RFC 5389 4-byte padding
        attrs.extend_from_slice(&ATTR_MAPPED_ADDRESS.to_be_bytes());
        attrs.extend_from_slice(&8u16.to_be_bytes());
        attrs.extend_from_slice(&[0x00, 0x01, 0x12, 0x34, 198, 51, 100, 7]);
        let resp_fallback = build_stun_response(tx_id, &attrs);
        assert_eq!(
            decode_binding_response(&resp_fallback, &tx_id),
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)))
        );
    }

    #[test]
    fn rejects_malformed_or_mismatched_stun_packets() {
        let tx_id = [9u8; 12];
        let v4 = Ipv4Addr::new(1, 2, 3, 4);
        let valid = build_stun_response(tx_id, &build_xor_mapped_v4_attr(v4, 1000));

        // Too short
        assert!(decode_binding_response(&valid[..19], &tx_id).is_none());
        // Wrong tx_id
        assert!(decode_binding_response(&valid, &[8u8; 12]).is_none());
        // Wrong magic cookie
        let mut bad_cookie = valid.clone();
        bad_cookie[4] ^= 0xFF;
        assert!(decode_binding_response(&bad_cookie, &tx_id).is_none());
        // Wrong message type
        let mut bad_type = valid.clone();
        bad_type[0] = 0x01;
        bad_type[1] = 0x11; // Error response
        assert!(decode_binding_response(&bad_type, &tx_id).is_none());
        // Truncated payload shorter than declared msg_len
        assert!(decode_binding_response(&valid[..valid.len() - 1], &tx_id).is_none());
    }

    #[test]
    fn evaluates_stun_leak_outcomes_accurately() {
        let blocked = evaluate_stun_outcome(
            StunProbeOutcome::BlockedOrUnreachable,
            Some("68.105.28.44"),
            1000,
        );
        assert!(!blocked.stun_reachable_direct);
        assert!(!blocked.leaked);
        assert!(blocked.reflexive_ip.is_none());

        // Matching proxy IP -> TUN covers UDP -> no leak
        let matched = evaluate_stun_outcome(
            StunProbeOutcome::ReflexiveIp(IpAddr::V4(Ipv4Addr::new(68, 105, 28, 44))),
            Some("68.105.28.44"),
            1001,
        );
        assert!(matched.stun_reachable_direct);
        assert!(!matched.leaked);
        assert_eq!(matched.reflexive_ip.as_deref(), Some("68.105.28.44"));

        // IPv4-mapped IPv6 matches IPv4 proxy IP -> no leak
        let v4_mapped: IpAddr = "::ffff:68.105.28.44".parse().unwrap();
        let matched_v6 = evaluate_stun_outcome(
            StunProbeOutcome::ReflexiveIp(v4_mapped),
            Some("68.105.28.44"),
            1002,
        );
        assert!(!matched_v6.leaked);

        // Divergent public IP -> REAL WebRTC STUN leak!
        let leaked = evaluate_stun_outcome(
            StunProbeOutcome::ReflexiveIp(IpAddr::V4(Ipv4Addr::new(114, 242, 10, 5))),
            Some("68.105.28.44"),
            1003,
        );
        assert!(leaked.stun_reachable_direct);
        assert!(leaked.leaked);
        assert_eq!(leaked.reflexive_ip.as_deref(), Some("114.242.10.5"));

        // Local/RFC1918 IP is never flagged as public ISP leak
        let local = evaluate_stun_outcome(
            StunProbeOutcome::ReflexiveIp(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
            Some("68.105.28.44"),
            1004,
        );
        assert!(!local.leaked);
    }
}
