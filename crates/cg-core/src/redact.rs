//! Screenshot/UI IP masking (`198.51.100.98` -> `198.51.*.*`) and notification PII redaction.

use cg_protocol::GuardSnapshot;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Redaction placeholder used in notification bodies when `include_egress = false`.
pub const REDACTED: &str = "已隐藏";

const REGION_NAMES_ZH: [&str; 25] = [
    "美国",
    "日本",
    "新加坡",
    "香港",
    "台湾",
    "韩国",
    "英国",
    "德国",
    "法国",
    "加拿大",
    "澳大利亚",
    "荷兰",
    "俄罗斯",
    "印度",
    "巴西",
    "土耳其",
    "阿联酋",
    "瑞士",
    "瑞典",
    "意大利",
    "西班牙",
    "中国",
    "澳门",
    "越南",
    "泰国",
];

/// Masks an IP address for screenshot/UI privacy (`198.51.100.98` -> `198.51.*.*`, IPv6 -> `XXXX:XXXX:*:*`).
pub fn mask_ip(raw: &str) -> String {
    let trimmed = raw.trim();
    match trimmed.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => mask_v4(v4),
        Ok(IpAddr::V6(v6)) => mask_v6(v6),
        Err(_) => trimmed.to_string(),
    }
}

fn mask_v4(v4: Ipv4Addr) -> String {
    let [a, b, _, _] = v4.octets();
    format!("{a}.{b}.*.*")
}

fn mask_v6(v6: Ipv6Addr) -> String {
    let seg = v6.segments();
    format!("{:x}:{:x}:*:*", seg[0], seg[1])
}

/// Replaces IPv4 addresses inside UI/log strings with masked `a.b.*.*` form.
pub fn mask_text_ips(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i].is_ascii_digit() {
            let start = i;
            let mut j = i;
            let mut dots = 0usize;
            while j < chars.len() {
                if chars[j].is_ascii_digit() {
                    j += 1;
                } else if chars[j] == '.' {
                    dots += 1;
                    j += 1;
                } else {
                    break;
                }
            }
            let cand: String = chars[start..j].iter().collect();
            if dots == 3
                && let Ok(v4) = cand.parse::<Ipv4Addr>()
            {
                out.push_str(&mask_v4(v4));
                i = j;
                continue;
            }
            out.extend(chars[start..j].iter());
            i = j;
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Returns a screenshot-safe copy of [`GuardSnapshot`] with egress and allowlist IPs masked.
pub fn mask_snapshot(snapshot: &GuardSnapshot) -> GuardSnapshot {
    let mut out = snapshot.clone();
    for target in &mut out.targets {
        if let Some(ip) = target.ip.as_deref() {
            target.ip = Some(mask_ip(ip));
        }
        target.expect_ips = target
            .expect_ips
            .iter()
            .map(|ip| mask_text_ips(ip))
            .collect();
        if let Some(rule) = target.matched_rule.as_deref() {
            target.matched_rule = Some(mask_text_ips(rule));
        }
        target.reason = mask_text_ips(&target.reason);
    }
    for target in &mut out.config.targets {
        target.expect_ips = target
            .expect_ips
            .iter()
            .map(|ip| mask_text_ips(ip))
            .collect();
    }
    for conn in &mut out.leak.direct {
        conn.remote = mask_ip(&conn.remote);
    }
    if let Some(trip) = &mut out.tripped {
        trip.reason = mask_text_ips(&trip.reason);
        trip.expected_summary = mask_text_ips(&trip.expected_summary);
        trip.observed_summary = mask_text_ips(&trip.observed_summary);
    }
    out.launch_error = mask_text_ips(&out.launch_error);
    for toast in &mut out.recent_toasts {
        toast.title = mask_text_ips(&toast.title);
        toast.body = mask_text_ips(&toast.body);
    }
    for entry in &mut out.recent_logs {
        entry.message = mask_text_ips(&entry.message);
    }
    out
}

/// Redacts egress PII (IPv4, IPv6, region codes, localized country names) from notification text
/// unless `include_egress` is explicitly `true` (`CONTRACT-v3.10.md` D5 / R14).
pub fn redact(text: &str, include_egress: bool) -> String {
    if include_egress {
        return text.to_string();
    }
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    while i < chars.len() {
        if let Some(skip) = region_marker_at(&chars, i) {
            out.push_str(REDACTED);
            i += skip;
            continue;
        }
        if let Some(skip) = ipv6_token_at(&chars, i) {
            out.push_str(REDACTED);
            i += skip;
            continue;
        }
        if chars[i].is_ascii_digit() {
            let start = i;
            let mut j = i;
            let mut dots = 0usize;
            while j < chars.len() {
                if chars[j].is_ascii_digit() {
                    j += 1;
                } else if chars[j] == '.' {
                    dots += 1;
                    j += 1;
                } else {
                    break;
                }
            }
            let cand: String = chars[start..j].iter().collect();
            if dots == 3 && cand.parse::<Ipv4Addr>().is_ok() {
                out.push_str(REDACTED);
                i = j;
                continue;
            }
            out.extend(chars[start..j].iter());
            i = j;
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    scrub_region_names(&out)
}

fn ipv6_token_at(chars: &[char], i: usize) -> Option<usize> {
    if !chars[i].is_ascii_hexdigit() && chars[i] != ':' {
        return None;
    }
    if i > 0 && chars[i - 1].is_ascii_alphanumeric() {
        return None;
    }
    let mut j = i;
    let mut colons = 0usize;
    while j < chars.len() && (chars[j].is_ascii_hexdigit() || chars[j] == ':') {
        if chars[j] == ':' {
            colons += 1;
        }
        j += 1;
    }
    if colons < 2 {
        return None;
    }
    let cand: String = chars[i..j].iter().collect();
    if cand.parse::<Ipv6Addr>().is_ok() {
        Some(j - i)
    } else {
        None
    }
}

fn region_marker_at(chars: &[char], i: usize) -> Option<usize> {
    let a = *chars.get(i)?;
    let b = *chars.get(i + 1)?;
    if !(a.is_ascii_uppercase() && b.is_ascii_uppercase()) {
        return None;
    }
    if chars.get(i + 2).is_some_and(char::is_ascii_alphanumeric) {
        return None;
    }
    let prev = i.checked_sub(1).and_then(|p| chars.get(p)).copied()?;
    let is_sep = prev.is_whitespace()
        || matches!(
            prev,
            '·' | '（' | '(' | '：' | ':' | '=' | ',' | '，' | '、' | '/' | '-' | '|'
        );
    if is_sep { Some(2) } else { None }
}

fn scrub_region_names(text: &str) -> String {
    let mut out = text.to_string();
    for name in REGION_NAMES_ZH {
        if out.contains(name) {
            out = out.replace(name, REDACTED);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_ipv4_and_ipv6_for_ui_screenshots() {
        assert_eq!(mask_ip("198.51.100.98"), "198.51.*.*");
        assert_eq!(mask_ip("203.0.113.45"), "203.0.*.*");
        assert_eq!(mask_ip("2001:db8:85a3::1"), "2001:db8:*:*");
        assert_eq!(
            mask_text_ips("出口 198.51.100.98（美国）不在白名单，v4.0.0"),
            "出口 198.51.*.*（美国）不在白名单，v4.0.0"
        );
    }

    #[test]
    fn redacts_egress_pii_by_default_and_keeps_when_enabled() {
        let msg = "出口 198.51.100.98（美国）· US 不在白名单，HTTP 500";
        let redacted = redact(msg, false);
        assert!(!redacted.contains("198.51.100.98"));
        assert!(!redacted.contains("美国"));
        assert!(!redacted.contains("US"));
        assert!(redacted.contains(REDACTED));
        assert!(redacted.contains("HTTP 500"));

        assert_eq!(redact(msg, true), msg);

        let v6 = redact("出口 2001:db8::1 异常", false);
        assert!(!v6.contains("2001:db8::1"));
        assert!(v6.contains(REDACTED));
    }

    #[test]
    fn ordinary_uppercase_words_and_semver_preserved_and_snapshot_masked() {
        assert_eq!(
            redact("OK API HTTP 500 版本 4.0.0", false),
            "OK API HTTP 500 版本 4.0.0"
        );

        let mut snap = GuardSnapshot::default();
        snap.targets.push(cg_protocol::TargetStatus {
            id: "claude".into(),
            name: "Claude".into(),
            builtin: true,
            state: cg_protocol::TargetState::Fail,
            anchor_url: "https://claude.ai/cdn-cgi/trace".into(),
            anchor_kind: cg_protocol::AnchorKind::Auto,
            expect_ips: vec!["198.51.100.0/24".into()],
            expect_regions: vec!["US".into()],
            ip: Some("203.0.113.45".into()),
            country: Some("CN".into()),
            raw_region: Some("CN".into()),
            colo: None,
            city: None,
            latency_ms: 20,
            checked_at: Some(100),
            reason: "出口 203.0.113.45 不在白名单".into(),
            fail_streak: 2,
            matched_rule: Some("198.51.100.98".into()),
        });
        snap.config.targets = cg_protocol::default_builtin_targets(&["198.51.100.98".into()], &[]);
        snap.leak.direct.push(cg_protocol::LeakConn {
            pid: 9,
            agent: "Claude".into(),
            remote: "203.0.113.45".into(),
            port: 443,
            is_mcp: false,
        });

        let masked = mask_snapshot(&snap);
        assert_eq!(masked.targets[0].ip.as_deref(), Some("203.0.*.*"));
        assert_eq!(masked.targets[0].expect_ips, vec!["198.51.*.*/24"]);
        assert_eq!(masked.targets[0].matched_rule.as_deref(), Some("198.51.*.*"));
        assert_eq!(masked.targets[0].reason, "出口 203.0.*.* 不在白名单");
        assert_eq!(masked.config.targets[1].expect_ips, vec!["198.51.*.*"]);
        assert_eq!(masked.leak.direct[0].remote, "203.0.*.*");
    }
}
