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

/// Masks an IP address or CIDR for screenshot/UI privacy (`198.51.100.98` -> `198.51.*.*`, IPv6 -> `XXXX:XXXX:*:*`).
pub fn mask_ip(raw: &str) -> String {
    let trimmed = raw.trim();
    let (addr_part, prefix_opt) = match trimmed.split_once('/') {
        Some((addr, prefix))
            if !prefix.is_empty()
                && prefix.bytes().all(|b| b.is_ascii_digit())
                && prefix.parse::<u8>().ok().is_some_and(|p| p <= 128) =>
        {
            (addr, Some(prefix))
        }
        _ => (trimmed, None),
    };
    let no_zone = match addr_part.split_once('%') {
        Some((addr, zone))
            if prefix_opt.is_none()
                && !zone.is_empty()
                && zone
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')) =>
        {
            addr
        }
        _ => addr_part,
    };
    let masked = match no_zone.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => Some(mask_v4(v4)),
        Ok(IpAddr::V6(v6)) => Some(mask_v6(v6)),
        Err(_) => None,
    };
    match (masked, prefix_opt) {
        (Some(m), Some(p)) => format!("{m}/{p}"),
        (Some(m), None) => m,
        (None, _) => trimmed.to_string(),
    }
}

fn mask_v4(v4: Ipv4Addr) -> String {
    let [a, b, _, _] = v4.octets();
    format!("{a}.{b}.*.*")
}

fn mask_v6(v6: Ipv6Addr) -> String {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return format!("::ffff:{}", mask_v4(v4));
    }
    let seg = v6.segments();
    format!("{:x}:{:x}:*:*", seg[0], seg[1])
}

/// Replaces IPv4/IPv6 addresses (including `::ffff:a.b.c.d`, `%zone`, and CIDR `/prefix`)
/// and `scheme://user:pass@` URL credentials inside UI/log strings with masked forms.
pub fn mask_text_ips(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    while i < chars.len() {
        if let Some((scheme_end, after_at)) = url_userinfo_at(&chars, i) {
            out.extend(chars[i..scheme_end].iter());
            out.push_str("***@");
            i = after_at;
            continue;
        }
        if let Some((skip, v6, cidr_prefix)) = ipv6_literal_at(&chars, i) {
            out.push_str(&mask_v6(v6));
            if let Some(prefix) = cidr_prefix {
                out.push('/');
                out.push_str(&prefix);
            }
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
            if dots == 3
                && let Ok(v4) = cand.parse::<Ipv4Addr>()
            {
                out.push_str(&mask_v4(v4));
                if let Some((plen, pstr)) = cidr_suffix_at(&chars, j, 32) {
                    out.push('/');
                    out.push_str(&pstr);
                    i = j + plen;
                } else {
                    i = j;
                }
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

fn url_userinfo_at(chars: &[char], i: usize) -> Option<(usize, usize)> {
    if !chars.get(i)?.is_ascii_alphabetic() {
        return None;
    }
    if i > 0 {
        let prev = chars[i - 1];
        if prev.is_ascii_alphanumeric() || matches!(prev, '+' | '-' | '.') {
            return None;
        }
    }
    let mut s = i + 1;
    while s < chars.len()
        && (chars[s].is_ascii_alphanumeric() || matches!(chars[s], '+' | '-' | '.'))
    {
        s += 1;
    }
    if chars.get(s) != Some(&':')
        || chars.get(s + 1) != Some(&'/')
        || chars.get(s + 2) != Some(&'/')
    {
        return None;
    }
    let scheme_end = s + 3;
    let mut auth_end = scheme_end;
    while auth_end < chars.len() {
        let c = chars[auth_end];
        if c.is_whitespace()
            || c.is_control()
            || matches!(
                c,
                '/' | '?' | '#' | '\\' | '"' | '\'' | ')' | '）' | '，' | ',' | '；' | ';'
            )
        {
            break;
        }
        auth_end += 1;
    }
    let at_rel = chars[scheme_end..auth_end]
        .iter()
        .rposition(|&c| c == '@')?;
    if at_rel == 0 {
        return None;
    }
    let at_idx = scheme_end + at_rel;
    if at_idx + 1 >= auth_end {
        return None;
    }
    Some((scheme_end, at_idx + 1))
}

fn cidr_suffix_at(chars: &[char], idx: usize, max_prefix: u8) -> Option<(usize, String)> {
    if chars.get(idx) != Some(&'/') {
        return None;
    }
    let mut end = idx + 1;
    while end < chars.len() && chars[end].is_ascii_digit() {
        end += 1;
    }
    if end == idx + 1 {
        return None;
    }
    if chars
        .get(end)
        .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '.')
    {
        return None;
    }
    let pstr: String = chars[idx + 1..end].iter().collect();
    let val = pstr.parse::<u8>().ok()?;
    if val > max_prefix {
        return None;
    }
    Some((end - idx, pstr))
}

fn ipv6_literal_at(chars: &[char], i: usize) -> Option<(usize, Ipv6Addr, Option<String>)> {
    if !chars[i].is_ascii_hexdigit() && chars[i] != ':' {
        return None;
    }
    if i > 0 && (chars[i - 1].is_ascii_alphanumeric() || chars[i - 1] == '.') {
        return None;
    }
    let mut j = i;
    let mut colons = 0usize;
    while j < chars.len() && (chars[j].is_ascii_hexdigit() || matches!(chars[j], ':' | '.')) {
        if chars[j] == ':' {
            colons += 1;
        }
        j += 1;
    }
    if colons < 2 {
        return None;
    }
    let mut addr_end = j;
    while addr_end > i && chars[addr_end - 1] == '.' {
        addr_end -= 1;
    }
    let cand: String = chars[i..addr_end].iter().collect();
    let v6 = cand.parse::<Ipv6Addr>().ok()?;

    let mut total_end = addr_end;
    if chars.get(total_end) == Some(&'%') {
        let mut z = total_end + 1;
        while z < chars.len()
            && (chars[z].is_ascii_alphanumeric() || matches!(chars[z], '.' | '_' | '-'))
        {
            z += 1;
        }
        if z > total_end + 1 {
            total_end = z;
        }
    }
    let cidr_prefix = if total_end == addr_end {
        if let Some((plen, pstr)) = cidr_suffix_at(chars, total_end, 128) {
            total_end += plen;
            Some(pstr)
        } else {
            None
        }
    } else {
        None
    };
    Some((total_end - i, v6, cidr_prefix))
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
    out.last_error = mask_text_ips(&out.last_error);

    // v5: 10D Risk Assessment, IP Purity, STUN Leak, DNS Coherence & Electron Hygiene
    if let Some(ip) = out.risk_assessment.ip_purity.ip.as_deref() {
        out.risk_assessment.ip_purity.ip = Some(mask_ip(ip));
    }
    out.risk_assessment.ip_purity.asn_org = mask_text_ips(&out.risk_assessment.ip_purity.asn_org);
    if let Some(ip) = out.risk_assessment.stun_leak.reflexive_ip.as_deref() {
        out.risk_assessment.stun_leak.reflexive_ip = Some(mask_ip(ip));
    }
    out.risk_assessment.stun_leak.summary = mask_text_ips(&out.risk_assessment.stun_leak.summary);
    out.risk_assessment.dns_coherence.summary =
        mask_text_ips(&out.risk_assessment.dns_coherence.summary);
    out.risk_assessment.electron_hygiene.summary =
        mask_text_ips(&out.risk_assessment.electron_hygiene.summary);
    out.risk_assessment.headline = mask_text_ips(&out.risk_assessment.headline);
    for dim in &mut out.risk_assessment.dimensions {
        dim.detail = mask_text_ips(&dim.detail);
        if let Some(rem) = dim.remediation_action.as_deref() {
            dim.remediation_action = Some(mask_text_ips(rem));
        }
    }
    out.risk_assessment.recommendations = out
        .risk_assessment
        .recommendations
        .iter()
        .map(|rec| mask_text_ips(rec))
        .collect();

    // v5: Kernel WFP blocked packet events & error detail
    out.wfp.last_error = mask_text_ips(&out.wfp.last_error);
    for ev in &mut out.wfp.recent_blocked {
        ev.remote_ip = mask_ip(&ev.remote_ip);
    }

    // v5: Sovereign Account Vault config allowlists & runtime status
    for vault_cfg in &mut out.config.vaults {
        vault_cfg.pinned_ips = vault_cfg
            .pinned_ips
            .iter()
            .map(|ip| mask_text_ips(ip))
            .collect();
    }
    for vault_rt in &mut out.vaults {
        if let Some(ip) = vault_rt.last_ip_masked.as_deref() {
            vault_rt.last_ip_masked = Some(mask_ip(ip));
        }
        vault_rt.summary = mask_text_ips(&vault_rt.summary);
    }

    // v5: Clean-Room anti-correlation scan report
    if let Some(report) = &mut out.last_cleanroom_report {
        report.summary = mask_text_ips(&report.summary);
        report.preserved_assets_summary = report
            .preserved_assets_summary
            .iter()
            .map(|s| mask_text_ips(s))
            .collect();
        for finding in &mut report.findings {
            finding.location_display = mask_text_ips(&finding.location_display);
            finding.masked_preview = mask_text_ips(&finding.masked_preview);
            finding.preservation_note = mask_text_ips(&finding.preservation_note);
        }
    }

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
        if let Some((scheme_end, after_at)) = url_userinfo_at(&chars, i) {
            out.extend(chars[i..scheme_end].iter());
            out.push_str("***@");
            i = after_at;
            continue;
        }
        if let Some(skip) = region_marker_at(&chars, i) {
            out.push_str(REDACTED);
            i += skip;
            continue;
        }
        if let Some((skip, _, _)) = ipv6_literal_at(&chars, i) {
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
                if let Some((plen, _)) = cidr_suffix_at(&chars, j, 32) {
                    i = j + plen;
                } else {
                    i = j;
                }
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
        assert_eq!(mask_ip("::ffff:198.51.100.98"), "::ffff:198.51.*.*");
        assert_eq!(mask_ip("fe80::1a2b:3c4d%eth0"), "fe80:0:*:*");
        assert_eq!(mask_ip("2606:4700::/32"), "2606:4700:*:*/32");
        assert_eq!(
            mask_text_ips("出口 198.51.100.98（美国）不在白名单，v4.0.0"),
            "出口 198.51.*.*（美国）不在白名单，v4.0.0"
        );
        assert_eq!(
            mask_text_ips(
                "出口 2001:db8:85a3::8a2e:370:7334 与 ::ffff:198.51.100.98 及 fe80::1234%eth0 子网 2606:4700::/32"
            ),
            "出口 2001:db8:*:* 与 ::ffff:198.51.*.* 及 fe80:0:*:* 子网 2606:4700:*:*/32"
        );
        assert_eq!(
            mask_text_ips(
                "代理 https://alice:s3cr3t@198.51.100.98:7890/trace 失败，联系 ops@example.com"
            ),
            "代理 https://***@198.51.*.*:7890/trace 失败，联系 ops@example.com"
        );
        assert_eq!(
            mask_text_ips("SOCKS socks5://user:p@ss@[2001:db8::1]:1080"),
            "SOCKS socks5://***@[2001:db8:*:*]:1080"
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

        let v6 = redact(
            "出口 2001:db8::1 / ::ffff:198.51.100.98 / fe80::99%eth0 异常",
            false,
        );
        assert!(!v6.contains("2001:db8::1"));
        assert!(!v6.contains("198.51.100.98"));
        assert!(!v6.contains("51.100.98"));
        assert!(!v6.contains("eth0"));
        assert!(v6.contains(REDACTED));

        let creds = redact("请求 http://admin:hunter2@example.com/ip 失败", false);
        assert!(!creds.contains("admin"));
        assert!(!creds.contains("hunter2"));
        assert!(creds.contains("http://***@example.com/ip"));
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
        assert_eq!(
            masked.targets[0].matched_rule.as_deref(),
            Some("198.51.*.*")
        );
        assert_eq!(masked.targets[0].reason, "出口 203.0.*.* 不在白名单");
        assert_eq!(masked.config.targets[1].expect_ips, vec!["198.51.*.*"]);
        assert_eq!(masked.leak.direct[0].remote, "203.0.*.*");
    }

    #[test]
    fn mask_snapshot_scrubs_all_v5_telemetry_vault_wfp_cleanroom_and_last_error_fields() {
        let mut snap = GuardSnapshot {
            last_error: "上游探测 198.51.100.42 超时".into(),
            ..GuardSnapshot::default()
        };
        snap.risk_assessment.ip_purity.ip = Some("198.51.100.42".into());
        snap.risk_assessment.ip_purity.asn_org = "ISP 198.51.100.42".into();
        snap.risk_assessment.stun_leak.reflexive_ip = Some("203.0.113.88".into());
        snap.risk_assessment.stun_leak.summary = "STUN 反射公网 203.0.113.88 泄露".into();
        snap.risk_assessment.dns_coherence.summary = "DNS 递归节点 114.114.114.114".into();
        snap.risk_assessment.electron_hygiene.summary = "直连 203.0.113.88 风险".into();
        snap.risk_assessment.headline = "F 级 · STUN 暴露 203.0.113.88".into();
        snap.risk_assessment
            .dimensions
            .push(cg_protocol::RiskDimensionItem {
                id: "webrtc_stun_exposure".into(),
                name: "STUN".into(),
                max_score: 2,
                score: 0,
                healthy: false,
                detail: "检测到 203.0.113.88 与代理 198.51.100.42 不一致".into(),
                remediation_action: Some("封堵 203.0.113.88 直连".into()),
            });
        snap.risk_assessment
            .recommendations
            .push("请勿直连 203.0.113.88".into());

        snap.wfp.last_error = "WFP 拦截直连 203.0.113.99 异常".into();
        snap.wfp.recent_blocked.push(cg_protocol::WfpBlockedEvent {
            seq: 1,
            timestamp_ms: 1_700_000_000_000,
            pid: Some(4242),
            agent_id: "claude".into(),
            app_path: r"C:\Apps\Claude\claude.exe".into(),
            remote_ip: "203.0.113.99".into(),
            remote_port: 443,
            protocol: "udp".into(),
            layer: "ale_auth_connect_v4".into(),
            filter_reason: "quic_shield".into(),
        });

        snap.config.vaults.push(cg_protocol::AccountVault {
            id: "us-pro".into(),
            name: "US Pro".into(),
            accent_hex: "#3B82F6".into(),
            enabled: true,
            pinned_regions: vec!["US".into()],
            pinned_ips: vec!["198.51.100.0/24".into(), "2001:db8:abcd::1".into()],
            pinned_asn: None,
            dedicated_proxy_port: None,
            preferred_mihomo_group: None,
            preferred_mihomo_node: None,
            auto_align_mihomo_on_vault_launch: false,
            min_safety_score: 75,
            cooldown_after_ip_change_secs: 900,
            share_ide_extensions: true,
            msix_isolation_mode: cg_protocol::MsixIsolationMode::default(),
        });
        snap.vaults.push(cg_protocol::VaultRuntimeStatus {
            id: "us-pro".into(),
            name: "US Pro".into(),
            accent_hex: "#3B82F6".into(),
            state: cg_protocol::VaultRuntimeState::EgressMismatch,
            running_pids: Vec::new(),
            running_apps: Vec::new(),
            egress_matches_contract: false,
            cooldown_remaining_secs: 0,
            last_active_at: None,
            last_ip_masked: Some("198.51.100.42".into()),
            last_country: Some("US".into()),
            vault_dir: r"C:\Vaults\us-pro".into(),
            summary: "当前出口 203.0.113.77 与绑定 198.51.100.42 不符".into(),
        });

        snap.last_cleanroom_report = Some(cg_protocol::CleanRoomReport {
            scanned_at: 1_700_000_000,
            scope: cg_protocol::CleanRoomScope::default(),
            pollution_score: 40,
            risk_level: cg_protocol::CleanRoomRiskLevel::Elevated,
            findings: vec![cg_protocol::CleanRoomFinding {
                id: "f1".into(),
                client_id: "claude".into(),
                vector: cg_protocol::CleanRoomVector::ClaudeCodeState,
                risk_weight: 25,
                location_display: "endpoint 198.51.100.42".into(),
                correlation_keys: vec!["userID".into()],
                masked_preview: "last_ip=203.0.113.88".into(),
                bytes_size: 128,
                preservation_note: "保留 198.51.100.42 配置".into(),
            }],
            preserved_assets_summary: vec!["保留 MCP 198.51.100.42".into()],
            summary: "发现 203.0.113.88 历史痕迹".into(),
        });

        let masked = mask_snapshot(&snap);
        let serialized = serde_json::to_string(&masked).unwrap();
        for raw_ip in [
            "198.51.100.42",
            "198.51.100.0",
            "203.0.113.88",
            "203.0.113.99",
            "203.0.113.77",
            "114.114.114.114",
            "2001:db8:abcd::1",
        ] {
            assert!(
                !serialized.contains(raw_ip),
                "mask_snapshot leaked raw IP {raw_ip}: {serialized}"
            );
        }
        assert_eq!(
            masked.risk_assessment.ip_purity.ip.as_deref(),
            Some("198.51.*.*")
        );
        assert_eq!(
            masked.risk_assessment.stun_leak.reflexive_ip.as_deref(),
            Some("203.0.*.*")
        );
        assert_eq!(masked.wfp.recent_blocked[0].remote_ip, "203.0.*.*");
        assert_eq!(
            masked.config.vaults[0].pinned_ips,
            vec!["198.51.*.*/24", "2001:db8:*:*"]
        );
        assert_eq!(
            masked.vaults[0].last_ip_masked.as_deref(),
            Some("198.51.*.*")
        );
    }
}
