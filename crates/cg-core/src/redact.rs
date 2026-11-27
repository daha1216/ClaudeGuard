//! Screenshot/UI IP masking (`198.51.100.98` -> `198.51.*.*`) and notification PII redaction.

use crate::geo;
use cg_protocol::{Config, GuardSnapshot, OperationReceipt, is_known_region, normalize_region};
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

const REGION_CITY_NAMES_EN: [&str; 24] = [
    "Los Angeles",
    "San Jose",
    "San Francisco",
    "New York",
    "Hong Kong",
    "Tel Aviv",
    "Sao Paulo",
    "Mexico City",
    "Singapore",
    "Frankfurt",
    "Amsterdam",
    "Stockholm",
    "Melbourne",
    "Vancouver",
    "Montreal",
    "Toronto",
    "Seattle",
    "Chicago",
    "Ashburn",
    "London",
    "Sydney",
    "Taipei",
    "Tokyo",
    "Osaka",
];

fn strip_valid_zone(addr: &str) -> &str {
    match addr.split_once('%') {
        Some((base, zone))
            if !zone.is_empty()
                && zone
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')) =>
        {
            base
        }
        _ => addr,
    }
}

fn is_valid_port_suffix(port_str: &str) -> bool {
    !port_str.is_empty()
        && port_str.len() <= 5
        && port_str.bytes().all(|b| b.is_ascii_digit())
        && port_str.parse::<u16>().ok().is_some_and(|p| p > 0)
}

/// Masks an IP address, `[IPv6]:port`, `IPv4:port`, or CIDR for screenshot/UI privacy
/// (`198.51.100.98` -> `198.51.*.*`, IPv6 -> `XXXX:XXXX:*:*`).
pub fn mask_ip(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix('[')
        && let Some(close_idx) = rest.find(']')
    {
        let inner = &rest[..close_idx];
        let suffix = &rest[close_idx + 1..];
        let valid_suffix = suffix.is_empty()
            || suffix.strip_prefix(':').is_some_and(is_valid_port_suffix)
            || suffix.strip_prefix('/').is_some_and(|p| {
                !p.is_empty()
                    && p.bytes().all(|b| b.is_ascii_digit())
                    && p.parse::<u8>().ok().is_some_and(|v| v <= 128)
            });
        if valid_suffix && let Ok(v6) = strip_valid_zone(inner).parse::<Ipv6Addr>() {
            return format!("[{}]{suffix}", mask_v6(v6));
        }
    }

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

    if prefix_opt.is_none()
        && addr_part.matches(':').count() == 1
        && let Some((host, port)) = addr_part.split_once(':')
        && is_valid_port_suffix(port)
        && let Ok(v4) = host.parse::<Ipv4Addr>()
    {
        return format!("{}:{port}", mask_v4(v4));
    }

    let no_zone = strip_valid_zone(addr_part);
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

/// Replaces IPv4/IPv6 addresses (including `::ffff:a.b.c.d`, `%zone`, `[v6]:port`, and CIDR `/prefix`)
/// and `scheme://user:pass@` URL credentials inside UI/log strings with masked forms.
pub fn mask_text_ips(text: &str) -> String {
    mask_text_ips_inner(text, false)
}

fn mask_non_loopback_ips(text: &str) -> String {
    mask_text_ips_inner(text, true)
}

fn mask_text_ips_inner(text: &str, preserve_loopback: bool) -> String {
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
            if preserve_loopback && v6.is_loopback() && cidr_prefix.is_none() {
                out.extend(chars[i..i + skip].iter());
            } else {
                out.push_str(&mask_v6(v6));
                if let Some(prefix) = cidr_prefix {
                    out.push('/');
                    out.push_str(&prefix);
                }
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
                let cidr = cidr_suffix_at(&chars, j, 32);
                if preserve_loopback && v4.is_loopback() && cidr.is_none() {
                    out.extend(chars[start..j].iter());
                    i = j;
                } else {
                    out.push_str(&mask_v4(v4));
                    if let Some((plen, pstr)) = cidr {
                        out.push('/');
                        out.push_str(&pstr);
                        i = j + plen;
                    } else {
                        i = j;
                    }
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
    let v6 = match cand.parse::<Ipv6Addr>() {
        Ok(addr) => addr,
        Err(_) => {
            // Backtrack a trailing `:port` suffix (e.g. `2001:db8::1:10000` or 8-group `v6:443`).
            let last_colon = cand.rfind(':')?;
            let port_part = &cand[last_colon + 1..];
            if !is_valid_port_suffix(port_part) {
                return None;
            }
            let base = &cand[..last_colon];
            let parsed = base.parse::<Ipv6Addr>().ok()?;
            let port_chars = port_part.chars().count() + 1;
            addr_end = addr_end.checked_sub(port_chars)?;
            parsed
        }
    };

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
    let cidr_prefix = if let Some((plen, pstr)) = cidr_suffix_at(chars, total_end, 128) {
        total_end += plen;
        Some(pstr)
    } else {
        None
    };
    Some((total_end - i, v6, cidr_prefix))
}

fn mask_receipt(receipt: &mut OperationReceipt) {
    if let Some(err) = receipt.error.as_deref() {
        receipt.error = Some(mask_text_ips(err));
    }
    for item in &mut receipt.items {
        item.detail = mask_text_ips(&item.detail);
    }
}

/// Returns a diagnostics-export copy of [`Config`] with allowlist IPs, vault pinned IPs,
/// custom anchor URLs, and non-loopback `proxy_host` masked.
pub fn mask_config_for_diagnostics(cfg: &Config) -> Config {
    let mut out = cfg.clone();
    out.proxy_host = mask_non_loopback_ips(&out.proxy_host);
    for target in &mut out.targets {
        target.expect_ips = target
            .expect_ips
            .iter()
            .map(|ip| mask_text_ips(ip))
            .collect();
        target.anchor_url = mask_text_ips(&target.anchor_url);
    }
    for vault_cfg in &mut out.vaults {
        vault_cfg.pinned_ips = vault_cfg
            .pinned_ips
            .iter()
            .map(|ip| mask_text_ips(ip))
            .collect();
    }
    out
}

/// Returns a screenshot-safe copy of [`GuardSnapshot`] with runtime egress IPs masked while
/// keeping `out.config.targets[*].expect_ips` and `out.config.vaults[*].pinned_ips` intact so
/// GUI `DraftStore` edits never persist masked `"*.*"` literals back to disk.
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

    if let Some(addr) = out.access.proxy_addr.as_deref() {
        out.access.proxy_addr = Some(mask_non_loopback_ips(addr));
    }
    out.access.note = mask_non_loopback_ips(&out.access.note);

    for conn in &mut out.leak.direct {
        conn.remote = mask_ip(&conn.remote);
    }
    out.leak.note = mask_non_loopback_ips(&out.leak.note);

    if let Some(trip) = &mut out.tripped {
        trip.reason = mask_text_ips(&trip.reason);
        trip.network_note = mask_text_ips(&trip.network_note);
        trip.expected_summary = mask_text_ips(&trip.expected_summary);
        trip.observed_summary = mask_text_ips(&trip.observed_summary);
        if let Some(receipt) = &mut trip.receipt {
            mask_receipt(receipt);
        }
    }
    if let Some(receipt) = &mut out.last_receipt {
        mask_receipt(receipt);
    }
    for item in &mut out.self_check.items {
        item.detail = mask_non_loopback_ips(&item.detail);
    }
    out.launch_error = mask_text_ips(&out.launch_error);
    out.last_error = mask_text_ips(&out.last_error);

    if let Some(host) = out.antigravity_proxy.proxy_host.as_deref() {
        out.antigravity_proxy.proxy_host = Some(mask_non_loopback_ips(host));
    }
    out.antigravity_proxy.summary = mask_non_loopback_ips(&out.antigravity_proxy.summary);
    out.feishu.last_error = mask_text_ips(&out.feishu.last_error);
    out.leak_shield.summary = mask_text_ips(&out.leak_shield.summary);
    out.mihomo.controller_url = mask_non_loopback_ips(&out.mihomo.controller_url);
    out.mihomo.note = mask_non_loopback_ips(&out.mihomo.note);
    out.hooks.summary = mask_non_loopback_ips(&out.hooks.summary);
    out.wsl_bridge.summary = mask_non_loopback_ips(&out.wsl_bridge.summary);
    out.burst_guard.summary = mask_text_ips(&out.burst_guard.summary);
    out.hotkeys.conflict_note = mask_text_ips(&out.hotkeys.conflict_note);

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
        ev.app_path = scrub_user_home_paths(&mask_text_ips(&ev.app_path));
    }

    // v5: Sovereign Account Vault runtime status (keep out.config.vaults[*].pinned_ips unmutated)
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

/// Redacts egress PII (IPv4, IPv6, region/colo codes, localized/English city & country names,
/// and local OS usernames) from notification text unless `include_egress` is explicitly `true`
/// (`CONTRACT-v3.10.md` D5 / R14).
pub fn redact(text: &str, include_egress: bool) -> String {
    if include_egress {
        return text.to_string();
    }
    let scrubbed_paths = scrub_user_home_paths(text);
    let chars: Vec<char> = scrubbed_paths.chars().collect();
    let mut out = String::with_capacity(scrubbed_paths.len());
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

fn is_region_left_boundary(chars: &[char], i: usize) -> bool {
    if i == 0 {
        return true;
    }
    let prev = chars[i - 1];
    prev.is_whitespace()
        || matches!(
            prev,
            '·' | '（'
                | '('
                | '['
                | '【'
                | '「'
                | '『'
                | '<'
                | '"'
                | '\''
                | '：'
                | ':'
                | '='
                | ','
                | '，'
                | '、'
                | '/'
                | '-'
                | '|'
        )
}

fn is_region_right_boundary(chars: &[char], end: usize) -> bool {
    !chars.get(end).is_some_and(char::is_ascii_alphanumeric)
}

fn region_marker_at(chars: &[char], i: usize) -> Option<usize> {
    if !is_region_left_boundary(chars, i) {
        return None;
    }
    let a = *chars.get(i)?;
    let b = *chars.get(i + 1)?;
    if !(a.is_ascii_uppercase() && b.is_ascii_uppercase()) {
        return None;
    }

    if let Some(&c) = chars.get(i + 2)
        && c.is_ascii_uppercase()
        && is_region_right_boundary(chars, i + 3)
    {
        let code3: String = [a, b, c].into_iter().collect();
        if !matches!(code3.as_str(), "COM" | "LAN" | "MAN")
            && (geo::by_colo(&code3).is_some() || normalize_region(&code3).is_some())
        {
            return Some(3);
        }
        return None;
    }

    if !is_region_right_boundary(chars, i + 2) {
        return None;
    }
    let code2: String = [a, b].into_iter().collect();
    if code2 != "AI" && is_known_region(&code2) {
        Some(2)
    } else {
        None
    }
}

fn scrub_user_home_paths(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    while i < chars.len() {
        // Match `\Users\<user>\` or `/Users/<user>/` case-insensitively.
        if matches!(chars[i], '\\' | '/')
            && i + 7 < chars.len()
            && chars[i + 1..i + 6]
                .iter()
                .collect::<String>()
                .eq_ignore_ascii_case("users")
            && matches!(chars[i + 6], '\\' | '/')
        {
            let sep = chars[i + 6];
            let user_start = i + 7;
            let mut user_end = user_start;
            while user_end < chars.len()
                && !matches!(
                    chars[user_end],
                    '\\' | '/' | '"' | '\'' | ' ' | '\t' | '\r' | '\n'
                )
            {
                user_end += 1;
            }
            if user_end > user_start {
                let uname: String = chars[user_start..user_end].iter().collect();
                if !uname.eq_ignore_ascii_case("public")
                    && !uname.eq_ignore_ascii_case("default")
                    && uname != REDACTED
                {
                    out.extend(chars[i..i + 7].iter());
                    out.push_str(REDACTED);
                    if user_end < chars.len() && matches!(chars[user_end], '\\' | '/') {
                        out.push(sep);
                        i = user_end + 1;
                    } else {
                        i = user_end;
                    }
                    continue;
                }
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

fn replace_ascii_case_insensitive_bounded(text: &str, needle: &str, replacement: &str) -> String {
    let lower_text = text.to_ascii_lowercase();
    let lower_needle = needle.to_ascii_lowercase();
    if !lower_text.contains(&lower_needle) {
        return text.to_string();
    }
    let bytes = text.as_bytes();
    let nlen = needle.len();
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    while let Some(rel) = lower_text[cursor..].find(&lower_needle) {
        let idx = cursor + rel;
        let end = idx + nlen;
        let left_ok = idx == 0 || !bytes[idx - 1].is_ascii_alphanumeric();
        let right_ok = end >= bytes.len() || !bytes[end].is_ascii_alphanumeric();
        if left_ok && right_ok {
            out.push_str(&text[cursor..idx]);
            out.push_str(replacement);
            cursor = end;
        } else {
            let step = text[idx..].chars().next().map_or(1, char::len_utf8);
            out.push_str(&text[cursor..idx + step]);
            cursor = idx + step;
        }
    }
    out.push_str(&text[cursor..]);
    out
}

fn scrub_region_names(text: &str) -> String {
    let mut out = text.to_string();
    for name in REGION_NAMES_ZH {
        if out.contains(name) {
            out = out.replace(name, REDACTED);
        }
    }
    for place in geo::PLACES {
        if !place.city.is_empty() && out.contains(place.city) {
            out = out.replace(place.city, REDACTED);
        }
    }
    for city_en in REGION_CITY_NAMES_EN {
        out = replace_ascii_case_insensitive_bounded(&out, city_en, REDACTED);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_ipv4_and_ipv6_for_ui_screenshots() {
        assert_eq!(mask_ip("198.51.100.98"), "198.51.*.*");
        assert_eq!(mask_ip("198.51.100.98:8080"), "198.51.*.*:8080");
        assert_eq!(mask_ip("203.0.113.45"), "203.0.*.*");
        assert_eq!(mask_ip("2001:db8:85a3::1"), "2001:db8:*:*");
        assert_eq!(mask_ip("[2001:db8::1]"), "[2001:db8:*:*]");
        assert_eq!(mask_ip("[2001:db8::1]:443"), "[2001:db8:*:*]:443");
        assert_eq!(mask_ip("[fe80::1a2b%eth0]:8080"), "[fe80:0:*:*]:8080");
        assert_eq!(mask_ip("::ffff:198.51.100.98"), "::ffff:198.51.*.*");
        assert_eq!(mask_ip("fe80::1a2b:3c4d%eth0"), "fe80:0:*:*");
        assert_eq!(mask_ip("fe80::1a2b%eth0/64"), "fe80:0:*:*/64");
        assert_eq!(mask_ip("2606:4700::/32"), "2606:4700:*:*/32");
        assert_eq!(
            mask_text_ips("出口 198.51.100.98（美国）不在白名单，v4.0.0"),
            "出口 198.51.*.*（美国）不在白名单，v4.0.0"
        );
        assert_eq!(
            mask_text_ips(
                "出口 2001:db8:85a3::8a2e:370:7334 与 ::ffff:198.51.100.98 及 fe80::1234%eth0 子网 2606:4700::/32 端口 2001:db8::1:10000"
            ),
            "出口 2001:db8:*:* 与 ::ffff:198.51.*.* 及 fe80:0:*:* 子网 2606:4700:*:*/32 端口 2001:db8:*:*:10000"
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
        let msg = "出口 198.51.100.98（美国）· US · 洛杉矶 · LAX 不在白名单，HTTP 500";
        let redacted = redact(msg, false);
        assert!(!redacted.contains("198.51.100.98"));
        assert!(!redacted.contains("美国"));
        assert!(!redacted.contains("US"));
        assert!(!redacted.contains("洛杉矶"));
        assert!(!redacted.contains("LAX"));
        assert!(redacted.contains(REDACTED));
        assert!(redacted.contains("HTTP 500"));

        // Leading region/colo markers, bracketed codes, English cities, and user home paths are scrubbed.
        let leading = redact(
            r"US [JP] Los Angeles C:\Users\alice\AppData\Local\Claude\claude.exe",
            false,
        );
        assert!(!leading.contains("US"));
        assert!(!leading.contains("JP"));
        assert!(!leading.contains("Los Angeles"));
        assert!(!leading.contains("alice"));

        assert_eq!(redact(msg, true), msg);

        let v6 = redact(
            "出口 2001:db8::1 / 2001:db8::1:10000 / ::ffff:198.51.100.98 / fe80::99%eth0 异常",
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
            redact(
                "OK AI IP OS UI API DNS UDP TCP WFP HTTP 500 版本 5.0.0",
                false
            ),
            "OK AI IP OS UI API DNS UDP TCP WFP HTTP 500 版本 5.0.0"
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
        // Pinned contract: mask_snapshot leaves out.config unmutated so GUI DraftStore never saves "*.*".
        assert_eq!(masked.config.targets[1].expect_ips, vec!["198.51.100.98"]);
        // Diagnostics export explicitly masks config allowlists via mask_config_for_diagnostics.
        let diag_cfg = mask_config_for_diagnostics(&snap.config);
        assert_eq!(diag_cfg.targets[1].expect_ips, vec!["198.51.*.*"]);
        assert_eq!(masked.leak.direct[0].remote, "203.0.*.*");
    }

    #[test]
    fn mask_snapshot_scrubs_all_v5_telemetry_vault_wfp_cleanroom_and_last_error_fields() {
        let mut snap = GuardSnapshot {
            last_error: "上游探测 198.51.100.42 超时".into(),
            ..GuardSnapshot::default()
        };
        snap.access.proxy_addr = Some("192.168.10.5:7890".into());
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
            app_path: r"C:\Users\secretuser\AppData\Local\Claude\claude.exe".into(),
            remote_ip: "203.0.113.99".into(),
            remote_port: 443,
            protocol: "udp".into(),
            layer: "ale_auth_connect_v4".into(),
            filter_reason: "quic_shield".into(),
        });

        snap.config.proxy_host = "192.168.10.5".into();
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
        // Editable config allowlists stay intact in GuardSnapshot for GUI DraftStore safety:
        assert_eq!(
            masked.config.vaults[0].pinned_ips,
            vec!["198.51.100.0/24", "2001:db8:abcd::1"]
        );

        let mut diag_snap = masked.clone();
        diag_snap.config = mask_config_for_diagnostics(&masked.config);
        let serialized = serde_json::to_string(&diag_snap).unwrap();
        for raw_ip in [
            "192.168.10.5",
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
                "diagnostics snapshot leaked raw IP {raw_ip}: {serialized}"
            );
        }
        assert!(!serialized.contains("secretuser"));
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
            diag_snap.config.vaults[0].pinned_ips,
            vec!["198.51.*.*/24", "2001:db8:*:*"]
        );
        assert_eq!(
            masked.vaults[0].last_ip_masked.as_deref(),
            Some("198.51.*.*")
        );
    }
}
