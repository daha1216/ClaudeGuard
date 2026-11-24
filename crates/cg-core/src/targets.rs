//! Built-in targets and strict target table validation (including IPv4/IPv6 CIDR and SSRF rules).

use cg_protocol::{
    AnchorKind, BUILTIN_TARGET_IDS, Target, default_builtin_targets, ensure_builtin_targets,
    is_builtin_target, is_known_region, normalize_ip_or_cidr, normalize_region,
};
use std::net::{Ipv4Addr, Ipv6Addr};

pub const BUILTIN_IDS: [&str; 4] = BUILTIN_TARGET_IDS;

pub fn is_builtin(id: &str) -> bool {
    is_builtin_target(id)
}

pub fn default_targets(expect_ips: &[String], expect_regions: &[String]) -> Vec<Target> {
    default_builtin_targets(expect_ips, expect_regions)
}

pub fn ensure_builtins(
    targets: Vec<Target>,
    fallback_ips: &[String],
    fallback_regions: &[String],
) -> Vec<Target> {
    ensure_builtin_targets(targets, fallback_ips, fallback_regions)
}

fn strict_ips(name: &str, raw: &[String]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for item in raw {
        let text = item.trim();
        if text.is_empty() {
            continue;
        }
        let Some(norm) = normalize_ip_or_cidr(text) else {
            return Err(format!("{name}：白名单 IP/CIDR 无法识别：{text}"));
        };
        if !out.contains(&norm) {
            out.push(norm);
        }
    }
    Ok(out)
}

fn strict_regions(name: &str, raw: &[String]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for item in raw {
        let text = item.trim();
        if text.is_empty() {
            continue;
        }
        let Some(code) = normalize_region(text) else {
            return Err(format!(
                "{name}：出口地区无法识别：{text}（填两字母代码，如 US、JP）"
            ));
        };
        if !is_known_region(&code) {
            return Err(format!("{name}：没有这个国家/地区代码：{text}"));
        }
        if !out.contains(&code) {
            out.push(code);
        }
    }
    Ok(out)
}

fn is_forbidden_probe_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_broadcast()
        || o[0] == 0
        || (o[0] == 100 && (64..=127).contains(&o[1]))
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
        || o[0] >= 240
}

fn is_forbidden_probe_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_forbidden_probe_ipv4(v4);
    }
    let seg = ip.segments();
    if seg[..6] == [0x0064, 0xff9b, 0, 0, 0, 0] {
        let v4 = Ipv4Addr::from(((u32::from(seg[6])) << 16) | u32::from(seg[7]));
        return is_forbidden_probe_ipv4(v4);
    }
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (seg[0] & 0xffc0) == 0xfe80
        || (seg[0] & 0xfe00) == 0xfc00
}

fn parse_valid_port(port_str: &str) -> Option<u16> {
    if port_str.is_empty() || !port_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    port_str.parse::<u16>().ok().filter(|&p| p > 0)
}

fn check_url(target: &Target) -> Result<(), String> {
    let url = target.anchor_url.trim();
    if url.is_empty() {
        return Err(format!("{}：请填写探测地址", target.name));
    }
    if url.len() > 300 {
        return Err(format!("{}：探测地址太长（上限 300 字符）", target.name));
    }
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!("{}：探测地址不能包含空白或控制字符", target.name));
    }
    let Some(rest) = url.strip_prefix("https://") else {
        return Err(format!("{}：探测地址必须以 https:// 开头", target.name));
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.starts_with(':') || authority.contains('\\') {
        return Err(format!("{}：探测地址缺少主机名", target.name));
    }
    if authority.contains('@') {
        return Err(format!(
            "{}：探测地址不允许包含账号认证信息（@）",
            target.name
        ));
    }

    if authority.starts_with('[') {
        let Some(close_idx) = authority.find(']') else {
            return Err(format!("{}：IPv6 探测地址缺少右方括号", target.name));
        };
        let host_inner = &authority[1..close_idx];
        let after_bracket = &authority[close_idx + 1..];
        if !after_bracket.is_empty() {
            let Some(port_str) = after_bracket.strip_prefix(':') else {
                return Err(format!("{}：探测地址主机格式无效", target.name));
            };
            if parse_valid_port(port_str).is_none() {
                return Err(format!("{}：探测地址端口无效", target.name));
            }
        }
        let Ok(v6) = host_inner.parse::<Ipv6Addr>() else {
            return Err(format!("{}：IPv6 探测地址无效", target.name));
        };
        if is_forbidden_probe_ipv6(v6) {
            return Err(format!(
                "{}：探测地址禁止使用本机、内网或保留 IP（{}）",
                target.name, host_inner
            ));
        }
        return Ok(());
    }

    if authority.contains(']') || authority.matches(':').count() > 1 {
        return Err(format!("{}：IPv6 探测地址必须使用方括号包裹", target.name));
    }

    let host_raw = if let Some((h, port_str)) = authority.split_once(':') {
        if h.is_empty() {
            return Err(format!("{}：探测地址缺少主机名", target.name));
        }
        if parse_valid_port(port_str).is_none() {
            return Err(format!("{}：探测地址端口无效", target.name));
        }
        h
    } else {
        authority
    };

    let host_clean = host_raw.trim_end_matches('.').to_ascii_lowercase();
    if host_clean.is_empty() {
        return Err(format!("{}：探测地址缺少主机名", target.name));
    }
    if host_clean == "localhost"
        || host_clean.ends_with(".localhost")
        || host_clean == "local"
        || host_clean.ends_with(".local")
    {
        return Err(format!(
            "{}：探测地址不允许使用本机或局域网域名（{}）",
            target.name, host_raw
        ));
    }

    if let Ok(v4) = host_clean.parse::<Ipv4Addr>() {
        if is_forbidden_probe_ipv4(v4) {
            return Err(format!(
                "{}：探测地址禁止使用本机、内网或保留 IP（{}）",
                target.name, v4
            ));
        }
        return Ok(());
    }

    if let Some(last_label) = host_clean.rsplit('.').next()
        && (!last_label.is_empty()
            && (last_label.bytes().all(|b| b.is_ascii_digit()) || last_label.starts_with("0x")))
    {
        return Err(format!("{}：探测地址主机名或 IP 字面量无效", target.name));
    }

    Ok(())
}

/// Validates and normalizes a complete target list before configuration persistence.
pub fn validate(targets: Vec<Target>) -> Result<Vec<Target>, String> {
    validate_with_options(targets, true)
}

/// Validates and normalizes a complete target list, optionally requiring at least one enabled target.
pub fn validate_with_options(
    targets: Vec<Target>,
    require_enabled: bool,
) -> Result<Vec<Target>, String> {
    let mut pending = targets;
    for target in pending.iter_mut() {
        target.id = target.id.trim().to_ascii_lowercase();
    }
    for id in BUILTIN_IDS {
        if !pending.iter().any(|t| t.id == id) {
            return Err(format!("缺少内置目标 {id}，请点“恢复默认”"));
        }
    }

    let mut out: Vec<Target> = Vec::new();
    let defaults = default_targets(&[], &[]);
    for mut target in pending {
        if target.id.is_empty() || target.id.len() > 24 {
            return Err("目标 id 不能为空且不超过 24 个字符".into());
        }
        if !target
            .id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err("目标 id 只能包含小写字母、数字、下划线和连字符".into());
        }
        if out.iter().any(|t| t.id == target.id) {
            return Err(format!("目标 id 重复：{}", target.id));
        }

        target.name = target.name.trim().to_string();
        if target.name.is_empty() || target.name.chars().count() > 16 {
            return Err("目标名称不能为空且不超过 16 个字".into());
        }

        if target.anchor_url.chars().any(char::is_control) {
            return Err(format!("{}：探测地址不能包含控制字符", target.name));
        }
        target.anchor_url = target.anchor_url.trim().to_string();
        check_url(&target)?;

        target.expect_ips = strict_ips(&target.name, &target.expect_ips)?;
        target.expect_regions = strict_regions(&target.name, &target.expect_regions)?;
        if target.enabled
            && target.anchor_kind != AnchorKind::Reachability
            && target.expect_ips.is_empty()
            && target.expect_regions.is_empty()
        {
            return Err(format!(
                "{}：至少要填一个白名单 IP/CIDR 或出口地区（都不填会一直熔断）",
                target.name
            ));
        }

        target.timeout_secs = target.timeout_secs.clamp(3, 60);

        if is_builtin(&target.id) {
            target.builtin = true;
            if let Some(base) = defaults.iter().find(|t| t.id == target.id) {
                target.bind_agent = base.bind_agent.clone();
            }
        } else {
            target.builtin = false;
            target.bind_agent = None;
        }
        out.push(target);
    }

    if require_enabled && !out.iter().any(|t| t.enabled) {
        return Err("至少需要启用一个监控目标".into());
    }

    out.sort_by_key(|t| {
        BUILTIN_IDS
            .iter()
            .position(|id| *id == t.id)
            .unwrap_or(BUILTIN_IDS.len())
    });
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_accepts_cidr_and_normalizes_host_bits() {
        let mut targets = default_targets(&["198.51.100.98/24".into()], &["usa".into()]);
        let validated = validate(targets.clone()).expect("valid cidr and region");
        assert_eq!(validated[1].expect_ips, vec!["198.51.100.0/24"]);
        assert_eq!(validated[1].expect_regions, vec!["US"]);

        targets[1].expect_ips = vec!["198.51.100.0/33".into()];
        assert!(validate(targets).is_err());
    }

    #[test]
    fn validate_rejects_bad_urls_missing_builtins_empty_lists_and_unknown_regions() {
        let mut targets = default_targets(&["198.51.100.98".into()], &[]);
        targets[1].anchor_url = "http://claude.ai/cdn-cgi/trace".into();
        assert!(validate(targets).is_err());

        let mut targets = default_targets(&["198.51.100.98".into()], &[]);
        targets[1].expect_ips.clear();
        assert!(validate(targets).is_err());

        let mut targets = default_targets(&[], &["ZZ".into()]);
        assert!(validate(targets.clone()).is_err());

        targets.remove(0);
        assert!(validate(targets).is_err());
    }

    #[test]
    fn validate_allows_disabled_target_with_empty_allowlist_and_rejects_enabled() {
        let mut targets = default_targets(&[], &["US".into()]);
        // Built-in `local` is disabled by default; clearing its allowlist while disabled must pass.
        targets[0].enabled = false;
        targets[0].expect_ips.clear();
        targets[0].expect_regions.clear();
        let validated =
            validate(targets.clone()).expect("disabled target may have empty allowlist");
        assert!(!validated[0].enabled);

        // Enabling it with an empty allowlist must still be rejected.
        targets[0].enabled = true;
        assert!(validate(targets).is_err());
    }

    #[test]
    fn ensure_builtins_restores_deleted_target_with_fallback_allowlist() {
        let claude = default_targets(&["198.51.100.98".into()], &["US".into()])[1].clone();
        let restored = ensure_builtins(vec![claude], &[], &[]);
        assert_eq!(restored.len(), 4);
        assert_eq!(restored[0].id, "local");
        assert_eq!(restored[0].expect_ips, vec!["198.51.100.98"]);
        assert_eq!(restored[2].id, "codex");
        assert_eq!(restored[2].expect_regions, vec!["US"]);
    }

    #[test]
    fn validate_blocks_ssrf_userinfo_bad_ports_and_all_disabled_targets() {
        let base = default_targets(&["2606:4700::1234/32".into()], &["US".into()]);
        let validated = validate(base.clone()).expect("valid ipv6 cidr");
        assert_eq!(validated[1].expect_ips, vec!["2606:4700::/32"]);

        for bad_url in [
            "https://user:pass@claude.ai/cdn-cgi/trace",
            "https://claude.ai/cdn-cgi/trace\n",
            "https://claude.ai/cdn-cgi/ trace",
            "https://claude.ai:0/cdn-cgi/trace",
            "https://claude.ai:70000/cdn-cgi/trace",
            "https://localhost/trace",
            "https://api.localhost/trace",
            "https://printer.local/trace",
            "https://127.0.0.1/trace",
            "https://127.1/trace",
            "https://10.0.0.1/trace",
            "https://172.16.0.1/trace",
            "https://172.31.255.254/trace",
            "https://192.168.1.1/trace",
            "https://169.254.169.254/latest/meta-data",
            "https://100.64.0.1/trace",
            "https://0.0.0.0/trace",
            "https://198.18.0.1/trace",
            "https://198.19.255.1/trace",
            "https://[::1]/trace",
            "https://[::]/trace",
            "https://[fe80::1]/trace",
            "https://[fc00::1]/trace",
            "https://[fd12:3456::1]/trace",
            "https://[::ffff:127.0.0.1]/trace",
            "https://[::ffff:10.0.0.1]/trace",
            "https://2606:4700::1111/trace",
            "https://[2606:4700::1111]:0/trace",
        ] {
            let mut t = base.clone();
            t[1].anchor_url = bad_url.into();
            assert!(
                validate(t).is_err(),
                "expected SSRF/URL rejection for {bad_url}"
            );
        }

        // Public IPv4 and bracketed public IPv6 with valid port are permitted.
        for ok_url in [
            "https://1.1.1.1/cdn-cgi/trace",
            "https://[2606:4700:4700::1111]:443/cdn-cgi/trace",
        ] {
            let mut t = base.clone();
            t[1].anchor_url = ok_url.into();
            assert!(validate(t).is_ok(), "expected public URL ok: {ok_url}");
        }

        // Disabling all targets is rejected when require_enabled = true, allowed when false.
        let mut all_off = base;
        for t in &mut all_off {
            t.enabled = false;
        }
        assert!(validate(all_off.clone()).is_err());
        assert!(validate_with_options(all_off, false).is_ok());
    }
}
