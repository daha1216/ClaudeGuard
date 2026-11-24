//! Egress policy evaluation matrix supporting exact IP, IPv4 CIDR subnets, ISO regions, and `PolicyPreset`.

use cg_protocol::{
    AnchorKind, Evaluation, PolicyPreset, PolicyVerdict, ProbeResult, Target, matched_ip_rule,
    normalize_region, region_hit, region_name,
};

const NO_INFO: &str = "有响应，但未识别到出口信息";

/// Evaluates a single target probe under the default [`PolicyPreset::StandardRegion`] preset.
pub fn evaluate(target: &Target, probe: &ProbeResult) -> Evaluation {
    evaluate_with_preset(target, probe, PolicyPreset::StandardRegion)
}

/// Evaluates a single target probe under the requested [`PolicyPreset`].
///
/// Invariants (`CONTRACT-v3.10.md` D4 & `AGENTS.md` #1-3):
/// - `AnchorKind::Reachability`: passes on any HTTP response (`probe.reachable`); transport/network
///   failure returns `PolicyVerdict::Unverified` (blocks Launch Gate & holds Flow A recovery,
///   never falsely trips or kills running apps on proxy jitter).
/// - Missing info / transport failure -> `PolicyVerdict::Unverified` (never `Fail`, never trips).
/// - Empty allowlist (`expect_ips.is_empty() && expect_regions.is_empty()`) -> NEVER passes
///   (except `Reachability`): returns `Fail` when egress info is present, `Unverified` if missing.
pub fn evaluate_with_preset(
    target: &Target,
    probe: &ProbeResult,
    preset: PolicyPreset,
) -> Evaluation {
    if !target.enabled {
        return eval(PolicyVerdict::Unverified, "目标已禁用，不参与判定", None);
    }

    if target.anchor_kind == AnchorKind::Reachability {
        return if probe.reachable {
            eval(
                PolicyVerdict::Pass,
                format!("可达 · {}ms", probe.latency_ms),
                Some("reachability".into()),
            )
        } else {
            eval(
                PolicyVerdict::Unverified,
                format!("经代理暂不可达（{}）", network_reason(probe)),
                None,
            )
        };
    }

    if !probe.reachable {
        return eval(PolicyVerdict::Unverified, network_reason(probe), None);
    }

    let has_geo = probe.has_info();
    if !target.has_expect() {
        return if has_geo {
            eval(PolicyVerdict::Fail, "未配置白名单，按宁可错杀处理", None)
        } else {
            eval(PolicyVerdict::Unverified, NO_INFO, None)
        };
    }

    if !has_geo {
        return eval(PolicyVerdict::Unverified, NO_INFO, None);
    }

    let matched_ip = probe
        .ip
        .as_deref()
        .and_then(|ip| matched_ip_rule(&target.expect_ips, ip));
    let matched_region = matched_region_rule(target, probe);

    match preset {
        PolicyPreset::StrictStaticIp => evaluate_strict_static(target, probe, matched_ip),
        PolicyPreset::StandardRegion => {
            evaluate_standard_region(target, probe, matched_ip, matched_region)
        }
        PolicyPreset::LooseAntiDirect => {
            evaluate_loose_anti_direct(probe, matched_ip, matched_region)
        }
    }
}

fn evaluate_strict_static(
    target: &Target,
    probe: &ProbeResult,
    matched_ip: Option<String>,
) -> Evaluation {
    if target.expect_ips.is_empty() {
        return eval(
            PolicyVerdict::Fail,
            "严格静态 IP 模式未配置 IP/CIDR 白名单",
            None,
        );
    }
    if probe.ip.is_none() {
        return eval(
            PolicyVerdict::Unverified,
            "缺少出口 IP，无法进行静态 IP 校验",
            None,
        );
    }
    if let Some(rule) = matched_ip {
        return eval(
            PolicyVerdict::Pass,
            format!("出口 {} 符合静态 IP 白名单", egress_label(probe)),
            Some(rule),
        );
    }
    eval(PolicyVerdict::Fail, fail_reason(probe), None)
}

fn evaluate_standard_region(
    target: &Target,
    probe: &ProbeResult,
    matched_ip: Option<String>,
    matched_region: Option<String>,
) -> Evaluation {
    if let Some(rule) = matched_ip {
        return eval(
            PolicyVerdict::Pass,
            format!("出口 {} 符合白名单", egress_label(probe)),
            Some(rule),
        );
    }
    if let Some(rule) = matched_region {
        return eval(
            PolicyVerdict::Pass,
            format!("出口地区 {} 符合白名单", region_label(probe)),
            Some(rule),
        );
    }
    if probe.ip.is_some()
        && probe.country.is_none()
        && probe.raw_region.is_none()
        && !target.expect_regions.is_empty()
    {
        return eval(PolicyVerdict::Unverified, "只有 IP，无法核对地区", None);
    }
    eval(PolicyVerdict::Fail, fail_reason(probe), None)
}

fn evaluate_loose_anti_direct(
    probe: &ProbeResult,
    matched_ip: Option<String>,
    matched_region: Option<String>,
) -> Evaluation {
    if let Some(rule) = matched_ip {
        return eval(
            PolicyVerdict::Pass,
            format!("出口 {} 符合白名单", egress_label(probe)),
            Some(rule),
        );
    }
    if let Some(rule) = matched_region {
        return eval(
            PolicyVerdict::Pass,
            format!("出口地区 {} 符合白名单", region_label(probe)),
            Some(rule),
        );
    }
    let country = probe
        .country
        .as_deref()
        .and_then(normalize_region)
        .or_else(|| probe.raw_region.as_deref().and_then(normalize_region));
    match country.as_deref() {
        Some("CN") => eval(
            PolicyVerdict::Fail,
            format!("检测到直连出口 {}（中国大陆）", egress_label(probe)),
            None,
        ),
        Some(other) => eval(
            PolicyVerdict::Pass,
            format!("宽松防直连通过：非直连出口 {}", region_name(other)),
            Some(format!("non-CN:{other}")),
        ),
        None => eval(
            PolicyVerdict::Unverified,
            "缺少地区信息，无法确认是否直连",
            None,
        ),
    }
}

fn eval(
    verdict: PolicyVerdict,
    reason: impl Into<String>,
    matched_rule: Option<String>,
) -> Evaluation {
    Evaluation {
        verdict,
        reason: reason.into(),
        matched_rule,
    }
}

fn matched_region_rule(target: &Target, probe: &ProbeResult) -> Option<String> {
    if let Some(country) = probe.country.as_deref()
        && region_hit(&target.expect_regions, country)
    {
        return normalize_region(country).or_else(|| Some(country.to_string()));
    }
    if let Some(raw) = probe.raw_region.as_deref().map(str::trim)
        && !raw.is_empty()
        && let Some(found) = target
            .expect_regions
            .iter()
            .find(|expect| expect.trim().eq_ignore_ascii_case(raw))
    {
        return Some(found.trim().to_ascii_uppercase());
    }
    None
}

fn fail_reason(probe: &ProbeResult) -> String {
    let has_region = probe.country.is_some() || probe.raw_region.is_some();
    match (probe.ip.as_deref(), has_region) {
        (Some(ip), true) => format!("出口 {ip}（{}）不在白名单", region_label(probe)),
        (Some(ip), false) => format!("出口 {ip} 不在白名单"),
        (None, true) => format!("出口地区 {} 不在白名单", region_label(probe)),
        (None, false) => "出口不在白名单".into(),
    }
}

fn egress_label(probe: &ProbeResult) -> String {
    let has_region = probe.country.is_some() || probe.raw_region.is_some();
    match (probe.ip.as_deref(), has_region) {
        (Some(ip), true) => format!("{ip}（{}）", region_label(probe)),
        (Some(ip), false) => ip.to_string(),
        (None, _) => region_label(probe),
    }
}

fn region_label(probe: &ProbeResult) -> String {
    match (&probe.country, &probe.raw_region) {
        (Some(code), _) => region_name(code).to_string(),
        (None, Some(raw)) => raw.to_string(),
        _ => String::new(),
    }
}

fn network_reason(probe: &ProbeResult) -> String {
    let detail = probe.detail.trim();
    if detail.is_empty() {
        "网络错误，未收到响应".into()
    } else {
        format!("网络错误：{detail}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(kind: AnchorKind, ips: &[&str], regions: &[&str]) -> Target {
        Target {
            id: "demo".into(),
            name: "测试出口".into(),
            builtin: false,
            enabled: true,
            anchor_url: "https://example.com/cdn-cgi/trace".into(),
            anchor_kind: kind,
            expect_ips: ips.iter().map(|s| (*s).to_string()).collect(),
            expect_regions: regions.iter().map(|s| (*s).to_string()).collect(),
            timeout_secs: 12,
            bind_agent: None,
        }
    }

    fn probe(ip: Option<&str>, country: Option<&str>) -> ProbeResult {
        ProbeResult {
            reachable: true,
            status: Some(200),
            ip: ip.map(str::to_string),
            country: country.map(str::to_string),
            raw_region: country.map(str::to_string),
            colo: Some("LAX".into()),
            city: Some("洛杉矶".into()),
            latency_ms: 60,
            parsed_as: "trace".into(),
            detail: String::new(),
        }
    }

    #[test]
    fn cidr_subnet_matches_and_records_rule() {
        let t = target(AnchorKind::Auto, &["198.51.100.0/24"], &[]);
        let eval = evaluate(&t, &probe(Some("198.51.100.98"), Some("US")));
        assert_eq!(eval.verdict, PolicyVerdict::Pass);
        assert_eq!(eval.matched_rule.as_deref(), Some("198.51.100.0/24"));

        let miss = evaluate(&t, &probe(Some("203.0.113.45"), Some("US")));
        assert_eq!(miss.verdict, PolicyVerdict::Fail);
    }

    #[test]
    fn empty_allowlist_never_passes_across_all_presets() {
        let t = target(AnchorKind::Auto, &[], &[]);
        let p = probe(Some("198.51.100.98"), Some("US"));
        for preset in [
            PolicyPreset::LooseAntiDirect,
            PolicyPreset::StandardRegion,
            PolicyPreset::StrictStaticIp,
        ] {
            let e = evaluate_with_preset(&t, &p, preset);
            assert_eq!(e.verdict, PolicyVerdict::Fail, "{preset:?}");
        }

        // Missing geo info still yields Unverified rather than Fail.
        let empty_probe = probe(None, None);
        for preset in [
            PolicyPreset::LooseAntiDirect,
            PolicyPreset::StandardRegion,
            PolicyPreset::StrictStaticIp,
        ] {
            assert_eq!(
                evaluate_with_preset(&t, &empty_probe, preset).verdict,
                PolicyVerdict::Unverified
            );
        }
    }

    #[test]
    fn reachability_ignores_empty_allowlist() {
        let t = target(AnchorKind::Reachability, &[], &[]);
        assert_eq!(
            evaluate_with_preset(&t, &probe(None, None), PolicyPreset::StrictStaticIp).verdict,
            PolicyVerdict::Pass
        );
        // Proxy/network jitter on Reachability evaluates to Unverified so it blocks launch
        // and warns the user without falsely tripping or killing running apps.
        let timeout_eval = evaluate(&t, &ProbeResult::failed("timeout"));
        assert_eq!(timeout_eval.verdict, PolicyVerdict::Unverified);
        assert!(timeout_eval.reason.contains("暂不可达"));
    }

    #[test]
    fn presets_differentiate_strict_standard_and_loose() {
        let region_only = target(AnchorKind::Auto, &[], &["US"]);
        let jp_probe = probe(Some("203.0.113.45"), Some("JP"));
        let cn_probe = probe(Some("203.0.113.46"), Some("CN"));
        let us_probe = probe(Some("198.51.100.98"), Some("US"));

        // StrictStaticIp rejects region-only allowlist even when country matches.
        assert_eq!(
            evaluate_with_preset(&region_only, &us_probe, PolicyPreset::StrictStaticIp).verdict,
            PolicyVerdict::Fail
        );
        // StandardRegion passes US, fails JP.
        assert_eq!(
            evaluate_with_preset(&region_only, &us_probe, PolicyPreset::StandardRegion).verdict,
            PolicyVerdict::Pass
        );
        assert_eq!(
            evaluate_with_preset(&region_only, &jp_probe, PolicyPreset::StandardRegion).verdict,
            PolicyVerdict::Fail
        );
        // LooseAntiDirect allows JP (non-CN), rejects CN.
        assert_eq!(
            evaluate_with_preset(&region_only, &jp_probe, PolicyPreset::LooseAntiDirect).verdict,
            PolicyVerdict::Pass
        );
        assert_eq!(
            evaluate_with_preset(&region_only, &cn_probe, PolicyPreset::LooseAntiDirect).verdict,
            PolicyVerdict::Fail
        );
    }

    #[test]
    fn missing_ip_in_strict_mode_is_unverified() {
        let t = target(AnchorKind::GeminiRegion, &["198.51.100.98"], &["US"]);
        let p = probe(None, Some("US"));
        assert_eq!(
            evaluate_with_preset(&t, &p, PolicyPreset::StrictStaticIp).verdict,
            PolicyVerdict::Unverified
        );
    }

    #[test]
    fn ip_hit_passes_even_with_other_region_and_network_error_is_unverified() {
        let t = target(AnchorKind::Auto, &["198.51.100.98"], &[]);
        let eval = evaluate(&t, &probe(Some("198.51.100.98"), Some("JP")));
        assert_eq!(eval.verdict, PolicyVerdict::Pass);
        assert_eq!(eval.matched_rule.as_deref(), Some("198.51.100.98"));

        let net_err = evaluate(&t, &ProbeResult::failed("connection reset"));
        assert_eq!(net_err.verdict, PolicyVerdict::Unverified);
    }

    #[test]
    fn ip_only_with_region_expectation_and_disabled_target_are_unverified() {
        let t = target(AnchorKind::Auto, &[], &["US"]);
        let mut p = probe(Some("198.51.100.98"), None);
        p.raw_region = None;
        assert_eq!(evaluate(&t, &p).verdict, PolicyVerdict::Unverified);
        assert_eq!(
            evaluate_with_preset(&t, &p, PolicyPreset::LooseAntiDirect).verdict,
            PolicyVerdict::Unverified
        );

        let mut disabled = target(AnchorKind::Auto, &["198.51.100.98"], &["US"]);
        disabled.enabled = false;
        assert_eq!(
            evaluate(&disabled, &probe(Some("203.0.113.45"), Some("CN"))).verdict,
            PolicyVerdict::Unverified
        );
    }

    #[test]
    fn alpha3_and_raw_region_matching_work() {
        let t = target(AnchorKind::Auto, &[], &["USA"]);
        assert_eq!(
            evaluate(&t, &probe(None, Some("US"))).verdict,
            PolicyVerdict::Pass
        );

        let custom_t = target(AnchorKind::Auto, &[], &["XYZ"]);
        let custom_p = ProbeResult {
            reachable: true,
            status: Some(200),
            ip: None,
            country: None,
            raw_region: Some("xyz".into()),
            ..ProbeResult::default()
        };
        assert_eq!(evaluate(&custom_t, &custom_p).verdict, PolicyVerdict::Pass);
    }

    #[test]
    fn strict_static_ip_rejects_empty_ip_list_and_matches_cidr() {
        let cidr_only = target(AnchorKind::Auto, &["198.51.100.0/24"], &["US"]);
        assert_eq!(
            evaluate_with_preset(
                &cidr_only,
                &probe(Some("198.51.100.98"), Some("US")),
                PolicyPreset::StrictStaticIp
            )
            .verdict,
            PolicyVerdict::Pass
        );
        assert_eq!(
            evaluate_with_preset(
                &cidr_only,
                &probe(Some("203.0.113.45"), Some("US")),
                PolicyPreset::StrictStaticIp
            )
            .verdict,
            PolicyVerdict::Fail
        );

        let region_only = target(AnchorKind::Auto, &[], &["US"]);
        assert_eq!(
            evaluate_with_preset(
                &region_only,
                &probe(Some("198.51.100.98"), Some("US")),
                PolicyPreset::StrictStaticIp
            )
            .verdict,
            PolicyVerdict::Fail
        );
    }
}
