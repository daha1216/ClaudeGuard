//! 判定矩阵：把一次探测结果映射成 Pass / Fail / Unverified。
//!
//! 语义以 SPEC §3 为准：拿不到出口信息时保守 Unverified（不熔断），
//! 拿到信息但不符合白名单才 Fail（宁可错杀）。纯函数，单测不发起网络。

use crate::model::{
    ip_hit, region_hit, region_name, AnchorKind, Evaluation, ProbeResult, Target, Verdict,
};

/// 目标可达、但响应里没有任何 IP / 地区信息时的统一说明。
const NO_INFO: &str = "有响应，但未识别到出口信息";

/// 对单个目标执行判定。
pub fn evaluate(target: &Target, probe: &ProbeResult) -> Evaluation {
    if !target.enabled {
        // 正常流程里 monitor 只探测启用目标；这里防御性返回 Unverified 而不是 Fail，避免误熔断。
        return evaluation(Verdict::Unverified, "目标已禁用，不参与判定");
    }

    if target.anchor_kind == AnchorKind::Reachability {
        // 仅可达性：任何 HTTP 响应都算通过，网络错误算失败（SPEC §3）。
        return if probe.reachable {
            evaluation(Verdict::Pass, format!("可达 · {}ms", probe.latency_ms))
        } else {
            evaluation(Verdict::Fail, "不可达")
        };
    }

    if !probe.reachable {
        return evaluation(Verdict::Unverified, network_reason(probe));
    }

    let ip_ok = probe
        .ip
        .as_deref()
        .is_some_and(|ip| ip_hit(&target.expect_ips, ip));
    let region_ok = region_matches(target, probe);
    if ip_ok || region_ok {
        return evaluation(Verdict::Pass, pass_reason(probe, ip_ok));
    }

    let has_geo = probe.ip.is_some() || probe.country.is_some() || probe.raw_region.is_some();
    if target.expect_ips.is_empty() && target.expect_regions.is_empty() {
        // 白名单没配置却拿到了出口信息：宁可错杀（SPEC §3）。
        return if has_geo {
            evaluation(Verdict::Fail, "未配置白名单，按宁可错杀处理")
        } else {
            evaluation(Verdict::Unverified, NO_INFO)
        };
    }
    if !has_geo {
        return evaluation(Verdict::Unverified, NO_INFO);
    }

    // 期望里有地区、这次只拿到 IP：不拿 IP 硬判，防止地区锚点失效时误熔断。
    if probe.ip.is_some()
        && probe.country.is_none()
        && probe.raw_region.is_none()
        && !target.expect_regions.is_empty()
    {
        return evaluation(Verdict::Unverified, "只有 IP，无法核对地区");
    }

    evaluation(Verdict::Fail, fail_reason(probe))
}

fn evaluation(verdict: Verdict, reason: impl Into<String>) -> Evaluation {
    Evaluation {
        verdict,
        reason: reason.into(),
    }
}

/// 地区命中：优先按归一后的 alpha-2 比较；归一不了的原文按原样（忽略大小写）比较。
fn region_matches(target: &Target, probe: &ProbeResult) -> bool {
    if probe
        .country
        .as_deref()
        .is_some_and(|country| region_hit(&target.expect_regions, country))
    {
        return true;
    }
    probe.raw_region.as_deref().is_some_and(|raw| {
        let raw = raw.trim();
        !raw.is_empty()
            && target
                .expect_regions
                .iter()
                .any(|expect| expect.trim().eq_ignore_ascii_case(raw))
    })
}

fn pass_reason(probe: &ProbeResult, ip_ok: bool) -> String {
    if ip_ok {
        format!("出口 {} 符合白名单", egress_label(probe))
    } else {
        format!("出口地区 {} 符合白名单", region_label(probe))
    }
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

/// 出口描述，如 `204.1.100.98（美国）` / `204.1.100.98` / `美国`。
fn egress_label(probe: &ProbeResult) -> String {
    let has_region = probe.country.is_some() || probe.raw_region.is_some();
    match (probe.ip.as_deref(), has_region) {
        (Some(ip), true) => format!("{ip}（{}）", region_label(probe)),
        (Some(ip), false) => ip.to_string(),
        (None, _) => region_label(probe),
    }
}

/// 地区中文名（未知时退回地区代码/原文）。
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
            expect_ips: ips.iter().map(|ip| (*ip).to_string()).collect(),
            expect_regions: regions.iter().map(|region| (*region).to_string()).collect(),
            timeout_secs: 12,
            bind_agent: None,
        }
    }

    fn trace_probe(ip: Option<&str>, country: Option<&str>) -> ProbeResult {
        trace_probe_with_raw(ip, country, country)
    }

    fn trace_probe_with_raw(
        ip: Option<&str>,
        country: Option<&str>,
        raw_region: Option<&str>,
    ) -> ProbeResult {
        ProbeResult {
            reachable: true,
            status: Some(200),
            ip: ip.map(|ip| ip.to_string()),
            country: country.map(|country| country.to_string()),
            raw_region: raw_region.map(|raw| raw.to_string()),
            colo: Some("LAX".into()),
            latency_ms: 88,
            parsed_as: "trace".into(),
            detail: "trace：测试数据".into(),
            ..ProbeResult::default()
        }
    }

    fn network_error() -> ProbeResult {
        ProbeResult::failed("连接超时或中断：timed out")
    }

    #[test]
    fn reachability_passes_on_any_http_response() {
        let probe = ProbeResult {
            reachable: true,
            status: Some(503),
            latency_ms: 42,
            parsed_as: "reachability".into(),
            ..ProbeResult::default()
        };
        let eval = evaluate(&target(AnchorKind::Reachability, &[], &[]), &probe);
        assert_eq!(eval.verdict, Verdict::Pass);
        assert_eq!(eval.reason, "可达 · 42ms");
    }

    #[test]
    fn reachability_fails_without_response() {
        let eval = evaluate(
            &target(AnchorKind::Reachability, &[], &[]),
            &network_error(),
        );
        assert_eq!(eval.verdict, Verdict::Fail);
        assert_eq!(eval.reason, "不可达");
    }

    #[test]
    fn empty_whitelist_with_info_is_fail() {
        let eval = evaluate(
            &target(AnchorKind::Auto, &[], &[]),
            &trace_probe(Some("204.1.100.98"), Some("US")),
        );
        assert_eq!(eval.verdict, Verdict::Fail);
        assert_eq!(eval.reason, "未配置白名单，按宁可错杀处理");
    }

    #[test]
    fn empty_whitelist_without_info_is_unverified() {
        let eval = evaluate(
            &target(AnchorKind::Auto, &[], &[]),
            &trace_probe(None, None),
        );
        assert_eq!(eval.verdict, Verdict::Unverified);
        assert_eq!(eval.reason, NO_INFO);
    }

    #[test]
    fn ip_hit_passes_even_with_other_region() {
        let eval = evaluate(
            &target(AnchorKind::Auto, &["204.1.100.98"], &[]),
            &trace_probe(Some("204.1.100.98"), Some("JP")),
        );
        assert_eq!(eval.verdict, Verdict::Pass);
        assert!(eval.reason.contains("204.1.100.98"));
        assert!(eval.reason.contains("符合白名单"));
    }

    #[test]
    fn multi_ip_list_matches_any_entry() {
        let eval = evaluate(
            &target(AnchorKind::Auto, &["1.1.1.1", "204.1.100.98"], &[]),
            &trace_probe(Some("204.1.100.98"), None),
        );
        assert_eq!(eval.verdict, Verdict::Pass);
    }

    #[test]
    fn region_hit_passes_without_ip() {
        let eval = evaluate(
            &target(AnchorKind::Auto, &[], &["JP"]),
            &trace_probe(None, Some("JP")),
        );
        assert_eq!(eval.verdict, Verdict::Pass);
        assert!(eval.reason.contains("日本"));
        assert!(eval.reason.contains("符合白名单"));
    }

    #[test]
    fn alpha3_expectation_matches_alpha2_probe() {
        let eval = evaluate(
            &target(AnchorKind::Auto, &[], &["USA"]),
            &trace_probe(None, Some("US")),
        );
        assert_eq!(eval.verdict, Verdict::Pass);
    }

    #[test]
    fn ip_and_region_miss_is_fail() {
        let eval = evaluate(
            &target(AnchorKind::Auto, &["1.1.1.1"], &["US"]),
            &trace_probe(Some("204.1.100.98"), Some("SG")),
        );
        assert_eq!(eval.verdict, Verdict::Fail);
        assert!(eval.reason.contains("204.1.100.98"));
        assert!(eval.reason.contains("新加坡"));
        assert!(eval.reason.contains("不在白名单"));
    }

    #[test]
    fn ip_miss_without_region_expectation_is_fail() {
        let eval = evaluate(
            &target(AnchorKind::Auto, &["1.1.1.1"], &[]),
            &trace_probe(Some("204.1.100.98"), None),
        );
        assert_eq!(eval.verdict, Verdict::Fail);
        assert_eq!(eval.reason, "出口 204.1.100.98 不在白名单");
    }

    #[test]
    fn ip_only_with_region_expectation_is_unverified() {
        let eval = evaluate(
            &target(AnchorKind::Auto, &[], &["US"]),
            &trace_probe(Some("204.1.100.98"), None),
        );
        assert_eq!(eval.verdict, Verdict::Unverified);
        assert_eq!(eval.reason, "只有 IP，无法核对地区");
    }

    #[test]
    fn reachable_without_info_is_unverified() {
        let eval = evaluate(
            &target(AnchorKind::Auto, &["1.1.1.1"], &[]),
            &trace_probe(None, None),
        );
        assert_eq!(eval.verdict, Verdict::Unverified);
        assert_eq!(eval.reason, NO_INFO);
    }

    #[test]
    fn network_error_is_unverified() {
        let eval = evaluate(
            &target(AnchorKind::Auto, &["1.1.1.1"], &[]),
            &network_error(),
        );
        assert_eq!(eval.verdict, Verdict::Unverified);
        assert!(eval.reason.contains("网络错误"));
        assert!(eval.reason.contains("连接超时"));
    }

    #[test]
    fn unnormalized_region_compares_raw_text() {
        let eval = evaluate(
            &target(AnchorKind::Auto, &[], &["XYZ"]),
            &trace_probe_with_raw(Some("204.1.100.98"), None, Some("xyz")),
        );
        assert_eq!(eval.verdict, Verdict::Pass);
        assert!(eval.reason.contains("XYZ") || eval.reason.contains("xyz"));
    }

    #[test]
    fn country_only_mismatch_is_fail() {
        let eval = evaluate(
            &target(AnchorKind::Auto, &[], &["US"]),
            &trace_probe(None, Some("JP")),
        );
        assert_eq!(eval.verdict, Verdict::Fail);
        assert!(eval.reason.contains("日本"));
        assert!(eval.reason.contains("不在白名单"));
    }

    #[test]
    fn disabled_target_is_unverified() {
        let mut demo = target(AnchorKind::Auto, &["204.1.100.98"], &[]);
        demo.enabled = false;
        let eval = evaluate(&demo, &trace_probe(Some("204.1.100.98"), Some("US")));
        assert_eq!(eval.verdict, Verdict::Unverified);
        assert!(eval.reason.contains("已禁用"));
    }
}
