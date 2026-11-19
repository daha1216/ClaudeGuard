//! Zero-input onboarding strategy recommender from detected proxy/TUN + probed egress.

use crate::geo;
use crate::targets;
use cg_protocol::{
    AccessEvidence, Config, Ipv4Cidr, OnboardingOption, OnboardingProbeResult, OnboardingStrategy,
    PolicyPreset, ProbeResult, clean_guarded_agents,
};
use std::net::Ipv4Addr;

/// User selection emitted from the first-run onboarding modal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OnboardingChoice {
    RecommendRegion,
    StrictStaticIp,
    CustomCidrOrRegions {
        expect_ips: Vec<String>,
        expect_regions: Vec<String>,
        preset: Option<PolicyPreset>,
    },
}

/// Computes zero-input onboarding recommendations from detected access path and probed exit.
pub fn recommend(
    access: &AccessEvidence,
    probe: Option<&ProbeResult>,
    detected_proxy_port: Option<u16>,
    installed_agents: Vec<String>,
) -> OnboardingProbeResult {
    let installed_agents = clean_guarded_agents(&installed_agents);
    let access_ready = access.is_known();

    let mut enriched_probe = probe.cloned();
    if let Some(p) = &mut enriched_probe
        && p.city.is_none()
        && let Some(colo) = p.colo.as_deref()
        && let Some(place) = geo::by_colo(colo)
    {
        p.city = Some(place.city.to_string());
    }

    let standby_notice = if !access_ready {
        Some(if access.is_uncovered() {
            "当前未检测到开启的系统代理或 TUN 网卡，守护器处于安全待机状态；可先开启代理后重测，或手动填写白名单。".into()
        } else {
            format!(
                "接入路径暂无法确认（{}），已跳过直连探测以避免真实 IP 外泄。",
                access.note
            )
        })
    } else if enriched_probe
        .as_ref()
        .is_none_or(|p| !p.reachable || !p.has_info())
    {
        Some(
            "代理已接入，但未能从探针提取到出口 IP 或地区信息；请检查代理连通性或手动填写白名单。"
                .into(),
        )
    } else {
        None
    };

    let ip = enriched_probe.as_ref().and_then(|p| p.ip.clone());
    let country = enriched_probe.as_ref().and_then(|p| p.country.clone());
    let city = enriched_probe.as_ref().and_then(|p| p.city.clone());

    let mut options = Vec::new();
    let mut recommended_strategy = None;

    if access_ready && let Some(ref code) = country {
        let place_desc = match (&city, &ip) {
            (Some(c), Some(addr)) => format!("{code} · {c}（{addr}）"),
            (None, Some(addr)) => format!("{code}（{addr}）"),
            _ => code.clone(),
        };
        recommended_strategy = Some(OnboardingStrategy::RecommendRegion);
        options.push(OnboardingOption {
            strategy: OnboardingStrategy::RecommendRegion,
            recommended: true,
            title: "推荐：允许当前国家节点".into(),
            subtitle: format!("出口 {place_desc}，允许 {code} 地区代理节点切换"),
            preset: PolicyPreset::StandardRegion,
            expect_ips: Vec::new(),
            expect_regions: vec![code.clone()],
        });
    }

    if access_ready && let Some(ref addr) = ip {
        let is_rec = recommended_strategy.is_none();
        if is_rec {
            recommended_strategy = Some(OnboardingStrategy::StrictStaticIp);
        }
        options.push(OnboardingOption {
            strategy: OnboardingStrategy::StrictStaticIp,
            recommended: is_rec,
            title: "严格：仅锁定当前静态 IP".into(),
            subtitle: format!("仅放行精确出口 IP {addr}，节点 IP 一旦变化即拦截"),
            preset: PolicyPreset::StrictStaticIp,
            expect_ips: vec![addr.clone()],
            expect_regions: Vec::new(),
        });
    }

    let suggested_cidr = ip
        .as_deref()
        .and_then(|s| s.parse::<Ipv4Addr>().ok())
        .and_then(|v4| Ipv4Cidr::parse(&format!("{v4}/24")))
        .map(|c| vec![c.canonical()])
        .unwrap_or_default();
    let suggested_regions = country.into_iter().collect::<Vec<_>>();

    options.push(OnboardingOption {
        strategy: OnboardingStrategy::CustomCidrOrRegions,
        recommended: false,
        title: "自定义多国或 CIDR".into(),
        subtitle: "手动配置多国地区代码、精确 IP 或 IPv4 CIDR 子网（如 198.51.100.0/24）".into(),
        preset: PolicyPreset::StandardRegion,
        expect_ips: suggested_cidr,
        expect_regions: suggested_regions,
    });

    OnboardingProbeResult {
        access: access.clone(),
        detected_proxy_port,
        probe: enriched_probe,
        installed_agents,
        recommended_strategy,
        standby_notice,
        options,
    }
}

/// Applies the user's selected onboarding strategy onto `base` and validates the resulting [`Config`].
pub fn apply_choice(
    base: &Config,
    rec: &OnboardingProbeResult,
    choice: OnboardingChoice,
) -> Result<Config, String> {
    let mut cfg = base.clone();
    if let Some(port) = rec.detected_proxy_port
        && port > 0
    {
        cfg.proxy_port = port;
    }
    if let Some(addr) = rec.access.proxy_addr.as_deref()
        && let Some((host, port_str)) = addr.rsplit_once(':')
    {
        let host = host.trim();
        if !host.is_empty() {
            cfg.proxy_host = host.to_string();
        }
        if let Ok(port) = port_str.parse::<u16>()
            && port > 0
        {
            cfg.proxy_port = port;
        }
    }
    if !rec.installed_agents.is_empty() {
        cfg.guarded_agents = clean_guarded_agents(&rec.installed_agents);
    }

    let (preset, expect_ips, expect_regions) = match choice {
        OnboardingChoice::RecommendRegion => {
            let opt = rec
                .options
                .iter()
                .find(|o| o.strategy == OnboardingStrategy::RecommendRegion)
                .ok_or_else(|| "未探测到可用出口地区，无法使用地区推荐策略".to_string())?;
            (
                opt.preset,
                opt.expect_ips.clone(),
                opt.expect_regions.clone(),
            )
        }
        OnboardingChoice::StrictStaticIp => {
            let opt = rec
                .options
                .iter()
                .find(|o| o.strategy == OnboardingStrategy::StrictStaticIp)
                .ok_or_else(|| "未探测到精确出口 IP，无法使用静态 IP 锁定策略".to_string())?;
            (
                opt.preset,
                opt.expect_ips.clone(),
                opt.expect_regions.clone(),
            )
        }
        OnboardingChoice::CustomCidrOrRegions {
            expect_ips,
            expect_regions,
            preset,
        } => (
            preset.unwrap_or(PolicyPreset::StandardRegion),
            expect_ips,
            expect_regions,
        ),
    };

    if expect_ips.is_empty() && expect_regions.is_empty() {
        return Err("至少需要配置一个白名单 IP/CIDR 或地区".to_string());
    }

    cfg.preset = preset;
    for target in &mut cfg.targets {
        if matches!(target.id.as_str(), "local" | "claude" | "codex") {
            target.expect_ips = expect_ips.clone();
            target.expect_regions = expect_regions.clone();
        }
    }
    cfg.targets = targets::validate(cfg.targets)?;
    cfg.first_run = false;
    cfg.migrate();
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cg_protocol::AccessLevel;

    fn sample_probe() -> ProbeResult {
        ProbeResult {
            reachable: true,
            status: Some(200),
            ip: Some("198.51.100.98".into()),
            country: Some("US".into()),
            raw_region: Some("US".into()),
            colo: Some("LAX".into()),
            city: None,
            latency_ms: 45,
            parsed_as: "trace".into(),
            detail: String::new(),
        }
    }

    #[test]
    fn recommends_region_and_applies_choice() {
        let access = AccessEvidence {
            level: AccessLevel::SystemProxy,
            proxy_addr: Some("127.0.0.1:7897".into()),
            observed_at: 1_700_000_000,
            revision: 1,
            ..AccessEvidence::default()
        };
        let rec = recommend(
            &access,
            Some(&sample_probe()),
            Some(7897),
            vec!["claude".into(), "chatgpt".into()],
        );
        assert_eq!(
            rec.recommended_strategy,
            Some(OnboardingStrategy::RecommendRegion)
        );
        assert!(rec.standby_notice.is_none());
        assert_eq!(
            rec.probe.as_ref().and_then(|p| p.city.as_deref()),
            Some("洛杉矶")
        );
        assert_eq!(rec.options.len(), 3);
        assert_eq!(rec.options[2].expect_ips, vec!["198.51.100.0/24"]);

        let cfg = apply_choice(&Config::default(), &rec, OnboardingChoice::RecommendRegion)
            .expect("apply region");
        assert!(!cfg.first_run);
        assert_eq!(cfg.proxy_port, 7897);
        assert_eq!(cfg.preset, PolicyPreset::StandardRegion);
        assert_eq!(cfg.target("claude").unwrap().expect_regions, vec!["US"]);

        let strict = apply_choice(&Config::default(), &rec, OnboardingChoice::StrictStaticIp)
            .expect("apply strict");
        assert_eq!(strict.preset, PolicyPreset::StrictStaticIp);
        assert_eq!(
            strict.target("claude").unwrap().expect_ips,
            vec!["198.51.100.98"]
        );
    }

    #[test]
    fn uncovered_onboarding_returns_standby_notice_without_recommended_rule() {
        let access = AccessEvidence {
            level: AccessLevel::Uncovered,
            note: "系统代理关闭".into(),
            ..AccessEvidence::default()
        };
        let rec = recommend(&access, None, None, vec![]);
        assert!(rec.recommended_strategy.is_none());
        assert!(rec.standby_notice.is_some());
        assert!(apply_choice(&Config::default(), &rec, OnboardingChoice::RecommendRegion).is_err());

        let custom = apply_choice(
            &Config::default(),
            &rec,
            OnboardingChoice::CustomCidrOrRegions {
                expect_ips: vec!["198.51.100.0/24".into()],
                expect_regions: vec![],
                preset: None,
            },
        )
        .expect("custom cidr works even in standby");
        assert!(!custom.first_run);
        assert_eq!(
            custom.target("claude").unwrap().expect_ips,
            vec!["198.51.100.0/24"]
        );
    }

    #[test]
    fn ip_only_probe_recommends_strict_static_ip_and_rejects_empty_custom() {
        let access = AccessEvidence {
            level: AccessLevel::Tun,
            tun_iface: Some("Mihomo".into()),
            route_hint: true,
            observed_at: 100,
            revision: 1,
            note: "TUN".into(),
            ..AccessEvidence::default()
        };
        let ip_only = ProbeResult {
            reachable: true,
            status: Some(200),
            ip: Some("203.0.113.45".into()),
            country: None,
            ..ProbeResult::default()
        };
        let rec = recommend(&access, Some(&ip_only), None, vec![]);
        assert_eq!(
            rec.recommended_strategy,
            Some(OnboardingStrategy::StrictStaticIp)
        );
        assert!(
            apply_choice(
                &Config::default(),
                &rec,
                OnboardingChoice::CustomCidrOrRegions {
                    expect_ips: vec![],
                    expect_regions: vec![],
                    preset: None,
                }
            )
            .is_err()
        );
    }
}
