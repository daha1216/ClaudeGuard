//! Zero-input onboarding strategy recommender from detected proxy/TUN + probed egress.

use crate::geo;
use crate::targets;
use cg_protocol::{
    AccessEvidence, Config, IpRule, Ipv4Cidr, OnboardingOption, OnboardingProbeResult,
    OnboardingStrategy, PolicyPreset, ProbeResult, clean_guarded_agents, normalize_ip,
};
use std::net::{Ipv4Addr, Ipv6Addr};

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
        && let Some(place) = geo::by_colo(colo).filter(|pl| {
            p.country
                .as_deref()
                .is_none_or(|cc| pl.country.eq_ignore_ascii_case(cc))
        })
    {
        p.city = Some(place.city.to_string());
    }

    let ip = enriched_probe.as_ref().and_then(|p| p.ip.clone());
    let country = enriched_probe.as_ref().and_then(|p| p.country.clone());
    let city = enriched_probe.as_ref().and_then(|p| p.city.clone());
    let is_cn_exit = country
        .as_deref()
        .is_some_and(|code| code.eq_ignore_ascii_case("CN"));
    let is_blocked_exit = country
        .as_deref()
        .is_some_and(crate::risk_scorer::is_unsupported_region);

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
    } else if is_cn_exit {
        let exit_desc = match (&city, &ip) {
            (Some(c), Some(addr)) => format!("CN · {c}（{addr}）"),
            (None, Some(addr)) => format!("CN（{addr}）"),
            _ => "CN".into(),
        };
        Some(format!(
            "检测到当前路由出口位于中国大陆直连地址（{exit_desc}），代理分流可能未覆盖目标站点；请切换海外节点或全局代理后重测，切勿直接将 CN 加入白名单。"
        ))
    } else if is_blocked_exit {
        let code_up = country.as_deref().unwrap_or("受限区").to_ascii_uppercase();
        let exit_desc = match (&city, &ip) {
            (Some(c), Some(addr)) => format!("{code_up} · {c}（{addr}）"),
            (None, Some(addr)) => format!("{code_up}（{addr}）"),
            _ => code_up.clone(),
        };
        Some(format!(
            "检测到当前代理出口位于受限封锁地区（{exit_desc}），Anthropic / OpenAI 官方策略禁止该地区访问（10 维安全分将触发清零红线）；请切换至美/日/新等合规节点后重测，切勿直接将该地区加入推荐白名单。"
        ))
    } else {
        None
    };

    let mut options = Vec::new();
    let mut recommended_strategy = None;

    if access_ready
        && !is_blocked_exit
        && let Some(ref code) = country
    {
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

    if access_ready
        && !is_blocked_exit
        && let Some(ref addr) = ip
    {
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

    let suggested_cidr = if is_blocked_exit {
        Vec::new()
    } else if let Some(norm) = ip.as_deref().and_then(normalize_ip) {
        if let Ok(v4) = norm.parse::<Ipv4Addr>() {
            Ipv4Cidr::parse(&format!("{v4}/24"))
                .map(|c| vec![c.canonical()])
                .unwrap_or_default()
        } else if let Ok(v6) = norm.parse::<Ipv6Addr>() {
            IpRule::parse(&format!("{v6}/64"))
                .map(|r| vec![r.canonical()])
                .unwrap_or_default()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };
    let suggested_regions = if is_blocked_exit {
        Vec::new()
    } else {
        country.into_iter().collect::<Vec<_>>()
    };

    options.push(OnboardingOption {
        strategy: OnboardingStrategy::CustomCidrOrRegions,
        recommended: false,
        title: "自定义多国或 CIDR".into(),
        subtitle: "手动配置多国地区代码、精确 IP 或 IPv4/IPv6 CIDR 子网（如 198.51.100.0/24）"
            .into(),
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

fn parse_proxy_host_port(raw: &str) -> Option<(String, u16)> {
    let trimmed = raw.trim();
    let rest = match trimmed.find("://") {
        Some(idx) => {
            let scheme = &trimmed[..idx];
            if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
                return None;
            }
            &trimmed[idx + 3..]
        }
        None => trimmed,
    };
    let rest = rest.trim().trim_end_matches('/');
    if rest.is_empty()
        || rest.chars().any(|c| {
            c.is_whitespace() || c.is_control() || matches!(c, '@' | '/' | '\\' | '?' | '#')
        })
    {
        return None;
    }
    if rest.starts_with('[') {
        let close = rest.find(']')?;
        let inner = &rest[1..close];
        inner.parse::<Ipv6Addr>().ok()?;
        let port_str = rest[close + 1..].strip_prefix(':')?;
        if port_str.is_empty() || !port_str.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let port = port_str.parse::<u16>().ok().filter(|&p| p > 0)?;
        return Some((format!("[{inner}]"), port));
    }
    if rest.contains(']') || rest.matches(':').count() != 1 {
        return None;
    }
    let (host, port_str) = rest.split_once(':')?;
    let host = host.trim();
    if host.is_empty() || port_str.is_empty() || !port_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let port = port_str.parse::<u16>().ok().filter(|&p| p > 0)?;
    Some((host.to_string(), port))
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
        && let Some((host, port)) = parse_proxy_host_port(addr)
    {
        cfg.proxy_host = host;
        cfg.proxy_port = port;
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
    fn onboarding_handles_ipv6_proxy_and_rejects_malformed_proxy_ports() {
        let access_v6 = AccessEvidence {
            level: AccessLevel::SystemProxy,
            proxy_addr: Some("[::1]:7897".into()),
            observed_at: 1_700_000_000,
            revision: 1,
            ..AccessEvidence::default()
        };
        let mut p_v6 = sample_probe();
        p_v6.ip = Some("2606:4700:4700::1111".into());
        let rec_v6 = recommend(&access_v6, Some(&p_v6), None, vec!["claude".into()]);
        assert_eq!(rec_v6.options[2].expect_ips, vec!["2606:4700:4700::/64"]);
        let cfg_v6 = apply_choice(
            &Config::default(),
            &rec_v6,
            OnboardingChoice::RecommendRegion,
        )
        .expect("apply ipv6 proxy");
        assert_eq!(cfg_v6.proxy_host, "[::1]");
        assert_eq!(cfg_v6.proxy_port, 7897);
        assert_eq!(cfg_v6.proxy_url(), "http://[::1]:7897");

        // Portless IPv6 or zero port in proxy_addr must NOT corrupt base proxy_host/proxy_port.
        for bad_addr in ["::1", "[::1]", "127.0.0.1:0", "127.0.0.1:99999"] {
            let bad_acc = AccessEvidence {
                level: AccessLevel::SystemProxy,
                proxy_addr: Some(bad_addr.into()),
                observed_at: 1_700_000_000,
                revision: 1,
                ..AccessEvidence::default()
            };
            let rec_bad = recommend(&bad_acc, Some(&sample_probe()), None, vec![]);
            let cfg_bad = apply_choice(
                &Config::default(),
                &rec_bad,
                OnboardingChoice::RecommendRegion,
            )
            .expect("fallback to base proxy");
            assert_eq!(cfg_bad.proxy_host, "127.0.0.1");
            assert_eq!(cfg_bad.proxy_port, 7890);
        }
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

    #[test]
    fn mainland_cn_egress_never_recommends_region_and_emits_standby_warning() {
        let access = AccessEvidence {
            level: AccessLevel::SystemProxy,
            proxy_addr: Some("127.0.0.1:7890".into()),
            route_hint: true,
            observed_at: 200,
            revision: 1,
            ..AccessEvidence::default()
        };
        let cn_probe = ProbeResult {
            reachable: true,
            status: Some(200),
            ip: Some("203.0.113.88".into()),
            country: Some("CN".into()),
            raw_region: Some("CN".into()),
            colo: Some("SHA".into()),
            latency_ms: 25,
            parsed_as: "trace".into(),
            detail: String::new(),
            city: None,
        };
        let rec = recommend(&access, Some(&cn_probe), Some(7890), vec!["claude".into()]);
        assert!(rec.recommended_strategy.is_none());
        assert!(rec.options.iter().all(|o| !o.recommended));
        assert!(
            !rec.options
                .iter()
                .any(|o| o.strategy == OnboardingStrategy::RecommendRegion)
        );
        let notice = rec.standby_notice.as_deref().expect("CN standby warning");
        assert!(notice.contains("CN"));
        assert!(notice.contains("直连"));
        assert!(apply_choice(&Config::default(), &rec, OnboardingChoice::RecommendRegion).is_err());

        // HK / MO / RU unsupported regions must also NEVER be recommended as compliant allowlists!
        for blocked_cc in ["HK", "MO", "RU"] {
            let mut blocked_probe = cn_probe.clone();
            blocked_probe.country = Some(blocked_cc.into());
            blocked_probe.raw_region = Some(blocked_cc.into());
            blocked_probe.colo = Some("HKG".into());
            let blocked_rec = recommend(
                &access,
                Some(&blocked_probe),
                Some(7890),
                vec!["claude".into()],
            );
            assert!(blocked_rec.recommended_strategy.is_none(), "{blocked_cc}");
            assert!(
                blocked_rec.options.iter().all(|o| !o.recommended),
                "{blocked_cc}"
            );
            assert!(blocked_rec.standby_notice.is_some(), "{blocked_cc}");
        }
    }
}
