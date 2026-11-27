//! Pure deterministic 10-dimension ban-risk & egress safety evaluator (`M2`).
//!
//! Produces a `0..=100` positive [`RiskAssessment`] (`100` = pristine native residential ISP
//! steady state) combining 10 orthogonal dimensions summing to 100 points, plus hard veto caps
//! for fatal anti-ban redlines and Haversine impossible-travel geo-velocity detection.

use std::collections::BTreeSet;

use crate::asn_db;
use crate::geo;
use cg_protocol::{
    AsnClassification, DnsCoherenceReport, ElectronHygieneReport, EnvCheck, GeoVelocityAlert,
    IpPurityReport, RiskAssessment, RiskDimensionItem, SafetyGrade, StunLeakReport, region_name,
};
use serde::{Deserialize, Serialize};

/// Default cross-country teleportation cooldown window in minutes (60 min).
pub const DEFAULT_TELEPORT_COOLDOWN_MINS: u32 = 60;

/// Same-country Anycast drift exemption radius (km).
pub const SAME_COUNTRY_ANYCAST_EXEMPT_KM: u32 = 350;

/// Minimum displacement distance (km) before speed-based (>900 km/h) impossible-travel check applies.
pub const SPEED_TELEPORT_MIN_DIST_KM: u32 = 500;

/// Supersonic travel speed threshold (km/h, faster than commercial airliners).
pub const IMPOSSIBLE_TRAVEL_SPEED_KMH: u32 = 900;

/// Hard veto safety score caps (`0..=100`).
pub const VETO_CAP_UNSUPPORTED_REGION: u8 = 0;
pub const VETO_CAP_STUN_LEAK: u8 = 20;
pub const VETO_CAP_CF_WAF_CHALLENGE: u8 = 20;
pub const VETO_CAP_TOR_EXIT: u8 = 25;
pub const VETO_CAP_IPV6_DUAL_STACK_SPLIT: u8 = 30;
pub const VETO_CAP_IMPOSSIBLE_TRAVEL: u8 = 35;
pub const VETO_CAP_DOMESTIC_DNS_LEAK: u8 = 45;

/// ISO 3166-1 alpha-2 country/region codes blocked by Anthropic / OpenAI terms of service.
pub const UNSUPPORTED_REGIONS: &[&str] = &["CN", "HK", "MO", "RU", "BY", "IR", "KP", "CU", "SY"];

/// Returns `true` if `country` is a hard-blocked / unsupported region.
pub fn is_unsupported_region(country: &str) -> bool {
    let norm = country.trim();
    UNSUPPORTED_REGIONS
        .iter()
        .any(|c| norm.eq_ignore_ascii_case(c))
}

/// Sanitized egress ledger observation fed into [`evaluate_geo_velocity`] (no disk I/O in `cg-core`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EgressObservation {
    pub ip_hmac_hex: String,
    pub subnet_hmac_hex: String,
    pub country: String,
    pub city_or_colo: String,
    /// Optional fixed-point latitude (`degrees * 10`, e.g. `Some(341)` = `34.1°N`; `None` when unknown).
    #[serde(default)]
    pub lat_tenths: Option<i16>,
    /// Optional fixed-point longitude (`degrees * 10`, e.g. `Some(-1182)` = `118.2°W`; `None` when unknown).
    #[serde(default)]
    pub lon_tenths: Option<i16>,
    pub observed_at: u64,
    /// Optional Sovereign Vault identifier (`None` for global ledger).
    #[serde(default)]
    pub vault_id: Option<String>,
}

/// Output of the 7-day geo-velocity and subnet churn evaluator.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GeoVelocityEvaluation {
    pub penalty: u8,
    pub alert: Option<GeoVelocityAlert>,
    pub distinct_subnets_1h: u32,
    pub distinct_subnets_24h: u32,
    pub distinct_countries_24h: u32,
    pub distinct_subnets_7d: u32,
    pub recommended_cooldown_mins: u32,
    pub summary: String,
}

/// All pure inputs required to compute a deterministic 10-dimension [`RiskAssessment`].
#[derive(Clone, Debug)]
pub struct RiskScoringInput {
    pub ip_purity: IpPurityReport,
    pub stun_leak: StunLeakReport,
    pub dns_coherence: DnsCoherenceReport,
    pub electron_hygiene: ElectronHygieneReport,
    pub env_check: Option<EnvCheck>,
    /// Optional `GetUserDefaultGeoName` Windows region code (e.g. `"CN"` or `"US"`).
    pub windows_geo_name: Option<String>,
    /// Optional Windows `AcceptLanguage` primary tag (e.g. `"zh-CN"` or `"en-US"`).
    pub accept_language: Option<String>,
    /// True when `claude.ai` edge returned Cloudflare 403 / `cf-mitigated: challenge`.
    pub edge_challenged: bool,
    /// True when TLS < 1.3 or HTTP downgraded to `http/1.1` on edge trace.
    pub tls_or_http_downgraded: bool,
    /// Active TUN or primary adapter MTU (`< 1280` indicates nested-VPN fragmentation).
    pub active_mtu: Option<u32>,
    /// Observed multi-probe RTT spread / jitter in milliseconds (`> 450ms` warns).
    pub rtt_jitter_ms: u64,
    /// Recent 7-day sanitized egress history (oldest-to-newest or unsorted; filtered by timestamp).
    pub history_7d: Vec<EgressObservation>,
    /// Current egress observation for geo-velocity evaluation.
    pub current_observation: Option<EgressObservation>,
    /// Cross-country teleportation cooldown window in minutes (`0` disables impossible-travel check).
    pub teleport_cooldown_mins: u32,
    /// Current Unix timestamp in seconds.
    pub now_secs: u64,
}

impl Default for RiskScoringInput {
    fn default() -> Self {
        Self {
            ip_purity: IpPurityReport::default(),
            stun_leak: StunLeakReport::default(),
            dns_coherence: DnsCoherenceReport::default(),
            electron_hygiene: ElectronHygieneReport::default(),
            env_check: None,
            windows_geo_name: None,
            accept_language: None,
            edge_challenged: false,
            tls_or_http_downgraded: false,
            active_mtu: None,
            rtt_jitter_ms: 0,
            history_7d: Vec::new(),
            current_observation: None,
            teleport_cooldown_mins: DEFAULT_TELEPORT_COOLDOWN_MINS,
            now_secs: 0,
        }
    }
}

impl RiskScoringInput {
    /// Creates a baseline input stamped at `now_secs` with the default 60-minute teleport cooldown.
    pub fn new(now_secs: u64) -> Self {
        Self {
            now_secs,
            ..Self::default()
        }
    }
}

/// Computes the great-circle Haversine distance in kilometers (rounded) between two
/// fixed-point `0.1°` coordinate pairs.
pub fn haversine_km(lat1_tenths: i16, lon1_tenths: i16, lat2_tenths: i16, lon2_tenths: i16) -> u32 {
    if lat1_tenths == lat2_tenths && lon1_tenths == lon2_tenths {
        return 0;
    }
    let lat1 = (f64::from(lat1_tenths) * 0.1).to_radians();
    let lon1 = (f64::from(lon1_tenths) * 0.1).to_radians();
    let lat2 = (f64::from(lat2_tenths) * 0.1).to_radians();
    let lon2 = (f64::from(lon2_tenths) * 0.1).to_radians();

    let dlat = lat2 - lat1;
    let dlon = lon2 - lon1;
    let a = (dlat * 0.5).sin().powi(2) + lat1.cos() * lat2.cos() * (dlon * 0.5).sin().powi(2);
    let c = 2.0 * a.sqrt().min(1.0).asin();
    (6371.0 * c).round() as u32
}

fn resolve_coords(obs: &EgressObservation) -> Option<(i16, i16)> {
    if let (Some(lat), Some(lon)) = (obs.lat_tenths, obs.lon_tenths)
        && (lat != 0 || lon != 0)
    {
        return Some((lat, lon));
    }
    let colo_opt = (!obs.city_or_colo.trim().is_empty()).then_some(obs.city_or_colo.as_str());
    let country_opt = (!obs.country.trim().is_empty()).then_some(obs.country.as_str());
    if let Some(place) = geo::resolve(colo_opt, country_opt) {
        let lat = (place.lat * 10.0).round() as i16;
        let lon = (place.lon * 10.0).round() as i16;
        if lat != 0 || lon != 0 {
            return Some((lat, lon));
        }
    }
    None
}

fn same_subnet_or_ip(a: &EgressObservation, b: &EgressObservation) -> bool {
    if !a.subnet_hmac_hex.is_empty() && !b.subnet_hmac_hex.is_empty() {
        return a.subnet_hmac_hex == b.subnet_hmac_hex;
    }
    if !a.ip_hmac_hex.is_empty() && !b.ip_hmac_hex.is_empty() {
        return a.ip_hmac_hex == b.ip_hmac_hex;
    }
    false
}

/// Evaluates 7-day subnet churn and impossible-travel geo-velocity between `history_7d` and `current`.
///
/// Rules:
/// - Vault-scoped observations (`current.vault_id.is_some()`) only compare against matching vault entries.
/// - Same `/24` (or `/48`) subnet rotation is treated as zero displacement.
/// - Same-country hops within `350 km` are exempted as normal Anycast edge drift.
/// - Cross-country hops within `teleport_cooldown_mins` OR displacements `> 500 km` with implied
///   speed `> 900 km/h` trigger an impossible-travel [`GeoVelocityAlert`] with recommended cooldown.
pub fn evaluate_geo_velocity(
    history_7d: &[EgressObservation],
    current: &EgressObservation,
    teleport_cooldown_mins: u32,
) -> GeoVelocityEvaluation {
    let now = current.observed_at;
    let mut subnets_1h: BTreeSet<&str> = BTreeSet::new();
    let mut subnets_24h: BTreeSet<&str> = BTreeSet::new();
    let mut countries_24h: BTreeSet<String> = BTreeSet::new();
    let mut subnets_7d: BTreeSet<&str> = BTreeSet::new();

    let curr_key = if !current.subnet_hmac_hex.is_empty() {
        current.subnet_hmac_hex.as_str()
    } else {
        current.ip_hmac_hex.as_str()
    };
    if !curr_key.is_empty() {
        subnets_1h.insert(curr_key);
        subnets_24h.insert(curr_key);
        subnets_7d.insert(curr_key);
    }
    if !current.country.trim().is_empty() {
        countries_24h.insert(current.country.trim().to_ascii_uppercase());
    }

    let mut prev_diff: Option<&EgressObservation> = None;

    for item in history_7d {
        if item.vault_id != current.vault_id {
            continue;
        }
        if item.observed_at > now {
            continue;
        }
        let age = now.saturating_sub(item.observed_at);
        if age > 7 * 86_400 {
            continue;
        }
        let key = if !item.subnet_hmac_hex.is_empty() {
            item.subnet_hmac_hex.as_str()
        } else {
            item.ip_hmac_hex.as_str()
        };
        if !key.is_empty() {
            subnets_7d.insert(key);
            if age <= 86_400 {
                subnets_24h.insert(key);
            }
            if age <= 3_600 {
                subnets_1h.insert(key);
            }
        }
        if age <= 86_400 && !item.country.trim().is_empty() {
            countries_24h.insert(item.country.trim().to_ascii_uppercase());
        }

        if !same_subnet_or_ip(item, current) {
            let replace = match prev_diff {
                None => true,
                Some(best) => item.observed_at >= best.observed_at,
            };
            if replace {
                prev_diff = Some(item);
            }
        }
    }

    let distinct_subnets_1h = subnets_1h.len() as u32;
    let distinct_subnets_24h = subnets_24h.len() as u32;
    let distinct_countries_24h = countries_24h.len() as u32;
    let distinct_subnets_7d = subnets_7d.len() as u32;

    if let Some(prev) = prev_diff {
        let elapsed_secs = now.saturating_sub(prev.observed_at).max(1);
        let elapsed_mins = (elapsed_secs / 60) as u32;
        let coords_pair = resolve_coords(prev).zip(resolve_coords(current));
        let (dist_km, speed_kmh) = match coords_pair {
            Some(((lat1, lon1), (lat2, lon2))) => {
                let d = haversine_km(lat1, lon1, lat2, lon2);
                let s = ((f64::from(d) * 3600.0) / (elapsed_secs as f64)).round() as u32;
                (d, s)
            }
            None => (0, 0),
        };

        let prev_cc = prev.country.trim().to_ascii_uppercase();
        let curr_cc = current.country.trim().to_ascii_uppercase();
        let cross_country = !prev_cc.is_empty() && !curr_cc.is_empty() && prev_cc != curr_cc;

        // Same-country <= 350 km (or same-country with unmapped coordinates) is exempted as normal Anycast drift.
        let is_anycast_jitter =
            !cross_country && coords_pair.is_none_or(|_| dist_km <= SAME_COUNTRY_ANYCAST_EXEMPT_KM);

        let cross_country_teleport = cross_country
            && (elapsed_mins < teleport_cooldown_mins
                || (coords_pair.is_some()
                    && dist_km > SPEED_TELEPORT_MIN_DIST_KM
                    && speed_kmh > IMPOSSIBLE_TRAVEL_SPEED_KMH));
        let supersonic_same_country = !cross_country
            && coords_pair.is_some()
            && dist_km > SPEED_TELEPORT_MIN_DIST_KM
            && speed_kmh > IMPOSSIBLE_TRAVEL_SPEED_KMH;

        if !is_anycast_jitter
            && teleport_cooldown_mins > 0
            && (cross_country_teleport || supersonic_same_country)
        {
            let flight_mins = if coords_pair.is_some() {
                ((f64::from(dist_km) / f64::from(IMPOSSIBLE_TRAVEL_SPEED_KMH)) * 60.0).ceil() as u32
            } else {
                0
            };
            let target_window = teleport_cooldown_mins.max(flight_mins.min(180));
            let cooldown_left_mins = target_window.saturating_sub(elapsed_mins).max(1);
            let cooldown_until = Some(now.saturating_add(u64::from(cooldown_left_mins) * 60));

            let prev_city = if prev.city_or_colo.is_empty() {
                region_name(&prev_cc).to_string()
            } else {
                prev.city_or_colo.clone()
            };
            let curr_city = if current.city_or_colo.is_empty() {
                region_name(&curr_cc).to_string()
            } else {
                current.city_or_colo.clone()
            };

            let summary = if cross_country {
                if coords_pair.is_some() {
                    format!(
                        "检测到跨国瞬移：{} 分钟前使用 {} ({}) 出口，当前为 {} ({}) 出口（跨越 {} km，等效 {} km/h）。建议切回原 {} 节点，或冷却 {} 分钟后再启动。",
                        elapsed_mins.max(1),
                        region_name(&prev_cc),
                        prev_city,
                        region_name(&curr_cc),
                        curr_city,
                        dist_km,
                        speed_kmh,
                        prev_cc,
                        cooldown_left_mins,
                    )
                } else {
                    format!(
                        "检测到跨国瞬移：{} 分钟前使用 {} ({}) 出口，当前为 {} ({}) 出口。建议切回原 {} 节点，或冷却 {} 分钟后再启动。",
                        elapsed_mins.max(1),
                        region_name(&prev_cc),
                        prev_city,
                        region_name(&curr_cc),
                        curr_city,
                        prev_cc,
                        cooldown_left_mins,
                    )
                }
            } else {
                format!(
                    "检测到同国超音速跃迁：{} 分钟前使用 {} ({}) 出口，当前为 {} ({}) 出口（跨越 {} km，等效 {} km/h）。建议固定单城节点，或冷却 {} 分钟后再启动。",
                    elapsed_mins.max(1),
                    region_name(&prev_cc),
                    prev_city,
                    region_name(&curr_cc),
                    curr_city,
                    dist_km,
                    speed_kmh,
                    cooldown_left_mins,
                )
            };

            return GeoVelocityEvaluation {
                penalty: 15,
                alert: Some(GeoVelocityAlert {
                    vault_id: current.vault_id.clone(),
                    from_country: prev_cc,
                    from_city: prev_city,
                    to_country: curr_cc,
                    to_city: curr_city,
                    distance_km: dist_km,
                    elapsed_secs,
                    implied_speed_kmh: speed_kmh,
                    cooldown_until,
                }),
                distinct_subnets_1h,
                distinct_subnets_24h,
                distinct_countries_24h,
                distinct_subnets_7d,
                recommended_cooldown_mins: cooldown_left_mins,
                summary,
            };
        }
    }

    // No impossible travel: evaluate sliding-window subnet / country churn.
    let mut penalty: u8 = match distinct_subnets_1h {
        0 | 1 => 0,
        2 => 4,
        3 => 8,
        _ => 12,
    };
    if distinct_countries_24h >= 3 {
        penalty = penalty.saturating_add(6).min(15);
    }

    let summary = if penalty == 0 {
        "出口地域与子网高度稳定（零瞬移）".to_string()
    } else {
        format!(
            "近 1h 切换 {} 个 /24 网段（24h 跨 {} 国），建议将代理策略组由 url-test 改为手动固定节点",
            distinct_subnets_1h, distinct_countries_24h
        )
    };

    GeoVelocityEvaluation {
        penalty,
        alert: None,
        distinct_subnets_1h,
        distinct_subnets_24h,
        distinct_countries_24h,
        distinct_subnets_7d,
        recommended_cooldown_mins: 0,
        summary,
    }
}

fn enrich_purity_offline(raw: &IpPurityReport) -> IpPurityReport {
    let mut out = raw.clone();
    if let Some(asn) = out.asn
        && let Some((class, org)) = asn_db::lookup_asn(asn)
    {
        if out.classification == AsnClassification::Unknown {
            out.classification = class;
        }
        if out.asn_org.trim().is_empty() {
            out.asn_org = org.to_string();
        }
        if matches!(
            class,
            AsnClassification::DatacenterHosting | AsnClassification::PublicProxyVpnTor
        ) {
            out.is_datacenter = true;
        }
    } else if out.classification == AsnClassification::Unknown && !out.asn_org.trim().is_empty() {
        let inferred = asn_db::classify_org_heuristic(&out.asn_org);
        if inferred != AsnClassification::Unknown {
            out.classification = inferred;
            if matches!(
                inferred,
                AsnClassification::DatacenterHosting | AsnClassification::PublicProxyVpnTor
            ) {
                out.is_datacenter = true;
            }
        }
    }
    out
}

fn abuse_penalty_from_bps(bps: u32) -> u8 {
    if bps < 5 {
        0
    } else if bps < 50 {
        let p = 1.0 + 4.0 * (f64::from(bps - 5) / 45.0);
        p.round().clamp(1.0, 5.0) as u8
    } else if bps < 200 {
        let p = 6.0 + 6.0 * (f64::from(bps - 50) / 150.0);
        p.round().clamp(6.0, 12.0) as u8
    } else if bps < 1000 {
        let p = 13.0 + 4.0 * (f64::from(bps - 200) / 800.0);
        p.round().clamp(13.0, 17.0) as u8
    } else {
        20
    }
}

fn abuse_penalty_from_risk_index(score: u8) -> u8 {
    match score {
        0..=15 => 0,
        16..=35 => {
            let p = 1.0 + 4.0 * (f64::from(score - 16) / 19.0);
            p.round().clamp(1.0, 5.0) as u8
        }
        36..=60 => {
            let p = 6.0 + 6.0 * (f64::from(score - 36) / 24.0);
            p.round().clamp(6.0, 12.0) as u8
        }
        61..=85 => {
            let p = 13.0 + 4.0 * (f64::from(score - 61) / 24.0);
            p.round().clamp(13.0, 17.0) as u8
        }
        _ => 20,
    }
}

fn push_unique_rec(recs: &mut Vec<String>, rec: impl Into<String>) {
    let text = rec.into();
    if !text.is_empty() && !recs.iter().any(|existing| existing == &text) {
        recs.push(text);
    }
}

/// Evaluates all 10 anti-ban dimensions and hard veto caps, returning a deterministic [`RiskAssessment`].
pub fn score_egress_risk(input: &RiskScoringInput) -> RiskAssessment {
    let purity = enrich_purity_offline(&input.ip_purity);
    let mut dimensions: Vec<RiskDimensionItem> = Vec::with_capacity(10);
    let mut recommendations: Vec<String> = Vec::new();
    let mut active_vetoes: Vec<(&'static str, u8)> = Vec::new();

    // ---- D1: ASN Ownership & Commercial Entity Classification (25 pts) ----
    let high_abuse_asn = purity.asn.is_some_and(asn_db::is_high_abuse_proxy_asn);
    let (d1_penalty, d1_detail, d1_rem) = match purity.classification {
        AsnClassification::PublicProxyVpnTor => (
            25u8,
            format!(
                "命中高风险共享代理/VPN 池 ASN（{}）",
                if purity.asn_org.is_empty() {
                    purity.classification.label_zh()
                } else {
                    purity.asn_org.as_str()
                }
            ),
            Some("请立即切换为独享家宽或低滥用商业专线节点".to_string()),
        ),
        _ if high_abuse_asn => (
            25u8,
            format!(
                "命中高风险共享代理/VPN 池 ASN（{}）",
                if purity.asn_org.is_empty() {
                    purity.classification.label_zh()
                } else {
                    purity.asn_org.as_str()
                }
            ),
            Some("请立即切换为独享家宽或低滥用商业专线节点".to_string()),
        ),
        AsnClassification::IspResidential if !purity.is_datacenter => (
            0,
            format!(
                "原生住宅 ISP 宽带（{}）",
                if purity.asn_org.is_empty() {
                    "已核验"
                } else {
                    purity.asn_org.as_str()
                }
            ),
            None,
        ),
        AsnClassification::IspResidential => (
            14,
            format!(
                "检测到伪家宽/机房托管住宅段（{}）",
                if purity.asn_org.is_empty() {
                    "ISP + Hosting"
                } else {
                    purity.asn_org.as_str()
                }
            ),
            Some("建议升级为真原生住宅家宽出口以降低注册/绑卡风控".to_string()),
        ),
        AsnClassification::MobileCellular if !purity.is_datacenter => (
            2,
            format!(
                "移动蜂窝运营商网段（{}）",
                if purity.asn_org.is_empty() {
                    "Mobile"
                } else {
                    purity.asn_org.as_str()
                }
            ),
            None,
        ),
        AsnClassification::EducationGov if !purity.is_datacenter => (
            2,
            format!(
                "高校/科研或政务合规网段（{}）",
                if purity.asn_org.is_empty() {
                    "Edu/Gov"
                } else {
                    purity.asn_org.as_str()
                }
            ),
            None,
        ),
        AsnClassification::BusinessIsp if !purity.is_datacenter => (
            6,
            format!(
                "商业企业专线 ISP（{}）",
                if purity.asn_org.is_empty() {
                    "Business ISP"
                } else {
                    purity.asn_org.as_str()
                }
            ),
            None,
        ),
        AsnClassification::DatacenterHosting
        | AsnClassification::BusinessIsp
        | AsnClassification::MobileCellular
        | AsnClassification::EducationGov => (
            22,
            format!(
                "云机房/VPS 托管网段（{}）",
                if purity.asn_org.is_empty() {
                    "Datacenter"
                } else {
                    purity.asn_org.as_str()
                }
            ),
            Some("机房段仅建议存量老号固定单节点使用，勿用于新号注册或绑卡".to_string()),
        ),
        AsnClassification::Unknown if purity.is_datacenter => (
            22,
            "云机房/VPS 托管网段（is_datacenter=true）".to_string(),
            Some("机房段仅建议存量老号固定单节点使用，勿用于新号注册或绑卡".to_string()),
        ),
        AsnClassification::Unknown => (
            8,
            "ASN 归属暂未识别（离线兜底）".to_string(),
            Some("可点击「立即深度体检」获取完整 ASN 归属信息".to_string()),
        ),
    };
    if let Some(ref r) = d1_rem {
        push_unique_rec(&mut recommendations, r.clone());
    }
    dimensions.push(RiskDimensionItem {
        id: "asn_ownership".into(),
        name: "ASN 归属与网络类型".into(),
        max_score: 25,
        score: 25u8.saturating_sub(d1_penalty),
        healthy: d1_penalty <= 6,
        detail: d1_detail,
        remediation_action: d1_rem,
    });

    // ---- D2: IP & /24 Subnet Abuse Density (20 pts) ----
    let d2_penalty = abuse_penalty_from_bps(purity.abuser_score_bps)
        .max(abuse_penalty_from_risk_index(purity.abuse_risk_score))
        .min(20);
    let d2_rem = (d2_penalty >= 6)
        .then(|| "当前 /24 子网邻居滥用密度较高，建议更换低噪独享节点避免连坐封号".to_string());
    if let Some(ref r) = d2_rem {
        push_unique_rec(&mut recommendations, r.clone());
    }
    let d2_detail = if d2_penalty == 0 {
        format!(
            "子网滥用密度极低（{} bps / 风险指数 {}）",
            purity.abuser_score_bps, purity.abuse_risk_score
        )
    } else {
        format!(
            "检测到子网滥用噪音（{} bps / 风险指数 {}，扣 {} 分）",
            purity.abuser_score_bps, purity.abuse_risk_score, d2_penalty
        )
    };
    dimensions.push(RiskDimensionItem {
        id: "abuse_density".into(),
        name: "IP 与 /24 子网滥用密度".into(),
        max_score: 20,
        score: 20u8.saturating_sub(d2_penalty),
        healthy: d2_penalty <= 5,
        detail: d2_detail,
        remediation_action: d2_rem,
    });

    // ---- D3: Public Proxy / VPN / Tor / Relay Blacklist Flags (15 pts) ----
    let (d3_penalty, d3_detail, d3_rem) = if purity.is_tor {
        active_vetoes.push(("Tor 匿名出口红线", VETO_CAP_TOR_EXIT));
        (
            15u8,
            "出口命中 Tor 匿名网络节点（触发红线封顶 <= 25）".to_string(),
            Some("立即断开 Tor 出口并切换至合规固定节点".to_string()),
        )
    } else if purity.is_proxy_or_vpn && purity.is_bogon_or_relay {
        (
            13,
            "同时命中公共 VPN/代理库与中继/异常标记".to_string(),
            Some("切换至非公开代理池的独享固定出口".to_string()),
        )
    } else if purity.is_proxy_or_vpn {
        (
            10,
            "命中公开代理或商业 VPN IP 黑名单".to_string(),
            Some("建议更换未被公开 VPN 数据库收录的独享节点".to_string()),
        )
    } else if purity.is_bogon_or_relay {
        (
            6,
            "命中共享中继（WARP / iCloud Relay）或保留段异常标记".to_string(),
            Some("共享中继稳定性较差，建议改用固定独享出口".to_string()),
        )
    } else {
        (
            0,
            "未命中任何公开 VPN / 代理 / Tor 黑名单".to_string(),
            None,
        )
    };
    if let Some(ref r) = d3_rem {
        push_unique_rec(&mut recommendations, r.clone());
    }
    dimensions.push(RiskDimensionItem {
        id: "blacklist_flags".into(),
        name: "代理 / VPN / Tor 黑名单标记".into(),
        max_score: 15,
        score: 15u8.saturating_sub(d3_penalty),
        healthy: d3_penalty == 0,
        detail: d3_detail,
        remediation_action: d3_rem,
    });

    // ---- D4: Geo-Velocity & 7-Day Subnet Churn (15 pts) ----
    let current_obs = input.current_observation.clone().or_else(|| {
        let country = purity.country.clone()?;
        Some(EgressObservation {
            ip_hmac_hex: purity.ip.clone().unwrap_or_default(),
            subnet_hmac_hex: String::new(),
            country,
            city_or_colo: purity.city.clone().unwrap_or_default(),
            lat_tenths: purity.lat_tenths,
            lon_tenths: purity.lon_tenths,
            observed_at: input.now_secs.max(purity.checked_at),
            vault_id: None,
        })
    });

    let geo_eval = match current_obs.as_ref() {
        Some(obs) => evaluate_geo_velocity(&input.history_7d, obs, input.teleport_cooldown_mins),
        None => GeoVelocityEvaluation {
            penalty: 0,
            alert: None,
            distinct_subnets_1h: u32::from(purity.ip.is_some()),
            distinct_subnets_24h: u32::from(purity.ip.is_some()),
            distinct_countries_24h: u32::from(purity.country.is_some()),
            distinct_subnets_7d: u32::from(purity.ip.is_some()),
            recommended_cooldown_mins: 0,
            summary: "暂无足够历史轨迹，出口地域稳定".to_string(),
        },
    };
    if geo_eval.alert.is_some() {
        active_vetoes.push(("跨国瞬移风控红线", VETO_CAP_IMPOSSIBLE_TRAVEL));
    }
    let d4_rem = if geo_eval.alert.is_some() {
        Some("切回原地区节点或等待瞬移冷却窗口结束再启动客户端".to_string())
    } else if geo_eval.penalty > 0 {
        Some("将 Mihomo/Clash 策略组改为手动固定单节点，避免 url-test 自动乱跳".to_string())
    } else {
        None
    };
    if let Some(ref r) = d4_rem {
        push_unique_rec(&mut recommendations, r.clone());
    }
    dimensions.push(RiskDimensionItem {
        id: "geo_velocity".into(),
        name: "地域稳定性与跨国瞬移检测".into(),
        max_score: 15,
        score: 15u8.saturating_sub(geo_eval.penalty),
        healthy: geo_eval.penalty == 0,
        detail: geo_eval.summary.clone(),
        remediation_action: d4_rem,
    });

    // ---- D5: Edge Trace Status & Supported Region (8 pts) ----
    let v4_country = purity.country.as_deref().map(str::trim).unwrap_or("");
    let unsupported_v4 = !v4_country.is_empty() && is_unsupported_region(v4_country);
    let (d5_penalty, d5_detail, d5_rem) = if unsupported_v4 {
        active_vetoes.push(("受限地区出口红线", VETO_CAP_UNSUPPORTED_REGION));
        (
            8u8,
            format!(
                "出口地区 {} ({}) 属于 Anthropic/OpenAI 受限封锁区（安全分清零）",
                v4_country.to_ascii_uppercase(),
                region_name(v4_country)
            ),
            Some("立即切换至美国/日本/新加坡等合规白名单地区节点".to_string()),
        )
    } else if input.edge_challenged {
        active_vetoes.push(("Cloudflare WAF 质询拦截", VETO_CAP_CF_WAF_CHALLENGE));
        (
            8,
            "目标边缘返回 Cloudflare 403 / 质询拦截，当前出口信誉受损".to_string(),
            Some("当前节点已被目标 WAF 标记，请立即更换出口节点".to_string()),
        )
    } else if input.tls_or_http_downgraded {
        (
            4,
            "边缘协议栈发生 TLS/HTTP 降级，疑似存在中间人代理或劣质转发".to_string(),
            Some("检查上游代理链路是否支持原生 TLS 1.3 + HTTP/2".to_string()),
        )
    } else if v4_country.is_empty() {
        (
            2,
            "尚未确认边缘出口国家码".to_string(),
            Some("请先执行一次合规链路探测以确认边缘出口地区".to_string()),
        )
    } else {
        (
            0,
            format!(
                "边缘出口 {} ({}) 合规且协议栈正常",
                v4_country.to_ascii_uppercase(),
                region_name(v4_country)
            ),
            None,
        )
    };
    if let Some(ref r) = d5_rem {
        push_unique_rec(&mut recommendations, r.clone());
    }
    dimensions.push(RiskDimensionItem {
        id: "edge_trace_status".into(),
        name: "边缘合规与 WAF 指纹状态".into(),
        max_score: 8,
        score: 8u8.saturating_sub(d5_penalty),
        healthy: d5_penalty == 0,
        detail: d5_detail,
        remediation_action: d5_rem,
    });

    // ---- D6: IPv4 / IPv6 Dual-Stack Coherence (5 pts) ----
    let v6_country = purity
        .ipv6_egress_country
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let v6_split_critical =
        !unsupported_v4 && !v4_country.is_empty() && v6_country.is_some_and(is_unsupported_region);
    let v6_country_mismatch = !v6_split_critical
        && (purity.dual_stack_split_detected
            || (!v4_country.is_empty()
                && v6_country.is_some_and(|v6c| !v6c.eq_ignore_ascii_case(v4_country))));

    let (d6_penalty, d6_detail, d6_rem) = if v6_split_critical {
        active_vetoes.push(("IPv6 双栈直连脑裂", VETO_CAP_IPV6_DUAL_STACK_SPLIT));
        (
            5u8,
            format!(
                "检测到 IPv4/IPv6 双栈脑裂（IPv4={}，IPv6={}，触发红线封顶 <= 30）",
                if v4_country.is_empty() {
                    "海外代理"
                } else {
                    v4_country
                },
                v6_country.unwrap_or("国内直连")
            ),
            Some("在「防漏护盾」中一键开启 WFP IPv6 护盾阻断直连泄露".to_string()),
        )
    } else if v6_country_mismatch {
        (
            3,
            format!(
                "IPv4 ({}) 与 IPv6 ({}) 出口国家不一致",
                v4_country,
                v6_country.unwrap_or("未知")
            ),
            Some("建议开启 IPv6 护盾或统一代理节点的双栈出口国家".to_string()),
        )
    } else {
        (
            0,
            match v6_country {
                Some(v6c) => format!("双栈出口国家一致（IPv6={v6c}）"),
                None => "IPv6 不可达或已被护盾隔离（纯单栈受控）".to_string(),
            },
            None,
        )
    };
    if let Some(ref r) = d6_rem {
        push_unique_rec(&mut recommendations, r.clone());
    }
    dimensions.push(RiskDimensionItem {
        id: "dual_stack_coherence".into(),
        name: "IPv4 / IPv6 双栈一致性".into(),
        max_score: 5,
        score: 5u8.saturating_sub(d6_penalty),
        healthy: d6_penalty == 0,
        detail: d6_detail,
        remediation_action: d6_rem,
    });

    // ---- D7: DNS Recursive Resolver Geo Coherence (4 pts) ----
    let (d7_penalty, d7_detail, d7_rem) = if input.dns_coherence.domestic_resolver_detected {
        active_vetoes.push(("DNS 国内递归泄露", VETO_CAP_DOMESTIC_DNS_LEAK));
        (
            4u8,
            "检测到国内 DNS 递归出口泄露（触发红线封顶 <= 45）".to_string(),
            Some("开启代理客户端 Fake-IP / 远端 DoH，并启用 WFP DNS 53 端口护盾".to_string()),
        )
    } else if input.dns_coherence.checked_at > 0
        && !input.dns_coherence.coherent
        && !input.dns_coherence.fake_ip_active
    {
        (
            2,
            format!(
                "DNS 解析器所在地区与 HTTP 出口不一致（{}）",
                if input.dns_coherence.resolver_countries.is_empty() {
                    "第三国解析".to_string()
                } else {
                    input.dns_coherence.resolver_countries.join("/")
                }
            ),
            Some("建议开启 Clash/Mihomo Fake-IP 或使用与出口同区的远端 DNS".to_string()),
        )
    } else {
        (
            0,
            if input.dns_coherence.fake_ip_active {
                "Fake-IP 远端代理解析已生效，无本地 DNS 泄露".to_string()
            } else if !input.dns_coherence.summary.is_empty() {
                input.dns_coherence.summary.clone()
            } else {
                "DNS 递归出口与代理地理一致".to_string()
            },
            None,
        )
    };
    if let Some(ref r) = d7_rem {
        push_unique_rec(&mut recommendations, r.clone());
    }
    dimensions.push(RiskDimensionItem {
        id: "dns_coherence".into(),
        name: "DNS 地理一致性与防泄露".into(),
        max_score: 4,
        score: 4u8.saturating_sub(d7_penalty),
        healthy: d7_penalty == 0,
        detail: d7_detail,
        remediation_action: d7_rem,
    });

    // ---- D8: OS Timezone + Locale + Windows GeoName + Accept-Language (4 pts) ----
    let mut d8_penalty: u8 = 0;
    let mut d8_notes: Vec<String> = Vec::new();
    if let Some(env) = &input.env_check {
        if env.tz_match == Some(false) {
            d8_penalty = d8_penalty.saturating_add(2);
            d8_notes.push("系统时区与出口不匹配".to_string());
        }
        if env.locale_match == Some(false) {
            d8_penalty = d8_penalty.saturating_add(1);
            d8_notes.push("系统 Locale 区域与出口不匹配".to_string());
        }
    }
    let geo_mismatch = !v4_country.is_empty()
        && input
            .windows_geo_name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .is_some_and(|g| !g.eq_ignore_ascii_case(v4_country));
    let lang_cn_mismatch = !v4_country.is_empty()
        && !v4_country.eq_ignore_ascii_case("CN")
        && input
            .accept_language
            .as_deref()
            .map(str::trim)
            .is_some_and(|l| l.to_ascii_lowercase().starts_with("zh-cn"));
    if geo_mismatch || lang_cn_mismatch {
        d8_penalty = d8_penalty.saturating_add(1);
        d8_notes.push("Windows 地区设置/首选语言与出口地区存在偏差".to_string());
    }
    d8_penalty = d8_penalty.min(4);
    let d8_rem = (d8_penalty > 0)
        .then(|| "可在「环境与防漏」中开启时区对齐或调整 Windows 地区设置".to_string());
    if let Some(ref r) = d8_rem {
        push_unique_rec(&mut recommendations, r.clone());
    }
    let d8_detail = if d8_notes.is_empty() {
        "操作系统时区、区域与语言指纹自洽".to_string()
    } else {
        d8_notes.join("；")
    };
    dimensions.push(RiskDimensionItem {
        id: "os_env_coherence".into(),
        name: "系统时区与区域指纹自洽".into(),
        max_score: 4,
        score: 4u8.saturating_sub(d8_penalty),
        healthy: d8_penalty == 0,
        detail: d8_detail,
        remediation_action: d8_rem,
    });

    // ---- D9: WebRTC ICE STUN UDP Exposure (2 pts) ----
    let stun_foreign_mismatch = !input.stun_leak.leaked
        && input.stun_leak.stun_reachable_direct
        && !v4_country.is_empty()
        && input
            .stun_leak
            .reflexive_country
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .is_some_and(|rc| !rc.eq_ignore_ascii_case(v4_country));

    let (d9_penalty, d9_detail, d9_rem) = if input.stun_leak.leaked {
        active_vetoes.push(("WebRTC STUN 真实 IP 泄露", VETO_CAP_STUN_LEAK));
        (
            2u8,
            "STUN UDP 探测反射出真实直连公网 IP（触发红线封顶 <= 20）".to_string(),
            Some("立即开启 Electron WebRTC 防漏参数并启用 WFP 仅隧道放行策略".to_string()),
        )
    } else if stun_foreign_mismatch {
        (
            1,
            "UDP STUN 出口与 HTTP 代理处于不同海外地区".to_string(),
            Some("检查代理客户端 UDP 转发策略与 TCP 节点是否一致".to_string()),
        )
    } else {
        (
            0,
            if !input.stun_leak.summary.is_empty() {
                input.stun_leak.summary.clone()
            } else {
                "WebRTC STUN UDP 已隔离或与代理出口一致".to_string()
            },
            None,
        )
    };
    if let Some(ref r) = d9_rem {
        push_unique_rec(&mut recommendations, r.clone());
    }
    dimensions.push(RiskDimensionItem {
        id: "webrtc_stun_exposure".into(),
        name: "WebRTC STUN UDP 防漏探针".into(),
        max_score: 2,
        score: 2u8.saturating_sub(d9_penalty),
        healthy: d9_penalty == 0,
        detail: d9_detail,
        remediation_action: d9_rem,
    });

    // ---- D10: Electron Hygiene & Tunnel MTU / RTT Stability (2 pts) ----
    let mut d10_penalty: u8 = 0;
    let mut d10_notes: Vec<String> = Vec::new();
    let hygiene_issue = !input.electron_hygiene.unguarded_running_agents.is_empty()
        || (input.electron_hygiene.checked_at > 0
            && (!input.electron_hygiene.webrtc_flag_enforced
                || !input.electron_hygiene.quic_disabled_flag));
    if hygiene_issue {
        d10_penalty = d10_penalty.saturating_add(1);
        if !input.electron_hygiene.unguarded_running_agents.is_empty() {
            d10_notes.push(format!(
                "检测到未注入防漏参数的裸启客户端：{}",
                input.electron_hygiene.unguarded_running_agents.join("、")
            ));
        } else {
            d10_notes.push("运行态 Electron 缺少 QUIC/WebRTC 防漏启动参数".to_string());
        }
    }
    let mtu_low = input.active_mtu.is_some_and(|mtu| mtu > 0 && mtu < 1280);
    let high_jitter = input.rtt_jitter_ms > 450;
    if mtu_low || high_jitter {
        d10_penalty = d10_penalty.saturating_add(1);
        if mtu_low {
            d10_notes.push(format!(
                "出口网卡 MTU 异常偏小（{} < 1280，疑似多层套娃隧道）",
                input.active_mtu.unwrap_or(0)
            ));
        }
        if high_jitter {
            d10_notes.push(format!(
                "探测延迟抖动偏高（{} ms > 450 ms）",
                input.rtt_jitter_ms
            ));
        }
    }
    d10_penalty = d10_penalty.min(2);
    let d10_rem = if hygiene_issue {
        Some("通过 ClaudeGuard 安全启动台重新启动 Electron 客户端以注入防漏参数".to_string())
    } else if mtu_low || high_jitter {
        Some("检查代理链路是否存在多层套娃转发或高负载拥塞".to_string())
    } else {
        None
    };
    if let Some(ref r) = d10_rem {
        push_unique_rec(&mut recommendations, r.clone());
    }
    let d10_detail = if d10_notes.is_empty() {
        "Electron 防漏卫生参数与隧道稳定性正常".to_string()
    } else {
        d10_notes.join("；")
    };
    dimensions.push(RiskDimensionItem {
        id: "electron_hygiene_tunnel".into(),
        name: "客户端卫生舱与隧道稳定性".into(),
        max_score: 2,
        score: 2u8.saturating_sub(d10_penalty),
        healthy: d10_penalty == 0,
        detail: d10_detail,
        remediation_action: d10_rem,
    });

    // ---- Aggregate Raw Score + Hard Veto Caps ----
    let raw_score: u8 = dimensions
        .iter()
        .map(|d| d.score)
        .fold(0u8, |acc, s| acc.saturating_add(s))
        .min(100);
    let min_cap = active_vetoes
        .iter()
        .map(|(_, cap)| *cap)
        .min()
        .unwrap_or(100);
    let final_score = raw_score.min(min_cap);
    let grade = SafetyGrade::from_score(final_score);

    let headline = if !active_vetoes.is_empty() {
        let labels: Vec<&str> = active_vetoes.iter().map(|(label, _)| *label).collect();
        format!(
            "{} 级（{}/100）· 触发红线封顶：{}",
            grade.code(),
            final_score,
            labels.join("、")
        )
    } else {
        match grade {
            SafetyGrade::S => format!("S 级（{final_score}/100）· 原生住宅级高纯净稳态"),
            SafetyGrade::A => format!("A 级（{final_score}/100）· 优质合规稳定出口"),
            SafetyGrade::B => format!("B 级（{final_score}/100）· 常规云机房/固定出口可用"),
            SafetyGrade::C => format!("C 级（{final_score}/100）· 风险偏高，建议优化节点或环境"),
            SafetyGrade::F => format!("F 级（{final_score}/100）· 高危封号风险，建议暂停启动"),
        }
    };

    let evaluated_at = input
        .now_secs
        .max(purity.checked_at)
        .max(input.stun_leak.checked_at)
        .max(input.dns_coherence.checked_at);

    RiskAssessment {
        score: final_score,
        grade,
        headline,
        dimensions,
        recommendations,
        geo_velocity_alert: geo_eval.alert,
        distinct_subnets_1h: geo_eval.distinct_subnets_1h,
        distinct_countries_24h: geo_eval.distinct_countries_24h,
        ip_purity: purity,
        stun_leak: input.stun_leak.clone(),
        dns_coherence: input.dns_coherence.clone(),
        electron_hygiene: input.electron_hygiene.clone(),
        evaluated_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pristine_input(now_secs: u64) -> RiskScoringInput {
        RiskScoringInput {
            ip_purity: IpPurityReport {
                ip: Some("73.120.45.10".into()),
                country: Some("US".into()),
                city: Some("Los Angeles".into()),
                lat_tenths: Some(341),
                lon_tenths: Some(-1182),
                asn: Some(7922),
                asn_org: "Comcast Cable".into(),
                classification: AsnClassification::IspResidential,
                abuse_risk_score: 0,
                abuser_score_bps: 2,
                is_datacenter: false,
                is_proxy_or_vpn: false,
                is_tor: false,
                is_bogon_or_relay: false,
                dual_stack_split_detected: false,
                ipv6_egress_country: None,
                source_tag: "ipapi_is".into(),
                checked_at: now_secs,
            },
            stun_leak: StunLeakReport {
                checked_at: now_secs,
                stun_reachable_direct: false,
                leaked: false,
                reflexive_ip: None,
                reflexive_country: None,
                summary: "STUN blocked".into(),
            },
            dns_coherence: DnsCoherenceReport {
                checked_at: now_secs,
                coherent: true,
                domestic_resolver_detected: false,
                fake_ip_active: true,
                resolver_countries: vec!["US".into()],
                summary: "Fake-IP active".into(),
            },
            electron_hygiene: ElectronHygieneReport {
                checked_at: now_secs,
                webrtc_flag_enforced: true,
                quic_disabled_flag: true,
                host_resolver_enforced: true,
                unguarded_running_agents: Vec::new(),
                summary: "OK".into(),
            },
            active_mtu: Some(1500),
            rtt_jitter_ms: 25,
            now_secs,
            ..RiskScoringInput::new(now_secs)
        }
    }

    #[test]
    fn pristine_residential_scores_100_grade_s_and_dimensions_sum_to_100() {
        let res = score_egress_risk(&pristine_input(10_000));
        assert_eq!(res.dimensions.len(), 10);
        let max_sum: u32 = res.dimensions.iter().map(|d| u32::from(d.max_score)).sum();
        assert_eq!(max_sum, 100);
        assert_eq!(res.score, 100);
        assert_eq!(res.grade, SafetyGrade::S);
        assert!(res.geo_velocity_alert.is_none());
        assert_eq!(res.evaluated_at, 10_000);
    }

    #[test]
    fn clean_datacenter_vps_scores_in_usable_band_and_enriches_asn_offline() {
        let mut input = pristine_input(10_000);
        input.ip_purity.asn = Some(16509);
        input.ip_purity.asn_org.clear();
        input.ip_purity.classification = AsnClassification::Unknown;
        input.ip_purity.is_datacenter = false;

        let res = score_egress_risk(&input);
        assert_eq!(
            res.ip_purity.classification,
            AsnClassification::DatacenterHosting
        );
        assert!(res.ip_purity.is_datacenter);
        assert!(res.ip_purity.asn_org.contains("Amazon"));
        assert_eq!(res.score, 78);
        assert_eq!(res.grade, SafetyGrade::A);
    }

    #[test]
    fn hard_veto_caps_enforce_exact_upper_bounds() {
        // 1) Tor <= 25
        let mut tor = pristine_input(10_000);
        tor.ip_purity.is_tor = true;
        let r_tor = score_egress_risk(&tor);
        assert!(r_tor.score <= 25, "Tor score was {}", r_tor.score);
        assert_eq!(r_tor.grade, SafetyGrade::F);

        // 2) STUN leak <= 20
        let mut stun = pristine_input(10_000);
        stun.stun_leak.leaked = true;
        stun.stun_leak.stun_reachable_direct = true;
        let r_stun = score_egress_risk(&stun);
        assert!(r_stun.score <= 20, "STUN leak score was {}", r_stun.score);
        assert_eq!(r_stun.grade, SafetyGrade::F);

        // 3) IPv6 dual-stack split <= 30
        let mut v6 = pristine_input(10_000);
        v6.ip_purity.dual_stack_split_detected = true;
        v6.ip_purity.ipv6_egress_country = Some("CN".into());
        let r_v6 = score_egress_risk(&v6);
        assert!(r_v6.score <= 30, "IPv6 split score was {}", r_v6.score);
        assert_eq!(r_v6.grade, SafetyGrade::F);

        // 4) Impossible travel <= 35
        let mut travel = pristine_input(10_000);
        travel.history_7d.push(EgressObservation {
            ip_hmac_hex: "aaa".into(),
            subnet_hmac_hex: "sub-us".into(),
            country: "US".into(),
            city_or_colo: "LAX".into(),
            lat_tenths: Some(341),
            lon_tenths: Some(-1182),
            observed_at: 9_700, // 5 min earlier
            vault_id: None,
        });
        travel.current_observation = Some(EgressObservation {
            ip_hmac_hex: "bbb".into(),
            subnet_hmac_hex: "sub-jp".into(),
            country: "JP".into(),
            city_or_colo: "NRT".into(),
            lat_tenths: Some(357),
            lon_tenths: Some(1398),
            observed_at: 10_000,
            vault_id: None,
        });
        let r_travel = score_egress_risk(&travel);
        assert!(
            r_travel.score <= 35,
            "Impossible travel score was {}",
            r_travel.score
        );
        assert!(r_travel.geo_velocity_alert.is_some());
        assert_eq!(r_travel.grade, SafetyGrade::F);

        // 5) Domestic DNS leak <= 45
        let mut dns = pristine_input(10_000);
        dns.dns_coherence.domestic_resolver_detected = true;
        dns.dns_coherence.coherent = false;
        dns.dns_coherence.fake_ip_active = false;
        let r_dns = score_egress_risk(&dns);
        assert!(
            r_dns.score <= 45,
            "Domestic DNS leak score was {}",
            r_dns.score
        );
        assert_eq!(r_dns.grade, SafetyGrade::C);

        // 6) Unsupported region == 0
        let mut cn = pristine_input(10_000);
        cn.ip_purity.country = Some("CN".into());
        let r_cn = score_egress_risk(&cn);
        assert_eq!(r_cn.score, 0);
        assert_eq!(r_cn.grade, SafetyGrade::F);

        // 7) Cloudflare WAF challenge <= 20
        let mut waf = pristine_input(10_000);
        waf.edge_challenged = true;
        let r_waf = score_egress_risk(&waf);
        assert!(r_waf.score <= 20, "WAF challenge score was {}", r_waf.score);
    }

    #[test]
    fn haversine_computes_accurate_great_circle_distances() {
        assert_eq!(haversine_km(341, -1182, 341, -1182), 0);

        // Los Angeles (34.1, -118.2) <-> Tokyo (35.7, 139.8) ~ 8,800 km
        let lax_nrt = haversine_km(341, -1182, 357, 1398);
        assert!(
            (8_650..=8_950).contains(&lax_nrt),
            "unexpected LAX-NRT distance: {lax_nrt} km"
        );

        // Los Angeles (34.1, -118.2) <-> San Diego (32.7, -117.2) ~ 180 km (within 350km Anycast exemption)
        let lax_san = haversine_km(341, -1182, 327, -1172);
        assert!(
            (150..=220).contains(&lax_san),
            "unexpected LAX-SAN distance: {lax_san} km"
        );
    }

    #[test]
    fn geo_velocity_exempts_same_country_anycast_and_flags_supersonic_cross_country() {
        // Same-country <= 350 km drift (LA -> San Diego in 60s): exempted!
        let history_local = vec![EgressObservation {
            ip_hmac_hex: "ip1".into(),
            subnet_hmac_hex: "sub1".into(),
            country: "US".into(),
            city_or_colo: "LAX".into(),
            lat_tenths: Some(341),
            lon_tenths: Some(-1182),
            observed_at: 10_000,
            vault_id: None,
        }];
        let curr_local = EgressObservation {
            ip_hmac_hex: "ip2".into(),
            subnet_hmac_hex: "sub2".into(),
            country: "US".into(),
            city_or_colo: "SAN".into(),
            lat_tenths: Some(327),
            lon_tenths: Some(-1172),
            observed_at: 10_060,
            vault_id: None,
        };
        let eval_local = evaluate_geo_velocity(&history_local, &curr_local, 60);
        assert!(eval_local.alert.is_none());
        assert_eq!(eval_local.distinct_subnets_1h, 2);

        // Cross-country US -> JP in 4 min: impossible travel + cooldown
        let curr_jp = EgressObservation {
            ip_hmac_hex: "ip3".into(),
            subnet_hmac_hex: "sub-jp".into(),
            country: "JP".into(),
            city_or_colo: "NRT".into(),
            lat_tenths: Some(357),
            lon_tenths: Some(1398),
            observed_at: 10_240,
            vault_id: None,
        };
        let eval_jp = evaluate_geo_velocity(&history_local, &curr_jp, 60);
        let alert = eval_jp
            .alert
            .expect("expected impossible travel alert for US->JP in 4m");
        assert_eq!(eval_jp.penalty, 15);
        assert_eq!(alert.from_country, "US");
        assert_eq!(alert.to_country, "JP");
        assert!(alert.implied_speed_kmh > 900);
        assert!(alert.cooldown_until.unwrap() > curr_jp.observed_at);
        assert!(eval_jp.recommended_cooldown_mins >= 50);

        // Cross-country US -> JP after 14 hours (speed ~630 km/h <= 900, elapsed > 60m): legitimate travel!
        let mut curr_jp_flight = curr_jp.clone();
        curr_jp_flight.observed_at = 10_000 + 14 * 3_600;
        let eval_flight = evaluate_geo_velocity(&history_local, &curr_jp_flight, 60);
        assert!(eval_flight.alert.is_none());
        assert_eq!(eval_flight.penalty, 0);

        // Per-vault isolation: vault-b must NOT collide with vault-a history, and global (None) must NOT collide with vault-a!
        let mut hist_vault_a = history_local;
        hist_vault_a[0].vault_id = Some("vault-a".into());
        let mut curr_vault_b = curr_jp.clone();
        curr_vault_b.vault_id = Some("vault-b".into());
        let eval_isolated = evaluate_geo_velocity(&hist_vault_a, &curr_vault_b, 60);
        assert!(eval_isolated.alert.is_none());

        let eval_global_vs_vault = evaluate_geo_velocity(&hist_vault_a, &curr_jp, 60);
        assert!(
            eval_global_vs_vault.alert.is_none(),
            "global observation (vault_id=None) must ignore vault-scoped history"
        );
    }

    #[test]
    fn null_island_missing_coords_never_false_trips_same_country_and_compliant_dual_stack_warns_only()
     {
        // 1) US (LAX known coords) -> US (unmapped small town, None coords or (0,0)): must NOT trip Null Island!
        let hist_us = vec![EgressObservation {
            ip_hmac_hex: "us1".into(),
            subnet_hmac_hex: "sub-us1".into(),
            country: "US".into(),
            city_or_colo: "Los Angeles".into(),
            lat_tenths: Some(341),
            lon_tenths: Some(-1182),
            observed_at: 10_000,
            vault_id: None,
        }];
        for (lat_opt, lon_opt) in [(None, None), (Some(0), Some(0))] {
            let curr_unmapped = EgressObservation {
                ip_hmac_hex: "us2".into(),
                subnet_hmac_hex: "sub-us2".into(),
                country: "US".into(),
                city_or_colo: "Bozeman".into(),
                lat_tenths: lat_opt,
                lon_tenths: lon_opt,
                observed_at: 10_030,
                vault_id: None,
            };
            let ev = evaluate_geo_velocity(&hist_us, &curr_unmapped, 60);
            assert!(
                ev.alert.is_none(),
                "unmapped same-country US hop must never compute distance to Null Island (0,0): {ev:?}"
            );
        }

        // 2) Unmapped cross-country US -> CA within cooldown window still enforces teleport_cooldown_mins with 0 fake distance.
        let curr_ca_unmapped = EgressObservation {
            ip_hmac_hex: "ca1".into(),
            subnet_hmac_hex: "sub-ca1".into(),
            country: "CA".into(),
            city_or_colo: "Saskatoon".into(),
            lat_tenths: None,
            lon_tenths: None,
            observed_at: 10_300, // 5m later
            vault_id: None,
        };
        let ev_cross = evaluate_geo_velocity(&hist_us, &curr_ca_unmapped, 60);
        let alert_cross = ev_cross.alert.expect("cross-country within 60m must alert");
        assert_eq!(alert_cross.distance_km, 0);
        assert_eq!(alert_cross.implied_speed_kmh, 0);
        assert_eq!(ev_cross.recommended_cooldown_mins, 55);

        // 3) Same-country supersonic (LAX -> JFK in 2m) uses accurate same-country copy.
        let curr_jfk = EgressObservation {
            ip_hmac_hex: "us-jfk".into(),
            subnet_hmac_hex: "sub-jfk".into(),
            country: "US".into(),
            city_or_colo: "New York".into(),
            lat_tenths: None,
            lon_tenths: None,
            observed_at: 10_120,
            vault_id: None,
        };
        let ev_same_super = evaluate_geo_velocity(&hist_us, &curr_jfk, 60);
        assert!(ev_same_super.alert.is_some());
        assert!(ev_same_super.summary.contains("同国超音速跃迁"));

        // 4) Compliant cross-country IPv6 (US v4 + CA v6 with dual_stack_split_detected=true) deducts 3 pts WITHOUT <=30 veto!
        let mut us_ca_v6 = pristine_input(10_000);
        us_ca_v6.ip_purity.dual_stack_split_detected = true;
        us_ca_v6.ip_purity.ipv6_egress_country = Some("CA".into());
        let res_v6 = score_egress_risk(&us_ca_v6);
        assert_eq!(res_v6.score, 97);
        assert_eq!(res_v6.grade, SafetyGrade::S);
    }
}
