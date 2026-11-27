//! M2: 4-tier rate-limit-proof IP purity intelligence, dual-stack IPv6 leak detection,
//! and DNS geographic coherence probe.
//!
//! Security & privacy invariants:
//! - ALL outbound HTTP requests strictly route through `ProbeRoute` via `crate::probe_http::probe_url`
//!   (ZERO ambient env proxy, ZERO silent direct fallback).
//! - When `ProbeRoute::Skip(_)` is passed (e.g. `AccessPath::Uncovered` or `Unknown`), ZERO network
//!   sockets are opened (fail-closed) and a pure offline report is returned.
//! - A 30-minute bounded (64-entry) in-memory TTL cache keyed by normalized IP prevents upstream
//!   rate-limit spam across polling cycles.

use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use cg_protocol::{AsnClassification, DnsCoherenceReport, IpPurityReport};

use crate::probe_http::{probe_url, ProbeRoute};
use crate::traits::{PlatformError, PlatformResult};

/// Default in-memory IP intelligence cache TTL (30 minutes).
pub const IP_INTEL_CACHE_TTL_SECS: u64 = 1_800;
/// Maximum cached IP entries retained in memory before oldest-entry eviction.
pub const IP_INTEL_CACHE_MAX_ENTRIES: usize = 64;
/// Default per-tier HTTP timeout for IP purity / DNS coherence probes.
pub const DEFAULT_IP_INTEL_TIMEOUT: Duration = Duration::from_secs(6);
/// Maximum response size accepted from IP intel / EDNS JSON endpoints (256 KiB).
const MAX_INTEL_BODY_BYTES: usize = 256 * 1024;

/// Sorted offline ASN table (`(asn, classification, canonical_org)`) enabling O(log N) binary search
/// when external JSON providers rate-limit (HTTP 429) or when running in offline/fail-closed mode.
const OFFLINE_KNOWN_ASNS: &[(u32, AsnClassification, &str)] = &[
    (
        174,
        AsnClassification::DatacenterHosting,
        "Cogent Communications",
    ),
    (
        701,
        AsnClassification::IspResidential,
        "Verizon Business / Fios",
    ),
    (
        906,
        AsnClassification::DatacenterHosting,
        "DMIT Cloud Services",
    ),
    (2516, AsnClassification::IspResidential, "KDDI Corporation"),
    (
        2856,
        AsnClassification::IspResidential,
        "British Telecommunications",
    ),
    (3215, AsnClassification::IspResidential, "Orange S.A."),
    (
        3320,
        AsnClassification::IspResidential,
        "Deutsche Telekom AG",
    ),
    (
        3462,
        AsnClassification::IspResidential,
        "Chunghwa Telecom (HiNet)",
    ),
    (
        4134,
        AsnClassification::IspResidential,
        "ChinaNet (China Telecom)",
    ),
    (4657, AsnClassification::IspResidential, "StarHub Ltd"),
    (
        4713,
        AsnClassification::IspResidential,
        "NTT Communications (OCN)",
    ),
    (4760, AsnClassification::IspResidential, "HKT Limited"),
    (
        4766,
        AsnClassification::IspResidential,
        "Korea Telecom (KT)",
    ),
    (4809, AsnClassification::IspResidential, "China Telecom CN2"),
    (4837, AsnClassification::IspResidential, "China Unicom"),
    (
        5089,
        AsnClassification::IspResidential,
        "Virgin Media Limited",
    ),
    (
        6939,
        AsnClassification::DatacenterHosting,
        "Hurricane Electric",
    ),
    (
        7018,
        AsnClassification::IspResidential,
        "AT&T Services, Inc.",
    ),
    (
        7473,
        AsnClassification::IspResidential,
        "Singapore Telecommunications (Singtel)",
    ),
    (
        7922,
        AsnClassification::IspResidential,
        "Comcast Cable Communications",
    ),
    (
        8075,
        AsnClassification::DatacenterHosting,
        "Microsoft Corporation (Azure)",
    ),
    (
        9009,
        AsnClassification::DatacenterHosting,
        "M247 Europe SRL",
    ),
    (9318, AsnClassification::IspResidential, "SK Broadband"),
    (
        9808,
        AsnClassification::IspResidential,
        "China Mobile Communications",
    ),
    (
        12876,
        AsnClassification::DatacenterHosting,
        "Scaleway S.A.S.",
    ),
    (
        13335,
        AsnClassification::DatacenterHosting,
        "Cloudflare, Inc.",
    ),
    (
        14061,
        AsnClassification::DatacenterHosting,
        "DigitalOcean, LLC",
    ),
    (
        14618,
        AsnClassification::DatacenterHosting,
        "Amazon.com, Inc. (AWS)",
    ),
    (
        15169,
        AsnClassification::DatacenterHosting,
        "Google LLC (GCP)",
    ),
    (16276, AsnClassification::DatacenterHosting, "OVH SAS"),
    (
        16509,
        AsnClassification::DatacenterHosting,
        "Amazon.com, Inc. (AWS)",
    ),
    (
        17676,
        AsnClassification::IspResidential,
        "SoftBank BB Corp.",
    ),
    (
        20115,
        AsnClassification::IspResidential,
        "Charter Communications (Spectrum)",
    ),
    (
        20473,
        AsnClassification::DatacenterHosting,
        "The Constant Company (Vultr)",
    ),
    (
        21928,
        AsnClassification::MobileCellular,
        "T-Mobile USA, Inc.",
    ),
    (
        22773,
        AsnClassification::IspResidential,
        "Cox Communications",
    ),
    (
        24940,
        AsnClassification::DatacenterHosting,
        "Hetzner Online GmbH",
    ),
    (
        25820,
        AsnClassification::DatacenterHosting,
        "IT7 Networks (BandwagonHost)",
    ),
    (
        28753,
        AsnClassification::DatacenterHosting,
        "Leaseweb Deutschland GmbH",
    ),
    (
        31898,
        AsnClassification::DatacenterHosting,
        "Oracle Corporation (OCI)",
    ),
    (36007, AsnClassification::DatacenterHosting, "Kamatera Inc"),
    (
        36352,
        AsnClassification::DatacenterHosting,
        "ColoCrossing / RackNerd",
    ),
    (
        37963,
        AsnClassification::DatacenterHosting,
        "Hangzhou Alibaba Advertising (Aliyun)",
    ),
    (
        45090,
        AsnClassification::DatacenterHosting,
        "Shenzhen Tencent Computer Systems",
    ),
    (
        45102,
        AsnClassification::DatacenterHosting,
        "Alibaba (US) Technology (Aliyun)",
    ),
    (51167, AsnClassification::DatacenterHosting, "Contabo GmbH"),
    (54574, AsnClassification::DatacenterHosting, "DMIT Inc."),
    (
        58453,
        AsnClassification::IspResidential,
        "China Mobile International",
    ),
    (
        60781,
        AsnClassification::DatacenterHosting,
        "Leaseweb Netherlands B.V.",
    ),
    (
        63949,
        AsnClassification::DatacenterHosting,
        "Akamai Connected Cloud (Linode)",
    ),
    (
        132203,
        AsnClassification::DatacenterHosting,
        "Tencent Building (Tencent Cloud)",
    ),
    (
        136907,
        AsnClassification::DatacenterHosting,
        "Huawei Cloud Service",
    ),
    (
        138915,
        AsnClassification::DatacenterHosting,
        "Akari Networks",
    ),
    (
        212238,
        AsnClassification::DatacenterHosting,
        "Datacamp Limited",
    ),
    (396982, AsnClassification::DatacenterHosting, "Google Cloud"),
];

/// Normalize an IP literal into a canonical lowercase cache key (returns `None` if invalid).
pub fn normalize_ip_key(raw: &str) -> Option<String> {
    let parsed: IpAddr = raw.trim().parse().ok()?;
    let canon = crate::netwatch_win::canonical_ip(parsed);
    Some(canon.to_string().to_ascii_lowercase())
}

fn normalize_country_code(raw: Option<&str>) -> Option<String> {
    let s = raw?.trim().to_ascii_uppercase();
    if s.len() == 2 && s.bytes().all(|b| b.is_ascii_alphabetic()) && s != "XX" {
        Some(s)
    } else {
        None
    }
}

fn coords_to_tenths(lat: Option<f64>, lon: Option<f64>) -> (Option<i16>, Option<i16>) {
    let lat_t = lat
        .filter(|v| v.is_finite() && (-90.0..=90.0).contains(v))
        .map(|v| (v * 10.0).round().clamp(-900.0, 900.0) as i16);
    let lon_t = lon
        .filter(|v| v.is_finite() && (-180.0..=180.0).contains(v))
        .map(|v| (v * 10.0).round().clamp(-1800.0, 1800.0) as i16);
    (lat_t, lon_t)
}

/// Pure offline ASN & organization classifier using binary search over `OFFLINE_KNOWN_ASNS`
/// plus case-insensitive organization keyword heuristics.
pub fn classify_offline_asn(
    asn: Option<u32>,
    org: &str,
) -> (AsnClassification, Option<&'static str>) {
    if let Some(num) = asn {
        if let Ok(idx) = OFFLINE_KNOWN_ASNS.binary_search_by_key(&num, |entry| entry.0) {
            let (_, cls, canonical) = OFFLINE_KNOWN_ASNS[idx];
            return (cls, Some(canonical));
        }
    }

    let low = org.trim().to_ascii_lowercase();
    if low.is_empty() {
        return (AsnClassification::Unknown, None);
    }

    if low.contains("tor exit")
        || low.contains("mullvad")
        || low.contains("nordvpn")
        || low.contains("expressvpn")
        || low.contains("protonvpn")
        || low.contains("surfshark")
        || low.contains("private internet access")
        || low.contains("cloudflare warp")
        || low.contains("proxy")
        || low.contains("vpn")
    {
        return (AsnClassification::PublicProxyVpnTor, None);
    }

    if low.contains("amazon")
        || low.contains("aws")
        || low.contains("google cloud")
        || low.contains("microsoft")
        || low.contains("azure")
        || low.contains("digitalocean")
        || low.contains("vultr")
        || low.contains("choopa")
        || low.contains("hetzner")
        || low.contains("ovh")
        || low.contains("linode")
        || low.contains("oracle")
        || low.contains("aliyun")
        || low.contains("alibaba")
        || low.contains("tencent")
        || low.contains("huawei cloud")
        || low.contains("datacamp")
        || low.contains("m247")
        || low.contains("dmit")
        || low.contains("bandwagon")
        || low.contains("it7")
        || low.contains("racknerd")
        || low.contains("contabo")
        || low.contains("scaleway")
        || low.contains("leaseweb")
        || low.contains("hosting")
        || low.contains("cloud")
        || low.contains("datacenter")
        || low.contains("data center")
        || low.contains("vps")
        || low.contains("server")
    {
        return (AsnClassification::DatacenterHosting, None);
    }

    if low.contains("university")
        || low.contains("college")
        || low.contains("academic")
        || low.contains("education")
        || low.contains("research")
        || low.contains("government")
    {
        return (AsnClassification::EducationGov, None);
    }

    if low.contains("mobile")
        || low.contains("wireless")
        || low.contains("cellular")
        || low.contains("t-mobile")
        || low.contains("vodafone")
    {
        return (AsnClassification::MobileCellular, None);
    }

    if low.contains("comcast")
        || low.contains("verizon")
        || low.contains("at&t")
        || low.contains("charter")
        || low.contains("spectrum")
        || low.contains("cox ")
        || low.contains("broadband")
        || low.contains("telecom")
        || low.contains("cable")
        || low.contains("fiber")
        || low.contains("residential")
        || low.contains("kddi")
        || low.contains("softbank")
        || low.contains("ntt")
        || low.contains("singtel")
        || low.contains("starhub")
        || low.contains("hinet")
        || low.contains("chunghwa")
        || low.contains("deutsche telekom")
    {
        return (AsnClassification::IspResidential, None);
    }

    (AsnClassification::Unknown, None)
}

/// Parse an `api.ipapi.is` `abuser_score` field (either string `"0.0125 (Low)"` or float `0.0125`)
/// into basis points (`0..=10000`, where `100` = `1.00%`).
pub fn parse_abuser_score_bps(val: &serde_json::Value) -> Option<u32> {
    let ratio = if let Some(n) = val.as_f64() {
        Some(n)
    } else if let Some(s) = val.as_str() {
        let token = s.split_whitespace().next().unwrap_or("").trim();
        token.parse::<f64>().ok()
    } else {
        None
    }?;
    if !ratio.is_finite() || ratio < 0.0 {
        return None;
    }
    Some((ratio * 10_000.0).round().clamp(0.0, 10_000.0) as u32)
}

fn parse_asn_value(val: &serde_json::Value) -> Option<u32> {
    if let Some(u) = val.as_u64() {
        return u32::try_from(u).ok().filter(|&n| n > 0);
    }
    if let Some(s) = val.as_str() {
        let trimmed = s.trim();
        let digits = trimmed
            .strip_prefix("AS")
            .or_else(|| trimmed.strip_prefix("as"))
            .unwrap_or(trimmed);
        return digits.parse::<u32>().ok().filter(|&n| n > 0);
    }
    None
}

fn compute_abuse_risk_score(
    abuser_bps: u32,
    is_datacenter: bool,
    is_proxy_or_vpn: bool,
    is_tor: bool,
    is_abuser: bool,
    is_bogon_or_relay: bool,
    classification: AsnClassification,
) -> u8 {
    let mut score: u32 = match abuser_bps {
        0..=15 => abuser_bps / 3,
        16..=100 => 5 + (abuser_bps - 15) / 8,
        101..=500 => 16 + (abuser_bps - 100) / 14,
        _ => 45 + ((abuser_bps - 500) / 50).min(30),
    };
    if is_datacenter || classification == AsnClassification::DatacenterHosting {
        score += 22;
    }
    if is_proxy_or_vpn || classification == AsnClassification::PublicProxyVpnTor {
        score += 35;
    }
    if is_abuser {
        score += 25;
    }
    if is_bogon_or_relay {
        score += 20;
    }
    if is_tor {
        score = score.max(92);
    }
    score.min(100) as u8
}

fn map_entity_type_str(raw: Option<&str>) -> Option<AsnClassification> {
    match raw?.trim().to_ascii_lowercase().as_str() {
        "isp" => Some(AsnClassification::IspResidential),
        "business" | "banking" => Some(AsnClassification::BusinessIsp),
        "education" | "government" => Some(AsnClassification::EducationGov),
        "hosting" => Some(AsnClassification::DatacenterHosting),
        _ => None,
    }
}

/// Tier 1 pure JSON parser for `https://api.ipapi.is/?q=<ip>`.
pub fn parse_ipapi_is_json(
    json_body: &str,
    fallback_ip: Option<&str>,
    fallback_country: Option<&str>,
    now_secs: u64,
) -> PlatformResult<IpPurityReport> {
    let root: serde_json::Value = serde_json::from_str(json_body)
        .map_err(|e| PlatformError::Network(format!("ipapi.is JSON 解析失败：{e}")))?;
    if root.get("error").is_some() {
        let msg = root
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("upstream error");
        return Err(PlatformError::Network(format!("ipapi.is 返回错误：{msg}")));
    }

    let ip = root
        .get("ip")
        .and_then(|v| v.as_str())
        .and_then(normalize_ip_key)
        .or_else(|| fallback_ip.and_then(normalize_ip_key));

    let is_datacenter = root
        .get("is_datacenter")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let is_proxy = root
        .get("is_proxy")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let is_vpn = root
        .get("is_vpn")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let is_tor = root
        .get("is_tor")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let is_bogon = root
        .get("is_bogon")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let is_mobile = root
        .get("is_mobile")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let is_abuser = root
        .get("is_abuser")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let is_proxy_or_vpn = is_proxy || is_vpn || is_tor;

    let asn_obj = root.get("asn");
    let company_obj = root.get("company");

    let asn = asn_obj.and_then(|a| a.get("asn")).and_then(parse_asn_value);
    let asn_org_raw = asn_obj
        .and_then(|a| a.get("org"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            company_obj
                .and_then(|c| c.get("name"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
        })
        .unwrap_or("");

    let asn_type_str = asn_obj
        .and_then(|a| a.get("type"))
        .and_then(|v| v.as_str())
        .or_else(|| {
            company_obj
                .and_then(|c| c.get("type"))
                .and_then(|v| v.as_str())
        });

    let asn_bps = asn_obj
        .and_then(|a| a.get("abuser_score"))
        .and_then(parse_abuser_score_bps)
        .unwrap_or(0);
    let company_bps = company_obj
        .and_then(|c| c.get("abuser_score"))
        .and_then(parse_abuser_score_bps)
        .unwrap_or(0);
    let abuser_score_bps = asn_bps.max(company_bps);

    let (offline_cls, offline_org) = classify_offline_asn(asn, asn_org_raw);
    let asn_org = if !asn_org_raw.is_empty() {
        asn_org_raw.to_string()
    } else {
        offline_org.unwrap_or_default().to_string()
    };

    let classification = if is_tor || is_proxy_or_vpn {
        AsnClassification::PublicProxyVpnTor
    } else if is_datacenter {
        AsnClassification::DatacenterHosting
    } else if is_mobile {
        AsnClassification::MobileCellular
    } else if let Some(mapped) = map_entity_type_str(asn_type_str) {
        mapped
    } else {
        offline_cls
    };

    let loc = root.get("location");
    let country = normalize_country_code(
        loc.and_then(|l| l.get("country_code"))
            .and_then(|v| v.as_str()),
    )
    .or_else(|| normalize_country_code(fallback_country));
    let city = loc
        .and_then(|l| l.get("city"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);
    let (lat_tenths, lon_tenths) = coords_to_tenths(
        loc.and_then(|l| l.get("latitude")).and_then(|v| v.as_f64()),
        loc.and_then(|l| l.get("longitude"))
            .and_then(|v| v.as_f64()),
    );

    let effective_dc = is_datacenter || classification == AsnClassification::DatacenterHosting;
    let abuse_risk_score = compute_abuse_risk_score(
        abuser_score_bps,
        effective_dc,
        is_proxy_or_vpn,
        is_tor,
        is_abuser,
        is_bogon,
        classification,
    );

    Ok(IpPurityReport {
        ip,
        country,
        city,
        lat_tenths,
        lon_tenths,
        asn,
        asn_org,
        classification,
        abuse_risk_score,
        abuser_score_bps,
        is_datacenter: effective_dc,
        is_proxy_or_vpn,
        is_tor,
        is_bogon_or_relay: is_bogon,
        dual_stack_split_detected: false,
        ipv6_egress_country: None,
        source_tag: "ipapi.is".to_string(),
        checked_at: now_secs,
    })
}

/// Split an `ipinfo.io` `org` string (e.g. `"AS7922 Comcast Cable Communications, LLC"`)
/// into `(Option<u32>, String)`.
fn split_ipinfo_org(raw: &str) -> (Option<u32>, String) {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return (None, String::new());
    }
    let mut parts = trimmed.splitn(2, char::is_whitespace);
    let first = parts.next().unwrap_or("");
    let rest = parts.next().unwrap_or("").trim();
    if let Some(num_str) = first
        .strip_prefix("AS")
        .or_else(|| first.strip_prefix("as"))
    {
        if let Ok(asn) = num_str.parse::<u32>() {
            if asn > 0 {
                return (Some(asn), rest.to_string());
            }
        }
    }
    (None, trimmed.to_string())
}

/// Tier 2 pure JSON parser for `https://ipinfo.io/<ip>/json`, enriched with offline ASN lookup.
pub fn parse_ipinfo_io_json(
    json_body: &str,
    fallback_ip: Option<&str>,
    fallback_country: Option<&str>,
    now_secs: u64,
) -> PlatformResult<IpPurityReport> {
    let root: serde_json::Value = serde_json::from_str(json_body)
        .map_err(|e| PlatformError::Network(format!("ipinfo.io JSON 解析失败：{e}")))?;
    if root.get("error").is_some() {
        return Err(PlatformError::Network("ipinfo.io 返回错误状态".to_string()));
    }

    let ip = root
        .get("ip")
        .and_then(|v| v.as_str())
        .and_then(normalize_ip_key)
        .or_else(|| fallback_ip.and_then(normalize_ip_key));
    let country = normalize_country_code(root.get("country").and_then(|v| v.as_str()))
        .or_else(|| normalize_country_code(fallback_country));
    let city = root
        .get("city")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);

    let (lat_tenths, lon_tenths) = root
        .get("loc")
        .and_then(|v| v.as_str())
        .and_then(|s| s.split_once(','))
        .map(|(la, lo)| {
            coords_to_tenths(la.trim().parse::<f64>().ok(), lo.trim().parse::<f64>().ok())
        })
        .unwrap_or((None, None));

    let org_raw = root.get("org").and_then(|v| v.as_str()).unwrap_or("");
    let (asn, parsed_org) = split_ipinfo_org(org_raw);
    let (offline_cls, offline_name) = classify_offline_asn(asn, &parsed_org);
    let asn_org = if !parsed_org.is_empty() {
        parsed_org
    } else {
        offline_name.unwrap_or_default().to_string()
    };

    let is_bogon = root.get("bogon").and_then(|v| v.as_bool()).unwrap_or(false);
    let privacy = root.get("privacy");
    let p_vpn = privacy
        .and_then(|p| p.get("vpn"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let p_proxy = privacy
        .and_then(|p| p.get("proxy"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let p_tor = privacy
        .and_then(|p| p.get("tor"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let p_relay = privacy
        .and_then(|p| p.get("relay"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let p_hosting = privacy
        .and_then(|p| p.get("hosting"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let is_proxy_or_vpn =
        p_vpn || p_proxy || p_tor || offline_cls == AsnClassification::PublicProxyVpnTor;
    let is_datacenter = p_hosting || offline_cls == AsnClassification::DatacenterHosting;
    let classification = if is_proxy_or_vpn {
        AsnClassification::PublicProxyVpnTor
    } else if is_datacenter {
        AsnClassification::DatacenterHosting
    } else {
        offline_cls
    };

    let abuse_risk_score = compute_abuse_risk_score(
        0,
        is_datacenter,
        is_proxy_or_vpn,
        p_tor,
        false,
        is_bogon || p_relay,
        classification,
    );

    Ok(IpPurityReport {
        ip,
        country,
        city,
        lat_tenths,
        lon_tenths,
        asn,
        asn_org,
        classification,
        abuse_risk_score,
        abuser_score_bps: 0,
        is_datacenter,
        is_proxy_or_vpn,
        is_tor: p_tor,
        is_bogon_or_relay: is_bogon || p_relay,
        dual_stack_split_detected: false,
        ipv6_egress_country: None,
        source_tag: "ipinfo.io".to_string(),
        checked_at: now_secs,
    })
}

/// Tier 3 pure key-value parser for Cloudflare `cdn-cgi/trace`.
pub fn parse_cdn_cgi_trace(
    body: &str,
    fallback_ip: Option<&str>,
    fallback_country: Option<&str>,
    now_secs: u64,
) -> PlatformResult<IpPurityReport> {
    let mut kv: HashMap<&str, &str> = HashMap::new();
    for line in body.lines() {
        if let Some((k, v)) = line.split_once('=') {
            kv.insert(k.trim(), v.trim());
        }
    }
    let ip_raw = kv.get("ip").copied();
    let loc_raw = kv.get("loc").copied();
    if ip_raw.is_none() && loc_raw.is_none() {
        return Err(PlatformError::Network(
            "cdn-cgi/trace 响应缺少 ip/loc 字段".to_string(),
        ));
    }

    let ip = ip_raw
        .and_then(normalize_ip_key)
        .or_else(|| fallback_ip.and_then(normalize_ip_key));
    let is_tor = loc_raw.is_some_and(|l| l.eq_ignore_ascii_case("T1"));
    let country = if is_tor {
        normalize_country_code(fallback_country)
    } else {
        normalize_country_code(loc_raw).or_else(|| normalize_country_code(fallback_country))
    };

    let warp_active = kv
        .get("warp")
        .copied()
        .is_some_and(|w| matches!(w.to_ascii_lowercase().as_str(), "on" | "plus"));
    let is_proxy_or_vpn = is_tor || warp_active;
    let classification = if is_proxy_or_vpn {
        AsnClassification::PublicProxyVpnTor
    } else {
        AsnClassification::Unknown
    };
    let asn_org = if warp_active {
        "Cloudflare WARP".to_string()
    } else if is_tor {
        "Tor Exit Node".to_string()
    } else {
        String::new()
    };

    let abuse_risk_score = compute_abuse_risk_score(
        0,
        false,
        is_proxy_or_vpn,
        is_tor,
        false,
        warp_active,
        classification,
    );

    Ok(IpPurityReport {
        ip,
        country,
        city: None,
        lat_tenths: None,
        lon_tenths: None,
        asn: None,
        asn_org,
        classification,
        abuse_risk_score,
        abuser_score_bps: 0,
        is_datacenter: false,
        is_proxy_or_vpn,
        is_tor,
        is_bogon_or_relay: warp_active,
        dual_stack_split_detected: false,
        ipv6_egress_country: None,
        source_tag: "cdn-cgi/trace".to_string(),
        checked_at: now_secs,
    })
}

/// Tier 4 pure offline ASN & org report builder (zero network calls).
pub fn build_offline_purity_report(
    observed_ip: Option<&str>,
    observed_country: Option<&str>,
    asn: Option<u32>,
    asn_org: Option<&str>,
    source_tag: &str,
    now_secs: u64,
) -> IpPurityReport {
    let ip = observed_ip.and_then(normalize_ip_key);
    let country = normalize_country_code(observed_country);
    let org_in = asn_org.map(str::trim).unwrap_or("");
    let (classification, canonical_org) = classify_offline_asn(asn, org_in);
    let resolved_org = if !org_in.is_empty() {
        org_in.to_string()
    } else {
        canonical_org.unwrap_or_default().to_string()
    };
    let is_datacenter = classification == AsnClassification::DatacenterHosting;
    let is_proxy_or_vpn = classification == AsnClassification::PublicProxyVpnTor;
    let abuse_risk_score = compute_abuse_risk_score(
        0,
        is_datacenter,
        is_proxy_or_vpn,
        false,
        false,
        false,
        classification,
    );

    IpPurityReport {
        ip,
        country,
        city: None,
        lat_tenths: None,
        lon_tenths: None,
        asn,
        asn_org: resolved_org,
        classification,
        abuse_risk_score,
        abuser_score_bps: 0,
        is_datacenter,
        is_proxy_or_vpn,
        is_tor: false,
        is_bogon_or_relay: false,
        dual_stack_split_detected: false,
        ipv6_egress_country: None,
        source_tag: source_tag.to_string(),
        checked_at: now_secs,
    }
}

#[derive(Clone, Debug)]
struct CachedPurityEntry {
    cached_at: u64,
    last_accessed_at: u64,
    report: IpPurityReport,
}

/// Bounded in-memory TTL cache keyed by normalized IP literal.
#[derive(Debug)]
pub struct IpIntelCache {
    ttl_secs: u64,
    max_entries: usize,
    entries: HashMap<String, CachedPurityEntry>,
}

impl Default for IpIntelCache {
    fn default() -> Self {
        Self::new(IP_INTEL_CACHE_TTL_SECS, IP_INTEL_CACHE_MAX_ENTRIES)
    }
}

impl IpIntelCache {
    pub fn new(ttl_secs: u64, max_entries: usize) -> Self {
        Self {
            ttl_secs,
            max_entries: max_entries.max(1),
            entries: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Look up a fresh cached report for `raw_ip` at `now_secs`.
    pub fn get(&mut self, raw_ip: &str, now_secs: u64) -> Option<IpPurityReport> {
        let key = normalize_ip_key(raw_ip)?;
        let fresh = {
            let entry = self.entries.get(&key)?;
            now_secs >= entry.cached_at && now_secs - entry.cached_at < self.ttl_secs
        };
        if !fresh {
            self.entries.remove(&key);
            return None;
        }
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.last_accessed_at = now_secs;
            return Some(entry.report.clone());
        }
        None
    }

    /// Insert or refresh a report keyed by `raw_ip`, evicting expired or least-recently-used entries
    /// once `max_entries` is reached.
    pub fn put(&mut self, raw_ip: &str, report: IpPurityReport, now_secs: u64) {
        let Some(key) = normalize_ip_key(raw_ip) else {
            return;
        };
        if !self.entries.contains_key(&key) && self.entries.len() >= self.max_entries {
            self.entries
                .retain(|_, v| now_secs >= v.cached_at && now_secs - v.cached_at < self.ttl_secs);
            if self.entries.len() >= self.max_entries {
                if let Some(oldest_key) = self
                    .entries
                    .iter()
                    .min_by_key(|(_, v)| (v.last_accessed_at, v.cached_at))
                    .map(|(k, _)| k.clone())
                {
                    self.entries.remove(&oldest_key);
                }
            }
        }
        self.entries.insert(
            key,
            CachedPurityEntry {
                cached_at: now_secs,
                last_accessed_at: now_secs,
                report,
            },
        );
    }
}

fn global_ip_intel_cache() -> &'static Mutex<IpIntelCache> {
    static CACHE: OnceLock<Mutex<IpIntelCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(IpIntelCache::default()))
}

/// Clear the process-global 30-minute IP purity cache (e.g. on manual deep refresh or node switch).
pub fn clear_ip_intel_cache() {
    let mut guard = global_ip_intel_cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    guard.clear();
}

/// Pure testable 4-tier IP intelligence orchestrator with injected HTTP fetcher and cache.
///
/// Guarantees:
/// - `ProbeRoute::Skip(_)` immediately returns an offline fail-closed report with ZERO HTTP calls.
/// - Cache hit within TTL returns immediately with ZERO HTTP calls.
/// - Tier 1 (`api.ipapi.is`) -> Tier 2 (`ipinfo.io`) -> Tier 3 (`cdn-cgi/trace`) -> Tier 4 (offline).
pub fn fetch_ip_purity_with_fetcher<F>(
    route: &ProbeRoute,
    observed_ip: Option<&str>,
    observed_country: Option<&str>,
    now_secs: u64,
    cache: &mut IpIntelCache,
    mut http_get: F,
) -> IpPurityReport
where
    F: FnMut(&str) -> PlatformResult<(u16, String)>,
{
    let norm_ip = observed_ip.and_then(normalize_ip_key);

    if matches!(route, ProbeRoute::Skip(_)) {
        return build_offline_purity_report(
            norm_ip.as_deref(),
            observed_country,
            None,
            None,
            "offline_fail_closed",
            now_secs,
        );
    }

    if let Some(ref ip_key) = norm_ip {
        if let Some(cached) = cache.get(ip_key, now_secs) {
            return cached;
        }
    }

    // Tier 1: api.ipapi.is
    let tier1_url = match norm_ip.as_deref() {
        Some(ip) => format!("https://api.ipapi.is/?q={ip}"),
        None => "https://api.ipapi.is/".to_string(),
    };
    if let Ok((200, body)) = http_get(&tier1_url) {
        if let Ok(report) =
            parse_ipapi_is_json(&body, norm_ip.as_deref(), observed_country, now_secs)
        {
            if let Some(ref key) = report.ip {
                cache.put(key, report.clone(), now_secs);
            }
            return report;
        }
    }

    // Tier 2: ipinfo.io
    let tier2_url = match norm_ip.as_deref() {
        Some(ip) => format!("https://ipinfo.io/{ip}/json"),
        None => "https://ipinfo.io/json".to_string(),
    };
    if let Ok((200, body)) = http_get(&tier2_url) {
        if let Ok(report) =
            parse_ipinfo_io_json(&body, norm_ip.as_deref(), observed_country, now_secs)
        {
            if let Some(ref key) = report.ip {
                cache.put(key, report.clone(), now_secs);
            }
            return report;
        }
    }

    // Tier 3: Cloudflare cdn-cgi/trace
    if let Ok((200, body)) = http_get("https://1.1.1.1/cdn-cgi/trace") {
        if let Ok(report) =
            parse_cdn_cgi_trace(&body, norm_ip.as_deref(), observed_country, now_secs)
        {
            if let Some(ref key) = report.ip {
                cache.put(key, report.clone(), now_secs);
            }
            return report;
        }
    }

    // Tier 4: Pure offline fallback
    let offline = build_offline_purity_report(
        norm_ip.as_deref(),
        observed_country,
        None,
        None,
        "offline_fallback",
        now_secs,
    );
    if let Some(ref key) = offline.ip {
        cache.put(key, offline.clone(), now_secs);
    }
    offline
}

/// 4-tier rate-limit-proof IP intelligence fetcher strictly routed via `ProbeRoute` (ZERO direct fallback).
pub fn fetch_ip_purity_via_route(
    route: &ProbeRoute,
    observed_ip: Option<&str>,
    observed_country: Option<&str>,
    now_secs: u64,
) -> IpPurityReport {
    if matches!(route, ProbeRoute::Skip(_)) {
        return build_offline_purity_report(
            observed_ip,
            observed_country,
            None,
            None,
            "offline_fail_closed",
            now_secs,
        );
    }

    let norm_ip = observed_ip.and_then(normalize_ip_key);
    if let Some(ref ip_key) = norm_ip {
        let mut guard = global_ip_intel_cache()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(cached) = guard.get(ip_key, now_secs) {
            return cached;
        }
    }

    // Perform network I/O outside the global cache mutex so concurrent callers never block on HTTP.
    let mut local_scratch = IpIntelCache::new(IP_INTEL_CACHE_TTL_SECS, 2);
    let report = fetch_ip_purity_with_fetcher(
        route,
        norm_ip.as_deref(),
        observed_country,
        now_secs,
        &mut local_scratch,
        |url| {
            let resp = probe_url(route, url, DEFAULT_IP_INTEL_TIMEOUT, MAX_INTEL_BODY_BYTES)?;
            Ok((resp.status, resp.body))
        },
    );

    if let Some(ref key) = report.ip {
        let mut guard = global_ip_intel_cache()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        guard.put(key, report.clone(), now_secs);
    }
    report
}

// ---------- Dual-Stack IPv6 Leak Helper ----------

/// Pure dual-stack split detector: returns `true` when both IPv4 and IPv6 egress countries are
/// known ISO alpha-2 codes and diverge (e.g. IPv4 routes via `US`/`JP` while IPv6 leaks via `CN`).
pub fn detect_dual_stack_ipv6_split(
    ipv4_country: Option<&str>,
    ipv6_country: Option<&str>,
) -> bool {
    let Some(v4) = normalize_country_code(ipv4_country) else {
        return false;
    };
    let Some(v6) = normalize_country_code(ipv6_country) else {
        return false;
    };
    v4 != v6
}

/// Merge an observed IPv6 egress country into an `IpPurityReport`, updating `dual_stack_split_detected`.
pub fn attach_dual_stack_ipv6_check(report: &mut IpPurityReport, ipv6_country: Option<String>) {
    let norm_v6 = normalize_country_code(ipv6_country.as_deref());
    report.dual_stack_split_detected =
        detect_dual_stack_ipv6_split(report.country.as_deref(), norm_v6.as_deref());
    report.ipv6_egress_country = norm_v6;
}

/// Probe IPv6 egress country strictly through `ProbeRoute` (skips cleanly on `ProbeRoute::Skip`).
pub fn probe_ipv6_egress_via_route(
    route: &ProbeRoute,
    timeout: Duration,
) -> Option<(String, Option<String>)> {
    if matches!(route, ProbeRoute::Skip(_)) {
        return None;
    }
    let resp = probe_url(
        route,
        "https://[2606:4700:4700::1111]/cdn-cgi/trace",
        timeout,
        64 * 1024,
    )
    .ok()?;
    if resp.status != 200 {
        return None;
    }
    let parsed = parse_cdn_cgi_trace(&resp.body, None, None, 0).ok()?;
    let ip = parsed.ip?;
    let parsed_addr: IpAddr = ip.parse().ok()?;
    if !parsed_addr.is_ipv6() {
        return None;
    }
    Some((ip, parsed.country))
}

// ---------- DNS Geographic Coherence Probe ----------

const COUNTRY_NAME_HINTS: &[(&str, &str)] = &[
    ("china", "CN"),
    ("hong kong", "HK"),
    ("macau", "MO"),
    ("taiwan", "TW"),
    ("united states", "US"),
    ("japan", "JP"),
    ("singapore", "SG"),
    ("united kingdom", "GB"),
    ("germany", "DE"),
    ("france", "FR"),
    ("netherlands", "NL"),
    ("canada", "CA"),
    ("australia", "AU"),
    ("south korea", "KR"),
    ("korea", "KR"),
    ("ireland", "IE"),
    ("switzerland", "CH"),
    ("sweden", "SE"),
    ("india", "IN"),
    ("russia", "RU"),
];

/// Extract a 2-letter ISO country code from an `edns.ip-api.com/json` response (`dns.geo` string).
pub fn parse_edns_resolver_country(json_body: &str) -> Option<String> {
    let root: serde_json::Value = serde_json::from_str(json_body).ok()?;
    let dns = root.get("dns")?;
    if let Some(cc) = normalize_country_code(dns.get("countryCode").and_then(|v| v.as_str())) {
        return Some(cc);
    }
    let geo = dns.get("geo").and_then(|v| v.as_str())?.trim();
    let head = geo.split(" - ").next().unwrap_or(geo).trim();
    if let Some(cc) = normalize_country_code(Some(head)) {
        return Some(cc);
    }
    let low = head.to_ascii_lowercase();
    for &(name, code) in COUNTRY_NAME_HINTS {
        if low == name || low.contains(name) {
            return Some(code.to_string());
        }
    }
    None
}

/// Check whether local OS DNS resolution for a monitored AI domain returns a TUN Fake-IP
/// (`198.18.0.0/15` or `fdfe:dcba:9876::/48`), proving local DNS is intercepted by Clash/Mihomo/sing-box.
pub fn detect_local_fake_ip_dns() -> bool {
    let Ok(addrs) = ("claude.ai", 443).to_socket_addrs() else {
        return false;
    };
    addrs
        .into_iter()
        .any(|sa| crate::netwatch_win::is_fake_ip_addr(sa.ip()))
}

/// Pure evaluator folding observed DNS resolver countries, expected proxy country, and Fake-IP state
/// into a protocol `DnsCoherenceReport`.
pub fn evaluate_dns_coherence(
    resolver_countries: Vec<String>,
    expected_country: Option<&str>,
    fake_ip_active: bool,
    now_secs: u64,
) -> DnsCoherenceReport {
    let expected = normalize_country_code(expected_country);
    let mut normalized: Vec<String> = Vec::new();
    for raw in resolver_countries {
        if let Some(cc) = normalize_country_code(Some(&raw)) {
            if !normalized.contains(&cc) {
                normalized.push(cc);
            }
        }
    }

    let domestic_resolver_detected = !fake_ip_active
        && expected.as_deref() != Some("CN")
        && normalized.iter().any(|c| c == "CN");

    let coherent = if domestic_resolver_detected {
        false
    } else if fake_ip_active {
        true
    } else {
        match expected.as_deref() {
            Some(exp) if !normalized.is_empty() => normalized.iter().any(|c| c == exp),
            _ => true,
        }
    };

    let summary = if domestic_resolver_detected {
        "检测到国内 DNS 解析器回源（CN），存在本地 DNS 地理位置泄漏风险".to_string()
    } else if fake_ip_active {
        "已检测到代理 Fake-IP DNS 接管（198.18.0.0/15），域名解析已由远端代理节点统一承接"
            .to_string()
    } else if normalized.is_empty() {
        "已完成代理通道 DNS 一致性核验，未发现国内 DNS 泄漏".to_string()
    } else if coherent {
        format!(
            "远端 DNS 解析地区（{}）与代理出口地区一致",
            normalized.join("/")
        )
    } else {
        format!(
            "DNS 解析地区（{}）与预期出口（{}）存在跨区偏移",
            normalized.join("/"),
            expected.as_deref().unwrap_or("--")
        )
    };

    DnsCoherenceReport {
        checked_at: now_secs,
        coherent,
        domestic_resolver_detected,
        fake_ip_active,
        resolver_countries: normalized,
        summary,
    }
}

/// Probe DNS geographic coherence strictly honoring `ProbeRoute` (ZERO direct fallback on `Skip`).
pub fn probe_dns_coherence(
    route: &ProbeRoute,
    expected_country: Option<&str>,
    now_secs: u64,
) -> DnsCoherenceReport {
    let fake_ip_active = detect_local_fake_ip_dns();

    if let ProbeRoute::Skip(reason) = route {
        return DnsCoherenceReport {
            checked_at: now_secs,
            coherent: fake_ip_active,
            domestic_resolver_detected: false,
            fake_ip_active,
            resolver_countries: Vec::new(),
            summary: format!("未执行外网 DNS 地理探测（{reason}）"),
        };
    }

    let mut countries = Vec::new();
    if let Ok(resp) = probe_url(
        route,
        "https://edns.ip-api.com/json",
        DEFAULT_IP_INTEL_TIMEOUT,
        64 * 1024,
    ) {
        if resp.status == 200 {
            if let Some(cc) = parse_edns_resolver_country(&resp.body) {
                countries.push(cc);
            }
        }
    }

    if countries.is_empty() {
        if let Ok(resp) = probe_url(
            route,
            "https://1.1.1.1/cdn-cgi/trace",
            DEFAULT_IP_INTEL_TIMEOUT,
            64 * 1024,
        ) {
            if resp.status == 200 {
                if let Ok(trace) = parse_cdn_cgi_trace(&resp.body, None, None, now_secs) {
                    if let Some(cc) = trace.country {
                        countries.push(cc);
                    }
                }
            }
        }
    }

    evaluate_dns_coherence(countries, expected_country, fake_ip_active, now_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_asn_table_is_strictly_sorted_for_binary_search() {
        for pair in OFFLINE_KNOWN_ASNS.windows(2) {
            assert!(
                pair[0].0 < pair[1].0,
                "OFFLINE_KNOWN_ASNS must be strictly ascending: {} >= {}",
                pair[0].0,
                pair[1].0
            );
        }
        assert_eq!(
            classify_offline_asn(Some(7922), "").0,
            AsnClassification::IspResidential
        );
        assert_eq!(
            classify_offline_asn(Some(16509), "").0,
            AsnClassification::DatacenterHosting
        );
        assert_eq!(
            classify_offline_asn(None, "Example Cloud VPS Hosting").0,
            AsnClassification::DatacenterHosting
        );
    }

    #[test]
    fn parses_ipapi_is_residential_and_datacenter_tor_payloads() {
        let residential_json = r#"{
            "ip": "68.105.28.44",
            "is_bogon": false,
            "is_mobile": false,
            "is_datacenter": false,
            "is_tor": false,
            "is_proxy": false,
            "is_vpn": false,
            "is_abuser": false,
            "asn": {
                "asn": 7922,
                "org": "Comcast Cable Communications, LLC",
                "type": "isp",
                "abuser_score": "0.0008 (Very Low)"
            },
            "location": {
                "country_code": "US",
                "city": "San Jose",
                "latitude": 37.3382,
                "longitude": -121.8863
            }
        }"#;
        let rep = parse_ipapi_is_json(residential_json, None, None, 10_000).unwrap();
        assert_eq!(rep.ip.as_deref(), Some("68.105.28.44"));
        assert_eq!(rep.country.as_deref(), Some("US"));
        assert_eq!(rep.city.as_deref(), Some("San Jose"));
        assert_eq!(rep.lat_tenths, Some(373));
        assert_eq!(rep.lon_tenths, Some(-1219));
        assert_eq!(rep.asn, Some(7922));
        assert_eq!(rep.classification, AsnClassification::IspResidential);
        assert_eq!(rep.abuser_score_bps, 8);
        assert!(rep.abuse_risk_score <= 15);
        assert!(!rep.is_datacenter);
        assert!(!rep.is_proxy_or_vpn);
        assert!(!rep.is_tor);
        assert_eq!(rep.source_tag, "ipapi.is");

        let tor_dc_json = r#"{
            "ip": "185.220.101.4",
            "is_bogon": false,
            "is_datacenter": true,
            "is_tor": true,
            "is_proxy": true,
            "is_vpn": false,
            "is_abuser": true,
            "asn": {
                "asn": 24940,
                "org": "Hetzner Online GmbH",
                "type": "hosting",
                "abuser_score": "0.045 (High)"
            },
            "location": {
                "country_code": "de",
                "city": "Falkenstein",
                "latitude": 50.4779,
                "longitude": 12.3713
            }
        }"#;
        let bad = parse_ipapi_is_json(tor_dc_json, None, None, 10_001).unwrap();
        assert_eq!(bad.country.as_deref(), Some("DE"));
        assert_eq!(bad.classification, AsnClassification::PublicProxyVpnTor);
        assert_eq!(bad.abuser_score_bps, 450);
        assert!(bad.is_tor);
        assert!(bad.is_proxy_or_vpn);
        assert!(bad.is_datacenter);
        assert!(bad.abuse_risk_score >= 92);
    }

    #[test]
    fn parses_ipinfo_io_json_with_offline_asn_enrichment() {
        let json = r#"{
            "ip": "54.183.12.9",
            "city": "San Jose",
            "region": "California",
            "country": "US",
            "loc": "37.3394,-121.8950",
            "org": "AS16509 Amazon.com, Inc."
        }"#;
        let rep = parse_ipinfo_io_json(json, None, None, 20_000).unwrap();
        assert_eq!(rep.ip.as_deref(), Some("54.183.12.9"));
        assert_eq!(rep.country.as_deref(), Some("US"));
        assert_eq!(rep.city.as_deref(), Some("San Jose"));
        assert_eq!(rep.lat_tenths, Some(373));
        assert_eq!(rep.lon_tenths, Some(-1219));
        assert_eq!(rep.asn, Some(16509));
        assert_eq!(rep.asn_org, "Amazon.com, Inc.");
        assert_eq!(rep.classification, AsnClassification::DatacenterHosting);
        assert!(rep.is_datacenter);
        assert_eq!(rep.source_tag, "ipinfo.io");
    }

    #[test]
    fn cache_ttl_and_four_tier_fallback_respect_fail_closed_route() {
        let mut cache = IpIntelCache::new(1800, 2);

        // 1. Fail-closed ProbeRoute::Skip makes ZERO HTTP requests
        let mut calls = 0usize;
        let skipped = fetch_ip_purity_with_fetcher(
            &ProbeRoute::Skip("uncovered".into()),
            Some("68.105.28.44"),
            Some("US"),
            1000,
            &mut cache,
            |_| {
                calls += 1;
                Ok((200, "{}".into()))
            },
        );
        assert_eq!(calls, 0);
        assert_eq!(skipped.source_tag, "offline_fail_closed");

        // 2. Tier 1 returns 429 -> falls back to Tier 2 (ipinfo.io) and caches for 30 min
        let route = ProbeRoute::Proxy("http://127.0.0.1:7890".into());
        let mut seen_urls = Vec::new();
        let rep = fetch_ip_purity_with_fetcher(
            &route,
            Some("68.105.28.44"),
            Some("US"),
            1000,
            &mut cache,
            |url| {
                seen_urls.push(url.to_string());
                if url.contains("api.ipapi.is") {
                    Ok((429, "rate limited".into()))
                } else if url.contains("ipinfo.io") {
                    Ok((
                        200,
                        r#"{"ip":"68.105.28.44","country":"US","city":"Phoenix","loc":"33.4484,-112.0740","org":"AS7922 Comcast Cable"}"#.into(),
                    ))
                } else {
                    Err(PlatformError::Network("unexpected".into()))
                }
            },
        );
        assert_eq!(seen_urls.len(), 2);
        assert_eq!(rep.source_tag, "ipinfo.io");
        assert_eq!(rep.classification, AsnClassification::IspResidential);

        // 3. Within 30m TTL (at t=2799) -> cache hit, 0 HTTP calls!
        let mut hit_calls = 0usize;
        let cached = fetch_ip_purity_with_fetcher(
            &route,
            Some(" 68.105.28.44 "),
            Some("US"),
            2799,
            &mut cache,
            |_| {
                hit_calls += 1;
                Err(PlatformError::Network("should not be called".into()))
            },
        );
        assert_eq!(hit_calls, 0);
        assert_eq!(cached.source_tag, "ipinfo.io");
        assert_eq!(cached.asn, Some(7922));

        // 4. After 30m TTL (at t=2800) -> expires; if all HTTP tiers fail -> Tier 3/4 fallback!
        let mut exp_calls = 0usize;
        let expired = fetch_ip_purity_with_fetcher(
            &route,
            Some("68.105.28.44"),
            Some("US"),
            2800,
            &mut cache,
            |url| {
                exp_calls += 1;
                if url.contains("cdn-cgi/trace") {
                    Ok((200, "ip=68.105.28.44\nloc=US\nwarp=off\n".into()))
                } else {
                    Ok((429, "rate limited".into()))
                }
            },
        );
        assert_eq!(exp_calls, 3);
        assert_eq!(expired.source_tag, "cdn-cgi/trace");

        // 5. LRU eviction respects max_entries = 2
        cache.put("1.1.1.1", expired.clone(), 2801);
        cache.put("8.8.8.8", expired.clone(), 2802);
        assert_eq!(cache.len(), 2);
        assert!(cache.get("68.105.28.44", 2803).is_none());
        assert!(cache.get("8.8.8.8", 2803).is_some());
    }

    #[test]
    fn dual_stack_ipv6_split_and_dns_coherence_evaluation() {
        assert!(detect_dual_stack_ipv6_split(Some("US"), Some("CN")));
        assert!(!detect_dual_stack_ipv6_split(Some("US"), Some("US")));
        assert!(!detect_dual_stack_ipv6_split(Some("US"), None));

        assert_eq!(
            parse_edns_resolver_country(
                r#"{"dns":{"ip":"1.1.1.1","geo":"United States - Cloudflare"}}"#
            )
            .as_deref(),
            Some("US")
        );
        assert_eq!(
            parse_edns_resolver_country(
                r#"{"dns":{"ip":"114.114.114.114","geo":"China - ChinaNet"}}"#
            )
            .as_deref(),
            Some("CN")
        );

        let leak = evaluate_dns_coherence(vec!["CN".into()], Some("US"), false, 5000);
        assert!(leak.domestic_resolver_detected);
        assert!(!leak.coherent);

        let fake_ip = evaluate_dns_coherence(vec!["CN".into()], Some("US"), true, 5001);
        assert!(!fake_ip.domestic_resolver_detected);
        assert!(fake_ip.coherent);
        assert!(fake_ip.fake_ip_active);

        let ok = evaluate_dns_coherence(vec!["US".into()], Some("US"), false, 5002);
        assert!(!ok.domestic_resolver_detected);
        assert!(ok.coherent);
    }
}
