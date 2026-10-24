//! v3 共享数据模型：目标、锚点、探测结果、判定、状态与更新状态机。
//!
//! 本模块只放跨模块类型与纯工具（序列化 / 地区归一 / IP 归一 / 时间），不做 I/O。

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn default_true() -> bool {
    true
}
pub fn default_timeout() -> u64 {
    12
}

// ---------- 锚点 ----------

/// 探测方式。`Auto` 按响应格式自动识别（trace → json → Gemini 地区标记 → 可达性）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AnchorKind {
    #[default]
    Auto,
    Trace,
    JsonIp,
    GeminiRegion,
    Reachability,
}

impl AnchorKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Auto => "自动识别",
            Self::Trace => "trace 文本",
            Self::JsonIp => "JSON 出口",
            Self::GeminiRegion => "页面地区标记",
            Self::Reachability => "仅可达性",
        }
    }
}

// ---------- 目标 ----------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub builtin: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub anchor_url: String,
    #[serde(default)]
    pub anchor_kind: AnchorKind,
    #[serde(default)]
    pub expect_ips: Vec<String>,
    #[serde(default)]
    pub expect_regions: Vec<String>,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub bind_agent: Option<String>,
}

#[allow(dead_code)]
impl Target {
    pub fn host(&self) -> String {
        self.anchor_url
            .split("://")
            .nth(1)
            .unwrap_or(&self.anchor_url)
            .split('/')
            .next()
            .unwrap_or("")
            .to_string()
    }

    pub fn has_expect(&self) -> bool {
        !self.expect_ips.is_empty() || !self.expect_regions.is_empty()
    }

    pub fn is_reachability(&self) -> bool {
        self.anchor_kind == AnchorKind::Reachability
    }
}

// ---------- 探测结果 ----------

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProbeResult {
    /// 是否拿到任何 HTTP 响应（含 4xx/5xx）。
    pub reachable: bool,
    pub status: Option<u16>,
    pub ip: Option<String>,
    /// 归一后的 ISO alpha-2。
    pub country: Option<String>,
    /// 原始地区原文（如 Gemini 的 USA）。
    pub raw_region: Option<String>,
    pub colo: Option<String>,
    pub city: Option<String>,
    pub latency_ms: u64,
    /// trace | json_ip | gemini_region | reachability | error
    pub parsed_as: String,
    pub detail: String,
}

#[allow(dead_code)]
impl ProbeResult {
    pub fn has_info(&self) -> bool {
        self.ip.is_some() || self.country.is_some()
    }

    pub fn failed(detail: impl Into<String>) -> Self {
        let detail = detail.into();
        Self {
            parsed_as: "error".into(),
            detail,
            ..Self::default()
        }
    }
}

// ---------- 判定 ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Pass,
    Fail,
    Unverified,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evaluation {
    pub verdict: Verdict,
    pub reason: String,
}

// ---------- 目标状态 ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetState {
    Pending,
    Checking,
    Pass,
    Fail,
    Unverified,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetStatus {
    pub id: String,
    pub name: String,
    pub builtin: bool,
    pub state: TargetState,
    pub anchor_url: String,
    pub anchor_kind: AnchorKind,
    pub expect_ips: Vec<String>,
    pub expect_regions: Vec<String>,
    pub ip: Option<String>,
    pub country: Option<String>,
    pub raw_region: Option<String>,
    pub colo: Option<String>,
    pub city: Option<String>,
    pub latency_ms: u64,
    pub checked_at: Option<u64>,
    pub reason: String,
    pub fail_streak: u32,
}

#[allow(dead_code)]
impl TargetStatus {
    pub fn from_target(t: &Target, state: TargetState) -> Self {
        Self {
            id: t.id.clone(),
            name: t.name.clone(),
            builtin: t.builtin,
            state,
            anchor_url: t.anchor_url.clone(),
            anchor_kind: t.anchor_kind,
            expect_ips: t.expect_ips.clone(),
            expect_regions: t.expect_regions.clone(),
            ip: None,
            country: None,
            raw_region: None,
            colo: None,
            city: None,
            latency_ms: 0,
            checked_at: None,
            reason: String::new(),
            fail_streak: 0,
        }
    }

    /// 应用到现有状态（保留 fail_streak 由调用方传入）。
    pub fn apply(&mut self, probe: &ProbeResult, eval: &Evaluation, streak: u32) {
        self.state = match (eval.verdict, probe.reachable) {
            (Verdict::Pass, _) => TargetState::Pass,
            (Verdict::Fail, _) => TargetState::Fail,
            (Verdict::Unverified, _) => TargetState::Unverified,
        };
        self.ip = probe.ip.clone();
        self.country = probe.country.clone();
        self.raw_region = probe.raw_region.clone();
        self.colo = probe.colo.clone();
        self.city = probe.city.clone();
        self.latency_ms = probe.latency_ms;
        self.checked_at = Some(now());
        self.reason = eval.reason.clone();
        self.fail_streak = streak;
    }

    pub fn region_text(&self) -> String {
        match (&self.country, &self.raw_region) {
            (Some(c), _) => region_name(c).to_string(),
            (None, Some(raw)) => raw.clone(),
            _ => String::new(),
        }
    }

    /// 目标行第二行说明（地区 / 组 / 状态原因）。
    pub fn geo_text(&self) -> String {
        if self.state == TargetState::Disabled {
            return "未启用".into();
        }
        if self.anchor_kind == AnchorKind::Reachability {
            return if self.state == TargetState::Pass {
                format!("可达 · {}ms", self.latency_ms)
            } else if self.state == TargetState::Fail {
                "不可达".into()
            } else {
                "待检测".into()
            };
        }
        if self.country.is_some() {
            let mut parts = vec![self.region_text()];
            if let Some(city) = self.city.as_deref().filter(|s| !s.is_empty()) {
                parts.push(city.to_string());
            }
            if let Some(colo) = self.colo.as_deref().filter(|s| !s.is_empty()) {
                parts.push(colo.to_string());
            }
            return parts.join(" · ");
        }
        if self.state == TargetState::Unverified || self.state == TargetState::Pending {
            return self.reason.clone();
        }
        self.reason.clone()
    }
}

// ---------- 整体状态 ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Overall {
    Idle,
    Checking,
    Pass,
    Fail,
    Tripped,
    Paused,
}

/// 断网档位。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CutMode {
    Off,
    Firewall,
    Nics,
}

impl CutMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Off => "不断网",
            Self::Firewall => "防火墙全局阻断",
            Self::Nics => "禁用物理网卡",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TripInfo {
    pub since: u64,
    pub reason: String,
    pub failing_ids: Vec<String>,
    pub killed: u32,
    pub firewall_rules: u32,
    pub quarantined_agents: Vec<String>,
    pub agents: Vec<String>,
    pub network_cut: CutMode,
    pub network_note: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentCount {
    pub id: String,
    pub name: String,
    pub count: usize,
}

// ---------- 软件更新状态机 ----------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum UpdState {
    #[default]
    Idle,
    Checking,
    UpToDate,
    Available {
        ver: String,
        url: String,
        size: u64,
    },
    Downloading {
        done: u64,
        total: u64,
    },
    Restarting,
    Failed {
        msg: String,
    },
}

// ---------- 地区 / IP 归一 ----------

/// alpha-3 → alpha-2（常见国家；覆盖探测器会返回的地区）。
const ALPHA3_TO_ALPHA2: &[(&str, &str)] = &[
    ("USA", "US"),
    ("CAN", "CA"),
    ("MEX", "MX"),
    ("BRA", "BR"),
    ("ARG", "AR"),
    ("CHL", "CL"),
    ("COL", "CO"),
    ("PER", "PE"),
    ("GBR", "GB"),
    ("IRL", "IE"),
    ("FRA", "FR"),
    ("DEU", "DE"),
    ("NLD", "NL"),
    ("BEL", "BE"),
    ("LUX", "LU"),
    ("CHE", "CH"),
    ("AUT", "AT"),
    ("ESP", "ES"),
    ("PRT", "PT"),
    ("ITA", "IT"),
    ("GRC", "GR"),
    ("POL", "PL"),
    ("CZE", "CZ"),
    ("SVK", "SK"),
    ("HUN", "HU"),
    ("ROU", "RO"),
    ("BGR", "BG"),
    ("SWE", "SE"),
    ("NOR", "NO"),
    ("DNK", "DK"),
    ("FIN", "FI"),
    ("EST", "EE"),
    ("LVA", "LV"),
    ("LTU", "LT"),
    ("UKR", "UA"),
    ("RUS", "RU"),
    ("TUR", "TR"),
    ("ISR", "IL"),
    ("ARE", "AE"),
    ("SAU", "SA"),
    ("EGY", "EG"),
    ("ZAF", "ZA"),
    ("NGA", "NG"),
    ("IND", "IN"),
    ("PAK", "PK"),
    ("BGD", "BD"),
    ("THA", "TH"),
    ("VNM", "VN"),
    ("MYS", "MY"),
    ("SGP", "SG"),
    ("IDN", "ID"),
    ("PHL", "PH"),
    ("CHN", "CN"),
    ("HKG", "HK"),
    ("MAC", "MO"),
    ("TWN", "TW"),
    ("JPN", "JP"),
    ("KOR", "KR"),
    ("PRK", "KP"),
    ("MNG", "MN"),
    ("KAZ", "KZ"),
    ("AUS", "AU"),
    ("NZL", "NZ"),
    ("CUB", "CU"),
    ("IRN", "IR"),
    ("SYR", "SY"),
    ("BLR", "BY"),
];

/// 把探测到的地区原文归一为 alpha-2；无法识别返回 None。
pub fn normalize_region(raw: &str) -> Option<String> {
    let up = raw.trim().to_ascii_uppercase();
    match up.len() {
        2 if up.chars().all(|c| c.is_ascii_alphabetic()) => Some(up),
        3 => ALPHA3_TO_ALPHA2
            .iter()
            .find(|(a3, _)| *a3 == up)
            .map(|(_, a2)| (*a2).to_string()),
        _ => None,
    }
}

/// 地区中文名（UI 用；未知时返回代码本身）。
pub fn region_name(code: &str) -> &str {
    match code.to_ascii_uppercase().as_str() {
        "US" => "美国",
        "JP" => "日本",
        "SG" => "新加坡",
        "HK" => "香港",
        "TW" => "台湾",
        "KR" => "韩国",
        "GB" => "英国",
        "DE" => "德国",
        "FR" => "法国",
        "CA" => "加拿大",
        "AU" => "澳大利亚",
        "NL" => "荷兰",
        "RU" => "俄罗斯",
        "IN" => "印度",
        "BR" => "巴西",
        "TR" => "土耳其",
        "AE" => "阿联酋",
        "CH" => "瑞士",
        "SE" => "瑞典",
        "IT" => "意大利",
        "ES" => "西班牙",
        "CN" => "中国",
        "MO" => "澳门",
        _ => code,
    }
}

/// ISO 3166-1 alpha-2 全表：校验用户填写的出口地区，避免把 "ZZ" 这类
/// 永远命中不了的代码写进白名单（会变成永久 Fail → 误熔断）。
const ISO_REGION_CODES: &str = "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW";

/// 是否是已知的 alpha-2 国家/地区代码（大小写不敏感）。
pub fn is_known_region(code: &str) -> bool {
    let up = code.trim().to_ascii_uppercase();
    up.len() == 2 && ISO_REGION_CODES.split(' ').any(|item| item == up)
}

pub fn normalize_ip(raw: &str) -> Option<String> {
    let text = raw.trim();
    if text.is_empty() {
        return None;
    }
    text.parse::<IpAddr>().ok().map(|ip| ip.to_string())
}

pub fn ip_hit(expect: &[String], ip: &str) -> bool {
    let Some(ip) = normalize_ip(ip) else {
        return false;
    };
    expect
        .iter()
        .filter_map(|e| normalize_ip(e))
        .any(|e| e == ip)
}

pub fn region_hit(expect: &[String], country: &str) -> bool {
    let Some(country) = normalize_region(country) else {
        return false;
    };
    expect.iter().any(|e| {
        normalize_region(e)
            .map(|n| n == country)
            .unwrap_or_else(|| e.trim().eq_ignore_ascii_case(country.as_str()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_alpha3_and_alpha2() {
        assert_eq!(normalize_region("USA").as_deref(), Some("US"));
        assert_eq!(normalize_region("jpn").as_deref(), Some("JP"));
        assert_eq!(normalize_region("HK").as_deref(), Some("HK"));
        assert_eq!(normalize_region(" Atlantis ").as_deref(), None);
        assert_eq!(normalize_region("7").as_deref(), None);
    }

    #[test]
    fn matches_regions_ignoring_case() {
        let expect = vec!["US".to_string()];
        assert!(region_hit(&expect, "us"));
        assert!(region_hit(&expect, "USA"));
        assert!(!region_hit(&expect, "JP"));
        assert!(!region_hit(&[], "US"));
    }

    #[test]
    fn normalizes_and_matches_ips() {
        assert_eq!(
            normalize_ip(" 204.1.100.98 ").as_deref(),
            Some("204.1.100.98")
        );
        assert_eq!(normalize_ip("204.1.100.098").as_deref(), None);
        assert_eq!(normalize_ip("::1").as_deref(), Some("::1"));
        let expect = vec!["204.1.100.98".to_string()];
        assert!(ip_hit(&expect, "204.1.100.98"));
        assert!(!ip_hit(&expect, "198.51.100.24"));
        assert!(!ip_hit(&expect, "not-an-ip"));
    }

    #[test]
    fn knows_iso_region_codes() {
        assert!(is_known_region("US"));
        assert!(is_known_region("jp"));
        assert!(is_known_region("GB"));
        assert!(!is_known_region("ZZ"));
        assert!(!is_known_region("USA"));
        assert!(!is_known_region(""));
    }

    #[test]
    fn target_host_drops_scheme_and_path() {
        let t = Target {
            id: "claude".into(),
            name: "Claude 出口".into(),
            builtin: true,
            enabled: true,
            anchor_url: "https://claude.ai/cdn-cgi/trace".into(),
            anchor_kind: AnchorKind::Auto,
            expect_ips: vec![],
            expect_regions: vec![],
            timeout_secs: 12,
            bind_agent: Some("claude".into()),
        };
        assert_eq!(t.host(), "claude.ai");
        assert!(!t.has_expect());
    }
}
