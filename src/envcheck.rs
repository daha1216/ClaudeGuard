//! 环境一致性检查（v3.12 引入）。
//!
//! 出口校验回答的是"流量从哪个 IP 出去"，但一个环境是否自洽还取决于另一组信号：
//! 系统时区、区域格式、语言。出口在美国、系统时区却是 UTC+8、区域是 zh-CN，
//! 这种组合本身就说明"人和出口不在一起"——对需要一致性的场景来说，它和 IP 不对一样显眼。
//!
//! 这里只做**检查**，不擅自改动系统（改动见 [`crate::envfix`]）。检查结论只用于提示，
//! 不参与熔断：用户完全可能就是想保持中文系统，那不该被判定成故障。
//!
//! 读取全部走注册表，不起子进程：
//! - 时区：`HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation` 的 `TimeZoneKeyName`
//! - 区域：`HKCU\Control Panel\International` 的 `LocaleName`（缺省时退回 `sLanguage`）

use serde::Serialize;

use crate::config::Config;
use crate::geo;
use crate::model::TargetStatus;

/// 系统当前的语言/时区画像。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct EnvInfo {
    /// Windows 时区键名，如 `China Standard Time`。
    pub tz_key: String,
    /// 展示用中文名，如「中国标准时间」。
    pub tz_label: String,
    /// 相对 UTC 的偏移（分钟），东八区 = 480。
    pub utc_offset_min: i32,
    /// 区域设置，如 `zh-CN`。
    pub locale: String,
    /// 语言部分，如 `zh`。
    pub lang: String,
    /// 区域部分，如 `CN`。
    pub region: String,
}

/// 一次一致性检查的结论。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvCheck {
    pub info: EnvInfo,
    /// 判定所依据的出口国家（取第一个通过且有国家信息的目标）。
    pub egress_country: Option<String>,
    /// 出口机房代码（有则用于更精确的时区匹配）。
    pub egress_colo: Option<String>,
    /// 期望城市（来自内置地点表）。
    pub expect_city: Option<String>,
    /// 期望的 Windows 时区键名。
    pub expect_tz: Option<String>,
    /// 时区是否与出口一致。`None` = 无法判定（出口信息不足）。
    pub tz_match: Option<bool>,
    /// 区域是否与出口一致。`None` = 无法判定。
    pub locale_match: Option<bool>,
    pub note: String,
}

impl EnvCheck {
    /// 是否存在可提示的不一致。
    pub fn mismatched(&self) -> bool {
        self.tz_match == Some(false) || self.locale_match == Some(false)
    }
}

/// 常见 Windows 时区键 → 中文名。表外的直接显示键名，不影响判定。
const TZ_LABELS: &[(&str, &str)] = &[
    ("China Standard Time", "中国标准时间"),
    ("Taipei Standard Time", "台北标准时间"),
    ("Tokyo Standard Time", "日本标准时间"),
    ("Korea Standard Time", "韩国标准时间"),
    ("Singapore Standard Time", "新加坡标准时间"),
    ("SE Asia Standard Time", "东南亚标准时间"),
    ("India Standard Time", "印度标准时间"),
    ("Arabian Standard Time", "阿拉伯标准时间"),
    ("Israel Standard Time", "以色列标准时间"),
    ("Turkey Standard Time", "土耳其标准时间"),
    ("Russian Standard Time", "俄罗斯标准时间"),
    ("GMT Standard Time", "格林尼治标准时间"),
    ("W. Europe Standard Time", "西欧标准时间"),
    ("Romance Standard Time", "中欧标准时间（巴黎）"),
    ("Central Europe Standard Time", "中欧标准时间（布拉格）"),
    ("Central European Standard Time", "中欧标准时间（华沙）"),
    ("FLE Standard Time", "东欧标准时间"),
    ("GTB Standard Time", "希腊标准时间"),
    ("Pacific Standard Time", "美国太平洋时间"),
    ("Mountain Standard Time", "美国山地时间"),
    ("Central Standard Time", "美国中部时间"),
    ("Eastern Standard Time", "美国东部时间"),
    ("Central Standard Time (Mexico)", "墨西哥中部时间"),
    ("E. South America Standard Time", "巴西标准时间"),
    ("AUS Eastern Standard Time", "澳大利亚东部时间"),
    ("New Zealand Standard Time", "新西兰标准时间"),
    ("South Africa Standard Time", "南非标准时间"),
];

/// 时区键 → 中文名。
pub fn tz_label(key: &str) -> String {
    TZ_LABELS
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.to_string())
        .unwrap_or_else(|| key.to_string())
}

/// 纯函数：把 `LocaleName`（如 `zh-CN`）拆成语言与区域。
pub fn split_locale(raw: &str) -> (String, String) {
    let raw = raw.trim();
    if raw.is_empty() {
        return (String::new(), String::new());
    }
    // 兼容 `zh_CN` / `zh-Hans-CN` 等写法：语言取第一段，区域取最后一段
    let parts: Vec<&str> = raw.split(['-', '_']).filter(|s| !s.is_empty()).collect();
    let lang = parts.first().map(|s| s.to_lowercase()).unwrap_or_default();
    // 只有一段时那一段就是语言本身，不能再当区域（`ja` 不是 `JA`）
    let region = if parts.len() < 2 {
        String::new()
    } else {
        parts
            .last()
            .filter(|s| s.len() == 2 || s.len() == 3)
            .map(|s| s.to_uppercase())
            .unwrap_or_default()
    };
    (lang, region)
}

/// 纯函数：UTC 偏移分钟 → `UTC+8` / `UTC-3:30` 这类展示串。
pub fn offset_label(min: i32) -> String {
    let sign = if min < 0 { '-' } else { '+' };
    let abs = min.abs();
    let h = abs / 60;
    let m = abs % 60;
    if m == 0 {
        format!("UTC{sign}{h}")
    } else {
        format!("UTC{sign}{h}:{m:02}")
    }
}

/// 读系统时区与区域。
pub fn read_env() -> EnvInfo {
    let (tz_key, utc_offset_min) = read_timezone();
    let locale = read_locale();
    let (lang, region) = split_locale(&locale);
    EnvInfo {
        tz_label: tz_label(&tz_key),
        tz_key,
        utc_offset_min,
        locale,
        lang,
        region,
    }
}

#[cfg(windows)]
fn read_timezone() -> (String, i32) {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let Ok(key) = hklm.open_subkey_with_flags(
        r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation",
        KEY_READ,
    ) else {
        return (String::new(), 0);
    };
    let tz_key: String = key.get_value("TimeZoneKeyName").unwrap_or_default();
    // ActiveTimeBias：本地时间 = UTC + (-bias)，单位分钟
    let bias: u32 = key.get_value("ActiveTimeBias").unwrap_or(0);
    let offset = -(bias as i32);
    (tz_key, offset)
}

#[cfg(not(windows))]
fn read_timezone() -> (String, i32) {
    (String::new(), 0)
}

#[cfg(windows)]
fn read_locale() -> String {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let Ok(key) = hkcu.open_subkey_with_flags(r"Control Panel\International", KEY_READ) else {
        return String::new();
    };
    // LocaleName 是 Win10+ 的标准位置；老系统退回 sLanguage + sCountry
    if let Ok(name) = key.get_value::<String, _>("LocaleName") {
        if !name.trim().is_empty() {
            return name.trim().to_string();
        }
    }
    let lang: String = key.get_value("sLanguage").unwrap_or_default();
    let country: String = key.get_value("sCountry").unwrap_or_default();
    if lang.is_empty() {
        String::new()
    } else if country.is_empty() {
        lang
    } else {
        format!("{lang}-{country}")
    }
}

#[cfg(not(windows))]
fn read_locale() -> String {
    String::new()
}

/// 从目标状态里挑出"判定所依据的出口"：优先 claude，其次任意通过且有国家信息的目标。
pub fn pick_egress(statuses: &[TargetStatus]) -> Option<(Option<String>, Option<String>)> {
    let mut best: Option<(Option<String>, Option<String>)> = None;
    for st in statuses {
        if st.state != crate::model::TargetState::Pass {
            continue;
        }
        let country = st.country.clone();
        let colo = st.colo.clone();
        if country.is_none() && colo.is_none() {
            continue;
        }
        if st.id == "claude" {
            return Some((country, colo));
        }
        if best.is_none() {
            best = Some((country, colo));
        }
    }
    best
}

/// 执行一次检查。`cfg.env_check` 关闭时返回空结论（`tz_match`/`locale_match` 均为 `None`）。
pub fn check(cfg: &Config, statuses: &[TargetStatus]) -> EnvCheck {
    let info = read_env();
    let mut out = EnvCheck {
        info,
        egress_country: None,
        egress_colo: None,
        expect_city: None,
        expect_tz: None,
        tz_match: None,
        locale_match: None,
        note: String::new(),
    };
    if !cfg.env_check {
        out.note = "环境一致性检查已关闭".to_string();
        return out;
    }
    let Some((country, colo)) = pick_egress(statuses) else {
        out.note = "没有可用的出口信息，暂不判定".to_string();
        return out;
    };
    out.egress_country = country.clone();
    out.egress_colo = colo.clone();
    let Some(place) = geo::resolve(colo.as_deref(), country.as_deref()) else {
        out.note = "出口地区不在内置地点表内，暂不判定".to_string();
        return out;
    };
    out.expect_city = Some(place.city.to_string());
    out.expect_tz = Some(place.tz.to_string());
    out.tz_match = Some(out.info.tz_key.eq_ignore_ascii_case(place.tz));
    if !out.info.region.is_empty() && !place.country.is_empty() {
        out.locale_match = Some(out.info.region.eq_ignore_ascii_case(place.country));
    }
    out.note = describe(&out);
    out
}

/// 纯函数：把结论写成一句人话。
pub fn describe(c: &EnvCheck) -> String {
    let Some(city) = &c.expect_city else {
        return "出口信息不足，暂不判定".to_string();
    };
    let country = c.egress_country.clone().unwrap_or_default();
    let mut parts: Vec<String> = Vec::new();
    match c.tz_match {
        // 一致的项不进文案：全一致时下面会给出「环境与出口一致」
        Some(true) | None => {}
        Some(false) => parts.push(format!(
            "时区不一致（出口在{}，系统是{}）",
            city,
            if c.info.tz_label.is_empty() {
                "未知时区".to_string()
            } else {
                format!(
                    "{}{}",
                    c.info.tz_label,
                    offset_suffix(c.info.utc_offset_min)
                )
            }
        )),
    }
    match c.locale_match {
        Some(true) => {}
        Some(false) => parts.push(format!(
            "区域不一致（出口在{}，系统是{}）",
            country,
            if c.info.locale.is_empty() {
                "未知".to_string()
            } else {
                c.info.locale.clone()
            }
        )),
        None => {}
    }
    if parts.is_empty() {
        format!("环境与出口一致（{}）", city)
    } else {
        parts.join("；")
    }
}

fn offset_suffix(min: i32) -> String {
    if min == 0 {
        String::new()
    } else {
        format!(" {}", offset_label(min))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AnchorKind, TargetState, TargetStatus};

    fn status(
        id: &str,
        state: TargetState,
        country: Option<&str>,
        colo: Option<&str>,
    ) -> TargetStatus {
        TargetStatus {
            id: id.to_string(),
            name: id.to_string(),
            builtin: true,
            state,
            anchor_url: String::new(),
            anchor_kind: AnchorKind::Auto,
            expect_ips: Vec::new(),
            expect_regions: Vec::new(),
            ip: None,
            country: country.map(str::to_string),
            raw_region: None,
            colo: colo.map(str::to_string),
            city: None,
            latency_ms: 0,
            checked_at: None,
            reason: String::new(),
            fail_streak: 0,
        }
    }

    #[test]
    fn locale_splitting_handles_common_shapes() {
        assert_eq!(split_locale("zh-CN"), ("zh".into(), "CN".into()));
        assert_eq!(split_locale("en_US"), ("en".into(), "US".into()));
        assert_eq!(split_locale("zh-Hans-CN"), ("zh".into(), "CN".into()));
        assert_eq!(split_locale(""), (String::new(), String::new()));
        // 只有语言时区域为空
        assert_eq!(split_locale("ja"), ("ja".into(), String::new()));
    }

    #[test]
    fn offset_labels_are_readable() {
        assert_eq!(offset_label(480), "UTC+8");
        assert_eq!(offset_label(0), "UTC+0");
        assert_eq!(offset_label(-300), "UTC-5");
        assert_eq!(offset_label(-210), "UTC-3:30");
    }

    #[test]
    fn tz_label_falls_back_to_key() {
        assert_eq!(tz_label("China Standard Time"), "中国标准时间");
        assert_eq!(tz_label("Nowhere Standard Time"), "Nowhere Standard Time");
    }

    #[test]
    fn pick_egress_prefers_claude() {
        let statuses = vec![
            status("local", TargetState::Pass, Some("JP"), Some("NRT")),
            status("claude", TargetState::Pass, Some("US"), Some("LAX")),
        ];
        let (country, colo) = pick_egress(&statuses).unwrap();
        assert_eq!(country.as_deref(), Some("US"));
        assert_eq!(colo.as_deref(), Some("LAX"));
    }

    #[test]
    fn pick_egress_skips_failing_targets() {
        let statuses = vec![
            status("claude", TargetState::Fail, Some("CN"), None),
            status("codex", TargetState::Pass, Some("US"), Some("SJC")),
        ];
        let (country, _) = pick_egress(&statuses).unwrap();
        assert_eq!(country.as_deref(), Some("US"));
    }

    #[test]
    fn pick_egress_none_when_nothing_usable() {
        let statuses = vec![status("claude", TargetState::Pass, None, None)];
        assert!(pick_egress(&statuses).is_none());
    }

    fn check_with(tz_key: &str, region: &str, country: &str, colo: &str) -> EnvCheck {
        let info = EnvInfo {
            tz_key: tz_key.to_string(),
            tz_label: tz_label(tz_key),
            utc_offset_min: 480,
            locale: format!("zh-{region}"),
            lang: "zh".to_string(),
            region: region.to_string(),
        };
        let place = geo::resolve(Some(colo), Some(country)).unwrap();
        EnvCheck {
            info,
            egress_country: Some(country.to_string()),
            egress_colo: Some(colo.to_string()),
            expect_city: Some(place.city.to_string()),
            expect_tz: Some(place.tz.to_string()),
            tz_match: Some(tz_key.eq_ignore_ascii_case(place.tz)),
            locale_match: Some(region.eq_ignore_ascii_case(place.country)),
            note: String::new(),
        }
    }

    #[test]
    fn mismatch_is_reported_in_plain_words() {
        let mut c = check_with("China Standard Time", "CN", "US", "LAX");
        c.note = describe(&c);
        assert_eq!(c.tz_match, Some(false));
        assert_eq!(c.locale_match, Some(false));
        assert!(c.mismatched());
        assert!(c.note.contains("时区不一致"));
        assert!(c.note.contains("洛杉矶"));
        assert!(c.note.contains("区域不一致"));
    }

    #[test]
    fn consistent_environment_is_quiet() {
        let mut c = check_with("Pacific Standard Time", "US", "US", "LAX");
        c.note = describe(&c);
        assert_eq!(c.tz_match, Some(true));
        assert_eq!(c.locale_match, Some(true));
        assert!(!c.mismatched());
        assert!(c.note.contains("环境与出口一致"));
    }

    #[test]
    fn timezone_only_mismatch_still_reported() {
        let mut c = check_with("China Standard Time", "US", "US", "LAX");
        c.note = describe(&c);
        assert_eq!(c.tz_match, Some(false));
        assert_eq!(c.locale_match, Some(true));
        assert!(c.note.contains("时区不一致"));
        assert!(!c.note.contains("区域不一致"));
    }

    #[test]
    fn disabled_check_says_so() {
        let cfg = Config {
            env_check: false,
            ..Config::default()
        };
        let c = check(&cfg, &[]);
        assert!(c.tz_match.is_none());
        assert!(c.note.contains("已关闭"));
    }
}
