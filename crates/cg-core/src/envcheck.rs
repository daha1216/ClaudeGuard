//! Pure timezone and locale consistency evaluator against verified egress location.

use crate::geo;
use cg_protocol::{Config, EnvCheck, EnvInfo, TargetState, TargetStatus};

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

pub fn tz_label(key: &str) -> String {
    TZ_LABELS
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| (*v).to_string())
        .unwrap_or_else(|| key.to_string())
}

pub fn split_locale(raw: &str) -> (String, String) {
    let raw = raw.trim();
    if raw.is_empty() {
        return (String::new(), String::new());
    }
    let parts: Vec<&str> = raw.split(['-', '_']).filter(|s| !s.is_empty()).collect();
    let lang = parts.first().map(|s| s.to_lowercase()).unwrap_or_default();
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

pub fn pick_egress(statuses: &[TargetStatus]) -> Option<(Option<String>, Option<String>)> {
    let mut best = None;
    for st in statuses {
        if st.state != TargetState::Pass {
            continue;
        }
        if st.country.is_none() && st.colo.is_none() {
            continue;
        }
        if st.id == "claude" {
            return Some((st.country.clone(), st.colo.clone()));
        }
        if best.is_none() {
            best = Some((st.country.clone(), st.colo.clone()));
        }
    }
    best
}

pub fn evaluate(cfg: &Config, info: EnvInfo, statuses: &[TargetStatus]) -> EnvCheck {
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
        out.note = "环境一致性检查已关闭".into();
        return out;
    }
    let Some((country, colo)) = pick_egress(statuses) else {
        out.note = "没有可用的出口信息，暂不判定".into();
        return out;
    };
    out.egress_country = country.clone();
    out.egress_colo = colo.clone();

    // If Cloudflare Anycast routed to a cross-border POP (e.g. US egress IP hitting YYZ in CA),
    // ignore `colo` so we evaluate against `country` rather than comparing locale against CA.
    let effective_colo =
        colo.as_deref()
            .filter(|c_code| match (geo::by_colo(c_code), country.as_deref()) {
                (Some(colo_place), Some(probe_country)) => {
                    colo_place.country.eq_ignore_ascii_case(probe_country)
                }
                (Some(_), None) => true,
                (None, _) => false,
            });

    if let Some(place) = geo::resolve(effective_colo, country.as_deref()) {
        if out.egress_country.is_none() && !place.country.is_empty() {
            out.egress_country = Some(place.country.to_string());
        }
        out.expect_city = Some(place.city.to_string());
        out.expect_tz = Some(place.tz.to_string());
        out.tz_match = Some(out.info.tz_key.eq_ignore_ascii_case(place.tz));
        let eff_country = country.as_deref().unwrap_or(place.country);
        if !out.info.region.is_empty() && !eff_country.is_empty() {
            out.locale_match = Some(out.info.region.eq_ignore_ascii_case(eff_country));
        }
        out.note = describe(&out);
        return out;
    }

    // Multi-timezone countries without a single default colo (e.g. US, CA, AU) still evaluate `locale_match`.
    if let Some(probe_country) = country.as_deref().filter(|s| !s.is_empty())
        && !out.info.region.is_empty()
    {
        out.locale_match = Some(out.info.region.eq_ignore_ascii_case(probe_country));
        out.note = describe(&out);
        return out;
    }

    out.note = "出口地区不在内置地点表内，暂不判定".into();
    out
}

pub fn describe(c: &EnvCheck) -> String {
    if c.expect_city.is_none() && c.tz_match.is_none() && c.locale_match.is_none() {
        return "出口信息不足，暂不判定".into();
    }
    let country = c.egress_country.clone().unwrap_or_default();
    let target_loc = c
        .expect_city
        .as_deref()
        .or(c.egress_country.as_deref())
        .unwrap_or("未知");
    let mut parts = Vec::new();
    if c.tz_match == Some(false) {
        let sys_tz = if c.info.tz_label.is_empty() {
            "未知时区".to_string()
        } else if c.info.utc_offset_min == 0 {
            c.info.tz_label.clone()
        } else {
            format!(
                "{} {}",
                c.info.tz_label,
                offset_label(c.info.utc_offset_min)
            )
        };
        parts.push(format!("时区不一致（出口在{target_loc}，系统是{sys_tz}）"));
    }
    if c.locale_match == Some(false) {
        let loc = if c.info.locale.is_empty() {
            "未知".to_string()
        } else {
            c.info.locale.clone()
        };
        parts.push(format!("区域不一致（出口在{country}，系统是{loc}）"));
    }
    if parts.is_empty() {
        format!("环境与出口一致（{target_loc}）")
    } else {
        parts.join("；")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cg_protocol::AnchorKind;

    #[test]
    fn splits_locales_formats_offsets_and_detects_mismatches() {
        assert_eq!(split_locale("zh-Hans-CN"), ("zh".into(), "CN".into()));
        assert_eq!(split_locale("ja"), ("ja".into(), String::new()));
        assert_eq!(offset_label(480), "UTC+8");
        assert_eq!(offset_label(-300), "UTC-5");
        assert_eq!(offset_label(-210), "UTC-3:30");

        let info = EnvInfo {
            tz_key: "China Standard Time".into(),
            tz_label: tz_label("China Standard Time"),
            utc_offset_min: 480,
            locale: "zh-CN".into(),
            lang: "zh".into(),
            region: "CN".into(),
        };
        let statuses = vec![TargetStatus {
            id: "claude".into(),
            name: "Claude".into(),
            builtin: true,
            state: TargetState::Pass,
            anchor_url: String::new(),
            anchor_kind: AnchorKind::Auto,
            expect_ips: vec![],
            expect_regions: vec![],
            ip: Some("198.51.100.98".into()),
            country: Some("US".into()),
            raw_region: Some("US".into()),
            colo: Some("LAX".into()),
            city: Some("洛杉矶".into()),
            latency_ms: 40,
            checked_at: Some(100),
            reason: String::new(),
            fail_streak: 0,
            matched_rule: None,
        }];
        let res = evaluate(&Config::default(), info, &statuses);
        assert_eq!(res.tz_match, Some(false));
        assert_eq!(res.locale_match, Some(false));
        assert!(res.mismatched());
        assert!(res.note.contains("洛杉矶"));
    }

    #[test]
    fn cross_border_anycast_colo_and_multi_tz_country_evaluate_cleanly() {
        // 1. US IP routed through Toronto (YYZ, CA) POP while Windows locale is en-US -> MUST NOT mismatch!
        let us_info = EnvInfo {
            tz_key: "Eastern Standard Time".into(),
            tz_label: tz_label("Eastern Standard Time"),
            utc_offset_min: -300,
            locale: "en-US".into(),
            lang: "en".into(),
            region: "US".into(),
        };
        let cross_border = vec![TargetStatus {
            id: "claude".into(),
            name: "Claude".into(),
            builtin: true,
            state: TargetState::Pass,
            anchor_url: String::new(),
            anchor_kind: AnchorKind::Trace,
            expect_ips: vec![],
            expect_regions: vec![],
            ip: Some("198.51.100.98".into()),
            country: Some("US".into()),
            raw_region: Some("US".into()),
            colo: Some("YYZ".into()),
            city: None,
            latency_ms: 28,
            checked_at: Some(200),
            reason: String::new(),
            fail_streak: 0,
            matched_rule: None,
        }];
        let ok_res = evaluate(&Config::default(), us_info, &cross_border);
        assert_eq!(ok_res.locale_match, Some(true));
        assert!(!ok_res.mismatched(), "note={}", ok_res.note);
        assert!(!ok_res.note.contains("不一致"));

        // 2. Multi-TZ country (US/CA/AU) without colo still detects zh-CN locale mismatch.
        let cn_info = EnvInfo {
            tz_key: "China Standard Time".into(),
            tz_label: tz_label("China Standard Time"),
            utc_offset_min: 480,
            locale: "zh-CN".into(),
            lang: "zh".into(),
            region: "CN".into(),
        };
        let ca_no_colo = vec![TargetStatus {
            id: "claude".into(),
            name: "Claude".into(),
            builtin: true,
            state: TargetState::Pass,
            anchor_url: String::new(),
            anchor_kind: AnchorKind::JsonIp,
            expect_ips: vec![],
            expect_regions: vec![],
            ip: Some("203.0.113.45".into()),
            country: Some("CA".into()),
            raw_region: Some("CA".into()),
            colo: None,
            city: None,
            latency_ms: 35,
            checked_at: Some(300),
            reason: String::new(),
            fail_streak: 0,
            matched_rule: None,
        }];
        let mm_res = evaluate(&Config::default(), cn_info, &ca_no_colo);
        assert_eq!(mm_res.tz_match, None);
        assert_eq!(mm_res.locale_match, Some(false));
        assert!(mm_res.mismatched());
        assert!(mm_res.note.contains("出口在CA"));
    }
}
