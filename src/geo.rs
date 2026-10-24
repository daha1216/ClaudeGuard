//! 出口地点表：把锚点返回的 Cloudflare 机房代码（colo）映射成可用的地理信息。
//!
//! 用途有两个，都依赖同一份事实：
//! 1. 环境一致性检查（envcheck）——出口在洛杉矶，系统时区却是「China Standard Time」，
//!    这种自相矛盾的组合本身就是异常信号。
//! 2. 环境对齐（envfix）——把系统时区、Windows 默认位置改到与出口一致。
//!
//! 表是**离线内置**的：对齐功能不能为了拿坐标再发一次网络请求（那等于把探测面扩大，
//! 与 netpol「探测是唯一允许直连的场景」冲突）。代价是表外的小机房只能按国家兜底，
//! 连国家都没有就干脆不动——宁可不改，也不能改错。

/// 一个已知出口地点。`tz` 是 Windows 时区键名（`tzutil /s` 直接吃这个格式）。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Place {
    pub colo: &'static str,
    pub city: &'static str,
    pub country: &'static str,
    pub tz: &'static str,
    pub lat: f64,
    pub lon: f64,
}

/// Cloudflare 机房代码 → 地点。覆盖常见落地城市，按代码字典序排列便于核对。
pub const PLACES: &[Place] = &[
    Place {
        colo: "AKL",
        city: "奥克兰",
        country: "NZ",
        tz: "New Zealand Standard Time",
        lat: -36.8485,
        lon: 174.7633,
    },
    Place {
        colo: "AMS",
        city: "阿姆斯特丹",
        country: "NL",
        tz: "W. Europe Standard Time",
        lat: 52.3676,
        lon: 4.9041,
    },
    Place {
        colo: "ARN",
        city: "斯德哥尔摩",
        country: "SE",
        tz: "W. Europe Standard Time",
        lat: 59.3293,
        lon: 18.0686,
    },
    Place {
        colo: "ATH",
        city: "雅典",
        country: "GR",
        tz: "GTB Standard Time",
        lat: 37.9838,
        lon: 23.7275,
    },
    Place {
        colo: "ATL",
        city: "亚特兰大",
        country: "US",
        tz: "Eastern Standard Time",
        lat: 33.7490,
        lon: -84.3880,
    },
    Place {
        colo: "BKK",
        city: "曼谷",
        country: "TH",
        tz: "SE Asia Standard Time",
        lat: 13.7563,
        lon: 100.5018,
    },
    Place {
        colo: "BOM",
        city: "孟买",
        country: "IN",
        tz: "India Standard Time",
        lat: 19.0760,
        lon: 72.8777,
    },
    Place {
        colo: "BUD",
        city: "布达佩斯",
        country: "HU",
        tz: "Central Europe Standard Time",
        lat: 47.4979,
        lon: 19.0402,
    },
    Place {
        colo: "CDG",
        city: "巴黎",
        country: "FR",
        tz: "Romance Standard Time",
        lat: 48.8566,
        lon: 2.3522,
    },
    Place {
        colo: "CGK",
        city: "雅加达",
        country: "ID",
        tz: "SE Asia Standard Time",
        lat: -6.2088,
        lon: 106.8456,
    },
    Place {
        colo: "CPH",
        city: "哥本哈根",
        country: "DK",
        tz: "W. Europe Standard Time",
        lat: 55.6761,
        lon: 12.5683,
    },
    Place {
        colo: "DEL",
        city: "新德里",
        country: "IN",
        tz: "India Standard Time",
        lat: 28.6139,
        lon: 77.2090,
    },
    Place {
        colo: "DFW",
        city: "达拉斯",
        country: "US",
        tz: "Central Standard Time",
        lat: 32.7767,
        lon: -96.7970,
    },
    Place {
        colo: "DUB",
        city: "都柏林",
        country: "IE",
        tz: "GMT Standard Time",
        lat: 53.3498,
        lon: -6.2603,
    },
    Place {
        colo: "DXB",
        city: "迪拜",
        country: "AE",
        tz: "Arabian Standard Time",
        lat: 25.2048,
        lon: 55.2708,
    },
    Place {
        colo: "EWR",
        city: "纽瓦克",
        country: "US",
        tz: "Eastern Standard Time",
        lat: 40.7357,
        lon: -74.1724,
    },
    Place {
        colo: "FRA",
        city: "法兰克福",
        country: "DE",
        tz: "W. Europe Standard Time",
        lat: 50.1109,
        lon: 8.6821,
    },
    Place {
        colo: "GRU",
        city: "圣保罗",
        country: "BR",
        tz: "E. South America Standard Time",
        lat: -23.5505,
        lon: -46.6333,
    },
    Place {
        colo: "HEL",
        city: "赫尔辛基",
        country: "FI",
        tz: "FLE Standard Time",
        lat: 60.1699,
        lon: 24.9384,
    },
    Place {
        colo: "HKG",
        city: "香港",
        country: "HK",
        tz: "China Standard Time",
        lat: 22.3193,
        lon: 114.1694,
    },
    Place {
        colo: "IAD",
        city: "阿什本",
        country: "US",
        tz: "Eastern Standard Time",
        lat: 39.0438,
        lon: -77.4874,
    },
    Place {
        colo: "ICN",
        city: "首尔",
        country: "KR",
        tz: "Korea Standard Time",
        lat: 37.5665,
        lon: 126.9780,
    },
    Place {
        colo: "IST",
        city: "伊斯坦布尔",
        country: "TR",
        tz: "Turkey Standard Time",
        lat: 41.0082,
        lon: 28.9784,
    },
    Place {
        colo: "JNB",
        city: "约翰内斯堡",
        country: "ZA",
        tz: "South Africa Standard Time",
        lat: -26.2041,
        lon: 28.0473,
    },
    Place {
        colo: "KIX",
        city: "大阪",
        country: "JP",
        tz: "Tokyo Standard Time",
        lat: 34.6937,
        lon: 135.5023,
    },
    Place {
        colo: "KUL",
        city: "吉隆坡",
        country: "MY",
        tz: "Singapore Standard Time",
        lat: 3.1390,
        lon: 101.6869,
    },
    Place {
        colo: "LAX",
        city: "洛杉矶",
        country: "US",
        tz: "Pacific Standard Time",
        lat: 34.0522,
        lon: -118.2437,
    },
    Place {
        colo: "LHR",
        city: "伦敦",
        country: "GB",
        tz: "GMT Standard Time",
        lat: 51.5074,
        lon: -0.1278,
    },
    Place {
        colo: "LIS",
        city: "里斯本",
        country: "PT",
        tz: "GMT Standard Time",
        lat: 38.7223,
        lon: -9.1393,
    },
    Place {
        colo: "MAD",
        city: "马德里",
        country: "ES",
        tz: "Romance Standard Time",
        lat: 40.4168,
        lon: -3.7038,
    },
    Place {
        colo: "MEL",
        city: "墨尔本",
        country: "AU",
        tz: "AUS Eastern Standard Time",
        lat: -37.8136,
        lon: 144.9631,
    },
    Place {
        colo: "MEX",
        city: "墨西哥城",
        country: "MX",
        tz: "Central Standard Time (Mexico)",
        lat: 19.4326,
        lon: -99.1332,
    },
    Place {
        colo: "MIA",
        city: "迈阿密",
        country: "US",
        tz: "Eastern Standard Time",
        lat: 25.7617,
        lon: -80.1918,
    },
    Place {
        colo: "MOW",
        city: "莫斯科",
        country: "RU",
        tz: "Russian Standard Time",
        lat: 55.7558,
        lon: 37.6173,
    },
    Place {
        colo: "MXP",
        city: "米兰",
        country: "IT",
        tz: "W. Europe Standard Time",
        lat: 45.4642,
        lon: 9.1900,
    },
    Place {
        colo: "NRT",
        city: "东京",
        country: "JP",
        tz: "Tokyo Standard Time",
        lat: 35.6762,
        lon: 139.6503,
    },
    Place {
        colo: "ORD",
        city: "芝加哥",
        country: "US",
        tz: "Central Standard Time",
        lat: 41.8781,
        lon: -87.6298,
    },
    Place {
        colo: "OSL",
        city: "奥斯陆",
        country: "NO",
        tz: "W. Europe Standard Time",
        lat: 59.9139,
        lon: 10.7522,
    },
    Place {
        colo: "PRG",
        city: "布拉格",
        country: "CZ",
        tz: "Central Europe Standard Time",
        lat: 50.0755,
        lon: 14.4378,
    },
    Place {
        colo: "SEA",
        city: "西雅图",
        country: "US",
        tz: "Pacific Standard Time",
        lat: 47.6062,
        lon: -122.3321,
    },
    Place {
        colo: "SFO",
        city: "旧金山",
        country: "US",
        tz: "Pacific Standard Time",
        lat: 37.7749,
        lon: -122.4194,
    },
    Place {
        colo: "SIN",
        city: "新加坡",
        country: "SG",
        tz: "Singapore Standard Time",
        lat: 1.3521,
        lon: 103.8198,
    },
    Place {
        colo: "SJC",
        city: "圣何塞",
        country: "US",
        tz: "Pacific Standard Time",
        lat: 37.3382,
        lon: -121.8863,
    },
    Place {
        colo: "SYD",
        city: "悉尼",
        country: "AU",
        tz: "AUS Eastern Standard Time",
        lat: -33.8688,
        lon: 151.2093,
    },
    Place {
        colo: "TLV",
        city: "特拉维夫",
        country: "IL",
        tz: "Israel Standard Time",
        lat: 32.0853,
        lon: 34.7818,
    },
    Place {
        colo: "TPE",
        city: "台北",
        country: "TW",
        tz: "Taipei Standard Time",
        lat: 25.0330,
        lon: 121.5654,
    },
    Place {
        colo: "VIE",
        city: "维也纳",
        country: "AT",
        tz: "W. Europe Standard Time",
        lat: 48.2082,
        lon: 16.3738,
    },
    Place {
        colo: "WAW",
        city: "华沙",
        country: "PL",
        tz: "Central European Standard Time",
        lat: 52.2297,
        lon: 21.0122,
    },
    Place {
        colo: "YVR",
        city: "温哥华",
        country: "CA",
        tz: "Pacific Standard Time",
        lat: 49.2827,
        lon: -123.1207,
    },
    Place {
        colo: "YYZ",
        city: "多伦多",
        country: "CA",
        tz: "Eastern Standard Time",
        lat: 43.6532,
        lon: -79.3832,
    },
    Place {
        colo: "ZRH",
        city: "苏黎世",
        country: "CH",
        tz: "W. Europe Standard Time",
        lat: 47.3769,
        lon: 8.5417,
    },
];

/// 只有单一时区的国家 → 兜底地点。多时区国家（US/CA/RU/BR/AU/MX/ID）故意不放，
/// 拿首都时区去猜一个横跨四个时区的国家只会改错。
pub const COUNTRY_FALLBACK: &[Place] = &[
    Place {
        colo: "",
        city: "新加坡",
        country: "SG",
        tz: "Singapore Standard Time",
        lat: 1.3521,
        lon: 103.8198,
    },
    Place {
        colo: "",
        city: "香港",
        country: "HK",
        tz: "China Standard Time",
        lat: 22.3193,
        lon: 114.1694,
    },
    Place {
        colo: "",
        city: "东京",
        country: "JP",
        tz: "Tokyo Standard Time",
        lat: 35.6762,
        lon: 139.6503,
    },
    Place {
        colo: "",
        city: "首尔",
        country: "KR",
        tz: "Korea Standard Time",
        lat: 37.5665,
        lon: 126.9780,
    },
    Place {
        colo: "",
        city: "台北",
        country: "TW",
        tz: "Taipei Standard Time",
        lat: 25.0330,
        lon: 121.5654,
    },
    Place {
        colo: "",
        city: "曼谷",
        country: "TH",
        tz: "SE Asia Standard Time",
        lat: 13.7563,
        lon: 100.5018,
    },
    Place {
        colo: "",
        city: "孟买",
        country: "IN",
        tz: "India Standard Time",
        lat: 19.0760,
        lon: 72.8777,
    },
    Place {
        colo: "",
        city: "迪拜",
        country: "AE",
        tz: "Arabian Standard Time",
        lat: 25.2048,
        lon: 55.2708,
    },
    Place {
        colo: "",
        city: "伦敦",
        country: "GB",
        tz: "GMT Standard Time",
        lat: 51.5074,
        lon: -0.1278,
    },
    Place {
        colo: "",
        city: "巴黎",
        country: "FR",
        tz: "Romance Standard Time",
        lat: 48.8566,
        lon: 2.3522,
    },
    Place {
        colo: "",
        city: "柏林",
        country: "DE",
        tz: "W. Europe Standard Time",
        lat: 52.5200,
        lon: 13.4050,
    },
    Place {
        colo: "",
        city: "阿姆斯特丹",
        country: "NL",
        tz: "W. Europe Standard Time",
        lat: 52.3676,
        lon: 4.9041,
    },
    Place {
        colo: "",
        city: "苏黎世",
        country: "CH",
        tz: "W. Europe Standard Time",
        lat: 47.3769,
        lon: 8.5417,
    },
    Place {
        colo: "",
        city: "斯德哥尔摩",
        country: "SE",
        tz: "W. Europe Standard Time",
        lat: 59.3293,
        lon: 18.0686,
    },
    Place {
        colo: "",
        city: "华沙",
        country: "PL",
        tz: "Central European Standard Time",
        lat: 52.2297,
        lon: 21.0122,
    },
    Place {
        colo: "",
        city: "布拉格",
        country: "CZ",
        tz: "Central Europe Standard Time",
        lat: 50.0755,
        lon: 14.4378,
    },
    Place {
        colo: "",
        city: "赫尔辛基",
        country: "FI",
        tz: "FLE Standard Time",
        lat: 60.1699,
        lon: 24.9384,
    },
    Place {
        colo: "",
        city: "雅典",
        country: "GR",
        tz: "GTB Standard Time",
        lat: 37.9838,
        lon: 23.7275,
    },
    Place {
        colo: "",
        city: "伊斯坦布尔",
        country: "TR",
        tz: "Turkey Standard Time",
        lat: 41.0082,
        lon: 28.9784,
    },
    Place {
        colo: "",
        city: "特拉维夫",
        country: "IL",
        tz: "Israel Standard Time",
        lat: 32.0853,
        lon: 34.7818,
    },
    Place {
        colo: "",
        city: "约翰内斯堡",
        country: "ZA",
        tz: "South Africa Standard Time",
        lat: -26.2041,
        lon: 28.0473,
    },
    Place {
        colo: "",
        city: "悉尼",
        country: "AU",
        tz: "AUS Eastern Standard Time",
        lat: -33.8688,
        lon: 151.2093,
    },
    Place {
        colo: "",
        city: "奥克兰",
        country: "NZ",
        tz: "New Zealand Standard Time",
        lat: -36.8485,
        lon: 174.7633,
    },
];

/// 按机房代码查（大小写不敏感）。锚点里的 colo 通常是三个大写字母。
pub fn by_colo(colo: &str) -> Option<&'static Place> {
    let key = colo.trim().to_ascii_uppercase();
    if key.is_empty() {
        return None;
    }
    PLACES.iter().find(|p| p.colo == key)
}

/// 按国家代码兜底查（仅单时区国家）。
pub fn by_country(country: &str) -> Option<&'static Place> {
    let key = country.trim().to_ascii_uppercase();
    if key.is_empty() {
        return None;
    }
    COUNTRY_FALLBACK.iter().find(|p| p.country == key)
}

/// 先看机房、再看国家。`colo` 为空时退化成国家兜底。
pub fn resolve(colo: Option<&str>, country: Option<&str>) -> Option<&'static Place> {
    colo.and_then(by_colo)
        .or_else(|| country.and_then(by_country))
}

/// 把经纬度格式化成 Windows 默认位置用的字符串（十进制、最多 4 位小数）。
pub fn coord(v: f64) -> String {
    format!("{:.4}", v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colo_lookup_is_case_insensitive() {
        assert_eq!(by_colo("lax").map(|p| p.country), Some("US"));
        assert_eq!(by_colo(" LAX ").map(|p| p.city), Some("洛杉矶"));
        assert!(by_colo("").is_none());
        assert!(by_colo("ZZZ").is_none());
    }

    #[test]
    fn country_fallback_skips_multi_tz_countries() {
        assert!(by_country("JP").is_some());
        // 多时区国家不兜底，避免猜错时区
        assert!(by_country("US").is_none());
        assert!(by_country("RU").is_none());
        assert!(by_country("ca").is_none());
    }

    #[test]
    fn resolve_prefers_colo_then_country() {
        // 机房命中，即使国家兜底表里也有该国家
        let p = resolve(Some("NRT"), Some("JP")).unwrap();
        assert_eq!(p.city, "东京");
        // 机房未知 → 国家兜底
        let p = resolve(Some("XYZ"), Some("JP")).unwrap();
        assert_eq!(p.city, "东京");
        // 都没有
        assert!(resolve(None, None).is_none());
        assert!(resolve(Some("XYZ"), Some("US")).is_none());
    }

    #[test]
    fn every_place_has_usable_fields() {
        for p in PLACES {
            assert_eq!(p.colo.len(), 3, "机房代码应为 3 位：{}", p.colo);
            assert!(!p.tz.is_empty());
            assert!(p.lat.abs() <= 90.0 && p.lon.abs() <= 180.0);
            assert!(!p.city.is_empty() && p.country.len() == 2);
        }
        for p in COUNTRY_FALLBACK {
            assert!(p.colo.is_empty());
            assert!(!p.tz.is_empty());
        }
    }

    #[test]
    fn coords_are_fixed_precision() {
        assert_eq!(coord(34.0522), "34.0522");
        assert_eq!(coord(-118.2437), "-118.2437");
        assert_eq!(coord(0.0), "0.0000");
    }
}
