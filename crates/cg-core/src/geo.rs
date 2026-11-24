//! Offline Cloudflare edge location (`colo`) and timezone lookup table.

/// Geographic and timezone metadata for a known Cloudflare edge location or country fallback.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Place {
    pub colo: &'static str,
    pub city: &'static str,
    pub country: &'static str,
    pub tz: &'static str,
    pub lat: f64,
    pub lon: f64,
}

/// Cloudflare `colo` IATA code table sorted alphabetically.
pub const PLACES: &[Place] = &[
    Place {
        colo: "ADL",
        city: "阿德莱德",
        country: "AU",
        tz: "Cen. Australia Standard Time",
        lat: -34.9285,
        lon: 138.6007,
    },
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
        colo: "BNE",
        city: "布里斯班",
        country: "AU",
        tz: "E. Australia Standard Time",
        lat: -27.4698,
        lon: 153.0251,
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
        colo: "PER",
        city: "珀斯",
        country: "AU",
        tz: "W. Australia Standard Time",
        lat: -31.9505,
        lon: 115.8605,
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

/// Single-timezone country fallbacks (multi-timezone countries like US/CA/RU/AU are omitted intentionally).
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
        city: "奥克兰",
        country: "NZ",
        tz: "New Zealand Standard Time",
        lat: -36.8485,
        lon: 174.7633,
    },
];

/// Looks up a [`Place`] by Cloudflare `colo` code (case-insensitive).
pub fn by_colo(colo: &str) -> Option<&'static Place> {
    let key = colo.trim().to_ascii_uppercase();
    if key.is_empty() {
        return None;
    }
    PLACES.iter().find(|p| p.colo == key)
}

/// Looks up a single-timezone fallback [`Place`] by ISO alpha-2 country code.
pub fn by_country(country: &str) -> Option<&'static Place> {
    let key = country.trim().to_ascii_uppercase();
    if key.is_empty() {
        return None;
    }
    COUNTRY_FALLBACK.iter().find(|p| p.country == key)
}

/// Resolves geographic metadata preferring `colo` over single-timezone country fallback.
pub fn resolve(colo: Option<&str>, country: Option<&str>) -> Option<&'static Place> {
    colo.and_then(by_colo)
        .or_else(|| country.and_then(by_country))
}

/// Formats latitude/longitude coordinate to 4 decimal places.
pub fn coord(v: f64) -> String {
    format!("{v:.4}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colo_and_country_lookup_work() {
        assert_eq!(by_colo("lax").map(|p| p.city), Some("洛杉矶"));
        assert_eq!(by_colo("nrt").map(|p| p.tz), Some("Tokyo Standard Time"));
        assert_eq!(
            by_colo("per").map(|p| p.tz),
            Some("W. Australia Standard Time")
        );
        assert_eq!(
            by_colo("adl").map(|p| p.tz),
            Some("Cen. Australia Standard Time")
        );
        assert_eq!(
            by_colo("bne").map(|p| p.tz),
            Some("E. Australia Standard Time")
        );
        assert!(by_colo("ZZZ").is_none());
        assert!(by_country("JP").is_some());
        assert!(by_country("US").is_none());
        assert!(by_country("CA").is_none());
        assert!(by_country("AU").is_none());
        assert_eq!(resolve(Some("LAX"), Some("US")).unwrap().city, "洛杉矶");
        assert_eq!(resolve(Some("XXX"), Some("JP")).unwrap().city, "东京");
        assert!(resolve(None, Some("AU")).is_none());
    }

    #[test]
    fn all_places_have_valid_coordinates_and_timezones() {
        for place in PLACES {
            assert_eq!(place.colo.len(), 3);
            assert_eq!(place.country.len(), 2);
            assert!(!place.city.is_empty());
            assert!(!place.tz.is_empty());
            assert!(place.lat.abs() <= 90.0 && place.lon.abs() <= 180.0);
        }
        for place in COUNTRY_FALLBACK {
            assert!(place.colo.is_empty());
            assert_eq!(place.country.len(), 2);
            assert!(!place.tz.is_empty());
        }
        assert_eq!(coord(34.0522), "34.0522");
    }
}
