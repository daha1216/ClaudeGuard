//! Windows timezone & locale reader + default location registry helpers (0 subprocesses).

pub use cg_protocol::EnvInfo;

use crate::traits::{PlatformError, PlatformResult};

/// Windows registry key for Sensor override default location.
pub const SENSOR_OVERRIDE_KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}";

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

/// Map a Windows timezone key to a readable Chinese display label (falling back to key).
pub fn tz_label(key: &str) -> String {
    TZ_LABELS
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| (*v).to_string())
        .unwrap_or_else(|| key.to_string())
}

/// Split a BCP-47 / Windows locale string (e.g. `zh-CN`, `en_US`, `zh-Hans-CN`) into `(lang, region)`.
pub fn split_locale(raw: &str) -> (String, String) {
    let raw = raw.trim();
    if raw.is_empty() {
        return (String::new(), String::new());
    }
    let parts: Vec<&str> = raw.split(['-', '_']).filter(|s| !s.is_empty()).collect();
    let lang = parts
        .first()
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    let region = if parts.len() < 2 {
        String::new()
    } else {
        parts
            .last()
            .filter(|s| s.len() == 2 || s.len() == 3)
            .map(|s| s.to_ascii_uppercase())
            .unwrap_or_default()
    };
    (lang, region)
}

/// Format UTC offset minutes (`480` -> `UTC+8`, `-210` -> `UTC-3:30`).
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

/// Read current Windows timezone & locale from Registry (`0` child processes).
#[cfg(windows)]
pub fn read_env_info() -> EnvInfo {
    let (tz_key, utc_offset_min) = read_timezone_reg();
    let locale = read_locale_reg();
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

#[cfg(not(windows))]
pub fn read_env_info() -> EnvInfo {
    EnvInfo::default()
}

#[cfg(windows)]
fn read_timezone_reg() -> (String, i32) {
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
    let bias: u32 = key.get_value("ActiveTimeBias").unwrap_or(0);
    // Windows ActiveTimeBias is `UTC - Local` in minutes.
    (tz_key, -(bias as i32))
}

#[cfg(windows)]
fn read_locale_reg() -> String {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ};
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let Ok(key) = hkcu.open_subkey_with_flags(r"Control Panel\International", KEY_READ) else {
        return String::new();
    };
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

/// Read Windows Sensor default location `(Latitude, Longitude)` from HKLM Registry.
#[cfg(windows)]
pub fn read_default_location() -> PlatformResult<(Option<String>, Option<String>)> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let Ok(key) = hklm.open_subkey_with_flags(SENSOR_OVERRIDE_KEY, KEY_READ) else {
        return Ok((None, None));
    };
    let lat: Option<String> = key.get_value("Latitude").ok();
    let lon: Option<String> = key.get_value("Longitude").ok();
    Ok((lat, lon))
}

#[cfg(not(windows))]
pub fn read_default_location() -> PlatformResult<(Option<String>, Option<String>)> {
    Err(PlatformError::unsupported(
        "env_alignment",
        "Windows Sensor location registry is only supported on Windows",
    ))
}

/// Write Windows Sensor default location `(Latitude, Longitude)` into HKLM Registry.
#[cfg(windows)]
pub fn write_default_location(lat: &str, lon: &str) -> PlatformResult<()> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let (key, _) = hklm.create_subkey(SENSOR_OVERRIDE_KEY).map_err(|e| {
        PlatformError::AccessDenied(format!("open Sensor override key failed: {e}"))
    })?;
    key.set_value("Latitude", &lat)
        .map_err(|e| PlatformError::AccessDenied(format!("write Latitude failed: {e}")))?;
    key.set_value("Longitude", &lon)
        .map_err(|e| PlatformError::AccessDenied(format!("write Longitude failed: {e}")))?;
    Ok(())
}

#[cfg(not(windows))]
pub fn write_default_location(_lat: &str, _lon: &str) -> PlatformResult<()> {
    Err(PlatformError::unsupported(
        "env_alignment",
        "Windows Sensor location registry is only supported on Windows",
    ))
}

/// Delete Windows Sensor default location values from HKLM Registry.
#[cfg(windows)]
pub fn delete_default_location() -> PlatformResult<()> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_WRITE};
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let Ok(key) = hklm.open_subkey_with_flags(SENSOR_OVERRIDE_KEY, KEY_WRITE) else {
        return Ok(());
    };
    let _ = key.delete_value("Latitude");
    let _ = key.delete_value("Longitude");
    Ok(())
}

#[cfg(not(windows))]
pub fn delete_default_location() -> PlatformResult<()> {
    Err(PlatformError::unsupported(
        "env_alignment",
        "Windows Sensor location registry is only supported on Windows",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locale_and_offset_formatting() {
        assert_eq!(split_locale("zh-CN"), ("zh".into(), "CN".into()));
        assert_eq!(split_locale("en_US"), ("en".into(), "US".into()));
        assert_eq!(split_locale("zh-Hans-CN"), ("zh".into(), "CN".into()));
        assert_eq!(split_locale("ja"), ("ja".into(), String::new()));
        assert_eq!(split_locale(""), (String::new(), String::new()));

        assert_eq!(offset_label(480), "UTC+8");
        assert_eq!(offset_label(0), "UTC+0");
        assert_eq!(offset_label(-300), "UTC-5");
        assert_eq!(offset_label(-210), "UTC-3:30");

        assert_eq!(tz_label("China Standard Time"), "中国标准时间");
        assert_eq!(tz_label("Unknown Zone"), "Unknown Zone");
    }

    #[cfg(windows)]
    #[test]
    fn registry_timezone_and_locale_readable() {
        let info = read_env_info();
        assert!(
            !info.tz_key.is_empty(),
            "TimeZoneKeyName should be readable"
        );
        let _ = read_default_location().expect("location query should not fail");
    }
}
