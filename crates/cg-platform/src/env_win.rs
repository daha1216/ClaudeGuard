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

#[cfg(any(windows, test))]
fn compose_locale_from_reg_values(
    locale_name: Option<&str>,
    iso_lang: Option<&str>,
    iso_ctry: Option<&str>,
    s_lang: Option<&str>,
    s_country: Option<&str>,
) -> String {
    if let Some(name) = locale_name.map(str::trim).filter(|s| !s.is_empty()) {
        return name.to_string();
    }
    let iso_l = iso_lang.map(str::trim).unwrap_or("");
    let iso_c = iso_ctry.map(str::trim).unwrap_or("");
    if !iso_l.is_empty() {
        return if iso_c.is_empty() {
            iso_l.to_string()
        } else {
            format!("{iso_l}-{iso_c}")
        };
    }
    let lang = s_lang.map(str::trim).unwrap_or("");
    let country = s_country.map(str::trim).unwrap_or("");
    if lang.is_empty() {
        String::new()
    } else if country.is_empty() {
        lang.to_string()
    } else {
        format!("{lang}-{country}")
    }
}

#[cfg(windows)]
fn read_locale_reg() -> String {
    let Some(key) = crate::access_win::open_interactive_user_subkey(r"Control Panel\International")
    else {
        return String::new();
    };
    let locale_name: Option<String> = key.get_value("LocaleName").ok();
    let iso_lang: Option<String> = key.get_value("sISO639LangName").ok();
    let iso_ctry: Option<String> = key.get_value("sISO3166CTRYName").ok();
    let s_lang: Option<String> = key.get_value("sLanguage").ok();
    let s_country: Option<String> = key.get_value("sCountry").ok();
    compose_locale_from_reg_values(
        locale_name.as_deref(),
        iso_lang.as_deref(),
        iso_ctry.as_deref(),
        s_lang.as_deref(),
        s_country.as_deref(),
    )
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

/// Parses Windows Registry 44-byte `REG_TZI_FORMAT` (`TZI` binary blob under `Time Zones\<Key>`).
#[cfg(any(windows, test))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct RegTzi {
    bias: i32,
    standard_bias: i32,
    daylight_bias: i32,
    standard_date: [u16; 8],
    daylight_date: [u16; 8],
}

#[cfg(any(windows, test))]
fn parse_reg_tzi(bytes: &[u8]) -> Option<RegTzi> {
    if bytes.len() < 44 {
        return None;
    }
    let i32_at = |off: usize| -> i32 {
        i32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
    };
    let u16_at = |off: usize| -> u16 { u16::from_le_bytes([bytes[off], bytes[off + 1]]) };
    let mut std_date = [0u16; 8];
    let mut dlt_date = [0u16; 8];
    for i in 0..8 {
        std_date[i] = u16_at(12 + i * 2);
        dlt_date[i] = u16_at(28 + i * 2);
    }
    Some(RegTzi {
        bias: i32_at(0),
        standard_bias: i32_at(4),
        daylight_bias: i32_at(8),
        standard_date: std_date,
        daylight_date: dlt_date,
    })
}

/// Sets the Windows system timezone natively via `SetDynamicTimeZoneInformation` (zero subprocesses).
///
/// Requires `SE_TIME_ZONE_NAME` privilege (held by Administrators and `LocalSystem` Windows Service).
#[cfg(windows)]
pub fn set_windows_timezone(tz_key: &str) -> PlatformResult<String> {
    use windows::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_NOT_ALL_ASSIGNED, HANDLE, LUID, SYSTEMTIME,
    };
    use windows::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
        SE_TIME_ZONE_NAME, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::Win32::System::Time::{
        SetDynamicTimeZoneInformation, DYNAMIC_TIME_ZONE_INFORMATION,
    };
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;

    let key_name = tz_key.trim();
    if key_name.is_empty() {
        return Err(PlatformError::InvalidInput("目标时区键名不能为空".into()));
    }

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let sub_path = format!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones\{key_name}");
    let tz_reg = hklm
        .open_subkey_with_flags(&sub_path, KEY_READ)
        .map_err(|e| {
            PlatformError::InvalidInput(format!("系统注册表中未找到时区「{key_name}」：{e}"))
        })?;

    let tzi_raw = tz_reg
        .get_raw_value("TZI")
        .map_err(|e| PlatformError::Io(format!("读取时区 TZI 失败：{e}")))?;
    let tzi = parse_reg_tzi(&tzi_raw.bytes)
        .ok_or_else(|| PlatformError::Io("时区 TZI 二进制格式无效".into()))?;
    let std_name: String = tz_reg.get_value("Std").unwrap_or_else(|_| key_name.into());
    let dlt_name: String = tz_reg.get_value("Dlt").unwrap_or_else(|_| key_name.into());

    // Enable SE_TIME_ZONE_NAME on current process token
    struct HandleGuard(HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
    let mut token = HANDLE::default();
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
    }
    .map_err(|e| PlatformError::AccessDenied(format!("打开进程令牌失败：{e}")))?;
    let _token = HandleGuard(token);

    let mut luid = LUID::default();
    unsafe { LookupPrivilegeValueW(None, SE_TIME_ZONE_NAME, &mut luid) }
        .map_err(|e| PlatformError::AccessDenied(format!("查询时区特权失败：{e}")))?;
    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    unsafe { AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None) }
        .map_err(|e| PlatformError::AccessDenied(format!("启用时区特权失败：{e}")))?;
    if unsafe { GetLastError() } == ERROR_NOT_ALL_ASSIGNED {
        return Err(PlatformError::AccessDenied(
            "当前进程令牌缺少 SE_TIME_ZONE_NAME 时区修改特权（需要管理员或服务权限）".into(),
        ));
    }

    let to_systime = |a: [u16; 8]| SYSTEMTIME {
        wYear: a[0],
        wMonth: a[1],
        wDayOfWeek: a[2],
        wDay: a[3],
        wHour: a[4],
        wMinute: a[5],
        wSecond: a[6],
        wMilliseconds: a[7],
    };
    let copy_wide = |src: &str, dst: &mut [u16]| {
        for (i, u) in src
            .encode_utf16()
            .take(dst.len().saturating_sub(1))
            .enumerate()
        {
            dst[i] = u;
        }
    };

    let mut dtzi = DYNAMIC_TIME_ZONE_INFORMATION {
        Bias: tzi.bias,
        StandardBias: tzi.standard_bias,
        DaylightBias: tzi.daylight_bias,
        StandardDate: to_systime(tzi.standard_date),
        DaylightDate: to_systime(tzi.daylight_date),
        DynamicDaylightTimeDisabled: false.into(),
        ..Default::default()
    };
    copy_wide(&std_name, &mut dtzi.StandardName);
    copy_wide(&dlt_name, &mut dtzi.DaylightName);
    copy_wide(key_name, &mut dtzi.TimeZoneKeyName);

    unsafe { SetDynamicTimeZoneInformation(&dtzi) }.map_err(|e| {
        PlatformError::AccessDenied(format!("设置系统时区失败（需要管理员或服务权限）：{e}"))
    })?;

    let (verified_key, _) = read_timezone_reg();
    Ok(verified_key)
}

#[cfg(not(windows))]
pub fn set_windows_timezone(_tz_key: &str) -> PlatformResult<String> {
    Err(PlatformError::unsupported(
        "env_alignment",
        "Windows timezone alignment is only supported on Windows",
    ))
}

/// Normalize a Windows `GetUserDefaultGeoName` / Registry `Geo\Name` value (ISO 3166-1 alpha-2
/// or UN M.49 numeric code) into a clean uppercase string.
pub fn normalize_geo_name(raw: &str) -> Option<String> {
    let trimmed = raw
        .trim()
        .trim_end_matches('\0')
        .trim()
        .to_ascii_uppercase();
    if trimmed.len() == 2 && trimmed.bytes().all(|b| b.is_ascii_alphabetic()) {
        return Some(trimmed);
    }
    if trimmed.len() == 3 && trimmed.bytes().all(|b| b.is_ascii_digit()) {
        return Some(trimmed);
    }
    None
}

#[cfg(windows)]
fn read_user_geo_name_from_reg() -> Option<String> {
    let key = crate::access_win::open_interactive_user_subkey(r"Control Panel\International\Geo")?;
    let name: String = key.get_value("Name").ok()?;
    normalize_geo_name(&name)
}

#[cfg(windows)]
fn read_user_geo_name_win32() -> Option<String> {
    use windows::Win32::Globalization::GetUserDefaultGeoName;

    let mut buf = [0u16; 16];
    let written = unsafe { GetUserDefaultGeoName(&mut buf) };
    if written <= 0 {
        return None;
    }
    let len = (written as usize).min(buf.len());
    let raw = String::from_utf16_lossy(&buf[..len]);
    normalize_geo_name(&raw)
}

/// Read the active user's Windows Region / Home Location ISO code (e.g. `"US"`, `"CN"`, `"JP"`)
/// via `Win32::Globalization::GetUserDefaultGeoName` (prioritizing the interactive user registry
/// hive when running under Session-0 `LocalSystem`).
#[cfg(windows)]
pub fn read_user_geo_name() -> Option<String> {
    if crate::access_win::is_session_zero() {
        if let Some(reg_geo) = read_user_geo_name_from_reg() {
            return Some(reg_geo);
        }
        return read_user_geo_name_win32();
    }
    read_user_geo_name_win32().or_else(read_user_geo_name_from_reg)
}

#[cfg(not(windows))]
pub fn read_user_geo_name() -> Option<String> {
    None
}

fn push_accept_lang_tag(tags: &mut Vec<String>, raw: &str) {
    let clean = raw.trim().replace('_', "-");
    if clean.is_empty() {
        return;
    }
    if !tags.iter().any(|t| t.eq_ignore_ascii_case(&clean)) {
        tags.push(clean.clone());
    }
    if let Some((base, _)) = clean.split_once('-') {
        let base_l = base.to_ascii_lowercase();
        if !base_l.is_empty() && !tags.iter().any(|t| t.eq_ignore_ascii_case(&base_l)) {
            tags.push(base_l);
        }
    }
}

/// Pure formatter converting Windows preferred UI languages + fallback locale into a standard
/// HTTP `Accept-Language` header hint (e.g. `"en-US,en;q=0.9,zh-CN;q=0.8"`).
pub fn format_accept_language_hint(
    preferred_languages: &[String],
    fallback_locale: &str,
) -> String {
    let mut tags: Vec<String> = Vec::new();
    for lang in preferred_languages {
        push_accept_lang_tag(&mut tags, lang);
    }
    if tags.is_empty() {
        push_accept_lang_tag(&mut tags, fallback_locale);
    }
    if tags.is_empty() {
        return "en-US,en;q=0.9".to_string();
    }

    let mut parts = Vec::with_capacity(tags.len().min(6));
    for (idx, tag) in tags.into_iter().take(6).enumerate() {
        if idx == 0 {
            parts.push(tag);
        } else {
            let q_tenths = 10u8.saturating_sub(idx as u8).max(1);
            parts.push(format!("{tag};q=0.{q_tenths}"));
        }
    }
    parts.join(",")
}

/// Read the active Windows interactive user's preferred UI languages (`Control Panel\International\User Profile`)
/// and format them into an `Accept-Language` hint for OS environment coherence auditing.
#[cfg(windows)]
pub fn read_accept_language_hint() -> String {
    let preferred: Vec<String> = crate::access_win::open_interactive_user_subkey(
        r"Control Panel\International\User Profile",
    )
    .and_then(|key| key.get_value::<Vec<String>, _>("Languages").ok())
    .unwrap_or_default();
    let fallback = read_locale_reg();
    format_accept_language_hint(&preferred, &fallback)
}

#[cfg(not(windows))]
pub fn read_accept_language_hint() -> String {
    "en-US,en;q=0.9".to_string()
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

        assert_eq!(
            compose_locale_from_reg_values(
                Some("en-US"),
                Some("zh"),
                Some("CN"),
                Some("CHS"),
                Some("China")
            ),
            "en-US"
        );
        assert_eq!(
            compose_locale_from_reg_values(
                Some(" "),
                Some("en"),
                Some("US"),
                Some("ENU"),
                Some("United States")
            ),
            "en-US"
        );
        assert_eq!(
            split_locale(&compose_locale_from_reg_values(
                None,
                Some("ja"),
                Some("JP"),
                Some("JPN"),
                Some("Japan")
            )),
            ("ja".into(), "JP".into())
        );
        assert_eq!(
            compose_locale_from_reg_values(None, None, None, Some("CHS"), Some("CN")),
            "CHS-CN"
        );
    }

    #[test]
    fn geo_name_normalization_and_accept_language_formatting() {
        assert_eq!(normalize_geo_name("us\0"), Some("US".into()));
        assert_eq!(normalize_geo_name(" cn "), Some("CN".into()));
        assert_eq!(normalize_geo_name("419"), Some("419".into()));
        assert_eq!(normalize_geo_name("invalid-geo"), None);

        assert_eq!(
            format_accept_language_hint(&["en-US".into(), "zh-CN".into()], "zh-CN"),
            "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7"
        );
        assert_eq!(format_accept_language_hint(&[], "ja_JP"), "ja-JP,ja;q=0.9");
        assert_eq!(format_accept_language_hint(&[], ""), "en-US,en;q=0.9");
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
        let geo = read_user_geo_name();
        assert!(
            geo.as_deref().is_some_and(|g| g.len() == 2 || g.len() == 3),
            "GetUserDefaultGeoName should return a valid ISO/M.49 code: {geo:?}"
        );
        assert!(!read_accept_language_hint().is_empty());
    }
}
