//! 环境对齐执行（v3.12 引入）：把系统时区、Windows 默认位置改到与出口一致。
//!
//! 这是本项目里**唯一会改系统设置**的功能，因此比照断网（[`crate::netcut`]）的规矩来：
//!
//! - **先记账，后动手**：改动前把原值写进 `%APPDATA%\ClaudeGuard\env-align.json`，
//!   恢复只认这本账。进程被杀、机器重启都能靠它还原。
//! - **只改能改回来的**：时区走 `tzutil /s`（系统自带），默认位置写注册表
//!   `…\Sensor\Overrides\{BFA794E4-…}` 的 `Latitude`/`Longitude`。
//!   位置权限（`SensorPermissionState`）**不动**——把定位权限打开是另一回事，
//!   用户没要求，也不该由本工具替用户决定。
//! - **不认识的地点就不改**：地点表（[`crate::geo`]）里没有的机房直接报错返回，
//!   绝不按"大概方向"猜一个坐标。
//!
//! 注意：这两项都是**用户可见的系统级改动**。UI 上必须说明"会自动还原"，
//! 并且提供「恢复原样」入口（IPC `env_restore`）。

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::config::{config_dir, Config};
use crate::geo::Place;
use crate::model::now;

/// 账本文件名。
pub const LEDGER_FILE: &str = "env-align.json";

/// 注册表位置：Windows「默认位置」。
pub const SENSOR_KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}";

/// 已经做过的改动。字段全部可空，兼容旧账本。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AppliedEnv {
    /// 改动时间。
    pub at: u64,
    /// 目标城市，仅用于展示。
    pub city: String,
    /// 改前的时区键（空 = 没改过时区）。
    pub tz_from: String,
    /// 改成什么时区（空 = 没改过时区）。
    pub tz_to: String,
    /// 改前的默认位置纬度（None = 原本没有这个值）。
    pub lat_from: Option<String>,
    /// 改前的默认位置经度。
    pub lon_from: Option<String>,
    /// 改成什么纬度。
    pub lat_to: String,
    /// 改成什么经度。
    pub lon_to: String,
}

impl AppliedEnv {
    /// 是否动过时区。
    pub fn touched_tz(&self) -> bool {
        !self.tz_to.is_empty()
    }

    /// 是否动过默认位置。
    pub fn touched_location(&self) -> bool {
        !self.lat_to.is_empty()
    }

    /// 一句话摘要（状态页展示）。
    pub fn summary(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if self.touched_tz() {
            parts.push(format!("时区→{}", crate::envcheck::tz_label(&self.tz_to)));
        }
        if self.touched_location() {
            parts.push(format!("位置→{}", self.city));
        }
        if parts.is_empty() {
            "未做任何改动".to_string()
        } else {
            parts.join("，")
        }
    }
}

/// 账本路径。
pub fn ledger_path() -> PathBuf {
    config_dir().join(LEDGER_FILE)
}

/// 读账本（不存在或损坏都当没改过）。
pub fn load() -> Option<AppliedEnv> {
    let text = std::fs::read_to_string(ledger_path()).ok()?;
    serde_json::from_str::<AppliedEnv>(text.trim()).ok()
}

fn save(rec: &AppliedEnv) -> Result<(), String> {
    let dir = config_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("创建配置目录失败：{e}"))?;
    let text = serde_json::to_string_pretty(rec).map_err(|e| format!("序列化失败：{e}"))?;
    let tmp = ledger_path().with_extension("json.tmp");
    std::fs::write(&tmp, text).map_err(|e| format!("写入账本失败：{e}"))?;
    std::fs::rename(&tmp, ledger_path()).map_err(|e| format!("替换账本失败：{e}"))?;
    Ok(())
}

/// 清账本。
pub fn clear() -> Result<(), String> {
    let p = ledger_path();
    if p.exists() {
        std::fs::remove_file(&p).map_err(|e| format!("删除账本失败：{e}"))?;
    }
    Ok(())
}

/// 纯函数：决定这次要改哪些项（None = 不需要改）。
pub fn plan(
    place: &Place,
    current_tz: &str,
    want_tz: bool,
    want_loc: bool,
) -> (Option<String>, bool) {
    let tz = if want_tz && !current_tz.eq_ignore_ascii_case(place.tz) {
        Some(place.tz.to_string())
    } else {
        None
    };
    (tz, want_loc)
}

/// 设置系统时区。返回改前的时区键。
#[cfg(windows)]
fn set_timezone(tz: &str) -> Result<(), String> {
    let exe = crate::guard::sys32("tzutil.exe");
    let out =
        crate::guard::run_hidden(&exe, &["/s", tz]).map_err(|e| format!("无法执行 tzutil：{e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!("tzutil 失败：{}", err.trim()));
    }
    Ok(())
}

#[cfg(not(windows))]
fn set_timezone(_tz: &str) -> Result<(), String> {
    Err("当前平台不支持时区对齐".to_string())
}

/// 读注册表里的默认位置（纬度, 经度）。
#[cfg(windows)]
fn read_location() -> (Option<String>, Option<String>) {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let Ok(key) = hklm.open_subkey_with_flags(SENSOR_KEY, KEY_READ) else {
        return (None, None);
    };
    let lat: Option<String> = key.get_value("Latitude").ok();
    let lon: Option<String> = key.get_value("Longitude").ok();
    (lat, lon)
}

#[cfg(not(windows))]
fn read_location() -> (Option<String>, Option<String>) {
    (None, None)
}

/// 写注册表默认位置。写不了就是写不了，如实报错。
#[cfg(windows)]
fn write_location(lat: &str, lon: &str) -> Result<(), String> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE};
    use winreg::RegKey;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let (key, _) = hklm
        .create_subkey(SENSOR_KEY)
        .map_err(|e| format!("打开注册表失败（需要管理员权限）：{e}"))?;
    let _ = KEY_READ;
    let _ = KEY_WRITE;
    key.set_value("Latitude", &lat.to_string())
        .map_err(|e| format!("写入纬度失败：{e}"))?;
    key.set_value("Longitude", &lon.to_string())
        .map_err(|e| format!("写入经度失败：{e}"))?;
    Ok(())
}

#[cfg(not(windows))]
fn write_location(_lat: &str, _lon: &str) -> Result<(), String> {
    Err("当前平台不支持默认位置对齐".to_string())
}

/// 删除默认位置值（原本不存在的场景）。
#[cfg(windows)]
fn delete_location() -> Result<(), String> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let Ok(key) = hklm.open_subkey_with_flags(SENSOR_KEY, winreg::enums::KEY_WRITE) else {
        return Ok(());
    };
    let _ = key.delete_value("Latitude");
    let _ = key.delete_value("Longitude");
    Ok(())
}

#[cfg(not(windows))]
fn delete_location() -> Result<(), String> {
    Ok(())
}

/// 执行对齐：改时区 / 改默认位置。返回本次账本记录。
///
/// `cfg` 决定改哪些项；两个开关都关时直接返回错误（调用方应先检查）。
pub fn apply(cfg: &Config, place: &Place) -> Result<AppliedEnv, String> {
    let want_tz = cfg.env_align_tz;
    let want_loc = cfg.env_align_location;
    if !want_tz && !want_loc {
        return Err("未开启任何对齐项".to_string());
    }
    // 已经改过就先还原，避免账本里记的"原值"被第二次改动覆盖
    if load().is_some() {
        restore()?;
    }
    let current_tz = crate::envcheck::read_env().tz_key;
    let (tz_to, do_loc) = plan(place, &current_tz, want_tz, want_loc);

    let mut rec = AppliedEnv {
        at: now(),
        city: place.city.to_string(),
        ..Default::default()
    };
    let mut done: Vec<&str> = Vec::new();

    if let Some(tz) = tz_to {
        set_timezone(&tz)?;
        rec.tz_from = current_tz;
        rec.tz_to = tz;
        done.push("时区");
    }
    if do_loc {
        let (lat_from, lon_from) = read_location();
        write_location(&crate::geo::coord(place.lat), &crate::geo::coord(place.lon))?;
        rec.lat_from = lat_from;
        rec.lon_from = lon_from;
        rec.lat_to = crate::geo::coord(place.lat);
        rec.lon_to = crate::geo::coord(place.lon);
        done.push("默认位置");
    }
    if done.is_empty() {
        return Err("当前环境已与出口一致，无需改动".to_string());
    }
    save(&rec)?;
    Ok(rec)
}

/// 还原到改动前的状态。没有账本时返回 Ok（幂等）。
pub fn restore() -> Result<String, String> {
    let Some(rec) = load() else {
        return Ok("没有需要还原的改动".to_string());
    };
    let mut done: Vec<&str> = Vec::new();
    if rec.touched_tz() && !rec.tz_from.is_empty() {
        set_timezone(&rec.tz_from)?;
        done.push("时区");
    }
    if rec.touched_location() {
        match (&rec.lat_from, &rec.lon_from) {
            (Some(lat), Some(lon)) => write_location(lat, lon)?,
            _ => delete_location()?,
        }
        done.push("默认位置");
    }
    clear()?;
    if done.is_empty() {
        Ok("账本为空，已清理".to_string())
    } else {
        Ok(format!("已还原：{}", done.join("、")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_skips_tz_when_already_matching() {
        let place = crate::geo::by_colo("LAX").unwrap();
        let (tz, loc) = plan(place, "Pacific Standard Time", true, false);
        assert!(tz.is_none(), "已经是目标时区就不该改");
        assert!(!loc);

        let (tz, _) = plan(place, "China Standard Time", true, false);
        assert_eq!(tz.as_deref(), Some("Pacific Standard Time"));
    }

    #[test]
    fn plan_respects_switch_off() {
        let place = crate::geo::by_colo("NRT").unwrap();
        let (tz, loc) = plan(place, "China Standard Time", false, false);
        assert!(tz.is_none());
        assert!(!loc);
    }

    #[test]
    fn summary_mentions_what_changed() {
        let rec = AppliedEnv {
            tz_from: "China Standard Time".to_string(),
            tz_to: "Pacific Standard Time".to_string(),
            city: "洛杉矶".to_string(),
            lat_to: "34.0522".to_string(),
            lon_to: "-118.2437".to_string(),
            ..Default::default()
        };
        assert!(rec.touched_tz() && rec.touched_location());
        let s = rec.summary();
        assert!(s.contains("时区→"));
        assert!(s.contains("洛杉矶"));
    }

    #[test]
    fn empty_record_summarizes_as_untouched() {
        let rec = AppliedEnv::default();
        assert!(!rec.touched_tz());
        assert!(!rec.touched_location());
        assert_eq!(rec.summary(), "未做任何改动");
    }

    #[test]
    fn ledger_roundtrip_is_lossless() {
        let rec = AppliedEnv {
            at: 123,
            city: "东京".to_string(),
            tz_from: "China Standard Time".to_string(),
            tz_to: "Tokyo Standard Time".to_string(),
            lat_from: None,
            lon_from: None,
            lat_to: "35.6762".to_string(),
            lon_to: "139.6503".to_string(),
        };
        let text = serde_json::to_string(&rec).unwrap();
        let back: AppliedEnv = serde_json::from_str(&text).unwrap();
        assert_eq!(rec, back);
        // 旧账本缺字段也能读
        let old: AppliedEnv = serde_json::from_str("{}").unwrap();
        assert_eq!(old, AppliedEnv::default());
    }
}
