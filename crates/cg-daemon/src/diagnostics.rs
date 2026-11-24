//! Redacted `.zip` support bundle exporter & rollback-safe OS environment alignment store.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use cg_core::redact::{mask_snapshot, redact};
use cg_platform::{env_win, process_win, zip_util};
use cg_protocol::{AppliedEnv, GuardSnapshot};
use serde::{Deserialize, Serialize};

const ENV_BACKUP_FILE: &str = "env_backup.json";

/// Persisted pre-alignment OS snapshot so timezone & Sensor location always roll back cleanly.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvBackup {
    pub orig_tz_key: Option<String>,
    pub orig_lat: Option<String>,
    pub orig_lon: Option<String>,
    pub applied: AppliedEnv,
}

pub fn load_env_backup(data_dir: &Path) -> Option<EnvBackup> {
    let raw = fs::read_to_string(data_dir.join(ENV_BACKUP_FILE)).ok()?;
    serde_json::from_str(&raw).ok()
}

pub fn save_env_backup(data_dir: &Path, backup: &EnvBackup) -> Result<(), String> {
    fs::create_dir_all(data_dir).map_err(|e| format!("创建数据目录失败：{e}"))?;
    let path = data_dir.join(ENV_BACKUP_FILE);
    let tmp = path.with_extension("json.tmp");
    let bytes =
        serde_json::to_vec_pretty(backup).map_err(|e| format!("序列化环境备份失败：{e}"))?;
    fs::write(&tmp, &bytes).map_err(|e| format!("写入环境备份临时文件失败：{e}"))?;
    fs::rename(&tmp, &path).map_err(|e| format!("落盘环境备份失败：{e}"))?;
    Ok(())
}

pub fn clear_env_backup(data_dir: &Path) {
    let _ = fs::remove_file(data_dir.join(ENV_BACKUP_FILE));
}

/// Applies real Windows timezone and/or Sensor default location alignment with pre-write backup.
pub fn apply_env_alignment(
    data_dir: &Path,
    target_city: Option<&str>,
    target_tz_key: Option<&str>,
    target_coords: Option<(f64, f64)>,
    align_tz: bool,
    align_location: bool,
    now_secs: u64,
) -> Result<(AppliedEnv, String), String> {
    if !align_tz && !align_location {
        return Err("请至少选择对齐时区或默认定位中的一项".into());
    }

    let existing = load_env_backup(data_dir);
    let cur_env = env_win::read_env_info();
    let (cur_lat, cur_lon) = env_win::read_default_location().unwrap_or((None, None));

    let mut backup = existing.unwrap_or_else(|| EnvBackup {
        orig_tz_key: (!cur_env.tz_key.is_empty()).then_some(cur_env.tz_key.clone()),
        orig_lat: cur_lat,
        orig_lon: cur_lon,
        applied: AppliedEnv::default(),
    });

    // Write backup BEFORE mutating OS state (WAL discipline).
    save_env_backup(data_dir, &backup)?;

    let mut notes = Vec::new();
    if let Some(city) = target_city.map(str::trim).filter(|s| !s.is_empty()) {
        backup.applied.city = city.to_string();
    }
    if align_tz {
        let desired_tz = target_tz_key
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                "当前未检测到合规出口对应的目标时区，请先完成一次出口探测".to_string()
            })?;
        let verified = env_win::set_windows_timezone(desired_tz)
            .map_err(|e| format!("应用系统时区失败：{e}"))?;
        if backup.applied.tz_from.is_empty() {
            backup.applied.tz_from = backup.orig_tz_key.clone().unwrap_or_default();
        }
        backup.applied.tz_to = verified.clone();
        notes.push(format!("时区已对齐至 {verified}"));
    }

    if align_location {
        let (lat, lon) = target_coords
            .ok_or_else(|| "当前出口地区无对应参考经纬度坐标，请先完成一次出口探测".to_string())?;
        let lat_s = format!("{lat:.4}");
        let lon_s = format!("{lon:.4}");
        env_win::write_default_location(&lat_s, &lon_s)
            .map_err(|e| format!("写入 Windows 默认定位失败：{e}"))?;
        if backup.applied.lat_to.is_empty() {
            backup.applied.lat_from = backup.orig_lat.clone();
            backup.applied.lon_from = backup.orig_lon.clone();
        }
        backup.applied.lat_to = lat_s.clone();
        backup.applied.lon_to = lon_s.clone();
        notes.push(format!("默认定位已对齐至 ({lat_s}, {lon_s})"));
    }

    backup.applied.at = now_secs;
    save_env_backup(data_dir, &backup)?;
    Ok((backup.applied, notes.join("；")))
}

/// Restores original Windows timezone and Sensor default location from persisted backup.
pub fn rollback_env_alignment(data_dir: &Path) -> Result<String, String> {
    let Some(backup) = load_env_backup(data_dir) else {
        return Ok("未发现待还原的环境对齐记录".into());
    };
    let mut notes = Vec::new();
    if backup.applied.touched_tz() {
        let orig_tz = if !backup.applied.tz_from.is_empty() {
            Some(backup.applied.tz_from.as_str())
        } else {
            backup.orig_tz_key.as_deref()
        };
        if let Some(tz) = orig_tz.filter(|s| !s.is_empty()) {
            env_win::set_windows_timezone(tz)
                .map_err(|e| format!("还原原始时区「{tz}」失败：{e}"))?;
            notes.push(format!("已还原时区至 {tz}"));
        }
    }
    if !backup.applied.lat_to.is_empty() || !backup.applied.lon_to.is_empty() {
        match (backup.orig_lat.as_deref(), backup.orig_lon.as_deref()) {
            (Some(lat), Some(lon)) => {
                env_win::write_default_location(lat, lon)
                    .map_err(|e| format!("还原原始默认定位失败：{e}"))?;
                notes.push("已还原原始默认定位".into());
            }
            _ => {
                env_win::delete_default_location().map_err(|e| format!("清除覆写定位失败：{e}"))?;
                notes.push("已清除覆写的默认定位".into());
            }
        }
    }
    clear_env_backup(data_dir);
    if notes.is_empty() {
        Ok("环境对齐记录已清理".into())
    } else {
        Ok(notes.join("；"))
    }
}

fn is_system_profile_path(path: &Path) -> bool {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    lower.contains("systemprofile")
        || lower.contains(r"\serviceprofiles\localservice")
        || lower.contains(r"\serviceprofiles\networkservice")
        || lower.contains("/serviceprofiles/localservice")
        || lower.contains("/serviceprofiles/networkservice")
}

fn profile_recency(home: &Path) -> SystemTime {
    [
        home.join("Desktop"),
        home.join("AppData").join("Local"),
        home.join("NTUSER.DAT"),
        home.to_path_buf(),
    ]
    .into_iter()
    .filter_map(|p| fs::metadata(p).and_then(|m| m.modified()).ok())
    .max()
    .unwrap_or(SystemTime::UNIX_EPOCH)
}

fn discover_interactive_user_home() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();

    // 1. Extract interactive user homes resolved via `cg_platform::process_win` (`ProfileList` / covered dirs).
    for covered in process_win::claude_covered_dirs() {
        for anc in covered.ancestors() {
            if anc
                .file_name()
                .is_some_and(|n| n.eq_ignore_ascii_case("AppData"))
            {
                if let Some(home) = anc.parent() {
                    if home.is_dir()
                        && !is_system_profile_path(home)
                        && !candidates.iter().any(|c| c == home)
                    {
                        candidates.push(home.to_path_buf());
                    }
                }
                break;
            }
        }
    }

    // 2. Also scan `<SystemDrive>\Users` for interactive profiles in case Claude dirs are absent.
    let sys_drive = std::env::var("SystemDrive")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "C:".into());
    let users_root = PathBuf::from(format!(
        r"{}\Users",
        sys_drive.trim_end_matches(['\\', '/'])
    ));
    if let Ok(entries) = fs::read_dir(&users_root) {
        for entry in entries.flatten() {
            let p = entry.path();
            let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let lower = name.to_ascii_lowercase();
            if matches!(
                lower.as_str(),
                "public" | "default" | "default user" | "all users"
            ) || is_system_profile_path(&p)
            {
                continue;
            }
            if p.is_dir()
                && (p.join("Desktop").is_dir() || p.join("AppData").is_dir())
                && !candidates.iter().any(|c| c == &p)
            {
                candidates.push(p);
            }
        }
    }

    candidates.sort_by(|a, b| {
        let a_desk = a.join("Desktop").is_dir();
        let b_desk = b.join("Desktop").is_dir();
        b_desk
            .cmp(&a_desk)
            .then_with(|| profile_recency(b).cmp(&profile_recency(a)))
    });
    candidates.into_iter().next()
}

fn resolve_diagnostics_dir_with(
    user_profile: Option<&Path>,
    interactive_home: Option<&Path>,
    data_dir: &Path,
    temp_dir: &Path,
) -> PathBuf {
    let is_session0_system = user_profile.is_some_and(is_system_profile_path);
    if let Some(profile) = user_profile.filter(|p| !is_system_profile_path(p)) {
        let desktop = profile.join("Desktop");
        if desktop.is_dir() {
            return desktop;
        }
        if profile.is_dir() {
            return profile.to_path_buf();
        }
    }

    if is_session0_system || user_profile.is_none() {
        if let Some(home) = interactive_home.filter(|h| !is_system_profile_path(h)) {
            let desktop = home.join("Desktop");
            if desktop.is_dir() {
                return desktop;
            }
            if home.is_dir() {
                return home.to_path_buf();
            }
        }
        if is_session0_system {
            return temp_dir.to_path_buf();
        }
    }

    data_dir.join("diagnostics")
}

/// Picks a user-accessible output directory (`Desktop` if writable, interactive user home under
/// Session-0 `LocalSystem`, `env::temp_dir()` fallback for `systemprofile`, otherwise `<data_dir>\diagnostics`).
fn resolve_diagnostics_dir(data_dir: &Path) -> PathBuf {
    let user_profile = std::env::var_os("USERPROFILE").map(PathBuf::from);
    let interactive = if user_profile.as_deref().is_none_or(is_system_profile_path) {
        discover_interactive_user_home()
    } else {
        None
    };
    let temp = std::env::temp_dir();
    resolve_diagnostics_dir_with(
        user_profile.as_deref(),
        interactive.as_deref(),
        data_dir,
        &temp,
    )
}

/// Builds a strictly redacted `.zip` diagnostic bundle containing zero raw IPs or credentials.
pub fn export_redacted_diagnostics_zip(
    data_dir: &Path,
    snap: &GuardSnapshot,
    now_secs: u64,
    explicit_dir: Option<&Path>,
) -> Result<PathBuf, String> {
    let mut masked = mask_snapshot(snap);
    for t in &mut masked.config.targets {
        t.expect_ips = t.expect_ips.iter().map(|ip| redact(ip, false)).collect();
    }
    for t in &mut masked.targets {
        t.expect_ips = t.expect_ips.iter().map(|ip| redact(ip, false)).collect();
        if let Some(rule) = t.matched_rule.as_deref() {
            t.matched_rule = Some(redact(rule, false));
        }
    }

    let snap_json =
        serde_json::to_vec_pretty(&masked).map_err(|e| format!("序列化脱敏快照失败：{e}"))?;

    let cfg_json = serde_json::to_vec_pretty(&masked.config)
        .map_err(|e| format!("序列化脱敏配置失败：{e}"))?;

    let self_check_json = serde_json::to_vec_pretty(&masked.self_check)
        .map_err(|e| format!("序列化防线自检失败：{e}"))?;
    let shield_json = serde_json::to_vec_pretty(&masked.leak_shield)
        .map_err(|e| format!("序列化防泄露护盾状态失败：{e}"))?;
    let mihomo_json = serde_json::to_vec_pretty(&masked.mihomo)
        .map_err(|e| format!("序列化代理内核状态失败：{e}"))?;
    let feishu_json = serde_json::to_vec_pretty(&masked.feishu)
        .map_err(|e| format!("序列化飞书状态失败：{e}"))?;

    let mut logs_txt = String::new();
    for entry in &masked.recent_logs {
        let msg = redact(&entry.message, false);
        logs_txt.push_str(&format!(
            "[{}] {:?} [{}] {}\n",
            entry.timestamp, entry.level, entry.category, msg
        ));
    }

    let zip_bytes = zip_util::build_zip_archive(&[
        ("snapshot_redacted.json", &snap_json),
        ("config_redacted.json", &cfg_json),
        ("self_check.json", &self_check_json),
        ("leak_shield.json", &shield_json),
        ("mihomo_status.json", &mihomo_json),
        ("feishu_status.json", &feishu_json),
        ("audit_logs.txt", logs_txt.as_bytes()),
    ])?;

    let out_dir = explicit_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| resolve_diagnostics_dir(data_dir));
    fs::create_dir_all(&out_dir).map_err(|e| format!("创建诊断导出目录失败：{e}"))?;

    let filename = format!("ClaudeGuard-Diagnostics-{now_secs}.zip");
    let out_path = out_dir.join(filename);
    fs::write(&out_path, &zip_bytes).map_err(|e| format!("写入诊断压缩包失败：{e}"))?;
    Ok(out_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cg_protocol::{LogEntry, LogLevel, TargetState, TargetStatus};
    use tempfile::tempdir;

    #[test]
    fn exported_diagnostics_zip_redacts_all_ips_and_is_valid_zip() {
        let dir = tempdir().unwrap();
        let mut snap = GuardSnapshot {
            version: "4.0.0".into(),
            ..GuardSnapshot::default()
        };
        let mut t = cg_protocol::default_builtin_targets(&["198.51.100.98".into()], &["US".into()])
            .into_iter()
            .next()
            .unwrap();
        t.id = "claude".into();
        let mut ts = TargetStatus::from_target(&t, TargetState::Pass);
        ts.ip = Some("198.51.100.98".into());
        ts.matched_rule = Some("198.51.100.98".into());
        ts.reason = "出口 198.51.100.98 通过".into();
        snap.config.targets =
            cg_protocol::default_builtin_targets(&["198.51.100.98".into()], &["US".into()]);
        snap.targets.push(ts);
        snap.recent_logs.push(LogEntry {
            id: 1,
            timestamp: 1000,
            level: LogLevel::Info,
            category: "probe".into(),
            message: "检测到真实出口 203.0.113.45 异常".into(),
        });

        let out = export_redacted_diagnostics_zip(dir.path(), &snap, 1700000000, Some(dir.path()))
            .expect("export zip");
        assert!(out.is_file());
        let raw = fs::read(&out).unwrap();
        let (_, snap_entry) =
            zip_util::extract_file_from_zip(&raw, "snapshot_redacted.json").expect("read snap");
        let snap_text = String::from_utf8(snap_entry).unwrap();
        assert!(!snap_text.contains("198.51.100.98"));
        assert!(!snap_text.contains("203.0.113.45"));

        let (_, logs_entry) =
            zip_util::extract_file_from_zip(&raw, "audit_logs.txt").expect("read logs");
        let logs_text = String::from_utf8(logs_entry).unwrap();
        assert!(!logs_text.contains("203.0.113.45"));
    }

    #[test]
    fn resolve_diagnostics_dir_handles_session0_systemprofile_and_fallback() {
        let root = tempdir().unwrap();
        let data_dir = root.path().join("ProgramData");
        let temp_dir = root.path().join("Temp");
        let user_home = root.path().join("Users").join("alice");
        let user_desktop = user_home.join("Desktop");
        fs::create_dir_all(&user_desktop).unwrap();
        fs::create_dir_all(&temp_dir).unwrap();

        let sys_profile = Path::new(r"C:\Windows\System32\config\systemprofile");
        assert!(is_system_profile_path(sys_profile));
        assert!(!is_system_profile_path(&user_home));

        // Session-0 LocalSystem resolves to active interactive user's Desktop when available.
        assert_eq!(
            resolve_diagnostics_dir_with(Some(sys_profile), Some(&user_home), &data_dir, &temp_dir,),
            user_desktop
        );

        // When no interactive user home is found under Session-0, falls back to env::temp_dir().
        assert_eq!(
            resolve_diagnostics_dir_with(Some(sys_profile), None, &data_dir, &temp_dir),
            temp_dir
        );

        // Normal interactive user resolves directly to their Desktop.
        assert_eq!(
            resolve_diagnostics_dir_with(Some(&user_home), None, &data_dir, &temp_dir),
            user_desktop
        );
    }
}
