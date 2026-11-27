//! Redacted `.zip` support bundle exporter & rollback-safe OS environment alignment store.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tempfile::NamedTempFile;

use cg_core::redact::{mask_snapshot, mask_text_ips, redact};
use cg_platform::{env_win, process_win, zip_util};
use cg_protocol::{
    normalize_region, region_name, AppliedEnv, GuardSnapshot, LogEntry, LogLevel, SafetyGrade,
    SanitizedHealthCard, TargetState,
};
use serde::{Deserialize, Serialize};

const ENV_BACKUP_FILE: &str = "env_backup.json";
const DAEMON_LOG_FILE: &str = "daemon.log";
const DAEMON_LOG_PREV_FILE: &str = "daemon.log.1";
const MAX_DAEMON_LOG_BYTES: u64 = 512 * 1024;
const MAX_DIAGNOSTIC_LOG_READ_BYTES: u64 = 1024 * 1024;
const MAX_DIAGNOSTIC_ARCHIVES: usize = 10;

/// Persisted pre-alignment OS snapshot so timezone & Sensor location always roll back cleanly.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvBackup {
    pub orig_tz_key: Option<String>,
    pub orig_lat: Option<String>,
    pub orig_lon: Option<String>,
    pub applied: AppliedEnv,
}

/// Inspects `symlink_metadata` across every existing prefix of `path` to detect junctions/symlinks.
pub fn has_reparse_point_in_chain(path: &Path) -> bool {
    crate::journal::has_reparse_point_in_chain(path)
}

pub fn load_env_backup(data_dir: &Path) -> Option<EnvBackup> {
    let raw = fs::read_to_string(data_dir.join(ENV_BACKUP_FILE)).ok()?;
    serde_json::from_str(&raw).ok()
}

pub fn save_env_backup(data_dir: &Path, backup: &EnvBackup) -> Result<(), String> {
    crate::journal::ensure_secure_data_dir(data_dir)?;
    let path = data_dir.join(ENV_BACKUP_FILE);
    let bytes =
        serde_json::to_vec_pretty(backup).map_err(|e| format!("序列化环境备份失败：{e}"))?;
    let mut tmp =
        NamedTempFile::new_in(data_dir).map_err(|e| format!("创建环境备份临时文件失败：{e}"))?;
    tmp.write_all(&bytes)
        .map_err(|e| format!("写入环境备份临时文件失败：{e}"))?;
    tmp.as_file()
        .sync_all()
        .map_err(|e| format!("同步环境备份临时文件失败：{e}"))?;
    tmp.persist(&path)
        .map_err(|e| format!("落盘环境备份失败：{}", e.error))?;
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
                        && !has_reparse_point_in_chain(home)
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
                || has_reparse_point_in_chain(&p)
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
        let a_desk = a.join("Desktop").is_dir() && !has_reparse_point_in_chain(&a.join("Desktop"));
        let b_desk = b.join("Desktop").is_dir() && !has_reparse_point_in_chain(&b.join("Desktop"));
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
        if desktop.is_dir() && !has_reparse_point_in_chain(&desktop) {
            return desktop;
        }
        if profile.is_dir() && !has_reparse_point_in_chain(profile) {
            return profile.to_path_buf();
        }
    }

    if is_session0_system || user_profile.is_none() {
        if let Some(home) = interactive_home.filter(|h| !is_system_profile_path(h)) {
            let desktop = home.join("Desktop");
            if desktop.is_dir() && !has_reparse_point_in_chain(&desktop) {
                return desktop;
            }
            if home.is_dir() && !has_reparse_point_in_chain(home) {
                return home.to_path_buf();
            }
        }
        if is_session0_system && !has_reparse_point_in_chain(temp_dir) {
            return temp_dir.to_path_buf();
        }
    }

    data_dir.join("diagnostics")
}

/// Picks a user-accessible output directory (`Desktop` if writable and free of reparse points,
/// interactive user home under Session-0 `LocalSystem`, `env::temp_dir()` fallback, otherwise `<data_dir>\diagnostics`).
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

/// Scrubs `\Users\<username>\` (and `/Users/<username>/`) segments to `<REDACTED>` using
/// guaranteed UTF-8 char boundaries (`char_indices`).
fn scrub_user_profile_paths(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut seg_start = 0usize;
    let mut prev_was_users = false;

    for (idx, ch) in text.char_indices() {
        if ch == '\\' || ch == '/' {
            let seg = &text[seg_start..idx];
            if prev_was_users && !seg.is_empty() {
                out.push_str("<REDACTED>");
            } else {
                out.push_str(seg);
            }
            out.push(ch);
            prev_was_users = seg.eq_ignore_ascii_case("Users");
            seg_start = idx + ch.len_utf8();
        }
    }

    let tail = &text[seg_start..];
    if prev_was_users && !tail.is_empty() {
        out.push_str("<REDACTED>");
    } else {
        out.push_str(tail);
    }
    out
}

/// Scrubs `scheme://user:pass@host` or `user:pass@host` credentials from proxy host/address strings.
fn scrub_proxy_credentials(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if let Some((scheme, rest)) = trimmed.split_once("://") {
        let (auth, suffix) = match rest.find(['/', '?', '#']) {
            Some(pos) => (&rest[..pos], &rest[pos..]),
            None => (rest, ""),
        };
        if let Some((_userinfo, hostport)) = auth.rsplit_once('@') {
            return format!("{scheme}://<REDACTED>@{hostport}{suffix}");
        }
        return trimmed.to_string();
    }
    let (auth, suffix) = match trimmed.find(['/', '?', '#']) {
        Some(pos) => (&trimmed[..pos], &trimmed[pos..]),
        None => (trimmed, ""),
    };
    if let Some((_userinfo, hostport)) = auth.rsplit_once('@') {
        return format!("<REDACTED>@{hostport}{suffix}");
    }
    trimmed.to_string()
}

/// Scrubs `scheme://user:pass@` URL credentials embedded inside free-form log/note text.
fn scrub_credentials_in_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some((before, after_scheme)) = rest.split_once("://") {
        out.push_str(before);
        out.push_str("://");
        let end = after_scheme
            .find(|c: char| c.is_whitespace() || matches!(c, '/' | '?' | '#' | '"' | '\'' | ')'))
            .unwrap_or(after_scheme.len());
        let authority = &after_scheme[..end];
        if let Some((_userinfo, hostport)) = authority.rsplit_once('@') {
            out.push_str("<REDACTED>@");
            out.push_str(hostport);
        } else {
            out.push_str(authority);
        }
        rest = &after_scheme[end..];
    }
    out.push_str(rest);
    out
}

fn format_log_level_upper(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Info => "INFO",
        LogLevel::Warn => "WARN",
        LogLevel::Error => "ERROR",
        LogLevel::Audit => "AUDIT",
    }
}

/// Appends strictly redacted operational/audit log entries to rolling `<data_dir>/daemon.log`
/// (rotating `daemon.log` -> `daemon.log.1` once `daemon.log` reaches `512 KiB`).
pub fn append_redacted_daemon_log_entries(data_dir: &Path, entries: &[LogEntry]) {
    if entries.is_empty() || has_reparse_point_in_chain(data_dir) {
        return;
    }
    if !data_dir.exists() && crate::journal::ensure_secure_data_dir(data_dir).is_err() {
        return;
    }
    if has_reparse_point_in_chain(data_dir) {
        return;
    }

    let log_path = data_dir.join(DAEMON_LOG_FILE);
    let prev_path = data_dir.join(DAEMON_LOG_PREV_FILE);

    if let Ok(meta) = fs::symlink_metadata(&log_path) {
        if crate::journal::is_reparse_point_metadata(&meta) || !meta.is_file() {
            return;
        }
        if meta.len() >= MAX_DAEMON_LOG_BYTES {
            if let Ok(prev_meta) = fs::symlink_metadata(&prev_path) {
                if crate::journal::is_reparse_point_metadata(&prev_meta) || !prev_meta.is_file() {
                    return;
                }
            }
            let _ = fs::remove_file(&prev_path);
            let _ = fs::rename(&log_path, &prev_path);
        }
    }

    let mut payload = String::new();
    for entry in entries {
        let clean =
            scrub_user_profile_paths(&scrub_credentials_in_text(&redact(&entry.message, false)))
                .replace(['\r', '\n'], " ");
        payload.push_str(&format!(
            "[{}] {} [{}] {}\n",
            entry.timestamp,
            format_log_level_upper(entry.level),
            entry.category,
            clean
        ));
    }

    let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&log_path) else {
        return;
    };
    if let Ok(meta) = file.metadata() {
        if crate::journal::is_reparse_point_metadata(&meta) || !meta.is_file() {
            return;
        }
    }
    let _ = file.write_all(payload.as_bytes());
}

fn read_scrubbed_daemon_log_for_zip(data_dir: &Path, filename: &str) -> Option<Vec<u8>> {
    if has_reparse_point_in_chain(data_dir) {
        return None;
    }
    let path = data_dir.join(filename);
    let meta = fs::symlink_metadata(&path).ok()?;
    if crate::journal::is_reparse_point_metadata(&meta) || !meta.is_file() {
        return None;
    }
    let mut file = File::open(&path).ok()?;
    let len = meta.len();
    if len > MAX_DIAGNOSTIC_LOG_READ_BYTES {
        let _ = file.seek(SeekFrom::Start(len - MAX_DIAGNOSTIC_LOG_READ_BYTES));
    }
    let mut raw = Vec::with_capacity(len.min(MAX_DIAGNOSTIC_LOG_READ_BYTES) as usize);
    file.take(MAX_DIAGNOSTIC_LOG_READ_BYTES)
        .read_to_end(&mut raw)
        .ok()?;
    let text = String::from_utf8_lossy(&raw);
    let clean = scrub_user_profile_paths(&scrub_credentials_in_text(&redact(&text, false)));
    Some(clean.into_bytes())
}

fn prune_diagnostics_archives(dir: &Path, keep: usize) {
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    let mut archives: Vec<(SystemTime, String, PathBuf)> = rd
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.starts_with("ClaudeGuard-Diagnostics-") || !name.ends_with(".zip") {
                return None;
            }
            let path = entry.path();
            let meta = fs::symlink_metadata(&path).ok()?;
            if crate::journal::is_reparse_point_metadata(&meta) || !meta.is_file() {
                return None;
            }
            let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            Some((mtime, name, path))
        })
        .collect();

    if archives.len() <= keep {
        return;
    }
    archives.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let remove_count = archives.len() - keep;
    for (_, _, old_path) in archives.into_iter().take(remove_count) {
        let _ = fs::remove_file(old_path);
    }
}

fn write_diagnostics_zip_create_new(
    out_dir: &Path,
    now_secs: u64,
    zip_bytes: &[u8],
) -> Result<PathBuf, String> {
    let mut last_err: Option<std::io::Error> = None;
    for suffix in 0..=16u32 {
        let filename = if suffix == 0 {
            format!("ClaudeGuard-Diagnostics-{now_secs}.zip")
        } else {
            format!("ClaudeGuard-Diagnostics-{now_secs}-{suffix}.zip")
        };
        let candidate = out_dir.join(filename);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(mut file) => {
                if let Err(e) = file.write_all(zip_bytes).and_then(|()| file.sync_all()) {
                    drop(file);
                    let _ = fs::remove_file(&candidate);
                    return Err(format!("写入诊断压缩包失败：{e}"));
                }
                return Ok(candidate);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                last_err = Some(e);
                continue;
            }
            Err(e) => return Err(format!("创建诊断压缩包失败：{e}")),
        }
    }
    Err(format!(
        "创建诊断压缩包失败（同名文件冲突超过上限）：{}",
        last_err.map(|e| e.to_string()).unwrap_or_default()
    ))
}

/// Builds a strictly redacted `.zip` diagnostic bundle containing zero raw IPs, coordinates,
/// usernames, city/colo identifiers, or proxy credentials.
pub fn export_redacted_diagnostics_zip(
    data_dir: &Path,
    snap: &GuardSnapshot,
    now_secs: u64,
    explicit_dir: Option<&Path>,
) -> Result<PathBuf, String> {
    let mut masked = mask_snapshot(snap);

    // 1. Scrub proxy credentials across config, access evidence, and antigravity_proxy.
    masked.config.proxy_host = scrub_proxy_credentials(&masked.config.proxy_host);
    if let Some(addr) = masked.access.proxy_addr.as_deref() {
        masked.access.proxy_addr = Some(scrub_proxy_credentials(addr));
    }
    masked.access.note = scrub_user_profile_paths(&scrub_credentials_in_text(&masked.access.note));
    if let Some(ph) = masked.antigravity_proxy.proxy_host.as_deref() {
        masked.antigravity_proxy.proxy_host = Some(scrub_proxy_credentials(ph));
    }

    // 2. Scrub `\Users\<username>\` in agent install paths and antigravity_dir.
    for agent in &mut masked.agents {
        agent.install_paths = agent
            .install_paths
            .iter()
            .map(|p| scrub_user_profile_paths(p))
            .collect();
    }
    if let Some(ag_dir) = masked.antigravity_proxy.antigravity_dir.as_deref() {
        masked.antigravity_proxy.antigravity_dir = Some(scrub_user_profile_paths(ag_dir));
    }
    masked.antigravity_proxy.summary = scrub_user_profile_paths(&scrub_credentials_in_text(
        &masked.antigravity_proxy.summary,
    ));

    // 3. Redact env_applied coordinates (`lat_from`, `lon_from`, `lat_to`, `lon_to` -> `"0.0"`) and city/colo.
    if let Some(applied) = &mut masked.env_applied {
        if applied.lat_from.is_some() {
            applied.lat_from = Some("0.0".to_string());
        }
        if applied.lon_from.is_some() {
            applied.lon_from = Some("0.0".to_string());
        }
        if !applied.lat_to.is_empty() {
            applied.lat_to = "0.0".to_string();
        }
        if !applied.lon_to.is_empty() {
            applied.lon_to = "0.0".to_string();
        }
        applied.city.clear();
    }
    masked.env.egress_colo = None;
    masked.env.expect_city = None;
    masked.env.note = redact(&masked.env.note, false);

    // 4. Redact target IPs, matched rules, and clear fine-grained colo/city location hints.
    for t in &mut masked.config.targets {
        t.expect_ips = t.expect_ips.iter().map(|ip| redact(ip, false)).collect();
    }
    for t in &mut masked.targets {
        t.expect_ips = t.expect_ips.iter().map(|ip| redact(ip, false)).collect();
        if let Some(rule) = t.matched_rule.as_deref() {
            t.matched_rule = Some(redact(rule, false));
        }
        t.colo = None;
        t.city = None;
    }

    for item in &mut masked.self_check.items {
        item.detail = scrub_user_profile_paths(&scrub_credentials_in_text(&item.detail));
    }
    for toast in &mut masked.recent_toasts {
        toast.body =
            scrub_user_profile_paths(&scrub_credentials_in_text(&redact(&toast.body, false)));
    }

    let mut logs_txt = String::new();
    for entry in &mut masked.recent_logs {
        let clean =
            scrub_user_profile_paths(&scrub_credentials_in_text(&redact(&entry.message, false)));
        entry.message = clean.clone();
        logs_txt.push_str(&format!(
            "[{}] {:?} [{}] {}\n",
            entry.timestamp, entry.level, entry.category, clean
        ));
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

    let daemon_log_bytes = read_scrubbed_daemon_log_for_zip(data_dir, DAEMON_LOG_FILE);
    let daemon_log_prev_bytes = read_scrubbed_daemon_log_for_zip(data_dir, DAEMON_LOG_PREV_FILE);

    let mut archive_entries: Vec<(&str, &[u8])> = vec![
        ("snapshot_redacted.json", &snap_json),
        ("config_redacted.json", &cfg_json),
        ("self_check.json", &self_check_json),
        ("leak_shield.json", &shield_json),
        ("mihomo_status.json", &mihomo_json),
        ("feishu_status.json", &feishu_json),
        ("audit_logs.txt", logs_txt.as_bytes()),
    ];
    if let Some(ref bytes) = daemon_log_bytes {
        archive_entries.push((DAEMON_LOG_FILE, bytes));
    }
    if let Some(ref bytes) = daemon_log_prev_bytes {
        archive_entries.push((DAEMON_LOG_PREV_FILE, bytes));
    }
    let zip_bytes = zip_util::build_zip_archive(&archive_entries)?;

    let fallback_dir = data_dir.join("diagnostics");
    let mut out_dir = explicit_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| resolve_diagnostics_dir(data_dir));

    if has_reparse_point_in_chain(&out_dir) {
        out_dir = fallback_dir.clone();
    }

    let using_fallback = out_dir == fallback_dir;
    if using_fallback {
        crate::journal::ensure_secure_data_dir(data_dir)?;
    }
    if has_reparse_point_in_chain(&out_dir) {
        return Err("拒绝向包含符号链接或重解析点的目录写入诊断压缩包".into());
    }
    fs::create_dir_all(&out_dir).map_err(|e| format!("创建诊断导出目录失败：{e}"))?;
    if has_reparse_point_in_chain(&out_dir) {
        return Err("检测到诊断导出目录存在符号链接或目录联接，已拒绝写入".into());
    }

    let out_path = write_diagnostics_zip_create_new(&out_dir, now_secs, &zip_bytes)?;
    if using_fallback {
        prune_diagnostics_archives(&fallback_dir, MAX_DIAGNOSTIC_ARCHIVES);
    }
    Ok(out_path)
}

/// Scrubs IPv4, IPv6, credentials (`user:pass@`), and user profile paths from a health card string
/// while preserving safe coarse country badges (`US`, `JP`, etc.).
fn scrub_health_card_text(raw: &str) -> String {
    let mut s = mask_text_ips(raw);
    let mut out_words = Vec::new();
    for token in s.split_whitespace() {
        let colon_count = token.bytes().filter(|&b| b == b':').count();
        let trimmed = token.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != ':');
        let is_ipv6_like = colon_count >= 2
            && !trimmed.is_empty()
            && trimmed.bytes().all(|b| b.is_ascii_hexdigit() || b == b':');
        if is_ipv6_like {
            out_words.push("<REDACTED>");
        } else {
            out_words.push(token);
        }
    }
    s = out_words.join(" ");

    for marker in ["\\Users\\", "/Users/", "/home/"] {
        while let Some(pos) = s.find(marker) {
            let after = pos + marker.len();
            let end = s[after..]
                .find(['\\', '/', ' ', '"', '\'', ')', ']'])
                .map(|rel| after + rel)
                .unwrap_or(s.len());
            if &s[after..end] == "<REDACTED>" {
                break;
            }
            s.replace_range(after..end, "<REDACTED>");
        }
    }
    s
}

/// Builds a 100% desensitized shareable Pre-Flight Health Card (`M7`) with zero IP/coordinate/PII leaks.
pub fn build_sanitized_health_card(
    snap: &GuardSnapshot,
    data_dir: &Path,
    now_secs: u64,
    export_png: bool,
) -> SanitizedHealthCard {
    let cg_version = if snap.version.trim().is_empty() {
        env!("CARGO_PKG_VERSION").to_string()
    } else {
        snap.version.clone()
    };

    let safety_score = if snap.risk_assessment.evaluated_at > 0 {
        snap.risk_assessment.score
    } else if snap.all_enabled_pass() {
        85
    } else {
        0
    };
    let grade = if snap.risk_assessment.evaluated_at > 0 {
        snap.risk_assessment.grade
    } else {
        SafetyGrade::from_score(safety_score)
    };

    let raw_country = snap
        .targets
        .iter()
        .find(|t| t.id == "claude" && t.state == TargetState::Pass)
        .and_then(|t| t.country.as_deref())
        .or(snap.risk_assessment.ip_purity.country.as_deref())
        .or_else(|| {
            snap.targets
                .iter()
                .find(|t| t.state == TargetState::Pass && t.country.is_some())
                .and_then(|t| t.country.as_deref())
        });
    let region_badge = raw_country
        .and_then(normalize_region)
        .map(|cc| format!("{cc} · {}", region_name(&cc)))
        .unwrap_or_else(|| "待核验出口地区".to_string());

    let asn_purity_badge = scrub_health_card_text(&format!(
        "{} · 滥用风险 {}/100",
        snap.risk_assessment.ip_purity.classification.label_zh(),
        snap.risk_assessment.ip_purity.abuse_risk_score
    ));

    let wfp_shield_badge = if snap.wfp.sublayer_registered {
        format!(
            "WFP 内核子层已启用 · 已拦截 {} 次直连",
            snap.wfp.total_blocked_packets
        )
    } else if !snap.wfp.active_backend.is_empty() {
        scrub_health_card_text(&format!("防火墙引擎 {}", snap.wfp.active_backend))
    } else {
        "系统防火墙守卫就绪".to_string()
    };

    let stun_ok = !snap.risk_assessment.stun_leak.leaked;
    let dns_ok = snap.risk_assessment.dns_coherence.checked_at == 0
        || snap.risk_assessment.dns_coherence.coherent;
    let dual_ok = !snap.risk_assessment.ip_purity.dual_stack_split_detected;
    let electron_ok = snap
        .risk_assessment
        .electron_hygiene
        .unguarded_running_agents
        .is_empty();
    let leak_hygiene_badge = format!(
        "STUN {} · DNS {} · IPv6 {} · Electron {}",
        if stun_ok { "安全" } else { "泄露风险" },
        if dns_ok { "一致" } else { "偏移" },
        if dual_ok { "无分叉" } else { "双栈分叉" },
        if electron_ok { "合规" } else { "需加固" }
    );

    let geo_stability_badge = if snap.risk_assessment.geo_velocity_alert.is_some() {
        format!(
            "检测到跨国瞬移预警（1h {} 子网 / 24h {} 国家）",
            snap.risk_assessment.distinct_subnets_1h, snap.risk_assessment.distinct_countries_24h
        )
    } else {
        format!(
            "轨迹稳定（1h {} 子网 / 24h {} 国家）",
            snap.risk_assessment.distinct_subnets_1h, snap.risk_assessment.distinct_countries_24h
        )
    };

    let vault_isolation_badge = format!(
        "{} 个隔离分身保险箱（{} 个运行中）",
        snap.config.vaults.len(),
        snap.vaults
            .iter()
            .filter(|v| !v.running_pids.is_empty())
            .count()
    );

    let markdown_snippet = scrub_health_card_text(&format!(
        "### 🛡️ ClaudeGuard v{cg_version} 防封健康体检卡\n\
         - **综合安全分**：**{safety_score}/100（{} 级）**\n\
         - **出口地区**：{region_badge}\n\
         - **ASN 纯净度**：{asn_purity_badge}\n\
         - **内核护盾**：{wfp_shield_badge}\n\
         - **防泄露卫生**：{leak_hygiene_badge}\n\
         - **地理轨迹**：{geo_stability_badge}\n\
         - **分身隔离**：{vault_isolation_badge}\n\
         > 已全程脱敏，零公网 IP / 经纬度 / 账号凭据泄露。",
        grade.code()
    ));

    let saved_png_path = if export_png {
        export_health_card_png(data_dir, safety_score, grade, now_secs)
            .ok()
            .map(|p| p.to_string_lossy().to_string())
    } else {
        None
    };

    SanitizedHealthCard {
        generated_at: now_secs,
        cg_version,
        safety_score,
        grade,
        region_badge: scrub_health_card_text(&region_badge),
        asn_purity_badge,
        wfp_shield_badge,
        leak_hygiene_badge,
        geo_stability_badge,
        vault_isolation_badge,
        markdown_snippet,
        saved_png_path,
    }
}

fn export_health_card_png(
    data_dir: &Path,
    safety_score: u8,
    grade: SafetyGrade,
    now_secs: u64,
) -> Result<PathBuf, String> {
    let out_dir = data_dir.join("health_cards");
    if has_reparse_point_in_chain(&out_dir) {
        return Err("refusing to export health card PNG through reparse point".into());
    }
    fs::create_dir_all(&out_dir).map_err(|e| format!("创建健康卡导出目录失败：{e}"))?;

    let base = format!("ClaudeGuard-HealthCard-{now_secs}");
    let mut chosen = out_dir.join(format!("{base}.png"));
    let mut file = None;
    for suffix in 0u32..100 {
        let candidate = if suffix == 0 {
            out_dir.join(format!("{base}.png"))
        } else {
            out_dir.join(format!("{base}-{suffix}.png"))
        };
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(f) => {
                chosen = candidate;
                file = Some(f);
                break;
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(format!("创建健康卡 PNG 文件失败：{err}")),
        }
    }
    let mut f = file.ok_or_else(|| "无法分配唯一健康卡 PNG 文件名".to_string())?;
    let bytes = encode_health_card_png(safety_score, grade);
    f.write_all(&bytes)
        .and_then(|()| f.sync_all())
        .map_err(|e| format!("写入健康卡 PNG 失败：{e}"))?;
    Ok(chosen)
}

fn encode_health_card_png(safety_score: u8, grade: SafetyGrade) -> Vec<u8> {
    const W: u32 = 240;
    const H: u32 = 72;
    let accent: [u8; 4] = match grade {
        SafetyGrade::S => [16, 185, 129, 255],
        SafetyGrade::A => [59, 130, 246, 255],
        SafetyGrade::B => [234, 179, 8, 255],
        SafetyGrade::C => [249, 115, 22, 255],
        SafetyGrade::F => [239, 68, 68, 255],
    };
    let bg: [u8; 4] = [18, 24, 38, 255];
    let track: [u8; 4] = [42, 52, 70, 255];
    let bar_fill_x = 20u32 + ((W - 40) * (safety_score.min(100) as u32)) / 100;

    let mut raw = Vec::with_capacity((H as usize) * (1 + (W as usize) * 4));
    for y in 0..H {
        raw.push(0);
        for x in 0..W {
            let px = if !(6..H - 2).contains(&y) || x < 6 {
                accent
            } else if (44..56).contains(&y) && (20..W - 20).contains(&x) {
                if x <= bar_fill_x {
                    accent
                } else {
                    track
                }
            } else {
                bg
            };
            raw.extend_from_slice(&px);
        }
    }

    let mut zlib = Vec::with_capacity(raw.len() + 32);
    zlib.push(0x78);
    zlib.push(0x01);
    let mut offset = 0usize;
    while offset < raw.len() {
        let chunk_len = (raw.len() - offset).min(65_535);
        let is_final = offset + chunk_len >= raw.len();
        zlib.push(if is_final { 0x01 } else { 0x00 });
        let len16 = chunk_len as u16;
        zlib.extend_from_slice(&len16.to_le_bytes());
        zlib.extend_from_slice(&(!len16).to_le_bytes());
        zlib.extend_from_slice(&raw[offset..offset + chunk_len]);
        offset += chunk_len;
    }
    let adler = adler32(&raw);
    zlib.extend_from_slice(&adler.to_be_bytes());

    let mut png = Vec::with_capacity(zlib.len() + 64);
    png.extend_from_slice(b"\x89PNG\r\n\x1a\n");

    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&W.to_be_bytes());
    ihdr.extend_from_slice(&H.to_be_bytes());
    ihdr.push(8);
    ihdr.push(6);
    ihdr.push(0);
    ihdr.push(0);
    ihdr.push(0);
    push_png_chunk(&mut png, b"IHDR", &ihdr);
    push_png_chunk(&mut png, b"IDAT", &zlib);
    push_png_chunk(&mut png, b"IEND", &[]);
    png
}

fn push_png_chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    let mut crc_input = Vec::with_capacity(4 + data.len());
    crc_input.extend_from_slice(kind);
    crc_input.extend_from_slice(data);
    out.extend_from_slice(&crc32_ieee(&crc_input).to_be_bytes());
}

fn adler32(data: &[u8]) -> u32 {
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + byte as u32) % 65_521;
        b = (b + a) % 65_521;
    }
    (b << 16) | a
}

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use cg_protocol::{
        AgentKind, AgentRuntimeStatus, LogEntry, LogLevel, TargetState, TargetStatus,
    };
    use tempfile::tempdir;

    #[test]
    fn exported_diagnostics_zip_redacts_ips_coords_usernames_credentials_and_colos() {
        let dir = tempdir().unwrap();
        let mut snap = GuardSnapshot {
            version: "4.1.2".into(),
            ..GuardSnapshot::default()
        };
        snap.config.proxy_host = "http://alice:s3cr3tPass@127.0.0.1:7890".into();
        snap.access.proxy_addr = Some("http://bob:topSecret@127.0.0.1:7890".into());
        snap.access.note = "系统代理 http://bob:topSecret@127.0.0.1:7890".into();
        snap.antigravity_proxy.antigravity_dir =
            Some(r"C:\Users\alice_secret\AppData\Local\Programs\Antigravity IDE".into());
        snap.antigravity_proxy.proxy_host = Some("socks5://user1:pw2@127.0.0.1:7890".into());
        snap.agents.push(AgentRuntimeStatus {
            id: "claude".into(),
            name: "Claude".into(),
            kind: AgentKind::Gui,
            installed: true,
            guarded: true,
            running_count: 1,
            orphan_count: 0,
            quarantined: false,
            firewall_rules: 0,
            install_paths: vec![
                r"C:\Users\alice_secret\AppData\Local\AnthropicClaude\claude.exe".into(),
            ],
        });
        snap.env_applied = Some(AppliedEnv {
            at: 1700000000,
            city: "Los Angeles".into(),
            tz_from: "China Standard Time".into(),
            tz_to: "Pacific Standard Time".into(),
            lat_from: Some("31.2304".into()),
            lon_from: Some("121.4737".into()),
            lat_to: "34.0522".into(),
            lon_to: "-118.2437".into(),
        });
        snap.env.egress_colo = Some("LAX".into());
        snap.env.expect_city = Some("Los Angeles".into());

        let mut t = cg_protocol::default_builtin_targets(&["198.51.100.98".into()], &["US".into()])
            .into_iter()
            .next()
            .unwrap();
        t.id = "claude".into();
        let mut ts = TargetStatus::from_target(&t, TargetState::Pass);
        ts.ip = Some("198.51.100.98".into());
        ts.colo = Some("LAX".into());
        ts.city = Some("Los Angeles".into());
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
            message: r"检测到真实出口 203.0.113.45 路径 C:\Users\alice_secret\claude.exe 代理 http://u:p@127.0.0.1:7890".into(),
        });

        let out = export_redacted_diagnostics_zip(dir.path(), &snap, 1700000000, Some(dir.path()))
            .expect("export zip");
        assert!(out.is_file());
        let raw = fs::read(&out).unwrap();
        let (_, snap_entry) =
            zip_util::extract_file_from_zip(&raw, "snapshot_redacted.json").expect("read snap");
        let snap_text = String::from_utf8(snap_entry).unwrap();
        for forbidden in [
            "198.51.100.98",
            "203.0.113.45",
            "alice_secret",
            "s3cr3tPass",
            "topSecret",
            "user1:pw2",
            "u:p@",
            "31.2304",
            "121.4737",
            "34.0522",
            "-118.2437",
            "Los Angeles",
            "\"LAX\"",
        ] {
            assert!(
                !snap_text.contains(forbidden),
                "snapshot_redacted.json leaked '{forbidden}': {snap_text}"
            );
        }
        let parsed_snap: GuardSnapshot = serde_json::from_str(&snap_text).unwrap();
        let applied = parsed_snap.env_applied.unwrap();
        assert_eq!(applied.lat_from.as_deref(), Some("0.0"));
        assert_eq!(applied.lon_from.as_deref(), Some("0.0"));
        assert_eq!(applied.lat_to, "0.0");
        assert_eq!(applied.lon_to, "0.0");
        assert!(parsed_snap.agents[0].install_paths[0].contains(r"\Users\<REDACTED>\"));
        assert!(parsed_snap
            .antigravity_proxy
            .antigravity_dir
            .unwrap()
            .contains(r"\Users\<REDACTED>\"));
        assert!(parsed_snap.targets[0].colo.is_none());
        assert!(parsed_snap.targets[0].city.is_none());
        assert!(parsed_snap.env.egress_colo.is_none());
        assert!(parsed_snap.env.expect_city.is_none());

        let (_, logs_entry) =
            zip_util::extract_file_from_zip(&raw, "audit_logs.txt").expect("read logs");
        let logs_text = String::from_utf8(logs_entry).unwrap();
        assert!(!logs_text.contains("203.0.113.45"));
        assert!(!logs_text.contains("alice_secret"));
        assert!(!logs_text.contains("u:p@"));
    }

    #[test]
    fn create_new_collision_suffix_never_overwrites_existing_and_fallback_prunes_to_10() {
        let root = tempdir().unwrap();
        let data_dir = root.path().join("data");
        let export_dir = root.path().join("out");
        fs::create_dir_all(&export_dir).unwrap();

        let pre_existing = export_dir.join("ClaudeGuard-Diagnostics-1700000100.zip");
        fs::write(&pre_existing, b"DO_NOT_OVERWRITE").unwrap();

        let snap = GuardSnapshot::default();
        let second =
            export_redacted_diagnostics_zip(&data_dir, &snap, 1700000100, Some(&export_dir))
                .expect("collision suffix -1");
        assert_eq!(
            second.file_name().unwrap().to_string_lossy(),
            "ClaudeGuard-Diagnostics-1700000100-1.zip"
        );
        assert_eq!(fs::read(&pre_existing).unwrap(), b"DO_NOT_OVERWRITE");

        // Verify fallback `<data_dir>\diagnostics` prunes archives to keep at most 10.
        let fallback_dir = data_dir.join("diagnostics");
        for ts in 1..=14u64 {
            let _ = export_redacted_diagnostics_zip(
                &data_dir,
                &snap,
                1700001000 + ts,
                Some(&fallback_dir),
            )
            .unwrap();
        }
        let remaining: Vec<_> = fs::read_dir(&fallback_dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".zip"))
            .collect();
        assert_eq!(remaining.len(), MAX_DIAGNOSTIC_ARCHIVES);

        // Windows junction on Desktop must be detected and routed to `<data_dir>\diagnostics`.
        #[cfg(windows)]
        {
            let target_dir = root.path().join("sensitive_target");
            fs::create_dir_all(&target_dir).unwrap();
            let user_home = root.path().join("Users").join("bob");
            fs::create_dir_all(&user_home).unwrap();
            let junction_desktop = user_home.join("Desktop");
            let status = std::process::Command::new("cmd.exe")
                .args([
                    "/C",
                    "mklink",
                    "/J",
                    &junction_desktop.to_string_lossy(),
                    &target_dir.to_string_lossy(),
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
            if status.is_ok_and(|s| s.success()) {
                assert!(has_reparse_point_in_chain(&junction_desktop));
                assert!(has_reparse_point_in_chain(&junction_desktop.join("sub")));
                let redirected = export_redacted_diagnostics_zip(
                    &data_dir,
                    &snap,
                    1700009999,
                    Some(&junction_desktop),
                )
                .expect("junction desktop must fall back safely to data_dir/diagnostics");
                assert!(redirected.starts_with(&fallback_dir));
                assert!(
                    fs::read_dir(&target_dir).unwrap().next().is_none(),
                    "must never write files through Desktop junction target"
                );
                let _ = fs::remove_dir(&junction_desktop);
            }
        }
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
            resolve_diagnostics_dir_with(Some(sys_profile), Some(&user_home), &data_dir, &temp_dir),
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

    #[test]
    fn rolling_daemon_log_redacts_rotates_at_512k_and_exports_into_diagnostics_zip() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().join("data");
        let out_dir = dir.path().join("out");
        fs::create_dir_all(&data_dir).unwrap();
        fs::create_dir_all(&out_dir).unwrap();

        let filler = "x".repeat(260 * 1024);
        append_redacted_daemon_log_entries(
            &data_dir,
            &[
                LogEntry {
                    id: 1,
                    timestamp: 1_700_000_001,
                    level: LogLevel::Warn,
                    category: "wal".into(),
                    message: format!(
                        r"first chunk 203.0.113.45 C:\Users\alice_secret\claude.exe http://u1:p1@127.0.0.1:7890 {filler}"
                    ),
                },
                LogEntry {
                    id: 2,
                    timestamp: 1_700_000_002,
                    level: LogLevel::Info,
                    category: "probe".into(),
                    message: format!("second chunk to reach 512KiB {filler}"),
                },
            ],
        );

        let log_path = data_dir.join("daemon.log");
        let prev_path = data_dir.join("daemon.log.1");
        assert!(log_path.metadata().unwrap().len() >= 512 * 1024);
        assert!(!prev_path.exists());

        // Next append must rotate `daemon.log` -> `daemon.log.1` and start a fresh `daemon.log`.
        append_redacted_daemon_log_entries(
            &data_dir,
            &[LogEntry {
                id: 3,
                timestamp: 1_700_000_003,
                level: LogLevel::Audit,
                category: "power".into(),
                message: r"post-rotate 198.51.100.98 C:\Users\bob_secret\app.exe socks5://u2:p2@127.0.0.1:7890".into(),
            }],
        );

        assert!(prev_path.is_file());
        assert!(log_path.is_file());
        assert!(log_path.metadata().unwrap().len() < 1024);

        let cur_text = fs::read_to_string(&log_path).unwrap();
        let prev_text = fs::read_to_string(&prev_path).unwrap();
        assert!(cur_text.contains("[1700000003] AUDIT [power]"));
        for forbidden in [
            "203.0.113.45",
            "198.51.100.98",
            "alice_secret",
            "bob_secret",
            "u1:p1@",
            "u2:p2@",
        ] {
            assert!(
                !cur_text.contains(forbidden),
                "daemon.log leaked {forbidden}"
            );
            assert!(
                !prev_text.contains(forbidden),
                "daemon.log.1 leaked {forbidden}"
            );
        }

        let snap = GuardSnapshot::default();
        let zip_path =
            export_redacted_diagnostics_zip(&data_dir, &snap, 1_700_000_100, Some(&out_dir))
                .expect("export zip with daemon.log and daemon.log.1");
        let raw_zip = fs::read(&zip_path).unwrap();
        let (_, z_cur) = zip_util::extract_file_from_zip(&raw_zip, "daemon.log")
            .expect("daemon.log must be bundled in diagnostics zip");
        let (_, z_prev) = zip_util::extract_file_from_zip(&raw_zip, "daemon.log.1")
            .expect("daemon.log.1 must be bundled in diagnostics zip");
        let z_cur_str = String::from_utf8(z_cur).unwrap();
        let z_prev_str = String::from_utf8(z_prev).unwrap();
        assert!(z_cur_str.contains("[1700000003] AUDIT [power]"));
        assert!(!z_cur_str.contains("bob_secret"));
        assert!(!z_prev_str.contains("alice_secret"));
    }

    #[test]
    fn sanitized_health_card_leaks_zero_ips_usernames_or_credentials_and_exports_png() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().join("data");
        fs::create_dir_all(&data_dir).unwrap();

        let mut snap = GuardSnapshot {
            version: "5.0.0".into(),
            ..GuardSnapshot::default()
        };
        let mut t = cg_protocol::default_builtin_targets(&["198.51.100.77".into()], &["US".into()])
            .into_iter()
            .next()
            .unwrap();
        t.id = "claude".into();
        let mut ts = TargetStatus::from_target(&t, TargetState::Pass);
        ts.ip = Some("198.51.100.77".into());
        ts.country = Some("US".into());
        ts.city = Some("Los Angeles".into());
        snap.targets.push(ts);
        snap.wfp.sublayer_registered = true;
        snap.wfp.total_blocked_packets = 5;
        snap.risk_assessment.evaluated_at = 1_700_000_123;
        snap.risk_assessment.score = 94;
        snap.risk_assessment.grade = SafetyGrade::S;
        snap.risk_assessment.ip_purity.ip = Some("198.51.100.77".into());
        snap.risk_assessment.ip_purity.country = Some("US".into());
        snap.risk_assessment.ip_purity.city = Some("Los Angeles".into());
        snap.risk_assessment.ip_purity.asn_org =
            r"Comcast 203.0.113.99 2001:db8::1234 C:\Users\secret_alice\test".into();
        snap.risk_assessment.stun_leak.reflexive_ip = Some("203.0.113.88".into());
        snap.risk_assessment.stun_leak.summary = "STUN 203.0.113.88".into();
        snap.risk_assessment.dns_coherence.coherent = true;

        let card_no_png = build_sanitized_health_card(&snap, &data_dir, 1_700_000_200, false);
        assert!(card_no_png.saved_png_path.is_none());
        assert_eq!(card_no_png.safety_score, 94);
        assert_eq!(card_no_png.grade, SafetyGrade::S);
        assert!(card_no_png.region_badge.contains("US"));
        let serialized = serde_json::to_string(&card_no_png).unwrap();
        for forbidden in [
            "198.51.100.77",
            "203.0.113.99",
            "203.0.113.88",
            "2001:db8::1234",
            "Los Angeles",
            "secret_alice",
        ] {
            assert!(
                !serialized.contains(forbidden),
                "SanitizedHealthCard leaked '{forbidden}': {serialized}"
            );
        }

        let card_with_png = build_sanitized_health_card(&snap, &data_dir, 1_700_000_201, true);
        let png_path = card_with_png
            .saved_png_path
            .as_deref()
            .expect("export_png=true must produce a PNG path");
        let png_bytes = fs::read(png_path).expect("read exported PNG");
        assert!(png_bytes.starts_with(b"\x89PNG\r\n\x1a\n"));
        assert!(png_bytes.len() > 64);
    }
}
