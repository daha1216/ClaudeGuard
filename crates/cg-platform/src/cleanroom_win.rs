//! M5: 4-vector local anti-correlation Clean-Room Residue Scanner & `.cgbak`
//! (`CGBAK005` AES-256-GCM + DPAPI) encrypted backup/restore engine.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use base64::{engine::general_purpose::STANDARD, Engine};
use cg_protocol::{
    CleanRoomBackupMeta, CleanRoomFinding, CleanRoomReport, CleanRoomRiskLevel, CleanRoomScope,
    CleanRoomVector,
};
use serde::{Deserialize, Serialize};

use crate::crypto_win;
use crate::vault_win::{
    atomic_write_no_reparse, ensure_no_reparse_points_chain, is_reparse_or_symlink,
    safe_create_dir_all_no_reparse, safe_remove_path_no_reparse,
};
use crate::zip_util;

/// Preservation guarantee shown on Claude Code findings.
pub const CLAUDE_CODE_PRESERVATION_NOTE: &str =
    "100% 保留 CLAUDE.md、settings.json、mcpServers 与 skills/";

/// Preservation guarantee shown on Claude Desktop findings.
pub const CLAUDE_DESKTOP_PRESERVATION_NOTE: &str =
    "100% 保留 claude_desktop_config.json（桌面端 MCP Servers 配置）";

/// Hard upper bound for raw uncompressed files packed into a single `.cgbak` ZIP archive (64 MiB).
pub const MAX_BACKUP_UNCOMPRESSED_BYTES: usize = 64 * 1024 * 1024;

/// Maximum per-file size included in `.cgbak` (skip huge cache blobs cleanly, never fail backup).
pub const MAX_SINGLE_BACKUP_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Maximum encrypted backups retained under `<data_dir>\CleanRoomBackups`.
pub const MAX_RETAINED_BACKUPS: usize = 10;

/// Correlation & telemetry keys purged from `~/.claude.json`.
const CLAUDE_JSON_PURGE_KEYS: &[&str] = &[
    "userID",
    "oauthAccount",
    "cachedStatsigGates",
    "cachedDynamicConfigs",
    "cachedGrowthBookFeatures",
    "statsigMetadata",
    "s1mAccessCache",
    "groveConfigCache",
    "passesEligibilityCache",
];

/// Read-only metadata summary of one matching Windows Credential Manager entry.
/// Never carries plaintext credential blobs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSummary {
    pub target_name: String,
    pub cred_type: u32,
    pub blob_bytes: u64,
    pub client_id: String,
}

/// Internal target action paired with each `CleanRoomFinding`.
#[derive(Clone, Debug)]
enum CleanTarget {
    SanitizeClaudeJson { path: PathBuf, home_root: PathBuf },
    RemoveFile { path: PathBuf, home_root: PathBuf },
    RemoveDir { path: PathBuf, home_root: PathBuf },
    WindowsCredential { target_name: String, cred_type: u32 },
    RunningProcess { pid: u32, exe_name: String },
}

#[derive(Clone, Debug)]
struct PlannedFinding {
    finding: CleanRoomFinding,
    target: CleanTarget,
}

/// Serialized manifest stored INSIDE the AES-256-GCM encrypted ZIP archive (`manifest.json`).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BackupArchiveManifest {
    schema_version: u32,
    backup_id: String,
    created_at: u64,
    files: Vec<BackupFileEntry>,
    credentials: Vec<BackupCredentialEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BackupFileEntry {
    zip_entry: String,
    anchor_root: String,
    rel_path: String,
    original_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BackupCredentialEntry {
    target_name: String,
    cred_type: u32,
    user_name: Option<String>,
    comment: Option<String>,
    target_alias: Option<String>,
    persist: u32,
    blob_b64: String,
}

/// Mask an opaque identifier (e.g. `userID`, `anonymousId`, credential target) so raw tokens
/// or IDs never leak into IPC snapshots or logs.
pub fn mask_identifier(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return "****".into();
    }
    let chars: Vec<char> = trimmed.chars().collect();
    if chars.len() <= 6 {
        return "****".into();
    }
    let prefix_len = if chars.len() >= 14 { 7 } else { 3 };
    let suffix_len = if chars.len() >= 14 { 4 } else { 2 };
    let prefix: String = chars[..prefix_len].iter().collect();
    let suffix: String = chars[chars.len() - suffix_len..].iter().collect();
    format!("{prefix}****{suffix}")
}

/// Mask an email address (e.g. `alice@gmail.com` -> `a***@gmail.com`).
pub fn mask_email(raw: &str) -> String {
    let trimmed = raw.trim();
    let Some((local, domain)) = trimmed.split_once('@') else {
        return mask_identifier(trimmed);
    };
    let first = local.chars().next().unwrap_or('*');
    format!("{first}***@{domain}")
}

/// Redacts Windows user home prefix so raw usernames never appear in clean-room displays.
pub fn redact_user_path(path: &Path, user_home: &Path) -> String {
    if let Ok(rel) = path.strip_prefix(user_home) {
        let rel_str = rel.to_string_lossy().replace('/', "\\");
        if let Some(rest) = strip_prefix_ci(&rel_str, r"AppData\Roaming\") {
            return format!(r"%APPDATA%\{rest}");
        }
        if let Some(rest) = strip_prefix_ci(&rel_str, r"AppData\Local\") {
            return format!(r"%LOCALAPPDATA%\{rest}");
        }
        return format!(r"%USERPROFILE%\{rel_str}");
    }
    // Defensive fallback: redact `C:\Users\<name>\...` even when path is outside `user_home`.
    let raw = path.to_string_lossy().replace('/', "\\");
    let lower = raw.to_ascii_lowercase();
    if let Some(idx) = lower.find(r"\users\") {
        let after = &raw[idx + 7..];
        if let Some(slash) = after.find('\\') {
            return format!(r"%USERPROFILE%{}", &after[slash..]);
        }
        return "%USERPROFILE%".into();
    }
    raw
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() < prefix.len() {
        return None;
    }
    let head = s.get(..prefix.len())?;
    if head.eq_ignore_ascii_case(prefix) {
        s.get(prefix.len()..)
    } else {
        None
    }
}

/// Computes deterministic composite chain-ban contamination score (`0..=100`) and risk level
/// from the 4-vector findings list.
pub fn compute_pollution_score(findings: &[CleanRoomFinding]) -> (u8, CleanRoomRiskLevel) {
    let mut v1: u16 = 0;
    let mut v2: u16 = 0;
    let mut v3: u16 = 0;
    let mut v4: u16 = 0;

    for f in findings {
        match f.vector {
            CleanRoomVector::ClaudeCodeState => {
                v1 = v1.saturating_add(f.risk_weight as u16).min(40)
            }
            CleanRoomVector::DesktopChromiumAndCrashpad => {
                v2 = v2.saturating_add(f.risk_weight as u16).min(35)
            }
            CleanRoomVector::WindowsCredentialManager => {
                v3 = v3.saturating_add(f.risk_weight as u16).min(15)
            }
            CleanRoomVector::OrphanMemoryProcess => {
                v4 = v4.saturating_add(f.risk_weight as u16).min(10)
            }
        }
    }

    let score = (v1 + v2 + v3 + v4).min(100) as u8;
    let level = match score {
        0 => CleanRoomRiskLevel::Clean,
        1..=29 => CleanRoomRiskLevel::Low,
        30..=59 => CleanRoomRiskLevel::Elevated,
        _ => CleanRoomRiskLevel::CriticalChainBanRisk,
    };
    (score, level)
}

/// Surgically removes/rotates ONLY account correlation and telemetry keys inside a parsed
/// `~/.claude.json` `serde_json::Value` while preserving `mcpServers`, `projects`, `theme`,
/// `hasCompletedOnboarding`, and all other user preferences 100% intact.
///
/// Returns the ordered list of removed/rotated keys.
pub fn sanitize_claude_json_value(val: &mut serde_json::Value) -> Vec<String> {
    let Some(root) = val.as_object_mut() else {
        return Vec::new();
    };

    let mut modified = Vec::new();
    for &key in CLAUDE_JSON_PURGE_KEYS {
        if root.remove(key).is_some() {
            modified.push(key.to_string());
        }
    }

    // Rotate `anonymousId` to a brand-new CSPRNG UUIDv4 so previous telemetry cannot link sessions.
    let old_anon = root
        .get("anonymousId")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let mut new_anon = crypto_win::random_uuid_v4()
        .unwrap_or_else(|_| "00000000-0000-4000-8000-000000000001".into());
    if old_anon.as_deref() == Some(new_anon.as_str()) {
        new_anon = crypto_win::random_uuid_v4()
            .unwrap_or_else(|_| "00000000-0000-4000-8000-000000000002".into());
    }
    root.insert("anonymousId".into(), serde_json::Value::String(new_anon));
    modified.push("anonymousId".into());

    // Refresh `firstStartTime` if present so old onboarding timestamp is not carried forward.
    if root.contains_key("firstStartTime") {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        root.insert(
            "firstStartTime".into(),
            serde_json::Value::String(format_unix_iso8601(now_secs)),
        );
        modified.push("firstStartTime".into());
    }

    // Strip per-project stale session correlation fields while preserving project settings & MCPs.
    if let Some(projects) = root.get_mut("projects").and_then(|v| v.as_object_mut()) {
        let mut stripped_session = false;
        for (_proj_path, proj_val) in projects.iter_mut() {
            if let Some(proj_obj) = proj_val.as_object_mut() {
                if proj_obj.remove("lastSessionId").is_some() {
                    stripped_session = true;
                }
                proj_obj.remove("lastCost");
            }
        }
        if stripped_session {
            modified.push("projects.*.lastSessionId".into());
        }
    }

    modified
}

/// 100% read-only 4-vector Clean-Room Residue Scanner.
///
/// Never mutates files, registry, credentials, or running processes.
/// When `user_home` points to an isolated sandbox/temp directory rather than a real Windows user
/// profile, live OS Credential Manager & live process scanning are skipped so tests remain
/// hermetic and deterministic.
pub fn scan_cleanroom(
    scope: &CleanRoomScope,
    user_home: Option<&Path>,
    now_secs: u64,
) -> CleanRoomReport {
    let include_host_os = should_query_host_os(user_home);
    let planned = collect_cleanroom_plan(scope, user_home, include_host_os);
    build_report(
        scope,
        planned.into_iter().map(|p| p.finding).collect(),
        now_secs,
    )
}

fn build_report(
    scope: &CleanRoomScope,
    findings: Vec<CleanRoomFinding>,
    now_secs: u64,
) -> CleanRoomReport {
    let (pollution_score, risk_level) = compute_pollution_score(&findings);

    let mut preserved = Vec::new();
    if scope.claude {
        preserved.push(CLAUDE_CODE_PRESERVATION_NOTE.to_string());
        preserved.push(CLAUDE_DESKTOP_PRESERVATION_NOTE.to_string());
    }
    if scope.chatgpt_codex {
        preserved.push("保留 ~/.codex/config.toml 与用户工作区脚本".to_string());
    }
    if scope.antigravity {
        preserved.push("保留 IDE 插件目录、settings.json 与工作区代码".to_string());
    }

    let summary = if findings.is_empty() {
        "净室检查通过：未检测到跨账号关联残留指纹（污染分 0/100）".to_string()
    } else {
        format!(
            "检测到 {} 项关联残留（污染分 {}/100，风险等级 {:?}），建议加密备份后执行一键净室洗白",
            findings.len(),
            pollution_score,
            risk_level
        )
    };

    CleanRoomReport {
        scanned_at: now_secs,
        scope: scope.clone(),
        pollution_score,
        risk_level,
        findings,
        preserved_assets_summary: preserved,
        summary,
    }
}

fn resolve_effective_home(user_home: Option<&Path>) -> Option<PathBuf> {
    if let Some(h) = user_home {
        return Some(h.to_path_buf());
    }
    std::env::var_os("USERPROFILE")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

fn resolve_appdata_dirs(user_home: Option<&Path>, effective_home: &Path) -> (PathBuf, PathBuf) {
    if user_home.is_some() {
        return (
            effective_home.join("AppData").join("Roaming"),
            effective_home.join("AppData").join("Local"),
        );
    }
    let roaming = std::env::var_os("APPDATA")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| effective_home.join("AppData").join("Roaming"));
    let local = std::env::var_os("LOCALAPPDATA")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| effective_home.join("AppData").join("Local"));
    (roaming, local)
}

/// Determines whether `user_home` refers to the real host user profile (vs. a sandbox/temp path).
fn should_query_host_os(user_home: Option<&Path>) -> bool {
    let Some(home) = user_home else {
        return true;
    };
    if let Some(real_profile) = std::env::var_os("USERPROFILE").filter(|v| !v.is_empty()) {
        let a = home
            .to_string_lossy()
            .replace('/', "\\")
            .trim_end_matches('\\')
            .to_ascii_lowercase();
        let b = PathBuf::from(real_profile)
            .to_string_lossy()
            .replace('/', "\\")
            .trim_end_matches('\\')
            .to_ascii_lowercase();
        if a == b {
            return true;
        }
    }
    // Also treat direct `<drive>:\Users\<single_segment>` paths as real Windows profiles
    // (used when Session-0 `LocalSystem` passes an interactive user's profile path).
    let norm = home
        .to_string_lossy()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_string();
    let bytes = norm.as_bytes();
    if bytes.len() > 9
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && norm[2..9].eq_ignore_ascii_case(r"\users\")
    {
        let rest = &norm[9..];
        return !rest.is_empty() && !rest.contains('\\');
    }
    false
}

fn collect_cleanroom_plan(
    scope: &CleanRoomScope,
    user_home: Option<&Path>,
    include_host_os: bool,
) -> Vec<PlannedFinding> {
    let mut plan = Vec::new();
    let Some(home) = resolve_effective_home(user_home) else {
        return plan;
    };
    let (roaming, local) = resolve_appdata_dirs(user_home, &home);

    // ---- Vector 1: Claude Code & CLI State ----
    if scope.claude {
        scan_claude_code_vector(&home, &mut plan);
    }
    if scope.chatgpt_codex {
        let codex_auth = home.join(".codex").join("auth.json");
        if is_safe_existing_file(&codex_auth) {
            let size = file_or_dir_bytes(&codex_auth);
            plan.push(PlannedFinding {
                finding: CleanRoomFinding {
                    id: "v1:codex:auth_json".into(),
                    client_id: "codex".into(),
                    vector: CleanRoomVector::ClaudeCodeState,
                    risk_weight: 20,
                    location_display: redact_user_path(&codex_auth, &home),
                    correlation_keys: vec!["tokens".into(), "account_id".into()],
                    masked_preview: format!("Codex OAuth auth.json ({size} B)"),
                    bytes_size: size,
                    preservation_note: "保留 ~/.codex/config.toml 与本地工程脚本".into(),
                },
                target: CleanTarget::RemoveFile {
                    path: codex_auth,
                    home_root: home.clone(),
                },
            });
        }
    }

    // ---- Vector 2: Desktop Chromium, MSIX LocalCache & Crashpad/Sentry ----
    if scope.claude {
        scan_chromium_root(
            &home,
            &roaming.join("Claude"),
            "claude",
            "exe",
            CLAUDE_DESKTOP_PRESERVATION_NOTE,
            &mut plan,
        );
        for msix_claude in discover_msix_roaming_dirs(&local, "claude_", "Claude") {
            scan_chromium_root(
                &home,
                &msix_claude,
                "claude",
                "msix",
                CLAUDE_DESKTOP_PRESERVATION_NOTE,
                &mut plan,
            );
        }
    }
    if scope.chatgpt_codex {
        let note = "保留用户本地聊天导出与脚本配置";
        scan_chromium_root(
            &home,
            &roaming.join("ChatGPT"),
            "chatgpt",
            "exe",
            note,
            &mut plan,
        );
        for msix_gpt in discover_msix_roaming_dirs(&local, "openai.", "ChatGPT") {
            scan_chromium_root(&home, &msix_gpt, "chatgpt", "msix", note, &mut plan);
        }
    }
    if scope.antigravity {
        scan_chromium_root(
            &home,
            &roaming.join("Antigravity"),
            "antigravity",
            "ide",
            "保留 Antigravity 插件、settings.json 与代码工程",
            &mut plan,
        );
    }

    // ---- Vector 3: Windows Credential Manager ----
    if include_host_os {
        for cred in enumerate_matching_credentials(scope) {
            let id = format!(
                "v3:cred:{}:{}",
                cred.cred_type,
                crypto_win::sha256_hex(cred.target_name.as_bytes())
                    .get(..12)
                    .unwrap_or("cred")
            );
            plan.push(PlannedFinding {
                finding: CleanRoomFinding {
                    id,
                    client_id: cred.client_id.clone(),
                    vector: CleanRoomVector::WindowsCredentialManager,
                    risk_weight: 15,
                    location_display: format!(
                        "Windows Credential Manager ({})",
                        mask_identifier(&cred.target_name)
                    ),
                    correlation_keys: vec!["CredentialTarget".into()],
                    masked_preview: format!(
                        "target={} (blob={} B, 已脱敏)",
                        mask_identifier(&cred.target_name),
                        cred.blob_bytes
                    ),
                    bytes_size: cred.blob_bytes,
                    preservation_note: "清理前将加密备份至 .cgbak，支持一键还原".into(),
                },
                target: CleanTarget::WindowsCredential {
                    target_name: cred.target_name,
                    cred_type: cred.cred_type,
                },
            });
        }
    }

    // ---- Vector 4: Active / Orphan Memory Processes ----
    if include_host_os {
        for (pid, exe_name, finding) in scan_live_orphan_processes_detailed(scope) {
            plan.push(PlannedFinding {
                finding,
                target: CleanTarget::RunningProcess { pid, exe_name },
            });
        }
    }

    plan
}

fn scan_claude_code_vector(home: &Path, plan: &mut Vec<PlannedFinding>) {
    // 1. ~/.claude.json surgical key inspection
    let claude_json = home.join(".claude.json");
    if is_safe_existing_file(&claude_json) {
        if let Ok(raw) = std::fs::read(&claude_json) {
            if let Ok(serde_json::Value::Object(map)) = serde_json::from_slice(&raw) {
                let mut dirty_keys = Vec::new();
                let mut previews = Vec::new();

                for &k in CLAUDE_JSON_PURGE_KEYS {
                    if let Some(v) = map.get(k) {
                        dirty_keys.push(k.to_string());
                        if k == "userID" {
                            if let Some(s) = v.as_str() {
                                previews.push(format!("userID={}", mask_identifier(s)));
                            }
                        } else if k == "oauthAccount" {
                            if let Some(acct) = v.as_object() {
                                if let Some(email) =
                                    acct.get("emailAddress").and_then(|e| e.as_str())
                                {
                                    previews.push(format!("email={}", mask_email(email)));
                                }
                                if let Some(uid) = acct.get("accountUuid").and_then(|e| e.as_str())
                                {
                                    previews.push(format!("account={}", mask_identifier(uid)));
                                }
                            }
                        }
                    }
                }

                // Check projects[*].lastSessionId
                if let Some(projects) = map.get("projects").and_then(|v| v.as_object()) {
                    if projects.values().any(|pv| {
                        pv.as_object()
                            .is_some_and(|o| o.contains_key("lastSessionId"))
                    }) {
                        dirty_keys.push("projects.*.lastSessionId".into());
                    }
                }

                // Only report `.claude.json` as contaminated when purgeable account/cache keys remain;
                // include `anonymousId` & `firstStartTime` in the reported correlation keys & preview.
                if !dirty_keys.is_empty() {
                    if let Some(anon) = map.get("anonymousId").and_then(|v| v.as_str()) {
                        dirty_keys.push("anonymousId".into());
                        previews.push(format!("anonymousId={}", mask_identifier(anon)));
                    }
                    if map.contains_key("firstStartTime") {
                        dirty_keys.push("firstStartTime".into());
                    }
                    let preview_str = if previews.is_empty() {
                        format!("{} 项遥测/特征缓存键", dirty_keys.len())
                    } else {
                        previews.join(" · ")
                    };
                    plan.push(PlannedFinding {
                        finding: CleanRoomFinding {
                            id: "v1:claude:claude_json".into(),
                            client_id: "claude-code".into(),
                            vector: CleanRoomVector::ClaudeCodeState,
                            risk_weight: 28,
                            location_display: redact_user_path(&claude_json, home),
                            correlation_keys: dirty_keys,
                            masked_preview: preview_str,
                            bytes_size: raw.len() as u64,
                            preservation_note: CLAUDE_CODE_PRESERVATION_NOTE.into(),
                        },
                        target: CleanTarget::SanitizeClaudeJson {
                            path: claude_json,
                            home_root: home.to_path_buf(),
                        },
                    });
                }
            }
        }
    }

    // 2. ~/.claude.json.backup* and ~/.claude.json.tmp*
    if ensure_no_reparse_points_chain(home).is_ok() {
        if let Ok(rd) = std::fs::read_dir(home) {
            let mut extras: Vec<PathBuf> = rd
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    let name = p
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    (name.starts_with(".claude.json.backup")
                        || name.starts_with(".claude.json.tmp"))
                        && is_safe_existing_file(p)
                })
                .collect();
            extras.sort();
            for p in extras {
                let fname = p
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("backup")
                    .to_string();
                let size = file_or_dir_bytes(&p);
                plan.push(PlannedFinding {
                    finding: CleanRoomFinding {
                        id: format!("v1:claude:backup:{fname}"),
                        client_id: "claude-code".into(),
                        vector: CleanRoomVector::ClaudeCodeState,
                        risk_weight: 6,
                        location_display: redact_user_path(&p, home),
                        correlation_keys: vec!["claude_json_backup".into()],
                        masked_preview: format!("{fname} ({size} B)"),
                        bytes_size: size,
                        preservation_note: CLAUDE_CODE_PRESERVATION_NOTE.into(),
                    },
                    target: CleanTarget::RemoveFile {
                        path: p,
                        home_root: home.to_path_buf(),
                    },
                });
            }
        }
    }

    // 3. ~/.claude/.credentials.json
    let creds_file = home.join(".claude").join(".credentials.json");
    if is_safe_existing_file(&creds_file) {
        let size = file_or_dir_bytes(&creds_file);
        plan.push(PlannedFinding {
            finding: CleanRoomFinding {
                id: "v1:claude:credentials_json".into(),
                client_id: "claude-code".into(),
                vector: CleanRoomVector::ClaudeCodeState,
                risk_weight: 16,
                location_display: redact_user_path(&creds_file, home),
                correlation_keys: vec!["claudeAiOauth".into()],
                masked_preview: format!("OAuth credentials file ({size} B, 内容已脱敏)"),
                bytes_size: size,
                preservation_note: CLAUDE_CODE_PRESERVATION_NOTE.into(),
            },
            target: CleanTarget::RemoveFile {
                path: creds_file,
                home_root: home.to_path_buf(),
            },
        });
    }

    // 4. ~/.claude/statsig & ~/.claude/telemetry
    for (sub, key, weight) in [
        ("statsig", "statsig_cache", 8u8),
        ("telemetry", "telemetry_queue", 14u8),
    ] {
        let dir = home.join(".claude").join(sub);
        if is_safe_non_empty_dir(&dir) {
            let size = file_or_dir_bytes(&dir);
            plan.push(PlannedFinding {
                finding: CleanRoomFinding {
                    id: format!("v1:claude:{sub}"),
                    client_id: "claude-code".into(),
                    vector: CleanRoomVector::ClaudeCodeState,
                    risk_weight: weight,
                    location_display: redact_user_path(&dir, home),
                    correlation_keys: vec![key.into()],
                    masked_preview: format!("~/.claude/{sub} ({size} B)"),
                    bytes_size: size,
                    preservation_note: CLAUDE_CODE_PRESERVATION_NOTE.into(),
                },
                target: CleanTarget::RemoveDir {
                    path: dir,
                    home_root: home.to_path_buf(),
                },
            });
        }
    }
}

fn scan_chromium_root(
    home: &Path,
    root: &Path,
    client_id: &str,
    variant: &str,
    preservation_note: &str,
    plan: &mut Vec<PlannedFinding>,
) {
    if !root.is_dir() || ensure_no_reparse_points_chain(root).is_err() {
        return;
    }

    let file_targets: &[(&str, &str, u8)] = &[
        (r"Network\Cookies", "network_cookies", 12),
        (r"Network\Cookies-journal", "network_cookies_journal", 4),
        ("Cookies", "cookies", 12),
        ("Cookies-journal", "cookies_journal", 4),
        (
            r"Network\Network Persistent State",
            "network_persistent_state",
            8,
        ),
        (
            "Network Persistent State",
            "root_network_persistent_state",
            8,
        ),
        (r"Network\TransportSecurity", "transport_security", 5),
        ("DIPS", "dips_db", 8),
        ("DIPS-wal", "dips_wal", 3),
        ("DIPS-shm", "dips_shm", 2),
    ];

    for &(rel, tag, weight) in file_targets {
        let p = root.join(rel);
        if is_safe_existing_file(&p) {
            let size = file_or_dir_bytes(&p);
            plan.push(PlannedFinding {
                finding: CleanRoomFinding {
                    id: format!("v2:{client_id}:{variant}:{tag}"),
                    client_id: client_id.into(),
                    vector: CleanRoomVector::DesktopChromiumAndCrashpad,
                    risk_weight: weight,
                    location_display: redact_user_path(&p, home),
                    correlation_keys: vec![tag.into()],
                    masked_preview: format!("{rel} ({size} B, 会话指纹已脱敏)"),
                    bytes_size: size,
                    preservation_note: preservation_note.into(),
                },
                target: CleanTarget::RemoveFile {
                    path: p,
                    home_root: home.to_path_buf(),
                },
            });
        }
    }

    let dir_targets: &[(&str, &str, u8)] = &[
        (r"Local Storage\leveldb", "local_storage_leveldb", 12),
        ("Session Storage", "session_storage", 8),
        ("Sentry", "sentry_envelopes", 10),
        (r"Crashpad\reports", "crashpad_reports", 12),
        (r"Crashpad\pending", "crashpad_pending", 10),
    ];

    for &(rel, tag, weight) in dir_targets {
        let dir = root.join(rel);
        if is_safe_non_empty_dir(&dir) {
            let size = file_or_dir_bytes(&dir);
            plan.push(PlannedFinding {
                finding: CleanRoomFinding {
                    id: format!("v2:{client_id}:{variant}:{tag}"),
                    client_id: client_id.into(),
                    vector: CleanRoomVector::DesktopChromiumAndCrashpad,
                    risk_weight: weight,
                    location_display: redact_user_path(&dir, home),
                    correlation_keys: vec![tag.into()],
                    masked_preview: format!("{rel} ({size} B)"),
                    bytes_size: size,
                    preservation_note: preservation_note.into(),
                },
                target: CleanTarget::RemoveDir {
                    path: dir,
                    home_root: home.to_path_buf(),
                },
            });
        }
    }
}

fn discover_msix_roaming_dirs(
    local_app_data: &Path,
    pkg_prefix_lower: &str,
    roaming_subdir: &str,
) -> Vec<PathBuf> {
    let packages_dir = local_app_data.join("Packages");
    if !packages_dir.is_dir() || ensure_no_reparse_points_chain(&packages_dir).is_err() {
        return Vec::new();
    }
    let mut found = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&packages_dir) {
        for entry in rd.flatten() {
            let p = entry.path();
            let name_l = p
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if !name_l.starts_with(pkg_prefix_lower) {
                continue;
            }
            let candidate = p.join("LocalCache").join("Roaming").join(roaming_subdir);
            if candidate.is_dir() && ensure_no_reparse_points_chain(&candidate).is_ok() {
                found.push(candidate);
            }
        }
    }
    found.sort();
    found
}

/// Pure matcher determining whether a Windows Credential Manager `TargetName` belongs to an
/// enabled client inside `scope`.
pub fn match_credential_target_client(
    target_name: &str,
    scope: &CleanRoomScope,
) -> Option<&'static str> {
    let lower = target_name.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return None;
    }
    if scope.claude
        && (lower.starts_with("claude")
            || lower.starts_with("anthropic")
            || lower.contains("claude.ai")
            || lower.contains("claude-code")
            || lower.contains("claude_code"))
    {
        return Some("claude");
    }
    if scope.chatgpt_codex
        && (lower.starts_with("openai")
            || lower.starts_with("chatgpt")
            || lower.contains("chatgpt.com")
            || lower.contains("codex"))
    {
        return Some("chatgpt");
    }
    if scope.antigravity && lower.contains("antigravity") {
        return Some("antigravity");
    }
    None
}

/// Enumerates matching Windows Credential Manager entries via `CredEnumerateW` (read-only).
/// Strictly returns metadata summaries without exposing raw secret blobs.
#[cfg(windows)]
pub fn enumerate_matching_credentials(scope: &CleanRoomScope) -> Vec<CredentialSummary> {
    use windows::core::PCWSTR;
    use windows::Win32::Security::Credentials::{
        CredEnumerateW, CredFree, CREDENTIALW, CRED_ENUMERATE_FLAGS,
    };

    let _imp = match crate::access_win::ImpersonateInteractiveUserGuard::enter() {
        Ok(g) => g,
        Err(_) => return Vec::new(),
    };

    struct CredListGuard(*mut *mut CREDENTIALW);
    impl Drop for CredListGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    CredFree(self.0.cast());
                }
            }
        }
    }

    let mut out = Vec::new();
    let mut count: u32 = 0;
    let mut creds_ptr: *mut *mut CREDENTIALW = core::ptr::null_mut();

    unsafe {
        if CredEnumerateW(
            PCWSTR::null(),
            CRED_ENUMERATE_FLAGS(0),
            &mut count,
            &mut creds_ptr,
        )
        .is_err()
            || creds_ptr.is_null()
            || count == 0
        {
            return out;
        }
        let _guard = CredListGuard(creds_ptr);
        let slice = core::slice::from_raw_parts(creds_ptr, count as usize);
        for &entry_ptr in slice {
            if entry_ptr.is_null() {
                continue;
            }
            let cred = &*entry_ptr;
            if cred.TargetName.is_null() {
                continue;
            }
            let target_name = cred.TargetName.to_string().unwrap_or_default();
            if let Some(client_id) = match_credential_target_client(&target_name, scope) {
                out.push(CredentialSummary {
                    target_name,
                    cred_type: cred.Type.0,
                    blob_bytes: cred.CredentialBlobSize as u64,
                    client_id: client_id.to_string(),
                });
            }
        }
    }
    out.sort_by(|a, b| a.target_name.cmp(&b.target_name));
    out
}

#[cfg(not(windows))]
pub fn enumerate_matching_credentials(_scope: &CleanRoomScope) -> Vec<CredentialSummary> {
    Vec::new()
}

#[cfg(windows)]
fn read_credential_for_backup(
    target_name: &str,
    cred_type: u32,
) -> Result<Option<BackupCredentialEntry>, String> {
    use windows::core::PCWSTR;
    use windows::Win32::Security::Credentials::{
        CredEnumerateW, CredFree, CREDENTIALW, CRED_ENUMERATE_FLAGS,
    };

    let _imp = crate::access_win::ImpersonateInteractiveUserGuard::enter()?;

    struct CredListGuard(*mut *mut CREDENTIALW);
    impl Drop for CredListGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    CredFree(self.0.cast());
                }
            }
        }
    }

    let mut count: u32 = 0;
    let mut creds_ptr: *mut *mut CREDENTIALW = core::ptr::null_mut();
    unsafe {
        if CredEnumerateW(
            PCWSTR::null(),
            CRED_ENUMERATE_FLAGS(0),
            &mut count,
            &mut creds_ptr,
        )
        .is_err()
            || creds_ptr.is_null()
            || count == 0
        {
            return Ok(None);
        }
        let _guard = CredListGuard(creds_ptr);
        let slice = core::slice::from_raw_parts(creds_ptr, count as usize);
        for &entry_ptr in slice {
            if entry_ptr.is_null() {
                continue;
            }
            let cred = &*entry_ptr;
            if cred.TargetName.is_null() {
                continue;
            }
            let name = cred.TargetName.to_string().unwrap_or_default();
            if name == target_name && cred.Type.0 == cred_type {
                let blob = if cred.CredentialBlob.is_null() || cred.CredentialBlobSize == 0 {
                    Vec::new()
                } else {
                    core::slice::from_raw_parts(
                        cred.CredentialBlob,
                        cred.CredentialBlobSize as usize,
                    )
                    .to_vec()
                };
                return Ok(Some(BackupCredentialEntry {
                    target_name: name,
                    cred_type,
                    user_name: (!cred.UserName.is_null())
                        .then(|| cred.UserName.to_string().ok())
                        .flatten(),
                    comment: (!cred.Comment.is_null())
                        .then(|| cred.Comment.to_string().ok())
                        .flatten(),
                    target_alias: (!cred.TargetAlias.is_null())
                        .then(|| cred.TargetAlias.to_string().ok())
                        .flatten(),
                    persist: cred.Persist.0,
                    blob_b64: STANDARD.encode(blob),
                }));
            }
        }
    }
    Ok(None)
}

#[cfg(not(windows))]
fn read_credential_for_backup(
    _target_name: &str,
    _cred_type: u32,
) -> Result<Option<BackupCredentialEntry>, String> {
    Ok(None)
}

#[cfg(windows)]
fn delete_windows_credential(target_name: &str, cred_type: u32) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Security::Credentials::{CredDeleteW, CRED_TYPE};

    let _imp = crate::access_win::ImpersonateInteractiveUserGuard::enter()?;

    let wide: Vec<u16> = std::ffi::OsStr::new(target_name)
        .encode_wide()
        .chain(Some(0))
        .collect();
    unsafe {
        CredDeleteW(PCWSTR::from_raw(wide.as_ptr()), CRED_TYPE(cred_type), 0)
            .map_err(|e| format!("CredDeleteW 失败：{e}"))
    }
}

#[cfg(not(windows))]
fn delete_windows_credential(_target_name: &str, _cred_type: u32) -> Result<(), String> {
    Ok(())
}

#[cfg(windows)]
fn restore_windows_credential(entry: &BackupCredentialEntry) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PWSTR;
    use windows::Win32::Security::Credentials::{
        CredWriteW, CREDENTIALW, CRED_FLAGS, CRED_PERSIST, CRED_TYPE,
    };

    let _imp = crate::access_win::ImpersonateInteractiveUserGuard::enter()?;

    let mut blob = STANDARD
        .decode(&entry.blob_b64)
        .map_err(|_| "备份凭据 Base64 格式损坏".to_string())?;
    let to_wide = |s: &str| -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(Some(0))
            .collect()
    };

    let mut wide_target = to_wide(&entry.target_name);
    let mut wide_user = entry.user_name.as_deref().map(to_wide);
    let mut wide_comment = entry.comment.as_deref().map(to_wide);
    let mut wide_alias = entry.target_alias.as_deref().map(to_wide);

    let cred = CREDENTIALW {
        Flags: CRED_FLAGS(0),
        Type: CRED_TYPE(entry.cred_type),
        TargetName: PWSTR(wide_target.as_mut_ptr()),
        Comment: wide_comment
            .as_mut()
            .map_or(PWSTR::null(), |v| PWSTR(v.as_mut_ptr())),
        CredentialBlobSize: blob.len() as u32,
        CredentialBlob: if blob.is_empty() {
            core::ptr::null_mut()
        } else {
            blob.as_mut_ptr()
        },
        Persist: CRED_PERSIST(entry.persist),
        TargetAlias: wide_alias
            .as_mut()
            .map_or(PWSTR::null(), |v| PWSTR(v.as_mut_ptr())),
        UserName: wide_user
            .as_mut()
            .map_or(PWSTR::null(), |v| PWSTR(v.as_mut_ptr())),
        ..Default::default()
    };

    unsafe { CredWriteW(&cred, 0).map_err(|e| format!("CredWriteW 还原凭据失败：{e}")) }
}

#[cfg(not(windows))]
fn restore_windows_credential(_entry: &BackupCredentialEntry) -> Result<(), String> {
    Ok(())
}

/// Pure matcher detecting running client processes that could write stale identity state back to disk.
pub fn scan_orphan_processes_from_list(
    scope: &CleanRoomScope,
    procs: &[(u32, String)],
) -> Vec<(u32, String, CleanRoomFinding)> {
    let mut out = Vec::new();
    for (pid, exe_name) in procs {
        let lower = exe_name.trim().to_ascii_lowercase();
        let client_id = if scope.claude && matches!(lower.as_str(), "claude.exe" | "cowork-svc.exe")
        {
            Some("claude")
        } else if scope.chatgpt_codex
            && matches!(
                lower.as_str(),
                "chatgpt.exe" | "chatgpt classic.exe" | "codex.exe"
            )
        {
            Some("chatgpt")
        } else if scope.antigravity
            && matches!(lower.as_str(), "antigravity.exe" | "antigravity ide.exe")
        {
            Some("antigravity")
        } else {
            None
        };

        if let Some(cid) = client_id {
            out.push((
                *pid,
                exe_name.clone(),
                CleanRoomFinding {
                    id: format!("v4:proc:{cid}:{pid}"),
                    client_id: cid.into(),
                    vector: CleanRoomVector::OrphanMemoryProcess,
                    risk_weight: 10,
                    location_display: format!("活跃进程 {exe_name} (PID {pid})"),
                    correlation_keys: vec!["write_back_race".into()],
                    masked_preview: format!("{exe_name} 仍在运行，清理前需关闭以防内存回写旧状态"),
                    bytes_size: 0,
                    preservation_note: "仅关闭所选客户端进程，不触碰用户工程文件".into(),
                },
            ));
        }
    }
    out
}

/// Read-only live scan for Vector 4 active/orphan client processes.
pub fn scan_live_orphan_processes(scope: &CleanRoomScope) -> Vec<CleanRoomFinding> {
    scan_live_orphan_processes_detailed(scope)
        .into_iter()
        .map(|(_, _, f)| f)
        .collect()
}

fn scan_live_orphan_processes_detailed(
    scope: &CleanRoomScope,
) -> Vec<(u32, String, CleanRoomFinding)> {
    let mut sys = sysinfo::System::new();
    sys.refresh_processes_specifics(sysinfo::ProcessRefreshKind::new());
    let procs: Vec<(u32, String)> = sys
        .processes()
        .iter()
        .map(|(pid, p)| (pid.as_u32(), p.name().to_string()))
        .collect();
    scan_orphan_processes_from_list(scope, &procs)
}

/// Executes Clean-Room sanitization with mandatory encrypted `.cgbak` (`CGBAK005`) rollback backup:
/// 1. Builds an in-memory ZIP of every targeted file + credential metadata (never raw plaintext on disk).
/// 2. Seals the ZIP via `crypto_win::seal_cgbak_envelope` into `<data_dir>\CleanRoomBackups\<backup_id>.cgbak`
///    and writes a companion `<backup_id>.meta.json` containing SHA-256 checksum & summary metadata.
/// 3. Terminates targeted live processes (if any), performs atomic surgical sanitization of `.claude.json`,
///    and safely deletes targeted residue files/dirs with full reparse-point checks.
/// 4. Runs a post-clean readback verification scan and returns `(CleanRoomBackupMeta, CleanRoomReport)`.
pub fn execute_cleanroom_with_backup(
    data_dir: &Path,
    scope: &CleanRoomScope,
    selected_ids: &[String],
    user_home: Option<&Path>,
    now_secs: u64,
) -> Result<(CleanRoomBackupMeta, CleanRoomReport), String> {
    ensure_no_reparse_points_chain(data_dir)?;
    let backups_dir = data_dir.join("CleanRoomBackups");
    safe_create_dir_all_no_reparse(&backups_dir)?;
    apply_backup_dir_strict_acl_if_service(&backups_dir);

    let include_host_os = should_query_host_os(user_home);
    let all_planned = collect_cleanroom_plan(scope, user_home, include_host_os);

    let selected_set: BTreeSet<&str> = selected_ids.iter().map(String::as_str).collect();
    let active_plan: Vec<PlannedFinding> = if selected_set.is_empty() {
        all_planned
    } else {
        all_planned
            .into_iter()
            .filter(|p| selected_set.contains(p.finding.id.as_str()))
            .collect()
    };

    // Step 0: Terminate targeted active processes first to eliminate write-back race.
    if include_host_os {
        let mut targets_to_stop = Vec::new();
        for p in &active_plan {
            if let CleanTarget::RunningProcess { pid, exe_name } = &p.target {
                targets_to_stop.push((*pid, exe_name.clone()));
            }
        }
        if !targets_to_stop.is_empty() {
            terminate_verified_pids(&targets_to_stop);
        }
    }

    // Step 1: Collect original bytes & credential snapshots into memory for the encrypted backup ZIP.
    let short_id = crypto_win::random_hex(4)?;
    let backup_id = format!("{now_secs}_{short_id}");

    let mut zip_blobs: Vec<(String, Vec<u8>)> = Vec::new();
    let mut manifest_files = Vec::new();
    let mut manifest_creds = Vec::new();
    let mut clients_included = BTreeSet::new();
    let mut total_uncompressed: usize = 0;
    let mut seen_paths: BTreeSet<PathBuf> = BTreeSet::new();

    for p in &active_plan {
        clients_included.insert(p.finding.client_id.clone());
        match &p.target {
            CleanTarget::SanitizeClaudeJson { path, home_root }
            | CleanTarget::RemoveFile { path, home_root } => {
                collect_file_for_backup(
                    path,
                    home_root,
                    &mut seen_paths,
                    &mut zip_blobs,
                    &mut manifest_files,
                    &mut total_uncompressed,
                )?;
            }
            CleanTarget::RemoveDir { path, home_root } => {
                collect_dir_files_for_backup(
                    path,
                    home_root,
                    &mut seen_paths,
                    &mut zip_blobs,
                    &mut manifest_files,
                    &mut total_uncompressed,
                )?;
            }
            CleanTarget::WindowsCredential {
                target_name,
                cred_type,
            } => {
                if let Some(entry) = read_credential_for_backup(target_name, *cred_type)? {
                    manifest_creds.push(entry);
                }
            }
            CleanTarget::RunningProcess { .. } => {}
        }
    }

    let item_count = manifest_files.len() + manifest_creds.len();
    let manifest = BackupArchiveManifest {
        schema_version: 1,
        backup_id: backup_id.clone(),
        created_at: now_secs,
        files: manifest_files,
        credentials: manifest_creds,
    };
    let manifest_bytes =
        serde_json::to_vec_pretty(&manifest).map_err(|e| format!("序列化净室备份清单失败：{e}"))?;

    let mut entries_ref: Vec<(&str, &[u8])> = Vec::with_capacity(zip_blobs.len() + 1);
    entries_ref.push(("manifest.json", &manifest_bytes));
    for (name, data) in &zip_blobs {
        entries_ref.push((name.as_str(), data.as_slice()));
    }

    let zip_bytes = zip_util::build_zip_archive(&entries_ref)?;
    let sealed_blob = crypto_win::seal_cgbak_envelope(&zip_bytes)?;
    let sha256_hex = crypto_win::sha256_hex(&sealed_blob);

    let cgbak_path = backups_dir.join(format!("{backup_id}.cgbak"));
    atomic_write_no_reparse(&cgbak_path, &sealed_blob)?;

    let meta = CleanRoomBackupMeta {
        backup_id: backup_id.clone(),
        created_at: now_secs,
        file_path: cgbak_path.to_string_lossy().to_string(),
        archive_bytes: sealed_blob.len() as u64,
        item_count,
        sha256_hex,
        clients_included: clients_included.into_iter().collect(),
    };
    let meta_path = backups_dir.join(format!("{backup_id}.meta.json"));
    let meta_bytes =
        serde_json::to_vec_pretty(&meta).map_err(|e| format!("序列化净室备份元数据失败：{e}"))?;
    atomic_write_no_reparse(&meta_path, &meta_bytes)?;

    prune_old_backups(&backups_dir, MAX_RETAINED_BACKUPS);

    // Step 2: Apply surgical sanitization & safe deletions.
    for p in &active_plan {
        match &p.target {
            CleanTarget::SanitizeClaudeJson { path, .. } => {
                sanitize_claude_json_file(path)?;
            }
            CleanTarget::RemoveFile { path, home_root } => {
                safe_remove_under_anchor(home_root, path)?;
            }
            CleanTarget::RemoveDir { path, home_root } => {
                safe_remove_under_anchor(home_root, path)?;
            }
            CleanTarget::WindowsCredential {
                target_name,
                cred_type,
            } => {
                delete_windows_credential(target_name, *cred_type)?;
            }
            CleanTarget::RunningProcess { .. } => {}
        }
    }

    // Step 3: Post-clean readback verification.
    let verified_report = scan_cleanroom(scope, user_home, now_secs);
    Ok((meta, verified_report))
}

fn sanitize_claude_json_file(path: &Path) -> Result<(), String> {
    ensure_no_reparse_points_chain(path)?;
    let raw = std::fs::read(path)
        .map_err(|e| format!("读取 .claude.json 失败（{}）：{e}", path.display()))?;
    let mut val: serde_json::Value = serde_json::from_slice(&raw)
        .map_err(|e| format!("解析 .claude.json 失败（{}）：{e}", path.display()))?;
    sanitize_claude_json_value(&mut val);
    let updated = serde_json::to_vec_pretty(&val)
        .map_err(|e| format!("序列化脱敏后的 .claude.json 失败：{e}"))?;
    atomic_write_no_reparse(path, &updated)
}

/// Ensures `target` is strictly nested under `anchor_root` and contains zero reparse points
/// before safely removing it.
fn safe_remove_under_anchor(anchor_root: &Path, target: &Path) -> Result<(), String> {
    ensure_no_reparse_points_chain(anchor_root)?;
    let rel = target.strip_prefix(anchor_root).map_err(|_| {
        format!(
            "安全拦截：删除目标（{}）超出允许的用户锚点范围（{}）",
            target.display(),
            anchor_root.display()
        )
    })?;
    if rel.as_os_str().is_empty()
        || rel.components().any(|c| {
            matches!(
                c,
                Component::ParentDir | Component::Prefix(_) | Component::RootDir
            )
        })
    {
        return Err(format!("安全拦截：非法相对删除路径（{}）", rel.display()));
    }
    safe_remove_path_no_reparse(target)
}

fn collect_file_for_backup(
    path: &Path,
    home_root: &Path,
    seen: &mut BTreeSet<PathBuf>,
    zip_blobs: &mut Vec<(String, Vec<u8>)>,
    manifest_files: &mut Vec<BackupFileEntry>,
    total_uncompressed: &mut usize,
) -> Result<(), String> {
    if !seen.insert(path.to_path_buf()) {
        return Ok(());
    }
    ensure_no_reparse_points_chain(path)?;
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(format!(
                "读取待备份文件元数据失败（{}）：{e}",
                path.display()
            ))
        }
    };
    if is_reparse_or_symlink(&meta) || !meta.is_file() {
        return Ok(());
    }
    if meta.len() > MAX_SINGLE_BACKUP_FILE_BYTES {
        return Ok(());
    }
    let data = std::fs::read(path)
        .map_err(|e| format!("读取待备份文件失败（{}）：{e}", path.display()))?;
    if total_uncompressed.saturating_add(data.len()) > MAX_BACKUP_UNCOMPRESSED_BYTES {
        return Ok(());
    }
    let rel = path
        .strip_prefix(home_root)
        .map_err(|_| format!("备份文件不在用户根目录下：{}", path.display()))?;
    let idx = manifest_files.len() + 1;
    let zip_entry = format!("files/{idx:05}.bin");
    *total_uncompressed = total_uncompressed.saturating_add(data.len());
    manifest_files.push(BackupFileEntry {
        zip_entry: zip_entry.clone(),
        anchor_root: home_root.to_string_lossy().to_string(),
        rel_path: rel.to_string_lossy().replace('\\', "/"),
        original_bytes: data.len() as u64,
    });
    zip_blobs.push((zip_entry, data));
    Ok(())
}

fn collect_dir_files_for_backup(
    dir: &Path,
    home_root: &Path,
    seen: &mut BTreeSet<PathBuf>,
    zip_blobs: &mut Vec<(String, Vec<u8>)>,
    manifest_files: &mut Vec<BackupFileEntry>,
    total_uncompressed: &mut usize,
) -> Result<(), String> {
    if ensure_no_reparse_points_chain(dir).is_err() {
        return Ok(());
    }
    let mut stack = vec![dir.to_path_buf()];
    while let Some(cur) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&cur) else {
            continue;
        };
        let mut children: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
        children.sort();
        for child in children {
            let Ok(meta) = std::fs::symlink_metadata(&child) else {
                continue;
            };
            if is_reparse_or_symlink(&meta) {
                continue;
            }
            if meta.is_dir() {
                stack.push(child);
            } else if meta.is_file() {
                collect_file_for_backup(
                    &child,
                    home_root,
                    seen,
                    zip_blobs,
                    manifest_files,
                    total_uncompressed,
                )?;
            }
        }
    }
    Ok(())
}

/// Lists all encrypted clean-room backups under `<data_dir>\CleanRoomBackups`, sorted newest-first.
pub fn list_cleanroom_backups(data_dir: &Path) -> Vec<CleanRoomBackupMeta> {
    let backups_dir = data_dir.join("CleanRoomBackups");
    if !backups_dir.is_dir() || ensure_no_reparse_points_chain(&backups_dir).is_err() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(&backups_dir) else {
        return out;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !name.ends_with(".meta.json") || !is_safe_existing_file(&p) {
            continue;
        }
        let Ok(raw) = std::fs::read(&p) else {
            continue;
        };
        let Ok(meta) = serde_json::from_slice::<CleanRoomBackupMeta>(&raw) else {
            continue;
        };
        if !is_valid_backup_id(&meta.backup_id) {
            continue;
        }
        let cgbak = backups_dir.join(format!("{}.cgbak", meta.backup_id));
        if is_safe_existing_file(&cgbak) {
            out.push(meta);
        }
    }
    out.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then_with(|| b.backup_id.cmp(&a.backup_id))
    });
    out
}

/// Decrypts `<data_dir>\CleanRoomBackups\<backup_id>.cgbak` (`CGBAK005`) and safely restores every
/// backed-up file (with full reparse-point & traversal protection) and Windows credential entry.
///
/// Returns the total number of restored files and credentials.
pub fn restore_cleanroom_backup(data_dir: &Path, backup_id: &str) -> Result<usize, String> {
    if !is_valid_backup_id(backup_id) {
        return Err(format!("非法的净室备份 ID：`{backup_id}`"));
    }
    ensure_no_reparse_points_chain(data_dir)?;
    let backups_dir = data_dir.join("CleanRoomBackups");
    ensure_no_reparse_points_chain(&backups_dir)?;

    let cgbak_path = backups_dir.join(format!("{backup_id}.cgbak"));
    ensure_no_reparse_points_chain(&cgbak_path)?;
    let blob = std::fs::read(&cgbak_path)
        .map_err(|e| format!("读取净室备份包失败（{}）：{e}", cgbak_path.display()))?;

    // Verify SHA-256 against companion metadata if present.
    let meta_path = backups_dir.join(format!("{backup_id}.meta.json"));
    if is_safe_existing_file(&meta_path) {
        if let Ok(raw_meta) = std::fs::read(&meta_path) {
            if let Ok(meta) = serde_json::from_slice::<CleanRoomBackupMeta>(&raw_meta) {
                if !meta.sha256_hex.is_empty() {
                    let actual = crypto_win::sha256_hex(&blob);
                    if !actual.eq_ignore_ascii_case(&meta.sha256_hex) {
                        return Err(format!(
                            "备份包完整性校验失败（SHA-256 不匹配）：{backup_id}"
                        ));
                    }
                }
            }
        }
    }

    let zip_bytes = crypto_win::open_cgbak_envelope(&blob)?;
    let (_mname, manifest_bytes) = zip_util::extract_file_from_zip(&zip_bytes, "manifest.json")?;
    let manifest: BackupArchiveManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| format!("解析备份包 manifest.json 失败：{e}"))?;

    let allowed_roots = build_allowed_restore_roots(data_dir);
    let mut restored_count = 0usize;
    let mut restored_anchors: BTreeMap<String, PathBuf> = BTreeMap::new();

    for entry in &manifest.files {
        let anchor = if let Some(cached) = restored_anchors.get(&entry.anchor_root) {
            cached.clone()
        } else {
            let validated = validate_allowed_restore_anchor(
                Path::new(&entry.anchor_root),
                data_dir,
                &allowed_roots,
            )?;
            restored_anchors.insert(entry.anchor_root.clone(), validated.clone());
            validated
        };

        let rel = validate_safe_rel_path(&entry.rel_path)?;
        validate_allowed_cleanroom_rel_path(&rel)?;
        let target = anchor.join(&rel);
        ensure_no_reparse_points_chain(&target)?;

        let (_ename, payload) = zip_util::extract_file_from_zip(&zip_bytes, &entry.zip_entry)?;
        atomic_write_no_reparse(&target, &payload)?;
        restored_count += 1;
    }

    for cred in &manifest.credentials {
        restore_windows_credential(cred)?;
        restored_count += 1;
    }

    Ok(restored_count)
}

fn normalize_canonical_key(path: &Path) -> String {
    let resolved = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let raw = resolved.to_string_lossy();
    let stripped = crate::process_win::strip_verbatim_win32_str(&raw);
    stripped
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

fn build_allowed_restore_roots(data_dir: &Path) -> Vec<String> {
    let mut roots = Vec::new();
    let mut push_root = |p: &Path| {
        let k = normalize_canonical_key(p);
        if !k.is_empty() && !roots.contains(&k) {
            roots.push(k);
        }
    };

    for home in crate::process_win::user_home_dirs() {
        push_root(&home);
    }
    if !crate::access_win::is_session_zero() {
        if let Some(up) = std::env::var_os("USERPROFILE").map(PathBuf::from) {
            push_root(&up);
        }
        push_root(&std::env::temp_dir());
    }

    // Support isolated unit-test sandboxes (`<sandbox>/cg_data` + `<sandbox>/user_home`) when
    // `data_dir` itself is outside `%ProgramData%` and system roots.
    let pd_key = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    let pd_norm = normalize_canonical_key(&pd_key);
    let data_norm = normalize_canonical_key(data_dir);
    if !pd_norm.is_empty()
        && data_norm != pd_norm
        && !data_norm.starts_with(&format!(r"{pd_norm}\"))
    {
        if let Some(sandbox_parent) = data_dir.parent() {
            if sandbox_parent.parent().is_some() {
                push_root(sandbox_parent);
            }
        }
    }
    roots
}

fn validate_allowed_restore_anchor(
    raw_anchor: &Path,
    data_dir: &Path,
    allowed_roots: &[String],
) -> Result<PathBuf, String> {
    ensure_no_reparse_points_chain(raw_anchor)?;
    if !raw_anchor.is_dir() {
        return Err(format!(
            "安全拦截：还原锚点目录不存在或无效（{}）",
            raw_anchor.display()
        ));
    }
    let anchor_norm = normalize_canonical_key(raw_anchor);
    if anchor_norm.is_empty() {
        return Err("安全拦截：还原锚点路径为空".into());
    }

    // Explicitly forbid system/service directories regardless of environment variables.
    let mut forbidden = vec![
        normalize_canonical_key(data_dir),
        r"c:\windows".to_string(),
        r"c:\program files".to_string(),
        r"c:\program files (x86)".to_string(),
        r"c:\programdata".to_string(),
    ];
    for env_k in [
        "SystemRoot",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramData",
    ] {
        if let Some(val) = std::env::var_os(env_k) {
            let k = normalize_canonical_key(Path::new(&val));
            if !k.is_empty() && !forbidden.contains(&k) {
                forbidden.push(k);
            }
        }
    }
    for bad in &forbidden {
        if !bad.is_empty() && (anchor_norm == *bad || anchor_norm.starts_with(&format!(r"{bad}\")))
        {
            return Err(format!(
                "安全拦截：拒绝向受保护系统或服务目录还原文件（{}）",
                raw_anchor.display()
            ));
        }
    }

    let is_allowed = allowed_roots
        .iter()
        .any(|root| anchor_norm == *root || anchor_norm.starts_with(&format!(r"{root}\")));
    if !is_allowed {
        return Err(format!(
            "安全拦截：备份清单锚点超出允许的用户主目录范围（{}）",
            raw_anchor.display()
        ));
    }

    Ok(raw_anchor.to_path_buf())
}

fn validate_allowed_cleanroom_rel_path(rel: &Path) -> Result<(), String> {
    let norm = rel
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let allowed = norm == ".claude.json"
        || norm.starts_with(".claude.json.backup")
        || norm.starts_with(".claude.json.tmp")
        || norm.starts_with(".claude/")
        || norm.starts_with("appdata/roaming/claude/")
        || norm.starts_with("appdata/roaming/chatgpt/")
        || norm.starts_with("appdata/roaming/antigravity/")
        || (norm.starts_with("appdata/local/packages/")
            && (norm.contains("/localcache/roaming/claude/")
                || norm.contains("/localcache/roaming/chatgpt/")));
    if !allowed {
        return Err(format!(
            "安全拦截：备份条目超出净室客户端状态白名单路径（{}）",
            rel.display()
        ));
    }
    Ok(())
}

fn is_valid_backup_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn validate_safe_rel_path(raw: &str) -> Result<PathBuf, String> {
    if raw.trim().is_empty() || raw.contains('\0') {
        return Err("备份清单包含空的相对路径".into());
    }
    let mut out = PathBuf::new();
    for seg in raw.split(['/', '\\']) {
        if seg.is_empty() || seg == "." || seg == ".." || seg.contains(':') {
            return Err(format!("安全拦截：备份清单包含非法路径段 `{raw}`"));
        }
        out.push(seg);
    }
    if out.as_os_str().is_empty() {
        return Err(format!("安全拦截：备份清单相对路径无效 `{raw}`"));
    }
    Ok(out)
}

fn prune_old_backups(backups_dir: &Path, keep: usize) {
    let mut metas = Vec::new();
    let Ok(rd) = std::fs::read_dir(backups_dir) else {
        return;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !name.ends_with(".meta.json") || !is_safe_existing_file(&p) {
            continue;
        }
        if let Ok(raw) = std::fs::read(&p) {
            if let Ok(meta) = serde_json::from_slice::<CleanRoomBackupMeta>(&raw) {
                if is_valid_backup_id(&meta.backup_id) {
                    metas.push(meta);
                }
            }
        }
    }
    metas.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then_with(|| b.backup_id.cmp(&a.backup_id))
    });
    for old in metas.into_iter().skip(keep) {
        let cgbak = backups_dir.join(format!("{}.cgbak", old.backup_id));
        let meta_file = backups_dir.join(format!("{}.meta.json", old.backup_id));
        let _ = safe_remove_path_no_reparse(&cgbak);
        let _ = safe_remove_path_no_reparse(&meta_file);
    }
}

fn terminate_verified_pids(targets: &[(u32, String)]) {
    let mut sys = sysinfo::System::new();
    sys.refresh_processes_specifics(sysinfo::ProcessRefreshKind::new());
    for (pid, expected_exe) in targets {
        if let Some(proc_) = sys.process(sysinfo::Pid::from_u32(*pid)) {
            if proc_.name().eq_ignore_ascii_case(expected_exe) {
                let _ = proc_.kill();
            }
        }
    }
}

fn is_safe_existing_file(path: &Path) -> bool {
    if ensure_no_reparse_points_chain(path).is_err() {
        return false;
    }
    std::fs::symlink_metadata(path)
        .map(|m| !is_reparse_or_symlink(&m) && m.is_file())
        .unwrap_or(false)
}

fn is_safe_non_empty_dir(path: &Path) -> bool {
    if ensure_no_reparse_points_chain(path).is_err() {
        return false;
    }
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if is_reparse_or_symlink(&meta) || !meta.is_dir() {
        return false;
    }
    std::fs::read_dir(path)
        .map(|mut rd| rd.next().is_some())
        .unwrap_or(false)
}

fn file_or_dir_bytes(path: &Path) -> u64 {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return 0;
    };
    if is_reparse_or_symlink(&meta) {
        return 0;
    }
    if meta.is_file() {
        return meta.len();
    }
    let mut total = 0u64;
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            let p = entry.path();
            let Ok(cm) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            if is_reparse_or_symlink(&cm) {
                continue;
            }
            if cm.is_dir() {
                stack.push(p);
            } else if cm.is_file() {
                total = total.saturating_add(cm.len());
            }
        }
    }
    total
}

/// Restricts `<data_dir>\CleanRoomBackups` ACL to `SYSTEM` + `Administrators` when running as
/// the Session-0 Windows Service (`D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`).
#[cfg(windows)]
fn apply_backup_dir_strict_acl_if_service(dir: &Path) {
    use core::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::{w, PWSTR};
    use windows::Win32::Foundation::{LocalFree, BOOL, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW,
        SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    };

    if !crate::access_win::is_session_zero() && !crate::access_win::is_elevated().unwrap_or(false) {
        return;
    }

    struct SdGuard(PSECURITY_DESCRIPTOR);
    impl Drop for SdGuard {
        fn drop(&mut self) {
            if !self.0 .0.is_null() {
                unsafe {
                    let _ = LocalFree(HLOCAL(self.0 .0.cast::<c_void>()));
                }
            }
        }
    }

    unsafe {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            w!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )
        .is_err()
        {
            return;
        }
        let _sd_guard = SdGuard(sd);

        let mut dacl_present = BOOL(0);
        let mut dacl_ptr: *mut ACL = core::ptr::null_mut();
        let mut dacl_defaulted = BOOL(0);
        if GetSecurityDescriptorDacl(sd, &mut dacl_present, &mut dacl_ptr, &mut dacl_defaulted)
            .is_err()
            || !dacl_present.as_bool()
        {
            return;
        }

        let mut wide: Vec<u16> = dir.as_os_str().encode_wide().chain(Some(0)).collect();
        let _ = SetNamedSecurityInfoW(
            PWSTR(wide.as_mut_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl_ptr.cast_const()),
            None,
        );
    }
}

#[cfg(not(windows))]
fn apply_backup_dir_strict_acl_if_service(_dir: &Path) {}

/// Converts Unix epoch seconds to an ISO-8601 UTC timestamp (`YYYY-MM-DDTHH:MM:SS.000Z`)
/// using Howard Hinnant's civil-from-days algorithm (zero external time crate).
fn format_unix_iso8601(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let rem = unix_secs % 86_400;
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + i64::from(m <= 2);

    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}.000Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_sandbox(tag: &str) -> PathBuf {
        let nonce = crypto_win::random_hex(6).unwrap_or_else(|_| "aabbcc".into());
        let dir = std::env::temp_dir().join(format!("cg-cleanroom-test-{tag}-{nonce}"));
        std::fs::create_dir_all(&dir).expect("create sandbox");
        dir
    }

    #[test]
    fn sanitize_claude_json_strips_identity_rotates_anon_and_preserves_mcp_assets() {
        let mut val = serde_json::json!({
            "userID": "user_01J9SECRETACCOUNT8K2P",
            "anonymousId": "11111111-1111-4111-8111-111111111111",
            "oauthAccount": {
                "accountUuid": "acct-secret-uuid",
                "emailAddress": "banned-user@example.com",
                "organizationUuid": "org-secret-uuid"
            },
            "cachedStatsigGates": { "tengu_gate": true },
            "cachedDynamicConfigs": { "cfg": 1 },
            "cachedGrowthBookFeatures": { "gb_flag": "on" },
            "firstStartTime": "2024-01-01T00:00:00.000Z",
            "theme": "dark",
            "hasCompletedOnboarding": true,
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem"]
                }
            },
            "projects": {
                "C:\\dev\\my-app": {
                    "allowedTools": ["Bash", "Edit"],
                    "lastSessionId": "old-session-abc",
                    "lastCost": 1.25
                }
            }
        });

        let modified = sanitize_claude_json_value(&mut val);
        assert!(modified.contains(&"userID".to_string()));
        assert!(modified.contains(&"oauthAccount".to_string()));
        assert!(modified.contains(&"cachedStatsigGates".to_string()));
        assert!(modified.contains(&"cachedGrowthBookFeatures".to_string()));
        assert!(modified.contains(&"anonymousId".to_string()));

        let obj = val.as_object().unwrap();
        assert!(!obj.contains_key("userID"));
        assert!(!obj.contains_key("oauthAccount"));
        assert!(!obj.contains_key("cachedStatsigGates"));
        assert!(!obj.contains_key("cachedDynamicConfigs"));
        assert!(!obj.contains_key("cachedGrowthBookFeatures"));

        // `anonymousId` must be rotated to a new non-empty UUIDv4.
        let new_anon = obj["anonymousId"].as_str().unwrap();
        assert_ne!(new_anon, "11111111-1111-4111-8111-111111111111");
        assert_eq!(new_anon.len(), 36);

        // User assets must remain 100% intact.
        assert_eq!(obj["theme"], "dark");
        assert_eq!(obj["hasCompletedOnboarding"], true);
        assert_eq!(obj["mcpServers"]["filesystem"]["command"], "npx");
        assert_eq!(
            obj["projects"]["C:\\dev\\my-app"]["allowedTools"][0],
            "Bash"
        );
        assert!(obj["projects"]["C:\\dev\\my-app"]
            .as_object()
            .unwrap()
            .get("lastSessionId")
            .is_none());
    }

    #[test]
    fn credential_and_process_matchers_and_masking_never_leak_raw_secrets() {
        let scope = CleanRoomScope::default();
        assert_eq!(
            match_credential_target_client("Claude Safe Storage", &scope),
            Some("claude")
        );
        assert_eq!(
            match_credential_target_client("Anthropic OAuth Token", &scope),
            Some("claude")
        );
        assert_eq!(
            match_credential_target_client("git:https://github.com", &scope),
            None
        );

        let masked = mask_identifier("user_01J9ABCDEF8K2P");
        assert!(!masked.contains("ABCDEF"));
        assert!(masked.contains("****"));
        assert_eq!(mask_email("alice@gmail.com"), "a***@gmail.com");

        let procs = vec![
            (1001, "claude.exe".into()),
            (1002, "cowork-svc.exe".into()),
            (1003, "notepad.exe".into()),
        ];
        let matched = scan_orphan_processes_from_list(&scope, &procs);
        assert_eq!(matched.len(), 2);
        assert!(matched
            .iter()
            .all(|(_, _, f)| f.vector == CleanRoomVector::OrphanMemoryProcess));
    }

    #[cfg(windows)]
    #[test]
    fn full_scan_encrypted_backup_sanitize_verify_clean_and_restore_lifecycle() {
        let sandbox = temp_sandbox("lifecycle");
        let fake_home = sandbox.join("user_home");
        let data_dir = sandbox.join("cg_data");
        std::fs::create_dir_all(&fake_home).unwrap();
        std::fs::create_dir_all(&data_dir).unwrap();

        // Seed Vector 1: ~/.claude.json, ~/.claude/telemetry, ~/.claude/CLAUDE.md (must be preserved!)
        let claude_json_path = fake_home.join(".claude.json");
        let original_claude_json = serde_json::json!({
            "userID": "user_01J9BANNED9999",
            "anonymousId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "oauthAccount": {
                "accountUuid": "acct-999",
                "emailAddress": "secret.dev@gmail.com"
            },
            "cachedStatsigGates": { "gate_a": true },
            "cachedGrowthBookFeatures": { "flag_b": 42 },
            "firstStartTime": "2024-06-01T12:00:00.000Z",
            "mcpServers": {
                "github": { "command": "npx", "args": ["mcp-github"] }
            },
            "theme": "light"
        });
        std::fs::write(
            &claude_json_path,
            serde_json::to_vec_pretty(&original_claude_json).unwrap(),
        )
        .unwrap();

        let claude_dir = fake_home.join(".claude");
        std::fs::create_dir_all(claude_dir.join("telemetry")).unwrap();
        std::fs::write(
            claude_dir.join("telemetry").join("batch_01.json"),
            br#"{"sessionId":"old-session"}"#,
        )
        .unwrap();
        std::fs::write(claude_dir.join("CLAUDE.md"), b"# My Precious Rules").unwrap();
        std::fs::write(claude_dir.join("settings.json"), br#"{"hooks":{}}"#).unwrap();

        // Seed Vector 2: Standard %APPDATA%\Claude AND MSIX LocalCache + preserved claude_desktop_config.json
        let desktop_root = fake_home.join("AppData").join("Roaming").join("Claude");
        std::fs::create_dir_all(desktop_root.join("Network")).unwrap();
        std::fs::create_dir_all(desktop_root.join("Crashpad").join("reports")).unwrap();
        std::fs::create_dir_all(desktop_root.join("Sentry")).unwrap();
        std::fs::write(
            desktop_root.join("Network").join("Cookies"),
            b"SQLite-cookie-blob",
        )
        .unwrap();
        std::fs::write(
            desktop_root
                .join("Crashpad")
                .join("reports")
                .join("dump.dmp"),
            b"MINIDUMP-old-ip",
        )
        .unwrap();
        std::fs::write(
            desktop_root.join("Sentry").join("event.envelope"),
            b"sentry-old-user",
        )
        .unwrap();
        std::fs::write(
            desktop_root.join("claude_desktop_config.json"),
            br#"{"mcpServers":{"local":{}}}"#,
        )
        .unwrap();

        let msix_root = fake_home
            .join("AppData")
            .join("Local")
            .join("Packages")
            .join("Claude_pzs8sxrjxfjjc")
            .join("LocalCache")
            .join("Roaming")
            .join("Claude");
        std::fs::create_dir_all(msix_root.join("Local Storage").join("leveldb")).unwrap();
        std::fs::write(
            msix_root
                .join("Local Storage")
                .join("leveldb")
                .join("000003.log"),
            b"msix-session-data",
        )
        .unwrap();

        let scope = CleanRoomScope::default();
        let now = 1_735_000_000u64;

        // 1. Read-only scan
        let pre = scan_cleanroom(&scope, Some(&fake_home), now);
        assert!(
            pre.pollution_score >= 60,
            "expected critical contamination score, got {}",
            pre.pollution_score
        );
        assert_eq!(pre.risk_level, CleanRoomRiskLevel::CriticalChainBanRisk);
        assert!(!pre.findings.is_empty());
        // Verify zero raw email / userID leaked in previews!
        for f in &pre.findings {
            assert!(!f.masked_preview.contains("user_01J9BANNED9999"));
            assert!(!f.masked_preview.contains("secret.dev@gmail.com"));
        }
        let cc_finding = pre
            .findings
            .iter()
            .find(|f| f.id == "v1:claude:claude_json")
            .expect("claude.json finding");
        assert_eq!(cc_finding.preservation_note, CLAUDE_CODE_PRESERVATION_NOTE);

        // 2. Execute clean-room with encrypted .cgbak backup
        let (backup_meta, post) =
            execute_cleanroom_with_backup(&data_dir, &scope, &[], Some(&fake_home), now)
                .expect("execute cleanroom");
        assert_eq!(post.pollution_score, 0, "post-clean score must be 0");
        assert_eq!(post.risk_level, CleanRoomRiskLevel::Clean);
        assert!(post.findings.is_empty());
        assert!(backup_meta.item_count >= 5);
        assert!(Path::new(&backup_meta.file_path).is_file());

        // Verify raw .cgbak starts with CGBAK005 and does NOT leak plaintext secret strings!
        let cgbak_raw = std::fs::read(&backup_meta.file_path).unwrap();
        assert!(cgbak_raw.starts_with(crypto_win::CGBAK_MAGIC));
        assert!(!cgbak_raw
            .windows(b"secret.dev@gmail.com".len())
            .any(|w| w == b"secret.dev@gmail.com"));

        // Verify user assets were 100% preserved!
        assert_eq!(
            std::fs::read_to_string(claude_dir.join("CLAUDE.md")).unwrap(),
            "# My Precious Rules"
        );
        assert_eq!(
            std::fs::read_to_string(desktop_root.join("claude_desktop_config.json")).unwrap(),
            r#"{"mcpServers":{"local":{}}}"#
        );
        let sanitized_val: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&claude_json_path).unwrap()).unwrap();
        assert_eq!(sanitized_val["mcpServers"]["github"]["command"], "npx");
        assert!(sanitized_val.get("userID").is_none());
        assert!(sanitized_val.get("oauthAccount").is_none());
        assert!(!desktop_root.join("Network").join("Cookies").exists());
        assert!(!msix_root.join("Local Storage").join("leveldb").exists());

        // 3. List backups
        let listed = list_cleanroom_backups(&data_dir);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].backup_id, backup_meta.backup_id);

        // 4. Restore from encrypted .cgbak backup & verify full recovery!
        let restored =
            restore_cleanroom_backup(&data_dir, &backup_meta.backup_id).expect("restore backup");
        assert_eq!(restored, backup_meta.item_count);
        let restored_val: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&claude_json_path).unwrap()).unwrap();
        assert_eq!(restored_val["userID"], "user_01J9BANNED9999");
        assert_eq!(
            std::fs::read(desktop_root.join("Network").join("Cookies")).unwrap(),
            b"SQLite-cookie-blob"
        );
        assert_eq!(
            std::fs::read(
                msix_root
                    .join("Local Storage")
                    .join("leveldb")
                    .join("000003.log")
            )
            .unwrap(),
            b"msix-session-data"
        );

        // Path traversal backup_id must be rejected.
        assert!(restore_cleanroom_backup(&data_dir, "../evil").is_err());

        // Tampering with the encrypted .cgbak blob must be rejected on restore.
        let mut tampered = std::fs::read(&backup_meta.file_path).unwrap();
        if let Some(last) = tampered.last_mut() {
            *last ^= 0xAA;
        }
        std::fs::write(&backup_meta.file_path, &tampered).unwrap();
        assert!(restore_cleanroom_backup(&data_dir, &backup_meta.backup_id).is_err());

        // System/service anchor_root and non-cleanroom relative paths (e.g. Startup) must be rejected.
        let allowed_roots = build_allowed_restore_roots(&data_dir);
        assert!(validate_allowed_restore_anchor(
            Path::new(r"C:\Windows\System32"),
            &data_dir,
            &allowed_roots
        )
        .is_err());
        assert!(validate_allowed_restore_anchor(&data_dir, &data_dir, &allowed_roots).is_err());
        assert!(validate_allowed_cleanroom_rel_path(Path::new(
            "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/evil.exe"
        ))
        .is_err());
        assert!(validate_allowed_cleanroom_rel_path(Path::new(".ssh/authorized_keys")).is_err());

        // Read-only credential enumeration must succeed safely without exposing raw secrets.
        let _creds = enumerate_matching_credentials(&scope);

        let _ = std::fs::remove_dir_all(&sandbox);
    }
}
