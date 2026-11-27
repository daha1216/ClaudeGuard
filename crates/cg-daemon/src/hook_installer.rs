//! M6: Idempotent CLI Hook (`~/.claude/settings.json`), Sovereign Vault hook, and
//! PowerShell `$PROFILE` wrapper installer/uninstaller.
//!
//! Safety invariants:
//! - Preserves ALL existing user JSON keys and hook entries in `settings.json`.
//! - If an existing `settings.json` contains invalid JSON syntax, aborts immediately
//!   with an actionable error — NEVER overwrites a user file with an empty object.
//! - Rejects NTFS junctions/symlinks along every ancestor path before writing.
//! - Saves a `.cg-bak` backup before mutating existing user files and writes atomically.

use std::io::Write;
use std::path::{Path, PathBuf};

use cg_platform::vault_win;
use cg_protocol::{AccountVault, HookFailMode, HookIntegrationStatus};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tempfile::NamedTempFile;

/// Non-secret user-readable offline hook policy file written under `<user_home>` so non-elevated
/// `claudeguard-cli --hook-gate` honors `FailOpenWithWarn` and `Disarmed` when the service is offline.
pub const HOOK_POLICY_FILE: &str = ".claudeguard-hook-policy.json";

/// Public, credential-free offline hook policy mirrored for non-admin CLI processes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicHookPolicy {
    pub hook_fail_mode: HookFailMode,
    pub disarmed: bool,
}

/// Primary start marker injected into PowerShell `$PROFILE`.
pub const PWSH_BLOCK_START: &str = "# >>> ClaudeGuard v5 Hook >>>";
/// Primary end marker injected into PowerShell `$PROFILE`.
pub const PWSH_BLOCK_END: &str = "# <<< ClaudeGuard v5 Hook <<<";

/// Legacy/alternate spec markers recognized cleanly when upgrading or stripping blocks.
const ALT_PWSH_BLOCK_START: &str = "# >>> ClaudeGuard v5 CLI Shield >>>";
const ALT_PWSH_BLOCK_END: &str = "# <<< ClaudeGuard v5 CLI Shield <<<";

/// Resolves the `claudeguard-cli.exe` path adjacent to the current executable, falling back
/// to the standard install path `C:\Program Files\ClaudeGuard\claudeguard-cli.exe`.
pub fn resolve_cli_exe_path() -> PathBuf {
    if let Ok(cur) = std::env::current_exe() {
        if let Some(dir) = cur.parent() {
            let sibling = dir.join("claudeguard-cli.exe");
            if sibling.is_file() {
                return sibling;
            }
            let sibling_unix = dir.join("claudeguard-cli");
            if sibling_unix.is_file() {
                return sibling_unix;
            }
        }
    }
    PathBuf::from(r"C:\Program Files\ClaudeGuard\claudeguard-cli.exe")
}

/// Resolves the active interactive user's home directory (Session-0 safe).
pub fn resolve_interactive_user_home() -> Option<PathBuf> {
    cg_platform::process_win::user_home_dirs()
        .into_iter()
        .next()
        .or_else(|| {
            std::env::var_os("USERPROFILE")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        })
}

/// Resolves a `User Shell Folders\Personal` registry value (supporting OneDrive Known Folder Move
/// such as `%USERPROFILE%\OneDrive\Documents` or an explicit path under `user_home`), falling back
/// cleanly to `user_home\Documents` when absent, outside `user_home`, or containing `..`.
pub fn resolve_documents_dir_from_personal(
    user_home: &Path,
    personal_raw: Option<&str>,
) -> PathBuf {
    let fallback = user_home.join("Documents");
    let Some(raw) = personal_raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return fallback;
    };
    if raw.contains("..") {
        return fallback;
    }

    let norm_raw = raw.replace('/', "\\");
    let home_norm = user_home
        .to_string_lossy()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_string();

    let rel_opt = if norm_raw.len() > "%USERPROFILE%\\".len()
        && norm_raw[.."%USERPROFILE%\\".len()].eq_ignore_ascii_case("%USERPROFILE%\\")
    {
        Some(&norm_raw["%USERPROFILE%\\".len()..])
    } else if norm_raw.len() > home_norm.len() + 1
        && norm_raw[..home_norm.len()].eq_ignore_ascii_case(&home_norm)
        && norm_raw.as_bytes()[home_norm.len()] == b'\\'
    {
        Some(&norm_raw[home_norm.len() + 1..])
    } else {
        None
    };

    if let Some(rel) = rel_opt
        .map(|r| r.trim_matches('\\'))
        .filter(|r| !r.is_empty())
    {
        let first_seg = rel.split('\\').next().unwrap_or("");
        if first_seg.eq_ignore_ascii_case("Documents") || user_home.join(first_seg).is_dir() {
            let candidate = user_home.join(rel);
            if vault_win::ensure_no_reparse_points_chain(&candidate).is_ok() {
                return candidate;
            }
        }
    }
    fallback
}

#[cfg(windows)]
fn read_interactive_personal_folder_raw(user_home: &Path) -> Option<String> {
    let active_home = resolve_interactive_user_home()?;
    let a = active_home
        .to_string_lossy()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase();
    let b = user_home
        .to_string_lossy()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase();
    if a != b {
        return None;
    }
    let key = cg_platform::access_win::open_interactive_user_subkey(
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
    )?;
    key.get_value::<String, _>("Personal").ok()
}

#[cfg(not(windows))]
fn read_interactive_personal_folder_raw(_user_home: &Path) -> Option<String> {
    None
}

/// Returns the default PowerShell 7 `$PROFILE.CurrentUserAllHosts` path under `user_home`
/// (honoring Windows OneDrive Known Folder Redirection when active).
pub fn default_pwsh_profile_path(user_home: &Path) -> PathBuf {
    let raw_personal = read_interactive_personal_folder_raw(user_home);
    resolve_documents_dir_from_personal(user_home, raw_personal.as_deref())
        .join("PowerShell")
        .join("profile.ps1")
}

/// Returns the default Claude Code `settings.json` path under `user_home`.
pub fn default_claude_settings_path(user_home: &Path) -> PathBuf {
    user_home.join(".claude").join("settings.json")
}

/// Returns true if a hook command string is managed by ClaudeGuard.
pub fn is_claudeguard_hook_command(cmd: &str) -> bool {
    let low = cmd.to_ascii_lowercase();
    low.contains("claudeguard-cli") && low.contains("--hook-gate")
}

fn entry_is_claudeguard_managed(entry: &Value) -> bool {
    if let Some(cmd) = entry.get("command").and_then(Value::as_str) {
        if is_claudeguard_hook_command(cmd) {
            return true;
        }
    }
    if let Some(hooks) = entry.get("hooks").and_then(Value::as_array) {
        if !hooks.is_empty()
            && hooks.iter().all(|h| {
                h.get("command")
                    .and_then(Value::as_str)
                    .is_some_and(is_claudeguard_hook_command)
            })
        {
            return true;
        }
    }
    false
}

fn build_hook_command(cli_exe: &Path, vault_id: Option<&str>, event_flag: Option<&str>) -> String {
    let exe_str = cli_exe.to_string_lossy().replace('"', "");
    let mut cmd = format!("\"{exe_str}\" --hook-gate --agent claude-code");
    if let Some(ev) = event_flag.map(str::trim).filter(|s| !s.is_empty()) {
        cmd.push_str(" --hook-event ");
        cmd.push_str(ev);
    }
    if let Some(vid) = vault_id.map(str::trim).filter(|s| !s.is_empty()) {
        cmd.push_str(" --vault ");
        cmd.push_str(vid);
    }
    cmd
}

/// Pure JSON merger updating `hooks.UserPromptSubmit` and `hooks.PreToolUse` idempotently
/// while preserving every other JSON key and existing user hook entry.
pub fn merge_claude_settings_value(
    root: &mut Value,
    cli_exe: &Path,
    vault_id: Option<&str>,
    install: bool,
) -> Result<(), String> {
    let obj = root
        .as_object_mut()
        .ok_or_else(|| "settings.json 根节点必须为 JSON 对象".to_string())?;

    if install && !obj.contains_key("$schema") {
        obj.insert(
            "$schema".into(),
            Value::String("https://json.schemastore.org/claude-code-settings.json".into()),
        );
    }

    if !install && !obj.contains_key("hooks") {
        return Ok(());
    }

    let hooks_val = obj
        .entry("hooks".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    let hooks_obj = hooks_val
        .as_object_mut()
        .ok_or_else(|| "settings.json 中的 `hooks` 字段必须为 JSON 对象".to_string())?;

    let prompt_cmd = build_hook_command(cli_exe, vault_id, None);
    let pre_tool_cmd = build_hook_command(cli_exe, vault_id, Some("pre-tool"));

    let desired_prompt = json!({
        "matcher": "",
        "hooks": [
            {
                "type": "command",
                "command": prompt_cmd,
                "timeout": 8
            }
        ]
    });
    let desired_pre_tool = json!({
        "matcher": "WebFetch|WebSearch|Bash",
        "hooks": [
            {
                "type": "command",
                "command": pre_tool_cmd,
                "timeout": 5
            }
        ]
    });

    for (event_key, desired_entry) in [
        ("UserPromptSubmit", desired_prompt),
        ("PreToolUse", desired_pre_tool),
    ] {
        if !install && !hooks_obj.contains_key(event_key) {
            continue;
        }
        let arr_val = hooks_obj
            .entry(event_key.to_string())
            .or_insert_with(|| Value::Array(Vec::new()));
        let arr = arr_val
            .as_array_mut()
            .ok_or_else(|| format!("settings.json 中的 `hooks.{event_key}` 必须为 JSON 数组"))?;

        // Strip previous ClaudeGuard entries while preserving all user-defined hooks intact.
        arr.retain(|item| !entry_is_claudeguard_managed(item));

        if install {
            arr.push(desired_entry);
        }
    }

    Ok(())
}

/// Checks whether a Claude Code `settings.json` file currently contains ClaudeGuard's
/// `UserPromptSubmit` hook entry.
pub fn is_claude_settings_hook_installed(settings_path: &Path) -> bool {
    let Ok(raw) = std::fs::read_to_string(settings_path) else {
        return false;
    };
    let clean = raw.trim().trim_start_matches('\u{feff}');
    let Ok(val) = serde_json::from_str::<Value>(clean) else {
        return false;
    };
    val.pointer("/hooks/UserPromptSubmit")
        .and_then(Value::as_array)
        .is_some_and(|arr| arr.iter().any(entry_is_claudeguard_managed))
}

/// Idempotently installs or removes ClaudeGuard hooks in `settings_path`.
///
/// Refuses to overwrite invalid JSON syntax; saves `<settings_path>.cg-bak` before modifying.
pub fn sync_claude_code_settings(
    settings_path: &Path,
    cli_exe: &Path,
    vault_id: Option<&str>,
    install: bool,
) -> Result<(), String> {
    vault_win::ensure_no_reparse_points_chain(settings_path)?;
    if let Some(parent) = settings_path.parent() {
        vault_win::safe_create_dir_all_no_reparse(parent)?;
    }

    let existed = settings_path.exists();
    let (original_bytes, mut root) = if existed {
        let raw_bytes = std::fs::read(settings_path).map_err(|e| {
            format!(
                "读取 Claude Code 配置文件失败（{}）：{e}",
                settings_path.display()
            )
        })?;
        let text = String::from_utf8(raw_bytes.clone()).map_err(|_| {
            format!(
                "配置文件不是有效 UTF-8 文本，已中止写入保护原文件：{}",
                settings_path.display()
            )
        })?;
        let trimmed = text.trim().trim_start_matches('\u{feff}');
        if trimmed.is_empty() {
            return Err(format!(
                "配置文件为空，请先检查或修复 {} 后再安装 Hook",
                settings_path.display()
            ));
        }
        let parsed: Value = serde_json::from_str(trimmed).map_err(|e| {
            format!(
                "检测到 {} 存在 JSON 语法错误（{e}），已中止 Hook 注入以避免覆盖原配置；请修复语法后重试",
                settings_path.display()
            )
        })?;
        (Some(raw_bytes), parsed)
    } else if !install {
        return Ok(());
    } else {
        (None, Value::Object(Map::new()))
    };

    let had_cg_hook = root
        .pointer("/hooks/UserPromptSubmit")
        .and_then(Value::as_array)
        .is_some_and(|arr| arr.iter().any(entry_is_claudeguard_managed))
        || root
            .pointer("/hooks/PreToolUse")
            .and_then(Value::as_array)
            .is_some_and(|arr| arr.iter().any(entry_is_claudeguard_managed));

    merge_claude_settings_value(&mut root, cli_exe, vault_id, install)?;

    if let Some(orig) = original_bytes {
        let bak_path = backup_path_for(settings_path);
        if !bak_path.exists() || !had_cg_hook {
            vault_win::ensure_no_reparse_points_chain(&bak_path)?;
            atomic_write_bytes(&bak_path, &orig)?;
        }
    }

    let serialized = serde_json::to_string_pretty(&root)
        .map_err(|e| format!("序列化 settings.json 失败：{e}"))?;
    let mut final_bytes = serialized.into_bytes();
    final_bytes.push(b'\n');
    atomic_write_bytes(settings_path, &final_bytes)
}

/// Renders the marked PowerShell `$PROFILE` wrapper block for `claude` and `codex`.
pub fn render_pwsh_profile_block(cli_exe: &Path) -> String {
    let exe_esc = cli_exe.to_string_lossy().replace('\'', "''");
    format!(
        "{start}\r\n\
function Invoke-ClaudeGuardCliWrap {{\r\n\
    param([string]$AgentId, [string]$ExeName, [string[]]$ForwardArgs)\r\n\
    $cgCli = '{exe_esc}'\r\n\
    if (Test-Path -LiteralPath $cgCli) {{\r\n\
        $gateArgs = @('--hook-gate', '--agent', $AgentId, '--exit-code-block')\r\n\
        if (-not [string]::IsNullOrWhiteSpace($env:CG_VAULT_ID)) {{\r\n\
            $gateArgs += @('--vault', $env:CG_VAULT_ID)\r\n\
        }}\r\n\
        $null | & $cgCli @gateArgs\r\n\
        if ($LASTEXITCODE -ne 0) {{ return }}\r\n\
    }}\r\n\
    $realCmd = Get-Command -Name $ExeName -CommandType Application,ExternalScript -ErrorAction SilentlyContinue | Where-Object {{ $_.Source -ne $PSCommandPath }} | Select-Object -First 1\r\n\
    if ($null -eq $realCmd) {{ Write-Error \"ClaudeGuard: executable not found: $ExeName\"; return }}\r\n\
    if ($MyInvocation.ExpectingInput) {{\r\n\
        $input | & $realCmd.Source @ForwardArgs\r\n\
    }} else {{\r\n\
        & $realCmd.Source @ForwardArgs\r\n\
    }}\r\n\
}}\r\n\
function claude {{ Invoke-ClaudeGuardCliWrap -AgentId 'claude-code' -ExeName 'claude' -ForwardArgs $args }}\r\n\
function codex  {{ Invoke-ClaudeGuardCliWrap -AgentId 'codex'       -ExeName 'codex'  -ForwardArgs $args }}\r\n\
{end}",
        start = PWSH_BLOCK_START,
        end = PWSH_BLOCK_END,
    )
}

/// Strips any existing ClaudeGuard marked block from a PowerShell profile string.
pub fn strip_pwsh_profile_block(existing: &str) -> String {
    let clean = existing.strip_prefix('\u{feff}').unwrap_or(existing);
    let mut kept_lines: Vec<&str> = Vec::new();
    let mut inside = false;
    for line in clean.lines() {
        let trimmed = line.trim();
        if trimmed == PWSH_BLOCK_START || trimmed == ALT_PWSH_BLOCK_START {
            inside = true;
            continue;
        }
        if inside && (trimmed == PWSH_BLOCK_END || trimmed == ALT_PWSH_BLOCK_END) {
            inside = false;
            continue;
        }
        if !inside {
            kept_lines.push(line);
        }
    }
    // Trim trailing blank lines introduced by repeated install/uninstall cycles.
    while kept_lines.last().is_some_and(|l| l.trim().is_empty()) {
        kept_lines.pop();
    }
    if kept_lines.is_empty() {
        String::new()
    } else {
        format!("{}\r\n", kept_lines.join("\r\n"))
    }
}

/// Pure updater returning updated PowerShell profile text with the ClaudeGuard wrapper block
/// idempotently inserted or removed.
pub fn merge_pwsh_profile_text(existing: &str, cli_exe: &Path, install: bool) -> String {
    let base = strip_pwsh_profile_block(existing);
    if !install {
        return base;
    }
    let block = render_pwsh_profile_block(cli_exe);
    if base.is_empty() {
        format!("{block}\r\n")
    } else {
        format!("{base}\r\n{block}\r\n")
    }
}

/// Checks whether a PowerShell `$PROFILE` file currently contains the ClaudeGuard wrapper block.
pub fn is_pwsh_profile_wrapped(profile_path: &Path) -> bool {
    let Ok(raw) = std::fs::read_to_string(profile_path) else {
        return false;
    };
    raw.contains(PWSH_BLOCK_START) || raw.contains(ALT_PWSH_BLOCK_START)
}

/// Idempotently injects or removes the ClaudeGuard wrapper block in `profile_path`.
pub fn sync_pwsh_profile(profile_path: &Path, cli_exe: &Path, install: bool) -> Result<(), String> {
    vault_win::ensure_no_reparse_points_chain(profile_path)?;
    if let Some(parent) = profile_path.parent() {
        vault_win::safe_create_dir_all_no_reparse(parent)?;
    }

    let existed = profile_path.exists();
    let existing = if existed {
        let orig_bytes = std::fs::read(profile_path).map_err(|e| {
            format!(
                "读取 PowerShell 配置文件失败（{}）：{e}",
                profile_path.display()
            )
        })?;
        let orig_str = String::from_utf8_lossy(&orig_bytes).into_owned();
        let already_wrapped =
            orig_str.contains(PWSH_BLOCK_START) || orig_str.contains(ALT_PWSH_BLOCK_START);
        let bak_path = backup_path_for(profile_path);
        if !bak_path.exists() || !already_wrapped {
            vault_win::ensure_no_reparse_points_chain(&bak_path)?;
            atomic_write_bytes(&bak_path, &orig_bytes)?;
        }
        orig_str
    } else if !install {
        return Ok(());
    } else {
        String::new()
    };

    let merged = merge_pwsh_profile_text(&existing, cli_exe, install);
    if !install && merged.is_empty() {
        return atomic_write_bytes(profile_path, b"");
    }
    // Write UTF-8 with BOM + CRLF for dual PowerShell 5.1 / PowerShell 7 compatibility.
    let mut out = Vec::with_capacity(3 + merged.len());
    out.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
    out.extend_from_slice(merged.as_bytes());
    atomic_write_bytes(profile_path, &out)
}

/// Read-only inspection of current Claude Code, PowerShell `$PROFILE`, and vault hook status.
pub fn inspect_hook_status_in(
    user_home: Option<&Path>,
    vaults_root: Option<&Path>,
    vaults: &[AccountVault],
    total_gate_checks: u64,
    total_gate_blocks: u64,
    last_gate_latency_us: u64,
) -> HookIntegrationStatus {
    let claude_installed = user_home
        .map(default_claude_settings_path)
        .is_some_and(|p| is_claude_settings_hook_installed(&p));
    let pwsh_wrapped = user_home
        .map(default_pwsh_profile_path)
        .is_some_and(|p| is_pwsh_profile_wrapped(&p));

    let mut counted_settings: Vec<PathBuf> = Vec::new();
    let mut vault_hooks_synced_count = 0usize;
    if let Some(vroot) = vaults_root {
        for v in vaults {
            if let Ok(root) = vault_win::resolve_vault_root_under(vroot, &v.id) {
                let paths = vault_win::VaultPaths::from_root(&v.id, root);
                let sp = paths.claude_code_home.join("settings.json");
                if is_claude_settings_hook_installed(&sp) {
                    vault_hooks_synced_count += 1;
                    counted_settings.push(sp);
                }
            }
        }
        if let Ok(entries) = std::fs::read_dir(vroot) {
            for entry in entries.flatten() {
                let dir = entry.path();
                let Ok(meta) = std::fs::symlink_metadata(&dir) else {
                    continue;
                };
                if crate::journal::is_reparse_point_metadata(&meta) || !meta.is_dir() {
                    continue;
                }
                for sub in ["claude_code_home", "claude-code"] {
                    let sp = dir.join(sub).join("settings.json");
                    if !counted_settings.contains(&sp) && is_claude_settings_hook_installed(&sp) {
                        vault_hooks_synced_count += 1;
                        counted_settings.push(sp);
                    }
                }
            }
        }
    }

    let summary = format_hook_summary(claude_installed, pwsh_wrapped, vault_hooks_synced_count);
    HookIntegrationStatus {
        claude_code_hook_installed: claude_installed,
        pwsh_profile_wrapped: pwsh_wrapped,
        vault_hooks_synced_count,
        total_gate_checks,
        total_gate_blocks,
        last_gate_latency_us,
        summary,
    }
}

/// High-level hook configurator operating on explicit roots (testable & hermetic).
#[allow(clippy::too_many_arguments)]
pub fn configure_cli_hooks_in(
    user_home: &Path,
    vaults_root: Option<&Path>,
    cli_exe: &Path,
    vaults: &[AccountVault],
    install_claude_code: bool,
    install_pwsh_profile: bool,
    sync_all_vaults: bool,
) -> Result<HookIntegrationStatus, String> {
    let settings_path = default_claude_settings_path(user_home);
    sync_claude_code_settings(&settings_path, cli_exe, None, install_claude_code)?;

    let profile_path = default_pwsh_profile_path(user_home);
    sync_pwsh_profile(&profile_path, cli_exe, install_pwsh_profile)?;

    if let Some(vroot) = vaults_root {
        if install_claude_code {
            if sync_all_vaults {
                for vault in vaults {
                    let paths = vault_win::ensure_vault_layout_in(vroot, vault)?;
                    let vault_settings = paths.claude_code_home.join("settings.json");
                    sync_claude_code_settings(&vault_settings, cli_exe, Some(&vault.id), true)?;
                }
            }
        } else {
            // Uninstalling Claude Code hooks ALWAYS cleans Sovereign Vault hooks without
            // creating new vault directories on disk (`#88` [HIGH-1] + `#86` #2).
            let mut cleaned_paths: Vec<PathBuf> = Vec::new();
            for vault in vaults {
                if let Ok(root) = vault_win::resolve_vault_root_under(vroot, &vault.id) {
                    let paths = vault_win::VaultPaths::from_root(&vault.id, root);
                    let vault_settings = paths.claude_code_home.join("settings.json");
                    if vault_settings.is_file() {
                        sync_claude_code_settings(
                            &vault_settings,
                            cli_exe,
                            Some(&vault.id),
                            false,
                        )?;
                        cleaned_paths.push(vault_settings);
                    }
                }
            }
            if let Ok(entries) = std::fs::read_dir(vroot) {
                for entry in entries.flatten() {
                    let dir = entry.path();
                    let Ok(meta) = std::fs::symlink_metadata(&dir) else {
                        continue;
                    };
                    if crate::journal::is_reparse_point_metadata(&meta) || !meta.is_dir() {
                        continue;
                    }
                    for sub in ["claude_code_home", "claude-code"] {
                        let sp = dir.join(sub).join("settings.json");
                        if !cleaned_paths.contains(&sp)
                            && sp.is_file()
                            && is_claude_settings_hook_installed(&sp)
                        {
                            let _ = sync_claude_code_settings(&sp, cli_exe, None, false);
                            cleaned_paths.push(sp);
                        }
                    }
                }
            }
        }
    }

    Ok(inspect_hook_status_in(
        Some(user_home),
        vaults_root,
        vaults,
        0,
        0,
        0,
    ))
}

/// Derives the Sovereign Vaults root directory (`<user_home>\AppData\Local\ClaudeGuard\Vaults`)
/// for an interactive user profile so Session-0 `LocalSystem` never writes into `systemprofile`.
pub fn vaults_root_for_user(user_home: &Path) -> PathBuf {
    user_home
        .join("AppData")
        .join("Local")
        .join("ClaudeGuard")
        .join("Vaults")
}

/// Production hook configurator targeting the active interactive user home & user vaults root.
pub fn configure_cli_hooks(
    vaults: &[AccountVault],
    install_claude_code: bool,
    install_pwsh_profile: bool,
    sync_all_vaults: bool,
) -> Result<HookIntegrationStatus, String> {
    let user_home = resolve_interactive_user_home()
        .ok_or_else(|| "无法定位当前交互用户主目录，无法配置 CLI Hook".to_string())?;
    let vaults_root = vaults_root_for_user(&user_home);
    let cli_exe = resolve_cli_exe_path();
    configure_cli_hooks_in(
        &user_home,
        Some(&vaults_root),
        &cli_exe,
        vaults,
        install_claude_code,
        install_pwsh_profile,
        sync_all_vaults,
    )
}

/// Production read-only hook status inspector.
pub fn inspect_hook_status(
    vaults: &[AccountVault],
    total_gate_checks: u64,
    total_gate_blocks: u64,
    last_gate_latency_us: u64,
) -> HookIntegrationStatus {
    let user_home = resolve_interactive_user_home();
    let vaults_root = user_home
        .as_deref()
        .map(vaults_root_for_user)
        .or_else(|| vault_win::default_vaults_root().ok());
    inspect_hook_status_in(
        user_home.as_deref(),
        vaults_root.as_deref(),
        vaults,
        total_gate_checks,
        total_gate_blocks,
        last_gate_latency_us,
    )
}

fn format_hook_summary(claude_ok: bool, pwsh_ok: bool, vault_count: usize) -> String {
    let mut parts = Vec::new();
    if claude_ok {
        parts.push("Claude Code Pre-Prompt Hook 已就绪".to_string());
    }
    if pwsh_ok {
        parts.push("PowerShell 包装器已注入".to_string());
    }
    if vault_count > 0 {
        parts.push(format!("{vault_count} 个主权仓已同步"));
    }
    if parts.is_empty() {
        "尚未安装 CLI 极速门禁钩子".to_string()
    } else {
        parts.join(" · ")
    }
}

fn backup_path_for(path: &Path) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(".cg-bak");
    PathBuf::from(os)
}

/// Writes `<dir>\.claudeguard-hook-policy.json` atomically with interactive-user read/modify ACL.
pub fn sync_public_hook_policy_in(
    dir: &Path,
    hook_fail_mode: HookFailMode,
    disarmed: bool,
) -> Result<(), String> {
    vault_win::safe_create_dir_all_no_reparse(dir)?;
    let target = dir.join(HOOK_POLICY_FILE);
    let payload = PublicHookPolicy {
        hook_fail_mode,
        disarmed,
    };
    let mut bytes = serde_json::to_vec_pretty(&payload)
        .map_err(|e| format!("序列化离线 Hook 策略文件失败：{e}"))?;
    bytes.push(b'\n');
    atomic_write_bytes(&target, &bytes)
}

/// Reads `<dir>\.claudeguard-hook-policy.json` if present and valid.
pub fn read_public_hook_policy_in(dir: &Path) -> Option<PublicHookPolicy> {
    let target = dir.join(HOOK_POLICY_FILE);
    vault_win::ensure_no_reparse_points_chain(&target).ok()?;
    let raw = std::fs::read_to_string(&target).ok()?;
    serde_json::from_str(raw.trim()).ok()
}

/// Reads the current user's `.claudeguard-hook-policy.json` from `USERPROFILE` or interactive user home.
pub fn read_public_hook_policy() -> Option<PublicHookPolicy> {
    if let Some(up) = std::env::var_os("USERPROFILE")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
    {
        if let Some(pol) = read_public_hook_policy_in(&up) {
            return Some(pol);
        }
    }
    let home = resolve_interactive_user_home()?;
    read_public_hook_policy_in(&home)
}

/// Mirrors `PublicHookPolicy` to interactive user home(s) when operating on the production
/// `%ProgramData%\ClaudeGuard` directory, or inside `data_dir` itself for hermetic test/custom dirs.
pub fn sync_public_hook_policy_for_data_dir(
    data_dir: &Path,
    hook_fail_mode: HookFailMode,
    disarmed: bool,
) {
    if crate::journal::is_default_programdata_claudeguard_dir(data_dir) {
        let mut homes = cg_platform::process_win::user_home_dirs();
        if let Some(active) = resolve_interactive_user_home() {
            if !homes.contains(&active) {
                homes.push(active);
            }
        }
        for home in homes {
            let _ = sync_public_hook_policy_in(&home, hook_fail_mode, disarmed);
        }
    } else {
        let _ = sync_public_hook_policy_in(data_dir, hook_fail_mode, disarmed);
    }
}

/// Strips ClaudeGuard CLI hooks, Sovereign Vault hooks, PowerShell `$PROFILE` blocks, WSL2 gate shims,
/// and `.claudeguard-*` helper files across all discovered interactive user profiles (`--unhook-all`).
pub fn unhook_all_user_profiles(vaults: &[AccountVault]) -> Result<usize, String> {
    let cli_exe = resolve_cli_exe_path();
    let mut homes = cg_platform::process_win::user_home_dirs();
    if let Some(active) = resolve_interactive_user_home() {
        if !homes.contains(&active) {
            homes.push(active);
        }
    }
    let mut cleaned = 0usize;
    for home in &homes {
        let vroot = vaults_root_for_user(home);
        if configure_cli_hooks_in(home, Some(&vroot), &cli_exe, vaults, false, false, true).is_ok()
        {
            cleaned += 1;
        }
        let policy_file = home.join(HOOK_POLICY_FILE);
        if vault_win::ensure_no_reparse_points_chain(&policy_file).is_ok() {
            let _ = std::fs::remove_file(&policy_file);
        }
        let wsl_tok = home.join(crate::wsl_bridge::WSL_TOKEN_FILE);
        if vault_win::ensure_no_reparse_points_chain(&wsl_tok).is_ok() {
            let _ = std::fs::remove_file(&wsl_tok);
        }
    }
    let _ = crate::wsl_bridge::unsync_all_wsl_distros();
    Ok(cleaned)
}

#[cfg(windows)]
pub(crate) fn ensure_interactive_user_modify_dacl_if_service(target: &Path) {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{LocalFree, BOOL, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW,
        SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        UNPROTECTED_DACL_SECURITY_INFORMATION,
    };

    if !cg_platform::access_win::is_session_zero() {
        return;
    }
    let Some(sid) = crate::wsl_bridge::resolve_user_sid_for_path(target) else {
        return;
    };
    if !cg_platform::access_win::is_interactive_user_sid(&sid) {
        return;
    }
    let sddl = format!("D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{sid})");
    let sddl_w: Vec<u16> = OsStr::new(&sddl)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_w.as_ptr()),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )
    }
    .is_err()
    {
        return;
    }
    struct SdGuard(PSECURITY_DESCRIPTOR);
    impl Drop for SdGuard {
        fn drop(&mut self) {
            if !self.0 .0.is_null() {
                unsafe {
                    let _ = LocalFree(HLOCAL(self.0 .0));
                }
            }
        }
    }
    let _sd_guard = SdGuard(sd);

    let mut present = BOOL(0);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut defaulted = BOOL(0);
    if unsafe { GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) }.is_err()
        || !present.as_bool()
        || dacl.is_null()
    {
        return;
    }
    let path_w: Vec<u16> = target
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let _ = unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(path_w.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
            PSID::default(),
            PSID::default(),
            Some(dacl.cast_const()),
            None,
        )
    };
}

fn atomic_write_bytes(target: &Path, bytes: &[u8]) -> Result<(), String> {
    vault_win::ensure_no_reparse_points_chain(target)?;
    let parent = target
        .parent()
        .ok_or_else(|| format!("目标路径缺少父目录：{}", target.display()))?;
    let mut tmp = NamedTempFile::new_in(parent)
        .map_err(|e| format!("创建临时文件失败（{}）：{e}", parent.display()))?;
    tmp.write_all(bytes)
        .map_err(|e| format!("写入临时文件失败：{e}"))?;
    tmp.as_file()
        .sync_all()
        .map_err(|e| format!("同步临时文件失败：{e}"))?;
    tmp.persist(target)
        .map_err(|e| format!("原子替换 {} 失败：{}", target.display(), e.error))?;
    #[cfg(windows)]
    ensure_interactive_user_modify_dacl_if_service(target);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cg_protocol::MsixIsolationMode;

    fn sample_vault(id: &str) -> AccountVault {
        AccountVault {
            id: id.into(),
            name: format!("Vault {id}"),
            accent_hex: "#5B69D0".into(),
            enabled: true,
            pinned_regions: vec!["US".into()],
            pinned_ips: Vec::new(),
            pinned_asn: None,
            dedicated_proxy_port: None,
            preferred_mihomo_group: None,
            preferred_mihomo_node: None,
            auto_align_mihomo_on_vault_launch: false,
            min_safety_score: 75,
            cooldown_after_ip_change_secs: 900,
            share_ide_extensions: true,
            msix_isolation_mode: MsixIsolationMode::AutoVerifyLock,
        }
    }

    #[test]
    fn claude_settings_merge_is_idempotent_and_preserves_existing_hooks_and_keys() {
        let dir = tempfile::tempdir().unwrap();
        let settings = default_claude_settings_path(dir.path());
        std::fs::create_dir_all(settings.parent().unwrap()).unwrap();

        let existing = json!({
            "model": "claude-sonnet-4-5",
            "permissions": { "allow": ["Read(*)"] },
            "hooks": {
                "UserPromptSubmit": [
                    {
                        "matcher": "",
                        "hooks": [
                            { "type": "command", "command": "my-custom-linter --check", "timeout": 3 }
                        ]
                    }
                ],
                "Stop": [
                    {
                        "matcher": "",
                        "hooks": [
                            { "type": "command", "command": "notify-done", "timeout": 2 }
                        ]
                    }
                ]
            }
        });
        std::fs::write(&settings, serde_json::to_string_pretty(&existing).unwrap()).unwrap();

        let cli = Path::new(r"C:\Program Files\ClaudeGuard\claudeguard-cli.exe");
        // Install twice to prove strict idempotency.
        sync_claude_code_settings(&settings, cli, None, true).unwrap();
        sync_claude_code_settings(&settings, cli, None, true).unwrap();

        assert!(is_claude_settings_hook_installed(&settings));
        assert!(backup_path_for(&settings).is_file());

        let parsed: Value =
            serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(parsed["model"], "claude-sonnet-4-5");
        assert_eq!(parsed["permissions"]["allow"][0], "Read(*)");
        assert_eq!(parsed["hooks"]["Stop"].as_array().unwrap().len(), 1);

        let ups = parsed["hooks"]["UserPromptSubmit"].as_array().unwrap();
        assert_eq!(
            ups.len(),
            2,
            "must keep user hook + exactly 1 ClaudeGuard hook"
        );
        assert_eq!(ups[0]["hooks"][0]["command"], "my-custom-linter --check");
        assert!(ups[1]["hooks"][0]["command"]
            .as_str()
            .unwrap()
            .contains("--hook-gate --agent claude-code"));

        let pre = parsed["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 1);
        assert_eq!(pre[0]["matcher"], "WebFetch|WebSearch|Bash");

        // Uninstall removes ONLY ClaudeGuard hooks while keeping user hooks 100% intact.
        sync_claude_code_settings(&settings, cli, None, false).unwrap();
        assert!(!is_claude_settings_hook_installed(&settings));
        let after_rm: Value =
            serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        let ups_after = after_rm["hooks"]["UserPromptSubmit"].as_array().unwrap();
        assert_eq!(ups_after.len(), 1);
        assert_eq!(
            ups_after[0]["hooks"][0]["command"],
            "my-custom-linter --check"
        );
        assert_eq!(after_rm["hooks"]["PreToolUse"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn corrupt_settings_json_aborts_without_overwriting_user_file() {
        let dir = tempfile::tempdir().unwrap();
        let settings = default_claude_settings_path(dir.path());
        std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
        let broken = "{ \"hooks\": [ invalid json ";
        std::fs::write(&settings, broken).unwrap();

        let cli = Path::new(r"C:\Program Files\ClaudeGuard\claudeguard-cli.exe");
        let err = sync_claude_code_settings(&settings, cli, None, true).unwrap_err();
        assert!(err.contains("JSON 语法错误"));
        assert_eq!(
            std::fs::read_to_string(&settings).unwrap(),
            broken,
            "corrupt user settings.json must NEVER be overwritten"
        );
    }

    #[test]
    fn pwsh_profile_and_vault_hooks_sync_idempotently() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let vroot = dir.path().join("vaults");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&vroot).unwrap();

        let profile = default_pwsh_profile_path(&home);
        std::fs::create_dir_all(profile.parent().unwrap()).unwrap();
        std::fs::write(&profile, "oh-my-posh init pwsh | Invoke-Expression\r\n").unwrap();

        let cli = Path::new(r"C:\Program Files\ClaudeGuard\claudeguard-cli.exe");
        let vaults = vec![sample_vault("work-us"), sample_vault("jp-alt")];

        let st = configure_cli_hooks_in(&home, Some(&vroot), cli, &vaults, true, true, true)
            .expect("configure hooks");
        assert!(st.claude_code_hook_installed);
        assert!(st.pwsh_profile_wrapped);
        assert_eq!(st.vault_hooks_synced_count, 2);

        let prof_text = std::fs::read_to_string(&profile).unwrap();
        assert!(prof_text.contains("oh-my-posh init pwsh | Invoke-Expression"));
        assert!(prof_text.contains(PWSH_BLOCK_START));
        assert!(prof_text.contains("function claude"));
        assert!(prof_text.contains("function codex"));

        // Verify vault settings carries `--vault work-us`.
        let v_settings = vroot
            .join("work-us")
            .join("claude_code_home")
            .join("settings.json");
        let v_text = std::fs::read_to_string(&v_settings).unwrap();
        assert!(v_text.contains("--vault work-us"));

        // Verify OneDrive `User Shell Folders\Personal` redirection & stdin-safe wrapper script.
        assert!(prof_text.contains("$null | & $cgCli @gateArgs"));
        assert!(prof_text.contains("Application,ExternalScript"));
        assert!(prof_text.contains("$MyInvocation.ExpectingInput"));

        let onedrive_docs = home.join("OneDrive").join("Documents");
        std::fs::create_dir_all(&onedrive_docs).unwrap();
        assert_eq!(
            resolve_documents_dir_from_personal(&home, Some(r"%USERPROFILE%\OneDrive\Documents")),
            onedrive_docs
        );

        // Re-running uninstall with sync_all_vaults=false (exact UI button payload) STILL cleans
        // all Sovereign Vault hooks and keeps oh-my-posh line & original .cg-bak intact!
        let st_off = configure_cli_hooks_in(&home, Some(&vroot), cli, &vaults, false, false, false)
            .expect("uninstall hooks with sync_all_vaults=false");
        assert!(!st_off.claude_code_hook_installed);
        assert!(!st_off.pwsh_profile_wrapped);
        assert_eq!(st_off.vault_hooks_synced_count, 0);
        let prof_after = std::fs::read_to_string(&profile).unwrap();
        assert!(prof_after.contains("oh-my-posh init pwsh | Invoke-Expression"));
        assert!(!prof_after.contains(PWSH_BLOCK_START));
        let bak_text = std::fs::read_to_string(backup_path_for(&profile)).unwrap();
        assert!(!bak_text.contains(PWSH_BLOCK_START));
    }
}
