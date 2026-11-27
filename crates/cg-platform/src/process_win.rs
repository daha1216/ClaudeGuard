//! Cached Windows process scanner, executable discovery, PID-reuse verification,
//! process-tree termination, multi-agent orphan detection, and normal-privilege shell launcher.
//!
//! Design invariants:
//! - `ProcessScanner::cached_snapshot()` performs zero syscalls / OS scans (R16).
//! - Covered executables for `claude` and `chatgpt` prefer AppModel `Repository\Packages`
//!   sorted newest-first by numeric version tuple, falling back to `WindowsApps` only when
//!   the registry key is absent or empty (R05).
//! - `antigravity` discovers user installs across `%LOCALAPPDATA%`, `%USERPROFILE%`, and
//!   `C:\Users\*\AppData\Local\Programs\{antigravity, Antigravity IDE}` (so `LocalSystem`
//!   `ClaudeGuardService` never misses per-user installs) and scans up to `max_depth = 5`
//!   (putting `Antigravity.exe` / `Antigravity IDE.exe` first for Safe Launch while covering
//!   `resources\bin\language_server.exe`, `webm_encoder.exe`, `elevate.exe`, `agy.exe`, etc.
//!   in COM Firewall rules, excluding uninstallers).
//! - CLI agents (`claude-code`, `codex`) are NEVER killed during a trip;
//!   only optional orphan residual sweep cleans CLI processes whose parent terminal (`ppid`)
//!   is already dead.
//! - Every termination re-verifies `(pid, start_time, exe_path)` immediately prior to `kill()`
//!   to eliminate PID-reuse collateral damage (R04), ordered children-first so parents cannot
//!   respawn helpers mid-sweep.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::traits::{PlatformError, PlatformResult};

/// Static GUI agent descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuiAgentDef {
    pub id: &'static str,
    pub name: &'static str,
}

/// Guarded GUI desktop agents (killable on trip + firewall quarantined).
pub const GUI_AGENTS: &[GuiAgentDef] = &[
    GuiAgentDef {
        id: "claude",
        name: "Claude",
    },
    GuiAgentDef {
        id: "chatgpt",
        name: "ChatGPT",
    },
    GuiAgentDef {
        id: "antigravity",
        name: "反重力",
    },
];

/// CLI agents (monitored for awareness; NEVER killed on trip).
pub const CLI_AGENTS: &[(&str, &str)] = &[("claude-code", "Claude Code"), ("codex", "Codex CLI")];

pub fn agent_ids() -> Vec<&'static str> {
    GUI_AGENTS.iter().map(|a| a.id).collect()
}

pub fn gui_agent_name(id: &str) -> &str {
    GUI_AGENTS
        .iter()
        .find(|a| a.id == id)
        .map(|a| a.name)
        .unwrap_or(id)
}

pub fn cli_agent_name(id: &str) -> &str {
    CLI_AGENTS
        .iter()
        .find(|a| a.0 == id)
        .map(|a| a.1)
        .unwrap_or(id)
}

/// Process identity tuple checked immediately before termination to block PID-reuse races.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_time: u64,
    pub exe_path: String,
}

/// Pure PID-reuse guard: requires matching PID, identical non-zero start time, and matching path.
pub fn same_identity(expected: &ProcessIdentity, observed: &ProcessIdentity) -> bool {
    expected.pid == observed.pid
        && expected.start_time > 0
        && expected.start_time == observed.start_time
        && !expected.exe_path.is_empty()
        && expected.exe_path.eq_ignore_ascii_case(&observed.exe_path)
}

/// Lowercase executable filename check for uninstallers.
pub fn is_uninstaller_exe(exe_name_l: &str) -> bool {
    exe_name_l.starts_with("uninstall")
        || exe_name_l.starts_with("unins")
        || exe_name_l.contains("uninstaller")
}

/// SCM auto-start service executables bundled inside Claude / Codex MSIX packages.
///
/// Covered by COM Firewall rules, retained in `CachedProcessSnapshot.procs`, and monitored in
/// `guarded_agent_pids`, while excluded from `gui_counts`, live GUI roots, and direct self-kill.
pub fn is_agent_scm_service_exe(exe_name_l: &str) -> bool {
    matches!(
        exe_name_l,
        "cowork-svc.exe"
            | "codex-windows-sandbox-service.exe"
            | "elevation_service.exe"
            | "elevated_tracing_service.exe"
    )
}

pub(crate) fn strip_ascii_prefix_ci<'a>(s: &'a str, prefix_ascii: &str) -> Option<&'a str> {
    if !prefix_ascii.is_ascii() {
        return None;
    }
    let head = s.as_bytes().get(..prefix_ascii.len())?;
    head.eq_ignore_ascii_case(prefix_ascii.as_bytes())
        .then(|| s.get(prefix_ascii.len()..))
        .flatten()
}

pub fn strip_verbatim_win32_str(raw: &str) -> std::borrow::Cow<'_, str> {
    let t = raw.trim();
    if let Some(unc) =
        strip_ascii_prefix_ci(t, r"\\?\UNC\").or_else(|| strip_ascii_prefix_ci(t, "//?/UNC/"))
    {
        std::borrow::Cow::Owned(format!(r"\\{unc}"))
    } else if let Some(dos) = t.strip_prefix(r"\\?\").or_else(|| t.strip_prefix("//?/")) {
        std::borrow::Cow::Borrowed(dos)
    } else {
        std::borrow::Cow::Borrowed(t)
    }
}

/// Zero-allocation (for normal DOS paths) case-insensitive directory prefix check enforcing a
/// path-separator boundary and stripping `\\?\` so `...\Programs\antigravity` never falsely
/// matches `...\Programs\antigravity ide`.
pub fn path_under_dir_l(exe_path_l: &str, dir_l: &str) -> bool {
    let d_cow = strip_verbatim_win32_str(dir_l);
    let p_cow = strip_verbatim_win32_str(exe_path_l);
    let d = d_cow.trim().trim_end_matches(['\\', '/']);
    let p = p_cow.trim();
    if d.is_empty() || p.len() <= d.len() {
        return false;
    }
    let d_bytes = d.as_bytes();
    let p_bytes = p.as_bytes();
    for i in 0..d_bytes.len() {
        let a = match p_bytes[i] {
            b'/' => b'\\',
            b => b.to_ascii_lowercase(),
        };
        let b = match d_bytes[i] {
            b'/' => b'\\',
            b => b.to_ascii_lowercase(),
        };
        if a != b {
            return false;
        }
    }
    matches!(p_bytes[d_bytes.len()], b'\\' | b'/')
}

fn is_claude_cli_path_l(exe_path_l: &str) -> bool {
    let norm = exe_path_l.replace('/', "\\");
    norm.contains(r"\claude\claude-code\")
        || norm.contains(r"\.local\bin\claude")
        || norm.contains(r"\.local\share\claude\")
        || norm.contains(r"\.claude\bin\")
        || norm.contains(r"\.claude\local\")
        || norm.contains(r"\volta\bin\claude")
        || norm.contains(r"\pnpm\claude")
        || norm.contains(r"\npm\claude")
        || norm.contains(r"\scoop\apps\claude-code\")
        || norm.contains(r"\.bun\bin\claude")
        || norm.contains(r"\winget\packages\anthropic.claudecode")
        || norm.contains(r"\winget\links\claude.exe")
        || norm.contains(r"@anthropic-ai\claude-code")
        || norm.contains("claude-code-win32")
}

/// Pure, zero-I/O classifier returning `true` ONLY when `(agent_id, exe_path, cmdline)`
/// identifies a root main Electron GUI executable (excluding CLI
/// tools, uninstallers, SCM services, Chromium `--type=` child workers, and LSP/MCP helpers).
pub fn is_root_electron_gui_process(agent_id: &str, exe_path: &str, cmdline: Option<&str>) -> bool {
    let id = agent_id.trim().to_ascii_lowercase();
    if !matches!(id.as_str(), "claude" | "chatgpt" | "antigravity") {
        return false;
    }
    let path_l = strip_verbatim_win32_str(exe_path)
        .replace('/', "\\")
        .to_ascii_lowercase();
    let exe_name_l = Path::new(&path_l)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    if exe_name_l.is_empty()
        || is_uninstaller_exe(exe_name_l)
        || is_agent_scm_service_exe(exe_name_l)
    {
        return false;
    }
    let cmd_l = cmdline.unwrap_or("").to_ascii_lowercase();
    if cmd_l.contains("--type=")
        || cmd_l.contains("electron_run_as_node")
        || cmd_l.contains("--import=")
        || cmd_l.contains("sidecar_sdk")
    {
        return false;
    }
    match id.as_str() {
        "claude" => !is_claude_cli_path_l(&path_l) && exe_name_l == "claude.exe",
        "chatgpt" => {
            !path_l.contains(r"\resources\codex.exe")
                && !cli_agent_matches("codex", exe_name_l, &path_l, &cmd_l)
                && matches!(
                    exe_name_l,
                    "chatgpt.exe" | "chatgpt classic.exe" | "codex.exe"
                )
        }
        "antigravity" => matches!(exe_name_l, "antigravity.exe" | "antigravity ide.exe"),
        _ => false,
    }
}

/// Pure matcher for GUI desktop agent processes (all inputs expected lowercase).
pub fn gui_agent_matches(
    id: &str,
    exe_name_l: &str,
    exe_path_l: &str,
    claude_dir_l: Option<&str>,
) -> bool {
    if is_uninstaller_exe(exe_name_l) {
        return false;
    }
    match id {
        "claude" => {
            if is_claude_cli_path_l(exe_path_l) {
                return false;
            }
            exe_name_l == "claude.exe"
                || exe_path_l.contains(r"\windowsapps\claude_")
                || exe_path_l.contains(r"\anthropicclaude\")
                || exe_path_l.contains(r"\programs\claude\")
                || claude_dir_l.is_some_and(|d| path_under_dir_l(exe_path_l, d))
        }
        "chatgpt" => {
            exe_name_l == "chatgpt.exe"
                || exe_name_l == "chatgpt classic.exe"
                || exe_path_l.contains(r"\windowsapps\openai.codex_")
                || exe_path_l.contains(r"\windowsapps\openai.chatgpt")
                || exe_path_l.contains(r"\programs\chatgpt\")
                || exe_path_l.contains(r"\programs\chatgpt classic\")
                || exe_path_l.contains(r"\programs\codex\")
        }
        "antigravity" => {
            exe_name_l == "antigravity.exe"
                || exe_name_l == "antigravity ide.exe"
                || exe_path_l.contains(r"\programs\antigravity\")
                || exe_path_l.contains(r"\programs\antigravity ide\")
        }
        _ => false,
    }
}

/// Pure matcher for CLI agent processes with explicit ChatGPT/Codex GUI directory exclusions
/// so `Codex.exe` inside `chatgpt_dirs_l` is ALWAYS classified as GUI (`chatgpt`), never CLI (`codex`).
pub fn cli_agent_matches_with_dirs(
    id: &str,
    exe_name_l: &str,
    exe_path_l: &str,
    cmd_l: &str,
    chatgpt_dirs_l: &[String],
) -> bool {
    if is_uninstaller_exe(exe_name_l) {
        return false;
    }
    match id {
        "claude-code" => {
            !exe_path_l.contains(r"\windowsapps\")
                && (cmd_l.contains(r"@anthropic-ai\claude-code")
                    || cmd_l.contains("@anthropic-ai/claude-code")
                    || is_claude_cli_path_l(exe_path_l))
        }
        "codex" => {
            let in_msix_or_gui = exe_path_l.contains(r"\windowsapps\")
                || exe_path_l.contains(r"\programs\codex\")
                || exe_path_l.contains(r"\programs\chatgpt\")
                || exe_path_l.contains(r"\programs\chatgpt classic\")
                || chatgpt_dirs_l
                    .iter()
                    .any(|d| path_under_dir_l(exe_path_l, d));
            !in_msix_or_gui
                && (exe_name_l.starts_with("codex")
                    || cmd_l.contains(r"@openai\codex")
                    || cmd_l.contains("@openai/codex")
                    || exe_path_l.contains(r"@openai\codex")
                    || exe_path_l.contains("@openai/codex")
                    || exe_path_l.contains("codex-win32-"))
        }
        _ => false,
    }
}

/// Pure matcher for CLI agent processes (all inputs expected lowercase).
pub fn cli_agent_matches(id: &str, exe_name_l: &str, exe_path_l: &str, cmd_l: &str) -> bool {
    cli_agent_matches_with_dirs(id, exe_name_l, exe_path_l, cmd_l, &[])
}

fn is_any_cli_agent_with_dirs(p: &ProcInfo, chatgpt_dirs_l: &[String]) -> bool {
    CLI_AGENTS.iter().any(|(cid, _)| {
        cli_agent_matches_with_dirs(cid, &p.name_l, &p.path_l, &p.cmd_l, chatgpt_dirs_l)
    })
}

fn is_any_cli_agent(p: &ProcInfo) -> bool {
    is_any_cli_agent_with_dirs(p, &[])
}

/// Interactive shells, ConPTY hosts, terminals, browsers, and editors that must never be
/// collateral-killed or traversed into as agent network helpers (unless inside `<AgentDir>`).
pub fn is_interactive_shell_or_terminal(exe_name_l: &str) -> bool {
    matches!(
        exe_name_l,
        "pwsh.exe"
            | "pwsh"
            | "powershell.exe"
            | "powershell"
            | "wt.exe"
            | "windowsterminal.exe"
            | "explorer.exe"
            | "bash.exe"
            | "bash"
            | "wsl.exe"
            | "wsl"
            | "wslhost.exe"
            | "conhost.exe"
            | "openconsole.exe"
            | "nu.exe"
            | "nu"
            | "zsh.exe"
            | "zsh"
            | "sh.exe"
            | "sh"
            | "fish.exe"
            | "fish"
            | "mintty.exe"
            | "alacritty.exe"
            | "wezterm-gui.exe"
            | "chrome.exe"
            | "msedge.exe"
            | "firefox.exe"
            | "brave.exe"
            | "code.exe"
    )
}

fn cmd_has_batch_c_flag(cmd_l: &str) -> bool {
    let bytes = cmd_l.as_bytes();
    if bytes.len() < 2 {
        return false;
    }
    for i in 0..=(bytes.len() - 2) {
        if bytes[i] == b'/' && bytes[i + 1] == b'c' {
            let prev_ok = i == 0 || bytes[i - 1].is_ascii_whitespace() || bytes[i - 1] == b'"';
            let next_ok =
                i + 2 == bytes.len() || bytes[i + 2].is_ascii_whitespace() || bytes[i + 2] == b'"';
            if prev_ok && next_ok {
                return true;
            }
        }
    }
    false
}

/// Process-level interactive shell / user-app boundary check: also treats `cmd.exe` WITHOUT `/c`
/// in `cmd_l` as an interactive user Command Prompt terminal so integrated `cmd.exe` shells are spared!
pub fn is_interactive_shell_proc(p: &ProcInfo) -> bool {
    if is_interactive_shell_or_terminal(&p.name_l) {
        return true;
    }
    matches!(p.name_l.as_str(), "cmd.exe" | "cmd") && !cmd_has_batch_c_flag(&p.cmd_l)
}

/// Normalized process record stored in snapshots and used by pure sweep/tree logic.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name_l: String,
    pub path_l: String,
    pub cmd_l: String,
    pub start_time: u64,
}

impl ProcInfo {
    pub fn identity(&self) -> ProcessIdentity {
        ProcessIdentity {
            pid: self.pid,
            start_time: self.start_time,
            exe_path: self.path_l.clone(),
        }
    }
}

fn is_claude_desktop_or_dir(p: &ProcInfo, claude_dirs_l: &[String]) -> bool {
    !is_uninstaller_exe(&p.name_l)
        && !is_agent_scm_service_exe(&p.name_l)
        && !is_any_cli_agent(p)
        && (gui_agent_matches(
            "claude",
            &p.name_l,
            &p.path_l,
            claude_dirs_l.first().map(String::as_str),
        ) || claude_dirs_l.iter().any(|d| path_under_dir_l(&p.path_l, d)))
}

fn is_chatgpt_codex_dir_or_gui(p: &ProcInfo, chatgpt_dirs_l: &[String]) -> bool {
    !is_uninstaller_exe(&p.name_l)
        && !is_agent_scm_service_exe(&p.name_l)
        && !is_any_cli_agent_with_dirs(p, chatgpt_dirs_l)
        && (gui_agent_matches("chatgpt", &p.name_l, &p.path_l, None)
            || chatgpt_dirs_l
                .iter()
                .any(|d| path_under_dir_l(&p.path_l, d)))
}

/// Whether `p` is an Antigravity-installed binary (`Antigravity.exe`, `language_server*.exe`,
/// `webm_encoder.exe`, `elevate.exe`, `agy.exe`, etc.), excluding uninstallers.
pub fn is_antigravity_dir_proc(p: &ProcInfo, ag_dirs_l: &[String]) -> bool {
    if is_uninstaller_exe(&p.name_l) {
        return false;
    }
    gui_agent_matches("antigravity", &p.name_l, &p.path_l, None)
        || ag_dirs_l.iter().any(|d| path_under_dir_l(&p.path_l, d))
}

/// Whether `p` is a live root Antigravity GUI main process (excluding `--type=` renderer/GPU/utility
/// children and excluding `language_server.exe -> cmd.exe -> Antigravity.exe` `ELECTRON_RUN_AS_NODE`
/// / `--import=` MCP sidecars).
pub fn is_live_root_antigravity_gui(p: &ProcInfo, by_pid: &HashMap<u32, &ProcInfo>) -> bool {
    if is_uninstaller_exe(&p.name_l) || is_agent_scm_service_exe(&p.name_l) {
        return false;
    }
    if p.name_l != "antigravity.exe" && p.name_l != "antigravity ide.exe" {
        return false;
    }
    if p.cmd_l.contains("--type=")
        || p.cmd_l.contains("electron_run_as_node")
        || p.cmd_l.contains("--import=")
        || p.cmd_l.contains("sidecar_sdk")
    {
        return false;
    }
    if let Some(parent) = by_pid.get(&p.ppid) {
        let pn = parent.name_l.as_str();
        if matches!(
            pn,
            "cmd.exe" | "cmd" | "node.exe" | "node" | "antigravity.exe" | "antigravity ide.exe"
        ) || pn.starts_with("language_server")
        {
            return false;
        }
    }
    true
}

/// Whether `p` is a live root Claude Desktop GUI process (excluding SCM services, CLI, and `--type=` children).
pub fn is_live_root_claude_gui(
    p: &ProcInfo,
    by_pid: &HashMap<u32, &ProcInfo>,
    claude_dirs_l: &[String],
) -> bool {
    if !is_claude_desktop_or_dir(p, claude_dirs_l) || p.name_l != "claude.exe" {
        return false;
    }
    if p.cmd_l.contains("--type=") || p.cmd_l.contains("electron_run_as_node") {
        return false;
    }
    if let Some(parent) = by_pid.get(&p.ppid) {
        if parent.name_l == "claude.exe" {
            return false;
        }
    }
    true
}

/// Whether `p` is a live root ChatGPT / Codex Desktop GUI process (excluding `resources\codex.exe`
/// worker processes, SCM services, and `--type=` children).
pub fn is_live_root_chatgpt_codex_gui(
    p: &ProcInfo,
    by_pid: &HashMap<u32, &ProcInfo>,
    chatgpt_dirs_l: &[String],
) -> bool {
    if !is_chatgpt_codex_dir_or_gui(p, chatgpt_dirs_l) {
        return false;
    }
    if !matches!(
        p.name_l.as_str(),
        "chatgpt.exe" | "chatgpt classic.exe" | "codex.exe"
    ) {
        return false;
    }
    if p.path_l.contains(r"\resources\codex.exe") {
        return false;
    }
    if p.cmd_l.contains("--type=") || p.cmd_l.contains("electron_run_as_node") {
        return false;
    }
    if let Some(parent) = by_pid.get(&p.ppid) {
        if matches!(
            parent.name_l.as_str(),
            "chatgpt.exe" | "chatgpt classic.exe" | "codex.exe"
        ) {
            return false;
        }
    }
    true
}

fn build_children_map(procs: &[ProcInfo]) -> HashMap<u32, Vec<usize>> {
    let mut children_by_ppid: HashMap<u32, Vec<usize>> = HashMap::new();
    for (idx, p) in procs.iter().enumerate() {
        if p.ppid != 0 && p.ppid != p.pid {
            children_by_ppid.entry(p.ppid).or_default().push(idx);
        }
    }
    children_by_ppid
}

fn reaches_any_root(
    start_pid: u32,
    roots: &HashSet<u32>,
    by_pid: &HashMap<u32, &ProcInfo>,
) -> bool {
    let mut cur = start_pid;
    let mut visited = HashSet::new();
    while cur != 0 && visited.insert(cur) {
        if roots.contains(&cur) {
            return true;
        }
        let Some(proc_item) = by_pid.get(&cur) else {
            break;
        };
        cur = proc_item.ppid;
    }
    false
}

#[allow(clippy::too_many_arguments)]
fn expand_non_shell_descendants(
    procs: &[ProcInfo],
    children_by_ppid: &HashMap<u32, Vec<usize>>,
    queue: &mut Vec<u32>,
    visited_pids: &mut HashSet<u32>,
    selected: &mut HashSet<usize>,
    skip_cli: bool,
    chatgpt_dirs_l: &[String],
    in_agent_dir_fn: impl Fn(&ProcInfo) -> bool,
) {
    while let Some(pid) = queue.pop() {
        let Some(kids) = children_by_ppid.get(&pid) else {
            continue;
        };
        for &child_idx in kids {
            let child = &procs[child_idx];
            if is_uninstaller_exe(&child.name_l)
                || (skip_cli && is_any_cli_agent_with_dirs(child, chatgpt_dirs_l))
            {
                continue;
            }
            let in_dir = in_agent_dir_fn(child);
            if !in_dir && is_interactive_shell_proc(child) {
                continue;
            }
            // Traverse through SCM service hosts to reach worker children without killing the SCM host itself.
            if is_agent_scm_service_exe(&child.name_l) {
                if visited_pids.insert(child.pid) {
                    queue.push(child.pid);
                }
                continue;
            }
            selected.insert(child_idx);
            if visited_pids.insert(child.pid) {
                queue.push(child.pid);
            }
        }
    }
}

fn postorder_indices(selected: &HashSet<usize>, procs: &[ProcInfo]) -> Vec<usize> {
    if selected.is_empty() {
        return Vec::new();
    }
    let mut children_of: HashMap<u32, Vec<usize>> = HashMap::new();
    let mut ordered_nodes: Vec<usize> = selected.iter().copied().collect();
    ordered_nodes.sort_by_key(|&i| procs[i].pid);

    for &idx in &ordered_nodes {
        let p = &procs[idx];
        if p.ppid != 0 && p.ppid != p.pid {
            children_of.entry(p.ppid).or_default().push(idx);
        }
    }

    fn visit(
        idx: usize,
        procs: &[ProcInfo],
        children_of: &HashMap<u32, Vec<usize>>,
        visited: &mut HashSet<usize>,
        out: &mut Vec<usize>,
    ) {
        if !visited.insert(idx) {
            return;
        }
        if let Some(kids) = children_of.get(&procs[idx].pid) {
            for &child_idx in kids {
                visit(child_idx, procs, children_of, visited, out);
            }
        }
        out.push(idx);
    }

    let mut visited = HashSet::with_capacity(ordered_nodes.len());
    let mut out = Vec::with_capacity(ordered_nodes.len());
    for idx in ordered_nodes {
        visit(idx, procs, &children_of, &mut visited, &mut out);
    }
    out
}

/// Pure selector building the complete kill tree for a GUI agent (`claude`, `chatgpt`, `antigravity`),
/// ordered **children-first (post-order DFS)** so children terminate before parents and cannot be respawned.
pub fn pick_gui_agent_kill_tree(
    agent_id: &str,
    procs: &[ProcInfo],
    claude_dir_l: Option<&str>,
    ag_dirs_l: &[String],
) -> Vec<ProcessIdentity> {
    let claude_dirs_l: Vec<String> = claude_dir_l
        .into_iter()
        .filter(|s| !s.trim().is_empty())
        .map(ToString::to_string)
        .collect();
    pick_gui_agent_kill_tree_with_dirs(agent_id, procs, &claude_dirs_l, &[], ag_dirs_l)
}

/// Pure selector building the complete GUI kill tree using full covered directory lists,
/// excluding SCM service hosts themselves while traversing through them to catch worker children.
pub fn pick_gui_agent_kill_tree_with_dirs(
    agent_id: &str,
    procs: &[ProcInfo],
    claude_dirs_l: &[String],
    chatgpt_dirs_l: &[String],
    ag_dirs_l: &[String],
) -> Vec<ProcessIdentity> {
    let children_by_ppid = build_children_map(procs);
    let mut selected: HashSet<usize> = HashSet::new();
    let mut queue: Vec<u32> = Vec::new();
    let mut visited_pids: HashSet<u32> = HashSet::new();

    for (idx, p) in procs.iter().enumerate() {
        if is_uninstaller_exe(&p.name_l) || is_any_cli_agent_with_dirs(p, chatgpt_dirs_l) {
            continue;
        }
        if primary_gui_matches_with_dirs(agent_id, p, claude_dirs_l, chatgpt_dirs_l, ag_dirs_l) {
            if !is_agent_scm_service_exe(&p.name_l) {
                selected.insert(idx);
            }
            if visited_pids.insert(p.pid) {
                queue.push(p.pid);
            }
        }
    }

    expand_non_shell_descendants(
        procs,
        &children_by_ppid,
        &mut queue,
        &mut visited_pids,
        &mut selected,
        true,
        chatgpt_dirs_l,
        |child| match agent_id {
            "antigravity" => is_antigravity_dir_proc(child, ag_dirs_l),
            "claude" => claude_dirs_l
                .iter()
                .any(|d| path_under_dir_l(&child.path_l, d)),
            "chatgpt" => {
                chatgpt_dirs_l
                    .iter()
                    .any(|d| path_under_dir_l(&child.path_l, d))
                    || gui_agent_matches("chatgpt", &child.name_l, &child.path_l, None)
            }
            _ => false,
        },
    );

    postorder_indices(&selected, procs)
        .into_iter()
        .map(|idx| procs[idx].identity())
        .collect()
}

/// Pure selector building the complete kill tree for a CLI agent (`claude-code`, `codex`),
/// walking descendant worker/MCP processes children-first and NEVER touching ancestor terminals.
pub fn pick_cli_agent_kill_tree(cli_id: &str, procs: &[ProcInfo]) -> Vec<ProcessIdentity> {
    pick_cli_agent_kill_tree_with_dirs(cli_id, procs, &[])
}

pub fn pick_cli_agent_kill_tree_with_dirs(
    cli_id: &str,
    procs: &[ProcInfo],
    chatgpt_dirs_l: &[String],
) -> Vec<ProcessIdentity> {
    let children_by_ppid = build_children_map(procs);
    let mut selected: HashSet<usize> = HashSet::new();
    let mut queue: Vec<u32> = Vec::new();
    let mut visited_pids: HashSet<u32> = HashSet::new();

    for (idx, p) in procs.iter().enumerate() {
        if is_uninstaller_exe(&p.name_l) || is_agent_scm_service_exe(&p.name_l) {
            continue;
        }
        if cli_agent_matches_with_dirs(cli_id, &p.name_l, &p.path_l, &p.cmd_l, chatgpt_dirs_l) {
            selected.insert(idx);
            if visited_pids.insert(p.pid) {
                queue.push(p.pid);
            }
        }
    }

    expand_non_shell_descendants(
        procs,
        &children_by_ppid,
        &mut queue,
        &mut visited_pids,
        &mut selected,
        false,
        chatgpt_dirs_l,
        |_| false,
    );

    postorder_indices(&selected, procs)
        .into_iter()
        .map(|idx| procs[idx].identity())
        .collect()
}

fn cmd_references_dir_l(cmd_l: &str, dir_l: &str) -> bool {
    let d_cow = strip_verbatim_win32_str(dir_l);
    let clean_d = d_cow
        .trim()
        .trim_end_matches(['\\', '/'])
        .replace('/', "\\");
    if clean_d.is_empty() {
        return false;
    }
    let norm_cmd = cmd_l.replace('/', "\\");
    let mut search_from = 0usize;
    while let Some(rel) = norm_cmd.get(search_from..).and_then(|s| s.find(&clean_d)) {
        let end = search_from + rel + clean_d.len();
        if matches!(norm_cmd.as_bytes().get(end), Some(b'\\')) {
            return true;
        }
        search_from = search_from + rel + 1;
        while search_from < norm_cmd.len() && !norm_cmd.is_char_boundary(search_from) {
            search_from += 1;
        }
    }
    false
}

/// Pure detector for Antigravity residual and mid-run detached crash-orphan processes.
///
/// - **Case A (Full exit residual)**: When NO live root Antigravity GUI exists in `procs`,
///   every remaining Antigravity-dir process (`language_server*.exe`, `antigravity.exe`,
///   `webm_encoder.exe`, etc.), their non-shell helper children, and orphaned Antigravity
///   sidecar/extension `node.exe` processes (`sidecar_sdk`, `.antigravity\extensions`, or `ag_dirs_l`)
///   whose `ppid` is dead are returned (never killing user dev servers in `.gemini\antigravity\scratch`
///   or unrelated user MCP servers).
/// - **Case B (Mid-run detached crash-orphan)**: Even while a live root Antigravity GUI is running,
///   any Antigravity-dir process whose `ppid` ancestor chain does NOT reach any live root Antigravity GUI
///   AND whose immediate `ppid` is dead (plus its non-shell children) is returned.
/// - Indices are ordered **children-first (post-order DFS)**.
pub fn pick_antigravity_orphans(procs: &[ProcInfo], ag_dirs_l: &[String]) -> Vec<usize> {
    if procs.is_empty() {
        return Vec::new();
    }
    let by_pid: HashMap<u32, &ProcInfo> = procs.iter().map(|p| (p.pid, p)).collect();
    let alive_pids: HashSet<u32> = by_pid.keys().copied().collect();
    let live_root_pids: HashSet<u32> = procs
        .iter()
        .filter(|p| is_live_root_antigravity_gui(p, &by_pid))
        .map(|p| p.pid)
        .collect();
    let children_by_ppid = build_children_map(procs);

    let mut selected: HashSet<usize> = HashSet::new();
    let mut queue: Vec<u32> = Vec::new();
    let mut visited_pids: HashSet<u32> = HashSet::new();

    if live_root_pids.is_empty() {
        for (idx, p) in procs.iter().enumerate() {
            if is_uninstaller_exe(&p.name_l)
                || is_agent_scm_service_exe(&p.name_l)
                || is_any_cli_agent(p)
            {
                continue;
            }
            if is_antigravity_dir_proc(p, ag_dirs_l) {
                selected.insert(idx);
                if visited_pids.insert(p.pid) {
                    queue.push(p.pid);
                }
                continue;
            }
            if is_interactive_shell_proc(p) {
                continue;
            }
            if matches!(p.name_l.as_str(), "node.exe" | "node")
                && (p.ppid == 0 || !alive_pids.contains(&p.ppid))
            {
                let norm_cmd = p.cmd_l.replace('/', "\\");
                let has_ag_marker = norm_cmd.contains("sidecar_sdk")
                    || norm_cmd.contains(r".antigravity\extensions")
                    || norm_cmd.contains(r".gemini\antigravity\extensions")
                    || ag_dirs_l.iter().any(|d| {
                        !d.is_empty()
                            && (path_under_dir_l(&p.path_l, d) || cmd_references_dir_l(&p.cmd_l, d))
                    });
                if has_ag_marker {
                    selected.insert(idx);
                    if visited_pids.insert(p.pid) {
                        queue.push(p.pid);
                    }
                }
            }
        }
    } else {
        for (idx, p) in procs.iter().enumerate() {
            if is_agent_scm_service_exe(&p.name_l) || !is_antigravity_dir_proc(p, ag_dirs_l) {
                continue;
            }
            if !reaches_any_root(p.pid, &live_root_pids, &by_pid)
                && (p.ppid == 0 || !alive_pids.contains(&p.ppid))
            {
                selected.insert(idx);
                if visited_pids.insert(p.pid) {
                    queue.push(p.pid);
                }
            }
        }
    }

    expand_non_shell_descendants(
        procs,
        &children_by_ppid,
        &mut queue,
        &mut visited_pids,
        &mut selected,
        true,
        &[],
        |child| is_antigravity_dir_proc(child, ag_dirs_l),
    );

    postorder_indices(&selected, procs)
}

/// Pure detector for Claude Desktop residual and mid-run detached crash-orphan processes
/// (excluding `cowork-svc.exe` and live CLI sessions), ordered **children-first**.
pub fn pick_claude_orphans(procs: &[ProcInfo], claude_dirs_l: &[String]) -> Vec<usize> {
    if procs.is_empty() {
        return Vec::new();
    }
    let by_pid: HashMap<u32, &ProcInfo> = procs.iter().map(|p| (p.pid, p)).collect();
    let alive_pids: HashSet<u32> = by_pid.keys().copied().collect();
    let live_root_pids: HashSet<u32> = procs
        .iter()
        .filter(|p| is_live_root_claude_gui(p, &by_pid, claude_dirs_l))
        .map(|p| p.pid)
        .collect();
    let children_by_ppid = build_children_map(procs);
    let mut selected: HashSet<usize> = HashSet::new();
    let mut queue: Vec<u32> = Vec::new();
    let mut visited_pids: HashSet<u32> = HashSet::new();

    if live_root_pids.is_empty() {
        for (idx, p) in procs.iter().enumerate() {
            if is_claude_desktop_or_dir(p, claude_dirs_l) {
                selected.insert(idx);
                if visited_pids.insert(p.pid) {
                    queue.push(p.pid);
                }
                continue;
            }
            if !is_uninstaller_exe(&p.name_l)
                && !is_agent_scm_service_exe(&p.name_l)
                && !is_any_cli_agent(p)
                && !is_interactive_shell_proc(p)
                && (p.ppid == 0 || !alive_pids.contains(&p.ppid))
                && (p.path_l.contains(r"\anthropicclaude\")
                    || p.cmd_l.contains("anthropicclaude")
                    || p.cmd_l.contains("github-mcp-server")
                    || claude_dirs_l.iter().any(|d| {
                        !d.is_empty()
                            && (path_under_dir_l(&p.path_l, d) || cmd_references_dir_l(&p.cmd_l, d))
                    }))
            {
                selected.insert(idx);
                if visited_pids.insert(p.pid) {
                    queue.push(p.pid);
                }
            }
        }
    } else {
        for (idx, p) in procs.iter().enumerate() {
            if !is_claude_desktop_or_dir(p, claude_dirs_l) {
                continue;
            }
            if !reaches_any_root(p.pid, &live_root_pids, &by_pid)
                && (p.ppid == 0 || !alive_pids.contains(&p.ppid))
            {
                selected.insert(idx);
                if visited_pids.insert(p.pid) {
                    queue.push(p.pid);
                }
            }
        }
    }

    expand_non_shell_descendants(
        procs,
        &children_by_ppid,
        &mut queue,
        &mut visited_pids,
        &mut selected,
        true,
        &[],
        |child| {
            claude_dirs_l
                .iter()
                .any(|d| path_under_dir_l(&child.path_l, d))
        },
    );

    postorder_indices(&selected, procs)
}

/// Pure detector for ChatGPT / Codex Desktop residual and mid-run detached crash-orphan processes
/// (`resources\codex.exe`, `codex-command-runner.exe`, `cua_node\bin\node.exe`,
/// `codex-computer-use*.exe`, `winpty-agent.exe`, etc., excluding SCM services), ordered **children-first**.
pub fn pick_chatgpt_codex_orphans(procs: &[ProcInfo], chatgpt_dirs_l: &[String]) -> Vec<usize> {
    if procs.is_empty() {
        return Vec::new();
    }
    let by_pid: HashMap<u32, &ProcInfo> = procs.iter().map(|p| (p.pid, p)).collect();
    let alive_pids: HashSet<u32> = by_pid.keys().copied().collect();
    let live_root_pids: HashSet<u32> = procs
        .iter()
        .filter(|p| is_live_root_chatgpt_codex_gui(p, &by_pid, chatgpt_dirs_l))
        .map(|p| p.pid)
        .collect();
    let children_by_ppid = build_children_map(procs);
    let mut selected: HashSet<usize> = HashSet::new();
    let mut queue: Vec<u32> = Vec::new();
    let mut visited_pids: HashSet<u32> = HashSet::new();

    if live_root_pids.is_empty() {
        for (idx, p) in procs.iter().enumerate() {
            if is_chatgpt_codex_dir_or_gui(p, chatgpt_dirs_l) {
                selected.insert(idx);
                if visited_pids.insert(p.pid) {
                    queue.push(p.pid);
                }
                continue;
            }
            if !is_uninstaller_exe(&p.name_l)
                && !is_agent_scm_service_exe(&p.name_l)
                && !is_any_cli_agent_with_dirs(p, chatgpt_dirs_l)
                && !is_interactive_shell_proc(p)
                && (p.ppid == 0 || !alive_pids.contains(&p.ppid))
                && (p.path_l.contains(r"\windowsapps\openai.")
                    || p.cmd_l.contains("openai.codex_")
                    || p.cmd_l.contains("openai.chatgpt")
                    || chatgpt_dirs_l.iter().any(|d| {
                        !d.is_empty()
                            && (path_under_dir_l(&p.path_l, d) || cmd_references_dir_l(&p.cmd_l, d))
                    }))
            {
                selected.insert(idx);
                if visited_pids.insert(p.pid) {
                    queue.push(p.pid);
                }
            }
        }
    } else {
        for (idx, p) in procs.iter().enumerate() {
            if !is_chatgpt_codex_dir_or_gui(p, chatgpt_dirs_l) {
                continue;
            }
            if !reaches_any_root(p.pid, &live_root_pids, &by_pid)
                && (p.ppid == 0 || !alive_pids.contains(&p.ppid))
            {
                selected.insert(idx);
                if visited_pids.insert(p.pid) {
                    queue.push(p.pid);
                }
            }
        }
    }

    expand_non_shell_descendants(
        procs,
        &children_by_ppid,
        &mut queue,
        &mut visited_pids,
        &mut selected,
        true,
        chatgpt_dirs_l,
        |child| {
            chatgpt_dirs_l
                .iter()
                .any(|d| path_under_dir_l(&child.path_l, d))
                || gui_agent_matches("chatgpt", &child.name_l, &child.path_l, None)
        },
    );

    postorder_indices(&selected, procs)
}

/// Pure detector for orphaned CLI sessions (`claude-code`, `codex`) whose launching
/// parent terminal (`ppid`) is dead, plus their non-shell descendant helpers, ordered **children-first**.
pub fn pick_cli_orphans(cli_id: &str, procs: &[ProcInfo]) -> Vec<usize> {
    pick_cli_orphans_with_dirs(cli_id, procs, &[])
}

pub fn pick_cli_orphans_with_dirs(
    cli_id: &str,
    procs: &[ProcInfo],
    chatgpt_dirs_l: &[String],
) -> Vec<usize> {
    if procs.is_empty() {
        return Vec::new();
    }
    let alive_pids: HashSet<u32> = procs.iter().map(|p| p.pid).collect();
    let children_by_ppid = build_children_map(procs);
    let mut selected: HashSet<usize> = HashSet::new();
    let mut queue: Vec<u32> = Vec::new();
    let mut visited_pids: HashSet<u32> = HashSet::new();

    for (idx, p) in procs.iter().enumerate() {
        if is_uninstaller_exe(&p.name_l) || is_agent_scm_service_exe(&p.name_l) {
            continue;
        }
        if cli_agent_matches_with_dirs(cli_id, &p.name_l, &p.path_l, &p.cmd_l, chatgpt_dirs_l)
            && (p.ppid == 0 || !alive_pids.contains(&p.ppid))
        {
            selected.insert(idx);
            if visited_pids.insert(p.pid) {
                queue.push(p.pid);
            }
        }
    }

    expand_non_shell_descendants(
        procs,
        &children_by_ppid,
        &mut queue,
        &mut visited_pids,
        &mut selected,
        false,
        chatgpt_dirs_l,
        |_| false,
    );

    postorder_indices(&selected, procs)
}

/// Claude family classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaudeKind {
    Desktop,
    Cli,
}

impl ClaudeKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Desktop => "桌面端",
            Self::Cli => "CLI",
        }
    }
}

/// Classify a process as Claude Desktop vs Claude Code CLI (excluding SCM service hosts).
pub fn classify_claude(p: &ProcInfo, claude_dir_l: Option<&str>) -> Option<ClaudeKind> {
    let dirs: Vec<String> = claude_dir_l
        .into_iter()
        .filter(|s| !s.trim().is_empty())
        .map(ToString::to_string)
        .collect();
    classify_claude_with_dirs(p, &dirs)
}

pub fn classify_claude_with_dirs(p: &ProcInfo, claude_dirs_l: &[String]) -> Option<ClaudeKind> {
    if is_uninstaller_exe(&p.name_l) || is_agent_scm_service_exe(&p.name_l) {
        return None;
    }
    if cli_agent_matches("claude-code", &p.name_l, &p.path_l, &p.cmd_l) {
        return Some(ClaudeKind::Cli);
    }
    if gui_agent_matches(
        "claude",
        &p.name_l,
        &p.path_l,
        claude_dirs_l.first().map(String::as_str),
    ) || claude_dirs_l.iter().any(|d| path_under_dir_l(&p.path_l, d))
    {
        return Some(ClaudeKind::Desktop);
    }
    None
}

/// Select all Claude processes (Desktop + CLI) for explicit manual sweep, ordered **children-first**.
pub fn pick_manual(procs: &[ProcInfo], claude_dir_l: Option<&str>) -> Vec<(usize, ClaudeKind)> {
    let dirs: Vec<String> = claude_dir_l
        .into_iter()
        .filter(|s| !s.trim().is_empty())
        .map(ToString::to_string)
        .collect();
    pick_manual_with_dirs(procs, &dirs)
}

pub fn pick_manual_with_dirs(
    procs: &[ProcInfo],
    claude_dirs_l: &[String],
) -> Vec<(usize, ClaudeKind)> {
    let mut kind_by_idx: HashMap<usize, ClaudeKind> = HashMap::new();
    let mut selected: HashSet<usize> = HashSet::new();
    for (i, p) in procs.iter().enumerate() {
        if let Some(k) = classify_claude_with_dirs(p, claude_dirs_l) {
            kind_by_idx.insert(i, k);
            selected.insert(i);
        }
    }
    postorder_indices(&selected, procs)
        .into_iter()
        .filter_map(|idx| kind_by_idx.get(&idx).copied().map(|k| (idx, k)))
        .collect()
}

/// Select only orphaned residual Claude processes after live root `Claude.exe` GUI has exited.
///
/// - Returns `None` while any live root `Claude.exe` GUI process is still running.
/// - Sweeps orphaned desktop auxiliary processes (`--type=gpu-process`, `crashpad`, `github-mcp-server`,
///   and their non-shell descendants) ordered **children-first**.
/// - CLI processes are selected ONLY when their parent terminal (`ppid`) is dead.
pub fn pick_residual(
    procs: &[ProcInfo],
    claude_dir_l: Option<&str>,
) -> Option<Vec<(usize, ClaudeKind)>> {
    let dirs: Vec<String> = claude_dir_l
        .into_iter()
        .filter(|s| !s.trim().is_empty())
        .map(ToString::to_string)
        .collect();
    pick_residual_with_dirs(procs, &dirs)
}

pub fn pick_residual_with_dirs(
    procs: &[ProcInfo],
    claude_dirs_l: &[String],
) -> Option<Vec<(usize, ClaudeKind)>> {
    let by_pid: HashMap<u32, &ProcInfo> = procs.iter().map(|p| (p.pid, p)).collect();
    if procs
        .iter()
        .any(|p| is_live_root_claude_gui(p, &by_pid, claude_dirs_l))
    {
        return None;
    }

    let desktop_orphans = pick_claude_orphans(procs, claude_dirs_l);
    let cli_orphans = pick_cli_orphans("claude-code", procs);

    let mut seen_pids = HashSet::new();
    let mut out = Vec::with_capacity(desktop_orphans.len() + cli_orphans.len());
    for idx in desktop_orphans {
        if seen_pids.insert(procs[idx].pid) {
            out.push((idx, ClaudeKind::Desktop));
        }
    }
    for idx in cli_orphans {
        if seen_pids.insert(procs[idx].pid) {
            out.push((idx, ClaudeKind::Cli));
        }
    }
    Some(out)
}

/// Sweep mode selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SweepMode {
    Manual,
    Residual,
}

/// Result of a residual/manual orphan sweep.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SweepReport {
    pub scanned: usize,
    pub killed: usize,
    pub desktop_killed: usize,
    pub cli_killed: usize,
    pub unconfirmed: usize,
    pub detail: Vec<String>,
    pub note: String,
}

/// Numeric package version key: `Claude_2.10.0.0_x64__hash` -> `[2, 10, 0, 0]`.
pub fn version_key(name: &str) -> Vec<u64> {
    let seg = name.split('_').nth(1).unwrap_or("");
    seg.split('.')
        .map(|p| p.parse::<u64>().unwrap_or(0))
        .collect()
}

/// Sort `(package_full_name, root_dir)` pairs newest-first by `version_key`.
pub fn sort_packages_newest_first(packages: &mut [(String, PathBuf)]) {
    packages.sort_by_key(|a| std::cmp::Reverse(version_key(&a.0)));
}

/// Deduplicate covered directories from AppModel registered packages (newest-first),
/// falling back to `fallback` ONLY when `packages` is empty.
pub fn covered_dirs_from(
    packages: &[(String, PathBuf)],
    fallback: Option<PathBuf>,
) -> Vec<PathBuf> {
    let mut sorted = packages.to_vec();
    sort_packages_newest_first(&mut sorted);
    let mut out = Vec::new();
    for (_, dir) in sorted {
        if !out.contains(&dir) {
            out.push(dir);
        }
    }
    if out.is_empty() {
        if let Some(dir) = fallback {
            out.push(dir);
        }
    }
    out
}

fn normalize_path_key_l(path: &Path) -> String {
    let raw = path.to_string_lossy();
    let stripped = strip_verbatim_win32_str(&raw);
    stripped
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

fn contains_path_ci(list: &[PathBuf], candidate: &Path) -> bool {
    let cand = normalize_path_key_l(candidate);
    list.iter()
        .any(|existing| normalize_path_key_l(existing) == cand)
}

/// Collect `.exe` files recursively up to `max_depth`, skipping uninstallers and applying `predicate`
/// on the lowercased file name.
pub fn collect_exes_matching<F>(
    dir: &Path,
    depth: u32,
    max_depth: u32,
    predicate: &F,
    out: &mut Vec<PathBuf>,
) where
    F: Fn(&str) -> bool,
{
    if depth > max_depth {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
    entries.sort_by(|a, b| {
        a.file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_ascii_lowercase()
            .cmp(
                &b.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_ascii_lowercase(),
            )
    });
    for p in entries {
        if p.is_dir() {
            collect_exes_matching(&p, depth + 1, max_depth, predicate, out);
        } else if p
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
        {
            let name_l = p
                .file_name()
                .map(|n| n.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            if !is_uninstaller_exe(&name_l) && predicate(&name_l) && !contains_path_ci(out, &p) {
                out.push(p);
            }
        }
    }
}

/// Collect `.exe` files recursively up to `max_depth`, skipping uninstaller binaries.
pub fn collect_exes_filtered(dir: &Path, depth: u32, max_depth: u32, out: &mut Vec<PathBuf>) {
    collect_exes_matching(dir, depth, max_depth, &|_| true, out);
}

/// Derive `Claude_pzs8sxrjxfjjc` PackageFamilyName from `Claude_2.16120.0.0_x64__pzs8sxrjxfjjc`.
pub fn family_name_from_dir(dir: &Path) -> Option<String> {
    let name = dir.file_name()?.to_string_lossy().to_string();
    let (pkg, hash) = name.split_once("__")?;
    let base = pkg.split('_').next()?;
    if base.is_empty() || hash.is_empty() {
        return None;
    }
    Some(format!("{base}_{hash}"))
}

/// Extract the numeric version segment (`"5.1231.2.0"`) from an MSIX package full name
/// (e.g., `"Claude_5.1231.2.0_x64__pzs8sxrjxfjjc"`).
pub fn msix_version_from_package_name(pkg_name: &str) -> Option<String> {
    let seg = pkg_name.split('_').nth(1)?.trim();
    if seg.is_empty() || !seg.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return None;
    }
    Some(seg.to_string())
}

/// Filter `HKEY_USERS` subkeys, skipping `.DEFAULT` and `*_Classes` hives.
pub fn is_valid_user_sid_subkey(sid_name: &str) -> bool {
    let trimmed = sid_name.trim();
    !trimmed.is_empty()
        && !trimmed.eq_ignore_ascii_case(".DEFAULT")
        && !trimmed.to_ascii_lowercase().ends_with("_classes")
}

/// Sort `(package_full_name, root_dir)` newest-first and deduplicate by case-insensitive `PackageRootFolder`.
pub fn dedup_and_sort_packages(mut packages: Vec<(String, PathBuf)>) -> Vec<(String, PathBuf)> {
    sort_packages_newest_first(&mut packages);
    let mut seen_dirs = HashSet::new();
    let mut out = Vec::with_capacity(packages.len());
    for (name, dir) in packages {
        let key = normalize_path_key_l(&dir);
        if !key.is_empty() && seen_dirs.insert(key) {
            out.push((name, dir));
        }
    }
    out
}

pub(crate) fn package_name_matches_prefix(pkg_name: &str, family_prefix: &str) -> bool {
    strip_ascii_prefix_ci(pkg_name, family_prefix).is_some()
}

#[cfg(windows)]
fn scan_appmodel_packages_under(
    hive_root: &winreg::RegKey,
    subkey_path: &str,
    family_prefix: &str,
    out: &mut Vec<(String, PathBuf)>,
) {
    let Ok(key) = hive_root.open_subkey(subkey_path) else {
        return;
    };
    for name in key.enum_keys().flatten() {
        if !package_name_matches_prefix(&name, family_prefix) {
            continue;
        }
        let Ok(sub) = key.open_subkey(&name) else {
            continue;
        };
        let Ok(root) = sub.get_value::<String, _>("PackageRootFolder") else {
            continue;
        };
        let path = PathBuf::from(root);
        if path.is_dir() {
            out.push((name, path));
        }
    }
}

#[cfg(windows)]
fn registered_package_dirs(family_prefix: &str) -> Vec<(String, PathBuf)> {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS};
    use winreg::RegKey;

    const REPO_USER: &str = r"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages";
    const REPO_MACHINE: &str = r"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages";

    let mut found = Vec::new();

    // (a) Current user HKCU
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    scan_appmodel_packages_under(&hkcu, REPO_USER, family_prefix, &mut found);

    // (b) All loaded user SID hives under HKEY_USERS (vital when daemon runs as LocalSystem service)
    let hku = RegKey::predef(HKEY_USERS);
    for sid in hku.enum_keys().flatten() {
        if !is_valid_user_sid_subkey(&sid) {
            continue;
        }
        let Ok(sid_key) = hku.open_subkey(&sid) else {
            continue;
        };
        scan_appmodel_packages_under(&sid_key, REPO_USER, family_prefix, &mut found);
    }

    // (c) System-wide HKLM
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    scan_appmodel_packages_under(&hklm, REPO_MACHINE, family_prefix, &mut found);

    dedup_and_sort_packages(found)
}

#[cfg(not(windows))]
fn registered_package_dirs(_family_prefix: &str) -> Vec<(String, PathBuf)> {
    Vec::new()
}

/// Return the newest installed MSIX package version (e.g. `"5.1231.2.0"` or `"26.1111.2228.0"`)
/// for `family_prefix` across HKCU / HKEY_USERS / HKLM, falling back to `WindowsApps` folder name.
pub fn installed_msix_version(family_prefix: &str) -> Option<String> {
    if let Some((pkg_name, _)) = registered_package_dirs(family_prefix).into_iter().next() {
        if let Some(ver) = msix_version_from_package_name(&pkg_name) {
            return Some(ver);
        }
    }
    find_windowsapps_dir(family_prefix).and_then(|dir| {
        dir.file_name()
            .and_then(|n| msix_version_from_package_name(&n.to_string_lossy()))
    })
}

pub(crate) fn find_windowsapps_dir_in(root: &Path, prefix: &str) -> Option<PathBuf> {
    let mut best: Option<(Vec<u64>, std::ffi::OsString)> = None;
    if let Ok(rd) = std::fs::read_dir(root) {
        for entry in rd.flatten() {
            let s = entry.file_name().to_string_lossy().to_string();
            if package_name_matches_prefix(&s, prefix) && s.contains("__") {
                let key = version_key(&s);
                if best.as_ref().is_none_or(|(k, _)| key > *k) {
                    best = Some((key, entry.file_name()));
                }
            }
        }
    }
    best.map(|(_, n)| root.join(n))
}

fn find_windowsapps_dir(prefix: &str) -> Option<PathBuf> {
    find_windowsapps_dir_in(Path::new(r"C:\Program Files\WindowsApps"), prefix)
}

fn is_skipped_system_user_dir(name: &str) -> bool {
    matches!(
        name.trim().to_ascii_lowercase().as_str(),
        "public"
            | "default"
            | "default user"
            | "all users"
            | "systemprofile"
            | "localservice"
            | "networkservice"
    )
}

fn is_systemprofile_path(path: &Path) -> bool {
    let key = normalize_path_key_l(path);
    key.ends_with(r"\system32\config\systemprofile")
        || key.ends_with(r"\syswow64\config\systemprofile")
}

pub(crate) fn expand_profile_image_path_with_drive(raw: &str, system_drive: &str) -> PathBuf {
    let trimmed = raw.trim().trim_matches('"').trim();
    let drive = system_drive.trim().trim_end_matches(['\\', '/']);
    if let Some(rest) = strip_ascii_prefix_ci(trimmed, "%systemdrive%") {
        return PathBuf::from(format!("{drive}{rest}"));
    }
    PathBuf::from(trimmed)
}

fn expand_profile_image_path(raw: &str) -> PathBuf {
    let drive = std::env::var("SystemDrive")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "C:".to_string());
    expand_profile_image_path_with_drive(raw, &drive)
}

#[cfg(windows)]
fn profile_list_entries() -> Vec<(String, PathBuf)> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let Ok(profile_list) = hklm.open_subkey_with_flags(
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList",
        KEY_READ,
    ) else {
        return Vec::new();
    };

    let active_sid = crate::access_win::active_interactive_user_sid();
    let mut entries: Vec<(bool, String, String, PathBuf)> = Vec::new();

    for sid in profile_list.enum_keys().flatten() {
        if !crate::access_win::is_interactive_user_sid(&sid) {
            continue;
        }
        let Ok(sub) = profile_list.open_subkey_with_flags(&sid, KEY_READ) else {
            continue;
        };
        let Ok(raw_img) = sub.get_value::<String, _>("ProfileImagePath") else {
            continue;
        };
        let path = expand_profile_image_path(&raw_img);
        if !path.is_dir() || is_systemprofile_path(&path) {
            continue;
        }
        if let Some(fname) = path.file_name().map(|n| n.to_string_lossy()) {
            if is_skipped_system_user_dir(&fname) {
                continue;
            }
        }
        let is_active = active_sid
            .as_deref()
            .is_some_and(|a| a.eq_ignore_ascii_case(&sid));
        let sort_key = normalize_path_key_l(&path);
        entries.push((is_active, sort_key, sid, path));
    }

    // Active console/RDP user first (`!is_active` == false < true), then deterministic path order.
    entries.sort_by(|a, b| (!a.0).cmp(&(!b.0)).then_with(|| a.1.cmp(&b.1)));
    entries
        .into_iter()
        .map(|(_, _, sid, path)| (sid, path))
        .collect()
}

#[cfg(not(windows))]
fn profile_list_entries() -> Vec<(String, PathBuf)> {
    Vec::new()
}

fn users_root_dir() -> PathBuf {
    std::env::var("SystemDrive")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(|d| PathBuf::from(format!(r"{}\Users", d.trim().trim_end_matches(['\\', '/']))))
        .unwrap_or_else(|| PathBuf::from(r"C:\Users"))
}

fn collect_sorted_user_homes(users_root: &Path) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(users_root) else {
        return Vec::new();
    };
    let mut entries: Vec<(String, PathBuf)> = rd
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            if !path.is_dir() {
                return None;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if is_skipped_system_user_dir(&name) {
                return None;
            }
            Some((name.to_ascii_lowercase(), path))
        })
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries.into_iter().map(|(_, p)| p).collect()
}

/// Testable resolver collecting per-user `%LOCALAPPDATA%\<subdir>` paths across explicit roots.
pub fn per_user_local_app_subdirs_from_roots(
    local_app_data: Option<&Path>,
    user_profile: Option<&Path>,
    users_root: Option<&Path>,
    rel_subdirs: &[&str],
) -> Vec<PathBuf> {
    let mut local_bases = Vec::new();
    if let Some(local) = local_app_data {
        local_bases.push(local.to_path_buf());
    }
    if let Some(profile) = user_profile {
        local_bases.push(profile.join("AppData").join("Local"));
    }
    if let Some(users) = users_root {
        for user_dir in collect_sorted_user_homes(users) {
            local_bases.push(user_dir.join("AppData").join("Local"));
        }
    }

    let mut seen_keys = HashSet::new();
    let mut dirs = Vec::new();
    for base in local_bases {
        for sub in rel_subdirs {
            let dir = base.join(sub);
            if !dir.is_dir() {
                continue;
            }
            let key = normalize_path_key_l(&dir);
            if seen_keys.insert(key) {
                dirs.push(dir);
            }
        }
    }
    dirs
}

/// Collect per-user `AppData\Local\<subdir>` directories across `ProfileList` (active user first),
/// current interactive user env, and `C:\Users\*`.
pub fn per_user_local_app_subdirs(rel_subdirs: &[&str]) -> Vec<PathBuf> {
    let mut local_bases = Vec::new();
    if !crate::access_win::is_session_zero() {
        if let Some(local) = std::env::var_os("LOCALAPPDATA").map(PathBuf::from) {
            if !is_systemprofile_path(&local) {
                local_bases.push(local);
            }
        }
    }
    for home in user_home_dirs() {
        local_bases.push(home.join("AppData").join("Local"));
    }

    let mut seen_keys = HashSet::new();
    let mut dirs = Vec::new();
    for base in local_bases {
        for sub in rel_subdirs {
            let dir = base.join(sub);
            if !dir.is_dir() {
                continue;
            }
            let key = normalize_path_key_l(&dir);
            if seen_keys.insert(key) {
                dirs.push(dir);
            }
        }
    }
    dirs
}

/// Collect deduplicated user home directories (`%USERPROFILE%` + `C:\Users\*`), supporting `LocalSystem`.
pub fn user_home_dirs_from_roots(
    user_profile: Option<&Path>,
    users_root: Option<&Path>,
) -> Vec<PathBuf> {
    let mut homes = Vec::new();
    let mut seen = HashSet::new();
    if let Some(profile) = user_profile {
        if profile.is_dir()
            && !is_systemprofile_path(profile)
            && seen.insert(normalize_path_key_l(profile))
        {
            homes.push(profile.to_path_buf());
        }
    }
    if let Some(users) = users_root {
        for home in collect_sorted_user_homes(users) {
            if seen.insert(normalize_path_key_l(&home)) {
                homes.push(home);
            }
        }
    }
    homes
}

/// Collect real interactive user homes: `ProfileList` (with `active_interactive_user_sid` first),
/// followed by `%USERPROFILE%` (non-`systemprofile`) and `C:\Users\*` fallback.
pub fn user_home_dirs() -> Vec<PathBuf> {
    let mut homes = Vec::new();
    let mut seen = HashSet::new();

    for (_, path) in profile_list_entries() {
        let key = normalize_path_key_l(&path);
        if !key.is_empty() && seen.insert(key) {
            homes.push(path);
        }
    }
    if !crate::access_win::is_session_zero() {
        if let Some(profile) = std::env::var_os("USERPROFILE").map(PathBuf::from) {
            if profile.is_dir() && !is_systemprofile_path(&profile) {
                let key = normalize_path_key_l(&profile);
                if !key.is_empty() && seen.insert(key) {
                    homes.push(profile);
                }
            }
        }
    }
    let users_root = users_root_dir();
    for home in collect_sorted_user_homes(&users_root) {
        let key = normalize_path_key_l(&home);
        if !key.is_empty() && seen.insert(key) {
            homes.push(home);
        }
    }
    homes
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct UninstallRecord {
    pub key_name: String,
    pub display_name: String,
    pub display_version: Option<String>,
    pub install_dir: Option<PathBuf>,
}

pub(crate) fn extract_install_dir_from_uninstall_values(
    install_location: Option<&str>,
    display_icon: Option<&str>,
) -> Option<PathBuf> {
    if let Some(loc) = install_location
        .map(|s| s.trim().trim_matches('"').trim())
        .filter(|s| !s.is_empty())
    {
        return Some(PathBuf::from(loc));
    }
    let icon = display_icon?.trim();
    if icon.is_empty() {
        return None;
    }
    let without_index = match icon.rsplit_once(',') {
        Some((before, idx))
            if !idx.trim().is_empty()
                && idx
                    .trim()
                    .trim_start_matches('-')
                    .bytes()
                    .all(|b| b.is_ascii_digit()) =>
        {
            before.trim()
        }
        _ => icon,
    };
    let clean = without_index.trim_matches('"').trim();
    if !clean.to_ascii_lowercase().ends_with(".exe") {
        return None;
    }
    Path::new(clean).parent().map(Path::to_path_buf)
}

#[cfg(windows)]
fn scan_uninstall_subkey(hive: &winreg::RegKey, subkey_path: &str, out: &mut Vec<UninstallRecord>) {
    use winreg::enums::KEY_READ;

    let Ok(uninstall) = hive.open_subkey_with_flags(subkey_path, KEY_READ) else {
        return;
    };
    for key_name in uninstall.enum_keys().flatten() {
        let Ok(sub) = uninstall.open_subkey_with_flags(&key_name, KEY_READ) else {
            continue;
        };
        let display_name: String = sub.get_value("DisplayName").unwrap_or_default();
        if display_name.trim().is_empty() && key_name.trim().is_empty() {
            continue;
        }
        let display_version: Option<String> = sub
            .get_value::<String, _>("DisplayVersion")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let install_location: Option<String> = sub.get_value("InstallLocation").ok();
        let display_icon: Option<String> = sub.get_value("DisplayIcon").ok();
        let install_dir = extract_install_dir_from_uninstall_values(
            install_location.as_deref(),
            display_icon.as_deref(),
        );
        out.push(UninstallRecord {
            key_name,
            display_name: display_name.trim().to_string(),
            display_version,
            install_dir,
        });
    }
}

const DISCOVERY_CACHE_TTL: Duration = Duration::from_secs(45);

#[derive(Clone, Debug)]
struct DiscoveryCacheState {
    populated_at: Instant,
    uninstall_records: Vec<UninstallRecord>,
    claude_dirs: Vec<PathBuf>,
    chatgpt_dirs: Vec<PathBuf>,
    antigravity_dirs: Vec<PathBuf>,
}

fn discovery_cache_slot() -> &'static Mutex<Option<DiscoveryCacheState>> {
    static SLOT: std::sync::OnceLock<Mutex<Option<DiscoveryCacheState>>> =
        std::sync::OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}

/// Invalidates the 45-second covered-directory & Uninstall registry cache so newly installed or
/// repaired client directories are picked up immediately on the next query.
pub fn invalidate_discovery_cache() {
    let mut guard = discovery_cache_slot()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    *guard = None;
}

fn with_discovery_cache<R>(f: impl FnOnce(&DiscoveryCacheState) -> R) -> R {
    {
        let guard = discovery_cache_slot()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(ref state) = *guard {
            if state.populated_at.elapsed() < DISCOVERY_CACHE_TTL {
                return f(state);
            }
        }
    }

    let uninstall_records = scan_uninstall_records_uncached();
    let claude_dirs = compute_claude_covered_dirs(&uninstall_records);
    let chatgpt_dirs = compute_chatgpt_covered_dirs(&uninstall_records);
    let antigravity_dirs = compute_antigravity_covered_dirs(&uninstall_records);
    let fresh = DiscoveryCacheState {
        populated_at: Instant::now(),
        uninstall_records,
        claude_dirs,
        chatgpt_dirs,
        antigravity_dirs,
    };
    let out = f(&fresh);
    let mut guard = discovery_cache_slot()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    *guard = Some(fresh);
    out
}

fn scan_uninstall_records() -> Vec<UninstallRecord> {
    with_discovery_cache(|c| c.uninstall_records.clone())
}

#[cfg(windows)]
fn scan_uninstall_records_uncached() -> Vec<UninstallRecord> {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS};
    use winreg::RegKey;

    const UNINSTALL_MACHINE: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    const UNINSTALL_WOW64: &str =
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";
    const UNINSTALL_USER: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall";

    let mut out = Vec::new();
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    scan_uninstall_subkey(&hklm, UNINSTALL_MACHINE, &mut out);
    scan_uninstall_subkey(&hklm, UNINSTALL_WOW64, &mut out);

    if !crate::access_win::is_session_zero() {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        scan_uninstall_subkey(&hkcu, UNINSTALL_USER, &mut out);
    }

    let hku = RegKey::predef(HKEY_USERS);
    let active_sid = crate::access_win::active_interactive_user_sid();
    if let Some(ref sid) = active_sid {
        if let Ok(sid_key) = hku.open_subkey(sid) {
            scan_uninstall_subkey(&sid_key, UNINSTALL_USER, &mut out);
        }
    }
    for sid in hku.enum_keys().flatten() {
        if !is_valid_user_sid_subkey(&sid) {
            continue;
        }
        if active_sid
            .as_deref()
            .is_some_and(|a| a.eq_ignore_ascii_case(&sid))
        {
            continue;
        }
        if let Ok(sid_key) = hku.open_subkey(&sid) {
            scan_uninstall_subkey(&sid_key, UNINSTALL_USER, &mut out);
        }
    }
    out
}

#[cfg(not(windows))]
fn scan_uninstall_records_uncached() -> Vec<UninstallRecord> {
    Vec::new()
}

fn merge_covered_dirs(primary: Vec<PathBuf>, extra: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut out = Vec::with_capacity(primary.len() + extra.len());
    let mut seen = HashSet::new();
    for dir in primary.into_iter().chain(extra) {
        let key = normalize_path_key_l(&dir);
        if !key.is_empty() && seen.insert(key) {
            out.push(dir);
        }
    }
    out
}

fn compute_claude_covered_dirs(uninstall_records: &[UninstallRecord]) -> Vec<PathBuf> {
    let msix = covered_dirs_from(
        &registered_package_dirs("Claude_"),
        find_windowsapps_dir("Claude_"),
    );
    let per_user = per_user_local_app_subdirs(&["AnthropicClaude", r"Programs\claude"]);
    let mut reg_dirs = Vec::new();
    for rec in uninstall_records {
        let dn = rec.display_name.to_ascii_lowercase();
        let kn = rec.key_name.to_ascii_lowercase();
        if (dn == "claude" || dn.contains("anthropicclaude") || kn.contains("anthropicclaude"))
            && !dn.contains("claudeguard")
            && !dn.contains("claude code")
        {
            if let Some(dir) = rec.install_dir.as_ref().filter(|d| d.is_dir()) {
                reg_dirs.push(dir.clone());
            }
        }
    }
    merge_covered_dirs(merge_covered_dirs(msix, per_user), reg_dirs)
}

pub fn claude_covered_dirs() -> Vec<PathBuf> {
    with_discovery_cache(|c| c.claude_dirs.clone())
}

fn compute_chatgpt_covered_dirs(uninstall_records: &[UninstallRecord]) -> Vec<PathBuf> {
    let mut pkgs = registered_package_dirs("OpenAI.Codex_");
    pkgs.extend(registered_package_dirs("OpenAI.ChatGPT_"));
    pkgs.extend(registered_package_dirs("OpenAI.ChatGPT-Desktop_"));
    let pkgs = dedup_and_sort_packages(pkgs);

    let mut msix = covered_dirs_from(&pkgs, find_windowsapps_dir("OpenAI.Codex_"));
    for fallback_prefix in ["OpenAI.ChatGPT_", "OpenAI.ChatGPT-Desktop_"] {
        if let Some(fallback_gpt) = find_windowsapps_dir(fallback_prefix) {
            if !contains_path_ci(&msix, &fallback_gpt) {
                msix.push(fallback_gpt);
            }
        }
    }
    let per_user = per_user_local_app_subdirs(&[
        r"Programs\ChatGPT",
        r"Programs\ChatGPT Classic",
        r"Programs\Codex",
    ]);
    let mut reg_dirs = Vec::new();
    for rec in uninstall_records {
        let dn = rec.display_name.to_ascii_lowercase();
        if dn.contains("chatgpt") || dn == "codex" || dn == "openai codex" {
            if let Some(dir) = rec.install_dir.as_ref().filter(|d| d.is_dir()) {
                reg_dirs.push(dir.clone());
            }
        }
    }
    merge_covered_dirs(merge_covered_dirs(msix, per_user), reg_dirs)
}

pub fn chatgpt_covered_dirs() -> Vec<PathBuf> {
    with_discovery_cache(|c| c.chatgpt_dirs.clone())
}

/// Testable multi-user Antigravity directory resolver supporting `LocalSystem` Windows Services
/// (where `%LOCALAPPDATA%` points to `systemprofile` instead of `C:\Users\<User>\AppData\Local`).
pub fn antigravity_covered_dirs_from_roots(
    local_app_data: Option<&Path>,
    user_profile: Option<&Path>,
    users_root: Option<&Path>,
) -> Vec<PathBuf> {
    per_user_local_app_subdirs_from_roots(
        local_app_data,
        user_profile,
        users_root,
        &[r"Programs\antigravity", r"Programs\Antigravity IDE"],
    )
}

fn compute_antigravity_covered_dirs(uninstall_records: &[UninstallRecord]) -> Vec<PathBuf> {
    let per_user =
        per_user_local_app_subdirs(&[r"Programs\antigravity", r"Programs\Antigravity IDE"]);
    let mut reg_dirs = Vec::new();
    for rec in uninstall_records {
        let dn = rec.display_name.to_ascii_lowercase();
        let kn = rec.key_name.to_ascii_lowercase();
        if (dn.contains("antigravity") || kn.contains("antigravity"))
            && !dn.contains("desktop-cn")
            && !dn.contains("launcher")
        {
            if let Some(dir) = rec.install_dir.as_ref().filter(|d| {
                d.is_dir()
                    && (d.join("Antigravity.exe").is_file()
                        || d.join("Antigravity IDE.exe").is_file()
                        || d.join("resources").is_dir())
            }) {
                reg_dirs.push(dir.clone());
            }
        }
    }
    for env_key in ["ProgramFiles", "ProgramFiles(x86)"] {
        if let Some(pf) = std::env::var_os(env_key).map(PathBuf::from) {
            for sub in ["Antigravity", "Antigravity IDE"] {
                let d = pf.join(sub);
                if d.is_dir()
                    && (d.join("Antigravity.exe").is_file()
                        || d.join("Antigravity IDE.exe").is_file())
                {
                    reg_dirs.push(d);
                }
            }
        }
    }
    merge_covered_dirs(per_user, reg_dirs)
}

/// Discover all Antigravity installation directories across `ProfileList` user homes, `C:\Users\*`,
/// and custom WinReg `Uninstall` install locations (cached with 45s TTL).
pub fn antigravity_covered_dirs() -> Vec<PathBuf> {
    with_discovery_cache(|c| c.antigravity_dirs.clone())
}

/// Discover all covered executables inside `dirs` up to `max_depth = 5`, placing main GUI
/// launchers (`Antigravity.exe` / `Antigravity IDE.exe`) first for Safe Launch while covering
/// `resources\bin\language_server.exe`, `webm_encoder.exe`, `elevate.exe`, `agy.exe`, etc.
pub fn discover_antigravity_exes_from_dirs(dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut exes = Vec::new();
    for dir in dirs {
        for primary_name in ["Antigravity.exe", "Antigravity IDE.exe"] {
            let primary = dir.join(primary_name);
            if primary.is_file() && !contains_path_ci(&exes, &primary) {
                exes.push(primary);
            }
        }
    }
    for dir in dirs {
        collect_exes_filtered(dir, 0, 5, &mut exes);
    }
    exes
}

/// Discover covered executables for `antigravity` from an explicit `%LOCALAPPDATA%` root.
pub fn discover_antigravity_exes_in(local_app_data: Option<&Path>) -> Vec<PathBuf> {
    let dirs = antigravity_covered_dirs_from_roots(local_app_data, None, None);
    discover_antigravity_exes_from_dirs(&dirs)
}

fn push_unique_dir(out: &mut Vec<PathBuf>, dir: PathBuf) {
    if !dir.as_os_str().is_empty() && !contains_path_ci(out, &dir) {
        out.push(dir);
    }
}

fn expand_user_tokens(raw: &str, home: &Path) -> PathBuf {
    let trimmed = raw.trim().trim_matches(['"', '\'']).trim();
    if let Some(rest) = trimmed
        .strip_prefix("~/")
        .or_else(|| trimmed.strip_prefix(r"~\"))
    {
        return home.join(rest);
    }
    if trimmed == "~" {
        return home.to_path_buf();
    }
    let replace_ci = |input: &str, tok: &str, replacement: &str| -> String {
        let ib = input.as_bytes();
        let tb = tok.as_bytes();
        if tb.is_empty() || ib.len() < tb.len() {
            return input.to_string();
        }
        for pos in 0..=(ib.len() - tb.len()) {
            if ib[pos..pos + tb.len()].eq_ignore_ascii_case(tb) {
                if let (Some(head), Some(tail)) = (input.get(..pos), input.get(pos + tb.len()..)) {
                    return format!("{head}{replacement}{tail}");
                }
            }
        }
        input.to_string()
    };
    let home_s = home.to_string_lossy();
    let appdata_s = home
        .join("AppData")
        .join("Roaming")
        .to_string_lossy()
        .into_owned();
    let local_s = home
        .join("AppData")
        .join("Local")
        .to_string_lossy()
        .into_owned();
    let mut expanded = replace_ci(trimmed, "%USERPROFILE%", &home_s);
    expanded = replace_ci(&expanded, "${USERPROFILE}", &home_s);
    expanded = replace_ci(&expanded, "%APPDATA%", &appdata_s);
    expanded = replace_ci(&expanded, "%LOCALAPPDATA%", &local_s);
    PathBuf::from(expanded)
}

pub(crate) fn parse_npmrc_prefix(npmrc_text: &str, home: &Path) -> Option<PathBuf> {
    let mut found = None;
    for raw_line in npmrc_text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        if k.trim().eq_ignore_ascii_case("prefix") {
            let val = v.trim();
            if !val.is_empty() {
                found = Some(expand_user_tokens(val, home));
            }
        }
    }
    found
}

fn collect_versioned_node_modules(base: &Path, sub_tail: Option<&str>, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(base) else {
        return;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if !p.is_dir() {
            continue;
        }
        let nm = match sub_tail {
            Some(tail) => p.join(tail).join("node_modules"),
            None => p.join("node_modules"),
        };
        push_unique_dir(out, nm);
    }
}

pub(crate) fn collect_node_roots_from_env_pairs(
    pairs: &[(&str, &str)],
    home: &Path,
    node_modules_roots: &mut Vec<PathBuf>,
    volta_pkg_roots: &mut Vec<PathBuf>,
) {
    for (k, raw_v) in pairs {
        let v = raw_v.trim();
        if v.is_empty() {
            continue;
        }
        let kl = k.trim().to_ascii_lowercase();
        match kl.as_str() {
            "npm_config_prefix" => {
                let p = expand_user_tokens(v, home);
                push_unique_dir(node_modules_roots, p.join("node_modules"));
                push_unique_dir(node_modules_roots, p.join("lib").join("node_modules"));
            }
            "nvm_symlink" => {
                let p = expand_user_tokens(v, home);
                push_unique_dir(node_modules_roots, p.join("node_modules"));
            }
            "nvm_home" => {
                let p = expand_user_tokens(v, home);
                push_unique_dir(node_modules_roots, p.join("node_modules"));
                collect_versioned_node_modules(&p, None, node_modules_roots);
            }
            "fnm_dir" => {
                let p = expand_user_tokens(v, home);
                collect_versioned_node_modules(
                    &p.join("node-versions"),
                    Some("installation"),
                    node_modules_roots,
                );
            }
            "pnpm_home" => {
                let p = expand_user_tokens(v, home);
                push_unique_dir(
                    node_modules_roots,
                    p.join("global").join("5").join("node_modules"),
                );
                collect_versioned_node_modules(&p.join("global"), None, node_modules_roots);
                push_unique_dir(node_modules_roots, p.join("node_modules"));
            }
            "volta_home" => {
                let p = expand_user_tokens(v, home);
                push_unique_dir(
                    volta_pkg_roots,
                    p.join("tools").join("image").join("packages"),
                );
            }
            "bun_install" => {
                let p = expand_user_tokens(v, home);
                push_unique_dir(
                    node_modules_roots,
                    p.join("install").join("global").join("node_modules"),
                );
            }
            "path" => {
                for seg in v.split(';') {
                    let clean = seg.trim().trim_matches('"').trim();
                    if clean.is_empty() {
                        continue;
                    }
                    let low = clean.to_ascii_lowercase();
                    if low.contains("nodejs") || low.contains("npm") {
                        let p = expand_user_tokens(clean, home);
                        push_unique_dir(node_modules_roots, p.join("node_modules"));
                        if p.file_name()
                            .is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case("bin"))
                        {
                            if let Some(parent) = p.parent() {
                                push_unique_dir(node_modules_roots, parent.join("node_modules"));
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

#[cfg(windows)]
fn read_user_env_pairs_for_home(home: &Path) -> Vec<(String, String)> {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_USERS, KEY_READ};
    use winreg::RegKey;

    const ENV_KEYS: &[&str] = &[
        "NPM_CONFIG_PREFIX",
        "NVM_SYMLINK",
        "NVM_HOME",
        "FNM_DIR",
        "PNPM_HOME",
        "VOLTA_HOME",
        "BUN_INSTALL",
        "Path",
    ];

    let home_key = normalize_path_key_l(home);
    if home_key.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    let read_from_env_subkey = |env_key: &winreg::RegKey, dst: &mut Vec<(String, String)>| {
        for &name in ENV_KEYS {
            if let Ok(val) = env_key.get_value::<String, _>(name) {
                if !val.trim().is_empty() {
                    dst.push((name.to_string(), val));
                }
            }
        }
    };

    for (sid, prof_path) in profile_list_entries() {
        if normalize_path_key_l(&prof_path) == home_key {
            let hku = RegKey::predef(HKEY_USERS);
            if let Ok(env_reg) = hku.open_subkey_with_flags(format!(r"{sid}\Environment"), KEY_READ)
            {
                read_from_env_subkey(&env_reg, &mut out);
                return out;
            }
        }
    }

    if !crate::access_win::is_session_zero() {
        if let Some(cur_prof) = std::env::var_os("USERPROFILE").map(PathBuf::from) {
            if normalize_path_key_l(&cur_prof) == home_key {
                let hkcu = RegKey::predef(HKEY_CURRENT_USER);
                if let Ok(env_reg) = hkcu.open_subkey_with_flags("Environment", KEY_READ) {
                    read_from_env_subkey(&env_reg, &mut out);
                }
            }
        }
    }
    out
}

#[cfg(not(windows))]
fn read_user_env_pairs_for_home(_home: &Path) -> Vec<(String, String)> {
    Vec::new()
}

fn candidate_cli_package_dirs_for_home(home: &Path, scope: &str, pkg: &str) -> Vec<PathBuf> {
    let roaming = home.join("AppData").join("Roaming");
    let local = home.join("AppData").join("Local");

    let mut nm_roots = Vec::new();
    let mut volta_roots = Vec::new();

    // 1. Default Windows npm global
    push_unique_dir(&mut nm_roots, roaming.join("npm").join("node_modules"));

    // 2. `<home>\.npmrc` (`prefix=`)
    if let Ok(npmrc) = std::fs::read_to_string(home.join(".npmrc")) {
        if let Some(prefix) = parse_npmrc_prefix(&npmrc, home) {
            push_unique_dir(&mut nm_roots, prefix.join("node_modules"));
            push_unique_dir(&mut nm_roots, prefix.join("lib").join("node_modules"));
        }
    }

    // 3. Per-user `HKU\<SID>\Environment` (matched strictly to `home` via ProfileList)
    let env_owned = read_user_env_pairs_for_home(home);
    if !env_owned.is_empty() {
        let refs: Vec<(&str, &str)> = env_owned
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        collect_node_roots_from_env_pairs(&refs, home, &mut nm_roots, &mut volta_roots);
    }

    // 4. NVM for Windows (`<AppData|LocalAppData>\nvm\v*\node_modules`)
    for nvm_base in [roaming.join("nvm"), local.join("nvm")] {
        collect_versioned_node_modules(&nvm_base, None, &mut nm_roots);
    }

    // 5. fnm (`<AppData|LocalAppData>\fnm\node-versions\v*\installation\node_modules` + `.fnm`)
    for fnm_base in [
        roaming.join("fnm").join("node-versions"),
        local.join("fnm").join("node-versions"),
        home.join(".fnm").join("node-versions"),
    ] {
        collect_versioned_node_modules(&fnm_base, Some("installation"), &mut nm_roots);
    }

    // 6. Volta (`<LocalAppData>\Volta\tools\image\packages`)
    push_unique_dir(
        &mut volta_roots,
        local
            .join("Volta")
            .join("tools")
            .join("image")
            .join("packages"),
    );

    // 7. pnpm global (`<LocalAppData>\pnpm\global\5\node_modules`)
    push_unique_dir(
        &mut nm_roots,
        local
            .join("pnpm")
            .join("global")
            .join("5")
            .join("node_modules"),
    );
    collect_versioned_node_modules(&local.join("pnpm").join("global"), None, &mut nm_roots);

    // 8. Bun global (`<home>\.bun\install\global\node_modules`)
    push_unique_dir(
        &mut nm_roots,
        home.join(".bun")
            .join("install")
            .join("global")
            .join("node_modules"),
    );

    // 9. Claude local (`<home>\.claude\local\node_modules`)
    push_unique_dir(
        &mut nm_roots,
        home.join(".claude").join("local").join("node_modules"),
    );

    let mut pkg_dirs = Vec::new();
    for nm in nm_roots {
        push_unique_dir(&mut pkg_dirs, nm.join(scope).join(pkg));
    }
    for vr in volta_roots {
        push_unique_dir(&mut pkg_dirs, vr.join(scope).join(pkg));
        push_unique_dir(
            &mut pkg_dirs,
            vr.join(scope)
                .join(pkg)
                .join("node_modules")
                .join(scope)
                .join(pkg),
        );
        push_unique_dir(&mut pkg_dirs, vr.join("node_modules").join(scope).join(pkg));
    }
    pkg_dirs
}

pub(crate) fn scan_scoop_app_version(scoop_root: &Path, app_name: &str, best: &mut Option<String>) {
    let app_dir = scoop_root.join("apps").join(app_name);
    if !app_dir.is_dir() {
        return;
    }
    if let Some(v) = read_package_json_version(&app_dir.join("current").join("manifest.json")) {
        pick_newer_version(best, &v);
    }
    if let Ok(rd) = std::fs::read_dir(&app_dir) {
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                if let Some(v) = read_package_json_version(&p.join("manifest.json")) {
                    pick_newer_version(best, &v);
                }
            }
        }
    }
}

fn program_data_scoop_root() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(|pd| PathBuf::from(pd).join("scoop"))
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData\scoop"))
}

pub(crate) fn read_cargo_crates2_version(
    crates2_path: &Path,
    crate_names: &[&str],
) -> Option<String> {
    let raw = std::fs::read_to_string(crates2_path).ok()?;
    let root: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let installs = root.get("installs")?.as_object()?;
    let mut best = None;
    for key in installs.keys() {
        let mut parts = key.split_whitespace();
        let Some(name) = parts.next() else {
            continue;
        };
        let Some(ver) = parts.next() else {
            continue;
        };
        if crate_names.iter().any(|c| name.eq_ignore_ascii_case(c)) {
            pick_newer_version(&mut best, ver);
        }
    }
    best
}

fn push_unique_file(out: &mut Vec<PathBuf>, file: PathBuf) {
    if file.is_file() && !contains_path_ci(out, &file) {
        out.push(file);
    }
}

fn collect_sorted_version_subdirs_newest_first(
    root: &Path,
    prefix_l: Option<&str>,
) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut pairs: Vec<(Vec<u64>, PathBuf)> = Vec::new();
    for entry in rd.flatten() {
        let p = entry.path();
        let fname = entry.file_name().to_string_lossy().to_string();
        if let Some(pref) = prefix_l {
            let low = fname.to_ascii_lowercase();
            let Some(rest) = low.strip_prefix(pref) else {
                continue;
            };
            if p.is_dir() {
                pairs.push((version_key(rest), p));
            }
        } else if p.is_dir() {
            pairs.push((version_key(&fname), p));
        } else if p.is_file() && p.extension().is_some_and(|e| e.eq_ignore_ascii_case("exe")) {
            let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            if is_numeric_version_str(stem.trim_start_matches(['v', 'V'])) {
                pairs.push((version_key(stem), p));
            }
        }
    }
    pairs.sort_by(|a, b| b.0.cmp(&a.0));
    pairs.into_iter().map(|(_, p)| p).collect()
}

/// Testable standalone CLI native executable (and shim fallback) discovery across explicit user home roots.
pub fn discover_cli_exes_in_homes(cli_id: &str, homes: &[PathBuf]) -> Vec<PathBuf> {
    let mut exes = Vec::new();
    match cli_id {
        "claude-code" => {
            for home in homes {
                for direct_claude in [
                    home.join(".local").join("bin").join("claude.exe"),
                    home.join(".claude").join("bin").join("claude.exe"),
                    home.join(".claude").join("local").join("claude.exe"),
                    home.join(".bun").join("bin").join("claude.exe"),
                    home.join("AppData")
                        .join("Local")
                        .join("Volta")
                        .join("bin")
                        .join("claude.exe"),
                    home.join("AppData")
                        .join("Local")
                        .join("Microsoft")
                        .join("WinGet")
                        .join("Links")
                        .join("claude.exe"),
                ] {
                    push_unique_file(&mut exes, direct_claude);
                }
                // Native Claude Code installer: `<home>\.local\share\claude\versions\<ver>\claude.exe` or `<ver>.exe`
                let native_versions = home
                    .join(".local")
                    .join("share")
                    .join("claude")
                    .join("versions");
                for ver_entry in collect_sorted_version_subdirs_newest_first(&native_versions, None)
                {
                    if ver_entry.is_file() {
                        push_unique_file(&mut exes, ver_entry);
                    } else {
                        collect_exes_matching(&ver_entry, 0, 2, &|n| n == "claude.exe", &mut exes);
                    }
                }
                let winget_pkgs = home
                    .join("AppData")
                    .join("Local")
                    .join("Microsoft")
                    .join("WinGet")
                    .join("Packages");
                if let Ok(rd) = std::fs::read_dir(&winget_pkgs) {
                    for entry in rd.flatten() {
                        let p = entry.path();
                        let fname = entry.file_name().to_string_lossy().to_string();
                        if p.is_dir()
                            && strip_ascii_prefix_ci(&fname, "Anthropic.ClaudeCode").is_some()
                        {
                            collect_exes_matching(&p, 0, 4, &|n| n == "claude.exe", &mut exes);
                        }
                    }
                }
                let roaming_cc = home
                    .join("AppData")
                    .join("Roaming")
                    .join("Claude")
                    .join("claude-code");
                collect_exes_matching(&roaming_cc, 0, 4, &|n| n == "claude.exe", &mut exes);
                for pkg_dir in
                    candidate_cli_package_dirs_for_home(home, "@anthropic-ai", "claude-code")
                {
                    collect_exes_matching(&pkg_dir, 0, 6, &|n| n == "claude.exe", &mut exes);
                }
                let scoop_cc = home.join("scoop").join("apps").join("claude-code");
                collect_exes_matching(&scoop_cc, 0, 4, &|n| n == "claude.exe", &mut exes);
            }
            if exes.is_empty() {
                for home in homes {
                    for shim in [
                        home.join("AppData")
                            .join("Roaming")
                            .join("npm")
                            .join("claude.cmd"),
                        home.join("AppData")
                            .join("Local")
                            .join("pnpm")
                            .join("claude.cmd"),
                        home.join("AppData")
                            .join("Roaming")
                            .join("npm")
                            .join("claude.ps1"),
                        home.join("AppData")
                            .join("Local")
                            .join("pnpm")
                            .join("claude.ps1"),
                    ] {
                        push_unique_file(&mut exes, shim);
                    }
                }
            }
        }
        "codex" => {
            // Pass 1: Exact `codex.exe` primary launchers FIRST (so `exes[0]` is never `codex-voice-host.exe`!)
            for home in homes {
                for direct in [
                    home.join(".local").join("bin").join("codex.exe"),
                    home.join(".cargo").join("bin").join("codex.exe"),
                    home.join(".bun").join("bin").join("codex.exe"),
                    home.join("AppData")
                        .join("Local")
                        .join("Volta")
                        .join("bin")
                        .join("codex.exe"),
                    home.join("scoop")
                        .join("apps")
                        .join("codex")
                        .join("current")
                        .join("codex.exe"),
                ] {
                    push_unique_file(&mut exes, direct);
                }
                for pkg_dir in candidate_cli_package_dirs_for_home(home, "@openai", "codex") {
                    collect_exes_matching(&pkg_dir, 0, 8, &|n| n == "codex.exe", &mut exes);
                }
            }
            // Pass 2: Auxiliary `codex*.exe` helpers (`codex-voice-host.exe`, `codex-command-runner.exe`) for firewall coverage
            for home in homes {
                for pkg_dir in candidate_cli_package_dirs_for_home(home, "@openai", "codex") {
                    collect_exes_matching(&pkg_dir, 0, 8, &|n| n.starts_with("codex"), &mut exes);
                }
                for bin_dir in [
                    home.join(".local").join("bin"),
                    home.join(".cargo").join("bin"),
                    home.join(".bun").join("bin"),
                ] {
                    collect_exes_matching(&bin_dir, 0, 0, &|n| n.starts_with("codex"), &mut exes);
                }
                let scoop_codex = home.join("scoop").join("apps").join("codex");
                collect_exes_matching(&scoop_codex, 0, 4, &|n| n.starts_with("codex"), &mut exes);
            }
            if !exes.iter().any(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.eq_ignore_ascii_case("codex.exe"))
            }) {
                // Insert `.cmd`/`.ps1` primary launcher at index 0 if only helper `.exe` or no `.exe` was found
                let mut shims = Vec::new();
                for home in homes {
                    for shim in [
                        home.join("AppData")
                            .join("Roaming")
                            .join("npm")
                            .join("codex.cmd"),
                        home.join("AppData")
                            .join("Local")
                            .join("pnpm")
                            .join("codex.cmd"),
                        home.join("AppData")
                            .join("Roaming")
                            .join("npm")
                            .join("codex.ps1"),
                        home.join("AppData")
                            .join("Local")
                            .join("pnpm")
                            .join("codex.ps1"),
                    ] {
                        push_unique_file(&mut shims, shim);
                    }
                }
                if !shims.is_empty() {
                    shims.extend(exes);
                    exes = shims;
                }
            }
        }
        _ => {}
    }
    exes
}

/// Discover standalone native CLI binaries (`claude-code`, `codex`) across all user homes and global Scoop.
pub fn discover_cli_exes(cli_id: &str) -> Vec<PathBuf> {
    let mut exes = discover_cli_exes_in_homes(cli_id, &user_home_dirs());
    let global_scoop = program_data_scoop_root();
    match cli_id {
        "claude-code" => {
            collect_exes_matching(
                &global_scoop.join("apps").join("claude-code"),
                0,
                4,
                &|n| n == "claude.exe",
                &mut exes,
            );
        }
        "codex" => {
            collect_exes_matching(
                &global_scoop.join("apps").join("codex"),
                0,
                4,
                &|n| n.starts_with("codex"),
                &mut exes,
            );
        }
        _ => {}
    }
    exes
}

/// Testable deep (`max_depth = 12`) Claude covered executable discovery + standalone `claude-code` CLI.
pub fn discover_claude_exes_from_dirs_and_homes(
    dirs: &[PathBuf],
    homes: &[PathBuf],
) -> Vec<PathBuf> {
    let mut exes = Vec::new();
    for dir in dirs {
        for primary in [dir.join("app").join("claude.exe"), dir.join("claude.exe")] {
            push_unique_file(&mut exes, primary);
        }
        // Squirrel layout (`AnthropicClaude\app-*\claude.exe`): sort newest `app-*` first so `exes[0]`
        // is always the newest main `claude.exe` (never `Update.exe` or an older `app-*` version).
        for app_ver_dir in collect_sorted_version_subdirs_newest_first(dir, Some("app-")) {
            push_unique_file(&mut exes, app_ver_dir.join("claude.exe"));
        }
    }
    for dir in dirs {
        collect_exes_filtered(dir, 0, 12, &mut exes);
    }
    for cli_exe in discover_cli_exes_in_homes("claude-code", homes) {
        if cli_exe
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("exe"))
            && !contains_path_ci(&exes, &cli_exe)
        {
            exes.push(cli_exe);
        }
    }
    exes
}

/// Testable deep (`max_depth = 12`) ChatGPT/Codex covered executable discovery + standalone `codex*.exe` CLI.
pub fn discover_chatgpt_exes_from_dirs_and_homes(
    dirs: &[PathBuf],
    homes: &[PathBuf],
) -> Vec<PathBuf> {
    let mut exes = Vec::new();
    for dir in dirs {
        for primary in [
            dir.join("app").join("ChatGPT.exe"),
            dir.join("app").join("ChatGPT Classic.exe"),
            dir.join("app").join("Codex.exe"),
            dir.join("ChatGPT.exe"),
            dir.join("ChatGPT Classic.exe"),
            dir.join("Codex.exe"),
        ] {
            push_unique_file(&mut exes, primary);
        }
    }
    for dir in dirs {
        collect_exes_filtered(dir, 0, 12, &mut exes);
    }
    for cli_exe in discover_cli_exes_in_homes("codex", homes) {
        if cli_exe
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("exe"))
            && !contains_path_ci(&exes, &cli_exe)
        {
            exes.push(cli_exe);
        }
    }
    exes
}

/// Discover covered executables across the 3 core GUI agents (`claude`, `chatgpt`, `antigravity`).
pub fn discover_agent_exes(agent_id: &str) -> Vec<PathBuf> {
    match agent_id {
        "claude" => {
            discover_claude_exes_from_dirs_and_homes(&claude_covered_dirs(), &user_home_dirs())
        }
        "chatgpt" => {
            discover_chatgpt_exes_from_dirs_and_homes(&chatgpt_covered_dirs(), &user_home_dirs())
        }
        "antigravity" => discover_antigravity_exes_from_dirs(&antigravity_covered_dirs()),
        _ => Vec::new(),
    }
}

/// Resolve an AppModel `AppUserModelId` (`<FamilyName>!<AppId>`) with fallback.
pub fn resolve_app_id(prefix: &str, app_name: &str, fallback: &str) -> String {
    let dirs = covered_dirs_from(
        &registered_package_dirs(prefix),
        find_windowsapps_dir(prefix),
    );
    if let Some(dir) = dirs.first() {
        if let Some(family) = family_name_from_dir(dir) {
            return format!("{family}!{app_name}");
        }
    }
    fallback.to_string()
}

/// Read `VS_FIXEDFILEINFO` file version (e.g. `2.33.0`) directly from a Windows PE executable without spawning subprocesses.
#[cfg(windows)]
pub fn read_pe_file_version(path: &Path) -> Option<String> {
    use core::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::{w, PCWSTR};
    use windows::Win32::Storage::FileSystem::{
        GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW, VS_FIXEDFILEINFO,
    };

    if !path.is_file() {
        return None;
    }
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut handle: u32 = 0;
    let size = unsafe { GetFileVersionInfoSizeW(PCWSTR(wide.as_ptr()), Some(&mut handle)) };
    if size == 0 || size > 4 * 1024 * 1024 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    unsafe {
        if GetFileVersionInfoW(
            PCWSTR(wide.as_ptr()),
            0,
            size,
            buf.as_mut_ptr().cast::<c_void>(),
        )
        .is_err()
        {
            return None;
        }
        let mut ptr: *mut c_void = core::ptr::null_mut();
        let mut len: u32 = 0;
        if !VerQueryValueW(buf.as_ptr().cast::<c_void>(), w!("\\"), &mut ptr, &mut len).as_bool()
            || ptr.is_null()
            || (len as usize) < core::mem::size_of::<VS_FIXEDFILEINFO>()
        {
            return None;
        }
        let info = &*(ptr.cast::<VS_FIXEDFILEINFO>());
        if info.dwSignature != 0xFEEF_04BD {
            return None;
        }
        let major = (info.dwFileVersionMS >> 16) & 0xFFFF;
        let minor = info.dwFileVersionMS & 0xFFFF;
        let build = (info.dwFileVersionLS >> 16) & 0xFFFF;
        let rev = info.dwFileVersionLS & 0xFFFF;
        if major == 0 && minor == 0 && build == 0 && rev == 0 {
            return None;
        }
        if rev == 0 {
            Some(format!("{major}.{minor}.{build}"))
        } else {
            Some(format!("{major}.{minor}.{build}.{rev}"))
        }
    }
}

#[cfg(not(windows))]
pub fn read_pe_file_version(_path: &Path) -> Option<String> {
    None
}

fn is_numeric_version_str(clean: &str) -> bool {
    !clean.is_empty()
        && clean.as_bytes()[0].is_ascii_digit()
        && clean.split(['-', '+']).next().is_some_and(|core| {
            !core.is_empty() && core.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        })
}

fn pick_newer_version(best: &mut Option<String>, candidate: &str) {
    let clean = crate::update_check::normalize_version(candidate);
    if !is_numeric_version_str(&clean) {
        return;
    }
    match best {
        None => *best = Some(clean),
        Some(prev) => {
            if crate::update_check::is_version_newer(&clean, prev) {
                *best = Some(clean);
            }
        }
    }
}

fn read_package_json_version(pkg_json: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(pkg_json).ok()?;
    let val: serde_json::Value = serde_json::from_str(&raw).ok()?;
    val.get("version")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().trim_start_matches(['v', 'V']).to_string())
        .filter(|s| is_numeric_version_str(s))
}

fn scan_versioned_claude_code_dir(root: &Path, best: &mut Option<String>) {
    let Ok(rd) = std::fs::read_dir(root) else {
        return;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if p.is_file() && p.extension().is_some_and(|e| e.eq_ignore_ascii_case("exe")) {
            let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            if is_numeric_version_str(stem.trim().trim_start_matches(['v', 'V'])) {
                pick_newer_version(best, stem);
            }
            continue;
        }
        if !p.is_dir() {
            continue;
        }
        if !is_numeric_version_str(name.trim().trim_start_matches(['v', 'V'])) {
            continue;
        }
        let has_bin = p.join("claude.exe").is_file()
            || std::fs::read_dir(&p).ok().is_some_and(|mut sub| {
                sub.any(|e| {
                    e.ok()
                        .is_some_and(|se| se.path().join("claude.exe").is_file())
                })
            });
        if has_bin {
            pick_newer_version(best, &name);
        }
    }
}

pub(crate) fn installed_claude_desktop_version_in_dirs(dirs: &[PathBuf]) -> Option<String> {
    let mut best = None;
    for dir in dirs {
        for exe in [dir.join("Claude.exe"), dir.join("app").join("Claude.exe")] {
            if let Some(v) = read_pe_file_version(&exe) {
                pick_newer_version(&mut best, &v);
            }
        }
        // Squirrel layout: `AnthropicClaude\app-0.9.3\claude.exe`
        if let Ok(rd) = std::fs::read_dir(dir) {
            for entry in rd.flatten() {
                let p = entry.path();
                if !p.is_dir() {
                    continue;
                }
                let name = entry.file_name().to_string_lossy().to_string();
                let low = name.to_ascii_lowercase();
                if let Some(ver_seg) = low.strip_prefix("app-") {
                    let sub_exe = p.join("claude.exe");
                    if let Some(pe_v) = read_pe_file_version(&sub_exe) {
                        pick_newer_version(&mut best, &pe_v);
                    } else if let Some(pkg_v) = read_package_json_version(
                        &p.join("resources").join("app").join("package.json"),
                    ) {
                        pick_newer_version(&mut best, &pkg_v);
                    } else if sub_exe.is_file() {
                        pick_newer_version(&mut best, ver_seg);
                    }
                }
            }
        }
    }
    best
}

/// Detect installed Claude Desktop version (MSIX registry/folder, Squirrel `AnthropicClaude\app-*\claude.exe`, or Uninstall registry).
pub fn installed_claude_desktop_version() -> Option<String> {
    if let Some(msix) = installed_msix_version("Claude_") {
        return Some(msix);
    }
    let mut best = installed_claude_desktop_version_in_dirs(&per_user_local_app_subdirs(&[
        "AnthropicClaude",
        r"Programs\Claude",
    ]));
    for rec in scan_uninstall_records() {
        let dn = rec.display_name.to_ascii_lowercase();
        let kn = rec.key_name.to_ascii_lowercase();
        if (dn == "claude" || dn.contains("anthropicclaude") || kn.contains("anthropicclaude"))
            && !dn.contains("claudeguard")
            && !dn.contains("claude code")
        {
            if let Some(ref dv) = rec.display_version {
                pick_newer_version(&mut best, dv);
            }
            if let Some(ref dir) = rec.install_dir {
                if let Some(v) =
                    installed_claude_desktop_version_in_dirs(core::slice::from_ref(dir))
                {
                    pick_newer_version(&mut best, &v);
                }
            }
        }
    }
    best
}

/// Detect installed OpenAI Codex Desktop (`26.x`) or Microsoft Store ChatGPT Desktop (`1.x`) version.
pub fn installed_codex_desktop_version() -> Option<String> {
    if let Some(msix) = installed_msix_version("OpenAI.Codex_") {
        return Some(msix);
    }
    let mut best = None;
    for dir in per_user_local_app_subdirs(&[r"Programs\Codex"]) {
        for exe in [dir.join("Codex.exe"), dir.join("app").join("Codex.exe")] {
            if let Some(v) = read_pe_file_version(&exe) {
                pick_newer_version(&mut best, &v);
            }
        }
    }
    for rec in scan_uninstall_records() {
        let dn = rec.display_name.trim().to_ascii_lowercase();
        if dn == "codex" || dn == "openai codex" {
            if let Some(ref dv) = rec.display_version {
                pick_newer_version(&mut best, dv);
            }
            if let Some(ref dir) = rec.install_dir {
                for exe in [dir.join("Codex.exe"), dir.join("app").join("Codex.exe")] {
                    if let Some(v) = read_pe_file_version(&exe) {
                        pick_newer_version(&mut best, &v);
                    }
                }
            }
        }
    }
    if best.is_some() {
        return best;
    }

    // Fallback to Microsoft Store `OpenAI.ChatGPT-Desktop_` / `Programs\ChatGPT` (`1.x` epoch).
    for prefix in ["OpenAI.ChatGPT-Desktop_", "OpenAI.ChatGPT_"] {
        if let Some(msix) = installed_msix_version(prefix) {
            return Some(msix);
        }
    }
    for dir in per_user_local_app_subdirs(&[r"Programs\ChatGPT", r"Programs\ChatGPT Classic"]) {
        for exe in [
            dir.join("ChatGPT.exe"),
            dir.join("app").join("ChatGPT.exe"),
            dir.join("ChatGPT Classic.exe"),
        ] {
            if let Some(v) = read_pe_file_version(&exe) {
                pick_newer_version(&mut best, &v);
            }
        }
    }
    best
}

/// Testable detector reading newest installed `@anthropic-ai/claude-code` / native `claude-code` version.
pub fn installed_claude_code_version_in_homes(homes: &[PathBuf]) -> Option<String> {
    let mut best = None;
    for home in homes {
        let roaming_cc = home
            .join("AppData")
            .join("Roaming")
            .join("Claude")
            .join("claude-code");
        scan_versioned_claude_code_dir(&roaming_cc, &mut best);

        let native_cc = home
            .join(".local")
            .join("share")
            .join("claude")
            .join("versions");
        scan_versioned_claude_code_dir(&native_cc, &mut best);

        for pkg_dir in candidate_cli_package_dirs_for_home(home, "@anthropic-ai", "claude-code") {
            if let Some(v) = read_package_json_version(&pkg_dir.join("package.json")) {
                pick_newer_version(&mut best, &v);
            }
        }

        scan_scoop_app_version(&home.join("scoop"), "claude-code", &mut best);

        for bin_exe in [
            home.join(".local").join("bin").join("claude.exe"),
            home.join(".claude").join("bin").join("claude.exe"),
            home.join(".claude").join("local").join("claude.exe"),
            home.join(".bun").join("bin").join("claude.exe"),
            home.join("AppData")
                .join("Local")
                .join("Volta")
                .join("bin")
                .join("claude.exe"),
        ] {
            if let Some(v) = read_pe_file_version(&bin_exe) {
                pick_newer_version(&mut best, &v);
            }
        }
    }
    best
}

/// Detect installed Claude Code CLI version across user homes and global Scoop.
pub fn installed_claude_code_version() -> Option<String> {
    let mut best = installed_claude_code_version_in_homes(&user_home_dirs());
    scan_scoop_app_version(&program_data_scoop_root(), "claude-code", &mut best);
    best
}

/// Testable detector reading newest installed `@openai/codex` / native `codex` CLI version.
pub fn installed_codex_cli_version_in_homes(homes: &[PathBuf]) -> Option<String> {
    let mut best = None;
    for home in homes {
        for pkg_dir in candidate_cli_package_dirs_for_home(home, "@openai", "codex") {
            if let Some(v) = read_package_json_version(&pkg_dir.join("package.json")) {
                pick_newer_version(&mut best, &v);
            }
        }

        scan_scoop_app_version(&home.join("scoop"), "codex", &mut best);

        for bin_exe in [
            home.join(".local").join("bin").join("codex.exe"),
            home.join(".bun").join("bin").join("codex.exe"),
        ] {
            if let Some(v) = read_pe_file_version(&bin_exe) {
                pick_newer_version(&mut best, &v);
            }
        }

        let cargo_bin = home.join(".cargo").join("bin");
        let cargo_exe = cargo_bin.join("codex.exe");
        if let Some(pe_ver) = read_pe_file_version(&cargo_exe) {
            pick_newer_version(&mut best, &pe_ver);
        } else if !cargo_bin.is_dir() || cargo_exe.is_file() {
            if let Some(cargo_ver) = read_cargo_crates2_version(
                &home.join(".cargo").join(".crates2.json"),
                &["codex-cli", "codex"],
            ) {
                pick_newer_version(&mut best, &cargo_ver);
            }
        }
    }
    best
}

/// Detect installed Codex CLI version across user homes and global Scoop.
pub fn installed_codex_cli_version() -> Option<String> {
    let mut best = installed_codex_cli_version_in_homes(&user_home_dirs());
    scan_scoop_app_version(&program_data_scoop_root(), "codex", &mut best);
    best
}

fn parse_app_update_url(yml_text: &str) -> Option<String> {
    for line in yml_text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("url:") {
            let clean = rest
                .trim()
                .trim_matches(['"', '\''])
                .trim()
                .trim_end_matches('/');
            if let Some((true, host, _)) = crate::probe_http::parse_probe_url_parts(clean) {
                let host_l = host.trim_end_matches('.').to_ascii_lowercase();
                let is_local = host_l == "localhost"
                    || host_l.ends_with(".localhost")
                    || host_l.ends_with(".local")
                    || host_l
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(crate::netwatch_win::is_local_addr);
                if !is_local {
                    return Some(clean.to_string());
                }
            }
        }
    }
    None
}

/// Testable detector returning `(ide_version, updater_base_url)` from Antigravity install roots.
pub fn installed_antigravity_ide_info_in_dirs(
    dirs: &[PathBuf],
) -> (Option<String>, Option<String>) {
    let mut best_ver: Option<String> = None;
    let mut updater_url: Option<String> = None;

    for dir in dirs {
        if !dir.is_dir() {
            continue;
        }
        let mut dir_ver: Option<String> = None;
        for exe_name in ["Antigravity.exe", "Antigravity IDE.exe"] {
            let exe = dir.join(exe_name);
            if let Some(v) = read_pe_file_version(&exe) {
                pick_newer_version(&mut dir_ver, &v);
            }
        }
        if dir_ver.is_none() {
            if let Some(v) =
                read_package_json_version(&dir.join("resources").join("app").join("package.json"))
            {
                pick_newer_version(&mut dir_ver, &v);
            }
        }
        if dir_ver.is_none() {
            if let Ok(raw) = std::fs::read_to_string(dir.join("version")) {
                pick_newer_version(&mut dir_ver, &raw);
            }
        }
        let dir_url = std::fs::read_to_string(dir.join("resources").join("app-update.yml"))
            .ok()
            .and_then(|yml| parse_app_update_url(&yml));

        if let Some(ref dv) = dir_ver {
            let is_newer = best_ver
                .as_deref()
                .is_none_or(|prev| crate::update_check::is_version_newer(dv, prev));
            if is_newer {
                best_ver = Some(dv.clone());
                if dir_url.is_some() {
                    updater_url = dir_url;
                }
            } else if updater_url.is_none() && dir_url.is_some() {
                updater_url = dir_url;
            }
        } else if updater_url.is_none() && dir_url.is_some() {
            updater_url = dir_url;
        }
    }
    (best_ver, updater_url)
}

/// Detect installed Antigravity client version (`Antigravity.exe` FileVersion / package.json) and its `app-update.yml` URL.
pub fn installed_antigravity_ide_info() -> (Option<String>, Option<String>) {
    installed_antigravity_ide_info_in_dirs(&antigravity_covered_dirs())
}

fn plugin_folder_matches(folder_l: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|raw_pat| {
        let pat = raw_pat.trim().to_ascii_lowercase();
        if pat.is_empty() {
            return false;
        }
        folder_l == pat
            || folder_l.starts_with(&format!("{pat}-"))
            || folder_l.starts_with(&format!("{pat}_"))
            || folder_l.starts_with(&format!("{pat}."))
            || folder_l.contains(&format!(".{pat}-"))
            || folder_l.ends_with(&format!(".{pat}"))
    })
}

fn plugin_manifest_name_matches(manifest_name: &str, patterns: &[&str]) -> bool {
    let low = manifest_name.trim().to_ascii_lowercase();
    let stripped = low.rsplit('/').next().unwrap_or(&low);
    patterns.iter().any(|raw_pat| {
        let pat = raw_pat.trim().to_ascii_lowercase();
        !pat.is_empty() && (low == pat || stripped == pat)
    })
}

/// Testable detector reading newest installed Antigravity plugin/extension version across
/// `.gemini\config\plugins`, `.antigravity\extensions`, and `.gemini\antigravity\extensions`.
pub fn installed_antigravity_plugin_version_in_homes(
    plugin_dirs: &[&str],
    homes: &[PathBuf],
) -> Option<String> {
    let manifest_rel_paths: [&Path; 4] = [
        Path::new("plugin.json"),
        Path::new("package.json"),
        Path::new(".gemini-plugin/plugin.json"),
        Path::new(".claude-plugin/plugin.json"),
    ];
    let mut best = None;

    for home in homes {
        let bases = [
            home.join(".gemini").join("config").join("plugins"),
            home.join(".antigravity").join("extensions"),
            home.join(".gemini").join("antigravity").join("extensions"),
        ];
        for base in &bases {
            let Ok(rd) = std::fs::read_dir(base) else {
                continue;
            };
            for entry in rd.flatten() {
                let root = entry.path();
                if !root.is_dir() {
                    continue;
                }
                let folder_l = entry.file_name().to_string_lossy().to_ascii_lowercase();
                let folder_matched = plugin_folder_matches(&folder_l, plugin_dirs);

                for rel in &manifest_rel_paths {
                    let mf = root.join(rel);
                    let Ok(raw) = std::fs::read_to_string(&mf) else {
                        continue;
                    };
                    let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) else {
                        continue;
                    };
                    let name_matched = val
                        .get("name")
                        .and_then(|v| v.as_str())
                        .is_some_and(|n| plugin_manifest_name_matches(n, plugin_dirs));
                    if folder_matched || name_matched {
                        if let Some(ver) = val.get("version").and_then(|v| v.as_str()) {
                            pick_newer_version(&mut best, ver);
                        }
                    }
                }
            }
        }
    }
    best
}

/// Detect installed `antigravity-usage-monitor` plugin version across user homes.
pub fn installed_ag_usage_monitor_version() -> Option<String> {
    installed_antigravity_plugin_version_in_homes(
        &["usage-monitor", "antigravity-usage-monitor"],
        &user_home_dirs(),
    )
}

/// Detect installed `agy-capsule` plugin version across user homes.
pub fn installed_ag_capsule_version() -> Option<String> {
    installed_antigravity_plugin_version_in_homes(&["agy-capsule"], &user_home_dirs())
}

fn unix_secs_to_ymd(secs: u64) -> String {
    // Howard Hinnant's civil-from-days algorithm (UTC YYYY.MM.DD for SemVer-friendly date compare).
    let z = (secs / 86_400) as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}.{m:02}.{d:02}")
}

/// Zero-dependency Electron ASAR header inspector verifying whether `resources\app.asar`
/// actually contains `Silas-02/antigravity-desktop-cn` injected localization/monitor files.
pub fn asar_contains_cn_patch(asar_path: &Path) -> bool {
    use std::io::Read;

    const MAX_HEADER_JSON_BYTES: usize = 8 * 1024 * 1024;
    let Ok(mut file) = std::fs::File::open(asar_path) else {
        return false;
    };
    let mut prefix = [0u8; 16];
    if file.read_exact(&mut prefix).is_err() {
        return false;
    }
    let header_json_len =
        u32::from_le_bytes([prefix[12], prefix[13], prefix[14], prefix[15]]) as usize;
    if header_json_len == 0 || header_json_len > MAX_HEADER_JSON_BYTES {
        return false;
    }
    let mut header_bytes = vec![0u8; header_json_len];
    if file.read_exact(&mut header_bytes).is_err() {
        return false;
    }
    let header = String::from_utf8_lossy(&header_bytes);
    header.contains("subframeLocalizationPreload.js")
        || header.contains("contextMonitor.js")
        || header.contains("context_monitor.js")
}

fn file_mtime_secs(path: &Path) -> Option<u64> {
    std::fs::metadata(path)
        .ok()?
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

fn read_cn_explicit_version(dir: &Path) -> Option<String> {
    let mut found = None;
    for text_file in ["antigravity-desktop-cn.version", ".cn-version"] {
        if let Ok(raw) = std::fs::read_to_string(dir.join(text_file)) {
            pick_newer_version(&mut found, &raw);
        }
    }
    if let Some(v) = read_package_json_version(&dir.join("cn-patch.json")) {
        pick_newer_version(&mut found, &v);
    }
    found
}

/// Testable detector checking whether `Silas-02/antigravity-desktop-cn` localization patch is
/// ACTUALLY active in live `resources\app` or live `resources\app.asar` (never false-positiving
/// on a stale `app.asar.bak` left behind after an IDE update!).
pub fn installed_antigravity_cn_version_in_dirs(dirs: &[PathBuf]) -> Option<String> {
    let mut best = None;
    for dir in dirs {
        if !dir.is_dir() {
            continue;
        }
        let res_dir = dir.join("resources");
        let app_dir = res_dir.join("app");
        let asar_path = res_dir.join("app.asar");

        // 1. Check live unpacked `resources\app` markers / version manifests
        let mut dir_ver = read_cn_explicit_version(&app_dir);
        let mut unpacked_mtime: Option<u64> = None;
        for js_marker in [
            app_dir.join("subframeLocalizationPreload.js"),
            app_dir.join("contextMonitor.js"),
            app_dir.join("context_monitor.js"),
            app_dir.join("cn_dict.js"),
        ] {
            if let Some(secs) = file_mtime_secs(&js_marker) {
                unpacked_mtime = Some(unpacked_mtime.map_or(secs, |prev| prev.max(secs)));
            }
        }
        if unpacked_mtime.is_none() {
            let preload = app_dir.join("preload.js");
            if let Ok(txt) = std::fs::read_to_string(&preload) {
                if txt.contains("antigravity-desktop-cn")
                    || txt.contains("subframeLocalizationPreload")
                    || txt.contains("contextMonitor")
                    || txt.contains("context_monitor")
                    || txt.contains("中文汉化")
                {
                    unpacked_mtime = file_mtime_secs(&preload);
                }
            }
        }
        let unpacked_active = dir_ver.is_some() || unpacked_mtime.is_some();

        // 2. Check live `resources\app.asar` header
        let asar_active = asar_contains_cn_patch(&asar_path);

        if !unpacked_active && !asar_active {
            // Even if `app.asar.bak` or a stale file in `resources\` exists, live app is NOT patched!
            continue;
        }

        if dir_ver.is_none() {
            dir_ver = read_cn_explicit_version(&res_dir);
        }
        if dir_ver.is_none() {
            // Prefer live `resources\app.asar` mtime (patch apply date), NOT `app.asar.bak`!
            let secs = if asar_active {
                file_mtime_secs(&asar_path)
            } else {
                unpacked_mtime
            };
            if let Some(s) = secs {
                dir_ver = Some(unix_secs_to_ymd(s));
            }
        }
        if let Some(ref v) = dir_ver {
            pick_newer_version(&mut best, v);
        }
    }
    best
}

/// Detect installed `Silas-02/antigravity-desktop-cn` patch version/date across Antigravity dirs.
pub fn installed_antigravity_cn_version() -> Option<String> {
    installed_antigravity_cn_version_in_dirs(&antigravity_covered_dirs())
}

// ---------- Cached ProcessScanner (zero scan on UI reads) ----------

/// Immutable process table snapshot served lock-free / RwLock-fast to UI and leak watch.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CachedProcessSnapshot {
    pub scanned_at_unix: u64,
    pub gui_counts: HashMap<String, usize>,
    pub cli_counts: HashMap<String, usize>,
    #[serde(default)]
    pub orphan_counts: HashMap<String, usize>,
    #[serde(default)]
    pub claude_dirs_l: Vec<String>,
    #[serde(default)]
    pub chatgpt_dirs_l: Vec<String>,
    #[serde(default)]
    pub antigravity_dirs_l: Vec<String>,
    pub procs: Vec<ProcInfo>,
}

impl CachedProcessSnapshot {
    /// Build a PID -> display-name map for currently guarded agent processes (GUI + CLI +
    /// full descendant network helpers/MCP/cua_node/SCM services for leak-watch awareness; zero OS calls).
    pub fn guarded_agent_pids(
        &self,
        guarded_agents: &[String],
        claude_dir_l: Option<&str>,
    ) -> HashMap<u32, String> {
        self.guarded_agent_pids_with_all_dirs(
            guarded_agents,
            claude_dir_l,
            &self.claude_dirs_l,
            &self.chatgpt_dirs_l,
            &self.antigravity_dirs_l,
        )
    }

    /// Build a PID -> display-name map with explicit Antigravity covered directories.
    pub fn guarded_agent_pids_with_dirs(
        &self,
        guarded_agents: &[String],
        claude_dir_l: Option<&str>,
        ag_dirs_l: &[String],
    ) -> HashMap<u32, String> {
        self.guarded_agent_pids_with_all_dirs(
            guarded_agents,
            claude_dir_l,
            &self.claude_dirs_l,
            &self.chatgpt_dirs_l,
            ag_dirs_l,
        )
    }

    /// Build a PID -> display-name map across all covered GUI + CLI agent roots and their
    /// full non-shell descendant process trees (through `cmd.exe`, SCM services, `cua_node`, etc.).
    pub fn guarded_agent_pids_with_all_dirs(
        &self,
        guarded_agents: &[String],
        claude_dir_l: Option<&str>,
        claude_dirs_l: &[String],
        chatgpt_dirs_l: &[String],
        ag_dirs_l: &[String],
    ) -> HashMap<u32, String> {
        let mut out = HashMap::new();
        if guarded_agents.is_empty() {
            return out;
        }

        let mut eff_claude_dirs = claude_dirs_l.to_vec();
        if let Some(extra) = claude_dir_l.map(str::trim).filter(|s| !s.is_empty()) {
            if !eff_claude_dirs
                .iter()
                .any(|d| d.eq_ignore_ascii_case(extra))
            {
                eff_claude_dirs.push(extra.to_ascii_lowercase());
            }
        }

        let guard_claude = guarded_agents.iter().any(|g| g == "claude");
        let guard_chatgpt = guarded_agents.iter().any(|g| g == "chatgpt");
        let guard_ag = guarded_agents.iter().any(|g| g == "antigravity");
        let guard_claude_cli = guard_claude || guarded_agents.iter().any(|g| g == "claude-code");
        let guard_codex_cli = guard_chatgpt || guarded_agents.iter().any(|g| g == "codex");

        let is_main_gui_exe = |owner_id: &str, exe_name_l: &str| -> bool {
            match owner_id {
                "claude" => exe_name_l == "claude.exe",
                "chatgpt" => matches!(
                    exe_name_l,
                    "chatgpt.exe" | "chatgpt classic.exe" | "codex.exe"
                ),
                "antigravity" => matches!(exe_name_l, "antigravity.exe" | "antigravity ide.exe"),
                _ => false,
            }
        };

        let primary_proc_label = |base_label: &str, owner_id: &str, exe_name_l: &str| -> String {
            if !is_main_gui_exe(owner_id, exe_name_l)
                && crate::netwatch_win::is_mcp_agent_label(exe_name_l)
            {
                format!("{base_label} ({exe_name_l})")
            } else {
                base_label.to_string()
            }
        };

        let children_by_ppid = build_children_map(&self.procs);
        let mut queue: Vec<(u32, String, &'static str)> = Vec::new();
        let mut visited_pids: HashSet<u32> = HashSet::new();

        for p in &self.procs {
            if is_uninstaller_exe(&p.name_l) {
                continue;
            }
            if guard_claude_cli
                && cli_agent_matches_with_dirs(
                    "claude-code",
                    &p.name_l,
                    &p.path_l,
                    &p.cmd_l,
                    chatgpt_dirs_l,
                )
            {
                let label = "Claude Code".to_string();
                out.insert(p.pid, label.clone());
                if visited_pids.insert(p.pid) {
                    queue.push((p.pid, label, "claude"));
                }
                continue;
            }
            if guard_codex_cli
                && cli_agent_matches_with_dirs(
                    "codex",
                    &p.name_l,
                    &p.path_l,
                    &p.cmd_l,
                    chatgpt_dirs_l,
                )
            {
                let label = "Codex CLI".to_string();
                let proc_label = if matches!(
                    p.name_l.as_str(),
                    "codex.exe" | "codex" | "node.exe" | "node" | "bun.exe" | "deno.exe"
                ) {
                    label.clone()
                } else {
                    format!("{label} ({})", p.name_l)
                };
                out.insert(p.pid, proc_label);
                if visited_pids.insert(p.pid) {
                    queue.push((p.pid, label, "chatgpt"));
                }
                continue;
            }
            if guard_claude
                && primary_gui_matches_with_dirs(
                    "claude",
                    p,
                    &eff_claude_dirs,
                    chatgpt_dirs_l,
                    ag_dirs_l,
                )
            {
                let label = gui_agent_name("claude").to_string();
                out.insert(p.pid, primary_proc_label(&label, "claude", &p.name_l));
                if visited_pids.insert(p.pid) {
                    queue.push((p.pid, label, "claude"));
                }
                continue;
            }
            if guard_chatgpt
                && primary_gui_matches_with_dirs(
                    "chatgpt",
                    p,
                    &eff_claude_dirs,
                    chatgpt_dirs_l,
                    ag_dirs_l,
                )
            {
                let label = gui_agent_name("chatgpt").to_string();
                out.insert(p.pid, primary_proc_label(&label, "chatgpt", &p.name_l));
                if visited_pids.insert(p.pid) {
                    queue.push((p.pid, label, "chatgpt"));
                }
                continue;
            }
            if guard_ag && is_antigravity_dir_proc(p, ag_dirs_l) {
                let label = gui_agent_name("antigravity").to_string();
                out.insert(p.pid, primary_proc_label(&label, "antigravity", &p.name_l));
                if visited_pids.insert(p.pid) {
                    queue.push((p.pid, label, "antigravity"));
                }
                continue;
            }
        }

        // Walk descendant trees across ALL guarded GUI & CLI processes (through `cmd.exe /c` & SCM services,
        // stopping at interactive user shells unless inside an agent's MSIX/install directory).
        while let Some((pid, label, owner_id)) = queue.pop() {
            let Some(kids) = children_by_ppid.get(&pid) else {
                continue;
            };
            for &child_idx in kids {
                let child = &self.procs[child_idx];
                if is_uninstaller_exe(&child.name_l)
                    || is_any_cli_agent_with_dirs(child, chatgpt_dirs_l)
                {
                    continue;
                }
                let in_agent_dir = match owner_id {
                    "antigravity" => is_antigravity_dir_proc(child, ag_dirs_l),
                    "claude" => eff_claude_dirs
                        .iter()
                        .any(|d| path_under_dir_l(&child.path_l, d)),
                    "chatgpt" => {
                        chatgpt_dirs_l
                            .iter()
                            .any(|d| path_under_dir_l(&child.path_l, d))
                            || gui_agent_matches("chatgpt", &child.name_l, &child.path_l, None)
                    }
                    _ => false,
                };
                if !in_agent_dir && is_interactive_shell_proc(child) {
                    continue;
                }
                if visited_pids.insert(child.pid) {
                    queue.push((child.pid, label.clone(), owner_id));
                }
                if !matches!(
                    child.name_l.as_str(),
                    "cmd.exe" | "cmd" | "conhost.exe" | "openconsole.exe"
                ) {
                    out.entry(child.pid).or_insert_with(|| {
                        if is_main_gui_exe(owner_id, &child.name_l) {
                            label.clone()
                        } else {
                            format!("{label} ({})", child.name_l)
                        }
                    });
                }
            }
        }

        out
    }
}

fn primary_gui_matches_with_dirs(
    agent_id: &str,
    p: &ProcInfo,
    claude_dirs_l: &[String],
    chatgpt_dirs_l: &[String],
    ag_dirs_l: &[String],
) -> bool {
    if is_uninstaller_exe(&p.name_l) || is_any_cli_agent_with_dirs(p, chatgpt_dirs_l) {
        return false;
    }
    match agent_id {
        "claude" => {
            gui_agent_matches(
                "claude",
                &p.name_l,
                &p.path_l,
                claude_dirs_l.first().map(String::as_str),
            ) || claude_dirs_l.iter().any(|d| path_under_dir_l(&p.path_l, d))
        }
        "chatgpt" => {
            gui_agent_matches("chatgpt", &p.name_l, &p.path_l, None)
                || chatgpt_dirs_l
                    .iter()
                    .any(|d| path_under_dir_l(&p.path_l, d))
        }
        "antigravity" => is_antigravity_dir_proc(p, ag_dirs_l),
        _ => false,
    }
}

/// Pure snapshot builder over a full process table: identifies primary GUI/CLI agent processes,
/// computes the cycle-safe descendant process tree closure rooted at guarded GUI & CLI agents,
/// and computes `gui_counts`, `cli_counts`, and `orphan_counts` across all 5 categories.
pub fn build_process_snapshot_from_table(
    all_procs: Vec<ProcInfo>,
    claude_dirs_l: &[String],
    chatgpt_dirs_l: &[String],
    ag_dirs_l: &[String],
    scanned_at_unix: u64,
) -> CachedProcessSnapshot {
    let children_by_ppid = build_children_map(&all_procs);
    let pid_to_idx: HashMap<u32, usize> = all_procs
        .iter()
        .enumerate()
        .map(|(i, p)| (p.pid, i))
        .collect();

    // Compute orphan sets against the FULL live process table so alive parent terminal PIDs are accurate.
    let ag_orphans_all: HashSet<usize> = pick_antigravity_orphans(&all_procs, ag_dirs_l)
        .into_iter()
        .collect();
    let claude_orphans_all: HashSet<usize> = pick_claude_orphans(&all_procs, claude_dirs_l)
        .into_iter()
        .collect();
    let chatgpt_orphans_all: HashSet<usize> =
        pick_chatgpt_codex_orphans(&all_procs, chatgpt_dirs_l)
            .into_iter()
            .collect();
    let claude_cli_orphans_all: HashSet<usize> =
        pick_cli_orphans_with_dirs("claude-code", &all_procs, chatgpt_dirs_l)
            .into_iter()
            .collect();
    let codex_cli_orphans_all: HashSet<usize> =
        pick_cli_orphans_with_dirs("codex", &all_procs, chatgpt_dirs_l)
            .into_iter()
            .collect();

    let mut keep_indices: HashSet<usize> = HashSet::new();
    let mut queue: Vec<u32> = Vec::new();
    let mut visited_pids: HashSet<u32> = HashSet::new();

    for (idx, p) in all_procs.iter().enumerate() {
        let is_gui = GUI_AGENTS.iter().any(|a| {
            primary_gui_matches_with_dirs(a.id, p, claude_dirs_l, chatgpt_dirs_l, ag_dirs_l)
        });
        if is_gui {
            keep_indices.insert(idx);
            if visited_pids.insert(p.pid) {
                queue.push(p.pid);
            }
        } else if is_any_cli_agent_with_dirs(p, chatgpt_dirs_l) {
            keep_indices.insert(idx);
            if visited_pids.insert(p.pid) {
                queue.push(p.pid);
            }
            // Keep immediate parent process record so CLI parent liveness stays inspectable in procs.
            if let Some(&par_idx) = pid_to_idx.get(&p.ppid) {
                keep_indices.insert(par_idx);
            }
        }
    }

    // Descendant process tree closure rooted at GUI & CLI agents (cycle-safe).
    while let Some(pid) = queue.pop() {
        let Some(kids) = children_by_ppid.get(&pid) else {
            continue;
        };
        for &child_idx in kids {
            keep_indices.insert(child_idx);
            let child_pid = all_procs[child_idx].pid;
            if visited_pids.insert(child_pid) {
                queue.push(child_pid);
            }
        }
    }

    for &idx in ag_orphans_all
        .iter()
        .chain(claude_orphans_all.iter())
        .chain(chatgpt_orphans_all.iter())
        .chain(claude_cli_orphans_all.iter())
        .chain(codex_cli_orphans_all.iter())
    {
        keep_indices.insert(idx);
    }

    let mut procs = Vec::with_capacity(keep_indices.len());
    let mut ag_orphan_new = HashSet::new();
    let mut claude_orphan_new = HashSet::new();
    let mut chatgpt_orphan_new = HashSet::new();
    let mut claude_cli_orphan_new = HashSet::new();
    let mut codex_cli_orphan_new = HashSet::new();

    for (old_idx, p) in all_procs.into_iter().enumerate() {
        if keep_indices.contains(&old_idx) {
            let new_idx = procs.len();
            if ag_orphans_all.contains(&old_idx) {
                ag_orphan_new.insert(new_idx);
            }
            if claude_orphans_all.contains(&old_idx) {
                claude_orphan_new.insert(new_idx);
            }
            if chatgpt_orphans_all.contains(&old_idx) {
                chatgpt_orphan_new.insert(new_idx);
            }
            if claude_cli_orphans_all.contains(&old_idx) {
                claude_cli_orphan_new.insert(new_idx);
            }
            if codex_cli_orphans_all.contains(&old_idx) {
                codex_cli_orphan_new.insert(new_idx);
            }
            procs.push(p);
        }
    }

    let mut gui_counts: HashMap<String, usize> = HashMap::new();
    let mut cli_counts: HashMap<String, usize> = HashMap::new();
    let mut orphan_counts: HashMap<String, usize> = HashMap::new();

    if !ag_orphans_all.is_empty() {
        orphan_counts.insert("antigravity".to_string(), ag_orphans_all.len());
    }
    if !claude_orphans_all.is_empty() {
        orphan_counts.insert("claude".to_string(), claude_orphans_all.len());
    }
    if !chatgpt_orphans_all.is_empty() {
        orphan_counts.insert("chatgpt".to_string(), chatgpt_orphans_all.len());
    }
    if !claude_cli_orphans_all.is_empty() {
        orphan_counts.insert("claude-code".to_string(), claude_cli_orphans_all.len());
    }
    if !codex_cli_orphans_all.is_empty() {
        orphan_counts.insert("codex".to_string(), codex_cli_orphans_all.len());
    }

    for (idx, info) in procs.iter().enumerate() {
        if !is_agent_scm_service_exe(&info.name_l) {
            for a in GUI_AGENTS {
                let is_orphan = match a.id {
                    "antigravity" => ag_orphan_new.contains(&idx),
                    "claude" => claude_orphan_new.contains(&idx),
                    "chatgpt" => chatgpt_orphan_new.contains(&idx),
                    _ => false,
                };
                if !is_orphan
                    && primary_gui_matches_with_dirs(
                        a.id,
                        info,
                        claude_dirs_l,
                        chatgpt_dirs_l,
                        ag_dirs_l,
                    )
                {
                    *gui_counts.entry(a.id.to_string()).or_default() += 1;
                }
            }
        }
        for (cid, _) in CLI_AGENTS {
            let is_orphan = match *cid {
                "claude-code" => claude_cli_orphan_new.contains(&idx),
                "codex" => codex_cli_orphan_new.contains(&idx),
                _ => false,
            };
            if !is_orphan
                && cli_agent_matches_with_dirs(
                    cid,
                    &info.name_l,
                    &info.path_l,
                    &info.cmd_l,
                    chatgpt_dirs_l,
                )
            {
                *cli_counts.entry((*cid).to_string()).or_default() += 1;
            }
        }
    }

    CachedProcessSnapshot {
        scanned_at_unix,
        gui_counts,
        cli_counts,
        orphan_counts,
        claude_dirs_l: claude_dirs_l.to_vec(),
        chatgpt_dirs_l: chatgpt_dirs_l.to_vec(),
        antigravity_dirs_l: ag_dirs_l.to_vec(),
        procs,
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn dirs_to_lowercase(dirs: Vec<PathBuf>) -> Vec<String> {
    dirs.into_iter()
        .map(|d| {
            let raw = d.to_string_lossy();
            strip_verbatim_win32_str(&raw)
                .replace('/', "\\")
                .to_ascii_lowercase()
        })
        .collect()
}

fn minimal_process_refresh_kind() -> sysinfo::ProcessRefreshKind {
    sysinfo::ProcessRefreshKind::new()
        .with_exe(sysinfo::UpdateKind::OnlyIfNotSet)
        .with_cmd(sysinfo::UpdateKind::OnlyIfNotSet)
}

fn collect_sys_procs(sys: &sysinfo::System) -> Vec<ProcInfo> {
    sys.processes()
        .values()
        .map(|p| ProcInfo {
            pid: p.pid().as_u32(),
            ppid: p.parent().map(|x| x.as_u32()).unwrap_or(0),
            name_l: p.name().to_ascii_lowercase(),
            path_l: p
                .exe()
                .map(|e| {
                    let raw = e.to_string_lossy();
                    strip_verbatim_win32_str(&raw)
                        .replace('/', "\\")
                        .to_ascii_lowercase()
                })
                .unwrap_or_default(),
            cmd_l: p
                .cmd()
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<_>>()
                .join(" ")
                .to_ascii_lowercase(),
            start_time: p.start_time(),
        })
        .collect()
}

struct ScannerInner {
    sys: sysinfo::System,
    last_refresh: Option<Instant>,
}

/// Thread-safe cached process scanner.
///
/// `cached_snapshot()` ONLY clones the cached `RwLock` payload (zero syscalls), guaranteeing
/// UI reads never block on PEB / Toolhelp enumeration.
pub struct ProcessScanner {
    ttl: Duration,
    inner: Mutex<ScannerInner>,
    cache: Arc<RwLock<CachedProcessSnapshot>>,
}

impl ProcessScanner {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Mutex::new(ScannerInner {
                sys: sysinfo::System::new(),
                last_refresh: None,
            }),
            cache: Arc::new(RwLock::new(CachedProcessSnapshot::default())),
        }
    }

    /// Return the last cached snapshot immediately without performing any OS scan.
    pub fn cached_snapshot(&self) -> CachedProcessSnapshot {
        self.cache.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Seed cache deterministically in unit tests without hitting the OS process table.
    #[cfg(test)]
    pub(crate) fn seed_for_test(&self, snap: CachedProcessSnapshot) {
        *self.cache.write().unwrap_or_else(|e| e.into_inner()) = snap;
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .last_refresh = Some(Instant::now());
    }

    /// Return cached snapshot if within `ttl`, otherwise run `refresh()`.
    pub fn snapshot_if_stale(&self) -> CachedProcessSnapshot {
        let fresh = {
            let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            guard.last_refresh.is_some_and(|t| t.elapsed() < self.ttl)
        };
        if fresh {
            return self.cached_snapshot();
        }
        self.refresh()
    }

    /// Perform a single bounded process table refresh and atomically update the cached snapshot.
    pub fn refresh(&self) -> CachedProcessSnapshot {
        let claude_dirs_l = dirs_to_lowercase(claude_covered_dirs());
        let chatgpt_dirs_l = dirs_to_lowercase(chatgpt_covered_dirs());
        let ag_dirs_l = dirs_to_lowercase(antigravity_covered_dirs());

        let all_procs = {
            let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner
                .sys
                .refresh_processes_specifics(minimal_process_refresh_kind());
            let collected = collect_sys_procs(&inner.sys);
            inner.last_refresh = Some(Instant::now());
            collected
        };

        let snap = build_process_snapshot_from_table(
            all_procs,
            &claude_dirs_l,
            &chatgpt_dirs_l,
            &ag_dirs_l,
            unix_now(),
        );
        *self.cache.write().unwrap_or_else(|e| e.into_inner()) = snap.clone();
        snap
    }
}

/// Verified termination report distinguishing killed vs PID-reuse skipped processes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedKillOutcome {
    pub killed: Vec<ProcessIdentity>,
    pub skipped_reused: Vec<ProcessIdentity>,
    pub vanished: Vec<u32>,
}

/// Pure testable termination orchestrator: checks `same_identity` against `inspect_now(pid)`
/// immediately before invoking `kill_now(pid)`.
pub fn terminate_with_recheck<FInspect, FKill>(
    candidates: &[ProcessIdentity],
    mut inspect_now: FInspect,
    mut kill_now: FKill,
) -> VerifiedKillOutcome
where
    FInspect: FnMut(u32) -> Option<ProcessIdentity>,
    FKill: FnMut(u32) -> bool,
{
    let mut outcome = VerifiedKillOutcome::default();
    for expected in candidates {
        let Some(observed) = inspect_now(expected.pid) else {
            outcome.vanished.push(expected.pid);
            continue;
        };
        if !same_identity(expected, &observed) {
            outcome.skipped_reused.push(expected.clone());
            continue;
        }
        if kill_now(expected.pid) {
            outcome.killed.push(expected.clone());
        }
    }
    outcome
}

#[cfg(windows)]
fn normalize_identity_exe_path(raw: &str) -> String {
    strip_verbatim_win32_str(raw)
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeKillStep {
    Killed,
    Vanished,
    SkippedMismatch,
    Failed,
}

/// Native Win32 handle-pinned process termination:
/// Opens ONE kernel `HANDLE` (`PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE`), verifies
/// `GetExitCodeProcess == STILL_ACTIVE`, `GetProcessTimes` (`lpCreationTime`), and
/// `QueryFullProcessImageNameW` (4096-`u16` buffer) on THAT EXACT HANDLE, then calls
/// `TerminateProcess(h, 1)` directly — zero `taskkill.exe` subprocesses and zero PID-reuse TOCTOU!
#[cfg(windows)]
pub(crate) fn terminate_identity_win32(expected: &ProcessIdentity) -> NativeKillStep {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{CloseHandle, ERROR_INVALID_PARAMETER, FILETIME, HANDLE};
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, GetProcessTimes, OpenProcess, QueryFullProcessImageNameW,
        TerminateProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
    };

    struct WinHandleGuard(HANDLE);
    impl Drop for WinHandleGuard {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    const STILL_ACTIVE_CODE: u32 = 259;
    const WINDOWS_TO_UNIX_EPOCH_SECS: u64 = 11_644_473_600;

    if expected.pid == 0 || expected.pid == std::process::id() {
        return NativeKillStep::SkippedMismatch;
    }
    if expected.start_time == 0 && expected.exe_path.trim().is_empty() {
        return NativeKillStep::SkippedMismatch;
    }

    unsafe {
        let handle = match OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
            false,
            expected.pid,
        ) {
            Ok(h) => h,
            Err(e) if e.code() == ERROR_INVALID_PARAMETER.to_hresult() => {
                return NativeKillStep::Vanished;
            }
            Err(_) => return NativeKillStep::Failed,
        };
        let _guard = WinHandleGuard(handle);

        let mut exit_code: u32 = 0;
        if GetExitCodeProcess(handle, &mut exit_code).is_err() {
            return NativeKillStep::Failed;
        }
        if exit_code != STILL_ACTIVE_CODE {
            return NativeKillStep::Vanished;
        }

        let mut creation = FILETIME::default();
        let mut exit_time = FILETIME::default();
        let mut kernel_time = FILETIME::default();
        let mut user_time = FILETIME::default();
        if GetProcessTimes(
            handle,
            &mut creation,
            &mut exit_time,
            &mut kernel_time,
            &mut user_time,
        )
        .is_err()
        {
            return NativeKillStep::SkippedMismatch;
        }
        let ticks = ((creation.dwHighDateTime as u64) << 32) | (creation.dwLowDateTime as u64);
        let actual_secs = (ticks / 10_000_000).saturating_sub(WINDOWS_TO_UNIX_EPOCH_SECS);
        if expected.start_time != 0 && actual_secs.abs_diff(expected.start_time) > 1 {
            return NativeKillStep::SkippedMismatch;
        }

        if !expected.exe_path.trim().is_empty() {
            let mut buf = vec![0u16; 4096];
            let mut size = buf.len() as u32;
            if QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_WIN32,
                PWSTR(buf.as_mut_ptr()),
                &mut size,
            )
            .is_err()
                || size == 0
            {
                return NativeKillStep::SkippedMismatch;
            }
            let actual_path = String::from_utf16_lossy(&buf[..(size as usize).min(buf.len())]);
            if normalize_identity_exe_path(&actual_path)
                != normalize_identity_exe_path(&expected.exe_path)
            {
                return NativeKillStep::SkippedMismatch;
            }
        }

        match TerminateProcess(handle, 1) {
            Ok(()) => NativeKillStep::Killed,
            Err(_) => {
                let mut post_code: u32 = 0;
                if GetExitCodeProcess(handle, &mut post_code).is_ok()
                    && post_code != STILL_ACTIVE_CODE
                {
                    NativeKillStep::Vanished
                } else {
                    NativeKillStep::Failed
                }
            }
        }
    }
}

/// Captures a kernel-verified [`ProcessIdentity`] `(pid, start_time, exe_path)` from a live `pid`
/// via `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` + `GetProcessTimes` + `QueryFullProcessImageNameW`.
#[cfg(windows)]
pub fn capture_process_identity(pid: u32) -> Option<ProcessIdentity> {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, GetProcessTimes, OpenProcess, QueryFullProcessImageNameW,
        PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    struct WinHandleGuard(HANDLE);
    impl Drop for WinHandleGuard {
        fn drop(&mut self) {
            if !self.0.is_invalid() && !self.0 .0.is_null() {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    const STILL_ACTIVE_CODE: u32 = 259;
    const WINDOWS_TO_UNIX_EPOCH_SECS: u64 = 11_644_473_600;

    if pid == 0 {
        return None;
    }

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let _guard = WinHandleGuard(handle);

        let mut exit_code: u32 = 0;
        if GetExitCodeProcess(handle, &mut exit_code).is_err() || exit_code != STILL_ACTIVE_CODE {
            return None;
        }

        let mut creation = FILETIME::default();
        let mut exit_time = FILETIME::default();
        let mut kernel_time = FILETIME::default();
        let mut user_time = FILETIME::default();
        if GetProcessTimes(
            handle,
            &mut creation,
            &mut exit_time,
            &mut kernel_time,
            &mut user_time,
        )
        .is_err()
        {
            return None;
        }
        let ticks = ((creation.dwHighDateTime as u64) << 32) | (creation.dwLowDateTime as u64);
        let start_time = (ticks / 10_000_000).saturating_sub(WINDOWS_TO_UNIX_EPOCH_SECS);

        let mut buf = vec![0u16; 4096];
        let mut size = buf.len() as u32;
        if QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut size,
        )
        .is_err()
            || size == 0
        {
            return None;
        }
        let raw_path = String::from_utf16_lossy(&buf[..(size as usize).min(buf.len())]);
        let exe_path = normalize_identity_exe_path(&raw_path);
        if exe_path.is_empty() {
            return None;
        }
        Some(ProcessIdentity {
            pid,
            start_time,
            exe_path,
        })
    }
}

#[cfg(not(windows))]
pub fn capture_process_identity(_pid: u32) -> Option<ProcessIdentity> {
    None
}

/// Terminates a single [`ProcessIdentity`] via handle-pinned `(pid, start_time, exe_path)`
/// verification, returning `true` iff the matching live process was terminated.
#[cfg(windows)]
pub fn terminate_verified_identity(id: &ProcessIdentity) -> bool {
    matches!(terminate_identity_win32(id), NativeKillStep::Killed)
}

#[cfg(not(windows))]
pub fn terminate_verified_identity(_id: &ProcessIdentity) -> bool {
    false
}

#[cfg(windows)]
fn terminate_identities_native(candidates: &[ProcessIdentity]) -> VerifiedKillOutcome {
    let mut outcome = VerifiedKillOutcome::default();
    for expected in candidates {
        match terminate_identity_win32(expected) {
            NativeKillStep::Killed => outcome.killed.push(expected.clone()),
            NativeKillStep::Vanished => outcome.vanished.push(expected.pid),
            NativeKillStep::SkippedMismatch | NativeKillStep::Failed => {
                outcome.skipped_reused.push(expected.clone());
            }
        }
    }
    outcome
}

#[cfg(not(windows))]
fn terminate_identities_native(candidates: &[ProcessIdentity]) -> VerifiedKillOutcome {
    let mut outcome = VerifiedKillOutcome::default();
    for c in candidates {
        outcome.vanished.push(c.pid);
    }
    outcome
}

/// Kill GUI process tree matching `agent_id` children-first (NEVER touches CLI processes,
/// SCM service hosts, or interactive user shells), re-verifying `(pid, start_time, exe_path)`
/// via a single pinned Win32 `HANDLE` immediately before each `TerminateProcess`.
pub fn kill_gui_agent(agent_id: &str) -> Vec<ProcessIdentity> {
    use sysinfo::System;

    let claude_dirs_l = dirs_to_lowercase(claude_covered_dirs());
    let chatgpt_dirs_l = dirs_to_lowercase(chatgpt_covered_dirs());
    let ag_dirs_l = dirs_to_lowercase(antigravity_covered_dirs());

    let mut sys = System::new();
    sys.refresh_processes_specifics(minimal_process_refresh_kind());
    let procs = collect_sys_procs(&sys);

    let candidates = pick_gui_agent_kill_tree_with_dirs(
        agent_id,
        &procs,
        &claude_dirs_l,
        &chatgpt_dirs_l,
        &ag_dirs_l,
    );
    terminate_identities_native(&candidates).killed
}

/// Kill CLI session process tree matching `cli_id` (`claude-code`, `codex`)
/// children-first with handle-pinned PID-reuse identity re-verification (never touches ancestor terminals).
pub fn kill_cli_agent(cli_id: &str) -> Vec<ProcessIdentity> {
    use sysinfo::System;

    let chatgpt_dirs_l = dirs_to_lowercase(chatgpt_covered_dirs());
    let mut sys = System::new();
    sys.refresh_processes_specifics(minimal_process_refresh_kind());
    let procs = collect_sys_procs(&sys);

    let candidates = pick_cli_agent_kill_tree_with_dirs(cli_id, &procs, &chatgpt_dirs_l);
    terminate_identities_native(&candidates).killed
}

/// Sweep Claude desktop residuals / orphan CLI processes with handle-pinned Win32 termination.
/// Never kills CLI processes attached to live terminals in `SweepMode::Residual`.
pub fn sweep_claude(mode: SweepMode) -> SweepReport {
    use sysinfo::System;

    let claude_dirs_l = dirs_to_lowercase(claude_covered_dirs());
    let mut sys = System::new();
    sys.refresh_processes_specifics(minimal_process_refresh_kind());
    let procs = collect_sys_procs(&sys);

    let picks = match mode {
        SweepMode::Manual => pick_manual_with_dirs(&procs, &claude_dirs_l),
        SweepMode::Residual => match pick_residual_with_dirs(&procs, &claude_dirs_l) {
            Some(v) => v,
            None => {
                return SweepReport {
                    scanned: pick_manual_with_dirs(&procs, &claude_dirs_l).len(),
                    note: "桌面端仍在运行，不清理".into(),
                    ..SweepReport::default()
                };
            }
        },
    };

    if picks.is_empty() {
        return SweepReport::default();
    }

    let candidates: Vec<ProcessIdentity> = picks
        .iter()
        .map(|(idx, _)| procs[*idx].identity())
        .collect();
    let meta_by_pid: HashMap<u32, (&str, ClaudeKind)> = picks
        .iter()
        .map(|(idx, kind)| (procs[*idx].pid, (procs[*idx].name_l.as_str(), *kind)))
        .collect();

    let outcome = terminate_identities_native(&candidates);
    let mut report = SweepReport {
        scanned: candidates.len(),
        killed: outcome.killed.len(),
        unconfirmed: outcome.skipped_reused.len() + outcome.vanished.len(),
        ..SweepReport::default()
    };

    for killed in &outcome.killed {
        if let Some(&(name_l, kind)) = meta_by_pid.get(&killed.pid) {
            match kind {
                ClaudeKind::Desktop => report.desktop_killed += 1,
                ClaudeKind::Cli => report.cli_killed += 1,
            }
            report
                .detail
                .push(format!("pid={} {}（{}）", killed.pid, name_l, kind.label()));
        }
    }
    report
}

/// Orphan category tag for unified 5-category residual sweeping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrphanCategory {
    Antigravity,
    ClaudeDesktop,
    ChatGptCodex,
    ClaudeCodeCli,
    CodexCli,
}

impl OrphanCategory {
    pub fn label_zh(self) -> &'static str {
        match self {
            Self::Antigravity => "反重力孤儿",
            Self::ClaudeDesktop => "Claude 桌面端",
            Self::ChatGptCodex => "ChatGPT/Codex 孤儿",
            Self::ClaudeCodeCli => "Claude CLI",
            Self::CodexCli => "Codex CLI",
        }
    }

    pub fn is_cli(self) -> bool {
        matches!(self, Self::ClaudeCodeCli | Self::CodexCli)
    }
}

/// Pure aggregator collecting all 5 orphan categories (Antigravity, Claude Desktop,
/// ChatGPT/Codex Desktop, Claude Code CLI, Codex CLI) deduplicated and children-first.
pub fn pick_all_orphan_targets(
    procs: &[ProcInfo],
    claude_dirs_l: &[String],
    chatgpt_dirs_l: &[String],
    ag_dirs_l: &[String],
) -> Vec<(usize, OrphanCategory)> {
    let mut targets = Vec::new();
    let mut seen_pids = HashSet::new();

    let buckets = [
        (
            pick_antigravity_orphans(procs, ag_dirs_l),
            OrphanCategory::Antigravity,
        ),
        (
            pick_claude_orphans(procs, claude_dirs_l),
            OrphanCategory::ClaudeDesktop,
        ),
        (
            pick_chatgpt_codex_orphans(procs, chatgpt_dirs_l),
            OrphanCategory::ChatGptCodex,
        ),
        (
            pick_cli_orphans_with_dirs("claude-code", procs, chatgpt_dirs_l),
            OrphanCategory::ClaudeCodeCli,
        ),
        (
            pick_cli_orphans_with_dirs("codex", procs, chatgpt_dirs_l),
            OrphanCategory::CodexCli,
        ),
    ];

    for (indices, cat) in buckets {
        for idx in indices {
            if seen_pids.insert(procs[idx].pid) {
                targets.push((idx, cat));
            }
        }
    }
    targets
}

/// Sweep all orphaned residual processes across all 5 guarded categories (Claude desktop,
/// ChatGPT/Codex desktop, Antigravity, Claude Code CLI, Codex CLI) children-first with
/// handle-pinned `(pid, start_time, exe_path)` Win32 termination.
pub fn sweep_all_orphans() -> SweepReport {
    use sysinfo::System;

    let claude_dirs_l = dirs_to_lowercase(claude_covered_dirs());
    let chatgpt_dirs_l = dirs_to_lowercase(chatgpt_covered_dirs());
    let ag_dirs_l = dirs_to_lowercase(antigravity_covered_dirs());

    let mut sys = System::new();
    sys.refresh_processes_specifics(minimal_process_refresh_kind());
    let procs = collect_sys_procs(&sys);

    let targets = pick_all_orphan_targets(&procs, &claude_dirs_l, &chatgpt_dirs_l, &ag_dirs_l);
    if targets.is_empty() {
        return SweepReport::default();
    }

    let candidates: Vec<ProcessIdentity> = targets
        .iter()
        .map(|(idx, _)| procs[*idx].identity())
        .collect();
    let meta_by_pid: HashMap<u32, (&str, OrphanCategory)> = targets
        .iter()
        .map(|(idx, cat)| (procs[*idx].pid, (procs[*idx].name_l.as_str(), *cat)))
        .collect();

    let outcome = terminate_identities_native(&candidates);
    let mut report = SweepReport {
        scanned: candidates.len(),
        killed: outcome.killed.len(),
        unconfirmed: outcome.skipped_reused.len() + outcome.vanished.len(),
        ..SweepReport::default()
    };

    for killed in &outcome.killed {
        if let Some(&(name_l, cat)) = meta_by_pid.get(&killed.pid) {
            if cat.is_cli() {
                report.cli_killed += 1;
            } else {
                report.desktop_killed += 1;
            }
            report.detail.push(format!(
                "pid={} {}（{}）",
                killed.pid,
                name_l,
                cat.label_zh()
            ));
        }
    }
    report
}

/// Fast Toolhelp32 Claude desktop presence check (zero PEB cmdline reads).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaudePresence {
    None,
    CliOnly,
    Desktop,
}

#[cfg(windows)]
pub fn claude_presence_fast(claude_dir_l: Option<&str>) -> ClaudePresence {
    use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    struct WinHandleGuard(HANDLE);
    impl Drop for WinHandleGuard {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    let mut seen = ClaudePresence::None;
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return ClaudePresence::Desktop;
        };
        if snap == INVALID_HANDLE_VALUE {
            return ClaudePresence::Desktop;
        }
        let _snap_guard = WinHandleGuard(snap);

        let mut entry = PROCESSENTRY32W {
            dwSize: core::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        if Process32FirstW(snap, &mut entry).is_ok() {
            loop {
                let len = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let name_l = String::from_utf16_lossy(&entry.szExeFile[..len]).to_ascii_lowercase();
                if name_l.contains("claude")
                    && !is_agent_scm_service_exe(&name_l)
                    && !is_uninstaller_exe(&name_l)
                {
                    let mut path_l = String::new();
                    if let Ok(handle) = OpenProcess(
                        PROCESS_QUERY_LIMITED_INFORMATION,
                        false,
                        entry.th32ProcessID,
                    ) {
                        let _proc_guard = WinHandleGuard(handle);
                        let mut buf = vec![0u16; 4096];
                        let mut size = buf.len() as u32;
                        if QueryFullProcessImageNameW(
                            handle,
                            PROCESS_NAME_WIN32,
                            windows::core::PWSTR(buf.as_mut_ptr()),
                            &mut size,
                        )
                        .is_ok()
                            && size > 0
                        {
                            path_l =
                                String::from_utf16_lossy(&buf[..(size as usize).min(buf.len())])
                                    .to_ascii_lowercase();
                        }
                    }
                    let cli = is_claude_cli_path_l(&path_l) || path_l.contains("@anthropic-ai");
                    let in_dir = claude_dir_l.is_some_and(|d| path_under_dir_l(&path_l, d));
                    if !cli
                        && (in_dir
                            || path_l.contains("windowsapps")
                            || path_l.contains(r"\anthropicclaude\")
                            || path_l.contains(r"\programs\claude\"))
                    {
                        seen = ClaudePresence::Desktop;
                        break;
                    }
                    if seen == ClaudePresence::None {
                        seen = ClaudePresence::CliOnly;
                    }
                }
                if Process32NextW(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
    }
    seen
}

#[cfg(not(windows))]
pub fn claude_presence_fast(_claude_dir_l: Option<&str>) -> ClaudePresence {
    ClaudePresence::None
}

// ---------- Normal-Privilege Shell Launcher ----------

/// Launch target for GUI desktop client applications.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LaunchTarget {
    /// Launch packaged MSIX app via `explorer.exe shell:AppsFolder\<app_user_model_id>`.
    AppsFolder { app_user_model_id: String },
    /// Launch standard desktop executable directly (must be an existing `.exe` file).
    Executable {
        path: PathBuf,
        args: Vec<String>,
        /// Case-insensitive environment overrides merged into the target user's env block.
        #[serde(default)]
        extra_env: BTreeMap<String, String>,
        /// Optional explicit working directory (defaults to the executable's parent directory).
        #[serde(default)]
        working_dir: Option<PathBuf>,
    },
}

impl Default for LaunchTarget {
    fn default() -> Self {
        Self::Executable {
            path: PathBuf::new(),
            args: Vec::new(),
            extra_env: BTreeMap::new(),
            working_dir: None,
        }
    }
}

impl LaunchTarget {
    /// Convenience constructor for an `Executable` target with empty `extra_env` and default `working_dir`.
    pub fn executable(path: PathBuf, args: Vec<String>) -> Self {
        Self::Executable {
            path,
            args,
            extra_env: BTreeMap::new(),
            working_dir: None,
        }
    }

    /// Convenience constructor for an `Executable` target carrying explicit `extra_env` and optional `working_dir`.
    pub fn executable_with_env(
        path: PathBuf,
        args: Vec<String>,
        extra_env: BTreeMap<String, String>,
        working_dir: Option<PathBuf>,
    ) -> Self {
        Self::Executable {
            path,
            args,
            extra_env,
            working_dir,
        }
    }

    /// Borrow `extra_env` overrides when this target is `LaunchTarget::Executable`.
    pub fn extra_env(&self) -> Option<&BTreeMap<String, String>> {
        match self {
            Self::Executable { extra_env, .. } => Some(extra_env),
            Self::AppsFolder { .. } => None,
        }
    }
}

/// Pure validator rejecting NUL bytes, empty keys, or `'='` inside `extra_env` variable names.
pub fn validate_extra_env(extra_env: &BTreeMap<String, String>) -> PlatformResult<()> {
    for (k, v) in extra_env {
        if k.trim().is_empty() || k.contains('\0') || k.contains('=') {
            return Err(PlatformError::InvalidInput(format!(
                "invalid environment variable name `{k}`"
            )));
        }
        if v.contains('\0') {
            return Err(PlatformError::InvalidInput(format!(
                "environment variable `{k}` value contains embedded NUL"
            )));
        }
    }
    Ok(())
}

/// Pure builder validating `LaunchTarget` and constructing `(program, args)`.
pub fn build_launch_command(target: &LaunchTarget) -> PlatformResult<(PathBuf, Vec<String>)> {
    match target {
        LaunchTarget::AppsFolder { app_user_model_id } => {
            let aumid = app_user_model_id.trim();
            if aumid.is_empty()
                || aumid.contains(['"', '&', '|', ';', '<', '>', '\r', '\n'])
                || !aumid.contains('!')
            {
                return Err(PlatformError::InvalidInput(format!(
                    "invalid AppUserModelId `{app_user_model_id}`"
                )));
            }
            let explorer = std::env::var("SystemRoot")
                .map(|r| PathBuf::from(r).join("explorer.exe"))
                .unwrap_or_else(|_| PathBuf::from(r"C:\Windows\explorer.exe"));
            Ok((explorer, vec![format!("shell:AppsFolder\\{aumid}")]))
        }
        LaunchTarget::Executable {
            path,
            args,
            extra_env,
            ..
        } => {
            validate_extra_env(extra_env)?;
            if !path.is_file() {
                return Err(PlatformError::InvalidInput(format!(
                    "executable not found: {}",
                    path.display()
                )));
            }
            Ok((path.clone(), args.clone()))
        }
    }
}

fn split_windows_env_entry(entry: &str) -> Option<(String, String)> {
    if entry.is_empty() {
        return None;
    }
    // Preserve Windows drive-current-directory pseudo-variables like `=C:=C:\Windows`.
    let eq_idx = if entry.starts_with('=') {
        entry.get(1..)?.find('=').map(|i| i + 1)?
    } else {
        entry.find('=')?
    };
    let key = entry.get(..eq_idx)?;
    let val = entry.get(eq_idx + 1..)?;
    if key.is_empty() {
        return None;
    }
    Some((key.to_string(), val.to_string()))
}

/// Parse a double-NUL-terminated Windows UTF-16 environment block into `(key, value)` pairs.
pub fn decode_windows_unicode_env_block(block: &[u16]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut start = 0usize;
    while start < block.len() {
        if block[start] == 0 {
            break;
        }
        let end = block[start..]
            .iter()
            .position(|&u| u == 0)
            .map(|rel| start + rel)
            .unwrap_or(block.len());
        let entry = String::from_utf16_lossy(&block[start..end]);
        if let Some(pair) = split_windows_env_entry(&entry) {
            out.push(pair);
        }
        if end >= block.len() {
            break;
        }
        start = end + 1;
    }
    out
}

/// Encode `(key, value)` pairs as a sorted, double-NUL-terminated UTF-16 Windows environment block.
pub fn encode_env_pairs_utf16(pairs: &[(String, String)]) -> PlatformResult<Vec<u16>> {
    let mut sorted: Vec<(&str, &str)> = Vec::with_capacity(pairs.len());
    for (k, v) in pairs {
        if k.is_empty() || k.contains('\0') || v.contains('\0') {
            return Err(PlatformError::InvalidInput(format!(
                "invalid environment entry `{k}`"
            )));
        }
        sorted.push((k.as_str(), v.as_str()));
    }
    sorted.sort_by_key(|(k, _)| k.to_ascii_uppercase());

    let mut block: Vec<u16> = Vec::new();
    for (k, v) in sorted {
        block.extend(k.encode_utf16());
        block.push(b'=' as u16);
        block.extend(v.encode_utf16());
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

/// Pure case-insensitive Windows UTF-16 environment block merger.
///
/// Parses `base_utf16` (double-NUL-terminated UTF-16 as returned by `CreateEnvironmentBlock`),
/// overrides matching keys or appends new keys from `extra_env` case-insensitively, sorts
/// entries in Windows case-insensitive key order, and returns a double-NUL-terminated `Vec<u16>`.
pub fn merge_windows_unicode_env_block(
    base_utf16: &[u16],
    extra_env: &BTreeMap<String, String>,
) -> PlatformResult<Vec<u16>> {
    validate_extra_env(extra_env)?;
    let mut merged = decode_windows_unicode_env_block(base_utf16);

    for (extra_k, extra_v) in extra_env {
        let mut replaced = false;
        for (k, v) in &mut merged {
            if k.eq_ignore_ascii_case(extra_k) {
                *k = extra_k.clone();
                *v = extra_v.clone();
                replaced = true;
                break;
            }
        }
        if !replaced {
            merged.push((extra_k.clone(), extra_v.clone()));
        }
    }

    encode_env_pairs_utf16(&merged)
}

fn push_quoted_win32_arg(out: &mut String, arg: &str, force_quotes: bool) {
    let needs_quotes =
        force_quotes || arg.is_empty() || arg.chars().any(|c| matches!(c, ' ' | '\t' | '"'));
    if !needs_quotes {
        out.push_str(arg);
        return;
    }
    out.push('"');
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        if ch == '\\' {
            backslashes += 1;
        } else if ch == '"' {
            for _ in 0..(backslashes * 2 + 1) {
                out.push('\\');
            }
            out.push('"');
            backslashes = 0;
        } else {
            for _ in 0..backslashes {
                out.push('\\');
            }
            backslashes = 0;
            out.push(ch);
        }
    }
    for _ in 0..(backslashes * 2) {
        out.push('\\');
    }
    out.push('"');
}

/// Pure `CommandLineToArgvW`-compliant Windows command line encoder (with raw `/d /s /k` & `/d /s /c`
/// support for `cmd.exe`, which uses non-`CommandLineToArgvW` outer-quote stripping).
pub(crate) fn format_windows_command_line(program: &Path, args: &[String]) -> String {
    let mut cmd = String::new();
    push_quoted_win32_arg(&mut cmd, &program.to_string_lossy(), true);
    let is_cmd_exe = program
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.eq_ignore_ascii_case("cmd.exe") || n.eq_ignore_ascii_case("cmd"));
    if is_cmd_exe
        && args.len() == 4
        && args[0].eq_ignore_ascii_case("/d")
        && args[1].eq_ignore_ascii_case("/s")
        && (args[2].eq_ignore_ascii_case("/k") || args[2].eq_ignore_ascii_case("/c"))
    {
        cmd.push(' ');
        cmd.push_str(&args[0]);
        cmd.push(' ');
        cmd.push_str(&args[1]);
        cmd.push(' ');
        cmd.push_str(&args[2]);
        cmd.push_str(" \"");
        cmd.push_str(&args[3]);
        cmd.push('"');
        return cmd;
    }
    for arg in args {
        cmd.push(' ');
        push_quoted_win32_arg(&mut cmd, arg, false);
    }
    cmd
}

#[cfg(windows)]
fn query_active_session_user_token() -> Option<windows::Win32::Foundation::HANDLE> {
    use core::ffi::c_void;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::RemoteDesktop::{
        WTSActive, WTSEnumerateSessionsW, WTSFreeMemory, WTSGetActiveConsoleSessionId,
        WTSQueryUserToken, WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW,
    };

    struct WtsMemGuard(*mut c_void);
    impl Drop for WtsMemGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    WTSFreeMemory(self.0);
                }
            }
        }
    }

    unsafe {
        let console_id = WTSGetActiveConsoleSessionId();
        if console_id != 0 && console_id != u32::MAX {
            let mut tok = HANDLE::default();
            if WTSQueryUserToken(console_id, &mut tok).is_ok() && !tok.is_invalid() {
                return Some(tok);
            }
        }

        let mut sessions_ptr: *mut WTS_SESSION_INFOW = core::ptr::null_mut();
        let mut count: u32 = 0;
        if WTSEnumerateSessionsW(
            WTS_CURRENT_SERVER_HANDLE,
            0,
            1,
            &mut sessions_ptr,
            &mut count,
        )
        .is_err()
            || sessions_ptr.is_null()
        {
            return None;
        }
        let _mem = WtsMemGuard(sessions_ptr.cast::<c_void>());
        let sessions = core::slice::from_raw_parts(sessions_ptr, count as usize);
        for info in sessions {
            if info.SessionId != 0 && info.State == WTSActive {
                let mut tok = HANDLE::default();
                if WTSQueryUserToken(info.SessionId, &mut tok).is_ok() && !tok.is_invalid() {
                    return Some(tok);
                }
            }
        }
    }
    None
}

#[cfg(windows)]
fn build_user_unicode_env_block_for_service() -> Option<Vec<u16>> {
    let home = user_home_dirs().into_iter().next()?;
    let mut env_map: Vec<(String, String)> = std::env::vars()
        .filter(|(k, _)| {
            !matches!(
                k.to_ascii_uppercase().as_str(),
                "USERPROFILE"
                    | "APPDATA"
                    | "LOCALAPPDATA"
                    | "TEMP"
                    | "TMP"
                    | "USERNAME"
                    | "HOMEDRIVE"
                    | "HOMEPATH"
            )
        })
        .collect();

    let home_s = home.to_string_lossy().into_owned();
    let user_name = home
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("User")
        .to_string();
    let (home_drive, home_path) = if let Some((drv, rest)) = home_s.split_once(':') {
        (
            format!("{drv}:"),
            if rest.is_empty() {
                "\\".to_string()
            } else {
                rest.to_string()
            },
        )
    } else {
        ("C:".to_string(), home_s.clone())
    };
    let roaming = home
        .join("AppData")
        .join("Roaming")
        .to_string_lossy()
        .into_owned();
    let local = home.join("AppData").join("Local");
    let temp = local.join("Temp").to_string_lossy().into_owned();
    let local_s = local.to_string_lossy().into_owned();

    // Merge per-user PATH entries from HKU\<SID>\Environment + standard user CLI bin roots.
    let user_env_pairs = read_user_env_pairs_for_home(&home);
    let mut extra_paths: Vec<String> = Vec::new();
    for (k, v) in &user_env_pairs {
        if k.eq_ignore_ascii_case("path") {
            for seg in v.split(';') {
                let clean = seg.trim().trim_matches('"').trim();
                if !clean.is_empty() {
                    let expanded = expand_user_tokens(clean, &home)
                        .to_string_lossy()
                        .into_owned();
                    if !extra_paths
                        .iter()
                        .any(|x| x.eq_ignore_ascii_case(&expanded))
                    {
                        extra_paths.push(expanded);
                    }
                }
            }
        }
    }
    for std_bin in [
        home.join(".local").join("bin"),
        home.join("AppData").join("Roaming").join("npm"),
        home.join("AppData").join("Local").join("pnpm"),
        home.join("AppData").join("Local").join("Volta").join("bin"),
        home.join(".cargo").join("bin"),
        home.join(".bun").join("bin"),
    ] {
        let s = std_bin.to_string_lossy().into_owned();
        if !extra_paths.iter().any(|x| x.eq_ignore_ascii_case(&s)) {
            extra_paths.push(s);
        }
    }
    if !extra_paths.is_empty() {
        let mut updated_path = false;
        for (k, v) in &mut env_map {
            if k.eq_ignore_ascii_case("PATH") {
                let suffix = extra_paths.join(";");
                if v.trim().is_empty() {
                    *v = suffix;
                } else {
                    *v = format!("{};{}", v.trim_end_matches(';'), suffix);
                }
                updated_path = true;
                break;
            }
        }
        if !updated_path {
            env_map.push(("Path".into(), extra_paths.join(";")));
        }
    }

    env_map.push(("USERNAME".into(), user_name));
    env_map.push(("HOMEDRIVE".into(), home_drive));
    env_map.push(("HOMEPATH".into(), home_path));
    env_map.push(("USERPROFILE".into(), home_s));
    env_map.push(("APPDATA".into(), roaming));
    env_map.push(("LOCALAPPDATA".into(), local_s));
    env_map.push(("TEMP".into(), temp.clone()));
    env_map.push(("TMP".into(), temp));
    encode_env_pairs_utf16(&env_map).ok()
}

#[cfg(windows)]
fn build_merged_user_env_block(
    user_token: windows::Win32::Foundation::HANDLE,
    extra_env: &BTreeMap<String, String>,
    session_zero_fallback: bool,
) -> PlatformResult<Option<Vec<u16>>> {
    use core::ffi::c_void;
    use windows::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};

    validate_extra_env(extra_env)?;

    struct EnvBlockGuard(*mut c_void);
    impl Drop for EnvBlockGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = DestroyEnvironmentBlock(self.0);
                }
            }
        }
    }

    let mut raw_env: *mut c_void = core::ptr::null_mut();
    let created = unsafe { CreateEnvironmentBlock(&mut raw_env, user_token, false) };
    if created.is_ok() && !raw_env.is_null() {
        let _guard = EnvBlockGuard(raw_env);
        // Bounded scan for double-NUL terminator (max 1 MiB UTF-16 units = 2 MiB)
        const MAX_UTF16_UNITS: usize = 512 * 1024;
        let ptr = raw_env.cast::<u16>();
        let mut len = 0usize;
        unsafe {
            while len + 1 < MAX_UTF16_UNITS {
                let cur = *ptr.add(len);
                let next = *ptr.add(len + 1);
                if cur == 0 && next == 0 {
                    len += 2;
                    break;
                }
                len += 1;
            }
        }
        let base_slice = unsafe { core::slice::from_raw_parts(ptr, len) };
        return Ok(Some(merge_windows_unicode_env_block(
            base_slice, extra_env,
        )?));
    }

    if session_zero_fallback {
        if let Some(base) = build_user_unicode_env_block_for_service() {
            return Ok(Some(merge_windows_unicode_env_block(&base, extra_env)?));
        }
    }

    if extra_env.is_empty() {
        return Ok(None);
    }

    let cur_pairs: Vec<(String, String)> = std::env::vars().collect();
    let base = encode_env_pairs_utf16(&cur_pairs)?;
    Ok(Some(merge_windows_unicode_env_block(&base, extra_env)?))
}

#[cfg(windows)]
fn enable_service_launch_privileges_best_effort() {
    use windows::core::w;
    use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID};
    use windows::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut proc_tok = HANDLE::default();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut proc_tok,
        )
        .is_err()
        {
            return;
        }
        for priv_name in [
            w!("SeAssignPrimaryTokenPrivilege"),
            w!("SeIncreaseQuotaPrivilege"),
        ] {
            let mut luid = LUID::default();
            if LookupPrivilegeValueW(None, priv_name, &mut luid).is_ok() {
                let tp = TOKEN_PRIVILEGES {
                    PrivilegeCount: 1,
                    Privileges: [LUID_AND_ATTRIBUTES {
                        Luid: luid,
                        Attributes: SE_PRIVILEGE_ENABLED,
                    }],
                };
                let _ = AdjustTokenPrivileges(proc_tok, false, Some(&tp), 0, None, None);
            }
        }
        let _ = CloseHandle(proc_tok);
    }
}

fn is_cli_or_script_launch_target(program: &Path) -> bool {
    let ext_l = program
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if matches!(ext_l.as_str(), "cmd" | "bat" | "ps1") {
        return true;
    }
    let path_l = strip_verbatim_win32_str(&program.to_string_lossy())
        .replace('/', "\\")
        .to_ascii_lowercase();
    let name_l = program
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if is_claude_cli_path_l(&path_l) {
        return true;
    }
    if name_l == "codex.exe" {
        let in_gui = path_l.contains(r"\windowsapps\")
            || path_l.contains(r"\programs\codex\")
            || path_l.contains(r"\programs\chatgpt\")
            || path_l.contains(r"\programs\chatgpt classic\");
        return !in_gui;
    }
    false
}

fn escape_ps_single_arg(raw: &str) -> String {
    format!("'{}'", raw.replace('\'', "''"))
}

fn wrap_cli_in_interactive_shell(program: &Path, args: &[String]) -> (PathBuf, Vec<String>) {
    let sys_root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    let pf = std::env::var_os("ProgramFiles")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"));

    let pwsh_candidates = [
        pf.join("PowerShell").join("7").join("pwsh.exe"),
        sys_root
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe"),
    ];
    if let Some(ps_exe) = pwsh_candidates.into_iter().find(|p| p.is_file()) {
        let mut ps_cmd = format!("& {}", escape_ps_single_arg(&program.to_string_lossy()));
        for a in args {
            ps_cmd.push(' ');
            ps_cmd.push_str(&escape_ps_single_arg(a));
        }
        return (
            ps_exe,
            vec![
                "-NoLogo".to_string(),
                "-NoExit".to_string(),
                "-ExecutionPolicy".to_string(),
                "Bypass".to_string(),
                "-Command".to_string(),
                ps_cmd,
            ],
        );
    }

    let cmd_exe = sys_root.join("System32").join("cmd.exe");
    let inner = format_windows_command_line(program, args);
    (
        cmd_exe,
        vec!["/d".to_string(), "/s".to_string(), "/k".to_string(), inner],
    )
}

fn is_windowsapps_container_path(path: &Path) -> bool {
    let path_l = path
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase();
    path_l.contains(r"\program files\windowsapps\") || path_l.contains(r"\windowsapps\")
}

fn build_cmd_start_appexeclink_invocation(alias: &Path, args: &[String]) -> (PathBuf, Vec<String>) {
    let sys_root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    let cmd_exe = sys_root.join("System32").join("cmd.exe");
    let mut inner = String::from("start \"\" ");
    inner.push_str(&format_windows_command_line(alias, args));
    (
        cmd_exe,
        vec!["/d".to_string(), "/s".to_string(), "/c".to_string(), inner],
    )
}

fn resolve_msix_execution_alias_if_needed(program: &Path) -> Option<PathBuf> {
    let path_l = program
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase();
    if !path_l.contains(r"\windowsapps\") {
        return None;
    }
    let exe_name = program.file_name()?;
    for home in user_home_dirs() {
        let alias = home
            .join("AppData")
            .join("Local")
            .join("Microsoft")
            .join("WindowsApps")
            .join(exe_name);
        if std::fs::symlink_metadata(&alias).is_ok() {
            return Some(alias);
        }
    }
    None
}

#[cfg(windows)]
fn launch_from_session_zero(
    program: &Path,
    args: &[String],
    cwd: Option<&Path>,
    extra_env: &BTreeMap<String, String>,
    new_console: bool,
) -> PlatformResult<()> {
    use core::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        DuplicateTokenEx, SecurityImpersonation, TokenPrimary, TOKEN_ADJUST_DEFAULT,
        TOKEN_ADJUST_SESSIONID, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{
        CreateProcessAsUserW, CREATE_NEW_CONSOLE, CREATE_UNICODE_ENVIRONMENT,
        PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOW,
    };

    struct WinHandleGuard(HANDLE);
    impl Drop for WinHandleGuard {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    enable_service_launch_privileges_best_effort();

    let raw_user_tok = query_active_session_user_token().ok_or_else(|| {
        PlatformError::Io("未检测到活动的交互式桌面会话，无法从服务会话启动客户端".into())
    })?;
    let _user_tok_guard = WinHandleGuard(raw_user_tok);

    let mut primary_tok = HANDLE::default();
    unsafe {
        DuplicateTokenEx(
            raw_user_tok,
            TOKEN_ASSIGN_PRIMARY
                | TOKEN_DUPLICATE
                | TOKEN_QUERY
                | TOKEN_ADJUST_DEFAULT
                | TOKEN_ADJUST_SESSIONID,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &mut primary_tok,
        )
    }
    .map_err(|e| PlatformError::Io(format!("DuplicateTokenEx(Session0) failed: {e}")))?;
    let _primary_guard = WinHandleGuard(primary_tok);

    let prog_w: Vec<u16> = program.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut cmd_w: Vec<u16> = format_windows_command_line(program, args)
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let cwd_w: Option<Vec<u16>> = cwd.map(|d| d.as_os_str().encode_wide().chain(Some(0)).collect());
    let cwd_pcwstr = cwd_w
        .as_ref()
        .map_or(PCWSTR::null(), |v| PCWSTR(v.as_ptr()));
    let mut desktop_w: Vec<u16> = "winsta0\\default".encode_utf16().chain(Some(0)).collect();
    let env_block = build_merged_user_env_block(primary_tok, extra_env, true)?;
    let mut flags = if env_block.is_some() {
        CREATE_UNICODE_ENVIRONMENT
    } else {
        PROCESS_CREATION_FLAGS(0)
    };
    if new_console {
        flags |= CREATE_NEW_CONSOLE;
    }

    let si = STARTUPINFOW {
        cb: core::mem::size_of::<STARTUPINFOW>() as u32,
        lpDesktop: PWSTR(desktop_w.as_mut_ptr()),
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();

    let direct_res = unsafe {
        CreateProcessAsUserW(
            primary_tok,
            PCWSTR(prog_w.as_ptr()),
            PWSTR(cmd_w.as_mut_ptr()),
            None,
            None,
            false,
            flags,
            env_block.as_ref().map(|b| b.as_ptr().cast::<c_void>()),
            cwd_pcwstr,
            &si,
            &mut pi,
        )
    };
    match direct_res {
        Ok(()) => {
            let _proc_guard = WinHandleGuard(pi.hProcess);
            let _thread_guard = WinHandleGuard(pi.hThread);
            Ok(())
        }
        Err(first_err) if !new_console && is_windowsapps_container_path(program) => {
            // `CreateProcessAsUserW` cannot directly open `IO_REPARSE_TAG_APPEXECLINK` (`1920`);
            // invoke `cmd.exe /d /s /c "start "" ..."` under the SAME non-elevated `primary_tok`
            // with `CREATE_NO_WINDOW` so `ShellExecuteExW` activates MSIX identity cleanly.
            const CREATE_NO_WINDOW_FLAG: u32 = 0x0800_0000;
            let alias = resolve_msix_execution_alias_if_needed(program)
                .unwrap_or_else(|| program.to_path_buf());
            let (shim_prog, shim_args) = build_cmd_start_appexeclink_invocation(&alias, args);
            let shim_prog_w: Vec<u16> =
                shim_prog.as_os_str().encode_wide().chain(Some(0)).collect();
            let mut shim_cmd_w: Vec<u16> = format_windows_command_line(&shim_prog, &shim_args)
                .encode_utf16()
                .chain(Some(0))
                .collect();
            let shim_flags = flags | PROCESS_CREATION_FLAGS(CREATE_NO_WINDOW_FLAG);
            let mut shim_pi = PROCESS_INFORMATION::default();
            unsafe {
                CreateProcessAsUserW(
                    primary_tok,
                    PCWSTR(shim_prog_w.as_ptr()),
                    PWSTR(shim_cmd_w.as_mut_ptr()),
                    None,
                    None,
                    false,
                    shim_flags,
                    env_block.as_ref().map(|b| b.as_ptr().cast::<c_void>()),
                    cwd_pcwstr,
                    &si,
                    &mut shim_pi,
                )
            }
            .map_err(|_| {
                PlatformError::Io(format!(
                    "CreateProcessAsUserW failed for {}: {first_err}",
                    program.display()
                ))
            })?;
            let _proc_guard = WinHandleGuard(shim_pi.hProcess);
            let _thread_guard = WinHandleGuard(shim_pi.hThread);
            Ok(())
        }
        Err(e) => Err(PlatformError::Io(format!(
            "CreateProcessAsUserW failed for {}: {e}",
            program.display()
        ))),
    }
}

#[cfg(windows)]
fn try_launch_via_shell_token(
    program: &Path,
    args: &[String],
    cwd: Option<&Path>,
    extra_env: &BTreeMap<String, String>,
    new_console: bool,
) -> PlatformResult<()> {
    use core::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        DuplicateTokenEx, SecurityImpersonation, TokenPrimary, TOKEN_ADJUST_DEFAULT,
        TOKEN_ADJUST_SESSIONID, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{
        CreateProcessWithTokenW, OpenProcess, OpenProcessToken, CREATE_NEW_CONSOLE,
        CREATE_UNICODE_ENVIRONMENT, LOGON_WITH_PROFILE, PROCESS_CREATION_FLAGS,
        PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, STARTUPINFOW,
    };
    use windows::Win32::UI::WindowsAndMessaging::{GetShellWindow, GetWindowThreadProcessId};

    struct WinHandleGuard(HANDLE);
    impl Drop for WinHandleGuard {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    unsafe {
        let shell_hwnd = GetShellWindow();
        if shell_hwnd.0.is_null() {
            return Err(PlatformError::Io("desktop shell window unavailable".into()));
        }
        let mut shell_pid: u32 = 0;
        GetWindowThreadProcessId(shell_hwnd, Some(&mut shell_pid));
        if shell_pid == 0 || shell_pid == std::process::id() {
            return Err(PlatformError::Io("invalid desktop shell PID".into()));
        }

        let shell_proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, shell_pid)
            .map_err(|e| PlatformError::Io(format!("OpenProcess(shell) failed: {e}")))?;
        let _proc_guard = WinHandleGuard(shell_proc);

        let mut shell_tok = HANDLE::default();
        OpenProcessToken(shell_proc, TOKEN_DUPLICATE, &mut shell_tok)
            .map_err(|e| PlatformError::Io(format!("OpenProcessToken(shell) failed: {e}")))?;
        let _tok_guard = WinHandleGuard(shell_tok);

        let mut primary_tok = HANDLE::default();
        DuplicateTokenEx(
            shell_tok,
            TOKEN_ASSIGN_PRIMARY
                | TOKEN_DUPLICATE
                | TOKEN_QUERY
                | TOKEN_ADJUST_DEFAULT
                | TOKEN_ADJUST_SESSIONID,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &mut primary_tok,
        )
        .map_err(|e| PlatformError::Io(format!("DuplicateTokenEx(shell) failed: {e}")))?;
        let _primary_guard = WinHandleGuard(primary_tok);

        let prog_w: Vec<u16> = program.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut cmd_w: Vec<u16> = format_windows_command_line(program, args)
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let cwd_w: Option<Vec<u16>> =
            cwd.map(|d| d.as_os_str().encode_wide().chain(Some(0)).collect());
        let cwd_pcwstr = cwd_w
            .as_ref()
            .map_or(PCWSTR::null(), |v| PCWSTR(v.as_ptr()));
        let env_block = if extra_env.is_empty() {
            None
        } else {
            build_merged_user_env_block(primary_tok, extra_env, false)?
        };
        let mut flags = if env_block.is_some() {
            CREATE_UNICODE_ENVIRONMENT
        } else {
            PROCESS_CREATION_FLAGS(0)
        };
        if new_console {
            flags |= CREATE_NEW_CONSOLE;
        }
        let si = STARTUPINFOW {
            cb: core::mem::size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };
        let mut pi = PROCESS_INFORMATION::default();

        let direct_res = CreateProcessWithTokenW(
            primary_tok,
            LOGON_WITH_PROFILE,
            PCWSTR(prog_w.as_ptr()),
            PWSTR(cmd_w.as_mut_ptr()),
            flags,
            env_block.as_ref().map(|b| b.as_ptr().cast::<c_void>()),
            cwd_pcwstr,
            &si,
            &mut pi,
        );
        match direct_res {
            Ok(()) => {
                let _child_proc = WinHandleGuard(pi.hProcess);
                let _child_thread = WinHandleGuard(pi.hThread);
                Ok(())
            }
            Err(first_err) if !new_console && is_windowsapps_container_path(program) => {
                const CREATE_NO_WINDOW_FLAG: u32 = 0x0800_0000;
                let alias = resolve_msix_execution_alias_if_needed(program)
                    .unwrap_or_else(|| program.to_path_buf());
                let (shim_prog, shim_args) = build_cmd_start_appexeclink_invocation(&alias, args);
                let shim_prog_w: Vec<u16> =
                    shim_prog.as_os_str().encode_wide().chain(Some(0)).collect();
                let mut shim_cmd_w: Vec<u16> = format_windows_command_line(&shim_prog, &shim_args)
                    .encode_utf16()
                    .chain(Some(0))
                    .collect();
                let mut shim_pi = PROCESS_INFORMATION::default();
                CreateProcessWithTokenW(
                    primary_tok,
                    LOGON_WITH_PROFILE,
                    PCWSTR(shim_prog_w.as_ptr()),
                    PWSTR(shim_cmd_w.as_mut_ptr()),
                    flags | PROCESS_CREATION_FLAGS(CREATE_NO_WINDOW_FLAG),
                    env_block.as_ref().map(|b| b.as_ptr().cast::<c_void>()),
                    cwd_pcwstr,
                    &si,
                    &mut shim_pi,
                )
                .map_err(|_| {
                    PlatformError::Io(format!("CreateProcessWithTokenW failed: {first_err}"))
                })?;
                let _child_proc = WinHandleGuard(shim_pi.hProcess);
                let _child_thread = WinHandleGuard(shim_pi.hThread);
                Ok(())
            }
            Err(e) => Err(PlatformError::Io(format!(
                "CreateProcessWithTokenW failed: {e}"
            ))),
        }
    }
}

/// Launch a desktop or CLI app under the normal-privilege interactive user token:
/// - Wraps CLI tools / `.cmd` / `.bat` / `.ps1` shims in an interactive PowerShell / `cmd.exe`
///   window with `CREATE_NEW_CONSOLE`.
/// - Resolves MSIX `WindowsApps` binaries to user `AppExecutionAlias` on `AccessDenied` when needed.
/// - In Session 0 (`LocalSystem` service): `WTSQueryUserToken` -> `DuplicateTokenEx(SecurityImpersonation)`
///   -> `CreateEnvironmentBlock` + `merge_windows_unicode_env_block` -> `CreateProcessAsUserW` (`winsta0\default`).
/// - When elevated in an interactive session: `GetShellWindow` (`explorer.exe`) -> `CreateProcessWithTokenW(LOGON_WITH_PROFILE)`.
/// - When already unelevated: `std::process::Command::spawn` with `extra_env`.
#[cfg(windows)]
pub fn launch_normal_privilege(target: &LaunchTarget) -> PlatformResult<()> {
    use std::os::windows::process::CommandExt;
    const CREATE_NEW_CONSOLE_FLAG: u32 = 0x0000_0010;

    let (raw_program, raw_args) = build_launch_command(target)?;
    let empty_env = BTreeMap::new();
    let extra_env = target.extra_env().unwrap_or(&empty_env);
    let fallback_user_home = user_home_dirs().into_iter().find(|d| d.is_dir());
    let cwd_owned: Option<PathBuf> = match target {
        LaunchTarget::Executable {
            path, working_dir, ..
        } => working_dir
            .as_deref()
            .filter(|d| d.is_dir() && !is_windowsapps_container_path(d))
            .map(Path::to_path_buf)
            .or_else(|| {
                path.parent()
                    .filter(|p| p.is_dir() && !is_windowsapps_container_path(p))
                    .map(Path::to_path_buf)
            })
            .or(fallback_user_home),
        LaunchTarget::AppsFolder { .. } => None,
    };
    let cwd = cwd_owned.as_deref();

    let is_cli = matches!(target, LaunchTarget::Executable { .. })
        && is_cli_or_script_launch_target(&raw_program);

    // Resolve restricted `C:\Program Files\WindowsApps\...` MSIX paths to the user's
    // `%LOCALAPPDATA%\Microsoft\WindowsApps\<exe>` execution alias upfront so normal-user launches
    // preserve MSIX Package Identity and never hit `ERROR_ACCESS_DENIED`.
    let effective_gui_program = if !is_cli && is_windowsapps_container_path(&raw_program) {
        resolve_msix_execution_alias_if_needed(&raw_program).unwrap_or_else(|| raw_program.clone())
    } else {
        raw_program.clone()
    };

    let (program, args) = if is_cli {
        wrap_cli_in_interactive_shell(&raw_program, &raw_args)
    } else {
        (effective_gui_program, raw_args.clone())
    };

    let run_once = |prog: &Path, prog_args: &[String]| -> PlatformResult<()> {
        if crate::access_win::is_session_zero() {
            return launch_from_session_zero(prog, prog_args, cwd, extra_env, is_cli);
        }
        // SECURITY INVARIANT: NEVER fall back to spawning an AI client under an elevated
        // Administrator token — doing so breaks the privilege boundary and stamps Admin ACLs
        // onto Sovereign Vault `--user-data-dir` files!
        if crate::access_win::is_elevated().unwrap_or(false) {
            return try_launch_via_shell_token(prog, prog_args, cwd, extra_env, is_cli).map_err(
                |e| {
                    PlatformError::AccessDenied(format!(
                        "无法降权至普通桌面用户身份启动客户端（已阻止管理员直启以保护隔离目录权限）：{e}"
                    ))
                },
            );
        }
        let mut cmd = std::process::Command::new(prog);
        cmd.args(prog_args);
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        if let Some(dir) = cwd {
            cmd.current_dir(dir);
        }
        if is_cli {
            cmd.creation_flags(CREATE_NEW_CONSOLE_FLAG);
        }
        cmd.spawn()
            .map_err(|e| PlatformError::Io(format!("failed to launch {}: {e}", prog.display())))?;
        Ok(())
    };

    match run_once(&program, &args) {
        Ok(()) => Ok(()),
        Err(first_err) => {
            if !is_cli {
                if let Some(alias) = resolve_msix_execution_alias_if_needed(&raw_program) {
                    if alias != program && run_once(&alias, &raw_args).is_ok() {
                        return Ok(());
                    }
                }
            }
            Err(first_err)
        }
    }
}

#[cfg(not(windows))]
pub fn launch_normal_privilege(_target: &LaunchTarget) -> PlatformResult<()> {
    Err(PlatformError::unsupported(
        "launch_app",
        "Windows shell launcher is only supported on Windows",
    ))
}

/// Alias for `launch_normal_privilege` preserving v5 Vault launcher naming.
pub fn spawn_normal_user(target: &LaunchTarget) -> PlatformResult<()> {
    launch_normal_privilege(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_temp_dir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "cg-proc-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn version_key_sorts_numerically_newest_first() {
        let mut pkgs = vec![
            ("Claude_2.9.0.0_x64__hash".into(), PathBuf::from(r"C:\v9")),
            (
                "Claude_2.10.1.0_x64__hash".into(),
                PathBuf::from(r"C:\v10b"),
            ),
            ("Claude_2.10.0.0_x64__hash".into(), PathBuf::from(r"C:\v10")),
        ];
        let dirs = covered_dirs_from(&pkgs, Some(PathBuf::from(r"C:\fallback")));
        assert_eq!(
            dirs,
            vec![
                PathBuf::from(r"C:\v10b"),
                PathBuf::from(r"C:\v10"),
                PathBuf::from(r"C:\v9"),
            ]
        );
        // Empty registry falls back cleanly.
        assert_eq!(
            covered_dirs_from(&[], Some(PathBuf::from(r"C:\fallback"))),
            vec![PathBuf::from(r"C:\fallback")]
        );
        sort_packages_newest_first(&mut pkgs);
        assert!(pkgs[0].0.contains("2.10.1.0"));
    }

    #[test]
    fn gui_vs_cli_fingerprints_are_mutually_safe() {
        let wa_claude =
            r"c:\program files\windowsapps\claude_2.16120.0.0_x64__pzs8sxrjxfjjc\claude.exe";
        assert!(gui_agent_matches("claude", "claude.exe", wa_claude, None));
        assert!(!cli_agent_matches(
            "claude-code",
            "claude.exe",
            wa_claude,
            ""
        ));

        // Claude Code CLI native binary (even though exe name is claude.exe!) must NEVER match GUI.
        let cli_paths = [
            r"c:\users\u\.local\bin\claude.exe",
            r"c:\users\u\appdata\roaming\claude\claude-code\2.1.304\abc\claude.exe",
        ];
        for path in cli_paths {
            assert!(!gui_agent_matches("claude", "claude.exe", path, None));
            assert!(cli_agent_matches("claude-code", "claude.exe", path, ""));
        }
        // npm claude-code
        assert!(cli_agent_matches(
            "claude-code",
            "node.exe",
            r"c:\program files\nodejs\node.exe",
            r"node c:\npm\node_modules\@anthropic-ai\claude-code\cli.js"
        ));

        // ChatGPT/Codex UWP package vs bundled runner & standalone codex CLI
        let wa_gpt = r"c:\program files\windowsapps\openai.codex_26.928.2636.0_x64__2p2nqsd0c76g0\app\chatgpt.exe";
        assert!(gui_agent_matches("chatgpt", "chatgpt.exe", wa_gpt, None));
        let runner = r"c:\program files\windowsapps\openai.codex_26.928.2636.0_x64__2p2nqsd0c76g0\app\resources\codex-command-runner.exe";
        assert!(gui_agent_matches(
            "chatgpt",
            "codex-command-runner.exe",
            runner,
            None
        ));
        assert!(!cli_agent_matches(
            "codex",
            "codex-command-runner.exe",
            runner,
            ""
        ));
        assert!(cli_agent_matches(
            "codex",
            "codex.exe",
            r"c:\users\u\.cargo\bin\codex.exe",
            ""
        ));
        assert!(cli_agent_matches(
            "codex",
            "codex-voice-host.exe",
            r"c:\users\u\appdata\roaming\npm\node_modules\@openai\codex\node_modules\@openai\codex-win32-x64\vendor\x86_64-pc-windows-msvc\codex-resources\voice\bin\codex-voice-host.exe",
            ""
        ));

        // Antigravity main + language_server & uninstaller exclusion
        assert!(gui_agent_matches(
            "antigravity",
            "antigravity.exe",
            r"c:\users\u\appdata\local\programs\antigravity\antigravity.exe",
            None
        ));
        assert!(gui_agent_matches(
            "antigravity",
            "language_server.exe",
            r"c:\users\u\appdata\local\programs\antigravity\resources\bin\language_server.exe",
            None
        ));
        assert!(gui_agent_matches(
            "antigravity",
            "antigravity ide.exe",
            r"c:\users\u\appdata\local\programs\antigravity ide\antigravity ide.exe",
            None
        ));
        assert!(!gui_agent_matches(
            "antigravity",
            "uninstall antigravity.exe",
            r"c:\users\u\appdata\local\programs\antigravity\uninstall antigravity.exe",
            None
        ));
    }

    #[test]
    fn antigravity_covered_dirs_localsystem_multiuser_and_dedup() {
        let root = unique_temp_dir("ag-roots");
        let sys_profile = root.join("systemprofile");
        let sys_local = sys_profile.join("AppData").join("Local");
        let users = root.join("Users");

        // Built-in Windows pseudo-profiles must be skipped even if subfolders exist.
        for skipped in ["Public", "Default", "Default User", "All Users"] {
            std::fs::create_dir_all(
                users
                    .join(skipped)
                    .join("AppData")
                    .join("Local")
                    .join("Programs")
                    .join("antigravity"),
            )
            .unwrap();
        }

        let alice_ag = users
            .join("Alice")
            .join("AppData")
            .join("Local")
            .join("Programs")
            .join("antigravity");
        let bob_ide = users
            .join("Bob")
            .join("AppData")
            .join("Local")
            .join("Programs")
            .join("Antigravity IDE");
        std::fs::create_dir_all(&alice_ag).unwrap();
        std::fs::create_dir_all(&bob_ide).unwrap();

        // 1. LocalSystem service context: LOCALAPPDATA & USERPROFILE point to systemprofile.
        let found_service =
            antigravity_covered_dirs_from_roots(Some(&sys_local), Some(&sys_profile), Some(&users));
        assert_eq!(found_service, vec![alice_ag.clone(), bob_ide.clone()]);

        // 2. Interactive Alice context with mixed-case duplicate path -> deduplicated!
        let alice_local_upper = PathBuf::from(
            users
                .join("Alice")
                .join("AppData")
                .join("Local")
                .to_string_lossy()
                .to_ascii_uppercase(),
        );
        let found_dedup = antigravity_covered_dirs_from_roots(
            Some(&alice_local_upper),
            Some(&users.join("Alice")),
            Some(&users),
        );
        assert_eq!(found_dedup.len(), 2);

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn antigravity_discovery_depth_5_finds_language_server_and_excludes_uninstallers() {
        let base = unique_temp_dir("ag-disc");
        let ag = base.join("Programs").join("antigravity");
        let ag_bin = ag.join("resources").join("bin");
        let ag_deep = ag.join("resources").join("app").join("mcp").join("bin");
        let ide = base.join("Programs").join("Antigravity IDE");

        std::fs::create_dir_all(&ag_bin).unwrap();
        std::fs::create_dir_all(&ag_deep).unwrap();
        std::fs::create_dir_all(&ide).unwrap();

        std::fs::write(ag.join("Antigravity.exe"), b"exe").unwrap();
        std::fs::write(ag.join("Uninstall Antigravity.exe"), b"unins").unwrap();
        std::fs::write(ag.join("resources").join("elevate.exe"), b"exe").unwrap();
        std::fs::write(ag_bin.join("language_server.exe"), b"exe").unwrap();
        std::fs::write(ag_bin.join("webm_encoder.exe"), b"exe").unwrap();
        std::fs::write(ag_deep.join("agy.exe"), b"exe").unwrap();
        std::fs::write(ide.join("Antigravity IDE.exe"), b"exe").unwrap();
        std::fs::write(ide.join("unins000.exe"), b"unins").unwrap();

        let exes = discover_antigravity_exes_in(Some(&base));
        assert_eq!(exes.len(), 6);
        // Primary GUI executables MUST come first so Safe Launch picks the GUI launcher.
        assert!(exes[0].ends_with("Antigravity.exe"));
        assert!(exes[1].ends_with("Antigravity IDE.exe"));
        assert!(exes.iter().any(|p| p.ends_with("language_server.exe")));
        assert!(exes.iter().any(|p| p.ends_with("webm_encoder.exe")));
        assert!(exes.iter().any(|p| p.ends_with("elevate.exe")));
        assert!(exes.iter().any(|p| p.ends_with("agy.exe")));
        assert!(!exes
            .iter()
            .any(|p| p.to_string_lossy().to_ascii_lowercase().contains("unins")));

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn snapshot_tree_closure_and_guarded_pids_monitor_ls_and_mcp_not_pwsh() {
        let ag_dir = r"c:\users\u\appdata\local\programs\antigravity";
        let mk = |pid: u32, ppid: u32, name: &str, path: &str, cmd: &str| ProcInfo {
            pid,
            ppid,
            name_l: name.to_string(),
            path_l: path.to_string(),
            cmd_l: cmd.to_string(),
            start_time: 1000 + pid as u64,
        };

        let all = vec![
            mk(10, 1, "explorer.exe", r"c:\windows\explorer.exe", ""),
            mk(
                100,
                10,
                "antigravity.exe",
                &format!(r"{ag_dir}\antigravity.exe"),
                &format!(r#""{ag_dir}\antigravity.exe""#),
            ),
            mk(
                200,
                100,
                "language_server.exe",
                &format!(r"{ag_dir}\resources\bin\language_server.exe"),
                "--standalone",
            ),
            mk(
                201,
                200,
                "cmd.exe",
                r"c:\windows\system32\cmd.exe",
                "/c agy-node.cmd",
            ),
            mk(
                202,
                201,
                "antigravity.exe",
                &format!(r"{ag_dir}\antigravity.exe"),
                "--import=file:///c:/users/u/.gemini/antigravity/sidecar_sdk/register.js",
            ),
            mk(203, 200, "uv.exe", r"c:\tools\uv.exe", "uv run mcp"),
            mk(
                204,
                203,
                "python.exe",
                r"c:\python\python.exe",
                "mcp_server.py",
            ),
            // Integrated interactive PowerShell terminal + user dev server inside it -> excluded from leak attribution!
            mk(
                300,
                100,
                "pwsh.exe",
                r"c:\program files\powershell\7\pwsh.exe",
                "pwsh",
            ),
            mk(
                301,
                300,
                "node.exe",
                r"c:\nodejs\node.exe",
                "node user-vite-dev.js",
            ),
            // Unrelated system process -> pruned from CachedProcessSnapshot.procs!
            mk(
                999,
                10,
                "svchost.exe",
                r"c:\windows\system32\svchost.exe",
                "",
            ),
        ];

        let snap = build_process_snapshot_from_table(all, &[], &[], &[ag_dir.to_string()], 5000);
        assert!(!snap.procs.iter().any(|p| p.pid == 999));
        assert!(snap.procs.iter().any(|p| p.pid == 200));
        assert!(snap.procs.iter().any(|p| p.pid == 201));
        assert!(!snap.orphan_counts.contains_key("antigravity"));
        assert_eq!(snap.gui_counts.get("antigravity"), Some(&3));

        let pids = snap.guarded_agent_pids(&["antigravity".to_string()], None);
        for expected_pid in [100u32, 200, 202] {
            assert_eq!(
                pids.get(&expected_pid).map(String::as_str),
                Some("反重力"),
                "pid {expected_pid} must map to 反重力"
            );
        }
        assert_eq!(pids.get(&203).map(String::as_str), Some("反重力 (uv.exe)"));
        assert_eq!(
            pids.get(&204).map(String::as_str),
            Some("反重力 (python.exe)")
        );
        assert!(crate::netwatch_win::is_mcp_agent_label(
            pids.get(&204).unwrap()
        ));
        assert!(!pids.contains_key(&300), "pwsh.exe must not be attributed");
        assert!(
            !pids.contains_key(&301),
            "user process inside pwsh.exe must not be attributed"
        );
    }

    #[test]
    fn kill_tree_orders_children_before_parents_and_spares_user_terminals() {
        let ag_dir = r"c:\users\u\appdata\local\programs\antigravity";
        let mk = |pid: u32, ppid: u32, name: &str, path: &str, cmd: &str| ProcInfo {
            pid,
            ppid,
            name_l: name.to_string(),
            path_l: path.to_string(),
            cmd_l: cmd.to_string(),
            start_time: 2000 + pid as u64,
        };

        // Intentionally put parents BEFORE children in input slice to prove post-order topological sort.
        let procs = vec![
            mk(
                100,
                10,
                "antigravity.exe",
                &format!(r"{ag_dir}\antigravity.exe"),
                "",
            ),
            mk(
                110,
                100,
                "antigravity.exe",
                &format!(r"{ag_dir}\antigravity.exe"),
                "--type=renderer",
            ),
            mk(
                120,
                100,
                "language_server.exe",
                &format!(r"{ag_dir}\resources\bin\language_server.exe"),
                "",
            ),
            mk(
                130,
                120,
                "cmd.exe",
                r"c:\windows\system32\cmd.exe",
                "/c agy-node",
            ),
            mk(
                140,
                130,
                "antigravity.exe",
                &format!(r"{ag_dir}\antigravity.exe"),
                "electron_run_as_node",
            ),
            mk(150, 120, "node.exe", r"c:\nodejs\node.exe", "mcp.js"),
            mk(
                160,
                100,
                "webm_encoder.exe",
                &format!(r"{ag_dir}\resources\bin\webm_encoder.exe"),
                "",
            ),
            // User shells / terminals that MUST NOT be killed!
            mk(
                170,
                100,
                "pwsh.exe",
                r"c:\program files\powershell\7\pwsh.exe",
                "",
            ),
            mk(171, 170, "node.exe", r"c:\nodejs\node.exe", "user.js"),
            mk(
                180,
                100,
                "powershell.exe",
                r"c:\windows\system32\windowspowershell\v1.0\powershell.exe",
                "",
            ),
            mk(190, 100, "wt.exe", r"c:\windowsapps\wt.exe", ""),
        ];

        let tree = pick_gui_agent_kill_tree("antigravity", &procs, None, &[ag_dir.to_string()]);
        let pids: Vec<u32> = tree.iter().map(|i| i.pid).collect();

        for must_have in [100u32, 110, 120, 130, 140, 150, 160] {
            assert!(pids.contains(&must_have), "missing pid {must_have}");
        }
        for must_spare in [170u32, 171, 180, 190] {
            assert!(!pids.contains(&must_spare), "collateral pid {must_spare}");
        }

        let pos = |pid: u32| pids.iter().position(|&x| x == pid).unwrap();
        // Every child must appear strictly BEFORE its parent!
        assert!(pos(140) < pos(130));
        assert!(pos(130) < pos(120));
        assert!(pos(150) < pos(120));
        assert!(pos(120) < pos(100));
        assert!(pos(110) < pos(100));
        assert!(pos(160) < pos(100));
    }

    #[test]
    fn antigravity_orphans_detects_full_exit_and_mid_run_detached_crash_orphans() {
        let ag_dir = r"c:\custom\antigravity";
        let mk = |pid: u32, ppid: u32, name: &str, path: &str, cmd: &str| ProcInfo {
            pid,
            ppid,
            name_l: name.to_string(),
            path_l: path.to_string(),
            cmd_l: cmd.to_string(),
            start_time: 3000 + pid as u64,
        };

        // 1. Healthy running tree (including cmd.exe -> Antigravity.exe sidecar) -> ZERO orphans.
        let healthy = vec![
            mk(10, 1, "explorer.exe", r"c:\windows\explorer.exe", ""),
            mk(
                100,
                10,
                "antigravity.exe",
                &format!(r"{ag_dir}\antigravity.exe"),
                "",
            ),
            mk(
                110,
                100,
                "language_server.exe",
                &format!(r"{ag_dir}\resources\bin\language_server.exe"),
                "",
            ),
            mk(
                111,
                110,
                "cmd.exe",
                r"c:\windows\system32\cmd.exe",
                "/c agy-node.cmd",
            ),
            mk(
                112,
                111,
                "antigravity.exe",
                &format!(r"{ag_dir}\antigravity.exe"),
                "--import=file:///sidecar_sdk/main.mjs",
            ),
        ];
        assert!(pick_antigravity_orphans(&healthy, &[ag_dir.to_string()]).is_empty());

        // 2. Case A: Root Antigravity.exe (100) exited, leaving language_server (110), sidecar (112),
        //    child node (113), detached MCP node (114), plus an unrelated live-terminal node (501).
        let after_exit = vec![
            mk(
                500,
                1,
                "pwsh.exe",
                r"c:\program files\powershell\7\pwsh.exe",
                "",
            ),
            mk(501, 500, "node.exe", r"c:\nodejs\node.exe", "node dev.js"),
            mk(
                110,
                100,
                "language_server.exe",
                &format!(r"{ag_dir}\resources\bin\language_server.exe"),
                "",
            ),
            mk(
                111,
                110,
                "cmd.exe",
                r"c:\windows\system32\cmd.exe",
                "/c agy-node.cmd",
            ),
            mk(
                112,
                111,
                "antigravity.exe",
                &format!(r"{ag_dir}\antigravity.exe"),
                "electron_run_as_node",
            ),
            mk(113, 110, "node.exe", r"c:\nodejs\node.exe", "mcp.js"),
            mk(
                114,
                9999,
                "node.exe",
                r"c:\nodejs\node.exe",
                r"node c:\users\u\.antigravity\extensions\agy-mcp\index.js",
            ),
            // User dev server in `.gemini\antigravity\scratch` & unrelated MCP & unreadable-cmd node MUST be spared!
            mk(
                601,
                9999,
                "node.exe",
                r"c:\nodejs\node.exe",
                r"node c:\users\u\.gemini\antigravity\scratch\my-app\vite.js",
            ),
            mk(
                602,
                9999,
                "node.exe",
                r"c:\nodejs\node.exe",
                r"node c:\users\u\.vscode\mcp\server.js",
            ),
            mk(603, 9999, "node.exe", r"c:\nodejs\node.exe", ""),
        ];
        let orphans_a: Vec<u32> = pick_antigravity_orphans(&after_exit, &[ag_dir.to_string()])
            .into_iter()
            .map(|i| after_exit[i].pid)
            .collect();
        assert_eq!(orphans_a.len(), 5);
        assert!(!orphans_a.contains(&501));
        assert!(!orphans_a.contains(&601));
        assert!(!orphans_a.contains(&602));
        assert!(!orphans_a.contains(&603));
        let pos_a = |pid: u32| orphans_a.iter().position(|&x| x == pid).unwrap();
        assert!(pos_a(112) < pos_a(111));
        assert!(pos_a(111) < pos_a(110));
        assert!(pos_a(113) < pos_a(110));

        // 3. Case B: Live Antigravity session (100 -> 110) running AND detached crash-orphan
        //    language_server.exe (900, dead ppid 899) + its child node.exe (901).
        let mid_run = vec![
            mk(
                100,
                10,
                "antigravity.exe",
                &format!(r"{ag_dir}\antigravity.exe"),
                "",
            ),
            mk(
                110,
                100,
                "language_server.exe",
                &format!(r"{ag_dir}\resources\bin\language_server.exe"),
                "",
            ),
            mk(
                900,
                899,
                "language_server.exe",
                &format!(r"{ag_dir}\resources\bin\language_server.exe"),
                "",
            ),
            mk(901, 900, "node.exe", r"c:\nodejs\node.exe", "mcp-orphan.js"),
        ];
        let orphans_b: Vec<u32> = pick_antigravity_orphans(&mid_run, &[ag_dir.to_string()])
            .into_iter()
            .map(|i| mid_run[i].pid)
            .collect();
        assert_eq!(orphans_b, vec![901, 900]);
    }

    #[test]
    fn pid_reuse_recheck_blocks_collateral_termination() {
        let c_same = ProcessIdentity {
            pid: 101,
            start_time: 1000,
            exe_path: r"c:\apps\claude.exe".into(),
        };
        let c_reused_time = ProcessIdentity {
            pid: 102,
            start_time: 1000,
            exe_path: r"c:\apps\claude.exe".into(),
        };
        let c_reused_path = ProcessIdentity {
            pid: 103,
            start_time: 1000,
            exe_path: r"c:\apps\claude.exe".into(),
        };
        let c_vanished = ProcessIdentity {
            pid: 104,
            start_time: 1000,
            exe_path: r"c:\apps\claude.exe".into(),
        };

        let mut killed_pids = Vec::new();
        let outcome = terminate_with_recheck(
            &[c_same, c_reused_time, c_reused_path, c_vanished],
            |pid| match pid {
                101 => Some(ProcessIdentity {
                    pid: 101,
                    start_time: 1000,
                    exe_path: r"C:\Apps\Claude.exe".into(), // case difference allowed
                }),
                102 => Some(ProcessIdentity {
                    pid: 102,
                    start_time: 2000, // PID reused!
                    exe_path: r"C:\Apps\Claude.exe".into(),
                }),
                103 => Some(ProcessIdentity {
                    pid: 103,
                    start_time: 1000,
                    exe_path: r"C:\Windows\System32\notepad.exe".into(), // path changed!
                }),
                _ => None,
            },
            |pid| {
                killed_pids.push(pid);
                true
            },
        );

        assert_eq!(killed_pids, vec![101]);
        assert_eq!(outcome.killed.len(), 1);
        assert_eq!(outcome.skipped_reused.len(), 2);
        assert_eq!(outcome.vanished, vec![104]);
    }

    #[test]
    fn residual_sweep_never_kills_cli_under_live_terminal() {
        let mk = |pid: u32, ppid: u32, name: &str, path: &str| ProcInfo {
            pid,
            ppid,
            name_l: name.to_string(),
            path_l: path.to_string(),
            cmd_l: String::new(),
            start_time: pid as u64 + 100,
        };
        let wa_dir = r"c:\program files\windowsapps\claude_2.42304.0.0_x64__pzs8sxrjxfjjc";
        let cli_native = r"c:\users\u\appdata\roaming\claude\claude-code\2.1.304\abc\claude.exe";

        let procs_with_desktop = vec![
            mk(100, 50, "claude.exe", &format!(r"{wa_dir}\claude.exe")),
            mk(102, 50, "claude.exe", cli_native),
            mk(50, 1, "windowsterminal.exe", r"c:\...\windowsterminal.exe"),
        ];
        assert!(pick_residual(&procs_with_desktop, Some(wa_dir)).is_none());

        let procs_desktop_gone = vec![
            mk(102, 50, "claude.exe", cli_native), // live terminal parent -> keep!
            mk(104, 9999, "claude.exe", cli_native), // dead parent -> orphan -> sweep!
            mk(50, 1, "windowsterminal.exe", r"c:\...\windowsterminal.exe"),
        ];
        let residual = pick_residual(&procs_desktop_gone, Some(wa_dir)).unwrap();
        assert_eq!(residual.len(), 1);
        assert_eq!(procs_desktop_gone[residual[0].0].pid, 104);
    }

    #[test]
    fn cached_scanner_serves_ui_without_rescan() {
        let scanner = ProcessScanner::new(Duration::from_secs(60));
        let mut counts = HashMap::new();
        counts.insert("claude".to_string(), 2);
        scanner.seed_for_test(CachedProcessSnapshot {
            scanned_at_unix: 12345,
            gui_counts: counts,
            cli_counts: HashMap::new(),
            orphan_counts: HashMap::new(),
            claude_dirs_l: Vec::new(),
            chatgpt_dirs_l: Vec::new(),
            antigravity_dirs_l: Vec::new(),
            procs: vec![ProcInfo {
                pid: 42,
                ppid: 1,
                name_l: "claude.exe".into(),
                path_l: r"c:\program files\windowsapps\claude_1.0\claude.exe".into(),
                cmd_l: String::new(),
                start_time: 777,
            }],
        });

        let snap = scanner.snapshot_if_stale();
        assert_eq!(snap.scanned_at_unix, 12345);
        assert_eq!(snap.gui_counts.get("claude"), Some(&2));
        let pids = snap.guarded_agent_pids(&["claude".into()], None);
        assert_eq!(pids.get(&42).map(String::as_str), Some("Claude"));
    }

    #[test]
    fn launch_command_validates_appsfolder_and_executable() {
        let (prog, args) = build_launch_command(&LaunchTarget::AppsFolder {
            app_user_model_id: "Claude_pzs8sxrjxfjjc!Claude".into(),
        })
        .unwrap();
        assert!(prog
            .to_string_lossy()
            .to_ascii_lowercase()
            .ends_with("explorer.exe"));
        assert_eq!(args, vec![r"shell:AppsFolder\Claude_pzs8sxrjxfjjc!Claude"]);

        // Reject shell injection / malformed AUMID
        assert!(build_launch_command(&LaunchTarget::AppsFolder {
            app_user_model_id: "bad&calc.exe".into(),
        })
        .is_err());
        assert!(build_launch_command(&LaunchTarget::executable(
            PathBuf::from(r"Z:\definitely\missing\app.exe"),
            vec![],
        ))
        .is_err());
    }

    #[test]
    fn msix_package_helpers_extract_versions_filter_sids_and_dedup() {
        assert_eq!(
            msix_version_from_package_name("Claude_5.1231.2.0_x64__pzs8sxrjxfjjc").as_deref(),
            Some("5.1231.2.0")
        );
        assert_eq!(
            msix_version_from_package_name("OpenAI.Codex_26.1111.2228.0_x64__2p2nqsd0c76g0")
                .as_deref(),
            Some("26.1111.2228.0")
        );
        assert!(msix_version_from_package_name("InvalidPackageName").is_none());

        assert!(is_valid_user_sid_subkey("S-1-5-21-1001"));
        assert!(!is_valid_user_sid_subkey(".DEFAULT"));
        assert!(!is_valid_user_sid_subkey(".default"));
        assert!(!is_valid_user_sid_subkey("S-1-5-21-1001_Classes"));
        assert!(!is_valid_user_sid_subkey(""));

        let deduped = dedup_and_sort_packages(vec![
            (
                "Claude_5.1000.0.0_x64__hash".into(),
                PathBuf::from(r"C:\Program Files\WindowsApps\Claude_old"),
            ),
            (
                "Claude_5.1231.2.0_x64__hash".into(),
                PathBuf::from(r"C:\Program Files\WindowsApps\Claude_new"),
            ),
            (
                "Claude_5.1231.1.0_x64__hash".into(),
                PathBuf::from(r"c:\program files\windowsapps\claude_new\"),
            ),
        ]);
        assert_eq!(deduped.len(), 2);
        assert_eq!(deduped[0].0, "Claude_5.1231.2.0_x64__hash");
    }

    #[test]
    fn deep_claude_codex_and_standalone_cli_discovery_covers_depth_12_and_filters_noise() {
        let root = unique_temp_dir("deep-disc");
        let claude_pkg = root.join("Claude_5.1231.2.0_x64__pzs8sxrjxfjjc");
        let codex_pkg = root.join("OpenAI.Codex_26.1111.2228.0_x64__2p2nqsd0c76g0");
        let user_home = root.join("Users").join("Alice");

        // Claude MSIX layout (up to depth 5/6)
        let claude_app = claude_pkg.join("app");
        let claude_mcp = claude_app
            .join("resources")
            .join("app.asar.unpacked")
            .join("resources")
            .join("github-mcp");
        std::fs::create_dir_all(&claude_mcp).unwrap();
        std::fs::write(claude_app.join("claude.exe"), b"exe").unwrap();
        std::fs::write(claude_app.join("resources").join("cowork-svc.exe"), b"exe").unwrap();
        std::fs::write(claude_mcp.join("github-mcp-server.exe"), b"exe").unwrap();
        std::fs::write(claude_app.join("unins000.exe"), b"unins").unwrap();

        // OpenAI.Codex MSIX layout (up to depth 11)
        let codex_app = codex_pkg.join("app");
        let codex_res = codex_app.join("resources");
        let codex_cua_node = codex_res.join("cua_node").join("bin");
        let codex_swift = codex_cua_node
            .join("node_modules")
            .join("@oai")
            .join("sky")
            .join("bin")
            .join("windows")
            .join("swift")
            .join("x64");
        std::fs::create_dir_all(&codex_swift).unwrap();
        std::fs::write(codex_app.join("ChatGPT.exe"), b"exe").unwrap();
        std::fs::write(codex_app.join("Codex.exe"), b"exe").unwrap();
        std::fs::write(codex_app.join("elevation_service.exe"), b"exe").unwrap();
        std::fs::write(codex_res.join("codex.exe"), b"exe").unwrap();
        std::fs::write(codex_res.join("codex-windows-sandbox-service.exe"), b"exe").unwrap();
        std::fs::write(codex_cua_node.join("node.exe"), b"exe").unwrap();
        std::fs::write(codex_swift.join("codex-computer-use-swift.exe"), b"exe").unwrap();

        // Standalone native CLIs under user home
        let local_bin = user_home.join(".local").join("bin");
        let cargo_bin = user_home.join(".cargo").join("bin");
        let cc_roaming = user_home
            .join("AppData")
            .join("Roaming")
            .join("Claude")
            .join("claude-code")
            .join("2.1.308")
            .join("abc");
        let cc_npm = user_home
            .join("AppData")
            .join("Roaming")
            .join("npm")
            .join("node_modules")
            .join("@anthropic-ai")
            .join("claude-code")
            .join("node_modules")
            .join("@anthropic-ai")
            .join("claude-code-win32-x64");
        let codex_npm_base = user_home
            .join("AppData")
            .join("Roaming")
            .join("npm")
            .join("node_modules")
            .join("@openai")
            .join("codex")
            .join("node_modules")
            .join("@openai")
            .join("codex-win32-x64")
            .join("vendor")
            .join("x86_64-pc-windows-msvc");
        let codex_npm_voice = codex_npm_base
            .join("codex-resources")
            .join("voice")
            .join("bin");
        let codex_npm_rg = codex_npm_base.join("codex-path");

        std::fs::create_dir_all(&local_bin).unwrap();
        std::fs::create_dir_all(&cargo_bin).unwrap();
        std::fs::create_dir_all(&cc_roaming).unwrap();
        std::fs::create_dir_all(&cc_npm).unwrap();
        std::fs::create_dir_all(&codex_npm_voice).unwrap();
        std::fs::create_dir_all(&codex_npm_rg).unwrap();

        std::fs::write(local_bin.join("claude.exe"), b"exe").unwrap();
        std::fs::write(local_bin.join("tvly.exe"), b"noise").unwrap();
        std::fs::write(cargo_bin.join("codex.exe"), b"exe").unwrap();
        std::fs::write(cargo_bin.join("cargo.exe"), b"noise").unwrap();
        std::fs::write(cc_roaming.join("claude.exe"), b"exe").unwrap();
        std::fs::write(cc_npm.join("claude.exe"), b"exe").unwrap();
        std::fs::write(codex_npm_voice.join("codex-voice-host.exe"), b"exe").unwrap();
        std::fs::write(codex_npm_rg.join("rg.exe"), b"noise").unwrap();

        let claude_exes = discover_claude_exes_from_dirs_and_homes(
            &[claude_pkg],
            std::slice::from_ref(&user_home),
        );
        assert!(claude_exes[0].ends_with(r"app\claude.exe"));
        assert!(claude_exes.iter().any(|p| p.ends_with("cowork-svc.exe")));
        assert!(claude_exes
            .iter()
            .any(|p| p.ends_with("github-mcp-server.exe")));
        assert!(claude_exes
            .iter()
            .any(|p| p.to_string_lossy().contains("claude-code")));
        assert!(!claude_exes
            .iter()
            .any(|p| p.to_string_lossy().contains("unins")));

        let chatgpt_exes = discover_chatgpt_exes_from_dirs_and_homes(
            &[codex_pkg],
            std::slice::from_ref(&user_home),
        );
        assert!(chatgpt_exes[0].ends_with(r"app\ChatGPT.exe"));
        assert!(chatgpt_exes[1].ends_with(r"app\Codex.exe"));
        assert!(chatgpt_exes
            .iter()
            .any(|p| p.ends_with("codex-computer-use-swift.exe")));
        assert!(chatgpt_exes
            .iter()
            .any(|p| p.to_string_lossy().contains(r"cua_node\bin\node.exe")));
        assert!(chatgpt_exes
            .iter()
            .any(|p| p.ends_with("codex-voice-host.exe")));
        assert!(!chatgpt_exes.iter().any(|p| p.ends_with("rg.exe")));
        assert!(!chatgpt_exes.iter().any(|p| p.ends_with("cargo.exe")));

        let cli_cc = discover_cli_exes_in_homes("claude-code", std::slice::from_ref(&user_home));
        assert_eq!(cli_cc.len(), 3);
        let cli_codex = discover_cli_exes_in_homes("codex", &[user_home]);
        assert_eq!(cli_codex.len(), 2);
        assert!(cli_codex
            .iter()
            .any(|p| p.ends_with("codex-voice-host.exe")));

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn scm_services_are_monitored_excluded_from_counts_and_traversed_on_kill() {
        let claude_dir = r"c:\program files\windowsapps\claude_5.1231.2.0_x64__pzs8sxrjxfjjc";
        let codex_dir =
            r"c:\program files\windowsapps\openai.codex_26.1111.2228.0_x64__2p2nqsd0c76g0";
        let mk = |pid: u32, ppid: u32, name: &str, path: &str, cmd: &str| ProcInfo {
            pid,
            ppid,
            name_l: name.to_string(),
            path_l: path.to_string(),
            cmd_l: cmd.to_string(),
            start_time: 4000 + pid as u64,
        };

        // 1. Only idle Windows SCM services running (user has NOT opened Claude or Codex).
        let idle_scm = vec![
            mk(
                10,
                1,
                "services.exe",
                r"c:\windows\system32\services.exe",
                "",
            ),
            mk(
                50,
                10,
                "cowork-svc.exe",
                &format!(r"{claude_dir}\app\resources\cowork-svc.exe"),
                "",
            ),
            mk(
                60,
                10,
                "codex-windows-sandbox-service.exe",
                &format!(r"{codex_dir}\app\resources\codex-windows-sandbox-service.exe"),
                "",
            ),
            mk(
                61,
                10,
                "elevation_service.exe",
                &format!(r"{codex_dir}\app\elevation_service.exe"),
                "",
            ),
        ];

        let snap_idle = build_process_snapshot_from_table(
            idle_scm.clone(),
            &[claude_dir.to_string()],
            &[codex_dir.to_string()],
            &[],
            100,
        );
        // running_count and orphan_counts MUST be 0 when only SCM services exist!
        assert_eq!(snap_idle.gui_counts.get("claude").copied(), None);
        assert_eq!(snap_idle.gui_counts.get("chatgpt").copied(), None);
        assert!(snap_idle.orphan_counts.is_empty());
        assert!(pick_claude_orphans(&idle_scm, &[claude_dir.to_string()]).is_empty());
        assert!(pick_chatgpt_codex_orphans(&idle_scm, &[codex_dir.to_string()]).is_empty());
        assert!(classify_claude(&idle_scm[1], Some(claude_dir)).is_none());

        // Yet SCM services ARE retained in procs and monitored in guarded_agent_pids!
        let pids_idle = snap_idle.guarded_agent_pids(&["claude".into(), "chatgpt".into()], None);
        assert_eq!(
            pids_idle.get(&50).map(String::as_str),
            Some("Claude (cowork-svc.exe)")
        );
        assert_eq!(pids_idle.get(&60).map(String::as_str), Some("ChatGPT"));
        assert_eq!(pids_idle.get(&61).map(String::as_str), Some("ChatGPT"));

        // 2. When SCM service spawns a worker child, kill tree MUST spare SCM host (60)
        //    while catching & killing its worker child (65) and nested helper (66)!
        let mut with_worker = idle_scm;
        with_worker.push(mk(
            65,
            60,
            "codex-command-runner.exe",
            &format!(r"{codex_dir}\app\resources\codex-command-runner.exe"),
            "",
        ));
        with_worker.push(mk(
            66,
            65,
            "node.exe",
            &format!(r"{codex_dir}\app\resources\cua_node\bin\node.exe"),
            "cua.js",
        ));

        let tree = pick_gui_agent_kill_tree_with_dirs(
            "chatgpt",
            &with_worker,
            &[],
            &[codex_dir.to_string()],
            &[],
        );
        let kill_pids: Vec<u32> = tree.iter().map(|i| i.pid).collect();
        assert!(
            !kill_pids.contains(&60),
            "SCM service host must not be killed"
        );
        assert!(
            !kill_pids.contains(&61),
            "SCM service host must not be killed"
        );
        assert_eq!(kill_pids, vec![66, 65]);
    }

    #[test]
    fn complete_orphan_detection_cli_kill_tree_and_socket_tree_monitoring() {
        let claude_dir = r"c:\program files\windowsapps\claude_5.1231.2.0_x64__pzs8sxrjxfjjc";
        let codex_dir =
            r"c:\program files\windowsapps\openai.codex_26.1111.2228.0_x64__2p2nqsd0c76g0";
        let mk = |pid: u32, ppid: u32, name: &str, path: &str, cmd: &str| ProcInfo {
            pid,
            ppid,
            name_l: name.to_string(),
            path_l: path.to_string(),
            cmd_l: cmd.to_string(),
            start_time: 5000 + pid as u64,
        };

        // Scenario:
        // - Claude Desktop exited, leaving github-mcp-server.exe (110, dead ppid 100) -> node.exe (111)
        // - Codex Desktop running: Codex.exe (200) -> resources\codex.exe (201) -> cua_node\node.exe (202)
        //   PLUS a detached crash-orphan codex-command-runner.exe (250, dead ppid 249) -> winpty-agent.exe (251)
        // - Live Claude Code CLI under live terminal wt.exe (300 -> 301 -> mcp node 302) -> NOT orphan!
        // - Orphaned Codex CLI whose terminal exited (400, dead ppid 399) -> codex-command-runner.exe (401) -> orphan!
        let procs = vec![
            mk(10, 1, "explorer.exe", r"c:\windows\explorer.exe", ""),
            mk(300, 10, "wt.exe", r"c:\windowsapps\wt.exe", ""),
            mk(
                110,
                100,
                "github-mcp-server.exe",
                &format!(
                    r"{claude_dir}\app\resources\app.asar.unpacked\resources\github-mcp\github-mcp-server.exe"
                ),
                "",
            ),
            mk(111, 110, "node.exe", r"c:\nodejs\node.exe", "mcp-child.js"),
            mk(
                200,
                10,
                "codex.exe",
                &format!(r"{codex_dir}\app\codex.exe"),
                "",
            ),
            mk(
                201,
                200,
                "codex.exe",
                &format!(r"{codex_dir}\app\resources\codex.exe"),
                "app-server",
            ),
            mk(
                202,
                201,
                "node.exe",
                &format!(r"{codex_dir}\app\resources\cua_node\bin\node.exe"),
                "cua-bridge.js",
            ),
            mk(
                250,
                249,
                "codex-command-runner.exe",
                &format!(r"{codex_dir}\app\resources\codex-command-runner.exe"),
                "",
            ),
            mk(
                251,
                250,
                "winpty-agent.exe",
                &format!(
                    r"{codex_dir}\app\resources\app.asar.unpacked\node_modules\node-pty\build\release\winpty-agent.exe"
                ),
                "",
            ),
            mk(
                301,
                300,
                "claude.exe",
                r"c:\users\u\.local\bin\claude.exe",
                "",
            ),
            mk(302, 301, "node.exe", r"c:\nodejs\node.exe", "cli-mcp.js"),
            mk(
                400,
                399,
                "codex.exe",
                r"c:\users\u\.cargo\bin\codex.exe",
                "",
            ),
            mk(
                401,
                400,
                "codex-command-runner.exe",
                r"c:\users\u\appdata\roaming\npm\node_modules\@openai\codex\node_modules\@openai\codex-win32-x64\vendor\x86_64-pc-windows-msvc\codex-resources\codex-command-runner.exe",
                "",
            ),
        ];

        let snap = build_process_snapshot_from_table(
            procs.clone(),
            &[claude_dir.to_string()],
            &[codex_dir.to_string()],
            &[],
            999,
        );

        // Counts: Codex Desktop live (200, 201, 202 = 3), Claude Desktop 0, Claude Code CLI live (1), Codex CLI 0 (400 is orphan)
        assert_eq!(snap.gui_counts.get("chatgpt"), Some(&3));
        assert_eq!(snap.gui_counts.get("claude").copied(), None);
        assert_eq!(snap.cli_counts.get("claude-code"), Some(&1));
        assert_eq!(snap.cli_counts.get("codex").copied(), None);

        // Orphan counts: claude (111, 110 = 2), chatgpt (251, 250 = 2), codex CLI (401, 400 = 2), claude-code = 0
        assert_eq!(snap.orphan_counts.get("claude"), Some(&2));
        assert_eq!(snap.orphan_counts.get("chatgpt"), Some(&2));
        assert_eq!(snap.orphan_counts.get("codex"), Some(&2));
        assert_eq!(snap.orphan_counts.get("claude-code").copied(), None);

        // Full descendant socket monitoring across GUI + CLI trees
        let pids = snap.guarded_agent_pids(&["claude".into(), "chatgpt".into()], None);
        assert_eq!(
            pids.get(&110).map(String::as_str),
            Some("Claude (github-mcp-server.exe)")
        );
        assert_eq!(
            pids.get(&111).map(String::as_str),
            Some("Claude (node.exe)")
        );
        assert_eq!(pids.get(&200).map(String::as_str), Some("ChatGPT"));
        assert_eq!(pids.get(&201).map(String::as_str), Some("ChatGPT"));
        assert_eq!(
            pids.get(&202).map(String::as_str),
            Some("ChatGPT (node.exe)")
        );
        assert_eq!(pids.get(&301).map(String::as_str), Some("Claude Code"));
        assert_eq!(
            pids.get(&302).map(String::as_str),
            Some("Claude Code (node.exe)")
        );
        assert_eq!(pids.get(&400).map(String::as_str), Some("Codex CLI"));
        assert_eq!(
            pids.get(&401).map(String::as_str),
            Some("Codex CLI (codex-command-runner.exe)")
        );
        assert!(
            !pids.contains_key(&300),
            "wt.exe terminal must never be monitored"
        );

        // CLI kill tree must kill children before parents and NEVER include wt.exe (300)!
        let cc_tree: Vec<u32> = pick_cli_agent_kill_tree("claude-code", &procs)
            .into_iter()
            .map(|i| i.pid)
            .collect();
        assert_eq!(cc_tree, vec![302, 301]);
        assert!(!cc_tree.contains(&300));

        // Unified orphan aggregator includes all orphaned categories in children-first order
        let all_orphans = pick_all_orphan_targets(
            &procs,
            &[claude_dir.to_string()],
            &[codex_dir.to_string()],
            &[],
        );
        let orphan_pids: Vec<u32> = all_orphans.iter().map(|(i, _)| procs[*i].pid).collect();
        assert_eq!(orphan_pids, vec![111, 110, 251, 250, 401, 400]);

        // Case A check: if Codex.exe (200) itself exits leaving resources\codex.exe (201) + cua_node (202),
        // resources\codex.exe is NOT treated as a live root GUI -> all remaining helpers are swept!
        let codex_after_exit = vec![
            mk(
                201,
                200,
                "codex.exe",
                &format!(r"{codex_dir}\app\resources\codex.exe"),
                "app-server",
            ),
            mk(
                202,
                201,
                "node.exe",
                &format!(r"{codex_dir}\app\resources\cua_node\bin\node.exe"),
                "cua-bridge.js",
            ),
        ];
        let after_exit_pids: Vec<u32> =
            pick_chatgpt_codex_orphans(&codex_after_exit, &[codex_dir.to_string()])
                .into_iter()
                .map(|i| codex_after_exit[i].pid)
                .collect();
        assert_eq!(after_exit_pids, vec![202, 201]);
    }

    #[test]
    fn client_local_version_detectors_read_cli_packages_and_antigravity_manifest() {
        let root = unique_temp_dir("client-ver");
        let home = root.join("UserA");

        // Claude Code versioned directory + npm package (versioned dir is newer: 2.1.308 > 2.1.284)
        let cc_dir = home
            .join("AppData")
            .join("Roaming")
            .join("Claude")
            .join("claude-code")
            .join("2.1.308");
        std::fs::create_dir_all(&cc_dir).unwrap();
        std::fs::write(cc_dir.join("claude.exe"), b"stub").unwrap();
        let npm_cc = home
            .join("AppData")
            .join("Roaming")
            .join("npm")
            .join("node_modules")
            .join("@anthropic-ai")
            .join("claude-code");
        std::fs::create_dir_all(&npm_cc).unwrap();
        std::fs::write(
            npm_cc.join("package.json"),
            r#"{"name":"@anthropic-ai/claude-code","version":"2.1.284"}"#,
        )
        .unwrap();
        assert_eq!(
            installed_claude_code_version_in_homes(std::slice::from_ref(&home)).as_deref(),
            Some("2.1.308")
        );

        // Codex CLI npm package
        let npm_codex = home
            .join("AppData")
            .join("Roaming")
            .join("npm")
            .join("node_modules")
            .join("@openai")
            .join("codex");
        std::fs::create_dir_all(&npm_codex).unwrap();
        std::fs::write(
            npm_codex.join("package.json"),
            r#"{"name":"@openai/codex","version":"0.158.0"}"#,
        )
        .unwrap();
        assert_eq!(
            installed_codex_cli_version_in_homes(std::slice::from_ref(&home)).as_deref(),
            Some("0.158.0")
        );

        // Antigravity app-update.yml + package.json fallback
        let ag_dir = root.join("antigravity");
        std::fs::create_dir_all(ag_dir.join("resources").join("app")).unwrap();
        std::fs::write(
            ag_dir.join("resources").join("app").join("package.json"),
            r#"{"name":"antigravity","version":"2.33.0"}"#,
        )
        .unwrap();
        std::fs::write(
            ag_dir.join("resources").join("app-update.yml"),
            "provider: generic\nurl: https://example.invalid/manifest/\n",
        )
        .unwrap();
        let (ag_ver, ag_url) = installed_antigravity_ide_info_in_dirs(&[ag_dir]);
        assert_eq!(ag_ver.as_deref(), Some("2.33.0"));
        assert_eq!(ag_url.as_deref(), Some("https://example.invalid/manifest"));
        let _ = std::fs::remove_dir_all(&root);

        // Real Windows system PE version check on kernel32.dll
        #[cfg(windows)]
        {
            let k32 = Path::new(r"C:\Windows\System32\kernel32.dll");
            if k32.is_file() {
                assert!(read_pe_file_version(k32).is_some());
            }
        }
    }

    fn build_synthetic_asar(header_json: &str) -> Vec<u8> {
        let json_bytes = header_json.as_bytes();
        let json_len = json_bytes.len() as u32;
        let padded_len = (json_len + 3) & !3;
        let mut out = Vec::with_capacity(16 + padded_len as usize);
        out.extend_from_slice(&4u32.to_le_bytes());
        out.extend_from_slice(&(padded_len + 8).to_le_bytes());
        out.extend_from_slice(&(padded_len + 4).to_le_bytes());
        out.extend_from_slice(&json_len.to_le_bytes());
        out.extend_from_slice(json_bytes);
        out.resize(16 + padded_len as usize, 0);
        out
    }

    #[test]
    fn chatgpt_classic_live_root_never_swept_as_orphan_and_discovered_primary() {
        let gpt_msix =
            r"c:\program files\windowsapps\openai.chatgpt-desktop_1.2026.70.0_x64__2p2nqsd0c76g0";
        let mk = |pid: u32, ppid: u32, name: &str, path: &str, cmd: &str| ProcInfo {
            pid,
            ppid,
            name_l: name.to_string(),
            path_l: path.to_string(),
            cmd_l: cmd.to_string(),
            start_time: 7000 + pid as u64,
        };

        let procs = vec![
            mk(10, 1, "explorer.exe", r"c:\windows\explorer.exe", ""),
            mk(
                500,
                10,
                "chatgpt classic.exe",
                &format!(r"{gpt_msix}\app\chatgpt classic.exe"),
                &format!(r#""{gpt_msix}\app\chatgpt classic.exe""#),
            ),
            mk(
                501,
                500,
                "chatgpt classic.exe",
                &format!(r"{gpt_msix}\app\chatgpt classic.exe"),
                "--type=renderer",
            ),
            mk(
                502,
                500,
                "chatgpt classic.exe",
                &format!(r"{gpt_msix}\app\chatgpt classic.exe"),
                "--type=gpu-process",
            ),
        ];

        assert!(gui_agent_matches(
            "chatgpt",
            "chatgpt classic.exe",
            &procs[1].path_l,
            None
        ));
        // Live `ChatGPT Classic.exe` window + children MUST have ZERO orphans!
        assert!(pick_chatgpt_codex_orphans(&procs, &[gpt_msix.to_string()]).is_empty());
        let snap =
            build_process_snapshot_from_table(procs, &[], &[gpt_msix.to_string()], &[], 1234);
        assert_eq!(snap.gui_counts.get("chatgpt"), Some(&3));
        assert!(!snap.orphan_counts.contains_key("chatgpt"));

        // Primary executable discovery includes `app\ChatGPT Classic.exe`
        let root = unique_temp_dir("gpt-classic");
        let pkg = root.join("OpenAI.ChatGPT-Desktop_1.2026.70.0_x64__2p2nqsd0c76g0");
        std::fs::create_dir_all(pkg.join("app")).unwrap();
        std::fs::write(pkg.join("app").join("ChatGPT Classic.exe"), b"exe").unwrap();
        let exes = discover_chatgpt_exes_from_dirs_and_homes(&[pkg], &[]);
        assert!(exes[0].ends_with(r"app\ChatGPT Classic.exe"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn asar_cn_patch_verification_rejects_stale_bak_and_uses_live_asar_mtime() {
        let root = unique_temp_dir("asar-cn");

        // 1. Stale `app.asar.bak` + unpatched `app.asar` (after IDE update) -> MUST return `None`!
        let wiped_dir = root.join("ag-wiped");
        std::fs::create_dir_all(wiped_dir.join("resources")).unwrap();
        let unpatched_asar =
            build_synthetic_asar(r#"{"files":{"main.js":{"size":10,"offset":"0"}}}"#);
        std::fs::write(
            wiped_dir.join("resources").join("app.asar"),
            &unpatched_asar,
        )
        .unwrap();
        std::fs::write(
            wiped_dir.join("resources").join("app.asar.bak"),
            b"old-backup",
        )
        .unwrap();
        std::fs::write(
            wiped_dir
                .join("resources")
                .join("antigravity-desktop-cn.version"),
            "1.5.0",
        )
        .unwrap();
        assert!(!asar_contains_cn_patch(
            &wiped_dir.join("resources").join("app.asar")
        ));
        assert!(
            installed_antigravity_cn_version_in_dirs(std::slice::from_ref(&wiped_dir)).is_none()
        );

        // 2. Patched `app.asar` containing `subframeLocalizationPreload.js` -> verified active!
        let patched_dir = root.join("ag-patched");
        std::fs::create_dir_all(patched_dir.join("resources")).unwrap();
        let patched_asar = build_synthetic_asar(
            r#"{"files":{"subframeLocalizationPreload.js":{"size":42,"offset":"0"}}}"#,
        );
        let live_asar_path = patched_dir.join("resources").join("app.asar");
        let bak_asar_path = patched_dir.join("resources").join("app.asar.bak");
        std::fs::write(&live_asar_path, &patched_asar).unwrap();
        std::fs::write(&bak_asar_path, &unpatched_asar).unwrap();

        // Set `app.asar.bak` mtime to 2024-01-15 and live `app.asar` mtime to 2026-03-20
        let bak_time = UNIX_EPOCH + Duration::from_secs(1_705_320_000); // 2024.01.15
        let live_time = UNIX_EPOCH + Duration::from_secs(1_773_990_000); // 2026.03.20
        if let Ok(f_bak) = std::fs::File::options().write(true).open(&bak_asar_path) {
            let _ = f_bak.set_times(std::fs::FileTimes::new().set_modified(bak_time));
        }
        if let Ok(f_live) = std::fs::File::options().write(true).open(&live_asar_path) {
            let _ = f_live.set_times(std::fs::FileTimes::new().set_modified(live_time));
        }

        assert!(asar_contains_cn_patch(&live_asar_path));
        assert_eq!(
            installed_antigravity_cn_version_in_dirs(&[wiped_dir, patched_dir]).as_deref(),
            Some("2026.03.20")
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn multi_manager_cli_cargo_crates2_squirrel_and_plugin_manifests_discovered() {
        let root = unique_temp_dir("multi-mgr");
        let home = root.join("DevUser");

        // 1. `.npmrc` custom prefix + pnpm + fnm + Volta + Bun + Scoop + `.claude\local` + `.cargo\.crates2.json`
        let custom_npm = root.join("custom-npm-global");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            home.join(".npmrc"),
            format!("; comment\nprefix=\"{}\"\n", custom_npm.display()),
        )
        .unwrap();
        let npmrc_cc = custom_npm
            .join("node_modules")
            .join("@anthropic-ai")
            .join("claude-code");
        std::fs::create_dir_all(&npmrc_cc).unwrap();
        std::fs::write(npmrc_cc.join("package.json"), r#"{"version":"2.2.10"}"#).unwrap();

        let pnpm_cc = home
            .join("AppData")
            .join("Local")
            .join("pnpm")
            .join("global")
            .join("5")
            .join("node_modules")
            .join("@anthropic-ai")
            .join("claude-code");
        std::fs::create_dir_all(&pnpm_cc).unwrap();
        std::fs::write(pnpm_cc.join("package.json"), r#"{"version":"2.3.5"}"#).unwrap();
        std::fs::write(pnpm_cc.join("claude.exe"), b"exe").unwrap();

        // Scoop claude-code (2.4.0 > 2.3.5)
        let scoop_cc = home
            .join("scoop")
            .join("apps")
            .join("claude-code")
            .join("current");
        std::fs::create_dir_all(&scoop_cc).unwrap();
        std::fs::write(scoop_cc.join("manifest.json"), r#"{"version":"2.4.0"}"#).unwrap();
        std::fs::write(scoop_cc.join("claude.exe"), b"exe").unwrap();

        assert_eq!(
            installed_claude_code_version_in_homes(std::slice::from_ref(&home)).as_deref(),
            Some("2.4.0")
        );
        let cc_exes = discover_cli_exes_in_homes("claude-code", std::slice::from_ref(&home));
        assert_eq!(cc_exes.len(), 2);

        // Cargo `.crates2.json` fallback when `codex.exe` has no Win32 PE VERSIONINFO
        let cargo_bin = home.join(".cargo").join("bin");
        std::fs::create_dir_all(&cargo_bin).unwrap();
        std::fs::write(cargo_bin.join("codex.exe"), b"rust-bin-no-pe-ver").unwrap();
        std::fs::write(
            home.join(".cargo").join(".crates2.json"),
            r#"{"installs":{"codex-cli 0.162.0 (registry+https://github.com/rust-lang/crates.io-index)":{"bins":["codex.exe"]}}}"#,
        )
        .unwrap();
        assert_eq!(
            installed_codex_cli_version_in_homes(std::slice::from_ref(&home)).as_deref(),
            Some("0.162.0")
        );

        // Env pair root extraction (`FNM_DIR`, `VOLTA_HOME`, `Path` with `nodejs`)
        let mut nm_roots = Vec::new();
        let mut volta_roots = Vec::new();
        collect_node_roots_from_env_pairs(
            &[
                ("VOLTA_HOME", r"D:\Volta"),
                ("Path", r"C:\Windows\System32;D:\Program Files\nodejs"),
            ],
            &home,
            &mut nm_roots,
            &mut volta_roots,
        );
        assert!(volta_roots.contains(&PathBuf::from(r"D:\Volta\tools\image\packages")));
        assert!(nm_roots.contains(&PathBuf::from(r"D:\Program Files\nodejs\node_modules")));

        // 2. Squirrel Claude Desktop `AnthropicClaude\app-*\claude.exe` + Uninstall helper + ProfileImagePath
        let sq_claude = root.join("AnthropicClaude");
        let sq_app = sq_claude.join("app-1.14.2");
        std::fs::create_dir_all(&sq_app).unwrap();
        std::fs::write(sq_app.join("claude.exe"), b"squirrel-bin").unwrap();
        assert_eq!(
            installed_claude_desktop_version_in_dirs(&[sq_claude]).as_deref(),
            Some("1.14.2")
        );
        assert_eq!(
            expand_profile_image_path_with_drive(r"%SystemDrive%\Users\Alice", "D:"),
            PathBuf::from(r"D:\Users\Alice")
        );
        assert_eq!(
            extract_install_dir_from_uninstall_values(
                None,
                Some(r#""D:\Apps\Antigravity\Antigravity.exe",0"#)
            ),
            Some(PathBuf::from(r"D:\Apps\Antigravity"))
        );

        // 3. Multi-dir `installed_antigravity_ide_info_in_dirs` updates BOTH best_ver and updater_url
        let ag_old = root.join("ag-old");
        let ag_new = root.join("ag-new");
        for (d, ver, url) in [
            (&ag_old, "2.30.0", "https://old.example.invalid/feed/"),
            (&ag_new, "2.36.1", "https://new.example.invalid/feed/"),
        ] {
            std::fs::create_dir_all(d.join("resources").join("app")).unwrap();
            std::fs::write(
                d.join("resources").join("app").join("package.json"),
                format!(r#"{{"version":"{ver}"}}"#),
            )
            .unwrap();
            std::fs::write(
                d.join("resources").join("app-update.yml"),
                format!("url: {url}\n"),
            )
            .unwrap();
        }
        let (best_ag_ver, best_ag_url) = installed_antigravity_ide_info_in_dirs(&[ag_old, ag_new]);
        assert_eq!(best_ag_ver.as_deref(), Some("2.36.1"));
        assert_eq!(
            best_ag_url.as_deref(),
            Some("https://new.example.invalid/feed")
        );

        // 4. Antigravity plugins across `.antigravity\extensions`, `.gemini\antigravity\extensions`, and `.gemini-plugin/plugin.json`
        let ext_um = home
            .join(".antigravity")
            .join("extensions")
            .join("silas.antigravity-usage-monitor-1.8.4");
        std::fs::create_dir_all(&ext_um).unwrap();
        std::fs::write(ext_um.join("package.json"), r#"{"version":"1.8.4"}"#).unwrap();

        let ext_cap = home
            .join(".gemini")
            .join("antigravity")
            .join("extensions")
            .join("custom-folder")
            .join(".gemini-plugin");
        std::fs::create_dir_all(&ext_cap).unwrap();
        std::fs::write(
            ext_cap.join("plugin.json"),
            r#"{"name":"@ikaros/agy-capsule","version":"0.9.2"}"#,
        )
        .unwrap();

        assert_eq!(
            installed_antigravity_plugin_version_in_homes(
                &["usage-monitor", "antigravity-usage-monitor"],
                std::slice::from_ref(&home)
            )
            .as_deref(),
            Some("1.8.4")
        );
        assert_eq!(
            installed_antigravity_plugin_version_in_homes(
                &["agy-capsule"],
                std::slice::from_ref(&home)
            )
            .as_deref(),
            Some("0.9.2")
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn utf8_chinese_msix_packages_and_profile_paths_never_panic() {
        // 1. 3-byte Chinese UTF-8 MSIX package names where ASCII prefix lengths (7, 13) land mid-character!
        for pkg in ["腾讯会议_3.20", "网易云音乐_2.10", "哔哩哔哩_1.0"] {
            assert!(!package_name_matches_prefix(pkg, "Claude_"));
            assert!(!package_name_matches_prefix(pkg, "OpenAI.Codex_"));
            assert!(!package_name_matches_prefix(pkg, "OpenAI.ChatGPT-Desktop_"));
        }
        assert!(package_name_matches_prefix(
            "claude_5.1231.2.0_x64__pzs8sxrjxfjjc",
            "Claude_"
        ));

        let wa_root = unique_temp_dir("zh-msix");
        for folder in [
            "腾讯会议_3.20__abc",
            "网易云音乐_2.10__def",
            "哔哩哔哩_1.0__ghi",
            "Claude_5.1231.2.0_x64__pzs8sxrjxfjjc",
        ] {
            std::fs::create_dir_all(wa_root.join(folder)).unwrap();
        }
        let matched = find_windowsapps_dir_in(&wa_root, "Claude_").unwrap();
        assert!(matched.ends_with("Claude_5.1231.2.0_x64__pzs8sxrjxfjjc"));
        assert!(find_windowsapps_dir_in(&wa_root, "OpenAI.Codex_").is_none());
        let _ = std::fs::remove_dir_all(&wa_root);

        // 2. Chinese user profile path (`D:\Users\张三\AppData` has byte 13 mid-char of `三`!)
        assert_eq!(
            expand_profile_image_path_with_drive(r"D:\Users\张三\AppData", "C:"),
            PathBuf::from(r"D:\Users\张三\AppData")
        );
        assert_eq!(
            expand_profile_image_path_with_drive(r"%SystemDrive%\Users\张三", "D:"),
            PathBuf::from(r"D:\Users\张三")
        );
        assert!(path_under_dir_l(
            r"\\?\d:\users\张三\appdata\local\programs\antigravity\antigravity.exe",
            r"d:\users\张三\appdata\local\programs\antigravity"
        ));
    }

    #[test]
    fn conpty_interactive_cmd_winget_codex_dir_and_claude_residual_sweep() {
        // 1. ConPTY / interactive cmd.exe without `/c` vs batch `cmd.exe /c`
        let mk = |pid: u32, ppid: u32, name: &str, path: &str, cmd: &str| ProcInfo {
            pid,
            ppid,
            name_l: name.to_string(),
            path_l: path.to_string(),
            cmd_l: cmd.to_string(),
            start_time: 8000 + pid as u64,
        };
        assert!(is_interactive_shell_or_terminal("conhost.exe"));
        assert!(is_interactive_shell_or_terminal("openconsole.exe"));
        assert!(is_interactive_shell_or_terminal("code.exe"));
        assert!(is_interactive_shell_or_terminal("chrome.exe"));
        assert!(is_interactive_shell_proc(&mk(
            1,
            0,
            "cmd.exe",
            r"c:\windows\system32\cmd.exe",
            r#""c:\windows\system32\cmd.exe""#
        )));
        assert!(!is_interactive_shell_proc(&mk(
            2,
            0,
            "cmd.exe",
            r"c:\windows\system32\cmd.exe",
            r#"cmd.exe /d /s /c "agy-node.cmd""#
        )));

        // Integrated `cmd.exe` (no `/c`) and `openconsole.exe` inside Antigravity MUST spare user's `node.exe`!
        let ag_dir = r"c:\apps\antigravity";
        let procs = vec![
            mk(
                100,
                10,
                "antigravity.exe",
                &format!(r"{ag_dir}\antigravity.exe"),
                "",
            ),
            mk(
                110,
                100,
                "cmd.exe",
                r"c:\windows\system32\cmd.exe",
                "cmd.exe",
            ),
            mk(111, 110, "node.exe", r"c:\nodejs\node.exe", "node vite.js"),
            mk(
                120,
                100,
                "openconsole.exe",
                r"c:\windows\openconsole.exe",
                "",
            ),
            mk(121, 120, "nu.exe", r"c:\tools\nu.exe", ""),
        ];
        let kill_pids: Vec<u32> =
            pick_gui_agent_kill_tree("antigravity", &procs, None, &[ag_dir.to_string()])
                .into_iter()
                .map(|i| i.pid)
                .collect();
        assert_eq!(kill_pids, vec![100]);

        // 2. WinGet Claude CLI is CLI, never GUI
        for wg in [
            r"c:\users\u\appdata\local\microsoft\winget\packages\anthropic.claudecode_microsoft.winget.source_8wekyb3d8bbwe\claude.exe",
            r"c:\users\u\appdata\local\microsoft\winget\links\claude.exe",
        ] {
            assert!(!gui_agent_matches("claude", "claude.exe", wg, None));
            assert!(cli_agent_matches("claude-code", "claude.exe", wg, ""));
        }

        // 3. `Codex.exe` inside custom `chatgpt_dirs_l` is GUI (`chatgpt`), NOT CLI (`codex`)!
        let custom_codex_dir = r"d:\custom\openai codex";
        let custom_codex_exe = r"d:\custom\openai codex\app\codex.exe";
        assert!(!cli_agent_matches_with_dirs(
            "codex",
            "codex.exe",
            custom_codex_exe,
            "",
            &[custom_codex_dir.to_string()]
        ));
        let codex_procs = vec![mk(50, 10, "codex.exe", custom_codex_exe, "")];
        let gpt_tree = pick_gui_agent_kill_tree_with_dirs(
            "chatgpt",
            &codex_procs,
            &[],
            &[custom_codex_dir.to_string()],
            &[],
        );
        assert_eq!(gpt_tree.len(), 1);

        // 4. `pick_residual` sweeps orphaned Claude `--type=gpu-process` / `github-mcp-server.exe` -> `node.exe` children-first!
        let claude_dir = r"c:\program files\windowsapps\claude_5.1231.2.0_x64__pzs8sxrjxfjjc";
        let residual_procs = vec![
            mk(
                210,
                200,
                "claude.exe",
                &format!(r"{claude_dir}\app\claude.exe"),
                "--type=gpu-process",
            ),
            mk(
                220,
                200,
                "github-mcp-server.exe",
                &format!(r"{claude_dir}\app\github-mcp-server.exe"),
                "",
            ),
            mk(221, 220, "node.exe", r"c:\nodejs\node.exe", "mcp-worker.js"),
        ];
        let res = pick_residual(&residual_procs, Some(claude_dir))
            .expect("orphaned GPU/MCP helpers must be swept when root Claude.exe is gone");
        let res_pids: Vec<u32> = res.iter().map(|(i, _)| residual_procs[*i].pid).collect();
        assert_eq!(res_pids.len(), 3);
        let pos = |pid: u32| res_pids.iter().position(|&x| x == pid).unwrap();
        assert!(
            pos(221) < pos(220),
            "child node.exe must precede parent mcp-server"
        );

        // 6. Command line quoting & discovery cache invalidation
        let quoted = format_windows_command_line(
            Path::new(r"D:\Users\张三\Antigravity IDE\Antigravity IDE.exe"),
            &[
                "--proxy-server=http://127.0.0.1:7890".into(),
                "arg with space".into(),
            ],
        );
        assert!(quoted.starts_with(r#""D:\Users\张三\Antigravity IDE\Antigravity IDE.exe""#));
        assert!(quoted.ends_with(r#""arg with space""#));
        invalidate_discovery_cache();
    }

    #[cfg(windows)]
    #[test]
    fn win32_handle_pinned_termination_verifies_identity_and_terminates_without_taskkill() {
        use std::os::windows::process::CommandExt;
        use std::process::{Command, Stdio};

        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let ping_exe = PathBuf::from(r"C:\Windows\System32\PING.EXE");
        if !ping_exe.is_file() {
            return;
        }

        let child = Command::new(&ping_exe)
            .args(["-n", "30", "127.0.0.1"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .expect("spawn background ping.exe for handle-pinned kill test");

        struct ChildCleanup(std::process::Child);
        impl Drop for ChildCleanup {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut guard = ChildCleanup(child);
        let pid = guard.0.id();

        // 1. Mismatched exe_path must be rejected without killing the process!
        assert_eq!(
            terminate_identity_win32(&ProcessIdentity {
                pid,
                start_time: 0,
                exe_path: r"C:\Windows\System32\notepad.exe".into(),
            }),
            NativeKillStep::SkippedMismatch
        );
        assert!(guard.0.try_wait().unwrap().is_none());

        // 2. Mismatched start_time must be rejected without killing the process!
        assert_eq!(
            terminate_identity_win32(&ProcessIdentity {
                pid,
                start_time: 946_684_800, // Year 2000
                exe_path: ping_exe.to_string_lossy().into_owned(),
            }),
            NativeKillStep::SkippedMismatch
        );
        assert!(guard.0.try_wait().unwrap().is_none());

        // 3. Matching identity terminates via handle-pinned `TerminateProcess(h, 1)`!
        let captured =
            capture_process_identity(pid).expect("capture_process_identity on live ping.exe");
        assert_eq!(captured.pid, pid);
        assert!(terminate_verified_identity(&captured));
        let status = guard.0.wait().expect("wait terminated ping.exe");
        assert!(!status.success());

        // Root Electron GUI classifier checks
        assert!(is_root_electron_gui_process(
            "antigravity",
            r"C:\Users\u\AppData\Local\Programs\antigravity\Antigravity.exe",
            Some(r#""Antigravity.exe" --disable-quic"#)
        ));
        assert!(!is_root_electron_gui_process(
            "antigravity",
            r"C:\Users\u\AppData\Local\Programs\antigravity\resources\app\extensions\antigravity\bin\language_server_windows_x64.exe",
            None
        ));
        assert!(!is_root_electron_gui_process(
            "antigravity",
            r"C:\Users\u\AppData\Local\Programs\antigravity\Antigravity.exe",
            Some("--type=renderer")
        ));
        assert!(!is_root_electron_gui_process(
            "claude",
            r"C:\Users\u\.local\share\claude\versions\2.1.88\claude.exe",
            None
        ));
        assert!(is_root_electron_gui_process(
            "claude",
            r"C:\Users\u\AppData\Local\AnthropicClaude\app-0.9.3\claude.exe",
            None
        ));
        assert!(is_root_electron_gui_process(
            "chatgpt",
            r"C:\Program Files\WindowsApps\OpenAI.ChatGPT-Desktop_1.0\app\ChatGPT.exe",
            None
        ));
        assert!(parse_app_update_url("url: http://insecure.example/feed\n").is_none());
        assert!(parse_app_update_url("url: https://127.0.0.1/feed\n").is_none());
        assert_eq!(
            parse_app_update_url("url: https://updates.antigravity.google/feed/\n").as_deref(),
            Some("https://updates.antigravity.google/feed")
        );
    }

    #[test]
    fn core_three_gui_and_two_cli_agent_contract() {
        assert_eq!(GUI_AGENTS.len(), 3);
        assert_eq!(CLI_AGENTS.len(), 2);
        assert_eq!(agent_ids(), vec!["claude", "chatgpt", "antigravity"]);
        assert_eq!(
            CLI_AGENTS.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
            vec!["claude-code", "codex"]
        );
    }

    #[test]
    fn merges_windows_unicode_env_block_case_insensitively_and_rejects_nul() {
        let base_pairs = vec![
            ("=C:".to_string(), r"C:\Windows".to_string()),
            ("Path".to_string(), r"C:\Windows\System32".to_string()),
            ("USERPROFILE".to_string(), r"C:\Users\Alice".to_string()),
            (
                "HTTP_PROXY".to_string(),
                "http://127.0.0.1:7890".to_string(),
            ),
        ];
        let base_block = encode_env_pairs_utf16(&base_pairs).unwrap();

        let mut extra = BTreeMap::new();
        extra.insert(
            "http_proxy".to_string(),
            "http://127.0.0.1:7892".to_string(),
        );
        extra.insert(
            "CLAUDE_CONFIG_DIR".to_string(),
            r"C:\Vaults\work\claude".to_string(),
        );

        let merged = merge_windows_unicode_env_block(&base_block, &extra).unwrap();
        // Must be double-NUL terminated
        assert!(merged.len() >= 2);
        assert_eq!(merged[merged.len() - 1], 0);
        assert_eq!(merged[merged.len() - 2], 0);

        let decoded = decode_windows_unicode_env_block(&merged);
        assert_eq!(decoded.len(), 5);
        assert!(decoded
            .iter()
            .any(|(k, v)| k == "=C:" && v == r"C:\Windows"));
        assert!(decoded
            .iter()
            .any(|(k, v)| k == "http_proxy" && v == "http://127.0.0.1:7892"));
        assert!(decoded
            .iter()
            .any(|(k, v)| k == "CLAUDE_CONFIG_DIR" && v == r"C:\Vaults\work\claude"));
        // Verify sorted case-insensitively
        for pair in decoded.windows(2) {
            assert!(pair[0].0.to_ascii_uppercase() <= pair[1].0.to_ascii_uppercase());
        }

        // Reject NUL in value or '=' in key
        let mut bad_nul = BTreeMap::new();
        bad_nul.insert("BAD".to_string(), "val\0injected".to_string());
        assert!(merge_windows_unicode_env_block(&base_block, &bad_nul).is_err());

        let mut bad_eq = BTreeMap::new();
        bad_eq.insert("A=B".to_string(), "1".to_string());
        assert!(merge_windows_unicode_env_block(&base_block, &bad_eq).is_err());
    }
}
