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
//! - CLI agents (`claude-code`, `codex`, `gemini-cli`) are NEVER killed during a trip;
//!   only optional orphan residual sweep cleans CLI processes whose parent terminal (`ppid`)
//!   is already dead.
//! - Every termination re-verifies `(pid, start_time, exe_path)` immediately prior to `kill()`
//!   to eliminate PID-reuse collateral damage (R04), ordered children-first so parents cannot
//!   respawn helpers mid-sweep.

use std::collections::{HashMap, HashSet};
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
pub const CLI_AGENTS: &[(&str, &str)] = &[
    ("claude-code", "Claude Code"),
    ("codex", "Codex CLI"),
    ("gemini", "Gemini CLI"),
];

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

/// Zero-allocation case-insensitive directory prefix check enforcing a path-separator boundary
/// so `...\Programs\antigravity` never falsely matches `...\Programs\antigravity ide`.
pub fn path_under_dir_l(exe_path_l: &str, dir_l: &str) -> bool {
    let d = dir_l.trim().trim_end_matches(['\\', '/']);
    let p = exe_path_l.trim();
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
    exe_path_l.contains(r"\claude\claude-code\")
        || exe_path_l.contains(r"\.local\bin\claude")
        || exe_path_l.contains(r"@anthropic-ai\claude-code")
        || exe_path_l.contains("@anthropic-ai/claude-code")
        || exe_path_l.contains("claude-code-win32")
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
                || exe_path_l.contains(r"\windowsapps\openai.codex_")
                || exe_path_l.contains(r"\windowsapps\openai.chatgpt")
                || exe_path_l.contains(r"\programs\chatgpt\")
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

/// Pure matcher for CLI agent processes (all inputs expected lowercase).
pub fn cli_agent_matches(id: &str, exe_name_l: &str, exe_path_l: &str, cmd_l: &str) -> bool {
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
                || exe_path_l.contains(r"\programs\chatgpt\");
            !in_msix_or_gui
                && (exe_name_l.starts_with("codex")
                    || cmd_l.contains(r"@openai\codex")
                    || cmd_l.contains("@openai/codex")
                    || exe_path_l.contains(r"@openai\codex")
                    || exe_path_l.contains("@openai/codex")
                    || exe_path_l.contains("codex-win32-"))
        }
        "gemini" => cmd_l.contains("gemini-cli"),
        _ => false,
    }
}

fn is_any_cli_agent(p: &ProcInfo) -> bool {
    CLI_AGENTS
        .iter()
        .any(|(cid, _)| cli_agent_matches(cid, &p.name_l, &p.path_l, &p.cmd_l))
}

/// Interactive shells and standalone terminal hosts that must never be collateral-killed
/// or traversed into as agent network helpers (unless their binary lives inside `<AntigravityDir>`).
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
            | "wsl.exe"
    )
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
        && !is_any_cli_agent(p)
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
    if p.name_l != "chatgpt.exe" && p.name_l != "codex.exe" {
        return false;
    }
    if p.path_l.contains(r"\resources\codex.exe") {
        return false;
    }
    if p.cmd_l.contains("--type=") || p.cmd_l.contains("electron_run_as_node") {
        return false;
    }
    if let Some(parent) = by_pid.get(&p.ppid) {
        if parent.name_l == "chatgpt.exe" || parent.name_l == "codex.exe" {
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

fn has_ancestor_matching(
    start_pid: u32,
    by_pid: &HashMap<u32, &ProcInfo>,
    pred: impl Fn(&ProcInfo) -> bool,
) -> bool {
    let Some(first) = by_pid.get(&start_pid) else {
        return false;
    };
    let mut cur = first.ppid;
    let mut visited = HashSet::new();
    while cur != 0 && visited.insert(cur) {
        let Some(par) = by_pid.get(&cur) else {
            break;
        };
        if pred(par) {
            return true;
        }
        cur = par.ppid;
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
    in_agent_dir_fn: impl Fn(&ProcInfo) -> bool,
) {
    while let Some(pid) = queue.pop() {
        let Some(kids) = children_by_ppid.get(&pid) else {
            continue;
        };
        for &child_idx in kids {
            let child = &procs[child_idx];
            if is_uninstaller_exe(&child.name_l) || (skip_cli && is_any_cli_agent(child)) {
                continue;
            }
            let in_dir = in_agent_dir_fn(child);
            if !in_dir && is_interactive_shell_or_terminal(&child.name_l) {
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
        if is_uninstaller_exe(&p.name_l) || is_any_cli_agent(p) {
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

/// Pure selector building the complete kill tree for a CLI agent (`claude-code`, `codex`, `gemini`),
/// walking descendant worker/MCP processes children-first and NEVER touching ancestor terminals.
pub fn pick_cli_agent_kill_tree(cli_id: &str, procs: &[ProcInfo]) -> Vec<ProcessIdentity> {
    let children_by_ppid = build_children_map(procs);
    let mut selected: HashSet<usize> = HashSet::new();
    let mut queue: Vec<u32> = Vec::new();
    let mut visited_pids: HashSet<u32> = HashSet::new();

    for (idx, p) in procs.iter().enumerate() {
        if is_uninstaller_exe(&p.name_l) || is_agent_scm_service_exe(&p.name_l) {
            continue;
        }
        if cli_agent_matches(cli_id, &p.name_l, &p.path_l, &p.cmd_l) {
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
        |_| false,
    );

    postorder_indices(&selected, procs)
        .into_iter()
        .map(|idx| procs[idx].identity())
        .collect()
}

/// Pure detector for Antigravity residual and mid-run detached crash-orphan processes.
///
/// - **Case A (Full exit residual)**: When NO live root Antigravity GUI exists in `procs`,
///   every remaining Antigravity-dir process (`language_server*.exe`, `antigravity.exe`,
///   `webm_encoder.exe`, etc.), their non-shell helper children, and orphaned Antigravity/MCP
///   `node.exe` processes whose `ppid` is dead are returned.
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

    let any_ag_proc_present = procs
        .iter()
        .any(|q| !is_agent_scm_service_exe(&q.name_l) && is_antigravity_dir_proc(q, ag_dirs_l));
    let mut selected: HashSet<usize> = HashSet::new();

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
                continue;
            }
            if is_interactive_shell_or_terminal(&p.name_l) {
                continue;
            }
            if has_ancestor_matching(p.pid, &by_pid, |par| {
                is_antigravity_dir_proc(par, ag_dirs_l)
            }) {
                selected.insert(idx);
                continue;
            }
            if matches!(p.name_l.as_str(), "node.exe" | "node")
                && (p.ppid == 0 || !alive_pids.contains(&p.ppid))
            {
                let has_ag_marker = p.cmd_l.contains("antigravity")
                    || p.cmd_l.contains("sidecar_sdk")
                    || p.cmd_l.contains("mcp")
                    || p.path_l.contains("antigravity")
                    || ag_dirs_l
                        .iter()
                        .any(|d| !d.is_empty() && (p.path_l.contains(d) || p.cmd_l.contains(d)));
                if has_ag_marker || (p.cmd_l.is_empty() && any_ag_proc_present) {
                    selected.insert(idx);
                }
            }
        }
    } else {
        let mut queue: Vec<u32> = Vec::new();
        let mut visited_pids: HashSet<u32> = HashSet::new();

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

        expand_non_shell_descendants(
            procs,
            &children_by_ppid,
            &mut queue,
            &mut visited_pids,
            &mut selected,
            true,
            |child| is_antigravity_dir_proc(child, ag_dirs_l),
        );
    }

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
                && !is_interactive_shell_or_terminal(&p.name_l)
                && (p.ppid == 0 || !alive_pids.contains(&p.ppid))
                && (p.path_l.contains(r"\anthropicclaude\")
                    || p.cmd_l.contains("anthropicclaude")
                    || p.cmd_l.contains("github-mcp-server")
                    || claude_dirs_l.iter().any(|d| {
                        !d.is_empty()
                            && (path_under_dir_l(&p.path_l, d) || p.cmd_l.contains(d.as_str()))
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
                && !is_any_cli_agent(p)
                && !is_interactive_shell_or_terminal(&p.name_l)
                && (p.ppid == 0 || !alive_pids.contains(&p.ppid))
                && (p.path_l.contains(r"\windowsapps\openai.")
                    || p.cmd_l.contains("openai.codex_")
                    || p.cmd_l.contains("openai.chatgpt")
                    || chatgpt_dirs_l.iter().any(|d| {
                        !d.is_empty()
                            && (path_under_dir_l(&p.path_l, d) || p.cmd_l.contains(d.as_str()))
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
        |child| {
            chatgpt_dirs_l
                .iter()
                .any(|d| path_under_dir_l(&child.path_l, d))
                || gui_agent_matches("chatgpt", &child.name_l, &child.path_l, None)
        },
    );

    postorder_indices(&selected, procs)
}

/// Pure detector for orphaned CLI sessions (`claude-code`, `codex`, `gemini`) whose launching
/// parent terminal (`ppid`) is dead, plus their non-shell descendant helpers, ordered **children-first**.
pub fn pick_cli_orphans(cli_id: &str, procs: &[ProcInfo]) -> Vec<usize> {
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
        if cli_agent_matches(cli_id, &p.name_l, &p.path_l, &p.cmd_l)
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
    if is_uninstaller_exe(&p.name_l) || is_agent_scm_service_exe(&p.name_l) {
        return None;
    }
    if cli_agent_matches("claude-code", &p.name_l, &p.path_l, &p.cmd_l) {
        return Some(ClaudeKind::Cli);
    }
    if gui_agent_matches("claude", &p.name_l, &p.path_l, claude_dir_l) {
        return Some(ClaudeKind::Desktop);
    }
    None
}

/// Select all Claude processes (Desktop + CLI) for explicit manual sweep.
pub fn pick_manual(procs: &[ProcInfo], claude_dir_l: Option<&str>) -> Vec<(usize, ClaudeKind)> {
    procs
        .iter()
        .enumerate()
        .filter_map(|(i, p)| classify_claude(p, claude_dir_l).map(|k| (i, k)))
        .collect()
}

/// Select only orphaned residual Claude processes after desktop has exited.
///
/// - Returns `None` while any Claude Desktop process is still running.
/// - Desktop auxiliary processes (renderer/crashpad/GPU) are selected.
/// - CLI processes are selected ONLY when their parent terminal (`ppid`) is dead.
pub fn pick_residual(
    procs: &[ProcInfo],
    claude_dir_l: Option<&str>,
) -> Option<Vec<(usize, ClaudeKind)>> {
    let all = pick_manual(procs, claude_dir_l);
    if all.iter().any(|(_, k)| *k == ClaudeKind::Desktop) {
        return None;
    }
    let alive: HashSet<u32> = procs.iter().map(|p| p.pid).collect();
    Some(
        all.into_iter()
            .filter(|(i, k)| match k {
                ClaudeKind::Desktop => true,
                ClaudeKind::Cli => {
                    let p = &procs[*i];
                    p.ppid == 0 || !alive.contains(&p.ppid)
                }
            })
            .collect(),
    )
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
    path.to_string_lossy()
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
        if name.len() < family_prefix.len()
            || !name[..family_prefix.len()].eq_ignore_ascii_case(family_prefix)
        {
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

fn find_windowsapps_dir(prefix: &str) -> Option<PathBuf> {
    let root = Path::new(r"C:\Program Files\WindowsApps");
    let mut best: Option<(Vec<u64>, std::ffi::OsString)> = None;
    if let Ok(rd) = std::fs::read_dir(root) {
        for entry in rd.flatten() {
            let s = entry.file_name().to_string_lossy().to_string();
            if s.len() >= prefix.len()
                && s[..prefix.len()].eq_ignore_ascii_case(prefix)
                && s.contains("__")
            {
                let key = version_key(&s);
                if best.as_ref().is_none_or(|(k, _)| key > *k) {
                    best = Some((key, entry.file_name()));
                }
            }
        }
    }
    best.map(|(_, n)| root.join(n))
}

fn is_skipped_system_user_dir(name: &str) -> bool {
    matches!(
        name.trim().to_ascii_lowercase().as_str(),
        "public" | "default" | "default user" | "all users"
    )
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

/// Testable resolver collecting per-user `%LOCALAPPDATA%\<subdir>` paths across current env and `C:\Users\*`.
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

/// Collect per-user `AppData\Local\<subdir>` directories across current user env and `C:\Users\*`.
pub fn per_user_local_app_subdirs(rel_subdirs: &[&str]) -> Vec<PathBuf> {
    let local = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    let profile = std::env::var_os("USERPROFILE").map(PathBuf::from);
    let users_root = users_root_dir();
    per_user_local_app_subdirs_from_roots(
        local.as_deref(),
        profile.as_deref(),
        Some(&users_root),
        rel_subdirs,
    )
}

/// Collect deduplicated user home directories (`%USERPROFILE%` + `C:\Users\*`), supporting `LocalSystem`.
pub fn user_home_dirs_from_roots(
    user_profile: Option<&Path>,
    users_root: Option<&Path>,
) -> Vec<PathBuf> {
    let mut homes = Vec::new();
    let mut seen = HashSet::new();
    if let Some(profile) = user_profile {
        if profile.is_dir() && seen.insert(normalize_path_key_l(profile)) {
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

fn user_home_dirs() -> Vec<PathBuf> {
    let profile = std::env::var_os("USERPROFILE").map(PathBuf::from);
    let users_root = users_root_dir();
    user_home_dirs_from_roots(profile.as_deref(), Some(&users_root))
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

pub fn claude_covered_dirs() -> Vec<PathBuf> {
    let msix = covered_dirs_from(
        &registered_package_dirs("Claude_"),
        find_windowsapps_dir("Claude_"),
    );
    let per_user = per_user_local_app_subdirs(&["AnthropicClaude", r"Programs\claude"]);
    merge_covered_dirs(msix, per_user)
}

pub fn chatgpt_covered_dirs() -> Vec<PathBuf> {
    let mut pkgs = registered_package_dirs("OpenAI.Codex_");
    pkgs.extend(registered_package_dirs("OpenAI.ChatGPT_"));
    let pkgs = dedup_and_sort_packages(pkgs);

    let mut msix = covered_dirs_from(&pkgs, find_windowsapps_dir("OpenAI.Codex_"));
    if let Some(fallback_gpt) = find_windowsapps_dir("OpenAI.ChatGPT_") {
        if !contains_path_ci(&msix, &fallback_gpt) {
            msix.push(fallback_gpt);
        }
    }
    let per_user = per_user_local_app_subdirs(&[r"Programs\ChatGPT", r"Programs\Codex"]);
    merge_covered_dirs(msix, per_user)
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

/// Discover all Antigravity installation directories across current user env and `C:\Users\*`.
pub fn antigravity_covered_dirs() -> Vec<PathBuf> {
    let local = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    let profile = std::env::var_os("USERPROFILE").map(PathBuf::from);
    let users_root = users_root_dir();
    antigravity_covered_dirs_from_roots(local.as_deref(), profile.as_deref(), Some(&users_root))
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

/// Testable standalone CLI native executable discovery across explicit user home roots.
pub fn discover_cli_exes_in_homes(cli_id: &str, homes: &[PathBuf]) -> Vec<PathBuf> {
    let mut exes = Vec::new();
    match cli_id {
        "claude-code" => {
            for home in homes {
                let local_claude = home.join(".local").join("bin").join("claude.exe");
                if local_claude.is_file() && !contains_path_ci(&exes, &local_claude) {
                    exes.push(local_claude);
                }
                let roaming_cc = home
                    .join("AppData")
                    .join("Roaming")
                    .join("Claude")
                    .join("claude-code");
                collect_exes_matching(&roaming_cc, 0, 4, &|n| n == "claude.exe", &mut exes);
                let npm_cc = home
                    .join("AppData")
                    .join("Roaming")
                    .join("npm")
                    .join("node_modules")
                    .join("@anthropic-ai")
                    .join("claude-code");
                collect_exes_matching(&npm_cc, 0, 5, &|n| n == "claude.exe", &mut exes);
            }
        }
        "codex" => {
            for home in homes {
                let npm_codex = home
                    .join("AppData")
                    .join("Roaming")
                    .join("npm")
                    .join("node_modules")
                    .join("@openai")
                    .join("codex");
                collect_exes_matching(&npm_codex, 0, 8, &|n| n.starts_with("codex"), &mut exes);
                let local_bin = home.join(".local").join("bin");
                collect_exes_matching(&local_bin, 0, 0, &|n| n.starts_with("codex"), &mut exes);
                let cargo_bin = home.join(".cargo").join("bin");
                collect_exes_matching(&cargo_bin, 0, 0, &|n| n.starts_with("codex"), &mut exes);
            }
        }
        _ => {}
    }
    exes
}

/// Discover standalone native CLI binaries for `claude-code` or `codex` across all user homes.
pub fn discover_cli_exes(cli_id: &str) -> Vec<PathBuf> {
    discover_cli_exes_in_homes(cli_id, &user_home_dirs())
}

/// Testable deep (`max_depth = 12`) Claude covered executable discovery + standalone `claude-code` CLI.
pub fn discover_claude_exes_from_dirs_and_homes(
    dirs: &[PathBuf],
    homes: &[PathBuf],
) -> Vec<PathBuf> {
    let mut exes = Vec::new();
    for dir in dirs {
        for primary in [dir.join("app").join("claude.exe"), dir.join("claude.exe")] {
            if primary.is_file() && !contains_path_ci(&exes, &primary) {
                exes.push(primary);
            }
        }
    }
    for dir in dirs {
        collect_exes_filtered(dir, 0, 12, &mut exes);
    }
    for cli_exe in discover_cli_exes_in_homes("claude-code", homes) {
        if !contains_path_ci(&exes, &cli_exe) {
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
            dir.join("app").join("Codex.exe"),
            dir.join("ChatGPT.exe"),
            dir.join("Codex.exe"),
        ] {
            if primary.is_file() && !contains_path_ci(&exes, &primary) {
                exes.push(primary);
            }
        }
    }
    for dir in dirs {
        collect_exes_filtered(dir, 0, 12, &mut exes);
    }
    for cli_exe in discover_cli_exes_in_homes("codex", homes) {
        if !contains_path_ci(&exes, &cli_exe) {
            exes.push(cli_exe);
        }
    }
    exes
}

/// Discover covered executables for `claude`, `chatgpt`, or `antigravity`.
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
    use windows::core::{PCWSTR, w};
    use windows::Win32::Storage::FileSystem::{
        GetFileVersionInfoSizeW, GetFileVersionInfoW, VS_FIXEDFILEINFO, VerQueryValueW,
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
        if GetFileVersionInfoW(PCWSTR(wide.as_ptr()), 0, size, buf.as_mut_ptr().cast::<c_void>())
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

fn pick_newer_version(best: &mut Option<String>, candidate: &str) {
    let clean = candidate.trim().trim_start_matches(['v', 'V']).trim();
    if clean.is_empty() || version_key(clean).is_empty() {
        return;
    }
    match best {
        None => *best = Some(clean.to_string()),
        Some(prev) => {
            if version_key(clean) > version_key(prev) {
                *best = Some(clean.to_string());
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
        .filter(|s| !s.is_empty() && !version_key(s).is_empty())
}

fn scan_versioned_claude_code_dir(root: &Path, best: &mut Option<String>) {
    let Ok(rd) = std::fs::read_dir(root) else {
        return;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if !p.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if version_key(&name).is_empty() {
            continue;
        }
        let has_bin = p.join("claude.exe").is_file()
            || std::fs::read_dir(&p)
                .ok()
                .is_some_and(|mut sub| {
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

/// Detect installed Claude Desktop version (MSIX registry/folder or non-MSIX PE FileVersion).
pub fn installed_claude_desktop_version() -> Option<String> {
    if let Some(msix) = installed_msix_version("Claude_") {
        return Some(msix);
    }
    let mut best = None;
    for dir in per_user_local_app_subdirs(&["AnthropicClaude", r"Programs\Claude"]) {
        for exe in [dir.join("Claude.exe"), dir.join("app").join("Claude.exe")] {
            if let Some(v) = read_pe_file_version(&exe) {
                pick_newer_version(&mut best, &v);
            }
        }
    }
    best
}

/// Detect installed ChatGPT / Codex Desktop MSIX version.
pub fn installed_codex_desktop_version() -> Option<String> {
    installed_msix_version("OpenAI.Codex_").or_else(|| installed_msix_version("OpenAI.ChatGPT_"))
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

        let pkg_json = home
            .join("AppData")
            .join("Roaming")
            .join("npm")
            .join("node_modules")
            .join("@anthropic-ai")
            .join("claude-code")
            .join("package.json");
        if let Some(v) = read_package_json_version(&pkg_json) {
            pick_newer_version(&mut best, &v);
        }

        let local_exe = home.join(".local").join("bin").join("claude.exe");
        if let Some(v) = read_pe_file_version(&local_exe) {
            pick_newer_version(&mut best, &v);
        }
    }
    best
}

/// Detect installed Claude Code CLI version across user homes.
pub fn installed_claude_code_version() -> Option<String> {
    installed_claude_code_version_in_homes(&user_home_dirs())
}

/// Testable detector reading newest installed `@openai/codex` / native `codex` CLI version.
pub fn installed_codex_cli_version_in_homes(homes: &[PathBuf]) -> Option<String> {
    let mut best = None;
    for home in homes {
        let pkg_json = home
            .join("AppData")
            .join("Roaming")
            .join("npm")
            .join("node_modules")
            .join("@openai")
            .join("codex")
            .join("package.json");
        if let Some(v) = read_package_json_version(&pkg_json) {
            pick_newer_version(&mut best, &v);
        }
        for bin_exe in [
            home.join(".local").join("bin").join("codex.exe"),
            home.join(".cargo").join("bin").join("codex.exe"),
        ] {
            if let Some(v) = read_pe_file_version(&bin_exe) {
                pick_newer_version(&mut best, &v);
            }
        }
    }
    best
}

/// Detect installed Codex CLI version across user homes.
pub fn installed_codex_cli_version() -> Option<String> {
    installed_codex_cli_version_in_homes(&user_home_dirs())
}

fn parse_app_update_url(yml_text: &str) -> Option<String> {
    for line in yml_text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("url:") {
            let clean = rest.trim().trim_matches(['"', '\'']).trim();
            if clean.starts_with("https://") || clean.starts_with("http://") {
                return Some(clean.trim_end_matches('/').to_string());
            }
        }
    }
    None
}

/// Testable detector returning `(ide_version, updater_base_url)` from Antigravity install roots.
pub fn installed_antigravity_ide_info_in_dirs(dirs: &[PathBuf]) -> (Option<String>, Option<String>) {
    let mut best_ver = None;
    let mut updater_url = None;

    for dir in dirs {
        if !dir.is_dir() {
            continue;
        }
        for exe_name in ["Antigravity.exe", "Antigravity IDE.exe"] {
            let exe = dir.join(exe_name);
            if let Some(v) = read_pe_file_version(&exe) {
                pick_newer_version(&mut best_ver, &v);
            }
        }
        if best_ver.is_none() {
            if let Some(v) =
                read_package_json_version(&dir.join("resources").join("app").join("package.json"))
            {
                pick_newer_version(&mut best_ver, &v);
            }
        }
        if best_ver.is_none() {
            if let Ok(raw) = std::fs::read_to_string(dir.join("version")) {
                pick_newer_version(&mut best_ver, &raw);
            }
        }
        if updater_url.is_none() {
            if let Ok(yml) =
                std::fs::read_to_string(dir.join("resources").join("app-update.yml"))
            {
                updater_url = parse_app_update_url(&yml);
            }
        }
    }
    (best_ver, updater_url)
}

/// Detect installed Antigravity client version (`Antigravity.exe` FileVersion / package.json) and its `app-update.yml` URL.
pub fn installed_antigravity_ide_info() -> (Option<String>, Option<String>) {
    installed_antigravity_ide_info_in_dirs(&antigravity_covered_dirs())
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

        let children_by_ppid = build_children_map(&self.procs);
        let mut queue: Vec<(u32, String, &'static str)> = Vec::new();
        let mut visited_pids: HashSet<u32> = HashSet::new();

        for p in &self.procs {
            if is_uninstaller_exe(&p.name_l) {
                continue;
            }
            if guard_claude && cli_agent_matches("claude-code", &p.name_l, &p.path_l, &p.cmd_l) {
                let label = "Claude Code".to_string();
                out.insert(p.pid, label.clone());
                if visited_pids.insert(p.pid) {
                    queue.push((p.pid, label, "claude"));
                }
                continue;
            }
            if guard_chatgpt && cli_agent_matches("codex", &p.name_l, &p.path_l, &p.cmd_l) {
                let label = "Codex CLI".to_string();
                out.insert(p.pid, label.clone());
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
                out.insert(p.pid, label.clone());
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
                out.insert(p.pid, label.clone());
                if visited_pids.insert(p.pid) {
                    queue.push((p.pid, label, "chatgpt"));
                }
                continue;
            }
            if guard_ag && is_antigravity_dir_proc(p, ag_dirs_l) {
                let label = gui_agent_name("antigravity").to_string();
                out.insert(p.pid, label.clone());
                if visited_pids.insert(p.pid) {
                    queue.push((p.pid, label, "antigravity"));
                }
            }
        }

        // Walk descendant trees across ALL guarded GUI & CLI processes (through cmd.exe & SCM services,
        // stopping at interactive user shells unless inside an agent's MSIX/install directory).
        while let Some((pid, label, owner_id)) = queue.pop() {
            let Some(kids) = children_by_ppid.get(&pid) else {
                continue;
            };
            for &child_idx in kids {
                let child = &self.procs[child_idx];
                if is_uninstaller_exe(&child.name_l) || is_any_cli_agent(child) {
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
                if !in_agent_dir && is_interactive_shell_or_terminal(&child.name_l) {
                    continue;
                }
                if visited_pids.insert(child.pid) {
                    queue.push((child.pid, label.clone(), owner_id));
                }
                if !matches!(child.name_l.as_str(), "cmd.exe" | "cmd" | "conhost.exe") {
                    out.entry(child.pid).or_insert_with(|| label.clone());
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
    if is_uninstaller_exe(&p.name_l) || is_any_cli_agent(p) {
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
    let claude_cli_orphans_all: HashSet<usize> = pick_cli_orphans("claude-code", &all_procs)
        .into_iter()
        .collect();
    let codex_cli_orphans_all: HashSet<usize> =
        pick_cli_orphans("codex", &all_procs).into_iter().collect();

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
        } else if is_any_cli_agent(p) {
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
            if !is_orphan && cli_agent_matches(cid, &info.name_l, &info.path_l, &info.cmd_l) {
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
        .map(|d| d.to_string_lossy().replace('/', "\\").to_ascii_lowercase())
        .collect()
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
                .map(|e| e.to_string_lossy().to_ascii_lowercase())
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
            inner.sys.refresh_processes();
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

fn terminate_identities_with_sysinfo(
    sys: &mut sysinfo::System,
    candidates: &[ProcessIdentity],
) -> VerifiedKillOutcome {
    use sysinfo::Pid;

    let sys_cell = std::cell::RefCell::new(sys);
    terminate_with_recheck(
        candidates,
        |pid_u32| {
            let mut s = sys_cell.borrow_mut();
            let pid = Pid::from_u32(pid_u32);
            s.refresh_process(pid);
            let p = s.process(pid)?;
            Some(ProcessIdentity {
                pid: pid_u32,
                start_time: p.start_time(),
                exe_path: p
                    .exe()
                    .map(|e| e.to_string_lossy().to_ascii_lowercase())
                    .unwrap_or_default(),
            })
        },
        |pid_u32| {
            sys_cell
                .borrow()
                .process(Pid::from_u32(pid_u32))
                .is_some_and(|p| p.kill())
        },
    )
}

/// Kill GUI process tree matching `agent_id` children-first (NEVER touches CLI processes,
/// SCM service hosts, or interactive user shells), re-verifying `(pid, start_time, exe_path)`
/// immediately before each kill.
pub fn kill_gui_agent(agent_id: &str) -> Vec<ProcessIdentity> {
    use sysinfo::System;

    let claude_dirs_l = dirs_to_lowercase(claude_covered_dirs());
    let chatgpt_dirs_l = dirs_to_lowercase(chatgpt_covered_dirs());
    let ag_dirs_l = dirs_to_lowercase(antigravity_covered_dirs());

    let mut sys = System::new();
    sys.refresh_processes();
    let procs = collect_sys_procs(&sys);

    let candidates = pick_gui_agent_kill_tree_with_dirs(
        agent_id,
        &procs,
        &claude_dirs_l,
        &chatgpt_dirs_l,
        &ag_dirs_l,
    );
    terminate_identities_with_sysinfo(&mut sys, &candidates).killed
}

/// Kill CLI session process tree matching `cli_id` (`claude-code`, `codex`, `gemini`)
/// children-first with PID-reuse identity re-verification (never touches ancestor terminals).
pub fn kill_cli_agent(cli_id: &str) -> Vec<ProcessIdentity> {
    use sysinfo::System;

    let mut sys = System::new();
    sys.refresh_processes();
    let procs = collect_sys_procs(&sys);

    let candidates = pick_cli_agent_kill_tree(cli_id, &procs);
    terminate_identities_with_sysinfo(&mut sys, &candidates).killed
}

/// Sweep Claude desktop residuals / orphan CLI processes with PID-reuse re-verification.
/// Never kills CLI processes attached to live terminals in `SweepMode::Residual`.
pub fn sweep_claude(mode: SweepMode) -> SweepReport {
    use sysinfo::{Pid, System};

    let claude_dir_l = claude_covered_dirs()
        .into_iter()
        .next()
        .map(|d| d.to_string_lossy().to_ascii_lowercase());
    let mut sys = System::new();
    sys.refresh_processes();
    let procs = collect_sys_procs(&sys);

    let picks = match mode {
        SweepMode::Manual => pick_manual(&procs, claude_dir_l.as_deref()),
        SweepMode::Residual => match pick_residual(&procs, claude_dir_l.as_deref()) {
            Some(v) => v,
            None => {
                return SweepReport {
                    scanned: pick_manual(&procs, claude_dir_l.as_deref()).len(),
                    note: "桌面端仍在运行，不清理".into(),
                    ..SweepReport::default()
                };
            }
        },
    };

    let mut report = SweepReport {
        scanned: picks.len(),
        ..SweepReport::default()
    };

    for (idx, kind) in picks {
        let info = &procs[idx];
        let expected = info.identity();
        let pid = Pid::from_u32(info.pid);
        sys.refresh_process(pid);
        let confirmed = sys.process(pid).is_some_and(|p| {
            let observed = ProcessIdentity {
                pid: info.pid,
                start_time: p.start_time(),
                exe_path: p
                    .exe()
                    .map(|e| e.to_string_lossy().to_ascii_lowercase())
                    .unwrap_or_default(),
            };
            same_identity(&expected, &observed)
        });
        if !confirmed {
            report.unconfirmed += 1;
            continue;
        }
        if let Some(p) = sys.process(pid) {
            if p.kill() {
                report.killed += 1;
                match kind {
                    ClaudeKind::Desktop => report.desktop_killed += 1,
                    ClaudeKind::Cli => report.cli_killed += 1,
                }
                report.detail.push(format!(
                    "pid={} {}（{}）",
                    info.pid,
                    info.name_l,
                    kind.label()
                ));
            }
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
            pick_cli_orphans("claude-code", procs),
            OrphanCategory::ClaudeCodeCli,
        ),
        (pick_cli_orphans("codex", procs), OrphanCategory::CodexCli),
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
/// `(pid, start_time, exe_path)` PID-reuse re-verification.
pub fn sweep_all_orphans() -> SweepReport {
    use sysinfo::System;

    let claude_dirs_l = dirs_to_lowercase(claude_covered_dirs());
    let chatgpt_dirs_l = dirs_to_lowercase(chatgpt_covered_dirs());
    let ag_dirs_l = dirs_to_lowercase(antigravity_covered_dirs());

    let mut sys = System::new();
    sys.refresh_processes();
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

    let outcome = terminate_identities_with_sysinfo(&mut sys, &candidates);
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
    use windows::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let mut seen = ClaudePresence::None;
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return ClaudePresence::Desktop;
        };
        if snap == INVALID_HANDLE_VALUE {
            return ClaudePresence::Desktop;
        }
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
                if name_l.contains("claude") && !is_agent_scm_service_exe(&name_l) {
                    let mut path_l = String::new();
                    if let Ok(handle) = OpenProcess(
                        PROCESS_QUERY_LIMITED_INFORMATION,
                        false,
                        entry.th32ProcessID,
                    ) {
                        let mut buf = [0u16; 1024];
                        let mut size = buf.len() as u32;
                        if QueryFullProcessImageNameW(
                            handle,
                            PROCESS_NAME_WIN32,
                            windows::core::PWSTR(buf.as_mut_ptr()),
                            &mut size,
                        )
                        .is_ok()
                        {
                            path_l = String::from_utf16_lossy(&buf[..size as usize])
                                .to_ascii_lowercase();
                        }
                        let _ = CloseHandle(handle);
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
        let _ = CloseHandle(snap);
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
    Executable { path: PathBuf, args: Vec<String> },
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
        LaunchTarget::Executable { path, args } => {
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

/// Launch a desktop app under the normal-privilege desktop shell token (`explorer.exe`).
#[cfg(windows)]
pub fn launch_normal_privilege(target: &LaunchTarget) -> PlatformResult<()> {
    let (program, args) = build_launch_command(target)?;
    std::process::Command::new(&program)
        .args(&args)
        .spawn()
        .map_err(|e| PlatformError::Io(format!("failed to launch {}: {e}", program.display())))?;
    Ok(())
}

#[cfg(not(windows))]
pub fn launch_normal_privilege(_target: &LaunchTarget) -> PlatformResult<()> {
    Err(PlatformError::unsupported(
        "launch_app",
        "Windows shell launcher is only supported on Windows",
    ))
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

        // Gemini CLI
        assert!(cli_agent_matches(
            "gemini",
            "node.exe",
            "",
            "node @google/gemini-cli/dist/index.js"
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
        for expected_pid in [100u32, 200, 202, 203, 204] {
            assert_eq!(
                pids.get(&expected_pid).map(String::as_str),
                Some("反重力"),
                "pid {expected_pid} must map to 反重力"
            );
        }
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
                "node antigravity-mcp.js",
            ),
        ];
        let orphans_a: Vec<u32> = pick_antigravity_orphans(&after_exit, &[ag_dir.to_string()])
            .into_iter()
            .map(|i| after_exit[i].pid)
            .collect();
        assert_eq!(orphans_a.len(), 5);
        assert!(!orphans_a.contains(&501));
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
        assert!(build_launch_command(&LaunchTarget::Executable {
            path: PathBuf::from(r"Z:\definitely\missing\app.exe"),
            args: vec![],
        })
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
        assert_eq!(pids_idle.get(&50).map(String::as_str), Some("Claude"));
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
        assert_eq!(pids.get(&110).map(String::as_str), Some("Claude"));
        assert_eq!(pids.get(&111).map(String::as_str), Some("Claude"));
        assert_eq!(pids.get(&200).map(String::as_str), Some("ChatGPT"));
        assert_eq!(pids.get(&201).map(String::as_str), Some("ChatGPT"));
        assert_eq!(pids.get(&202).map(String::as_str), Some("ChatGPT"));
        assert_eq!(pids.get(&301).map(String::as_str), Some("Claude Code"));
        assert_eq!(pids.get(&302).map(String::as_str), Some("Claude Code"));
        assert_eq!(pids.get(&400).map(String::as_str), Some("Codex CLI"));
        assert_eq!(pids.get(&401).map(String::as_str), Some("Codex CLI"));
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
        std::fs::write(npm_cc.join("package.json"), r#"{"name":"@anthropic-ai/claude-code","version":"2.1.284"}"#).unwrap();
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
        std::fs::write(npm_codex.join("package.json"), r#"{"name":"@openai/codex","version":"0.158.0"}"#).unwrap();
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
}
