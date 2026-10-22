//! macOS process adapter for upstream v3.5. Bundle-scoped GUI fingerprints,
//! standalone CLI fingerprints and PID/start-time checks before signalling.
//! Network quarantine is unavailable and always reported as such.
use std::path::{Path, PathBuf};
use std::process::Command;
pub struct GuiAgentDef {
    pub id: &'static str,
    pub name: &'static str,
}
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

// Claude Code participates in v3.5 explicit sweep/trip; other CLIs are only observed.
pub const CLI_AGENTS: &[(&str, &str)] = &[
    ("claude-code", "Claude Code"),
    ("codex", "Codex CLI"),
    ("gemini", "Gemini CLI"),
];

/// GUI 守护对象的 id 列表（config 的 guarded_agents 校验/清洗依赖它）。
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

/// 单个 GUI agent 的进程判定（纯函数，可单测）。
/// 入参统一小写；claude_dir_l 是 Claude 安装目录（v1 起的目录前缀口径）。
pub fn gui_agent_matches(id: &str, _name: &str, path: &str, _claude: Option<&str>) -> bool {
    let bundles: &[&str] = match id {
        "claude" => &["claude.app"],
        "chatgpt" => &["chatgpt.app", "codex.app"],
        "antigravity" => &["antigravity.app"],
        _ => return false,
    };
    // Require a complete bundle component and Contents boundary; never match bare process names.
    Path::new(path)
        .components()
        .zip(Path::new(path).components().skip(1))
        .any(|(a, b)| {
            bundles.iter().any(|bundle| a.as_os_str() == *bundle) && b.as_os_str() == "contents"
        })
}

pub fn cli_agent_matches(id: &str, name: &str, path: &str, cmd: &str) -> bool {
    // Bundled helpers belong to the GUI, never to standalone CLI sessions.
    if path.contains(".app/contents/") {
        return false;
    }
    match id {
        "claude-code" => {
            path.ends_with("/.local/bin/claude")
                || path.contains("/.local/share/claude/versions/")
                || cmd.contains("/node_modules/@anthropic-ai/claude-code/")
        }
        "codex" => name == "codex" || cmd.contains("/node_modules/@openai/codex/"),
        "gemini" => cmd.contains("/node_modules/@google/gemini-cli/"),
        _ => false,
    }
}

/// 一次进程表全量扫描：每个 GUI/CLI agent 的运行进程数（>0 才保留）。
/// 状态行与熔断判定共用，避免多次 refresh_processes。
pub struct AgentScan {
    pub gui: Vec<(&'static GuiAgentDef, usize)>,
    pub cli: Vec<(&'static str, usize)>,
}

pub fn scan_agents() -> AgentScan {
    use sysinfo::System;
    let claude_dir_l = find_claude_dir().map(|d| d.to_string_lossy().to_lowercase());
    let mut sys = System::new();
    sys.refresh_processes();
    let mut gui: Vec<(&'static GuiAgentDef, usize)> = GUI_AGENTS.iter().map(|a| (a, 0)).collect();
    let mut cli: Vec<(&'static str, usize)> = CLI_AGENTS.iter().map(|a| (a.0, 0)).collect();
    for p in sys.processes().values() {
        let name_l = p.name().to_string().to_lowercase();
        let path_l = p
            .exe()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        for (i, a) in GUI_AGENTS.iter().enumerate() {
            if gui_agent_matches(a.id, &name_l, &path_l, claude_dir_l.as_deref()) {
                gui[i].1 += 1;
            }
        }
        let cmd_l = p
            .cmd()
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase();
        for (i, (cid, _)) in CLI_AGENTS.iter().enumerate() {
            if cli_agent_matches(cid, &name_l, &path_l, &cmd_l) {
                cli[i].1 += 1;
            }
        }
    }
    AgentScan {
        gui: gui.into_iter().filter(|(_, n)| *n > 0).collect(),
        cli: cli.into_iter().filter(|(_, n)| *n > 0).collect(),
    }
}

/// 杀掉指定 agent 的全部进程，返回杀掉的进程数。
pub fn kill_agent(id: &str) -> usize {
    let killed = kill_matching(id, &snapshot_processes());
    if killed > 0 {
        log_line(&format!("kill_agent({id}): {killed} processes terminated"));
    }
    killed
}

// The caller supplies a snapshot; identity is refreshed immediately before each signal.
fn kill_matching(id: &str, processes: &[ProcInfo]) -> usize {
    processes
        .iter()
        .filter(|p| gui_agent_matches(id, &p.name_l, &p.path_l, None) && kill_verified(p))
        .count()
}

/// 按配置的守护对象逐个查杀（持续异常时的"只杀不加规则"路径）。
pub fn kill_agents(cfg: &crate::config::Config) -> usize {
    cfg.guarded_agents.iter().map(|id| kill_agent(id)).sum()
}

// ---------- Claude 进程清理（v3.2：熔断连 CLI、退出后清残留、一键全清） ----------

/// 进程快照里与清理判定相关的字段（统一小写）。
/// 清理的全部决策都在这份快照上做纯函数计算，方便单测。
pub struct ProcInfo {
    pub pid: u32,
    pub start_time: u64,
    pub executable: PathBuf,
    pub ppid: u32,
    pub name_l: String,
    pub path_l: String,
    pub cmd_l: String,
}

fn proc_info_of(p: &sysinfo::Process) -> ProcInfo {
    ProcInfo {
        pid: p.pid().as_u32(),
        start_time: p.start_time(),
        executable: p.exe().unwrap_or_else(|| Path::new("")).to_path_buf(),
        ppid: p.parent().map(|x| x.as_u32()).unwrap_or(0),
        name_l: p.name().to_string().to_lowercase(),
        path_l: p
            .exe()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default(),
        cmd_l: p
            .cmd()
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase(),
    }
}

pub fn snapshot_processes() -> Vec<ProcInfo> {
    use sysinfo::System;
    let mut sys = System::new();
    sys.refresh_processes();
    sys.processes().values().map(proc_info_of).collect()
}

/// Claude 进程分类：桌面端 / Claude Code CLI。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaudeKind {
    Desktop,
    Cli,
}

impl ClaudeKind {
    fn label(self) -> &'static str {
        match self {
            ClaudeKind::Desktop => "桌面端",
            ClaudeKind::Cli => "CLI",
        }
    }
}

pub fn classify_claude(p: &ProcInfo, claude_dir_l: Option<&str>) -> Option<ClaudeKind> {
    if cli_agent_matches("claude-code", &p.name_l, &p.path_l, &p.cmd_l) {
        return Some(ClaudeKind::Cli);
    }
    if gui_agent_matches("claude", &p.name_l, &p.path_l, claude_dir_l) {
        return Some(ClaudeKind::Desktop);
    }
    None
}

/// 全部 Claude 进程（桌面 + CLI，不管父子关系）。一键清理用。
pub fn pick_manual(procs: &[ProcInfo], claude_dir_l: Option<&str>) -> Vec<(usize, ClaudeKind)> {
    procs
        .iter()
        .enumerate()
        .filter_map(|(i, p)| classify_claude(p, claude_dir_l).map(|k| (i, k)))
        .collect()
}

/// 残留判定（纯函数）：桌面端全部消失后，哪些 Claude 进程算"残留"。
/// - 桌面家族进程：主进程不在了，剩下的 crashpad/gpu/renderer 全算残留；
/// - CLI：父进程已死（孤儿）才算残留——挂在活终端下的会话不清，避免误杀正在用的终端。
///
/// 返回 `None` 表示桌面端还在运行（不算退出，不清）。
pub fn pick_residual(
    procs: &[ProcInfo],
    claude_dir_l: Option<&str>,
) -> Option<Vec<(usize, ClaudeKind)>> {
    let all = pick_manual(procs, claude_dir_l);
    if all.iter().any(|(_, k)| *k == ClaudeKind::Desktop) {
        return None;
    }
    let alive: std::collections::HashSet<u32> = procs.iter().map(|p| p.pid).collect();
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

/// 清理模式：一键全清 / 仅 CLI（熔断路径）/ 桌面端退出后的残留清理。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepMode {
    Manual,
    CliOnly,
    Residual,
}

#[derive(Debug, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SweepReport {
    /// 扫描到的 Claude 进程数（residual 模式下是判定为残留的数量）
    pub scanned: usize,
    pub killed: usize,
    pub desktop_killed: usize,
    pub cli_killed: usize,
    /// 每条 "pid 名称（类型）"
    pub detail: Vec<String>,
    /// 特殊情况说明（桌面端仍在运行等），空串表示正常执行
    pub note: String,
}

/// 扫描并结束 Claude 进程。Manual = 桌面端 + CLI 全清；Residual = 仅残留（桌面家族 + 孤儿 CLI）。
pub fn sweep_claude(mode: SweepMode) -> SweepReport {
    use sysinfo::System;
    let claude_dir_l = find_claude_dir().map(|d| d.to_string_lossy().to_lowercase());
    let mut sys = System::new();
    sys.refresh_processes();
    let procs: Vec<ProcInfo> = sys.processes().values().map(proc_info_of).collect();
    let picks = match mode {
        SweepMode::Manual => pick_manual(&procs, claude_dir_l.as_deref()),
        SweepMode::CliOnly => pick_manual(&procs, claude_dir_l.as_deref())
            .into_iter()
            .filter(|(_, k)| *k == ClaudeKind::Cli)
            .collect(),
        SweepMode::Residual => match pick_residual(&procs, claude_dir_l.as_deref()) {
            Some(v) => v,
            None => {
                return SweepReport {
                    scanned: pick_manual(&procs, claude_dir_l.as_deref()).len(),
                    note: "桌面端仍在运行，不清理".into(),
                    ..SweepReport::default()
                }
            }
        },
    };
    let mut report = SweepReport {
        scanned: picks.len(),
        ..SweepReport::default()
    };
    for (i, kind) in picks {
        let info = &procs[i];
        if kill_verified(info) {
            report.killed += 1;
            match kind {
                ClaudeKind::Desktop => report.desktop_killed += 1,
                ClaudeKind::Cli => report.cli_killed += 1,
            }
            let line = format!("pid={} {}（{}）", info.pid, info.name_l, kind.label());
            report.detail.push(line.clone());
            log_line(&format!("sweep: killed {} {line}", kind.label()));
        }
    }
    report
}

/// 结束全部 Claude Code CLI 进程（熔断路径用），返回结束数。
pub fn kill_claude_cli() -> usize {
    sweep_claude(SweepMode::CliOnly).killed
}

pub fn log_line(msg: &str) {
    let dir = crate::config::config_dir();
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("guard.log");
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        use std::io::Write;
        let _ = writeln!(f, "{} {}", chrono_like_now(), msg);
    }
    // 日志上限：超过 1MB 就地裁剪到最近约 400KB（按行边界切，临时文件+rename 原子替换）。
    // 默认 15s 一检约 290KB/天，长期常驻机器几个月才会触发一次。
    let _ = trim_log_if_huge(&path, 1_000_000, 400_000);
}

/// 文件超过 `max_bytes` 时重写为最近 `keep_bytes` 的尾部（从完整行边界开始，
/// 最多回退到整文件）。小文件或读失败时原样保留。
fn trim_log_if_huge(
    path: &std::path::Path,
    max_bytes: u64,
    keep_bytes: usize,
) -> std::io::Result<()> {
    let len = std::fs::metadata(path)?.len();
    if len <= max_bytes {
        return Ok(());
    }
    let data = std::fs::read(path)?;
    // 找到保留起点：先跳到 (len - keep)，再前进到下一个换行，保证不切半行。
    let skip = data.len().saturating_sub(keep_bytes);
    let mut start = skip;
    if start > 0 {
        if let Some(nl) = data[start..].iter().position(|&b| b == b'\n') {
            start += nl + 1;
        } else {
            start = data.len(); // 尾部一行超长：宁可清空也不切半行
        }
    }
    let tmp = path.with_extension("log.tmp");
    std::fs::write(&tmp, &data[start..])?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn chrono_like_now() -> String {
    // 避免引入 chrono：用 PowerShell 太重，直接取系统时间戳格式化
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // 简单地返回 unix 秒 + 本地格式占位（egui 显示用各自时间）；日志用原始秒可读性够用
    format!("[{secs}]")
}

/// Refresh PID identity immediately before signalling to avoid stale snapshot/PID reuse.
fn kill_verified(info: &ProcInfo) -> bool {
    let mut sys = sysinfo::System::new();
    let pid = sysinfo::Pid::from_u32(info.pid);
    sys.refresh_process(pid);
    sys.process(pid).is_some_and(|p| {
        p.start_time() == info.start_time
            && p.exe() == Some(info.executable.as_path())
            && p.pid().as_u32() != std::process::id()
            && p.kill()
    })
}

pub fn find_claude_dir() -> Option<PathBuf> {
    let mut candidates = vec![PathBuf::from("/Applications/Claude.app")];
    if let Some(home) = std::env::var_os("HOME") {
        candidates.push(PathBuf::from(home).join("Applications/Claude.app"));
    }
    candidates
        .into_iter()
        .find(|p| p.join("Contents/MacOS/Claude").is_file())
}
pub fn resolve_app_id(_fallback: &str) -> String {
    "com.anthropic.claudefordesktop".into()
}
pub fn launch_claude(app_id: &str) -> Result<(), String> {
    let out = Command::new("/usr/bin/open")
        .args(["-b", app_id])
        .output()
        .map_err(|e| format!("无法启动 Claude：{e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err("macOS 未能启动 Claude，请确认已安装官方桌面端".into())
    }
}
pub fn is_admin() -> bool {
    false
} // This build neither requires nor requests root privileges.
pub fn firewall_release() -> bool {
    true
} // No rules are created by this build.
pub fn firewall_dedupe() -> usize {
    0
}

pub fn trip(cfg: &crate::config::Config, reason: &str) -> TripResult {
    let mut report = TripResult {
        agents: cfg
            .guarded_agents
            .iter()
            .map(|id| gui_agent_name(id).to_string())
            .collect(),
        ..TripResult::default()
    };
    log_line(&format!("TRIP: {reason}"));
    if cfg.kill_on_fail {
        report.killed = kill_agents(cfg);
        // v3.5 SPEC: Claude Code is included only when Claude is selected.
        if cfg.guarded_agents.iter().any(|id| id == "claude") {
            report.cli_killed = kill_claude_cli();
            report.killed += report.cli_killed;
        }
    }
    if cfg.quarantine_on_fail {
        log_line("macOS 按应用网络隔离未实现；未添加防火墙规则，不能阻止应用重新联网");
    }
    report
}
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct TripResult {
    pub killed: usize,
    /// 其中 Claude Code CLI 的进程数（v3.2 起熔断连 CLI 一起清）
    pub cli_killed: usize,
    pub firewall_rules: usize,
    pub quarantined: bool,
    /// 本次熔断涉及的 agent 显示名（UI 文案用）
    pub agents: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bundle_boundaries_exclude_namesakes_and_cli() {
        assert!(gui_agent_matches(
            "claude",
            "helper",
            "/applications/claude.app/contents/frameworks/helper",
            None
        ));
        assert!(gui_agent_matches(
            "chatgpt",
            "codex",
            "/applications/codex.app/contents/macos/codex",
            None
        ));
        assert!(!gui_agent_matches(
            "chatgpt",
            "codex",
            "/applications/codex.app-backup/contents/macos/codex",
            None
        ));
        for path in [
            "/tmp/claude",
            "/applications/claude.app.evil/contents/macos/claude",
            "/applications/claude.app-backup/contents/macos/claude",
            "/tmp/claude.app/other/tool",
        ] {
            assert!(!gui_agent_matches("claude", "claude", path, None));
        }
        assert!(!cli_agent_matches(
            "codex",
            "codex",
            "/applications/chatgpt.app/contents/macos/codex",
            ""
        ));
        assert!(cli_agent_matches(
            "claude-code",
            "claude",
            "/users/example/.local/share/claude/versions/1.0",
            ""
        ));
        assert!(!cli_agent_matches(
            "claude-code",
            "node",
            "/usr/local/bin/node",
            "node server.js"
        ));
    }
    #[test]
    fn selected_bundle_and_helpers_close_without_touching_other_apps() {
        let dir = tempfile::tempdir().unwrap();
        let mut children = Vec::new();
        for name in [
            "Claude.app/Contents/MacOS/main",
            "Claude.app/Contents/Frameworks/helper",
            "ChatGPT.app/Contents/MacOS/main",
            "Claude.app-backup/Contents/MacOS/main",
        ] {
            let exe = dir.path().join(name);
            std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
            std::fs::copy("/bin/sleep", &exe).unwrap();
            children.push(Command::new(exe).arg("30").spawn().unwrap());
        }
        // Only synthetic subprocess identities enter the production selector.
        let mut sys = sysinfo::System::new();
        let procs: Vec<_> = children
            .iter()
            .map(|child| {
                let pid = sysinfo::Pid::from_u32(child.id());
                sys.refresh_process(pid);
                proc_info_of(sys.process(pid).unwrap())
            })
            .collect();
        assert_eq!(kill_matching("claude", &procs), 2);
        for child in &mut children[..2] {
            assert!(!child.wait().unwrap().success());
        }
        for child in &mut children[2..] {
            assert!(child.try_wait().unwrap().is_none());
            child.kill().unwrap();
            child.wait().unwrap();
        }
        assert_eq!(kill_matching("claude", &procs), 0);
    }

    #[test]
    fn signals_only_the_expected_process_identity() {
        let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let mut sys = sysinfo::System::new();
        let pid = sysinfo::Pid::from_u32(child.id());
        sys.refresh_process(pid);
        let mut info = proc_info_of(sys.process(pid).unwrap());
        let actual = info.start_time;
        info.start_time = actual.wrapping_add(1);
        assert!(!kill_verified(&info));
        assert!(child.try_wait().unwrap().is_none());
        info.start_time = actual;
        assert!(kill_verified(&info));
        assert!(!child.wait().unwrap().success());
    }
}
