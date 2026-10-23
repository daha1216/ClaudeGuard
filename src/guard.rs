//! 熔断与隔离：agent 注册表、定位安装目录、杀进程、防火墙规则、启动 Claude。
//!
//! v2.7 起守护对象不止 Claude：GUI agent（可查杀+断网）与 CLI agent（只检测提醒）分开对待。

use std::path::{Path, PathBuf};
use std::process::Command;

pub const FW_RULE_OUT: &str = "ClaudeGuard Block Out";
pub const FW_RULE_IN: &str = "ClaudeGuard Block In";

/// GUI 守护对象注册表：熔断时查杀 + 断网隔离。
/// 指纹（2026-10 实机确认）：
/// - claude:     UWP 包 Claude_*（WindowsApps），安装目录任意 exe + claude.exe 兜底
/// - chatgpt:    UWP 包 OpenAI.Codex_*（ChatGPT 桌面版就用这个包名），主程序 app\ChatGPT.exe
/// - antigravity: 反重力两个安装形态——Electron 版 Antigravity.exe / IDE 版 "Antigravity IDE.exe"
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

/// CLI 守护对象（只检测 + 提醒，绝不杀进程）：
/// CLI 跑在 node/终端宿主里，按 exe 查杀会误伤终端和前端项目，防火墙也无粒度可拦。
/// 指纹：npm 全局布局的 js 路径 + 原生二进制名。
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
pub fn gui_agent_matches(
    id: &str,
    exe_name_l: &str,
    exe_path_l: &str,
    claude_dir_l: Option<&str>,
) -> bool {
    match id {
        "claude" => {
            // CLI 原生二进制也叫 claude.exe（claude-code 安装布局），先排除再按桌面端匹配
            if exe_path_l.contains(r"\claude\claude-code\")
                || exe_path_l.contains(r"\.local\bin\claude")
            {
                return false;
            }
            exe_name_l == "claude.exe"
                || claude_dir_l
                    .map(|d| exe_path_l.starts_with(d))
                    .unwrap_or(false)
        }
        "chatgpt" => {
            exe_name_l == "chatgpt.exe" && exe_path_l.contains(r"\windowsapps\openai.codex_")
        }
        "antigravity" => exe_name_l == "antigravity.exe" || exe_name_l == "antigravity ide.exe",
        _ => false,
    }
}

/// 单个 CLI agent 的判定（纯函数，可单测）。cmd_l 是命令行参数拼接（小写）。
pub fn cli_agent_matches(id: &str, exe_name_l: &str, exe_path_l: &str, cmd_l: &str) -> bool {
    match id {
        // npm: node …\npm\node_modules\@anthropic-ai\claude-code\cli.js；原生: …\.local\bin\claude.exe
        // 或新安装布局 %APPDATA%\Claude\claude-code\<ver>\<hash>\claude.exe（2026-10 实机确认）
        "claude-code" => {
            cmd_l.contains(r"@anthropic-ai\claude-code")
                || exe_path_l.contains(r"\.local\bin\claude")
                || exe_path_l.contains(r"\claude\claude-code\")
        }
        // 原生 codex*.exe（排除 ChatGPT 桌面版内置的 codex-command-runner）或 npm js
        "codex" => {
            (exe_name_l.starts_with("codex") && !exe_path_l.contains(r"\windowsapps\"))
                || cmd_l.contains(r"@openai\codex")
        }
        "gemini" => cmd_l.contains("gemini-cli"),
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
    use sysinfo::System;
    let claude_dir_l = find_claude_dir().map(|d| d.to_string_lossy().to_lowercase());
    let mut sys = System::new();
    sys.refresh_processes();
    let mut killed = 0usize;
    for (pid, proc) in sys.processes() {
        let name_l = proc.name().to_string().to_lowercase();
        let path_l = proc
            .exe()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        if gui_agent_matches(id, &name_l, &path_l, claude_dir_l.as_deref()) {
            let pidv: u32 = pid.as_u32();
            if proc.kill() {
                killed += 1;
                log_line(&format!("killed {id} process pid={pidv}"));
            }
        }
    }
    if killed > 0 {
        log_line(&format!("kill_agent({id}): {killed} processes terminated"));
    }
    killed
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
    pub ppid: u32,
    pub name_l: String,
    pub path_l: String,
    pub cmd_l: String,
}

fn proc_info_of(p: &sysinfo::Process) -> ProcInfo {
    ProcInfo {
        pid: p.pid().as_u32(),
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
        let Some(proc) = sys.process(sysinfo::Pid::from_u32(info.pid)) else {
            continue;
        };
        if proc.kill() {
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

/// 目录名版本段转数字序列：Claude_2.16120.0.0_x64__hash -> [2,16120,0,0]
/// 数字逐段比较，避免字典序 "2.9" > "2.10" 的错误。
fn version_key(name: &str) -> Vec<u64> {
    let seg = name.split('_').nth(1).unwrap_or("");
    seg.split('.')
        .map(|p| p.parse::<u64>().unwrap_or(0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 行为锁: 兜底封锁规则名按 agent 区分，与熔断隔离规则名互不冲突。
    #[test]
    fn lockdown_rule_names_are_scoped() {
        assert_eq!(
            lockdown_rule_name("claude"),
            "ClaudeGuard Lockdown (claude)"
        );
        assert_ne!(lockdown_rule_name("chatgpt"), lockdown_rule_name("claude"));
        // 熔断隔离规则沿用旧名（不带后缀），兜底封锁必须错开。
        let (q_out, q_in) = fw_names("claude");
        assert_ne!(lockdown_rule_name("claude"), q_out);
        assert_ne!(lockdown_rule_name("claude"), q_in);
    }

    /// 行为锁: 日志裁剪只在上限触发, 保留尾部完整行, 原子替换。
    #[test]
    fn trim_log_respects_cap_and_line_boundary() {
        let dir = std::env::temp_dir().join(format!("cg-trim-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("t.log");
        // 每行 10 字节, 写 300 行 = 3000B; cap=1000, keep=400 → 触发
        let mut body = String::new();
        for i in 0..300 {
            body.push_str(&format!("{:09}\n", i)); // 9 位数字+换行 = 10B
        }
        std::fs::write(&p, &body).unwrap();
        trim_log_if_huge(&p, 1000, 400).unwrap();
        let out = std::fs::read_to_string(&p).unwrap();
        assert!(out.len() <= 400, "裁剪后不超过 keep: {}", out.len());
        assert!(out.ends_with("299\n"), "尾部完整保留");
        assert!(
            out.starts_with(|c: char| c.is_ascii_digit()) && !out.starts_with('\n'),
            "从行首开始"
        );
        assert!(!out.contains("\n\n"), "没有切出半行(不会出现空行缝合)");
        let first: u64 = out.lines().next().unwrap().parse().unwrap();
        assert_eq!(
            first,
            300 - (out.len() / 10) as u64,
            "起点正好落在行边界(整行保留)"
        );
        // 小文件不动
        std::fs::write(&p, "short\n").unwrap();
        trim_log_if_huge(&p, 1000, 400).unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "short\n");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// 行为锁: 版本比较必须按数字段, 不许退回字典序。
    #[test]
    fn version_key_numeric_compare() {
        let v9 = version_key("Claude_2.9.0.0_x64__hash");
        let v10 = version_key("Claude_2.10.0.0_x64__hash");
        let v10b = version_key("Claude_2.10.1.0_x64__hash");
        let v3 = version_key("Claude_3.0.0.0_x64__hash");
        assert!(v10 > v9, "2.10 必须大于 2.9（字典序会判错）");
        assert!(v10b > v10);
        assert!(v3 > v10);
        assert_eq!(v9, vec![2, 9, 0, 0]);
        // 非常规目录名不 panic, 缺段按 0 处理
        assert_eq!(version_key("Claude___x"), vec![0]);
        assert_eq!(version_key("Claude"), vec![0]);
        assert_eq!(version_key("x_2.1_y"), vec![2, 1]);
        // OpenAI.Codex 包名（ChatGPT 桌面版）同一解析器可用
        assert_eq!(
            version_key("OpenAI.Codex_26.928.2636.0_x64__2p2nqsd0c76g0"),
            vec![26, 928, 2636, 0]
        );
    }

    /// 行为锁: GUI agent 进程指纹（2026-10 实机确认的路径/名称）。
    #[test]
    fn gui_agent_fingerprints() {
        let wa_claude =
            r"c:\program files\windowsapps\claude_2.16120.0.0_x64__pzs8sxrjxfjjc\claude.exe";
        assert!(gui_agent_matches("claude", "claude.exe", wa_claude, None));
        // Claude 安装目录下的其他 exe（目录前缀口径，v1 起沿用）
        assert!(gui_agent_matches(
            "claude",
            "anything.exe",
            r"c:\program files\windowsapps\claude_2.16120.0.0_x64__pzs8sxrjxfjjc\sub\tool.exe",
            Some(r"c:\program files\windowsapps\claude_2.16120.0.0_x64__pzs8sxrjxfjjc")
        ));
        assert!(!gui_agent_matches(
            "claude",
            "anything.exe",
            r"c:\program files\windowsapps\claude_2.16120.0.0_x64__pzs8sxrjxfjjc\sub\tool.exe",
            None
        ));
        // CLI 原生二进制（claude-code 安装布局 / .local\bin）不算桌面端，就算重名 claude.exe
        assert!(!gui_agent_matches(
            "claude",
            "claude.exe",
            r"c:\users\daha\appdata\roaming\claude\claude-code\2.1.304\abc123\claude.exe",
            None
        ));
        assert!(!gui_agent_matches(
            "claude",
            "claude.exe",
            r"c:\users\daha\.local\bin\claude.exe",
            None
        ));
        // chatgpt: 包名 OpenAI.Codex_* 下的 ChatGPT.exe；同名 exe 在别处不算
        let wa_gpt = r"c:\program files\windowsapps\openai.codex_26.928.2636.0_x64__2p2nqsd0c76g0\app\chatgpt.exe";
        assert!(gui_agent_matches("chatgpt", "chatgpt.exe", wa_gpt, None));
        assert!(!gui_agent_matches(
            "chatgpt",
            "chatgpt.exe",
            r"c:\temp\chatgpt.exe",
            None
        ));
        // 内置 runner 不是主程序，不按 GUI 进程杀（隔离规则仍会拦它的网络）
        assert!(!gui_agent_matches(
            "chatgpt",
            "codex-command-runner.exe",
            r"c:\program files\windowsapps\openai.codex_26.9_x\app\resources\codex-command-runner.exe",
            None
        ));
        // antigravity 两个安装形态
        assert!(gui_agent_matches(
            "antigravity",
            "antigravity.exe",
            r"c:\users\u\appdata\local\programs\antigravity\antigravity.exe",
            None
        ));
        assert!(gui_agent_matches(
            "antigravity",
            "antigravity ide.exe",
            r"c:\users\u\appdata\local\programs\antigravity ide\antigravity ide.exe",
            None
        ));
        // 卸载器不算
        assert!(!gui_agent_matches(
            "antigravity",
            "uninstall antigravity.exe",
            r"c:\users\u\appdata\local\programs\antigravity\uninstall antigravity.exe",
            None
        ));
        assert!(!gui_agent_matches("bogus", "x.exe", r"c:\x.exe", None));
    }

    /// 行为锁: CLI agent 指纹——npm js 路径 / 原生二进制；ChatGPT 内置 runner 不算 CLI。
    #[test]
    fn cli_agent_fingerprints() {
        let npm = r"c:\users\u\appdata\roaming\npm\node_modules\@anthropic-ai\claude-code\cli.js";
        assert!(cli_agent_matches(
            "claude-code",
            "node.exe",
            r"c:\program files\nodejs\node.exe",
            npm
        ));
        // 原生安装布局
        assert!(cli_agent_matches(
            "claude-code",
            "claude.exe",
            r"c:\users\u\.local\bin\claude.exe",
            ""
        ));
        // 原生 claude.exe 在别处不算（避免误伤同名）
        assert!(!cli_agent_matches(
            "claude-code",
            "claude.exe",
            r"c:\x\claude.exe",
            ""
        ));
        // 新安装布局：桌面端自带的 claude-code 原生二进制（2026-10 实机路径）
        assert!(cli_agent_matches(
            "claude-code",
            "claude.exe",
            r"c:\users\daha\appdata\roaming\claude\claude-code\2.1.304\9f4d5c\claude.exe",
            ""
        ));
        // codex 原生二进制
        assert!(cli_agent_matches(
            "codex",
            "codex-x86_64-pc-windows-msvc.exe",
            r"c:\users\u\.cargo\bin\codex-x86_64-pc-windows-msvc.exe",
            ""
        ));
        assert!(cli_agent_matches(
            "codex",
            "node.exe",
            "",
            r"node x @openai\codex\bin\codex.js"
        ));
        // ChatGPT 桌面版内置 runner：GUI 包内，不重复算 CLI
        assert!(!cli_agent_matches(
            "codex",
            "codex-command-runner.exe",
            r"c:\program files\windowsapps\openai.codex_26.9_x\app\resources\codex-command-runner.exe",
            ""
        ));
        assert!(cli_agent_matches(
            "gemini",
            "node.exe",
            "",
            r"node …\@google\gemini-cli\bin\gemini.js"
        ));
        assert!(!cli_agent_matches(
            "gemini",
            "node.exe",
            "",
            r"node server.js"
        ));
        assert!(!cli_agent_matches("bogus", "x.exe", "", ""));
    }

    /// 行为锁: 清理判定——桌面端在则不算退出；桌面家族全算残留；CLI 只清孤儿。
    #[test]
    fn sweep_picking_modes() {
        let mk = |pid: u32, ppid: u32, name: &str, path: &str| ProcInfo {
            pid,
            ppid,
            name_l: name.to_string(),
            path_l: path.to_string(),
            cmd_l: String::new(),
        };
        let wa_dir = r"c:\program files\windowsapps\claude_2.42304.0.0_x64__pzs8sxrjxfjjc";
        let wa = format!(r"{wa_dir}\claude.exe");
        let cli_native = r"c:\users\daha\appdata\roaming\claude\claude-code\2.1.304\abc\claude.exe";

        // 场景 1：桌面主进程 + crashpad + 终端里的 CLI（父=活终端）+ 桌面拉起的 CLI + 孤儿 CLI + 无关进程
        let procs = vec![
            mk(100, 50, "claude.exe", &wa),
            mk(101, 100, "crashpad_handler.exe", &wa),
            mk(102, 50, "claude.exe", cli_native),
            mk(103, 100, "claude.exe", cli_native),
            mk(50, 1, "windowsterminal.exe", r"c:\...\windowsterminal.exe"),
            mk(104, 9999, "claude.exe", cli_native),
            mk(105, 50, "node.exe", r"c:\program files\nodejs\node.exe"),
        ];
        // 桌面端在 → 不算退出，不清理
        assert!(pick_residual(&procs, Some(wa_dir)).is_none());
        // 一键全清 = 桌面 2 + CLI 3
        let manual = pick_manual(&procs, Some(wa_dir));
        assert_eq!(manual.len(), 5);
        assert_eq!(
            manual
                .iter()
                .filter(|(_, k)| *k == ClaudeKind::Desktop)
                .count(),
            2
        );

        // 场景 2：桌面已退出。终端里的 CLI（父活）不清；父已死的 CLI 清。
        let procs2 = vec![
            mk(102, 50, "claude.exe", cli_native),
            mk(103, 100, "claude.exe", cli_native),
            mk(104, 9999, "claude.exe", cli_native),
            mk(50, 1, "windowsterminal.exe", r"c:\...\windowsterminal.exe"),
        ];
        let residual = pick_residual(&procs2, Some(wa_dir)).expect("桌面已退出应给出残留清单");
        let ids: Vec<u32> = residual.iter().map(|(i, _)| procs2[*i].pid).collect();
        assert_eq!(ids, vec![103, 104], "活终端下的 CLI 不清，孤儿/桌面遗孤清");
    }

    /// 行为锁: 防火墙规则名——claude 用 v1 老名（存量规则识别），其他带后缀。
    #[test]
    fn fw_names_claude_legacy() {
        assert_eq!(fw_names("claude"), (FW_RULE_OUT.into(), FW_RULE_IN.into()));
        assert_eq!(
            fw_names("chatgpt"),
            (
                "ClaudeGuard Block Out (chatgpt)".into(),
                "ClaudeGuard Block In (chatgpt)".into()
            )
        );
    }

    /// 行为锁: GUI 守护对象注册表 = 契约要求的三个 id（config.clean_guarded 依赖）。
    #[test]
    fn agent_ids_match_contract() {
        assert_eq!(agent_ids(), vec!["claude", "chatgpt", "antigravity"]);
        assert_eq!(agent_ids().len(), GUI_AGENTS.len());
        // 显示名与兜底：未知 id 原样返回（UI 仍能展示）
        assert_eq!(gui_agent_name("antigravity"), "反重力");
        assert_eq!(gui_agent_name("unknown"), "unknown");
    }

    /// 行为锁: 同名同程序的重复隔离规则只保留第一条实例，其余按实例 Name 返回。
    #[test]
    fn dedupes_duplicate_firewall_rule_instances() {
        let json = r#"[
            {"name":"{a}","display":"ClaudeGuard Block Out","program":"C:\\Apps\\A.exe"},
            {"name":"{b}","display":"ClaudeGuard Block Out","program":"c:\\apps\\a.EXE"},
            {"name":"{c}","display":"ClaudeGuard Block Out","program":"C:\\Apps\\B.exe"},
            {"name":"{d}","display":"ClaudeGuard Block In","program":"C:\\Apps\\A.exe"}
        ]"#;
        let rules = parse_rule_instances(json);
        assert_eq!(rules.len(), 4);
        assert_eq!(duplicate_rule_instances(&rules), vec!["{b}"]);

        // 单条输出是对象、多条是数组；空/null/非法都不 panic
        let single =
            r#"{"name":"{x}","display":"ClaudeGuard Block Out","program":"C:\\Apps\\A.exe"}"#;
        let one = parse_rule_instances(single);
        assert_eq!(one.len(), 1);
        assert!(duplicate_rule_instances(&one).is_empty());
        assert!(parse_rule_instances("").is_empty());
        assert!(parse_rule_instances("null").is_empty());
        assert!(parse_rule_instances("not json").is_empty());
        // 没有 Name 的实例没法定点删除，跳过而不是整组误删
        let missing = r#"[
            {"display":"ClaudeGuard Block Out","program":"C:\\A.exe"},
            {"display":"ClaudeGuard Block Out","program":"C:\\A.exe"}
        ]"#;
        assert!(duplicate_rule_instances(&parse_rule_instances(missing)).is_empty());
    }

    /// 行为锁: PowerShell 的 base64/UTF-8 回传按 UTF-8 解码（中文网卡名/路径不坏）。
    #[test]
    fn decodes_base64_powershell_output() {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        let json = r#"["WLAN","以太网"]"#;
        let encoded = STANDARD.encode(json.as_bytes());
        assert_eq!(decode_b64_text(&encoded).as_deref(), Some(json));
        // 允许空白/末尾换行（PowerShell 输出风格）
        assert_eq!(
            decode_b64_text(&format!(" {encoded}\n")),
            Some(json.to_string())
        );
        assert!(decode_b64_text("").is_none());
        assert!(decode_b64_text("   \n").is_none());
        assert!(decode_b64_text("不是 base64").is_none());
    }
}

/// 定位 WindowsApps 下指定前缀的安装目录（版本数值最大者）。
/// Claude_ → Claude 桌面端；OpenAI.Codex_ → ChatGPT 桌面版（OpenAI 用这个包名发 ChatGPT）。
fn find_windowsapps_dir(prefix: &str) -> Option<PathBuf> {
    let root = Path::new(r"C:\Program Files\WindowsApps");
    let mut best: Option<(Vec<u64>, std::ffi::OsString)> = None;
    if let Ok(rd) = std::fs::read_dir(root) {
        for entry in rd.flatten() {
            let s = entry.file_name().to_string_lossy().to_string();
            if s.starts_with(prefix) && s.contains("__") {
                let key = version_key(&s);
                let better = match &best {
                    Some((k, _)) => key > *k,
                    None => true,
                };
                if better {
                    best = Some((key, entry.file_name()));
                }
            }
        }
    }
    best.map(|(_, n)| root.join(n))
}

pub fn find_claude_dir() -> Option<PathBuf> {
    find_windowsapps_dir("Claude_")
}

/// ChatGPT 桌面版安装目录（UWP 包 OpenAI.Codex_*）
pub fn find_chatgpt_dir() -> Option<PathBuf> {
    find_windowsapps_dir("OpenAI.Codex_")
}

/// Claude_2.16120.0.0_x64__pzs8sxrjxfjjc -> Claude_pzs8sxrjxfjjc
pub fn family_name_from_dir(dir: &Path) -> Option<String> {
    let name = dir.file_name()?.to_string_lossy().to_string();
    let (pkg, hash) = name.split_once("__")?;
    // pkg = Claude_2.16120.0.0_x64 -> Claude
    let base = pkg.split('_').next()?.to_string();
    Some(format!("{base}_{hash}"))
}

pub fn resolve_app_id(fallback: &str) -> String {
    if let Some(dir) = find_claude_dir() {
        if let Some(family) = family_name_from_dir(&dir) {
            return format!("{family}!Claude");
        }
    }
    fallback.to_string()
}

/// 收集目录下的 exe（递归，限深 3）
fn collect_exes(dir: &Path, depth: u32, out: &mut Vec<PathBuf>) {
    if depth > 3 {
        return;
    }
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                collect_exes(&p, depth + 1, out);
            } else if p
                .extension()
                .map(|x| x.eq_ignore_ascii_case("exe"))
                .unwrap_or(false)
            {
                out.push(p);
            }
        }
    }
}

/// System32 下系统工具的绝对路径（本进程以管理员运行，避免 PATH/应用目录搜索提权面）。
/// name 可含子路径，如 r"WindowsPowerShell\v1.0\powershell.exe"。
pub(crate) fn sys32(name: &str) -> PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    PathBuf::from(root).join("System32").join(name)
}

/// CREATE_NO_WINDOW：GUI 进程（无控制台）拉起控制台子进程时不弹黑框。
pub(crate) const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// 相对 System32 的 Windows PowerShell 5.1 路径（cmdlet 只在 5.1 上有保证）。
pub(crate) const POWERSHELL: &str = r"WindowsPowerShell\v1.0\powershell.exe";

/// 起隐藏窗口的子进程并收集输出（绝对路径调用，不走相对路径搜索）。
pub(crate) fn run_hidden(exe: &Path, args: &[&str]) -> std::io::Result<std::process::Output> {
    use std::os::windows::process::CommandExt;
    Command::new(exe)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
}

/// 纯函数：解码 PowerShell 回传的 base64/UTF-8 文本。
///
/// Windows PowerShell 5.1 把中文写到被重定向的 stdout 时按控制台代码页编码，
/// 直接按 UTF-8 读会乱码（中文网卡名、用户名路径都会中招），所以 PowerShell 侧
/// 统一先 `[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(...))` 再输出。
pub(crate) fn decode_b64_text(text: &str) -> Option<String> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.is_empty() {
        return None;
    }
    let bytes = STANDARD.decode(compact.as_bytes()).ok()?;
    String::from_utf8(bytes).ok()
}

fn netsh(args: &[&str]) -> bool {
    Command::new(sys32("netsh.exe"))
        .args(args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// agent 的防火墙规则名。claude 沿用 v1 老名（已装用户的存量规则靠它识别），
/// 其他 agent 带后缀，避免跨 agent 误删。
fn fw_names(id: &str) -> (String, String) {
    match id {
        "claude" => (FW_RULE_OUT.into(), FW_RULE_IN.into()),
        other => (
            format!("{FW_RULE_OUT} ({other})"),
            format!("{FW_RULE_IN} ({other})"),
        ),
    }
}

/// agent 的可执行文件集合（隔离规则按 exe 粒度添加）。
/// - claude / chatgpt: 安装目录全量 exe（含内置 runner，如 ChatGPT 的 codex-command-runner）
/// - antigravity: 两个已知安装位置的主程序（不收 Uninstall*.exe）
fn agent_exes(id: &str) -> Vec<PathBuf> {
    let mut exes = Vec::new();
    match id {
        "claude" => {
            if let Some(dir) = find_claude_dir() {
                collect_exes(&dir, 0, &mut exes);
            }
        }
        "chatgpt" => {
            if let Some(dir) = find_chatgpt_dir() {
                collect_exes(&dir, 0, &mut exes);
            }
        }
        "antigravity" => {
            if let Ok(local) = std::env::var("LOCALAPPDATA") {
                let base = PathBuf::from(local).join("Programs");
                for (sub, exe) in [
                    ("antigravity", "Antigravity.exe"),
                    ("Antigravity IDE", "Antigravity IDE.exe"),
                ] {
                    let p = base.join(sub).join(exe);
                    if p.is_file() {
                        exes.push(p);
                    }
                }
            }
        }
        _ => {}
    }
    exes
}

/// 防火墙隔离：为指定 agent 的全部 exe 添加出入站 Block 规则。返回出站规则添加数。
pub fn firewall_quarantine_agent(id: &str) -> usize {
    let exes = agent_exes(id);
    if exes.is_empty() {
        log_line(&format!("quarantine({id}): no exes found"));
        return 0;
    }
    let (name_out, name_in) = fw_names(id);
    log_line(&format!("quarantine({id}): {} exes", exes.len()));
    let mut added = 0usize;
    for exe in exes {
        let p = exe.to_string_lossy().to_string();
        if netsh(&[
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={name_out}"),
            "dir=out",
            "action=block",
            "enable=yes",
            &format!("program={p}"),
        ]) {
            added += 1;
        }
        let _ = netsh(&[
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={name_in}"),
            "dir=in",
            "action=block",
            "enable=yes",
            &format!("program={p}"),
        ]);
    }
    log_line(&format!("quarantine({id}): {added} outbound rules added"));
    added
}

/// 解除单个 agent 的隔离规则
pub fn firewall_release_agent(id: &str) -> bool {
    let (name_out, name_in) = fw_names(id);
    let a = netsh(&[
        "advfirewall",
        "firewall",
        "delete",
        "rule",
        &format!("name={name_out}"),
    ]);
    let b = netsh(&[
        "advfirewall",
        "firewall",
        "delete",
        "rule",
        &format!("name={name_in}"),
    ]);
    log_line(&format!("firewall release({id}): out={a} in={b}"));
    a || b
}

/// 解除全部 agent 的隔离规则（通过即恢复 / 托盘手动解除共用）
pub fn firewall_release() -> bool {
    let mut any = false;
    for a in GUI_AGENTS {
        if firewall_release_agent(a.id) {
            any = true;
        }
    }
    any
}

/// 是否存在任何 ClaudeGuard 隔离规则
pub fn firewall_active() -> bool {
    let check = |name: &str| {
        Command::new(sys32("netsh.exe"))
            .args([
                "advfirewall",
                "firewall",
                "show",
                "rule",
                &format!("name={name}"),
            ])
            .output()
            .map(|o| {
                let text = String::from_utf8_lossy(&o.stdout);
                text.contains(name) && !text.trim().is_empty()
            })
            .unwrap_or(false)
    };
    GUI_AGENTS.iter().any(|a| {
        let (o, i) = fw_names(a.id);
        check(&o) || check(&i)
    })
}

/// 一条防火墙规则实例。`Get-NetFirewallRule` 的 Name 是实例 ID（GUID），
/// DisplayName 才是规则显示名；按实例 Name 删才不会把同名规则整组误删。
#[derive(Debug, serde::Deserialize)]
struct FwRuleInstance {
    #[serde(default)]
    name: String,
    #[serde(default)]
    display: String,
    #[serde(default)]
    program: String,
}

/// `Get-NetFirewallRule ... | ConvertTo-Json`：单条输出对象，多条输出数组。
#[derive(serde::Deserialize)]
#[serde(untagged)]
enum RuleList {
    One(FwRuleInstance),
    Many(Vec<FwRuleInstance>),
}

/// 纯函数：解析规则实例 JSON（空/null/非法输入返回空）。
fn parse_rule_instances(text: &str) -> Vec<FwRuleInstance> {
    let text = text.trim();
    if text.is_empty() || text.eq_ignore_ascii_case("null") {
        return Vec::new();
    }
    match serde_json::from_str::<RuleList>(text) {
        Ok(RuleList::One(rule)) => vec![rule],
        Ok(RuleList::Many(rules)) => rules,
        Err(_) => Vec::new(),
    }
}

/// 纯函数：同一 (显示名, 程序) 的重复规则实例只保留第一条，返回其余实例的 Name。
/// v2 每次熔断都 `netsh add rule`，持续失败会让同名规则越积越多。
fn duplicate_rule_instances(rules: &[FwRuleInstance]) -> Vec<String> {
    let mut seen: Vec<(String, String)> = Vec::new();
    let mut duplicates: Vec<String> = Vec::new();
    for rule in rules {
        let name = rule.name.trim();
        if name.is_empty() {
            continue;
        }
        let key = (
            rule.display.trim().to_ascii_lowercase(),
            rule.program.trim().to_ascii_lowercase(),
        );
        if seen.contains(&key) {
            duplicates.push(name.to_string());
        } else {
            seen.push(key);
        }
    }
    duplicates
}

/// 枚举 ClaudeGuard 隔离规则并删掉同名重复实例，返回删除的实例数。
///
/// netsh 按名字删会整组删掉，没法只删多余实例，所以走 PowerShell 拿实例 GUID（Name）
/// 后用 `Remove-NetFirewallRule -Name` 精确删；失败（非管理员等）时返回 0，不影响熔断。
pub fn firewall_dedupe() -> usize {
    let script = r"$rules = @(Get-NetFirewallRule -DisplayName 'ClaudeGuard*' -ErrorAction SilentlyContinue | ForEach-Object { $app = $_ | Get-NetFirewallApplicationFilter; [pscustomobject]@{ name = $_.Name; display = $_.DisplayName; program = [string]$app.Program } }); if ($rules.Count -gt 0) { $json = $rules | ConvertTo-Json -Compress } else { $json = '[]' }; [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$json))";
    let out = match run_hidden(
        &sys32(POWERSHELL),
        &["-NoProfile", "-NonInteractive", "-Command", script],
    ) {
        Ok(out) => out,
        Err(err) => {
            log_line(&format!("firewall_dedupe: 无法启动 PowerShell（{err}）"));
            return 0;
        }
    };
    if !out.status.success() {
        log_line(&format!(
            "firewall_dedupe: 枚举规则失败（exit={:?}）",
            out.status.code()
        ));
        return 0;
    }
    let raw = String::from_utf8_lossy(&out.stdout).to_string();
    let text = decode_b64_text(&raw).unwrap_or(raw);
    let duplicates = duplicate_rule_instances(&parse_rule_instances(&text));
    if duplicates.is_empty() {
        return 0;
    }
    let quoted: Vec<String> = duplicates
        .iter()
        .map(|name| format!("'{}'", name.replace('\'', "''")))
        .collect();
    let script = format!(
        "Remove-NetFirewallRule -Name {} -ErrorAction Stop",
        quoted.join(",")
    );
    let removed = run_hidden(
        &sys32(POWERSHELL),
        &["-NoProfile", "-NonInteractive", "-Command", &script],
    )
    .map(|out| out.status.success())
    .unwrap_or(false);
    if removed {
        log_line(&format!(
            "firewall_dedupe: 删除重复隔离规则 {} 条",
            duplicates.len()
        ));
        duplicates.len()
    } else {
        log_line("firewall_dedupe: 删除重复规则失败");
        0
    }
}

/// 当前是否管理员（清单已 requireAdministrator，这里用于兜底显示）
pub fn is_admin() -> bool {
    Command::new(sys32("net.exe"))
        .args(["session"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// 检查当前账户的包状态并提交 Claude 启动请求；成功不代表应用已激活。
pub fn launch_claude(app_id: &str) -> Result<(), String> {
    crate::claude_update::check_claude_launch_ready()?;
    let arg = format!("shell:AppsFolder\\{app_id}");
    let explorer = std::env::var("SystemRoot")
        .map(|r| PathBuf::from(r).join("explorer.exe"))
        .unwrap_or_else(|_| PathBuf::from(r"C:\Windows\explorer.exe"));
    Command::new(explorer)
        .arg(&arg)
        .spawn()
        .map_err(|e| format!("无法向 Windows 发送 Claude 启动请求：{e}"))?;
    log_line(&format!("launch claude ({app_id}): request submitted"));
    Ok(())
}

/// 熔断：按配置的守护对象逐个杀进程 + 防火墙隔离（按配置开关）。
/// CLI agent 不在此列——它们只检测提醒，绝不杀。
pub fn trip(cfg: &crate::config::Config, reason: &str) -> TripResult {
    let mut res = TripResult::default();
    log_line(&format!("TRIP: {reason}"));
    res.agents = cfg
        .guarded_agents
        .iter()
        .map(|id| gui_agent_name(id).to_string())
        .collect();
    if cfg.kill_on_fail {
        for id in &cfg.guarded_agents {
            res.killed += kill_agent(id);
        }
        // v3.2：Claude 是守护对象时，Claude Code CLI 一并结束（不再只提醒）
        if cfg.guarded_agents.iter().any(|id| id == "claude") {
            res.cli_killed = kill_claude_cli();
            res.killed += res.cli_killed;
        }
    }
    if cfg.quarantine_on_fail {
        // v3.9：防火墙整体关着时 Block 规则不生效（实测踩过），隔离前先确保开启。
        fw_ensure_on();
        for id in &cfg.guarded_agents {
            res.firewall_rules += firewall_quarantine_agent(id);
        }
        res.quarantined = res.firewall_rules > 0 || firewall_active();
    }
    res
}

// ---------- v3.9 防火墙兜底封锁 ----------

/// 兜底封锁规则名前缀（与熔断隔离规则分开管理：隔离随熔断加/解除，兜底随接入状态维持）。
pub const LOCKDOWN_RULE: &str = "ClaudeGuard Lockdown";

fn lockdown_rule_name(id: &str) -> String {
    format!("{LOCKDOWN_RULE} ({id})")
}

/// 确保 Windows 防火墙处于开启。默认出站策略是"允许"，开启不影响正常流量；
/// 但防火墙整体关着时一切 Block 规则都是摆设（2026-10 实测用户机器三档全关）。
/// 只开不关——不逆向改用户的防火墙状态。
pub fn fw_ensure_on() -> bool {
    let out = Command::new(sys32("netsh.exe"))
        .args(["advfirewall", "show", "allprofiles", "state"])
        .output();
    let text = out
        .map(|o| String::from_utf8_lossy(&o.stdout).to_lowercase())
        .unwrap_or_default();
    if text.split_whitespace().any(|w| w == "off") {
        let ok = netsh(&["advfirewall", "set", "allprofiles", "state", "on"]);
        log_line(if ok {
            "firewall: 检测到 Windows 防火墙未开启，已自动开启（默认出站=允许，不影响正常流量）"
        } else {
            "firewall: 尝试开启 Windows 防火墙失败，Block 规则可能不生效"
        });
        return ok;
    }
    true
}

/// 一键兜底封锁：为全部守护对象的 exe 添加出站 Block 规则。
/// 回环（127.0.0.1 系统代理）不受 Windows 防火墙过滤，代理模式照常可用；
/// 直连/TUN 流量被拦。返回添加的规则数。
pub fn lockdown_apply(cfg: &crate::config::Config) -> usize {
    fw_ensure_on();
    let mut added = 0usize;
    for id in &cfg.guarded_agents {
        let name = lockdown_rule_name(id);
        for exe in agent_exes(id) {
            if netsh(&[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={name}"),
                "dir=out",
                "action=block",
                "enable=yes",
                &format!("program={}", exe.to_string_lossy()),
            ]) {
                added += 1;
            }
        }
    }
    log_line(&format!("lockdown: {added} outbound block rules added"));
    added
}

/// 解除全部兜底封锁规则（防火墙本身保持开启）。返回是否删到规则。
pub fn lockdown_clear() -> bool {
    let mut any = false;
    for a in GUI_AGENTS {
        if netsh(&[
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={}", lockdown_rule_name(a.id)),
        ]) {
            any = true;
        }
    }
    log_line(&format!("lockdown: cleared={any}"));
    any
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
