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

pub fn gui_agent_ids() -> Vec<&'static str> {
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
        "claude-code" => {
            cmd_l.contains(r"@anthropic-ai\claude-code")
                || exe_path_l.contains(r"\.local\bin\claude")
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

pub fn log_line(msg: &str) {
    let dir = crate::config::config_dir();
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("guard.log");
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        use std::io::Write;
        let _ = writeln!(f, "{} {}", chrono_like_now(), msg);
    }
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

/// 当前是否管理员（清单已 requireAdministrator，这里用于兜底显示）
pub fn is_admin() -> bool {
    Command::new(sys32("net.exe"))
        .args(["session"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// 启动 Claude（UWP）
pub fn launch_claude(app_id: &str) -> bool {
    let arg = format!("shell:AppsFolder\\{app_id}");
    let explorer = std::env::var("SystemRoot")
        .map(|r| PathBuf::from(r).join("explorer.exe"))
        .unwrap_or_else(|_| PathBuf::from(r"C:\Windows\explorer.exe"));
    let ok = Command::new(explorer)
        .arg(&arg)
        .spawn()
        .map(|_| true)
        .unwrap_or(false);
    log_line(&format!("launch claude ({app_id}): {ok}"));
    ok
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
    }
    if cfg.quarantine_on_fail {
        for id in &cfg.guarded_agents {
            res.firewall_rules += firewall_quarantine_agent(id);
        }
        res.quarantined = res.firewall_rules > 0 || firewall_active();
    }
    res
}

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct TripResult {
    pub killed: usize,
    pub firewall_rules: usize,
    pub quarantined: bool,
    /// 本次熔断涉及的 agent 显示名（UI 文案用）
    pub agents: Vec<String>,
}
