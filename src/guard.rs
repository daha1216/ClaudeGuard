//! 熔断与隔离：定位 Claude、杀进程、防火墙规则、启动 Claude。

use std::path::{Path, PathBuf};
use std::process::Command;

pub const FW_RULE_OUT: &str = "ClaudeGuard Block Out";
pub const FW_RULE_IN: &str = "ClaudeGuard Block In";

pub fn log_line(msg: &str) {
    let dir = crate::config::config_dir();
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("guard.log");
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
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

/// 定位 Claude 安装目录（WindowsApps 下 Claude_ 开头，取字典序最大的版本）
pub fn find_claude_dir() -> Option<PathBuf> {
    let root = Path::new(r"C:\Program Files\WindowsApps");
    let mut best: Option<std::ffi::OsString> = None;
    if let Ok(rd) = std::fs::read_dir(root) {
        for entry in rd.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("Claude_") && name.contains("__") {
                let prev = best.take();
                best = match prev {
                    Some(p) if p.to_string_lossy() >= name => Some(p),
                    _ => Some(entry.file_name()),
                };
            }
        }
    }
    best.map(|n| root.join(n))
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
            } else if p.extension().map(|x| x.eq_ignore_ascii_case("exe")).unwrap_or(false) {
                out.push(p);
            }
        }
    }
}

/// 杀掉所有 Claude 进程（按安装目录路径匹配 + 进程名兜底），返回杀掉的进程数
pub fn kill_claude() -> usize {
    use sysinfo::{Pid, System};
    let dir = find_claude_dir();
    let dir_s = dir.as_ref().map(|d| d.to_string_lossy().to_lowercase());
    let mut sys = System::new();
    sys.refresh_processes();
    let mut killed = 0usize;
    for (pid, proc) in sys.processes() {
        let exe_match = proc
            .exe()
            .map(|p| {
                let s = p.to_string_lossy().to_lowercase();
                dir_s.as_ref().map(|d| s.starts_with(d.as_str())).unwrap_or(false)
                    || (s.contains(r"\windowsapps\claude_") && s.ends_with("claude.exe"))
            })
            .unwrap_or(false);
        let name_match = proc.name().eq_ignore_ascii_case("claude.exe");
        if exe_match || name_match {
            let pidv: u32 = pid.as_u32();
            if proc.kill() {
                killed += 1;
                log_line(&format!("killed claude process pid={pidv}"));
            }
        }
        let _ = Pid::from_u32(0); // 保持 import
    }
    if killed > 0 {
        log_line(&format!("kill_claude: {killed} processes terminated"));
    }
    killed
}

fn netsh(args: &[&str]) -> bool {
    Command::new("netsh")
        .args(args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// 防火墙隔离：为 Claude 全部 exe 添加出入站 Block 规则。返回添加的规则数。
pub fn firewall_quarantine() -> usize {
    let Some(dir) = find_claude_dir() else {
        log_line("quarantine: claude dir not found");
        return 0;
    };
    let mut exes = Vec::new();
    collect_exes(&dir, 0, &mut exes);
    let mut added = 0usize;
    log_line(&format!("quarantine: {} exes under {}", exes.len(), dir.display()));
    for exe in exes {
        let p = exe.to_string_lossy().to_string();
        if netsh(&[
            "advfirewall", "firewall", "add", "rule",
            &format!("name={FW_RULE_OUT}"),
            "dir=out", "action=block", "enable=yes", &format!("program={p}"),
        ]) {
            added += 1;
        }
        let _ = netsh(&[
            "advfirewall", "firewall", "add", "rule",
            &format!("name={FW_RULE_IN}"),
            "dir=in", "action=block", "enable=yes", &format!("program={p}"),
        ]);
    }
    log_line(&format!("quarantine: {added} outbound rules added"));
    added
}

/// 解除隔离：删除全部 ClaudeGuard 规则
pub fn firewall_release() -> bool {
    let a = netsh(&["advfirewall", "firewall", "delete", "rule", &format!("name={FW_RULE_OUT}")]);
    let b = netsh(&["advfirewall", "firewall", "delete", "rule", &format!("name={FW_RULE_IN}")]);
    log_line(&format!("firewall release: out={a} in={b}"));
    a || b
}

/// 是否存在 ClaudeGuard 规则
pub fn firewall_active() -> bool {
    let check = |name: &str| {
        Command::new("netsh")
            .args(["advfirewall", "firewall", "show", "rule", &format!("name={name}")])
            .output()
            .map(|o| {
                let text = String::from_utf8_lossy(&o.stdout);
                text.contains(name) && !text.trim().is_empty()
            })
            .unwrap_or(false)
    };
    check(FW_RULE_OUT) || check(FW_RULE_IN)
}

/// 当前是否管理员（清单已 requireAdministrator，这里用于兜底显示）
pub fn is_admin() -> bool {
    Command::new("net")
        .args(["session"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// 启动 Claude（UWP）
pub fn launch_claude(app_id: &str) -> bool {
    let arg = format!("shell:AppsFolder\\{app_id}");
    let ok = Command::new("explorer.exe")
        .arg(&arg)
        .spawn()
        .map(|_| true)
        .unwrap_or(false);
    log_line(&format!("launch claude ({app_id}): {ok}"));
    ok
}

/// 熔断：杀进程 + 防火墙隔离（按配置开关）
pub fn trip(cfg: &crate::config::Config, reason: &str) -> TripResult {
    let mut res = TripResult::default();
    log_line(&format!("TRIP: {reason}"));
    if cfg.kill_on_fail {
        res.killed = kill_claude();
    }
    if cfg.quarantine_on_fail {
        res.firewall_rules = firewall_quarantine();
        res.quarantined = res.firewall_rules > 0 || firewall_active();
    }
    res
}

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct TripResult {
    pub killed: usize,
    pub firewall_rules: usize,
    pub quarantined: bool,
}
