//! 熔断与隔离：定位 Claude、杀进程、防火墙规则、启动 Claude。

use std::path::{Path, PathBuf};
use std::process::Command;

pub const FW_RULE_OUT: &str = "ClaudeGuard Block Out";
pub const FW_RULE_IN: &str = "ClaudeGuard Block In";

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
    }
}

/// 定位 Claude 安装目录（WindowsApps 下 Claude_ 开头，版本数值最大者）
pub fn find_claude_dir() -> Option<PathBuf> {
    let root = Path::new(r"C:\Program Files\WindowsApps");
    let mut best: Option<(Vec<u64>, std::ffi::OsString)> = None;
    if let Ok(rd) = std::fs::read_dir(root) {
        for entry in rd.flatten() {
            let s = entry.file_name().to_string_lossy().to_string();
            if s.starts_with("Claude_") && s.contains("__") {
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

/// 与 kill_claude 同一口径的 Claude 进程判定（安装目录前缀 + WindowsApps 兜底 + 进程名）
fn is_claude_proc(proc: &sysinfo::Process, dir_s: &Option<String>) -> bool {
    let exe_match = proc
        .exe()
        .map(|p| {
            let s = p.to_string_lossy().to_lowercase();
            dir_s
                .as_ref()
                .map(|d| s.starts_with(d.as_str()))
                .unwrap_or(false)
                || (s.contains(r"\windowsapps\claude_") && s.ends_with("claude.exe"))
        })
        .unwrap_or(false);
    exe_match || proc.name().eq_ignore_ascii_case("claude.exe")
}

/// Claude 桌面端是否在运行（状态行展示用；不含杀进程副作用）
pub fn claude_running() -> bool {
    use sysinfo::System;
    let dir = find_claude_dir();
    let dir_s = dir.as_ref().map(|d| d.to_string_lossy().to_lowercase());
    let mut sys = System::new();
    sys.refresh_processes();
    sys.processes()
        .iter()
        .any(|(_, p)| is_claude_proc(p, &dir_s))
}

/// 杀掉所有 Claude 进程（按安装目录路径匹配 + 进程名兜底），返回杀掉的进程数
pub fn kill_claude() -> usize {
    use sysinfo::System;
    let dir = find_claude_dir();
    let dir_s = dir.as_ref().map(|d| d.to_string_lossy().to_lowercase());
    let mut sys = System::new();
    sys.refresh_processes();
    let mut killed = 0usize;
    for (pid, proc) in sys.processes() {
        if is_claude_proc(proc, &dir_s) {
            let pidv: u32 = pid.as_u32();
            if proc.kill() {
                killed += 1;
                log_line(&format!("killed claude process pid={pidv}"));
            }
        }
    }
    if killed > 0 {
        log_line(&format!("kill_claude: {killed} processes terminated"));
    }
    killed
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

/// 防火墙隔离：为 Claude 全部 exe 添加出入站 Block 规则。返回添加的规则数。
pub fn firewall_quarantine() -> usize {
    let Some(dir) = find_claude_dir() else {
        log_line("quarantine: claude dir not found");
        return 0;
    };
    let mut exes = Vec::new();
    collect_exes(&dir, 0, &mut exes);
    let mut added = 0usize;
    log_line(&format!(
        "quarantine: {} exes under {}",
        exes.len(),
        dir.display()
    ));
    for exe in exes {
        let p = exe.to_string_lossy().to_string();
        if netsh(&[
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={FW_RULE_OUT}"),
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
            &format!("name={FW_RULE_IN}"),
            "dir=in",
            "action=block",
            "enable=yes",
            &format!("program={p}"),
        ]);
    }
    log_line(&format!("quarantine: {added} outbound rules added"));
    added
}

/// 解除隔离：删除全部 ClaudeGuard 规则
pub fn firewall_release() -> bool {
    let a = netsh(&[
        "advfirewall",
        "firewall",
        "delete",
        "rule",
        &format!("name={FW_RULE_OUT}"),
    ]);
    let b = netsh(&[
        "advfirewall",
        "firewall",
        "delete",
        "rule",
        &format!("name={FW_RULE_IN}"),
    ]);
    log_line(&format!("firewall release: out={a} in={b}"));
    a || b
}

/// 是否存在 ClaudeGuard 规则
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
    check(FW_RULE_OUT) || check(FW_RULE_IN)
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
