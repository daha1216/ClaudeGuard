//! 断网执行：防火墙全局阻断 / 禁用物理网卡，以及断网状态的持久化与启动自愈。
//!
//! 两个档位都先加满防火墙规则 `CUT_RULE`（Nics 档再加一步禁用网卡）：
//! 规则是最后一道闸，恢复网卡的过程中网络仍被规则挡着，避免出现"断网真空"。
//! 现场落在 `%APPDATA%\ClaudeGuard\netcut.json`，进程崩溃/被杀后下次启动由 `heal()` 恢复。

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::guard::{decode_b64_text, log_line, run_hidden, sys32};
use crate::model::{now, CutMode};

/// 断网防火墙规则名（monitor/自愈也按这个名字找规则）。
pub const CUT_RULE: &str = "ClaudeGuard Cut All";

/// 启用中的物理网卡列表。PowerShell 输出 base64/UTF-8：
/// Windows PowerShell 5.1 写被重定向的 stdout 时按控制台代码页编码，中文网卡名会被转坏。
const NIC_ENUM_SCRIPT: &str = r"$json = @(Get-NetAdapter -Physical | Where-Object {$_.Status -eq 'Up'} | Select-Object -ExpandProperty Name) | ConvertTo-Json -Compress; [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$json))";

/// 串行化 cut/restore/heal：monitor 线程与退出恢复可能同时进来，
/// 交错执行会重复禁用/漏恢复网卡。heal 持同一把锁调用 `restore_locked`，避免重入死锁。
static LOCK: Mutex<()> = Mutex::new(());

/// netcut.json：崩溃恢复所需的断网现场（字段名即对外契约）。
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct CutState {
    /// "firewall" | "nics"
    mode: String,
    /// 防火墙全局阻断规则是否已加上
    firewall: bool,
    /// 断网前处于启用状态的物理网卡名（记录的是初始状态，恢复时逐个 Enable）
    nics: Vec<String>,
    /// 断网开始时间（unix 秒）
    since: u64,
}

/// 按档位断网。Off 档是 no-op；重复调用同一档位幂等。
pub fn cut(mode: CutMode) -> (bool, String) {
    if mode == CutMode::Off {
        return (true, "断网档位为关闭".to_string());
    }
    with_lock(|| cut_locked(mode))
}

/// 恢复网络：删规则 + 重新启用 netcut.json 里记录的网卡 + 删状态文件。可重复调用。
pub fn restore() -> (bool, String) {
    with_lock(restore_locked)
}

/// 启动自愈：恢复上次残留的断网现场、清理孤儿/重复规则，返回执行过的动作描述。
pub fn heal() -> Vec<String> {
    with_lock(heal_locked)
}

/// 当前生效的断网档位（读状态文件，没有断网现场时返回 None）。
/// 契约接口：StateView/UI 读取断网状态用，monitor 尚未接线。
#[allow(dead_code)]
pub fn active() -> Option<CutMode> {
    let state = load_state_from(&state_path())?;
    parse_mode(&state.mode)
}

/// 当前是否处于断网状态。
/// 契约接口：StateView/UI 读取断网状态用，monitor 尚未接线。
#[allow(dead_code)]
pub fn is_cut() -> bool {
    active().is_some()
}

/// 纯函数：解析 `Get-NetAdapter ... | ConvertTo-Json` 的网卡名列表。
/// ConvertTo-Json 单元素输出字符串、多元素输出数组；空/`null`/非法输入返回空。
/// 保留顺序、去首尾空白、大小写不敏感去重（中文名原样保留）。
pub fn parse_nic_json(text: &str) -> Vec<String> {
    let text = text.trim().trim_start_matches('\u{feff}').trim();
    if text.is_empty() || text.eq_ignore_ascii_case("null") {
        return Vec::new();
    }
    let value: serde_json::Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(_) => return Vec::new(),
    };
    let names: Vec<String> = match value {
        serde_json::Value::String(name) => vec![name],
        serde_json::Value::Array(items) => items
            .into_iter()
            .filter_map(|item| item.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    };
    let mut out: Vec<String> = Vec::new();
    for name in names {
        let name = name.trim().to_string();
        if name.is_empty() || out.iter().any(|seen| seen.eq_ignore_ascii_case(&name)) {
            continue;
        }
        out.push(name);
    }
    out
}

/// 纯函数：netsh 规则列表输出里出现 `rule`（ASCII 规则名）的行数。
/// netsh 输出随系统语言本地化（"规则名称" / "Rule Name"），只能按规则名本身计数；
/// 规则名是 ASCII，中文标签段即使被控制台代码页弄乱也不影响这里的匹配。
pub fn count_rule_in_listing(text: &str, rule: &str) -> usize {
    if rule.trim().is_empty() {
        return 0;
    }
    text.lines().filter(|line| line.contains(rule)).count()
}

/// 纯函数：把任意字符串变成 PowerShell 单引号字面量（内部单引号翻倍），
/// 网卡名拼进命令时不会被注入。
pub fn ps_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn mode_name(mode: CutMode) -> &'static str {
    match mode {
        CutMode::Off => "off",
        CutMode::Firewall => "firewall",
        CutMode::Nics => "nics",
    }
}

#[allow(dead_code)]
fn parse_mode(name: &str) -> Option<CutMode> {
    match name {
        "firewall" => Some(CutMode::Firewall),
        "nics" => Some(CutMode::Nics),
        _ => None,
    }
}

fn with_lock<F: FnOnce() -> T, T>(f: F) -> T {
    let _guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    f()
}

fn state_path() -> PathBuf {
    crate::config::config_dir().join("netcut.json")
}

fn cut_locked(mode: CutMode) -> (bool, String) {
    let path = state_path();
    let previous = load_state_from(&path);
    // 同档位重复断网（monitor 重试/配置没变）：沿用已有现场，不重复禁用网卡。
    if let Some(state) = previous.as_ref() {
        if state.mode == mode_name(mode) && state.firewall {
            let _ = delete_cut_rule();
            let (firewall_ok, detail) = add_cut_rule();
            let msg = if firewall_ok {
                "断网仍生效".to_string()
            } else {
                format!("重新添加防火墙规则失败：{detail}")
            };
            log_line(&format!("netcut: cut({}) 重复确认 -> {msg}", mode.label()));
            return (firewall_ok, msg);
        }
        // 档位变化：先完整恢复旧档位，再按新档位断网，避免两种阻断手段叠加。
        let _ = restore_locked();
    }
    let mut notes: Vec<String> = Vec::new();
    let (firewall_ok, firewall_detail) = add_cut_rule();
    if !firewall_ok {
        notes.push(format!("防火墙全局阻断失败：{firewall_detail}"));
    }
    let mut nics: Vec<String> = Vec::new();
    if mode == CutMode::Nics {
        // 已断网时重新枚举会看到 0 个 Up 网卡，优先沿用状态文件里记录的初始网卡。
        let recorded = previous
            .as_ref()
            .filter(|state| state.mode == mode_name(mode) && !state.nics.is_empty())
            .map(|state| state.nics.clone());
        let names = recorded.unwrap_or_else(list_up_nics);
        if names.is_empty() {
            notes.push("未找到启用中的物理网卡".to_string());
        }
        for name in &names {
            if disable_nic(name) {
                nics.push(name.clone());
            } else {
                notes.push(format!("禁用网卡失败：{name}"));
            }
        }
    }
    let engaged = firewall_ok || !nics.is_empty();
    if !engaged {
        notes.push("断网未生效，请确认以管理员身份运行".to_string());
        let msg = notes.join("；");
        log_line(&format!("netcut: cut({}) 失败 -> {msg}", mode.label()));
        return (false, msg);
    }
    let state = CutState {
        mode: mode_name(mode).to_string(),
        firewall: firewall_ok,
        nics: nics.clone(),
        since: now(),
    };
    // 现场写不下去就回滚：没有 netcut.json 的话，进程一崩网络就永久断着。
    if !save_state_to(&path, &state) {
        for name in &nics {
            let _ = enable_nic(name);
        }
        let _ = delete_cut_rule();
        let msg = "断网状态记录写入失败，已回滚断网".to_string();
        log_line(&format!("netcut: cut({}) -> {msg}", mode.label()));
        return (false, msg);
    }
    let mut msg = if mode == CutMode::Nics {
        format!("已禁用 {} 个物理网卡", nics.len())
    } else {
        "已启用防火墙全局阻断".to_string()
    };
    if mode == CutMode::Nics && nics.is_empty() {
        msg = "物理网卡禁用未生效，仅剩防火墙全局阻断".to_string();
    }
    if !notes.is_empty() {
        msg.push('；');
        msg.push_str(&notes.join("；"));
    }
    log_line(&format!("netcut: cut({}) -> {msg}", mode.label()));
    (true, msg)
}

fn restore_locked() -> (bool, String) {
    let path = state_path();
    let state_exists = path.exists();
    let state = load_state_from(&path);
    let mut actions: Vec<String> = Vec::new();
    let mut nics_ok = true;
    if let Some(state) = state.as_ref() {
        // 先恢复网卡、最后删规则：恢复过程中网络仍受规则管着。
        for name in &state.nics {
            if enable_nic(name) {
                actions.push(format!("已启用网卡 {name}"));
            } else {
                nics_ok = false;
                actions.push(format!("启用网卡失败：{name}"));
            }
        }
    }
    let (rule_ok, detail) = delete_cut_rule();
    if !detail.is_empty() {
        if rule_ok {
            actions.push("已删除断网防火墙规则".to_string());
        } else {
            actions.push(format!("删除断网防火墙规则失败：{detail}"));
        }
    }
    let ok = nics_ok && rule_ok;
    if state_exists {
        // 有失败就保留现场，下次启动自愈重试；否则删干净。
        if ok {
            match std::fs::remove_file(&path) {
                Ok(()) => actions.push("已清理断网状态记录".to_string()),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => actions.push(format!("清理断网状态记录失败：{err}")),
            }
        } else {
            actions.push("断网状态记录保留，下次启动自愈会重试".to_string());
        }
    }
    if actions.is_empty() {
        return (true, "未发现断网残留".to_string());
    }
    let msg = actions.join("；");
    log_line(&format!("netcut: restore -> {msg}"));
    (ok, msg)
}

fn heal_locked() -> Vec<String> {
    let mut actions: Vec<String> = Vec::new();
    let path = state_path();
    if path.exists() {
        let (_ok, msg) = restore_locked();
        let line = format!("检测到上次熔断残留，已恢复网络（{msg}）");
        log_line(&format!("netcut: {line}"));
        actions.push(line);
    }
    let duplicates = dedupe_cut_rules();
    if duplicates > 0 {
        actions.push(format!("清理重复断网规则 {duplicates} 份"));
    }
    let (removed, detail) = delete_cut_rule();
    if !detail.is_empty() {
        if removed {
            actions.push("清理了孤儿断网防火墙规则".to_string());
        } else {
            actions.push(format!("清理孤儿断网规则失败：{detail}"));
        }
    }
    let deduped = crate::guard::firewall_dedupe();
    if deduped > 0 {
        actions.push(format!("清理重复隔离规则 {deduped} 条"));
    }
    if !actions.is_empty() {
        log_line(&format!("netcut: self-heal {}", actions.join("；")));
    }
    actions
}

/// 同名断网规则多于一份时整组删除（heal 阶段还没有新断网，删光安全），返回重复份数。
fn dedupe_cut_rules() -> usize {
    let count = cut_rule_count();
    if count <= 1 {
        return 0;
    }
    let name_arg = format!("name={CUT_RULE}");
    if netsh(&["advfirewall", "firewall", "delete", "rule", &name_arg]).0 {
        log_line(&format!("netcut: 清理重复断网规则 {} 份", count - 1));
        count - 1
    } else {
        0
    }
}

fn save_state_to(path: &Path, state: &CutState) -> bool {
    let json = match serde_json::to_vec(state) {
        Ok(json) => json,
        Err(err) => {
            log_line(&format!("netcut: 断网状态序列化失败（{err}）"));
            return false;
        }
    };
    if let Some(dir) = path.parent() {
        if let Err(err) = std::fs::create_dir_all(dir) {
            log_line(&format!("netcut: 创建断网状态目录失败（{err}）"));
            return false;
        }
    }
    let tmp = path.with_extension("json.tmp");
    if let Err(err) = std::fs::write(&tmp, &json) {
        log_line(&format!("netcut: 写入断网状态失败（{err}）"));
        return false;
    }
    if let Err(err) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        log_line(&format!("netcut: 提交断网状态失败（{err}）"));
        return false;
    }
    true
}

fn load_state_from(path: &Path) -> Option<CutState> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return None,
        Err(err) => {
            log_line(&format!("netcut: 读取断网状态失败（{err}）"));
            return None;
        }
    };
    match serde_json::from_str(&text) {
        Ok(state) => Some(state),
        Err(err) => {
            log_line(&format!("netcut: 断网状态文件损坏（{err}）"));
            None
        }
    }
}

fn netsh(args: &[&str]) -> (bool, String) {
    run("netsh.exe", args)
}

fn add_cut_rule() -> (bool, String) {
    let name_arg = format!("name={CUT_RULE}");
    netsh(&[
        "advfirewall",
        "firewall",
        "add",
        "rule",
        &name_arg,
        "dir=out",
        "action=block",
        "profile=any",
        "enable=yes",
    ])
}

fn delete_cut_rule() -> (bool, String) {
    if cut_rule_count() == 0 {
        return (true, String::new());
    }
    let name_arg = format!("name={CUT_RULE}");
    let (ok, detail) = netsh(&["advfirewall", "firewall", "delete", "rule", &name_arg]);
    (ok || is_no_match(&detail), detail)
}

fn cut_rule_count() -> usize {
    let name_arg = format!("name={CUT_RULE}");
    let (ok, detail) = netsh(&["advfirewall", "firewall", "show", "rule", &name_arg]);
    if !ok && is_no_match(&detail) {
        return 0;
    }
    count_rule_in_listing(&detail, CUT_RULE)
}

/// netsh 找不到规则时的提示。中文 Windows 的提示是 GBK 编码，按 UTF-8 lossy 读出来是乱码，
/// 所以中文串只在纯函数单测里有效；实际幂等主要靠删前先用 `show` 计数。
fn is_no_match(detail: &str) -> bool {
    let detail = detail.to_ascii_lowercase();
    detail.contains("no rules match") || detail.contains("没有与指定条件")
}

/// 执行 PowerShell 命令（输出走 log_line），返回 (成功, 输出)。
fn powershell(script: &str) -> (bool, String) {
    run(
        crate::guard::POWERSHELL,
        &["-NoProfile", "-NonInteractive", "-Command", script],
    )
}

fn list_up_nics() -> Vec<String> {
    let (ok, raw) = powershell(NIC_ENUM_SCRIPT);
    if !ok {
        return Vec::new();
    }
    let json = decode_b64_text(&raw).unwrap_or(raw);
    let names = parse_nic_json(&json);
    log_line(&format!("netcut: 启用中的物理网卡 {}", names.join(", ")));
    names
}

fn set_nic_enabled(name: &str, enabled: bool) -> bool {
    let verb = if enabled {
        "Enable-NetAdapter"
    } else {
        "Disable-NetAdapter"
    };
    let script = format!(
        "{verb} -Name {} -Confirm:$false -ErrorAction Stop",
        ps_literal(name)
    );
    powershell(&script).0
}

fn disable_nic(name: &str) -> bool {
    set_nic_enabled(name, false)
}

fn enable_nic(name: &str) -> bool {
    set_nic_enabled(name, true)
}

fn run(exe_name: &str, args: &[&str]) -> (bool, String) {
    let exe = sys32(exe_name);
    match run_hidden(&exe, args) {
        Ok(out) => {
            let mut detail = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            if !err.is_empty() {
                if !detail.is_empty() {
                    detail.push(' ');
                }
                detail.push_str(&err);
            }
            let detail = shorten(&detail, 300);
            log_line(&format!(
                "netcut: {exe_name} {} -> exit={} {detail}",
                shorten(&args.join(" "), 400),
                out.status.code().unwrap_or(-1)
            ));
            (out.status.success(), detail)
        }
        Err(err) => {
            log_line(&format!("netcut: 无法启动 {exe_name}（{err}）"));
            (false, format!("无法启动 {exe_name}：{err}"))
        }
    }
}

fn shorten(text: &str, max_chars: usize) -> String {
    let text = text.trim();
    let mut chars = text.chars();
    let head: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{head}…")
    } else {
        head
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 行为锁: netcut.json 字段名/形状是对外契约（monitor/自愈依赖），并能原子往返。
    #[test]
    fn state_roundtrip_and_json_shape() {
        let state = CutState {
            mode: "firewall".to_string(),
            firewall: true,
            nics: vec!["WLAN".to_string()],
            since: 42,
        };
        let json = serde_json::to_value(&state).unwrap();
        assert_eq!(json["mode"], "firewall");
        assert_eq!(json["firewall"], true);
        assert_eq!(json["nics"][0], "WLAN");
        assert_eq!(json["since"], 42);

        let dir = std::env::temp_dir().join(format!("cg-netcut-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("netcut.json");
        assert!(save_state_to(&path, &state));
        assert_eq!(load_state_from(&path), Some(state));
        // 重复写（覆盖）也走原子替换
        let second = CutState {
            mode: "nics".to_string(),
            firewall: true,
            nics: vec!["以太网".to_string()],
            since: 43,
        };
        assert!(save_state_to(&path, &second));
        assert_eq!(load_state_from(&path), Some(second));
        std::fs::remove_file(&path).unwrap();
        assert_eq!(load_state_from(&path), None);
        // 损坏的状态文件不能让启动自愈 panic
        std::fs::write(&path, "not json").unwrap();
        assert_eq!(load_state_from(&path), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// 行为锁: 网卡 JSON 的两种形态（单字符串/数组）与脏输入。
    #[test]
    fn parses_nic_json_single_and_array() {
        assert_eq!(parse_nic_json(r#""WLAN""#), vec!["WLAN"]);
        assert_eq!(
            parse_nic_json(r#"["WLAN","以太网"]"#),
            vec!["WLAN", "以太网"]
        );
        assert_eq!(parse_nic_json(r#"[" WLAN ", "wlan", ""]"#), vec!["WLAN"]);
        assert_eq!(parse_nic_json(r#"["WLAN",null,3]"#), vec!["WLAN"]);
        assert_eq!(parse_nic_json("\u{feff}[\"WLAN\"]"), vec!["WLAN"]);
        assert_eq!(parse_nic_json("[]"), Vec::<String>::new());
        assert_eq!(parse_nic_json("null"), Vec::<String>::new());
        assert_eq!(parse_nic_json(""), Vec::<String>::new());
        assert_eq!(parse_nic_json("   "), Vec::<String>::new());
        assert_eq!(parse_nic_json("不是 JSON"), Vec::<String>::new());
        assert_eq!(parse_nic_json("123"), Vec::<String>::new());
    }

    /// 行为锁: netsh 输出按行数规则名（中英文标签都能数），精确匹配规则名。
    #[test]
    fn counts_cut_rule_in_netsh_listing() {
        let rule = "ClaudeGuard Cut All";
        assert_eq!(CUT_RULE, rule);
        let cn = "规则名称:                             ClaudeGuard Cut All\n\
                  ----------------------------------------------------------------------\n";
        assert_eq!(count_rule_in_listing(cn, rule), 1);
        let en = "Rule Name:                            ClaudeGuard Cut All\n";
        assert_eq!(count_rule_in_listing(en, rule), 1);
        assert_eq!(count_rule_in_listing(&format!("{cn}{cn}"), rule), 2);
        assert_eq!(
            count_rule_in_listing("No rules match the specified criteria.", rule),
            0
        );
        assert_eq!(count_rule_in_listing("", rule), 0);
        assert_eq!(count_rule_in_listing(cn, ""), 0);
    }

    /// 行为锁: 网卡名拼进 PowerShell 前必须按单引号字面量转义。
    #[test]
    fn quotes_powershell_literals() {
        assert_eq!(ps_literal("WLAN"), "'WLAN'");
        assert_eq!(ps_literal("O'Brien"), "'O''Brien'");
        assert_eq!(ps_literal(""), "''");
        assert_eq!(ps_literal("$(Remove-Item C:\\)"), "'$(Remove-Item C:\\)'");
    }

    /// 行为锁: 找不到规则提示的识别（英文为准，中文串兜底）。
    #[test]
    fn detects_netsh_no_match_text() {
        assert!(is_no_match("No rules match the specified criteria."));
        assert!(is_no_match("没有与指定条件匹配的规则。"));
        assert!(!is_no_match("Ok."));
        assert!(!is_no_match(""));
    }

    /// 行为锁: 状态文件里的 mode 字面量与 CutMode 的映射（monitor 读 CutMode 用）。
    #[test]
    fn mode_names_roundtrip() {
        assert_eq!(mode_name(CutMode::Firewall), "firewall");
        assert_eq!(mode_name(CutMode::Nics), "nics");
        assert_eq!(mode_name(CutMode::Off), "off");
        assert_eq!(parse_mode("firewall"), Some(CutMode::Firewall));
        assert_eq!(parse_mode("nics"), Some(CutMode::Nics));
        assert_eq!(parse_mode("off"), None);
        assert_eq!(parse_mode("bogus"), None);
    }

    /// 行为锁: 截断只在超长时发生，且按字符边界（中文不切坏）。
    #[test]
    fn shortens_without_splitting_chars() {
        assert_eq!(shorten("abc", 10), "abc");
        assert_eq!(shorten("  abc  ", 10), "abc");
        assert_eq!(shorten("abcdef", 3), "abc…");
        assert_eq!(shorten("中文网卡名", 2), "中文…");
    }
}
