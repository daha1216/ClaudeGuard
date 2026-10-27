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

/// 启用中的物理网卡（GUID + 名称）。PowerShell 输出 base64/UTF-8：
/// Windows PowerShell 5.1 写被重定向的 stdout 时按控制台代码页编码，中文网卡名会被转坏。
const NIC_ENUM_SCRIPT: &str = r"$json = @(Get-NetAdapter -Physical | Where-Object {$_.Status -eq 'Up'} | Select-Object InterfaceGuid,Name) | ConvertTo-Json -Compress; [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$json))";

/// 网卡身份：GUID 是稳定标识（名称可能变、也不唯一），名称只用于展示。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NicRef {
    pub guid: String,
    pub name: String,
}

/// 纯函数：解析网卡列表 JSON，兼容两种历史形态：
/// - 新形态 `[{"InterfaceGuid":"…","Name":"以太网"}]`
/// - 旧形态 `["以太网"]`（只有名称，GUID 留空，恢复时按名称兜底）
pub fn parse_nic_refs(text: &str) -> Vec<NicRef> {
    let text = text.trim().trim_start_matches('\u{feff}').trim();
    if text.is_empty() || text.eq_ignore_ascii_case("null") {
        return Vec::new();
    }
    let value: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let items: Vec<serde_json::Value> = match value {
        serde_json::Value::Array(items) => items,
        other => vec![other],
    };
    let mut out: Vec<NicRef> = Vec::new();
    for item in items {
        let nic = match item {
            serde_json::Value::String(name) => NicRef {
                guid: String::new(),
                name: name.trim().to_string(),
            },
            serde_json::Value::Object(map) => {
                let guid = map
                    .get("InterfaceGuid")
                    .or_else(|| map.get("interfaceGuid"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim()
                    .to_string();
                let name = map
                    .get("Name")
                    .or_else(|| map.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim()
                    .to_string();
                NicRef { guid, name }
            }
            _ => continue,
        };
        if nic.name.is_empty() && nic.guid.is_empty() {
            continue;
        }
        // 同一网卡按 GUID（无 GUID 时按名称）去重，保留首次出现的顺序。
        let dup = out.iter().any(|x| {
            if !nic.guid.is_empty() && !x.guid.is_empty() {
                x.guid.eq_ignore_ascii_case(&nic.guid)
            } else {
                x.name.eq_ignore_ascii_case(&nic.name)
            }
        });
        if !dup {
            out.push(nic);
        }
    }
    out
}

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
    // R02：先把"要改什么、原状态是什么"落盘，再动系统。
    // 记账失败就不动手——否则一旦禁用网卡后崩溃，机器会带着无记录的网络现场。
    let planned = if mode == CutMode::Nics {
        list_up_nics_detailed()
    } else {
        Vec::new()
    };
    let scope: Vec<String> =
        std::iter::once(format!("{}{}", crate::ledger::SCOPE_FIREWALL, CUT_RULE))
            .chain(
                planned
                    .iter()
                    .filter(|n| !n.guid.is_empty())
                    .map(|n| format!("{}{}", crate::ledger::SCOPE_NIC, n.guid)),
            )
            .collect();
    let mut txn = crate::ledger::Txn::new(
        crate::ledger::TxnKind::Netcut,
        &crate::state::generation_id(),
        scope,
        serde_json::json!({
            "mode": mode_name(mode),
            "nics": planned,
            "cut_rule_present": cut_rule_count() > 0,
        }),
    );
    if let Err(err) = crate::ledger::save(&txn) {
        let msg = format!("断网前写入恢复账本失败，已放弃断网：{err}");
        log_line(&format!("netcut: cut({}) -> {msg}", mode.label()));
        return (false, msg);
    }

    let mut notes: Vec<String> = Vec::new();
    let (firewall_ok, firewall_detail) = add_cut_rule();
    txn.record("添加防火墙全局阻断规则", firewall_ok, &firewall_detail);
    let _ = crate::ledger::save(&txn);
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
            // 账本里记的是 GUID，优先按 GUID 禁用（名称只做展示与旧现场兜底）。
            let guid = planned
                .iter()
                .find(|n| n.name.eq_ignore_ascii_case(name))
                .map(|n| n.guid.clone())
                .unwrap_or_default();
            let ok = if guid.is_empty() {
                disable_nic(name)
            } else {
                set_nic_enabled_by_guid(&guid, false)
            };
            txn.record(&format!("禁用网卡 {name}"), ok, "");
            let _ = crate::ledger::save(&txn);
            if ok {
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
    // 后置核验：规则条数与网卡实际状态都要查，不能只看命令返回码。
    let rule_present = cut_rule_count() > 0;
    txn.record("核验全局阻断规则", rule_present, "");
    let mut nics_verified = true;
    if mode == CutMode::Nics {
        for name in &nics {
            let down = !nic_is_up(name);
            nics_verified &= down;
            txn.record(&format!("核验网卡已断开 {name}"), down, "");
        }
    }
    let verified = rule_present && nics_verified;
    txn.done = verified;
    if let Err(err) = crate::ledger::save(&txn) {
        log_line(&format!(
            "netcut: 账本提交失败（{err}），保持未完成状态供恢复"
        ));
    }

    let mut msg = if mode == CutMode::Nics {
        format!("已禁用 {} 个物理网卡", nics.len())
    } else {
        "已启用防火墙全局阻断".to_string()
    };
    if mode == CutMode::Nics && nics.is_empty() {
        msg = "物理网卡禁用未生效，仅剩防火墙全局阻断".to_string();
    }
    if !verified {
        msg.push_str("；断网核验未通过，下次启动会按账本恢复");
    }
    if !notes.is_empty() {
        msg.push('；');
        msg.push_str(&notes.join("；"));
    }
    log_line(&format!("netcut: cut({}) -> {msg}", mode.label()));
    (verified, msg)
}

/// 恢复计划的一条：账本里有 GUID 就按 GUID 恢复，只有旧现场的名称时才退化为按名称。
pub struct NicRestore {
    pub guid: Option<String>,
    pub name: String,
}

/// 恢复计划 = 账本记过的网卡 ∪ 状态文件里记的网卡。
///
/// 账本是"我改过什么"的权威记录：禁用网卡成功、`netcut.json` 还没写就崩溃时，
/// 只有账本知道那张网卡被关掉了，所以这里不能拿状态文件当驱动源。
pub fn restore_plan(ledger: &[(String, String)], state_nics: &[String]) -> Vec<NicRestore> {
    let mut out: Vec<NicRestore> = Vec::new();
    for (guid, name) in ledger {
        let guid = guid.trim();
        if guid.is_empty() {
            continue;
        }
        let label = if name.trim().is_empty() {
            guid.to_string()
        } else {
            name.trim().to_string()
        };
        out.push(NicRestore {
            guid: Some(guid.to_string()),
            name: label,
        });
    }
    for name in state_nics {
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        if out.iter().any(|n| n.name.eq_ignore_ascii_case(name)) {
            continue;
        }
        out.push(NicRestore {
            guid: None,
            name: name.to_string(),
        });
    }
    out
}

/// 从账本里取出 (GUID, 名称) 对：GUID 来自 scope，名称来自 original 里的原始枚举。
fn ledger_nic_pairs(txn: &crate::ledger::Txn, managed: &[String]) -> Vec<(String, String)> {
    let recorded: Vec<(String, String)> = txn
        .original
        .get("nics")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|n| {
                    let guid = n.get("guid").and_then(|x| x.as_str())?.to_string();
                    let name = n
                        .get("name")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();
                    Some((guid, name))
                })
                .collect()
        })
        .unwrap_or_default();
    managed
        .iter()
        .filter_map(|s| s.strip_prefix(crate::ledger::SCOPE_NIC))
        .map(|g| {
            let name = recorded
                .iter()
                .find(|(gg, _)| gg.eq_ignore_ascii_case(g))
                .map(|(_, n)| n.clone())
                .unwrap_or_default();
            (g.to_string(), name)
        })
        .collect()
}

fn restore_locked() -> (bool, String) {
    let path = state_path();
    let state_exists = path.exists();
    let state = load_state_from(&path);
    let mut actions: Vec<String> = Vec::new();
    let mut nics_ok = true;
    // R02：账本是"我改过什么"的权威记录。损坏/读不出时不能当成没有残留，
    // 也不能凭 netcut.json 里的名字乱动，先按可恢复的部分做并如实报告。
    let loaded = crate::ledger::load();
    // 账本损坏时不知道还有哪些改动没撤，这一轮不能宣称恢复完成，也不能删账本。
    let ledger_ok = !matches!(loaded, crate::ledger::Loaded::Corrupt(_));
    let txn = match loaded {
        crate::ledger::Loaded::Pending(t) | crate::ledger::Loaded::Done(t) => Some(t),
        crate::ledger::Loaded::Corrupt(err) => {
            log_line(&format!("netcut: 恢复账本损坏（{err}），保留证据"));
            actions.push("恢复账本损坏，已保留原文件待人工确认".to_string());
            None
        }
        crate::ledger::Loaded::Unreadable(err) => {
            log_line(&format!("netcut: 恢复账本读取失败（{err}）"));
            actions.push("恢复账本读取失败，未做任何变更".to_string());
            return (false, actions.join("；"));
        }
        crate::ledger::Loaded::NotFound => None,
    };
    if let Some(t) = txn.as_ref() {
        if !t.all_steps_ok() {
            // 上次事务没走完：把失败步骤带进恢复报告，别让用户以为一切正常。
            let failed = t.failure_summary();
            if !failed.is_empty() {
                log_line(&format!("netcut: 上次断网未完成 -> {failed}"));
                actions.push(format!("上次断网未完成：{failed}"));
            }
        }
    }
    let (managed, rejected) = txn
        .as_ref()
        .map(|t| crate::ledger::split_managed(&t.scope))
        .unwrap_or_default();
    if !rejected.is_empty() {
        log_line(&format!(
            "netcut: 账本含不可管理范围，已忽略 {} 项",
            rejected.len()
        ));
        actions.push(format!("已忽略 {} 项无法识别的账本条目", rejected.len()));
    }
    let ledger_pairs = txn
        .as_ref()
        .map(|t| ledger_nic_pairs(t, &managed))
        .unwrap_or_default();
    let state_nics: Vec<String> = state.as_ref().map(|s| s.nics.clone()).unwrap_or_default();
    let plan = restore_plan(&ledger_pairs, &state_nics);
    // 先恢复网卡、最后删规则：恢复过程中网络仍受规则管着。
    for nic in &plan {
        let ok = match nic.guid.as_deref() {
            Some(guid) => set_nic_enabled_by_guid(guid, true),
            None => enable_nic(&nic.name),
        };
        if ok {
            actions.push(format!("已启用网卡 {}", nic.name));
        } else {
            nics_ok = false;
            actions.push(format!("启用网卡失败：{}", nic.name));
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
    let ok = nics_ok && rule_ok && ledger_ok;
    if ok {
        // 核验通过才清账本；否则保留，下次自愈重试（账本是唯一可信的现场记录）。
        if let Err(err) = crate::ledger::clear() {
            actions.push(format!("清理恢复账本失败：{err}"));
        }
    } else if !ledger_ok {
        actions.push("恢复账本损坏，未清理账本（需人工确认后再删）".to_string());
    }
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
    // R02：账本损坏/读不出时不能当成"没有残留"直接开网——先报告，交给人工/后续恢复。
    match crate::ledger::load() {
        crate::ledger::Loaded::Corrupt(err) => {
            let line = format!("恢复账本损坏，保留现场待确认（{err}）");
            log_line(&format!("netcut: {line}"));
            actions.push(line);
            return actions;
        }
        crate::ledger::Loaded::Unreadable(err) => {
            let line = format!("恢复账本读取失败，未自动恢复网络（{err}）");
            log_line(&format!("netcut: {line}"));
            actions.push(line);
            return actions;
        }
        _ => {}
    }
    if path.exists() {
        let (ok, msg) = restore_locked();
        let line = if ok {
            format!("检测到上次熔断残留，已恢复网络（{msg}）")
        } else {
            format!("上次残留恢复未完成，已保留现场（{msg}）")
        };
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

/// netsh 找不到规则时的提示。2026-10 中文 Win11 实测输出是合法 UTF-8：
/// `"\r\n没有与指定标准相匹配的规则。\r\n\r\n"`（exit 1，48 字节）——不是 GBK，
/// 而当前版本的措辞是「指定标准」，旧版本才是「指定条件」，两种都收。
/// 实际幂等仍靠删前先用 `show` 计数（`count_rule_in_listing` 按 ASCII 规则名数行，
/// 与界面语言无关）；这里只是竞态下"规则已被别处删掉"的兜底。
fn is_no_match(detail: &str) -> bool {
    let detail = detail.to_ascii_lowercase();
    detail.contains("no rules match") || detail.contains("没有与指定")
}

/// 执行 PowerShell 命令（输出走 log_line），返回 (成功, 输出)。
fn powershell(script: &str) -> (bool, String) {
    run(
        crate::guard::POWERSHELL,
        &["-NoProfile", "-NonInteractive", "-Command", script],
    )
}

/// 网卡当前是否处于 Up（核验断网是否真的生效）。
fn nic_is_up(name: &str) -> bool {
    let script = format!(
        "$a = Get-NetAdapter -Name '{}' -ErrorAction SilentlyContinue; if ($a) {{ [string]$a.Status }} else {{ 'Missing' }}",
        name.replace('\'', "''")
    );
    let (ok, detail) = powershell(&script);
    if !ok {
        return true; // 查不出来就不敢说"已断开"，按仍在线处理
    }
    detail.trim().eq_ignore_ascii_case("Up")
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

/// 按 GUID 启停网卡（名称可能重复/被改，GUID 才稳定）。
fn set_nic_enabled_by_guid(guid: &str, enabled: bool) -> bool {
    let verb = if enabled {
        "Enable-NetAdapter"
    } else {
        "Disable-NetAdapter"
    };
    let script = format!(
        "{verb} -InterfaceGuid '{}' -Confirm:$false -ErrorAction Stop",
        guid.replace('\'', "''")
    );
    let (ok, detail) = powershell(&script);
    if !ok {
        log_line(&format!("netcut: {verb} guid={guid} 失败（{detail}）"));
    }
    ok
}

/// 启用中的物理网卡（含 GUID）。
fn list_up_nics_detailed() -> Vec<NicRef> {
    let (ok, raw) = powershell(NIC_ENUM_SCRIPT);
    if !ok {
        return Vec::new();
    }
    let json = decode_b64_text(&raw).unwrap_or(raw);
    let nics = parse_nic_refs(&json);
    log_line(&format!(
        "netcut: 启用中的物理网卡 {}",
        nics.iter()
            .map(|n| n.name.clone())
            .collect::<Vec<_>>()
            .join(", ")
    ));
    nics
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
    fn parse_nic_refs_accepts_guid_and_legacy_name_forms() {
        // 新形态：GUID + 名称（中文名原样保留）
        let json = r#"[{"InterfaceGuid":"6f1c2f9a-1b2c-4d5e-8f90-1234567890ab","Name":"以太网"},{"InterfaceGuid":"0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d","Name":"WLAN"}]"#;
        let nics = parse_nic_refs(json);
        assert_eq!(nics.len(), 2);
        assert_eq!(nics[0].name, "以太网");
        assert!(nics[0].guid.starts_with("6f1c2f9a"));

        // 旧形态：只有名称，GUID 留空（恢复时按名称兜底）
        let legacy = parse_nic_refs(r#"["以太网","WLAN"]"#);
        assert_eq!(legacy.len(), 2);
        assert!(legacy.iter().all(|n| n.guid.is_empty()));

        // 单对象（ConvertTo-Json 单元素）、null、垃圾输入
        assert_eq!(
            parse_nic_refs(r#"{"InterfaceGuid":"a","Name":"E"}"#).len(),
            1
        );
        assert!(parse_nic_refs("null").is_empty());
        assert!(parse_nic_refs("not json").is_empty());

        // 同 GUID 去重
        let dup = parse_nic_refs(
            r#"[{"InterfaceGuid":"same","Name":"A"},{"InterfaceGuid":"same","Name":"B"}]"#,
        );
        assert_eq!(dup.len(), 1);
    }

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
    /// 中文串取的是 2026-10 实测抓到的原文，而不是"看起来像"的写法——喂给它的
    /// 必须是真实 netsh 输出，否则这条测试只会锁住一个错字面量。
    #[test]
    fn detects_netsh_no_match_text() {
        assert!(is_no_match("No rules match the specified criteria."));
        assert!(is_no_match("\r\n没有与指定标准相匹配的规则。\r\n\r\n"));
        assert!(is_no_match("没有与指定条件匹配的规则。")); // 旧版本措辞
        assert!(!is_no_match("Ok."));
        assert!(!is_no_match(""));
        assert!(!is_no_match("已更新 1 条规则。"));
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

    /// T03-02：禁用网卡成功、状态文件还没写就崩溃时，只有账本知道那张网卡。
    #[test]
    fn restore_plan_recovers_ledger_nics_without_state_file() {
        let ledger = vec![(
            "6f1c2f9a-1b2c-4d5e-8f90-1234567890ab".to_string(),
            "以太网".to_string(),
        )];
        let plan = restore_plan(&ledger, &[]);
        assert_eq!(plan.len(), 1);
        assert_eq!(
            plan[0].guid.as_deref(),
            Some("6f1c2f9a-1b2c-4d5e-8f90-1234567890ab")
        );
        assert_eq!(plan[0].name, "以太网");
    }

    /// 旧现场（账本没有、状态文件有）仍要按名称恢复，不能因为没账本就跳过。
    #[test]
    fn restore_plan_falls_back_to_state_names() {
        let plan = restore_plan(&[], &["WLAN".to_string()]);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].guid, None);
        assert_eq!(plan[0].name, "WLAN");
    }

    /// 同一张网卡两边都记着时只恢复一次，且优先按 GUID（名称可能被用户改过）。
    #[test]
    fn restore_plan_dedupes_and_prefers_guid() {
        let ledger = vec![(
            "6f1c2f9a-1b2c-4d5e-8f90-1234567890ab".to_string(),
            "以太网".to_string(),
        )];
        let plan = restore_plan(&ledger, &["以太网".to_string(), "WLAN".to_string()]);
        assert_eq!(plan.len(), 2);
        assert_eq!(
            plan[0].guid.as_deref(),
            Some("6f1c2f9a-1b2c-4d5e-8f90-1234567890ab")
        );
        assert_eq!(plan[1].name, "WLAN");
    }

    /// 账本里没有名称时用 GUID 兜底展示，空条目直接丢弃。
    #[test]
    fn restore_plan_skips_blank_entries() {
        let ledger = vec![
            (
                "6f1c2f9a-1b2c-4d5e-8f90-1234567890ab".to_string(),
                String::new(),
            ),
            (String::new(), "垃圾".to_string()),
        ];
        let plan = restore_plan(&ledger, &[String::new(), "  ".to_string()]);
        assert_eq!(plan.len(), 1);
        assert_eq!(
            plan[0].name, "6f1c2f9a-1b2c-4d5e-8f90-1234567890ab",
            "没有名称时应回落到 GUID"
        );
    }
}
