//! 写前账本（R02）：任何系统改动之前，先把"我要改什么、原状态是什么"落盘。
//!
//! 为什么不是"改完再记"：断网要禁用网卡，如果禁用成功、记账前进程被杀，
//! 机器就带着一个没有任何记录的网络现场，下次启动无从恢复。所以顺序必须是
//! **写意图 → 执行 → 逐步记结果 → 核验 → 提交**，任何一步失败都保留账本供恢复。
//!
//! 账本放在用户可写目录，因此读取侧只信"事实字段"，并且对资源标识做白名单校验：
//! 网卡必须是 GUID 形式、规则名必须带本产品前缀。用户可写的 JSON 不能变成
//! 高权限任意操作指令（例如伪造一条"删除所有规则"的账本）。

use std::path::{Path, PathBuf};

use crate::model::now;

/// 账本文件名（%APPDATA%\ClaudeGuard\ledger.json）。
pub const LEDGER_FILE: &str = "ledger.json";

/// 一次事务的范围标识前缀，读取时按它校验，避免账本被塞进任意资源名。
pub const SCOPE_NIC: &str = "nic:";
pub const SCOPE_FIREWALL: &str = "firewall:";

/// 事务类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TxnKind {
    /// 断网（防火墙全局阻断 + 可选禁用网卡）
    Netcut,
    /// 熔断隔离（按 exe 加 Block 规则）
    Quarantine,
    /// 未接入兜底封锁
    Lockdown,
}

/// 单步执行结果。
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Step {
    pub op: String,
    pub ok: bool,
    #[serde(default)]
    pub detail: String,
    pub at: u64,
}

/// 一次系统改动事务。
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Txn {
    /// 事务 ID（时间 + 序号，便于日志对照）
    pub id: String,
    pub kind: TxnKind,
    /// 开始时间
    pub since: u64,
    /// 运行代次（进程启动标识），用于判断"这是不是上一代留下的现场"
    #[serde(default)]
    pub generation: String,
    /// 涉及资源（"nic:{GUID}" / "firewall:{规则名}"），恢复时只动这些
    pub scope: Vec<String>,
    /// 改动前的原始状态（只记事实，不记命令）
    #[serde(default)]
    pub original: serde_json::Value,
    /// 逐步执行结果
    #[serde(default)]
    pub steps: Vec<Step>,
    /// 是否已核验通过并提交；false 表示"可能没做完"，需要恢复流程处理
    #[serde(default)]
    pub done: bool,
}

/// 读取结果：区分"没有账本"与"账本读不出来"。
///
/// 损坏/权限失败绝不能当成"没有残留"——那会导致带着保护残留直接开网。
#[derive(Debug, Clone, PartialEq)]
pub enum Loaded {
    /// 没有账本（干净状态）
    NotFound,
    /// 读到未完成的事务
    Pending(Txn),
    /// 读到已完成的事务（正常应已被清理）
    Done(Txn),
    /// 文件存在但解析失败：保留证据，调用方应进入 RecoveryPending
    Corrupt(String),
    /// 读文件失败（权限/IO）
    Unreadable(String),
}

impl Txn {
    pub fn new(
        kind: TxnKind,
        generation: &str,
        scope: Vec<String>,
        original: serde_json::Value,
    ) -> Txn {
        let ts = now();
        Txn {
            id: format!("{ts}-{}", std::process::id()),
            kind,
            since: ts,
            generation: generation.to_string(),
            scope,
            original,
            steps: Vec::new(),
            done: false,
        }
    }

    pub fn record(&mut self, op: &str, ok: bool, detail: &str) {
        self.steps.push(Step {
            op: op.to_string(),
            ok,
            detail: detail.to_string(),
            at: now(),
        });
    }

    /// 所有步骤都成功。
    pub fn all_steps_ok(&self) -> bool {
        !self.steps.is_empty() && self.steps.iter().all(|s| s.ok)
    }

    /// 失败步骤的描述（给用户看的一句话）。
    pub fn failure_summary(&self) -> String {
        let failed: Vec<String> = self
            .steps
            .iter()
            .filter(|s| !s.ok)
            .map(|s| {
                if s.detail.is_empty() {
                    s.op.clone()
                } else {
                    format!("{}（{}）", s.op, s.detail)
                }
            })
            .collect();
        if failed.is_empty() {
            String::new()
        } else {
            failed.join("；")
        }
    }
}

/// 纯函数：资源标识是否为本产品可管理的范围。
///
/// 账本在用户可写目录，恢复时只允许动这些形态的资源：
/// - `nic:{GUID}`：网卡必须用稳定 GUID（名称会变、也不唯一）
/// - `firewall:{规则名}`：必须带本产品规则前缀
pub fn scope_is_managed(item: &str) -> bool {
    if let Some(guid) = item.strip_prefix(SCOPE_NIC) {
        return is_guid(guid);
    }
    if let Some(name) = item.strip_prefix(SCOPE_FIREWALL) {
        return name.starts_with("ClaudeGuard ");
    }
    false
}

/// 纯函数：`{8-4-4-4-12}` 形式（大小写不敏感）。
fn is_guid(text: &str) -> bool {
    let parts: Vec<&str> = text.split('-').collect();
    if parts.len() != 5 {
        return false;
    }
    let want = [8usize, 4, 4, 4, 12];
    parts
        .iter()
        .zip(want.iter())
        .all(|(p, n)| p.len() == *n && p.chars().all(|c| c.is_ascii_hexdigit()))
}

/// 纯函数：过滤出可管理的范围项，返回 (可管理, 被拒绝的)。
pub fn split_managed(scope: &[String]) -> (Vec<String>, Vec<String>) {
    let mut ok = Vec::new();
    let mut bad = Vec::new();
    for item in scope {
        if scope_is_managed(item) {
            ok.push(item.clone());
        } else {
            bad.push(item.clone());
        }
    }
    (ok, bad)
}

/// 纯函数：解析账本文本。
pub fn parse(text: &str) -> Result<Txn, String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err("账本为空".to_string());
    }
    serde_json::from_str::<Txn>(trimmed).map_err(|e| format!("账本解析失败：{e}"))
}

/// 账本路径（`%APPDATA%\ClaudeGuard\ledger.json`）。
pub fn path() -> PathBuf {
    crate::config::config_dir().join(LEDGER_FILE)
}

pub fn load_from(file: &Path) -> Loaded {
    let text = match std::fs::read_to_string(file) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Loaded::NotFound,
        Err(err) => return Loaded::Unreadable(err.to_string()),
    };
    match parse(&text) {
        Ok(txn) if txn.done => Loaded::Done(txn),
        Ok(txn) => Loaded::Pending(txn),
        Err(err) => Loaded::Corrupt(err),
    }
}

pub fn load() -> Loaded {
    load_from(&path())
}

/// 原子写入：先写临时文件并 fsync，再 rename 覆盖。
///
/// rename 单独不保证断电后可见（目录项也要落盘），所以写完顺手 fsync 目录；
/// 目录 fsync 在 Windows 上不可用，失败忽略。
pub fn save_to(file: &Path, txn: &Txn) -> Result<(), String> {
    use std::io::Write;
    let dir = file
        .parent()
        .ok_or_else(|| "账本路径没有父目录".to_string())?;
    std::fs::create_dir_all(dir).map_err(|e| format!("创建账本目录失败：{e}"))?;
    let tmp = file.with_extension("json.tmp");
    let body = serde_json::to_vec_pretty(txn).map_err(|e| format!("账本序列化失败：{e}"))?;
    {
        let mut f = std::fs::File::create(&tmp).map_err(|e| format!("写账本临时文件失败：{e}"))?;
        f.write_all(&body)
            .map_err(|e| format!("写账本临时文件失败：{e}"))?;
        f.sync_all().map_err(|e| format!("账本落盘失败：{e}"))?;
    }
    std::fs::rename(&tmp, file).map_err(|e| format!("账本提交失败：{e}"))?;
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

pub fn save(txn: &Txn) -> Result<(), String> {
    save_to(&path(), txn)
}

/// 删除账本（只在确认恢复完成且核验通过后调用）。
pub fn clear_at(file: &Path) -> Result<(), String> {
    match std::fs::remove_file(file) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("删除账本失败：{err}")),
    }
}

pub fn clear() -> Result<(), String> {
    clear_at(&path())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn txn() -> Txn {
        Txn::new(
            TxnKind::Netcut,
            "gen-1",
            vec![
                format!("{SCOPE_NIC}6f1c2f9a-1b2c-4d5e-8f90-1234567890ab"),
                format!("{SCOPE_FIREWALL}{}", crate::netcut::CUT_RULE),
            ],
            serde_json::json!({"nics": ["以太网"], "firewall": false}),
        )
    }

    #[test]
    fn only_managed_scopes_are_accepted() {
        let (ok, bad) = split_managed(&[
            format!("{SCOPE_NIC}6f1c2f9a-1b2c-4d5e-8f90-1234567890ab"),
            format!("{SCOPE_FIREWALL}ClaudeGuard Cut All"),
            "nic:以太网".to_string(),
            "firewall:Some Other App".to_string(),
            "nic:not-a-guid".to_string(),
            "reg:HKEY_LOCAL_MACHINE\\SAM".to_string(),
        ]);
        assert_eq!(ok.len(), 2, "只接受 GUID 网卡与本产品规则名");
        assert_eq!(bad.len(), 4);
        assert!(
            bad.iter().any(|s| s.contains("SAM")),
            "任意注册表路径必须被拒绝"
        );
    }

    #[test]
    fn steps_record_failures_and_summarize() {
        let mut t = txn();
        t.record("禁用网卡 以太网", true, "");
        t.record("添加全局阻断规则", false, "exit=1");
        assert!(!t.all_steps_ok());
        assert!(t.failure_summary().contains("添加全局阻断规则"));
        assert!(t.failure_summary().contains("exit=1"));
        t.record("核验", true, "");
        assert_eq!(t.steps.len(), 3);
    }

    #[test]
    fn load_distinguishes_missing_corrupt_and_pending() {
        let dir = std::env::temp_dir().join(format!("cg-ledger-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join(LEDGER_FILE);

        assert_eq!(load_from(&file), Loaded::NotFound);

        std::fs::write(&file, "{ not json").unwrap();
        assert!(
            matches!(load_from(&file), Loaded::Corrupt(_)),
            "损坏不能被当成没有残留"
        );

        let t = txn();
        save_to(&file, &t).unwrap();
        match load_from(&file) {
            Loaded::Pending(got) => assert_eq!(got.id, t.id),
            other => panic!("期望 Pending，实际 {other:?}"),
        }

        let mut done = t.clone();
        done.done = true;
        save_to(&file, &done).unwrap();
        assert!(matches!(load_from(&file), Loaded::Done(_)));

        clear_at(&file).unwrap();
        assert_eq!(load_from(&file), Loaded::NotFound);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_is_atomic_and_leaves_no_temp_file() {
        let dir = std::env::temp_dir().join(format!("cg-ledger2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join(LEDGER_FILE);
        let t = txn();
        save_to(&file, &t).unwrap();
        assert!(file.exists());
        assert!(!dir.join("ledger.json.tmp").exists(), "临时文件不能残留");
        // 覆盖写也要成功（重试场景）
        save_to(&file, &t).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
