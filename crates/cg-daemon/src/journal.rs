//! Crash-safe Write-Ahead Recovery Journal (WAL).
//!
//! Every system-mutating action (firewall quarantine, lockdown, global firewall cut,
//! NIC disable, timezone/location alignment) MUST persist and `sync_all` a WAL
//! transaction via [`JournalStore::begin_tx`] BEFORE touching the OS.
//!
//! On startup (and offline `--restore`), [`heal_on_startup`] / [`heal_offline`]
//! deterministically rolls back uncommitted or orphaned residue via an injected
//! [`RecoveryExecutor`], verifies cleanup (`list_managed_firewall_rules` == 0),
//! and clears the journal only after verified success.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tempfile::NamedTempFile;

use cg_platform::{PlatformDriver, PlatformError};

use crate::protocol::now_unix_secs;

/// WAL journal filename inside the ClaudeGuard data directory.
pub const JOURNAL_FILE: &str = "journal.json";

/// Current WAL schema version.
pub const JOURNAL_VERSION: u32 = 4;

/// Prefix required for all firewall rules managed by ClaudeGuard.
pub const MANAGED_RULE_PREFIX: &str = "ClaudeGuard ";

static TX_SEQ: AtomicU64 = AtomicU64::new(1);

/// Resolves the ClaudeGuard daemon data directory (`%ProgramData%\ClaudeGuard` primary).
///
/// Precedence: explicit override -> `CG_DATA_DIR` -> `%ProgramData%\ClaudeGuard`
/// -> `%APPDATA%\ClaudeGuard` -> `%LOCALAPPDATA%\ClaudeGuard` -> temp dir.
/// Never falls back to `cwd` (`AGENTS.md` #P2-7).
pub fn resolve_data_dir(explicit: Option<&Path>) -> PathBuf {
    if let Some(dir) = explicit {
        return dir.to_path_buf();
    }
    if let Some(env_dir) = non_empty_env("CG_DATA_DIR") {
        return PathBuf::from(env_dir);
    }
    pick_default_data_base(
        non_empty_env("ProgramData").or_else(|| non_empty_env("PROGRAMDATA")),
        non_empty_env("APPDATA"),
        non_empty_env("LOCALAPPDATA"),
        std::env::temp_dir(),
    )
    .join("ClaudeGuard")
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn pick_default_data_base(
    program_data: Option<String>,
    app_data: Option<String>,
    local_app_data: Option<String>,
    temp_dir: PathBuf,
) -> PathBuf {
    if let Some(p) = program_data {
        return PathBuf::from(p);
    }
    if let Some(p) = app_data {
        return PathBuf::from(p);
    }
    if let Some(p) = local_app_data {
        return PathBuf::from(p);
    }
    temp_dir
}

/// High-level transaction category recorded in the WAL.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TxKind {
    Quarantine,
    Lockdown,
    GlobalCut,
    NicDisable,
    EnvAlign,
    Composite,
}

/// Firewall rule traffic direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallDirection {
    Inbound,
    Outbound,
}

/// Individual reversible/auditable OS mutation planned in a WAL transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum WalAction {
    AddFirewallRule {
        rule_name: String,
        #[serde(default)]
        program: Option<String>,
        direction: FirewallDirection,
    },
    GlobalFirewallCut {
        rule_name: String,
    },
    DisableNic {
        nic_guid: String,
        nic_name: String,
    },
    AlignTimezone {
        from_tz: String,
        to_tz: String,
    },
    AlignLocation {
        #[serde(default)]
        from_lat: Option<String>,
        #[serde(default)]
        from_lon: Option<String>,
        to_lat: String,
        to_lon: String,
    },
    KillProcesses {
        agent_ids: Vec<String>,
    },
}

/// Planned step written before OS mutation begins.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedStep {
    pub step_id: u32,
    pub description: String,
    pub action: WalAction,
}

/// Execution record of an applied step.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedStep {
    pub step_id: u32,
    pub op: String,
    pub ok: bool,
    #[serde(default)]
    pub detail: String,
    pub at: u64,
}

/// Network adapter identity snapshot in [`BaselineState`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NicSnapshot {
    pub guid: String,
    pub name: String,
}

/// Pre-mutation system baseline recorded before applying changes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineState {
    #[serde(default)]
    pub firewall_rules_present: Vec<String>,
    #[serde(default)]
    pub enabled_nics: Vec<NicSnapshot>,
    #[serde(default)]
    pub timezone_key: Option<String>,
    #[serde(default)]
    pub location_lat: Option<String>,
    #[serde(default)]
    pub location_lon: Option<String>,
}

/// Crash-safe Write-Ahead Log record persisted to `journal.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryJournal {
    pub version: u32,
    pub tx_id: String,
    pub epoch: u64,
    pub kind: TxKind,
    pub created_at: u64,
    #[serde(default)]
    pub planned_steps: Vec<PlannedStep>,
    #[serde(default)]
    pub applied_steps: Vec<AppliedStep>,
    #[serde(default)]
    pub baseline: BaselineState,
    #[serde(default)]
    pub committed: bool,
}

impl RecoveryJournal {
    /// Creates a new uncommitted WAL transaction record.
    pub fn new(
        epoch: u64,
        kind: TxKind,
        planned_steps: Vec<PlannedStep>,
        baseline: BaselineState,
    ) -> Self {
        let ts = now_unix_secs();
        let seq = TX_SEQ.fetch_add(1, Ordering::Relaxed);
        Self {
            version: JOURNAL_VERSION,
            tx_id: format!("{ts}-{}-{seq}", std::process::id()),
            epoch,
            kind,
            created_at: ts,
            planned_steps,
            applied_steps: Vec::new(),
            baseline,
            committed: false,
        }
    }

    /// Appends a step execution record.
    pub fn record_step(
        &mut self,
        step_id: u32,
        op: impl Into<String>,
        ok: bool,
        detail: impl Into<String>,
    ) {
        self.applied_steps.push(AppliedStep {
            step_id,
            op: op.into(),
            ok,
            detail: detail.into(),
            at: now_unix_secs(),
        });
    }
}

/// Result of loading `journal.json` from disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoadedJournal {
    NotFound,
    Uncommitted(RecoveryJournal),
    Committed(RecoveryJournal),
    Corrupt(String),
    Unreadable(String),
}

/// Validates that a firewall rule name belongs strictly to ClaudeGuard.
pub fn is_managed_firewall_rule(name: &str) -> bool {
    name.starts_with(MANAGED_RULE_PREFIX)
        && name.len() > MANAGED_RULE_PREFIX.len()
        && !name.contains(['\r', '\n', '\0'])
}

/// Validates an adapter GUID (`8-4-4-4-12` hex, with or without `{}` braces).
pub fn is_valid_guid(raw: &str) -> bool {
    let trimmed = raw.trim();
    let inner = trimmed
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or(trimmed);
    let parts: Vec<&str> = inner.split('-').collect();
    if parts.len() != 5 {
        return false;
    }
    let lengths = [8usize, 4, 4, 4, 12];
    parts
        .iter()
        .zip(lengths.iter())
        .all(|(p, want)| p.len() == *want && p.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Validates that all identifiers in a WAL journal stay inside managed bounds.
pub fn validate_journal_safety(journal: &RecoveryJournal) -> Result<(), String> {
    for step in &journal.planned_steps {
        match &step.action {
            WalAction::AddFirewallRule { rule_name, .. }
            | WalAction::GlobalFirewallCut { rule_name } => {
                if !is_managed_firewall_rule(rule_name) {
                    return Err(format!(
                        "step {} contains unmanaged firewall rule '{}'",
                        step.step_id, rule_name
                    ));
                }
            }
            WalAction::DisableNic { nic_guid, .. } => {
                if !is_valid_guid(nic_guid) {
                    return Err(format!(
                        "step {} contains invalid NIC GUID '{}'",
                        step.step_id, nic_guid
                    ));
                }
            }
            WalAction::AlignTimezone { from_tz, .. } => {
                if from_tz.trim().is_empty() || from_tz.contains(['\r', '\n', '\0']) {
                    return Err(format!(
                        "step {} contains invalid baseline timezone '{}'",
                        step.step_id, from_tz
                    ));
                }
            }
            WalAction::AlignLocation { .. } | WalAction::KillProcesses { .. } => {}
        }
    }
    for nic in &journal.baseline.enabled_nics {
        if !is_valid_guid(&nic.guid) {
            return Err(format!("baseline contains invalid NIC GUID '{}'", nic.guid));
        }
    }
    for rule in &journal.baseline.firewall_rules_present {
        if !is_managed_firewall_rule(rule) {
            return Err(format!(
                "baseline contains unmanaged firewall rule '{rule}'"
            ));
        }
    }
    Ok(())
}

/// Atomic disk persistence wrapper for `journal.json`.
#[derive(Clone, Debug)]
pub struct JournalStore {
    dir: PathBuf,
}

impl JournalStore {
    /// Creates a store rooted at `dir`.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Returns the store directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Returns the full path to `journal.json`.
    pub fn path(&self) -> PathBuf {
        self.dir.join(JOURNAL_FILE)
    }

    /// Writes a new uncommitted WAL transaction BEFORE any system mutation occurs.
    pub fn begin_tx(
        &self,
        epoch: u64,
        kind: TxKind,
        planned_steps: Vec<PlannedStep>,
        baseline: BaselineState,
    ) -> Result<RecoveryJournal, String> {
        let journal = RecoveryJournal::new(epoch, kind, planned_steps, baseline);
        validate_journal_safety(&journal)?;
        self.save_atomic(&journal)?;
        Ok(journal)
    }

    /// Atomically updates an in-progress WAL transaction (e.g., recording applied steps).
    pub fn checkpoint_tx(&self, journal: &RecoveryJournal) -> Result<(), String> {
        validate_journal_safety(journal)?;
        self.save_atomic(journal)
    }

    /// Marks the WAL transaction committed and atomically persists it with `sync_all`.
    pub fn commit_tx(&self, journal: &mut RecoveryJournal) -> Result<(), String> {
        validate_journal_safety(journal)?;
        journal.committed = true;
        self.save_atomic(journal)
    }

    /// Atomically serializes, `sync_all`s, and renames `journal.json` via `tempfile`.
    pub fn save_atomic(&self, journal: &RecoveryJournal) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir).map_err(|e| {
            format!(
                "failed to create journal directory {}: {e}",
                self.dir.display()
            )
        })?;
        let target = self.path();
        let body = serde_json::to_vec_pretty(journal)
            .map_err(|e| format!("failed to serialize WAL journal: {e}"))?;

        let mut tmp = NamedTempFile::new_in(&self.dir).map_err(|e| {
            format!(
                "failed to create temp WAL file in {}: {e}",
                self.dir.display()
            )
        })?;
        tmp.write_all(&body)
            .map_err(|e| format!("failed to write temp WAL file: {e}"))?;
        tmp.as_file()
            .sync_all()
            .map_err(|e| format!("failed to sync_all temp WAL file: {e}"))?;
        tmp.persist(&target).map_err(|e| {
            format!(
                "failed to atomically rename WAL journal to {}: {}",
                target.display(),
                e.error
            )
        })?;

        // Best-effort directory sync (ignored on Windows where directory fsync is unsupported).
        if let Ok(dir_handle) = std::fs::File::open(&self.dir) {
            let _ = dir_handle.sync_all();
        }
        Ok(())
    }

    /// Loads the WAL journal while distinguishing missing, uncommitted, committed, corrupt, and unreadable states.
    pub fn load(&self) -> LoadedJournal {
        let path = self.path();
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return LoadedJournal::NotFound;
            }
            Err(err) => return LoadedJournal::Unreadable(err.to_string()),
        };
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return LoadedJournal::Corrupt("journal file is empty".to_string());
        }
        match serde_json::from_str::<RecoveryJournal>(trimmed) {
            Ok(j) if j.committed => LoadedJournal::Committed(j),
            Ok(j) => LoadedJournal::Uncommitted(j),
            Err(err) => LoadedJournal::Corrupt(format!("invalid journal JSON: {err}")),
        }
    }

    /// Removes `journal.json` after verified cleanup (idempotent if absent).
    pub fn clear(&self) -> Result<(), String> {
        let path = self.path();
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(format!(
                "failed to remove WAL journal {}: {e}",
                path.display(),
                e = err
            )),
        }
    }
}

/// Platform recovery execution hook plugged in by `cg-platform` in Wave-2 (and mocked in Wave-1 tests).
pub trait RecoveryExecutor: Send + Sync {
    /// Lists currently installed firewall rules whose names start with `ClaudeGuard `.
    fn list_managed_firewall_rules(&self) -> Result<Vec<String>, String>;

    /// Removes one managed firewall rule by exact name.
    fn remove_firewall_rule(&self, rule_name: &str) -> Result<(), String>;

    /// Removes all managed ClaudeGuard firewall rules, returning count removed.
    fn clear_all_managed_firewall_rules(&self) -> Result<usize, String>;

    /// Re-enables a physical/virtual network adapter identified by its stable Windows GUID.
    fn enable_nic_by_guid(&self, guid: &str, name_hint: &str) -> Result<(), String>;

    /// Restores Windows system timezone to `tz_key`.
    fn restore_timezone(&self, tz_key: &str) -> Result<(), String>;

    /// Restores or clears the Windows Sensor default location override.
    fn restore_location(&self, lat: Option<&str>, lon: Option<&str>) -> Result<(), String>;
}

/// No-op recovery executor for Wave-1 foreground/dev mode when platform drivers are not yet wired.
#[derive(Debug, Default)]
pub struct NoopRecoveryExecutor;

impl RecoveryExecutor for NoopRecoveryExecutor {
    fn list_managed_firewall_rules(&self) -> Result<Vec<String>, String> {
        Ok(Vec::new())
    }

    fn remove_firewall_rule(&self, _rule_name: &str) -> Result<(), String> {
        Ok(())
    }

    fn clear_all_managed_firewall_rules(&self) -> Result<usize, String> {
        Ok(0)
    }

    fn enable_nic_by_guid(&self, _guid: &str, _name_hint: &str) -> Result<(), String> {
        Ok(())
    }

    fn restore_timezone(&self, _tz_key: &str) -> Result<(), String> {
        Ok(())
    }

    fn restore_location(&self, _lat: Option<&str>, _lon: Option<&str>) -> Result<(), String> {
        Ok(())
    }
}

/// Concrete [`RecoveryExecutor`] backed by `cg_platform::PlatformDriver` (COM Firewall, Env registry).
pub struct PlatformRecoveryExecutor {
    driver: Arc<dyn PlatformDriver>,
}

impl PlatformRecoveryExecutor {
    /// Creates a recovery executor delegating OS operations to `driver`.
    pub fn new(driver: Arc<dyn PlatformDriver>) -> Self {
        Self { driver }
    }
}

impl RecoveryExecutor for PlatformRecoveryExecutor {
    fn list_managed_firewall_rules(&self) -> Result<Vec<String>, String> {
        match self.driver.firewall().enumerate_rules("ClaudeGuard") {
            Ok(records) => Ok(records
                .into_iter()
                .map(|r| r.name)
                .filter(|name| is_managed_firewall_rule(name))
                .collect()),
            Err(PlatformError::Unsupported { .. }) => Ok(Vec::new()),
            Err(err) => Err(err.to_string()),
        }
    }

    fn remove_firewall_rule(&self, rule_name: &str) -> Result<(), String> {
        if !is_managed_firewall_rule(rule_name) {
            return Err(format!("refusing to remove unmanaged rule '{rule_name}'"));
        }
        match self
            .driver
            .firewall()
            .remove_rules_by_name(&[rule_name.to_string()])
        {
            Ok(report) if report.clean() => Ok(()),
            Ok(report) => Err(format!(
                "firewall rule '{rule_name}' cleanup incomplete (query_ok={}, remaining={})",
                report.query_ok, report.remaining
            )),
            Err(PlatformError::Unsupported { .. }) => Ok(()),
            Err(err) => Err(err.to_string()),
        }
    }

    fn clear_all_managed_firewall_rules(&self) -> Result<usize, String> {
        match self
            .driver
            .firewall()
            .remove_rules_with_prefix("ClaudeGuard")
        {
            Ok(report) if report.clean() => Ok(report.removed),
            Ok(report) => Err(format!(
                "managed firewall cleanup incomplete (query_ok={}, remaining={})",
                report.query_ok, report.remaining
            )),
            Err(PlatformError::Unsupported { .. }) => Ok(0),
            Err(err) => Err(err.to_string()),
        }
    }

    fn enable_nic_by_guid(&self, guid: &str, _name_hint: &str) -> Result<(), String> {
        if !self.driver.capabilities().nic_disable {
            return Err(format!(
                "NIC control is not supported by current platform driver (guid={guid})"
            ));
        }
        Err(format!(
            "NIC re-enable hook not implemented for guid={guid}"
        ))
    }

    fn restore_timezone(&self, tz_key: &str) -> Result<(), String> {
        match self.driver.read_env_info() {
            Ok(info) if info.tz_key.eq_ignore_ascii_case(tz_key) => Ok(()),
            Ok(info) => Err(format!(
                "timezone restoration from '{}' to '{tz_key}' is unsupported without elevated tz helper",
                info.tz_key
            )),
            Err(PlatformError::Unsupported { .. }) => Ok(()),
            Err(err) => Err(err.to_string()),
        }
    }

    fn restore_location(&self, lat: Option<&str>, lon: Option<&str>) -> Result<(), String> {
        let res = match (lat, lon) {
            (Some(la), Some(lo)) => self.driver.write_default_location(la, lo),
            _ => self.driver.delete_default_location(),
        };
        match res {
            Ok(()) | Err(PlatformError::Unsupported { .. }) => Ok(()),
            Err(err) => Err(err.to_string()),
        }
    }
}

/// Overall startup/offline WAL heal status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealStatus {
    Clean,
    RecoveredFromCrash,
    RecoveredOrphans,
    CorruptJournal,
    Failed,
}

/// Single step outcome in a [`HealReport`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealItem {
    pub action: String,
    pub ok: bool,
    pub detail: String,
}

/// Deterministic recovery and verification report returned by [`heal_on_startup`] and [`heal_offline`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealReport {
    pub status: HealStatus,
    pub ok: bool,
    pub verified: bool,
    pub journal_tx_id: Option<String>,
    pub items: Vec<HealItem>,
    pub remaining_rules: Vec<String>,
    pub summary: String,
}

impl HealReport {
    fn push(&mut self, action: impl Into<String>, ok: bool, detail: impl Into<String>) {
        if !ok {
            self.ok = false;
        }
        self.items.push(HealItem {
            action: action.into(),
            ok,
            detail: detail.into(),
        });
    }
}

/// Executes startup WAL crash-residue detection, deterministic rollback, and post-cleanup verification.
pub fn heal_on_startup(store: &JournalStore, executor: &dyn RecoveryExecutor) -> HealReport {
    run_heal(store, executor)
}

/// Executes offline WAL recovery (used by `claudeguard-cli --restore` when the daemon service is stopped).
pub fn heal_offline(store: &JournalStore, executor: &dyn RecoveryExecutor) -> HealReport {
    run_heal(store, executor)
}

fn run_heal(store: &JournalStore, executor: &dyn RecoveryExecutor) -> HealReport {
    match store.load() {
        LoadedJournal::NotFound => heal_orphans_only(executor),
        LoadedJournal::Uncommitted(journal) => heal_from_journal(store, executor, &journal, true),
        LoadedJournal::Committed(journal) => heal_from_journal(store, executor, &journal, false),
        LoadedJournal::Corrupt(err) => handle_corrupt_journal(executor, &err),
        LoadedJournal::Unreadable(err) => HealReport {
            status: HealStatus::Failed,
            ok: false,
            verified: false,
            journal_tx_id: None,
            items: vec![HealItem {
                action: "read_journal".to_string(),
                ok: false,
                detail: err.clone(),
            }],
            remaining_rules: Vec::new(),
            summary: format!("WAL journal unreadable (fail-closed): {err}"),
        },
    }
}

fn heal_orphans_only(executor: &dyn RecoveryExecutor) -> HealReport {
    let mut report = HealReport {
        status: HealStatus::Clean,
        ok: true,
        verified: false,
        journal_tx_id: None,
        items: Vec::new(),
        remaining_rules: Vec::new(),
        summary: String::new(),
    };

    let existing = match executor.list_managed_firewall_rules() {
        Ok(rules) => rules,
        Err(err) => {
            report.push("inspect_orphaned_rules", false, err.clone());
            report.status = HealStatus::Failed;
            report.summary = format!("failed to query firewall rules on startup: {err}");
            return report;
        }
    };

    let managed_orphans: Vec<String> = existing
        .into_iter()
        .filter(|r| is_managed_firewall_rule(r))
        .collect();

    if managed_orphans.is_empty() {
        report.verified = true;
        report.summary = "clean startup: no WAL journal or orphaned firewall rules".to_string();
        return report;
    }

    for rule in &managed_orphans {
        match executor.remove_firewall_rule(rule) {
            Ok(()) => report.push(format!("remove_orphan_rule:{rule}"), true, "removed"),
            Err(err) => report.push(format!("remove_orphan_rule:{rule}"), false, err),
        }
    }

    verify_rules_cleared(&mut report, executor);
    report.status = if report.ok && report.verified {
        HealStatus::RecoveredOrphans
    } else {
        HealStatus::Failed
    };
    report.summary = if report.ok && report.verified {
        format!(
            "cleaned {} orphaned firewall rule(s)",
            managed_orphans.len()
        )
    } else {
        "failed to clean or verify orphaned firewall rules".to_string()
    };
    report
}

fn heal_from_journal(
    store: &JournalStore,
    executor: &dyn RecoveryExecutor,
    journal: &RecoveryJournal,
    uncommitted: bool,
) -> HealReport {
    let mut report = HealReport {
        status: HealStatus::RecoveredFromCrash,
        ok: true,
        verified: false,
        journal_tx_id: Some(journal.tx_id.clone()),
        items: Vec::new(),
        remaining_rules: Vec::new(),
        summary: String::new(),
    };

    if let Err(err) = validate_journal_safety(journal) {
        report.push("validate_journal_safety", false, err.clone());
        report.status = HealStatus::Failed;
        report.summary = format!(
            "WAL safety validation rejected journal {}: {err}",
            journal.tx_id
        );
        return report;
    }

    let mut rules_to_remove: BTreeSet<String> = BTreeSet::new();
    let mut nics_to_enable: Vec<(String, String)> = Vec::new();
    let mut seen_guids: BTreeSet<String> = BTreeSet::new();
    let mut restore_tz: Option<String> = None;
    let mut restore_loc: Option<(Option<String>, Option<String>)> = None;

    // Reverse planned steps deterministically (last applied -> first undone).
    for step in journal.planned_steps.iter().rev() {
        match &step.action {
            WalAction::AddFirewallRule { rule_name, .. }
            | WalAction::GlobalFirewallCut { rule_name } => {
                rules_to_remove.insert(rule_name.clone());
            }
            WalAction::DisableNic { nic_guid, nic_name } => {
                let key = nic_guid.to_ascii_lowercase();
                if seen_guids.insert(key) {
                    nics_to_enable.push((nic_guid.clone(), nic_name.clone()));
                }
            }
            WalAction::AlignTimezone { from_tz, .. } => {
                restore_tz.get_or_insert_with(|| from_tz.clone());
            }
            WalAction::AlignLocation {
                from_lat, from_lon, ..
            } => {
                restore_loc.get_or_insert_with(|| (from_lat.clone(), from_lon.clone()));
            }
            WalAction::KillProcesses { .. } => {}
        }
    }

    // Ensure any NICs captured in baseline are also guaranteed re-enabled.
    for nic in &journal.baseline.enabled_nics {
        let key = nic.guid.to_ascii_lowercase();
        if seen_guids.insert(key) {
            nics_to_enable.push((nic.guid.clone(), nic.name.clone()));
        }
    }
    if restore_tz.is_none() {
        restore_tz = journal.baseline.timezone_key.clone();
    }

    // Also include any orphaned managed firewall rules visible on the host.
    match executor.list_managed_firewall_rules() {
        Ok(existing) => {
            for rule in existing {
                if is_managed_firewall_rule(&rule) {
                    rules_to_remove.insert(rule);
                }
            }
        }
        Err(err) => {
            report.push("list_managed_firewall_rules", false, err);
        }
    }

    // Step 1: Re-enable disabled NICs first (while or after rules clear, network interfaces come back).
    for (guid, name) in &nics_to_enable {
        match executor.enable_nic_by_guid(guid, name) {
            Ok(()) => report.push(
                format!("enable_nic:{guid}"),
                true,
                format!("enabled {name}"),
            ),
            Err(err) => report.push(format!("enable_nic:{guid}"), false, err),
        }
    }

    // Step 2: Remove all ClaudeGuard firewall rules (global cut, quarantine, lockdown).
    for rule in &rules_to_remove {
        match executor.remove_firewall_rule(rule) {
            Ok(()) => report.push(format!("remove_firewall_rule:{rule}"), true, "removed"),
            Err(err) => report.push(format!("remove_firewall_rule:{rule}"), false, err),
        }
    }

    // Step 3: Restore environment timezone/location if altered in this transaction.
    if let Some(tz_key) = restore_tz {
        match executor.restore_timezone(&tz_key) {
            Ok(()) => report.push("restore_timezone", true, format!("restored to {tz_key}")),
            Err(err) => report.push("restore_timezone", false, err),
        }
    }
    if let Some((lat, lon)) = restore_loc {
        match executor.restore_location(lat.as_deref(), lon.as_deref()) {
            Ok(()) => report.push("restore_location", true, "restored sensor location"),
            Err(err) => report.push("restore_location", false, err),
        }
    }

    // Step 4: Mandatory post-cleanup verification (never trust unverified cleanup).
    verify_rules_cleared(&mut report, executor);

    if report.ok && report.verified {
        match store.clear() {
            Ok(()) => {
                report.push(
                    "clear_journal",
                    true,
                    "journal cleared after verified recovery",
                );
                report.status = HealStatus::RecoveredFromCrash;
                let phase = if uncommitted {
                    "uncommitted crash WAL"
                } else {
                    "active WAL residue"
                };
                report.summary = format!(
                    "recovered and verified {} tx {} ({} item(s))",
                    phase,
                    journal.tx_id,
                    report.items.len()
                );
            }
            Err(err) => {
                report.push("clear_journal", false, err);
                report.status = HealStatus::Failed;
                report.summary = "recovery verified, but clearing journal failed".to_string();
            }
        }
    } else {
        // Fail-closed: preserve journal on disk so subsequent startups/CLI keep retrying recovery.
        report.status = HealStatus::Failed;
        report.summary = format!(
            "recovery of tx {} incomplete or unverified; journal preserved",
            journal.tx_id
        );
    }

    report
}

fn handle_corrupt_journal(executor: &dyn RecoveryExecutor, parse_err: &str) -> HealReport {
    let mut report = HealReport {
        status: HealStatus::CorruptJournal,
        ok: false, // Corrupt journal always signals Degraded until manually resolved or cleared.
        verified: false,
        journal_tx_id: None,
        items: vec![HealItem {
            action: "parse_journal".to_string(),
            ok: false,
            detail: parse_err.to_string(),
        }],
        remaining_rules: Vec::new(),
        summary: String::new(),
    };

    // Safely remove any ClaudeGuard-prefixed firewall rules, while keeping the corrupt journal file on disk.
    match executor.clear_all_managed_firewall_rules() {
        Ok(count) => report.items.push(HealItem {
            action: "clear_managed_firewall_rules".to_string(),
            ok: true,
            detail: format!("removed {count} managed firewall rule(s)"),
        }),
        Err(err) => report.items.push(HealItem {
            action: "clear_managed_firewall_rules".to_string(),
            ok: false,
            detail: err,
        }),
    }

    match executor.list_managed_firewall_rules() {
        Ok(rules) => {
            let remaining: Vec<String> = rules
                .into_iter()
                .filter(|r| is_managed_firewall_rule(r))
                .collect();
            report.verified = remaining.is_empty();
            report.remaining_rules = remaining;
        }
        Err(err) => {
            report.items.push(HealItem {
                action: "verify_firewall_cleared".to_string(),
                ok: false,
                detail: err,
            });
        }
    }

    report.summary = format!(
        "corrupt WAL journal preserved ({parse_err}); safe firewall cleanup verified={}",
        report.verified
    );
    report
}

fn verify_rules_cleared(report: &mut HealReport, executor: &dyn RecoveryExecutor) {
    match executor.list_managed_firewall_rules() {
        Ok(rules) => {
            let remaining: Vec<String> = rules
                .into_iter()
                .filter(|r| is_managed_firewall_rule(r))
                .collect();
            if remaining.is_empty() {
                report.verified = true;
                report.push("verify_firewall_cleared", true, "0 managed rules remain");
            } else {
                report.verified = false;
                report.remaining_rules = remaining.clone();
                report.push(
                    "verify_firewall_cleared",
                    false,
                    format!("{} rule(s) still remain", remaining.len()),
                );
            }
        }
        Err(err) => {
            report.verified = false;
            report.push(
                "verify_firewall_cleared",
                false,
                format!("verification query failed: {err}"),
            );
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    pub(crate) struct MockRecoveryState {
        pub firewall_rules: Vec<String>,
        pub disabled_nics: Vec<String>,
        pub current_tz: String,
        pub location: Option<(String, String)>,
        pub calls: Vec<String>,
        pub fail_list_rules: bool,
        pub fail_remove_rule: Option<String>,
        pub fail_enable_nic: Option<String>,
    }

    pub(crate) struct MockRecoveryExecutor {
        pub state: Mutex<MockRecoveryState>,
    }

    impl MockRecoveryExecutor {
        pub fn new(state: MockRecoveryState) -> Self {
            Self {
                state: Mutex::new(state),
            }
        }
    }

    impl RecoveryExecutor for MockRecoveryExecutor {
        fn list_managed_firewall_rules(&self) -> Result<Vec<String>, String> {
            let mut st = self.state.lock().unwrap();
            st.calls.push("list_managed_firewall_rules".to_string());
            if st.fail_list_rules {
                return Err("mock COM query failure".to_string());
            }
            Ok(st.firewall_rules.clone())
        }

        fn remove_firewall_rule(&self, rule_name: &str) -> Result<(), String> {
            let mut st = self.state.lock().unwrap();
            st.calls.push(format!("remove_firewall_rule:{rule_name}"));
            if st.fail_remove_rule.as_deref() == Some(rule_name) {
                return Err(format!("mock failed to remove {rule_name}"));
            }
            st.firewall_rules.retain(|r| r != rule_name);
            Ok(())
        }

        fn clear_all_managed_firewall_rules(&self) -> Result<usize, String> {
            let mut st = self.state.lock().unwrap();
            st.calls
                .push("clear_all_managed_firewall_rules".to_string());
            let before = st.firewall_rules.len();
            st.firewall_rules.retain(|r| !is_managed_firewall_rule(r));
            Ok(before - st.firewall_rules.len())
        }

        fn enable_nic_by_guid(&self, guid: &str, _name_hint: &str) -> Result<(), String> {
            let mut st = self.state.lock().unwrap();
            st.calls.push(format!("enable_nic_by_guid:{guid}"));
            if st.fail_enable_nic.as_deref() == Some(guid) {
                return Err(format!("mock failed to enable NIC {guid}"));
            }
            st.disabled_nics.retain(|g| !g.eq_ignore_ascii_case(guid));
            Ok(())
        }

        fn restore_timezone(&self, tz_key: &str) -> Result<(), String> {
            let mut st = self.state.lock().unwrap();
            st.calls.push(format!("restore_timezone:{tz_key}"));
            st.current_tz = tz_key.to_string();
            Ok(())
        }

        fn restore_location(&self, lat: Option<&str>, lon: Option<&str>) -> Result<(), String> {
            let mut st = self.state.lock().unwrap();
            st.calls.push("restore_location".to_string());
            st.location = match (lat, lon) {
                (Some(la), Some(lo)) => Some((la.to_string(), lo.to_string())),
                _ => None,
            };
            Ok(())
        }
    }

    fn sample_steps_and_baseline() -> (Vec<PlannedStep>, BaselineState) {
        let guid = "{6f1c2f9a-1b2c-4d5e-8f90-1234567890ab}".to_string();
        let steps = vec![
            PlannedStep {
                step_id: 1,
                description: "block claude outbound".into(),
                action: WalAction::AddFirewallRule {
                    rule_name: "ClaudeGuard Block Out (claude)".into(),
                    program: Some(r"C:\Program Files\Claude\claude.exe".into()),
                    direction: FirewallDirection::Outbound,
                },
            },
            PlannedStep {
                step_id: 2,
                description: "global firewall cut".into(),
                action: WalAction::GlobalFirewallCut {
                    rule_name: "ClaudeGuard Cut All".into(),
                },
            },
            PlannedStep {
                step_id: 3,
                description: "disable physical adapter".into(),
                action: WalAction::DisableNic {
                    nic_guid: guid.clone(),
                    nic_name: "Ethernet".into(),
                },
            },
            PlannedStep {
                step_id: 4,
                description: "align timezone".into(),
                action: WalAction::AlignTimezone {
                    from_tz: "China Standard Time".into(),
                    to_tz: "Pacific Standard Time".into(),
                },
            },
            PlannedStep {
                step_id: 5,
                description: "align location".into(),
                action: WalAction::AlignLocation {
                    from_lat: None,
                    from_lon: None,
                    to_lat: "34.0522".into(),
                    to_lon: "-118.2437".into(),
                },
            },
        ];
        let baseline = BaselineState {
            firewall_rules_present: Vec::new(),
            enabled_nics: vec![NicSnapshot {
                guid,
                name: "Ethernet".into(),
            }],
            timezone_key: Some("China Standard Time".into()),
            location_lat: None,
            location_lon: None,
        };
        (steps, baseline)
    }

    #[test]
    fn wal_uncommitted_crash_recovers_all_resources_and_clears_journal() {
        let dir = tempfile::tempdir().unwrap();
        let store = JournalStore::new(dir.path());
        let (steps, baseline) = sample_steps_and_baseline();

        // Simulate crash mid-mutation: WAL written (committed = false), OS partially mutated.
        let tx = store
            .begin_tx(7, TxKind::Composite, steps, baseline)
            .expect("begin_tx");
        assert!(!tx.committed);
        assert!(store.path().exists());

        let exec = MockRecoveryExecutor::new(MockRecoveryState {
            firewall_rules: vec![
                "ClaudeGuard Block Out (claude)".into(),
                "ClaudeGuard Cut All".into(),
            ],
            disabled_nics: vec!["{6f1c2f9a-1b2c-4d5e-8f90-1234567890ab}".into()],
            current_tz: "Pacific Standard Time".into(),
            location: Some(("34.0522".into(), "-118.2437".into())),
            ..Default::default()
        });

        let report = heal_on_startup(&store, &exec);
        assert_eq!(report.status, HealStatus::RecoveredFromCrash);
        assert!(report.ok);
        assert!(report.verified);
        assert_eq!(report.journal_tx_id.as_deref(), Some(tx.tx_id.as_str()));
        assert!(
            !store.path().exists(),
            "journal must be cleared after verified recovery"
        );

        let st = exec.state.lock().unwrap();
        assert!(st.firewall_rules.is_empty());
        assert!(st.disabled_nics.is_empty());
        assert_eq!(st.current_tz, "China Standard Time");
        assert_eq!(st.location, None);
    }

    #[test]
    fn wal_committed_active_crash_also_recovers_on_boot() {
        let dir = tempfile::tempdir().unwrap();
        let store = JournalStore::new(dir.path());
        let (steps, baseline) = sample_steps_and_baseline();

        let mut tx = store
            .begin_tx(9, TxKind::GlobalCut, steps, baseline)
            .unwrap();
        store.commit_tx(&mut tx).unwrap();
        assert!(matches!(store.load(), LoadedJournal::Committed(_)));

        let exec = MockRecoveryExecutor::new(MockRecoveryState {
            firewall_rules: vec!["ClaudeGuard Cut All".into()],
            disabled_nics: vec!["{6f1c2f9a-1b2c-4d5e-8f90-1234567890ab}".into()],
            current_tz: "Pacific Standard Time".into(),
            ..Default::default()
        });

        let report = heal_on_startup(&store, &exec);
        assert_eq!(report.status, HealStatus::RecoveredFromCrash);
        assert!(report.ok && report.verified);
        assert!(!store.path().exists());
    }

    #[test]
    fn orphaned_rules_without_journal_are_detected_and_cleaned() {
        let dir = tempfile::tempdir().unwrap();
        let store = JournalStore::new(dir.path());
        let exec = MockRecoveryExecutor::new(MockRecoveryState {
            firewall_rules: vec![
                "ClaudeGuard Lockdown (claude)".into(),
                "Windows Defender Core".into(), // Unmanaged rule must NEVER be touched!
            ],
            ..Default::default()
        });

        let report = heal_on_startup(&store, &exec);
        assert_eq!(report.status, HealStatus::RecoveredOrphans);
        assert!(report.ok);
        assert!(report.verified);

        let st = exec.state.lock().unwrap();
        assert_eq!(st.firewall_rules, vec!["Windows Defender Core".to_string()]);
    }

    #[test]
    fn corrupt_journal_is_preserved_and_reports_failure() {
        let dir = tempfile::tempdir().unwrap();
        let store = JournalStore::new(dir.path());
        std::fs::write(store.path(), "{ corrupt-json ").unwrap();

        let exec = MockRecoveryExecutor::new(MockRecoveryState {
            firewall_rules: vec!["ClaudeGuard Cut All".into()],
            ..Default::default()
        });

        let report = heal_on_startup(&store, &exec);
        assert_eq!(report.status, HealStatus::CorruptJournal);
        assert!(!report.ok);
        assert!(report.verified);
        assert!(store.path().exists(), "corrupt journal must stay on disk");
        assert!(exec.state.lock().unwrap().firewall_rules.is_empty());
    }

    #[test]
    fn fail_closed_when_verification_query_fails_or_rules_remain() {
        let dir = tempfile::tempdir().unwrap();
        let store = JournalStore::new(dir.path());
        let (steps, baseline) = sample_steps_and_baseline();
        store
            .begin_tx(1, TxKind::Quarantine, steps, baseline)
            .unwrap();

        let exec = MockRecoveryExecutor::new(MockRecoveryState {
            firewall_rules: vec!["ClaudeGuard Cut All".into()],
            fail_list_rules: true,
            ..Default::default()
        });

        let report = heal_on_startup(&store, &exec);
        assert_eq!(report.status, HealStatus::Failed);
        assert!(!report.ok);
        assert!(!report.verified);
        assert!(
            store.path().exists(),
            "journal must NOT be deleted when verification fails"
        );
    }

    #[test]
    fn safety_validation_rejects_unmanaged_firewall_rules_and_bad_guids() {
        let dir = tempfile::tempdir().unwrap();
        let store = JournalStore::new(dir.path());

        let bad_rule = PlannedStep {
            step_id: 1,
            description: "forged rule".into(),
            action: WalAction::GlobalFirewallCut {
                rule_name: "Windows Defender Allow All".into(),
            },
        };
        assert!(store
            .begin_tx(
                1,
                TxKind::Lockdown,
                vec![bad_rule],
                BaselineState::default()
            )
            .is_err());

        let bad_nic = PlannedStep {
            step_id: 2,
            description: "bad nic".into(),
            action: WalAction::DisableNic {
                nic_guid: "not-a-guid".into(),
                nic_name: "Ethernet".into(),
            },
        };
        assert!(store
            .begin_tx(
                1,
                TxKind::NicDisable,
                vec![bad_nic],
                BaselineState::default()
            )
            .is_err());

        // Also test forged on-disk tampering is rejected at heal time.
        let forged_json = serde_json::json!({
            "version": 4,
            "tx_id": "forged-1",
            "epoch": 1,
            "kind": "lockdown",
            "created_at": 100,
            "planned_steps": [{
                "step_id": 1,
                "description": "tampered",
                "action": {
                    "action": "global_firewall_cut",
                    "rule_name": "System Rule"
                }
            }],
            "applied_steps": [],
            "baseline": {},
            "committed": false
        });
        std::fs::write(store.path(), serde_json::to_vec(&forged_json).unwrap()).unwrap();
        let exec = MockRecoveryExecutor::new(MockRecoveryState::default());
        let report = heal_on_startup(&store, &exec);
        assert_eq!(report.status, HealStatus::Failed);
        assert!(!report.ok);
        assert!(exec.state.lock().unwrap().calls.is_empty());
    }

    #[test]
    fn fail_closed_when_rules_remain_after_cleanup_and_no_temp_files_leak() {
        let dir = tempfile::tempdir().unwrap();
        let store = JournalStore::new(dir.path());
        let (steps, baseline) = sample_steps_and_baseline();
        store
            .begin_tx(2, TxKind::Quarantine, steps, baseline)
            .unwrap();

        // Verify atomic persist left zero stray temp files.
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(entries, vec![JOURNAL_FILE.to_string()]);

        // Simulate remove_firewall_rule failure -> rules remain -> journal MUST remain.
        let exec = MockRecoveryExecutor::new(MockRecoveryState {
            firewall_rules: vec!["ClaudeGuard Cut All".into()],
            fail_remove_rule: Some("ClaudeGuard Cut All".into()),
            ..Default::default()
        });
        let report = heal_on_startup(&store, &exec);
        assert_eq!(report.status, HealStatus::Failed);
        assert!(!report.ok);
        assert!(!report.verified);
        assert_eq!(
            report.remaining_rules,
            vec!["ClaudeGuard Cut All".to_string()]
        );
        assert!(store.path().exists());
    }
}
