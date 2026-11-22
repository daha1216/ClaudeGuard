//! Real Wave-2 daemon engine actor wiring `cg-core::GuardEngine`, `cg-platform::PlatformDriver`,
//! `JournalStore`, `ConfigStore`, `TimelineAggregator`, and background monitor/telemetry loops.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use cg_core::agents::{CLI_AGENTS, GUI_AGENTS};
use cg_core::anchors;
use cg_core::engine::{
    CheckPurpose, EffectCommand, EngineEvent, EngineState, GuardEngine, PendingTxKind,
};
use cg_core::envcheck;
use cg_core::onboarding;
use cg_core::timeline::BUCKETS_48;
use cg_core::TimelineAggregator;
use cg_platform::access_win::{self, AccessPath};
use cg_platform::antigravity_proxy_win;
use cg_platform::firewall_com;
use cg_platform::leak_shield_win;
use cg_platform::mihomo_win;
use cg_platform::netwatch_win;
use cg_platform::probe_http::{self, NetworkPolicy, ProbeRoute};
use cg_platform::process_win::{
    self, CachedProcessSnapshot, ClaudePresence, ProcessScanner, SweepMode,
};
use cg_platform::{update_check, PlatformDriver, PlatformError};

use crate::config_store::{ConfigStore, LoadedConfig};
use crate::coordinator::{
    ActorControl, CoordinatorActor, CoordinatorContext, CoordinatorEvent, CoordinatorHandle,
    TelemetryBundle,
};
use crate::diagnostics;
use crate::disarm;
use crate::feishu::FeishuNotifier;
use crate::journal::{
    self, BaselineState, FirewallDirection, HealReport, HealStatus, JournalStore, LoadedJournal,
    PlannedStep, RecoveryExecutor, RecoveryJournal, TxKind, WalAction,
};
use crate::protocol::{
    now_unix_secs, AccessEvidence, AccessLevel, AgentKind, AgentRuntimeStatus,
    AntigravityProxyStatus, ComponentUpdateStatus, Config, CutMode, DefenseCheckItem,
    DefenseSelfCheck, ErrorCode, GuardSnapshot, LeakReport, LeakShieldStatus, Lifecycle, LogLevel,
    MihomoStatus, OnboardingProbeResult, OperationReceipt, OperationStatus, PipeRequest,
    PipeResponse, PolicyPreset, ProbeResult, ProtectionState, SelfCheckStatus, Target,
    ToastNotificationEvent, UpdateCheckPhase, UpdateSummary,
};

pub const TIMELINE_FILE: &str = "timeline.json";
const DEFAULT_TELEMETRY_INTERVAL: Duration = Duration::from_secs(10);
const AUTO_UPDATE_CHECK_INTERVAL: Duration = Duration::from_secs(6 * 3600);

fn resolve_access_and_route(
    driver: &dyn PlatformDriver,
    cfg: &Config,
    cfg_rev: u64,
    targets: &[Target],
    enforce_access_path: bool,
    now_secs: u64,
) -> (AccessEvidence, ProbeRoute) {
    let hosts: Vec<String> = targets
        .iter()
        .filter(|t| t.enabled)
        .map(|t| t.host().to_ascii_lowercase())
        .filter(|h| !h.is_empty())
        .collect();

    let caps = driver.capabilities();
    if caps.access_path_inspection && enforce_access_path {
        match driver.inspect_access_path(&hosts) {
            Ok((access_path, _info)) => {
                let ev = access_path.to_protocol_evidence(now_secs, cfg_rev);
                let r = probe_http::plan_probe_route(&access_path);
                (ev, r)
            }
            Err(err) => {
                let ev = AccessEvidence {
                    level: AccessLevel::Unknown,
                    observed_at: now_secs,
                    revision: cfg_rev,
                    note: err.to_string(),
                    ..AccessEvidence::default()
                };
                (ev, ProbeRoute::Skip(err.to_string()))
            }
        }
    } else {
        let ev = match driver.inspect_access_path(&hosts) {
            Ok((p, _)) => p.to_protocol_evidence(now_secs, cfg_rev),
            Err(_) => AccessEvidence {
                level: AccessLevel::Unknown,
                observed_at: now_secs,
                revision: cfg_rev,
                note: "access inspection bypassed or unsupported".into(),
                ..AccessEvidence::default()
            },
        };
        let policy = NetworkPolicy::with_proxy(&cfg.proxy_host, cfg.proxy_port);
        let r = match policy.route() {
            probe_http::Route::Proxy(addr) => ProbeRoute::Proxy(addr),
            probe_http::Route::Direct => ProbeRoute::Direct,
        };
        (ev, r)
    }
}

fn local_client_versions() -> update_check::LocalClientVersions {
    let (ag_ide_ver, ag_manifest_base) = process_win::installed_antigravity_ide_info();
    update_check::LocalClientVersions {
        claude_desktop: process_win::installed_claude_desktop_version(),
        claude_code: process_win::installed_claude_code_version(),
        codex_desktop: process_win::installed_codex_desktop_version(),
        codex_cli: process_win::installed_codex_cli_version(),
        antigravity_ide: ag_ide_ver,
        antigravity_manifest_base: ag_manifest_base,
        antigravity_cn: process_win::installed_antigravity_cn_version(),
        ag_usage_monitor: process_win::installed_ag_usage_monitor_version(),
        ag_capsule: process_win::installed_ag_capsule_version(),
    }
}

fn hydrate_local_updates(
    updates: &mut UpdateSummary,
    cg_version: &str,
    ag_proxy: &AntigravityProxyStatus,
    local: &update_check::LocalClientVersions,
) {
    update_check::hydrate_summary_locals(updates, cg_version, ag_proxy, local);
}

fn merge_slot(dst: &mut ComponentUpdateStatus, incoming: ComponentUpdateStatus) {
    if incoming.installed_version.is_some() {
        dst.installed_version = incoming.installed_version.clone();
    }
    if incoming.checked_at > dst.checked_at
        || (dst.phase == UpdateCheckPhase::Idle && incoming.phase != UpdateCheckPhase::Idle)
    {
        *dst = incoming;
    }
}

fn merge_telemetry_updates(dst: &mut UpdateSummary, incoming: UpdateSummary) {
    dst.claude_msix_version = incoming.claude_msix_version;
    dst.codex_msix_version = incoming.codex_msix_version;
    // Note: Keep installed_version cleared cleanly when uninstalled for antigravity_proxy / clients
    dst.antigravity_proxy.installed_version = incoming.antigravity_proxy.installed_version.clone();

    merge_slot(&mut dst.claudeguard, incoming.claudeguard);
    if incoming.antigravity_proxy.checked_at > dst.antigravity_proxy.checked_at
        || (dst.antigravity_proxy.phase == UpdateCheckPhase::Idle
            && incoming.antigravity_proxy.phase != UpdateCheckPhase::Idle)
    {
        dst.antigravity_proxy = incoming.antigravity_proxy;
    }
    merge_slot(&mut dst.claude_desktop, incoming.claude_desktop);
    merge_slot(&mut dst.claude_code, incoming.claude_code);
    merge_slot(&mut dst.codex_desktop, incoming.codex_desktop);
    merge_slot(&mut dst.codex_cli, incoming.codex_cli);
    merge_slot(&mut dst.antigravity_ide, incoming.antigravity_ide);
    merge_slot(&mut dst.antigravity_cn, incoming.antigravity_cn);
    merge_slot(&mut dst.ag_usage_monitor, incoming.ag_usage_monitor);
    merge_slot(&mut dst.ag_capsule, incoming.ag_capsule);
}

fn parse_update_component_filter(
    component: Option<&str>,
) -> Result<(bool, bool, Option<String>), String> {
    match component.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok((true, true, None)),
        Some(raw) => match raw.to_ascii_lowercase().as_str() {
            "claudeguard" => Ok((true, false, Some("claudeguard".to_string()))),
            "antigravity_proxy" | "antigravity-proxy" => {
                Ok((false, true, Some("antigravity_proxy".to_string())))
            }
            "claude_desktop" | "claude-desktop" | "claude" => {
                Ok((false, false, Some("claude_desktop".to_string())))
            }
            "claude_code" | "claude-code" => Ok((false, false, Some("claude_code".to_string()))),
            "codex_desktop" | "codex-desktop" | "chatgpt" => {
                Ok((false, false, Some("codex_desktop".to_string())))
            }
            "codex_cli" | "codex-cli" | "codex" => {
                Ok((false, false, Some("codex_cli".to_string())))
            }
            "antigravity_ide" | "antigravity-ide" | "antigravity" => {
                Ok((false, false, Some("antigravity_ide".to_string())))
            }
            "antigravity_cn" | "antigravity-cn" | "antigravity-desktop-cn" => {
                Ok((false, false, Some("antigravity_cn".to_string())))
            }
            "ag_usage_monitor" | "antigravity-usage-monitor" | "usage-monitor" => {
                Ok((false, false, Some("ag_usage_monitor".to_string())))
            }
            "ag_capsule" | "agy-capsule" => Ok((false, false, Some("ag_capsule".to_string()))),
            "plugins" | "antigravity_plugins" => {
                Ok((false, true, Some("antigravity_plugins".to_string())))
            }
            _ => Err(format!("未知的更新检查组件 '{raw}'")),
        },
    }
}

fn component_matches_filter(norm: Option<&str>, id: &str) -> bool {
    match norm {
        None => true,
        Some("antigravity_plugins") => {
            matches!(id, "antigravity_cn" | "ag_usage_monitor" | "ag_capsule")
        }
        Some(other) => other == id,
    }
}

fn build_skipped_update_summary(
    prev: &UpdateSummary,
    cg_version: &str,
    ag_proxy: &AntigravityProxyStatus,
    component: Option<&str>,
    reason: &str,
    now_secs: u64,
) -> UpdateSummary {
    let mut out = prev.clone();
    let local = local_client_versions();
    hydrate_local_updates(&mut out, cg_version, ag_proxy, &local);
    let (check_cg, check_ag, norm) =
        parse_update_component_filter(component).unwrap_or((true, true, None));
    if check_cg {
        out.claudeguard.phase = UpdateCheckPhase::Failed;
        out.claudeguard.checked_at = Some(now_secs);
        out.claudeguard.note = format!("当前接入路径受阻，已拒绝直连检查更新：{reason}");
    }
    if check_ag {
        out.antigravity_proxy.checked_at = Some(now_secs);
        if !ag_proxy.installed {
            out.antigravity_proxy.phase = UpdateCheckPhase::NotInstalled;
            out.antigravity_proxy.note = "本机未检测到反重力客户端".to_string();
        } else {
            out.antigravity_proxy.phase = UpdateCheckPhase::Failed;
            out.antigravity_proxy.note = format!("当前接入路径受阻，已拒绝直连检查更新：{reason}");
        }
    }
    for (id, slot) in [
        ("claude_desktop", &mut out.claude_desktop),
        ("claude_code", &mut out.claude_code),
        ("codex_desktop", &mut out.codex_desktop),
        ("codex_cli", &mut out.codex_cli),
        ("antigravity_ide", &mut out.antigravity_ide),
        ("antigravity_cn", &mut out.antigravity_cn),
        ("ag_usage_monitor", &mut out.ag_usage_monitor),
        ("ag_capsule", &mut out.ag_capsule),
    ] {
        if component_matches_filter(norm.as_deref(), id) {
            slot.phase = UpdateCheckPhase::Failed;
            slot.checked_at = Some(now_secs);
            slot.note = format!("当前接入路径受阻，已拒绝直连检查更新：{reason}");
        }
    }
    out
}

fn paired_cli_id(agent_id: &str) -> Option<&'static str> {
    match agent_id {
        "claude" => Some("claude-code"),
        "chatgpt" => Some("codex"),
        _ => None,
    }
}

fn paired_gui_for_cli(cli_id: &str) -> Option<&'static str> {
    match cli_id {
        "claude-code" => Some("claude"),
        "codex" => Some("chatgpt"),
        _ => None,
    }
}

fn paired_clis_for_agents(agents: &[String]) -> Vec<&'static str> {
    let mut out = Vec::new();
    for agent in agents {
        if let Some(cli_id) = paired_cli_id(agent.as_str()) {
            if !out.contains(&cli_id) {
                out.push(cli_id);
            }
        }
    }
    out
}

fn kill_gui_list_with_receipt(
    driver: &dyn PlatformDriver,
    agents: &[String],
    item_prefix: &str,
    receipt: &mut OperationReceipt,
) -> (u32, bool, bool) {
    let mut total = 0u32;
    let mut any_failed = false;
    let mut any_supported = false;
    for agent in agents {
        match driver.kill_gui_agent(agent) {
            Ok(list) => {
                any_supported = true;
                total = total.saturating_add(list.len() as u32);
                receipt.push_item(
                    format!("{item_prefix}:{agent}"),
                    OperationStatus::Verified,
                    format!("terminated {} process(es)", list.len()),
                );
            }
            Err(PlatformError::Unsupported { detail, .. }) => {
                receipt.push_item(
                    format!("{item_prefix}:{agent}"),
                    OperationStatus::Unsupported,
                    detail,
                );
            }
            Err(err) => {
                any_supported = true;
                any_failed = true;
                receipt.push_item(
                    format!("{item_prefix}:{agent}"),
                    OperationStatus::Failed,
                    err.to_string(),
                );
            }
        }
    }
    (total, any_failed, any_supported)
}

fn kill_cli_list_with_receipt(
    driver: &dyn PlatformDriver,
    cli_ids: &[&str],
    receipt: &mut OperationReceipt,
) -> (u32, bool, bool) {
    let mut total = 0u32;
    let mut any_failed = false;
    let mut any_supported = false;
    for cli_id in cli_ids {
        match driver.kill_cli_agent(cli_id) {
            Ok(list) => {
                any_supported = true;
                total = total.saturating_add(list.len() as u32);
                receipt.push_item(
                    format!("kill_cli:{cli_id}"),
                    OperationStatus::Verified,
                    format!("terminated {} CLI process(es)", list.len()),
                );
            }
            Err(PlatformError::Unsupported { detail, .. }) => {
                receipt.push_item(
                    format!("kill_cli:{cli_id}"),
                    OperationStatus::Unsupported,
                    detail,
                );
            }
            Err(err) => {
                any_supported = true;
                any_failed = true;
                receipt.push_item(
                    format!("kill_cli:{cli_id}"),
                    OperationStatus::Failed,
                    err.to_string(),
                );
            }
        }
    }
    (total, any_failed, any_supported)
}

/// Abstraction over network/access probing so tests can deterministically drive pass/fail/unverified rounds.
pub trait ProbeRunner: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    fn inspect_and_probe(
        &self,
        driver: &dyn PlatformDriver,
        cfg: &Config,
        cfg_rev: u64,
        targets: &[Target],
        enforce_access_path: bool,
        skip_network_probes: bool,
        now_secs: u64,
    ) -> (AccessEvidence, Vec<(String, ProbeResult)>);
}

/// Production [`ProbeRunner`] using `cg_platform` access inspection + `NetworkPolicy` HTTP probes + `cg_core` parsers.
#[derive(Debug, Default)]
pub struct PlatformProbeRunner;

impl ProbeRunner for PlatformProbeRunner {
    fn inspect_and_probe(
        &self,
        driver: &dyn PlatformDriver,
        cfg: &Config,
        cfg_rev: u64,
        targets: &[Target],
        enforce_access_path: bool,
        skip_network_probes: bool,
        now_secs: u64,
    ) -> (AccessEvidence, Vec<(String, ProbeResult)>) {
        let (access, route) =
            resolve_access_and_route(driver, cfg, cfg_rev, targets, enforce_access_path, now_secs);

        if skip_network_probes || matches!(route, ProbeRoute::Skip(_)) {
            return (access, Vec::new());
        }

        let enabled: Vec<&Target> = targets.iter().filter(|t| t.enabled).collect();
        let mut results = Vec::with_capacity(enabled.len());

        std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(enabled.len());
            for target in enabled {
                let r = &route;
                handles.push(scope.spawn(move || {
                    let timeout = Duration::from_secs(target.timeout_secs.clamp(3, 60));
                    let probe = match probe_http::probe_url(
                        r,
                        &target.anchor_url,
                        timeout,
                        anchors::MAX_BODY_BYTES,
                    ) {
                        Ok(resp) => anchors::parse_body_bytes(
                            target.anchor_kind,
                            resp.body.as_bytes(),
                            Some(resp.status),
                            resp.latency_ms,
                        ),
                        Err(err) => ProbeResult::failed(err.to_string()),
                    };
                    (target.id.clone(), probe)
                }));
            }
            for h in handles {
                if let Ok(item) = h.join() {
                    results.push(item);
                }
            }
        });

        (access, results)
    }
}

struct ProbeJob {
    cfg: Config,
    cfg_rev: u64,
    runtime_epoch: u64,
    purpose: CheckPurpose,
    targets: Vec<Target>,
    enforce_access_path: bool,
    skip_network_probes: bool,
}

/// Initialization outcome returned when constructing [`RealEngineActor`].
pub struct BootstrappedActor {
    pub actor: RealEngineActor,
    pub initial_snapshot: GuardSnapshot,
    pub heal_report: HealReport,
    pub process_scanner: Arc<ProcessScanner>,
}

/// Injection point for synchronizing OS 4-vector leak shield rules (`leak_shield_win::sync_leak_shield` in production).
type LeakShieldSyncFn = Arc<
    dyn Fn(&[PathBuf], bool, bool, bool) -> cg_platform::PlatformResult<LeakShieldStatus>
        + Send
        + Sync,
>;

/// Single-writer actor executing `GuardEngine::step` and real OS/WAL/Config side effects.
pub struct RealEngineActor {
    engine: EngineState,
    driver: Arc<dyn PlatformDriver>,
    probe_runner: Arc<dyn ProbeRunner>,
    recovery_executor: Arc<dyn RecoveryExecutor>,
    journal: JournalStore,
    active_journal: Option<RecoveryJournal>,
    config_store: ConfigStore,
    timeline_path: PathBuf,
    data_dir: PathBuf,
    process_scanner: Arc<ProcessScanner>,
    cached_agents: Vec<AgentRuntimeStatus>,
    event_tx: SyncSender<CoordinatorEvent>,
    probe_tx: SyncSender<ProbeJob>,
    _probe_worker: Option<JoinHandle<()>>,
    recheck_waiters: Vec<SyncSender<PipeResponse>>,
    launch_waiters: Vec<(Option<String>, SyncSender<PipeResponse>)>,
    last_rejected: Option<(ErrorCode, String)>,
    stopping_ready: bool,
    feishu: Arc<FeishuNotifier>,
    recent_toasts: VecDeque<ToastNotificationEvent>,
    toast_seq: u64,
    leak_shield: LeakShieldStatus,
    leak_shield_syncer: LeakShieldSyncFn,
    mihomo: MihomoStatus,
}

impl RealEngineActor {
    /// Bootstraps WAL startup recovery, config migration, 24h timeline, and `GuardEngine` state.
    pub fn bootstrap(
        data_dir: PathBuf,
        driver: Arc<dyn PlatformDriver>,
        probe_runner: Arc<dyn ProbeRunner>,
        recovery_executor: Arc<dyn RecoveryExecutor>,
        probe_event_tx: SyncSender<CoordinatorEvent>,
    ) -> BootstrappedActor {
        let now = now_unix_secs();
        let journal = JournalStore::new(&data_dir);
        let heal_report = journal::heal_on_startup(&journal, &*recovery_executor);

        let config_store = ConfigStore::new(&data_dir);
        let _ = config_store.backup_legacy_once();
        let (cfg, corrupt_err) = match config_store.load_readonly() {
            LoadedConfig::NotFound => (Config::default(), None),
            LoadedConfig::Loaded(outcome) => (outcome.config, None),
            LoadedConfig::Corrupt { error, raw } => {
                let _ = config_store.backup_corrupt_once(&raw);
                (Config::default(), Some(error))
            }
        };

        let timeline_path = data_dir.join(TIMELINE_FILE);
        let timeline = TimelineAggregator::load_from(&timeline_path, BUCKETS_48);
        let caps = driver.capabilities();

        let mut engine = EngineState::new(cfg, caps.app_quarantine, caps.global_cut, now);
        engine.timeline = timeline;

        let disarmed_reason = disarm::read_disarmed(&data_dir).ok().flatten();
        let wal_pending = !heal_report.ok || !heal_report.verified;
        let wal_corrupt = heal_report.status == HealStatus::CorruptJournal;
        let last_error = if wal_pending {
            Some(heal_report.summary.clone())
        } else {
            corrupt_err
        };

        let (next_engine, _boot_cmds) = GuardEngine::step(
            engine,
            EngineEvent::Bootstrap {
                wal_pending,
                wal_corrupt,
                disarmed_reason,
                last_error,
            },
            now,
        );
        engine = next_engine;

        let process_scanner = Arc::new(ProcessScanner::new(Duration::from_secs(5)));
        let init_procs = if caps.process_guard {
            process_scanner.refresh()
        } else {
            process_scanner.cached_snapshot()
        };
        let init_fw_query_ok = caps.app_quarantine && heal_report.verified;
        let cached_agents = build_agent_statuses(
            &engine.config,
            &init_procs,
            &*driver,
            &[],
            engine.tripped.as_ref(),
        );
        let mut init_ag_proxy = driver.inspect_antigravity_proxy(
            engine.config.proxy_port,
            engine.config.last_seen_antigravity_version.as_deref(),
            &init_procs,
            now,
        );
        if engine.lifecycle == Lifecycle::Unconfigured {
            init_ag_proxy.version_changed_from = None;
        }

        let (probe_tx, probe_rx) = mpsc::sync_channel::<ProbeJob>(16);
        let worker_driver = driver.clone();
        let worker_runner = probe_runner.clone();
        let event_tx = probe_event_tx.clone();
        let worker_tx = probe_event_tx;

        let probe_worker = std::thread::Builder::new()
            .name("cg-probe-worker".to_string())
            .spawn(move || {
                while let Ok(job) = probe_rx.recv() {
                    let ts = now_unix_secs();
                    let (access, probes) = worker_runner.inspect_and_probe(
                        &*worker_driver,
                        &job.cfg,
                        job.cfg_rev,
                        &job.targets,
                        job.enforce_access_path,
                        job.skip_network_probes,
                        ts,
                    );
                    let _ = worker_tx.send(CoordinatorEvent::RoundFinished {
                        cfg_rev: job.cfg_rev,
                        runtime_epoch: job.runtime_epoch,
                        purpose: job.purpose,
                        access,
                        probes,
                        now_secs: now_unix_secs(),
                    });
                }
            })
            .expect("failed to spawn probe worker thread");

        let feishu = Arc::new(FeishuNotifier::load(&data_dir));
        if let Some(env_backup) = diagnostics::load_env_backup(&data_dir) {
            engine.env_applied = Some(env_backup.applied);
        }
        let init_shield = if caps.app_quarantine {
            leak_shield_win::inspect_leak_shield()
        } else {
            LeakShieldStatus::default()
        };
        let mut actor = Self {
            engine,
            driver,
            probe_runner,
            recovery_executor,
            journal,
            active_journal: None,
            config_store,
            timeline_path,
            data_dir,
            process_scanner: process_scanner.clone(),
            cached_agents,
            event_tx,
            probe_tx,
            _probe_worker: Some(probe_worker),
            recheck_waiters: Vec::new(),
            launch_waiters: Vec::new(),
            last_rejected: None,
            stopping_ready: false,
            feishu,
            recent_toasts: VecDeque::new(),
            toast_seq: 0,
            leak_shield: init_shield,
            leak_shield_syncer: Arc::new(leak_shield_win::sync_leak_shield),
            mihomo: MihomoStatus::default(),
        };

        actor.step_and_run(
            EngineEvent::AntigravityProxyUpdated {
                status: init_ag_proxy,
            },
            now,
        );
        let init_local = local_client_versions();
        hydrate_local_updates(
            &mut actor.engine.updates,
            &actor.engine.version,
            &actor.engine.antigravity_proxy,
            &init_local,
        );
        let init_self_check = build_defense_self_check(
            &actor.engine.config,
            &*actor.driver,
            &actor.journal,
            init_fw_query_ok,
            &actor.engine.antigravity_proxy,
            now,
        );
        actor.step_and_run(
            EngineEvent::SelfCheckUpdated {
                self_check: init_self_check,
            },
            now,
        );
        let initial_snapshot = actor.build_snapshot(now);

        BootstrappedActor {
            actor,
            initial_snapshot,
            heal_report,
            process_scanner,
        }
    }

    #[cfg(test)]
    fn with_leak_shield_syncer(mut self, syncer: LeakShieldSyncFn) -> Self {
        self.leak_shield_syncer = syncer;
        self
    }

    fn sync_leak_shield_rules(&mut self, now: u64) -> Result<OperationReceipt, PlatformError> {
        let mut exes = Vec::new();
        for agent in &self.engine.config.guarded_agents {
            for p in self.driver.discover_agent_exes(agent).unwrap_or_default() {
                if !exes.contains(&p) {
                    exes.push(p);
                }
            }
        }
        let status = (self.leak_shield_syncer)(
            &exes,
            self.engine.config.leak_shield_quic,
            self.engine.config.leak_shield_dns_doh,
            self.engine.config.leak_shield_ipv6,
        )?;
        let summary = status.summary.clone();
        self.leak_shield = status;
        let mut receipt =
            OperationReceipt::new(format!("shield-sync-{now}"), OperationStatus::Verified);
        receipt.verified_scope = "leak_shield".into();
        receipt.push_item("leak_shield", OperationStatus::Verified, summary.clone());
        self.engine.push_log(
            now,
            LogLevel::Audit,
            "shield",
            &format!("同步 4 维防泄露护盾：{summary}"),
        );
        Ok(receipt)
    }

    fn build_snapshot(&self, now: u64) -> GuardSnapshot {
        let mut snap = self.engine.to_snapshot(now, self.cached_agents.clone());
        snap.recent_toasts = self.recent_toasts.iter().cloned().collect();
        snap.feishu = self.feishu.status();
        snap.leak_shield = self.leak_shield.clone();
        snap.mihomo = self.mihomo.clone();
        snap
    }

    fn publish_snapshot(&self, snapshot_store: &SnapshotStoreRef<'_>, now: u64) -> GuardSnapshot {
        let snap = self.build_snapshot(now);
        snapshot_store.replace(snap.clone());
        snap
    }

    fn step_and_run(&mut self, event: EngineEvent, now: u64) {
        let state = std::mem::replace(
            &mut self.engine,
            EngineState::new(Config::default(), false, false, now),
        );
        let (next_state, cmds) = GuardEngine::step(state, event, now);
        self.engine = next_state;
        self.execute_commands(cmds, now);
    }

    fn execute_commands(&mut self, cmds: Vec<EffectCommand>, now: u64) {
        for cmd in cmds {
            match cmd {
                EffectCommand::ResolveAccessAndProbe {
                    cfg_rev,
                    runtime_epoch,
                    purpose,
                    targets,
                    enforce_access_path,
                    skip_network_probes,
                } => {
                    let job = ProbeJob {
                        cfg: self.engine.config.clone(),
                        cfg_rev,
                        runtime_epoch,
                        purpose,
                        targets,
                        enforce_access_path,
                        skip_network_probes,
                    };
                    if self.probe_tx.try_send(job).is_err() {
                        self.engine.push_log(
                            now,
                            LogLevel::Warn,
                            "probe",
                            "probe worker queue saturated; skipping duplicate round",
                        );
                    }
                }
                EffectCommand::SyncLockdown {
                    want,
                    manual,
                    agents,
                } => {
                    self.run_sync_lockdown(want, manual, &agents, now);
                }
                EffectCommand::ExecuteIsolation {
                    tx_id,
                    runtime_epoch,
                    agents,
                    kill_on_fail,
                    kill_cli_on_fail,
                    quarantine_on_fail,
                    cut_mode,
                    reason,
                    failing_ids: _,
                } => {
                    self.run_isolation(
                        &tx_id,
                        runtime_epoch,
                        &agents,
                        kill_on_fail,
                        kill_cli_on_fail,
                        quarantine_on_fail,
                        cut_mode,
                        &reason,
                        now,
                    );
                }
                EffectCommand::KillGuardedAgents {
                    runtime_epoch: _,
                    agents,
                    include_claude_cli,
                    reason: _,
                } => {
                    for agent in &agents {
                        let _ = self.driver.kill_gui_agent(agent);
                    }
                    if include_claude_cli {
                        for cli_id in paired_clis_for_agents(&agents) {
                            let _ = self.driver.kill_cli_agent(cli_id);
                        }
                    }
                }
                EffectCommand::ExecuteFlowANetworkRestore {
                    tx_id,
                    runtime_epoch,
                    agents,
                } => {
                    self.run_flow_a_network_restore(&tx_id, runtime_epoch, &agents, now);
                }
                EffectCommand::ExecuteFlowAAppRelease {
                    tx_id,
                    runtime_epoch,
                } => {
                    self.run_flow_a_app_release(&tx_id, runtime_epoch, now);
                }
                EffectCommand::ExecuteFlowBDisarmRestore {
                    tx_id,
                    runtime_epoch,
                    reason,
                } => {
                    self.run_flow_b_restore(&tx_id, runtime_epoch, &reason, now);
                }
                EffectCommand::ClearDisarmMarker => {
                    let res = disarm::clear_disarmed(&self.data_dir);
                    self.step_and_run(
                        EngineEvent::RearmPersisted {
                            ok: res.is_ok(),
                            error: res.err(),
                        },
                        now,
                    );
                }
                EffectCommand::PersistConfig {
                    config,
                    target_cfg_rev: _,
                } => match self.config_store.save_verified(&config) {
                    Ok(saved) => {
                        self.step_and_run(
                            EngineEvent::ConfigPersisted {
                                ok: true,
                                config: Some(saved),
                                error: None,
                            },
                            now,
                        );
                    }
                    Err(err) => {
                        self.step_and_run(
                            EngineEvent::ConfigPersisted {
                                ok: false,
                                config: None,
                                error: Some(err),
                            },
                            now,
                        );
                    }
                },
                EffectCommand::CommitWal { .. } => {
                    if let Some(mut tx) = self.active_journal.take() {
                        let _ = self.journal.commit_tx(&mut tx);
                    }
                }
                EffectCommand::ClearWal => {
                    self.active_journal = None;
                    let _ = self.journal.clear();
                }
                EffectCommand::PersistTimeline => {
                    let _ = self.engine.timeline.save_to(&self.timeline_path);
                }
                EffectCommand::Notify { class, title, body } => {
                    if self.engine.config.notify.is_on(&class) {
                        let safe_body = cg_core::redact::redact(
                            &body,
                            self.engine.config.notify.include_egress,
                        );
                        // Always enqueue into the Session-1 GUI toast relay ring so Session-0
                        // Windows Service notifications reliably surface on the user's desktop.
                        self.toast_seq = self.toast_seq.saturating_add(1);
                        if self.recent_toasts.len() >= 16 {
                            self.recent_toasts.pop_front();
                        }
                        self.recent_toasts.push_back(ToastNotificationEvent {
                            seq: self.toast_seq,
                            timestamp: now,
                            class: class.clone(),
                            title: title.clone(),
                            body: safe_body.clone(),
                        });

                        if !access_win::is_session_zero() {
                            let drv = self.driver.clone();
                            let t_title = title.clone();
                            let t_body = safe_body.clone();
                            std::thread::spawn(move || {
                                let _ = drv.send_toast(&t_title, &t_body);
                            });
                        }

                        if self.feishu.enqueue(&class, &title, &safe_body) {
                            let feishu = self.feishu.clone();
                            let policy = NetworkPolicy::direct();
                            std::thread::spawn(move || {
                                let _ = feishu.flush_due(&policy);
                            });
                        }
                    }
                }
                EffectCommand::AuditLog { .. } => {}
                EffectCommand::RequestRejected { code, reason } => {
                    self.last_rejected = Some((code, reason));
                }
                EffectCommand::ReadyToExit => {
                    self.stopping_ready = true;
                }
            }
        }
    }

    fn run_sync_lockdown(&mut self, want: bool, manual: bool, agents: &[String], now: u64) {
        let mut receipt =
            OperationReceipt::new(format!("lockdown-{}", now), OperationStatus::Unknown);

        if want {
            let mut agent_exes = Vec::new();
            let mut steps = Vec::new();
            let mut step_id = 1u32;
            for agent in agents {
                let exes = self.driver.discover_agent_exes(agent).unwrap_or_default();
                if !exes.is_empty() {
                    let rule_name = firewall_com::lockdown_rule_name(agent);
                    for exe in &exes {
                        steps.push(PlannedStep {
                            step_id,
                            description: format!("lockdown outbound {agent}"),
                            action: WalAction::AddFirewallRule {
                                rule_name: rule_name.clone(),
                                program: Some(exe.to_string_lossy().to_string()),
                                direction: FirewallDirection::Outbound,
                            },
                        });
                        step_id += 1;
                    }
                    agent_exes.push((agent.clone(), exes));
                }
            }

            if agent_exes.is_empty() {
                receipt.status = OperationStatus::NotApplicable;
                receipt.verified_scope = "no installed guarded exes".into();
                if manual {
                    self.step_and_run(
                        EngineEvent::ManualLockdownCompleted {
                            on: true,
                            receipt,
                            confirmed: true,
                            query_ok: true,
                            rules: 0,
                        },
                        now,
                    );
                } else {
                    self.step_and_run(
                        EngineEvent::LockdownSynced {
                            want: true,
                            confirmed: true,
                            query_ok: true,
                            rules: 0,
                        },
                        now,
                    );
                }
                return;
            }

            match self.journal.begin_tx(
                self.engine.runtime_epoch,
                TxKind::Lockdown,
                steps,
                BaselineState::default(),
            ) {
                Ok(tx) => self.active_journal = Some(tx),
                Err(err) => {
                    receipt.status = OperationStatus::Failed;
                    receipt.error = Some(format!("WAL begin_tx failed: {err}"));
                    if manual {
                        self.step_and_run(
                            EngineEvent::ManualLockdownCompleted {
                                on: true,
                                receipt,
                                confirmed: false,
                                query_ok: false,
                                rules: 0,
                            },
                            now,
                        );
                    } else {
                        self.step_and_run(
                            EngineEvent::LockdownSynced {
                                want: true,
                                confirmed: false,
                                query_ok: false,
                                rules: 0,
                            },
                            now,
                        );
                    }
                    return;
                }
            }

            let apply_res = firewall_com::apply_lockdown(self.driver.firewall(), &agent_exes);
            let status = firewall_com::lockdown_status(self.driver.firewall());
            let (confirmed, err_msg) = match apply_res {
                Ok(cov) if cov.complete() && status.query_ok && status.on => (true, None),
                Ok(cov) => (false, Some(cov.summary())),
                Err(e) => (false, Some(e.to_string())),
            };

            receipt.status = if confirmed {
                if let Some(mut tx) = self.active_journal.take() {
                    let _ = self.journal.commit_tx(&mut tx);
                }
                OperationStatus::Verified
            } else {
                OperationStatus::Failed
            };
            receipt.error = err_msg;

            if manual {
                self.step_and_run(
                    EngineEvent::ManualLockdownCompleted {
                        on: true,
                        receipt,
                        confirmed,
                        query_ok: status.query_ok,
                        rules: status.rules,
                    },
                    now,
                );
            } else {
                self.step_and_run(
                    EngineEvent::LockdownSynced {
                        want: true,
                        confirmed,
                        query_ok: status.query_ok,
                        rules: status.rules,
                    },
                    now,
                );
            }
        } else {
            let clear_res = firewall_com::clear_lockdown(self.driver.firewall());
            let status = firewall_com::lockdown_status(self.driver.firewall());
            let confirmed =
                matches!(clear_res, Ok(ref r) if r.clean()) && status.query_ok && !status.on;
            receipt.status = if confirmed {
                OperationStatus::Verified
            } else {
                OperationStatus::Failed
            };
            if let Err(err) = clear_res {
                receipt.error = Some(err.to_string());
            }
            if confirmed && !self.engine.protection.is_isolated() {
                let _ = self.journal.clear();
                self.active_journal = None;
            }
            if manual {
                self.step_and_run(
                    EngineEvent::ManualLockdownCompleted {
                        on: false,
                        receipt,
                        confirmed,
                        query_ok: status.query_ok,
                        rules: status.rules,
                    },
                    now,
                );
            } else {
                self.step_and_run(
                    EngineEvent::LockdownSynced {
                        want: false,
                        confirmed,
                        query_ok: status.query_ok,
                        rules: status.rules,
                    },
                    now,
                );
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn run_isolation(
        &mut self,
        tx_id: &str,
        runtime_epoch: u64,
        agents: &[String],
        kill_on_fail: bool,
        kill_cli_on_fail: bool,
        quarantine_on_fail: bool,
        cut_mode: CutMode,
        _reason: &str,
        now: u64,
    ) {
        let mut receipt = OperationReceipt::new(tx_id, OperationStatus::Unknown);
        let mut agent_exes: Vec<(String, Vec<PathBuf>)> = Vec::new();
        let mut planned_steps: Vec<PlannedStep> = Vec::new();
        let mut step_id = 1u32;

        if kill_on_fail && !agents.is_empty() {
            planned_steps.push(PlannedStep {
                step_id,
                description: "terminate guarded GUI processes".into(),
                action: WalAction::KillProcesses {
                    agent_ids: agents.to_vec(),
                },
            });
            step_id += 1;
        }

        if quarantine_on_fail {
            for agent in agents {
                let exes = self.driver.discover_agent_exes(agent).unwrap_or_default();
                let (out_name, in_name) = firewall_com::quarantine_rule_names(agent);
                for exe in &exes {
                    let exe_str = exe.to_string_lossy().to_string();
                    planned_steps.push(PlannedStep {
                        step_id,
                        description: format!("quarantine outbound {agent}"),
                        action: WalAction::AddFirewallRule {
                            rule_name: out_name.clone(),
                            program: Some(exe_str.clone()),
                            direction: FirewallDirection::Outbound,
                        },
                    });
                    step_id += 1;
                    planned_steps.push(PlannedStep {
                        step_id,
                        description: format!("quarantine inbound {agent}"),
                        action: WalAction::AddFirewallRule {
                            rule_name: in_name.clone(),
                            program: Some(exe_str),
                            direction: FirewallDirection::Inbound,
                        },
                    });
                    step_id += 1;
                }
                agent_exes.push((agent.clone(), exes));
            }
        }

        if cut_mode != CutMode::Off {
            planned_steps.push(PlannedStep {
                step_id,
                description: "apply global outbound firewall cut".into(),
                action: WalAction::GlobalFirewallCut {
                    rule_name: firewall_com::CUT_ALL_RULE.to_string(),
                },
            });
        }

        // Write & sync_all WAL BEFORE mutating processes/firewall.
        match self.journal.begin_tx(
            runtime_epoch,
            TxKind::Composite,
            planned_steps,
            BaselineState::default(),
        ) {
            Ok(tx) => self.active_journal = Some(tx),
            Err(err) => {
                receipt.status = OperationStatus::Failed;
                receipt.error = Some(format!("WAL persistence failed before isolation: {err}"));
                self.step_and_run(
                    EngineEvent::IsolationCompleted {
                        runtime_epoch,
                        receipt,
                        killed: 0,
                        cli_killed: 0,
                        firewall_rules: 0,
                        quarantined_agents: Vec::new(),
                        network_cut_applied: CutMode::Off,
                        network_note: "WAL write failed; no OS changes made".into(),
                    },
                    now,
                );
                return;
            }
        }

        let mut killed = 0u32;
        let mut cli_killed = 0u32;
        if kill_on_fail {
            let (gui_n, _, _) =
                kill_gui_list_with_receipt(&*self.driver, agents, "kill", &mut receipt);
            killed = gui_n;
            if kill_cli_on_fail {
                let cli_targets = paired_clis_for_agents(agents);
                let (cli_n, _, _) =
                    kill_cli_list_with_receipt(&*self.driver, &cli_targets, &mut receipt);
                cli_killed = cli_n;
            }
        }

        let mut total_fw_rules = 0u32;
        let mut quarantined_agents = Vec::new();
        let mut fw_all_ok = true;

        if quarantine_on_fail {
            for (agent, exes) in &agent_exes {
                if exes.is_empty() {
                    receipt.push_item(
                        format!("firewall:{agent}"),
                        OperationStatus::NotApplicable,
                        "no installed executables discovered",
                    );
                    continue;
                }
                match firewall_com::quarantine_agent(self.driver.firewall(), agent, exes) {
                    Ok(cov) if cov.complete() => {
                        total_fw_rules = total_fw_rules.saturating_add(cov.verified as u32);
                        quarantined_agents.push(agent.clone());
                        receipt.push_item(
                            format!("firewall:{agent}"),
                            OperationStatus::Verified,
                            cov.summary(),
                        );
                    }
                    Ok(cov) => {
                        fw_all_ok = false;
                        total_fw_rules = total_fw_rules.saturating_add(cov.verified as u32);
                        receipt.push_item(
                            format!("firewall:{agent}"),
                            if cov.query_ok {
                                OperationStatus::Partial
                            } else {
                                OperationStatus::Unknown
                            },
                            cov.summary(),
                        );
                    }
                    Err(PlatformError::Unsupported { detail, .. }) => {
                        receipt.push_item(
                            format!("firewall:{agent}"),
                            OperationStatus::Unsupported,
                            detail,
                        );
                    }
                    Err(err) => {
                        fw_all_ok = false;
                        receipt.push_item(
                            format!("firewall:{agent}"),
                            OperationStatus::Failed,
                            err.to_string(),
                        );
                    }
                }
            }
        }

        let mut network_cut_applied = CutMode::Off;
        let mut network_note = "仅应用级隔离".to_string();
        if cut_mode != CutMode::Off {
            match firewall_com::apply_global_cut(self.driver.firewall()) {
                Ok(cov) if cov.complete() => {
                    network_cut_applied = CutMode::Firewall;
                    total_fw_rules = total_fw_rules.saturating_add(cov.verified as u32);
                    network_note =
                        if cut_mode == CutMode::Nics && !self.driver.capabilities().nic_disable {
                            "已执行防火墙全局阻断（网卡禁用能力未启用）".into()
                        } else {
                            "已执行防火墙全局阻断".into()
                        };
                    receipt.push_item("global_cut", OperationStatus::Verified, cov.summary());
                }
                Ok(cov) => {
                    fw_all_ok = false;
                    network_note = cov.summary();
                    receipt.push_item(
                        "global_cut",
                        if cov.query_ok {
                            OperationStatus::Partial
                        } else {
                            OperationStatus::Unknown
                        },
                        cov.summary(),
                    );
                }
                Err(err) => {
                    fw_all_ok = false;
                    network_note = err.to_string();
                    receipt.push_item("global_cut", OperationStatus::Failed, err.to_string());
                }
            }
        }

        receipt.status = if fw_all_ok {
            OperationStatus::Verified
        } else {
            OperationStatus::Partial
        };
        if !fw_all_ok {
            receipt.error = Some("防火墙隔离核验未完全通过，已保留 WAL 账本".into());
        }

        self.step_and_run(
            EngineEvent::IsolationCompleted {
                runtime_epoch,
                receipt,
                killed,
                cli_killed,
                firewall_rules: total_fw_rules,
                quarantined_agents,
                network_cut_applied,
                network_note,
            },
            now,
        );
    }

    fn run_flow_a_network_restore(
        &mut self,
        tx_id: &str,
        runtime_epoch: u64,
        agents: &[String],
        now: u64,
    ) {
        let mut receipt = OperationReceipt::new(tx_id, OperationStatus::Unknown);
        let cut_clear = firewall_com::clear_global_cut(self.driver.firewall());
        let cut_ok = match cut_clear {
            Ok(report) if report.clean() => {
                receipt.push_item(
                    "clear_global_cut",
                    OperationStatus::Verified,
                    format!("removed {} global cut rule(s)", report.removed),
                );
                true
            }
            Ok(report) => {
                receipt.push_item(
                    "clear_global_cut",
                    if report.query_ok {
                        OperationStatus::Partial
                    } else {
                        OperationStatus::Unknown
                    },
                    format!("remaining={}", report.remaining),
                );
                false
            }
            Err(PlatformError::Unsupported { detail, .. }) => {
                receipt.push_item("clear_global_cut", OperationStatus::NotApplicable, detail);
                true
            }
            Err(err) => {
                receipt.push_item("clear_global_cut", OperationStatus::Failed, err.to_string());
                false
            }
        };

        let mut app_isolation_intact = true;
        if self.engine.network_isolation_supported && self.engine.config.quarantine_on_fail {
            let has_any_installed_exes = agents.iter().any(|a| {
                !self
                    .driver
                    .discover_agent_exes(a)
                    .unwrap_or_default()
                    .is_empty()
            });
            if has_any_installed_exes {
                match self.driver.firewall().enumerate_rules("ClaudeGuard Block") {
                    Ok(rules) => {
                        let active = rules.iter().filter(|r| r.enabled).count();
                        app_isolation_intact = active > 0;
                        receipt.push_item(
                            "verify_app_isolation",
                            if app_isolation_intact {
                                OperationStatus::Verified
                            } else {
                                OperationStatus::Failed
                            },
                            format!("{active} active app quarantine rule(s)"),
                        );
                    }
                    Err(err) => {
                        app_isolation_intact = false;
                        receipt.push_item(
                            "verify_app_isolation",
                            OperationStatus::Unknown,
                            err.to_string(),
                        );
                    }
                }
            }
        }

        receipt.status = if cut_ok && app_isolation_intact {
            OperationStatus::Verified
        } else {
            OperationStatus::Failed
        };
        if !app_isolation_intact {
            receipt.error = Some("应用级隔离规则不完整，拒绝开放业务网络".into());
        }

        self.step_and_run(
            EngineEvent::FlowANetworkRestored {
                runtime_epoch,
                receipt,
                app_isolation_intact,
            },
            now,
        );
    }

    fn run_flow_a_app_release(&mut self, tx_id: &str, runtime_epoch: u64, now: u64) {
        let mut receipt = OperationReceipt::new(tx_id, OperationStatus::Unknown);
        let mut all_ok = true;
        let agents = self.engine.config.guarded_agents.clone();

        for agent in &agents {
            match firewall_com::release_agent(self.driver.firewall(), agent) {
                Ok(report) if report.clean() => {
                    receipt.push_item(
                        format!("release:{agent}"),
                        OperationStatus::Verified,
                        format!("removed {} rule(s)", report.removed),
                    );
                }
                Ok(report) => {
                    all_ok = false;
                    receipt.push_item(
                        format!("release:{agent}"),
                        if report.query_ok {
                            OperationStatus::Partial
                        } else {
                            OperationStatus::Unknown
                        },
                        format!("remaining={}", report.remaining),
                    );
                }
                Err(PlatformError::Unsupported { detail, .. }) => {
                    receipt.push_item(
                        format!("release:{agent}"),
                        OperationStatus::NotApplicable,
                        detail,
                    );
                }
                Err(err) => {
                    all_ok = false;
                    receipt.push_item(
                        format!("release:{agent}"),
                        OperationStatus::Failed,
                        err.to_string(),
                    );
                }
            }
        }

        receipt.status = if all_ok {
            OperationStatus::Verified
        } else {
            OperationStatus::Failed
        };
        if !all_ok {
            receipt.error = Some("部分应用隔离规则清除未核验".into());
        }

        self.step_and_run(
            EngineEvent::FlowAAppReleaseCompleted {
                runtime_epoch,
                receipt,
            },
            now,
        );
    }

    fn run_flow_b_restore(&mut self, tx_id: &str, runtime_epoch: u64, reason: &str, now: u64) {
        let is_stopping = self
            .engine
            .pending_tx
            .as_ref()
            .is_some_and(|tx| tx.kind == PendingTxKind::StoppingRestore);

        let heal = journal::heal_offline(&self.journal, &*self.recovery_executor);
        if self.driver.capabilities().app_quarantine {
            if let Ok(removed) = leak_shield_win::clear_leak_shield() {
                if removed > 0 {
                    self.leak_shield = LeakShieldStatus::default();
                }
            }
        }
        if self.engine.env_applied.is_some()
            && diagnostics::rollback_env_alignment(&self.data_dir).is_ok()
        {
            self.engine.env_applied = None;
        }
        let mut receipt = OperationReceipt::new(
            tx_id,
            if heal.ok && heal.verified {
                OperationStatus::Verified
            } else if heal.verified {
                OperationStatus::Partial
            } else {
                OperationStatus::Failed
            },
        );
        for item in &heal.items {
            receipt.push_item(
                item.action.clone(),
                if item.ok {
                    OperationStatus::Verified
                } else {
                    OperationStatus::Failed
                },
                item.detail.clone(),
            );
        }
        receipt.remaining = heal.remaining_rules.clone();

        if !heal.ok || !heal.verified {
            receipt.error = Some(heal.summary.clone());
        } else if !is_stopping {
            if let Err(err) = disarm::mark_disarmed(&self.data_dir, reason) {
                receipt.status = OperationStatus::Failed;
                receipt.error = Some(err);
            }
        }

        if is_stopping {
            self.step_and_run(
                EngineEvent::StopRestoreCompleted {
                    runtime_epoch,
                    receipt,
                },
                now,
            );
        } else {
            self.step_and_run(
                EngineEvent::FlowBCompleted {
                    runtime_epoch,
                    receipt,
                    reason: reason.to_string(),
                },
                now,
            );
        }
    }

    fn flush_superseded_waiters(&mut self, snapshot: &GuardSnapshot) {
        let round = self.engine.active_round;
        let still_matching = round.is_some_and(|r| {
            r.cfg_rev == self.engine.cfg_rev && r.runtime_epoch == self.engine.runtime_epoch
        });
        if still_matching {
            return;
        }
        for tx in self.recheck_waiters.drain(..) {
            let _ = tx.send(PipeResponse::Error {
                code: ErrorCode::IllegalState,
                message: "recheck superseded by configuration or lifecycle change".into(),
                receipt: None,
            });
        }
        for (_, tx) in self.launch_waiters.drain(..) {
            let _ = tx.send(PipeResponse::LaunchGate {
                allowed: false,
                reason: "launch check superseded by configuration or lifecycle change".into(),
                snapshot: Some(Box::new(snapshot.clone())),
            });
        }
    }

    fn fulfill_round_waiters(&mut self, snapshot: &GuardSnapshot, now: u64) {
        for tx in self.recheck_waiters.drain(..) {
            let _ = tx.send(PipeResponse::Ack {
                receipt: self.engine.last_receipt.clone(),
                snapshot: Some(Box::new(snapshot.clone())),
            });
        }

        if !self.launch_waiters.is_empty() {
            let waiters = std::mem::take(&mut self.launch_waiters);
            let mut blocked_reason: Option<String> = None;
            for (agent_id, tx) in waiters {
                let decision = GuardEngine::evaluate_launch_gate_for_agent(
                    &self.engine,
                    agent_id.as_deref(),
                    now,
                );
                if !decision.allowed && blocked_reason.is_none() {
                    blocked_reason = Some(decision.reason.clone());
                }
                let _ = tx.send(PipeResponse::LaunchGate {
                    allowed: decision.allowed,
                    reason: decision.reason,
                    snapshot: Some(Box::new(snapshot.clone())),
                });
            }
            if let Some(reason) = blocked_reason {
                if self.engine.config.notify.is_on("launch_blocked") {
                    let safe_body =
                        cg_core::redact::redact(&reason, self.engine.config.notify.include_egress);
                    let drv = self.driver.clone();
                    std::thread::spawn(move || {
                        let _ = drv.send_toast("ClaudeGuard 已阻止启动", &safe_body);
                    });
                }
            }
        }
    }

    fn handle_pipe_request(
        &mut self,
        req: PipeRequest,
        reply: SyncSender<PipeResponse>,
        snapshot_store: &SnapshotStoreRef<'_>,
    ) {
        let now = now_unix_secs();
        self.last_rejected = None;

        match req {
            PipeRequest::GetSnapshot => {
                let snap = snapshot_store.read();
                let _ = reply.send(PipeResponse::Snapshot {
                    snapshot: Box::new(snap),
                });
            }
            PipeRequest::RecheckNow { target_id } => {
                if let Some(raw_tid) = target_id
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    if matches!(
                        self.engine.lifecycle,
                        Lifecycle::Stopping | Lifecycle::Maintenance
                    ) {
                        let _ = reply.send(PipeResponse::Error {
                            code: ErrorCode::IllegalState,
                            message: "当前生命周期不允许发起单目标复检".into(),
                            receipt: None,
                        });
                        return;
                    }
                    if self.engine.protection == ProtectionState::Recovering {
                        let _ = reply.send(PipeResponse::Error {
                            code: ErrorCode::Busy,
                            message: "恢复事务正在执行，请稍后再试".into(),
                            receipt: None,
                        });
                        return;
                    }
                    let Some(target) = self
                        .engine
                        .config
                        .targets
                        .iter()
                        .find(|t| t.id == raw_tid)
                        .cloned()
                    else {
                        let _ = reply.send(PipeResponse::Error {
                            code: ErrorCode::NotFound,
                            message: format!("未找到监控目标：{raw_tid}"),
                            receipt: None,
                        });
                        return;
                    };
                    if !target.enabled {
                        let _ = reply.send(PipeResponse::Error {
                            code: ErrorCode::ValidationFailed,
                            message: format!("目标「{}」当前已禁用，请先启用后再复检", target.name),
                            receipt: None,
                        });
                        return;
                    }

                    let cfg = self.engine.config.clone();
                    let cfg_rev = self.engine.cfg_rev;
                    let runtime_epoch = self.engine.runtime_epoch;
                    let enforce_access = self.engine.network_isolation_supported
                        && self.engine.config.enforce_access_path;
                    let skip_network = self.engine.lifecycle == Lifecycle::Unconfigured;
                    let driver = self.driver.clone();
                    let runner = self.probe_runner.clone();
                    let event_tx = self.event_tx.clone();
                    let tid = target.id.clone();

                    std::thread::spawn(move || {
                        let ts = now_unix_secs();
                        let (access, probes) = runner.inspect_and_probe(
                            &*driver,
                            &cfg,
                            cfg_rev,
                            &[target],
                            enforce_access,
                            skip_network,
                            ts,
                        );
                        let probe = probes
                            .into_iter()
                            .find(|(id, _)| id == &tid)
                            .map(|(_, p)| p)
                            .unwrap_or_else(|| ProbeResult::failed("未收到目标探测结果"));
                        let _ = event_tx.send(CoordinatorEvent::SingleTargetProbed {
                            cfg_rev,
                            runtime_epoch,
                            target_id: tid,
                            access,
                            probe,
                            now_secs: now_unix_secs(),
                            reply,
                        });
                    });
                    return;
                }

                self.step_and_run(
                    EngineEvent::StartRound {
                        purpose: CheckPurpose::Manual,
                    },
                    now,
                );
                if let Some((code, msg)) = self.last_rejected.take() {
                    let _ = reply.send(PipeResponse::Error {
                        code,
                        message: msg,
                        receipt: None,
                    });
                    return;
                }
                let snap = self.publish_snapshot(snapshot_store, now);
                if self.engine.checking {
                    self.recheck_waiters.push(reply);
                } else {
                    let _ = reply.send(PipeResponse::Ack {
                        receipt: self.engine.last_receipt.clone(),
                        snapshot: Some(Box::new(snap)),
                    });
                }
            }
            PipeRequest::SetPolicyPreset { preset } => {
                self.step_and_run(EngineEvent::SetPolicyPreset { preset }, now);
                let snap = self.publish_snapshot(snapshot_store, now);
                self.flush_superseded_waiters(&snap);
                self.send_mutation_reply(reply, snap);
            }
            PipeRequest::SaveConfig { config } => {
                let prev_shield = (
                    self.engine.config.leak_shield_quic,
                    self.engine.config.leak_shield_dns_doh,
                    self.engine.config.leak_shield_ipv6,
                    self.engine.config.guarded_agents.clone(),
                );
                self.step_and_run(EngineEvent::SaveConfig { next: config }, now);
                let next_shield = (
                    self.engine.config.leak_shield_quic,
                    self.engine.config.leak_shield_dns_doh,
                    self.engine.config.leak_shield_ipv6,
                    self.engine.config.guarded_agents.clone(),
                );
                if self.last_rejected.is_none()
                    && prev_shield != next_shield
                    && self.engine.lifecycle == Lifecycle::Armed
                    && self.driver.capabilities().app_quarantine
                {
                    match self.sync_leak_shield_rules(now) {
                        Ok(receipt) => {
                            self.engine.last_receipt = Some(receipt);
                        }
                        Err(err) => {
                            let detail = format!("保存配置后自动同步防泄露护盾规则失败：{err}");
                            self.engine.push_log(now, LogLevel::Warn, "shield", &detail);
                            let mut receipt = OperationReceipt::new(
                                format!("shield-sync-{now}"),
                                OperationStatus::Partial,
                            );
                            receipt.verified_scope = "leak_shield".into();
                            receipt.push_item("leak_shield", OperationStatus::Failed, detail);
                            self.engine.last_receipt = Some(receipt);
                        }
                    }
                }
                let snap = self.publish_snapshot(snapshot_store, now);
                self.flush_superseded_waiters(&snap);
                self.send_mutation_reply(reply, snap);
            }
            PipeRequest::Pause { duration_secs } => {
                self.step_and_run(EngineEvent::Pause { duration_secs }, now);
                let snap = self.publish_snapshot(snapshot_store, now);
                self.send_mutation_reply(reply, snap);
            }
            PipeRequest::SetManualLockdown { on } => {
                self.step_and_run(EngineEvent::SetManualLockdown { on }, now);
                let snap = self.publish_snapshot(snapshot_store, now);
                self.send_mutation_reply(reply, snap);
            }
            PipeRequest::RecoverSafeFlowA => {
                self.step_and_run(EngineEvent::RecoverSafeFlowA, now);
                let snap = self.publish_snapshot(snapshot_store, now);
                self.flush_superseded_waiters(&snap);
                self.send_mutation_reply(reply, snap);
            }
            PipeRequest::DisarmAndRestoreFlowB { reason } => {
                let reason_text = reason.unwrap_or_else(|| "用户显式停止保护并恢复".to_string());
                let was_unconfigured = self.engine.lifecycle == Lifecycle::Unconfigured;
                self.step_and_run(
                    EngineEvent::DisarmAndRestoreFlowB {
                        reason: reason_text.clone(),
                    },
                    now,
                );
                if was_unconfigured && self.last_rejected.is_none() {
                    let heal = journal::heal_offline(&self.journal, &*self.recovery_executor);
                    if heal.ok && heal.verified {
                        let _ = disarm::mark_disarmed(&self.data_dir, &reason_text);
                    }
                }
                let snap = self.publish_snapshot(snapshot_store, now);
                self.flush_superseded_waiters(&snap);
                self.send_mutation_reply(reply, snap);
            }
            PipeRequest::Rearm => {
                self.step_and_run(EngineEvent::Rearm, now);
                let snap = self.publish_snapshot(snapshot_store, now);
                self.flush_superseded_waiters(&snap);
                self.send_mutation_reply(reply, snap);
            }
            PipeRequest::CheckLaunchGate { agent_id } => {
                let decision = GuardEngine::evaluate_launch_gate_for_agent(
                    &self.engine,
                    agent_id.as_deref(),
                    now,
                );
                let snap = self.publish_snapshot(snapshot_store, now);
                if decision.allowed || !decision.requires_recheck {
                    if !decision.allowed
                        && self.engine.lifecycle == Lifecycle::Armed
                        && self.engine.config.notify.is_on("launch_blocked")
                    {
                        let safe_body = cg_core::redact::redact(
                            &decision.reason,
                            self.engine.config.notify.include_egress,
                        );
                        let drv = self.driver.clone();
                        std::thread::spawn(move || {
                            let _ = drv.send_toast("ClaudeGuard 已阻止启动", &safe_body);
                        });
                    }
                    let _ = reply.send(PipeResponse::LaunchGate {
                        allowed: decision.allowed,
                        reason: decision.reason,
                        snapshot: Some(Box::new(snap)),
                    });
                    return;
                }

                // Needs fresh Launch-purpose probe round before deciding.
                self.step_and_run(
                    EngineEvent::StartRound {
                        purpose: CheckPurpose::Launch,
                    },
                    now,
                );
                if let Some((_code, reason)) = self.last_rejected.take() {
                    let _ = reply.send(PipeResponse::LaunchGate {
                        allowed: false,
                        reason,
                        snapshot: Some(Box::new(snap)),
                    });
                    return;
                }
                let snap = self.publish_snapshot(snapshot_store, now);
                if self.engine.checking {
                    self.launch_waiters.push((agent_id, reply));
                } else {
                    let final_dec = GuardEngine::evaluate_launch_gate_for_agent(
                        &self.engine,
                        agent_id.as_deref(),
                        now,
                    );
                    let _ = reply.send(PipeResponse::LaunchGate {
                        allowed: final_dec.allowed,
                        reason: final_dec.reason,
                        snapshot: Some(Box::new(snap)),
                    });
                }
            }
            PipeRequest::SweepOrphans => {
                let mut receipt =
                    OperationReceipt::new(format!("sweep-{now}"), OperationStatus::Verified);
                match self.driver.sweep_all_orphans() {
                    Ok(report) => {
                        receipt.verified_scope = format!(
                            "scanned={}, killed={} (desktop={}, cli={})",
                            report.scanned, report.killed, report.desktop_killed, report.cli_killed
                        );
                        let item_detail = if !report.detail.is_empty() {
                            format!("{} [{}]", receipt.verified_scope, report.detail.join(", "))
                        } else if !report.note.is_empty() {
                            format!("{} ({})", receipt.verified_scope, report.note)
                        } else {
                            receipt.verified_scope.clone()
                        };
                        receipt.push_item(
                            "sweep_all_orphans",
                            OperationStatus::Verified,
                            item_detail.clone(),
                        );
                        self.engine.push_log(
                            now,
                            LogLevel::Info,
                            "sweep",
                            &format!("清理孤儿进程完成：{item_detail}"),
                        );
                    }
                    Err(PlatformError::Unsupported { detail, .. }) => {
                        receipt.status = OperationStatus::Unsupported;
                        receipt.push_item(
                            "sweep_all_orphans",
                            OperationStatus::Unsupported,
                            detail,
                        );
                    }
                    Err(err) => {
                        receipt.status = OperationStatus::Failed;
                        receipt.error = Some(err.to_string());
                        receipt.push_item(
                            "sweep_all_orphans",
                            OperationStatus::Failed,
                            err.to_string(),
                        );
                    }
                }
                self.engine.last_receipt = Some(receipt.clone());
                let snap = self.publish_snapshot(snapshot_store, now);
                let _ = reply.send(PipeResponse::Ack {
                    receipt: Some(receipt),
                    snapshot: Some(Box::new(snap)),
                });
            }
            PipeRequest::ProbeOnboarding => {
                let probe = self.run_probe_onboarding(now);
                let _ = reply.send(PipeResponse::OnboardingProbe { probe });
            }
            PipeRequest::CompleteOnboarding { config } => {
                self.step_and_run(EngineEvent::CompleteOnboarding { config }, now);
                let rejected = self.last_rejected.is_some();
                let err_empty = self.engine.last_error.is_empty();
                if !rejected && err_empty && self.engine.lifecycle == Lifecycle::Armed {
                    self.step_and_run(
                        EngineEvent::StartRound {
                            purpose: CheckPurpose::Monitor,
                        },
                        now,
                    );
                }
                let snap = self.publish_snapshot(snapshot_store, now);
                self.flush_superseded_waiters(&snap);
                self.send_mutation_reply(reply, snap);
            }
            PipeRequest::QueryLogs {
                since_ts,
                until_ts,
                limit,
                query,
            } => {
                let needle = query
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_ascii_lowercase);
                let matched: Vec<_> = self
                    .engine
                    .logs
                    .iter()
                    .filter(|entry| since_ts.is_none_or(|s| entry.timestamp >= s))
                    .filter(|entry| until_ts.is_none_or(|u| entry.timestamp <= u))
                    .filter(|entry| {
                        needle.as_ref().is_none_or(|q| {
                            entry.category.to_ascii_lowercase().contains(q)
                                || entry.message.to_ascii_lowercase().contains(q)
                        })
                    })
                    .cloned()
                    .collect();
                let total = matched.len();
                let cap = limit.unwrap_or(200).min(500);
                let start = total.saturating_sub(cap);
                let entries = matched[start..].to_vec();
                let _ = reply.send(PipeResponse::Logs { entries, total });
            }
            PipeRequest::CheckUpdates { component } => {
                let normalized_component = match parse_update_component_filter(component.as_deref())
                {
                    Ok((_, _, norm)) => norm,
                    Err(msg) => {
                        let _ = reply.send(PipeResponse::Error {
                            code: ErrorCode::InvalidRequest,
                            message: msg,
                            receipt: None,
                        });
                        return;
                    }
                };

                if self.engine.is_tripped() {
                    let _ = reply.send(PipeResponse::Error {
                        code: ErrorCode::IllegalState,
                        message: "当前处于熔断隔离态，为防止暴露真实出口已禁止联网检查更新".into(),
                        receipt: None,
                    });
                    return;
                }

                let driver = self.driver.clone();
                let cfg = self.engine.config.clone();
                let cfg_rev = self.engine.cfg_rev;
                let cg_version = self.engine.version.clone();
                let ag_proxy = self.engine.antigravity_proxy.clone();
                let prev_updates = self.engine.updates.clone();
                let event_tx = self.event_tx.clone();

                std::thread::Builder::new()
                    .name("cg-update-check".to_string())
                    .spawn(move || {
                        let ts = now_unix_secs();
                        let (_access, route) = resolve_access_and_route(
                            &*driver,
                            &cfg,
                            cfg_rev,
                            &cfg.targets,
                            cfg.enforce_access_path,
                            ts,
                        );
                        let summary = match route {
                            ProbeRoute::Skip(reason) => build_skipped_update_summary(
                                &prev_updates,
                                &cg_version,
                                &ag_proxy,
                                normalized_component.as_deref(),
                                &reason,
                                ts,
                            ),
                            route => driver.check_updates(
                                &route,
                                &cg_version,
                                &ag_proxy,
                                normalized_component.as_deref(),
                                &prev_updates,
                                ts,
                            ),
                        };
                        let _ = event_tx.send(CoordinatorEvent::UpdatesChecked {
                            summary: Box::new(summary),
                            component: normalized_component,
                            now_secs: now_unix_secs(),
                            reply: Some(reply),
                        });
                    })
                    .expect("failed to spawn update check worker thread");
            }
            PipeRequest::ForceKillAgent {
                agent_id,
                include_cli,
            } => {
                let (gui_targets, cli_targets): (Vec<String>, Vec<&'static str>) =
                    match agent_id.as_deref().map(str::trim) {
                        None => {
                            let mut guis = Vec::new();
                            for g in &self.engine.config.guarded_agents {
                                if !guis.contains(g) {
                                    guis.push(g.clone());
                                }
                            }
                            let clis = if include_cli {
                                vec!["claude-code", "codex"]
                            } else {
                                Vec::new()
                            };
                            (guis, clis)
                        }
                        Some(raw) => match raw.to_ascii_lowercase().as_str() {
                            "claude" => (
                                vec!["claude".to_string()],
                                if include_cli {
                                    vec!["claude-code"]
                                } else {
                                    Vec::new()
                                },
                            ),
                            "chatgpt" => (
                                vec!["chatgpt".to_string()],
                                if include_cli {
                                    vec!["codex"]
                                } else {
                                    Vec::new()
                                },
                            ),
                            "antigravity" => (vec!["antigravity".to_string()], Vec::new()),
                            "claude-code" => (Vec::new(), vec!["claude-code"]),
                            "codex" => (Vec::new(), vec!["codex"]),
                            "gemini" => (Vec::new(), vec!["gemini"]),
                            _ => {
                                let _ = reply.send(PipeResponse::Error {
                                    code: ErrorCode::InvalidRequest,
                                    message: format!("未知的应用或 CLI 标识：{raw}"),
                                    receipt: None,
                                });
                                return;
                            }
                        },
                    };

                let mut receipt =
                    OperationReceipt::new(format!("force-kill-{now}"), OperationStatus::Unknown);
                let (gui_killed, gui_failed, gui_supported) = kill_gui_list_with_receipt(
                    &*self.driver,
                    &gui_targets,
                    "kill_gui",
                    &mut receipt,
                );
                let (cli_killed, cli_failed, cli_supported) =
                    kill_cli_list_with_receipt(&*self.driver, &cli_targets, &mut receipt);

                let any_failed = gui_failed || cli_failed;
                let any_supported = gui_supported || cli_supported;
                receipt.verified_scope =
                    format!("gui_killed={gui_killed}, cli_killed={cli_killed}");
                receipt.status = if gui_targets.is_empty() && cli_targets.is_empty() {
                    OperationStatus::NotApplicable
                } else if any_failed {
                    let failed_msgs: Vec<String> = receipt
                        .items
                        .iter()
                        .filter(|i| i.status == OperationStatus::Failed)
                        .map(|i| format!("{}: {}", i.name, i.detail))
                        .collect();
                    receipt.error = Some(failed_msgs.join("；"));
                    OperationStatus::Failed
                } else if !any_supported {
                    OperationStatus::Unsupported
                } else {
                    OperationStatus::Verified
                };

                let procs = if self.driver.capabilities().process_guard {
                    self.process_scanner.refresh()
                } else {
                    self.process_scanner.cached_snapshot()
                };
                let fw_rules = self
                    .driver
                    .firewall()
                    .enumerate_rules("ClaudeGuard")
                    .unwrap_or_default();
                self.cached_agents = build_agent_statuses(
                    &self.engine.config,
                    &procs,
                    &*self.driver,
                    &fw_rules,
                    self.engine.tripped.as_ref(),
                );

                self.engine.push_log(
                    now,
                    LogLevel::Audit,
                    "kill",
                    &format!(
                        "强制终止代理（target={}，include_cli={}）：GUI {} 个，CLI {} 个",
                        agent_id.as_deref().unwrap_or("all"),
                        include_cli,
                        gui_killed,
                        cli_killed
                    ),
                );
                self.engine.last_receipt = Some(receipt.clone());
                let snap = self.publish_snapshot(snapshot_store, now);
                let _ = reply.send(PipeResponse::Ack {
                    receipt: Some(receipt),
                    snapshot: Some(Box::new(snap)),
                });
            }
            PipeRequest::SaveFeishuConfig {
                enabled,
                webhook,
                secret,
                clear_secret,
            } => match self
                .feishu
                .save_config(enabled, webhook, secret, clear_secret)
            {
                Ok(st) => {
                    let detail = if st.enabled {
                        format!("飞书推送已启用（{}）", st.webhook_masked)
                    } else {
                        "飞书推送已保存为关闭状态".into()
                    };
                    let mut receipt = OperationReceipt::new(
                        format!("feishu-save-{now}"),
                        OperationStatus::Verified,
                    );
                    receipt.verified_scope = "feishu.config".into();
                    receipt.push_item("feishu_config", OperationStatus::Verified, detail.clone());
                    self.engine
                        .push_log(now, LogLevel::Audit, "notify", &detail);
                    self.engine.last_receipt = Some(receipt.clone());
                    let snap = self.publish_snapshot(snapshot_store, now);
                    let _ = reply.send(PipeResponse::Ack {
                        receipt: Some(receipt),
                        snapshot: Some(Box::new(snap)),
                    });
                }
                Err(msg) => {
                    let _ = reply.send(PipeResponse::Error {
                        code: ErrorCode::ValidationFailed,
                        message: msg,
                        receipt: None,
                    });
                }
            },
            PipeRequest::TestFeishu { webhook, secret } => {
                let feishu = self.feishu.clone();
                let event_tx = self.event_tx.clone();
                let policy = NetworkPolicy::direct();
                std::thread::spawn(move || {
                    let result = feishu.send_test(&policy, webhook.as_deref(), secret.as_deref());
                    let _ = event_tx.send(CoordinatorEvent::FeishuTestFinished {
                        result,
                        now_secs: now_unix_secs(),
                        reply,
                    });
                });
            }
            PipeRequest::SyncLeakShield => {
                if !self.driver.capabilities().app_quarantine {
                    let _ = reply.send(PipeResponse::Error {
                        code: ErrorCode::Unsupported,
                        message: "当前平台不支持防火墙防泄露护盾规则".into(),
                        receipt: None,
                    });
                    return;
                }
                match self.sync_leak_shield_rules(now) {
                    Ok(receipt) => {
                        self.engine.last_receipt = Some(receipt.clone());
                        let snap = self.publish_snapshot(snapshot_store, now);
                        let _ = reply.send(PipeResponse::Ack {
                            receipt: Some(receipt),
                            snapshot: Some(Box::new(snap)),
                        });
                    }
                    Err(err) => {
                        let _ = reply.send(PipeResponse::Error {
                            code: ErrorCode::IoFailed,
                            message: format!("同步防泄露护盾规则失败：{err}"),
                            receipt: None,
                        });
                    }
                }
            }
            PipeRequest::SwitchProxyNode {
                group,
                node,
                close_connections,
            } => {
                let event_tx = self.event_tx.clone();
                std::thread::spawn(move || {
                    let result = mihomo_win::switch_mihomo_node(&group, &node, close_connections);
                    let mihomo = mihomo_win::inspect_mihomo();
                    let _ = event_tx.send(CoordinatorEvent::MihomoSwitchFinished {
                        result,
                        mihomo,
                        now_secs: now_unix_secs(),
                        reply,
                    });
                });
            }
            PipeRequest::RepairAntigravityProxy => {
                if self.engine.is_tripped() {
                    let _ = reply.send(PipeResponse::Error {
                        code: ErrorCode::IllegalState,
                        message: "当前处于熔断隔离态，请先切回合规节点并复检解封后再执行热修复下载"
                            .into(),
                        receipt: None,
                    });
                    return;
                }
                let (_access, route) = resolve_access_and_route(
                    &*self.driver,
                    &self.engine.config,
                    self.engine.cfg_rev,
                    &self.engine.config.targets,
                    self.engine.config.enforce_access_path,
                    now,
                );
                let proxy_port = self.engine.config.proxy_port;
                let event_tx = self.event_tx.clone();
                std::thread::spawn(move || {
                    let res =
                        antigravity_proxy_win::repair_antigravity_proxy(&route, proxy_port, None)
                            .map(|r| r.summary);
                    let _ = event_tx.send(CoordinatorEvent::AntigravityRepairFinished {
                        result: res,
                        now_secs: now_unix_secs(),
                        reply,
                    });
                });
            }
            PipeRequest::ApplyEnvAlignment {
                align_tz,
                align_location,
            } => {
                let place = self
                    .engine
                    .target_statuses
                    .iter()
                    .find(|t| t.state == crate::protocol::TargetState::Pass)
                    .or_else(|| {
                        self.engine
                            .target_statuses
                            .iter()
                            .find(|t| t.country.is_some() || t.colo.is_some())
                    })
                    .and_then(|t| {
                        cg_core::geo::resolve(t.colo.as_deref(), t.country.as_deref()).or_else(
                            || match t.country.as_deref() {
                                Some("US") => cg_core::geo::by_colo("LAX"),
                                _ => None,
                            },
                        )
                    });
                let target_city = place.map(|p| p.city);
                let target_tz = place.map(|p| p.tz);
                let target_coords = place.map(|p| (p.lat, p.lon));
                match diagnostics::apply_env_alignment(
                    &self.data_dir,
                    target_city,
                    target_tz,
                    target_coords,
                    align_tz,
                    align_location,
                    now,
                ) {
                    Ok((applied, detail)) => {
                        let env_info = self.driver.read_env_info().unwrap_or_default();
                        let env_check = envcheck::evaluate(
                            &self.engine.config,
                            env_info,
                            &self.engine.target_statuses,
                        );
                        self.step_and_run(
                            EngineEvent::EnvUpdated {
                                check: env_check,
                                applied: Some(applied),
                            },
                            now,
                        );
                        let mut receipt = OperationReceipt::new(
                            format!("env-align-{now}"),
                            OperationStatus::Verified,
                        );
                        receipt.verified_scope = "env.alignment".into();
                        receipt.push_item(
                            "env_alignment",
                            OperationStatus::Verified,
                            detail.clone(),
                        );
                        self.engine.push_log(
                            now,
                            LogLevel::Audit,
                            "env",
                            &format!("系统环境对齐完成：{detail}"),
                        );
                        self.engine.last_receipt = Some(receipt.clone());
                        let snap = self.publish_snapshot(snapshot_store, now);
                        let _ = reply.send(PipeResponse::Ack {
                            receipt: Some(receipt),
                            snapshot: Some(Box::new(snap)),
                        });
                    }
                    Err(msg) => {
                        let _ = reply.send(PipeResponse::Error {
                            code: ErrorCode::IoFailed,
                            message: msg,
                            receipt: None,
                        });
                    }
                }
            }
            PipeRequest::RollbackEnvAlignment => {
                match diagnostics::rollback_env_alignment(&self.data_dir) {
                    Ok(detail) => {
                        let env_info = self.driver.read_env_info().unwrap_or_default();
                        let env_check = envcheck::evaluate(
                            &self.engine.config,
                            env_info,
                            &self.engine.target_statuses,
                        );
                        self.step_and_run(
                            EngineEvent::EnvUpdated {
                                check: env_check,
                                applied: None,
                            },
                            now,
                        );
                        let mut receipt = OperationReceipt::new(
                            format!("env-rollback-{now}"),
                            OperationStatus::Verified,
                        );
                        receipt.verified_scope = "env.rollback".into();
                        receipt.push_item(
                            "env_rollback",
                            OperationStatus::Verified,
                            detail.clone(),
                        );
                        self.engine.push_log(
                            now,
                            LogLevel::Audit,
                            "env",
                            &format!("系统环境回滚完成：{detail}"),
                        );
                        self.engine.last_receipt = Some(receipt.clone());
                        let snap = self.publish_snapshot(snapshot_store, now);
                        let _ = reply.send(PipeResponse::Ack {
                            receipt: Some(receipt),
                            snapshot: Some(Box::new(snap)),
                        });
                    }
                    Err(msg) => {
                        let _ = reply.send(PipeResponse::Error {
                            code: ErrorCode::IoFailed,
                            message: msg,
                            receipt: None,
                        });
                    }
                }
            }
            PipeRequest::ExportDiagnostics => {
                let snap = self.build_snapshot(now);
                match diagnostics::export_redacted_diagnostics_zip(&self.data_dir, &snap, now, None)
                {
                    Ok(path) => {
                        let path_s = path.to_string_lossy().to_string();
                        let mut receipt = OperationReceipt::new(
                            format!("diag-export-{now}"),
                            OperationStatus::Verified,
                        );
                        receipt.verified_scope = path_s.clone();
                        receipt.push_item(
                            "diagnostics_zip",
                            OperationStatus::Verified,
                            format!("已导出脱敏诊断包：{path_s}"),
                        );
                        self.engine.push_log(
                            now,
                            LogLevel::Audit,
                            "diagnostics",
                            &format!("导出脱敏诊断压缩包：{path_s}"),
                        );
                        self.engine.last_receipt = Some(receipt.clone());
                        let next_snap = self.publish_snapshot(snapshot_store, now);
                        let _ = reply.send(PipeResponse::Ack {
                            receipt: Some(receipt),
                            snapshot: Some(Box::new(next_snap)),
                        });
                    }
                    Err(msg) => {
                        let _ = reply.send(PipeResponse::Error {
                            code: ErrorCode::IoFailed,
                            message: msg,
                            receipt: None,
                        });
                    }
                }
            }
        }
    }

    fn send_mutation_reply(&mut self, reply: SyncSender<PipeResponse>, snap: GuardSnapshot) {
        if let Some((code, message)) = self.last_rejected.take() {
            let _ = reply.send(PipeResponse::Error {
                code,
                message,
                receipt: self.engine.last_receipt.clone(),
            });
            return;
        }
        if !self.engine.last_error.is_empty()
            && (self.engine.protection == ProtectionState::Degraded
                || self.engine.last_error.contains("失败"))
        {
            let _ = reply.send(PipeResponse::Error {
                code: ErrorCode::IoFailed,
                message: self.engine.last_error.clone(),
                receipt: self.engine.last_receipt.clone(),
            });
            return;
        }
        let receipt = self.engine.last_receipt.clone().or_else(|| {
            Some(OperationReceipt::new(
                format!("ack-{}", snap.runtime_epoch),
                OperationStatus::Verified,
            ))
        });
        let _ = reply.send(PipeResponse::Ack {
            receipt,
            snapshot: Some(Box::new(snap)),
        });
    }

    fn run_probe_onboarding(&self, now: u64) -> OnboardingProbeResult {
        let hosts: Vec<String> = self
            .engine
            .config
            .targets
            .iter()
            .filter(|t| t.enabled)
            .map(|t| t.host().to_ascii_lowercase())
            .filter(|h| !h.is_empty())
            .collect();
        let (access_ev, probe_route) = match self.driver.inspect_access_path(&hosts) {
            Ok((path, _)) => (
                path.to_protocol_evidence(now, self.engine.cfg_rev),
                probe_http::plan_probe_route(&path),
            ),
            Err(_) => (
                AccessEvidence {
                    level: AccessLevel::Unknown,
                    observed_at: now,
                    revision: self.engine.cfg_rev,
                    note: "无法读取接入路径".into(),
                    ..AccessEvidence::default()
                },
                ProbeRoute::Skip("unsupported".into()),
            ),
        };

        let detected_proxy_port = access_ev
            .proxy_addr
            .as_deref()
            .and_then(|addr| addr.rsplit_once(':'))
            .and_then(|(_, p)| p.parse::<u16>().ok())
            .or(Some(self.engine.config.proxy_port));

        let claude_target = self
            .engine
            .config
            .target("claude")
            .cloned()
            .unwrap_or_else(|| {
                cg_protocol::default_builtin_targets(&[], &[])
                    .into_iter()
                    .find(|t| t.id == "claude")
                    .expect("builtin claude target")
            });

        let probe = if access_ev.is_known() && !matches!(probe_route, ProbeRoute::Skip(_)) {
            let (_ev, mut list) = self.probe_runner.inspect_and_probe(
                &*self.driver,
                &self.engine.config,
                self.engine.cfg_rev,
                &[claude_target],
                self.engine.config.enforce_access_path,
                false,
                now,
            );
            list.pop().map(|(_, p)| p)
        } else {
            None
        };

        let mut installed_agents = Vec::new();
        for a in GUI_AGENTS {
            if !self
                .driver
                .discover_agent_exes(a.id)
                .unwrap_or_default()
                .is_empty()
            {
                installed_agents.push(a.id.to_string());
            }
        }

        onboarding::recommend(
            &access_ev,
            probe.as_ref(),
            detected_proxy_port,
            installed_agents,
        )
    }
}

type SnapshotStoreRef<'a> = crate::coordinator::SnapshotStore;

impl CoordinatorActor for RealEngineActor {
    fn on_event(&mut self, event: CoordinatorEvent, ctx: &CoordinatorContext<'_>) -> ActorControl {
        match event {
            CoordinatorEvent::Pipe { req, reply } => {
                self.handle_pipe_request(req, reply, ctx.snapshot);
            }
            CoordinatorEvent::Tick => {
                let now = now_unix_secs();
                self.step_and_run(EngineEvent::Tick, now);
                if self.feishu.status().queued > 0 {
                    let feishu = self.feishu.clone();
                    let policy = NetworkPolicy::direct();
                    std::thread::spawn(move || {
                        let _ = feishu.flush_due(&policy);
                    });
                }
                let _ = self.publish_snapshot(ctx.snapshot, now);
            }
            CoordinatorEvent::SingleTargetProbed {
                cfg_rev,
                runtime_epoch,
                target_id,
                access,
                probe,
                now_secs,
                reply,
            } => {
                self.step_and_run(
                    EngineEvent::TargetRechecked {
                        cfg_rev,
                        runtime_epoch,
                        target_id: target_id.clone(),
                        access,
                        probe,
                    },
                    now_secs,
                );
                let mut receipt = OperationReceipt::new(
                    format!("recheck-{target_id}-{now_secs}"),
                    OperationStatus::Verified,
                );
                receipt.verified_scope = format!("target:{target_id}");
                if let Some(st) = self
                    .engine
                    .target_statuses
                    .iter()
                    .find(|t| t.id == target_id)
                {
                    receipt.push_item(
                        &st.name,
                        OperationStatus::Verified,
                        format!("{:?} ({}ms)", st.state, st.latency_ms),
                    );
                }
                self.engine.last_receipt = Some(receipt.clone());
                let snap = self.publish_snapshot(ctx.snapshot, now_secs);
                let _ = reply.send(PipeResponse::Ack {
                    receipt: Some(receipt),
                    snapshot: Some(Box::new(snap)),
                });
            }
            CoordinatorEvent::FeishuTestFinished {
                result,
                now_secs,
                reply,
            } => match result {
                Ok(_) => {
                    let mut receipt = OperationReceipt::new(
                        format!("feishu-test-{now_secs}"),
                        OperationStatus::Verified,
                    );
                    receipt.verified_scope = "feishu.test".into();
                    receipt.push_item(
                        "feishu_test",
                        OperationStatus::Verified,
                        "脱敏测试卡片已成功送达飞书群机器人",
                    );
                    self.engine.push_log(
                        now_secs,
                        LogLevel::Audit,
                        "notify",
                        "飞书机器人脱敏连通性测试发送成功",
                    );
                    self.engine.last_receipt = Some(receipt.clone());
                    let snap = self.publish_snapshot(ctx.snapshot, now_secs);
                    let _ = reply.send(PipeResponse::Ack {
                        receipt: Some(receipt),
                        snapshot: Some(Box::new(snap)),
                    });
                }
                Err(msg) => {
                    self.engine.push_log(
                        now_secs,
                        LogLevel::Warn,
                        "notify",
                        &format!("飞书测试发送失败：{msg}"),
                    );
                    let _ = self.publish_snapshot(ctx.snapshot, now_secs);
                    let _ = reply.send(PipeResponse::Error {
                        code: ErrorCode::IoFailed,
                        message: msg,
                        receipt: None,
                    });
                }
            },
            CoordinatorEvent::AntigravityRepairFinished {
                result,
                now_secs,
                reply,
            } => match result {
                Ok(summary) => {
                    let procs = if self.driver.capabilities().process_guard {
                        self.process_scanner.refresh()
                    } else {
                        self.process_scanner.cached_snapshot()
                    };
                    let ag = self.driver.inspect_antigravity_proxy(
                        self.engine.config.proxy_port,
                        self.engine.config.last_seen_antigravity_version.as_deref(),
                        &procs,
                        now_secs,
                    );
                    self.step_and_run(
                        EngineEvent::AntigravityProxyUpdated { status: ag },
                        now_secs,
                    );
                    let mut receipt = OperationReceipt::new(
                        format!("ag-repair-{now_secs}"),
                        OperationStatus::Verified,
                    );
                    receipt.verified_scope = "antigravity_proxy".into();
                    receipt.push_item(
                        "antigravity_proxy",
                        OperationStatus::Verified,
                        summary.clone(),
                    );
                    self.engine
                        .push_log(now_secs, LogLevel::Audit, "antigravity", &summary);
                    self.engine.last_receipt = Some(receipt.clone());
                    let snap = self.publish_snapshot(ctx.snapshot, now_secs);
                    let _ = reply.send(PipeResponse::Ack {
                        receipt: Some(receipt),
                        snapshot: Some(Box::new(snap)),
                    });
                }
                Err(msg) => {
                    self.engine.push_log(
                        now_secs,
                        LogLevel::Warn,
                        "antigravity",
                        &format!("antigravity-proxy 一键热修复失败：{msg}"),
                    );
                    let _ = self.publish_snapshot(ctx.snapshot, now_secs);
                    let _ = reply.send(PipeResponse::Error {
                        code: ErrorCode::IoFailed,
                        message: msg,
                        receipt: None,
                    });
                }
            },
            CoordinatorEvent::MihomoSwitchFinished {
                result,
                mihomo,
                now_secs,
                reply,
            } => {
                self.mihomo = mihomo;
                match result {
                    Ok(detail) => {
                        let mut receipt = OperationReceipt::new(
                            format!("mihomo-switch-{now_secs}"),
                            OperationStatus::Verified,
                        );
                        receipt.verified_scope = "mihomo.node".into();
                        receipt.push_item("mihomo_node", OperationStatus::Verified, detail.clone());
                        self.engine
                            .push_log(now_secs, LogLevel::Audit, "mihomo", &detail);
                        if self.engine.is_tripped() {
                            self.step_and_run(EngineEvent::RecoverSafeFlowA, now_secs);
                        } else if self.engine.lifecycle == Lifecycle::Armed {
                            self.step_and_run(
                                EngineEvent::StartRound {
                                    purpose: CheckPurpose::Manual,
                                },
                                now_secs,
                            );
                        }
                        self.engine.last_receipt = Some(receipt.clone());
                        let snap = self.publish_snapshot(ctx.snapshot, now_secs);
                        let _ = reply.send(PipeResponse::Ack {
                            receipt: Some(receipt),
                            snapshot: Some(Box::new(snap)),
                        });
                    }
                    Err(msg) => {
                        self.engine.push_log(
                            now_secs,
                            LogLevel::Warn,
                            "mihomo",
                            &format!("切换 Mihomo 节点失败：{msg}"),
                        );
                        let _ = self.publish_snapshot(ctx.snapshot, now_secs);
                        let _ = reply.send(PipeResponse::Error {
                            code: ErrorCode::IoFailed,
                            message: msg,
                            receipt: None,
                        });
                    }
                }
            }
            CoordinatorEvent::RoundFinished {
                cfg_rev,
                runtime_epoch,
                purpose,
                access,
                probes,
                now_secs,
            } => {
                let accepted_round =
                    cfg_rev == self.engine.cfg_rev && runtime_epoch == self.engine.runtime_epoch;
                self.step_and_run(
                    EngineEvent::RoundCompleted {
                        cfg_rev,
                        runtime_epoch,
                        purpose,
                        access,
                        probes,
                    },
                    now_secs,
                );
                let snap = self.publish_snapshot(ctx.snapshot, now_secs);
                if accepted_round {
                    self.fulfill_round_waiters(&snap, now_secs);
                } else {
                    self.flush_superseded_waiters(&snap);
                }
            }
            CoordinatorEvent::Telemetry(bundle) => {
                self.cached_agents = bundle.agents;
                self.leak_shield = bundle.leak_shield;
                self.mihomo = bundle.mihomo;
                self.step_and_run(
                    EngineEvent::LeakUpdated {
                        report: bundle.leak,
                    },
                    bundle.now_secs,
                );
                self.step_and_run(
                    EngineEvent::EnvUpdated {
                        check: bundle.env,
                        applied: self.engine.env_applied.clone(),
                    },
                    bundle.now_secs,
                );
                self.step_and_run(
                    EngineEvent::AntigravityProxyUpdated {
                        status: bundle.antigravity_proxy,
                    },
                    bundle.now_secs,
                );
                self.step_and_run(
                    EngineEvent::SelfCheckUpdated {
                        self_check: bundle.self_check,
                    },
                    bundle.now_secs,
                );
                if let Some(upd) = bundle.updates {
                    merge_telemetry_updates(&mut self.engine.updates, upd);
                } else {
                    self.engine.updates.antigravity_proxy.installed_version = self
                        .engine
                        .antigravity_proxy
                        .injector_version
                        .as_deref()
                        .map(update_check::normalize_version)
                        .filter(|s| !s.is_empty());
                }
                let _ = self.publish_snapshot(ctx.snapshot, bundle.now_secs);
            }
            CoordinatorEvent::UpdatesChecked {
                summary,
                component,
                now_secs,
                reply,
            } => {
                if self.engine.is_tripped() {
                    if let Some(tx) = reply {
                        let _ = tx.send(PipeResponse::Error {
                            code: ErrorCode::IllegalState,
                            message: "当前处于熔断隔离态，为防止暴露真实出口已禁止联网检查更新"
                                .into(),
                            receipt: None,
                        });
                    }
                    return ActorControl::Continue;
                }

                let mut next_summary = *summary;
                let (check_cg, check_ag, normalized) =
                    parse_update_component_filter(component.as_deref())
                        .unwrap_or((true, true, None));
                let check_client = |id: &str| component_matches_filter(normalized.as_deref(), id);
                if !check_cg {
                    next_summary.claudeguard = self.engine.updates.claudeguard.clone();
                }
                if !check_ag {
                    next_summary.antigravity_proxy = self.engine.updates.antigravity_proxy.clone();
                }
                if !check_client("claude_desktop") {
                    next_summary.claude_desktop = self.engine.updates.claude_desktop.clone();
                }
                if !check_client("claude_code") {
                    next_summary.claude_code = self.engine.updates.claude_code.clone();
                }
                if !check_client("codex_desktop") {
                    next_summary.codex_desktop = self.engine.updates.codex_desktop.clone();
                }
                if !check_client("codex_cli") {
                    next_summary.codex_cli = self.engine.updates.codex_cli.clone();
                }
                if !check_client("antigravity_ide") {
                    next_summary.antigravity_ide = self.engine.updates.antigravity_ide.clone();
                }
                if !check_client("antigravity_cn") {
                    next_summary.antigravity_cn = self.engine.updates.antigravity_cn.clone();
                }
                if !check_client("ag_usage_monitor") {
                    next_summary.ag_usage_monitor = self.engine.updates.ag_usage_monitor.clone();
                }
                if !check_client("ag_capsule") {
                    next_summary.ag_capsule = self.engine.updates.ag_capsule.clone();
                }

                self.step_and_run(
                    EngineEvent::UpdatesChecked {
                        summary: Box::new(next_summary.clone()),
                    },
                    now_secs,
                );

                let receipt_opt = if reply.is_some() {
                    let mut receipt = OperationReceipt::new(
                        format!("updates-{now_secs}"),
                        OperationStatus::Unknown,
                    );
                    let mut failed_notes = Vec::new();
                    let mut scope_parts = Vec::new();

                    let mut record_slot =
                        |key: &str, checked: bool, slot: &ComponentUpdateStatus| {
                            if !checked {
                                return;
                            }
                            let st = match slot.phase {
                                UpdateCheckPhase::Failed => {
                                    failed_notes.push(slot.note.clone());
                                    OperationStatus::Failed
                                }
                                UpdateCheckPhase::NotInstalled => OperationStatus::NotApplicable,
                                _ => OperationStatus::Verified,
                            };
                            scope_parts.push(format!("{key}={:?}", slot.phase));
                            receipt.push_item(key, st, slot.note.clone());
                        };

                    record_slot("claudeguard", check_cg, &next_summary.claudeguard);
                    record_slot(
                        "antigravity_proxy",
                        check_ag,
                        &next_summary.antigravity_proxy,
                    );
                    record_slot(
                        "claude_desktop",
                        check_client("claude_desktop"),
                        &next_summary.claude_desktop,
                    );
                    record_slot(
                        "claude_code",
                        check_client("claude_code"),
                        &next_summary.claude_code,
                    );
                    record_slot(
                        "codex_desktop",
                        check_client("codex_desktop"),
                        &next_summary.codex_desktop,
                    );
                    record_slot(
                        "codex_cli",
                        check_client("codex_cli"),
                        &next_summary.codex_cli,
                    );
                    record_slot(
                        "antigravity_ide",
                        check_client("antigravity_ide"),
                        &next_summary.antigravity_ide,
                    );
                    record_slot(
                        "antigravity_cn",
                        check_client("antigravity_cn"),
                        &next_summary.antigravity_cn,
                    );
                    record_slot(
                        "ag_usage_monitor",
                        check_client("ag_usage_monitor"),
                        &next_summary.ag_usage_monitor,
                    );
                    record_slot(
                        "ag_capsule",
                        check_client("ag_capsule"),
                        &next_summary.ag_capsule,
                    );

                    receipt.verified_scope = scope_parts.join(", ");
                    if failed_notes.is_empty() {
                        receipt.status = OperationStatus::Verified;
                    } else {
                        receipt.status = OperationStatus::Failed;
                        receipt.error = Some(failed_notes.join("；"));
                    }

                    self.engine.push_log(
                        now_secs,
                        LogLevel::Audit,
                        "update",
                        &format!(
                            "检查更新完成（{}）：{}",
                            receipt.verified_scope,
                            receipt.error.as_deref().unwrap_or("已刷新组件版本状态")
                        ),
                    );
                    self.engine.last_receipt = Some(receipt.clone());
                    Some(receipt)
                } else {
                    None
                };

                let snap = self.publish_snapshot(ctx.snapshot, now_secs);
                if let Some(tx) = reply {
                    let _ = tx.send(PipeResponse::Ack {
                        receipt: receipt_opt,
                        snapshot: Some(Box::new(snap)),
                    });
                }
            }
            CoordinatorEvent::BeginStopping { reply } => {
                let now = now_unix_secs();
                self.stopping_ready = false;
                self.step_and_run(EngineEvent::BeginStopping, now);
                let snap = self.publish_snapshot(ctx.snapshot, now);
                self.flush_superseded_waiters(&snap);
                let receipt = self.engine.last_receipt.clone().unwrap_or_default();
                if self.stopping_ready {
                    let _ = reply.send(Ok(receipt));
                } else {
                    let err = receipt
                        .error
                        .clone()
                        .unwrap_or_else(|| self.engine.last_error.clone());
                    let _ = reply.send(Err(err));
                }
            }
            CoordinatorEvent::Shutdown => return ActorControl::Stop,
        }
        ActorControl::Continue
    }
}

/// Computes `AgentRuntimeStatus` rows purely from cached process snapshot + discovered exes + firewall rule counts.
pub fn build_agent_statuses(
    cfg: &Config,
    procs: &CachedProcessSnapshot,
    driver: &dyn PlatformDriver,
    fw_rules: &[cg_platform::FirewallRuleRecord],
    tripped: Option<&crate::protocol::TripInfo>,
) -> Vec<AgentRuntimeStatus> {
    let mut out = Vec::with_capacity(GUI_AGENTS.len() + CLI_AGENTS.len());

    for a in GUI_AGENTS {
        let exes = driver.discover_agent_exes(a.id).unwrap_or_default();
        let install_paths: Vec<String> = exes
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        let rule_prefix_out = format!("ClaudeGuard Block Out ({})", a.id);
        let rule_prefix_in = format!("ClaudeGuard Block In ({})", a.id);
        let rule_prefix_lock = format!("ClaudeGuard Lockdown ({})", a.id);
        let fw_count = fw_rules
            .iter()
            .filter(|r| {
                r.enabled
                    && (r.name.eq_ignore_ascii_case(&rule_prefix_out)
                        || r.name.eq_ignore_ascii_case(&rule_prefix_in)
                        || r.name.eq_ignore_ascii_case(&rule_prefix_lock)
                        || (a.id == "claude"
                            && (r.name.eq_ignore_ascii_case(firewall_com::FW_RULE_OUT)
                                || r.name.eq_ignore_ascii_case(firewall_com::FW_RULE_IN))))
            })
            .count();

        out.push(AgentRuntimeStatus {
            id: a.id.to_string(),
            name: a.name.to_string(),
            kind: AgentKind::Gui,
            installed: !install_paths.is_empty(),
            guarded: cfg.guarded_agents.iter().any(|g| g == a.id),
            running_count: *procs.gui_counts.get(a.id).unwrap_or(&0),
            orphan_count: *procs.orphan_counts.get(a.id).unwrap_or(&0),
            quarantined: tripped.is_some_and(|t| t.quarantined_agents.iter().any(|q| q == a.id)),
            firewall_rules: fw_count,
            install_paths,
        });
    }

    for (cid, cname) in CLI_AGENTS {
        let running = *procs.cli_counts.get(*cid).unwrap_or(&0);
        let orphans = *procs.orphan_counts.get(*cid).unwrap_or(&0);
        let exes = driver.discover_cli_exes(cid).unwrap_or_default();
        let install_paths: Vec<String> = exes
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        let installed = running > 0 || orphans > 0 || !install_paths.is_empty();
        let guarded = cfg.kill_cli_on_fail
            && paired_gui_for_cli(cid)
                .is_some_and(|gui| cfg.guarded_agents.iter().any(|g| g == gui));
        out.push(AgentRuntimeStatus {
            id: (*cid).to_string(),
            name: (*cname).to_string(),
            kind: AgentKind::Cli,
            installed,
            guarded,
            running_count: running,
            orphan_count: orphans,
            quarantined: false,
            firewall_rules: 0,
            install_paths,
        });
    }

    out
}

/// Computes `DefenseSelfCheck` (core rows + optional Antigravity proxy row) off the snapshot read path.
pub fn build_defense_self_check(
    cfg: &Config,
    driver: &dyn PlatformDriver,
    journal: &JournalStore,
    firewall_query_ok: bool,
    ag_proxy: &AntigravityProxyStatus,
    now_secs: u64,
) -> DefenseSelfCheck {
    let caps = driver.capabilities();
    let elevated = driver.is_elevated().unwrap_or(false);
    let (wal_clean, wal_pending_tx, wal_detail, wal_status) = match journal.load() {
        LoadedJournal::NotFound => (
            true,
            None,
            "账本干净，无未提交变更".to_string(),
            SelfCheckStatus::Healthy,
        ),
        LoadedJournal::Uncommitted(j) => (
            false,
            Some(j.tx_id.clone()),
            format!("存在未提交事务 {}", j.tx_id),
            SelfCheckStatus::Degraded,
        ),
        LoadedJournal::Committed(j) => (
            false,
            Some(j.tx_id.clone()),
            format!("存在生效隔离事务 {}", j.tx_id),
            SelfCheckStatus::Degraded,
        ),
        LoadedJournal::Corrupt(err) | LoadedJournal::Unreadable(err) => (
            false,
            None,
            format!("账本异常：{err}"),
            SelfCheckStatus::Degraded,
        ),
    };

    let fw_status = if !caps.app_quarantine {
        SelfCheckStatus::Unsupported
    } else if firewall_query_ok {
        SelfCheckStatus::Healthy
    } else {
        SelfCheckStatus::Degraded
    };

    let leak_status = if !caps.leak_watch {
        SelfCheckStatus::Unsupported
    } else if cfg.leak_watch {
        SelfCheckStatus::Healthy
    } else {
        SelfCheckStatus::Disabled
    };

    let mut items = vec![
        DefenseCheckItem {
            id: "daemon".into(),
            name: "Guardian 服务".into(),
            status: SelfCheckStatus::Healthy,
            detail: if elevated {
                "运行中（高权限上下文）".into()
            } else {
                "运行中（前台控制台模式）".into()
            },
        },
        DefenseCheckItem {
            id: "firewall_com".into(),
            name: "Win32 COM 防火墙".into(),
            status: fw_status,
            detail: if !caps.app_quarantine {
                "当前平台不支持".into()
            } else if firewall_query_ok {
                "INetFwPolicy2 就绪且可回查".into()
            } else {
                "防火墙 COM 回查异常".into()
            },
        },
        DefenseCheckItem {
            id: "leak_radar".into(),
            name: "直连防泄露雷达".into(),
            status: leak_status,
            detail: if !caps.leak_watch {
                "当前平台不支持".into()
            } else if cfg.leak_watch {
                "GetExtendedTcpTable 监控中（排除 198.18.0.0/15）".into()
            } else {
                "已在设置中关闭".into()
            },
        },
        DefenseCheckItem {
            id: "wal_journal".into(),
            name: "WAL 崩溃恢复账本".into(),
            status: wal_status,
            detail: wal_detail,
        },
    ];

    if ag_proxy.installed {
        let status = if ag_proxy.state.is_healthy() {
            SelfCheckStatus::Healthy
        } else if !cfg.require_antigravity_proxy {
            SelfCheckStatus::Disabled
        } else {
            SelfCheckStatus::Degraded
        };
        items.push(DefenseCheckItem {
            id: "ag_proxy".into(),
            name: "反重力透明代理注入".into(),
            status,
            detail: ag_proxy.summary.clone(),
        });
    }

    DefenseSelfCheck {
        daemon_running: true,
        daemon_elevated: elevated,
        firewall_com_ready: caps.app_quarantine,
        firewall_query_ok,
        global_cut_ready: caps.global_cut,
        leak_radar_active: caps.leak_watch && cfg.leak_watch,
        wal_clean,
        wal_pending_tx,
        items,
        checked_at: now_secs,
    }
}

/// Manages periodic monitor ticks, cached process/leak/env telemetry, and residual sweeps.
pub struct BackgroundMonitorHandle {
    stop_flag: Arc<AtomicBool>,
    stop_signal: Arc<(Mutex<bool>, Condvar)>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl BackgroundMonitorHandle {
    /// Spawns the background scheduler + telemetry loop for a live [`CoordinatorHandle`].
    pub fn start(
        coordinator: CoordinatorHandle,
        driver: Arc<dyn PlatformDriver>,
        process_scanner: Arc<ProcessScanner>,
        data_dir: PathBuf,
        enable_initial_tick: bool,
    ) -> Self {
        Self::start_with_intervals(
            coordinator,
            driver,
            process_scanner,
            data_dir,
            enable_initial_tick,
            DEFAULT_TELEMETRY_INTERVAL,
            AUTO_UPDATE_CHECK_INTERVAL,
        )
    }

    /// Spawns the background scheduler + telemetry loop with configurable intervals (also used in tests).
    pub fn start_with_intervals(
        coordinator: CoordinatorHandle,
        driver: Arc<dyn PlatformDriver>,
        process_scanner: Arc<ProcessScanner>,
        data_dir: PathBuf,
        enable_initial_tick: bool,
        telemetry_interval: Duration,
        update_check_interval: Duration,
    ) -> Self {
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_signal = Arc::new((Mutex::new(false), Condvar::new()));

        let t_flag = stop_flag.clone();
        let t_sig = stop_signal.clone();
        let journal = JournalStore::new(data_dir);

        let thread = std::thread::Builder::new()
            .name("cg-monitor-loop".to_string())
            .spawn(move || {
                let mut last_tick = if enable_initial_tick {
                    coordinator.try_tick();
                    Instant::now()
                } else {
                    Instant::now()
                };
                let mut last_telemetry = Instant::now() - telemetry_interval;
                let mut last_upd_check: Option<Instant> = None;
                let mut desktop_gone_since: Option<Instant> = None;

                while !t_flag.load(Ordering::Acquire) {
                    let snap = coordinator.snapshot();
                    let interval = Duration::from_secs(snap.config.clamped_interval_secs());

                    if last_tick.elapsed() >= interval {
                        coordinator.try_tick();
                        last_tick = Instant::now();
                    }

                    if last_telemetry.elapsed() >= telemetry_interval {
                        let now = now_unix_secs();
                        let procs = if driver.capabilities().process_guard {
                            process_scanner.refresh()
                        } else {
                            process_scanner.cached_snapshot()
                        };
                        let (fw_rules, fw_query_ok) =
                            match driver.firewall().enumerate_rules("ClaudeGuard") {
                                Ok(rules) => (rules, true),
                                Err(PlatformError::Unsupported { .. }) => (Vec::new(), false),
                                Err(_) => (Vec::new(), false),
                            };
                        let agents = build_agent_statuses(
                            &snap.config,
                            &procs,
                            &*driver,
                            &fw_rules,
                            snap.tripped.as_ref(),
                        );

                        let claude_dir_l = process_win::claude_covered_dirs()
                            .into_iter()
                            .next()
                            .map(|d| d.to_string_lossy().to_ascii_lowercase());
                        let pid_map = procs.guarded_agent_pids(
                            &snap.config.guarded_agents,
                            claude_dir_l.as_deref(),
                        );
                        let access_info = access_win::AccessInfo::from(&snap.access);
                        let leak = if driver.capabilities().leak_watch {
                            let conns = driver.scan_tcp_connections().unwrap_or_default();
                            netwatch_win::fold(
                                &conns,
                                &pid_map,
                                snap.config.proxy_port,
                                &access_info,
                                now,
                            )
                        } else {
                            LeakReport::not_applicable("unsupported", "当前平台不支持直连观察", now)
                        };

                        let env_info = driver.read_env_info().unwrap_or_default();
                        let env = envcheck::evaluate(&snap.config, env_info, &snap.targets);
                        let antigravity_proxy = driver.inspect_antigravity_proxy(
                            snap.config.proxy_port,
                            snap.config.last_seen_antigravity_version.as_deref(),
                            &procs,
                            now,
                        );
                        let self_check = build_defense_self_check(
                            &snap.config,
                            &*driver,
                            &journal,
                            fw_query_ok,
                            &antigravity_proxy,
                            now,
                        );

                        let local_clients = local_client_versions();
                        let mut local_updates = snap.updates.clone();
                        hydrate_local_updates(
                            &mut local_updates,
                            &snap.version,
                            &antigravity_proxy,
                            &local_clients,
                        );

                        let leak_shield = if driver.capabilities().app_quarantine {
                            leak_shield_win::inspect_leak_shield()
                        } else {
                            LeakShieldStatus::default()
                        };
                        let mihomo = mihomo_win::inspect_mihomo();

                        coordinator.try_send_telemetry(TelemetryBundle {
                            agents,
                            leak,
                            leak_shield,
                            mihomo,
                            env,
                            antigravity_proxy: antigravity_proxy.clone(),
                            self_check,
                            updates: Some(local_updates.clone()),
                            now_secs: now,
                        });

                        if snap.config.auto_upd_check
                            && snap.lifecycle == Lifecycle::Armed
                            && snap.protection == ProtectionState::Monitoring
                            && snap.all_enabled_pass()
                            && last_upd_check.is_none_or(|t| t.elapsed() >= update_check_interval)
                        {
                            let (_access, route) = resolve_access_and_route(
                                &*driver,
                                &snap.config,
                                snap.cfg_rev,
                                &snap.config.targets,
                                snap.config.enforce_access_path,
                                now,
                            );
                            if !matches!(route, ProbeRoute::Skip(_)) {
                                let checked = driver.check_updates(
                                    &route,
                                    &snap.version,
                                    &antigravity_proxy,
                                    None,
                                    &local_updates,
                                    now,
                                );
                                let _ = coordinator.event_sender().try_send(
                                    CoordinatorEvent::UpdatesChecked {
                                        summary: Box::new(checked),
                                        component: None,
                                        now_secs: now,
                                        reply: None,
                                    },
                                );
                                last_upd_check = Some(Instant::now());
                            }
                        }

                        // Auto residual sweep 4s after Claude desktop exits when enabled.
                        if snap.lifecycle == Lifecycle::Armed
                            && snap.config.sweep_on_exit
                            && !snap.is_paused_at(now)
                            && snap.config.guarded_agents.iter().any(|g| g == "claude")
                        {
                            let desktop_running =
                                procs.gui_counts.get("claude").copied().unwrap_or(0) > 0;
                            if desktop_running {
                                desktop_gone_since = None;
                            } else if let Some(since) = desktop_gone_since {
                                if since.elapsed() >= Duration::from_secs(4) {
                                    let _ = driver.sweep_claude(SweepMode::Residual);
                                    desktop_gone_since = None;
                                }
                            } else if process_win::claude_presence_fast(None)
                                != ClaudePresence::Desktop
                            {
                                desktop_gone_since = Some(Instant::now());
                            }
                        } else {
                            desktop_gone_since = None;
                        }

                        last_telemetry = Instant::now();
                    }

                    let wait_dur = telemetry_interval.min(Duration::from_millis(500));
                    let (lock, cvar) = &*t_sig;
                    if let Ok(guard) = lock.lock() {
                        if *guard {
                            break;
                        }
                        let _ = cvar.wait_timeout(guard, wait_dur);
                    }
                }
            })
            .expect("failed to spawn monitor loop thread");

        Self {
            stop_flag,
            stop_signal,
            thread: Mutex::new(Some(thread)),
        }
    }

    /// Signals the monitor loop to stop and joins its thread cleanly.
    pub fn shutdown(&self) {
        self.stop_flag.store(true, Ordering::Release);
        let (lock, cvar) = &*self.stop_signal;
        if let Ok(mut guard) = lock.lock() {
            *guard = true;
            cvar.notify_all();
        }
        if let Ok(mut guard) = self.thread.lock() {
            if let Some(handle) = guard.take() {
                let _ = handle.join();
            }
        }
    }
}

impl Drop for BackgroundMonitorHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Helper mapping `AccessPath` values in unit tests.
#[allow(dead_code)]
pub fn access_evidence_from_path(path: &AccessPath, now_secs: u64, rev: u64) -> AccessEvidence {
    path.to_protocol_evidence(now_secs, rev)
}

#[allow(dead_code)]
fn _unused_policy_preset_guard(_: PolicyPreset, _: HashMap<u32, String>) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinator::{start_coordinator_with, CoordinatorHandle};
    use crate::journal::tests::{MockRecoveryExecutor, MockRecoveryState};
    use crate::journal::PlatformRecoveryExecutor;
    use crate::protocol::{AntigravityProxyState, EnvCheck};
    use cg_platform::netwatch_win::TcpConn;
    use cg_platform::process_win::{LaunchTarget, ProcessIdentity, SweepReport};
    use cg_platform::{
        Coverage, FirewallEngine, FirewallProfileStatus, FirewallRuleRecord, FirewallRuleSpec,
        PlatformCapabilities, PlatformResult, RemoveReport, UnsupportedPlatformDriver,
    };
    use cg_protocol::EnvInfo;
    use std::sync::atomic::AtomicUsize;

    #[derive(Default)]
    struct InMemoryFirewallEngine {
        rules: Mutex<Vec<FirewallRuleRecord>>,
    }

    impl FirewallEngine for InMemoryFirewallEngine {
        fn engine_name(&self) -> &'static str {
            "in-memory-mock"
        }

        fn profile_status(&self) -> PlatformResult<FirewallProfileStatus> {
            Ok(FirewallProfileStatus {
                domain_enabled: true,
                private_enabled: true,
                public_enabled: true,
            })
        }

        fn ensure_profiles_enabled(&self) -> PlatformResult<bool> {
            Ok(true)
        }

        fn enumerate_rules(&self, prefix: &str) -> PlatformResult<Vec<FirewallRuleRecord>> {
            let p = prefix.trim().to_ascii_lowercase();
            let rules = self.rules.lock().unwrap();
            Ok(rules
                .iter()
                .filter(|r| p.is_empty() || r.name.trim().to_ascii_lowercase().starts_with(&p))
                .cloned()
                .collect())
        }

        fn dedupe_rules(&self, _prefix: &str) -> PlatformResult<usize> {
            Ok(0)
        }

        fn ensure_rules(&self, desired: &[FirewallRuleSpec]) -> PlatformResult<Coverage> {
            let mut rules = self.rules.lock().unwrap();
            let mut added = 0usize;
            for spec in desired {
                let prog = spec
                    .program
                    .as_ref()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();
                let exists = rules.iter().any(|r| {
                    r.name.eq_ignore_ascii_case(&spec.name)
                        && r.program.eq_ignore_ascii_case(&prog)
                        && r.direction == spec.direction
                        && r.action == spec.action
                });
                if !exists {
                    rules.push(FirewallRuleRecord {
                        name: spec.name.clone(),
                        program: prog,
                        direction: spec.direction,
                        action: spec.action,
                        enabled: spec.enabled,
                        profiles: spec.profiles,
                    });
                    added += 1;
                }
            }
            Ok(Coverage {
                desired: desired.len(),
                verified: desired.len(),
                added,
                query_ok: true,
            })
        }

        fn remove_rules_by_name(&self, names: &[String]) -> PlatformResult<RemoveReport> {
            let wants: Vec<String> = names
                .iter()
                .map(|n| n.trim().to_ascii_lowercase())
                .collect();
            let mut rules = self.rules.lock().unwrap();
            let before = rules.len();
            rules.retain(|r| {
                !wants
                    .iter()
                    .any(|w| w == &r.name.trim().to_ascii_lowercase())
            });
            Ok(RemoveReport {
                removed: before - rules.len(),
                remaining: 0,
                query_ok: true,
            })
        }

        fn remove_rules_with_prefix(&self, prefix: &str) -> PlatformResult<RemoveReport> {
            let p = prefix.trim().to_ascii_lowercase();
            let mut rules = self.rules.lock().unwrap();
            let before = rules.len();
            rules.retain(|r| !r.name.trim().to_ascii_lowercase().starts_with(&p));
            Ok(RemoveReport {
                removed: before - rules.len(),
                remaining: 0,
                query_ok: true,
            })
        }
    }

    type UpdateCheckFn = Box<
        dyn Fn(
                &ProbeRoute,
                &str,
                &AntigravityProxyStatus,
                Option<&str>,
                &UpdateSummary,
                u64,
            ) -> UpdateSummary
            + Send
            + Sync,
    >;

    struct ControllableDriver {
        fw: Arc<InMemoryFirewallEngine>,
        fallback: UnsupportedPlatformDriver,
        ag_proxy: Mutex<AntigravityProxyStatus>,
        sweep_all_calls: AtomicUsize,
        sweep_claude_calls: AtomicUsize,
        sweep_report: Mutex<SweepReport>,
        gui_exes: Mutex<HashMap<String, Vec<PathBuf>>>,
        cli_exes: Mutex<HashMap<String, Vec<PathBuf>>>,
        gui_killed_calls: Mutex<Vec<String>>,
        cli_killed_calls: Mutex<Vec<String>>,
        mock_gui_identities: Mutex<HashMap<String, Vec<ProcessIdentity>>>,
        mock_cli_identities: Mutex<HashMap<String, Vec<ProcessIdentity>>>,
        access_path_override: Mutex<Option<AccessPath>>,
        check_updates_calls: AtomicUsize,
        last_update_route: Mutex<Option<ProbeRoute>>,
        update_fn: Mutex<Option<UpdateCheckFn>>,
    }

    impl ControllableDriver {
        fn new() -> Self {
            Self {
                fw: Arc::new(InMemoryFirewallEngine::default()),
                fallback: UnsupportedPlatformDriver::default(),
                ag_proxy: Mutex::new(AntigravityProxyStatus::default()),
                sweep_all_calls: AtomicUsize::new(0),
                sweep_claude_calls: AtomicUsize::new(0),
                sweep_report: Mutex::new(SweepReport::default()),
                gui_exes: Mutex::new(HashMap::new()),
                cli_exes: Mutex::new(HashMap::new()),
                gui_killed_calls: Mutex::new(Vec::new()),
                cli_killed_calls: Mutex::new(Vec::new()),
                mock_gui_identities: Mutex::new(HashMap::new()),
                mock_cli_identities: Mutex::new(HashMap::new()),
                access_path_override: Mutex::new(None),
                check_updates_calls: AtomicUsize::new(0),
                last_update_route: Mutex::new(None),
                update_fn: Mutex::new(None),
            }
        }
    }

    impl PlatformDriver for ControllableDriver {
        fn capabilities(&self) -> PlatformCapabilities {
            let mut caps = PlatformCapabilities::windows_com_default();
            caps.toast_notifications = false;
            caps.leak_watch = false;
            caps.env_alignment = false;
            caps.process_guard = false;
            caps
        }

        fn firewall(&self) -> &dyn FirewallEngine {
            &*self.fw
        }

        fn is_elevated(&self) -> PlatformResult<bool> {
            Ok(true)
        }

        fn read_access_evidence(&self) -> PlatformResult<access_win::AccessEvidenceRaw> {
            Ok(access_win::AccessEvidenceRaw {
                enable: false,
                server: None,
                autoconfig: None,
                overrides: None,
            })
        }

        fn detect_tun_adapter(&self) -> PlatformResult<Option<String>> {
            Ok(Some("TestTun0".into()))
        }

        fn inspect_access_path(
            &self,
            _monitored_hosts: &[String],
        ) -> PlatformResult<(AccessPath, access_win::AccessInfo)> {
            let path = self
                .access_path_override
                .lock()
                .unwrap()
                .clone()
                .unwrap_or_else(|| AccessPath::Tun {
                    adapter: "TestTun0".into(),
                });
            let info = access_win::AccessInfo::from(&path);
            Ok((path, info))
        }

        fn scan_tcp_connections(&self) -> PlatformResult<Vec<TcpConn>> {
            Ok(Vec::new())
        }

        fn discover_agent_exes(&self, agent_id: &str) -> PlatformResult<Vec<PathBuf>> {
            if let Some(list) = self.gui_exes.lock().unwrap().get(agent_id).cloned() {
                return Ok(list);
            }
            match agent_id {
                "claude" => Ok(vec![PathBuf::from(r"C:\Apps\Claude\claude.exe")]),
                "antigravity" => {
                    let ag = self.ag_proxy.lock().unwrap();
                    if ag.installed {
                        Ok(vec![
                            PathBuf::from(r"C:\Apps\antigravity\Antigravity.exe"),
                            PathBuf::from(r"C:\Apps\antigravity\resources\bin\language_server.exe"),
                        ])
                    } else {
                        Ok(Vec::new())
                    }
                }
                _ => Ok(Vec::new()),
            }
        }

        fn discover_cli_exes(&self, cli_id: &str) -> PlatformResult<Vec<PathBuf>> {
            Ok(self
                .cli_exes
                .lock()
                .unwrap()
                .get(cli_id)
                .cloned()
                .unwrap_or_default())
        }

        fn kill_gui_agent(&self, agent_id: &str) -> PlatformResult<Vec<ProcessIdentity>> {
            self.gui_killed_calls
                .lock()
                .unwrap()
                .push(agent_id.to_string());
            Ok(self
                .mock_gui_identities
                .lock()
                .unwrap()
                .get(agent_id)
                .cloned()
                .unwrap_or_default())
        }

        fn kill_cli_agent(&self, cli_id: &str) -> PlatformResult<Vec<ProcessIdentity>> {
            self.cli_killed_calls
                .lock()
                .unwrap()
                .push(cli_id.to_string());
            Ok(self
                .mock_cli_identities
                .lock()
                .unwrap()
                .get(cli_id)
                .cloned()
                .unwrap_or_default())
        }

        fn check_updates(
            &self,
            route: &ProbeRoute,
            cg_version: &str,
            ag_proxy: &AntigravityProxyStatus,
            component: Option<&str>,
            prev: &UpdateSummary,
            now_secs: u64,
        ) -> UpdateSummary {
            self.check_updates_calls.fetch_add(1, Ordering::AcqRel);
            *self.last_update_route.lock().unwrap() = Some(route.clone());
            if let Some(f) = self.update_fn.lock().unwrap().as_ref() {
                return f(route, cg_version, ag_proxy, component, prev, now_secs);
            }
            let mut out = prev.clone();
            hydrate_local_updates(
                &mut out,
                cg_version,
                ag_proxy,
                &update_check::LocalClientVersions::default(),
            );
            let (check_cg, check_ag, _) =
                parse_update_component_filter(component).unwrap_or((true, true, None));
            if check_cg {
                out.claudeguard.phase = UpdateCheckPhase::UpToDate;
                out.claudeguard.latest_version = Some(cg_version.to_string());
                out.claudeguard.checked_at = Some(now_secs);
                out.claudeguard.note = "mock up to date".to_string();
            }
            if check_ag {
                out.antigravity_proxy.checked_at = Some(now_secs);
                if ag_proxy.installed {
                    out.antigravity_proxy.phase = UpdateCheckPhase::UpToDate;
                    out.antigravity_proxy.latest_version = ag_proxy.injector_version.clone();
                    out.antigravity_proxy.note = "mock ag up to date".to_string();
                } else {
                    out.antigravity_proxy.phase = UpdateCheckPhase::NotInstalled;
                    out.antigravity_proxy.note = "本机未检测到反重力客户端".to_string();
                }
            }
            out
        }

        fn sweep_claude(&self, _mode: SweepMode) -> PlatformResult<SweepReport> {
            self.sweep_claude_calls.fetch_add(1, Ordering::AcqRel);
            Ok(self.sweep_report.lock().unwrap().clone())
        }

        fn sweep_all_orphans(&self) -> PlatformResult<SweepReport> {
            self.sweep_all_calls.fetch_add(1, Ordering::AcqRel);
            Ok(self.sweep_report.lock().unwrap().clone())
        }

        fn inspect_antigravity_proxy(
            &self,
            _expected_proxy_port: u16,
            _last_seen_version: Option<&str>,
            _snap: &CachedProcessSnapshot,
            _now_secs: u64,
        ) -> AntigravityProxyStatus {
            self.ag_proxy.lock().unwrap().clone()
        }

        fn launch_app_normal_privilege(&self, target: &LaunchTarget) -> PlatformResult<()> {
            self.fallback.launch_app_normal_privilege(target)
        }

        fn send_toast(&self, title: &str, body: &str) -> PlatformResult<()> {
            self.fallback.send_toast(title, body)
        }

        fn protect_secret(&self, plaintext: &[u8]) -> PlatformResult<Vec<u8>> {
            self.fallback.protect_secret(plaintext)
        }

        fn unprotect_secret(&self, ciphertext: &[u8]) -> PlatformResult<Vec<u8>> {
            self.fallback.unprotect_secret(ciphertext)
        }

        fn read_env_info(&self) -> PlatformResult<EnvInfo> {
            self.fallback.read_env_info()
        }

        fn read_default_location(&self) -> PlatformResult<(Option<String>, Option<String>)> {
            self.fallback.read_default_location()
        }

        fn write_default_location(&self, lat: &str, lon: &str) -> PlatformResult<()> {
            self.fallback.write_default_location(lat, lon)
        }

        fn delete_default_location(&self) -> PlatformResult<()> {
            self.fallback.delete_default_location()
        }
    }

    struct DelayedProbeRunner {
        gate_tx: Option<Mutex<Option<mpsc::SyncSender<()>>>>,
        release_rx: Option<Mutex<mpsc::Receiver<()>>>,
        pass: Arc<AtomicBool>,
        ip_on_pass: String,
    }

    impl ProbeRunner for DelayedProbeRunner {
        fn inspect_and_probe(
            &self,
            _driver: &dyn PlatformDriver,
            _cfg: &Config,
            cfg_rev: u64,
            targets: &[Target],
            _enforce_access_path: bool,
            _skip_network_probes: bool,
            now_secs: u64,
        ) -> (AccessEvidence, Vec<(String, ProbeResult)>) {
            if let Some(cell) = &self.gate_tx {
                if let Some(tx) = cell.lock().unwrap().take() {
                    let _ = tx.send(());
                }
            }
            if let Some(rx_lock) = &self.release_rx {
                let _ = rx_lock.lock().unwrap().recv_timeout(Duration::from_secs(2));
            }

            let ok = self.pass.load(Ordering::Acquire);
            let access = AccessEvidence {
                level: AccessLevel::Tun,
                observed_at: now_secs,
                revision: cfg_rev,
                note: "mock tun".into(),
                ..AccessEvidence::default()
            };
            let results = targets
                .iter()
                .filter(|t| t.enabled)
                .map(|t| {
                    let probe = if ok {
                        ProbeResult {
                            reachable: true,
                            status: Some(200),
                            ip: Some(self.ip_on_pass.clone()),
                            country: Some("US".into()),
                            raw_region: Some("US".into()),
                            colo: Some("SJC".into()),
                            city: None,
                            latency_ms: 15,
                            parsed_as: "trace".into(),
                            detail: "ok".into(),
                        }
                    } else {
                        ProbeResult {
                            reachable: true,
                            status: Some(200),
                            ip: Some("203.0.113.45".into()),
                            country: Some("CN".into()),
                            raw_region: Some("CN".into()),
                            colo: None,
                            city: None,
                            latency_ms: 55,
                            parsed_as: "trace".into(),
                            detail: "mismatch".into(),
                        }
                    };
                    (t.id.clone(), probe)
                })
                .collect();
            (access, results)
        }
    }

    fn boot_actor(
        dir: &std::path::Path,
        driver: Arc<dyn PlatformDriver>,
        runner: Arc<dyn ProbeRunner>,
        recovery: Arc<dyn RecoveryExecutor>,
    ) -> CoordinatorHandle {
        let data_dir = dir.to_path_buf();
        let (handle, _) = start_coordinator_with(|event_tx| {
            let boot = RealEngineActor::bootstrap(data_dir, driver, runner, recovery, event_tx);
            (boot.initial_snapshot, Box::new(boot.actor), ())
        });
        handle
    }

    fn make_cfg(region: &str) -> Config {
        let mut cfg = Config {
            first_run: false,
            enforce_access_path: false,
            trip_threshold: 1,
            cut_mode: CutMode::Off,
            ..Default::default()
        };
        for target in &mut cfg.targets {
            target.expect_regions = vec![region.into()];
        }
        cfg
    }

    #[test]
    fn stale_round_discarded_after_save_config_and_active_round_completes() {
        let dir = tempfile::tempdir().unwrap();
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(4);
        let pass = Arc::new(AtomicBool::new(false));
        let runner = Arc::new(DelayedProbeRunner {
            gate_tx: Some(Mutex::new(Some(entered_tx))),
            release_rx: Some(Mutex::new(release_rx)),
            pass: pass.clone(),
            ip_on_pass: "198.51.100.98".into(),
        });
        let driver: Arc<dyn PlatformDriver> = Arc::new(UnsupportedPlatformDriver::default());
        let recovery = Arc::new(MockRecoveryExecutor::new(MockRecoveryState::default()));
        let coord = boot_actor(dir.path(), driver, runner, recovery);

        // CompleteOnboarding triggers round for cfg_rev=1.
        assert!(matches!(
            coord.dispatch(PipeRequest::CompleteOnboarding {
                config: make_cfg("US"),
            }),
            PipeResponse::Ack { .. }
        ));
        entered_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("probe worker must start first round");

        // While first probe blocks, SaveConfig bumps cfg_rev to 2.
        assert!(matches!(
            coord.dispatch(PipeRequest::SaveConfig {
                config: make_cfg("US"),
            }),
            PipeResponse::Ack { .. }
        ));
        assert_eq!(coord.snapshot().cfg_rev, 2);

        // Release blocked probe (still failing, cfg_rev=1) -> must be discarded!
        pass.store(true, Ordering::Release);
        release_tx.send(()).unwrap();
        std::thread::sleep(Duration::from_millis(40));
        assert!(
            coord.snapshot().tripped.is_none(),
            "stale failing round for old cfg_rev must NOT trip engine"
        );

        // Now run fresh RecheckNow on cfg_rev=2 with passing flag.
        release_tx.send(()).unwrap();
        assert!(matches!(
            coord.dispatch(PipeRequest::RecheckNow { target_id: None }),
            PipeResponse::Ack { .. }
        ));
        let snap = coord.snapshot();
        assert_eq!(snap.cfg_rev, 2);
        assert!(snap.all_enabled_pass());

        match coord.dispatch(PipeRequest::QueryLogs {
            since_ts: None,
            until_ts: None,
            limit: Some(50),
            query: Some("丢弃".into()),
        }) {
            PipeResponse::Logs { entries, total } => {
                assert!(total >= 1 && !entries.is_empty());
            }
            other => panic!("expected Logs, got {other:?}"),
        }

        coord.shutdown();
    }

    #[test]
    fn trip_writes_wal_then_flow_a_recovers_and_check_launch_gate_updates() {
        let dir = tempfile::tempdir().unwrap();
        let driver = Arc::new(ControllableDriver::new());
        let pass = Arc::new(AtomicBool::new(false));
        let runner = Arc::new(DelayedProbeRunner {
            gate_tx: None,
            release_rx: None,
            pass: pass.clone(),
            ip_on_pass: "198.51.100.98".into(),
        });
        let recovery = Arc::new(PlatformRecoveryExecutor::new(driver.clone()));
        let coord = boot_actor(dir.path(), driver.clone(), runner, recovery);

        // Onboarding probe also checks access + claude target.
        let onboarding_resp = coord.dispatch(PipeRequest::ProbeOnboarding);
        assert!(matches!(
            onboarding_resp,
            PipeResponse::OnboardingProbe { .. }
        ));

        let mut cfg = make_cfg("US");
        cfg.enforce_access_path = true;
        assert!(matches!(
            coord.dispatch(PipeRequest::CompleteOnboarding { config: cfg }),
            PipeResponse::Ack { .. }
        ));

        // Failing RecheckNow trips engine -> quarantines claude in MockFirewallEngine + writes WAL.
        assert!(matches!(
            coord.dispatch(PipeRequest::RecheckNow { target_id: None }),
            PipeResponse::Ack { .. }
        ));
        let tripped_snap = coord.snapshot();
        assert_eq!(tripped_snap.protection, ProtectionState::Quarantined);
        assert!(tripped_snap.tripped.is_some());
        assert!(!driver.fw.enumerate_rules("ClaudeGuard").unwrap().is_empty());
        assert!(JournalStore::new(dir.path()).path().exists());

        // CheckLaunchGate must refuse launch while quarantined/failing.
        match coord.dispatch(PipeRequest::CheckLaunchGate {
            agent_id: Some("claude".into()),
        }) {
            PipeResponse::LaunchGate { allowed, .. } => assert!(!allowed),
            other => panic!("expected LaunchGate deny, got {other:?}"),
        }

        // Flip probe to passing and trigger Flow A stage 1 + stage 2.
        pass.store(true, Ordering::Release);
        assert!(matches!(
            coord.dispatch(PipeRequest::RecoverSafeFlowA),
            PipeResponse::Ack { .. }
        ));
        assert_eq!(
            coord.snapshot().protection,
            ProtectionState::NetworkReadyAppHeld
        );

        assert!(matches!(
            coord.dispatch(PipeRequest::RecheckNow { target_id: None }),
            PipeResponse::Ack { .. }
        ));
        let recovered = coord.snapshot();
        assert_eq!(recovered.protection, ProtectionState::Monitoring);
        assert!(recovered.tripped.is_none());
        assert!(driver.fw.enumerate_rules("ClaudeGuard").unwrap().is_empty());
        assert!(!JournalStore::new(dir.path()).path().exists());

        match coord.dispatch(PipeRequest::CheckLaunchGate {
            agent_id: Some("claude".into()),
        }) {
            PipeResponse::LaunchGate { allowed, .. } => assert!(allowed),
            other => panic!("expected LaunchGate allow after Flow A recovery, got {other:?}"),
        }

        coord.shutdown();
    }

    #[test]
    fn check_launch_gate_blocks_antigravity_when_proxy_missing_dll_while_claude_passes() {
        let dir = tempfile::tempdir().unwrap();
        let driver = Arc::new(ControllableDriver::new());
        let missing_dll = AntigravityProxyStatus {
            state: AntigravityProxyState::MissingDll,
            installed: true,
            antigravity_dir: Some(r"C:\Apps\antigravity".into()),
            antigravity_version: Some("45.0.0".into()),
            dll_present: false,
            dll_valid: false,
            dll_size: 0,
            config_present: true,
            injector_version: Some("2.6.3".into()),
            proxy_type: Some("socks5".into()),
            proxy_host: Some("127.0.0.1".into()),
            proxy_port: Some(7890),
            port_matches_guard: true,
            child_injection: Some(true),
            runtime_running: false,
            runtime_dll_loaded_main: false,
            runtime_dll_loaded_ls: false,
            version_changed_from: Some("44.9.1".into()),
            checked_at: 1_700_000_100,
            summary: "version.dll 缺失，可能已被客户端升级覆盖".into(),
        };
        *driver.ag_proxy.lock().unwrap() = missing_dll.clone();

        let gate_cell: Arc<Mutex<Option<mpsc::SyncSender<()>>>> = Arc::new(Mutex::new(None));
        let (release_tx, release_rx) = mpsc::sync_channel(8);
        let pass = Arc::new(AtomicBool::new(true));

        struct GatedRunner {
            gate: Arc<Mutex<Option<mpsc::SyncSender<()>>>>,
            release: Mutex<mpsc::Receiver<()>>,
            pass: Arc<AtomicBool>,
        }
        impl ProbeRunner for GatedRunner {
            fn inspect_and_probe(
                &self,
                _driver: &dyn PlatformDriver,
                _cfg: &Config,
                cfg_rev: u64,
                targets: &[Target],
                _enforce_access_path: bool,
                _skip_network_probes: bool,
                now_secs: u64,
            ) -> (AccessEvidence, Vec<(String, ProbeResult)>) {
                let block = if let Some(tx) = self.gate.lock().unwrap().take() {
                    let _ = tx.send(());
                    true
                } else {
                    false
                };
                if block {
                    let _ = self
                        .release
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(2));
                }
                let ok = self.pass.load(Ordering::Acquire);
                let access = AccessEvidence {
                    level: AccessLevel::Tun,
                    observed_at: now_secs,
                    revision: cfg_rev,
                    note: "mock tun".into(),
                    ..AccessEvidence::default()
                };
                let results = targets
                    .iter()
                    .filter(|t| t.enabled)
                    .map(|t| {
                        let probe = ProbeResult {
                            reachable: true,
                            status: Some(200),
                            ip: Some(if ok {
                                "198.51.100.98".into()
                            } else {
                                "203.0.113.45".into()
                            }),
                            country: Some(if ok { "US".into() } else { "CN".into() }),
                            raw_region: Some(if ok { "US".into() } else { "CN".into() }),
                            colo: Some("SJC".into()),
                            city: None,
                            latency_ms: 15,
                            parsed_as: "trace".into(),
                            detail: "ok".into(),
                        };
                        (t.id.clone(), probe)
                    })
                    .collect();
                (access, results)
            }
        }

        let runner = Arc::new(GatedRunner {
            gate: gate_cell.clone(),
            release: Mutex::new(release_rx),
            pass,
        });
        let recovery = Arc::new(MockRecoveryExecutor::new(MockRecoveryState::default()));
        let coord = boot_actor(dir.path(), driver.clone(), runner, recovery);

        // Bootstrap immediately hydrates antigravity_proxy + self_check.
        let boot_snap = coord.snapshot();
        assert_eq!(
            boot_snap.antigravity_proxy.state,
            AntigravityProxyState::MissingDll
        );
        assert!(boot_snap
            .self_check
            .items
            .iter()
            .any(|i| i.id == "ag_proxy" && i.status == SelfCheckStatus::Degraded));

        // Onboard and complete a synchronous RecheckNow so protection enters `Monitoring`.
        let mut cfg = make_cfg("US");
        cfg.require_antigravity_proxy = true;
        assert!(matches!(
            coord.dispatch(PipeRequest::CompleteOnboarding {
                config: cfg.clone()
            }),
            PipeResponse::Ack { .. }
        ));
        assert!(matches!(
            coord.dispatch(PipeRequest::RecheckNow { target_id: None }),
            PipeResponse::Ack { .. }
        ));
        assert_eq!(coord.snapshot().protection, ProtectionState::Monitoring);

        // 1) Direct `CheckLaunchGate`: `antigravity` blocks on `MissingDll`, while `claude` passes!
        match coord.dispatch(PipeRequest::CheckLaunchGate {
            agent_id: Some("antigravity".into()),
        }) {
            PipeResponse::LaunchGate {
                allowed, reason, ..
            } => {
                assert!(!allowed);
                assert!(reason.contains("反重力透明代理未就绪"));
                assert!(reason.contains("version.dll 缺失"));
            }
            other => panic!("expected LaunchGate deny for antigravity, got {other:?}"),
        }
        match coord.dispatch(PipeRequest::CheckLaunchGate {
            agent_id: Some("claude".into()),
        }) {
            PipeResponse::LaunchGate { allowed, .. } => assert!(allowed),
            other => panic!("expected LaunchGate allow for claude, got {other:?}"),
        }

        // 2) `fulfill_round_waiters` per-agent check: temporarily mark proxy Healthy, SaveConfig
        // (resets target states to Pending while staying `Monitoring`), arm gate on next probe,
        // queue BOTH `antigravity` and `claude` launch waiters, flip proxy back to `MissingDll`
        // via Telemetry while the probe is paused, then release!
        let mut healthy_ag = missing_dll.clone();
        healthy_ag.state = AntigravityProxyState::Healthy;
        healthy_ag.dll_present = true;
        healthy_ag.dll_valid = true;
        healthy_ag.version_changed_from = None;
        let journal = JournalStore::new(dir.path());
        coord.try_send_telemetry(TelemetryBundle {
            agents: Vec::new(),
            leak: LeakReport::not_applicable("mock", "mock", 1_700_000_200),
            leak_shield: LeakShieldStatus::default(),
            mihomo: MihomoStatus::default(),
            env: EnvCheck::default(),
            antigravity_proxy: healthy_ag.clone(),
            self_check: build_defense_self_check(
                &cfg,
                &*driver,
                &journal,
                true,
                &healthy_ag,
                1_700_000_200,
            ),
            updates: None,
            now_secs: 1_700_000_200,
        });
        assert!(matches!(
            coord.dispatch(PipeRequest::SaveConfig {
                config: cfg.clone()
            }),
            PipeResponse::Ack { .. }
        ));
        assert!(!coord.snapshot().all_enabled_pass());

        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        *gate_cell.lock().unwrap() = Some(entered_tx);

        let coord_ag = coord.clone();
        let ag_waiter = std::thread::spawn(move || {
            coord_ag.dispatch(PipeRequest::CheckLaunchGate {
                agent_id: Some("antigravity".into()),
            })
        });
        entered_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("first Launch waiter entered probe");

        let coord_cl = coord.clone();
        let cl_waiter = std::thread::spawn(move || {
            coord_cl.dispatch(PipeRequest::CheckLaunchGate {
                agent_id: Some("claude".into()),
            })
        });
        // Ensure `cl_waiter` has also queued into `launch_waiters` before releasing.
        let _ = coord.dispatch(PipeRequest::QueryLogs {
            since_ts: None,
            until_ts: None,
            limit: Some(1),
            query: None,
        });

        // Telemetry reports `MissingDll` before the paused Launch round finishes.
        let mut degraded_again = missing_dll;
        degraded_again.version_changed_from = None;
        coord.try_send_telemetry(TelemetryBundle {
            agents: Vec::new(),
            leak: LeakReport::not_applicable("mock", "mock", 1_700_000_205),
            leak_shield: LeakShieldStatus::default(),
            mihomo: MihomoStatus::default(),
            env: EnvCheck::default(),
            antigravity_proxy: degraded_again.clone(),
            self_check: build_defense_self_check(
                &cfg,
                &*driver,
                &journal,
                true,
                &degraded_again,
                1_700_000_205,
            ),
            updates: None,
            now_secs: 1_700_000_205,
        });
        let _ = coord.dispatch(PipeRequest::QueryLogs {
            since_ts: None,
            until_ts: None,
            limit: Some(1),
            query: None,
        });

        release_tx.send(()).unwrap();

        match ag_waiter.join().unwrap() {
            PipeResponse::LaunchGate {
                allowed, reason, ..
            } => {
                assert!(!allowed);
                assert!(reason.contains("反重力透明代理未就绪"));
            }
            other => panic!("expected LaunchGate deny for queued antigravity waiter: {other:?}"),
        }
        match cl_waiter.join().unwrap() {
            PipeResponse::LaunchGate { allowed, .. } => assert!(allowed),
            other => panic!("expected LaunchGate allow for queued claude waiter: {other:?}"),
        }

        // 3) Disabling `require_antigravity_proxy` allows `antigravity` once probe passes.
        cfg.require_antigravity_proxy = false;
        assert!(matches!(
            coord.dispatch(PipeRequest::SaveConfig { config: cfg }),
            PipeResponse::Ack { .. }
        ));
        assert!(matches!(
            coord.dispatch(PipeRequest::RecheckNow { target_id: None }),
            PipeResponse::Ack { .. }
        ));
        match coord.dispatch(PipeRequest::CheckLaunchGate {
            agent_id: Some("antigravity".into()),
        }) {
            PipeResponse::LaunchGate { allowed, .. } => assert!(allowed),
            other => {
                panic!("expected LaunchGate allow when require_antigravity_proxy=false: {other:?}")
            }
        }

        coord.shutdown();
    }

    #[test]
    fn sweep_orphans_invokes_driver_sweep_all_orphans() {
        let dir = tempfile::tempdir().unwrap();
        let driver = Arc::new(ControllableDriver::new());
        *driver.sweep_report.lock().unwrap() = SweepReport {
            scanned: 3,
            killed: 2,
            desktop_killed: 0,
            cli_killed: 1,
            unconfirmed: 1,
            detail: vec![
                "pid=4100 language_server.exe（反重力孤儿）".into(),
                "pid=4200 node.exe（Claude CLI）".into(),
            ],
            note: String::new(),
        };
        let runner = Arc::new(DelayedProbeRunner {
            gate_tx: None,
            release_rx: None,
            pass: Arc::new(AtomicBool::new(true)),
            ip_on_pass: "198.51.100.98".into(),
        });
        let recovery = Arc::new(MockRecoveryExecutor::new(MockRecoveryState::default()));
        let coord = boot_actor(dir.path(), driver.clone(), runner, recovery);

        match coord.dispatch(PipeRequest::SweepOrphans) {
            PipeResponse::Ack { receipt, .. } => {
                let r = receipt.expect("SweepOrphans must return receipt");
                assert_eq!(r.status, OperationStatus::Verified);
                assert!(r.verified_scope.contains("scanned=3, killed=2"));
                assert_eq!(r.items.len(), 1);
                assert_eq!(r.items[0].name, "sweep_all_orphans");
                assert!(r.items[0].detail.contains("language_server.exe"));
            }
            other => panic!("expected Ack from SweepOrphans, got {other:?}"),
        }

        assert_eq!(driver.sweep_all_calls.load(Ordering::Acquire), 1);
        assert_eq!(
            driver.sweep_claude_calls.load(Ordering::Acquire),
            0,
            "SweepOrphans must delegate to sweep_all_orphans rather than sweep_claude"
        );

        coord.shutdown();
    }

    #[test]
    fn telemetry_updates_antigravity_proxy_and_build_agent_statuses_propagates_orphan_counts() {
        let dir = tempfile::tempdir().unwrap();
        let driver = Arc::new(ControllableDriver::new());
        let runner = Arc::new(DelayedProbeRunner {
            gate_tx: None,
            release_rx: None,
            pass: Arc::new(AtomicBool::new(true)),
            ip_on_pass: "198.51.100.98".into(),
        });
        let recovery = Arc::new(MockRecoveryExecutor::new(MockRecoveryState::default()));
        let coord = boot_actor(dir.path(), driver.clone(), runner, recovery);

        let mut cfg = make_cfg("US");
        cfg.guarded_agents = vec!["claude".into(), "antigravity".into()];

        let healthy_ag = AntigravityProxyStatus {
            state: AntigravityProxyState::Healthy,
            installed: true,
            antigravity_dir: Some(r"C:\Apps\antigravity".into()),
            antigravity_version: Some("44.9.1".into()),
            dll_present: true,
            dll_valid: true,
            dll_size: 730_112,
            config_present: true,
            injector_version: Some("2.6.3".into()),
            proxy_type: Some("socks5".into()),
            proxy_host: Some("127.0.0.1".into()),
            proxy_port: Some(7890),
            port_matches_guard: true,
            child_injection: Some(true),
            runtime_running: true,
            runtime_dll_loaded_main: true,
            runtime_dll_loaded_ls: true,
            version_changed_from: None,
            checked_at: 1_700_000_500,
            summary: "version.dll 与运行时注入全部正常".into(),
        };
        *driver.ag_proxy.lock().unwrap() = healthy_ag.clone();

        let proc_snap = CachedProcessSnapshot {
            scanned_at_unix: 1_700_000_500,
            gui_counts: HashMap::from([("antigravity".into(), 4), ("claude".into(), 2)]),
            cli_counts: HashMap::from([("claude-code".into(), 1)]),
            orphan_counts: HashMap::from([
                ("antigravity".into(), 2),
                ("claude".into(), 1),
                ("claude-code".into(), 3),
            ]),
            antigravity_dirs_l: vec![r"c:\apps\antigravity".into()],
            ..Default::default()
        };

        let agents = build_agent_statuses(&cfg, &proc_snap, &*driver, &[], None);
        let ag_row = agents.iter().find(|a| a.id == "antigravity").unwrap();
        assert!(ag_row.installed);
        assert!(ag_row.guarded);
        assert_eq!(ag_row.running_count, 4);
        assert_eq!(ag_row.orphan_count, 2);

        let claude_row = agents.iter().find(|a| a.id == "claude").unwrap();
        assert_eq!(claude_row.running_count, 2);
        assert_eq!(claude_row.orphan_count, 1);

        let cli_row = agents.iter().find(|a| a.id == "claude-code").unwrap();
        assert_eq!(cli_row.running_count, 1);
        assert_eq!(cli_row.orphan_count, 3);

        let journal = JournalStore::new(dir.path());
        let self_check =
            build_defense_self_check(&cfg, &*driver, &journal, true, &healthy_ag, 1_700_000_500);
        assert_eq!(
            self_check
                .items
                .iter()
                .find(|i| i.id == "ag_proxy")
                .map(|i| i.status),
            Some(SelfCheckStatus::Healthy)
        );

        // Disabled self-check branch when degraded & require_antigravity_proxy == false.
        let mut disabled_cfg = cfg.clone();
        disabled_cfg.require_antigravity_proxy = false;
        let mut degraded_ag = healthy_ag.clone();
        degraded_ag.state = AntigravityProxyState::MissingDll;
        let disabled_sc = build_defense_self_check(
            &disabled_cfg,
            &*driver,
            &journal,
            true,
            &degraded_ag,
            1_700_000_501,
        );
        assert_eq!(
            disabled_sc
                .items
                .iter()
                .find(|i| i.id == "ag_proxy")
                .map(|i| i.status),
            Some(SelfCheckStatus::Disabled)
        );

        coord.try_send_telemetry(TelemetryBundle {
            agents,
            leak: LeakReport::not_applicable("mock", "mock", 1_700_000_500),
            leak_shield: LeakShieldStatus::default(),
            mihomo: MihomoStatus::default(),
            env: EnvCheck::default(),
            antigravity_proxy: healthy_ag.clone(),
            self_check,
            updates: None,
            now_secs: 1_700_000_500,
        });

        // Synchronize through the single-writer queue via QueryLogs so telemetry has been applied.
        let _ = coord.dispatch(PipeRequest::QueryLogs {
            since_ts: None,
            until_ts: None,
            limit: Some(5),
            query: None,
        });

        let snap = coord.snapshot();
        assert_eq!(snap.antigravity_proxy, healthy_ag);
        assert_eq!(
            snap.agents
                .iter()
                .find(|a| a.id == "antigravity")
                .map(|a| a.orphan_count),
            Some(2)
        );
        assert!(snap
            .self_check
            .items
            .iter()
            .any(|i| i.id == "ag_proxy" && i.status == SelfCheckStatus::Healthy));

        coord.shutdown();
    }

    #[test]
    fn check_updates_updates_snapshot_logs_audit_and_blocks_when_tripped_or_uncovered() {
        let dir = tempfile::tempdir().unwrap();
        let driver = Arc::new(ControllableDriver::new());
        let pass = Arc::new(AtomicBool::new(true));
        let runner = Arc::new(DelayedProbeRunner {
            gate_tx: None,
            release_rx: None,
            pass: pass.clone(),
            ip_on_pass: "198.51.100.98".into(),
        });
        let recovery = Arc::new(MockRecoveryExecutor::new(MockRecoveryState::default()));

        // Gate check_updates so we verify O(1) GetSnapshot never blocks while check runs off-thread.
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let gate_tx = Mutex::new(Some(entered_tx));
        let gate_rx = Mutex::new(release_rx);
        *driver.update_fn.lock().unwrap() = Some(Box::new(
            move |route, cg_ver, _ag, component, prev, now_secs| {
                if let Some(tx) = gate_tx.lock().unwrap().take() {
                    let _ = tx.send(());
                }
                let _ = gate_rx.lock().unwrap().recv_timeout(Duration::from_secs(2));
                assert!(matches!(route, ProbeRoute::Proxy(ref p) if p == "http://127.0.0.1:7890"));
                let mut next = prev.clone();
                if component.is_none() || component == Some("claudeguard") {
                    next.claudeguard.phase = UpdateCheckPhase::UpdateAvailable;
                    next.claudeguard.installed_version = Some(cg_ver.to_string());
                    next.claudeguard.latest_version = Some("4.1.0".into());
                    next.claudeguard.release_url =
                        Some("https://github.com/daha1216/ClaudeGuard/releases/tag/v4.1.0".into());
                    next.claudeguard.checked_at = Some(now_secs);
                    next.claudeguard.note = "发现新版 ClaudeGuard：4.0.0 -> 4.1.0".into();
                }
                if component.is_none() || component == Some("antigravity_proxy") {
                    next.antigravity_proxy.phase = UpdateCheckPhase::NotInstalled;
                    next.antigravity_proxy.checked_at = Some(now_secs);
                    next.antigravity_proxy.note = "本机未检测到反重力客户端".into();
                }
                next
            },
        ));

        let coord = boot_actor(dir.path(), driver.clone(), runner, recovery);
        assert_eq!(
            driver.check_updates_calls.load(Ordering::Acquire),
            0,
            "bootstrap must never invoke check_updates or network"
        );

        let mut cfg = make_cfg("US");
        cfg.enforce_access_path = true;
        cfg.proxy_host = "127.0.0.1".into();
        cfg.proxy_port = 7890;
        *driver.access_path_override.lock().unwrap() = Some(AccessPath::SystemProxy {
            addr: "127.0.0.1:7890".into(),
        });
        assert!(matches!(
            coord.dispatch(PipeRequest::CompleteOnboarding { config: cfg }),
            PipeResponse::Ack { .. }
        ));

        // Invalid component rejected cleanly.
        match coord.dispatch(PipeRequest::CheckUpdates {
            component: Some("invalid-comp".into()),
        }) {
            PipeResponse::Error { code, .. } => assert_eq!(code, ErrorCode::InvalidRequest),
            other => panic!("expected InvalidRequest, got {other:?}"),
        }

        // Run CheckUpdates off-thread; verify GetSnapshot returns immediately while worker blocks.
        let coord_bg = coord.clone();
        let upd_handle = std::thread::spawn(move || {
            coord_bg.dispatch(PipeRequest::CheckUpdates { component: None })
        });
        entered_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("check_updates worker must run");
        assert!(matches!(
            coord.dispatch(PipeRequest::GetSnapshot),
            PipeResponse::Snapshot { .. }
        ));
        release_tx.send(()).unwrap();

        match upd_handle.join().unwrap() {
            PipeResponse::Ack {
                receipt: Some(r),
                snapshot: Some(snap),
            } => {
                assert_eq!(r.status, OperationStatus::Verified);
                assert_eq!(
                    snap.updates.claudeguard.phase,
                    UpdateCheckPhase::UpdateAvailable
                );
                assert_eq!(
                    snap.updates.claudeguard.latest_version.as_deref(),
                    Some("4.1.0")
                );
            }
            other => panic!("expected Ack with updated snapshot, got {other:?}"),
        }

        // Verify audit log recorded under category "update".
        match coord.dispatch(PipeRequest::QueryLogs {
            since_ts: None,
            until_ts: None,
            limit: Some(50),
            query: Some("update".into()),
        }) {
            PipeResponse::Logs { entries, .. } => {
                assert!(entries
                    .iter()
                    .any(|e| e.category == "update" && e.level == LogLevel::Audit));
            }
            other => panic!("expected Logs, got {other:?}"),
        }

        // Telemetry refresh with older/unpopulated summary must preserve GitHub release results.
        let journal = JournalStore::new(dir.path());
        let sc = build_defense_self_check(
            &coord.snapshot().config,
            &*driver,
            &journal,
            true,
            &AntigravityProxyStatus::default(),
            1_700_000_999,
        );
        let msix_only = UpdateSummary {
            claude_msix_version: Some("1.2.3.4".into()),
            codex_msix_version: Some("26.1.2.3".into()),
            ..Default::default()
        };
        coord.try_send_telemetry(TelemetryBundle {
            agents: Vec::new(),
            leak: LeakReport::not_applicable("mock", "mock", 1_700_000_999),
            leak_shield: LeakShieldStatus::default(),
            mihomo: MihomoStatus::default(),
            env: EnvCheck::default(),
            antigravity_proxy: AntigravityProxyStatus::default(),
            self_check: sc,
            updates: Some(msix_only),
            now_secs: 1_700_000_999,
        });
        let _ = coord.dispatch(PipeRequest::QueryLogs {
            since_ts: None,
            until_ts: None,
            limit: Some(1),
            query: None,
        });
        let after_tel = coord.snapshot();
        assert_eq!(
            after_tel.updates.claude_msix_version.as_deref(),
            Some("1.2.3.4")
        );
        assert_eq!(
            after_tel.updates.codex_msix_version.as_deref(),
            Some("26.1.2.3")
        );
        assert_eq!(
            after_tel.updates.claudeguard.phase,
            UpdateCheckPhase::UpdateAvailable
        );
        assert_eq!(
            after_tel.updates.claudeguard.latest_version.as_deref(),
            Some("4.1.0")
        );

        // When AccessPath is Uncovered (ProbeRoute::Skip), must fail closed WITHOUT calling driver.check_updates.
        *driver.update_fn.lock().unwrap() = None;
        let calls_before_skip = driver.check_updates_calls.load(Ordering::Acquire);
        *driver.access_path_override.lock().unwrap() = Some(AccessPath::Uncovered);
        match coord.dispatch(PipeRequest::CheckUpdates {
            component: Some("claudeguard".into()),
        }) {
            PipeResponse::Ack {
                receipt: Some(r),
                snapshot: Some(snap),
            } => {
                assert_eq!(r.status, OperationStatus::Failed);
                assert_eq!(snap.updates.claudeguard.phase, UpdateCheckPhase::Failed);
                assert!(snap.updates.claudeguard.note.contains("拒绝直连"));
            }
            other => panic!("expected Ack(Failed) on ProbeRoute::Skip, got {other:?}"),
        }
        assert_eq!(
            driver.check_updates_calls.load(Ordering::Acquire),
            calls_before_skip,
            "ProbeRoute::Skip must never call driver.check_updates"
        );

        // Trip engine -> CheckUpdates immediately rejects with ErrorCode::IllegalState.
        *driver.access_path_override.lock().unwrap() = Some(AccessPath::Tun {
            adapter: "TestTun0".into(),
        });
        pass.store(false, Ordering::Release);
        assert!(matches!(
            coord.dispatch(PipeRequest::RecheckNow { target_id: None }),
            PipeResponse::Ack { .. }
        ));
        assert_eq!(coord.snapshot().protection, ProtectionState::Quarantined);
        match coord.dispatch(PipeRequest::CheckUpdates { component: None }) {
            PipeResponse::Error {
                code,
                message,
                receipt,
            } => {
                assert_eq!(code, ErrorCode::IllegalState);
                assert!(message.contains("熔断隔离态"));
                assert!(receipt.is_none());
            }
            other => panic!("expected IllegalState error when tripped, got {other:?}"),
        }

        coord.shutdown();
    }

    #[test]
    fn run_isolation_kills_both_claude_code_and_codex_clis_when_kill_cli_on_fail_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let driver = Arc::new(ControllableDriver::new());
        driver.gui_exes.lock().unwrap().insert(
            "chatgpt".into(),
            vec![PathBuf::from(r"C:\Apps\Codex\Codex.exe")],
        );
        driver.mock_gui_identities.lock().unwrap().insert(
            "claude".into(),
            vec![ProcessIdentity {
                pid: 1001,
                start_time: 10,
                exe_path: r"C:\Apps\Claude\claude.exe".into(),
            }],
        );
        driver.mock_gui_identities.lock().unwrap().insert(
            "chatgpt".into(),
            vec![ProcessIdentity {
                pid: 1002,
                start_time: 11,
                exe_path: r"C:\Apps\Codex\Codex.exe".into(),
            }],
        );
        driver.mock_cli_identities.lock().unwrap().insert(
            "claude-code".into(),
            vec![ProcessIdentity {
                pid: 2001,
                start_time: 12,
                exe_path: r"C:\Users\dev\.local\bin\claude.exe".into(),
            }],
        );
        driver.mock_cli_identities.lock().unwrap().insert(
            "codex".into(),
            vec![
                ProcessIdentity {
                    pid: 2002,
                    start_time: 13,
                    exe_path: r"C:\Users\dev\.local\bin\codex.exe".into(),
                },
                ProcessIdentity {
                    pid: 2003,
                    start_time: 14,
                    exe_path: r"C:\Users\dev\.local\bin\codex.exe".into(),
                },
            ],
        );

        let pass = Arc::new(AtomicBool::new(true));
        let runner = Arc::new(DelayedProbeRunner {
            gate_tx: None,
            release_rx: None,
            pass: pass.clone(),
            ip_on_pass: "198.51.100.98".into(),
        });
        let recovery = Arc::new(MockRecoveryExecutor::new(MockRecoveryState::default()));
        let coord = boot_actor(dir.path(), driver.clone(), runner, recovery);

        let mut cfg = make_cfg("US");
        cfg.guarded_agents = vec!["claude".into(), "chatgpt".into()];
        cfg.kill_on_fail = true;
        cfg.kill_cli_on_fail = true;
        assert!(matches!(
            coord.dispatch(PipeRequest::CompleteOnboarding {
                config: cfg.clone()
            }),
            PipeResponse::Ack { .. }
        ));
        assert!(matches!(
            coord.dispatch(PipeRequest::RecheckNow { target_id: None }),
            PipeResponse::Ack { .. }
        ));
        assert_eq!(coord.snapshot().protection, ProtectionState::Monitoring);
        assert!(driver.cli_killed_calls.lock().unwrap().is_empty());

        // Flip probe to fail and recheck -> trips and runs isolation killing GUI + both CLIs.
        pass.store(false, Ordering::Release);
        assert!(matches!(
            coord.dispatch(PipeRequest::RecheckNow { target_id: None }),
            PipeResponse::Ack { .. }
        ));

        let snap = coord.snapshot();
        assert_eq!(snap.protection, ProtectionState::Quarantined);
        let trip = snap.tripped.as_ref().expect("must be tripped");
        assert_eq!(trip.killed, 2);
        let receipt = trip.receipt.as_ref().expect("trip receipt");
        assert!(receipt
            .items
            .iter()
            .any(|i| i.name == "kill_cli:claude-code" && i.status == OperationStatus::Verified));
        assert!(receipt
            .items
            .iter()
            .any(|i| i.name == "kill_cli:codex" && i.status == OperationStatus::Verified));

        // Verify IsolationCompleted reported accurate cli_killed = 3 in trip audit log.
        assert!(snap
            .recent_logs
            .iter()
            .any(|l| l.category == "trip" && l.message.contains("CLI 3")));
        assert_eq!(
            driver.cli_killed_calls.lock().unwrap().as_slice(),
            &["claude-code", "codex"]
        );

        // Next round while still Quarantined triggers KillGuardedAgents -> also kills both CLIs.
        driver.cli_killed_calls.lock().unwrap().clear();
        assert!(matches!(
            coord.dispatch(PipeRequest::RecheckNow { target_id: None }),
            PipeResponse::Ack { .. }
        ));
        assert_eq!(
            driver.cli_killed_calls.lock().unwrap().as_slice(),
            &["claude-code", "codex"]
        );

        // Recover via Flow A, disable kill_cli_on_fail, trip again -> zero CLI kills!
        pass.store(true, Ordering::Release);
        assert!(matches!(
            coord.dispatch(PipeRequest::RecoverSafeFlowA),
            PipeResponse::Ack { .. }
        ));
        assert!(matches!(
            coord.dispatch(PipeRequest::RecheckNow { target_id: None }),
            PipeResponse::Ack { .. }
        ));
        assert_eq!(coord.snapshot().protection, ProtectionState::Monitoring);

        cfg.kill_cli_on_fail = false;
        assert!(matches!(
            coord.dispatch(PipeRequest::SaveConfig { config: cfg }),
            PipeResponse::Ack { .. }
        ));
        driver.cli_killed_calls.lock().unwrap().clear();
        pass.store(false, Ordering::Release);
        assert!(matches!(
            coord.dispatch(PipeRequest::RecheckNow { target_id: None }),
            PipeResponse::Ack { .. }
        ));
        let snap2 = coord.snapshot();
        assert_eq!(snap2.protection, ProtectionState::Quarantined);
        assert!(
            driver.cli_killed_calls.lock().unwrap().is_empty(),
            "kill_cli_on_fail=false must NOT terminate CLI processes"
        );
        assert!(snap2
            .recent_logs
            .iter()
            .any(|l| l.category == "trip" && l.message.contains("CLI 0")));

        coord.shutdown();
    }

    #[test]
    fn force_kill_agent_and_build_agent_statuses_cover_all_gui_and_cli_agents() {
        let dir = tempfile::tempdir().unwrap();
        let driver = Arc::new(ControllableDriver::new());
        driver.cli_exes.lock().unwrap().insert(
            "claude-code".into(),
            vec![PathBuf::from(r"C:\Users\dev\.local\bin\claude.exe")],
        );
        driver.cli_exes.lock().unwrap().insert(
            "codex".into(),
            vec![PathBuf::from(r"C:\Users\dev\.cargo\bin\codex.exe")],
        );
        driver.mock_gui_identities.lock().unwrap().insert(
            "chatgpt".into(),
            vec![ProcessIdentity {
                pid: 3001,
                start_time: 21,
                exe_path: r"C:\Apps\Codex\ChatGPT.exe".into(),
            }],
        );
        driver.mock_cli_identities.lock().unwrap().insert(
            "codex".into(),
            vec![ProcessIdentity {
                pid: 3002,
                start_time: 22,
                exe_path: r"C:\Users\dev\.cargo\bin\codex.exe".into(),
            }],
        );
        driver.mock_cli_identities.lock().unwrap().insert(
            "claude-code".into(),
            vec![ProcessIdentity {
                pid: 3003,
                start_time: 23,
                exe_path: r"C:\Users\dev\.local\bin\claude.exe".into(),
            }],
        );

        // Verify build_agent_statuses populates CLI install_paths, installed, guarded, and all 5 orphan counts.
        let mut cfg = make_cfg("US");
        cfg.guarded_agents = vec!["claude".into(), "chatgpt".into()];
        cfg.kill_cli_on_fail = true;
        let proc_snap = CachedProcessSnapshot {
            scanned_at_unix: 1_700_000_600,
            gui_counts: HashMap::from([("claude".into(), 1), ("chatgpt".into(), 2)]),
            cli_counts: HashMap::from([("gemini".into(), 1)]),
            orphan_counts: HashMap::from([
                ("claude".into(), 1),
                ("chatgpt".into(), 2),
                ("antigravity".into(), 3),
                ("claude-code".into(), 4),
                ("codex".into(), 5),
                ("gemini".into(), 6),
            ]),
            ..Default::default()
        };
        let rows = build_agent_statuses(&cfg, &proc_snap, &*driver, &[], None);
        for (id, expected_orphan) in [
            ("claude", 1usize),
            ("chatgpt", 2),
            ("antigravity", 3),
            ("claude-code", 4),
            ("codex", 5),
            ("gemini", 6),
        ] {
            let row = rows.iter().find(|r| r.id == id).unwrap();
            assert_eq!(row.orphan_count, expected_orphan, "agent {id}");
        }
        let cc_row = rows.iter().find(|r| r.id == "claude-code").unwrap();
        assert!(cc_row.installed);
        assert!(cc_row.guarded);
        assert_eq!(
            cc_row.install_paths,
            vec![r"C:\Users\dev\.local\bin\claude.exe".to_string()]
        );
        let codex_row = rows.iter().find(|r| r.id == "codex").unwrap();
        assert!(codex_row.installed);
        assert!(codex_row.guarded);
        assert_eq!(
            codex_row.install_paths,
            vec![r"C:\Users\dev\.cargo\bin\codex.exe".to_string()]
        );
        let gemini_row = rows.iter().find(|r| r.id == "gemini").unwrap();
        assert!(gemini_row.installed, "running > 0 marks gemini installed");
        assert!(!gemini_row.guarded);

        // Now test PipeRequest::ForceKillAgent via actor.
        let runner = Arc::new(DelayedProbeRunner {
            gate_tx: None,
            release_rx: None,
            pass: Arc::new(AtomicBool::new(true)),
            ip_on_pass: "198.51.100.98".into(),
        });
        let recovery = Arc::new(MockRecoveryExecutor::new(MockRecoveryState::default()));
        let coord = boot_actor(dir.path(), driver.clone(), runner, recovery);
        assert!(matches!(
            coord.dispatch(PipeRequest::CompleteOnboarding { config: cfg }),
            PipeResponse::Ack { .. }
        ));

        // 1) Unknown agent_id rejected cleanly.
        match coord.dispatch(PipeRequest::ForceKillAgent {
            agent_id: Some("unknown".into()),
            include_cli: true,
        }) {
            PipeResponse::Error { code, .. } => assert_eq!(code, ErrorCode::InvalidRequest),
            other => panic!("expected InvalidRequest, got {other:?}"),
        }

        // 2) Per-agent "chatgpt" with include_cli=true kills chatgpt GUI + codex CLI.
        match coord.dispatch(PipeRequest::ForceKillAgent {
            agent_id: Some("chatgpt".into()),
            include_cli: true,
        }) {
            PipeResponse::Ack {
                receipt: Some(r),
                snapshot: Some(snap),
            } => {
                assert_eq!(r.status, OperationStatus::Verified);
                assert!(r.verified_scope.contains("gui_killed=1, cli_killed=1"));
                assert!(snap
                    .recent_logs
                    .iter()
                    .any(|l| l.category == "kill" && l.level == LogLevel::Audit));
                let cc = snap.agents.iter().find(|a| a.id == "claude-code").unwrap();
                assert!(cc.installed);
                assert!(!cc.install_paths.is_empty());
            }
            other => panic!("expected Ack from ForceKillAgent(chatgpt), got {other:?}"),
        }
        assert_eq!(
            driver.gui_killed_calls.lock().unwrap().as_slice(),
            &["chatgpt"]
        );
        assert_eq!(
            driver.cli_killed_calls.lock().unwrap().as_slice(),
            &["codex"]
        );

        // 3) Global ForceKillAgent(None, include_cli=true) kills all guarded GUI + claude-code + codex.
        driver.gui_killed_calls.lock().unwrap().clear();
        driver.cli_killed_calls.lock().unwrap().clear();
        match coord.dispatch(PipeRequest::ForceKillAgent {
            agent_id: None,
            include_cli: true,
        }) {
            PipeResponse::Ack {
                receipt: Some(r), ..
            } => {
                assert_eq!(r.status, OperationStatus::Verified);
                assert!(r.verified_scope.contains("gui_killed=1, cli_killed=2"));
            }
            other => panic!("expected Ack from global ForceKillAgent, got {other:?}"),
        }
        assert_eq!(
            driver.gui_killed_calls.lock().unwrap().as_slice(),
            &["claude", "chatgpt"]
        );
        assert_eq!(
            driver.cli_killed_calls.lock().unwrap().as_slice(),
            &["claude-code", "codex"]
        );

        coord.shutdown();
    }

    #[test]
    fn background_monitor_triggers_auto_update_check_when_healthy_and_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let driver = Arc::new(ControllableDriver::new());
        let runner = Arc::new(DelayedProbeRunner {
            gate_tx: None,
            release_rx: None,
            pass: Arc::new(AtomicBool::new(true)),
            ip_on_pass: "198.51.100.98".into(),
        });
        let recovery = Arc::new(MockRecoveryExecutor::new(MockRecoveryState::default()));
        let process_scanner = Arc::new(ProcessScanner::new(Duration::from_secs(5)));

        let data_dir = dir.path().to_path_buf();
        let drv_clone = driver.clone();
        let (coord, ()) = start_coordinator_with(|event_tx| {
            let boot = RealEngineActor::bootstrap(data_dir, drv_clone, runner, recovery, event_tx);
            (boot.initial_snapshot, Box::new(boot.actor), ())
        });

        let mut cfg = make_cfg("US");
        cfg.auto_upd_check = true;
        assert!(matches!(
            coord.dispatch(PipeRequest::CompleteOnboarding { config: cfg }),
            PipeResponse::Ack { .. }
        ));
        assert!(matches!(
            coord.dispatch(PipeRequest::RecheckNow { target_id: None }),
            PipeResponse::Ack { .. }
        ));
        assert_eq!(coord.snapshot().protection, ProtectionState::Monitoring);
        assert!(coord.snapshot().all_enabled_pass());

        let monitor = BackgroundMonitorHandle::start_with_intervals(
            coord.clone(),
            driver.clone(),
            process_scanner,
            dir.path().to_path_buf(),
            false,
            Duration::from_millis(25),
            Duration::from_secs(3600),
        );

        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if driver.check_updates_calls.load(Ordering::Acquire) >= 1
                && coord.snapshot().updates.claudeguard.phase == UpdateCheckPhase::UpToDate
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        monitor.shutdown();

        assert_eq!(
            driver.check_updates_calls.load(Ordering::Acquire),
            1,
            "auto update check must trigger once after healthy monitoring is confirmed"
        );
        assert_eq!(
            coord.snapshot().updates.claudeguard.phase,
            UpdateCheckPhase::UpToDate
        );

        coord.shutdown();
    }

    #[test]
    fn save_config_auto_syncs_leak_shield_when_armed_and_skips_when_unchanged_or_disarmed() {
        type SyncCall = (Vec<PathBuf>, bool, bool, bool);
        let calls: Arc<Mutex<Vec<SyncCall>>> = Arc::new(Mutex::new(Vec::new()));
        let calls_hook = calls.clone();
        let mock_syncer: LeakShieldSyncFn = Arc::new(move |exes, quic, dns, ipv6| {
            calls_hook
                .lock()
                .unwrap()
                .push((exes.to_vec(), quic, dns, ipv6));
            let active_rules =
                exes.len() * (usize::from(quic) + usize::from(dns) * 3 + usize::from(ipv6));
            Ok(LeakShieldStatus {
                enabled: active_rules > 0,
                quic_blocked: quic && active_rules > 0,
                dns_doh_blocked: dns && active_rules > 0,
                ipv6_blocked: ipv6 && active_rules > 0,
                active_rules,
                summary: format!("mock shield synced ({active_rules})"),
            })
        });

        let dir = tempfile::tempdir().unwrap();
        let driver = Arc::new(ControllableDriver::new());
        driver.gui_exes.lock().unwrap().insert(
            "chatgpt".into(),
            vec![PathBuf::from(r"C:\Apps\ChatGPT\ChatGPT.exe")],
        );
        let runner = Arc::new(DelayedProbeRunner {
            gate_tx: None,
            release_rx: None,
            pass: Arc::new(AtomicBool::new(true)),
            ip_on_pass: "198.51.100.98".into(),
        });
        let recovery = Arc::new(MockRecoveryExecutor::new(MockRecoveryState::default()));

        let data_dir = dir.path().to_path_buf();
        let drv_clone = driver.clone();
        let syncer_clone = mock_syncer.clone();
        let (coord, ()) = start_coordinator_with(|event_tx| {
            let boot = RealEngineActor::bootstrap(data_dir, drv_clone, runner, recovery, event_tx);
            let actor = boot.actor.with_leak_shield_syncer(syncer_clone);
            (boot.initial_snapshot, Box::new(actor), ())
        });

        let mut cfg = make_cfg("US");
        cfg.guarded_agents = vec!["claude".into()];
        cfg.leak_shield_quic = false;
        cfg.leak_shield_dns_doh = false;
        cfg.leak_shield_ipv6 = false;
        assert!(matches!(
            coord.dispatch(PipeRequest::CompleteOnboarding {
                config: cfg.clone(),
            }),
            PipeResponse::Ack { .. }
        ));
        assert_eq!(coord.snapshot().lifecycle, Lifecycle::Armed);
        assert!(calls.lock().unwrap().is_empty());

        // 1) Enabling QUIC while Armed automatically triggers leak shield sync.
        cfg.leak_shield_quic = true;
        match coord.dispatch(PipeRequest::SaveConfig {
            config: cfg.clone(),
        }) {
            PipeResponse::Ack {
                receipt: Some(rcpt),
                snapshot: Some(snap),
            } => {
                assert_eq!(rcpt.status, OperationStatus::Verified);
                assert_eq!(rcpt.verified_scope, "leak_shield");
                assert!(snap.leak_shield.enabled);
                assert!(snap.leak_shield.quic_blocked);
                assert!(!snap.leak_shield.dns_doh_blocked);
                assert!(!snap.leak_shield.ipv6_blocked);
                assert_eq!(snap.leak_shield.active_rules, 1);
                assert!(snap
                    .recent_logs
                    .iter()
                    .any(|l| l.category == "shield" && l.level == LogLevel::Audit));
            }
            other => panic!("expected Ack with leak_shield receipt, got {other:?}"),
        }
        assert_eq!(calls.lock().unwrap().len(), 1);
        assert_eq!(
            calls.lock().unwrap()[0],
            (
                vec![PathBuf::from(r"C:\Apps\Claude\claude.exe")],
                true,
                false,
                false
            )
        );

        // 2) Saving unrelated config changes does NOT re-trigger leak shield sync.
        cfg.kill_cli_on_fail = !cfg.kill_cli_on_fail;
        assert!(matches!(
            coord.dispatch(PipeRequest::SaveConfig {
                config: cfg.clone(),
            }),
            PipeResponse::Ack { .. }
        ));
        assert_eq!(calls.lock().unwrap().len(), 1);

        // 3) Enabling DNS/DoH + IPv6 and adding another guarded agent triggers sync with updated exes.
        cfg.leak_shield_dns_doh = true;
        cfg.leak_shield_ipv6 = true;
        cfg.guarded_agents = vec!["claude".into(), "chatgpt".into()];
        assert!(matches!(
            coord.dispatch(PipeRequest::SaveConfig {
                config: cfg.clone(),
            }),
            PipeResponse::Ack { .. }
        ));
        assert_eq!(calls.lock().unwrap().len(), 2);
        assert_eq!(
            calls.lock().unwrap()[1],
            (
                vec![
                    PathBuf::from(r"C:\Apps\Claude\claude.exe"),
                    PathBuf::from(r"C:\Apps\ChatGPT\ChatGPT.exe"),
                ],
                true,
                true,
                true
            )
        );
        let snap2 = coord.snapshot();
        assert!(snap2.leak_shield.quic_blocked);
        assert!(snap2.leak_shield.dns_doh_blocked);
        assert!(snap2.leak_shield.ipv6_blocked);
        assert_eq!(snap2.leak_shield.active_rules, 10);

        // 4) Toggling all vectors off triggers idempotent rule removal sync.
        cfg.leak_shield_quic = false;
        cfg.leak_shield_dns_doh = false;
        cfg.leak_shield_ipv6 = false;
        assert!(matches!(
            coord.dispatch(PipeRequest::SaveConfig {
                config: cfg.clone(),
            }),
            PipeResponse::Ack { .. }
        ));
        assert_eq!(calls.lock().unwrap().len(), 3);
        assert!(!coord.snapshot().leak_shield.enabled);
        assert_eq!(coord.snapshot().leak_shield.active_rules, 0);

        coord.shutdown();

        // 5) When Lifecycle::Disarmed, changing leak shield flags in SaveConfig must NOT trigger sync.
        let disarmed_dir = tempfile::tempdir().unwrap();
        let store = ConfigStore::new(disarmed_dir.path());
        store.save_verified(&cfg).unwrap();
        disarm::mark_disarmed(disarmed_dir.path(), "unit-test").unwrap();

        let disarmed_calls = Arc::new(AtomicUsize::new(0));
        let dc_hook = disarmed_calls.clone();
        let disarmed_syncer: LeakShieldSyncFn = Arc::new(move |_, _, _, _| {
            dc_hook.fetch_add(1, Ordering::AcqRel);
            Ok(LeakShieldStatus::default())
        });
        let runner2 = Arc::new(DelayedProbeRunner {
            gate_tx: None,
            release_rx: None,
            pass: Arc::new(AtomicBool::new(true)),
            ip_on_pass: "198.51.100.98".into(),
        });
        let recovery2 = Arc::new(MockRecoveryExecutor::new(MockRecoveryState::default()));
        let d_path = disarmed_dir.path().to_path_buf();
        let (coord2, ()) = start_coordinator_with(|event_tx| {
            let boot = RealEngineActor::bootstrap(d_path, driver, runner2, recovery2, event_tx);
            let actor = boot.actor.with_leak_shield_syncer(disarmed_syncer);
            (boot.initial_snapshot, Box::new(actor), ())
        });
        assert_eq!(coord2.snapshot().lifecycle, Lifecycle::Disarmed);

        cfg.leak_shield_quic = true;
        assert!(matches!(
            coord2.dispatch(PipeRequest::SaveConfig { config: cfg }),
            PipeResponse::Ack { .. }
        ));
        assert_eq!(
            disarmed_calls.load(Ordering::Acquire),
            0,
            "SaveConfig while Disarmed must NOT write firewall leak shield rules"
        );
        coord2.shutdown();
    }
}
