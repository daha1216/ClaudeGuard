//! Real Wave-2 daemon engine actor wiring `cg-core::GuardEngine`, `cg-platform::PlatformDriver`,
//! `JournalStore`, `ConfigStore`, `TimelineAggregator`, and background monitor/telemetry loops.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
use cg_core::hygiene_plan;
use cg_core::onboarding;
use cg_core::policy;
use cg_core::risk_scorer;
use cg_core::timeline::BUCKETS_48;
use cg_core::{BurstGuardConfig, BurstGuardTracker, TimelineAggregator};
use cg_platform::access_win::{self, AccessPath};
use cg_platform::antigravity_proxy_win;
use cg_platform::cleanroom_win;
use cg_platform::env_win;
use cg_platform::firewall_com;
use cg_platform::hygiene_win;
use cg_platform::ip_intel;
use cg_platform::leak_shield_win;
use cg_platform::mihomo_win;
use cg_platform::netwatch_win;
use cg_platform::probe_http::{self, NetworkPolicy, ProbeRoute};
use cg_platform::process_win::{
    self, CachedProcessSnapshot, ClaudePresence, LaunchTarget, ProcessScanner, SweepMode,
};
use cg_platform::stun_probe;
use cg_platform::vault_win;
use cg_platform::{update_check, wfp_win, PlatformDriver, PlatformError};

use crate::config_store::{ConfigStore, LoadedConfig};
use crate::coordinator::{
    check_vault_egress_contract, current_primary_egress, evaluate_fast_hook_gate_at, ActorControl,
    CoordinatorActor, CoordinatorContext, CoordinatorEvent, CoordinatorHandle, FastGateOutcome,
    HookGateMetrics, TelemetryBundle,
};
use crate::diagnostics;
use crate::disarm;
use crate::egress_ledger::EgressLedger;
use crate::feishu::FeishuNotifier;
use crate::hook_installer;
use crate::journal::{
    self, BaselineState, FirewallDirection, HealReport, HealStatus, JournalStore, LoadedJournal,
    PlannedStep, RecoveryExecutor, RecoveryJournal, TxKind, WalAction,
};
use crate::protocol::{
    is_valid_vault_id, now_unix_millis, now_unix_secs, AccessEvidence, AccessLevel, AgentKind,
    AgentRuntimeStatus, AntigravityProxyState, AntigravityProxyStatus, BurstGuardStatus,
    CleanRoomReport, ComponentUpdateStatus, Config, CutMode, DefenseCheckItem, DefenseSelfCheck,
    ErrorCode, GuardSnapshot, HookDecision, HookIntegrationStatus, HotkeyStatus, LeakReport,
    LeakShieldStatus, Lifecycle, LogLevel, MihomoStatus, OnboardingProbeResult, OperationReceipt,
    OperationStatus, PipeRequest, PipeResponse, PolicyPreset, ProbeResult, ProtectionState,
    RiskAssessment, SelfCheckStatus, Target, ToastNotificationEvent, UpdateCheckPhase,
    UpdateSummary, VaultAppTarget, VaultRuntimeState, VaultRuntimeStatus, WslBridgeStatus,
    KNOWN_CLI_AGENT_IDS,
};
use crate::wsl_bridge;

pub const TIMELINE_FILE: &str = "timeline.json";
const DEFAULT_TELEMETRY_INTERVAL: Duration = Duration::from_secs(10);
const AUTO_UPDATE_CHECK_INTERVAL: Duration = Duration::from_secs(6 * 3600);
const AUTO_UPDATE_RETRY_INTERVAL: Duration = Duration::from_secs(20 * 60);
const WAKE_GRACE_DURATION: Duration = Duration::from_secs(20);

struct InFlightGuard(Arc<AtomicBool>);

impl InFlightGuard {
    fn try_acquire(flag: &Arc<AtomicBool>) -> Option<Self> {
        flag.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Self(flag.clone()))
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn fallback_proxy_route(cfg: &Config) -> ProbeRoute {
    let policy = NetworkPolicy::with_proxy(&cfg.proxy_host, cfg.proxy_port);
    match policy.route() {
        probe_http::Route::Proxy(addr) => ProbeRoute::Proxy(addr),
        probe_http::Route::Direct => ProbeRoute::Direct,
    }
}

fn monitored_hosts_for_slice(cfg: &Config, targets: &[Target]) -> Vec<String> {
    if targets.len() == cfg.targets.len()
        && targets
            .iter()
            .zip(cfg.targets.iter())
            .all(|(a, b)| a.id == b.id && a.enabled == b.enabled && a.anchor_url == b.anchor_url)
    {
        return cg_core::access::monitored_hosts(cfg);
    }
    let mut tmp = cfg.clone();
    tmp.targets = targets.to_vec();
    cg_core::access::monitored_hosts(&tmp)
}

fn resolve_access_and_route(
    driver: &dyn PlatformDriver,
    cfg: &Config,
    cfg_rev: u64,
    targets: &[Target],
    enforce_access_path: bool,
    now_secs: u64,
) -> (AccessEvidence, ProbeRoute) {
    let hosts = monitored_hosts_for_slice(cfg, targets);

    let caps = driver.capabilities();
    if caps.access_path_inspection {
        match driver.inspect_access_path(&hosts) {
            Ok((access_path, _info)) => {
                let ev = access_path.to_protocol_evidence(now_secs, cfg_rev);
                let route = match &access_path {
                    AccessPath::SystemProxy { addr } => {
                        if addr.contains("://") {
                            ProbeRoute::Proxy(addr.clone())
                        } else {
                            ProbeRoute::Proxy(format!("http://{addr}"))
                        }
                    }
                    AccessPath::Tun { .. } => ProbeRoute::Direct,
                    _ => match probe_http::plan_probe_route(&access_path) {
                        ProbeRoute::Skip(_) if !enforce_access_path => fallback_proxy_route(cfg),
                        other => other,
                    },
                };
                (ev, route)
            }
            Err(err) => {
                let ev = AccessEvidence {
                    level: AccessLevel::Unknown,
                    observed_at: now_secs,
                    revision: cfg_rev,
                    note: err.to_string(),
                    ..AccessEvidence::default()
                };
                let route = if enforce_access_path {
                    ProbeRoute::Skip(err.to_string())
                } else {
                    fallback_proxy_route(cfg)
                };
                (ev, route)
            }
        }
    } else {
        let ev = AccessEvidence {
            level: AccessLevel::Unknown,
            observed_at: now_secs,
            revision: cfg_rev,
            note: "access inspection bypassed or unsupported".into(),
            ..AccessEvidence::default()
        };
        (ev, fallback_proxy_route(cfg))
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
    let v5_local = update_check::V5LocalIdeVersions::detect();
    update_check::hydrate_v5_ide_updates(updates, &v5_local, now_unix_secs());
}

fn merge_slot(dst: &mut ComponentUpdateStatus, incoming: ComponentUpdateStatus) {
    if incoming.checked_at > dst.checked_at
        || (dst.phase == UpdateCheckPhase::Idle && incoming.phase != UpdateCheckPhase::Idle)
    {
        *dst = incoming;
    } else {
        dst.installed_version = incoming.installed_version.clone();
    }
    if dst.id != "claudeguard"
        && dst.installed_version.is_none()
        && matches!(
            dst.phase,
            UpdateCheckPhase::UpToDate | UpdateCheckPhase::UpdateAvailable
        )
    {
        dst.phase = UpdateCheckPhase::NotInstalled;
    }
}

fn merge_telemetry_updates(dst: &mut UpdateSummary, incoming: UpdateSummary) {
    dst.claude_msix_version = incoming.claude_msix_version;
    dst.codex_msix_version = incoming.codex_msix_version;

    merge_slot(&mut dst.claudeguard, incoming.claudeguard);
    merge_slot(&mut dst.antigravity_proxy, incoming.antigravity_proxy);
    merge_slot(&mut dst.claude_desktop, incoming.claude_desktop);
    merge_slot(&mut dst.claude_code, incoming.claude_code);
    merge_slot(&mut dst.codex_desktop, incoming.codex_desktop);
    merge_slot(&mut dst.codex_cli, incoming.codex_cli);
    merge_slot(&mut dst.antigravity_ide, incoming.antigravity_ide);
    merge_slot(&mut dst.antigravity_cn, incoming.antigravity_cn);
    merge_slot(&mut dst.ag_usage_monitor, incoming.ag_usage_monitor);
    merge_slot(&mut dst.ag_capsule, incoming.ag_capsule);
    merge_slot(&mut dst.cursor_ide, incoming.cursor_ide);
    merge_slot(&mut dst.windsurf_ide, incoming.windsurf_ide);
    merge_slot(&mut dst.zed_ide, incoming.zed_ide);
    merge_slot(&mut dst.trae_ide, incoming.trae_ide);
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
            "cursor_ide" | "cursor-ide" | "cursor" => {
                Ok((false, false, Some("cursor_ide".to_string())))
            }
            "windsurf_ide" | "windsurf-ide" | "windsurf" => {
                Ok((false, false, Some("windsurf_ide".to_string())))
            }
            "zed_ide" | "zed-ide" | "zed" => Ok((false, false, Some("zed_ide".to_string()))),
            "trae_ide" | "trae-ide" | "trae" => Ok((false, false, Some("trae_ide".to_string()))),
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
        ("cursor_ide", &mut out.cursor_ide),
        ("windsurf_ide", &mut out.windsurf_ide),
        ("zed_ide", &mut out.zed_ide),
        ("trae_ide", &mut out.trae_ide),
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

const PROBE_JITTER_RETRY_DELAY: Duration = Duration::from_millis(350);

/// Probe a single target over `route`, absorbing one transient proxy/TLS blip when the initial
/// transport error occurs fast enough to retry inside the original timeout budget.
/// Strictly reuses the exact same `ProbeRoute` (never falls back to direct).
fn probe_target_with_jitter_retry(route: &ProbeRoute, target: &Target) -> ProbeResult {
    let timeout = Duration::from_secs(target.timeout_secs.clamp(3, 60));
    let started = Instant::now();
    let first = probe_http::probe_url(route, &target.anchor_url, timeout, anchors::MAX_BODY_BYTES);
    let resp = match first {
        Ok(resp) => Ok(resp),
        Err(first_err) => {
            let elapsed = started.elapsed();
            if !matches!(route, ProbeRoute::Skip(_)) && elapsed < timeout / 2 {
                std::thread::sleep(PROBE_JITTER_RETRY_DELAY);
                let remaining = timeout
                    .saturating_sub(started.elapsed())
                    .max(Duration::from_secs(2));
                probe_http::probe_url(
                    route,
                    &target.anchor_url,
                    remaining,
                    anchors::MAX_BODY_BYTES,
                )
                .or(Err(first_err))
            } else {
                Err(first_err)
            }
        }
    };
    match resp {
        Ok(resp) => anchors::parse_body_bytes(
            target.anchor_kind,
            resp.body.as_bytes(),
            Some(resp.status),
            resp.latency_ms,
        ),
        Err(err) => ProbeResult::failed(err.to_string()),
    }
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
                    let probe = probe_target_with_jitter_retry(r, target);
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
    pub egress_ledger: Arc<EgressLedger>,
}

/// Injection point for synchronizing OS 4-vector leak shield rules (`leak_shield_win::sync_leak_shield` in production).
type LeakShieldSyncFn = Arc<
    dyn Fn(&[PathBuf], bool, bool, bool) -> cg_platform::PlatformResult<LeakShieldStatus>
        + Send
        + Sync,
>;

type FastHookWaiter = (
    String,
    Option<String>,
    Option<String>,
    SyncSender<PipeResponse>,
);

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
    synced_agent_exes: BTreeMap<String, Vec<PathBuf>>,
    event_tx: SyncSender<CoordinatorEvent>,
    probe_tx: SyncSender<ProbeJob>,
    _probe_worker: Option<JoinHandle<()>>,
    recheck_waiters: Vec<SyncSender<PipeResponse>>,
    launch_waiters: Vec<(Option<String>, SyncSender<PipeResponse>)>,
    fast_hook_waiters: Vec<FastHookWaiter>,
    last_rejected: Option<(ErrorCode, String)>,
    mutation_error: Option<String>,
    pause_deadline: Option<Instant>,
    wake_grace_until: Option<Instant>,
    wake_timer_active: Arc<AtomicBool>,
    stopping_ready: bool,
    feishu: Arc<FeishuNotifier>,
    feishu_flush_in_flight: Arc<AtomicBool>,
    single_recheck_in_flight: Arc<AtomicBool>,
    onboarding_probe_in_flight: Arc<AtomicBool>,
    update_check_in_flight: Arc<AtomicBool>,
    feishu_test_in_flight: Arc<AtomicBool>,
    mihomo_switch_in_flight: Arc<AtomicBool>,
    ag_repair_in_flight: Arc<AtomicBool>,
    deep_audit_in_flight: Arc<AtomicBool>,
    wsl_sync_in_flight: Arc<AtomicBool>,
    recent_toasts: VecDeque<ToastNotificationEvent>,
    toast_seq: u64,
    leak_shield: LeakShieldStatus,
    leak_shield_syncer: LeakShieldSyncFn,
    mihomo: MihomoStatus,
    last_wal_heal_error: Option<String>,
    last_wal_heal_attempt: Option<Instant>,
    last_flushed_log_id: AtomicU64,
    // ---- v5 Runtime State (M1–M7) ----
    egress_ledger: Arc<EgressLedger>,
    last_cleanroom_report: Option<CleanRoomReport>,
    cleanroom_backup_count: usize,
    hooks: HookIntegrationStatus,
    wsl_bridge: WslBridgeStatus,
    vault_sessions: HashMap<String, Vec<(u32, String)>>,
    burst_guard_ref: Option<Arc<Mutex<BurstGuardTracker>>>,
    hook_metrics_ref: Option<Arc<HookGateMetrics>>,
    test_user_home_override: Option<PathBuf>,
    test_vaults_root_override: Option<PathBuf>,
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
        let default_syncer: LeakShieldSyncFn = Arc::new(|exes, quic, dns_doh, ipv6| {
            if let Some(hybrid) = cg_platform::active_hybrid_firewall() {
                hybrid.sync_leak_shield_wfp(exes, quic, dns_doh, ipv6)
            } else {
                leak_shield_win::sync_leak_shield(exes, quic, dns_doh, ipv6)
            }
        });
        Self::bootstrap_with_syncer(
            data_dir,
            driver,
            probe_runner,
            recovery_executor,
            probe_event_tx,
            default_syncer,
        )
    }

    fn bootstrap_with_syncer(
        data_dir: PathBuf,
        driver: Arc<dyn PlatformDriver>,
        probe_runner: Arc<dyn ProbeRunner>,
        recovery_executor: Arc<dyn RecoveryExecutor>,
        probe_event_tx: SyncSender<CoordinatorEvent>,
        leak_shield_syncer: LeakShieldSyncFn,
    ) -> BootstrappedActor {
        let now = now_unix_secs();
        let _ = journal::ensure_secure_data_dir(&data_dir);
        let journal = JournalStore::new(&data_dir);
        let mut heal_report = journal::heal_on_startup(&journal, &*recovery_executor);
        if driver.capabilities().app_quarantine
            && (!heal_report.ok || !heal_report.verified)
            && heal_report.status != HealStatus::CorruptJournal
        {
            for backoff_ms in [250u64, 500, 1000, 1500] {
                std::thread::sleep(Duration::from_millis(backoff_ms));
                heal_report = journal::heal_on_startup(&journal, &*recovery_executor);
                if (heal_report.ok && heal_report.verified)
                    || heal_report.status == HealStatus::CorruptJournal
                {
                    break;
                }
            }
        }

        let config_store = ConfigStore::new(&data_dir);
        let _ = config_store.backup_legacy_once();
        let (cfg, corrupt_err) = match config_store.load_readonly() {
            LoadedConfig::NotFound => (Config::default(), None),
            LoadedConfig::Loaded(outcome) => {
                let mut loaded = outcome.config;
                match cg_core::targets::validate(loaded.targets.clone()) {
                    Ok(valid_targets) => {
                        loaded.targets = valid_targets;
                        (loaded, None)
                    }
                    Err(val_err) => {
                        if let Ok(raw) = std::fs::read_to_string(config_store.path()) {
                            let _ = config_store.backup_corrupt_once(&raw);
                        }
                        (
                            Config::default(),
                            Some(format!(
                                "配置文件校验未通过，已隔离并恢复安全默认配置：{val_err}"
                            )),
                        )
                    }
                }
            }
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
        if disarmed_reason.is_some() {
            if caps.app_quarantine {
                let _ = leak_shield_win::clear_leak_shield();
            }
            let _ = diagnostics::rollback_env_alignment(&data_dir);
        }
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
        let mut synced_agent_exes = BTreeMap::new();
        for a in &cached_agents {
            if a.kind == AgentKind::Gui {
                synced_agent_exes.insert(
                    a.id.clone(),
                    a.install_paths.iter().map(PathBuf::from).collect(),
                );
            }
        }
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
            .ok();

        let feishu = Arc::new(FeishuNotifier::load(&data_dir));
        if let Some(env_backup) = diagnostics::load_env_backup(&data_dir) {
            engine.env_applied = Some(env_backup.applied);
        }
        let init_shield =
            if caps.app_quarantine && init_fw_query_ok && engine.lifecycle != Lifecycle::Disarmed {
                leak_shield_win::inspect_leak_shield()
            } else {
                LeakShieldStatus::default()
            };
        let init_wal_heal_error = wal_pending.then(|| heal_report.summary.clone());
        let egress_ledger = Arc::new(EgressLedger::open(&data_dir));
        let cleanroom_backup_count = cleanroom_win::list_cleanroom_backups(&data_dir).len();
        let init_hooks = hook_installer::inspect_hook_status(&engine.config.vaults, 0, 0, 0);
        let init_wsl_bridge = WslBridgeStatus {
            enabled: engine.config.wsl_bridge_enabled,
            listening: false,
            bound_port: None,
            token_ready: false,
            synced_distros: Vec::new(),
            proxy_desync_detected: false,
            summary: if engine.config.wsl_bridge_enabled {
                "WSL2 回环桥接等待初始化".into()
            } else {
                "WSL2 跨子系统桥接已关闭".into()
            },
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
            synced_agent_exes,
            event_tx,
            probe_tx,
            _probe_worker: probe_worker,
            recheck_waiters: Vec::new(),
            launch_waiters: Vec::new(),
            fast_hook_waiters: Vec::new(),
            last_rejected: None,
            mutation_error: None,
            pause_deadline: None,
            wake_grace_until: None,
            wake_timer_active: Arc::new(AtomicBool::new(false)),
            stopping_ready: false,
            feishu,
            feishu_flush_in_flight: Arc::new(AtomicBool::new(false)),
            single_recheck_in_flight: Arc::new(AtomicBool::new(false)),
            onboarding_probe_in_flight: Arc::new(AtomicBool::new(false)),
            update_check_in_flight: Arc::new(AtomicBool::new(false)),
            feishu_test_in_flight: Arc::new(AtomicBool::new(false)),
            mihomo_switch_in_flight: Arc::new(AtomicBool::new(false)),
            ag_repair_in_flight: Arc::new(AtomicBool::new(false)),
            deep_audit_in_flight: Arc::new(AtomicBool::new(false)),
            wsl_sync_in_flight: Arc::new(AtomicBool::new(false)),
            recent_toasts: VecDeque::new(),
            toast_seq: 0,
            leak_shield: init_shield,
            leak_shield_syncer,
            mihomo: MihomoStatus::default(),
            last_wal_heal_error: init_wal_heal_error,
            last_wal_heal_attempt: None,
            last_flushed_log_id: AtomicU64::new(0),
            egress_ledger: egress_ledger.clone(),
            last_cleanroom_report: None,
            cleanroom_backup_count,
            hooks: init_hooks,
            wsl_bridge: init_wsl_bridge,
            vault_sessions: HashMap::new(),
            burst_guard_ref: None,
            hook_metrics_ref: None,
            test_user_home_override: None,
            test_vaults_root_override: None,
        };

        actor.sync_wfp_config(now);

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
        let mut init_self_check = build_defense_self_check(
            &actor.engine.config,
            &*actor.driver,
            &actor.journal,
            init_fw_query_ok,
            &actor.engine.antigravity_proxy,
            now,
        );
        enrich_self_check_wal_error(
            &mut init_self_check,
            &actor.journal,
            actor.last_wal_heal_error.as_deref(),
        );
        actor.step_and_run(
            EngineEvent::SelfCheckUpdated {
                self_check: init_self_check,
            },
            now,
        );
        if actor.engine.lifecycle == Lifecycle::Armed
            && caps.app_quarantine
            && (actor.engine.config.leak_shield_quic
                || actor.engine.config.leak_shield_dns_doh
                || actor.engine.config.leak_shield_ipv6)
        {
            if let Err(err) = actor.sync_leak_shield_rules(now) {
                actor.engine.push_log(
                    now,
                    LogLevel::Warn,
                    "shield",
                    &format!("启动同步防泄露护盾规则失败：{err}"),
                );
            }
        }
        actor.flush_pending_daemon_logs();
        let initial_snapshot = actor.build_snapshot(now);

        BootstrappedActor {
            actor,
            initial_snapshot,
            heal_report,
            process_scanner,
            egress_ledger,
        }
    }

    #[cfg(test)]
    fn with_leak_shield_syncer(mut self, syncer: LeakShieldSyncFn) -> Self {
        self.leak_shield_syncer = syncer;
        self
    }

    #[cfg(test)]
    fn with_test_sandbox_dirs(mut self, user_home: PathBuf, vaults_root: PathBuf) -> Self {
        self.test_user_home_override = Some(user_home);
        self.test_vaults_root_override = Some(vaults_root);
        self
    }

    fn effective_user_home(&self) -> Option<PathBuf> {
        self.test_user_home_override
            .clone()
            .or_else(hook_installer::resolve_interactive_user_home)
    }

    fn effective_vaults_root(&self) -> Result<PathBuf, String> {
        if let Some(ref root) = self.test_vaults_root_override {
            return Ok(root.clone());
        }
        vault_win::default_vaults_root()
    }

    fn sync_wfp_config(&mut self, now: u64) {
        if self.driver.capabilities().app_quarantine {
            if let Some(hybrid) = cg_platform::active_hybrid_firewall() {
                let _ = hybrid.set_preference(self.engine.config.firewall_backend);
                // Safest default: `wfp_boot_guard` is default `false`. Only arm persistent boot
                // filters when explicitly opted-in while Armed, recording WAL first.
                if self.engine.config.wfp_boot_guard && self.engine.lifecycle == Lifecycle::Armed {
                    let mut exes = Vec::new();
                    for agent in &self.engine.config.guarded_agents {
                        for p in self.driver.discover_agent_exes(agent).unwrap_or_default() {
                            if !exes.contains(&p) {
                                exes.push(p);
                            }
                        }
                    }
                    let sublayer_guid = format_wfp_persistent_sublayer_guid();
                    let step = PlannedStep {
                        step_id: 1,
                        description: "arm opt-in persistent WFP boot-time guard".into(),
                        action: WalAction::WfpPersistentSync { sublayer_guid },
                    };
                    if let Ok(mut tx) = self.journal.begin_coexisting_tx(
                        self.engine.runtime_epoch,
                        TxKind::Composite,
                        vec![step],
                        BaselineState::default(),
                        self.engine.lockdown_applied == Some(true),
                        self.engine.protection.is_isolated(),
                    ) {
                        if hybrid.sync_boot_guard(true, &exes).is_ok() {
                            let _ = self.journal.commit_tx(&mut tx);
                        }
                    }
                } else {
                    let _ = hybrid.sync_boot_guard(false, &[]);
                }
            }
        }
        let wfp = self.driver.wfp_status();
        self.step_and_run(
            EngineEvent::WfpUpdated {
                status: Box::new(wfp),
            },
            now,
        );
    }

    fn sync_leak_shield_rules(&mut self, now: u64) -> Result<OperationReceipt, PlatformError> {
        let mut exes = Vec::new();
        for agent in &self.engine.config.guarded_agents {
            let discovered = self.driver.discover_agent_exes(agent).unwrap_or_default();
            self.synced_agent_exes
                .insert(agent.clone(), discovered.clone());
            for p in discovered {
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

    fn sync_monotonic_pause(&mut self, now: u64) {
        let Some(deadline) = self.pause_deadline else {
            return;
        };
        let now_inst = Instant::now();
        if let Some(rem) = deadline.checked_duration_since(now_inst) {
            if !rem.is_zero() {
                let secs = rem.as_secs().max(1);
                self.engine.paused_until = Some(now.saturating_add(secs));
                return;
            }
        }
        self.pause_deadline = None;
        if self.engine.paused_until.is_some() {
            self.engine.paused_until = Some(now);
        }
    }

    fn in_wake_grace(&self, now: u64) -> bool {
        self.wake_grace_until
            .is_some_and(|deadline| Instant::now() < deadline)
            || self.engine.is_in_resume_grace(now)
    }

    fn poll_wake_grace_expiry(&mut self, now: u64) -> bool {
        if let Some(deadline) = self.wake_grace_until {
            if Instant::now() >= deadline {
                self.wake_grace_until = None;
                self.engine.resume_grace_until = None;
                self.engine.push_log(
                    now,
                    LogLevel::Info,
                    "power",
                    "睡眠唤醒宽限窗口已结束，立即发起合规检测",
                );
                return true;
            }
        }
        false
    }

    fn spawn_feishu_flush_if_idle(&self) {
        let Some(guard) = InFlightGuard::try_acquire(&self.feishu_flush_in_flight) else {
            return;
        };
        let feishu = self.feishu.clone();
        let policy = NetworkPolicy::direct();
        let _ = std::thread::Builder::new()
            .name("cg-feishu-flush".to_string())
            .spawn(move || {
                let _guard = guard;
                let _ = feishu.flush_due(&policy);
            });
    }

    /// Unified notification emitter used by both `EffectCommand::Notify` and `launch_blocked` (`H-08`).
    fn emit_notification(&mut self, class: &str, title: &str, body: &str, now: u64) {
        if !self.engine.config.notify.is_on(class) {
            return;
        }
        let safe_body = cg_core::redact::redact(body, self.engine.config.notify.include_egress);
        self.toast_seq = self.toast_seq.saturating_add(1);
        if self.recent_toasts.len() >= 16 {
            self.recent_toasts.pop_front();
        }
        self.recent_toasts.push_back(ToastNotificationEvent {
            seq: self.toast_seq,
            timestamp: now,
            class: class.to_string(),
            title: title.to_string(),
            body: safe_body.clone(),
        });

        if !access_win::is_session_zero() {
            let drv = self.driver.clone();
            let t_title = title.to_string();
            let t_body = safe_body.clone();
            let _ = std::thread::Builder::new()
                .name("cg-toast".to_string())
                .spawn(move || {
                    let _ = drv.send_toast(&t_title, &t_body);
                });
        }

        if self.feishu.enqueue(class, title, &safe_body) {
            self.spawn_feishu_flush_if_idle();
        }
    }

    fn resync_guarded_agents_on_path_change(&mut self, agents: &[AgentRuntimeStatus], now: u64) {
        if self.engine.lifecycle == Lifecycle::Stopping {
            return;
        }
        let mut changed_guarded = Vec::new();
        for status in agents {
            if status.kind != AgentKind::Gui {
                continue;
            }
            let next_exes: Vec<PathBuf> = status.install_paths.iter().map(PathBuf::from).collect();
            let prev_same = self
                .synced_agent_exes
                .get(&status.id)
                .is_some_and(|prev| prev == &next_exes);
            if !prev_same {
                self.synced_agent_exes
                    .insert(status.id.clone(), next_exes.clone());
                if self
                    .engine
                    .config
                    .guarded_agents
                    .iter()
                    .any(|g| g == &status.id)
                {
                    changed_guarded.push((status.id.clone(), next_exes));
                }
            }
        }
        if changed_guarded.is_empty() || !self.driver.capabilities().app_quarantine {
            return;
        }

        let names: Vec<String> = changed_guarded.iter().map(|(id, _)| id.clone()).collect();
        self.engine.push_log(
            now,
            LogLevel::Audit,
            "msix",
            &format!(
                "检测到受保护客户端安装路径变更（{}），正在自动重同步防火墙/护盾规则",
                names.join(", ")
            ),
        );

        // 1. Re-sync active app quarantine rules & WAL if currently isolated.
        if self.engine.protection.is_isolated() && self.engine.config.quarantine_on_fail {
            let mut new_steps = Vec::new();
            let mut step_id = 1u32;
            for (agent_id, exes) in &changed_guarded {
                if exes.is_empty() {
                    continue;
                }
                let (out_name, in_name) = firewall_com::quarantine_rule_names(agent_id);
                for exe in exes {
                    let exe_str = exe.to_string_lossy().to_string();
                    new_steps.push(PlannedStep {
                        step_id,
                        description: format!("resync quarantine outbound {agent_id}"),
                        action: WalAction::AddFirewallRule {
                            rule_name: out_name.clone(),
                            program: Some(exe_str.clone()),
                            direction: FirewallDirection::Outbound,
                        },
                    });
                    step_id += 1;
                    new_steps.push(PlannedStep {
                        step_id,
                        description: format!("resync quarantine inbound {agent_id}"),
                        action: WalAction::AddFirewallRule {
                            rule_name: in_name.clone(),
                            program: Some(exe_str),
                            direction: FirewallDirection::Inbound,
                        },
                    });
                    step_id += 1;
                }
            }
            if !new_steps.is_empty() {
                if let Ok(mut tx) = self.journal.begin_coexisting_tx(
                    self.engine.runtime_epoch,
                    TxKind::Quarantine,
                    new_steps,
                    BaselineState::default(),
                    self.engine.lockdown_applied == Some(true),
                    true,
                ) {
                    for (agent_id, exes) in &changed_guarded {
                        if !exes.is_empty() {
                            let _ = firewall_com::quarantine_agent(
                                self.driver.firewall(),
                                agent_id,
                                exes,
                            );
                        }
                    }
                    let _ = self.journal.commit_tx(&mut tx);
                }
            }
        }

        // 2. Re-sync active lockdown rules if lockdown is currently applied.
        if self.engine.lockdown_applied == Some(true) {
            let mut all_exes = Vec::new();
            let mut ld_steps = Vec::new();
            let mut step_id = 1u32;
            for agent in &self.engine.config.guarded_agents {
                let exes = self
                    .synced_agent_exes
                    .get(agent)
                    .cloned()
                    .unwrap_or_else(|| self.driver.discover_agent_exes(agent).unwrap_or_default());
                if !exes.is_empty() {
                    let rule_name = firewall_com::lockdown_rule_name(agent);
                    for exe in &exes {
                        ld_steps.push(PlannedStep {
                            step_id,
                            description: format!("resync lockdown outbound {agent}"),
                            action: WalAction::AddFirewallRule {
                                rule_name: rule_name.clone(),
                                program: Some(exe.to_string_lossy().to_string()),
                                direction: FirewallDirection::Outbound,
                            },
                        });
                        step_id += 1;
                    }
                    all_exes.push((agent.clone(), exes));
                }
            }
            if !all_exes.is_empty() {
                if let Ok(mut tx) = self.journal.begin_coexisting_tx(
                    self.engine.runtime_epoch,
                    TxKind::Lockdown,
                    ld_steps,
                    BaselineState::default(),
                    false,
                    self.engine.protection.is_isolated(),
                ) {
                    let _ = firewall_com::apply_lockdown(self.driver.firewall(), &all_exes);
                    let _ = self.journal.commit_tx(&mut tx);
                }
            }
        }

        // 3. Re-sync 4-Vector Leak Shield rules if armed and any vector is enabled.
        if self.engine.lifecycle == Lifecycle::Armed
            && (self.engine.config.leak_shield_quic
                || self.engine.config.leak_shield_dns_doh
                || self.engine.config.leak_shield_ipv6)
        {
            let _ = self.sync_leak_shield_rules(now);
        }
    }

    fn build_vault_statuses(&self, snap: &GuardSnapshot, now: u64) -> Vec<VaultRuntimeStatus> {
        let vaults_root = self.effective_vaults_root().ok();
        let (obs_ip, obs_country, obs_asn) = current_primary_egress(snap);
        self.engine
            .config
            .vaults
            .iter()
            .map(|vault| {
                let sessions: Vec<(u32, String)> = self
                    .vault_sessions
                    .get(&vault.id)
                    .map(|entries| {
                        entries
                            .iter()
                            .filter(|(pid, _)| *pid > 0 && is_pid_alive(*pid))
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default();
                let running_pids: Vec<u32> = sessions.iter().map(|(pid, _)| *pid).collect();
                let mut running_apps: Vec<String> = Vec::new();
                for (_, app) in &sessions {
                    if !running_apps.contains(app) {
                        running_apps.push(app.clone());
                    }
                }
                let cooldown_remaining =
                    self.egress_ledger.vault_cooldown_remaining(&vault.id, now);
                let egress_match_res = check_vault_egress_contract(
                    vault,
                    obs_ip.as_deref(),
                    obs_country.as_deref(),
                    obs_asn,
                );
                let egress_matches_contract = egress_match_res.is_ok();
                let (last_active_at, last_country) = self
                    .egress_ledger
                    .vault_last_activity(&vault.id)
                    .map(|(ts, c)| (Some(ts), (!c.is_empty()).then_some(c)))
                    .unwrap_or((None, None));
                let state = if !vault.enabled {
                    VaultRuntimeState::Disabled
                } else if !running_pids.is_empty() {
                    VaultRuntimeState::ActiveRunning
                } else if cooldown_remaining > 0 {
                    VaultRuntimeState::CoolingDown
                } else if !egress_matches_contract {
                    VaultRuntimeState::EgressMismatch
                } else {
                    VaultRuntimeState::Ready
                };
                let vault_dir = vaults_root
                    .as_ref()
                    .map(|r| r.join(&vault.id).to_string_lossy().to_string())
                    .unwrap_or_default();
                let summary = match state {
                    VaultRuntimeState::Disabled => "保险箱已停用".into(),
                    VaultRuntimeState::ActiveRunning => format!(
                        "运行中（{} 个进程：{}）",
                        running_pids.len(),
                        running_apps.join(", ")
                    ),
                    VaultRuntimeState::CoolingDown => {
                        format!("换 IP 冷却保护中（剩余 {cooldown_remaining}s）")
                    }
                    VaultRuntimeState::EgressMismatch => egress_match_res
                        .err()
                        .unwrap_or_else(|| "当前出口与保险箱绑定契约不匹配".into()),
                    VaultRuntimeState::Ready => "出口契约匹配，可安全一键启动".into(),
                };
                VaultRuntimeStatus {
                    id: vault.id.clone(),
                    name: vault.name.clone(),
                    accent_hex: vault.accent_hex.clone(),
                    state,
                    running_pids,
                    running_apps,
                    egress_matches_contract,
                    cooldown_remaining_secs: cooldown_remaining,
                    last_active_at,
                    last_ip_masked: None,
                    last_country,
                    vault_dir,
                    summary,
                }
            })
            .collect()
    }

    fn build_snapshot(&self, now: u64) -> GuardSnapshot {
        let mut snap = self.engine.to_snapshot(now, self.cached_agents.clone());
        if let Some(deadline) = self.pause_deadline {
            snap.paused_until = deadline
                .checked_duration_since(Instant::now())
                .filter(|rem| !rem.is_zero())
                .map(|rem| now.saturating_add(rem.as_secs().max(1)));
        }
        snap.recent_toasts = self.recent_toasts.iter().cloned().collect();
        snap.feishu = self.feishu.status();
        snap.leak_shield = self.leak_shield.clone();
        snap.mihomo = self.mihomo.clone();

        // v5 control-plane telemetry fields
        if snap.wfp.active_backend.is_empty() {
            snap.wfp = self.driver.wfp_status();
        }
        snap.last_cleanroom_report = self.last_cleanroom_report.clone();
        snap.cleanroom_backup_count = self.cleanroom_backup_count;

        let mut hooks = self.hooks.clone();
        if let Some(ref metrics) = self.hook_metrics_ref {
            let (checks, blocks, latency_us) = metrics.snapshot_counts();
            hooks.total_gate_checks = checks;
            hooks.total_gate_blocks = blocks;
            hooks.last_gate_latency_us = latency_us;
        }
        snap.hooks = hooks;

        let mut wsl = self.wsl_bridge.clone();
        wsl.enabled = self.engine.config.wsl_bridge_enabled;
        if let Some(ref metrics) = self.hook_metrics_ref {
            wsl.proxy_desync_detected = metrics.wsl_proxy_desync.load(Ordering::Relaxed);
        }
        snap.wsl_bridge = wsl;

        snap.burst_guard = if let Some(ref bg) = self.burst_guard_ref {
            let tracker = bg.lock().unwrap_or_else(|e| e.into_inner());
            tracker.overall_status(
                now_unix_millis(),
                &BurstGuardConfig::from_config(&self.engine.config),
            )
        } else {
            BurstGuardStatus {
                mode: self.engine.config.burst_guard_mode,
                summary: "节律正常（1m:0 / 15m:0）".into(),
                ..Default::default()
            }
        };

        snap.hotkeys = HotkeyStatus {
            enabled: self.engine.config.global_hotkeys_enabled,
            panic_lockdown_chord: self.engine.config.hotkey_panic_lockdown.clone(),
            quick_hud_chord: self.engine.config.hotkey_quick_hud.clone(),
            panic_registered_ok: self.engine.config.global_hotkeys_enabled,
            hud_registered_ok: self.engine.config.global_hotkeys_enabled,
            conflict_note: String::new(),
        };

        snap.vaults = self.build_vault_statuses(&snap, now);
        snap
    }

    fn flush_pending_daemon_logs(&self) {
        let watermark = self.last_flushed_log_id.load(Ordering::Acquire);
        let batch: Vec<crate::protocol::LogEntry> = self
            .engine
            .logs
            .iter()
            .filter(|entry| entry.id > watermark)
            .cloned()
            .collect();
        if let Some(max_id) = batch.last().map(|e| e.id) {
            diagnostics::append_redacted_daemon_log_entries(&self.data_dir, &batch);
            self.last_flushed_log_id.store(max_id, Ordering::Release);
        }
    }

    fn publish_snapshot(&self, snapshot_store: &SnapshotStoreRef<'_>, now: u64) -> GuardSnapshot {
        self.flush_pending_daemon_logs();
        let snap = self.build_snapshot(now);
        snapshot_store.replace(snap.clone());
        snap
    }

    fn on_system_shutting_down(&mut self, now: u64) {
        let recent_false_uncovered_trip = !self.engine.lockdown_manual
            && self
                .engine
                .last_auto_uncovered_action_at
                .is_some_and(|ts| now.saturating_sub(ts) <= 20)
            && (self.engine.lockdown_applied == Some(true)
                || self.engine.is_tripped()
                || self.journal.path().exists());
        if recent_false_uncovered_trip {
            let heal = journal::heal_offline(&self.journal, &*self.recovery_executor);
            if heal.ok && heal.verified {
                self.active_journal = None;
                self.step_and_run(EngineEvent::AbortFalseShutdownTrip, now);
                return;
            }
        }
        if !self.engine.system_shutting_down {
            self.step_and_run(EngineEvent::SystemShuttingDown, now);
        }
    }

    fn try_recover_wal_pending(&mut self, now: u64, force: bool) -> bool {
        if !self.engine.wal_pending {
            return false;
        }
        let due = force
            || self
                .last_wal_heal_attempt
                .is_none_or(|t| t.elapsed() >= Duration::from_secs(15));
        if !due {
            return false;
        }
        self.last_wal_heal_attempt = Some(Instant::now());
        let heal = journal::heal_offline(&self.journal, &*self.recovery_executor);
        if heal.ok && heal.verified {
            self.last_wal_heal_error = None;
            self.step_and_run(EngineEvent::WalHealed, now);
            if self.engine.lifecycle == Lifecycle::Armed
                && self.driver.capabilities().app_quarantine
                && (self.engine.config.leak_shield_quic
                    || self.engine.config.leak_shield_dns_doh
                    || self.engine.config.leak_shield_ipv6)
            {
                if let Err(err) = self.sync_leak_shield_rules(now) {
                    self.engine.push_log(
                        now,
                        LogLevel::Warn,
                        "shield",
                        &format!("恢复核验后同步防泄露护盾规则失败：{err}"),
                    );
                }
            }
            let self_check = build_defense_self_check(
                &self.engine.config,
                &*self.driver,
                &self.journal,
                self.driver.capabilities().app_quarantine,
                &self.engine.antigravity_proxy,
                now,
            );
            self.step_and_run(EngineEvent::SelfCheckUpdated { self_check }, now);
            true
        } else {
            self.last_wal_heal_error = Some(heal.summary.clone());
            self.engine.last_error = heal.summary;
            let mut self_check = build_defense_self_check(
                &self.engine.config,
                &*self.driver,
                &self.journal,
                false,
                &self.engine.antigravity_proxy,
                now,
            );
            enrich_self_check_wal_error(
                &mut self_check,
                &self.journal,
                self.last_wal_heal_error.as_deref(),
            );
            self.step_and_run(EngineEvent::SelfCheckUpdated { self_check }, now);
            false
        }
    }

    fn step_and_run(&mut self, event: EngineEvent, now: u64) {
        self.sync_monotonic_pause(now);
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
                    let err_clone = res.as_ref().err().cloned();
                    self.step_and_run(
                        EngineEvent::RearmPersisted {
                            ok: res.is_ok(),
                            error: res.err(),
                        },
                        now,
                    );
                    if let Some(err) = err_clone {
                        self.mutation_error = Some(err);
                    }
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
                        self.mutation_error = Some(err.clone());
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
                    let keep_lockdown = self.engine.lockdown_applied == Some(true);
                    let keep_isolated = self.engine.protection.is_isolated();
                    if !keep_lockdown && !keep_isolated {
                        let _ = self.journal.clear();
                    } else {
                        let _ = self.journal.retain_coexisting_committed(
                            self.engine.runtime_epoch,
                            keep_lockdown,
                            keep_isolated,
                        );
                    }
                }
                EffectCommand::PersistTimeline => {
                    let _ = self.engine.timeline.save_to(&self.timeline_path);
                }
                EffectCommand::Notify { class, title, body } => {
                    self.emit_notification(&class, &title, &body, now);
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
                self.synced_agent_exes.insert(agent.clone(), exes.clone());
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

            match self.journal.begin_coexisting_tx(
                self.engine.runtime_epoch,
                TxKind::Lockdown,
                steps,
                BaselineState::default(),
                false,
                self.engine.protection.is_isolated(),
            ) {
                Ok(tx) => self.active_journal = Some(tx),
                Err(err) => {
                    let msg = format!("WAL begin_tx failed: {err}");
                    receipt.status = OperationStatus::Failed;
                    receipt.error = Some(msg.clone());
                    if manual {
                        self.mutation_error = Some(msg);
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
            receipt.error = err_msg.clone();

            if manual {
                if !confirmed || !status.query_ok {
                    self.mutation_error =
                        Some(err_msg.unwrap_or_else(|| "手动封锁核验未通过".to_string()));
                }
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
            if manual {
                if !confirmed || !status.query_ok {
                    self.mutation_error = Some(
                        receipt
                            .error
                            .clone()
                            .unwrap_or_else(|| "解除手动封锁核验未通过".to_string()),
                    );
                }
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
            if confirmed {
                self.active_journal = None;
                let keep_lockdown = self.engine.lockdown_applied == Some(true);
                let keep_isolated = self.engine.protection.is_isolated();
                if !keep_lockdown && !keep_isolated {
                    let _ = self.journal.clear();
                } else {
                    let _ = self.journal.retain_coexisting_committed(
                        self.engine.runtime_epoch,
                        keep_lockdown,
                        keep_isolated,
                    );
                }
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
                self.synced_agent_exes.insert(agent.clone(), exes.clone());
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

        // Write & sync_all WAL BEFORE mutating processes/firewall, preserving active Lockdown/Baseline (`H-04`).
        match self.journal.begin_coexisting_tx(
            runtime_epoch,
            TxKind::Composite,
            planned_steps,
            BaselineState::default(),
            self.engine.lockdown_applied == Some(true),
            false,
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
        if !receipt.status.is_verified_or_na() || !app_isolation_intact {
            self.mutation_error = Some(
                receipt
                    .error
                    .clone()
                    .unwrap_or_else(|| "流程 A 恢复业务网络未核验成功".to_string()),
            );
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
        // H-02: Release ALL known GUI agent IDs (plus any configured/quarantined IDs) so agents
        // unchecked while tripped never remain permanently quarantined in Windows Firewall.
        let mut agents: Vec<String> = cg_protocol::KNOWN_GUI_AGENT_IDS
            .iter()
            .map(|id| (*id).to_string())
            .collect();
        for g in &self.engine.config.guarded_agents {
            if !agents.contains(g) {
                agents.push(g.clone());
            }
        }
        if let Some(ref trip) = self.engine.tripped {
            for q in &trip.quarantined_agents {
                if !agents.contains(q) {
                    agents.push(q.clone());
                }
            }
        }

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
            if let Some(hybrid) = cg_platform::active_hybrid_firewall() {
                let _ = hybrid.clear_persistent_boot_guard();
            }
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
            if !is_stopping {
                self.mutation_error = Some(heal.summary.clone());
            }
        } else if !is_stopping {
            if let Err(err) = disarm::mark_disarmed(&self.data_dir, reason) {
                receipt.status = OperationStatus::Failed;
                receipt.error = Some(err.clone());
                self.mutation_error = Some(err);
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
        for (_, _, _, tx) in self.fast_hook_waiters.drain(..) {
            let _ = tx.send(PipeResponse::FastGateVerdict {
                allowed: false,
                decision: HookDecision::Block,
                safety_score: snapshot.risk_assessment.score,
                reason: "配置或守卫生命周期已变更，门禁复核已中止".into(),
                latency_path: "sync_probe_fallback".into(),
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
                self.emit_notification("launch_blocked", "ClaudeGuard 已阻止启动", &reason, now);
            }
        }

        if !self.fast_hook_waiters.is_empty() {
            let waiters = std::mem::take(&mut self.fast_hook_waiters);
            let fallback_tracker = Mutex::new(BurstGuardTracker::new());
            let now_ms = now_unix_millis();
            for (agent_id, vault_id, hook_event, tx) in waiters {
                let tracker_ref: &Mutex<BurstGuardTracker> =
                    self.burst_guard_ref.as_deref().unwrap_or(&fallback_tracker);
                let resp = match evaluate_fast_hook_gate_at(
                    snapshot,
                    tracker_ref,
                    &agent_id,
                    vault_id.as_deref(),
                    hook_event.as_deref(),
                    now,
                    now_ms,
                ) {
                    FastGateOutcome::Immediate(PipeResponse::FastGateVerdict {
                        allowed,
                        decision,
                        safety_score,
                        reason,
                        ..
                    }) => PipeResponse::FastGateVerdict {
                        allowed,
                        decision,
                        safety_score,
                        reason,
                        latency_path: "sync_probe_fallback".into(),
                    },
                    FastGateOutcome::Immediate(other) => other,
                    FastGateOutcome::NeedsSyncProbe => PipeResponse::FastGateVerdict {
                        allowed: false,
                        decision: HookDecision::Block,
                        safety_score: snapshot.risk_assessment.score,
                        reason:
                            "🛡️ [ClaudeGuard 复核未通过] 出口探测仍未确认合规，已阻止提示词发送"
                                .into(),
                        latency_path: "sync_probe_fallback".into(),
                    },
                };
                let _ = tx.send(resp);
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
        self.mutation_error = None;
        if self.poll_wake_grace_expiry(now) && self.engine.lifecycle == Lifecycle::Armed {
            self.step_and_run(
                EngineEvent::StartRound {
                    purpose: CheckPurpose::Monitor,
                },
                now,
            );
        }

        match req {
            PipeRequest::GetSnapshot => {
                let snap = snapshot_store.read();
                let _ = reply.send(PipeResponse::Snapshot {
                    snapshot: Box::new(snap),
                });
            }
            PipeRequest::RecheckNow { target_id } => {
                let _ = self.try_recover_wal_pending(now, true);
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

                    let Some(in_flight) =
                        InFlightGuard::try_acquire(&self.single_recheck_in_flight)
                    else {
                        let _ = reply.send(PipeResponse::Error {
                            code: ErrorCode::Busy,
                            message: "单目标复检正在执行，请稍后再试".into(),
                            receipt: None,
                        });
                        return;
                    };

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

                    let reply_cell = Arc::new(Mutex::new(Some(reply)));
                    let worker_reply = reply_cell.clone();
                    if std::thread::Builder::new()
                        .name("cg-single-recheck".to_string())
                        .spawn(move || {
                            let _guard = in_flight;
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
                            if let Some(tx) = worker_reply.lock().ok().and_then(|mut g| g.take()) {
                                let _ = event_tx.send(CoordinatorEvent::SingleTargetProbed {
                                    cfg_rev,
                                    runtime_epoch,
                                    target_id: tid,
                                    access,
                                    probe,
                                    now_secs: now_unix_secs(),
                                    reply: tx,
                                });
                            }
                        })
                        .is_err()
                    {
                        if let Some(tx) = reply_cell.lock().ok().and_then(|mut g| g.take()) {
                            let _ = tx.send(PipeResponse::Error {
                                code: ErrorCode::Busy,
                                message: "创建单目标复检工作线程失败，请稍后重试".into(),
                                receipt: None,
                            });
                        }
                    }
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
                let prev_wfp = (
                    self.engine.config.firewall_backend,
                    self.engine.config.wfp_boot_guard,
                );
                let prev_shield = (
                    self.engine.config.leak_shield_quic,
                    self.engine.config.leak_shield_dns_doh,
                    self.engine.config.leak_shield_ipv6,
                    self.engine.config.guarded_agents.clone(),
                );
                self.step_and_run(EngineEvent::SaveConfig { next: config }, now);
                let next_wfp = (
                    self.engine.config.firewall_backend,
                    self.engine.config.wfp_boot_guard,
                );
                if self.last_rejected.is_none() && prev_wfp != next_wfp {
                    self.sync_wfp_config(now);
                }
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
                if self.last_rejected.is_none() {
                    self.pause_deadline = match duration_secs {
                        Some(secs) if secs > 0 => Some(Instant::now() + Duration::from_secs(secs)),
                        _ => None,
                    };
                }
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
                if self.last_rejected.is_none() {
                    self.pause_deadline = None;
                }
                if was_unconfigured && self.last_rejected.is_none() {
                    let heal = journal::heal_offline(&self.journal, &*self.recovery_executor);
                    if !heal.ok || !heal.verified {
                        self.mutation_error = Some(heal.summary);
                    } else if let Err(err) = disarm::mark_disarmed(&self.data_dir, &reason_text) {
                        self.mutation_error = Some(err);
                    }
                }
                let snap = self.publish_snapshot(snapshot_store, now);
                self.flush_superseded_waiters(&snap);
                self.send_mutation_reply(reply, snap);
            }
            PipeRequest::Rearm => {
                self.step_and_run(EngineEvent::Rearm, now);
                if self.last_rejected.is_none()
                    && self.mutation_error.is_none()
                    && self.engine.lifecycle == Lifecycle::Armed
                    && self.driver.capabilities().app_quarantine
                {
                    self.sync_wfp_config(now);
                    match self.sync_leak_shield_rules(now) {
                        Ok(receipt) => {
                            self.engine.last_receipt = Some(receipt);
                        }
                        Err(err) => {
                            let detail = format!("重新布防后自动同步防泄露护盾规则失败：{err}");
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
            PipeRequest::CheckLaunchGate { agent_id } => {
                self.sync_monotonic_pause(now);
                let decision = GuardEngine::evaluate_launch_gate_for_agent(
                    &self.engine,
                    agent_id.as_deref(),
                    now,
                );
                let snap = self.publish_snapshot(snapshot_store, now);
                if decision.allowed || !decision.requires_recheck {
                    if !decision.allowed && self.engine.lifecycle == Lifecycle::Armed {
                        self.emit_notification(
                            "launch_blocked",
                            "ClaudeGuard 已阻止启动",
                            &decision.reason,
                            now,
                        );
                    }
                    let snap = self.publish_snapshot(snapshot_store, now);
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
                if matches!(
                    self.engine.lifecycle,
                    Lifecycle::Unconfigured | Lifecycle::Disarmed | Lifecycle::Stopping
                ) {
                    let _ = reply.send(PipeResponse::Error {
                        code: ErrorCode::IllegalState,
                        message: format!(
                            "当前生命周期（{}）不允许执行孤儿进程清理",
                            self.engine.lifecycle.label()
                        ),
                        receipt: None,
                    });
                    return;
                }
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
                let Some(in_flight) = InFlightGuard::try_acquire(&self.onboarding_probe_in_flight)
                else {
                    let _ = reply.send(PipeResponse::Error {
                        code: ErrorCode::Busy,
                        message: "向导探测正在进行中，请稍候".into(),
                        receipt: None,
                    });
                    return;
                };
                let driver = self.driver.clone();
                let probe_runner = self.probe_runner.clone();
                let cfg = self.engine.config.clone();
                let cfg_rev = self.engine.cfg_rev;
                let reply_cell = Arc::new(Mutex::new(Some(reply)));
                let worker_reply = reply_cell.clone();
                if std::thread::Builder::new()
                    .name("cg-onboarding-probe".to_string())
                    .spawn(move || {
                        let _guard = in_flight;
                        let probe = probe_onboarding_with(
                            &*driver,
                            &*probe_runner,
                            &cfg,
                            cfg_rev,
                            now_unix_secs(),
                        );
                        if let Ok(mut g) = worker_reply.lock() {
                            if let Some(tx) = g.take() {
                                let _ = tx.send(PipeResponse::OnboardingProbe { probe });
                            }
                        }
                    })
                    .is_err()
                {
                    if let Ok(mut g) = reply_cell.lock() {
                        if let Some(tx) = g.take() {
                            let _ = tx.send(PipeResponse::Error {
                                code: ErrorCode::Busy,
                                message: "创建向导探测工作线程失败，请稍后重试".into(),
                                receipt: None,
                            });
                        }
                    }
                }
            }
            PipeRequest::CompleteOnboarding { config } => {
                self.step_and_run(EngineEvent::CompleteOnboarding { config }, now);
                let rejected = self.last_rejected.is_some();
                let persisted_ok = self.mutation_error.is_none();
                if !rejected && persisted_ok && self.engine.lifecycle == Lifecycle::Armed {
                    self.sync_wfp_config(now);
                    if self.driver.capabilities().app_quarantine
                        && (self.engine.config.leak_shield_quic
                            || self.engine.config.leak_shield_dns_doh
                            || self.engine.config.leak_shield_ipv6)
                    {
                        if let Err(err) = self.sync_leak_shield_rules(now) {
                            self.engine.push_log(
                                now,
                                LogLevel::Warn,
                                "shield",
                                &format!("首次布防同步防泄露护盾规则失败：{err}"),
                            );
                        }
                    }
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

                let Some(in_flight) = InFlightGuard::try_acquire(&self.update_check_in_flight)
                else {
                    let _ = reply.send(PipeResponse::Error {
                        code: ErrorCode::Busy,
                        message: "更新检查正在进行中，请稍候".into(),
                        receipt: None,
                    });
                    return;
                };

                let driver = self.driver.clone();
                let cfg = self.engine.config.clone();
                let cfg_rev = self.engine.cfg_rev;
                let cg_version = self.engine.version.clone();
                let ag_proxy = self.engine.antigravity_proxy.clone();
                let prev_updates = self.engine.updates.clone();
                let event_tx = self.event_tx.clone();
                let reply_cell = Arc::new(Mutex::new(Some(reply)));
                let worker_reply = reply_cell.clone();

                if std::thread::Builder::new()
                    .name("cg-update-check".to_string())
                    .spawn(move || {
                        let _guard = in_flight;
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
                        let tx_opt = worker_reply.lock().ok().and_then(|mut g| g.take());
                        let _ = event_tx.send(CoordinatorEvent::UpdatesChecked {
                            summary: Box::new(summary),
                            component: normalized_component,
                            now_secs: now_unix_secs(),
                            reply: tx_opt,
                        });
                    })
                    .is_err()
                {
                    if let Ok(mut g) = reply_cell.lock() {
                        if let Some(tx) = g.take() {
                            let _ = tx.send(PipeResponse::Error {
                                code: ErrorCode::Busy,
                                message: "创建更新检查工作线程失败，请稍后重试".into(),
                                receipt: None,
                            });
                        }
                    }
                }
            }
            PipeRequest::ForceKillAgent {
                agent_id,
                include_cli,
            } => {
                if matches!(
                    self.engine.lifecycle,
                    Lifecycle::Unconfigured | Lifecycle::Disarmed | Lifecycle::Stopping
                ) {
                    let _ = reply.send(PipeResponse::Error {
                        code: ErrorCode::IllegalState,
                        message: format!(
                            "当前生命周期（{}）不允许强制终止应用进程",
                            self.engine.lifecycle.label()
                        ),
                        receipt: None,
                    });
                    return;
                }
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
                            "cursor" => (vec!["cursor".to_string()], Vec::new()),
                            "windsurf" => (vec!["windsurf".to_string()], Vec::new()),
                            "zed" => (vec!["zed".to_string()], Vec::new()),
                            "trae" => (vec!["trae".to_string()], Vec::new()),
                            "claude-code" => (Vec::new(), vec!["claude-code"]),
                            "codex" => (Vec::new(), vec!["codex"]),
                            "gemini" => (Vec::new(), vec!["gemini"]),
                            "aider" => (Vec::new(), vec!["aider"]),
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
                let Some(in_flight) = InFlightGuard::try_acquire(&self.feishu_test_in_flight)
                else {
                    let _ = reply.send(PipeResponse::Error {
                        code: ErrorCode::Busy,
                        message: "飞书连通性测试正在进行中，请稍候".into(),
                        receipt: None,
                    });
                    return;
                };
                let feishu = self.feishu.clone();
                let event_tx = self.event_tx.clone();
                let policy = NetworkPolicy::direct();
                let reply_cell = Arc::new(Mutex::new(Some(reply)));
                let worker_reply = reply_cell.clone();
                if std::thread::Builder::new()
                    .name("cg-feishu-test".to_string())
                    .spawn(move || {
                        let _guard = in_flight;
                        let result =
                            feishu.send_test(&policy, webhook.as_deref(), secret.as_deref());
                        if let Some(tx) = worker_reply.lock().ok().and_then(|mut g| g.take()) {
                            let _ = event_tx.send(CoordinatorEvent::FeishuTestFinished {
                                result,
                                now_secs: now_unix_secs(),
                                reply: tx,
                            });
                        }
                    })
                    .is_err()
                {
                    if let Some(tx) = reply_cell.lock().ok().and_then(|mut g| g.take()) {
                        let _ = tx.send(PipeResponse::Error {
                            code: ErrorCode::Busy,
                            message: "创建飞书测试工作线程失败，请稍后重试".into(),
                            receipt: None,
                        });
                    }
                }
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
                let Some(in_flight) = InFlightGuard::try_acquire(&self.mihomo_switch_in_flight)
                else {
                    let _ = reply.send(PipeResponse::Error {
                        code: ErrorCode::Busy,
                        message: "代理节点切换正在执行，请稍候".into(),
                        receipt: None,
                    });
                    return;
                };
                let cfg_rev = self.engine.cfg_rev;
                let runtime_epoch = self.engine.runtime_epoch;
                let event_tx = self.event_tx.clone();
                let reply_cell = Arc::new(Mutex::new(Some(reply)));
                let worker_reply = reply_cell.clone();
                if std::thread::Builder::new()
                    .name("cg-mihomo-switch".to_string())
                    .spawn(move || {
                        let _guard = in_flight;
                        let result =
                            mihomo_win::switch_mihomo_node(&group, &node, close_connections);
                        let mihomo = mihomo_win::inspect_mihomo();
                        if let Some(tx) = worker_reply.lock().ok().and_then(|mut g| g.take()) {
                            let _ = event_tx.send(CoordinatorEvent::MihomoSwitchFinished {
                                cfg_rev,
                                runtime_epoch,
                                result,
                                mihomo,
                                now_secs: now_unix_secs(),
                                reply: tx,
                            });
                        }
                    })
                    .is_err()
                {
                    if let Some(tx) = reply_cell.lock().ok().and_then(|mut g| g.take()) {
                        let _ = tx.send(PipeResponse::Error {
                            code: ErrorCode::Busy,
                            message: "创建节点切换工作线程失败，请稍后重试".into(),
                            receipt: None,
                        });
                    }
                }
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
                let Some(in_flight) = InFlightGuard::try_acquire(&self.ag_repair_in_flight) else {
                    let _ = reply.send(PipeResponse::Error {
                        code: ErrorCode::Busy,
                        message: "反重力透明代理修复正在执行，请稍候".into(),
                        receipt: None,
                    });
                    return;
                };
                let (_access, route) = resolve_access_and_route(
                    &*self.driver,
                    &self.engine.config,
                    self.engine.cfg_rev,
                    &self.engine.config.targets,
                    self.engine.config.enforce_access_path,
                    now,
                );
                let proxy_port = self.engine.config.proxy_port;
                let repair_cache_dir = self.data_dir.join("antigravity-proxy");

                let event_tx = self.event_tx.clone();
                let reply_cell = Arc::new(Mutex::new(Some(reply)));
                let worker_reply = reply_cell.clone();
                if std::thread::Builder::new()
                    .name("cg-ag-repair".to_string())
                    .spawn(move || {
                        let _guard = in_flight;
                        // The manual button always re-downloads the latest release, then seeds
                        // the verified-DLL cache the background auto re-injection relies on.
                        let res = antigravity_proxy_win::repair_antigravity_proxy(
                            &route, proxy_port, None,
                        )
                        .map(|r| {
                            if let Ok(dir) = antigravity_proxy_win::resolve_antigravity_dir(None) {
                                let _ = antigravity_proxy_win::cache_proxy_dll_from_dir(
                                    &dir,
                                    &repair_cache_dir,
                                    &r.release_tag,
                                );
                            }
                            r.summary
                        });
                        if let Some(tx) = worker_reply.lock().ok().and_then(|mut g| g.take()) {
                            let _ = event_tx.send(CoordinatorEvent::AntigravityRepairFinished {
                                result: res,
                                now_secs: now_unix_secs(),
                                reply: tx,
                            });
                        }
                    })
                    .is_err()
                {
                    if let Some(tx) = reply_cell.lock().ok().and_then(|mut g| g.take()) {
                        let _ = tx.send(PipeResponse::Error {
                            code: ErrorCode::Busy,
                            message: "创建热修复工作线程失败，请稍后重试".into(),
                            receipt: None,
                        });
                    }
                }
            }
            PipeRequest::ApplyEnvAlignment {
                align_tz,
                align_location,
            } => {
                let place = envcheck::pick_egress(&self.engine.target_statuses).and_then(
                    |(country, colo)| {
                        cg_core::geo::resolve(colo.as_deref(), country.as_deref()).or_else(|| {
                            match country.as_deref() {
                                Some("US") => cg_core::geo::by_colo("LAX"),
                                _ => None,
                            }
                        })
                    },
                );
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
                self.flush_pending_daemon_logs();
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
            PipeRequest::NotifySystemShutdown => {
                self.on_system_shutting_down(now);
                let snap = self.publish_snapshot(snapshot_store, now);
                let _ = reply.send(PipeResponse::Ack {
                    receipt: None,
                    snapshot: Some(Box::new(snap)),
                });
            }
            // ---- v5 Control-Plane Requests (M1–M7) ----
            PipeRequest::FastHookGate {
                agent_id,
                vault_id,
                hook_event,
            } => {
                self.sync_monotonic_pause(now);
                let cur_snap = self.build_snapshot(now);
                let fallback_tracker = Mutex::new(BurstGuardTracker::new());
                let tracker_ref: &Mutex<BurstGuardTracker> =
                    self.burst_guard_ref.as_deref().unwrap_or(&fallback_tracker);
                if let FastGateOutcome::Immediate(resp) = evaluate_fast_hook_gate_at(
                    &cur_snap,
                    tracker_ref,
                    &agent_id,
                    vault_id.as_deref(),
                    hook_event.as_deref(),
                    now,
                    now_unix_millis(),
                ) {
                    let _ = reply.send(resp);
                    return;
                }

                // Stale or unverified: run/join a real Launch-purpose probe round.
                self.step_and_run(
                    EngineEvent::StartRound {
                        purpose: CheckPurpose::Launch,
                    },
                    now,
                );
                if let Some((_code, reason)) = self.last_rejected.take() {
                    let _ = reply.send(PipeResponse::FastGateVerdict {
                        allowed: false,
                        decision: HookDecision::Block,
                        safety_score: cur_snap.risk_assessment.score,
                        reason,
                        latency_path: "sync_probe_fallback".into(),
                    });
                    return;
                }
                let snap = self.publish_snapshot(snapshot_store, now);
                if self.engine.checking {
                    self.fast_hook_waiters
                        .push((agent_id, vault_id, hook_event, reply));
                } else {
                    let decision = GuardEngine::evaluate_launch_gate_for_agent(
                        &self.engine,
                        Some(agent_id.as_str()),
                        now,
                    );
                    let _ = reply.send(PipeResponse::FastGateVerdict {
                        allowed: decision.allowed,
                        decision: if decision.allowed {
                            HookDecision::Allow
                        } else {
                            HookDecision::Block
                        },
                        safety_score: snap.risk_assessment.score,
                        reason: decision.reason,
                        latency_path: "sync_probe_fallback".into(),
                    });
                }
            }
            PipeRequest::UpsertVault { mut vault } => {
                vault.normalize();
                if !is_valid_vault_id(&vault.id) {
                    let _ = reply.send(PipeResponse::Error {
                        code: ErrorCode::ValidationFailed,
                        message: format!(
                            "非法账号保险箱 ID `{}`：仅允许 2-32 位小写字母、数字、`-` 或 `_` 且不能为 Windows 保留名",
                            vault.id
                        ),
                        receipt: None,
                    });
                    return;
                }
                let vaults_root = match self.effective_vaults_root() {
                    Ok(p) => p,
                    Err(err) => {
                        let _ = reply.send(PipeResponse::Error {
                            code: ErrorCode::IoFailed,
                            message: err,
                            receipt: None,
                        });
                        return;
                    }
                };
                let paths = match vault_win::ensure_vault_layout_in(&vaults_root, &vault) {
                    Ok(p) => p,
                    Err(err) => {
                        let _ = reply.send(PipeResponse::Error {
                            code: ErrorCode::IoFailed,
                            message: err,
                            receipt: None,
                        });
                        return;
                    }
                };

                let mut next_cfg = self.engine.config.clone();
                if let Some(existing) = next_cfg
                    .vaults
                    .iter_mut()
                    .find(|v| v.id.eq_ignore_ascii_case(&vault.id))
                {
                    *existing = vault.clone();
                } else {
                    next_cfg.vaults.push(vault.clone());
                }
                match self.config_store.save_verified(&next_cfg) {
                    Ok(saved) => {
                        self.engine.config = saved;
                        if self.hooks.claude_code_hook_installed {
                            let cli_exe = hook_installer::resolve_cli_exe_path();
                            let _ = hook_installer::sync_claude_code_settings(
                                &paths.claude_code_home.join("settings.json"),
                                &cli_exe,
                                Some(&vault.id),
                                true,
                            );
                        }
                        let mut receipt = OperationReceipt::new(
                            format!("vault-upsert-{}-{now}", vault.id),
                            OperationStatus::Verified,
                        );
                        receipt.verified_scope = paths.vault_root.to_string_lossy().to_string();
                        receipt.push_item(
                            format!("vault:{}", vault.id),
                            OperationStatus::Verified,
                            format!("已初始化主权隔离保险箱「{}」", vault.name),
                        );
                        self.engine.push_log(
                            now,
                            LogLevel::Audit,
                            "vault",
                            &format!("创建/更新主权账号保险箱「{}」（{}）", vault.name, vault.id),
                        );
                        self.engine.last_receipt = Some(receipt);
                    }
                    Err(err) => {
                        self.mutation_error = Some(err);
                    }
                }
                let snap = self.publish_snapshot(snapshot_store, now);
                self.send_mutation_reply(reply, snap);
            }
            PipeRequest::DeleteVault {
                vault_id,
                purge_disk_data,
            } => {
                let norm_id = vault_id.trim().to_ascii_lowercase();
                if !is_valid_vault_id(&norm_id) {
                    let _ = reply.send(PipeResponse::Error {
                        code: ErrorCode::ValidationFailed,
                        message: format!("非法的保险箱 ID：`{vault_id}`"),
                        receipt: None,
                    });
                    return;
                }
                if !self
                    .engine
                    .config
                    .vaults
                    .iter()
                    .any(|v| v.id.eq_ignore_ascii_case(&norm_id))
                {
                    let _ = reply.send(PipeResponse::Error {
                        code: ErrorCode::NotFound,
                        message: format!("未找到账号保险箱 `{norm_id}`"),
                        receipt: None,
                    });
                    return;
                }
                let vaults_root = match self.effective_vaults_root() {
                    Ok(p) => p,
                    Err(err) => {
                        let _ = reply.send(PipeResponse::Error {
                            code: ErrorCode::IoFailed,
                            message: err,
                            receipt: None,
                        });
                        return;
                    }
                };
                let _ = self.stop_vault_processes(&norm_id, &vaults_root);
                let archived = match vault_win::remove_vault_files_in(
                    &vaults_root,
                    &norm_id,
                    purge_disk_data,
                    now,
                ) {
                    Ok(p) => p,
                    Err(err) => {
                        let _ = reply.send(PipeResponse::Error {
                            code: ErrorCode::IoFailed,
                            message: err,
                            receipt: None,
                        });
                        return;
                    }
                };

                let mut next_cfg = self.engine.config.clone();
                next_cfg
                    .vaults
                    .retain(|v| !v.id.eq_ignore_ascii_case(&norm_id));
                match self.config_store.save_verified(&next_cfg) {
                    Ok(saved) => {
                        self.engine.config = saved;
                        let detail = match archived {
                            Some(p) => {
                                format!("已移除保险箱 `{norm_id}` 并安全归档至 {}", p.display())
                            }
                            None if purge_disk_data => {
                                format!("已移除保险箱 `{norm_id}` 并清理磁盘隔离数据")
                            }
                            None => format!("已移除保险箱 `{norm_id}` 配置"),
                        };
                        let mut receipt = OperationReceipt::new(
                            format!("vault-delete-{norm_id}-{now}"),
                            OperationStatus::Verified,
                        );
                        receipt.verified_scope = norm_id.clone();
                        receipt.push_item(
                            "vault_delete",
                            OperationStatus::Verified,
                            detail.clone(),
                        );
                        self.engine.push_log(now, LogLevel::Audit, "vault", &detail);
                        self.engine.last_receipt = Some(receipt);
                    }
                    Err(err) => {
                        self.mutation_error = Some(err);
                    }
                }
                let snap = self.publish_snapshot(snapshot_store, now);
                self.send_mutation_reply(reply, snap);
            }
            PipeRequest::LaunchVault {
                vault_id,
                app,
                extra_args,
            } => {
                let norm_id = vault_id.trim().to_ascii_lowercase();
                let Some(vault) = self
                    .engine
                    .config
                    .vaults
                    .iter()
                    .find(|v| v.id.eq_ignore_ascii_case(&norm_id))
                    .cloned()
                else {
                    let _ = reply.send(PipeResponse::Error {
                        code: ErrorCode::NotFound,
                        message: format!("未找到主权账号保险箱 `{norm_id}`"),
                        receipt: None,
                    });
                    return;
                };
                if !vault.enabled {
                    let _ = reply.send(PipeResponse::Error {
                        code: ErrorCode::IllegalState,
                        message: format!("保险箱「{}」当前已停用", vault.name),
                        receipt: None,
                    });
                    return;
                }
                if self.engine.is_tripped() || self.engine.lockdown_applied == Some(true) {
                    let _ = reply.send(PipeResponse::Error {
                        code: ErrorCode::IllegalState,
                        message: "当前处于熔断隔离或锁死状态，已拒绝启动分身保险箱".into(),
                        receipt: None,
                    });
                    return;
                }
                let snap = self.build_snapshot(now);
                if self.engine.lifecycle == Lifecycle::Armed
                    && self.engine.config.enforce_access_path
                    && snap.access.is_uncovered()
                {
                    let _ = reply.send(PipeResponse::Error {
                        code: ErrorCode::IllegalState,
                        message: "未检测到活跃代理通道（TUN/系统代理离线），拒绝启动分身保险箱"
                            .into(),
                        receipt: None,
                    });
                    return;
                }

                // Cooldown enforcement.
                let cooldown = self.egress_ledger.vault_cooldown_remaining(&vault.id, now);
                if cooldown > 0 {
                    let _ = reply.send(PipeResponse::Error {
                        code: ErrorCode::IllegalState,
                        message: format!(
                            "保险箱「{}」处于换 IP 冷静期（剩余 {cooldown}s），暂不允许启动",
                            vault.name
                        ),
                        receipt: None,
                    });
                    return;
                }

                // Contract verification (safest default: read-only HARD BLOCK on mismatch unless
                // `vault.auto_align_mihomo_on_vault_launch == true`).
                let (obs_ip, obs_country, obs_asn) = current_primary_egress(&snap);
                if let Err(mismatch_reason) = check_vault_egress_contract(
                    &vault,
                    obs_ip.as_deref(),
                    obs_country.as_deref(),
                    obs_asn,
                ) {
                    if vault.auto_align_mihomo_on_vault_launch {
                        if let (Some(group), Some(node)) = (
                            vault.preferred_mihomo_group.as_deref(),
                            vault.preferred_mihomo_node.as_deref(),
                        ) {
                            match mihomo_win::switch_mihomo_node(group, node, true) {
                                Ok(msg) => {
                                    self.engine.push_log(
                                        now,
                                        LogLevel::Audit,
                                        "vault",
                                        &format!(
                                            "保险箱「{}」自动对齐 Mihomo 节点（{msg}），触发复检等待核验",
                                            vault.name
                                        ),
                                    );
                                    self.step_and_run(
                                        EngineEvent::StartRound {
                                            purpose: CheckPurpose::Manual,
                                        },
                                        now,
                                    );
                                    let _ = reply.send(PipeResponse::Error {
                                        code: ErrorCode::IllegalState,
                                        message: format!(
                                            "出口不匹配，已自动请求 Mihomo 切换至 `{node}` 并发起出口复检，请等待 2 秒核验通过后再次启动"
                                        ),
                                        receipt: None,
                                    });
                                    return;
                                }
                                Err(err) => {
                                    let _ = reply.send(PipeResponse::Error {
                                        code: ErrorCode::IllegalState,
                                        message: format!(
                                            "{mismatch_reason}；自动对齐 Mihomo 节点失败：{err}"
                                        ),
                                        receipt: None,
                                    });
                                    return;
                                }
                            }
                        }
                    }
                    let _ = reply.send(PipeResponse::Error {
                        code: ErrorCode::IllegalState,
                        message: format!(
                            "出口契约阻断（只读硬拦截，未改动您的代理配置）：{mismatch_reason}"
                        ),
                        receipt: None,
                    });
                    return;
                }

                if snap.risk_assessment.evaluated_at > 0
                    && snap.risk_assessment.score < vault.min_safety_score
                {
                    let _ = reply.send(PipeResponse::Error {
                        code: ErrorCode::IllegalState,
                        message: format!(
                            "当前 10D 出口安全分 {} 低于保险箱「{}」最低要求 {}，已拒绝启动",
                            snap.risk_assessment.score, vault.name, vault.min_safety_score
                        ),
                        receipt: None,
                    });
                    return;
                }

                let vaults_root = match self.effective_vaults_root() {
                    Ok(p) => p,
                    Err(err) => {
                        let _ = reply.send(PipeResponse::Error {
                            code: ErrorCode::IoFailed,
                            message: err,
                            receipt: None,
                        });
                        return;
                    }
                };
                if let Err(err) = vault_win::ensure_vault_layout_in(&vaults_root, &vault) {
                    let _ = reply.send(PipeResponse::Error {
                        code: ErrorCode::IoFailed,
                        message: err,
                        receipt: None,
                    });
                    return;
                }

                let user_home = self.effective_user_home();
                let mut spec = match vault_win::plan_vault_launch_env_and_args_in(
                    &vaults_root,
                    user_home.as_deref(),
                    &vault,
                    app,
                    &self.engine.config.proxy_host,
                    self.engine.config.proxy_port,
                    &extra_args,
                ) {
                    Ok(s) => s,
                    Err(err) => {
                        let _ = reply.send(PipeResponse::Error {
                            code: ErrorCode::ValidationFailed,
                            message: err,
                            receipt: None,
                        });
                        return;
                    }
                };

                if let vault_win::MsixLaunchStrategy::ExclusiveSwapLock { .. } = &spec.msix_strategy
                {
                    if let Err(err) = vault_win::acquire_msix_exclusive_lock(
                        &vaults_root,
                        app.agent_id(),
                        &vault.id,
                        now,
                    ) {
                        let _ = reply.send(PipeResponse::Error {
                            code: ErrorCode::IllegalState,
                            message: err,
                            receipt: None,
                        });
                        return;
                    }
                }

                // Append mode-aware Electron anti-leak hygiene args when enabled.
                if self.engine.config.enforce_electron_hygiene_flags
                    && hygiene_plan::is_electron_agent(app.agent_id())
                {
                    let proxy_addr = format!(
                        "{}:{}",
                        self.engine.config.proxy_host, spec.effective_proxy_port
                    );
                    let ag_dll_active = app == VaultAppTarget::AntigravityIde
                        && self.engine.antigravity_proxy.state.is_healthy();
                    let plan =
                        hygiene_plan::plan_electron_hygiene(&hygiene_plan::HygienePlanInput {
                            agent_id: app.agent_id().to_string(),
                            access_level: snap.access.level,
                            proxy_addr: Some(proxy_addr),
                            antigravity_version_dll_active: ag_dll_active,
                            enabled: true,
                        });
                    for flag in plan.args {
                        if !spec.args.contains(&flag) {
                            spec.args.push(flag);
                        }
                    }
                }

                let exe_candidates = if app.is_cli() {
                    self.driver
                        .discover_cli_exes(app.agent_id())
                        .unwrap_or_default()
                } else {
                    self.driver
                        .discover_agent_exes(app.agent_id())
                        .unwrap_or_default()
                };
                let Some(exe_path) = exe_candidates.into_iter().next() else {
                    let _ = reply.send(PipeResponse::Error {
                        code: ErrorCode::NotFound,
                        message: format!(
                            "未在本机找到目标客户端 `{}` 的可执行文件",
                            app.agent_id()
                        ),
                        receipt: None,
                    });
                    return;
                };

                let target = LaunchTarget::executable_with_env(
                    exe_path,
                    spec.args,
                    spec.env,
                    spec.working_dir,
                );
                let has_process_guard = self.driver.capabilities().process_guard;
                let before_pids: std::collections::HashSet<u32> = if has_process_guard {
                    self.process_scanner
                        .refresh()
                        .procs
                        .iter()
                        .map(|p| p.pid)
                        .collect()
                } else {
                    std::collections::HashSet::new()
                };
                match self.driver.launch_app_normal_privilege(&target) {
                    Ok(()) => {
                        if has_process_guard {
                            let mut discovered = discover_launched_vault_pids(
                                &self.process_scanner.refresh(),
                                &vaults_root,
                                &vault.id,
                                app,
                                &before_pids,
                            );
                            if discovered.is_empty() {
                                std::thread::sleep(Duration::from_millis(80));
                                discovered = discover_launched_vault_pids(
                                    &self.process_scanner.refresh(),
                                    &vaults_root,
                                    &vault.id,
                                    app,
                                    &before_pids,
                                );
                            }
                            if !discovered.is_empty() {
                                merge_vault_session_pids(
                                    self.vault_sessions.entry(vault.id.clone()).or_default(),
                                    discovered,
                                );
                            }
                        }
                        let _ = self.egress_ledger.record_vault_activity(
                            &vault.id,
                            obs_ip.as_deref(),
                            obs_country.as_deref(),
                            snap.risk_assessment.ip_purity.city.as_deref(),
                            snap.risk_assessment.ip_purity.lat_tenths,
                            snap.risk_assessment.ip_purity.lon_tenths,
                            vault.cooldown_after_ip_change_secs,
                            now,
                        );
                        let mut receipt = OperationReceipt::new(
                            format!("vault-launch-{}-{now}", vault.id),
                            OperationStatus::Verified,
                        );
                        receipt.verified_scope = format!("{}:{}", vault.id, app.agent_id());
                        receipt.push_item(
                            "vault_launch",
                            OperationStatus::Verified,
                            format!("已在主权保险箱「{}」启动 {}", vault.name, app.agent_id()),
                        );
                        self.engine.push_log(
                            now,
                            LogLevel::Audit,
                            "vault",
                            &format!("启动主权保险箱「{}」应用 {}", vault.name, app.agent_id()),
                        );
                        self.engine.last_receipt = Some(receipt.clone());
                        let next_snap = self.publish_snapshot(snapshot_store, now);
                        let _ = reply.send(PipeResponse::Ack {
                            receipt: Some(receipt),
                            snapshot: Some(Box::new(next_snap)),
                        });
                    }
                    Err(err) => {
                        let _ = reply.send(PipeResponse::Error {
                            code: ErrorCode::IoFailed,
                            message: format!("启动分身保险箱进程失败：{err}"),
                            receipt: None,
                        });
                    }
                }
            }
            PipeRequest::StopVault { vault_id } => {
                let norm_id = vault_id.trim().to_ascii_lowercase();
                if !is_valid_vault_id(&norm_id) {
                    let _ = reply.send(PipeResponse::Error {
                        code: ErrorCode::ValidationFailed,
                        message: format!("非法的保险箱 ID：`{vault_id}`"),
                        receipt: None,
                    });
                    return;
                }
                let vaults_root = match self.effective_vaults_root() {
                    Ok(p) => p,
                    Err(err) => {
                        let _ = reply.send(PipeResponse::Error {
                            code: ErrorCode::IoFailed,
                            message: err,
                            receipt: None,
                        });
                        return;
                    }
                };
                let stopped = self.stop_vault_processes(&norm_id, &vaults_root);
                let mut receipt = OperationReceipt::new(
                    format!("vault-stop-{norm_id}-{now}"),
                    OperationStatus::Verified,
                );
                receipt.verified_scope = format!("stopped_pids={stopped}");
                receipt.push_item(
                    "vault_stop",
                    OperationStatus::Verified,
                    format!("已停止保险箱 `{norm_id}` 下 {stopped} 个跟踪进程"),
                );
                self.engine.push_log(
                    now,
                    LogLevel::Audit,
                    "vault",
                    &format!("停止主权保险箱 `{norm_id}`（终止 {stopped} 个进程）"),
                );
                self.engine.last_receipt = Some(receipt.clone());
                let snap = self.publish_snapshot(snapshot_store, now);
                let _ = reply.send(PipeResponse::Ack {
                    receipt: Some(receipt),
                    snapshot: Some(Box::new(snap)),
                });
            }
            PipeRequest::GenerateVaultShortcuts { vault_id } => {
                let norm_id = vault_id.trim().to_ascii_lowercase();
                let Some(vault) = self
                    .engine
                    .config
                    .vaults
                    .iter()
                    .find(|v| v.id.eq_ignore_ascii_case(&norm_id))
                    .cloned()
                else {
                    let _ = reply.send(PipeResponse::Error {
                        code: ErrorCode::NotFound,
                        message: format!("未找到主权账号保险箱 `{norm_id}`"),
                        receipt: None,
                    });
                    return;
                };
                let vaults_root = match self.effective_vaults_root() {
                    Ok(p) => p,
                    Err(err) => {
                        let _ = reply.send(PipeResponse::Error {
                            code: ErrorCode::IoFailed,
                            message: err,
                            receipt: None,
                        });
                        return;
                    }
                };
                let cli_exe = hook_installer::resolve_cli_exe_path();
                let desktop_dir = self
                    .effective_user_home()
                    .map(|h| h.join("Desktop"))
                    .unwrap_or_else(|| vaults_root.join(&vault.id).join("shortcuts"));
                match vault_win::generate_vault_shortcuts_in(
                    &vaults_root,
                    &vault,
                    &cli_exe,
                    &desktop_dir,
                ) {
                    Ok(created) => {
                        let mut receipt = OperationReceipt::new(
                            format!("vault-shortcuts-{norm_id}-{now}"),
                            OperationStatus::Verified,
                        );
                        receipt.verified_scope = format!("created={}", created.len());
                        receipt.push_item(
                            "vault_shortcuts",
                            OperationStatus::Verified,
                            format!("已生成 {} 个直启快捷方式与终端环境脚本", created.len()),
                        );
                        self.engine.push_log(
                            now,
                            LogLevel::Audit,
                            "vault",
                            &format!(
                                "已为保险箱「{}」生成 {} 个快捷方式",
                                vault.name,
                                created.len()
                            ),
                        );
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
                            message: err,
                            receipt: None,
                        });
                    }
                }
            }
            PipeRequest::ScanCleanRoom { scope } => {
                let user_home = self.effective_user_home();
                let report = cleanroom_win::scan_cleanroom(&scope, user_home.as_deref(), now);
                self.last_cleanroom_report = Some(report.clone());
                self.cleanroom_backup_count =
                    cleanroom_win::list_cleanroom_backups(&self.data_dir).len();
                let _ = self.publish_snapshot(snapshot_store, now);
                let _ = reply.send(PipeResponse::CleanRoomScan {
                    report: Box::new(report),
                });
            }
            PipeRequest::ExecuteCleanRoom {
                scope,
                selected_finding_ids,
            } => {
                let user_home = self.effective_user_home();
                match cleanroom_win::execute_cleanroom_with_backup(
                    &self.data_dir,
                    &scope,
                    &selected_finding_ids,
                    user_home.as_deref(),
                    now,
                ) {
                    Ok((meta, post_report)) => {
                        self.last_cleanroom_report = Some(post_report.clone());
                        self.cleanroom_backup_count =
                            cleanroom_win::list_cleanroom_backups(&self.data_dir).len();
                        let mut receipt = OperationReceipt::new(
                            format!("cleanroom-exec-{now}"),
                            OperationStatus::Verified,
                        );
                        receipt.verified_scope = meta.backup_id.clone();
                        receipt.push_item(
                            "cleanroom_backup",
                            OperationStatus::Verified,
                            format!(
                                "已生成加密备份 {}（{} 项，残余污染分 {}/100）",
                                meta.backup_id, meta.item_count, post_report.pollution_score
                            ),
                        );
                        self.engine.push_log(
                            now,
                            LogLevel::Audit,
                            "cleanroom",
                            &format!(
                                "净室洗白完成：已加密备份 {}（{} 项），复扫污染分 {}/100",
                                meta.backup_id, meta.item_count, post_report.pollution_score
                            ),
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
            PipeRequest::ListCleanRoomBackups => {
                let backups = cleanroom_win::list_cleanroom_backups(&self.data_dir);
                self.cleanroom_backup_count = backups.len();
                let _ = self.publish_snapshot(snapshot_store, now);
                let _ = reply.send(PipeResponse::CleanRoomBackups { backups });
            }
            PipeRequest::RestoreCleanRoomBackup { backup_id } => {
                match cleanroom_win::restore_cleanroom_backup(&self.data_dir, &backup_id) {
                    Ok(restored) => {
                        let mut receipt = OperationReceipt::new(
                            format!("cleanroom-restore-{now}"),
                            OperationStatus::Verified,
                        );
                        receipt.verified_scope = format!("backup={backup_id}, restored={restored}");
                        receipt.push_item(
                            "cleanroom_restore",
                            OperationStatus::Verified,
                            format!("已从加密备份 `{backup_id}` 还原 {restored} 项文件/凭据"),
                        );
                        self.engine.push_log(
                            now,
                            LogLevel::Audit,
                            "cleanroom",
                            &format!("净室回滚完成：已从 `{backup_id}` 还原 {restored} 项"),
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
            PipeRequest::ConfigureCliHooks {
                install_claude_code,
                install_pwsh_profile,
                sync_all_vaults,
            } => {
                let Some(user_home) = self.effective_user_home() else {
                    let _ = reply.send(PipeResponse::Error {
                        code: ErrorCode::IoFailed,
                        message: "未能解析交互用户主目录，无法写入 CLI Hook 配置".into(),
                        receipt: None,
                    });
                    return;
                };
                let vaults_root = match self.effective_vaults_root() {
                    Ok(p) => p,
                    Err(err) => {
                        let _ = reply.send(PipeResponse::Error {
                            code: ErrorCode::IoFailed,
                            message: err,
                            receipt: None,
                        });
                        return;
                    }
                };
                let cli_exe = hook_installer::resolve_cli_exe_path();
                match hook_installer::configure_cli_hooks_in(
                    &user_home,
                    Some(&vaults_root),
                    &cli_exe,
                    &self.engine.config.vaults,
                    install_claude_code,
                    install_pwsh_profile,
                    sync_all_vaults,
                ) {
                    Ok(status) => {
                        let summary = status.summary.clone();
                        self.hooks = status;
                        let mut receipt = OperationReceipt::new(
                            format!("cli-hooks-{now}"),
                            OperationStatus::Verified,
                        );
                        receipt.verified_scope = "cli_hooks".into();
                        receipt.push_item("cli_hooks", OperationStatus::Verified, summary.clone());
                        self.engine
                            .push_log(now, LogLevel::Audit, "hooks", &summary);
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
            PipeRequest::SyncWslBridge => {
                let Some(in_flight) = InFlightGuard::try_acquire(&self.wsl_sync_in_flight) else {
                    let _ = reply.send(PipeResponse::Error {
                        code: ErrorCode::Busy,
                        message: "WSL2 发行版探针同步正在进行中，请稍候".into(),
                        receipt: None,
                    });
                    return;
                };
                let enabled = self.engine.config.wsl_bridge_enabled;
                let bound_port = self.wsl_bridge.bound_port;
                let token_ready = self.wsl_bridge.token_ready;
                let desync = self
                    .hook_metrics_ref
                    .as_ref()
                    .is_some_and(|m| m.wsl_proxy_desync.load(Ordering::Relaxed));
                let event_tx = self.event_tx.clone();
                let reply_cell = Arc::new(Mutex::new(Some(reply)));
                let worker_reply = reply_cell.clone();
                if std::thread::Builder::new()
                    .name("cg-wsl-sync".to_string())
                    .spawn(move || {
                        let _guard = in_flight;
                        let status =
                            wsl_bridge::sync_wsl_distros(enabled, bound_port, token_ready, desync);
                        if let Some(tx) = worker_reply.lock().ok().and_then(|mut g| g.take()) {
                            let _ = event_tx.send(CoordinatorEvent::WslBridgeSynced {
                                status: Box::new(status),
                                now_secs: now_unix_secs(),
                                reply: Some(tx),
                            });
                        }
                    })
                    .is_err()
                {
                    if let Some(tx) = reply_cell.lock().ok().and_then(|mut g| g.take()) {
                        let _ = tx.send(PipeResponse::Error {
                            code: ErrorCode::Busy,
                            message: "创建 WSL2 同步工作线程失败，请稍后重试".into(),
                            receipt: None,
                        });
                    }
                }
            }
            PipeRequest::TriggerPanicLockdown => {
                if matches!(
                    self.engine.lifecycle,
                    Lifecycle::Unconfigured | Lifecycle::Stopping
                ) {
                    let _ = reply.send(PipeResponse::Error {
                        code: ErrorCode::IllegalState,
                        message: format!(
                            "当前生命周期（{}）不允许触发紧急全锁死",
                            self.engine.lifecycle.label()
                        ),
                        receipt: None,
                    });
                    return;
                }
                self.step_and_run(EngineEvent::SetManualLockdown { on: true }, now);
                let mut receipt = OperationReceipt::new(
                    format!("panic-lockdown-{now}"),
                    OperationStatus::Verified,
                );
                let guis = self.engine.config.guarded_agents.clone();
                let (gui_killed, _, _) = kill_gui_list_with_receipt(
                    &*self.driver,
                    &guis,
                    "panic_kill_gui",
                    &mut receipt,
                );
                let (cli_killed, _, _) =
                    kill_cli_list_with_receipt(&*self.driver, &KNOWN_CLI_AGENT_IDS, &mut receipt);
                let mut vault_killed = 0usize;
                if let Ok(vaults_root) = self.effective_vaults_root() {
                    let mut vids: Vec<String> = self.vault_sessions.keys().cloned().collect();
                    for v in &self.engine.config.vaults {
                        if !vids.iter().any(|existing| existing == &v.id) {
                            vids.push(v.id.clone());
                        }
                    }
                    for vid in vids {
                        vault_killed += self.stop_vault_processes(&vid, &vaults_root);
                    }
                }
                receipt.verified_scope = format!(
                    "lockdown=true, gui_killed={gui_killed}, cli_killed={cli_killed}, vault_killed={vault_killed}"
                );
                let msg = format!(
                    "触发紧急一键锁死（Panic Lockdown）：已锁定出站并终止 GUI {gui_killed} / CLI {cli_killed} / 保险箱 {vault_killed} 个进程"
                );
                self.engine.push_log(now, LogLevel::Audit, "panic", &msg);
                self.emit_notification("trip", "ClaudeGuard 紧急锁死已触发", &msg, now);
                self.engine.last_receipt = Some(receipt.clone());
                let snap = self.publish_snapshot(snapshot_store, now);
                let _ = reply.send(PipeResponse::Ack {
                    receipt: Some(receipt),
                    snapshot: Some(Box::new(snap)),
                });
            }
            PipeRequest::ClearWfpBlockedEvents => {
                self.driver.clear_wfp_events();
                let wfp = self.driver.wfp_status();
                self.step_and_run(
                    EngineEvent::WfpUpdated {
                        status: Box::new(wfp),
                    },
                    now,
                );
                let mut receipt = OperationReceipt::new(
                    format!("wfp-clear-events-{now}"),
                    OperationStatus::Verified,
                );
                receipt.verified_scope = "wfp.recent_blocked".into();
                receipt.push_item(
                    "clear_wfp_events",
                    OperationStatus::Verified,
                    "已清空 WFP 实时内核拦截事件缓冲队列",
                );
                self.engine
                    .push_log(now, LogLevel::Audit, "wfp", "已清空 WFP 内核拦截事件列表");
                self.engine.last_receipt = Some(receipt.clone());
                let snap = self.publish_snapshot(snapshot_store, now);
                let _ = reply.send(PipeResponse::Ack {
                    receipt: Some(receipt),
                    snapshot: Some(Box::new(snap)),
                });
            }
            PipeRequest::RunDeepRiskAudit => {
                let Some(in_flight) = InFlightGuard::try_acquire(&self.deep_audit_in_flight) else {
                    let _ = reply.send(PipeResponse::Error {
                        code: ErrorCode::Busy,
                        message: "10D 深度封号风险体检正在进行中，请稍候".into(),
                        receipt: None,
                    });
                    return;
                };
                let snap = self.build_snapshot(now);
                let driver = self.driver.clone();
                let ledger = self.egress_ledger.clone();
                let scanner = self.process_scanner.clone();
                let has_process_guard = self.driver.capabilities().process_guard;
                let event_tx = self.event_tx.clone();
                let reply_cell = Arc::new(Mutex::new(Some(reply)));
                let worker_reply = reply_cell.clone();
                if std::thread::Builder::new()
                    .name("cg-deep-risk-audit".to_string())
                    .spawn(move || {
                        let _guard = in_flight;
                        ip_intel::clear_ip_intel_cache();
                        let procs = if has_process_guard {
                            scanner.refresh()
                        } else {
                            scanner.cached_snapshot()
                        };
                        let electron_pids = collect_electron_agent_pids(&procs);
                        let ts = now_unix_secs();
                        let assessment = compute_deep_risk_assessment(
                            &*driver,
                            &snap,
                            &ledger,
                            &electron_pids,
                            true,
                            ts,
                        );
                        if let Some(tx) = worker_reply.lock().ok().and_then(|mut g| g.take()) {
                            let _ = event_tx.send(CoordinatorEvent::DeepRiskAuditFinished {
                                assessment: Box::new(assessment),
                                now_secs: now_unix_secs(),
                                reply: Some(tx),
                            });
                        }
                    })
                    .is_err()
                {
                    if let Some(tx) = reply_cell.lock().ok().and_then(|mut g| g.take()) {
                        let _ = tx.send(PipeResponse::Error {
                            code: ErrorCode::Busy,
                            message: "创建深度体检工作线程失败，请稍后重试".into(),
                            receipt: None,
                        });
                    }
                }
            }
            PipeRequest::ClearGeoVelocityCooldown => {
                let _ = self.egress_ledger.clear_cooldown(now);
                let mut next_risk = self.engine.risk_assessment.clone();
                next_risk.geo_velocity_alert = None;
                self.step_and_run(
                    EngineEvent::RiskUpdated {
                        assessment: Box::new(next_risk),
                    },
                    now,
                );
                let mut receipt = OperationReceipt::new(
                    format!("clear-geo-cooldown-{now}"),
                    OperationStatus::Verified,
                );
                receipt.verified_scope = "egress_ledger.cooldown".into();
                receipt.push_item(
                    "clear_geo_velocity_cooldown",
                    OperationStatus::Verified,
                    "已确认行程并清除时空瞬移冷却锁定",
                );
                self.engine.push_log(
                    now,
                    LogLevel::Audit,
                    "risk",
                    "用户手动确认并清除了跨国瞬移冷却锁",
                );
                self.engine.last_receipt = Some(receipt.clone());
                let snap = self.publish_snapshot(snapshot_store, now);
                let _ = reply.send(PipeResponse::Ack {
                    receipt: Some(receipt),
                    snapshot: Some(Box::new(snap)),
                });
            }
            PipeRequest::BuildHealthCard { export_png } => {
                let snap = self.build_snapshot(now);
                let card = diagnostics::build_sanitized_health_card(
                    &snap,
                    &self.data_dir,
                    now,
                    export_png,
                );
                if export_png {
                    self.engine.push_log(
                        now,
                        LogLevel::Audit,
                        "diagnostics",
                        "已导出脱敏防封健康体检卡 PNG",
                    );
                    let _ = self.publish_snapshot(snapshot_store, now);
                }
                let _ = reply.send(PipeResponse::HealthCard {
                    card: Box::new(card),
                });
            }
        }
    }

    fn refresh_live_vault_sessions(&mut self, procs: &CachedProcessSnapshot) {
        self.vault_sessions.retain(|_, entries| {
            entries.retain(|(pid, _)| *pid > 0 && is_pid_alive(*pid));
            !entries.is_empty()
        });
        let Ok(vaults_root) = self.effective_vaults_root() else {
            return;
        };
        let vault_ids: Vec<String> = self
            .engine
            .config
            .vaults
            .iter()
            .map(|v| v.id.clone())
            .collect();
        for vid in vault_ids {
            let discovered = discover_live_vault_pids(procs, &vaults_root, &vid);
            if !discovered.is_empty() {
                merge_vault_session_pids(self.vault_sessions.entry(vid).or_default(), discovered);
            }
        }
    }

    fn stop_vault_processes(&mut self, vault_id: &str, vaults_root: &std::path::Path) -> usize {
        let mut target_pids: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
        if let Some(entries) = self.vault_sessions.remove(vault_id) {
            for (pid, _app) in entries {
                if pid > 0 {
                    target_pids.insert(pid);
                }
            }
        }
        if self.driver.capabilities().process_guard {
            let procs = self.process_scanner.refresh();
            for (pid, _app) in discover_live_vault_pids(&procs, vaults_root, vault_id) {
                if pid > 0 {
                    target_pids.insert(pid);
                }
            }
        }
        let mut count = 0usize;
        for pid in target_pids {
            if terminate_pid_best_effort(pid) {
                count += 1;
            }
        }
        let _ = vault_win::release_msix_exclusive_lock(vaults_root, "claude", vault_id);
        let _ = vault_win::release_msix_exclusive_lock(vaults_root, "chatgpt", vault_id);
        count
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
        if let Some(message) = self.mutation_error.take() {
            let _ = reply.send(PipeResponse::Error {
                code: ErrorCode::IoFailed,
                message,
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

    #[allow(dead_code)]
    fn run_probe_onboarding(&self, now: u64) -> OnboardingProbeResult {
        probe_onboarding_with(
            &*self.driver,
            &*self.probe_runner,
            &self.engine.config,
            self.engine.cfg_rev,
            now,
        )
    }
}

fn format_wfp_persistent_sublayer_guid() -> String {
    let g = wfp_win::CLAUDEGUARD_WFP_SUBLAYER_PERSISTENT_GUID_U128;
    format!(
        "{{{:08x}-{:04x}-{:04x}-{:04x}-{:012x}}}",
        (g >> 96) as u32,
        ((g >> 80) & 0xFFFF) as u16,
        ((g >> 64) & 0xFFFF) as u16,
        ((g >> 48) & 0xFFFF) as u16,
        g & 0xFFFF_FFFF_FFFF,
    )
}

#[cfg(windows)]
fn terminate_pid_best_effort(pid: u32) -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
    if pid == 0 || pid == std::process::id() {
        return false;
    }
    unsafe {
        let Ok(handle) = OpenProcess(PROCESS_TERMINATE, false, pid) else {
            return false;
        };
        let ok = TerminateProcess(handle, 1).is_ok();
        let _ = CloseHandle(handle);
        ok
    }
}

#[cfg(not(windows))]
fn terminate_pid_best_effort(_pid: u32) -> bool {
    false
}

#[cfg(windows)]
pub(crate) fn is_pid_alive(pid: u32) -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    const STILL_ACTIVE_EXIT_CODE: u32 = 259;
    if pid == 0 {
        return false;
    }
    unsafe {
        let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return false;
        };
        let mut exit_code: u32 = 0;
        let alive = GetExitCodeProcess(handle, &mut exit_code).is_ok()
            && exit_code == STILL_ACTIVE_EXIT_CODE;
        let _ = CloseHandle(handle);
        alive
    }
}

#[cfg(not(windows))]
pub(crate) fn is_pid_alive(_pid: u32) -> bool {
    false
}

/// Extracts main Electron GUI client `(agent_id, pid)` pairs from a cached process snapshot
/// for live command-line anti-leak hygiene auditing (`NtQueryInformationProcess(60)`).
///
/// Filters out Chromium child helper processes (`--type=renderer`, `--type=gpu-process`, etc.),
/// SCM service/updater helpers, and non-Electron clients such as `zed`.
pub fn collect_electron_agent_pids(procs: &CachedProcessSnapshot) -> Vec<(String, u32)> {
    let pid_to_name: HashMap<u32, &str> = procs
        .procs
        .iter()
        .map(|p| (p.pid, p.name_l.as_str()))
        .collect();
    let mut out: Vec<(String, u32)> = Vec::new();
    let mut seen_pids: std::collections::HashSet<u32> = std::collections::HashSet::new();

    for p in &procs.procs {
        if p.pid == 0 || !seen_pids.insert(p.pid) {
            continue;
        }
        if cg_core::agents::is_agent_scm_service_exe(&p.name_l)
            || p.name_l.contains("crashpad")
            || p.name_l.contains("updater")
            || p.name_l == "update.exe"
            || p.cmd_l.contains("--type=")
        {
            continue;
        }
        if p.cmd_l.is_empty()
            && p.ppid != 0
            && pid_to_name
                .get(&p.ppid)
                .is_some_and(|parent_name| *parent_name == p.name_l.as_str())
        {
            continue;
        }
        for agent in GUI_AGENTS {
            if !hygiene_plan::is_electron_agent(agent.id) {
                continue;
            }
            if cg_core::agents::gui_agent_matches_with_all_dirs(
                agent.id,
                &p.name_l,
                &p.path_l,
                &procs.claude_dirs_l,
                &procs.chatgpt_dirs_l,
                &procs.antigravity_dirs_l,
            ) {
                out.push((agent.id.to_string(), p.pid));
                break;
            }
        }
    }
    out
}

fn normalize_path_needle(path: &std::path::Path) -> (String, String) {
    let raw = path.to_string_lossy();
    let stripped = raw.strip_prefix(r"\\?\").unwrap_or(&raw);
    let bs = stripped
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase();
    let fs = bs.replace('\\', "/");
    (bs, fs)
}

fn cmd_contains_path_prefix(cmd_l: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let mut search_from = 0usize;
    while let Some(rel) = cmd_l[search_from..].find(needle) {
        let end = search_from + rel + needle.len();
        let boundary_ok = match cmd_l[end..].chars().next() {
            None => true,
            Some('\\' | '/' | '"' | '\'' | ' ' | '\t' | ';' | ',') => true,
            Some(_) => false,
        };
        if boundary_ok {
            return true;
        }
        search_from = search_from + rel + 1;
        if search_from >= cmd_l.len() {
            break;
        }
    }
    false
}

fn infer_vault_proc_app_label(
    p: &process_win::ProcInfo,
    cmd_l: &str,
    procs: &CachedProcessSnapshot,
) -> String {
    for agent in GUI_AGENTS {
        if cg_core::agents::gui_agent_matches_with_all_dirs(
            agent.id,
            &p.name_l,
            &p.path_l,
            &procs.claude_dirs_l,
            &procs.chatgpt_dirs_l,
            &procs.antigravity_dirs_l,
        ) {
            return agent.id.to_string();
        }
    }
    for (id, _) in CLI_AGENTS {
        if cg_core::agents::cli_agent_matches(id, &p.name_l, &p.path_l, cmd_l) {
            return (*id).to_string();
        }
    }
    let stem = p.name_l.trim_end_matches(".exe").trim();
    if stem.is_empty() {
        "vault-app".to_string()
    } else {
        stem.to_string()
    }
}

/// Pure snapshot scanner discovering all non-zero processes whose command line references
/// `<vaults_root>\<vault_id>` (e.g. `--user-data-dir=<vault_dir>\...`), enforcing strict path boundaries
/// so `jp` never false-matches `jp-work`.
pub fn discover_vault_pids_in_snapshot(
    procs: &CachedProcessSnapshot,
    vaults_root: &std::path::Path,
    vault_id: &str,
) -> Vec<(u32, String)> {
    let vault_dir = vaults_root.join(vault_id);
    let (needle_bs, needle_fs) = normalize_path_needle(&vault_dir);
    let self_pid = std::process::id();
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for p in &procs.procs {
        if p.pid == 0 || p.pid == self_pid || !seen.insert(p.pid) {
            continue;
        }
        if cmd_contains_path_prefix(&p.cmd_l, &needle_bs)
            || cmd_contains_path_prefix(&p.cmd_l, &needle_fs)
        {
            out.push((p.pid, infer_vault_proc_app_label(p, &p.cmd_l, procs)));
        }
    }
    out
}

fn discover_live_vault_pids(
    procs: &CachedProcessSnapshot,
    vaults_root: &std::path::Path,
    vault_id: &str,
) -> Vec<(u32, String)> {
    let mut found = discover_vault_pids_in_snapshot(procs, vaults_root, vault_id);
    let mut seen: std::collections::HashSet<u32> = found.iter().map(|(pid, _)| *pid).collect();
    let vault_dir = vaults_root.join(vault_id);
    let (needle_bs, needle_fs) = normalize_path_needle(&vault_dir);
    let self_pid = std::process::id();

    for p in &procs.procs {
        if p.pid == 0 || p.pid == self_pid || !p.cmd_l.is_empty() || seen.contains(&p.pid) {
            continue;
        }
        let matches_known_gui = GUI_AGENTS.iter().any(|agent| {
            cg_core::agents::gui_agent_matches_with_all_dirs(
                agent.id,
                &p.name_l,
                &p.path_l,
                &procs.claude_dirs_l,
                &procs.chatgpt_dirs_l,
                &procs.antigravity_dirs_l,
            )
        });
        if !matches_known_gui {
            continue;
        }
        if let Ok(raw_cmd) = hygiene_win::query_process_command_line_fast(p.pid) {
            let cmd_l = raw_cmd.to_ascii_lowercase();
            if cmd_contains_path_prefix(&cmd_l, &needle_bs)
                || cmd_contains_path_prefix(&cmd_l, &needle_fs)
            {
                seen.insert(p.pid);
                found.push((p.pid, infer_vault_proc_app_label(p, &cmd_l, procs)));
            }
        }
    }
    found
}

fn discover_launched_vault_pids(
    after_procs: &CachedProcessSnapshot,
    vaults_root: &std::path::Path,
    vault_id: &str,
    app: VaultAppTarget,
    before_pids: &std::collections::HashSet<u32>,
) -> Vec<(u32, String)> {
    let mut found = discover_live_vault_pids(after_procs, vaults_root, vault_id);
    let mut seen: std::collections::HashSet<u32> = found.iter().map(|(pid, _)| *pid).collect();
    let self_pid = std::process::id();
    let agent_id = app.agent_id();

    for p in &after_procs.procs {
        if p.pid == 0 || p.pid == self_pid || before_pids.contains(&p.pid) || seen.contains(&p.pid)
        {
            continue;
        }
        let matched = if app.is_cli() {
            cg_core::agents::cli_agent_matches(agent_id, &p.name_l, &p.path_l, &p.cmd_l)
        } else {
            cg_core::agents::gui_agent_matches_with_all_dirs(
                agent_id,
                &p.name_l,
                &p.path_l,
                &after_procs.claude_dirs_l,
                &after_procs.chatgpt_dirs_l,
                &after_procs.antigravity_dirs_l,
            )
        };
        if matched {
            seen.insert(p.pid);
            found.push((p.pid, agent_id.to_string()));
        }
    }
    found
}

fn merge_vault_session_pids(existing: &mut Vec<(u32, String)>, incoming: Vec<(u32, String)>) {
    for (pid, app) in incoming {
        if pid == 0 {
            continue;
        }
        if !existing
            .iter()
            .any(|(existing_pid, _)| *existing_pid == pid)
        {
            existing.push((pid, app));
        }
    }
}

/// Computes a full 10-Dimension Ban-Risk & Egress Safety [`RiskAssessment`] strictly off-thread.
///
/// Honors fail-closed routing: when `ProbeRoute::Skip(_)` or `access_path_inspection` is unsupported,
/// opens ZERO external sockets and computes an offline purity/hygiene/ledger assessment cleanly.
pub fn compute_deep_risk_assessment(
    driver: &dyn PlatformDriver,
    snap: &GuardSnapshot,
    ledger: &EgressLedger,
    electron_pids: &[(String, u32)],
    allow_network: bool,
    now_secs: u64,
) -> RiskAssessment {
    let (obs_ip, obs_country, _obs_asn) = current_primary_egress(snap);
    let route = if allow_network && driver.capabilities().access_path_inspection {
        resolve_access_and_route(
            driver,
            &snap.config,
            snap.cfg_rev,
            &snap.config.targets,
            snap.config.enforce_access_path,
            now_secs,
        )
        .1
    } else {
        ProbeRoute::Skip("offline".into())
    };

    let mut ip_purity = ip_intel::fetch_ip_purity_via_route(
        &route,
        obs_ip.as_deref(),
        obs_country.as_deref(),
        now_secs,
    );

    if allow_network && !matches!(route, ProbeRoute::Skip(_)) {
        let ipv6_cc = ip_intel::probe_ipv6_egress_via_route(&route, Duration::from_secs(3))
            .and_then(|(_, cc)| cc);
        ip_intel::attach_dual_stack_ipv6_check(&mut ip_purity, ipv6_cc);
    }

    let stun_leak = if allow_network
        && snap.config.enable_stun_dns_audit
        && driver.capabilities().access_path_inspection
    {
        stun_probe::probe_webrtc_stun_leak(
            ip_purity.ip.as_deref().or(obs_ip.as_deref()),
            1200,
            now_secs,
        )
    } else {
        crate::protocol::StunLeakReport::default()
    };

    let dns_coherence = if allow_network
        && snap.config.enable_stun_dns_audit
        && !matches!(route, ProbeRoute::Skip(_))
    {
        ip_intel::probe_dns_coherence(
            &route,
            ip_purity.country.as_deref().or(obs_country.as_deref()),
            now_secs,
        )
    } else {
        crate::protocol::DnsCoherenceReport::default()
    };

    let electron_hygiene = hygiene_win::audit_running_electron_hygiene(electron_pids, now_secs);

    let history_7d = ledger.observations_for_scoring(None, now_secs);
    let current_observation = match (
        ip_purity.ip.as_deref().or(obs_ip.as_deref()),
        ip_purity.country.as_deref().or(obs_country.as_deref()),
    ) {
        (Some(ip), Some(cc)) => {
            let city = ip_purity.city.as_deref().unwrap_or("");
            let _ = ledger.record_and_evaluate(
                ip,
                cc,
                city,
                ip_purity.lat_tenths,
                ip_purity.lon_tenths,
                None,
                if snap.config.enforce_geo_velocity {
                    risk_scorer::DEFAULT_TELEPORT_COOLDOWN_MINS
                } else {
                    0
                },
                now_secs,
            );
            Some(ledger.make_observation(
                ip,
                cc,
                city,
                ip_purity.lat_tenths,
                ip_purity.lon_tenths,
                None,
                now_secs,
            ))
        }
        _ => None,
    };

    let mut lat_min = u64::MAX;
    let mut lat_max = 0u64;
    for t in &snap.targets {
        if t.latency_ms > 0 {
            lat_min = lat_min.min(t.latency_ms);
            lat_max = lat_max.max(t.latency_ms);
        }
    }
    let rtt_jitter_ms = lat_max.saturating_sub(lat_min);

    let input = risk_scorer::RiskScoringInput {
        ip_purity,
        stun_leak,
        dns_coherence,
        electron_hygiene,
        env_check: Some(snap.env.clone()),
        windows_geo_name: env_win::read_user_geo_name(),
        accept_language: Some(env_win::read_accept_language_hint()),
        edge_challenged: false,
        tls_or_http_downgraded: false,
        active_mtu: None,
        rtt_jitter_ms,
        history_7d,
        current_observation,
        teleport_cooldown_mins: if snap.config.enforce_geo_velocity {
            risk_scorer::DEFAULT_TELEPORT_COOLDOWN_MINS
        } else {
            0
        },
        now_secs,
    };
    risk_scorer::score_egress_risk(&input)
}

fn is_non_cn_geo_probe(p: &ProbeResult) -> bool {
    let has_ip = p.ip.as_deref().is_some_and(|s| !s.trim().is_empty());
    let country = p
        .country
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    p.reachable && has_ip && country.is_some_and(|c| !c.eq_ignore_ascii_case("CN"))
}

fn probe_onboarding_with(
    driver: &dyn PlatformDriver,
    probe_runner: &dyn ProbeRunner,
    cfg: &Config,
    cfg_rev: u64,
    now: u64,
) -> OnboardingProbeResult {
    let hosts = cg_core::access::monitored_hosts(cfg);
    let (access_ev, probe_route) = match driver.inspect_access_path(&hosts) {
        Ok((path, _)) => (
            path.to_protocol_evidence(now, cfg_rev),
            probe_http::plan_probe_route(&path),
        ),
        Err(_) => (
            AccessEvidence {
                level: AccessLevel::Unknown,
                observed_at: now,
                revision: cfg_rev,
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
        .and_then(|(_, p)| p.trim_end_matches('/').parse::<u16>().ok())
        .filter(|&p| p > 0);

    let claude_target = cfg.target("claude").cloned().unwrap_or_else(|| {
        cg_protocol::default_builtin_targets(&[], &[])
            .into_iter()
            .find(|t| t.id == "claude")
            .unwrap_or(Target {
                id: "claude".into(),
                name: "Claude".into(),
                builtin: true,
                enabled: true,
                anchor_url: "https://claude.ai/cdn-cgi/trace".into(),
                anchor_kind: crate::protocol::AnchorKind::Trace,
                expect_ips: Vec::new(),
                expect_regions: Vec::new(),
                timeout_secs: 12,
                bind_agent: Some("claude".into()),
            })
    });

    let probe = if access_ev.is_known() && !matches!(probe_route, ProbeRoute::Skip(_)) {
        let mut chatgpt_fallback = claude_target.clone();
        chatgpt_fallback.id = "chatgpt".into();
        chatgpt_fallback.name = "ChatGPT".into();
        chatgpt_fallback.enabled = true;
        chatgpt_fallback.anchor_url = "https://chatgpt.com/cdn-cgi/trace".into();

        let mut cloudflare_fallback = claude_target.clone();
        cloudflare_fallback.id = "cloudflare".into();
        cloudflare_fallback.name = "Cloudflare".into();
        cloudflare_fallback.enabled = true;
        cloudflare_fallback.anchor_url = "https://cloudflare.com/cdn-cgi/trace".into();

        let mut claude_probe = claude_target;
        claude_probe.enabled = true;

        let candidates = [claude_probe, chatgpt_fallback, cloudflare_fallback];
        let mut best_cn: Option<ProbeResult> = None;
        let mut best_reachable: Option<ProbeResult> = None;
        let mut first_failed: Option<ProbeResult> = None;
        let mut selected: Option<ProbeResult> = None;

        for candidate in candidates {
            let (_ev, mut list) = probe_runner.inspect_and_probe(
                driver,
                cfg,
                cfg_rev,
                &[candidate],
                cfg.enforce_access_path,
                false,
                now,
            );
            if let Some((_, res)) = list.pop() {
                if is_non_cn_geo_probe(&res) {
                    selected = Some(res);
                    break;
                }
                if res.reachable
                    && res
                        .country
                        .as_deref()
                        .is_some_and(|c| c.trim().eq_ignore_ascii_case("CN"))
                {
                    if best_cn.is_none() {
                        best_cn = Some(res);
                    }
                } else if res.reachable && res.ip.is_some() {
                    if best_reachable.is_none() {
                        best_reachable = Some(res);
                    }
                } else if first_failed.is_none() {
                    first_failed = Some(res);
                }
            }
        }

        selected.or(best_cn).or(best_reachable).or(first_failed)
    } else {
        None
    };

    let mut installed_agents = Vec::new();
    for a in GUI_AGENTS {
        if !driver
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

type SnapshotStoreRef<'a> = crate::coordinator::SnapshotStore;

impl CoordinatorActor for RealEngineActor {
    fn on_event(&mut self, event: CoordinatorEvent, ctx: &CoordinatorContext<'_>) -> ActorControl {
        if self.burst_guard_ref.is_none() {
            self.burst_guard_ref = Some(ctx.burst_guard.clone());
        }
        if self.hook_metrics_ref.is_none() {
            self.hook_metrics_ref = Some(ctx.hook_metrics.clone());
        }
        match event {
            CoordinatorEvent::Pipe { req, reply } => {
                self.handle_pipe_request(req, reply, ctx.snapshot);
            }
            CoordinatorEvent::Tick => {
                let now = now_unix_secs();
                let _ = self.poll_wake_grace_expiry(now);
                self.step_and_run(EngineEvent::Tick, now);
                if self.feishu.status().queued > 0 {
                    self.spawn_feishu_flush_if_idle();
                }
                let _ = self.publish_snapshot(ctx.snapshot, now);
            }
            CoordinatorEvent::SystemResumed => {
                let now = now_unix_secs();
                self.wake_grace_until = Some(Instant::now() + WAKE_GRACE_DURATION);
                self.engine.notify_system_resumed(now);
                let _ = self.publish_snapshot(ctx.snapshot, now);

                if let Some(guard) = InFlightGuard::try_acquire(&self.wake_timer_active) {
                    let tx = self.event_tx.clone();
                    let _ = std::thread::Builder::new()
                        .name("cg-wake-grace".to_string())
                        .spawn(move || {
                            let _guard = guard;
                            std::thread::sleep(WAKE_GRACE_DURATION + Duration::from_millis(50));
                            let _ = tx.try_send(CoordinatorEvent::Tick);
                        });
                }
            }
            CoordinatorEvent::SystemShuttingDown => {
                let now = now_unix_secs();
                self.on_system_shutting_down(now);
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
            CoordinatorEvent::AntigravityAutoRepairFinished {
                result,
                now_secs,
                trigger_state,
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
                    self.engine.push_log(
                        now_secs,
                        LogLevel::Audit,
                        "antigravity",
                        &format!("自动补注入 version.dll（{:?}）：{summary}", trigger_state),
                    );
                    self.emit_notification("warning", "反重力注入已自动恢复", &summary, now_secs);
                    let _ = self.publish_snapshot(ctx.snapshot, now_secs);
                }
                Err(msg) => {
                    self.engine.push_log(
                        now_secs,
                        LogLevel::Warn,
                        "antigravity",
                        &format!(
                            "自动补注入 version.dll 未完成（{:?}）：{msg}",
                            trigger_state
                        ),
                    );
                    let _ = self.publish_snapshot(ctx.snapshot, now_secs);
                }
            },
            CoordinatorEvent::MihomoSwitchFinished {
                cfg_rev,
                runtime_epoch,
                result,
                mihomo,
                now_secs,
                reply,
            } => {
                self.mihomo = mihomo;
                let stale =
                    cfg_rev != self.engine.cfg_rev || runtime_epoch != self.engine.runtime_epoch;
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
                        if !stale {
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
                        } else {
                            self.engine.push_log(
                                now_secs,
                                LogLevel::Info,
                                "mihomo",
                                "节点切换期间守护代次或配置已变更，已跳过自动恢复触发",
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
                mut access,
                mut probes,
                now_secs,
            } => {
                if cg_platform::access_win::is_system_shutting_down() {
                    self.on_system_shutting_down(now_secs);
                }
                let _ = self.poll_wake_grace_expiry(now_secs);
                let accepted_round =
                    cfg_rev == self.engine.cfg_rev && runtime_epoch == self.engine.runtime_epoch;
                if accepted_round
                    && purpose != CheckPurpose::Launch
                    && !self.engine.is_tripped()
                    && self.in_wake_grace(now_secs)
                {
                    let access_enforced = self.engine.network_isolation_supported
                        && self.engine.config.enforce_access_path;
                    let would_fail_probe = self.engine.config.targets.iter().any(|t| {
                        if !t.enabled {
                            return false;
                        }
                        let probe = probes
                            .iter()
                            .find(|(id, _)| id == &t.id)
                            .map(|(_, p)| p.clone())
                            .unwrap_or_else(|| ProbeResult::failed("wake grace"));
                        policy::evaluate_with_preset(t, &probe, self.engine.config.preset).verdict
                            == crate::protocol::PolicyVerdict::Fail
                    });
                    if (access_enforced && access.is_uncovered()) || would_fail_probe {
                        access.level = AccessLevel::Unknown;
                        access.note = "系统唤醒网络重连宽限期内（20s），暂缓熔断与自动封锁".into();
                        for (_, p) in &mut probes {
                            *p = ProbeResult::failed("系统唤醒重连宽限期内，等待下一轮复检");
                        }
                    }
                }
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
                if cg_platform::access_win::is_system_shutting_down() {
                    self.on_system_shutting_down(bundle.now_secs);
                }
                let _ = self.poll_wake_grace_expiry(bundle.now_secs);
                self.resync_guarded_agents_on_path_change(&bundle.agents, bundle.now_secs);

                // H-07: Discard off-thread telemetry computed against a superseded cfg_rev or runtime_epoch
                // so stale proxy_port / leak scans never trigger false PortMismatch or false leak-trips.
                if bundle.cfg_rev != self.engine.cfg_rev
                    || bundle.runtime_epoch != self.engine.runtime_epoch
                {
                    if self.engine.system_shutting_down {
                        let _ = self.publish_snapshot(ctx.snapshot, bundle.now_secs);
                    }
                    return ActorControl::Continue;
                }

                self.cached_agents = bundle.agents;
                self.leak_shield = bundle.leak_shield;
                self.mihomo = bundle.mihomo;
                self.hooks = bundle.hooks;
                {
                    let mut bg = ctx.burst_guard.lock().unwrap_or_else(|e| e.into_inner());
                    bg.set_suspicious_oauth_processes(bundle.suspicious_oauth_processes);
                }
                self.step_and_run(
                    EngineEvent::WfpUpdated {
                        status: Box::new(bundle.wfp),
                    },
                    bundle.now_secs,
                );
                if let Some(risk) = bundle.risk_assessment {
                    self.step_and_run(
                        EngineEvent::RiskUpdated {
                            assessment: Box::new(risk),
                        },
                        bundle.now_secs,
                    );
                }
                let effective_leak = if self.in_wake_grace(bundle.now_secs) && bundle.leak.leaked()
                {
                    LeakReport::not_applicable(
                        "wake_grace",
                        "系统唤醒网络重连宽限期内（20s），暂缓直连泄露熔断",
                        bundle.now_secs,
                    )
                } else {
                    bundle.leak
                };
                self.step_and_run(
                    EngineEvent::LeakUpdated {
                        report: effective_leak,
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
                let mut self_check = bundle.self_check;
                if self.engine.wal_pending {
                    enrich_self_check_wal_error(
                        &mut self_check,
                        &self.journal,
                        self.last_wal_heal_error.as_deref(),
                    );
                }
                self.step_and_run(
                    EngineEvent::SelfCheckUpdated { self_check },
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
                    if self
                        .engine
                        .updates
                        .antigravity_proxy
                        .installed_version
                        .is_none()
                        && matches!(
                            self.engine.updates.antigravity_proxy.phase,
                            UpdateCheckPhase::UpToDate | UpdateCheckPhase::UpdateAvailable
                        )
                    {
                        self.engine.updates.antigravity_proxy.phase =
                            UpdateCheckPhase::NotInstalled;
                    }
                }
                if self.try_recover_wal_pending(bundle.now_secs, false)
                    && self.engine.lifecycle == Lifecycle::Armed
                {
                    self.step_and_run(
                        EngineEvent::StartRound {
                            purpose: CheckPurpose::Monitor,
                        },
                        bundle.now_secs,
                    );
                }
                if self.driver.capabilities().process_guard {
                    let procs = self.process_scanner.cached_snapshot();
                    self.refresh_live_vault_sessions(&procs);
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

                let incoming = *summary;
                let (check_cg, check_ag, normalized) =
                    parse_update_component_filter(component.as_deref())
                        .unwrap_or((true, true, None));
                let check_client = |id: &str| component_matches_filter(normalized.as_deref(), id);

                // H-07: Start from live `self.engine.updates` and merge ONLY slots actually checked in this job.
                let mut next_summary = self.engine.updates.clone();
                if incoming.claude_msix_version.is_some() {
                    next_summary.claude_msix_version = incoming.claude_msix_version.clone();
                }
                if incoming.codex_msix_version.is_some() {
                    next_summary.codex_msix_version = incoming.codex_msix_version.clone();
                }
                let merge_checked_slot = |checked: bool,
                                          dst: &mut ComponentUpdateStatus,
                                          inc: &ComponentUpdateStatus|
                 -> bool {
                    if !checked || inc.phase == UpdateCheckPhase::Idle || inc.checked_at.is_none() {
                        return false;
                    }
                    if dst
                        .checked_at
                        .is_none_or(|prev| inc.checked_at >= Some(prev))
                    {
                        *dst = inc.clone();
                    }
                    true
                };

                let did_cg = merge_checked_slot(
                    check_cg,
                    &mut next_summary.claudeguard,
                    &incoming.claudeguard,
                );
                let did_ag = merge_checked_slot(
                    check_ag,
                    &mut next_summary.antigravity_proxy,
                    &incoming.antigravity_proxy,
                );
                let did_cd = merge_checked_slot(
                    check_client("claude_desktop"),
                    &mut next_summary.claude_desktop,
                    &incoming.claude_desktop,
                );
                let did_cc = merge_checked_slot(
                    check_client("claude_code"),
                    &mut next_summary.claude_code,
                    &incoming.claude_code,
                );
                let did_cxd = merge_checked_slot(
                    check_client("codex_desktop"),
                    &mut next_summary.codex_desktop,
                    &incoming.codex_desktop,
                );
                let did_cxc = merge_checked_slot(
                    check_client("codex_cli"),
                    &mut next_summary.codex_cli,
                    &incoming.codex_cli,
                );
                let did_ide = merge_checked_slot(
                    check_client("antigravity_ide"),
                    &mut next_summary.antigravity_ide,
                    &incoming.antigravity_ide,
                );
                let did_cn = merge_checked_slot(
                    check_client("antigravity_cn"),
                    &mut next_summary.antigravity_cn,
                    &incoming.antigravity_cn,
                );
                let did_um = merge_checked_slot(
                    check_client("ag_usage_monitor"),
                    &mut next_summary.ag_usage_monitor,
                    &incoming.ag_usage_monitor,
                );
                let did_cap = merge_checked_slot(
                    check_client("ag_capsule"),
                    &mut next_summary.ag_capsule,
                    &incoming.ag_capsule,
                );
                let did_cursor = merge_checked_slot(
                    check_client("cursor_ide"),
                    &mut next_summary.cursor_ide,
                    &incoming.cursor_ide,
                );
                let did_windsurf = merge_checked_slot(
                    check_client("windsurf_ide"),
                    &mut next_summary.windsurf_ide,
                    &incoming.windsurf_ide,
                );
                let did_zed = merge_checked_slot(
                    check_client("zed_ide"),
                    &mut next_summary.zed_ide,
                    &incoming.zed_ide,
                );
                let did_trae = merge_checked_slot(
                    check_client("trae_ide"),
                    &mut next_summary.trae_ide,
                    &incoming.trae_ide,
                );

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
                    let mut ok_count = 0usize;
                    let mut failed_count = 0usize;
                    let mut failed_notes: Vec<String> = Vec::new();
                    let mut scope_parts = Vec::new();

                    let mut record_slot =
                        |key: &str, checked: bool, slot: &ComponentUpdateStatus| {
                            if !checked {
                                return;
                            }
                            let st = match slot.phase {
                                UpdateCheckPhase::Failed => {
                                    failed_count += 1;
                                    let note = slot.note.trim();
                                    let clean = if note.is_empty() {
                                        format!("{key} 检测失败")
                                    } else {
                                        note.to_string()
                                    };
                                    if !failed_notes.contains(&clean) {
                                        failed_notes.push(clean);
                                    }
                                    OperationStatus::Failed
                                }
                                UpdateCheckPhase::NotInstalled => OperationStatus::NotApplicable,
                                _ => {
                                    ok_count += 1;
                                    OperationStatus::Verified
                                }
                            };
                            scope_parts.push(format!("{key}={:?}", slot.phase));
                            receipt.push_item(key, st, slot.note.clone());
                        };

                    record_slot("claudeguard", did_cg, &next_summary.claudeguard);
                    record_slot("antigravity_proxy", did_ag, &next_summary.antigravity_proxy);
                    record_slot("claude_desktop", did_cd, &next_summary.claude_desktop);
                    record_slot("claude_code", did_cc, &next_summary.claude_code);
                    record_slot("codex_desktop", did_cxd, &next_summary.codex_desktop);
                    record_slot("codex_cli", did_cxc, &next_summary.codex_cli);
                    record_slot("antigravity_ide", did_ide, &next_summary.antigravity_ide);
                    record_slot("antigravity_cn", did_cn, &next_summary.antigravity_cn);
                    record_slot("ag_usage_monitor", did_um, &next_summary.ag_usage_monitor);
                    record_slot("ag_capsule", did_cap, &next_summary.ag_capsule);
                    record_slot("cursor_ide", did_cursor, &next_summary.cursor_ide);
                    record_slot("windsurf_ide", did_windsurf, &next_summary.windsurf_ide);
                    record_slot("zed_ide", did_zed, &next_summary.zed_ide);
                    record_slot("trae_ide", did_trae, &next_summary.trae_ide);

                    receipt.verified_scope = scope_parts.join(", ");
                    if failed_count == 0 {
                        receipt.status = OperationStatus::Verified;
                    } else if ok_count > 0 {
                        receipt.status = OperationStatus::Partial;
                        let brief = if failed_notes.len() <= 2 {
                            failed_notes.join("；")
                        } else {
                            format!("{} 等", failed_notes[..2].join("；"))
                        };
                        receipt.error = Some(format!(
                            "已完成 {ok_count} 项，{failed_count} 项检测失败：{brief}"
                        ));
                    } else {
                        receipt.status = OperationStatus::Failed;
                        let brief = if failed_notes.len() <= 2 {
                            failed_notes.join("；")
                        } else {
                            format!("{} 等", failed_notes[..2].join("；"))
                        };
                        receipt.error = Some(brief);
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
            CoordinatorEvent::DeepRiskAuditFinished {
                assessment,
                now_secs,
                reply,
            } => {
                let headline = assessment.headline.clone();
                let score = assessment.score;
                let grade = assessment.grade;
                self.step_and_run(EngineEvent::RiskUpdated { assessment }, now_secs);
                let mut receipt = OperationReceipt::new(
                    format!("deep-risk-audit-{now_secs}"),
                    OperationStatus::Verified,
                );
                receipt.verified_scope = format!("score={score}, grade={}", grade.code());
                receipt.push_item("risk_audit", OperationStatus::Verified, headline.clone());
                self.engine.push_log(
                    now_secs,
                    LogLevel::Audit,
                    "risk",
                    &format!(
                        "完成 10D 深度封号风险体检：{score}/100（{} 级）· {headline}",
                        grade.code()
                    ),
                );
                self.engine.last_receipt = Some(receipt.clone());
                let snap = self.publish_snapshot(ctx.snapshot, now_secs);
                if let Some(tx) = reply {
                    let _ = tx.send(PipeResponse::Ack {
                        receipt: Some(receipt),
                        snapshot: Some(Box::new(snap)),
                    });
                }
            }
            CoordinatorEvent::WslBridgeSynced {
                status,
                now_secs,
                reply,
            } => {
                let summary = status.summary.clone();
                self.wsl_bridge = *status;
                let mut receipt = OperationReceipt::new(
                    format!("wsl-sync-{now_secs}"),
                    OperationStatus::Verified,
                );
                receipt.verified_scope = "wsl_bridge".into();
                receipt.push_item("wsl_bridge", OperationStatus::Verified, summary.clone());
                self.engine
                    .push_log(now_secs, LogLevel::Audit, "wsl", &summary);
                self.engine.last_receipt = Some(receipt.clone());
                let snap = self.publish_snapshot(ctx.snapshot, now_secs);
                if let Some(tx) = reply {
                    let _ = tx.send(PipeResponse::Ack {
                        receipt: Some(receipt),
                        snapshot: Some(Box::new(snap)),
                    });
                }
            }
            CoordinatorEvent::UpdateWslBridgeStatus { status } => {
                self.wsl_bridge = *status;
                let _ = self.publish_snapshot(ctx.snapshot, now_unix_secs());
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

fn enrich_self_check_wal_error(
    self_check: &mut DefenseSelfCheck,
    journal: &JournalStore,
    wal_heal_error: Option<&str>,
) {
    let Some(err) = wal_heal_error.map(str::trim).filter(|s| !s.is_empty()) else {
        return;
    };
    match journal.load() {
        LoadedJournal::NotFound => {
            self_check.wal_clean = false;
            if let Some(item) = self_check.items.iter_mut().find(|i| i.id == "wal_journal") {
                item.status = SelfCheckStatus::Degraded;
                item.detail = format!("启动恢复核验未完成：{err}");
            }
        }
        LoadedJournal::Uncommitted(_) | LoadedJournal::Committed(_) => {
            self_check.wal_clean = false;
            if let Some(item) = self_check.items.iter_mut().find(|i| i.id == "wal_journal") {
                item.status = SelfCheckStatus::Degraded;
                if !item.detail.contains(err) {
                    item.detail = format!("{}（{err}）", item.detail);
                }
            }
        }
        LoadedJournal::Corrupt(_) | LoadedJournal::Unreadable(_) => {}
    }
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

/// Exponential backoff between repeated automatic re-injections (30s doubling, 10 min cap).
fn auto_repair_backoff_secs(failures: u32) -> u64 {
    (30u64 << failures.min(5)).min(600)
}

/// True when the on-disk injection is broken in a way that a re-injection can fix.
fn needs_auto_antigravity_repair(status: &AntigravityProxyStatus) -> bool {
    status.installed
        && matches!(
            status.state,
            AntigravityProxyState::MissingDll
                | AntigravityProxyState::MissingOrInvalidConfig
                | AntigravityProxyState::PortMismatch
        )
}

/// Scheduling state for the automatic `version.dll` re-injection.
#[derive(Default)]
struct AutoRepairBudget {
    next_attempt: Option<Instant>,
    failures: u32,
}

impl AutoRepairBudget {
    fn due(&self, now: Instant) -> bool {
        self.next_attempt.is_none_or(|t| now >= t)
    }

    fn record_attempt(&mut self, now: Instant) {
        self.failures = self.failures.saturating_add(1);
        self.next_attempt =
            Some(now + Duration::from_secs(auto_repair_backoff_secs(self.failures)));
    }

    fn reset(&mut self) {
        self.next_attempt = None;
        self.failures = 0;
    }
}

/// Keeps `version.dll` injection alive across Antigravity self-updates: when the monitor tick
/// observes a broken injection it re-installs a previously verified DLL (cache first, release
/// download as fallback) without a pipe request. Failures back off exponentially.
#[allow(clippy::too_many_arguments)]
fn schedule_auto_antigravity_repair(
    driver: &dyn PlatformDriver,
    snap: &GuardSnapshot,
    status: &AntigravityProxyStatus,
    budget: &Arc<Mutex<AutoRepairBudget>>,
    in_flight: &Arc<AtomicBool>,
    coordinator: &CoordinatorHandle,
    cache_dir: &std::path::Path,
    now: u64,
) {
    let mut slot = match budget.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };

    if !snap.config.auto_repair_antigravity_proxy || !needs_auto_antigravity_repair(status) {
        slot.reset();
        return;
    }
    if snap.lifecycle != Lifecycle::Armed
        || snap.protection != ProtectionState::Monitoring
        || snap.tripped.is_some()
    {
        return;
    }
    if !slot.due(Instant::now()) {
        return;
    }

    let (_access, route) = resolve_access_and_route(
        driver,
        &snap.config,
        snap.cfg_rev,
        &snap.config.targets,
        snap.config.enforce_access_path,
        now,
    );
    if matches!(route, ProbeRoute::Skip(_)) {
        return;
    }
    if in_flight
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }

    slot.record_attempt(Instant::now());
    let proxy_port = snap.config.proxy_port;
    let explicit_dir = status.antigravity_dir.as_ref().map(PathBuf::from);
    let trigger_state = status.state;
    let cache = cache_dir.to_path_buf();
    let tx = coordinator.event_sender();
    let flag = in_flight.clone();
    drop(slot);

    struct ResetInFlight(Arc<AtomicBool>);
    impl Drop for ResetInFlight {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }

    let _ = std::thread::Builder::new()
        .name("cg-ag-auto-repair".to_string())
        .spawn(move || {
            let _guard = ResetInFlight(flag);
            let result = antigravity_proxy_win::repair_antigravity_proxy_cached(
                &route,
                proxy_port,
                explicit_dir.as_deref(),
                &cache,
            )
            .map(|r| r.summary);
            let _ = tx.try_send(CoordinatorEvent::AntigravityAutoRepairFinished {
                result,
                now_secs: now_unix_secs(),
                trigger_state,
            });
        });
}

fn has_any_failed_update_slot(u: &UpdateSummary) -> bool {
    [
        &u.claudeguard,
        &u.antigravity_proxy,
        &u.claude_desktop,
        &u.claude_code,
        &u.codex_desktop,
        &u.codex_cli,
        &u.antigravity_ide,
        &u.antigravity_cn,
        &u.ag_usage_monitor,
        &u.ag_capsule,
        &u.cursor_ide,
        &u.windsurf_ide,
        &u.zed_ide,
        &u.trae_ide,
    ]
    .into_iter()
    .any(|slot| slot.phase == UpdateCheckPhase::Failed)
}

fn compute_leak_report(
    driver: &dyn PlatformDriver,
    snap: &GuardSnapshot,
    pid_map: &HashMap<u32, String>,
    access_info: &access_win::AccessInfo,
    now: u64,
) -> LeakReport {
    if !snap.config.leak_watch {
        return LeakReport::not_applicable(&access_info.path, "直连泄露观察已关闭", now);
    }
    if snap.access.tun_iface.is_some() {
        return LeakReport::not_applicable(
            "tun",
            "检测到 TUN 网卡同时在线，公网流量由虚拟网卡接管",
            now,
        );
    }
    if !driver.capabilities().leak_watch {
        return LeakReport::not_applicable("unsupported", "当前平台不支持直连观察", now);
    }
    let active_proxy_port = snap
        .access
        .proxy_addr
        .as_deref()
        .and_then(|addr| addr.rsplit_once(':'))
        .and_then(|(_, p)| p.trim_end_matches('/').parse::<u16>().ok())
        .filter(|&p| p > 0)
        .unwrap_or(snap.config.proxy_port);
    let conns = driver.scan_tcp_connections().unwrap_or_default();
    netwatch_win::fold(&conns, pid_map, active_proxy_port, access_info, now)
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
        egress_ledger: Arc<EgressLedger>,
        data_dir: PathBuf,
        enable_initial_tick: bool,
    ) -> Self {
        Self::start_with_intervals(
            coordinator,
            driver,
            process_scanner,
            egress_ledger,
            data_dir,
            enable_initial_tick,
            DEFAULT_TELEMETRY_INTERVAL,
            AUTO_UPDATE_CHECK_INTERVAL,
        )
    }

    /// Spawns the background scheduler + telemetry loop with configurable intervals (also used in tests).
    #[allow(clippy::too_many_arguments)]
    pub fn start_with_intervals(
        coordinator: CoordinatorHandle,
        driver: Arc<dyn PlatformDriver>,
        process_scanner: Arc<ProcessScanner>,
        egress_ledger: Arc<EgressLedger>,
        data_dir: PathBuf,
        enable_initial_tick: bool,
        telemetry_interval: Duration,
        update_check_interval: Duration,
    ) -> Self {
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_signal = Arc::new((Mutex::new(false), Condvar::new()));

        let t_flag = stop_flag.clone();
        let t_sig = stop_signal.clone();
        let ag_cache_dir = data_dir.join("antigravity-proxy");
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
                let mut last_telemetry: Option<Instant> = None;
                let last_upd_check: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));
                let auto_upd_in_flight = Arc::new(AtomicBool::new(false));
                let bg_risk_in_flight = Arc::new(AtomicBool::new(false));
                let mut last_risk_audit: Option<Instant> = None;
                let mut last_risk_ip: Option<String> = None;
                let ag_auto_repair: Arc<Mutex<AutoRepairBudget>> =
                    Arc::new(Mutex::new(AutoRepairBudget::default()));
                let ag_auto_repair_in_flight = Arc::new(AtomicBool::new(false));
                let mut desktop_gone_since: Option<Instant> = None;

                while !t_flag.load(Ordering::Acquire) {
                    let snap = coordinator.snapshot();
                    let interval = Duration::from_secs(snap.config.clamped_interval_secs());

                    if last_tick.elapsed() >= interval {
                        coordinator.try_tick();
                        last_tick = Instant::now();
                    }

                    if last_telemetry.is_none_or(|t| t.elapsed() >= telemetry_interval) {
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
                        let leak =
                            compute_leak_report(&*driver, &snap, &pid_map, &access_info, now);

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

                        let leak_shield = if driver.capabilities().app_quarantine
                            && fw_query_ok
                            && (!fw_rules.is_empty() || snap.leak_shield.enabled)
                        {
                            leak_shield_win::inspect_leak_shield()
                        } else {
                            LeakShieldStatus::default()
                        };
                        let mihomo = mihomo_win::inspect_mihomo();
                        let wfp = driver.wfp_status();
                        let (checks, blocks, latency_us) = coordinator.hook_gate_metrics();
                        let hooks = hook_installer::inspect_hook_status(
                            &snap.config.vaults,
                            checks,
                            blocks,
                            latency_us,
                        );
                        let suspicious_oauth_processes = Vec::new();

                        coordinator.try_send_telemetry(TelemetryBundle {
                            cfg_rev: snap.cfg_rev,
                            runtime_epoch: snap.runtime_epoch,
                            agents,
                            leak,
                            leak_shield,
                            mihomo,
                            env,
                            antigravity_proxy: antigravity_proxy.clone(),
                            self_check,
                            updates: Some(local_updates.clone()),
                            wfp,
                            risk_assessment: None,
                            hooks,
                            suspicious_oauth_processes,
                            now_secs: now,
                        });

                        // Periodic off-thread 10D risk assessment refresh (every 5m or when primary egress IP changes).
                        let (cur_ip, _, _) = current_primary_egress(&snap);
                        let ip_changed = cur_ip.is_some() && cur_ip != last_risk_ip;
                        let risk_due = ip_changed
                            || last_risk_audit
                                .is_none_or(|t| t.elapsed() >= Duration::from_secs(300));
                        if snap.lifecycle == Lifecycle::Armed
                            && snap.protection == ProtectionState::Monitoring
                            && snap.all_enabled_pass()
                            && driver.capabilities().access_path_inspection
                            && risk_due
                            && bg_risk_in_flight
                                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                                .is_ok()
                        {
                            last_risk_audit = Some(Instant::now());
                            last_risk_ip = cur_ip;
                            let r_driver = driver.clone();
                            let r_snap = snap.clone();
                            let r_ledger = egress_ledger.clone();
                            let r_electron_pids = collect_electron_agent_pids(&procs);
                            let r_tx = coordinator.event_sender();
                            let r_flag = bg_risk_in_flight.clone();
                            let r_stop = t_flag.clone();
                            let _ = std::thread::Builder::new()
                                .name("cg-bg-risk-audit".to_string())
                                .spawn(move || {
                                    struct ResetRisk(Arc<AtomicBool>);
                                    impl Drop for ResetRisk {
                                        fn drop(&mut self) {
                                            self.0.store(false, Ordering::Release);
                                        }
                                    }
                                    let _guard = ResetRisk(r_flag);
                                    let assessment = compute_deep_risk_assessment(
                                        &*r_driver,
                                        &r_snap,
                                        &r_ledger,
                                        &r_electron_pids,
                                        true,
                                        now_unix_secs(),
                                    );
                                    if !r_stop.load(Ordering::Acquire) {
                                        let _ = r_tx.try_send(
                                            CoordinatorEvent::DeepRiskAuditFinished {
                                                assessment: Box::new(assessment),
                                                now_secs: now_unix_secs(),
                                                reply: None,
                                            },
                                        );
                                    }
                                });
                        }

                        let effective_upd_interval = if has_any_failed_update_slot(&snap.updates) {
                            AUTO_UPDATE_RETRY_INTERVAL.min(update_check_interval)
                        } else {
                            update_check_interval
                        };
                        let upd_due = last_upd_check.lock().ok().is_some_and(|g| {
                            g.is_none_or(|t| t.elapsed() >= effective_upd_interval)
                        });

                        if snap.config.auto_upd_check
                            && snap.lifecycle == Lifecycle::Armed
                            && snap.protection == ProtectionState::Monitoring
                            && snap.all_enabled_pass()
                            && upd_due
                            && !auto_upd_in_flight.load(Ordering::Acquire)
                        {
                            let (_access, route) = resolve_access_and_route(
                                &*driver,
                                &snap.config,
                                snap.cfg_rev,
                                &snap.config.targets,
                                snap.config.enforce_access_path,
                                now,
                            );
                            if !matches!(route, ProbeRoute::Skip(_))
                                && auto_upd_in_flight
                                    .compare_exchange(
                                        false,
                                        true,
                                        Ordering::AcqRel,
                                        Ordering::Acquire,
                                    )
                                    .is_ok()
                            {
                                let bg_driver = driver.clone();
                                let bg_tx = coordinator.event_sender();
                                let bg_ver = snap.version.clone();
                                let bg_ag = antigravity_proxy.clone();
                                let bg_prev = local_updates.clone();
                                let bg_in_flight = auto_upd_in_flight.clone();
                                let bg_last = last_upd_check.clone();
                                let bg_stop = t_flag.clone();
                                let _ = std::thread::Builder::new()
                                    .name("cg-auto-update".to_string())
                                    .spawn(move || {
                                        struct ResetInFlight(Arc<AtomicBool>);
                                        impl Drop for ResetInFlight {
                                            fn drop(&mut self) {
                                                self.0.store(false, Ordering::Release);
                                            }
                                        }
                                        let _guard = ResetInFlight(bg_in_flight);
                                        let checked = bg_driver.check_updates(
                                            &route, &bg_ver, &bg_ag, None, &bg_prev, now,
                                        );
                                        if let Ok(mut g) = bg_last.lock() {
                                            *g = Some(Instant::now());
                                        }
                                        if !bg_stop.load(Ordering::Acquire) {
                                            let _ =
                                                bg_tx.try_send(CoordinatorEvent::UpdatesChecked {
                                                    summary: Box::new(checked),
                                                    component: None,
                                                    now_secs: now_unix_secs(),
                                                    reply: None,
                                                });
                                        }
                                    });
                            }
                        }

                        schedule_auto_antigravity_repair(
                            &*driver,
                            &snap,
                            &antigravity_proxy,
                            &ag_auto_repair,
                            &ag_auto_repair_in_flight,
                            &coordinator,
                            &ag_cache_dir,
                            now,
                        );

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

                        last_telemetry = Some(Instant::now());
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
            .ok();

        Self {
            stop_flag,
            stop_signal,
            thread: Mutex::new(thread),
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
    use crate::protocol::{AntigravityProxyState, EnvCheck, WfpStatus};
    use cg_platform::netwatch_win::TcpConn;
    use cg_platform::process_win::{LaunchTarget, ProcessIdentity, SweepReport};
    use cg_platform::{
        Coverage, FirewallEngine, FirewallProfileStatus, FirewallRuleRecord, FirewallRuleSpec,
        PlatformCapabilities, PlatformResult, RemoveReport, UnsupportedPlatformDriver,
    };
    use cg_protocol::EnvInfo;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn auto_repair_targets_only_recoverable_states() {
        let mut st = AntigravityProxyStatus {
            installed: true,
            ..Default::default()
        };
        for state in [
            AntigravityProxyState::MissingDll,
            AntigravityProxyState::MissingOrInvalidConfig,
            AntigravityProxyState::PortMismatch,
        ] {
            st.state = state;
            assert!(
                needs_auto_antigravity_repair(&st),
                "{state:?} must be auto-repairable"
            );
        }
        for state in [
            AntigravityProxyState::Healthy,
            AntigravityProxyState::RuntimeUnhooked,
            AntigravityProxyState::NotInstalled,
        ] {
            st.state = state;
            assert!(
                !needs_auto_antigravity_repair(&st),
                "{state:?} must not trigger a repair"
            );
        }
        st.state = AntigravityProxyState::MissingDll;
        st.installed = false;
        assert!(!needs_auto_antigravity_repair(&st));
    }

    #[test]
    fn auto_repair_backoff_grows_then_caps() {
        let secs: Vec<u64> = (0..8).map(auto_repair_backoff_secs).collect();
        assert_eq!(secs, vec![30, 60, 120, 240, 480, 600, 600, 600]);

        let start = Instant::now();
        let mut budget = AutoRepairBudget::default();
        assert!(budget.due(start));
        budget.record_attempt(start);
        assert!(!budget.due(start));
        // First failure waits 30s * 2 = 60s; the guard is checked again after that.
        assert!(!budget.due(start + Duration::from_secs(59)));
        assert!(budget.due(start + Duration::from_secs(61)));
        budget.record_attempt(start);
        assert!(!budget.due(start + Duration::from_secs(119)));
        assert!(budget.due(start + Duration::from_secs(121)));
        budget.reset();
        assert!(budget.due(start));
    }

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
        allow_launch: AtomicBool,
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
                allow_launch: AtomicBool::new(false),
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
            if self.allow_launch.load(Ordering::Acquire) {
                Ok(())
            } else {
                self.fallback.launch_app_normal_privilege(target)
            }
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

    fn noop_shield_syncer() -> LeakShieldSyncFn {
        Arc::new(|exes, quic, dns, ipv6| {
            let active_rules =
                exes.len() * (usize::from(quic) + usize::from(dns) * 3 + usize::from(ipv6));
            Ok(LeakShieldStatus {
                enabled: active_rules > 0,
                quic_blocked: quic && active_rules > 0,
                dns_doh_blocked: dns && active_rules > 0,
                ipv6_blocked: ipv6 && active_rules > 0,
                active_rules,
                summary: format!("mock shield ({active_rules})"),
            })
        })
    }

    fn boot_actor(
        dir: &std::path::Path,
        driver: Arc<dyn PlatformDriver>,
        runner: Arc<dyn ProbeRunner>,
        recovery: Arc<dyn RecoveryExecutor>,
    ) -> CoordinatorHandle {
        let data_dir = dir.to_path_buf();
        let syncer = noop_shield_syncer();
        let (handle, _) = start_coordinator_with(|event_tx| {
            let boot = RealEngineActor::bootstrap_with_syncer(
                data_dir, driver, runner, recovery, event_tx, syncer,
            );
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
        let cur_snap = coord.snapshot();
        coord.try_send_telemetry(TelemetryBundle {
            cfg_rev: cur_snap.cfg_rev,
            runtime_epoch: cur_snap.runtime_epoch,
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
            wfp: WfpStatus::default(),
            risk_assessment: None,
            hooks: HookIntegrationStatus::default(),
            suspicious_oauth_processes: Vec::new(),
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
        let cur_snap2 = coord.snapshot();
        coord.try_send_telemetry(TelemetryBundle {
            cfg_rev: cur_snap2.cfg_rev,
            runtime_epoch: cur_snap2.runtime_epoch,
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
            wfp: WfpStatus::default(),
            risk_assessment: None,
            hooks: HookIntegrationStatus::default(),
            suspicious_oauth_processes: Vec::new(),
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

        // M-04: Reject SweepOrphans and ForceKillAgent while Unconfigured.
        match coord.dispatch(PipeRequest::SweepOrphans) {
            PipeResponse::Error { code, .. } => assert_eq!(code, ErrorCode::IllegalState),
            other => panic!("expected IllegalState in Unconfigured, got {other:?}"),
        }
        match coord.dispatch(PipeRequest::ForceKillAgent {
            agent_id: None,
            include_cli: true,
        }) {
            PipeResponse::Error { code, .. } => assert_eq!(code, ErrorCode::IllegalState),
            other => panic!("expected IllegalState in Unconfigured, got {other:?}"),
        }
        assert_eq!(driver.sweep_all_calls.load(Ordering::Acquire), 0);

        assert!(matches!(
            coord.dispatch(PipeRequest::CompleteOnboarding {
                config: make_cfg("US")
            }),
            PipeResponse::Ack { .. }
        ));

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

        let cur_snap = coord.snapshot();
        coord.try_send_telemetry(TelemetryBundle {
            cfg_rev: cur_snap.cfg_rev,
            runtime_epoch: cur_snap.runtime_epoch,
            agents,
            leak: LeakReport::not_applicable("mock", "mock", 1_700_000_500),
            leak_shield: LeakShieldStatus::default(),
            mihomo: MihomoStatus::default(),
            env: EnvCheck::default(),
            antigravity_proxy: healthy_ag.clone(),
            self_check,
            updates: None,
            wfp: WfpStatus::default(),
            risk_assessment: None,
            hooks: HookIntegrationStatus::default(),
            suspicious_oauth_processes: Vec::new(),
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
        let tel_now = now_unix_secs();
        let sc = build_defense_self_check(
            &coord.snapshot().config,
            &*driver,
            &journal,
            true,
            &AntigravityProxyStatus::default(),
            tel_now,
        );
        let msix_only = UpdateSummary {
            claude_msix_version: Some("1.2.3.4".into()),
            codex_msix_version: Some("26.1.2.3".into()),
            ..Default::default()
        };
        let cur_snap = coord.snapshot();
        coord.try_send_telemetry(TelemetryBundle {
            cfg_rev: cur_snap.cfg_rev,
            runtime_epoch: cur_snap.runtime_epoch,
            agents: Vec::new(),
            leak: LeakReport::not_applicable("mock", "mock", tel_now),
            leak_shield: LeakShieldStatus::default(),
            mihomo: MihomoStatus::default(),
            env: EnvCheck::default(),
            antigravity_proxy: AntigravityProxyStatus::default(),
            self_check: sc,
            updates: Some(msix_only),
            wfp: WfpStatus::default(),
            risk_assessment: None,
            hooks: HookIntegrationStatus::default(),
            suspicious_oauth_processes: Vec::new(),
            now_secs: tel_now,
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
        let (coord, egress_ledger) = start_coordinator_with(|event_tx| {
            let boot = RealEngineActor::bootstrap(data_dir, drv_clone, runner, recovery, event_tx);
            (
                boot.initial_snapshot,
                Box::new(boot.actor),
                boot.egress_ledger,
            )
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
            egress_ledger,
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

    #[test]
    fn monitor_only_prevents_killing_antigravity_through_coordinator() {
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
        let coord = boot_actor(dir.path(), driver.clone(), runner, recovery);

        let mut cfg = make_cfg("US");
        cfg.monitor_only = true;
        cfg.guarded_agents = vec!["claude".into(), "chatgpt".into(), "antigravity".into()];
        assert!(matches!(
            coord.dispatch(PipeRequest::CompleteOnboarding { config: cfg }),
            PipeResponse::Ack { .. }
        ));

        // Flip to non-compliant CN IP and recheck -> must NOT isolate or kill in monitor_only mode.
        pass.store(false, Ordering::Release);
        assert!(matches!(
            coord.dispatch(PipeRequest::RecheckNow { target_id: None }),
            PipeResponse::Ack { .. }
        ));
        let snap = coord.snapshot();
        assert_eq!(snap.protection, ProtectionState::Monitoring);
        assert!(snap.tripped.is_none());
        assert!(driver.gui_killed_calls.lock().unwrap().is_empty());
        assert!(snap.launch_error.contains("仅监测"));

        coord.shutdown();
    }

    #[test]
    fn resolve_access_and_route_honors_tun_and_custom_system_proxy_even_when_unforced() {
        let driver = ControllableDriver::new();
        let mut cfg = make_cfg("US");
        cfg.enforce_access_path = false;
        cfg.proxy_host = "127.0.0.1".into();
        cfg.proxy_port = 7890;

        // 1. TUN active while enforce_access_path == false -> ProbeRoute::Direct (never dead 7890).
        *driver.access_path_override.lock().unwrap() = Some(AccessPath::Tun {
            adapter: "MihomoTun".into(),
        });
        let (ev_tun, route_tun) =
            resolve_access_and_route(&driver, &cfg, 1, &cfg.targets, false, 1_700_000_000);
        assert_eq!(ev_tun.level, AccessLevel::Tun);
        assert_eq!(route_tun, ProbeRoute::Direct);

        // 2. SystemProxy on custom port 10809 while enforce_access_path == false -> ProbeRoute::Proxy(10809).
        *driver.access_path_override.lock().unwrap() = Some(AccessPath::SystemProxy {
            addr: "127.0.0.1:10809".into(),
        });
        let (ev_px, route_px) =
            resolve_access_and_route(&driver, &cfg, 1, &cfg.targets, false, 1_700_000_000);
        assert_eq!(ev_px.level, AccessLevel::SystemProxy);
        assert_eq!(route_px, ProbeRoute::Proxy("http://127.0.0.1:10809".into()));

        // 3. Uncovered + !enforce_access_path -> falls back to configured proxy 7890.
        *driver.access_path_override.lock().unwrap() = Some(AccessPath::Uncovered);
        let (_ev_unc, route_unc) =
            resolve_access_and_route(&driver, &cfg, 1, &cfg.targets, false, 1_700_000_000);
        assert_eq!(route_unc, ProbeRoute::Proxy("http://127.0.0.1:7890".into()));

        // 4. Uncovered + enforce_access_path -> fails closed with ProbeRoute::Skip.
        let (_ev_skip, route_skip) =
            resolve_access_and_route(&driver, &cfg, 1, &cfg.targets, true, 1_700_000_000);
        assert!(matches!(route_skip, ProbeRoute::Skip(_)));

        // 5. UnsupportedPlatformDriver falls back to configured proxy when !enforce_access_path.
        let unsupported = UnsupportedPlatformDriver::default();
        let (_ev_u, route_u) =
            resolve_access_and_route(&unsupported, &cfg, 1, &cfg.targets, false, 1_700_000_000);
        assert_eq!(route_u, ProbeRoute::Proxy("http://127.0.0.1:7890".into()));
    }

    #[test]
    fn leak_report_honors_disabled_flag_tun_coexistence_and_active_proxy_port() {
        struct LeakTestDriver {
            inner: ControllableDriver,
            scans: AtomicUsize,
            conns: Vec<TcpConn>,
        }
        impl PlatformDriver for LeakTestDriver {
            fn capabilities(&self) -> PlatformCapabilities {
                let mut c = self.inner.capabilities();
                c.leak_watch = true;
                c
            }
            fn firewall(&self) -> &dyn FirewallEngine {
                self.inner.firewall()
            }
            fn is_elevated(&self) -> PlatformResult<bool> {
                Ok(true)
            }
            fn read_access_evidence(&self) -> PlatformResult<access_win::AccessEvidenceRaw> {
                self.inner.read_access_evidence()
            }
            fn detect_tun_adapter(&self) -> PlatformResult<Option<String>> {
                self.inner.detect_tun_adapter()
            }
            fn inspect_access_path(
                &self,
                hosts: &[String],
            ) -> PlatformResult<(AccessPath, access_win::AccessInfo)> {
                self.inner.inspect_access_path(hosts)
            }
            fn scan_tcp_connections(&self) -> PlatformResult<Vec<TcpConn>> {
                self.scans.fetch_add(1, Ordering::AcqRel);
                Ok(self.conns.clone())
            }
            fn discover_agent_exes(&self, id: &str) -> PlatformResult<Vec<PathBuf>> {
                self.inner.discover_agent_exes(id)
            }
            fn discover_cli_exes(&self, id: &str) -> PlatformResult<Vec<PathBuf>> {
                self.inner.discover_cli_exes(id)
            }
            fn kill_gui_agent(&self, id: &str) -> PlatformResult<Vec<ProcessIdentity>> {
                self.inner.kill_gui_agent(id)
            }
            fn kill_cli_agent(&self, id: &str) -> PlatformResult<Vec<ProcessIdentity>> {
                self.inner.kill_cli_agent(id)
            }
            fn check_updates(
                &self,
                r: &ProbeRoute,
                v: &str,
                ag: &AntigravityProxyStatus,
                c: Option<&str>,
                p: &UpdateSummary,
                n: u64,
            ) -> UpdateSummary {
                self.inner.check_updates(r, v, ag, c, p, n)
            }
            fn sweep_claude(&self, m: SweepMode) -> PlatformResult<SweepReport> {
                self.inner.sweep_claude(m)
            }
            fn sweep_all_orphans(&self) -> PlatformResult<SweepReport> {
                self.inner.sweep_all_orphans()
            }
            fn inspect_antigravity_proxy(
                &self,
                port: u16,
                ver: Option<&str>,
                s: &CachedProcessSnapshot,
                n: u64,
            ) -> AntigravityProxyStatus {
                self.inner.inspect_antigravity_proxy(port, ver, s, n)
            }
            fn launch_app_normal_privilege(&self, t: &LaunchTarget) -> PlatformResult<()> {
                self.inner.launch_app_normal_privilege(t)
            }
            fn send_toast(&self, t: &str, b: &str) -> PlatformResult<()> {
                self.inner.send_toast(t, b)
            }
            fn protect_secret(&self, p: &[u8]) -> PlatformResult<Vec<u8>> {
                self.inner.protect_secret(p)
            }
            fn unprotect_secret(&self, c: &[u8]) -> PlatformResult<Vec<u8>> {
                self.inner.unprotect_secret(c)
            }
            fn read_env_info(&self) -> PlatformResult<EnvInfo> {
                self.inner.read_env_info()
            }
            fn read_default_location(&self) -> PlatformResult<(Option<String>, Option<String>)> {
                self.inner.read_default_location()
            }
            fn write_default_location(&self, lat: &str, lon: &str) -> PlatformResult<()> {
                self.inner.write_default_location(lat, lon)
            }
            fn delete_default_location(&self) -> PlatformResult<()> {
                self.inner.delete_default_location()
            }
        }

        let drv = LeakTestDriver {
            inner: ControllableDriver::new(),
            scans: AtomicUsize::new(0),
            conns: vec![TcpConn {
                pid: 4242,
                remote: "127.0.0.1".parse().unwrap(),
                port: 10809,
            }],
        };
        let pid_map = HashMap::from([(4242u32, "claude".to_string())]);
        let mut snap = GuardSnapshot::default();
        snap.config.proxy_port = 7890;
        snap.access.level = AccessLevel::SystemProxy;
        snap.access.proxy_addr = Some("127.0.0.1:10809".into());

        // 1. leak_watch == false -> skips scan_tcp_connections completely!
        snap.config.leak_watch = false;
        let info = access_win::AccessInfo::from(&snap.access);
        let r_off = compute_leak_report(&drv, &snap, &pid_map, &info, 1000);
        assert!(r_off.note.contains("直连泄露观察已关闭"));
        assert_eq!(drv.scans.load(Ordering::Acquire), 0);

        // 2. SystemProxy + TUN coexistence -> not_applicable without scanning TCP!
        snap.config.leak_watch = true;
        snap.access.tun_iface = Some("Mihomo".into());
        let r_tun = compute_leak_report(&drv, &snap, &pid_map, &info, 1001);
        assert!(r_tun.note.contains("TUN 网卡同时在线"));
        assert_eq!(drv.scans.load(Ordering::Acquire), 0);

        // 3. Pure SystemProxy on custom port 10809 -> active proxy port honored as proxied!
        snap.access.tun_iface = None;
        let info_px = access_win::AccessInfo::from(&snap.access);
        let r_px = compute_leak_report(&drv, &snap, &pid_map, &info_px, 1002);
        assert_eq!(drv.scans.load(Ordering::Acquire), 1);
        assert_eq!(r_px.proxied, 1);
        assert_eq!(r_px.direct_total, 0);
    }

    #[test]
    fn merge_slot_clears_uninstalled_clients_and_updates_checked_emits_partial_status() {
        let mut slot = ComponentUpdateStatus {
            id: "codex_cli".into(),
            name: "Codex CLI".into(),
            ..ComponentUpdateStatus::default()
        };
        slot.installed_version = Some("0.11.0".into());
        slot.latest_version = Some("0.12.0".into());
        slot.phase = UpdateCheckPhase::UpdateAvailable;
        slot.checked_at = Some(100);

        let mut incoming_uninstalled = slot.clone();
        incoming_uninstalled.installed_version = None;
        merge_slot(&mut slot, incoming_uninstalled);
        assert!(slot.installed_version.is_none());
        assert_eq!(slot.phase, UpdateCheckPhase::NotInstalled);

        // ClaudeGuard itself preserves phase even if telemetry incoming has None installed_version.
        let mut cg_slot = ComponentUpdateStatus {
            id: "claudeguard".into(),
            name: "ClaudeGuard".into(),
            ..ComponentUpdateStatus::default()
        };
        cg_slot.installed_version = Some("4.0.0".into());
        cg_slot.latest_version = Some("4.1.0".into());
        cg_slot.phase = UpdateCheckPhase::UpdateAvailable;
        cg_slot.checked_at = Some(100);
        merge_slot(
            &mut cg_slot,
            ComponentUpdateStatus {
                id: "claudeguard".into(),
                name: "ClaudeGuard".into(),
                ..ComponentUpdateStatus::default()
            },
        );
        assert_eq!(cg_slot.phase, UpdateCheckPhase::UpdateAvailable);

        // CoordinatorEvent::UpdatesChecked returns Partial when some slots pass and some fail.
        let dir = tempfile::tempdir().unwrap();
        let driver = Arc::new(ControllableDriver::new());
        *driver.update_fn.lock().unwrap() =
            Some(Box::new(|_route, cg_ver, _ag, _comp, prev, now_secs| {
                let mut next = prev.clone();
                next.claudeguard.phase = UpdateCheckPhase::UpToDate;
                next.claudeguard.installed_version = Some(cg_ver.to_string());
                next.claudeguard.latest_version = Some(cg_ver.to_string());
                next.claudeguard.checked_at = Some(now_secs);
                next.claude_code.phase = UpdateCheckPhase::Failed;
                next.claude_code.checked_at = Some(now_secs);
                next.claude_code.note = "GitHub API 限流".into();
                next.codex_cli.phase = UpdateCheckPhase::Failed;
                next.codex_cli.checked_at = Some(now_secs);
                next.codex_cli.note = "GitHub API 限流".into();
                next
            }));
        let runner = Arc::new(DelayedProbeRunner {
            gate_tx: None,
            release_rx: None,
            pass: Arc::new(AtomicBool::new(true)),
            ip_on_pass: "198.51.100.98".into(),
        });
        let recovery = Arc::new(MockRecoveryExecutor::new(MockRecoveryState::default()));
        let coord = boot_actor(dir.path(), driver, runner, recovery);
        assert!(matches!(
            coord.dispatch(PipeRequest::CompleteOnboarding {
                config: make_cfg("US")
            }),
            PipeResponse::Ack { .. }
        ));

        match coord.dispatch(PipeRequest::CheckUpdates { component: None }) {
            PipeResponse::Ack {
                receipt: Some(rcpt),
                ..
            } => {
                assert_eq!(rcpt.status, OperationStatus::Partial);
                let err = rcpt.error.unwrap_or_default();
                assert!(err.contains("GitHub API 限流"));
                assert_eq!(
                    err.matches("GitHub API 限流").count(),
                    1,
                    "duplicate failure notes must be deduplicated: {err}"
                );
            }
            other => panic!("expected Ack(Partial), got {other:?}"),
        }
        coord.shutdown();
    }

    #[test]
    fn onboarding_probe_runs_off_coordinator_with_multi_anchor_fallback_and_no_fake_port() {
        struct MultiAnchorRunner {
            gate: Mutex<Option<mpsc::SyncSender<()>>>,
            release: Mutex<Option<mpsc::Receiver<()>>>,
            all_cn: AtomicBool,
        }
        impl ProbeRunner for MultiAnchorRunner {
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
                if let Some(tx) = self.gate.lock().unwrap().take() {
                    let _ = tx.send(());
                }
                if let Some(rx) = self.release.lock().unwrap().take() {
                    let _ = rx.recv_timeout(Duration::from_secs(2));
                }
                let force_cn = self.all_cn.load(Ordering::Acquire);
                let ev = AccessEvidence {
                    level: AccessLevel::Tun,
                    observed_at: now_secs,
                    revision: cfg_rev,
                    note: "mock tun".into(),
                    ..AccessEvidence::default()
                };
                let out = targets
                    .iter()
                    .map(|t| {
                        let res = if force_cn || t.id == "claude" {
                            ProbeResult {
                                reachable: true,
                                status: Some(200),
                                ip: Some("203.0.113.10".into()),
                                country: Some("CN".into()),
                                raw_region: Some("CN".into()),
                                colo: Some("SHA".into()),
                                city: None,
                                latency_ms: 30,
                                parsed_as: "trace".into(),
                                detail: "cn".into(),
                            }
                        } else {
                            ProbeResult {
                                reachable: true,
                                status: Some(200),
                                ip: Some("198.51.100.88".into()),
                                country: Some("US".into()),
                                raw_region: Some("US".into()),
                                colo: Some("SJC".into()),
                                city: None,
                                latency_ms: 42,
                                parsed_as: "trace".into(),
                                detail: "us".into(),
                            }
                        };
                        (t.id.clone(), res)
                    })
                    .collect();
                (ev, out)
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let driver = Arc::new(ControllableDriver::new());
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let runner = Arc::new(MultiAnchorRunner {
            gate: Mutex::new(Some(entered_tx)),
            release: Mutex::new(Some(release_rx)),
            all_cn: AtomicBool::new(false),
        });
        let recovery = Arc::new(MockRecoveryExecutor::new(MockRecoveryState::default()));
        let coord = boot_actor(dir.path(), driver, runner.clone(), recovery);

        let coord_bg = coord.clone();
        let handle = std::thread::spawn(move || coord_bg.dispatch(PipeRequest::ProbeOnboarding));
        entered_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("onboarding worker entered");

        // Coordinator must NOT block GetSnapshot while ProbeOnboarding is in flight!
        assert!(matches!(
            coord.dispatch(PipeRequest::GetSnapshot),
            PipeResponse::Snapshot { .. }
        ));
        release_tx.send(()).unwrap();

        match handle.join().unwrap() {
            PipeResponse::OnboardingProbe { probe } => {
                assert_eq!(
                    probe.detected_proxy_port, None,
                    "TUN mode without proxy_addr must NOT report fake default proxy port"
                );
                let p = probe.probe.expect("fallback anchor result");
                assert_eq!(p.country.as_deref(), Some("US"));
                assert_eq!(p.ip.as_deref(), Some("198.51.100.88"));
            }
            other => panic!("expected OnboardingProbe, got {other:?}"),
        }

        // When all anchors return CN, falls back to CN result so onboarding warns.
        runner.all_cn.store(true, Ordering::Release);
        match coord.dispatch(PipeRequest::ProbeOnboarding) {
            PipeResponse::OnboardingProbe { probe } => {
                let p = probe.probe.expect("cn fallback result");
                assert_eq!(p.country.as_deref(), Some("CN"));
            }
            other => panic!("expected OnboardingProbe(CN), got {other:?}"),
        }

        coord.shutdown();
    }

    #[test]
    fn bootstrap_and_complete_onboarding_sync_leak_shield_when_armed_with_enabled_vectors() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_ref = calls.clone();
        let syncer: LeakShieldSyncFn = Arc::new(move |exes, quic, dns, ipv6| {
            calls_ref.fetch_add(1, Ordering::AcqRel);
            let active_rules =
                exes.len() * (usize::from(quic) + usize::from(dns) * 3 + usize::from(ipv6));
            Ok(LeakShieldStatus {
                enabled: active_rules > 0,
                quic_blocked: quic && active_rules > 0,
                dns_doh_blocked: dns && active_rules > 0,
                ipv6_blocked: ipv6 && active_rules > 0,
                active_rules,
                summary: "synced".into(),
            })
        });

        let dir = tempfile::tempdir().unwrap();
        let driver = Arc::new(ControllableDriver::new());
        let runner = Arc::new(DelayedProbeRunner {
            gate_tx: None,
            release_rx: None,
            pass: Arc::new(AtomicBool::new(true)),
            ip_on_pass: "198.51.100.98".into(),
        });
        let recovery = Arc::new(MockRecoveryExecutor::new(MockRecoveryState::default()));

        let data_dir = dir.path().to_path_buf();
        let drv_c = driver.clone();
        let run_c = runner.clone();
        let rec_c = recovery.clone();
        let sync_c = syncer.clone();
        let (coord, ()) = start_coordinator_with(|event_tx| {
            let boot = RealEngineActor::bootstrap_with_syncer(
                data_dir, drv_c, run_c, rec_c, event_tx, sync_c,
            );
            (boot.initial_snapshot, Box::new(boot.actor), ())
        });
        assert_eq!(calls.load(Ordering::Acquire), 0, "Unconfigured skips sync");

        let mut cfg = make_cfg("US");
        cfg.leak_shield_quic = true;
        cfg.leak_shield_dns_doh = false;
        cfg.leak_shield_ipv6 = false;
        assert!(matches!(
            coord.dispatch(PipeRequest::CompleteOnboarding { config: cfg }),
            PipeResponse::Ack { .. }
        ));
        assert_eq!(
            calls.load(Ordering::Acquire),
            1,
            "CompleteOnboarding must sync active leak shield rules immediately"
        );
        assert!(coord.snapshot().leak_shield.quic_blocked);
        coord.shutdown();

        // Reboot against persisted Armed config -> bootstrap syncs leak shield rules immediately!
        let data_dir2 = dir.path().to_path_buf();
        let (coord2, ()) = start_coordinator_with(|event_tx| {
            let boot = RealEngineActor::bootstrap_with_syncer(
                data_dir2, driver, runner, recovery, event_tx, syncer,
            );
            (boot.initial_snapshot, Box::new(boot.actor), ())
        });
        assert_eq!(
            calls.load(Ordering::Acquire),
            2,
            "bootstrap must sync leak shield rules when Armed and any shield flag is true"
        );
        assert!(coord2.snapshot().leak_shield.quic_blocked);
        coord2.shutdown();
    }

    #[test]
    fn monitor_loop_handles_telemetry_interval_exceeding_uptime_without_panic_c01() {
        let dir = tempfile::tempdir().unwrap();
        let driver: Arc<dyn PlatformDriver> = Arc::new(ControllableDriver::new());
        let runner = Arc::new(DelayedProbeRunner {
            gate_tx: None,
            release_rx: None,
            pass: Arc::new(AtomicBool::new(true)),
            ip_on_pass: "198.51.100.98".into(),
        });
        let recovery = Arc::new(MockRecoveryExecutor::new(MockRecoveryState::default()));
        let coord = boot_actor(dir.path(), driver.clone(), runner, recovery);
        let scanner = Arc::new(ProcessScanner::new(Duration::from_secs(5)));
        let ledger = Arc::new(EgressLedger::open(dir.path()));

        // Huge 100-year interval is strictly larger than any OS uptime (`Instant::now() - interval` would panic!).
        let huge_interval = Duration::from_secs(86_400 * 365 * 100);
        let monitor = BackgroundMonitorHandle::start_with_intervals(
            coord.clone(),
            driver,
            scanner,
            ledger,
            dir.path().to_path_buf(),
            false,
            huge_interval,
            huge_interval,
        );
        std::thread::sleep(Duration::from_millis(80));
        monitor.shutdown();
        coord.shutdown();
    }

    #[test]
    fn msix_path_change_resyncs_quarantine_and_shield_and_flow_a_releases_all_known_agents() {
        let shield_paths: Arc<Mutex<Vec<Vec<PathBuf>>>> = Arc::new(Mutex::new(Vec::new()));
        let sp_ref = shield_paths.clone();
        let syncer: LeakShieldSyncFn = Arc::new(move |exes, quic, _, _| {
            sp_ref.lock().unwrap().push(exes.to_vec());
            Ok(LeakShieldStatus {
                enabled: quic && !exes.is_empty(),
                quic_blocked: quic && !exes.is_empty(),
                active_rules: exes.len(),
                summary: "synced".into(),
                ..Default::default()
            })
        });

        let dir = tempfile::tempdir().unwrap();
        let driver = Arc::new(ControllableDriver::new());
        let v1_claude = PathBuf::from(r"C:\Program Files\WindowsApps\Claude_6.28899\Claude.exe");
        let v2_claude = PathBuf::from(r"C:\Program Files\WindowsApps\Claude_6.29000\Claude.exe");
        let chatgpt_exe = PathBuf::from(r"C:\Program Files\WindowsApps\OpenAI.ChatGPT\ChatGPT.exe");
        driver
            .gui_exes
            .lock()
            .unwrap()
            .insert("claude".into(), vec![v1_claude.clone()]);
        driver
            .gui_exes
            .lock()
            .unwrap()
            .insert("chatgpt".into(), vec![chatgpt_exe.clone()]);

        let pass = Arc::new(AtomicBool::new(false));
        let runner = Arc::new(DelayedProbeRunner {
            gate_tx: None,
            release_rx: None,
            pass: pass.clone(),
            ip_on_pass: "198.51.100.98".into(),
        });
        let recovery = Arc::new(PlatformRecoveryExecutor::new(driver.clone()));
        let d_path = dir.path().to_path_buf();
        let drv_c = driver.clone();
        let (coord, ()) = start_coordinator_with(|event_tx| {
            let boot = RealEngineActor::bootstrap_with_syncer(
                d_path, drv_c, runner, recovery, event_tx, syncer,
            );
            (boot.initial_snapshot, Box::new(boot.actor), ())
        });

        let mut cfg = make_cfg("US");
        cfg.guarded_agents = vec!["claude".into(), "chatgpt".into()];
        cfg.leak_shield_quic = true;
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
        assert_eq!(coord.snapshot().protection, ProtectionState::Quarantined);

        // Store silently updates Claude MSIX path to v2 while Quarantined!
        driver
            .gui_exes
            .lock()
            .unwrap()
            .insert("claude".into(), vec![v2_claude.clone()]);
        let cur = coord.snapshot();
        let new_agents = build_agent_statuses(
            &cur.config,
            &CachedProcessSnapshot::default(),
            &*driver,
            &[],
            cur.tripped.as_ref(),
        );
        coord.try_send_telemetry(TelemetryBundle {
            cfg_rev: cur.cfg_rev,
            runtime_epoch: cur.runtime_epoch,
            agents: new_agents,
            leak: LeakReport::not_applicable("mock", "mock", 1_700_001_000),
            leak_shield: cur.leak_shield.clone(),
            mihomo: MihomoStatus::default(),
            env: EnvCheck::default(),
            antigravity_proxy: AntigravityProxyStatus::default(),
            self_check: DefenseSelfCheck::default(),
            updates: None,
            wfp: WfpStatus::default(),
            risk_assessment: None,
            hooks: HookIntegrationStatus::default(),
            suspicious_oauth_processes: Vec::new(),
            now_secs: 1_700_001_000,
        });
        let _ = coord.dispatch(PipeRequest::QueryLogs {
            since_ts: None,
            until_ts: None,
            limit: Some(5),
            query: None,
        });

        let rules_after_msix = driver.fw.enumerate_rules("ClaudeGuard Block").unwrap();
        assert!(
            rules_after_msix
                .iter()
                .any(|r| r.program.contains("Claude_6.29000")),
            "MSIX update while quarantined must automatically bind firewall quarantine to new exe"
        );
        assert!(
            shield_paths
                .lock()
                .unwrap()
                .last()
                .unwrap()
                .contains(&v2_claude),
            "MSIX update must automatically resync leak shield to new exe"
        );

        // H-02: Uncheck `chatgpt` from guarded_agents while tripped, then recover via Flow A -> `chatgpt` MUST still be released!
        cfg.guarded_agents = vec!["claude".into()];
        assert!(matches!(
            coord.dispatch(PipeRequest::SaveConfig { config: cfg }),
            PipeResponse::Ack { .. }
        ));
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
        assert!(
            driver
                .fw
                .enumerate_rules("ClaudeGuard Block")
                .unwrap()
                .is_empty(),
            "Flow A must release ALL KNOWN_GUI_AGENT_IDS including agents unchecked while tripped"
        );

        coord.shutdown();
    }

    #[test]
    fn stale_telemetry_discarded_and_pause_unaffected_by_stale_last_error_and_wake_grace() {
        let dir = tempfile::tempdir().unwrap();
        // Plant a corrupt WAL journal so bootstrap enters Armed + Degraded with non-empty `last_error` (`M-02`).
        std::fs::write(JournalStore::new(dir.path()).path(), "{corrupt-wal").unwrap();
        let driver = Arc::new(ControllableDriver::new());
        let runner = Arc::new(DelayedProbeRunner {
            gate_tx: None,
            release_rx: None,
            pass: Arc::new(AtomicBool::new(true)),
            ip_on_pass: "198.51.100.98".into(),
        });
        let recovery = Arc::new(MockRecoveryExecutor::new(MockRecoveryState::default()));
        let coord = boot_actor(dir.path(), driver, runner, recovery);

        let boot_snap = coord.snapshot();
        assert_eq!(boot_snap.lifecycle, Lifecycle::Armed);
        assert_eq!(boot_snap.protection, ProtectionState::Degraded);
        assert!(!boot_snap.last_error.is_empty());

        // M-02: Valid `Pause` must return `Ack`, NOT `ErrorCode::IoFailed` from stale `last_error`!
        match coord.dispatch(PipeRequest::Pause {
            duration_secs: Some(60),
        }) {
            PipeResponse::Ack {
                snapshot: Some(s), ..
            } => {
                assert!(s.paused_until.is_some());
            }
            other => panic!("Pause must succeed despite stale last_error, got {other:?}"),
        }
        assert!(matches!(
            coord.dispatch(PipeRequest::Pause {
                duration_secs: Some(0)
            }),
            PipeResponse::Ack { .. }
        ));
        coord.shutdown();

        // H-07 + MED-02: Stale telemetry & post-wake 20s grace window suppress false leak-trips!
        let dir2 = tempfile::tempdir().unwrap();
        let driver2 = Arc::new(ControllableDriver::new());
        let runner2 = Arc::new(DelayedProbeRunner {
            gate_tx: None,
            release_rx: None,
            pass: Arc::new(AtomicBool::new(true)),
            ip_on_pass: "198.51.100.98".into(),
        });
        let recovery2 = Arc::new(MockRecoveryExecutor::new(MockRecoveryState::default()));
        let coord2 = boot_actor(dir2.path(), driver2, runner2, recovery2);
        let mut cfg = make_cfg("US");
        cfg.leak_trip = true;
        assert!(matches!(
            coord2.dispatch(PipeRequest::CompleteOnboarding { config: cfg }),
            PipeResponse::Ack { .. }
        ));
        assert!(matches!(
            coord2.dispatch(PipeRequest::RecheckNow { target_id: None }),
            PipeResponse::Ack { .. }
        ));
        assert_eq!(coord2.snapshot().protection, ProtectionState::Monitoring);

        let leaking = LeakReport {
            applicable: true,
            mode: "system_proxy".into(),
            checked_at: 1_700_002_000,
            agent_conns: 1,
            proxied: 0,
            local: 0,
            direct: vec![crate::protocol::LeakConn {
                pid: 999,
                agent: "claude".into(),
                remote: "203.0.113.77".into(),
                port: 443,
                is_mcp: false,
            }],
            direct_total: 1,
            note: "direct leak".into(),
        };

        // 1) Stale cfg_rev telemetry with leak must be discarded without tripping!
        coord2.try_send_telemetry(TelemetryBundle {
            cfg_rev: 0,
            runtime_epoch: coord2.snapshot().runtime_epoch,
            agents: Vec::new(),
            leak: leaking.clone(),
            leak_shield: LeakShieldStatus::default(),
            mihomo: MihomoStatus::default(),
            env: EnvCheck::default(),
            antigravity_proxy: AntigravityProxyStatus::default(),
            self_check: DefenseSelfCheck::default(),
            updates: None,
            wfp: WfpStatus::default(),
            risk_assessment: None,
            hooks: HookIntegrationStatus::default(),
            suspicious_oauth_processes: Vec::new(),
            now_secs: 1_700_002_000,
        });
        let _ = coord2.dispatch(PipeRequest::QueryLogs {
            since_ts: None,
            until_ts: None,
            limit: Some(1),
            query: None,
        });
        assert!(coord2.snapshot().tripped.is_none());

        // 2) SystemResumed enters 20s wake grace window -> fresh-rev leak telemetry is suppressed!
        coord2.notify_system_resumed();
        let cur = coord2.snapshot();
        coord2.try_send_telemetry(TelemetryBundle {
            cfg_rev: cur.cfg_rev,
            runtime_epoch: cur.runtime_epoch,
            agents: Vec::new(),
            leak: leaking,
            leak_shield: LeakShieldStatus::default(),
            mihomo: MihomoStatus::default(),
            env: EnvCheck::default(),
            antigravity_proxy: AntigravityProxyStatus::default(),
            self_check: DefenseSelfCheck::default(),
            updates: None,
            wfp: WfpStatus::default(),
            risk_assessment: None,
            hooks: HookIntegrationStatus::default(),
            suspicious_oauth_processes: Vec::new(),
            now_secs: now_unix_secs(),
        });
        let _ = coord2.dispatch(PipeRequest::QueryLogs {
            since_ts: None,
            until_ts: None,
            limit: Some(5),
            query: None,
        });
        assert!(
            coord2.snapshot().tripped.is_none(),
            "post-wake grace window must suppress false leak-trips while TUN/Wi-Fi reconnects"
        );
        coord2.shutdown();
    }

    struct FlakyRecoveryExecutor {
        remaining_failures: Mutex<usize>,
        inner: MockRecoveryExecutor,
    }

    impl FlakyRecoveryExecutor {
        fn new(failures: usize, state: MockRecoveryState) -> Self {
            Self {
                remaining_failures: Mutex::new(failures),
                inner: MockRecoveryExecutor::new(state),
            }
        }
    }

    impl RecoveryExecutor for FlakyRecoveryExecutor {
        fn remove_firewall_rule(&self, rule_name: &str) -> Result<(), String> {
            self.inner.remove_firewall_rule(rule_name)
        }

        fn list_managed_firewall_rules(&self) -> Result<Vec<String>, String> {
            let mut rem = self.remaining_failures.lock().unwrap();
            if *rem > 0 {
                *rem -= 1;
                return Err("RPC_S_SERVER_UNAVAILABLE (BFE starting)".into());
            }
            drop(rem);
            self.inner.list_managed_firewall_rules()
        }

        fn clear_all_managed_firewall_rules(&self) -> Result<usize, String> {
            self.inner.clear_all_managed_firewall_rules()
        }

        fn enable_nic_by_guid(&self, guid: &str, name_hint: &str) -> Result<(), String> {
            self.inner.enable_nic_by_guid(guid, name_hint)
        }

        fn restore_timezone(&self, tz_key: &str) -> Result<(), String> {
            self.inner.restore_timezone(tz_key)
        }

        fn restore_location(&self, lat: Option<&str>, lon: Option<&str>) -> Result<(), String> {
            self.inner.restore_location(lat, lon)
        }
    }

    struct AccessAwareProbeRunner {
        pass: Arc<AtomicBool>,
    }

    impl ProbeRunner for AccessAwareProbeRunner {
        fn inspect_and_probe(
            &self,
            driver: &dyn PlatformDriver,
            _cfg: &Config,
            cfg_rev: u64,
            targets: &[Target],
            enforce_access_path: bool,
            skip_network_probes: bool,
            now_secs: u64,
        ) -> (AccessEvidence, Vec<(String, ProbeResult)>) {
            let path = driver
                .inspect_access_path(&[])
                .map(|(p, _)| p)
                .unwrap_or(AccessPath::Uncovered);
            let access = match path {
                AccessPath::Tun { adapter } => AccessEvidence {
                    level: AccessLevel::Tun,
                    tun_iface: Some(adapter),
                    route_hint: true,
                    observed_at: now_secs,
                    revision: cfg_rev,
                    note: "mock tun".into(),
                    ..AccessEvidence::default()
                },
                AccessPath::Uncovered => AccessEvidence {
                    level: AccessLevel::Uncovered,
                    observed_at: now_secs,
                    revision: cfg_rev,
                    note: "未接入代理或 TUN".into(),
                    ..AccessEvidence::default()
                },
                _ => AccessEvidence {
                    level: AccessLevel::Unknown,
                    observed_at: now_secs,
                    revision: cfg_rev,
                    note: "unknown".into(),
                    ..AccessEvidence::default()
                },
            };
            if skip_network_probes || (enforce_access_path && !access.is_known()) {
                return (access, Vec::new());
            }
            let ok = self.pass.load(Ordering::Acquire);
            let results = targets
                .iter()
                .filter(|t| t.enabled)
                .map(|t| {
                    let probe = if ok {
                        ProbeResult {
                            reachable: true,
                            status: Some(200),
                            ip: Some("198.51.100.98".into()),
                            country: Some("US".into()),
                            raw_region: Some("US".into()),
                            colo: Some("SJC".into()),
                            latency_ms: 15,
                            parsed_as: "trace".into(),
                            detail: "ok".into(),
                            ..ProbeResult::default()
                        }
                    } else {
                        ProbeResult::failed("fail")
                    };
                    (t.id.clone(), probe)
                })
                .collect();
            (access, results)
        }
    }

    #[test]
    fn early_boot_retry_and_wal_pending_auto_heals_on_recheck_and_telemetry() {
        // 1) Early-boot retry (`[250, 500, ...]`) recovers transient BFE COM startup failure on attempt 2.
        let dir_retry = tempfile::tempdir().unwrap();
        ConfigStore::new(dir_retry.path())
            .save_verified(&make_cfg("US"))
            .unwrap();
        let driver_retry = Arc::new(ControllableDriver::new());
        let runner_retry = Arc::new(DelayedProbeRunner {
            gate_tx: None,
            release_rx: None,
            pass: Arc::new(AtomicBool::new(true)),
            ip_on_pass: "198.51.100.98".into(),
        });
        let flaky_once = Arc::new(FlakyRecoveryExecutor::new(1, MockRecoveryState::default()));
        let coord_retry = boot_actor(dir_retry.path(), driver_retry, runner_retry, flaky_once);
        assert_eq!(coord_retry.snapshot().lifecycle, Lifecycle::Armed);
        assert_eq!(coord_retry.snapshot().protection, ProtectionState::Pending);
        assert!(coord_retry.snapshot().self_check.wal_clean);
        coord_retry.shutdown();

        // 2) `Degraded(wal_pending)` preserves detailed boot error + self_check item, then heals on `RecheckNow`.
        let dir_recheck = tempfile::tempdir().unwrap();
        ConfigStore::new(dir_recheck.path())
            .save_verified(&make_cfg("US"))
            .unwrap();
        let driver_recheck: Arc<dyn PlatformDriver> =
            Arc::new(UnsupportedPlatformDriver::default());
        let runner_recheck = Arc::new(DelayedProbeRunner {
            gate_tx: None,
            release_rx: None,
            pass: Arc::new(AtomicBool::new(true)),
            ip_on_pass: "198.51.100.98".into(),
        });
        let flaky_boot = Arc::new(FlakyRecoveryExecutor::new(1, MockRecoveryState::default()));
        let coord_recheck = boot_actor(
            dir_recheck.path(),
            driver_recheck,
            runner_recheck,
            flaky_boot,
        );

        let snap0 = coord_recheck.snapshot();
        assert_eq!(snap0.protection, ProtectionState::Degraded);
        assert!(snap0.last_error.contains("RPC_S_SERVER_UNAVAILABLE"));
        assert!(!snap0.self_check.wal_clean);
        let wal_item = snap0
            .self_check
            .items
            .iter()
            .find(|i| i.id == "wal_journal")
            .unwrap();
        assert_eq!(wal_item.status, SelfCheckStatus::Degraded);
        assert!(wal_item.detail.contains("启动恢复核验未完成"));

        match coord_recheck.dispatch(PipeRequest::RecheckNow { target_id: None }) {
            PipeResponse::Ack {
                snapshot: Some(healed_snap),
                ..
            } => {
                assert_eq!(healed_snap.protection, ProtectionState::Monitoring);
                assert!(healed_snap.last_error.is_empty());
                assert!(healed_snap.self_check.wal_clean);
            }
            other => panic!("expected Ack after RecheckNow heal, got {other:?}"),
        }
        coord_recheck.shutdown();

        // 3) `Degraded(wal_pending)` also self-heals automatically via background `Telemetry`!
        let dir_tel = tempfile::tempdir().unwrap();
        ConfigStore::new(dir_tel.path())
            .save_verified(&make_cfg("US"))
            .unwrap();
        let driver_tel: Arc<dyn PlatformDriver> = Arc::new(UnsupportedPlatformDriver::default());
        let runner_tel = Arc::new(DelayedProbeRunner {
            gate_tx: None,
            release_rx: None,
            pass: Arc::new(AtomicBool::new(true)),
            ip_on_pass: "198.51.100.98".into(),
        });
        let flaky_tel = Arc::new(FlakyRecoveryExecutor::new(1, MockRecoveryState::default()));
        let coord_tel = boot_actor(dir_tel.path(), driver_tel, runner_tel, flaky_tel);
        assert_eq!(coord_tel.snapshot().protection, ProtectionState::Degraded);

        let cur = coord_tel.snapshot();
        coord_tel.try_send_telemetry(TelemetryBundle {
            cfg_rev: cur.cfg_rev,
            runtime_epoch: cur.runtime_epoch,
            agents: Vec::new(),
            leak: LeakReport::default(),
            leak_shield: LeakShieldStatus::default(),
            mihomo: MihomoStatus::default(),
            env: EnvCheck::default(),
            antigravity_proxy: AntigravityProxyStatus::default(),
            self_check: cur.self_check,
            updates: None,
            wfp: WfpStatus::default(),
            risk_assessment: None,
            hooks: HookIntegrationStatus::default(),
            suspicious_oauth_processes: Vec::new(),
            now_secs: now_unix_secs(),
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        while coord_tel.snapshot().protection != ProtectionState::Monitoring
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(20));
        }
        let healed_tel = coord_tel.snapshot();
        assert_eq!(healed_tel.protection, ProtectionState::Monitoring);
        assert!(healed_tel.last_error.is_empty());
        assert!(healed_tel.self_check.wal_clean);
        coord_tel.shutdown();
    }

    #[test]
    fn false_shutdown_uncovered_trip_rolls_back_and_rearm_syncs_leak_shield() {
        let dir = tempfile::tempdir().unwrap();
        let driver = Arc::new(ControllableDriver::new());
        let pass = Arc::new(AtomicBool::new(true));
        let runner = Arc::new(AccessAwareProbeRunner { pass: pass.clone() });
        let recovery = Arc::new(PlatformRecoveryExecutor::new(driver.clone()));
        let coord = boot_actor(dir.path(), driver.clone(), runner, recovery);

        let mut cfg = make_cfg("US");
        cfg.enforce_access_path = true;
        cfg.lockdown_on_uncovered = true;
        cfg.trip_threshold = 1;
        cfg.leak_shield_quic = true;
        cfg.leak_shield_dns_doh = true;
        cfg.leak_shield_ipv6 = true;
        assert!(matches!(
            coord.dispatch(PipeRequest::CompleteOnboarding { config: cfg }),
            PipeResponse::Ack { .. }
        ));
        assert!(matches!(
            coord.dispatch(PipeRequest::RecheckNow { target_id: None }),
            PipeResponse::Ack { .. }
        ));
        assert_eq!(coord.snapshot().protection, ProtectionState::Monitoring);
        assert!(coord.snapshot().leak_shield.enabled);
        assert!(coord.snapshot().leak_shield.active_rules > 0);

        // Flow B disarm clears shield -> Rearm MUST re-synchronize Leak Shield rules immediately!
        assert!(matches!(
            coord.dispatch(PipeRequest::DisarmAndRestoreFlowB {
                reason: Some("test disarm".into()),
            }),
            PipeResponse::Ack { .. }
        ));
        assert_eq!(coord.snapshot().lifecycle, Lifecycle::Disarmed);

        match coord.dispatch(PipeRequest::Rearm) {
            PipeResponse::Ack {
                snapshot: Some(rearmed),
                ..
            } => {
                assert_eq!(rearmed.lifecycle, Lifecycle::Armed);
                assert!(
                    rearmed.leak_shield.enabled && rearmed.leak_shield.active_rules > 0,
                    "Rearm must re-sync Leak Shield rules"
                );
            }
            other => panic!("expected Ack from Rearm, got {other:?}"),
        }
        assert!(matches!(
            coord.dispatch(PipeRequest::RecheckNow { target_id: None }),
            PipeResponse::Ack { .. }
        ));
        assert_eq!(coord.snapshot().protection, ProtectionState::Monitoring);

        // Simulate user-mode TUN (`Clash`) exiting 2s before OS shutdown -> false uncovered lockdown & quarantine!
        *driver.access_path_override.lock().unwrap() = Some(AccessPath::Uncovered);
        assert!(matches!(
            coord.dispatch(PipeRequest::RecheckNow { target_id: None }),
            PipeResponse::Ack { .. }
        ));
        let tripped_snap = coord.snapshot();
        assert_eq!(tripped_snap.protection, ProtectionState::Quarantined);
        assert!(tripped_snap.tripped.is_some());
        assert!(tripped_snap.lockdown);
        assert!(JournalStore::new(dir.path()).path().exists());
        assert!(!driver.fw.enumerate_rules("ClaudeGuard").unwrap().is_empty());

        // OS shutdown notification arrives within 20s -> false uncovered trip & WAL rolled back!
        match coord.dispatch(PipeRequest::NotifySystemShutdown) {
            PipeResponse::Ack {
                snapshot: Some(rolled_back),
                ..
            } => {
                assert_eq!(rolled_back.protection, ProtectionState::Monitoring);
                assert!(rolled_back.tripped.is_none());
                assert!(!rolled_back.lockdown);
            }
            other => panic!("expected Ack from NotifySystemShutdown, got {other:?}"),
        }
        assert!(
            !JournalStore::new(dir.path()).path().exists(),
            "false shutdown trip WAL must not persist across reboot"
        );
        assert!(
            driver.fw.enumerate_rules("ClaudeGuard").unwrap().is_empty(),
            "false shutdown trip firewall rules must be cleaned before reboot"
        );
        assert!(
            dir.path().join("daemon.log").is_file(),
            "rolling redacted daemon.log must be flushed to data_dir"
        );

        coord.shutdown();
    }

    #[test]
    fn v5_vaults_cleanroom_panic_lockdown_wfp_and_health_card_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().join("data");
        let fake_home = dir.path().join("home");
        let vaults_root = dir.path().join("vaults");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::create_dir_all(&fake_home).unwrap();
        std::fs::create_dir_all(&vaults_root).unwrap();

        let driver = Arc::new(ControllableDriver::new());
        let pass = Arc::new(AtomicBool::new(true));
        let runner = Arc::new(AccessAwareProbeRunner { pass: pass.clone() });
        let recovery = Arc::new(PlatformRecoveryExecutor::new(driver.clone()));

        let (coord, ()) = start_coordinator_with(|event_tx| {
            let mut boot = RealEngineActor::bootstrap(
                data_dir.clone(),
                driver.clone(),
                runner,
                recovery,
                event_tx,
            );
            boot.actor = boot
                .actor
                .with_test_sandbox_dirs(fake_home.clone(), vaults_root.clone());
            (boot.initial_snapshot, Box::new(boot.actor), ())
        });

        let mut cfg = make_cfg("US");
        cfg.enforce_access_path = false;
        assert!(matches!(
            coord.dispatch(PipeRequest::CompleteOnboarding { config: cfg }),
            PipeResponse::Ack { .. }
        ));
        assert!(matches!(
            coord.dispatch(PipeRequest::RecheckNow { target_id: None }),
            PipeResponse::Ack { .. }
        ));

        // 1) UpsertVault creates isolated dirs, seeds machine-id, and persists config.
        let jp_vault = crate::protocol::AccountVault {
            id: "jp-work".into(),
            name: "日本工作仓".into(),
            accent_hex: "#10B981".into(),
            enabled: true,
            pinned_regions: vec!["JP".into()],
            pinned_ips: Vec::new(),
            pinned_asn: None,
            dedicated_proxy_port: None,
            preferred_mihomo_group: None,
            preferred_mihomo_node: None,
            auto_align_mihomo_on_vault_launch: false,
            min_safety_score: 75,
            cooldown_after_ip_change_secs: 900,
            share_ide_extensions: true,
            msix_isolation_mode: Default::default(),
        };
        match coord.dispatch(PipeRequest::UpsertVault {
            vault: jp_vault.clone(),
        }) {
            PipeResponse::Ack {
                snapshot: Some(snap),
                ..
            } => {
                assert_eq!(snap.config.vaults.len(), 1);
                assert_eq!(snap.vaults.len(), 1);
                assert_eq!(snap.vaults[0].state, VaultRuntimeState::EgressMismatch);
                assert!(vaults_root.join("jp-work").join("meta.json").is_file());
            }
            other => panic!("expected Ack from UpsertVault, got {other:?}"),
        }

        // 2) LaunchVault enforces read-only hard block when current egress (US) mismatches vault (JP).
        match coord.dispatch(PipeRequest::LaunchVault {
            vault_id: "jp-work".into(),
            app: VaultAppTarget::ClaudeDesktop,
            extra_args: Vec::new(),
        }) {
            PipeResponse::Error { code, message, .. } => {
                assert_eq!(code, ErrorCode::IllegalState);
                assert!(message.contains("只读硬拦截"));
            }
            other => panic!("LaunchVault must hard-block on mismatch, got {other:?}"),
        }

        // 3) DeleteVault with purge_disk_data=false archives directory safely instead of destroying it.
        assert!(matches!(
            coord.dispatch(PipeRequest::DeleteVault {
                vault_id: "jp-work".into(),
                purge_disk_data: false,
            }),
            PipeResponse::Ack { .. }
        ));
        assert!(coord.snapshot().config.vaults.is_empty());
        assert!(!vaults_root.join("jp-work").exists());
        assert!(vaults_root.join(vault_win::ARCHIVED_VAULTS_DIR).is_dir());

        // 4) ScanCleanRoom + ExecuteCleanRoom + ListCleanRoomBackups + RestoreCleanRoomBackup.
        let claude_json = fake_home.join(".claude.json");
        std::fs::write(
            &claude_json,
            r#"{"userID":"usr_secret_123456789","anonymousId":"anon-1111","mcpServers":{"keep":{"command":"npx"}}}"#,
        )
        .unwrap();
        let scope = crate::protocol::CleanRoomScope::default();
        let finding_ids: Vec<String> = match coord.dispatch(PipeRequest::ScanCleanRoom {
            scope: scope.clone(),
        }) {
            PipeResponse::CleanRoomScan { report } => {
                assert!(report.pollution_score > 0);
                assert!(!report.findings.is_empty());
                report.findings.into_iter().map(|f| f.id).collect()
            }
            other => panic!("expected CleanRoomScan, got {other:?}"),
        };
        assert!(matches!(
            coord.dispatch(PipeRequest::ExecuteCleanRoom {
                scope,
                selected_finding_ids: finding_ids,
            }),
            PipeResponse::Ack { .. }
        ));
        let cleaned_text = std::fs::read_to_string(&claude_json).unwrap();
        assert!(!cleaned_text.contains("usr_secret_123456789"));
        assert!(cleaned_text.contains("mcpServers"));

        let backup_id = match coord.dispatch(PipeRequest::ListCleanRoomBackups) {
            PipeResponse::CleanRoomBackups { backups } => {
                assert_eq!(backups.len(), 1);
                backups[0].backup_id.clone()
            }
            other => panic!("expected CleanRoomBackups, got {other:?}"),
        };
        assert!(matches!(
            coord.dispatch(PipeRequest::RestoreCleanRoomBackup { backup_id }),
            PipeResponse::Ack { .. }
        ));
        let restored_text = std::fs::read_to_string(&claude_json).unwrap();
        assert!(restored_text.contains("usr_secret_123456789"));

        // 5) ConfigureCliHooks installs Claude Code hook idempotently in fake_home.
        assert!(matches!(
            coord.dispatch(PipeRequest::ConfigureCliHooks {
                install_claude_code: true,
                install_pwsh_profile: false,
                sync_all_vaults: false,
            }),
            PipeResponse::Ack { .. }
        ));
        assert!(coord.snapshot().hooks.claude_code_hook_installed);

        // 6) RunDeepRiskAudit + ClearGeoVelocityCooldown + ClearWfpBlockedEvents.
        assert!(matches!(
            coord.dispatch(PipeRequest::RunDeepRiskAudit),
            PipeResponse::Ack { .. }
        ));
        assert!(coord.snapshot().risk_assessment.evaluated_at > 0);
        assert!(matches!(
            coord.dispatch(PipeRequest::ClearGeoVelocityCooldown),
            PipeResponse::Ack { .. }
        ));
        assert!(matches!(
            coord.dispatch(PipeRequest::ClearWfpBlockedEvents),
            PipeResponse::Ack { .. }
        ));

        // 7) BuildHealthCard produces zero IP leaks.
        match coord.dispatch(PipeRequest::BuildHealthCard { export_png: false }) {
            PipeResponse::HealthCard { card } => {
                let raw = serde_json::to_string(&card).unwrap();
                assert!(
                    !raw.contains("198.51.100."),
                    "HealthCard must never leak raw egress IP: {raw}"
                );
                assert!(card.region_badge.contains("US"));
            }
            other => panic!("expected HealthCard, got {other:?}"),
        }

        // 8) TriggerPanicLockdown enables manual lockdown immediately.
        assert!(matches!(
            coord.dispatch(PipeRequest::TriggerPanicLockdown),
            PipeResponse::Ack { .. }
        ));
        let after_panic = coord.snapshot();
        assert!(after_panic.lockdown);
        assert!(after_panic.lockdown_manual);

        coord.shutdown();
    }

    #[test]
    fn fast_hook_gate_stale_fallback_counts_burst_guard_only_once() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = make_cfg("US");
        cfg.burst_guard_mode = crate::protocol::BurstGuardMode::ThrottleGate;
        cfg.burst_warn_rpm = 5;
        cfg.burst_throttle_rpm = 7;
        ConfigStore::new(dir.path()).save_verified(&cfg).unwrap();

        let driver: Arc<dyn PlatformDriver> = Arc::new(ControllableDriver::new());
        let runner = Arc::new(DelayedProbeRunner {
            gate_tx: None,
            release_rx: None,
            pass: Arc::new(AtomicBool::new(true)),
            ip_on_pass: "198.51.100.71".into(),
        });
        let recovery = Arc::new(MockRecoveryExecutor::new(MockRecoveryState::default()));
        let coord = boot_actor(dir.path(), driver, runner, recovery);

        // Freshly bootstrapped Armed state has `checked_at == None` (stale), so FastHookGate
        // must go through `NeedsSyncProbe` -> coordinator -> real probe -> `fulfill_round_waiters`,
        // recording EXACTLY 1 BurstGuard event (never 3).
        assert!(coord.snapshot().checked_at.is_none());
        match coord.dispatch(PipeRequest::FastHookGate {
            agent_id: "claude-code".into(),
            vault_id: None,
            hook_event: Some("UserPromptSubmit".into()),
        }) {
            PipeResponse::FastGateVerdict {
                allowed,
                decision,
                latency_path,
                ..
            } => {
                assert!(
                    allowed,
                    "first stale FastHookGate prompt must not self-block via BurstGuard triple-count"
                );
                assert_eq!(decision, HookDecision::Allow);
                assert_eq!(latency_path, "sync_probe_fallback");
            }
            other => panic!("expected FastGateVerdict, got {other:?}"),
        }

        // Republish snapshot via RecheckNow and verify BurstGuard recorded exactly 1 prompt.
        assert!(matches!(
            coord.dispatch(PipeRequest::RecheckNow { target_id: None }),
            PipeResponse::Ack { .. }
        ));
        assert_eq!(
            coord.snapshot().burst_guard.prompts_last_1m,
            1,
            "stale fallback must increment BurstGuard counter by exactly 1"
        );

        // Prompts #2..#7 hit fast_o1 and are still allowed (<= normalized throttle_rpm=7).
        for n in 2..=7u32 {
            match coord.dispatch(PipeRequest::FastHookGate {
                agent_id: "claude-code".into(),
                vault_id: None,
                hook_event: Some("UserPromptSubmit".into()),
            }) {
                PipeResponse::FastGateVerdict {
                    allowed,
                    latency_path,
                    ..
                } => {
                    assert!(allowed, "prompt #{n} must still be allowed (<= 7)");
                    assert_eq!(latency_path, "fast_o1");
                }
                other => panic!("expected fast_o1 Allow on prompt #{n}, got {other:?}"),
            }
        }

        // Prompt #8 exceeds throttle_rpm=7 and blocks via BurstGuard on fast_o1.
        match coord.dispatch(PipeRequest::FastHookGate {
            agent_id: "claude-code".into(),
            vault_id: None,
            hook_event: Some("UserPromptSubmit".into()),
        }) {
            PipeResponse::FastGateVerdict {
                allowed,
                decision,
                reason,
                latency_path,
                ..
            } => {
                assert!(!allowed);
                assert_eq!(decision, HookDecision::Block);
                assert_eq!(latency_path, "fast_o1");
                assert!(reason.contains("BurstGuard"), "unexpected reason: {reason}");
            }
            other => panic!("expected BurstGuard Block on 8th prompt, got {other:?}"),
        }

        coord.shutdown();
    }

    #[test]
    fn clear_geo_velocity_cooldown_updates_shared_egress_ledger_without_split_brain() {
        let dir = tempfile::tempdir().unwrap();
        let driver: Arc<dyn PlatformDriver> = Arc::new(ControllableDriver::new());
        let runner = Arc::new(DelayedProbeRunner {
            gate_tx: None,
            release_rx: None,
            pass: Arc::new(AtomicBool::new(true)),
            ip_on_pass: "198.51.100.88".into(),
        });
        let recovery = Arc::new(MockRecoveryExecutor::new(MockRecoveryState::default()));
        let data_dir = dir.path().to_path_buf();
        let drv_clone = driver.clone();
        let (coord, shared_ledger) = start_coordinator_with(|event_tx| {
            let boot = RealEngineActor::bootstrap(data_dir, drv_clone, runner, recovery, event_tx);
            (
                boot.initial_snapshot,
                Box::new(boot.actor),
                boot.egress_ledger,
            )
        });

        assert!(matches!(
            coord.dispatch(PipeRequest::CompleteOnboarding {
                config: make_cfg("US"),
            }),
            PipeResponse::Ack { .. }
        ));
        assert!(matches!(
            coord.dispatch(PipeRequest::RecheckNow { target_id: None }),
            PipeResponse::Ack { .. }
        ));

        let now = now_unix_secs();
        let _ = shared_ledger.record_and_evaluate(
            "198.51.100.10",
            "US",
            "San Jose",
            Some(373),
            Some(-1219),
            None,
            60,
            now.saturating_sub(600),
        );
        let jump_eval = shared_ledger.record_and_evaluate(
            "203.0.113.55",
            "JP",
            "Tokyo",
            Some(357),
            Some(1397),
            None,
            60,
            now.saturating_sub(60),
        );
        assert!(
            jump_eval.alert.is_some(),
            "US -> JP in 9 minutes must trigger impossible-travel alert"
        );
        assert_eq!(shared_ledger.observations_for_scoring(None, now).len(), 2);

        // User clears cooldown via daemon IPC; shared ledger handle (also held by BackgroundMonitorHandle)
        // must immediately observe the cleared state with zero split-brain resurrection.
        assert!(matches!(
            coord.dispatch(PipeRequest::ClearGeoVelocityCooldown),
            PipeResponse::Ack { .. }
        ));
        assert!(
            shared_ledger
                .observations_for_scoring(None, now_unix_secs())
                .is_empty(),
            "shared EgressLedger must immediately drop pre-clear observations"
        );
        let bg_assessment = compute_deep_risk_assessment(
            &*driver,
            &coord.snapshot(),
            &shared_ledger,
            &[],
            false,
            now_unix_secs(),
        );
        assert!(
            bg_assessment.geo_velocity_alert.is_none(),
            "background audit on shared ledger must not resurrect cleared geo-velocity alert"
        );

        coord.shutdown();
    }

    #[test]
    fn collect_electron_agent_pids_filters_helpers_and_non_electron_agents() {
        let snap = CachedProcessSnapshot {
            procs: vec![
                process_win::ProcInfo {
                    pid: 101,
                    ppid: 10,
                    name_l: "claude.exe".into(),
                    path_l: r"c:\users\alice\appdata\local\anthropicclaude\claude.exe".into(),
                    cmd_l: r"claude.exe --disable-quic".into(),
                    start_time: 1,
                },
                process_win::ProcInfo {
                    pid: 102,
                    ppid: 101,
                    name_l: "claude.exe".into(),
                    path_l: r"c:\users\alice\appdata\local\anthropicclaude\claude.exe".into(),
                    cmd_l: r"claude.exe --type=renderer --lang=en-us".into(),
                    start_time: 2,
                },
                process_win::ProcInfo {
                    pid: 103,
                    ppid: 101,
                    name_l: "claude.exe".into(),
                    path_l: r"c:\users\alice\appdata\local\anthropicclaude\claude.exe".into(),
                    cmd_l: String::new(),
                    start_time: 3,
                },
                process_win::ProcInfo {
                    pid: 104,
                    ppid: 101,
                    name_l: "cowork-svc.exe".into(),
                    path_l: r"c:\users\alice\appdata\local\anthropicclaude\cowork-svc.exe".into(),
                    cmd_l: "cowork-svc.exe".into(),
                    start_time: 4,
                },
                process_win::ProcInfo {
                    pid: 201,
                    ppid: 10,
                    name_l: "cursor.exe".into(),
                    path_l: r"c:\users\alice\appdata\local\programs\cursor\cursor.exe".into(),
                    cmd_l: "cursor.exe".into(),
                    start_time: 5,
                },
                process_win::ProcInfo {
                    pid: 301,
                    ppid: 10,
                    name_l: "zed.exe".into(),
                    path_l: r"c:\users\alice\appdata\local\programs\zed\zed.exe".into(),
                    cmd_l: "zed.exe".into(),
                    start_time: 6,
                },
                process_win::ProcInfo {
                    pid: 401,
                    ppid: 10,
                    name_l: "notepad.exe".into(),
                    path_l: r"c:\windows\system32\notepad.exe".into(),
                    cmd_l: "notepad.exe".into(),
                    start_time: 7,
                },
            ],
            ..Default::default()
        };

        let found = collect_electron_agent_pids(&snap);
        assert_eq!(
            found,
            vec![("claude".to_string(), 101), ("cursor".to_string(), 201)]
        );
    }

    #[test]
    fn discover_vault_pids_and_liveness_pruning_never_use_dummy_pid_zero() {
        let vaults_root = std::path::Path::new(r"C:\Users\alice\AppData\Local\ClaudeGuard\Vaults");
        let procs = CachedProcessSnapshot {
            procs: vec![
                process_win::ProcInfo {
                    pid: 0,
                    ppid: 0,
                    name_l: "claude.exe".into(),
                    path_l: r"c:\programs\claude\claude.exe".into(),
                    cmd_l: r#"claude.exe --user-data-dir="c:\users\alice\appdata\local\claudeguard\vaults\jp\claude-desktop""#.into(),
                    start_time: 1,
                },
                process_win::ProcInfo {
                    pid: 5001,
                    ppid: 10,
                    name_l: "claude.exe".into(),
                    path_l: r"c:\programs\claude\claude.exe".into(),
                    cmd_l: r#"claude.exe --user-data-dir="c:\users\alice\appdata\local\claudeguard\vaults\jp\claude-desktop""#.into(),
                    start_time: 2,
                },
                process_win::ProcInfo {
                    pid: 5002,
                    ppid: 10,
                    name_l: "claude.exe".into(),
                    path_l: r"c:\programs\claude\claude.exe".into(),
                    cmd_l: r#"claude.exe --user-data-dir="c:\users\alice\appdata\local\claudeguard\vaults\jp-work\claude-desktop""#.into(),
                    start_time: 3,
                },
                process_win::ProcInfo {
                    pid: 5003,
                    ppid: 10,
                    name_l: "cursor.exe".into(),
                    path_l: r"c:\users\alice\appdata\local\programs\cursor\cursor.exe".into(),
                    cmd_l: "cursor.exe --user-data-dir=c:/users/alice/appdata/local/claudeguard/vaults/jp/cursor-ide".into(),
                    start_time: 4,
                },
            ],
            ..Default::default()
        };

        // Prefix-boundary isolation: `jp` must NOT match `jp-work` and must exclude dummy PID 0.
        let jp_pids = discover_vault_pids_in_snapshot(&procs, vaults_root, "jp");
        assert_eq!(
            jp_pids,
            vec![(5001, "claude".to_string()), (5003, "cursor".to_string())]
        );
        let jp_work_pids = discover_vault_pids_in_snapshot(&procs, vaults_root, "jp-work");
        assert_eq!(jp_work_pids, vec![(5002, "claude".to_string())]);

        assert!(!is_pid_alive(0));
        assert!(!is_pid_alive(u32::MAX - 1));
        #[cfg(windows)]
        assert!(is_pid_alive(std::process::id()));

        // Verify LaunchVault on a matching vault NEVER inserts dummy PID 0 into running_pids.
        let dir = tempfile::tempdir().unwrap();
        let fake_vaults = dir.path().join("vaults");
        let driver = Arc::new(ControllableDriver::new());
        driver.allow_launch.store(true, Ordering::Release);
        driver.gui_exes.lock().unwrap().insert(
            "claude".into(),
            vec![PathBuf::from(r"C:\Programs\Claude\Claude.exe")],
        );
        let runner = Arc::new(DelayedProbeRunner {
            gate_tx: None,
            release_rx: None,
            pass: Arc::new(AtomicBool::new(true)),
            ip_on_pass: "198.51.100.77".into(),
        });
        let recovery = Arc::new(MockRecoveryExecutor::new(MockRecoveryState::default()));
        let drv: Arc<dyn PlatformDriver> = driver;
        let data_dir = dir.path().to_path_buf();
        let fv = fake_vaults.clone();
        let (coord, ()) = start_coordinator_with(|event_tx| {
            let mut boot = RealEngineActor::bootstrap(data_dir, drv, runner, recovery, event_tx);
            boot.actor.test_vaults_root_override = Some(fv);
            (boot.initial_snapshot, Box::new(boot.actor), ())
        });
        assert!(matches!(
            coord.dispatch(PipeRequest::CompleteOnboarding {
                config: make_cfg("US"),
            }),
            PipeResponse::Ack { .. }
        ));
        assert!(matches!(
            coord.dispatch(PipeRequest::RecheckNow { target_id: None }),
            PipeResponse::Ack { .. }
        ));

        let us_vault = crate::protocol::AccountVault {
            id: "us-live".into(),
            name: "美国实测仓".into(),
            accent_hex: "#3B82F6".into(),
            enabled: true,
            pinned_regions: vec!["US".into()],
            pinned_ips: Vec::new(),
            pinned_asn: None,
            dedicated_proxy_port: None,
            preferred_mihomo_group: None,
            preferred_mihomo_node: None,
            auto_align_mihomo_on_vault_launch: false,
            min_safety_score: 50,
            cooldown_after_ip_change_secs: 0,
            share_ide_extensions: true,
            msix_isolation_mode: Default::default(),
        };
        assert!(matches!(
            coord.dispatch(PipeRequest::UpsertVault { vault: us_vault }),
            PipeResponse::Ack { .. }
        ));
        match coord.dispatch(PipeRequest::LaunchVault {
            vault_id: "us-live".into(),
            app: VaultAppTarget::ClaudeDesktop,
            extra_args: Vec::new(),
        }) {
            PipeResponse::Ack {
                snapshot: Some(snap),
                ..
            } => {
                assert_eq!(snap.vaults.len(), 1);
                assert!(
                    !snap.vaults[0].running_pids.contains(&0),
                    "LaunchVault must NEVER store dummy PID 0"
                );
                assert_ne!(
                    snap.vaults[0].state,
                    VaultRuntimeState::ActiveRunning,
                    "vault without real live PIDs must not falsely report ActiveRunning"
                );
            }
            other => panic!("expected Ack from matching US LaunchVault, got {other:?}"),
        }

        coord.shutdown();
    }
}
