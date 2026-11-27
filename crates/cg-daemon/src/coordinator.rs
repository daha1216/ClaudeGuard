//! O(1) snapshot store, `<2ms` `FastHookGate` evaluator, and single-writer coordinator queue.
//!
//! - [`PipeRequest::GetSnapshot`] reads [`SnapshotStore`] (`Arc<RwLock<GuardSnapshot>>`)
//!   in O(1) memory with ZERO syscalls, process scans, or queue blocking.
//! - [`PipeRequest::FastHookGate`] evaluates fresh snapshots, BurstGuard velocity/cadence,
//!   10D ban-risk gates, and Sovereign Vault pinning in O(1) memory directly on the IPC thread
//!   (bypassing the single-writer mutation queue), falling back cleanly to the coordinator only
//!   when the snapshot is stale or unverified.
//! - All mutating/query IPC requests, background monitor ticks, async probe completions,
//!   and periodic telemetry updates flow through one dedicated single-writer coordinator thread.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::Instant;

use cg_core::{BurstGuardConfig, BurstGuardTracker, CheckPurpose};
use cg_platform::process_win::ProcessIdentity;
use cg_protocol::{
    matched_ip_rule, normalize_region, AccountVault, AnchorKind, AsnClassification,
    BurstGuardStatus, CleanRoomBackupMeta, CleanRoomReport, Config, HookDecision, HookFailMode,
    HookIntegrationStatus, Lifecycle, ProtectionState, RiskAssessment, SanitizedHealthCard,
    TargetState, VaultAppTarget, VaultRuntimeState, WfpStatus, WslBridgeStatus,
};

use crate::protocol::{
    now_unix_millis, now_unix_secs, AccessEvidence, AgentRuntimeStatus, AntigravityProxyState,
    AntigravityProxyStatus, DefenseSelfCheck, EnvCheck, ErrorCode, FeishuStatus, GuardSnapshot,
    LeakReport, LeakShieldStatus, MihomoStatus, OperationReceipt, PipeRequest, PipeResponse,
    ProbeResult, UpdateSummary,
};

const QUEUE_CAPACITY: usize = 256;

/// Lock-free atomic metrics shared between O(1) `FastHookGate`, WSL2 bridge, and snapshot builder.
#[derive(Debug, Default)]
pub struct HookGateMetrics {
    pub total_gate_checks: AtomicU64,
    pub total_gate_blocks: AtomicU64,
    pub last_gate_latency_us: AtomicU64,
    pub wsl_proxy_desync: AtomicBool,
}

impl HookGateMetrics {
    pub fn record(&self, allowed: bool, latency_us: u64) {
        self.total_gate_checks.fetch_add(1, Ordering::Relaxed);
        if !allowed {
            self.total_gate_blocks.fetch_add(1, Ordering::Relaxed);
        }
        self.last_gate_latency_us
            .store(latency_us.max(1), Ordering::Relaxed);
    }

    pub fn snapshot_counts(&self) -> (u64, u64, u64) {
        (
            self.total_gate_checks.load(Ordering::Relaxed),
            self.total_gate_blocks.load(Ordering::Relaxed),
            self.last_gate_latency_us.load(Ordering::Relaxed),
        )
    }
}

/// Result of attempting the O(1) `FastHookGate` fast path.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FastGateOutcome {
    Immediate(PipeResponse),
    NeedsSyncProbe,
}

/// Cached egress observation probed through a dedicated local proxy port (`vault.dedicated_proxy_port`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PortEgressObservation {
    pub port: u16,
    pub ip: Option<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub colo: Option<String>,
    pub lat_tenths: Option<i16>,
    pub lon_tenths: Option<i16>,
    pub asn: Option<u32>,
    pub observed_at: u64,
}

/// Result produced by the off-thread `LaunchVault` worker.
#[derive(Clone, Debug)]
pub enum VaultLaunchWorkerOutcome {
    Launched {
        obs_ip: Option<String>,
        obs_country: Option<String>,
        obs_city: Option<String>,
        lat_tenths: Option<i16>,
        lon_tenths: Option<i16>,
        port_obs: Option<PortEgressObservation>,
        discovered_sessions: Vec<(ProcessIdentity, String)>,
    },
    AutoAlignedMihomo {
        node: String,
        detail: String,
    },
    Failed {
        code: ErrorCode,
        message: String,
    },
}

/// Extracts primary observed `(ip, country, asn)` from the latest snapshot.
pub fn current_primary_egress(
    snap: &GuardSnapshot,
) -> (Option<String>, Option<String>, Option<u32>) {
    let preferred_target = snap
        .targets
        .iter()
        .find(|t| {
            t.id == "claude"
                && t.state == TargetState::Pass
                && (t.ip.is_some() || t.country.is_some())
        })
        .or_else(|| {
            snap.targets.iter().find(|t| {
                t.state == TargetState::Pass
                    && t.anchor_kind != AnchorKind::Reachability
                    && (t.ip.is_some() || t.country.is_some())
            })
        })
        .or_else(|| {
            snap.targets.iter().find(|t| {
                t.state != TargetState::Disabled && (t.ip.is_some() || t.country.is_some())
            })
        });

    let ip = preferred_target
        .and_then(|t| t.ip.clone())
        .or_else(|| snap.risk_assessment.ip_purity.ip.clone());
    let country = preferred_target
        .and_then(|t| t.country.clone())
        .or_else(|| snap.risk_assessment.ip_purity.country.clone());
    let asn = snap.risk_assessment.ip_purity.asn;
    (ip, country, asn)
}

/// Verifies whether observed `(ip, country, asn)` satisfies a Sovereign Account Vault's pinning contract.
pub fn check_vault_egress_contract(
    vault: &AccountVault,
    ip: Option<&str>,
    country: Option<&str>,
    asn: Option<u32>,
) -> Result<(), String> {
    if !vault.pinned_ips.is_empty() {
        let Some(obs_ip) = ip.map(str::trim).filter(|s| !s.is_empty()) else {
            return Err(format!(
                "保险箱「{}」绑定了固定出口 IP/CIDR，但当前尚未识别到出口 IP",
                vault.name
            ));
        };
        if matched_ip_rule(&vault.pinned_ips, obs_ip).is_none() {
            return Err(format!(
                "当前出口 IP 不符合保险箱「{}」绑定的白名单规则",
                vault.name
            ));
        }
    }

    if !vault.pinned_regions.is_empty() {
        let obs_norm = country.and_then(normalize_region);
        let region_ok = obs_norm.as_deref().is_some_and(|norm| {
            vault
                .pinned_regions
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(norm))
        });
        if !region_ok {
            return Err(format!(
                "当前出口地区（{}）不符合保险箱「{}」绑定的地区列表（{}）",
                obs_norm.as_deref().unwrap_or("未知"),
                vault.name,
                vault.pinned_regions.join("/")
            ));
        }
    }

    if let Some(expected_asn) = vault.pinned_asn {
        if asn != Some(expected_asn) {
            return Err(format!(
                "当前出口 ASN（{}）不符合保险箱「{}」绑定的 AS{expected_asn}",
                asn.map(|a| format!("AS{a}"))
                    .unwrap_or_else(|| "未知".into()),
                vault.name
            ));
        }
    }

    Ok(())
}

/// Pure O(1) evaluator for [`PipeRequest::FastHookGate`].
///
/// Guarantees zero syscalls, zero process scans, and zero queue contention on the fast path.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_fast_hook_gate_at(
    snap: &GuardSnapshot,
    burst_guard: &Mutex<BurstGuardTracker>,
    agent_id: &str,
    vault_id: Option<&str>,
    hook_event: Option<&str>,
    now_secs: u64,
    now_ms: u64,
) -> FastGateOutcome {
    let empty_ports = HashMap::new();
    evaluate_fast_hook_gate_with_ports_at(
        snap,
        burst_guard,
        &empty_ports,
        agent_id,
        vault_id,
        hook_event,
        now_secs,
        now_ms,
    )
}

/// Pure O(1) evaluator for [`PipeRequest::FastHookGate`] with per-port dedicated Vault egress cache.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_fast_hook_gate_with_ports_at(
    snap: &GuardSnapshot,
    burst_guard: &Mutex<BurstGuardTracker>,
    port_egress: &HashMap<u16, PortEgressObservation>,
    agent_id: &str,
    vault_id: Option<&str>,
    hook_event: Option<&str>,
    now_secs: u64,
    now_ms: u64,
) -> FastGateOutcome {
    let safety_score = if snap.risk_assessment.evaluated_at > 0 {
        snap.risk_assessment.score
    } else if snap.all_enabled_pass() {
        100
    } else {
        0
    };

    let block = |reason: String| {
        FastGateOutcome::Immediate(PipeResponse::FastGateVerdict {
            allowed: false,
            decision: HookDecision::Block,
            safety_score,
            reason,
            latency_path: "fast_o1".to_string(),
        })
    };
    let allow = |reason: String| {
        FastGateOutcome::Immediate(PipeResponse::FastGateVerdict {
            allowed: true,
            decision: HookDecision::Allow,
            safety_score,
            reason,
            latency_path: "fast_o1".to_string(),
        })
    };

    // 1. Instant hard-block states (regardless of snapshot freshness).
    if snap.is_tripped() {
        let detail = snap
            .tripped
            .as_ref()
            .map(|t| t.reason.trim())
            .filter(|s| !s.is_empty())
            .unwrap_or("出口违规隔离中");
        return block(format!(
            "🛡️ [ClaudeGuard 熔断拦截] 守卫已触发隔离熔断（{detail}），已阻断提示词发送以防封号"
        ));
    }
    if snap.lockdown {
        return block(
            "🛡️ [ClaudeGuard 锁死拦截] 当前处于防裸连锁死状态，请恢复合规代理并核验通过后再试"
                .to_string(),
        );
    }

    // 2. Non-armed lifecycle states.
    match snap.lifecycle {
        Lifecycle::Unconfigured => {
            return match snap.config.hook_fail_mode {
                HookFailMode::FailOpenWithWarn => {
                    allow("警告：ClaudeGuard 尚未完成初始化配置（按 FailOpenWithWarn 放行）".into())
                }
                HookFailMode::FailClosed => block(
                    "🛡️ [ClaudeGuard 未初始化] 请先完成引导配置并布防后再发送提示词".to_string(),
                ),
            };
        }
        Lifecycle::Disarmed => {
            return allow("ClaudeGuard 已解除布防，门禁放行".to_string());
        }
        Lifecycle::Stopping => {
            return match snap.config.hook_fail_mode {
                HookFailMode::FailOpenWithWarn => {
                    allow("警告：ClaudeGuard 服务正在停止（按 FailOpenWithWarn 放行）".into())
                }
                HookFailMode::FailClosed => {
                    block("🛡️ [ClaudeGuard 服务停止中] 已按安全优先策略拦截提示词".to_string())
                }
            };
        }
        Lifecycle::Maintenance => {
            return block(
                "🛡️ [ClaudeGuard 维护模式拦截] 守卫处于维护状态，暂不允许发送提示词".to_string(),
            );
        }
        Lifecycle::Armed => {}
    }

    if snap.is_paused_at(now_secs) {
        return allow("ClaudeGuard 临时暂停中，门禁放行".to_string());
    }

    // 3. Snapshot freshness, Pending state, non-tripped Uncovered/Fail, and dedicated-port cache
    //    checks BEFORE mutating BurstGuardTracker so NeedsSyncProbe never double-counts prompts.
    let ttl = snap.config.hook_freshness_ttl_secs.clamp(10, 300);
    let is_fresh = snap
        .checked_at
        .is_some_and(|ts| now_secs.saturating_sub(ts) <= ttl);
    if !is_fresh || snap.protection == ProtectionState::Pending {
        return FastGateOutcome::NeedsSyncProbe;
    }

    if snap.protection != ProtectionState::Monitoring {
        return block(format!(
            "🛡️ [ClaudeGuard 状态拦截] 当前保护状态为 {:?}，暂不允许发送提示词",
            snap.protection
        ));
    }

    let normalized_vault = vault_id.map(str::trim).filter(|s| !s.is_empty());
    let mut dedicated_egress: Option<&PortEgressObservation> = None;
    let mut uses_dedicated_port = false;

    if let Some(vid) = normalized_vault {
        if let Some(vault) = snap
            .config
            .vaults
            .iter()
            .find(|v| v.id.eq_ignore_ascii_case(vid))
        {
            if vault.enabled {
                if let Some(port) = vault
                    .dedicated_proxy_port
                    .filter(|&p| p > 0 && p != snap.config.proxy_port)
                {
                    uses_dedicated_port = true;
                    match port_egress.get(&port) {
                        Some(obs) if now_secs.saturating_sub(obs.observed_at) <= ttl => {
                            dedicated_egress = Some(obs);
                        }
                        _ => return FastGateOutcome::NeedsSyncProbe,
                    }
                }
            }
        }
    }

    if !uses_dedicated_port
        && ((snap.config.enforce_access_path && !snap.access.is_known())
            || !snap.all_enabled_pass())
    {
        return FastGateOutcome::NeedsSyncProbe;
    }

    // 4. BurstGuard sliding-window rate & robotic cadence check (O(1) in-memory).
    // Only executes once we know this evaluation produces a terminal Immediate verdict.
    let is_pre_tool = hook_event.is_some_and(|e| {
        let lower = e.trim().to_ascii_lowercase();
        matches!(lower.as_str(), "pretooluse" | "pre_tool_use" | "pre-tool")
    });
    let burst_cfg = BurstGuardConfig::from_config(&snap.config);
    let burst_eval = {
        let mut tracker = burst_guard.lock().unwrap_or_else(|e| e.into_inner());
        if is_pre_tool {
            tracker.evaluate_only(agent_id, normalized_vault, now_ms, &burst_cfg)
        } else {
            tracker.record_and_evaluate(agent_id, normalized_vault, now_ms, &burst_cfg)
        }
    };
    if burst_eval.hook_decision == HookDecision::Block {
        return block(format!(
            "🛡️ [ClaudeGuard BurstGuard 拦截] {}",
            burst_eval.reason
        ));
    }

    // 5. M2 10-Dimension Ban-Risk, Geo-Velocity cooldown & Datacenter ASN checks (for global proxy).
    if !uses_dedicated_port && snap.risk_assessment.evaluated_at > 0 {
        if snap.config.enforce_geo_velocity {
            if let Some(alert) = snap.risk_assessment.geo_velocity_alert.as_ref() {
                let active = alert.cooldown_until.is_none_or(|until| until > now_secs);
                if active {
                    let remain = alert
                        .cooldown_until
                        .map_or(0, |until| until.saturating_sub(now_secs));
                    return block(format!(
                        "🛡️ [ClaudeGuard 时空瞬移冷却] 检测到异常跨国跃迁（{} -> {}，{}km），剩余冷却 {}s",
                        alert.from_country, alert.to_country, alert.distance_km, remain
                    ));
                }
            }
        }
        if snap.config.block_datacenter_asn
            && (snap.risk_assessment.ip_purity.is_datacenter
                || matches!(
                    snap.risk_assessment.ip_purity.classification,
                    AsnClassification::DatacenterHosting | AsnClassification::PublicProxyVpnTor
                ))
        {
            return block(
                "🛡️ [ClaudeGuard 机房 IP 拦截] 当前出口属于云机房/VPS 或高风险共享代理段，已按策略阻断提示词"
                    .to_string(),
            );
        }
    }

    // 6. M4 Sovereign Account Vault pinning & cooldown contract (when vault_id provided).
    if let Some(vid) = normalized_vault {
        let Some(vault) = snap
            .config
            .vaults
            .iter()
            .find(|v| v.id.eq_ignore_ascii_case(vid))
        else {
            return block(format!(
                "🛡️ [ClaudeGuard 分身保险箱拦截] 未找到标识为「{vid}」的保险箱配置"
            ));
        };
        if !vault.enabled {
            return block(format!(
                "🛡️ [ClaudeGuard 分身保险箱拦截] 保险箱「{}」已停用",
                vault.name
            ));
        }
        if let Some(rt) = snap
            .vaults
            .iter()
            .find(|v| v.id.eq_ignore_ascii_case(&vault.id))
        {
            if rt.cooldown_remaining_secs > 0 || rt.state == VaultRuntimeState::CoolingDown {
                return block(format!(
                    "🛡️ [ClaudeGuard 分身保险箱冷却] 保险箱「{}」换 IP 冷却中（剩余 {}s）",
                    vault.name, rt.cooldown_remaining_secs
                ));
            }
        }

        let (obs_ip, obs_country, obs_asn) = if let Some(obs) = dedicated_egress {
            (obs.ip.clone(), obs.country.clone(), obs.asn)
        } else {
            current_primary_egress(snap)
        };
        if let Err(reason) =
            check_vault_egress_contract(vault, obs_ip.as_deref(), obs_country.as_deref(), obs_asn)
        {
            return block(format!("🛡️ [ClaudeGuard 分身契约拦截] {reason}"));
        }
        if !uses_dedicated_port
            && snap.risk_assessment.evaluated_at > 0
            && snap.risk_assessment.score < vault.min_safety_score
        {
            return block(format!(
                "🛡️ [ClaudeGuard 安全分不足] 当前出口安全分 {} 低于保险箱「{}」要求阈值 {}",
                snap.risk_assessment.score, vault.name, vault.min_safety_score
            ));
        }
    } else if snap.risk_assessment.evaluated_at > 0
        && snap.risk_assessment.score < snap.config.min_global_safety_score
    {
        return block(format!(
            "🛡️ [ClaudeGuard 安全分拦截] 当前 10D 出口安全分 {} 低于全局阈值 {}",
            snap.risk_assessment.score, snap.config.min_global_safety_score
        ));
    }

    allow(format!(
        "出口合规安全（安全分 {safety_score}/100，缓存命中 O(1)）"
    ))
}

/// Thread-safe O(1) snapshot container backed by `Arc<RwLock<GuardSnapshot>>`.
#[derive(Clone, Debug)]
pub struct SnapshotStore {
    inner: Arc<RwLock<GuardSnapshot>>,
}

impl SnapshotStore {
    /// Creates a new store initialized with `initial`.
    pub fn new(initial: GuardSnapshot) -> Self {
        Self {
            inner: Arc::new(RwLock::new(initial)),
        }
    }

    /// Reads the current snapshot in O(1) with zero syscalls or process scans.
    pub fn read(&self) -> GuardSnapshot {
        match self.inner.read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Atomically replaces the stored snapshot.
    pub fn replace(&self, next: GuardSnapshot) {
        match self.inner.write() {
            Ok(mut guard) => *guard = next,
            Err(mut poisoned) => **poisoned.get_mut() = next,
        }
    }

    /// Mutates the snapshot under the write lock.
    pub fn update(&self, f: impl FnOnce(&mut GuardSnapshot)) {
        match self.inner.write() {
            Ok(mut guard) => f(&mut guard),
            Err(mut poisoned) => f(poisoned.get_mut()),
        }
    }
}

/// Control signal returned by [`CoordinatorActor::on_event`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActorControl {
    Continue,
    Stop,
}

/// Telemetry bundle computed off-thread and published into [`GuardEngine`].
#[derive(Clone, Debug)]
pub struct TelemetryBundle {
    pub cfg_rev: u64,
    pub runtime_epoch: u64,
    pub agents: Vec<AgentRuntimeStatus>,
    pub leak: LeakReport,
    pub leak_shield: LeakShieldStatus,
    pub mihomo: MihomoStatus,
    pub env: EnvCheck,
    pub antigravity_proxy: AntigravityProxyStatus,
    pub self_check: DefenseSelfCheck,
    pub updates: Option<UpdateSummary>,
    pub wfp: WfpStatus,
    pub risk_assessment: Option<RiskAssessment>,
    pub hooks: HookIntegrationStatus,
    pub suspicious_oauth_processes: Vec<String>,
    pub now_secs: u64,
}

/// Events serialized by the single-writer coordinator thread.
pub enum CoordinatorEvent {
    Pipe {
        req: PipeRequest,
        reply: SyncSender<PipeResponse>,
    },
    Tick,
    SystemResumed,
    SystemShuttingDown,
    RoundFinished {
        cfg_rev: u64,
        runtime_epoch: u64,
        purpose: CheckPurpose,
        access: AccessEvidence,
        probes: Vec<(String, ProbeResult)>,
        now_secs: u64,
    },
    SingleTargetProbed {
        cfg_rev: u64,
        runtime_epoch: u64,
        target_id: String,
        access: AccessEvidence,
        probe: ProbeResult,
        now_secs: u64,
        reply: SyncSender<PipeResponse>,
    },
    FeishuTestFinished {
        result: Result<FeishuStatus, String>,
        now_secs: u64,
        reply: SyncSender<PipeResponse>,
    },
    AntigravityRepairFinished {
        result: Result<String, String>,
        now_secs: u64,
        reply: SyncSender<PipeResponse>,
    },
    /// Background re-injection of `version.dll` after Antigravity overwrote it (no pipe reply).
    AntigravityAutoRepairFinished {
        result: Result<String, String>,
        now_secs: u64,
        trigger_state: AntigravityProxyState,
    },
    MihomoSwitchFinished {
        cfg_rev: u64,
        runtime_epoch: u64,
        result: Result<String, String>,
        mihomo: MihomoStatus,
        now_secs: u64,
        reply: SyncSender<PipeResponse>,
    },
    Telemetry(Box<TelemetryBundle>),
    UpdatesChecked {
        summary: Box<UpdateSummary>,
        component: Option<String>,
        now_secs: u64,
        reply: Option<SyncSender<PipeResponse>>,
    },
    DeepRiskAuditFinished {
        assessment: Box<RiskAssessment>,
        now_secs: u64,
        reply: Option<SyncSender<PipeResponse>>,
    },
    WslBridgeSynced {
        status: Box<WslBridgeStatus>,
        now_secs: u64,
        reply: Option<SyncSender<PipeResponse>>,
    },
    UpdateWslBridgeStatus {
        status: Box<WslBridgeStatus>,
    },
    ExportDiagnosticsFinished {
        result: Result<PathBuf, String>,
        now_secs: u64,
        reply: SyncSender<PipeResponse>,
    },
    HealthCardBuilt {
        card: Box<SanitizedHealthCard>,
        export_png: bool,
        now_secs: u64,
        reply: SyncSender<PipeResponse>,
    },
    CleanRoomScanned {
        report: Box<CleanRoomReport>,
        backup_count: usize,
        now_secs: u64,
        reply: SyncSender<PipeResponse>,
    },
    CleanRoomExecuted {
        result: Result<(CleanRoomBackupMeta, CleanRoomReport, usize), String>,
        now_secs: u64,
        reply: SyncSender<PipeResponse>,
    },
    CleanRoomRestored {
        backup_id: String,
        result: Result<usize, String>,
        now_secs: u64,
        reply: SyncSender<PipeResponse>,
    },
    VaultShortcutsGenerated {
        vault_id: String,
        vault_name: String,
        result: Result<usize, String>,
        now_secs: u64,
        reply: SyncSender<PipeResponse>,
    },
    CliHooksConfigured {
        result: Result<HookIntegrationStatus, String>,
        now_secs: u64,
        reply: SyncSender<PipeResponse>,
    },
    VaultLaunchFinished {
        vault: Box<AccountVault>,
        app: VaultAppTarget,
        outcome: Box<VaultLaunchWorkerOutcome>,
        now_secs: u64,
        reply: SyncSender<PipeResponse>,
    },
    PortEgressProbed {
        observations: Vec<PortEgressObservation>,
        now_secs: u64,
    },
    BeginStopping {
        reply: SyncSender<Result<OperationReceipt, String>>,
    },
    Shutdown,
}

/// Context passed to [`CoordinatorActor::on_event`].
pub struct CoordinatorContext<'a> {
    pub snapshot: &'a SnapshotStore,
    pub event_tx: &'a SyncSender<CoordinatorEvent>,
    pub burst_guard: &'a Arc<Mutex<BurstGuardTracker>>,
    pub hook_metrics: &'a Arc<HookGateMetrics>,
    pub port_egress: &'a Arc<RwLock<HashMap<u16, PortEgressObservation>>>,
}

/// Stateful single-writer actor owned exclusively by the coordinator thread.
pub trait CoordinatorActor: Send + 'static {
    fn on_event(&mut self, event: CoordinatorEvent, ctx: &CoordinatorContext<'_>) -> ActorControl;
}

/// Cloneable handle to submit mutations/events or read O(1) [`GuardSnapshot`]s.
#[derive(Clone)]
pub struct CoordinatorHandle {
    snapshot: SnapshotStore,
    tx: SyncSender<CoordinatorEvent>,
    stopped: Arc<AtomicBool>,
    worker: Arc<Mutex<Option<JoinHandle<()>>>>,
    burst_guard: Arc<Mutex<BurstGuardTracker>>,
    hook_metrics: Arc<HookGateMetrics>,
    port_egress: Arc<RwLock<HashMap<u16, PortEgressObservation>>>,
}

impl CoordinatorHandle {
    /// Returns the latest committed [`GuardSnapshot`] in O(1) with zero syscalls or queue wait.
    pub fn snapshot(&self) -> GuardSnapshot {
        self.snapshot.read()
    }

    /// Updates the published snapshot directly (mainly for tests).
    pub fn update_snapshot(&self, f: impl FnOnce(&mut GuardSnapshot)) {
        self.snapshot.update(f);
    }

    /// Replaces the published snapshot atomically.
    pub fn replace_snapshot(&self, next: GuardSnapshot) {
        self.snapshot.replace(next);
    }

    /// Returns a clone of the coordinator event sender for background workers.
    pub fn event_sender(&self) -> SyncSender<CoordinatorEvent> {
        self.tx.clone()
    }

    /// Returns shared BurstGuard tracker handle.
    pub fn burst_guard(&self) -> Arc<Mutex<BurstGuardTracker>> {
        self.burst_guard.clone()
    }

    /// Returns `(total_checks, total_blocks, last_latency_us)` recorded by `FastHookGate`.
    pub fn hook_gate_metrics(&self) -> (u64, u64, u64) {
        self.hook_metrics.snapshot_counts()
    }

    /// Computes live [`BurstGuardStatus`] for the given [`Config`].
    pub fn burst_guard_status(&self, cfg: &Config) -> BurstGuardStatus {
        let tracker = self.burst_guard.lock().unwrap_or_else(|e| e.into_inner());
        tracker.overall_status(now_unix_millis(), &BurstGuardConfig::from_config(cfg))
    }

    /// Updates suspicious unauthorized third-party OAuth processes observed by netwatch.
    pub fn set_suspicious_oauth_processes(&self, processes: Vec<String>) {
        let mut tracker = self.burst_guard.lock().unwrap_or_else(|e| e.into_inner());
        tracker.set_suspicious_oauth_processes(processes);
    }

    /// Records whether WSL2 proxy desync (`SystemProxy` host + empty WSL `HTTPS_PROXY`) was observed.
    pub fn set_wsl_proxy_desync(&self, detected: bool) {
        self.hook_metrics
            .wsl_proxy_desync
            .store(detected, Ordering::Relaxed);
    }

    /// Returns whether WSL2 proxy desync was observed.
    pub fn wsl_proxy_desync(&self) -> bool {
        self.hook_metrics.wsl_proxy_desync.load(Ordering::Relaxed)
    }

    /// Publishes an updated [`WslBridgeStatus`] asynchronously to the coordinator actor.
    pub fn update_wsl_bridge_status(&self, status: WslBridgeStatus) {
        if !self.stopped.load(Ordering::Acquire) {
            let _ = self.tx.try_send(CoordinatorEvent::UpdateWslBridgeStatus {
                status: Box::new(status),
            });
        }
    }

    /// Reads a clone of the cached per-port dedicated Vault egress map in O(1).
    pub fn port_egress_map(&self) -> HashMap<u16, PortEgressObservation> {
        match self.port_egress.read() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// Publishes background dedicated-port egress observations into the shared cache and coordinator.
    pub fn publish_port_egress(&self, observations: Vec<PortEgressObservation>, now_secs: u64) {
        if observations.is_empty() {
            return;
        }
        {
            let mut guard = match self.port_egress.write() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            for obs in &observations {
                guard.insert(obs.port, obs.clone());
            }
        }
        if !self.stopped.load(Ordering::Acquire) {
            let _ = self.tx.try_send(CoordinatorEvent::PortEgressProbed {
                observations,
                now_secs,
            });
        }
    }

    /// Executes the O(1) `<2ms` `FastHookGate` fast path, falling back to the coordinator
    /// queue only when the snapshot is stale or unverified.
    pub fn fast_hook_gate(
        &self,
        agent_id: &str,
        vault_id: Option<&str>,
        hook_event: Option<&str>,
    ) -> PipeResponse {
        let started = Instant::now();
        let snap = self.snapshot.read();
        let now_s = now_unix_secs();
        let now_ms = now_unix_millis();
        let ports = self.port_egress_map();

        let resp = match evaluate_fast_hook_gate_with_ports_at(
            &snap,
            &self.burst_guard,
            &ports,
            agent_id,
            vault_id,
            hook_event,
            now_s,
            now_ms,
        ) {
            FastGateOutcome::Immediate(resp) => resp,
            FastGateOutcome::NeedsSyncProbe => {
                self.dispatch_to_coordinator(PipeRequest::FastHookGate {
                    agent_id: agent_id.to_string(),
                    vault_id: vault_id.map(str::to_string),
                    hook_event: hook_event.map(str::to_string),
                })
            }
        };

        let elapsed_us = started.elapsed().as_micros().min(u64::MAX as u128) as u64;
        let allowed = matches!(resp, PipeResponse::FastGateVerdict { allowed: true, .. });
        self.hook_metrics.record(allowed, elapsed_us);
        resp
    }

    /// Dispatches a [`PipeRequest`].
    ///
    /// - `GetSnapshot` reads `Arc<RwLock<GuardSnapshot>>` directly in O(1).
    /// - `FastHookGate` evaluates in O(1) on fresh snapshots without entering the mutation queue.
    /// - All other operations are serialized FIFO through the single-writer queue.
    pub fn dispatch(&self, req: PipeRequest) -> PipeResponse {
        if matches!(req, PipeRequest::GetSnapshot) {
            return PipeResponse::Snapshot {
                snapshot: Box::new(self.snapshot.read()),
            };
        }
        if let PipeRequest::FastHookGate {
            ref agent_id,
            ref vault_id,
            ref hook_event,
        } = req
        {
            return self.fast_hook_gate(agent_id, vault_id.as_deref(), hook_event.as_deref());
        }
        self.dispatch_to_coordinator(req)
    }

    fn dispatch_to_coordinator(&self, req: PipeRequest) -> PipeResponse {
        if self.stopped.load(Ordering::Acquire) {
            return PipeResponse::Error {
                code: ErrorCode::Busy,
                message: "daemon coordinator is shutting down".into(),
                receipt: None,
            };
        }
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        match self.tx.try_send(CoordinatorEvent::Pipe {
            req,
            reply: reply_tx,
        }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                return PipeResponse::Error {
                    code: ErrorCode::Busy,
                    message: "mutation coordinator queue is full".into(),
                    receipt: None,
                };
            }
            Err(TrySendError::Disconnected(_)) => {
                return PipeResponse::Error {
                    code: ErrorCode::Internal,
                    message: "mutation coordinator stopped".into(),
                    receipt: None,
                };
            }
        }
        reply_rx.recv().unwrap_or_else(|_| PipeResponse::Error {
            code: ErrorCode::Internal,
            message: "mutation coordinator exited before replying".into(),
            receipt: None,
        })
    }

    /// Enqueues a background monitor tick (non-blocking; drops cleanly if busy).
    pub fn try_tick(&self) {
        if !self.stopped.load(Ordering::Acquire) {
            let _ = self.tx.try_send(CoordinatorEvent::Tick);
        }
    }

    /// Notifies the coordinator that Windows resumed from sleep/hibernate (`PBT_APMRESUME*`).
    pub fn notify_system_resumed(&self) {
        if !self.stopped.load(Ordering::Acquire) {
            let _ = self.tx.try_send(CoordinatorEvent::SystemResumed);
        }
    }

    /// Notifies the coordinator that Windows shutdown/reboot has started (`SERVICE_CONTROL_PRESHUTDOWN` / `SHUTDOWN`).
    pub fn notify_system_shutting_down(&self) {
        if !self.stopped.load(Ordering::Acquire) {
            let _ = self.tx.try_send(CoordinatorEvent::SystemShuttingDown);
        }
    }

    /// Enqueues off-thread telemetry updates (non-blocking).
    pub fn try_send_telemetry(&self, bundle: TelemetryBundle) {
        if !self.stopped.load(Ordering::Acquire) {
            let _ = self
                .tx
                .try_send(CoordinatorEvent::Telemetry(Box::new(bundle)));
        }
    }

    /// Drives the engine's `BeginStopping` Flow B cleanup protocol synchronously.
    pub fn begin_stopping_flow_b(&self) -> Result<OperationReceipt, String> {
        if self.stopped.load(Ordering::Acquire) {
            return Err("coordinator already stopped".to_string());
        }
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        self.tx
            .send(CoordinatorEvent::BeginStopping { reply: reply_tx })
            .map_err(|_| "coordinator channel disconnected".to_string())?;
        reply_rx
            .recv()
            .map_err(|_| "coordinator dropped stop reply".to_string())?
    }

    /// Signals the single-writer thread to stop and joins it (idempotent).
    pub fn shutdown(&self) {
        if !self.stopped.swap(true, Ordering::AcqRel) {
            let _ = self.tx.send(CoordinatorEvent::Shutdown);
        }
        if let Ok(mut guard) = self.worker.lock() {
            if let Some(handle) = guard.take() {
                let _ = handle.join();
            }
        }
    }
}

/// Starts the single-writer mutation coordinator thread from a factory receiving its [`CoordinatorEvent`] sender.
pub fn start_coordinator_with<T, F>(factory: F) -> (CoordinatorHandle, T)
where
    F: FnOnce(SyncSender<CoordinatorEvent>) -> (GuardSnapshot, Box<dyn CoordinatorActor>, T),
{
    let (tx, rx) = mpsc::sync_channel::<CoordinatorEvent>(QUEUE_CAPACITY);
    let (initial_snapshot, mut actor, extra) = factory(tx.clone());
    let snapshot = SnapshotStore::new(initial_snapshot);
    let stopped = Arc::new(AtomicBool::new(false));
    let burst_guard = Arc::new(Mutex::new(BurstGuardTracker::new()));
    let hook_metrics = Arc::new(HookGateMetrics::default());
    let port_egress = Arc::new(RwLock::new(HashMap::new()));

    let worker_snapshot = snapshot.clone();
    let worker_tx = tx.clone();
    let worker_burst = burst_guard.clone();
    let worker_metrics = hook_metrics.clone();
    let worker_ports = port_egress.clone();

    let handle = std::thread::Builder::new()
        .name("cg-mutation-coordinator".to_string())
        .spawn(move || {
            let ctx = CoordinatorContext {
                snapshot: &worker_snapshot,
                event_tx: &worker_tx,
                burst_guard: &worker_burst,
                hook_metrics: &worker_metrics,
                port_egress: &worker_ports,
            };
            while let Ok(event) = rx.recv() {
                if matches!(event, CoordinatorEvent::Shutdown) {
                    break;
                }
                if actor.on_event(event, &ctx) == ActorControl::Stop {
                    break;
                }
            }
        })
        .expect("failed to spawn mutation coordinator thread");

    (
        CoordinatorHandle {
            snapshot,
            tx,
            stopped,
            worker: Arc::new(Mutex::new(Some(handle))),
            burst_guard,
            hook_metrics,
            port_egress,
        },
        extra,
    )
}

/// Starts the single-writer mutation coordinator thread and returns its [`CoordinatorHandle`].
pub fn start_coordinator(
    initial_snapshot: GuardSnapshot,
    actor: Box<dyn CoordinatorActor>,
) -> CoordinatorHandle {
    let (handle, ()) = start_coordinator_with(|_| (initial_snapshot, actor, ()));
    handle
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        AccessLevel, BurstGuardMode, GeoVelocityAlert, IpPurityReport, SafetyGrade, TargetStatus,
    };
    use cg_protocol::default_builtin_targets;
    use std::time::Duration;

    struct BlockingCoordinatorActor;

    impl CoordinatorActor for BlockingCoordinatorActor {
        fn on_event(
            &mut self,
            event: CoordinatorEvent,
            _ctx: &CoordinatorContext<'_>,
        ) -> ActorControl {
            match event {
                CoordinatorEvent::Pipe { req, reply } => {
                    if matches!(req, PipeRequest::RecheckNow { .. }) {
                        // Simulate a slow blocking mutation inside coordinator thread.
                        std::thread::sleep(Duration::from_millis(350));
                        let _ = reply.send(PipeResponse::Ack {
                            receipt: None,
                            snapshot: None,
                        });
                    } else if matches!(req, PipeRequest::FastHookGate { .. }) {
                        let _ = reply.send(PipeResponse::FastGateVerdict {
                            allowed: true,
                            decision: HookDecision::Allow,
                            safety_score: 80,
                            reason: "fallback sync probe ok".into(),
                            latency_path: "sync_probe_fallback".into(),
                        });
                    }
                }
                CoordinatorEvent::Shutdown => return ActorControl::Stop,
                _ => {}
            }
            ActorControl::Continue
        }
    }

    fn healthy_fresh_snapshot(now_s: u64) -> GuardSnapshot {
        let mut target = default_builtin_targets(&[], &["US".into()])
            .into_iter()
            .next()
            .unwrap();
        target.id = "claude".into();
        let mut ts = TargetStatus::from_target(&target, TargetState::Pass);
        ts.ip = Some("198.51.100.20".into());
        ts.country = Some("US".into());
        ts.checked_at = Some(now_s);
        GuardSnapshot {
            lifecycle: Lifecycle::Armed,
            protection: ProtectionState::Monitoring,
            checked_at: Some(now_s),
            access: AccessEvidence {
                level: AccessLevel::Tun,
                ..Default::default()
            },
            targets: vec![ts],
            risk_assessment: RiskAssessment {
                score: 92,
                grade: SafetyGrade::S,
                evaluated_at: now_s,
                ip_purity: IpPurityReport {
                    ip: Some("198.51.100.20".into()),
                    country: Some("US".into()),
                    asn: Some(7922),
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn fast_hook_gate_o1_bypasses_blocked_coordinator_in_sub_2ms() {
        let now_s = now_unix_secs();
        let snap = healthy_fresh_snapshot(now_s);
        let coord = start_coordinator(snap, Box::new(BlockingCoordinatorActor));

        // Block coordinator thread for 350ms on a background thread.
        let c_slow = coord.clone();
        let slow_thread = std::thread::spawn(move || {
            let _ = c_slow.dispatch(PipeRequest::RecheckNow { target_id: None });
        });
        std::thread::sleep(Duration::from_millis(25));

        // Fire 100 FastHookGate requests while coordinator is completely blocked.
        let started = Instant::now();
        for _ in 0..100 {
            let resp = coord.dispatch(PipeRequest::FastHookGate {
                agent_id: "claude-code".into(),
                vault_id: None,
                hook_event: Some("PreToolUse".into()),
            });
            match resp {
                PipeResponse::FastGateVerdict {
                    allowed,
                    decision,
                    safety_score,
                    latency_path,
                    ..
                } => {
                    assert!(allowed);
                    assert_eq!(decision, HookDecision::Allow);
                    assert_eq!(safety_score, 92);
                    assert_eq!(latency_path, "fast_o1");
                }
                other => panic!("unexpected fast gate verdict: {other:?}"),
            }
        }
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_millis(150),
            "100 O(1) FastHookGate calls must bypass blocked coordinator (<1.5ms avg), took {elapsed:?}"
        );
        let (checks, blocks, _) = coord.hook_gate_metrics();
        assert_eq!(checks, 100);
        assert_eq!(blocks, 0);

        slow_thread.join().unwrap();
        coord.shutdown();
    }

    #[test]
    fn fast_hook_gate_enforces_vault_pinning_cooldown_stale_fallback_and_burst_throttle() {
        let now_s = 1_700_000_500u64;
        let now_ms = now_s * 1000;
        let mut snap = healthy_fresh_snapshot(now_s);
        let mut jp_vault = AccountVault {
            id: "jp-work".into(),
            name: "日本工作号".into(),
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
        jp_vault.normalize();
        snap.config.vaults.push(jp_vault);

        let tracker = Mutex::new(BurstGuardTracker::new());

        // 1) Vault region mismatch (egress is US, vault requires JP) -> immediate O(1) block.
        let mismatch = evaluate_fast_hook_gate_at(
            &snap,
            &tracker,
            "claude-code",
            Some("jp-work"),
            None,
            now_s,
            now_ms,
        );
        assert!(matches!(
            mismatch,
            FastGateOutcome::Immediate(PipeResponse::FastGateVerdict {
                allowed: false,
                decision: HookDecision::Block,
                ..
            })
        ));

        // 2) Geo-velocity active cooldown blocks immediately.
        let mut cool_snap = snap.clone();
        cool_snap.risk_assessment.geo_velocity_alert = Some(GeoVelocityAlert {
            from_country: "US".into(),
            to_country: "JP".into(),
            distance_km: 8800,
            cooldown_until: Some(now_s + 300),
            ..Default::default()
        });
        let cool = evaluate_fast_hook_gate_at(
            &cool_snap,
            &tracker,
            "claude-code",
            None,
            None,
            now_s,
            now_ms,
        );
        assert!(matches!(
            cool,
            FastGateOutcome::Immediate(PipeResponse::FastGateVerdict {
                allowed: false,
                decision: HookDecision::Block,
                ..
            })
        ));

        // 3) Stale snapshot (> hook_freshness_ttl_secs) requests sync probe fallback
        //    WITHOUT mutating BurstGuardTracker (no duplicate counting).
        let stale_tracker = Mutex::new(BurstGuardTracker::new());
        let mut stale_snap = snap.clone();
        stale_snap.checked_at = Some(now_s.saturating_sub(120));
        let stale = evaluate_fast_hook_gate_at(
            &stale_snap,
            &stale_tracker,
            "claude-code",
            None,
            None,
            now_s,
            now_ms,
        );
        assert_eq!(stale, FastGateOutcome::NeedsSyncProbe);
        assert_eq!(
            stale_tracker
                .lock()
                .unwrap()
                .overall_status(now_ms, &BurstGuardConfig::default())
                .prompts_last_1m,
            0,
            "NeedsSyncProbe must never record a BurstGuard event"
        );

        // 4) BurstGuard ThrottleGate blocks once 1m prompt count exceeds threshold.
        let mut burst_snap = snap.clone();
        burst_snap.config.burst_guard_mode = BurstGuardMode::ThrottleGate;
        burst_snap.config.burst_warn_rpm = 3;
        burst_snap.config.burst_throttle_rpm = 4;
        let fresh_tracker = Mutex::new(BurstGuardTracker::new());
        for i in 0..4u64 {
            let out = evaluate_fast_hook_gate_at(
                &burst_snap,
                &fresh_tracker,
                "claude-code",
                None,
                None,
                now_s,
                now_ms + i * 500,
            );
            assert!(matches!(
                out,
                FastGateOutcome::Immediate(PipeResponse::FastGateVerdict { allowed: true, .. })
            ));
        }
        let blocked = evaluate_fast_hook_gate_at(
            &burst_snap,
            &fresh_tracker,
            "claude-code",
            None,
            None,
            now_s,
            now_ms + 2_500,
        );
        assert!(matches!(
            blocked,
            FastGateOutcome::Immediate(PipeResponse::FastGateVerdict {
                allowed: false,
                decision: HookDecision::Block,
                ..
            })
        ));
    }
}
