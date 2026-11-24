//! Deterministic GuardEngine state machine implementing `CONTRACT-v3.10.md`.
//!
//! Pure reducer signature:
//! `(EngineState, EngineEvent, now_secs) -> (EngineState, Vec<EffectCommand>)`
//!
//! Zero OS/network/disk I/O lives in this module; all side effects are emitted as
//! explicit [`EffectCommand`] values and verified via follow-up completion events.

use std::collections::{BTreeMap, VecDeque};

use crate::policy;
use crate::targets;
use crate::timeline::{BUCKETS_48, TimelineAggregator};
use cg_protocol::{
    AccessEvidence, AgentRuntimeStatus, AnchorKind, AntigravityProxyStatus, AppliedEnv, Config,
    CutMode, DefenseSelfCheck, EnvCheck, ErrorCode, GuardSnapshot, LeakReport, Lifecycle, LogEntry,
    LogLevel, OperationReceipt, OperationStatus, PolicyPreset, PolicyVerdict, ProbeResult,
    ProtectionState, SNAPSHOT_SCHEMA_VERSION, Target, TargetState, TargetStatus, TripInfo,
    UpdateCheckPhase, UpdateSummary, is_legal_state_pair, normalize_ip,
};

const MAX_LOG_ENTRIES: usize = 500;

/// Why a check round was initiated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckPurpose {
    Monitor,
    Manual,
    Launch,
}

/// Captures the exact monotonic round ID, config revision, and runtime epoch a check round was started under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoundToken {
    pub round_id: u64,
    pub cfg_rev: u64,
    pub runtime_epoch: u64,
    pub purpose: CheckPurpose,
    pub started_at: u64,
}

/// Pending multi-step system mutation awaiting post-mutation verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingTxKind {
    Isolation,
    FlowANetworkRestore,
    FlowAAppRelease,
    FlowBDisarmRestore,
    StoppingRestore,
}

/// Active transaction metadata attached to an in-flight `Recovering` or `Isolating` state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingTransaction {
    pub tx_id: String,
    pub kind: PendingTxKind,
    pub runtime_epoch: u64,
    pub started_at: u64,
}

/// Result of querying the synchronous Launch Gate (`CONTRACT-v3.10.md` §2.6 #4, §3.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaunchDecision {
    pub allowed: bool,
    pub reason: String,
    pub requires_recheck: bool,
}

/// Complete deterministic state of the ClaudeGuard engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EngineState {
    pub version: String,
    pub platform: String,
    pub network_isolation_supported: bool,
    pub global_cut_ready: bool,
    pub lifecycle: Lifecycle,
    pub protection: ProtectionState,
    pub config: Config,
    pub cfg_rev: u64,
    pub runtime_epoch: u64,
    pub next_round_id: u64,
    pub checking: bool,
    pub active_round: Option<RoundToken>,
    pub checked_at: Option<u64>,
    pub target_statuses: Vec<TargetStatus>,
    /// Last verified compliant egress IP (normalized) per target id under the current `cfg_rev` / epoch.
    pub last_pass_ips: BTreeMap<String, String>,
    /// Dedup flag so IP-unchanged trip suppression notifies once per incident until recovered.
    pub ip_unchanged_hold_notified: bool,
    /// Dedup flag so `monitor_only` warns once per incident until recovered.
    pub monitor_only_warn_notified: bool,
    pub access: AccessEvidence,
    pub access_streak: u32,
    pub paused_until: Option<u64>,
    pub pause_duration_secs: Option<u64>,
    pub last_step_wall_secs: Option<u64>,
    pub resume_grace_until: Option<u64>,
    pub lockdown_applied: Option<bool>,
    pub lockdown_manual: bool,
    pub tripped: Option<TripInfo>,
    pub disarmed_reason: String,
    pub launch_error: String,
    pub last_error: String,
    pub last_receipt: Option<OperationReceipt>,
    pub antigravity_proxy: AntigravityProxyStatus,
    pub updates: UpdateSummary,
    pub leak: LeakReport,
    pub env: EnvCheck,
    pub env_applied: Option<AppliedEnv>,
    pub self_check: DefenseSelfCheck,
    pub timeline: TimelineAggregator,
    pub logs: VecDeque<LogEntry>,
    pub next_log_id: u64,
    pub pending_tx: Option<PendingTransaction>,
}

impl EngineState {
    /// Constructs initial engine state from a migrated [`Config`] and platform capability flags.
    pub fn new(
        mut config: Config,
        network_isolation_supported: bool,
        global_cut_ready: bool,
        now_secs: u64,
    ) -> Self {
        config.migrate();
        let lifecycle = if config.first_run {
            Lifecycle::Unconfigured
        } else {
            Lifecycle::Armed
        };
        let target_statuses = initial_target_statuses(&config);
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            platform: std::env::consts::OS.to_string(),
            network_isolation_supported,
            global_cut_ready,
            lifecycle,
            protection: ProtectionState::Pending,
            cfg_rev: 0,
            runtime_epoch: 1,
            next_round_id: 1,
            checking: false,
            active_round: None,
            checked_at: None,
            target_statuses,
            last_pass_ips: BTreeMap::new(),
            ip_unchanged_hold_notified: false,
            monitor_only_warn_notified: false,
            access: AccessEvidence {
                observed_at: now_secs,
                ..AccessEvidence::default()
            },
            access_streak: 0,
            paused_until: None,
            pause_duration_secs: None,
            last_step_wall_secs: (now_secs > 0).then_some(now_secs),
            resume_grace_until: None,
            lockdown_applied: None,
            lockdown_manual: false,
            tripped: None,
            disarmed_reason: String::new(),
            launch_error: String::new(),
            last_error: String::new(),
            last_receipt: None,
            antigravity_proxy: AntigravityProxyStatus::default(),
            updates: UpdateSummary::default(),
            leak: LeakReport::not_applicable("skipped", "尚未观察", now_secs),
            env: EnvCheck {
                note: "尚未检查".into(),
                ..EnvCheck::default()
            },
            env_applied: None,
            self_check: DefenseSelfCheck {
                checked_at: now_secs,
                ..DefenseSelfCheck::default()
            },
            timeline: TimelineAggregator::new(BUCKETS_48),
            logs: VecDeque::new(),
            next_log_id: 1,
            pending_tx: None,
            config,
        }
    }

    pub fn is_paused(&self, now_secs: u64) -> bool {
        self.paused_until.is_some_and(|until| until > now_secs)
    }

    pub fn is_in_resume_grace(&self, now_secs: u64) -> bool {
        self.resume_grace_until
            .is_some_and(|until| now_secs < until)
    }

    /// Activates the 20-second post-sleep/hibernate network reconnect grace window (`[C-04]`).
    pub fn notify_system_resumed(&mut self, now_secs: u64) {
        self.last_step_wall_secs = Some(now_secs);
        self.resume_grace_until = Some(now_secs.saturating_add(20));
        self.access_streak = 0;
        for st in &mut self.target_statuses {
            st.fail_streak = 0;
        }
        self.push_log(
            now_secs,
            LogLevel::Info,
            "power",
            "检测到系统休眠唤醒，进入 20 秒网络重连缓冲期",
        );
    }

    pub fn is_tripped(&self) -> bool {
        self.tripped.is_some() || self.protection.is_isolated()
    }

    pub fn push_log(&mut self, now_secs: u64, level: LogLevel, category: &str, msg: &str) {
        let entry = LogEntry {
            id: self.next_log_id,
            timestamp: now_secs,
            level,
            category: category.to_string(),
            message: msg.to_string(),
        };
        self.next_log_id = self.next_log_id.saturating_add(1);
        if self.logs.len() >= MAX_LOG_ENTRIES {
            self.logs.pop_front();
        }
        self.logs.push_back(entry);
    }

    /// Projects an immutable UI [`GuardSnapshot`] without triggering any OS or network calls.
    pub fn to_snapshot(&self, now_secs: u64, agents: Vec<AgentRuntimeStatus>) -> GuardSnapshot {
        GuardSnapshot {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            version: self.version.clone(),
            platform: self.platform.clone(),
            network_isolation_supported: self.network_isolation_supported,
            lifecycle: self.lifecycle,
            protection: self.protection,
            cfg_rev: self.cfg_rev,
            runtime_epoch: self.runtime_epoch,
            checking: self.checking,
            checked_at: self.checked_at,
            paused_until: self.paused_until.filter(|u| *u > now_secs),
            lockdown: self.lockdown_applied == Some(true),
            lockdown_manual: self.lockdown_manual,
            preset: self.config.preset,
            theme_mode: self.config.theme_mode,
            privacy_mask_ip: self.config.privacy_mask_ip,
            config: self.config.clone(),
            targets: self.target_statuses.clone(),
            access: self.access.clone(),
            tripped: self.tripped.clone(),
            agents,
            antigravity_proxy: self.antigravity_proxy.clone(),
            updates: self.updates.clone(),
            leak: self.leak.clone(),
            env: self.env.clone(),
            env_applied: self.env_applied.clone(),
            self_check: self.self_check.clone(),
            timeline: self.timeline.snapshot(now_secs),
            launch_error: self.launch_error.clone(),
            last_error: self.last_error.clone(),
            last_receipt: self.last_receipt.clone(),
            disarmed_reason: self.disarmed_reason.clone(),
            recent_logs: self.logs.iter().cloned().collect(),
            recent_toasts: Vec::new(),
            feishu: cg_protocol::FeishuStatus::default(),
            leak_shield: cg_protocol::LeakShieldStatus::default(),
            mihomo: cg_protocol::MihomoStatus::default(),
        }
    }
}

/// Input events accepted by [`GuardEngine::step`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineEvent {
    Bootstrap {
        wal_pending: bool,
        wal_corrupt: bool,
        disarmed_reason: Option<String>,
        last_error: Option<String>,
    },
    Tick,
    StartRound {
        purpose: CheckPurpose,
    },
    RoundCompleted {
        cfg_rev: u64,
        runtime_epoch: u64,
        purpose: CheckPurpose,
        access: AccessEvidence,
        probes: Vec<(String, ProbeResult)>,
    },
    IsolationCompleted {
        runtime_epoch: u64,
        receipt: OperationReceipt,
        killed: u32,
        cli_killed: u32,
        firewall_rules: u32,
        quarantined_agents: Vec<String>,
        network_cut_applied: CutMode,
        network_note: String,
    },
    LockdownSynced {
        want: bool,
        confirmed: bool,
        query_ok: bool,
        rules: usize,
    },
    SetManualLockdown {
        on: bool,
    },
    ManualLockdownCompleted {
        on: bool,
        receipt: OperationReceipt,
        confirmed: bool,
        query_ok: bool,
        rules: usize,
    },
    Pause {
        duration_secs: Option<u64>,
    },
    RecoverSafeFlowA,
    FlowANetworkRestored {
        runtime_epoch: u64,
        receipt: OperationReceipt,
        app_isolation_intact: bool,
    },
    FlowAAppReleaseCompleted {
        runtime_epoch: u64,
        receipt: OperationReceipt,
    },
    DisarmAndRestoreFlowB {
        reason: String,
    },
    FlowBCompleted {
        runtime_epoch: u64,
        receipt: OperationReceipt,
        reason: String,
    },
    Rearm,
    RearmPersisted {
        ok: bool,
        error: Option<String>,
    },
    SaveConfig {
        next: Config,
    },
    SetPolicyPreset {
        preset: PolicyPreset,
    },
    CompleteOnboarding {
        config: Config,
    },
    ConfigPersisted {
        ok: bool,
        config: Option<Config>,
        error: Option<String>,
    },
    EnterMaintenance {
        reason: String,
        allow_while_isolated: bool,
    },
    ExitMaintenance {
        ok: bool,
        error: Option<String>,
    },
    BeginStopping,
    StopRestoreCompleted {
        runtime_epoch: u64,
        receipt: OperationReceipt,
    },
    LeakUpdated {
        report: LeakReport,
    },
    EnvUpdated {
        check: EnvCheck,
        applied: Option<AppliedEnv>,
    },
    SelfCheckUpdated {
        self_check: DefenseSelfCheck,
    },
    AntigravityProxyUpdated {
        status: AntigravityProxyStatus,
    },
    /// Single-target manual recheck completion (updates only `target_id`, preserving other targets).
    TargetRechecked {
        cfg_rev: u64,
        runtime_epoch: u64,
        target_id: String,
        access: AccessEvidence,
        probe: ProbeResult,
    },
    UpdatesChecked {
        summary: Box<UpdateSummary>,
    },
}

/// Imperative side-effect commands emitted by [`GuardEngine::step`] for execution by `cg-daemon` / `cg-platform`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EffectCommand {
    ResolveAccessAndProbe {
        cfg_rev: u64,
        runtime_epoch: u64,
        purpose: CheckPurpose,
        targets: Vec<Target>,
        enforce_access_path: bool,
        skip_network_probes: bool,
    },
    SyncLockdown {
        want: bool,
        manual: bool,
        agents: Vec<String>,
    },
    ExecuteIsolation {
        tx_id: String,
        runtime_epoch: u64,
        agents: Vec<String>,
        kill_on_fail: bool,
        kill_cli_on_fail: bool,
        quarantine_on_fail: bool,
        cut_mode: CutMode,
        reason: String,
        failing_ids: Vec<String>,
    },
    KillGuardedAgents {
        runtime_epoch: u64,
        agents: Vec<String>,
        include_claude_cli: bool,
        reason: String,
    },
    ExecuteFlowANetworkRestore {
        tx_id: String,
        runtime_epoch: u64,
        agents: Vec<String>,
    },
    ExecuteFlowAAppRelease {
        tx_id: String,
        runtime_epoch: u64,
    },
    ExecuteFlowBDisarmRestore {
        tx_id: String,
        runtime_epoch: u64,
        reason: String,
    },
    ClearDisarmMarker,
    PersistConfig {
        config: Config,
        target_cfg_rev: u64,
    },
    CommitWal {
        tx_id: String,
    },
    ClearWal,
    PersistTimeline,
    Notify {
        class: String,
        title: String,
        body: String,
    },
    AuditLog {
        category: String,
        message: String,
    },
    RequestRejected {
        code: ErrorCode,
        reason: String,
    },
    ReadyToExit,
}

/// Pure deterministic state machine orchestrating all ClaudeGuard invariants.
pub struct GuardEngine;

impl GuardEngine {
    /// Marks the engine state as resumed from system sleep/hibernate (`[C-04]`).
    pub fn notify_system_resumed(state: &mut EngineState, now_secs: u64) {
        state.notify_system_resumed(now_secs);
    }

    /// Pure transition reducer: `(EngineState, EngineEvent, now_secs) -> (EngineState, Vec<EffectCommand>)`.
    pub fn step(
        mut state: EngineState,
        event: EngineEvent,
        now_secs: u64,
    ) -> (EngineState, Vec<EffectCommand>) {
        let mut cmds = Vec::new();
        observe_wall_clock(&mut state, now_secs, &mut cmds);
        expire_pause_if_elapsed(&mut state, now_secs, &mut cmds);

        match event {
            EngineEvent::Bootstrap {
                wal_pending,
                wal_corrupt,
                disarmed_reason,
                last_error,
            } => handle_bootstrap(
                &mut state,
                wal_pending,
                wal_corrupt,
                disarmed_reason,
                last_error,
                now_secs,
                &mut cmds,
            ),
            EngineEvent::Tick => handle_tick(&mut state, now_secs, &mut cmds),
            EngineEvent::StartRound { purpose } => {
                handle_start_round(&mut state, purpose, now_secs, &mut cmds);
            }
            EngineEvent::RoundCompleted {
                cfg_rev,
                runtime_epoch,
                purpose,
                access,
                probes,
            } => handle_round_completed(
                &mut state,
                cfg_rev,
                runtime_epoch,
                purpose,
                access,
                probes,
                now_secs,
                &mut cmds,
            ),
            EngineEvent::IsolationCompleted {
                runtime_epoch,
                receipt,
                killed,
                cli_killed,
                firewall_rules,
                quarantined_agents,
                network_cut_applied,
                network_note,
            } => handle_isolation_completed(
                &mut state,
                runtime_epoch,
                receipt,
                killed,
                cli_killed,
                firewall_rules,
                quarantined_agents,
                network_cut_applied,
                network_note,
                now_secs,
                &mut cmds,
            ),
            EngineEvent::LockdownSynced {
                want,
                confirmed,
                query_ok,
                rules,
            } => handle_lockdown_synced(
                &mut state, want, confirmed, query_ok, rules, now_secs, &mut cmds,
            ),
            EngineEvent::SetManualLockdown { on } => {
                handle_set_manual_lockdown(&mut state, on, now_secs, &mut cmds);
            }
            EngineEvent::ManualLockdownCompleted {
                on,
                receipt,
                confirmed,
                query_ok,
                rules,
            } => handle_manual_lockdown_completed(
                &mut state, on, receipt, confirmed, query_ok, rules, now_secs, &mut cmds,
            ),
            EngineEvent::Pause { duration_secs } => {
                handle_pause(&mut state, duration_secs, now_secs, &mut cmds);
            }
            EngineEvent::RecoverSafeFlowA => handle_recover_flow_a(&mut state, now_secs, &mut cmds),
            EngineEvent::FlowANetworkRestored {
                runtime_epoch,
                receipt,
                app_isolation_intact,
            } => handle_flow_a_network_restored(
                &mut state,
                runtime_epoch,
                receipt,
                app_isolation_intact,
                now_secs,
                &mut cmds,
            ),
            EngineEvent::FlowAAppReleaseCompleted {
                runtime_epoch,
                receipt,
            } => handle_flow_a_app_release_completed(
                &mut state,
                runtime_epoch,
                receipt,
                now_secs,
                &mut cmds,
            ),
            EngineEvent::DisarmAndRestoreFlowB { reason } => {
                handle_disarm_flow_b(&mut state, &reason, now_secs, &mut cmds);
            }
            EngineEvent::FlowBCompleted {
                runtime_epoch,
                receipt,
                reason,
            } => handle_flow_b_completed(
                &mut state,
                runtime_epoch,
                receipt,
                &reason,
                now_secs,
                &mut cmds,
            ),
            EngineEvent::Rearm => handle_rearm(&mut state, now_secs, &mut cmds),
            EngineEvent::RearmPersisted { ok, error } => {
                handle_rearm_persisted(&mut state, ok, error, now_secs, &mut cmds);
            }
            EngineEvent::SaveConfig { next } => {
                handle_save_config(&mut state, next, false, now_secs, &mut cmds);
            }
            EngineEvent::SetPolicyPreset { preset } => {
                let mut next = state.config.clone();
                next.preset = preset;
                handle_save_config(&mut state, next, false, now_secs, &mut cmds);
            }
            EngineEvent::CompleteOnboarding { mut config } => {
                config.first_run = false;
                handle_save_config(&mut state, config, true, now_secs, &mut cmds);
            }
            EngineEvent::ConfigPersisted { ok, config, error } => {
                handle_config_persisted(&mut state, ok, config, error, now_secs, &mut cmds);
            }
            EngineEvent::EnterMaintenance {
                reason,
                allow_while_isolated,
            } => handle_enter_maintenance(
                &mut state,
                &reason,
                allow_while_isolated,
                now_secs,
                &mut cmds,
            ),
            EngineEvent::ExitMaintenance { ok, error } => {
                handle_exit_maintenance(&mut state, ok, error, now_secs, &mut cmds);
            }
            EngineEvent::BeginStopping => handle_begin_stopping(&mut state, now_secs, &mut cmds),
            EngineEvent::StopRestoreCompleted {
                runtime_epoch,
                receipt,
            } => handle_stop_restore_completed(
                &mut state,
                runtime_epoch,
                receipt,
                now_secs,
                &mut cmds,
            ),
            EngineEvent::LeakUpdated { report } => {
                handle_leak_updated(&mut state, report, now_secs, &mut cmds);
            }
            EngineEvent::EnvUpdated { check, applied } => {
                state.env = check;
                state.env_applied = applied;
            }
            EngineEvent::SelfCheckUpdated { self_check } => {
                state.self_check = self_check;
            }
            EngineEvent::AntigravityProxyUpdated { status } => {
                handle_antigravity_proxy_updated(&mut state, status, now_secs, &mut cmds);
            }
            EngineEvent::TargetRechecked {
                cfg_rev,
                runtime_epoch,
                target_id,
                access,
                probe,
            } => {
                handle_target_rechecked(
                    &mut state,
                    cfg_rev,
                    runtime_epoch,
                    target_id,
                    access,
                    probe,
                    now_secs,
                    &mut cmds,
                );
            }
            EngineEvent::UpdatesChecked { summary } => {
                handle_updates_checked(&mut state, *summary, now_secs, &mut cmds);
            }
        }

        debug_assert!(
            is_legal_state_pair(state.lifecycle, state.protection),
            "illegal state pair after step: {:?} + {:?}",
            state.lifecycle,
            state.protection
        );
        (state, cmds)
    }

    /// Evaluates whether guarded application launch is permitted (`CONTRACT-v3.10.md` §2.6 #4, §3.4).
    pub fn evaluate_launch_gate(state: &EngineState, now_secs: u64) -> LaunchDecision {
        Self::evaluate_launch_gate_for_agent(state, None, now_secs)
    }

    /// Evaluates whether launch is permitted for an optional specific agent (`"antigravity"` checks `antigravity-proxy` health first).
    pub fn evaluate_launch_gate_for_agent(
        state: &EngineState,
        agent_id: Option<&str>,
        now_secs: u64,
    ) -> LaunchDecision {
        if agent_id.is_some_and(|id| id.trim().eq_ignore_ascii_case("antigravity"))
            && state.config.require_antigravity_proxy
            && state.antigravity_proxy.installed
            && !state.antigravity_proxy.is_ready_for_launch()
        {
            return LaunchDecision {
                allowed: false,
                reason: format!(
                    "反重力透明代理未就绪（{}）：{}（若使用 antigravity-launcher / TUN / 自定义代理，可在「防漏 → 反重力代理注入」中关闭「反重力注入强制核验」）",
                    state.antigravity_proxy.state.label_zh(),
                    state.antigravity_proxy.summary
                ),
                requires_recheck: false,
            };
        }
        if state.lifecycle == Lifecycle::Unconfigured {
            return LaunchDecision {
                allowed: false,
                reason: "尚未完成初始化向导配置，禁止通过守护器启动".into(),
                requires_recheck: false,
            };
        }
        if state.lifecycle == Lifecycle::Disarmed {
            return LaunchDecision {
                allowed: false,
                reason: "已停止保护，无法通过守护器启动；请先重新布防".into(),
                requires_recheck: false,
            };
        }
        if state.lifecycle != Lifecycle::Armed {
            return LaunchDecision {
                allowed: false,
                reason: format!("当前生命周期（{}）不允许启动应用", state.lifecycle.label()),
                requires_recheck: false,
            };
        }
        if state.is_paused(now_secs) {
            return LaunchDecision {
                allowed: false,
                reason: "守护处于暂停期间，无法确认出口合规，禁止启动".into(),
                requires_recheck: false,
            };
        }
        if state.protection != ProtectionState::Monitoring || state.tripped.is_some() {
            return LaunchDecision {
                allowed: false,
                reason: format!("当前保护状态（{}）禁止启动应用", state.protection.label()),
                requires_recheck: false,
            };
        }
        if state.checked_at.is_none() {
            return LaunchDecision {
                allowed: false,
                reason: "尚未完成当前代次出口检查，需先完成探测".into(),
                requires_recheck: true,
            };
        }
        if state.network_isolation_supported
            && state.config.enforce_access_path
            && !state.access.is_known()
        {
            return LaunchDecision {
                allowed: false,
                reason: format!("接入路径未确认：{}", state.access.note),
                requires_recheck: true,
            };
        }

        let enabled: Vec<&TargetStatus> = state
            .target_statuses
            .iter()
            .filter(|s| s.state != TargetState::Disabled)
            .collect();
        if enabled.is_empty() {
            return LaunchDecision {
                allowed: false,
                reason: "没有已启用的监控目标，禁止放行".into(),
                requires_recheck: false,
            };
        }
        let failing: Vec<&str> = enabled
            .iter()
            .filter(|s| s.state == TargetState::Fail)
            .map(|s| s.name.as_str())
            .collect();
        if !failing.is_empty() {
            return LaunchDecision {
                allowed: false,
                reason: format!("{} 出口未通过白名单校验", failing.join("、")),
                requires_recheck: true,
            };
        }
        let unverified: Vec<&str> = enabled
            .iter()
            .filter(|s| s.state != TargetState::Pass)
            .map(|s| s.name.as_str())
            .collect();
        if !unverified.is_empty() {
            return LaunchDecision {
                allowed: false,
                reason: format!(
                    "{} 出口无法确认（Unverified），禁止放行",
                    unverified.join("、")
                ),
                requires_recheck: true,
            };
        }
        LaunchDecision {
            allowed: true,
            reason: String::new(),
            requires_recheck: false,
        }
    }
}

fn initial_target_statuses(cfg: &Config) -> Vec<TargetStatus> {
    cfg.targets
        .iter()
        .map(|t| {
            let st = if t.enabled {
                TargetState::Pending
            } else {
                TargetState::Disabled
            };
            TargetStatus::from_target(t, st)
        })
        .collect()
}

fn observe_wall_clock(state: &mut EngineState, now_secs: u64, cmds: &mut Vec<EffectCommand>) {
    let prev_wall = state.last_step_wall_secs;
    if let Some(prev) = prev_wall {
        let jump_limit = state
            .config
            .clamped_interval_secs()
            .saturating_mul(2)
            .max(45);
        if now_secs > prev && now_secs - prev > jump_limit {
            state.resume_grace_until = Some(now_secs.saturating_add(20));
            state.access_streak = 0;
            for st in &mut state.target_statuses {
                st.fail_streak = 0;
            }
            log_both(
                state,
                now_secs,
                LogLevel::Info,
                "power",
                "检测到系统休眠唤醒，进入 20 秒网络重连缓冲期",
                cmds,
            );
        }
    }

    if let Some(until) = state.paused_until
        && now_secs < until
    {
        if let Some(dur) = state.pause_duration_secs {
            if until.saturating_sub(now_secs) > dur {
                state.paused_until = Some(now_secs.saturating_add(dur));
            }
        } else if let Some(prev) = prev_wall
            && now_secs < prev
        {
            let rem = until.saturating_sub(prev);
            if until.saturating_sub(now_secs) > rem {
                state.paused_until = Some(now_secs.saturating_add(rem));
            }
        }
    }

    if let Some(until) = state.resume_grace_until {
        if now_secs >= until {
            state.resume_grace_until = None;
        } else if until.saturating_sub(now_secs) > 20 {
            state.resume_grace_until = Some(now_secs.saturating_add(20));
        }
    }

    if now_secs > 0 {
        state.last_step_wall_secs = Some(now_secs);
    }
}

fn expire_pause_if_elapsed(state: &mut EngineState, now_secs: u64, cmds: &mut Vec<EffectCommand>) {
    if let Some(until) = state.paused_until
        && now_secs >= until
    {
        state.paused_until = None;
        state.pause_duration_secs = None;
        log_both(
            state,
            now_secs,
            LogLevel::Info,
            "pause",
            "暂停时间已到，恢复守护检查（既有隔离保持不变）",
            cmds,
        );
    }
}

fn log_both(
    state: &mut EngineState,
    now_secs: u64,
    level: LogLevel,
    category: &str,
    msg: impl Into<String>,
    cmds: &mut Vec<EffectCommand>,
) {
    let msg = msg.into();
    state.push_log(now_secs, level, category, &msg);
    cmds.push(EffectCommand::AuditLog {
        category: category.to_string(),
        message: msg,
    });
}

fn next_tx_id(prefix: &str, epoch: u64, now_secs: u64) -> String {
    format!("{prefix}-{epoch}-{now_secs}")
}

fn clear_compliant_ip_baseline(state: &mut EngineState) {
    state.last_pass_ips.clear();
    state.ip_unchanged_hold_notified = false;
    state.monitor_only_warn_notified = false;
}

fn format_failing_reason(statuses: &[TargetStatus], access_uncovered: bool) -> String {
    let mut whitelist_names: Vec<&str> = Vec::new();
    let mut reach_names: Vec<&str> = Vec::new();
    for st in statuses {
        if st.state == TargetState::Fail {
            if st.anchor_kind == AnchorKind::Reachability {
                reach_names.push(st.name.as_str());
            } else {
                whitelist_names.push(st.name.as_str());
            }
        }
    }
    let mut parts: Vec<String> = Vec::new();
    if !whitelist_names.is_empty() {
        parts.push(format!("{} 出口不在白名单", whitelist_names.join("、")));
    }
    if !reach_names.is_empty() {
        parts.push(format!("{} 经代理不可达", reach_names.join("、")));
    }
    if !parts.is_empty() {
        parts.join("；")
    } else if access_uncovered {
        "系统代理未开启且未检测到 TUN 网卡，应用会直连真实出口".into()
    } else {
        String::new()
    }
}

/// Returns `Some(stable_ips_summary)` when automatic trip should be suppressed because proxy
/// access is intact and observed egress IPs have NOT changed from the verified compliant baseline.
///
/// Safety invariants:
/// - Never suppresses when `suppress_trip_when_ip_unchanged == false`.
/// - Never suppresses when `access_uncovered` or `access_unknown` (proxy gone = direct-IP risk).
/// - Never suppresses before a compliant baseline has been established (`last_pass_ips.is_empty()`),
///   so starting on a non-compliant/CN IP always trips.
/// - Never suppresses if ANY enabled target reports a new IP that differs from its compliant baseline,
///   or if ANY failing target lacks an observable IP (`st.ip == None`, `[C-02]`).
fn egress_ip_unchanged_summary(
    state: &EngineState,
    statuses: &[TargetStatus],
    access_uncovered: bool,
    access_unknown: bool,
) -> Option<String> {
    if !state.config.suppress_trip_when_ip_unchanged
        || access_uncovered
        || access_unknown
        || state.last_pass_ips.is_empty()
    {
        return None;
    }

    let mut matched_ips: Vec<String> = Vec::new();
    let mut any_failing = false;

    for st in statuses {
        if st.state == TargetState::Disabled {
            continue;
        }
        if st.state == TargetState::Fail {
            any_failing = true;
        }
        if let Some(cur_ip) = st.ip.as_deref().and_then(normalize_ip) {
            if let Some(base_ip) = state.last_pass_ips.get(&st.id) {
                if cur_ip != *base_ip {
                    return None;
                }
                if !matched_ips.contains(&cur_ip) {
                    matched_ips.push(cur_ip);
                }
            } else if st.state == TargetState::Fail {
                // Failing target has never passed with a verified IP under current config -> must trip!
                return None;
            }
        } else if st.state == TargetState::Fail {
            // Failing target lacks an IP (e.g. GeminiRegion or region-only probe) -> cannot prove IP unchanged!
            return None;
        }
    }

    if !any_failing {
        return None;
    }

    if matched_ips.is_empty() {
        for ip in state.last_pass_ips.values() {
            if !matched_ips.contains(ip) {
                matched_ips.push(ip.clone());
            }
        }
    }
    Some(matched_ips.join("、"))
}

fn handle_bootstrap(
    state: &mut EngineState,
    wal_pending: bool,
    wal_corrupt: bool,
    disarmed_reason: Option<String>,
    last_error: Option<String>,
    now_secs: u64,
    cmds: &mut Vec<EffectCommand>,
) {
    if let Some(err) = last_error {
        state.last_error = err;
    }
    if wal_corrupt {
        state.lifecycle = Lifecycle::Armed;
        state.protection = ProtectionState::Degraded;
        state.last_error = "恢复记录损坏，已保留现场并进入降级态".into();
        log_both(
            state,
            now_secs,
            LogLevel::Error,
            "wal",
            "检测到损坏的 WAL 恢复记录，已进入 Degraded（不自动清除保护）",
            cmds,
        );
        return;
    }
    if wal_pending {
        state.lifecycle = Lifecycle::Armed;
        state.protection = ProtectionState::Degraded;
        state.last_error = "检测到未完成的系统变更事务，等待恢复核验".into();
        log_both(
            state,
            now_secs,
            LogLevel::Warn,
            "wal",
            "检测到上次未提交的 WAL 事务，已保持 fail-closed 降级态",
            cmds,
        );
        return;
    }
    if let Some(reason) = disarmed_reason {
        state.lifecycle = Lifecycle::Disarmed;
        state.protection = ProtectionState::Monitoring;
        state.disarmed_reason = reason;
        return;
    }
    if state.config.first_run {
        state.lifecycle = Lifecycle::Unconfigured;
        state.protection = ProtectionState::Pending;
    } else {
        state.lifecycle = Lifecycle::Armed;
        state.protection = ProtectionState::Pending;
    }
}

fn handle_tick(state: &mut EngineState, now_secs: u64, cmds: &mut Vec<EffectCommand>) {
    if matches!(
        state.lifecycle,
        Lifecycle::Stopping | Lifecycle::Maintenance
    ) {
        return;
    }
    if state.checking || state.protection == ProtectionState::Recovering {
        return;
    }
    handle_start_round(state, CheckPurpose::Monitor, now_secs, cmds);
}

fn handle_start_round(
    state: &mut EngineState,
    purpose: CheckPurpose,
    now_secs: u64,
    cmds: &mut Vec<EffectCommand>,
) {
    if matches!(
        state.lifecycle,
        Lifecycle::Stopping | Lifecycle::Maintenance
    ) {
        cmds.push(EffectCommand::RequestRejected {
            code: ErrorCode::IllegalState,
            reason: "当前生命周期不允许发起新一轮检查".into(),
        });
        return;
    }
    if state.protection == ProtectionState::Recovering {
        cmds.push(EffectCommand::RequestRejected {
            code: ErrorCode::Busy,
            reason: "恢复事务正在执行，请稍后再试".into(),
        });
        return;
    }
    if state.checking && purpose != CheckPurpose::Launch {
        return;
    }
    let round_id = state.next_round_id;
    state.next_round_id = state.next_round_id.saturating_add(1);
    state.checking = true;
    state.active_round = Some(RoundToken {
        round_id,
        cfg_rev: state.cfg_rev,
        runtime_epoch: state.runtime_epoch,
        purpose,
        started_at: now_secs,
    });
    let skip_network_probes = state.lifecycle == Lifecycle::Unconfigured;
    cmds.push(EffectCommand::ResolveAccessAndProbe {
        cfg_rev: state.cfg_rev,
        runtime_epoch: state.runtime_epoch,
        purpose,
        targets: state.config.targets.clone(),
        enforce_access_path: state.network_isolation_supported
            && state.config.enforce_access_path
            && state.lifecycle != Lifecycle::Unconfigured,
        skip_network_probes,
    });
}

#[allow(clippy::too_many_arguments)]
fn handle_round_completed(
    state: &mut EngineState,
    cfg_rev: u64,
    runtime_epoch: u64,
    purpose: CheckPurpose,
    access: AccessEvidence,
    probes: Vec<(String, ProbeResult)>,
    now_secs: u64,
    cmds: &mut Vec<EffectCommand>,
) {
    let _ = purpose;
    if cfg_rev != state.cfg_rev || runtime_epoch != state.runtime_epoch {
        log_both(
            state,
            now_secs,
            LogLevel::Info,
            "round",
            format!(
                "丢弃过期轮次结果（round rev={cfg_rev}/epoch={runtime_epoch}, current rev={}/epoch={}）",
                state.cfg_rev, state.runtime_epoch
            ),
            cmds,
        );
        if state
            .active_round
            .is_some_and(|r| r.cfg_rev == cfg_rev && r.runtime_epoch == runtime_epoch)
        {
            state.checking = false;
            state.active_round = None;
        }
        return;
    }

    state.checking = false;
    state.active_round = None;
    state.access = access.clone();
    state.checked_at = Some(now_secs);

    let paused = state.is_paused(now_secs);
    let unconfigured = state.lifecycle == Lifecycle::Unconfigured;
    let armed = state.lifecycle == Lifecycle::Armed;
    let access_enforced = state.network_isolation_supported && state.config.enforce_access_path;
    let access_uncovered = access_enforced && access.is_uncovered();
    let access_unknown = access_enforced && access.is_unknown();
    let access_bad = access_uncovered || access_unknown;
    let skip_probes = unconfigured || access_bad;

    let previous = state.target_statuses.clone();
    let mut next_statuses = Vec::with_capacity(state.config.targets.len());
    let skip_reason = if unconfigured {
        "尚未完成配置，已跳过探测".to_string()
    } else if access_unknown {
        format!("接入路径无法确认，已跳过探测：{}", access.note)
    } else {
        "未接入代理链路，已跳过探测".to_string()
    };

    for target in &state.config.targets {
        if !target.enabled {
            next_statuses.push(TargetStatus::from_target(target, TargetState::Disabled));
            continue;
        }
        let mut slot = TargetStatus::from_target(target, TargetState::Pending);
        if skip_probes {
            slot.state = TargetState::Unverified;
            slot.reason = skip_reason.clone();
            slot.checked_at = Some(now_secs);
            if paused {
                slot.fail_streak = previous
                    .iter()
                    .find(|s| s.id == target.id)
                    .map(|s| s.fail_streak)
                    .unwrap_or(0);
            } else {
                slot.fail_streak = 0;
            }
            next_statuses.push(slot);
            continue;
        }

        let probe = probes
            .iter()
            .find(|(id, _)| id == &target.id)
            .map(|(_, p)| p.clone())
            .unwrap_or_else(|| ProbeResult::failed("未收到目标探测结果"));
        let eval = policy::evaluate_with_preset(target, &probe, state.config.preset);
        let prev_streak = previous
            .iter()
            .find(|s| s.id == target.id)
            .map(|s| s.fail_streak)
            .unwrap_or(0);
        let streak = match eval.verdict {
            PolicyVerdict::Fail if paused => prev_streak,
            PolicyVerdict::Fail => prev_streak.saturating_add(1),
            // Unverified and Pass both reset consecutive fail streak so Unverified never trips.
            PolicyVerdict::Pass | PolicyVerdict::Unverified => 0,
        };
        slot.apply_at(&probe, &eval, streak, now_secs);
        next_statuses.push(slot);
    }

    let failing_ids: Vec<String> = next_statuses
        .iter()
        .filter(|s| s.state == TargetState::Fail)
        .map(|s| s.id.clone())
        .collect();
    let enabled_count = next_statuses
        .iter()
        .filter(|s| s.state != TargetState::Disabled)
        .count();
    let passed_count = next_statuses
        .iter()
        .filter(|s| s.state == TargetState::Pass)
        .count();
    let max_streak = next_statuses
        .iter()
        .map(|s| s.fail_streak)
        .max()
        .unwrap_or(0);
    let max_latency_ms = next_statuses
        .iter()
        .filter(|s| s.state != TargetState::Disabled)
        .map(|s| s.latency_ms)
        .max()
        .unwrap_or(0);
    let all_pass = enabled_count > 0 && passed_count == enabled_count && !access_bad;

    if state.is_in_resume_grace(now_secs) && all_pass && !access_bad {
        state.resume_grace_until = None;
    }
    let in_resume_grace = state.is_in_resume_grace(now_secs);

    if state.network_isolation_supported && armed {
        let want_auto = !state.config.monitor_only
            && !(in_resume_grace && state.lockdown_applied != Some(true))
            && access_uncovered
            && state.config.lockdown_on_uncovered;
        let want = want_auto || state.lockdown_manual;
        let allowed = !(paused && want && state.lockdown_applied != Some(true));
        if allowed && state.lockdown_applied != Some(want) {
            cmds.push(EffectCommand::SyncLockdown {
                want,
                manual: state.lockdown_manual,
                agents: state.config.guarded_agents.clone(),
            });
        }
    }

    // Evaluate IP-unchanged hold against the PRIOR verified baseline before recording this round's passes.
    let ip_unchanged_hold =
        egress_ip_unchanged_summary(state, &next_statuses, access_uncovered, access_unknown);

    for st in &next_statuses {
        if st.state == TargetState::Pass
            && st.anchor_kind != AnchorKind::Reachability
            && let Some(norm_ip) = st.ip.as_deref().and_then(normalize_ip)
        {
            state.last_pass_ips.insert(st.id.clone(), norm_ip);
        }
    }

    if armed
        && !paused
        && !in_resume_grace
        && !state.config.monitor_only
        && ip_unchanged_hold.is_none()
        && !state.protection.is_isolated()
        && state.config.trip_threshold > 1
    {
        for status in &next_statuses {
            if status.state == TargetState::Fail
                && status.fail_streak == state.config.trip_threshold - 1
            {
                let msg = format!(
                    "{} 出口第 {} 次连续失败，再失败一次将熔断。",
                    status.name, status.fail_streak
                );
                log_both(state, now_secs, LogLevel::Warn, "probe", &msg, cmds);
                cmds.push(EffectCommand::Notify {
                    class: "warning".into(),
                    title: "ClaudeGuard 检查未通过".into(),
                    body: msg,
                });
            }
        }
    }

    state.target_statuses = next_statuses;
    if all_pass {
        state.ip_unchanged_hold_notified = false;
        state.monitor_only_warn_notified = false;
    }

    if armed {
        if access_uncovered {
            if !paused {
                state.access_streak = state.access_streak.saturating_add(1);
            }
            if !paused
                && !in_resume_grace
                && !state.config.monitor_only
                && !state.protection.is_isolated()
                && state.config.trip_threshold > 1
                && state.access_streak == state.config.trip_threshold - 1
            {
                let msg = "系统代理未开启且无 TUN 网卡，下一轮将熔断。";
                log_both(state, now_secs, LogLevel::Warn, "access", msg, cmds);
                cmds.push(EffectCommand::Notify {
                    class: "warning".into(),
                    title: "ClaudeGuard 检查未通过".into(),
                    body: msg.into(),
                });
            }
        } else {
            state.access_streak = 0;
        }
    } else {
        state.access_streak = 0;
    }

    let round_verdict = if !failing_ids.is_empty() || access_uncovered {
        Some(PolicyVerdict::Fail)
    } else if all_pass {
        Some(PolicyVerdict::Pass)
    } else {
        Some(PolicyVerdict::Unverified)
    };
    state
        .timeline
        .record(now_secs, state.protection, round_verdict, max_latency_ms);
    cmds.push(EffectCommand::PersistTimeline);

    if !armed {
        if unconfigured {
            state.launch_error = "尚未完成配置：请先在向导中设置监控目标与白名单".into();
        }
        return;
    }

    let fail_reason = format_failing_reason(&state.target_statuses, access_uncovered);

    match state.protection {
        ProtectionState::NetworkReadyAppHeld => {
            if all_pass || state.config.monitor_only {
                let tx_id = next_tx_id("flow-a-release", state.runtime_epoch, now_secs);
                state.protection = ProtectionState::Recovering;
                state.pending_tx = Some(PendingTransaction {
                    tx_id: tx_id.clone(),
                    kind: PendingTxKind::FlowAAppRelease,
                    runtime_epoch: state.runtime_epoch,
                    started_at: now_secs,
                });
                cmds.push(EffectCommand::ExecuteFlowAAppRelease {
                    tx_id,
                    runtime_epoch: state.runtime_epoch,
                });
            } else if !failing_ids.is_empty() || access_uncovered {
                state.launch_error = fail_reason.clone();
                if !paused
                    && !in_resume_grace
                    && !state.config.monitor_only
                    && state.config.kill_on_fail
                {
                    cmds.push(EffectCommand::KillGuardedAgents {
                        runtime_epoch: state.runtime_epoch,
                        agents: state.config.guarded_agents.clone(),
                        include_claude_cli: state.config.kill_cli_on_fail,
                        reason: fail_reason,
                    });
                }
            } else {
                state.launch_error = "出口尚有未确认项（Unverified），保持应用隔离".into();
            }
        }
        ProtectionState::Quarantined | ProtectionState::GlobalCut => {
            if (!failing_ids.is_empty() || access_uncovered)
                && !paused
                && !in_resume_grace
                && !state.config.monitor_only
                && state.config.kill_on_fail
            {
                cmds.push(EffectCommand::KillGuardedAgents {
                    runtime_epoch: state.runtime_epoch,
                    agents: state.config.guarded_agents.clone(),
                    include_claude_cli: state.config.kill_cli_on_fail,
                    reason: fail_reason,
                });
            }
        }
        ProtectionState::Isolating | ProtectionState::Recovering | ProtectionState::Degraded => {}
        ProtectionState::Pending | ProtectionState::Monitoring => {
            let target_trip = !failing_ids.is_empty() && max_streak >= state.config.trip_threshold;
            let access_trip =
                access_uncovered && state.access_streak >= state.config.trip_threshold;

            if state.config.monitor_only {
                state.protection = ProtectionState::Monitoring;
                if !failing_ids.is_empty() || access_uncovered {
                    state.launch_error = format!("{fail_reason}（仅监测模式，已跳过自动熔断）");
                    if (target_trip || access_trip) && !state.monitor_only_warn_notified {
                        state.monitor_only_warn_notified = true;
                        let msg = format!(
                            "仅监测模式预警：{fail_reason}，已按设置跳过自动熔断与进程终止。"
                        );
                        log_both(state, now_secs, LogLevel::Warn, "probe", &msg, cmds);
                        cmds.push(EffectCommand::Notify {
                            class: "warning".into(),
                            title: "ClaudeGuard 出口预警（仅监测）".into(),
                            body: msg,
                        });
                    }
                } else if access_unknown {
                    state.launch_error = format!("无法确认应用接入路径：{}", access.note);
                } else if all_pass {
                    state.launch_error.clear();
                } else {
                    state.launch_error = "部分目标无法确认，暂不允许启动".into();
                }
            } else if !paused && !in_resume_grace && access_trip {
                begin_isolation(state, fail_reason, failing_ids, now_secs, cmds);
            } else if !paused && !in_resume_grace && target_trip {
                if let Some(stable_ips) = ip_unchanged_hold {
                    state.protection = ProtectionState::Monitoring;
                    state.launch_error =
                        format!("{fail_reason}（出口 IP {stable_ips} 未变，已按策略暂不熔断）");
                    if !state.ip_unchanged_hold_notified {
                        state.ip_unchanged_hold_notified = true;
                        let msg = format!(
                            "{fail_reason}，但当前出口 IP（{stable_ips}）与已核验合规基线一致，已按策略跳过熔断（仅告警不杀进程）。"
                        );
                        log_both(state, now_secs, LogLevel::Warn, "probe", &msg, cmds);
                        cmds.push(EffectCommand::Notify {
                            class: "warning".into(),
                            title: "ClaudeGuard 出口波动（IP 未变，未熔断）".into(),
                            body: msg,
                        });
                    }
                } else {
                    begin_isolation(state, fail_reason, failing_ids, now_secs, cmds);
                }
            } else {
                state.protection = ProtectionState::Monitoring;
                if !failing_ids.is_empty() || access_uncovered {
                    state.launch_error = fail_reason;
                } else if access_unknown {
                    state.launch_error = format!("无法确认应用接入路径：{}", access.note);
                } else if all_pass {
                    state.launch_error.clear();
                } else {
                    state.launch_error = "部分目标无法确认，暂不允许启动".into();
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_target_rechecked(
    state: &mut EngineState,
    cfg_rev: u64,
    runtime_epoch: u64,
    target_id: String,
    access: AccessEvidence,
    probe: ProbeResult,
    now_secs: u64,
    cmds: &mut Vec<EffectCommand>,
) {
    if cfg_rev != state.cfg_rev || runtime_epoch != state.runtime_epoch {
        return;
    }
    let Some(target) = state
        .config
        .targets
        .iter()
        .find(|t| t.id == target_id && t.enabled)
        .cloned()
    else {
        return;
    };

    state.access = access.clone();
    state.checked_at = Some(now_secs);

    let paused = state.is_paused(now_secs);
    let armed = state.lifecycle == Lifecycle::Armed;
    let access_enforced = state.network_isolation_supported && state.config.enforce_access_path;
    let access_uncovered = access_enforced && access.is_uncovered();
    let access_unknown = access_enforced && access.is_unknown();
    let access_bad = access_uncovered || access_unknown;

    let prev_streak = state
        .target_statuses
        .iter()
        .find(|s| s.id == target.id)
        .map(|s| s.fail_streak)
        .unwrap_or(0);

    let mut slot = TargetStatus::from_target(&target, TargetState::Pending);
    let eval = if access_bad {
        slot.state = TargetState::Unverified;
        slot.reason = if access_unknown {
            format!("接入路径无法确认，已跳过探测：{}", access.note)
        } else {
            "未接入代理链路，已跳过探测".into()
        };
        slot.checked_at = Some(now_secs);
        slot.fail_streak = if paused { prev_streak } else { 0 };
        None
    } else {
        let ev = policy::evaluate_with_preset(&target, &probe, state.config.preset);
        let streak = match ev.verdict {
            PolicyVerdict::Fail if paused => prev_streak,
            PolicyVerdict::Fail => prev_streak.saturating_add(1),
            PolicyVerdict::Pass | PolicyVerdict::Unverified => 0,
        };
        if ev.verdict == PolicyVerdict::Pass
            && target.anchor_kind != AnchorKind::Reachability
            && let Some(norm_ip) = probe.ip.as_deref().and_then(normalize_ip)
        {
            state.last_pass_ips.insert(target.id.clone(), norm_ip);
        }
        slot.apply_at(&probe, &ev, streak, now_secs);
        Some(ev)
    };

    if let Some(existing) = state.target_statuses.iter_mut().find(|s| s.id == target.id) {
        *existing = slot.clone();
    } else {
        state.target_statuses.push(slot.clone());
    }

    let enabled_count = state
        .target_statuses
        .iter()
        .filter(|s| s.state != TargetState::Disabled)
        .count();
    let passed_count = state
        .target_statuses
        .iter()
        .filter(|s| s.state == TargetState::Pass)
        .count();
    let all_pass = enabled_count > 0 && passed_count == enabled_count && !access_bad;

    if state.is_in_resume_grace(now_secs) && all_pass {
        state.resume_grace_until = None;
    }
    let in_resume_grace = state.is_in_resume_grace(now_secs);

    let verdict_opt = eval
        .as_ref()
        .map(|e| e.verdict)
        .or(Some(PolicyVerdict::Unverified));
    state
        .timeline
        .record(now_secs, state.protection, verdict_opt, slot.latency_ms);
    cmds.push(EffectCommand::PersistTimeline);

    log_both(
        state,
        now_secs,
        if slot.state == TargetState::Fail {
            LogLevel::Warn
        } else {
            LogLevel::Info
        },
        "probe",
        format!(
            "单目标复检 [{}]：{:?}（{}）",
            slot.name,
            slot.state,
            if slot.reason.is_empty() {
                slot.matched_rule.as_deref().unwrap_or("已核验")
            } else {
                slot.reason.as_str()
            }
        ),
        cmds,
    );

    if !armed {
        return;
    }

    if state.protection == ProtectionState::NetworkReadyAppHeld {
        if all_pass || state.config.monitor_only {
            let tx_id = next_tx_id("flow-a-release", state.runtime_epoch, now_secs);
            state.protection = ProtectionState::Recovering;
            state.pending_tx = Some(PendingTransaction {
                tx_id: tx_id.clone(),
                kind: PendingTxKind::FlowAAppRelease,
                runtime_epoch: state.runtime_epoch,
                started_at: now_secs,
            });
            cmds.push(EffectCommand::ExecuteFlowAAppRelease {
                tx_id,
                runtime_epoch: state.runtime_epoch,
            });
        } else if slot.state == TargetState::Fail || access_uncovered {
            state.launch_error = format_failing_reason(&state.target_statuses, access_uncovered);
        } else {
            state.launch_error = "出口尚有未确认项（Unverified），保持应用隔离".into();
        }
        return;
    }

    if !paused
        && matches!(
            state.protection,
            ProtectionState::Pending | ProtectionState::Monitoring
        )
    {
        if slot.state == TargetState::Fail && slot.fail_streak >= state.config.trip_threshold {
            let reason = format_failing_reason(&[slot.clone()], false);
            if state.config.monitor_only {
                state.protection = ProtectionState::Monitoring;
                state.launch_error = format!("{reason}（仅监测模式，已跳过自动熔断）");
            } else if in_resume_grace {
                state.protection = ProtectionState::Monitoring;
                state.launch_error = reason;
            } else if let Some(stable_ips) = egress_ip_unchanged_summary(
                state,
                &state.target_statuses,
                access_uncovered,
                access_unknown,
            ) {
                state.protection = ProtectionState::Monitoring;
                state.launch_error =
                    format!("{reason}（出口 IP {stable_ips} 未变，已按策略暂不熔断）");
                if !state.ip_unchanged_hold_notified {
                    state.ip_unchanged_hold_notified = true;
                    log_both(
                        state,
                        now_secs,
                        LogLevel::Warn,
                        "probe",
                        format!(
                            "{reason}，但当前出口 IP（{stable_ips}）未变化，已按策略跳过熔断。"
                        ),
                        cmds,
                    );
                }
            } else {
                begin_isolation(state, reason, vec![slot.id], now_secs, cmds);
            }
        } else if all_pass {
            state.protection = ProtectionState::Monitoring;
            state.launch_error.clear();
            state.ip_unchanged_hold_notified = false;
            state.monitor_only_warn_notified = false;
        }
    }
}

fn begin_isolation(
    state: &mut EngineState,
    reason: String,
    failing_ids: Vec<String>,
    now_secs: u64,
    cmds: &mut Vec<EffectCommand>,
) {
    clear_compliant_ip_baseline(state);
    state.runtime_epoch = state.runtime_epoch.saturating_add(1);
    let epoch = state.runtime_epoch;
    state.protection = ProtectionState::Isolating;
    let tx_id = next_tx_id("isolate", epoch, now_secs);
    state.pending_tx = Some(PendingTransaction {
        tx_id: tx_id.clone(),
        kind: PendingTxKind::Isolation,
        runtime_epoch: epoch,
        started_at: now_secs,
    });

    let cut_mode = if !state.network_isolation_supported {
        CutMode::Off
    } else if state.config.cut_mode != CutMode::Off && !state.global_cut_ready {
        log_both(
            state,
            now_secs,
            LogLevel::Warn,
            "netcut",
            "全局断网请求被阻止（D2 恢复执行器未就绪），降为仅应用级隔离",
            cmds,
        );
        CutMode::Off
    } else {
        state.config.cut_mode
    };

    log_both(
        state,
        now_secs,
        LogLevel::Audit,
        "trip",
        format!("触发熔断（epoch={epoch}）：{reason}"),
        cmds,
    );

    cmds.push(EffectCommand::ExecuteIsolation {
        tx_id,
        runtime_epoch: epoch,
        agents: state.config.guarded_agents.clone(),
        kill_on_fail: state.config.kill_on_fail,
        kill_cli_on_fail: state.config.kill_cli_on_fail,
        quarantine_on_fail: state.network_isolation_supported && state.config.quarantine_on_fail,
        cut_mode,
        reason,
        failing_ids,
    });
}

#[allow(clippy::too_many_arguments)]
fn handle_isolation_completed(
    state: &mut EngineState,
    runtime_epoch: u64,
    receipt: OperationReceipt,
    killed: u32,
    cli_killed: u32,
    firewall_rules: u32,
    quarantined_agents: Vec<String>,
    network_cut_applied: CutMode,
    network_note: String,
    now_secs: u64,
    cmds: &mut Vec<EffectCommand>,
) {
    if runtime_epoch != state.runtime_epoch || state.protection != ProtectionState::Isolating {
        log_both(
            state,
            now_secs,
            LogLevel::Warn,
            "trip",
            format!("丢弃过期隔离回执（epoch={runtime_epoch}）"),
            cmds,
        );
        return;
    }
    let tx_id = state
        .pending_tx
        .take()
        .map(|tx| tx.tx_id)
        .unwrap_or_default();
    state.last_receipt = Some(receipt.clone());

    if receipt.status == OperationStatus::Verified {
        state.protection = if network_cut_applied != CutMode::Off {
            ProtectionState::GlobalCut
        } else {
            ProtectionState::Quarantined
        };
        let failing_ids: Vec<String> = state
            .target_statuses
            .iter()
            .filter(|s| s.state == TargetState::Fail)
            .map(|s| s.id.clone())
            .collect();
        let reason = if failing_ids.is_empty() {
            state.launch_error.clone()
        } else {
            format!(
                "{} 出口不在白名单",
                state
                    .target_statuses
                    .iter()
                    .filter(|s| s.state == TargetState::Fail)
                    .map(|s| s.name.as_str())
                    .collect::<Vec<_>>()
                    .join("、")
            )
        };
        let (expected_summary, observed_summary) = build_trip_diff(state);
        state.tripped = Some(TripInfo {
            since: now_secs,
            reason: reason.clone(),
            failing_ids,
            killed,
            firewall_rules,
            quarantined_agents: quarantined_agents.clone(),
            agents: quarantined_agents,
            network_cut: network_cut_applied,
            network_note,
            expected_summary,
            observed_summary,
            receipt: Some(receipt),
        });
        state.last_error.clear();
        if !tx_id.is_empty() {
            cmds.push(EffectCommand::CommitWal { tx_id });
        }
        log_both(
            state,
            now_secs,
            LogLevel::Audit,
            "trip",
            format!(
                "熔断隔离已核验：结束 {killed} 个 GUI 进程（CLI {cli_killed}），规则 {firewall_rules} 条"
            ),
            cmds,
        );
        cmds.push(EffectCommand::Notify {
            class: "trip".into(),
            title: "ClaudeGuard 已熔断".into(),
            body: format!("{reason}，已隔离相关应用；确认出口正常后可恢复。"),
        });
    } else {
        state.protection = ProtectionState::Degraded;
        state.last_error = receipt
            .error
            .clone()
            .unwrap_or_else(|| "隔离核验未通过，已保留账本并进入降级态".into());
        log_both(
            state,
            now_secs,
            LogLevel::Error,
            "trip",
            format!(
                "隔离核验失败（status={:?}）：{}",
                receipt.status, state.last_error
            ),
            cmds,
        );
    }
}

fn build_trip_diff(state: &EngineState) -> (String, String) {
    let mut expected = Vec::new();
    let mut observed = Vec::new();
    for st in &state.target_statuses {
        if st.state == TargetState::Fail {
            let exp = if !st.expect_ips.is_empty() || !st.expect_regions.is_empty() {
                format!(
                    "{}: IP={:?} 地区={:?}",
                    st.name, st.expect_ips, st.expect_regions
                )
            } else {
                format!("{}: 未配置白名单", st.name)
            };
            let obs = format!(
                "{}: IP={} 地区={}",
                st.name,
                st.ip.as_deref().unwrap_or("-"),
                st.country.as_deref().unwrap_or("-")
            );
            expected.push(exp);
            observed.push(obs);
        }
    }
    if expected.is_empty() && state.access.is_uncovered() {
        expected.push("系统代理或 TUN 网卡已接入".into());
        observed.push(state.access.note.clone());
    }
    (expected.join("；"), observed.join("；"))
}

fn handle_lockdown_synced(
    state: &mut EngineState,
    want: bool,
    confirmed: bool,
    query_ok: bool,
    rules: usize,
    now_secs: u64,
    cmds: &mut Vec<EffectCommand>,
) {
    if confirmed && query_ok {
        state.lockdown_applied = Some(want);
        log_both(
            state,
            now_secs,
            LogLevel::Info,
            "lockdown",
            if want {
                format!("兜底封锁已核验生效（{rules} 条规则）")
            } else {
                "兜底封锁已核验解除".into()
            },
            cmds,
        );
    } else {
        log_both(
            state,
            now_secs,
            LogLevel::Warn,
            "lockdown",
            "兜底封锁同步后回查未确认，下一轮将重试",
            cmds,
        );
    }
}

fn handle_set_manual_lockdown(
    state: &mut EngineState,
    on: bool,
    now_secs: u64,
    cmds: &mut Vec<EffectCommand>,
) {
    if state.lifecycle == Lifecycle::Unconfigured {
        cmds.push(EffectCommand::RequestRejected {
            code: ErrorCode::IllegalState,
            reason: "未完成向导配置前禁止手动封锁（CONTRACT §2.1）".into(),
        });
        return;
    }
    if !state.network_isolation_supported {
        cmds.push(EffectCommand::RequestRejected {
            code: ErrorCode::Unsupported,
            reason: "当前平台不支持防火墙封锁".into(),
        });
        return;
    }
    if state.lifecycle == Lifecycle::Stopping {
        cmds.push(EffectCommand::RequestRejected {
            code: ErrorCode::IllegalState,
            reason: "正在停止退出，拒绝新的封锁请求".into(),
        });
        return;
    }
    log_both(
        state,
        now_secs,
        LogLevel::Audit,
        "lockdown",
        if on {
            "请求开启手动封锁"
        } else {
            "请求解除手动封锁"
        },
        cmds,
    );
    cmds.push(EffectCommand::SyncLockdown {
        want: on,
        manual: true,
        agents: state.config.guarded_agents.clone(),
    });
}

#[allow(clippy::too_many_arguments)]
fn handle_manual_lockdown_completed(
    state: &mut EngineState,
    on: bool,
    receipt: OperationReceipt,
    confirmed: bool,
    query_ok: bool,
    rules: usize,
    now_secs: u64,
    cmds: &mut Vec<EffectCommand>,
) {
    state.last_receipt = Some(receipt);
    if confirmed && query_ok {
        state.lockdown_manual = on;
        state.lockdown_applied = Some(on);
        state.last_error.clear();
        log_both(
            state,
            now_secs,
            LogLevel::Audit,
            "lockdown",
            if on {
                format!("手动封锁已生效并核验（{rules} 条规则），将独立保持直到手动解除")
            } else {
                "手动封锁已解除并核验".into()
            },
            cmds,
        );
    } else {
        state.last_error = if !query_ok {
            "防火墙规则回查失败，无法确认手动封锁结果".into()
        } else {
            "手动封锁核验未通过，未修改手动意图".into()
        };
        log_both(
            state,
            now_secs,
            LogLevel::Error,
            "lockdown",
            state.last_error.clone(),
            cmds,
        );
    }
}

fn handle_pause(
    state: &mut EngineState,
    duration_secs: Option<u64>,
    now_secs: u64,
    cmds: &mut Vec<EffectCommand>,
) {
    if state.lifecycle != Lifecycle::Armed {
        cmds.push(EffectCommand::RequestRejected {
            code: ErrorCode::IllegalState,
            reason: "仅 Armed 状态允许暂停或恢复守护".into(),
        });
        return;
    }
    match duration_secs {
        Some(secs) if secs > 0 => {
            state.paused_until = Some(now_secs.saturating_add(secs));
            state.pause_duration_secs = Some(secs);
            log_both(
                state,
                now_secs,
                LogLevel::Audit,
                "pause",
                format!("已暂停守护 {secs} 秒（停止新杀进程与新隔离，既有隔离保持不变）"),
                cmds,
            );
        }
        _ => {
            state.paused_until = None;
            state.pause_duration_secs = None;
            log_both(
                state,
                now_secs,
                LogLevel::Audit,
                "pause",
                "已提前结束暂停",
                cmds,
            );
        }
    }
}

fn handle_recover_flow_a(state: &mut EngineState, now_secs: u64, cmds: &mut Vec<EffectCommand>) {
    if state.lifecycle != Lifecycle::Armed {
        cmds.push(EffectCommand::RequestRejected {
            code: ErrorCode::IllegalState,
            reason: "仅 Armed 状态可执行流程 A 恢复".into(),
        });
        return;
    }
    if !matches!(
        state.protection,
        ProtectionState::Quarantined | ProtectionState::GlobalCut | ProtectionState::Degraded
    ) {
        cmds.push(EffectCommand::RequestRejected {
            code: ErrorCode::IllegalState,
            reason: format!(
                "当前保护状态（{}）不需要执行流程 A 第一阶段",
                state.protection.label()
            ),
        });
        return;
    }
    state.runtime_epoch = state.runtime_epoch.saturating_add(1);
    let epoch = state.runtime_epoch;
    state.protection = ProtectionState::Recovering;
    let tx_id = next_tx_id("flow-a-net", epoch, now_secs);
    state.pending_tx = Some(PendingTransaction {
        tx_id: tx_id.clone(),
        kind: PendingTxKind::FlowANetworkRestore,
        runtime_epoch: epoch,
        started_at: now_secs,
    });
    log_both(
        state,
        now_secs,
        LogLevel::Audit,
        "recover",
        "开始流程 A 第一阶段：恢复业务网络并保持应用级隔离",
        cmds,
    );
    cmds.push(EffectCommand::ExecuteFlowANetworkRestore {
        tx_id,
        runtime_epoch: epoch,
        agents: state.config.guarded_agents.clone(),
    });
}

fn handle_flow_a_network_restored(
    state: &mut EngineState,
    runtime_epoch: u64,
    receipt: OperationReceipt,
    app_isolation_intact: bool,
    now_secs: u64,
    cmds: &mut Vec<EffectCommand>,
) {
    if runtime_epoch != state.runtime_epoch || state.protection != ProtectionState::Recovering {
        return;
    }
    state.pending_tx = None;
    state.last_receipt = Some(receipt.clone());

    if receipt.status.is_verified_or_na() && app_isolation_intact {
        state.protection = ProtectionState::NetworkReadyAppHeld;
        state.last_error.clear();
        if let Some(trip) = &mut state.tripped {
            trip.network_cut = CutMode::Off;
            trip.network_note = "业务网络已恢复，应用隔离保持至当前代次全通过".into();
        }
        log_both(
            state,
            now_secs,
            LogLevel::Audit,
            "recover",
            "流程 A 第一阶段完成：进入 NetworkReadyAppHeld，立即执行当前代次复检",
            cmds,
        );
        handle_start_round(state, CheckPurpose::Manual, now_secs, cmds);
    } else {
        state.protection = ProtectionState::Degraded;
        state.last_error = receipt.error.unwrap_or_else(|| {
            if !app_isolation_intact {
                "应用级隔离校验不完整，已停止流程 A 并保持保护（请选择流程 B 或修复隔离）".into()
            } else {
                "流程 A 恢复业务网络未核验成功，进入降级态".into()
            }
        });
        log_both(
            state,
            now_secs,
            LogLevel::Error,
            "recover",
            state.last_error.clone(),
            cmds,
        );
    }
}

fn handle_flow_a_app_release_completed(
    state: &mut EngineState,
    runtime_epoch: u64,
    receipt: OperationReceipt,
    now_secs: u64,
    cmds: &mut Vec<EffectCommand>,
) {
    if runtime_epoch != state.runtime_epoch || state.protection != ProtectionState::Recovering {
        return;
    }
    state.pending_tx = None;
    state.last_receipt = Some(receipt.clone());

    if receipt.status.is_verified_or_na() {
        state.protection = ProtectionState::Monitoring;
        state.tripped = None;
        state.access_streak = 0;
        state.ip_unchanged_hold_notified = false;
        state.monitor_only_warn_notified = false;
        for st in &mut state.target_statuses {
            st.fail_streak = 0;
        }
        state.launch_error.clear();
        state.last_error.clear();
        cmds.push(EffectCommand::ClearWal);
        log_both(
            state,
            now_secs,
            LogLevel::Audit,
            "recover",
            "流程 A 完成：当前代次全部目标通过，已解除应用级隔离并返回 Monitoring",
            cmds,
        );
        cmds.push(EffectCommand::Notify {
            class: "recover".into(),
            title: "ClaudeGuard 已安全恢复".into(),
            body: "出口检查通过，已解除应用级隔离。".into(),
        });
    } else {
        state.protection = ProtectionState::Degraded;
        state.last_error = receipt
            .error
            .unwrap_or_else(|| "解除应用级隔离核验失败，保持降级态".into());
        log_both(
            state,
            now_secs,
            LogLevel::Error,
            "recover",
            state.last_error.clone(),
            cmds,
        );
    }
}

fn handle_disarm_flow_b(
    state: &mut EngineState,
    reason: &str,
    now_secs: u64,
    cmds: &mut Vec<EffectCommand>,
) {
    if state.lifecycle == Lifecycle::Stopping {
        cmds.push(EffectCommand::RequestRejected {
            code: ErrorCode::IllegalState,
            reason: "正在退出停止中".into(),
        });
        return;
    }
    if state.lifecycle == Lifecycle::Unconfigured {
        state.lifecycle = Lifecycle::Disarmed;
        state.protection = ProtectionState::Monitoring;
        state.disarmed_reason = reason.to_string();
        log_both(
            state,
            now_secs,
            LogLevel::Audit,
            "disarm",
            format!("未配置状态已撤防：{reason}"),
            cmds,
        );
        return;
    }
    if state.lifecycle == Lifecycle::Disarmed && state.protection == ProtectionState::Monitoring {
        // Still execute idempotent cleanup verification so `--restore` always verifies 0 rules.
        state.lifecycle = Lifecycle::Armed;
    }
    state.runtime_epoch = state.runtime_epoch.saturating_add(1);
    let epoch = state.runtime_epoch;
    state.protection = ProtectionState::Recovering;
    let tx_id = next_tx_id("flow-b", epoch, now_secs);
    state.pending_tx = Some(PendingTransaction {
        tx_id: tx_id.clone(),
        kind: PendingTxKind::FlowBDisarmRestore,
        runtime_epoch: epoch,
        started_at: now_secs,
    });
    log_both(
        state,
        now_secs,
        LogLevel::Audit,
        "disarm",
        format!("开始流程 B（停止保护并恢复全部改动）：{reason}"),
        cmds,
    );
    cmds.push(EffectCommand::ExecuteFlowBDisarmRestore {
        tx_id,
        runtime_epoch: epoch,
        reason: reason.to_string(),
    });
}

fn handle_flow_b_completed(
    state: &mut EngineState,
    runtime_epoch: u64,
    receipt: OperationReceipt,
    reason: &str,
    now_secs: u64,
    cmds: &mut Vec<EffectCommand>,
) {
    if runtime_epoch != state.runtime_epoch || state.protection != ProtectionState::Recovering {
        return;
    }
    state.pending_tx = None;
    state.last_receipt = Some(receipt.clone());

    if receipt.status.is_verified_or_na() {
        state.lifecycle = Lifecycle::Disarmed;
        state.protection = ProtectionState::Monitoring;
        state.disarmed_reason = reason.to_string();
        state.tripped = None;
        state.lockdown_manual = false;
        state.lockdown_applied = Some(false);
        state.access_streak = 0;
        clear_compliant_ip_baseline(state);
        for st in &mut state.target_statuses {
            st.fail_streak = 0;
        }
        state.launch_error.clear();
        state.last_error.clear();
        cmds.push(EffectCommand::ClearWal);
        log_both(
            state,
            now_secs,
            LogLevel::Audit,
            "disarm",
            format!("流程 B 已核验完成，进入 Disarmed（{reason}）"),
            cmds,
        );
    } else {
        state.protection = ProtectionState::Degraded;
        state.last_error = receipt
            .error
            .unwrap_or_else(|| "流程 B 清理未完全核验，已保留现场并进入降级态".into());
        log_both(
            state,
            now_secs,
            LogLevel::Error,
            "disarm",
            state.last_error.clone(),
            cmds,
        );
    }
}

fn handle_rearm(state: &mut EngineState, now_secs: u64, cmds: &mut Vec<EffectCommand>) {
    if state.lifecycle != Lifecycle::Disarmed {
        cmds.push(EffectCommand::RequestRejected {
            code: ErrorCode::IllegalState,
            reason: "仅 Disarmed 状态可重新布防".into(),
        });
        return;
    }
    if state.protection == ProtectionState::NetworkReadyAppHeld {
        cmds.push(EffectCommand::RequestRejected {
            code: ErrorCode::IllegalState,
            reason: "存在待恢复隔离残留，请先完成恢复再重新布防".into(),
        });
        return;
    }
    log_both(
        state,
        now_secs,
        LogLevel::Audit,
        "rearm",
        "请求重新布防",
        cmds,
    );
    cmds.push(EffectCommand::ClearDisarmMarker);
}

fn handle_rearm_persisted(
    state: &mut EngineState,
    ok: bool,
    error: Option<String>,
    now_secs: u64,
    cmds: &mut Vec<EffectCommand>,
) {
    if !ok {
        state.last_error = error.unwrap_or_else(|| "清除撤防标记失败，保持 Disarmed".into());
        log_both(
            state,
            now_secs,
            LogLevel::Error,
            "rearm",
            state.last_error.clone(),
            cmds,
        );
        return;
    }
    state.lifecycle = Lifecycle::Armed;
    state.protection = ProtectionState::Pending;
    state.disarmed_reason.clear();
    state.last_error.clear();
    clear_compliant_ip_baseline(state);
    state.runtime_epoch = state.runtime_epoch.saturating_add(1);
    log_both(
        state,
        now_secs,
        LogLevel::Audit,
        "rearm",
        "已重新布防，立即触发首轮检测",
        cmds,
    );
    handle_start_round(state, CheckPurpose::Manual, now_secs, cmds);
}

fn validate_proxy_host(raw: &str) -> Result<String, String> {
    if raw.chars().any(char::is_control) {
        return Err("代理主机地址不能包含控制字符".into());
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("代理主机地址不能为空".into());
    }
    if trimmed
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '@' | '/' | '\\' | '?' | '#'))
    {
        return Err("代理主机地址包含非法字符".into());
    }
    if trimmed.starts_with('[') || trimmed.ends_with(']') {
        let Some(inner) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) else {
            return Err("IPv6 代理主机地址方括号不匹配".into());
        };
        if inner.parse::<std::net::Ipv6Addr>().is_err() {
            return Err("IPv6 代理主机地址无效".into());
        }
        return Ok(trimmed.to_string());
    }
    if trimmed.contains(':') && trimmed.parse::<std::net::Ipv6Addr>().is_err() {
        return Err("代理主机地址无效（请不要在主机字段填写端口）".into());
    }
    Ok(trimmed.to_string())
}

fn is_tx_in_flight(state: &EngineState) -> bool {
    state.pending_tx.is_some()
        || matches!(
            state.protection,
            ProtectionState::Isolating | ProtectionState::Recovering
        )
}

fn handle_save_config(
    state: &mut EngineState,
    mut next: Config,
    is_onboarding: bool,
    now_secs: u64,
    cmds: &mut Vec<EffectCommand>,
) {
    if state.lifecycle == Lifecycle::Stopping {
        cmds.push(EffectCommand::RequestRejected {
            code: ErrorCode::IllegalState,
            reason: "正在退出，拒绝修改配置".into(),
        });
        return;
    }
    if is_tx_in_flight(state) {
        cmds.push(EffectCommand::RequestRejected {
            code: ErrorCode::Busy,
            reason: "当前正在执行隔离或恢复事务，请稍候重试".into(),
        });
        return;
    }
    match validate_proxy_host(&next.proxy_host) {
        Ok(clean_host) => next.proxy_host = clean_host,
        Err(err) => {
            cmds.push(EffectCommand::RequestRejected {
                code: ErrorCode::ValidationFailed,
                reason: err,
            });
            return;
        }
    }
    if is_onboarding {
        next.first_run = false;
    } else if state.lifecycle != Lifecycle::Unconfigured && next.first_run {
        cmds.push(EffectCommand::RequestRejected {
            code: ErrorCode::ValidationFailed,
            reason: "已完成初始化向导，禁止将配置重置为未配置状态".into(),
        });
        return;
    }
    next.migrate();
    match targets::validate_with_options(next.targets, !next.first_run) {
        Ok(validated) => next.targets = validated,
        Err(err) => {
            cmds.push(EffectCommand::RequestRejected {
                code: ErrorCode::ValidationFailed,
                reason: err,
            });
            return;
        }
    }
    // CONTRACT §3.6 & R11: do NOT mutate memory config or cfg_rev until persistence succeeds!
    log_both(
        state,
        now_secs,
        LogLevel::Info,
        "config",
        "配置校验通过，等待原子写入与回读核验",
        cmds,
    );
    cmds.push(EffectCommand::PersistConfig {
        config: next,
        target_cfg_rev: state.cfg_rev.saturating_add(1),
    });
}

fn handle_config_persisted(
    state: &mut EngineState,
    ok: bool,
    config: Option<Config>,
    error: Option<String>,
    now_secs: u64,
    cmds: &mut Vec<EffectCommand>,
) {
    if !ok {
        state.last_error =
            error.unwrap_or_else(|| "配置写入或回读核验失败，内存配置保持不变".into());
        log_both(
            state,
            now_secs,
            LogLevel::Error,
            "config",
            state.last_error.clone(),
            cmds,
        );
        return;
    }
    let Some(cfg) = config else {
        state.last_error = "配置保存回执缺少配置载荷".into();
        return;
    };
    let was_unconfigured = state.lifecycle == Lifecycle::Unconfigured;
    let prev_monitor_only = state.config.monitor_only;
    let prev_guarded_agents = state.config.guarded_agents.clone();
    let prev_lockdown_applied = state.lockdown_applied;
    let in_tx = is_tx_in_flight(state);

    state.config = cfg;
    state.cfg_rev = state.cfg_rev.saturating_add(1);
    if !in_tx {
        state.runtime_epoch = state.runtime_epoch.saturating_add(1);
    }
    state.target_statuses = initial_target_statuses(&state.config);
    state.access_streak = 0;
    clear_compliant_ip_baseline(state);
    state.checking = false;
    state.active_round = None;
    state.last_error.clear();

    if state.config.guarded_agents != prev_guarded_agents {
        state.lockdown_applied = None;
    }

    if !was_unconfigured && state.config.monitor_only != prev_monitor_only {
        log_both(
            state,
            now_secs,
            LogLevel::Audit,
            "config",
            if state.config.monitor_only {
                "已开启仅监测模式：继续只读巡检与告警，不自动熔断或终止进程"
            } else {
                "已关闭仅监测模式：恢复自动熔断隔离保护"
            },
            cmds,
        );
    }

    if was_unconfigured && !state.config.first_run {
        state.lifecycle = Lifecycle::Armed;
        state.protection = ProtectionState::Pending;
        log_both(
            state,
            now_secs,
            LogLevel::Audit,
            "onboarding",
            "向导配置已保存并布防，开始首轮监控",
            cmds,
        );
    } else if state.config.first_run {
        state.lifecycle = Lifecycle::Unconfigured;
        state.protection = ProtectionState::Pending;
    } else {
        log_both(
            state,
            now_secs,
            LogLevel::Info,
            "config",
            format!(
                "配置已提交（cfg_rev={}），旧轮次结果自动失效",
                state.cfg_rev
            ),
            cmds,
        );
    }

    if state.network_isolation_supported && state.lifecycle == Lifecycle::Armed {
        if state.config.guarded_agents != prev_guarded_agents && state.lockdown_manual {
            cmds.push(EffectCommand::SyncLockdown {
                want: true,
                manual: true,
                agents: state.config.guarded_agents.clone(),
            });
        }
        if !was_unconfigured && !prev_monitor_only && state.config.monitor_only {
            if prev_lockdown_applied == Some(true) && !state.lockdown_manual {
                cmds.push(EffectCommand::SyncLockdown {
                    want: false,
                    manual: false,
                    agents: state.config.guarded_agents.clone(),
                });
            }
            if !in_tx {
                if matches!(
                    state.protection,
                    ProtectionState::Quarantined | ProtectionState::GlobalCut
                ) {
                    handle_recover_flow_a(state, now_secs, cmds);
                } else if state.protection == ProtectionState::NetworkReadyAppHeld {
                    let tx_id = next_tx_id("flow-a-release", state.runtime_epoch, now_secs);
                    state.protection = ProtectionState::Recovering;
                    state.pending_tx = Some(PendingTransaction {
                        tx_id: tx_id.clone(),
                        kind: PendingTxKind::FlowAAppRelease,
                        runtime_epoch: state.runtime_epoch,
                        started_at: now_secs,
                    });
                    cmds.push(EffectCommand::ExecuteFlowAAppRelease {
                        tx_id,
                        runtime_epoch: state.runtime_epoch,
                    });
                }
            }
        }
    }
}

fn handle_enter_maintenance(
    state: &mut EngineState,
    reason: &str,
    allow_while_isolated: bool,
    now_secs: u64,
    cmds: &mut Vec<EffectCommand>,
) {
    if state.lifecycle != Lifecycle::Armed {
        cmds.push(EffectCommand::RequestRejected {
            code: ErrorCode::IllegalState,
            reason: "仅 Armed 状态可进入 Maintenance".into(),
        });
        return;
    }
    // CONTRACT D6: app updates are forbidden while isolated, recovering, or degraded.
    if !allow_while_isolated
        && (state.protection.is_isolated()
            || matches!(
                state.protection,
                ProtectionState::Recovering | ProtectionState::Degraded
            )
            || state.pending_tx.is_some())
    {
        cmds.push(EffectCommand::RequestRejected {
            code: ErrorCode::IllegalState,
            reason: "保护异常或恢复事务进行中，禁止进入应用更新维护态（CONTRACT D6）".into(),
        });
        return;
    }
    // CONTRACT §2.4: Maintenance permits Recovering, Quarantined, GlobalCut, Degraded.
    state.lifecycle = Lifecycle::Maintenance;
    if !matches!(
        state.protection,
        ProtectionState::Recovering
            | ProtectionState::Quarantined
            | ProtectionState::GlobalCut
            | ProtectionState::Degraded
    ) {
        state.protection = ProtectionState::Recovering;
    }
    state.runtime_epoch = state.runtime_epoch.saturating_add(1);
    log_both(
        state,
        now_secs,
        LogLevel::Audit,
        "maintenance",
        format!("进入维护态：{reason}"),
        cmds,
    );
}

fn handle_exit_maintenance(
    state: &mut EngineState,
    ok: bool,
    error: Option<String>,
    now_secs: u64,
    cmds: &mut Vec<EffectCommand>,
) {
    if state.lifecycle != Lifecycle::Maintenance {
        return;
    }
    state.lifecycle = Lifecycle::Armed;
    if ok {
        if !state.protection.is_isolated() {
            state.protection = ProtectionState::Pending;
        }
        clear_compliant_ip_baseline(state);
        state.last_error.clear();
        log_both(
            state,
            now_secs,
            LogLevel::Audit,
            "maintenance",
            "退出维护态",
            cmds,
        );
    } else {
        state.protection = ProtectionState::Degraded;
        state.last_error = error.unwrap_or_else(|| "维护事务失败，进入降级态".into());
        log_both(
            state,
            now_secs,
            LogLevel::Error,
            "maintenance",
            state.last_error.clone(),
            cmds,
        );
    }
}

fn handle_begin_stopping(state: &mut EngineState, now_secs: u64, cmds: &mut Vec<EffectCommand>) {
    state.runtime_epoch = state.runtime_epoch.saturating_add(1);
    let epoch = state.runtime_epoch;
    state.lifecycle = Lifecycle::Stopping;
    state.protection = ProtectionState::Recovering;
    let tx_id = next_tx_id("stop", epoch, now_secs);
    state.pending_tx = Some(PendingTransaction {
        tx_id: tx_id.clone(),
        kind: PendingTxKind::StoppingRestore,
        runtime_epoch: epoch,
        started_at: now_secs,
    });
    log_both(
        state,
        now_secs,
        LogLevel::Audit,
        "lifecycle",
        "开始正常退出恢复协议（Flow B）",
        cmds,
    );
    cmds.push(EffectCommand::ExecuteFlowBDisarmRestore {
        tx_id,
        runtime_epoch: epoch,
        reason: "正常退出".into(),
    });
}

fn handle_stop_restore_completed(
    state: &mut EngineState,
    runtime_epoch: u64,
    receipt: OperationReceipt,
    now_secs: u64,
    cmds: &mut Vec<EffectCommand>,
) {
    if runtime_epoch != state.runtime_epoch || state.lifecycle != Lifecycle::Stopping {
        return;
    }
    state.pending_tx = None;
    state.last_receipt = Some(receipt.clone());
    if receipt.status.is_verified_or_na() {
        cmds.push(EffectCommand::ClearWal);
        log_both(
            state,
            now_secs,
            LogLevel::Audit,
            "lifecycle",
            "退出恢复与核验成功，允许退出",
            cmds,
        );
        cmds.push(EffectCommand::ReadyToExit);
    } else {
        state.protection = ProtectionState::Degraded;
        state.last_error = receipt
            .error
            .unwrap_or_else(|| "退出前恢复或核验失败，保持运行以防残留断网（CONTRACT D3）".into());
        log_both(
            state,
            now_secs,
            LogLevel::Error,
            "lifecycle",
            state.last_error.clone(),
            cmds,
        );
    }
}

fn handle_leak_updated(
    state: &mut EngineState,
    report: LeakReport,
    now_secs: u64,
    cmds: &mut Vec<EffectCommand>,
) {
    state.leak = report.clone();
    if state.lifecycle == Lifecycle::Armed
        && !state.is_paused(now_secs)
        && !state.is_in_resume_grace(now_secs)
        && !state.config.monitor_only
        && state.protection == ProtectionState::Monitoring
        && state.config.leak_trip
        && report.applicable
        && report.leaked()
    {
        begin_isolation(
            state,
            format!("检测到 {} 条直连泄露", report.direct_total),
            Vec::new(),
            now_secs,
            cmds,
        );
    }
}

/// Module-level helper delegating to [`GuardEngine::evaluate_launch_gate`].
pub fn evaluate_launch_gate(state: &EngineState, now_secs: u64) -> LaunchDecision {
    GuardEngine::evaluate_launch_gate(state, now_secs)
}

/// Module-level helper delegating to [`GuardEngine::evaluate_launch_gate_for_agent`].
pub fn evaluate_launch_gate_for_agent(
    state: &EngineState,
    agent_id: Option<&str>,
    now_secs: u64,
) -> LaunchDecision {
    GuardEngine::evaluate_launch_gate_for_agent(state, agent_id, now_secs)
}

fn handle_antigravity_proxy_updated(
    state: &mut EngineState,
    status: AntigravityProxyStatus,
    now_secs: u64,
    cmds: &mut Vec<EffectCommand>,
) {
    let prev_state = state.antigravity_proxy.state;
    let in_tx = is_tx_in_flight(state);
    let version_changed = status.version_changed_from.is_some()
        || (status.antigravity_version.is_some()
            && status.antigravity_version != state.config.last_seen_antigravity_version);

    if version_changed && !in_tx {
        state.config.last_seen_antigravity_version = status.antigravity_version.clone();
        let audit_msg = if let Some(prev) = status.version_changed_from.as_deref() {
            format!(
                "检测到反重力客户端版本更新：{} -> {}（{}）",
                prev,
                status.antigravity_version.as_deref().unwrap_or("未知"),
                status.summary
            )
        } else {
            format!(
                "已记录反重力客户端版本：{}",
                status.antigravity_version.as_deref().unwrap_or("未知")
            )
        };
        log_both(
            state,
            now_secs,
            LogLevel::Audit,
            "ag_proxy",
            audit_msg,
            cmds,
        );

        if status.version_changed_from.is_some() {
            state.cfg_rev = state.cfg_rev.saturating_add(1);
            cmds.push(EffectCommand::PersistConfig {
                config: state.config.clone(),
                target_cfg_rev: state.cfg_rev,
            });
            cmds.push(EffectCommand::Notify {
                class: "client_update".into(),
                title: "检测到反重力客户端更新".into(),
                body: status.summary.clone(),
            });
        }
    }

    if state.config.require_antigravity_proxy
        && status.state.is_degraded()
        && prev_state != status.state
    {
        log_both(
            state,
            now_secs,
            LogLevel::Warn,
            "ag_proxy",
            &status.summary,
            cmds,
        );
        cmds.push(EffectCommand::Notify {
            class: "warning".into(),
            title: format!("反重力透明代理异常：{}", status.state.label_zh()),
            body: status.summary.clone(),
        });
    }

    state.antigravity_proxy = status;
}

fn handle_updates_checked(
    state: &mut EngineState,
    summary: UpdateSummary,
    now_secs: u64,
    cmds: &mut Vec<EffectCommand>,
) {
    if summary.antigravity_proxy.phase == UpdateCheckPhase::UpdateAvailable
        && summary.antigravity_proxy.latest_version
            != state.updates.antigravity_proxy.latest_version
    {
        log_both(
            state,
            now_secs,
            LogLevel::Warn,
            "update",
            &summary.antigravity_proxy.note,
            cmds,
        );
        cmds.push(EffectCommand::Notify {
            class: "client_update".into(),
            title: "antigravity-proxy 发现新版本".into(),
            body: summary.antigravity_proxy.note.clone(),
        });
    }
    if summary.claudeguard.phase == UpdateCheckPhase::UpdateAvailable
        && summary.claudeguard.latest_version != state.updates.claudeguard.latest_version
    {
        log_both(
            state,
            now_secs,
            LogLevel::Info,
            "update",
            &summary.claudeguard.note,
            cmds,
        );
        cmds.push(EffectCommand::Notify {
            class: "self_update".into(),
            title: "ClaudeGuard 发现新版本".into(),
            body: summary.claudeguard.note.clone(),
        });
    }
    let prev_cn = state.updates.antigravity_cn.latest_version.clone();
    let prev_um = state.updates.ag_usage_monitor.latest_version.clone();
    let prev_cap = state.updates.ag_capsule.latest_version.clone();
    for (title, next_slot, prev_ver) in [
        (
            "Antigravity 中文汉化引擎发现更新",
            &summary.antigravity_cn,
            prev_cn,
        ),
        (
            "antigravity-usage-monitor 发现新版本",
            &summary.ag_usage_monitor,
            prev_um,
        ),
        ("agy-capsule 发现新版本", &summary.ag_capsule, prev_cap),
    ] {
        if next_slot.phase == UpdateCheckPhase::UpdateAvailable
            && next_slot.latest_version != prev_ver
        {
            log_both(
                state,
                now_secs,
                LogLevel::Info,
                "update",
                &next_slot.note,
                cmds,
            );
            cmds.push(EffectCommand::Notify {
                class: "client_update".into(),
                title: title.into(),
                body: next_slot.note.clone(),
            });
        }
    }
    state.updates = summary;
}

#[cfg(test)]
mod tests {
    use super::*;
    use cg_protocol::AccessLevel;

    fn armed_config() -> Config {
        let mut cfg = Config {
            first_run: false,
            ..Config::default()
        };
        for t in &mut cfg.targets {
            if matches!(t.id.as_str(), "local" | "claude" | "codex") {
                t.expect_ips = vec!["198.51.100.0/24".into()];
                t.expect_regions = vec!["US".into()];
            }
        }
        cfg
    }

    fn covered_access() -> AccessEvidence {
        AccessEvidence {
            level: AccessLevel::SystemProxy,
            proxy_addr: Some("127.0.0.1:7890".into()),
            route_hint: true,
            observed_at: 1_700_000_000,
            revision: 1,
            note: "系统代理 127.0.0.1:7890".into(),
            ..AccessEvidence::default()
        }
    }

    fn uncovered_access() -> AccessEvidence {
        AccessEvidence {
            level: AccessLevel::Uncovered,
            observed_at: 1_700_000_000,
            revision: 1,
            note: "未接入".into(),
            ..AccessEvidence::default()
        }
    }

    fn pass_probes() -> Vec<(String, ProbeResult)> {
        vec![
            (
                "claude".into(),
                ProbeResult {
                    reachable: true,
                    status: Some(200),
                    ip: Some("198.51.100.98".into()),
                    country: Some("US".into()),
                    raw_region: Some("US".into()),
                    colo: Some("LAX".into()),
                    latency_ms: 40,
                    parsed_as: "trace".into(),
                    detail: String::new(),
                    ..ProbeResult::default()
                },
            ),
            (
                "codex".into(),
                ProbeResult {
                    reachable: true,
                    status: Some(200),
                    ip: Some("198.51.100.99".into()),
                    country: Some("US".into()),
                    raw_region: Some("US".into()),
                    colo: Some("LAX".into()),
                    latency_ms: 45,
                    parsed_as: "trace".into(),
                    detail: String::new(),
                    ..ProbeResult::default()
                },
            ),
            (
                "antigravity".into(),
                ProbeResult {
                    reachable: true,
                    status: Some(200),
                    latency_ms: 50,
                    parsed_as: "reachability".into(),
                    ..ProbeResult::default()
                },
            ),
        ]
    }

    fn fail_probes() -> Vec<(String, ProbeResult)> {
        let mut p = pass_probes();
        p[0].1.ip = Some("203.0.113.45".into());
        p[0].1.country = Some("CN".into());
        p[0].1.raw_region = Some("CN".into());
        p
    }

    fn unverified_probes() -> Vec<(String, ProbeResult)> {
        let mut p = pass_probes();
        p[0].1 = ProbeResult::failed("timeout");
        p
    }

    fn verified_receipt(id: &str) -> OperationReceipt {
        OperationReceipt::new(id, OperationStatus::Verified)
    }

    #[test]
    fn unconfigured_never_kills_isolates_cuts_or_locks_down() {
        let state = EngineState::new(Config::default(), true, true, 100);
        assert_eq!(state.lifecycle, Lifecycle::Unconfigured);
        assert_eq!(state.protection, ProtectionState::Pending);

        let (state, cmds) = GuardEngine::step(state, EngineEvent::Tick, 105);
        assert!(matches!(
            cmds.as_slice(),
            [EffectCommand::ResolveAccessAndProbe {
                skip_network_probes: true,
                ..
            }]
        ));

        let rev = state.cfg_rev;
        let epoch = state.runtime_epoch;
        let (state, cmds) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: rev,
                runtime_epoch: epoch,
                purpose: CheckPurpose::Monitor,
                access: uncovered_access(),
                probes: vec![],
            },
            106,
        );
        assert_eq!(state.lifecycle, Lifecycle::Unconfigured);
        assert_eq!(state.protection, ProtectionState::Pending);
        assert!(!cmds.iter().any(|c| matches!(
            c,
            EffectCommand::ExecuteIsolation { .. }
                | EffectCommand::KillGuardedAgents { .. }
                | EffectCommand::SyncLockdown { want: true, .. }
        )));

        let (_, lock_cmds) = GuardEngine::step(
            state.clone(),
            EngineEvent::SetManualLockdown { on: true },
            107,
        );
        assert!(matches!(
            lock_cmds.as_slice(),
            [EffectCommand::RequestRejected {
                code: ErrorCode::IllegalState,
                ..
            }]
        ));
        assert!(!GuardEngine::evaluate_launch_gate(&state, 107).allowed);
    }

    #[test]
    fn stale_cfg_rev_and_runtime_epoch_rounds_are_rejected() {
        let mut state = EngineState::new(armed_config(), true, true, 100);
        state.cfg_rev = 3;
        state.runtime_epoch = 5;

        // Stale cfg_rev
        let (s1, c1) = GuardEngine::step(
            state.clone(),
            EngineEvent::RoundCompleted {
                cfg_rev: 2,
                runtime_epoch: 5,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: fail_probes(),
            },
            110,
        );
        assert_eq!(s1.protection, ProtectionState::Pending);
        assert!(s1.checked_at.is_none());
        assert!(
            !c1.iter()
                .any(|c| matches!(c, EffectCommand::ExecuteIsolation { .. }))
        );

        // Stale runtime_epoch
        let (s2, c2) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: 3,
                runtime_epoch: 4,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: fail_probes(),
            },
            111,
        );
        assert_eq!(s2.protection, ProtectionState::Pending);
        assert!(s2.checked_at.is_none());
        assert!(
            !c2.iter()
                .any(|c| matches!(c, EffectCommand::ExecuteIsolation { .. }))
        );
    }

    #[test]
    fn trip_threshold_debounce_and_unverified_invariants() {
        let mut cfg = armed_config();
        cfg.trip_threshold = 2;
        let state = EngineState::new(cfg, true, true, 100);

        // First fail: streak=1 < threshold=2 -> warning only, NO trip!
        let (state, cmds1) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: fail_probes(),
            },
            110,
        );
        assert_eq!(state.protection, ProtectionState::Monitoring);
        assert_eq!(state.target_statuses[1].fail_streak, 1);
        assert!(
            !cmds1
                .iter()
                .any(|c| matches!(c, EffectCommand::ExecuteIsolation { .. }))
        );
        assert!(
            cmds1
                .iter()
                .any(|c| matches!(c, EffectCommand::Notify { class, .. } if class == "warning"))
        );

        // Unverified round resets streak & NEVER trips & blocks launch!
        let (state, cmds_u) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: unverified_probes(),
            },
            120,
        );
        assert_eq!(state.protection, ProtectionState::Monitoring);
        assert_eq!(state.target_statuses[1].fail_streak, 0);
        assert!(
            !cmds_u
                .iter()
                .any(|c| matches!(c, EffectCommand::ExecuteIsolation { .. }))
        );
        assert!(!GuardEngine::evaluate_launch_gate(&state, 120).allowed);

        // Two consecutive fails -> trips!
        let (state, _) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: fail_probes(),
            },
            130,
        );
        let (state, cmds2) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: fail_probes(),
            },
            140,
        );
        assert_eq!(state.protection, ProtectionState::Isolating);
        assert!(
            cmds2
                .iter()
                .any(|c| matches!(c, EffectCommand::ExecuteIsolation { .. }))
        );
    }

    #[test]
    fn pause_blocks_new_kills_and_isolations_while_preserving_quarantine() {
        let mut cfg = armed_config();
        cfg.trip_threshold = 1;
        let state = EngineState::new(cfg, true, true, 100);

        // Pause for 30m
        let (state, _) = GuardEngine::step(
            state,
            EngineEvent::Pause {
                duration_secs: Some(1800),
            },
            100,
        );
        assert!(state.is_paused(101));
        assert!(!GuardEngine::evaluate_launch_gate(&state, 101).allowed);

        // Failing round during pause does NOT isolate or kill
        let (mut state, cmds) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: fail_probes(),
            },
            105,
        );
        assert_eq!(state.protection, ProtectionState::Monitoring);
        assert!(!cmds.iter().any(|c| matches!(
            c,
            EffectCommand::ExecuteIsolation { .. } | EffectCommand::KillGuardedAgents { .. }
        )));

        // Existing quarantine is preserved during pause and not auto-released even on pass
        state.protection = ProtectionState::Quarantined;
        state.lockdown_applied = Some(false);
        let (state, cmds_q) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: pass_probes(),
            },
            110,
        );
        assert_eq!(state.protection, ProtectionState::Quarantined);
        assert!(!cmds_q.iter().any(|c| matches!(
            c,
            EffectCommand::ExecuteIsolation { .. }
                | EffectCommand::KillGuardedAgents { .. }
                | EffectCommand::ExecuteFlowANetworkRestore { .. }
                | EffectCommand::ExecuteFlowAAppRelease { .. }
                | EffectCommand::ExecuteFlowBDisarmRestore { .. }
        )));
    }

    #[test]
    fn manual_lockdown_survives_covered_access_and_requires_verified_readback() {
        let state = EngineState::new(armed_config(), true, true, 100);

        // Request manual lockdown ON -> query_ok=false must NOT commit lockdown_manual!
        let (state, _) = GuardEngine::step(state, EngineEvent::SetManualLockdown { on: true }, 101);
        let (state, _) = GuardEngine::step(
            state,
            EngineEvent::ManualLockdownCompleted {
                on: true,
                receipt: OperationReceipt::new("ld", OperationStatus::Unknown),
                confirmed: false,
                query_ok: false,
                rules: 0,
            },
            102,
        );
        assert!(!state.lockdown_manual);

        // Verified manual lockdown ON
        let (state, _) = GuardEngine::step(
            state,
            EngineEvent::ManualLockdownCompleted {
                on: true,
                receipt: verified_receipt("ld"),
                confirmed: true,
                query_ok: true,
                rules: 3,
            },
            103,
        );
        assert!(state.lockdown_manual);
        assert_eq!(state.lockdown_applied, Some(true));

        // Subsequent covered round must NOT emit SyncLockdown(want=false)
        let (state, cmds) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: pass_probes(),
            },
            110,
        );
        assert!(state.lockdown_manual);
        assert!(
            !cmds
                .iter()
                .any(|c| matches!(c, EffectCommand::SyncLockdown { want: false, .. }))
        );
    }

    #[test]
    fn flow_a_two_stage_recovery_requires_current_epoch_full_pass() {
        let mut cfg = armed_config();
        cfg.trip_threshold = 1;
        cfg.cut_mode = CutMode::Firewall;
        let state = EngineState::new(cfg, true, true, 100);

        // Trip -> Isolating -> GlobalCut
        let (state, _) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: fail_probes(),
            },
            110,
        );
        assert_eq!(state.protection, ProtectionState::Isolating);
        let epoch = state.runtime_epoch;
        let (state, _) = GuardEngine::step(
            state,
            EngineEvent::IsolationCompleted {
                runtime_epoch: epoch,
                receipt: verified_receipt("iso"),
                killed: 1,
                cli_killed: 0,
                firewall_rules: 6,
                quarantined_agents: vec!["claude".into()],
                network_cut_applied: CutMode::Firewall,
                network_note: String::new(),
            },
            111,
        );
        assert_eq!(state.protection, ProtectionState::GlobalCut);

        // Flow A Stage 1 -> Recovering -> NetworkReadyAppHeld
        let (state, cmds_a1) = GuardEngine::step(state, EngineEvent::RecoverSafeFlowA, 120);
        assert_eq!(state.protection, ProtectionState::Recovering);
        assert!(
            cmds_a1
                .iter()
                .any(|c| matches!(c, EffectCommand::ExecuteFlowANetworkRestore { .. }))
        );
        let epoch_a = state.runtime_epoch;
        let (state, cmds_a2) = GuardEngine::step(
            state,
            EngineEvent::FlowANetworkRestored {
                runtime_epoch: epoch_a,
                receipt: verified_receipt("flow-a-1"),
                app_isolation_intact: true,
            },
            121,
        );
        assert_eq!(state.protection, ProtectionState::NetworkReadyAppHeld);
        assert!(
            cmds_a2
                .iter()
                .any(|c| matches!(c, EffectCommand::ResolveAccessAndProbe { .. }))
        );

        // Unverified round while NetworkReadyAppHeld must NOT release quarantine!
        let rev_a = state.cfg_rev;
        let (state, cmds_unv) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: rev_a,
                runtime_epoch: epoch_a,
                purpose: CheckPurpose::Manual,
                access: covered_access(),
                probes: unverified_probes(),
            },
            122,
        );
        assert_eq!(state.protection, ProtectionState::NetworkReadyAppHeld);
        assert!(
            !cmds_unv
                .iter()
                .any(|c| matches!(c, EffectCommand::ExecuteFlowAAppRelease { .. }))
        );

        // Current-epoch full Pass -> Recovering -> Monitoring
        let rev_a2 = state.cfg_rev;
        let (state, cmds_pass) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: rev_a2,
                runtime_epoch: epoch_a,
                purpose: CheckPurpose::Manual,
                access: covered_access(),
                probes: pass_probes(),
            },
            125,
        );
        assert_eq!(state.protection, ProtectionState::Recovering);
        assert!(
            cmds_pass
                .iter()
                .any(|c| matches!(c, EffectCommand::ExecuteFlowAAppRelease { .. }))
        );

        let (state, cmds_done) = GuardEngine::step(
            state,
            EngineEvent::FlowAAppReleaseCompleted {
                runtime_epoch: epoch_a,
                receipt: verified_receipt("flow-a-2"),
            },
            126,
        );
        assert_eq!(state.lifecycle, Lifecycle::Armed);
        assert_eq!(state.protection, ProtectionState::Monitoring);
        assert!(state.tripped.is_none());
        assert!(cmds_done.contains(&EffectCommand::ClearWal));
        assert!(GuardEngine::evaluate_launch_gate(&state, 126).allowed);
    }

    #[test]
    fn flow_b_moves_to_disarmed_only_after_verified_cleanup() {
        let mut state = EngineState::new(armed_config(), true, true, 100);
        state.protection = ProtectionState::Quarantined;

        let (state, _) = GuardEngine::step(
            state,
            EngineEvent::DisarmAndRestoreFlowB {
                reason: "用户停用保护".into(),
            },
            110,
        );
        assert_eq!(state.protection, ProtectionState::Recovering);
        let epoch = state.runtime_epoch;

        // Failed cleanup must stay Degraded and NOT disarm!
        let (degraded, cmds_fail) = GuardEngine::step(
            state.clone(),
            EngineEvent::FlowBCompleted {
                runtime_epoch: epoch,
                receipt: OperationReceipt::new("fb", OperationStatus::Partial),
                reason: "用户停用保护".into(),
            },
            111,
        );
        assert_eq!(degraded.lifecycle, Lifecycle::Armed);
        assert_eq!(degraded.protection, ProtectionState::Degraded);
        assert!(!cmds_fail.contains(&EffectCommand::ClearWal));

        // Verified cleanup moves to Disarmed + Monitoring
        let (disarmed, cmds_ok) = GuardEngine::step(
            state,
            EngineEvent::FlowBCompleted {
                runtime_epoch: epoch,
                receipt: verified_receipt("fb"),
                reason: "用户停用保护".into(),
            },
            112,
        );
        assert_eq!(disarmed.lifecycle, Lifecycle::Disarmed);
        assert_eq!(disarmed.protection, ProtectionState::Monitoring);
        assert_eq!(disarmed.disarmed_reason, "用户停用保护");
        assert!(cmds_ok.contains(&EffectCommand::ClearWal));
        assert!(!GuardEngine::evaluate_launch_gate(&disarmed, 112).allowed);
    }

    #[test]
    fn config_save_failure_leaves_memory_and_cfg_rev_unchanged() {
        let state = EngineState::new(armed_config(), true, true, 100);
        let orig_port = state.config.proxy_port;

        let mut next = state.config.clone();
        next.proxy_port = 9999;
        let (state, cmds) = GuardEngine::step(state, EngineEvent::SaveConfig { next }, 101);
        assert!(
            cmds.iter()
                .any(|c| matches!(c, EffectCommand::PersistConfig { .. }))
        );
        // Still original until ConfigPersisted(ok=true)
        assert_eq!(state.config.proxy_port, orig_port);
        assert_eq!(state.cfg_rev, 0);

        let (state, _) = GuardEngine::step(
            state,
            EngineEvent::ConfigPersisted {
                ok: false,
                config: None,
                error: Some("disk full".into()),
            },
            102,
        );
        assert_eq!(state.config.proxy_port, orig_port);
        assert_eq!(state.cfg_rev, 0);
        assert_eq!(state.last_error, "disk full");
    }

    #[test]
    fn onboarding_completion_transitions_unconfigured_to_armed() {
        let state = EngineState::new(Config::default(), true, true, 100);
        assert_eq!(state.lifecycle, Lifecycle::Unconfigured);
        let mut onboard_cfg = armed_config();
        onboard_cfg.first_run = true; // CompleteOnboarding must force false
        let (state, cmds) = GuardEngine::step(
            state,
            EngineEvent::CompleteOnboarding {
                config: onboard_cfg.clone(),
            },
            101,
        );
        let persisted = cmds.into_iter().find_map(|c| match c {
            EffectCommand::PersistConfig { config, .. } => Some(config),
            _ => None,
        });
        let persisted = persisted.expect("PersistConfig emitted");
        assert!(!persisted.first_run);

        let (state, _) = GuardEngine::step(
            state,
            EngineEvent::ConfigPersisted {
                ok: true,
                config: Some(persisted),
                error: None,
            },
            102,
        );
        assert_eq!(state.lifecycle, Lifecycle::Armed);
        assert_eq!(state.protection, ProtectionState::Pending);
        assert_eq!(state.cfg_rev, 1);
    }

    #[test]
    fn stopping_and_maintenance_enforce_contract_rules() {
        let mut state = EngineState::new(armed_config(), true, true, 100);
        state.protection = ProtectionState::Quarantined;

        // D6: app update maintenance rejected while Quarantined
        let (state, cmds) = GuardEngine::step(
            state,
            EngineEvent::EnterMaintenance {
                reason: "update".into(),
                allow_while_isolated: false,
            },
            101,
        );
        assert_eq!(state.lifecycle, Lifecycle::Armed);
        assert!(matches!(
            cmds.as_slice(),
            [EffectCommand::RequestRejected {
                code: ErrorCode::IllegalState,
                ..
            }]
        ));

        // Stopping waits for verified Flow B before ReadyToExit
        let (state, _) = GuardEngine::step(state, EngineEvent::BeginStopping, 102);
        assert_eq!(state.lifecycle, Lifecycle::Stopping);
        assert_eq!(state.protection, ProtectionState::Recovering);
        let epoch = state.runtime_epoch;
        let (failed_stop, cmds_fail) = GuardEngine::step(
            state.clone(),
            EngineEvent::StopRestoreCompleted {
                runtime_epoch: epoch,
                receipt: OperationReceipt::new("stop", OperationStatus::Failed),
            },
            103,
        );
        assert_eq!(failed_stop.protection, ProtectionState::Degraded);
        assert!(!cmds_fail.contains(&EffectCommand::ReadyToExit));

        let (_, cmds_ok) = GuardEngine::step(
            state,
            EngineEvent::StopRestoreCompleted {
                runtime_epoch: epoch,
                receipt: verified_receipt("stop"),
            },
            104,
        );
        assert!(cmds_ok.contains(&EffectCommand::ReadyToExit));
    }

    #[test]
    fn bootstrap_handles_corrupt_and_pending_wal_without_clearing_state() {
        let state = EngineState::new(Config::default(), true, true, 100);
        let (corrupt, _) = GuardEngine::step(
            state.clone(),
            EngineEvent::Bootstrap {
                wal_pending: false,
                wal_corrupt: true,
                disarmed_reason: None,
                last_error: None,
            },
            101,
        );
        assert_eq!(corrupt.lifecycle, Lifecycle::Armed);
        assert_eq!(corrupt.protection, ProtectionState::Degraded);
        assert!(corrupt.last_error.contains("损坏"));

        let (pending, _) = GuardEngine::step(
            state.clone(),
            EngineEvent::Bootstrap {
                wal_pending: true,
                wal_corrupt: false,
                disarmed_reason: None,
                last_error: None,
            },
            101,
        );
        assert_eq!(pending.lifecycle, Lifecycle::Armed);
        assert_eq!(pending.protection, ProtectionState::Degraded);

        let (disarmed, _) = GuardEngine::step(
            state,
            EngineEvent::Bootstrap {
                wal_pending: false,
                wal_corrupt: false,
                disarmed_reason: Some("--restore".into()),
                last_error: None,
            },
            101,
        );
        assert_eq!(disarmed.lifecycle, Lifecycle::Disarmed);
        assert_eq!(disarmed.protection, ProtectionState::Monitoring);
        assert_eq!(disarmed.disarmed_reason, "--restore");
    }

    #[test]
    fn launch_purpose_blocks_launch_gate_without_bypassing_trip_threshold() {
        let mut cfg = armed_config();
        cfg.trip_threshold = 3;
        let state = EngineState::new(cfg, true, true, 100);

        // Unknown access blocks launch without tripping
        let (unknown_st, cmds_unk) = GuardEngine::step(
            state.clone(),
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Launch,
                access: AccessEvidence {
                    level: AccessLevel::Unknown,
                    note: "PAC".into(),
                    ..AccessEvidence::default()
                },
                probes: vec![],
            },
            101,
        );
        assert_eq!(unknown_st.protection, ProtectionState::Monitoring);
        assert!(!GuardEngine::evaluate_launch_gate(&unknown_st, 101).allowed);
        assert!(
            !cmds_unk
                .iter()
                .any(|c| matches!(c, EffectCommand::ExecuteIsolation { .. }))
        );

        // Launch purpose with failing target on streak=1 denies Launch Gate without killing running apps (< trip_threshold=3)
        let (held, cmds_s1) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Launch,
                access: covered_access(),
                probes: fail_probes(),
            },
            102,
        );
        assert_eq!(held.protection, ProtectionState::Monitoring);
        assert!(!GuardEngine::evaluate_launch_gate(&held, 102).allowed);
        assert!(
            !cmds_s1
                .iter()
                .any(|c| matches!(c, EffectCommand::ExecuteIsolation { .. }))
        );
    }

    #[test]
    fn global_cut_blocked_when_d2_not_ready_and_clamped_when_unsupported() {
        let mut cfg = armed_config();
        cfg.trip_threshold = 1;
        cfg.cut_mode = CutMode::Nics;

        // D2 global_cut_ready = false on Windows -> clamps cut_mode to Off
        let state_not_ready = EngineState::new(cfg.clone(), true, false, 100);
        let (_, cmds1) = GuardEngine::step(
            state_not_ready,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: fail_probes(),
            },
            101,
        );
        assert!(cmds1.iter().any(|c| matches!(
            c,
            EffectCommand::ExecuteIsolation {
                cut_mode: CutMode::Off,
                quarantine_on_fail: true,
                ..
            }
        )));

        // Non-Windows (network_isolation_supported = false) -> rejects lockdown & clamps quarantine/cut
        let state_mac = EngineState::new(cfg, false, false, 100);
        let (_, lock_cmds) = GuardEngine::step(
            state_mac.clone(),
            EngineEvent::SetManualLockdown { on: true },
            101,
        );
        assert!(matches!(
            lock_cmds.as_slice(),
            [EffectCommand::RequestRejected {
                code: ErrorCode::Unsupported,
                ..
            }]
        ));
        let (_, cmds2) = GuardEngine::step(
            state_mac,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: fail_probes(),
            },
            102,
        );
        assert!(cmds2.iter().any(|c| matches!(
            c,
            EffectCommand::ExecuteIsolation {
                cut_mode: CutMode::Off,
                quarantine_on_fail: false,
                ..
            }
        )));
    }

    #[test]
    fn isolation_and_flow_a_failures_transition_to_degraded_without_clearing_wal() {
        let mut cfg = armed_config();
        cfg.trip_threshold = 1;
        let state = EngineState::new(cfg, true, true, 100);

        let (state, _) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: fail_probes(),
            },
            101,
        );
        let ep1 = state.runtime_epoch;
        let (degraded_iso, cmds_iso) = GuardEngine::step(
            state.clone(),
            EngineEvent::IsolationCompleted {
                runtime_epoch: ep1,
                receipt: OperationReceipt::new("iso", OperationStatus::Partial),
                killed: 1,
                cli_killed: 0,
                firewall_rules: 2,
                quarantined_agents: vec![],
                network_cut_applied: CutMode::Off,
                network_note: "partial".into(),
            },
            102,
        );
        assert_eq!(degraded_iso.protection, ProtectionState::Degraded);
        assert!(!cmds_iso.contains(&EffectCommand::ClearWal));

        // Flow A stage 1 where app_isolation_intact=false -> stops Flow A into Degraded
        let (flow_a, _) = GuardEngine::step(degraded_iso, EngineEvent::RecoverSafeFlowA, 103);
        let ep2 = flow_a.runtime_epoch;
        let (broken_a, cmds_a) = GuardEngine::step(
            flow_a,
            EngineEvent::FlowANetworkRestored {
                runtime_epoch: ep2,
                receipt: verified_receipt("a1"),
                app_isolation_intact: false,
            },
            104,
        );
        assert_eq!(broken_a.protection, ProtectionState::Degraded);
        assert!(
            !cmds_a
                .iter()
                .any(|c| matches!(c, EffectCommand::ResolveAccessAndProbe { .. }))
        );
    }

    #[test]
    fn pause_expiry_rearm_leak_trip_and_preset_change_work() {
        let mut cfg = armed_config();
        cfg.leak_trip = true;
        let state = EngineState::new(cfg, true, true, 100);

        // Pause expires automatically on Tick >= paused_until
        let (state, _) = GuardEngine::step(
            state,
            EngineEvent::Pause {
                duration_secs: Some(60),
            },
            100,
        );
        assert!(state.is_paused(150));
        let (state, _) = GuardEngine::step(state, EngineEvent::Tick, 160);
        assert!(!state.is_paused(160));

        // Simulate Monitoring + leak_trip = true -> LeakUpdated triggers isolation!
        let (mut mon, _) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: pass_probes(),
            },
            165,
        );
        assert_eq!(mon.protection, ProtectionState::Monitoring);
        let (leaked_st, leak_cmds) = GuardEngine::step(
            mon.clone(),
            EngineEvent::LeakUpdated {
                report: LeakReport {
                    applicable: true,
                    mode: "system_proxy".into(),
                    checked_at: 166,
                    agent_conns: 1,
                    proxied: 0,
                    local: 0,
                    direct: vec![],
                    direct_total: 1,
                    note: "leak".into(),
                },
            },
            166,
        );
        assert_eq!(leaked_st.protection, ProtectionState::Isolating);
        assert!(
            leak_cmds
                .iter()
                .any(|c| matches!(c, EffectCommand::ExecuteIsolation { .. }))
        );

        // Disarm -> Rearm requires ClearDisarmMarker persistence before Armed
        mon.lifecycle = Lifecycle::Disarmed;
        mon.protection = ProtectionState::Monitoring;
        let (rearming, rearm_cmds) = GuardEngine::step(mon, EngineEvent::Rearm, 170);
        assert!(rearm_cmds.contains(&EffectCommand::ClearDisarmMarker));
        assert_eq!(rearming.lifecycle, Lifecycle::Disarmed);
        let (rearmed, rearm_ok_cmds) = GuardEngine::step(
            rearming,
            EngineEvent::RearmPersisted {
                ok: true,
                error: None,
            },
            171,
        );
        assert_eq!(rearmed.lifecycle, Lifecycle::Armed);
        assert_eq!(rearmed.protection, ProtectionState::Pending);
        assert!(
            rearm_ok_cmds
                .iter()
                .any(|c| matches!(c, EffectCommand::ResolveAccessAndProbe { .. }))
        );

        // SetPolicyPreset persists & increments cfg_rev, invalidating old round
        let (saving, save_cmds) = GuardEngine::step(
            rearmed,
            EngineEvent::SetPolicyPreset {
                preset: PolicyPreset::StrictStaticIp,
            },
            172,
        );
        let new_cfg = save_cmds
            .into_iter()
            .find_map(|c| match c {
                EffectCommand::PersistConfig { config, .. } => Some(config),
                _ => None,
            })
            .expect("PersistConfig");
        let (updated, _) = GuardEngine::step(
            saving,
            EngineEvent::ConfigPersisted {
                ok: true,
                config: Some(new_cfg),
                error: None,
            },
            173,
        );
        assert_eq!(updated.config.preset, PolicyPreset::StrictStaticIp);
        assert_eq!(updated.cfg_rev, 1);

        let snap = updated.to_snapshot(173, vec![]);
        assert_eq!(snap.preset, PolicyPreset::StrictStaticIp);
        assert!(snap.has_legal_state_pair());
        assert_eq!(snap.timeline.len(), 48);
    }

    #[test]
    fn disarmed_and_maintenance_never_kill_isolate_or_lockdown() {
        let mut cfg = armed_config();
        cfg.trip_threshold = 1;
        let mut state = EngineState::new(cfg, true, true, 100);
        state.lifecycle = Lifecycle::Disarmed;
        state.protection = ProtectionState::Monitoring;

        let (st1, cmds1) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: uncovered_access(),
                probes: fail_probes(),
            },
            101,
        );
        assert_eq!(st1.lifecycle, Lifecycle::Disarmed);
        assert!(!cmds1.iter().any(|c| matches!(
            c,
            EffectCommand::ExecuteIsolation { .. }
                | EffectCommand::KillGuardedAgents { .. }
                | EffectCommand::SyncLockdown { want: true, .. }
        )));

        let mut maint = st1;
        maint.lifecycle = Lifecycle::Maintenance;
        maint.protection = ProtectionState::Recovering;
        let (st2, cmds2) = GuardEngine::step(
            maint,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: uncovered_access(),
                probes: fail_probes(),
            },
            102,
        );
        assert_eq!(st2.lifecycle, Lifecycle::Maintenance);
        assert!(!cmds2.iter().any(|c| matches!(
            c,
            EffectCommand::ExecuteIsolation { .. }
                | EffectCommand::KillGuardedAgents { .. }
                | EffectCommand::SyncLockdown { want: true, .. }
        )));
    }

    #[test]
    fn unverified_target_blocks_launch_even_when_others_pass() {
        let state = EngineState::new(armed_config(), true, true, 100);
        let (st, _) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: unverified_probes(),
            },
            105,
        );
        assert_eq!(st.protection, ProtectionState::Monitoring);
        let gate = GuardEngine::evaluate_launch_gate(&st, 105);
        assert!(!gate.allowed);
        assert!(gate.requires_recheck);
    }

    #[test]
    fn manual_lockdown_off_requires_verified_readback_to_clear() {
        let mut state = EngineState::new(armed_config(), true, true, 100);
        state.lockdown_manual = true;
        state.lockdown_applied = Some(true);

        // Unconfirmed clear must preserve lockdown_manual = true
        let (st1, _) = GuardEngine::step(
            state,
            EngineEvent::ManualLockdownCompleted {
                on: false,
                receipt: OperationReceipt::new("ld", OperationStatus::Partial),
                confirmed: false,
                query_ok: true,
                rules: 2,
            },
            101,
        );
        assert!(st1.lockdown_manual);

        // Verified clear clears lockdown_manual
        let (st2, _) = GuardEngine::step(
            st1,
            EngineEvent::ManualLockdownCompleted {
                on: false,
                receipt: verified_receipt("ld"),
                confirmed: true,
                query_ok: true,
                rules: 0,
            },
            102,
        );
        assert!(!st2.lockdown_manual);
        assert_eq!(st2.lockdown_applied, Some(false));
    }

    #[test]
    fn pause_allows_clearing_auto_lockdown_but_blocks_adding_new_lockdown() {
        let mut state = EngineState::new(armed_config(), true, true, 100);
        state.paused_until = Some(500);
        state.lockdown_applied = Some(false);

        // Uncovered during pause must NOT emit SyncLockdown(want=true)
        let (st1, cmds1) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: uncovered_access(),
                probes: vec![],
            },
            110,
        );
        assert!(
            !cmds1
                .iter()
                .any(|c| matches!(c, EffectCommand::SyncLockdown { want: true, .. }))
        );

        // If lockdown was previously active (auto, not manual), covered access MAY clear it even while paused
        let mut st2 = st1;
        st2.lockdown_applied = Some(true);
        st2.lockdown_manual = false;
        let (_, cmds2) = GuardEngine::step(
            st2,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: pass_probes(),
            },
            120,
        );
        assert!(
            cmds2
                .iter()
                .any(|c| matches!(c, EffectCommand::SyncLockdown { want: false, .. }))
        );
    }

    #[test]
    fn flow_a_stage2_release_failure_transitions_to_degraded() {
        let mut state = EngineState::new(armed_config(), true, true, 100);
        state.protection = ProtectionState::NetworkReadyAppHeld;
        let (state, _) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Manual,
                access: covered_access(),
                probes: pass_probes(),
            },
            105,
        );
        assert_eq!(state.protection, ProtectionState::Recovering);
        let (degraded, cmds) = GuardEngine::step(
            state,
            EngineEvent::FlowAAppReleaseCompleted {
                runtime_epoch: 1,
                receipt: OperationReceipt::new("rel", OperationStatus::Failed),
            },
            106,
        );
        assert_eq!(degraded.protection, ProtectionState::Degraded);
        assert!(!cmds.contains(&EffectCommand::ClearWal));
    }

    #[test]
    fn rearm_rejects_illegal_states_and_handles_persistence_failure() {
        let mut state = EngineState::new(armed_config(), true, true, 100);
        // Reject when Armed
        let (_, cmds_armed) = GuardEngine::step(state.clone(), EngineEvent::Rearm, 101);
        assert!(matches!(
            cmds_armed.as_slice(),
            [EffectCommand::RequestRejected {
                code: ErrorCode::IllegalState,
                ..
            }]
        ));

        // Reject when Disarmed + NetworkReadyAppHeld
        state.lifecycle = Lifecycle::Disarmed;
        state.protection = ProtectionState::NetworkReadyAppHeld;
        let (_, cmds_held) = GuardEngine::step(state.clone(), EngineEvent::Rearm, 102);
        assert!(matches!(
            cmds_held.as_slice(),
            [EffectCommand::RequestRejected {
                code: ErrorCode::IllegalState,
                ..
            }]
        ));

        // Failed RearmPersisted keeps Disarmed
        state.protection = ProtectionState::Monitoring;
        let (failed, _) = GuardEngine::step(
            state,
            EngineEvent::RearmPersisted {
                ok: false,
                error: Some("io error".into()),
            },
            103,
        );
        assert_eq!(failed.lifecycle, Lifecycle::Disarmed);
        assert_eq!(failed.last_error, "io error");
    }

    #[test]
    fn invalid_config_save_rejected_without_emitting_persist() {
        let state = EngineState::new(armed_config(), true, true, 100);
        let mut bad = armed_config();
        bad.targets[1].anchor_url = "http://insecure.example.com/trace".into();
        let (after, cmds) =
            GuardEngine::step(state.clone(), EngineEvent::SaveConfig { next: bad }, 101);
        assert_eq!(after.cfg_rev, state.cfg_rev);
        assert!(matches!(
            cmds.as_slice(),
            [EffectCommand::RequestRejected {
                code: ErrorCode::ValidationFailed,
                ..
            }]
        ));
    }

    #[test]
    fn maintenance_exit_handles_success_and_failure() {
        let state = EngineState::new(armed_config(), true, true, 100);
        let (maint, _) = GuardEngine::step(
            state,
            EngineEvent::EnterMaintenance {
                reason: "self update".into(),
                allow_while_isolated: false,
            },
            101,
        );
        assert_eq!(maint.lifecycle, Lifecycle::Maintenance);
        assert_eq!(maint.protection, ProtectionState::Recovering);

        let (ok_armed, _) = GuardEngine::step(
            maint.clone(),
            EngineEvent::ExitMaintenance {
                ok: true,
                error: None,
            },
            102,
        );
        assert_eq!(ok_armed.lifecycle, Lifecycle::Armed);
        assert_eq!(ok_armed.protection, ProtectionState::Pending);

        let (err_armed, _) = GuardEngine::step(
            maint,
            EngineEvent::ExitMaintenance {
                ok: false,
                error: Some("handoff timeout".into()),
            },
            103,
        );
        assert_eq!(err_armed.lifecycle, Lifecycle::Armed);
        assert_eq!(err_armed.protection, ProtectionState::Degraded);
        assert_eq!(err_armed.last_error, "handoff timeout");
    }

    #[test]
    fn uncovered_access_streak_debounces_before_tripping() {
        let mut cfg = armed_config();
        cfg.trip_threshold = 2;
        let state = EngineState::new(cfg, true, true, 100);

        let (st1, cmds1) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: uncovered_access(),
                probes: vec![],
            },
            101,
        );
        assert_eq!(st1.access_streak, 1);
        assert_eq!(st1.protection, ProtectionState::Monitoring);
        assert!(
            !cmds1
                .iter()
                .any(|c| matches!(c, EffectCommand::ExecuteIsolation { .. }))
        );

        let (st2, cmds2) = GuardEngine::step(
            st1,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: uncovered_access(),
                probes: vec![],
            },
            102,
        );
        assert_eq!(st2.access_streak, 2);
        assert_eq!(st2.protection, ProtectionState::Isolating);
        assert!(
            cmds2
                .iter()
                .any(|c| matches!(c, EffectCommand::ExecuteIsolation { .. }))
        );
    }

    #[test]
    fn antigravity_proxy_updated_emits_degraded_warning_once_per_state_transition() {
        use cg_protocol::AntigravityProxyState;

        let mut cfg = armed_config();
        cfg.require_antigravity_proxy = true;
        let state = EngineState::new(cfg, true, true, 100);
        let missing = AntigravityProxyStatus {
            state: AntigravityProxyState::MissingDll,
            installed: true,
            antigravity_version: Some("44.9.1".into()),
            summary: "version.dll 缺失，存在直连风险".into(),
            ..AntigravityProxyStatus::default()
        };

        let (st1, cmds1) = GuardEngine::step(
            state,
            EngineEvent::AntigravityProxyUpdated {
                status: missing.clone(),
            },
            105,
        );
        assert_eq!(
            st1.antigravity_proxy.state,
            AntigravityProxyState::MissingDll
        );
        assert_eq!(
            st1.to_snapshot(105, Vec::new()).antigravity_proxy.state,
            AntigravityProxyState::MissingDll
        );
        assert_eq!(
            st1.config.last_seen_antigravity_version.as_deref(),
            Some("44.9.1")
        );
        assert!(st1.logs.iter().any(|l| {
            l.level == LogLevel::Warn
                && l.category == "ag_proxy"
                && l.message.contains("version.dll 缺失")
        }));
        assert!(cmds1.iter().any(|c| matches!(
            c,
            EffectCommand::Notify { class, title, body }
                if class == "warning"
                    && title == "反重力透明代理异常：注入丢失 (version.dll)"
                    && body.contains("version.dll 缺失")
        )));
        assert!(
            !cmds1
                .iter()
                .any(|c| matches!(c, EffectCommand::PersistConfig { .. }))
        );

        // Same degraded state on subsequent poll must not spam duplicate warning notifications.
        let (st2, cmds2) = GuardEngine::step(
            st1,
            EngineEvent::AntigravityProxyUpdated { status: missing },
            110,
        );
        assert!(
            !cmds2
                .iter()
                .any(|c| matches!(c, EffectCommand::Notify { .. }))
        );

        // Transitioning to a different degraded state emits a new warning alert.
        let unhooked = AntigravityProxyStatus {
            state: AntigravityProxyState::RuntimeUnhooked,
            installed: true,
            antigravity_version: Some("44.9.1".into()),
            runtime_running: true,
            summary: "language_server.exe 未加载 version.dll".into(),
            ..AntigravityProxyStatus::default()
        };
        let (st3, cmds3) = GuardEngine::step(
            st2,
            EngineEvent::AntigravityProxyUpdated { status: unhooked },
            115,
        );
        assert_eq!(
            st3.antigravity_proxy.state,
            AntigravityProxyState::RuntimeUnhooked
        );
        assert!(cmds3.iter().any(|c| matches!(
            c,
            EffectCommand::Notify { class, title, .. }
                if class == "warning" && title == "反重力透明代理异常：运行态未挂载"
        )));
    }

    #[test]
    fn antigravity_proxy_optional_mode_suppresses_degraded_warning_spam() {
        use cg_protocol::AntigravityProxyState;

        let mut cfg = armed_config();
        cfg.require_antigravity_proxy = false;
        let state = EngineState::new(cfg, true, true, 100);

        let missing = AntigravityProxyStatus {
            state: AntigravityProxyState::MissingDll,
            installed: true,
            antigravity_version: Some("44.9.1".into()),
            summary: "未检测到 version.dll".into(),
            ..AntigravityProxyStatus::default()
        };

        let (st1, cmds1) = GuardEngine::step(
            state,
            EngineEvent::AntigravityProxyUpdated { status: missing },
            105,
        );
        assert_eq!(
            st1.antigravity_proxy.state,
            AntigravityProxyState::MissingDll
        );
        assert!(
            !st1.logs
                .iter()
                .any(|l| l.level == LogLevel::Warn && l.category == "ag_proxy"),
            "require_antigravity_proxy=false must not emit Warn log for MissingDll"
        );
        assert!(
            !cmds1
                .iter()
                .any(|c| matches!(c, EffectCommand::Notify { class, .. } if class == "warning")),
            "require_antigravity_proxy=false must not emit warning notification for MissingDll"
        );

        let unhooked = AntigravityProxyStatus {
            state: AntigravityProxyState::RuntimeUnhooked,
            installed: true,
            antigravity_version: Some("44.9.1".into()),
            runtime_running: true,
            summary: "language_server.exe 未加载 version.dll".into(),
            ..AntigravityProxyStatus::default()
        };
        let (st2, cmds2) = GuardEngine::step(
            st1,
            EngineEvent::AntigravityProxyUpdated { status: unhooked },
            110,
        );
        assert_eq!(
            st2.antigravity_proxy.state,
            AntigravityProxyState::RuntimeUnhooked
        );
        assert!(
            !st2.logs
                .iter()
                .any(|l| l.level == LogLevel::Warn && l.category == "ag_proxy")
        );
        assert!(
            !cmds2
                .iter()
                .any(|c| matches!(c, EffectCommand::Notify { class, .. } if class == "warning"))
        );
    }

    #[test]
    fn antigravity_proxy_version_upgrade_persists_config_and_notifies_client_update() {
        use cg_protocol::AntigravityProxyState;

        let mut cfg = armed_config();
        cfg.require_antigravity_proxy = true;
        cfg.last_seen_antigravity_version = Some("44.9.1".into());
        let state = EngineState::new(cfg, true, true, 100);
        assert_eq!(state.cfg_rev, 0);

        let upgraded_missing = AntigravityProxyStatus {
            state: AntigravityProxyState::MissingDll,
            installed: true,
            antigravity_version: Some("45.0.0".into()),
            version_changed_from: Some("44.9.1".into()),
            summary: "反重力升级至 v45.0.0 后 version.dll 被覆盖丢失".into(),
            ..AntigravityProxyStatus::default()
        };

        let (after, cmds) = GuardEngine::step(
            state,
            EngineEvent::AntigravityProxyUpdated {
                status: upgraded_missing,
            },
            120,
        );
        assert_eq!(after.cfg_rev, 1);
        assert_eq!(
            after.config.last_seen_antigravity_version.as_deref(),
            Some("45.0.0")
        );
        assert!(after.logs.iter().any(|l| {
            l.level == LogLevel::Audit
                && l.category == "ag_proxy"
                && l.message.contains("44.9.1")
                && l.message.contains("45.0.0")
        }));
        assert!(cmds.iter().any(|c| matches!(
            c,
            EffectCommand::PersistConfig {
                config,
                target_cfg_rev: 1,
            } if config.last_seen_antigravity_version.as_deref() == Some("45.0.0")
        )));
        assert!(cmds.iter().any(|c| matches!(
            c,
            EffectCommand::Notify { class, title, body }
                if class == "client_update"
                    && title == "检测到反重力客户端更新"
                    && body.contains("v45.0.0")
        )));
        assert!(cmds.iter().any(|c| matches!(
            c,
            EffectCommand::Notify { class, title, .. }
                if class == "warning" && title == "反重力透明代理异常：注入丢失 (version.dll)"
        )));
    }

    #[test]
    fn evaluate_launch_gate_for_agent_blocks_uninjected_antigravity_and_allows_healthy_or_other_agents()
     {
        use cg_protocol::AntigravityProxyState;

        let mut cfg = armed_config();
        cfg.require_antigravity_proxy = true;
        let state = EngineState::new(cfg, true, true, 100);
        let (mut ready, _) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: pass_probes(),
            },
            105,
        );
        assert!(GuardEngine::evaluate_launch_gate(&ready, 106).allowed);

        // MissingDll blocks Antigravity fail-closed, while Claude and generic gate remain allowed.
        ready.antigravity_proxy = AntigravityProxyStatus {
            state: AntigravityProxyState::MissingDll,
            installed: true,
            summary: "version.dll 缺失".into(),
            ..AntigravityProxyStatus::default()
        };
        let blocked_dll = evaluate_launch_gate_for_agent(&ready, Some("antigravity"), 106);
        assert!(!blocked_dll.allowed);
        assert!(!blocked_dll.requires_recheck);
        assert!(blocked_dll.reason.contains("注入丢失 (version.dll)"));
        assert!(blocked_dll.reason.contains("antigravity-launcher"));
        assert!(blocked_dll.reason.contains("反重力注入强制核验"));
        assert!(evaluate_launch_gate_for_agent(&ready, Some("claude"), 106).allowed);
        assert!(GuardEngine::evaluate_launch_gate(&ready, 106).allowed);

        // RuntimeUnhooked also blocks Antigravity launch.
        ready.antigravity_proxy.state = AntigravityProxyState::RuntimeUnhooked;
        ready.antigravity_proxy.summary = "language_server 未挂载".into();
        let blocked_rt =
            GuardEngine::evaluate_launch_gate_for_agent(&ready, Some("antigravity"), 106);
        assert!(!blocked_rt.allowed);
        assert!(blocked_rt.reason.contains("运行态未挂载"));

        // Healthy injection allows Antigravity launch.
        ready.antigravity_proxy.state = AntigravityProxyState::Healthy;
        ready.antigravity_proxy.summary = "注入生效".into();
        assert!(
            GuardEngine::evaluate_launch_gate_for_agent(&ready, Some("antigravity"), 106).allowed
        );

        // Disabling require_antigravity_proxy bypasses the injection check while still enforcing normal egress gate.
        ready.antigravity_proxy.state = AntigravityProxyState::MissingDll;
        ready.config.require_antigravity_proxy = false;
        assert!(
            GuardEngine::evaluate_launch_gate_for_agent(&ready, Some("antigravity"), 106).allowed
        );
    }

    #[test]
    fn updates_checked_projects_snapshot_and_dedups_notifications_per_latest_version() {
        let state = EngineState::new(armed_config(), true, true, 100);
        assert_eq!(state.updates, UpdateSummary::default());

        let mut summary1 = UpdateSummary::default();
        summary1.antigravity_proxy.phase = UpdateCheckPhase::UpdateAvailable;
        summary1.antigravity_proxy.installed_version = Some("2.6.0".into());
        summary1.antigravity_proxy.latest_version = Some("2.6.3".into());
        summary1.antigravity_proxy.note = "antigravity-proxy 2.6.0 -> 2.6.3".into();
        summary1.claudeguard.phase = UpdateCheckPhase::UpdateAvailable;
        summary1.claudeguard.latest_version = Some("4.1.0".into());
        summary1.claudeguard.note = "ClaudeGuard 4.0.0 -> 4.1.0".into();
        summary1.claude_msix_version = Some("1.2.3.0".into());
        summary1.codex_msix_version = Some("26.501.0.0".into());

        let (st1, cmds1) = GuardEngine::step(
            state,
            EngineEvent::UpdatesChecked {
                summary: Box::new(summary1.clone()),
            },
            110,
        );
        assert_eq!(st1.updates, summary1);
        assert_eq!(st1.to_snapshot(110, Vec::new()).updates, summary1);
        assert!(st1.logs.iter().any(|l| {
            l.level == LogLevel::Warn
                && l.category == "update"
                && l.message == "antigravity-proxy 2.6.0 -> 2.6.3"
        }));
        assert!(st1.logs.iter().any(|l| {
            l.level == LogLevel::Info
                && l.category == "update"
                && l.message == "ClaudeGuard 4.0.0 -> 4.1.0"
        }));
        assert!(cmds1.iter().any(|c| matches!(
            c,
            EffectCommand::Notify { class, title, body }
                if class == "client_update"
                    && title == "antigravity-proxy 发现新版本"
                    && body == "antigravity-proxy 2.6.0 -> 2.6.3"
        )));
        assert!(cmds1.iter().any(|c| matches!(
            c,
            EffectCommand::Notify { class, title, body }
                if class == "self_update"
                    && title == "ClaudeGuard 发现新版本"
                    && body == "ClaudeGuard 4.0.0 -> 4.1.0"
        )));

        // Re-checking with identical latest_version must not re-notify or duplicate logs.
        let logs_before = st1.logs.len();
        let (st2, cmds2) = GuardEngine::step(
            st1,
            EngineEvent::UpdatesChecked {
                summary: Box::new(summary1.clone()),
            },
            120,
        );
        assert_eq!(st2.logs.len(), logs_before);
        assert!(
            !cmds2
                .iter()
                .any(|c| matches!(c, EffectCommand::Notify { .. }))
        );

        // Bumping antigravity_proxy latest_version notifies only for antigravity_proxy.
        let mut summary2 = summary1;
        summary2.antigravity_proxy.latest_version = Some("2.6.4".into());
        summary2.antigravity_proxy.note = "antigravity-proxy 2.6.0 -> 2.6.4".into();
        let (st3, cmds3) = GuardEngine::step(
            st2,
            EngineEvent::UpdatesChecked {
                summary: Box::new(summary2),
            },
            130,
        );
        assert!(cmds3.iter().any(|c| matches!(
            c,
            EffectCommand::Notify { class, body, .. }
                if class == "client_update" && body == "antigravity-proxy 2.6.0 -> 2.6.4"
        )));
        assert!(!cmds3.iter().any(|c| matches!(
            c,
            EffectCommand::Notify { class, .. } if class == "self_update"
        )));
        assert_eq!(
            st3.updates.antigravity_proxy.latest_version.as_deref(),
            Some("2.6.4")
        );
    }

    #[test]
    fn kill_cli_on_fail_propagates_to_execute_isolation_and_kill_guarded_agents() {
        let mut cfg_off = armed_config();
        cfg_off.trip_threshold = 1;
        cfg_off.kill_cli_on_fail = false;
        let state_off = EngineState::new(cfg_off, true, true, 100);
        let (iso_off, cmds_off) = GuardEngine::step(
            state_off,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: fail_probes(),
            },
            101,
        );
        assert!(cmds_off.iter().any(|c| matches!(
            c,
            EffectCommand::ExecuteIsolation {
                kill_cli_on_fail: false,
                ..
            }
        )));

        let ep_off = iso_off.runtime_epoch;
        let (q_off, _) = GuardEngine::step(
            iso_off,
            EngineEvent::IsolationCompleted {
                runtime_epoch: ep_off,
                receipt: verified_receipt("iso"),
                killed: 1,
                cli_killed: 0,
                firewall_rules: 1,
                quarantined_agents: vec!["claude".into()],
                network_cut_applied: CutMode::Off,
                network_note: String::new(),
            },
            102,
        );
        let (_, kill_cmds_off) = GuardEngine::step(
            q_off,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: ep_off,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: fail_probes(),
            },
            103,
        );
        assert!(kill_cmds_off.iter().any(|c| matches!(
            c,
            EffectCommand::KillGuardedAgents {
                include_claude_cli: false,
                ..
            }
        )));

        // When enabled (even if guarded_agents omits "claude"), kill_cli_on_fail propagates as true.
        let mut cfg_on = armed_config();
        cfg_on.trip_threshold = 1;
        cfg_on.guarded_agents = vec!["chatgpt".into()];
        cfg_on.kill_cli_on_fail = true;
        let state_on = EngineState::new(cfg_on, true, true, 100);
        let (iso_on, cmds_on) = GuardEngine::step(
            state_on,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: fail_probes(),
            },
            101,
        );
        assert!(cmds_on.iter().any(|c| matches!(
            c,
            EffectCommand::ExecuteIsolation {
                kill_cli_on_fail: true,
                ..
            }
        )));

        let ep_on = iso_on.runtime_epoch;
        let (q_on, _) = GuardEngine::step(
            iso_on,
            EngineEvent::IsolationCompleted {
                runtime_epoch: ep_on,
                receipt: verified_receipt("iso"),
                killed: 1,
                cli_killed: 1,
                firewall_rules: 1,
                quarantined_agents: vec!["chatgpt".into()],
                network_cut_applied: CutMode::Off,
                network_note: String::new(),
            },
            102,
        );
        let (_, kill_cmds_on) = GuardEngine::step(
            q_on,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: ep_on,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: fail_probes(),
            },
            103,
        );
        assert!(kill_cmds_on.iter().any(|c| matches!(
            c,
            EffectCommand::KillGuardedAgents {
                include_claude_cli: true,
                ..
            }
        )));
    }

    #[test]
    fn ip_unchanged_suppresses_same_ip_geo_blip_but_trips_when_failing_target_lacks_ip() {
        let mut cfg = armed_config();
        cfg.trip_threshold = 2;
        cfg.suppress_trip_when_ip_unchanged = true;
        // Region-only allowlist (US) so a GeoIP blip on the SAME IP triggers PolicyVerdict::Fail.
        for t in &mut cfg.targets {
            t.expect_ips.clear();
        }
        // Add a region-only custom target (no IP returned).
        cfg.targets.push(Target {
            id: "gemini".into(),
            name: "Gemini 地区".into(),
            builtin: false,
            enabled: true,
            anchor_url: "https://gemini.google.com/".into(),
            anchor_kind: AnchorKind::GeminiRegion,
            expect_ips: Vec::new(),
            expect_regions: vec!["US".into()],
            timeout_secs: 12,
            bind_agent: None,
        });
        let state = EngineState::new(cfg, true, true, 100);

        // Round 1: establish verified compliant baseline IPs (claude=198.51.100.98, codex=198.51.100.99).
        let mut pass = pass_probes();
        pass.push((
            "gemini".into(),
            ProbeResult {
                reachable: true,
                status: Some(200),
                ip: None,
                country: Some("US".into()),
                raw_region: Some("USA".into()),
                latency_ms: 40,
                parsed_as: "gemini_region".into(),
                ..ProbeResult::default()
            },
        ));
        let (state, _) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: pass.clone(),
            },
            110,
        );
        assert_eq!(
            state.last_pass_ips.get("claude").map(String::as_str),
            Some("198.51.100.98")
        );
        assert_eq!(
            state.last_pass_ips.get("codex").map(String::as_str),
            Some("198.51.100.99")
        );

        // Round 2 & 3: codex suffers a GeoIP blip (reports SG) while keeping EXACT SAME IP 198.51.100.99,
        // and gemini continues passing -> MUST NOT trip or kill!
        let mut same_ip_blip = pass.clone();
        for (id, p) in &mut same_ip_blip {
            if id == "codex" {
                p.ip = Some("198.51.100.99".into());
                p.country = Some("SG".into());
                p.raw_region = Some("SG".into());
            }
        }

        let (state, cmds2) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: same_ip_blip.clone(),
            },
            125,
        );
        assert_eq!(state.protection, ProtectionState::Monitoring);
        assert!(
            !cmds2
                .iter()
                .any(|c| matches!(c, EffectCommand::ExecuteIsolation { .. }))
        );

        let (state, cmds3) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: same_ip_blip,
            },
            140,
        );
        assert_eq!(state.protection, ProtectionState::Monitoring);
        assert!(
            !cmds3
                .iter()
                .any(|c| matches!(c, EffectCommand::ExecuteIsolation { .. }))
        );
        assert!(state.launch_error.contains("未变"));
        assert!(
            !GuardEngine::evaluate_launch_gate(&state, 140).allowed,
            "launch gate must stay closed until all targets pass"
        );

        // [C-02] When a failing target lacks an observable IP (`gemini` -> `ip: None`, `country: Some("CN")`),
        // `egress_ip_unchanged_summary` MUST NOT suppress the circuit-breaker trip!
        let mut no_ip_fail = pass;
        for (id, p) in &mut no_ip_fail {
            if id == "gemini" {
                p.ip = None;
                p.country = Some("CN".into());
                p.raw_region = Some("CHN".into());
            }
        }
        let (state, _) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: no_ip_fail.clone(),
            },
            155,
        );
        let (state, cmds_trip) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: no_ip_fail,
            },
            170,
        );
        assert_eq!(state.protection, ProtectionState::Isolating);
        assert!(
            cmds_trip
                .iter()
                .any(|c| matches!(c, EffectCommand::ExecuteIsolation { .. }))
        );
    }

    #[test]
    fn ip_changed_to_non_compliant_and_never_passed_ip_still_trip() {
        let mut cfg = armed_config();
        cfg.trip_threshold = 1;
        cfg.suppress_trip_when_ip_unchanged = true;
        let state = EngineState::new(cfg.clone(), true, true, 100);

        // Starting on a non-compliant CN IP (never passed -> no baseline) MUST trip immediately.
        let (st_never_passed, cmds_np) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: fail_probes(),
            },
            105,
        );
        assert_eq!(st_never_passed.protection, ProtectionState::Isolating);
        assert!(
            cmds_np
                .iter()
                .any(|c| matches!(c, EffectCommand::ExecuteIsolation { .. }))
        );

        // Passing first on 198.51.100.10 then drifting to a DIFFERENT CN IP 203.0.113.55 MUST trip.
        let state2 = EngineState::new(cfg, true, true, 100);
        let (state2, _) = GuardEngine::step(
            state2,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: pass_probes(),
            },
            110,
        );
        let (state2, cmds_drift) = GuardEngine::step(
            state2,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: fail_probes(), // 203.0.113.55 != 198.51.100.10
            },
            125,
        );
        assert_eq!(state2.protection, ProtectionState::Isolating);
        assert!(
            cmds_drift
                .iter()
                .any(|c| matches!(c, EffectCommand::ExecuteIsolation { .. }))
        );
    }

    #[test]
    fn access_uncovered_always_trips_even_when_ip_unchanged_guard_on() {
        let mut cfg = armed_config();
        cfg.trip_threshold = 1;
        cfg.suppress_trip_when_ip_unchanged = true;
        let state = EngineState::new(cfg, true, true, 100);

        // Establish compliant IP baseline first.
        let (state, _) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: pass_probes(),
            },
            110,
        );
        assert!(!state.last_pass_ips.is_empty());

        // Proxy turned off (access_uncovered) -> MUST trip immediately regardless of baseline!
        let (state, cmds) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: uncovered_access(),
                probes: Vec::new(),
            },
            125,
        );
        assert_eq!(state.protection, ProtectionState::Isolating);
        assert!(
            cmds.iter()
                .any(|c| matches!(c, EffectCommand::ExecuteIsolation { .. }))
        );
    }

    #[test]
    fn config_change_clears_ip_baseline_and_disabling_guard_trips_same_ip() {
        let mut cfg = armed_config();
        cfg.trip_threshold = 1;
        cfg.suppress_trip_when_ip_unchanged = true;
        let state = EngineState::new(cfg.clone(), true, true, 100);

        // Establish baseline on 198.51.100.10 (US).
        let (state, _) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: pass_probes(),
            },
            110,
        );
        assert!(!state.last_pass_ips.is_empty());

        // User tightens whitelist to JP only (clearing IP allowlist) -> config persisted clears baseline.
        let mut tightened = cfg.clone();
        for t in &mut tightened.targets {
            if t.enabled && t.anchor_kind != AnchorKind::Reachability {
                t.expect_ips.clear();
                t.expect_regions = vec!["JP".into()];
            }
        }
        let (state, _) = GuardEngine::step(
            state,
            EngineEvent::ConfigPersisted {
                ok: true,
                config: Some(tightened),
                error: None,
            },
            115,
        );
        assert!(state.last_pass_ips.is_empty());
        let rev = state.cfg_rev;
        let ep = state.runtime_epoch;
        let (state, cmds_tight) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: rev,
                runtime_epoch: ep,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: pass_probes(), // 198.51.100.98 (US) is now disallowed
            },
            120,
        );
        assert_eq!(state.protection, ProtectionState::Isolating);
        assert!(
            cmds_tight
                .iter()
                .any(|c| matches!(c, EffectCommand::ExecuteIsolation { .. }))
        );

        // Disabling suppress_trip_when_ip_unchanged trips even when IP stays identical.
        let mut strict_cfg = armed_config();
        strict_cfg.trip_threshold = 1;
        strict_cfg.suppress_trip_when_ip_unchanged = false;
        for t in &mut strict_cfg.targets {
            t.expect_ips.clear();
        }
        let st_strict = EngineState::new(strict_cfg, true, true, 100);
        let (st_strict, _) = GuardEngine::step(
            st_strict,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: pass_probes(),
            },
            110,
        );
        let mut same_ip_fail = pass_probes();
        for (id, p) in &mut same_ip_fail {
            if id == "claude" {
                p.ip = Some("198.51.100.98".into());
                p.country = Some("SG".into());
                p.raw_region = Some("SG".into());
            }
        }
        let (st_strict, cmds_strict) = GuardEngine::step(
            st_strict,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: same_ip_fail,
            },
            120,
        );
        assert_eq!(st_strict.protection, ProtectionState::Isolating);
        assert!(
            cmds_strict
                .iter()
                .any(|c| matches!(c, EffectCommand::ExecuteIsolation { .. }))
        );
    }

    #[test]
    fn reachability_timeout_never_trips_and_still_blocks_launch_gate() {
        let mut cfg = armed_config();
        cfg.trip_threshold = 1;
        let state = EngineState::new(cfg, true, true, 100);

        // Claude & Codex pass, Antigravity (Reachability) times out twice in a row.
        let mut ag_timeout = pass_probes();
        for (id, p) in &mut ag_timeout {
            if id == "antigravity" {
                *p = ProbeResult::failed("proxy timeout");
            }
        }
        let (state, cmds1) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: ag_timeout.clone(),
            },
            110,
        );
        let (state, cmds2) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: ag_timeout,
            },
            125,
        );
        assert_eq!(state.protection, ProtectionState::Monitoring);
        assert!(
            !cmds1
                .iter()
                .any(|c| matches!(c, EffectCommand::ExecuteIsolation { .. }))
        );
        assert!(
            !cmds2
                .iter()
                .any(|c| matches!(c, EffectCommand::ExecuteIsolation { .. }))
        );
        let ag = state
            .target_statuses
            .iter()
            .find(|t| t.id == "antigravity")
            .expect("antigravity status");
        assert_eq!(ag.state, TargetState::Unverified);
        assert_eq!(ag.fail_streak, 0);
        // Launch Gate still refuses launching while Antigravity backend is unreachable.
        assert!(!GuardEngine::evaluate_launch_gate(&state, 125).allowed);
    }

    #[test]
    fn monitor_only_suppresses_auto_trip_kill_and_auto_lockdown_while_keeping_manual_lockdown() {
        let mut cfg = armed_config();
        cfg.trip_threshold = 1;
        cfg.monitor_only = true;
        cfg.leak_trip = true;
        cfg.lockdown_on_uncovered = true;
        let state = EngineState::new(cfg, true, true, 100);

        // Non-compliant CN IP does NOT trip or kill, warns once, and blocks launch gate.
        let (state, cmds_fail) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: fail_probes(),
            },
            110,
        );
        assert_eq!(state.protection, ProtectionState::Monitoring);
        assert!(!cmds_fail.iter().any(|c| matches!(
            c,
            EffectCommand::ExecuteIsolation { .. } | EffectCommand::KillGuardedAgents { .. }
        )));
        assert!(
            cmds_fail
                .iter()
                .any(|c| matches!(c, EffectCommand::Notify { class, .. } if class == "warning"))
        );
        assert!(!GuardEngine::evaluate_launch_gate(&state, 110).allowed);

        // Uncovered access does NOT auto-lockdown or trip in monitor_only mode.
        let (state, cmds_unc) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: uncovered_access(),
                probes: Vec::new(),
            },
            125,
        );
        assert_eq!(state.protection, ProtectionState::Monitoring);
        assert!(!cmds_unc.iter().any(|c| matches!(
            c,
            EffectCommand::ExecuteIsolation { .. } | EffectCommand::SyncLockdown { want: true, .. }
        )));

        // Leak report does NOT auto-trip in monitor_only mode.
        let (state, cmds_leak) = GuardEngine::step(
            state,
            EngineEvent::LeakUpdated {
                report: LeakReport {
                    applicable: true,
                    direct_total: 2,
                    ..LeakReport::default()
                },
            },
            130,
        );
        assert_eq!(state.protection, ProtectionState::Monitoring);
        assert!(
            !cmds_leak
                .iter()
                .any(|c| matches!(c, EffectCommand::ExecuteIsolation { .. }))
        );

        // Manual lockdown STILL works when explicitly invoked by user.
        let (_, cmds_manual) =
            GuardEngine::step(state, EngineEvent::SetManualLockdown { on: true }, 135);
        assert!(cmds_manual.iter().any(|c| matches!(
            c,
            EffectCommand::SyncLockdown {
                want: true,
                manual: true,
                ..
            }
        )));
    }

    #[test]
    fn mid_transaction_config_mutations_rejected_and_ag_proxy_persist_deferred() {
        use cg_protocol::AntigravityProxyState;

        let mut cfg = armed_config();
        cfg.trip_threshold = 1;
        cfg.last_seen_antigravity_version = Some("44.9.1".into());
        let state = EngineState::new(cfg.clone(), true, true, 100);

        // Trigger isolation -> protection == Isolating, pending_tx == Some(..)
        let (iso_state, _) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: fail_probes(),
            },
            105,
        );
        assert_eq!(iso_state.protection, ProtectionState::Isolating);
        assert!(iso_state.pending_tx.is_some());
        let tx_epoch = iso_state.runtime_epoch;

        // SaveConfig and SetPolicyPreset MUST be rejected with Busy while transaction is in flight.
        let (s1, c_save) = GuardEngine::step(
            iso_state.clone(),
            EngineEvent::SaveConfig { next: cfg.clone() },
            106,
        );
        assert_eq!(s1.runtime_epoch, tx_epoch);
        assert!(matches!(
            c_save.as_slice(),
            [EffectCommand::RequestRejected {
                code: ErrorCode::Busy,
                ..
            }]
        ));

        let (_, c_preset) = GuardEngine::step(
            iso_state.clone(),
            EngineEvent::SetPolicyPreset {
                preset: PolicyPreset::StrictStaticIp,
            },
            106,
        );
        assert!(matches!(
            c_preset.as_slice(),
            [EffectCommand::RequestRejected {
                code: ErrorCode::Busy,
                ..
            }]
        ));

        // AntigravityProxyUpdated during Isolating MUST NOT emit PersistConfig or advance last_seen_antigravity_version yet.
        let upgraded = AntigravityProxyStatus {
            state: AntigravityProxyState::MissingDll,
            installed: true,
            antigravity_version: Some("45.0.0".into()),
            version_changed_from: Some("44.9.1".into()),
            summary: "升级至 v45.0.0".into(),
            ..AntigravityProxyStatus::default()
        };
        let (iso_after_ag, cmds_ag) = GuardEngine::step(
            iso_state,
            EngineEvent::AntigravityProxyUpdated {
                status: upgraded.clone(),
            },
            107,
        );
        assert!(
            !cmds_ag
                .iter()
                .any(|c| matches!(c, EffectCommand::PersistConfig { .. }))
        );
        assert_eq!(
            iso_after_ag.config.last_seen_antigravity_version.as_deref(),
            Some("44.9.1")
        );
        assert_eq!(iso_after_ag.runtime_epoch, tx_epoch);

        // IsolationCompleted completes without deadlocking!
        let (quarantined, _) = GuardEngine::step(
            iso_after_ag,
            EngineEvent::IsolationCompleted {
                runtime_epoch: tx_epoch,
                receipt: verified_receipt("iso"),
                killed: 1,
                cli_killed: 0,
                firewall_rules: 2,
                quarantined_agents: vec!["claude".into()],
                network_cut_applied: CutMode::Off,
                network_note: String::new(),
            },
            108,
        );
        assert_eq!(quarantined.protection, ProtectionState::Quarantined);
        assert!(quarantined.pending_tx.is_none());

        // Next clean telemetry tick persists last_seen_antigravity_version as expected.
        let (persisted_ag, cmds_ag2) = GuardEngine::step(
            quarantined,
            EngineEvent::AntigravityProxyUpdated { status: upgraded },
            110,
        );
        assert_eq!(
            persisted_ag.config.last_seen_antigravity_version.as_deref(),
            Some("45.0.0")
        );
        assert!(
            cmds_ag2
                .iter()
                .any(|c| matches!(c, EffectCommand::PersistConfig { .. }))
        );
    }

    #[test]
    fn sleep_wake_grace_window_suppresses_false_trip_and_clears_on_pass() {
        let mut cfg = armed_config();
        cfg.trip_threshold = 1;
        let state = EngineState::new(cfg, true, true, 100);

        // Initial compliant round at t=110.
        let (mut state, _) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: pass_probes(),
            },
            110,
        );
        state.lockdown_applied = Some(false);

        // Simulate laptop waking from sleep at t=500 (jump = 390s > 45s) while Wi-Fi/proxy is still down!
        let (woke, cmds_wake) = GuardEngine::step(
            state,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: uncovered_access(),
                probes: Vec::new(),
            },
            500,
        );
        assert_eq!(woke.resume_grace_until, Some(520));
        assert_eq!(woke.protection, ProtectionState::Monitoring);
        assert!(!woke.launch_error.is_empty());
        assert!(!GuardEngine::evaluate_launch_gate(&woke, 500).allowed);
        assert!(!cmds_wake.iter().any(|c| matches!(
            c,
            EffectCommand::ExecuteIsolation { .. } | EffectCommand::SyncLockdown { want: true, .. }
        )));
        assert!(
            woke.logs
                .iter()
                .any(|l| l.message.contains("20 秒网络重连缓冲期"))
        );

        // Explicit notify_system_resumed at t=510 extends grace to 530 and resets streaks.
        let mut manual_wake = woke.clone();
        GuardEngine::notify_system_resumed(&mut manual_wake, 510);
        assert_eq!(manual_wake.resume_grace_until, Some(530));
        assert_eq!(manual_wake.access_streak, 0);

        // Passing round at t=512 clears resume_grace_until immediately!
        let (recovered, _) = GuardEngine::step(
            manual_wake,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: pass_probes(),
            },
            512,
        );
        assert!(recovered.resume_grace_until.is_none());
        assert!(GuardEngine::evaluate_launch_gate(&recovered, 512).allowed);

        // If still failing AFTER the 20s grace window expires (t=525 >= 520), normal isolation trips.
        let (tripped_after_grace, cmds_after) = GuardEngine::step(
            woke,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: fail_probes(),
            },
            525,
        );
        assert!(tripped_after_grace.resume_grace_until.is_none());
        assert_eq!(tripped_after_grace.protection, ProtectionState::Isolating);
        assert!(
            cmds_after
                .iter()
                .any(|c| matches!(c, EffectCommand::ExecuteIsolation { .. }))
        );
    }

    #[test]
    fn monitor_only_transition_releases_quarantine_and_guarded_agents_resyncs_lockdown() {
        let mut cfg = armed_config();
        cfg.trip_threshold = 1;
        let mut state = EngineState::new(cfg.clone(), true, true, 100);
        state.protection = ProtectionState::Quarantined;
        state.lockdown_applied = Some(true);
        state.lockdown_manual = false;

        // Flip monitor_only false -> true while Quarantined + auto-lockdown applied.
        let mut mon_cfg = cfg.clone();
        mon_cfg.monitor_only = true;
        let (recovering, cmds1) = GuardEngine::step(
            state,
            EngineEvent::ConfigPersisted {
                ok: true,
                config: Some(mon_cfg),
                error: None,
            },
            110,
        );
        assert!(cmds1.iter().any(|c| matches!(
            c,
            EffectCommand::SyncLockdown {
                want: false,
                manual: false,
                ..
            }
        )));
        assert!(
            cmds1
                .iter()
                .any(|c| matches!(c, EffectCommand::ExecuteFlowANetworkRestore { .. }))
        );
        assert_eq!(recovering.protection, ProtectionState::Recovering);

        let ep = recovering.runtime_epoch;
        let (held, _) = GuardEngine::step(
            recovering,
            EngineEvent::FlowANetworkRestored {
                runtime_epoch: ep,
                receipt: verified_receipt("a1"),
                app_isolation_intact: true,
            },
            112,
        );
        assert_eq!(held.protection, ProtectionState::NetworkReadyAppHeld);

        // Even when probes fail, NetworkReadyAppHeld releases app quarantine because monitor_only == true!
        let rev = held.cfg_rev;
        let (releasing, cmds_rel) = GuardEngine::step(
            held,
            EngineEvent::RoundCompleted {
                cfg_rev: rev,
                runtime_epoch: ep,
                purpose: CheckPurpose::Manual,
                access: covered_access(),
                probes: fail_probes(),
            },
            115,
        );
        assert_eq!(releasing.protection, ProtectionState::Recovering);
        assert!(
            cmds_rel
                .iter()
                .any(|c| matches!(c, EffectCommand::ExecuteFlowAAppRelease { .. }))
        );

        // Changing guarded_agents resets lockdown_applied and immediately syncs when lockdown_manual is true.
        let mut manual_ld = EngineState::new(cfg.clone(), true, true, 120);
        manual_ld.lockdown_manual = true;
        manual_ld.lockdown_applied = Some(true);
        let mut next_agents_cfg = cfg;
        next_agents_cfg.guarded_agents = vec!["claude".into(), "chatgpt".into()];
        let (resynced, cmds_sync) = GuardEngine::step(
            manual_ld,
            EngineEvent::ConfigPersisted {
                ok: true,
                config: Some(next_agents_cfg),
                error: None,
            },
            125,
        );
        assert_eq!(resynced.lockdown_applied, None);
        assert!(cmds_sync.iter().any(|c| matches!(
            c,
            EffectCommand::SyncLockdown {
                want: true,
                manual: true,
                agents,
            } if agents == &vec!["claude".to_string(), "chatgpt".to_string()]
        )));
    }

    #[test]
    fn save_config_validates_proxy_host_and_forbids_first_run_regression() {
        let state = EngineState::new(armed_config(), true, true, 100);

        for bad_host in [
            "",
            "   ",
            "127.0.0.1 evil",
            "user@127.0.0.1",
            "127.0.0.1/path",
            r"127.0.0.1\path",
            "127.0.0.1?a=1",
            "127.0.0.1#frag",
            "127.0.0.1\n",
            "127.0.0.1:8080",
            "[::1",
        ] {
            let mut bad = armed_config();
            bad.proxy_host = bad_host.into();
            let (_, cmds) =
                GuardEngine::step(state.clone(), EngineEvent::SaveConfig { next: bad }, 105);
            assert!(
                matches!(
                    cmds.as_slice(),
                    [EffectCommand::RequestRejected {
                        code: ErrorCode::ValidationFailed,
                        ..
                    }]
                ),
                "expected proxy_host rejection for {bad_host:?}"
            );
        }

        // Raw IPv6 and bracketed IPv6 proxy_host are accepted.
        for ok_host in ["::1", "[::1]", "2001:db8::1"] {
            let mut good = armed_config();
            good.proxy_host = ok_host.into();
            let (_, cmds) =
                GuardEngine::step(state.clone(), EngineEvent::SaveConfig { next: good }, 105);
            assert!(
                cmds.iter()
                    .any(|c| matches!(c, EffectCommand::PersistConfig { .. })),
                "expected proxy_host accepted for {ok_host}"
            );
        }

        // Armed state MUST forbid resetting first_run = true.
        let mut regressed = armed_config();
        regressed.first_run = true;
        let (_, cmds_reg) =
            GuardEngine::step(state, EngineEvent::SaveConfig { next: regressed }, 106);
        assert!(matches!(
            cmds_reg.as_slice(),
            [EffectCommand::RequestRejected {
                code: ErrorCode::ValidationFailed,
                ..
            }]
        ));
    }

    #[test]
    fn round_id_monotonic_pause_freezes_streaks_clamps_clock_jump_and_target_recheck_recovers() {
        let mut cfg = armed_config();
        cfg.trip_threshold = 2;
        let state = EngineState::new(cfg, true, true, 1_000);

        // Monotonic round_id increments across StartRound invocations.
        let (s1, _) = GuardEngine::step(
            state,
            EngineEvent::StartRound {
                purpose: CheckPurpose::Monitor,
            },
            1_001,
        );
        assert_eq!(s1.active_round.map(|r| r.round_id), Some(1));
        let (s2, _) = GuardEngine::step(
            s1,
            EngineEvent::StartRound {
                purpose: CheckPurpose::Launch,
            },
            1_002,
        );
        assert_eq!(s2.active_round.map(|r| r.round_id), Some(2));

        // Establish fail_streak = 1 before pausing.
        let (s3, _) = GuardEngine::step(
            s2,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: fail_probes(),
            },
            1_005,
        );
        assert_eq!(s3.target_statuses[1].fail_streak, 1);

        // Pause for 60s at t=1010 -> paused_until = 1070.
        let (s4, _) = GuardEngine::step(
            s3,
            EngineEvent::Pause {
                duration_secs: Some(60),
            },
            1_010,
        );
        assert_eq!(s4.paused_until, Some(1_070));

        // Failing rounds while paused MUST hold fail_streak and access_streak steady (not increment!).
        let (s5, _) = GuardEngine::step(
            s4,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: covered_access(),
                probes: fail_probes(),
            },
            1_020,
        );
        assert_eq!(s5.target_statuses[1].fail_streak, 1);

        let (s6, _) = GuardEngine::step(
            s5,
            EngineEvent::RoundCompleted {
                cfg_rev: 0,
                runtime_epoch: 1,
                purpose: CheckPurpose::Monitor,
                access: uncovered_access(),
                probes: Vec::new(),
            },
            1_025,
        );
        assert_eq!(s6.access_streak, 0);

        // Backwards NTP clock jump to t=500 clamps paused_until to 500 + 60 = 560!
        let (mut s7, _) = GuardEngine::step(s6, EngineEvent::Tick, 500);
        assert_eq!(s7.paused_until, Some(560));

        // NetworkReadyAppHeld recovers via single-target TargetRechecked once all enabled targets are Pass!
        s7.paused_until = None;
        s7.pause_duration_secs = None;
        s7.protection = ProtectionState::NetworkReadyAppHeld;
        for st in &mut s7.target_statuses {
            if st.state != TargetState::Disabled {
                st.state = if st.id == "claude" {
                    TargetState::Unverified
                } else {
                    TargetState::Pass
                };
            }
        }
        let claude_pass = pass_probes()
            .into_iter()
            .find(|(id, _)| id == "claude")
            .unwrap()
            .1;
        let (s8, cmds_recheck) = GuardEngine::step(
            s7,
            EngineEvent::TargetRechecked {
                cfg_rev: 0,
                runtime_epoch: 1,
                target_id: "claude".into(),
                access: covered_access(),
                probe: claude_pass,
            },
            510,
        );
        assert_eq!(s8.protection, ProtectionState::Recovering);
        assert!(
            cmds_recheck
                .iter()
                .any(|c| matches!(c, EffectCommand::ExecuteFlowAAppRelease { .. }))
        );
    }
}
