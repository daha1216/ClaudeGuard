//! Non-blocking Named Pipe IPC client (`\\.\pipe\ClaudeGuardV4`) + normal-user Safe Launch spawner.
//!
//! All Named Pipe calls execute on background worker threads via `cx.background_executor()`,
//! never blocking the GPUI render/UI thread.

use crate::demo::{DemoScenario, build_demo_onboarding_probe, build_demo_snapshot, now_unix_secs};
use crate::protocol::{
    AgentKind, DEFAULT_PIPE_NAME, ErrorCode, GuardSnapshot, Lifecycle, OperationItemReceipt,
    OperationReceipt, OperationStatus, PipeRequest, PipeResponse, PolicyPreset, ProtectionState,
    TargetState, UpdateCheckPhase,
};
use std::sync::{Arc, Mutex};

/// Connection mode for [`DaemonClient`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportEndpoint {
    Pipe(String),
    Demo(DemoScenario),
}

impl Default for TransportEndpoint {
    fn default() -> Self {
        Self::Pipe(DEFAULT_PIPE_NAME.to_string())
    }
}

/// High-level transport errors returned to the UI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportError {
    DaemonOffline(String),
    Protocol(String),
    Timeout(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DaemonOffline(msg) => write!(f, "守护服务未连接：{msg}"),
            Self::Protocol(msg) => write!(f, "协议错误：{msg}"),
            Self::Timeout(msg) => write!(f, "通信超时：{msg}"),
        }
    }
}

/// Thread-safe Named Pipe + interactive Demo client.
#[derive(Clone)]
pub struct DaemonClient {
    endpoint: TransportEndpoint,
    demo_state: Arc<Mutex<Option<GuardSnapshot>>>,
}

impl DaemonClient {
    pub fn new(endpoint: TransportEndpoint) -> Self {
        let initial_demo = match &endpoint {
            TransportEndpoint::Demo(scenario) => Some(build_demo_snapshot(*scenario)),
            TransportEndpoint::Pipe(_) => None,
        };
        Self {
            endpoint,
            demo_state: Arc::new(Mutex::new(initial_demo)),
        }
    }

    pub fn endpoint(&self) -> &TransportEndpoint {
        &self.endpoint
    }

    pub fn is_demo(&self) -> bool {
        matches!(self.endpoint, TransportEndpoint::Demo(_))
    }

    /// Sends a single synchronous IPC request (intended to run on `cx.background_executor()`).
    pub fn exchange(&self, req: PipeRequest) -> Result<PipeResponse, TransportError> {
        match &self.endpoint {
            TransportEndpoint::Demo(scenario) => Ok(self.exchange_demo(*scenario, req)),
            TransportEndpoint::Pipe(pipe_name) => exchange_named_pipe(pipe_name, &req),
        }
    }

    fn exchange_demo(&self, scenario: DemoScenario, req: PipeRequest) -> PipeResponse {
        let mut guard = self.demo_state.lock().expect("demo state lock");
        let snap = guard.get_or_insert_with(|| build_demo_snapshot(scenario));
        let now = now_unix_secs();

        match req {
            PipeRequest::GetSnapshot => PipeResponse::Snapshot {
                snapshot: Box::new(snap.clone()),
            },
            PipeRequest::RecheckNow { target_id } => {
                snap.checked_at = Some(now);
                if let Some(tid) = target_id.as_deref() {
                    if let Some(t) = snap.targets.iter_mut().find(|t| t.id == tid) {
                        t.checked_at = Some(now);
                    }
                } else {
                    for t in &mut snap.targets {
                        if t.state != TargetState::Disabled {
                            t.checked_at = Some(now);
                        }
                    }
                }
                if snap.lifecycle == Lifecycle::Armed && !snap.is_tripped() {
                    snap.protection = ProtectionState::Monitoring;
                }
                PipeResponse::Ack {
                    receipt: None,
                    snapshot: Some(Box::new(snap.clone())),
                }
            }
            PipeRequest::SetPolicyPreset { preset } => {
                snap.preset = preset;
                snap.config.preset = preset;
                snap.cfg_rev += 1;
                PipeResponse::Ack {
                    receipt: None,
                    snapshot: Some(Box::new(snap.clone())),
                }
            }
            PipeRequest::SaveConfig { config } => {
                snap.preset = config.preset;
                snap.theme_mode = config.theme_mode;
                snap.privacy_mask_ip = config.privacy_mask_ip;
                snap.config = config;
                snap.cfg_rev += 1;
                if snap.lifecycle == Lifecycle::Armed {
                    sync_demo_leak_shield_status(snap);
                }
                PipeResponse::Ack {
                    receipt: None,
                    snapshot: Some(Box::new(snap.clone())),
                }
            }
            PipeRequest::Pause { duration_secs } => {
                match duration_secs {
                    Some(secs) if secs > 0 => snap.paused_until = Some(now + secs),
                    _ => snap.paused_until = None,
                }
                snap.runtime_epoch += 1;
                PipeResponse::Ack {
                    receipt: None,
                    snapshot: Some(Box::new(snap.clone())),
                }
            }
            PipeRequest::SetManualLockdown { on } => {
                snap.lockdown_manual = on;
                snap.lockdown = on;
                snap.runtime_epoch += 1;
                PipeResponse::Ack {
                    receipt: None,
                    snapshot: Some(Box::new(snap.clone())),
                }
            }
            PipeRequest::RecoverSafeFlowA => {
                *snap = build_demo_snapshot(DemoScenario::Pass);
                PipeResponse::Ack {
                    receipt: None,
                    snapshot: Some(Box::new(snap.clone())),
                }
            }
            PipeRequest::DisarmAndRestoreFlowB { reason } => {
                let mut disarmed = build_demo_snapshot(DemoScenario::Disarmed);
                if let Some(r) = reason {
                    disarmed.disarmed_reason = r;
                }
                *snap = disarmed;
                PipeResponse::Ack {
                    receipt: None,
                    snapshot: Some(Box::new(snap.clone())),
                }
            }
            PipeRequest::Rearm => {
                *snap = build_demo_snapshot(DemoScenario::Pass);
                PipeResponse::Ack {
                    receipt: None,
                    snapshot: Some(Box::new(snap.clone())),
                }
            }
            PipeRequest::CheckLaunchGate { agent_id } => {
                let ag_blocked = agent_id.as_deref() == Some("antigravity")
                    && snap.config.require_antigravity_proxy
                    && snap.antigravity_proxy.installed
                    && !snap.antigravity_proxy.is_ready_for_launch();
                let allowed = !ag_blocked
                    && snap.lifecycle == Lifecycle::Armed
                    && !snap.is_paused_at(now)
                    && snap.protection == ProtectionState::Monitoring
                    && snap.all_enabled_pass();
                let reason = if ag_blocked {
                    if snap.antigravity_proxy.summary.is_empty() {
                        format!(
                            "反重力透明代理注入异常（{}），已阻止直连启动",
                            snap.antigravity_proxy.state.label_zh()
                        )
                    } else {
                        snap.antigravity_proxy.summary.clone()
                    }
                } else if allowed {
                    format!(
                        "{} 出口合规校验通过，允许安全启动",
                        agent_id.as_deref().unwrap_or("AI 应用")
                    )
                } else if snap.is_tripped() {
                    "当前处于熔断隔离状态，禁止启动 AI 应用".into()
                } else if snap.lifecycle == Lifecycle::Disarmed {
                    "当前已撤防，请先重新布防再通过安全启动门禁".into()
                } else if snap.is_paused_at(now) {
                    "守护已暂停，暂停期间拒绝安全启动".into()
                } else {
                    "存在未通过或未确认的目标，拒绝启动".into()
                };
                PipeResponse::LaunchGate {
                    allowed,
                    reason,
                    snapshot: Some(Box::new(snap.clone())),
                }
            }
            PipeRequest::SweepOrphans => {
                for agent in &mut snap.agents {
                    agent.orphan_count = 0;
                }
                PipeResponse::Ack {
                    receipt: None,
                    snapshot: Some(Box::new(snap.clone())),
                }
            }
            PipeRequest::ProbeOnboarding => PipeResponse::OnboardingProbe {
                probe: build_demo_onboarding_probe(true),
            },
            PipeRequest::CompleteOnboarding { mut config } => {
                config.first_run = false;
                let preset = config.preset;
                let mut armed = build_demo_snapshot(DemoScenario::Pass);
                armed.config = config;
                armed.preset = preset;
                if preset == PolicyPreset::StrictStaticIp {
                    for t in &mut armed.targets {
                        if t.state == TargetState::Pass {
                            t.matched_rule = Some("静态 IP 198.51.100.98".into());
                        }
                    }
                }
                *snap = armed;
                PipeResponse::Ack {
                    receipt: None,
                    snapshot: Some(Box::new(snap.clone())),
                }
            }
            PipeRequest::QueryLogs { limit, query, .. } => {
                let needle = query.unwrap_or_default().to_ascii_lowercase();
                let mut entries: Vec<_> = snap
                    .recent_logs
                    .iter()
                    .filter(|item| {
                        needle.is_empty()
                            || item.message.to_ascii_lowercase().contains(&needle)
                            || item.category.to_ascii_lowercase().contains(&needle)
                    })
                    .cloned()
                    .collect();
                let total = entries.len();
                if let Some(lim) = limit
                    && entries.len() > lim
                {
                    entries.truncate(lim);
                }
                PipeResponse::Logs { entries, total }
            }
            PipeRequest::CheckUpdates { component } => {
                let comp = component.as_deref().map(str::trim);
                let is_plugins = matches!(comp, Some("plugins" | "antigravity_plugins"));
                let touch = |slot: &mut crate::protocol::ComponentUpdateStatus,
                             key: &str,
                             in_plugins: bool,
                             default_note: &str| {
                    if comp.is_none() || comp == Some(key) || (is_plugins && in_plugins) {
                        slot.checked_at = Some(now);
                        if slot.phase == UpdateCheckPhase::Idle {
                            slot.phase = UpdateCheckPhase::UpToDate;
                        }
                        if slot.note.is_empty() {
                            slot.note = default_note.into();
                        }
                    }
                };
                let cg_note = format!(
                    "当前 v{} 已是最新正式版本（官方签名校验已启用）",
                    env!("CARGO_PKG_VERSION")
                );
                touch(
                    &mut snap.updates.claudeguard,
                    "claudeguard",
                    false,
                    &cg_note,
                );
                touch(
                    &mut snap.updates.antigravity_proxy,
                    "antigravity_proxy",
                    true,
                    "已完成 antigravity-proxy 版本核验",
                );
                touch(
                    &mut snap.updates.claude_desktop,
                    "claude_desktop",
                    false,
                    "已完成 Claude Desktop 官方最新版本核验",
                );
                touch(
                    &mut snap.updates.claude_code,
                    "claude_code",
                    false,
                    "已完成 Claude Code CLI 官方最新版本核验",
                );
                touch(
                    &mut snap.updates.codex_desktop,
                    "codex_desktop",
                    false,
                    "已完成 ChatGPT / Codex 桌面端版本核验",
                );
                touch(
                    &mut snap.updates.codex_cli,
                    "codex_cli",
                    false,
                    "已完成 Codex CLI 官方最新版本核验",
                );
                touch(
                    &mut snap.updates.antigravity_ide,
                    "antigravity_ide",
                    false,
                    "已完成 Antigravity IDE 官方最新版本核验",
                );
                touch(
                    &mut snap.updates.antigravity_cn,
                    "antigravity_cn",
                    true,
                    "已完成 Silas-02/antigravity-desktop-cn 上游版本核验",
                );
                touch(
                    &mut snap.updates.ag_usage_monitor,
                    "ag_usage_monitor",
                    true,
                    "已完成 yuhuan-dev/antigravity-usage-monitor 上游版本核验",
                );
                touch(
                    &mut snap.updates.ag_capsule,
                    "ag_capsule",
                    true,
                    "已完成 Lumidarin/agy-capsule 上游版本核验",
                );
                PipeResponse::Ack {
                    receipt: None,
                    snapshot: Some(Box::new(snap.clone())),
                }
            }
            PipeRequest::ForceKillAgent {
                agent_id,
                include_cli,
            } => {
                let mut cleared_agents = 0usize;
                let mut cleared_procs = 0usize;
                for agent in &mut snap.agents {
                    let matches = match agent_id.as_deref() {
                        None => include_cli || agent.kind == AgentKind::Gui,
                        Some("claude") => {
                            agent.id == "claude" || (include_cli && agent.id == "claude-code")
                        }
                        Some("chatgpt") => {
                            agent.id == "chatgpt" || (include_cli && agent.id == "codex")
                        }
                        Some(id) => agent.id == id,
                    };
                    if matches {
                        cleared_agents += 1;
                        cleared_procs += agent.running_count + agent.orphan_count;
                        agent.running_count = 0;
                        agent.orphan_count = 0;
                    }
                }
                let scope = match agent_id.as_deref() {
                    Some(id) => format!("强制全清 {id} 进程树与孤儿残留"),
                    None if include_cli => "强制全清全部受管桌面端与 CLI 进程".into(),
                    None => "强制全清全部受管桌面端进程".into(),
                };
                let receipt = OperationReceipt {
                    id: format!("rcpt-kill-{now}"),
                    status: OperationStatus::Verified,
                    items: vec![OperationItemReceipt {
                        name: scope.clone(),
                        status: OperationStatus::Verified,
                        detail: format!(
                            "已清理 {cleared_agents} 个受管对象共 {cleared_procs} 个运行/孤儿进程"
                        ),
                    }],
                    error: None,
                    verified_scope: scope,
                    remaining: Vec::new(),
                };
                snap.last_receipt = Some(receipt.clone());
                PipeResponse::Ack {
                    receipt: Some(receipt),
                    snapshot: Some(Box::new(snap.clone())),
                }
            }
            PipeRequest::SaveFeishuConfig {
                enabled,
                webhook,
                secret,
                clear_secret,
            } => {
                if let Some(url) = webhook.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                    if !url.starts_with("https://open.feishu.cn/open-apis/bot/v2/hook/")
                        && !url.starts_with("https://open.larksuite.com/open-apis/bot/v2/hook/")
                    {
                        return PipeResponse::Error {
                            code: ErrorCode::ValidationFailed,
                            message: "请填写飞书 / Lark 群自定义机器人的官方 HTTPS Webhook 地址"
                                .into(),
                            receipt: None,
                        };
                    }
                    let tail = url.get(url.len().saturating_sub(4)..).unwrap_or("");
                    snap.feishu.has_webhook = true;
                    snap.feishu.webhook_masked = format!("open.feishu.cn/.../{tail}");
                }
                if clear_secret {
                    snap.feishu.has_secret = false;
                } else if secret.as_deref().is_some_and(|s| !s.trim().is_empty()) {
                    snap.feishu.has_secret = true;
                }
                if enabled && !snap.feishu.has_webhook {
                    return PipeResponse::Error {
                        code: ErrorCode::ValidationFailed,
                        message: "启用飞书通知前请先填写有效的飞书 Webhook HTTPS 地址".into(),
                        receipt: None,
                    };
                }
                snap.feishu.enabled = enabled;
                snap.feishu.last_error.clear();
                PipeResponse::Ack {
                    receipt: None,
                    snapshot: Some(Box::new(snap.clone())),
                }
            }
            PipeRequest::TestFeishu { webhook, .. } => {
                let effective = webhook.as_deref().map(str::trim).filter(|s| !s.is_empty());
                if let Some(url) = effective
                    && !url.starts_with("https://open.feishu.cn/open-apis/bot/v2/hook/")
                    && !url.starts_with("https://open.larksuite.com/open-apis/bot/v2/hook/")
                {
                    return PipeResponse::Error {
                        code: ErrorCode::ValidationFailed,
                        message: "Webhook 地址格式无效，需为飞书 / Lark 官方 HTTPS Webhook".into(),
                        receipt: None,
                    };
                }
                if effective.is_none() && !snap.feishu.has_webhook {
                    return PipeResponse::Error {
                        code: ErrorCode::ValidationFailed,
                        message: "请先填写或保存飞书 Webhook 地址后再测试".into(),
                        receipt: None,
                    };
                }
                snap.feishu.last_sent_at = Some(now);
                snap.feishu.last_error.clear();
                PipeResponse::Ack {
                    receipt: None,
                    snapshot: Some(Box::new(snap.clone())),
                }
            }
            PipeRequest::SyncLeakShield => {
                sync_demo_leak_shield_status(snap);
                PipeResponse::Ack {
                    receipt: None,
                    snapshot: Some(Box::new(snap.clone())),
                }
            }
            PipeRequest::SwitchProxyNode { group, node, .. } => {
                snap.mihomo.active_group = group.clone();
                snap.mihomo.active_node = node.clone();
                snap.mihomo.active_delay_ms = snap
                    .mihomo
                    .candidates
                    .iter()
                    .find(|c| c.name == node)
                    .and_then(|c| c.delay_ms);
                snap.mihomo.note = format!("Mihomo · 组 [{group}] 已切换至节点：{node}");
                PipeResponse::Ack {
                    receipt: None,
                    snapshot: Some(Box::new(snap.clone())),
                }
            }
            PipeRequest::RepairAntigravityProxy => {
                snap.antigravity_proxy.state = crate::protocol::AntigravityProxyState::Healthy;
                snap.antigravity_proxy.dll_present = true;
                snap.antigravity_proxy.dll_valid = true;
                snap.antigravity_proxy.port_matches_guard = true;
                snap.antigravity_proxy.summary =
                    "已完成 antigravity-proxy 热修复注入并同步端口".into();
                PipeResponse::Ack {
                    receipt: None,
                    snapshot: Some(Box::new(snap.clone())),
                }
            }
            PipeRequest::ApplyEnvAlignment {
                align_tz,
                align_location,
            } => {
                snap.env_applied = Some(crate::protocol::AppliedEnv {
                    at: now,
                    city: "洛杉矶".into(),
                    tz_from: "China Standard Time".into(),
                    tz_to: if align_tz {
                        "Pacific Standard Time".into()
                    } else {
                        String::new()
                    },
                    lat_from: None,
                    lon_from: None,
                    lat_to: if align_location {
                        "34.0522".into()
                    } else {
                        String::new()
                    },
                    lon_to: if align_location {
                        "-118.2437".into()
                    } else {
                        String::new()
                    },
                });
                PipeResponse::Ack {
                    receipt: None,
                    snapshot: Some(Box::new(snap.clone())),
                }
            }
            PipeRequest::RollbackEnvAlignment => {
                snap.env_applied = None;
                PipeResponse::Ack {
                    receipt: None,
                    snapshot: Some(Box::new(snap.clone())),
                }
            }
            PipeRequest::ExportDiagnostics => {
                let receipt = OperationReceipt {
                    id: format!("diag-{now}"),
                    status: OperationStatus::Verified,
                    items: vec![OperationItemReceipt {
                        name: "diagnostics_zip".into(),
                        status: OperationStatus::Verified,
                        detail: "已生成脱敏诊断包 ClaudeGuard-Diagnostics-demo.zip".into(),
                    }],
                    error: None,
                    verified_scope: "ClaudeGuard-Diagnostics-demo.zip".into(),
                    remaining: Vec::new(),
                };
                snap.last_receipt = Some(receipt.clone());
                PipeResponse::Ack {
                    receipt: Some(receipt),
                    snapshot: Some(Box::new(snap.clone())),
                }
            }
        }
    }
}

fn sync_demo_leak_shield_status(snap: &mut GuardSnapshot) {
    let quic = snap.config.leak_shield_quic;
    let dns = snap.config.leak_shield_dns_doh;
    let ipv6 = snap.config.leak_shield_ipv6;
    let rules = usize::from(quic) * 4 + usize::from(dns) * 12 + usize::from(ipv6) * 4;
    snap.leak_shield.enabled = rules > 0;
    snap.leak_shield.quic_blocked = quic;
    snap.leak_shield.dns_doh_blocked = dns;
    snap.leak_shield.ipv6_blocked = ipv6;
    snap.leak_shield.active_rules = rules;
    snap.leak_shield.summary = if rules == 0 {
        "防泄露护盾已关闭".into()
    } else {
        format!("已同步防泄露护盾规则（生效 {rules} 条）")
    };
}

/// Validates a Windows Named Pipe endpoint path (`\\.\pipe\<name>`).
pub fn validate_pipe_name(pipe_name: &str) -> Result<(), TransportError> {
    let suffix = pipe_name
        .strip_prefix(r"\\.\pipe\")
        .ok_or_else(|| TransportError::Protocol(format!("非法管道端点：{pipe_name}")))?;
    if suffix.is_empty() || suffix.contains('\\') || suffix.contains('\0') || suffix.len() > 240 {
        return Err(TransportError::Protocol(format!(
            "非法管道端点名称：{pipe_name}"
        )));
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn request_timeout_ms(req: &PipeRequest) -> u64 {
    match req {
        PipeRequest::RepairAntigravityProxy => 65_000,
        PipeRequest::CheckUpdates { .. }
        | PipeRequest::RecheckNow { .. }
        | PipeRequest::ProbeOnboarding
        | PipeRequest::SyncLeakShield
        | PipeRequest::TestFeishu { .. }
        | PipeRequest::CheckLaunchGate { .. } => 30_000,
        _ => 8_000,
    }
}

#[cfg(windows)]
mod win_overlapped {
    use std::ffi::c_void;
    use std::io::{self, Read, Write};
    use std::time::Instant;

    const ERROR_HANDLE_EOF_RAW: u32 = 38;
    const ERROR_BROKEN_PIPE_RAW: u32 = 109;
    const ERROR_IO_PENDING_RAW: u32 = 997;
    const WAIT_OBJECT_0_RAW: u32 = 0;
    const WAIT_TIMEOUT_RAW: u32 = 258;

    #[repr(C)]
    struct RawOverlapped {
        internal: usize,
        internal_high: usize,
        offset: u32,
        offset_high: u32,
        h_event: *mut c_void,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateEventW(
            lp_event_attributes: *const c_void,
            b_manual_reset: i32,
            b_initial_state: i32,
            lp_name: *const u16,
        ) -> *mut c_void;
        fn ResetEvent(h_event: *mut c_void) -> i32;
        fn WaitForSingleObject(h_handle: *mut c_void, dw_milliseconds: u32) -> u32;
        fn ReadFile(
            h_file: *mut c_void,
            lp_buffer: *mut u8,
            n_number_of_bytes_to_read: u32,
            lp_number_of_bytes_read: *mut u32,
            lp_overlapped: *mut RawOverlapped,
        ) -> i32;
        fn WriteFile(
            h_file: *mut c_void,
            lp_buffer: *const u8,
            n_number_of_bytes_to_write: u32,
            lp_number_of_bytes_written: *mut u32,
            lp_overlapped: *mut RawOverlapped,
        ) -> i32;
        fn CancelIoEx(h_file: *mut c_void, lp_overlapped: *const RawOverlapped) -> i32;
        fn GetOverlappedResult(
            h_file: *mut c_void,
            lp_overlapped: *const RawOverlapped,
            lp_number_of_bytes_transferred: *mut u32,
            b_wait: i32,
        ) -> i32;
        fn CloseHandle(h_object: *mut c_void) -> i32;
        fn GetLastError() -> u32;
    }

    pub(super) struct OverlappedPipe {
        handle: *mut c_void,
        event: *mut c_void,
        deadline: Instant,
        pub(super) timed_out: bool,
    }

    impl OverlappedPipe {
        pub(super) fn new(handle: *mut c_void, deadline: Instant) -> Result<Self, io::Error> {
            // SAFETY: Manual-reset unnamed Win32 event; `handle` is owned and closed on error/Drop.
            let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
            if event.is_null() {
                let err = unsafe { GetLastError() };
                unsafe {
                    let _ = CloseHandle(handle);
                }
                return Err(io::Error::from_raw_os_error(err as i32));
            }
            Ok(Self {
                handle,
                event,
                deadline,
                timed_out: false,
            })
        }

        fn remaining_ms(&mut self) -> Result<u32, io::Error> {
            let rem = self.deadline.saturating_duration_since(Instant::now());
            if rem.is_zero() {
                self.timed_out = true;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "named pipe deadline expired",
                ));
            }
            Ok(rem.as_millis().clamp(1, u32::MAX as u128) as u32)
        }
    }

    impl Drop for OverlappedPipe {
        fn drop(&mut self) {
            // SAFETY: Both `event` and `handle` are exclusively owned by `OverlappedPipe`.
            unsafe {
                if !self.event.is_null() {
                    let _ = CloseHandle(self.event);
                }
                if !self.handle.is_null() {
                    let _ = CloseHandle(self.handle);
                }
            }
        }
    }

    impl Read for OverlappedPipe {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            let wait_ms = self.remaining_ms()?;
            let to_read = buf.len().min(u32::MAX as usize) as u32;
            // SAFETY: Event is reset before issuing overlapped ReadFile; on timeout/error,
            // CancelIoEx + blocking GetOverlappedResult drains the IRP before `ov` or `buf` drops.
            unsafe {
                let _ = ResetEvent(self.event);
                let mut ov = RawOverlapped {
                    internal: 0,
                    internal_high: 0,
                    offset: 0,
                    offset_high: 0,
                    h_event: self.event,
                };
                let mut transferred = 0u32;
                let ok = ReadFile(
                    self.handle,
                    buf.as_mut_ptr(),
                    to_read,
                    &mut transferred,
                    &mut ov,
                );
                if ok != 0 {
                    return Ok(transferred as usize);
                }
                let err = GetLastError();
                if err == ERROR_BROKEN_PIPE_RAW || err == ERROR_HANDLE_EOF_RAW {
                    return Ok(0);
                }
                if err != ERROR_IO_PENDING_RAW {
                    return Err(io::Error::from_raw_os_error(err as i32));
                }

                let w = WaitForSingleObject(self.event, wait_ms);
                if w == WAIT_OBJECT_0_RAW {
                    if GetOverlappedResult(self.handle, &ov, &mut transferred, 0) != 0 {
                        return Ok(transferred as usize);
                    }
                    let gerr = GetLastError();
                    if gerr == ERROR_BROKEN_PIPE_RAW || gerr == ERROR_HANDLE_EOF_RAW {
                        return Ok(0);
                    }
                    return Err(io::Error::from_raw_os_error(gerr as i32));
                }

                let wait_err = GetLastError();
                let _ = CancelIoEx(self.handle, &ov);
                let _ = GetOverlappedResult(self.handle, &ov, &mut transferred, 1);
                if w == WAIT_TIMEOUT_RAW {
                    self.timed_out = true;
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "named pipe read timed out",
                    ))
                } else {
                    Err(io::Error::from_raw_os_error(wait_err as i32))
                }
            }
        }
    }

    impl Write for OverlappedPipe {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            let wait_ms = self.remaining_ms()?;
            let to_write = buf.len().min(u32::MAX as usize) as u32;
            // SAFETY: Event is reset before issuing overlapped WriteFile; on timeout/error,
            // CancelIoEx + blocking GetOverlappedResult drains the IRP before `ov` or `buf` drops.
            unsafe {
                let _ = ResetEvent(self.event);
                let mut ov = RawOverlapped {
                    internal: 0,
                    internal_high: 0,
                    offset: 0,
                    offset_high: 0,
                    h_event: self.event,
                };
                let mut transferred = 0u32;
                let ok = WriteFile(
                    self.handle,
                    buf.as_ptr(),
                    to_write,
                    &mut transferred,
                    &mut ov,
                );
                if ok != 0 {
                    return Ok(transferred as usize);
                }
                let err = GetLastError();
                if err != ERROR_IO_PENDING_RAW {
                    return Err(io::Error::from_raw_os_error(err as i32));
                }

                let w = WaitForSingleObject(self.event, wait_ms);
                if w == WAIT_OBJECT_0_RAW {
                    if GetOverlappedResult(self.handle, &ov, &mut transferred, 0) != 0 {
                        return Ok(transferred as usize);
                    }
                    let gerr = GetLastError();
                    return Err(io::Error::from_raw_os_error(gerr as i32));
                }

                let wait_err = GetLastError();
                let _ = CancelIoEx(self.handle, &ov);
                let _ = GetOverlappedResult(self.handle, &ov, &mut transferred, 1);
                if w == WAIT_TIMEOUT_RAW {
                    self.timed_out = true;
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "named pipe write timed out",
                    ))
                } else {
                    Err(io::Error::from_raw_os_error(wait_err as i32))
                }
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}

/// Synchronous Named Pipe roundtrip (runs on background thread pool) with strict per-request deadline.
#[cfg(windows)]
fn exchange_named_pipe(pipe_name: &str, req: &PipeRequest) -> Result<PipeResponse, TransportError> {
    exchange_named_pipe_with_timeout(
        pipe_name,
        req,
        std::time::Duration::from_millis(request_timeout_ms(req)),
    )
}

#[cfg(windows)]
fn exchange_named_pipe_with_timeout(
    pipe_name: &str,
    req: &PipeRequest,
    timeout: std::time::Duration,
) -> Result<PipeResponse, TransportError> {
    use crate::protocol::{encode_frame, read_frame};
    use std::io::Write;
    use std::time::Instant;
    use windows::Win32::Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, GENERIC_READ, GENERIC_WRITE,
    };
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED, FILE_SHARE_NONE, OPEN_EXISTING,
    };
    use windows::Win32::System::Pipes::WaitNamedPipeW;
    use windows::core::HSTRING;

    validate_pipe_name(pipe_name)?;
    let frame = encode_frame(req).map_err(|e| TransportError::Protocol(e.to_string()))?;
    let wide = HSTRING::from(pipe_name);
    let timeout_ms = timeout.as_millis().max(1);
    let deadline = Instant::now() + timeout;

    let mut last_err = String::new();
    let handle = 'connect: {
        for attempt in 0..3 {
            if Instant::now() >= deadline {
                return Err(TransportError::Timeout(format!(
                    "连接守护管道超时（>{timeout_ms}ms）"
                )));
            }
            let res = unsafe {
                CreateFileW(
                    &wide,
                    GENERIC_READ.0 | GENERIC_WRITE.0,
                    FILE_SHARE_NONE,
                    None,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                    None,
                )
            };
            match res {
                Ok(h) => break 'connect h,
                Err(err) => {
                    let code = err.code().0 as u32;
                    let win32_err = code & 0xFFFF;
                    last_err = err.message();
                    if win32_err == ERROR_PIPE_BUSY.0 && attempt < 2 {
                        let rem_ms = deadline
                            .saturating_duration_since(Instant::now())
                            .as_millis()
                            .min(1200) as u32;
                        if rem_ms == 0 {
                            return Err(TransportError::Timeout(format!(
                                "守护管道繁忙超时（>{timeout_ms}ms）"
                            )));
                        }
                        let _ = unsafe { WaitNamedPipeW(&wide, rem_ms) };
                        continue;
                    }
                    if win32_err == ERROR_PIPE_BUSY.0 {
                        return Err(TransportError::Timeout(last_err));
                    }
                    if win32_err == ERROR_FILE_NOT_FOUND.0 {
                        return Err(TransportError::DaemonOffline(
                            "守护服务未运行或管道尚未就绪".into(),
                        ));
                    }
                    return Err(TransportError::DaemonOffline(last_err));
                }
            }
        }
        return Err(TransportError::Timeout(last_err));
    };

    let mut pipe = win_overlapped::OverlappedPipe::new(handle.0, deadline)
        .map_err(|e| TransportError::Protocol(e.to_string()))?;
    if let Err(err) = pipe.write_all(&frame) {
        if pipe.timed_out || err.kind() == std::io::ErrorKind::TimedOut {
            return Err(TransportError::Timeout(format!(
                "发送守护请求超时（>{timeout_ms}ms）"
            )));
        }
        return Err(TransportError::Protocol(err.to_string()));
    }
    match read_frame(&mut pipe) {
        Ok(resp) => Ok(resp),
        Err(err) => {
            if pipe.timed_out {
                Err(TransportError::Timeout(format!(
                    "等待守护服务响应超时（>{timeout_ms}ms）"
                )))
            } else {
                Err(TransportError::Protocol(err.to_string()))
            }
        }
    }
}

#[cfg(not(windows))]
fn exchange_named_pipe(
    pipe_name: &str,
    _req: &PipeRequest,
) -> Result<PipeResponse, TransportError> {
    validate_pipe_name(pipe_name)?;
    Err(TransportError::DaemonOffline(
        "非 Windows 平台仅支持 --demo 模式".into(),
    ))
}

#[cfg(any(windows, test))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct AgentLaunchPlan {
    disable_quic: bool,
    working_dir: Option<std::path::PathBuf>,
    toast_message: String,
}

#[cfg(any(windows, test))]
fn plan_agent_launch(agent_id: &str, user_profile: Option<&std::path::Path>) -> AgentLaunchPlan {
    if matches!(agent_id, "claude" | "chatgpt" | "antigravity") {
        AgentLaunchPlan {
            disable_quic: true,
            working_dir: None,
            toast_message: format!("已安全启动 {agent_id}（普通用户权限 · 已禁用 QUIC 泄露）"),
        }
    } else if matches!(agent_id, "claude-code" | "codex" | "codex-cli" | "gemini") {
        let working_dir = user_profile
            .filter(|p| !p.as_os_str().is_empty() && p.is_dir())
            .map(std::path::Path::to_path_buf);
        let toast_message = if let Some(dir) = &working_dir {
            format!(
                "已安全启动 CLI {agent_id}（普通用户权限 · 工作目录 {}）",
                dir.display()
            )
        } else {
            format!("已安全启动 CLI {agent_id}（普通用户权限）")
        };
        AgentLaunchPlan {
            disable_quic: false,
            working_dir,
            toast_message,
        }
    } else {
        AgentLaunchPlan {
            disable_quic: false,
            working_dir: None,
            toast_message: format!("已安全启动 {agent_id}（普通用户权限）"),
        }
    }
}

/// Launches an AI desktop or CLI application using the normal-user GUI token (`asInvoker`)
/// so launched apps preserve standard drag-and-drop and UIPI privileges.
#[cfg(windows)]
pub fn launch_agent_normal_user(
    agent_id: &str,
    install_paths: &[String],
) -> Result<String, String> {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    if let Some(exe) = install_paths.iter().find(|p| Path::new(p).is_file()) {
        let user_profile = std::env::var_os("USERPROFILE").map(PathBuf::from);
        let plan = plan_agent_launch(agent_id, user_profile.as_deref());
        let mut cmd = Command::new(exe);
        // Vector 4 of the 4-Vector Leak Shield: disable UDP QUIC on Electron/Chromium AI apps
        // so traffic never bypasses HTTP proxies via HTTP/3 UDP:443.
        if plan.disable_quic {
            cmd.arg("--disable-quic");
        }
        if let Some(cwd) = &plan.working_dir {
            cmd.current_dir(cwd);
        }
        cmd.spawn()
            .map_err(|e| format!("启动 {agent_id} 失败：{e}"))?;
        return Ok(plan.toast_message);
    }

    // Fallback: Shell AppsFolder AUMID / Start Menu heuristic
    let shell_target = match agent_id {
        "claude" => Some(r"shell:AppsFolder\Claude_pzs8sxrjxfjjc!Claude"),
        "chatgpt" => Some(r"shell:AppsFolder\OpenAI.Codex_2p2nqsd0c76g0!App"),
        _ => None,
    };
    if let Some(target) = shell_target {
        Command::new("explorer.exe")
            .arg(target)
            .spawn()
            .map_err(|e| format!("通过 explorer 启动 {agent_id} 失败：{e}"))?;
        return Ok(format!("已通过系统壳层安全启动 {agent_id}"));
    }

    Err(format!("未找到 {agent_id} 的安装路径，请确认客户端已安装"))
}

#[cfg(not(windows))]
pub fn launch_agent_normal_user(
    agent_id: &str,
    _install_paths: &[String],
) -> Result<String, String> {
    Ok(format!("[demo] 已模拟安全启动 {agent_id}"))
}

/// Safely opens an `https://` URL in the user's default browser without invoking a shell.
#[cfg(windows)]
pub fn open_external_url(url: &str) -> Result<(), String> {
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    use windows::core::PCWSTR;

    let trimmed = url.trim();
    if !trimmed.starts_with("https://")
        || trimmed.bytes().any(|b| b.is_ascii_control() || b == b' ')
    {
        return Err("仅允许打开安全的 HTTPS 外部链接".into());
    }
    let op: Vec<u16> = "open\0".encode_utf16().collect();
    let target: Vec<u16> = trimmed.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: Null-terminated UTF-16 buffers outlive ShellExecuteW.
    let res = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(op.as_ptr()),
            PCWSTR(target.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };
    if (res.0 as isize) <= 32 {
        return Err(format!("打开浏览器失败（错误码 {}）", res.0 as isize));
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn open_external_url(url: &str) -> Result<(), String> {
    if !url.trim().starts_with("https://") {
        return Err("仅允许打开安全的 HTTPS 外部链接".into());
    }
    Ok(())
}

/// Requests UAC elevation to start the `ClaudeGuardService` Windows Service (`sc.exe start ClaudeGuardService`).
#[cfg(windows)]
pub fn start_daemon_service_elevated() -> Result<(), String> {
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;
    use windows::core::{PCWSTR, w};

    // SAFETY: Static wide literals outlive ShellExecuteW.
    let res = unsafe {
        ShellExecuteW(
            None,
            w!("runas"),
            w!("sc.exe"),
            w!("start ClaudeGuardService"),
            PCWSTR::null(),
            SW_HIDE,
        )
    };
    let code = res.0 as isize;
    if code <= 32 {
        if code == 5 {
            return Err("已取消管理员授权（UAC），可复制命令在管理员终端手动启动".into());
        }
        return Err(format!("拉起 ClaudeGuardService 失败（错误码 {code}）"));
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn start_daemon_service_elevated() -> Result<(), String> {
    Err("仅 Windows 支持通过服务管理器启动 ClaudeGuardService".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_windows_named_pipe_endpoints() {
        assert!(validate_pipe_name(DEFAULT_PIPE_NAME).is_ok());
        assert!(validate_pipe_name(r"\\.\pipe\cg-test-1").is_ok());
        assert!(validate_pipe_name("invalid").is_err());
        assert!(validate_pipe_name(r"\\.\pipe\").is_err());
        assert!(validate_pipe_name(r"\\.\pipe\bad\name").is_err());
    }

    #[test]
    fn demo_transport_supports_flow_a_flow_b_and_launch_gate() {
        let client = DaemonClient::new(TransportEndpoint::Demo(DemoScenario::Trip));
        let gate = client
            .exchange(PipeRequest::CheckLaunchGate {
                agent_id: Some("claude".into()),
            })
            .expect("launch gate");
        assert!(matches!(
            gate,
            PipeResponse::LaunchGate { allowed: false, .. }
        ));

        // Flow A recovers Trip -> Armed / Monitoring -> Launch Gate allows
        let flow_a = client
            .exchange(PipeRequest::RecoverSafeFlowA)
            .expect("flow A");
        assert!(matches!(flow_a, PipeResponse::Ack { .. }));
        let gate_after = client
            .exchange(PipeRequest::CheckLaunchGate {
                agent_id: Some("claude".into()),
            })
            .expect("launch gate after flow A");
        assert!(matches!(
            gate_after,
            PipeResponse::LaunchGate { allowed: true, .. }
        ));

        // Flow B disarms and blocks Launch Gate
        let _ = client
            .exchange(PipeRequest::DisarmAndRestoreFlowB {
                reason: Some("test".into()),
            })
            .expect("flow B");
        let gate_disarmed = client
            .exchange(PipeRequest::CheckLaunchGate {
                agent_id: Some("claude".into()),
            })
            .expect("launch gate disarmed");
        assert!(matches!(
            gate_disarmed,
            PipeResponse::LaunchGate { allowed: false, .. }
        ));
    }

    #[test]
    fn demo_save_config_syncs_leak_shield_when_armed() {
        let client = DaemonClient::new(TransportEndpoint::Demo(DemoScenario::Pass));
        let mut cfg = build_demo_snapshot(DemoScenario::Pass).config;
        cfg.leak_shield_quic = true;
        cfg.leak_shield_dns_doh = true;
        cfg.leak_shield_ipv6 = true;
        let resp = client
            .exchange(PipeRequest::SaveConfig { config: cfg })
            .expect("save config");
        match resp {
            PipeResponse::Ack {
                snapshot: Some(snap),
                ..
            } => {
                assert!(snap.leak_shield.quic_blocked);
                assert!(snap.leak_shield.dns_doh_blocked);
                assert!(snap.leak_shield.ipv6_blocked);
                assert_eq!(snap.leak_shield.active_rules, 20);
            }
            other => panic!("unexpected SaveConfig response: {other:?}"),
        }
    }

    #[test]
    fn demo_launch_gate_blocks_antigravity_when_proxy_dll_missing() {
        let client = DaemonClient::new(TransportEndpoint::Demo(DemoScenario::Pass));
        {
            let mut guard = client.demo_state.lock().expect("demo state");
            let snap = guard.as_mut().expect("pass snapshot");
            snap.antigravity_proxy = build_demo_snapshot(DemoScenario::Trip).antigravity_proxy;
        }
        // Claude still passes launch gate while Antigravity is blocked until version.dll is repaired.
        let claude_gate = client
            .exchange(PipeRequest::CheckLaunchGate {
                agent_id: Some("claude".into()),
            })
            .expect("claude gate");
        assert!(matches!(
            claude_gate,
            PipeResponse::LaunchGate { allowed: true, .. }
        ));

        let ag_gate = client
            .exchange(PipeRequest::CheckLaunchGate {
                agent_id: Some("antigravity".into()),
            })
            .expect("antigravity gate");
        assert!(matches!(
            ag_gate,
            PipeResponse::LaunchGate { allowed: false, .. }
        ));
    }

    #[test]
    fn demo_transport_handles_check_updates_and_force_kill_agent() {
        let client = DaemonClient::new(TransportEndpoint::Demo(DemoScenario::Trip));
        {
            let mut guard = client.demo_state.lock().expect("demo state");
            let snap = guard.as_mut().expect("trip snapshot");
            snap.updates.claudeguard.checked_at = Some(100);
            snap.updates.antigravity_proxy.checked_at = Some(100);
        }

        // Targeted CheckUpdates updates only antigravity_proxy checked_at.
        let upd_ag = client
            .exchange(PipeRequest::CheckUpdates {
                component: Some("antigravity_proxy".into()),
            })
            .expect("check updates antigravity_proxy");
        match upd_ag {
            PipeResponse::Ack {
                snapshot: Some(snap),
                ..
            } => {
                assert_eq!(snap.updates.claudeguard.checked_at, Some(100));
                assert!(snap.updates.antigravity_proxy.checked_at.unwrap_or(0) > 100);
                assert_eq!(
                    snap.updates.antigravity_proxy.phase,
                    UpdateCheckPhase::UpdateAvailable
                );
            }
            other => panic!("unexpected CheckUpdates response: {other:?}"),
        }

        // Full CheckUpdates updates both components.
        let upd_all = client
            .exchange(PipeRequest::CheckUpdates { component: None })
            .expect("check all updates");
        match upd_all {
            PipeResponse::Ack {
                snapshot: Some(snap),
                ..
            } => {
                assert!(snap.updates.claudeguard.checked_at.unwrap_or(0) > 100);
                assert_eq!(snap.updates.claudeguard.phase, UpdateCheckPhase::UpToDate);
            }
            other => panic!("unexpected full CheckUpdates response: {other:?}"),
        }

        // Pass scenario ForceKillAgent: desktop-only single-agent kill, paired suite kill, GUI-only, and full kill.
        let pass_client = DaemonClient::new(TransportEndpoint::Demo(DemoScenario::Pass));
        let kill_claude_desktop = pass_client
            .exchange(PipeRequest::ForceKillAgent {
                agent_id: Some("claude".into()),
                include_cli: false,
            })
            .expect("force kill claude desktop");
        match kill_claude_desktop {
            PipeResponse::Ack {
                receipt: Some(rcpt),
                snapshot: Some(snap),
            } => {
                assert_eq!(rcpt.status, OperationStatus::Verified);
                let claude = snap.agents.iter().find(|a| a.id == "claude").unwrap();
                assert_eq!(claude.running_count, 0);
                assert_eq!(claude.orphan_count, 0);
                let claude_code = snap.agents.iter().find(|a| a.id == "claude-code").unwrap();
                assert!(claude_code.running_count > 0);
            }
            other => panic!("unexpected ForceKillAgent(claude desktop) response: {other:?}"),
        }

        let kill_claude_suite = pass_client
            .exchange(PipeRequest::ForceKillAgent {
                agent_id: Some("claude".into()),
                include_cli: true,
            })
            .expect("force kill claude suite");
        match kill_claude_suite {
            PipeResponse::Ack {
                receipt: Some(rcpt),
                snapshot: Some(snap),
            } => {
                assert_eq!(rcpt.status, OperationStatus::Verified);
                let claude_code = snap.agents.iter().find(|a| a.id == "claude-code").unwrap();
                assert_eq!(claude_code.running_count, 0);
                assert_eq!(claude_code.orphan_count, 0);
            }
            other => panic!("unexpected ForceKillAgent(claude suite) response: {other:?}"),
        }

        let kill_gui_only = pass_client
            .exchange(PipeRequest::ForceKillAgent {
                agent_id: None,
                include_cli: false,
            })
            .expect("force kill gui only");
        match kill_gui_only {
            PipeResponse::Ack {
                receipt: Some(rcpt),
                snapshot: Some(snap),
            } => {
                assert_eq!(rcpt.status, OperationStatus::Verified);
                for a in &snap.agents {
                    if a.kind == AgentKind::Gui {
                        assert_eq!(a.running_count, 0);
                        assert_eq!(a.orphan_count, 0);
                    }
                }
                let codex = snap.agents.iter().find(|a| a.id == "codex").unwrap();
                assert!(codex.running_count > 0);
            }
            other => panic!("unexpected ForceKillAgent(gui only) response: {other:?}"),
        }

        let kill_all = pass_client
            .exchange(PipeRequest::ForceKillAgent {
                agent_id: None,
                include_cli: true,
            })
            .expect("force kill all");
        match kill_all {
            PipeResponse::Ack {
                receipt: Some(rcpt),
                snapshot: Some(snap),
            } => {
                assert_eq!(rcpt.status, OperationStatus::Verified);
                for a in &snap.agents {
                    assert_eq!(a.running_count, 0);
                    assert_eq!(a.orphan_count, 0);
                }
            }
            other => panic!("unexpected ForceKillAgent(all) response: {other:?}"),
        }
    }

    #[test]
    fn agent_launch_plan_distinguishes_gui_quic_and_cli_working_dir() {
        let existing_dir = std::env::temp_dir();
        assert!(existing_dir.is_dir());

        for gui_id in ["claude", "chatgpt", "antigravity"] {
            let plan = plan_agent_launch(gui_id, Some(&existing_dir));
            assert!(plan.disable_quic, "{gui_id} must pass --disable-quic");
            assert!(plan.working_dir.is_none());
            assert!(plan.toast_message.contains("已禁用 QUIC 泄露"));
        }

        for cli_id in ["claude-code", "codex", "codex-cli", "gemini"] {
            let plan = plan_agent_launch(cli_id, Some(&existing_dir));
            assert!(!plan.disable_quic, "{cli_id} must NOT pass --disable-quic");
            assert_eq!(plan.working_dir.as_deref(), Some(existing_dir.as_path()));
            assert!(
                !plan.toast_message.contains("QUIC"),
                "{cli_id} toast must not falsely claim QUIC disabled: {}",
                plan.toast_message
            );
            assert!(plan.toast_message.contains("CLI"));
            assert!(plan.toast_message.contains("工作目录"));
        }

        // Non-existent USERPROFILE falls back cleanly without failing.
        let missing_dir = existing_dir.join("cg_nonexistent_profile_dir_9f8e7d");
        let fallback = plan_agent_launch("claude-code", Some(&missing_dir));
        assert!(!fallback.disable_quic);
        assert!(fallback.working_dir.is_none());
        assert!(!fallback.toast_message.contains("QUIC"));
        assert!(!fallback.toast_message.contains("工作目录"));
    }

    #[test]
    fn request_timeout_tiers_match_rpc_workload() {
        assert_eq!(request_timeout_ms(&PipeRequest::GetSnapshot), 8_000);
        assert_eq!(
            request_timeout_ms(&PipeRequest::CheckUpdates { component: None }),
            30_000
        );
        assert_eq!(
            request_timeout_ms(&PipeRequest::RecheckNow { target_id: None }),
            30_000
        );
        assert_eq!(request_timeout_ms(&PipeRequest::ProbeOnboarding), 30_000);
        assert_eq!(request_timeout_ms(&PipeRequest::SyncLeakShield), 30_000);
        assert_eq!(
            request_timeout_ms(&PipeRequest::RepairAntigravityProxy),
            65_000
        );
    }

    #[cfg(windows)]
    #[test]
    fn overlapped_named_pipe_enforces_deadline_and_classifies_offline() {
        use std::ffi::c_void;
        use std::sync::mpsc;
        use std::time::{Duration, Instant};

        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn CreateNamedPipeW(
                lp_name: *const u16,
                dw_open_mode: u32,
                dw_pipe_mode: u32,
                n_max_instances: u32,
                n_out_buffer_size: u32,
                n_in_buffer_size: u32,
                n_default_time_out: u32,
                lp_security_attributes: *const c_void,
            ) -> *mut c_void;
            fn ConnectNamedPipe(h_named_pipe: *mut c_void, lp_overlapped: *mut c_void) -> i32;
            fn DisconnectNamedPipe(h_named_pipe: *mut c_void) -> i32;
            fn CloseHandle(h_object: *mut c_void) -> i32;
        }

        // 1. Missing pipe immediately returns DaemonOffline (not Timeout/Protocol).
        let missing_pipe = format!(r"\\.\pipe\cg-gui-missing-{}", std::process::id());
        let offline = exchange_named_pipe_with_timeout(
            &missing_pipe,
            &PipeRequest::GetSnapshot,
            Duration::from_millis(200),
        );
        assert!(matches!(offline, Err(TransportError::DaemonOffline(_))));

        // 2. Stalled pipe server that accepts client and writes nothing triggers Timeout via CancelIoEx.
        let pipe_name = format!(r"\\.\pipe\cg-gui-stall-{}", std::process::id());
        let wide: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (done_tx, done_rx) = mpsc::sync_channel(1);

        let server = std::thread::spawn(move || unsafe {
            const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
            let h = CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                0,
                1,
                4096,
                4096,
                0,
                std::ptr::null(),
            );
            assert!(!h.is_null() && (h as isize) != -1);
            ready_tx.send(()).unwrap();
            let _ = ConnectNamedPipe(h, std::ptr::null_mut());
            // Hold connection open without sending response until client cancels via deadline.
            let _ = done_rx.recv_timeout(Duration::from_secs(3));
            let _ = DisconnectNamedPipe(h);
            let _ = CloseHandle(h);
        });

        ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let started = Instant::now();
        let stalled = exchange_named_pipe_with_timeout(
            &pipe_name,
            &PipeRequest::GetSnapshot,
            Duration::from_millis(120),
        );
        let elapsed = started.elapsed();
        let _ = done_tx.send(());
        server.join().unwrap();

        assert!(
            matches!(stalled, Err(TransportError::Timeout(_))),
            "expected Timeout on stalled pipe, got {stalled:?}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "CancelIoEx must abort stalled read promptly, took {elapsed:?}"
        );
    }
}
