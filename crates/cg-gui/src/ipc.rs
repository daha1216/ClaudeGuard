//! Non-blocking Named Pipe IPC client (`\\.\pipe\ClaudeGuardV4`) + normal-user Safe Launch spawner.
//!
//! All Named Pipe calls execute on background worker threads via `cx.background_executor()`,
//! never blocking the GPUI render/UI thread.

use crate::demo::{DemoScenario, build_demo_onboarding_probe, build_demo_snapshot, now_unix_secs};
use crate::protocol::{
    AgentKind, DEFAULT_PIPE_NAME, ErrorCode, GuardSnapshot, Lifecycle, MAX_FRAME_BYTES,
    OperationItemReceipt, OperationReceipt, OperationStatus, PipeRequest, PipeResponse,
    PolicyPreset, ProtectionState, TargetState, UpdateCheckPhase, encode_frame, read_frame,
    write_frame,
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
                let touch = |slot: &mut crate::protocol::ComponentUpdateStatus, key: &str, default_note: &str| {
                    if comp.is_none() || comp == Some(key) {
                        slot.checked_at = Some(now);
                        if slot.phase == UpdateCheckPhase::Idle {
                            slot.phase = UpdateCheckPhase::UpToDate;
                        }
                        if slot.note.is_empty() {
                            slot.note = default_note.into();
                        }
                    }
                };
                touch(
                    &mut snap.updates.claudeguard,
                    "claudeguard",
                    "当前 v4.0.0 已是最新正式版本（官方签名校验已启用）",
                );
                touch(
                    &mut snap.updates.antigravity_proxy,
                    "antigravity_proxy",
                    "已完成 antigravity-proxy 版本核验",
                );
                touch(
                    &mut snap.updates.claude_desktop,
                    "claude_desktop",
                    "已完成 Claude Desktop 官方最新版本核验",
                );
                touch(
                    &mut snap.updates.claude_code,
                    "claude_code",
                    "已完成 Claude Code CLI 官方最新版本核验",
                );
                touch(
                    &mut snap.updates.codex_desktop,
                    "codex_desktop",
                    "已完成 ChatGPT / Codex 桌面端版本核验",
                );
                touch(
                    &mut snap.updates.codex_cli,
                    "codex_cli",
                    "已完成 Codex CLI 官方最新版本核验",
                );
                touch(
                    &mut snap.updates.antigravity_ide,
                    "antigravity_ide",
                    "已完成 Antigravity IDE 官方最新版本核验",
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
                snap.antigravity_proxy.state =
                    crate::protocol::AntigravityProxyState::Healthy;
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

/// Synchronous Named Pipe roundtrip (runs on background thread pool).
#[cfg(windows)]
fn exchange_named_pipe(pipe_name: &str, req: &PipeRequest) -> Result<PipeResponse, TransportError> {
    use std::fs::File;
    use std::os::windows::io::FromRawHandle;
    use windows::Win32::Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, GENERIC_READ, GENERIC_WRITE,
    };
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE, OPEN_EXISTING,
    };
    use windows::Win32::System::Pipes::WaitNamedPipeW;
    use windows::core::HSTRING;

    validate_pipe_name(pipe_name)?;
    let wide = HSTRING::from(pipe_name);
    let _payload_check = encode_frame(req).map_err(|e| TransportError::Protocol(e.to_string()))?;

    let mut last_err = String::new();
    let handle = 'connect: {
        for attempt in 0..3 {
            let res = unsafe {
                CreateFileW(
                    &wide,
                    GENERIC_READ.0 | GENERIC_WRITE.0,
                    FILE_SHARE_NONE,
                    None,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
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
                        let _ = unsafe { WaitNamedPipeW(&wide, 1200) };
                        continue;
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

    // SAFETY: `handle` is an owned valid Win32 file handle from CreateFileW.
    let mut pipe_file = unsafe { File::from_raw_handle(handle.0) };
    write_frame(&mut pipe_file, req).map_err(|e| TransportError::Protocol(e.to_string()))?;
    let resp: PipeResponse =
        read_frame(&mut pipe_file).map_err(|e| TransportError::Protocol(e.to_string()))?;
    let _ = MAX_FRAME_BYTES;
    Ok(resp)
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

/// Launches an AI desktop application using the normal-user GUI token (`asInvoker`)
/// so launched apps preserve standard drag-and-drop and UIPI privileges.
#[cfg(windows)]
pub fn launch_agent_normal_user(
    agent_id: &str,
    install_paths: &[String],
) -> Result<String, String> {
    use std::path::Path;
    use std::process::Command;

    if let Some(exe) = install_paths.iter().find(|p| Path::new(p).is_file()) {
        let mut cmd = Command::new(exe);
        // Vector 4 of the 4-Vector Leak Shield: disable UDP QUIC on Electron/Chromium AI apps
        // so traffic never bypasses HTTP proxies via HTTP/3 UDP:443.
        if matches!(agent_id, "claude" | "chatgpt" | "antigravity") {
            cmd.arg("--disable-quic");
        }
        cmd.spawn()
            .map_err(|e| format!("启动 {agent_id} 失败：{e}"))?;
        return Ok(format!("已安全启动 {agent_id}（普通用户权限 · 已禁用 QUIC 泄露）"));
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
}
