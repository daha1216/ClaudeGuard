//! Wire protocol re-exports from `cg-protocol` plus thin UI display/masking helpers.

pub use cg_protocol::{
    AccessEvidence, AccessLevel, AccountVault, AgentKind, AgentRuntimeStatus, AnchorKind,
    AntigravityProxyState, AntigravityProxyStatus, AppliedEnv, AsnClassification,
    BUILTIN_TARGET_IDS, BurstGuardMode, BurstGuardStatus, CONFIG_VERSION, CleanRoomBackupMeta,
    CleanRoomFinding, CleanRoomReport, CleanRoomRiskLevel, CleanRoomScope, CleanRoomVector,
    ComponentUpdateStatus, Config, CutMode, DEFAULT_PIPE_NAME, DefenseCheckItem, DefenseSelfCheck,
    DnsCoherenceReport, ElectronHygieneReport, EnvCheck, EnvInfo, ErrorCode, FeishuStatus,
    FirewallBackendPref, FrameError, GeoVelocityAlert, GuardSnapshot, HookDecision, HookFailMode,
    HookIntegrationStatus, HotkeyStatus, IpPurityReport, KNOWN_CLI_AGENT_IDS, KNOWN_GUI_AGENT_IDS,
    LeakConn, LeakReport, LeakShieldStatus, Lifecycle, LogEntry, LogLevel, MAX_FRAME_BYTES,
    MihomoNodeInfo, MihomoStatus, MsixIsolationMode, NotifyPrefs, OnboardingOption,
    OnboardingProbeResult, OnboardingStrategy, OperationItemReceipt, OperationReceipt,
    OperationStatus, PipeRequest, PipeResponse, PolicyPreset, PolicyVerdict, ProbeResult,
    ProtectionState, RiskAssessment, RiskDimensionItem, SNAPSHOT_SCHEMA_VERSION, SafetyGrade,
    SanitizedHealthCard, SelfCheckStatus, StunLeakReport, Target, TargetState, TargetStatus,
    ThemeMode, TimelineBucket, TimelineStatus, ToastNotificationEvent, TripInfo, UpdateCheckPhase,
    UpdateSummary, VaultAppTarget, VaultRuntimeState, VaultRuntimeStatus, WfpBlockedEvent,
    WfpStatus, WslBridgeStatus, clean_guarded_agents, decode_frame, default_builtin_targets,
    encode_frame, ensure_builtin_targets, is_known_region, is_valid_vault_id, normalize_ip,
    normalize_ip_or_cidr, normalize_region, read_frame, region_name, try_decode_frame, write_frame,
};
use std::net::{IpAddr, Ipv4Addr};

/// Segmented-capsule preset choices in display order.
pub const POLICY_PRESETS: [PolicyPreset; 3] = [
    PolicyPreset::LooseAntiDirect,
    PolicyPreset::StandardRegion,
    PolicyPreset::StrictStaticIp,
];

/// Supported network cut-mode choices in display order (excludes unimplemented NIC driver).
pub const CUT_MODES: [CutMode; 2] = [CutMode::Off, CutMode::Firewall];

/// Supported v5 firewall isolation engine preferences.
pub const FIREWALL_BACKENDS: [FirewallBackendPref; 3] = [
    FirewallBackendPref::AutoWfpFirst,
    FirewallBackendPref::WfpOnly,
    FirewallBackendPref::ComLegacy,
];

/// Supported v5 CLI Hook fallback modes.
pub const HOOK_FAIL_MODES: [HookFailMode; 2] =
    [HookFailMode::FailClosed, HookFailMode::FailOpenWithWarn];

/// Supported v5 BurstGuard rate-control modes.
pub const BURST_GUARD_MODES: [BurstGuardMode; 3] = [
    BurstGuardMode::Off,
    BurstGuardMode::WarnOnly,
    BurstGuardMode::ThrottleGate,
];

/// Supported MSIX isolation strategies for Sovereign Account Vaults.
pub const MSIX_ISOLATION_MODES: [MsixIsolationMode; 2] = [
    MsixIsolationMode::AutoVerifyLock,
    MsixIsolationMode::ExclusiveSwapLock,
];

/// Anchor parser choices when cycling target anchor kinds.
pub const ANCHOR_KINDS: [AnchorKind; 5] = [
    AnchorKind::Auto,
    AnchorKind::Trace,
    AnchorKind::JsonIp,
    AnchorKind::GeminiRegion,
    AnchorKind::Reachability,
];

/// Extension trait adding concise Chinese display labels onto [`cg_protocol`] enums
/// that do not expose inherent `.label()` methods.
pub trait UiLabelExt {
    fn label(self) -> &'static str;
}

impl UiLabelExt for TargetState {
    fn label(self) -> &'static str {
        match self {
            Self::Pending => "待检测",
            Self::Checking => "检测中",
            Self::Pass => "合规放行",
            Self::Fail => "违规拦截",
            Self::Unverified => "未确认",
            Self::Disabled => "已禁用",
        }
    }
}

impl UiLabelExt for AccessLevel {
    fn label(self) -> &'static str {
        match self {
            Self::SystemProxy => "系统代理",
            Self::Tun => "TUN 全局",
            Self::Uncovered => "未覆盖（直连风险）",
            Self::Unknown => "接入未知",
        }
    }
}

impl UiLabelExt for OperationStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Verified => "已核验",
            Self::Partial => "部分完成",
            Self::Failed => "失败",
            Self::Unknown => "未知",
            Self::Unsupported => "不支持",
            Self::NotApplicable => "不适用",
        }
    }
}

impl UiLabelExt for TimelineStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Empty => "无记录",
            Self::Pass => "合规",
            Self::Warn => "待确认/暂停",
            Self::Fail => "告警/熔断",
        }
    }
}

impl UiLabelExt for SelfCheckStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Healthy => "正常",
            Self::Degraded => "异常/未清理",
            Self::Disabled => "已关闭",
            Self::Unsupported => "不支持",
            Self::Unknown => "待检",
        }
    }
}

impl UiLabelExt for LogLevel {
    fn label(self) -> &'static str {
        match self {
            Self::Info => "信息",
            Self::Warn => "告警",
            Self::Error => "熔断",
            Self::Audit => "审计",
        }
    }
}

impl UiLabelExt for AntigravityProxyState {
    fn label(self) -> &'static str {
        self.label_zh()
    }
}

impl UiLabelExt for UpdateCheckPhase {
    fn label(self) -> &'static str {
        self.label_zh()
    }
}

impl UiLabelExt for FirewallBackendPref {
    fn label(self) -> &'static str {
        self.label_zh()
    }
}

impl UiLabelExt for AsnClassification {
    fn label(self) -> &'static str {
        self.label_zh()
    }
}

impl UiLabelExt for SafetyGrade {
    fn label(self) -> &'static str {
        match self {
            Self::S => "S 级 · 极低风险",
            Self::A => "A 级 · 纯净合规",
            Self::B => "B 级 · 轻度提示",
            Self::C => "C 级 · 存在风险",
            Self::F => "F 级 · 极高封号风险",
        }
    }
}

impl UiLabelExt for VaultRuntimeState {
    fn label(self) -> &'static str {
        match self {
            Self::Ready => "待命就绪",
            Self::ActiveRunning => "守护运行中",
            Self::CoolingDown => "换 IP 冷却中",
            Self::EgressMismatch => "出口违约锁定",
            Self::Disabled => "已停用",
        }
    }
}

impl UiLabelExt for CleanRoomRiskLevel {
    fn label(self) -> &'static str {
        match self {
            Self::Clean => "洁净无污染",
            Self::Low => "低风险残留",
            Self::Elevated => "中度关联风险",
            Self::CriticalChainBanRisk => "极高危连坐风险",
        }
    }
}

impl UiLabelExt for CleanRoomVector {
    fn label(self) -> &'static str {
        match self {
            Self::ClaudeCodeState => "V1 · CLI 身份与遥测队列",
            Self::DesktopChromiumAndCrashpad => "V2 · 桌面/MSIX 与崩溃信封",
            Self::WindowsCredentialManager => "V3 · 系统凭据钥匙串",
            Self::OrphanMemoryProcess => "V4 · 内存驻留孤儿进程",
        }
    }
}

impl UiLabelExt for HookFailMode {
    fn label(self) -> &'static str {
        match self {
            Self::FailClosed => "服务离线时安全截停 (Fail-Closed)",
            Self::FailOpenWithWarn => "离线告警放行 (Fail-Open)",
        }
    }
}

impl UiLabelExt for BurstGuardMode {
    fn label(self) -> &'static str {
        match self {
            Self::Off => "关闭",
            Self::WarnOnly => "仅告警提醒",
            Self::ThrottleGate => "门禁硬限速",
        }
    }
}

impl UiLabelExt for MsixIsolationMode {
    fn label(self) -> &'static str {
        match self {
            Self::AutoVerifyLock => "自动核验多开锁",
            Self::ExclusiveSwapLock => "严格单实例独占锁",
        }
    }
}

impl UiLabelExt for VaultAppTarget {
    fn label(self) -> &'static str {
        match self {
            Self::ClaudeDesktop => "Claude",
            Self::ChatgptDesktop => "ChatGPT / Codex",
            Self::AntigravityIde => "Antigravity",
            Self::ClaudeCodeCli => "Claude Code",
            Self::CodexCli => "Codex CLI",
        }
    }
}

/// Fail-closed check matching CLI/daemon launch compliance (`Armed`, `Monitoring`, `all_enabled_pass`, `!tripped`).
pub fn snapshot_is_check_passed(snap: &GuardSnapshot) -> bool {
    snap.lifecycle == Lifecycle::Armed
        && snap.protection == ProtectionState::Monitoring
        && !snap.is_tripped()
        && snap.all_enabled_pass()
}

/// Masks a single IP or IPv4 CIDR string for UI screenshot privacy (`198.51.100.98` -> `198.51.*.*`).
pub fn mask_ip_str(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Some((ip_part, prefix)) = trimmed.split_once('/')
        && let Ok(IpAddr::V4(v4)) = ip_part.trim().parse::<IpAddr>()
    {
        let [a, b, _, _] = v4.octets();
        return format!("{a}.{b}.*.* /{prefix}").replace(" /", "/");
    }
    match trimmed.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            let [a, b, _, _] = v4.octets();
            format!("{a}.{b}.*.*")
        }
        Ok(IpAddr::V6(v6)) => {
            let segs = v6.segments();
            format!("{:x}:{:x}::*", segs[0], segs[1])
        }
        Err(_) => trimmed.to_string(),
    }
}

/// Masks any IPv4 tokens embedded inside diagnostic/log text when privacy mode is enabled.
pub fn mask_ips_in_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                i += 1;
            }
            let candidate = &text[start..i];
            if candidate.parse::<Ipv4Addr>().is_ok() {
                out.push_str(&mask_ip_str(candidate));
            } else {
                out.push_str(candidate);
            }
        } else {
            let ch = text[i..].chars().next().expect("valid utf8");
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privacy_mask_redacts_ipv4_ipv6_and_embedded_text() {
        assert_eq!(mask_ip_str("198.51.100.98"), "198.51.*.*");
        assert_eq!(mask_ip_str("198.51.100.0/24"), "198.51.*.*/24");
        assert_eq!(mask_ip_str("2001:db8:85a3::8a2e:370:7334"), "2001:db8::*");
        assert_eq!(
            mask_ips_in_text("实测 HK 203.0.113.45 违反规则 198.51.100.98"),
            "实测 HK 203.0.*.* 违反规则 198.51.*.*"
        );
    }

    #[test]
    fn frame_codec_roundtrips_canonical_protocol_variants() {
        let reqs = [
            PipeRequest::GetSnapshot,
            PipeRequest::RecheckNow {
                target_id: Some("claude".into()),
            },
            PipeRequest::SetPolicyPreset {
                preset: PolicyPreset::StrictStaticIp,
            },
            PipeRequest::SaveConfig {
                config: Config::default(),
            },
            PipeRequest::Pause {
                duration_secs: Some(1800),
            },
            PipeRequest::SetManualLockdown { on: true },
            PipeRequest::RecoverSafeFlowA,
            PipeRequest::DisarmAndRestoreFlowB {
                reason: Some("user stopped protection".into()),
            },
            PipeRequest::Rearm,
            PipeRequest::CheckLaunchGate {
                agent_id: Some("claude".into()),
            },
            PipeRequest::SweepOrphans,
            PipeRequest::ProbeOnboarding,
            PipeRequest::CompleteOnboarding {
                config: Config::default(),
            },
            PipeRequest::QueryLogs {
                since_ts: Some(100),
                until_ts: Some(200),
                limit: Some(50),
                query: Some("trip".into()),
                level: Some(LogLevel::Error),
            },
            PipeRequest::CheckUpdates {
                component: Some("antigravity_proxy".into()),
            },
            PipeRequest::ForceKillAgent {
                agent_id: Some("claude".into()),
                include_cli: true,
            },
            PipeRequest::FastHookGate {
                agent_id: "claude-code".into(),
                vault_id: Some("work-claude-max".into()),
                hook_event: Some("UserPromptSubmit".into()),
            },
            PipeRequest::ScanCleanRoom {
                scope: CleanRoomScope::default(),
            },
            PipeRequest::ListCleanRoomBackups,
            PipeRequest::TriggerPanicLockdown,
            PipeRequest::ClearWfpBlockedEvents,
            PipeRequest::RunDeepRiskAudit,
            PipeRequest::ClearGeoVelocityCooldown,
            PipeRequest::BuildHealthCard { export_png: true },
        ];

        for req in reqs {
            let encoded = encode_frame(&req).expect("encode");
            let len = u32::from_le_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]) as usize;
            assert_eq!(len + 4, encoded.len());
            let decoded: PipeRequest = decode_frame(&encoded).expect("decode");
            assert_eq!(decoded, req);
        }

        let mut cursor = std::io::Cursor::new(Vec::new());
        let resp = PipeResponse::LaunchGate {
            allowed: false,
            reason: format!("policy {:?}", PolicyVerdict::Fail),
            snapshot: Some(Box::new(GuardSnapshot::default())),
        };
        write_frame(&mut cursor, &resp).expect("write_frame");
        cursor.set_position(0);
        let decoded: PipeResponse = read_frame(&mut cursor).expect("read_frame");
        assert_eq!(decoded, resp);

        let onb_resp = PipeResponse::OnboardingProbe {
            probe: OnboardingProbeResult::default(),
            detected_local_ports: vec![7897, 7890],
        };
        let encoded_onb = encode_frame(&onb_resp).expect("encode onboarding probe");
        let decoded_onb: PipeResponse =
            decode_frame(&encoded_onb).expect("decode onboarding probe");
        assert_eq!(decoded_onb, onb_resp);
    }

    #[test]
    fn frame_codec_rejects_zero_truncated_and_oversized_frames() {
        assert_eq!(
            decode_frame::<PipeRequest>(&0u32.to_le_bytes()),
            Err(FrameError::ZeroLength)
        );
        assert_eq!(
            decode_frame::<PipeRequest>(&[1, 0]),
            Err(FrameError::TruncatedHeader { available: 2 })
        );
        let oversized_hdr = ((MAX_FRAME_BYTES as u32) + 1).to_le_bytes();
        assert!(matches!(
            decode_frame::<PipeRequest>(&oversized_hdr),
            Err(FrameError::TooLarge { .. })
        ));
    }

    #[test]
    fn antigravity_proxy_state_ui_label_delegates_to_label_zh() {
        for state in [
            AntigravityProxyState::NotInstalled,
            AntigravityProxyState::Healthy,
            AntigravityProxyState::MissingDll,
            AntigravityProxyState::MissingOrInvalidConfig,
            AntigravityProxyState::PortMismatch,
            AntigravityProxyState::RuntimeUnhooked,
        ] {
            assert_eq!(state.label(), state.label_zh());
        }
    }

    #[test]
    fn update_check_phase_ui_label_delegates_to_label_zh() {
        for phase in [
            UpdateCheckPhase::Idle,
            UpdateCheckPhase::Checking,
            UpdateCheckPhase::UpToDate,
            UpdateCheckPhase::UpdateAvailable,
            UpdateCheckPhase::NotInstalled,
            UpdateCheckPhase::Failed,
        ] {
            assert_eq!(phase.label(), phase.label_zh());
        }
    }
}
