//! Wire protocol re-exports from `cg-protocol` plus thin UI display/masking helpers.

pub use cg_protocol::{
    AccessEvidence, AccessLevel, AgentKind, AgentRuntimeStatus, AnchorKind, AntigravityProxyState,
    AntigravityProxyStatus, AppliedEnv, BUILTIN_TARGET_IDS, CONFIG_VERSION, ComponentUpdateStatus,
    Config, CutMode, DEFAULT_PIPE_NAME, DefenseCheckItem, DefenseSelfCheck, EnvCheck, EnvInfo,
    ErrorCode, FeishuStatus, FrameError, GuardSnapshot, KNOWN_GUI_AGENT_IDS, LeakConn, LeakReport,
    Lifecycle, LogEntry, LogLevel, MAX_FRAME_BYTES, NotifyPrefs, OnboardingOption,
    OnboardingProbeResult, OnboardingStrategy, OperationItemReceipt, OperationReceipt,
    OperationStatus, PipeRequest, PipeResponse, PolicyPreset, PolicyVerdict, ProbeResult,
    ProtectionState, SNAPSHOT_SCHEMA_VERSION, SelfCheckStatus, Target, TargetState, TargetStatus,
    ThemeMode, TimelineBucket, TimelineStatus, ToastNotificationEvent, TripInfo, UpdateCheckPhase,
    UpdateSummary, decode_frame, default_builtin_targets, encode_frame, normalize_ip,
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
            },
            PipeRequest::CheckUpdates {
                component: Some("antigravity_proxy".into()),
            },
            PipeRequest::ForceKillAgent {
                agent_id: Some("claude".into()),
                include_cli: true,
            },
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
