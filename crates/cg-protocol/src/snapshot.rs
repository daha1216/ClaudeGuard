//! Immutable atomic snapshot served in O(1) by the daemon and rendered by the UI.

use crate::config::Config;
use crate::model::{
    AccessEvidence, AgentRuntimeStatus, AntigravityProxyStatus, AppliedEnv, DefenseSelfCheck,
    EnvCheck, FeishuStatus, LeakReport, LeakShieldStatus, LogEntry, MihomoStatus, PolicyPreset,
    TargetState, TargetStatus, ThemeMode, TimelineBucket, ToastNotificationEvent, TripInfo,
    UpdateSummary,
};
use crate::state::{Lifecycle, OperationReceipt, ProtectionState, is_legal_state_pair};
use crate::v5::{
    BurstGuardStatus, CleanRoomReport, HookIntegrationStatus, HotkeyStatus, RiskAssessment,
    VaultRuntimeStatus, WfpStatus, WslBridgeStatus,
};
use serde::{Deserialize, Serialize};

/// Schema version for [`GuardSnapshot`] payloads over Named Pipe IPC.
pub const SNAPSHOT_SCHEMA_VERSION: u32 = 5;

/// Immutable point-in-time snapshot of the entire guard engine and cached runtime probes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardSnapshot {
    pub schema_version: u32,
    pub version: String,
    pub platform: String,
    pub network_isolation_supported: bool,
    pub lifecycle: Lifecycle,
    pub protection: ProtectionState,
    pub cfg_rev: u64,
    pub runtime_epoch: u64,
    pub checking: bool,
    #[serde(default)]
    pub checked_at: Option<u64>,
    #[serde(default)]
    pub paused_until: Option<u64>,
    pub lockdown: bool,
    pub lockdown_manual: bool,
    pub preset: PolicyPreset,
    pub theme_mode: ThemeMode,
    pub privacy_mask_ip: bool,
    pub config: Config,
    #[serde(default)]
    pub targets: Vec<TargetStatus>,
    pub access: AccessEvidence,
    #[serde(default)]
    pub tripped: Option<TripInfo>,
    #[serde(default)]
    pub agents: Vec<AgentRuntimeStatus>,
    #[serde(default)]
    pub antigravity_proxy: AntigravityProxyStatus,
    #[serde(default)]
    pub updates: UpdateSummary,
    pub leak: LeakReport,
    pub env: EnvCheck,
    #[serde(default)]
    pub env_applied: Option<AppliedEnv>,
    pub self_check: DefenseSelfCheck,
    #[serde(default)]
    pub timeline: Vec<TimelineBucket>,
    #[serde(default)]
    pub launch_error: String,
    #[serde(default)]
    pub last_error: String,
    #[serde(default)]
    pub last_receipt: Option<OperationReceipt>,
    #[serde(default)]
    pub disarmed_reason: String,
    #[serde(default)]
    pub recent_logs: Vec<LogEntry>,
    #[serde(default)]
    pub recent_toasts: Vec<ToastNotificationEvent>,
    #[serde(default)]
    pub feishu: FeishuStatus,
    #[serde(default)]
    pub leak_shield: LeakShieldStatus,
    #[serde(default)]
    pub mihomo: MihomoStatus,
    // ---- v5 Runtime Telemetry & Sovereign Control Plane ----
    #[serde(default)]
    pub wfp: WfpStatus,
    #[serde(default)]
    pub risk_assessment: RiskAssessment,
    #[serde(default)]
    pub vaults: Vec<VaultRuntimeStatus>,
    #[serde(default)]
    pub last_cleanroom_report: Option<CleanRoomReport>,
    #[serde(default)]
    pub cleanroom_backup_count: usize,
    #[serde(default)]
    pub hooks: HookIntegrationStatus,
    #[serde(default)]
    pub wsl_bridge: WslBridgeStatus,
    #[serde(default)]
    pub burst_guard: BurstGuardStatus,
    #[serde(default)]
    pub hotkeys: HotkeyStatus,
}

impl GuardSnapshot {
    /// Returns true when the pause window is still active at `now_secs`.
    pub fn is_paused_at(&self, now_secs: u64) -> bool {
        self.paused_until.is_some_and(|until| until > now_secs)
    }

    /// Returns true if active isolation or trip diagnostic metadata is present.
    pub fn is_tripped(&self) -> bool {
        self.tripped.is_some() || self.protection.is_isolated()
    }

    /// Verifies that `(lifecycle, protection)` satisfies `CONTRACT-v3.10.md` §2.4.
    pub fn has_legal_state_pair(&self) -> bool {
        is_legal_state_pair(self.lifecycle, self.protection)
    }

    /// Returns true if at least one target is enabled and all enabled targets are `Pass`.
    pub fn all_enabled_pass(&self) -> bool {
        let mut enabled = 0usize;
        let mut passed = 0usize;
        for target in &self.targets {
            if target.state != TargetState::Disabled {
                enabled += 1;
                if target.state == TargetState::Pass {
                    passed += 1;
                }
            }
        }
        enabled > 0 && passed == enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AntigravityProxyState, Target, default_builtin_targets};

    #[test]
    fn snapshot_helpers_and_serde_roundtrip() {
        let mut snap = GuardSnapshot {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            lifecycle: Lifecycle::Armed,
            protection: ProtectionState::Monitoring,
            paused_until: Some(200),
            antigravity_proxy: AntigravityProxyStatus {
                state: AntigravityProxyState::Healthy,
                installed: true,
                antigravity_version: Some("44.9.1".into()),
                proxy_port: Some(7890),
                port_matches_guard: true,
                summary: "注入生效".into(),
                ..AntigravityProxyStatus::default()
            },
            ..GuardSnapshot::default()
        };
        assert!(snap.has_legal_state_pair());
        assert!(snap.is_paused_at(150));
        assert!(!snap.is_paused_at(200));
        assert!(!snap.all_enabled_pass());

        let targets: Vec<Target> = default_builtin_targets(&[], &["US".into()]);
        snap.targets = targets
            .iter()
            .map(|t| {
                TargetStatus::from_target(
                    t,
                    if t.enabled {
                        TargetState::Pass
                    } else {
                        TargetState::Disabled
                    },
                )
            })
            .collect();
        assert!(snap.all_enabled_pass());

        snap.targets[1].state = TargetState::Unverified;
        assert!(!snap.all_enabled_pass());

        // All disabled must never count as all_enabled_pass
        for t in &mut snap.targets {
            t.state = TargetState::Disabled;
        }
        assert!(!snap.all_enabled_pass());

        let json = serde_json::to_string(&snap).expect("serialize snapshot");
        let back: GuardSnapshot = serde_json::from_str(&json).expect("deserialize snapshot");
        assert_eq!(back, snap);
    }
}
