//! Lifecycle, protection state, §2.4 legality checks, and operation receipts.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Guard process lifecycle state (`CONTRACT-v3.10.md` §2.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    /// First-run wizard not yet completed, or config corrupt without usable backup.
    /// Destructive actions (launch, kill, isolate, cut, lockdown) are strictly forbidden.
    #[default]
    Unconfigured,
    /// Normal armed protection.
    Armed,
    /// App update, uninstall, or recovery transaction in progress.
    Maintenance,
    /// Graceful exit or uninstall shutdown in progress.
    Stopping,
    /// User explicitly disarmed protection (`--restore` or Flow B); process stays alive read-only.
    Disarmed,
}

impl Lifecycle {
    /// Human-readable label for UI and logs.
    pub fn label(self) -> &'static str {
        match self {
            Self::Unconfigured => "未配置",
            Self::Armed => "已布防",
            Self::Maintenance => "维护中",
            Self::Stopping => "正在停止",
            Self::Disarmed => "已撤防",
        }
    }

    /// Checks whether `(self, protection)` is permitted under `CONTRACT-v3.10.md` §2.4.
    pub fn allows(self, protection: ProtectionState) -> bool {
        is_legal_state_pair(self, protection)
    }
}

impl fmt::Display for Lifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Active protection state (`CONTRACT-v3.10.md` §2.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionState {
    /// Armed (or unconfigured) and awaiting completion of the initial check round.
    #[default]
    Pending,
    /// Normal monitoring without active isolation.
    Monitoring,
    /// Executing isolation actions; post-mutation verification not yet complete.
    Isolating,
    /// App-level quarantine verified (processes terminated + firewall rules verified).
    Quarantined,
    /// Global network cut verified on top of app-level quarantine.
    GlobalCut,
    /// Multi-step recovery transaction in progress.
    Recovering,
    /// Flow A stage 1 complete: business network restored while app quarantine remains held.
    NetworkReadyAppHeld,
    /// Incomplete protection, missing capability, corrupt WAL, or verification failure.
    Degraded,
}

impl ProtectionState {
    /// Human-readable label for UI and logs.
    pub fn label(self) -> &'static str {
        match self {
            Self::Pending => "等待首轮检查",
            Self::Monitoring => "正常守护",
            Self::Isolating => "正在隔离",
            Self::Quarantined => "应用已隔离",
            Self::GlobalCut => "全局已断网",
            Self::Recovering => "恢复事务中",
            Self::NetworkReadyAppHeld => "网络已恢复·应用隔离中",
            Self::Degraded => "降级/异常",
        }
    }

    /// Returns true when the protection state implies active isolation or pending recovery.
    pub fn is_isolated(self) -> bool {
        matches!(
            self,
            Self::Isolating | Self::Quarantined | Self::GlobalCut | Self::NetworkReadyAppHeld
        )
    }

    /// Checks whether `(lifecycle, self)` is permitted under `CONTRACT-v3.10.md` §2.4.
    pub fn is_legal_for(self, lifecycle: Lifecycle) -> bool {
        is_legal_state_pair(lifecycle, self)
    }
}

impl fmt::Display for ProtectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Enforces `CONTRACT-v3.10.md` §2.4 legal `(Lifecycle, ProtectionState)` combinations:
/// - `Unconfigured`: `Pending`
/// - `Armed`: all 8 protection states
/// - `Maintenance`: `Recovering`, `Quarantined`, `GlobalCut`, `Degraded`
/// - `Stopping`: `Recovering`, `Degraded`
/// - `Disarmed`: `Monitoring`, `NetworkReadyAppHeld`
pub fn is_legal_state_pair(lifecycle: Lifecycle, protection: ProtectionState) -> bool {
    match lifecycle {
        Lifecycle::Unconfigured => protection == ProtectionState::Pending,
        Lifecycle::Armed => true,
        Lifecycle::Maintenance => matches!(
            protection,
            ProtectionState::Recovering
                | ProtectionState::Quarantined
                | ProtectionState::GlobalCut
                | ProtectionState::Degraded
        ),
        Lifecycle::Stopping => matches!(
            protection,
            ProtectionState::Recovering | ProtectionState::Degraded
        ),
        Lifecycle::Disarmed => matches!(
            protection,
            ProtectionState::Monitoring | ProtectionState::NetworkReadyAppHeld
        ),
    }
}

/// Validates a `(Lifecycle, ProtectionState)` pair, returning an error message if illegal.
pub fn validate_state_pair(
    lifecycle: Lifecycle,
    protection: ProtectionState,
) -> Result<(), String> {
    if is_legal_state_pair(lifecycle, protection) {
        Ok(())
    } else {
        Err(format!(
            "illegal state combination per CONTRACT §2.4: lifecycle={lifecycle:?}, protection={protection:?}"
        ))
    }
}

/// Post-mutation verification outcome (`CONTRACT-v3.10.md` §4).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    /// Action executed and verified by readback.
    Verified,
    /// Only part of the target scope succeeded or remained verified.
    Partial,
    /// Execution failed.
    Failed,
    /// Query or verification failed; actual system state cannot be trusted.
    #[default]
    Unknown,
    /// Capability is not supported on the current OS/platform.
    Unsupported,
    /// No managed resources existed for this operation.
    NotApplicable,
}

impl OperationStatus {
    /// Returns true when the status confirms a clean, verified outcome or non-applicable no-op.
    pub fn is_verified_or_na(self) -> bool {
        matches!(self, Self::Verified | Self::NotApplicable)
    }
}

/// Single step/item inside an [`OperationReceipt`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationItemReceipt {
    pub name: String,
    pub status: OperationStatus,
    #[serde(default)]
    pub detail: String,
}

/// Structured audit/verification receipt for mutating operations (`CONTRACT-v3.10.md` §4).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationReceipt {
    pub id: String,
    pub status: OperationStatus,
    #[serde(default)]
    pub items: Vec<OperationItemReceipt>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub verified_scope: String,
    #[serde(default)]
    pub remaining: Vec<String>,
}

impl OperationReceipt {
    /// Creates a new receipt with empty items and scope.
    pub fn new(id: impl Into<String>, status: OperationStatus) -> Self {
        Self {
            id: id.into(),
            status,
            items: Vec::new(),
            error: None,
            verified_scope: String::new(),
            remaining: Vec::new(),
        }
    }

    /// Appends a sub-item result to the receipt.
    pub fn push_item(
        &mut self,
        name: impl Into<String>,
        status: OperationStatus,
        detail: impl Into<String>,
    ) {
        self.items.push(OperationItemReceipt {
            name: name.into(),
            status,
            detail: detail.into(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legal_state_matrix_matches_contract_section_2_4() {
        let all_protection = [
            ProtectionState::Pending,
            ProtectionState::Monitoring,
            ProtectionState::Isolating,
            ProtectionState::Quarantined,
            ProtectionState::GlobalCut,
            ProtectionState::Recovering,
            ProtectionState::NetworkReadyAppHeld,
            ProtectionState::Degraded,
        ];

        // Unconfigured allows only Pending
        for p in all_protection {
            assert_eq!(
                is_legal_state_pair(Lifecycle::Unconfigured, p),
                p == ProtectionState::Pending,
                "Unconfigured + {p:?}"
            );
        }

        // Armed allows all 8
        for p in all_protection {
            assert!(is_legal_state_pair(Lifecycle::Armed, p));
        }

        // Maintenance allows Recovering, Quarantined, GlobalCut, Degraded
        assert!(!is_legal_state_pair(
            Lifecycle::Maintenance,
            ProtectionState::Isolating
        ));
        assert!(!is_legal_state_pair(
            Lifecycle::Maintenance,
            ProtectionState::Monitoring
        ));
        assert!(is_legal_state_pair(
            Lifecycle::Maintenance,
            ProtectionState::Recovering
        ));
        assert!(is_legal_state_pair(
            Lifecycle::Maintenance,
            ProtectionState::Quarantined
        ));
        assert!(is_legal_state_pair(
            Lifecycle::Maintenance,
            ProtectionState::GlobalCut
        ));
        assert!(is_legal_state_pair(
            Lifecycle::Maintenance,
            ProtectionState::Degraded
        ));

        // Stopping allows only Recovering and Degraded
        assert!(!is_legal_state_pair(
            Lifecycle::Stopping,
            ProtectionState::Isolating
        ));
        assert!(!is_legal_state_pair(
            Lifecycle::Stopping,
            ProtectionState::Monitoring
        ));
        assert!(is_legal_state_pair(
            Lifecycle::Stopping,
            ProtectionState::Recovering
        ));
        assert!(is_legal_state_pair(
            Lifecycle::Stopping,
            ProtectionState::Degraded
        ));

        // Disarmed allows Monitoring and NetworkReadyAppHeld
        assert!(is_legal_state_pair(
            Lifecycle::Disarmed,
            ProtectionState::Monitoring
        ));
        assert!(is_legal_state_pair(
            Lifecycle::Disarmed,
            ProtectionState::NetworkReadyAppHeld
        ));
        assert!(!is_legal_state_pair(
            Lifecycle::Disarmed,
            ProtectionState::Isolating
        ));
        assert!(!is_legal_state_pair(
            Lifecycle::Disarmed,
            ProtectionState::Quarantined
        ));
    }

    #[test]
    fn validate_state_pair_rejects_illegal_combinations() {
        assert!(
            validate_state_pair(Lifecycle::Unconfigured, ProtectionState::Quarantined).is_err()
        );
        assert!(validate_state_pair(Lifecycle::Maintenance, ProtectionState::Isolating).is_err());
        assert!(validate_state_pair(Lifecycle::Stopping, ProtectionState::Isolating).is_err());
        assert!(validate_state_pair(Lifecycle::Armed, ProtectionState::Monitoring).is_ok());
    }

    #[test]
    fn lifecycle_protection_and_receipt_roundtrip_serde() {
        let mut receipt = OperationReceipt::new("tx-1", OperationStatus::Partial);
        receipt.push_item("firewall", OperationStatus::Verified, "removed 4 rules");
        receipt.push_item("nic", OperationStatus::Failed, "access denied");
        receipt.remaining.push("nic:{GUID}".into());
        receipt.verified_scope = "firewall".into();
        receipt.error = Some("partial cleanup".into());

        let json = serde_json::to_string(&receipt).expect("serialize receipt");
        assert!(json.contains(r#""status":"partial""#));
        let back: OperationReceipt = serde_json::from_str(&json).expect("deserialize receipt");
        assert_eq!(back, receipt);

        let lc = Lifecycle::Armed;
        let ps = ProtectionState::NetworkReadyAppHeld;
        assert!(lc.allows(ps));
        assert!(ps.is_legal_for(lc));
        assert!(ps.is_isolated());
        assert_eq!(
            serde_json::from_str::<ProtectionState>("\"network_ready_app_held\"").unwrap(),
            ps
        );
    }
}
