//! Re-exports canonical contract types from `cg-protocol` and provides daemon runtime helpers.

use std::time::{SystemTime, UNIX_EPOCH};

pub use cg_protocol::{
    decode_frame, encode_frame, read_frame, try_decode_frame, write_frame, AccessEvidence,
    AccessLevel, AgentKind, AgentRuntimeStatus, AnchorKind, AntigravityProxyState,
    AntigravityProxyStatus, AppliedEnv, ComponentUpdateStatus, Config, CutMode, DefenseCheckItem,
    DefenseSelfCheck, EnvCheck, EnvInfo, ErrorCode, Evaluation, FrameError, GuardSnapshot,
    LeakConn, LeakReport, Lifecycle, LogEntry, LogLevel, MigrationOutcome, NotifyPrefs,
    OnboardingOption, OnboardingProbeResult, OnboardingStrategy, OperationItemReceipt,
    OperationReceipt, OperationStatus, PipeRequest, PipeResponse, PolicyPreset, PolicyVerdict,
    ProbeResult, ProtectionState, SelfCheckStatus, Target, TargetState, TargetStatus, ThemeMode,
    TimelineBucket, TimelineStatus, TripInfo, UpdateCheckPhase, UpdateSummary, DEFAULT_PIPE_NAME,
    MAX_FRAME_BYTES, SNAPSHOT_SCHEMA_VERSION,
};

/// Daemon package version string.
pub const DAEMON_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Returns current UNIX timestamp in seconds.
pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Evaluates whether a [`GuardSnapshot`] passes scriptable `--check` validation.
pub fn snapshot_is_check_passed(snap: &GuardSnapshot) -> bool {
    let access_ok = !snap.network_isolation_supported
        || !snap.config.enforce_access_path
        || snap.access.is_known();
    snap.lifecycle == Lifecycle::Armed
        && snap.protection == ProtectionState::Monitoring
        && snap.tripped.is_none()
        && snap.checked_at.is_some()
        && snap.all_enabled_pass()
        && access_ok
}
