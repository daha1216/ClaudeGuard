//! Shared contract types, config v5 migration, snapshots, and Named Pipe framing for ClaudeGuard v5.

pub mod config;
pub mod model;
pub mod pipe;
pub mod snapshot;
pub mod state;
pub mod v5;

pub use config::{
    CONFIG_VERSION, Config, KNOWN_CLI_AGENT_IDS, KNOWN_GUI_AGENT_IDS, MigrationOutcome,
    NotifyPrefs, clean_guarded_agents,
};
pub use model::{
    AccessEvidence, AccessLevel, AgentKind, AgentRuntimeStatus, AnchorKind, AntigravityProxyState,
    AntigravityProxyStatus, AppliedEnv, BUILTIN_TARGET_IDS, ComponentUpdateStatus, CutMode,
    DefenseCheckItem, DefenseSelfCheck, EnvCheck, EnvInfo, Evaluation, FeishuStatus, IpRule,
    Ipv4Cidr, LeakConn, LeakReport, LeakShieldStatus, LogEntry, LogLevel, MihomoNodeInfo,
    MihomoStatus, OnboardingOption, OnboardingProbeResult, OnboardingStrategy, PolicyPreset,
    PolicyVerdict, ProbeResult, SelfCheckStatus, Target, TargetState, TargetStatus, ThemeMode,
    TimelineBucket, TimelineStatus, ToastNotificationEvent, TripInfo, UpdateCheckPhase,
    UpdateSummary, default_builtin_targets, ensure_builtin_targets, ip_hit, is_builtin_target,
    is_known_region, matched_ip_rule, normalize_ip, normalize_ip_or_cidr, normalize_region,
    region_hit, region_name,
};
pub use pipe::{
    DEFAULT_PIPE_NAME, ErrorCode, FrameError, MAX_FRAME_BYTES, PipeRequest, PipeResponse,
    decode_frame, encode_frame, read_frame, try_decode_frame, write_frame,
};
pub use snapshot::{GuardSnapshot, SNAPSHOT_SCHEMA_VERSION};
pub use state::{
    Lifecycle, OperationItemReceipt, OperationReceipt, OperationStatus, ProtectionState,
    is_legal_state_pair, validate_state_pair,
};
pub use v5::{
    AccountVault, AsnClassification, BurstGuardMode, BurstGuardStatus, CleanRoomBackupMeta,
    CleanRoomFinding, CleanRoomReport, CleanRoomRiskLevel, CleanRoomScope, CleanRoomVector,
    DnsCoherenceReport, ElectronHygieneReport, FirewallBackendPref, GeoVelocityAlert, HookDecision,
    HookFailMode, HookIntegrationStatus, HotkeyStatus, IpPurityReport, MsixIsolationMode,
    RiskAssessment, RiskDimensionItem, SafetyGrade, SanitizedHealthCard, StunLeakReport,
    VaultAppTarget, VaultRuntimeState, VaultRuntimeStatus, WfpBlockedEvent, WfpStatus,
    WslBridgeStatus, is_valid_vault_id,
};
