//! ClaudeGuard v4 deterministic functional core.

pub mod access;
pub mod agents;
pub mod anchors;
pub mod engine;
pub mod envcheck;
pub mod geo;
pub mod netwatch;
pub mod onboarding;
pub mod policy;
pub mod redact;
pub mod targets;
pub mod timeline;

pub use agents::{
    cli_agent_matches, gui_agent_matches, gui_agent_matches_with_all_dirs,
    gui_agent_matches_with_dirs, is_agent_scm_service_exe, same_process_identity,
};
pub use cg_protocol;
pub use engine::{
    CheckPurpose, EffectCommand, EngineEvent, EngineState, GuardEngine, LaunchDecision,
    PendingTransaction, PendingTxKind, RoundToken, evaluate_launch_gate,
    evaluate_launch_gate_for_agent,
};
pub use onboarding::{OnboardingChoice, apply_choice, recommend};
pub use policy::{evaluate, evaluate_with_preset};
pub use redact::{REDACTED, mask_ip, mask_snapshot, mask_text_ips, redact};
pub use timeline::{BUCKETS_48, BUCKETS_96, SECONDS_PER_DAY, TimelineAggregator};
