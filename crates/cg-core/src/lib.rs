//! ClaudeGuard v5 deterministic functional core.

pub mod access;
pub mod agents;
pub mod anchors;
pub mod asn_db;
pub mod burst_guard;
pub mod engine;
pub mod envcheck;
pub mod geo;
pub mod hygiene_plan;
pub mod netwatch;
pub mod onboarding;
pub mod policy;
pub mod redact;
pub mod risk_scorer;
pub mod targets;
pub mod timeline;

pub use agents::{
    CLI_AGENTS, GUI_AGENTS, GuiAgentDef, cli_agent_matches, gui_agent_matches,
    gui_agent_matches_with_all_dirs, gui_agent_matches_with_custom_dirs,
    gui_agent_matches_with_dirs, is_agent_scm_service_exe, same_process_identity,
};
pub use asn_db::{
    AsnEntry, KNOWN_ASNS, classify_asn, classify_org_heuristic, is_high_abuse_proxy_asn,
    known_asn_count, lookup_asn, lookup_asn_entry,
};
pub use burst_guard::{
    BurstEvaluation, BurstGuardConfig, BurstGuardTracker, BurstVerdict, CadenceMetrics,
    compute_cadence_cv, compute_cadence_metrics,
};
pub use cg_protocol;
pub use engine::{
    CheckPurpose, EffectCommand, EngineEvent, EngineState, GuardEngine, LaunchDecision,
    PendingTransaction, PendingTxKind, RoundToken, evaluate_launch_gate,
    evaluate_launch_gate_for_agent,
};
pub use hygiene_plan::{
    CommandLineHygieneAudit, HygienePlan, HygienePlanInput, audit_cmdline_hygiene,
    format_args_for_windows_cmdline, is_electron_agent, plan_chromium_hygiene_args,
    plan_electron_hygiene, plan_electron_hygiene_args,
};
pub use onboarding::{OnboardingChoice, apply_choice, recommend};
pub use policy::{evaluate, evaluate_with_preset};
pub use redact::{
    REDACTED, mask_config_for_diagnostics, mask_ip, mask_snapshot, mask_text_ips, redact,
};
pub use risk_scorer::{
    DEFAULT_TELEPORT_COOLDOWN_MINS, EgressObservation, GeoVelocityEvaluation, RiskScoringInput,
    evaluate_geo_velocity, haversine_km, is_unsupported_region, score_egress_risk,
};
pub use timeline::{BUCKETS_48, BUCKETS_96, SECONDS_PER_DAY, TimelineAggregator};
