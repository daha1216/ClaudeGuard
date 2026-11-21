//! Cross-platform capability descriptors, error types, and driver traits.
//!
//! `FirewallEngine` separates the firewall backend from `PlatformDriver` so Windows COM
//! (`INetFwPolicy2`) is the default v4 engine and a future Windows Filtering Platform (`FwpmEngineOpen0`)
//! engine can plug in seamlessly. Non-Windows builds compile cleanly and report `Unsupported`.

use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::access_win::{AccessEvidenceRaw, AccessInfo, AccessPath};
use crate::env_win::EnvInfo;
use crate::netwatch_win::TcpConn;
use crate::probe_http::ProbeRoute;
use crate::process_win::{
    CachedProcessSnapshot, LaunchTarget, ProcessIdentity, SweepMode, SweepReport,
};

/// Unified result alias for platform operations.
pub type PlatformResult<T> = Result<T, PlatformError>;

/// Structured platform error distinguishing unsupported features from access/COM/IO failures.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PlatformError {
    /// Capability is not supported on the current OS or backend.
    Unsupported { feature: String, detail: String },
    /// OS denied permission (e.g. non-elevated caller attempting firewall/HKLM mutation).
    AccessDenied(String),
    /// Invalid arguments or disallowed input (e.g. unsafe launch target or oversized DPAPI secret).
    InvalidInput(String),
    /// Windows COM / WinRT call failed with an HRESULT.
    Com { code: i32, context: String },
    /// Filesystem or Win32 I/O error.
    Io(String),
    /// Network / proxy / redirect policy failure.
    Network(String),
}

impl PlatformError {
    /// Construct an `Unsupported` error for a named feature.
    pub fn unsupported(feature: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::Unsupported {
            feature: feature.into(),
            detail: detail.into(),
        }
    }

    /// Returns `true` when the failure is an explicit platform capability boundary.
    pub fn is_unsupported(&self) -> bool {
        matches!(self, Self::Unsupported { .. })
    }
}

impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported { feature, detail } => {
                write!(f, "unsupported capability `{feature}`: {detail}")
            }
            Self::AccessDenied(msg) => write!(f, "access denied: {msg}"),
            Self::InvalidInput(msg) => write!(f, "invalid input: {msg}"),
            Self::Com { code, context } => {
                write!(f, "COM error 0x{:08X} during {context}", *code as u32)
            }
            Self::Io(msg) => write!(f, "I/O error: {msg}"),
            Self::Network(msg) => write!(f, "network error: {msg}"),
        }
    }
}

impl std::error::Error for PlatformError {}

/// Explicit platform capability matrix (CONTRACT §7).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformCapabilities {
    pub os: String,
    pub firewall_engine: String,
    pub app_quarantine: bool,
    pub lockdown: bool,
    pub global_cut: bool,
    pub nic_disable: bool,
    pub access_path_inspection: bool,
    pub leak_watch: bool,
    pub toast_notifications: bool,
    pub dpapi_secrets: bool,
    pub env_alignment: bool,
    pub process_guard: bool,
}

impl PlatformCapabilities {
    /// Native Windows v4 capabilities (COM firewall + IpHelper + Toolhelp32 + WinRT Toast + DPAPI).
    pub fn windows_com_default() -> Self {
        Self {
            os: "windows".to_string(),
            firewall_engine: "windows-com-netfwpolicy2".to_string(),
            app_quarantine: true,
            lockdown: true,
            global_cut: true,
            // Native SetupAPI/WMI NIC toggling is not enabled yet; global cut uses COM firewall.
            nic_disable: false,
            access_path_inspection: true,
            leak_watch: true,
            toast_notifications: true,
            dpapi_secrets: true,
            env_alignment: true,
            process_guard: true,
        }
    }

    /// Non-Windows placeholder reporting Windows-specific backends as unsupported.
    pub fn unsupported_non_windows(os: impl Into<String>) -> Self {
        Self {
            os: os.into(),
            firewall_engine: "unsupported".to_string(),
            app_quarantine: false,
            lockdown: false,
            global_cut: false,
            nic_disable: false,
            access_path_inspection: false,
            leak_watch: false,
            toast_notifications: false,
            dpapi_secrets: false,
            env_alignment: false,
            process_guard: false,
        }
    }
}

/// Firewall rule traffic direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleDirection {
    Inbound,
    Outbound,
}

/// Firewall rule action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Block,
    Allow,
}

/// Windows Firewall profile bitmask constant for Domain | Private | Public (`NET_FW_PROFILE2_ALL`).
pub const FW_PROFILE_ALL: i32 = 0x7FFF_FFFF;

/// Desired firewall rule specification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallRuleSpec {
    pub name: String,
    /// `None` means apply to all programs (used by `ClaudeGuard Cut All`).
    pub program: Option<PathBuf>,
    pub direction: RuleDirection,
    pub action: RuleAction,
    pub enabled: bool,
    pub description: Option<String>,
    pub profiles: i32,
}

impl FirewallRuleSpec {
    /// Outbound block rule scoped to a single executable across all firewall profiles.
    pub fn block_out(name: impl Into<String>, program: PathBuf) -> Self {
        Self {
            name: name.into(),
            program: Some(program),
            direction: RuleDirection::Outbound,
            action: RuleAction::Block,
            enabled: true,
            description: Some("ClaudeGuard v4 application isolation".to_string()),
            profiles: FW_PROFILE_ALL,
        }
    }

    /// Inbound block rule scoped to a single executable across all firewall profiles.
    pub fn block_in(name: impl Into<String>, program: PathBuf) -> Self {
        Self {
            name: name.into(),
            program: Some(program),
            direction: RuleDirection::Inbound,
            action: RuleAction::Block,
            enabled: true,
            description: Some("ClaudeGuard v4 application isolation".to_string()),
            profiles: FW_PROFILE_ALL,
        }
    }

    /// Global outbound block rule across all programs and profiles (`ClaudeGuard Cut All`).
    pub fn global_block_out(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            program: None,
            direction: RuleDirection::Outbound,
            action: RuleAction::Block,
            enabled: true,
            description: Some("ClaudeGuard v4 global outbound cut".to_string()),
            profiles: FW_PROFILE_ALL,
        }
    }
}

/// Observed firewall rule record read back from the OS firewall store.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallRuleRecord {
    pub name: String,
    pub program: String,
    pub direction: RuleDirection,
    pub action: RuleAction,
    pub enabled: bool,
    pub profiles: i32,
}

/// Status of the three Windows Defender Firewall profiles.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallProfileStatus {
    pub domain_enabled: bool,
    pub private_enabled: bool,
    pub public_enabled: bool,
}

impl FirewallProfileStatus {
    /// True only when all three profiles are active.
    pub fn all_enabled(&self) -> bool {
        self.domain_enabled && self.private_enabled && self.public_enabled
    }

    /// Number of disabled profiles.
    pub fn disabled_count(&self) -> usize {
        usize::from(!self.domain_enabled)
            + usize::from(!self.private_enabled)
            + usize::from(!self.public_enabled)
    }
}

/// Post-mutation firewall rule verification result (R01).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Coverage {
    /// Expected rule count (`exes * directions`).
    pub desired: usize,
    /// Number of desired rules confirmed active, matching program/direction/action/enabled.
    pub verified: usize,
    /// Number of new rules created during this mutation.
    pub added: usize,
    /// Whether readback verification query succeeded; `false` NEVER claims completion.
    pub query_ok: bool,
}

impl Coverage {
    /// Returns `true` iff readback succeeded, at least one rule was expected, and all were verified.
    pub fn complete(&self) -> bool {
        self.query_ok && self.desired > 0 && self.verified == self.desired
    }

    /// Human-readable verification summary (never includes PII/IPs).
    pub fn summary(&self) -> String {
        if !self.query_ok {
            format!("无法核验（期望 {} 条）", self.desired)
        } else if self.complete() {
            format!("已核验 {} 条", self.verified)
        } else {
            format!("仅核验 {}/{} 条", self.verified, self.desired)
        }
    }
}

/// Result of an idempotent firewall rule removal operation with readback verification.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveReport {
    /// Number of rule instances removed (0 when already absent).
    pub removed: usize,
    /// Number of matching rules still present on readback (0 when clean).
    pub remaining: usize,
    /// Whether post-removal readback succeeded; `false` means cleanup cannot be confirmed.
    pub query_ok: bool,
}

impl RemoveReport {
    /// Returns `true` iff readback confirmed zero matching rules remain.
    pub fn clean(&self) -> bool {
        self.query_ok && self.remaining == 0
    }
}

/// Verified lockdown query snapshot (CONTRACT §8.8).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockdownStatus {
    pub on: bool,
    pub query_ok: bool,
    pub rules: usize,
}

/// Pluggable firewall engine abstraction (`ComFirewallEngine` today, `WfpFirewallEngine` next).
pub trait FirewallEngine: Send + Sync {
    /// Backend identifier string.
    fn engine_name(&self) -> &'static str;

    /// Query enabled state of firewall profiles.
    fn profile_status(&self) -> PlatformResult<FirewallProfileStatus>;

    /// Ensure firewall profiles are enabled (never turns off any user profile).
    /// Returns `Ok(true)` if all profiles are now enabled, `Ok(false)` if any remain disabled.
    fn ensure_profiles_enabled(&self) -> PlatformResult<bool>;

    /// Enumerate all rules whose display name starts with `prefix` (case-insensitive).
    fn enumerate_rules(&self, prefix: &str) -> PlatformResult<Vec<FirewallRuleRecord>>;

    /// Deduplicate rules sharing the same `(name, program, direction, action)` under `prefix`.
    /// Returns the number of duplicate instances removed.
    fn dedupe_rules(&self, prefix: &str) -> PlatformResult<usize>;

    /// Idempotently add missing rules in `desired` and verify them via post-mutation readback.
    fn ensure_rules(&self, desired: &[FirewallRuleSpec]) -> PlatformResult<Coverage>;

    /// Idempotently remove all rule instances matching any exact name in `names`, then verify via readback.
    fn remove_rules_by_name(&self, names: &[String]) -> PlatformResult<RemoveReport>;

    /// Idempotently remove all rule instances whose name starts with `prefix`, then verify via readback.
    fn remove_rules_with_prefix(&self, prefix: &str) -> PlatformResult<RemoveReport>;
}

/// Cross-platform OS driver interface used by `cg-daemon` and `cg-gui`.
pub trait PlatformDriver: Send + Sync {
    /// Report OS and backend capabilities accurately.
    fn capabilities(&self) -> PlatformCapabilities;

    /// Access the active firewall engine implementation.
    fn firewall(&self) -> &dyn FirewallEngine;

    /// Microsecond process elevation check (Win32 `GetTokenInformation(TokenElevation)`).
    fn is_elevated(&self) -> PlatformResult<bool>;

    /// Read OS proxy configuration without spawning subprocesses.
    fn read_access_evidence(&self) -> PlatformResult<AccessEvidenceRaw>;

    /// Detect active up TUN adapter via `GetAdaptersAddresses`.
    fn detect_tun_adapter(&self) -> PlatformResult<Option<String>>;

    /// Inspect resolved access path combining proxy registry + TUN + monitored hosts.
    fn inspect_access_path(
        &self,
        monitored_hosts: &[String],
    ) -> PlatformResult<(AccessPath, AccessInfo)>;

    /// Enumerate ESTABLISHED IPv4/IPv6 TCP sockets with owning PIDs.
    fn scan_tcp_connections(&self) -> PlatformResult<Vec<TcpConn>>;

    /// Discover covered executables for a guarded agent id (`claude`, `chatgpt`, `antigravity`).
    fn discover_agent_exes(&self, agent_id: &str) -> PlatformResult<Vec<PathBuf>>;

    /// Discover standalone native CLI executables for `cli_id` (`claude-code`, `codex`, `gemini`).
    fn discover_cli_exes(&self, cli_id: &str) -> PlatformResult<Vec<PathBuf>> {
        let _ = cli_id;
        Ok(Vec::new())
    }

    /// Kill running GUI processes belonging to `agent_id` with PID-reuse identity re-verification.
    fn kill_gui_agent(&self, agent_id: &str) -> PlatformResult<Vec<ProcessIdentity>>;

    /// Kill running CLI session processes belonging to `cli_id` (`claude-code`, `codex`, `gemini`)
    /// children-first with PID-reuse re-verification (never touches ancestor terminals).
    fn kill_cli_agent(&self, cli_id: &str) -> PlatformResult<Vec<ProcessIdentity>> {
        let _ = cli_id;
        Ok(Vec::new())
    }

    /// Sweep Claude desktop residuals / orphan CLI processes (never kills CLI attached to live terminals).
    fn sweep_claude(&self, mode: SweepMode) -> PlatformResult<SweepReport>;

    /// Sweep all orphaned residual processes across guarded agents (Claude, ChatGPT/Codex, Antigravity, CLIs).
    fn sweep_all_orphans(&self) -> PlatformResult<SweepReport> {
        self.sweep_claude(SweepMode::Residual)
    }

    /// Check updates across ClaudeGuard, `antigravity-proxy`, and all tracked AI clients.
    fn check_updates(
        &self,
        route: &ProbeRoute,
        cg_version: &str,
        ag_proxy: &cg_protocol::AntigravityProxyStatus,
        component: Option<&str>,
        prev: &cg_protocol::UpdateSummary,
        now_secs: u64,
    ) -> cg_protocol::UpdateSummary {
        let _ = (route, ag_proxy, component, now_secs);
        let (ag_ide_ver, ag_manifest_base) = crate::process_win::installed_antigravity_ide_info();
        let local = crate::update_check::LocalClientVersions {
            claude_desktop: crate::process_win::installed_claude_desktop_version(),
            claude_code: crate::process_win::installed_claude_code_version(),
            codex_desktop: crate::process_win::installed_codex_desktop_version(),
            codex_cli: crate::process_win::installed_codex_cli_version(),
            antigravity_ide: ag_ide_ver,
            antigravity_manifest_base: ag_manifest_base,
            antigravity_cn: crate::process_win::installed_antigravity_cn_version(),
            ag_usage_monitor: crate::process_win::installed_ag_usage_monitor_version(),
            ag_capsule: crate::process_win::installed_ag_capsule_version(),
        };
        let mut out = prev.clone();
        crate::update_check::hydrate_summary_locals(&mut out, cg_version, ag_proxy, &local);
        out
    }

    /// Inspect `yuaotian/antigravity-proxy` static (`version.dll` + `config.json`) and live memory module state.
    fn inspect_antigravity_proxy(
        &self,
        expected_proxy_port: u16,
        last_seen_version: Option<&str>,
        snap: &CachedProcessSnapshot,
        now_secs: u64,
    ) -> cg_protocol::AntigravityProxyStatus {
        let _ = (expected_proxy_port, last_seen_version, snap, now_secs);
        cg_protocol::AntigravityProxyStatus::default()
    }

    /// Launch a desktop application under normal user shell privileges.
    fn launch_app_normal_privilege(&self, target: &LaunchTarget) -> PlatformResult<()>;

    /// Send a native OS toast notification (WinRT on Windows, zero PowerShell).
    fn send_toast(&self, title: &str, body: &str) -> PlatformResult<()>;

    /// Encrypt sensitive bytes with OS user-bound protection (Win32 DPAPI).
    fn protect_secret(&self, plaintext: &[u8]) -> PlatformResult<Vec<u8>>;

    /// Decrypt sensitive bytes with OS user-bound protection (Win32 DPAPI).
    fn unprotect_secret(&self, ciphertext: &[u8]) -> PlatformResult<Vec<u8>>;

    /// Read system timezone and locale metadata from OS settings.
    fn read_env_info(&self) -> PlatformResult<EnvInfo>;

    /// Read current override default location `(lat, lon)`.
    fn read_default_location(&self) -> PlatformResult<(Option<String>, Option<String>)>;

    /// Write override default location `(lat, lon)`.
    fn write_default_location(&self, lat: &str, lon: &str) -> PlatformResult<()>;

    /// Delete override default location values.
    fn delete_default_location(&self) -> PlatformResult<()>;
}

/// Non-Windows firewall backend that cleanly reports `Unsupported` for every operation.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnsupportedFirewallEngine;

impl FirewallEngine for UnsupportedFirewallEngine {
    fn engine_name(&self) -> &'static str {
        "unsupported"
    }

    fn profile_status(&self) -> PlatformResult<FirewallProfileStatus> {
        Err(PlatformError::unsupported(
            "firewall",
            "Windows Firewall COM engine is only supported on Windows",
        ))
    }

    fn ensure_profiles_enabled(&self) -> PlatformResult<bool> {
        Err(PlatformError::unsupported(
            "firewall",
            "Windows Firewall COM engine is only supported on Windows",
        ))
    }

    fn enumerate_rules(&self, _prefix: &str) -> PlatformResult<Vec<FirewallRuleRecord>> {
        Err(PlatformError::unsupported(
            "firewall",
            "Windows Firewall COM engine is only supported on Windows",
        ))
    }

    fn dedupe_rules(&self, _prefix: &str) -> PlatformResult<usize> {
        Err(PlatformError::unsupported(
            "firewall",
            "Windows Firewall COM engine is only supported on Windows",
        ))
    }

    fn ensure_rules(&self, _desired: &[FirewallRuleSpec]) -> PlatformResult<Coverage> {
        Err(PlatformError::unsupported(
            "firewall",
            "Windows Firewall COM engine is only supported on Windows",
        ))
    }

    fn remove_rules_by_name(&self, _names: &[String]) -> PlatformResult<RemoveReport> {
        Err(PlatformError::unsupported(
            "firewall",
            "Windows Firewall COM engine is only supported on Windows",
        ))
    }

    fn remove_rules_with_prefix(&self, _prefix: &str) -> PlatformResult<RemoveReport> {
        Err(PlatformError::unsupported(
            "firewall",
            "Windows Firewall COM engine is only supported on Windows",
        ))
    }
}

/// Non-Windows `PlatformDriver` returning `Unsupported` cleanly on every OS-specific hook.
#[derive(Debug, Default)]
pub struct UnsupportedPlatformDriver {
    firewall: UnsupportedFirewallEngine,
}

impl PlatformDriver for UnsupportedPlatformDriver {
    fn capabilities(&self) -> PlatformCapabilities {
        PlatformCapabilities::unsupported_non_windows(std::env::consts::OS)
    }

    fn firewall(&self) -> &dyn FirewallEngine {
        &self.firewall
    }

    fn is_elevated(&self) -> PlatformResult<bool> {
        Err(PlatformError::unsupported(
            "elevation",
            "non-Windows platform",
        ))
    }

    fn read_access_evidence(&self) -> PlatformResult<AccessEvidenceRaw> {
        Err(PlatformError::unsupported(
            "access_path",
            "non-Windows platform",
        ))
    }

    fn detect_tun_adapter(&self) -> PlatformResult<Option<String>> {
        Err(PlatformError::unsupported(
            "tun_detection",
            "non-Windows platform",
        ))
    }

    fn inspect_access_path(
        &self,
        _monitored_hosts: &[String],
    ) -> PlatformResult<(AccessPath, AccessInfo)> {
        Err(PlatformError::unsupported(
            "access_path",
            "non-Windows platform",
        ))
    }

    fn scan_tcp_connections(&self) -> PlatformResult<Vec<TcpConn>> {
        Err(PlatformError::unsupported(
            "leak_watch",
            "non-Windows platform",
        ))
    }

    fn discover_agent_exes(&self, _agent_id: &str) -> PlatformResult<Vec<PathBuf>> {
        Err(PlatformError::unsupported(
            "process_guard",
            "non-Windows platform",
        ))
    }

    fn kill_gui_agent(&self, _agent_id: &str) -> PlatformResult<Vec<ProcessIdentity>> {
        Err(PlatformError::unsupported(
            "process_guard",
            "non-Windows platform",
        ))
    }

    fn sweep_claude(&self, _mode: SweepMode) -> PlatformResult<SweepReport> {
        Err(PlatformError::unsupported(
            "process_guard",
            "non-Windows platform",
        ))
    }

    fn launch_app_normal_privilege(&self, _target: &LaunchTarget) -> PlatformResult<()> {
        Err(PlatformError::unsupported(
            "launch_app",
            "non-Windows platform",
        ))
    }

    fn send_toast(&self, _title: &str, _body: &str) -> PlatformResult<()> {
        Err(PlatformError::unsupported(
            "toast_notifications",
            "non-Windows platform",
        ))
    }

    fn protect_secret(&self, _plaintext: &[u8]) -> PlatformResult<Vec<u8>> {
        Err(PlatformError::unsupported(
            "dpapi_secrets",
            "non-Windows platform",
        ))
    }

    fn unprotect_secret(&self, _ciphertext: &[u8]) -> PlatformResult<Vec<u8>> {
        Err(PlatformError::unsupported(
            "dpapi_secrets",
            "non-Windows platform",
        ))
    }

    fn read_env_info(&self) -> PlatformResult<EnvInfo> {
        Err(PlatformError::unsupported(
            "env_alignment",
            "non-Windows platform",
        ))
    }

    fn read_default_location(&self) -> PlatformResult<(Option<String>, Option<String>)> {
        Err(PlatformError::unsupported(
            "env_alignment",
            "non-Windows platform",
        ))
    }

    fn write_default_location(&self, _lat: &str, _lon: &str) -> PlatformResult<()> {
        Err(PlatformError::unsupported(
            "env_alignment",
            "non-Windows platform",
        ))
    }

    fn delete_default_location(&self) -> PlatformResult<()> {
        Err(PlatformError::unsupported(
            "env_alignment",
            "non-Windows platform",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_and_unsupported_driver_behave_honestly() {
        let win_caps = PlatformCapabilities::windows_com_default();
        assert_eq!(win_caps.os, "windows");
        assert_eq!(win_caps.firewall_engine, "windows-com-netfwpolicy2");
        assert!(win_caps.app_quarantine);
        assert!(win_caps.global_cut);
        assert!(!win_caps.nic_disable);

        let mac_caps = PlatformCapabilities::unsupported_non_windows("macos");
        assert!(!mac_caps.app_quarantine);
        assert!(!mac_caps.global_cut);
        assert_eq!(mac_caps.firewall_engine, "unsupported");

        let drv = UnsupportedPlatformDriver::default();
        assert_eq!(drv.firewall().engine_name(), "unsupported");
        assert!(drv
            .firewall()
            .profile_status()
            .unwrap_err()
            .is_unsupported());
        assert!(drv
            .firewall()
            .ensure_profiles_enabled()
            .unwrap_err()
            .is_unsupported());
        assert!(drv
            .firewall()
            .enumerate_rules("ClaudeGuard")
            .unwrap_err()
            .is_unsupported());
        assert!(drv
            .firewall()
            .ensure_rules(&[])
            .unwrap_err()
            .is_unsupported());
        assert!(drv.is_elevated().unwrap_err().is_unsupported());
        assert!(drv.send_toast("t", "b").unwrap_err().is_unsupported());
        assert!(drv.protect_secret(b"x").unwrap_err().is_unsupported());
    }
}
