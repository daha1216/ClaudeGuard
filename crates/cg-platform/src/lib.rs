//! `cg-platform`: ClaudeGuard v4 native OS/platform abstraction and Windows driver.
//!
//! Zero `powershell.exe`, `netsh.exe`, or `net.exe` on guard paths:
//! - `firewall_com`: Native Windows Firewall COM (`INetFwPolicy2` / `INetFwRules` / `INetFwRule`)
//! - `process_win`: Cached `ProcessScanner`, AppModel discovery, PID-reuse re-check, normal launcher
//! - `access_win`: Registry proxy + `GetAdaptersAddresses` TUN + `TokenElevation` admin check
//! - `netwatch_win`: `GetExtendedTcpTable` IPv4/IPv6 leak inspector excluding `198.18.0.0/15` fake-ip
//! - `notify_win`: Native WinRT `ToastNotificationManager` + idempotent AUMID registration
//! - `probe_http`: Unified `NetworkPolicy` HTTP probe & GitHub Release 302 allowlisted downloader
//! - `crypto_win`: Native Win32 DPAPI (`CryptProtectData` / `CryptUnprotectData`) + Feishu HMAC
//! - `env_win`: Native Registry timezone/locale & default location reader

pub mod access_win;
pub mod antigravity_proxy_win;
#[cfg(windows)]
pub(crate) mod com;
pub mod crypto_win;
pub mod env_win;
pub mod firewall_com;
pub mod netwatch_win;
pub mod notify_win;
pub mod probe_http;
pub mod process_win;
pub mod traits;
pub mod update_check;

pub use cg_protocol;
pub use update_check::{
    check_all_updates, fetch_github_latest_from_url, fetch_github_latest_release, is_version_newer,
    parse_github_latest_release, GithubReleaseInfo, ANTIGRAVITY_PROXY_REPO, CLAUDEGUARD_REPO,
};

#[cfg(windows)]
use std::path::PathBuf;

pub use traits::{
    Coverage, FirewallEngine, FirewallProfileStatus, FirewallRuleRecord, FirewallRuleSpec,
    LockdownStatus, PlatformCapabilities, PlatformDriver, PlatformError, PlatformResult,
    RemoveReport, RuleAction, RuleDirection, UnsupportedFirewallEngine, UnsupportedPlatformDriver,
    FW_PROFILE_ALL,
};

#[cfg(windows)]
use access_win::{AccessEvidenceRaw, AccessInfo, AccessPath};
#[cfg(windows)]
use env_win::EnvInfo;
#[cfg(windows)]
use netwatch_win::TcpConn;
#[cfg(windows)]
use process_win::{LaunchTarget, ProcessIdentity, SweepMode, SweepReport};

/// Native Windows `PlatformDriver` backed by COM Firewall, IpHelper, Toolhelp32, WinRT Toast,
/// Win32 DPAPI, and Registry readers.
#[cfg(windows)]
#[derive(Debug, Default)]
pub struct WindowsPlatformDriver {
    firewall: firewall_com::ComFirewallEngine,
}

#[cfg(windows)]
impl WindowsPlatformDriver {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(windows)]
impl PlatformDriver for WindowsPlatformDriver {
    fn capabilities(&self) -> PlatformCapabilities {
        PlatformCapabilities::windows_com_default()
    }

    fn firewall(&self) -> &dyn FirewallEngine {
        &self.firewall
    }

    fn is_elevated(&self) -> PlatformResult<bool> {
        access_win::is_elevated()
    }

    fn read_access_evidence(&self) -> PlatformResult<AccessEvidenceRaw> {
        Ok(access_win::read_proxy_evidence())
    }

    fn detect_tun_adapter(&self) -> PlatformResult<Option<String>> {
        Ok(access_win::detect_tun_adapter())
    }

    fn inspect_access_path(
        &self,
        monitored_hosts: &[String],
    ) -> PlatformResult<(AccessPath, AccessInfo)> {
        Ok(access_win::inspect_access_path(monitored_hosts))
    }

    fn scan_tcp_connections(&self) -> PlatformResult<Vec<TcpConn>> {
        Ok(netwatch_win::established_conns())
    }

    fn discover_agent_exes(&self, agent_id: &str) -> PlatformResult<Vec<PathBuf>> {
        Ok(process_win::discover_agent_exes(agent_id))
    }

    fn discover_cli_exes(&self, cli_id: &str) -> PlatformResult<Vec<PathBuf>> {
        Ok(process_win::discover_cli_exes(cli_id))
    }

    fn kill_gui_agent(&self, agent_id: &str) -> PlatformResult<Vec<ProcessIdentity>> {
        Ok(process_win::kill_gui_agent(agent_id))
    }

    fn kill_cli_agent(&self, cli_id: &str) -> PlatformResult<Vec<ProcessIdentity>> {
        Ok(process_win::kill_cli_agent(cli_id))
    }

    fn sweep_claude(&self, mode: SweepMode) -> PlatformResult<SweepReport> {
        Ok(process_win::sweep_claude(mode))
    }

    fn sweep_all_orphans(&self) -> PlatformResult<SweepReport> {
        Ok(process_win::sweep_all_orphans())
    }

    fn check_updates(
        &self,
        route: &probe_http::ProbeRoute,
        cg_version: &str,
        ag_proxy: &cg_protocol::AntigravityProxyStatus,
        component: Option<&str>,
        prev: &cg_protocol::UpdateSummary,
        now_secs: u64,
    ) -> cg_protocol::UpdateSummary {
        let (ag_ide_ver, ag_manifest_base) = process_win::installed_antigravity_ide_info();
        let local = update_check::LocalClientVersions {
            claude_desktop: process_win::installed_claude_desktop_version(),
            claude_code: process_win::installed_claude_code_version(),
            codex_desktop: process_win::installed_codex_desktop_version(),
            codex_cli: process_win::installed_codex_cli_version(),
            antigravity_ide: ag_ide_ver,
            antigravity_manifest_base: ag_manifest_base,
        };
        update_check::check_all_updates_full(
            route,
            cg_version,
            ag_proxy,
            &local,
            component,
            prev,
            now_secs,
        )
    }

    fn inspect_antigravity_proxy(
        &self,
        expected_proxy_port: u16,
        last_seen_version: Option<&str>,
        snap: &process_win::CachedProcessSnapshot,
        now_secs: u64,
    ) -> cg_protocol::AntigravityProxyStatus {
        antigravity_proxy_win::inspect_antigravity_proxy(
            expected_proxy_port,
            last_seen_version,
            snap,
            now_secs,
        )
    }

    fn launch_app_normal_privilege(&self, target: &LaunchTarget) -> PlatformResult<()> {
        process_win::launch_normal_privilege(target)
    }

    fn send_toast(&self, title: &str, body: &str) -> PlatformResult<()> {
        notify_win::send_toast(title, body)
    }

    fn protect_secret(&self, plaintext: &[u8]) -> PlatformResult<Vec<u8>> {
        crypto_win::protect_bytes(plaintext, crypto_win::DpapiScope::CurrentUser)
    }

    fn unprotect_secret(&self, ciphertext: &[u8]) -> PlatformResult<Vec<u8>> {
        crypto_win::unprotect_bytes(ciphertext)
    }

    fn read_env_info(&self) -> PlatformResult<EnvInfo> {
        Ok(env_win::read_env_info())
    }

    fn read_default_location(&self) -> PlatformResult<(Option<String>, Option<String>)> {
        env_win::read_default_location()
    }

    fn write_default_location(&self, lat: &str, lon: &str) -> PlatformResult<()> {
        env_win::write_default_location(lat, lon)
    }

    fn delete_default_location(&self) -> PlatformResult<()> {
        env_win::delete_default_location()
    }
}

/// Platform driver alias (`WindowsPlatformDriver` on Windows, `UnsupportedPlatformDriver` elsewhere).
#[cfg(windows)]
pub type NativePlatformDriver = WindowsPlatformDriver;

/// Platform driver alias (`WindowsPlatformDriver` on Windows, `UnsupportedPlatformDriver` elsewhere).
#[cfg(not(windows))]
pub type NativePlatformDriver = UnsupportedPlatformDriver;

/// Construct the default driver for the current compile target.
pub fn default_platform_driver() -> NativePlatformDriver {
    NativePlatformDriver::default()
}
