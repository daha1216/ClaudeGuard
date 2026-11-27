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
pub mod cleanroom_win;
#[cfg(windows)]
pub(crate) mod com;
pub mod crypto_win;
pub mod env_win;
pub mod firewall_com;
pub mod hygiene_win;
pub mod ip_intel;
pub mod leak_shield_win;
pub mod mihomo_win;
pub mod netwatch_win;
pub mod notify_win;
pub mod probe_http;
pub mod process_win;
pub mod stun_probe;
pub mod traits;
pub mod update_check;
pub mod vault_win;
pub mod wfp_win;
pub mod zip_util;

pub use cg_protocol;
pub use update_check::{
    check_all_updates, fetch_github_latest_from_url, fetch_github_latest_release, is_version_newer,
    parse_github_latest_release, GithubReleaseInfo, ANTIGRAVITY_PROXY_REPO, CLAUDEGUARD_REPO,
};

#[cfg(windows)]
use std::path::PathBuf;
#[cfg(windows)]
use std::sync::{Arc, OnceLock, RwLock, Weak};

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

#[cfg(windows)]
static ACTIVE_HYBRID_FIREWALL: OnceLock<RwLock<Option<Weak<wfp_win::HybridFirewallEngine>>>> =
    OnceLock::new();

#[cfg(windows)]
fn register_active_hybrid_firewall(engine: &Arc<wfp_win::HybridFirewallEngine>) {
    let lock = ACTIVE_HYBRID_FIREWALL.get_or_init(|| RwLock::new(None));
    if let Ok(mut guard) = lock.write() {
        *guard = Some(Arc::downgrade(engine));
    }
}

/// Returns the active [`wfp_win::HybridFirewallEngine`] owned by the live [`WindowsPlatformDriver`],
/// allowing `cg-daemon` to synchronize WFP backend preferences, boot-time filters, and split-permit
/// posture without opening duplicate BFE handles.
#[cfg(windows)]
pub fn active_hybrid_firewall() -> Option<Arc<wfp_win::HybridFirewallEngine>> {
    ACTIVE_HYBRID_FIREWALL
        .get()
        .and_then(|lock| lock.read().ok())
        .and_then(|guard| guard.as_ref().and_then(Weak::upgrade))
}

/// Non-Windows stub returning `None` cleanly.
#[cfg(not(windows))]
pub fn active_hybrid_firewall() -> Option<std::sync::Arc<wfp_win::HybridFirewallEngine>> {
    None
}

/// Native Windows `PlatformDriver` backed by Dual-Session WFP / COM Hybrid Firewall, IpHelper,
/// Toolhelp32, WinRT Toast, Win32 DPAPI/CNG, and Registry readers.
#[cfg(windows)]
#[derive(Debug)]
pub struct WindowsPlatformDriver {
    firewall: Arc<wfp_win::HybridFirewallEngine>,
}

#[cfg(windows)]
impl Default for WindowsPlatformDriver {
    fn default() -> Self {
        Self::with_firewall_backend(cg_protocol::FirewallBackendPref::AutoWfpFirst)
    }
}

#[cfg(windows)]
impl WindowsPlatformDriver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a `WindowsPlatformDriver` with an explicit initial [`cg_protocol::FirewallBackendPref`].
    pub fn with_firewall_backend(pref: cg_protocol::FirewallBackendPref) -> Self {
        let firewall = Arc::new(wfp_win::HybridFirewallEngine::new(pref));
        register_active_hybrid_firewall(&firewall);
        Self { firewall }
    }

    /// Borrow the underlying [`wfp_win::HybridFirewallEngine`] handle.
    pub fn hybrid_firewall(&self) -> &Arc<wfp_win::HybridFirewallEngine> {
        &self.firewall
    }

    /// Query live WFP sublayer and blocked-packet attribution telemetry.
    pub fn wfp_status(&self) -> cg_protocol::WfpStatus {
        self.firewall.wfp_status()
    }

    /// Clear the in-memory WFP blocked-packet event ring buffer.
    pub fn clear_wfp_events(&self) {
        self.firewall.clear_wfp_events();
    }

    /// Switch the firewall backend preference at runtime (`AutoWfpFirst` / `WfpOnly` / `ComLegacy`).
    pub fn set_firewall_backend(
        &self,
        pref: cg_protocol::FirewallBackendPref,
    ) -> cg_protocol::WfpStatus {
        self.firewall.set_preference(pref)
    }

    /// Synchronize the opt-in persistent `FWPM_FILTER_FLAG_BOOTTIME` early boot guard (`wfp_boot_guard`).
    pub fn sync_wfp_boot_guard(&self, enable: bool, app_exes: &[PathBuf]) -> PlatformResult<usize> {
        self.firewall.sync_boot_guard(enable, app_exes)
    }

    /// Synchronize the Per-App Split-Permit Sandwich and dynamic WFP posture.
    pub fn sync_wfp_tunnel_only(
        &self,
        spec: &wfp_win::WfpRuntimePostureSpec,
    ) -> PlatformResult<cg_protocol::WfpStatus> {
        self.firewall.sync_tunnel_only_split_permit(spec)
    }

    /// Synchronize the 4-Vector Leak Shield via WFP when active, or COM fallback.
    pub fn sync_leak_shield_wfp(
        &self,
        app_paths: &[PathBuf],
        block_quic: bool,
        block_dns_doh: bool,
        block_ipv6: bool,
    ) -> PlatformResult<cg_protocol::LeakShieldStatus> {
        self.firewall
            .sync_leak_shield_wfp(app_paths, block_quic, block_dns_doh, block_ipv6)
    }

    /// Idempotently purge any persistent / boot-time ClaudeGuard WFP filters.
    pub fn clear_persistent_boot_guard(&self) -> PlatformResult<RemoveReport> {
        self.firewall.clear_persistent_boot_guard()
    }
}

#[cfg(windows)]
impl PlatformDriver for WindowsPlatformDriver {
    fn capabilities(&self) -> PlatformCapabilities {
        if self.firewall.engine_name() == wfp_win::BACKEND_WFP_DYNAMIC {
            PlatformCapabilities::windows_wfp_default()
        } else {
            PlatformCapabilities::windows_com_default()
        }
    }

    fn firewall(&self) -> &dyn FirewallEngine {
        self.firewall.as_ref()
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
            antigravity_cn: process_win::installed_antigravity_cn_version(),
            ag_usage_monitor: process_win::installed_ag_usage_monitor_version(),
            ag_capsule: process_win::installed_ag_capsule_version(),
        };
        let v5_local = update_check::V5LocalIdeVersions {
            cursor_ide: process_win::installed_cursor_ide_version(),
            windsurf_ide: process_win::installed_windsurf_ide_version(),
            zed_ide: process_win::installed_zed_ide_version(),
            trae_ide: process_win::installed_trae_ide_version(),
        };
        let mut seeded_prev = prev.clone();
        update_check::hydrate_v5_ide_updates(&mut seeded_prev, &v5_local, now_secs);
        update_check::check_all_updates_full(
            route,
            cg_version,
            ag_proxy,
            &local,
            component,
            &seeded_prev,
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

    fn wfp_status(&self) -> cg_protocol::WfpStatus {
        self.firewall.wfp_status()
    }

    fn clear_wfp_events(&self) {
        self.firewall.clear_wfp_events();
    }

    fn detect_tun_adapter_with_luid(&self) -> PlatformResult<Option<(String, u64)>> {
        Ok(wfp_win::detect_active_tun_luid())
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
