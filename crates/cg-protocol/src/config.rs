//! v5 configuration schema and lossless v2/v3/v4 JSON migration parser.

use crate::model::{
    CutMode, PolicyPreset, Target, ThemeMode, default_builtin_targets, default_true,
    ensure_builtin_targets, is_builtin_target, is_known_region, normalize_ip_or_cidr,
    normalize_region,
};
use crate::v5::{
    AccountVault, BurstGuardMode, FirewallBackendPref, HookFailMode, is_valid_vault_id,
};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Current config schema version (v5).
pub const CONFIG_VERSION: u32 = 5;

/// Known GUI agent identifiers that may appear in `guarded_agents`.
pub const KNOWN_GUI_AGENT_IDS: [&str; 3] = ["claude", "chatgpt", "antigravity"];

/// Known CLI agent identifiers observed and protected by Pre-Prompt Hook gates.
pub const KNOWN_CLI_AGENT_IDS: [&str; 2] = ["claude-code", "codex"];

fn default_global_min_score() -> u8 {
    60
}

fn default_hook_ttl_secs() -> u64 {
    45
}

fn default_burst_warn_rpm() -> u32 {
    18
}

fn default_burst_throttle_rpm() -> u32 {
    30
}

fn default_panic_chord() -> String {
    "Ctrl+Alt+Shift+L".into()
}

fn default_hud_chord() -> String {
    "Ctrl+Alt+Shift+H".into()
}

fn default_proxy_host() -> String {
    "127.0.0.1".into()
}

fn default_proxy_port() -> u16 {
    7890
}

fn default_interval_secs() -> u64 {
    15
}

fn default_trip_threshold() -> u32 {
    2
}

fn default_guarded_agents() -> Vec<String> {
    vec!["claude".into()]
}

fn default_targets() -> Vec<Target> {
    default_builtin_targets(&[], &[])
}

/// Desktop and webhook notification preferences (`CONTRACT-v3.10.md` D5 / R14).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotifyPrefs {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub trip: bool,
    #[serde(default = "default_true")]
    pub recover: bool,
    #[serde(default = "default_true")]
    pub launch_blocked: bool,
    #[serde(default = "default_true")]
    pub warning: bool,
    #[serde(default = "default_true")]
    pub client_update: bool,
    #[serde(default = "default_true")]
    pub self_update: bool,
    /// When `false` (default), egress IP/region/city/hostname PII is redacted from notifications.
    #[serde(default)]
    pub include_egress: bool,
}

impl Default for NotifyPrefs {
    fn default() -> Self {
        Self {
            enabled: true,
            trip: true,
            recover: true,
            launch_blocked: true,
            warning: true,
            client_update: true,
            self_update: true,
            include_egress: false,
        }
    }
}

impl NotifyPrefs {
    /// Returns true if notifications are globally enabled and the given category is active.
    pub fn is_on(&self, class: &str) -> bool {
        if !self.enabled {
            return false;
        }
        match class {
            "trip" => self.trip,
            "recover" => self.recover,
            "launch_blocked" => self.launch_blocked,
            "warning" => self.warning,
            "client_update" => self.client_update,
            "self_update" => self.self_update,
            _ => true,
        }
    }
}

/// ClaudeGuard v4 persisted configuration (`%APPDATA%\ClaudeGuard\config.json`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub version: u32,
    #[serde(default = "default_true")]
    pub first_run: bool,
    #[serde(default = "default_proxy_host")]
    pub proxy_host: String,
    #[serde(default = "default_proxy_port")]
    pub proxy_port: u16,
    #[serde(default = "default_interval_secs", alias = "check_interval_secs")]
    pub interval_secs: u64,
    #[serde(default = "default_trip_threshold")]
    pub trip_threshold: u32,
    #[serde(default = "default_true")]
    pub enforce_access_path: bool,
    #[serde(default = "default_true")]
    pub kill_on_fail: bool,
    #[serde(default = "default_true")]
    pub kill_cli_on_fail: bool,
    #[serde(default = "default_true")]
    pub quarantine_on_fail: bool,
    /// Suppress automatic trip/isolation when proxy access is intact and the observed egress IP
    /// has not changed from the last verified compliant baseline under the current config revision.
    #[serde(default = "default_true")]
    pub suppress_trip_when_ip_unchanged: bool,
    /// Observe-only mode: keep read-only probing, alerts, timeline, and launch-gate checks active
    /// without executing automatic trip isolation, process kills, or auto-lockdown.
    #[serde(default)]
    pub monitor_only: bool,
    #[serde(default)]
    pub cut_mode: CutMode,
    #[serde(default = "default_true")]
    pub lockdown_on_uncovered: bool,
    #[serde(default = "default_true")]
    pub sweep_on_exit: bool,
    #[serde(default = "default_true")]
    pub leak_watch: bool,
    #[serde(default)]
    pub leak_trip: bool,
    #[serde(default = "default_true")]
    pub leak_shield_quic: bool,
    #[serde(default)]
    pub leak_shield_dns_doh: bool,
    #[serde(default)]
    pub leak_shield_ipv6: bool,
    #[serde(default = "default_true")]
    pub env_check: bool,
    #[serde(default)]
    pub env_align_tz: bool,
    #[serde(default)]
    pub env_align_location: bool,
    #[serde(default)]
    pub privacy_mask_ip: bool,
    #[serde(default)]
    pub theme_mode: ThemeMode,
    #[serde(default)]
    pub preset: PolicyPreset,
    #[serde(default = "default_guarded_agents")]
    pub guarded_agents: Vec<String>,
    #[serde(default)]
    pub targets: Vec<Target>,
    #[serde(default)]
    pub notify: NotifyPrefs,

    // Additional v3 user preferences preserved across v3 -> v4 upgrade.
    #[serde(default = "default_true")]
    pub cli_warn: bool,
    #[serde(default = "default_true")]
    pub close_to_tray: bool,
    #[serde(default)]
    pub auto_start_with_system: bool,
    #[serde(default = "default_true")]
    pub auto_upd_check: bool,
    #[serde(default = "default_true")]
    pub require_antigravity_proxy: bool,
    /// Automatically re-inject `version.dll` after an Antigravity self-update overwrote it.
    #[serde(default = "default_true")]
    pub auto_repair_antigravity_proxy: bool,
    #[serde(default)]
    pub last_seen_antigravity_version: Option<String>,

    // ---- v5 Anti-Ban Kernel, Intelligence, Vaults, Hook & Hotkey preferences ----
    /// M1: Firewall isolation engine preference (default: Dynamic WFP with seamless COM fallback).
    #[serde(default)]
    pub firewall_backend: FirewallBackendPref,
    /// M1: Opt-in persistent early boot-time WFP guard (default `false` to prevent boot surprises).
    #[serde(default)]
    pub wfp_boot_guard: bool,
    /// M2: Global minimum 10D egress safety score (`0..=100`, default `60`).
    #[serde(default = "default_global_min_score")]
    pub min_global_safety_score: u8,
    /// M2: Block launch on impossible-travel cross-country geo-teleportation (`>900 km/h`).
    #[serde(default = "default_true")]
    pub enforce_geo_velocity: bool,
    /// M2: Opt-in hard block when egress ASN is classified as cloud datacenter hosting.
    #[serde(default)]
    pub block_datacenter_asn: bool,
    /// M3: Inject WebRTC / QUIC / DNS-over-proxy anti-leak flags when safe-launching Electron apps.
    #[serde(default = "default_true")]
    pub enforce_electron_hygiene_flags: bool,
    /// M3: Periodically run native RFC 5389 UDP STUN leak & DNS coherence probes.
    #[serde(default = "default_true")]
    pub enable_stun_dns_audit: bool,
    /// M4: Sovereign Multi-Account Isolated Vaults.
    #[serde(default)]
    pub vaults: Vec<AccountVault>,
    /// M6: `FastHookGate` O(1) snapshot freshness TTL in seconds (`10..=300`, default `45`).
    #[serde(default = "default_hook_ttl_secs")]
    pub hook_freshness_ttl_secs: u64,
    /// M6: Hook fallback behavior when daemon service is unreachable.
    #[serde(default)]
    pub hook_fail_mode: HookFailMode,
    /// M6: Enable WSL2 localhost HMAC gate bridge.
    #[serde(default = "default_true")]
    pub wsl_bridge_enabled: bool,
    /// M6: BurstGuard automated rate-burst & robotic cadence guard mode.
    #[serde(default)]
    pub burst_guard_mode: BurstGuardMode,
    #[serde(default = "default_burst_warn_rpm")]
    pub burst_warn_rpm: u32,
    #[serde(default = "default_burst_throttle_rpm")]
    pub burst_throttle_rpm: u32,
    /// M7: Global emergency hotkeys toggle & chord strings.
    #[serde(default = "default_true")]
    pub global_hotkeys_enabled: bool,
    #[serde(default = "default_panic_chord")]
    pub hotkey_panic_lockdown: String,
    #[serde(default = "default_hud_chord")]
    pub hotkey_quick_hud: String,

    // ---- Legacy v2/v3 fields: read-only migration inputs, never serialized in v5 ----
    #[serde(default, skip_serializing, rename = "cut_network")]
    pub legacy_cut_network: Option<bool>,
    #[serde(default, skip_serializing, rename = "disable_network_adapters")]
    pub legacy_disable_network_adapters: Option<bool>,
    #[serde(default, skip_serializing)]
    pub allowed_ips: Vec<String>,
    #[serde(default, skip_serializing)]
    pub egress_region: String,
    #[serde(default, skip_serializing)]
    pub required_ip: Option<String>,
    #[serde(default, skip_serializing)]
    pub connect_target: Option<String>,
    #[serde(default, skip_serializing)]
    pub app_id: Option<String>,
    #[serde(default, skip_serializing)]
    pub launch_on_pass: Option<bool>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            first_run: true,
            proxy_host: default_proxy_host(),
            proxy_port: default_proxy_port(),
            interval_secs: default_interval_secs(),
            trip_threshold: default_trip_threshold(),
            enforce_access_path: true,
            kill_on_fail: true,
            kill_cli_on_fail: true,
            quarantine_on_fail: true,
            suppress_trip_when_ip_unchanged: true,
            monitor_only: false,
            cut_mode: CutMode::Off,
            lockdown_on_uncovered: true,
            sweep_on_exit: true,
            leak_watch: true,
            leak_trip: false,
            leak_shield_quic: true,
            leak_shield_dns_doh: false,
            leak_shield_ipv6: false,
            env_check: true,
            env_align_tz: false,
            env_align_location: false,
            privacy_mask_ip: false,
            theme_mode: ThemeMode::Auto,
            preset: PolicyPreset::StandardRegion,
            guarded_agents: default_guarded_agents(),
            targets: default_targets(),
            notify: NotifyPrefs::default(),
            cli_warn: true,
            close_to_tray: true,
            auto_start_with_system: false,
            auto_upd_check: true,
            require_antigravity_proxy: true,
            auto_repair_antigravity_proxy: true,
            last_seen_antigravity_version: None,
            firewall_backend: FirewallBackendPref::default(),
            wfp_boot_guard: false,
            min_global_safety_score: default_global_min_score(),
            enforce_geo_velocity: true,
            block_datacenter_asn: false,
            enforce_electron_hygiene_flags: true,
            enable_stun_dns_audit: true,
            vaults: Vec::new(),
            hook_freshness_ttl_secs: default_hook_ttl_secs(),
            hook_fail_mode: HookFailMode::default(),
            wsl_bridge_enabled: true,
            burst_guard_mode: BurstGuardMode::default(),
            burst_warn_rpm: default_burst_warn_rpm(),
            burst_throttle_rpm: default_burst_throttle_rpm(),
            global_hotkeys_enabled: true,
            hotkey_panic_lockdown: default_panic_chord(),
            hotkey_quick_hud: default_hud_chord(),
            legacy_cut_network: None,
            legacy_disable_network_adapters: None,
            allowed_ips: Vec::new(),
            egress_region: String::new(),
            required_ip: None,
            connect_target: None,
            app_id: None,
            launch_on_pass: None,
        }
    }
}

/// Summary of migrating a v2/v3/v4 JSON payload into a v4 [`Config`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationOutcome {
    pub config: Config,
    pub source_version: u32,
    pub migrated: bool,
    pub notes: Vec<String>,
    pub preserved_cut_mode: Option<CutMode>,
}

impl Config {
    /// Parses a v2, v3, or v4 JSON config string losslessly and migrates it to v4.
    pub fn from_legacy_json(raw: &str) -> Result<MigrationOutcome, String> {
        let trimmed = raw.trim().trim_start_matches('\u{feff}');
        if trimmed.is_empty() {
            return Err("config JSON is empty".to_string());
        }
        let value: serde_json::Value =
            serde_json::from_str(trimmed).map_err(|e| format!("invalid config JSON: {e}"))?;
        let obj = value
            .as_object()
            .ok_or_else(|| "config JSON root must be an object".to_string())?;

        let has_v2_fields = obj.contains_key("allowed_ips")
            || obj.contains_key("required_ip")
            || obj.contains_key("egress_region");
        let explicit_version = obj
            .get("version")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);
        let source_version = match explicit_version {
            Some(v) if v > 0 => v,
            _ if obj.contains_key("targets") => 3,
            _ => 2,
        };
        let has_explicit_cut_mode = obj.contains_key("cut_mode");

        let mut cfg: Config = serde_json::from_value(value.clone())
            .map_err(|e| format!("config decode error: {e}"))?;

        let mut notes = Vec::new();
        let mut preserved_cut_mode = None;

        if has_explicit_cut_mode {
            cfg.legacy_cut_network = None;
            cfg.legacy_disable_network_adapters = None;
        } else if let Some(cut_net) = cfg.legacy_cut_network.take() {
            let disable_nics = cfg.legacy_disable_network_adapters.take().unwrap_or(false);
            let mapped = if !cut_net {
                CutMode::Off
            } else if disable_nics {
                CutMode::Nics
            } else {
                CutMode::Firewall
            };
            cfg.cut_mode = mapped;
            if mapped != CutMode::Off {
                preserved_cut_mode = Some(mapped);
                notes.push(format!("已无损保留旧配置断网档位：{}", mapped.label()));
            }
        } else {
            cfg.legacy_disable_network_adapters = None;
        }

        if has_v2_fields {
            notes.push("已将 v2 白名单字段迁移至目标列表".to_string());
        }
        if obj.contains_key("check_interval_secs") && !obj.contains_key("interval_secs") {
            notes.push("已将 check_interval_secs 映射到 interval_secs".to_string());
        }

        if !cfg.targets.is_empty() {
            cfg.targets = sanitize_migrated_targets(std::mem::take(&mut cfg.targets));
        }
        cfg.migrate();
        let migrated = source_version < CONFIG_VERSION || has_v2_fields || !has_explicit_cut_mode;
        Ok(MigrationOutcome {
            config: cfg,
            source_version,
            migrated,
            notes,
            preserved_cut_mode,
        })
    }

    /// Convenience helper returning the migrated v4 [`Config`] from any v2/v3/v4 JSON.
    pub fn from_json_str(raw: &str) -> Result<Self, String> {
        Self::from_legacy_json(raw).map(|outcome| outcome.config)
    }

    /// Migrates any legacy fields in-place, fills missing built-in targets, and clamps numeric bounds.
    pub fn migrate(&mut self) {
        if let Some(cut_net) = self.legacy_cut_network.take() {
            let disable_nics = self.legacy_disable_network_adapters.take().unwrap_or(false);
            if self.cut_mode == CutMode::Off {
                self.cut_mode = if !cut_net {
                    CutMode::Off
                } else if disable_nics {
                    CutMode::Nics
                } else {
                    CutMode::Firewall
                };
            }
        } else {
            self.legacy_disable_network_adapters = None;
        }

        let mut legacy_ips = std::mem::take(&mut self.allowed_ips);
        if legacy_ips.is_empty()
            && let Some(ip) = self.required_ip.take()
        {
            legacy_ips.push(ip);
        }
        let legacy_ips: Vec<String> = legacy_ips
            .iter()
            .filter_map(|ip| normalize_ip_or_cidr(ip))
            .collect();
        let legacy_region = normalize_region(&self.egress_region)
            .filter(|c| is_known_region(c))
            .unwrap_or_default();
        let legacy_regions: Vec<String> = if legacy_region.is_empty() {
            Vec::new()
        } else {
            vec![legacy_region]
        };

        if self.targets.is_empty() {
            self.targets = default_builtin_targets(&legacy_ips, &legacy_regions);
        } else {
            let defaults = default_builtin_targets(&[], &[]);
            for target in &mut self.targets {
                target.timeout_secs = target.timeout_secs.clamp(3, 60);
                let id_norm = target.id.trim().to_ascii_lowercase();
                if is_builtin_target(&id_norm) {
                    target.builtin = true;
                    if let Some(base) = defaults.iter().find(|d| d.id == id_norm) {
                        target.bind_agent = base.bind_agent.clone();
                    }
                } else {
                    target.builtin = false;
                    target.bind_agent = None;
                }
            }
        }
        self.targets = ensure_builtin_targets(
            std::mem::take(&mut self.targets),
            &legacy_ips,
            &legacy_regions,
        );
        self.guarded_agents = clean_guarded_agents(&self.guarded_agents);

        self.interval_secs = self.interval_secs.clamp(5, 3600);
        self.trip_threshold = self.trip_threshold.clamp(1, 5);
        self.min_global_safety_score = self.min_global_safety_score.min(100);
        self.hook_freshness_ttl_secs = self.hook_freshness_ttl_secs.clamp(10, 300);
        self.burst_warn_rpm = self.burst_warn_rpm.clamp(5, 300);
        self.burst_throttle_rpm = self
            .burst_throttle_rpm
            .max(self.burst_warn_rpm.saturating_add(2))
            .clamp(7, 600);
        if self.hotkey_panic_lockdown.trim().is_empty() {
            self.hotkey_panic_lockdown = default_panic_chord();
        }
        if self.hotkey_quick_hud.trim().is_empty() {
            self.hotkey_quick_hud = default_hud_chord();
        }
        let mut clean_vaults = Vec::new();
        for mut v in std::mem::take(&mut self.vaults) {
            v.normalize();
            if is_valid_vault_id(&v.id) && !clean_vaults.iter().any(|x: &AccountVault| x.id == v.id)
            {
                clean_vaults.push(v);
            }
        }
        self.vaults = clean_vaults;
        self.proxy_host = self.proxy_host.trim().to_string();
        if self.proxy_host.is_empty() {
            self.proxy_host = default_proxy_host();
        }
        if self.proxy_port == 0 {
            self.proxy_port = default_proxy_port();
        }

        self.allowed_ips.clear();
        self.egress_region.clear();
        self.required_ip = None;
        self.connect_target = None;
        self.app_id = None;
        self.launch_on_pass = None;
        self.version = CONFIG_VERSION;
    }

    pub fn enabled_targets(&self) -> impl Iterator<Item = &Target> {
        self.targets.iter().filter(|t| t.enabled)
    }

    pub fn target(&self, id: &str) -> Option<&Target> {
        self.targets.iter().find(|t| t.id == id)
    }

    pub fn proxy_url(&self) -> String {
        let host = self.proxy_host.trim();
        if host.contains(':') && !host.starts_with('[') && !host.ends_with(']') {
            format!("http://[{}]:{}", host, self.proxy_port)
        } else {
            format!("http://{}:{}", host, self.proxy_port)
        }
    }

    pub fn clamped_interval_secs(&self) -> u64 {
        self.interval_secs.clamp(5, 3600)
    }
}

/// Sanitizes `guarded_agents`: trims/lowercases, strips unknown IDs, deduplicates in order,
/// and falls back to `["claude"]` when a non-empty input contained only invalid entries.
/// An explicit empty slice stays empty.
pub fn clean_guarded_agents(raw: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for id in raw {
        let normalized = id.trim().to_ascii_lowercase();
        if KNOWN_GUI_AGENT_IDS.contains(&normalized.as_str()) && !out.contains(&normalized) {
            out.push(normalized);
        }
    }
    if out.is_empty() && !raw.is_empty() {
        out.push("claude".into());
    }
    out
}

fn is_forbidden_probe_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_broadcast()
        || o[0] == 0
        || (o[0] == 100 && (64..=127).contains(&o[1]))
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
        || o[0] >= 240
}

fn is_forbidden_probe_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_forbidden_probe_ipv4(v4);
    }
    let seg = ip.segments();
    if seg[..6] == [0x0064, 0xff9b, 0, 0, 0, 0] {
        let v4 = Ipv4Addr::from(((u32::from(seg[6])) << 16) | u32::from(seg[7]));
        return is_forbidden_probe_ipv4(v4);
    }
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (seg[0] & 0xffc0) == 0xfe80
        || (seg[0] & 0xfe00) == 0xfc00
}

fn is_safe_target_anchor_url(raw: &str) -> bool {
    let url = raw.trim();
    if url.is_empty() || url.len() > 300 || url.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return false;
    }
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty()
        || authority.starts_with(':')
        || authority.contains('\\')
        || authority.contains('@')
    {
        return false;
    }
    let valid_port = |s: &str| {
        !s.is_empty()
            && s.bytes().all(|b| b.is_ascii_digit())
            && s.parse::<u16>().ok().is_some_and(|p| p > 0)
    };
    if authority.starts_with('[') {
        let Some(close_idx) = authority.find(']') else {
            return false;
        };
        let host_inner = &authority[1..close_idx];
        let after = &authority[close_idx + 1..];
        if !after.is_empty() && !after.strip_prefix(':').is_some_and(valid_port) {
            return false;
        }
        let Ok(v6) = host_inner.parse::<Ipv6Addr>() else {
            return false;
        };
        return !is_forbidden_probe_ipv6(v6);
    }
    if authority.contains(']') || authority.matches(':').count() > 1 {
        return false;
    }
    let host_raw = if let Some((h, p)) = authority.split_once(':') {
        if h.is_empty() || !valid_port(p) {
            return false;
        }
        h
    } else {
        authority
    };
    let host_clean = host_raw.trim_end_matches('.').to_ascii_lowercase();
    if host_clean.is_empty()
        || host_clean == "localhost"
        || host_clean.ends_with(".localhost")
        || host_clean == "local"
        || host_clean.ends_with(".local")
    {
        return false;
    }
    if let Ok(v4) = host_clean.parse::<Ipv4Addr>() {
        return !is_forbidden_probe_ipv4(v4);
    }
    if let Some(last_label) = host_clean.rsplit('.').next()
        && !last_label.is_empty()
        && (last_label.bytes().all(|b| b.is_ascii_digit()) || last_label.starts_with("0x"))
    {
        return false;
    }
    true
}

fn sanitize_migrated_targets(targets: Vec<Target>) -> Vec<Target> {
    let defaults = default_builtin_targets(&[], &[]);
    let mut out: Vec<Target> = Vec::with_capacity(targets.len());
    for mut target in targets {
        target.id = target.id.trim().to_ascii_lowercase();
        if target.id.is_empty()
            || target.id.len() > 24
            || !target
                .id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            || out.iter().any(|existing| existing.id == target.id)
        {
            continue;
        }

        target.name = target.name.trim().to_string();
        if target.name.chars().count() > 16 {
            target.name = target.name.chars().take(16).collect();
        }
        target.anchor_url = target.anchor_url.trim().to_string();
        target.timeout_secs = target.timeout_secs.clamp(3, 60);

        let mut clean_ips = Vec::new();
        for ip in &target.expect_ips {
            if let Some(norm) = normalize_ip_or_cidr(ip)
                && !clean_ips.contains(&norm)
            {
                clean_ips.push(norm);
            }
        }
        target.expect_ips = clean_ips;

        let mut clean_regions = Vec::new();
        for reg in &target.expect_regions {
            if let Some(code) = normalize_region(reg)
                && is_known_region(&code)
                && !clean_regions.contains(&code)
            {
                clean_regions.push(code);
            }
        }
        target.expect_regions = clean_regions;

        if is_builtin_target(&target.id) {
            target.builtin = true;
            if let Some(base) = defaults.iter().find(|d| d.id == target.id) {
                if target.name.is_empty() {
                    target.name = base.name.clone();
                }
                if !is_safe_target_anchor_url(&target.anchor_url) {
                    target.anchor_url = base.anchor_url.clone();
                }
                target.bind_agent = base.bind_agent.clone();
            }
        } else {
            target.builtin = false;
            target.bind_agent = None;
            if target.name.is_empty() {
                target.name = target.id.chars().take(16).collect();
            }
            if !is_safe_target_anchor_url(&target.anchor_url) {
                continue;
            }
        }
        out.push(target);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::AnchorKind;

    #[test]
    fn proxy_url_brackets_raw_ipv6_and_preserves_bracketed_or_ipv4() {
        let mut cfg = Config {
            proxy_host: "127.0.0.1".into(),
            proxy_port: 7890,
            ..Config::default()
        };
        assert_eq!(cfg.proxy_url(), "http://127.0.0.1:7890");

        cfg.proxy_host = "::1".into();
        assert_eq!(cfg.proxy_url(), "http://[::1]:7890");

        cfg.proxy_host = "[::1]".into();
        assert_eq!(cfg.proxy_url(), "http://[::1]:7890");

        cfg.proxy_host = "2001:db8::1".into();
        cfg.proxy_port = 7897;
        assert_eq!(cfg.proxy_url(), "http://[2001:db8::1]:7897");
    }

    #[test]
    fn migrates_v2_json_losslessly_to_v4() {
        let v2 = r#"{
            "proxy_host": "127.0.0.1",
            "proxy_port": 7890,
            "allowed_ips": ["198.51.100.98", " 203.0.113.0/24 "],
            "egress_region": "usa",
            "guarded_agents": ["claude", "unknown", "claude", "ChatGPT"],
            "cli_warn": false,
            "connect_target": "api.anthropic.com:443",
            "check_interval_secs": 30,
            "kill_on_fail": true,
            "quarantine_on_fail": true,
            "launch_on_pass": false,
            "close_to_tray": false,
            "auto_start_with_system": true,
            "first_run": false
        }"#;

        let outcome = Config::from_legacy_json(v2).expect("v2 config should parse");
        assert_eq!(outcome.source_version, 2);
        assert!(outcome.migrated);
        let cfg = outcome.config;
        assert_eq!(cfg.version, CONFIG_VERSION);
        assert!(!cfg.first_run);
        assert_eq!(cfg.interval_secs, 30);
        assert_eq!(cfg.cut_mode, CutMode::Off);
        assert_eq!(cfg.guarded_agents, vec!["claude", "chatgpt"]);
        assert!(!cfg.cli_warn);
        assert!(!cfg.close_to_tray);
        assert!(cfg.auto_start_with_system);
        assert!(cfg.lockdown_on_uncovered);
        for id in ["local", "claude", "codex"] {
            let t = cfg.target(id).expect(id);
            assert_eq!(t.expect_ips, vec!["198.51.100.98", "203.0.113.0/24"]);
            assert_eq!(t.expect_regions, vec!["US"]);
        }
        assert_eq!(
            cfg.target("antigravity").map(|t| t.anchor_kind),
            Some(AnchorKind::Reachability)
        );

        let reserialized = serde_json::to_string(&cfg).expect("serialize v4");
        assert!(!reserialized.contains("allowed_ips"));
        assert!(!reserialized.contains("cut_network"));
    }

    #[test]
    fn migrates_v3_cut_network_and_nics_without_silent_downgrade() {
        let v3_fw = r#"{
            "version": 3,
            "first_run": false,
            "proxy_port": 7897,
            "check_interval_secs": 20,
            "trip_threshold": 3,
            "cut_network": true,
            "disable_network_adapters": false,
            "notify": { "enabled": true, "include_egress": true },
            "targets": []
        }"#;
        let out_fw = Config::from_legacy_json(v3_fw).expect("v3 firewall config");
        assert_eq!(out_fw.source_version, 3);
        assert_eq!(out_fw.config.cut_mode, CutMode::Firewall);
        assert_eq!(out_fw.preserved_cut_mode, Some(CutMode::Firewall));
        assert_eq!(out_fw.config.proxy_port, 7897);
        assert_eq!(out_fw.config.interval_secs, 20);
        assert_eq!(out_fw.config.trip_threshold, 3);
        assert!(out_fw.config.notify.include_egress);

        let v3_nics = r#"{
            "version": 3,
            "first_run": false,
            "cut_network": true,
            "disable_network_adapters": true
        }"#;
        let out_nics = Config::from_legacy_json(v3_nics).expect("v3 nics config");
        assert_eq!(out_nics.config.cut_mode, CutMode::Nics);
        assert_eq!(out_nics.preserved_cut_mode, Some(CutMode::Nics));
    }

    #[test]
    fn v3_custom_targets_and_defaults_preserved_losslessly() {
        let v3 = r#"{
            "version": 3,
            "first_run": false,
            "proxy_host": "127.0.0.1",
            "proxy_port": 7890,
            "targets": [
                {
                    "id": "claude",
                    "name": "Claude 出口",
                    "builtin": true,
                    "enabled": true,
                    "anchor_url": "https://claude.ai/cdn-cgi/trace",
                    "anchor_kind": "trace",
                    "expect_ips": ["198.51.100.98"],
                    "expect_regions": ["US"],
                    "timeout_secs": 15,
                    "bind_agent": "claude"
                },
                {
                    "id": "custom1",
                    "name": "Custom",
                    "builtin": false,
                    "enabled": true,
                    "anchor_url": "https://example.com/ip",
                    "anchor_kind": "json_ip",
                    "expect_ips": ["203.0.113.0/24"],
                    "expect_regions": [],
                    "timeout_secs": 10
                }
            ]
        }"#;
        let cfg = Config::from_json_str(v3).expect("parse v3");
        assert_eq!(cfg.version, CONFIG_VERSION);
        assert_eq!(cfg.targets.len(), 5);
        assert_eq!(
            cfg.target("custom1").unwrap().expect_ips,
            vec!["203.0.113.0/24"]
        );
        assert!(cfg.target("local").is_some_and(|t| !t.enabled));
        assert!(!cfg.notify.include_egress);
    }

    #[test]
    fn clamps_bounds_and_cleans_agents() {
        let raw = r#"{"proxy_host":"  ","proxy_port":0,"interval_secs":1,"trip_threshold":99,"guarded_agents":["nope"]}"#;
        let cfg = Config::from_json_str(raw).expect("parse");
        assert_eq!(cfg.proxy_host, "127.0.0.1");
        assert_eq!(cfg.proxy_port, 7890);
        assert_eq!(cfg.interval_secs, 5);
        assert_eq!(cfg.trip_threshold, 5);
        assert_eq!(cfg.guarded_agents, vec!["claude"]);
        assert!(cfg.kill_cli_on_fail);
        assert!(clean_guarded_agents(&[]).is_empty());
        assert_eq!(
            clean_guarded_agents(&[
                "Claude".into(),
                "legacy-ide".into(),
                "antigravity".into(),
                "chatgpt".into(),
                "claude".into(),
            ]),
            vec!["claude", "antigravity", "chatgpt"]
        );
        assert_eq!(KNOWN_GUI_AGENT_IDS, ["claude", "chatgpt", "antigravity"]);
        assert_eq!(KNOWN_CLI_AGENT_IDS, ["claude-code", "codex"]);
    }

    #[test]
    fn kill_cli_on_fail_defaults_true_and_roundtrips() {
        let def = Config::default();
        assert!(def.kill_cli_on_fail);
        assert!(def.suppress_trip_when_ip_unchanged);
        assert!(!def.monitor_only);

        let omitted: Config = serde_json::from_str(r#"{"version":4}"#).expect("omitted field");
        assert!(omitted.kill_cli_on_fail);
        assert!(omitted.suppress_trip_when_ip_unchanged);
        assert!(!omitted.monitor_only);

        let disabled: Config = serde_json::from_str(
            r#"{"version":4,"kill_cli_on_fail":false,"suppress_trip_when_ip_unchanged":false,"monitor_only":true}"#,
        )
        .expect("custom breaker flags");
        assert!(!disabled.kill_cli_on_fail);
        assert!(!disabled.suppress_trip_when_ip_unchanged);
        assert!(disabled.monitor_only);
        let json = serde_json::to_string(&disabled).expect("serialize");
        let back = Config::from_json_str(&json).expect("roundtrip");
        assert!(!back.kill_cli_on_fail);
        assert!(!back.suppress_trip_when_ip_unchanged);
        assert!(back.monitor_only);
    }

    #[test]
    fn rejects_empty_or_corrupt_json_and_roundtrips_v4() {
        assert!(Config::from_legacy_json("").is_err());
        assert!(Config::from_legacy_json("[]").is_err());
        assert!(Config::from_legacy_json("{bad").is_err());

        let cfg = Config {
            first_run: false,
            privacy_mask_ip: true,
            theme_mode: ThemeMode::Dark,
            preset: PolicyPreset::LooseAntiDirect,
            cut_mode: CutMode::Firewall,
            leak_trip: true,
            env_align_tz: true,
            require_antigravity_proxy: false,
            last_seen_antigravity_version: Some("44.9.1".into()),
            notify: NotifyPrefs {
                include_egress: true,
                ..Default::default()
            },
            ..Default::default()
        };

        let json = serde_json::to_string_pretty(&cfg).expect("serialize v4");
        let parsed = Config::from_json_str(&json).expect("roundtrip v4");
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn migrates_legacy_required_ip_and_keeps_empty_v2_whitelist_strict() {
        let req_ip =
            r#"{"proxy_host":"127.0.0.1","proxy_port":7890,"required_ip":"198.51.100.98"}"#;
        let cfg = Config::from_json_str(req_ip).expect("required_ip");
        assert_eq!(
            cfg.target("claude").unwrap().expect_ips,
            vec!["198.51.100.98"]
        );

        let empty = r#"{"proxy_host":"127.0.0.1","proxy_port":7890,"allowed_ips":[]}"#;
        let cfg_empty = Config::from_json_str(empty).expect("empty allowed_ips");
        assert!(cfg_empty.target("claude").unwrap().expect_ips.is_empty());
        assert!(
            cfg_empty
                .target("claude")
                .unwrap()
                .expect_regions
                .is_empty()
        );
    }

    #[test]
    fn migrate_preserves_explicit_cut_mode_off_and_sanitizes_ssrf_targets() {
        let mixed_cut = r#"{
            "version": 4,
            "first_run": false,
            "cut_mode": "off",
            "cut_network": true,
            "disable_network_adapters": true,
            "targets": [
                {
                    "id": " claude ",
                    "name": "Claude",
                    "builtin": false,
                    "enabled": true,
                    "anchor_url": "http://127.0.0.1:9090/ssrf",
                    "anchor_kind": "auto",
                    "expect_ips": ["198.51.100.42/24"],
                    "expect_regions": ["usa", "XX", "ZZ"],
                    "timeout_secs": 999,
                    "bind_agent": "chatgpt"
                },
                {
                    "id": "bad_ssrf",
                    "name": "Bad",
                    "builtin": false,
                    "enabled": true,
                    "anchor_url": "https://192.168.1.1/ip",
                    "anchor_kind": "json_ip",
                    "expect_ips": [],
                    "expect_regions": ["US"],
                    "timeout_secs": 1
                }
            ]
        }"#;
        let cfg = Config::from_json_str(mixed_cut).expect("migrate mixed cut_mode");
        assert_eq!(cfg.cut_mode, CutMode::Off);
        let claude = cfg.target("claude").expect("claude builtin");
        assert!(claude.builtin);
        assert_eq!(claude.anchor_url, "https://claude.ai/cdn-cgi/trace");
        assert_eq!(claude.bind_agent.as_deref(), Some("claude"));
        assert_eq!(claude.timeout_secs, 60);
        assert_eq!(claude.expect_ips, vec!["198.51.100.0/24"]);
        assert_eq!(claude.expect_regions, vec!["US"]);
        assert!(cfg.target("bad_ssrf").is_none());
    }
}
