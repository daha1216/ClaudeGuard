//! v4 configuration schema and lossless v2/v3 JSON migration parser.

use crate::model::{
    CutMode, PolicyPreset, Target, ThemeMode, default_builtin_targets, default_true,
    ensure_builtin_targets, normalize_ip_or_cidr, normalize_region,
};
use serde::{Deserialize, Serialize};

/// Current config schema version (v4).
pub const CONFIG_VERSION: u32 = 4;

/// Known GUI agent identifiers that may appear in `guarded_agents`.
pub const KNOWN_GUI_AGENT_IDS: [&str; 3] = ["claude", "chatgpt", "antigravity"];

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
    #[serde(default)]
    pub last_seen_antigravity_version: Option<String>,

    // ---- Legacy v2/v3 fields: read-only migration inputs, never serialized in v4 ----
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
            last_seen_antigravity_version: None,
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

        if !has_explicit_cut_mode && let Some(cut_net) = cfg.legacy_cut_network {
            let mapped = if !cut_net {
                CutMode::Off
            } else if cfg.legacy_disable_network_adapters.unwrap_or(false) {
                CutMode::Nics
            } else {
                CutMode::Firewall
            };
            cfg.cut_mode = mapped;
            if mapped != CutMode::Off {
                preserved_cut_mode = Some(mapped);
                notes.push(format!("已无损保留旧配置断网档位：{}", mapped.label()));
            }
        }

        if has_v2_fields {
            notes.push("已将 v2 白名单字段迁移至目标列表".to_string());
        }
        if obj.contains_key("check_interval_secs") && !obj.contains_key("interval_secs") {
            notes.push("已将 check_interval_secs 映射到 interval_secs".to_string());
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
        let legacy_region = normalize_region(&self.egress_region).unwrap_or_default();
        let legacy_regions: Vec<String> = if legacy_region.is_empty() {
            Vec::new()
        } else {
            vec![legacy_region]
        };

        if self.targets.is_empty() {
            self.targets = default_builtin_targets(&legacy_ips, &legacy_regions);
        }
        self.targets = ensure_builtin_targets(
            std::mem::take(&mut self.targets),
            &legacy_ips,
            &legacy_regions,
        );
        self.guarded_agents = clean_guarded_agents(&self.guarded_agents);

        self.interval_secs = self.interval_secs.clamp(5, 3600);
        self.trip_threshold = self.trip_threshold.clamp(1, 5);
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
        format!("http://{}:{}", self.proxy_host, self.proxy_port)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::AnchorKind;

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
        assert_eq!(cfg.version, 4);
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
    }

    #[test]
    fn kill_cli_on_fail_defaults_true_and_roundtrips() {
        let def = Config::default();
        assert!(def.kill_cli_on_fail);

        let omitted: Config = serde_json::from_str(r#"{"version":4}"#).expect("omitted field");
        assert!(omitted.kill_cli_on_fail);

        let disabled: Config =
            serde_json::from_str(r#"{"version":4,"kill_cli_on_fail":false}"#).expect("false");
        assert!(!disabled.kill_cli_on_fail);
        let json = serde_json::to_string(&disabled).expect("serialize");
        let back = Config::from_json_str(&json).expect("roundtrip");
        assert!(!back.kill_cli_on_fail);
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
}
