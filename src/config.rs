//! v3 配置：读取、原子保存、v2 迁移与校验。
//!
//! `config.json` 只落 v3 字段；v2 的 `allowed_ips` / `egress_region` /
//! `required_ip` 等旧字段仅用于反序列化后迁移，迁移完成即清空且不再序列化。

use crate::guard;
use crate::model::{default_true, normalize_ip, normalize_region, CutMode, Target};
use crate::targets;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub fn config_dir() -> PathBuf {
    let base = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("ClaudeGuard")
}

pub fn config_path() -> PathBuf {
    config_dir().join("config.json")
}

fn default_proxy_host() -> String {
    "127.0.0.1".into()
}
fn default_proxy_port() -> u16 {
    7890
}
fn default_interval() -> u64 {
    15
}
fn default_threshold() -> u32 {
    2
}
fn default_agents() -> Vec<String> {
    vec!["claude".into()]
}

/// 桌面通知分类开关（总开关 + 五类）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
        }
    }
}

impl NotifyPrefs {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub version: u32,
    #[serde(default = "default_proxy_host")]
    pub proxy_host: String,
    #[serde(default = "default_proxy_port")]
    pub proxy_port: u16,
    #[serde(default)]
    pub targets: Vec<Target>,
    #[serde(default = "default_interval")]
    pub check_interval_secs: u64,
    #[serde(default = "default_threshold")]
    pub trip_threshold: u32,
    #[serde(default = "default_true")]
    pub cut_network: bool,
    #[serde(default)]
    pub disable_network_adapters: bool,
    #[serde(default = "default_true")]
    pub kill_on_fail: bool,
    #[serde(default = "default_true")]
    pub quarantine_on_fail: bool,
    #[serde(default = "default_agents")]
    pub guarded_agents: Vec<String>,
    #[serde(default = "default_true")]
    pub cli_warn: bool,
    /// Claude 桌面端退出后自动清理残留进程（桌面家族 + 孤儿 CLI）
    #[serde(default = "default_true")]
    pub sweep_on_exit: bool,
    #[serde(default = "default_true")]
    pub close_to_tray: bool,
    #[serde(default)]
    pub auto_start_with_system: bool,
    #[serde(default)]
    pub notify: NotifyPrefs,
    /// 后台每 6 小时静默检查 ClaudeGuard 自身新版本
    #[serde(default = "default_true")]
    pub auto_upd_check: bool,
    #[serde(default = "default_true")]
    pub first_run: bool,

    // ---- v2 旧字段：只读迁移用，不落盘 ----
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
            version: 3,
            proxy_host: default_proxy_host(),
            proxy_port: default_proxy_port(),
            targets: targets::default_targets(&[], &[]),
            check_interval_secs: default_interval(),
            trip_threshold: default_threshold(),
            cut_network: true,
            disable_network_adapters: false,
            kill_on_fail: true,
            quarantine_on_fail: true,
            guarded_agents: default_agents(),
            cli_warn: true,
            sweep_on_exit: true,
            close_to_tray: true,
            auto_start_with_system: false,
            notify: NotifyPrefs::default(),
            auto_upd_check: true,
            first_run: true,
            allowed_ips: Vec::new(),
            egress_region: String::new(),
            required_ip: None,
            connect_target: None,
            app_id: None,
            launch_on_pass: None,
        }
    }
}

impl Config {
    pub fn load() -> Self {
        let path = config_path();
        let mut cfg = match std::fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str::<Config>(&text) {
                Ok(cfg) => cfg,
                Err(err) => {
                    backup_corrupt(&text);
                    guard::log_line(&format!(
                        "config: 配置无法解析（{err}），已备份并重置为默认"
                    ));
                    Self::default()
                }
            },
            Err(_) => Self::default(),
        };
        cfg.migrate();
        cfg.save();
        cfg
    }

    /// v2 → v3 迁移：旧白名单写进内置目标，旧字段清空，跨字段钳制。
    pub fn migrate(&mut self) {
        let mut legacy_ips = std::mem::take(&mut self.allowed_ips);
        if legacy_ips.is_empty() {
            if let Some(ip) = self.required_ip.take() {
                legacy_ips.push(ip);
            }
        }
        let legacy_ips: Vec<String> = legacy_ips
            .iter()
            .filter_map(|ip| normalize_ip(ip))
            .collect();
        let legacy_region = normalize_region(&self.egress_region).unwrap_or_default();

        let legacy_regions: Vec<String> = if legacy_region.is_empty() {
            Vec::new()
        } else {
            vec![legacy_region.clone()]
        };

        if self.targets.is_empty() {
            self.targets = targets::default_targets(&legacy_ips, &legacy_regions);
        }
        self.targets = targets::ensure_builtins(self.targets.clone(), &legacy_ips, &legacy_regions);
        self.guarded_agents = clean_guarded(&self.guarded_agents);

        self.check_interval_secs = self.check_interval_secs.clamp(5, 3600);
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
        self.version = 3;
    }

    pub fn save(&self) -> bool {
        let dir = config_dir();
        if std::fs::create_dir_all(&dir).is_err() {
            return false;
        }
        let text = match serde_json::to_string_pretty(self) {
            Ok(text) => text,
            Err(err) => {
                guard::log_line(&format!("config: 序列化失败：{err}"));
                return false;
            }
        };
        let tmp = dir.join("config.json.tmp");
        if std::fs::write(&tmp, text.as_bytes()).is_err() {
            return false;
        }
        let ok = std::fs::rename(&tmp, config_path()).is_ok();
        if !ok {
            let _ = std::fs::remove_file(&tmp);
            guard::log_line("config: 保存失败（rename）");
        }
        ok
    }

    pub fn proxy_url(&self) -> String {
        format!("http://{}:{}", self.proxy_host, self.proxy_port)
    }

    pub fn cut_mode(&self) -> CutMode {
        if !self.cut_network {
            CutMode::Off
        } else if self.disable_network_adapters {
            CutMode::Nics
        } else {
            CutMode::Firewall
        }
    }

    pub fn enabled_targets(&self) -> impl Iterator<Item = &Target> {
        self.targets.iter().filter(|t| t.enabled)
    }

    pub fn target(&self, id: &str) -> Option<&Target> {
        self.targets.iter().find(|t| t.id == id)
    }

    pub fn interval_secs(&self) -> u64 {
        self.check_interval_secs.clamp(5, 3600)
    }

    /// 把 UI 提交的部分字段深合并进现有配置并保存（未知字段忽略、数值重新钳制）。
    pub fn apply_patch(&self, patch: &serde_json::Value) -> Result<Config, String> {
        let base = serde_json::to_value(self).map_err(|err| err.to_string())?;
        let merged = deep_merge(base, patch.clone());
        let mut next: Config =
            serde_json::from_value(merged).map_err(|err| format!("设置字段无效：{err}"))?;
        next.migrate();
        next.save();
        Ok(next)
    }
}

/// 递归合并两个 JSON 值：对象按键合并，其余以 patch 为准。
fn deep_merge(base: serde_json::Value, patch: serde_json::Value) -> serde_json::Value {
    match (base, patch) {
        (serde_json::Value::Object(mut base_map), serde_json::Value::Object(patch_map)) => {
            for (key, value) in patch_map {
                match base_map.get_mut(&key) {
                    Some(slot) => {
                        let current = slot.take();
                        *slot = deep_merge(current, value);
                    }
                    None => {
                        base_map.insert(key, value);
                    }
                }
            }
            serde_json::Value::Object(base_map)
        }
        (_, patch) => patch,
    }
}

fn backup_corrupt(text: &str) {
    let dir = config_dir();
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let stamp = crate::model::now();
    let path = dir.join(format!("config.json.bak-{stamp}"));
    let _ = std::fs::write(path, text.as_bytes());
}

/// 清洗守护对象：去未知、去重、保留顺序；全垃圾时回填 claude；显式空列表尊重用户。
pub fn clean_guarded(raw: &[String]) -> Vec<String> {
    let known = guard::agent_ids();
    let mut out: Vec<String> = Vec::new();
    for id in raw {
        let id = id.trim().to_ascii_lowercase();
        if known.contains(&id.as_str()) && !out.contains(&id) {
            out.push(id);
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

    fn v2_json() -> &'static str {
        r#"{
            "proxy_host": "127.0.0.1",
            "proxy_port": 7890,
            "allowed_ips": ["204.1.100.98", " 198.51.100.7 "],
            "egress_region": "us",
            "guarded_agents": ["claude", "foo", "claude", "chatgpt"],
            "cli_warn": false,
            "connect_target": "api.anthropic.com:443",
            "app_id": "",
            "check_interval_secs": 15,
            "kill_on_fail": true,
            "quarantine_on_fail": true,
            "launch_on_pass": false,
            "close_to_tray": true,
            "auto_start_with_system": false,
            "first_run": false
        }"#
    }

    #[test]
    fn migrates_v2_whitelist_into_builtin_targets() {
        let mut cfg: Config = serde_json::from_str(v2_json()).unwrap();
        assert!(cfg.targets.is_empty());
        cfg.migrate();
        assert_eq!(cfg.version, 3);
        assert!(cfg.targets.len() >= 4);
        for id in ["local", "claude", "codex"] {
            let t = cfg.target(id).expect(id);
            assert_eq!(t.expect_ips, vec!["204.1.100.98", "198.51.100.7"]);
            assert_eq!(t.expect_regions, vec!["US"]);
        }
        let anti = cfg.target("antigravity").unwrap();
        assert!(anti.expect_ips.is_empty());
        assert_eq!(anti.anchor_kind, crate::model::AnchorKind::Reachability);
        assert!(cfg.allowed_ips.is_empty());
        assert_eq!(cfg.guarded_agents, vec!["claude", "chatgpt"]);
        assert!(!cfg.first_run);
    }

    #[test]
    fn migrates_legacy_required_ip() {
        let text = r#"{"proxy_host":"127.0.0.1","proxy_port":7890,"required_ip":"204.1.100.98"}"#;
        let mut cfg: Config = serde_json::from_str(text).unwrap();
        cfg.migrate();
        assert_eq!(
            cfg.target("claude").unwrap().expect_ips,
            vec!["204.1.100.98"]
        );
    }

    #[test]
    fn empty_v2_whitelist_stays_strict() {
        let text = r#"{"proxy_host":"127.0.0.1","proxy_port":7890,"allowed_ips":[]}"#;
        let mut cfg: Config = serde_json::from_str(text).unwrap();
        cfg.migrate();
        for id in ["local", "claude", "codex"] {
            let t = cfg.target(id).unwrap();
            assert!(t.expect_ips.is_empty() && t.expect_regions.is_empty());
        }
    }

    #[test]
    fn cleans_guarded_agents() {
        assert_eq!(clean_guarded(&["claude".into()]), vec!["claude"]);
        assert_eq!(
            clean_guarded(&["ChatGPT".into(), "chatgpt".into(), "x".into()]),
            vec!["chatgpt"]
        );
        assert_eq!(clean_guarded(&["nope".into()]), vec!["claude"]);
        assert!(clean_guarded(&[]).is_empty());
    }

    #[test]
    fn clamps_numbers_and_fills_proxy() {
        let text =
            r#"{"proxy_host":"  ","proxy_port":0,"check_interval_secs":1,"trip_threshold":9}"#;
        let mut cfg: Config = serde_json::from_str(text).unwrap();
        cfg.migrate();
        assert_eq!(cfg.proxy_host, "127.0.0.1");
        assert_eq!(cfg.proxy_port, 7890);
        assert_eq!(cfg.check_interval_secs, 5);
        assert_eq!(cfg.trip_threshold, 5);
    }

    #[test]
    fn cut_mode_respects_flags() {
        let mut cfg = Config::default();
        assert_eq!(cfg.cut_mode(), CutMode::Firewall);
        cfg.disable_network_adapters = true;
        assert_eq!(cfg.cut_mode(), CutMode::Nics);
        cfg.cut_network = false;
        assert_eq!(cfg.cut_mode(), CutMode::Off);
    }
}
