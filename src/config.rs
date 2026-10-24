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
    #[cfg(target_os = "macos")]
    {
        crate::macos::data_dir()
    }
    #[cfg(not(target_os = "macos"))]
    let base = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    #[cfg(not(target_os = "macos"))]
    base.join("ClaudeGuard")
}

/// 仅 macOS 验收测试使用；Windows 侧统一走 `load_from`/`save_to`。
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
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
    /// R14 / D5：通知正文是否附带出口 IP/地区。默认脱敏。
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
    /// v3.7：接入路径检查（系统代理关 + 无 TUN 视为未接入，计入熔断）。
    #[serde(default = "default_true")]
    pub enforce_access_path: bool,
    /// v3.9：未接入时自动维持守护对象的出站防火墙封锁（兜底，接入后自动解除）。
    #[serde(default = "default_true")]
    pub lockdown_on_uncovered: bool,
    /// D1：新装默认不做全局断网（应用级隔离为主）；旧配置里的显式值原样保留。
    #[serde(default)]
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
    /// v3.12：观察被守护应用的直连泄露（系统代理模式下比对真实连接）。
    #[serde(default = "default_true")]
    pub leak_watch: bool,
    /// v3.12：发现直连即熔断。默认关闭——先告警，确认无误报再让用户自己开。
    #[serde(default)]
    pub leak_trip: bool,
    /// v3.12：环境一致性检查（系统时区/区域 vs 出口，只提示不熔断）。
    #[serde(default = "default_true")]
    pub env_check: bool,
    /// v3.12：把系统时区对齐到出口（退出/恢复时还原）。
    #[serde(default)]
    pub env_align_tz: bool,
    /// v3.12：把 Windows 默认位置对齐到出口（退出/恢复时还原）。
    #[serde(default)]
    pub env_align_location: bool,
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
            version: CONFIG_VERSION,
            proxy_host: default_proxy_host(),
            proxy_port: default_proxy_port(),
            targets: targets::default_targets(&[], &[]),
            check_interval_secs: default_interval(),
            trip_threshold: default_threshold(),
            enforce_access_path: true,
            lockdown_on_uncovered: true,
            cut_network: false,
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
            leak_watch: true,
            leak_trip: false,
            env_check: true,
            env_align_tz: false,
            env_align_location: false,
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

/// 当前配置版本。v3.10/D1 起为 4：新装默认 `cut_network=false`（应用级隔离为主），
/// 旧配置保留用户原有档位、不静默改档。
pub const CONFIG_VERSION: u32 = 4;

impl Config {
    pub fn load() -> Self {
        Self::load_from(&config_dir())
    }

    /// 只读加载：不写回任何文件（`--check` 等 CLI 与 GUI 共用）。
    pub fn load_from(dir: &std::path::Path) -> Self {
        let path = dir.join("config.json");
        let mut cfg = match std::fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str::<Config>(&text) {
                Ok(cfg) => cfg,
                Err(err) => {
                    backup_corrupt_in(dir, &text);
                    guard::log_line(&format!(
                        "config: 配置无法解析（{err}），已备份并重置为默认"
                    ));
                    Self::default()
                }
            },
            Err(_) => Self::default(),
        };
        cfg.migrate();
        // v3.10 R11：加载是只读路径（`--check` 等 CLI 也走它），绝不在这里写文件。
        // 迁移是幂等的，真正的落盘发生在用户下一次成功保存时。
        cfg
    }

    /// D1：升级到 v3.10 前，把旧配置原样备份一份，便于回滚。
    ///
    /// 只在**应用启动时**调用（`--check` 等只读路径不碰磁盘，见不变量 7）。
    /// 已有备份就不覆盖——那份才是真正的"升级前"状态。
    /// 返回备份文件路径（本次新建时）或 `None`（无需备份/已存在/读不到）。
    pub fn backup_legacy(dir: &std::path::Path) -> Option<std::path::PathBuf> {
        let src = dir.join("config.json");
        let text = std::fs::read_to_string(&src).ok()?;
        let value: serde_json::Value = serde_json::from_str(&text).ok()?;
        let version = value.get("version").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        if version >= CONFIG_VERSION {
            return None;
        }
        let dst = dir.join(format!("config.v{version}.bak.json"));
        if dst.exists() {
            return None;
        }
        std::fs::create_dir_all(dir).ok()?;
        match std::fs::write(&dst, text.as_bytes()) {
            Ok(()) => {
                guard::log_line(&format!(
                    "config: 已备份 v{version} 配置到 {}",
                    dst.display()
                ));
                Some(dst)
            }
            Err(err) => {
                guard::log_line(&format!("config: 备份旧配置失败：{err}"));
                None
            }
        }
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
        self.version = CONFIG_VERSION;
    }

    /// 原子写入配置。失败时返回原因，调用方**不得**把改动提交到内存
    /// （CONTRACT-v3.10 不变量 7：保存失败不改变内存配置，也不得提示"已保存"）。
    pub fn save(&self) -> Result<(), String> {
        self.save_to(&config_dir())
    }

    /// 原子写入指定目录（`save` 的实现，测试与只读路径复用）。
    pub fn save_to(&self, dir: &std::path::Path) -> Result<(), String> {
        let dir = dir.to_path_buf();
        std::fs::create_dir_all(&dir).map_err(|err| {
            guard::log_line(&format!("config: 无法创建配置目录：{err}"));
            format!("无法创建配置目录 {}：{err}", dir.display())
        })?;
        let text = serde_json::to_string_pretty(self).map_err(|err| {
            guard::log_line(&format!("config: 序列化失败：{err}"));
            format!("配置序列化失败：{err}")
        })?;
        let tmp = dir.join("config.json.tmp");
        std::fs::write(&tmp, text.as_bytes()).map_err(|err| {
            guard::log_line(&format!("config: 写入临时文件失败：{err}"));
            format!("无法写入 {}：{err}", tmp.display())
        })?;
        let target = dir.join("config.json");
        std::fs::rename(&tmp, &target).map_err(|err| {
            let _ = std::fs::remove_file(&tmp);
            guard::log_line(&format!("config: 保存失败（rename）：{err}"));
            format!("无法替换 {}：{err}", target.display())
        })
    }

    /// 仅 macOS 分支使用（Windows 走 `access::resolve` 的系统代理判定）。
    #[cfg_attr(target_os = "windows", allow(dead_code))]
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
        next.save()?;
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

fn backup_corrupt_in(dir: &std::path::Path, text: &str) {
    if std::fs::create_dir_all(dir).is_err() {
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
    #[test]
    fn load_from_is_read_only_even_when_migrating() {
        let dir = std::env::temp_dir().join("cg-load-readonly");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("fixture");
        let file = dir.join("config.json");
        // v2 时代字段：allowed_ips 需要迁移，但加载不得写回。
        let legacy = r#"{"version":3,"allowed_ips":["127.0.0.1"],"first_run":false}"#;
        std::fs::write(&file, legacy).expect("fixture");
        let before = std::fs::read_to_string(&file).expect("read");
        let cfg = super::Config::load_from(&dir);
        assert!(!cfg.first_run, "应读到既有配置");
        // 默认四目标里"本机出口"默认关闭，迁移后仍是 3 个启用。
        assert_eq!(cfg.targets.len(), 4);
        assert_eq!(cfg.targets.iter().filter(|t| t.enabled).count(), 3);
        assert!(
            cfg.target("local").map(|t| !t.enabled).unwrap_or(false),
            "本机出口默认关闭"
        );
        // v2 的 allowed_ips 应迁进 Claude 目标的白名单。
        assert_eq!(
            cfg.target("claude").map(|t| t.expect_ips.clone()),
            Some(vec!["127.0.0.1".to_string()])
        );
        let after = std::fs::read_to_string(&file).expect("read");
        assert_eq!(before, after, "加载（含迁移）不得改动磁盘文件");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_to_reports_failure_without_writing() {
        let cfg = super::Config::default();
        // 目标目录是一个已存在文件的下级 → create_dir_all 必然失败。
        let dir = std::env::temp_dir().join("cg-save-fail");
        let _ = std::fs::create_dir_all(&dir);
        let blocker = dir.join("blocker");
        std::fs::write(&blocker, b"x").expect("fixture");
        let bad = blocker.join("sub");
        let err = cfg.save_to(&bad).expect_err("必须报告保存失败");
        assert!(err.contains("无法创建配置目录"), "错误应说明原因：{err}");
        assert!(!bad.join("config.json").exists(), "失败时不得留下配置文件");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_to_writes_atomically_and_leaves_no_temp_file() {
        let cfg = super::Config::default();
        let dir = std::env::temp_dir().join("cg-save-ok");
        let _ = std::fs::remove_dir_all(&dir);
        cfg.save_to(&dir).expect("应保存成功");
        assert!(dir.join("config.json").exists());
        assert!(!dir.join("config.json.tmp").exists(), "临时文件必须被移走");
        let text = std::fs::read_to_string(dir.join("config.json")).expect("读回");
        assert!(text.contains("\"first_run\""), "落盘内容应是完整配置");
        let _ = std::fs::remove_dir_all(&dir);
    }

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
        assert_eq!(cfg.version, CONFIG_VERSION);
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
        // v3.9 新字段对旧配置缺省=true（未接入即封锁是安全默认）。
        assert!(cfg.lockdown_on_uncovered);
    }

    #[test]
    fn lockdown_default_true_for_older_v3_json() {
        let text = r#"{"proxy_host":"127.0.0.1","proxy_port":7890,"targets":[]}"#;
        let cfg: Config = serde_json::from_str(text).unwrap();
        assert!(cfg.lockdown_on_uncovered);
        let def = Config::default();
        assert!(def.lockdown_on_uncovered);
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

    /// D1：新装默认不做全局断网；显式打开后按"防火墙/禁用网卡"两档。
    #[test]
    fn cut_mode_respects_flags() {
        let mut cfg = Config::default();
        assert_eq!(cfg.cut_mode(), CutMode::Off, "新装默认不全局断网");
        cfg.cut_network = true;
        assert_eq!(cfg.cut_mode(), CutMode::Firewall);
        cfg.disable_network_adapters = true;
        assert_eq!(cfg.cut_mode(), CutMode::Nics);
        cfg.cut_network = false;
        assert_eq!(cfg.cut_mode(), CutMode::Off);
    }

    /// D1 备份：v3 配置启动时留一份 `config.v3.bak.json`，且不覆盖已有备份。
    #[test]
    fn legacy_backup_is_created_once_and_never_overwritten() {
        let dir = std::env::temp_dir().join("cg-cfg-backup-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        std::fs::write(&path, br#"{"version":3,"proxy_port":7890}"#).unwrap();

        let first = Config::backup_legacy(&dir).expect("v3 配置应被备份");
        assert!(first.exists());
        assert_eq!(
            std::fs::read(&first).unwrap(),
            br#"{"version":3,"proxy_port":7890}"#
        );

        // 第二次调用（用户已经改过配置）不得覆盖那份"升级前"的快照
        std::fs::write(&path, br#"{"version":3,"proxy_port":9999}"#).unwrap();
        assert!(Config::backup_legacy(&dir).is_none(), "已有备份不覆盖");
        assert_eq!(
            std::fs::read(&first).unwrap(),
            br#"{"version":3,"proxy_port":7890}"#
        );

        // 已是当前版本：不需要备份
        std::fs::write(&path, br#"{"version":4,"proxy_port":7890}"#).unwrap();
        assert!(Config::backup_legacy(&dir).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 旧配置里显式写着 `cut_network: true` 时，迁移不得静默改成 false（D1 不改档）。
    #[test]
    fn legacy_cut_network_true_survives_migration() {
        let json = r#"{"version":3,"proxy_host":"127.0.0.1","proxy_port":7890,
            "cut_network":true,"first_run":false}"#;
        let mut cfg: Config = serde_json::from_str(json).unwrap();
        cfg.migrate();
        assert!(cfg.cut_network, "用户原有档位必须保留");
        assert_eq!(cfg.cut_mode(), CutMode::Firewall);
        assert_eq!(cfg.version, CONFIG_VERSION);
    }

    /// 缺字段的老文件（v2）迁移后按新装默认值走：不全局断网。
    #[test]
    fn missing_cut_network_defaults_to_off() {
        let json = r#"{"version":2,"proxy_host":"127.0.0.1","proxy_port":7890}"#;
        let mut cfg: Config = serde_json::from_str(json).unwrap();
        cfg.migrate();
        assert!(!cfg.cut_network);
        assert_eq!(cfg.cut_mode(), CutMode::Off);
    }
}
