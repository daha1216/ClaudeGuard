use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "snake_case")]
pub struct Config {
    pub proxy_host: String,
    pub proxy_port: u16,
    pub required_ip: String,
    pub connect_target: String,
    /// AppUserModelId of the Claude UWP app
    pub app_id: String,
    pub check_interval_secs: u64,
    pub kill_on_fail: bool,
    pub quarantine_on_fail: bool,
    /// auto-launch Claude once when checks first pass after app start
    pub launch_on_pass: bool,
    pub close_to_tray: bool,
    pub auto_start_with_system: bool,
    pub first_run: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            proxy_host: "127.0.0.1".into(),
            proxy_port: 7890,
            required_ip: "204.1.100.98".into(),
            connect_target: "api.anthropic.com:443".into(),
            app_id: "Claude_pzs8sxrjxfjjc!Claude".into(),
            check_interval_secs: 15,
            kill_on_fail: true,
            quarantine_on_fail: true,
            launch_on_pass: true,
            close_to_tray: true,
            auto_start_with_system: false,
            first_run: true,
        }
    }
}

pub fn config_dir() -> PathBuf {
    let base = std::env::var("APPDATA").unwrap_or_else(|_| ".".into());
    PathBuf::from(base).join("ClaudeGuard")
}

pub fn config_path() -> PathBuf {
    config_dir().join("config.json")
}

impl Config {
    pub fn load() -> Self {
        let p = config_path();
        if let Ok(text) = fs::read_to_string(&p) {
            if let Ok(cfg) = serde_json::from_str::<Config>(&text) {
                return cfg;
            }
        }
        Self::default()
    }

    pub fn save(&self) -> std::io::Result<()> {
        let dir = config_dir();
        fs::create_dir_all(&dir)?;
        let text = serde_json::to_string_pretty(self).unwrap_or_default();
        // write via temp + rename for atomicity
        let tmp = dir.join("config.json.tmp");
        fs::write(&tmp, text)?;
        fs::rename(&tmp, config_path())
    }
}
