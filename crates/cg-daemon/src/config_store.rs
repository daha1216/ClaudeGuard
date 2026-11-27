//! Atomic configuration persistence (`config.json`) with read-back verification (`CONTRACT` §3.6 & R11).

use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

use cg_core::targets;
use cg_protocol::{Config, MigrationOutcome, CONFIG_VERSION};

use crate::protocol::now_unix_secs;

pub const CONFIG_FILE: &str = "config.json";

/// Result of read-only config loading.
#[derive(Clone, Debug)]
pub enum LoadedConfig {
    NotFound,
    Loaded(Box<MigrationOutcome>),
    Corrupt { error: String, raw: String },
}

/// Atomic reader/writer for `config.json` inside `data_dir`.
#[derive(Clone, Debug)]
pub struct ConfigStore {
    dir: PathBuf,
}

/// Validates `targets` against `cg_core::targets::validate`, allowing empty IP/region allowlists
/// ONLY while `first_run == true` (pre-onboarding `Lifecycle::Unconfigured`), while still enforcing
/// all built-in target presence, URL/SSRF checks, ID uniqueness, and syntax validation.
pub fn validate_targets_for_config(
    targets: Vec<cg_protocol::Target>,
    first_run: bool,
) -> Result<Vec<cg_protocol::Target>, String> {
    if !first_run {
        return targets::validate(targets);
    }

    for id in targets::BUILTIN_IDS {
        if !targets.iter().any(|t| t.id.trim().eq_ignore_ascii_case(id)) {
            return Err(format!("缺少内置目标 {id}，请点“恢复默认”"));
        }
    }

    let mut empty_allowlist_ids: Vec<String> = Vec::new();
    let mut staged = targets;
    for t in &mut staged {
        let id_norm = t.id.trim().to_ascii_lowercase();
        let has_ip = t.expect_ips.iter().any(|s| !s.trim().is_empty());
        let has_region = t.expect_regions.iter().any(|s| !s.trim().is_empty());
        if t.enabled
            && t.anchor_kind != cg_protocol::AnchorKind::Reachability
            && !has_ip
            && !has_region
        {
            empty_allowlist_ids.push(id_norm);
            t.expect_regions = vec!["US".to_string()];
        }
    }

    let mut validated = targets::validate_with_options(staged, false)?;
    for t in &mut validated {
        if empty_allowlist_ids.iter().any(|id| id == &t.id) {
            t.expect_regions.clear();
        }
    }
    Ok(validated)
}

impl ConfigStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn path(&self) -> PathBuf {
        self.dir.join(CONFIG_FILE)
    }

    /// Read-only load used by both daemon bootstrap and `--check` (never mutates disk).
    pub fn load_readonly(&self) -> LoadedConfig {
        let path = self.path();
        let raw = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return LoadedConfig::NotFound;
            }
            Err(err) => {
                return LoadedConfig::Corrupt {
                    error: format!("failed to read {}: {err}", path.display()),
                    raw: String::new(),
                };
            }
        };
        match Config::from_legacy_json(&raw) {
            Ok(outcome) => LoadedConfig::Loaded(Box::new(outcome)),
            Err(error) => LoadedConfig::Corrupt { error, raw },
        }
    }

    /// Creates a one-time backup `config.v{ver}.bak.json` when upgrading from `< CONFIG_VERSION`.
    pub fn backup_legacy_once(&self) -> Option<PathBuf> {
        let raw = std::fs::read_to_string(self.path()).ok()?;
        let val: serde_json::Value = serde_json::from_str(&raw).ok()?;
        let ver = val.get("version").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        if ver >= CONFIG_VERSION {
            return None;
        }
        let dst = self.dir.join(format!("config.v{ver}.bak.json"));
        if dst.exists() {
            return None;
        }
        crate::journal::ensure_secure_data_dir(&self.dir).ok()?;
        let mut tmp = NamedTempFile::new_in(&self.dir).ok()?;
        tmp.write_all(raw.as_bytes()).ok()?;
        tmp.as_file().sync_all().ok()?;
        tmp.persist(&dst).ok()?;
        Some(dst)
    }

    /// Preserves corrupt configuration text before falling back (`config.corrupt.<ts>.json`).
    pub fn backup_corrupt_once(&self, raw: &str) -> Option<PathBuf> {
        if raw.trim().is_empty() {
            return None;
        }
        crate::journal::ensure_secure_data_dir(&self.dir).ok()?;
        let dst = self
            .dir
            .join(format!("config.corrupt.{}.json", now_unix_secs()));
        let mut tmp = NamedTempFile::new_in(&self.dir).ok()?;
        tmp.write_all(raw.as_bytes()).ok()?;
        tmp.as_file().sync_all().ok()?;
        tmp.persist(&dst).ok()?;
        Some(dst)
    }

    /// Validates, atomically writes (`sync_all` + rename), and reads back `config.json` (`CONTRACT` §3.6).
    ///
    /// Any validation, serialization, write, rename, or read-back verification error returns `Err`
    /// without altering the existing `config.json` on disk.
    pub fn save_verified(&self, cfg: &Config) -> Result<Config, String> {
        for id in targets::BUILTIN_IDS {
            if !cfg
                .targets
                .iter()
                .any(|t| t.id.trim().eq_ignore_ascii_case(id))
            {
                return Err(format!("缺少内置目标 {id}，请点“恢复默认”"));
            }
        }
        let mut normalized = cfg.clone();
        normalized.migrate();
        normalized.targets = validate_targets_for_config(normalized.targets, normalized.first_run)?;

        crate::journal::ensure_secure_data_dir(&self.dir)?;

        let json = serde_json::to_string_pretty(&normalized)
            .map_err(|e| format!("failed to serialize config: {e}"))?;

        let path = self.path();
        let mut tmp = NamedTempFile::new_in(&self.dir)
            .map_err(|e| format!("failed to create temp config file: {e}"))?;
        tmp.write_all(json.as_bytes())
            .map_err(|e| format!("failed to write temp config file: {e}"))?;
        tmp.as_file()
            .sync_all()
            .map_err(|e| format!("failed to sync temp config file: {e}"))?;
        tmp.persist(&path)
            .map_err(|e| format!("failed to persist config {}: {}", path.display(), e.error))?;

        // Mandatory read-back verification per CONTRACT §3.6.
        let readback_raw =
            std::fs::read_to_string(&path).map_err(|e| format!("config read-back failed: {e}"))?;
        let readback = Config::from_json_str(&readback_raw)
            .map_err(|e| format!("config read-back parse failed: {e}"))?;
        if readback != normalized {
            return Err("config read-back mismatch after atomic save".to_string());
        }
        Ok(normalized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_verified_writes_atomically_and_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        let store = ConfigStore::new(dir.path());
        assert!(matches!(store.load_readonly(), LoadedConfig::NotFound));

        let mut cfg = Config {
            first_run: false,
            ..Config::default()
        };
        for t in &mut cfg.targets {
            if matches!(t.id.as_str(), "local" | "claude" | "codex") {
                t.expect_regions = vec!["US".into()];
            }
        }
        let saved = store.save_verified(&cfg).expect("save_verified");
        assert_eq!(saved.version, CONFIG_VERSION);

        match store.load_readonly() {
            LoadedConfig::Loaded(out) => assert_eq!(out.config, saved),
            other => panic!("unexpected load result: {other:?}"),
        }
    }

    #[test]
    fn corrupt_config_is_detected_and_invalid_targets_are_rejected_without_touching_disk() {
        let dir = tempfile::tempdir().unwrap();
        let store = ConfigStore::new(dir.path());
        std::fs::write(store.path(), "{not-valid-json").unwrap();
        assert!(matches!(
            store.load_readonly(),
            LoadedConfig::Corrupt { .. }
        ));

        let mut bad = Config::default();
        bad.targets.clear();
        assert!(store.save_verified(&bad).is_err());

        // First-run pre-onboarding config with empty region/IP allowlists saves & loads cleanly!
        let first_run_cfg = Config::default();
        assert!(first_run_cfg.first_run);
        let saved_first = store
            .save_verified(&first_run_cfg)
            .expect("first_run config must persist before onboarding");
        assert!(saved_first.first_run);
        assert!(saved_first.targets[1].expect_regions.is_empty());
    }
}
