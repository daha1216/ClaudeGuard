//! M2/M4: Machine-keyed DPAPI-HMAC 7-day rolling egress geo-velocity ledger.
//!
//! Security & privacy invariants:
//! - Generates a 256-bit random HMAC key stored encrypted at rest via Windows DPAPI
//!   (`DpapiScope::LocalMachine`) in `<data_dir>\ledger_key.dpapi`.
//! - Persists rolling 7-day history to `<data_dir>\egress_history.json` storing **ONLY**
//!   HMAC-SHA256 digests of the IP and `/24` (or IPv6 `/48`) subnet prefix alongside country,
//!   city/colo, fixed-point coordinates (`lat_tenths`/`lon_tenths`), timestamp, and optional
//!   `vault_id` — **ZERO plaintext IP addresses ever touch disk**.
//! - Uses atomic `NamedTempFile` + `sync_all` + `persist` with full reparse-point checks.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use cg_core::risk_scorer::{evaluate_geo_velocity, EgressObservation, GeoVelocityEvaluation};
use cg_platform::crypto_win::{self, DpapiScope};
use cg_protocol::GeoVelocityAlert;
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use crate::journal;

/// Encrypted machine-keyed HMAC secret filename inside `data_dir`.
pub const LEDGER_KEY_FILE: &str = "ledger_key.dpapi";

/// Sanitized 7-day egress history filename inside `data_dir`.
pub const EGRESS_HISTORY_FILE: &str = "egress_history.json";

/// Retention window (7 days in seconds).
pub const RETENTION_SECS: u64 = 7 * 86_400;

/// Maximum retained ledger entries to bound disk & memory usage.
pub const MAX_LEDGER_ENTRIES: usize = 4096;

/// Pure RFC 2104 HMAC-SHA256 backed by `cg_platform::crypto_win::sha256_hex` (zero extra deps).
pub fn hmac_sha256_bytes(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    let mut block_key = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hashed = sha256_bytes(key);
        block_key[..32].copy_from_slice(&hashed);
    } else {
        block_key[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5Cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= block_key[i];
        opad[i] ^= block_key[i];
    }

    let mut inner_buf = Vec::with_capacity(BLOCK_SIZE + data.len());
    inner_buf.extend_from_slice(&ipad);
    inner_buf.extend_from_slice(data);
    let inner_hash = sha256_bytes(&inner_buf);

    let mut outer_buf = [0u8; BLOCK_SIZE + 32];
    outer_buf[..BLOCK_SIZE].copy_from_slice(&opad);
    outer_buf[BLOCK_SIZE..].copy_from_slice(&inner_hash);
    sha256_bytes(&outer_buf)
}

/// Computes lowercase hex-encoded HMAC-SHA256 (64 ASCII hex chars).
pub fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
    bytes_to_hex(&hmac_sha256_bytes(key, data))
}

/// Constant-time byte-slice equality comparison (resistant to timing side channels).
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let hex = crypto_win::sha256_hex(data);
    decode_hex_32(&hex).unwrap_or([0u8; 32])
}

fn decode_hex_32(hex: &str) -> Option<[u8; 32]> {
    let b = hex.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = hex_nibble(b[i * 2])?;
        let lo = hex_nibble(b[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(ch: u8) -> Option<u8> {
    match ch {
        b'0'..=b'9' => Some(ch - b'0'),
        b'a'..=b'f' => Some(ch - b'a' + 10),
        b'A'..=b'F' => Some(ch - b'A' + 10),
        _ => None,
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Normalizes an IP string and computes `(canonical_ip, subnet_prefix_key)` strictly in memory.
fn normalize_ip_and_subnet(raw_ip: &str) -> (String, String) {
    let trimmed = raw_ip.trim();
    if let Ok(parsed) = trimmed.parse::<IpAddr>() {
        let canon = cg_platform::netwatch_win::canonical_ip(parsed);
        match canon {
            IpAddr::V4(v4) => {
                let [a, b, c, _] = v4.octets();
                (v4.to_string(), format!("v4:{a}.{b}.{c}.0/24"))
            }
            IpAddr::V6(v6) => {
                let s = v6.segments();
                (
                    v6.to_string().to_ascii_lowercase(),
                    format!("v6:{:04x}:{:04x}:{:04x}::/48", s[0], s[1], s[2]),
                )
            }
        }
    } else {
        let norm = trimmed.to_ascii_lowercase();
        (norm.clone(), format!("raw:{norm}"))
    }
}

fn normalize_opt_coords(lat: Option<i16>, lon: Option<i16>) -> (Option<i16>, Option<i16>) {
    match (lat, lon) {
        (Some(0), Some(0)) => (None, None),
        (Some(la), Some(lo)) => (Some(la), Some(lo)),
        _ => (None, None),
    }
}

/// Sanitized single ledger observation persisted on disk (ZERO plaintext IP fields).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EgressLedgerEntry {
    pub ip_hmac_hex: String,
    pub subnet_hmac_hex: String,
    pub country: String,
    pub city_or_colo: String,
    #[serde(default)]
    pub lat_tenths: Option<i16>,
    #[serde(default)]
    pub lon_tenths: Option<i16>,
    pub observed_at: u64,
    #[serde(default)]
    pub vault_id: Option<String>,
}

impl From<&EgressLedgerEntry> for EgressObservation {
    fn from(e: &EgressLedgerEntry) -> Self {
        let (lat_tenths, lon_tenths) = normalize_opt_coords(e.lat_tenths, e.lon_tenths);
        Self {
            ip_hmac_hex: e.ip_hmac_hex.clone(),
            subnet_hmac_hex: e.subnet_hmac_hex.clone(),
            country: e.country.clone(),
            city_or_colo: e.city_or_colo.clone(),
            lat_tenths,
            lon_tenths,
            observed_at: e.observed_at,
            vault_id: e.vault_id.clone(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LedgerDiskState {
    #[serde(default = "default_schema_version")]
    schema_version: u32,
    #[serde(default)]
    entries: Vec<EgressLedgerEntry>,
    #[serde(default)]
    cooldown_cleared_at: Option<u64>,
    #[serde(default)]
    vault_cooldowns: BTreeMap<String, u64>,
}

fn default_schema_version() -> u32 {
    1
}

/// Thread-safe DPAPI-HMAC 7-day geo-velocity ledger.
pub struct EgressLedger {
    data_dir: PathBuf,
    secret: [u8; 32],
    state: Mutex<LedgerDiskState>,
    io_lock: Mutex<()>,
}

impl EgressLedger {
    /// Opens or initializes `<data_dir>\ledger_key.dpapi` and `<data_dir>\egress_history.json`.
    pub fn open(data_dir: impl Into<PathBuf>) -> Self {
        let dir = data_dir.into();
        let secret = load_or_init_dpapi_secret(&dir).unwrap_or_else(|err| {
            crate::diagnostics::append_redacted_daemon_log_entries(
                &dir,
                &[cg_protocol::LogEntry {
                    id: 0,
                    timestamp: crate::protocol::now_unix_secs(),
                    level: cg_protocol::LogLevel::Warn,
                    category: "ledger".into(),
                    message: format!(
                        "DPAPI 出口轨迹密钥初始化失败，已降级使用内存临时密钥（重启后轨迹将重置）：{err}"
                    ),
                }],
            );
            let mut fallback = [0u8; 32];
            let _ = crypto_win::random_bytes(&mut fallback);
            fallback
        });
        Self::open_with_secret(dir, secret)
    }

    /// Opens the ledger using an explicit 256-bit HMAC secret (deterministic for tests).
    pub fn open_with_secret(data_dir: impl Into<PathBuf>, secret: [u8; 32]) -> Self {
        let dir = data_dir.into();
        let state = load_disk_state(&dir).unwrap_or_default();
        Self {
            data_dir: dir,
            secret,
            state: Mutex::new(state),
            io_lock: Mutex::new(()),
        }
    }

    /// Serializes disk persistence strictly in lock order (`io_lock` -> `state`), always writing
    /// the latest in-memory snapshot so concurrent callers can never clobber newer mutations.
    fn persist_latest(&self) -> Result<(), String> {
        let _io = self.io_lock.lock().unwrap_or_else(|e| e.into_inner());
        let snapshot = self.state.lock().unwrap_or_else(|e| e.into_inner()).clone();
        save_disk_state(&self.data_dir, &snapshot)
    }

    /// Path to `<data_dir>\egress_history.json`.
    pub fn history_path(&self) -> PathBuf {
        self.data_dir.join(EGRESS_HISTORY_FILE)
    }

    /// Path to `<data_dir>\ledger_key.dpapi`.
    pub fn key_path(&self) -> PathBuf {
        self.data_dir.join(LEDGER_KEY_FILE)
    }

    /// Builds a sanitized HMAC-hashed [`EgressObservation`] in memory without mutating disk.
    #[allow(clippy::too_many_arguments)]
    pub fn make_observation(
        &self,
        raw_ip: &str,
        country: &str,
        city_or_colo: &str,
        lat_tenths: Option<i16>,
        lon_tenths: Option<i16>,
        vault_id: Option<&str>,
        now_secs: u64,
    ) -> EgressObservation {
        let (ip_hmac_hex, subnet_hmac_hex) = self.hash_ip_and_subnet(raw_ip);
        let norm_vault = normalize_vault_opt(vault_id);
        let (lat_norm, lon_norm) = normalize_opt_coords(lat_tenths, lon_tenths);
        EgressObservation {
            ip_hmac_hex,
            subnet_hmac_hex,
            country: country.trim().to_ascii_uppercase(),
            city_or_colo: city_or_colo.trim().to_string(),
            lat_tenths: lat_norm,
            lon_tenths: lon_norm,
            observed_at: now_secs,
            vault_id: norm_vault,
        }
    }

    fn record_and_evaluate_locked(
        guard: &mut LedgerDiskState,
        current: &EgressObservation,
        teleport_cooldown_mins: u32,
        now_secs: u64,
    ) -> GeoVelocityEvaluation {
        prune_entries(guard, now_secs);

        // Filter out historical entries predating an explicit user cooldown clear and enforce
        // strict scope isolation (`e.vault_id == current.vault_id`) so concurrent multi-region
        // vaults never pollute global (`None`) geo-velocity evaluation.
        let cleared_at = guard.cooldown_cleared_at.unwrap_or(0);
        let history_for_eval: Vec<EgressObservation> = guard
            .entries
            .iter()
            .filter(|e| e.observed_at > cleared_at && e.vault_id == current.vault_id)
            .map(EgressObservation::from)
            .collect();

        let eval = evaluate_geo_velocity(&history_for_eval, current, teleport_cooldown_mins);

        // Persist observation (deduplicating contiguous identical scope+subnet+country entries).
        if !current.ip_hmac_hex.is_empty() && !current.country.is_empty() {
            let entry = EgressLedgerEntry {
                ip_hmac_hex: current.ip_hmac_hex.clone(),
                subnet_hmac_hex: current.subnet_hmac_hex.clone(),
                country: current.country.clone(),
                city_or_colo: current.city_or_colo.clone(),
                lat_tenths: current.lat_tenths,
                lon_tenths: current.lon_tenths,
                observed_at: now_secs,
                vault_id: current.vault_id.clone(),
            };

            let updated_existing = guard
                .entries
                .iter_mut()
                .rev()
                .find(|prev| prev.vault_id == entry.vault_id)
                .is_some_and(|prev| {
                    if prev.subnet_hmac_hex == entry.subnet_hmac_hex
                        && prev.country == entry.country
                        && prev.ip_hmac_hex == entry.ip_hmac_hex
                    {
                        prev.observed_at = prev.observed_at.max(now_secs);
                        if !entry.city_or_colo.is_empty() {
                            prev.city_or_colo = entry.city_or_colo.clone();
                        }
                        if entry.lat_tenths.is_some() && entry.lon_tenths.is_some() {
                            prev.lat_tenths = entry.lat_tenths;
                            prev.lon_tenths = entry.lon_tenths;
                        }
                        true
                    } else {
                        false
                    }
                });

            if !updated_existing {
                guard.entries.push(entry);
            }
            if guard.entries.len() > MAX_LEDGER_ENTRIES {
                let excess = guard.entries.len() - MAX_LEDGER_ENTRIES;
                guard.entries.drain(0..excess);
            }
        }

        if let (Some(vid), Some(alert)) = (current.vault_id.as_deref(), eval.alert.as_ref()) {
            if let Some(until) = alert.cooldown_until {
                let prev = guard.vault_cooldowns.get(vid).copied().unwrap_or(0);
                guard
                    .vault_cooldowns
                    .insert(vid.to_string(), prev.max(until));
            }
        }

        eval
    }

    /// Records a new egress observation (HMAC-hashed), prunes entries older than 7 days,
    /// evaluates impossible-travel & subnet churn via `cg_core::risk_scorer::evaluate_geo_velocity`,
    /// updates per-vault cooldown if needed, and atomically persists `egress_history.json`.
    #[allow(clippy::too_many_arguments)]
    pub fn record_and_evaluate(
        &self,
        raw_ip: &str,
        country: &str,
        city_or_colo: &str,
        lat_tenths: Option<i16>,
        lon_tenths: Option<i16>,
        vault_id: Option<&str>,
        teleport_cooldown_mins: u32,
        now_secs: u64,
    ) -> GeoVelocityEvaluation {
        let current = self.make_observation(
            raw_ip,
            country,
            city_or_colo,
            lat_tenths,
            lon_tenths,
            vault_id,
            now_secs,
        );

        let eval = {
            let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
            Self::record_and_evaluate_locked(&mut guard, &current, teleport_cooldown_mins, now_secs)
        };
        let _ = self.persist_latest();
        eval
    }

    /// Records a Sovereign Vault launch/activity observation and applies `cooldown_after_ip_change_secs`
    /// if the vault's egress subnet or country changed since its previous recorded launch.
    #[allow(clippy::too_many_arguments)]
    pub fn record_vault_activity(
        &self,
        vault_id: &str,
        raw_ip: Option<&str>,
        country: Option<&str>,
        city_or_colo: Option<&str>,
        lat_tenths: Option<i16>,
        lon_tenths: Option<i16>,
        cooldown_after_ip_change_secs: u64,
        now_secs: u64,
    ) -> Option<GeoVelocityAlert> {
        let ip = raw_ip.map(str::trim).filter(|s| !s.is_empty())?;
        let cc = country.unwrap_or("").trim().to_ascii_uppercase();
        let city = city_or_colo.unwrap_or("").trim();
        let cooldown_mins = cooldown_after_ip_change_secs
            .div_ceil(60)
            .min(u64::from(u32::MAX)) as u32;
        let current = self.make_observation(
            ip,
            &cc,
            city,
            lat_tenths,
            lon_tenths,
            Some(vault_id),
            now_secs,
        );

        let alert = {
            let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let vid_norm = current.vault_id.clone();
            let prev_subnet = guard
                .entries
                .iter()
                .rev()
                .find(|e| e.vault_id == vid_norm)
                .map(|e| (e.subnet_hmac_hex.clone(), e.observed_at));
            let eval = Self::record_and_evaluate_locked(
                &mut guard,
                &current,
                cooldown_mins.max(1),
                now_secs,
            );
            // Enforce per-vault IP-change cooldown even within the same country if subnet changed recently.
            if cooldown_after_ip_change_secs > 0 {
                if let Some((old_sub, old_ts)) = prev_subnet {
                    if old_sub != current.subnet_hmac_hex
                        && now_secs.saturating_sub(old_ts) < cooldown_after_ip_change_secs
                    {
                        let until = now_secs.saturating_add(cooldown_after_ip_change_secs);
                        if let Some(vid) = vid_norm {
                            let prev = guard.vault_cooldowns.get(&vid).copied().unwrap_or(0);
                            guard.vault_cooldowns.insert(vid, prev.max(until));
                        }
                    }
                }
            }
            eval.alert
        };
        let _ = self.persist_latest();
        alert
    }

    /// Returns sanitized 7-day observations suitable for feeding into `cg_core::risk_scorer::score_egress_risk`.
    /// Entries predating an explicit user `clear_cooldown` are excluded so cleared alerts stay cleared.
    pub fn observations_for_scoring(
        &self,
        vault_id: Option<&str>,
        now_secs: u64,
    ) -> Vec<EgressObservation> {
        let guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let cleared_at = guard.cooldown_cleared_at.unwrap_or(0);
        let norm_vault = normalize_vault_opt(vault_id);
        guard
            .entries
            .iter()
            .filter(|e| {
                e.observed_at > cleared_at
                    && now_secs.saturating_sub(e.observed_at) <= RETENTION_SECS
                    && e.vault_id == norm_vault
            })
            .map(EgressObservation::from)
            .collect()
    }

    /// Counts distinct `/24` (or `/48`) HMAC-hashed subnets observed over the last 1 hour
    /// within the exact requested scope (`None` = global only, `Some(v)` = that vault only).
    pub fn distinct_subnets_1h(&self, vault_id: Option<&str>, now_secs: u64) -> u32 {
        let guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let norm_vault = normalize_vault_opt(vault_id);
        let mut set: BTreeSet<&str> = BTreeSet::new();
        for e in &guard.entries {
            if e.vault_id != norm_vault {
                continue;
            }
            if e.observed_at <= now_secs && now_secs.saturating_sub(e.observed_at) <= 3_600 {
                let key = if !e.subnet_hmac_hex.is_empty() {
                    e.subnet_hmac_hex.as_str()
                } else {
                    e.ip_hmac_hex.as_str()
                };
                if !key.is_empty() {
                    set.insert(key);
                }
            }
        }
        set.len() as u32
    }

    /// Counts distinct ISO-2 country codes observed over the last 24 hours
    /// within the exact requested scope (`None` = global only, `Some(v)` = that vault only).
    pub fn distinct_countries_24h(&self, vault_id: Option<&str>, now_secs: u64) -> u32 {
        let guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let norm_vault = normalize_vault_opt(vault_id);
        let mut set: BTreeSet<&str> = BTreeSet::new();
        for e in &guard.entries {
            if e.vault_id != norm_vault {
                continue;
            }
            if e.observed_at <= now_secs
                && now_secs.saturating_sub(e.observed_at) <= 86_400
                && !e.country.trim().is_empty()
            {
                set.insert(e.country.as_str());
            }
        }
        set.len() as u32
    }

    /// Clears active global and per-vault impossible-travel cooldowns (user confirmed legitimate travel).
    pub fn clear_cooldown(&self, now_secs: u64) -> Result<(), String> {
        {
            let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
            guard.cooldown_cleared_at = Some(now_secs);
            guard.vault_cooldowns.clear();
        }
        self.persist_latest()
    }

    /// Returns remaining cooldown seconds (`0` if clear/expired) for a specific Sovereign Vault.
    pub fn vault_cooldown_remaining(&self, vault_id: &str, now_secs: u64) -> u64 {
        let Some(vid) = normalize_vault_opt(Some(vault_id)) else {
            return 0;
        };
        let guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .vault_cooldowns
            .get(&vid)
            .copied()
            .map_or(0, |until| until.saturating_sub(now_secs))
    }

    /// Explicitly sets a cooldown deadline for a specific vault (e.g. after IP change).
    pub fn set_vault_cooldown_until(
        &self,
        vault_id: &str,
        cooldown_until: u64,
    ) -> Result<(), String> {
        let Some(vid) = normalize_vault_opt(Some(vault_id)) else {
            return Ok(());
        };
        {
            let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
            guard.vault_cooldowns.insert(vid, cooldown_until);
        }
        self.persist_latest()
    }

    /// Returns `(last_active_at, last_country)` recorded for a specific vault, if any.
    pub fn vault_last_activity(&self, vault_id: &str) -> Option<(u64, String)> {
        let vid = normalize_vault_opt(Some(vault_id))?;
        let guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .entries
            .iter()
            .rev()
            .find(|e| e.vault_id.as_deref() == Some(vid.as_str()))
            .map(|e| (e.observed_at, e.country.clone()))
    }

    fn hash_ip_and_subnet(&self, raw_ip: &str) -> (String, String) {
        let trimmed = raw_ip.trim();
        if trimmed.is_empty() {
            return (String::new(), String::new());
        }
        let (canon_ip, subnet_prefix) = normalize_ip_and_subnet(trimmed);
        let ip_hmac = hmac_sha256_hex(&self.secret, canon_ip.as_bytes());
        let subnet_hmac = hmac_sha256_hex(&self.secret, subnet_prefix.as_bytes());
        (ip_hmac, subnet_hmac)
    }
}

fn normalize_vault_opt(vault_id: Option<&str>) -> Option<String> {
    vault_id
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_ascii_lowercase)
}

fn prune_entries(state: &mut LedgerDiskState, now_secs: u64) {
    state.entries.retain(|e| {
        e.observed_at <= now_secs && now_secs.saturating_sub(e.observed_at) <= RETENTION_SECS
    });
    state
        .vault_cooldowns
        .retain(|_, &mut until| until > now_secs);
}

fn load_or_init_dpapi_secret(data_dir: &Path) -> Result<[u8; 32], String> {
    journal::ensure_secure_data_dir(data_dir)?;
    let key_path = data_dir.join(LEDGER_KEY_FILE);
    if journal::has_reparse_point_in_chain(&key_path) {
        return Err(format!(
            "refusing to read/write ledger key through reparse point: {}",
            key_path.display()
        ));
    }

    if key_path.is_file() {
        let cipher = std::fs::read(&key_path).map_err(|e| {
            format!(
                "failed to read existing ledger key {} (refusing to overwrite): {e}",
                key_path.display()
            )
        })?;
        let plain = crypto_win::unprotect_bytes(&cipher).map_err(|e| {
            format!(
                "failed to unprotect existing ledger key {} (refusing to overwrite): {e}",
                key_path.display()
            )
        })?;
        if plain.len() == 32 {
            let mut secret = [0u8; 32];
            secret.copy_from_slice(&plain);
            return Ok(secret);
        }
        return Err(format!(
            "existing ledger key {} has unexpected decrypted length {} (refusing to overwrite)",
            key_path.display(),
            plain.len()
        ));
    }

    let mut secret = [0u8; 32];
    crypto_win::random_bytes(&mut secret)?;
    let cipher = crypto_win::protect_bytes(&secret, DpapiScope::LocalMachine)
        .map_err(|e| format!("failed to protect ledger key with DPAPI: {e}"))?;

    atomic_write_in_dir(data_dir, &key_path, &cipher)?;
    Ok(secret)
}

fn load_disk_state(data_dir: &Path) -> Result<LedgerDiskState, String> {
    let path = data_dir.join(EGRESS_HISTORY_FILE);
    if journal::has_reparse_point_in_chain(&path) {
        return Err(format!(
            "refusing to read egress history through reparse point: {}",
            path.display()
        ));
    }
    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(LedgerDiskState::default()),
        Err(e) => return Err(format!("failed to read egress_history.json: {e}")),
    };
    serde_json::from_str(&raw).map_err(|e| format!("invalid egress_history.json: {e}"))
}

fn save_disk_state(data_dir: &Path, state: &LedgerDiskState) -> Result<(), String> {
    journal::ensure_secure_data_dir(data_dir)?;
    let path = data_dir.join(EGRESS_HISTORY_FILE);
    if journal::has_reparse_point_in_chain(&path) {
        return Err(format!(
            "refusing to persist egress history through reparse point: {}",
            path.display()
        ));
    }
    let bytes = serde_json::to_vec_pretty(state)
        .map_err(|e| format!("failed to serialize egress_history.json: {e}"))?;
    atomic_write_in_dir(data_dir, &path, &bytes)
}

fn atomic_write_in_dir(dir: &Path, target: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut tmp = NamedTempFile::new_in(dir)
        .map_err(|e| format!("failed to create temp file in {}: {e}", dir.display()))?;
    tmp.write_all(bytes)
        .map_err(|e| format!("failed to write temp file: {e}"))?;
    tmp.as_file()
        .sync_all()
        .map_err(|e| format!("failed to sync temp file: {e}"))?;
    tmp.persist(target)
        .map_err(|e| format!("failed to persist {}: {}", target.display(), e.error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4231_hmac_sha256_vectors_match_exactly() {
        // RFC 4231 Test Case 2: Key = "Jefe", Data = "what do ya want for nothing?"
        let mac2 = hmac_sha256_hex(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            mac2,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );

        // RFC 4231 Test Case 1: Key = 0x0b * 20, Data = "Hi There"
        let mac1 = hmac_sha256_hex(&[0x0bu8; 20], b"Hi There");
        assert_eq!(
            mac1,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );

        // Long key (> 64 bytes): RFC 4231 Test Case 6
        let key6 = [0xaau8; 131];
        let mac6 = hmac_sha256_hex(
            &key6,
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );
        assert_eq!(
            mac6,
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );

        assert!(constant_time_eq(mac2.as_bytes(), mac2.as_bytes()));
        assert!(!constant_time_eq(mac1.as_bytes(), mac2.as_bytes()));
    }

    #[test]
    fn dpapi_hmac_ledger_persists_zero_plaintext_ips_and_detects_impossible_travel() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = EgressLedger::open(dir.path());

        #[cfg(windows)]
        assert!(
            ledger.key_path().is_file(),
            "ledger_key.dpapi should be persisted on Windows"
        );

        let ip_us = "198.51.100.42";
        let ip_jp = "203.0.113.88";

        let eval1 = ledger.record_and_evaluate(
            ip_us,
            "US",
            "Los Angeles",
            Some(341),
            Some(-1182),
            None,
            60,
            1_700_000_000,
        );
        assert!(eval1.alert.is_none());
        assert_eq!(ledger.distinct_subnets_1h(None, 1_700_000_000), 1);
        assert_eq!(ledger.distinct_countries_24h(None, 1_700_000_000), 1);

        // 10 minutes later: jump LA -> Tokyo (~8,800 km) => Impossible Travel!
        let eval2 = ledger.record_and_evaluate(
            ip_jp,
            "JP",
            "Tokyo",
            Some(357),
            Some(1397),
            None,
            60,
            1_700_000_600,
        );
        let alert = eval2
            .alert
            .expect("expected impossible travel alert for LA -> Tokyo in 10 min");
        assert_eq!(alert.from_country, "US");
        assert_eq!(alert.to_country, "JP");
        assert!(alert.distance_km > 8_000);
        assert!(alert.cooldown_until.is_some());
        assert_eq!(ledger.distinct_subnets_1h(None, 1_700_000_600), 2);
        assert_eq!(ledger.distinct_countries_24h(None, 1_700_000_600), 2);

        // Verify ZERO plaintext IP or /24 prefix appears anywhere in egress_history.json!
        let on_disk = std::fs::read_to_string(ledger.history_path()).unwrap();
        for forbidden in ["198.51.100.42", "198.51.100", "203.0.113.88", "203.0.113"] {
            assert!(
                !on_disk.contains(forbidden),
                "egress_history.json leaked plaintext IP fragment `{forbidden}`: {on_disk}"
            );
        }

        // Reloading from disk with the same DPAPI key preserves HMAC history & counts.
        let reloaded = EgressLedger::open(dir.path());
        assert_eq!(reloaded.distinct_subnets_1h(None, 1_700_000_600), 2);
        assert_eq!(reloaded.distinct_countries_24h(None, 1_700_000_600), 2);

        // Explicit cooldown clear lifts stale impossible-travel alerts cleanly.
        reloaded.clear_cooldown(1_700_000_700).unwrap();
        let after_clear = reloaded.record_and_evaluate(
            "203.0.113.99",
            "JP",
            "Tokyo",
            Some(357),
            Some(1397),
            None,
            60,
            1_700_000_710,
        );
        assert!(after_clear.alert.is_none());
    }

    #[test]
    fn vault_scoped_cooldowns_are_isolated_from_other_vaults() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = EgressLedger::open_with_secret(dir.path(), [0x42u8; 32]);

        let a1 = ledger.record_and_evaluate(
            "198.51.100.10",
            "US",
            "Los Angeles",
            Some(341),
            Some(-1182),
            Some("vault-us"),
            60,
            2_000_000,
        );
        assert!(a1.alert.is_none());

        // Different vault in Tokyo 60s later must NOT trigger impossible travel!
        let b1 = ledger.record_and_evaluate(
            "203.0.113.20",
            "JP",
            "Tokyo",
            Some(357),
            Some(1397),
            Some("vault-jp"),
            60,
            2_000_060,
        );
        assert!(b1.alert.is_none());
        assert_eq!(ledger.vault_cooldown_remaining("vault-us", 2_000_060), 0);
        assert_eq!(ledger.vault_cooldown_remaining("vault-jp", 2_000_060), 0);

        // Same vault `vault-us` jumping to Tokyo 2 minutes later DOES trigger per-vault cooldown!
        let a2 = ledger.record_and_evaluate(
            "203.0.113.20",
            "JP",
            "Tokyo",
            Some(357),
            Some(1397),
            Some("vault-us"),
            60,
            2_000_120,
        );
        assert!(a2.alert.is_some());
        assert!(ledger.vault_cooldown_remaining("vault-us", 2_000_120) > 0);
        assert_eq!(ledger.vault_cooldown_remaining("vault-jp", 2_000_120), 0);

        // Vault-scoped US + JP entries MUST NOT leak into global (`None`) scope!
        assert!(
            ledger.observations_for_scoring(None, 2_000_120).is_empty(),
            "vault observations must never pollute global scoring"
        );
        assert_eq!(ledger.distinct_subnets_1h(None, 2_000_120), 0);
        assert_eq!(ledger.distinct_countries_24h(None, 2_000_120), 0);

        // Global observation in US after vault-jp in Tokyo must NOT trip global geo-velocity!
        let g1 = ledger.record_and_evaluate(
            "198.51.100.55",
            "US",
            "Los Angeles",
            Some(341),
            Some(-1182),
            None,
            60,
            2_000_150,
        );
        assert!(
            g1.alert.is_none(),
            "concurrent vault-jp activity must never falsely trip global US egress"
        );
        assert_eq!(ledger.distinct_countries_24h(None, 2_000_150), 1);
    }
}
