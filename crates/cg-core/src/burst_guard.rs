//! Pure deterministic prompt velocity & robotic cadence guard (`M6` BurstGuard).
//!
//! Tracks sliding 1-minute and 15-minute prompt submission timestamps per `(agent_id, vault_id)`
//! and computes inter-arrival interval mean and coefficient of variation (`CV = stddev / mean`)
//! to detect runaway retry scripts and mechanical fixed-interval cron loops.

use std::collections::{BTreeMap, VecDeque};

use cg_protocol::{BurstGuardMode, BurstGuardStatus, Config, HookDecision};

/// Maximum retained timestamps per `(agent_id, vault_id)` bucket.
pub const BURST_RING_CAPACITY: usize = 512;

/// Short burst sliding window duration (1 minute in ms).
pub const WINDOW_1M_MS: u64 = 60_000;

/// Long fatigue sliding window duration (15 minutes in ms).
pub const WINDOW_15M_MS: u64 = 15 * 60_000;

/// Default maximum prompts permitted in a 15-minute window before fatigue throttling.
pub const DEFAULT_MAX_15M_PROMPTS: u32 = 180;

/// Minimum number of adjacent inter-arrival intervals required for robotic cadence detection.
pub const ROBOTIC_MIN_INTERVALS: usize = 8;

/// Maximum recent timestamps sampled for robotic cadence entropy check (10 timestamps = 9 intervals).
pub const ROBOTIC_SAMPLE_TIMESTAMPS: usize = 10;

/// Maximum mean interval (ms) considered for robotic cadence (2 minutes).
pub const ROBOTIC_MAX_MEAN_MS: f64 = 120_000.0;

/// Coefficient of variation threshold (`CV < 0.04` => suspiciously mechanical cadence).
pub const ROBOTIC_CV_THRESHOLD: f64 = 0.04;

/// Configuration parameters for [`BurstGuardTracker`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BurstGuardConfig {
    pub mode: BurstGuardMode,
    pub warn_rpm: u32,
    pub throttle_rpm: u32,
    pub max_15m_prompts: u32,
}

impl Default for BurstGuardConfig {
    fn default() -> Self {
        Self {
            mode: BurstGuardMode::WarnOnly,
            warn_rpm: 18,
            throttle_rpm: 30,
            max_15m_prompts: DEFAULT_MAX_15M_PROMPTS,
        }
    }
}

impl BurstGuardConfig {
    /// Extracts BurstGuard thresholds from persisted [`Config`].
    pub fn from_config(cfg: &Config) -> Self {
        Self {
            mode: cfg.burst_guard_mode,
            warn_rpm: cfg.burst_warn_rpm,
            throttle_rpm: cfg.burst_throttle_rpm,
            max_15m_prompts: DEFAULT_MAX_15M_PROMPTS,
        }
    }
}

/// Gate throttle verdict produced by [`BurstGuardTracker`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BurstVerdict {
    Allow,
    Warn,
    Throttle,
}

/// Cadence entropy metrics computed from recent prompt submission intervals.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CadenceMetrics {
    pub interval_count: usize,
    pub mean_ms: f64,
    pub stddev_ms: f64,
    pub cv: f64,
    pub robotic: bool,
}

/// Combined verdict, hook gate decision, and UI snapshot status for a prompt evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BurstEvaluation {
    pub verdict: BurstVerdict,
    pub hook_decision: HookDecision,
    pub status: BurstGuardStatus,
    pub reason: String,
}

/// Computes `(mean_ms, cv)` over the most recent adjacent inter-arrival intervals
/// when at least [`ROBOTIC_MIN_INTERVALS`] (`>= 8`) intervals exist (`>= 9` timestamps).
pub fn compute_cadence_metrics(timestamps_ms: &[u64]) -> Option<CadenceMetrics> {
    if timestamps_ms.len() <= ROBOTIC_MIN_INTERVALS {
        return None;
    }
    let sample_start = timestamps_ms
        .len()
        .saturating_sub(ROBOTIC_SAMPLE_TIMESTAMPS);
    let sample = &timestamps_ms[sample_start..];
    let interval_count = sample.len().saturating_sub(1);
    if interval_count < ROBOTIC_MIN_INTERVALS {
        return None;
    }

    let mut intervals = Vec::with_capacity(interval_count);
    for pair in sample.windows(2) {
        intervals.push(pair[1].saturating_sub(pair[0]) as f64);
    }

    let n = intervals.len() as f64;
    let mean_ms = intervals.iter().sum::<f64>() / n;
    let variance = intervals
        .iter()
        .map(|dt| {
            let diff = *dt - mean_ms;
            diff * diff
        })
        .sum::<f64>()
        / n;
    let stddev_ms = variance.sqrt();
    let cv = stddev_ms / mean_ms.max(1.0);
    let robotic = mean_ms < ROBOTIC_MAX_MEAN_MS && cv < ROBOTIC_CV_THRESHOLD;

    Some(CadenceMetrics {
        interval_count,
        mean_ms,
        stddev_ms,
        cv,
        robotic,
    })
}

/// Convenience helper returning `(mean_ms, cv)` when `>= 8` intervals exist.
pub fn compute_cadence_cv(timestamps_ms: &[u64]) -> Option<(f64, f64)> {
    compute_cadence_metrics(timestamps_ms).map(|m| (m.mean_ms, m.cv))
}

/// Pure deterministic sliding-window tracker for BurstGuard (`M6`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BurstGuardTracker {
    buckets: BTreeMap<(String, Option<String>), VecDeque<u64>>,
    suspicious_processes: Vec<String>,
}

impl BurstGuardTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Updates detected unauthorized third-party OAuth / API-hijack processes (from netwatch).
    pub fn set_suspicious_oauth_processes(&mut self, mut processes: Vec<String>) {
        processes.sort();
        processes.dedup();
        self.suspicious_processes = processes;
    }

    /// Evicts expired (> 15m) timestamps across all tracked buckets.
    pub fn prune(&mut self, now_ms: u64) {
        let cutoff = now_ms.saturating_sub(WINDOW_15M_MS);
        self.buckets.retain(|_, q| {
            while let Some(&front) = q.front() {
                if front < cutoff {
                    q.pop_front();
                } else {
                    break;
                }
            }
            !q.is_empty()
        });
    }

    /// Clears all tracked prompt history and suspicious process flags.
    pub fn clear(&mut self) {
        self.buckets.clear();
        self.suspicious_processes.clear();
    }

    /// Records a new prompt submission at `now_ms` and returns the BurstGuard verdict & status.
    ///
    /// Blocked attempts (`HookDecision::Block` under [`BurstGuardMode::ThrottleGate`]) are NOT
    /// committed into the sliding window so local retries while throttled never cause a
    /// self-extending 15-minute lockout.
    pub fn record_and_evaluate(
        &mut self,
        agent_id: &str,
        vault_id: Option<&str>,
        now_ms: u64,
        cfg: &BurstGuardConfig,
    ) -> BurstEvaluation {
        let key = bucket_key(agent_id, vault_id);
        let stamped = {
            let q = self.buckets.entry(key.clone()).or_default();
            let cutoff_15m = now_ms.saturating_sub(WINDOW_15M_MS);
            while let Some(&front) = q.front() {
                if front < cutoff_15m {
                    q.pop_front();
                } else {
                    break;
                }
            }
            // Guard against minor backward wall-clock jumps while keeping monotonic intervals.
            let ts = q.back().copied().map_or(now_ms, |last| now_ms.max(last));
            q.push_back(ts);
            ts
        };

        let eval = self.evaluate_bucket(agent_id, vault_id, stamped, cfg);
        if let Some(q) = self.buckets.get_mut(&key) {
            if eval.hook_decision == HookDecision::Block {
                q.pop_back();
            } else {
                while q.len() > BURST_RING_CAPACITY {
                    q.pop_front();
                }
            }
        }
        eval
    }

    /// Evaluates the current bucket state without recording a new prompt submission.
    pub fn evaluate_only(
        &self,
        agent_id: &str,
        vault_id: Option<&str>,
        now_ms: u64,
        cfg: &BurstGuardConfig,
    ) -> BurstEvaluation {
        self.evaluate_bucket(agent_id, vault_id, now_ms, cfg)
    }

    /// Builds an aggregated [`BurstGuardStatus`] across all active buckets for `GuardSnapshot`.
    pub fn overall_status(&self, now_ms: u64, cfg: &BurstGuardConfig) -> BurstGuardStatus {
        let cutoff_1m = now_ms.saturating_sub(WINDOW_1M_MS);
        let cutoff_15m = now_ms.saturating_sub(WINDOW_15M_MS);

        let mut max_1m: u32 = 0;
        let mut max_15m: u32 = 0;
        let mut robotic = false;

        for q in self.buckets.values() {
            let slice: Vec<u64> = q.iter().copied().filter(|&ts| ts >= cutoff_15m).collect();
            let c15 = slice.len() as u32;
            let c1 = slice.iter().filter(|&&ts| ts >= cutoff_1m).count() as u32;
            max_1m = max_1m.max(c1);
            max_15m = max_15m.max(c15);
            if compute_cadence_metrics(&slice).is_some_and(|m| m.robotic) {
                robotic = true;
            }
        }

        let unauthorized = !self.suspicious_processes.is_empty();
        let summary = format_status_summary(cfg, max_1m, max_15m, robotic, unauthorized);

        BurstGuardStatus {
            mode: cfg.mode,
            prompts_last_1m: max_1m,
            prompts_last_15m: max_15m,
            robotic_cadence_detected: robotic,
            unauthorized_oauth_client_detected: unauthorized,
            suspicious_processes: self.suspicious_processes.clone(),
            summary,
        }
    }

    fn evaluate_bucket(
        &self,
        agent_id: &str,
        vault_id: Option<&str>,
        now_ms: u64,
        cfg: &BurstGuardConfig,
    ) -> BurstEvaluation {
        let key = bucket_key(agent_id, vault_id);
        let cutoff_1m = now_ms.saturating_sub(WINDOW_1M_MS);
        let cutoff_15m = now_ms.saturating_sub(WINDOW_15M_MS);

        let recent_15m: Vec<u64> = self
            .buckets
            .get(&key)
            .map(|q| q.iter().copied().filter(|&ts| ts >= cutoff_15m).collect())
            .unwrap_or_default();

        let prompts_last_15m = recent_15m.len() as u32;
        let prompts_last_1m = recent_15m.iter().filter(|&&ts| ts >= cutoff_1m).count() as u32;
        let cadence = compute_cadence_metrics(&recent_15m);
        let robotic_cadence_detected = cadence.is_some_and(|m| m.robotic);
        let unauthorized_oauth_client_detected = !self.suspicious_processes.is_empty();

        let exceeds_1m_throttle = prompts_last_1m > cfg.throttle_rpm;
        let exceeds_15m_cap = prompts_last_15m > cfg.max_15m_prompts;
        let exceeds_1m_warn = prompts_last_1m >= cfg.warn_rpm;

        let (verdict, hook_decision, reason) = match cfg.mode {
            BurstGuardMode::Off => (
                BurstVerdict::Allow,
                HookDecision::Allow,
                "BurstGuard 已关闭".to_string(),
            ),
            BurstGuardMode::WarnOnly => {
                if unauthorized_oauth_client_detected {
                    (
                        BurstVerdict::Warn,
                        HookDecision::Allow,
                        format!(
                            "检测到疑似非官方进程复用 OAuth 凭据（{}），仅预警模式放行，请核查未知第三方工具",
                            self.suspicious_processes.join("、")
                        ),
                    )
                } else if exceeds_1m_throttle || exceeds_15m_cap {
                    (
                        BurstVerdict::Warn,
                        HookDecision::Allow,
                        format!(
                            "高频突发预警：近 1m {} 次 / 15m {} 次（仅预警模式放行，建议检查是否存在死循环脚本）",
                            prompts_last_1m, prompts_last_15m
                        ),
                    )
                } else if robotic_cadence_detected {
                    let cv = cadence.map(|m| m.cv).unwrap_or(0.0);
                    (
                        BurstVerdict::Warn,
                        HookDecision::Allow,
                        format!(
                            "检测到机械定频节律（CV={cv:.4} < 0.04），极易触发自动化风控，请停止定时心跳脚本"
                        ),
                    )
                } else if exceeds_1m_warn {
                    (
                        BurstVerdict::Warn,
                        HookDecision::Allow,
                        format!(
                            "提交频率偏高（近 1m {} 次 >= 预警阈值 {}）",
                            prompts_last_1m, cfg.warn_rpm
                        ),
                    )
                } else {
                    (
                        BurstVerdict::Allow,
                        HookDecision::Allow,
                        "提交频率与节律正常".to_string(),
                    )
                }
            }
            BurstGuardMode::ThrottleGate => {
                if unauthorized_oauth_client_detected {
                    (
                        BurstVerdict::Throttle,
                        HookDecision::Block,
                        format!(
                            "BurstGuard 凭据防盗用拦截：检测到非官方进程疑似复用 OAuth 凭据（{}），已阻断提交",
                            self.suspicious_processes.join("、")
                        ),
                    )
                } else if exceeds_1m_throttle {
                    (
                        BurstVerdict::Throttle,
                        HookDecision::Block,
                        format!(
                            "BurstGuard 熔断限流：近 1m 提交 {} 次超过限流阈值 {}，已拦截以防失控脚本触发封号",
                            prompts_last_1m, cfg.throttle_rpm
                        ),
                    )
                } else if exceeds_15m_cap {
                    (
                        BurstVerdict::Throttle,
                        HookDecision::Block,
                        format!(
                            "BurstGuard 疲劳限流：近 15m 提交 {} 次超过上限 {}，已暂停放行",
                            prompts_last_15m, cfg.max_15m_prompts
                        ),
                    )
                } else if robotic_cadence_detected {
                    let cv = cadence.map(|m| m.cv).unwrap_or(0.0);
                    (
                        BurstVerdict::Warn,
                        HookDecision::Allow,
                        format!("检测到机械定频节律（CV={cv:.4} < 0.04），建议增加随机人工间隔"),
                    )
                } else if exceeds_1m_warn {
                    (
                        BurstVerdict::Warn,
                        HookDecision::Allow,
                        format!(
                            "提交频率接近限流（近 1m {}/{} 次）",
                            prompts_last_1m, cfg.throttle_rpm
                        ),
                    )
                } else {
                    (
                        BurstVerdict::Allow,
                        HookDecision::Allow,
                        "提交频率与节律正常".to_string(),
                    )
                }
            }
        };

        let summary = format_status_summary(
            cfg,
            prompts_last_1m,
            prompts_last_15m,
            robotic_cadence_detected,
            unauthorized_oauth_client_detected,
        );

        BurstEvaluation {
            verdict,
            hook_decision,
            status: BurstGuardStatus {
                mode: cfg.mode,
                prompts_last_1m,
                prompts_last_15m,
                robotic_cadence_detected,
                unauthorized_oauth_client_detected,
                suspicious_processes: self.suspicious_processes.clone(),
                summary,
            },
            reason,
        }
    }
}

fn bucket_key(agent_id: &str, vault_id: Option<&str>) -> (String, Option<String>) {
    (
        agent_id.trim().to_ascii_lowercase(),
        vault_id
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_ascii_lowercase),
    )
}

fn format_status_summary(
    cfg: &BurstGuardConfig,
    prompts_1m: u32,
    prompts_15m: u32,
    robotic: bool,
    unauthorized: bool,
) -> String {
    if cfg.mode == BurstGuardMode::Off {
        return "BurstGuard 已关闭".to_string();
    }
    let mut notes = Vec::new();
    if unauthorized {
        notes.push("检测到非官方进程疑似复用 OAuth 凭据".to_string());
    }
    if robotic {
        notes.push("检测到机械定频节律（CV < 0.04）".to_string());
    }
    if prompts_1m > cfg.throttle_rpm || prompts_15m > cfg.max_15m_prompts {
        notes.push(format!("突发超限（1m:{prompts_1m} / 15m:{prompts_15m}）"));
    } else if prompts_1m >= cfg.warn_rpm {
        notes.push(format!("高频预警（1m:{prompts_1m} / 15m:{prompts_15m}）"));
    }
    if notes.is_empty() {
        format!("节律正常（1m:{prompts_1m} / 15m:{prompts_15m}）")
    } else {
        notes.join("；")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_human_cadence_is_allowed_and_not_robotic() {
        let mut tracker = BurstGuardTracker::new();
        let cfg = BurstGuardConfig::default();
        // Irregular human intervals in ms
        let timestamps = [
            1_000_000, 1_012_400, 1_019_100, 1_048_500, 1_055_200, 1_094_000, 1_102_300, 1_140_800,
            1_152_900, 1_199_400,
        ];
        let mut last = None;
        for ts in timestamps {
            last = Some(tracker.record_and_evaluate("claude-code", None, ts, &cfg));
        }
        let eval = last.unwrap();
        assert_eq!(eval.verdict, BurstVerdict::Allow);
        assert_eq!(eval.hook_decision, HookDecision::Allow);
        assert!(!eval.status.robotic_cadence_detected);
        let (_, cv) = compute_cadence_cv(&timestamps).unwrap();
        assert!(cv > 0.2);
    }

    #[test]
    fn mechanical_fixed_cadence_triggers_robotic_detection_at_8_plus_intervals() {
        let mut tracker = BurstGuardTracker::new();
        let cfg = BurstGuardConfig::default();

        // 8 timestamps = 7 intervals -> not yet >= 8 intervals
        let mut ts = 1_000_000u64;
        for _ in 0..8 {
            let eval = tracker.record_and_evaluate("claude-code", Some("work"), ts, &cfg);
            assert!(!eval.status.robotic_cadence_detected);
            ts += 10_000;
        }

        // 9th timestamp = 8 intervals, exact 10,000ms spacing -> CV = 0.0 < 0.04 -> robotic!
        let eval9 = tracker.record_and_evaluate("claude-code", Some("work"), ts, &cfg);
        assert!(eval9.status.robotic_cadence_detected);
        assert_eq!(eval9.verdict, BurstVerdict::Warn);
        assert_eq!(eval9.hook_decision, HookDecision::Allow);

        // Slow cadence (mean >= 120,000ms) is NOT flagged as robotic burst
        let slow: Vec<u64> = (0..10).map(|i| 1_000_000 + i * 130_000).collect();
        let metrics = compute_cadence_metrics(&slow).unwrap();
        assert!(!metrics.robotic);
    }

    #[test]
    fn throttle_gate_blocks_on_1m_and_15m_overflow_while_warn_only_allows() {
        let cfg_throttle = BurstGuardConfig {
            mode: BurstGuardMode::ThrottleGate,
            warn_rpm: 18,
            throttle_rpm: 30,
            max_15m_prompts: 180,
        };
        let mut tracker = BurstGuardTracker::new();

        // Submit 30 prompts within 1m (irregular spacing so cadence is non-robotic)
        let mut ts = 5_000_000u64;
        for i in 0..30 {
            ts += if i % 2 == 0 { 800 } else { 1_900 };
            let eval = tracker.record_and_evaluate("claude-code", None, ts, &cfg_throttle);
            assert_eq!(eval.hook_decision, HookDecision::Allow);
            if i + 1 >= 18 {
                assert_eq!(eval.verdict, BurstVerdict::Warn);
            }
        }

        // 31st prompt exceeds throttle_rpm=30 -> Throttle + Block without polluting window!
        let eval31 = tracker.record_and_evaluate("claude-code", None, ts + 500, &cfg_throttle);
        assert_eq!(eval31.verdict, BurstVerdict::Throttle);
        assert_eq!(eval31.hook_decision, HookDecision::Block);
        assert_eq!(eval31.status.prompts_last_1m, 31);

        // Even 200 rapid blocked retries must NOT inflate the 15m window into a self-extending lockout.
        for retry in 1..=200 {
            let blocked_retry = tracker.record_and_evaluate(
                "claude-code",
                None,
                ts + 500 + retry * 10,
                &cfg_throttle,
            );
            assert_eq!(blocked_retry.hook_decision, HookDecision::Block);
        }

        // Same bucket under WarnOnly allows (non-blocking)
        let cfg_warn = BurstGuardConfig {
            mode: BurstGuardMode::WarnOnly,
            ..cfg_throttle.clone()
        };
        let eval_warn = tracker.evaluate_only("claude-code", None, ts + 500, &cfg_warn);
        assert_eq!(eval_warn.verdict, BurstVerdict::Warn);
        assert_eq!(eval_warn.hook_decision, HookDecision::Allow);

        // Same bucket under Off allows cleanly
        let cfg_off = BurstGuardConfig {
            mode: BurstGuardMode::Off,
            ..cfg_throttle.clone()
        };
        let eval_off = tracker.evaluate_only("claude-code", None, ts + 500, &cfg_off);
        assert_eq!(eval_off.verdict, BurstVerdict::Allow);
        assert_eq!(eval_off.hook_decision, HookDecision::Allow);

        // After 61s, 1m window expires cleanly with only the 30 permitted prompts retained
        let eval_after = tracker.evaluate_only("claude-code", None, ts + 65_000, &cfg_throttle);
        assert_eq!(eval_after.status.prompts_last_1m, 0);
        assert_eq!(eval_after.status.prompts_last_15m, 30);
        assert_eq!(eval_after.hook_decision, HookDecision::Allow);
    }

    #[test]
    fn fatigue_15m_cap_blocks_and_tracks_oauth_hijack_processes() {
        let cfg = BurstGuardConfig {
            mode: BurstGuardMode::ThrottleGate,
            warn_rpm: 18,
            throttle_rpm: 30,
            max_15m_prompts: 40,
        };
        let mut tracker = BurstGuardTracker::new();

        // Spread 41 prompts over 10 minutes (well below 1m rpm, exceeds 15m cap=40)
        let mut ts = 10_000_000u64;
        for i in 0..40 {
            ts += if i % 2 == 0 { 10_000 } else { 20_000 };
            let ev = tracker.record_and_evaluate("claude-code", None, ts, &cfg);
            assert_eq!(ev.hook_decision, HookDecision::Allow);
        }
        let blocked = tracker.record_and_evaluate("claude-code", None, ts + 12_000, &cfg);
        assert_eq!(blocked.verdict, BurstVerdict::Throttle);
        assert_eq!(blocked.hook_decision, HookDecision::Block);

        // Unauthorized OAuth client processes block under ThrottleGate and warn under WarnOnly.
        tracker.set_suspicious_oauth_processes(vec!["rogue-proxy.exe".into()]);
        let oauth_blocked = tracker.evaluate_only("claude-code", None, ts + 15_000, &cfg);
        assert_eq!(oauth_blocked.verdict, BurstVerdict::Throttle);
        assert_eq!(oauth_blocked.hook_decision, HookDecision::Block);
        assert!(oauth_blocked.status.unauthorized_oauth_client_detected);
        assert_eq!(
            oauth_blocked.status.suspicious_processes,
            vec!["rogue-proxy.exe"]
        );

        let cfg_warn = BurstGuardConfig {
            mode: BurstGuardMode::WarnOnly,
            ..cfg.clone()
        };
        let oauth_warn = tracker.evaluate_only("claude-code", None, ts + 15_000, &cfg_warn);
        assert_eq!(oauth_warn.verdict, BurstVerdict::Warn);
        assert_eq!(oauth_warn.hook_decision, HookDecision::Allow);
        assert!(oauth_warn.status.unauthorized_oauth_client_detected);

        let agg = tracker.overall_status(ts + 12_000, &cfg);
        assert_eq!(agg.prompts_last_15m, 40);
        assert!(agg.unauthorized_oauth_client_detected);

        tracker.prune(ts + WINDOW_15M_MS + 60_000);
        let after_prune = tracker.overall_status(ts + WINDOW_15M_MS + 60_000, &cfg);
        assert_eq!(after_prune.prompts_last_15m, 0);
    }
}
