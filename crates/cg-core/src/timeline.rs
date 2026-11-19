//! 24-hour rolling ring-bucket timeline aggregator (48 or 96 buckets), serializable across restarts.

use cg_protocol::{PolicyVerdict, ProtectionState, TimelineBucket, TimelineStatus};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

pub const SECONDS_PER_DAY: u64 = 86_400;
pub const BUCKETS_48: usize = 48;
pub const BUCKETS_96: usize = 96;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct BucketAccum {
    bucket: TimelineBucket,
    latency_sum_ms: u64,
}

/// 24-hour fixed-resolution timeline aggregator persisted across daemon restarts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineAggregator {
    bucket_count: usize,
    bucket_secs: u32,
    buckets: BTreeMap<u64, BucketAccum>,
}

impl Default for TimelineAggregator {
    fn default() -> Self {
        Self::new(BUCKETS_48)
    }
}

impl TimelineAggregator {
    /// Creates an aggregator with either 48 (30-min) or 96 (15-min) buckets spanning 24 hours.
    /// Any other count snaps to 48 or 96 (>= 72 -> 96, else 48).
    pub fn new(bucket_count: usize) -> Self {
        let count = if bucket_count >= 72 {
            BUCKETS_96
        } else {
            BUCKETS_48
        };
        let bucket_secs = (SECONDS_PER_DAY / count as u64) as u32;
        Self {
            bucket_count: count,
            bucket_secs,
            buckets: BTreeMap::new(),
        }
    }

    pub fn bucket_count(&self) -> usize {
        self.bucket_count
    }

    pub fn bucket_secs(&self) -> u32 {
        self.bucket_secs
    }

    /// Aligns an arbitrary Unix timestamp down to the enclosing bucket boundary.
    pub fn align_ts(&self, now_secs: u64) -> u64 {
        let step = u64::from(self.bucket_secs);
        (now_secs / step) * step
    }

    /// Records a check/protection observation into the bucket enclosing `now_secs` and prunes >24h history.
    pub fn record(
        &mut self,
        now_secs: u64,
        protection: ProtectionState,
        verdict: Option<PolicyVerdict>,
        latency_ms: u64,
    ) {
        let start = self.align_ts(now_secs);
        let bucket_secs = self.bucket_secs;
        let entry = self.buckets.entry(start).or_insert_with(|| BucketAccum {
            bucket: TimelineBucket::empty(start, bucket_secs),
            latency_sum_ms: 0,
        });

        entry.bucket.total_checks = entry.bucket.total_checks.saturating_add(1);
        entry.latency_sum_ms = entry.latency_sum_ms.saturating_add(latency_ms);
        entry.bucket.max_latency_ms = entry.bucket.max_latency_ms.max(latency_ms);
        entry.bucket.avg_latency_ms =
            entry.latency_sum_ms / u64::from(entry.bucket.total_checks.max(1));

        let is_fail = matches!(
            protection,
            ProtectionState::Isolating | ProtectionState::Quarantined | ProtectionState::GlobalCut
        ) || verdict == Some(PolicyVerdict::Fail);
        let is_warn = matches!(
            protection,
            ProtectionState::Degraded
                | ProtectionState::NetworkReadyAppHeld
                | ProtectionState::Recovering
        ) || verdict == Some(PolicyVerdict::Unverified);

        if is_fail {
            entry.bucket.fail_count = entry.bucket.fail_count.saturating_add(1);
        } else if is_warn {
            entry.bucket.warn_count = entry.bucket.warn_count.saturating_add(1);
        } else if verdict == Some(PolicyVerdict::Pass) || protection == ProtectionState::Monitoring
        {
            entry.bucket.pass_count = entry.bucket.pass_count.saturating_add(1);
        }

        entry.bucket.status = if entry.bucket.fail_count > 0 {
            TimelineStatus::Fail
        } else if entry.bucket.warn_count > 0 {
            TimelineStatus::Warn
        } else if entry.bucket.pass_count > 0 {
            TimelineStatus::Pass
        } else {
            TimelineStatus::Empty
        };

        self.prune_before(start);
    }

    fn prune_before(&mut self, current_bucket_start: u64) {
        let span = (self.bucket_count as u64).saturating_sub(1) * u64::from(self.bucket_secs);
        let oldest_keep = current_bucket_start.saturating_sub(span);
        self.buckets.retain(|&ts, _| ts >= oldest_keep);
    }

    /// Produces a chronological fixed-length (`48` or `96`) slice covering the 24h window ending at `now_secs`.
    pub fn snapshot(&self, now_secs: u64) -> Vec<TimelineBucket> {
        let current = self.align_ts(now_secs);
        let step = u64::from(self.bucket_secs);
        let first = current.saturating_sub((self.bucket_count as u64 - 1) * step);
        let mut out = Vec::with_capacity(self.bucket_count);
        for idx in 0..self.bucket_count {
            let start = first + (idx as u64) * step;
            if let Some(acc) = self.buckets.get(&start) {
                out.push(acc.bucket.clone());
            } else {
                out.push(TimelineBucket::empty(start, self.bucket_secs));
            }
        }
        out
    }

    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| format!("timeline serialize failed: {e}"))
    }

    pub fn from_json(raw: &str) -> Result<Self, String> {
        let mut parsed: Self =
            serde_json::from_str(raw.trim()).map_err(|e| format!("timeline parse failed: {e}"))?;
        if parsed.bucket_count != BUCKETS_48 && parsed.bucket_count != BUCKETS_96 {
            parsed.bucket_count = BUCKETS_48;
            parsed.bucket_secs = 1800;
        }
        Ok(parsed)
    }

    /// Atomically persists the timeline ring buffer to `path`.
    pub fn save_to(&self, path: &Path) -> Result<(), String> {
        let dir = path
            .parent()
            .ok_or_else(|| "timeline path has no parent directory".to_string())?;
        std::fs::create_dir_all(dir).map_err(|e| format!("create timeline dir failed: {e}"))?;
        let text = self.to_json()?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, text.as_bytes())
            .map_err(|e| format!("write timeline temp failed: {e}"))?;
        std::fs::rename(&tmp, path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("commit timeline failed: {e}")
        })
    }

    /// Loads persisted 24h timeline from `path` (returning empty aggregator if missing or invalid).
    pub fn load_from(path: &Path, default_buckets: usize) -> Self {
        match std::fs::read_to_string(path) {
            Ok(raw) => Self::from_json(&raw).unwrap_or_else(|_| Self::new(default_buckets)),
            Err(_) => Self::new(default_buckets),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeline_produces_fixed_48_or_96_buckets_and_rolls_over_24h() {
        let mut tl = TimelineAggregator::new(48);
        assert_eq!(tl.bucket_count(), 48);
        assert_eq!(tl.bucket_secs(), 1800);

        let t0 = 1_700_000_400; // aligned to 1800s boundary: 1_699_999_200
        tl.record(
            t0,
            ProtectionState::Monitoring,
            Some(PolicyVerdict::Pass),
            40,
        );
        tl.record(
            t0 + 10,
            ProtectionState::Monitoring,
            Some(PolicyVerdict::Pass),
            60,
        );
        let snap1 = tl.snapshot(t0 + 10);
        assert_eq!(snap1.len(), 48);
        let last = snap1.last().unwrap();
        assert_eq!(last.total_checks, 2);
        assert_eq!(last.pass_count, 2);
        assert_eq!(last.avg_latency_ms, 50);
        assert_eq!(last.max_latency_ms, 60);
        assert_eq!(last.status, TimelineStatus::Pass);

        // Fail dominates Warn and Pass in the same bucket.
        tl.record(
            t0 + 20,
            ProtectionState::Quarantined,
            Some(PolicyVerdict::Fail),
            90,
        );
        assert_eq!(
            tl.snapshot(t0 + 20).last().unwrap().status,
            TimelineStatus::Fail
        );

        // Advance > 24h -> old bucket pruned.
        let t_later = t0 + SECONDS_PER_DAY + 3600;
        tl.record(
            t_later,
            ProtectionState::Monitoring,
            Some(PolicyVerdict::Unverified),
            10,
        );
        let snap_later = tl.snapshot(t_later);
        assert_eq!(snap_later.len(), 48);
        assert_eq!(snap_later.last().unwrap().status, TimelineStatus::Warn);
        assert_eq!(snap_later.iter().filter(|b| b.total_checks > 0).count(), 1);
    }

    #[test]
    fn timeline_serializes_and_restores_96_buckets() {
        let mut tl = TimelineAggregator::new(96);
        assert_eq!(tl.bucket_count(), 96);
        assert_eq!(tl.bucket_secs(), 900);
        let t = 1_700_001_000;
        tl.record(
            t,
            ProtectionState::Monitoring,
            Some(PolicyVerdict::Pass),
            25,
        );
        let raw = tl.to_json().expect("serialize");
        let restored = TimelineAggregator::from_json(&raw).expect("restore");
        assert_eq!(restored.bucket_count(), 96);
        assert_eq!(restored.snapshot(t).len(), 96);
        assert_eq!(restored.snapshot(t).last().unwrap().pass_count, 1);
    }

    #[test]
    fn timeline_saves_and_loads_from_disk_across_restarts() {
        let dir = std::env::temp_dir().join("cg-v4-timeline-test");
        let _ = std::fs::remove_dir_all(&dir);
        let file = dir.join("timeline.json");

        let mut tl = TimelineAggregator::new(48);
        let t = 1_700_002_000;
        tl.record(
            t,
            ProtectionState::Monitoring,
            Some(PolicyVerdict::Pass),
            30,
        );
        tl.record(
            t + 1800,
            ProtectionState::Degraded,
            Some(PolicyVerdict::Unverified),
            50,
        );
        tl.save_to(&file).expect("save timeline");
        assert!(file.exists());
        assert!(!file.with_extension("json.tmp").exists());

        let loaded = TimelineAggregator::load_from(&file, 48);
        let snap = loaded.snapshot(t + 1800);
        assert_eq!(snap.len(), 48);
        assert_eq!(snap[46].status, TimelineStatus::Pass);
        assert_eq!(snap[47].status, TimelineStatus::Warn);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
