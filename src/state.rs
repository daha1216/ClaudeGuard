//! 全局运行状态（`AppState`）：配置、目标状态、熔断态、日志环、更新状态与事件。
//!
//! 所有跨线程状态集中在这里；UI 只通过 `guard://state` 事件和 `get_state` 命令取快照。

use crate::config::{Config, NotifyPrefs};
use crate::model::{
    AgentCount, CutMode, Overall, TargetState, TargetStatus, TripInfo, UpdState, VERSION,
};
use crate::notify;
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use tauri::{AppHandle, Emitter};

pub const EV_STATE: &str = "guard://state";
pub const EV_LOG: &str = "guard://log";
const LOG_RING: usize = 200;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StateView {
    pub checking: bool,
    pub checked_at: Option<u64>,
    pub interval_secs: u64,
    pub trip_threshold: u32,
    pub overall: Overall,
    pub targets: Vec<TargetStatus>,
    pub tripped: Option<TripInfo>,
    pub paused_until: Option<u64>,
    pub admin: bool,
    pub installed: bool,
    pub version: &'static str,
    pub upd: UpdState,
    pub feishu: crate::feishu::Status,
    pub claude_update: crate::claude_update::Status,
    pub codex_update: crate::claude_update::Status,
    pub agents_running: Vec<AgentCount>,
    pub cli_running: Vec<String>,
    pub launch_error: String,
    pub smoke_settings: bool,
    pub notify_enabled: bool,
    pub cut_mode: CutMode,
}

pub struct AppState {
    pub app: AppHandle,
    pub cfg: Mutex<Config>,
    pub statuses: Mutex<Vec<TargetStatus>>,
    pub checking: AtomicBool,
    pub last_check: Mutex<Option<u64>>,
    pub tripped: Mutex<Option<TripInfo>>,
    pub paused_until: Mutex<Option<u64>>,
    pub logs: Mutex<VecDeque<String>>,
    pub upd: Mutex<UpdState>,
    pub feishu: Arc<crate::feishu::Notifier>,
    pub claude_update: crate::claude_update::Updater,
    pub codex_update: crate::claude_update::Updater,
    pub launch_error: Mutex<String>,
    pub stop: Arc<AtomicBool>,
    pub is_admin: bool,
    pub smoke_settings: bool,
}

impl AppState {
    pub fn new(app: AppHandle) -> Arc<Self> {
        let cfg = Config::load();
        let smoke_settings = std::env::var("CG_SMOKE_SETTINGS").ok().as_deref() == Some("1");
        let statuses: Vec<TargetStatus> = cfg
            .targets
            .iter()
            .map(|t| {
                let state = if t.enabled {
                    TargetState::Pending
                } else {
                    TargetState::Disabled
                };
                TargetStatus::from_target(t, state)
            })
            .collect();
        let is_admin = crate::guard::is_admin();
        Arc::new(Self {
            app,
            statuses: Mutex::new(statuses),
            cfg: Mutex::new(cfg),
            checking: AtomicBool::new(false),
            last_check: Mutex::new(None),
            tripped: Mutex::new(None),
            paused_until: Mutex::new(None),
            logs: Mutex::new(VecDeque::with_capacity(LOG_RING)),
            upd: Mutex::new(UpdState::Idle),
            feishu: Arc::new(crate::feishu::Notifier::load()),
            claude_update: crate::claude_update::Updater::load(
                crate::claude_update::Product::Claude,
            ),
            codex_update: crate::claude_update::Updater::load(crate::claude_update::Product::Codex),
            launch_error: Mutex::new(String::new()),
            stop: Arc::new(AtomicBool::new(false)),
            is_admin,
            smoke_settings,
        })
    }

    // ---------- 配置 ----------

    pub fn config(&self) -> Config {
        lock(&self.cfg).clone()
    }

    pub fn set_config(&self, cfg: Config) {
        *lock(&self.cfg) = cfg;
    }

    // ---------- 目标状态 ----------

    pub fn statuses(&self) -> Vec<TargetStatus> {
        lock(&self.statuses).clone()
    }

    pub fn set_statuses(&self, statuses: Vec<TargetStatus>) {
        *lock(&self.statuses) = statuses;
    }

    pub fn reset_statuses_from_config(&self) {
        let cfg = self.config();
        lock(&self.statuses).clear();
        let mut statuses = lock(&self.statuses);
        for t in &cfg.targets {
            let state = if t.enabled {
                TargetState::Pending
            } else {
                TargetState::Disabled
            };
            statuses.push(TargetStatus::from_target(t, state));
        }
    }

    pub fn clear_streaks(&self) {
        for status in lock(&self.statuses).iter_mut() {
            status.fail_streak = 0;
        }
    }

    // ---------- 熔断 / 暂停 / 检查 ----------

    pub fn tripped(&self) -> Option<TripInfo> {
        lock(&self.tripped).clone()
    }

    pub fn set_tripped(&self, trip: Option<TripInfo>) {
        *lock(&self.tripped) = trip;
    }

    pub fn is_tripped(&self) -> bool {
        lock(&self.tripped).is_some()
    }

    pub fn paused_until(&self) -> Option<u64> {
        let until = *lock(&self.paused_until);
        until.filter(|until| *until > crate::model::now())
    }

    pub fn is_paused(&self) -> bool {
        self.paused_until().is_some()
    }

    pub fn set_paused_until(&self, until: Option<u64>) {
        *lock(&self.paused_until) = until;
    }

    pub fn set_checking(&self, on: bool) {
        self.checking.store(on, Ordering::SeqCst);
    }

    pub fn is_checking(&self) -> bool {
        self.checking.load(Ordering::SeqCst)
    }

    pub fn set_last_check(&self, ts: u64) {
        *lock(&self.last_check) = Some(ts);
    }

    pub fn last_check(&self) -> Option<u64> {
        *lock(&self.last_check)
    }

    // ---------- 更新状态 ----------

    pub fn upd(&self) -> UpdState {
        lock(&self.upd).clone()
    }

    pub fn set_upd(&self, upd: UpdState) {
        *lock(&self.upd) = upd;
    }

    pub fn launch_error(&self) -> String {
        lock(&self.launch_error).clone()
    }

    pub fn set_launch_error(&self, msg: impl Into<String>) {
        *lock(&self.launch_error) = msg.into();
    }

    // ---------- 日志 ----------

    /// 写日志文件 + 内存环 + 推 UI 事件。
    pub fn log(&self, msg: impl AsRef<str>) {
        let line = msg.as_ref().to_string();
        crate::guard::log_line(&line);
        {
            let mut logs = lock(&self.logs);
            if logs.len() >= LOG_RING {
                logs.pop_front();
            }
            logs.push_back(format!("{} {line}", crate::model::now()));
        }
        let _ = self.app.emit(EV_LOG, line);
    }

    pub fn recent_logs(&self, limit: usize) -> Vec<String> {
        let logs = lock(&self.logs);
        let skip = logs.len().saturating_sub(limit);
        logs.iter().skip(skip).cloned().collect()
    }

    // ---------- 整体状态 ----------

    pub fn overall(&self) -> Overall {
        if self.is_tripped() {
            return Overall::Tripped;
        }
        if self.is_paused() {
            return Overall::Paused;
        }
        if self.is_checking() {
            return Overall::Checking;
        }
        let statuses = lock(&self.statuses);
        let enabled: Vec<&TargetStatus> = statuses
            .iter()
            .filter(|s| s.state != TargetState::Disabled)
            .collect();
        if enabled.is_empty() {
            return Overall::Idle;
        }
        if enabled.iter().any(|s| s.state == TargetState::Fail) {
            return Overall::Fail;
        }
        let passed = enabled
            .iter()
            .filter(|s| s.state == TargetState::Pass)
            .count();
        if passed == enabled.len() {
            Overall::Pass
        } else {
            Overall::Idle
        }
    }

    // ---------- 通知 ----------

    pub fn notify(&self, class: &str, title: &str, body: &str) -> bool {
        let prefs: NotifyPrefs = self.config().notify;
        // 客户端更新与 v2 一致走双通道：桌面通知 + 飞书队列（飞书是否真的发由 Notifier 的 enabled 决定）。
        if class == "client_update" {
            self.feishu.notify(&format!("{title}\n{body}"));
        }
        notify::send(&prefs, class, title, body)
    }

    // ---------- 快照 / 事件 ----------

    pub fn state_view(&self) -> StateView {
        let cfg = self.config();
        let statuses = self.statuses();
        let (agents_running, cli_running) = agent_usage();
        StateView {
            checking: self.is_checking(),
            checked_at: self.last_check(),
            interval_secs: cfg.interval_secs(),
            trip_threshold: cfg.trip_threshold,
            overall: self.overall(),
            targets: statuses,
            tripped: self.tripped(),
            paused_until: self.paused_until(),
            admin: self.is_admin,
            installed: crate::install::is_installed(),
            version: VERSION,
            upd: self.upd(),
            feishu: self.feishu.status(),
            claude_update: self.claude_update.status(),
            codex_update: self.codex_update.status(),
            agents_running,
            cli_running,
            launch_error: self.launch_error(),
            smoke_settings: self.smoke_settings,
            notify_enabled: cfg.notify.enabled,
            cut_mode: cfg.cut_mode(),
        }
    }

    pub fn emit_state(&self) {
        let view = self.state_view();
        let _ = self.app.emit(EV_STATE, view);
    }
}

fn agent_usage() -> (Vec<AgentCount>, Vec<String>) {
    let scan = crate::guard::scan_agents();
    let running = scan
        .gui
        .iter()
        .filter(|(_, count)| *count > 0)
        .map(|(def, count)| AgentCount {
            id: def.id.to_string(),
            name: def.name.to_string(),
            count: *count,
        })
        .collect();
    let cli = scan
        .cli
        .iter()
        .filter(|(_, count)| *count > 0)
        .map(|(id, _)| crate::guard::cli_agent_name(id).to_string())
        .collect();
    (running, cli)
}

#[cfg(test)]
mod tests {
    use crate::model::{Overall, TargetState};

    /// overall 的纯逻辑（不依赖 AppState/AppHandle）：与 AppState::overall 保持一致。
    fn overall_of(tripped: bool, paused: bool, checking: bool, states: &[TargetState]) -> Overall {
        if tripped {
            return Overall::Tripped;
        }
        if paused {
            return Overall::Paused;
        }
        if checking {
            return Overall::Checking;
        }
        let enabled: Vec<TargetState> = states
            .iter()
            .copied()
            .filter(|s| *s != TargetState::Disabled)
            .collect();
        if enabled.is_empty() {
            return Overall::Idle;
        }
        if enabled.contains(&TargetState::Fail) {
            return Overall::Fail;
        }
        let passed = enabled.iter().filter(|s| **s == TargetState::Pass).count();
        if passed == enabled.len() {
            Overall::Pass
        } else {
            Overall::Idle
        }
    }

    #[test]
    fn overall_prioritizes_trip_and_pause() {
        assert_eq!(overall_of(true, true, true, &[]), Overall::Tripped);
        assert_eq!(overall_of(false, true, true, &[]), Overall::Paused);
        assert_eq!(overall_of(false, false, true, &[]), Overall::Checking);
    }

    #[test]
    fn overall_pass_requires_all_enabled_pass() {
        assert_eq!(
            overall_of(false, false, false, &[TargetState::Pass, TargetState::Pass]),
            Overall::Pass
        );
        assert_eq!(
            overall_of(
                false,
                false,
                false,
                &[TargetState::Pass, TargetState::Unverified]
            ),
            Overall::Idle
        );
        assert_eq!(
            overall_of(false, false, false, &[TargetState::Pass, TargetState::Fail]),
            Overall::Fail
        );
    }

    #[test]
    fn overall_idle_when_nothing_enabled() {
        assert_eq!(
            overall_of(false, false, false, &[TargetState::Disabled]),
            Overall::Idle
        );
    }
}
