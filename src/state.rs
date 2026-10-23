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
    pub platform: &'static str,
    pub network_isolation_supported: bool,
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
    pub guarded_agents: Vec<String>,
    pub access: crate::access::AccessInfo,
    pub enforce_access: bool,
    pub lockdown: bool,
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
    pub access: Mutex<crate::access::AccessInfo>,
    pub access_streak: std::sync::atomic::AtomicU32,
    /// v3.9 兜底封锁：上次同步到防火墙的意图（None=启动后未同步过，首轮会强制对齐）。
    pub lockdown_last: Mutex<Option<bool>>,
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
            access: Mutex::new(crate::access::AccessInfo {
                path: "skipped".into(),
                note: "尚未检测".into(),
            }),
            access_streak: std::sync::atomic::AtomicU32::new(0),
            lockdown_last: Mutex::new(None),
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
        self.access_streak.store(0, Ordering::SeqCst);
    }

    // ---------- 接入路径（v3.7） ----------

    pub fn set_access(&self, access: crate::access::AccessInfo) {
        *lock(&self.access) = access;
    }

    pub fn access(&self) -> crate::access::AccessInfo {
        lock(&self.access).clone()
    }

    /// 未接入计数 +1，返回当前值。
    pub fn bump_access_streak(&self) -> u32 {
        self.access_streak.fetch_add(1, Ordering::SeqCst) + 1
    }

    pub fn reset_access_streak(&self) {
        self.access_streak.store(0, Ordering::SeqCst);
    }

    // ---------- 防火墙兜底封锁（v3.9） ----------

    /// 兜底封锁当前是否生效（按已同步到防火墙的意图）。
    pub fn lockdown_on(&self) -> bool {
        *lock(&self.lockdown_last) == Some(true)
    }

    /// 把"想要的状态"同步到防火墙：只在意图变化时增删规则（避免每轮重复 add 堆积）。
    /// 启动后首轮 `last=None` 必然不同步状态——顺带清理崩溃残留或补上未接入封锁。
    pub fn sync_lockdown(&self, want: bool, cfg: &Config) {
        let mut last = lock(&self.lockdown_last);
        if *last == Some(want) {
            return;
        }
        if want {
            let n = crate::guard::lockdown_apply(cfg);
            self.log(format!(
                "防火墙兜底：已封锁守护对象出站（{n} 条规则）；走系统代理不受影响，接入后自动解除"
            ));
        } else {
            crate::guard::lockdown_clear();
            self.log("防火墙兜底：已解除出站封锁");
        }
        *last = Some(want);
    }

    /// 手动一键：立即封锁（无视接入状态；自动逻辑之后按接入状态接管）。
    pub fn lockdown_now(&self, on: bool, cfg: &Config) {
        if on {
            let n = crate::guard::lockdown_apply(cfg);
            self.log(format!("手动封锁：已添加 {n} 条出站封锁规则"));
            *lock(&self.lockdown_last) = Some(true);
        } else {
            crate::guard::lockdown_clear();
            self.log("手动解除：已删除全部出站封锁规则");
            *lock(&self.lockdown_last) = Some(false);
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
            platform: std::env::consts::OS,
            network_isolation_supported: cfg!(windows),
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
            cut_mode: if cfg!(target_os = "macos") {
                CutMode::Off
            } else {
                cfg.cut_mode()
            },
            guarded_agents: cfg.guarded_agents.clone(),
            access: self.access(),
            enforce_access: cfg!(target_os = "windows") && cfg.enforce_access_path,
            lockdown: self.lockdown_on(),
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
