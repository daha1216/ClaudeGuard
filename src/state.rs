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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
    /// v3.10 R12：持久错误（配置保存失败等），UI 以横幅常驻直到下一次成功操作。
    pub last_error: String,
    pub smoke_settings: bool,
    pub notify_enabled: bool,
    pub cut_mode: CutMode,
    pub guarded_agents: Vec<String>,
    pub access: crate::access::AccessInfo,
    pub enforce_access: bool,
    pub lockdown: bool,
    /// v3.10 R13：手动封锁是否由用户开启（独立生命周期）。
    pub lockdown_manual: bool,
    /// v3.10 R06：用户已要求停止保护（只检测，不动作）。
    pub disarmed: bool,
    pub disarmed_reason: String,
}

/// 本进程的启动代次（启动时间 + PID）。账本用它区分"上一代留下的现场"。
pub fn generation_id() -> String {
    use std::sync::OnceLock;
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| format!("{}-{}", crate::model::now(), std::process::id()))
        .clone()
}

pub struct AppState {
    pub app: AppHandle,
    pub cfg: Mutex<Config>,
    pub statuses: Mutex<Vec<TargetStatus>>,
    pub checking: AtomicBool,
    /// R10：配置代次（每次 set_config +1），用于丢弃过期轮次的结果。
    pub cfg_rev: AtomicU64,
    /// R10：熔断执行权——同一时刻只允许一轮真正执行熔断（杀进程/断网/隔离）。
    pub trip_guard: Mutex<()>,
    pub last_check: Mutex<Option<u64>>,
    pub tripped: Mutex<Option<TripInfo>>,
    pub paused_until: Mutex<Option<u64>>,
    pub logs: Mutex<VecDeque<String>>,
    pub upd: Mutex<UpdState>,
    pub feishu: Arc<crate::feishu::Notifier>,
    pub claude_update: crate::claude_update::Updater,
    pub codex_update: crate::claude_update::Updater,
    pub launch_error: Mutex<String>,
    /// v3.10 R12：持久错误——保存失败等"操作未生效"的原因，成功后再清除。
    pub last_error: Mutex<String>,
    pub access: Mutex<crate::access::AccessInfo>,
    pub access_streak: std::sync::atomic::AtomicU32,
    /// v3.9 兜底封锁：上次同步到防火墙的意图（None=启动后未同步过，首轮会强制对齐）。
    pub lockdown_last: Mutex<Option<bool>>,
    /// v3.10 R13：用户手动封锁意图（独立生命周期，不被下一轮自动逻辑覆盖）。
    pub lockdown_manual: Mutex<bool>,
    /// v3.10 R06：用户要求停止保护（`--restore` 急救或界面手动停止）。
    /// 存在时守护器只做检测，不再 kill/隔离/断网/封锁，也不拦截启动。
    pub disarmed: Mutex<Option<String>>,
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
            cfg_rev: AtomicU64::new(0),
            trip_guard: Mutex::new(()),
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
            last_error: Mutex::new(String::new()),
            access: Mutex::new(crate::access::AccessInfo {
                path: "skipped".into(),
                note: "尚未检测".into(),
            }),
            access_streak: std::sync::atomic::AtomicU32::new(0),
            lockdown_last: Mutex::new(None),
            lockdown_manual: Mutex::new(false),
            disarmed: Mutex::new(crate::disarm::reason()),
            stop: Arc::new(AtomicBool::new(false)),
            is_admin,
            smoke_settings,
        })
    }

    // ---------- 配置 ----------

    pub fn config(&self) -> Config {
        lock(&self.cfg).clone()
    }

    /// 配置代次：每次配置变更 +1。轮次开始时记下代次，提交结果前比对，
    /// 代次变了就说明"这一轮依据的配置已经过期"，结果不得提交（R10）。
    pub fn cfg_rev(&self) -> u64 {
        self.cfg_rev.load(Ordering::SeqCst)
    }

    pub fn set_config(&self, cfg: Config) {
        *lock(&self.cfg) = cfg;
        self.cfg_rev.fetch_add(1, Ordering::SeqCst);
    }

    /// 一次拿到"配置 + 代次"，保证两者来自同一时刻。
    pub fn config_rev(&self) -> (Config, u64) {
        let cfg = lock(&self.cfg).clone();
        (cfg, self.cfg_rev.load(Ordering::SeqCst))
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

    /// UI 用：手动封锁是否处于用户开启状态。
    pub fn lockdown_manual_on(&self) -> bool {
        self.lockdown_manual()
    }

    /// 用户是否手动要求封锁（R13：手动意图独立于接入状态）。
    pub fn lockdown_manual(&self) -> bool {
        *lock(&self.lockdown_manual)
    }

    /// R13：本轮应同步到的封锁意图 = 自动策略 ∨ 用户手动封锁。
    ///
    /// 手动意图独立于接入状态，因此不会被"接入恢复"的下一轮自动逻辑清除。
    pub fn desired_lockdown(auto_want: bool, manual: bool) -> bool {
        auto_want || manual
    }

    /// R13 + D3：暂停期间只允许"减少副作用"的同步（解除），不允许新增封锁；
    /// 已经处于封锁时保持原样（幂等）。
    pub fn lockdown_sync_allowed(paused: bool, current: Option<bool>, want: bool) -> bool {
        !(paused && want && current != Some(true))
    }

    /// 把"想要的状态"同步到防火墙：只在意图变化时增删规则（避免每轮重复 add 堆积）。
    /// 启动后首轮 `last=None` 必然不同步状态——顺带清理崩溃残留或补上未接入封锁。
    ///
    /// 暂停期间不新增副作用（CONTRACT D3）：暂停时不施加封锁，但**也不解除**既有封锁。
    pub fn sync_lockdown(&self, want: bool, cfg: &Config) {
        // R13：手动封锁优先，且不被自动逻辑（接入状态变化）清除。
        let want = Self::desired_lockdown(want, self.lockdown_manual());
        let mut last = lock(&self.lockdown_last);
        if *last == Some(want) {
            return;
        }
        if !Self::lockdown_sync_allowed(self.is_paused(), *last, want) {
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

    /// 手动一键：立即封锁 / 解除封锁。
    ///
    /// R13：手动封锁意图有独立生命周期——开启后一直保持，直到用户手动解除；
    /// 自动逻辑（未接入时维持封锁）只在没有手动意图时生效。解除手动封锁后
    /// 由下一轮自动逻辑按接入状态接管。
    pub fn lockdown_now(&self, on: bool, cfg: &Config) {
        if on {
            let n = crate::guard::lockdown_apply(cfg);
            *lock(&self.lockdown_manual) = true;
            self.log(format!(
                "手动封锁：已添加 {n} 条出站封锁规则；将持续生效，直到你手动解除"
            ));
            *lock(&self.lockdown_last) = Some(true);
        } else {
            crate::guard::lockdown_clear();
            *lock(&self.lockdown_manual) = false;
            self.log("手动解除：已删除出站封锁规则；之后按接入状态自动接管");
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

    /// 是否处于"用户要求停止保护"状态。
    pub fn is_disarmed(&self) -> bool {
        lock(&self.disarmed).is_some()
    }

    pub fn disarmed_reason(&self) -> String {
        lock(&self.disarmed).clone().unwrap_or_default()
    }

    /// 停止保护：写意图文件（跨重启保留）+ 更新内存态。
    /// 文件写失败必须返回错误——否则重启后守护器会重新施加规则，急救失效。
    pub fn disarm(&self, reason: &str) -> Result<(), String> {
        crate::disarm::mark(reason)?;
        *lock(&self.disarmed) = Some(reason.to_string());
        self.log(format!(
            "已停止保护：{reason}（此后只检测，不再结束进程/隔离/断网）"
        ));
        self.emit_state();
        Ok(())
    }

    /// 重新布防：删意图文件 + 清内存态。
    pub fn rearm(&self) -> Result<(), String> {
        crate::disarm::clear()?;
        *lock(&self.disarmed) = None;
        self.log("已重新布防：恢复守护动作");
        self.emit_state();
        Ok(())
    }

    /// 与磁盘上的停止保护意图对齐（存活实例感知外部 `--restore` / `--rearm`）。
    ///
    /// 启动时读一次不够：外部入口改的是文件，不重读的话常驻进程会继续按旧意图
    /// 杀进程、加规则。返回是否发生了变化，便于调用方决定要不要额外动作。
    pub fn sync_disarm(&self) -> bool {
        let disk = crate::disarm::reason();
        let changed = {
            let mut cur = lock(&self.disarmed);
            match crate::disarm::reconcile(cur.as_deref(), disk.as_deref()) {
                Some(next) => {
                    *cur = next;
                    true
                }
                None => false,
            }
        };
        if changed {
            let reason = self.disarmed_reason();
            if reason.is_empty() {
                self.log("检测到外部重新布防，已恢复守护动作");
            } else {
                self.log(format!(
                    "检测到外部停止保护请求（{reason}），此后只检测，不再结束进程/隔离/断网"
                ));
            }
            self.emit_state();
        }
        changed
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

    /// v3.10 R12：记录"操作未生效"的持久错误（配置保存失败等），并推给 UI。
    pub fn set_error(&self, msg: impl Into<String>) {
        let msg = msg.into();
        if msg.trim().is_empty() {
            return;
        }
        *lock(&self.last_error) = msg.clone();
        self.log(format!("操作未生效：{msg}"));
        self.emit_state();
    }

    /// 成功后清除持久错误。
    pub fn clear_error(&self) {
        let had = {
            let mut slot = lock(&self.last_error);
            let had = !slot.is_empty();
            slot.clear();
            had
        };
        if had {
            self.emit_state();
        }
    }

    pub fn last_error(&self) -> String {
        lock(&self.last_error).clone()
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
        // R14 / D5：桌面通知与飞书共用同一脱敏出口，默认不带出口 IP/地区。
        let body = crate::redact::redact(body, prefs.include_egress);
        // 客户端更新与 v2 一致走双通道：桌面通知 + 飞书队列（飞书是否真的发由 Notifier 的 enabled 决定）。
        if class == "client_update" {
            self.feishu.notify(&format!("{title}\n{body}"));
        }
        notify::send(&prefs, class, title, &body)
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
            last_error: self.last_error(),
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
            lockdown_manual: self.lockdown_manual_on(),
            disarmed: self.is_disarmed(),
            disarmed_reason: self.disarmed_reason(),
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
    use super::AppState;
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
    fn manual_lockdown_survives_auto_clear() {
        // 手动封锁开启后，即使自动策略本轮判定"不需要封锁"，意图仍为封锁。
        assert!(AppState::desired_lockdown(false, true));
        assert!(AppState::desired_lockdown(true, false));
        assert!(AppState::desired_lockdown(true, true));
        assert!(!AppState::desired_lockdown(false, false));
    }

    #[test]
    fn paused_blocks_new_lockdown_but_allows_release() {
        // 暂停中不允许新增封锁（D3：暂停不新增副作用）。
        assert!(!AppState::lockdown_sync_allowed(true, None, true));
        assert!(!AppState::lockdown_sync_allowed(true, Some(false), true));
        // 已封锁时保持幂等。
        assert!(AppState::lockdown_sync_allowed(true, Some(true), true));
        // 解除（减少副作用）始终允许。
        assert!(AppState::lockdown_sync_allowed(true, Some(true), false));
        // 非暂停时正常同步。
        assert!(AppState::lockdown_sync_allowed(false, None, true));
    }

    #[test]
    fn overall_idle_when_nothing_enabled() {
        assert_eq!(
            overall_of(false, false, false, &[TargetState::Disabled]),
            Overall::Idle
        );
    }
}
