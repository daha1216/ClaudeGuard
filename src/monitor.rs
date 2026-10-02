//! v2 监测核心：把 v1 app.rs 的后台语义（监测线程 / run_check / 熔断 / 解除 / 更新状态机）
//! 原样搬到 Tauri 事件模型上。守卫判定逻辑一行未改，只把"每帧轮询锁"换成事件推送。
//!
//! 对等依据：docs/PARITY-v2.md §5。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::{AppHandle, Emitter};

use crate::checks::{self, CheckOutcome};
use crate::config::Config;
use crate::guard::{self, TripResult};
use crate::update;

pub const EV_STATUS: &str = "guard://status";
pub const EV_LOG: &str = "guard://log";
pub const EV_UPDATE: &str = "guard://update";

/// v1 Purpose {Monitor, Manual, Launch} 原样。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Monitor,
    Manual,
    Launch,
}

/// 软件更新状态机（v1 UpdState 原样，仅加 serde 以便事件推送）。
#[derive(Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum UpdState {
    Idle,
    Checking,
    UpToDate,
    Available { ver: String, url: String, size: u64 },
    Downloading { done: u64, total: u64 },
    Restarting,
    Failed { msg: String },
}

/// 推给前端的守卫快照（对应 v1 UI 每帧从 Shared 读到的全部字段）。
/// camelCase：JS 侧惯例（smoke_settings → smokeSettings），Config 保持 snake 原样往返。
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusSnapshot {
    pub checking: bool,
    pub last: Option<CheckOutcome>,
    pub tripped: Option<TripSnap>,
    pub admin: bool,
    pub installed: bool,
    pub version: &'static str,
    pub smoke_settings: bool,
    /// 守护暂停截止（unix 秒）：暂停期间检查照常但跳过熔断。托盘"暂停守护 30 分钟"设置。
    pub pause_until: Option<i64>,
    /// 正在进行的检查是否用户触发（前端只在手动检查时转圈/禁按钮）。
    pub manual: bool,
    /// 守护范围内正在运行的 GUI agent 显示名（状态行用；与 kill 同一匹配口径）
    pub agents_running: Vec<String>,
    /// 正在运行的 CLI agent 显示名（Claude Code/Codex/Gemini CLI——只提醒不杀）
    pub cli_running: Vec<String>,
}

#[derive(Clone, Serialize)]
pub struct TripSnap {
    pub killed: usize,
    pub firewall_rules: usize,
    pub quarantined: bool,
    /// 本次熔断涉及的 agent 显示名
    pub agents: Vec<String>,
}

impl From<&TripResult> for TripSnap {
    fn from(t: &TripResult) -> Self {
        Self {
            killed: t.killed,
            firewall_rules: t.firewall_rules,
            quarantined: t.quarantined,
            agents: t.agents.clone(),
        }
    }
}

/// v1 Shared 的等价物。loglines 环形 200 条照旧。
pub struct Shared {
    pub cfg: Arc<Mutex<Config>>,
    pub last: Arc<Mutex<Option<CheckOutcome>>>,
    pub tripped: Arc<Mutex<Option<TripResult>>>,
    pub pause_until: Arc<Mutex<Option<i64>>>,
    /// 当前正在跑的检查是否用户触发（手动/启动按钮）。后台周期检查不转圈、不打断界面。
    pub manual: AtomicBool,
    pub busy: Arc<AtomicBool>,
    pub stop: Arc<AtomicBool>,
    pub loglines: Arc<Mutex<Vec<String>>>,
    pub upd: Arc<Mutex<UpdState>>,
    app: Mutex<Option<AppHandle>>,
}

impl Shared {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg: Arc::new(Mutex::new(cfg)),
            last: Arc::new(Mutex::new(None)),
            tripped: Arc::new(Mutex::new(None)),
            pause_until: Arc::new(Mutex::new(None)),
            manual: AtomicBool::new(false),
            busy: Arc::new(AtomicBool::new(false)),
            stop: Arc::new(AtomicBool::new(false)),
            loglines: Arc::new(Mutex::new(Vec::new())),
            upd: Arc::new(Mutex::new(UpdState::Idle)),
            app: Mutex::new(None),
        }
    }

    pub fn attach(&self, app: AppHandle) {
        *self.app.lock().unwrap() = Some(app);
    }

    fn emit<S: Serialize + Clone>(&self, event: &str, payload: S) {
        if let Some(app) = self.app.lock().unwrap().as_ref() {
            let _ = app.emit(event, payload);
        }
    }

    /// v1 Shared::log：guard.log 落盘 + 内存环形缓冲 + 事件推送。
    pub fn log(&self, msg: impl Into<String>) {
        let msg = msg.into();
        guard::log_line(&msg);
        {
            let mut buf = self.loglines.lock().unwrap();
            if buf.len() >= 200 {
                let keep_from = buf.len() - 199;
                buf.drain(..keep_from);
            }
            buf.push(msg.clone());
        }
        self.emit(EV_LOG, &msg);
    }

    pub fn snapshot_extras(
        &self,
        admin: bool,
        installed: bool,
        smoke_settings: bool,
    ) -> StatusSnapshot {
        let cfg = self.cfg.lock().unwrap();
        let scan = guard::scan_agents();
        StatusSnapshot {
            checking: self.busy.load(Ordering::SeqCst),
            last: self.last.lock().unwrap().clone(),
            tripped: self.tripped.lock().unwrap().as_ref().map(TripSnap::from),
            admin,
            installed,
            version: update::current_version(),
            smoke_settings,
            pause_until: *self.pause_until.lock().unwrap(),
            manual: self.manual.load(Ordering::SeqCst),
            agents_running: scan
                .gui
                .iter()
                .filter(|(a, _)| cfg.guarded_agents.iter().any(|id| id == a.id))
                .map(|(a, n)| {
                    if *n > 1 {
                        format!("{}×{}", a.name, n)
                    } else {
                        a.name.to_string()
                    }
                })
                .collect(),
            cli_running: scan
                .cli
                .iter()
                .map(|(id, n)| {
                    let name = guard::cli_agent_name(id);
                    if *n > 1 {
                        format!("{name}×{n}")
                    } else {
                        name.to_string()
                    }
                })
                .collect(),
        }
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 守护是否处于暂停窗口内（托盘"暂停守护 30 分钟"）。
pub fn pause_active(sh: &Shared) -> bool {
    sh.pause_until
        .lock()
        .unwrap()
        .map(|t| t > now_secs())
        .unwrap_or(false)
}

/// 设置/清除暂停。None = 立即恢复守护。UI 侧自行把 pause_until 格式化成本地时间。
pub fn set_pause(sh: &Arc<Shared>, until: Option<i64>) {
    *sh.pause_until.lock().unwrap() = until;
    match until {
        Some(_) => sh.log("守护已暂停 30 分钟：检查照常，但不会结束守护对象的进程或断网"),
        None => sh.log("已恢复守护（暂停结束或手动恢复）"),
    }
    sh.emit(EV_STATUS, sh_full_snapshot(sh));
}

/// v1 run_check（app.rs:112-174）逐条对等：busy 防重入、熔断条件、重复熔断只杀不加规则、
/// 通过即解除、Launch 目的的启动/拦截语义。
pub fn run_check(sh: &Arc<Shared>, purpose: Purpose) {
    if sh.busy.swap(true, Ordering::SeqCst) {
        return; // 已有检查在跑（v1 同款防重入）
    }
    // 手动/启动触发的检查才算"用户在等"——UI 转圈只给这类；后台周期检查静默跑。
    sh.manual.store(
        matches!(purpose, Purpose::Manual | Purpose::Launch),
        Ordering::SeqCst,
    );
    sh.emit(EV_STATUS, sh_full_snapshot(sh));

    let cfg = sh.cfg.lock().unwrap().clone();
    let sh2 = Arc::clone(sh);
    let out = checks::run_checks(&cfg, move |line| sh2.log(line));

    *sh.last.lock().unwrap() = Some(out.clone());
    let reason_disp = if out.reason.is_empty() {
        "-"
    } else {
        &out.reason
    };
    sh.log(format!(
        "result: passed={} reason={}",
        out.passed, reason_disp
    ));

    // 熔断条件（v2.6）：拿到了出口信息且 IP 列表与地区规则都不满足才熔断；
    // 网络失败/地区模式下拿不到地区（None）不熔断，沿用 v1 防误杀语义。
    // 暂停窗口内跳过熔断（检查与日志照常，恢复通过时隔离照常解除）。
    let (_, mismatch) = checks::match_egress(
        &cfg,
        out.egress_ip.as_deref(),
        out.egress_country.as_deref(),
    );
    let already = sh.tripped.lock().unwrap().is_some();
    if !out.passed && mismatch {
        if pause_active(sh) {
            sh.log("守护已暂停：本次跳过熔断");
        } else if already {
            let killed = guard::kill_agents(&cfg);
            if killed > 0 {
                sh.log(format!("持续异常：再次结束 {killed} 个守护对象进程"));
            }
        } else {
            let res = guard::trip(&cfg, &out.reason);
            sh.log(format!(
                "已熔断：结束 {} 个进程，新增防火墙规则 {} 条",
                res.killed, res.firewall_rules
            ));
            *sh.tripped.lock().unwrap() = Some(res);
        }
        // CLI 提醒（只在新熔断时提醒一次，避免每个检查周期刷屏）：
        // CLI 跑在终端/node 宿主里，绝不自动结束——出口不对时只能用户自己关。
        if !already && cfg.cli_warn {
            let cli = guard::scan_agents().cli;
            if !cli.is_empty() {
                let names = cli
                    .iter()
                    .map(|(id, _)| guard::cli_agent_name(id))
                    .collect::<Vec<_>>()
                    .join("、");
                sh.log(format!(
                    "CLI 提醒：{names} 正在运行但出口不一致；CLI 不会自动结束，请自行关闭"
                ));
            }
        }
    }

    // 每次通过都检查解除（v1 同款）。
    if out.passed && already {
        if guard::firewall_release() {
            sh.log("检测通过：已解除防火墙隔离");
        }
        *sh.tripped.lock().unwrap() = None;
    }

    if purpose == Purpose::Launch {
        if out.passed {
            let app_id = guard::resolve_app_id(&cfg.app_id);
            if guard::launch_claude(&app_id) {
                sh.log("校验通过，已启动 Claude");
            } else {
                sh.log("启动 Claude 失败（shell:AppsFolder）");
            }
        } else {
            sh.log("校验未通过，已阻止启动");
        }
    }

    sh.busy.store(false, Ordering::SeqCst);
    sh.manual.store(false, Ordering::SeqCst);
    sh.emit(EV_STATUS, sh_full_snapshot(sh));
}

/// 手动/启动按钮触发：每次新线程（v1 spawn_check 同款）。
pub fn spawn_check(sh: &Arc<Shared>, purpose: Purpose) {
    let sh = Arc::clone(sh);
    std::thread::spawn(move || run_check(&sh, purpose));
}

/// v1 release_now（app.rs:371-378）：托盘"解除隔离"。
pub fn release_now(sh: &Arc<Shared>) {
    if guard::firewall_release() {
        sh.log("已手动解除防火墙隔离");
    } else {
        sh.log("没有可解除的隔离规则");
    }
    *sh.tripped.lock().unwrap() = None;
    sh.emit(EV_STATUS, sh_full_snapshot(sh));
}

/// v1 监测线程（app.rs:266-284）：启动 1 秒后首轮；300ms tick；到点且空闲才跑；
/// 间隔实时读 cfg、clamp(5,3600)。
pub fn spawn_monitor(sh: Arc<Shared>) {
    std::thread::spawn(move || {
        let mut next = Instant::now() + Duration::from_secs(1);
        loop {
            if sh.stop.load(Ordering::SeqCst) {
                break;
            }
            let now = Instant::now();
            if now >= next && !sh.busy.load(Ordering::SeqCst) {
                run_check(&sh, Purpose::Monitor);
                let iv = sh.cfg.lock().unwrap().check_interval_secs.clamp(5, 3600);
                next = Instant::now() + Duration::from_secs(iv);
            }
            std::thread::sleep(Duration::from_millis(300));
        }
    });
}

/// v1 更新检查线程（spawn_update_check）。
pub fn spawn_update_check(sh: &Arc<Shared>) {
    let sh = Arc::clone(sh);
    std::thread::spawn(move || {
        *sh.upd.lock().unwrap() = UpdState::Checking;
        sh.emit(EV_UPDATE, Clone::clone(&*sh.upd.lock().unwrap()));
        let cfg = sh.cfg.lock().unwrap().clone();
        match update::check_latest(&cfg) {
            Ok(rel) => {
                let remote = rel.version().to_string();
                if update::is_newer(&remote, update::current_version()) {
                    match rel.exe_asset() {
                        Some(a) => {
                            let st = UpdState::Available {
                                ver: remote,
                                url: a.browser_download_url.clone(),
                                size: a.size,
                            };
                            *sh.upd.lock().unwrap() = st.clone();
                            sh.emit(EV_UPDATE, st);
                        }
                        None => {
                            let st = UpdState::Failed {
                                msg: "新版本没有附带 exe 文件".into(),
                            };
                            *sh.upd.lock().unwrap() = st.clone();
                            sh.emit(EV_UPDATE, st);
                        }
                    }
                } else {
                    *sh.upd.lock().unwrap() = UpdState::UpToDate;
                    sh.emit(EV_UPDATE, UpdState::UpToDate);
                }
            }
            Err(e) => {
                let st = UpdState::Failed { msg: e };
                *sh.upd.lock().unwrap() = st.clone();
                sh.emit(EV_UPDATE, st);
            }
        }
    });
}

/// v1 更新下载线程（app.rs:325-368）：进度事件 → Restarting → apply_update(true) → exit(0)。
pub fn spawn_update_download(sh: &Arc<Shared>, url: String, size: u64) {
    let sh = Arc::clone(sh);
    std::thread::spawn(move || {
        {
            let mut st = sh.upd.lock().unwrap();
            *st = UpdState::Downloading {
                done: 0,
                total: size,
            };
            sh.emit(EV_UPDATE, Clone::clone(&*st));
        }
        let cfg = sh.cfg.lock().unwrap().clone();
        let sh2 = Arc::clone(&sh);
        let res = update::download(&cfg, &url, size, move |done, total| {
            let mut st = sh2.upd.lock().unwrap();
            *st = UpdState::Downloading { done, total };
            sh2.emit(EV_UPDATE, Clone::clone(&*st));
        });
        match res {
            Ok(path) => {
                *sh.upd.lock().unwrap() = UpdState::Restarting;
                sh.emit(EV_UPDATE, UpdState::Restarting);
                match update::apply_update(&path, true) {
                    Ok(()) => std::process::exit(0),
                    Err(e) => {
                        let st = UpdState::Failed { msg: e };
                        *sh.upd.lock().unwrap() = st.clone();
                        sh.emit(EV_UPDATE, st);
                    }
                }
            }
            Err(e) => {
                let st = UpdState::Failed { msg: e };
                *sh.upd.lock().unwrap() = st.clone();
                sh.emit(EV_UPDATE, st);
            }
        }
    });
}

// —— 界面辅助状态（启动时填一次；install 后刷新） ——

/// admin/installed 缓存：v1 存在 GuardApp 字段里（net session / current_exe 判定，代价高不逐帧算）。
pub static ADMIN_FLAG: AtomicBool = AtomicBool::new(false);
pub static INSTALLED_FLAG: AtomicBool = AtomicBool::new(false);

pub fn smoke_settings() -> bool {
    std::env::var("CG_SMOKE_SETTINGS").is_ok()
}

/// 拿到完整快照（admin/installed 用缓存标志，smoke 读环境变量）。
pub fn sh_full_snapshot(sh: &Shared) -> StatusSnapshot {
    sh.snapshot_extras(
        ADMIN_FLAG.load(Ordering::SeqCst),
        INSTALLED_FLAG.load(Ordering::SeqCst),
        smoke_settings(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh() -> Arc<Shared> {
        Arc::new(Shared::new(crate::config::Config::default()))
    }

    #[test]
    fn pause_window_toggles() {
        let s = sh();
        assert!(!pause_active(&s), "默认未暂停");
        let until = now_secs() + 1800;
        set_pause(&s, Some(until));
        assert!(pause_active(&s), "设置 30 分钟窗口后生效");
        assert_eq!(*s.pause_until.lock().unwrap(), Some(until));
        set_pause(&s, None);
        assert!(!pause_active(&s), "手动清除立即恢复");
        // 过期窗口视为已恢复
        set_pause(&s, Some(now_secs() - 1));
        assert!(!pause_active(&s), "过期暂停不算数");
    }
}
