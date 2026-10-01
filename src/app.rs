//! egui 界面（Apple 浅色风格）+ 系统托盘 + 常驻监测线程。

use eframe::egui;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc::Receiver, Arc, Mutex};
use std::time::{Duration, Instant};

use crate::checks::{self, CheckOutcome, StepState};
use crate::config::Config;
use crate::guard::{self, TripResult};
use crate::install;
use crate::theme::{
    BG, BLUE, BLUE_H, GREEN, GREEN_DEEP, LINK, MIST, ORANGE, RED, SEP, TXT, TXT2,
};
use crate::update;
use crate::widgets::{
    TitleAction, arc, banner, btext, capsule, card_p, chevron, hairline, ios_toggle,
    ios_toggle_disabled, setting_row, text_link, title_bar,
};

const TRAY_SHOW: &str = "cg_show";
const TRAY_RECHECK: &str = "cg_recheck";
const TRAY_RELEASE: &str = "cg_release";
const TRAY_QUIT: &str = "cg_quit";

#[derive(Debug)]
pub enum TrayMsg {
    Show,
    IconClick,
    Recheck,
    Release,
    Quit,
}

#[derive(Clone, Copy, PartialEq)]
enum Purpose {
    Monitor,
    Manual,
    Launch,
}

#[derive(Clone, Copy, PartialEq)]
enum Screen {
    Wizard,
    Main,
}

#[derive(Clone, Copy, PartialEq)]
enum RingState {
    Spin,
    Pass,
    Fail,
    Idle,
}

/// 更新流程状态（后台线程写，UI 线程读）
#[derive(Clone)]
enum UpdState {
    Idle,
    Checking,
    UpToDate,
    Available {
        ver: String,
        url: String,
        size: u64,
    },
    Downloading {
        done: u64,
        total: u64,
    },
    Restarting,
    Failed(String),
}

/// 线程间共享状态
#[derive(Clone)]
pub struct Shared {
    pub cfg: Arc<Mutex<Config>>,
    pub last: Arc<Mutex<Option<CheckOutcome>>>,
    pub tripped: Arc<Mutex<Option<TripResult>>>,
    pub busy: Arc<AtomicBool>,
    pub hide_req: Arc<AtomicBool>,
    pub stop: Arc<AtomicBool>,
    pub loglines: Arc<Mutex<Vec<String>>>,
}

impl Shared {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg: Arc::new(Mutex::new(cfg)),
            last: Arc::new(Mutex::new(None)),
            tripped: Arc::new(Mutex::new(None)),
            busy: Arc::new(AtomicBool::new(false)),
            hide_req: Arc::new(AtomicBool::new(false)),
            stop: Arc::new(AtomicBool::new(false)),
            loglines: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn log(&self, msg: &str) {
        guard::log_line(msg);
        let mut v = self.loglines.lock().unwrap();
        v.push(msg.to_string());
        let n = v.len();
        if n > 200 {
            v.drain(..n - 200);
        }
    }

    pub fn snapshot(&self) -> (Option<CheckOutcome>, bool, Option<TripResult>) {
        (
            self.last.lock().unwrap().clone(),
            self.busy.load(Ordering::SeqCst),
            self.tripped.lock().unwrap().clone(),
        )
    }
}

/// 在任意线程执行一次完整检测，并按结果联动熔断/解除。
fn run_check(sh: &Shared, ctx: &egui::Context, purpose: Purpose) {
    if sh.busy.swap(true, Ordering::SeqCst) {
        return; // 已有检测在进行
    }
    let cfg = sh.cfg.lock().unwrap().clone();
    let out = checks::run_checks(&cfg, |m| sh.log(&m));
    *sh.last.lock().unwrap() = Some(out.clone());
    sh.log(&format!(
        "result: passed={} reason={}",
        out.passed,
        if out.reason.is_empty() { "-" } else { &out.reason }
    ));

    // 只有"确实拿到了出口 IP 且不匹配"才熔断；网络查询失败不误杀
    let mismatch = matches!(&out.egress_ip, Some(ip) if *ip != cfg.required_ip);
    if !out.passed && mismatch {
        let already = sh.tripped.lock().unwrap().is_some();
        if already {
            let killed = guard::kill_claude();
            if killed > 0 {
                sh.log(&format!("持续异常：再次结束 {killed} 个 Claude 进程"));
            }
        } else {
            let res = guard::trip(&cfg, &out.reason);
            sh.log(&format!(
                "已熔断：结束 {} 个进程，新增防火墙规则 {} 条",
                res.killed, res.firewall_rules
            ));
            *sh.tripped.lock().unwrap() = Some(res);
        }
    } else if out.passed {
        let mut t = sh.tripped.lock().unwrap();
        if t.is_some() {
            if guard::firewall_release() {
                sh.log("检测通过：已解除防火墙隔离");
            }
            *t = None;
        }
    }

    if purpose == Purpose::Launch {
        if out.passed {
            let app_id = guard::resolve_app_id(&cfg.app_id);
            if guard::launch_claude(&app_id) {
                sh.log("校验通过，已启动 Claude");
                if cfg.close_to_tray {
                    sh.hide_req.store(true, Ordering::SeqCst);
                }
            } else {
                sh.log("启动 Claude 失败（shell:AppsFolder）");
            }
        } else {
            sh.log("校验未通过，已阻止启动");
        }
    }

    sh.busy.store(false, Ordering::SeqCst);
    ctx.request_repaint();
}

// ---------------- 应用主体 ----------------

pub struct GuardApp {
    sh: Shared,
    rx: Receiver<TrayMsg>,
    tray: Option<tray_icon::TrayIcon>,
    quitting: bool,
    start_hidden: bool,
    maximized: bool,
    admin: bool,
    installed: bool,
    screen: Screen,
    pub(crate) wiz_page: u8,
    show_details: bool,
    show_settings: bool,
    // 测试钩子缓存: CG_SMOKE_SETTINGS=1 时截图视图只渲染设置卡
    smoke_settings: bool,
    show_log: bool,
    notice: Option<(String, Instant)>,
    upd: Arc<Mutex<UpdState>>,
    // 设置编辑缓冲（wizard.rs 也要读写这几个）
    pub(crate) ed_port: String,
    pub(crate) ed_ip: String,
    ed_interval: String,
    pub(crate) err_port: Option<String>,
    pub(crate) err_ip: Option<String>,
    err_interval: Option<String>,
}

impl GuardApp {
    pub fn new(cc: &eframe::CreationContext<'_>, start_hidden: bool, tray_img: tray_icon::Icon) -> Self {
        crate::theme::init(&cc.egui_ctx);

        let cfg = Config::load();
        update::cleanup_old();
        let first_run = cfg.first_run;
        let sh = Shared::new(cfg.clone());
        if guard::firewall_active() {
            *sh.tripped.lock().unwrap() = Some(TripResult::default());
            sh.log("检测到已有 ClaudeGuard 防火墙规则（沿用隔离状态）");
        }

        // ---- 托盘 ----
        use tray_icon::menu::{Menu, MenuEvent, MenuItem};
        use tray_icon::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
        let menu = Menu::new();
        let mi_show = MenuItem::with_id(TRAY_SHOW, "显示主窗口", true, None);
        let mi_recheck = MenuItem::with_id(TRAY_RECHECK, "立即检测", true, None);
        let mi_release = MenuItem::with_id(TRAY_RELEASE, "解除隔离", true, None);
        let mi_quit = MenuItem::with_id(TRAY_QUIT, "退出", true, None);
        let _ = menu.append_items(&[&mi_show, &mi_recheck, &mi_release, &mi_quit]);
        let tray = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("Claude 守护器")
            .with_icon(tray_img)
            .build()
            .ok();

        let (tx, rx) = std::sync::mpsc::channel::<TrayMsg>();
        let ctx_m = cc.egui_ctx.clone();
        let tx_m = tx.clone();
        MenuEvent::set_event_handler(Some(move |e: tray_icon::menu::MenuEvent| {
            let msg = match e.id.0.as_str() {
                TRAY_SHOW => TrayMsg::Show,
                TRAY_RECHECK => TrayMsg::Recheck,
                TRAY_RELEASE => TrayMsg::Release,
                TRAY_QUIT => TrayMsg::Quit,
                _ => return,
            };
            let _ = tx_m.send(msg);
            ctx_m.request_repaint();
        }));
        let ctx_i = cc.egui_ctx.clone();
        let tx_i = tx.clone();
        TrayIconEvent::set_event_handler(Some(move |e: TrayIconEvent| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = e
            {
                let _ = tx_i.send(TrayMsg::IconClick);
                ctx_i.request_repaint();
            }
        }));

        // ---- 常驻监测线程 ----
        {
            let sh2 = sh.clone();
            let ctx3 = cc.egui_ctx.clone();
            std::thread::spawn(move || {
                let mut next = Instant::now() + Duration::from_secs(1);
                loop {
                    if sh2.stop.load(Ordering::SeqCst) {
                        break;
                    }
                    if Instant::now() >= next && !sh2.busy.load(Ordering::SeqCst) {
                        run_check(&sh2, &ctx3, Purpose::Monitor);
                        let iv = sh2.cfg.lock().unwrap().check_interval_secs.clamp(5, 3600);
                        next = Instant::now() + Duration::from_secs(iv);
                    }
                    std::thread::sleep(Duration::from_millis(300));
                }
            });
        }

        Self {
            ed_port: cfg.proxy_port.to_string(),
            ed_ip: cfg.required_ip.clone(),
            ed_interval: cfg.check_interval_secs.to_string(),
            err_port: None,
            err_ip: None,
            err_interval: None,
            sh,
            rx,
            tray,
            quitting: false,
            start_hidden,
            maximized: false,
            admin: guard::is_admin(),
            installed: install::is_installed(),
            screen: if first_run { Screen::Wizard } else { Screen::Main },
            wiz_page: 0,
            show_details: false,
            // 测试钩子: CG_SMOKE_SETTINGS 展开设置卡(截图验证用)
            show_settings: std::env::var("CG_SMOKE_SETTINGS").is_ok(),
            smoke_settings: std::env::var("CG_SMOKE_SETTINGS").is_ok(),
            show_log: false,
            notice: None,
            upd: Arc::new(Mutex::new(UpdState::Idle)),
        }
    }

    fn spawn_check(&self, ctx: &egui::Context, purpose: Purpose) {
        let sh = self.sh.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || run_check(&sh, &ctx, purpose));
    }

    /// 后台查 GitHub 最新版本
    fn spawn_update_check(&self) {
        let st = self.upd.clone();
        let cfg = self.sh.cfg.lock().unwrap().clone();
        std::thread::spawn(move || {
            let new = match update::check_latest(&cfg) {
                Ok(rel) => {
                    if update::is_newer(rel.version(), update::current_version()) {
                        match rel.exe_asset() {
                            Some(a) => UpdState::Available {
                                ver: rel.version().to_string(),
                                url: a.browser_download_url.clone(),
                                size: a.size,
                            },
                            None => UpdState::Failed("新版本没有附带 exe 文件".into()),
                        }
                    } else {
                        UpdState::UpToDate
                    }
                }
                Err(e) => UpdState::Failed(e),
            };
            *st.lock().unwrap() = new;
        });
    }

    /// 后台下载新版本并自动重启替换
    fn spawn_update_download(&self, url: String, size: u64) {
        let st = self.upd.clone();
        let cfg = self.sh.cfg.lock().unwrap().clone();
        std::thread::spawn(move || {
            let st2 = st.clone();
            let r = update::download(&cfg, &url, size, move |done, total| {
                *st2.lock().unwrap() = UpdState::Downloading { done, total };
            });
            match r {
                Ok(path) => {
                    *st.lock().unwrap() = UpdState::Restarting;
                    match update::apply_update(&path) {
                        Ok(()) => std::process::exit(0),
                        Err(e) => *st.lock().unwrap() = UpdState::Failed(e),
                    }
                }
                Err(e) => *st.lock().unwrap() = UpdState::Failed(e),
            }
        });
    }

    fn release_now(&mut self) {
        if guard::firewall_release() {
            self.sh.log("已手动解除防火墙隔离");
        } else {
            self.sh.log("没有可解除的隔离规则");
        }
        *self.sh.tripped.lock().unwrap() = None;
    }

    /// 大状态（圆环 + 主标题 + 副标题）
    fn hero_state(&self) -> (RingState, String, String) {
        let (last, busy, tripped) = self.sh.snapshot();
        if busy {
            return (RingState::Spin, "正在检查…".into(), "正在核对代理和出口 IP".into());
        }
        if tripped.is_some() {
            let reason = last
                .as_ref()
                .map(|o| o.reason.clone())
                .filter(|r| !r.is_empty())
                .unwrap_or_else(|| "出口 IP 与约定不一致".into());
            return (RingState::Fail, "已暂停 Claude".into(), format!("{reason} · 切回节点后自动恢复"));
        }
        if let Some(o) = last {
            if o.passed {
                let desc = o.egress_desc.as_deref().unwrap_or("").chars().take(18).collect::<String>();
                return (
                    RingState::Pass,
                    "一切正常".into(),
                    format!("出口 {} {}", o.egress_ip.as_deref().unwrap_or("-"), desc),
                );
            }
            return (RingState::Fail, "没有通过检查".into(), plain_reason(&o.reason));
        }
        (RingState::Idle, "准备中".into(), "马上开始第一次检查".into())
    }

    pub(crate) fn do_install(&mut self) {
        match install::install() {
            Ok(p) => {
                self.installed = true;
                self.sh.log(&format!("安装完成: {}", p.display()));
                self.notice = Some(("安装完成，桌面已建快捷方式".into(), Instant::now()));
            }
            Err(e) => {
                self.sh.log(&format!("安装失败: {e}"));
                self.notice = Some((format!("安装失败：{e}"), Instant::now()));
            }
        }
    }

    pub(crate) fn finish_wizard(&mut self) {
        {
            let mut cfg = self.sh.cfg.lock().unwrap();
            cfg.first_run = false;
            let _ = cfg.save();
        }
        self.screen = Screen::Main;
    }

    // ---------------- 主界面 ----------------
    fn main_ui(&mut self, ui: &mut egui::Ui, compact: bool) {
        let (ring, headline, sub) = self.hero_state();
        let busy = self.sh.busy.load(Ordering::SeqCst);
        let tripped = self.sh.tripped.lock().unwrap().is_some();
        let last = self.sh.last.lock().unwrap().clone();

        // —— 大状态圆环（居中；矮窗口用小一号的环） ——
        let (blk, radius, rstroke, gs) = if compact { (104.0, 36.0, 6.5, 0.72) } else { (150.0, 52.0, 9.0, 1.0) };
        ui.add_space(if compact { 2.0 } else { 4.0 });
        ui.vertical_centered(|ui| {
            let (rrect, _) = ui.allocate_exact_size(egui::vec2(blk, blk), egui::Sense::hover());
            let c = rrect.center();
        // 底环
        arc(ui, c, radius, 0.0, std::f32::consts::TAU, rstroke, SEP);
        let now = ui.ctx().input(|i| i.time) as f32;
        match ring {
            RingState::Spin => {
                let a0 = now * 2.6;
                for i in 0..3 {
                    let s = a0 + i as f32 * (std::f32::consts::TAU / 3.0);
                    arc(ui, c, radius, s, s + 1.4, rstroke, BLUE);
                }
                ui.ctx().request_repaint_after(Duration::from_millis(30));
            }
            RingState::Pass => {
                arc(ui, c, radius, 0.0, std::f32::consts::TAU, rstroke, GREEN);
                // 矢量勾（避免字体缺字形）
                let st = egui::Stroke::new(6.0 * gs, GREEN);
                let a = egui::pos2(c.x - 17.0 * gs, c.y + 1.0 * gs);
                let b = egui::pos2(c.x - 6.0 * gs, c.y + 13.0 * gs);
                let d = egui::pos2(c.x + 18.0 * gs, c.y - 13.0 * gs);
                ui.painter().line_segment([a, b], st);
                ui.painter().line_segment([b, d], st);
            }
            RingState::Fail => {
                arc(ui, c, radius, 0.0, std::f32::consts::TAU, rstroke, RED);
                // 矢量感叹号
                let st = egui::Stroke::new(6.0 * gs, RED);
                ui.painter().line_segment([egui::pos2(c.x, c.y - 17.0 * gs), egui::pos2(c.x, c.y + 5.0 * gs)], st);
                ui.painter().circle_filled(egui::pos2(c.x, c.y + 19.0 * gs), 4.0 * gs, RED);
            }
            RingState::Idle => {
                // 三个灰点
                for dx in [-14.0, 0.0, 14.0] {
                    ui.painter().circle_filled(egui::pos2(c.x + dx * gs, c.y), 4.5 * gs, TXT2);
                }
            }
        }
        });
        // 主/副标题（仿半粗 + Iron Gray）
        {
            let (r, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), if compact { 26.0 } else { 32.0 }), egui::Sense::hover());
            btext(ui, r.center(), egui::Align2::CENTER_CENTER, &headline, if compact { 20.0 } else { 24.0 }, TXT);
        }
        {
            let (r, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), if compact { 20.0 } else { 24.0 }), egui::Sense::hover());
            ui.painter().text(r.center(), egui::Align2::CENTER_CENTER, &sub, egui::FontId::proportional(if compact { 13.0 } else { 14.0 }), TXT2);
        }
        ui.add_space(if compact { 4.0 } else { 10.0 });

        // —— 提示条（放在主按钮之前，重要信息不被折叠到屏幕外） ——
        if let Some((msg, t)) = &self.notice {
            if t.elapsed() < Duration::from_secs(4) {
                banner(ui, GREEN, "完成", msg, compact);
            } else {
                self.notice = None;
            }
        }
        if !self.admin {
            banner(
                ui,
                ORANGE,
                "需要管理员权限",
                if compact {
                    "请关掉本窗口，用桌面的 ClaudeGuard 快捷方式重新打开。"
                } else {
                    "自动断网要用管理员权限。请关掉这个窗口，用桌面的 ClaudeGuard 快捷方式重新打开。"
                },
                compact,
            );
        }
        if tripped {
            banner(
                ui,
                RED,
                "Claude 已被暂停",
                "出口 IP 和约定不一致：已结束 Claude 的进程，并断开了它的网络。切回正确节点后会自动恢复。",
                compact,
            );
        } else if let Some(o) = &last {
            if !o.passed && !busy && o.egress_ip.is_none() {
                banner(
                    ui,
                    ORANGE,
                    "暂时没法确认网络",
                    "刚才的检查没有成功，可能是网络没通。确认代理软件开着，再点重新检查。",
                    compact,
                );
            }
        }
        ui.add_space(if compact { 3.0 } else { 6.0 });

        // —— 主按钮 ——
        ui.vertical_centered(|ui| {
            let avail = ui.available_width() - 28.0;
            let w = avail.min(320.0);
            let last_ok = last.as_ref().map(|o| o.passed).unwrap_or(false);
            let has_result = last.is_some();
            if tripped {
                if capsule(ui, "cta_recheck", "我已切回节点，重新检查", w, BLUE, BLUE_H, !busy) {
                    self.spawn_check(ui.ctx(), Purpose::Manual);
                }
            } else if busy || !has_result {
                capsule(ui, "cta_busy", "正在检查，稍候…", w, MIST, MIST, false);
            } else if last_ok {
                if capsule(ui, "cta_launch", "启动 Claude", w, BLUE, BLUE_H, true) {
                    self.spawn_check(ui.ctx(), Purpose::Launch);
                }
            } else {
                // 检查未通过: 不提供"启动"入口, 引导重新检查
                if capsule(ui, "cta_retry", "重新检查", w, BLUE, BLUE_H, true) {
                    self.spawn_check(ui.ctx(), Purpose::Manual);
                }
            }
            ui.add_space(if compact { 3.0 } else { 6.0 });
            if last_ok && !tripped {
                if text_link(ui, "link_recheck", "重新检查", 12.0, LINK) {
                    self.spawn_check(ui.ctx(), Purpose::Manual);
                }
            }
        });
        ui.add_space(if compact { 3.0 } else { 10.0 });

        // —— 检查详情（默认收起，弱化） ——
        ui.add_space(if compact { 2.0 } else { 4.0 });
        card_p(ui, if compact { 12 } else { 20 }, |ui| {
            ui.horizontal(|ui| {
                let open = self.show_details;
                let label = "检查详情";
                let tw = ui.painter().layout_no_wrap(label.to_string(), egui::FontId::proportional(13.0), TXT2).size().x;
                let (rect, resp) = ui.allocate_exact_size(egui::vec2(tw + 18.0, 20.0), egui::Sense::click());
                ui.painter().text(rect.left_center(), egui::Align2::LEFT_CENTER, label, egui::FontId::proportional(13.0), TXT2);
                chevron(ui, egui::pos2(rect.left() + tw + 9.0, rect.center().y), open, TXT2);
                let clicked = resp.clicked();
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        egui::RichText::new(match (&last, busy) {
                            (Some(o), _) if o.passed => "全部通过",
                            (Some(_), _) => "有问题",
                            (None, true) => "检查中",
                            (None, false) => "还没检查",
                        })
                        .size(12.0)
                        .color(if last.as_ref().map(|o| o.passed).unwrap_or(false) { GREEN_DEEP } else { TXT2 }),
                    );
                });
                if clicked {
                    self.show_details = !self.show_details;
                }
            });
            if self.show_details {
                ui.add_space(4.0);
                hairline(ui);
                ui.add_space(6.0);
                if let Some(o) = &last {
                    step_row(ui, "代理已开启", &o.proxy);
                    step_row(ui, "代理能连通", &o.port);
                    step_row(ui, "出口 IP 正确", &o.egress);
                } else {
                    ui.label(egui::RichText::new("还没有结果，稍等片刻…").size(12.5).color(TXT2));
                }
            }
        });

        self.settings_card(ui, compact);

        // —— 运行日志（弱化收起） ——
        card_p(ui, if compact { 12 } else { 20 }, |ui| {
            ui.horizontal(|ui| {
                let label = "运行日志";
                let tw = ui.painter().layout_no_wrap(label.to_string(), egui::FontId::proportional(13.0), TXT2).size().x;
                let (rect, resp) = ui.allocate_exact_size(egui::vec2(tw + 18.0, 20.0), egui::Sense::click());
                ui.painter().text(rect.left_center(), egui::Align2::LEFT_CENTER, label, egui::FontId::proportional(13.0), TXT2);
                chevron(ui, egui::pos2(rect.left() + tw + 9.0, rect.center().y), self.show_log, TXT2);
                if resp.clicked() {
                    self.show_log = !self.show_log;
                }
            });
            if self.show_log {
                ui.add_space(4.0);
                hairline(ui);
                ui.add_space(6.0);
                let lines = self.sh.loglines.lock().unwrap().clone();
                let start = lines.len().saturating_sub(30);
                egui::ScrollArea::vertical().max_height(150.0).show(ui, |ui| {
                    for l in &lines[start..] {
                        ui.label(egui::RichText::new(l).size(11.0).color(TXT2).monospace());
                    }
                });
            }
        });

        // —— 底栏 ——
        ui.add_space(if compact { 4.0 } else { 8.0 });
        ui.vertical_centered(|ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(concat!("ClaudeGuard v", env!("CARGO_PKG_VERSION"))).size(12.0).color(TXT2));
                ui.label(egui::RichText::new("·").size(12.0).color(TXT2));
                if text_link(ui, "ft_data", "打开数据文件夹", 12.0, LINK) {
                    let explorer = std::env::var("SystemRoot")
                        .map(|r| std::path::PathBuf::from(r).join("explorer.exe"))
                        .unwrap_or_else(|_| std::path::PathBuf::from(r"C:\Windows\explorer.exe"));
                    let _ = std::process::Command::new(explorer)
                        .arg(crate::config::config_dir())
                        .spawn();
                }
                if !self.installed {
                    ui.label(egui::RichText::new("·").size(12.0).color(TXT2));
                    if text_link(ui, "ft_install", "安装到电脑", 12.0, LINK) {
                        self.do_install();
                    }
                }
            });
        });
    }

    fn settings_card(&mut self, ui: &mut egui::Ui, compact: bool) {
        card_p(ui, if compact { 12 } else { 20 }, |ui| {
            ui.horizontal(|ui| {
                let label = "设置";
                let tw = ui.painter().layout_no_wrap(label.to_string(), egui::FontId::proportional(13.0), TXT2).size().x;
                let (rect, resp) = ui.allocate_exact_size(egui::vec2(tw + 18.0, 20.0), egui::Sense::click());
                ui.painter().text(rect.left_center(), egui::Align2::LEFT_CENTER, label, egui::FontId::proportional(13.0), TXT2);
                chevron(ui, egui::pos2(rect.left() + tw + 9.0, rect.center().y), self.show_settings, TXT2);
                if resp.clicked() {
                    self.show_settings = !self.show_settings;
                }
            });
            if !self.show_settings {
                return;
            }
            ui.add_space(4.0);
            hairline(ui);
            ui.add_space(6.0);
            let (r, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 24.0), egui::Sense::hover());
            btext(ui, egui::pos2(r.left(), r.center().y), egui::Align2::LEFT_CENTER, "检测", 15.0, TXT);
            ui.add_space(4.0);
            let mut saved = false;
            setting_row(ui, "代理端口", "代理软件的端口，常见是 7890", |ui| {
                let r = ui.add(egui::TextEdit::singleline(&mut self.ed_port).desired_width(140.0).font(egui::TextStyle::Monospace));
                if r.lost_focus() || ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    if let Ok(p) = self.ed_port.trim().parse::<u16>() {
                        self.sh.cfg.lock().unwrap().proxy_port = p;
                        self.err_port = None;
                        saved = true;
                    } else {
                        self.err_port = Some("端口要填 1-65535".into());
                    }
                }
            });
            if let Some(e) = &self.err_port {
                ui.label(egui::RichText::new(e).size(12.0).color(RED));
            }
            setting_row(ui, "约定的出口 IP", "只认这个出口，别的都会拦", |ui| {
                let r = ui.add(egui::TextEdit::singleline(&mut self.ed_ip).desired_width(140.0).font(egui::TextStyle::Monospace));
                if r.lost_focus() || ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    if std::net::Ipv4Addr::from_str(self.ed_ip.trim()).is_ok() {
                        self.sh.cfg.lock().unwrap().required_ip = self.ed_ip.trim().to_string();
                        self.err_ip = None;
                        saved = true;
                    } else {
                        self.err_ip = Some("要写成 4 段数字，如 203.0.113.10".into());
                    }
                }
            });
            if let Some(e) = &self.err_ip {
                ui.label(egui::RichText::new(e).size(12.0).color(RED));
            }
            setting_row(ui, "检查间隔", "每隔几秒复查一次（秒）", |ui| {
                let r = ui.add(egui::TextEdit::singleline(&mut self.ed_interval).desired_width(140.0).font(egui::TextStyle::Monospace));
                if r.lost_focus() || ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    if let Ok(iv) = self.ed_interval.trim().parse::<u64>() {
                        if (5..=3600).contains(&iv) {
                            self.sh.cfg.lock().unwrap().check_interval_secs = iv;
                            self.err_interval = None;
                            saved = true;
                        } else {
                            self.err_interval = Some("范围 5-3600 秒".into());
                        }
                    } else {
                        self.err_interval = Some("填数字".into());
                    }
                }
            });
            if let Some(e) = &self.err_interval {
                ui.label(egui::RichText::new(e).size(12.0).color(RED));
            }
            hairline(ui);
            ui.add_space(6.0);

            // 异常时组
            let (r, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 24.0), egui::Sense::hover());
            btext(ui, egui::pos2(r.left(), r.center().y), egui::Align2::LEFT_CENTER, "发现出口不对时", 15.0, TXT);
            ui.add_space(4.0);
            let mut chg = false;
            {
                let mut cfg = self.sh.cfg.lock().unwrap();
                let mut v = cfg.kill_on_fail;
                setting_row(ui, "停掉 Claude", "立刻结束 Claude 的所有进程", |ui| {
                    if ios_toggle(ui, "tg_kill", &mut v) {
                        chg = true;
                    }
                });
                let mut v2 = cfg.quarantine_on_fail;
                setting_row(ui, "断开它的网络", "用防火墙拦住 Claude 联网，恢复后自动解除", |ui| {
                    if ios_toggle(ui, "tg_quar", &mut v2) {
                        chg = true;
                    }
                });
                if chg {
                    cfg.kill_on_fail = v;
                    cfg.quarantine_on_fail = v2;
                }
            }
            if chg {
                let _ = self.sh.cfg.lock().unwrap().save();
                self.notice = Some(("已保存".into(), Instant::now()));
            }
            hairline(ui);
            ui.add_space(6.0);

            // 通用组
            let (r, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 24.0), egui::Sense::hover());
            btext(ui, egui::pos2(r.left(), r.center().y), egui::Align2::LEFT_CENTER, "通用", 15.0, TXT);
            ui.add_space(4.0);
            let mut chg2 = false;
            {
                let mut cfg = self.sh.cfg.lock().unwrap();
                let mut v = cfg.close_to_tray;
                setting_row(ui, "关窗后驻留托盘", "守护继续在后台运行", |ui| {
                    if ios_toggle(ui, "tg_tray", &mut v) {
                        chg2 = true;
                    }
                });
                let installed = self.installed;
                let mut v2 = cfg.auto_start_with_system;
                if installed {
                    setting_row(ui, "开机自启", "开机后自动在托盘里默默守护", |ui| {
                        if ios_toggle(ui, "tg_autostart", &mut v2) {
                            chg2 = true;
                        }
                    });
                } else {
                    setting_row(ui, "开机自启", "安装之后才能开启", |ui| {
                        let _ = ios_toggle_disabled(ui, "tg_autostart_d");
                    });
                }
                if chg2 {
                    cfg.close_to_tray = v;
                    if installed {
                        cfg.auto_start_with_system = v2;
                    }
                }
            }
            if chg2 {
                let cfg = self.sh.cfg.lock().unwrap();
                if self.installed {
                    let _ = install::set_autostart(cfg.auto_start_with_system);
                }
                let _ = cfg.save();
                drop(cfg);
                self.notice = Some(("已保存".into(), Instant::now()));
            }
            // ---- 软件更新 ----
            hairline(ui);
            ui.add_space(6.0);
            let (r, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 24.0), egui::Sense::hover());
            btext(ui, egui::pos2(r.left(), r.center().y), egui::Align2::LEFT_CENTER, "软件更新", 15.0, TXT);
            ui.add_space(4.0);
            let upd = self.upd.lock().unwrap().clone();
            let mut act_check = false;
            let mut act_download: Option<(String, u64)> = None;
            match &upd {
                UpdState::Idle | UpdState::UpToDate => {
                    let desc = if matches!(upd, UpdState::Idle) {
                        "从 GitHub 看看有没有新版本"
                    } else {
                        "已经是最新版本了"
                    };
                    setting_row(ui, "检查更新", desc, |ui| {
                        if text_link(ui, "upd_check", "检查更新", 13.0, LINK) {
                            act_check = true;
                        }
                    });
                }
                UpdState::Checking => {
                    setting_row(ui, "检查更新", "正在向 GitHub 查询", |ui| {
                        ui.label(egui::RichText::new("正在检查…").size(13.0).color(TXT2));
                    });
                }
                UpdState::Available { ver, url, size } => {
                    setting_row(ui, "检查更新", "有新版本，下载完会自动重启", |ui| {
                        if text_link(ui, "upd_dl", &format!("下载 v{ver} 并更新"), 13.0, LINK) {
                            act_download = Some((url.clone(), *size));
                        }
                    });
                }
                UpdState::Downloading { done, total } => {
                    setting_row(ui, "正在下载新版本", "下载完会自动重启", |ui| {
                        let pct = if *total > 0 { (*done as f32 / *total as f32 * 100.0) as u64 } else { 0 };
                        ui.label(egui::RichText::new(format!("{pct}%")).size(13.0).color(TXT));
                    });
                    let (r, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 6.0), egui::Sense::hover());
                    let frac = if *total > 0 { *done as f32 / *total as f32 } else { 0.0 }.clamp(0.0, 1.0);
                    ui.painter().rect_filled(egui::Rect::from_min_size(r.min, egui::vec2(r.width() * frac, 6.0)), egui::CornerRadius::same(3), BLUE);
                    ui.painter().rect_stroke(r, egui::CornerRadius::same(3), egui::Stroke::new(1.0, SEP), egui::StrokeKind::Middle);
                }
                UpdState::Restarting => {
                    setting_row(ui, "检查更新", "下载完成，马上重启", |ui| {
                        ui.label(egui::RichText::new("即将重启…").size(13.0).color(TXT2));
                    });
                }
                UpdState::Failed(e) => {
                    setting_row(ui, "检查更新", "上次没成功，可以再试", |ui| {
                        if text_link(ui, "upd_retry", "重试", 13.0, LINK) {
                            act_check = true;
                        }
                    });
                    ui.label(egui::RichText::new(e).size(12.0).color(RED));
                }
            }
            if act_check {
                *self.upd.lock().unwrap() = UpdState::Checking;
                self.spawn_update_check();
            }
            if let Some((url, size)) = act_download {
                *self.upd.lock().unwrap() = UpdState::Downloading { done: 0, total: size };
                self.spawn_update_download(url, size);
            }

            if saved {
                let _ = self.sh.cfg.lock().unwrap().save();
                self.notice = Some(("已保存".into(), Instant::now()));
            }
        });
    }
}

/// 明细行
fn step_row(ui: &mut egui::Ui, name: &str, res: &crate::checks::StepResult) {
    let (c, txt) = match res.state {
        StepState::Pass => (GREEN, res.text.clone()),
        StepState::Fail => (RED, res.text.clone()),
        StepState::Skip => (TXT2, "未检测".into()),
    };
    ui.horizontal(|ui| {
        let (r, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
        ui.painter().circle_filled(r.center(), 3.5, c);
        ui.label(egui::RichText::new(name).size(14.0).color(TXT));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(egui::RichText::new(txt).size(12.0).color(TXT2));
        });
    });
    ui.add_space(3.0);
}

/// 把技术 reason 翻译成普通人语言
fn plain_reason(reason: &str) -> String {
    if reason.is_empty() {
        return "没有通过检查".into();
    }
    if reason.contains("系统代理") {
        "电脑还没开系统代理：打开代理软件里的「系统代理」开关".into()
    } else if reason.contains("端口") || reason.contains("握手") || reason.contains("CONNECT") {
        "连不上代理端口：看看代理软件是不是开着".into()
    } else if reason.contains("出口") || reason.contains("IP") {
        "出口 IP 和约定不一致".into()
    } else {
        reason.to_string()
    }
}

impl eframe::App for GuardApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.start_hidden {
            self.start_hidden = false;
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }
        if ctx.input(|i| i.viewport().close_requested()) && !self.quitting {
            let to_tray = self.sh.cfg.lock().unwrap().close_to_tray;
            if to_tray {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            }
        }
        if self.sh.hide_req.swap(false, Ordering::SeqCst) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                TrayMsg::Show | TrayMsg::IconClick => {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
                TrayMsg::Recheck => {
                    self.spawn_check(ctx, Purpose::Manual);
                }
                TrayMsg::Release => self.release_now(),
                TrayMsg::Quit => {
                    self.quitting = true;
                    self.sh.stop.store(true, Ordering::SeqCst);
                    self.tray = None;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }
        ctx.request_repaint_after(Duration::from_millis(800));
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(BG).inner_margin(egui::Margin::same(14)))
            .show(ui, |ui| {
                if let Some(act) = title_bar(ui, self.maximized) {
                    match act {
                        TitleAction::Close => {
                            // Windows 习惯：× 遵循"关窗驻留托盘"设置，关了就真退出
                            let to_tray = self.sh.cfg.lock().unwrap().close_to_tray;
                            if to_tray {
                                self.sh.log("窗口已收进托盘，守护仍在运行");
                                ui.ctx().send_viewport_cmd(egui::ViewportCommand::CancelClose);
                                ui.ctx().send_viewport_cmd(egui::ViewportCommand::Visible(false));
                            } else {
                                self.quitting = true;
                                self.sh.stop.store(true, Ordering::SeqCst);
                                self.tray = None;
                                ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                            }
                        }
                        TitleAction::Minimize => {
                            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Minimized(true));
                        }
                        TitleAction::MaximizeToggle => {
                            self.maximized = !self.maximized;
                            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Maximized(self.maximized));
                        }
                    }
                }
                ui.add_space(2.0);
                let scr = self.screen;
                // 极矮窗口(用户手动缩小/超小屏)才紧凑排版; 正常屏幕一律标准设计
                // 注意: 此处 avail = 窗口高-标题栏44-面板边距, 508 窗口实测约 439-453 → 阈值取 400
                let compact = ui.available_height() < 400.0;
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        match scr {
                            Screen::Wizard => self.wizard_ui(ui),
                            Screen::Main => {
                                // 测试钩子: smoke_settings 时只渲染设置卡(截图验证, 免滚动依赖)
                                if self.smoke_settings {
                                    self.settings_card(ui, false);
                                    // 截图时滚到底部, 露出最下面的"软件更新"分组
                                    ui.scroll_to_cursor(Some(egui::Align::Max));
                                } else {
                                    self.main_ui(ui, compact);
                                }
                            }
                        }
                    });
            });
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.sh.stop.store(true, Ordering::SeqCst);
        self.tray = None;
    }
}
