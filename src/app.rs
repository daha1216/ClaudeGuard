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

// ---- Apple 产品页规范调色板（backup/DESIGN (1).md）----
const BG: egui::Color32 = egui::Color32::from_rgb(0xF5, 0xF5, 0xF7); // Pure Canvas 画布
const CARD: egui::Color32 = egui::Color32::from_rgb(0xFF, 0xFF, 0xFF); // Paper White 卡片
const SEP: egui::Color32 = egui::Color32::from_rgb(0xD6, 0xD6, 0xD6); // Fog 发丝线
const TXT: egui::Color32 = egui::Color32::from_rgb(0x1D, 0x1D, 0x1F); // Obsidian 主文字
const TXT2: egui::Color32 = egui::Color32::from_rgb(0x70, 0x70, 0x70); // Iron Gray 次文字
const BLUE: egui::Color32 = egui::Color32::from_rgb(0x00, 0x71, 0xE3); // Signal Blue 主按钮（唯一彩色填充）
const BLUE_H: egui::Color32 = egui::Color32::from_rgb(0x00, 0x7D, 0xF0); // hover
const LINK: egui::Color32 = egui::Color32::from_rgb(0x00, 0x66, 0xCC); // Deep Link Blue 行内链接
const GREEN: egui::Color32 = egui::Color32::from_rgb(0x03, 0xAA, 0x49); // Pulse Green 通过态
const GREEN_DEEP: egui::Color32 = egui::Color32::from_rgb(0x03, 0x87, 0x3A); // Deep Green 绿色文字
const RED: egui::Color32 = egui::Color32::from_rgb(0xE4, 0x00, 0x2B); // 失败态红
const ORANGE: egui::Color32 = egui::Color32::from_rgb(0xED, 0x63, 0x00); // Ember Orange 警示
const MIST: egui::Color32 = egui::Color32::from_rgb(0xE2, 0xE2, 0xE5); // Mist 中性胶囊/控件面
const CLOSE_RED: egui::Color32 = egui::Color32::from_rgb(0xC4, 0x2B, 0x1C); // Windows 关闭钮 hover

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

fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    let sources = [
        ("segoe", r"C:\Windows\Fonts\segoeui.ttf"),
        ("msyh", r"C:\Windows\Fonts\msyh.ttc"),
        ("segoe-symbol", r"C:\Windows\Fonts\segoeuisymbol.ttf"),
    ];
    for (name, path) in sources {
        if let Ok(bytes) = std::fs::read(path) {
            fonts
                .font_data
                .insert(name.to_string(), egui::FontData::from_owned(bytes).into());
            fonts
                .families
                .entry(egui::FontFamily::Proportional)
                .or_default()
                .push(name.to_string());
            fonts
                .families
                .entry(egui::FontFamily::Monospace)
                .or_default()
                .push(name.to_string());
        }
    }
    // Segoe UI 优先（拉丁字形，规范 system-ui 替身），中文回退微软雅黑，符号回退 Segoe Symbol
    if let Some(v) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
        for want in ["segoe", "msyh"] {
            if let Some(pos) = v.iter().position(|s| s == want) {
                let n = v.remove(pos);
                v.insert(0, n);
            }
        }
    }
    ctx.set_fonts(fonts);
}

fn apple_style(ctx: &egui::Context) {
    let mut style = egui::Style::default();
    style.visuals = egui::Visuals::light();
    style.visuals.panel_fill = BG;
    style.visuals.window_fill = CARD;
    style.visuals.extreme_bg_color = CARD;
    // 输入框：白底 + 1px Fog 发丝线，聚焦时蓝描边（规范表面层级）
    style.visuals.widgets.inactive.bg_fill = CARD;
    style.visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, SEP);
    style.visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, TXT);
    style.visuals.widgets.hovered.bg_fill = CARD;
    style.visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, egui::Color32::from_rgb(0x87, 0x87, 0x8A));
    style.visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, TXT);
    style.visuals.widgets.active.bg_fill = CARD;
    style.visuals.widgets.active.bg_stroke = egui::Stroke::new(1.0, BLUE);
    style.visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0, TXT);
    style.visuals.selection.bg_fill = BLUE;
    style.visuals.selection.stroke = egui::Stroke::new(1.0, egui::Color32::WHITE);
    style.visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, TXT2);
    style.visuals.warn_fg_color = ORANGE;
    style.visuals.error_fg_color = RED;
    style.spacing.item_spacing = egui::vec2(8.0, 8.0);
    style.spacing.button_padding = egui::vec2(12.0, 6.0);
    ctx.set_style_of(egui::Theme::Light, style);
}

// ---------------- 自绘小部件 ----------------

/// 仿半粗字重：egui 无字重支持，双重绘制 0.5px 偏移加粗（规范：最重 600）
fn btext(ui: &mut egui::Ui, pos: egui::Pos2, align: egui::Align2, text: &str, size: f32, color: egui::Color32) {
    let f = egui::FontId::proportional(size);
    ui.painter().text(pos, align, text, f.clone(), color);
    ui.painter().text(egui::pos2(pos.x + 0.5, pos.y), align, text, f, color);
}

/// Windows 窗口按钮字形（矢量，避免字体缺字形）
#[derive(Clone, Copy)]
enum CaptionGlyph {
    Minimize,
    Maximize,
    Restore,
    Close,
}

/// Windows 风格窗口按钮（46×44，hover 浅灰 / 关闭钮 hover 红 + 白字形）
fn caption_btn(ui: &mut egui::Ui, id: &str, rect: egui::Rect, glyph: CaptionGlyph, close_style: bool) -> bool {
    let resp = ui.interact(rect, egui::Id::new(id), egui::Sense::click());
    let hovered = resp.hovered();
    let fill = if close_style {
        if hovered { CLOSE_RED } else { egui::Color32::TRANSPARENT }
    } else if hovered {
        egui::Color32::from_rgb(0xE9, 0xE9, 0xEC)
    } else {
        egui::Color32::TRANSPARENT
    };
    if fill != egui::Color32::TRANSPARENT {
        ui.painter().rect_filled(rect, egui::CornerRadius::same(6), fill);
    }
    let c = rect.center();
    let glyph_color = if close_style && hovered { egui::Color32::WHITE } else { TXT };
    let st = egui::Stroke::new(1.2, glyph_color);
    match glyph {
        CaptionGlyph::Minimize => {
            ui.painter().line_segment(
                [egui::pos2(c.x - 5.5, c.y + 3.0), egui::pos2(c.x + 5.5, c.y + 3.0)],
                st,
            );
        }
        CaptionGlyph::Maximize => {
            let r = egui::Rect::from_center_size(c, egui::vec2(11.0, 11.0));
            ui.painter().rect_stroke(r, egui::CornerRadius::same(1), st, egui::StrokeKind::Middle);
        }
        CaptionGlyph::Restore => {
            // 背面小方块 + 前面小方块（用画布色遮挡叠压部分，得到经典还原字形）
            let back = egui::Rect::from_min_max(egui::pos2(c.x - 5.5, c.y - 5.5), egui::pos2(c.x + 3.5, c.y + 3.5));
            let front = egui::Rect::from_min_max(egui::pos2(c.x - 3.0, c.y - 2.0), egui::pos2(c.x + 5.5, c.y + 5.5));
            ui.painter().rect_stroke(back, egui::CornerRadius::same(1), st, egui::StrokeKind::Middle);
            ui.painter().rect_filled(front, egui::CornerRadius::same(1), BG);
            ui.painter().rect_stroke(front, egui::CornerRadius::same(1), st, egui::StrokeKind::Middle);
        }
        CaptionGlyph::Close => {
            ui.painter().line_segment([egui::pos2(c.x - 4.5, c.y - 4.5), egui::pos2(c.x + 4.5, c.y + 4.5)], st);
            ui.painter().line_segment([egui::pos2(c.x - 4.5, c.y + 4.5), egui::pos2(c.x + 4.5, c.y - 4.5)], st);
        }
    }
    resp.clicked()
}

/// Windows 习惯标题栏：左侧标题 + 右侧 最小化/最大化/关闭 + 拖拽 + 双击最大化。返回 Some(action)。
enum TitleAction {
    Close,
    Minimize,
    MaximizeToggle,
}
fn title_bar(ui: &mut egui::Ui, maximized: bool) -> Option<TitleAction> {
    let h = 44.0;
    let (bar, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), h), egui::Sense::hover());
    // 左侧标题（Windows 习惯）
    ui.painter().text(
        egui::pos2(bar.left() + 16.0, bar.center().y),
        egui::Align2::LEFT_CENTER,
        "Claude 守护器",
        egui::FontId::proportional(12.0),
        TXT2,
    );
    // 右侧窗口按钮：最小化 / 最大化 / 关闭
    let bw = 46.0;
    let mut act = None;
    let x1 = bar.right();
    let y0 = bar.top();
    if caption_btn(ui, "cap_min", egui::Rect::from_min_max(egui::pos2(x1 - bw * 3.0, y0), egui::pos2(x1 - bw * 2.0, bar.bottom())), CaptionGlyph::Minimize, false) {
        act = Some(TitleAction::Minimize);
    }
    if caption_btn(ui, "cap_max", egui::Rect::from_min_max(egui::pos2(x1 - bw * 2.0, y0), egui::pos2(x1 - bw, bar.bottom())), if maximized { CaptionGlyph::Restore } else { CaptionGlyph::Maximize }, false) {
        act = Some(TitleAction::MaximizeToggle);
    }
    if caption_btn(ui, "cap_close", egui::Rect::from_min_max(egui::pos2(x1 - bw, y0), bar.right_bottom()), CaptionGlyph::Close, true) {
        act = Some(TitleAction::Close);
    }
    // 拖拽区（按钮左侧全部）+ 双击最大化
    let drag_rect = egui::Rect::from_min_max(bar.left_top(), egui::pos2(x1 - bw * 3.0, bar.bottom()));
    let resp = ui.interact(drag_rect, egui::Id::new("titlebar_drag"), egui::Sense::drag());
    if resp.dragged() {
        ui.ctx().send_viewport_cmd(egui::ViewportCommand::StartDrag);
    }
    if resp.double_clicked() {
        act = Some(TitleAction::MaximizeToggle);
    }
    act
}

/// iOS 胶囊开关（规范色：开 Pulse Green / 关 Mist），改动返回 true
fn ios_toggle(ui: &mut egui::Ui, id: &str, on: &mut bool) -> bool {
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(50.0, 30.0), egui::Sense::click());
    let changed = if resp.clicked() {
        *on = !*on;
        true
    } else {
        false
    };
    let t = ui.ctx().animate_value_with_time(egui::Id::new(id), if *on { 1.0 } else { 0.0 }, 0.15);
    let lerp = |a: u8, b: u8| (a as f32 + (b as f32 - a as f32) * t) as u8;
    let track = egui::Color32::from_rgb(lerp(0xE2, 0x03), lerp(0xE2, 0xAA), lerp(0xE5, 0x49));
    ui.painter().rect_filled(rect, egui::CornerRadius::same(15), track);
    let kx = rect.left() + 15.0 + (rect.right() - 15.0 - (rect.left() + 15.0)) * t;
    let ky = rect.center().y;
    ui.painter()
        .circle_stroke(egui::pos2(kx, ky), 12.0, egui::Stroke::new(1.0, egui::Color32::from_black_alpha(20)));
    ui.painter().circle_filled(egui::pos2(kx, ky), 11.6, egui::Color32::WHITE);
    changed
}

/// 胶囊主按钮（规范：全圆 980px / 17px 文字 / Signal Blue 是唯一彩色填充）
fn capsule(ui: &mut egui::Ui, _id: &str, label: &str, w: f32, bg: egui::Color32, bg_hover: egui::Color32, enabled: bool) -> bool {
    let h = 44.0;
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(w, h), egui::Sense::click());
    let color = if !enabled {
        MIST
    } else if resp.hovered() {
        bg_hover
    } else {
        bg
    };
    ui.painter().rect_filled(rect, egui::CornerRadius::same(22), color);
    btext(ui, rect.center(), egui::Align2::CENTER_CENTER, label, 17.0, if enabled { egui::Color32::WHITE } else { TXT2 });
    resp.clicked() && enabled
}

/// 小文字链接（规范：Deep Link Blue，hover 出下划线）
fn text_link(ui: &mut egui::Ui, id: &str, label: &str, size: f32, color: egui::Color32) -> bool {
    let tw = ui.painter().layout_no_wrap(label.to_string(), egui::FontId::proportional(size), color).size().x;
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(tw + 6.0, size * 1.7), egui::Sense::click());
    let hover = resp.hovered();
    ui.painter().text(
        rect.left_center(),
        egui::Align2::LEFT_CENTER,
        label,
        egui::FontId::proportional(size),
        color,
    );
    if hover {
        let y = rect.left_center().y + size * 0.72;
        ui.painter().line_segment([egui::pos2(rect.left(), y), egui::pos2(rect.left() + tw, y)], egui::Stroke::new(1.0, color));
    }
    resp.clicked()
}

/// 白色卡片（规范：28px 圆角 + 1px Fog 发丝线，无阴影；矮窗口用小内边距）
fn card_p(ui: &mut egui::Ui, pad: i8, add: impl FnOnce(&mut egui::Ui)) {
    ui.add_space(2.0);
    egui::Frame::new()
        .fill(CARD)
        .stroke(egui::Stroke::new(1.0, SEP))
        .corner_radius(28)
        .inner_margin(egui::Margin::same(pad))
        .outer_margin(egui::Margin::same(2))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            add(ui);
        });
}

fn card(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) {
    card_p(ui, 20, add);
}

/// 卡片内设置行：左侧 标题+说明，右侧控件
fn setting_row(ui: &mut egui::Ui, title: &str, desc: &str, right: impl FnOnce(&mut egui::Ui)) {
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.set_min_width(ui.available_width() - 170.0);
            ui.label(egui::RichText::new(title).size(14.0).color(TXT));
            ui.label(egui::RichText::new(desc).size(12.0).color(TXT2));
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            right(ui);
        });
    });
    ui.add_space(2.0);
}

fn hairline(ui: &mut egui::Ui) {
    let w = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(egui::vec2(w, 1.0), egui::Sense::hover());
    ui.painter().rect_filled(rect, egui::CornerRadius::same(1), SEP);
}

fn lerp_color(a: egui::Color32, b: egui::Color32, t: f32) -> egui::Color32 {
    let l = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t) as u8;
    egui::Color32::from_rgb(l(a.r(), b.r()), l(a.g(), b.g()), l(a.b(), b.b()))
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
    wiz_page: u8,
    show_details: bool,
    show_settings: bool,
    show_log: bool,
    notice: Option<(String, Instant)>,
    // 设置编辑缓冲
    ed_port: String,
    ed_ip: String,
    ed_interval: String,
    ed_target: String,
    err_port: Option<String>,
    err_ip: Option<String>,
    err_interval: Option<String>,
    err_target: Option<String>,
}

impl GuardApp {
    pub fn new(cc: &eframe::CreationContext<'_>, start_hidden: bool, tray_img: tray_icon::Icon) -> Self {
        install_fonts(&cc.egui_ctx);
        apple_style(&cc.egui_ctx);

        let cfg = Config::load();
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
            ed_target: cfg.connect_target.clone(),
            err_port: None,
            err_ip: None,
            err_interval: None,
            err_target: None,
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
            show_settings: false,
            show_log: false,
            notice: None,
        }
    }

    fn spawn_check(&self, ctx: &egui::Context, purpose: Purpose) {
        let sh = self.sh.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || run_check(&sh, &ctx, purpose));
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

    fn do_install(&mut self) {
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

    fn finish_wizard(&mut self) {
        {
            let mut cfg = self.sh.cfg.lock().unwrap();
            cfg.first_run = false;
            let _ = cfg.save();
        }
        self.screen = Screen::Main;
    }

    // ---------------- 首跑向导 ----------------
    fn wizard_ui(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        match self.wiz_page {
            0 => {
                ui.add_space(16.0);
                {
                    let (r, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 34.0), egui::Sense::hover());
                    btext(ui, r.center(), egui::Align2::CENTER_CENTER, "欢迎使用", 24.0, TXT);
                }
                {
                    let (r, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 34.0), egui::Sense::hover());
                    btext(ui, r.center(), egui::Align2::CENTER_CENTER, "Claude 守护器", 24.0, TXT);
                }
                ui.add_space(10.0);
                card(ui, |ui| {
                    ui.label(egui::RichText::new("它做三件事").size(13.0).color(TXT2));
                    ui.add_space(6.0);
                    for (t, d) in [
                        ("替你把关", "打开 Claude 前，先确认网络走的是约定的出口"),
                        ("一直在守护", "常驻后台，每隔几秒复查一次，不用你操心"),
                        ("不对就刹车", "一旦出口不对，立刻停掉 Claude 并断开它的联网"),
                    ] {
                        ui.horizontal(|ui| {
                            let (r, _) = ui.allocate_exact_size(egui::vec2(12.0, 14.0), egui::Sense::hover());
                            ui.painter().circle_filled(r.center(), 2.5, BLUE);
                            ui.label(egui::RichText::new(t).size(14.0).color(TXT));
                            ui.label(egui::RichText::new(d).size(12.0).color(TXT2));
                        });
                    }
                });
                ui.add_space(14.0);
                wiz_dots(ui, self.wiz_page);
                ui.add_space(10.0);
                ui.vertical_centered(|ui| {
                    let avail = (ui.available_width() - 28.0).min(320.0);
                    if capsule(ui, "wiz_next0", "继续", avail, BLUE, BLUE_H, true) {
                        self.wiz_page = 1;
                    }
                });
            }
            1 => {
                ui.add_space(8.0);
                {
                    let (r, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 30.0), egui::Sense::hover());
                    btext(ui, r.center(), egui::Align2::CENTER_CENTER, "两个关键数字", 21.0, TXT);
                }
                ui.vertical_centered(|ui| {
                    ui.label(egui::RichText::new("不知道的话，保持默认就好").size(12.0).color(TXT2));
                });
                ui.add_space(8.0);
                card(ui, |ui| {
                    ui.label(egui::RichText::new("代理端口").size(14.0).color(TXT));
                    ui.label(egui::RichText::new("代理软件的端口，常见是 7890").size(12.0).color(TXT2));
                    let r = ui.add(egui::TextEdit::singleline(&mut self.ed_port).desired_width(180.0));
                    if let Some(e) = &self.err_port {
                        ui.label(egui::RichText::new(e).size(12.0).color(RED));
                    }
                    let _ = r;
                    ui.add_space(6.0);
                    hairline(ui);
                    ui.add_space(6.0);
                    ui.label(egui::RichText::new("约定的出口 IP").size(14.0).color(TXT));
                    ui.label(egui::RichText::new("只有从这个出口走，才允许用 Claude").size(12.0).color(TXT2));
                    let r2 = ui.add(egui::TextEdit::singleline(&mut self.ed_ip).desired_width(180.0));
                    let _ = r2;
                    if let Some(e) = &self.err_ip {
                        ui.label(egui::RichText::new(e).size(12.0).color(RED));
                    }
                });
                let ok_port = self.ed_port.trim().parse::<u16>().is_ok();
                let ok_ip = std::net::Ipv4Addr::from_str(self.ed_ip.trim()).is_ok();
                self.err_port.set_if_none_else_clear(!ok_port, "端口需为 1-65535 的数字");
                self.err_ip.set_if_none_else_clear(!ok_ip, "要写成 4 段数字，如 204.1.100.98");
                ui.add_space(14.0);
                wiz_dots(ui, self.wiz_page);
                ui.add_space(10.0);
                ui.vertical_centered(|ui| {
                    let avail = (ui.available_width() - 28.0).min(320.0);
                    if capsule(ui, "wiz_next1", "继续", avail, BLUE, BLUE_H, ok_port && ok_ip) {
                        self.wiz_page = 2;
                    }
                    ui.add_space(4.0);
                    if text_link(ui, "wiz_back1", "上一步", 12.0, LINK) {
                        self.wiz_page = 0;
                    }
                });
            }
            _ => {
                ui.add_space(8.0);
                {
                    let (r, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 30.0), egui::Sense::hover());
                    btext(ui, r.center(), egui::Align2::CENTER_CENTER, "最后一步", 21.0, TXT);
                }
                ui.vertical_centered(|ui| {
                    ui.label(egui::RichText::new("要把它装进这台电脑吗？").size(12.0).color(TXT2));
                });
                ui.add_space(8.0);
                card(ui, |ui| {
                    let (rect, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 64.0), egui::Sense::click());
                    ui.painter().rect_filled(rect, egui::CornerRadius::same(10), BG);
                    ui.painter().rect_stroke(rect, egui::CornerRadius::same(10), egui::Stroke::new(if resp.hovered() { 1.5 } else { 1.0 }, if resp.hovered() { BLUE } else { SEP }), egui::StrokeKind::Middle);
                    ui.painter().text(egui::pos2(rect.left() + 14.0, rect.center().y - 10.0), egui::Align2::LEFT_CENTER, "安装到这台电脑（推荐）", egui::FontId::proportional(14.0), TXT);
                    ui.painter().text(egui::pos2(rect.left() + 14.0, rect.center().y + 12.0), egui::Align2::LEFT_CENTER, "放进程序列表，桌面建快捷方式，随时可卸载", egui::FontId::proportional(12.0), TXT2);
                    let click_a = resp.clicked();
                    ui.add_space(4.0);
                    let (rect2, resp2) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 64.0), egui::Sense::click());
                    ui.painter().rect_filled(rect2, egui::CornerRadius::same(10), BG);
                    ui.painter().rect_stroke(rect2, egui::CornerRadius::same(10), egui::Stroke::new(if resp2.hovered() { 1.5 } else { 1.0 }, if resp2.hovered() { BLUE } else { SEP }), egui::StrokeKind::Middle);
                    ui.painter().text(egui::pos2(rect2.left() + 14.0, rect2.center().y - 10.0), egui::Align2::LEFT_CENTER, "直接用，不安装", egui::FontId::proportional(14.0), TXT);
                    ui.painter().text(egui::pos2(rect2.left() + 14.0, rect2.center().y + 12.0), egui::Align2::LEFT_CENTER, "这次打开就当便携版用，不影响功能", egui::FontId::proportional(12.0), TXT2);
                    let click_b = resp2.clicked();
                    if click_a {
                        self.do_install();
                        self.finish_wizard();
                    } else if click_b {
                        self.finish_wizard();
                    }
                });
                ui.add_space(12.0);
                wiz_dots(ui, self.wiz_page);
                ui.add_space(10.0);
                ui.vertical_centered(|ui| {
                    if text_link(ui, "wiz_back2", "上一步", 12.0, LINK) {
                        self.wiz_page = 1;
                    }
                });
            }
        }
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
                ui.label(egui::RichText::new(format!("ClaudeGuard v{}", env!("CARGO_PKG_VERSION"))).size(12.0).color(TXT2));
                ui.label(egui::RichText::new("·").size(12.0).color(TXT2));
                if text_link(ui, "ft_data", "打开数据文件夹", 12.0, LINK) {
                    let _ = std::process::Command::new("explorer.exe")
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
                        self.err_ip = Some("要写成 4 段数字，如 204.1.100.98".into());
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
            if saved {
                let _ = self.sh.cfg.lock().unwrap().save();
                self.notice = Some(("已保存".into(), Instant::now()));
            }
        });
    }
}

/// 弧线（手动画线段，避免 API 差异）
fn arc(ui: &mut egui::Ui, c: egui::Pos2, r: f32, a0: f32, a1: f32, w: f32, color: egui::Color32) {
    let n = ((a1 - a0).abs() / 0.15).ceil().max(2.0) as usize;
    let mut prev = egui::pos2(c.x + r * a0.cos(), c.y + r * a0.sin());
    for i in 1..=n {
        let a = a0 + (a1 - a0) * i as f32 / n as f32;
        let p = egui::pos2(c.x + r * a.cos(), c.y + r * a.sin());
        ui.painter().line_segment([prev, p], egui::Stroke::new(w, color));
        prev = p;
    }
}

trait ErrOpt {
    fn set_if_none_else_clear(&mut self, err: bool, msg: &str);
}
impl ErrOpt for Option<String> {
    fn set_if_none_else_clear(&mut self, err: bool, msg: &str) {
        if err {
            if self.is_none() {
                *self = Some(msg.into());
            }
        } else {
            *self = None;
        }
    }
}

/// 展开指示小箭头（矢量，避免缺字形）
fn chevron(ui: &mut egui::Ui, at: egui::Pos2, up: bool, color: egui::Color32) {
    let (a, b, c) = if up {
        (
            egui::pos2(at.x - 4.0, at.y + 2.0),
            egui::pos2(at.x, at.y - 2.5),
            egui::pos2(at.x + 4.0, at.y + 2.0),
        )
    } else {
        (
            egui::pos2(at.x - 4.0, at.y - 2.0),
            egui::pos2(at.x, at.y + 2.5),
            egui::pos2(at.x + 4.0, at.y - 2.0),
        )
    };
    let st = egui::Stroke::new(1.6, color);
    ui.painter().line_segment([a, b], st);
    ui.painter().line_segment([b, c], st);
}

/// 明细行
fn step_row(ui: &mut egui::Ui, name: &str, res: &crate::checks::StepResult) {
    let (c, txt) = match res.state {
        StepState::Pass => (GREEN, res.text.clone()),
        StepState::Fail => (RED, res.text.clone()),
        StepState::Running => (BLUE, res.text.clone()),
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

/// 提示横幅（规范：白卡 + 状态色发丝线，不用彩色大填充）
fn banner(ui: &mut egui::Ui, color: egui::Color32, title: &str, desc: &str, compact: bool) {
    egui::Frame::new()
        .fill(CARD)
        .stroke(egui::Stroke::new(1.0, lerp_color(SEP, color, 0.55)))
        .corner_radius(if compact { 10 } else { 14 })
        .inner_margin(egui::Margin::same(if compact { 10 } else { 14 }))
        .outer_margin(egui::Margin::symmetric(2, if compact { 1 } else { 2 }))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                let (r, _) = ui.allocate_exact_size(egui::vec2(14.0, 14.0), egui::Sense::hover());
                ui.painter().circle_filled(r.center(), 5.5, color);
                ui.label(egui::RichText::new(title).size(if compact { 13.0 } else { 14.0 }).color(TXT));
            });
            ui.label(egui::RichText::new(desc).size(12.0).color(TXT2));
        });
}

/// 禁用态开关（Mist 底 + 白旋钮）
fn ios_toggle_disabled(ui: &mut egui::Ui, id: &str) -> bool {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(50.0, 30.0), egui::Sense::hover());
    let _ = id;
    ui.painter().rect_filled(rect, egui::CornerRadius::same(15), MIST);
    ui.painter().circle_filled(egui::pos2(rect.left() + 15.0, rect.center().y), 11.6, egui::Color32::WHITE);
    false
}

/// 向导步骤圆点（painter 绝对居中，避免布局歧义）
fn wiz_dots(ui: &mut egui::Ui, page: u8) {
    let (drect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 12.0), egui::Sense::hover());
    let dc = drect.center();
    for i in 0..3i32 {
        let col = if i as u8 == page { BLUE } else { SEP };
        ui.painter().circle_filled(egui::pos2(dc.x + (i as f32 - 1.0) * 20.0, dc.y), 4.0, col);
    }
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
                            Screen::Main => self.main_ui(ui, compact),
                        }
                    });
            });
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.sh.stop.store(true, Ordering::SeqCst);
        self.tray = None;
    }
}
