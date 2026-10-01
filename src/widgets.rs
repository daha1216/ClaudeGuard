//! 自绘小部件库：无状态绘制函数 + 标题栏 + 开关/胶囊/链接/卡片等。
//! 全部为纯函数（不持应用状态），颜色常量来自 theme。

use eframe::egui;

use crate::theme::{BG, CARD, CLOSE_RED, MIST, SEP, TXT, TXT2};

/// 仿半粗字重：egui 无字重支持，双重绘制 0.5px 偏移加粗（规范：最重 600）
pub(crate) fn btext(
    ui: &mut egui::Ui,
    pos: egui::Pos2,
    align: egui::Align2,
    text: &str,
    size: f32,
    color: egui::Color32,
) {
    let f = egui::FontId::proportional(size);
    ui.painter().text(pos, align, text, f.clone(), color);
    ui.painter()
        .text(egui::pos2(pos.x + 0.5, pos.y), align, text, f, color);
}

/// Windows 窗口按钮字形（矢量，避免字体缺字形）
#[derive(Clone, Copy)]
pub(crate) enum CaptionGlyph {
    Minimize,
    Maximize,
    Restore,
    Close,
}

/// Windows 风格窗口按钮（46×44，hover 浅灰 / 关闭钮 hover 红 + 白字形）
pub(crate) fn caption_btn(
    ui: &mut egui::Ui,
    id: &str,
    rect: egui::Rect,
    glyph: CaptionGlyph,
    close_style: bool,
) -> bool {
    let resp = ui.interact(rect, egui::Id::new(id), egui::Sense::click());
    let hovered = resp.hovered();
    let fill = if close_style {
        if hovered {
            CLOSE_RED
        } else {
            egui::Color32::TRANSPARENT
        }
    } else if hovered {
        egui::Color32::from_rgb(0xE9, 0xE9, 0xEC)
    } else {
        egui::Color32::TRANSPARENT
    };
    if fill != egui::Color32::TRANSPARENT {
        ui.painter()
            .rect_filled(rect, egui::CornerRadius::same(6), fill);
    }
    let c = rect.center();
    let glyph_color = if close_style && hovered {
        egui::Color32::WHITE
    } else {
        TXT
    };
    let st = egui::Stroke::new(1.2, glyph_color);
    match glyph {
        CaptionGlyph::Minimize => {
            ui.painter().line_segment(
                [
                    egui::pos2(c.x - 5.5, c.y + 3.0),
                    egui::pos2(c.x + 5.5, c.y + 3.0),
                ],
                st,
            );
        }
        CaptionGlyph::Maximize => {
            let r = egui::Rect::from_center_size(c, egui::vec2(11.0, 11.0));
            ui.painter()
                .rect_stroke(r, egui::CornerRadius::same(1), st, egui::StrokeKind::Middle);
        }
        CaptionGlyph::Restore => {
            // 背面小方块 + 前面小方块（用画布色遮挡叠压部分，得到经典还原字形）
            let back = egui::Rect::from_min_max(
                egui::pos2(c.x - 5.5, c.y - 5.5),
                egui::pos2(c.x + 3.5, c.y + 3.5),
            );
            let front = egui::Rect::from_min_max(
                egui::pos2(c.x - 3.0, c.y - 2.0),
                egui::pos2(c.x + 5.5, c.y + 5.5),
            );
            ui.painter().rect_stroke(
                back,
                egui::CornerRadius::same(1),
                st,
                egui::StrokeKind::Middle,
            );
            ui.painter()
                .rect_filled(front, egui::CornerRadius::same(1), BG);
            ui.painter().rect_stroke(
                front,
                egui::CornerRadius::same(1),
                st,
                egui::StrokeKind::Middle,
            );
        }
        CaptionGlyph::Close => {
            ui.painter().line_segment(
                [
                    egui::pos2(c.x - 4.5, c.y - 4.5),
                    egui::pos2(c.x + 4.5, c.y + 4.5),
                ],
                st,
            );
            ui.painter().line_segment(
                [
                    egui::pos2(c.x - 4.5, c.y + 4.5),
                    egui::pos2(c.x + 4.5, c.y - 4.5),
                ],
                st,
            );
        }
    }
    resp.clicked()
}

/// Windows 习惯标题栏：左侧标题 + 右侧 最小化/最大化/关闭 + 拖拽 + 双击最大化。返回 Some(action)。
pub(crate) enum TitleAction {
    Close,
    Minimize,
    MaximizeToggle,
}

/// 边缘缩放带厚度(逻辑px)。200% DPI 下=12 物理px，与系统无边框窗口手感一致。
pub(crate) const EDGE_W: f32 = 6.0;
/// 三个标题栏按钮(最小化/最大化/关闭)总宽。顶边缩放带要让出这块(按钮顶边优先响应点击)。
pub(crate) const CAP_BTNS_W: f32 = 46.0 * 3.0;

/// 无边框窗口四边/四角拖拽缩放：悬停切换方向箭头光标，按下交给系统缩放循环
/// (egui `BeginResize` → winit → WM_NCLBUTTONDOWN + HT*)。
/// 每帧在 ui() 末尾调用；最大化时禁用。
pub(crate) fn resize_edges(ctx: &egui::Context, maximized: bool) {
    use egui::viewport::ResizeDirection;
    if maximized {
        return;
    }
    let Some(p) = ctx.pointer_latest_pos() else {
        return;
    };
    let r = ctx.viewport_rect();
    if !r.contains(p) {
        return;
    }
    let west = p.x - r.left() < EDGE_W;
    let east = r.right() - p.x < EDGE_W;
    // 顶边在标题栏按钮区上方不响应，保持按钮完整可点(与系统行为一致)
    let north = p.y - r.top() < EDGE_W && p.x < r.right() - CAP_BTNS_W;
    let south = r.bottom() - p.y < EDGE_W;
    let dir = match (west || east, north || south) {
        (true, true) => Some(if west == north {
            if west {
                ResizeDirection::NorthWest
            } else {
                ResizeDirection::SouthEast
            }
        } else if west {
            ResizeDirection::SouthWest
        } else {
            ResizeDirection::NorthEast
        }),
        (true, false) => Some(if west {
            ResizeDirection::West
        } else {
            ResizeDirection::East
        }),
        (false, true) => Some(if north {
            ResizeDirection::North
        } else {
            ResizeDirection::South
        }),
        (false, false) => None,
    };
    let Some(dir) = dir else { return };
    // 边缘带矩形(角为正方形, 边为整条带)
    let (l, rt, t, b) = (r.left(), r.right(), r.top(), r.bottom());
    let band = match dir {
        ResizeDirection::North => {
            egui::Rect::from_min_max(egui::pos2(l, t), egui::pos2(rt, t + EDGE_W))
        }
        ResizeDirection::South => {
            egui::Rect::from_min_max(egui::pos2(l, b - EDGE_W), egui::pos2(rt, b))
        }
        ResizeDirection::West => {
            egui::Rect::from_min_max(egui::pos2(l, t), egui::pos2(l + EDGE_W, b))
        }
        ResizeDirection::East => {
            egui::Rect::from_min_max(egui::pos2(rt - EDGE_W, t), egui::pos2(rt, b))
        }
        ResizeDirection::NorthWest => {
            egui::Rect::from_min_max(egui::pos2(l, t), egui::pos2(l + EDGE_W, t + EDGE_W))
        }
        ResizeDirection::NorthEast => {
            egui::Rect::from_min_max(egui::pos2(rt - EDGE_W, t), egui::pos2(rt, t + EDGE_W))
        }
        ResizeDirection::SouthWest => {
            egui::Rect::from_min_max(egui::pos2(l, b - EDGE_W), egui::pos2(l + EDGE_W, b))
        }
        ResizeDirection::SouthEast => {
            egui::Rect::from_min_max(egui::pos2(rt - EDGE_W, b - EDGE_W), egui::pos2(rt, b))
        }
    };
    // 必须注册真实交互控件: 纯数学判断不参与 egui 命中测试, egui-winit 会把按下事件当
    // "无控件要输入"丢弃, BeginResize 永远发不出去。用 Foreground 层的隐形 Area 承接。
    egui::Area::new(egui::Id::new("resize-band"))
        .order(egui::Order::Foreground)
        .fixed_pos(band.min)
        .interactable(true)
        .show(ctx, |ui| {
            let resp = ui.allocate_rect(band, egui::Sense::drag());
            if resp.is_pointer_button_down_on() || resp.drag_started() {
                ctx.send_viewport_cmd(egui::ViewportCommand::BeginResize(dir));
            }
        });
    ctx.set_cursor_icon(match dir {
        ResizeDirection::North => egui::CursorIcon::ResizeNorth,
        ResizeDirection::South => egui::CursorIcon::ResizeSouth,
        ResizeDirection::East => egui::CursorIcon::ResizeEast,
        ResizeDirection::West => egui::CursorIcon::ResizeWest,
        ResizeDirection::NorthEast => egui::CursorIcon::ResizeNorthEast,
        ResizeDirection::NorthWest => egui::CursorIcon::ResizeNorthWest,
        ResizeDirection::SouthEast => egui::CursorIcon::ResizeSouthEast,
        ResizeDirection::SouthWest => egui::CursorIcon::ResizeSouthWest,
    });
}

pub(crate) fn title_bar(ui: &mut egui::Ui, maximized: bool) -> Option<TitleAction> {
    let h = 44.0;
    let (bar, _) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), h), egui::Sense::hover());
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
    if caption_btn(
        ui,
        "cap_min",
        egui::Rect::from_min_max(
            egui::pos2(x1 - bw * 3.0, y0),
            egui::pos2(x1 - bw * 2.0, bar.bottom()),
        ),
        CaptionGlyph::Minimize,
        false,
    ) {
        act = Some(TitleAction::Minimize);
    }
    if caption_btn(
        ui,
        "cap_max",
        egui::Rect::from_min_max(
            egui::pos2(x1 - bw * 2.0, y0),
            egui::pos2(x1 - bw, bar.bottom()),
        ),
        if maximized {
            CaptionGlyph::Restore
        } else {
            CaptionGlyph::Maximize
        },
        false,
    ) {
        act = Some(TitleAction::MaximizeToggle);
    }
    if caption_btn(
        ui,
        "cap_close",
        egui::Rect::from_min_max(egui::pos2(x1 - bw, y0), bar.right_bottom()),
        CaptionGlyph::Close,
        true,
    ) {
        act = Some(TitleAction::Close);
    }
    // 拖拽区（按钮左侧全部）+ 双击最大化；顶边让出 EDGE_W 给缩放带，避免按下同时发 StartDrag+BeginResize
    let drag_rect = egui::Rect::from_min_max(
        egui::pos2(bar.left(), bar.top() + if maximized { 0.0 } else { EDGE_W }),
        egui::pos2(x1 - bw * 3.0, bar.bottom()),
    );
    let resp = ui.interact(
        drag_rect,
        egui::Id::new("titlebar_drag"),
        egui::Sense::drag(),
    );
    if resp.dragged() {
        ui.ctx().send_viewport_cmd(egui::ViewportCommand::StartDrag);
    }
    if resp.double_clicked() {
        act = Some(TitleAction::MaximizeToggle);
    }
    act
}

/// iOS 胶囊开关（规范色：开 Pulse Green / 关 Mist），改动返回 true
pub(crate) fn ios_toggle(ui: &mut egui::Ui, id: &str, on: &mut bool) -> bool {
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(50.0, 30.0), egui::Sense::click());
    let changed = if resp.clicked() {
        *on = !*on;
        true
    } else {
        false
    };
    let t = ui
        .ctx()
        .animate_value_with_time(egui::Id::new(id), if *on { 1.0 } else { 0.0 }, 0.15);
    let lerp = |a: u8, b: u8| (a as f32 + (b as f32 - a as f32) * t) as u8;
    let track = egui::Color32::from_rgb(lerp(0xE2, 0x03), lerp(0xE2, 0xAA), lerp(0xE5, 0x49));
    ui.painter()
        .rect_filled(rect, egui::CornerRadius::same(15), track);
    let kx = rect.left() + 15.0 + (rect.right() - 15.0 - (rect.left() + 15.0)) * t;
    let ky = rect.center().y;
    ui.painter().circle_stroke(
        egui::pos2(kx, ky),
        12.0,
        egui::Stroke::new(1.0, egui::Color32::from_black_alpha(20)),
    );
    ui.painter()
        .circle_filled(egui::pos2(kx, ky), 11.6, egui::Color32::WHITE);
    changed
}

/// 胶囊主按钮（规范：全圆 980px / 17px 文字 / Signal Blue 是唯一彩色填充）
pub(crate) fn capsule(
    ui: &mut egui::Ui,
    _id: &str,
    label: &str,
    w: f32,
    bg: egui::Color32,
    bg_hover: egui::Color32,
    enabled: bool,
) -> bool {
    let h = 44.0;
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(w, h), egui::Sense::click());
    let color = if !enabled {
        MIST
    } else if resp.hovered() {
        bg_hover
    } else {
        bg
    };
    ui.painter()
        .rect_filled(rect, egui::CornerRadius::same(22), color);
    btext(
        ui,
        rect.center(),
        egui::Align2::CENTER_CENTER,
        label,
        17.0,
        if enabled { egui::Color32::WHITE } else { TXT2 },
    );
    resp.clicked() && enabled
}

/// 小文字链接（规范：Deep Link Blue，hover 出下划线）
pub(crate) fn text_link(
    ui: &mut egui::Ui,
    _id: &str,
    label: &str,
    size: f32,
    color: egui::Color32,
) -> bool {
    let tw = ui
        .painter()
        .layout_no_wrap(label.to_string(), egui::FontId::proportional(size), color)
        .size()
        .x;
    let (rect, resp) =
        ui.allocate_exact_size(egui::vec2(tw + 6.0, size * 1.7), egui::Sense::click());
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
        ui.painter().line_segment(
            [egui::pos2(rect.left(), y), egui::pos2(rect.left() + tw, y)],
            egui::Stroke::new(1.0, color),
        );
    }
    resp.clicked()
}

/// 白色卡片（规范：28px 圆角 + 1px Fog 发丝线，无阴影；矮窗口用小内边距）
pub(crate) fn card_p(ui: &mut egui::Ui, pad: i8, add: impl FnOnce(&mut egui::Ui)) {
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

pub(crate) fn card(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) {
    card_p(ui, 20, add);
}

/// 卡片内设置行：左侧 标题+说明，右侧控件
pub(crate) fn setting_row(
    ui: &mut egui::Ui,
    title: &str,
    desc: &str,
    right: impl FnOnce(&mut egui::Ui),
) {
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

pub(crate) fn hairline(ui: &mut egui::Ui) {
    let w = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(egui::vec2(w, 1.0), egui::Sense::hover());
    ui.painter()
        .rect_filled(rect, egui::CornerRadius::same(1), SEP);
}

pub(crate) fn lerp_color(a: egui::Color32, b: egui::Color32, t: f32) -> egui::Color32 {
    let l = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t) as u8;
    egui::Color32::from_rgb(l(a.r(), b.r()), l(a.g(), b.g()), l(a.b(), b.b()))
}

/// 弧线（手动画线段，避免 API 差异）
pub(crate) fn arc(
    ui: &mut egui::Ui,
    c: egui::Pos2,
    r: f32,
    a0: f32,
    a1: f32,
    w: f32,
    color: egui::Color32,
) {
    let n = ((a1 - a0).abs() / 0.15).ceil().max(2.0) as usize;
    let mut prev = egui::pos2(c.x + r * a0.cos(), c.y + r * a0.sin());
    for i in 1..=n {
        let a = a0 + (a1 - a0) * i as f32 / n as f32;
        let p = egui::pos2(c.x + r * a.cos(), c.y + r * a.sin());
        ui.painter()
            .line_segment([prev, p], egui::Stroke::new(w, color));
        prev = p;
    }
}

/// 展开指示小箭头（矢量，避免缺字形）
pub(crate) fn chevron(ui: &mut egui::Ui, at: egui::Pos2, up: bool, color: egui::Color32) {
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

/// 提示横幅（规范：白卡 + 状态色发丝线，不用彩色大填充）
pub(crate) fn banner(
    ui: &mut egui::Ui,
    color: egui::Color32,
    title: &str,
    desc: &str,
    compact: bool,
) {
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
                ui.label(
                    egui::RichText::new(title)
                        .size(if compact { 13.0 } else { 14.0 })
                        .color(TXT),
                );
            });
            ui.label(egui::RichText::new(desc).size(12.0).color(TXT2));
        });
}

/// 禁用态开关（Mist 底 + 白旋钮）
pub(crate) fn ios_toggle_disabled(ui: &mut egui::Ui, id: &str) -> bool {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(50.0, 30.0), egui::Sense::hover());
    let _ = id;
    ui.painter()
        .rect_filled(rect, egui::CornerRadius::same(15), MIST);
    ui.painter().circle_filled(
        egui::pos2(rect.left() + 15.0, rect.center().y),
        11.6,
        egui::Color32::WHITE,
    );
    false
}

/// 表单错误缓冲小助手：出错时置默认消息（不覆盖已有），正确时清空
pub(crate) trait ErrOpt {
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
