//! Apple 产品页规范主题（backup/DESIGN (1).md）：调色板 + 字体 + 全局样式。

use eframe::egui;

pub(crate) const BG: egui::Color32 = egui::Color32::from_rgb(0xF5, 0xF5, 0xF7); // Pure Canvas 画布
pub(crate) const CARD: egui::Color32 = egui::Color32::from_rgb(0xFF, 0xFF, 0xFF); // Paper White 卡片
pub(crate) const SEP: egui::Color32 = egui::Color32::from_rgb(0xD6, 0xD6, 0xD6); // Fog 发丝线
pub(crate) const TXT: egui::Color32 = egui::Color32::from_rgb(0x1D, 0x1D, 0x1F); // Obsidian 主文字
pub(crate) const TXT2: egui::Color32 = egui::Color32::from_rgb(0x70, 0x70, 0x70); // Iron Gray 次文字
pub(crate) const BLUE: egui::Color32 = egui::Color32::from_rgb(0x00, 0x71, 0xE3); // Signal Blue 主按钮（唯一彩色填充）
pub(crate) const BLUE_H: egui::Color32 = egui::Color32::from_rgb(0x00, 0x7D, 0xF0); // hover
pub(crate) const LINK: egui::Color32 = egui::Color32::from_rgb(0x00, 0x66, 0xCC); // Deep Link Blue 行内链接
pub(crate) const GREEN: egui::Color32 = egui::Color32::from_rgb(0x03, 0xAA, 0x49); // Pulse Green 通过态
pub(crate) const GREEN_DEEP: egui::Color32 = egui::Color32::from_rgb(0x03, 0x87, 0x3A); // Deep Green 绿色文字
pub(crate) const RED: egui::Color32 = egui::Color32::from_rgb(0xE4, 0x00, 0x2B); // 失败态红
pub(crate) const ORANGE: egui::Color32 = egui::Color32::from_rgb(0xED, 0x63, 0x00); // Ember Orange 警示
pub(crate) const MIST: egui::Color32 = egui::Color32::from_rgb(0xE2, 0xE2, 0xE5); // Mist 中性胶囊/控件面
pub(crate) const CLOSE_RED: egui::Color32 = egui::Color32::from_rgb(0xC4, 0x2B, 0x1C); // Windows 关闭钮 hover

/// 一次性初始化（窗口创建时调用）：先装字体，再上全局样式。
pub(crate) fn init(ctx: &egui::Context) {
    install_fonts(ctx);
    apple_style(ctx);
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
        }
    }
    // Segoe UI 优先（拉丁字形），中文回退微软雅黑，符号回退 Segoe Symbol。
    // move-to-front 须按"想排最前者最后搬"的顺序遍历：先 msyh 后 segoe => [segoe, msyh, ...]
    if let Some(v) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
        for want in ["msyh", "segoe"] {
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
