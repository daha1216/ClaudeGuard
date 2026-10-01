//! 首次运行向导（三页：欢迎 → 端口/IP → 安装选择）。

use std::str::FromStr;

use eframe::egui;

use crate::app::GuardApp;
use crate::theme::{BG, BLUE, BLUE_H, LINK, RED, SEP, TXT, TXT2};
use crate::widgets::{btext, capsule, card, hairline, text_link, ErrOpt};

/// 向导步骤圆点（painter 绝对居中，避免布局歧义）
fn wiz_dots(ui: &mut egui::Ui, page: u8) {
    let (drect, _) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 12.0), egui::Sense::hover());
    let dc = drect.center();
    for i in 0..3i32 {
        let col = if i as u8 == page { BLUE } else { SEP };
        ui.painter()
            .circle_filled(egui::pos2(dc.x + (i as f32 - 1.0) * 20.0, dc.y), 4.0, col);
    }
}

impl GuardApp {
    pub(crate) fn wizard_ui(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        match self.wiz_page {
            0 => {
                ui.add_space(16.0);
                {
                    let (r, _) = ui.allocate_exact_size(
                        egui::vec2(ui.available_width(), 34.0),
                        egui::Sense::hover(),
                    );
                    btext(
                        ui,
                        r.center(),
                        egui::Align2::CENTER_CENTER,
                        "欢迎使用",
                        24.0,
                        TXT,
                    );
                }
                {
                    let (r, _) = ui.allocate_exact_size(
                        egui::vec2(ui.available_width(), 34.0),
                        egui::Sense::hover(),
                    );
                    btext(
                        ui,
                        r.center(),
                        egui::Align2::CENTER_CENTER,
                        "Claude 守护器",
                        24.0,
                        TXT,
                    );
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
                            let (r, _) = ui
                                .allocate_exact_size(egui::vec2(12.0, 14.0), egui::Sense::hover());
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
                    let (r, _) = ui.allocate_exact_size(
                        egui::vec2(ui.available_width(), 30.0),
                        egui::Sense::hover(),
                    );
                    btext(
                        ui,
                        r.center(),
                        egui::Align2::CENTER_CENTER,
                        "两个关键数字",
                        21.0,
                        TXT,
                    );
                }
                ui.vertical_centered(|ui| {
                    ui.label(
                        egui::RichText::new("不知道的话，保持默认就好")
                            .size(12.0)
                            .color(TXT2),
                    );
                });
                ui.add_space(8.0);
                card(ui, |ui| {
                    ui.label(egui::RichText::new("代理端口").size(14.0).color(TXT));
                    ui.label(
                        egui::RichText::new("代理软件的端口，常见是 7890")
                            .size(12.0)
                            .color(TXT2),
                    );
                    let r =
                        ui.add(egui::TextEdit::singleline(&mut self.ed_port).desired_width(180.0));
                    if let Some(e) = &self.err_port {
                        ui.label(egui::RichText::new(e).size(12.0).color(RED));
                    }
                    let _ = r;
                    ui.add_space(6.0);
                    hairline(ui);
                    ui.add_space(6.0);
                    ui.label(egui::RichText::new("约定的出口 IP").size(14.0).color(TXT));
                    ui.label(
                        egui::RichText::new("只有从这个出口走，才允许用 Claude")
                            .size(12.0)
                            .color(TXT2),
                    );
                    let r2 =
                        ui.add(egui::TextEdit::singleline(&mut self.ed_ip).desired_width(180.0));
                    let _ = r2;
                    if let Some(e) = &self.err_ip {
                        ui.label(egui::RichText::new(e).size(12.0).color(RED));
                    }
                });
                let ok_port = self.ed_port.trim().parse::<u16>().is_ok();
                let ok_ip = std::net::Ipv4Addr::from_str(self.ed_ip.trim()).is_ok();
                self.err_port
                    .set_if_none_else_clear(!ok_port, "端口需为 1-65535 的数字");
                self.err_ip
                    .set_if_none_else_clear(!ok_ip, "要写成 4 段数字，如 203.0.113.10");
                ui.add_space(14.0);
                wiz_dots(ui, self.wiz_page);
                ui.add_space(10.0);
                ui.vertical_centered(|ui| {
                    let avail = (ui.available_width() - 28.0).min(320.0);
                    if capsule(
                        ui,
                        "wiz_next1",
                        "继续",
                        avail,
                        BLUE,
                        BLUE_H,
                        ok_port && ok_ip,
                    ) {
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
                    let (r, _) = ui.allocate_exact_size(
                        egui::vec2(ui.available_width(), 30.0),
                        egui::Sense::hover(),
                    );
                    btext(
                        ui,
                        r.center(),
                        egui::Align2::CENTER_CENTER,
                        "最后一步",
                        21.0,
                        TXT,
                    );
                }
                ui.vertical_centered(|ui| {
                    ui.label(
                        egui::RichText::new("要把它装进这台电脑吗？")
                            .size(12.0)
                            .color(TXT2),
                    );
                });
                ui.add_space(8.0);
                card(ui, |ui| {
                    let (rect, resp) = ui.allocate_exact_size(
                        egui::vec2(ui.available_width(), 64.0),
                        egui::Sense::click(),
                    );
                    ui.painter()
                        .rect_filled(rect, egui::CornerRadius::same(10), BG);
                    ui.painter().rect_stroke(
                        rect,
                        egui::CornerRadius::same(10),
                        egui::Stroke::new(
                            if resp.hovered() { 1.5 } else { 1.0 },
                            if resp.hovered() { BLUE } else { SEP },
                        ),
                        egui::StrokeKind::Middle,
                    );
                    ui.painter().text(
                        egui::pos2(rect.left() + 14.0, rect.center().y - 10.0),
                        egui::Align2::LEFT_CENTER,
                        "安装到这台电脑（推荐）",
                        egui::FontId::proportional(14.0),
                        TXT,
                    );
                    ui.painter().text(
                        egui::pos2(rect.left() + 14.0, rect.center().y + 12.0),
                        egui::Align2::LEFT_CENTER,
                        "放进程序列表，桌面建快捷方式，随时可卸载",
                        egui::FontId::proportional(12.0),
                        TXT2,
                    );
                    let click_a = resp.clicked();
                    ui.add_space(4.0);
                    let (rect2, resp2) = ui.allocate_exact_size(
                        egui::vec2(ui.available_width(), 64.0),
                        egui::Sense::click(),
                    );
                    ui.painter()
                        .rect_filled(rect2, egui::CornerRadius::same(10), BG);
                    ui.painter().rect_stroke(
                        rect2,
                        egui::CornerRadius::same(10),
                        egui::Stroke::new(
                            if resp2.hovered() { 1.5 } else { 1.0 },
                            if resp2.hovered() { BLUE } else { SEP },
                        ),
                        egui::StrokeKind::Middle,
                    );
                    ui.painter().text(
                        egui::pos2(rect2.left() + 14.0, rect2.center().y - 10.0),
                        egui::Align2::LEFT_CENTER,
                        "直接用，不安装",
                        egui::FontId::proportional(14.0),
                        TXT,
                    );
                    ui.painter().text(
                        egui::pos2(rect2.left() + 14.0, rect2.center().y + 12.0),
                        egui::Align2::LEFT_CENTER,
                        "这次打开就当便携版用，不影响功能",
                        egui::FontId::proportional(12.0),
                        TXT2,
                    );
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
}
