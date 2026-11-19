//! Mode A — Tray Quick HUD (`368 × 452` logical px, bottom-right anchored above taskbar).

use crate::app::{AppController, HudWindowView, open_console_window};
use crate::protocol::PipeRequest;
use crate::state::HudProjection;
use crate::theme::{BadgeTone, HeroTone, ThemePalette};
use crate::widgets::controls::{
    ButtonKind, action_button, bento_card, cc_badge, latency_pill, mono_tabular, status_pill,
};
use gpui::{
    Context, Div, Entity, FontWeight, MouseButton, WindowControlArea, div, prelude::*, px, rgb,
    rgba,
};

pub fn render_hud(
    ctrl: Entity<AppController>,
    proj: &HudProjection,
    toast: Option<&(String, bool)>,
    busy: bool,
    p: &'static ThemePalette,
    cx: &mut Context<HudWindowView>,
) -> Div {
    let hero_surface = p.hero(proj.hero.tone);
    let connected = proj.connected;
    let ctrl_sweep = ctrl.clone();
    let ctrl_pause = ctrl.clone();
    let ctrl_recheck = ctrl.clone();
    let ctrl_retry = ctrl.clone();
    let ctrl_console = ctrl.clone();

    let mut grid_cards: Vec<Div> = proj
        .target_tiles
        .iter()
        .take(3)
        .map(|tile| {
            bento_card(p)
                .flex_1()
                .flex_basis(px(0.))
                .min_w(px(0.))
                .p(px(10.))
                .gap(px(4.))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap(px(4.))
                        .child(
                            div()
                                .truncate()
                                .text_size(px(11.5))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.text_primary))
                                .child(tile.name.clone()),
                        )
                        .child(cc_badge(&tile.cc_badge, p)),
                )
                .child(
                    mono_tabular(tile.ip_display.clone())
                        .truncate()
                        .text_size(px(13.))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(rgb(p.text_primary)),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap(px(4.))
                        .child(status_pill(tile.state_label.clone(), tile.badge_tone, p))
                        .child(latency_pill(tile.latency_label.clone(), p)),
                )
        })
        .collect();

    // 4th Bento cell in 2x2 grid: 进程守护
    let orphan_tone = if proj.total_orphans > 0 {
        BadgeTone::Warn
    } else {
        BadgeTone::Pass
    };
    grid_cards.push(
        bento_card(p)
            .flex_1()
            .flex_basis(px(0.))
            .min_w(px(0.))
            .p(px(10.))
            .gap(px(4.))
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap(px(4.))
                    .child(
                        div()
                            .truncate()
                            .text_size(px(11.5))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(rgb(p.text_primary))
                            .child(proj.process_tile_title.clone()),
                    )
                    .child(status_pill(
                        if proj.total_orphans > 0 {
                            format!("{} 孤儿", proj.total_orphans)
                        } else {
                            "干净".into()
                        },
                        orphan_tone,
                        p,
                    )),
            )
            .child(
                div()
                    .truncate()
                    .text_size(px(12.5))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(rgb(p.text_primary))
                    .child(proj.process_tile_value.clone()),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap(px(4.))
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.))
                            .truncate()
                            .text_size(px(10.))
                            .text_color(rgb(p.text_muted))
                            .child(proj.process_tile_sub.clone()),
                    )
                    .child({
                        let sweep_enabled = connected && !busy;
                        let mut btn = div()
                            .id("hud-sweep-orphans")
                            .flex_shrink_0()
                            .px(px(7.))
                            .py(px(2.))
                            .rounded(px(6.))
                            .bg(rgb(p.inset_bg))
                            .border_1()
                            .border_color(rgb(p.inset_border))
                            .text_size(px(10.))
                            .text_color(rgb(if sweep_enabled {
                                p.link_text
                            } else {
                                p.text_muted
                            }))
                            .child("清孤儿");
                        if sweep_enabled {
                            btn = btn.cursor_pointer().on_mouse_up(
                                MouseButton::Left,
                                cx.listener(move |_, _, _, cx| {
                                    ctrl_sweep.update(cx, |c, cx| {
                                        c.send_request(
                                            PipeRequest::SweepOrphans,
                                            Some("孤儿进程清理已执行"),
                                            cx,
                                        );
                                    });
                                }),
                            );
                        }
                        btn
                    }),
            ),
    );

    let row_top = div()
        .flex()
        .gap(px(8.))
        .children(grid_cards.drain(0..grid_cards.len().min(2)));
    let row_bot = div().flex().gap(px(8.)).children(grid_cards);

    let launch_buttons = proj.launch_apps.iter().map(|app| {
        let ctrl_l = ctrl.clone();
        let aid = app.agent_id.clone();
        let paths = app.install_paths.clone();
        let can_try = connected && !busy && app.installed;
        let is_primary = connected
            && proj.hero.can_launch
            && !app.quarantined
            && !app.ag_proxy_blocked
            && app.agent_id == "claude";

        let sub_label = if !connected {
            "未连接"
        } else if app.ag_proxy_blocked {
            "注入丢失"
        } else if app.quarantined {
            "已隔离"
        } else if !proj.hero.can_launch {
            "门禁拦截"
        } else if app.running_count > 0 {
            "● 运行中"
        } else {
            "▶ 启动"
        };

        let (card_bg, card_border, title_color, sub_color) = if is_primary {
            (
                p.primary_btn_bg,
                p.primary_btn_bg,
                p.primary_btn_text,
                p.primary_btn_text,
            )
        } else {
            let fail_badge = p.badge(BadgeTone::Fail);
            let sub = if !connected {
                p.badge_warn.text
            } else if app.ag_proxy_blocked || app.quarantined {
                fail_badge.text
            } else if !proj.hero.can_launch {
                p.text_muted
            } else if app.running_count > 0 {
                p.badge_pass.text
            } else {
                p.link_text
            };
            let border = if connected && app.ag_proxy_blocked {
                fail_badge.dot
            } else {
                p.inset_border
            };
            (p.inset_bg, border, p.text_primary, sub)
        };

        div()
            .id(gpui::ElementId::Name(
                format!("hud-launch-{}", app.agent_id).into(),
            ))
            .flex_1()
            .flex_basis(px(0.))
            .min_w(px(0.))
            .flex()
            .flex_col()
            .items_center()
            .justify_center()
            .gap(px(3.))
            .py(px(8.))
            .px(px(6.))
            .rounded(px(10.))
            .bg(rgb(card_bg))
            .border_1()
            .border_color(rgb(card_border))
            .when(can_try, |d| {
                let hover = if is_primary {
                    p.primary_btn_hover_bg
                } else {
                    p.sidebar_hover_bg
                };
                d.cursor_pointer().hover(move |s| s.bg(rgb(hover)))
            })
            .child(
                div()
                    .text_size(px(12.))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(rgb(title_color))
                    .child(app.label.clone()),
            )
            .child(
                div()
                    .text_size(px(10.))
                    .font_weight(FontWeight::MEDIUM)
                    .text_color(rgb(sub_color))
                    .child(sub_label),
            )
            .when(can_try, |d| {
                d.on_mouse_up(
                    MouseButton::Left,
                    cx.listener(move |_, _, _, cx| {
                        ctrl_l.update(cx, |c, cx| {
                            c.launch_app_with_gate(aid.clone(), paths.clone(), cx);
                        });
                    }),
                )
            })
    });

    // Top Hero Bento Card (with integrated drag area, proxy pill, and close button)
    let hero_card = div()
        .flex()
        .flex_col()
        .flex_shrink_0()
        .p(px(12.))
        .gap(px(5.))
        .rounded(px(14.))
        .bg(rgba(hero_surface.bg))
        .border_1()
        .border_color(rgba(hero_surface.border))
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .gap(px(6.))
                .window_control_area(WindowControlArea::Drag)
                .child(
                    div()
                        .px(px(8.))
                        .py(px(2.5))
                        .rounded(px(999.))
                        .bg(rgba(hero_surface.pill_bg))
                        .text_size(px(10.5))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(rgb(hero_surface.pill_text))
                        .child(format!("● {}", proj.hero.pill_label)),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(5.))
                        .child(
                            div()
                                .px(px(7.))
                                .py(px(2.))
                                .rounded(px(999.))
                                .bg(rgb(p.card_bg))
                                .border_1()
                                .border_color(rgb(p.card_border))
                                .text_size(px(10.))
                                .font_family("Cascadia Mono")
                                .text_color(rgb(p.text_secondary))
                                .child(proj.hero.access_badge.clone()),
                        )
                        .child(
                            div()
                                .id("hud-close-btn")
                                .w(px(22.))
                                .h(px(22.))
                                .rounded(px(6.))
                                .bg(rgb(p.card_bg))
                                .border_1()
                                .border_color(rgb(p.card_border))
                                .flex()
                                .items_center()
                                .justify_center()
                                .text_size(px(10.5))
                                .text_color(rgb(p.text_muted))
                                .cursor_pointer()
                                .hover(|s| s.bg(rgb(0xEF4444)).text_color(rgb(0xFFFFFF)))
                                .child("✕")
                                .on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(|view, _, window, cx| {
                                        view.ctrl.update(cx, |c, _| c.hud_window = None);
                                        window.remove_window();
                                    }),
                                ),
                        ),
                ),
        )
        .child(
            div()
                .flex()
                .items_baseline()
                .justify_between()
                .gap(px(8.))
                .window_control_area(WindowControlArea::Drag)
                .child(
                    div()
                        .text_size(px(16.5))
                        .font_weight(FontWeight::BOLD)
                        .text_color(rgb(hero_surface.title))
                        .child(proj.hero.title.clone()),
                )
                .child(
                    div()
                        .text_size(px(10.5))
                        .text_color(rgb(hero_surface.subtitle))
                        .child(format!(
                            "{} 通过 · {}",
                            proj.hero.pass_count, proj.hero.checked_age_text
                        )),
                ),
        )
        .child(
            div()
                .text_size(px(11.))
                .line_height(px(15.5))
                .text_color(rgb(hero_surface.subtitle))
                .child(proj.hero.subtitle.clone()),
        );

    // Tight middle Bento stack (never stretches vertically; scrolls cleanly if toast/offline card appears)
    let middle_stack = div()
        .id("hud-middle-scroll")
        .flex()
        .flex_col()
        .flex_1()
        .min_h(px(0.))
        .overflow_y_scroll()
        .gap(px(8.))
        .when(!connected, |col| {
            let err_text = proj
                .connection_err
                .clone()
                .unwrap_or_else(|| "无法连接到命名管道 \\\\.\\pipe\\ClaudeGuardV4".into());
            col.child(
                bento_card(p)
                    .p(px(10.))
                    .gap(px(6.))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(
                                div()
                                    .text_size(px(12.))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .text_color(rgb(p.text_primary))
                                    .child("守护通信已断开 · 安全闭锁"),
                            )
                            .child(status_pill("未连接", BadgeTone::Warn, p)),
                    )
                    .child(
                        div()
                            .text_size(px(10.5))
                            .line_height(px(15.))
                            .text_color(rgb(p.text_secondary))
                            .child(err_text),
                    )
                    .child(
                        action_button(
                            "hud-retry-conn",
                            "↻ 重试连接守护服务",
                            ButtonKind::Primary,
                            !busy,
                            p,
                        )
                        .when(!busy, |b| {
                            b.on_mouse_up(
                                MouseButton::Left,
                                cx.listener(move |_, _, _, cx| {
                                    ctrl_retry.update(cx, |c, cx| {
                                        c.send_request(
                                            PipeRequest::GetSnapshot,
                                            Some("已重新连接到 Guardian 守护服务"),
                                            cx,
                                        );
                                    });
                                }),
                            )
                        }),
                    ),
            )
        })
        .when(!proj.target_tiles.is_empty(), |col| {
            col.child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(8.))
                    .child(row_top)
                    .child(row_bot),
            )
        })
        .when_some(proj.ag_proxy_warning.clone(), |col, warn_msg| {
            let b = p.badge(BadgeTone::Fail);
            let ctrl_env = ctrl.clone();
            col.child(
                div()
                    .id("hud-ag-proxy-warn")
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap(px(6.))
                    .px(px(9.))
                    .py(px(5.))
                    .rounded(px(8.))
                    .bg(rgba(b.bg))
                    .border_1()
                    .border_color(rgba(p.hero_tripped.border))
                    .cursor_pointer()
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.))
                            .truncate()
                            .text_size(px(10.5))
                            .font_weight(FontWeight::MEDIUM)
                            .text_color(rgb(b.text))
                            .child(warn_msg),
                    )
                    .on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |view, _, window, cx| {
                            ctrl_env.update(cx, |c, cx| {
                                c.set_nav(crate::state::NavSection::Environment, cx);
                            });
                            open_console_window(ctrl_env.clone(), cx);
                            view.ctrl.update(cx, |c, _| c.hud_window = None);
                            window.remove_window();
                        }),
                    ),
            )
        })
        .child(
            bento_card(p)
                .p(px(10.))
                .gap(px(7.))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .child(
                            div()
                                .text_size(px(11.5))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.text_primary))
                                .child("安全启动应用"),
                        )
                        .child(
                            div()
                                .text_size(px(10.))
                                .text_color(rgb(p.text_muted))
                                .child(if proj.hero.can_launch {
                                    "点击前置核验并拉起"
                                } else {
                                    "未通过前拦截启动"
                                }),
                        ),
                )
                .child(div().flex().gap(px(7.)).children(launch_buttons)),
        )
        .when_some(toast.cloned(), |col, (msg, ok)| {
            let b = if ok { p.badge_pass } else { p.badge_fail };
            col.child(
                div()
                    .px(px(9.))
                    .py(px(5.))
                    .rounded(px(8.))
                    .bg(rgba(b.bg))
                    .text_size(px(10.5))
                    .text_color(rgb(b.text))
                    .child(msg),
            )
        });

    // Footer bar: Pause 30m · Recheck | Open Main Console
    let footer = div()
        .flex()
        .flex_shrink_0()
        .items_center()
        .justify_between()
        .gap(px(6.))
        .pt(px(2.))
        .child(
            div()
                .flex()
                .items_center()
                .gap(px(6.))
                .child(
                    action_button(
                        "hud-pause",
                        proj.pause_button_label.clone(),
                        ButtonKind::Secondary,
                        connected && !busy,
                        p,
                    )
                    .when(connected && !busy, |b| {
                        b.on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |_, _, _, cx| {
                                ctrl_pause.update(cx, |c, cx| c.toggle_pause_30m(cx));
                            }),
                        )
                    }),
                )
                .child(
                    action_button(
                        "hud-recheck",
                        "↻ 重检",
                        ButtonKind::Secondary,
                        connected && !busy,
                        p,
                    )
                    .when(connected && !busy, |b| {
                        b.on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |_, _, _, cx| {
                                ctrl_recheck.update(cx, |c, cx| {
                                    c.send_request(
                                        PipeRequest::RecheckNow { target_id: None },
                                        Some("已重新检测全部出口"),
                                        cx,
                                    );
                                });
                            }),
                        )
                    }),
                ),
        )
        .child(
            action_button(
                "hud-open-console",
                if proj.hero.tone == HeroTone::Tripped {
                    "打开解封控制台 ↖"
                } else {
                    "打开主控制台 ↖"
                },
                ButtonKind::Primary,
                true,
                p,
            )
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(move |view, _, window, cx| {
                    open_console_window(ctrl_console.clone(), cx);
                    view.ctrl.update(cx, |c, _| c.hud_window = None);
                    window.remove_window();
                }),
            ),
        );

    div()
        .flex()
        .flex_col()
        .size_full()
        .p(px(10.))
        .gap(px(8.))
        .child(hero_card)
        .child(middle_stack)
        .child(footer)
}
