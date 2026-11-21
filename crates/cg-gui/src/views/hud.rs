//! Mode A — Compact Frost Ceramic Tray Quick HUD (`398 × 432` logical px, ZERO Mihomo).
//!
//! Layout:
//! - Draggable header with status pulse dot + live CC/latency + close button
//! - IP & proxy port strip
//! - 3-endpoint mini status strip (`Claude` / `Codex` / `Antigravity`)
//! - 2×2 brand-icon Safe Launch Deck (`▶ 启动` / `🔒 锁定`, zero truncation)
//! - Compact footer (`一键全清` | `立即核验`/`复查解封` + `主控台`)

use crate::app::{AppController, HudWindowView, open_console_window};
use crate::assets::{brand_icon, ui_icon};
use crate::protocol::PipeRequest;
use crate::state::HudProjection;
use crate::theme::{BadgeTone, HeroTone, ThemePalette};
use crate::widgets::controls::{ButtonKind, action_button, inset_box, mono_tabular};
use gpui::{
    Context, Div, Entity, FontWeight, MouseButton, WindowControlArea, div, prelude::*, px, rgb,
    rgba,
};

fn hud_short_app(agent_id: &str, fallback: &str) -> String {
    match agent_id {
        "claude" => "Claude".into(),
        "claude-code" => "Code CLI".into(),
        "chatgpt" => "ChatGPT".into(),
        "antigravity" => "Antigravity".into(),
        _ => fallback.to_string(),
    }
}

fn hud_short_target(id: &str, fallback: &str) -> String {
    match id {
        "claude" => "Claude".into(),
        "codex" | "chatgpt" => "Codex".into(),
        "antigravity" => "Antigravity".into(),
        _ => fallback.to_string(),
    }
}

pub fn render_hud(
    ctrl: Entity<AppController>,
    proj: &HudProjection,
    toast: Option<&(String, bool)>,
    busy: bool,
    p: &'static ThemePalette,
    cx: &mut Context<HudWindowView>,
) -> Div {
    let connected = proj.connected;
    let can_act = connected && !busy;
    let tripped = proj.hero.tone == HeroTone::Tripped;
    let proxy_port = ctrl
        .read(cx)
        .snapshot
        .as_ref()
        .map(|s| s.config.proxy_port)
        .unwrap_or(7890);

    let dot_rgb = match proj.hero.tone {
        HeroTone::Healthy => p.badge_pass.dot,
        HeroTone::Tripped => p.badge_fail.dot,
        HeroTone::DisarmedOrPaused => p.badge_warn.dot,
    };

    let primary_tile = proj
        .target_tiles
        .iter()
        .find(|t| t.id == "claude")
        .or_else(|| proj.target_tiles.first());
    let primary_ip = primary_tile
        .map(|t| t.ip_display.clone())
        .unwrap_or_else(|| "等待出口探测".into());
    let right_metric = primary_tile
        .map(|t| format!("{} · {}", t.cc_badge, t.latency_label))
        .unwrap_or_else(|| proj.hero.access_badge.clone());

    let title_text: String = if !connected {
        "守护服务未连接".into()
    } else if tripped {
        "出口熔断锁定".into()
    } else if proj.hero.tone == HeroTone::Healthy {
        "出口纯净合规".into()
    } else {
        proj.hero.title.clone()
    };

    let ctrl_close = ctrl.clone();
    let ctrl_kill_all = ctrl.clone();
    let ctrl_primary = ctrl.clone();
    let ctrl_console = ctrl.clone();

    let mini_targets = proj.target_tiles.iter().take(3).map(|t| {
        let is_fail = t.badge_tone == BadgeTone::Fail;
        let color = if is_fail {
            p.badge_fail.text
        } else if t.badge_tone == BadgeTone::Warn {
            p.badge_warn.text
        } else {
            p.badge_pass.text
        };
        let metric = if is_fail {
            format!("{} 越界", t.cc_badge)
        } else if t.cc_badge == "TLS" {
            t.latency_label.clone()
        } else {
            format!("{} · {}", t.cc_badge, t.latency_label)
        };
        inset_box(p)
            .flex_1()
            .flex_basis(px(0.))
            .min_w(px(0.))
            .px(px(8.))
            .py(px(6.5))
            .gap(px(2.))
            .when(is_fail, |box_d| {
                box_d
                    .bg(rgba(p.badge_fail.bg))
                    .border_color(rgba(p.hero_tripped.border))
            })
            .child(
                div()
                    .truncate()
                    .text_size(px(10.5))
                    .text_color(rgb(p.text_secondary))
                    .child(hud_short_target(&t.id, &t.name)),
            )
            .child(
                mono_tabular(metric)
                    .truncate()
                    .text_size(px(11.))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(rgb(color)),
            )
    });

    let mut launch_pads: Vec<Div> = proj
        .launch_apps
        .iter()
        .take(4)
        .map(|app| {
            let ctrl_l = ctrl.clone();
            let aid = app.agent_id.clone();
            let paths = app.install_paths.clone();
            let locked = !connected || !proj.hero.can_launch || app.quarantined || app.ag_proxy_blocked;
            let can_click = connected && !busy && app.installed;
            let pill_txt = if locked { p.badge_fail.text } else { p.text_primary };
            let sub_txt = if !app.installed {
                "未安装"
            } else if app.ag_proxy_blocked {
                "注入缺失"
            } else if locked {
                "门禁拦截中"
            } else {
                "防直连通道就绪"
            };
            let hover_bg = p.sidebar_hover_bg;

            let mut pad = div()
                .id(gpui::ElementId::Name(format!("hud-launch-{}", app.agent_id).into()))
                .flex()
                .flex_col()
                .justify_between()
                .flex_1()
                .flex_basis(px(0.))
                .min_w(px(0.))
                .px(px(10.))
                .py(px(9.))
                .gap(px(6.))
                .rounded(px(11.))
                .bg(rgb(p.card_bg))
                .border_1()
                .border_color(if locked && tripped {
                    rgba(p.hero_tripped.border)
                } else {
                    rgb(p.card_border)
                })
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap(px(5.))
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap(px(6.5))
                                .min_w(px(0.))
                                .flex_1()
                                .child(brand_icon(&app.agent_id, 21.0, 5.5, p.is_dark))
                                .child(
                                    div()
                                        .truncate()
                                        .text_size(px(11.5))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(p.text_primary))
                                        .child(hud_short_app(&app.agent_id, &app.label)),
                                ),
                        )
                        .child(
                            div()
                                .flex()
                                .flex_shrink_0()
                                .items_center()
                                .gap(px(3.))
                                .px(px(6.5))
                                .py(px(2.))
                                .rounded(px(999.))
                                .bg(if locked {
                                    rgba(p.badge_fail.bg)
                                } else {
                                    rgb(p.inset_bg)
                                })
                                .border_1()
                                .border_color(rgb(p.card_border))
                                .text_size(px(10.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(pill_txt))
                                .child(ui_icon(
                                    if locked {
                                        "icons/ui/lock.svg"
                                    } else {
                                        "icons/ui/play.svg"
                                    },
                                    9.0,
                                    pill_txt,
                                ))
                                .child(if locked { "锁定" } else { "启动" }),
                        ),
                )
                .child(
                    div()
                        .truncate()
                        .text_size(px(10.5))
                        .text_color(rgb(if locked { p.badge_fail.text } else { p.text_muted }))
                        .child(sub_txt),
                );

            if can_click {
                pad = pad
                    .cursor_pointer()
                    .hover(move |s| s.bg(rgb(hover_bg)))
                    .on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |_, _, _, cx| {
                            ctrl_l.update(cx, |c, cx| {
                                c.launch_app_with_gate(aid.clone(), paths.clone(), cx);
                            });
                        }),
                    );
            }
            div().flex_1().flex_basis(px(0.)).min_w(px(0.)).child(pad)
        })
        .collect();

    let pad_row1 = div()
        .flex()
        .w_full()
        .gap(px(7.))
        .children(launch_pads.drain(0..launch_pads.len().min(2)));
    let pad_row2 = div().flex().w_full().gap(px(7.)).children(launch_pads);

    let hover_close = p.sidebar_hover_bg;

    div()
        .flex()
        .flex_col()
        .justify_between()
        .size_full()
        .p(px(15.))
        .gap(px(10.))
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(10.))
                // Draggable Header
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap(px(8.))
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap(px(8.))
                                .child(
                                    div()
                                        .w(px(8.))
                                        .h(px(8.))
                                        .rounded(px(999.))
                                        .bg(rgb(dot_rgb)),
                                )
                                .child(
                                    div()
                                        .text_size(px(14.5))
                                        .font_weight(FontWeight::BOLD)
                                        .text_color(rgb(p.text_primary))
                                        .child(title_text),
                                ),
                        )
                        .child(div().flex_1().h(px(24.)).window_control_area(WindowControlArea::Drag))
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap(px(7.))
                                .child(
                                    mono_tabular(right_metric)
                                        .text_size(px(11.5))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(dot_rgb)),
                                )
                                .child(
                                    div()
                                        .id("hud-close-btn")
                                        .flex()
                                        .items_center()
                                        .justify_center()
                                        .w(px(22.))
                                        .h(px(22.))
                                        .rounded(px(999.))
                                        .bg(rgb(p.card_bg))
                                        .border_1()
                                        .border_color(rgb(p.card_border))
                                        .cursor_pointer()
                                        .hover(move |s| s.bg(rgb(hover_close)))
                                        .child(ui_icon("icons/ui/close.svg", 11.0, p.text_secondary))
                                        .on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, window, cx| {
                                                ctrl_close.update(cx, |c, _| c.hud_window = None);
                                                window.remove_window();
                                            }),
                                        ),
                                ),
                        ),
                )
                // IP + Proxy Port row
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .child(
                            mono_tabular(primary_ip)
                                .text_size(px(11.5))
                                .text_color(rgb(p.text_secondary)),
                        )
                        .child(
                            mono_tabular(format!("本地代理 :{proxy_port}"))
                                .text_size(px(11.))
                                .text_color(rgb(p.text_muted)),
                        ),
                )
                // Optional inline toast or warning (wraps cleanly without mid-sentence clipping)
                .when_some(toast.cloned(), |col, (msg, ok)| {
                    let b = if ok { p.badge_pass } else { p.badge_fail };
                    col.child(
                        div()
                            .px(px(9.))
                            .py(px(5.5))
                            .rounded(px(8.))
                            .bg(rgba(b.bg))
                            .text_size(px(11.))
                            .line_height(px(15.))
                            .text_color(rgb(b.text))
                            .child(msg),
                    )
                })
                .when_some(proj.ag_proxy_warning.clone(), |col, warn| {
                    col.child(
                        div()
                            .px(px(9.))
                            .py(px(5.5))
                            .rounded(px(8.))
                            .bg(rgba(p.badge_fail.bg))
                            .text_size(px(10.5))
                            .line_height(px(14.5))
                            .text_color(rgb(p.badge_fail.text))
                            .child(warn),
                    )
                })
                // 3-target compact strip
                .child(div().flex().w_full().gap(px(6.)).children(mini_targets))
                // 2x2 Safe Launch Deck
                .child(div().flex().flex_col().gap(px(7.)).child(pad_row1).child(pad_row2))
                // Compact read-only health strip in normal state so HUD feels balanced without blank void
                .when(toast.is_none() && proj.ag_proxy_warning.is_none(), |col| {
                    col.child(
                        inset_box(p)
                            .flex_row()
                            .items_center()
                            .justify_between()
                            .px(px(10.))
                            .py(px(6.5))
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap(px(6.))
                                    .child(
                                        div()
                                            .w(px(5.5))
                                            .h(px(5.5))
                                            .rounded(px(999.))
                                            .bg(rgb(dot_rgb)),
                                    )
                                    .child(
                                        div()
                                            .text_size(px(10.5))
                                            .text_color(rgb(p.text_secondary))
                                            .child("只读守护中 · 不改动你的代理策略"),
                                    ),
                            )
                            .child(
                                mono_tabular(format!("核验于 {}", proj.hero.checked_age_text))
                                    .text_size(px(10.))
                                    .text_color(rgb(p.text_muted)),
                            ),
                    )
                }),
        )
        // Footer
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .pt(px(9.))
                .border_t_1()
                .border_color(rgb(p.card_border))
                .gap(px(7.))
                .child(
                    action_button(
                        "hud-kill-all",
                        "一键全清",
                        ButtonKind::Secondary,
                        can_act,
                        p,
                    )
                    .h(px(28.))
                    .px(px(10.))
                    .text_size(px(11.))
                    .text_color(rgb(if can_act {
                        p.badge_fail.text
                    } else {
                        p.text_muted
                    }))
                    .when(can_act, |b| {
                        b.on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |_, _, _, cx| {
                                ctrl_kill_all.update(cx, |c, cx| {
                                    c.send_request(
                                        PipeRequest::ForceKillAgent {
                                            agent_id: None,
                                            include_cli: true,
                                        },
                                        Some("HUD 已全清受管进程"),
                                        cx,
                                    );
                                });
                            }),
                        )
                    }),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(6.))
                        .child(
                            action_button(
                                "hud-recheck-or-recover",
                                if !connected {
                                    "重连守护"
                                } else if tripped {
                                    "复查解封"
                                } else {
                                    "立即核验"
                                },
                                ButtonKind::Secondary,
                                !busy,
                                p,
                            )
                            .h(px(28.))
                            .px(px(10.))
                            .text_size(px(11.5))
                            .when(!busy, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_primary.update(cx, |c, cx| {
                                            if !connected {
                                                c.send_request(
                                                    PipeRequest::GetSnapshot,
                                                    Some("已重连后台守护服务"),
                                                    cx,
                                                );
                                            } else if tripped {
                                                c.send_request(
                                                    PipeRequest::RecoverSafeFlowA,
                                                    Some("复查达标，已恢复放行"),
                                                    cx,
                                                );
                                            } else {
                                                c.send_request(
                                                    PipeRequest::RecheckNow { target_id: None },
                                                    Some("已完成全链路出口核验"),
                                                    cx,
                                                );
                                            }
                                        });
                                    }),
                                )
                            }),
                        )
                        .child(
                            action_button("hud-open-console", "主控台", ButtonKind::Primary, true, p)
                                .h(px(28.))
                                .px(px(11.))
                                .text_size(px(11.5))
                                .on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, window, cx| {
                                        open_console_window(ctrl_console.clone(), cx);
                                        ctrl_console.update(cx, |c, _| c.hud_window = None);
                                        window.remove_window();
                                    }),
                                ),
                        ),
                ),
        )
}
