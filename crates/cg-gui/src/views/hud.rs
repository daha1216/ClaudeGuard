//! Mode A — Compact Frost Ceramic v2 Tray Quick HUD (`398 × 432` logical px, pixel-locked).
//!
//! Zero layout shift: toast banners render as a floating overlay in `HudWindowView`,
//! while `ag_proxy_warning` shares the fixed bottom strip slot (clickable to jump to repair).

use crate::app::{AppController, EnvSubTab, HudWindowView, open_console_window};
use crate::assets::{brand_icon, ui_icon};
use crate::protocol::{Lifecycle, PipeRequest};
use crate::state::{HudProjection, NavSection};
use crate::theme::{BadgeTone, HeroTone, ThemePalette};
use crate::widgets::controls::{
    ButtonKind, action_button, inset_box, mono_tabular, pulse_status_dot, status_dot,
};
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
    busy: bool,
    p: &'static ThemePalette,
    cx: &mut Context<HudWindowView>,
) -> Div {
    let connected = proj.connected;
    let can_act = connected && !busy;
    let ctrl_r = ctrl.read(cx);
    let is_demo = ctrl_r.client.is_demo();
    let start_svc_busy = ctrl_r.is_scope_busy(&crate::app::ActionScope::StartService);
    let snap = ctrl_r.snapshot.clone();
    let lifecycle = snap
        .as_deref()
        .map(|s| s.lifecycle)
        .unwrap_or(Lifecycle::Unconfigured);
    let really_tripped = snap.as_deref().is_some_and(|s| s.is_tripped());
    let monitor_only = snap.as_deref().is_some_and(|s| s.config.monitor_only);
    let pre_trip_fail = !really_tripped && proj.hero.fail_count > 0;
    let proxy_port = snap.as_deref().map(|s| s.config.proxy_port).unwrap_or(7890);
    let total_running: usize = snap
        .as_deref()
        .map(|s| s.agents.iter().map(|a| a.running_count).sum())
        .unwrap_or(0);
    let kill_all_armed = ctrl_r.is_confirm_armed("hud-kill-all");
    let kill_all_enabled = can_act && (total_running > 0 || proj.total_orphans > 0);

    let dot_rgb = match proj.hero.tone {
        HeroTone::Healthy => p.badge_pass.dot,
        HeroTone::Tripped => p.badge_fail.dot,
        HeroTone::DisarmedOrPaused => p.badge_warn.dot,
    };
    let right_metric_color = match proj.hero.tone {
        HeroTone::Healthy => p.text_secondary,
        HeroTone::Tripped => p.badge_fail.text,
        HeroTone::DisarmedOrPaused => p.badge_warn.text,
    };

    let primary_tile = proj
        .target_tiles
        .iter()
        .find(|t| t.id == "claude")
        .or_else(|| proj.target_tiles.first());
    let primary_ip = primary_tile
        .map(|t| t.ip_display.clone())
        .unwrap_or_else(|| "等待探测".into());
    let right_metric = primary_tile
        .map(|t| format!("{} · {}", t.cc_badge, t.latency_label))
        .unwrap_or_else(|| proj.hero.access_badge.clone());

    let title_text: String = if !connected {
        "服务未连接".into()
    } else if really_tripped {
        "出口已熔断".into()
    } else if lifecycle == Lifecycle::Unconfigured {
        "等待首启配置".into()
    } else if lifecycle == Lifecycle::Disarmed {
        "已撤防放行".into()
    } else if proj.hero.is_paused {
        "守护已暂停".into()
    } else if pre_trip_fail && monitor_only {
        "仅监测 · 异常".into()
    } else if pre_trip_fail {
        "出口异常".into()
    } else if proj.hero.tone == HeroTone::Healthy {
        "出口合规".into()
    } else {
        "正在探测出口".into()
    };

    let ctrl_close = ctrl.clone();
    let ctrl_kill_all = ctrl.clone();
    let ctrl_start_svc = ctrl.clone();
    let ctrl_primary = ctrl.clone();
    let ctrl_console = ctrl.clone();
    let ctrl_ag_jump = ctrl.clone();

    let mini_targets = proj.target_tiles.iter().take(3).map(|t| {
        let is_fail = t.badge_tone == BadgeTone::Fail;
        let is_warn = t.badge_tone == BadgeTone::Warn;
        let is_pass = t.badge_tone == BadgeTone::Pass;
        let color = if is_fail {
            p.badge_fail.text
        } else if is_warn {
            p.badge_warn.text
        } else if is_pass {
            p.text_primary
        } else {
            p.text_muted
        };
        let metric = if is_fail {
            format!("{} 越界", t.cc_badge)
        } else if is_warn {
            if t.cc_badge == "--" || t.cc_badge == "TLS" {
                t.state_label.clone()
            } else {
                format!("{} 待检", t.cc_badge)
            }
        } else if !is_pass {
            t.state_label.clone()
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
                div()
                    .flex()
                    .items_center()
                    .min_w(px(0.))
                    .gap(px(4.5))
                    .when(is_pass, |row| row.child(status_dot(p.badge_pass.dot, 5.0)))
                    .child(
                        mono_tabular(metric)
                            .truncate()
                            .min_w(px(0.))
                            .text_size(px(11.))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(rgb(color)),
                    ),
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
            let hard_locked = !connected
                || really_tripped
                || pre_trip_fail
                || app.quarantined
                || app.ag_proxy_blocked;
            let standby_locked = !hard_locked && !proj.hero.can_launch;
            let can_click = connected && !busy && app.installed;

            let (pill_bg, pill_border, pill_icon, pill_icon_color, pill_txt, pill_label) =
                if hard_locked {
                    (
                        rgba(p.badge_fail.bg),
                        rgba(p.hero_tripped.border),
                        "icons/ui/lock.svg",
                        p.badge_fail.text,
                        p.badge_fail.text,
                        "锁定",
                    )
                } else if standby_locked {
                    let label = if proj.hero.is_paused {
                        "已暂停"
                    } else if lifecycle == Lifecycle::Disarmed {
                        "待布防"
                    } else {
                        "待探测"
                    };
                    (
                        rgb(p.inset_bg),
                        rgb(p.card_border),
                        "icons/ui/clock.svg",
                        p.text_muted,
                        p.text_muted,
                        label,
                    )
                } else {
                    (
                        rgb(p.inset_bg),
                        rgb(p.secondary_btn_border),
                        "icons/ui/play.svg",
                        p.accent_soft_text,
                        p.text_primary,
                        "启动",
                    )
                };

            let sub_txt = if hard_locked {
                if app.ag_proxy_blocked {
                    "注入失效"
                } else if !connected {
                    "服务离线"
                } else if !app.installed {
                    "未安装"
                } else if really_tripped || app.quarantined {
                    "已熔断隔离"
                } else {
                    "出口异常锁定"
                }
            } else if standby_locked {
                if !app.installed {
                    "未安装"
                } else if proj.hero.is_paused {
                    "守护已暂停"
                } else if lifecycle == Lifecycle::Disarmed {
                    "已撤防放行"
                } else {
                    "等待首轮探测"
                }
            } else if !app.installed {
                "未安装"
            } else {
                "安全通道就绪"
            };
            let sub_color = if hard_locked {
                p.badge_fail.text
            } else {
                p.text_muted
            };
            let hover_bg = p.sidebar_hover_bg;

            let mut pad = div()
                .id(gpui::ElementId::Name(
                    format!("hud-launch-{}", app.agent_id).into(),
                ))
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
                .border_color(if hard_locked && really_tripped {
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
                                .child(brand_icon(&app.agent_id, 22.0, 6.0, p.is_dark))
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
                                .bg(pill_bg)
                                .border_1()
                                .border_color(pill_border)
                                .text_size(px(10.))
                                .font_weight(FontWeight::MEDIUM)
                                .text_color(rgb(pill_txt))
                                .child(ui_icon(pill_icon, 9.0, pill_icon_color))
                                .child(pill_label),
                        ),
                )
                .child(
                    div()
                        .truncate()
                        .text_size(px(10.5))
                        .text_color(rgb(sub_color))
                        .child(sub_txt),
                );

            if can_click {
                pad = pad
                    .cursor_pointer()
                    .hover(move |s| s.bg(rgb(hover_bg)).border_color(rgb(p.line_strong)))
                    .active(|s| s.opacity(0.90))
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

    // Single fixed-height bottom health/warning strip: keeps 3-target strip & 2x2 deck pixel-locked!
    let bottom_strip = if let Some(warn) = proj.ag_proxy_warning.clone() {
        inset_box(p)
            .id("hud-ag-warning-strip")
            .cursor_pointer()
            .flex_row()
            .items_center()
            .justify_between()
            .gap(px(8.))
            .px(px(10.))
            .py(px(6.5))
            .bg(rgba(p.badge_fail.bg))
            .border_color(rgba(p.hero_tripped.border))
            .hover(|s| s.opacity(0.90))
            .child(
                div()
                    .truncate()
                    .flex_1()
                    .min_w(px(0.))
                    .text_size(px(10.5))
                    .font_weight(FontWeight::MEDIUM)
                    .text_color(rgb(p.badge_fail.text))
                    .child(warn),
            )
            .child(
                div()
                    .flex_shrink_0()
                    .text_size(px(10.5))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(rgb(p.badge_fail.text))
                    .child("去修复 →"),
            )
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(move |_, _, window, cx| {
                    ctrl_ag_jump.update(cx, |c, cx| {
                        c.env_tab = EnvSubTab::Antigravity;
                        c.set_nav(NavSection::Environment, cx);
                        c.hud_window = None;
                    });
                    open_console_window(ctrl_ag_jump.clone(), cx);
                    window.remove_window();
                }),
            )
            .into_any_element()
    } else {
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
                    .child(status_dot(dot_rgb, 5.5))
                    .child(
                        div()
                            .text_size(px(10.5))
                            .text_color(rgb(p.text_secondary))
                            .child("只读探测 · 不改代理策略"),
                    ),
            )
            .child(
                mono_tabular(format!("探测 · {}", proj.hero.checked_age_text))
                    .text_size(px(10.))
                    .text_color(rgb(p.text_muted)),
            )
            .into_any_element()
    };

    let primary_footer_label = if !connected {
        "重连服务"
    } else if lifecycle == Lifecycle::Unconfigured {
        "去配置"
    } else if lifecycle == Lifecycle::Disarmed {
        "重新布防"
    } else if proj.hero.is_paused {
        "恢复守护"
    } else if really_tripped {
        "复查解封"
    } else {
        "立即探测"
    };

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
                                .child(pulse_status_dot(
                                    "hud-status-pulse",
                                    dot_rgb,
                                    8.0,
                                    connected
                                        && (proj.hero.tone == HeroTone::Healthy || really_tripped),
                                ))
                                .child(
                                    div()
                                        .text_size(px(14.5))
                                        .font_weight(FontWeight::BOLD)
                                        .text_color(rgb(p.text_primary))
                                        .child(title_text),
                                ),
                        )
                        .child(
                            div()
                                .flex_1()
                                .h(px(24.))
                                .window_control_area(WindowControlArea::Drag),
                        )
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap(px(7.))
                                .child(
                                    mono_tabular(right_metric)
                                        .text_size(px(11.5))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(right_metric_color)),
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
                                        .active(|s| s.opacity(0.85))
                                        .child(ui_icon(
                                            "icons/ui/close.svg",
                                            11.0,
                                            p.text_secondary,
                                        ))
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
                // 3-target compact strip
                .child(div().flex().w_full().gap(px(6.)).children(mini_targets))
                // 2x2 Safe Launch Deck
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .gap(px(7.))
                        .child(pad_row1)
                        .child(pad_row2),
                )
                // Fixed-height health / clickable warning strip
                .child(bottom_strip),
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
                        if kill_all_armed {
                            "确认全清？"
                        } else {
                            "一键全清"
                        },
                        if kill_all_armed {
                            ButtonKind::DangerSoft
                        } else {
                            ButtonKind::Ghost
                        },
                        kill_all_enabled,
                        p,
                    )
                    .h(px(28.))
                    .px(px(10.))
                    .text_size(px(11.))
                    .when(kill_all_enabled, |b| {
                        b.on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |_, _, _, cx| {
                                ctrl_kill_all.update(cx, |c, cx| {
                                    if c.arm_or_consume_confirm("hud-kill-all", cx) {
                                        c.send_request(
                                            PipeRequest::ForceKillAgent {
                                                agent_id: None,
                                                include_cli: true,
                                            },
                                            Some("已清理全部受管进程"),
                                            cx,
                                        );
                                    }
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
                        .when(!connected && !is_demo, |row| {
                            row.child(
                                action_button(
                                    "hud-start-service",
                                    if start_svc_busy {
                                        "启动中…"
                                    } else {
                                        "启动守护服务"
                                    },
                                    ButtonKind::Primary,
                                    !busy,
                                    p,
                                )
                                .h(px(28.))
                                .px(px(9.))
                                .text_size(px(11.))
                                .when(!busy, |b| {
                                    b.on_mouse_up(
                                        MouseButton::Left,
                                        cx.listener(move |_, _, _, cx| {
                                            ctrl_start_svc
                                                .update(cx, |c, cx| c.start_daemon_service(cx));
                                        }),
                                    )
                                }),
                            )
                        })
                        .child(
                            action_button(
                                "hud-recheck-or-recover",
                                primary_footer_label,
                                ButtonKind::Secondary,
                                !busy,
                                p,
                            )
                            .h(px(28.))
                            .px(px(10.))
                            .text_size(px(11.5))
                            .when(!busy, |b| {
                                let is_paused = proj.hero.is_paused;
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, window, cx| {
                                        if connected && lifecycle == Lifecycle::Unconfigured {
                                            ctrl_primary.update(cx, |c, cx| {
                                                c.hud_window = None;
                                                c.open_onboarding_modal(cx);
                                            });
                                            open_console_window(ctrl_primary.clone(), cx);
                                            window.remove_window();
                                            return;
                                        }
                                        ctrl_primary.update(cx, |c, cx| {
                                            if !connected {
                                                c.send_request(
                                                    PipeRequest::GetSnapshot,
                                                    Some("已重连守护服务"),
                                                    cx,
                                                );
                                            } else if lifecycle == Lifecycle::Disarmed {
                                                c.send_request(
                                                    PipeRequest::Rearm,
                                                    Some("已重新布防"),
                                                    cx,
                                                );
                                            } else if is_paused {
                                                c.toggle_pause_30m(cx);
                                            } else if really_tripped {
                                                c.send_request(
                                                    PipeRequest::RecoverSafeFlowA,
                                                    Some("复查通过，已解封放行"),
                                                    cx,
                                                );
                                            } else {
                                                c.send_request(
                                                    PipeRequest::RecheckNow { target_id: None },
                                                    Some("出口探测已完成"),
                                                    cx,
                                                );
                                            }
                                        });
                                    }),
                                )
                            }),
                        )
                        .child(
                            action_button(
                                "hud-open-console",
                                "主控台",
                                if !connected && !is_demo {
                                    ButtonKind::Secondary
                                } else {
                                    ButtonKind::Primary
                                },
                                true,
                                p,
                            )
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
