//! Mode B — Frost Ceramic `守护总览` view.
//!
//! Layout:
//! - Upper row: Hero Status Card + Dedicated 2×2 `安全启动台`
//! - Lower 3-column balanced row: `受管进程治理` | Read-Only `出口实况探测` (no Mihomo) | `四维防漏` + 24h tape

use crate::app::{AppController, ConsoleWindowView, EnvSubTab};
use crate::assets::{brand_icon, ui_icon};
use crate::protocol::{Lifecycle, PipeRequest, TimelineStatus};
use crate::state::{ConsoleProjection, NavSection};
use crate::theme::{BadgeTone, HeroTone, ThemePalette};
use crate::widgets::controls::{
    ButtonKind, action_button, bento_card, icon_action_button, inset_box, mono_tabular,
    toggle_switch,
};
use gpui::{Context, Div, Entity, FontWeight, MouseButton, div, prelude::*, px, relative, rgb, rgba};

fn cleanup_toast_for_agent(agent_id: &str) -> &'static str {
    match agent_id {
        "claude" => "已安静清理 Claude 桌面端及孤儿残留",
        "claude-code" => "已安静清理 Claude Code CLI 会话及孤儿残留",
        "chatgpt" => "已安静清理 ChatGPT / Codex 桌面端及孤儿残留",
        "codex" => "已安静清理 Codex CLI 会话及孤儿残留",
        "antigravity" => "已安静清理 Antigravity IDE 及孤儿残留",
        _ => "已清理该受管应用进程",
    }
}

fn short_launch_name(agent_id: &str, fallback: &str) -> String {
    match agent_id {
        "claude" => "Claude".into(),
        "claude-code" => "Code CLI".into(),
        "chatgpt" => "ChatGPT".into(),
        "antigravity" => "Antigravity".into(),
        _ => fallback.to_string(),
    }
}

fn short_target_name(id: &str, fallback: &str) -> String {
    match id {
        "claude" => "Claude 出口".into(),
        "codex" | "chatgpt" => "Codex / OpenAI".into(),
        "antigravity" => "Antigravity 后端".into(),
        _ => fallback.to_string(),
    }
}

pub fn render_overview(
    ctrl: Entity<AppController>,
    proj: &ConsoleProjection,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> Div {
    let ctrl_r = ctrl.read(cx);
    let snap = ctrl_r.snapshot.clone();
    let busy = ctrl_r.busy_action;
    let connected = proj.connected;
    let can_act = connected && !busy;
    let cfg = snap.as_ref().map(|s| s.config.clone()).unwrap_or_default();
    let lifecycle = snap
        .as_ref()
        .map(|s| s.lifecycle)
        .unwrap_or(Lifecycle::Unconfigured);
    let tripped = proj.hero.tone == HeroTone::Tripped;
    let ag_proxy = snap
        .as_ref()
        .map(|s| s.antigravity_proxy.clone())
        .unwrap_or_default();
    let ag_degraded = ag_proxy.installed && !ag_proxy.is_ready_for_launch();
    let shield_status = snap
        .as_ref()
        .map(|s| s.leak_shield.clone())
        .unwrap_or_default();
    let leak_watch = snap
        .as_ref()
        .map(|s| s.leak.clone())
        .unwrap_or_default();

    // -------------------------------------------------------------------------
    // Upper Row Left: Hero Status Card
    // -------------------------------------------------------------------------
    let hero_surf = p.hero(proj.hero.tone);
    let total_targets = (proj.hero.pass_count + proj.hero.fail_count + proj.hero.unverified_count).max(1);
    let status_dot_color = match proj.hero.tone {
        HeroTone::Healthy => p.badge_pass.dot,
        HeroTone::Tripped => p.badge_fail.dot,
        HeroTone::DisarmedOrPaused => p.badge_warn.dot,
    };
    let status_kicker = match proj.hero.tone {
        HeroTone::Healthy => format!("实时守护正常 · {}/{} 出口合规", proj.hero.pass_count, total_targets),
        HeroTone::Tripped => format!("熔断保护已触发 · {} 项越界", proj.hero.fail_count.max(1)),
        HeroTone::DisarmedOrPaused => proj.hero.pill_label.clone(),
    };
    let hero_title = if !connected {
        "守护服务未连接"
    } else if lifecycle == Lifecycle::Unconfigured {
        "等待完成首启配置"
    } else if lifecycle == Lifecycle::Disarmed {
        "保护已撤防放行"
    } else if tripped {
        "已隔离受管 AI 出站"
    } else if proj.hero.is_paused {
        "已暂停自动拦截"
    } else {
        "出口纯净合规"
    };

    let tripped_lines: Option<(String, String)> = proj.tripped_card.as_ref().map(|diag| {
        (
            format!("期望：{}", diag.expected_summary),
            format!("实测：{}", diag.observed_summary),
        )
    });
    let hero_meta = if let Some(primary) = proj
        .target_cards
        .iter()
        .find(|t| t.id == "claude")
        .or_else(|| proj.target_cards.first())
    {
        format!(
            "{} · {} · {}",
            primary.location_display, primary.ip_display, primary.latency_label
        )
    } else {
        proj.hero.subtitle.clone()
    };

    let hero_actions = if !connected {
        let ctrl_conn = ctrl.clone();
        div().flex().items_center().gap(px(8.)).child(
            icon_action_button(
                "ov-reconnect",
                "icons/ui/refresh.svg",
                if busy { "重连中…" } else { "重新连接守护" },
                ButtonKind::Primary,
                !busy,
                p,
            )
            .when(!busy, |b| {
                b.on_mouse_up(
                    MouseButton::Left,
                    cx.listener(move |_, _, _, cx| {
                        ctrl_conn.update(cx, |c, cx| {
                            c.send_request(
                                PipeRequest::GetSnapshot,
                                Some("已重新连接后台守护服务"),
                                cx,
                            );
                        });
                    }),
                )
            }),
        )
    } else if lifecycle == Lifecycle::Unconfigured {
        let ctrl_onb = ctrl.clone();
        div().flex().items_center().gap(px(8.)).child(
            icon_action_button(
                "ov-open-onb",
                "icons/ui/shield.svg",
                "完成首启向导并布防",
                ButtonKind::Primary,
                true,
                p,
            )
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(move |_, _, _, cx| {
                    ctrl_onb.update(cx, |c, cx| c.open_onboarding_modal(cx));
                }),
            ),
        )
    } else if lifecycle == Lifecycle::Disarmed {
        let ctrl_rearm = ctrl.clone();
        div().flex().items_center().gap(px(8.)).child(
            icon_action_button(
                "ov-rearm",
                "icons/ui/shield.svg",
                "重新布防",
                ButtonKind::Primary,
                can_act,
                p,
            )
            .when(can_act, |b| {
                b.on_mouse_up(
                    MouseButton::Left,
                    cx.listener(move |_, _, _, cx| {
                        ctrl_rearm.update(cx, |c, cx| {
                            c.send_request(
                                PipeRequest::Rearm,
                                Some("已重新布防并恢复出口守护"),
                                cx,
                            );
                        });
                    }),
                )
            }),
        )
    } else if tripped {
        let ctrl_a = ctrl.clone();
        let ctrl_b = ctrl.clone();
        div()
            .flex()
            .flex_wrap()
            .items_center()
            .gap(px(8.))
            .child(
                icon_action_button(
                    "ov-trip-flow-a",
                    "icons/ui/refresh.svg",
                    "复查并解封",
                    ButtonKind::Danger,
                    can_act,
                    p,
                )
                .when(can_act, |b| {
                    b.on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |_, _, _, cx| {
                            ctrl_a.update(cx, |c, cx| {
                                c.send_request(
                                    PipeRequest::RecoverSafeFlowA,
                                    Some("全链路复查通过，已安全解封放行"),
                                    cx,
                                );
                            });
                        }),
                    )
                }),
            )
            .child(
                action_button(
                    "ov-trip-flow-b",
                    "暂不用 AI · 解封",
                    ButtonKind::Secondary,
                    can_act,
                    p,
                )
                .when(can_act, |b| {
                    b.on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |_, _, _, cx| {
                            ctrl_b.update(cx, |c, cx| {
                                c.send_request(
                                    PipeRequest::DisarmAndRestoreFlowB {
                                        reason: Some("用户从总览手动停止并解封".into()),
                                    },
                                    Some("已撤防并解除隔离规则"),
                                    cx,
                                );
                            });
                        }),
                    )
                }),
            )
    } else {
        let ctrl_chk = ctrl.clone();
        let ctrl_pause = ctrl.clone();
        div()
            .flex()
            .flex_wrap()
            .items_center()
            .gap(px(8.))
            .child(
                icon_action_button(
                    "ov-recheck-now",
                    "icons/ui/refresh.svg",
                    "立即核验",
                    ButtonKind::Primary,
                    can_act,
                    p,
                )
                .when(can_act, |b| {
                    b.on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |_, _, _, cx| {
                            ctrl_chk.update(cx, |c, cx| {
                                c.send_request(
                                    PipeRequest::RecheckNow { target_id: None },
                                    Some("已完成新一轮全链路出口核验"),
                                    cx,
                                );
                            });
                        }),
                    )
                }),
            )
            .child(
                action_button(
                    "ov-pause-30m",
                    if proj.hero.is_paused {
                        "恢复守护"
                    } else {
                        "暂停 30m"
                    },
                    ButtonKind::Secondary,
                    can_act,
                    p,
                )
                .when(can_act, |b| {
                    b.on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |_, _, _, cx| {
                            ctrl_pause.update(cx, |c, cx| c.toggle_pause_30m(cx));
                        }),
                    )
                }),
            )
    };

    let hero_card = bento_card(p)
        .w(relative(0.53))
        .flex_shrink_0()
        .bg(rgba(hero_surf.bg))
        .border_color(rgba(hero_surf.border))
        .px(px(19.))
        .py(px(17.))
        .justify_between()
        .gap(px(14.))
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(6.))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(7.))
                        .child(
                            div()
                                .w(px(7.5))
                                .h(px(7.5))
                                .rounded(px(999.))
                                .bg(rgb(status_dot_color)),
                        )
                        .child(
                            div()
                                .text_size(px(12.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(status_dot_color))
                                .child(status_kicker),
                        ),
                )
                .child(
                    div()
                        .text_size(px(22.))
                        .font_weight(FontWeight::BOLD)
                        .line_height(px(27.))
                        .text_color(rgb(hero_surf.title))
                        .child(hero_title),
                )
                .child(if let Some((exp_line, obs_line)) = tripped_lines {
                    div()
                        .flex()
                        .flex_col()
                        .gap(px(2.5))
                        .child(
                            mono_tabular(exp_line)
                                .text_size(px(11.))
                                .line_height(px(15.))
                                .text_color(rgb(hero_surf.subtitle)),
                        )
                        .child(
                            mono_tabular(obs_line)
                                .text_size(px(11.5))
                                .font_weight(FontWeight::SEMIBOLD)
                                .line_height(px(15.5))
                                .text_color(rgb(p.badge_fail.text)),
                        )
                        .into_any_element()
                } else {
                    mono_tabular(hero_meta)
                        .truncate()
                        .text_size(px(11.5))
                        .text_color(rgb(hero_surf.subtitle))
                        .into_any_element()
                }),
        )
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .gap(px(8.))
                .child(hero_actions)
                .child(
                    div()
                        .flex()
                        .items_center()
                        .flex_shrink_0()
                        .gap(px(4.))
                        .text_size(px(11.))
                        .text_color(rgb(p.text_muted))
                        .child("代理")
                        .child(mono_tabular(format!(":{}", cfg.proxy_port))),
                ),
        );

    // -------------------------------------------------------------------------
    // Upper Row Right: Dedicated 2x2 Safe Launch Deck
    // -------------------------------------------------------------------------
    let deck_ok = connected && proj.hero.can_launch;
    let deck_color = if tripped {
        p.badge_fail.text
    } else if deck_ok {
        p.badge_pass.text
    } else {
        p.badge_warn.text
    };
    let deck_badge = if !connected {
        "未连接 · 已锁定"
    } else if tripped {
        "熔断已锁定"
    } else if deck_ok {
        "门禁放行 · 防直连"
    } else {
        "待核验 / 已暂停"
    };

    let mut pad_cards: Vec<Div> = proj
        .launch_apps
        .iter()
        .take(4)
        .map(|app| {
            let ctrl_l = ctrl.clone();
            let aid = app.agent_id.clone();
            let paths = app.install_paths.clone();
            let locked = !connected || !proj.hero.can_launch || app.quarantined || app.ag_proxy_blocked;
            let is_warn = !locked && app.orphan_count > 0;
            let dot_rgb = if locked {
                p.badge_fail.dot
            } else if is_warn {
                p.badge_warn.dot
            } else if !app.installed {
                p.text_muted
            } else {
                p.badge_pass.dot
            };
            let sub_text = if !app.installed {
                "未检测到安装".to_string()
            } else if app.ag_proxy_blocked {
                "注入缺失".to_string()
            } else if locked {
                "禁止启动".to_string()
            } else if app.agent_id == "antigravity" {
                "注入健康".to_string()
            } else if app.orphan_count > 0 {
                format!("{}运行 · {}孤儿", app.running_count, app.orphan_count)
            } else {
                format!("{}运行 · 合规", app.running_count)
            };
            let sub_color = if locked {
                p.badge_fail.text
            } else if is_warn {
                p.badge_warn.text
            } else {
                p.text_secondary
            };

            let pill_bg = if locked { p.badge_fail.bg } else { p.card_bg };
            let pill_txt = if locked { p.badge_fail.text } else { p.text_primary };
            let hover_bg = p.sidebar_hover_bg;
            let can_click = connected && !busy && app.installed;

            let mut card = div()
                .id(gpui::ElementId::Name(format!("ov-launch-{}", app.agent_id).into()))
                .flex()
                .flex_col()
                .justify_between()
                .flex_1()
                .flex_basis(px(0.))
                .min_w(px(0.))
                .p(px(10.))
                .gap(px(8.))
                .rounded(px(11.))
                .bg(rgb(p.inset_bg))
                .border_1()
                .border_color(if locked && tripped {
                    rgba(p.hero_tripped.border)
                } else {
                    rgb(p.inset_border)
                })
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap(px(6.))
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap(px(7.))
                                .min_w(px(0.))
                                .flex_1()
                                .child(brand_icon(&app.agent_id, 24.0, 6.5, p.is_dark))
                                .child(
                                    div()
                                        .truncate()
                                        .text_size(px(12.))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(p.text_primary))
                                        .child(short_launch_name(&app.agent_id, &app.label)),
                                ),
                        )
                        .child(
                            div()
                                .flex()
                                .flex_shrink_0()
                                .items_center()
                                .gap(px(3.))
                                .px(px(7.))
                                .py(px(2.5))
                                .rounded(px(999.))
                                .bg(if locked { rgba(pill_bg) } else { rgb(pill_bg) })
                                .border_1()
                                .border_color(rgb(p.card_border))
                                .text_size(px(10.5))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(pill_txt))
                                .child(ui_icon(
                                    if locked {
                                        "icons/ui/lock.svg"
                                    } else {
                                        "icons/ui/play.svg"
                                    },
                                    9.5,
                                    pill_txt,
                                ))
                                .child(if locked { "锁定" } else { "启动" }),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(5.))
                        .child(
                            div()
                                .w(px(5.5))
                                .h(px(5.5))
                                .rounded(px(999.))
                                .flex_shrink_0()
                                .bg(rgb(dot_rgb)),
                        )
                        .child(
                            mono_tabular(sub_text)
                                .truncate()
                                .text_size(px(10.5))
                                .font_weight(FontWeight::MEDIUM)
                                .text_color(rgb(sub_color)),
                        ),
                );

            if can_click {
                card = card
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
            div().flex_1().flex_basis(px(0.)).min_w(px(0.)).child(card)
        })
        .collect();

    let pads_row1 = div()
        .flex()
        .w_full()
        .gap(px(8.))
        .children(pad_cards.drain(0..pad_cards.len().min(2)));
    let pads_row2 = div().flex().w_full().gap(px(8.)).children(pad_cards);

    let launch_deck = bento_card(p)
        .flex_1()
        .min_w(px(0.))
        .px(px(16.))
        .py(px(14.))
        .gap(px(10.))
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
                        .gap(px(6.))
                        .child(ui_icon(
                            if tripped {
                                "icons/ui/shield_alert.svg"
                            } else {
                                "icons/ui/shield.svg"
                            },
                            14.0,
                            deck_color,
                        ))
                        .child(
                            div()
                                .text_size(px(13.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.text_primary))
                                .child("安全启动台"),
                        ),
                )
                .child(
                    div()
                        .text_size(px(11.))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(rgb(deck_color))
                        .child(deck_badge),
                ),
        )
        .child(pads_row1)
        .child(pads_row2);

    // -------------------------------------------------------------------------
    // Lower Row Col 1: Managed Processes
    // -------------------------------------------------------------------------
    let total_running: usize = proj.agent_statuses.iter().map(|a| a.running_count).sum();
    let total_orphans: usize = proj.agent_statuses.iter().map(|a| a.orphan_count).sum();
    let ctrl_kill_all = ctrl.clone();
    let ctrl_sweep = ctrl.clone();

    let proc_rows = proj.agent_statuses.iter().take(5).map(|a| {
        let can_kill = can_act && (a.running_count > 0 || a.orphan_count > 0);
        let aid = a.id.clone();
        let toast = cleanup_toast_for_agent(&a.id);
        let ctrl_k = ctrl.clone();
        let stat_txt = if a.orphan_count > 0 {
            format!("{} 运行 · {} 孤儿", a.running_count, a.orphan_count)
        } else {
            format!("{} 运行", a.running_count)
        };
        let stat_color = if a.orphan_count > 0 {
            p.badge_warn.text
        } else {
            p.text_muted
        };
        let hover_bg = p.sidebar_hover_bg;

        div()
            .flex()
            .items_center()
            .justify_between()
            .gap(px(6.))
            .py(px(5.5))
            .px(px(4.))
            .rounded(px(7.))
            .hover(move |s| s.bg(rgb(hover_bg)))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(7.))
                    .min_w(px(0.))
                    .flex_1()
                    .child(brand_icon(&a.id, 18.0, 5.0, p.is_dark))
                    .child(
                        div()
                            .truncate()
                            .text_size(px(12.))
                            .font_weight(FontWeight::MEDIUM)
                            .text_color(rgb(p.text_primary))
                            .child(a.name.clone()),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .flex_shrink_0()
                    .gap(px(6.))
                    .child(
                        mono_tabular(stat_txt)
                            .text_size(px(10.5))
                            .text_color(rgb(stat_color)),
                    )
                    .child(
                        action_button(
                            gpui::ElementId::Name(format!("ov-kill-{}", a.id).into()),
                            "清理",
                            ButtonKind::Secondary,
                            can_kill,
                            p,
                        )
                        .h(px(22.))
                        .px(px(7.))
                        .text_size(px(10.5))
                        .when(can_kill, |b| {
                            b.on_mouse_up(
                                MouseButton::Left,
                                cx.listener(move |_, _, _, cx| {
                                    ctrl_k.update(cx, |c, cx| {
                                        c.send_request(
                                            PipeRequest::ForceKillAgent {
                                                agent_id: Some(aid.clone()),
                                                include_cli: true,
                                            },
                                            Some(toast),
                                            cx,
                                        );
                                    });
                                }),
                            )
                        }),
                    ),
            )
    });

    let col_procs = bento_card(p)
        .w(relative(0.355))
        .flex_shrink_0()
        .px(px(15.))
        .py(px(14.))
        .justify_between()
        .gap(px(10.))
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(8.))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .child(
                            div()
                                .text_size(px(12.5))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.text_primary))
                                .child("受管进程治理"),
                        )
                        .child(
                            action_button(
                                "ov-kill-all",
                                "一键全清",
                                ButtonKind::Secondary,
                                can_act && (total_running > 0 || total_orphans > 0),
                                p,
                            )
                            .h(px(23.))
                            .px(px(8.))
                            .text_size(px(10.5))
                            .text_color(rgb(if can_act && (total_running > 0 || total_orphans > 0) {
                                p.badge_fail.text
                            } else {
                                p.text_muted
                            }))
                            .when(can_act && (total_running > 0 || total_orphans > 0), |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_kill_all.update(cx, |c, cx| {
                                            c.send_request(
                                                PipeRequest::ForceKillAgent {
                                                    agent_id: None,
                                                    include_cli: true,
                                                },
                                                Some("已安全清空全部受管 AI 进程与孤儿残留"),
                                                cx,
                                            );
                                        });
                                    }),
                                )
                            }),
                        ),
                )
                .child(div().flex().flex_col().gap(px(2.)).children(proc_rows)),
        )
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .pt(px(9.))
                .border_t_1()
                .border_color(rgb(p.card_border))
                .child(
                    mono_tabular(format!("{total_running} 运行 · {total_orphans} 孤儿"))
                        .text_size(px(11.))
                        .text_color(rgb(p.text_muted)),
                )
                .child(if total_orphans > 0 {
                    div()
                        .id("ov-sweep-orphans")
                        .cursor_pointer()
                        .text_size(px(11.))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(rgb(p.badge_warn.text))
                        .child("一键清孤儿")
                        .on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |_, _, _, cx| {
                                ctrl_sweep.update(cx, |c, cx| {
                                    c.send_request(
                                        PipeRequest::SweepOrphans,
                                        Some("已完成受管应用孤儿残留清扫"),
                                        cx,
                                    );
                                });
                            }),
                        )
                        .into_any_element()
                } else {
                    div()
                        .text_size(px(11.))
                        .text_color(rgb(p.text_muted))
                        .child("无孤儿残留")
                        .into_any_element()
                }),
        );

    // -------------------------------------------------------------------------
    // Lower Row Col 2: Read-Only Live Egress Telemetry (ZERO Mihomo)
    // -------------------------------------------------------------------------
    let ctrl_to_targets = ctrl.clone();
    let egress_rows = proj.target_cards.iter().take(3).map(|t| {
        let is_fail = t.badge_tone == BadgeTone::Fail;
        let is_warn = t.badge_tone == BadgeTone::Warn;
        let status_color = if is_fail {
            p.badge_fail.text
        } else if is_warn {
            p.badge_warn.text
        } else {
            p.badge_pass.text
        };
        let status_txt = if is_fail {
            format!("{} · 越界", t.cc_badge)
        } else if t.cc_badge == "TLS" {
            "代理连通".to_string()
        } else {
            format!("{} · 合规", t.cc_badge)
        };
        let tid = t.id.clone();
        let tname = t.name.clone();
        let ctrl_rt = ctrl.clone();
        let hover_bg = p.sidebar_hover_bg;

        inset_box(p)
            .flex_row()
            .items_center()
            .justify_between()
            .px(px(10.))
            .py(px(8.5))
            .gap(px(8.))
            .when(is_fail, |box_d| {
                box_d
                    .bg(rgba(p.badge_fail.bg))
                    .border_color(rgba(p.hero_tripped.border))
            })
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(8.))
                    .min_w(px(0.))
                    .flex_1()
                    .child(brand_icon(&t.id, 22.0, 6.0, p.is_dark))
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .min_w(px(0.))
                            .flex_1()
                            .gap(px(1.5))
                            .child(
                                div()
                                    .truncate()
                                    .text_size(px(12.))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .text_color(rgb(p.text_primary))
                                    .child(short_target_name(&t.id, &t.name)),
                            )
                            .child(
                                mono_tabular(t.ip_display.clone())
                                    .truncate()
                                    .text_size(px(10.5))
                                    .text_color(rgb(p.text_muted)),
                            ),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .flex_shrink_0()
                    .gap(px(7.))
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .items_end()
                            .gap(px(1.))
                            .child(
                                mono_tabular(status_txt)
                                    .text_size(px(11.))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .text_color(rgb(status_color)),
                            )
                            .child(
                                mono_tabular(t.latency_label.clone())
                                    .text_size(px(10.))
                                    .text_color(rgb(p.text_muted)),
                            ),
                    )
                    .child({
                        let mut btn = div()
                            .id(gpui::ElementId::Name(format!("ov-recheck-{}", t.id).into()))
                            .flex()
                            .items_center()
                            .justify_center()
                            .w(px(24.))
                            .h(px(24.))
                            .rounded(px(7.))
                            .bg(rgb(p.card_bg))
                            .border_1()
                            .border_color(rgb(p.card_border))
                            .child(ui_icon("icons/ui/refresh.svg", 11.5, p.text_secondary));
                        if can_act {
                            btn = btn
                                .cursor_pointer()
                                .hover(move |s| s.bg(rgb(hover_bg)))
                                .on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        let id = tid.clone();
                                        let msg = format!("已完成单目标重检：{tname}");
                                        ctrl_rt.update(cx, |c, cx| {
                                            c.send_request(
                                                PipeRequest::RecheckNow { target_id: Some(id) },
                                                None,
                                                cx,
                                            );
                                            c.set_toast(msg, true, cx);
                                        });
                                    }),
                                );
                        }
                        btn
                    }),
            )
    });

    let col_egress = bento_card(p)
        .w(relative(0.365))
        .flex_shrink_0()
        .px(px(15.))
        .py(px(14.))
        .justify_between()
        .gap(px(10.))
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(9.))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap(px(6.))
                        .child(
                            div()
                                .text_size(px(12.5))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.text_primary))
                                .child("出口实况探测"),
                        )
                        .child(
                            mono_tabular(format!("只读核验 · {}", proj.hero.checked_age_text))
                                .text_size(px(10.5))
                                .text_color(rgb(p.text_muted)),
                        ),
                )
                .child(div().flex().flex_col().gap(px(8.)).children(egress_rows)),
        )
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .pt(px(9.))
                .border_t_1()
                .border_color(rgb(p.card_border))
                .child(
                    div()
                        .text_size(px(11.))
                        .text_color(rgb(p.text_muted))
                        .child("不改动你的代理分流策略"),
                )
                .child(
                    div()
                        .id("ov-to-targets")
                        .cursor_pointer()
                        .text_size(px(11.))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(rgb(p.text_primary))
                        .child("白名单配置 →")
                        .on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |_, _, _, cx| {
                                ctrl_to_targets.update(cx, |c, cx| {
                                    c.set_nav(NavSection::Targets, cx);
                                });
                            }),
                        ),
                ),
        );

    // -------------------------------------------------------------------------
    // Lower Row Col 3: 4-Vector Leak Shield + Antigravity Status + 24h Mini Tape
    // -------------------------------------------------------------------------
    let ctrl_to_env = ctrl.clone();
    let ctrl_to_ag = ctrl.clone();
    let ctrl_to_audit = ctrl.clone();
    let ctrl_q = ctrl.clone();
    let ctrl_d = ctrl.clone();
    let ctrl_v = ctrl.clone();

    let mut non_empty = 0u32;
    let mut pass_bars = 0u32;
    let mini_bars = proj.timeline_bars.iter().map(|b| {
        let c = match b.status {
            TimelineStatus::Pass => {
                non_empty += 1;
                pass_bars += 1;
                p.timeline.pass
            }
            TimelineStatus::Warn => {
                non_empty += 1;
                p.timeline.warn
            }
            TimelineStatus::Fail => {
                non_empty += 1;
                p.timeline.fail
            }
            TimelineStatus::Empty => p.timeline.empty,
        };
        div()
            .flex_1()
            .min_w(px(2.))
            .h(px(10.))
            .rounded(px(1.5))
            .bg(rgb(c))
    });
    let mini_bars_vec: Vec<Div> = mini_bars.collect();
    let compliance_pct = if non_empty == 0 {
        "--".to_string()
    } else {
        format!("{:.1}%", (pass_bars as f64 / non_empty as f64) * 100.0)
    };

    let col_shield = bento_card(p)
        .flex_1()
        .min_w(px(0.))
        .px(px(15.))
        .py(px(14.))
        .justify_between()
        .gap(px(10.))
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(10.))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .child(
                            div()
                                .text_size(px(12.5))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.text_primary))
                                .child("四维防漏"),
                        )
                        .child(
                            div()
                                .id("ov-to-env")
                                .cursor_pointer()
                                .text_size(px(11.))
                                .font_weight(FontWeight::MEDIUM)
                                .text_color(rgb(p.text_muted))
                                .child("详情 →")
                                .on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_to_env.update(cx, |c, cx| {
                                            c.env_tab = EnvSubTab::Shield;
                                            c.set_nav(NavSection::Environment, cx);
                                        });
                                    }),
                                ),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .gap(px(10.))
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .justify_between()
                                .child(
                                    div()
                                        .text_size(px(12.))
                                        .font_weight(FontWeight::MEDIUM)
                                        .text_color(rgb(p.text_secondary))
                                        .child("阻断 QUIC"),
                                )
                                .child(
                                    toggle_switch("ov-sh-quic", cfg.leak_shield_quic, can_act, p)
                                        .when(can_act, |sw| {
                                            sw.on_mouse_up(
                                                MouseButton::Left,
                                                cx.listener(move |_, _, _, cx| {
                                                    let next = !cfg.leak_shield_quic;
                                                    ctrl_q.update(cx, |c, cx| {
                                                        c.save_config_patch(
                                                            move |x| x.leak_shield_quic = next,
                                                            "QUIC 防漏开关已更新",
                                                            cx,
                                                        );
                                                    });
                                                }),
                                            )
                                        }),
                                ),
                        )
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .justify_between()
                                .child(
                                    div()
                                        .text_size(px(12.))
                                        .font_weight(FontWeight::MEDIUM)
                                        .text_color(rgb(p.text_secondary))
                                        .child("阻断 DNS / DoH"),
                                )
                                .child(
                                    toggle_switch("ov-sh-dns", cfg.leak_shield_dns_doh, can_act, p)
                                        .when(can_act, |sw| {
                                            sw.on_mouse_up(
                                                MouseButton::Left,
                                                cx.listener(move |_, _, _, cx| {
                                                    let next = !cfg.leak_shield_dns_doh;
                                                    ctrl_d.update(cx, |c, cx| {
                                                        c.save_config_patch(
                                                            move |x| x.leak_shield_dns_doh = next,
                                                            "DNS / DoH 防漏开关已更新",
                                                            cx,
                                                        );
                                                    });
                                                }),
                                            )
                                        }),
                                ),
                        )
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .justify_between()
                                .child(
                                    div()
                                        .text_size(px(12.))
                                        .font_weight(FontWeight::MEDIUM)
                                        .text_color(rgb(p.text_secondary))
                                        .child("阻断 IPv6"),
                                )
                                .child(
                                    toggle_switch("ov-sh-ipv6", cfg.leak_shield_ipv6, can_act, p)
                                        .when(can_act, |sw| {
                                            sw.on_mouse_up(
                                                MouseButton::Left,
                                                cx.listener(move |_, _, _, cx| {
                                                    let next = !cfg.leak_shield_ipv6;
                                                    ctrl_v.update(cx, |c, cx| {
                                                        c.save_config_patch(
                                                            move |x| x.leak_shield_ipv6 = next,
                                                            "IPv6 防漏开关已更新",
                                                            cx,
                                                        );
                                                    });
                                                }),
                                            )
                                        }),
                                ),
                        ),
                )
                .child(
                    inset_box(p)
                        .id("ov-ag-inject-shortcut")
                        .cursor_pointer()
                        .flex_row()
                        .items_center()
                        .justify_between()
                        .px(px(9.))
                        .py(px(7.))
                        .child(
                            div()
                                .text_size(px(11.))
                                .text_color(rgb(p.text_secondary))
                                .child("反重力注入"),
                        )
                        .child(
                            div()
                                .text_size(px(11.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(if ag_degraded {
                                    p.badge_fail.text
                                } else if ag_proxy.installed {
                                    p.badge_pass.text
                                } else {
                                    p.text_muted
                                }))
                                .child(if ag_degraded {
                                    "● 异常 · 去修复"
                                } else if ag_proxy.installed {
                                    "● 正常"
                                } else {
                                    "○ 未安装"
                                }),
                        )
                        .on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |_, _, _, cx| {
                                ctrl_to_ag.update(cx, |c, cx| {
                                    c.env_tab = EnvSubTab::Antigravity;
                                    c.set_nav(NavSection::Environment, cx);
                                });
                            }),
                        ),
                )
                .child(
                    inset_box(p)
                        .flex_row()
                        .items_center()
                        .justify_between()
                        .px(px(9.))
                        .py(px(7.))
                        .child(
                            mono_tabular(format!("护盾 {} 规则", shield_status.active_rules))
                                .text_size(px(10.5))
                                .text_color(rgb(p.text_secondary)),
                        )
                        .child(
                            mono_tabular(if leak_watch.direct_total > 0 {
                                format!("● {} 直连泄露", leak_watch.direct_total)
                            } else {
                                "● 0 直连泄露".into()
                            })
                            .text_size(px(10.5))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(rgb(if leak_watch.direct_total > 0 {
                                p.badge_fail.text
                            } else {
                                p.badge_pass.text
                            })),
                        ),
                ),
        )
        .child(
            div()
                .id("ov-mini-timeline")
                .cursor_pointer()
                .flex()
                .flex_col()
                .gap(px(6.))
                .pt(px(9.))
                .border_t_1()
                .border_color(rgb(p.card_border))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .child(
                            div()
                                .text_size(px(11.))
                                .text_color(rgb(p.text_muted))
                                .child("24h 轨迹"),
                        )
                        .child(
                            mono_tabular(compliance_pct)
                                .text_size(px(11.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(if tripped {
                                    p.badge_fail.text
                                } else {
                                    p.badge_pass.text
                                })),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(1.5))
                        .children(mini_bars_vec),
                )
                .on_mouse_up(
                    MouseButton::Left,
                    cx.listener(move |_, _, _, cx| {
                        ctrl_to_audit.update(cx, |c, cx| c.set_nav(NavSection::Audit, cx));
                    }),
                ),
        );

    div()
        .flex()
        .flex_col()
        .w_full()
        .flex_1()
        .min_w(px(0.))
        .gap(px(11.))
        .child(
            div()
                .flex()
                .flex_row()
                .w_full()
                .min_w(px(0.))
                .gap(px(11.))
                .child(hero_card)
                .child(launch_deck),
        )
        .child(
            div()
                .flex()
                .flex_row()
                .w_full()
                .flex_1()
                .min_w(px(0.))
                .gap(px(11.))
                .child(col_procs)
                .child(col_egress)
                .child(col_shield),
        )
}
