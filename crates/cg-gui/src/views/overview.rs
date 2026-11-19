//! Mode B — `守护总览磁贴` Bento overview, Tripped Dual-Path Card, 48-bar timeline, and 4-row defense self-check.

use crate::app::{AppController, ConsoleWindowView};
use crate::protocol::{Lifecycle, PipeRequest, SelfCheckStatus, TimelineStatus, UiLabelExt};
use crate::state::{ConsoleProjection, NavSection, TrippedDiagnosticViewModel};
use crate::theme::{BadgeTone, ThemePalette};
use crate::widgets::controls::{
    ButtonKind, action_button, bento_card, card_header, cc_badge, inset_box, latency_pill,
    mono_tabular, status_pill,
};
use gpui::{Context, Div, Entity, FontWeight, MouseButton, div, prelude::*, px, rgb, rgba};

pub fn render_overview(
    ctrl: Entity<AppController>,
    proj: &ConsoleProjection,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> Div {
    let snap_opt = ctrl.read(cx).snapshot.clone();
    let is_disarmed = snap_opt
        .as_ref()
        .is_some_and(|s| s.lifecycle == Lifecycle::Disarmed);
    let busy = ctrl.read(cx).busy_action;
    let connected = proj.connected;

    let mut root = div().flex().flex_col().gap(px(14.));

    // Tripped Diagnostic Dual-Path Card
    if let Some(diag) = proj.tripped_card.as_ref() {
        root = root.child(render_tripped_diagnostic_card(
            ctrl.clone(),
            diag,
            connected,
            busy,
            p,
            cx,
        ));
    } else if is_disarmed {
        let ctrl_rearm = ctrl.clone();
        let ds = p.hero_disarmed;
        let can_rearm = connected && !busy;
        root = root.child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .gap(px(12.))
                .p(px(14.))
                .rounded(px(16.))
                .bg(rgba(ds.bg))
                .border_1()
                .border_color(rgba(ds.border))
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .gap(px(3.))
                        .child(
                            div()
                                .text_size(px(14.))
                                .font_weight(FontWeight::BOLD)
                                .text_color(rgb(ds.title))
                                .child("当前处于撤防状态（保护已停止）"),
                        )
                        .child(
                            div()
                                .text_size(px(12.))
                                .text_color(rgb(ds.subtitle))
                                .child("防火墙隔离与全局断网已核验清除，AI 应用可直接运行；切回合规节点后可随时重新布防。"),
                        ),
                )
                .child(
                    action_button("overview-rearm", "🛡 重新布防", ButtonKind::Primary, can_rearm, p)
                        .when(can_rearm, |b| {
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
                ),
        );
    }

    // Row 1: 1.55fr Hero Bento + 1fr Safe Launch Bento
    let hero_surface = p.hero(proj.hero.tone);
    let ctrl_recheck = ctrl.clone();
    let ctrl_pause = ctrl.clone();

    let hero_bento = div()
        .flex()
        .flex_col()
        .justify_between()
        .flex_grow(1.55)
        .flex_basis(px(0.))
        .min_w(px(0.))
        .p(px(16.))
        .gap(px(10.))
        .rounded(px(14.))
        .bg(rgba(hero_surface.bg))
        .border_1()
        .border_color(rgba(hero_surface.border))
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .gap(px(10.))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(8.))
                        .child(
                            div()
                                .w(px(10.))
                                .h(px(10.))
                                .rounded(px(999.))
                                .bg(rgba(hero_surface.ring)),
                        )
                        .child(
                            div()
                                .px(px(9.))
                                .py(px(3.))
                                .rounded(px(999.))
                                .bg(rgba(hero_surface.pill_bg))
                                .text_size(px(11.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(hero_surface.pill_text))
                                .child(proj.hero.pill_label.clone()),
                        )
                        .child(
                            div()
                                .px(px(8.))
                                .py(px(3.))
                                .rounded(px(6.))
                                .bg(rgb(p.card_bg))
                                .border_1()
                                .border_color(rgb(p.card_border))
                                .text_size(px(10.5))
                                .font_family("Cascadia Mono")
                                .text_color(rgb(p.text_secondary))
                                .child(proj.hero.access_badge.clone()),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(12.))
                        .child(metric_chip(
                            "通过",
                            proj.hero.pass_count,
                            p.badge_pass.text,
                            p,
                        ))
                        .child(metric_chip(
                            "违规",
                            proj.hero.fail_count,
                            p.badge_fail.text,
                            p,
                        ))
                        .child(metric_chip(
                            "待确认",
                            proj.hero.unverified_count,
                            p.text_muted,
                            p,
                        )),
                ),
        )
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(4.))
                .child(
                    div()
                        .text_size(px(20.))
                        .font_weight(FontWeight::BOLD)
                        .text_color(rgb(hero_surface.title))
                        .child(proj.hero.title.clone()),
                )
                .child(
                    div()
                        .text_size(px(12.5))
                        .line_height(px(18.))
                        .text_color(rgb(hero_surface.subtitle))
                        .child(proj.hero.subtitle.clone()),
                ),
        )
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .gap(px(8.))
                .child(
                    div()
                        .text_size(px(11.))
                        .text_color(rgb(hero_surface.subtitle))
                        .child(format!("最近核验：{}", proj.hero.checked_age_text)),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(8.))
                        .child({
                            let can_pause = connected && !busy;
                            action_button(
                                "hero-pause",
                                if proj.hero.is_paused {
                                    "▶ 恢复守护"
                                } else {
                                    "II 暂停 30 分钟"
                                },
                                ButtonKind::Secondary,
                                can_pause,
                                p,
                            )
                            .when(can_pause, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_pause.update(cx, |c, cx| c.toggle_pause_30m(cx));
                                    }),
                                )
                            })
                        })
                        .child({
                            let can_recheck = connected && !busy;
                            action_button(
                                "hero-recheck",
                                if connected {
                                    "↻ 立即重检"
                                } else {
                                    "↻ 重试连接"
                                },
                                ButtonKind::Primary,
                                !busy,
                                p,
                            )
                            .when(!busy, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_recheck.update(cx, |c, cx| {
                                            let req = if can_recheck {
                                                PipeRequest::RecheckNow { target_id: None }
                                            } else {
                                                PipeRequest::GetSnapshot
                                            };
                                            let ok_msg = if can_recheck {
                                                "已完成新一轮出口核验"
                                            } else {
                                                "已重新连接 Guardian 守护服务"
                                            };
                                            c.send_request(req, Some(ok_msg), cx);
                                        });
                                    }),
                                )
                            })
                        }),
                ),
        );

    // 1fr Safe Launch Bento
    let launch_rows = proj.launch_apps.iter().map(|app| {
        let ctrl_l = ctrl.clone();
        let aid = app.agent_id.clone();
        let paths = app.install_paths.clone();
        let can_launch_click = connected && !busy && app.installed;
        let btn_label = if !connected {
            "服务离线"
        } else if app.ag_proxy_blocked {
            "注入丢失"
        } else if app.quarantined {
            "已隔离"
        } else if proj.hero.can_launch {
            "安全启动"
        } else {
            "门禁拦截"
        };
        let kind = if !connected {
            ButtonKind::Secondary
        } else if app.ag_proxy_blocked || app.quarantined {
            ButtonKind::Danger
        } else if proj.hero.can_launch {
            ButtonKind::Primary
        } else {
            ButtonKind::Secondary
        };

        inset_box(p)
            .flex_row()
            .items_center()
            .justify_between()
            .px(px(11.))
            .py(px(8.))
            .gap(px(8.))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_w(px(0.))
                    .gap(px(1.))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(6.))
                            .child(
                                div()
                                    .text_size(px(12.5))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .text_color(rgb(p.text_primary))
                                    .child(app.label.clone()),
                            )
                            .child(if connected && app.ag_proxy_blocked {
                                status_pill("注入丢失", BadgeTone::Fail, p)
                            } else {
                                div()
                                    .text_size(px(10.))
                                    .text_color(rgb(p.text_muted))
                                    .child(app.badge.clone())
                            }),
                    )
                    .child(
                        div()
                            .truncate()
                            .text_size(px(10.5))
                            .text_color(rgb(if connected && app.ag_proxy_blocked {
                                p.badge_fail.text
                            } else {
                                p.text_muted
                            }))
                            .child(if !connected {
                                "守护离线：禁止旁路启动".into()
                            } else if app.ag_proxy_blocked {
                                "version.dll 注入异常 · 已拦截直连".into()
                            } else if app.running_count > 0 {
                                format!("运行中 {} 个进程", app.running_count)
                            } else if !app.installed {
                                "未检测到安装".into()
                            } else {
                                "待启动（普通用户权限）".into()
                            }),
                    ),
            )
            .child(
                action_button(
                    gpui::ElementId::Name(format!("launch-btn-{}", app.agent_id).into()),
                    btn_label,
                    kind,
                    can_launch_click,
                    p,
                )
                .when(can_launch_click, |b| {
                    b.on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |_, _, _, cx| {
                            ctrl_l.update(cx, |c, cx| {
                                c.launch_app_with_gate(aid.clone(), paths.clone(), cx);
                            });
                        }),
                    )
                }),
            )
    });

    let safe_launch_bento = bento_card(p)
        .flex_grow(1.0)
        .flex_basis(px(0.))
        .min_w(px(0.))
        .p(px(14.))
        .gap(px(8.))
        .child(card_header(
            "Safe Launch 安全启动坞",
            if proj.hero.can_launch {
                "门禁绿色放行"
            } else {
                "门禁保护锁定"
            },
            p,
        ))
        .child(div().flex().flex_col().gap(px(7.)).children(launch_rows));

    let row1 = div()
        .flex()
        .gap(px(12.))
        .child(hero_bento)
        .child(safe_launch_bento);

    // Row 2: 3 Target Bento Cards
    let row2 = if proj.target_cards.is_empty() {
        bento_card(p)
            .p(px(14.))
            .gap(px(6.))
            .child(card_header(
                "AI 出口监测目标",
                if connected { "暂无启用目标" } else { "等待守护连接" },
                p,
            ))
            .child(
                div()
                    .text_size(px(12.))
                    .text_color(rgb(p.text_muted))
                    .child(if connected {
                        "当前没有启用的目标，请在「目标与白名单」配置并保存监控目标。"
                    } else {
                        "未连接到 Guardian 服务，无法核验各 AI 目标出口；Safe Launch 处于闭锁拦截态。"
                    }),
            )
    } else {
        let target_cards = proj.target_cards.iter().map(|card| {
            bento_card(p)
                .flex_1()
                .flex_basis(px(0.))
                .min_w(px(0.))
                .p(px(13.))
                .gap(px(7.))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap(px(4.))
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .min_w(px(0.))
                                .gap(px(5.))
                                .child(
                                    div()
                                        .truncate()
                                        .text_size(px(13.))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(p.text_primary))
                                        .child(card.name.clone()),
                                )
                                .child(cc_badge(&card.cc_badge, p)),
                        )
                        .child(status_pill(card.state_label.clone(), card.badge_tone, p)),
                )
                .child(
                    div()
                        .flex()
                        .items_baseline()
                        .justify_between()
                        .gap(px(6.))
                        .child(
                            mono_tabular(card.ip_display.clone())
                                .truncate()
                                .text_size(px(15.))
                                .font_weight(FontWeight::BOLD)
                                .text_color(rgb(p.text_primary)),
                        )
                        .child(latency_pill(card.latency_label.clone(), p)),
                )
                .child(
                    div()
                        .truncate()
                        .text_size(px(11.5))
                        .text_color(rgb(p.text_secondary))
                        .child(card.location_display.clone()),
                )
                .child(
                    inset_box(p)
                        .px(px(8.))
                        .py(px(5.))
                        .truncate()
                        .text_size(px(10.5))
                        .text_color(rgb(p.text_muted))
                        .child(format!("命中规则：{}", card.matched_rule)),
                )
        });
        div().flex().gap(px(12.)).children(target_cards)
    };

    // Row 3: 24h Timeline (48-bar clickable) + Defense Self-Check (4 rows)
    // ... (现有代码)
    let row3 = div()
        .flex()
        .gap(px(12.))
        .child(timeline_card)
        .child(self_check_card);

    // Row 4: Process Cleanup
    let ctrl_sweep = ctrl.clone();
    let row4 = bento_card(p)
        .p(px(14.))
        .gap(px(8.))
        .child(card_header("进程清理", "扫描并清理孤儿进程", p))
        .child(
            action_button(
                "overview-sweep",
                "🧹 立即执行孤儿清理",
                ButtonKind::Danger,
                connected,
                p,
            )
            .when(connected, |b| {
                b.on_mouse_up(
                    MouseButton::Left,
                    cx.listener(move |_, _, _, cx| {
                        ctrl_sweep.update(cx, |c, cx| {
                            c.send_request(PipeRequest::SweepOrphans, Some("孤儿进程清理已执行"), cx);
                        });
                    }),
                )
            }),
        );

    root = root.child(row1).child(row2).child(row3).child(row4);
    root
}

fn metric_chip(label: &'static str, value: usize, color: u32, p: &ThemePalette) -> Div {
    div()
        .flex()
        .items_baseline()
        .gap(px(4.))
        .child(
            mono_tabular(value.to_string())
                .text_size(px(15.))
                .font_weight(FontWeight::BOLD)
                .text_color(rgb(color)),
        )
        .child(
            div()
                .text_size(px(10.5))
                .text_color(rgb(p.text_muted))
                .child(label),
        )
}

fn render_tripped_diagnostic_card(
    ctrl: Entity<AppController>,
    diag: &TrippedDiagnosticViewModel,
    connected: bool,
    busy: bool,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> Div {
    let can_act = connected && !busy;
    let tr = p.hero_tripped;
    let ctrl_a = ctrl.clone();
    let ctrl_b = ctrl;

    let receipt_items: Vec<Div> = diag
        .receipt
        .as_ref()
        .map(|r| {
            r.items
                .iter()
                .map(|it| {
                    inset_box(p)
                        .flex_row()
                        .items_center()
                        .justify_between()
                        .px(px(10.))
                        .py(px(6.))
                        .child(
                            div()
                                .text_size(px(11.5))
                                .text_color(rgb(p.text_primary))
                                .child(format!("{} · {}", it.name, it.detail)),
                        )
                        .child(status_pill(it.status.label(), BadgeTone::Pass, p))
                })
                .collect()
        })
        .unwrap_or_default();

    div()
        .flex()
        .flex_col()
        .p(px(16.))
        .gap(px(12.))
        .rounded(px(16.))
        .bg(rgba(tr.bg))
        .border_1()
        .border_color(rgba(tr.border))
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .gap(px(8.))
                .child(
                    div()
                        .text_size(px(15.5))
                        .font_weight(FontWeight::BOLD)
                        .text_color(rgb(tr.title))
                        .child(format!("⚠ 熔断根因诊断 · {}", diag.reason)),
                )
                .child(status_pill(
                    format!(
                        "已终止 {} 进程 · {} 条 COM 规则已核验",
                        diag.killed_count, diag.firewall_rules
                    ),
                    BadgeTone::Fail,
                    p,
                )),
        )
        .child(
            div()
                .flex()
                .gap(px(12.))
                .child(
                    inset_box(p)
                        .flex_1()
                        .p(px(11.))
                        .gap(px(4.))
                        .child(
                            div()
                                .text_size(px(11.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.text_muted))
                                .child("期望白名单"),
                        )
                        .child(
                            mono_tabular(diag.expected_summary.clone())
                                .text_size(px(13.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.badge_pass.text)),
                        ),
                )
                .child(
                    inset_box(p)
                        .flex_1()
                        .p(px(11.))
                        .gap(px(4.))
                        .child(
                            div()
                                .text_size(px(11.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.text_muted))
                                .child("实测违规出口"),
                        )
                        .child(
                            mono_tabular(diag.observed_summary.clone())
                                .text_size(px(13.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.badge_fail.text)),
                        ),
                ),
        )
        .when(!receipt_items.is_empty(), |card| {
            card.child(div().flex().flex_col().gap(px(6.)).children(receipt_items))
        })
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .gap(px(10.))
                .child(
                    div()
                        .text_size(px(11.5))
                        .text_color(rgb(tr.subtitle))
                        .child(diag.network_note.clone()),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(8.))
                        .child(
                            action_button(
                                "flow-b-disarm",
                                "⏹ 暂不使用 AI，停止保护并立即解封（进入撤防态）",
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
                                                    reason: Some(
                                                        "用户选择流程 B 停止保护并立即解封".into(),
                                                    ),
                                                },
                                                Some("已执行流程 B：隔离规则已清除，进入撤防态"),
                                                cx,
                                            );
                                        });
                                    }),
                                )
                            }),
                        )
                        .child(
                            action_button(
                                "flow-a-recover",
                                "↻ 我已切回合规节点，立即复检并安全解封",
                                ButtonKind::Primary,
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
                                                Some("流程 A 复检通过，已安全解封并恢复监控"),
                                                cx,
                                            );
                                        });
                                    }),
                                )
                            }),
                        ),
                ),
        )
}
