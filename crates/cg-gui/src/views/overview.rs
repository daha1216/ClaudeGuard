//! Mode B — `守护总览磁贴` unified Bento homepage:
//! 1. Single adaptive status/alert strip (eliminates duplicate Hero + Tripped stacking)
//! 2. Primary Hero focus: full-width 2x2 Safe Launch Dock
//! 3. Integrated Managed Process Monitor & Quick Cleanup
//! 4. Responsive AI Egress Target Matrix (with per-target recheck)
//! 5. Progressive Disclosure: 24h Protection Timeline + Defense Health Self-Check

use crate::app::{AppController, ConsoleWindowView};
use crate::protocol::{Lifecycle, PipeRequest, SelfCheckStatus, TimelineStatus, UiLabelExt};
use crate::state::{ConsoleProjection, NavSection, TrippedDiagnosticViewModel};
use crate::theme::{BadgeTone, ThemePalette};
use crate::widgets::controls::{
    ButtonKind, action_button, bento_card, card_header, cc_badge, inset_box, latency_pill,
    mono_tabular, status_pill,
};
use gpui::{Context, Div, Entity, FontWeight, MouseButton, div, prelude::*, px, rgb, rgba};

fn cleanup_toast_for_agent(agent_id: &str) -> &'static str {
    match agent_id {
        "claude" => "已清理 Claude Desktop 进程与孤儿残留",
        "claude-code" => "已清理 Claude Code CLI 会话进程",
        "chatgpt" => "已清理 ChatGPT / Codex 桌面端进程",
        "codex" => "已清理 Codex CLI 会话进程",
        "antigravity" => "已清理反重力客户端进程与孤儿残留",
        _ => "已清理所选受管进程",
    }
}

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
    let lockdown_manual = snap_opt.as_ref().is_some_and(|s| s.lockdown_manual);
    let busy = ctrl.read(cx).busy_action;
    let connected = proj.connected;

    // ── Band 1: Single Unified Status / Alert Strip ─────────────────────────────────────────
    let band1 = if let Some(diag) = proj.tripped_card.as_ref() {
        render_unified_tripped_strip(ctrl.clone(), proj, diag, connected, busy, p, cx)
    } else if is_disarmed {
        render_disarmed_strip(ctrl.clone(), proj, connected, busy, p, cx)
    } else {
        render_healthy_status_strip(ctrl.clone(), proj, connected, busy, p, cx)
    };

    // ── Band 2: Primary Visual Focus — Safe Launch 安全启动坞 ───────────────────────────────
    let band2 = render_safe_launch_dock(ctrl.clone(), proj, connected, busy, p, cx);

    // ── Band 3: Integrated Managed Process Monitor & Quick Cleanup ──────────────────────────
    let band3 =
        render_process_monitor_card(ctrl.clone(), proj, connected, busy, lockdown_manual, p, cx);

    // ── Band 4: AI Egress Target Matrix (responsive 3-column chunks) ────────────────────────
    let band4 = render_target_matrix(ctrl.clone(), proj, connected, busy, p, cx);

    // ── Band 5: Progressive Disclosure — 24h Timeline + Defense Health Self-Check ───────────
    let band5 = div()
        .flex()
        .w_full()
        .min_w(px(0.))
        .gap(px(12.))
        .child(render_timeline_card(ctrl.clone(), proj, p, cx))
        .child(render_self_check_card(proj, p));

    div()
        .flex()
        .flex_col()
        .w_full()
        .min_w(px(0.))
        .gap(px(14.))
        .child(band1)
        .child(band2)
        .child(band3)
        .child(band4)
        .child(band5)
}

fn render_healthy_status_strip(
    ctrl: Entity<AppController>,
    proj: &ConsoleProjection,
    connected: bool,
    busy: bool,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> Div {
    let hs = p.hero(proj.hero.tone);
    let ctrl_pause = ctrl.clone();
    let ctrl_recheck = ctrl;

    div()
        .flex()
        .flex_col()
        .w_full()
        .min_w(px(0.))
        .p(px(16.))
        .gap(px(10.))
        .rounded(px(16.))
        .bg(rgba(hs.bg))
        .border_1()
        .border_color(rgba(hs.border))
        .child(
            div()
                .flex()
                .flex_wrap()
                .items_center()
                .justify_between()
                .gap(px(10.))
                .child(
                    div()
                        .flex()
                        .flex_wrap()
                        .items_center()
                        .gap(px(8.))
                        .child(
                            div()
                                .flex_shrink_0()
                                .w(px(9.))
                                .h(px(9.))
                                .rounded(px(999.))
                                .bg(rgba(hs.ring)),
                        )
                        .child(
                            div()
                                .flex_shrink_0()
                                .whitespace_nowrap()
                                .px(px(9.))
                                .py(px(3.))
                                .rounded(px(999.))
                                .bg(rgba(hs.pill_bg))
                                .text_size(px(11.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(hs.pill_text))
                                .child(proj.hero.pill_label.clone()),
                        )
                        .child(
                            div()
                                .flex_shrink_0()
                                .whitespace_nowrap()
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
                        .flex_wrap()
                        .items_center()
                        .gap(px(12.))
                        .child(metric_chip(
                            "通过",
                            proj.hero.pass_count,
                            p.badge_pass.text,
                            p,
                        ))
                        .child(metric_chip(
                            "异常",
                            proj.hero.fail_count,
                            p.badge_fail.text,
                            p,
                        ))
                        .child(metric_chip(
                            "待核验",
                            proj.hero.unverified_count,
                            p.text_muted,
                            p,
                        )),
                ),
        )
        .child(
            div()
                .flex()
                .flex_wrap()
                .items_end()
                .justify_between()
                .gap(px(12.))
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .flex_1()
                        .min_w(px(260.))
                        .gap(px(4.))
                        .child(
                            div()
                                .text_size(px(19.))
                                .font_weight(FontWeight::BOLD)
                                .text_color(rgb(hs.title))
                                .child(proj.hero.title.clone()),
                        )
                        .child(
                            div()
                                .text_size(px(12.))
                                .line_height(px(17.5))
                                .text_color(rgb(hs.subtitle))
                                .child(format!(
                                    "{} · 最近核验：{}",
                                    proj.hero.subtitle, proj.hero.checked_age_text
                                )),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .flex_wrap()
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
                                                "已重新连接后台守护服务"
                                            };
                                            c.send_request(req, Some(ok_msg), cx);
                                        });
                                    }),
                                )
                            })
                        }),
                ),
        )
}

fn render_disarmed_strip(
    ctrl: Entity<AppController>,
    proj: &ConsoleProjection,
    connected: bool,
    busy: bool,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> Div {
    let ds = p.hero_disarmed;
    let can_rearm = connected && !busy;

    div()
        .flex()
        .flex_wrap()
        .items_center()
        .justify_between()
        .w_full()
        .min_w(px(0.))
        .gap(px(12.))
        .p(px(16.))
        .rounded(px(16.))
        .bg(rgba(ds.bg))
        .border_1()
        .border_color(rgba(ds.border))
        .child(
            div()
                .flex()
                .flex_col()
                .flex_1()
                .min_w(px(260.))
                .gap(px(5.))
                .child(
                    div()
                        .flex()
                        .flex_wrap()
                        .items_center()
                        .gap(px(8.))
                        .child(
                            div()
                                .flex_shrink_0()
                                .whitespace_nowrap()
                                .px(px(9.))
                                .py(px(2.5))
                                .rounded(px(999.))
                                .bg(rgba(ds.pill_bg))
                                .text_size(px(11.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(ds.pill_text))
                                .child("已撤防 · 保护已停止"),
                        )
                        .child(
                            div()
                                .flex_shrink_0()
                                .whitespace_nowrap()
                                .px(px(8.))
                                .py(px(2.5))
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
                        .text_size(px(16.))
                        .font_weight(FontWeight::BOLD)
                        .text_color(rgb(ds.title))
                        .child("当前处于撤防状态，隔离与网络限制已全部解除"),
                )
                .child(
                    div()
                        .text_size(px(12.))
                        .line_height(px(17.5))
                        .text_color(rgb(ds.subtitle))
                        .child("受管 AI 应用可直接运行；切回合规节点后可随时点击右侧重新布防。"),
                ),
        )
        .child(
            action_button(
                "overview-rearm",
                "🛡 重新布防",
                ButtonKind::Primary,
                can_rearm,
                p,
            )
            .when(can_rearm, |b| {
                b.on_mouse_up(
                    MouseButton::Left,
                    cx.listener(move |_, _, _, cx| {
                        ctrl.update(cx, |c, cx| {
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
}

fn render_unified_tripped_strip(
    ctrl: Entity<AppController>,
    proj: &ConsoleProjection,
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
                        .w_full()
                        .flex_row()
                        .items_center()
                        .justify_between()
                        .px(px(10.))
                        .py(px(6.))
                        .gap(px(8.))
                        .child(
                            div()
                                .flex_1()
                                .min_w(px(0.))
                                .text_size(px(11.5))
                                .line_height(px(16.))
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
        .w_full()
        .min_w(px(0.))
        .p(px(16.))
        .gap(px(12.))
        .rounded(px(16.))
        .bg(rgba(tr.bg))
        .border_1()
        .border_color(rgba(tr.border))
        // Header: Status pills + metrics on left, wrapped dual-path recovery actions on right
        .child(
            div()
                .flex()
                .flex_wrap()
                .items_center()
                .justify_between()
                .gap(px(10.))
                .child(
                    div()
                        .flex()
                        .flex_wrap()
                        .items_center()
                        .gap(px(8.))
                        .child(status_pill("熔断保护已触发", BadgeTone::Fail, p))
                        .child(
                            div()
                                .flex_shrink_0()
                                .whitespace_nowrap()
                                .px(px(8.))
                                .py(px(2.5))
                                .rounded(px(6.))
                                .bg(rgb(p.card_bg))
                                .border_1()
                                .border_color(rgb(p.card_border))
                                .text_size(px(10.5))
                                .font_family("Cascadia Mono")
                                .text_color(rgb(p.text_secondary))
                                .child(proj.hero.access_badge.clone()),
                        )
                        .child(metric_chip(
                            "通过",
                            proj.hero.pass_count,
                            p.badge_pass.text,
                            p,
                        ))
                        .child(metric_chip(
                            "异常",
                            proj.hero.fail_count,
                            p.badge_fail.text,
                            p,
                        )),
                )
                .child(
                    div()
                        .flex()
                        .flex_wrap()
                        .items_center()
                        .gap(px(8.))
                        .child(
                            action_button(
                                "trip-flow-a",
                                "↻ 节点已切回 · 立即复检解封",
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
                                                Some("复检通过，已安全解封并恢复守护"),
                                                cx,
                                            );
                                        });
                                    }),
                                )
                            }),
                        )
                        .child(
                            action_button(
                                "trip-flow-b",
                                "⏹ 暂不用 AI · 停止并解封",
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
                                                    reason: Some("用户从主控台手动停止并解封".into()),
                                                },
                                                Some("已撤防并核验解除隔离限制"),
                                                cx,
                                            );
                                        });
                                    }),
                                )
                            }),
                        ),
                ),
        )
        // Title & wrapped reason
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(4.))
                .child(
                    div()
                        .text_size(px(17.5))
                        .font_weight(FontWeight::BOLD)
                        .text_color(rgb(tr.title))
                        .child("检测到出口偏离，已自动隔离受管 AI 应用"),
                )
                .child(
                    div()
                        .w_full()
                        .text_size(px(12.))
                        .line_height(px(17.5))
                        .text_color(rgb(tr.subtitle))
                        .child(format!(
                            "触发原因：{} · 最近核验：{}",
                            diag.reason, proj.hero.checked_age_text
                        )),
                ),
        )
        // Expected vs Observed diff
        .child(
            div()
                .flex()
                .w_full()
                .min_w(px(0.))
                .gap(px(10.))
                .child(
                    inset_box(p)
                        .flex_1()
                        .flex_basis(px(0.))
                        .min_w(px(0.))
                        .p(px(10.))
                        .gap(px(3.))
                        .child(
                            div()
                                .text_size(px(10.5))
                                .text_color(rgb(p.text_muted))
                                .child("期望出口白名单"),
                        )
                        .child(
                            div()
                                .w_full()
                                .text_size(px(12.))
                                .line_height(px(17.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.text_primary))
                                .child(diag.expected_summary.clone()),
                        ),
                )
                .child(
                    inset_box(p)
                        .flex_1()
                        .flex_basis(px(0.))
                        .min_w(px(0.))
                        .p(px(10.))
                        .gap(px(3.))
                        .child(
                            div()
                                .text_size(px(10.5))
                                .text_color(rgb(p.text_muted))
                                .child("当前实测出口"),
                        )
                        .child(
                            div()
                                .w_full()
                                .text_size(px(12.))
                                .line_height(px(17.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.badge_fail.text))
                                .child(diag.observed_summary.clone()),
                        ),
                ),
        )
        // Compact wrapped execution summary chips
        .child(
            div()
                .flex()
                .flex_wrap()
                .items_center()
                .gap(px(8.))
                .child(status_pill(
                    format!("已终止 {} 个进程", diag.killed_count),
                    BadgeTone::Fail,
                    p,
                ))
                .child(status_pill(
                    format!("防火墙隔离 {} 条", diag.firewall_rules),
                    BadgeTone::Warn,
                    p,
                ))
                .child(status_pill(diag.network_note.clone(), BadgeTone::Muted, p)),
        )
        .when(!receipt_items.is_empty(), |box_el| {
            box_el.child(
                div()
                    .flex()
                    .flex_col()
                    .w_full()
                    .min_w(px(0.))
                    .gap(px(6.))
                    .children(receipt_items),
            )
        })
}

fn render_safe_launch_dock(
    ctrl: Entity<AppController>,
    proj: &ConsoleProjection,
    connected: bool,
    busy: bool,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> Div {
    let cards: Vec<Div> = proj
        .launch_apps
        .iter()
        .map(|app| {
            let ctrl_l = ctrl.clone();
            let ctrl_env = ctrl.clone();
            let aid = app.agent_id.clone();
            let paths = app.install_paths.clone();
            let is_ag_blocked = connected && app.ag_proxy_blocked;
            let can_click = connected && !busy && (app.installed || is_ag_blocked);

            let (btn_label, kind) = if !connected {
                ("守护未连接", ButtonKind::Secondary)
            } else if is_ag_blocked {
                ("前往修复注入", ButtonKind::Danger)
            } else if app.quarantined {
                ("已隔离拦截", ButtonKind::Danger)
            } else if !app.installed {
                ("未安装", ButtonKind::Secondary)
            } else if proj.hero.can_launch {
                ("▶ 安全启动", ButtonKind::Primary)
            } else {
                ("门禁拦截", ButtonKind::Secondary)
            };

            let status_text = if !connected {
                "后台守护未连接，已禁止旁路启动".to_string()
            } else if is_ag_blocked {
                "antigravity-proxy 注入异常，已阻止直连启动".to_string()
            } else if app.quarantined {
                "当前处于熔断隔离中，切回合规节点并复检后放行".to_string()
            } else if !app.installed {
                "本机未检测到安装路径".to_string()
            } else if app.running_count > 0 && app.orphan_count > 0 {
                format!(
                    "运行中 {} 个进程 · 发现 {} 个孤儿残留",
                    app.running_count, app.orphan_count
                )
            } else if app.running_count > 0 {
                format!("运行中 {} 个进程 · 出口受保护", app.running_count)
            } else if proj.hero.can_launch {
                "就绪 · 启动前自动核验出口白名单".to_string()
            } else {
                "等待出口核验通过后自动解锁".to_string()
            };

            let status_color = if is_ag_blocked || app.quarantined {
                p.badge_fail.text
            } else if app.orphan_count > 0 {
                p.badge_warn.text
            } else if app.running_count > 0 && proj.hero.can_launch {
                p.badge_pass.text
            } else {
                p.text_muted
            };

            let badge_pill = if is_ag_blocked {
                status_pill("注入异常", BadgeTone::Fail, p)
            } else if app.quarantined {
                status_pill("已隔离", BadgeTone::Fail, p)
            } else if app.running_count > 0 {
                status_pill(format!("运行中 {}", app.running_count), BadgeTone::Pass, p)
            } else if app.installed {
                status_pill(app.badge.clone(), BadgeTone::Muted, p)
            } else {
                status_pill("未安装", BadgeTone::Muted, p)
            };

            inset_box(p)
                .flex_1()
                .flex_basis(px(0.))
                .min_w(px(0.))
                .flex_row()
                .items_center()
                .justify_between()
                .p(px(12.))
                .gap(px(10.))
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .flex_1()
                        .min_w(px(0.))
                        .gap(px(4.))
                        .child(
                            div()
                                .flex()
                                .flex_wrap()
                                .items_center()
                                .gap(px(6.))
                                .child(
                                    div()
                                        .text_size(px(13.5))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(p.text_primary))
                                        .child(app.label.clone()),
                                )
                                .child(badge_pill),
                        )
                        .child(
                            div()
                                .w_full()
                                .text_size(px(11.))
                                .line_height(px(15.5))
                                .text_color(rgb(status_color))
                                .child(status_text),
                        ),
                )
                .child(
                    action_button(
                        gpui::ElementId::Name(format!("launch-btn-{}", app.agent_id).into()),
                        btn_label,
                        kind,
                        can_click,
                        p,
                    )
                    .when(can_click, |b| {
                        b.on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |_, _, _, cx| {
                                if is_ag_blocked {
                                    ctrl_env.update(cx, |c, cx| {
                                        c.set_nav(NavSection::Environment, cx);
                                    });
                                } else {
                                    ctrl_l.update(cx, |c, cx| {
                                        c.launch_app_with_gate(aid.clone(), paths.clone(), cx);
                                    });
                                }
                            }),
                        )
                    }),
                )
        })
        .collect();

    let mut rows: Vec<Div> = Vec::new();
    let mut iter = cards.into_iter();
    while let Some(first) = iter.next() {
        let mut row = div().flex().w_full().min_w(px(0.)).gap(px(10.)).child(first);
        if let Some(second) = iter.next() {
            row = row.child(second);
        } else {
            row = row.child(div().flex_1().flex_basis(px(0.)).min_w(px(0.)));
        }
        rows.push(row);
    }

    bento_card(p)
        .w_full()
        .p(px(16.))
        .gap(px(10.))
        .child(card_header(
            "Safe Launch 安全启动坞",
            if !connected {
                "守护离线 · 安全闭锁"
            } else if proj.hero.can_launch {
                "出口已核验 · 门禁绿色放行"
            } else {
                "门禁保护锁定 · 等待合规恢复"
            },
            p,
        ))
        .child(
            div()
                .flex()
                .flex_col()
                .w_full()
                .min_w(px(0.))
                .gap(px(10.))
                .children(rows),
        )
}

fn render_process_monitor_card(
    ctrl: Entity<AppController>,
    proj: &ConsoleProjection,
    connected: bool,
    busy: bool,
    lockdown_manual: bool,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> Div {
    let ctrl_sweep = ctrl.clone();
    let ctrl_kill_all = ctrl.clone();
    let ctrl_lock = ctrl.clone();

    let total_running: usize = proj.agent_statuses.iter().map(|r| r.running_count).sum();
    let total_orphans: usize = proj.agent_statuses.iter().map(|r| r.orphan_count).sum();
    let any_active = total_running + total_orphans > 0;

    let agent_rows = proj.agent_statuses.iter().map(|row| {
        let ctrl_row = ctrl.clone();
        let row_id = row.id.clone();
        let row_is_cli = row.kind.contains("CLI");
        let can_clean = connected && !busy && (row.running_count > 0 || row.orphan_count > 0);
        let toast_msg = cleanup_toast_for_agent(&row.id);

        let meta_line = if row.orphan_count > 0 {
            format!(
                "运行 {} 个进程 · {} 个孤儿残留 · 隔离规则 {} 条",
                row.running_count, row.orphan_count, row.firewall_rules
            )
        } else if row.running_count > 0 {
            format!(
                "运行 {} 个进程 · 隔离规则 {} 条",
                row.running_count, row.firewall_rules
            )
        } else if !row.installed {
            "本机未检测到安装".to_string()
        } else {
            format!("待机中 · 隔离规则 {} 条", row.firewall_rules)
        };

        inset_box(p)
            .w_full()
            .flex_row()
            .items_center()
            .justify_between()
            .px(px(12.))
            .py(px(8.))
            .gap(px(10.))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_w(px(0.))
                    .gap(px(2.))
                    .child(
                        div()
                            .flex()
                            .flex_wrap()
                            .items_center()
                            .gap(px(6.))
                            .child(
                                div()
                                    .text_size(px(12.5))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .text_color(rgb(p.text_primary))
                                    .child(row.name.clone()),
                            )
                            .child(
                                div()
                                    .text_size(px(10.5))
                                    .text_color(rgb(p.text_muted))
                                    .child(row.kind.clone()),
                            ),
                    )
                    .child(
                        div()
                            .text_size(px(11.))
                            .text_color(rgb(if row.orphan_count > 0 {
                                p.badge_warn.text
                            } else {
                                p.text_secondary
                            }))
                            .child(meta_line),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(8.))
                    .child(if row.quarantined {
                        status_pill("已隔离", BadgeTone::Fail, p)
                    } else if row.orphan_count > 0 {
                        status_pill(format!("{} 孤儿", row.orphan_count), BadgeTone::Warn, p)
                    } else if row.running_count > 0 {
                        status_pill(format!("运行 {}", row.running_count), BadgeTone::Pass, p)
                    } else {
                        status_pill("未运行", BadgeTone::Muted, p)
                    })
                    .child(
                        action_button(
                            gpui::ElementId::Name(format!("overview-kill-{}", row.id).into()),
                            "清理",
                            if can_clean {
                                ButtonKind::Danger
                            } else {
                                ButtonKind::Secondary
                            },
                            can_clean,
                            p,
                        )
                        .when(can_clean, |b| {
                            b.on_mouse_up(
                                MouseButton::Left,
                                cx.listener(move |_, _, _, cx| {
                                    ctrl_row.update(cx, |c, cx| {
                                        c.send_request(
                                            PipeRequest::ForceKillAgent {
                                                agent_id: Some(row_id.clone()),
                                                include_cli: row_is_cli,
                                            },
                                            Some(toast_msg),
                                            cx,
                                        );
                                    });
                                }),
                            )
                        }),
                    ),
            )
    });

    bento_card(p)
        .w_full()
        .p(px(16.))
        .gap(px(10.))
        .child(
            div()
                .flex()
                .flex_wrap()
                .items_center()
                .justify_between()
                .gap(px(8.))
                .child(
                    div()
                        .flex()
                        .flex_wrap()
                        .items_center()
                        .gap(px(8.))
                        .child(
                            div()
                                .text_size(px(13.5))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.text_primary))
                                .child("受管进程实况与一键清理"),
                        )
                        .child(status_pill(
                            format!("运行 {total_running} · 孤儿 {total_orphans}"),
                            if total_orphans > 0 {
                                BadgeTone::Warn
                            } else if total_running > 0 {
                                BadgeTone::Pass
                            } else {
                                BadgeTone::Muted
                            },
                            p,
                        )),
                )
                .child(
                    div()
                        .flex()
                        .flex_wrap()
                        .items_center()
                        .gap(px(8.))
                        .child(
                            action_button(
                                "overview-sweep",
                                "清理孤儿进程",
                                ButtonKind::Secondary,
                                connected && !busy,
                                p,
                            )
                            .when(connected && !busy, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_sweep.update(cx, |c, cx| {
                                            c.send_request(
                                                PipeRequest::SweepOrphans,
                                                Some("已完成受管孤儿进程扫描与清理"),
                                                cx,
                                            );
                                        });
                                    }),
                                )
                            }),
                        )
                        .child(
                            action_button(
                                "overview-kill-all",
                                "× 一键全清进程",
                                ButtonKind::Danger,
                                connected && !busy && any_active,
                                p,
                            )
                            .when(connected && !busy && any_active, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_kill_all.update(cx, |c, cx| {
                                            c.send_request(
                                                PipeRequest::ForceKillAgent {
                                                    agent_id: None,
                                                    include_cli: true,
                                                },
                                                Some("已终止全部受管桌面端与 CLI 进程"),
                                                cx,
                                            );
                                        });
                                    }),
                                )
                            }),
                        )
                        .child(
                            action_button(
                                "overview-lockdown-toggle",
                                if lockdown_manual {
                                    "解除手动封锁"
                                } else {
                                    "紧急封锁出站"
                                },
                                if lockdown_manual {
                                    ButtonKind::Primary
                                } else {
                                    ButtonKind::Secondary
                                },
                                connected && !busy,
                                p,
                            )
                            .when(connected && !busy, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        let next = !lockdown_manual;
                                        ctrl_lock.update(cx, |c, cx| {
                                            c.send_request(
                                                PipeRequest::SetManualLockdown { on: next },
                                                Some(if next {
                                                    "已开启手动紧急封锁，受管应用出站已阻断"
                                                } else {
                                                    "已解除手动封锁"
                                                }),
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
            div()
                .flex()
                .flex_col()
                .w_full()
                .min_w(px(0.))
                .gap(px(6.))
                .children(agent_rows),
        )
}

fn render_target_matrix(
    ctrl: Entity<AppController>,
    proj: &ConsoleProjection,
    connected: bool,
    busy: bool,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> Div {
    if proj.target_cards.is_empty() {
        return bento_card(p)
            .w_full()
            .p(px(14.))
            .gap(px(6.))
            .child(card_header(
                "AI 出口监测实况",
                if connected { "暂无启用目标" } else { "等待守护连接" },
                p,
            ))
            .child(
                div()
                    .text_size(px(12.))
                    .text_color(rgb(p.text_muted))
                    .child(if connected {
                        "当前没有启用的监控目标，请在「目标与白名单」中添加并保存。"
                    } else {
                        "后台守护未连接，无法核验各 AI 目标出口；Safe Launch 处于闭锁拦截态。"
                    }),
            );
    }

    let mut grid_rows: Vec<Div> = Vec::new();
    for chunk in proj.target_cards.chunks(3) {
        let mut row = div().flex().w_full().min_w(px(0.)).gap(px(12.));
        for card in chunk {
            let ctrl_r = ctrl.clone();
            let tid = card.id.clone();
            let can_recheck = connected && !busy;

            row = row.child(
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
                            .gap(px(6.))
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .flex_1()
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
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap(px(4.))
                                    .child(status_pill(card.state_label.clone(), card.badge_tone, p))
                                    .child({
                                        let mut btn = div()
                                            .id(gpui::ElementId::Name(
                                                format!("target-recheck-{}", card.id).into(),
                                            ))
                                            .flex_shrink_0()
                                            .w(px(22.))
                                            .h(px(22.))
                                            .rounded(px(6.))
                                            .bg(rgb(p.inset_bg))
                                            .border_1()
                                            .border_color(rgb(p.inset_border))
                                            .flex()
                                            .items_center()
                                            .justify_center()
                                            .text_size(px(11.))
                                            .text_color(rgb(if can_recheck {
                                                p.text_secondary
                                            } else {
                                                p.text_muted
                                            }))
                                            .child("↻");
                                        if can_recheck {
                                            let hover = p.sidebar_hover_bg;
                                            btn = btn
                                                .cursor_pointer()
                                                .hover(move |s| s.bg(rgb(hover)))
                                                .on_mouse_up(
                                                    MouseButton::Left,
                                                    cx.listener(move |_, _, _, cx| {
                                                        ctrl_r.update(cx, |c, cx| {
                                                            c.send_request(
                                                                PipeRequest::RecheckNow {
                                                                    target_id: Some(tid.clone()),
                                                                },
                                                                Some("已触发单目标出口复检"),
                                                                cx,
                                                            );
                                                        });
                                                    }),
                                                );
                                        }
                                        btn
                                    }),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .items_baseline()
                            .justify_between()
                            .gap(px(6.))
                            .child(
                                mono_tabular(card.ip_display.clone())
                                    .flex_1()
                                    .min_w(px(0.))
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
                            .w_full()
                            .px(px(8.))
                            .py(px(5.))
                            .truncate()
                            .text_size(px(10.5))
                            .text_color(rgb(p.text_muted))
                            .child(format!("命中规则：{}", card.matched_rule)),
                    ),
            );
        }
        // Keep column width stable when last chunk has < 3 cards
        for _ in chunk.len()..3 {
            row = row.child(div().flex_1().flex_basis(px(0.)).min_w(px(0.)));
        }
        grid_rows.push(row);
    }

    div()
        .flex()
        .flex_col()
        .w_full()
        .min_w(px(0.))
        .gap(px(12.))
        .children(grid_rows)
}

fn render_timeline_card(
    ctrl: Entity<AppController>,
    proj: &ConsoleProjection,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> Div {
    let bars = proj.timeline_bars.iter().map(|bar| {
        let ctrl_b = ctrl.clone();
        let idx = bar.index;
        let color = match bar.status {
            TimelineStatus::Pass => p.badge_pass.dot,
            TimelineStatus::Warn => p.badge_warn.dot,
            TimelineStatus::Fail => p.badge_fail.dot,
            TimelineStatus::Empty => p.inset_border,
        };
        let height_px = match bar.status {
            TimelineStatus::Empty => 10.0,
            TimelineStatus::Pass => (16.0 + (bar.total_checks.min(12) as f32) * 2.0).min(40.0),
            TimelineStatus::Warn => 32.0,
            TimelineStatus::Fail => 42.0,
        };
        div()
            .id(gpui::ElementId::Name(format!("ov-tl-{idx}").into()))
            .flex_1()
            .flex_basis(px(0.))
            .min_w(px(2.))
            .h(px(height_px))
            .rounded(px(3.))
            .bg(rgb(color))
            .when(bar.selected, |d| d.border_1().border_color(rgb(p.text_primary)))
            .cursor_pointer()
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(move |_, _, _, cx| {
                    ctrl_b.update(cx, |c, cx| {
                        c.select_timeline_bucket(idx, true, cx);
                    });
                }),
            )
    });

    bento_card(p)
        .flex_1()
        .flex_basis(px(0.))
        .min_w(px(0.))
        .p(px(14.))
        .gap(px(10.))
        .child(card_header("24 小时防护轨迹", "点击柱段查看审计", p))
        .child(
            inset_box(p)
                .w_full()
                .flex_row()
                .items_end()
                .h(px(58.))
                .px(px(8.))
                .py(px(8.))
                .gap(px(2.))
                .children(bars),
        )
        .child(
            div()
                .w_full()
                .text_size(px(11.5))
                .line_height(px(16.))
                .text_color(rgb(p.text_secondary))
                .child(proj.selected_bucket_summary.clone()),
        )
}

fn render_self_check_card(proj: &ConsoleProjection, p: &ThemePalette) -> Div {
    let rows = proj.self_checks.iter().map(|item| {
        let tone = match item.status {
            SelfCheckStatus::Healthy => BadgeTone::Pass,
            SelfCheckStatus::Degraded => BadgeTone::Fail,
            SelfCheckStatus::Disabled | SelfCheckStatus::Unsupported => BadgeTone::Warn,
            SelfCheckStatus::Unknown => BadgeTone::Muted,
        };
        inset_box(p)
            .w_full()
            .flex_row()
            .items_center()
            .justify_between()
            .px(px(10.))
            .py(px(7.))
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
                            .text_size(px(12.))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(rgb(p.text_primary))
                            .child(item.name.clone()),
                    )
                    .child(
                        div()
                            .w_full()
                            .text_size(px(10.5))
                            .line_height(px(15.))
                            .text_color(rgb(p.text_muted))
                            .child(item.detail.clone()),
                    ),
            )
            .child(status_pill(item.status.label(), tone, p))
    });

    bento_card(p)
        .flex_1()
        .flex_basis(px(0.))
        .min_w(px(0.))
        .p(px(14.))
        .gap(px(8.))
        .child(card_header("防线健康自检", "核心守护链路", p))
        .child(
            div()
                .flex()
                .flex_col()
                .w_full()
                .min_w(px(0.))
                .gap(px(6.))
                .children(rows),
        )
}

fn metric_chip(label: &'static str, value: usize, color: u32, p: &ThemePalette) -> Div {
    div()
        .flex()
        .flex_shrink_0()
        .whitespace_nowrap()
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
