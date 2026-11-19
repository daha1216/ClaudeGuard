//! Mode B — `熔断与防火墙` view (circuit-breaker strategy, guarded agents, manual lockdown).

use crate::app::{AppController, ConsoleWindowView};
use crate::protocol::{CUT_MODES, PipeRequest};
use crate::state::ConsoleProjection;
use crate::theme::{BadgeTone, ThemePalette};
use crate::views::shared::switch_row;
use crate::widgets::controls::{
    ButtonKind, action_button, bento_card, card_header, inset_box, segmented_capsule_item,
    segmented_capsule_track, status_pill,
};
use gpui::{Context, Div, Entity, FontWeight, MouseButton, div, prelude::*, px, rgb};
/// Sub-view: `熔断与防火墙`
pub fn render_breaker_page(
    ctrl: Entity<AppController>,
    proj: &ConsoleProjection,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> Div {
    let snap = ctrl.read(cx).snapshot.clone();
    let busy = ctrl.read(cx).busy_action;
    let connected = ctrl.read(cx).connected;
    let cfg = snap.as_ref().map(|s| s.config.clone()).unwrap_or_default();
    let lockdown_manual = snap.as_ref().is_some_and(|s| s.lockdown_manual);

    let cut_items = CUT_MODES.into_iter().map(|mode| {
        let active = cfg.cut_mode == mode;
        let ctrl_c = ctrl.clone();
        segmented_capsule_item(
            gpui::ElementId::Name(format!("cut-{}", mode.label()).into()),
            mode.label(),
            active,
            p,
        )
        .when(connected && !busy, |item| {
            item.on_mouse_up(
                MouseButton::Left,
                cx.listener(move |_, _, _, cx| {
                    ctrl_c.update(cx, |c, cx| {
                        c.save_config_patch(move |cfg| cfg.cut_mode = mode, "断网档位已更新", cx);
                    });
                }),
            )
        })
    });

    let ctrl_kill = ctrl.clone();
    let ctrl_kill_cli = ctrl.clone();
    let ctrl_quar = ctrl.clone();
    let ctrl_access = ctrl.clone();
    let ctrl_sweep_cfg = ctrl.clone();
    let ctrl_lock_auto = ctrl.clone();
    let ctrl_lock_on = ctrl.clone();
    let ctrl_lock_off = ctrl.clone();
    let ctrl_sweep_now = ctrl.clone();
    let ctrl_force_all = ctrl.clone();

    let ctrl_ag_claude = ctrl.clone();
    let ctrl_ag_chatgpt = ctrl.clone();
    let ctrl_ag_ag = ctrl.clone();

    let guarded_claude = cfg.guarded_agents.iter().any(|a| a == "claude");
    let guarded_chatgpt = cfg.guarded_agents.iter().any(|a| a == "chatgpt");
    let guarded_ag = cfg.guarded_agents.iter().any(|a| a == "antigravity");

    let agent_rows = proj.agent_statuses.iter().map(|row| {
        let can_row_kill = connected && !busy && (row.running_count > 0 || row.orphan_count > 0);
        let row_id = row.id.clone();
        let row_is_cli = row.kind.contains("CLI");
        let ctrl_row = ctrl.clone();
        let sub_line = if row.orphan_count > 0 {
            format!(
                "运行进程 {} · 孤儿 {} · 防火墙隔离规则 {}",
                row.running_count, row.orphan_count, row.firewall_rules
            )
        } else {
            format!(
                "运行进程 {} · 防火墙隔离规则 {}",
                row.running_count, row.firewall_rules
            )
        };

        inset_box(p)
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
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(8.))
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
                            )
                            .child(
                                div()
                                    .px(px(5.))
                                    .py(px(1.))
                                    .rounded(px(4.))
                                    .bg(rgb(p.cc_pill_bg))
                                    .text_size(px(10.))
                                    .text_color(rgb(if row.installed {
                                        p.cc_pill_text
                                    } else {
                                        p.text_muted
                                    }))
                                    .child(if row.installed {
                                        "已安装"
                                    } else {
                                        "未安装"
                                    }),
                            )
                            .when(row.orphan_count > 0, |hdr| {
                                hdr.child(
                                    div()
                                        .text_size(px(10.5))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(p.badge_warn.text))
                                        .child(format!("· 孤儿 {}", row.orphan_count)),
                                )
                            }),
                    )
                    .child(
                        div()
                            .text_size(px(11.))
                            .text_color(rgb(p.text_muted))
                            .child(sub_line),
                    ),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .flex_shrink_0()
                    .gap(px(8.))
                    .child(status_pill(
                        if row.quarantined {
                            "已防火墙隔离"
                        } else {
                            "正常放行"
                        },
                        if row.quarantined {
                            BadgeTone::Fail
                        } else {
                            BadgeTone::Pass
                        },
                        p,
                    ))
                    .child(
                        action_button(
                            gpui::ElementId::Name(format!("br-row-kill-{}", row.id).into()),
                            "全清",
                            ButtonKind::Secondary,
                            can_row_kill,
                            p,
                        )
                        .h(px(26.))
                        .px(px(10.))
                        .when(can_row_kill, |b| {
                            b.on_mouse_up(
                                MouseButton::Left,
                                cx.listener(move |_, _, _, cx| {
                                    let id = row_id.clone();
                                    ctrl_row.update(cx, |c, cx| {
                                        c.send_request(
                                            PipeRequest::ForceKillAgent {
                                                agent_id: Some(id),
                                                include_cli: true,
                                            },
                                            Some(if row_is_cli {
                                                "已全清该 CLI 会话与孤儿残留"
                                            } else {
                                                "已全清该受管应用进程树与孤儿残留"
                                            }),
                                            cx,
                                        );
                                    });
                                }),
                            )
                        }),
                    ),
            )
    });

    div()
        .flex()
        .flex_col()
        .gap(px(14.))
        .child(
            bento_card(p)
                .p(px(16.))
                .gap(px(12.))
                .child(card_header("熔断处置与隔离策略", "支持自动核验与无损恢复", p))
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
                                .flex_col()
                                .flex_1()
                                .min_w(px(220.))
                                .child(
                                    div()
                                        .text_size(px(12.5))
                                        .font_weight(FontWeight::MEDIUM)
                                        .text_color(rgb(p.text_primary))
                                        .child("全局断网档位"),
                                )
                                .child(
                                    div()
                                        .text_size(px(11.))
                                        .text_color(rgb(p.text_muted))
                                        .child("默认仅应用级隔离；开启全局断网后支持一键安全恢复与撤防回滚"),
                                ),
                        )
                        .child(segmented_capsule_track(p).children(cut_items)),
                )
                .child(switch_row(
                    "br-kill",
                    "熔断时终止受管桌面端进程",
                    "多重进程校验防止误杀无关程序（终端 CLI 策略由下方开关独立控制）",
                    cfg.kill_on_fail,
                    p,
                    cx.listener(move |_, _, _, cx| {
                        let next = !cfg.kill_on_fail;
                        ctrl_kill.update(cx, |c, cx| {
                            c.save_config_patch(move |x| x.kill_on_fail = next, "已更新", cx);
                        });
                    }),
                ))
                .child(switch_row(
                    "br-kill-cli",
                    "熔断时同步终止 Claude Code / Codex CLI 会话",
                    "开启后触发熔断时同步清理 Claude Code 与 Codex 命令行会话进程",
                    cfg.kill_cli_on_fail,
                    p,
                    cx.listener(move |_, _, _, cx| {
                        let next = !cfg.kill_cli_on_fail;
                        ctrl_kill_cli.update(cx, |c, cx| {
                            c.save_config_patch(move |x| x.kill_cli_on_fail = next, "已更新", cx);
                        });
                    }),
                ))
                .child(switch_row(
                    "br-quar",
                    "应用级防火墙隔离",
                    "触发熔断时写入精确出站/入站阻断规则并自动回读核验",
                    cfg.quarantine_on_fail,
                    p,
                    cx.listener(move |_, _, _, cx| {
                        let next = !cfg.quarantine_on_fail;
                        ctrl_quar.update(cx, |c, cx| {
                            c.save_config_patch(move |x| x.quarantine_on_fail = next, "已更新", cx);
                        });
                    }),
                ))
                .child(switch_row(
                    "br-access",
                    "接入路径强校验（防代理关闭后直连）",
                    "系统代理关闭且无活跃 TUN 虚拟网卡时立即触发防泄露封锁",
                    cfg.enforce_access_path,
                    p,
                    cx.listener(move |_, _, _, cx| {
                        let next = !cfg.enforce_access_path;
                        ctrl_access.update(cx, |c, cx| {
                            c.save_config_patch(move |x| x.enforce_access_path = next, "已更新", cx);
                        });
                    }),
                ))
                .child(switch_row(
                    "br-sweep",
                    "退出后自动清扫残留与孤儿进程",
                    "AI 桌面客户端关闭后自动清理无主渲染进程与孤儿后台子进程",
                    cfg.sweep_on_exit,
                    p,
                    cx.listener(move |_, _, _, cx| {
                        let next = !cfg.sweep_on_exit;
                        ctrl_sweep_cfg.update(cx, |c, cx| {
                            c.save_config_patch(move |x| x.sweep_on_exit = next, "已更新", cx);
                        });
                    }),
                ))
                .child(switch_row(
                    "br-lock-auto",
                    "未接入代理时自动兜底封锁出站",
                    "检测到系统代理与 TUN 均不可用时自动封锁受管应用出站",
                    cfg.lockdown_on_uncovered,
                    p,
                    cx.listener(move |_, _, _, cx| {
                        let next = !cfg.lockdown_on_uncovered;
                        ctrl_lock_auto.update(cx, |c, cx| {
                            c.save_config_patch(
                                move |x| x.lockdown_on_uncovered = next,
                                "已更新",
                                cx,
                            );
                        });
                    }),
                ))
                .child(switch_row(
                    "br-ag-claude",
                    "守护 Claude 桌面版",
                    "熔断时自动终止进程并写入应用级出站/入站防火墙隔离规则",
                    guarded_claude,
                    p,
                    cx.listener(move |_, _, _, cx| {
                        ctrl_ag_claude.update(cx, |c, cx| c.toggle_agent_guarded("claude", cx));
                    }),
                ))
                .child(switch_row(
                    "br-ag-chatgpt",
                    "守护 ChatGPT / Codex 桌面版",
                    "包含 Microsoft Store (MSIX) OpenAI.Codex 宿主应用",
                    guarded_chatgpt,
                    p,
                    cx.listener(move |_, _, _, cx| {
                        ctrl_ag_chatgpt.update(cx, |c, cx| c.toggle_agent_guarded("chatgpt", cx));
                    }),
                ))
                .child(switch_row(
                    "br-ag-antigravity",
                    "守护反重力桌面版 (Antigravity IDE)",
                    "熔断或手动封锁时一并隔离 IDE 网络出站",
                    guarded_ag,
                    p,
                    cx.listener(move |_, _, _, cx| {
                        ctrl_ag_ag.update(cx, |c, cx| c.toggle_agent_guarded("antigravity", cx));
                    }),
                )),
        )
        .child(
            bento_card(p)
                .p(px(16.))
                .gap(px(12.))
                .child(card_header(
                    "手动一键封锁与受管进程实况",
                    if lockdown_manual { "手动封锁生效中" } else { "待命" },
                    p,
                ))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap(px(10.))
                        .child(
                            div()
                                .flex_1()
                                .min_w(px(0.))
                                .text_size(px(12.))
                                .text_color(rgb(p.text_secondary))
                                .child("手动封锁拥有独立生命周期，不会被下一轮自动检测覆盖"),
                        )
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .flex_shrink_0()
                                .gap(px(8.))
                                .child({
                                    let can_sweep = connected && !busy;
                                    action_button(
                                        "br-sweep-now",
                                        "一键清孤儿",
                                        ButtonKind::Secondary,
                                        can_sweep,
                                        p,
                                    )
                                    .when(can_sweep, |b| {
                                        b.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                ctrl_sweep_now.update(cx, |c, cx| {
                                                    c.send_request(
                                                        PipeRequest::SweepOrphans,
                                                        Some("孤儿进程清扫完成"),
                                                        cx,
                                                    );
                                                });
                                            }),
                                        )
                                    })
                                })
                                .child({
                                    let can_force_all = connected && !busy;
                                    action_button(
                                        "br-force-kill-all",
                                        "一键全清受管进程",
                                        ButtonKind::Danger,
                                        can_force_all,
                                        p,
                                    )
                                    .when(can_force_all, |b| {
                                        b.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                ctrl_force_all.update(cx, |c, cx| {
                                                    c.send_request(
                                                        PipeRequest::ForceKillAgent {
                                                            agent_id: None,
                                                            include_cli: true,
                                                        },
                                                        Some("已全清全部受管进程与孤儿残留"),
                                                        cx,
                                                    );
                                                });
                                            }),
                                        )
                                    })
                                })
                                .child({
                                    let can_on = connected && !busy && !lockdown_manual;
                                    action_button(
                                        "br-lock-on",
                                        "封锁出站",
                                        ButtonKind::Danger,
                                        can_on,
                                        p,
                                    )
                                    .when(can_on, |b| {
                                        b.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                ctrl_lock_on.update(cx, |c, cx| {
                                                    c.send_request(
                                                        PipeRequest::SetManualLockdown { on: true },
                                                        Some("已手动开启应用出站封锁"),
                                                        cx,
                                                    );
                                                });
                                            }),
                                        )
                                    })
                                })
                                .child({
                                    let can_off = connected && !busy && lockdown_manual;
                                    action_button(
                                        "br-lock-off",
                                        "解除手动封锁",
                                        ButtonKind::Primary,
                                        can_off,
                                        p,
                                    )
                                    .when(can_off, |b| {
                                        b.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                ctrl_lock_off.update(cx, |c, cx| {
                                                    c.send_request(
                                                        PipeRequest::SetManualLockdown { on: false },
                                                        Some("已解除手动封锁"),
                                                        cx,
                                                    );
                                                });
                                            }),
                                        )
                                    })
                                }),
                        ),
                )
                .child(div().flex().flex_col().gap(px(6.)).children(agent_rows)),
        )
}


