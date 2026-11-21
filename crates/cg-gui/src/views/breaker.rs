//! Mode B — Frost Ceramic `熔断与防火墙` view.
//!
//! 2 sub-tabs:
//! - `策略与开关` (`BreakerSubTab::Rules`): CutMode + guarded agent chips, manual emergency lockdown,
//!   2×3 automation rule grid, and 2-column plain-language guide.
//! - `防线与进程实况` (`BreakerSubTab::Live`): 5 managed AI apps with brand icons, live process/orphan/rule
//!   counts, quick cleanup controls, and 3-column guide.

use crate::app::{AppController, BreakerSubTab, ConsoleWindowView};
use crate::assets::{brand_icon, ui_icon};
use crate::protocol::{CUT_MODES, PipeRequest};
use crate::state::ConsoleProjection;
use crate::theme::ThemePalette;
use crate::views::shared::page_guide_card;
use crate::widgets::controls::{
    ButtonKind, action_button, bento_card, mono_tabular, segmented_capsule_item,
    segmented_capsule_track, subtab_bar, subtab_item, toggle_switch,
};
use gpui::{Context, Div, Entity, FontWeight, MouseButton, div, prelude::*, px, rgb, rgba};

pub fn render_breaker_page(
    ctrl: Entity<AppController>,
    proj: &ConsoleProjection,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> Div {
    let ctrl_r = ctrl.read(cx);
    let snap = ctrl_r.snapshot.clone();
    let busy = ctrl_r.busy_action;
    let connected = ctrl_r.connected;
    let tab = ctrl_r.breaker_tab;
    let cfg = snap.as_ref().map(|s| s.config.clone()).unwrap_or_default();
    let lockdown_manual = snap.as_ref().is_some_and(|s| s.lockdown_manual);
    let tripped = snap.as_ref().is_some_and(|s| s.is_tripped());
    let lock_active = tripped || lockdown_manual;
    let can_act = connected && !busy;

    let total_orphans: usize = proj.agent_statuses.iter().map(|a| a.orphan_count).sum();
    let total_rules: usize = proj.agent_statuses.iter().map(|a| a.firewall_rules).sum();

    let ctrl_t_rules = ctrl.clone();
    let ctrl_t_live = ctrl.clone();
    let tabs = div().flex().items_center().child(
        subtab_bar(p)
            .child(
                subtab_item(
                    "br-tab-rules",
                    "策略与开关",
                    tab == BreakerSubTab::Rules,
                    None,
                    None,
                    p,
                )
                .on_mouse_up(
                    MouseButton::Left,
                    cx.listener(move |_, _, _, cx| {
                        ctrl_t_rules.update(cx, |c, cx| {
                            c.breaker_tab = BreakerSubTab::Rules;
                            cx.notify();
                        });
                    }),
                ),
            )
            .child(
                subtab_item(
                    "br-tab-live",
                    "防线与进程实况",
                    tab == BreakerSubTab::Live,
                    (total_orphans > 0).then_some(p.badge_warn.dot),
                    None,
                    p,
                )
                .on_mouse_up(
                    MouseButton::Left,
                    cx.listener(move |_, _, _, cx| {
                        ctrl_t_live.update(cx, |c, cx| {
                            c.breaker_tab = BreakerSubTab::Live;
                            cx.notify();
                        });
                    }),
                ),
            ),
    );

    let body = match tab {
        BreakerSubTab::Rules => {
            let cut_items = CUT_MODES.into_iter().map(|mode| {
                let active = cfg.cut_mode == mode;
                let ctrl_c = ctrl.clone();
                let mode_lbl = match mode {
                    crate::protocol::CutMode::Off => "仅应用级隔离",
                    _ => "全局防火墙断网",
                };
                segmented_capsule_item(
                    gpui::ElementId::Name(format!("cut-{mode:?}").into()),
                    mode_lbl,
                    active,
                    p,
                )
                .when(can_act, |item| {
                    item.on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |_, _, _, cx| {
                            ctrl_c.update(cx, |c, cx| {
                                c.save_config_patch(
                                    move |x| x.cut_mode = mode,
                                    "全局断网档位已更新",
                                    cx,
                                );
                            });
                        }),
                    )
                })
            });

            let agent_chips = [
                ("claude", "Claude 桌面版"),
                ("chatgpt", "ChatGPT / Codex"),
                ("antigravity", "反重力 IDE"),
            ]
            .into_iter()
            .map(|(aid, lbl)| {
                let on = cfg.guarded_agents.iter().any(|a| a == aid);
                let ctrl_ag = ctrl.clone();
                let bg = if on { p.primary_btn_bg } else { p.inset_bg };
                let fg = if on {
                    p.primary_btn_text
                } else {
                    p.text_secondary
                };
                let bdr = if on { p.primary_btn_bg } else { p.card_border };
                div()
                    .id(gpui::ElementId::Name(format!("br-agent-{aid}").into()))
                    .flex()
                    .items_center()
                    .gap(px(5.))
                    .h(px(27.))
                    .px(px(10.))
                    .rounded(px(8.))
                    .bg(rgb(bg))
                    .border_1()
                    .border_color(rgb(bdr))
                    .text_size(px(11.5))
                    .font_weight(FontWeight::MEDIUM)
                    .text_color(rgb(fg))
                    .when(on, |chip| chip.child(ui_icon("icons/ui/check.svg", 11.5, fg)))
                    .child(lbl)
                    .when(can_act, |chip| {
                        chip.cursor_pointer().on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |_, _, _, cx| {
                                ctrl_ag.update(cx, |c, cx| c.toggle_agent_guarded(aid, cx));
                            }),
                        )
                    })
            });

            let left_top = bento_card(p)
                .flex_1()
                .flex_basis(px(0.))
                .px(px(16.))
                .py(px(14.))
                .justify_between()
                .gap(px(12.))
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
                                        .child("全局断网档位与受管对象"),
                                )
                                .child(
                                    div()
                                        .text_size(px(11.))
                                        .text_color(rgb(p.text_muted))
                                        .child("支持无损恢复"),
                                ),
                        )
                        .child(segmented_capsule_track(p).children(cut_items)),
                )
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .gap(px(6.))
                        .child(
                            div()
                                .text_size(px(11.))
                                .text_color(rgb(p.text_muted))
                                .child("启用熔断隔离守护的桌面应用"),
                        )
                        .child(div().flex().flex_wrap().gap(px(6.)).children(agent_chips)),
                );

            let ctrl_lock_toggle = ctrl.clone();
            let ctrl_disarm = ctrl.clone();
            let right_top = bento_card(p)
                .flex_1()
                .flex_basis(px(0.))
                .px(px(16.))
                .py(px(14.))
                .justify_between()
                .gap(px(10.))
                .when(lock_active, |card| {
                    card.bg(rgba(p.hero_tripped.bg))
                        .border_color(rgba(p.hero_tripped.border))
                })
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .gap(px(6.))
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
                                        .child("手动紧急封锁"),
                                )
                                .child(
                                    div()
                                        .text_size(px(11.))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(if lock_active {
                                            p.badge_fail.text
                                        } else {
                                            p.badge_pass.text
                                        }))
                                        .child(if lockdown_manual {
                                            "● 手动封锁生效中"
                                        } else if tripped {
                                            "● 自动熔断隔离中"
                                        } else {
                                            "● 待命放行"
                                        }),
                                ),
                        )
                        .child(
                            div()
                                .text_size(px(11.5))
                                .line_height(px(17.))
                                .text_color(rgb(p.text_secondary))
                                .child("手动封锁拥有独立生命周期，不会被下一轮自动巡检覆盖；确认线路安全后可随时一键解除封锁。"),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .flex_wrap()
                        .items_center()
                        .gap(px(8.))
                        .child(
                            action_button(
                                "br-lock-toggle",
                                if lockdown_manual {
                                    "解除手动封锁"
                                } else {
                                    "立即封锁出站"
                                },
                                if lockdown_manual {
                                    ButtonKind::Primary
                                } else {
                                    ButtonKind::Danger
                                },
                                can_act,
                                p,
                            )
                            .when(can_act, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        let next = !lockdown_manual;
                                        ctrl_lock_toggle.update(cx, |c, cx| {
                                            c.send_request(
                                                PipeRequest::SetManualLockdown { on: next },
                                                Some(if next {
                                                    "已手动开启应用出站封锁"
                                                } else {
                                                    "已解除手动封锁"
                                                }),
                                                cx,
                                            );
                                        });
                                    }),
                                )
                            }),
                        )
                        .child(
                            action_button(
                                "br-disarm-all",
                                "解除防护并还原",
                                ButtonKind::Secondary,
                                can_act,
                                p,
                            )
                            .when(can_act, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_disarm.update(cx, |c, cx| {
                                            c.send_request(
                                                PipeRequest::DisarmAndRestoreFlowB {
                                                    reason: Some("用户从熔断页手动解除防护并还原".into()),
                                                },
                                                Some("已解除全部防线规则并还原原始环境"),
                                                cx,
                                            );
                                        });
                                    }),
                                )
                            }),
                        ),
                );

            let make_rule_cell = |id: &'static str,
                                  title: &'static str,
                                  sub: &'static str,
                                  on: bool,
                                  bottom_border: bool,
                                  ctrl_c: Entity<AppController>,
                                  mutate: fn(&mut crate::protocol::Config, bool),
                                  cx: &mut Context<ConsoleWindowView>|
             -> Div {
                let mut cell = div()
                    .flex()
                    .flex_1()
                    .flex_basis(px(0.))
                    .min_w(px(0.))
                    .items_center()
                    .justify_between()
                    .gap(px(12.))
                    .py(px(9.5));
                if bottom_border {
                    cell = cell.border_b_1().border_color(rgb(p.card_border));
                }
                cell.child(
                    div()
                        .flex()
                        .flex_col()
                        .min_w(px(0.))
                        .flex_1()
                        .gap(px(2.))
                        .child(
                            div()
                                .text_size(px(12.))
                                .font_weight(FontWeight::MEDIUM)
                                .text_color(rgb(p.text_primary))
                                .child(title),
                        )
                        .child(
                            div()
                                .text_size(px(10.5))
                                .text_color(rgb(p.text_muted))
                                .child(sub),
                        ),
                )
                .child(toggle_switch(id, on, can_act, p).when(can_act, |sw| {
                    sw.on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |_, _, _, cx| {
                            let next = !on;
                            ctrl_c.update(cx, |c, cx| {
                                c.save_config_patch(move |x| mutate(x, next), "防线规则已更新", cx);
                            });
                        }),
                    )
                }))
            };

            let rules_card = bento_card(p)
                .w_full()
                .px(px(17.))
                .py(px(13.))
                .gap(px(4.))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .pb(px(4.))
                        .child(
                            div()
                                .text_size(px(12.5))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.text_primary))
                                .child("自动化处置策略（6 项防线规则）"),
                        )
                        .child(
                            div()
                                .text_size(px(11.))
                                .text_color(rgb(p.text_muted))
                                .child("更改即时生效"),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .flex_row()
                        .gap(px(22.))
                        .child(make_rule_cell(
                            "br-kill",
                            "熔断时终止桌面端进程",
                            "多重校验防误杀无关程序",
                            cfg.kill_on_fail,
                            true,
                            ctrl.clone(),
                            |x, v| x.kill_on_fail = v,
                            cx,
                        ))
                        .child(make_rule_cell(
                            "br-kill-cli",
                            "熔断同步终止 CLI 会话",
                            "覆盖 Claude Code / Codex CLI",
                            cfg.kill_cli_on_fail,
                            true,
                            ctrl.clone(),
                            |x, v| x.kill_cli_on_fail = v,
                            cx,
                        )),
                )
                .child(
                    div()
                        .flex()
                        .flex_row()
                        .gap(px(22.))
                        .child(make_rule_cell(
                            "br-quar",
                            "应用级防火墙隔离",
                            "写入精准出站阻断并自动回读核验",
                            cfg.quarantine_on_fail,
                            true,
                            ctrl.clone(),
                            |x, v| x.quarantine_on_fail = v,
                            cx,
                        ))
                        .child(make_rule_cell(
                            "br-access",
                            "接入路径强校验",
                            "代理关闭且无 TUN 时立即封锁",
                            cfg.enforce_access_path,
                            true,
                            ctrl.clone(),
                            |x, v| x.enforce_access_path = v,
                            cx,
                        )),
                )
                .child(
                    div()
                        .flex()
                        .flex_row()
                        .gap(px(22.))
                        .child(make_rule_cell(
                            "br-sweep",
                            "退出后自动清扫残留孤儿",
                            "应用关闭后清理无主渲染子进程",
                            cfg.sweep_on_exit,
                            false,
                            ctrl.clone(),
                            |x, v| x.sweep_on_exit = v,
                            cx,
                        ))
                        .child(make_rule_cell(
                            "br-lock-auto",
                            "未接入代理兜底封锁",
                            "代理与 TUN 均不可用时自动封锁",
                            cfg.lockdown_on_uncovered,
                            false,
                            ctrl.clone(),
                            |x, v| x.lockdown_on_uncovered = v,
                            cx,
                        )),
                );

            let guide = page_guide_card(
                "",
                "",
                &[
                    (
                        "断网档位区别",
                        "「仅应用级隔离」只拦截受管 AI 客户端出站，不影响浏览器和日常上网；「全局防火墙断网」用于高敏场景，会暂停除代理内核外全部公网出站。",
                    ),
                    (
                        "无损恢复保障",
                        "无论自动熔断还是手动封锁，都可通过总览「复查并解封」或上方「解除防护并还原」秒级恢复全部网络与防火墙原始状态。",
                    ),
                ],
                p,
            );

            div()
                .flex()
                .flex_col()
                .w_full()
                .gap(px(11.))
                .child(
                    div()
                        .flex()
                        .flex_row()
                        .w_full()
                        .gap(px(11.))
                        .child(left_top)
                        .child(right_top),
                )
                .child(rules_card)
                .child(guide)
        }

        BreakerSubTab::Live => {
            let ctrl_sweep = ctrl.clone();
            let ctrl_force_all = ctrl.clone();
            let row_count = proj.agent_statuses.len();

            let rows = proj.agent_statuses.iter().enumerate().map(|(idx, row)| {
                let can_kill = can_act && (row.running_count > 0 || row.orphan_count > 0);
                let rid = row.id.clone();
                let is_cli = row.kind.contains("CLI");
                let ctrl_k = ctrl.clone();
                let sub_line = if row.orphan_count > 0 {
                    format!(
                        "运行进程 {} · 孤儿残留 {} · 防火墙隔离规则 {} 条",
                        row.running_count, row.orphan_count, row.firewall_rules
                    )
                } else {
                    format!(
                        "运行进程 {} · 防火墙隔离规则 {} 条",
                        row.running_count, row.firewall_rules
                    )
                };

                let mut r = div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .py(px(9.))
                    .gap(px(10.));
                if idx + 1 < row_count {
                    r = r.border_b_1().border_color(rgb(p.card_border));
                }
                r.child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(10.))
                        .min_w(px(0.))
                        .flex_1()
                        .child(brand_icon(&row.id, 24.0, 6.0, p.is_dark))
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .min_w(px(0.))
                                .gap(px(2.))
                                .child(
                                    div()
                                        .flex()
                                        .items_center()
                                        .gap(px(7.))
                                        .child(
                                            div()
                                                .text_size(px(12.5))
                                                .font_weight(FontWeight::SEMIBOLD)
                                                .text_color(rgb(p.text_primary))
                                                .child(row.name.clone()),
                                        )
                                        .child(
                                            div()
                                                .px(px(6.))
                                                .py(px(1.))
                                                .rounded(px(5.))
                                                .bg(rgb(p.inset_bg))
                                                .text_size(px(10.))
                                                .text_color(rgb(p.text_muted))
                                                .child(if row.installed {
                                                    "已安装"
                                                } else {
                                                    "未安装"
                                                }),
                                        ),
                                )
                                .child(
                                    mono_tabular(sub_line)
                                        .text_size(px(11.))
                                        .text_color(rgb(if row.orphan_count > 0 {
                                            p.badge_warn.text
                                        } else {
                                            p.text_muted
                                        })),
                                ),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .flex_shrink_0()
                        .gap(px(12.))
                        .child(
                            div()
                                .text_size(px(11.5))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(if row.quarantined {
                                    p.badge_fail.text
                                } else {
                                    p.badge_pass.text
                                }))
                                .child(if row.quarantined {
                                    "● 已防火墙隔离"
                                } else {
                                    "● 正常放行"
                                }),
                        )
                        .child(
                            action_button(
                                gpui::ElementId::Name(format!("br-live-kill-{}", row.id).into()),
                                "清理",
                                ButtonKind::Secondary,
                                can_kill,
                                p,
                            )
                            .h(px(25.))
                            .px(px(10.))
                            .text_size(px(11.))
                            .when(can_kill, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        let id = rid.clone();
                                        ctrl_k.update(cx, |c, cx| {
                                            c.send_request(
                                                PipeRequest::ForceKillAgent {
                                                    agent_id: Some(id),
                                                    include_cli: true,
                                                },
                                                Some(if is_cli {
                                                    "已清理该 CLI 会话及孤儿残留"
                                                } else {
                                                    "已清理该受管应用进程树及孤儿残留"
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

            let live_card = bento_card(p)
                .w_full()
                .px(px(17.))
                .py(px(14.))
                .gap(px(8.))
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
                                        .text_size(px(12.5))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(p.text_primary))
                                        .child("受管应用防线与进程实况"),
                                )
                                .child(
                                    mono_tabular(format!(
                                        "当前隔离规则 {total_rules} 条 · 孤儿残留 {total_orphans} 个"
                                    ))
                                    .text_size(px(11.))
                                    .text_color(rgb(p.text_muted)),
                                ),
                        )
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap(px(7.))
                                .child(
                                    action_button(
                                        "br-live-sweep",
                                        "一键清孤儿",
                                        ButtonKind::Secondary,
                                        can_act,
                                        p,
                                    )
                                    .h(px(28.))
                                    .px(px(10.))
                                    .when(can_act, |b| {
                                        b.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                ctrl_sweep.update(cx, |c, cx| {
                                                    c.send_request(
                                                        PipeRequest::SweepOrphans,
                                                        Some("孤儿进程清扫完成"),
                                                        cx,
                                                    );
                                                });
                                            }),
                                        )
                                    }),
                                )
                                .child(
                                    action_button(
                                        "br-live-kill-all",
                                        "全清受管进程",
                                        ButtonKind::Danger,
                                        can_act,
                                        p,
                                    )
                                    .h(px(28.))
                                    .px(px(11.))
                                    .when(can_act, |b| {
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
                                    }),
                                ),
                        ),
                )
                .child(div().flex().flex_col().children(rows));

            let guide = page_guide_card(
                "应用级隔离与进程治理说明",
                "三重校验防误杀 · 无残留解封",
                &[
                    (
                        "1. 防火墙精准隔离",
                        "触发熔断后仅封锁上方受管 AI 应用的出站通信，浏览器和其他办公软件正常上网；复查达标后会自动删除对应规则。",
                    ),
                    (
                        "2. 什么是「孤儿残留」？",
                        "桌面端关闭窗口后，部分后台渲染或辅助进程可能仍驻留内存并悄悄联网。点击「一键清孤儿」即可无感清理。",
                    ),
                    (
                        "3. 一键全清适用场景",
                        "切换代理线路前或紧急排障时，可使用「全清受管进程」一次性结束全部受管桌面端与终端会话，避免旧连接残留。",
                    ),
                ],
                p,
            );

            div()
                .flex()
                .flex_col()
                .w_full()
                .gap(px(11.))
                .child(live_card)
                .child(guide)
        }
    };

    div()
        .flex()
        .flex_col()
        .w_full()
        .min_w(px(0.))
        .gap(px(10.))
        .child(tabs)
        .child(body)
}
