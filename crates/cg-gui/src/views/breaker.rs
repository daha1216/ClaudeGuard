//! Mode B — Frost Ceramic `熔断与防火墙` view.
//!
//! 2 sub-tabs:
//! - `策略与开关` (`BreakerSubTab::Rules`): CutMode + guarded agent chips, manual emergency lockdown,
//!   2×3 automation rule grid, and 2-column plain-language guide.
//! - `防线与进程实况` (`BreakerSubTab::Live`): 5 managed AI apps with brand icons, live process/orphan/rule
//!   counts, quick cleanup controls, and 3-column guide.

use crate::app::{AppController, BreakerSubTab, ConsoleWindowView};
use crate::assets::{agent_icon_key, brand_icon_scaled, ui_icon};
use crate::motion::PageChoreo;
use crate::protocol::{CUT_MODES, FIREWALL_BACKENDS, FirewallBackendPref, Lifecycle, PipeRequest};
use crate::state::{ConsoleProjection, format_unix_hm, mask_wfp_event_ip};
use crate::theme::{BadgeTone, ThemePalette};
use crate::views::shared::{brand_family_rank, canonical_agent_label, page_guide_card};
use crate::widgets::controls::{
    ButtonKind, action_button, bento_card_bloom, inset_box, mono_tabular, offset_pane,
    segmented_capsule_item, segmented_capsule_track, status_dot, subtab_bar, subtab_item,
    toggle_switch, tone_tag,
};
use gpui::{Context, Div, Entity, FontWeight, MouseButton, div, prelude::*, px, rgb, rgba};

fn breaker_agent_label<'a>(id: &str, fallback: &'a str) -> &'a str {
    match id.to_ascii_lowercase().as_str() {
        "cursor" => "Cursor IDE",
        "windsurf" => "Windsurf IDE",
        "zed" => "Zed IDE",
        "trae" => "Trae IDE",
        "gemini" => "Gemini CLI",
        "aider" => "Aider CLI",
        _ => canonical_agent_label(id, fallback),
    }
}

fn breaker_agent_rank(id: &str) -> u8 {
    match id.to_ascii_lowercase().as_str() {
        "cursor" => 6,
        "windsurf" => 7,
        "zed" => 8,
        "trae" => 9,
        "gemini" => 11,
        "aider" => 12,
        _ => brand_family_rank(id),
    }
}

fn wfp_reason_label(reason: &str) -> &'static str {
    match reason {
        "direct_nic_bypass" => "直连网卡旁路",
        "boot_time_guard" => "开机防抢跑",
        "app_quarantine" => "熔断隔离阻断",
        "quic_shield" => "QUIC 护盾",
        "doh_shield" => "DoH/DNS 护盾",
        "ipv6_shield" => "IPv6 护盾",
        "panic_lockdown" => "紧急锁死",
        _ => "内核规则阻断",
    }
}

pub fn render_breaker_page(
    ctrl: Entity<AppController>,
    proj: &ConsoleProjection,
    choreo: PageChoreo,
    subtab_dx: f32,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> Div {
    let ctrl_r = ctrl.read(cx);
    let snap = ctrl_r.snapshot.clone();
    let busy = ctrl_r.busy_action;
    let connected = ctrl_r.connected;
    let tab = ctrl_r.breaker_tab;
    let cfg = snap.as_ref().map(|s| s.config.clone()).unwrap_or_default();
    let lifecycle = snap
        .as_ref()
        .map(|s| s.lifecycle)
        .unwrap_or(Lifecycle::Unconfigured);
    let lockdown_manual = snap.as_ref().is_some_and(|s| s.lockdown_manual);
    let tripped = snap.as_ref().is_some_and(|s| s.is_tripped());
    let lock_active = tripped || lockdown_manual;
    let can_act = connected && !busy;

    let lock_armed = ctrl_r.is_confirm_armed("br-lock");
    let disarm_armed = ctrl_r.is_confirm_armed("br-disarm");
    let live_kill_armed = ctrl_r.is_confirm_armed("br-live-kill-all");

    let monitor_only = ctrl_r.effective_toggle("br-monitor-only", cfg.monitor_only);
    let suppress_trip_when_ip_unchanged =
        ctrl_r.effective_toggle("br-ip-unchanged", cfg.suppress_trip_when_ip_unchanged);
    let kill_on_fail = ctrl_r.effective_toggle("br-kill", cfg.kill_on_fail);
    let kill_cli_on_fail = ctrl_r.effective_toggle("br-kill-cli", cfg.kill_cli_on_fail);
    let quarantine_on_fail = ctrl_r.effective_toggle("br-quar", cfg.quarantine_on_fail);
    let enforce_access_path = ctrl_r.effective_toggle("br-access", cfg.enforce_access_path);
    let sweep_on_exit = ctrl_r.effective_toggle("br-sweep", cfg.sweep_on_exit);
    let lockdown_on_uncovered = ctrl_r.effective_toggle("br-lock-auto", cfg.lockdown_on_uncovered);
    let wfp_boot_guard = ctrl_r.effective_toggle("br-wfp-boot", cfg.wfp_boot_guard);
    let privacy_mask = ctrl_r.privacy_mask;
    let wfp_filter = ctrl_r.wfp_agent_filter.clone();
    let wfp = snap.as_ref().map(|s| s.wfp.clone()).unwrap_or_default();

    let total_running: usize = proj.agent_statuses.iter().map(|a| a.running_count).sum();
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
                    crate::protocol::CutMode::Off => "应用级隔离",
                    _ => "全局断网",
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
                                    "断网档位已更新",
                                    cx,
                                );
                            });
                        }),
                    )
                })
            });

            let agent_chips = [
                ("claude", "Claude"),
                ("chatgpt", "ChatGPT / Codex"),
                ("antigravity", "Antigravity"),
                ("cursor", "Cursor"),
                ("windsurf", "Windsurf"),
                ("zed", "Zed"),
                ("trae", "Trae"),
            ]
            .into_iter()
            .map(|(aid, lbl)| {
                let on = cfg.guarded_agents.iter().any(|a| a == aid);
                let ctrl_ag = ctrl.clone();
                let bg = if on { p.accent_soft_bg } else { p.inset_bg };
                let fg = if on {
                    p.accent_soft_text
                } else {
                    p.text_secondary
                };
                let bdr = if on {
                    p.accent_soft_border
                } else {
                    p.card_border
                };
                let hov = p.sidebar_hover_bg;
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
                    .font_weight(if on {
                        FontWeight::SEMIBOLD
                    } else {
                        FontWeight::MEDIUM
                    })
                    .text_color(rgb(fg))
                    .when(on, |chip| {
                        chip.child(ui_icon("icons/ui/check.svg", 11.5, fg))
                    })
                    .child(lbl)
                    .when(can_act, |chip| {
                        chip.cursor_pointer()
                            .hover(move |s| if on { s.opacity(0.88) } else { s.bg(rgb(hov)) })
                            .active(|s| s.opacity(0.82))
                            .on_mouse_up(
                                MouseButton::Left,
                                cx.listener(move |_, _, _, cx| {
                                    ctrl_ag.update(cx, |c, cx| c.toggle_agent_guarded(aid, cx));
                                }),
                            )
                    })
            });
            let no_guarded_agents = cfg.guarded_agents.is_empty();

            let left_top = div()
                .flex_1()
                .flex_basis(px(0.))
                .min_w(px(0.))
                .flex()
                .child(
                    bento_card_bloom(p, 16., 14., choreo.tile(0, 0))
                        .flex_1()
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
                                                .child("断网档位与受管应用"),
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
                                        .child("受管桌面应用"),
                                )
                                .child(div().flex().flex_wrap().gap(px(6.)).children(agent_chips))
                                .when(no_guarded_agents, |col| {
                                    col.child(
                                        div()
                                            .text_size(px(10.5))
                                            .text_color(rgb(p.badge_warn.text))
                                            .child(
                                                "未勾选受管桌面应用，熔断时不会执行应用级隔离。",
                                            ),
                                    )
                                }),
                        ),
                );

            let ctrl_lock_toggle = ctrl.clone();
            let ctrl_disarm = ctrl.clone();
            let right_top = div()
                .flex_1()
                .flex_basis(px(0.))
                .min_w(px(0.))
                .flex()
                .child(
                    bento_card_bloom(p, 16., 14., choreo.tile(0, 1))
                        .flex_1()
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
                                                .flex()
                                                .items_center()
                                                .gap(px(5.5))
                                                .text_size(px(11.))
                                                .font_weight(FontWeight::SEMIBOLD)
                                                .text_color(rgb(if lock_active {
                                                    p.badge_fail.text
                                                } else {
                                                    p.text_primary
                                                }))
                                                .child(status_dot(
                                                    if lock_active {
                                                        p.badge_fail.dot
                                                    } else {
                                                        p.badge_pass.dot
                                                    },
                                                    5.5,
                                                ))
                                                .child(if lockdown_manual {
                                                    "手动封锁中"
                                                } else if tripped {
                                                    "已自动熔断"
                                                } else {
                                                    "正常放行"
                                                }),
                                        ),
                                )
                                .child(
                                    div()
                                        .text_size(px(11.5))
                                        .line_height(px(17.))
                                        .text_color(rgb(p.text_secondary))
                                        .child("手动封锁独立生效，不被自动巡检覆盖，确认安全后可随时解封。"),
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
                                        } else if lock_armed {
                                            "确认封锁出站"
                                        } else {
                                            "立即封锁出站"
                                        },
                                        if lockdown_manual {
                                            ButtonKind::Primary
                                        } else if lock_armed {
                                            ButtonKind::Danger
                                        } else {
                                            ButtonKind::DangerSoft
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
                                                    if !next
                                                        || c.arm_or_consume_confirm("br-lock", cx)
                                                    {
                                                        c.send_request(
                                                            PipeRequest::SetManualLockdown {
                                                                on: next,
                                                            },
                                                            Some(if next {
                                                                "已开启手动出站封锁"
                                                            } else {
                                                                "已解除手动封锁"
                                                            }),
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
                                        "br-disarm-all",
                                        if lifecycle == Lifecycle::Disarmed {
                                            "重新布防"
                                        } else if disarm_armed {
                                            "确认撤防并还原"
                                        } else {
                                            "解除防护并还原"
                                        },
                                        if lifecycle == Lifecycle::Disarmed {
                                            ButtonKind::Primary
                                        } else if disarm_armed {
                                            ButtonKind::DangerSoft
                                        } else {
                                            ButtonKind::Secondary
                                        },
                                        can_act,
                                        p,
                                    )
                                    .when(can_act, |b| {
                                        b.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                ctrl_disarm.update(cx, |c, cx| {
                                                    if lifecycle == Lifecycle::Disarmed {
                                                        c.send_request(
                                                            PipeRequest::Rearm,
                                                            Some("已重新布防并恢复守护"),
                                                            cx,
                                                        );
                                                    } else if c
                                                        .arm_or_consume_confirm("br-disarm", cx)
                                                    {
                                                        c.send_request(
                                                            PipeRequest::DisarmAndRestoreFlowB {
                                                                reason: Some(
                                                                    "用户从熔断页手动解除防护并还原"
                                                                        .into(),
                                                                ),
                                                            },
                                                            Some("已解除防护并还原网络与防火墙规则"),
                                                            cx,
                                                        );
                                                    }
                                                });
                                            }),
                                        )
                                    }),
                                ),
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
                    .py(px(7.5));
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
                                c.save_toggle_patch(
                                    id,
                                    next,
                                    move |x| mutate(x, next),
                                    "处置策略已更新",
                                    cx,
                                );
                            });
                        }),
                    )
                }))
            };

            let rules_card = div().w_full().flex().child(
                bento_card_bloom(p, 17., 13., choreo.tile(1, 0))
                    .flex_1()
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
                                    .child("自动处置策略"),
                            )
                            .child(
                                div()
                                    .text_size(px(11.))
                                    .text_color(rgb(p.text_muted))
                                    .child("8 项规则 · 即时生效"),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .gap(px(22.))
                            .child(make_rule_cell(
                                "br-monitor-only",
                                "仅监测不熔断",
                                "只持续巡检与告警，不自动杀进程或封锁",
                                monitor_only,
                                true,
                                ctrl.clone(),
                                |x, v| x.monitor_only = v,
                                cx,
                            ))
                            .child(make_rule_cell(
                                "br-ip-unchanged",
                                "出口 IP 不变时不熔断",
                                "梯子波动但出口 IP 未变时仅提示，不强杀",
                                suppress_trip_when_ip_unchanged,
                                true,
                                ctrl.clone(),
                                |x, v| x.suppress_trip_when_ip_unchanged = v,
                                cx,
                            )),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .gap(px(22.))
                            .child(make_rule_cell(
                                "br-kill",
                                "熔断终止桌面端",
                                "校验签名与路径，防止误杀",
                                kill_on_fail,
                                true,
                                ctrl.clone(),
                                |x, v| x.kill_on_fail = v,
                                cx,
                            ))
                            .child(make_rule_cell(
                                "br-kill-cli",
                                "熔断终止 CLI 会话",
                                "同步清理 Claude Code 与 Codex CLI",
                                kill_cli_on_fail,
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
                                "阻断受管应用出站并自动核验",
                                quarantine_on_fail,
                                true,
                                ctrl.clone(),
                                |x, v| x.quarantine_on_fail = v,
                                cx,
                            ))
                            .child(make_rule_cell(
                                "br-access",
                                "代理路径强校验",
                                "无代理且无 TUN 时立即封锁",
                                enforce_access_path,
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
                                "自动清扫孤儿进程",
                                "应用退出后回收无主后台进程",
                                sweep_on_exit,
                                false,
                                ctrl.clone(),
                                |x, v| x.sweep_on_exit = v,
                                cx,
                            ))
                            .child(make_rule_cell(
                                "br-lock-auto",
                                "无代理兜底封锁",
                                "代理与 TUN 均失效时自动封锁",
                                lockdown_on_uncovered,
                                false,
                                ctrl.clone(),
                                |x, v| x.lockdown_on_uncovered = v,
                                cx,
                            )),
                    ),
            );

            let guide = page_guide_card(
                "",
                "",
                &[
                    (
                        "防误杀与仅监测",
                        "默认开启「出口 IP 不变时不熔断」，梯子波动或反重力超时不会误杀进程；「仅监测不熔断」可只告警不拦截。",
                    ),
                    (
                        "档位与无损恢复",
                        "应用级仅拦截受管 AI 客户端，不影响日常上网；任何自动熔断或手动封锁均支持秒级无损还原。",
                    ),
                ],
                p,
            );

            let backend_items = FIREWALL_BACKENDS.into_iter().map(|bk| {
                let active = cfg.firewall_backend == bk;
                let ctrl_bk = ctrl.clone();
                let short_lbl = match bk {
                    FirewallBackendPref::AutoWfpFirst => "WFP 优先 (推荐)",
                    FirewallBackendPref::WfpOnly => "仅 WFP 内核",
                    FirewallBackendPref::ComLegacy => "COM 兼容",
                };
                segmented_capsule_item(
                    gpui::ElementId::Name(format!("wfp-bk-{bk:?}").into()),
                    short_lbl,
                    active,
                    p,
                )
                .when(can_act, |item| {
                    item.on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |_, _, _, cx| {
                            ctrl_bk.update(cx, |c, cx| {
                                c.save_config_patch(
                                    move |x| x.firewall_backend = bk,
                                    "WFP 防火墙引擎偏好已更新",
                                    cx,
                                );
                            });
                        }),
                    )
                })
            });

            let ctrl_boot = ctrl.clone();
            let wfp_engine_card = div().w_full().flex().child(
                bento_card_bloom(p, 17., 13., choreo.tile(1, 0))
                    .flex_1()
                    .gap(px(9.))
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
                                            .text_size(px(12.5))
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(rgb(p.text_primary))
                                            .child("WFP 内核过滤引擎 (0ms 防抢跑)"),
                                    )
                                    .child(tone_tag(
                                        if wfp.sublayer_registered && wfp.dynamic_session_open {
                                            format!("动态子层就绪 · {} 条规则", wfp.active_filter_count)
                                        } else {
                                            "待激活 / COM 兼容".into()
                                        },
                                        if wfp.sublayer_registered {
                                            BadgeTone::Pass
                                        } else {
                                            BadgeTone::Muted
                                        },
                                        p,
                                    )),
                            )
                            .child(
                                mono_tabular(format!(
                                    "累计拦截 {} 包 · 事件订阅 {}",
                                    wfp.total_blocked_packets,
                                    if wfp.net_event_subscribed { "开启" } else { "关闭" }
                                ))
                                .text_size(px(11.))
                                .text_color(rgb(p.text_muted)),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .items_center()
                            .gap(px(16.))
                            .child(
                                div()
                                    .flex_1()
                                    .flex_basis(px(0.))
                                    .min_w(px(0.))
                                    .child(segmented_capsule_track(p).children(backend_items)),
                            )
                            .child(
                                div()
                                    .flex()
                                    .flex_1()
                                    .flex_basis(px(0.))
                                    .min_w(px(0.))
                                    .items_center()
                                    .justify_between()
                                    .gap(px(10.))
                                    .child(
                                        div()
                                            .flex()
                                            .flex_col()
                                            .gap(px(1.5))
                                            .child(
                                                div()
                                                    .text_size(px(11.5))
                                                    .font_weight(FontWeight::MEDIUM)
                                                    .text_color(rgb(p.text_primary))
                                                    .child("开机联网前抢先保护（默认关闭）"),
                                            )
                                            .child(
                                                div()
                                                    .text_size(px(10.5))
                                                    .text_color(rgb(p.text_muted))
                                                    .child("系统刚开机、后台服务尚未完全就绪前，提前阻断 AI 软件偷跑直连"),
                                            ),
                                    )
                                    .child(
                                        toggle_switch("br-wfp-boot", wfp_boot_guard, can_act, p)
                                            .when(can_act, |sw| {
                                                sw.on_mouse_up(
                                                    MouseButton::Left,
                                                    cx.listener(move |_, _, _, cx| {
                                                        let next = !wfp_boot_guard;
                                                        ctrl_boot.update(cx, |c, cx| {
                                                            c.save_toggle_patch(
                                                                "br-wfp-boot",
                                                                next,
                                                                move |x| x.wfp_boot_guard = next,
                                                                "开机早期 WFP 保护已更新",
                                                                cx,
                                                            );
                                                        });
                                                    }),
                                                )
                                            }),
                                    ),
                            ),
                    ),
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
                .child(wfp_engine_card)
                .child(rules_card)
                .child(choreo.tile(1, 1).apply(guide))
        }

        BreakerSubTab::Live => {
            let ctrl_sweep = ctrl.clone();
            let ctrl_force_all = ctrl.clone();
            let mut sorted_rows: Vec<_> = proj.agent_statuses.iter().collect();
            sorted_rows.sort_by_key(|row| breaker_agent_rank(&row.id));
            let row_count = sorted_rows.len();

            let rows = sorted_rows.into_iter().enumerate().map(|(idx, row)| {
                let row_pose = choreo.inner_bloom(1, idx.min(4));
                let can_kill = can_act && (row.running_count > 0 || row.orphan_count > 0);
                let rid = row.id.clone();
                let is_cli = row.kind.contains("CLI");
                let icon_key = agent_icon_key(&row.id, &row.kind);
                let display_name = breaker_agent_label(&row.id, &row.name).to_string();
                let ctrl_k = ctrl.clone();
                let sub_line = if row.orphan_count > 0 {
                    format!(
                        "运行 {} · 孤儿 {} · 隔离规则 {} 条",
                        row.running_count, row.orphan_count, row.firewall_rules
                    )
                } else if row.running_count == 0 && row.firewall_rules == 0 {
                    "未运行 · 无隔离规则".to_string()
                } else {
                    format!(
                        "运行 {} · 隔离规则 {} 条",
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
                let row_el = r
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(10.))
                            .min_w(px(0.))
                            .flex_1()
                            .child(brand_icon_scaled(
                                icon_key,
                                24.0,
                                6.0,
                                p.is_dark,
                                row_pose.scale,
                            ))
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
                                                    .child(display_name),
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
                                    .child(mono_tabular(sub_line).text_size(px(11.)).text_color(
                                        rgb(if row.orphan_count > 0 {
                                            p.badge_warn.text
                                        } else {
                                            p.text_muted
                                        }),
                                    )),
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
                                    .flex()
                                    .items_center()
                                    .gap(px(5.5))
                                    .text_size(px(11.5))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .text_color(rgb(if row.quarantined {
                                        p.badge_fail.text
                                    } else {
                                        p.text_primary
                                    }))
                                    .child(status_dot(
                                        if row.quarantined {
                                            p.badge_fail.dot
                                        } else {
                                            p.badge_pass.dot
                                        },
                                        6.0,
                                    ))
                                    .child(if row.quarantined {
                                        "已隔离"
                                    } else {
                                        "正常放行"
                                    }),
                            )
                            .child(
                                action_button(
                                    gpui::ElementId::Name(
                                        format!("br-live-kill-{}", row.id).into(),
                                    ),
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
                                                        "已清理该 CLI 会话及孤儿"
                                                    } else {
                                                        "已清理该应用进程及孤儿"
                                                    }),
                                                    cx,
                                                );
                                            });
                                        }),
                                    )
                                }),
                            ),
                    );
                row_pose.apply(row_el)
            });

            let live_card = div().w_full().flex().child(
                bento_card_bloom(p, 17., 14., choreo.tile(0, 0))
                    .flex_1()
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
                                            .child("受管 AI 客户端实况"),
                                    )
                                    .child(
                                        mono_tabular(format!(
                                            "运行 {total_running} · 孤儿 {total_orphans} · 规则 {total_rules} 条"
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
                                            "清理孤儿",
                                            ButtonKind::Secondary,
                                            can_act && total_orphans > 0,
                                            p,
                                        )
                                        .h(px(28.))
                                        .px(px(10.))
                                        .when(can_act && total_orphans > 0, |b| {
                                            b.on_mouse_up(
                                                MouseButton::Left,
                                                cx.listener(move |_, _, _, cx| {
                                                    ctrl_sweep.update(cx, |c, cx| {
                                                        c.send_request(
                                                            PipeRequest::SweepOrphans,
                                                            Some("孤儿进程已清理"),
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
                                            if live_kill_armed {
                                                "确认全清受管进程"
                                            } else {
                                                "全清受管进程"
                                            },
                                            if live_kill_armed {
                                                ButtonKind::Danger
                                            } else {
                                                ButtonKind::DangerSoft
                                            },
                                            can_act && (total_running > 0 || total_orphans > 0),
                                            p,
                                        )
                                        .h(px(28.))
                                        .px(px(11.))
                                        .when(
                                            can_act && (total_running > 0 || total_orphans > 0),
                                            |b| {
                                                b.on_mouse_up(
                                                    MouseButton::Left,
                                                    cx.listener(move |_, _, _, cx| {
                                                        ctrl_force_all.update(cx, |c, cx| {
                                                            if c.arm_or_consume_confirm(
                                                                "br-live-kill-all",
                                                                cx,
                                                            ) {
                                                                c.send_request(
                                                                    PipeRequest::ForceKillAgent {
                                                                        agent_id: None,
                                                                        include_cli: true,
                                                                    },
                                                                    Some(
                                                                        "已清理全部受管进程与孤儿",
                                                                    ),
                                                                    cx,
                                                                );
                                                            }
                                                        });
                                                    }),
                                                )
                                            },
                                        ),
                                    ),
                            ),
                    )
                    .child(if row_count == 0 {
                        div()
                            .flex()
                            .items_center()
                            .justify_center()
                            .py(px(22.))
                            .rounded(px(10.))
                            .bg(rgb(p.inset_bg))
                            .border_1()
                            .border_color(rgb(p.card_border))
                            .text_size(px(11.5))
                            .text_color(rgb(p.text_muted))
                            .child(if connected {
                                "暂未检测到受管 AI 客户端"
                            } else {
                                "等待守护服务同步受管客户端状态…"
                            })
                    } else {
                        div().flex().flex_col().children(rows)
                    }),
            );

            let guide = page_guide_card(
                "隔离与进程治理",
                "路径与签名校验 · 解封零残留",
                &[
                    (
                        "1. 精准匹配防误杀",
                        "熔断仅拦截受管 AI 客户端出站，不影响日常上网；解封后自动清除规则。",
                    ),
                    (
                        "2. 孤儿残留清理",
                        "关闭窗口后若后台子进程仍驻留联网，点「清理孤儿」即可安全回收。",
                    ),
                    (
                        "3. 一键全清场景",
                        "切换代理线路前或紧急排障时，用「全清受管进程」清空旧会话连接。",
                    ),
                ],
                p,
            );

            let filtered_wfp: Vec<_> = wfp
                .recent_blocked
                .iter()
                .filter(|ev| match wfp_filter.as_deref() {
                    None => true,
                    Some(f) => ev.agent_id.eq_ignore_ascii_case(f),
                })
                .take(12)
                .collect();

            let filter_chips = [
                (None, "全部"),
                (Some("claude"), "Claude"),
                (Some("cursor"), "Cursor"),
                (Some("antigravity"), "Antigravity"),
                (Some("chatgpt"), "ChatGPT"),
            ]
            .into_iter()
            .map(|(val, lbl)| {
                let active = wfp_filter.as_deref() == val;
                let ctrl_f = ctrl.clone();
                div()
                    .id(gpui::ElementId::Name(
                        format!("wfp-flt-{}", val.unwrap_or("all")).into(),
                    ))
                    .cursor_pointer()
                    .px(px(8.))
                    .py(px(3.))
                    .rounded(px(6.))
                    .bg(rgb(if active { p.accent_soft_bg } else { p.inset_bg }))
                    .border_1()
                    .border_color(rgb(if active {
                        p.accent_soft_border
                    } else {
                        p.card_border
                    }))
                    .text_size(px(10.5))
                    .font_weight(if active {
                        FontWeight::SEMIBOLD
                    } else {
                        FontWeight::MEDIUM
                    })
                    .text_color(rgb(if active {
                        p.accent_soft_text
                    } else {
                        p.text_secondary
                    }))
                    .child(lbl)
                    .on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |_, _, _, cx| {
                            ctrl_f.update(cx, |c, cx| {
                                c.wfp_agent_filter = val.map(str::to_string);
                                cx.notify();
                            });
                        }),
                    )
            });

            let ctrl_clear_wfp = ctrl.clone();
            let wfp_rows: Vec<Div> = filtered_wfp
                .into_iter()
                .map(|ev| {
                    let ip_disp = mask_wfp_event_ip(ev, privacy_mask);
                    let hm = format_unix_hm(ev.timestamp_ms / 1000);
                    let pid_str = ev
                        .pid
                        .map(|pid| format!("PID {pid}"))
                        .unwrap_or_else(|| "内核".into());
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap(px(8.))
                        .px(px(10.))
                        .py(px(6.5))
                        .rounded(px(8.))
                        .bg(rgb(p.inset_bg))
                        .border_1()
                        .border_color(rgb(p.card_border))
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap(px(8.))
                                .min_w(px(0.))
                                .flex_1()
                                .child(
                                    mono_tabular(hm)
                                        .text_size(px(10.5))
                                        .text_color(rgb(p.text_muted)),
                                )
                                .child(
                                    mono_tabular(format!(
                                        "{} ({pid_str})",
                                        crate::views::shared::canonical_agent_label(
                                            &ev.agent_id,
                                            &ev.agent_id
                                        )
                                    ))
                                    .text_size(px(11.))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .text_color(rgb(p.text_primary)),
                                )
                                .child(
                                    mono_tabular(format!(
                                        "{}:{} · {}",
                                        ip_disp,
                                        ev.remote_port,
                                        ev.protocol.to_ascii_uppercase()
                                    ))
                                    .truncate()
                                    .text_size(px(11.))
                                    .text_color(rgb(p.text_secondary)),
                                ),
                        )
                        .child(tone_tag(
                            wfp_reason_label(&ev.filter_reason),
                            BadgeTone::Fail,
                            p,
                        ))
                })
                .collect();

            let wfp_waterfall_card = div().w_full().flex().child(
                bento_card_bloom(p, 17., 14., choreo.tile(1, 0))
                    .flex_1()
                    .gap(px(9.))
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
                                    .items_center()
                                    .min_w(px(0.))
                                    .gap(px(8.))
                                    .child(
                                        div()
                                            .text_size(px(12.5))
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(rgb(p.text_primary))
                                            .child("实时防漏拦截记录"),
                                    )
                                    .child(
                                        mono_tabular(format!(
                                            "{} · 累计阻断 {} 次泄露请求",
                                            crate::state::friendly_firewall_backend(
                                                &wfp.active_backend
                                            ),
                                            wfp.total_blocked_packets
                                        ))
                                        .truncate()
                                        .text_size(px(10.5))
                                        .text_color(rgb(p.text_muted)),
                                    ),
                            )
                            .child(
                                div()
                                    .flex()
                                    .flex_wrap()
                                    .items_center()
                                    .gap(px(6.))
                                    .children(filter_chips)
                                    .child(
                                        action_button(
                                            "br-wfp-clear",
                                            "清空记录",
                                            ButtonKind::Ghost,
                                            can_act && !wfp.recent_blocked.is_empty(),
                                            p,
                                        )
                                        .h(px(25.))
                                        .px(px(9.))
                                        .text_size(px(10.5))
                                        .when(
                                            can_act && !wfp.recent_blocked.is_empty(),
                                            |b| {
                                                b.on_mouse_up(
                                                    MouseButton::Left,
                                                    cx.listener(move |_, _, _, cx| {
                                                        ctrl_clear_wfp.update(cx, |c, cx| {
                                                            c.send_request(
                                                                PipeRequest::ClearWfpBlockedEvents,
                                                                Some("已清空 WFP 实时拦截事件缓存"),
                                                                cx,
                                                            );
                                                        });
                                                    }),
                                                )
                                            },
                                        ),
                                    ),
                            ),
                    )
                    .child(if wfp_rows.is_empty() {
                        inset_box(p)
                            .py(px(14.))
                            .items_center()
                            .justify_center()
                            .child(
                                div()
                                    .text_size(px(11.))
                                    .text_color(rgb(p.text_muted))
                                    .child("当前筛选范围暂无内核拦截数据包事件"),
                            )
                    } else {
                        div().flex().flex_col().gap(px(5.)).children(wfp_rows)
                    }),
            );

            div()
                .flex()
                .flex_col()
                .w_full()
                .gap(px(11.))
                .child(live_card)
                .child(wfp_waterfall_card)
                .child(choreo.tile(1, 1).apply(guide))
        }
    };

    div()
        .flex()
        .flex_col()
        .w_full()
        .min_w(px(0.))
        .overflow_hidden()
        .gap(px(10.))
        .child(choreo.slot(0).apply(tabs))
        .child(offset_pane(subtab_dx, body))
}
