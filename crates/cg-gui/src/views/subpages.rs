//! Mode B sub-pages (`目标与白名单`, `熔断与防火墙`, `环境与防泄露`, `时间线与审计`,
//! `客户端更新`, `通知与飞书`) + Zero-Input Smart First-Run Onboarding Modal.

use crate::app::{AppController, ConsoleWindowView};
use crate::demo::now_unix_secs;
use crate::protocol::{
    AntigravityProxyStatus, CUT_MODES, LogLevel, OnboardingStrategy, PipeRequest, TimelineStatus,
    UiLabelExt, UpdateCheckPhase, UpdateSummary, mask_ip_str,
};
use crate::state::{
    ConsoleProjection, NavSection, format_relative_secs, format_unix_hm,
    project_antigravity_proxy_card,
};
use crate::theme::{BadgeTone, ThemePalette};
use crate::widgets::controls::{
    ButtonKind, action_button, bento_card, card_header, inset_box, mono_tabular,
    segmented_capsule_item, segmented_capsule_track, status_pill, toggle_switch,
};
use gpui::{
    Context, Div, Entity, FontWeight, MouseButton, div, prelude::*, px, rgb, rgba, uniform_list,
};

/// Sub-view: `目标与白名单` (draft-isolated inputs, CIDR/IP & regions, add/edit/delete).
pub fn render_targets_page(
    ctrl: Entity<AppController>,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> Div {
    let ctrl_read = ctrl.read(cx);
    let dirty = ctrl_read.drafts.dirty;
    let err = ctrl_read.drafts.validation_error.clone();
    let targets = ctrl_read.drafts.targets.clone();
    let busy = ctrl_read.busy_action;
    let connected = ctrl_read.connected;

    let port_in = ctrl_read.inputs.proxy_port.clone();
    let interval_in = ctrl_read.inputs.interval_secs.clone();
    let thresh_in = ctrl_read.inputs.trip_threshold.clone();
    let new_name = ctrl_read.inputs.new_target_name.clone();
    let new_url = ctrl_read.inputs.new_target_url.clone();
    let new_ips = ctrl_read.inputs.new_target_ips.clone();
    let new_reg = ctrl_read.inputs.new_target_regions.clone();
    let ip_map = ctrl_read.inputs.target_ips.clone();
    let reg_map = ctrl_read.inputs.target_regions.clone();

    let ctrl_save = ctrl.clone();
    let ctrl_reset = ctrl.clone();
    let ctrl_add = ctrl.clone();

    let rows = targets.into_iter().map(|t| {
        let tid_toggle = t.id.clone();
        let tid_kind = t.id.clone();
        let tid_del = t.id.clone();
        let ctrl_tog = ctrl.clone();
        let ctrl_k = ctrl.clone();
        let ctrl_d = ctrl.clone();
        let ip_input = ip_map.get(&t.id).cloned();
        let reg_input = reg_map.get(&t.id).cloned();

        inset_box(p)
            .p(px(12.))
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
                                toggle_switch(
                                    gpui::ElementId::Name(format!("tgt-en-{}", t.id).into()),
                                    t.enabled,
                                    true,
                                    p,
                                )
                                .on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_tog.update(cx, |c, cx| {
                                            c.toggle_target_draft_enabled(&tid_toggle, cx);
                                        });
                                    }),
                                ),
                            )
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .child(
                                        div()
                                            .text_size(px(13.))
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(rgb(p.text_primary))
                                            .child(t.name.clone()),
                                    )
                                    .child(
                                        mono_tabular(t.anchor_url.clone())
                                            .text_size(px(11.))
                                            .text_color(rgb(p.text_muted)),
                                    ),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(8.))
                            .child(
                                action_button(
                                    gpui::ElementId::Name(format!("tgt-kind-{}", t.id).into()),
                                    format!("解析：{}", t.anchor_kind.label()),
                                    ButtonKind::Secondary,
                                    true,
                                    p,
                                )
                                .on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_k.update(cx, |c, cx| {
                                            c.cycle_target_draft_kind(&tid_kind, cx);
                                        });
                                    }),
                                ),
                            )
                            .when(!t.builtin, |row| {
                                row.child(
                                    action_button(
                                        gpui::ElementId::Name(format!("tgt-del-{}", t.id).into()),
                                        "删除",
                                        ButtonKind::Danger,
                                        true,
                                        p,
                                    )
                                    .on_mouse_up(
                                        MouseButton::Left,
                                        cx.listener(move |_, _, _, cx| {
                                            ctrl_d.update(cx, |c, cx| {
                                                c.delete_target_draft(&tid_del, cx);
                                            });
                                        }),
                                    ),
                                )
                            }),
                    ),
            )
            .child(
                div()
                    .flex()
                    .gap(px(10.))
                    .child(
                        div()
                            .flex_1()
                            .flex()
                            .flex_col()
                            .gap(px(4.))
                            .child(
                                div()
                                    .text_size(px(11.))
                                    .text_color(rgb(p.text_muted))
                                    .child("允许 IP / IPv4 CIDR 网段"),
                            )
                            .when_some(ip_input, |d, input| d.child(input)),
                    )
                    .child(
                        div()
                            .w(px(220.))
                            .flex()
                            .flex_col()
                            .gap(px(4.))
                            .child(
                                div()
                                    .text_size(px(11.))
                                    .text_color(rgb(p.text_muted))
                                    .child("允许地区（ISO 两字母，如 US, SG）"),
                            )
                            .when_some(reg_input, |d, input| d.child(input)),
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
                .child(card_header(
                    "全局代理与探测参数",
                    if dirty {
                        "草稿已修改 · 未保存"
                    } else {
                        "与后台同步"
                    },
                    p,
                ))
                .child(
                    div()
                        .flex()
                        .gap(px(12.))
                        .child(labeled_field("本地代理端口", port_in, p))
                        .child(labeled_field("巡检间隔（秒）", interval_in, p))
                        .child(labeled_field("熔断连续失败阈值", thresh_in, p)),
                ),
        )
        .child(
            bento_card(p)
                .p(px(16.))
                .gap(px(12.))
                .child(card_header(
                    "监控目标与白名单规则",
                    "后台刷新绝不覆盖草稿",
                    p,
                ))
                .when_some(err, |c, msg| {
                    c.child(
                        div()
                            .px(px(10.))
                            .py(px(8.))
                            .rounded(px(8.))
                            .bg(rgba(p.badge_fail.bg))
                            .text_size(px(11.5))
                            .text_color(rgb(p.badge_fail.text))
                            .child(msg),
                    )
                })
                .child(div().flex().flex_col().gap(px(10.)).children(rows))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_end()
                        .gap(px(8.))
                        .child(
                            action_button(
                                "targets-reset",
                                "撤销未保存修改",
                                ButtonKind::Secondary,
                                dirty && !busy,
                                p,
                            )
                            .on_mouse_up(
                                MouseButton::Left,
                                cx.listener(move |_, _, _, cx| {
                                    ctrl_reset.update(cx, |c, cx| c.reset_target_drafts(cx));
                                }),
                            ),
                        )
                        .child({
                            let can_save = connected && !busy;
                            action_button(
                                "targets-save",
                                if connected {
                                    "保存目标与参数配置"
                                } else {
                                    "守护离线 · 暂不可保存"
                                },
                                ButtonKind::Primary,
                                can_save,
                                p,
                            )
                            .when(can_save, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_save.update(cx, |c, cx| c.save_target_drafts(cx));
                                    }),
                                )
                            })
                        }),
                ),
        )
        .child(
            bento_card(p)
                .p(px(16.))
                .gap(px(10.))
                .child(card_header(
                    "新增自定义监控目标",
                    "支持 Trace / JSON / 页面地区",
                    p,
                ))
                .child(
                    div()
                        .flex()
                        .gap(px(10.))
                        .child(labeled_field("目标名称", new_name, p))
                        .child(labeled_field("探测锚点 URL", new_url, p)),
                )
                .child(
                    div()
                        .flex()
                        .gap(px(10.))
                        .child(labeled_field("允许 IP / CIDR", new_ips, p))
                        .child(labeled_field("允许地区代码", new_reg, p)),
                )
                .child(
                    div().flex().justify_end().child(
                        action_button(
                            "targets-add-btn",
                            "＋ 添加到目标列表",
                            ButtonKind::Secondary,
                            true,
                            p,
                        )
                        .on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |_, _, _, cx| {
                                ctrl_add.update(cx, |c, cx| c.add_custom_target_from_draft(cx));
                            }),
                        ),
                    ),
                ),
        )
}

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
        let row_is_cli = row.kind.starts_with("CLI");
        let ctrl_row = ctrl.clone();
        let sub_line = if row.orphan_count > 0 {
            format!(
                "运行进程 {} · 孤儿 {} · COM 防火墙规则 {}",
                row.running_count, row.orphan_count, row.firewall_rules
            )
        } else {
            format!(
                "运行进程 {} · COM 防火墙规则 {}",
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
                .child(card_header("熔断处置与隔离策略", "CONTRACT §D1/D2", p))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .child(
                            div()
                                .flex()
                                .flex_col()
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
                                        .child("默认仅应用级隔离；全局断网由 WAL 写前账本保护并支持流程 A/B 安全恢复"),
                                ),
                        )
                        .child(segmented_capsule_track(p).children(cut_items)),
                )
                .child(switch_row(
                    "br-kill",
                    "熔断时终止受管 GUI 进程",
                    "按 PID + 启动时间 + 映像路径二次核验防误杀（CLI 策略由下方开关独立控制）",
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
                    "开启后触发熔断时同步清理 @anthropic-ai/claude-code 与 @openai/codex CLI 进程树",
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
                    "Win32 COM 应用级防火墙隔离",
                    "通过 INetFwPolicy2 写入精确 Block 规则并回读核验",
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
                    "系统代理关且无活跃 TUN 网卡时立即判 Uncovered 并触发防泄露封锁",
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
                    "Claude 桌面端关闭后清理无主 renderer 与孤儿 CLI 子进程",
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
                    "检测到系统代理与 TUN 均不可用时自动封锁受管 GUI 应用出站",
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
                    "熔断时终止并写入 INetFwRule 出站/入站隔离",
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

/// Sub-view: `环境与防泄露`
pub fn render_environment_page(
    ctrl: Entity<AppController>,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> Div {
    let ctrl_r = ctrl.read(cx);
    let snap = ctrl_r.snapshot.clone();
    let mask = ctrl_r.privacy_mask;
    let busy = ctrl_r.busy_action;
    let connected = ctrl_r.connected;
    let cfg = snap.as_ref().map(|s| s.config.clone()).unwrap_or_default();
    let ag_proxy = snap
        .as_ref()
        .map(|s| s.antigravity_proxy.clone())
        .unwrap_or_default();
    let updates = snap.as_ref().map(|s| s.updates.clone()).unwrap_or_default();
    let leak = snap.as_ref().map(|s| s.leak.clone()).unwrap_or_default();
    let env = snap.as_ref().map(|s| s.env.clone()).unwrap_or_default();

    let ag_card = render_antigravity_proxy_card(
        ctrl.clone(),
        &ag_proxy,
        &updates,
        cfg.proxy_port,
        cfg.require_antigravity_proxy,
        mask,
        connected,
        busy,
        p,
        cx,
    );

    let ctrl_lw = ctrl.clone();
    let ctrl_lt = ctrl.clone();
    let ctrl_ec = ctrl.clone();
    let ctrl_tz = ctrl.clone();
    let ctrl_loc = ctrl.clone();
    let ctrl_scan = ctrl.clone();
    let ctrl_align = ctrl.clone();

    let direct_rows = leak.direct.iter().map(|c| {
        let remote = if mask {
            mask_ip_str(&c.remote)
        } else {
            c.remote.clone()
        };
        inset_box(p)
            .flex_row()
            .items_center()
            .justify_between()
            .px(px(10.))
            .py(px(6.))
            .child(
                mono_tabular(format!(
                    "PID {} · {} -> {}:{}",
                    c.pid, c.agent, remote, c.port
                ))
                .text_size(px(11.5))
                .text_color(rgb(p.badge_fail.text)),
            )
            .child(status_pill("绕过代理直连", BadgeTone::Fail, p))
    });

    div()
        .flex()
        .flex_col()
        .gap(px(14.))
        .child(ag_card)
        .child(
            bento_card(p)
                .p(px(16.))
                .gap(px(10.))
                .child(card_header("直连防泄露雷达（GetExtendedTcpTable）", leak.note.clone(), p))
                .child(switch_row(
                    "env-leak-watch",
                    "开启直连防泄露观察",
                    "系统代理模式下排查绕过代理的外连套接字（自动豁免回环与 198.18.0.0/15 TUN 虚拟 IP）",
                    cfg.leak_watch,
                    p,
                    cx.listener(move |_, _, _, cx| {
                        let next = !cfg.leak_watch;
                        ctrl_lw.update(cx, |c, cx| {
                            c.save_config_patch(move |x| x.leak_watch = next, "已更新", cx);
                        });
                    }),
                ))
                .child(switch_row(
                    "env-leak-trip",
                    "发现直连立即触发熔断",
                    "默认仅记录告警与日志；确认无误报后可启用自动熔断",
                    cfg.leak_trip,
                    p,
                    cx.listener(move |_, _, _, cx| {
                        let next = !cfg.leak_trip;
                        ctrl_lt.update(cx, |c, cx| {
                            c.save_config_patch(move |x| x.leak_trip = next, "已更新", cx);
                        });
                    }),
                ))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .child(
                            mono_tabular(format!(
                                "连接总计 {} · 经代理 {} · 本地 {} · 直连泄露 {}",
                                leak.agent_conns, leak.proxied, leak.local, leak.direct_total
                            ))
                            .text_size(px(12.))
                            .text_color(rgb(p.text_secondary)),
                        )
                        .child({
                            let can_scan = connected && !busy;
                            action_button(
                                "env-scan-now",
                                "↻ 立即扫描套接字",
                                ButtonKind::Secondary,
                                can_scan,
                                p,
                            )
                            .when(can_scan, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_scan.update(cx, |c, cx| {
                                            c.send_request(
                                                PipeRequest::RecheckNow { target_id: None },
                                                Some("已完成直连套接字扫描"),
                                                cx,
                                            );
                                        });
                                    }),
                                )
                            })
                        }),
                )
                .children(direct_rows),
        )
        .child(
            bento_card(p)
                .p(px(16.))
                .gap(px(10.))
                .child(card_header("系统时区与区域一致性", env.note.clone(), p))
                .child(
                    div()
                        .flex()
                        .gap(px(10.))
                        .child(
                            inset_box(p)
                                .flex_1()
                                .p(px(10.))
                                .gap(px(4.))
                                .child(
                                    div()
                                        .text_size(px(11.))
                                        .text_color(rgb(p.text_muted))
                                        .child("当前 Windows 时区 / 区域"),
                                )
                                .child(
                                    div()
                                        .text_size(px(12.5))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(p.text_primary))
                                        .child(format!("{} · {}", env.info.tz_label, env.info.locale)),
                                ),
                        )
                        .child(
                            inset_box(p)
                                .flex_1()
                                .p(px(10.))
                                .gap(px(4.))
                                .child(
                                    div()
                                        .text_size(px(11.))
                                        .text_color(rgb(p.text_muted))
                                        .child("期望出口对应时区"),
                                )
                                .child(
                                    div()
                                        .text_size(px(12.5))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(p.text_primary))
                                        .child(format!(
                                            "{} · {}",
                                            env.expect_city.as_deref().unwrap_or("待识别"),
                                            env.expect_tz.as_deref().unwrap_or("--")
                                        )),
                                ),
                        ),
                )
                .child(switch_row(
                    "env-check-sw",
                    "检测时区与区域一致性",
                    "对比出口城市（colo 映射）与 Windows 本地时区及区域格式",
                    cfg.env_check,
                    p,
                    cx.listener(move |_, _, _, cx| {
                        let next = !cfg.env_check;
                        ctrl_ec.update(cx, |c, cx| {
                            c.save_config_patch(move |x| x.env_check = next, "已更新", cx);
                        });
                    }),
                ))
                .child(switch_row(
                    "env-tz-sw",
                    "自动对齐 Windows 时区",
                    "出口城市连续一致后自动切换时区并在安全撤防/退出时由 WAL 还原",
                    cfg.env_align_tz,
                    p,
                    cx.listener(move |_, _, _, cx| {
                        let next = !cfg.env_align_tz;
                        ctrl_tz.update(cx, |c, cx| {
                            c.save_config_patch(move |x| x.env_align_tz = next, "已更新", cx);
                        });
                    }),
                ))
                .child(switch_row(
                    "env-loc-sw",
                    "自动对齐 Windows 默认位置",
                    "同步更新系统默认地理坐标，退出时按 WAL 基线还原",
                    cfg.env_align_location,
                    p,
                    cx.listener(move |_, _, _, cx| {
                        let next = !cfg.env_align_location;
                        ctrl_loc.update(cx, |c, cx| {
                            c.save_config_patch(
                                move |x| x.env_align_location = next,
                                "已更新",
                                cx,
                            );
                        });
                    }),
                ))
                .child(
                    div()
                        .flex()
                        .justify_end()
                        .child({
                            let can_align = connected && !busy;
                            action_button(
                                "env-realign-btn",
                                "↻ 立即校验环境一致性",
                                ButtonKind::Secondary,
                                can_align,
                                p,
                            )
                            .when(can_align, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_align.update(cx, |c, cx| {
                                            c.send_request(
                                                PipeRequest::RecheckNow { target_id: None },
                                                Some("环境一致性校验已刷新"),
                                                cx,
                                            );
                                        });
                                    }),
                                )
                            })
                        }),
                ),
        )
}

#[allow(clippy::too_many_arguments)]
fn render_antigravity_proxy_card(
    ctrl: Entity<AppController>,
    ag: &AntigravityProxyStatus,
    updates: &UpdateSummary,
    guard_proxy_port: u16,
    require_ag_proxy: bool,
    privacy_mask: bool,
    connected: bool,
    busy: bool,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> Div {
    let vm = project_antigravity_proxy_card(ag, guard_proxy_port, privacy_mask, now_unix_secs());
    let can_act = connected && !busy;
    let ctrl_toggle = ctrl.clone();
    let ctrl_to_updates = ctrl.clone();
    let ctrl_recheck = ctrl;
    let has_ag_update = updates.antigravity_proxy.phase == UpdateCheckPhase::UpdateAvailable;
    let ag_update_tag = updates
        .antigravity_proxy
        .latest_version
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|v| format!("v{}", v.trim_start_matches('v')))
        .unwrap_or_else(|| "新版".into());
    let ag_update_surf = p.badge(BadgeTone::Warn);

    let ver_color = if vm.version_warn {
        p.badge_warn.text
    } else if ag.installed {
        p.text_primary
    } else {
        p.text_muted
    };
    let dll_color = match vm.dll_tone {
        BadgeTone::Pass => p.badge_pass.text,
        BadgeTone::Fail => p.badge_fail.text,
        BadgeTone::Warn => p.badge_warn.text,
        BadgeTone::Muted => p.text_muted,
    };
    let cfg_color = match vm.config_tone {
        BadgeTone::Pass => p.text_primary,
        BadgeTone::Fail => p.badge_fail.text,
        BadgeTone::Warn => p.badge_warn.text,
        BadgeTone::Muted => p.text_muted,
    };
    let rt_color = match vm.runtime_tone {
        BadgeTone::Pass => p.badge_pass.text,
        BadgeTone::Fail => p.badge_fail.text,
        BadgeTone::Warn => p.badge_warn.text,
        BadgeTone::Muted => p.text_secondary,
    };

    let summary_surface = if vm.is_degraded {
        Some(p.badge(BadgeTone::Fail))
    } else {
        None
    };

    bento_card(p)
        .p(px(16.))
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
                        .gap(px(8.))
                        .child(
                            div()
                                .text_size(px(13.5))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.text_primary))
                                .child("反重力透明代理注入守护 (antigravity-proxy)"),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(8.))
                        .when(has_ag_update, |row| {
                            row.child(
                                div()
                                    .id("env-ag-upd-available-badge")
                                    .flex()
                                    .items_center()
                                    .gap(px(5.))
                                    .px(px(8.))
                                    .py(px(3.))
                                    .rounded(px(999.))
                                    .bg(rgba(ag_update_surf.bg))
                                    .border_1()
                                    .border_color(rgb(ag_update_surf.dot))
                                    .cursor_pointer()
                                    .child(
                                        div()
                                            .w(px(6.))
                                            .h(px(6.))
                                            .rounded(px(999.))
                                            .bg(rgb(ag_update_surf.dot)),
                                    )
                                    .child(
                                        div()
                                            .text_size(px(11.))
                                            .font_weight(FontWeight::MEDIUM)
                                            .text_color(rgb(ag_update_surf.text))
                                            .child(format!("发现仓库新版 {ag_update_tag}")),
                                    )
                                    .on_mouse_up(
                                        MouseButton::Left,
                                        cx.listener(move |_, _, _, cx| {
                                            ctrl_to_updates.update(cx, |c, cx| {
                                                c.set_nav(NavSection::Updates, cx);
                                            });
                                        }),
                                    ),
                            )
                        })
                        .when_some(vm.checked_age_label, |row, age| {
                            row.child(
                                div()
                                    .text_size(px(11.))
                                    .text_color(rgb(p.text_muted))
                                    .child(format!("核验于 {age}")),
                            )
                        })
                        .child(status_pill(vm.pill_label, vm.pill_tone, p)),
                ),
        )
        // 2x2 diagnostic tiles
        .child(
            div()
                .flex()
                .gap(px(10.))
                .child(ag_diag_tile(
                    "客户端版本",
                    vm.version_primary,
                    vm.version_sub,
                    ver_color,
                    true,
                    p,
                ))
                .child(ag_diag_tile(
                    "version.dll 劫持模块",
                    vm.dll_primary,
                    vm.dll_sub,
                    dll_color,
                    false,
                    p,
                )),
        )
        .child(
            div()
                .flex()
                .gap(px(10.))
                .child(ag_diag_tile(
                    "config.json 代理配置",
                    vm.config_primary,
                    vm.config_sub,
                    cfg_color,
                    true,
                    p,
                ))
                .child(ag_diag_tile(
                    "运行态内存挂载 (language_server)",
                    vm.runtime_primary,
                    vm.runtime_sub,
                    rt_color,
                    false,
                    p,
                )),
        )
        // Summary + install directory bar
        .child({
            let mut bar = inset_box(p).px(px(12.)).py(px(8.)).gap(px(3.));
            if let Some(surf) = summary_surface {
                bar = bar
                    .bg(rgba(surf.bg))
                    .border_color(rgba(p.hero_tripped.border));
            }
            bar.child(
                div()
                    .text_size(px(12.))
                    .font_weight(FontWeight::MEDIUM)
                    .text_color(rgb(if vm.is_degraded {
                        p.badge_fail.text
                    } else if ag.installed {
                        p.text_primary
                    } else {
                        p.text_muted
                    }))
                    .child(if vm.is_degraded {
                        format!("! {}", vm.summary_text)
                    } else {
                        vm.summary_text
                    }),
            )
            .child(
                mono_tabular(format!("安装目录：{}", vm.dir_text))
                    .truncate()
                    .text_size(px(11.))
                    .text_color(rgb(p.text_muted)),
            )
        })
        // Bottom row: toggle_switch + immediate recheck button
        .child(
            inset_box(p)
                .flex_row()
                .items_center()
                .justify_between()
                .px(px(12.))
                .py(px(9.))
                .gap(px(12.))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(10.))
                        .flex_1()
                        .min_w(px(0.))
                        .child(
                            toggle_switch("env-ag-require-proxy", require_ag_proxy, can_act, p)
                                .when(can_act, |sw| {
                                    sw.on_mouse_up(
                                        MouseButton::Left,
                                        cx.listener(move |_, _, _, cx| {
                                            let next = !require_ag_proxy;
                                            ctrl_toggle.update(cx, |c, cx| {
                                                c.save_config_patch(
                                                    move |x| x.require_antigravity_proxy = next,
                                                    if next {
                                                        "已开启反重力注入失效拦截门禁"
                                                    } else {
                                                        "已关闭反重力注入失效拦截门禁"
                                                    },
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
                                .flex_col()
                                .gap(px(1.))
                                .flex_1()
                                .min_w(px(0.))
                                .child(
                                    div()
                                        .text_size(px(12.5))
                                        .font_weight(FontWeight::MEDIUM)
                                        .text_color(rgb(p.text_primary))
                                        .child("注入失效时拦截安全启动"),
                                )
                                .child(
                                    div()
                                        .truncate()
                                        .text_size(px(11.))
                                        .text_color(rgb(p.text_muted))
                                        .child("客户端自动升级覆盖 version.dll 或内存未挂载时，阻止反重力直连启动"),
                                ),
                        ),
                )
                .child(
                    action_button(
                        "env-ag-recheck-btn",
                        "↻ 立即重检",
                        ButtonKind::Secondary,
                        can_act,
                        p,
                    )
                    .when(can_act, |b| {
                        b.on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |_, _, _, cx| {
                                ctrl_recheck.update(cx, |c, cx| {
                                    c.send_request(
                                        PipeRequest::RecheckNow { target_id: None },
                                        Some("已完成反重力透明代理注入核验"),
                                        cx,
                                    );
                                });
                            }),
                        )
                    }),
                ),
        )
}

fn ag_diag_tile(
    label: &'static str,
    primary: String,
    sub: String,
    primary_color: u32,
    mono: bool,
    p: &ThemePalette,
) -> Div {
    let val_el = if mono {
        mono_tabular(primary)
    } else {
        div().child(primary)
    }
    .truncate()
    .text_size(px(12.5))
    .font_weight(FontWeight::SEMIBOLD)
    .text_color(rgb(primary_color));

    inset_box(p)
        .flex_1()
        .flex_basis(px(0.))
        .min_w(px(0.))
        .p(px(10.))
        .gap(px(3.))
        .child(
            div()
                .text_size(px(11.))
                .text_color(rgb(p.text_muted))
                .child(label),
        )
        .child(val_el)
        .child(
            div()
                .truncate()
                .text_size(px(10.5))
                .text_color(rgb(p.text_muted))
                .child(sub),
        )
}

/// Sub-view: `时间线与审计` (24h bucket filter + `uniform_list` virtualized log stream).
pub fn render_audit_page(
    ctrl: Entity<AppController>,
    proj: &ConsoleProjection,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> Div {
    let ctrl_r = ctrl.read(cx);
    let scroll_handle = ctrl_r.audit_list_scroll.clone();
    let has_bucket = ctrl_r.selected_bucket.is_some();
    let logs_loading = ctrl_r.logs_loading;
    let total_server = ctrl_r.queried_logs_total;
    let connected = ctrl_r.connected;
    let ctrl_clear = ctrl.clone();
    let ctrl_refresh = ctrl.clone();

    let bars = proj.timeline_bars.iter().map(|bar| {
        let color = match bar.status {
            TimelineStatus::Pass => p.timeline.pass,
            TimelineStatus::Warn => p.timeline.warn,
            TimelineStatus::Fail => p.timeline.fail,
            TimelineStatus::Empty => p.timeline.empty,
        };
        let idx = bar.index;
        let ctrl_b = ctrl.clone();
        let mut el = div()
            .id(gpui::ElementId::Name(format!("audit-bar-{idx}").into()))
            .flex_1()
            .min_w(px(3.))
            .h(px(28.))
            .rounded(px(2.))
            .bg(rgb(color))
            .cursor_pointer()
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(move |_, _, _, cx| {
                    ctrl_b.update(cx, |c, cx| c.select_timeline_bucket(idx, false, cx));
                }),
            );
        if bar.selected {
            el = el.border_1().border_color(rgb(p.text_primary));
        }
        el
    });

    let logs = proj.filtered_logs.clone();
    let log_count = logs.len();
    let palette_for_list = p;

    let list_el = if log_count == 0 {
        inset_box(p)
            .p(px(20.))
            .items_center()
            .text_size(px(12.))
            .text_color(rgb(p.text_muted))
            .child("当前时间桶或搜索条件下没有匹配的审计日志")
    } else {
        div()
            .h(px(360.))
            .w_full()
            .rounded(px(12.))
            .bg(rgb(p.inset_bg))
            .border_1()
            .border_color(rgb(p.inset_border))
            .p(px(6.))
            .child(
                uniform_list("audit-log-stream", log_count, move |range, _window, _cx| {
                    range
                        .map(|idx| {
                            let entry = &logs[idx];
                            let tone = match entry.level {
                                LogLevel::Info => BadgeTone::Pass,
                                LogLevel::Warn => BadgeTone::Warn,
                                LogLevel::Error => BadgeTone::Fail,
                                LogLevel::Audit => BadgeTone::Muted,
                            };
                            div()
                                .flex()
                                .items_center()
                                .gap(px(8.))
                                .h(px(30.))
                                .px(px(8.))
                                .rounded(px(7.))
                                .child(
                                    mono_tabular(format_unix_hm(entry.timestamp))
                                        .w(px(68.))
                                        .flex_shrink_0()
                                        .text_size(px(11.))
                                        .text_color(rgb(palette_for_list.text_muted)),
                                )
                                .child(status_pill(entry.level.label(), tone, palette_for_list))
                                .child(
                                    div()
                                        .px(px(6.))
                                        .py(px(1.))
                                        .rounded(px(5.))
                                        .bg(rgb(palette_for_list.cc_pill_bg))
                                        .text_size(px(10.))
                                        .font_family("Cascadia Mono")
                                        .text_color(rgb(palette_for_list.cc_pill_text))
                                        .child(entry.category.clone()),
                                )
                                .child(
                                    div()
                                        .flex_1()
                                        .min_w(px(0.))
                                        .truncate()
                                        .text_size(px(12.))
                                        .text_color(rgb(palette_for_list.text_primary))
                                        .child(entry.message.clone()),
                                )
                        })
                        .collect()
                })
                .track_scroll(&scroll_handle)
                .size_full(),
            )
    };

    div()
        .flex()
        .flex_col()
        .gap(px(14.))
        .child(
            bento_card(p)
                .p(px(16.))
                .gap(px(10.))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .child(
                            div()
                                .text_size(px(13.5))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.text_primary))
                                .child("24h 时间线桶过滤"),
                        )
                        .when(has_bucket, |d| {
                            d.child(
                                action_button(
                                    "audit-clear-bucket",
                                    "清除时段筛选",
                                    ButtonKind::Secondary,
                                    true,
                                    p,
                                )
                                .on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_clear.update(cx, |c, cx| c.clear_timeline_bucket(cx));
                                    }),
                                ),
                            )
                        }),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(2.))
                        .p(px(6.))
                        .rounded(px(10.))
                        .bg(rgb(p.inset_bg))
                        .border_1()
                        .border_color(rgb(p.inset_border))
                        .children(bars),
                )
                .child(
                    div()
                        .text_size(px(11.5))
                        .text_color(rgb(p.text_muted))
                        .child(proj.selected_bucket_summary.clone()),
                ),
        )
        .child(
            bento_card(p)
                .p(px(16.))
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
                                .gap(px(8.))
                                .child(
                                    div()
                                        .text_size(px(13.5))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(p.text_primary))
                                        .child("虚拟化审计日志流（uniform_list）"),
                                )
                                .child(
                                    div()
                                        .text_size(px(11.5))
                                        .text_color(rgb(p.text_muted))
                                        .child(if total_server > log_count {
                                            format!(
                                                "显示 {log_count} / 服务端命中 {total_server} 条"
                                            )
                                        } else {
                                            format!("共 {log_count} 条")
                                        }),
                                ),
                        )
                        .child({
                            let can_pull = connected && !logs_loading;
                            action_button(
                                "audit-query-refresh",
                                if logs_loading {
                                    "查询中…"
                                } else {
                                    "↻ 查询最新审计日志"
                                },
                                ButtonKind::Secondary,
                                can_pull,
                                p,
                            )
                            .when(can_pull, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_refresh.update(cx, |c, cx| c.refresh_audit_logs(cx));
                                    }),
                                )
                            })
                        }),
                )
                .child(list_el),
        )
}

fn update_phase_tone(phase: UpdateCheckPhase) -> BadgeTone {
    match phase {
        UpdateCheckPhase::UpToDate => BadgeTone::Pass,
        UpdateCheckPhase::UpdateAvailable => BadgeTone::Warn,
        UpdateCheckPhase::Failed => BadgeTone::Fail,
        UpdateCheckPhase::Idle | UpdateCheckPhase::Checking | UpdateCheckPhase::NotInstalled => {
            BadgeTone::Muted
        }
    }
}

fn format_ver_label(ver: Option<&str>, fallback: &str) -> String {
    ver.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|v| format!("v{}", v.trim_start_matches(['v', 'V'])))
        .unwrap_or_else(|| fallback.to_string())
}

/// Sub-view: `客户端更新`
pub fn render_updates_page(
    ctrl: Entity<AppController>,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> Div {
    let ctrl_r = ctrl.read(cx);
    let snap = ctrl_r.snapshot.clone();
    let connected = ctrl_r.connected;
    let busy = ctrl_r.busy_action;
    let cfg = snap.as_ref().map(|s| s.config.clone()).unwrap_or_default();
    let ver = snap
        .as_ref()
        .map(|s| s.version.clone())
        .unwrap_or_else(|| "4.0.0".into());
    let tripped = snap.as_ref().is_some_and(|s| s.is_tripped());
    let updates = snap.as_ref().map(|s| s.updates.clone()).unwrap_or_default();
    let ag_proxy = snap
        .as_ref()
        .map(|s| s.antigravity_proxy.clone())
        .unwrap_or_default();
    let now = now_unix_secs();
    let can_check = connected && !busy && !tripped;

    let cg_upd = &updates.claudeguard;
    let cg_cur = format_ver_label(cg_upd.installed_version.as_deref().or(Some(&ver)), "v4.0.0");
    let cg_latest = format_ver_label(cg_upd.latest_version.as_deref(), "待检查");
    let cg_note = if cg_upd.note.trim().is_empty() {
        "已启用 Ed25519 清单验签 + Authenticode 发布者校验 + NetworkPolicy 代理通道".to_string()
    } else {
        cg_upd.note.clone()
    };
    let cg_checked_age = format_relative_secs(cg_upd.checked_at, now);
    let cg_repo = if cg_upd.repo.is_empty() {
        "daha1216/ClaudeGuard"
    } else {
        cg_upd.repo.as_str()
    };

    let ag_upd = &updates.antigravity_proxy;
    let ag_repo = if ag_upd.repo.is_empty() {
        "yuaotian/antigravity-proxy"
    } else {
        ag_upd.repo.as_str()
    };
    let ag_local_ver = if !ag_proxy.installed {
        "未安装反重力".into()
    } else {
        format_ver_label(
            ag_upd
                .installed_version
                .as_deref()
                .or(ag_proxy.injector_version.as_deref()),
            "未注入/已丢失",
        )
    };
    let ag_local_sub = if !ag_proxy.installed {
        "本机未检测到 Antigravity 客户端".into()
    } else if !ag_proxy.dll_valid {
        "! version.dll 缺失或签名异常".into()
    } else {
        "version.dll 已注入且特征有效".into()
    };
    let ag_local_color = if !ag_proxy.installed {
        p.text_muted
    } else if !ag_proxy.dll_valid
        || ag_upd.installed_version.is_none() && ag_proxy.injector_version.is_none()
    {
        p.badge_fail.text
    } else {
        p.text_primary
    };
    let ag_latest_ver = format_ver_label(ag_upd.latest_version.as_deref(), "待检查");
    let ag_latest_color = match ag_upd.phase {
        UpdateCheckPhase::UpdateAvailable => p.badge_warn.text,
        UpdateCheckPhase::UpToDate => p.badge_pass.text,
        UpdateCheckPhase::Failed => p.badge_fail.text,
        _ => p.text_primary,
    };
    let ag_latest_sub = ag_upd
        .release_url
        .clone()
        .unwrap_or_else(|| "GitHub Releases 最新版元数据".into());
    let ag_note = if ag_upd.note.trim().is_empty() {
        "点击右侧按钮经代理通道检查 yuaotian/antigravity-proxy 最新版本".to_string()
    } else {
        ag_upd.note.clone()
    };
    let ag_checked_age = format_relative_secs(ag_upd.checked_at, now);

    let claude_msix_label = updates
        .claude_msix_version
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|v| format!("MSIX v{}", v.trim_start_matches(['v', 'V'])))
        .unwrap_or_else(|| "MSIX 未检出".into());
    let codex_msix_label = updates
        .codex_msix_version
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|v| format!("MSIX v{}", v.trim_start_matches(['v', 'V'])))
        .unwrap_or_else(|| "MSIX 未检出".into());

    let ctrl_auto = ctrl.clone();
    let ctrl_check_all = ctrl.clone();
    let ctrl_check_ag = ctrl;

    div()
        .flex()
        .flex_col()
        .gap(px(14.))
        .child(
            bento_card(p)
                .p(px(16.))
                .gap(px(10.))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap(px(8.))
                        .child(
                            div()
                                .text_size(px(13.5))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.text_primary))
                                .child("ClaudeGuard 自身与组件更新巡检"),
                        )
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap(px(8.))
                                .child(
                                    mono_tabular(format!("当前 {cg_cur} / 最新 {cg_latest}"))
                                        .text_size(px(11.5))
                                        .text_color(rgb(p.text_secondary)),
                                )
                                .child(status_pill(
                                    cg_upd.phase.label(),
                                    update_phase_tone(cg_upd.phase),
                                    p,
                                )),
                        ),
                )
                .child(switch_row(
                    "upd-auto",
                    "自动静默检查新版本",
                    "每 6 小时经代理网络策略检查签名清单，保护隔离期间禁止应用更新",
                    cfg.auto_upd_check,
                    p,
                    cx.listener(move |_, _, _, cx| {
                        if !connected || busy {
                            return;
                        }
                        let next = !cfg.auto_upd_check;
                        ctrl_auto.update(cx, |c, cx| {
                            c.save_config_patch(move |x| x.auto_upd_check = next, "已更新", cx);
                        });
                    }),
                ))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
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
                                        .text_size(px(12.))
                                        .text_color(rgb(p.text_secondary))
                                        .child(cg_note),
                                )
                                .child(
                                    mono_tabular(format!(
                                        "仓库：{cg_repo} · 最近巡检：{cg_checked_age}"
                                    ))
                                    .text_size(px(11.))
                                    .text_color(rgb(p.text_muted)),
                                ),
                        )
                        .child(
                            action_button(
                                "upd-check-btn",
                                if tripped {
                                    "隔离期间禁止更新"
                                } else {
                                    "↻ 立即检查全部更新"
                                },
                                ButtonKind::Primary,
                                can_check,
                                p,
                            )
                            .when(can_check, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_check_all.update(cx, |c, cx| {
                                            c.send_request(
                                                PipeRequest::CheckUpdates { component: None },
                                                Some("已完成全部组件更新巡检"),
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
            bento_card(p)
                .p(px(16.))
                .gap(px(10.))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap(px(8.))
                        .child(
                            div()
                                .text_size(px(13.5))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.text_primary))
                                .child("antigravity-proxy 注入仓库版本检测 · yuaotian/antigravity-proxy"),
                        )
                        .child(status_pill(
                            ag_upd.phase.label(),
                            update_phase_tone(ag_upd.phase),
                            p,
                        )),
                )
                .child(
                    div()
                        .flex()
                        .gap(px(10.))
                        .child(ag_diag_tile(
                            "本地已注入版本",
                            ag_local_ver,
                            ag_local_sub,
                            ag_local_color,
                            true,
                            p,
                        ))
                        .child(ag_diag_tile(
                            "GitHub 仓库最新版",
                            ag_latest_ver,
                            ag_latest_sub,
                            ag_latest_color,
                            true,
                            p,
                        ))
                        .child(ag_diag_tile(
                            "检测源仓库",
                            ag_repo.to_string(),
                            "通过受管代理通道只读核验 Release".into(),
                            p.text_primary,
                            true,
                            p,
                        )),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
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
                                        .text_size(px(12.))
                                        .text_color(rgb(if ag_upd.phase == UpdateCheckPhase::UpdateAvailable {
                                            p.badge_warn.text
                                        } else if ag_upd.phase == UpdateCheckPhase::Failed {
                                            p.badge_fail.text
                                        } else {
                                            p.text_secondary
                                        }))
                                        .child(ag_note),
                                )
                                .child(
                                    mono_tabular(format!("最近检测：{ag_checked_age}"))
                                        .text_size(px(11.))
                                        .text_color(rgb(p.text_muted)),
                                ),
                        )
                        .child(
                            action_button(
                                "upd-check-ag-proxy-btn",
                                "↻ 检测 antigravity-proxy 最新版",
                                if ag_upd.phase == UpdateCheckPhase::UpdateAvailable {
                                    ButtonKind::Primary
                                } else {
                                    ButtonKind::Secondary
                                },
                                can_check,
                                p,
                            )
                            .when(can_check, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_check_ag.update(cx, |c, cx| {
                                            c.send_request(
                                                PipeRequest::CheckUpdates {
                                                    component: Some("antigravity_proxy".into()),
                                                },
                                                Some("已完成 antigravity-proxy 最新版检测"),
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
                .gap(px(14.))
                .child(
                    bento_card(p)
                        .flex_1()
                        .flex_basis(px(0.))
                        .min_w(px(0.))
                        .p(px(16.))
                        .gap(px(8.))
                        .child(card_header(
                            "Claude 桌面端 & Claude Code",
                            claude_msix_label.clone(),
                            p,
                        ))
                        .child(
                            div()
                                .text_size(px(12.))
                                .text_color(rgb(p.text_secondary))
                                .child("全覆盖 depth-12 MSIX 子进程树（含 github-mcp-server.exe / cowork-svc.exe）与 @anthropic-ai/claude-code CLI 会话；更新后自动追加 INetFwRule 并回读核验，杜绝升级脱保。"),
                        )
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap(px(8.))
                                .child(status_pill(
                                    claude_msix_label,
                                    if updates.claude_msix_version.is_some() {
                                        BadgeTone::Pass
                                    } else {
                                        BadgeTone::Muted
                                    },
                                    p,
                                ))
                                .child(status_pill(
                                    "COM 防火墙 + CLI 覆盖",
                                    BadgeTone::Pass,
                                    p,
                                )),
                        ),
                )
                .child(
                    bento_card(p)
                        .flex_1()
                        .flex_basis(px(0.))
                        .min_w(px(0.))
                        .p(px(16.))
                        .gap(px(8.))
                        .child(card_header(
                            "ChatGPT / Codex 桌面端 & CLI",
                            codex_msix_label.clone(),
                            p,
                        ))
                        .child(
                            div()
                                .text_size(px(12.))
                                .text_color(rgb(p.text_secondary))
                                .child("全覆盖 ChatGPT.exe + Codex.exe + cua_node 与 depth-11 codex-computer-use 子树及 @openai/codex CLI；经代理通道校验签名并在运行进程安全交接后绑定隔离路径。"),
                        )
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap(px(8.))
                                .child(status_pill(
                                    codex_msix_label,
                                    if updates.codex_msix_version.is_some() {
                                        BadgeTone::Pass
                                    } else {
                                        BadgeTone::Muted
                                    },
                                    p,
                                ))
                                .child(status_pill(
                                    "代理通道 + CLI 覆盖",
                                    BadgeTone::Pass,
                                    p,
                                )),
                        ),
                ),
        )
}

/// Sub-view: `通知与飞书`
pub fn render_notify_page(
    ctrl: Entity<AppController>,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> Div {
    let ctrl_r = ctrl.read(cx);
    let snap = ctrl_r.snapshot.clone();
    let cfg = snap.as_ref().map(|s| s.config.clone()).unwrap_or_default();
    let n = cfg.notify;
    let webhook_in = ctrl_r.inputs.feishu_webhook.clone();
    let secret_in = ctrl_r.inputs.feishu_secret.clone();
    let feishu_enabled = ctrl_r.drafts.feishu_enabled;
    let clear_secret = ctrl_r.drafts.feishu_clear_secret;
    let fs_note = ctrl_r
        .feishu_status_note
        .clone()
        .unwrap_or_else(|| "凭据由 Windows DPAPI CryptProtectData 加密存储于当前用户".into());

    let ctrl_en = ctrl.clone();
    let ctrl_trip = ctrl.clone();
    let ctrl_rec = ctrl.clone();
    let ctrl_egress = ctrl.clone();
    let ctrl_fs_en = ctrl.clone();
    let ctrl_fs_clr = ctrl.clone();
    let ctrl_fs_save = ctrl.clone();
    let ctrl_fs_test = ctrl.clone();

    div()
        .flex()
        .flex_col()
        .gap(px(14.))
        .child(
            bento_card(p)
                .p(px(16.))
                .gap(px(10.))
                .child(card_header("原生 WinRT Toast 通知", "零 PowerShell", p))
                .child(switch_row(
                    "nt-enabled",
                    "启用桌面 Toast 通知",
                    "通过 WinRT ToastNotificationManager 原生推送",
                    n.enabled,
                    p,
                    cx.listener(move |_, _, _, cx| {
                        let next = !n.enabled;
                        ctrl_en.update(cx, |c, cx| {
                            c.save_config_patch(move |x| x.notify.enabled = next, "已更新", cx);
                        });
                    }),
                ))
                .child(switch_row(
                    "nt-trip",
                    "熔断与隔离告警",
                    "发生出口偏离或隔离时立即推送桌面提醒",
                    n.trip,
                    p,
                    cx.listener(move |_, _, _, cx| {
                        let next = !n.trip;
                        ctrl_trip.update(cx, |c, cx| {
                            c.save_config_patch(move |x| x.notify.trip = next, "已更新", cx);
                        });
                    }),
                ))
                .child(switch_row(
                    "nt-recover",
                    "流程 A/B 安全恢复通知",
                    "网络恢复或撤防核验完成后提示结果",
                    n.recover,
                    p,
                    cx.listener(move |_, _, _, cx| {
                        let next = !n.recover;
                        ctrl_rec.update(cx, |c, cx| {
                            c.save_config_patch(move |x| x.notify.recover = next, "已更新", cx);
                        });
                    }),
                ))
                .child(switch_row(
                    "nt-egress",
                    "通知正文附带出口 IP 与地区（默认脱敏关闭）",
                    "CONTRACT §D5：关闭时外发通知仅含目标别名、状态与原因码，绝不泄露出口 IP 或主机名",
                    n.include_egress,
                    p,
                    cx.listener(move |_, _, _, cx| {
                        let next = !n.include_egress;
                        ctrl_egress.update(cx, |c, cx| {
                            c.save_config_patch(
                                move |x| x.notify.include_egress = next,
                                "隐私脱敏策略已更新",
                                cx,
                            );
                        });
                    }),
                )),
        )
        .child(
            bento_card(p)
                .p(px(16.))
                .gap(px(10.))
                .child(card_header("飞书群机器人 Webhook", "经 NetworkPolicy 外发", p))
                .child(switch_row(
                    "fs-en-sw",
                    "启用飞书群机器人推送",
                    "支持 HMAC-SHA256 加签与离线队列重试",
                    feishu_enabled,
                    p,
                    cx.listener(move |_, _, _, cx| {
                        ctrl_fs_en.update(cx, |c, cx| {
                            c.drafts.feishu_enabled = !c.drafts.feishu_enabled;
                            cx.notify();
                        });
                    }),
                ))
                .child(labeled_field("Webhook HTTPS 地址", webhook_in, p))
                .child(labeled_field("加签密钥（已掩码输入）", secret_in, p))
                .child(switch_row(
                    "fs-clr-sw",
                    "保存时清除已存储的旧密钥",
                    "勾选后将抹除 DPAPI 中保存的加签密钥",
                    clear_secret,
                    p,
                    cx.listener(move |_, _, _, cx| {
                        ctrl_fs_clr.update(cx, |c, cx| {
                            c.drafts.feishu_clear_secret = !c.drafts.feishu_clear_secret;
                            cx.notify();
                        });
                    }),
                ))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .child(
                            div()
                                .text_size(px(11.))
                                .text_color(rgb(p.text_muted))
                                .child(fs_note),
                        )
                        .child(
                            div()
                                .flex()
                                .gap(px(8.))
                                .child(
                                    action_button("fs-test-btn", "发送脱敏测试", ButtonKind::Secondary, true, p)
                                        .on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                ctrl_fs_test.update(cx, |c, cx| {
                                                    let url = c.drafts.feishu_webhook.trim().to_string();
                                                    if !url.is_empty() && !url.starts_with("https://") {
                                                        c.set_toast("Webhook 必须以 https:// 开头", false, cx);
                                                    } else {
                                                        c.feishu_status_note = Some("已构造脱敏预览消息（不含出口 IP / 主机名）".into());
                                                        c.set_toast("脱敏测试消息已校验通过", true, cx);
                                                    }
                                                });
                                            }),
                                        ),
                                )
                                .child(
                                    action_button("fs-save-btn", "保存飞书配置", ButtonKind::Primary, true, p)
                                        .on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                ctrl_fs_save.update(cx, |c, cx| {
                                                    let url = c.drafts.feishu_webhook.trim().to_string();
                                                    if !url.is_empty() && !url.starts_with("https://") {
                                                        c.set_toast("Webhook 必须以 https:// 开头", false, cx);
                                                        return;
                                                    }
                                                    c.feishu_status_note = Some("飞书配置草稿已校验并就绪".into());
                                                    c.set_toast("飞书通知配置已保存", true, cx);
                                                });
                                            }),
                                        ),
                                ),
                        ),
                ),
        )
}

/// Zero-Input Smart First-Run Onboarding Modal.
pub fn render_onboarding_modal(
    ctrl: Entity<AppController>,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> gpui::Stateful<Div> {
    let ctrl_r = ctrl.read(cx);
    let mask = ctrl_r.privacy_mask;
    let selected = ctrl_r.drafts.onboarding_strategy;
    let probe = ctrl_r.onboarding_probe.clone();
    let loading = ctrl_r.onboarding_loading;
    let connected = ctrl_r.connected;
    let is_demo = ctrl_r.client.is_demo();
    let proxy_off_sim = ctrl_r.onboarding_proxy_off_sim;
    let cidr_in = ctrl_r.inputs.onboarding_cidr.clone();
    let reg_in = ctrl_r.inputs.onboarding_regions.clone();

    let ctrl_skip = ctrl.clone();
    let ctrl_done = ctrl.clone();
    let ctrl_reprobe = ctrl.clone();
    let ctrl_sim_toggle = ctrl.clone();

    let access_summary = probe
        .as_ref()
        .map(|pr| {
            let port = pr
                .detected_proxy_port
                .map(|port| format!(":{port} 系统代理"))
                .unwrap_or_else(|| pr.access.level.label().to_string());
            let apps = if pr.installed_agents.is_empty() {
                "待发现".into()
            } else {
                pr.installed_agents.join(" / ")
            };
            let exit = pr
                .probe
                .as_ref()
                .map(|p_res| {
                    let cc = p_res.country.as_deref().unwrap_or("--");
                    let city = p_res.city.as_deref().unwrap_or("");
                    let ip = p_res
                        .ip
                        .as_deref()
                        .map(|ip| {
                            if mask {
                                mask_ip_str(ip)
                            } else {
                                ip.to_string()
                            }
                        })
                        .unwrap_or_else(|| "--".into());
                    format!("{cc} · {city} {ip} ({}ms)", p_res.latency_ms)
                })
                .unwrap_or_else(|| "未探测到合规出口".into());
            (port, apps, exit, pr.standby_notice.clone())
        })
        .unwrap_or_else(|| {
            (
                "探测中…".into(),
                "扫描本机 AI 应用…".into(),
                "正在经代理探测当前出口…".into(),
                None,
            )
        });

    let options = probe
        .as_ref()
        .map(|pr| pr.options.clone())
        .unwrap_or_default();

    let radio_cards = options.into_iter().map(|opt| {
        let strat = opt.strategy;
        let active = strat == selected;
        let ctrl_opt = ctrl.clone();
        let title = if mask {
            crate::protocol::mask_ips_in_text(&opt.title)
        } else {
            opt.title.clone()
        };
        let sub = if mask {
            crate::protocol::mask_ips_in_text(&opt.subtitle)
        } else {
            opt.subtitle.clone()
        };

        div()
            .id(gpui::ElementId::Name(format!("onb-opt-{strat:?}").into()))
            .flex()
            .flex_col()
            .gap(px(4.))
            .p(px(12.))
            .rounded(px(12.))
            .cursor_pointer()
            .bg(rgb(if active {
                p.sidebar_active_bg
            } else {
                p.inset_bg
            }))
            .border_1()
            .border_color(rgb(if active {
                p.sidebar_active_border
            } else {
                p.inset_border
            }))
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(8.))
                            .child(
                                div()
                                    .w(px(12.))
                                    .h(px(12.))
                                    .rounded(px(999.))
                                    .border_2()
                                    .border_color(rgb(if active {
                                        p.primary_btn_bg
                                    } else {
                                        p.text_muted
                                    }))
                                    .when(active, |d| d.bg(rgb(p.primary_btn_bg))),
                            )
                            .child(
                                div()
                                    .text_size(px(13.))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .text_color(rgb(p.text_primary))
                                    .child(title),
                            ),
                    )
                    .when(opt.recommended, |d| {
                        d.child(status_pill("推荐方案", BadgeTone::Pass, p))
                    }),
            )
            .child(
                div()
                    .pl(px(20.))
                    .text_size(px(11.5))
                    .text_color(rgb(p.text_secondary))
                    .child(sub),
            )
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(move |_, _, _, cx| {
                    ctrl_opt.update(cx, |c, cx| {
                        c.drafts.onboarding_strategy = strat;
                        cx.notify();
                    });
                }),
            )
    });

    div()
        .id("onboarding-backdrop")
        .absolute()
        .inset_0()
        .occlude()
        .on_mouse_down(MouseButton::Left, |_, _, _| {})
        .bg(rgba(0x0B101ACC))
        .flex()
        .items_center()
        .justify_center()
        .p(px(14.))
        .child(
            bento_card(p)
                .id("onboarding-modal-card")
                .w(px(580.))
                .max_w_full()
                .max_h_full()
                .overflow_y_scroll()
                .p(px(18.))
                .gap(px(10.))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .gap(px(3.))
                                .child(
                                    div()
                                        .text_size(px(18.))
                                        .font_weight(FontWeight::BOLD)
                                        .text_color(rgb(p.text_primary))
                                        .child("零输入智能首启向导"),
                                )
                                .child(
                                    div()
                                        .text_size(px(12.))
                                        .text_color(rgb(p.text_muted))
                                        .child("已自动探测代理、AI 客户端与当前出口，1 次点击即可完成布防"),
                                ),
                        )
                        .when(is_demo, |d| {
                            d.child(
                                action_button(
                                    "onb-sim-proxy",
                                    if proxy_off_sim { "模拟：代理已开启" } else { "模拟：代理关闭" },
                                    ButtonKind::Secondary,
                                    true,
                                    p,
                                )
                                .on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_sim_toggle.update(cx, |c, cx| {
                                            c.onboarding_proxy_off_sim = !c.onboarding_proxy_off_sim;
                                            c.probe_onboarding(cx);
                                        });
                                    }),
                                ),
                            )
                        }),
                )
                // Auto-detected summary Bento strip
                .child(
                    div()
                        .flex()
                        .gap(px(10.))
                        .child(info_mini_box("接入检测", access_summary.0, p))
                        .child(info_mini_box("已发现 AI 应用", access_summary.1, p))
                        .child(info_mini_box("当前出口探测", access_summary.2, p)),
                )
                .when_some(access_summary.3, |card, standby| {
                    card.child(
                        div()
                            .p(px(11.))
                            .rounded(px(10.))
                            .bg(rgba(p.badge_warn.bg))
                            .text_size(px(12.))
                            .text_color(rgb(p.badge_warn.text))
                            .child(standby),
                    )
                })
                .child(div().flex().flex_col().gap(px(8.)).children(radio_cards))
                .when(selected == OnboardingStrategy::CustomCidrOrRegions, |card| {
                    card.child(
                        div()
                            .flex()
                            .gap(px(10.))
                            .child(labeled_field("自定义地区（ISO 代码）", reg_in, p))
                            .child(labeled_field("自定义 IP / CIDR", cidr_in, p)),
                    )
                })
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .pt(px(4.))
                        .child(
                            div()
                                .flex()
                                .gap(px(8.))
                                .child(
                                    action_button("onb-skip", "暂不布防（保持只读）", ButtonKind::Ghost, true, p)
                                        .on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                ctrl_skip.update(cx, |c, cx| c.skip_onboarding(cx));
                                            }),
                                        ),
                                )
                                .child(
                                    action_button("onb-reprobe", "↻ 重新探测", ButtonKind::Secondary, !loading, p)
                                        .on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                ctrl_reprobe.update(cx, |c, cx| c.probe_onboarding(cx));
                                            }),
                                        ),
                                ),
                        )
                        .child({
                            let can_complete = connected && !loading && probe.is_some();
                            action_button(
                                "onb-complete",
                                if connected {
                                    "✓ 一键保存并立即布防"
                                } else {
                                    "守护离线 · 无法完成布防"
                                },
                                ButtonKind::Primary,
                                can_complete,
                                p,
                            )
                            .when(can_complete, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_done.update(cx, |c, cx| c.complete_onboarding(cx));
                                    }),
                                )
                            })
                        }),
                ),
        )
}

fn info_mini_box(label: &'static str, value: String, p: &ThemePalette) -> Div {
    inset_box(p)
        .flex_1()
        .p(px(10.))
        .gap(px(3.))
        .child(
            div()
                .text_size(px(10.5))
                .text_color(rgb(p.text_muted))
                .child(label),
        )
        .child(
            mono_tabular(value)
                .text_size(px(12.))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(rgb(p.text_primary)),
        )
}

fn labeled_field(
    label: &'static str,
    input: Entity<crate::widgets::text_input::DraftTextInput>,
    p: &ThemePalette,
) -> Div {
    div()
        .flex_1()
        .flex()
        .flex_col()
        .gap(px(4.))
        .child(
            div()
                .text_size(px(11.5))
                .font_weight(FontWeight::MEDIUM)
                .text_color(rgb(p.text_secondary))
                .child(label),
        )
        .child(input)
}

fn switch_row(
    id: &'static str,
    title: &'static str,
    hint: &'static str,
    on: bool,
    p: &ThemePalette,
    on_click: impl Fn(&gpui::MouseUpEvent, &mut gpui::Window, &mut gpui::App) + 'static,
) -> Div {
    inset_box(p)
        .flex_row()
        .items_center()
        .justify_between()
        .px(px(12.))
        .py(px(9.))
        .gap(px(12.))
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(2.))
                .flex_1()
                .min_w(px(0.))
                .child(
                    div()
                        .text_size(px(12.5))
                        .font_weight(FontWeight::MEDIUM)
                        .text_color(rgb(p.text_primary))
                        .child(title),
                )
                .child(
                    div()
                        .text_size(px(11.))
                        .text_color(rgb(p.text_muted))
                        .child(hint),
                ),
        )
        .child(toggle_switch(id, on, true, p).on_mouse_up(MouseButton::Left, on_click))
}
