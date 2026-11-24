//! Mode B — Frost Ceramic `目标与白名单` view.
//!
//! Features:
//! - Compact single-line global proxy/interval/threshold toolbar with dirty indicator
//! - Collapsible `+ 新增目标` drawer
//! - Per-target cards with brand icons, live status, visual 12-region multi-select picker,
//!   static IP/CIDR input, and connectivity-only hint bar
//! - Bottom 3-column plain-language guide card

use crate::app::{ActionScope, AppController, ConsoleWindowView, EnvSubTab};
use crate::assets::{brand_icon_scaled, ui_icon};
use crate::motion::PageChoreo;
use crate::protocol::{AnchorKind, PipeRequest, TargetState, UiLabelExt};
use crate::state::{NavSection, split_tokens};
use crate::theme::ThemePalette;
use crate::views::shared::page_guide_card;
use crate::widgets::controls::{
    ButtonKind, action_button, bento_card_bloom, icon_action_button, inset_box, mono_tabular,
    spinning_ui_icon, status_dot, toggle_switch,
};
use crate::widgets::text_input::DraftTextInput;
use gpui::{Context, Div, Entity, FontWeight, MouseButton, div, prelude::*, px, relative, rgb};

const REGION_CATALOG: [(&str, &str); 12] = [
    ("US", "美国"),
    ("JP", "日本"),
    ("SG", "新加坡"),
    ("GB", "英国"),
    ("CA", "加拿大"),
    ("DE", "德国"),
    ("TW", "台湾"),
    ("KR", "韩国"),
    ("AU", "澳大利亚"),
    ("NL", "荷兰"),
    ("FR", "法国"),
    ("CH", "瑞士"),
];

fn region_chip_label(code: &str) -> String {
    let upper = code.trim().to_ascii_uppercase();
    for (c, cn) in REGION_CATALOG {
        if c == upper {
            return format!("{cn} {c}");
        }
    }
    upper
}

fn render_region_selector(
    ctrl: Entity<AppController>,
    target_id: String,
    selected_codes: Vec<String>,
    custom_input: Option<Entity<DraftTextInput>>,
    is_open: bool,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> Div {
    let hover_bg = p.sidebar_hover_bg;
    let danger_txt = p.badge_fail.text;
    let ctrl_open = ctrl.clone();
    let tid_open = target_id.clone();

    let selected_tags = selected_codes.iter().map(|code| {
        let code_cl = code.clone();
        let tid_rm = target_id.clone();
        let ctrl_rm = ctrl.clone();
        div()
            .flex()
            .items_center()
            .gap(px(4.))
            .h(px(22.))
            .px(px(7.))
            .rounded(px(6.))
            .bg(rgb(p.accent_soft_bg))
            .border_1()
            .border_color(rgb(p.accent_soft_border))
            .text_size(px(11.))
            .font_weight(FontWeight::MEDIUM)
            .text_color(rgb(p.accent_soft_text))
            .child(region_chip_label(code))
            .child(
                div()
                    .id(gpui::ElementId::Name(
                        format!("reg-rm-{target_id}-{code}").into(),
                    ))
                    .cursor_pointer()
                    .text_size(px(12.))
                    .text_color(rgb(p.text_muted))
                    .hover(move |s| s.text_color(rgb(danger_txt)))
                    .child("×")
                    .on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |_, _, _, cx| {
                            cx.stop_propagation();
                            ctrl_rm.update(cx, |c, cx| {
                                c.toggle_target_region(&tid_rm, &code_cl, cx);
                            });
                        }),
                    ),
            )
    });

    let tag_bar = div()
        .flex()
        .flex_wrap()
        .items_center()
        .gap(px(5.))
        .min_h(px(30.))
        .px(px(6.))
        .py(px(3.))
        .rounded(px(8.))
        .bg(rgb(p.input_bg))
        .border_1()
        .border_color(rgb(if is_open {
            p.input_focus_border
        } else {
            p.input_border
        }))
        .when(selected_codes.is_empty(), |bar| {
            bar.child(
                div()
                    .pl(px(3.))
                    .text_size(px(11.))
                    .text_color(rgb(p.text_muted))
                    .child("未限定地区"),
            )
        })
        .children(selected_tags)
        .child(
            div()
                .id(gpui::ElementId::Name(
                    format!("reg-pick-btn-{target_id}").into(),
                ))
                .flex()
                .items_center()
                .gap(px(3.))
                .h(px(22.))
                .px(px(7.))
                .rounded(px(6.))
                .border_1()
                .border_color(rgb(p.line_strong))
                .cursor_pointer()
                .hover(move |s| s.bg(rgb(hover_bg)))
                .text_size(px(11.))
                .font_weight(FontWeight::MEDIUM)
                .text_color(rgb(p.text_secondary))
                .child("＋ 选择地区")
                .child(ui_icon("icons/ui/chevrons.svg", 10.5, p.text_muted))
                .on_mouse_up(
                    MouseButton::Left,
                    cx.listener(move |_, _, _, cx| {
                        cx.stop_propagation();
                        let id = tid_open.clone();
                        ctrl_open.update(cx, |c, cx| {
                            if c.open_region_picker_for.as_deref() == Some(id.as_str()) {
                                c.open_region_picker_for = None;
                            } else {
                                c.open_region_picker_for = Some(id);
                                c.policy_menu_open = false;
                            }
                            cx.notify();
                        });
                    }),
                ),
        );

    let mut wrapper = div().flex().flex_col().gap(px(6.)).child(tag_bar);

    if is_open {
        let ctrl_done = ctrl.clone();
        let rows: Vec<Div> = REGION_CATALOG
            .chunks(4)
            .map(|chunk| {
                let cells = chunk.iter().map(|(code, cn)| {
                    let on = selected_codes.iter().any(|s| s.eq_ignore_ascii_case(code));
                    let tid_c = target_id.clone();
                    let code_s = (*code).to_string();
                    let ctrl_t = ctrl.clone();
                    let bg = if on { p.accent_soft_bg } else { p.inset_bg };
                    let txt = if on {
                        p.accent_soft_text
                    } else {
                        p.text_secondary
                    };
                    let bdr = if on {
                        p.accent_soft_border
                    } else {
                        p.card_border
                    };
                    let hov = if on {
                        p.accent_soft_bg
                    } else {
                        p.sidebar_hover_bg
                    };
                    div()
                        .id(gpui::ElementId::Name(
                            format!("reg-opt-{target_id}-{code}").into(),
                        ))
                        .flex()
                        .flex_1()
                        .flex_basis(px(0.))
                        .items_center()
                        .justify_between()
                        .h(px(27.))
                        .px(px(8.))
                        .rounded(px(7.))
                        .bg(rgb(bg))
                        .border_1()
                        .border_color(rgb(bdr))
                        .cursor_pointer()
                        .hover(move |s| s.bg(rgb(hov)).opacity(0.92))
                        .active(|s| s.opacity(0.84))
                        .text_size(px(11.))
                        .font_weight(if on {
                            FontWeight::SEMIBOLD
                        } else {
                            FontWeight::MEDIUM
                        })
                        .text_color(rgb(txt))
                        .child(*cn)
                        .child(mono_tabular(*code).text_size(px(10.)).text_color(rgb(txt)))
                        .on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |_, _, _, cx| {
                                cx.stop_propagation();
                                ctrl_t.update(cx, |c, cx| {
                                    c.toggle_target_region(&tid_c, &code_s, cx);
                                });
                            }),
                        )
                });
                div().flex().w_full().gap(px(5.)).children(cells)
            })
            .collect();

        wrapper = wrapper.child(
            div()
                .id(gpui::ElementId::Name(
                    format!("reg-panel-{target_id}").into(),
                ))
                .flex()
                .flex_col()
                .gap(px(6.))
                .p(px(9.))
                .rounded(px(10.))
                .bg(rgb(p.card_bg))
                .border_1()
                .border_color(rgb(p.line_strong))
                .on_mouse_up(MouseButton::Left, |_, _, cx| {
                    cx.stop_propagation();
                })
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .child(
                            div()
                                .text_size(px(11.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.text_primary))
                                .child("点选或输入两字母 ISO 代码"),
                        )
                        .child(
                            div()
                                .id(gpui::ElementId::Name(
                                    format!("reg-done-{target_id}").into(),
                                ))
                                .cursor_pointer()
                                .text_size(px(11.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.link_text))
                                .child("完成")
                                .on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        cx.stop_propagation();
                                        ctrl_done.update(cx, |c, cx| {
                                            c.open_region_picker_for = None;
                                            cx.notify();
                                        });
                                    }),
                                ),
                        ),
                )
                .children(rows)
                .when_some(custom_input, |panel, inp| {
                    panel.child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(6.))
                            .pt(px(3.))
                            .child(
                                div()
                                    .flex_shrink_0()
                                    .text_size(px(10.5))
                                    .text_color(rgb(p.text_muted))
                                    .child("代码列表"),
                            )
                            .child(div().flex_1().child(inp)),
                    )
                }),
        );
    }

    wrapper
}

pub fn render_targets_page(
    ctrl: Entity<AppController>,
    choreo: PageChoreo,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> Div {
    let ctrl_r = ctrl.read(cx);
    let snap = ctrl_r.snapshot.clone();
    let dirty = ctrl_r.drafts.dirty;
    let targets = ctrl_r.drafts.targets.clone();
    let show_drawer = ctrl_r.show_add_target_drawer;
    let open_picker = ctrl_r.open_region_picker_for.clone();
    let new_regions_raw = ctrl_r.drafts.new_target_regions.clone();
    let busy = ctrl_r.busy_action;
    let connected = ctrl_r.connected;
    let can_act = connected && !busy;
    let active_preset = snap
        .as_ref()
        .map(|s| s.preset)
        .unwrap_or(crate::protocol::PolicyPreset::StandardRegion);

    let port_in = ctrl_r.inputs.proxy_port.clone();
    let interval_in = ctrl_r.inputs.interval_secs.clone();
    let thresh_in = ctrl_r.inputs.trip_threshold.clone();
    let new_name = ctrl_r.inputs.new_target_name.clone();
    let new_url = ctrl_r.inputs.new_target_url.clone();
    let new_ips = ctrl_r.inputs.new_target_ips.clone();
    let new_reg_input = ctrl_r.inputs.new_target_regions.clone();
    let ip_map = ctrl_r.inputs.target_ips.clone();
    let reg_map = ctrl_r.inputs.target_regions.clone();
    let busy_targets: std::collections::HashSet<String> = ctrl_r
        .in_flight
        .iter()
        .filter_map(|scope| match scope {
            ActionScope::RecheckTarget(id) => Some(id.clone()),
            _ => None,
        })
        .collect();

    let ctrl_toggle_drawer = ctrl.clone();
    let ctrl_close_drawer = ctrl.clone();
    let ctrl_save = ctrl.clone();
    let ctrl_reset = ctrl.clone();
    let ctrl_add = ctrl.clone();

    // -------------------------------------------------------------------------
    // Top Global Params Bar
    // -------------------------------------------------------------------------
    let global_bar = bento_card_bloom(p, 16.0, 10.0, choreo.tile(0, 0))
        .flex_1()
        .flex_row()
        .flex_wrap()
        .items_center()
        .justify_between()
        .gap(px(10.))
        .child(
            div()
                .flex()
                .flex_wrap()
                .items_center()
                .gap(px(14.))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(6.))
                        .child(
                            div()
                                .text_size(px(12.))
                                .text_color(rgb(p.text_secondary))
                                .child("本地代理端口"),
                        )
                        .child(div().w(px(70.)).child(port_in)),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(6.))
                        .child(
                            div()
                                .text_size(px(12.))
                                .text_color(rgb(p.text_secondary))
                                .child("巡检间隔"),
                        )
                        .child(div().w(px(54.)).child(interval_in))
                        .child(
                            div()
                                .text_size(px(11.))
                                .text_color(rgb(p.text_muted))
                                .child("秒"),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(6.))
                        .child(
                            div()
                                .text_size(px(12.))
                                .text_color(rgb(p.text_secondary))
                                .child("连续失败阈值"),
                        )
                        .child(div().w(px(48.)).child(thresh_in))
                        .child(
                            div()
                                .text_size(px(11.))
                                .text_color(rgb(p.text_muted))
                                .child("次"),
                        ),
                ),
        )
        .child(
            div()
                .flex()
                .items_center()
                .gap(px(7.))
                .flex_shrink_0()
                .when(dirty, |row| {
                    row.child(
                        div()
                            .text_size(px(11.))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(rgb(p.badge_warn.text))
                            .child("● 未保存"),
                    )
                })
                .child(
                    icon_action_button(
                        "tgt-toggle-drawer",
                        "icons/ui/plus.svg",
                        "新增目标",
                        ButtonKind::Secondary,
                        true,
                        p,
                    )
                    .h(px(28.))
                    .px(px(10.))
                    .on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |_, _, _, cx| {
                            ctrl_toggle_drawer.update(cx, |c, cx| {
                                c.show_add_target_drawer = !c.show_add_target_drawer;
                                cx.notify();
                            });
                        }),
                    ),
                )
                .when(dirty, |row| {
                    row.child(
                        action_button("tgt-reset-btn", "撤销", ButtonKind::Secondary, !busy, p)
                            .h(px(28.))
                            .px(px(10.))
                            .when(!busy, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_reset.update(cx, |c, cx| c.reset_target_drafts(cx));
                                    }),
                                )
                            }),
                    )
                })
                .child(
                    action_button(
                        "tgt-save-btn",
                        if connected {
                            "保存配置"
                        } else {
                            "守护离线"
                        },
                        ButtonKind::Primary,
                        can_act,
                        p,
                    )
                    .h(px(28.))
                    .px(px(12.))
                    .when(can_act, |b| {
                        b.on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |_, _, _, cx| {
                                ctrl_save.update(cx, |c, cx| c.save_target_drafts(cx));
                            }),
                        )
                    }),
                ),
        );

    // -------------------------------------------------------------------------
    // Collapsible Add Custom Target Drawer
    // -------------------------------------------------------------------------
    let new_reg_codes: Vec<String> = split_tokens(&new_regions_raw)
        .into_iter()
        .map(|s| s.to_ascii_uppercase())
        .collect();

    let add_drawer = show_drawer.then(|| {
        bento_card_bloom(p, 16.0, 12.0, choreo.tile(0, 1))
            .flex_1()
            .gap(px(9.))
            .border_color(rgb(p.primary_btn_bg))
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
                            .child("新增监控目标"),
                    )
                    .child(
                        div()
                            .text_size(px(11.))
                            .text_color(rgb(p.text_muted))
                            .child("填写探测网址与放行规则"),
                    ),
            )
            .child(
                div()
                    .flex()
                    .w_full()
                    .gap(px(8.))
                    .child(div().w(relative(0.36)).child(new_name))
                    .child(div().flex_1().child(new_url)),
            )
            .child(
                div()
                    .flex()
                    .w_full()
                    .items_start()
                    .gap(px(8.))
                    .child(div().w(relative(0.44)).child(new_ips))
                    .child(div().flex_1().child(render_region_selector(
                        ctrl.clone(),
                        "__new__".into(),
                        new_reg_codes,
                        Some(new_reg_input),
                        open_picker.as_deref() == Some("__new__"),
                        p,
                        cx,
                    ))),
            )
            .child(
                div()
                    .flex()
                    .justify_end()
                    .gap(px(7.))
                    .child(
                        action_button("tgt-drawer-cancel", "取消", ButtonKind::Secondary, true, p)
                            .h(px(27.))
                            .on_mouse_up(
                                MouseButton::Left,
                                cx.listener(move |_, _, _, cx| {
                                    ctrl_close_drawer.update(cx, |c, cx| {
                                        c.show_add_target_drawer = false;
                                        cx.notify();
                                    });
                                }),
                            ),
                    )
                    .child(
                        action_button(
                            "tgt-drawer-submit",
                            "添加目标",
                            ButtonKind::Primary,
                            true,
                            p,
                        )
                        .h(px(27.))
                        .on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |_, _, _, cx| {
                                ctrl_add.update(cx, |c, cx| {
                                    c.add_custom_target_from_draft(cx);
                                    if c.drafts.validation_error.is_none() {
                                        c.show_add_target_drawer = false;
                                    }
                                });
                            }),
                        ),
                    ),
            )
    });

    // -------------------------------------------------------------------------
    // Target Cards
    // -------------------------------------------------------------------------
    let target_cards = targets.into_iter().enumerate().map(|(idx, t)| {
        let live = snap
            .as_ref()
            .and_then(|s| s.targets.iter().find(|x| x.id == t.id));
        let is_reach_only = t.anchor_kind == AnchorKind::Reachability;
        let is_fail = live.is_some_and(|s| s.state == TargetState::Fail);
        let is_pass = live.is_some_and(|s| s.state == TargetState::Pass);
        let status_dot_color = if !t.enabled {
            p.text_muted
        } else if is_fail {
            p.badge_fail.dot
        } else if is_pass {
            p.badge_pass.dot
        } else {
            p.badge_warn.dot
        };
        let status_color = if !t.enabled {
            p.text_muted
        } else if is_fail {
            p.badge_fail.text
        } else if is_pass {
            p.text_primary
        } else {
            p.badge_warn.text
        };
        let status_summary = if !t.enabled {
            "已停用".to_string()
        } else if let Some(ls) = live {
            let ms_txt = if ls.latency_ms > 0 {
                format!(" · {}ms", ls.latency_ms)
            } else {
                String::new()
            };
            if is_reach_only {
                if is_pass {
                    format!("● 代理连通{ms_txt}")
                } else if ls.state == TargetState::Unverified {
                    format!("● 暂不可达（波动）{ms_txt}")
                } else {
                    format!("● {}{ms_txt}", ls.state.label())
                }
            } else if let Some(cc) = ls.country.as_deref().filter(|s| !s.is_empty()) {
                let lbl = region_chip_label(cc);
                if is_fail {
                    format!("● {lbl} · 越界{ms_txt}")
                } else {
                    format!("● {lbl}{ms_txt}")
                }
            } else {
                format!("● {}{ms_txt}", ls.state.label())
            }
        } else {
            "● 待探测".to_string()
        };

        let tid_en = t.id.clone();
        let tid_recheck = t.id.clone();
        let tid_del = t.id.clone();
        let tid_kind = t.id.clone();
        let tname_rc = t.name.clone();
        let ctrl_en = ctrl.clone();
        let ctrl_rc = ctrl.clone();
        let ctrl_del = ctrl.clone();
        let ctrl_kind = ctrl.clone();
        let ctrl_ag_jump = ctrl.clone();

        let ip_input = ip_map.get(&t.id).cloned();
        let reg_input = reg_map.get(&t.id).cloned();
        let region_codes: Vec<String> = split_tokens(&t.expect_regions_text)
            .into_iter()
            .map(|s| s.to_ascii_uppercase())
            .collect();
        let picker_open = open_picker.as_deref() == Some(t.id.as_str());
        let saved_on_daemon = live.is_some();
        let can_recheck = can_act && t.enabled && saved_on_daemon;
        let target_busy = busy_targets.contains(&t.id);
        let fail_reason = live
            .filter(|ls| matches!(ls.state, TargetState::Fail | TargetState::Unverified))
            .map(|ls| ls.reason.trim().to_string())
            .filter(|r| !r.is_empty());
        let del_hover_bg = p.danger_soft_bg;
        let del_hover_bdr = p.danger_soft_border;
        let del_hover_fg = p.danger_soft_text;

        let card_pose = choreo.tile(1 + (idx / 2).min(2), idx % 2);
        let icon_scale = choreo.icon_scale(0, idx);

        let card = bento_card_bloom(p, 14.0, 9.0, card_pose)
            .flex_1()
            .gap(px(6.))
            .when(!t.enabled, |c| c.bg(rgb(p.guide_bg)))
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
                            .gap(px(10.))
                            .min_w(px(0.))
                            .flex_1()
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
                                        ctrl_en.update(cx, |c, cx| {
                                            c.toggle_target_draft_enabled(&tid_en, cx);
                                        });
                                    }),
                                ),
                            )
                            .child(brand_icon_scaled(&t.id, 24.0, 6.5, p.is_dark, icon_scale))
                            .child(
                                div()
                                    .flex()
                                    .flex_col()
                                    .min_w(px(0.))
                                    .flex_1()
                                    .gap(px(1.))
                                    .child(
                                        div()
                                            .truncate()
                                            .text_size(px(12.5))
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(rgb(if t.enabled {
                                                p.text_primary
                                            } else {
                                                p.text_muted
                                            }))
                                            .child(t.name.clone()),
                                    )
                                    .child(
                                        mono_tabular(t.anchor_url.clone())
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
                            .gap(px(8.))
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap(px(5.))
                                    .when(t.enabled, |r| r.child(status_dot(status_dot_color, 5.5)))
                                    .child(
                                        mono_tabular(
                                            status_summary.trim_start_matches("● ").to_string(),
                                        )
                                        .text_size(px(11.5))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(status_color)),
                                    ),
                            )
                            .child({
                                let rc_fg = if can_recheck {
                                    p.secondary_btn_text
                                } else {
                                    p.text_muted
                                };
                                let rc_bg = if can_recheck {
                                    p.secondary_btn_bg
                                } else {
                                    p.inset_bg
                                };
                                let rc_bdr = if can_recheck {
                                    p.secondary_btn_border
                                } else {
                                    p.inset_border
                                };
                                let rc_hov = p.sidebar_hover_bg;
                                div()
                                    .id(gpui::ElementId::Name(
                                        format!("tgt-recheck-{}", t.id).into(),
                                    ))
                                    .flex()
                                    .flex_shrink_0()
                                    .items_center()
                                    .gap(px(4.5))
                                    .h(px(25.))
                                    .px(px(9.))
                                    .rounded(px(8.))
                                    .bg(rgb(rc_bg))
                                    .border_1()
                                    .border_color(rgb(rc_bdr))
                                    .text_size(px(11.))
                                    .font_weight(FontWeight::MEDIUM)
                                    .text_color(rgb(rc_fg))
                                    .child(spinning_ui_icon(
                                        gpui::ElementId::Name(format!("tgt-spin-{}", t.id).into()),
                                        "icons/ui/refresh.svg",
                                        11.0,
                                        rc_fg,
                                        target_busy,
                                    ))
                                    .child(if target_busy {
                                        "重检中"
                                    } else if !saved_on_daemon {
                                        "待保存"
                                    } else {
                                        "重检"
                                    })
                                    .when(can_recheck, |b| {
                                        b.cursor_pointer()
                                            .hover(move |s| s.bg(rgb(rc_hov)))
                                            .active(|s| s.opacity(0.88))
                                            .on_mouse_up(
                                                MouseButton::Left,
                                                cx.listener(move |_, _, _, cx| {
                                                    let id = tid_recheck.clone();
                                                    let msg = format!("已重检：{tname_rc}");
                                                    ctrl_rc.update(cx, |c, cx| {
                                                        c.send_request_msg(
                                                            PipeRequest::RecheckNow {
                                                                target_id: Some(id),
                                                            },
                                                            Some(msg),
                                                            cx,
                                                        );
                                                    });
                                                }),
                                            )
                                    })
                            })
                            .when(!t.builtin, |row| {
                                row.child(
                                    action_button(
                                        gpui::ElementId::Name(format!("tgt-kind-{}", t.id).into()),
                                        format!("模式：{}", t.anchor_kind.label()),
                                        ButtonKind::Secondary,
                                        true,
                                        p,
                                    )
                                    .h(px(25.))
                                    .px(px(8.))
                                    .text_size(px(10.5))
                                    .on_mouse_up(
                                        MouseButton::Left,
                                        cx.listener(move |_, _, _, cx| {
                                            ctrl_kind.update(cx, |c, cx| {
                                                c.cycle_target_draft_kind(&tid_kind, cx);
                                            });
                                        }),
                                    ),
                                )
                                .child(
                                    div()
                                        .id(gpui::ElementId::Name(
                                            format!("tgt-del-{}", t.id).into(),
                                        ))
                                        .flex()
                                        .items_center()
                                        .justify_center()
                                        .w(px(25.))
                                        .h(px(25.))
                                        .rounded(px(7.))
                                        .bg(rgb(p.secondary_btn_bg))
                                        .border_1()
                                        .border_color(rgb(p.secondary_btn_border))
                                        .text_color(rgb(p.text_muted))
                                        .cursor_pointer()
                                        .hover(move |s| {
                                            s.bg(rgb(del_hover_bg))
                                                .border_color(rgb(del_hover_bdr))
                                                .text_color(rgb(del_hover_fg))
                                        })
                                        .active(|s| s.opacity(0.86))
                                        .child(
                                            gpui::svg()
                                                .path("icons/ui/trash.svg")
                                                .size(px(12.0))
                                                .flex_shrink_0(),
                                        )
                                        .on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                ctrl_del.update(cx, |c, cx| {
                                                    c.delete_target_draft(&tid_del, cx);
                                                });
                                            }),
                                        ),
                                )
                            }),
                    ),
            )
            .when_some(fail_reason, |card, reason| {
                card.child(
                    div()
                        .text_size(px(11.))
                        .text_color(rgb(status_color))
                        .child(format!("探测详情：{reason}")),
                )
            })
            .when(t.enabled, |card| {
                let ip_active = matches!(
                    active_preset,
                    crate::protocol::PolicyPreset::StrictStaticIp
                        | crate::protocol::PolicyPreset::StandardRegion
                );
                let region_active = active_preset == crate::protocol::PolicyPreset::StandardRegion;
                card.child(if is_reach_only {
                    inset_box(p)
                        .flex_row()
                        .items_center()
                        .justify_between()
                        .px(px(10.))
                        .py(px(5.5))
                        .gap(px(10.))
                        .child(
                            div()
                                .flex_1()
                                .min_w(px(0.))
                                .text_size(px(11.5))
                                .text_color(rgb(p.text_secondary))
                                .child("仅核验代理连通与延迟，不限地区或静态 IP。"),
                        )
                        .child(
                            div()
                                .id(gpui::ElementId::Name(
                                    format!("tgt-ag-jump-{}", t.id).into(),
                                ))
                                .flex_shrink_0()
                                .cursor_pointer()
                                .text_size(px(11.5))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.link_text))
                                .hover(|s| s.opacity(0.80))
                                .child("查看代理注入 →")
                                .on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_ag_jump.update(cx, |c, cx| {
                                            c.env_tab = EnvSubTab::Antigravity;
                                            c.set_nav(NavSection::Environment, cx);
                                        });
                                    }),
                                ),
                        )
                } else {
                    div()
                        .flex()
                        .flex_row()
                        .items_start()
                        .w_full()
                        .min_w(px(0.))
                        .gap(px(10.))
                        .child(
                            div()
                                .w(relative(0.43))
                                .flex()
                                .flex_col()
                                .gap(px(3.))
                                .when(!ip_active, |d| d.opacity(0.62))
                                .child(
                                    div()
                                        .text_size(px(10.5))
                                        .text_color(rgb(p.text_muted))
                                        .child("静态 IP / CIDR（标准 / 严格生效）"),
                                )
                                .when_some(ip_input, |d, inp| d.child(inp)),
                        )
                        .child(
                            div()
                                .flex_1()
                                .min_w(px(0.))
                                .flex()
                                .flex_col()
                                .gap(px(3.))
                                .when(!region_active, |d| d.opacity(0.62))
                                .child(
                                    div()
                                        .text_size(px(10.5))
                                        .text_color(rgb(p.text_muted))
                                        .child("放行国家 / 地区（标准策略生效）"),
                                )
                                .child(render_region_selector(
                                    ctrl.clone(),
                                    t.id.clone(),
                                    region_codes,
                                    reg_input,
                                    picker_open,
                                    p,
                                    cx,
                                )),
                        )
                })
            });
        div().w_full().min_w(px(0.)).flex().child(card)
    });

    let guide = page_guide_card(
        "策略与校验说明",
        "点「保存配置」或 Ctrl+S 生效",
        &[
            (
                "1. 三档策略",
                "宽松仅测代理可达；标准匹配地区或静态 IP；严格仅放行静态 IP。",
            ),
            (
                "2. 防抖熔断",
                "定时只读探测，连续失败达阈值（1–5 次）才熔断，避免偶发抖动误封。",
            ),
            (
                "3. 自定义扩展",
                "内置官方最优端点，可点「新增目标」扩展站点或在地区栏输入代码。",
            ),
        ],
        p,
    );

    div()
        .flex()
        .flex_col()
        .w_full()
        .min_w(px(0.))
        .gap(px(10.))
        .child(div().w_full().min_w(px(0.)).flex().child(global_bar))
        .when_some(add_drawer, |root, drawer| {
            root.child(div().w_full().min_w(px(0.)).flex().child(drawer))
        })
        .child(div().flex().flex_col().gap(px(7.)).children(target_cards))
        .child(choreo.slot(4).apply(guide))
}
