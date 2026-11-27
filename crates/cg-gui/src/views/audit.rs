//! Mode B — Frost Ceramic v2 `时间线与审计` view.
//!
//! Features:
//! - Interactive 48-bar 24h compliance trajectory with live hover readout
//! - Search input with clear `×` button + Enter server-side query + harmonized ceramic filter pills
//! - Responsive virtualized `uniform_list` audit log stream + expandable full-message bar & click-to-copy

use crate::app::{ActionScope, AppController, ConsoleWindowView};
use crate::assets::ui_icon;
use crate::motion::PageChoreo;
use crate::protocol::{LogLevel, PipeRequest, TimelineStatus, UiLabelExt};
use crate::state::{ConsoleProjection, format_unix_hm, format_unix_ymdhms};
use crate::theme::ThemePalette;
use crate::widgets::controls::{
    ButtonKind, action_button, bento_card_bloom, inset_box, mono_tabular, spinning_action_button,
    spinning_ui_icon, status_dot,
};
use gpui::{
    BoxShadow, Context, Div, Entity, FontWeight, MouseButton, div, prelude::*, px, rgb, rgba,
    uniform_list,
};

pub fn render_audit_page(
    ctrl: Entity<AppController>,
    proj: &ConsoleProjection,
    choreo: PageChoreo,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> Div {
    let ctrl_r = ctrl.read(cx);
    let scroll_handle = ctrl_r.audit_list_scroll.clone();
    let has_bucket = ctrl_r.selected_bucket.is_some();
    let hovered_bucket = ctrl_r.hovered_bucket;
    let active_level = ctrl_r.audit_level_filter;
    let selected_log_id = ctrl_r.selected_log_id;
    let search_non_empty = !ctrl_r.drafts.search_query.trim().is_empty();
    let search_input = ctrl_r.inputs.search.clone();
    let logs_loading = ctrl_r.logs_loading;
    let export_busy = ctrl_r.is_scope_busy(&ActionScope::ExportDiagnostics);
    let health_card_busy = ctrl_r.is_scope_busy(&ActionScope::BuildHealthCard);
    let total_server = ctrl_r.queried_logs_total;
    let connected = ctrl_r.connected;
    let busy = ctrl_r.busy_action;

    let ctrl_clear = ctrl.clone();
    let ctrl_refresh = ctrl.clone();
    let ctrl_copy_batch = ctrl.clone();
    let ctrl_health_card = ctrl.clone();
    let ctrl_export = ctrl.clone();
    let ctrl_reset_all = ctrl.clone();
    let ctrl_clear_search = ctrl.clone();

    let mut non_empty = 0u32;
    let mut pass_bars = 0u32;
    let bars: Vec<_> = proj
        .timeline_bars
        .iter()
        .map(|bar| {
            let color = match bar.status {
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
            let idx = bar.index;
            let elevated = bar.selected || hovered_bucket == Some(idx);
            let ctrl_b = ctrl.clone();
            let ctrl_h = ctrl.clone();

            let mut el = div()
                .id(("audit-bar", idx))
                .flex_1()
                .min_w(px(3.))
                .h(px(if elevated { 26.0 } else { 18.0 }))
                .rounded(px(2.5))
                .bg(rgb(color))
                .cursor_pointer()
                .on_hover(cx.listener(move |_, hovered, _, cx| {
                    ctrl_h.update(cx, |c, cx| {
                        let next = if *hovered {
                            Some(idx)
                        } else if c.hovered_bucket == Some(idx) {
                            None
                        } else {
                            c.hovered_bucket
                        };
                        if c.hovered_bucket != next {
                            c.hovered_bucket = next;
                            cx.notify();
                        }
                    });
                }))
                .on_mouse_up(
                    MouseButton::Left,
                    cx.listener(move |_, _, _, cx| {
                        ctrl_b.update(cx, |c, cx| c.select_timeline_bucket(idx, false, cx));
                    }),
                );
            if bar.selected {
                el = el.border_1().border_color(rgb(p.primary_btn_bg));
            }
            el
        })
        .collect();

    let compliance_ratio = if non_empty == 0 {
        None
    } else {
        Some((pass_bars as f64 / non_empty as f64) * 100.0)
    };
    let (compliance_txt, compliance_color, compliance_dot) = match compliance_ratio {
        None => ("暂无采样".to_string(), p.text_muted, None),
        Some(pct) if pct >= 95.0 => (
            format!("{pct:.1}% 合规"),
            p.text_primary,
            Some(p.badge_pass.dot),
        ),
        Some(pct) if pct >= 70.0 => (
            format!("{pct:.1}% 合规"),
            p.badge_warn.text,
            Some(p.badge_warn.dot),
        ),
        Some(pct) => (
            format!("{pct:.1}% 合规"),
            p.badge_fail.text,
            Some(p.badge_fail.dot),
        ),
    };

    let timeline_summary = if let Some(h_idx) = hovered_bucket
        && let Some(b) = proj.timeline_bars.get(h_idx)
    {
        format!(
            "{} · {} · 通过 {} / 告警 {} / 失败 {} · 均值 {}ms",
            format_unix_hm(b.bucket_start),
            b.status.label(),
            b.pass_count,
            b.warn_count,
            b.fail_count,
            b.avg_latency_ms
        )
    } else if has_bucket {
        proj.selected_bucket_summary.clone()
    } else {
        "每格 30 分钟 · 点击柱条按时段筛选".to_string()
    };

    let all_count = proj.filtered_logs.len();
    let logs: Vec<_> = proj
        .filtered_logs
        .iter()
        .filter(|entry| active_level.is_none_or(|lvl| entry.level == lvl))
        .cloned()
        .collect();
    let log_count = logs.len();
    let logs_for_batch_copy = logs.clone();
    let selected_log = selected_log_id.and_then(|id| logs.iter().find(|l| l.id == id).cloned());
    let palette_for_list = p;

    let level_chips = [
        (None, "全部"),
        (Some(LogLevel::Info), "信息"),
        (Some(LogLevel::Warn), "告警"),
        (Some(LogLevel::Error), "熔断"),
        (Some(LogLevel::Audit), "审计"),
    ]
    .into_iter()
    .map(|(lvl, label)| {
        let on = active_level == lvl;
        let ctrl_l = ctrl.clone();
        let hover_bg = p.sidebar_hover_bg;
        let hover_txt = p.text_primary;
        let mut chip = div()
            .id(gpui::ElementId::Name(format!("audit-lvl-{label}").into()))
            .flex()
            .items_center()
            .justify_center()
            .h(px(24.))
            .px(px(9.))
            .rounded(px(6.5))
            .cursor_pointer()
            .text_size(px(11.))
            .font_weight(if on {
                FontWeight::SEMIBOLD
            } else {
                FontWeight::MEDIUM
            })
            .text_color(rgb(if on { p.text_primary } else { p.text_secondary }))
            .active(|s| s.opacity(0.86))
            .child(label)
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(move |_, _, _, cx| {
                    ctrl_l.update(cx, |c, cx| {
                        c.audit_level_filter = lvl;
                        cx.notify();
                    });
                }),
            );
        if on {
            chip = chip.bg(rgb(p.card_bg)).shadow(vec![
                BoxShadow::new(px(0.), px(1.), rgba(p.shadow_rgba).into()).blur_radius(px(3.)),
            ]);
        } else {
            chip = chip.hover(move |s| s.bg(rgb(hover_bg)).text_color(rgb(hover_txt)));
        }
        chip
    });

    let ctrl_row_sel = ctrl.clone();
    let list_el = if log_count == 0 {
        inset_box(p)
            .flex_1()
            .min_h(px(260.))
            .items_center()
            .justify_center()
            .gap(px(10.))
            .child(
                div()
                    .text_size(px(12.))
                    .text_color(rgb(p.text_muted))
                    .child("暂无匹配的审计日志"),
            )
            .child(
                action_button(
                    "audit-reset-filters",
                    "重置筛选",
                    ButtonKind::Secondary,
                    true,
                    p,
                )
                .h(px(27.))
                .on_mouse_up(
                    MouseButton::Left,
                    cx.listener(move |_, _, _, cx| {
                        ctrl_reset_all.update(cx, |c, cx| {
                            c.audit_level_filter = None;
                            c.selected_log_id = None;
                            c.drafts.search_query.clear();
                            c.inputs
                                .search
                                .update(cx, |i, cx| i.set_text_silent("", cx));
                            c.clear_timeline_bucket(cx);
                        });
                    }),
                ),
            )
    } else {
        div()
            .flex_1()
            .min_h(px(260.))
            .w_full()
            .rounded(px(10.))
            .bg(rgb(p.inset_bg))
            .border_1()
            .border_color(rgb(p.inset_border))
            .px(px(6.))
            .py(px(4.))
            .child(
                uniform_list("audit-log-stream", log_count, move |range, _window, _cx| {
                    range
                        .map(|idx| {
                            let entry = &logs[idx];
                            let entry_id = entry.id;
                            let is_sel = selected_log_id == Some(entry_id);
                            let ctrl_click = ctrl_row_sel.clone();
                            let hover_row = palette_for_list.sidebar_hover_bg;
                            let (lvl_dot_color, lvl_text_color) = match entry.level {
                                LogLevel::Info => (
                                    palette_for_list.badge_pass.dot,
                                    palette_for_list.text_secondary,
                                ),
                                LogLevel::Warn => (
                                    palette_for_list.badge_warn.dot,
                                    palette_for_list.badge_warn.text,
                                ),
                                LogLevel::Error => (
                                    palette_for_list.badge_fail.dot,
                                    palette_for_list.badge_fail.text,
                                ),
                                LogLevel::Audit => {
                                    (palette_for_list.text_muted, palette_for_list.text_muted)
                                }
                            };
                            div()
                                .id(gpui::ElementId::Name(
                                    format!("audit-row-{entry_id}").into(),
                                ))
                                .flex()
                                .items_center()
                                .w_full()
                                .min_w(px(0.))
                                .gap(px(9.))
                                .h(px(31.))
                                .px(px(8.))
                                .rounded(px(6.))
                                .cursor_pointer()
                                .when(is_sel, |r| r.bg(rgb(palette_for_list.accent_soft_bg)))
                                .hover(move |s| s.bg(rgb(hover_row)))
                                .border_b_1()
                                .border_color(rgb(palette_for_list.card_border))
                                .on_mouse_up(MouseButton::Left, move |_, _, cx| {
                                    ctrl_click.update(cx, |c, cx| {
                                        c.selected_log_id = if c.selected_log_id == Some(entry_id) {
                                            None
                                        } else {
                                            Some(entry_id)
                                        };
                                        cx.notify();
                                    });
                                })
                                .child(
                                    mono_tabular(format_unix_hm(entry.timestamp))
                                        .w(px(60.))
                                        .flex_shrink_0()
                                        .text_size(px(11.))
                                        .text_color(rgb(palette_for_list.text_muted)),
                                )
                                .child(
                                    div()
                                        .flex()
                                        .items_center()
                                        .gap(px(5.))
                                        .w(px(46.))
                                        .flex_shrink_0()
                                        .text_size(px(11.))
                                        .font_weight(FontWeight::MEDIUM)
                                        .text_color(rgb(lvl_text_color))
                                        .child(status_dot(lvl_dot_color, 5.5))
                                        .child(entry.level.label()),
                                )
                                .child(
                                    div()
                                        .flex()
                                        .items_center()
                                        .justify_center()
                                        .w(px(68.))
                                        .flex_shrink_0()
                                        .px(px(5.))
                                        .py(px(1.5))
                                        .rounded(px(5.5))
                                        .bg(rgb(palette_for_list.card_bg))
                                        .border_1()
                                        .border_color(rgb(palette_for_list.card_border))
                                        .text_size(px(10.))
                                        .font_family("Cascadia Mono")
                                        .text_color(rgb(palette_for_list.text_secondary))
                                        .child(entry.category.clone()),
                                )
                                .child(
                                    div()
                                        .flex_1()
                                        .min_w(px(0.))
                                        .truncate()
                                        .text_size(px(11.5))
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

    let count_display = if total_server > all_count {
        format!("{log_count} / {total_server} 条")
    } else {
        format!("{log_count} / {all_count} 条")
    };
    let can_pull = connected && !logs_loading;
    let can_export = connected && !busy;
    let can_export_health = connected && !busy && !health_card_busy;
    let hover_tile = p.sidebar_hover_bg;

    let ctrl_copy_log = ctrl.clone();
    let ctrl_close_log = ctrl.clone();

    let timeline_card = bento_card_bloom(p, 17.0, 12.0, choreo.tile(0, 0))
        .flex_1()
        .gap(px(8.))
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
                        .min_w(px(0.))
                        .flex_1()
                        .child(
                            div()
                                .text_size(px(13.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.text_primary))
                                .child("24 小时出口合规轨迹"),
                        )
                        .child(
                            div()
                                .truncate()
                                .text_size(px(11.))
                                .text_color(rgb(p.text_muted))
                                .child(timeline_summary),
                        ),
                )
                .child(if has_bucket {
                    action_button(
                        "audit-clear-bucket",
                        "清除时段",
                        ButtonKind::Secondary,
                        true,
                        p,
                    )
                    .h(px(24.))
                    .px(px(9.))
                    .text_size(px(11.))
                    .on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |_, _, _, cx| {
                            ctrl_clear.update(cx, |c, cx| c.clear_timeline_bucket(cx));
                        }),
                    )
                    .into_any_element()
                } else {
                    div()
                        .flex()
                        .items_center()
                        .gap(px(5.5))
                        .when_some(compliance_dot, |row, dot| row.child(status_dot(dot, 5.5)))
                        .child(
                            mono_tabular(compliance_txt)
                                .text_size(px(11.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(compliance_color)),
                        )
                        .into_any_element()
                }),
        )
        .child(
            div()
                .flex()
                .items_end()
                .h(px(34.))
                .gap(px(2.))
                .px(px(6.))
                .py(px(4.))
                .rounded(px(9.))
                .bg(rgb(p.inset_bg))
                .border_1()
                .border_color(rgb(p.inset_border))
                .children(bars),
        )
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .px(px(2.))
                .child(
                    mono_tabular("24 小时前")
                        .text_size(px(10.))
                        .text_color(rgb(p.text_muted)),
                )
                .child(
                    mono_tabular("18 小时前")
                        .text_size(px(10.))
                        .text_color(rgb(p.text_muted)),
                )
                .child(
                    mono_tabular("12 小时前")
                        .text_size(px(10.))
                        .text_color(rgb(p.text_muted)),
                )
                .child(
                    mono_tabular("6 小时前")
                        .text_size(px(10.))
                        .text_color(rgb(p.text_muted)),
                )
                .child(
                    mono_tabular("现在")
                        .text_size(px(10.))
                        .text_color(rgb(p.text_muted)),
                ),
        );

    let logs_card = bento_card_bloom(p, 17.0, 12.0, choreo.tile(0, 1))
        .flex_1()
        .gap(px(9.))
        .justify_between()
        .child(
            div()
                .flex()
                .flex_col()
                .flex_1()
                .min_h(px(0.))
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
                                .gap(px(6.))
                                .child(div().w(px(210.)).child(search_input))
                                .when(search_non_empty, |row| {
                                    row.child(
                                        div()
                                            .id("audit-clear-search")
                                            .flex()
                                            .items_center()
                                            .justify_center()
                                            .w(px(24.))
                                            .h(px(24.))
                                            .rounded(px(6.5))
                                            .bg(rgb(p.secondary_btn_bg))
                                            .border_1()
                                            .border_color(rgb(p.secondary_btn_border))
                                            .cursor_pointer()
                                            .hover(move |s| s.bg(rgb(hover_tile)))
                                            .child(ui_icon(
                                                "icons/ui/close.svg",
                                                10.5,
                                                p.text_secondary,
                                            ))
                                            .on_mouse_up(
                                                MouseButton::Left,
                                                cx.listener(move |_, _, _, cx| {
                                                    ctrl_clear_search.update(cx, |c, cx| {
                                                        c.clear_search_query(cx);
                                                    });
                                                }),
                                            ),
                                    )
                                })
                                .child(
                                    div()
                                        .flex()
                                        .items_center()
                                        .gap(px(2.))
                                        .p(px(2.))
                                        .rounded(px(8.))
                                        .bg(rgb(p.inset_bg))
                                        .border_1()
                                        .border_color(rgb(p.card_border))
                                        .children(level_chips),
                                ),
                        )
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap(px(7.))
                                .child(
                                    mono_tabular(count_display)
                                        .text_size(px(11.))
                                        .text_color(rgb(p.text_muted)),
                                )
                                .child({
                                    let rf_fg = if can_pull {
                                        p.secondary_btn_text
                                    } else {
                                        p.text_muted
                                    };
                                    div()
                                        .id("audit-refresh-btn")
                                        .flex()
                                        .items_center()
                                        .gap(px(5.))
                                        .h(px(28.))
                                        .px(px(9.))
                                        .rounded(px(8.))
                                        .bg(rgb(p.secondary_btn_bg))
                                        .border_1()
                                        .border_color(rgb(p.secondary_btn_border))
                                        .text_size(px(11.5))
                                        .font_weight(FontWeight::MEDIUM)
                                        .text_color(rgb(rf_fg))
                                        .child(spinning_ui_icon(
                                            "audit-rf-spin",
                                            "icons/ui/refresh.svg",
                                            11.5,
                                            rf_fg,
                                            logs_loading,
                                        ))
                                        .child(if logs_loading { "查询中" } else { "刷新" })
                                        .when(can_pull, |b| {
                                            b.cursor_pointer()
                                                .hover(move |s| s.bg(rgb(hover_tile)))
                                                .active(|s| s.opacity(0.88))
                                                .on_mouse_up(
                                                    MouseButton::Left,
                                                    cx.listener(move |_, _, _, cx| {
                                                        ctrl_refresh.update(cx, |c, cx| {
                                                            c.refresh_audit_logs(cx);
                                                        });
                                                    }),
                                                )
                                        })
                                })
                                .child(
                                    action_button(
                                        "audit-copy-filtered",
                                        "复制筛选结果",
                                        ButtonKind::Secondary,
                                        log_count > 0,
                                        p,
                                    )
                                    .h(px(28.))
                                    .px(px(10.))
                                    .when(log_count > 0, |b| {
                                        b.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                let count = logs_for_batch_copy.len();
                                                let text = logs_for_batch_copy
                                                    .iter()
                                                    .map(|entry| {
                                                        format!(
                                                            "[{}] [{}] [{}] {}",
                                                            format_unix_ymdhms(entry.timestamp),
                                                            entry.level.label(),
                                                            entry.category,
                                                            entry.message
                                                        )
                                                    })
                                                    .collect::<Vec<_>>()
                                                    .join("\n");
                                                ctrl_copy_batch.update(cx, |c, cx| {
                                                    c.copy_to_clipboard(
                                                        text,
                                                        &format!(" {count} 条筛选日志"),
                                                        cx,
                                                    );
                                                });
                                            }),
                                        )
                                    }),
                                )
                                .child(
                                    spinning_action_button(
                                        "audit-export-health-card",
                                        "icons/ui/shield.svg",
                                        if health_card_busy {
                                            "生成中…"
                                        } else {
                                            "导出防封体检图"
                                        },
                                        ButtonKind::Secondary,
                                        can_export_health,
                                        health_card_busy,
                                        p,
                                    )
                                    .h(px(28.))
                                    .px(px(10.))
                                    .when(
                                        can_export_health,
                                        |b| {
                                            b.on_mouse_up(
                                                MouseButton::Left,
                                                cx.listener(move |_, _, _, cx| {
                                                    ctrl_health_card.update(cx, |c, cx| {
                                                        c.build_and_export_health_card(true, cx);
                                                    });
                                                }),
                                            )
                                        },
                                    ),
                                )
                                .child(
                                    action_button(
                                        "audit-export-diag",
                                        if export_busy {
                                            "导出中…"
                                        } else {
                                            "导出脱敏诊断包"
                                        },
                                        ButtonKind::Primary,
                                        can_export,
                                        p,
                                    )
                                    .h(px(28.))
                                    .px(px(11.))
                                    .when(can_export, |b| {
                                        b.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                ctrl_export.update(cx, |c, cx| {
                                                    c.send_request(
                                                        PipeRequest::ExportDiagnostics,
                                                        Some("已导出脱敏诊断包"),
                                                        cx,
                                                    );
                                                });
                                            }),
                                        )
                                    }),
                                ),
                        ),
                )
                .child(list_el)
                .when_some(selected_log, |col, entry| {
                    let full_text = format!(
                        "[{}] [{}] [{}] {}",
                        format_unix_ymdhms(entry.timestamp),
                        entry.level.label(),
                        entry.category,
                        entry.message
                    );
                    let full_copy = full_text.clone();
                    col.child(
                        inset_box(p)
                            .flex_row()
                            .items_start()
                            .justify_between()
                            .gap(px(10.))
                            .px(px(10.))
                            .py(px(8.))
                            .child(
                                mono_tabular(full_text)
                                    .flex_1()
                                    .min_w(px(0.))
                                    .text_size(px(11.))
                                    .line_height(px(16.))
                                    .text_color(rgb(p.text_primary)),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .flex_shrink_0()
                                    .gap(px(5.))
                                    .child(
                                        action_button(
                                            "audit-copy-selected",
                                            "复制",
                                            ButtonKind::Secondary,
                                            true,
                                            p,
                                        )
                                        .h(px(24.))
                                        .px(px(8.))
                                        .text_size(px(10.5))
                                        .on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                let txt = full_copy.clone();
                                                ctrl_copy_log.update(cx, |c, cx| {
                                                    c.copy_to_clipboard(txt, "日志", cx);
                                                });
                                            }),
                                        ),
                                    )
                                    .child(
                                        div()
                                            .id("audit-close-selected")
                                            .cursor_pointer()
                                            .p(px(3.))
                                            .rounded(px(5.))
                                            .hover(move |s| s.bg(rgb(hover_tile)))
                                            .child(ui_icon(
                                                "icons/ui/close.svg",
                                                10.5,
                                                p.text_muted,
                                            ))
                                            .on_mouse_up(
                                                MouseButton::Left,
                                                cx.listener(move |_, _, _, cx| {
                                                    ctrl_close_log.update(cx, |c, cx| {
                                                        c.selected_log_id = None;
                                                        cx.notify();
                                                    });
                                                }),
                                            ),
                                    ),
                            ),
                    )
                }),
        )
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .pt(px(8.))
                .border_t_1()
                .border_color(rgb(p.card_border))
                .child(
                    div()
                        .text_size(px(11.))
                        .text_color(rgb(p.text_muted))
                        .child("点击日志展开并复制 · 诊断包自动脱敏路径与 IP"),
                )
                .child(
                    mono_tabular("自动轮转保留")
                        .text_size(px(10.5))
                        .text_color(rgb(p.text_muted)),
                ),
        );

    div()
        .flex()
        .flex_col()
        .w_full()
        .flex_1()
        .min_w(px(0.))
        .gap(px(10.))
        .child(div().w_full().min_w(px(0.)).flex().child(timeline_card))
        .child(
            div()
                .flex()
                .flex_1()
                .w_full()
                .min_w(px(0.))
                .min_h(px(300.))
                .child(logs_card),
        )
}
