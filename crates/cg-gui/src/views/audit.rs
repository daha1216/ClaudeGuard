//! Mode B — Frost Ceramic `时间线与审计` view.
//!
//! Features:
//! - Interactive 48-bar 24h compliance trajectory bucket filter with time scale
//! - Search input + 5 level filter chips (`全部 / 信息 / 警告 / 错误 / 审计`)
//! - Virtualized `uniform_list` audit log stream + redacted `.zip` diagnostic bundle export

use crate::app::{AppController, ConsoleWindowView};
use crate::protocol::{LogLevel, PipeRequest, TimelineStatus, UiLabelExt};
use crate::state::{ConsoleProjection, format_unix_hm};
use crate::theme::ThemePalette;
use crate::widgets::controls::{
    ButtonKind, action_button, bento_card, icon_action_button, inset_box, mono_tabular,
};
use gpui::{Context, Div, Entity, FontWeight, MouseButton, div, prelude::*, px, rgb, uniform_list};

pub fn render_audit_page(
    ctrl: Entity<AppController>,
    proj: &ConsoleProjection,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> Div {
    let ctrl_r = ctrl.read(cx);
    let scroll_handle = ctrl_r.audit_list_scroll.clone();
    let has_bucket = ctrl_r.selected_bucket.is_some();
    let active_level = ctrl_r.audit_level_filter;
    let search_input = ctrl_r.inputs.search.clone();
    let logs_loading = ctrl_r.logs_loading;
    let total_server = ctrl_r.queried_logs_total;
    let connected = ctrl_r.connected;
    let busy = ctrl_r.busy_action;

    let ctrl_clear = ctrl.clone();
    let ctrl_refresh = ctrl.clone();
    let ctrl_export = ctrl.clone();
    let ctrl_reset_all = ctrl.clone();

    let mut non_empty = 0u32;
    let mut pass_bars = 0u32;
    let bars: Vec<gpui::Stateful<Div>> = proj
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
            let ctrl_b = ctrl.clone();
            let mut el = div()
                .id(gpui::ElementId::Name(format!("audit-bar-{idx}").into()))
                .flex_1()
                .min_w(px(3.))
                .h(px(22.))
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
        })
        .collect();

    let compliance_txt = if non_empty == 0 {
        "暂无采样".to_string()
    } else {
        format!("{:.1}% 合规", (pass_bars as f64 / non_empty as f64) * 100.0)
    };

    let all_count = proj.filtered_logs.len();
    let logs: Vec<_> = proj
        .filtered_logs
        .iter()
        .filter(|entry| active_level.is_none_or(|lvl| entry.level == lvl))
        .cloned()
        .collect();
    let log_count = logs.len();
    let palette_for_list = p;

    let level_chips = [
        (None, "全部"),
        (Some(LogLevel::Info), "信息"),
        (Some(LogLevel::Warn), "警告"),
        (Some(LogLevel::Error), "错误"),
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
            .px(px(8.))
            .rounded(px(6.))
            .cursor_pointer()
            .text_size(px(11.))
            .font_weight(if on {
                FontWeight::SEMIBOLD
            } else {
                FontWeight::MEDIUM
            })
            .text_color(rgb(if on {
                p.primary_btn_text
            } else {
                p.text_secondary
            }))
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
            chip = chip.bg(rgb(p.primary_btn_bg));
        } else {
            chip = chip.hover(move |s| s.bg(rgb(hover_bg)).text_color(rgb(hover_txt)));
        }
        chip
    });

    let list_el = if log_count == 0 {
        inset_box(p)
            .h(px(300.))
            .items_center()
            .justify_center()
            .gap(px(10.))
            .child(
                div()
                    .text_size(px(12.))
                    .text_color(rgb(p.text_muted))
                    .child("当前时段或筛选条件下没有匹配的审计日志"),
            )
            .child(
                action_button("audit-reset-filters", "重置全部筛选", ButtonKind::Secondary, true, p)
                    .h(px(27.))
                    .on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |_, _, _, cx| {
                            ctrl_reset_all.update(cx, |c, cx| {
                                c.audit_level_filter = None;
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
            .h(px(330.))
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
                            let lvl_color = match entry.level {
                                LogLevel::Info => palette_for_list.badge_pass.text,
                                LogLevel::Warn => palette_for_list.badge_warn.text,
                                LogLevel::Error => palette_for_list.badge_fail.text,
                                LogLevel::Audit => palette_for_list.text_muted,
                            };
                            div()
                                .flex()
                                .items_center()
                                .w_full()
                                .min_w(px(0.))
                                .gap(px(9.))
                                .h(px(31.))
                                .px(px(8.))
                                .border_b_1()
                                .border_color(rgb(palette_for_list.card_border))
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
                                        .text_color(rgb(lvl_color))
                                        .child(
                                            div()
                                                .w(px(5.5))
                                                .h(px(5.5))
                                                .rounded(px(999.))
                                                .bg(rgb(lvl_color)),
                                        )
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

    div()
        .flex()
        .flex_col()
        .w_full()
        .flex_1()
        .min_w(px(0.))
        .gap(px(10.))
        .child(
            bento_card(p)
                .w_full()
                .px(px(17.))
                .py(px(12.))
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
                                        .text_size(px(12.5))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(p.text_primary))
                                        .child("24 小时出口合规轨迹"),
                                )
                                .child(
                                    div()
                                        .truncate()
                                        .text_size(px(11.))
                                        .text_color(rgb(p.text_muted))
                                        .child(proj.selected_bucket_summary.clone()),
                                ),
                        )
                        .child(if has_bucket {
                            action_button(
                                "audit-clear-bucket",
                                "清除时段筛选",
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
                            mono_tabular(compliance_txt)
                                .text_size(px(11.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.badge_pass.text))
                                .into_any_element()
                        }),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
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
                        .child(mono_tabular("24 小时前").text_size(px(10.)).text_color(rgb(p.text_muted)))
                        .child(mono_tabular("18 小时前").text_size(px(10.)).text_color(rgb(p.text_muted)))
                        .child(mono_tabular("12 小时前").text_size(px(10.)).text_color(rgb(p.text_muted)))
                        .child(mono_tabular("6 小时前").text_size(px(10.)).text_color(rgb(p.text_muted)))
                        .child(mono_tabular("现在").text_size(px(10.)).text_color(rgb(p.text_muted))),
                ),
        )
        .child(
            bento_card(p)
                .w_full()
                .flex_1()
                .px(px(17.))
                .py(px(12.))
                .gap(px(9.))
                .justify_between()
                .child(
                    div()
                        .flex()
                        .flex_col()
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
                                        .gap(px(8.))
                                        .child(div().w(px(210.)).child(search_input))
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
                                        .child(
                                            icon_action_button(
                                                "audit-refresh-btn",
                                                "icons/ui/refresh.svg",
                                                if logs_loading { "查询中" } else { "刷新" },
                                                ButtonKind::Secondary,
                                                can_pull,
                                                p,
                                            )
                                            .h(px(28.))
                                            .px(px(9.))
                                            .when(can_pull, |b| {
                                                b.on_mouse_up(
                                                    MouseButton::Left,
                                                    cx.listener(move |_, _, _, cx| {
                                                        ctrl_refresh.update(cx, |c, cx| {
                                                            c.refresh_audit_logs(cx);
                                                        });
                                                    }),
                                                )
                                            }),
                                        )
                                        .child(
                                            action_button(
                                                "audit-export-diag",
                                                "导出脱敏诊断包 (.zip)",
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
                                                                Some("已导出脱敏诊断包 (.zip)"),
                                                                cx,
                                                            );
                                                        });
                                                    }),
                                                )
                                            }),
                                        ),
                                ),
                        )
                        .child(list_el),
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
                                .child("导出脱敏诊断包时会自动隐藏本机用户名、绝对路径及外网 IP 后两段，可放心用于问题排查。"),
                        )
                        .child(
                            mono_tabular("本地日志自动轮转保留")
                                .text_size(px(10.5))
                                .text_color(rgb(p.text_muted)),
                        ),
                ),
        )
}
