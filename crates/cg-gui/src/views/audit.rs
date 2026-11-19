//! Mode B — `时间线与审计` view (24h bucket filter + virtualized audit log stream).

use crate::app::{AppController, ConsoleWindowView};
use crate::protocol::{LogLevel, TimelineStatus, UiLabelExt};
use crate::state::{ConsoleProjection, format_unix_hm};
use crate::theme::{BadgeTone, ThemePalette};
use crate::widgets::controls::{
    ButtonKind, action_button, bento_card, inset_box, mono_tabular, status_pill,
};
use gpui::{Context, Div, Entity, FontWeight, MouseButton, div, prelude::*, px, rgb, uniform_list};
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
                                        .child("实时审计日志流"),
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

