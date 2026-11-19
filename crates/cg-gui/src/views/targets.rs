//! Mode B — `目标与白名单` view (draft-isolated target & allowlist editor).

use crate::app::{AppController, ConsoleWindowView};
use crate::theme::ThemePalette;
use crate::views::shared::labeled_field;
use crate::widgets::controls::{
    ButtonKind, action_button, bento_card, card_header, inset_box, mono_tabular, toggle_switch,
};
use gpui::{Context, Div, Entity, FontWeight, MouseButton, div, prelude::*, px, rgb, rgba};
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


