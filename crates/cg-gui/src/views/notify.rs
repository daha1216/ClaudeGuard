//! Mode B — Frost Ceramic `通知与飞书` view.
//!
//! 2 sub-tabs:
//! - `提醒内容与隐私` (`NotifySubTab::Events`): desktop master switch, egress-IP privacy toggle,
//!   2×3 granular 6-category event subscription matrix with `仅留关键告警` / `全部开启` presets,
//!   and 2-column anti-spam & privacy guide.
//! - `飞书 / Lark 机器人` (`NotifySubTab::Feishu`): encrypted webhook & HMAC signing secret config,
//!   3 diagnostic status tiles, redacted test trigger, and 3-column setup guide.

use crate::app::{AppController, ConsoleWindowView, NotifySubTab};
use crate::demo::now_unix_secs;
use crate::motion::PageChoreo;
use crate::protocol::PipeRequest;
use crate::state::format_relative_secs;
use crate::theme::{BadgeTone, ThemePalette};
use crate::views::shared::{ag_diag_tile, labeled_field, page_guide_card, switch_row_gated};
use crate::widgets::controls::{
    ButtonKind, action_button, bento_card_bloom, mono_tabular, offset_pane, status_dot, subtab_bar,
    subtab_item, toggle_switch, tone_tag,
};
use gpui::{Context, Div, Entity, FontWeight, MouseButton, div, prelude::*, px, relative, rgb};

pub fn render_notify_page(
    ctrl: Entity<AppController>,
    choreo: PageChoreo,
    subtab_dx: f32,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> Div {
    let ctrl_r = ctrl.read(cx);
    let snap = ctrl_r.snapshot.clone();
    let tab = ctrl_r.notify_tab;
    let connected = ctrl_r.connected;
    let busy = ctrl_r.busy_action;
    let can_act = connected && !busy;

    let cfg = snap.as_ref().map(|s| s.config.clone()).unwrap_or_default();
    let feishu = snap.as_ref().map(|s| s.feishu.clone()).unwrap_or_default();
    let n = cfg.notify;
    let webhook_in = ctrl_r.inputs.feishu_webhook.clone();
    let secret_in = ctrl_r.inputs.feishu_secret.clone();
    let feishu_enabled = ctrl_r.drafts.feishu_enabled;
    let clear_secret = ctrl_r.drafts.feishu_clear_secret;
    let feishu_dirty = ctrl_r.feishu_dirty;
    let now = now_unix_secs();

    let master_on = ctrl_r.effective_toggle("nt-enabled", n.enabled);
    let egress_on = ctrl_r.effective_toggle("nt-egress", n.include_egress);
    let trip_on = ctrl_r.effective_toggle("nt-trip", n.trip);
    let recover_on = ctrl_r.effective_toggle("nt-recover", n.recover);
    let launch_blocked_on = ctrl_r.effective_toggle("nt-launch-blocked", n.launch_blocked);
    let warning_on = ctrl_r.effective_toggle("nt-warning", n.warning);
    let client_upd_on = ctrl_r.effective_toggle("nt-client-upd", n.client_update);
    let self_upd_on = ctrl_r.effective_toggle("nt-self-upd", n.self_update);

    let active_cats = [
        trip_on,
        recover_on,
        launch_blocked_on,
        warning_on,
        client_upd_on,
        self_upd_on,
    ]
    .into_iter()
    .filter(|&on| on)
    .count();

    let ctrl_t_ev = ctrl.clone();
    let ctrl_t_fs = ctrl.clone();
    let tabs = div().flex().items_center().child(
        subtab_bar(p)
            .child(
                subtab_item(
                    "nt-tab-events",
                    "提醒内容与隐私",
                    tab == NotifySubTab::Events,
                    None,
                    Some(format!("{active_cats}/6")),
                    p,
                )
                .on_mouse_up(
                    MouseButton::Left,
                    cx.listener(move |_, _, _, cx| {
                        ctrl_t_ev.update(cx, |c, cx| {
                            c.notify_tab = NotifySubTab::Events;
                            cx.notify();
                        });
                    }),
                ),
            )
            .child(
                subtab_item(
                    "nt-tab-feishu",
                    "飞书 / Lark 机器人",
                    tab == NotifySubTab::Feishu,
                    (feishu.enabled && feishu.has_webhook).then_some(p.badge_pass.dot),
                    None,
                    p,
                )
                .on_mouse_up(
                    MouseButton::Left,
                    cx.listener(move |_, _, _, cx| {
                        ctrl_t_fs.update(cx, |c, cx| {
                            c.notify_tab = NotifySubTab::Feishu;
                            cx.notify();
                        });
                    }),
                ),
            ),
    );

    let body = match tab {
        NotifySubTab::Events => {
            let ctrl_en = ctrl.clone();
            let ctrl_egress = ctrl.clone();
            let ctrl_crit = ctrl.clone();
            let ctrl_all = ctrl.clone();
            let ctrl_to_fs = ctrl.clone();

            let make_ev_cell = |id: &'static str,
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
                                .text_color(rgb(if master_on {
                                    p.text_primary
                                } else {
                                    p.text_muted
                                }))
                                .child(title),
                        )
                        .child(
                            div()
                                .text_size(px(10.5))
                                .line_height(px(14.5))
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
                                    "订阅选项已更新",
                                    cx,
                                );
                            });
                        }),
                    )
                }))
            };

            let master_card = bento_card_bloom(p, 16., 13., choreo.tile(0, 0))
                .flex_1()
                .flex_row()
                .items_center()
                .justify_between()
                .gap(px(12.))
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .flex_1()
                        .min_w(px(0.))
                        .gap(px(3.))
                        .child(
                            div()
                                .text_size(px(12.5))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.text_primary))
                                .child("Windows 系统通知"),
                        )
                        .child(
                            div()
                                .text_size(px(10.5))
                                .line_height(px(15.))
                                .text_color(rgb(p.text_muted))
                                .child("关键事件推送至系统通知中心"),
                        ),
                )
                .child(
                    toggle_switch("nt-enabled", master_on, can_act, p).when(can_act, |sw| {
                        sw.on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |_, _, _, cx| {
                                let next = !master_on;
                                ctrl_en.update(cx, |c, cx| {
                                    c.save_toggle_patch(
                                        "nt-enabled",
                                        next,
                                        move |x| x.notify.enabled = next,
                                        "系统通知开关已更新",
                                        cx,
                                    );
                                });
                            }),
                        )
                    }),
                );

            let privacy_card = bento_card_bloom(p, 16., 13., choreo.tile(0, 1))
                .flex_1()
                .flex_row()
                .items_center()
                .justify_between()
                .gap(px(12.))
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .flex_1()
                        .min_w(px(0.))
                        .gap(px(3.))
                        .child(
                            div()
                                .text_size(px(12.5))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.text_primary))
                                .child("通知附带 IP 与地区"),
                        )
                        .child(
                            div()
                                .text_size(px(10.5))
                                .line_height(px(15.))
                                .text_color(rgb(p.text_muted))
                                .child("默认关闭，外发仅含事件与原因"),
                        ),
                )
                .child(
                    toggle_switch("nt-egress", egress_on, can_act, p).when(can_act, |sw| {
                        sw.on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |_, _, _, cx| {
                                let next = !egress_on;
                                ctrl_egress.update(cx, |c, cx| {
                                    c.save_toggle_patch(
                                        "nt-egress",
                                        next,
                                        move |x| x.notify.include_egress = next,
                                        "脱敏策略已更新",
                                        cx,
                                    );
                                });
                            }),
                        )
                    }),
                );

            let top_pair = div()
                .flex()
                .flex_row()
                .w_full()
                .gap(px(11.))
                .child(
                    div()
                        .flex_1()
                        .flex_basis(px(0.))
                        .min_w(px(0.))
                        .flex()
                        .child(master_card),
                )
                .child(
                    div()
                        .flex_1()
                        .flex_basis(px(0.))
                        .min_w(px(0.))
                        .flex()
                        .child(privacy_card),
                );

            let matrix_card = bento_card_bloom(p, 17., 13., choreo.tile(1, 0))
                .flex_1()
                .gap(px(4.))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .pb(px(4.))
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
                                        .child("事件订阅"),
                                )
                                .child(
                                    mono_tabular(if master_on {
                                        format!("已开 {active_cats}/6 · 同步用于桌面与飞书")
                                    } else {
                                        format!("已开 {active_cats}/6 · 系统通知已关（仅飞书生效）")
                                    })
                                    .text_size(px(11.))
                                    .text_color(rgb(
                                        if master_on {
                                            p.text_muted
                                        } else {
                                            p.badge_warn.text
                                        },
                                    )),
                                ),
                        )
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap(px(6.))
                                .child(
                                    action_button(
                                        "nt-preset-critical",
                                        "仅留关键告警",
                                        ButtonKind::Secondary,
                                        can_act,
                                        p,
                                    )
                                    .h(px(25.))
                                    .px(px(9.))
                                    .text_size(px(11.))
                                    .when(can_act, |b| {
                                        b.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                ctrl_crit.update(cx, |c, cx| {
                                                    c.save_config_patch(
                                                        |x| {
                                                            x.notify.enabled = true;
                                                            x.notify.trip = true;
                                                            x.notify.recover = false;
                                                            x.notify.launch_blocked = true;
                                                            x.notify.warning = true;
                                                            x.notify.client_update = false;
                                                            x.notify.self_update = false;
                                                        },
                                                        "已切换为仅留关键告警",
                                                        cx,
                                                    );
                                                });
                                            }),
                                        )
                                    }),
                                )
                                .child(
                                    action_button(
                                        "nt-preset-all",
                                        "全部开启",
                                        ButtonKind::Secondary,
                                        can_act,
                                        p,
                                    )
                                    .h(px(25.))
                                    .px(px(9.))
                                    .text_size(px(11.))
                                    .when(can_act, |b| {
                                        b.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                ctrl_all.update(cx, |c, cx| {
                                                    c.save_config_patch(
                                                        |x| {
                                                            x.notify.enabled = true;
                                                            x.notify.trip = true;
                                                            x.notify.recover = true;
                                                            x.notify.launch_blocked = true;
                                                            x.notify.warning = true;
                                                            x.notify.client_update = true;
                                                            x.notify.self_update = true;
                                                        },
                                                        "已开启全部 6 项通知",
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
                        .when(!master_on, |d| d.opacity(0.6))
                        .child(
                            div()
                                .flex()
                                .flex_row()
                                .gap(px(22.))
                                .child(make_ev_cell(
                                    "nt-trip",
                                    "熔断与隔离告警",
                                    "出口越界、断网或自动封锁时通知",
                                    trip_on,
                                    true,
                                    ctrl.clone(),
                                    |x, v| x.notify.trip = v,
                                    cx,
                                ))
                                .child(make_ev_cell(
                                    "nt-recover",
                                    "解封与恢复通知",
                                    "复查通过自动放行或手动解封后通知",
                                    recover_on,
                                    true,
                                    ctrl.clone(),
                                    |x, v| x.notify.recover = v,
                                    cx,
                                )),
                        )
                        .child(
                            div()
                                .flex()
                                .flex_row()
                                .gap(px(22.))
                                .child(make_ev_cell(
                                    "nt-launch-blocked",
                                    "启动拦截提醒",
                                    "熔断锁定期或注入失效拦截启动时通知",
                                    launch_blocked_on,
                                    true,
                                    ctrl.clone(),
                                    |x, v| x.notify.launch_blocked = v,
                                    cx,
                                ))
                                .child(make_ev_cell(
                                    "nt-warning",
                                    "直连与风险预警",
                                    "检测到旁路直连、MCP 外连或时区异常",
                                    warning_on,
                                    true,
                                    ctrl.clone(),
                                    |x, v| x.notify.warning = v,
                                    cx,
                                )),
                        )
                        .child(
                            div()
                                .flex()
                                .flex_row()
                                .gap(px(22.))
                                .child(make_ev_cell(
                                    "nt-client-upd",
                                    "客户端与插件更新",
                                    "受管 AI 客户端、注入器或插件有新版",
                                    client_upd_on,
                                    false,
                                    ctrl.clone(),
                                    |x, v| x.notify.client_update = v,
                                    cx,
                                ))
                                .child(make_ev_cell(
                                    "nt-self-upd",
                                    "守护端版本更新",
                                    "ClaudeGuard 发布正式新版本时通知",
                                    self_upd_on,
                                    false,
                                    ctrl.clone(),
                                    |x, v| x.notify.self_update = v,
                                    cx,
                                )),
                        ),
                );

            let guide = page_guide_card(
                "通知说明",
                "去重防打扰 · 默认脱敏",
                &[
                    (
                        "1. 防打扰冷却",
                        "同类波动自动去重冷却，避免重复弹窗；点「仅留关键告警」可降噪。",
                    ),
                    (
                        "2. 统一脱敏",
                        "以上开关同步作用于系统通知与飞书，默认不外发 IP 与主机名。",
                    ),
                ],
                p,
            )
            .child(
                div().flex().justify_end().pt(px(2.)).child(
                    div()
                        .id("nt-jump-feishu")
                        .cursor_pointer()
                        .text_size(px(11.5))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(rgb(p.text_primary))
                        .child("配置飞书推送 →")
                        .on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |_, _, _, cx| {
                                ctrl_to_fs.update(cx, |c, cx| {
                                    c.notify_tab = NotifySubTab::Feishu;
                                    cx.notify();
                                });
                            }),
                        ),
                ),
            );

            div()
                .flex()
                .flex_col()
                .w_full()
                .gap(px(10.))
                .child(top_pair)
                .child(div().w_full().flex().child(matrix_card))
                .child(choreo.tile(1, 1).apply(guide))
        }

        NotifySubTab::Feishu => {
            let webhook_status = if feishu.has_webhook {
                if feishu.webhook_masked.is_empty() {
                    "已加密保存".to_string()
                } else {
                    feishu.webhook_masked.clone()
                }
            } else {
                "未配置".to_string()
            };
            let secret_status = if feishu.has_secret {
                "已加密保存"
            } else {
                "未启用"
            };
            let last_sent_text = if feishu.last_sent_at.is_some() {
                format_relative_secs(feishu.last_sent_at, now)
            } else {
                "暂无记录".to_string()
            };

            let ctrl_fs_en = ctrl.clone();
            let ctrl_fs_clr = ctrl.clone();
            let ctrl_fs_test = ctrl.clone();
            let ctrl_fs_save = ctrl.clone();

            let fs_card = bento_card_bloom(p, 17., 14., choreo.tile(0, 0))
                .flex_1()
                .gap(px(11.))
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
                                        .child("飞书 / Lark Webhook"),
                                )
                                .when(feishu_dirty, |row| {
                                    row.child(tone_tag("未保存", BadgeTone::Warn, p))
                                })
                                .child(
                                    div()
                                        .text_size(px(11.))
                                        .text_color(rgb(p.text_muted))
                                        .child("复用事件订阅与默认脱敏策略"),
                                ),
                        )
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap(px(8.))
                                .child(
                                    div()
                                        .flex()
                                        .items_center()
                                        .gap(px(5.5))
                                        .text_size(px(11.5))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(if feishu_enabled {
                                            p.text_primary
                                        } else {
                                            p.text_muted
                                        }))
                                        .when(feishu_enabled, |d| {
                                            d.child(status_dot(p.badge_pass.dot, 5.5))
                                        })
                                        .child(if feishu_enabled {
                                            "已启用"
                                        } else {
                                            "已暂停"
                                        }),
                                )
                                .child(toggle_switch("fs-en-sw", feishu_enabled, can_act, p).when(
                                    can_act,
                                    |sw| {
                                        sw.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                ctrl_fs_en.update(cx, |c, cx| {
                                                    c.drafts.feishu_enabled =
                                                        !c.drafts.feishu_enabled;
                                                    c.feishu_dirty = true;
                                                    cx.notify();
                                                });
                                            }),
                                        )
                                    },
                                )),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .flex_row()
                        .gap(px(9.))
                        .child(ag_diag_tile(
                            "Webhook 地址",
                            webhook_status,
                            if feishu.has_webhook {
                                "留空保存即保留现有地址".into()
                            } else {
                                "粘贴地址后保存即可启用".into()
                            },
                            if feishu.has_webhook {
                                p.text_primary
                            } else {
                                p.text_muted
                            },
                            true,
                            p,
                        ))
                        .child(ag_diag_tile(
                            "签名校验",
                            secret_status.into(),
                            "HMAC-SHA256 防伪造校验".into(),
                            if feishu.has_secret {
                                p.text_primary
                            } else {
                                p.text_muted
                            },
                            false,
                            p,
                        ))
                        .child(ag_diag_tile(
                            "离线队列与送达",
                            format!("待发 {} · {last_sent_text}", feishu.queued),
                            if !feishu.last_error.is_empty() {
                                feishu.last_error.clone()
                            } else {
                                format!("累计失败 {} 次", feishu.failed)
                            },
                            if feishu.queued > 0 {
                                p.badge_warn.text
                            } else {
                                p.text_primary
                            },
                            true,
                            p,
                        )),
                )
                .child(
                    div()
                        .flex()
                        .flex_row()
                        .gap(px(10.))
                        .child(div().w(relative(0.57)).child(labeled_field(
                            "Webhook 地址（留空保留现有）",
                            webhook_in,
                            p,
                        )))
                        .child(div().flex_1().child(labeled_field(
                            "加签密钥（留空保留现有）",
                            secret_in,
                            p,
                        ))),
                )
                .child(switch_row_gated(
                    "fs-clr-sw",
                    "保存时清除旧加签密钥",
                    "切换为无加签校验的机器人时开启",
                    clear_secret,
                    can_act,
                    p,
                    cx.listener(move |_, _, _, cx| {
                        ctrl_fs_clr.update(cx, |c, cx| {
                            c.drafts.feishu_clear_secret = !c.drafts.feishu_clear_secret;
                            c.feishu_dirty = true;
                            cx.notify();
                        });
                    }),
                ))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .pt(px(9.))
                        .border_t_1()
                        .border_color(rgb(p.card_border))
                        .gap(px(10.))
                        .child(
                            mono_tabular(if egress_on {
                                "外发策略：附带 IP 与地区"
                            } else {
                                "外发策略：默认脱敏（隐藏 IP 与主机名）"
                            })
                            .text_size(px(11.))
                            .text_color(rgb(p.text_muted)),
                        )
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap(px(8.))
                                .child(
                                    action_button(
                                        "fs-test-btn",
                                        "发送脱敏测试",
                                        ButtonKind::Secondary,
                                        can_act,
                                        p,
                                    )
                                    .h(px(28.))
                                    .when(can_act, |b| {
                                        b.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                ctrl_fs_test.update(cx, |c, cx| {
                                                    let raw_url =
                                                        c.drafts.feishu_webhook.trim().to_string();
                                                    let raw_sec =
                                                        c.drafts.feishu_secret.trim().to_string();
                                                    c.send_request(
                                                        PipeRequest::TestFeishu {
                                                            webhook: (!raw_url.is_empty())
                                                                .then_some(raw_url),
                                                            secret: (!raw_sec.is_empty())
                                                                .then_some(raw_sec),
                                                        },
                                                        Some("脱敏测试已送达飞书"),
                                                        cx,
                                                    );
                                                });
                                            }),
                                        )
                                    }),
                                )
                                .child(
                                    action_button(
                                        "fs-save-btn",
                                        "保存配置",
                                        ButtonKind::Primary,
                                        can_act,
                                        p,
                                    )
                                    .h(px(28.))
                                    .when(can_act, |b| {
                                        b.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                ctrl_fs_save.update(cx, |c, cx| {
                                                    c.save_feishu_from_drafts(cx);
                                                });
                                            }),
                                        )
                                    }),
                                ),
                        ),
                );

            let guide = page_guide_card(
                "飞书接入说明",
                "仅放行 open.feishu.cn / open.larksuite.com",
                &[
                    (
                        "1. 获取 Webhook",
                        "在飞书群「设置 → 群机器人」新建自定义机器人，粘贴地址并保存。",
                    ),
                    (
                        "2. 本机加密存储",
                        "建议开启飞书签名校验；地址与密钥经系统凭据加密，不明文落盘。",
                    ),
                    (
                        "3. 断网离线补发",
                        "熔断断网时推送暂存本地队列，网络恢复后按退避策略自动补发。",
                    ),
                ],
                p,
            );

            div()
                .flex()
                .flex_col()
                .w_full()
                .gap(px(10.))
                .child(div().w_full().flex().child(fs_card))
                .child(choreo.tile(1, 0).apply(guide))
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
