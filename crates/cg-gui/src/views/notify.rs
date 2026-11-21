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
use crate::protocol::PipeRequest;
use crate::state::format_relative_secs;
use crate::theme::ThemePalette;
use crate::views::shared::{ag_diag_tile, labeled_field, page_guide_card, switch_row};
use crate::widgets::controls::{
    ButtonKind, action_button, bento_card, mono_tabular, subtab_bar, subtab_item, toggle_switch,
};
use gpui::{Context, Div, Entity, FontWeight, MouseButton, div, prelude::*, px, relative, rgb};

pub fn render_notify_page(
    ctrl: Entity<AppController>,
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
    let now = now_unix_secs();

    let active_cats = [
        n.trip,
        n.recover,
        n.launch_blocked,
        n.warning,
        n.client_update,
        n.self_update,
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
                                .text_color(rgb(if n.enabled {
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
                                c.save_config_patch(move |x| mutate(x, next), "提醒选项已更新", cx);
                            });
                        }),
                    )
                }))
            };

            let top_pair = div()
                .flex()
                .flex_row()
                .w_full()
                .gap(px(11.))
                .child(
                    bento_card(p)
                        .flex_1()
                        .flex_basis(px(0.))
                        .flex_row()
                        .items_center()
                        .justify_between()
                        .px(px(16.))
                        .py(px(13.))
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
                                        .child("启用 Windows 系统桌面提醒"),
                                )
                                .child(
                                    div()
                                        .text_size(px(10.5))
                                        .line_height(px(15.))
                                        .text_color(rgb(p.text_muted))
                                        .child("后台服务检测到关键事件时，自动转发到桌面右下角通知中心"),
                                ),
                        )
                        .child(
                            toggle_switch("nt-enabled", n.enabled, can_act, p).when(can_act, |sw| {
                                sw.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        let next = !n.enabled;
                                        ctrl_en.update(cx, |c, cx| {
                                            c.save_config_patch(
                                                move |x| x.notify.enabled = next,
                                                "桌面提醒总开关已更新",
                                                cx,
                                            );
                                        });
                                    }),
                                )
                            }),
                        ),
                )
                .child(
                    bento_card(p)
                        .flex_1()
                        .flex_basis(px(0.))
                        .flex_row()
                        .items_center()
                        .justify_between()
                        .px(px(16.))
                        .py(px(13.))
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
                                        .child("通知附带出口 IP 与地区"),
                                )
                                .child(
                                    div()
                                        .text_size(px(10.5))
                                        .line_height(px(15.))
                                        .text_color(rgb(p.text_muted))
                                        .child("默认关闭：外发通知仅含事件与原因，绝不泄露出口 IP 与主机名"),
                                ),
                        )
                        .child(
                            toggle_switch("nt-egress", n.include_egress, can_act, p).when(
                                can_act,
                                |sw| {
                                    sw.on_mouse_up(
                                        MouseButton::Left,
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
                                    )
                                },
                            ),
                        ),
                );

            let matrix_card = bento_card(p)
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
                                        .child("按事件类型精细订阅"),
                                )
                                .child(
                                    mono_tabular(format!(
                                        "已开启 {active_cats} / 6 类事件 · 同步作用于桌面弹窗与飞书推送"
                                    ))
                                    .text_size(px(11.))
                                    .text_color(rgb(p.text_muted)),
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
                                                        "已切换为「仅留关键告警」（免打扰模式）",
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
                                                        "已开启全部 6 类事件通知",
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
                        .flex_row()
                        .gap(px(22.))
                        .child(make_ev_cell(
                            "nt-trip",
                            "熔断与防火墙隔离告警",
                            "出口越界漂移、断网或自动封锁受管应用时立即通知",
                            n.trip,
                            true,
                            ctrl.clone(),
                            |x, v| x.notify.trip = v,
                            cx,
                        ))
                        .child(make_ev_cell(
                            "nt-recover",
                            "安全解封与恢复通知",
                            "线路复查达标自动放行，或手动解除防护完成后提示",
                            n.recover,
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
                            "安全启动拦截提醒",
                            "熔断锁定期或反重力注入失效拦截启动时弹出原因",
                            n.launch_blocked,
                            true,
                            ctrl.clone(),
                            |x, v| x.notify.launch_blocked = v,
                            cx,
                        ))
                        .child(make_ev_cell(
                            "nt-warning",
                            "直连泄露与风险预警",
                            "发现绕过代理的直连 / MCP 连接、时区不一致或延迟异常",
                            n.warning,
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
                            "AI 客户端与插件更新",
                            "Claude / Codex / 反重力 / 注入器与生态插件发布新版时提醒",
                            n.client_update,
                            false,
                            ctrl.clone(),
                            |x, v| x.notify.client_update = v,
                            cx,
                        ))
                        .child(make_ev_cell(
                            "nt-self-upd",
                            "ClaudeGuard 守护端更新",
                            "ClaudeGuard 自身发布正式新版本时提醒",
                            n.self_update,
                            false,
                            ctrl.clone(),
                            |x, v| x.notify.self_update = v,
                            cx,
                        )),
                );

            let guide = page_guide_card(
                "提醒机制与隐私说明",
                "防打扰去重冷却 · 默认隐私脱敏",
                &[
                    (
                        "1. 防打扰冷却与精准告警",
                        "同类状态波动内置去重冷却窗口，避免短时间内连续弹窗轰炸；若只想守住封号底线，可点右上角「仅留关键告警」。",
                    ),
                    (
                        "2. 桌面与飞书统一订阅脱敏",
                        "上方 6 项订阅开关与隐私脱敏策略同步作用于 Windows 系统通知与飞书群机器人，默认绝不外发出口 IP 与主机名。",
                    ),
                ],
                p,
            )
            .child(
                div()
                    .flex()
                    .justify_end()
                    .pt(px(2.))
                    .child(
                        div()
                            .id("nt-jump-feishu")
                            .cursor_pointer()
                            .text_size(px(11.5))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(rgb(p.text_primary))
                            .child("前往配置飞书推送 →")
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
                .child(matrix_card)
                .child(guide)
        }

        NotifySubTab::Feishu => {
            let webhook_status = if feishu.has_webhook {
                if feishu.webhook_masked.is_empty() {
                    "已本机加密保存".to_string()
                } else {
                    feishu.webhook_masked.clone()
                }
            } else {
                "尚未配置".to_string()
            };
            let secret_status = if feishu.has_secret {
                "● 已本机加密保存"
            } else {
                "未启用加签"
            };
            let last_sent_text = if feishu.last_sent_at.is_some() {
                format_relative_secs(feishu.last_sent_at, now)
            } else {
                "尚未发送".to_string()
            };

            let ctrl_fs_en = ctrl.clone();
            let ctrl_fs_clr = ctrl.clone();
            let ctrl_fs_test = ctrl.clone();
            let ctrl_fs_save = ctrl.clone();

            let fs_card = bento_card(p)
                .w_full()
                .px(px(17.))
                .py(px(14.))
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
                                        .child("飞书 / Lark 群机器人 Webhook"),
                                )
                                .child(
                                    div()
                                        .text_size(px(11.))
                                        .text_color(rgb(p.text_muted))
                                        .child("复用同一套 6 项事件订阅与默认脱敏策略"),
                                ),
                        )
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap(px(8.))
                                .child(
                                    div()
                                        .text_size(px(11.5))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(if feishu_enabled {
                                            p.badge_pass.text
                                        } else {
                                            p.text_muted
                                        }))
                                        .child(if feishu_enabled {
                                            "● 已启用推送"
                                        } else {
                                            "已暂停推送"
                                        }),
                                )
                                .child(
                                    toggle_switch("fs-en-sw", feishu_enabled, true, p).on_mouse_up(
                                        MouseButton::Left,
                                        cx.listener(move |_, _, _, cx| {
                                            ctrl_fs_en.update(cx, |c, cx| {
                                                c.drafts.feishu_enabled = !c.drafts.feishu_enabled;
                                                cx.notify();
                                            });
                                        }),
                                    ),
                                ),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .flex_row()
                        .gap(px(9.))
                        .child(ag_diag_tile(
                            "已存 Webhook 地址",
                            webhook_status,
                            if feishu.has_webhook {
                                "留空保存将保留现有加密地址".into()
                            } else {
                                "粘贴机器人地址后点击保存".into()
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
                            "加签密钥状态",
                            secret_status.into(),
                            "HMAC-SHA256 签名防伪造".into(),
                            if feishu.has_secret {
                                p.badge_pass.text
                            } else {
                                p.text_muted
                            },
                            false,
                            p,
                        ))
                        .child(ag_diag_tile(
                            "离线重试队列 / 最近送达",
                            format!("待发 {} 条 · {last_sent_text}", feishu.queued),
                            if !feishu.last_error.is_empty() {
                                feishu.last_error.clone()
                            } else {
                                format!("历史失败 {} 条", feishu.failed)
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
                        .child(
                            div()
                                .w(relative(0.57))
                                .child(labeled_field(
                                    "更新 Webhook 地址（留空则保留已加密保存的地址）",
                                    webhook_in,
                                    p,
                                )),
                        )
                        .child(
                            div()
                                .flex_1()
                                .child(labeled_field(
                                    "更新加签密钥（留空则保留已存密钥）",
                                    secret_in,
                                    p,
                                )),
                        ),
                )
                .child(switch_row(
                    "fs-clr-sw",
                    "保存时清除已存储的旧签名密钥",
                    "仅在更换为无加签校验的机器人时需要开启",
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
                        .pt(px(9.))
                        .border_t_1()
                        .border_color(rgb(p.card_border))
                        .gap(px(10.))
                        .child(
                            mono_tabular(if n.include_egress {
                                "隐私策略：外发包含出口 IP / 地区"
                            } else {
                                "隐私策略：默认脱敏（隐藏出口 IP 与主机名）"
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
                                                        Some("飞书脱敏测试消息已送达"),
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
                                        "保存飞书配置",
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
                                                    let enabled = c.drafts.feishu_enabled;
                                                    let clear_secret = c.drafts.feishu_clear_secret;
                                                    let raw_url =
                                                        c.drafts.feishu_webhook.trim().to_string();
                                                    let raw_sec =
                                                        c.drafts.feishu_secret.trim().to_string();
                                                    c.drafts.feishu_webhook.clear();
                                                    c.drafts.feishu_secret.clear();
                                                    c.drafts.feishu_clear_secret = false;
                                                    c.inputs
                                                        .feishu_webhook
                                                        .update(cx, |i, cx| i.set_text_silent("", cx));
                                                    c.inputs
                                                        .feishu_secret
                                                        .update(cx, |i, cx| i.set_text_silent("", cx));
                                                    c.send_request(
                                                        PipeRequest::SaveFeishuConfig {
                                                            enabled,
                                                            webhook: (!raw_url.is_empty())
                                                                .then_some(raw_url),
                                                            secret: (!raw_sec.is_empty())
                                                                .then_some(raw_sec),
                                                            clear_secret,
                                                        },
                                                        Some("飞书通知配置已本机加密保存"),
                                                        cx,
                                                    );
                                                });
                                            }),
                                        )
                                    }),
                                ),
                        ),
                );

            let guide = page_guide_card(
                "飞书接入与凭据安全说明",
                "仅放行 open.feishu.cn / open.larksuite.com",
                &[
                    (
                        "1. 获取机器人地址",
                        "在飞书群打开「设置 → 群机器人 → 添加自定义机器人」，复制 Webhook 地址粘贴到上方即可。",
                    ),
                    (
                        "2. 本机加密零明文",
                        "推荐在飞书开启「签名校验」并填入密钥；地址与密钥均由 Windows 本机凭据加密存储，绝不明文落盘。",
                    ),
                    (
                        "3. 断网自动补发",
                        "熔断断网导致推送暂不可达时，告警会自动进入本地离线队列，网络恢复后按指数退避自动补发。",
                    ),
                ],
                p,
            );

            div()
                .flex()
                .flex_col()
                .w_full()
                .gap(px(10.))
                .child(fs_card)
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
