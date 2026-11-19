//! Mode B — `通知与飞书` view (Session-1 native Windows notifications + real DPAPI Feishu webhook).

use crate::app::{AppController, ConsoleWindowView};
use crate::demo::now_unix_secs;
use crate::protocol::PipeRequest;
use crate::state::format_relative_secs;
use crate::theme::{BadgeTone, ThemePalette};
use crate::views::shared::{labeled_field, switch_row};
use crate::widgets::controls::{
    ButtonKind, action_button, bento_card, card_header, inset_box, mono_tabular, status_pill,
};
use gpui::{Context, Div, Entity, FontWeight, MouseButton, div, prelude::*, px, rgb};

/// Sub-view: `通知与飞书`
pub fn render_notify_page(
    ctrl: Entity<AppController>,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> Div {
    let ctrl_r = ctrl.read(cx);
    let snap = ctrl_r.snapshot.clone();
    let connected = ctrl_r.connected;
    let busy = ctrl_r.busy_action;
    let cfg = snap.as_ref().map(|s| s.config.clone()).unwrap_or_default();
    let feishu = snap.as_ref().map(|s| s.feishu.clone()).unwrap_or_default();
    let n = cfg.notify;
    let webhook_in = ctrl_r.inputs.feishu_webhook.clone();
    let secret_in = ctrl_r.inputs.feishu_secret.clone();
    let feishu_enabled = ctrl_r.drafts.feishu_enabled;
    let clear_secret = ctrl_r.drafts.feishu_clear_secret;
    let now = now_unix_secs();

    let webhook_status = if feishu.has_webhook {
        if feishu.webhook_masked.is_empty() {
            "已加密保存".to_string()
        } else {
            feishu.webhook_masked.clone()
        }
    } else {
        "尚未配置".to_string()
    };
    let secret_status = if feishu.has_secret {
        "已加密保存"
    } else {
        "未启用加签"
    };
    let last_sent_text = if feishu.last_sent_at.is_some() {
        format_relative_secs(feishu.last_sent_at, now)
    } else {
        "尚未发送".to_string()
    };

    let fs_note = if !feishu.last_error.is_empty() {
        feishu.last_error.clone()
    } else if let Some(note) = ctrl_r.feishu_status_note.clone() {
        note
    } else if feishu.has_webhook {
        format!(
            "凭据已通过本机系统加密落盘 · 待重试 {} · 失败 {} · 最近送达：{}",
            feishu.queued, feishu.failed, last_sent_text
        )
    } else {
        "凭据由 Windows 系统本机安全加密存储，绝不以明文落盘；未填写新地址时保留已存凭据".into()
    };

    let fs_note_color = if !feishu.last_error.is_empty() {
        p.badge_fail.text
    } else {
        p.text_muted
    };

    let can_act = connected && !busy;

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
        .w_full()
        .min_w(px(0.))
        .gap(px(14.))
        .child(
            bento_card(p)
                .w_full()
                .p(px(16.))
                .gap(px(10.))
                .child(card_header("系统桌面通知", "Windows 原生提醒（后台服务自动转发）", p))
                .child(switch_row(
                    "nt-enabled",
                    "启用桌面弹窗通知",
                    "发生关键防护事件时在系统右下角即时弹窗提醒，后台服务模式下自动转发至当前桌面",
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
                    "安全解封与恢复通知",
                    "出口复检通过或撤防核验完成后提示结果",
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
                    "默认关闭：外发通知仅含目标名称、状态与异常原因，绝不泄露出口 IP 或主机名",
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
                .w_full()
                .p(px(16.))
                .gap(px(10.))
                .child(
                    div()
                        .flex()
                        .flex_wrap()
                        .items_center()
                        .justify_between()
                        .gap(px(8.))
                        .child(
                            div()
                                .text_size(px(13.5))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.text_primary))
                                .child("飞书 / Lark 群机器人 Webhook"),
                        )
                        .child(status_pill(
                            if feishu.enabled && feishu.has_webhook {
                                "已启用推送"
                            } else if feishu.has_webhook {
                                "已配置（未开启）"
                            } else {
                                "未配置"
                            },
                            if feishu.enabled && feishu.has_webhook {
                                BadgeTone::Pass
                            } else {
                                BadgeTone::Muted
                            },
                            p,
                        )),
                )
                .child(
                    div()
                        .flex()
                        .w_full()
                        .min_w(px(0.))
                        .gap(px(10.))
                        .child(
                            inset_box(p)
                                .flex_1()
                                .flex_basis(px(0.))
                                .min_w(px(0.))
                                .px(px(10.))
                                .py(px(8.))
                                .gap(px(2.))
                                .child(
                                    div()
                                        .text_size(px(10.))
                                        .text_color(rgb(p.text_muted))
                                        .child("已存 Webhook"),
                                )
                                .child(
                                    mono_tabular(webhook_status)
                                        .truncate()
                                        .text_size(px(12.))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(if feishu.has_webhook {
                                            p.text_primary
                                        } else {
                                            p.text_muted
                                        })),
                                ),
                        )
                        .child(
                            inset_box(p)
                                .flex_1()
                                .flex_basis(px(0.))
                                .min_w(px(0.))
                                .px(px(10.))
                                .py(px(8.))
                                .gap(px(2.))
                                .child(
                                    div()
                                        .text_size(px(10.))
                                        .text_color(rgb(p.text_muted))
                                        .child("签名密钥"),
                                )
                                .child(
                                    div()
                                        .text_size(px(12.))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(if feishu.has_secret {
                                            p.badge_pass.text
                                        } else {
                                            p.text_muted
                                        }))
                                        .child(secret_status),
                                ),
                        )
                        .child(
                            inset_box(p)
                                .flex_1()
                                .flex_basis(px(0.))
                                .min_w(px(0.))
                                .px(px(10.))
                                .py(px(8.))
                                .gap(px(2.))
                                .child(
                                    div()
                                        .text_size(px(10.))
                                        .text_color(rgb(p.text_muted))
                                        .child("投递队列 / 最近送达"),
                                )
                                .child(
                                    mono_tabular(format!(
                                        "待发 {} · {}",
                                        feishu.queued, last_sent_text
                                    ))
                                    .truncate()
                                    .text_size(px(12.))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .text_color(rgb(if feishu.queued > 0 {
                                        p.badge_warn.text
                                    } else {
                                        p.text_primary
                                    })),
                                ),
                        ),
                )
                .child(switch_row(
                    "fs-en-sw",
                    "启用飞书群机器人推送",
                    "支持 HMAC-SHA256 加签与离线持久化退避重试，默认按隐私开关自动脱敏",
                    feishu_enabled,
                    p,
                    cx.listener(move |_, _, _, cx| {
                        ctrl_fs_en.update(cx, |c, cx| {
                            c.drafts.feishu_enabled = !c.drafts.feishu_enabled;
                            cx.notify();
                        });
                    }),
                ))
                .child(labeled_field("Webhook HTTPS 地址（留空则保留已加密保存的地址）", webhook_in, p))
                .child(labeled_field("加签密钥（已掩码输入，留空则保留已存密钥）", secret_in, p))
                .child(switch_row(
                    "fs-clr-sw",
                    "保存时清除已存储的旧密钥",
                    "勾选后将清除本机已保存的加签密钥",
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
                        .flex_wrap()
                        .items_center()
                        .justify_between()
                        .gap(px(10.))
                        .child(
                            div()
                                .flex_1()
                                .min_w(px(220.))
                                .text_size(px(11.5))
                                .line_height(px(16.5))
                                .text_color(rgb(fs_note_color))
                                .child(fs_note),
                        )
                        .child(
                            div()
                                .flex()
                                .flex_wrap()
                                .gap(px(8.))
                                .child(
                                    action_button(
                                        "fs-test-btn",
                                        "发送脱敏测试",
                                        ButtonKind::Secondary,
                                        can_act,
                                        p,
                                    )
                                    .when(can_act, |b| {
                                        b.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                ctrl_fs_test.update(cx, |c, cx| {
                                                    let raw_url =
                                                        c.drafts.feishu_webhook.trim().to_string();
                                                    let raw_sec =
                                                        c.drafts.feishu_secret.trim().to_string();
                                                    let webhook = if raw_url.is_empty() {
                                                        None
                                                    } else {
                                                        Some(raw_url)
                                                    };
                                                    let secret = if raw_sec.is_empty() {
                                                        None
                                                    } else {
                                                        Some(raw_sec)
                                                    };
                                                    c.send_request(
                                                        PipeRequest::TestFeishu { webhook, secret },
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
                                                    let webhook = if raw_url.is_empty() {
                                                        None
                                                    } else {
                                                        Some(raw_url)
                                                    };
                                                    let secret = if raw_sec.is_empty() {
                                                        None
                                                    } else {
                                                        Some(raw_sec)
                                                    };
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
                                                            webhook,
                                                            secret,
                                                            clear_secret,
                                                        },
                                                        Some("飞书通知配置已加密保存"),
                                                        cx,
                                                    );
                                                });
                                            }),
                                        )
                                    }),
                                ),
                        ),
                ),
        )
}
