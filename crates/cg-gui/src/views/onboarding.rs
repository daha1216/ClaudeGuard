//! Mode B — Zero-Input Smart First-Run Onboarding Modal.

use crate::app::{AppController, ConsoleWindowView};
use crate::protocol::{OnboardingStrategy, UiLabelExt, mask_ip_str};
use crate::theme::{BadgeTone, ThemePalette};
use crate::views::shared::{info_mini_box, labeled_field};
use crate::widgets::controls::{ButtonKind, action_button, bento_card, status_pill};
use gpui::{Context, Div, Entity, FontWeight, MouseButton, div, prelude::*, px, rgb, rgba};
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
                p.card_bg
            } else {
                p.inset_bg
            }))
            .border_1()
            .border_color(rgb(if active {
                p.primary_btn_bg
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
        .bg(rgba(p.scrim_rgba))
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

