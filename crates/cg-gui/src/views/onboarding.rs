//! Mode B — Zero-Input Smart First-Run Onboarding Modal.

use crate::app::{AppController, ConsoleWindowView};
use crate::motion::spring_sheet;
use crate::protocol::{OnboardingStrategy, UiLabelExt, mask_ip_str};
use crate::theme::{BadgeTone, ThemePalette};
use crate::views::shared::{info_mini_box, labeled_field};
use crate::widgets::controls::{
    ButtonKind, action_button, bento_card, float_shadow, spinning_ui_icon, status_dot, status_pill,
};
use gpui::{
    AnimationExt, Context, Div, Entity, FontWeight, MouseButton, SpringAnimation, div, prelude::*,
    px, rgb, rgba,
};

fn friendly_agent_name(id: &str) -> &str {
    match id.trim().to_ascii_lowercase().as_str() {
        "claude" | "claude_desktop" | "claude-desktop" => "Claude Desktop",
        "chatgpt" | "codex" | "codex_desktop" | "codex-desktop" => "ChatGPT",
        "antigravity" | "antigravity_ide" | "antigravity-ide" => "Antigravity",
        "cursor" | "cursor_ide" | "cursor-ide" => "Cursor IDE",
        "windsurf" | "windsurf_ide" | "windsurf-ide" => "Windsurf IDE",
        "zed" | "zed_ide" | "zed-ide" => "Zed",
        "trae" | "trae_ide" | "trae-ide" => "Trae IDE",
        "claude-code" | "claude_code" => "Claude Code CLI",
        "codex-cli" | "codex_cli" => "Codex CLI",
        "gemini" | "gemini-cli" | "gemini_cli" => "Gemini CLI",
        "aider" | "aider-cli" | "aider_cli" => "Aider CLI",
        _ => id,
    }
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
    let submitting = ctrl_r.onboarding_submitting;
    let onboarding_error = ctrl_r.onboarding_error.clone();
    let connected = ctrl_r.connected;
    let is_demo = ctrl_r.client.is_demo();
    let busy = ctrl_r.busy_action;
    let start_svc_busy = ctrl_r.is_scope_busy(&crate::app::ActionScope::StartService);
    let proxy_off_sim = ctrl_r.onboarding_proxy_off_sim;
    let cidr_in = ctrl_r.inputs.onboarding_cidr.clone();
    let reg_in = ctrl_r.inputs.onboarding_regions.clone();

    let ctrl_skip = ctrl.clone();
    let ctrl_done = ctrl.clone();
    let ctrl_start_svc = ctrl.clone();
    let ctrl_reconn = ctrl.clone();
    let ctrl_reprobe = ctrl.clone();
    let ctrl_sim_toggle = ctrl.clone();

    let access_summary = probe
        .as_ref()
        .map(|pr| {
            let port = pr
                .detected_proxy_port
                .map(|port| format!("本地代理 :{port}"))
                .unwrap_or_else(|| pr.access.level.label().to_string());
            let apps = if pr.installed_agents.is_empty() {
                "未发现".into()
            } else {
                pr.installed_agents
                    .iter()
                    .map(|id| friendly_agent_name(id))
                    .collect::<Vec<_>>()
                    .join(" · ")
            };
            let exit = pr
                .probe
                .as_ref()
                .map(|p_res| {
                    let cc = p_res.country.as_deref().map(str::trim).unwrap_or("");
                    let city = p_res.city.as_deref().map(str::trim).unwrap_or("");
                    let loc = match (cc.is_empty(), city.is_empty()) {
                        (false, false) => format!("{cc} · {city}"),
                        (false, true) => cc.to_string(),
                        (true, false) => city.to_string(),
                        (true, true) => "--".to_string(),
                    };
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
                    format!("{loc} · {ip} ({}ms)", p_res.latency_ms)
                })
                .unwrap_or_else(|| "未探测到出口".into());
            (port, apps, exit, pr.standby_notice.clone())
        })
        .unwrap_or_else(|| {
            (
                "探测中…".into(),
                "扫描客户端…".into(),
                "正在探测当前出口…".into(),
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
        let raw_title = if opt.recommended {
            opt.title
                .strip_prefix("推荐：")
                .or_else(|| opt.title.strip_prefix("推荐:"))
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(&opt.title)
        } else {
            opt.title.as_str()
        };
        let title = if mask {
            crate::protocol::mask_ips_in_text(raw_title)
        } else {
            raw_title.to_string()
        };
        let sub = if mask {
            crate::protocol::mask_ips_in_text(&opt.subtitle)
        } else {
            opt.subtitle.clone()
        };

        let hover_bg = p.sidebar_hover_bg;
        div()
            .id(gpui::ElementId::Name(format!("onb-opt-{strat:?}").into()))
            .flex()
            .flex_col()
            .gap(px(4.))
            .p(px(12.))
            .rounded(px(12.))
            .cursor_pointer()
            .when(active, |d| {
                d.bg(rgb(p.accent_soft_bg))
                    .border_1()
                    .border_color(rgb(p.accent_soft_border))
            })
            .when(!active, |d| {
                d.bg(rgb(p.inset_bg))
                    .border_1()
                    .border_color(rgb(p.inset_border))
                    .hover(move |s| s.bg(rgb(hover_bg)))
            })
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
                                    .w(px(14.))
                                    .h(px(14.))
                                    .rounded(px(999.))
                                    .border_2()
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .border_color(rgb(if active {
                                        p.primary_btn_bg
                                    } else {
                                        p.line_strong
                                    }))
                                    .when(active, |d| d.child(status_dot(p.primary_btn_bg, 6.0))),
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
                        d.child(status_pill("推荐", BadgeTone::Pass, p))
                    }),
            )
            .child(
                div()
                    .pl(px(22.))
                    .text_size(px(11.5))
                    .line_height(px(16.5))
                    .text_color(rgb(p.text_secondary))
                    .child(sub),
            )
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(move |_, _, _, cx| {
                    ctrl_opt.update(cx, |c, cx| {
                        c.drafts.onboarding_strategy = strat;
                        c.onboarding_error = None;
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
                .border_color(rgb(p.line_strong))
                .shadow(float_shadow(p))
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
                                        .child("首次配置向导"),
                                )
                                .child(
                                    div()
                                        .text_size(px(12.))
                                        .text_color(rgb(p.text_muted))
                                        .child("已自动识别本地代理、受管 AI 客户端与当前出口，确认策略后一键布防"),
                                ),
                        )
                        .when(is_demo, |d| {
                            d.child(
                                action_button(
                                    "onb-sim-proxy",
                                    if proxy_off_sim { "模拟：代理已开" } else { "模拟：代理已关" },
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
                        .child(info_mini_box("本地代理", access_summary.0, p))
                        .child(info_mini_box("受管 AI 客户端", access_summary.1, p))
                        .child(info_mini_box("当前出口", access_summary.2, p)),
                )
                .when_some(access_summary.3, |card, standby| {
                    card.child(
                        div()
                            .p(px(11.))
                            .rounded(px(10.))
                            .bg(rgba(p.badge_warn.bg))
                            .text_size(px(12.))
                            .line_height(px(17.))
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
                            .child(labeled_field("允许地区（ISO 代码）", reg_in, p))
                            .child(labeled_field("允许 IP / CIDR", cidr_in, p)),
                    )
                })
                .when_some(onboarding_error, |card, err| {
                    card.child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(8.))
                            .p(px(10.))
                            .rounded(px(10.))
                            .bg(rgba(p.badge_fail.bg))
                            .text_size(px(12.))
                            .text_color(rgb(p.badge_fail.text))
                            .child(
                                div()
                                    .w(px(6.))
                                    .h(px(6.))
                                    .flex_shrink_0()
                                    .rounded(px(999.))
                                    .bg(rgb(p.badge_fail.dot)),
                            )
                            .child(err),
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
                                    action_button(
                                        "onb-skip",
                                        "暂不布防 · 仅只读",
                                        ButtonKind::Ghost,
                                        !submitting,
                                        p,
                                    )
                                    .when(!submitting, |b| {
                                        b.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                ctrl_skip.update(cx, |c, cx| c.skip_onboarding(cx));
                                            }),
                                        )
                                    }),
                                )
                                .child({
                                    let can_reprobe = !loading && !submitting;
                                    let hover_bg = p.sidebar_hover_bg;
                                    div()
                                        .id("onb-reprobe")
                                        .flex()
                                        .items_center()
                                        .justify_center()
                                        .gap(px(5.5))
                                        .h(px(30.))
                                        .px(px(12.))
                                        .rounded(px(9.))
                                        .bg(rgb(p.secondary_btn_bg))
                                        .border_1()
                                        .border_color(rgb(p.secondary_btn_border))
                                        .text_size(px(12.))
                                        .font_weight(FontWeight::MEDIUM)
                                        .text_color(rgb(p.secondary_btn_text))
                                        .when(can_reprobe, |b| {
                                            b.cursor_pointer()
                                                .hover(move |s| s.bg(rgb(hover_bg)))
                                                .active(|s| s.opacity(0.86))
                                                .on_mouse_up(
                                                    MouseButton::Left,
                                                    cx.listener(move |_, _, _, cx| {
                                                        ctrl_reprobe.update(cx, |c, cx| {
                                                            c.probe_onboarding(cx);
                                                        });
                                                    }),
                                                )
                                        })
                                        .when(!can_reprobe, |b| b.opacity(0.45))
                                        .child(spinning_ui_icon(
                                            "onb-reprobe-spin",
                                            "icons/ui/refresh.svg",
                                            12.0,
                                            p.secondary_btn_text,
                                            loading,
                                        ))
                                        .child(if loading { "探测中…" } else { "重新探测" })
                                }),
                        )
                        .child(if !connected && !is_demo {
                            div()
                                .flex()
                                .items_center()
                                .gap(px(8.))
                                .child(
                                    action_button(
                                        "onb-reconnect",
                                        "重连服务",
                                        ButtonKind::Secondary,
                                        !busy,
                                        p,
                                    )
                                    .when(!busy, |b| {
                                        b.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                ctrl_reconn.update(cx, |c, cx| {
                                                    c.send_request(
                                                        crate::protocol::PipeRequest::GetSnapshot,
                                                        Some("已重新连接守护服务"),
                                                        cx,
                                                    );
                                                });
                                            }),
                                        )
                                    }),
                                )
                                .child(
                                    action_button(
                                        "onb-start-service",
                                        if start_svc_busy {
                                            "启动中…"
                                        } else {
                                            "启动守护服务"
                                        },
                                        ButtonKind::Primary,
                                        !busy,
                                        p,
                                    )
                                    .when(!busy, |b| {
                                        b.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                ctrl_start_svc.update(cx, |c, cx| {
                                                    c.start_daemon_service(cx);
                                                });
                                            }),
                                        )
                                    }),
                                )
                                .into_any_element()
                        } else {
                            let can_complete =
                                connected && !loading && !submitting && probe.is_some();
                            let complete_label = if !connected {
                                "服务离线"
                            } else if loading {
                                "探测中…"
                            } else if submitting {
                                "正在布防…"
                            } else {
                                "保存并布防"
                            };
                            action_button(
                                "onb-complete",
                                complete_label,
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
                            .into_any_element()
                        }),
                )
                .with_spring(
                    "onboarding-sheet-enter",
                    SpringAnimation::new(spring_sheet())
                        .to(1.0_f32)
                        .from(0.0_f32),
                    |el, t: f32| {
                        let t = t.clamp(0.0, 1.0);
                        el.opacity(t).mt(px((1.0 - t) * 14.0))
                    },
                ),
        )
}
