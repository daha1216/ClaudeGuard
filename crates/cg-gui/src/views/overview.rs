//! Mode B — Frost Ceramic v2 `守护总览` view.
//!
//! Layout:
//! - Upper row (47% / 53%): Hero Status Card (with 3-cell live telemetry strip) + 2×2 `安全启动台`
//! - Lower 3-column balanced row (33.5% / 35.5% / 31%): `受管进程治理` | Read-Only `出口实况探测` | `四维防漏` + 24h tape

use crate::app::{ActionScope, AppController, ConsoleWindowView, EnvSubTab};
use crate::assets::{agent_icon_key, brand_icon_scaled, ui_icon};
use crate::motion::PageChoreo;
use crate::protocol::{Lifecycle, PipeRequest, SafetyGrade, TimelineStatus};
use crate::state::{ConsoleProjection, NavSection, safety_grade_tone};
use crate::theme::{BadgeTone, HeroTone, ThemePalette};
use crate::views::shared::{brand_family_rank, canonical_agent_label};
use crate::widgets::controls::{
    ButtonKind, action_button, bento_card_bloom, icon_action_button, inset_box, mono_tabular,
    pulse_status_dot, spinning_action_button, spinning_ui_icon, status_dot, toggle_switch,
    tone_tag,
};
use gpui::{
    BoxShadow, Context, Div, Entity, FontWeight, MouseButton, div, prelude::*, px, relative, rgb,
    rgba,
};

fn cleanup_toast_for_agent(agent_id: &str) -> &'static str {
    match agent_id {
        "claude" => "已清理 Claude 桌面端及孤儿进程",
        "claude-code" => "已清理 Claude Code 及孤儿进程",
        "chatgpt" => "已清理 ChatGPT / Codex 及孤儿进程",
        "codex" => "已清理 Codex CLI 及孤儿进程",
        "antigravity" => "已清理 Antigravity 及孤儿进程",
        _ => "已清理受管 AI 客户端进程",
    }
}

fn short_launch_name(agent_id: &str, fallback: &str) -> String {
    match agent_id {
        "claude" => "Claude".into(),
        "claude-code" => "Code CLI".into(),
        "chatgpt" => "ChatGPT".into(),
        "antigravity" => "Antigravity".into(),
        "codex" => "Codex CLI".into(),
        _ => fallback.to_string(),
    }
}

fn short_target_name(id: &str, fallback: &str) -> String {
    match id {
        "claude" => "Claude 出口".into(),
        "codex" | "chatgpt" => "Codex / OpenAI".into(),
        "antigravity" => "Antigravity 后端".into(),
        _ => fallback.to_string(),
    }
}

fn compact_target_sub(ip_display: &str) -> &str {
    match ip_display {
        "Google 后端连通探测" => "Google 后端连通",
        "仅可达性探测" => "仅连通探测",
        "暂不可达（网络波动）" => "暂不可达（波动）",
        other => other,
    }
}

pub fn render_overview(
    ctrl: Entity<AppController>,
    proj: &ConsoleProjection,
    choreo: PageChoreo,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> Div {
    let ctrl_r = ctrl.read(cx);
    let snap = ctrl_r.snapshot.clone();
    let busy = ctrl_r.busy_action;
    let is_demo = ctrl_r.client.is_demo();
    let recheck_all_busy = ctrl_r.is_scope_busy(&ActionScope::RecheckAll);
    let start_svc_busy = ctrl_r.is_scope_busy(&ActionScope::StartService);
    let kill_all_armed = ctrl_r.is_confirm_armed("ov-kill-all");
    let connected = proj.connected;
    let can_act = connected && !busy;

    let (
        proxy_port,
        interval_secs,
        require_ag_proxy,
        quic_on,
        dns_on,
        ipv6_on,
        lifecycle,
        really_tripped,
        ag_installed,
        ag_ready,
        active_rules,
        direct_total,
    ) = if let Some(s) = snap.as_deref() {
        (
            s.config.proxy_port,
            s.config.interval_secs,
            s.config.require_antigravity_proxy,
            ctrl_r.effective_toggle("sh-quic", s.config.leak_shield_quic),
            ctrl_r.effective_toggle("sh-dns", s.config.leak_shield_dns_doh),
            ctrl_r.effective_toggle("sh-ipv6", s.config.leak_shield_ipv6),
            s.lifecycle,
            s.is_tripped(),
            s.antigravity_proxy.installed,
            s.antigravity_proxy.is_ready_for_launch(),
            s.leak_shield.active_rules,
            s.leak.direct_total,
        )
    } else {
        (
            7890,
            15,
            true,
            true,
            false,
            false,
            Lifecycle::Unconfigured,
            false,
            false,
            false,
            0,
            0,
        )
    };
    let ag_degraded = require_ag_proxy && ag_installed && !ag_ready;
    let monitor_only = snap.as_deref().is_some_and(|s| s.config.monitor_only);
    let ip_unchanged_hold = !really_tripped
        && !monitor_only
        && proj.hero.fail_count > 0
        && snap
            .as_deref()
            .is_some_and(|s| s.launch_error.contains("未变"));
    let pre_trip_fail = !really_tripped && proj.hero.fail_count > 0 && !ip_unchanged_hold;

    // 24h compliance metrics computed once for both Hero telemetry strip and 24h mini tape.
    let mut non_empty = 0u32;
    let mut pass_bars = 0u32;
    let mini_bars_vec: Vec<Div> = proj
        .timeline_bars
        .iter()
        .map(|b| {
            let c = match b.status {
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
            div()
                .flex_1()
                .min_w(px(2.))
                .h(px(10.))
                .rounded(px(1.5))
                .bg(rgb(c))
        })
        .collect();
    let compliance_pct = if non_empty == 0 {
        "--".to_string()
    } else {
        format!("{:.1}%", (pass_bars as f64 / non_empty as f64) * 100.0)
    };

    // -------------------------------------------------------------------------
    // Upper Row Left: Hero Status Card (47%, filled middle telemetry strip)
    // -------------------------------------------------------------------------
    let hero_surf = p.hero(proj.hero.tone);
    let total_targets =
        (proj.hero.pass_count + proj.hero.fail_count + proj.hero.unverified_count).max(1);
    let status_dot_color = match proj.hero.tone {
        HeroTone::Healthy => p.badge_pass.dot,
        HeroTone::Tripped => p.badge_fail.dot,
        HeroTone::DisarmedOrPaused => p.badge_warn.dot,
    };
    let status_kicker_color = match proj.hero.tone {
        HeroTone::Healthy => p.text_secondary,
        HeroTone::Tripped => p.badge_fail.text,
        HeroTone::DisarmedOrPaused => hero_surf.subtitle,
    };
    let status_kicker = match proj.hero.tone {
        HeroTone::Healthy if monitor_only => format!(
            "仅监测模式 · {}/{} 出口合规",
            proj.hero.pass_count, total_targets
        ),
        HeroTone::Healthy => format!(
            "守护正常 · {}/{} 出口合规",
            proj.hero.pass_count, total_targets
        ),
        HeroTone::Tripped if really_tripped => {
            format!("已触发熔断 · {} 项越界", proj.hero.fail_count.max(1))
        }
        HeroTone::Tripped if monitor_only => {
            format!(
                "仅监测预警 · {} 项异常（不熔断）",
                proj.hero.fail_count.max(1)
            )
        }
        HeroTone::Tripped => format!("出口预警 · {} 项异常", proj.hero.fail_count.max(1)),
        HeroTone::DisarmedOrPaused => {
            if !connected {
                "未连接 · 安全闭锁".into()
            } else if lifecycle == Lifecycle::Unconfigured {
                "待首启配置".into()
            } else if lifecycle == Lifecycle::Disarmed {
                "已撤防".into()
            } else if proj.hero.is_paused {
                "守护已暂停".into()
            } else if ip_unchanged_hold {
                "出口波动 · IP 未变暂不熔断".into()
            } else if monitor_only && proj.hero.fail_count > 0 {
                format!(
                    "仅监测预警 · {} 项异常（不熔断）",
                    proj.hero.fail_count.max(1)
                )
            } else {
                proj.hero.pill_label.clone()
            }
        }
    };
    let hero_title = if !connected {
        "守护服务未连接"
    } else if lifecycle == Lifecycle::Unconfigured {
        "等待完成首启配置"
    } else if lifecycle == Lifecycle::Disarmed {
        "保护已撤防放行"
    } else if really_tripped {
        "已隔离受管 AI 客户端"
    } else if ip_unchanged_hold {
        "出口波动（IP 未变）"
    } else if pre_trip_fail && monitor_only {
        "出口异常（仅监测）"
    } else if pre_trip_fail {
        "检测到出口不合规"
    } else if proj.hero.is_paused {
        "已暂停自动拦截"
    } else if proj.hero.tone == HeroTone::Healthy {
        "出口纯净合规"
    } else {
        "正在核验出口与防线"
    };

    let tripped_lines: Option<(String, String)> = proj.tripped_card.as_ref().map(|diag| {
        (
            format!("期望：{}", diag.expected_summary),
            format!("实测：{}", diag.observed_summary),
        )
    });

    let primary_target = proj
        .target_cards
        .iter()
        .find(|t| t.id == "claude")
        .or_else(|| proj.target_cards.first());

    let hero_ip_copy = primary_target.map(|t| t.ip_display.clone());
    let hero_subtitle = if proj.hero.is_paused {
        format!(
            "仅只读探测，不触发新增隔离（{}）",
            proj.hero
                .paused_remaining_text
                .as_deref()
                .unwrap_or("即将自动恢复")
        )
    } else if let Some(primary) = primary_target {
        format!("{} · {}", primary.location_display, primary.ip_display)
    } else {
        proj.hero.subtitle.clone()
    };

    let metric_region = primary_target
        .map(|t| format!("{} · {}", t.cc_badge, t.latency_label))
        .unwrap_or_else(|| "--".into());
    let metric_mid_label = if proj.hero.is_paused {
        "暂停倒计时"
    } else {
        "出口通道"
    };
    let metric_mid_val = if proj.hero.is_paused {
        proj.hero
            .paused_remaining_text
            .clone()
            .unwrap_or_else(|| "即将恢复".into())
    } else {
        proj.hero.access_badge.clone()
    };
    let hover_tile = p.sidebar_hover_bg;

    let hero_actions = if !connected {
        let ctrl_start = ctrl.clone();
        let ctrl_conn = ctrl.clone();
        div()
            .flex()
            .flex_wrap()
            .items_center()
            .gap(px(8.))
            .when(!is_demo, |row| {
                row.child(
                    spinning_action_button(
                        "ov-start-service",
                        "icons/ui/shield.svg",
                        if start_svc_busy {
                            "启动中…"
                        } else {
                            "启动守护服务"
                        },
                        ButtonKind::Primary,
                        !busy,
                        start_svc_busy,
                        p,
                    )
                    .when(!busy, |b| {
                        b.on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |_, _, _, cx| {
                                ctrl_start.update(cx, |c, cx| c.start_daemon_service(cx));
                            }),
                        )
                    }),
                )
            })
            .child(
                icon_action_button(
                    "ov-reconnect",
                    "icons/ui/refresh.svg",
                    if busy && !start_svc_busy {
                        "重连中…"
                    } else {
                        "重连服务"
                    },
                    if is_demo {
                        ButtonKind::Primary
                    } else {
                        ButtonKind::Secondary
                    },
                    !busy,
                    p,
                )
                .when(!busy, |b| {
                    b.on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |_, _, _, cx| {
                            ctrl_conn.update(cx, |c, cx| {
                                c.send_request(
                                    PipeRequest::GetSnapshot,
                                    Some("已重新连接守护服务"),
                                    cx,
                                );
                            });
                        }),
                    )
                }),
            )
    } else if lifecycle == Lifecycle::Unconfigured {
        let ctrl_onb = ctrl.clone();
        div().flex().items_center().gap(px(8.)).child(
            icon_action_button(
                "ov-open-onb",
                "icons/ui/shield.svg",
                "完成首启配置",
                ButtonKind::Primary,
                true,
                p,
            )
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(move |_, _, _, cx| {
                    ctrl_onb.update(cx, |c, cx| c.open_onboarding_modal(cx));
                }),
            ),
        )
    } else if lifecycle == Lifecycle::Disarmed {
        let ctrl_rearm = ctrl.clone();
        div().flex().items_center().gap(px(8.)).child(
            icon_action_button(
                "ov-rearm",
                "icons/ui/shield.svg",
                "重新布防",
                ButtonKind::Primary,
                can_act,
                p,
            )
            .when(can_act, |b| {
                b.on_mouse_up(
                    MouseButton::Left,
                    cx.listener(move |_, _, _, cx| {
                        ctrl_rearm.update(cx, |c, cx| {
                            c.send_request(
                                PipeRequest::Rearm,
                                Some("已重新布防，恢复出口守护"),
                                cx,
                            );
                        });
                    }),
                )
            }),
        )
    } else if really_tripped {
        let ctrl_a = ctrl.clone();
        let ctrl_b = ctrl.clone();
        div()
            .flex()
            .flex_wrap()
            .items_center()
            .gap(px(8.))
            .child(
                icon_action_button(
                    "ov-trip-flow-a",
                    "icons/ui/refresh.svg",
                    "复查并解封",
                    ButtonKind::Danger,
                    can_act,
                    p,
                )
                .when(can_act, |b| {
                    b.on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |_, _, _, cx| {
                            ctrl_a.update(cx, |c, cx| {
                                c.send_request(
                                    PipeRequest::RecoverSafeFlowA,
                                    Some("复查通过，已安全解封"),
                                    cx,
                                );
                            });
                        }),
                    )
                }),
            )
            .child(
                action_button(
                    "ov-trip-flow-b",
                    "暂不用 AI · 解封",
                    ButtonKind::Secondary,
                    can_act,
                    p,
                )
                .when(can_act, |b| {
                    b.on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |_, _, _, cx| {
                            ctrl_b.update(cx, |c, cx| {
                                c.send_request(
                                    PipeRequest::DisarmAndRestoreFlowB {
                                        reason: Some("用户从总览手动停止并解封".into()),
                                    },
                                    Some("已撤防并解除隔离"),
                                    cx,
                                );
                            });
                        }),
                    )
                }),
            )
    } else {
        let ctrl_chk = ctrl.clone();
        let ctrl_pause = ctrl.clone();
        let can_recheck_hero = connected && !recheck_all_busy;
        let can_pause_hero = ctrl_r.can_toggle_pause();

        div()
            .flex()
            .flex_wrap()
            .items_center()
            .gap(px(8.))
            .child(
                spinning_action_button(
                    "ov-recheck-now",
                    "icons/ui/refresh.svg",
                    if recheck_all_busy {
                        "核验中…"
                    } else {
                        "立即核验"
                    },
                    ButtonKind::Primary,
                    can_recheck_hero,
                    recheck_all_busy,
                    p,
                )
                .when(can_recheck_hero, |b| {
                    b.on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |_, _, _, cx| {
                            ctrl_chk.update(cx, |c, cx| {
                                c.send_request(
                                    PipeRequest::RecheckNow { target_id: None },
                                    Some("已完成出口核验"),
                                    cx,
                                );
                            });
                        }),
                    )
                }),
            )
            .child(
                action_button(
                    "ov-pause-30m",
                    if proj.hero.is_paused {
                        "恢复守护"
                    } else {
                        "暂停 30m"
                    },
                    ButtonKind::Secondary,
                    can_pause_hero,
                    p,
                )
                .when(can_pause_hero, |b| {
                    b.on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |_, _, _, cx| {
                            ctrl_pause.update(cx, |c, cx| c.toggle_pause_30m(cx));
                        }),
                    )
                }),
            )
    };

    let ctrl_copy_hero_ip = ctrl.clone();
    let hero_subtitle_el = if let Some((exp_line, obs_line)) = tripped_lines {
        div()
            .flex()
            .flex_col()
            .gap(px(2.5))
            .child(
                mono_tabular(exp_line)
                    .text_size(px(11.))
                    .line_height(px(15.))
                    .text_color(rgb(hero_surf.subtitle)),
            )
            .child(
                mono_tabular(obs_line)
                    .text_size(px(11.5))
                    .font_weight(FontWeight::SEMIBOLD)
                    .line_height(px(15.5))
                    .text_color(rgb(p.badge_fail.text)),
            )
            .into_any_element()
    } else if let Some(ip_to_copy) =
        hero_ip_copy.filter(|ip| ip.chars().any(|c| c.is_ascii_digit()) && !ip.contains('*'))
    {
        div()
            .id("ov-hero-copy-ip")
            .cursor_pointer()
            .rounded(px(6.))
            .hover(move |s| s.bg(rgb(hover_tile)))
            .child(
                mono_tabular(hero_subtitle)
                    .truncate()
                    .text_size(px(11.5))
                    .text_color(rgb(hero_surf.subtitle)),
            )
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(move |_, _, _, cx| {
                    let ip = ip_to_copy.clone();
                    ctrl_copy_hero_ip.update(cx, |c, cx| c.copy_to_clipboard(ip, "出口 IP", cx));
                }),
            )
            .into_any_element()
    } else {
        mono_tabular(hero_subtitle)
            .truncate()
            .text_size(px(11.5))
            .text_color(rgb(hero_surf.subtitle))
            .into_any_element()
    };

    let hero_telemetry_strip = div()
        .flex()
        .items_center()
        .w_full()
        .gap(px(7.))
        .child(
            inset_box(p)
                .flex_1()
                .flex_basis(px(0.))
                .px(px(10.))
                .py(px(6.5))
                .gap(px(1.5))
                .child(
                    div()
                        .text_size(px(10.))
                        .text_color(rgb(p.text_muted))
                        .child("主出口"),
                )
                .child(
                    mono_tabular(metric_region)
                        .truncate()
                        .text_size(px(11.5))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(rgb(p.text_primary)),
                ),
        )
        .child(
            inset_box(p)
                .flex_1()
                .flex_basis(px(0.))
                .px(px(10.))
                .py(px(6.5))
                .gap(px(1.5))
                .child(
                    div()
                        .text_size(px(10.))
                        .text_color(rgb(p.text_muted))
                        .child(metric_mid_label),
                )
                .child(
                    mono_tabular(metric_mid_val)
                        .truncate()
                        .text_size(px(11.5))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(rgb(if proj.hero.is_paused {
                            p.badge_warn.text
                        } else {
                            p.text_primary
                        })),
                ),
        )
        .child(
            inset_box(p)
                .flex_1()
                .flex_basis(px(0.))
                .px(px(10.))
                .py(px(6.5))
                .gap(px(1.5))
                .child(
                    div()
                        .text_size(px(10.))
                        .text_color(rgb(p.text_muted))
                        .child("24h 合规"),
                )
                .child(
                    mono_tabular(compliance_pct.clone())
                        .truncate()
                        .text_size(px(11.5))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(rgb(if really_tripped {
                            p.badge_fail.text
                        } else if non_empty == 0 {
                            p.text_muted
                        } else {
                            p.text_primary
                        })),
                ),
        );

    let (risk_score, risk_grade, risk_evaluated) = snap
        .as_deref()
        .map(|s| {
            (
                s.risk_assessment.score,
                s.risk_assessment.grade,
                s.risk_assessment.evaluated_at > 0,
            )
        })
        .unwrap_or((0, SafetyGrade::C, false));
    let risk_tone = if risk_evaluated {
        safety_grade_tone(risk_grade)
    } else {
        BadgeTone::Muted
    };
    let configuring_hooks = ctrl_r.is_scope_busy(&ActionScope::ConfigureHooks);
    let hooks_unconfigured = snap
        .as_deref()
        .is_some_and(|s| !s.hooks.claude_code_hook_installed);
    let geo_cooldown_alert = snap
        .as_deref()
        .and_then(|s| s.risk_assessment.geo_velocity_alert.clone());
    let ctrl_to_radar = ctrl.clone();

    let risk_ring_badge = div()
        .id("ov-risk-score-badge")
        .cursor_pointer()
        .flex()
        .items_center()
        .flex_shrink_0()
        .hover(|s| s.opacity(0.88))
        .child(tone_tag(
            if risk_evaluated {
                format!("体检 {risk_score}分 · {}级", risk_grade.code())
            } else {
                "防封体检待检".into()
            },
            risk_tone,
            p,
        ))
        .on_mouse_up(
            MouseButton::Left,
            cx.listener(move |_, _, _, cx| {
                ctrl_to_radar.update(cx, |c, cx| {
                    c.env_tab = EnvSubTab::RiskRadar;
                    c.set_nav(NavSection::Environment, cx);
                });
            }),
        );

    let hero_pose = choreo.tile(0, 0);
    let hero_card = bento_card_bloom(p, 18.0, 16.0, hero_pose)
        .flex_1()
        .bg(rgba(hero_surf.bg))
        .border_color(rgba(hero_surf.border))
        .justify_between()
        .gap(px(12.))
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(5.5))
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
                                .gap(px(7.))
                                .min_w(px(0.))
                                .child(pulse_status_dot(
                                    "hero-status-pulse",
                                    status_dot_color,
                                    7.5,
                                    connected
                                        && (proj.hero.tone == HeroTone::Healthy || really_tripped),
                                ))
                                .child(
                                    div()
                                        .truncate()
                                        .text_size(px(12.))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(status_kicker_color))
                                        .child(status_kicker),
                                ),
                        )
                        .child(risk_ring_badge),
                )
                .child(
                    div()
                        .text_size(px(22.))
                        .font_weight(FontWeight::BOLD)
                        .line_height(px(27.))
                        .text_color(rgb(hero_surf.title))
                        .child(hero_title),
                )
                .child(hero_subtitle_el),
        )
        .when(!really_tripped, |c| c.child(hero_telemetry_strip))
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .gap(px(8.))
                .child(hero_actions)
                .child({
                    let (foot_label, foot_val) = if proj.hero.is_paused || snap.is_none() {
                        ("端口", format!(":{proxy_port}"))
                    } else {
                        ("轮询", format!("{interval_secs}s"))
                    };
                    div()
                        .flex()
                        .items_center()
                        .flex_shrink_0()
                        .gap(px(4.))
                        .text_size(px(11.))
                        .text_color(rgb(p.text_muted))
                        .child(foot_label)
                        .child(mono_tabular(foot_val))
                }),
        );
    let hero_slot = div()
        .w(relative(0.47))
        .flex_shrink_0()
        .flex()
        .child(hero_card);

    // -------------------------------------------------------------------------
    // Upper Row Right: Dedicated 2x2 Safe Launch Deck (53%)
    // -------------------------------------------------------------------------
    let deck_ok = connected && proj.hero.can_launch;
    let deck_crisis = really_tripped || (pre_trip_fail && !monitor_only);
    let deck_dot_color = if deck_crisis || !connected {
        p.badge_fail.dot
    } else if deck_ok {
        p.badge_pass.dot
    } else {
        p.badge_warn.dot
    };
    let deck_text_color = if deck_crisis {
        p.badge_fail.text
    } else {
        p.text_secondary
    };
    let deck_badge = if !connected {
        "离线锁定"
    } else if really_tripped {
        "熔断锁定"
    } else if pre_trip_fail {
        "预警锁定"
    } else if deck_ok {
        "门禁放行"
    } else if proj.hero.is_paused {
        "守护已暂停"
    } else if lifecycle == Lifecycle::Disarmed {
        "已撤防"
    } else {
        "待核验"
    };

    let mut pad_cards: Vec<Div> = proj
        .launch_apps
        .iter()
        .take(4)
        .enumerate()
        .map(|(pad_idx, app)| {
            let pad_pose = choreo.inner_bloom(0, pad_idx);
            let ctrl_l = ctrl.clone();
            let aid = app.agent_id.clone();
            let paths = app.install_paths.clone();
            let hard_locked = !connected
                || really_tripped
                || pre_trip_fail
                || app.quarantined
                || app.ag_proxy_blocked;
            let standby_locked = !hard_locked && !proj.hero.can_launch;
            let unlocked = !hard_locked && !standby_locked;

            let dot_rgb = if hard_locked {
                p.badge_fail.dot
            } else if standby_locked {
                if app.orphan_count > 0 {
                    p.badge_warn.dot
                } else {
                    p.text_muted
                }
            } else if app.orphan_count > 0 {
                p.badge_warn.dot
            } else if !app.installed {
                p.text_muted
            } else {
                p.badge_pass.dot
            };

            let sub_text = if hard_locked {
                if app.ag_proxy_blocked {
                    "注入缺失".to_string()
                } else if !connected {
                    "服务离线".to_string()
                } else {
                    "禁止启动".to_string()
                }
            } else if standby_locked {
                if !app.installed {
                    "未安装".to_string()
                } else if proj.hero.is_paused {
                    "已暂停".to_string()
                } else if lifecycle == Lifecycle::Disarmed {
                    "已撤防".to_string()
                } else {
                    "等待核验".to_string()
                }
            } else if !app.installed {
                "未安装".to_string()
            } else if app.agent_id == "antigravity" && app.ag_proxy_ready {
                if app.orphan_count > 0 {
                    format!("注入正常 · {} 孤儿", app.orphan_count)
                } else {
                    format!("{} 运行 · 注入正常", app.running_count)
                }
            } else if app.orphan_count > 0 {
                format!("{} 运行 · {} 孤儿", app.running_count, app.orphan_count)
            } else if app.agent_id == "antigravity" && !require_ag_proxy {
                format!("{} 运行 · 自定义代理", app.running_count)
            } else {
                format!("{} 运行 · 合规", app.running_count)
            };

            let sub_color = if hard_locked {
                p.badge_fail.text
            } else if standby_locked {
                p.text_muted
            } else if app.orphan_count > 0 {
                p.badge_warn.text
            } else {
                p.text_secondary
            };

            let (pill_bg, pill_border, pill_icon, pill_icon_color, pill_txt, pill_label) =
                if hard_locked {
                    (
                        rgba(p.badge_fail.bg),
                        rgba(p.hero_tripped.border),
                        "icons/ui/lock.svg",
                        p.badge_fail.text,
                        p.badge_fail.text,
                        "锁定",
                    )
                } else if standby_locked {
                    let label = if proj.hero.is_paused {
                        "已暂停"
                    } else if lifecycle == Lifecycle::Disarmed {
                        "待布防"
                    } else {
                        "待核验"
                    };
                    (
                        rgb(p.card_bg),
                        rgb(p.card_border),
                        "icons/ui/clock.svg",
                        p.text_muted,
                        p.text_muted,
                        label,
                    )
                } else {
                    (
                        rgb(p.card_bg),
                        rgb(p.secondary_btn_border),
                        "icons/ui/play.svg",
                        p.accent_soft_text,
                        p.text_primary,
                        "启动",
                    )
                };

            let hover_bg = p.sidebar_hover_bg;
            let hover_border = p.card_hover_border;
            let can_click = connected && !busy && app.installed;

            let mut card = div()
                .id(gpui::ElementId::Name(
                    format!("ov-launch-{}", app.agent_id).into(),
                ))
                .flex()
                .flex_col()
                .justify_between()
                .min_w(px(0.))
                .p(px(10.5))
                .gap(px(9.))
                .rounded(px(11.))
                .bg(rgb(p.inset_bg))
                .border_1()
                .border_color(if hard_locked && really_tripped {
                    rgba(p.hero_tripped.border)
                } else {
                    rgb(p.inset_border)
                })
                .when(!pad_pose.is_settled(), |c| {
                    c.opacity(pad_pose.opacity.clamp(0.0, 1.0))
                })
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap(px(6.))
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap(px(7.5))
                                .min_w(px(0.))
                                .flex_1()
                                .child(brand_icon_scaled(
                                    &app.agent_id,
                                    25.0,
                                    7.0,
                                    p.is_dark,
                                    pad_pose.scale,
                                ))
                                .child(
                                    div()
                                        .truncate()
                                        .text_size(px(12.))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(p.text_primary))
                                        .child(short_launch_name(&app.agent_id, &app.label)),
                                ),
                        )
                        .child(
                            div()
                                .flex()
                                .flex_shrink_0()
                                .items_center()
                                .gap(px(3.5))
                                .px(px(8.))
                                .py(px(2.5))
                                .rounded(px(999.))
                                .bg(pill_bg)
                                .border_1()
                                .border_color(pill_border)
                                .when(unlocked, |pill| {
                                    pill.shadow(vec![
                                        BoxShadow::new(
                                            px(0.),
                                            px(1.),
                                            rgba(p.specular_top_rgba).into(),
                                        )
                                        .inset(),
                                        BoxShadow::new(px(0.), px(1.), rgba(p.shadow_rgba).into())
                                            .blur_radius(px(2.5)),
                                    ])
                                })
                                .text_size(px(10.5))
                                .font_weight(FontWeight::MEDIUM)
                                .text_color(rgb(pill_txt))
                                .child(ui_icon(pill_icon, 9.5, pill_icon_color))
                                .child(pill_label),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(5.5))
                        .child(status_dot(dot_rgb, 5.5))
                        .child(
                            mono_tabular(sub_text)
                                .truncate()
                                .text_size(px(10.5))
                                .font_weight(FontWeight::MEDIUM)
                                .text_color(rgb(sub_color)),
                        ),
                );

            if can_click {
                card = card
                    .cursor_pointer()
                    .hover(move |s| s.bg(rgb(hover_bg)).border_color(rgb(hover_border)))
                    .active(|s| s.opacity(0.90))
                    .on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |_, _, _, cx| {
                            ctrl_l.update(cx, |c, cx| {
                                c.launch_app_with_gate(aid.clone(), paths.clone(), cx);
                            });
                        }),
                    );
            }
            div()
                .flex_1()
                .flex_basis(px(0.))
                .min_w(px(0.))
                .flex()
                .child(card.flex_1())
        })
        .collect();

    let pads_row1 = div()
        .flex()
        .w_full()
        .gap(px(8.))
        .children(pad_cards.drain(0..pad_cards.len().min(2)));
    let pads_row2 = div().flex().w_full().gap(px(8.)).children(pad_cards);

    let deck_pose = choreo.tile(0, 1);
    let launch_deck = bento_card_bloom(p, 16.0, 14.0, deck_pose)
        .flex_1()
        .min_w(px(0.))
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
                        .gap(px(6.))
                        .child(ui_icon(
                            if really_tripped {
                                "icons/ui/shield_alert.svg"
                            } else {
                                "icons/ui/shield.svg"
                            },
                            14.0,
                            deck_text_color,
                        ))
                        .child(
                            div()
                                .text_size(px(13.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.text_primary))
                                .child("安全启动台"),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(5.5))
                        .child(status_dot(deck_dot_color, 5.5))
                        .child(
                            div()
                                .text_size(px(11.))
                                .font_weight(if deck_crisis {
                                    FontWeight::SEMIBOLD
                                } else {
                                    FontWeight::MEDIUM
                                })
                                .text_color(rgb(deck_text_color))
                                .child(deck_badge),
                        ),
                ),
        )
        .child(pads_row1)
        .child(pads_row2);
    let deck_slot = div().flex_1().min_w(px(0.)).flex().child(launch_deck);

    // -------------------------------------------------------------------------
    // Lower Row Col 1: Managed Processes (33.5%)
    // -------------------------------------------------------------------------
    let total_running: usize = proj.agent_statuses.iter().map(|a| a.running_count).sum();
    let total_orphans: usize = proj.agent_statuses.iter().map(|a| a.orphan_count).sum();
    let ctrl_kill_all = ctrl.clone();
    let ctrl_sweep = ctrl.clone();

    // Group managed core AI clients cleanly by brand family.
    let mut sorted_agents: Vec<_> = proj.agent_statuses.iter().collect();
    sorted_agents.sort_by_key(|a| brand_family_rank(&a.id));

    let proc_rows = sorted_agents
        .iter()
        .take(5)
        .enumerate()
        .map(|(row_idx, a)| {
            let row_pose = choreo.inner_bloom(1, row_idx.min(4));
            let can_kill = can_act && (a.running_count > 0 || a.orphan_count > 0);
            let aid = a.id.clone();
            let toast = cleanup_toast_for_agent(&a.id);
            let ctrl_k = ctrl.clone();
            let stat_txt = if !a.installed {
                "未安装".into()
            } else if a.orphan_count > 0 {
                format!("{} 运行 · {} 孤儿", a.running_count, a.orphan_count)
            } else {
                format!("{} 运行", a.running_count)
            };
            let stat_color = if a.orphan_count > 0 {
                p.badge_warn.text
            } else {
                p.text_muted
            };
            let hover_bg = p.sidebar_hover_bg;
            let icon_key = agent_icon_key(&a.id, &a.kind);
            let display_name = canonical_agent_label(&a.id, &a.name).to_string();

            let row = div()
                .flex()
                .items_center()
                .justify_between()
                .gap(px(6.))
                .py(px(5.5))
                .px(px(5.))
                .rounded(px(8.))
                .hover(move |s| s.bg(rgb(hover_bg)))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(7.5))
                        .min_w(px(0.))
                        .flex_1()
                        .child(brand_icon_scaled(
                            icon_key,
                            19.0,
                            5.5,
                            p.is_dark,
                            row_pose.scale,
                        ))
                        .child(
                            div()
                                .truncate()
                                .text_size(px(12.))
                                .font_weight(FontWeight::MEDIUM)
                                .text_color(rgb(p.text_primary))
                                .child(display_name),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .flex_shrink_0()
                        .gap(px(6.))
                        .child(
                            mono_tabular(stat_txt)
                                .text_size(px(10.5))
                                .text_color(rgb(stat_color)),
                        )
                        .child(
                            action_button(
                                gpui::ElementId::Name(format!("ov-kill-{}", a.id).into()),
                                "清理",
                                ButtonKind::Ghost,
                                can_kill,
                                p,
                            )
                            .h(px(22.))
                            .px(px(7.))
                            .text_size(px(10.5))
                            .when(can_kill, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_k.update(cx, |c, cx| {
                                            c.send_request(
                                                PipeRequest::ForceKillAgent {
                                                    agent_id: Some(aid.clone()),
                                                    include_cli: true,
                                                },
                                                Some(toast),
                                                cx,
                                            );
                                        });
                                    }),
                                )
                            }),
                        ),
                );
            row_pose.apply(row)
        });

    let kill_all_enabled =
        ctrl.read(cx).can_kill_processes() && (total_running > 0 || total_orphans > 0);
    let procs_pose = choreo.tile(1, 0);
    let col_procs = bento_card_bloom(p, 15.0, 14.0, procs_pose)
        .flex_1()
        .justify_between()
        .gap(px(10.))
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(8.))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .child(
                            div()
                                .text_size(px(13.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.text_primary))
                                .child("受管进程治理"),
                        )
                        .child(
                            action_button(
                                "ov-kill-all",
                                if kill_all_armed {
                                    "确认全清？"
                                } else {
                                    "一键全清"
                                },
                                if kill_all_armed {
                                    ButtonKind::DangerSoft
                                } else {
                                    ButtonKind::Ghost
                                },
                                kill_all_enabled,
                                p,
                            )
                            .h(px(23.))
                            .px(px(8.))
                            .text_size(px(10.5))
                            .when(kill_all_enabled, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_kill_all.update(cx, |c, cx| {
                                            if c.arm_or_consume_confirm("ov-kill-all", cx) {
                                                c.send_request(
                                                    PipeRequest::ForceKillAgent {
                                                        agent_id: None,
                                                        include_cli: true,
                                                    },
                                                    Some("已清理全部受管 AI 客户端进程"),
                                                    cx,
                                                );
                                            }
                                        });
                                    }),
                                )
                            }),
                        ),
                )
                .child(div().flex().flex_col().gap(px(2.)).children(proc_rows)),
        )
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .pt(px(9.))
                .border_t_1()
                .border_color(rgb(p.card_border))
                .child(
                    mono_tabular(format!("{total_running} 运行 · {total_orphans} 孤儿"))
                        .text_size(px(11.))
                        .text_color(rgb(p.text_muted)),
                )
                .child(if total_orphans > 0 {
                    let sweep_hover_bg = p.sidebar_hover_bg;
                    let sweep_hover_border = p.card_hover_border;
                    div()
                        .id("ov-sweep-orphans")
                        .cursor_pointer()
                        .flex()
                        .items_center()
                        .gap(px(5.))
                        .px(px(8.))
                        .py(px(2.5))
                        .rounded(px(7.))
                        .bg(rgb(p.inset_bg))
                        .border_1()
                        .border_color(rgb(p.inset_border))
                        .hover(move |s| {
                            s.bg(rgb(sweep_hover_bg))
                                .border_color(rgb(sweep_hover_border))
                        })
                        .active(|s| s.opacity(0.88))
                        .child(status_dot(p.badge_warn.dot, 5.0))
                        .child(
                            div()
                                .text_size(px(10.5))
                                .font_weight(FontWeight::MEDIUM)
                                .text_color(rgb(p.text_secondary))
                                .child("清理孤儿"),
                        )
                        .on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |_, _, _, cx| {
                                ctrl_sweep.update(cx, |c, cx| {
                                    c.send_request(
                                        PipeRequest::SweepOrphans,
                                        Some("已清理全部孤儿进程"),
                                        cx,
                                    );
                                });
                            }),
                        )
                        .into_any_element()
                } else {
                    div()
                        .text_size(px(11.))
                        .text_color(rgb(p.text_muted))
                        .child("无孤儿进程")
                        .into_any_element()
                }),
        );
    let procs_slot = div()
        .w(relative(0.335))
        .flex_shrink_0()
        .flex()
        .child(col_procs);

    // -------------------------------------------------------------------------
    // Lower Row Col 2: Read-Only Live Egress Telemetry (35.5%)
    // -------------------------------------------------------------------------
    let ctrl_to_targets = ctrl.clone();
    let extra_targets = proj.target_cards.len().saturating_sub(3);
    let egress_rows = proj
        .target_cards
        .iter()
        .take(3)
        .enumerate()
        .map(|(row_idx, t)| {
            let row_pose = choreo.inner_bloom(2, row_idx);
            let is_fail = t.badge_tone == BadgeTone::Fail;
            let is_warn = t.badge_tone == BadgeTone::Warn;
            let is_pass = t.badge_tone == BadgeTone::Pass;
            let status_color = if is_fail {
                p.badge_fail.text
            } else if is_warn {
                p.badge_warn.text
            } else if is_pass {
                p.text_primary
            } else {
                p.text_muted
            };
            let status_txt = if is_fail {
                format!("{} · 越界", t.cc_badge)
            } else if is_warn {
                if t.cc_badge == "--" || t.cc_badge == "TLS" {
                    t.state_label.clone()
                } else {
                    format!("{} · 待确认", t.cc_badge)
                }
            } else if !is_pass {
                t.state_label.clone()
            } else if t.cc_badge == "TLS" {
                "代理连通".to_string()
            } else {
                format!("{} · 合规", t.cc_badge)
            };
            let tid = t.id.clone();
            let tname = t.name.clone();
            let ip_copy = t.ip_display.clone();
            let ip_copyable = ip_copy.chars().any(|c| c.is_ascii_digit()) && !ip_copy.contains('*');
            let target_busy = ctrl_r.is_scope_busy(&ActionScope::RecheckTarget(t.id.clone()));
            let ctrl_rt = ctrl.clone();
            let ctrl_ip = ctrl.clone();
            let hover_bg = p.sidebar_hover_bg;

            let row_box = inset_box(p)
                .flex_row()
                .items_center()
                .justify_between()
                .px(px(10.))
                .py(px(8.5))
                .gap(px(8.))
                .when(is_fail, |box_d| {
                    box_d
                        .bg(rgba(p.badge_fail.bg))
                        .border_color(rgba(p.hero_tripped.border))
                })
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(8.))
                        .min_w(px(0.))
                        .flex_1()
                        .child(brand_icon_scaled(
                            &t.id,
                            23.0,
                            6.5,
                            p.is_dark,
                            row_pose.scale,
                        ))
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .min_w(px(0.))
                                .flex_1()
                                .gap(px(1.5))
                                .child(
                                    div()
                                        .truncate()
                                        .text_size(px(12.))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(p.text_primary))
                                        .child(short_target_name(&t.id, &t.name)),
                                )
                                .child({
                                    let mut ip_el = div()
                                        .id(gpui::ElementId::Name(
                                            format!("ov-copy-ip-{}", t.id).into(),
                                        ))
                                        .child(
                                            mono_tabular(
                                                compact_target_sub(&t.ip_display).to_string(),
                                            )
                                            .truncate()
                                            .text_size(px(10.5))
                                            .text_color(rgb(p.text_muted)),
                                        );
                                    if ip_copyable {
                                        let ip_str = ip_copy.clone();
                                        ip_el = ip_el
                                            .cursor_pointer()
                                            .hover(move |s| s.text_color(rgb(p.text_primary)))
                                            .on_mouse_up(
                                                MouseButton::Left,
                                                cx.listener(move |_, _, _, cx| {
                                                    let ip = ip_str.clone();
                                                    ctrl_ip.update(cx, |c, cx| {
                                                        c.copy_to_clipboard(ip, "出口 IP", cx);
                                                    });
                                                }),
                                            );
                                    }
                                    ip_el
                                }),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .flex_shrink_0()
                        .gap(px(7.))
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .items_end()
                                .gap(px(1.))
                                .child(
                                    div()
                                        .flex()
                                        .items_center()
                                        .gap(px(5.))
                                        .when(is_pass, |row| {
                                            row.child(status_dot(p.badge_pass.dot, 5.5))
                                        })
                                        .child(
                                            mono_tabular(status_txt)
                                                .text_size(px(11.))
                                                .font_weight(FontWeight::SEMIBOLD)
                                                .text_color(rgb(status_color)),
                                        ),
                                )
                                .child(
                                    mono_tabular(t.latency_label.clone())
                                        .text_size(px(10.))
                                        .text_color(rgb(p.text_muted)),
                                ),
                        )
                        .child({
                            let mut btn = div()
                                .id(gpui::ElementId::Name(format!("ov-recheck-{}", t.id).into()))
                                .flex()
                                .items_center()
                                .justify_center()
                                .w(px(24.))
                                .h(px(24.))
                                .rounded(px(7.))
                                .bg(rgb(p.card_bg))
                                .border_1()
                                .border_color(rgb(p.card_border))
                                .child(spinning_ui_icon(
                                    gpui::ElementId::Name(format!("ov-spin-{}", t.id).into()),
                                    "icons/ui/refresh.svg",
                                    11.5,
                                    p.text_secondary,
                                    target_busy,
                                ));
                            if can_act {
                                btn = btn
                                    .cursor_pointer()
                                    .hover(move |s| {
                                        s.bg(rgb(hover_bg)).border_color(rgb(p.line_strong))
                                    })
                                    .active(|s| s.opacity(0.85))
                                    .on_mouse_up(
                                        MouseButton::Left,
                                        cx.listener(move |_, _, _, cx| {
                                            let id = tid.clone();
                                            let msg = format!("已完成重检：{tname}");
                                            ctrl_rt.update(cx, |c, cx| {
                                                c.send_request_msg(
                                                    PipeRequest::RecheckNow {
                                                        target_id: Some(id),
                                                    },
                                                    Some(msg),
                                                    cx,
                                                );
                                            });
                                        }),
                                    );
                            }
                            btn
                        }),
                );
            row_pose.apply(row_box)
        });

    let egress_pose = choreo.tile(1, 1);
    let col_egress = bento_card_bloom(p, 15.0, 14.0, egress_pose)
        .flex_1()
        .justify_between()
        .gap(px(10.))
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(9.))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap(px(6.))
                        .child(
                            div()
                                .text_size(px(13.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.text_primary))
                                .child("出口实况探测"),
                        )
                        .child(
                            mono_tabular(
                                if matches!(
                                    proj.hero.checked_age_text.as_str(),
                                    "尚未检测" | "等待快照"
                                ) {
                                    proj.hero.checked_age_text.clone()
                                } else {
                                    format!("最近 · {}", proj.hero.checked_age_text)
                                },
                            )
                            .text_size(px(10.5))
                            .text_color(rgb(p.text_muted)),
                        ),
                )
                .child(div().flex().flex_col().gap(px(8.)).children(egress_rows)),
        )
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .pt(px(9.))
                .border_t_1()
                .border_color(rgb(p.card_border))
                .child(
                    div()
                        .text_size(px(11.))
                        .text_color(rgb(p.text_muted))
                        .child(if extra_targets > 0 {
                            format!("另有 {extra_targets} 项目标")
                        } else {
                            "仅只读核验 · 不改代理".into()
                        }),
                )
                .child(
                    div()
                        .id("ov-to-targets")
                        .cursor_pointer()
                        .text_size(px(11.))
                        .font_weight(FontWeight::MEDIUM)
                        .text_color(rgb(p.link_text))
                        .hover(move |s| s.text_color(rgb(p.link_hover_text)))
                        .child("白名单配置 →")
                        .on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |_, _, _, cx| {
                                ctrl_to_targets.update(cx, |c, cx| {
                                    c.set_nav(NavSection::Targets, cx);
                                });
                            }),
                        ),
                ),
        );
    let egress_slot = div()
        .w(relative(0.355))
        .flex_shrink_0()
        .flex()
        .child(col_egress);

    // -------------------------------------------------------------------------
    // Lower Row Col 3: 4-Vector Leak Shield + Antigravity Status + 24h Mini Tape (31%)
    // -------------------------------------------------------------------------
    let ctrl_to_env = ctrl.clone();
    let ctrl_to_shield = ctrl.clone();
    let ctrl_to_ag = ctrl.clone();
    let ctrl_to_audit = ctrl.clone();
    let ctrl_q = ctrl.clone();
    let ctrl_d = ctrl.clone();
    let ctrl_v = ctrl.clone();

    let (ag_dot, ag_label_color, ag_label) = if ag_degraded {
        (p.badge_fail.dot, p.badge_fail.text, "异常 · 修复")
    } else if ag_installed && ag_ready {
        (p.badge_pass.dot, p.text_secondary, "正常")
    } else if ag_installed && !require_ag_proxy {
        (p.text_muted, p.text_muted, "自定义代理")
    } else {
        (p.text_muted, p.text_muted, "未安装")
    };

    let shield_pose = choreo.tile(1, 2);
    let col_shield = bento_card_bloom(p, 15.0, 14.0, shield_pose)
        .flex_1()
        .min_w(px(0.))
        .justify_between()
        .gap(px(10.))
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(10.))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .child(
                            div()
                                .text_size(px(13.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.text_primary))
                                .child("四维防漏"),
                        )
                        .child(
                            div()
                                .id("ov-to-env")
                                .cursor_pointer()
                                .text_size(px(11.))
                                .font_weight(FontWeight::MEDIUM)
                                .text_color(rgb(p.link_text))
                                .hover(move |s| s.text_color(rgb(p.link_hover_text)))
                                .child("详情 →")
                                .on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_to_env.update(cx, |c, cx| {
                                            c.env_tab = EnvSubTab::Shield;
                                            c.set_nav(NavSection::Environment, cx);
                                        });
                                    }),
                                ),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .gap(px(10.))
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .justify_between()
                                .child(
                                    div()
                                        .text_size(px(12.))
                                        .font_weight(FontWeight::MEDIUM)
                                        .text_color(rgb(p.text_secondary))
                                        .child("阻断 QUIC"),
                                )
                                .child(toggle_switch("ov-sh-quic", quic_on, can_act, p).when(
                                    can_act,
                                    |sw| {
                                        sw.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                let next = !quic_on;
                                                ctrl_q.update(cx, |c, cx| {
                                                    c.save_toggle_patch(
                                                        "sh-quic",
                                                        next,
                                                        move |x| x.leak_shield_quic = next,
                                                        "QUIC 防漏规则已同步",
                                                        cx,
                                                    );
                                                });
                                            }),
                                        )
                                    },
                                )),
                        )
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .justify_between()
                                .child(
                                    div()
                                        .text_size(px(12.))
                                        .font_weight(FontWeight::MEDIUM)
                                        .text_color(rgb(p.text_secondary))
                                        .child("阻断 DNS / DoH"),
                                )
                                .child(toggle_switch("ov-sh-dns", dns_on, can_act, p).when(
                                    can_act,
                                    |sw| {
                                        sw.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                let next = !dns_on;
                                                ctrl_d.update(cx, |c, cx| {
                                                    c.save_toggle_patch(
                                                        "sh-dns",
                                                        next,
                                                        move |x| x.leak_shield_dns_doh = next,
                                                        "DNS / DoH 防漏规则已同步",
                                                        cx,
                                                    );
                                                });
                                            }),
                                        )
                                    },
                                )),
                        )
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .justify_between()
                                .child(
                                    div()
                                        .text_size(px(12.))
                                        .font_weight(FontWeight::MEDIUM)
                                        .text_color(rgb(p.text_secondary))
                                        .child("阻断 IPv6"),
                                )
                                .child(toggle_switch("ov-sh-ipv6", ipv6_on, can_act, p).when(
                                    can_act,
                                    |sw| {
                                        sw.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                let next = !ipv6_on;
                                                ctrl_v.update(cx, |c, cx| {
                                                    c.save_toggle_patch(
                                                        "sh-ipv6",
                                                        next,
                                                        move |x| x.leak_shield_ipv6 = next,
                                                        "IPv6 防漏规则已同步",
                                                        cx,
                                                    );
                                                });
                                            }),
                                        )
                                    },
                                )),
                        ),
                )
                .child(
                    inset_box(p)
                        .id("ov-ag-inject-shortcut")
                        .cursor_pointer()
                        .flex_row()
                        .items_center()
                        .justify_between()
                        .px(px(9.))
                        .py(px(7.))
                        .hover(move |s| s.bg(rgb(hover_tile)))
                        .child(
                            div()
                                .text_size(px(11.))
                                .text_color(rgb(p.text_secondary))
                                .child("反重力注入"),
                        )
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap(px(5.))
                                .child(status_dot(ag_dot, 5.5))
                                .child(
                                    div()
                                        .text_size(px(11.))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(ag_label_color))
                                        .child(ag_label),
                                ),
                        )
                        .on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |_, _, _, cx| {
                                ctrl_to_ag.update(cx, |c, cx| {
                                    c.env_tab = EnvSubTab::Antigravity;
                                    c.set_nav(NavSection::Environment, cx);
                                });
                            }),
                        ),
                )
                .child(
                    inset_box(p)
                        .id("ov-shield-radar-shortcut")
                        .cursor_pointer()
                        .flex_row()
                        .items_center()
                        .justify_between()
                        .px(px(9.))
                        .py(px(7.))
                        .hover(move |s| s.bg(rgb(hover_tile)))
                        .child(
                            mono_tabular(format!("护盾 {active_rules} 条"))
                                .text_size(px(10.5))
                                .text_color(rgb(p.text_secondary)),
                        )
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap(px(5.))
                                .child(status_dot(
                                    if direct_total > 0 {
                                        p.badge_fail.dot
                                    } else {
                                        p.badge_pass.dot
                                    },
                                    5.5,
                                ))
                                .child(
                                    mono_tabular(if direct_total > 0 {
                                        format!("{direct_total} 条直连")
                                    } else {
                                        "无直连".into()
                                    })
                                    .text_size(px(10.5))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .text_color(rgb(
                                        if direct_total > 0 {
                                            p.badge_fail.text
                                        } else {
                                            p.text_secondary
                                        },
                                    )),
                                ),
                        )
                        .on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |_, _, _, cx| {
                                ctrl_to_shield.update(cx, |c, cx| {
                                    c.env_tab = EnvSubTab::Shield;
                                    c.set_nav(NavSection::Environment, cx);
                                });
                            }),
                        ),
                ),
        )
        .child(
            div()
                .id("ov-mini-timeline")
                .cursor_pointer()
                .flex()
                .flex_col()
                .gap(px(6.))
                .pt(px(9.))
                .border_t_1()
                .border_color(rgb(p.card_border))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .child(
                            div()
                                .text_size(px(11.))
                                .text_color(rgb(p.text_muted))
                                .child("24h 轨迹"),
                        )
                        .child(
                            mono_tabular(compliance_pct)
                                .text_size(px(11.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(if really_tripped {
                                    p.badge_fail.text
                                } else if non_empty == 0 {
                                    p.text_muted
                                } else {
                                    p.text_primary
                                })),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(1.5))
                        .children(mini_bars_vec),
                )
                .on_mouse_up(
                    MouseButton::Left,
                    cx.listener(move |_, _, _, cx| {
                        ctrl_to_audit.update(cx, |c, cx| c.set_nav(NavSection::Audit, cx));
                    }),
                ),
        );
    let shield_slot = div().flex_1().min_w(px(0.)).flex().child(col_shield);

    // Closed-loop 1-click inline remediation strip (Geo-Velocity Cooldown or Unprotected CLI Hooks)
    let inline_remediation_banner = if connected && !really_tripped {
        if let Some(alert) = geo_cooldown_alert {
            let ctrl_geo_fix = ctrl.clone();
            let rem_secs = alert
                .cooldown_until
                .unwrap_or(0)
                .saturating_sub(crate::demo::now_unix_secs());
            let mins = rem_secs / 60;
            let secs = rem_secs % 60;
            Some(
                inset_box(p)
                    .flex_row()
                    .items_center()
                    .justify_between()
                    .gap(px(10.))
                    .px(px(12.))
                    .py(px(7.5))
                    .bg(rgba(p.badge_warn.bg))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(7.))
                            .min_w(px(0.))
                            .flex_1()
                            .child(status_dot(p.badge_warn.dot, 6.0))
                            .child(
                                div()
                                    .truncate()
                                    .text_size(px(11.5))
                                    .font_weight(FontWeight::MEDIUM)
                                    .text_color(rgb(p.badge_warn.text))
                                    .child(format!(
                                        "跨国秒切保护生效中（距上次节点约 {} km，剩余冷却 {:02}:{:02}）",
                                        alert.distance_km, mins, secs
                                    )),
                            ),
                    )
                    .child(
                        action_button(
                            "ov-clear-geo-cooldown",
                            "确认本人切换节点 · 立即放行",
                            ButtonKind::Secondary,
                            can_act,
                            p,
                        )
                        .h(px(25.))
                        .px(px(10.))
                        .text_size(px(11.))
                        .when(can_act, |b| {
                            b.on_mouse_up(
                                MouseButton::Left,
                                cx.listener(move |_, _, _, cx| {
                                    ctrl_geo_fix.update(cx, |c, cx| {
                                        c.send_request(
                                            PipeRequest::ClearGeoVelocityCooldown,
                                            Some("已确认本人切换节点，立即恢复放行"),
                                            cx,
                                        );
                                    });
                                }),
                            )
                        }),
                    )
                    .into_any_element(),
            )
        } else if hooks_unconfigured
            && lifecycle == Lifecycle::Armed
            && ctrl.read(cx).dismissed_overview_banner_key.as_deref() != Some("hooks-unconfigured")
        {
            let ctrl_hook_fix = ctrl.clone();
            let ctrl_hook_dismiss = ctrl.clone();
            Some(
                inset_box(p)
                    .flex_row()
                    .items_center()
                    .justify_between()
                    .gap(px(10.))
                    .px(px(12.))
                    .py(px(7.))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(7.))
                            .min_w(px(0.))
                            .flex_1()
                            .child(status_dot(p.badge_warn.dot, 5.5))
                            .child(
                                div()
                                    .truncate()
                                    .text_size(px(11.5))
                                    .text_color(rgb(p.text_secondary))
                                    .child(
                                        "终端命令行（Claude Code / PowerShell）尚未开启每次提问前自动防封检查",
                                    ),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .flex_shrink_0()
                            .gap(px(6.))
                            .child(
                                spinning_action_button(
                                    "ov-oneclick-cli-hooks",
                                    "icons/ui/shield.svg",
                                    if configuring_hooks {
                                        "正在保护…"
                                    } else {
                                        "一键保护终端"
                                    },
                                    ButtonKind::Primary,
                                    can_act && !configuring_hooks,
                                    configuring_hooks,
                                    p,
                                )
                                .h(px(25.))
                                .px(px(10.))
                                .text_size(px(11.))
                                .when(can_act && !configuring_hooks, |b| {
                                    b.on_mouse_up(
                                        MouseButton::Left,
                                        cx.listener(move |_, _, _, cx| {
                                            ctrl_hook_fix.update(cx, |c, cx| {
                                                c.send_request(
                                                    PipeRequest::ConfigureCliHooks {
                                                        install_claude_code: true,
                                                        install_pwsh_profile: true,
                                                        sync_all_vaults: true,
                                                    },
                                                    Some("已为终端 Claude Code 与 PowerShell 开启防封保护"),
                                                    cx,
                                                );
                                            });
                                        }),
                                    )
                                }),
                            )
                            .child(
                                action_button(
                                    "ov-dismiss-cli-hooks-banner",
                                    "× 已知晓",
                                    ButtonKind::Ghost,
                                    true,
                                    p,
                                )
                                .h(px(25.))
                                .px(px(7.5))
                                .text_size(px(10.5))
                                .on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_hook_dismiss.update(cx, |c, cx| {
                                            c.dismissed_overview_banner_key =
                                                Some("hooks-unconfigured".into());
                                            cx.notify();
                                        });
                                    }),
                                ),
                            ),
                    )
                    .into_any_element(),
            )
        } else {
            None
        }
    } else {
        None
    };

    div()
        .flex()
        .flex_col()
        .w_full()
        .flex_1()
        .min_w(px(0.))
        .gap(px(11.))
        .when_some(inline_remediation_banner, |col, banner| col.child(banner))
        .child(
            div()
                .flex()
                .flex_row()
                .w_full()
                .min_w(px(0.))
                .gap(px(11.))
                .child(hero_slot)
                .child(deck_slot),
        )
        .child(
            div()
                .flex()
                .flex_row()
                .w_full()
                .flex_1()
                .min_w(px(0.))
                .gap(px(11.))
                .child(procs_slot)
                .child(egress_slot)
                .child(shield_slot),
        )
}
