//! Mode B — Frost Ceramic `防漏与环境` view (3 pure defense sub-tabs, ZERO Mihomo mutation).
//!
//! Sub-tabs:
//! 1. `防漏护盾与雷达` (`EnvSubTab::Shield`): 4-vector leak shield + direct-leak & MCP radar
//! 2. `反重力代理注入` (`EnvSubTab::Antigravity`): 2×2 diagnostics + plain-language explanation + hot-repair
//! 3. `时区与区域指纹` (`EnvSubTab::Timezone`): pure Windows TZ & locale alignment (no proxy switching)

use crate::app::{ActionScope, AppController, ConsoleWindowView, EnvSubTab};
use crate::assets::brand_icon_scaled;
use crate::demo::now_unix_secs;
use crate::motion::PageChoreo;
use crate::protocol::{
    AntigravityProxyStatus, BURST_GUARD_MODES, BurstGuardMode, HOOK_FAIL_MODES, HookFailMode,
    PipeRequest, UiLabelExt, UpdateCheckPhase, UpdateSummary, mask_ip_str, mask_ips_in_text,
};
use crate::state::{
    NavSection, format_relative_secs, format_remaining_secs, project_antigravity_proxy_card,
    safety_grade_tone,
};
use crate::theme::{BadgeTone, ThemePalette};
use crate::views::shared::{ag_diag_tile, page_guide_card, switch_row_gated};
use crate::widgets::controls::{
    ButtonKind, action_button, bento_card_bloom, icon_action_button, inset_box, mono_tabular,
    offset_pane, segmented_capsule_item, segmented_capsule_track, spinning_action_button,
    spinning_ui_icon, status_dot, status_pill, subtab_bar, subtab_item, tone_tag,
};
use gpui::{
    Context, Div, Entity, FontWeight, MouseButton, div, prelude::*, px, relative, rgb, rgba,
};

fn mask_windows_user_path(path: &str) -> String {
    let lower = path.to_ascii_lowercase();
    for marker in ["\\users\\", "/users/"] {
        if let Some(pos) = lower.find(marker) {
            let start = pos + marker.len();
            if path.is_char_boundary(start)
                && let Some(rest) = path.get(start..)
            {
                let end_rel = rest.find(['\\', '/']).unwrap_or(rest.len());
                if end_rel > 0 {
                    let mut out = String::with_capacity(path.len());
                    out.push_str(&path[..start]);
                    out.push_str("***");
                    out.push_str(&rest[end_rel..]);
                    return out;
                }
            }
        }
    }
    path.to_string()
}

pub fn render_environment_page(
    ctrl: Entity<AppController>,
    choreo: PageChoreo,
    subtab_dx: f32,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> Div {
    let ctrl_r = ctrl.read(cx);
    let snap = ctrl_r.snapshot.clone();
    let tab = ctrl_r.env_tab;
    let mask = ctrl_r.privacy_mask;
    let busy = ctrl_r.busy_action;
    let connected = ctrl_r.connected;
    let tripped = snap.as_ref().is_some_and(|s| s.is_tripped());
    let can_act = connected && !busy;

    let cfg = snap.as_ref().map(|s| s.config.clone()).unwrap_or_default();
    let ag_proxy = snap
        .as_ref()
        .map(|s| s.antigravity_proxy.clone())
        .unwrap_or_default();
    let updates = snap.as_ref().map(|s| s.updates.clone()).unwrap_or_default();
    let leak = snap.as_ref().map(|s| s.leak.clone()).unwrap_or_default();
    let shield = snap
        .as_ref()
        .map(|s| s.leak_shield.clone())
        .unwrap_or_default();
    let env = snap.as_ref().map(|s| s.env.clone()).unwrap_or_default();
    let env_applied = snap.as_ref().and_then(|s| s.env_applied.clone());
    let risk = snap
        .as_ref()
        .map(|s| s.risk_assessment.clone())
        .unwrap_or_default();
    let hooks = snap.as_ref().map(|s| s.hooks.clone()).unwrap_or_default();
    let wsl = snap
        .as_ref()
        .map(|s| s.wsl_bridge.clone())
        .unwrap_or_default();
    let burst = snap
        .as_ref()
        .map(|s| s.burst_guard.clone())
        .unwrap_or_default();
    let hotkeys_snap = snap.as_ref().map(|s| s.hotkeys.clone()).unwrap_or_default();
    let local_hk_report = ctrl_r.hotkey_registration_report();
    let risk_alert = risk.evaluated_at > 0
        && (risk.geo_velocity_alert.is_some()
            || risk.stun_leak.leaked
            || risk.dns_coherence.domestic_resolver_detected
            || risk.score < 60);
    let hooks_alert = wsl.proxy_desync_detected
        || burst.robotic_cadence_detected
        || burst.unauthorized_oauth_client_detected;

    let require_ag_proxy =
        ctrl_r.effective_toggle("env-ag-require-proxy", cfg.require_antigravity_proxy);
    let auto_repair_ag_proxy =
        ctrl_r.effective_toggle("env-ag-auto-repair", cfg.auto_repair_antigravity_proxy);
    let ag_issue = ag_proxy.installed && require_ag_proxy && !ag_proxy.is_ready_for_launch();
    let is_rechecking = ctrl_r.is_scope_busy(&ActionScope::RecheckAll);
    let is_repairing_ag = ctrl_r.is_scope_busy(&ActionScope::RepairAntigravity);
    let is_syncing_shield = ctrl_r.is_scope_busy(&ActionScope::SyncLeakShield);
    let is_aligning_env = ctrl_r.is_scope_busy(&ActionScope::EnvAlign);
    let is_deep_auditing = ctrl_r.is_scope_busy(&ActionScope::DeepRiskAudit);
    let is_configuring_hooks = ctrl_r.is_scope_busy(&ActionScope::ConfigureHooks);
    let is_syncing_wsl = ctrl_r.is_scope_busy(&ActionScope::SyncWslBridge);
    let is_building_card = ctrl_r.is_scope_busy(&ActionScope::BuildHealthCard);

    let quic_on = ctrl_r.effective_toggle("sh-quic", cfg.leak_shield_quic);
    let dns_on = ctrl_r.effective_toggle("sh-dns", cfg.leak_shield_dns_doh);
    let ipv6_on = ctrl_r.effective_toggle("sh-ipv6", cfg.leak_shield_ipv6);
    let leak_watch_on = ctrl_r.effective_toggle("env-leak-watch", cfg.leak_watch);
    let leak_trip_on = ctrl_r.effective_toggle("env-leak-trip", cfg.leak_trip);
    let env_check_on = ctrl_r.effective_toggle("env-check-sw", cfg.env_check);
    let env_align_tz_on = ctrl_r.effective_toggle("env-tz-sw", cfg.env_align_tz);
    let env_align_loc_on = ctrl_r.effective_toggle("env-loc-sw", cfg.env_align_location);
    let block_dc_asn_on = ctrl_r.effective_toggle("env-block-dc-asn", cfg.block_datacenter_asn);
    let geo_vel_on = ctrl_r.effective_toggle("env-geo-vel", cfg.enforce_geo_velocity);
    let electron_hyg_on =
        ctrl_r.effective_toggle("env-electron-hyg", cfg.enforce_electron_hygiene_flags);
    let stun_audit_on = ctrl_r.effective_toggle("env-stun-audit", cfg.enable_stun_dns_audit);
    let wsl_enabled_on = ctrl_r.effective_toggle("env-wsl-enabled", cfg.wsl_bridge_enabled);
    let hotkeys_enabled_on =
        ctrl_r.effective_toggle("env-hotkeys-enabled", cfg.global_hotkeys_enabled);
    let shield_unsynced = cfg.leak_shield_quic != shield.quic_blocked
        || cfg.leak_shield_dns_doh != shield.dns_doh_blocked
        || cfg.leak_shield_ipv6 != shield.ipv6_blocked;

    let ctrl_t1 = ctrl.clone();
    let ctrl_t_risk = ctrl.clone();
    let ctrl_t_hooks = ctrl.clone();
    let ctrl_t2 = ctrl.clone();
    let ctrl_t3 = ctrl.clone();
    let tabs = div().flex().items_center().child(
        subtab_bar(p)
            .child(
                subtab_item(
                    "env-tab-shield",
                    "防漏护盾与雷达",
                    tab == EnvSubTab::Shield,
                    None,
                    None,
                    p,
                )
                .on_mouse_up(
                    MouseButton::Left,
                    cx.listener(move |_, _, _, cx| {
                        ctrl_t1.update(cx, |c, cx| {
                            c.env_tab = EnvSubTab::Shield;
                            cx.notify();
                        });
                    }),
                ),
            )
            .child(
                subtab_item(
                    "env-tab-risk",
                    "10D 风险雷达",
                    tab == EnvSubTab::RiskRadar,
                    risk_alert.then_some(p.badge_fail.dot),
                    (risk.evaluated_at > 0).then(|| format!("{}分", risk.score)),
                    p,
                )
                .on_mouse_up(
                    MouseButton::Left,
                    cx.listener(move |_, _, _, cx| {
                        ctrl_t_risk.update(cx, |c, cx| {
                            c.env_tab = EnvSubTab::RiskRadar;
                            cx.notify();
                        });
                    }),
                ),
            )
            .child(
                subtab_item(
                    "env-tab-hooks",
                    "CLI 门禁 & WSL2",
                    tab == EnvSubTab::HooksWsl,
                    hooks_alert.then_some(p.badge_warn.dot),
                    None,
                    p,
                )
                .on_mouse_up(
                    MouseButton::Left,
                    cx.listener(move |_, _, _, cx| {
                        ctrl_t_hooks.update(cx, |c, cx| {
                            c.env_tab = EnvSubTab::HooksWsl;
                            cx.notify();
                        });
                    }),
                ),
            )
            .child(
                subtab_item(
                    "env-tab-ag",
                    "反重力代理注入",
                    tab == EnvSubTab::Antigravity,
                    ag_issue.then_some(p.badge_fail.dot),
                    None,
                    p,
                )
                .on_mouse_up(
                    MouseButton::Left,
                    cx.listener(move |_, _, _, cx| {
                        ctrl_t2.update(cx, |c, cx| {
                            c.env_tab = EnvSubTab::Antigravity;
                            cx.notify();
                        });
                    }),
                ),
            )
            .child(
                subtab_item(
                    "env-tab-tz",
                    "时区与区域指纹",
                    tab == EnvSubTab::Timezone,
                    None,
                    None,
                    p,
                )
                .on_mouse_up(
                    MouseButton::Left,
                    cx.listener(move |_, _, _, cx| {
                        ctrl_t3.update(cx, |c, cx| {
                            c.env_tab = EnvSubTab::Timezone;
                            cx.notify();
                        });
                    }),
                ),
            ),
    );

    let body = match tab {
        EnvSubTab::Shield => {
            let ctrl_q = ctrl.clone();
            let ctrl_d = ctrl.clone();
            let ctrl_v = ctrl.clone();
            let ctrl_sync = ctrl.clone();
            let ctrl_lw = ctrl.clone();
            let ctrl_lt = ctrl.clone();
            let ctrl_scan = ctrl.clone();

            let shield_pill = |label: &'static str, on: bool| -> Div {
                div()
                    .px(px(7.))
                    .py(px(2.5))
                    .rounded(px(6.))
                    .bg(rgb(p.card_bg))
                    .border_1()
                    .border_color(rgb(p.card_border))
                    .text_size(px(10.5))
                    .font_family("Cascadia Mono")
                    .text_color(rgb(if on { p.badge_pass.text } else { p.text_muted }))
                    .child(format!("{} {label}", if on { "●" } else { "○" }))
            };

            let left_shield = bento_card_bloom(p, 16., 14., choreo.tile(0, 0))
                .flex_1()
                .justify_between()
                .gap(px(10.))
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .gap(px(6.))
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .justify_between()
                                .child(
                                    div()
                                        .text_size(px(12.5))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(p.text_primary))
                                        .child("四维防漏护盾"),
                                )
                                .child(
                                    div()
                                        .flex()
                                        .items_center()
                                        .gap(px(6.))
                                        .when(shield_unsynced, |row| {
                                            row.child(tone_tag("待同步", BadgeTone::Warn, p))
                                        })
                                        .child(
                                            div()
                                                .flex()
                                                .items_center()
                                                .gap(px(5.5))
                                                .when(shield.enabled, |d| {
                                                    d.child(status_dot(p.badge_pass.dot, 5.5))
                                                })
                                                .child(
                                                    mono_tabular(if shield.enabled {
                                                        format!(
                                                            "生效 {} 条规则",
                                                            shield.active_rules
                                                        )
                                                    } else {
                                                        "未启用".into()
                                                    })
                                                    .text_size(px(11.))
                                                    .font_weight(FontWeight::SEMIBOLD)
                                                    .text_color(rgb(if shield.enabled {
                                                        p.text_primary
                                                    } else {
                                                        p.text_muted
                                                    })),
                                                ),
                                        ),
                                ),
                        )
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .child(
                                    switch_row_gated(
                                        "sh-quic-sw",
                                        "阻断 QUIC (UDP:443)",
                                        "阻止 HTTP/3 绕过代理直连",
                                        quic_on,
                                        can_act,
                                        p,
                                        cx.listener(move |_, _, _, cx| {
                                            let next = !quic_on;
                                            ctrl_q.update(cx, |c, cx| {
                                                c.save_toggle_patch(
                                                    "sh-quic",
                                                    next,
                                                    move |x| x.leak_shield_quic = next,
                                                    "QUIC 护盾已更新",
                                                    cx,
                                                );
                                            });
                                        }),
                                    )
                                    .border_b_1()
                                    .border_color(rgb(p.card_border)),
                                )
                                .child(
                                    switch_row_gated(
                                        "sh-dns-sw",
                                        "阻断 DNS / DoH 直连",
                                        "防止绕过代理向公共 DNS 解析",
                                        dns_on,
                                        can_act,
                                        p,
                                        cx.listener(move |_, _, _, cx| {
                                            let next = !dns_on;
                                            ctrl_d.update(cx, |c, cx| {
                                                c.save_toggle_patch(
                                                    "sh-dns",
                                                    next,
                                                    move |x| x.leak_shield_dns_doh = next,
                                                    "DNS / DoH 护盾已更新",
                                                    cx,
                                                );
                                            });
                                        }),
                                    )
                                    .border_b_1()
                                    .border_color(rgb(p.card_border)),
                                )
                                .child(switch_row_gated(
                                    "sh-ipv6-sw",
                                    "阻断公网 IPv6 直连",
                                    "防止双栈网络下 IPv6 绕过代理",
                                    ipv6_on,
                                    can_act,
                                    p,
                                    cx.listener(move |_, _, _, cx| {
                                        let next = !ipv6_on;
                                        ctrl_v.update(cx, |c, cx| {
                                            c.save_toggle_patch(
                                                "sh-ipv6",
                                                next,
                                                move |x| x.leak_shield_ipv6 = next,
                                                "IPv6 护盾已更新",
                                                cx,
                                            );
                                        });
                                    }),
                                )),
                        )
                        .child(
                            inset_box(p)
                                .px(px(11.))
                                .py(px(9.))
                                .gap(px(6.))
                                .child(
                                    div()
                                        .flex()
                                        .items_center()
                                        .justify_between()
                                        .child(
                                            div()
                                                .text_size(px(11.))
                                                .font_weight(FontWeight::SEMIBOLD)
                                                .text_color(rgb(p.text_primary))
                                                .child("生效范围"),
                                        )
                                        .child(
                                            div()
                                                .text_size(px(10.5))
                                                .font_weight(FontWeight::MEDIUM)
                                                .text_color(rgb(p.text_secondary))
                                                .child("仅限受管 AI 应用"),
                                        ),
                                )
                                .child(
                                    div()
                                        .flex()
                                        .flex_wrap()
                                        .gap(px(5.))
                                        .child(shield_pill("UDP:443 QUIC", quic_on))
                                        .child(shield_pill("DNS:53 & DoH", dns_on))
                                        .child(shield_pill("公网 IPv6", ipv6_on))
                                        .child(shield_pill(
                                            "反重力注入",
                                            ag_proxy.installed && ag_proxy.is_ready_for_launch(),
                                        )),
                                )
                                .child(
                                    div()
                                        .text_size(px(10.5))
                                        .line_height(px(15.5))
                                        .text_color(rgb(p.text_secondary))
                                        .child("规则仅绑定受管 AI 客户端，不影响日常联网；撤防或卸载自动清空。"),
                                ),
                        ),
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
                                .text_color(rgb(if shield_unsynced {
                                    p.badge_warn.text
                                } else {
                                    p.text_muted
                                }))
                                .child(if shield_unsynced {
                                    "开关与生效规则不一致，请同步"
                                } else if shield.enabled {
                                    "规则已同步至系统防火墙"
                                } else {
                                    "变更将于布防时自动生效"
                                }),
                        )
                        .child({
                            let can_sync_shield = connected && !is_syncing_shield;
                            spinning_action_button(
                                "env-shield-sync",
                                "icons/ui/refresh.svg",
                                if is_syncing_shield {
                                    "同步中…"
                                } else {
                                    "同步护盾规则"
                                },
                                ButtonKind::Primary,
                                can_sync_shield,
                                is_syncing_shield,
                                p,
                            )
                            .h(px(28.))
                            .when(can_sync_shield, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_sync.update(cx, |c, cx| {
                                            c.send_request(
                                                PipeRequest::SyncLeakShield,
                                                Some("四维防漏规则已同步"),
                                                cx,
                                            );
                                        });
                                    }),
                                )
                            })
                        }),
                );

            let mut leak_rows: Vec<Div> = if leak.direct.is_empty() {
                let note_text = if leak.proxied > 0 {
                    format!("{} 条活跃外连均走本地代理", leak.proxied)
                } else if !leak.note.is_empty() {
                    if mask {
                        mask_ips_in_text(&leak.note)
                    } else {
                        leak.note.clone()
                    }
                } else if leak.agent_conns == 0 {
                    "暂无受管客户端活跃外连".to_string()
                } else {
                    "受管客户端流量均经受管通道转发".to_string()
                };
                vec![
                    inset_box(p)
                        .px(px(11.))
                        .py(px(10.))
                        .gap(px(3.))
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap(px(5.5))
                                .text_size(px(11.5))
                                .font_weight(FontWeight::MEDIUM)
                                .text_color(rgb(p.text_primary))
                                .child(status_dot(p.badge_pass.dot, 5.5))
                                .child("无直连或 MCP 旁路泄露"),
                        )
                        .child(
                            div()
                                .text_size(px(10.5))
                                .text_color(rgb(p.text_muted))
                                .child(note_text),
                        ),
                ]
            } else {
                leak.direct
                    .iter()
                    .take(6)
                    .map(|c| {
                        let remote = if mask {
                            mask_ip_str(&c.remote)
                        } else {
                            c.remote.clone()
                        };
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .px(px(9.))
                            .py(px(6.5))
                            .rounded(px(8.))
                            .bg(rgba(p.badge_fail.bg))
                            .border_1()
                            .border_color(rgba(p.hero_tripped.border))
                            .gap(px(8.))
                            .child(
                                mono_tabular(format!(
                                    "PID {} · {} → {}:{}",
                                    c.pid, c.agent, remote, c.port
                                ))
                                .flex_1()
                                .min_w(px(0.))
                                .truncate()
                                .text_size(px(11.))
                                .text_color(rgb(p.badge_fail.text)),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .flex_shrink_0()
                                    .gap(px(5.))
                                    .when(c.is_mcp, |d| {
                                        d.child(
                                            div()
                                                .px(px(6.))
                                                .py(px(1.))
                                                .rounded(px(999.))
                                                .bg(rgb(p.card_bg))
                                                .border_1()
                                                .border_color(rgb(p.card_border))
                                                .text_size(px(10.))
                                                .text_color(rgb(p.text_secondary))
                                                .child("MCP"),
                                        )
                                    })
                                    .child(
                                        div()
                                            .text_size(px(10.5))
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(rgb(p.badge_fail.text))
                                            .child("直连泄露"),
                                    ),
                            )
                    })
                    .collect()
            };
            if leak.direct_total > 6 {
                leak_rows.push(
                    div()
                        .px(px(9.))
                        .py(px(5.))
                        .text_size(px(10.5))
                        .text_color(rgb(p.text_muted))
                        .child(format!(
                            "其余 {} 条详见「时间线与审计」",
                            leak.direct_total - 6
                        )),
                );
            }

            let scan_hover_bg = p.sidebar_hover_bg;
            let right_radar = bento_card_bloom(p, 16., 14., choreo.tile(0, 1))
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
                                        .text_size(px(12.5))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(p.text_primary))
                                        .child("直连与 MCP 雷达"),
                                )
                                .child(
                                    div()
                                        .flex()
                                        .items_center()
                                        .gap(px(5.5))
                                        .child(status_dot(
                                            if leak.direct_total > 0 {
                                                p.badge_fail.dot
                                            } else {
                                                p.badge_pass.dot
                                            },
                                            5.5,
                                        ))
                                        .child(
                                            mono_tabular(if leak.direct_total > 0 {
                                                format!("发现 {} 条直连", leak.direct_total)
                                            } else {
                                                "0 直连泄露".into()
                                            })
                                            .text_size(px(11.))
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(rgb(if leak.direct_total > 0 {
                                                p.badge_fail.text
                                            } else {
                                                p.text_primary
                                            })),
                                        ),
                                ),
                        )
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .child(
                                    switch_row_gated(
                                        "env-leak-watch",
                                        "直连泄露监测",
                                        "持续监测受管进程及 MCP 子进程外连",
                                        leak_watch_on,
                                        can_act,
                                        p,
                                        cx.listener(move |_, _, _, cx| {
                                            let next = !leak_watch_on;
                                            ctrl_lw.update(cx, |c, cx| {
                                                c.save_toggle_patch(
                                                    "env-leak-watch",
                                                    next,
                                                    move |x| x.leak_watch = next,
                                                    "直连泄露监测已更新",
                                                    cx,
                                                );
                                            });
                                        }),
                                    )
                                    .border_b_1()
                                    .border_color(rgb(p.card_border)),
                                )
                                .child(switch_row_gated(
                                    "env-leak-trip",
                                    "发现直连自动熔断",
                                    "默认仅告警，确认无误报后可开启",
                                    leak_trip_on,
                                    can_act,
                                    p,
                                    cx.listener(move |_, _, _, cx| {
                                        let next = !leak_trip_on;
                                        ctrl_lt.update(cx, |c, cx| {
                                            c.save_toggle_patch(
                                                "env-leak-trip",
                                                next,
                                                move |x| x.leak_trip = next,
                                                "直连自动熔断已更新",
                                                cx,
                                            );
                                        });
                                    }),
                                )),
                        )
                        .child(
                            inset_box(p)
                                .flex_row()
                                .items_center()
                                .justify_between()
                                .px(px(10.))
                                .py(px(7.))
                                .child(
                                    mono_tabular(format!(
                                        "活跃 {} · 代理 {} · 本地 {}",
                                        leak.agent_conns, leak.proxied, leak.local
                                    ))
                                    .text_size(px(11.))
                                    .text_color(rgb(p.text_secondary)),
                                )
                                .child(
                                    mono_tabular(format!("直连 {}", leak.direct_total))
                                        .text_size(px(11.))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(if leak.direct_total > 0 {
                                            p.badge_fail.text
                                        } else {
                                            p.text_secondary
                                        })),
                                ),
                        )
                        .child(div().flex().flex_col().gap(px(6.)).children(leak_rows)),
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
                                .child("自动豁免本机回环与 TUN 网卡"),
                        )
                        .child(
                            div()
                                .id("env-scan-now")
                                .flex()
                                .items_center()
                                .justify_center()
                                .gap(px(5.5))
                                .h(px(28.))
                                .px(px(11.))
                                .rounded(px(9.))
                                .bg(rgb(p.secondary_btn_bg))
                                .border_1()
                                .border_color(rgb(p.secondary_btn_border))
                                .text_size(px(12.))
                                .font_weight(FontWeight::MEDIUM)
                                .text_color(rgb(p.secondary_btn_text))
                                .when(can_act, |b| {
                                    b.cursor_pointer()
                                        .hover(move |s| s.bg(rgb(scan_hover_bg)))
                                        .active(|s| s.opacity(0.86))
                                        .on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                ctrl_scan.update(cx, |c, cx| {
                                                    c.send_request(
                                                        PipeRequest::RecheckNow { target_id: None },
                                                        Some("直连扫描已完成"),
                                                        cx,
                                                    );
                                                });
                                            }),
                                        )
                                })
                                .when(!can_act, |b| b.opacity(0.45))
                                .child(spinning_ui_icon(
                                    "env-scan-now-spin",
                                    "icons/ui/refresh.svg",
                                    12.5,
                                    p.secondary_btn_text,
                                    is_rechecking,
                                ))
                                .child(if is_rechecking {
                                    "扫描中…"
                                } else {
                                    "立即扫描"
                                }),
                        ),
                );

            let shield_guide = page_guide_card(
                "防漏原理",
                "仅约束受管 AI 客户端 · 不影响日常上网",
                &[
                    (
                        "1. 旁路协议封堵",
                        "封锁受管应用的 QUIC、直连 DNS 与公网 IPv6 旁路，强制流量经代理转发。",
                    ),
                    (
                        "2. MCP 子进程监测",
                        "自动识别 AI 工具拉起的 MCP 子进程异常直连并标记来源 PID。",
                    ),
                    (
                        "3. 回环与 TUN 豁免",
                        "自动放行 127.0.0.1、内网与 TUN 网卡流量，撤防或卸载即清空规则。",
                    ),
                ],
                p,
            );

            div()
                .flex()
                .flex_col()
                .w_full()
                .gap(px(10.))
                .child(
                    div()
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
                                .child(left_shield),
                        )
                        .child(
                            div()
                                .flex_1()
                                .flex_basis(px(0.))
                                .min_w(px(0.))
                                .flex()
                                .child(right_radar),
                        ),
                )
                .child(choreo.tile(1, 0).apply(shield_guide))
        }

        EnvSubTab::Antigravity => {
            let ag_running = snap.as_ref().is_some_and(|s| {
                s.agents
                    .iter()
                    .any(|a| a.id == "antigravity" && a.running_count > 0)
            });
            render_antigravity_proxy_card(
                ctrl.clone(),
                AgCardCtx {
                    ag: &ag_proxy,
                    updates: &updates,
                    guard_proxy_port: cfg.proxy_port,
                    require_ag_proxy,
                    auto_repair_ag_proxy,
                    privacy_mask: mask,
                    connected,
                    tripped,
                    can_act,
                    is_rechecking,
                    is_repairing: is_repairing_ag,
                    ag_running,
                },
                choreo,
                p,
                cx,
            )
        }

        EnvSubTab::Timezone => {
            let ctrl_ec = ctrl.clone();
            let ctrl_tz = ctrl.clone();
            let ctrl_loc = ctrl.clone();
            let ctrl_rb = ctrl.clone();
            let ctrl_apply = ctrl.clone();

            let tz_aligned = !env.mismatched();
            let loc_sub = match env_applied.as_ref() {
                Some(ap) if ap.touched_location() => "默认位置：已按出口对齐（已备份）",
                Some(_) => "默认位置：未修改（仅对齐时区）",
                None => "默认位置：系统原始值",
            };
            let main_tz_card = bento_card_bloom(p, 17., 14., choreo.tile(0, 0))
                .flex_1()
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
                                        .text_size(px(12.5))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(p.text_primary))
                                        .child("系统时区与区域对齐"),
                                )
                                .child(
                                    div()
                                        .text_size(px(11.))
                                        .text_color(rgb(p.text_muted))
                                        .child("仅对齐本机时区与区域，不修改代理策略"),
                                ),
                        )
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap(px(5.5))
                                .text_size(px(11.5))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(if tz_aligned {
                                    p.text_primary
                                } else {
                                    p.badge_warn.text
                                }))
                                .child(status_dot(
                                    if tz_aligned {
                                        p.badge_pass.dot
                                    } else {
                                        p.badge_warn.dot
                                    },
                                    5.5,
                                ))
                                .child(if env.mismatched() {
                                    if env_applied.is_some() {
                                        "出口已变 · 有偏差"
                                    } else {
                                        "与出口有偏差"
                                    }
                                } else if env_applied.is_some() {
                                    "已与出口对齐"
                                } else {
                                    "时区一致"
                                }),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .flex_row()
                        .gap(px(10.))
                        .child(ag_diag_tile(
                            "本机时区与区域",
                            format!("{} · {}", env.info.tz_label, env.info.locale),
                            loc_sub.into(),
                            p.text_primary,
                            true,
                            p,
                        ))
                        .child(ag_diag_tile(
                            "目标出口环境",
                            format!(
                                "{} · {}",
                                env.expect_city.as_deref().unwrap_or("待识别"),
                                env.expect_tz.as_deref().unwrap_or("--")
                            ),
                            "按当前合规出口城市自动匹配".into(),
                            p.text_primary,
                            true,
                            p,
                        )),
                )
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .child(
                            switch_row_gated(
                                "env-check-sw",
                                "检测时区与区域偏差",
                                "出口核验后对比本机时区，跨区偏差时提醒",
                                env_check_on,
                                can_act,
                                p,
                                cx.listener(move |_, _, _, cx| {
                                    let next = !env_check_on;
                                    ctrl_ec.update(cx, |c, cx| {
                                        c.save_toggle_patch(
                                            "env-check-sw",
                                            next,
                                            move |x| x.env_check = next,
                                            "时区偏差检测已更新",
                                            cx,
                                        );
                                    });
                                }),
                            )
                            .border_b_1()
                            .border_color(rgb(p.card_border)),
                        )
                        .child(
                            switch_row_gated(
                                "env-tz-sw",
                                "同步 Windows 系统时区",
                                "对齐出口时调整系统时区；首次自动备份，撤防或退出无损还原",
                                env_align_tz_on,
                                can_act,
                                p,
                                cx.listener(move |_, _, _, cx| {
                                    let next = !env_align_tz_on;
                                    ctrl_tz.update(cx, |c, cx| {
                                        c.save_toggle_patch(
                                            "env-tz-sw",
                                            next,
                                            move |x| x.env_align_tz = next,
                                            "系统时区对齐选项已更新",
                                            cx,
                                        );
                                    });
                                }),
                            )
                            .border_b_1()
                            .border_color(rgb(p.card_border)),
                        )
                        .child(switch_row_gated(
                            "env-loc-sw",
                            "同步 Windows 默认位置",
                            "对齐出口时同步系统默认坐标，撤防或退出同样无损还原",
                            env_align_loc_on,
                            can_act,
                            p,
                            cx.listener(move |_, _, _, cx| {
                                let next = !env_align_loc_on;
                                ctrl_loc.update(cx, |c, cx| {
                                    c.save_toggle_patch(
                                        "env-loc-sw",
                                        next,
                                        move |x| x.env_align_location = next,
                                        "默认位置对齐选项已更新",
                                        cx,
                                    );
                                });
                            }),
                        )),
                )
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
                            mono_tabular(if let Some(ap) = env_applied.as_ref() {
                                format!(
                                    "已对齐 {}：{} → {} · 可随时还原",
                                    ap.city,
                                    if ap.tz_from.is_empty() {
                                        "原始"
                                    } else {
                                        &ap.tz_from
                                    },
                                    if ap.tz_to.is_empty() {
                                        "未改"
                                    } else {
                                        &ap.tz_to
                                    }
                                )
                            } else {
                                format!("原始时区：{} · 对齐前自动备份", env.info.tz_label)
                            })
                            .flex_1()
                            .min_w(px(0.))
                            .truncate()
                            .text_size(px(11.))
                            .text_color(rgb(p.text_muted)),
                        )
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap(px(8.))
                                .child({
                                    let can_rb =
                                        connected && !is_aligning_env && env_applied.is_some();
                                    action_button(
                                        "env-rollback-btn",
                                        "还原原始环境",
                                        ButtonKind::Secondary,
                                        can_rb,
                                        p,
                                    )
                                    .h(px(28.))
                                    .when(can_rb, |b| {
                                        b.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                ctrl_rb.update(cx, |c, cx| {
                                                    c.send_request(
                                                        PipeRequest::RollbackEnvAlignment,
                                                        Some("已还原原始时区与默认位置"),
                                                        cx,
                                                    );
                                                });
                                            }),
                                        )
                                    })
                                })
                                .child({
                                    let do_tz = env_align_tz_on;
                                    let do_loc = env_align_loc_on;
                                    let can_align =
                                        connected && !is_aligning_env && (do_tz || do_loc);
                                    action_button(
                                        "env-apply-align-btn",
                                        if is_aligning_env {
                                            "对齐中…"
                                        } else if !do_tz && !do_loc {
                                            "请先开启对齐项"
                                        } else {
                                            "立即对齐出口"
                                        },
                                        ButtonKind::Primary,
                                        can_align,
                                        p,
                                    )
                                    .h(px(28.))
                                    .when(can_align, |b| {
                                        b.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                ctrl_apply.update(cx, |c, cx| {
                                                    c.send_request(
                                                        PipeRequest::ApplyEnvAlignment {
                                                            align_tz: do_tz,
                                                            align_location: do_loc,
                                                        },
                                                        Some("已将本机环境对齐至当前出口"),
                                                        cx,
                                                    );
                                                });
                                            }),
                                        )
                                    })
                                }),
                        ),
                );

            let guide = page_guide_card(
                "时区与区域对齐说明",
                "仅调整本机环境 · 退出无损还原",
                &[
                    (
                        "1. 减少跨区风控",
                        "出口与本机系统时区不一致时，部分受管 AI 客户端会判定账号环境异常。",
                    ),
                    (
                        "2. 不改代理策略",
                        "仅通过只读探测识别出口地区并同步本机时区，不切换节点或改动分流规则。",
                    ),
                    (
                        "3. 自动备份复原",
                        "首次对齐前自动备份原始值；点「还原原始环境」、撤防或退出均自动恢复。",
                    ),
                ],
                p,
            );

            div()
                .flex()
                .flex_col()
                .w_full()
                .gap(px(10.))
                .child(div().w_full().flex().child(main_tz_card))
                .child(choreo.tile(1, 0).apply(guide))
        }

        EnvSubTab::RiskRadar => {
            let now = now_unix_secs();
            let score_tone = if risk.evaluated_at > 0 {
                safety_grade_tone(risk.grade)
            } else {
                BadgeTone::Muted
            };
            let bar_color = match score_tone {
                BadgeTone::Pass => p.badge_pass.dot,
                BadgeTone::Warn => p.badge_warn.dot,
                BadgeTone::Fail => p.badge_fail.dot,
                BadgeTone::Muted => p.text_muted,
            };
            let checked_age =
                format_relative_secs((risk.evaluated_at > 0).then_some(risk.evaluated_at), now);

            let ctrl_audit = ctrl.clone();
            let ctrl_card = ctrl.clone();
            let ctrl_dc = ctrl.clone();
            let ctrl_gv = ctrl.clone();
            let ctrl_eh = ctrl.clone();
            let ctrl_sa = ctrl.clone();

            let header_card = bento_card_bloom(p, 17.0, 14.0, choreo.tile(0, 0))
                .flex_1()
                .gap(px(10.))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap(px(10.))
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .gap(px(3.))
                                .min_w(px(0.))
                                .flex_1()
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
                                                .child("当前网络防封体检分"),
                                        )
                                        .child(tone_tag(
                                            if risk.evaluated_at > 0 {
                                                format!("{} / 100 · {}", risk.score, risk.grade.label())
                                            } else {
                                                "尚未执行深度体检".into()
                                            },
                                            score_tone,
                                            p,
                                        )),
                                )
                                .child(
                                    mono_tabular(format!(
                                        "{} · 上次评估：{checked_age} · 1h 子网 {} 个 · 24h 跨国 {} 国",
                                        if risk.headline.is_empty() {
                                            "点击右侧「立即深度体检」评估 ASN、STUN 与 DNS 纯净度"
                                        } else {
                                            &risk.headline
                                        },
                                        risk.distinct_subnets_1h,
                                        risk.distinct_countries_24h
                                    ))
                                    .truncate()
                                    .text_size(px(11.))
                                    .text_color(rgb(p.text_secondary)),
                                ),
                        )
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .flex_shrink_0()
                                .gap(px(7.))
                                .child(
                                    icon_action_button(
                                        "env-export-health-card",
                                        "icons/ui/shield.svg",
                                        if is_building_card {
                                            "生成中…"
                                        } else {
                                            "导出防封体检图（已隐去 IP 与账号）"
                                        },
                                        ButtonKind::Secondary,
                                        can_act && !is_building_card,
                                        p,
                                    )
                                    .when(can_act && !is_building_card, |b| {
                                        b.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                ctrl_card.update(cx, |c, cx| {
                                                    c.build_and_export_health_card(true, cx);
                                                });
                                            }),
                                        )
                                    }),
                                )
                                .child(
                                    spinning_action_button(
                                        "env-run-deep-audit",
                                        "icons/ui/radar.svg",
                                        if is_deep_auditing {
                                            "深度体检中…"
                                        } else {
                                            "立即深度体检"
                                        },
                                        ButtonKind::Primary,
                                        can_act && !is_deep_auditing,
                                        is_deep_auditing,
                                        p,
                                    )
                                    .when(can_act && !is_deep_auditing, |b| {
                                        b.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                ctrl_audit.update(cx, |c, cx| {
                                                    c.send_request(
                                                        PipeRequest::RunDeepRiskAudit,
                                                        Some("10D 深度防封体检已完成"),
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
                        .w_full()
                        .h(px(7.))
                        .rounded(px(999.))
                        .bg(rgb(p.inset_bg))
                        .border_1()
                        .border_color(rgb(p.card_border))
                        .overflow_hidden()
                        .child(
                            div()
                                .h_full()
                                .w(relative((f32::from(risk.score) / 100.0).clamp(0.02, 1.0)))
                                .rounded(px(999.))
                                .bg(rgb(bar_color)),
                        ),
                );

            // Optional Impossible-Travel Geo-Velocity Alert Banner with Manual Cooldown Clear
            let geo_alert_el = risk.geo_velocity_alert.as_ref().map(|alert| {
                let ctrl_clear_geo = ctrl.clone();
                let rem_txt = format_remaining_secs(alert.cooldown_until, now)
                    .unwrap_or_else(|| "已就绪".into());
                bento_card_bloom(p, 16.0, 12.0, choreo.tile(0, 1))
                    .flex_1()
                    .bg(rgba(p.hero_tripped.bg))
                    .border_color(rgba(p.hero_tripped.border))
                    .flex_row()
                    .items_center()
                    .justify_between()
                    .gap(px(12.))
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap(px(3.))
                            .min_w(px(0.))
                            .flex_1()
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap(px(7.))
                                    .child(status_dot(p.badge_fail.dot, 6.5))
                                    .child(
                                        div()
                                            .text_size(px(12.5))
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(rgb(p.badge_fail.text))
                                            .child(format!(
                                                "跨国秒切保护（防异地登录风控） · 距上次节点约 {} km，建议冷却后再用",
                                                alert.distance_km
                                            )),
                                    ),
                            )
                            .child(
                                mono_tabular(format!(
                                    "{} ({}) → {} ({}) · 间隔 {}s · 剩余冷却 {}",
                                    alert.from_country,
                                    alert.from_city,
                                    alert.to_country,
                                    alert.to_city,
                                    alert.elapsed_secs,
                                    rem_txt
                                ))
                                .truncate()
                                .text_size(px(11.))
                                .text_color(rgb(p.text_primary)),
                            ),
                    )
                    .child(
                        action_button(
                            "env-clear-geo-cooldown",
                            "确认本人切换节点 · 立即放行",
                            ButtonKind::DangerSoft,
                            can_act,
                            p,
                        )
                        .when(can_act, |b| {
                            b.on_mouse_up(
                                MouseButton::Left,
                                cx.listener(move |_, _, _, cx| {
                                    ctrl_clear_geo.update(cx, |c, cx| {
                                        c.send_request(
                                            PipeRequest::ClearGeoVelocityCooldown,
                                            Some("已手动解除防瞬移冷却锁"),
                                            cx,
                                        );
                                    });
                                }),
                            )
                        }),
                    )
            });

            let purity = &risk.ip_purity;
            let ip_disp = purity
                .ip
                .as_deref()
                .map(|ip| {
                    if mask {
                        mask_ip_str(ip)
                    } else {
                        ip.to_string()
                    }
                })
                .unwrap_or_else(|| "待探测".into());
            let asn_disp = purity
                .asn
                .map(|n| format!("AS{n}"))
                .unwrap_or_else(|| "未知 ASN".into());
            let bps_pct = format!("{:.2}%", f64::from(purity.abuser_score_bps) / 100.0);

            let asn_card = bento_card_bloom(p, 16.0, 14.0, choreo.tile(1, 0))
                .flex_1()
                .gap(px(9.))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .child(
                            div()
                                .text_size(px(12.5))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.text_primary))
                                .child("当前节点宽带纯净度 & 运营商类型"),
                        )
                        .child(tone_tag(
                            purity.classification.label(),
                            if purity.is_tor || purity.is_datacenter || purity.is_proxy_or_vpn {
                                BadgeTone::Fail
                            } else {
                                BadgeTone::Pass
                            },
                            p,
                        )),
                )
                .child(
                    div()
                        .flex()
                        .flex_row()
                        .gap(px(7.))
                        .child(ag_diag_tile(
                            "出口 ASN 与运营商",
                            asn_disp,
                            if purity.asn_org.is_empty() {
                                ip_disp.clone()
                            } else {
                                purity.asn_org.clone()
                            },
                            p.text_primary,
                            true,
                            p,
                        ))
                        .child(ag_diag_tile(
                            "欺诈指数 / 邻段污染",
                            format!("{}% · /24 {bps_pct}", purity.abuse_risk_score),
                            format!(
                                "{} · {}",
                                purity.country.as_deref().unwrap_or("--"),
                                ip_disp
                            ),
                            if purity.abuse_risk_score >= 50 {
                                p.badge_fail.text
                            } else if purity.abuse_risk_score >= 20 {
                                p.badge_warn.text
                            } else {
                                p.badge_pass.text
                            },
                            true,
                            p,
                        )),
                )
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .child(
                            switch_row_gated(
                                "env-block-dc-asn",
                                "硬拦截云机房 / VPS 段 ASN（默认关闭）",
                                "显式开启后，识别到云机房段出口时启动门禁将直接拒止",
                                block_dc_asn_on,
                                can_act,
                                p,
                                cx.listener(move |_, _, _, cx| {
                                    let next = !block_dc_asn_on;
                                    ctrl_dc.update(cx, |c, cx| {
                                        c.save_toggle_patch(
                                            "env-block-dc-asn",
                                            next,
                                            move |x| x.block_datacenter_asn = next,
                                            "机房 ASN 拦截策略已更新",
                                            cx,
                                        );
                                    });
                                }),
                            )
                            .border_b_1()
                            .border_color(rgb(p.card_border)),
                        )
                        .child(switch_row_gated(
                            "env-geo-vel",
                            "启用 7 日时空轨迹防瞬移门禁",
                            "同仓短时跨洲切换 (>900 km/h) 触发防封冷却（同国 350km 豁免）",
                            geo_vel_on,
                            can_act,
                            p,
                            cx.listener(move |_, _, _, cx| {
                                let next = !geo_vel_on;
                                ctrl_gv.update(cx, |c, cx| {
                                    c.save_toggle_patch(
                                        "env-geo-vel",
                                        next,
                                        move |x| x.enforce_geo_velocity = next,
                                        "防瞬移时空门禁已更新",
                                        cx,
                                    );
                                });
                            }),
                        )),
                );

            let stun = &risk.stun_leak;
            let dns = &risk.dns_coherence;
            let hyg = &risk.electron_hygiene;
            let dual_split = purity.dual_stack_split_detected;
            let has_proto_leak = stun.leaked || dns.domestic_resolver_detected || dual_split;
            let ctrl_fix_ipv6 = ctrl.clone();
            let stun_card = bento_card_bloom(p, 16.0, 14.0, choreo.tile(1, 1))
                .flex_1()
                .gap(px(9.))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .child(
                            div()
                                .text_size(px(12.5))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.text_primary))
                                .child("客户端启动防泄露加固 & DNS/UDP 检测"),
                        )
                        .child(tone_tag(
                            if dual_split {
                                "双栈分叉风险"
                            } else if has_proto_leak {
                                "发现泄露项"
                            } else {
                                "协议零泄露"
                            },
                            if has_proto_leak {
                                BadgeTone::Fail
                            } else {
                                BadgeTone::Pass
                            },
                            p,
                        )),
                )
                .when(dual_split, |card| {
                    card.child(
                        inset_box(p)
                            .flex_row()
                            .items_center()
                            .justify_between()
                            .gap(px(8.))
                            .px(px(10.))
                            .py(px(6.5))
                            .bg(rgba(p.badge_fail.bg))
                            .border_color(rgba(p.hero_tripped.border))
                            .child(
                                div()
                                    .flex_1()
                                    .min_w(px(0.))
                                    .truncate()
                                    .text_size(px(10.5))
                                    .font_weight(FontWeight::MEDIUM)
                                    .text_color(rgb(p.badge_fail.text))
                                    .child("检测到 IPv4 / IPv6 双栈出口不一致，公网 IPv6 可能绕过代理直连"),
                            )
                            .child(
                                action_button(
                                    "env-risk-fix-ipv6",
                                    if ipv6_on {
                                        "同步 IPv6 护盾"
                                    } else {
                                        "一键封堵 IPv6"
                                    },
                                    ButtonKind::DangerSoft,
                                    can_act,
                                    p,
                                )
                                .h(px(24.))
                                .px(px(8.))
                                .text_size(px(10.5))
                                .when(can_act, |b| {
                                    b.on_mouse_up(
                                        MouseButton::Left,
                                        cx.listener(move |_, _, _, cx| {
                                            ctrl_fix_ipv6.update(cx, |c, cx| {
                                                c.save_toggle_patch(
                                                    "sh-ipv6",
                                                    true,
                                                    |x| x.leak_shield_ipv6 = true,
                                                    "已开启公网 IPv6 防漏阻断并同步规则",
                                                    cx,
                                                );
                                            });
                                        }),
                                    )
                                }),
                            ),
                    )
                })
                .child(
                    div()
                        .flex()
                        .flex_row()
                        .gap(px(7.))
                        .child(ag_diag_tile(
                            "RFC 5389 WebRTC STUN",
                            if stun.leaked {
                                "存在 UDP 穿透泄露".into()
                            } else {
                                "0 泄露".into()
                            },
                            if mask {
                                mask_ips_in_text(&stun.summary)
                            } else {
                                stun.summary.clone()
                            },
                            if stun.leaked {
                                p.badge_fail.text
                            } else {
                                p.badge_pass.text
                            },
                            false,
                            p,
                        ))
                        .child(ag_diag_tile(
                            "DNS 解析地理一致性",
                            if dns.domestic_resolver_detected {
                                "国内递归泄露".into()
                            } else if dns.coherent {
                                format!("一致 ({})", dns.resolver_countries.join("/"))
                            } else {
                                "待核验".into()
                            },
                            dns.summary.clone(),
                            if dns.domestic_resolver_detected {
                                p.badge_fail.text
                            } else if dns.coherent {
                                p.badge_pass.text
                            } else {
                                p.text_muted
                            },
                            false,
                            p,
                        )),
                )
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .child(
                            switch_row_gated(
                                "env-stun-audit",
                                "周期性运行 UDP STUN 与 DNS 一致性体检",
                                "定时核查底层 UDP 反射出口与 DNS 递归归属",
                                stun_audit_on,
                                can_act,
                                p,
                                cx.listener(move |_, _, _, cx| {
                                    let next = !stun_audit_on;
                                    ctrl_sa.update(cx, |c, cx| {
                                        c.save_toggle_patch(
                                            "env-stun-audit",
                                            next,
                                            move |x| x.enable_stun_dns_audit = next,
                                            "STUN / DNS 周期审计已更新",
                                            cx,
                                        );
                                    });
                                }),
                            )
                            .border_b_1()
                            .border_color(rgb(p.card_border)),
                        )
                        .child(switch_row_gated(
                            "env-electron-hyg",
                            "客户端启动防泄露加固",
                            "自动关闭 QUIC 与 WebRTC 真实网卡暴露（系统代理模式同步锁定远端 DNS 解析）",
                            electron_hyg_on,
                            can_act,
                            p,
                            cx.listener(move |_, _, _, cx| {
                                let next = !electron_hyg_on;
                                ctrl_eh.update(cx, |c, cx| {
                                    c.save_toggle_patch(
                                        "env-electron-hyg",
                                        next,
                                        move |x| x.enforce_electron_hygiene_flags = next,
                                        "Electron 防漏卫生策略已更新",
                                        cx,
                                    );
                                });
                            }),
                        ))
                        .when(!hyg.summary.is_empty(), |col| {
                            col.child(
                                div()
                                    .text_size(px(10.5))
                                    .text_color(rgb(p.text_muted))
                                    .child(hyg.summary.clone()),
                            )
                        }),
                );

            let dim_rows: Vec<Div> = risk
                .dimensions
                .iter()
                .map(|d| {
                    let detail = if mask {
                        mask_ips_in_text(&d.detail)
                    } else {
                        d.detail.clone()
                    };
                    let dim_id = d.id.clone();
                    let needs_fix = d.score < d.max_score || !d.healthy;
                    let fix_label: Option<&'static str> = if !needs_fix {
                        None
                    } else {
                        match dim_id.as_str() {
                            "wfp_shield" | "dual_stack" | "webrtc_stun" | "dns_coherence" => {
                                Some("一键开启四重防漏")
                            }
                            "electron_hygiene" => Some("一键开启启动防漏"),
                            "tz_locale" => Some("一键对齐时区"),
                            "geo_velocity" => Some("确认换线·放行"),
                            "burst_guard" | "cli_wsl_coverage" | "cli_hooks" => {
                                Some("一键保护终端")
                            }
                            "clean_room_hygiene" | "cleanroom" => Some("立即扫描残留"),
                            "asn_purity" | "abuse_score" => Some("配专属空间 →"),
                            _ => None,
                        }
                    };
                    let ctrl_dim_fix = ctrl.clone();
                    let hov_fix = p.sidebar_hover_bg;

                    inset_box(p)
                        .flex_1()
                        .flex_basis(px(0.))
                        .min_w(px(0.))
                        .px(px(10.))
                        .py(px(7.))
                        .gap(px(2.5))
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
                                        .min_w(px(0.))
                                        .gap(px(5.5))
                                        .child(status_dot(
                                            if d.healthy {
                                                p.badge_pass.dot
                                            } else {
                                                p.badge_fail.dot
                                            },
                                            5.5,
                                        ))
                                        .child(
                                            div()
                                                .truncate()
                                                .text_size(px(11.5))
                                                .font_weight(FontWeight::SEMIBOLD)
                                                .text_color(rgb(p.text_primary))
                                                .child(d.name.clone()),
                                        ),
                                )
                                .child(
                                    div()
                                        .flex()
                                        .items_center()
                                        .flex_shrink_0()
                                        .gap(px(6.))
                                        .when_some(fix_label, |row, lbl| {
                                            let id_for_click = dim_id.clone();
                                            row.child(
                                                div()
                                                    .id(gpui::ElementId::Name(
                                                        format!("dim-fix-{}", dim_id).into(),
                                                    ))
                                                    .px(px(6.5))
                                                    .py(px(1.5))
                                                    .rounded(px(6.))
                                                    .bg(rgb(p.accent_soft_bg))
                                                    .border_1()
                                                    .border_color(rgb(p.accent_soft_border))
                                                    .text_size(px(10.))
                                                    .font_weight(FontWeight::SEMIBOLD)
                                                    .text_color(rgb(p.accent_soft_text))
                                                    .when(can_act, |pill| {
                                                        pill.cursor_pointer()
                                                            .hover(move |s| s.bg(rgb(hov_fix)))
                                                            .on_mouse_up(
                                                                MouseButton::Left,
                                                                cx.listener(
                                                                    move |_, _, _, cx| {
                                                                        let did =
                                                                            id_for_click.clone();
                                                                        ctrl_dim_fix.update(
                                                                            cx,
                                                                            |c, cx| match did
                                                                                .as_str()
                                                                            {
                                                                                "wfp_shield"
                                                                                | "dual_stack"
                                                                                | "webrtc_stun"
                                                                                | "dns_coherence" => {
                                                                                    let is_stun =
                                                                                        did == "webrtc_stun";
                                                                                    c.save_config_patch(
                                                                                        move |cfg| {
                                                                                            cfg.leak_shield_quic =
                                                                                                true;
                                                                                            cfg.leak_shield_dns_doh =
                                                                                                true;
                                                                                            cfg.leak_shield_ipv6 =
                                                                                                true;
                                                                                            if is_stun {
                                                                                                cfg.enforce_electron_hygiene_flags =
                                                                                                    true;
                                                                                                cfg.enable_stun_dns_audit =
                                                                                                    true;
                                                                                            }
                                                                                        },
                                                                                        if is_stun {
                                                                                            "已开启四重防漏与 WebRTC/STUN 防护加固"
                                                                                        } else {
                                                                                            "已开启四重防漏保护并同步防火墙规则"
                                                                                        },
                                                                                        cx,
                                                                                    );
                                                                                }
                                                                                "electron_hygiene" => {
                                                                                    c.save_config_patch(
                                                                                        |cfg| {
                                                                                            cfg.enforce_electron_hygiene_flags =
                                                                                                true;
                                                                                        },
                                                                                        "已开启客户端启动防漏加固",
                                                                                        cx,
                                                                                    );
                                                                                }
                                                                                "tz_locale" => {
                                                                                    c.send_request(
                                                                                        PipeRequest::ApplyEnvAlignment {
                                                                                            align_tz:
                                                                                                true,
                                                                                            align_location:
                                                                                                false,
                                                                                        },
                                                                                        Some(
                                                                                            "已一键对齐本机时区与节点地区",
                                                                                        ),
                                                                                        cx,
                                                                                    );
                                                                                }
                                                                                "geo_velocity" => {
                                                                                    c.send_request(
                                                                                        PipeRequest::ClearGeoVelocityCooldown,
                                                                                        Some(
                                                                                            "已确认本人换线并解除冷却",
                                                                                        ),
                                                                                        cx,
                                                                                    );
                                                                                }
                                                                                "burst_guard"
                                                                                | "cli_wsl_coverage"
                                                                                | "cli_hooks" => {
                                                                                    c.send_request(
                                                                                        PipeRequest::ConfigureCliHooks {
                                                                                            install_claude_code:
                                                                                                true,
                                                                                            install_pwsh_profile:
                                                                                                true,
                                                                                            sync_all_vaults:
                                                                                                true,
                                                                                        },
                                                                                        Some(
                                                                                            "已完成终端防封保护一键接入",
                                                                                        ),
                                                                                        cx,
                                                                                    );
                                                                                }
                                                                                "clean_room_hygiene"
                                                                                | "cleanroom" => {
                                                                                    c.set_nav(
                                                                                        NavSection::CleanRoom,
                                                                                        cx,
                                                                                    );
                                                                                    c.run_cleanroom_scan(
                                                                                        cx,
                                                                                    );
                                                                                }
                                                                                _ => {
                                                                                    c.set_nav(
                                                                                        NavSection::Vaults,
                                                                                        cx,
                                                                                    );
                                                                                }
                                                                            },
                                                                        );
                                                                    },
                                                                ),
                                                            )
                                                    })
                                                    .when(!can_act, |pill| pill.opacity(0.5))
                                                    .child(lbl),
                                            )
                                        })
                                        .child(
                                            mono_tabular(format!("{}/{}", d.score, d.max_score))
                                                .text_size(px(11.))
                                                .font_weight(FontWeight::SEMIBOLD)
                                                .text_color(rgb(if d.healthy {
                                                    p.badge_pass.text
                                                } else {
                                                    p.badge_fail.text
                                                })),
                                        ),
                                ),
                        )
                        .child(
                            div()
                                .truncate()
                                .text_size(px(10.5))
                                .text_color(rgb(p.text_secondary))
                                .child(detail),
                        )
                })
                .collect();

            let mut dim_grid = Vec::new();
            let mut dim_iter = dim_rows.into_iter();
            while let Some(first) = dim_iter.next() {
                let mut row = div().flex().flex_row().w_full().gap(px(8.)).child(first);
                if let Some(second) = dim_iter.next() {
                    row = row.child(second);
                }
                dim_grid.push(row);
            }

            let dims_card = bento_card_bloom(p, 16.0, 13.0, choreo.tile(2, 0))
                .flex_1()
                .gap(px(8.))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .child(
                            div()
                                .text_size(px(12.5))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.text_primary))
                                .child("10 维度安全评分明细"),
                        )
                        .child(
                            div()
                                .text_size(px(11.))
                                .text_color(rgb(p.text_muted))
                                .child(
                                    "高危项（Tor / STUN / 超音速瞬移 / 国内 DNS）具备封顶否决权",
                                ),
                        ),
                )
                .child(div().flex().flex_col().gap(px(7.)).children(dim_grid));

            div()
                .flex()
                .flex_col()
                .w_full()
                .gap(px(11.))
                .child(div().w_full().flex().child(header_card))
                .when_some(geo_alert_el, |col, alert| {
                    col.child(div().w_full().flex().child(alert))
                })
                .child(
                    div()
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
                                .child(asn_card),
                        )
                        .child(
                            div()
                                .flex_1()
                                .flex_basis(px(0.))
                                .min_w(px(0.))
                                .flex()
                                .child(stun_card),
                        ),
                )
                .child(div().w_full().flex().child(dims_card))
        }

        EnvSubTab::HooksWsl => {
            let ctrl_inst_hooks = ctrl.clone();
            let ctrl_uninst_hooks = ctrl.clone();
            let ctrl_wsl_sw = ctrl.clone();
            let ctrl_wsl_sync = ctrl.clone();
            let ctrl_hk_sw = ctrl.clone();

            let fail_mode_items = HOOK_FAIL_MODES.into_iter().map(|fm| {
                let active = cfg.hook_fail_mode == fm;
                let ctrl_fm = ctrl.clone();
                let short_lbl = match fm {
                    HookFailMode::FailClosed => "服务离线截停 (推荐)",
                    HookFailMode::FailOpenWithWarn => "离线告警放行",
                };
                segmented_capsule_item(
                    gpui::ElementId::Name(format!("hook-fm-{fm:?}").into()),
                    short_lbl,
                    active,
                    p,
                )
                .when(can_act, |item| {
                    item.on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |_, _, _, cx| {
                            ctrl_fm.update(cx, |c, cx| {
                                c.save_config_patch(
                                    move |x| x.hook_fail_mode = fm,
                                    "CLI 门禁降级策略已更新",
                                    cx,
                                );
                            });
                        }),
                    )
                })
            });

            let burst_items = BURST_GUARD_MODES.into_iter().map(|bm| {
                let active = cfg.burst_guard_mode == bm;
                let ctrl_bm = ctrl.clone();
                let short_lbl = match bm {
                    BurstGuardMode::Off => "关闭",
                    BurstGuardMode::WarnOnly => "仅告警",
                    BurstGuardMode::ThrottleGate => "门禁限速",
                };
                segmented_capsule_item(
                    gpui::ElementId::Name(format!("burst-mode-{bm:?}").into()),
                    short_lbl,
                    active,
                    p,
                )
                .when(can_act, |item| {
                    item.on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |_, _, _, cx| {
                            ctrl_bm.update(cx, |c, cx| {
                                c.save_config_patch(
                                    move |x| x.burst_guard_mode = bm,
                                    "BurstGuard 速率防风控模式已更新",
                                    cx,
                                );
                            });
                        }),
                    )
                })
            });

            let lat_display = if hooks.last_gate_latency_us == 0 {
                "--".into()
            } else if hooks.last_gate_latency_us < 1000 {
                format!("{} μs", hooks.last_gate_latency_us)
            } else {
                format!("{:.2} ms", hooks.last_gate_latency_us as f64 / 1000.0)
            };

            let hooks_card = bento_card_bloom(p, 16.0, 14.0, choreo.tile(0, 0))
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
                                .child(
                                    div()
                                        .text_size(px(12.5))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(p.text_primary))
                                        .child("终端命令行防封保护（Claude Code / PowerShell）"),
                                )
                                .child(tone_tag(
                                    if hooks.claude_code_hook_installed {
                                        format!("已接入 · 延迟 {lat_display}")
                                    } else {
                                        "未接入".into()
                                    },
                                    if hooks.claude_code_hook_installed {
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
                                .flex_row()
                                .gap(px(7.))
                                .child(ag_diag_tile(
                                    "Claude Code Hook",
                                    if hooks.claude_code_hook_installed {
                                        "已注入".into()
                                    } else {
                                        "未安装".into()
                                    },
                                    format!("已同步 {} 个主权仓", hooks.vault_hooks_synced_count),
                                    if hooks.claude_code_hook_installed {
                                        p.badge_pass.text
                                    } else {
                                        p.text_muted
                                    },
                                    false,
                                    p,
                                ))
                                .child(ag_diag_tile(
                                    "PowerShell 包装 & 统计",
                                    if hooks.pwsh_profile_wrapped {
                                        "已包裹".into()
                                    } else {
                                        "未包裹".into()
                                    },
                                    format!(
                                        "放行 {} / 截停 {}",
                                        hooks.total_gate_checks, hooks.total_gate_blocks
                                    ),
                                    p.text_primary,
                                    true,
                                    p,
                                )),
                        )
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .gap(px(5.))
                                .child(
                                    div()
                                        .text_size(px(10.5))
                                        .text_color(rgb(p.text_muted))
                                        .child("守护离线时门禁策略 (Fail-Mode)"),
                                )
                                .child(segmented_capsule_track(p).children(fail_mode_items)),
                        )
                        .when(!hooks.summary.is_empty(), |col| {
                            col.child(
                                div()
                                    .text_size(px(10.5))
                                    .text_color(rgb(p.text_secondary))
                                    .child(hooks.summary.clone()),
                            )
                        }),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap(px(8.))
                        .pt(px(8.))
                        .border_t_1()
                        .border_color(rgb(p.card_border))
                        .child(
                            action_button(
                                "env-hooks-uninstall",
                                "卸载钩子",
                                ButtonKind::Ghost,
                                can_act
                                    && !is_configuring_hooks
                                    && (hooks.claude_code_hook_installed
                                        || hooks.pwsh_profile_wrapped),
                                p,
                            )
                            .h(px(28.))
                            .when(
                                can_act
                                    && !is_configuring_hooks
                                    && (hooks.claude_code_hook_installed
                                        || hooks.pwsh_profile_wrapped),
                                |b| {
                                    b.on_mouse_up(
                                        MouseButton::Left,
                                        cx.listener(move |_, _, _, cx| {
                                            ctrl_uninst_hooks.update(cx, |c, cx| {
                                                c.dismissed_overview_banner_key =
                                                    Some("hooks-unconfigured".into());
                                                c.send_request(
                                                    PipeRequest::ConfigureCliHooks {
                                                        install_claude_code: false,
                                                        install_pwsh_profile: false,
                                                        sync_all_vaults: true,
                                                    },
                                                    Some("已卸载 CLI 门禁钩子并清理全部账号空间配置"),
                                                    cx,
                                                );
                                            });
                                        }),
                                    )
                                },
                            ),
                        )
                        .child(
                            spinning_action_button(
                                "env-hooks-install",
                                "icons/ui/shield.svg",
                                if is_configuring_hooks {
                                    "接入中…"
                                } else {
                                    "一键保护终端 & 同步全部账号空间"
                                },
                                ButtonKind::Primary,
                                can_act && !is_configuring_hooks,
                                is_configuring_hooks,
                                p,
                            )
                            .h(px(28.))
                            .when(can_act && !is_configuring_hooks, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_inst_hooks.update(cx, |c, cx| {
                                            c.dismissed_overview_banner_key = None;
                                            c.send_request(
                                                PipeRequest::ConfigureCliHooks {
                                                    install_claude_code: true,
                                                    install_pwsh_profile: true,
                                                    sync_all_vaults: true,
                                                },
                                                Some("已完成 Claude Code & PowerShell 门禁一键接入"),
                                                cx,
                                            );
                                        });
                                    }),
                                )
                            }),
                        ),
                );

            let wsl_card = bento_card_bloom(p, 16.0, 14.0, choreo.tile(0, 1))
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
                                .child(
                                    div()
                                        .text_size(px(12.5))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(p.text_primary))
                                        .child("WSL2 子系统联动保护"),
                                )
                                .child(tone_tag(
                                    if wsl.proxy_desync_detected {
                                        "代理不一致预警"
                                    } else if wsl.listening {
                                        "联动运行中"
                                    } else {
                                        "未开启"
                                    },
                                    if wsl.proxy_desync_detected {
                                        BadgeTone::Fail
                                    } else if wsl.listening {
                                        BadgeTone::Pass
                                    } else {
                                        BadgeTone::Muted
                                    },
                                    p,
                                )),
                        )
                        .child(switch_row_gated(
                            "env-wsl-enabled",
                            "开启 WSL2 子系统防封联动",
                            "让 Linux 子系统内的 AI 工具共享主机的防封门禁与代理核验",
                            wsl_enabled_on,
                            can_act,
                            p,
                            cx.listener(move |_, _, _, cx| {
                                let next = !wsl_enabled_on;
                                ctrl_wsl_sw.update(cx, |c, cx| {
                                    c.save_toggle_patch(
                                        "env-wsl-enabled",
                                        next,
                                        move |x| x.wsl_bridge_enabled = next,
                                        "WSL2 门禁桥接开关已更新",
                                        cx,
                                    );
                                });
                            }),
                        ))
                        .child(
                            div()
                                .flex()
                                .flex_row()
                                .gap(px(7.))
                                .child(ag_diag_tile(
                                    "桥接监听端点",
                                    wsl.bound_port
                                        .map(|pt| format!("127.0.0.1:{pt}"))
                                        .unwrap_or_else(|| "未绑定".into()),
                                    if wsl.token_ready {
                                        "HMAC 令牌已就绪".into()
                                    } else {
                                        "待签发令牌".into()
                                    },
                                    p.text_primary,
                                    true,
                                    p,
                                ))
                                .child(ag_diag_tile(
                                    "已同步发行版",
                                    if wsl.synced_distros.is_empty() {
                                        "0 个".into()
                                    } else {
                                        wsl.synced_distros.join(", ")
                                    },
                                    if wsl.proxy_desync_detected {
                                        "检测到 WSL 代理与宿主机不一致".into()
                                    } else {
                                        "代理环境与宿主机一致".into()
                                    },
                                    if wsl.proxy_desync_detected {
                                        p.badge_fail.text
                                    } else {
                                        p.badge_pass.text
                                    },
                                    false,
                                    p,
                                )),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap(px(8.))
                        .pt(px(8.))
                        .border_t_1()
                        .border_color(rgb(p.card_border))
                        .child(
                            div()
                                .truncate()
                                .flex_1()
                                .text_size(px(10.5))
                                .text_color(rgb(p.text_muted))
                                .child(if wsl.summary.is_empty() {
                                    "同步后自动在 WSL2 发行版部署极轻量探针脚本".to_string()
                                } else {
                                    wsl.summary.clone()
                                }),
                        )
                        .child(
                            spinning_action_button(
                                "env-wsl-sync",
                                "icons/ui/refresh.svg",
                                if is_syncing_wsl {
                                    "同步中…"
                                } else {
                                    "同步 WSL2 桥接"
                                },
                                ButtonKind::Secondary,
                                can_act && wsl_enabled_on && !is_syncing_wsl,
                                is_syncing_wsl,
                                p,
                            )
                            .h(px(28.))
                            .when(
                                can_act && wsl_enabled_on && !is_syncing_wsl,
                                |b| {
                                    b.on_mouse_up(
                                        MouseButton::Left,
                                        cx.listener(move |_, _, _, cx| {
                                            ctrl_wsl_sync.update(cx, |c, cx| {
                                                c.send_request(
                                                    PipeRequest::SyncWslBridge,
                                                    Some("已完成 WSL2 跨子系统门禁同步"),
                                                    cx,
                                                );
                                            });
                                        }),
                                    )
                                },
                            ),
                        ),
                );

            let panic_ok = local_hk_report.panic_ok || hotkeys_snap.panic_registered_ok;
            let hud_ok = local_hk_report.hud_ok || hotkeys_snap.hud_registered_ok;
            let hk_conflict = if !local_hk_report.conflict_note.is_empty() {
                local_hk_report.conflict_note.clone()
            } else {
                hotkeys_snap.conflict_note.clone()
            };

            let ctrl_hk_preset = ctrl.clone();
            let cur_panic_chord = cfg.hotkey_panic_lockdown.clone();
            let burst_and_hotkey_card = bento_card_bloom(p, 16.0, 14.0, choreo.tile(1, 0))
                .flex_1()
                .gap(px(10.))
                .child(
                    div()
                        .flex()
                        .flex_row()
                        .gap(px(16.))
                        .child(
                            div()
                                .flex_1()
                                .flex_basis(px(0.))
                                .min_w(px(0.))
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
                                                .text_size(px(12.5))
                                                .font_weight(FontWeight::SEMIBOLD)
                                                .text_color(rgb(p.text_primary))
                                                .child("高频提问防风控保护"),
                                        )
                                        .child(tone_tag(
                                            if burst.robotic_cadence_detected {
                                                "疑似脚本高频"
                                            } else {
                                                burst.mode.label()
                                            },
                                            if burst.robotic_cadence_detected
                                                || burst.unauthorized_oauth_client_detected
                                            {
                                                BadgeTone::Fail
                                            } else {
                                                BadgeTone::Pass
                                            },
                                            p,
                                        )),
                                )
                                .child(segmented_capsule_track(p).children(burst_items))
                                .child(
                                    mono_tabular(format!(
                                        "近 1 分钟 {} 次 · 近 15 分钟 {} 次（提醒阈值 {} 次/分 · 限速 {} 次/分）",
                                        burst.prompts_last_1m,
                                        burst.prompts_last_15m,
                                        cfg.burst_warn_rpm,
                                        cfg.burst_throttle_rpm
                                    ))
                                    .text_size(px(10.5))
                                    .text_color(rgb(p.text_secondary)),
                                ),
                        )
                        .child(
                            div()
                                .flex_1()
                                .flex_basis(px(0.))
                                .min_w(px(0.))
                                .flex()
                                .flex_col()
                                .gap(px(6.))
                                .child(switch_row_gated(
                                    "env-hotkeys-enabled",
                                    "全局快捷热键（随时锁网 / 呼出迷你窗）",
                                    "系统级原生热键，不挂键盘钩子、不触发游戏反作弊",
                                    hotkeys_enabled_on,
                                    can_act,
                                    p,
                                    cx.listener(move |_, _, _, cx| {
                                        let next = !hotkeys_enabled_on;
                                        ctrl_hk_sw.update(cx, |c, cx| {
                                            c.save_toggle_patch(
                                                "env-hotkeys-enabled",
                                                next,
                                                move |x| x.global_hotkeys_enabled = next,
                                                "全局紧急热键开关已更新",
                                                cx,
                                            );
                                        });
                                    }),
                                ))
                                .child(
                                    div()
                                        .flex()
                                        .flex_wrap()
                                        .items_center()
                                        .gap(px(6.))
                                        .child(tone_tag(
                                            format!(
                                                "紧急锁死 {} {}",
                                                cfg.hotkey_panic_lockdown,
                                                if panic_ok { "✓" } else { "!" }
                                            ),
                                            if panic_ok {
                                                BadgeTone::Pass
                                            } else {
                                                BadgeTone::Warn
                                            },
                                            p,
                                        ))
                                        .child(tone_tag(
                                            format!(
                                                "快捷 HUD {} {}",
                                                cfg.hotkey_quick_hud,
                                                if hud_ok { "✓" } else { "!" }
                                            ),
                                            if hud_ok {
                                                BadgeTone::Pass
                                            } else {
                                                BadgeTone::Warn
                                            },
                                            p,
                                        ))
                                        .child(
                                            action_button(
                                                "env-cycle-hotkey-preset",
                                                "切换防冲突组合键",
                                                ButtonKind::Ghost,
                                                can_act && hotkeys_enabled_on,
                                                p,
                                            )
                                            .h(px(23.))
                                            .px(px(7.5))
                                            .text_size(px(10.))
                                            .when(can_act && hotkeys_enabled_on, |b| {
                                                b.on_mouse_up(
                                                    MouseButton::Left,
                                                    cx.listener(move |_, _, _, cx| {
                                                        let (next_p, next_h) = if cur_panic_chord
                                                            .eq_ignore_ascii_case("Ctrl+Alt+Shift+L")
                                                        {
                                                            ("Win+Shift+F9", "Win+Shift+F10")
                                                        } else if cur_panic_chord
                                                            .eq_ignore_ascii_case("Win+Shift+F9")
                                                        {
                                                            ("Ctrl+Alt+F11", "Ctrl+Alt+F12")
                                                        } else {
                                                            ("Ctrl+Alt+Shift+L", "Ctrl+Alt+Shift+H")
                                                        };
                                                        ctrl_hk_preset.update(cx, |c, cx| {
                                                            c.save_config_patch_msg(
                                                                move |x| {
                                                                    x.hotkey_panic_lockdown =
                                                                        next_p.into();
                                                                    x.hotkey_quick_hud =
                                                                        next_h.into();
                                                                },
                                                                format!(
                                                                    "已切换热键为 {next_p} / {next_h}"
                                                                ),
                                                                cx,
                                                            );
                                                        });
                                                    }),
                                                )
                                            }),
                                        ),
                                )
                                .when(!hk_conflict.is_empty(), |col| {
                                    col.child(
                                        div()
                                            .text_size(px(10.5))
                                            .text_color(rgb(p.badge_warn.text))
                                            .child(format!("热键冲突提示：{hk_conflict}")),
                                    )
                                }),
                        ),
                );

            div()
                .flex()
                .flex_col()
                .w_full()
                .gap(px(11.))
                .child(
                    div()
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
                                .child(hooks_card),
                        )
                        .child(
                            div()
                                .flex_1()
                                .flex_basis(px(0.))
                                .min_w(px(0.))
                                .flex()
                                .child(wsl_card),
                        ),
                )
                .child(div().w_full().flex().child(burst_and_hotkey_card))
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

struct AgCardCtx<'a> {
    ag: &'a AntigravityProxyStatus,
    updates: &'a UpdateSummary,
    guard_proxy_port: u16,
    require_ag_proxy: bool,
    auto_repair_ag_proxy: bool,
    privacy_mask: bool,
    connected: bool,
    tripped: bool,
    can_act: bool,
    is_rechecking: bool,
    is_repairing: bool,
    ag_running: bool,
}

fn render_antigravity_proxy_card(
    ctrl: Entity<AppController>,
    ctx: AgCardCtx<'_>,
    choreo: PageChoreo,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> Div {
    let AgCardCtx {
        ag,
        updates,
        guard_proxy_port,
        require_ag_proxy,
        auto_repair_ag_proxy,
        privacy_mask,
        connected,
        tripped,
        can_act,
        is_rechecking,
        is_repairing,
        ag_running,
    } = ctx;
    let can_repair = connected && !tripped && ag.installed && !is_repairing;
    let repair_confirm_armed = ctrl.read(cx).is_confirm_armed("env-ag-repair-running");
    let ctrl_kill_ag = ctrl.clone();
    let vm = project_antigravity_proxy_card(ag, guard_proxy_port, privacy_mask, now_unix_secs());
    let show_degraded_alert = vm.is_degraded && require_ag_proxy;
    let (pill_label, pill_tone) = if !require_ag_proxy && ag.installed && !ag.is_ready_for_launch()
    {
        ("已关闭核验".to_string(), BadgeTone::Muted)
    } else {
        (vm.pill_label, vm.pill_tone)
    };
    let display_dir = if privacy_mask {
        mask_windows_user_path(&vm.dir_text)
    } else {
        vm.dir_text.clone()
    };
    let ctrl_toggle_req = ctrl.clone();
    let ctrl_toggle_repair = ctrl.clone();
    let ctrl_to_updates = ctrl.clone();
    let ctrl_repair = ctrl.clone();
    let ctrl_recheck = ctrl;

    let has_ag_update = updates.antigravity_proxy.phase == UpdateCheckPhase::UpdateAvailable;
    let ag_update_tag = updates
        .antigravity_proxy
        .latest_version
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|v| format!("v{}", v.trim_start_matches(['v', 'V'])))
        .unwrap_or_else(|| "新版".into());
    let ag_upd_surf = p.badge(BadgeTone::Warn);

    let ver_color = if vm.version_warn {
        p.badge_warn.text
    } else if ag.installed {
        p.text_primary
    } else {
        p.text_muted
    };
    let dll_color = if !require_ag_proxy && vm.dll_tone == BadgeTone::Fail {
        p.text_muted
    } else {
        match vm.dll_tone {
            BadgeTone::Pass => p.badge_pass.text,
            BadgeTone::Fail => p.badge_fail.text,
            BadgeTone::Warn => p.badge_warn.text,
            BadgeTone::Muted => p.text_muted,
        }
    };
    let cfg_color = match vm.config_tone {
        BadgeTone::Pass => p.text_primary,
        BadgeTone::Fail => p.badge_fail.text,
        BadgeTone::Warn => p.badge_warn.text,
        BadgeTone::Muted => p.text_muted,
    };
    let rt_color = if !require_ag_proxy && vm.runtime_tone == BadgeTone::Fail {
        p.text_secondary
    } else {
        match vm.runtime_tone {
            BadgeTone::Pass => p.badge_pass.text,
            BadgeTone::Fail => p.badge_fail.text,
            BadgeTone::Warn => p.badge_warn.text,
            BadgeTone::Muted => p.text_secondary,
        }
    };

    let guide_box = page_guide_card(
        "代理注入原理",
        "组件：yuaotian/antigravity-proxy",
        &[
            (
                "1. 强制接管流量",
                "Antigravity 部分后台组件不走系统代理，注入后强制全部经本地代理转发。",
            ),
            (
                "2. 更新覆盖风险",
                "客户端自动更新可能覆盖 version.dll 导致注入失效，系统会及时告警。",
            ),
            (
                "3. 自动与手动修复",
                "默认自更新后后台静默补回注入模块与配置，也可点「下载并热修复」；改用 TUN 可关闭。",
            ),
        ],
        p,
    );

    let recheck_hover_bg = p.sidebar_hover_bg;

    let ag_card = bento_card_bloom(p, 17., 14., choreo.tile(0, 0))
        .flex_1()
        .gap(px(9.))
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
                        .gap(px(9.))
                        .child(brand_icon_scaled(
                            "antigravity",
                            24.0,
                            6.0,
                            p.is_dark,
                            choreo.icon_scale(1, 0),
                        ))
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap(px(8.))
                                .child(
                                    div()
                                        .text_size(px(13.))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(p.text_primary))
                                        .child("反重力代理注入"),
                                )
                                .child(
                                    mono_tabular(format!(
                                        "antigravity-proxy · {}",
                                        vm.checked_age_label
                                            .as_deref()
                                            .map(|a| format!("核验于 {a}"))
                                            .unwrap_or_else(|| "实时核验".into())
                                    ))
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
                        .when(has_ag_update, |row| {
                            row.child(
                                div()
                                    .id("env-ag-upd-pill")
                                    .flex()
                                    .items_center()
                                    .gap(px(5.))
                                    .h(px(24.))
                                    .px(px(9.))
                                    .rounded(px(999.))
                                    .bg(rgba(ag_upd_surf.bg))
                                    .border_1()
                                    .border_color(rgb(ag_upd_surf.dot))
                                    .cursor_pointer()
                                    .text_size(px(10.5))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .text_color(rgb(ag_upd_surf.text))
                                    .child(status_dot(ag_upd_surf.dot, 5.0))
                                    .child(format!("可更新 {ag_update_tag} →"))
                                    .on_mouse_up(
                                        MouseButton::Left,
                                        cx.listener(move |_, _, _, cx| {
                                            ctrl_to_updates.update(cx, |c, cx| {
                                                c.set_nav(NavSection::Updates, cx);
                                            });
                                        }),
                                    ),
                            )
                        })
                        .child(status_pill(pill_label, pill_tone, p)),
                ),
        )
        .child(
            div()
                .flex()
                .flex_row()
                .gap(px(9.))
                .child(choreo.inner_bloom(1, 0).apply(ag_diag_tile(
                    "客户端版本",
                    vm.version_primary,
                    vm.version_sub,
                    ver_color,
                    true,
                    p,
                )))
                .child(choreo.inner_bloom(1, 1).apply(ag_diag_tile(
                    "注入模块 (version.dll)",
                    vm.dll_primary,
                    vm.dll_sub,
                    dll_color,
                    false,
                    p,
                ))),
        )
        .child(
            div()
                .flex()
                .flex_row()
                .gap(px(9.))
                .child(choreo.inner_bloom(1, 2).apply(ag_diag_tile(
                    "代理配置 (config.json)",
                    vm.config_primary,
                    vm.config_sub,
                    cfg_color,
                    true,
                    p,
                )))
                .child(choreo.inner_bloom(1, 3).apply(ag_diag_tile(
                    "运行态注入 (language_server)",
                    vm.runtime_primary,
                    vm.runtime_sub,
                    rt_color,
                    false,
                    p,
                ))),
        )
        .child({
            let mut bar = inset_box(p).px(px(12.)).py(px(8.)).gap(px(2.5));
            if show_degraded_alert {
                bar = bar
                    .bg(rgba(p.badge_fail.bg))
                    .border_color(rgba(p.hero_tripped.border));
            }
            let summary_line = if show_degraded_alert {
                format!("! {}", vm.summary_text)
            } else if vm.is_degraded && !require_ag_proxy {
                "已关闭注入核验（适用启动器、全局 TUN 或自定义代理）；如需 DLL 注入可点右下角热修复。".to_string()
            } else {
                vm.summary_text
            };
            bar.child(
                div()
                    .text_size(px(12.))
                    .font_weight(FontWeight::MEDIUM)
                    .text_color(rgb(if show_degraded_alert {
                        p.badge_fail.text
                    } else if ag.installed {
                        p.text_primary
                    } else {
                        p.text_muted
                    }))
                    .child(summary_line),
            )
            .child(
                mono_tabular(format!("安装目录：{display_dir}"))
                    .truncate()
                    .text_size(px(10.5))
                    .text_color(rgb(p.text_muted)),
            )
        })
        .when(ag_running, |card| {
            card.child(
                inset_box(p)
                    .flex_row()
                    .items_center()
                    .justify_between()
                    .gap(px(10.))
                    .px(px(12.))
                    .py(px(7.))
                    .bg(rgba(p.badge_warn.bg))
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.))
                            .truncate()
                            .text_size(px(11.))
                            .font_weight(FontWeight::MEDIUM)
                            .text_color(rgb(p.badge_warn.text))
                            .child("检测到 Antigravity 正在运行，可能锁住 version.dll；建议先关闭后再执行热修复"),
                    )
                    .child(
                        action_button(
                            "env-ag-close-running",
                            "先关闭 Antigravity",
                            ButtonKind::Secondary,
                            connected,
                            p,
                        )
                        .h(px(25.))
                        .px(px(9.))
                        .text_size(px(10.5))
                        .when(connected, |b| {
                            b.on_mouse_up(
                                MouseButton::Left,
                                cx.listener(move |_, _, _, cx| {
                                    ctrl_kill_ag.update(cx, |c, cx| {
                                        c.send_request(
                                            PipeRequest::ForceKillAgent {
                                                agent_id: Some("antigravity".into()),
                                                include_cli: false,
                                            },
                                            Some("已关闭 Antigravity，现在可安全执行热修复"),
                                            cx,
                                        );
                                    });
                                }),
                            )
                        }),
                    ),
            )
        })
        .child(choreo.inner_bloom(1, 4).apply(guide_box))
        .child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .w_full()
                .min_w(px(0.))
                .gap(px(16.))
                .pt(px(9.))
                .border_t_1()
                .border_color(rgb(p.card_border))
                .child(
                    div()
                        .flex_1()
                        .flex_basis(px(0.))
                        .min_w(px(0.))
                        .child(
                            switch_row_gated(
                                "env-ag-require-proxy",
                                "注入失效时拦截启动",
                                "使用 antigravity-launcher、全局 TUN 或自定义代理时可关闭",
                                require_ag_proxy,
                                can_act,
                                p,
                                cx.listener(move |_, _, _, cx| {
                                    let next = !require_ag_proxy;
                                    ctrl_toggle_req.update(cx, |c, cx| {
                                        c.save_toggle_patch(
                                            "env-ag-require-proxy",
                                            next,
                                            move |x| x.require_antigravity_proxy = next,
                                            if next {
                                                "已开启注入失效启动拦截"
                                            } else {
                                                "已关闭注入失效拦截与告警"
                                            },
                                            cx,
                                        );
                                    });
                                }),
                            )
                            .py(px(2.)),
                        ),
                )
                .child(div().w(px(1.)).self_stretch().bg(rgb(p.card_border)))
                .child(
                    div()
                        .flex_1()
                        .flex_basis(px(0.))
                        .min_w(px(0.))
                        .child(
                            switch_row_gated(
                                "env-ag-auto-repair",
                                "自更新后自动补注入",
                                "检测到覆盖或端口漂移时静默修复 version.dll 与配置",
                                auto_repair_ag_proxy,
                                can_act,
                                p,
                                cx.listener(move |_, _, _, cx| {
                                    let next = !auto_repair_ag_proxy;
                                    ctrl_toggle_repair.update(cx, |c, cx| {
                                        c.save_toggle_patch(
                                            "env-ag-auto-repair",
                                            next,
                                            move |x| x.auto_repair_antigravity_proxy = next,
                                            if next {
                                                "已开启反重力自动补注入"
                                            } else {
                                                "已关闭反重力自动补注入"
                                            },
                                            cx,
                                        );
                                    });
                                }),
                            )
                            .py(px(2.)),
                        ),
                ),
        )
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .gap(px(12.))
                .pt(px(9.))
                .border_t_1()
                .border_color(rgb(p.card_border))
                .child(
                    mono_tabular(format!(
                        "门禁：{} · 自动补注入：{} · 端口 :{}",
                        if require_ag_proxy { "已开启" } else { "已关闭" },
                        if auto_repair_ag_proxy {
                            "已开启"
                        } else {
                            "已关闭"
                        },
                        guard_proxy_port
                    ))
                    .flex_1()
                    .min_w(px(0.))
                    .truncate()
                    .text_size(px(11.))
                    .text_color(rgb(p.text_muted)),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .flex_shrink_0()
                        .gap(px(8.))
                        .child(
                            div()
                                .id("env-ag-recheck-btn")
                                .flex()
                                .items_center()
                                .justify_center()
                                .gap(px(5.5))
                                .h(px(29.))
                                .px(px(11.))
                                .rounded(px(9.))
                                .bg(rgb(p.secondary_btn_bg))
                                .border_1()
                                .border_color(rgb(p.secondary_btn_border))
                                .text_size(px(12.))
                                .font_weight(FontWeight::MEDIUM)
                                .text_color(rgb(p.secondary_btn_text))
                                .when(can_act, |b| {
                                    b.cursor_pointer()
                                        .hover(move |s| s.bg(rgb(recheck_hover_bg)))
                                        .active(|s| s.opacity(0.86))
                                        .on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                ctrl_recheck.update(cx, |c, cx| {
                                                    c.send_request(
                                                        PipeRequest::RecheckNow { target_id: None },
                                                        Some("反重力注入状态核验完成"),
                                                        cx,
                                                    );
                                                });
                                            }),
                                        )
                                })
                                .when(!can_act, |b| b.opacity(0.45))
                                .child(spinning_ui_icon(
                                    "env-ag-recheck-spin",
                                    "icons/ui/refresh.svg",
                                    12.5,
                                    p.secondary_btn_text,
                                    is_rechecking,
                                ))
                                .child(if is_rechecking { "核验中…" } else { "重新核验" }),
                        )
                        .child(
                            action_button(
                                "env-ag-repair-btn",
                                if tripped {
                                    "隔离期暂停"
                                } else if is_repairing {
                                    "修复中…"
                                } else if ag_running && repair_confirm_armed {
                                    "确认仍在运行下修复"
                                } else {
                                    "下载并热修复"
                                },
                                if ag_running && repair_confirm_armed {
                                    ButtonKind::DangerSoft
                                } else if show_degraded_alert && !tripped {
                                    ButtonKind::Primary
                                } else {
                                    ButtonKind::Secondary
                                },
                                can_repair,
                                p,
                            )
                            .h(px(29.))
                            .when(can_repair, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_repair.update(cx, |c, cx| {
                                            if ag_running
                                                && !c.arm_or_consume_confirm(
                                                    "env-ag-repair-running",
                                                    cx,
                                                )
                                            {
                                                c.set_toast(
                                                    "Antigravity 正在运行可能锁住 version.dll，建议先关闭；再点一次强制继续修复",
                                                    false,
                                                    cx,
                                                );
                                                return;
                                            }
                                            c.send_request(
                                                PipeRequest::RepairAntigravityProxy,
                                                Some("antigravity-proxy 已完成热修复并同步端口"),
                                                cx,
                                            );
                                        });
                                    }),
                                )
                            }),
                        ),
                ),
        );
    div().w_full().flex().child(ag_card)
}

#[cfg(test)]
mod tests {
    use super::mask_windows_user_path;

    #[test]
    fn masks_windows_username_in_install_paths() {
        assert_eq!(
            mask_windows_user_path(r"C:\Users\alice\AppData\Local\Programs\Antigravity"),
            r"C:\Users\***\AppData\Local\Programs\Antigravity"
        );
        assert_eq!(
            mask_windows_user_path("C:/users/bob/tools"),
            "C:/users/***/tools"
        );
        assert_eq!(
            mask_windows_user_path(r"C:\Program Files\ClaudeGuard"),
            r"C:\Program Files\ClaudeGuard"
        );
    }
}
