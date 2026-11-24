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
    AntigravityProxyStatus, PipeRequest, UpdateCheckPhase, UpdateSummary, mask_ip_str,
    mask_ips_in_text,
};
use crate::state::{NavSection, project_antigravity_proxy_card};
use crate::theme::{BadgeTone, ThemePalette};
use crate::views::shared::{ag_diag_tile, page_guide_card, switch_row_gated};
use crate::widgets::controls::{
    ButtonKind, action_button, bento_card_bloom, inset_box, mono_tabular, offset_pane,
    spinning_action_button, spinning_ui_icon, status_dot, status_pill, subtab_bar, subtab_item,
    toggle_switch, tone_tag,
};
use gpui::{Context, Div, Entity, FontWeight, MouseButton, div, prelude::*, px, rgb, rgba};

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
    let require_ag_proxy =
        ctrl_r.effective_toggle("env-ag-require-proxy", cfg.require_antigravity_proxy);
    let ag_issue = ag_proxy.installed && require_ag_proxy && !ag_proxy.is_ready_for_launch();
    let is_rechecking = ctrl_r.is_scope_busy(&ActionScope::RecheckAll);
    let is_repairing_ag = ctrl_r.is_scope_busy(&ActionScope::RepairAntigravity);
    let is_syncing_shield = ctrl_r.is_scope_busy(&ActionScope::SyncLeakShield);
    let is_aligning_env = ctrl_r.is_scope_busy(&ActionScope::EnvAlign);

    let quic_on = ctrl_r.effective_toggle("sh-quic-sw", cfg.leak_shield_quic);
    let dns_on = ctrl_r.effective_toggle("sh-dns-sw", cfg.leak_shield_dns_doh);
    let ipv6_on = ctrl_r.effective_toggle("sh-ipv6-sw", cfg.leak_shield_ipv6);
    let leak_watch_on = ctrl_r.effective_toggle("env-leak-watch", cfg.leak_watch);
    let leak_trip_on = ctrl_r.effective_toggle("env-leak-trip", cfg.leak_trip);
    let env_check_on = ctrl_r.effective_toggle("env-check-sw", cfg.env_check);
    let env_align_tz_on = ctrl_r.effective_toggle("env-tz-sw", cfg.env_align_tz);
    let env_align_loc_on = ctrl_r.effective_toggle("env-loc-sw", cfg.env_align_location);
    let shield_unsynced = cfg.leak_shield_quic != shield.quic_blocked
        || cfg.leak_shield_dns_doh != shield.dns_doh_blocked
        || cfg.leak_shield_ipv6 != shield.ipv6_blocked;

    let ctrl_t1 = ctrl.clone();
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
                                                    "sh-quic-sw",
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
                                                    "sh-dns-sw",
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
                                                "sh-ipv6-sw",
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

        EnvSubTab::Antigravity => render_antigravity_proxy_card(
            ctrl.clone(),
            AgCardCtx {
                ag: &ag_proxy,
                updates: &updates,
                guard_proxy_port: cfg.proxy_port,
                require_ag_proxy,
                privacy_mask: mask,
                connected,
                tripped,
                can_act,
                is_rechecking,
                is_repairing: is_repairing_ag,
            },
            choreo,
            p,
            cx,
        ),

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
                                    let can_align = connected && !is_aligning_env;
                                    let do_tz = env_align_tz_on || !env_align_loc_on;
                                    let do_loc = env_align_loc_on;
                                    action_button(
                                        "env-apply-align-btn",
                                        if is_aligning_env {
                                            "对齐中…"
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
    privacy_mask: bool,
    connected: bool,
    tripped: bool,
    can_act: bool,
    is_rechecking: bool,
    is_repairing: bool,
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
        privacy_mask,
        connected,
        tripped,
        can_act,
        is_rechecking,
        is_repairing,
    } = ctx;
    let can_repair = connected && !tripped && ag.installed && !is_repairing;
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
    let ctrl_toggle = ctrl.clone();
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
                "3. 修复或静音告警",
                "改用启动器或 TUN 时可关闭下方门禁；如需 DLL 注入，点「下载并热修复」补回。",
            ),
        ],
        p,
    );

    let recheck_hover_bg = p.sidebar_hover_bg;

    let ag_card = bento_card_bloom(p, 17., 14., choreo.tile(0, 0))
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
        .child(choreo.inner_bloom(1, 4).apply(guide_box))
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .gap(px(12.))
                .pt(px(10.))
                .border_t_1()
                .border_color(rgb(p.card_border))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(10.))
                        .flex_1()
                        .min_w(px(0.))
                        .child(
                            toggle_switch("env-ag-require-proxy", require_ag_proxy, can_act, p)
                                .when(can_act, |sw| {
                                    sw.on_mouse_up(
                                        MouseButton::Left,
                                        cx.listener(move |_, _, _, cx| {
                                            let next = !require_ag_proxy;
                                            ctrl_toggle.update(cx, |c, cx| {
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
                                }),
                        )
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .min_w(px(0.))
                                .gap(px(1.5))
                                .child(
                                    div()
                                        .text_size(px(12.))
                                        .font_weight(FontWeight::MEDIUM)
                                        .text_color(rgb(p.text_primary))
                                        .child("注入失效时拦截启动"),
                                )
                                .child(
                                    div()
                                        .truncate()
                                        .text_size(px(10.5))
                                        .text_color(rgb(p.text_muted))
                                        .child("使用 antigravity-launcher、全局 TUN 或自定义代理时可关闭"),
                                ),
                        ),
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
                                } else {
                                    "下载并热修复"
                                },
                                if show_degraded_alert && !tripped {
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
