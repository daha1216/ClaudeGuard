//! Mode B — `环境与防泄露` view (antigravity-proxy diagnostics, direct-leak radar, timezone/locale).

use crate::app::{AppController, ConsoleWindowView};
use crate::demo::now_unix_secs;
use crate::protocol::{
    AntigravityProxyStatus, PipeRequest, UpdateCheckPhase, UpdateSummary, mask_ip_str,
};
use crate::state::{NavSection, project_antigravity_proxy_card};
use crate::theme::{BadgeTone, ThemePalette};
use crate::views::shared::{ag_diag_tile, switch_row};
use crate::widgets::controls::{
    ButtonKind, action_button, bento_card, card_header, inset_box, mono_tabular, status_pill,
    toggle_switch,
};
use gpui::{Context, Div, Entity, FontWeight, MouseButton, div, prelude::*, px, rgb, rgba};
/// Sub-view: `环境与防泄露`
pub fn render_environment_page(
    ctrl: Entity<AppController>,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> Div {
    let ctrl_r = ctrl.read(cx);
    let snap = ctrl_r.snapshot.clone();
    let mask = ctrl_r.privacy_mask;
    let busy = ctrl_r.busy_action;
    let connected = ctrl_r.connected;
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
    let mihomo = snap.as_ref().map(|s| s.mihomo.clone()).unwrap_or_default();
    let env = snap.as_ref().map(|s| s.env.clone()).unwrap_or_default();
    let env_applied = snap.as_ref().and_then(|s| s.env_applied.clone());

    let ag_card = render_antigravity_proxy_card(
        ctrl.clone(),
        &ag_proxy,
        &updates,
        cfg.proxy_port,
        cfg.require_antigravity_proxy,
        mask,
        connected,
        busy,
        p,
        cx,
    );

    let ctrl_sh_quic = ctrl.clone();
    let ctrl_sh_dns = ctrl.clone();
    let ctrl_sh_v6 = ctrl.clone();
    let ctrl_sh_sync = ctrl.clone();
    let ctrl_lw = ctrl.clone();
    let ctrl_lt = ctrl.clone();
    let ctrl_ec = ctrl.clone();
    let ctrl_tz = ctrl.clone();
    let ctrl_loc = ctrl.clone();
    let ctrl_scan = ctrl.clone();
    let ctrl_apply_env = ctrl.clone();
    let ctrl_rollback_env = ctrl.clone();
    let ctrl_align = ctrl.clone();

    let can_act = connected && !busy;

    let shield_card = bento_card(p)
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
                        .child("4 维防泄露护盾（QUIC / DNS / IPv6）"),
                )
                .child(status_pill(
                    if shield.enabled {
                        format!("已生效 {} 条规则", shield.active_rules)
                    } else {
                        "未启用护盾".into()
                    },
                    if shield.enabled {
                        BadgeTone::Pass
                    } else {
                        BadgeTone::Muted
                    },
                    p,
                )),
        )
        .child(switch_row(
            "sh-quic-sw",
            "阻断 QUIC UDP:443 直连泄露（同步启用安全启动防 QUIC 参数）",
            "防止受管 AI 桌面客户端通过 HTTP/3 UDP:443 绕过本地代理直连出口",
            cfg.leak_shield_quic,
            p,
            cx.listener(move |_, _, _, cx| {
                let next = !cfg.leak_shield_quic;
                ctrl_sh_quic.update(cx, |c, cx| {
                    c.save_config_patch(move |x| x.leak_shield_quic = next, "已更新护盾配置", cx);
                });
            }),
        ))
        .child(switch_row(
            "sh-dns-sw",
            "阻断明文 DNS:53 与公共 DoH 直连解析",
            "禁止受管应用绕过代理向运营商 DNS 或公共 DoH 节点发起域名解析",
            cfg.leak_shield_dns_doh,
            p,
            cx.listener(move |_, _, _, cx| {
                let next = !cfg.leak_shield_dns_doh;
                ctrl_sh_dns.update(cx, |c, cx| {
                    c.save_config_patch(
                        move |x| x.leak_shield_dns_doh = next,
                        "已更新 DNS/DoH 护盾配置",
                        cx,
                    );
                });
            }),
        ))
        .child(switch_row(
            "sh-ipv6-sw",
            "阻断公网 IPv6 直连泄露（2000::/3）",
            "家庭双栈宽带环境下，若本地代理仅接管 IPv4，可强制阻断受管应用公网 IPv6 直连",
            cfg.leak_shield_ipv6,
            p,
            cx.listener(move |_, _, _, cx| {
                let next = !cfg.leak_shield_ipv6;
                ctrl_sh_v6.update(cx, |c, cx| {
                    c.save_config_patch(move |x| x.leak_shield_ipv6 = next, "已更新 IPv6 护盾配置", cx);
                });
            }),
        ))
        .child(
            div()
                .flex()
                .flex_wrap()
                .items_center()
                .justify_between()
                .gap(px(8.))
                .child(
                    div()
                        .flex_1()
                        .min_w(px(200.))
                        .text_size(px(11.5))
                        .text_color(rgb(p.text_secondary))
                        .child(if shield.summary.is_empty() {
                            "点击右侧按钮立即将勾选的护盾策略写入系统防火墙规则（撤防/卸载时自动无残留清理）".to_string()
                        } else {
                            shield.summary.clone()
                        }),
                )
                .child(
                    action_button(
                        "env-shield-sync",
                        "↻ 立即同步护盾规则",
                        ButtonKind::Primary,
                        can_act,
                        p,
                    )
                    .when(can_act, |b| {
                        b.on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |_, _, _, cx| {
                                ctrl_sh_sync.update(cx, |c, cx| {
                                    c.send_request(
                                        PipeRequest::SyncLeakShield,
                                        Some("4 维防泄露护盾规则已同步并生效"),
                                        cx,
                                    );
                                });
                            }),
                        )
                    }),
                ),
        );

    // Mihomo / Clash External Controller integration card
    let mihomo_chips: Vec<Div> = mihomo
        .candidates
        .iter()
        .map(|node| {
            let is_active = node.name == mihomo.active_node;
            let clickable = can_act && !is_active && !mihomo.active_group.is_empty();
            let mut inner = div()
                .id(gpui::ElementId::Name(
                    format!("mihomo-chip-{}", node.name).into(),
                ))
                .flex_shrink_0()
                .whitespace_nowrap()
                .px(px(10.))
                .py(px(5.))
                .rounded(px(8.))
                .border_1()
                .text_size(px(11.5))
                .font_weight(if is_active {
                    FontWeight::SEMIBOLD
                } else {
                    FontWeight::NORMAL
                })
                .bg(rgb(if is_active {
                    p.primary_btn_bg
                } else {
                    p.inset_bg
                }))
                .border_color(rgb(if is_active {
                    p.primary_btn_bg
                } else {
                    p.inset_border
                }))
                .text_color(rgb(if is_active {
                    p.primary_btn_text
                } else {
                    p.text_primary
                }))
                .child(match node.delay_ms {
                    Some(ms) => format!("{} · {}ms", node.name, ms),
                    None => node.name.clone(),
                });
            if clickable {
                let hover = p.sidebar_hover_bg;
                let ctrl_sw = ctrl.clone();
                let grp = mihomo.active_group.clone();
                let target_node = node.name.clone();
                inner = inner
                    .cursor_pointer()
                    .hover(move |s| s.bg(rgb(hover)))
                    .on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |_, _, _, cx| {
                            ctrl_sw.update(cx, |c, cx| {
                                c.send_request(
                                    PipeRequest::SwitchProxyNode {
                                        group: grp.clone(),
                                        node: target_node.clone(),
                                        close_connections: true,
                                    },
                                    Some("已切换代理节点、断开旧连接并自动触发出口复检"),
                                    cx,
                                );
                            });
                        }),
                    );
            }
            div().flex_shrink_0().child(inner)
        })
        .collect();

    let mihomo_card = bento_card(p)
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
                        .child("代理内核联动（Mihomo / Clash）"),
                )
                .child(status_pill(
                    if mihomo.available {
                        if mihomo.active_node.is_empty() {
                            mihomo.core_name.clone()
                        } else {
                            format!("{} · {}", mihomo.core_name, mihomo.active_node)
                        }
                    } else {
                        "未检测到控制接口".into()
                    },
                    if mihomo.available {
                        BadgeTone::Pass
                    } else {
                        BadgeTone::Muted
                    },
                    p,
                )),
        )
        .child(
            div()
                .text_size(px(11.5))
                .line_height(px(16.5))
                .text_color(rgb(p.text_secondary))
                .child(if mihomo.note.is_empty() {
                    "自动发现本机回环控制接口（127.0.0.1），点击下方节点即可一键切换、断开旧连接并复检出口".to_string()
                } else {
                    mihomo.note.clone()
                }),
        )
        .when(!mihomo_chips.is_empty(), |card| {
            card.child(
                div()
                    .flex()
                    .flex_wrap()
                    .w_full()
                    .min_w(px(0.))
                    .gap(px(8.))
                    .children(mihomo_chips),
            )
        });

    let direct_rows = leak.direct.iter().map(|c| {
        let remote = if mask {
            mask_ip_str(&c.remote)
        } else {
            c.remote.clone()
        };
        inset_box(p)
            .w_full()
            .flex_row()
            .items_center()
            .justify_between()
            .px(px(10.))
            .py(px(6.))
            .gap(px(8.))
            .child(
                mono_tabular(format!(
                    "PID {} · {} -> {}:{}",
                    c.pid, c.agent, remote, c.port
                ))
                .flex_1()
                .min_w(px(0.))
                .truncate()
                .text_size(px(11.5))
                .text_color(rgb(p.badge_fail.text)),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(6.))
                    .when(c.is_mcp, |d| d.child(status_pill("MCP 子进程", BadgeTone::Warn, p)))
                    .child(status_pill("绕过代理直连", BadgeTone::Fail, p)),
            )
    });

    div()
        .flex()
        .flex_col()
        .w_full()
        .min_w(px(0.))
        .gap(px(14.))
        .child(ag_card)
        .child(shield_card)
        .child(mihomo_card)
        .child(
            bento_card(p)
                .p(px(16.))
                .gap(px(10.))
                .child(card_header("直连防泄露雷达", leak.note.clone(), p))
                .child(switch_row(
                    "env-leak-watch",
                    "开启直连防泄露观察",
                    "系统代理模式下排查绕过代理的外连套接字（自动豁免回环与 198.18.0.0/15 TUN 虚拟 IP）",
                    cfg.leak_watch,
                    p,
                    cx.listener(move |_, _, _, cx| {
                        let next = !cfg.leak_watch;
                        ctrl_lw.update(cx, |c, cx| {
                            c.save_config_patch(move |x| x.leak_watch = next, "已更新", cx);
                        });
                    }),
                ))
                .child(switch_row(
                    "env-leak-trip",
                    "发现直连立即触发熔断",
                    "默认仅记录告警与日志；确认无误报后可启用自动熔断",
                    cfg.leak_trip,
                    p,
                    cx.listener(move |_, _, _, cx| {
                        let next = !cfg.leak_trip;
                        ctrl_lt.update(cx, |c, cx| {
                            c.save_config_patch(move |x| x.leak_trip = next, "已更新", cx);
                        });
                    }),
                ))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .child(
                            mono_tabular(format!(
                                "连接总计 {} · 经代理 {} · 本地 {} · 直连泄露 {}",
                                leak.agent_conns, leak.proxied, leak.local, leak.direct_total
                            ))
                            .text_size(px(12.))
                            .text_color(rgb(p.text_secondary)),
                        )
                        .child({
                            let can_scan = connected && !busy;
                            action_button(
                                "env-scan-now",
                                "↻ 立即扫描套接字",
                                ButtonKind::Secondary,
                                can_scan,
                                p,
                            )
                            .when(can_scan, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_scan.update(cx, |c, cx| {
                                            c.send_request(
                                                PipeRequest::RecheckNow { target_id: None },
                                                Some("已完成直连套接字扫描"),
                                                cx,
                                            );
                                        });
                                    }),
                                )
                            })
                        }),
                )
                .children(direct_rows),
        )
        .child(
            bento_card(p)
                .p(px(16.))
                .gap(px(10.))
                .child(card_header("系统时区与区域一致性", env.note.clone(), p))
                .child(
                    div()
                        .flex()
                        .gap(px(10.))
                        .child(
                            inset_box(p)
                                .flex_1()
                                .p(px(10.))
                                .gap(px(4.))
                                .child(
                                    div()
                                        .text_size(px(11.))
                                        .text_color(rgb(p.text_muted))
                                        .child("当前 Windows 时区 / 区域"),
                                )
                                .child(
                                    div()
                                        .text_size(px(12.5))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(p.text_primary))
                                        .child(format!("{} · {}", env.info.tz_label, env.info.locale)),
                                ),
                        )
                        .child(
                            inset_box(p)
                                .flex_1()
                                .p(px(10.))
                                .gap(px(4.))
                                .child(
                                    div()
                                        .text_size(px(11.))
                                        .text_color(rgb(p.text_muted))
                                        .child("期望出口对应时区"),
                                )
                                .child(
                                    div()
                                        .text_size(px(12.5))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(p.text_primary))
                                        .child(format!(
                                            "{} · {}",
                                            env.expect_city.as_deref().unwrap_or("待识别"),
                                            env.expect_tz.as_deref().unwrap_or("--")
                                        )),
                                ),
                        ),
                )
                .child(switch_row(
                    "env-check-sw",
                    "检测时区与区域一致性",
                    "对比出口城市（colo 映射）与 Windows 本地时区及区域格式",
                    cfg.env_check,
                    p,
                    cx.listener(move |_, _, _, cx| {
                        let next = !cfg.env_check;
                        ctrl_ec.update(cx, |c, cx| {
                            c.save_config_patch(move |x| x.env_check = next, "已更新", cx);
                        });
                    }),
                ))
                .child(switch_row(
                    "env-tz-sw",
                    "自动对齐 Windows 时区",
                    "出口城市连续一致后自动切换时区并在安全撤防/退出时由 WAL 还原",
                    cfg.env_align_tz,
                    p,
                    cx.listener(move |_, _, _, cx| {
                        let next = !cfg.env_align_tz;
                        ctrl_tz.update(cx, |c, cx| {
                            c.save_config_patch(move |x| x.env_align_tz = next, "已更新", cx);
                        });
                    }),
                ))
                .child(switch_row(
                    "env-loc-sw",
                    "自动对齐 Windows 默认位置",
                    "同步更新系统默认地理坐标，退出时按 WAL 基线还原",
                    cfg.env_align_location,
                    p,
                    cx.listener(move |_, _, _, cx| {
                        let next = !cfg.env_align_location;
                        ctrl_loc.update(cx, |c, cx| {
                            c.save_config_patch(
                                move |x| x.env_align_location = next,
                                "已更新",
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
                        .justify_between()
                        .gap(px(8.))
                        .child(
                            div()
                                .flex_1()
                                .min_w(px(200.))
                                .text_size(px(11.5))
                                .text_color(rgb(if env_applied.is_some() {
                                    p.badge_pass.text
                                } else {
                                    p.text_muted
                                }))
                                .child(if let Some(ap) = env_applied.as_ref() {
                                    format!(
                                        "已对齐环境（{}）：时区 {} → {}",
                                        ap.city,
                                        if ap.tz_from.is_empty() { "原始" } else { &ap.tz_from },
                                        if ap.tz_to.is_empty() { "未改" } else { &ap.tz_to }
                                    )
                                } else {
                                    "执行对齐前将自动备份原时区与默认定位，撤防或卸载时自动无损还原"
                                        .to_string()
                                }),
                        )
                        .child(
                            div()
                                .flex()
                                .flex_wrap()
                                .gap(px(8.))
                                .child({
                                    let can_rb = connected && !busy && env_applied.is_some();
                                    action_button(
                                        "env-rollback-btn",
                                        "↩ 一键还原原始环境",
                                        ButtonKind::Secondary,
                                        can_rb,
                                        p,
                                    )
                                    .when(can_rb, |b| {
                                        b.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                ctrl_rollback_env.update(cx, |c, cx| {
                                                    c.send_request(
                                                        PipeRequest::RollbackEnvAlignment,
                                                        Some("已还原原始 Windows 时区与默认定位"),
                                                        cx,
                                                    );
                                                });
                                            }),
                                        )
                                    })
                                })
                                .child({
                                    let can_apply = connected && !busy;
                                    let do_tz = cfg.env_align_tz || !cfg.env_align_location;
                                    let do_loc = cfg.env_align_location;
                                    action_button(
                                        "env-apply-align-btn",
                                        "立即对齐出口时区/定位",
                                        ButtonKind::Primary,
                                        can_apply,
                                        p,
                                    )
                                    .when(can_apply, |b| {
                                        b.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                ctrl_apply_env.update(cx, |c, cx| {
                                                    c.send_request(
                                                        PipeRequest::ApplyEnvAlignment {
                                                            align_tz: do_tz,
                                                            align_location: do_loc,
                                                        },
                                                        Some("已将系统时区/定位对齐至当前出口"),
                                                        cx,
                                                    );
                                                });
                                            }),
                                        )
                                    })
                                })
                                .child({
                                    let can_align = connected && !busy;
                                    action_button(
                                        "env-realign-btn",
                                        "↻ 刷新校验",
                                        ButtonKind::Secondary,
                                        can_align,
                                        p,
                                    )
                                    .when(can_align, |b| {
                                        b.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                ctrl_align.update(cx, |c, cx| {
                                                    c.send_request(
                                                        PipeRequest::RecheckNow { target_id: None },
                                                        Some("环境一致性校验已刷新"),
                                                        cx,
                                                    );
                                                });
                                            }),
                                        )
                                    })
                                }),
                        ),
                ),
        )
}

#[allow(clippy::too_many_arguments)]
fn render_antigravity_proxy_card(
    ctrl: Entity<AppController>,
    ag: &AntigravityProxyStatus,
    updates: &UpdateSummary,
    guard_proxy_port: u16,
    require_ag_proxy: bool,
    privacy_mask: bool,
    connected: bool,
    busy: bool,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> Div {
    let vm = project_antigravity_proxy_card(ag, guard_proxy_port, privacy_mask, now_unix_secs());
    let can_act = connected && !busy;
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
        .map(|v| format!("v{}", v.trim_start_matches('v')))
        .unwrap_or_else(|| "新版".into());
    let ag_update_surf = p.badge(BadgeTone::Warn);

    let ver_color = if vm.version_warn {
        p.badge_warn.text
    } else if ag.installed {
        p.text_primary
    } else {
        p.text_muted
    };
    let dll_color = match vm.dll_tone {
        BadgeTone::Pass => p.badge_pass.text,
        BadgeTone::Fail => p.badge_fail.text,
        BadgeTone::Warn => p.badge_warn.text,
        BadgeTone::Muted => p.text_muted,
    };
    let cfg_color = match vm.config_tone {
        BadgeTone::Pass => p.text_primary,
        BadgeTone::Fail => p.badge_fail.text,
        BadgeTone::Warn => p.badge_warn.text,
        BadgeTone::Muted => p.text_muted,
    };
    let rt_color = match vm.runtime_tone {
        BadgeTone::Pass => p.badge_pass.text,
        BadgeTone::Fail => p.badge_fail.text,
        BadgeTone::Warn => p.badge_warn.text,
        BadgeTone::Muted => p.text_secondary,
    };

    let summary_surface = if vm.is_degraded {
        Some(p.badge(BadgeTone::Fail))
    } else {
        None
    };

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
                                .child("反重力透明代理注入守护 (antigravity-proxy)"),
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
                                    .id("env-ag-upd-available-badge")
                                    .flex()
                                    .items_center()
                                    .gap(px(5.))
                                    .px(px(8.))
                                    .py(px(3.))
                                    .rounded(px(999.))
                                    .bg(rgba(ag_update_surf.bg))
                                    .border_1()
                                    .border_color(rgb(ag_update_surf.dot))
                                    .cursor_pointer()
                                    .child(
                                        div()
                                            .w(px(6.))
                                            .h(px(6.))
                                            .rounded(px(999.))
                                            .bg(rgb(ag_update_surf.dot)),
                                    )
                                    .child(
                                        div()
                                            .text_size(px(11.))
                                            .font_weight(FontWeight::MEDIUM)
                                            .text_color(rgb(ag_update_surf.text))
                                            .child(format!("发现仓库新版 {ag_update_tag}")),
                                    )
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
                        .when_some(vm.checked_age_label, |row, age| {
                            row.child(
                                div()
                                    .text_size(px(11.))
                                    .text_color(rgb(p.text_muted))
                                    .child(format!("核验于 {age}")),
                            )
                        })
                        .child(status_pill(vm.pill_label, vm.pill_tone, p)),
                ),
        )
        // 2x2 diagnostic tiles
        .child(
            div()
                .flex()
                .gap(px(10.))
                .child(ag_diag_tile(
                    "客户端版本",
                    vm.version_primary,
                    vm.version_sub,
                    ver_color,
                    true,
                    p,
                ))
                .child(ag_diag_tile(
                    "version.dll 劫持模块",
                    vm.dll_primary,
                    vm.dll_sub,
                    dll_color,
                    false,
                    p,
                )),
        )
        .child(
            div()
                .flex()
                .gap(px(10.))
                .child(ag_diag_tile(
                    "config.json 代理配置",
                    vm.config_primary,
                    vm.config_sub,
                    cfg_color,
                    true,
                    p,
                ))
                .child(ag_diag_tile(
                    "运行态内存挂载 (language_server)",
                    vm.runtime_primary,
                    vm.runtime_sub,
                    rt_color,
                    false,
                    p,
                )),
        )
        // Summary + install directory bar
        .child({
            let mut bar = inset_box(p).px(px(12.)).py(px(8.)).gap(px(3.));
            if let Some(surf) = summary_surface {
                bar = bar
                    .bg(rgba(surf.bg))
                    .border_color(rgba(p.hero_tripped.border));
            }
            bar.child(
                div()
                    .text_size(px(12.))
                    .font_weight(FontWeight::MEDIUM)
                    .text_color(rgb(if vm.is_degraded {
                        p.badge_fail.text
                    } else if ag.installed {
                        p.text_primary
                    } else {
                        p.text_muted
                    }))
                    .child(if vm.is_degraded {
                        format!("! {}", vm.summary_text)
                    } else {
                        vm.summary_text
                    }),
            )
            .child(
                mono_tabular(format!("安装目录：{}", vm.dir_text))
                    .truncate()
                    .text_size(px(11.))
                    .text_color(rgb(p.text_muted)),
            )
        })
        // Bottom row: toggle_switch + immediate recheck button
        .child(
            inset_box(p)
                .flex_row()
                .items_center()
                .justify_between()
                .px(px(12.))
                .py(px(9.))
                .gap(px(12.))
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
                                                c.save_config_patch(
                                                    move |x| x.require_antigravity_proxy = next,
                                                    if next {
                                                        "已开启反重力注入失效拦截门禁"
                                                    } else {
                                                        "已关闭反重力注入失效拦截门禁"
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
                                .gap(px(1.))
                                .flex_1()
                                .min_w(px(0.))
                                .child(
                                    div()
                                        .text_size(px(12.5))
                                        .font_weight(FontWeight::MEDIUM)
                                        .text_color(rgb(p.text_primary))
                                        .child("注入失效时拦截安全启动"),
                                )
                                .child(
                                    div()
                                        .truncate()
                                        .text_size(px(11.))
                                        .text_color(rgb(p.text_muted))
                                        .child("客户端自动升级覆盖 version.dll 或内存未挂载时，阻止反重力直连启动"),
                                ),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .flex_wrap()
                        .items_center()
                        .gap(px(8.))
                        .child(
                            action_button(
                                "env-ag-repair-btn",
                                "一键下载并热修复注入",
                                if vm.is_degraded {
                                    ButtonKind::Primary
                                } else {
                                    ButtonKind::Secondary
                                },
                                can_act && ag.installed,
                                p,
                            )
                            .when(can_act && ag.installed, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_repair.update(cx, |c, cx| {
                                            c.send_request(
                                                PipeRequest::RepairAntigravityProxy,
                                                Some("已完成 antigravity-proxy 验签热修复注入并同步端口"),
                                                cx,
                                            );
                                        });
                                    }),
                                )
                            }),
                        )
                        .child(
                            action_button(
                                "env-ag-recheck-btn",
                                "↻ 立即重检",
                                ButtonKind::Secondary,
                                can_act,
                                p,
                            )
                            .when(can_act, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_recheck.update(cx, |c, cx| {
                                            c.send_request(
                                                PipeRequest::RecheckNow { target_id: None },
                                                Some("已完成反重力透明代理注入核验"),
                                                cx,
                                            );
                                        });
                                    }),
                                )
                            }),
                        ),
                ),
        )
}


