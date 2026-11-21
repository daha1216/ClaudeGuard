//! Mode B — Frost Ceramic `防漏与环境` view (3 pure defense sub-tabs, ZERO Mihomo mutation).
//!
//! Sub-tabs:
//! 1. `防漏护盾与雷达` (`EnvSubTab::Shield`): 4-vector leak shield + direct-leak & MCP radar
//! 2. `反重力代理注入` (`EnvSubTab::Antigravity`): 2×2 diagnostics + plain-language explanation + hot-repair
//! 3. `时区与区域指纹` (`EnvSubTab::Timezone`): pure Windows TZ & locale alignment (no proxy switching)

use crate::app::{AppController, ConsoleWindowView, EnvSubTab};
use crate::assets::brand_icon;
use crate::demo::now_unix_secs;
use crate::protocol::{
    AntigravityProxyStatus, PipeRequest, UpdateCheckPhase, UpdateSummary, mask_ip_str,
};
use crate::state::{NavSection, project_antigravity_proxy_card};
use crate::theme::{BadgeTone, ThemePalette};
use crate::views::shared::{ag_diag_tile, page_guide_card, switch_row};
use crate::widgets::controls::{
    ButtonKind, action_button, bento_card, icon_action_button, inset_box, mono_tabular,
    status_pill, subtab_bar, subtab_item, toggle_switch,
};
use gpui::{Context, Div, Entity, FontWeight, MouseButton, div, prelude::*, px, rgb, rgba};

pub fn render_environment_page(
    ctrl: Entity<AppController>,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> Div {
    let ctrl_r = ctrl.read(cx);
    let snap = ctrl_r.snapshot.clone();
    let tab = ctrl_r.env_tab;
    let mask = ctrl_r.privacy_mask;
    let busy = ctrl_r.busy_action;
    let connected = ctrl_r.connected;
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
    let ag_issue = ag_proxy.installed && !ag_proxy.is_ready_for_launch();

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

            let left_shield = bento_card(p)
                .flex_1()
                .flex_basis(px(0.))
                .px(px(16.))
                .py(px(14.))
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
                                        .child("4 维防泄露护盾"),
                                )
                                .child(
                                    mono_tabular(if shield.enabled {
                                        format!("● 已生效 {} 条防火墙规则", shield.active_rules)
                                    } else {
                                        "未启用".into()
                                    })
                                    .text_size(px(11.))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .text_color(rgb(if shield.enabled {
                                        p.badge_pass.text
                                    } else {
                                        p.text_muted
                                    })),
                                ),
                        )
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .child(
                                    switch_row(
                                        "sh-quic-sw",
                                        "阻断 QUIC UDP:443 直连",
                                        "同步注入安全启动防 QUIC 参数，阻止 HTTP/3 绕过代理",
                                        cfg.leak_shield_quic,
                                        p,
                                        cx.listener(move |_, _, _, cx| {
                                            let next = !cfg.leak_shield_quic;
                                            ctrl_q.update(cx, |c, cx| {
                                                c.save_config_patch(
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
                                    switch_row(
                                        "sh-dns-sw",
                                        "阻断明文 DNS:53 与公共 DoH",
                                        "禁止受管应用绕过代理向运营商或公共 DNS 节点解析",
                                        cfg.leak_shield_dns_doh,
                                        p,
                                        cx.listener(move |_, _, _, cx| {
                                            let next = !cfg.leak_shield_dns_doh;
                                            ctrl_d.update(cx, |c, cx| {
                                                c.save_config_patch(
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
                                .child(switch_row(
                                    "sh-ipv6-sw",
                                    "阻断公网 IPv6 直连 (2000::/3)",
                                    "双栈宽带下本地代理仅接管 IPv4 时封锁 IPv6 直出",
                                    cfg.leak_shield_ipv6,
                                    p,
                                    cx.listener(move |_, _, _, cx| {
                                        let next = !cfg.leak_shield_ipv6;
                                        ctrl_v.update(cx, |c, cx| {
                                            c.save_config_patch(
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
                                                .child("当前护盾策略与生效边界"),
                                        )
                                        .child(
                                            div()
                                                .text_size(px(10.5))
                                                .font_weight(FontWeight::SEMIBOLD)
                                                .text_color(rgb(p.badge_pass.text))
                                                .child("仅限受管 AI 应用"),
                                        ),
                                )
                                .child(
                                    div()
                                        .flex()
                                        .flex_wrap()
                                        .gap(px(5.))
                                        .child(shield_pill("UDP:443 QUIC", cfg.leak_shield_quic))
                                        .child(shield_pill("DNS:53 & DoH", cfg.leak_shield_dns_doh))
                                        .child(shield_pill("公网 IPv6", cfg.leak_shield_ipv6))
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
                                        .child("所有规则仅精准绑定已安装的受管 AI 客户端路径，绝不影响浏览器、游戏或日常软件联网；撤防或卸载时自动清空零残留。"),
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
                                .text_color(rgb(p.text_muted))
                                .child("规则已写入 Windows 防火墙"),
                        )
                        .child(
                            icon_action_button(
                                "env-shield-sync",
                                "icons/ui/refresh.svg",
                                "同步护盾规则",
                                ButtonKind::Primary,
                                can_act,
                                p,
                            )
                            .h(px(28.))
                            .when(can_act, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_sync.update(cx, |c, cx| {
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

            let leak_rows: Vec<Div> = if leak.direct.is_empty() {
                vec![
                    inset_box(p)
                        .px(px(11.))
                        .py(px(10.))
                        .gap(px(3.))
                        .child(
                            div()
                                .text_size(px(11.5))
                                .font_weight(FontWeight::MEDIUM)
                                .text_color(rgb(p.badge_pass.text))
                                .child("● 未发现绕过本地代理的直连或 MCP 外连"),
                        )
                        .child(
                            div()
                                .text_size(px(10.5))
                                .text_color(rgb(p.text_muted))
                                .child(if leak.note.is_empty() {
                                    "全部受管客户端与子进程流量均正常经受管通道转发。".to_string()
                                } else {
                                    leak.note.clone()
                                }),
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

            let right_radar = bento_card(p)
                .flex_1()
                .flex_basis(px(0.))
                .px(px(16.))
                .py(px(14.))
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
                                        .child("直连防泄露与 MCP 雷达"),
                                )
                                .child(
                                    mono_tabular(if leak.direct_total > 0 {
                                        format!("● 发现 {} 条直连", leak.direct_total)
                                    } else {
                                        "● 0 直连泄露".into()
                                    })
                                    .text_size(px(11.))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .text_color(rgb(if leak.direct_total > 0 {
                                        p.badge_fail.text
                                    } else {
                                        p.badge_pass.text
                                    })),
                                ),
                        )
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .child(
                                    switch_row(
                                        "env-leak-watch",
                                        "开启直连防泄露观察",
                                        "持续扫描受管进程及 MCP 子进程的外连目标",
                                        cfg.leak_watch,
                                        p,
                                        cx.listener(move |_, _, _, cx| {
                                            let next = !cfg.leak_watch;
                                            ctrl_lw.update(cx, |c, cx| {
                                                c.save_config_patch(
                                                    move |x| x.leak_watch = next,
                                                    "直连防泄露观察已更新",
                                                    cx,
                                                );
                                            });
                                        }),
                                    )
                                    .border_b_1()
                                    .border_color(rgb(p.card_border)),
                                )
                                .child(switch_row(
                                    "env-leak-trip",
                                    "发现直连立即触发熔断",
                                    "默认仅告警记录；确认无误报后可开启强拦截",
                                    cfg.leak_trip,
                                    p,
                                    cx.listener(move |_, _, _, cx| {
                                        let next = !cfg.leak_trip;
                                        ctrl_lt.update(cx, |c, cx| {
                                            c.save_config_patch(
                                                move |x| x.leak_trip = next,
                                                "直连自动熔断开关已更新",
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
                                        "活跃连接 {} · 经代理 {} · 本地 {}",
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
                                            p.badge_pass.text
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
                                .child("已自动豁免本机回环与 TUN 虚拟网卡"),
                        )
                        .child(
                            icon_action_button(
                                "env-scan-now",
                                "icons/ui/refresh.svg",
                                "立即扫描",
                                ButtonKind::Secondary,
                                can_act,
                                p,
                            )
                            .h(px(28.))
                            .when(can_act, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_scan.update(cx, |c, cx| {
                                            c.send_request(
                                                PipeRequest::RecheckNow { target_id: None },
                                                Some("已完成受管进程直连扫描"),
                                                cx,
                                            );
                                        });
                                    }),
                                )
                            }),
                        ),
                );

            let shield_guide = page_guide_card(
                "4 维防漏护盾与直连雷达原理",
                "仅精准约束受管 AI 客户端 · 不影响日常应用联网",
                &[
                    (
                        "1. QUIC / DNS / IPv6 旁路封堵",
                        "部分客户端会尝试经 UDP 443 (HTTP/3)、直连 DNS 或公网 IPv6 绕开本地代理；护盾通过按程序路径绑定的防火墙规则堵住旁路。",
                    ),
                    (
                        "2. MCP 子进程直连雷达",
                        "AI 工具拉起的 MCP 插件与子进程常忽略系统代理。开启直连观察后，雷达会自动识别异常外连并标记来源 PID。",
                    ),
                    (
                        "3. 本机回环与 TUN 自动豁免",
                        "发往 127.0.0.1、内网局域网及 TUN 虚拟网卡的流量均自动放行，无误报干扰；撤防或卸载时自动清理全部防火墙规则。",
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
                        .child(left_shield)
                        .child(right_radar),
                )
                .child(shield_guide)
        }

        EnvSubTab::Antigravity => render_antigravity_proxy_card(
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
        ),

        EnvSubTab::Timezone => {
            let ctrl_ec = ctrl.clone();
            let ctrl_tz = ctrl.clone();
            let ctrl_loc = ctrl.clone();
            let ctrl_rb = ctrl.clone();
            let ctrl_apply = ctrl.clone();

            let tz_aligned = env_applied.is_some() || !env.mismatched();
            let main_tz_card = bento_card(p)
                .w_full()
                .px(px(17.))
                .py(px(14.))
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
                                        .child("系统时区与区域指纹一致性"),
                                )
                                .child(
                                    div()
                                        .text_size(px(11.))
                                        .text_color(rgb(p.text_muted))
                                        .child("仅对齐 Windows 本机时间与区域设置，绝不修改代理软件节点策略"),
                                ),
                        )
                        .child(
                            div()
                                .text_size(px(11.5))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(if tz_aligned {
                                    p.badge_pass.text
                                } else {
                                    p.badge_warn.text
                                }))
                                .child(if env_applied.is_some() {
                                    "● 已与出口对齐"
                                } else if env.mismatched() {
                                    "● 与出口存在偏差"
                                } else {
                                    "● 时区一致"
                                }),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .flex_row()
                        .gap(px(10.))
                        .child(ag_diag_tile(
                            "本机当前 Windows 时区 / 区域",
                            format!("{} · {}", env.info.tz_label, env.info.locale),
                            if env_applied.is_some() {
                                "默认位置：已按出口对齐（已备份原始值）".into()
                            } else {
                                "默认位置：系统原始值（未修改）".into()
                            },
                            p.text_primary,
                            true,
                            p,
                        ))
                        .child(ag_diag_tile(
                            "当前合规出口对应目标环境",
                            format!(
                                "{} · {}",
                                env.expect_city.as_deref().unwrap_or("待识别"),
                                env.expect_tz.as_deref().unwrap_or("--")
                            ),
                            "依据当前检测到的合规出口所在城市自动匹配".into(),
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
                            switch_row(
                                "env-check-sw",
                                "检测时区与区域一致性",
                                "每次出口核验后对比出口城市与本机 Windows 时区，发现跨区偏差时给出提示",
                                cfg.env_check,
                                p,
                                cx.listener(move |_, _, _, cx| {
                                    let next = !cfg.env_check;
                                    ctrl_ec.update(cx, |c, cx| {
                                        c.save_config_patch(
                                            move |x| x.env_check = next,
                                            "时区一致性检测已更新",
                                            cx,
                                        );
                                    });
                                }),
                            )
                            .border_b_1()
                            .border_color(rgb(p.card_border)),
                        )
                        .child(
                            switch_row(
                                "env-tz-sw",
                                "自动对齐 Windows 系统时区",
                                "自动备份你的原始时区；在点击撤防、退出软件或卸载时自动无损恢复",
                                cfg.env_align_tz,
                                p,
                                cx.listener(move |_, _, _, cx| {
                                    let next = !cfg.env_align_tz;
                                    ctrl_tz.update(cx, |c, cx| {
                                        c.save_config_patch(
                                            move |x| x.env_align_tz = next,
                                            "自动对齐时区已更新",
                                            cx,
                                        );
                                    });
                                }),
                            )
                            .border_b_1()
                            .border_color(rgb(p.card_border)),
                        )
                        .child(switch_row(
                            "env-loc-sw",
                            "自动对齐 Windows 默认位置",
                            "按出口城市同步系统默认地理坐标，同样支持一键与退出无损还原",
                            cfg.env_align_location,
                            p,
                            cx.listener(move |_, _, _, cx| {
                                let next = !cfg.env_align_location;
                                ctrl_loc.update(cx, |c, cx| {
                                    c.save_config_patch(
                                        move |x| x.env_align_location = next,
                                        "自动对齐默认位置已更新",
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
                                    "已对齐（{}）：{} → {} · 随时可无损还原",
                                    ap.city,
                                    if ap.tz_from.is_empty() { "原始" } else { &ap.tz_from },
                                    if ap.tz_to.is_empty() { "未改" } else { &ap.tz_to }
                                )
                            } else {
                                format!("原始环境备份：{} · 随时可无损还原", env.info.tz_label)
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
                                    let can_rb = can_act && env_applied.is_some();
                                    action_button(
                                        "env-rollback-btn",
                                        "还原原始环境",
                                        ButtonKind::Secondary,
                                        can_rb,
                                        p,
                                    )
                                    .h(px(28.))
                                    .when(!can_rb, |b| b.opacity(0.55))
                                    .when(can_rb, |b| {
                                        b.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                ctrl_rb.update(cx, |c, cx| {
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
                                    let do_tz = cfg.env_align_tz || !cfg.env_align_location;
                                    let do_loc = cfg.env_align_location;
                                    action_button(
                                        "env-apply-align-btn",
                                        "立即对齐出口",
                                        ButtonKind::Primary,
                                        can_act,
                                        p,
                                    )
                                    .h(px(28.))
                                    .when(can_act, |b| {
                                        b.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                ctrl_apply.update(cx, |c, cx| {
                                                    c.send_request(
                                                        PipeRequest::ApplyEnvAlignment {
                                                            align_tz: do_tz,
                                                            align_location: do_loc,
                                                        },
                                                        Some("已将系统时区对齐至当前出口"),
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
                "为什么需要「时区与区域指纹」对齐？",
                "纯本机环境辅助 · 零残留还原保障",
                &[
                    (
                        "1. 减少跨区风控信号",
                        "当出口位于美国或日本，而本机 Windows 时区仍停留在北京时间时，部分 AI 桌面客户端会结合本地系统时区判断账号环境是否异常。",
                    ),
                    (
                        "2. 不干涉你的代理策略",
                        "ClaudeGuard 只读检测你当前代理出口所在地区并辅助同步本机时区，绝不会擅自切换你的代理节点或篡改代理软件的分流规则。",
                    ),
                    (
                        "3. 自动备份与一键复原",
                        "首次对齐前会持久备份原时区与定位状态；日常只需点「还原原始环境」，或在撤防、退出守护时均会自动恢复，不留系统残留。",
                    ),
                ],
                p,
            );

            div()
                .flex()
                .flex_col()
                .w_full()
                .gap(px(10.))
                .child(main_tz_card)
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

    let guide_box = page_guide_card(
        "什么是「反重力代理注入」？（通俗说明）",
        "开源组件：yuaotian/antigravity-proxy",
        &[
            (
                "1. 它是干什么的？",
                "Antigravity 后台部分组件不走 Windows 系统代理，容易偷偷直连。该模块把它的全部流量强制转进本地代理，不开全局 TUN 也能稳稳代理。",
            ),
            (
                "2. 为什么会失效？",
                "每当 Antigravity 自动更新覆盖目录时，代理文件（version.dll）可能被新版冲掉，导致代理保护失效。",
            ),
            (
                "3. 失效了怎么办？",
                "保持下方拦截开关开启，失效时会自动挡住防直连；只需点右下角「一键下载并热修复注入」，几秒钟就能自动补回并同步端口。",
            ),
        ],
        p,
    );

    bento_card(p)
        .w_full()
        .px(px(17.))
        .py(px(14.))
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
                        .child(brand_icon("antigravity", 24.0, 6.0, p.is_dark))
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
                                        .child("反重力透明代理注入守护"),
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
                                    .child(format!("● 发现新版 {ag_update_tag} →"))
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
                        .child(status_pill(vm.pill_label, vm.pill_tone, p)),
                ),
        )
        .child(
            div()
                .flex()
                .flex_row()
                .gap(px(9.))
                .child(ag_diag_tile(
                    "客户端版本",
                    vm.version_primary,
                    vm.version_sub,
                    ver_color,
                    true,
                    p,
                ))
                .child(ag_diag_tile(
                    "version.dll 代理注入模块",
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
                .flex_row()
                .gap(px(9.))
                .child(ag_diag_tile(
                    "config.json 代理配置",
                    vm.config_primary,
                    vm.config_sub,
                    cfg_color,
                    true,
                    p,
                ))
                .child(ag_diag_tile(
                    "运行态注入状态 (language_server)",
                    vm.runtime_primary,
                    vm.runtime_sub,
                    rt_color,
                    false,
                    p,
                )),
        )
        .child({
            let mut bar = inset_box(p).px(px(12.)).py(px(8.)).gap(px(2.5));
            if vm.is_degraded {
                bar = bar
                    .bg(rgba(p.badge_fail.bg))
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
                    .text_size(px(10.5))
                    .text_color(rgb(p.text_muted)),
            )
        })
        .child(guide_box)
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
                                .min_w(px(0.))
                                .gap(px(1.5))
                                .child(
                                    div()
                                        .text_size(px(12.))
                                        .font_weight(FontWeight::MEDIUM)
                                        .text_color(rgb(p.text_primary))
                                        .child("注入失效时拦截安全启动"),
                                )
                                .child(
                                    div()
                                        .truncate()
                                        .text_size(px(10.5))
                                        .text_color(rgb(p.text_muted))
                                        .child("客户端升级覆盖 version.dll 或未挂载时禁止直连拉起"),
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
                            icon_action_button(
                                "env-ag-recheck-btn",
                                "icons/ui/refresh.svg",
                                "立即重检",
                                ButtonKind::Secondary,
                                can_act,
                                p,
                            )
                            .h(px(29.))
                            .when(can_act, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_recheck.update(cx, |c, cx| {
                                            c.send_request(
                                                PipeRequest::RecheckNow { target_id: None },
                                                Some("已完成反重力注入状态核验"),
                                                cx,
                                            );
                                        });
                                    }),
                                )
                            }),
                        )
                        .child(
                            action_button(
                                "env-ag-repair-btn",
                                "一键下载并热修复注入",
                                if vm.is_degraded {
                                    ButtonKind::Danger
                                } else {
                                    ButtonKind::Primary
                                },
                                can_act && ag.installed,
                                p,
                            )
                            .h(px(29.))
                            .when(can_act && ag.installed, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_repair.update(cx, |c, cx| {
                                            c.send_request(
                                                PipeRequest::RepairAntigravityProxy,
                                                Some("已完成 antigravity-proxy 校验热修复并同步端口"),
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
