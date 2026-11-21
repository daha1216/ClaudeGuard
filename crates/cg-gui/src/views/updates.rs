//! Mode B — Frost Ceramic `客户端更新` view.
//!
//! Tracks all 10 components (strictly read-only through managed proxy):
//! - Band 1: `ClaudeGuard 守护端` + 6h auto-check switch + `立即巡检全部 (10)`
//! - Band 2: `antigravity-proxy 透明代理注入器` + `检测` + `去热修复 →`
//! - Band 3: Symmetrical 2×3 grid (`Claude Desktop`, `Claude Code CLI`, `ChatGPT / Codex 桌面端`,
//!   `Codex CLI`, `Antigravity IDE` [with `插件推荐` button opening the 4-plugin update modal],
//!   `Antigravity 中文汉化引擎` [Silas-02/antigravity-desktop-cn]).

use crate::app::{AppController, ConsoleWindowView, EnvSubTab};
use crate::assets::{brand_icon, ui_icon};
use crate::demo::now_unix_secs;
use crate::ipc::open_external_url;
use crate::protocol::{ComponentUpdateStatus, PipeRequest, UiLabelExt, UpdateCheckPhase};
use crate::state::{NavSection, format_relative_secs};
use crate::theme::{BadgeTone, ThemePalette};
use crate::views::plugins_modal::count_plugin_updates;
use crate::widgets::controls::{
    ButtonKind, action_button, bento_card, icon_action_button, mono_tabular, toggle_switch,
    tone_tag,
};
use gpui::{Context, Div, Entity, FontWeight, MouseButton, div, prelude::*, px, rgb};

fn update_phase_tone(phase: UpdateCheckPhase) -> BadgeTone {
    match phase {
        UpdateCheckPhase::UpToDate => BadgeTone::Pass,
        UpdateCheckPhase::UpdateAvailable => BadgeTone::Warn,
        UpdateCheckPhase::Failed => BadgeTone::Fail,
        UpdateCheckPhase::Idle | UpdateCheckPhase::Checking | UpdateCheckPhase::NotInstalled => {
            BadgeTone::Muted
        }
    }
}

fn fmt_ver(ver: Option<&str>, is_repo_track: bool, fallback: &str) -> String {
    match ver.map(str::trim).filter(|s| !s.is_empty()) {
        None => fallback.to_string(),
        Some(v) if is_repo_track => v.trim_start_matches(['v', 'V']).to_string(),
        Some(v) => format!("v{}", v.trim_start_matches(['v', 'V'])),
    }
}

fn component_toast(id: &str) -> &'static str {
    match id {
        "claude_desktop" => "已完成 Claude Desktop 最新版本检测",
        "claude_code" => "已完成 Claude Code CLI 最新版本检测",
        "codex_desktop" => "已完成 ChatGPT / Codex 桌面端最新版本检测",
        "codex_cli" => "已完成 Codex CLI 最新版本检测",
        "antigravity_ide" => "已完成 Antigravity IDE 最新版本检测",
        "antigravity_cn" => "已完成 Antigravity 中文汉化引擎仓库更新检测",
        _ => "已完成组件版本检测",
    }
}

struct GridCardSpec<'a> {
    item: &'a ComponentUpdateStatus,
    icon_key: &'static str,
    title: &'static str,
    subtitle: &'static str,
    source: &'static str,
    is_repo_track: bool,
    repo_url: Option<&'static str>,
    has_plugins_btn: bool,
}

#[allow(clippy::too_many_arguments)]
fn render_grid_card(
    ctrl: Entity<AppController>,
    spec: GridCardSpec<'_>,
    plugin_updates_count: usize,
    can_check: bool,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> Div {
    let item = spec.item;
    let has_up = item.phase == UpdateCheckPhase::UpdateAvailable;
    let phase_label = if spec.is_repo_track && has_up {
        "仓库有更新"
    } else {
        item.phase.label()
    };

    let cur = fmt_ver(
        item.installed_version.as_deref(),
        spec.is_repo_track,
        if spec.is_repo_track { "未检测" } else { "未安装" },
    );
    let lat = fmt_ver(item.latest_version.as_deref(), spec.is_repo_track, "待检查");

    let ver_line = if spec.is_repo_track {
        if has_up {
            div()
                .flex()
                .items_center()
                .gap(px(4.))
                .min_w(px(0.))
                .child(
                    mono_tabular(format!("本地 {cur} →"))
                        .text_size(px(11.5))
                        .text_color(rgb(p.text_secondary)),
                )
                .child(
                    mono_tabular(format!("上游 {lat}"))
                        .text_size(px(11.5))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(rgb(p.badge_warn.text)),
                )
        } else {
            mono_tabular(format!("本地 {cur} · {}", spec.source))
                .truncate()
                .text_size(px(11.5))
                .text_color(rgb(p.text_secondary))
        }
    } else if has_up {
        div()
            .flex()
            .items_center()
            .gap(px(4.))
            .min_w(px(0.))
            .child(
                mono_tabular(format!("本机 {cur} →"))
                    .text_size(px(11.5))
                    .font_weight(FontWeight::MEDIUM)
                    .text_color(rgb(p.text_primary)),
            )
            .child(
                mono_tabular(lat)
                    .text_size(px(11.5))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(rgb(p.badge_warn.text)),
            )
    } else {
        mono_tabular(format!("本机 {cur} · {}", spec.source))
            .truncate()
            .text_size(px(11.5))
            .text_color(rgb(p.text_secondary))
    };

    let comp_id = item.id.clone();
    let toast_msg = component_toast(&item.id);
    let ctrl_chk = ctrl.clone();
    let ctrl_plug = ctrl.clone();
    let ctrl_repo = ctrl;

    let hover_bg = p.sidebar_hover_bg;

    bento_card(p)
        .flex_1()
        .flex_basis(px(0.))
        .min_w(px(0.))
        .px(px(14.))
        .py(px(11.))
        .justify_between()
        .gap(px(8.))
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
                        .min_w(px(0.))
                        .flex_1()
                        .child(brand_icon(spec.icon_key, 24.0, 6.0, p.is_dark))
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .min_w(px(0.))
                                .flex_1()
                                .gap(px(1.))
                                .child(
                                    div()
                                        .truncate()
                                        .text_size(px(12.5))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(p.text_primary))
                                        .child(spec.title),
                                )
                                .child(
                                    mono_tabular(spec.subtitle)
                                        .truncate()
                                        .text_size(px(10.5))
                                        .text_color(rgb(p.text_muted)),
                                ),
                        ),
                )
                .child(tone_tag(phase_label, update_phase_tone(item.phase), p)),
        )
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .gap(px(8.))
                .pt(px(6.))
                .border_t_1()
                .border_color(rgb(p.card_border))
                .child(div().flex_1().min_w(px(0.)).child(ver_line))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .flex_shrink_0()
                        .gap(px(6.))
                        .when(spec.has_plugins_btn, |row| {
                            row.child(
                                div()
                                    .id("upd-open-plugins-modal")
                                    .flex()
                                    .items_center()
                                    .gap(px(4.5))
                                    .h(px(24.))
                                    .px(px(9.))
                                    .rounded(px(7.))
                                    .bg(rgb(p.secondary_btn_bg))
                                    .border_1()
                                    .border_color(rgb(p.line_strong))
                                    .cursor_pointer()
                                    .hover(move |s| s.bg(rgb(hover_bg)))
                                    .text_size(px(11.))
                                    .font_weight(FontWeight::MEDIUM)
                                    .text_color(rgb(p.text_primary))
                                    .child(ui_icon("icons/ui/puzzle.svg", 11.0, p.text_primary))
                                    .child("插件推荐")
                                    .when(plugin_updates_count > 0, |btn| {
                                        btn.child(
                                            div()
                                                .w(px(5.5))
                                                .h(px(5.5))
                                                .rounded(px(999.))
                                                .bg(rgb(p.badge_warn.dot)),
                                        )
                                    })
                                    .on_mouse_up(
                                        MouseButton::Left,
                                        cx.listener(move |_, _, _, cx| {
                                            cx.stop_propagation();
                                            ctrl_plug.update(cx, |c, cx| {
                                                c.show_plugins_modal = true;
                                                cx.notify();
                                            });
                                        }),
                                    ),
                            )
                        })
                        .when_some(spec.repo_url, |row, url| {
                            row.child(
                                icon_action_button(
                                    gpui::ElementId::Name(format!("upd-repo-{}", item.id).into()),
                                    "icons/ui/ext.svg",
                                    "仓库",
                                    ButtonKind::Secondary,
                                    true,
                                    p,
                                )
                                .h(px(24.))
                                .px(px(8.))
                                .text_size(px(11.))
                                .on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        let res = open_external_url(url);
                                        ctrl_repo.update(cx, |c, cx| match res {
                                            Ok(()) => c.set_toast(
                                                "已在浏览器中打开 Silas-02/antigravity-desktop-cn",
                                                true,
                                                cx,
                                            ),
                                            Err(err) => c.set_toast(err, false, cx),
                                        });
                                    }),
                                ),
                            )
                        })
                        .child(
                            icon_action_button(
                                gpui::ElementId::Name(format!("upd-check-{}", item.id).into()),
                                "icons/ui/refresh.svg",
                                "检查",
                                ButtonKind::Secondary,
                                can_check,
                                p,
                            )
                            .h(px(24.))
                            .px(px(8.))
                            .text_size(px(11.))
                            .when(can_check, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        let id = comp_id.clone();
                                        ctrl_chk.update(cx, |c, cx| {
                                            c.send_request(
                                                PipeRequest::CheckUpdates {
                                                    component: Some(id),
                                                },
                                                Some(toast_msg),
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

pub fn render_updates_page(
    ctrl: Entity<AppController>,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> Div {
    let ctrl_r = ctrl.read(cx);
    let snap = ctrl_r.snapshot.clone();
    let connected = ctrl_r.connected;
    let busy = ctrl_r.busy_action;
    let cfg = snap.as_ref().map(|s| s.config.clone()).unwrap_or_default();
    let ver = snap
        .as_ref()
        .map(|s| s.version.clone())
        .unwrap_or_else(|| "4.0.0".into());
    let tripped = snap.as_ref().is_some_and(|s| s.is_tripped());
    let updates = snap.as_ref().map(|s| s.updates.clone()).unwrap_or_default();
    let ag_proxy = snap
        .as_ref()
        .map(|s| s.antigravity_proxy.clone())
        .unwrap_or_default();
    let now = now_unix_secs();
    let can_check = connected && !busy && !tripped;

    let cg = &updates.claudeguard;
    let cg_cur = fmt_ver(cg.installed_version.as_deref().or(Some(&ver)), false, "v4.0.0");
    let cg_age = format_relative_secs(cg.checked_at, now);

    let ag = &updates.antigravity_proxy;
    let ag_has_up = ag.phase == UpdateCheckPhase::UpdateAvailable;
    let ag_local = if !ag_proxy.installed {
        "未安装".into()
    } else {
        fmt_ver(
            ag.installed_version
                .as_deref()
                .or(ag_proxy.injector_version.as_deref()),
            false,
            "未注入",
        )
    };
    let ag_latest = fmt_ver(ag.latest_version.as_deref(), false, "待检查");

    let ctrl_auto = ctrl.clone();
    let ctrl_check_all = ctrl.clone();
    let ctrl_ag_chk = ctrl.clone();
    let ctrl_ag_fix = ctrl.clone();

    let plugin_ups = count_plugin_updates(&updates);
    let grid_items = [
        GridCardSpec {
            item: &updates.claude_desktop,
            icon_key: "claude",
            title: "Claude Desktop",
            subtitle: "Anthropic 官方桌面端",
            source: "官方桌面发布源",
            is_repo_track: false,
            repo_url: None,
            has_plugins_btn: false,
        },
        GridCardSpec {
            item: &updates.claude_code,
            icon_key: "claude-code",
            title: "Claude Code CLI",
            subtitle: "@anthropic-ai/claude-code",
            source: "npm 官方源",
            is_repo_track: false,
            repo_url: None,
            has_plugins_btn: false,
        },
        GridCardSpec {
            item: &updates.codex_desktop,
            icon_key: "chatgpt",
            title: "ChatGPT / Codex 桌面端",
            subtitle: "OpenAI 官方桌面端",
            source: "官方桌面发布源",
            is_repo_track: false,
            repo_url: None,
            has_plugins_btn: false,
        },
        GridCardSpec {
            item: &updates.codex_cli,
            icon_key: "codex-cli",
            title: "Codex CLI",
            subtitle: "@openai/codex",
            source: "npm 官方源",
            is_repo_track: false,
            repo_url: None,
            has_plugins_btn: false,
        },
        GridCardSpec {
            item: &updates.antigravity_ide,
            icon_key: "antigravity",
            title: "Antigravity IDE",
            subtitle: "Google Antigravity 桌面客户端",
            source: "官方更新渠道",
            is_repo_track: false,
            repo_url: None,
            has_plugins_btn: true,
        },
        GridCardSpec {
            item: &updates.antigravity_cn,
            icon_key: "antigravity_cn",
            title: "Antigravity 中文汉化引擎",
            subtitle: "Silas-02/antigravity-desktop-cn",
            source: "GitHub 仓库",
            is_repo_track: true,
            repo_url: Some("https://github.com/Silas-02/antigravity-desktop-cn"),
            has_plugins_btn: false,
        },
    ];
    let avail_grid = grid_items
        .iter()
        .filter(|g| g.item.phase == UpdateCheckPhase::UpdateAvailable)
        .count();

    let mut cards: Vec<Div> = grid_items
        .into_iter()
        .map(|spec| render_grid_card(ctrl.clone(), spec, plugin_ups, can_check, p, cx))
        .collect();
    let row1 = div().flex().flex_row().w_full().gap(px(10.)).children(cards.drain(0..2));
    let row2 = div().flex().flex_row().w_full().gap(px(10.)).children(cards.drain(0..2));
    let row3 = div().flex().flex_row().w_full().gap(px(10.)).children(cards);

    div()
        .flex()
        .flex_col()
        .w_full()
        .flex_1()
        .min_w(px(0.))
        .gap(px(10.))
        // Band 1: ClaudeGuard Self + Auto Check + Global Recheck (10)
        .child(
            bento_card(p)
                .w_full()
                .flex_row()
                .items_center()
                .justify_between()
                .px(px(16.))
                .py(px(12.))
                .gap(px(12.))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(11.))
                        .min_w(px(0.))
                        .flex_1()
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .justify_center()
                                .w(px(30.))
                                .h(px(30.))
                                .rounded(px(9.))
                                .bg(rgb(p.primary_btn_bg))
                                .flex_shrink_0()
                                .child(ui_icon("icons/ui/shield.svg", 16.0, p.primary_btn_text)),
                        )
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .min_w(px(0.))
                                .gap(px(2.))
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
                                                .child("ClaudeGuard 守护端"),
                                        )
                                        .child(
                                            mono_tabular(cg_cur)
                                                .text_size(px(11.5))
                                                .text_color(rgb(p.text_secondary)),
                                        )
                                        .child(tone_tag(
                                            cg.phase.label(),
                                            update_phase_tone(cg.phase),
                                            p,
                                        )),
                                )
                                .child(
                                    mono_tabular(format!(
                                        "仓库 daha1216/ClaudeGuard · 最近巡检：{cg_age} · 全量仅经代理只读查询"
                                    ))
                                    .truncate()
                                    .text_size(px(11.))
                                    .text_color(rgb(p.text_muted)),
                                ),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .flex_shrink_0()
                        .gap(px(12.))
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap(px(7.))
                                .child(
                                    div()
                                        .text_size(px(11.5))
                                        .text_color(rgb(p.text_secondary))
                                        .child("每 6h 静默巡检"),
                                )
                                .child(
                                    toggle_switch(
                                        "upd-auto-check-sw",
                                        cfg.auto_upd_check,
                                        connected && !busy,
                                        p,
                                    )
                                    .when(connected && !busy, |sw| {
                                        sw.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                let next = !cfg.auto_upd_check;
                                                ctrl_auto.update(cx, |c, cx| {
                                                    c.save_config_patch(
                                                        move |x| x.auto_upd_check = next,
                                                        if next {
                                                            "已开启每 6 小时静默更新巡检"
                                                        } else {
                                                            "已关闭自动静默巡检"
                                                        },
                                                        cx,
                                                    );
                                                });
                                            }),
                                        )
                                    }),
                                ),
                        )
                        .child(
                            icon_action_button(
                                "upd-check-all-btn",
                                "icons/ui/refresh.svg",
                                if tripped {
                                    "隔离期间禁止检查"
                                } else {
                                    "立即巡检全部 (10)"
                                },
                                ButtonKind::Primary,
                                can_check,
                                p,
                            )
                            .h(px(29.))
                            .px(px(12.))
                            .when(can_check, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_check_all.update(cx, |c, cx| {
                                            c.send_request(
                                                PipeRequest::CheckUpdates { component: None },
                                                Some("已完成全部 10 项客户端、注入器与插件版本巡检"),
                                                cx,
                                            );
                                        });
                                    }),
                                )
                            }),
                        ),
                ),
        )
        // Band 2: antigravity-proxy Featured Injector Module
        .child(
            bento_card(p)
                .w_full()
                .flex_row()
                .items_center()
                .justify_between()
                .px(px(16.))
                .py(px(12.))
                .gap(px(14.))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(11.))
                        .min_w(px(0.))
                        .flex_1()
                        .child(brand_icon("antigravity", 30.0, 8.0, p.is_dark))
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .min_w(px(0.))
                                .flex_1()
                                .gap(px(2.5))
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
                                                .child("antigravity-proxy 透明代理注入器"),
                                        )
                                        .child(
                                            mono_tabular("yuaotian/antigravity-proxy")
                                                .text_size(px(11.))
                                                .text_color(rgb(p.text_muted)),
                                        )
                                        .child(tone_tag(
                                            if ag_has_up {
                                                format!("发现新版 {ag_latest}")
                                            } else {
                                                ag.phase.label().to_string()
                                            },
                                            update_phase_tone(ag.phase),
                                            p,
                                        )),
                                )
                                .child(
                                    div()
                                        .truncate()
                                        .text_size(px(11.5))
                                        .text_color(rgb(p.text_secondary))
                                        .child("专为 Antigravity 打造的免 TUN 强制代理工具，支持 DLL 注入与进程流量劫持。"),
                                ),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .flex_shrink_0()
                        .gap(px(10.))
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .items_end()
                                .gap(px(1.))
                                .child(
                                    div()
                                        .text_size(px(10.))
                                        .text_color(rgb(p.text_muted))
                                        .child("本地注入 → 仓库最新"),
                                )
                                .child(
                                    div()
                                        .flex()
                                        .items_center()
                                        .gap(px(4.))
                                        .child(
                                            mono_tabular(format!("{ag_local} →"))
                                                .text_size(px(12.))
                                                .font_weight(FontWeight::SEMIBOLD)
                                                .text_color(rgb(p.text_primary)),
                                        )
                                        .child(
                                            mono_tabular(ag_latest)
                                                .text_size(px(12.))
                                                .font_weight(FontWeight::SEMIBOLD)
                                                .text_color(rgb(if ag_has_up {
                                                    p.badge_warn.text
                                                } else {
                                                    p.badge_pass.text
                                                })),
                                        ),
                                ),
                        )
                        .child(
                            action_button(
                                "upd-ag-check",
                                "检测",
                                ButtonKind::Secondary,
                                can_check,
                                p,
                            )
                            .h(px(28.))
                            .px(px(10.))
                            .when(can_check, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_ag_chk.update(cx, |c, cx| {
                                            c.send_request(
                                                PipeRequest::CheckUpdates {
                                                    component: Some("antigravity_proxy".into()),
                                                },
                                                Some("已完成 antigravity-proxy 仓库版本核验"),
                                                cx,
                                            );
                                        });
                                    }),
                                )
                            }),
                        )
                        .child(
                            action_button(
                                "upd-ag-repair-jump",
                                "去热修复 →",
                                ButtonKind::Primary,
                                true,
                                p,
                            )
                            .h(px(28.))
                            .px(px(10.))
                            .on_mouse_up(
                                MouseButton::Left,
                                cx.listener(move |_, _, _, cx| {
                                    ctrl_ag_fix.update(cx, |c, cx| {
                                        c.env_tab = EnvSubTab::Antigravity;
                                        c.set_nav(NavSection::Environment, cx);
                                    });
                                }),
                            ),
                        ),
                ),
        )
        // Band 3: 2x3 Symmetrical Grid
        .child(
            div()
                .flex()
                .flex_col()
                .w_full()
                .flex_1()
                .gap(px(9.))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .px(px(3.))
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
                                        .child("受管 AI 客户端与生态组件版本追踪"),
                                )
                                .child(
                                    div()
                                        .text_size(px(11.))
                                        .text_color(rgb(p.text_muted))
                                        .child("绝不后台自动覆盖客户端 · 隔离期暂停检查"),
                                ),
                        )
                        .child(
                            mono_tabular(if avail_grid > 0 {
                                format!("追踪 6 项 · {avail_grid} 项有更新")
                            } else {
                                "追踪 6 项 · 均已对齐最新".into()
                            })
                            .text_size(px(11.))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(rgb(if avail_grid > 0 {
                                p.badge_warn.text
                            } else {
                                p.badge_pass.text
                            })),
                        ),
                )
                .child(row1)
                .child(row2)
                .child(row3),
        )
}
