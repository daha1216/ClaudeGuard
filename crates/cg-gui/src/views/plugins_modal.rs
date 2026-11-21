//! Centered Frost Ceramic modal — `Antigravity 精选插件与更新检测`.
//!
//! Tracks all 4 curated Antigravity ecosystem open-source projects with live local vs upstream
//! version comparison, per-item & batch update check via managed proxy, and direct GitHub links.

use crate::app::{AppController, ConsoleWindowView, PluginCategory};
use crate::assets::{brand_icon, ui_icon};
use crate::demo::now_unix_secs;
use crate::ipc::open_external_url;
use crate::protocol::{ComponentUpdateStatus, PipeRequest, UpdateCheckPhase};
use crate::state::format_relative_secs;
use crate::theme::{BadgeTone, ThemePalette};
use crate::widgets::controls::{
    ButtonKind, action_button, icon_action_button, mono_tabular, tone_tag,
};
use gpui::{BoxShadow, Context, Div, Entity, FontWeight, MouseButton, div, prelude::*, px, rgb, rgba};

struct PluginSpec {
    id: &'static str,
    comp_key: &'static str,
    cat: PluginCategory,
    name: &'static str,
    repo: &'static str,
    url: &'static str,
    badge: &'static str,
    is_repo_track: bool,
    desc: &'static str,
}

const PLUGINS: [PluginSpec; 4] = [
    PluginSpec {
        id: "usage-monitor",
        comp_key: "ag_usage_monitor",
        cat: PluginCategory::Monitor,
        name: "antigravity-usage-monitor",
        repo: "yuhuan-dev/antigravity-usage-monitor",
        url: "https://github.com/yuhuan-dev/antigravity-usage-monitor",
        badge: "用量与上下文",
        is_repo_track: false,
        desc: "实时监控生成速度（TPS / 首字延迟）、上下文窗口各模块占用明细、子代理消耗以及模型配额重置倒计时。",
    },
    PluginSpec {
        id: "agy-capsule",
        comp_key: "ag_capsule",
        cat: PluginCategory::Monitor,
        name: "agy-capsule",
        repo: "Lumidarin/agy-capsule",
        url: "https://github.com/Lumidarin/agy-capsule",
        badge: "底部胶囊栏",
        is_repo_track: false,
        desc: "在 Antigravity 底部嵌入轻量胶囊状态栏，一眼查看上下文进度、输入/输出/缓存 Token 明细与模型剩余额度。",
    },
    PluginSpec {
        id: "desktop-cn",
        comp_key: "antigravity_cn",
        cat: PluginCategory::Localization,
        name: "antigravity-desktop-cn",
        repo: "Silas-02/antigravity-desktop-cn",
        url: "https://github.com/Silas-02/antigravity-desktop-cn",
        badge: "中文汉化",
        is_repo_track: true,
        desc: "Antigravity 桌面版动态中文汉化引擎，支持一键应用并智能跳过对话正文与代码块，随时可无损还原英文原版。",
    },
    PluginSpec {
        id: "ag-proxy",
        comp_key: "antigravity_proxy",
        cat: PluginCategory::Proxy,
        name: "antigravity-proxy",
        repo: "yuaotian/antigravity-proxy",
        url: "https://github.com/yuaotian/antigravity-proxy",
        badge: "免 TUN 代理",
        is_repo_track: false,
        desc: "专为 Antigravity 打造的免 TUN 强制代理工具，支持 DLL 注入与后台子进程流量接管；ClaudeGuard 已内置状态核验与一键热修复。",
    },
];

fn slot_for<'a>(
    updates: &'a crate::protocol::UpdateSummary,
    comp_key: &str,
) -> &'a ComponentUpdateStatus {
    match comp_key {
        "ag_usage_monitor" => &updates.ag_usage_monitor,
        "ag_capsule" => &updates.ag_capsule,
        "antigravity_cn" => &updates.antigravity_cn,
        _ => &updates.antigravity_proxy,
    }
}

fn fmt_ver(raw: Option<&str>, is_repo_track: bool, fallback: &str) -> String {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => fallback.to_string(),
        Some(v) if is_repo_track => v.trim_start_matches(['v', 'V']).to_string(),
        Some(v) => format!("v{}", v.trim_start_matches(['v', 'V'])),
    }
}

/// Counts how many of the 4 curated Antigravity plugins/tools have updates available.
pub fn count_plugin_updates(updates: &crate::protocol::UpdateSummary) -> usize {
    PLUGINS
        .iter()
        .filter(|spec| slot_for(updates, spec.comp_key).phase == UpdateCheckPhase::UpdateAvailable)
        .count()
}

pub fn render_plugins_modal(
    ctrl: Entity<AppController>,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> gpui::Stateful<Div> {
    let ctrl_r = ctrl.read(cx);
    let snap = ctrl_r.snapshot.clone();
    let connected = ctrl_r.connected;
    let busy = ctrl_r.busy_action;
    let active_cat = ctrl_r.plugin_category;
    let tripped = snap.as_ref().is_some_and(|s| s.is_tripped());
    let updates = snap.as_ref().map(|s| s.updates.clone()).unwrap_or_default();
    let now = now_unix_secs();
    let can_check = connected && !busy && !tripped;
    let total_up = count_plugin_updates(&updates);

    let cats = [
        (PluginCategory::All, "全部"),
        (PluginCategory::Monitor, "用量监控"),
        (PluginCategory::Localization, "汉化增强"),
        (PluginCategory::Proxy, "网络代理"),
    ];

    let cat_chips = cats.into_iter().map(|(cat, label)| {
        let is_on = cat == active_cat;
        let ctrl_c = ctrl.clone();
        div()
            .id(gpui::ElementId::Name(format!("plugin-cat-{cat:?}").into()))
            .flex()
            .items_center()
            .justify_center()
            .h(px(25.))
            .px(px(10.))
            .rounded(px(7.))
            .cursor_pointer()
            .bg(rgb(if is_on {
                p.sidebar_active_bg
            } else {
                p.inset_bg
            }))
            .text_size(px(11.5))
            .font_weight(if is_on {
                FontWeight::SEMIBOLD
            } else {
                FontWeight::MEDIUM
            })
            .text_color(rgb(if is_on {
                p.sidebar_active_text
            } else {
                p.text_secondary
            }))
            .child(label)
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(move |_, _, _, cx| {
                    ctrl_c.update(cx, |c, cx| {
                        c.plugin_category = cat;
                        cx.notify();
                    });
                }),
            )
    });

    let rows: Vec<Div> = PLUGINS
        .iter()
        .filter(|spec| active_cat == PluginCategory::All || spec.cat == active_cat)
        .map(|spec| {
            let slot = slot_for(&updates, spec.comp_key);
            let has_up = slot.phase == UpdateCheckPhase::UpdateAvailable;
            let cur_str = fmt_ver(
                slot.installed_version.as_deref(),
                spec.is_repo_track,
                if spec.is_repo_track { "未检测" } else { "未安装" },
            );
            let lat_str = fmt_ver(slot.latest_version.as_deref(), spec.is_repo_track, "待检查");
            let age_str = format_relative_secs(slot.checked_at, now);

            let (pill_label, pill_tone) = match slot.phase {
                UpdateCheckPhase::UpdateAvailable => (
                    if spec.is_repo_track {
                        "仓库有更新".to_string()
                    } else {
                        format!("发现新版 {lat_str}")
                    },
                    BadgeTone::Warn,
                ),
                UpdateCheckPhase::UpToDate => ("已是最新".to_string(), BadgeTone::Pass),
                UpdateCheckPhase::Failed => ("检测失败".to_string(), BadgeTone::Fail),
                UpdateCheckPhase::NotInstalled => ("未安装".to_string(), BadgeTone::Muted),
                _ => ("待检测".to_string(), BadgeTone::Muted),
            };

            let ver_line = if has_up {
                if spec.is_repo_track {
                    format!("本地 {cur_str} → 上游 {lat_str}")
                } else {
                    format!("本机 {cur_str} → 最新 {lat_str}")
                }
            } else if slot.installed_version.is_some() {
                format!("本机 {cur_str} · 已对齐最新")
            } else if slot.latest_version.is_some() {
                format!("本机未安装 · 上游 {lat_str}")
            } else {
                "点击右侧「检查」经代理获取上游版本".to_string()
            };

            let ctrl_chk = ctrl.clone();
            let ctrl_open = ctrl.clone();
            let comp_key = spec.comp_key.to_string();
            let name_chk = spec.name;
            let url = slot
                .release_url
                .as_deref()
                .filter(|u| u.starts_with("https://"))
                .unwrap_or(spec.url)
                .to_string();
            let repo_lbl = spec.repo;

            div()
                .flex()
                .flex_col()
                .w_full()
                .min_w(px(0.))
                .gap(px(5.))
                .px(px(14.))
                .py(px(10.5))
                .rounded(px(12.))
                .bg(rgb(p.inset_bg))
                .border_1()
                .border_color(rgb(p.inset_border))
                // Row 1: Name + badges (left) | Check + GitHub buttons (right)
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .w_full()
                        .min_w(px(0.))
                        .gap(px(10.))
                        .child(
                            div()
                                .flex()
                                .flex_wrap()
                                .items_center()
                                .min_w(px(0.))
                                .flex_1()
                                .gap(px(6.))
                                .child(
                                    mono_tabular(spec.name)
                                        .text_size(px(12.5))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(p.text_primary)),
                                )
                                .child(
                                    div()
                                        .px(px(6.5))
                                        .py(px(1.5))
                                        .rounded(px(999.))
                                        .bg(rgb(p.card_bg))
                                        .border_1()
                                        .border_color(rgb(p.card_border))
                                        .text_size(px(10.))
                                        .font_weight(FontWeight::MEDIUM)
                                        .text_color(rgb(p.text_secondary))
                                        .child(spec.badge),
                                )
                                .child(tone_tag(pill_label, pill_tone, p)),
                        )
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap(px(6.))
                                .flex_shrink_0()
                                .child(
                                    icon_action_button(
                                        gpui::ElementId::Name(
                                            format!("plugin-chk-{}", spec.id).into(),
                                        ),
                                        "icons/ui/refresh.svg",
                                        "检查",
                                        ButtonKind::Secondary,
                                        can_check,
                                        p,
                                    )
                                    .h(px(26.))
                                    .px(px(9.))
                                    .when(can_check, |b| {
                                        b.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                let key = comp_key.clone();
                                                let done_msg =
                                                    format!("已完成 {name_chk} 上游版本检测");
                                                ctrl_chk.update(cx, |c, cx| {
                                                    c.send_request(
                                                        PipeRequest::CheckUpdates {
                                                            component: Some(key),
                                                        },
                                                        None,
                                                        cx,
                                                    );
                                                    c.set_toast(done_msg, true, cx);
                                                });
                                            }),
                                        )
                                    }),
                                )
                                .child(
                                    icon_action_button(
                                        gpui::ElementId::Name(
                                            format!("plugin-gh-{}", spec.id).into(),
                                        ),
                                        "icons/ui/ext.svg",
                                        "GitHub",
                                        ButtonKind::Secondary,
                                        true,
                                        p,
                                    )
                                    .h(px(26.))
                                    .px(px(9.))
                                    .on_mouse_up(
                                        MouseButton::Left,
                                        cx.listener(move |_, _, _, cx| {
                                            match open_external_url(&url) {
                                                Ok(()) => ctrl_open.update(cx, |c, cx| {
                                                    c.set_toast(
                                                        format!("已打开 {repo_lbl}"),
                                                        true,
                                                        cx,
                                                    );
                                                }),
                                                Err(err) => ctrl_open.update(cx, |c, cx| {
                                                    c.set_toast(err, false, cx);
                                                }),
                                            }
                                        }),
                                    ),
                                ),
                        ),
                )
                // Row 2: Full-width version comparison + repository + relative check time
                .child(
                    mono_tabular(format!("{ver_line} · {repo_lbl} · {age_str}"))
                        .w_full()
                        .text_size(px(10.5))
                        .text_color(rgb(if has_up {
                            p.badge_warn.text
                        } else {
                            p.text_muted
                        })),
                )
                // Row 3: Full-width description
                .child(
                    div()
                        .w_full()
                        .text_size(px(11.5))
                        .line_height(px(16.))
                        .text_color(rgb(p.text_secondary))
                        .child(spec.desc),
                )
        })
        .collect();

    let ctrl_backdrop = ctrl.clone();
    let ctrl_x = ctrl.clone();
    let ctrl_close = ctrl.clone();
    let ctrl_all = ctrl.clone();

    div()
        .id("plugins-modal-backdrop")
        .absolute()
        .inset_0()
        .bg(rgba(p.scrim_rgba))
        .flex()
        .items_center()
        .justify_center()
        .p(px(20.))
        .on_mouse_up(
            MouseButton::Left,
            cx.listener(move |_, _, _, cx| {
                ctrl_backdrop.update(cx, |c, cx| {
                    c.show_plugins_modal = false;
                    cx.notify();
                });
            }),
        )
        .child(
            div()
                .id("plugins-modal-sheet")
                .flex()
                .flex_col()
                .w(px(756.))
                .max_w_full()
                .max_h(px(620.))
                .p(px(18.))
                .gap(px(11.))
                .rounded(px(20.))
                .bg(rgb(p.card_bg))
                .border_1()
                .border_color(rgb(p.line_strong))
                .shadow(vec![
                    BoxShadow::new(px(0.), px(20.), rgba(0x00000038).into()).blur_radius(px(48.)),
                ])
                .on_mouse_up(MouseButton::Left, |_, _, cx| {
                    cx.stop_propagation();
                })
                // Header
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap(px(10.))
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap(px(10.))
                                .child(brand_icon("antigravity", 28.0, 7.5, p.is_dark))
                                .child(
                                    div()
                                        .flex()
                                        .flex_col()
                                        .gap(px(1.))
                                        .child(
                                            div()
                                                .text_size(px(14.5))
                                                .font_weight(FontWeight::BOLD)
                                                .text_color(rgb(p.text_primary))
                                                .child("Antigravity 精选插件与更新检测"),
                                        )
                                        .child(
                                            div()
                                                .text_size(px(11.))
                                                .text_color(rgb(p.text_muted))
                                                .child("自动识别本机已装插件版本并经受管代理只读检测上游更新"),
                                        ),
                                ),
                        )
                        .child(
                            div()
                                .id("plugins-modal-x")
                                .w(px(28.))
                                .h(px(28.))
                                .rounded(px(999.))
                                .bg(rgb(p.inset_bg))
                                .border_1()
                                .border_color(rgb(p.card_border))
                                .flex()
                                .items_center()
                                .justify_center()
                                .cursor_pointer()
                                .child(ui_icon("icons/ui/close.svg", 13.0, p.text_secondary))
                                .on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_x.update(cx, |c, cx| {
                                            c.show_plugins_modal = false;
                                            cx.notify();
                                        });
                                    }),
                                ),
                        ),
                )
                // Toolbar: Category filter + Check All Plugins
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
                                .gap(px(2.))
                                .p(px(2.))
                                .rounded(px(8.))
                                .bg(rgb(p.inset_bg))
                                .border_1()
                                .border_color(rgb(p.card_border))
                                .children(cat_chips),
                        )
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap(px(8.))
                                .child(
                                    mono_tabular(if total_up > 0 {
                                        format!("{total_up} 项有更新")
                                    } else {
                                        "全部已是最新".into()
                                    })
                                    .text_size(px(11.))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .text_color(rgb(if total_up > 0 {
                                        p.badge_warn.text
                                    } else {
                                        p.badge_pass.text
                                    })),
                                )
                                .child(
                                    icon_action_button(
                                        "plugins-check-all",
                                        "icons/ui/refresh.svg",
                                        if tripped {
                                            "隔离期暂停"
                                        } else {
                                            "全部检查更新"
                                        },
                                        ButtonKind::Primary,
                                        can_check,
                                        p,
                                    )
                                    .h(px(27.))
                                    .px(px(10.))
                                    .when(can_check, |b| {
                                        b.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                ctrl_all.update(cx, |c, cx| {
                                                    c.send_request(
                                                        PipeRequest::CheckUpdates {
                                                            component: Some(
                                                                "antigravity_plugins".into(),
                                                            ),
                                                        },
                                                        Some("已完成全部 4 项插件与工具版本检测"),
                                                        cx,
                                                    );
                                                });
                                            }),
                                        )
                                    }),
                                ),
                        ),
                )
                // Plugin List
                .child(
                    div()
                        .id("plugins-modal-scroll")
                        .flex()
                        .flex_col()
                        .flex_1()
                        .min_h(px(0.))
                        .overflow_y_scroll()
                        .gap(px(8.))
                        .children(rows),
                )
                // Footer
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap(px(10.))
                        .pt(px(9.))
                        .border_t_1()
                        .border_color(rgb(p.card_border))
                        .child(
                            div()
                                .text_size(px(11.))
                                .text_color(rgb(p.text_muted))
                                .child("所有更新检测均只读查询 GitHub 上游，绝不自动覆写插件；点击 GitHub 可前往获取新版。"),
                        )
                        .child(
                            action_button("plugins-modal-close", "关闭", ButtonKind::Primary, true, p)
                                .h(px(28.))
                                .px(px(14.))
                                .on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_close.update(cx, |c, cx| {
                                            c.show_plugins_modal = false;
                                            cx.notify();
                                        });
                                    }),
                                ),
                        ),
                ),
        )
}
