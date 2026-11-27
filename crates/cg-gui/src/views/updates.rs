//! Mode B — Frost Ceramic `客户端更新` view.
//!
//! Tracks all 10 components (strictly read-only through managed proxy):
//! - Band 1: `ClaudeGuard 守护端` + 6h auto-check switch + `全部巡检 (10)`
//! - Band 2: `antigravity-proxy 代理注入器` + `检测` + `热修复 →`
//! - Band 3: Symmetrical 2×3 grid (`Claude Desktop`, `Claude Code CLI`, `ChatGPT / Codex 桌面端`,
//!   `Codex CLI`, `Antigravity IDE` [with `插件推荐` button opening the 4-plugin update modal],
//!   `Antigravity 中文汉化引擎` [Silas-02/antigravity-desktop-cn]).

use crate::app::{ActionScope, AppController, ConsoleWindowView, EnvSubTab};
use crate::assets::{brand_icon_scaled, brand_mark, ui_icon};
use crate::demo::now_unix_secs;
use crate::motion::{PageChoreo, SlotPose};
use crate::protocol::{ComponentUpdateStatus, PipeRequest, UiLabelExt, UpdateCheckPhase};
use crate::state::{NavSection, format_relative_secs};
use crate::theme::{BadgeTone, ThemePalette};
use crate::views::plugins_modal::count_plugin_updates;
use crate::widgets::controls::{
    ButtonKind, action_button, bento_card_bloom, icon_action_button, mono_tabular,
    spinning_action_button, spinning_ui_icon, status_dot, toggle_switch, tone_tag,
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

fn strip_ascii_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    if head.eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

pub(crate) fn concise_update_error(note: &str) -> String {
    let mut s = note.trim();
    loop {
        let prev = s;

        for tag in [
            "当前接入路径受阻，",
            "巡检失败：",
            "巡检失败:",
            "检测失败：",
            "检测失败:",
            "检查失败：",
            "检查失败:",
            "更新失败：",
            "更新失败:",
            "失败：",
            "失败:",
        ] {
            if let Some(rest) = s.strip_prefix(tag) {
                s = rest.trim_start();
            }
        }

        if s.starts_with("检查")
            || s.starts_with("检测")
            || s.starts_with("查询")
            || s.starts_with("获取")
        {
            for marker in [
                "更新失败：",
                "更新失败:",
                "检测失败：",
                "检测失败:",
                "检查失败：",
                "检查失败:",
                "失败：",
                "失败:",
            ] {
                if let Some(after) = s
                    .find(marker)
                    .filter(|&pos| !s[..pos].contains(['：', ':', '，', ',']))
                    .map(|pos| s[pos + marker.len()..].trim_start())
                    .filter(|after| !after.is_empty())
                {
                    s = after;
                    break;
                }
            }
        }

        for prefix in [
            "network error:",
            "i/o error:",
            "io error:",
            "access denied:",
            "invalid input:",
            "error:",
        ] {
            if let Some(rest) = strip_ascii_prefix_ci(s, prefix) {
                s = rest.trim_start();
            }
        }

        if s == prev {
            break;
        }
    }

    if s.is_empty() {
        "请确认本地代理连通后重试".to_string()
    } else {
        s.to_string()
    }
}

fn component_toast(id: &str) -> &'static str {
    match id {
        "claude_desktop" => "已检测 Claude Desktop 版本",
        "claude_code" => "已检测 Claude Code CLI 版本",
        "codex_desktop" => "已检测 ChatGPT / Codex 桌面端版本",
        "codex_cli" => "已检测 Codex CLI 版本",
        "antigravity_ide" => "已检测 Antigravity IDE 版本",
        "antigravity_cn" => "已检测 Antigravity 汉化仓库",
        _ => "已完成版本检测",
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
    is_checking: bool,
}

struct CardMotion {
    pose: SlotPose,
    icon_scale: f32,
}

fn render_grid_card(
    ctrl: Entity<AppController>,
    spec: GridCardSpec<'_>,
    motion: CardMotion,
    plugin_updates_count: usize,
    can_check_base: bool,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> Div {
    let can_check = can_check_base && !spec.is_checking;
    let item = spec.item;
    let has_up = item.phase == UpdateCheckPhase::UpdateAvailable;
    let is_failed = item.phase == UpdateCheckPhase::Failed;
    let phase_label = if spec.is_repo_track && has_up {
        "仓库有更新"
    } else {
        item.phase.label()
    };

    let cur = fmt_ver(
        item.installed_version.as_deref(),
        spec.is_repo_track,
        if spec.is_repo_track {
            "未检测"
        } else {
            "未安装"
        },
    );
    let lat = fmt_ver(item.latest_version.as_deref(), spec.is_repo_track, "待检查");

    let ver_line = if is_failed {
        mono_tabular(concise_update_error(&item.note))
            .truncate()
            .text_size(px(11.5))
            .text_color(rgb(p.badge_fail.text))
    } else if spec.is_repo_track {
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

    let external_url: Option<String> = item
        .release_url
        .as_deref()
        .filter(|u| u.starts_with("https://"))
        .map(ToString::to_string)
        .or_else(|| spec.repo_url.map(ToString::to_string));
    let link_label = if spec.is_repo_track && !has_up {
        "仓库"
    } else if has_up {
        "下载"
    } else {
        "发布页"
    };
    let link_title = spec.title;

    let comp_id = item.id.clone();
    let toast_msg = component_toast(&item.id);
    let ctrl_chk = ctrl.clone();
    let ctrl_plug = ctrl.clone();
    let ctrl_repo = ctrl;

    let hover_bg = p.sidebar_hover_bg;
    let sec_hover_bg = p.sidebar_hover_bg;

    let card = bento_card_bloom(p, 14.0, 11.0, motion.pose)
        .flex_1()
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
                        .child(brand_icon_scaled(
                            spec.icon_key,
                            24.0,
                            6.0,
                            p.is_dark,
                            motion.icon_scale,
                        ))
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
                                    .active(|s| s.opacity(0.86))
                                    .text_size(px(11.))
                                    .font_weight(FontWeight::MEDIUM)
                                    .text_color(rgb(p.text_primary))
                                    .child(ui_icon("icons/ui/puzzle.svg", 11.0, p.text_primary))
                                    .child("插件推荐")
                                    .when(plugin_updates_count > 0, |btn| {
                                        btn.child(status_dot(p.badge_warn.dot, 5.5))
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
                        .when_some(external_url, |row, url| {
                            row.child(
                                icon_action_button(
                                    gpui::ElementId::Name(format!("upd-repo-{}", item.id).into()),
                                    "icons/ui/ext.svg",
                                    link_label,
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
                                        let u = url.clone();
                                        ctrl_repo.update(cx, |c, cx| {
                                            c.open_url_async(u, cx);
                                            c.set_toast(
                                                format!("已在浏览器打开 {link_title}"),
                                                true,
                                                cx,
                                            );
                                        });
                                    }),
                                ),
                            )
                        })
                        .child(
                            div()
                                .id(gpui::ElementId::Name(
                                    format!("upd-check-{}", item.id).into(),
                                ))
                                .flex()
                                .items_center()
                                .justify_center()
                                .gap(px(4.5))
                                .h(px(24.))
                                .px(px(8.))
                                .rounded(px(8.))
                                .bg(rgb(p.secondary_btn_bg))
                                .border_1()
                                .border_color(rgb(p.secondary_btn_border))
                                .text_size(px(11.))
                                .font_weight(FontWeight::MEDIUM)
                                .text_color(rgb(p.secondary_btn_text))
                                .when(can_check, |b| {
                                    b.cursor_pointer()
                                        .hover(move |s| s.bg(rgb(sec_hover_bg)))
                                        .active(|s| s.opacity(0.86))
                                        .on_mouse_up(
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
                                })
                                .when(!can_check, |b| b.opacity(0.45))
                                .child(spinning_ui_icon(
                                    gpui::ElementId::Name(
                                        format!("upd-check-spin-{}", item.id).into(),
                                    ),
                                    "icons/ui/refresh.svg",
                                    11.5,
                                    p.secondary_btn_text,
                                    spec.is_checking,
                                ))
                                .child("检查"),
                        ),
                ),
        );

    div()
        .flex_1()
        .flex_basis(px(0.))
        .min_w(px(0.))
        .flex()
        .child(card)
}

pub fn render_updates_page(
    ctrl: Entity<AppController>,
    choreo: PageChoreo,
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
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").into());
    let tripped = snap.as_ref().is_some_and(|s| s.is_tripped());
    let updates = snap.as_ref().map(|s| s.updates.clone()).unwrap_or_default();
    let ag_proxy = snap
        .as_ref()
        .map(|s| s.antigravity_proxy.clone())
        .unwrap_or_default();
    let now = now_unix_secs();
    let can_check_base = connected && !tripped;
    let checking_all = ctrl_r.is_scope_busy(&ActionScope::UpdatesAll);
    let checking_plugins =
        ctrl_r.is_scope_busy(&ActionScope::UpdatesComponent("antigravity_plugins".into()));
    let checking_ag = checking_all
        || checking_plugins
        || ctrl_r.is_scope_busy(&ActionScope::UpdatesComponent("antigravity_proxy".into()));
    let can_check_all = can_check_base && !checking_all;
    let can_check_ag = can_check_base && !checking_ag;
    let auto_upd_on = ctrl_r.effective_toggle("upd-auto-check-sw", cfg.auto_upd_check);
    let ag_needs_repair =
        cfg.require_antigravity_proxy && ag_proxy.installed && !ag_proxy.is_ready_for_launch();

    let cg = &updates.claudeguard;
    let cg_cur = fmt_ver(
        cg.installed_version.as_deref().or(Some(&ver)),
        false,
        concat!("v", env!("CARGO_PKG_VERSION")),
    );
    let cg_has_up = cg.phase == UpdateCheckPhase::UpdateAvailable;
    let cg_release_url = cg_has_up.then(|| {
        cg.release_url
            .as_deref()
            .filter(|u| u.starts_with("https://"))
            .unwrap_or("https://github.com/daha1216/ClaudeGuard/releases")
            .to_string()
    });
    let cg_age = format_relative_secs(cg.checked_at, now);

    let ag = &updates.antigravity_proxy;
    let ag_has_up = ag.phase == UpdateCheckPhase::UpdateAvailable;
    let ag_release_url = ag_has_up.then(|| {
        ag.release_url
            .as_deref()
            .filter(|u| u.starts_with("https://"))
            .unwrap_or("https://github.com/yuaotian/antigravity-proxy/releases")
            .to_string()
    });
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
    let ctrl_cg_dl = ctrl.clone();
    let ctrl_ag_dl = ctrl.clone();
    let ctrl_ag_chk = ctrl.clone();
    let ctrl_ag_fix = ctrl.clone();

    let plugin_ups = count_plugin_updates(&updates);
    let grid_items = [
        GridCardSpec {
            item: &updates.claude_desktop,
            icon_key: "claude",
            title: "Claude Desktop",
            subtitle: "Anthropic 桌面端",
            source: "官方发布源",
            is_repo_track: false,
            repo_url: Some("https://claude.ai/download"),
            has_plugins_btn: false,
            is_checking: checking_all
                || ctrl_r.is_scope_busy(&ActionScope::UpdatesComponent("claude_desktop".into())),
        },
        GridCardSpec {
            item: &updates.claude_code,
            icon_key: "claude-code",
            title: "Claude Code CLI",
            subtitle: "@anthropic-ai/claude-code",
            source: "npm",
            is_repo_track: false,
            repo_url: Some("https://www.npmjs.com/package/@anthropic-ai/claude-code"),
            has_plugins_btn: false,
            is_checking: checking_all
                || ctrl_r.is_scope_busy(&ActionScope::UpdatesComponent("claude_code".into())),
        },
        GridCardSpec {
            item: &updates.codex_desktop,
            icon_key: "chatgpt",
            title: "ChatGPT / Codex 桌面端",
            subtitle: "OpenAI 桌面端",
            source: "官方发布源",
            is_repo_track: false,
            repo_url: Some("https://openai.com/chatgpt/desktop/"),
            has_plugins_btn: false,
            is_checking: checking_all
                || ctrl_r.is_scope_busy(&ActionScope::UpdatesComponent("codex_desktop".into())),
        },
        GridCardSpec {
            item: &updates.codex_cli,
            icon_key: "codex-cli",
            title: "Codex CLI",
            subtitle: "@openai/codex",
            source: "npm",
            is_repo_track: false,
            repo_url: Some("https://www.npmjs.com/package/@openai/codex"),
            has_plugins_btn: false,
            is_checking: checking_all
                || ctrl_r.is_scope_busy(&ActionScope::UpdatesComponent("codex_cli".into())),
        },
        GridCardSpec {
            item: &updates.antigravity_ide,
            icon_key: "antigravity",
            title: "Antigravity IDE",
            subtitle: "Google 桌面端",
            source: "官方源",
            is_repo_track: false,
            repo_url: Some("https://antigravity.google/download"),
            has_plugins_btn: true,
            is_checking: checking_all
                || ctrl_r.is_scope_busy(&ActionScope::UpdatesComponent("antigravity_ide".into())),
        },
        GridCardSpec {
            item: &updates.antigravity_cn,
            icon_key: "antigravity_cn",
            title: "Antigravity 中文汉化引擎",
            subtitle: "Silas-02/antigravity-desktop-cn",
            source: "GitHub",
            is_repo_track: true,
            repo_url: Some("https://github.com/Silas-02/antigravity-desktop-cn"),
            has_plugins_btn: false,
            is_checking: checking_all
                || checking_plugins
                || ctrl_r.is_scope_busy(&ActionScope::UpdatesComponent("antigravity_cn".into())),
        },
    ];
    let grid_total = grid_items.len();
    let avail_grid = grid_items
        .iter()
        .filter(|g| g.item.phase == UpdateCheckPhase::UpdateAvailable)
        .count();
    let failed_grid = grid_items
        .iter()
        .filter(|g| g.item.phase == UpdateCheckPhase::Failed)
        .count();
    let checked_grid = grid_items
        .iter()
        .filter(|g| {
            !matches!(
                g.item.phase,
                UpdateCheckPhase::Idle | UpdateCheckPhase::Checking
            )
        })
        .count();
    let (grid_summary_text, grid_summary_color, grid_summary_dot) =
        if avail_grid > 0 && failed_grid > 0 {
            (
                format!("{grid_total} 项追踪 · {avail_grid} 项可更新 · {failed_grid} 项失败"),
                p.badge_warn.text,
                Some(p.badge_warn.dot),
            )
        } else if avail_grid > 0 {
            (
                format!("{grid_total} 项追踪 · {avail_grid} 项可更新"),
                p.badge_warn.text,
                Some(p.badge_warn.dot),
            )
        } else if failed_grid > 0 {
            (
                format!("{grid_total} 项追踪 · {failed_grid} 项失败"),
                p.badge_fail.text,
                Some(p.badge_fail.dot),
            )
        } else if checked_grid == 0 {
            (
                format!("{grid_total} 项追踪 · 尚未巡检"),
                p.text_muted,
                None,
            )
        } else {
            (
                format!("{grid_total} 项追踪 · 均已最新"),
                p.text_primary,
                Some(p.badge_pass.dot),
            )
        };

    let mut cards: Vec<Div> = grid_items
        .into_iter()
        .enumerate()
        .map(|(idx, spec)| {
            let row_idx = idx / 2;
            let col_idx = idx % 2;
            render_grid_card(
                ctrl.clone(),
                spec,
                CardMotion {
                    pose: choreo.tile(1 + row_idx.min(3), col_idx),
                    icon_scale: choreo.icon_scale(2 + row_idx.min(2), col_idx),
                },
                plugin_ups,
                can_check_base,
                p,
                cx,
            )
        })
        .collect();
    let mut grid_rows: Vec<Div> = Vec::new();
    while !cards.is_empty() {
        let take_n = cards.len().min(2);
        let pair: Vec<Div> = cards.drain(0..take_n).collect();
        grid_rows.push(div().flex().flex_row().w_full().gap(px(10.)).children(pair));
    }
    let sec_hover = p.sidebar_hover_bg;

    div()
        .flex()
        .flex_col()
        .w_full()
        .flex_1()
        .min_w(px(0.))
        .gap(px(10.))
        // Band 1: ClaudeGuard Self + Auto Check + Global Recheck (10)
        .child(
            div().w_full().min_w(px(0.)).flex().child(
                bento_card_bloom(p, 16.0, 12.0, choreo.tile(0, 0))
                    .flex_1()
                    .flex_row()
                    .items_center()
                    .justify_between()
                    .gap(px(12.))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(11.))
                        .min_w(px(0.))
                        .flex_1()
                        .child(brand_mark(30.0, p.is_dark))
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
                                    mono_tabular(if cg.phase == UpdateCheckPhase::Failed {
                                        format!("巡检失败：{}", concise_update_error(&cg.note))
                                    } else {
                                        format!("daha1216/ClaudeGuard · 上次巡检：{cg_age}")
                                    })
                                    .truncate()
                                    .text_size(px(11.))
                                    .text_color(rgb(if cg.phase == UpdateCheckPhase::Failed {
                                        p.badge_fail.text
                                    } else {
                                        p.text_muted
                                    })),
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
                                .items_center()
                                .gap(px(7.))
                                .child(
                                    div()
                                        .text_size(px(11.5))
                                        .text_color(rgb(p.text_secondary))
                                        .child("每 6h 自动巡检"),
                                )
                                .child(
                                    toggle_switch(
                                        "upd-auto-check-sw",
                                        auto_upd_on,
                                        connected && !busy,
                                        p,
                                    )
                                    .when(connected && !busy, |sw| {
                                        sw.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                let next = !auto_upd_on;
                                                ctrl_auto.update(cx, |c, cx| {
                                                    c.save_toggle_patch(
                                                        "upd-auto-check-sw",
                                                        next,
                                                        move |x| x.auto_upd_check = next,
                                                        if next {
                                                            "已开启每 6h 自动巡检"
                                                        } else {
                                                            "已关闭自动巡检"
                                                        },
                                                        cx,
                                                    );
                                                });
                                            }),
                                        )
                                    }),
                                ),
                        )
                        .when_some(cg_release_url, |row, url| {
                            row.child(
                                icon_action_button(
                                    "upd-cg-download",
                                    "icons/ui/ext.svg",
                                    "下载",
                                    ButtonKind::Secondary,
                                    true,
                                    p,
                                )
                                .h(px(29.))
                                .px(px(10.))
                                .on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        let u = url.clone();
                                        ctrl_cg_dl.update(cx, |c, cx| {
                                            c.open_url_async(u, cx);
                                            c.set_toast(
                                                "已在浏览器打开 ClaudeGuard 发布页",
                                                true,
                                                cx,
                                            );
                                        });
                                    }),
                                ),
                            )
                        })
                        .child(
                            spinning_action_button(
                                "upd-check-all-btn",
                                "icons/ui/refresh.svg",
                                if tripped {
                                    "隔离期暂停"
                                } else if checking_all {
                                    "巡检中…"
                                } else {
                                    "全部巡检 (10)"
                                },
                                ButtonKind::Primary,
                                can_check_all,
                                checking_all,
                                p,
                            )
                            .h(px(29.))
                            .px(px(12.))
                            .when(can_check_all, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_check_all.update(cx, |c, cx| {
                                            c.send_request(
                                                PipeRequest::CheckUpdates { component: None },
                                                Some("已完成全部 10 项版本巡检"),
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
        // Band 2: antigravity-proxy Featured Injector Module
        .child(
            div().w_full().min_w(px(0.)).flex().child(
                bento_card_bloom(p, 16.0, 12.0, choreo.tile(0, 1))
                    .flex_1()
                    .flex_row()
                    .items_center()
                    .justify_between()
                    .gap(px(14.))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(11.))
                        .min_w(px(0.))
                        .flex_1()
                        .child(brand_icon_scaled(
                            "antigravity_proxy",
                            30.0,
                            8.0,
                            p.is_dark,
                            choreo.icon_scale(1, 0),
                        ))
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
                                                .child("antigravity-proxy 代理注入器"),
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
                                        .text_color(rgb(if ag.phase == UpdateCheckPhase::Failed {
                                            p.badge_fail.text
                                        } else {
                                            p.text_secondary
                                        }))
                                        .child(if ag.phase == UpdateCheckPhase::Failed {
                                            format!("检测失败：{}", concise_update_error(&ag.note))
                                        } else {
                                            "Antigravity 免 TUN 代理注入组件，保障进程流量走代理。"
                                                .to_string()
                                        }),
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
                                .flex()
                                .flex_col()
                                .items_end()
                                .gap(px(1.))
                                .child(
                                    div()
                                        .text_size(px(10.))
                                        .text_color(rgb(p.text_muted))
                                        .child("本地 → 最新"),
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
                                                } else if ag.phase == UpdateCheckPhase::UpToDate {
                                                    p.text_primary
                                                } else {
                                                    p.text_muted
                                                })),
                                        ),
                                ),
                        )
                        .when_some(ag_release_url, |row, url| {
                            row.child(
                                icon_action_button(
                                    "upd-ag-release",
                                    "icons/ui/ext.svg",
                                    "发布页",
                                    ButtonKind::Secondary,
                                    true,
                                    p,
                                )
                                .h(px(28.))
                                .px(px(9.))
                                .on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        let u = url.clone();
                                        ctrl_ag_dl.update(cx, |c, cx| {
                                            c.open_url_async(u, cx);
                                            c.set_toast(
                                                "已在浏览器打开 antigravity-proxy 发布页",
                                                true,
                                                cx,
                                            );
                                        });
                                    }),
                                ),
                            )
                        })
                        .child(
                            div()
                                .id("upd-ag-check")
                                .flex()
                                .items_center()
                                .justify_center()
                                .gap(px(5.))
                                .h(px(28.))
                                .px(px(10.))
                                .rounded(px(9.))
                                .bg(rgb(p.secondary_btn_bg))
                                .border_1()
                                .border_color(rgb(p.secondary_btn_border))
                                .text_size(px(12.))
                                .font_weight(FontWeight::MEDIUM)
                                .text_color(rgb(p.secondary_btn_text))
                                .when(can_check_ag, |b| {
                                    b.cursor_pointer()
                                        .hover(move |s| s.bg(rgb(sec_hover)))
                                        .active(|s| s.opacity(0.86))
                                        .on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                ctrl_ag_chk.update(cx, |c, cx| {
                                                    c.send_request(
                                                        PipeRequest::CheckUpdates {
                                                            component: Some(
                                                                "antigravity_proxy".into(),
                                                            ),
                                                        },
                                                        Some("已检测 antigravity-proxy 版本"),
                                                        cx,
                                                    );
                                                });
                                            }),
                                        )
                                })
                                .when(!can_check_ag, |b| b.opacity(0.45))
                                .child(spinning_ui_icon(
                                    "upd-ag-check-spin",
                                    "icons/ui/refresh.svg",
                                    12.0,
                                    p.secondary_btn_text,
                                    checking_ag,
                                ))
                                .child("检测"),
                        )
                        .child(
                            action_button(
                                "upd-ag-repair-jump",
                                "热修复 →",
                                if ag_needs_repair {
                                    ButtonKind::DangerSoft
                                } else {
                                    ButtonKind::Secondary
                                },
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
                .child(choreo.slot(2).apply(
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
                                        .child("客户端与组件版本"),
                                )
                                .child(
                                    div()
                                        .text_size(px(11.))
                                        .text_color(rgb(p.text_muted))
                                        .child("仅只读检测 · 绝不自动覆盖安装"),
                                ),
                        )
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap(px(5.5))
                                .when_some(grid_summary_dot, |row, dot| {
                                    row.child(status_dot(dot, 5.5))
                                })
                                .child(
                                    mono_tabular(grid_summary_text)
                                        .text_size(px(11.))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(grid_summary_color)),
                                ),
                        ),
                ))
                .children(grid_rows),
        )
}

#[cfg(test)]
mod tests {
    use super::concise_update_error;

    #[test]
    fn strips_nested_check_and_network_prefixes() {
        assert_eq!(
            concise_update_error(
                "检查 ClaudeGuard 更新失败: network error: GitHub API 限流，稍后自动重试"
            ),
            "GitHub API 限流，稍后自动重试"
        );
        assert_eq!(
            concise_update_error("失败：检查 antigravity-proxy 更新失败：Network Error: 请求超时"),
            "请求超时"
        );
        assert_eq!(
            concise_update_error(
                "检测失败：检查 antigravity-usage-monitor 更新失败：io error: 连接被重置"
            ),
            "连接被重置"
        );
        assert_eq!(
            concise_update_error("检查 agy-capsule 更新失败：GitHub 返回 HTTP 403"),
            "GitHub 返回 HTTP 403"
        );
        assert_eq!(
            concise_update_error("当前接入路径受阻，已拒绝直连检查更新：本地代理未监听"),
            "已拒绝直连检查更新：本地代理未监听"
        );
        assert_eq!(concise_update_error("   "), "请确认本地代理连通后重试");
    }
}
