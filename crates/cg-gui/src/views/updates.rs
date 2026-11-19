//! Mode B — `客户端更新` view (7-component local + remote official update tracker).

use crate::app::{AppController, ConsoleWindowView};
use crate::demo::now_unix_secs;
use crate::protocol::{ComponentUpdateStatus, PipeRequest, UiLabelExt, UpdateCheckPhase};
use crate::state::format_relative_secs;
use crate::theme::{BadgeTone, ThemePalette};
use crate::views::shared::{ag_diag_tile, switch_row};
use crate::widgets::controls::{
    ButtonKind, action_button, bento_card, inset_box, mono_tabular, status_pill,
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

fn format_ver_label(ver: Option<&str>, fallback: &str) -> String {
    ver.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|v| format!("v{}", v.trim_start_matches(['v', 'V'])))
        .unwrap_or_else(|| fallback.to_string())
}

const ANTIGRAVITY_PROXY_INTRO: &str =
    "专为 Antigravity 打造的免 TUN 强制代理工具，支持 DLL 注入与进程流量劫持。";

fn client_update_toast(component_id: &str) -> &'static str {
    match component_id {
        "claude_desktop" => "已完成 Claude Desktop 官方最新版本检查",
        "claude_code" => "已完成 Claude Code CLI 官方最新版本检查",
        "codex_desktop" => "已完成 ChatGPT / Codex 桌面端官方版本检查",
        "codex_cli" => "已完成 Codex CLI 官方最新版本检查",
        "antigravity_ide" => "已完成 Antigravity IDE 官方最新版本检查",
        _ => "已完成组件版本检查",
    }
}

fn render_client_update_card(
    ctrl: Entity<AppController>,
    item: &ComponentUpdateStatus,
    subtitle: &'static str,
    can_check: bool,
    now: u64,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> Div {
    let comp_id = item.id.clone();
    let toast_msg = client_update_toast(&item.id);
    let installed_str = format_ver_label(item.installed_version.as_deref(), "未检测到");
    let latest_str = format_ver_label(item.latest_version.as_deref(), "待检查");
    let checked_age = format_relative_secs(item.checked_at, now);

    let latest_color = match item.phase {
        UpdateCheckPhase::UpdateAvailable => p.badge_warn.text,
        UpdateCheckPhase::UpToDate => p.badge_pass.text,
        UpdateCheckPhase::Failed => p.badge_fail.text,
        _ => p.text_primary,
    };

    let note_text = if item.note.trim().is_empty() {
        "点击「检查」通过受管代理通道获取官方最新版本".to_string()
    } else {
        item.note.clone()
    };

    let source_label = if item.repo.trim().is_empty() {
        "官方发布渠道"
    } else {
        item.repo.as_str()
    };

    bento_card(p)
        .flex_1()
        .flex_basis(px(0.))
        .min_w(px(0.))
        .p(px(14.))
        .gap(px(9.))
        .child(
            div()
                .flex()
                .flex_wrap()
                .items_center()
                .justify_between()
                .gap(px(6.))
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .flex_1()
                        .min_w(px(0.))
                        .gap(px(2.))
                        .child(
                            div()
                                .text_size(px(13.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.text_primary))
                                .child(item.name.clone()),
                        )
                        .child(
                            div()
                                .text_size(px(10.5))
                                .text_color(rgb(p.text_muted))
                                .child(subtitle),
                        ),
                )
                .child(status_pill(
                    item.phase.label(),
                    update_phase_tone(item.phase),
                    p,
                )),
        )
        .child(
            div()
                .flex()
                .w_full()
                .min_w(px(0.))
                .gap(px(8.))
                .child(
                    inset_box(p)
                        .flex_1()
                        .flex_basis(px(0.))
                        .min_w(px(0.))
                        .px(px(10.))
                        .py(px(7.))
                        .gap(px(2.))
                        .child(
                            div()
                                .text_size(px(10.))
                                .text_color(rgb(p.text_muted))
                                .child("本机已装"),
                        )
                        .child(
                            mono_tabular(installed_str)
                                .truncate()
                                .text_size(px(13.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(if item.installed_version.is_some() {
                                    p.text_primary
                                } else {
                                    p.text_muted
                                })),
                        ),
                )
                .child(
                    inset_box(p)
                        .flex_1()
                        .flex_basis(px(0.))
                        .min_w(px(0.))
                        .px(px(10.))
                        .py(px(7.))
                        .gap(px(2.))
                        .child(
                            div()
                                .text_size(px(10.))
                                .text_color(rgb(p.text_muted))
                                .child("官方最新"),
                        )
                        .child(
                            mono_tabular(latest_str)
                                .truncate()
                                .text_size(px(13.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(latest_color)),
                        ),
                ),
        )
        .child(
            div()
                .w_full()
                .text_size(px(11.5))
                .line_height(px(16.))
                .text_color(rgb(match item.phase {
                    UpdateCheckPhase::UpdateAvailable => p.badge_warn.text,
                    UpdateCheckPhase::Failed => p.badge_fail.text,
                    _ => p.text_secondary,
                }))
                .child(note_text),
        )
        .child(
            div()
                .flex()
                .flex_wrap()
                .items_center()
                .justify_between()
                .gap(px(8.))
                .child(
                    mono_tabular(format!("来源：{source_label} · {checked_age}"))
                        .flex_1()
                        .min_w(px(0.))
                        .truncate()
                        .text_size(px(10.5))
                        .text_color(rgb(p.text_muted)),
                )
                .child(
                    action_button(
                        gpui::ElementId::Name(format!("upd-check-{}", item.id).into()),
                        "↻ 检查",
                        if item.phase == UpdateCheckPhase::UpdateAvailable {
                            ButtonKind::Primary
                        } else {
                            ButtonKind::Secondary
                        },
                        can_check,
                        p,
                    )
                    .when(can_check, |b| {
                        b.on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |_, _, _, cx| {
                                ctrl.update(cx, |c, cx| {
                                    c.send_request(
                                        PipeRequest::CheckUpdates {
                                            component: Some(comp_id.clone()),
                                        },
                                        Some(toast_msg),
                                        cx,
                                    );
                                });
                            }),
                        )
                    }),
                ),
        )
}

/// Sub-view: `客户端更新`
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

    let cg_upd = &updates.claudeguard;
    let cg_cur = format_ver_label(cg_upd.installed_version.as_deref().or(Some(&ver)), "v4.0.0");
    let cg_latest = format_ver_label(cg_upd.latest_version.as_deref(), "待检查");
    let cg_note = if cg_upd.note.trim().is_empty() {
        "已启用官方发布签名校验，仅通过受管代理通道静默检查新版本".to_string()
    } else {
        cg_upd.note.clone()
    };
    let cg_checked_age = format_relative_secs(cg_upd.checked_at, now);
    let cg_repo = if cg_upd.repo.is_empty() {
        "daha1216/ClaudeGuard"
    } else {
        cg_upd.repo.as_str()
    };

    let ag_upd = &updates.antigravity_proxy;
    let ag_repo = if ag_upd.repo.is_empty() {
        "yuaotian/antigravity-proxy"
    } else {
        ag_upd.repo.as_str()
    };
    let ag_local_ver = if !ag_proxy.installed {
        "未安装反重力".into()
    } else {
        format_ver_label(
            ag_upd
                .installed_version
                .as_deref()
                .or(ag_proxy.injector_version.as_deref()),
            "未注入/已丢失",
        )
    };
    let ag_local_sub = if !ag_proxy.installed {
        "本机未检测到 Antigravity 客户端".into()
    } else if !ag_proxy.dll_valid {
        "! version.dll 缺失或签名异常".into()
    } else {
        "version.dll 已注入且特征有效".into()
    };
    let ag_local_color = if !ag_proxy.installed {
        p.text_muted
    } else if !ag_proxy.dll_valid
        || ag_upd.installed_version.is_none() && ag_proxy.injector_version.is_none()
    {
        p.badge_fail.text
    } else {
        p.text_primary
    };
    let ag_latest_ver = format_ver_label(ag_upd.latest_version.as_deref(), "待检查");
    let ag_latest_color = match ag_upd.phase {
        UpdateCheckPhase::UpdateAvailable => p.badge_warn.text,
        UpdateCheckPhase::UpToDate => p.badge_pass.text,
        UpdateCheckPhase::Failed => p.badge_fail.text,
        _ => p.text_primary,
    };
    let ag_latest_sub = ag_upd
        .release_url
        .clone()
        .unwrap_or_else(|| "GitHub Releases 最新版元数据".into());
    let ag_note = if ag_upd.note.trim().is_empty() {
        "点击右侧按钮经代理通道检查 yuaotian/antigravity-proxy 最新版本".to_string()
    } else {
        ag_upd.note.clone()
    };
    let ag_checked_age = format_relative_secs(ag_upd.checked_at, now);

    // Count how many of the 5 tracked AI clients have updates available
    let client_specs: [(&ComponentUpdateStatus, &'static str); 5] = [
        (
            &updates.claude_desktop,
            "Anthropic 官方桌面端（含后台子进程与升级后自动续保）",
        ),
        (
            &updates.claude_code,
            "Anthropic 官方命令行终端（@anthropic-ai/claude-code）",
        ),
        (
            &updates.codex_desktop,
            "OpenAI 官方桌面端（支持升级后自动续保与隔离路径同步）",
        ),
        (
            &updates.codex_cli,
            "OpenAI 官方命令行终端（@openai/codex）",
        ),
        (
            &updates.antigravity_ide,
            "Google Antigravity 桌面客户端（自动核验升级后代理注入状态）",
        ),
    ];
    let avail_clients = client_specs
        .iter()
        .filter(|(s, _)| s.phase == UpdateCheckPhase::UpdateAvailable)
        .count();
    let installed_clients = client_specs
        .iter()
        .filter(|(s, _)| s.installed_version.is_some())
        .count();

    let client_cards: Vec<Div> = client_specs
        .iter()
        .map(|(slot, subtitle)| {
            render_client_update_card(ctrl.clone(), slot, subtitle, can_check, now, p, cx)
        })
        .collect();

    let mut client_rows: Vec<Div> = Vec::new();
    let mut iter = client_cards.into_iter();
    while let Some(first) = iter.next() {
        let mut row = div().flex().w_full().min_w(px(0.)).gap(px(12.)).child(first);
        if let Some(second) = iter.next() {
            row = row.child(second);
        } else {
            row = row.child(div().flex_1().flex_basis(px(0.)).min_w(px(0.)));
        }
        client_rows.push(row);
    }

    let ctrl_auto = ctrl.clone();
    let ctrl_check_all = ctrl.clone();
    let ctrl_check_ag = ctrl;

    div()
        .flex()
        .flex_col()
        .w_full()
        .min_w(px(0.))
        .gap(px(14.))
        // Card 1: ClaudeGuard Self + Global Refresh
        .child(
            bento_card(p)
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
                                .child("ClaudeGuard 守护端与全局版本巡检"),
                        )
                        .child(
                            div()
                                .flex()
                                .flex_wrap()
                                .items_center()
                                .gap(px(8.))
                                .child(
                                    mono_tabular(format!("当前 {cg_cur} / 最新 {cg_latest}"))
                                        .text_size(px(11.5))
                                        .text_color(rgb(p.text_secondary)),
                                )
                                .child(status_pill(
                                    cg_upd.phase.label(),
                                    update_phase_tone(cg_upd.phase),
                                    p,
                                )),
                        ),
                )
                .child(switch_row(
                    "upd-auto",
                    "自动静默检查新版本",
                    "每 6 小时经代理通道静默检查全部 7 项组件版本；触发隔离期间禁止更新",
                    cfg.auto_upd_check,
                    p,
                    cx.listener(move |_, _, _, cx| {
                        if !connected || busy {
                            return;
                        }
                        let next = !cfg.auto_upd_check;
                        ctrl_auto.update(cx, |c, cx| {
                            c.save_config_patch(move |x| x.auto_upd_check = next, "已更新", cx);
                        });
                    }),
                ))
                .child(
                    div()
                        .flex()
                        .flex_wrap()
                        .items_center()
                        .justify_between()
                        .gap(px(10.))
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .flex_1()
                                .min_w(px(240.))
                                .gap(px(2.))
                                .child(
                                    div()
                                        .text_size(px(12.))
                                        .line_height(px(17.))
                                        .text_color(rgb(p.text_secondary))
                                        .child(cg_note),
                                )
                                .child(
                                    mono_tabular(format!(
                                        "仓库：{cg_repo} · 最近巡检：{cg_checked_age}"
                                    ))
                                    .text_size(px(11.))
                                    .text_color(rgb(p.text_muted)),
                                ),
                        )
                        .child(
                            action_button(
                                "upd-check-btn",
                                if tripped {
                                    "隔离期间禁止检查"
                                } else {
                                    "↻ 立即检查全部更新"
                                },
                                ButtonKind::Primary,
                                can_check,
                                p,
                            )
                            .when(can_check, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_check_all.update(cx, |c, cx| {
                                            c.send_request(
                                                PipeRequest::CheckUpdates { component: None },
                                                Some("已完成全部 7 项组件与客户端版本检查"),
                                                cx,
                                            );
                                        });
                                    }),
                                )
                            }),
                        ),
                ),
        )
        // Card 2: antigravity-proxy with user's exact description
        .child(
            bento_card(p)
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
                                .flex()
                                .flex_col()
                                .flex_1()
                                .min_w(px(220.))
                                .gap(px(3.))
                                .child(
                                    div()
                                        .text_size(px(13.5))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(p.text_primary))
                                        .child("antigravity-proxy 透明代理注入器 · yuaotian/antigravity-proxy"),
                                )
                                .child(
                                    div()
                                        .text_size(px(12.))
                                        .line_height(px(17.))
                                        .text_color(rgb(p.text_secondary))
                                        .child(ANTIGRAVITY_PROXY_INTRO),
                                ),
                        )
                        .child(status_pill(
                            ag_upd.phase.label(),
                            update_phase_tone(ag_upd.phase),
                            p,
                        )),
                )
                .child(
                    div()
                        .flex()
                        .w_full()
                        .min_w(px(0.))
                        .gap(px(10.))
                        .child(ag_diag_tile(
                            "本地已注入版本",
                            ag_local_ver,
                            ag_local_sub,
                            ag_local_color,
                            true,
                            p,
                        ))
                        .child(ag_diag_tile(
                            "GitHub 仓库最新版",
                            ag_latest_ver,
                            ag_latest_sub,
                            ag_latest_color,
                            true,
                            p,
                        ))
                        .child(ag_diag_tile(
                            "检测源仓库",
                            ag_repo.to_string(),
                            "通过受管代理通道只读核验 Release".into(),
                            p.text_primary,
                            true,
                            p,
                        )),
                )
                .child(
                    div()
                        .flex()
                        .flex_wrap()
                        .items_center()
                        .justify_between()
                        .gap(px(10.))
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .flex_1()
                                .min_w(px(240.))
                                .gap(px(2.))
                                .child(
                                    div()
                                        .text_size(px(12.))
                                        .line_height(px(17.))
                                        .text_color(rgb(if ag_upd.phase == UpdateCheckPhase::UpdateAvailable {
                                            p.badge_warn.text
                                        } else if ag_upd.phase == UpdateCheckPhase::Failed {
                                            p.badge_fail.text
                                        } else {
                                            p.text_secondary
                                        }))
                                        .child(ag_note),
                                )
                                .child(
                                    mono_tabular(format!("最近检测：{ag_checked_age}"))
                                        .text_size(px(11.))
                                        .text_color(rgb(p.text_muted)),
                                ),
                        )
                        .child(
                            action_button(
                                "upd-check-ag-proxy-btn",
                                "↻ 检测 antigravity-proxy 最新版",
                                if ag_upd.phase == UpdateCheckPhase::UpdateAvailable {
                                    ButtonKind::Primary
                                } else {
                                    ButtonKind::Secondary
                                },
                                can_check,
                                p,
                            )
                            .when(can_check, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_check_ag.update(cx, |c, cx| {
                                            c.send_request(
                                                PipeRequest::CheckUpdates {
                                                    component: Some("antigravity_proxy".into()),
                                                },
                                                Some("已完成 antigravity-proxy 最新版检测"),
                                                cx,
                                            );
                                        });
                                    }),
                                )
                            }),
                        ),
                ),
        )
        // Card 3: 5 Tracked AI Clients Official Version Radar
        .child(
            div()
                .flex()
                .flex_col()
                .w_full()
                .min_w(px(0.))
                .gap(px(10.))
                .child(
                    div()
                        .flex()
                        .flex_wrap()
                        .items_center()
                        .justify_between()
                        .gap(px(8.))
                        .px(px(2.))
                        .child(
                            div()
                                .text_size(px(13.5))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.text_primary))
                                .child("受管 AI 客户端官方版本追踪"),
                        )
                        .child(status_pill(
                            if avail_clients > 0 {
                                format!("已装 {installed_clients}/5 · {avail_clients} 项可更新")
                            } else {
                                format!("已装 {installed_clients}/5 · 均已对齐最新")
                            },
                            if avail_clients > 0 {
                                BadgeTone::Warn
                            } else {
                                BadgeTone::Pass
                            },
                            p,
                        )),
                )
                .children(client_rows),
        )
}


