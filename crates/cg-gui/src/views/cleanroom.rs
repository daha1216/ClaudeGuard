//! Mode B — Frost Ceramic v5 `防连坐净室清理器` view (Module M5).
//!
//! 3-step lossless sanitization workflow:
//! 1. Client scope checkboxes (`Claude` / `ChatGPT & Codex` / `Antigravity`)
//!    + 100% Read-Only Deep Scan (`PipeRequest::ScanCleanRoom`)
//! 2. Pollution Score Gauge + 4-Vector Findings List (selectable) +「100% 保留资产绿盾清单」
//!    (`CLAUDE.md`, `settings.json`, `mcpServers`, `skills/`)
//! 3. One-click Encrypted Backup & Surgical Sanitization (`PipeRequest::ExecuteCleanRoom`)
//!    + Encrypted `.cgbak` Time-Machine Restore list (`PipeRequest::RestoreCleanRoomBackup`).

use crate::app::{ActionScope, AppController, ConsoleWindowView};
use crate::assets::ui_icon;
use crate::demo::now_unix_secs;
use crate::motion::PageChoreo;
use crate::protocol::{CleanRoomRiskLevel, CleanRoomScope, CleanRoomVector, UiLabelExt};
use crate::state::{format_relative_secs, format_unix_ymdhms};
use crate::theme::{BadgeTone, ThemePalette};
use crate::views::shared::page_guide_card;
use crate::widgets::controls::{
    ButtonKind, action_button, bento_card_bloom, icon_action_button, inset_box, mono_tabular,
    spinning_action_button, status_dot, tone_tag,
};
use gpui::{
    Context, Div, Entity, FontWeight, MouseButton, div, prelude::*, px, relative, rgb, rgba,
};

fn pollution_tone(level: CleanRoomRiskLevel) -> BadgeTone {
    match level {
        CleanRoomRiskLevel::Clean => BadgeTone::Pass,
        CleanRoomRiskLevel::Low => BadgeTone::Muted,
        CleanRoomRiskLevel::Elevated => BadgeTone::Warn,
        CleanRoomRiskLevel::CriticalChainBanRisk => BadgeTone::Fail,
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes == 0 {
        "内存态".into()
    } else if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

pub fn render_cleanroom_page(
    ctrl: Entity<AppController>,
    choreo: PageChoreo,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> Div {
    let ctrl_r = ctrl.read(cx);
    let snap = ctrl_r.snapshot.clone();
    let connected = ctrl_r.connected;
    let busy = ctrl_r.busy_action;
    let scope = ctrl_r.cleanroom_scope.clone();
    let selected_ids = ctrl_r.cleanroom_selected_ids.clone();
    let report = ctrl_r
        .cleanroom_report
        .clone()
        .or_else(|| snap.as_ref().and_then(|s| s.last_cleanroom_report.clone()));
    let backups = ctrl_r.cleanroom_backups.clone();
    let scanning = ctrl_r.is_scope_busy(&ActionScope::CleanRoomScan);
    let executing = ctrl_r.is_scope_busy(&ActionScope::CleanRoomExecute);
    let purge_armed = ctrl_r.is_confirm_armed("cr-execute-purge");
    let can_act = connected && !busy;
    let now = now_unix_secs();

    // -------------------------------------------------------------------------
    // Step 1: Scope selection & Read-Only Deep Scan
    // -------------------------------------------------------------------------
    struct ScopeOption {
        key: &'static str,
        label: &'static str,
        on: bool,
        toggle: fn(&mut CleanRoomScope),
    }

    let scope_items = [
        ScopeOption {
            key: "claude",
            label: "Claude 全家桶 (Desktop + MSIX + Code)",
            on: scope.claude,
            toggle: |s| s.claude = !s.claude,
        },
        ScopeOption {
            key: "chatgpt",
            label: "ChatGPT / Codex",
            on: scope.chatgpt_codex,
            toggle: |s| s.chatgpt_codex = !s.chatgpt_codex,
        },
        ScopeOption {
            key: "antigravity",
            label: "Antigravity 会话态",
            on: scope.antigravity,
            toggle: |s| s.antigravity = !s.antigravity,
        },
    ];

    let scope_chips = scope_items.into_iter().map(|opt| {
        let ScopeOption {
            key,
            label: lbl,
            on,
            toggle: toggle_fn,
        } = opt;
        let ctrl_s = ctrl.clone();
        let bg = if on { p.accent_soft_bg } else { p.inset_bg };
        let fg = if on {
            p.accent_soft_text
        } else {
            p.text_secondary
        };
        let bdr = if on {
            p.accent_soft_border
        } else {
            p.card_border
        };
        let hov = p.sidebar_hover_bg;
        div()
            .id(gpui::ElementId::Name(format!("cr-scope-{key}").into()))
            .cursor_pointer()
            .flex()
            .items_center()
            .gap(px(5.5))
            .h(px(28.))
            .px(px(10.))
            .rounded(px(8.))
            .bg(rgb(bg))
            .border_1()
            .border_color(rgb(bdr))
            .text_size(px(11.5))
            .font_weight(if on {
                FontWeight::SEMIBOLD
            } else {
                FontWeight::MEDIUM
            })
            .text_color(rgb(fg))
            .hover(move |s| if on { s.opacity(0.90) } else { s.bg(rgb(hov)) })
            .when(on, |c| c.child(ui_icon("icons/ui/check.svg", 11.5, fg)))
            .child(lbl)
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(move |_, _, _, cx| {
                    ctrl_s.update(cx, |c, cx| {
                        toggle_fn(&mut c.cleanroom_scope);
                        cx.notify();
                    });
                }),
            )
    });

    let any_scope_selected = scope.claude || scope.chatgpt_codex || scope.antigravity;
    let ctrl_scan = ctrl.clone();
    let step1_card = bento_card_bloom(p, 17.0, 14.0, choreo.tile(0, 0))
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
                        .gap(px(2.))
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
                                        .child("封号残留深度清理 · 选择扫描范围"),
                                )
                                .child(tone_tag("100% 纯只读扫描", BadgeTone::Pass, p)),
                        )
                        .child(
                            div()
                                .text_size(px(11.))
                                .text_color(rgb(p.text_secondary))
                                .child("换新号前先做只读扫描定位旧号残留痕迹（扫描阶段绝不改动任何文件，清理前自动加密备份）。"),
                        ),
                )
                .child(
                    spinning_action_button(
                        "cr-run-scan",
                        "icons/ui/radar.svg",
                        if scanning {
                            "深度扫描中…"
                        } else {
                            "纯只读深度扫描"
                        },
                        ButtonKind::Primary,
                        can_act && any_scope_selected && !scanning,
                        scanning,
                        p,
                    )
                    .when(can_act && any_scope_selected && !scanning, |b| {
                        b.on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |_, _, _, cx| {
                                ctrl_scan.update(cx, |c, cx| c.run_cleanroom_scan(cx));
                            }),
                        )
                    }),
                ),
        )
        .child(div().flex().flex_wrap().gap(px(7.)).children(scope_chips));

    // -------------------------------------------------------------------------
    // Step 2: Pollution Score Gauge + 4-Vector Findings + 100% Preserved Assets Shield
    // -------------------------------------------------------------------------
    let (score, level, scanned_age, findings, preserved_list, report_summary) =
        if let Some(rpt) = report.as_ref() {
            (
                rpt.pollution_score,
                rpt.risk_level,
                format_relative_secs(Some(rpt.scanned_at), now),
                rpt.findings.clone(),
                rpt.preserved_assets_summary.clone(),
                rpt.summary.clone(),
            )
        } else {
            (
                0,
                CleanRoomRiskLevel::Clean,
                "尚未扫描".into(),
                Vec::new(),
                vec![
                    "CLAUDE.md（全局与项目提示词 100% 保留）".into(),
                    "settings.json（模型偏好与 Hook 100% 保留）".into(),
                    "mcpServers & claude_desktop_config.json（MCP 工具 100% 保留）".into(),
                    "skills/ · commands/ · agents/（全部自定义技能 100% 保留）".into(),
                ],
                "点击上方「纯只读深度扫描」开始四维关联残留体检".into(),
            )
        };

    let score_tone = pollution_tone(level);
    let bar_fill_color = match score_tone {
        BadgeTone::Pass | BadgeTone::Muted => p.badge_pass.dot,
        BadgeTone::Warn => p.badge_warn.dot,
        BadgeTone::Fail => p.badge_fail.dot,
    };

    let vector_counts = [
        (
            CleanRoomVector::ClaudeCodeState,
            "V1 CLI 遥测",
            findings
                .iter()
                .filter(|f| f.vector == CleanRoomVector::ClaudeCodeState)
                .count(),
        ),
        (
            CleanRoomVector::DesktopChromiumAndCrashpad,
            "V2 桌面/MSIX",
            findings
                .iter()
                .filter(|f| f.vector == CleanRoomVector::DesktopChromiumAndCrashpad)
                .count(),
        ),
        (
            CleanRoomVector::WindowsCredentialManager,
            "V3 系统凭据",
            findings
                .iter()
                .filter(|f| f.vector == CleanRoomVector::WindowsCredentialManager)
                .count(),
        ),
        (
            CleanRoomVector::OrphanMemoryProcess,
            "V4 内存孤儿",
            findings
                .iter()
                .filter(|f| f.vector == CleanRoomVector::OrphanMemoryProcess)
                .count(),
        ),
    ];

    let vector_pills = vector_counts.into_iter().map(|(_, lbl, count)| {
        let tone_col = if count > 0 {
            p.badge_warn.text
        } else {
            p.badge_pass.text
        };
        inset_box(p)
            .flex_1()
            .flex_basis(px(0.))
            .px(px(9.))
            .py(px(6.))
            .gap(px(2.))
            .child(
                div()
                    .text_size(px(10.))
                    .text_color(rgb(p.text_muted))
                    .child(lbl),
            )
            .child(
                mono_tabular(if count > 0 {
                    format!("命中 {count} 项")
                } else {
                    "洁净 0 项".into()
                })
                .text_size(px(11.))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(rgb(tone_col)),
            )
    });

    let selected_count = findings
        .iter()
        .filter(|f| selected_ids.contains(&f.id))
        .count();
    let all_finding_ids_header: Vec<String> = findings.iter().map(|x| x.id.clone()).collect();
    let ctrl_sel_all = ctrl.clone();
    let ctrl_sel_clear = ctrl.clone();

    let finding_rows: Vec<gpui::Stateful<Div>> = findings
        .iter()
        .map(|f| {
            let fid = f.id.clone();
            let is_checked = selected_ids.contains(&f.id);
            let ctrl_sel = ctrl.clone();
            let weight_tone = if f.risk_weight >= 30 {
                BadgeTone::Fail
            } else if f.risk_weight >= 15 {
                BadgeTone::Warn
            } else {
                BadgeTone::Muted
            };
            let hov = p.sidebar_hover_bg;

            div()
                .id(gpui::ElementId::Name(format!("cr-find-{}", f.id).into()))
                .cursor_pointer()
                .flex()
                .flex_col()
                .gap(px(4.))
                .px(px(11.))
                .py(px(9.))
                .rounded(px(10.))
                .bg(rgb(p.inset_bg))
                .border_1()
                .border_color(rgb(if is_checked {
                    p.accent_soft_border
                } else {
                    p.card_border
                }))
                .hover(move |s| s.bg(rgb(hov)))
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
                                .flex_1()
                                .child(
                                    div()
                                        .flex()
                                        .items_center()
                                        .justify_center()
                                        .w(px(16.))
                                        .h(px(16.))
                                        .rounded(px(4.5))
                                        .bg(rgb(if is_checked {
                                            p.accent_soft_bg
                                        } else {
                                            p.card_bg
                                        }))
                                        .border_1()
                                        .border_color(rgb(if is_checked {
                                            p.accent_soft_border
                                        } else {
                                            p.card_border
                                        }))
                                        .when(is_checked, |b| {
                                            b.child(ui_icon(
                                                "icons/ui/check.svg",
                                                10.0,
                                                p.accent_soft_text,
                                            ))
                                        }),
                                )
                                .child(
                                    div()
                                        .truncate()
                                        .text_size(px(11.5))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(p.text_primary))
                                        .child(f.vector.label()),
                                )
                                .child(
                                    mono_tabular(format_bytes(f.bytes_size))
                                        .text_size(px(10.))
                                        .text_color(rgb(p.text_muted)),
                                ),
                        )
                        .child(tone_tag(format!("风险 +{}", f.risk_weight), weight_tone, p)),
                )
                .child(
                    mono_tabular(f.location_display.clone())
                        .truncate()
                        .text_size(px(10.5))
                        .text_color(rgb(p.text_secondary)),
                )
                .child(
                    div()
                        .text_size(px(10.5))
                        .text_color(rgb(p.text_muted))
                        .child(format!(
                            "关联字段：{} · {}",
                            f.correlation_keys.join(", "),
                            f.masked_preview
                        )),
                )
                .when(!f.preservation_note.is_empty(), |box_d| {
                    box_d.child(
                        div()
                            .text_size(px(10.5))
                            .text_color(rgb(p.badge_pass.text))
                            .child(format!("保留承诺：{}", f.preservation_note)),
                    )
                })
                .on_mouse_up(
                    MouseButton::Left,
                    cx.listener(move |_, _, _, cx| {
                        let id = fid.clone();
                        ctrl_sel.update(cx, |c, cx| {
                            c.cleanroom_selection_initialized = true;
                            if !c.cleanroom_selected_ids.remove(&id) {
                                c.cleanroom_selected_ids.insert(id);
                            }
                            cx.notify();
                        });
                    }),
                )
        })
        .collect();

    let findings_card = bento_card_bloom(p, 16.0, 14.0, choreo.tile(1, 0))
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
                        .flex_col()
                        .min_w(px(0.))
                        .flex_1()
                        .gap(px(2.))
                        .child(
                            div()
                                .text_size(px(13.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.text_primary))
                                .child("旧号关联残留清单"),
                        )
                        .child(
                            mono_tabular(format!(
                                "已选 {selected_count}/{} 项 · 上次扫描：{scanned_age} · {report_summary}",
                                findings.len()
                            ))
                            .truncate()
                            .text_size(px(10.5))
                            .text_color(rgb(p.text_muted)),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .flex_shrink_0()
                        .gap(px(5.))
                        .when(!findings.is_empty(), |row| {
                            let all_ids_clone = all_finding_ids_header.clone();
                            row.child(
                                action_button(
                                    "cr-select-all",
                                    "全选",
                                    ButtonKind::Ghost,
                                    selected_count < findings.len(),
                                    p,
                                )
                                .h(px(24.))
                                .px(px(7.5))
                                .text_size(px(10.5))
                                .when(selected_count < findings.len(), |b| {
                                    b.on_mouse_up(
                                        MouseButton::Left,
                                        cx.listener(move |_, _, _, cx| {
                                            let ids = all_ids_clone.clone();
                                            ctrl_sel_all.update(cx, |c, cx| {
                                                c.cleanroom_selection_initialized = true;
                                                c.cleanroom_selected_ids =
                                                    ids.into_iter().collect();
                                                cx.notify();
                                            });
                                        }),
                                    )
                                }),
                            )
                            .child(
                                action_button(
                                    "cr-select-clear",
                                    "清空",
                                    ButtonKind::Ghost,
                                    selected_count > 0,
                                    p,
                                )
                                .h(px(24.))
                                .px(px(7.5))
                                .text_size(px(10.5))
                                .when(selected_count > 0, |b| {
                                    b.on_mouse_up(
                                        MouseButton::Left,
                                        cx.listener(move |_, _, _, cx| {
                                            ctrl_sel_clear.update(cx, |c, cx| {
                                                c.cleanroom_selection_initialized = true;
                                                c.cleanroom_selected_ids.clear();
                                                cx.notify();
                                            });
                                        }),
                                    )
                                }),
                            )
                        })
                        .child(tone_tag(
                            format!("{score}/100 · {}", level.label()),
                            score_tone,
                            p,
                        )),
                ),
        )
        // Pollution Score Gauge Bar
        .child(
            div()
                .w_full()
                .h(px(8.))
                .rounded(px(999.))
                .bg(rgb(p.inset_bg))
                .border_1()
                .border_color(rgb(p.card_border))
                .overflow_hidden()
                .child(
                    div()
                        .h_full()
                        .w(relative((f32::from(score) / 100.0).clamp(0.02, 1.0)))
                        .rounded(px(999.))
                        .bg(rgb(bar_fill_color)),
                ),
        )
        .child(div().flex().flex_row().gap(px(7.)).children(vector_pills))
        .child(if finding_rows.is_empty() {
            inset_box(p)
                .py(px(18.))
                .items_center()
                .justify_center()
                .gap(px(4.))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(6.))
                        .text_size(px(12.))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(rgb(p.badge_pass.text))
                        .child(status_dot(p.badge_pass.dot, 6.5))
                        .child("净室状态洁净 · 当前范围零跨号关联污染"),
                )
                .child(
                    div()
                        .text_size(px(10.5))
                        .text_color(rgb(p.text_muted))
                        .child("可以安全登录新账号或启动新的主权隔离仓。"),
                )
        } else {
            div().flex().flex_col().gap(px(7.)).children(finding_rows)
        });

    // Right column: 100% Preserved Assets Green Shield List + Step 3 Purge Action
    let preserved_rows = preserved_list.into_iter().map(|line| {
        div()
            .flex()
            .items_center()
            .gap(px(7.))
            .px(px(10.))
            .py(px(7.))
            .rounded(px(8.))
            .bg(rgba(p.badge_pass.bg))
            .border_1()
            .border_color(rgb(p.card_border))
            .child(ui_icon("icons/ui/shield.svg", 12.0, p.badge_pass.text))
            .child(
                div()
                    .flex_1()
                    .min_w(px(0.))
                    .text_size(px(11.))
                    .font_weight(FontWeight::MEDIUM)
                    .text_color(rgb(p.text_primary))
                    .child(line),
            )
    });

    let ctrl_purge = ctrl.clone();
    let can_purge = can_act && selected_count > 0 && !executing;
    let purge_btn_label: String = if executing {
        "正在自动备份并清理…".into()
    } else if purge_armed {
        format!("确认立即备份并清理已选 {selected_count} 项？")
    } else if selected_count > 0 {
        format!("自动加密备份并清理已选 ({selected_count} 项)")
    } else {
        "请先勾选需要清理的残留项".into()
    };

    let shield_and_action_card = bento_card_bloom(p, 16.0, 14.0, choreo.tile(1, 1))
        .flex_1()
        .justify_between()
        .gap(px(12.))
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
                                .text_size(px(13.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.text_primary))
                                .child("100% 完整保留的配置与技能清单"),
                        )
                        .child(tone_tag("无损清理", BadgeTone::Pass, p)),
                )
                .child(
                    div()
                        .text_size(px(11.))
                        .line_height(px(16.))
                        .text_color(rgb(p.text_secondary))
                        .child("仅清除旧号登录态、设备识别码、遥测缓存与崩溃记录，以下个人配置与工作流绝对保留："),
                )
                .child(div().flex().flex_col().gap(px(6.)).children(preserved_rows)),
        )
        .child(
            inset_box(p)
                .px(px(12.))
                .py(px(11.))
                .gap(px(8.))
                .child(
                    div()
                        .text_size(px(12.))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(rgb(p.text_primary))
                        .child("安全备份并一键清理残留"),
                )
                .child(
                    div()
                        .text_size(px(10.5))
                        .line_height(px(15.5))
                        .text_color(rgb(p.text_secondary))
                        .child("自动执行：① 关闭后台残留进程防回写 → ② 在本机加密保存清理前备份 → ③ 清理所选痕迹并自动复查确认。"),
                )
                .child(
                    spinning_action_button(
                        "cr-execute-purge",
                        "icons/ui/shield.svg",
                        purge_btn_label,
                        if purge_armed {
                            ButtonKind::Danger
                        } else {
                            ButtonKind::Primary
                        },
                        can_purge,
                        executing,
                        p,
                    )
                    .w_full()
                    .when(can_purge, |b| {
                        b.on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |_, _, _, cx| {
                                ctrl_purge.update(cx, |c, cx| {
                                    if c.arm_or_consume_confirm("cr-execute-purge", cx) {
                                        c.execute_cleanroom_purge(cx);
                                    }
                                });
                            }),
                        )
                    }),
                ),
        );

    // -------------------------------------------------------------------------
    // Time-Machine Encrypted `.cgbak` Backup Restore List
    // -------------------------------------------------------------------------
    let ctrl_refresh_bk = ctrl.clone();
    let ctrl_open_bk_dir = ctrl.clone();
    let backup_rows: Vec<Div> = backups
        .iter()
        .map(|bk| {
            let bid = bk.backup_id.clone();
            let row_restoring = ctrl
                .read(cx)
                .is_scope_busy(&ActionScope::CleanRoomRestore(bk.backup_id.clone()));
            let arm_key = format!("cr-restore-{}", bk.backup_id);
            let armed = ctrl.read(cx).is_confirm_armed(&arm_key);
            let ctrl_rst = ctrl.clone();
            let sha_short: String = bk.sha256_hex.chars().take(12).collect();
            let clients_lbl = if bk.clients_included.is_empty() {
                "Claude".into()
            } else {
                bk.clients_included
                    .iter()
                    .map(|id| crate::views::shared::canonical_agent_label(id, id))
                    .collect::<Vec<_>>()
                    .join(", ")
            };

            div()
                .flex()
                .items_center()
                .justify_between()
                .gap(px(10.))
                .px(px(11.))
                .py(px(8.))
                .rounded(px(9.))
                .bg(rgb(p.inset_bg))
                .border_1()
                .border_color(rgb(p.card_border))
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .min_w(px(0.))
                        .flex_1()
                        .gap(px(2.))
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap(px(7.))
                                .child(
                                    mono_tabular(format!("{}.cgbak", bk.backup_id))
                                        .text_size(px(11.5))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(p.text_primary)),
                                )
                                .child(tone_tag("本机加密保护", BadgeTone::Pass, p)),
                        )
                        .child(
                            mono_tabular(format!(
                                "{} · 范围 [{}] · {} 项 · {} · 校验:{}…",
                                format_unix_ymdhms(bk.created_at),
                                clients_lbl,
                                bk.item_count,
                                format_bytes(bk.archive_bytes),
                                sha_short
                            ))
                            .truncate()
                            .text_size(px(10.5))
                            .text_color(rgb(p.text_muted)),
                        ),
                )
                .child(
                    spinning_action_button(
                        gpui::ElementId::Name(format!("cr-restore-btn-{}", bk.backup_id).into()),
                        "icons/ui/refresh.svg",
                        if row_restoring {
                            "正在还原…"
                        } else if armed {
                            "确认无损还原？"
                        } else {
                            "一键还原"
                        },
                        if armed {
                            ButtonKind::DangerSoft
                        } else {
                            ButtonKind::Secondary
                        },
                        can_act && !row_restoring,
                        row_restoring,
                        p,
                    )
                    .h(px(26.))
                    .px(px(10.))
                    .text_size(px(11.))
                    .when(can_act && !row_restoring, |b| {
                        b.on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |_, _, _, cx| {
                                let id = bid.clone();
                                let key = arm_key.clone();
                                ctrl_rst.update(cx, |c, cx| {
                                    if c.arm_or_consume_confirm(&key, cx) {
                                        c.restore_cleanroom_backup(id, cx);
                                    }
                                });
                            }),
                        )
                    }),
                )
        })
        .collect();

    let backup_card = bento_card_bloom(p, 16.0, 13.0, choreo.tile(2, 0))
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
                        .gap(px(8.))
                        .min_w(px(0.))
                        .child(
                            div()
                                .text_size(px(12.5))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.text_primary))
                                .child("清理前自动备份记录（本机加密保护，可一键无损还原）"),
                        )
                        .child(
                            mono_tabular(format!("共 {} 份备份", backups.len()))
                                .text_size(px(11.))
                                .text_color(rgb(p.text_muted)),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .flex_shrink_0()
                        .gap(px(6.))
                        .child(
                            action_button(
                                "cr-open-backup-dir",
                                "打开备份目录",
                                ButtonKind::Secondary,
                                true,
                                p,
                            )
                            .h(px(26.))
                            .px(px(9.))
                            .text_size(px(11.))
                            .on_mouse_up(
                                MouseButton::Left,
                                cx.listener(move |_, _, _, cx| {
                                    ctrl_open_bk_dir.update(cx, |c, cx| {
                                        c.open_cleanroom_backup_dir(cx);
                                    });
                                }),
                            ),
                        )
                        .child(
                            icon_action_button(
                                "cr-refresh-backups",
                                "icons/ui/refresh.svg",
                                "刷新列表",
                                ButtonKind::Secondary,
                                can_act,
                                p,
                            )
                            .h(px(26.))
                            .px(px(9.))
                            .text_size(px(11.))
                            .when(can_act, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_refresh_bk.update(cx, |c, cx| {
                                            c.refresh_cleanroom_backups(cx);
                                        });
                                    }),
                                )
                            }),
                        ),
                ),
        )
        .child(if backup_rows.is_empty() {
            inset_box(p)
                .py(px(14.))
                .items_center()
                .justify_center()
                .child(
                    div()
                        .text_size(px(11.))
                        .text_color(rgb(p.text_muted))
                        .child("暂无历史 .cgbak 加密备份（首次执行洗白前将自动创建）"),
                )
        } else {
            div().flex().flex_col().gap(px(6.)).children(backup_rows)
        });

    let guide = page_guide_card(
        "防连坐净室工作原理",
        "防重解析点逃逸 · 绝不泄露凭据明文 · 可随时回滚",
        &[
            (
                "1. 捕获隐蔽关联源",
                "覆盖 MSIX Packages\\Claude_*\\LocalCache 暗门、Crashpad 崩溃信封与未上传 telemetry 队列。",
            ),
            (
                "2. CGBAK005 双层加密",
                "采用随机 DEK AES-256-GCM 加密载荷 + Windows DPAPI 保护 KEK，本机当前用户专属可解。",
            ),
            (
                "3. 字段级手术剥离",
                "只移除 .claude.json 中的身份与实验种子，100% 保留你的 MCP、CLAUDE.md 与 Skills。",
            ),
        ],
        p,
    );

    div()
        .flex()
        .flex_col()
        .w_full()
        .min_w(px(0.))
        .gap(px(11.))
        .child(div().w_full().flex().child(step1_card))
        .child(
            div()
                .flex()
                .flex_row()
                .w_full()
                .gap(px(11.))
                .child(
                    div()
                        .w(relative(0.60))
                        .flex_shrink_0()
                        .flex()
                        .child(findings_card),
                )
                .child(
                    div()
                        .flex_1()
                        .min_w(px(0.))
                        .flex()
                        .child(shield_and_action_card),
                ),
        )
        .child(div().w_full().flex().child(backup_card))
        .child(choreo.tile(2, 1).apply(guide))
}
