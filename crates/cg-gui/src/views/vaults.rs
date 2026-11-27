//! Mode B — Frost Ceramic v5 `多账号主权隔离仓` view (Module M4).
//!
//! Layout:
//! - Vault Sovereignty Header card (total / active count, `+ 新建主权账号仓`)
//! - Collapsible Draft-Isolated Create/Edit Sovereign Vault drawer (backed by `DraftStore.vault_draft`,
//!   100% immune to 1s background snapshot polling, with 1-click「采纳当前实时出口作为基线」)
//! - 2-column Bento grid of Sovereign Account Vault cards showing pinned regions/IPs/ASN, live state
//!   pill, 1-click safe-launch buttons (`Claude`, `Code CLI`, `Codex`, `Antigravity`, `Cursor`),
//!   `生成桌面快捷方式`, `停止此仓`, `编辑`, and `删除`.

use crate::app::{ActionScope, AppController, ConsoleWindowView};
use crate::demo::now_unix_secs;
use crate::motion::PageChoreo;
use crate::protocol::{
    AccountVault, MSIX_ISOLATION_MODES, PipeRequest, UiLabelExt, VaultAppTarget, VaultRuntimeState,
    VaultRuntimeStatus, mask_ip_str,
};
use crate::state::format_relative_secs;
use crate::theme::{BadgeTone, ThemePalette};
use crate::views::shared::{
    canonical_agent_label, labeled_field, page_guide_card, switch_row_gated,
};
use crate::widgets::controls::{
    ButtonKind, action_button, bento_card_bloom, icon_action_button, inset_box, mono_tabular,
    segmented_capsule_item, segmented_capsule_track, status_dot, tone_tag,
};
use gpui::{Context, Div, Entity, FontWeight, MouseButton, div, prelude::*, px, rgb};

fn vault_state_tone(state: VaultRuntimeState) -> BadgeTone {
    match state {
        VaultRuntimeState::ActiveRunning => BadgeTone::Pass,
        VaultRuntimeState::Ready => BadgeTone::Muted,
        VaultRuntimeState::CoolingDown => BadgeTone::Warn,
        VaultRuntimeState::EgressMismatch => BadgeTone::Fail,
        VaultRuntimeState::Disabled => BadgeTone::Muted,
    }
}

fn vault_state_label(rt: &VaultRuntimeStatus) -> String {
    match rt.state {
        VaultRuntimeState::ActiveRunning => {
            format!("守护运行中 · {} 进程", rt.running_pids.len().max(1))
        }
        VaultRuntimeState::CoolingDown => {
            let mins = rt.cooldown_remaining_secs / 60;
            let secs = rt.cooldown_remaining_secs % 60;
            format!("换 IP 冷却中 {mins:02}:{secs:02}")
        }
        other => other.label().to_string(),
    }
}

fn format_vault_ips(ips: &[String], privacy_mask: bool) -> String {
    if ips.is_empty() {
        return "按地区匹配".into();
    }
    ips.iter()
        .map(|ip| {
            if privacy_mask {
                mask_ip_str(ip)
            } else {
                ip.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn vault_accent_dot_color(accent_hex: &str, p: &ThemePalette) -> u32 {
    let hex = accent_hex.trim().trim_start_matches('#');
    if hex.len() == 6
        && let Ok(val) = u32::from_str_radix(hex, 16)
    {
        return val;
    }
    p.accent_soft_text
}

pub fn render_vaults_page(
    ctrl: Entity<AppController>,
    choreo: PageChoreo,
    p: &'static ThemePalette,
    cx: &mut Context<ConsoleWindowView>,
) -> Div {
    let ctrl_r = ctrl.read(cx);
    let snap = ctrl_r.snapshot.clone();
    let connected = ctrl_r.connected;
    let busy = ctrl_r.busy_action;
    let privacy_mask = ctrl_r.privacy_mask;
    let show_drawer = ctrl_r.show_vault_drawer;
    let draft = ctrl_r.drafts.vault_draft.clone();
    let validation_err = ctrl_r.drafts.vault_validation_error.clone();
    let can_act = connected && !busy;
    let now = now_unix_secs();

    let cfg_vaults: Vec<AccountVault> = snap
        .as_ref()
        .map(|s| s.config.vaults.clone())
        .unwrap_or_default();
    let rt_vaults: Vec<VaultRuntimeStatus> =
        snap.as_ref().map(|s| s.vaults.clone()).unwrap_or_default();

    let total_vaults = cfg_vaults.len().max(rt_vaults.len());
    let active_vaults = rt_vaults
        .iter()
        .filter(|v| v.state == VaultRuntimeState::ActiveRunning)
        .count();

    let ctrl_new = ctrl.clone();
    let header_card = bento_card_bloom(p, 17.0, 13.0, choreo.tile(0, 0))
        .flex_1()
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
                        .gap(px(8.))
                        .child(
                            div()
                                .text_size(px(13.5))
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(rgb(p.text_primary))
                                .child("多账号独立防封空间"),
                        )
                        .child(tone_tag("数据独立防串号", BadgeTone::Pass, p)),
                )
                .child(
                    mono_tabular(format!(
                        "账号数据互不串号，节点不符自动拒启 · 已创建 {total_vaults} 个空间 · 当前运行中 {active_vaults} 个"
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
                .gap(px(8.))
                .child(
                    icon_action_button(
                        "vault-open-new",
                        "icons/ui/plus.svg",
                        if show_drawer && !draft.editing_existing {
                            "收起表单"
                        } else {
                            "新建账号空间"
                        },
                        ButtonKind::Primary,
                        connected,
                        p,
                    )
                    .when(connected, |b| {
                        b.on_mouse_up(
                            MouseButton::Left,
                            cx.listener(move |_, _, _, cx| {
                                ctrl_new.update(cx, |c, cx| {
                                    if c.show_vault_drawer && !c.drafts.vault_draft.editing_existing
                                    {
                                        c.close_vault_drawer(cx);
                                    } else {
                                        c.open_new_vault_drawer(cx);
                                    }
                                });
                            }),
                        )
                    }),
                ),
        );

    // Inline Create/Edit Draft-Isolated Form Drawer
    let drawer_el = show_drawer.then(|| {
        let inputs = &ctrl.read(cx).inputs;
        let in_id = inputs.vault_id.clone();
        let in_name = inputs.vault_name.clone();
        let in_regions = inputs.vault_regions.clone();
        let in_ips = inputs.vault_ips.clone();
        let in_asn = inputs.vault_asn.clone();
        let in_port = inputs.vault_proxy_port.clone();
        let in_group = inputs.vault_mihomo_group.clone();
        let in_node = inputs.vault_mihomo_node.clone();
        let in_score = inputs.vault_min_score.clone();
        let in_cool = inputs.vault_cooldown.clone();

        let ctrl_adopt = ctrl.clone();
        let ctrl_adopt_strict = ctrl.clone();
        let ctrl_save = ctrl.clone();
        let ctrl_cancel = ctrl.clone();
        let ctrl_share = ctrl.clone();
        let ctrl_align = ctrl.clone();
        let ctrl_enabled = ctrl.clone();
        let is_saving = ctrl
            .read(cx)
            .is_scope_busy(&ActionScope::VaultOp(draft.id.clone()));

        let msix_items = MSIX_ISOLATION_MODES.into_iter().map(|mode| {
            let active = draft.msix_isolation_mode == mode;
            let ctrl_m = ctrl.clone();
            segmented_capsule_item(
                gpui::ElementId::Name(format!("vault-msix-{mode:?}").into()),
                mode.label(),
                active,
                p,
            )
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(move |_, _, _, cx| {
                    ctrl_m.update(cx, |c, cx| {
                        c.drafts.vault_draft.msix_isolation_mode = mode;
                        c.drafts.vault_dirty = true;
                        cx.notify();
                    });
                }),
            )
        });

        let accent_swatches = [
            ("#5B69D0", "星靛"),
            ("#16A34A", "翠绿"),
            ("#2B4F8D", "深蓝"),
            ("#D97706", "琥珀"),
            ("#DC2626", "朱红"),
        ]
        .into_iter()
        .map(|(hex, lbl)| {
            let active = draft.accent_hex.eq_ignore_ascii_case(hex);
            let ctrl_a = ctrl.clone();
            let dot_col = vault_accent_dot_color(hex, p);
            div()
                .id(gpui::ElementId::Name(format!("vault-accent-{hex}").into()))
                .cursor_pointer()
                .flex()
                .items_center()
                .gap(px(5.))
                .h(px(26.))
                .px(px(9.))
                .rounded(px(7.))
                .bg(rgb(if active {
                    p.accent_soft_bg
                } else {
                    p.inset_bg
                }))
                .border_1()
                .border_color(rgb(if active {
                    p.accent_soft_border
                } else {
                    p.card_border
                }))
                .text_size(px(11.))
                .font_weight(if active {
                    FontWeight::SEMIBOLD
                } else {
                    FontWeight::MEDIUM
                })
                .text_color(rgb(if active {
                    p.accent_soft_text
                } else {
                    p.text_secondary
                }))
                .child(status_dot(dot_col, 7.0))
                .child(lbl)
                .on_mouse_up(
                    MouseButton::Left,
                    cx.listener(move |_, _, _, cx| {
                        ctrl_a.update(cx, |c, cx| {
                            c.drafts.vault_draft.accent_hex = hex.into();
                            c.drafts.vault_dirty = true;
                            cx.notify();
                        });
                    }),
                )
        });

        bento_card_bloom(p, 17.0, 14.0, choreo.tile(0, 1))
            .w_full()
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
                                    .text_size(px(13.))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .text_color(rgb(p.text_primary))
                                    .child(if draft.editing_existing {
                                        "编辑账号防封空间"
                                    } else {
                                        "新建账号防封空间"
                                    }),
                            )
                            .child(
                                div()
                                    .text_size(px(10.5))
                                    .text_color(rgb(p.text_muted))
                                    .child("按 Esc 关闭、Ctrl+S 保存；推荐使用「绑定当前节点地区」避免动态节点换 IP 被误拦。"),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .flex_shrink_0()
                            .gap(px(6.))
                            .child(
                                icon_action_button(
                                    "vault-adopt-egress",
                                    "icons/ui/globe.svg",
                                    "一键绑定当前节点地区（推荐）",
                                    ButtonKind::Primary,
                                    connected,
                                    p,
                                )
                                .h(px(28.))
                                .when(connected, |b| {
                                    b.on_mouse_up(
                                        MouseButton::Left,
                                        cx.listener(move |_, _, _, cx| {
                                            ctrl_adopt.update(cx, |c, cx| {
                                                c.adopt_egress_into_vault_draft(cx);
                                            });
                                        }),
                                    )
                                }),
                            )
                            .child(
                                action_button(
                                    "vault-adopt-strict-ip",
                                    "严格绑定当前静态 IP",
                                    ButtonKind::Secondary,
                                    connected,
                                    p,
                                )
                                .h(px(28.))
                                .when(connected, |b| {
                                    b.on_mouse_up(
                                        MouseButton::Left,
                                        cx.listener(move |_, _, _, cx| {
                                            ctrl_adopt_strict.update(cx, |c, cx| {
                                                c.adopt_egress_strict_ip_into_vault_draft(cx);
                                            });
                                        }),
                                    )
                                }),
                            ),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_row()
                    .gap(px(10.))
                    .child(if draft.editing_existing {
                        div()
                            .flex()
                            .flex_col()
                            .flex_1()
                            .min_w(px(0.))
                            .gap(px(4.))
                            .child(
                                div()
                                    .text_size(px(11.))
                                    .font_weight(FontWeight::MEDIUM)
                                    .text_color(rgb(p.text_secondary))
                                    .child("隔离仓 ID（创建后固定防克隆）"),
                            )
                            .child(
                                inset_box(p)
                                    .h(px(32.))
                                    .px(px(10.))
                                    .justify_center()
                                    .child(
                                        mono_tabular(format!("{}（已锁定）", draft.id))
                                            .truncate()
                                            .text_size(px(11.5))
                                            .text_color(rgb(p.text_muted)),
                                    ),
                            )
                    } else {
                        labeled_field("隔离仓 ID (a-z/0-9/-/_)", in_id, p)
                    })
                    .child(labeled_field("显示名称", in_name, p))
                    .child(labeled_field("锁定地区 (ISO-2 如 US, JP)", in_regions, p)),
            )
            .child(
                div()
                    .flex()
                    .flex_row()
                    .gap(px(10.))
                    .child(labeled_field("锁定静态 IP / CIDR（可选）", in_ips, p))
                    .child(labeled_field("锁定 ASN（如 7922，可选）", in_asn, p))
                    .child(labeled_field("独立代理端口（可选）", in_port, p)),
            )
            .child(
                div()
                    .flex()
                    .flex_row()
                    .gap(px(10.))
                    .child(labeled_field("关联 Mihomo 策略组（可选）", in_group, p))
                    .child(labeled_field("偏好 Mihomo 节点（可选）", in_node, p))
                    .child(labeled_field("最低安全分 (0-100)", in_score, p))
                    .child(labeled_field("换 IP 冷却秒数", in_cool, p)),
            )
            .child(
                div()
                    .flex()
                    .flex_row()
                    .items_center()
                    .justify_between()
                    .gap(px(14.))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .flex_wrap()
                            .gap(px(6.))
                            .child(
                                div()
                                    .text_size(px(11.))
                                    .text_color(rgb(p.text_muted))
                                    .child("色标"),
                            )
                            .children(accent_swatches),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(8.))
                            .child(
                                div()
                                    .text_size(px(11.))
                                    .text_color(rgb(p.text_muted))
                                    .child("商店版 Claude 防串号保护"),
                            )
                            .child(
                                div()
                                    .w(px(280.))
                                    .child(segmented_capsule_track(p).children(msix_items)),
                            ),
                    ),
            )
            .child(
                inset_box(p)
                    .px(px(12.))
                    .py(px(4.))
                    .child(
                        switch_row_gated(
                            "vault-sw-enabled",
                            "启用此主权隔离仓",
                            "停用后将禁止从此仓拉起任何客户端",
                            draft.enabled,
                            true,
                            p,
                            cx.listener(move |_, _, _, cx| {
                                ctrl_enabled.update(cx, |c, cx| {
                                    c.drafts.vault_draft.enabled = !c.drafts.vault_draft.enabled;
                                    c.drafts.vault_dirty = true;
                                    cx.notify();
                                });
                            }),
                        )
                        .border_b_1()
                        .border_color(rgb(p.card_border)),
                    )
                    .child(
                        switch_row_gated(
                            "vault-sw-share-ext",
                            "共享宿主机 IDE 扩展目录",
                            "VS Code 系（Cursor / Windsurf / Antigravity）复用插件本体但物理隔离登录态与机器码",
                            draft.share_ide_extensions,
                            true,
                            p,
                            cx.listener(move |_, _, _, cx| {
                                ctrl_share.update(cx, |c, cx| {
                                    c.drafts.vault_draft.share_ide_extensions =
                                        !c.drafts.vault_draft.share_ide_extensions;
                                    c.drafts.vault_dirty = true;
                                    cx.notify();
                                });
                            }),
                        )
                        .border_b_1()
                        .border_color(rgb(p.card_border)),
                    )
                    .child(switch_row_gated(
                        "vault-sw-auto-mihomo",
                        "启动时自动对齐 Mihomo 节点（默认关闭）",
                        "显式开启后，拉起此仓前将请求本地 Mihomo API 切至偏好节点",
                        draft.auto_align_mihomo_on_vault_launch,
                        true,
                        p,
                        cx.listener(move |_, _, _, cx| {
                            ctrl_align.update(cx, |c, cx| {
                                c.drafts.vault_draft.auto_align_mihomo_on_vault_launch =
                                    !c.drafts.vault_draft.auto_align_mihomo_on_vault_launch;
                                c.drafts.vault_dirty = true;
                                cx.notify();
                            });
                        }),
                    )),
            )
            .when_some(validation_err, |card, err| {
                card.child(
                    div()
                        .px(px(10.))
                        .py(px(7.))
                        .rounded(px(8.))
                        .bg(gpui::rgba(p.badge_fail.bg))
                        .border_1()
                        .border_color(gpui::rgba(p.hero_tripped.border))
                        .text_size(px(11.5))
                        .text_color(rgb(p.badge_fail.text))
                        .child(err),
                )
            })
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_end()
                    .gap(px(8.))
                    .child(
                        action_button("vault-cancel-btn", "取消", ButtonKind::Secondary, true, p)
                            .on_mouse_up(
                                MouseButton::Left,
                                cx.listener(move |_, _, _, cx| {
                                    ctrl_cancel.update(cx, |c, cx| c.close_vault_drawer(cx));
                                }),
                            ),
                    )
                    .child(
                        action_button(
                            "vault-save-btn",
                            if is_saving { "保存中…" } else { "保存隔离仓" },
                            ButtonKind::Primary,
                            can_act && !is_saving,
                            p,
                        )
                        .when(can_act && !is_saving, |b| {
                            b.on_mouse_up(
                                MouseButton::Left,
                                cx.listener(move |_, _, _, cx| {
                                    ctrl_save.update(cx, |c, cx| c.save_vault_draft(cx));
                                }),
                            )
                        }),
                    ),
            )
    });

    // Build 2-column Bento grid of Sovereign Account Vault cards
    let mut vault_cards: Vec<Div> = cfg_vaults
        .iter()
        .enumerate()
        .map(|(idx, v)| {
            let rt = rt_vaults
                .iter()
                .find(|r| r.id == v.id)
                .cloned()
                .unwrap_or_else(|| VaultRuntimeStatus {
                    id: v.id.clone(),
                    name: v.name.clone(),
                    accent_hex: v.accent_hex.clone(),
                    state: if v.enabled {
                        VaultRuntimeState::Ready
                    } else {
                        VaultRuntimeState::Disabled
                    },
                    egress_matches_contract: true,
                    ..VaultRuntimeStatus::default()
                });
            let tone = vault_state_tone(rt.state);
            let pill_txt = vault_state_label(&rt);
            let is_running =
                rt.state == VaultRuntimeState::ActiveRunning || !rt.running_pids.is_empty();
            let dot_col = vault_accent_dot_color(&v.accent_hex, p);
            let del_key = format!("vault-del-{}", v.id);
            let del_armed = ctrl.read(cx).is_confirm_armed(&del_key);

            let region_str = if v.pinned_regions.is_empty() {
                "不限合规国".into()
            } else {
                v.pinned_regions.join(" / ")
            };
            let ip_str = format_vault_ips(&v.pinned_ips, privacy_mask);
            let asn_str = v
                .pinned_asn
                .map(|a| format!("AS{a}"))
                .unwrap_or_else(|| "自动纯净度".into());
            let mihomo_str = v
                .preferred_mihomo_node
                .as_deref()
                .map(|n| {
                    if v.auto_align_mihomo_on_vault_launch {
                        format!("{n} (自动对齐)")
                    } else {
                        format!("{n} (仅核验)")
                    }
                })
                .unwrap_or_else(|| "默认全局通道".into());

            let last_seen = format_relative_secs(rt.last_active_at, now);
            let last_exit = match (rt.last_country.as_deref(), rt.last_ip_masked.as_deref()) {
                (Some(cc), Some(ip)) => format!("{cc} · {ip}"),
                (Some(cc), None) => cc.to_string(),
                _ => "尚未活跃".into(),
            };

            let mihomo_can_align = v.auto_align_mihomo_on_vault_launch
                && v.preferred_mihomo_node
                    .as_deref()
                    .is_some_and(|n| !n.trim().is_empty());
            let launch_targets = [
                (VaultAppTarget::ClaudeDesktop, "Claude"),
                (VaultAppTarget::ClaudeCodeCli, "Code CLI"),
                (VaultAppTarget::CursorIde, "Cursor"),
                (VaultAppTarget::AntigravityIde, "Antigravity"),
                (VaultAppTarget::ChatgptDesktop, "ChatGPT"),
                (VaultAppTarget::WindsurfIde, "Windsurf"),
                (VaultAppTarget::ZedIde, "Zed"),
                (VaultAppTarget::TraeIde, "Trae"),
                (VaultAppTarget::CodexCli, "Codex CLI"),
                (VaultAppTarget::GeminiCli, "Gemini CLI"),
                (VaultAppTarget::AiderCli, "Aider CLI"),
            ];
            let can_launch_vault = can_act
                && v.enabled
                && rt.state != VaultRuntimeState::CoolingDown
                && (rt.state != VaultRuntimeState::EgressMismatch || mihomo_can_align);

            let launch_btns = launch_targets.into_iter().map(|(target, label)| {
                let ctrl_l = ctrl.clone();
                let vid = v.id.clone();
                let btn_lbl = if rt.state == VaultRuntimeState::EgressMismatch
                    && mihomo_can_align
                    && target == VaultAppTarget::ClaudeDesktop
                {
                    "一键切节点启动 Claude"
                } else {
                    label
                };
                icon_action_button(
                    gpui::ElementId::Name(format!("vault-launch-{}-{target:?}", v.id).into()),
                    "icons/ui/play.svg",
                    btn_lbl,
                    ButtonKind::Secondary,
                    can_launch_vault,
                    p,
                )
                .h(px(25.))
                .px(px(8.5))
                .text_size(px(10.5))
                .when(can_launch_vault, |b| {
                    b.on_mouse_up(
                        MouseButton::Left,
                        cx.listener(move |_, _, _, cx| {
                            let id = vid.clone();
                            ctrl_l.update(cx, |c, cx| {
                                c.send_request_msg(
                                    PipeRequest::LaunchVault {
                                        vault_id: id,
                                        app: target,
                                        extra_args: Vec::new(),
                                    },
                                    Some(format!("已在账号空间启动 {}", target.label())),
                                    cx,
                                );
                            });
                        }),
                    )
                })
            });

            // Closed-loop 1-click inline recovery bar when vault is blocked by EgressMismatch or CoolingDown
            let recovery_bar = if rt.state == VaultRuntimeState::EgressMismatch {
                let ctrl_rc = ctrl.clone();
                let ctrl_ed = ctrl.clone();
                let vid_ed = v.id.clone();
                Some(
                    inset_box(p)
                        .flex_row()
                        .items_center()
                        .justify_between()
                        .gap(px(8.))
                        .px(px(10.))
                        .py(px(6.5))
                        .bg(gpui::rgba(p.badge_fail.bg))
                        .border_color(gpui::rgba(p.hero_tripped.border))
                        .child(
                            div()
                                .flex_1()
                                .min_w(px(0.))
                                .truncate()
                                .text_size(px(10.5))
                                .font_weight(FontWeight::MEDIUM)
                                .text_color(rgb(p.badge_fail.text))
                                .child(if mihomo_can_align {
                                    "当前节点不符 · 点击下方客户端将自动切回绑定节点"
                                } else {
                                    "当前代理节点与本空间绑定地区/IP不符，已自动拦停"
                                }),
                        )
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .flex_shrink_0()
                                .gap(px(5.))
                                .child(
                                    action_button(
                                        gpui::ElementId::Name(
                                            format!("vault-mismatch-recheck-{}", v.id).into(),
                                        ),
                                        "重检节点",
                                        ButtonKind::Secondary,
                                        can_act,
                                        p,
                                    )
                                    .h(px(23.))
                                    .px(px(7.5))
                                    .text_size(px(10.))
                                    .when(can_act, |b| {
                                        b.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                ctrl_rc.update(cx, |c, cx| {
                                                    c.send_request(
                                                        PipeRequest::RecheckNow { target_id: None },
                                                        Some("已完成当前节点复查"),
                                                        cx,
                                                    );
                                                });
                                            }),
                                        )
                                    }),
                                )
                                .child(
                                    action_button(
                                        gpui::ElementId::Name(
                                            format!("vault-mismatch-edit-{}", v.id).into(),
                                        ),
                                        "改绑地区",
                                        ButtonKind::Ghost,
                                        connected,
                                        p,
                                    )
                                    .h(px(23.))
                                    .px(px(7.5))
                                    .text_size(px(10.))
                                    .when(connected, |b| {
                                        b.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                let id = vid_ed.clone();
                                                ctrl_ed.update(cx, |c, cx| {
                                                    c.open_edit_vault_drawer(&id, cx);
                                                });
                                            }),
                                        )
                                    }),
                                ),
                        ),
                )
            } else if rt.state == VaultRuntimeState::CoolingDown {
                let ctrl_cool = ctrl.clone();
                Some(
                    inset_box(p)
                        .flex_row()
                        .items_center()
                        .justify_between()
                        .gap(px(8.))
                        .px(px(10.))
                        .py(px(6.5))
                        .bg(gpui::rgba(p.badge_warn.bg))
                        .child(
                            div()
                                .flex_1()
                                .min_w(px(0.))
                                .truncate()
                                .text_size(px(10.5))
                                .font_weight(FontWeight::MEDIUM)
                                .text_color(rgb(p.badge_warn.text))
                                .child("刚切换节点地区，防异地登录风控冷却保护中"),
                        )
                        .child(
                            action_button(
                                gpui::ElementId::Name(
                                    format!("vault-clear-cooldown-{}", v.id).into(),
                                ),
                                "确认本人换线 · 立即放行",
                                ButtonKind::Secondary,
                                can_act,
                                p,
                            )
                            .h(px(23.))
                            .px(px(8.))
                            .text_size(px(10.))
                            .when(can_act, |b| {
                                b.on_mouse_up(
                                    MouseButton::Left,
                                    cx.listener(move |_, _, _, cx| {
                                        ctrl_cool.update(cx, |c, cx| {
                                            c.send_request(
                                                PipeRequest::ClearGeoVelocityCooldown,
                                                Some("已解除换线冷却保护，可立即启动"),
                                                cx,
                                            );
                                        });
                                    }),
                                )
                            }),
                        ),
                )
            } else {
                None
            };

            let ctrl_lnk = ctrl.clone();
            let vid_lnk = v.id.clone();
            let ctrl_stop = ctrl.clone();
            let vid_stop = v.id.clone();
            let ctrl_edit = ctrl.clone();
            let vid_edit = v.id.clone();
            let ctrl_del = ctrl.clone();
            let vid_del = v.id.clone();

            let card = bento_card_bloom(p, 16.0, 14.0, choreo.tile(1 + idx / 2, idx % 2))
                .flex_1()
                .justify_between()
                .gap(px(10.))
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .gap(px(9.))
                        // Card header
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
                                        .flex_1()
                                        .child(status_dot(dot_col, 9.0))
                                        .child(
                                            div()
                                                .flex()
                                                .flex_col()
                                                .min_w(px(0.))
                                                .child(
                                                    div()
                                                        .truncate()
                                                        .text_size(px(13.))
                                                        .font_weight(FontWeight::SEMIBOLD)
                                                        .text_color(rgb(p.text_primary))
                                                        .child(v.name.clone()),
                                                )
                                                .child(
                                                    mono_tabular(format!(
                                                        "ID: {} · 最低安全分 ≥{}",
                                                        v.id, v.min_safety_score
                                                    ))
                                                    .truncate()
                                                    .text_size(px(10.5))
                                                    .text_color(rgb(p.text_muted)),
                                                ),
                                        ),
                                )
                                .child(tone_tag(pill_txt, tone, p)),
                        )
                        // Contract strip
                        .child(
                            div()
                                .flex()
                                .flex_row()
                                .gap(px(6.))
                                .child(
                                    inset_box(p)
                                        .flex_1()
                                        .flex_basis(px(0.))
                                        .px(px(9.))
                                        .py(px(6.5))
                                        .gap(px(2.))
                                        .child(
                                            div()
                                                .text_size(px(10.))
                                                .text_color(rgb(p.text_muted))
                                                .child("锁定地区 / ASN"),
                                        )
                                        .child(
                                            mono_tabular(format!("{region_str} · {asn_str}"))
                                                .truncate()
                                                .text_size(px(11.))
                                                .font_weight(FontWeight::SEMIBOLD)
                                                .text_color(rgb(p.text_primary)),
                                        ),
                                )
                                .child(
                                    inset_box(p)
                                        .flex_1()
                                        .flex_basis(px(0.))
                                        .px(px(9.))
                                        .py(px(6.5))
                                        .gap(px(2.))
                                        .child(
                                            div()
                                                .text_size(px(10.))
                                                .text_color(rgb(p.text_muted))
                                                .child("锁定 IP / CIDR"),
                                        )
                                        .child(
                                            mono_tabular(ip_str)
                                                .truncate()
                                                .text_size(px(11.))
                                                .font_weight(FontWeight::SEMIBOLD)
                                                .text_color(rgb(p.text_primary)),
                                        ),
                                )
                                .child(
                                    inset_box(p)
                                        .flex_1()
                                        .flex_basis(px(0.))
                                        .px(px(9.))
                                        .py(px(6.5))
                                        .gap(px(2.))
                                        .child(
                                            div()
                                                .text_size(px(10.))
                                                .text_color(rgb(p.text_muted))
                                                .child("Mihomo 联动"),
                                        )
                                        .child(
                                            mono_tabular(mihomo_str)
                                                .truncate()
                                                .text_size(px(11.))
                                                .font_weight(FontWeight::SEMIBOLD)
                                                .text_color(rgb(p.text_secondary)),
                                        ),
                                ),
                        )
                        // Spatiotemporal summary
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .justify_between()
                                .gap(px(8.))
                                .child(
                                    mono_tabular(format!(
                                        "最近活跃：{last_seen} · 上次出口：{last_exit}"
                                    ))
                                    .truncate()
                                    .text_size(px(10.5))
                                    .text_color(rgb(p.text_secondary)),
                                )
                                .when(!rt.running_apps.is_empty(), |row| {
                                    let friendly_running = rt
                                        .running_apps
                                        .iter()
                                        .map(|id| canonical_agent_label(id, id))
                                        .collect::<Vec<_>>()
                                        .join(", ");
                                    row.child(
                                        mono_tabular(format!("运行中：{friendly_running}"))
                                            .text_size(px(10.5))
                                            .text_color(rgb(p.badge_pass.text)),
                                    )
                                }),
                        )
                        .when_some(recovery_bar, |col, bar| col.child(bar))
                        .when(!rt.summary.is_empty(), |col| {
                            col.child(
                                div()
                                    .text_size(px(10.5))
                                    .text_color(rgb(p.text_muted))
                                    .child(rt.summary.clone()),
                            )
                        })
                        // 1-click safe launch row (all 11 managed GUI & CLI clients)
                        .child(div().flex().flex_wrap().gap(px(5.5)).children(launch_btns)),
                )
                // Footer operations
                .child(
                    div()
                        .flex()
                        .flex_wrap()
                        .items_center()
                        .justify_between()
                        .gap(px(6.))
                        .pt(px(8.))
                        .border_t_1()
                        .border_color(rgb(p.card_border))
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap(px(6.))
                                .child(
                                    icon_action_button(
                                        gpui::ElementId::Name(
                                            format!("vault-lnk-{}", v.id).into(),
                                        ),
                                        "icons/ui/ext.svg",
                                        "生成桌面快捷方式",
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
                                                let id = vid_lnk.clone();
                                                ctrl_lnk.update(cx, |c, cx| {
                                                    c.send_request(
                                                        PipeRequest::GenerateVaultShortcuts {
                                                            vault_id: id,
                                                        },
                                                        Some("已生成桌面直启快捷方式"),
                                                        cx,
                                                    );
                                                });
                                            }),
                                        )
                                    }),
                                )
                                .child(
                                    action_button(
                                        gpui::ElementId::Name(
                                            format!("vault-stop-{}", v.id).into(),
                                        ),
                                        "停止此仓",
                                        ButtonKind::DangerSoft,
                                        can_act && is_running,
                                        p,
                                    )
                                    .h(px(26.))
                                    .px(px(9.))
                                    .text_size(px(11.))
                                    .when(can_act && is_running, |b| {
                                        b.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                let id = vid_stop.clone();
                                                ctrl_stop.update(cx, |c, cx| {
                                                    c.send_request(
                                                        PipeRequest::StopVault { vault_id: id },
                                                        Some("已安全停止该隔离仓全部进程"),
                                                        cx,
                                                    );
                                                });
                                            }),
                                        )
                                    }),
                                ),
                        )
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap(px(6.))
                                .child(
                                    action_button(
                                        gpui::ElementId::Name(
                                            format!("vault-edit-{}", v.id).into(),
                                        ),
                                        "编辑",
                                        ButtonKind::Ghost,
                                        connected,
                                        p,
                                    )
                                    .h(px(26.))
                                    .px(px(9.))
                                    .text_size(px(11.))
                                    .when(connected, |b| {
                                        b.on_mouse_up(
                                            MouseButton::Left,
                                            cx.listener(move |_, _, _, cx| {
                                                let id = vid_edit.clone();
                                                ctrl_edit.update(cx, |c, cx| {
                                                    c.open_edit_vault_drawer(&id, cx);
                                                });
                                            }),
                                        )
                                    }),
                                )
                                .child(
                                    action_button(
                                        gpui::ElementId::Name(
                                            format!("vault-del-{}", v.id).into(),
                                        ),
                                        if del_armed { "确认删除？" } else { "删除" },
                                        if del_armed {
                                            ButtonKind::Danger
                                        } else {
                                            ButtonKind::Ghost
                                        },
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
                                                let id = vid_del.clone();
                                                let key = del_key.clone();
                                                ctrl_del.update(cx, |c, cx| {
                                                    if c.arm_or_consume_confirm(&key, cx) {
                                                        c.send_request(
                                                            PipeRequest::DeleteVault {
                                                                vault_id: id,
                                                                purge_disk_data: false,
                                                            },
                                                            Some("已移除隔离仓配置（磁盘数据已安全保留）"),
                                                            cx,
                                                        );
                                                    }
                                                });
                                            }),
                                        )
                                    }),
                                ),
                        ),
                );
            div().flex_1().flex_basis(px(0.)).min_w(px(0.)).flex().child(card)
        })
        .collect();

    let mut grid_rows = Vec::new();
    while !vault_cards.is_empty() {
        let take_n = vault_cards.len().min(2);
        let pair: Vec<Div> = vault_cards.drain(0..take_n).collect();
        grid_rows.push(div().flex().flex_row().w_full().gap(px(11.)).children(pair));
    }

    let empty_placeholder = grid_rows.is_empty().then(|| {
        inset_box(p)
            .w_full()
            .py(px(28.))
            .items_center()
            .justify_center()
            .gap(px(6.))
            .child(
                div()
                    .text_size(px(12.5))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(rgb(p.text_primary))
                    .child("尚未创建多账号主权隔离仓"),
            )
            .child(
                div()
                    .text_size(px(11.))
                    .text_color(rgb(p.text_muted))
                    .child("点击右上角「新建主权账号仓」，10 秒一键采纳当前出口基线并隔离工作号/个人号。"),
            )
    });

    let guide = page_guide_card(
        "主权多账号物理隔离原理",
        "一仓一目录 · 一仓一机器码 · 一仓一出口契约",
        &[
            (
                "1. 物理目录与配置隔离",
                "为每个账号仓分配独立 --user-data-dir、CLAUDE_CONFIG_DIR 与 CODEX_HOME，彻底杜绝 Cookies 串号。",
            ),
            (
                "2. 出口契约与独立冷却",
                "同仓跨洲换 IP 自动触发防瞬移冷却，但不同主权仓跨国交替使用互不误报。",
            ),
            (
                "3. 桌面快捷方式直启",
                "一键生成桌面 .lnk，点击即可自动完成 6 步安全门禁校验并注入对应仓的隔离环境。",
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
        .child(div().w_full().flex().child(header_card))
        .when_some(drawer_el, |col, d| col.child(d))
        .children(grid_rows)
        .when_some(empty_placeholder, |col, e| col.child(e))
        .child(choreo.tile(2, 0).apply(guide))
}
