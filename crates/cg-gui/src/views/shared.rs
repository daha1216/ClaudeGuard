//! Shared composite UI widgets reused across Frost Ceramic Console views.

use crate::theme::ThemePalette;
use crate::widgets::controls::{guide_card, inset_box, mono_tabular, toggle_switch};
use gpui::{Div, Entity, FontWeight, MouseButton, div, prelude::*, px, rgb};

/// Stable brand-family sort key so siblings with matching brand icons/colors
/// (Anthropic: Claude + Claude Code; OpenAI: ChatGPT + Codex CLI; Google: Antigravity)
/// always stay visually grouped together.
pub fn brand_family_rank(id: &str) -> u8 {
    match id.trim().to_ascii_lowercase().as_str() {
        "claude" | "claude_desktop" | "claude-desktop" => 0,
        "claude-code" | "claude_code" => 1,
        "chatgpt" | "codex_desktop" | "codex-desktop" => 2,
        "codex" | "codex-cli" | "codex_cli" => 3,
        "antigravity" | "antigravity_ide" | "antigravity-ide" => 4,
        "antigravity_cn" | "antigravity-cn" => 5,
        "local" => 12,
        _ => 20,
    }
}

/// Harmonized display label across Launch Deck, Process Governance, Vaults, and Breaker views.
pub fn canonical_agent_label<'a>(id: &str, fallback: &'a str) -> &'a str {
    match id.trim().to_ascii_lowercase().as_str() {
        "all" => "全部受管端",
        "claude" | "claude_desktop" | "claude-desktop" => "Claude",
        "claude-code" | "claude_code" => "Claude Code",
        "chatgpt" | "codex_desktop" | "codex-desktop" => "ChatGPT",
        "codex" | "codex-cli" | "codex_cli" => "Codex CLI",
        "antigravity" | "antigravity_ide" | "antigravity-ide" => "Antigravity",
        "antigravity_cn" | "antigravity-cn" => "Antigravity 汉化包",
        _ => fallback,
    }
}

/// Compact diagnostic metric tile (`gd-diag-box`).
pub fn ag_diag_tile(
    label: &'static str,
    primary: String,
    sub: String,
    primary_color: u32,
    mono: bool,
    p: &ThemePalette,
) -> Div {
    let val_el = if mono {
        mono_tabular(primary)
    } else {
        div().child(primary)
    }
    .truncate()
    .text_size(px(12.5))
    .font_weight(FontWeight::SEMIBOLD)
    .text_color(rgb(primary_color));

    inset_box(p)
        .flex_1()
        .flex_basis(px(0.))
        .min_w(px(0.))
        .px(px(12.))
        .py(px(9.))
        .gap(px(3.))
        .child(
            div()
                .text_size(px(10.5))
                .text_color(rgb(p.text_muted))
                .child(label),
        )
        .child(val_el)
        .child(
            div()
                .truncate()
                .text_size(px(10.5))
                .text_color(rgb(p.text_secondary))
                .child(sub),
        )
}

pub fn info_mini_box(label: &'static str, value: String, p: &ThemePalette) -> Div {
    inset_box(p)
        .flex_1()
        .flex_basis(px(0.))
        .min_w(px(0.))
        .px(px(11.))
        .py(px(8.))
        .gap(px(2.))
        .child(
            div()
                .text_size(px(10.5))
                .text_color(rgb(p.text_muted))
                .child(label),
        )
        .child(
            mono_tabular(value)
                .truncate()
                .text_size(px(12.))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(rgb(p.text_primary)),
        )
}

pub fn labeled_field(
    label: &'static str,
    input: Entity<crate::widgets::text_input::DraftTextInput>,
    p: &ThemePalette,
) -> Div {
    div()
        .flex_1()
        .flex_basis(px(0.))
        .min_w(px(0.))
        .flex()
        .flex_col()
        .gap(px(4.))
        .child(
            div()
                .text_size(px(10.5))
                .font_weight(FontWeight::MEDIUM)
                .text_color(rgb(p.text_muted))
                .child(label),
        )
        .child(input)
}

/// Clean divider-separated switch row matching Frost Ceramic `gd-sub-row` / `gd-sw-cell`.
pub fn switch_row(
    id: &'static str,
    title: &'static str,
    hint: &'static str,
    on: bool,
    p: &ThemePalette,
    on_click: impl Fn(&gpui::MouseUpEvent, &mut gpui::Window, &mut gpui::App) + 'static,
) -> Div {
    switch_row_gated(id, title, hint, on, true, p, on_click)
}

/// Divider-separated switch row with explicit interactive `enabled` gating.
pub fn switch_row_gated(
    id: &'static str,
    title: &'static str,
    hint: &'static str,
    on: bool,
    enabled: bool,
    p: &ThemePalette,
    on_click: impl Fn(&gpui::MouseUpEvent, &mut gpui::Window, &mut gpui::App) + 'static,
) -> Div {
    div()
        .flex()
        .flex_row()
        .items_center()
        .justify_between()
        .w_full()
        .min_w(px(0.))
        .py(px(8.))
        .gap(px(12.))
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(2.))
                .flex_1()
                .min_w(px(0.))
                .child(
                    div()
                        .text_size(px(12.))
                        .font_weight(FontWeight::MEDIUM)
                        .text_color(rgb(if enabled {
                            p.text_primary
                        } else {
                            p.text_muted
                        }))
                        .child(title),
                )
                .child(
                    div()
                        .text_size(px(10.5))
                        .line_height(px(14.5))
                        .text_color(rgb(p.text_muted))
                        .child(hint),
                ),
        )
        .child(
            toggle_switch(id, on, enabled, p)
                .when(enabled, |sw| sw.on_mouse_up(MouseButton::Left, on_click)),
        )
}

/// Structured 2-column or 3-column plain-language guide card (`gd-guide-card`).
pub fn page_guide_card(
    title: &'static str,
    subtitle: &'static str,
    items: &[(&'static str, &'static str)],
    p: &ThemePalette,
) -> Div {
    let cols = items.iter().map(|(heading, body)| {
        div()
            .flex()
            .flex_col()
            .flex_1()
            .flex_basis(px(0.))
            .min_w(px(0.))
            .gap(px(2.5))
            .child(
                div()
                    .text_size(px(11.5))
                    .line_height(px(15.5))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(rgb(p.text_primary))
                    .child(*heading),
            )
            .child(
                div()
                    .text_size(px(11.))
                    .line_height(px(16.))
                    .text_color(rgb(p.text_secondary))
                    .child(*body),
            )
    });

    guide_card(p)
        .w_full()
        .px(px(15.))
        .py(px(10.5))
        .gap(px(7.))
        .when(!title.is_empty() || !subtitle.is_empty(), |card| {
            card.child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap(px(8.))
                    .child(
                        div()
                            .flex_shrink_0()
                            .text_size(px(12.))
                            .line_height(px(16.))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(rgb(p.text_primary))
                            .child(title),
                    )
                    .child(
                        div()
                            .truncate()
                            .text_size(px(10.5))
                            .line_height(px(15.))
                            .text_color(rgb(p.text_muted))
                            .child(subtitle),
                    ),
            )
        })
        .child(
            div()
                .flex()
                .flex_row()
                .w_full()
                .min_w(px(0.))
                .gap(px(16.))
                .children(cols),
        )
}
