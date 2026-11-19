//! Pure-GPUI Glass Bento primitives: `BentoCard`, `ToggleSwitch`, `SegmentedCapsule`,
//! `.cc` country badge, semantic pills, buttons, and tabular-numeral mono text helper.

use crate::theme::{BadgeTone, ThemePalette, layout};
use gpui::{
    BoxShadow, Div, ElementId, FontFeatures, FontWeight, Stateful, div, prelude::*, px, rgb, rgba,
};
use std::sync::Arc;

/// Returns OpenType tabular-numerals `FontFeatures` (`tnum = 1`).
pub fn tabular_features() -> FontFeatures {
    FontFeatures(Arc::new(vec![("tnum".into(), 1)]))
}

/// Monospace tabular-numeral `Div` wrapper for IP addresses, latency metrics, and timestamps.
pub fn mono_tabular(text: impl Into<gpui::SharedString>) -> Div {
    div()
        .font_family("Cascadia Mono")
        .font_features(tabular_features())
        .child(text.into())
}

/// Primary Scheme C Bento Card container (`16px` radius, `1px` border, subtle shadow).
pub fn bento_card(p: &ThemePalette) -> Div {
    div()
        .flex()
        .flex_col()
        .min_w(px(0.))
        .rounded(px(layout::RADIUS_BENTO))
        .bg(rgb(p.card_bg))
        .border_1()
        .border_color(rgb(p.card_border))
        .shadow(vec![
            BoxShadow::new(px(0.), px(6.), rgba(p.shadow_rgba).into()).blur_radius(px(18.)),
        ])
}

/// Subtle inner inset card (`12px` radius, `inset_bg` / `inset_border`).
pub fn inset_box(p: &ThemePalette) -> Div {
    div()
        .flex()
        .flex_col()
        .min_w(px(0.))
        .rounded(px(layout::RADIUS_INSET))
        .bg(rgb(p.inset_bg))
        .border_1()
        .border_color(rgb(p.inset_border))
}

/// Compact `.cc` country pill badge (e.g., `US`, `HK`, `SG`).
pub fn cc_badge(code: &str, p: &ThemePalette) -> Div {
    div()
        .flex_shrink_0()
        .whitespace_nowrap()
        .px(px(7.))
        .py(px(2.))
        .rounded(px(6.))
        .bg(rgb(p.cc_pill_bg))
        .text_size(px(10.5))
        .font_weight(FontWeight::SEMIBOLD)
        .font_family("Cascadia Mono")
        .text_color(rgb(p.cc_pill_text))
        .child(code.to_string())
}

/// Semantic pill with leading status dot and tinted background.
pub fn status_pill(label: impl Into<gpui::SharedString>, tone: BadgeTone, p: &ThemePalette) -> Div {
    let b = p.badge(tone);
    div()
        .flex()
        .flex_shrink_0()
        .whitespace_nowrap()
        .items_center()
        .gap(px(5.))
        .px(px(8.))
        .py(px(3.))
        .rounded(px(999.))
        .bg(rgba(b.bg))
        .child(div().w(px(6.)).h(px(6.)).rounded(px(999.)).bg(rgb(b.dot)))
        .child(
            div()
                .text_size(px(11.))
                .font_weight(FontWeight::MEDIUM)
                .text_color(rgb(b.text))
                .child(label.into()),
        )
}

/// Latency / metadata chip (`54ms` tabular numeral).
pub fn latency_pill(label: impl Into<gpui::SharedString>, p: &ThemePalette) -> Div {
    div()
        .flex_shrink_0()
        .whitespace_nowrap()
        .px(px(7.))
        .py(px(2.))
        .rounded(px(6.))
        .bg(rgb(p.inset_bg))
        .border_1()
        .border_color(rgb(p.inset_border))
        .text_size(px(10.5))
        .text_color(rgb(p.text_muted))
        .font_family("Cascadia Mono")
        .font_features(tabular_features())
        .child(label.into())
}

/// Button visual variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ButtonKind {
    Primary,
    Secondary,
    Danger,
    Ghost,
}

pub fn action_button(
    id: impl Into<ElementId>,
    label: impl Into<gpui::SharedString>,
    kind: ButtonKind,
    enabled: bool,
    p: &ThemePalette,
) -> Stateful<Div> {
    let (bg, border, text) = match (kind, enabled) {
        (_, false) => (p.inset_bg, p.inset_border, p.text_muted),
        (ButtonKind::Primary, true) => (p.primary_btn_bg, p.primary_btn_bg, p.primary_btn_text),
        (ButtonKind::Danger, true) => (p.danger_btn_bg, p.danger_btn_bg, p.danger_btn_text),
        (ButtonKind::Secondary, true) => (
            p.secondary_btn_bg,
            p.secondary_btn_border,
            p.secondary_btn_text,
        ),
        (ButtonKind::Ghost, true) => (p.card_bg, p.card_border, p.text_secondary),
    };

    let mut btn = div()
        .id(id)
        .flex()
        .flex_shrink_0()
        .whitespace_nowrap()
        .items_center()
        .justify_center()
        .gap(px(6.))
        .h(px(32.))
        .px(px(12.))
        .rounded(px(layout::RADIUS_CONTROL))
        .bg(rgb(bg))
        .border_1()
        .border_color(rgb(border))
        .text_size(px(12.))
        .font_weight(FontWeight::MEDIUM)
        .text_color(rgb(text));

    if enabled {
        let hover_bg = match kind {
            ButtonKind::Primary => p.primary_btn_hover_bg,
            ButtonKind::Danger => 0xB91C1C,
            ButtonKind::Secondary | ButtonKind::Ghost => p.sidebar_hover_bg,
        };
        btn = btn.cursor_pointer().hover(move |s| s.bg(rgb(hover_bg)));
    }
    btn.child(label.into())
}

/// Interactive pill toggle switch (`38x22`).
pub fn toggle_switch(
    id: impl Into<ElementId>,
    on: bool,
    enabled: bool,
    p: &ThemePalette,
) -> Stateful<Div> {
    let track = if !enabled {
        p.inset_border
    } else if on {
        p.toggle_track_on
    } else {
        p.toggle_track_off
    };
    let knob_ml = if on { px(18.) } else { px(3.) };
    let mut el = div()
        .id(id)
        .flex()
        .items_center()
        .w(px(38.))
        .h(px(22.))
        .rounded(px(999.))
        .bg(rgb(track))
        .child(
            div()
                .w(px(16.))
                .h(px(16.))
                .rounded(px(999.))
                .bg(rgb(p.toggle_knob))
                .ml(knob_ml),
        );
    if enabled {
        el = el.cursor_pointer();
    }
    el
}

/// Capsule container for 3-way segmented controls (`PolicyPreset`, `CutMode`, `ThemeMode`).
pub fn segmented_capsule_track(p: &ThemePalette) -> Div {
    div()
        .flex()
        .items_center()
        .gap(px(2.))
        .p(px(3.))
        .rounded(px(10.))
        .bg(rgb(p.capsule_track_bg))
        .border_1()
        .border_color(rgb(p.card_border))
}

pub fn segmented_capsule_item(
    id: impl Into<ElementId>,
    label: &'static str,
    active: bool,
    p: &ThemePalette,
) -> Stateful<Div> {
    let mut item = div()
        .id(id)
        .px(px(10.))
        .py(px(4.))
        .rounded(px(7.))
        .text_size(px(11.5))
        .cursor_pointer()
        .font_weight(if active {
            FontWeight::SEMIBOLD
        } else {
            FontWeight::NORMAL
        })
        .text_color(rgb(if active {
            p.capsule_active_text
        } else {
            p.text_muted
        }));

    if active {
        item = item.bg(rgb(p.capsule_active_bg));
    } else {
        let hover = p.sidebar_hover_bg;
        item = item.hover(move |s| s.bg(rgb(hover)));
    }
    item.child(label)
}

/// Small section heading inside Bento cards.
pub fn card_header(
    title: &'static str,
    right_tag: impl Into<gpui::SharedString>,
    p: &ThemePalette,
) -> Div {
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
                .child(title),
        )
        .child(
            div()
                .text_size(px(11.))
                .text_color(rgb(p.text_muted))
                .child(right_tag.into()),
        )
}
