//! Pure-GPUI Frost Ceramic primitives: `bento_card`, `guide_card`, `inset_box`,
//! `subtab_bar` / `subtab_item`, `toggle_switch`, `action_button`, `icon_action_button`,
//! semantic pills, and tabular-numeral mono text helper.

use crate::assets::ui_icon;
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

/// Primary Frost Ceramic tile container (`16px` radius, `1px` crisp border, subtle ceramic shadow).
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
            BoxShadow::new(px(0.), px(4.), rgba(p.shadow_rgba).into()).blur_radius(px(14.)),
        ])
}

/// Translucent Frost Ceramic page guide container (`14px` radius, calm `guide_bg`).
pub fn guide_card(p: &ThemePalette) -> Div {
    div()
        .flex()
        .flex_col()
        .min_w(px(0.))
        .rounded(px(14.))
        .bg(rgb(p.guide_bg))
        .border_1()
        .border_color(rgb(p.card_border))
}

/// Subtle inner inset card (`11px` radius, `inset_bg` / `inset_border`).
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

/// Compact `.cc` country pill badge.
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
        .py(px(2.5))
        .rounded(px(999.))
        .bg(rgba(b.bg))
        .child(div().w(px(5.5)).h(px(5.5)).rounded(px(999.)).bg(rgb(b.dot)))
        .child(
            div()
                .text_size(px(10.5))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(rgb(b.text))
                .child(label.into()),
        )
}

/// Compact pill without dot (used for update status tags & plugin tags).
pub fn tone_tag(label: impl Into<gpui::SharedString>, tone: BadgeTone, p: &ThemePalette) -> Div {
    let b = p.badge(tone);
    div()
        .flex_shrink_0()
        .whitespace_nowrap()
        .px(px(7.5))
        .py(px(2.))
        .rounded(px(999.))
        .bg(rgba(b.bg))
        .text_size(px(10.5))
        .font_weight(FontWeight::SEMIBOLD)
        .text_color(rgb(b.text))
        .child(label.into())
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
        .gap(px(5.))
        .h(px(30.))
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

/// Compact button with leading monochrome SVG icon.
pub fn icon_action_button(
    id: impl Into<ElementId>,
    icon_path: &'static str,
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
        .gap(px(5.))
        .h(px(30.))
        .px(px(11.))
        .rounded(px(layout::RADIUS_CONTROL))
        .bg(rgb(bg))
        .border_1()
        .border_color(rgb(border))
        .text_size(px(11.5))
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
    btn.child(ui_icon(icon_path, 12.0, text)).child(label.into())
}

/// Interactive pill toggle switch (`34x19` Frost Ceramic spec).
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
    let knob_ml = if on { px(17.) } else { px(2.) };
    let mut el = div()
        .id(id)
        .flex()
        .flex_shrink_0()
        .items_center()
        .w(px(34.))
        .h(px(19.))
        .rounded(px(999.))
        .bg(rgb(track))
        .child(
            div()
                .w(px(15.))
                .h(px(15.))
                .rounded(px(999.))
                .bg(rgb(p.toggle_knob))
                .ml(knob_ml),
        );
    if enabled {
        el = el.cursor_pointer();
    }
    el
}

/// Subtab bar container (`gd-subtab-bar`).
pub fn subtab_bar(p: &ThemePalette) -> Div {
    div()
        .flex()
        .items_center()
        .gap(px(2.))
        .p(px(3.))
        .rounded(px(10.))
        .bg(rgb(p.inset_bg))
        .border_1()
        .border_color(rgb(p.card_border))
}

/// Subtab button item (`gd-subtab`), optional indicator dot or right count.
pub fn subtab_item(
    id: impl Into<ElementId>,
    label: &'static str,
    active: bool,
    dot_color: Option<u32>,
    badge_right: Option<String>,
    p: &ThemePalette,
) -> Stateful<Div> {
    let mut item = div()
        .id(id)
        .flex()
        .items_center()
        .gap(px(6.))
        .h(px(27.))
        .px(px(12.))
        .rounded(px(7.))
        .cursor_pointer()
        .text_size(px(12.))
        .font_weight(if active {
            FontWeight::SEMIBOLD
        } else {
            FontWeight::MEDIUM
        })
        .text_color(rgb(if active {
            p.text_primary
        } else {
            p.text_secondary
        }));

    if active {
        item = item
            .bg(rgb(p.card_bg))
            .shadow(vec![
                BoxShadow::new(px(0.), px(1.), rgba(p.shadow_rgba).into()).blur_radius(px(3.)),
            ]);
    } else {
        let hover_txt = p.text_primary;
        item = item.hover(move |s| s.text_color(rgb(hover_txt)));
    }
    item = item.child(label);
    if let Some(txt) = badge_right {
        item = item.child(
            mono_tabular(txt)
                .text_size(px(10.5))
                .text_color(rgb(p.text_muted)),
        );
    }
    if let Some(dot) = dot_color {
        item = item.child(div().w(px(6.)).h(px(6.)).rounded(px(999.)).bg(rgb(dot)));
    }
    item
}

/// Capsule container for 2/3-way segmented controls (`CutMode`, etc.).
pub fn segmented_capsule_track(p: &ThemePalette) -> Div {
    div()
        .flex()
        .items_center()
        .w_full()
        .gap(px(2.))
        .p(px(3.))
        .rounded(px(9.))
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
        .flex_1()
        .flex()
        .items_center()
        .justify_center()
        .h(px(27.))
        .px(px(10.))
        .rounded(px(7.))
        .text_size(px(11.5))
        .cursor_pointer()
        .font_weight(if active {
            FontWeight::SEMIBOLD
        } else {
            FontWeight::MEDIUM
        })
        .text_color(rgb(if active {
            p.capsule_active_text
        } else {
            p.text_secondary
        }));

    if active {
        item = item
            .bg(rgb(p.capsule_active_bg))
            .shadow(vec![
                BoxShadow::new(px(0.), px(1.), rgba(p.shadow_rgba).into()).blur_radius(px(3.)),
            ]);
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
                .text_size(px(12.5))
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
