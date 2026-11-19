//! Shared composite UI widgets reused across Mode B Console views.

use crate::theme::ThemePalette;
use crate::widgets::controls::{inset_box, mono_tabular, toggle_switch};
use gpui::{Div, Entity, FontWeight, MouseButton, div, prelude::*, px, rgb};
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
        .p(px(10.))
        .gap(px(3.))
        .child(
            div()
                .text_size(px(11.))
                .text_color(rgb(p.text_muted))
                .child(label),
        )
        .child(val_el)
        .child(
            div()
                .truncate()
                .text_size(px(10.5))
                .text_color(rgb(p.text_muted))
                .child(sub),
        )
}


pub fn info_mini_box(label: &'static str, value: String, p: &ThemePalette) -> Div {
    inset_box(p)
        .flex_1()
        .p(px(10.))
        .gap(px(3.))
        .child(
            div()
                .text_size(px(10.5))
                .text_color(rgb(p.text_muted))
                .child(label),
        )
        .child(
            mono_tabular(value)
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
        .flex()
        .flex_col()
        .gap(px(4.))
        .child(
            div()
                .text_size(px(11.5))
                .font_weight(FontWeight::MEDIUM)
                .text_color(rgb(p.text_secondary))
                .child(label),
        )
        .child(input)
}

pub fn switch_row(
    id: &'static str,
    title: &'static str,
    hint: &'static str,
    on: bool,
    p: &ThemePalette,
    on_click: impl Fn(&gpui::MouseUpEvent, &mut gpui::Window, &mut gpui::App) + 'static,
) -> Div {
    inset_box(p)
        .flex_row()
        .items_center()
        .justify_between()
        .px(px(12.))
        .py(px(9.))
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
                        .text_size(px(12.5))
                        .font_weight(FontWeight::MEDIUM)
                        .text_color(rgb(p.text_primary))
                        .child(title),
                )
                .child(
                    div()
                        .text_size(px(11.))
                        .text_color(rgb(p.text_muted))
                        .child(hint),
                ),
        )
        .child(toggle_switch(id, on, true, p).on_mouse_up(MouseButton::Left, on_click))
}

