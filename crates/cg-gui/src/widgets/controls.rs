//! Pure-GPUI Frost Ceramic v2 primitives: `bento_card`, `bento_card_bloom`, `guide_card`,
//! `guide_card_bloom`, `inset_box`, `subtab_bar` / `subtab_item`, spring-driven `toggle_switch`,
//! `action_button`, `icon_action_button`, `spinning_ui_icon`, `status_dot` / `pulse_status_dot`,
//! `float_shadow`, semantic pills, and cached tabular-numeral mono text helpers.

use crate::assets::ui_icon;
use crate::motion::{lerp_rgb, rgba_with_alpha_scale, spring_snappy};
use crate::theme::{BadgeTone, ThemePalette, layout};
use gpui::{
    Animation, AnimationExt, AnyElement, App, Background, BorderStyle, Bounds, BoxShadow, Corners,
    Div, Edges, Element, ElementId, FontFeatures, FontWeight, GlobalElementId, Hsla,
    InspectorElementId, IntoElement, LayoutId, ParentElement, Pixels, Rgba, SpringAnimation,
    Stateful, StyleRefinement, Styled, Transformation, Window, div, linear_color_stop,
    linear_gradient, point, prelude::*, px, quad, radians, rgb, rgba, svg,
};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

static TABULAR_FEATURES: OnceLock<FontFeatures> = OnceLock::new();

/// Returns OpenType tabular-numerals `FontFeatures` (`tnum = 1`), cached globally
/// to eliminate per-frame allocations across cards, telemetry, and tables.
pub fn tabular_features() -> FontFeatures {
    TABULAR_FEATURES
        .get_or_init(|| FontFeatures(Arc::new(vec![("tnum".into(), 1)])))
        .clone()
}

/// Monospace tabular-numeral `Div` wrapper for IP addresses, latency metrics, and timestamps.
pub fn mono_tabular(text: impl Into<gpui::SharedString>) -> Div {
    div()
        .font_family("Cascadia Mono")
        .font_features(tabular_features())
        .child(text.into())
}

/// Layered Apple-grade floating elevation shadow for modals, popovers, dropdowns, and toasts.
pub fn float_shadow(p: &ThemePalette) -> Vec<BoxShadow> {
    vec![
        BoxShadow::new(px(0.), px(14.), rgba(p.shadow_float_rgba).into())
            .blur_radius(px(34.))
            .spread_radius(px(-4.)),
        BoxShadow::new(px(0.), px(3.), rgba(p.shadow_rgba).into()).blur_radius(px(10.)),
    ]
}

/// Primary matte-porcelain ceramic tile container (`16px` radius, calm 1px hairline border,
/// fast-path 0-blur top specular highlight + single refined ambient elevation shadow).
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
            BoxShadow::new(px(0.), px(1.), rgba(p.specular_top_rgba).into()).inset(),
            BoxShadow::new(px(0.), px(3.), rgba(p.shadow_rgba).into())
                .blur_radius(px(9.))
                .spread_radius(px(-1.5)),
        ])
}

/// Zero-layout-cost pure horizontal pane translator using GPUI's `window.with_element_offset`.
///
/// Keeps Taffy flexbox layout 100% invariant at `(0, 0)` on every animation frame while translating
/// the entire child subtree horizontally in `prepaint` in O(1), eliminating layout thrashing.
pub struct OffsetPane {
    dx: f32,
    child: Option<AnyElement>,
}

/// Wraps `child` in a zero-Taffy-reflow pure horizontal [`OffsetPane`] (`dy == 0.0` strictly).
pub fn offset_pane(dx: f32, child: impl IntoElement) -> OffsetPane {
    OffsetPane {
        dx,
        child: Some(child.into_any_element()),
    }
}

impl IntoElement for OffsetPane {
    type Element = Self;

    fn into_element(self) -> Self::Element {
        self
    }
}

impl Element for OffsetPane {
    type RequestLayoutState = AnyElement;
    type PrepaintState = ();

    fn id(&self) -> Option<ElementId> {
        None
    }

    fn source_location(&self) -> Option<&'static std::panic::Location<'static>> {
        None
    }

    fn request_layout(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&InspectorElementId>,
        window: &mut Window,
        cx: &mut App,
    ) -> (LayoutId, Self::RequestLayoutState) {
        let mut child = self.child.take().expect("OffsetPane rendered once");
        let layout_id = child.request_layout(window, cx);
        (layout_id, child)
    }

    fn prepaint(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&InspectorElementId>,
        _bounds: Bounds<Pixels>,
        child: &mut Self::RequestLayoutState,
        window: &mut Window,
        cx: &mut App,
    ) -> Self::PrepaintState {
        if self.dx.abs() >= 0.05 {
            window.with_element_offset(point(px(self.dx), px(0.0)), |window| {
                child.prepaint(window, cx);
            });
        } else {
            child.prepaint(window, cx);
        }
    }

    fn paint(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&InspectorElementId>,
        _bounds: Bounds<Pixels>,
        child: &mut Self::RequestLayoutState,
        _prepaint: &mut Self::PrepaintState,
        window: &mut Window,
        cx: &mut App,
    ) {
        child.paint(window, cx);
    }
}

/// Zero-reflow GPU paint-time symmetric unfolding ceramic card element.
///
/// Inner layout padding `(pad_x, pad_y)` and every child text/control coordinate stay 100% frozen
/// across every animation frame (zero Taffy flexbox re-layout, zero ±1px subpixel text jitter),
/// while the ceramic card shell (background quad + 1px hairline border + lean ambient shadow +
/// top specular highlight) expands symmetrically outward from its own center in GPU `paint()`.
pub struct BloomCard {
    inner: Option<Div>,
    pose: crate::motion::SlotPose,
    base_radius: f32,
    pad_x: f32,
    pad_y: f32,
    default_bg: u32,
    default_border: u32,
    shadow_rgba: u32,
    specular_top_rgba: u32,
    with_shadow: bool,
}

#[doc(hidden)]
pub struct BloomShellSpec {
    bg: Background,
    border: Hsla,
}

#[doc(hidden)]
pub struct BloomCardLayoutState {
    child: AnyElement,
    shell: Option<BloomShellSpec>,
}

impl BloomCard {
    fn new(
        base_div: Div,
        p: &ThemePalette,
        pose: crate::motion::SlotPose,
        base_radius: f32,
        pad_x: f32,
        pad_y: f32,
        with_shadow: bool,
    ) -> Self {
        Self {
            inner: Some(base_div.px(px(pad_x)).py(px(pad_y))),
            pose,
            base_radius,
            pad_x,
            pad_y,
            default_bg: if with_shadow { p.card_bg } else { p.guide_bg },
            default_border: p.card_border,
            shadow_rgba: p.shadow_rgba,
            specular_top_rgba: p.specular_top_rgba,
            with_shadow,
        }
    }

    /// Computes the clamped `(sx, sy)` shell inset in logical pixels for the current pose.
    pub fn shell_inset_xy(&self) -> (f32, f32) {
        if self.pose.is_settled() {
            (0.0, 0.0)
        } else {
            let sx = self.pose.inset_px.clamp(0.0, (self.pad_x - 2.0).max(0.0));
            let sy = (self.pose.inset_px * 0.78).clamp(0.0, (self.pad_y - 2.0).max(0.0));
            (sx, sy)
        }
    }
}

impl Styled for BloomCard {
    fn style(&mut self) -> &mut StyleRefinement {
        self.inner
            .as_mut()
            .expect("BloomCard styled before layout")
            .style()
    }
}

impl ParentElement for BloomCard {
    fn extend(&mut self, elements: impl IntoIterator<Item = AnyElement>) {
        self.inner
            .as_mut()
            .expect("BloomCard extended before layout")
            .extend(elements);
    }
}

impl IntoElement for BloomCard {
    type Element = Self;

    fn into_element(self) -> Self::Element {
        self
    }
}

impl Element for BloomCard {
    type RequestLayoutState = BloomCardLayoutState;
    type PrepaintState = ();

    fn id(&self) -> Option<ElementId> {
        None
    }

    fn source_location(&self) -> Option<&'static std::panic::Location<'static>> {
        None
    }

    fn request_layout(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&InspectorElementId>,
        window: &mut Window,
        cx: &mut App,
    ) -> (LayoutId, Self::RequestLayoutState) {
        let mut div_el = self.inner.take().expect("BloomCard rendered once");
        if self.pose.is_settled() {
            let mut child = div_el.into_any_element();
            let layout_id = child.request_layout(window, cx);
            return (layout_id, BloomCardLayoutState { child, shell: None });
        }

        let style = div_el.style();
        let bg = style
            .background
            .take()
            .and_then(|fill| fill.color())
            .unwrap_or_else(|| rgb(self.default_bg).into());
        let border = style
            .border_color
            .take()
            .unwrap_or_else(|| rgb(self.default_border).into());
        style.border_widths = Default::default();
        style.box_shadow = None;
        style.opacity = Some(self.pose.opacity.clamp(0.0, 1.0));

        let mut child = div_el.into_any_element();
        let layout_id = child.request_layout(window, cx);
        (
            layout_id,
            BloomCardLayoutState {
                child,
                shell: Some(BloomShellSpec { bg, border }),
            },
        )
    }

    fn prepaint(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&InspectorElementId>,
        _bounds: Bounds<Pixels>,
        state: &mut Self::RequestLayoutState,
        window: &mut Window,
        cx: &mut App,
    ) -> Self::PrepaintState {
        state.child.prepaint(window, cx);
    }

    fn paint(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&InspectorElementId>,
        bounds: Bounds<Pixels>,
        state: &mut Self::RequestLayoutState,
        _prepaint: &mut Self::PrepaintState,
        window: &mut Window,
        cx: &mut App,
    ) {
        if let Some(shell) = &state.shell {
            let (sx, sy) = self.shell_inset_xy();
            let left = bounds.left() + px(sx);
            let top = bounds.top() + px(sy);
            let right = (bounds.right() - px(sx)).max(left);
            let bottom = (bounds.bottom() - px(sy)).max(top);
            let shell_bounds = Bounds::from_corners(point(left, top), point(right, bottom));
            let radii = Corners::all(px(self.base_radius + sx * 0.45));
            let op = self.pose.opacity.clamp(0.0, 1.0);
            let sh = (self.pose.shadow_alpha * op).clamp(0.0, 1.0);

            if self.with_shadow && sh > 0.01 {
                let drop = [BoxShadow::new(
                    px(0.),
                    px(3.),
                    rgba_with_alpha_scale(self.shadow_rgba, sh).into(),
                )
                .blur_radius(px(9.))
                .spread_radius(px(-1.5))];
                window.paint_drop_shadows(shell_bounds, radii, &drop);
            }

            window.paint_quad(quad(
                shell_bounds,
                radii,
                shell.bg.opacity(op),
                Edges::all(px(1.)),
                shell.border.opacity(op),
                BorderStyle::Solid,
            ));

            if self.with_shadow && sh > 0.01 {
                let inset = [BoxShadow::new(
                    px(0.),
                    px(1.),
                    rgba_with_alpha_scale(self.specular_top_rgba, sh).into(),
                )
                .inset()];
                window.paint_inset_shadows(shell_bounds, radii, &inset);
            }
        }

        state.child.paint(window, cx);
    }
}

/// Matte-porcelain ceramic Bento tile with zero-reflow GPU paint-time symmetric unfold.
///
/// Inner padding `(pad_x, pad_y)` and every child element remain 100% layout-invariant across all
/// frames (zero Taffy flexbox thrashing, zero ±1px text shake), while [`BloomCard::paint`] smoothly
/// unfolds the ceramic shell outward from its center and blooms elevation shadow in GPU shaders.
pub fn bento_card_bloom(
    p: &ThemePalette,
    pad_x: f32,
    pad_y: f32,
    pose: crate::motion::SlotPose,
) -> BloomCard {
    BloomCard::new(
        bento_card(p),
        p,
        pose,
        layout::RADIUS_BENTO,
        pad_x,
        pad_y,
        true,
    )
}

/// Applies a [`crate::motion::SlotPose`] choreography transform to a card or section `Div`.
pub fn choreo_slot(el: Div, pose: crate::motion::SlotPose) -> Div {
    pose.apply(el)
}

/// Sculpted macOS Tahoe Liquid Glass sliding capsule used in the Floating Dock and SubTab bars.
pub fn liquid_glass_pill(left_px: f32, width_px: f32, radius_px: f32, p: &ThemePalette) -> Div {
    div()
        .absolute()
        .top(px(0.))
        .bottom(px(0.))
        .left(px(left_px))
        .w(px(width_px))
        .rounded(px(radius_px))
        .bg(linear_gradient(
            180.0,
            linear_color_stop(rgb(p.dock_pill_top), 0.0),
            linear_color_stop(rgb(p.dock_pill_bottom), 1.0),
        ))
        .border_1()
        .border_color(rgb(p.sidebar_active_border))
        .shadow(vec![
            BoxShadow::new(px(0.), px(1.), rgba(p.specular_top_rgba).into()).inset(),
            BoxShadow::new(px(0.), px(2.), rgba(p.shadow_rgba).into())
                .blur_radius(px(6.))
                .spread_radius(px(-1.5)),
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

/// Translucent Frost Ceramic page guide container with zero-reflow GPU paint-time symmetric unfold.
pub fn guide_card_bloom(
    p: &ThemePalette,
    pad_x: f32,
    pad_y: f32,
    pose: crate::motion::SlotPose,
) -> BloomCard {
    BloomCard::new(guide_card(p), p, pose, 14.0, pad_x, pad_y, false)
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

/// Crisp circular semantic status indicator dot.
pub fn status_dot(color: u32, size_px: f32) -> Div {
    div()
        .flex_shrink_0()
        .w(px(size_px))
        .h(px(size_px))
        .rounded(px(999.))
        .bg(rgb(color))
}

/// Semantic status dot with an optional 30fps-capped breathing halo when `pulsing` is active.
///
/// Automatically renders statically under Windows Reduce Motion with zero idle frames.
pub fn pulse_status_dot(
    _id: impl Into<ElementId>,
    color: u32,
    size_px: f32,
    pulsing: bool,
) -> AnyElement {
    if !pulsing {
        return status_dot(color, size_px).into_any_element();
    }

    let halo_expand = 6.0_f32;
    let halo_size = size_px + halo_expand;
    let halo_offset = -halo_expand * 0.5;
    let halo_rgba = (color << 8) | 0x38;

    // Serene static concentric jewel halo (0% idle CPU/GPU; eliminates 30fps full-window redraw spam).
    div()
        .relative()
        .flex()
        .flex_shrink_0()
        .items_center()
        .justify_center()
        .w(px(size_px))
        .h(px(size_px))
        .child(
            div()
                .absolute()
                .top(px(halo_offset))
                .left(px(halo_offset))
                .w(px(halo_size))
                .h(px(halo_size))
                .rounded(px(999.))
                .bg(rgba(halo_rgba)),
        )
        .child(status_dot(color, size_px))
        .into_any_element()
}

/// Monochrome SVG icon that rotates smoothly around its center when `spinning` is true.
///
/// Uses a fixed raster size (`size(px(size_px))`) and GPU `Transformation::rotate`,
/// avoiding SVG atlas cache misses on every frame.
pub fn spinning_ui_icon(
    id: impl Into<ElementId>,
    path: &'static str,
    size_px: f32,
    color: u32,
    spinning: bool,
) -> AnyElement {
    let icon = svg()
        .path(path)
        .size(px(size_px))
        .flex_shrink_0()
        .text_color(rgb(color));

    if spinning {
        icon.with_animation(
            id,
            Animation::new(Duration::from_millis(800)).repeat(),
            |s, delta| {
                s.with_transformation(Transformation::rotate(radians(
                    std::f32::consts::TAU * delta,
                )))
            },
        )
        .into_any_element()
    } else {
        icon.into_any_element()
    }
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
        .child(status_dot(b.dot, 5.5))
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
    DangerSoft,
    Ghost,
}

#[derive(Clone)]
struct ButtonVisuals {
    bg: Background,
    border: Rgba,
    text: u32,
    hover_bg: Background,
    hover_border: Rgba,
    active_bg: Background,
    shadows: Vec<BoxShadow>,
}

fn button_visuals(kind: ButtonKind, enabled: bool, p: &ThemePalette) -> ButtonVisuals {
    if !enabled {
        let bg: Background = rgb(p.inset_bg).into();
        let border = rgb(p.inset_border);
        return ButtonVisuals {
            bg,
            border,
            text: p.text_muted,
            hover_bg: bg,
            hover_border: border,
            active_bg: bg,
            shadows: Vec::new(),
        };
    }

    match kind {
        ButtonKind::Primary => {
            let is_light_frosted = !p.is_dark && p.primary_btn_text != 0xFFFFFF;
            let is_dark_frosted = p.is_dark && p.primary_btn_text == 0xECF3FF;
            let (border, hover_border, active_bg) = if is_light_frosted {
                (
                    rgb(p.accent_soft_border),
                    lerp_rgb(p.accent_soft_border, p.primary_btn_text, 0.22),
                    lerp_rgb(p.primary_btn_bottom, p.accent_soft_border, 0.35).into(),
                )
            } else if is_dark_frosted {
                (
                    rgb(p.accent_soft_border),
                    lerp_rgb(p.accent_soft_border, p.primary_btn_text, 0.18),
                    lerp_rgb(p.primary_btn_bottom, p.frame_bg, 0.14).into(),
                )
            } else {
                let active_target = if p.is_dark { p.frame_bg } else { 0x000000 };
                let active_mix = if p.is_dark { 0.14 } else { 0.10 };
                (
                    rgb(p.primary_btn_bottom),
                    rgb(p.primary_btn_hover_bottom),
                    lerp_rgb(p.primary_btn_bottom, active_target, active_mix).into(),
                )
            };
            ButtonVisuals {
                bg: linear_gradient(
                    180.0,
                    linear_color_stop(rgb(p.primary_btn_top), 0.0),
                    linear_color_stop(rgb(p.primary_btn_bottom), 1.0),
                ),
                border,
                text: p.primary_btn_text,
                hover_bg: linear_gradient(
                    180.0,
                    linear_color_stop(rgb(p.primary_btn_hover_top), 0.0),
                    linear_color_stop(rgb(p.primary_btn_hover_bottom), 1.0),
                ),
                hover_border,
                active_bg,
                shadows: vec![
                    BoxShadow::new(px(0.), px(1.), rgba(p.primary_specular_rgba).into()).inset(),
                    BoxShadow::new(px(0.), px(2.), rgba(p.primary_shadow_rgba).into())
                        .blur_radius(px(7.))
                        .spread_radius(px(-1.)),
                ],
            }
        }
        ButtonKind::Danger => {
            let active_target = if p.is_dark { p.frame_bg } else { 0x000000 };
            ButtonVisuals {
                bg: rgb(p.danger_btn_bg).into(),
                border: rgb(p.danger_btn_bg),
                text: p.danger_btn_text,
                hover_bg: rgb(p.danger_btn_hover_bg).into(),
                hover_border: rgb(p.danger_btn_hover_bg),
                active_bg: lerp_rgb(p.danger_btn_hover_bg, active_target, 0.14).into(),
                shadows: vec![
                    BoxShadow::new(px(0.), px(1.), rgba(p.primary_specular_rgba).into()).inset(),
                    BoxShadow::new(px(0.), px(2.), rgba(p.shadow_rgba).into()).blur_radius(px(5.)),
                ],
            }
        }
        ButtonKind::DangerSoft => {
            let hover_mix = if p.is_dark { 0.24 } else { 0.12 };
            let active_mix = if p.is_dark { 0.34 } else { 0.20 };
            ButtonVisuals {
                bg: rgb(p.danger_soft_bg).into(),
                border: rgb(p.danger_soft_border),
                text: p.danger_soft_text,
                hover_bg: lerp_rgb(p.danger_soft_bg, p.danger_btn_bg, hover_mix).into(),
                hover_border: lerp_rgb(p.danger_soft_border, p.danger_btn_bg, 0.36),
                active_bg: lerp_rgb(p.danger_soft_bg, p.danger_btn_bg, active_mix).into(),
                shadows: Vec::new(),
            }
        }
        ButtonKind::Secondary => ButtonVisuals {
            bg: rgb(p.secondary_btn_bg).into(),
            border: rgb(p.secondary_btn_border),
            text: p.secondary_btn_text,
            hover_bg: rgb(p.sidebar_hover_bg).into(),
            hover_border: rgb(p.card_hover_border),
            active_bg: lerp_rgb(p.sidebar_hover_bg, p.inset_border, 0.50).into(),
            shadows: vec![
                BoxShadow::new(px(0.), px(1.), rgba(p.specular_top_rgba).into()).inset(),
                BoxShadow::new(px(0.), px(1.), rgba(p.shadow_rgba).into()).blur_radius(px(2.)),
            ],
        },
        ButtonKind::Ghost => ButtonVisuals {
            bg: rgb(p.card_bg).into(),
            border: rgb(p.card_border),
            text: p.text_secondary,
            hover_bg: rgb(p.sidebar_hover_bg).into(),
            hover_border: rgb(p.card_hover_border),
            active_bg: lerp_rgb(p.sidebar_hover_bg, p.inset_border, 0.50).into(),
            shadows: Vec::new(),
        },
    }
}

pub fn action_button(
    id: impl Into<ElementId>,
    label: impl Into<gpui::SharedString>,
    kind: ButtonKind,
    enabled: bool,
    p: &ThemePalette,
) -> Stateful<Div> {
    let v = button_visuals(kind, enabled, p);

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
        .bg(v.bg)
        .border_1()
        .border_color(v.border)
        .text_size(px(12.))
        .font_weight(FontWeight::MEDIUM)
        .text_color(rgb(v.text));

    if !v.shadows.is_empty() {
        btn = btn.shadow(v.shadows);
    }

    if enabled {
        let hover_bg = v.hover_bg;
        let hover_border = v.hover_border;
        let active_bg = v.active_bg;
        btn = btn
            .cursor_pointer()
            .hover(move |s| s.bg(hover_bg).border_color(hover_border))
            .active(move |s| s.bg(active_bg).opacity(0.92));
    }
    btn.child(label.into())
}

/// Compact button with leading monochrome SVG icon and tactile micro-press state.
pub fn icon_action_button(
    id: impl Into<ElementId>,
    icon_path: &'static str,
    label: impl Into<gpui::SharedString>,
    kind: ButtonKind,
    enabled: bool,
    p: &ThemePalette,
) -> Stateful<Div> {
    let v = button_visuals(kind, enabled, p);

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
        .bg(v.bg)
        .border_1()
        .border_color(v.border)
        .text_size(px(11.5))
        .font_weight(FontWeight::MEDIUM)
        .text_color(rgb(v.text));

    if !v.shadows.is_empty() {
        btn = btn.shadow(v.shadows);
    }

    if enabled {
        let hover_bg = v.hover_bg;
        let hover_border = v.hover_border;
        let active_bg = v.active_bg;
        btn = btn
            .cursor_pointer()
            .hover(move |s| s.bg(hover_bg).border_color(hover_border))
            .active(move |s| s.bg(active_bg).opacity(0.92));
    }
    btn.child(ui_icon(icon_path, 12.0, v.text))
        .child(label.into())
}

/// Sculpted button with a leading monochrome SVG icon that smoothly spins on the GPU when `spinning` is true.
pub fn spinning_action_button(
    id: impl Into<ElementId>,
    icon_path: &'static str,
    label: impl Into<gpui::SharedString>,
    kind: ButtonKind,
    enabled: bool,
    spinning: bool,
    p: &ThemePalette,
) -> Stateful<Div> {
    let el_id = id.into();
    let spin_id = ElementId::Name(format!("{el_id}-spin").into());
    let v = button_visuals(kind, enabled, p);

    let mut btn = div()
        .id(el_id)
        .flex()
        .flex_shrink_0()
        .whitespace_nowrap()
        .items_center()
        .justify_center()
        .gap(px(5.5))
        .h(px(30.))
        .px(px(12.))
        .rounded(px(layout::RADIUS_CONTROL))
        .bg(v.bg)
        .border_1()
        .border_color(v.border)
        .text_size(px(12.))
        .font_weight(FontWeight::MEDIUM)
        .text_color(rgb(v.text));

    if !v.shadows.is_empty() {
        btn = btn.shadow(v.shadows);
    }

    if enabled {
        let hover_bg = v.hover_bg;
        let hover_border = v.hover_border;
        let active_bg = v.active_bg;
        btn = btn
            .cursor_pointer()
            .hover(move |s| s.bg(hover_bg).border_color(hover_border))
            .active(move |s| s.bg(active_bg).opacity(0.92));
    }
    btn.child(spinning_ui_icon(spin_id, icon_path, 12.0, v.text, spinning))
        .child(label.into())
}

/// Interactive 120Hz spring-driven pill toggle switch (`34x19` Frost Ceramic v2 spec).
///
/// Smoothly animates knob travel (`2.0..17.0px`), subtle elastic mid-flight pill stretch,
/// and track color cross-fade via GPUI's native `with_spring` while respecting Reduce Motion.
pub fn toggle_switch(
    id: impl Into<ElementId>,
    on: bool,
    enabled: bool,
    p: &ThemePalette,
) -> Stateful<Div> {
    let track_off = p.toggle_track_off;
    let track_on = p.toggle_track_on;
    let disabled_track = p.inset_border;
    let knob_color = p.toggle_knob;
    let knob_shadow = p.shadow_rgba;

    let animated_track = div()
        .relative()
        .w(px(34.))
        .h(px(19.))
        .rounded(px(999.))
        .with_spring(
            "toggle-spring",
            SpringAnimation::new(spring_snappy())
                .to(on)
                .with_epsilon(0.002),
            move |track, phase| {
                let t = phase.0.clamp(0.0, 1.0);
                let stretch = 2.6 * (std::f32::consts::PI * t).sin();
                let knob_w = 15.0 + stretch;
                let raw_left = 2.0 + 15.0 * phase.0 - stretch * 0.5;
                let knob_left = raw_left.clamp(1.5, 32.5 - knob_w);
                let track_bg = if enabled {
                    lerp_rgb(track_off, track_on, t)
                } else {
                    rgb(disabled_track)
                };

                let mut knob = div()
                    .absolute()
                    .top(px(2.))
                    .left(px(knob_left))
                    .w(px(knob_w))
                    .h(px(15.))
                    .rounded(px(999.))
                    .bg(rgb(knob_color))
                    .shadow(vec![
                        BoxShadow::new(px(0.), px(0.5), rgba(knob_shadow).into())
                            .blur_radius(px(1.)),
                        BoxShadow::new(px(0.), px(1.5), rgba(knob_shadow).into())
                            .blur_radius(px(3.)),
                    ]);
                if !enabled {
                    knob = knob.opacity(0.78);
                }

                track
                    .bg(track_bg)
                    .shadow(vec![
                        BoxShadow::new(px(0.), px(1.), rgba(knob_shadow).into())
                            .blur_radius(px(1.5))
                            .inset(),
                    ])
                    .child(knob)
            },
        );

    let mut el = div()
        .id(id)
        .flex()
        .flex_shrink_0()
        .items_center()
        .w(px(34.))
        .h(px(19.))
        .child(animated_track);

    if enabled {
        el = el.cursor_pointer().active(|s| s.opacity(0.90));
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
            .bg(linear_gradient(
                180.0,
                linear_color_stop(rgb(p.dock_pill_top), 0.0),
                linear_color_stop(rgb(p.dock_pill_bottom), 1.0),
            ))
            .border_1()
            .border_color(rgb(p.sidebar_active_border))
            .shadow(vec![
                BoxShadow::new(px(0.), px(1.), rgba(p.specular_top_rgba).into()).inset(),
                BoxShadow::new(px(0.), px(1.5), rgba(p.shadow_rgba).into()).blur_radius(px(4.)),
            ])
            .active(|s| s.opacity(0.92));
    } else {
        let hover_txt = p.text_primary;
        let hover_bg = p.sidebar_hover_bg;
        let press_bg = p.inset_border;
        item = item
            .hover(move |s| s.text_color(rgb(hover_txt)).bg(rgb(hover_bg)))
            .active(move |s| s.bg(rgb(press_bg)).opacity(0.90));
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
        item = item.child(status_dot(dot, 6.0));
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
            ])
            .active(|s| s.opacity(0.92));
    } else {
        let hover_bg = p.sidebar_hover_bg;
        let hover_txt = p.text_primary;
        let press_bg = p.inset_border;
        item = item
            .hover(move |s| s.bg(rgb(hover_bg)).text_color(rgb(hover_txt)))
            .active(move |s| s.bg(rgb(press_bg)).opacity(0.90));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::theme::{CRYSTAL_GLASS_DARK, CRYSTAL_GLASS_LIGHT, LINEAR_INDIGO_LIGHT};

    #[test]
    fn primary_button_visuals_craft_frosted_crystal_and_solid_variants() {
        let light_crystal = button_visuals(ButtonKind::Primary, true, &CRYSTAL_GLASS_LIGHT);
        assert_eq!(
            light_crystal.border,
            rgb(CRYSTAL_GLASS_LIGHT.accent_soft_border)
        );
        assert_eq!(
            light_crystal.hover_border,
            lerp_rgb(
                CRYSTAL_GLASS_LIGHT.accent_soft_border,
                CRYSTAL_GLASS_LIGHT.primary_btn_text,
                0.22
            )
        );
        assert_eq!(light_crystal.text, CRYSTAL_GLASS_LIGHT.primary_btn_text);
        assert_eq!(light_crystal.shadows.len(), 2);

        let dark_crystal = button_visuals(ButtonKind::Primary, true, &CRYSTAL_GLASS_DARK);
        assert_eq!(
            dark_crystal.border,
            rgb(CRYSTAL_GLASS_DARK.accent_soft_border)
        );
        assert_eq!(dark_crystal.text, CRYSTAL_GLASS_DARK.primary_btn_text);

        let solid_indigo = button_visuals(ButtonKind::Primary, true, &LINEAR_INDIGO_LIGHT);
        assert_eq!(
            solid_indigo.border,
            rgb(LINEAR_INDIGO_LIGHT.primary_btn_bottom)
        );
        assert_eq!(
            solid_indigo.hover_border,
            rgb(LINEAR_INDIGO_LIGHT.primary_btn_hover_bottom)
        );
        assert_eq!(solid_indigo.text, 0xFFFFFF);
    }

    #[test]
    fn bento_and_guide_card_bloom_construct_cleanly_for_settled_and_unfolding_poses() {
        use crate::motion::{PageChoreo, SlotPose};
        use gpui::{AbsoluteLength, DefiniteLength};

        let pad_x = 16.0_f32;
        let pad_y = 14.0_f32;

        // Settled poses delegate cleanly with zero margin, zero shell inset, and exact padding
        let mut bento_settled =
            bento_card_bloom(&CRYSTAL_GLASS_LIGHT, pad_x, pad_y, SlotPose::SETTLED);
        assert_eq!(bento_settled.shell_inset_xy(), (0.0, 0.0));
        assert_eq!(bento_settled.style().margin.left, None);
        assert_eq!(bento_settled.style().margin.top, None);
        assert_eq!(
            bento_settled.style().padding.left,
            Some(DefiniteLength::Absolute(AbsoluteLength::Pixels(px(pad_x))))
        );
        assert_eq!(
            bento_settled.style().padding.top,
            Some(DefiniteLength::Absolute(AbsoluteLength::Pixels(px(pad_y))))
        );
        assert_eq!(bento_settled.style().opacity, None);

        let mut guide_settled =
            guide_card_bloom(&CRYSTAL_GLASS_DARK, pad_x, pad_y, SlotPose::SETTLED);
        assert_eq!(guide_settled.shell_inset_xy(), (0.0, 0.0));
        assert_eq!(guide_settled.style().margin.left, None);
        assert_eq!(
            guide_settled.style().padding.left,
            Some(DefiniteLength::Absolute(AbsoluteLength::Pixels(px(pad_x))))
        );

        // Unfolding poses keep Taffy margin == None and padding == exact (pad_x, pad_y)
        // (zero layout thrash, zero ±1px text shake) while GPU paint_quad handles shell inset.
        let unfolding_pose = PageChoreo {
            elapsed_s: 0.10,
            direction: 1,
            active: true,
        }
        .tile(0, 1);
        assert!(!unfolding_pose.is_settled());

        let expected_sx = unfolding_pose.inset_px.clamp(0.0, (pad_x - 2.0).max(0.0));
        let expected_sy = (unfolding_pose.inset_px * 0.78).clamp(0.0, (pad_y - 2.0).max(0.0));

        let mut bento_unfolding =
            bento_card_bloom(&CRYSTAL_GLASS_LIGHT, pad_x, pad_y, unfolding_pose);
        assert_eq!(bento_unfolding.shell_inset_xy(), (expected_sx, expected_sy));
        assert_eq!(bento_unfolding.style().margin.left, None);
        assert_eq!(bento_unfolding.style().margin.top, None);
        assert_eq!(
            bento_unfolding.style().padding.left,
            Some(DefiniteLength::Absolute(AbsoluteLength::Pixels(px(pad_x))))
        );
        assert_eq!(
            bento_unfolding.style().padding.top,
            Some(DefiniteLength::Absolute(AbsoluteLength::Pixels(px(pad_y))))
        );

        let mut guide_unfolding =
            guide_card_bloom(&CRYSTAL_GLASS_DARK, pad_x, pad_y, unfolding_pose);
        assert_eq!(guide_unfolding.shell_inset_xy(), (expected_sx, expected_sy));
        assert_eq!(guide_unfolding.style().margin.left, None);
        assert_eq!(
            guide_unfolding.style().padding.left,
            Some(DefiniteLength::Absolute(AbsoluteLength::Pixels(px(pad_x))))
        );

        // Tight padding (<= 2px) clamps GPU shell inset safely to 0 without clipping content
        let tight = bento_card_bloom(&CRYSTAL_GLASS_LIGHT, 2.0, 2.0, unfolding_pose);
        assert_eq!(tight.shell_inset_xy(), (0.0, 0.0));
    }
}
