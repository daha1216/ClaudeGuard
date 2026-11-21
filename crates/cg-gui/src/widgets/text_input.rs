//! Theme-aware Win32 IME-compatible single-line `DraftTextInput` (`EntityInputHandler`).

use std::ops::Range;

use gpui::{
    App, Bounds, ClipboardItem, Context, CursorStyle, Element, ElementId, ElementInputHandler,
    Entity, EntityInputHandler, FocusHandle, Focusable, Global, GlobalElementId,
    InspectorElementId, IntoElement, KeyBinding, LayoutId, MouseButton, MouseDownEvent,
    MouseMoveEvent, MouseUpEvent, PaintQuad, Pixels, Point, Render, ShapedLine, SharedString,
    Style, TextAlign, TextRun, UTF16Selection, UnderlineStyle, Window, actions, div, fill, point,
    prelude::*, px, relative, rgb, rgba, size,
};

use super::text_edit::{TextEditState, byte_index_from_utf16, utf16_index_from_byte, utf16_len};
use crate::theme::{LIGHT_C2, ThemePalette};

actions!([
    DraftBackspace,
    DraftDelete,
    DraftLeft,
    DraftRight,
    DraftSelectLeft,
    DraftSelectRight,
    DraftSelectAll,
    DraftHome,
    DraftEnd,
    DraftSelectHome,
    DraftSelectEnd,
    DraftPaste,
    DraftCut,
    DraftCopy
]);

/// Global palette snapshot read by `DraftTextInput` during layout/paint.
#[derive(Clone, Copy)]
pub struct ActivePaletteGlobal(pub &'static ThemePalette);

impl Global for ActivePaletteGlobal {}

pub fn bind_keys(cx: &mut App) {
    cx.bind_keys([
        KeyBinding::new("backspace", DraftBackspace, Some("DraftTextInput")),
        KeyBinding::new("delete", DraftDelete, Some("DraftTextInput")),
        KeyBinding::new("left", DraftLeft, Some("DraftTextInput")),
        KeyBinding::new("right", DraftRight, Some("DraftTextInput")),
        KeyBinding::new("shift-left", DraftSelectLeft, Some("DraftTextInput")),
        KeyBinding::new("shift-right", DraftSelectRight, Some("DraftTextInput")),
        KeyBinding::new("ctrl-a", DraftSelectAll, Some("DraftTextInput")),
        KeyBinding::new("home", DraftHome, Some("DraftTextInput")),
        KeyBinding::new("end", DraftEnd, Some("DraftTextInput")),
        KeyBinding::new("shift-home", DraftSelectHome, Some("DraftTextInput")),
        KeyBinding::new("shift-end", DraftSelectEnd, Some("DraftTextInput")),
        KeyBinding::new("ctrl-v", DraftPaste, Some("DraftTextInput")),
        KeyBinding::new("ctrl-c", DraftCopy, Some("DraftTextInput")),
        KeyBinding::new("ctrl-x", DraftCut, Some("DraftTextInput")),
    ]);
}

type ChangeHandler = Box<dyn Fn(&str, &mut Window, &mut App)>;

pub struct DraftTextInput {
    focus_handle: FocusHandle,
    state: TextEditState,
    placeholder: SharedString,
    masked: bool,
    compact: bool,
    monospace: bool,
    last_layout: Option<ShapedLine>,
    last_bounds: Option<Bounds<Pixels>>,
    is_selecting: bool,
    selection_anchor: Option<usize>,
    on_change: Option<ChangeHandler>,
}

impl DraftTextInput {
    pub fn new(cx: &mut Context<Self>) -> Self {
        Self {
            focus_handle: cx.focus_handle(),
            state: TextEditState::new(),
            placeholder: "".into(),
            masked: false,
            compact: false,
            monospace: false,
            last_layout: None,
            last_bounds: None,
            is_selecting: false,
            selection_anchor: None,
            on_change: None,
        }
    }

    pub fn with_placeholder(mut self, placeholder: impl Into<SharedString>) -> Self {
        self.placeholder = placeholder.into();
        self
    }

    pub fn with_text(mut self, text: &str) -> Self {
        self.state.set_text(text);
        self
    }

    pub fn with_masked(mut self, masked: bool) -> Self {
        self.masked = masked;
        self
    }

    pub fn with_compact(mut self, compact: bool) -> Self {
        self.compact = compact;
        self
    }

    pub fn with_monospace(mut self, monospace: bool) -> Self {
        self.monospace = monospace;
        self
    }

    pub fn with_on_change(
        mut self,
        handler: impl Fn(&str, &mut Window, &mut App) + 'static,
    ) -> Self {
        self.on_change = Some(Box::new(handler));
        self
    }

    pub fn text(&self) -> &str {
        self.state.text()
    }

    pub fn set_text_silent(&mut self, text: &str, cx: &mut Context<Self>) {
        if self.state.text() != text {
            self.state.set_text(text);
            self.selection_anchor = Some(self.state.cursor());
            cx.notify();
        }
    }

    pub fn clear(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.state.set_text("");
        self.selection_anchor = Some(0);
        self.changed(window, cx);
    }

    fn changed(&self, window: &mut Window, cx: &mut Context<Self>) {
        window.notify_text_input_changed(&self.focus_handle);
        window.notify_text_selection_changed(&self.focus_handle);
        if let Some(handler) = self.on_change.as_ref() {
            handler(self.state.text(), window, cx);
        }
        cx.notify();
    }

    fn move_cursor(
        &mut self,
        mutate: impl FnOnce(&mut TextEditState),
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        mutate(&mut self.state);
        self.selection_anchor = Some(self.state.cursor());
        window.notify_text_selection_changed(&self.focus_handle);
        cx.notify();
    }

    fn on_backspace(&mut self, _: &DraftBackspace, window: &mut Window, cx: &mut Context<Self>) {
        if self.state.backspace() {
            self.selection_anchor = Some(self.state.cursor());
            self.changed(window, cx);
        }
    }

    fn on_delete(&mut self, _: &DraftDelete, window: &mut Window, cx: &mut Context<Self>) {
        if self.state.delete() {
            self.selection_anchor = Some(self.state.cursor());
            self.changed(window, cx);
        }
    }

    fn on_left(&mut self, _: &DraftLeft, window: &mut Window, cx: &mut Context<Self>) {
        self.move_cursor(|s| s.move_left(false), window, cx);
    }

    fn on_right(&mut self, _: &DraftRight, window: &mut Window, cx: &mut Context<Self>) {
        self.move_cursor(|s| s.move_right(false), window, cx);
    }

    fn on_select_left(&mut self, _: &DraftSelectLeft, window: &mut Window, cx: &mut Context<Self>) {
        self.move_cursor(|s| s.move_left(true), window, cx);
    }

    fn on_select_right(
        &mut self,
        _: &DraftSelectRight,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.move_cursor(|s| s.move_right(true), window, cx);
    }

    fn on_select_all(&mut self, _: &DraftSelectAll, window: &mut Window, cx: &mut Context<Self>) {
        self.state.select_all();
        self.selection_anchor = Some(0);
        window.notify_text_selection_changed(&self.focus_handle);
        cx.notify();
    }

    fn on_home(&mut self, _: &DraftHome, window: &mut Window, cx: &mut Context<Self>) {
        self.move_cursor(|s| s.move_home(false), window, cx);
    }

    fn on_end(&mut self, _: &DraftEnd, window: &mut Window, cx: &mut Context<Self>) {
        self.move_cursor(|s| s.move_end(false), window, cx);
    }

    fn on_select_home(&mut self, _: &DraftSelectHome, window: &mut Window, cx: &mut Context<Self>) {
        self.move_cursor(|s| s.move_home(true), window, cx);
    }

    fn on_select_end(&mut self, _: &DraftSelectEnd, window: &mut Window, cx: &mut Context<Self>) {
        self.move_cursor(|s| s.move_end(true), window, cx);
    }

    fn on_paste(&mut self, _: &DraftPaste, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(text) = cx.read_from_clipboard().and_then(|item| item.text())
            && self.state.insert_text(&text)
        {
            self.selection_anchor = Some(self.state.cursor());
            self.changed(window, cx);
        }
    }

    fn on_copy(&mut self, _: &DraftCopy, _window: &mut Window, cx: &mut Context<Self>) {
        if self.masked {
            return;
        }
        let selected = self.state.selected_text();
        if !selected.is_empty() {
            cx.write_to_clipboard(ClipboardItem::new_string(selected));
        }
    }

    fn on_cut(&mut self, _: &DraftCut, window: &mut Window, cx: &mut Context<Self>) {
        let selected = self.state.selected_text();
        if !selected.is_empty() {
            if !self.masked {
                cx.write_to_clipboard(ClipboardItem::new_string(selected));
            }
            self.state.replace_text_in_range(None, "");
            self.selection_anchor = Some(self.state.cursor());
            self.changed(window, cx);
        }
    }

    fn on_mouse_down(
        &mut self,
        event: &MouseDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        window.focus(&self.focus_handle, cx);
        self.is_selecting = true;
        window.request_virtual_keyboard();
        let index = self.index_for_mouse_position(event.position);
        if event.modifiers.shift {
            let anchor = self.selection_anchor.unwrap_or(self.state.cursor());
            self.state.select_to(anchor, index);
        } else {
            self.selection_anchor = Some(index);
            self.state.set_cursor(index);
        }
        window.notify_text_selection_changed(&self.focus_handle);
        cx.notify();
    }

    fn on_mouse_up(&mut self, _: &MouseUpEvent, _window: &mut Window, _: &mut Context<Self>) {
        self.is_selecting = false;
    }

    fn on_mouse_move(
        &mut self,
        event: &MouseMoveEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.is_selecting {
            let anchor = self.selection_anchor.unwrap_or(self.state.cursor());
            let index = self.index_for_mouse_position(event.position);
            self.state.select_to(anchor, index);
            window.notify_text_selection_changed(&self.focus_handle);
            cx.notify();
        }
    }

    fn index_for_mouse_position(&self, position: Point<Pixels>) -> usize {
        let (Some(bounds), Some(line)) = (self.last_bounds.as_ref(), self.last_layout.as_ref())
        else {
            return 0;
        };
        if position.y < bounds.top() {
            return 0;
        }
        if position.y > bounds.bottom() {
            return utf16_len(self.state.text());
        }
        let byte = line.closest_index_for_x(position.x - bounds.left());
        if self.masked {
            let char_idx = line.text[..byte.min(line.text.len())].chars().count();
            let raw_char_byte = self
                .state
                .text()
                .char_indices()
                .nth(char_idx)
                .map(|(i, _)| i)
                .unwrap_or_else(|| self.state.text().len());
            utf16_index_from_byte(self.state.text(), raw_char_byte)
        } else {
            utf16_index_from_byte(self.state.text(), byte)
        }
    }
}

impl Focusable for DraftTextInput {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

impl EntityInputHandler for DraftTextInput {
    fn text_for_range(
        &mut self,
        range_utf16: Range<usize>,
        actual_range: &mut Option<Range<usize>>,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> Option<String> {
        let (text, actual) = self.state.substring_with_range(range_utf16);
        actual_range.replace(actual);
        Some(text)
    }

    fn selected_text_range(
        &mut self,
        _ignore_disabled_input: bool,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> Option<UTF16Selection> {
        Some(UTF16Selection {
            range: self.state.selected_range(),
            reversed: self.state.selection_reversed(),
        })
    }

    fn set_selected_text_range(
        &mut self,
        range_utf16: Range<usize>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.state.select_range(range_utf16);
        self.selection_anchor = Some(self.state.cursor());
        window.notify_text_selection_changed(&self.focus_handle);
        cx.notify();
    }

    fn text_length_utf16(
        &mut self,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> Option<usize> {
        Some(utf16_len(self.state.text()))
    }

    fn marked_text_range(
        &self,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> Option<Range<usize>> {
        self.state.marked_range()
    }

    fn unmark_text(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.state.unmark_text();
        self.changed(window, cx);
    }

    fn replace_text_in_range(
        &mut self,
        range_utf16: Option<Range<usize>>,
        new_text: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.state.replace_text_in_range(range_utf16, new_text);
        self.selection_anchor = Some(self.state.cursor());
        self.changed(window, cx);
    }

    fn replace_and_mark_text_in_range(
        &mut self,
        range_utf16: Option<Range<usize>>,
        new_text: &str,
        new_selected_range_utf16: Option<Range<usize>>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.state
            .replace_and_mark_text_in_range(range_utf16, new_text, new_selected_range_utf16);
        self.selection_anchor = Some(self.state.cursor());
        self.changed(window, cx);
    }

    fn bounds_for_range(
        &mut self,
        range_utf16: Range<usize>,
        element_bounds: Bounds<Pixels>,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> Option<Bounds<Pixels>> {
        let last_layout = self.last_layout.as_ref()?;
        if !self.masked && last_layout.text != self.state.text() {
            return None;
        }
        let start = byte_index_from_utf16(self.state.text(), range_utf16.start);
        let end = byte_index_from_utf16(self.state.text(), range_utf16.end);
        let (sx, ex) = if self.masked {
            let sc = self.state.text()[..start].chars().count() * '•'.len_utf8();
            let ec = self.state.text()[..end].chars().count() * '•'.len_utf8();
            (
                last_layout.x_for_index(sc.min(last_layout.text.len())),
                last_layout.x_for_index(ec.min(last_layout.text.len())),
            )
        } else {
            (last_layout.x_for_index(start), last_layout.x_for_index(end))
        };
        Some(Bounds::from_corners(
            point(element_bounds.left() + sx, element_bounds.top()),
            point(element_bounds.left() + ex, element_bounds.bottom()),
        ))
    }

    fn selection_bounds_for_range(
        &mut self,
        range_utf16: Range<usize>,
        element_bounds: Bounds<Pixels>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Vec<Bounds<Pixels>> {
        self.bounds_for_range(range_utf16, element_bounds, window, cx)
            .into_iter()
            .collect()
    }

    fn character_index_for_point(
        &mut self,
        point: Point<Pixels>,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> Option<usize> {
        let line_point = self.last_bounds?.localize(&point)?;
        let last_layout = self.last_layout.as_ref()?;
        let byte = last_layout.closest_index_for_x(line_point.x);
        if self.masked {
            let char_idx = last_layout.text[..byte.min(last_layout.text.len())]
                .chars()
                .count();
            let raw_byte = self
                .state
                .text()
                .char_indices()
                .nth(char_idx)
                .map(|(i, _)| i)
                .unwrap_or_else(|| self.state.text().len());
            Some(utf16_index_from_byte(self.state.text(), raw_byte))
        } else {
            Some(utf16_index_from_byte(self.state.text(), byte))
        }
    }
}

struct TextElement {
    input: Entity<DraftTextInput>,
    palette: &'static ThemePalette,
}

struct PrepaintState {
    line: Option<ShapedLine>,
    cursor: Option<PaintQuad>,
    selection: Option<PaintQuad>,
}

impl IntoElement for TextElement {
    type Element = Self;

    fn into_element(self) -> Self::Element {
        self
    }
}

impl Element for TextElement {
    type RequestLayoutState = ();
    type PrepaintState = PrepaintState;

    fn id(&self) -> Option<ElementId> {
        None
    }

    fn source_location(&self) -> Option<&'static core::panic::Location<'static>> {
        None
    }

    fn request_layout(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&InspectorElementId>,
        window: &mut Window,
        cx: &mut App,
    ) -> (LayoutId, Self::RequestLayoutState) {
        let mut style = Style::default();
        style.size.width = relative(1.).into();
        style.size.height = window.line_height().into();
        (window.request_layout(style, [], cx), ())
    }

    fn prepaint(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&InspectorElementId>,
        bounds: Bounds<Pixels>,
        _request_layout: &mut Self::RequestLayoutState,
        window: &mut Window,
        cx: &mut App,
    ) -> Self::PrepaintState {
        let input = self.input.read(cx);
        let content = input.state.text();
        let selected_range = input.state.selected_range();
        let cursor = input.state.cursor();
        let marked_range = input.state.marked_range();
        let style = window.text_style();
        let p = self.palette;

        let (display_text, text_color) = if content.is_empty() {
            (input.placeholder.clone(), rgb(p.text_muted))
        } else if input.masked {
            let bullets = "•".repeat(content.chars().count());
            (SharedString::from(bullets), rgb(p.text_primary))
        } else {
            (SharedString::from(content.to_string()), rgb(p.text_primary))
        };

        let base_run = TextRun {
            len: display_text.len(),
            font: style.font(),
            color: text_color.into(),
            background_color: None,
            underline: None,
            strikethrough: None,
        };

        let runs = if !input.masked
            && let Some(marked) = marked_range.map(|range| {
                byte_index_from_utf16(&display_text, range.start)
                    ..byte_index_from_utf16(&display_text, range.end)
            }) {
            let mut runs = Vec::new();
            if marked.start > 0 {
                runs.push(TextRun {
                    len: marked.start,
                    ..base_run.clone()
                });
            }
            if marked.end > marked.start {
                runs.push(TextRun {
                    len: marked.end - marked.start,
                    underline: Some(UnderlineStyle {
                        color: Some(base_run.color),
                        thickness: px(1.),
                        wavy: false,
                    }),
                    ..base_run.clone()
                });
            }
            if marked.end < display_text.len() {
                runs.push(TextRun {
                    len: display_text.len() - marked.end,
                    ..base_run.clone()
                });
            }
            runs
        } else {
            vec![base_run]
        };

        let font_size = style.font_size.to_pixels(window.rem_size());
        let line = window
            .text_system()
            .shape_line(display_text.clone(), font_size, &runs, None);

        let visual_byte = |raw_utf16: usize| -> usize {
            let raw_b = byte_index_from_utf16(content, raw_utf16);
            if input.masked {
                (content[..raw_b].chars().count() * '•'.len_utf8()).min(display_text.len())
            } else {
                raw_b
            }
        };

        let cursor_pos = line.x_for_index(visual_byte(cursor));
        let (selection, cursor_quad) = if selected_range.is_empty() {
            (
                None,
                Some(fill(
                    Bounds::new(
                        point(bounds.left() + cursor_pos, bounds.top()),
                        size(px(1.8), bounds.bottom() - bounds.top()),
                    ),
                    rgb(p.input_focus_border),
                )),
            )
        } else {
            let start = visual_byte(selected_range.start);
            let end = visual_byte(selected_range.end);
            (
                Some(fill(
                    Bounds::from_corners(
                        point(bounds.left() + line.x_for_index(start), bounds.top()),
                        point(bounds.left() + line.x_for_index(end), bounds.bottom()),
                    ),
                    rgba(p.input_selection_rgba),
                )),
                None,
            )
        };

        PrepaintState {
            line: Some(line),
            cursor: cursor_quad,
            selection,
        }
    }

    fn paint(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&InspectorElementId>,
        bounds: Bounds<Pixels>,
        _request_layout: &mut Self::RequestLayoutState,
        prepaint: &mut Self::PrepaintState,
        window: &mut Window,
        cx: &mut App,
    ) {
        let focus_handle = self.input.read(cx).focus_handle.clone();
        window.handle_input(
            &focus_handle,
            ElementInputHandler::new(bounds, self.input.clone()),
            cx,
        );
        let line = prepaint.line.take().expect("text line shaped in prepaint");
        if let Some(selection) = prepaint.selection.take() {
            window.paint_quad(selection);
        }
        line.paint(
            bounds.origin,
            window.line_height(),
            TextAlign::Left,
            None,
            window,
            cx,
        )
        .ok();
        if focus_handle.is_focused(window)
            && let Some(cursor) = prepaint.cursor.take()
        {
            window.paint_quad(cursor);
        }
        self.input.update(cx, |input, _cx| {
            input.last_layout = Some(line);
            input.last_bounds = Some(bounds);
        });
    }
}

impl Render for DraftTextInput {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let p = cx
            .try_global::<ActivePaletteGlobal>()
            .map(|g| g.0)
            .unwrap_or(&LIGHT_C2);
        let focused = self.focus_handle.is_focused(window);
        let (h, py_pad, text_sz, line_h) = if self.compact {
            (px(30.), px(5.), px(12.), px(18.))
        } else {
            (px(34.), px(6.5), px(12.), px(19.))
        };

        let mut box_div = div()
            .h(h)
            .w_full()
            .px(px(11.))
            .py(py_pad)
            .bg(rgb(p.input_bg))
            .border_1()
            .border_color(rgb(if focused {
                p.input_focus_border
            } else {
                p.input_border
            }))
            .rounded(px(8.))
            .overflow_hidden()
            .child(TextElement {
                input: cx.entity(),
                palette: p,
            });
        if self.monospace {
            box_div = box_div.font_family("Cascadia Mono");
        }

        div()
            .flex()
            .key_context("DraftTextInput")
            .track_focus(&self.focus_handle(cx))
            .cursor(CursorStyle::IBeam)
            .on_action(cx.listener(Self::on_backspace))
            .on_action(cx.listener(Self::on_delete))
            .on_action(cx.listener(Self::on_left))
            .on_action(cx.listener(Self::on_right))
            .on_action(cx.listener(Self::on_select_left))
            .on_action(cx.listener(Self::on_select_right))
            .on_action(cx.listener(Self::on_select_all))
            .on_action(cx.listener(Self::on_home))
            .on_action(cx.listener(Self::on_end))
            .on_action(cx.listener(Self::on_select_home))
            .on_action(cx.listener(Self::on_select_end))
            .on_action(cx.listener(Self::on_paste))
            .on_action(cx.listener(Self::on_copy))
            .on_action(cx.listener(Self::on_cut))
            .on_mouse_down(MouseButton::Left, cx.listener(Self::on_mouse_down))
            .on_mouse_up(MouseButton::Left, cx.listener(Self::on_mouse_up))
            .on_mouse_up_out(MouseButton::Left, cx.listener(Self::on_mouse_up))
            .on_mouse_move(cx.listener(Self::on_mouse_move))
            .w_full()
            .line_height(line_h)
            .text_size(text_sz)
            .child(box_div)
    }
}
