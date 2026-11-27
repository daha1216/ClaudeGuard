//! Theme-aware Win32 IME-compatible single-line `DraftTextInput` (`EntityInputHandler`)
//! with horizontal viewport auto-scroll, word navigation/selection, spring focus ring,
//! and typing-aware caret blinking.

use std::ops::Range;
use std::time::Duration;

use gpui::{
    AnimationExt, App, Bounds, BoxShadow, ClipboardItem, ContentMask, Context, CursorStyle,
    Element, ElementId, ElementInputHandler, Entity, EntityInputHandler, FocusHandle, Focusable,
    Global, GlobalElementId, InspectorElementId, IntoElement, KeyBinding, LayoutId, MouseButton,
    MouseDownEvent, MouseMoveEvent, MouseUpEvent, PaintQuad, Pixels, Point, Render, ShapedLine,
    SharedString, SpringAnimation, Style, Task, TextAlign, TextRun, UTF16Selection, UnderlineStyle,
    Window, actions, div, fill, point, prelude::*, px, relative, rgb, rgba, size,
};

use super::text_edit::{TextEditState, byte_index_from_utf16, utf16_index_from_byte, utf16_len};
use crate::motion::{lerp_rgb, rgba_with_alpha_scale, spring_snappy};
use crate::theme::{LIGHT_C2, ThemePalette};

/// Breathing margin (px) maintained between the caret and viewport edges when scrolled.
const SCROLL_CARET_MARGIN_PX: f32 = 8.0;

/// Solid-caret grace period after any edit or cursor movement before blinking resumes.
const CARET_BLINK_HOLD_MS: u64 = 600;

/// Half-cycle blink interval once the caret is idle (matches native Windows/macOS cadence).
const CARET_BLINK_INTERVAL_MS: u64 = 530;

actions!([
    DraftBackspace,
    DraftDelete,
    DraftDeleteWordBack,
    DraftDeleteWordForward,
    DraftLeft,
    DraftRight,
    DraftWordLeft,
    DraftWordRight,
    DraftSelectLeft,
    DraftSelectRight,
    DraftSelectWordLeft,
    DraftSelectWordRight,
    DraftSelectAll,
    DraftHome,
    DraftEnd,
    DraftSelectHome,
    DraftSelectEnd,
    DraftPaste,
    DraftCut,
    DraftCopy,
    DraftSubmit,
    DraftCancel,
    DraftTabNext,
    DraftTabPrev
]);

/// Global palette snapshot read by `DraftTextInput` during layout/paint.
#[derive(Clone, Copy)]
pub struct ActivePaletteGlobal(pub &'static ThemePalette);

impl Global for ActivePaletteGlobal {}

pub fn bind_keys(cx: &mut App) {
    cx.bind_keys([
        KeyBinding::new("backspace", DraftBackspace, Some("DraftTextInput")),
        KeyBinding::new("delete", DraftDelete, Some("DraftTextInput")),
        KeyBinding::new(
            "ctrl-backspace",
            DraftDeleteWordBack,
            Some("DraftTextInput"),
        ),
        KeyBinding::new(
            "ctrl-delete",
            DraftDeleteWordForward,
            Some("DraftTextInput"),
        ),
        KeyBinding::new("left", DraftLeft, Some("DraftTextInput")),
        KeyBinding::new("right", DraftRight, Some("DraftTextInput")),
        KeyBinding::new("ctrl-left", DraftWordLeft, Some("DraftTextInput")),
        KeyBinding::new("ctrl-right", DraftWordRight, Some("DraftTextInput")),
        KeyBinding::new("shift-left", DraftSelectLeft, Some("DraftTextInput")),
        KeyBinding::new("shift-right", DraftSelectRight, Some("DraftTextInput")),
        KeyBinding::new(
            "ctrl-shift-left",
            DraftSelectWordLeft,
            Some("DraftTextInput"),
        ),
        KeyBinding::new(
            "ctrl-shift-right",
            DraftSelectWordRight,
            Some("DraftTextInput"),
        ),
        KeyBinding::new("ctrl-a", DraftSelectAll, Some("DraftTextInput")),
        KeyBinding::new("home", DraftHome, Some("DraftTextInput")),
        KeyBinding::new("end", DraftEnd, Some("DraftTextInput")),
        KeyBinding::new("shift-home", DraftSelectHome, Some("DraftTextInput")),
        KeyBinding::new("shift-end", DraftSelectEnd, Some("DraftTextInput")),
        KeyBinding::new("ctrl-v", DraftPaste, Some("DraftTextInput")),
        KeyBinding::new("ctrl-c", DraftCopy, Some("DraftTextInput")),
        KeyBinding::new("ctrl-x", DraftCut, Some("DraftTextInput")),
        KeyBinding::new("enter", DraftSubmit, Some("DraftTextInput")),
        KeyBinding::new("escape", DraftCancel, Some("DraftTextInput")),
        KeyBinding::new("tab", DraftTabNext, Some("DraftTextInput")),
        KeyBinding::new("shift-tab", DraftTabPrev, Some("DraftTextInput")),
    ]);
}

type ChangeHandler = Box<dyn Fn(&str, &mut Window, &mut App)>;
type SubmitHandler = Box<dyn Fn(&mut Window, &mut App)>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum CharClass {
    Whitespace,
    Word,
    Punct,
}

fn classify_char(ch: char) -> CharClass {
    if ch.is_whitespace() {
        CharClass::Whitespace
    } else if ch.is_alphanumeric() || ch == '_' {
        CharClass::Word
    } else {
        CharClass::Punct
    }
}

/// Returns the UTF-16 range of the contiguous word/token surrounding `utf16_offset`.
fn word_range_at(text: &str, utf16_offset: usize) -> Range<usize> {
    if text.is_empty() {
        return 0..0;
    }

    let mut byte = byte_index_from_utf16(text, utf16_offset).min(text.len());
    let target_class = if let Some(ch) = text[byte..].chars().next() {
        classify_char(ch)
    } else if let Some((prev_idx, ch)) = text[..byte].char_indices().next_back() {
        byte = prev_idx;
        classify_char(ch)
    } else {
        return 0..0;
    };

    let mut start_byte = byte;
    for (idx, ch) in text[..byte].char_indices().rev() {
        if classify_char(ch) == target_class {
            start_byte = idx;
        } else {
            break;
        }
    }

    let mut end_byte = byte;
    for (rel_idx, ch) in text[byte..].char_indices() {
        if classify_char(ch) == target_class {
            end_byte = byte + rel_idx + ch.len_utf8();
        } else {
            break;
        }
    }

    utf16_index_from_byte(text, start_byte)..utf16_index_from_byte(text, end_byte)
}

fn is_network_token_char(ch: char) -> bool {
    ch.is_alphanumeric() || matches!(ch, '.' | ':' | '/' | '-' | '_' | '[' | ']')
}

/// Returns the UTF-16 range of a contiguous network/config token (`203.0.113.0/24`,
/// `127.0.0.1:7897`, `:7897`, `work-claude-max`) for double-click selection.
fn token_range_at(text: &str, utf16_offset: usize) -> Range<usize> {
    if text.is_empty() {
        return 0..0;
    }

    let mut byte = byte_index_from_utf16(text, utf16_offset).min(text.len());
    let anchor_ch = if let Some(ch) = text[byte..].chars().next() {
        ch
    } else if let Some((prev_idx, ch)) = text[..byte].char_indices().next_back() {
        byte = prev_idx;
        ch
    } else {
        return 0..0;
    };

    if !is_network_token_char(anchor_ch) {
        return word_range_at(text, utf16_offset);
    }

    let mut start_byte = byte;
    for (idx, ch) in text[..byte].char_indices().rev() {
        if is_network_token_char(ch) {
            start_byte = idx;
        } else {
            break;
        }
    }

    let mut end_byte = byte;
    for (rel_idx, ch) in text[byte..].char_indices() {
        if is_network_token_char(ch) {
            end_byte = byte + rel_idx + ch.len_utf8();
        } else {
            break;
        }
    }

    utf16_index_from_byte(text, start_byte)..utf16_index_from_byte(text, end_byte)
}

/// Finds the previous UTF-16 word boundary before `utf16_offset` (Windows/VS Code semantics).
fn prev_word_boundary(text: &str, utf16_offset: usize) -> usize {
    let mut byte = byte_index_from_utf16(text, utf16_offset).min(text.len());
    if byte == 0 {
        return 0;
    }

    while let Some((idx, ch)) = text[..byte].char_indices().next_back() {
        if classify_char(ch) == CharClass::Whitespace {
            byte = idx;
        } else {
            break;
        }
    }

    if let Some((_, ch)) = text[..byte].char_indices().next_back() {
        let target_class = classify_char(ch);
        while let Some((idx, prev_ch)) = text[..byte].char_indices().next_back() {
            if classify_char(prev_ch) == target_class {
                byte = idx;
            } else {
                break;
            }
        }
    }

    utf16_index_from_byte(text, byte)
}

/// Finds the next UTF-16 word boundary after `utf16_offset` (Windows/VS Code semantics).
fn next_word_boundary(text: &str, utf16_offset: usize) -> usize {
    let mut byte = byte_index_from_utf16(text, utf16_offset).min(text.len());
    let len = text.len();
    if byte >= len {
        return utf16_len(text);
    }

    while let Some(ch) = text[byte..].chars().next() {
        if classify_char(ch) == CharClass::Whitespace {
            byte += ch.len_utf8();
        } else {
            break;
        }
    }

    if let Some(ch) = text[byte..].chars().next() {
        let target_class = classify_char(ch);
        while let Some(next_ch) = text[byte..].chars().next() {
            if classify_char(next_ch) == target_class {
                byte += next_ch.len_utf8();
            } else {
                break;
            }
        }
    }

    utf16_index_from_byte(text, byte)
}

/// Keeps `caret_x` comfortably visible within `[0, viewport_w]` with a breathing margin.
fn compute_horizontal_scroll(
    prev_scroll: f32,
    caret_x: f32,
    content_w: f32,
    viewport_w: f32,
) -> f32 {
    if viewport_w <= 1.0 || content_w <= viewport_w - 2.0 {
        return 0.0;
    }

    let margin = SCROLL_CARET_MARGIN_PX.min(viewport_w * 0.25);
    let mut scroll = prev_scroll.max(0.0);

    if caret_x - scroll > viewport_w - margin {
        scroll = caret_x - (viewport_w - margin);
    } else if caret_x - scroll < margin {
        scroll = (caret_x - margin).max(0.0);
    }

    let max_scroll = (content_w - viewport_w + margin).max(0.0);
    scroll.clamp(0.0, max_scroll)
}

pub struct DraftTextInput {
    focus_handle: FocusHandle,
    state: TextEditState,
    placeholder: SharedString,
    masked: bool,
    compact: bool,
    monospace: bool,
    last_layout: Option<ShapedLine>,
    last_bounds: Option<Bounds<Pixels>>,
    scroll_x: f32,
    is_selecting: bool,
    selection_anchor: Option<usize>,
    on_change: Option<ChangeHandler>,
    on_submit: Option<SubmitHandler>,
    caret_visible: bool,
    was_focused: bool,
    blink_epoch: u64,
    blink_task: Option<Task<()>>,
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
            scroll_x: 0.0,
            is_selecting: false,
            selection_anchor: None,
            on_change: None,
            on_submit: None,
            caret_visible: true,
            was_focused: false,
            blink_epoch: 0,
            blink_task: None,
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

    pub fn with_on_submit(mut self, handler: impl Fn(&mut Window, &mut App) + 'static) -> Self {
        self.on_submit = Some(Box::new(handler));
        self
    }

    pub fn text(&self) -> &str {
        self.state.text()
    }

    pub fn set_text_silent(&mut self, text: &str, cx: &mut Context<Self>) {
        if self.state.text() != text {
            self.state.set_text(text);
            if text.is_empty() {
                self.scroll_x = 0.0;
            }
            self.selection_anchor = Some(self.state.cursor());
            cx.notify();
        }
    }

    pub fn clear(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.state.set_text("");
        self.scroll_x = 0.0;
        self.selection_anchor = Some(0);
        self.changed(window, cx);
    }

    fn sync_caret_blink(&mut self, focused: bool, cx: &mut Context<Self>) {
        let should_blink = focused && !cx.reduce_motion();
        if should_blink {
            if !self.was_focused || self.blink_task.is_none() {
                self.was_focused = true;
                self.caret_visible = true;
                self.restart_caret_blink(cx);
            }
        } else {
            self.was_focused = focused;
            self.stop_caret_blink();
        }
    }

    fn reset_caret_blink(&mut self, cx: &mut Context<Self>) {
        self.caret_visible = true;
        if self.was_focused && !cx.reduce_motion() {
            self.restart_caret_blink(cx);
        } else {
            self.blink_epoch = self.blink_epoch.wrapping_add(1);
            self.blink_task = None;
        }
    }

    fn stop_caret_blink(&mut self) {
        self.caret_visible = true;
        self.blink_epoch = self.blink_epoch.wrapping_add(1);
        self.blink_task = None;
    }

    fn restart_caret_blink(&mut self, cx: &mut Context<Self>) {
        self.blink_epoch = self.blink_epoch.wrapping_add(1);
        let epoch = self.blink_epoch;
        self.blink_task = Some(cx.spawn(async move |this, cx| {
            cx.background_executor()
                .timer(Duration::from_millis(CARET_BLINK_HOLD_MS))
                .await;
            loop {
                let keep_going = this
                    .update(cx, |input, cx| {
                        if input.blink_epoch != epoch || !input.was_focused || cx.reduce_motion() {
                            return false;
                        }
                        input.caret_visible = !input.caret_visible;
                        cx.notify();
                        true
                    })
                    .unwrap_or(false);
                if !keep_going {
                    break;
                }
                cx.background_executor()
                    .timer(Duration::from_millis(CARET_BLINK_INTERVAL_MS))
                    .await;
            }
        }));
    }

    fn changed(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.reset_caret_blink(cx);
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
        self.reset_caret_blink(cx);
        window.notify_text_selection_changed(&self.focus_handle);
        cx.notify();
    }

    fn move_word(
        &mut self,
        forward: bool,
        extend: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let target = if self.masked {
            if forward {
                utf16_len(self.state.text())
            } else {
                0
            }
        } else if forward {
            next_word_boundary(self.state.text(), self.state.cursor())
        } else {
            prev_word_boundary(self.state.text(), self.state.cursor())
        };

        if extend {
            let range = self.state.selected_range();
            let anchor = if range.is_empty() {
                self.state.cursor()
            } else if self.state.cursor() == range.start {
                range.end
            } else {
                range.start
            };
            self.selection_anchor = Some(anchor);
            self.state.select_to(anchor, target);
        } else {
            self.selection_anchor = Some(target);
            self.state.set_cursor(target);
        }

        self.reset_caret_blink(cx);
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

    fn on_delete_word_back(
        &mut self,
        _: &DraftDeleteWordBack,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if !self.state.selected_range().is_empty() {
            self.state.replace_text_in_range(None, "");
            self.selection_anchor = Some(self.state.cursor());
            self.changed(window, cx);
            return;
        }
        let cursor = self.state.cursor();
        if cursor == 0 {
            return;
        }
        let start = if self.masked {
            0
        } else {
            prev_word_boundary(self.state.text(), cursor)
        };
        if start < cursor {
            self.state.replace_text_in_range(Some(start..cursor), "");
            self.selection_anchor = Some(self.state.cursor());
            self.changed(window, cx);
        }
    }

    fn on_delete_word_forward(
        &mut self,
        _: &DraftDeleteWordForward,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if !self.state.selected_range().is_empty() {
            self.state.replace_text_in_range(None, "");
            self.selection_anchor = Some(self.state.cursor());
            self.changed(window, cx);
            return;
        }
        let cursor = self.state.cursor();
        let total = utf16_len(self.state.text());
        if cursor >= total {
            return;
        }
        let end = if self.masked {
            total
        } else {
            next_word_boundary(self.state.text(), cursor)
        };
        if end > cursor {
            self.state.replace_text_in_range(Some(cursor..end), "");
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

    fn on_word_left(&mut self, _: &DraftWordLeft, window: &mut Window, cx: &mut Context<Self>) {
        self.move_word(false, false, window, cx);
    }

    fn on_word_right(&mut self, _: &DraftWordRight, window: &mut Window, cx: &mut Context<Self>) {
        self.move_word(true, false, window, cx);
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

    fn on_select_word_left(
        &mut self,
        _: &DraftSelectWordLeft,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.move_word(false, true, window, cx);
    }

    fn on_select_word_right(
        &mut self,
        _: &DraftSelectWordRight,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.move_word(true, true, window, cx);
    }

    fn on_select_all(&mut self, _: &DraftSelectAll, window: &mut Window, cx: &mut Context<Self>) {
        self.state.select_all();
        self.selection_anchor = Some(0);
        self.reset_caret_blink(cx);
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

    fn on_submit(&mut self, _: &DraftSubmit, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(handler) = self.on_submit.as_ref() {
            handler(window, cx);
        }
    }

    fn on_cancel(&mut self, _: &DraftCancel, window: &mut Window, cx: &mut Context<Self>) {
        if self.focus_handle.is_focused(window) {
            self.is_selecting = false;
            self.was_focused = false;
            self.stop_caret_blink();
            window.blur(cx);
            cx.notify();
        }
    }

    fn on_tab_next(&mut self, _: &DraftTabNext, window: &mut Window, cx: &mut Context<Self>) {
        window.focus_next(cx);
    }

    fn on_tab_prev(&mut self, _: &DraftTabPrev, window: &mut Window, cx: &mut Context<Self>) {
        window.focus_prev(cx);
    }

    fn on_mouse_down(
        &mut self,
        event: &MouseDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        window.focus(&self.focus_handle, cx);
        window.request_virtual_keyboard();
        let index = self.index_for_mouse_position(event.position);

        if event.click_count >= 3 {
            self.is_selecting = false;
            self.state.select_all();
            self.selection_anchor = Some(0);
        } else if event.click_count == 2 {
            self.is_selecting = false;
            if self.masked {
                self.state.select_all();
                self.selection_anchor = Some(0);
            } else {
                let range = token_range_at(self.state.text(), index);
                self.selection_anchor = Some(range.start);
                self.state.select_range(range);
            }
        } else {
            self.is_selecting = true;
            if event.modifiers.shift {
                let anchor = self.selection_anchor.unwrap_or(self.state.cursor());
                self.state.select_to(anchor, index);
            } else {
                self.selection_anchor = Some(index);
                self.state.set_cursor(index);
            }
        }

        self.reset_caret_blink(cx);
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
            if index != self.state.cursor() {
                self.state.select_to(anchor, index);
                self.reset_caret_blink(cx);
                window.notify_text_selection_changed(&self.focus_handle);
                cx.notify();
            }
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
        let local_x = position.x - bounds.left() + px(self.scroll_x);
        let byte = line.closest_index_for_x(local_x);
        if self.masked {
            if self.state.text().is_empty() || !line.text.starts_with('•') {
                return 0;
            }
            let mut clamped = byte.min(line.text.len());
            while !line.text.is_char_boundary(clamped) {
                clamped -= 1;
            }
            let char_idx = line.text[..clamped].chars().count();
            let raw_char_byte = self
                .state
                .text()
                .char_indices()
                .nth(char_idx)
                .map(|(i, _)| i)
                .unwrap_or_else(|| self.state.text().len());
            utf16_index_from_byte(self.state.text(), raw_char_byte)
        } else {
            if self.state.text().is_empty() {
                return 0;
            }
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
        self.reset_caret_blink(cx);
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
        if self.masked {
            let expected_len = self.state.text().chars().count() * '•'.len_utf8();
            if self.state.text().is_empty()
                || last_layout.text.len() != expected_len
                || !last_layout.text.starts_with('•')
            {
                return None;
            }
        } else if last_layout.text != self.state.text() {
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
        let scroll = px(self.scroll_x);
        let max_w = element_bounds.size.width;
        let vis_sx = (sx - scroll).clamp(px(0.), max_w);
        let vis_ex = (ex - scroll).clamp(px(0.), max_w);
        Some(Bounds::from_corners(
            point(element_bounds.left() + vis_sx, element_bounds.top()),
            point(element_bounds.left() + vis_ex, element_bounds.bottom()),
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
        let byte = last_layout.closest_index_for_x(line_point.x + px(self.scroll_x));
        if self.masked {
            if self.state.text().is_empty() || !last_layout.text.starts_with('•') {
                return Some(0);
            }
            let mut clamped = byte.min(last_layout.text.len());
            while !last_layout.text.is_char_boundary(clamped) {
                clamped -= 1;
            }
            let char_idx = last_layout.text[..clamped].chars().count();
            let raw_byte = self
                .state
                .text()
                .char_indices()
                .nth(char_idx)
                .map(|(i, _)| i)
                .unwrap_or_else(|| self.state.text().len());
            Some(utf16_index_from_byte(self.state.text(), raw_byte))
        } else {
            if self.state.text().is_empty() {
                return Some(0);
            }
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
    scroll_x: f32,
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
        let prev_scroll = input.scroll_x;
        let caret_visible = input.caret_visible;
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

        let cursor_pos = if content.is_empty() {
            px(0.)
        } else {
            line.x_for_index(visual_byte(cursor))
        };
        let scroll_x = if content.is_empty() {
            0.0
        } else {
            compute_horizontal_scroll(
                prev_scroll,
                cursor_pos.as_f32(),
                line.width().as_f32(),
                bounds.size.width.as_f32(),
            )
        };
        let scroll_px = px(scroll_x);

        let (selection, cursor_quad) = if selected_range.is_empty() {
            let caret = if caret_visible {
                let top = bounds.top() + px(1.);
                let height = (bounds.bottom() - bounds.top() - px(2.)).max(px(1.));
                Some(fill(
                    Bounds::new(
                        point(bounds.left() + cursor_pos - scroll_px, top),
                        size(px(1.8), height),
                    ),
                    rgb(p.input_focus_border),
                ))
            } else {
                None
            };
            (None, caret)
        } else {
            let start = visual_byte(selected_range.start);
            let end = visual_byte(selected_range.end);
            (
                Some(fill(
                    Bounds::from_corners(
                        point(
                            bounds.left() + line.x_for_index(start) - scroll_px,
                            bounds.top(),
                        ),
                        point(
                            bounds.left() + line.x_for_index(end) - scroll_px,
                            bounds.bottom(),
                        ),
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
            scroll_x,
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
        let scroll_x = prepaint.scroll_x;
        let selection = prepaint.selection.take();
        let cursor = prepaint.cursor.take();
        let is_focused = focus_handle.is_focused(window);

        window.with_content_mask(Some(ContentMask { bounds }), |window| {
            if let Some(selection) = selection {
                window.paint_quad(selection);
            }
            line.paint(
                point(bounds.origin.x - px(scroll_x), bounds.origin.y),
                window.line_height(),
                TextAlign::Left,
                None,
                window,
                cx,
            )
            .ok();
            if is_focused && let Some(cursor) = cursor {
                window.paint_quad(cursor);
            }
        });

        self.input.update(cx, |input, _cx| {
            input.last_layout = Some(line);
            input.last_bounds = Some(bounds);
            input.scroll_x = scroll_x;
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
        self.sync_caret_blink(focused, cx);

        let (h, py_pad, text_sz, line_h) = if self.compact {
            (px(30.), px(5.), px(12.), px(18.))
        } else {
            (px(34.), px(6.5), px(12.), px(19.))
        };

        let idle_border = p.input_border;
        let focus_border = p.input_focus_border;
        let focus_ring_rgba = (focus_border << 8) | 0x36;

        let mut box_div = div()
            .h(h)
            .w_full()
            .px(px(11.))
            .py(py_pad)
            .bg(rgb(p.input_bg))
            .border_1()
            .rounded(px(8.))
            .overflow_hidden()
            .child(TextElement {
                input: cx.entity(),
                palette: p,
            });
        if self.monospace {
            box_div = box_div.font_family("Cascadia Mono");
        }

        let animated_box = box_div.with_spring(
            "input-focus-ring",
            SpringAnimation::new(spring_snappy())
                .to(focused)
                .with_epsilon(0.002),
            move |el, phase| {
                let t = phase.0.clamp(0.0, 1.0);
                let el = el.border_color(lerp_rgb(idle_border, focus_border, t));
                if t > 0.01 {
                    el.shadow(vec![
                        BoxShadow::new(
                            px(0.),
                            px(0.),
                            rgba_with_alpha_scale(focus_ring_rgba, t).into(),
                        )
                        .spread_radius(px(2.5 * t)),
                    ])
                } else {
                    el
                }
            },
        );

        div()
            .flex()
            .key_context("DraftTextInput")
            .track_focus(&self.focus_handle(cx))
            .cursor(CursorStyle::IBeam)
            .on_action(cx.listener(Self::on_backspace))
            .on_action(cx.listener(Self::on_delete))
            .on_action(cx.listener(Self::on_delete_word_back))
            .on_action(cx.listener(Self::on_delete_word_forward))
            .on_action(cx.listener(Self::on_left))
            .on_action(cx.listener(Self::on_right))
            .on_action(cx.listener(Self::on_word_left))
            .on_action(cx.listener(Self::on_word_right))
            .on_action(cx.listener(Self::on_select_left))
            .on_action(cx.listener(Self::on_select_right))
            .on_action(cx.listener(Self::on_select_word_left))
            .on_action(cx.listener(Self::on_select_word_right))
            .on_action(cx.listener(Self::on_select_all))
            .on_action(cx.listener(Self::on_home))
            .on_action(cx.listener(Self::on_end))
            .on_action(cx.listener(Self::on_select_home))
            .on_action(cx.listener(Self::on_select_end))
            .on_action(cx.listener(Self::on_paste))
            .on_action(cx.listener(Self::on_copy))
            .on_action(cx.listener(Self::on_cut))
            .on_action(cx.listener(Self::on_submit))
            .on_action(cx.listener(Self::on_cancel))
            .on_action(cx.listener(Self::on_tab_next))
            .on_action(cx.listener(Self::on_tab_prev))
            .on_mouse_down(MouseButton::Left, cx.listener(Self::on_mouse_down))
            .on_mouse_up(MouseButton::Left, cx.listener(Self::on_mouse_up))
            .on_mouse_up_out(MouseButton::Left, cx.listener(Self::on_mouse_up))
            .on_mouse_move(cx.listener(Self::on_mouse_move))
            .w_full()
            .line_height(line_h)
            .text_size(text_sz)
            .child(animated_box)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_range_and_boundaries_handle_cidrs_urls_and_cjk() {
        let cidr = "203.0.113.0/24, 198.51.100.12";
        // Clicking inside "113" selects "113"
        let r = word_range_at(cidr, 7);
        assert_eq!(&cidr[r.start..r.end], "113");

        // Stepping backwards from end crosses "12", ".", "100"
        let end = utf16_len(cidr);
        let b1 = prev_word_boundary(cidr, end);
        assert_eq!(&cidr[b1..end], "12");
        let b2 = prev_word_boundary(cidr, b1);
        assert_eq!(&cidr[b2..b1], ".");
        let b3 = prev_word_boundary(cidr, b2);
        assert_eq!(&cidr[b3..b2], "100");

        // Stepping forward across URL tokens
        let url = "https://example.invalid/hook_01";
        assert_eq!(next_word_boundary(url, 0), 5); // "https"
        assert_eq!(next_word_boundary(url, 5), 8); // "://"
        assert_eq!(next_word_boundary(url, 8), 15); // "example"

        // UTF-16 CJK + emoji surrogate pair safety
        let mixed = "节点😀 203.0.113.5";
        let end_mixed = utf16_len(mixed);
        let prev = prev_word_boundary(mixed, end_mixed);
        assert!(prev < end_mixed);
        let word_first = word_range_at(mixed, 1);
        assert_eq!(word_first, 0..2); // "节点"
    }

    #[test]
    fn horizontal_scroll_tracks_caret_and_resets_when_content_fits() {
        // Content fits inside viewport -> always 0.0
        assert_eq!(compute_horizontal_scroll(50.0, 120.0, 180.0, 240.0), 0.0);

        // Long webhook URL overflowing a 200px viewport -> scroll right to keep 8px margin
        let s1 = compute_horizontal_scroll(0.0, 420.0, 420.0, 200.0);
        assert!((s1 - 228.0).abs() < 1e-4);

        // Caret moving left while still inside visible window keeps scroll steady
        let s2 = compute_horizontal_scroll(s1, 300.0, 420.0, 200.0);
        assert_eq!(s2, s1);

        // Caret moving past left margin scrolls left cleanly
        let s3 = compute_horizontal_scroll(s2, 100.0, 420.0, 200.0);
        assert!((s3 - 92.0).abs() < 1e-4);

        // Caret at 0 snaps back to 0.0
        assert_eq!(compute_horizontal_scroll(s3, 0.0, 420.0, 200.0), 0.0);
    }

    #[test]
    fn token_range_selects_full_cidr_endpoint_and_vault_id_tokens() {
        let cidr = "203.0.113.0/24, [::1]:7897 work-claude-max";
        let r_cidr = token_range_at(cidr, 7);
        assert_eq!(&cidr[r_cidr.start..r_cidr.end], "203.0.113.0/24");

        let r_v6 = token_range_at(cidr, 20);
        assert_eq!(&cidr[r_v6.start..r_v6.end], "[::1]:7897");

        let r_vid = token_range_at(cidr, 30);
        assert_eq!(&cidr[r_vid.start..r_vid.end], "work-claude-max");

        let fwd = next_word_boundary("7897 10809", 0);
        assert_eq!(fwd, 4);
    }
}
