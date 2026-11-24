//! Deterministic single-line text editing state expressed in UTF-16 offsets for GPUI IME.

use std::ops::Range;
use unicode_segmentation::UnicodeSegmentation;

pub fn utf16_len(text: &str) -> usize {
    text.encode_utf16().count()
}

pub fn byte_index_from_utf16(text: &str, utf16_offset: usize) -> usize {
    let mut units = 0usize;
    for (byte, ch) in text.char_indices() {
        if units + ch.len_utf16() > utf16_offset {
            return byte;
        }
        units += ch.len_utf16();
        if units == utf16_offset {
            return byte + ch.len_utf8();
        }
    }
    text.len()
}

pub fn utf16_index_from_byte(text: &str, byte_offset: usize) -> usize {
    let mut end = byte_offset.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].encode_utf16().count()
}

pub fn clamp_utf16_range(text: &str, range: Range<usize>) -> Range<usize> {
    let (start, end) = if range.start <= range.end {
        (range.start, range.end)
    } else {
        (range.end, range.start)
    };
    let start = byte_index_from_utf16(text, start);
    let end = byte_index_from_utf16(text, end);
    utf16_index_from_byte(text, start)..utf16_index_from_byte(text, end)
}

/// Maximum characters retained in a single-line `TextEditState` so multi-MB clipboard pastes
/// never stall DirectWrite text shaping or layout.
pub const MAX_SINGLE_LINE_CHARS: usize = 4096;

/// Returns the longest prefix of `s` containing at most `max_chars` Unicode scalar values,
/// snapping back to the nearest extended grapheme boundary whenever possible so emoji ZWJ
/// sequences and combining marks are never torn in half.
fn slice_within_char_budget(s: &str, max_chars: usize) -> &str {
    if max_chars == 0 || s.is_empty() {
        return "";
    }
    let mut total_chars = 0usize;
    let mut safe_end = 0usize;
    for (idx, grapheme) in s.grapheme_indices(true) {
        let g_chars = grapheme.chars().count();
        if total_chars + g_chars > max_chars {
            if safe_end == 0 && g_chars > 64 {
                // Pathological single grapheme exceeding 64 scalar chars (e.g. Zalgo combining run):
                // fall back to a clean UTF-8 `char` boundary.
                let fallback_end = s
                    .char_indices()
                    .nth(max_chars)
                    .map(|(b, _)| b)
                    .unwrap_or(s.len());
                return &s[..fallback_end];
            }
            return &s[..safe_end];
        }
        total_chars += g_chars;
        safe_end = idx + grapheme.len();
    }
    s
}

pub fn sanitize_input(raw: &str) -> String {
    // Collect a tiny margin past `MAX_SINGLE_LINE_CHARS` so multi-codepoint graphemes right at
    // the cap can be evaluated cleanly without allocating or scanning multi-MB clipboard blobs.
    const SCAN_CAP: usize = MAX_SINGLE_LINE_CHARS + 32;
    let mut out = String::with_capacity(raw.len().min(MAX_SINGLE_LINE_CHARS));
    let mut emitted = 0usize;
    let mut prev_was_newline = false;

    for ch in raw.chars() {
        match ch {
            '\r' | '\n' => {
                if !prev_was_newline {
                    if emitted >= SCAN_CAP {
                        break;
                    }
                    out.push(' ');
                    emitted += 1;
                    prev_was_newline = true;
                }
            }
            '\t' => {
                prev_was_newline = false;
                if emitted >= SCAN_CAP {
                    break;
                }
                out.push(' ');
                emitted += 1;
            }
            c if c.is_control() => {
                prev_was_newline = false;
            }
            c => {
                prev_was_newline = false;
                if emitted >= SCAN_CAP {
                    break;
                }
                out.push(c);
                emitted += 1;
            }
        }
    }

    if emitted > MAX_SINGLE_LINE_CHARS {
        let trimmed_len = slice_within_char_budget(&out, MAX_SINGLE_LINE_CHARS).len();
        out.truncate(trimmed_len);
    }
    out
}

#[derive(Debug, Clone)]
pub struct TextEditState {
    text: String,
    selection: Range<usize>,
    cursor: usize,
    marked: Option<Range<usize>>,
}

impl Default for TextEditState {
    fn default() -> Self {
        Self::new()
    }
}

impl TextEditState {
    pub fn new() -> Self {
        Self {
            text: String::new(),
            selection: 0..0,
            cursor: 0,
            marked: None,
        }
    }

    pub fn from_text(text: &str) -> Self {
        let mut state = Self::new();
        state.set_text(text);
        state
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn selected_range(&self) -> Range<usize> {
        self.selection.clone()
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn marked_range(&self) -> Option<Range<usize>> {
        self.marked.clone()
    }

    pub fn selected_text(&self) -> String {
        self.substring(self.selection.clone())
    }

    pub fn substring_with_range(&self, range: Range<usize>) -> (String, Range<usize>) {
        let actual = clamp_utf16_range(&self.text, range);
        let start = byte_index_from_utf16(&self.text, actual.start);
        let end = byte_index_from_utf16(&self.text, actual.end);
        (self.text[start..end].to_string(), actual)
    }

    pub fn substring(&self, range: Range<usize>) -> String {
        self.substring_with_range(range).0
    }

    pub fn selection_reversed(&self) -> bool {
        !self.selection.is_empty() && self.cursor == self.selection.start
    }

    pub fn select_to(&mut self, anchor: usize, focus: usize) {
        let anchor = self.clamp_offset(anchor);
        let focus = self.clamp_offset(focus);
        self.selection = anchor.min(focus)..anchor.max(focus);
        self.cursor = focus;
        self.marked = None;
    }

    pub fn set_text(&mut self, text: &str) {
        self.text = sanitize_input(text);
        self.marked = None;
        let end = utf16_len(&self.text);
        self.selection = end..end;
        self.cursor = end;
    }

    pub fn set_cursor(&mut self, utf16_offset: usize) {
        let offset = self.clamp_offset(utf16_offset);
        self.selection = offset..offset;
        self.cursor = offset;
        self.marked = None;
    }

    pub fn select_range(&mut self, range: Range<usize>) {
        let forward = range.start <= range.end;
        let selection = self.clamp_range(range);
        self.cursor = if forward {
            selection.end
        } else {
            selection.start
        };
        self.selection = selection;
        self.marked = None;
    }

    pub fn select_all(&mut self) {
        let end = utf16_len(&self.text);
        self.selection = 0..end;
        self.cursor = end;
        self.marked = None;
    }

    pub fn move_left(&mut self, extend: bool) {
        if !extend && !self.selection.is_empty() {
            self.selection = self.selection.start..self.selection.start;
            self.cursor = self.selection.start;
            return;
        }
        let target = self.previous_grapheme(self.cursor);
        self.move_cursor_to(target, extend);
    }

    pub fn move_right(&mut self, extend: bool) {
        if !extend && !self.selection.is_empty() {
            self.selection = self.selection.end..self.selection.end;
            self.cursor = self.selection.end;
            return;
        }
        let target = self.next_grapheme(self.cursor);
        self.move_cursor_to(target, extend);
    }

    pub fn move_home(&mut self, extend: bool) {
        self.move_cursor_to(0, extend);
    }

    pub fn move_end(&mut self, extend: bool) {
        self.move_cursor_to(utf16_len(&self.text), extend);
    }

    pub fn backspace(&mut self) -> bool {
        if !self.selection.is_empty() {
            let range = self.selection.clone();
            self.replace_range(range, "");
            return true;
        }
        if self.cursor == 0 {
            return false;
        }
        let start = self.previous_grapheme(self.cursor);
        let range = start..self.cursor;
        self.replace_range(range, "");
        true
    }

    pub fn delete(&mut self) -> bool {
        if !self.selection.is_empty() {
            let range = self.selection.clone();
            self.replace_range(range, "");
            return true;
        }
        let end = self.next_grapheme(self.cursor);
        if end == self.cursor {
            return false;
        }
        let range = self.cursor..end;
        self.replace_range(range, "");
        true
    }

    pub fn insert_text(&mut self, text: &str) -> bool {
        let inserted = sanitize_input(text);
        if inserted.is_empty() {
            return false;
        }
        let range = self.clamp_range(self.selection.clone());
        let (start, actual_utf16) = self.replace_range_inner(range.clone(), &inserted);
        if actual_utf16 == 0 && range.is_empty() {
            return false;
        }
        let end = start + actual_utf16;
        self.marked = None;
        self.selection = end..end;
        self.cursor = end;
        true
    }

    pub fn replace_text_in_range(&mut self, range: Option<Range<usize>>, text: &str) {
        let range = range
            .map(|r| self.clamp_range(r))
            .or_else(|| self.marked.clone())
            .unwrap_or_else(|| self.selection.clone());
        let inserted = sanitize_input(text);
        let (start, actual_utf16) = self.replace_range_inner(range, &inserted);
        self.marked = None;
        let end = start + actual_utf16;
        self.selection = end..end;
        self.cursor = end;
    }

    pub fn replace_and_mark_text_in_range(
        &mut self,
        range: Option<Range<usize>>,
        text: &str,
        new_selected_range: Option<Range<usize>>,
    ) {
        let range = range
            .map(|r| self.clamp_range(r))
            .or_else(|| self.marked.clone())
            .unwrap_or_else(|| self.selection.clone());
        let inserted = sanitize_input(text);
        let (start, inserted_len) = self.replace_range_inner(range, &inserted);
        let end = start + inserted_len;

        if inserted_len == 0 {
            self.marked = None;
            self.selection = start..start;
            self.cursor = start;
            return;
        }

        self.marked = Some(start..end);
        let selected = new_selected_range.unwrap_or(inserted_len..inserted_len);
        let selected_start = start + selected.start.min(inserted_len);
        let selected_end = start + selected.end.min(inserted_len);
        self.selection = selected_start.min(selected_end)..selected_start.max(selected_end);
        self.cursor = selected_end;
    }

    pub fn unmark_text(&mut self) {
        self.marked = None;
    }

    fn replace_range(&mut self, range: Range<usize>, inserted: &str) {
        let range = self.clamp_range(range);
        let (start, actual_utf16) = self.replace_range_inner(range, inserted);
        let end = start + actual_utf16;
        self.marked = None;
        self.selection = end..end;
        self.cursor = end;
    }

    fn replace_range_inner(&mut self, range: Range<usize>, inserted: &str) -> (usize, usize) {
        let start_byte = byte_index_from_utf16(&self.text, range.start);
        let end_byte = byte_index_from_utf16(&self.text, range.end);
        let kept_chars =
            self.text[..start_byte].chars().count() + self.text[end_byte..].chars().count();
        let budget = MAX_SINGLE_LINE_CHARS.saturating_sub(kept_chars);
        let bounded = slice_within_char_budget(inserted, budget);
        let actual_utf16 = utf16_len(bounded);
        self.text.replace_range(start_byte..end_byte, bounded);
        (utf16_index_from_byte(&self.text, start_byte), actual_utf16)
    }

    fn move_cursor_to(&mut self, target: usize, extend: bool) {
        let target = self.clamp_offset(target);
        if extend {
            let anchor = if self.cursor == self.selection.start {
                self.selection.end
            } else {
                self.selection.start
            };
            self.selection = anchor.min(target)..anchor.max(target);
            self.cursor = target;
        } else {
            self.selection = target..target;
            self.cursor = target;
        }
        self.marked = None;
    }

    fn previous_grapheme(&self, utf16_offset: usize) -> usize {
        let byte = byte_index_from_utf16(&self.text, utf16_offset);
        let previous = self.text[..byte]
            .grapheme_indices(true)
            .next_back()
            .map(|(index, _)| index)
            .unwrap_or(0);
        utf16_index_from_byte(&self.text, previous)
    }

    fn next_grapheme(&self, utf16_offset: usize) -> usize {
        let byte = byte_index_from_utf16(&self.text, utf16_offset);
        let next = self.text[byte..]
            .graphemes(true)
            .next()
            .map(|grapheme| byte + grapheme.len())
            .unwrap_or(self.text.len());
        utf16_index_from_byte(&self.text, next)
    }

    fn clamp_offset(&self, offset: usize) -> usize {
        utf16_index_from_byte(&self.text, byte_index_from_utf16(&self.text, offset))
    }

    fn clamp_range(&self, range: Range<usize>) -> Range<usize> {
        clamp_utf16_range(&self.text, range)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16_ime_composition_and_graphemes_roundtrip() {
        let mut state = TextEditState::from_text("a😀");
        assert!(state.backspace());
        assert_eq!(state.text(), "a");
        state.replace_and_mark_text_in_range(None, "ni", None);
        assert_eq!(state.marked_range(), Some(1..3));
        state.replace_text_in_range(None, "你");
        assert_eq!(state.text(), "a你");
        assert_eq!(state.marked_range(), None);
    }

    #[test]
    fn sanitize_input_collapses_crlf_and_consecutive_newlines() {
        assert_eq!(sanitize_input("US\r\nJP\r\n\r\nSG"), "US JP SG");
        assert_eq!(
            sanitize_input("line1\n\n\nline2\r\rline3"),
            "line1 line2 line3"
        );
        assert_eq!(sanitize_input("a\tb\x07c"), "a bc");
    }

    #[test]
    fn caps_single_line_paste_at_max_chars_preserving_grapheme_boundaries() {
        let huge = "x".repeat(MAX_SINGLE_LINE_CHARS + 50_000);
        let mut state = TextEditState::from_text(&huge);
        assert_eq!(state.text().chars().count(), MAX_SINGLE_LINE_CHARS);
        assert!(!state.insert_text("more"));
        assert_eq!(state.text().chars().count(), MAX_SINGLE_LINE_CHARS);

        // Multi-codepoint ZWJ emoji grapheme (`👨‍👩‍👧` = 5 scalar chars) straddling the 4096 boundary
        // must not be torn into partial ZWJ fragments.
        let prefix = "a".repeat(MAX_SINGLE_LINE_CHARS - 3);
        let mut emoji_state = TextEditState::from_text(&prefix);
        let _ = emoji_state.insert_text("👨‍👩‍👧tail");
        assert_eq!(emoji_state.text(), prefix);
        assert!(emoji_state.text().chars().count() <= MAX_SINGLE_LINE_CHARS);
    }
}
