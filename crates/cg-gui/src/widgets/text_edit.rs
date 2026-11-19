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

pub fn sanitize_input(raw: &str) -> String {
    raw.chars()
        .filter_map(|c| match c {
            '\r' | '\n' | '\t' => Some(' '),
            c if c.is_control() => None,
            c => Some(c),
        })
        .collect()
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
        let range = self.selection.clone();
        self.replace_range(range, &inserted);
        true
    }

    pub fn replace_text_in_range(&mut self, range: Option<Range<usize>>, text: &str) {
        let range = range
            .map(|r| self.clamp_range(r))
            .or_else(|| self.marked.clone())
            .unwrap_or_else(|| self.selection.clone());
        let inserted = sanitize_input(text);
        let start = self.replace_range_inner(range, &inserted);
        self.marked = None;
        let end = start + utf16_len(&inserted);
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
        let start = self.replace_range_inner(range, &inserted);
        let inserted_len = utf16_len(&inserted);
        let end = start + inserted_len;

        if inserted.is_empty() {
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
        let start = self.replace_range_inner(range, inserted);
        let end = start + utf16_len(inserted);
        self.marked = None;
        self.selection = end..end;
        self.cursor = end;
    }

    fn replace_range_inner(&mut self, range: Range<usize>, inserted: &str) -> usize {
        let start_byte = byte_index_from_utf16(&self.text, range.start);
        let end_byte = byte_index_from_utf16(&self.text, range.end);
        self.text.replace_range(start_byte..end_byte, inserted);
        utf16_index_from_byte(&self.text, start_byte)
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
}
