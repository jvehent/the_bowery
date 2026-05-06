//! Single-line input editor — the bottom prompt for the active
//! pane and for the `:command` palette. Multi-line editing is on
//! the C-4 wishlist; for now we keep it simple.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

#[derive(Debug, Default)]
pub(crate) struct InputState {
    pub(crate) buffer: String,
    pub(crate) cursor: usize,
    /// History (most recent at index 0). Walked with up/down arrow.
    pub(crate) history: Vec<String>,
    /// Index into `history` while walking; `None` = editing a new
    /// line that hasn't been committed yet.
    history_cursor: Option<usize>,
}

#[derive(Debug)]
pub(crate) enum InputAction {
    /// Bound to Enter — caller should treat the buffer as a
    /// completed line and process it. Returns the line and clears
    /// the editor.
    Submit(String),
    /// Bound to Esc — caller should cancel any modal it had open.
    Cancel,
    /// Editing happened; redraw and continue.
    Edited,
    /// No input action this key — caller may consume the key for
    /// pane-level navigation.
    Passthrough,
}

impl InputState {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn clear(&mut self) {
        self.buffer.clear();
        self.cursor = 0;
        self.history_cursor = None;
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) -> InputAction {
        match (key.code, key.modifiers) {
            (KeyCode::Enter, KeyModifiers::NONE) => {
                let line = std::mem::take(&mut self.buffer);
                self.cursor = 0;
                self.history_cursor = None;
                if !line.is_empty() {
                    self.history.insert(0, line.clone());
                    self.history.truncate(500);
                }
                InputAction::Submit(line)
            }
            (KeyCode::Esc, _) => InputAction::Cancel,
            (KeyCode::Backspace, _) => {
                if self.cursor > 0 {
                    let prev = self.cursor - 1;
                    self.buffer.remove(prev);
                    self.cursor = prev;
                    InputAction::Edited
                } else {
                    InputAction::Passthrough
                }
            }
            (KeyCode::Delete, _) => {
                if self.cursor < self.buffer.len() {
                    self.buffer.remove(self.cursor);
                    InputAction::Edited
                } else {
                    InputAction::Passthrough
                }
            }
            (KeyCode::Left, _) => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                    InputAction::Edited
                } else {
                    InputAction::Passthrough
                }
            }
            (KeyCode::Right, _) => {
                if self.cursor < self.buffer.len() {
                    self.cursor += 1;
                    InputAction::Edited
                } else {
                    InputAction::Passthrough
                }
            }
            (KeyCode::Home, _) => {
                self.cursor = 0;
                InputAction::Edited
            }
            (KeyCode::End, _) => {
                self.cursor = self.buffer.len();
                InputAction::Edited
            }
            (KeyCode::Up, _) => self.history_step(1),
            (KeyCode::Down, _) => self.history_step(-1),
            (KeyCode::Char(c), m) if !m.contains(KeyModifiers::CONTROL) => {
                self.buffer.insert(self.cursor, c);
                self.cursor += c.len_utf8();
                InputAction::Edited
            }
            _ => InputAction::Passthrough,
        }
    }

    fn history_step(&mut self, dir: i32) -> InputAction {
        if self.history.is_empty() {
            return InputAction::Passthrough;
        }
        let new_cursor = match self.history_cursor {
            None if dir > 0 => Some(0),
            Some(i) if dir > 0 => Some((i + 1).min(self.history.len() - 1)),
            Some(0) if dir < 0 => None,
            Some(i) if dir < 0 => Some(i - 1),
            other => other,
        };
        self.history_cursor = new_cursor;
        if let Some(i) = new_cursor {
            self.buffer.clone_from(&self.history[i]);
            self.cursor = self.buffer.len();
        } else {
            self.buffer.clear();
            self.cursor = 0;
        }
        InputAction::Edited
    }
}
