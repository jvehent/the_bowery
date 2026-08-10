//! Centralized colors so changing the visual identity is a one-file
//! edit. Keep low-saturation: the console is meant to be readable
//! over an ssh + tmux + low-bandwidth combo, where bright colors
//! flicker and washed-out ones don't render at all.

use ratatui::style::{Color, Modifier, Style};

/// Status bar text — high contrast, slightly muted.
pub(crate) fn status_bar() -> Style {
    Style::default().fg(Color::Black).bg(Color::Cyan)
}

pub(crate) fn pane_title_active() -> Style {
    Style::default()
        .fg(Color::Black)
        .bg(Color::White)
        .add_modifier(Modifier::BOLD)
}

pub(crate) fn pane_title_idle() -> Style {
    Style::default().fg(Color::DarkGray)
}

pub(crate) fn input_prompt() -> Style {
    Style::default().fg(Color::Yellow)
}

pub(crate) fn error() -> Style {
    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
}

pub(crate) fn dim() -> Style {
    Style::default().fg(Color::DarkGray)
}

/// The selected row in a browsable table. Reversed rather than a fixed
/// background so it stays visible under any terminal colour scheme —
/// including the low-contrast ones this console is meant to survive.
pub(crate) fn selected_row() -> Style {
    Style::default().add_modifier(Modifier::REVERSED)
}

/// Label column inside a detail overlay.
pub(crate) fn detail_label() -> Style {
    Style::default().fg(Color::Cyan)
}

/// Footer hint line (key legends).
pub(crate) fn hint() -> Style {
    Style::default()
        .fg(Color::DarkGray)
        .add_modifier(Modifier::ITALIC)
}

pub(crate) fn header_row() -> Style {
    Style::default()
        .fg(Color::Black)
        .bg(Color::Gray)
        .add_modifier(Modifier::BOLD)
}
