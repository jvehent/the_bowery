//! Placeholder pane content for views that haven't shipped yet
//! (Alerts → C-3, Map → C-5, etc). Renders a single centered line
//! pointing the operator at the relevant phase.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::theme;

pub(crate) fn render(f: &mut Frame<'_>, area: Rect, pane: &str, phase: &str) {
    let block = Block::default().borders(Borders::ALL).title(pane);
    let inner = block.inner(area);
    f.render_widget(block, area);
    let body =
        Paragraph::new(format!("{pane} pane lands in console phase {phase}.")).style(theme::dim());
    f.render_widget(body, inner);
}
