//! Help pane — renders the operator handbook (`docs/CONSOLE.md`)
//! inside the console so operators can look up syntax without
//! switching applications.
//!
//! The markdown is `include_str!`ed at compile time so the binary
//! stays self-contained: distro packagers don't need to ship the
//! docs file alongside `/usr/bin/bowery-console`.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::theme;

const HANDBOOK_MD: &str = include_str!("../../../../docs/CONSOLE.md");

#[derive(Debug, Default)]
pub(crate) struct HelpPane {
    /// Vertical scroll offset (lines).
    pub(crate) scroll: u16,
}

impl HelpPane {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn scroll_down(&mut self, by: u16) {
        self.scroll = self.scroll.saturating_add(by);
    }

    pub(crate) fn scroll_up(&mut self, by: u16) {
        self.scroll = self.scroll.saturating_sub(by);
    }

    pub(crate) fn home(&mut self) {
        self.scroll = 0;
    }

    pub(crate) fn render(&self, f: &mut Frame<'_>, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title("Help (↑↓/PgUp/PgDn scroll · Home jumps to top)");
        let inner = block.inner(area);
        f.render_widget(block, area);

        let lines: Vec<Line<'static>> = HANDBOOK_MD.lines().map(render_md_line).collect();
        f.render_widget(
            Paragraph::new(lines)
                .scroll((self.scroll, 0))
                .wrap(Wrap { trim: false }),
            inner,
        );
    }
}

/// Cheap markdown-aware line renderer. Not a real parser; just
/// enough to make headings stand out and inline code highlight.
fn render_md_line(line: &str) -> Line<'static> {
    if let Some(rest) = line.strip_prefix("# ") {
        return Line::from(Span::styled(
            rest.to_string(),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ));
    }
    if let Some(rest) = line.strip_prefix("## ") {
        return Line::from(Span::styled(
            rest.to_string(),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ));
    }
    if let Some(rest) = line.strip_prefix("### ") {
        return Line::from(Span::styled(
            rest.to_string(),
            Style::default().fg(Color::Yellow),
        ));
    }
    if line.starts_with("    ") || line.starts_with("```") {
        return Line::from(Span::styled(
            line.to_string(),
            Style::default().fg(Color::Green),
        ));
    }
    if line.starts_with('|') {
        return Line::from(Span::styled(
            line.to_string(),
            Style::default().fg(Color::Magenta),
        ));
    }
    if line.starts_with("- ") || line.starts_with("* ") {
        return Line::from(vec![
            Span::styled("• ", theme::dim()),
            Span::raw(line[2..].to_string()),
        ]);
    }
    Line::from(line.to_string())
}
