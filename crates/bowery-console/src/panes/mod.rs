//! Pane registry. Each pane owns its own state and rendering; the
//! top-level `App` selects which one is foregrounded and dispatches
//! input to it.

pub(crate) mod alerts;
pub(crate) mod audit;
pub(crate) mod chat;
pub(crate) mod doctor;
pub(crate) mod help;
pub(crate) mod map;
pub(crate) mod peers;
pub(crate) mod query;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum PaneId {
    Query,
    Alerts,
    Map,
    Audit,
    Peers,
    Doctor,
    Chat,
    Help,
}

impl PaneId {
    /// Hotkey used in the top-tabs bar (`[1] Query` etc.).
    pub(crate) fn hotkey(self) -> char {
        match self {
            Self::Query => '1',
            Self::Alerts => '2',
            Self::Map => '3',
            Self::Audit => '4',
            Self::Peers => '5',
            Self::Doctor => '6',
            Self::Chat => '7',
            Self::Help => '8',
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Query => "Query",
            Self::Alerts => "Alerts",
            Self::Map => "Map",
            Self::Audit => "Audit",
            Self::Peers => "Peers",
            Self::Doctor => "Doctor",
            Self::Chat => "Chat",
            Self::Help => "Help",
        }
    }

    pub(crate) const ALL: [PaneId; 8] = [
        Self::Query,
        Self::Alerts,
        Self::Map,
        Self::Audit,
        Self::Peers,
        Self::Doctor,
        Self::Chat,
        Self::Help,
    ];

    /// Panes whose contents are a selectable list. These get row
    /// navigation keys and an Enter-to-detail overlay; the others
    /// (Chat, Help, Doctor prose) keep the keys for their own use.
    pub(crate) fn is_browsable(self) -> bool {
        matches!(
            self,
            Self::Query | Self::Alerts | Self::Audit | Self::Peers | Self::Map
        )
    }

    /// Resolve `[1]`-style hotkeys back to a `PaneId`.
    pub(crate) fn from_hotkey(c: char) -> Option<Self> {
        Self::ALL.iter().copied().find(|p| p.hotkey() == c)
    }
}

/// Split a pane's inner area into (content, one-line key hint).
///
/// Every browsable pane shows its key legend on the last line so
/// drill-down is discoverable without opening the handbook.
pub(crate) fn split_hint(
    inner: ratatui::layout::Rect,
) -> (ratatui::layout::Rect, ratatui::layout::Rect) {
    use ratatui::layout::{Constraint, Direction, Layout};
    if inner.height < 2 {
        return (inner, ratatui::layout::Rect { height: 0, ..inner });
    }
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(inner);
    (parts[0], parts[1])
}

/// One `label: value` line in a detail overlay.
pub(crate) fn kv(label: &str, value: impl Into<String>) -> ratatui::text::Line<'static> {
    use ratatui::text::{Line, Span};
    Line::from(vec![
        Span::styled(format!("{label:<12}"), crate::theme::detail_label()),
        Span::raw(value.into()),
    ])
}

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

// ---------------------------------------------------------------------------
// Shared rendering for the panes backed by a `CollectSink` (Query, Audit,
// Map). Before this, each had its own near-identical stateless `Table`,
// which is why only the first screenful of any result was ever reachable.
// ---------------------------------------------------------------------------

/// Render a result set as a browsable table with a key-hint footer.
///
/// Takes `&mut Browser` because the visible window can only be computed
/// once the row height is known, which is here.
pub(crate) fn render_sink_table(
    f: &mut ratatui::Frame<'_>,
    area: ratatui::layout::Rect,
    sink: &bowery_cli::exec::CollectSink,
    browser: &mut crate::browse::Browser,
    hint: &str,
) {
    use ratatui::layout::Constraint;
    use ratatui::widgets::{Cell, Paragraph, Row as TableRow, Table, TableState};

    browser.set_len(sink.rows.len());
    if sink.columns.is_empty() {
        f.render_widget(Paragraph::new("(no rows)").style(crate::theme::dim()), area);
        return;
    }

    let (list_area, hint_area) = split_hint(area);
    let header = TableRow::new(
        sink.columns
            .iter()
            .map(|c| Cell::from(c.clone()))
            .collect::<Vec<_>>(),
    )
    .style(crate::theme::header_row());

    // One line for the header; the rest is rows.
    let visible = browser.visible_range(list_area.height.saturating_sub(1) as usize);
    let rows: Vec<TableRow> = sink.rows[visible]
        .iter()
        .map(|r| {
            TableRow::new(
                r.values
                    .iter()
                    .map(|v| Cell::from(query::render_value(v)))
                    .collect::<Vec<_>>(),
            )
        })
        .collect();

    let widths: Vec<Constraint> = sink.columns.iter().map(|_| Constraint::Min(8)).collect();
    let table = Table::new(rows, widths)
        .header(header)
        .row_highlight_style(crate::theme::selected_row())
        .highlight_symbol("▸ ");
    let mut state = TableState::default().with_selected(browser.selected_in_view());
    f.render_stateful_widget(table, list_area, &mut state);
    f.render_widget(
        Paragraph::new(hint.to_string()).style(crate::theme::hint()),
        hint_area,
    );
}

/// Full-screen detail for one row of a result set: every column on its
/// own line, untruncated.
///
/// This is the whole point of the overlay — a table cell clips long
/// values (a sha256, a full argv, a rationale) exactly when they matter
/// most.
pub(crate) fn render_sink_detail(
    f: &mut ratatui::Frame<'_>,
    area: ratatui::layout::Rect,
    sink: &bowery_cli::exec::CollectSink,
    browser: &mut crate::browse::Browser,
    title: &str,
    hint: &str,
) {
    use ratatui::text::{Line, Span};
    use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

    // Sync here too: the overlay must not depend on the list having been
    // rendered first, and a refresh can shrink the set while it's open.
    browser.set_len(sink.rows.len());
    let Some(idx) = browser.selected() else {
        return;
    };
    let Some(row) = sink.rows.get(idx) else {
        return;
    };

    let block = Block::default().borders(Borders::ALL).title(format!(
        "{title} — row {} of {} — Esc back",
        idx + 1,
        sink.rows.len()
    ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut lines: Vec<Line<'static>> = Vec::new();
    for (i, col) in sink.columns.iter().enumerate() {
        let value = row
            .values
            .get(i)
            .map_or_else(|| "NULL".to_string(), query::render_value);
        // Multi-line values (a rationale, an argv) get their own block so
        // the label column stays aligned.
        if value.contains('\n') {
            lines.push(kv(col, ""));
            for chunk in value.lines() {
                lines.push(Line::from(format!("  {chunk}")));
            }
        } else {
            lines.push(kv(col, value));
        }
    }

    if !hint.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            hint.to_string(),
            crate::theme::hint(),
        )));
    }

    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

#[cfg(test)]
mod tests {
    use super::*;
    use bowery_cli::exec::{CollectSink, CollectedRow};
    use bowery_proto::{SqlValue, SqlValueKind};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    pub(crate) fn text_row(vals: &[&str]) -> CollectedRow {
        CollectedRow {
            agent_fp: Vec::new(),
            values: vals
                .iter()
                .map(|v| SqlValue {
                    value: Some(SqlValueKind::Text((*v).to_string())),
                })
                .collect(),
        }
    }

    fn sink(cols: &[&str], n: usize) -> CollectSink {
        CollectSink {
            columns: cols.iter().map(|c| (*c).to_string()).collect(),
            rows: (0..n)
                .map(|i| {
                    let vals: Vec<String> = cols.iter().map(|c| format!("{c}-{i}")).collect();
                    text_row(&vals.iter().map(String::as_str).collect::<Vec<_>>())
                })
                .collect(),
        }
    }

    fn draw(f: impl FnOnce(&mut ratatui::Frame<'_>)) -> String {
        let mut term = Terminal::new(TestBackend::new(90, 16)).unwrap();
        term.draw(f).unwrap();
        term.backend()
            .buffer()
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect::<String>()
    }

    #[test]
    fn sink_table_reaches_rows_past_the_first_screenful() {
        let s = sink(&["col"], 200);
        let mut b = crate::browse::Browser::default();
        let first = draw(|f| render_sink_table(f, f.area(), &s, &mut b, "hint"));
        assert!(first.contains("col-0"), "first page renders");
        assert!(
            !first.contains("col-199"),
            "last row is off-screen initially"
        );

        b.end();
        let last = draw(|f| render_sink_table(f, f.area(), &s, &mut b, "hint"));
        assert!(
            last.contains("col-199"),
            "the end of a 200-row result must be reachable: {last}"
        );
    }

    #[test]
    fn sink_detail_shows_every_column_untruncated() {
        // A wide row is exactly the case the table clips.
        let mut s = sink(&["a", "b", "c"], 1);
        s.rows[0] = text_row(&["short", &"f".repeat(64), "tail"]);
        let mut b = crate::browse::Browser::default();
        let out = draw(|f| render_sink_detail(f, f.area(), &s, &mut b, "T", "pivots: x"));
        assert!(out.contains(&"f".repeat(64)), "64-char value must be whole");
        assert!(out.contains("tail"), "later columns must still render");
        assert!(out.contains("pivots: x"), "hint line missing");
    }

    #[test]
    fn sink_detail_on_empty_result_is_a_noop() {
        let s = CollectSink::default();
        let mut b = crate::browse::Browser::default();
        // Must not panic when there is nothing selected.
        let _ = draw(|f| render_sink_detail(f, f.area(), &s, &mut b, "T", ""));
    }

    /// The defect this guards: `is_browsable` claiming a pane that
    /// `App::browser_mut` has no arm for. `handle_browse_keys` consumes
    /// arrow keys for anything browsable, so a mismatch silently eats
    /// the keystrokes *and* keeps them from reaching the input editor —
    /// which is exactly what shipped in the first console slice.
    ///
    /// `browser_mut` lives on `App` (needs a live relay to construct),
    /// so this asserts against the list it must stay in step with; the
    /// match there is exhaustive over `PaneId`, so adding a pane forces
    /// both sides to be revisited.
    #[test]
    fn browsable_panes_are_exactly_the_ones_with_browsers() {
        let browsable: Vec<PaneId> = PaneId::ALL
            .iter()
            .copied()
            .filter(|p| p.is_browsable())
            .collect();
        assert_eq!(
            browsable,
            vec![
                PaneId::Query,
                PaneId::Alerts,
                PaneId::Map,
                PaneId::Audit,
                PaneId::Peers
            ],
            "if this changes, App::browser_mut and App::open_detail must \
             gain or lose the same arm"
        );
        // Prose panes must keep their keys: Chat needs them for the
        // message editor, Help for scrolling.
        for p in [PaneId::Doctor, PaneId::Chat, PaneId::Help] {
            assert!(!p.is_browsable(), "{p:?} must not claim browsability");
        }
    }
}
