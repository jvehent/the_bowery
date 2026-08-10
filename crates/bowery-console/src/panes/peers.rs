//! Peers pane — read/write `~/.bowery/peers.toml` via the
//! `bowery_cli::peers` library API.
//!
//! C-3 ships a read-only renderer plus `:peers reload` reload via
//! the palette. Add/remove are wired in C-4 (they need richer input
//! editing).

use bowery_cli::peers::{Manifest, Peer};
use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row as TableRow, Table, TableState};

use crate::browse::Browser;
use crate::panes::kv;
use crate::theme;

#[derive(Debug, Default)]
pub(crate) struct PeersPane {
    pub(crate) entries: Vec<Peer>,
    /// Cursor + viewport over `entries`.
    browser: Browser,
    pub(crate) error: Option<String>,
    pub(crate) loaded_path: Option<std::path::PathBuf>,
}

impl PeersPane {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Reload the manifest from disk. Called on pane activation and
    /// from the `:peers reload` palette command.
    pub(crate) fn reload(&mut self) {
        let path = match bowery_cli::peers::default_path() {
            Ok(p) => p,
            Err(e) => {
                self.error = Some(format!("default_path: {e:#}"));
                return;
            }
        };
        match Manifest::load(&path) {
            Ok(m) => {
                self.entries = m.peers;
                self.loaded_path = Some(path);
                self.error = None;
            }
            Err(e) => {
                self.error = Some(format!("{}: {e:#}", path.display()));
                self.loaded_path = Some(path);
            }
        }
    }

    pub(crate) fn render(&mut self, f: &mut Frame<'_>, area: Rect) {
        let title = match &self.loaded_path {
            Some(p) => format!("Peers ({} entries · {})", self.entries.len(), p.display()),
            None => "Peers (not loaded)".to_string(),
        };
        let block = Block::default().borders(Borders::ALL).title(title);
        let inner = block.inner(area);
        f.render_widget(block, area);

        if let Some(e) = &self.error {
            f.render_widget(Paragraph::new(e.clone()).style(theme::error()), inner);
            return;
        }
        if self.entries.is_empty() {
            f.render_widget(
                Paragraph::new(
                    "peers.toml is empty.\n\
                     Add via `bowery peers add --name <…> --fp <…> --pubkey-b64 <…>`\n\
                     or, in this console, the `:peers add` palette command (C-4).",
                )
                .style(theme::dim()),
                inner,
            );
            return;
        }

        let header = TableRow::new([
            Cell::from("name"),
            Cell::from("fingerprint"),
            Cell::from("pubkey_b64"),
        ])
        .style(theme::header_row());

        self.browser.set_len(self.entries.len());
        let (list_area, hint_area) = crate::panes::split_hint(inner);
        let visible = self
            .browser
            .visible_range(list_area.height.saturating_sub(1) as usize);
        let rows: Vec<TableRow> = self.entries[visible]
            .iter()
            .map(|p| {
                TableRow::new([
                    Cell::from(p.name.clone()),
                    Cell::from(short_fp(&p.fp)),
                    Cell::from(p.pubkey_b64.clone()),
                ])
            })
            .collect();
        let widths = [
            Constraint::Length(20),
            Constraint::Length(20),
            Constraint::Min(20),
        ];
        let table = Table::new(rows, widths)
            .header(header)
            .row_highlight_style(theme::selected_row())
            .highlight_symbol("▸ ");
        let mut state = TableState::default().with_selected(self.browser.selected_in_view());
        f.render_stateful_widget(table, list_area, &mut state);
        f.render_widget(
            Paragraph::new("↑↓ move  ⏎ peer detail  r reload").style(theme::hint()),
            hint_area,
        );
    }

    /// Full-screen detail for the selected peer.
    ///
    /// The table truncates the fingerprint to 16 chars and clips the
    /// pubkey; both are needed in full to enroll the peer elsewhere, so
    /// the overlay shows them untruncated and copyable.
    pub(crate) fn render_detail(&mut self, f: &mut Frame<'_>, area: Rect) {
        self.browser.set_len(self.entries.len());
        let Some(peer) = self.selected_peer().cloned() else {
            return;
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .title("Peer detail — Esc back");
        let inner = block.inner(area);
        f.render_widget(block, area);

        let mut lines = vec![
            kv("name", peer.name.clone()),
            kv("fingerprint", peer.fp.clone()),
            kv("pubkey_b64", peer.pubkey_b64.clone()),
            kv("addr", peer.addr.clone().unwrap_or_else(|| "-".into())),
            Line::from(""),
        ];
        lines.push(Line::from(Span::styled(
            "pivots:  n alerts it raised   m its mesh-peer row",
            theme::hint(),
        )));
        f.render_widget(
            Paragraph::new(lines).wrap(ratatui::widgets::Wrap { trim: false }),
            inner,
        );
    }

    pub(crate) fn browser_mut(&mut self) -> &mut Browser {
        &mut self.browser
    }

    /// The peer under the cursor, if any.
    pub(crate) fn selected_peer(&self) -> Option<&Peer> {
        self.entries.get(self.browser.selected()?)
    }
}

fn short_fp(fp: &str) -> String {
    if fp.len() > 16 {
        format!("{}…", &fp[..16])
    } else {
        fp.to_string()
    }
}
