//! Peers pane — read/write `~/.bowery/peers.toml` via the
//! `bowery_cli::peers` library API.
//!
//! C-3 ships a read-only renderer plus `:peers reload` reload via
//! the palette. Add/remove are wired in C-4 (they need richer input
//! editing).

use bowery_cli::peers::{Manifest, Peer};
use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row as TableRow, Table};

use crate::theme;

#[derive(Debug, Default)]
pub(crate) struct PeersPane {
    pub(crate) entries: Vec<Peer>,
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

    pub(crate) fn render(&self, f: &mut Frame<'_>, area: Rect) {
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

        let rows: Vec<TableRow> = self
            .entries
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
        f.render_widget(Table::new(rows, widths).header(header), inner);
    }
}

fn short_fp(fp: &str) -> String {
    if fp.len() > 16 {
        format!("{}…", &fp[..16])
    } else {
        fp.to_string()
    }
}
