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
