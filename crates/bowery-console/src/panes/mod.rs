//! Pane registry. Each pane owns its own state and rendering; the
//! top-level `App` selects which one is foregrounded and dispatches
//! input to it.

pub(crate) mod query;
pub(crate) mod stub;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum PaneId {
    Query,
    Alerts,
    Map,
    Audit,
    Peers,
    Doctor,
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
        }
    }

    pub(crate) const ALL: [PaneId; 6] = [
        Self::Query,
        Self::Alerts,
        Self::Map,
        Self::Audit,
        Self::Peers,
        Self::Doctor,
    ];

    /// Resolve `[1]`-style hotkeys back to a `PaneId`.
    pub(crate) fn from_hotkey(c: char) -> Option<Self> {
        Self::ALL.iter().copied().find(|p| p.hotkey() == c)
    }
}
