//! Building an [`Alert`] without restating the same six fields.
//!
//! Thirteen construction sites across seven modules, each spelling out
//! `originator_fp: fp.as_bytes().to_vec()`, `suggested_actions:
//! Vec::new()`, `ts_unix_ms: current_unix_ms()`, `backend: ….clone()`
//! and `confirmation: None` — five fields that are the same everywhere
//! and one (`exe_sha256_hex`) that is empty at most of them.
//!
//! That is not merely repetitive. Adding a field to [`Alert`] means
//! editing thirteen places, and a detection author copying a nearby
//! site inherits whatever that site happened to set — which is how
//! `context` came to be populated at some sites and left empty at
//! others long after it existed.
//!
//! The builder makes the shared fields automatic and the per-finding
//! ones explicit, so what a site actually decides is what it writes
//! down.

use bowery_crypto::Fingerprint;
use bowery_proto::{Alert, AlertConfirmation, Attribute};

use crate::inbox::current_unix_ms;

/// An [`Alert`] under construction.
#[derive(Debug)]
pub struct AlertBuilder {
    alert: Alert,
}

impl AlertBuilder {
    /// Start an alert. `episode_id`, `suspicion` and `rationale` are
    /// required because no finding is meaningful without them.
    #[must_use]
    pub fn new(
        originator_fp: Fingerprint,
        backend_label: &str,
        episode_id: impl Into<String>,
        suspicion: f32,
        rationale: impl Into<String>,
    ) -> Self {
        Self {
            alert: Alert {
                originator_fp: originator_fp.as_bytes().to_vec(),
                episode_id: episode_id.into(),
                exe_sha256_hex: String::new(),
                exe_path: String::new(),
                suspicion,
                rationale: rationale.into(),
                suggested_actions: Vec::new(),
                ts_unix_ms: current_unix_ms(),
                backend: backend_label.to_string(),
                confirmation: None,
                context: Vec::new(),
            },
        }
    }

    /// The subject: a binary path, a file path, an endpoint.
    #[must_use]
    pub fn subject(mut self, path: impl Into<String>) -> Self {
        self.alert.exe_path = path.into();
        self
    }

    /// SHA-256 of the binary this is about, lowercase hex.
    ///
    /// Left empty when there is none. That emptiness is load-bearing:
    /// `bowery notify` screens against `VirusTotal` by this field, and a
    /// file alert that carried no hash silently bypassed the filter for
    /// months.
    #[must_use]
    pub fn exe_sha256_hex(mut self, hex: impl Into<String>) -> Self {
        self.alert.exe_sha256_hex = hex.into();
        self
    }

    /// Triage context: command line, ancestry, open handles.
    #[must_use]
    pub fn context(mut self, context: Vec<Attribute>) -> Self {
        self.alert.context = context;
        self
    }

    /// The whisper round's verdict, when one ran.
    ///
    /// Absent means *no round ran*, which is a different fact from a
    /// round that ran and did not confirm — the SQL surface renders it
    /// as NULL rather than 0 for exactly that reason.
    #[must_use]
    pub fn confirmation(mut self, confirmation: AlertConfirmation) -> Self {
        self.alert.confirmation = Some(confirmation);
        self
    }

    /// Actions the analyzer proposed.
    #[must_use]
    pub fn suggested_actions(mut self, actions: Vec<String>) -> Self {
        self.alert.suggested_actions = actions;
        self
    }

    #[must_use]
    pub fn build(self) -> Alert {
        self.alert
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp() -> Fingerprint {
        Fingerprint::from_bytes([7u8; 32])
    }

    #[test]
    fn the_shared_fields_are_filled_without_being_written() {
        let a = AlertBuilder::new(fp(), "mock/echo", "ep-1", 0.9, "why").build();
        assert_eq!(a.originator_fp, vec![7u8; 32]);
        assert_eq!(a.backend, "mock/echo");
        assert!(a.ts_unix_ms > 0);
        assert!(a.suggested_actions.is_empty());
        assert!(a.confirmation.is_none());
    }

    /// Absent confirmation means no round ran, which the SQL surface
    /// renders as NULL. A builder that defaulted it to something would
    /// erase the distinction.
    #[test]
    fn confirmation_is_absent_until_a_round_says_otherwise() {
        let a = AlertBuilder::new(fp(), "b", "ep", 0.5, "why").build();
        assert!(a.confirmation.is_none());
        let confirmed = AlertBuilder::new(fp(), "b", "ep", 0.5, "why")
            .confirmation(AlertConfirmation {
                peers_asked: 3,
                peers_unseen: 3,
                peers_seen: 0,
                peers_no_reply: 0,
                peers_refused: 0,
                quorum: 2,
                confirmed: true,
            })
            .build();
        assert!(confirmed.confirmation.is_some_and(|c| c.confirmed));
    }

    /// An empty hash is what makes `VirusTotal` screening skip an alert,
    /// so it must stay empty unless a site sets it deliberately.
    #[test]
    fn the_hash_is_empty_unless_given() {
        let a = AlertBuilder::new(fp(), "b", "ep", 0.5, "why").build();
        assert!(a.exe_sha256_hex.is_empty());
        let b = AlertBuilder::new(fp(), "b", "ep", 0.5, "why")
            .exe_sha256_hex("abc123")
            .build();
        assert_eq!(b.exe_sha256_hex, "abc123");
    }

    #[test]
    fn subject_and_context_land_where_expected() {
        let a = AlertBuilder::new(fp(), "b", "ep", 0.5, "why")
            .subject("/usr/bin/curl")
            .context(vec![Attribute::new("pid", "42")])
            .build();
        assert_eq!(a.exe_path, "/usr/bin/curl");
        assert_eq!(a.context.len(), 1);
    }
}
