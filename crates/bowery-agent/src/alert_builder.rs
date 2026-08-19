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
//!
//! That prediction came true within the month: `rule_id` had to reach
//! every alert, and a required argument here is what made each site
//! state which detection it speaks for instead of inheriting a
//! neighbour's answer.

use bowery_crypto::Fingerprint;
use bowery_proto::{Alert, AlertConfirmation, Attribute};

use crate::inbox::current_unix_ms;

/// An [`Alert`] under construction.
#[derive(Debug)]
pub struct AlertBuilder {
    alert: Alert,
}

impl AlertBuilder {
    /// Start an alert.
    ///
    /// `rule_id`, `episode_id`, `suspicion` and `rationale` are required
    /// because no finding is meaningful without them. `rule_id`
    /// especially: an alert that cannot name its own detection cannot be
    /// counted against it, cannot be found in `bowery_alerts`, and
    /// cannot be pointed at by an operator saying it is benign.
    ///
    /// Built-in detections must pass their own module constant.
    /// Operator-configured rules carry their configured id instead,
    /// which is why this is not `&'static str` — and
    /// [`crate::inbox::AlertInbox::append`] debug-asserts the value is
    /// either a registered rule or an operator one, which checks what a
    /// type could not.
    #[must_use]
    pub fn new(
        originator_fp: Fingerprint,
        backend_label: &str,
        rule_id: impl Into<String>,
        episode_id: impl Into<String>,
        suspicion: f32,
        rationale: impl Into<String>,
    ) -> Self {
        let rule_id = rule_id.into();
        debug_assert!(
            bowery_analysis::attack::all_rule_ids().contains(&rule_id.as_str()),
            "`{rule_id}` is not a detection the agent knows. A built-in alert must name a \
             registered rule, or it appears on no coverage map and moves no counter. \
             Operator-configured rules use `for_operator_rule` instead.",
        );
        Self::raw(
            originator_fp,
            backend_label,
            rule_id,
            episode_id,
            suspicion,
            rationale,
        )
    }

    /// Start an alert for a rule an operator configured in `[monitor]`.
    ///
    /// Those ids are chosen in config — a filename, a `comm=` fragment,
    /// whatever the operator wrote — so they cannot be checked against a
    /// compiled-in registry the way [`Self::new`] checks a built-in.
    /// Separate constructor rather than a weaker check on one, so the
    /// built-in path keeps its guarantee.
    #[must_use]
    pub fn for_operator_rule(
        originator_fp: Fingerprint,
        backend_label: &str,
        rule_id: impl Into<String>,
        episode_id: impl Into<String>,
        suspicion: f32,
        rationale: impl Into<String>,
    ) -> Self {
        Self::raw(
            originator_fp,
            backend_label,
            rule_id,
            episode_id,
            suspicion,
            rationale,
        )
    }

    fn raw(
        originator_fp: Fingerprint,
        backend_label: &str,
        rule_id: impl Into<String>,
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
                rule_id: rule_id.into(),
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
        let a = AlertBuilder::new(fp(), "mock/echo", "cred.read_netrc", "ep-1", 0.9, "why").build();
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
        let a = AlertBuilder::new(fp(), "b", "cred.read_netrc", "ep", 0.5, "why").build();
        assert!(a.confirmation.is_none());
        let confirmed = AlertBuilder::new(fp(), "b", "cred.read_netrc", "ep", 0.5, "why")
            .confirmation(AlertConfirmation {
                peers_asked: 3,
                peers_unseen: 3,
                peers_seen: 0,
                peers_no_reply: 0,
                peers_refused: 0,
                peers_incomparable: 0,
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
        let a = AlertBuilder::new(fp(), "b", "cred.read_netrc", "ep", 0.5, "why").build();
        assert!(a.exe_sha256_hex.is_empty());
        let b = AlertBuilder::new(fp(), "b", "cred.read_netrc", "ep", 0.5, "why")
            .exe_sha256_hex("abc123")
            .build();
        assert_eq!(b.exe_sha256_hex, "abc123");
    }

    /// The id has to survive to the alert, or nothing downstream can
    /// attribute the finding.
    #[test]
    fn the_rule_is_carried_and_cannot_be_defaulted_away() {
        let a =
            AlertBuilder::new(fp(), "b", "lineage.service_spawned_shell", "ep", 0.9, "why").build();
        assert_eq!(a.rule_id, "lineage.service_spawned_shell");
    }

    #[test]
    fn subject_and_context_land_where_expected() {
        let a = AlertBuilder::new(fp(), "b", "cred.read_netrc", "ep", 0.5, "why")
            .subject("/usr/bin/curl")
            .context(vec![Attribute::new("pid", "42")])
            .build();
        assert_eq!(a.exe_path, "/usr/bin/curl");
        assert_eq!(a.context.len(), 1);
    }
}
