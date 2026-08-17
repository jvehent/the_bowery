//! The `file.access` kind: *"does this happen on your host too?"*
//!
//! The question every other kind so far could not ask. `net.inbound_connect`
//! asks a counterparty to incriminate or exonerate itself about one
//! event; this asks the neighbourhood a question about *shape*: some
//! binary read a credential file here — is that what this fleet looks
//! like, or is this host doing something the others are not?
//!
//! # Why the polarity is the opposite of prevalence
//!
//! For binaries, a peer that has seen the artifact argues it is a normal
//! fleet artifact, so confirmation counts peers that have **never** seen
//! it. The same logic lands here: peers that see the same binary reading
//! the same credential path are evidence of a management agent, a
//! backup job, a monitoring tool — something installed everywhere on
//! purpose. A read that **no** peer recognises is the one worth reading.
//!
//! # What this is allowed to ask about, and why that is bounded
//!
//! Only `(exe, path)` pairs where the path already matched a built-in
//! watch rule. That bound is the privacy property. Without it, the query
//! would be a filesystem-enumeration oracle: ask a peer about any path
//! you like and learn from the answer whether it exists and who touched
//! it. Restricted to the watch set, a peer only ever discloses the same
//! class of fact the asker already observed for itself, about a path
//! both agents were built to watch.
//!
//! It is deliberately **not** anchored on `comm`. The subject is the
//! resolved exe path, for the reason the whole file-watch layer refuses
//! to key on `comm`: it is 16 bytes any process sets with `prctl`, so
//! two hosts "agreeing" about a process called `sshd` would agree about
//! nothing at all.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bowery_crypto::Fingerprint;
use bowery_proto::{Attribute, Corroboration, CorroborationAnswer, CorroborationQuery, attribute};
use bowery_whisper::corroborate;
use tracing::debug;

use super::{Audience, Claim, Rule};

/// Handler selector, on the wire and in the registry.
pub const KIND: &str = "file.access";

/// Subject attribute: the resolved exe path of the process that touched
/// the file.
pub const ATTR_EXE: &str = "exe";
/// Subject attribute: the file that was touched.
pub const ATTR_PATH: &str = "path";
/// Subject attribute: `read` or `write`. Reading `/etc/shadow` and
/// writing it are different events, and a peer must not answer about one
/// having seen the other.
pub const ATTR_ACCESS: &str = "access";

/// Longest history a peer may be asked to search.
///
/// Wider than the connection kind's ten minutes because the question is
/// about habit rather than about one event: a management agent that
/// reads `/etc/shadow` hourly should still corroborate a read seen
/// twenty minutes ago. Bounded because the window is attacker-chosen and
/// answering must stay cheap.
pub const MAX_WINDOW_MS: u64 = 6 * 60 * 60 * 1000;

/// How many peers to ask.
///
/// Small: this is a question about what is ordinary, and if three peers
/// cannot answer it a fourth will not help.
const FANOUT: usize = 3;

// ---------------------------------------------------------------------------
// Asker side
// ---------------------------------------------------------------------------

/// Ask the neighbourhood whether a file finding is fleet-normal.
///
/// `episode_id` is the alert already raised locally. The finding is
/// **never** withheld pending an answer: a detection that waits for the
/// mesh is one that says nothing on a single-node install, on a
/// partitioned network, or when every peer is down — which are exactly
/// the moments it matters. The round can only ever *downgrade* what was
/// already reported.
///
/// `None` when the exe could not be resolved. Two hosts cannot agree
/// about a binary neither can name, and asking anyway would collect
/// agreement about the empty string.
#[must_use]
pub fn claim_for(
    exe: Option<&str>,
    path: &str,
    is_read: bool,
    episode_id: String,
    ts: std::time::SystemTime,
    half_window: Duration,
    explained_suspicion: f32,
) -> Option<Claim> {
    let exe = exe?;
    if exe.is_empty() || !path.starts_with('/') {
        debug!(
            exe,
            path, "file.access claim needs an absolute path and a named exe"
        );
        return None;
    }
    let access = if is_read { "read" } else { "write" };
    let (window_start_unix_ms, window_end_unix_ms) = super::window_around(ts, half_window);
    Some(Claim {
        kind: KIND,
        subject: vec![
            Attribute::new(ATTR_EXE, exe.to_string()),
            Attribute::new(ATTR_PATH, path.to_string()),
            Attribute::new(ATTR_ACCESS, access.to_string()),
        ],
        window_start_unix_ms,
        window_end_unix_ms,
        audience: Audience::Neighbourhood { limit: FANOUT },
        // deny_quorum 0: this round must never raise an alert of its
        // own. The local finding was already reported the moment it was
        // observed, and a second alert saying "and nobody else does
        // this" would double every credential finding on the fleet
        // rather than clarify it. The round exists only to take a
        // finding *back*.
        rule: Rule {
            deny_quorum: 0,
            corroboration_clears: true,
        },
        // One round per shape per window, not one per open. sshd reads
        // the same key on every connection, and each read would
        // otherwise put the same question to the same three peers.
        dedup_key: format!("{access}:{exe}:{path}"),
        summary: format!("{exe} {access} {path}"),
        suspicion: 0.0,
        supersedes: Some(episode_id),
        explained_suspicion,
    })
}

// ---------------------------------------------------------------------------
// Responder side
// ---------------------------------------------------------------------------

/// Answers `file.access` from this host's own file-open history.
#[derive(Debug)]
pub struct FileAccessResponder {
    log: Arc<bowery_eventlog::EventLog>,
}

impl FileAccessResponder {
    #[must_use]
    pub fn new(log: Arc<bowery_eventlog::EventLog>) -> Self {
        Self { log }
    }
}

#[async_trait]
impl super::CorroborationResponder for FileAccessResponder {
    fn kind(&self) -> &'static str {
        KIND
    }

    async fn respond(
        &self,
        _asker: Fingerprint,
        query: &CorroborationQuery,
    ) -> CorroborationAnswer {
        let Some(exe) = attribute(&query.subject, ATTR_EXE) else {
            return corroborate::refuse(query, "missing exe");
        };
        let Some(path) = attribute(&query.subject, ATTR_PATH) else {
            return corroborate::refuse(query, "missing path");
        };
        let Some(access) = attribute(&query.subject, ATTR_ACCESS) else {
            return corroborate::refuse(query, "missing access");
        };
        let is_read = match access {
            "read" => true,
            "write" => false,
            _ => return corroborate::refuse(query, "access must be read or write"),
        };

        // The bound that keeps this from being an enumeration oracle.
        // Only paths this agent's own watch set covers may be asked
        // about — the same class of fact the asker observed for itself,
        // about a path both agents were built to watch. Anything else
        // and a peer could walk the filesystem one question at a time.
        let covered = if is_read {
            bowery_analysis::file_watch::classify_read(path).is_some()
        } else {
            bowery_analysis::file_watch::classify(path).is_some()
        };
        if !covered {
            debug!(path, "refusing file.access: not a watched path");
            return corroborate::refuse(query, "path is not in the built-in watch set");
        }

        let end = query.window_end_unix_ms;
        let start = query
            .window_start_unix_ms
            .max(end.saturating_sub(MAX_WINDOW_MS));

        let log = self.log.clone();
        let exe_owned = exe.to_string();
        let path_owned = path.to_string();
        let found = tokio::task::spawn_blocking(move || {
            // Coverage before conclusion, twice over.
            //
            // The window is the obvious half: a freshly-installed agent,
            // or one whose retention has trimmed the period asked about,
            // must refuse rather than report absence.
            //
            // Attribution is the half that was missing, and it made this
            // whole kind unable to answer the question it exists for. A
            // host attributes an access to a binary only when it saw
            // that binary exec; every long-running daemon — sshd, cron,
            // systemd — started before the agent did, and those are
            // precisely what read credential files. Reporting "I do not
            // see that" in such a case is a false denial, and on a live
            // fleet it was every single one: 24 rounds, zero
            // corroborations.
            if !log.covers_since(start).unwrap_or(false) {
                return None;
            }
            log.file_access_evidence(&exe_owned, &path_owned, is_read, start, end)
                .ok()
        })
        .await;

        match found {
            Ok(Some(bowery_eventlog::AccessEvidence::Seen)) => {
                corroborate::answer(query, Corroboration::Corroborated, Vec::new())
            }
            Ok(Some(bowery_eventlog::AccessEvidence::NotSeen)) => {
                corroborate::answer(query, Corroboration::Denied, Vec::new())
            }
            Ok(Some(bowery_eventlog::AccessEvidence::CannotAttribute)) => corroborate::refuse(
                query,
                "this host has attributed no file access to a binary in that window, so \
                 its silence is not evidence",
            ),
            Ok(None) => corroborate::refuse(
                query,
                "history does not cover the requested window on this host",
            ),
            Err(e) => {
                debug!(error = %e, "file.access lookup task failed");
                corroborate::refuse(query, "lookup failed")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    fn claim() -> Option<Claim> {
        claim_for(
            Some("/usr/sbin/sshd"),
            "/etc/shadow",
            true,
            "file-cred.read_shadow-1".into(),
            SystemTime::now(),
            Duration::from_mins(30),
            0.1,
        )
    }

    #[test]
    fn a_claim_names_the_exe_the_path_and_the_direction() {
        let c = claim().expect("claim");
        assert_eq!(c.kind, KIND);
        assert_eq!(attribute(&c.subject, ATTR_EXE), Some("/usr/sbin/sshd"));
        assert_eq!(attribute(&c.subject, ATTR_PATH), Some("/etc/shadow"));
        assert_eq!(attribute(&c.subject, ATTR_ACCESS), Some("read"));
    }

    /// The round exists to take a finding back, never to raise one.
    ///
    /// A second alert saying "and nobody else does this" would double
    /// every credential finding on the fleet rather than clarify it.
    #[test]
    fn the_round_can_never_raise_an_alert_of_its_own() {
        let c = claim().expect("claim");
        assert_eq!(c.rule.deny_quorum, 0);
        let tally = super::super::Tally {
            asked: 3,
            corroborated: 0,
            denied: 3,
            refused: 0,
            no_reply: 0,
        };
        assert!(
            !c.rule.confirms(&tally),
            "three denials must still raise nothing"
        );
    }

    #[test]
    fn it_supersedes_the_alert_that_was_already_raised() {
        let c = claim().expect("claim");
        assert_eq!(c.supersedes.as_deref(), Some("file-cred.read_shadow-1"));
        assert!(c.explained_suspicion < 0.5);
    }

    /// Two hosts cannot agree about a binary neither can name.
    #[test]
    fn an_unresolvable_exe_asks_nothing() {
        assert!(
            claim_for(
                None,
                "/etc/shadow",
                true,
                "ep".into(),
                SystemTime::now(),
                Duration::from_mins(30),
                0.1
            )
            .is_none()
        );
        assert!(
            claim_for(
                Some(""),
                "/etc/shadow",
                true,
                "ep".into(),
                SystemTime::now(),
                Duration::from_mins(30),
                0.1
            )
            .is_none()
        );
    }

    /// sshd reads the same key on every connection; without a dedup key
    /// scoped to the shape, each read would put the same question to the
    /// same three peers.
    #[test]
    fn repeats_of_the_same_shape_collapse_to_one_round() {
        let a = claim().expect("claim");
        let b = claim().expect("claim");
        assert_eq!(a.dedup_key, b.dedup_key);
        let other = claim_for(
            Some("/usr/sbin/sshd"),
            "/etc/shadow",
            false,
            "ep".into(),
            SystemTime::now(),
            Duration::from_mins(30),
            0.1,
        )
        .expect("claim");
        assert_ne!(
            a.dedup_key, other.dedup_key,
            "a read and a write are different questions"
        );
    }
}
