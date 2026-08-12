//! Cross-host corroboration: "can anyone else account for what I just
//! saw?" — the transport half.
//!
//! This module deliberately knows nothing about *what* is being
//! corroborated. It carries a `kind` string and an opaque list of
//! key/value attributes; the handler registered for that kind, up in
//! the agent, is the only code that interprets them. Everything
//! security-critical is here and is therefore written once:
//!
//! - envelope signing, recipient binding, replay and skew gating
//!   (inherited from [`crate::envelope`], same as `qa`),
//! - absolute deadlines on the wire, so a responder never answers a
//!   question the asker has already given up on,
//! - the checks that make an answer *usable*: it must echo the
//!   `query_id` and the `kind` it was asked about.
//!
//! A new kind of suspicion is a handler registration. It does not touch
//! this file, and it does not touch the wire format — which is the
//! point. Reimplementing "ask a peer and tally the replies" per
//! detection is how one of them ends up without a rate limit, without a
//! deadline, or counting silence as agreement.
//!
//! Wire pattern is one bidirectional stream, identical to [`crate::qa`]:
//!
//! ```text
//!   Asker                                        Responder
//!     |  open_bi { sealed query }      --->          |
//!     |  <-----  reply { sealed answer }             |
//! ```
//!
//! # What this module does not decide
//!
//! **Whether a query is allowed.** A generic "ask a peer about its
//! history" primitive is a generic enumeration primitive unless every
//! handler constrains what may be asked to facts the asker already
//! knows. That constraint is necessarily kind-specific, so it is the
//! handler's job; the agent's `CorroborationResponder` trait states it
//! as a contract rather than leaving it to each implementation to
//! remember.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bowery_crypto::Fingerprint;
use bowery_proto::{
    Attribute, Body, Corroboration, CorroborationAnswer, CorroborationQuery, WhisperPayload,
};
use rand::RngCore;
use thiserror::Error;

use crate::envelope::{self, FingerprintResolver, Sealer, Verifier};
use crate::transport::{self, BoweryConnection};

/// Default per-peer deadline for a corroboration round. Matches
/// [`crate::qa::DEFAULT_ASK_TIMEOUT`]: well above QUIC handshake + RTT,
/// short enough that a stalled peer doesn't hold a round open.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Error)]
pub enum AskError {
    #[error("asker timed out waiting for a corroboration answer after {0:?}")]
    Timeout(Duration),

    #[error("envelope crypto failed: {0}")]
    Envelope(#[from] envelope::Error),

    #[error("transport: {0}")]
    Transport(#[from] transport::Error),

    #[error("peer replied with a {0} body, expected a CorroborationAnswer")]
    UnexpectedBody(&'static str),

    #[error("missing payload body in peer response")]
    MissingBody,

    #[error("answer's query_id didn't match our query")]
    WrongQueryId,

    #[error("asked about kind `{asked}`, peer answered about `{got}`")]
    WrongKind { asked: String, got: String },
}

/// Why a responder rejected a query before ever consulting local data.
///
/// These are shape checks, not policy: policy is the handler's.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum QueryRejection {
    #[error("query_id is empty")]
    NoQueryId,

    #[error("kind is empty")]
    NoKind,

    #[error("query expired at {deadline_unix_ms} (now {now_unix_ms})")]
    Expired {
        deadline_unix_ms: u64,
        now_unix_ms: u64,
    },

    #[error("window is inverted: start {start} > end {end}")]
    InvertedWindow { start: u64, end: u64 },

    #[error("subject carries {got} attributes; the cap is {cap}")]
    TooManyAttributes { got: usize, cap: usize },
}

/// Ceiling on subject attributes a responder will look at. Generous for
/// any real detection (the connection kind uses two) and bounded so a
/// peer can't hand us an arbitrarily long list to walk per query.
pub const MAX_SUBJECT_ATTRIBUTES: usize = 32;

/// Fresh 128-bit query id, hex-encoded. Distinct per query even when
/// two are issued back to back.
#[must_use]
pub fn fresh_query_id() -> String {
    let mut raw = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut raw);
    hex::encode(raw)
}

/// Build a query with a fresh id and an absolute deadline derived from
/// `ttl`. Absolute deadlines go on the wire so the responder doesn't
/// need to know our ask-time — same convention as
/// [`crate::qa::build_question`].
#[must_use]
pub fn build_query(
    kind: &str,
    subject: Vec<Attribute>,
    window_start_unix_ms: u64,
    window_end_unix_ms: u64,
    ttl: Duration,
) -> CorroborationQuery {
    let ttl_ms = u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX);
    CorroborationQuery {
        query_id: fresh_query_id(),
        kind: kind.to_string(),
        deadline_unix_ms: now_unix_ms().saturating_add(ttl_ms),
        window_start_unix_ms,
        window_end_unix_ms,
        subject,
    }
}

/// Shape-check an inbound query. Call this before dispatching to a
/// handler, so every kind inherits the same deadline and bounds
/// checking rather than each remembering to do it.
///
/// # Errors
///
/// Returns the specific [`QueryRejection`] so the caller can log which
/// check failed; all of them mean "drop it".
pub fn check_query(q: &CorroborationQuery) -> Result<(), QueryRejection> {
    if q.query_id.is_empty() {
        return Err(QueryRejection::NoQueryId);
    }
    if q.kind.is_empty() {
        return Err(QueryRejection::NoKind);
    }
    if q.subject.len() > MAX_SUBJECT_ATTRIBUTES {
        return Err(QueryRejection::TooManyAttributes {
            got: q.subject.len(),
            cap: MAX_SUBJECT_ATTRIBUTES,
        });
    }
    if q.window_start_unix_ms > q.window_end_unix_ms {
        return Err(QueryRejection::InvertedWindow {
            start: q.window_start_unix_ms,
            end: q.window_end_unix_ms,
        });
    }
    let now = now_unix_ms();
    if now > q.deadline_unix_ms {
        return Err(QueryRejection::Expired {
            deadline_unix_ms: q.deadline_unix_ms,
            now_unix_ms: now,
        });
    }
    Ok(())
}

/// Build a refusal for `query`. Used by handlers that decline, and by
/// the dispatcher when no handler is registered for a kind.
///
/// A refusal is always *sent*. Staying silent instead would be read by
/// the asker as a timeout, which is indistinguishable from an agent
/// that is down — and "this peer is unreachable" and "this peer won't
/// answer that" should not look the same to an operator.
#[must_use]
pub fn refuse(query: &CorroborationQuery, reason: impl Into<String>) -> CorroborationAnswer {
    CorroborationAnswer {
        query_id: query.query_id.clone(),
        kind: query.kind.clone(),
        outcome: Corroboration::Refused as i32,
        evidence: Vec::new(),
        reason: reason.into(),
    }
}

/// Build an answer carrying `outcome` and `evidence` for `query`.
#[must_use]
pub fn answer(
    query: &CorroborationQuery,
    outcome: Corroboration,
    evidence: Vec<Attribute>,
) -> CorroborationAnswer {
    CorroborationAnswer {
        query_id: query.query_id.clone(),
        kind: query.kind.clone(),
        outcome: outcome as i32,
        evidence,
        reason: String::new(),
    }
}

/// Send `query` to `responder` over `conn` and await the verified
/// answer.
///
/// The caller has already dialled the peer and holds a [`Sealer`] (its
/// own identity) plus a [`Verifier`] that resolves the responder's key.
/// `responder` binds the envelope signature to that recipient (Phase-8
/// H1 anti-replay).
///
/// # Errors
///
/// Anything short of an answer that verifies, echoes our `query_id`,
/// and names the `kind` we asked about.
pub async fn ask<R: FingerprintResolver>(
    conn: &BoweryConnection,
    sealer: &Sealer,
    verifier: &Verifier<R>,
    responder: Fingerprint,
    query: CorroborationQuery,
    timeout: Duration,
) -> Result<CorroborationAnswer, AskError> {
    let expected_id = query.query_id.clone();
    let expected_kind = query.kind.clone();

    let outbound = sealer.seal_for(&responder, &WhisperPayload::corroboration_query(query));

    let exchange = async {
        let bytes = conn.request(&outbound).await?;
        let opened = verifier.open(&bytes)?;
        let answer = match opened.payload.body {
            Some(Body::CorroborationAnswer(a)) => a,
            Some(other) => return Err(AskError::UnexpectedBody(other.kind_name())),
            None => return Err(AskError::MissingBody),
        };
        // Both checks matter for the same reason: an answer that is not
        // provably about the question we asked must not be tallied. A
        // peer that replies to a `net.inbound_connect` query with a
        // `Denied` for some other kind would otherwise contribute a
        // denial toward an alert quorum.
        if answer.query_id != expected_id {
            return Err(AskError::WrongQueryId);
        }
        if answer.kind != expected_kind {
            return Err(AskError::WrongKind {
                asked: expected_kind.clone(),
                got: answer.kind.clone(),
            });
        }
        Ok(answer)
    };

    match tokio::time::timeout(timeout, exchange).await {
        Ok(result) => result,
        Err(_) => Err(AskError::Timeout(timeout)),
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query() -> CorroborationQuery {
        build_query(
            "test.kind",
            vec![Attribute::new("a", "1")],
            0,
            now_unix_ms(),
            Duration::from_secs(30),
        )
    }

    #[test]
    fn build_query_sets_an_absolute_future_deadline() {
        let q = query();
        let now = now_unix_ms();
        assert!(q.deadline_unix_ms > now);
        assert!(q.deadline_unix_ms <= now + 30_000);
        assert_eq!(q.kind, "test.kind");
    }

    #[test]
    fn fresh_query_ids_are_distinct() {
        assert_ne!(fresh_query_id(), fresh_query_id());
        assert_eq!(fresh_query_id().len(), 32); // 16 bytes, hex
    }

    #[test]
    fn check_query_accepts_a_well_formed_query() {
        assert!(check_query(&query()).is_ok());
    }

    #[test]
    fn check_query_rejects_an_expired_query() {
        let mut q = query();
        q.deadline_unix_ms = 1;
        assert!(matches!(
            check_query(&q),
            Err(QueryRejection::Expired { .. })
        ));
    }

    #[test]
    fn check_query_rejects_empty_identifiers() {
        let mut q = query();
        q.query_id = String::new();
        assert_eq!(check_query(&q), Err(QueryRejection::NoQueryId));

        let mut q = query();
        q.kind = String::new();
        assert_eq!(check_query(&q), Err(QueryRejection::NoKind));
    }

    #[test]
    fn check_query_rejects_an_inverted_window() {
        let mut q = query();
        q.window_start_unix_ms = 100;
        q.window_end_unix_ms = 50;
        // Left unchecked this reaches SQLite as `BETWEEN 100 AND 50`,
        // which matches nothing — a silently empty search that the
        // asker would read as a denial.
        assert!(matches!(
            check_query(&q),
            Err(QueryRejection::InvertedWindow { .. })
        ));
    }

    #[test]
    fn check_query_rejects_an_oversized_subject() {
        let mut q = query();
        q.subject = (0..=MAX_SUBJECT_ATTRIBUTES)
            .map(|i| Attribute::new(format!("k{i}"), "v"))
            .collect();
        assert!(matches!(
            check_query(&q),
            Err(QueryRejection::TooManyAttributes { .. })
        ));
    }

    #[test]
    fn refuse_and_answer_echo_the_query_identity() {
        let q = query();
        let r = refuse(&q, "not allowed");
        assert_eq!(r.query_id, q.query_id);
        assert_eq!(r.kind, q.kind);
        assert_eq!(r.corroboration(), Corroboration::Refused);
        assert_eq!(r.reason, "not allowed");

        let a = answer(
            &q,
            Corroboration::Corroborated,
            vec![Attribute::new("pid", "42")],
        );
        assert_eq!(a.query_id, q.query_id);
        assert_eq!(a.corroboration(), Corroboration::Corroborated);
        assert_eq!(bowery_proto::attribute(&a.evidence, "pid"), Some("42"));
    }

    #[test]
    fn an_unrecognised_outcome_reads_as_unspecified_not_as_a_denial() {
        // The failure this guards is quiet and one-directional: a future
        // peer sending an outcome this build has never heard of must
        // degrade to "told me nothing", never to the answer that raises
        // an alert.
        let a = CorroborationAnswer {
            query_id: "x".into(),
            kind: "k".into(),
            outcome: 9999,
            evidence: Vec::new(),
            reason: String::new(),
        };
        assert_eq!(a.corroboration(), Corroboration::Unspecified);
    }
}
