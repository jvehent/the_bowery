//! Phase-5 whisper Q&A: end-to-end ask / answer over [`BoweryConnection`].
//!
//! Wire pattern (one bidirectional stream — pool slice 3 of the
//! Phase-10 connection-reuse work):
//! ```text
//!   Asker                                       Responder
//!     |  open_bi { sealed_question }    --->        |
//!     |  <-----  reply { sealed_answer }            |
//! ```
//!
//! Bidi (instead of two uni streams) means both halves of the
//! exchange ride a single Quinn stream, so the asker doesn't need a
//! separate `accept_uni` reader to receive the response — and a
//! pooled connection's inbound handler (which *also* runs
//! `accept_uni` for peer-initiated whispers) doesn't compete with
//! the asker for the reply.
//!
//! - Both sides reuse [`Sealer`] / [`Verifier`] for envelope crypto, so
//!   Q&A inherits envelope signing, replay protection, clock-skew
//!   gating, and the TOFU resolver from Phase 1.
//! - The connection is short-lived: one question, one answer, then
//!   close. We're explicit about this in the asker so the underlying
//!   QUIC connection has a chance to flush before the caller drops it.
//! - The responder's `seen_count` lookup is pluggable. The agent wires
//!   it to the baseline DB; tests use a `HashMap`-backed fake.
//!
//! What this module does *not* do:
//! - Bloom-advert distribution: that lives in the mesh KV layer
//!   (Phase 5d/e). Q&A is for follow-up confirmations on a tier-1
//!   fingerprint that already showed up in someone's advert.
//! - Tier-2 escalation: a follow-up phase will add a "send me the full
//!   sha256 if you really saw it" round, signed under a fresh
//!   transcript so the asker can prove they observed it independently.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bowery_crypto::Fingerprint;
use bowery_proto::{Answer, Body, Question, WhisperPayload};
use rand::RngCore;
use thiserror::Error;
use tracing::debug;

use crate::envelope::{self, FingerprintResolver, Sealer, Verifier};
use crate::fingerprint::{TIER1_LEN, Tier1Fingerprint};
use crate::transport::{self, BoweryConnection};

/// Episode-id width on the wire. UUID-shaped (16 bytes) but we don't
/// pin the v4 spec — any 128 bits of entropy works.
pub const EPISODE_ID_LEN: usize = 16;

/// Default per-question deadline. Five seconds is well above QUIC
/// handshake + RTT for any realistic neighborhood and short enough
/// that a stalled peer doesn't block the asker indefinitely.
pub const DEFAULT_ASK_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Error)]
pub enum AskError {
    #[error("asker timed out waiting for answer after {0:?}")]
    Timeout(Duration),

    #[error("envelope crypto failed: {0}")]
    Envelope(#[from] envelope::Error),

    #[error("transport: {0}")]
    Transport(#[from] transport::Error),

    #[error("peer replied with a {0} body, expected an Answer")]
    UnexpectedBody(&'static str),

    #[error("answer's tier1_fp didn't match our question (got {got:?})")]
    WrongFingerprint { got: Vec<u8> },

    #[error("answer's episode_id didn't match our question")]
    WrongEpisodeId,

    #[error("missing payload body in peer response")]
    MissingBody,
}

#[derive(Debug, Error)]
pub enum AnswerError {
    #[error("envelope crypto failed: {0}")]
    Envelope(#[from] envelope::Error),

    #[error("transport: {0}")]
    Transport(#[from] transport::Error),

    #[error("peer's question is malformed: {0}")]
    BadQuestion(String),

    #[error("question body was {0}, expected a Question")]
    UnexpectedBody(&'static str),

    #[error("missing payload body in peer question")]
    MissingBody,
}

/// Generate a fresh 128-bit episode id from a CSPRNG. Distinct
/// per-question even when two questions are issued back-to-back.
pub fn fresh_episode_id() -> [u8; EPISODE_ID_LEN] {
    let mut id = [0u8; EPISODE_ID_LEN];
    rand::thread_rng().fill_bytes(&mut id);
    id
}

/// Build a [`Question`] payload with a fresh episode id and a sensible
/// TTL. Note callers can mutate the returned `Question` before sealing
/// (e.g. set a non-empty note).
pub fn build_question(fp: Tier1Fingerprint, ttl: Duration, note: impl Into<String>) -> Question {
    let ttl_ms = u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX);
    Question {
        episode_id: fresh_episode_id().to_vec(),
        tier1_fp: fp.as_bytes().to_vec(),
        ttl_ms: ttl_deadline_ms(ttl_ms),
        note: note.into(),
    }
}

/// Convert a relative TTL (ms) into an absolute deadline (ms since
/// unix epoch) using the local wall clock. We send absolute deadlines
/// on the wire so the responder doesn't need to know our ask-time.
fn ttl_deadline_ms(rel_ms: u64) -> u64 {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0);
    now_ms.saturating_add(rel_ms)
}

// ---------------------------------------------------------------------------
// Asker
// ---------------------------------------------------------------------------

/// Send a question on `conn` to `responder`, await the answer, return
/// it verified.
///
/// The caller is responsible for having already dialed the peer and
/// having a [`Sealer`] (their own identity) plus a [`Verifier`] that
/// can resolve the *responder's* verifying key — typically the same
/// `KnownNeighbors` used to pin the connection's TLS verifier.
/// `responder` is the responder's fingerprint, used to bind the
/// envelope signature to that recipient (Phase-8 H1 anti-replay).
pub async fn ask<R: FingerprintResolver>(
    conn: &BoweryConnection,
    sealer: &Sealer,
    verifier: &Verifier<R>,
    responder: Fingerprint,
    question: Question,
    timeout: Duration,
) -> Result<Answer, AskError> {
    let expected_episode = question.episode_id.clone();
    let expected_fp = question.tier1_fp.clone();

    let outbound = sealer.seal_for(&responder, &WhisperPayload::question(question));

    let exchange = async {
        let answer_bytes = conn.request(&outbound).await?;
        let opened = verifier.open(&answer_bytes)?;
        let answer = match opened.payload.body {
            Some(Body::Answer(a)) => a,
            Some(other) => return Err(AskError::UnexpectedBody(body_kind(&other))),
            None => return Err(AskError::MissingBody),
        };
        if answer.episode_id != expected_episode {
            return Err(AskError::WrongEpisodeId);
        }
        if answer.tier1_fp != expected_fp {
            return Err(AskError::WrongFingerprint {
                got: answer.tier1_fp,
            });
        }
        Ok(answer)
    };

    match tokio::time::timeout(timeout, exchange).await {
        Ok(result) => result,
        Err(_) => Err(AskError::Timeout(timeout)),
    }
}

// ---------------------------------------------------------------------------
// Responder
// ---------------------------------------------------------------------------

/// Local observation summary the responder consults before replying.
///
/// The agent looks this up in the baseline DB by tier-1 fingerprint;
/// `seen_count == 0` means "I have never observed this." Tests provide
/// fakes via a closure passed to [`answer_one`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LocalSighting {
    pub seen_count: u64,
    pub first_seen_unix_ms: u64,
    pub last_seen_unix_ms: u64,
}

/// Read one [`Question`] from `conn`, run `lookup` to find the local
/// sighting, and send the corresponding [`Answer`] back. Returns the
/// question that was answered (handy for tests + tracing).
///
/// `note` is a short string the responder attaches to its answer
/// (e.g. its own role tag); pass `""` to omit.
pub async fn answer_one<R, F>(
    conn: &BoweryConnection,
    sealer: &Sealer,
    verifier: &Verifier<R>,
    lookup: F,
    note: &str,
) -> Result<Question, AnswerError>
where
    R: FingerprintResolver,
    F: FnOnce(Tier1Fingerprint) -> LocalSighting,
{
    let (bytes, reply) = conn.accept_request().await?;
    let opened = verifier.open(&bytes)?;
    // Asker's fingerprint, recovered from the verified envelope. Used
    // as the recipient when sealing the Answer back to them
    // (Phase-8 H1).
    let asker = opened.sender;
    let question = match opened.payload.body {
        Some(Body::Question(q)) => q,
        Some(other) => return Err(AnswerError::UnexpectedBody(body_kind(&other))),
        None => return Err(AnswerError::MissingBody),
    };

    if question.tier1_fp.len() != TIER1_LEN {
        return Err(AnswerError::BadQuestion(format!(
            "tier1_fp is {} bytes; expected {TIER1_LEN}",
            question.tier1_fp.len()
        )));
    }
    if question.episode_id.len() != EPISODE_ID_LEN {
        return Err(AnswerError::BadQuestion(format!(
            "episode_id is {} bytes; expected {EPISODE_ID_LEN}",
            question.episode_id.len()
        )));
    }

    // Drop expired questions silently — the asker will treat our
    // non-response as a timeout. We don't want to send a vacuous
    // "seen_count: 0" response to an expired question, since the asker
    // can no longer correlate it with the originating verdict.
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(u64::MAX);
    if now_ms > question.ttl_ms {
        debug!(
            now_ms,
            ttl_ms = question.ttl_ms,
            "dropping expired whisper question"
        );
        return Ok(question);
    }

    let mut fp_bytes = [0u8; TIER1_LEN];
    fp_bytes.copy_from_slice(&question.tier1_fp);
    let fp = Tier1Fingerprint::from_bytes(fp_bytes);

    let sighting = lookup(fp);
    let answer = Answer {
        episode_id: question.episode_id.clone(),
        tier1_fp: question.tier1_fp.clone(),
        seen_count: sighting.seen_count,
        first_seen_unix_ms: sighting.first_seen_unix_ms,
        last_seen_unix_ms: sighting.last_seen_unix_ms,
        note: note.to_string(),
    };
    let outbound = sealer.seal_for(&asker, &WhisperPayload::answer(answer));
    reply.send(&outbound).await?;
    Ok(question)
}

fn body_kind(body: &Body) -> &'static str {
    match body {
        Body::Question(_) => "Question",
        Body::Answer(_) => "Answer",
        Body::Alert(_) => "Alert",
        Body::OperatorCommand(_) => "OperatorCommand",
        Body::OperatorResult(_) => "OperatorResult",
        Body::Heartbeat(_) => "Heartbeat",
        Body::NeighborOp(_) => "NeighborOp",
        Body::Subscribe(_) => "Subscribe",
        Body::Alerts(_) => "Alerts",
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::StaticResolver;
    use crate::fingerprint::Tier1Fingerprint;
    use crate::tls::PinnedCertVerifier;
    use crate::transport::BoweryEndpoint;
    use bowery_crypto::Identity;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    fn loopback() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    /// Build a connected pair: alpha dials beta. Returns
    /// `(alpha_endpoint, alpha_conn, beta_endpoint, beta_conn,
    ///  alpha_sealer, beta_sealer, alpha_verifier, beta_verifier)`.
    #[allow(clippy::similar_names, clippy::type_complexity)]
    async fn paired() -> (
        BoweryEndpoint,
        BoweryConnection,
        BoweryEndpoint,
        BoweryConnection,
        Sealer,
        Sealer,
        Verifier<StaticResolver>,
        Verifier<StaticResolver>,
        Fingerprint, // beta's fingerprint — recipient for ask() in tests
    ) {
        let id_alpha = Arc::new(Identity::generate());
        let id_beta = Arc::new(Identity::generate());

        let mut resolver_alpha = StaticResolver::new();
        resolver_alpha.insert(id_beta.verifying_key());
        let mut resolver_beta = StaticResolver::new();
        resolver_beta.insert(id_alpha.verifying_key());

        let dial_verifier = Arc::new(PinnedCertVerifier::expecting(
            resolver_alpha.clone(),
            id_beta.fingerprint(),
        ));
        let accept_verifier_alpha = Arc::new(PinnedCertVerifier::new(resolver_alpha.clone()));
        let accept_verifier_beta = Arc::new(PinnedCertVerifier::new(resolver_beta.clone()));

        let endpoint_beta =
            BoweryEndpoint::bind(id_beta.clone(), accept_verifier_beta, loopback()).unwrap();
        let endpoint_alpha =
            BoweryEndpoint::bind(id_alpha.clone(), accept_verifier_alpha, loopback()).unwrap();

        let beta_addr = endpoint_beta.local_addr().unwrap();

        let endpoint_beta_clone = endpoint_beta.clone();
        let beta_accept = tokio::spawn(async move {
            endpoint_beta_clone
                .accept()
                .await
                .expect("incoming")
                .expect("connection ok")
        });

        let alpha_conn = endpoint_alpha
            .dial(dial_verifier, beta_addr)
            .await
            .expect("dial");
        let beta_conn = beta_accept.await.unwrap();

        let alpha_fp = id_alpha.fingerprint();
        let beta_fp = id_beta.fingerprint();
        let alpha_sealer = Sealer::new(id_alpha.clone());
        let beta_sealer = Sealer::new(id_beta.clone());
        let alpha_verifier = Verifier::new(resolver_alpha, alpha_fp);
        let beta_verifier = Verifier::new(resolver_beta, beta_fp);

        (
            endpoint_alpha,
            alpha_conn,
            endpoint_beta,
            beta_conn,
            alpha_sealer,
            beta_sealer,
            alpha_verifier,
            beta_verifier,
            beta_fp,
        )
    }

    #[tokio::test]
    async fn ask_answer_round_trip_returns_seen_counts() {
        let (
            ep_alpha,
            alpha_conn,
            ep_beta,
            beta_conn,
            alpha_sealer,
            beta_sealer,
            alpha_verifier,
            beta_verifier,
            beta_fp,
        ) = paired().await;

        let fp = Tier1Fingerprint::derive(b"sneaky");

        let beta_task = tokio::spawn(async move {
            answer_one(
                &beta_conn,
                &beta_sealer,
                &beta_verifier,
                |asked| {
                    assert_eq!(asked, fp);
                    LocalSighting {
                        seen_count: 7,
                        first_seen_unix_ms: 1_700_000_000_000,
                        last_seen_unix_ms: 1_700_000_300_000,
                    }
                },
                "beta-host",
            )
            .await
            .expect("answer_one")
        });

        let question = build_question(fp, Duration::from_mins(1), "test");
        let answer = ask(
            &alpha_conn,
            &alpha_sealer,
            &alpha_verifier,
            beta_fp,
            question,
            Duration::from_secs(5),
        )
        .await
        .expect("ask");

        let _ = beta_task.await;
        assert_eq!(answer.seen_count, 7);
        assert_eq!(answer.first_seen_unix_ms, 1_700_000_000_000);
        assert_eq!(answer.last_seen_unix_ms, 1_700_000_300_000);
        assert_eq!(answer.note, "beta-host");

        ep_alpha.close().await;
        ep_beta.close().await;
    }

    #[tokio::test]
    async fn ask_returns_zero_when_responder_has_no_sighting() {
        let (
            ep_alpha,
            alpha_conn,
            ep_beta,
            beta_conn,
            alpha_sealer,
            beta_sealer,
            alpha_verifier,
            beta_verifier,
            beta_fp,
        ) = paired().await;

        let fp = Tier1Fingerprint::derive(b"nothing-here");

        let beta_task = tokio::spawn(async move {
            answer_one(
                &beta_conn,
                &beta_sealer,
                &beta_verifier,
                |_| LocalSighting::default(),
                "",
            )
            .await
            .expect("answer_one")
        });

        let answer = ask(
            &alpha_conn,
            &alpha_sealer,
            &alpha_verifier,
            beta_fp,
            build_question(fp, Duration::from_mins(1), ""),
            Duration::from_secs(5),
        )
        .await
        .expect("ask");

        let _ = beta_task.await;
        assert_eq!(answer.seen_count, 0);
        assert_eq!(answer.first_seen_unix_ms, 0);

        ep_alpha.close().await;
        ep_beta.close().await;
    }

    #[tokio::test]
    async fn ask_times_out_when_peer_never_replies() {
        let (
            ep_alpha,
            alpha_conn,
            ep_beta,
            _beta_conn, // intentionally never read from
            alpha_sealer,
            _beta_sealer,
            alpha_verifier,
            _beta_verifier,
            beta_fp,
        ) = paired().await;

        let fp = Tier1Fingerprint::derive(b"silent");
        let result = ask(
            &alpha_conn,
            &alpha_sealer,
            &alpha_verifier,
            beta_fp,
            build_question(fp, Duration::from_mins(1), ""),
            Duration::from_millis(200),
        )
        .await;
        assert!(matches!(result, Err(AskError::Timeout(_))), "{result:?}");

        ep_alpha.close().await;
        ep_beta.close().await;
    }

    #[tokio::test]
    async fn responder_drops_expired_question() {
        let (
            ep_alpha,
            alpha_conn,
            ep_beta,
            beta_conn,
            alpha_sealer,
            beta_sealer,
            alpha_verifier,
            beta_verifier,
            beta_fp,
        ) = paired().await;

        let fp = Tier1Fingerprint::derive(b"expired");
        let mut question = build_question(fp, Duration::from_mins(1), "");
        question.ttl_ms = 1; // already expired

        let beta_task = tokio::spawn(async move {
            answer_one(
                &beta_conn,
                &beta_sealer,
                &beta_verifier,
                |_| LocalSighting {
                    seen_count: 99,
                    ..Default::default()
                },
                "",
            )
            .await
        });

        let result = ask(
            &alpha_conn,
            &alpha_sealer,
            &alpha_verifier,
            beta_fp,
            question,
            Duration::from_millis(300),
        )
        .await;
        // From the asker's perspective, "responder silently dropped"
        // looks like either a timeout (if beta hasn't dropped its
        // connection yet) or a transport error (if beta's drop closed
        // the connection before the timeout fires). Either is a valid
        // signal for "no answer," and the agent's aggregator treats
        // them the same way.
        assert!(
            matches!(result, Err(AskError::Timeout(_) | AskError::Transport(_))),
            "{result:?}"
        );

        let beta_outcome = beta_task.await.unwrap();
        assert!(beta_outcome.is_ok(), "beta should have dropped silently");

        ep_alpha.close().await;
        ep_beta.close().await;
    }

    #[test]
    fn fresh_episode_ids_are_distinct() {
        let a = fresh_episode_id();
        let b = fresh_episode_id();
        assert_ne!(a, b);
        assert_eq!(a.len(), EPISODE_ID_LEN);
    }

    #[test]
    fn build_question_sets_absolute_ttl_in_future() {
        let q = build_question(
            Tier1Fingerprint::derive(b"x"),
            Duration::from_mins(1),
            "note",
        );
        let now_ms = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();
        assert!(q.ttl_ms > now_ms);
        assert!(q.ttl_ms < now_ms + 120_000);
        assert_eq!(q.note, "note");
        assert_eq!(q.tier1_fp.len(), TIER1_LEN);
        assert_eq!(q.episode_id.len(), EPISODE_ID_LEN);
    }
}
