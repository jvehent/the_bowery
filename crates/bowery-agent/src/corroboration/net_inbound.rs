//! The `net.inbound_connect` kind: *"did you connect to me?"*
//!
//! Lateral movement is two events on two machines, and neither is
//! remarkable alone. An inbound SSH is normal. An outbound SSH is
//! normal. What is not normal is an inbound connection that the host it
//! came from has no record of making — and only the two endpoints
//! together can see that.
//!
//! Two halves live here, and they are deliberately the *only* things
//! that know what this detection is about:
//!
//! - [`claim_for`], which turns an inbound connect event into a
//!   [`Claim`] for the engine to run.
//! - [`InboundConnectResponder`], which answers one on the other side.
//!
//! # What a denial means
//!
//! Either the source host's agent is not seeing what it should — blind,
//! tampered with, or newly compromised — or the source address was
//! spoofed. Both are worth waking someone for, and neither is visible
//! from one host. That is also why the responder works so hard to
//! *refuse* rather than deny when it isn't sure: a denial is an
//! accusation, and an accusation that fires on ordinary conditions is
//! one an operator learns to ignore.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bowery_crypto::Fingerprint;
use bowery_events::{NetDirection, NetworkConnect};
use bowery_mesh::PeerInfo;
use bowery_proto::{Attribute, Corroboration, CorroborationAnswer, CorroborationQuery, attribute};
use bowery_whisper::corroborate;
use tokio::sync::watch;
use tracing::{debug, warn};

use super::{Audience, Claim, Rule};

/// Handler selector, on the wire and in the registry.
pub const KIND: &str = "net.inbound_connect";

/// Subject attribute: the address that was connected to. Must be an
/// address of the **asker**, and the responder enforces it.
pub const ATTR_DST_ADDR: &str = "dst_addr";
/// Subject attribute: the port that was connected to.
pub const ATTR_DST_PORT: &str = "dst_port";

/// Evidence attributes, populated only on
/// [`Corroboration::Corroborated`].
pub const ATTR_PID: &str = "pid";
pub const ATTR_COMM: &str = "comm";
pub const ATTR_EXE_PATH: &str = "exe_path";
pub const ATTR_TS: &str = "ts_unix_ms";

/// Longest history window a peer may ask us to search.
///
/// A correlation question is about one connection, so minutes is
/// generous. The cap exists because the window is attacker-chosen: an
/// unbounded one turns a cheap question into a full-history scan, and
/// the whole point of the query is that answering it is cheap.
pub const MAX_WINDOW_MS: u64 = 10 * 60 * 1000;

// ---------------------------------------------------------------------------
// Asker side
// ---------------------------------------------------------------------------

/// Turn an inbound connection into a claim, or `None` if there is
/// nothing worth asking about.
///
/// The filters here are all about not asking questions that can only
/// produce noise:
///
/// - **Outbound is somebody else's problem.** We made that connection;
///   there is nothing to corroborate.
/// - **An unknown local address can't be named.** The query has to tell
///   the peer which of *our* addresses it reached, or a multi-homed
///   host gets back "no record" for a perfectly real connection and
///   accuses a healthy agent of lying. If the sensor didn't give us
///   one, we don't guess.
///
/// Whether the source is a mesh peer at all is decided later, by
/// [`Audience::PeerAtAddress`] resolving against the live mesh view —
/// deliberately not here, where a detector would have to be handed the
/// mesh just to filter.
#[must_use]
pub fn claim_for(conn: &NetworkConnect, half_window: Duration, suspicion: f32) -> Option<Claim> {
    if conn.direction != NetDirection::Inbound {
        return None;
    }
    if conn.local_addr.is_unspecified() {
        debug!(
            src = %conn.daddr,
            "inbound connect without a local address; cannot ask a peer about it"
        );
        return None;
    }

    let (window_start_unix_ms, window_end_unix_ms) = super::window_around(conn.ts, half_window);
    Some(Claim {
        kind: KIND,
        subject: vec![
            Attribute::new(ATTR_DST_ADDR, conn.local_addr.to_string()),
            Attribute::new(ATTR_DST_PORT, conn.local_port.to_string()),
        ],
        window_start_unix_ms,
        window_end_unix_ms,
        audience: Audience::PeerAtAddress(conn.daddr),
        rule: Rule::deny_alerts(),
        // Source host and the port it reached, not the source port:
        // a scan or a busy client opens many connections that differ
        // only in ephemeral source port, and every one of them asks the
        // same question.
        dedup_key: format!("{}->{}", conn.daddr, conn.local_port),
        summary: format!(
            "inbound connection from {} to {}:{}",
            conn.daddr, conn.local_addr, conn.local_port
        ),
        suspicion,
        // A counterparty claim stands alone: there is no earlier alert
        // to revise, because the inbound connection raised none.
        supersedes: None,
        explained_suspicion: 0.0,
    })
}

// ---------------------------------------------------------------------------
// Responder side
// ---------------------------------------------------------------------------

/// Answers `net.inbound_connect` from this host's own outbound history.
#[derive(Debug)]
pub struct InboundConnectResponder {
    log: Arc<bowery_eventlog::EventLog>,
    /// Live mesh view, used to check that an asker is asking about its
    /// own address. Never anything the query itself asserts.
    peers: watch::Receiver<Vec<PeerInfo>>,
}

impl InboundConnectResponder {
    #[must_use]
    pub fn new(log: Arc<bowery_eventlog::EventLog>, peers: watch::Receiver<Vec<PeerInfo>>) -> Self {
        Self { log, peers }
    }

    /// Is `addr` an address we believe belongs to `asker`?
    fn asker_owns(&self, asker: Fingerprint, addr: &str) -> bool {
        self.peers
            .borrow()
            .iter()
            .filter(|p| p.fingerprint == asker)
            .any(|p| p.whisper_addr.ip().to_string() == addr)
    }
}

#[async_trait]
impl super::CorroborationResponder for InboundConnectResponder {
    fn kind(&self) -> &'static str {
        KIND
    }

    /// The privacy property is enforced here, and it is the reason this
    /// query is safe to expose at all: **the address asked about must
    /// be an address of the asker**, as *our* view of the mesh reports
    /// it. A peer therefore only ever learns about traffic it was
    /// already party to — it observed the inbound side itself. Without
    /// the check this would be a primitive for enumerating any peer's
    /// outbound connections, one address at a time.
    async fn respond(&self, asker: Fingerprint, query: &CorroborationQuery) -> CorroborationAnswer {
        let Some(dst_addr) = attribute(&query.subject, ATTR_DST_ADDR) else {
            return corroborate::refuse(query, "missing dst_addr");
        };
        let Some(Ok(port)) = attribute(&query.subject, ATTR_DST_PORT).map(str::parse::<u16>) else {
            return corroborate::refuse(query, "missing or invalid dst_port");
        };

        if !self.asker_owns(asker, dst_addr) {
            warn!(
                asker = %asker,
                dst_addr,
                "refusing correlation query: address is not the asker's own"
            );
            return corroborate::refuse(query, "dst_addr is not an address of the asker");
        }

        // Clamp the window regardless of what was asked for.
        let end = query.window_end_unix_ms;
        let start = query
            .window_start_unix_ms
            .max(end.saturating_sub(MAX_WINDOW_MS));

        let log = self.log.clone();
        let addr = dst_addr.to_string();
        // SQLite is synchronous, and this runs on the connection
        // handler's task.
        let found = tokio::task::spawn_blocking(move || {
            // Coverage first. "I have no record of it" and "I would not
            // have recorded it either way" are opposite answers, and
            // only the first is evidence. Without this check every
            // freshly-installed agent denies every connection made
            // before it was installed, and every agent whose retention
            // has trimmed the window denies whatever fell off the end —
            // false accusations that look exactly like the real finding
            // and vastly outnumber it.
            match log.covers_since(start) {
                Ok(true) => {}
                Ok(false) => return Ok(Coverage::Insufficient),
                Err(e) => return Err(e),
            }
            log.find_outbound_to(&addr, port, start, end)
                .map(Coverage::Searched)
        })
        .await;

        match found {
            Ok(Ok(Coverage::Searched(Some(m)))) => corroborate::answer(
                query,
                Corroboration::Corroborated,
                vec![
                    Attribute::new(ATTR_PID, m.pid.to_string()),
                    Attribute::new(ATTR_COMM, m.comm),
                    Attribute::new(ATTR_EXE_PATH, m.exe_path),
                    Attribute::new(ATTR_TS, m.ts_unix_ms.to_string()),
                ],
            ),
            Ok(Ok(Coverage::Searched(None))) => {
                corroborate::answer(query, Corroboration::Denied, Vec::new())
            }
            Ok(Ok(Coverage::Insufficient)) => {
                debug!(
                    asker = %asker,
                    window_start = start,
                    "refusing correlation query: history does not reach back that far"
                );
                corroborate::refuse(query, "history does not cover the requested window")
            }
            Ok(Err(e)) => {
                warn!(error = %e, "correlation lookup failed");
                // Distinct from "no record": an error here must not be
                // read as evidence that the connection never happened.
                corroborate::refuse(query, format!("lookup failed: {e}"))
            }
            Err(e) => {
                warn!(error = %e, "correlation lookup task panicked");
                corroborate::refuse(query, "lookup task failed")
            }
        }
    }
}

/// Whether the log could speak to the requested window at all.
enum Coverage {
    Searched(Option<bowery_eventlog::ConnectionMatch>),
    Insufficient,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corroboration::CorroborationResponder;
    use bowery_events::NetFamily;
    use std::net::{IpAddr, SocketAddr};
    use std::time::{Duration, SystemTime};

    fn inbound() -> NetworkConnect {
        NetworkConnect {
            pid: 0,
            comm: String::new(),
            family: NetFamily::V4,
            daddr: "100.117.62.35".parse().unwrap(),
            local_addr: "100.105.157.53".parse().unwrap(),
            dport: 46620,
            local_port: 22,
            direction: NetDirection::Inbound,
            ts: SystemTime::now(),
        }
    }

    #[test]
    fn an_inbound_connection_names_our_own_address() {
        // The asker must tell the peer which of *our* addresses it
        // reached — measured by the sensor, never guessed — or a
        // multi-homed host gets "no record" for a real connection.
        let claim = claim_for(&inbound(), Duration::from_mins(5), 0.7).expect("claim");
        assert_eq!(claim.kind, KIND);
        assert_eq!(
            attribute(&claim.subject, ATTR_DST_ADDR),
            Some("100.105.157.53")
        );
        assert_eq!(attribute(&claim.subject, ATTR_DST_PORT), Some("22"));
        assert!(matches!(
            claim.audience,
            Audience::PeerAtAddress(ip) if ip == "100.117.62.35".parse::<IpAddr>().unwrap()
        ));
    }

    #[test]
    fn outbound_connections_raise_nothing() {
        let mut conn = inbound();
        conn.direction = NetDirection::Outbound;
        assert!(claim_for(&conn, Duration::from_mins(5), 0.7).is_none());
    }

    #[test]
    fn an_unspecified_local_address_raises_nothing() {
        // Pre-migration rows and any future sensor that can't measure
        // our own address: better to ask nothing than to ask about an
        // address the peer never connected to and read the inevitable
        // "no record" as a finding.
        let mut conn = inbound();
        conn.local_addr = "0.0.0.0".parse().unwrap();
        assert!(claim_for(&conn, Duration::from_mins(5), 0.7).is_none());
    }

    #[test]
    fn the_dedup_key_ignores_the_ephemeral_source_port() {
        // A scan opens hundreds of connections differing only in source
        // port, and every one of them asks the identical question.
        let a = claim_for(&inbound(), Duration::from_mins(5), 0.7).unwrap();
        let mut second = inbound();
        second.dport = 51075;
        let b = claim_for(&second, Duration::from_mins(5), 0.7).unwrap();
        assert_eq!(a.dedup_key, b.dedup_key);
    }

    #[test]
    fn the_window_straddles_the_observation() {
        let conn = inbound();
        let claim = claim_for(&conn, Duration::from_mins(5), 0.7).unwrap();
        let at = super::super::window_around(conn.ts, Duration::ZERO).0;
        assert_eq!(claim.window_start_unix_ms, at - 300_000);
        assert_eq!(claim.window_end_unix_ms, at + 300_000);
    }

    // -- responder ------------------------------------------------------

    fn peer_info(fp: Fingerprint, addr: SocketAddr) -> PeerInfo {
        PeerInfo {
            fingerprint: fp,
            verifying_key: ed25519_dalek::VerifyingKey::from_bytes(&[
                0x3a, 0x4f, 0x77, 0x16, 0xd5, 0x3e, 0x9c, 0x6c, 0x76, 0x4b, 0x44, 0x49, 0x12, 0x91,
                0xfa, 0x9d, 0x6f, 0x1b, 0xea, 0x4d, 0x21, 0x66, 0xa2, 0xa6, 0xc5, 0xe4, 0xa1, 0xab,
                0x6b, 0x06, 0xc9, 0x07,
            ])
            .expect("valid pubkey"),
            whisper_addr: addr,
            agent_version: "0.0.1".into(),
            role_vector: None,
            bloom_advert: None,
            membership_grant: None,
            log_report: None,
        }
    }

    /// A responder whose mesh view says `asker` lives at `10.0.0.1`,
    /// over a log seeded with `events`.
    fn responder(
        asker: Fingerprint,
        events: &[bowery_events::Event],
    ) -> (InboundConnectResponder, watch::Sender<Vec<PeerInfo>>) {
        let log = Arc::new(bowery_eventlog::EventLog::open_in_memory().unwrap());
        if !events.is_empty() {
            log.append_batch(events).unwrap();
        }
        let (tx, rx) = watch::channel(vec![peer_info(asker, "10.0.0.1:9902".parse().unwrap())]);
        (InboundConnectResponder::new(log, rx), tx)
    }

    fn outbound_to(addr: &str, port: u16, ts: SystemTime) -> bowery_events::Event {
        bowery_events::Event::NetworkConnect(NetworkConnect {
            pid: 4242,
            comm: "curl".into(),
            family: NetFamily::V4,
            daddr: addr.parse().unwrap(),
            local_addr: "10.0.0.9".parse().unwrap(),
            dport: port,
            local_port: 0,
            direction: NetDirection::Outbound,
            ts,
        })
    }

    fn query_for(addr: &str, port: u16) -> CorroborationQuery {
        let now = crate::corroboration::now_unix_ms();
        corroborate::build_query(
            KIND,
            vec![
                Attribute::new(ATTR_DST_ADDR, addr),
                Attribute::new(ATTR_DST_PORT, port.to_string()),
            ],
            now.saturating_sub(300_000),
            now.saturating_add(300_000),
            Duration::from_secs(30),
        )
    }

    #[tokio::test]
    async fn corroborates_a_connection_it_made_and_attributes_it() {
        let asker = Fingerprint::from_bytes([7; 32]);
        // Two events: an old one so the log demonstrably covers the
        // window, and the connection being asked about. Without the
        // first, the honest answer is "I wasn't recording then" — see
        // `refuses_when_history_does_not_reach_back_far_enough`.
        let old = SystemTime::now() - Duration::from_hours(1);
        let (r, _tx) = responder(
            asker,
            &[
                outbound_to("192.0.2.5", 443, old),
                outbound_to("10.0.0.1", 22, SystemTime::now()),
            ],
        );
        let answer = r.respond(asker, &query_for("10.0.0.1", 22)).await;
        assert_eq!(answer.corroboration(), Corroboration::Corroborated);
        // The attribution is the whole point: the accepting host can
        // never derive this on its own.
        assert_eq!(attribute(&answer.evidence, ATTR_COMM), Some("curl"));
        assert_eq!(attribute(&answer.evidence, ATTR_PID), Some("4242"));
    }

    #[tokio::test]
    async fn denies_a_connection_it_did_not_make() {
        let asker = Fingerprint::from_bytes([7; 32]);
        // History covers the window (there is an older event), but holds
        // nothing to 10.0.0.1:22.
        let old = SystemTime::now() - Duration::from_hours(1);
        let (r, _tx) = responder(asker, &[outbound_to("192.0.2.5", 443, old)]);
        let answer = r.respond(asker, &query_for("10.0.0.1", 22)).await;
        assert_eq!(answer.corroboration(), Corroboration::Denied);
    }

    #[tokio::test]
    async fn refuses_an_address_that_is_not_the_askers_own() {
        // Without this the message is a primitive for enumerating any
        // peer's outbound traffic, one address at a time.
        let asker = Fingerprint::from_bytes([7; 32]);
        let old = SystemTime::now() - Duration::from_hours(1);
        let (r, _tx) = responder(asker, &[outbound_to("203.0.113.9", 443, old)]);
        let answer = r.respond(asker, &query_for("203.0.113.9", 443)).await;
        assert_eq!(answer.corroboration(), Corroboration::Refused);
        assert!(answer.reason.contains("not an address of the asker"));
    }

    #[tokio::test]
    async fn refuses_when_history_does_not_reach_back_far_enough() {
        // A freshly-installed agent knows nothing about last week, and
        // saying "I have no record" would accuse every peer that ever
        // talked to it. This is the check that keeps the alert
        // trustworthy.
        let asker = Fingerprint::from_bytes([7; 32]);
        let (r, _tx) = responder(asker, &[outbound_to("192.0.2.5", 443, SystemTime::now())]);
        let answer = r.respond(asker, &query_for("10.0.0.1", 22)).await;
        assert_eq!(answer.corroboration(), Corroboration::Refused);
        assert!(
            answer.reason.contains("does not cover"),
            "{}",
            answer.reason
        );
    }

    #[tokio::test]
    async fn an_empty_log_refuses_rather_than_denying() {
        let asker = Fingerprint::from_bytes([7; 32]);
        let (r, _tx) = responder(asker, &[]);
        let answer = r.respond(asker, &query_for("10.0.0.1", 22)).await;
        assert_eq!(answer.corroboration(), Corroboration::Refused);
    }

    #[tokio::test]
    async fn refuses_a_malformed_subject() {
        let asker = Fingerprint::from_bytes([7; 32]);
        let (r, _tx) = responder(asker, &[]);
        let mut q = query_for("10.0.0.1", 22);
        q.subject = vec![Attribute::new(ATTR_DST_ADDR, "10.0.0.1")]; // no port
        assert_eq!(
            r.respond(asker, &q).await.corroboration(),
            Corroboration::Refused
        );

        let mut q = query_for("10.0.0.1", 22);
        q.subject = vec![
            Attribute::new(ATTR_DST_ADDR, "10.0.0.1"),
            Attribute::new(ATTR_DST_PORT, "not-a-port"),
        ];
        assert_eq!(
            r.respond(asker, &q).await.corroboration(),
            Corroboration::Refused
        );
    }

    #[tokio::test]
    async fn an_unknown_asker_is_refused() {
        // Nobody in our mesh view owns that address, so we cannot
        // establish that the asker was party to the traffic.
        let asker = Fingerprint::from_bytes([7; 32]);
        let (r, _tx) = responder(asker, &[]);
        let stranger = Fingerprint::from_bytes([8; 32]);
        let answer = r.respond(stranger, &query_for("10.0.0.1", 22)).await;
        assert_eq!(answer.corroboration(), Corroboration::Refused);
    }
}
