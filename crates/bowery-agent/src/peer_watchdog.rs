//! Says out loud when a *neighbour* has stopped talking.
//!
//! [`crate::probe_watchdog`] made this agent's own blindness visible.
//! This closes the matching hole one level up: an agent that is stopped
//! outright.
//!
//! Every detection built so far assumes the agent is running. An
//! attacker on a compromised host does not have to defeat any of them —
//! `systemctl stop bowery-agent` defeats all of them at once, and until
//! now that produced no signal anywhere in the fleet. The mesh knew
//! within seconds: chitchat's failure detector drops the node from
//! `live_nodes`, and `bowery-mesh` republishes the set. That fact was
//! consumed in six places, every one of them routing — who to ask, who
//! owns an address — and nowhere as a finding.
//!
//! A host cannot report its own death. Its neighbours can.
//!
//! # The distinction that makes this safe to enable
//!
//! A peer disappearing means one of two very different things, and the
//! observer usually cannot tell them apart from the peer alone:
//!
//! - *that host stopped* — a crash, a shutdown, or someone silencing the
//!   agent. Worth waking a person for.
//! - *this host lost the network* — in which case **every** peer vanishes
//!   at once, none of them are actually gone, and alerting per peer
//!   produces a storm at precisely the moment the mesh is least able to
//!   judge anything.
//!
//! What separates them is what else is still visible. If other peers are
//! still gossiping, the network is fine and the missing one is genuinely
//! missing. If nothing at all remains, the honest finding is about
//! *this* agent's isolation, reported once, rather than an accusation
//! against every neighbour.
//!
//! That is the same rule the corroboration engine already applies in the
//! other direction: silence is not evidence, and an observer without
//! standing refuses rather than answers.
//!
//! # What deliberately does not alert
//!
//! - **A peer never seen live.** A fingerprint in the manifest that has
//!   not gossiped yet is unconfigured or not deployed, not silenced.
//! - **A brief gap.** Chitchat's own failure detector already tolerates
//!   jitter; the grace period on top absorbs a restart, a reboot, and an
//!   upgrade — all of which are things an operator did on purpose.
//! - **Anything during our own startup.** A newly-started agent has not
//!   discovered the mesh yet, and would otherwise report the entire
//!   fleet missing every time it restarts.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// This module's rule id on the ATT&CK map. Both findings — a peer gone
/// silent, and this host isolated from all of them — are the same
/// detection seen from the two possible sides.
pub const RULE_ID: &str = "peer.silent";

use bowery_crypto::Fingerprint;
use bowery_mesh::PeerInfo;
use bowery_proto::{Alert, Attribute};

use crate::alert_builder::AlertBuilder;
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::agent::AgentEvent;
use crate::inbox::{AlertInbox, current_unix_ms};

/// How often the live set is examined.
pub const CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// How long a peer may be missing before it is a finding.
///
/// Long enough to cover a reboot and an agent upgrade, which are the
/// two ordinary reasons a healthy peer goes away. Chitchat's failure
/// detector has already waited before dropping it from the live set, so
/// this sits on top of that.
pub const DEFAULT_GRACE: Duration = Duration::from_mins(5);

/// How long this agent gets to discover the mesh before absence means
/// anything.
///
/// Without it, every restart reports the entire fleet missing — the same
/// false alarm [`crate::probe_watchdog`] hit when it declared the sensor
/// blind one millisecond before the probes attached.
pub const STARTUP_GRACE: Duration = Duration::from_mins(2);

/// How long a known-missing peer waits before it is restated.
pub const REMIND_AFTER: Duration = Duration::from_hours(1);

/// What the observer can honestly say about the fleet right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Still discovering. Say nothing.
    Starting,
    /// Peers are visible and none have been missing past the grace
    /// period.
    Healthy,
    /// These peers are gone, and enough of the fleet is still visible
    /// for that to mean something.
    Missing(Vec<Fingerprint>),
    /// Nothing is visible at all. The finding is about *this* agent, not
    /// about the peers — a partitioned observer that accuses every
    /// neighbour is worse than one that admits it cannot see.
    Isolated { known: usize },
}

/// Tracks which peers have ever been live, and when each was last seen.
#[derive(Debug)]
pub struct PeerLiveness {
    last_seen: HashMap<Fingerprint, Instant>,
    /// Reported-missing peers, so a finding is raised on transition and
    /// then restated on a slow cadence rather than every check.
    reported: HashMap<Fingerprint, Instant>,
    isolated_reported: Option<Instant>,
    grace: Duration,
}

impl PeerLiveness {
    #[must_use]
    pub fn new(grace: Duration) -> Self {
        Self {
            last_seen: HashMap::new(),
            reported: HashMap::new(),
            isolated_reported: None,
            grace,
        }
    }

    /// Fold in the current live set and decide what to say.
    ///
    /// `since_start` is how long this agent has been up; `now` is
    /// injected so the whole thing is testable without sleeping.
    pub fn observe(&mut self, live: &[PeerInfo], since_start: Duration, now: Instant) -> Verdict {
        for p in live {
            self.last_seen.insert(p.fingerprint, now);
            // A peer that came back is no longer a finding, and must be
            // able to be reported again if it goes away later.
            if self.reported.remove(&p.fingerprint).is_some() {
                info!(peer = %p.fingerprint, "peer is gossiping again");
            }
        }
        if !live.is_empty() {
            self.isolated_reported = None;
        }

        if since_start < STARTUP_GRACE {
            return Verdict::Starting;
        }

        // Never seen anything: either a single-node install or an agent
        // whose mesh config is wrong. Neither is a peer's fault, and
        // there is nothing to accuse.
        if self.last_seen.is_empty() {
            return Verdict::Healthy;
        }

        // Seen peers before, see none now. This says nothing trustworthy
        // about any individual peer — the common cause is our own
        // network — so it is reported once, about ourselves.
        if live.is_empty() {
            let stale = self
                .last_seen
                .values()
                .all(|t| now.duration_since(*t) >= self.grace);
            if stale {
                return Verdict::Isolated {
                    known: self.last_seen.len(),
                };
            }
            return Verdict::Healthy;
        }

        // Peers remain visible, so the network is fine and a missing
        // peer is genuinely missing.
        let mut missing: Vec<Fingerprint> = self
            .last_seen
            .iter()
            .filter(|(fp, seen)| {
                now.duration_since(**seen) >= self.grace
                    && self
                        .reported
                        .get(*fp)
                        .is_none_or(|at| now.duration_since(*at) >= REMIND_AFTER)
            })
            .map(|(fp, _)| *fp)
            .collect();
        if missing.is_empty() {
            return Verdict::Healthy;
        }
        // Deterministic order, so an alert set is stable across checks
        // and a test can assert on it.
        missing.sort_by_key(bowery_crypto::Fingerprint::to_string);
        for fp in &missing {
            self.reported.insert(*fp, now);
        }
        Verdict::Missing(missing)
    }

    /// Record that isolation has been reported, so it is restated on the
    /// remind cadence rather than every check.
    pub fn mark_isolated_reported(&mut self, now: Instant) {
        self.isolated_reported = Some(now);
    }

    /// Should isolation be reported right now?
    #[must_use]
    pub fn isolation_is_new(&self, now: Instant) -> bool {
        self.isolated_reported
            .is_none_or(|at| now.duration_since(at) >= REMIND_AFTER)
    }

    /// How many distinct peers have ever been seen gossiping.
    #[must_use]
    pub fn known(&self) -> usize {
        self.last_seen.len()
    }
}

fn missing_alert(
    originator_fp: Fingerprint,
    backend_label: &str,
    peer: Fingerprint,
    still_visible: usize,
    grace: Duration,
) -> Alert {
    AlertBuilder::new(
        originator_fp,
        backend_label,
        RULE_ID,
        format!("peer-silent-{peer}-{}", current_unix_ms()),
        // High, and deliberately so. Every other detection this agent
        // makes is void on a host whose agent is not running, and
        // stopping it is the first thing an attacker who finds it does.
        0.9,
        format!(
            "peer {peer} stopped gossiping more than {}m ago while {still_visible} other \
             peer(s) remain visible from here, so this is that host rather than this \
             one. An agent that is not running detects nothing and answers no \
             corroboration query — check whether it was stopped, and by whom",
            grace.as_secs() / 60
        ),
    )
    .context(vec![
        Attribute::new("peer_fp", peer.to_string()),
        Attribute::new("peers_still_visible", still_visible.to_string()),
        Attribute::new("silent_for_at_least", format!("{}m", grace.as_secs() / 60)),
    ])
    .build()
}

fn isolated_alert(originator_fp: Fingerprint, backend_label: &str, known: usize) -> Alert {
    AlertBuilder::new(
        originator_fp,
        backend_label,
        RULE_ID,
        format!("peer-isolated-{}", current_unix_ms()),
        0.8,
        format!(
            "this agent can no longer see any of the {known} peer(s) it had been \
             gossiping with. That is reported about this host rather than about them: \
             when every peer disappears at once the usual cause is this machine's own \
             network, and accusing {known} neighbours would be {known} false findings. \
             While isolated this agent cannot corroborate anything, so its alerts carry \
             no neighbourhood evidence"
        ),
    )
    .context(vec![Attribute::new("peers_known", known.to_string())])
    .build()
}

/// Watch the mesh's live set and report neighbours that go silent.
pub fn spawn(
    peers: watch::Receiver<Vec<PeerInfo>>,
    inbox: Arc<AlertInbox>,
    originator_fp: Fingerprint,
    backend_label: String,
    grace: Duration,
    events_tx: broadcast::Sender<AgentEvent>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let started = Instant::now();
        let mut state = PeerLiveness::new(grace);
        let mut ticker = tokio::time::interval(CHECK_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = ticker.tick() => {}
                _ = shutdown_rx.changed() => break,
            }
            if *shutdown_rx.borrow() {
                break;
            }
            let live = peers.borrow().clone();
            let now = Instant::now();
            match state.observe(&live, now.duration_since(started), now) {
                Verdict::Starting | Verdict::Healthy => {}
                Verdict::Missing(peers_missing) => {
                    for peer in peers_missing {
                        warn!(%peer, "peer stopped gossiping");
                        let alert =
                            missing_alert(originator_fp, &backend_label, peer, live.len(), grace);
                        let episode_id = alert.episode_id.clone();
                        let suspicion = alert.suspicion;
                        let appended = inbox.append(alert);
                        if appended.stored() {
                            let _ = events_tx.send(AgentEvent::AlertEmitted {
                                episode_id,
                                suspicion,
                            });
                        }
                    }
                }
                Verdict::Isolated { known } => {
                    if state.isolation_is_new(now) {
                        warn!(known, "this agent can see no peers at all");
                        let alert = isolated_alert(originator_fp, &backend_label, known);
                        let episode_id = alert.episode_id.clone();
                        let suspicion = alert.suspicion;
                        let appended = inbox.append(alert);
                        if appended.stored() {
                            let _ = events_tx.send(AgentEvent::AlertEmitted {
                                episode_id,
                                suspicion,
                            });
                        }
                        state.mark_isolated_reported(now);
                    }
                }
            }
        }
        info!("peer liveness watchdog stopped");
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn peer(seed: u8) -> PeerInfo {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let verifying_key = key.verifying_key();
        PeerInfo {
            platform: bowery_proto::platform_key(),
            fingerprint: Fingerprint::from_verifying_key(&verifying_key),
            verifying_key,
            whisper_addr: "127.0.0.1:9902".parse().unwrap(),
            agent_version: "test".into(),
            role_vector: None,
            bloom_advert: None,
            membership_grant: None,
            log_report: None,
        }
    }

    fn after(base: Instant, secs: u64) -> Instant {
        base + Duration::from_secs(secs)
    }

    const GRACE: Duration = Duration::from_mins(5);
    const UP: Duration = Duration::from_mins(10);

    #[test]
    fn a_newly_started_agent_accuses_nobody() {
        // It has not discovered the mesh yet. Reporting the whole fleet
        // missing on every restart is the false alarm the probe watchdog
        // already learned once.
        let mut s = PeerLiveness::new(GRACE);
        let t = Instant::now();
        assert_eq!(s.observe(&[], Duration::from_secs(5), t), Verdict::Starting);
    }

    #[test]
    fn a_single_node_install_is_not_a_finding() {
        // Never saw a peer, so nothing is missing.
        let mut s = PeerLiveness::new(GRACE);
        let t = Instant::now();
        assert_eq!(s.observe(&[], UP, t), Verdict::Healthy);
    }

    #[test]
    fn a_peer_that_stops_while_others_remain_is_a_finding() {
        let (a, b) = (peer(1), peer(2));
        let mut s = PeerLiveness::new(GRACE);
        let t = Instant::now();
        assert_eq!(s.observe(&[a.clone(), b.clone()], UP, t), Verdict::Healthy);
        // `a` keeps gossiping, `b` goes quiet.
        let later = after(t, 6 * 60);
        assert_eq!(
            s.observe(std::slice::from_ref(&a), UP, later),
            Verdict::Missing(vec![b.fingerprint])
        );
    }

    #[test]
    fn a_brief_gap_is_not_a_finding() {
        // A restart or an upgrade. Chitchat has already waited before
        // dropping the node; the grace absorbs the rest.
        let (a, b) = (peer(1), peer(2));
        let mut s = PeerLiveness::new(GRACE);
        let t = Instant::now();
        s.observe(&[a.clone(), b.clone()], UP, t);
        assert_eq!(
            s.observe(std::slice::from_ref(&a), UP, after(t, 60)),
            Verdict::Healthy
        );
    }

    /// The case that decides whether this is safe to enable at all.
    ///
    /// When the observer loses its own network, every peer vanishes at
    /// once and none of them are actually gone. Alerting per peer would
    /// produce a storm at exactly the moment the mesh can judge least.
    #[test]
    fn losing_the_network_reports_this_host_not_every_neighbour() {
        let mut s = PeerLiveness::new(GRACE);
        let t = Instant::now();
        s.observe(&[peer(1), peer(2), peer(3)], UP, t);
        assert_eq!(
            s.observe(&[], UP, after(t, 6 * 60)),
            Verdict::Isolated { known: 3 }
        );
    }

    #[test]
    fn a_peer_that_comes_back_stops_being_a_finding() {
        let (a, b) = (peer(1), peer(2));
        let mut s = PeerLiveness::new(GRACE);
        let t = Instant::now();
        s.observe(&[a.clone(), b.clone()], UP, t);
        let gone = after(t, 6 * 60);
        assert!(matches!(
            s.observe(std::slice::from_ref(&a), UP, gone),
            Verdict::Missing(_)
        ));
        let back = after(gone, 30);
        assert_eq!(s.observe(&[a, b], UP, back), Verdict::Healthy);
    }

    #[test]
    fn a_missing_peer_is_reported_once_not_every_check() {
        let (a, b) = (peer(1), peer(2));
        let mut s = PeerLiveness::new(GRACE);
        let t = Instant::now();
        s.observe(&[a.clone(), b.clone()], UP, t);
        let gone = after(t, 6 * 60);
        assert!(matches!(
            s.observe(std::slice::from_ref(&a), UP, gone),
            Verdict::Missing(_)
        ));
        assert_eq!(
            s.observe(std::slice::from_ref(&a), UP, after(gone, 30)),
            Verdict::Healthy,
            "a second check inside the remind window must stay quiet"
        );
        // ...but it is restated eventually, because a stopped agent
        // stays stopped until someone acts.
        assert!(matches!(
            s.observe(std::slice::from_ref(&a), UP, after(gone, 3601)),
            Verdict::Missing(_)
        ));
    }

    #[test]
    fn a_peer_that_left_and_returned_can_be_reported_again() {
        let (a, b) = (peer(1), peer(2));
        let mut s = PeerLiveness::new(GRACE);
        let t = Instant::now();
        s.observe(&[a.clone(), b.clone()], UP, t);
        let gone = after(t, 6 * 60);
        assert!(matches!(
            s.observe(std::slice::from_ref(&a), UP, gone),
            Verdict::Missing(_)
        ));
        s.observe(&[a.clone(), b.clone()], UP, after(gone, 10));
        // Second disappearance is its own finding, not suppressed by the
        // first one's remind window.
        assert!(matches!(
            s.observe(std::slice::from_ref(&a), UP, after(gone, 10 + 6 * 60)),
            Verdict::Missing(_)
        ));
    }

    #[test]
    fn the_alert_says_which_peer_and_what_else_was_visible() {
        let fp = peer(7).fingerprint;
        let a = missing_alert(peer(1).fingerprint, "test", fp, 2, GRACE);
        assert!(a.rationale.contains(&fp.to_string()));
        assert!(a.rationale.contains("2 other peer(s) remain visible"));
        assert!(a.context.iter().any(|c| c.key == "peers_still_visible"));
        assert!(a.suspicion >= 0.9);
    }

    #[test]
    fn the_isolation_alert_is_about_this_host() {
        let a = isolated_alert(peer(1).fingerprint, "test", 3);
        assert!(a.rationale.contains("this agent"));
        assert!(
            a.rationale.contains("3 false findings"),
            "it must say why it is not accusing the peers: {}",
            a.rationale
        );
    }
}
