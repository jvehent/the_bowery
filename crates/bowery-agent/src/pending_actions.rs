//! Actions held back until the neighbourhood agrees.
//!
//! `DESIGN.md` has specified from the start that a hard action requires
//! either standing operator authorization *or* k-of-n peer agreement.
//! The quorum signal has existed and been trustworthy for a while; the
//! response engine never saw it. This is the wire between them.
//!
//! # Why an action cannot simply be gated in the engine
//!
//! The two facts arrive at different times. An action is decided the
//! moment a verdict is produced, when the alert still carries
//! `confirmation: None` — the whisper round has only just been fired.
//! Confirmation lands later, in `finish_round`, as a superseding alert.
//!
//! An engine asked "is this corroborated?" at decision time would
//! therefore always answer no, and a policy requiring corroboration
//! would deny everything forever. So the action is **parked** instead,
//! and released when — and only when — the round confirms.
//!
//! # What must not happen
//!
//! **A parked action must never fire late.** If the round stalls, the
//! process it was about is long gone and the pid may belong to something
//! else entirely; killing it then is worse than not killing it at all.
//! Hence a TTL, checked on release rather than trusted to a sweeper.
//!
//! **Not confirming must drop the action, and say so.** Silence here
//! would be indistinguishable from an action that ran, in the one log an
//! operator consults to find out what this agent did. Every parked
//! action leaves the store with a recorded reason.
//!
//! **An episode that never runs a round must expire, not wait.** A
//! verdict below the whisper threshold fires no round at all, so nothing
//! will ever release it. The TTL is what makes that terminate, and the
//! expiry is reported rather than swept silently.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use bowery_response::Action;

/// How long an action waits for its round before it is abandoned.
///
/// A whisper round is seconds; this is generous for a slow one and far
/// short of the point where acting on a stale pid becomes dangerous.
pub const DEFAULT_TTL: Duration = Duration::from_mins(2);

/// Why an action left the store without being executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dropped {
    /// The round completed and the neighbourhood did not confirm.
    NotCorroborated,
    /// The round completed and nothing could be compared — every peer
    /// that answered runs a different platform.
    ///
    /// Distinct from [`Self::NotCorroborated`] for the same reason that
    /// module records a reason at all: "the fleet disagreed with you"
    /// and "the fleet was never able to look" are different facts about
    /// an action that did not happen, and an operator reading the audit
    /// trail to find out why is owed the second one.
    NotComparable,
    /// No confirmation arrived in time — usually because the episode
    /// never triggered a round at all.
    Expired,
}

impl Dropped {
    /// Operator-facing reason, recorded in the audit trail.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::NotCorroborated => "held for corroboration; the neighbourhood did not confirm",
            Self::NotComparable => {
                "held for corroboration; no peer could compare (different platform)"
            }
            Self::Expired => "held for corroboration; no whisper round confirmed it in time",
        }
    }
}

/// An action leaving the store, and what happened to it.
///
/// Carried on a channel rather than executed in place: `finish_round`
/// runs on the whisper task, which must not be blocked by a kill or a
/// BPF map write, and the audit trail is written by the same task that
/// writes every other one.
#[derive(Debug)]
pub struct Release {
    pub episode_id: String,
    pub action: Action,
    /// `None` means execute it; `Some` says why it is being abandoned.
    pub dropped: Option<Dropped>,
}

struct Parked {
    actions: Vec<Action>,
    at: Instant,
}

/// Actions waiting on a quorum, keyed by episode.
#[derive(Default)]
pub struct PendingActions {
    inner: std::sync::Mutex<HashMap<String, Parked>>,
    ttl: Duration,
    max_tracked: usize,
}

impl std::fmt::Debug for PendingActions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingActions")
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

impl PendingActions {
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: std::sync::Mutex::new(HashMap::new()),
            ttl,
            // Episodes awaiting a round are transient; this bounds a
            // pathological burst rather than a real workload.
            max_tracked: 1024,
        }
    }

    /// Hold `actions` until the round for `episode_id` confirms.
    ///
    /// Returns the actions back when the store is unusable, so the
    /// caller can decide rather than silently losing them.
    pub fn park(&self, episode_id: &str, actions: Vec<Action>, now: Instant) {
        if actions.is_empty() {
            return;
        }
        let Ok(mut guard) = self.inner.lock() else {
            return;
        };
        if guard.len() >= self.max_tracked {
            // Drop the oldest rather than the incoming one: a burst
            // should not be able to keep a legitimate action out.
            if let Some(oldest) = guard
                .iter()
                .min_by_key(|(_, p)| p.at)
                .map(|(k, _)| k.clone())
            {
                guard.remove(&oldest);
            }
        }
        guard
            .entry(episode_id.to_string())
            .or_insert_with(|| Parked {
                actions: Vec::new(),
                at: now,
            })
            .actions
            .extend(actions);
    }

    /// The round confirmed: hand back what was held.
    ///
    /// Returns empty when nothing was parked, or when what was parked
    /// has aged past the TTL — a stale action must not fire late, and
    /// the pid it names may belong to something else by now.
    pub fn release(&self, episode_id: &str, now: Instant) -> Vec<Action> {
        let Ok(mut guard) = self.inner.lock() else {
            return Vec::new();
        };
        let Some(parked) = guard.remove(episode_id) else {
            return Vec::new();
        };
        if now.duration_since(parked.at) > self.ttl {
            return Vec::new();
        }
        parked.actions
    }

    /// The round completed without confirming: discard and report.
    pub fn discard(&self, episode_id: &str) -> Vec<Action> {
        let Ok(mut guard) = self.inner.lock() else {
            return Vec::new();
        };
        guard
            .remove(episode_id)
            .map(|p| p.actions)
            .unwrap_or_default()
    }

    /// Everything that has waited too long, removed and returned so the
    /// caller can record why each was abandoned.
    ///
    /// Reported rather than swept silently: an action that was decided
    /// and never carried out is exactly what an operator reading the
    /// audit trail needs to know about.
    pub fn take_expired(&self, now: Instant) -> Vec<(String, Vec<Action>)> {
        let Ok(mut guard) = self.inner.lock() else {
            return Vec::new();
        };
        let stale: Vec<String> = guard
            .iter()
            .filter(|(_, p)| now.duration_since(p.at) > self.ttl)
            .map(|(k, _)| k.clone())
            .collect();
        stale
            .into_iter()
            .filter_map(|k| guard.remove(&k).map(|p| (k, p.actions)))
            .collect()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().map_or(0, |g| g.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kill(episode: &str) -> Action {
        Action::KillProcess {
            pid: 4242,
            episode_id: episode.into(),
        }
    }

    fn store() -> PendingActions {
        PendingActions::new(DEFAULT_TTL)
    }

    #[test]
    fn a_confirmed_round_releases_what_it_was_holding() {
        let s = store();
        let t = Instant::now();
        s.park("ep-1", vec![kill("ep-1")], t);
        let released = s.release("ep-1", t + Duration::from_secs(3));
        assert_eq!(released.len(), 1);
        // ...and only once.
        assert!(s.release("ep-1", t + Duration::from_secs(4)).is_empty());
    }

    /// The safety property that decides whether this is usable at all:
    /// a stale action must not fire late. By then the process is long
    /// gone and the pid may belong to something else entirely.
    #[test]
    fn a_stale_action_is_never_released() {
        let s = PendingActions::new(Duration::from_mins(2));
        let t = Instant::now();
        s.park("ep-1", vec![kill("ep-1")], t);
        assert!(
            s.release("ep-1", t + Duration::from_secs(2 * 60 + 1))
                .is_empty(),
            "an action older than the TTL must not be handed back"
        );
    }

    #[test]
    fn a_round_that_does_not_confirm_discards_and_hands_back_for_reporting() {
        let s = store();
        let t = Instant::now();
        s.park("ep-1", vec![kill("ep-1")], t);
        let dropped = s.discard("ep-1");
        assert_eq!(dropped.len(), 1, "the caller must be able to record it");
        assert_eq!(s.len(), 0);
    }

    /// An episode below the whisper threshold fires no round, so nothing
    /// will ever release it. The TTL is what makes that terminate, and
    /// the expiry is returned so it can be recorded rather than swept
    /// silently.
    #[test]
    fn an_episode_that_never_runs_a_round_expires_and_is_reported() {
        let s = PendingActions::new(Duration::from_mins(2));
        let t = Instant::now();
        s.park("ep-quiet", vec![kill("ep-quiet")], t);
        assert!(s.take_expired(t + Duration::from_secs(10)).is_empty());
        let expired = s.take_expired(t + Duration::from_secs(2 * 60 + 1));
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].0, "ep-quiet");
        assert_eq!(expired[0].1.len(), 1);
        assert_eq!(s.len(), 0, "expiry removes it");
    }

    #[test]
    fn parking_nothing_stores_nothing() {
        let s = store();
        s.park("ep-1", Vec::new(), Instant::now());
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn several_actions_for_one_episode_are_all_held() {
        let s = store();
        let t = Instant::now();
        s.park("ep-1", vec![kill("ep-1")], t);
        s.park(
            "ep-1",
            vec![Action::BlockExec {
                comm: "evil".into(),
                episode_id: "ep-1".into(),
            }],
            t,
        );
        assert_eq!(s.release("ep-1", t + Duration::from_secs(1)).len(), 2);
    }

    #[test]
    fn an_unknown_episode_releases_nothing() {
        let s = store();
        assert!(s.release("never-parked", Instant::now()).is_empty());
    }

    /// A burst must not be able to push a legitimate action out of the
    /// store, so the *oldest* is evicted rather than the incoming one.
    #[test]
    fn the_store_is_bounded_and_evicts_the_oldest() {
        let s = store();
        let t = Instant::now();
        for i in 0..2000 {
            s.park(
                &format!("ep-{i}"),
                vec![kill("x")],
                t + Duration::from_millis(i),
            );
        }
        assert!(s.len() <= 1024);
        // The most recent survived.
        assert_eq!(
            s.release("ep-1999", t + Duration::from_secs(2)).len(),
            1,
            "the newest park must not be the one evicted"
        );
    }

    #[test]
    fn each_drop_reason_says_what_happened() {
        assert!(
            Dropped::NotCorroborated
                .reason()
                .contains("did not confirm")
        );
        assert!(Dropped::Expired.reason().contains("in time"));
    }
}
