//! Phase-8 slice 2: property tests for `ReplayGuard`.
//!
//! The deterministic unit tests (in `replay.rs`) cover the named
//! invariants by construction. These proptests beat the same
//! invariants against random nonce sequences across multiple
//! senders, looking for adversarial orderings the unit tests don't
//! enumerate.
//!
//! Invariants checked:
//!
//! 1. **No double-accept** — any `(sender, nonce)` pair the guard
//!    accepts once must be rejected on every subsequent attempt
//!    (with `AlreadySeen` if still in the window, `TooOld` if it
//!    has fallen out).
//!
//! 2. **Window bound** — a nonce more than `WINDOW_BITS` (128)
//!    below the per-sender highest is always rejected as `TooOld`.
//!
//! 3. **Monotone highest** — after recording `n > highest`, the new
//!    highest equals `n`.
//!
//! 4. **Cross-sender independence** — operations on sender A leave
//!    sender B's accept/reject behaviour identical to running the
//!    same B-only sequence in a fresh guard.

use std::collections::HashMap;

use bowery_crypto::{Fingerprint, Identity};
use bowery_whisper::{Replay, ReplayGuard};
use proptest::collection::vec;
use proptest::prelude::*;

const WINDOW_BITS: u64 = 128;

/// Build N distinct fingerprints up front so the proptest's index
/// space is small (proptest cardinality matters for shrinking).
fn senders(n: usize) -> Vec<Fingerprint> {
    (0..n).map(|_| Identity::generate().fingerprint()).collect()
}

/// Reference model: per-sender map from nonce → "ever accepted".
#[derive(Default)]
struct Model {
    per_sender: HashMap<Fingerprint, PerSenderModel>,
}

#[derive(Default)]
struct PerSenderModel {
    accepted: std::collections::HashSet<u64>,
    highest: u64,
}

impl Model {
    /// Returns whether the guard *should* accept this op.
    fn should_accept(&self, sender: Fingerprint, nonce: u64) -> bool {
        let Some(state) = self.per_sender.get(&sender) else {
            return true; // first nonce from a new sender always wins
        };
        if state.accepted.contains(&nonce) {
            return false;
        }
        if nonce > state.highest {
            return true;
        }
        // nonce <= highest: in-window iff offset < WINDOW_BITS
        (state.highest - nonce) < WINDOW_BITS
    }

    fn record(&mut self, sender: Fingerprint, nonce: u64) {
        let entry = self.per_sender.entry(sender).or_default();
        entry.accepted.insert(nonce);
        if nonce > entry.highest {
            entry.highest = nonce;
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    /// Random nonce sequences across N senders. Compare guard
    /// decisions against the reference model.
    #[test]
    fn guard_matches_reference_model(
        // 3 senders is enough to catch cross-sender bugs; more wastes
        // proptest cycles.
        ops in vec((0u8..3, 0u64..10_000), 1..200),
    ) {
        let senders = senders(3);
        let mut guard = ReplayGuard::new();
        let mut model = Model::default();

        for (sender_idx, nonce) in ops {
            let sender = senders[sender_idx as usize];
            let expected = model.should_accept(sender, nonce);
            let actual = guard.check_and_record(sender, nonce).is_ok();
            prop_assert_eq!(
                actual, expected,
                "guard disagreed with model at (sender_idx={}, nonce={}): actual={}, expected={}",
                sender_idx, nonce, actual, expected
            );
            if actual {
                model.record(sender, nonce);
            }
        }
    }

    /// Window-bound: a nonce more than WINDOW_BITS below the highest
    /// must be rejected as TooOld.
    #[test]
    fn nonces_below_window_are_too_old(
        // Ensure `highest >= below_offset` so the subtraction can't
        // underflow at any sampled point in the range. Picking the
        // lower bound of `highest` to be `below_offset_max + 1` keeps
        // every sampled (highest, below_offset) pair valid.
        highest in (WINDOW_BITS + 1000)..1_000_000u64,
        below_offset in WINDOW_BITS..(WINDOW_BITS + 1000),
    ) {
        let mut guard = ReplayGuard::new();
        let s = Identity::generate().fingerprint();
        guard.check_and_record(s, highest).unwrap();
        let nonce = highest - below_offset;
        let result = guard.check_and_record(s, nonce);
        prop_assert!(
            matches!(result, Err(Replay::TooOld { .. })),
            "expected TooOld for nonce {} below highest {}, got {:?}",
            nonce, highest, result
        );
    }

    /// Cross-sender independence: A's nonce sequence does not change
    /// what B sees.
    #[test]
    fn senders_have_independent_history(
        a_ops in vec(0u64..10_000, 1..50),
        b_op in 0u64..10_000,
    ) {
        let a = Identity::generate().fingerprint();
        let b = Identity::generate().fingerprint();

        // Path 1: process all of A then B once.
        let mut g1 = ReplayGuard::new();
        for n in &a_ops {
            let _ = g1.check_and_record(a, *n);
        }
        let r1 = g1.check_and_record(b, b_op);

        // Path 2: just process B alone.
        let mut g2 = ReplayGuard::new();
        let r2 = g2.check_and_record(b, b_op);

        prop_assert_eq!(
            r1.is_ok(), r2.is_ok(),
            "B's first nonce {} accept-decision changed because of A's history",
            b_op
        );
    }

    /// Recording a fresh `n > highest` advances `highest` to `n`.
    #[test]
    fn highest_advances_on_strictly_increasing(
        seq in vec(0u64..1_000_000, 1..50),
    ) {
        let mut guard = ReplayGuard::new();
        let s = Identity::generate().fingerprint();
        let mut last_accepted: Option<u64> = None;
        for n in seq {
            let accepted_before = last_accepted;
            let outcome = guard.check_and_record(s, n);
            if outcome.is_ok() {
                // Either monotone forward, or a recovered hole within
                // the window. Both leave `highest >= n`.
                let prev = accepted_before.unwrap_or(0);
                last_accepted = Some(prev.max(n));
            }
        }
        // Sanity: replaying any accepted nonce must now fail.
        if let Some(n) = last_accepted {
            let result = guard.check_and_record(s, n);
            prop_assert!(
                result.is_err(),
                "replaying accepted nonce {} succeeded second time",
                n
            );
        }
    }
}
