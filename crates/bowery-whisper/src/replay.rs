//! Per-sender sliding-window replay protection.
//!
//! For each sender fingerprint we track:
//! - `highest`: the highest nonce we've accepted from that sender.
//! - `bitmap`: a 128-bit window where bit `i` represents nonce
//!   `highest - i`. Bit 0 is always set after a successful record.
//!
//! A nonce is accepted iff it is strictly newer than `highest`, or it
//! falls within the window and its bit is currently clear.

use std::collections::HashMap;

use bowery_crypto::Fingerprint;

const WINDOW_BITS: u64 = 128;

#[derive(Debug, Default)]
pub struct ReplayGuard {
    peers: HashMap<Fingerprint, PerSenderState>,
}

#[derive(Debug, Clone, Copy)]
struct PerSenderState {
    highest: u64,
    bitmap: u128,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Replay {
    #[error("nonce {nonce} is older than the replay window (highest seen: {highest})")]
    TooOld { nonce: u64, highest: u64 },

    #[error("nonce {0} has already been seen")]
    AlreadySeen(u64),
}

impl ReplayGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a `(sender, nonce)` if it has not been seen and is within the
    /// replay window. Returns `Ok(())` when the nonce is fresh, otherwise an
    /// error describing why it was rejected.
    pub fn check_and_record(&mut self, sender: Fingerprint, nonce: u64) -> Result<(), Replay> {
        match self.peers.get_mut(&sender) {
            None => {
                self.peers.insert(
                    sender,
                    PerSenderState {
                        highest: nonce,
                        bitmap: 1,
                    },
                );
                Ok(())
            }
            Some(state) => state.update(nonce),
        }
    }

    #[cfg(test)]
    pub(crate) fn highest(&self, sender: &Fingerprint) -> Option<u64> {
        self.peers.get(sender).map(|s| s.highest)
    }
}

impl PerSenderState {
    fn update(&mut self, nonce: u64) -> Result<(), Replay> {
        if nonce > self.highest {
            let shift = nonce - self.highest;
            self.bitmap = if shift >= WINDOW_BITS {
                1
            } else {
                (self.bitmap << shift) | 1
            };
            self.highest = nonce;
            return Ok(());
        }

        let offset = self.highest - nonce;
        if offset >= WINDOW_BITS {
            return Err(Replay::TooOld {
                nonce,
                highest: self.highest,
            });
        }

        let mask: u128 = 1u128 << offset;
        if self.bitmap & mask != 0 {
            return Err(Replay::AlreadySeen(nonce));
        }
        self.bitmap |= mask;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bowery_crypto::Identity;

    fn fp() -> Fingerprint {
        Identity::generate().fingerprint()
    }

    #[test]
    fn first_nonce_is_accepted() {
        let mut g = ReplayGuard::new();
        let s = fp();
        assert!(g.check_and_record(s, 100).is_ok());
        assert_eq!(g.highest(&s), Some(100));
    }

    #[test]
    fn replay_of_same_nonce_is_rejected() {
        let mut g = ReplayGuard::new();
        let s = fp();
        g.check_and_record(s, 100).unwrap();
        assert_eq!(g.check_and_record(s, 100), Err(Replay::AlreadySeen(100)));
    }

    #[test]
    fn out_of_order_within_window_is_accepted_then_rejected() {
        let mut g = ReplayGuard::new();
        let s = fp();
        g.check_and_record(s, 100).unwrap();
        g.check_and_record(s, 95).unwrap();
        assert_eq!(g.check_and_record(s, 95), Err(Replay::AlreadySeen(95)));
    }

    #[test]
    fn nonce_far_below_window_is_rejected_as_too_old() {
        let mut g = ReplayGuard::new();
        let s = fp();
        g.check_and_record(s, 1000).unwrap();
        let outcome = g.check_and_record(s, 500);
        assert!(matches!(outcome, Err(Replay::TooOld { .. })));
    }

    #[test]
    fn large_jump_forward_resets_window() {
        let mut g = ReplayGuard::new();
        let s = fp();
        g.check_and_record(s, 1).unwrap();
        // Jump forward by more than the window. Old nonces (well below the
        // new highest) become unrecoverable too-old, which is intentional.
        g.check_and_record(s, 10_000).unwrap();
        assert_eq!(
            g.check_and_record(s, 5_000),
            Err(Replay::TooOld {
                nonce: 5_000,
                highest: 10_000
            })
        );
    }

    #[test]
    fn distinct_senders_have_independent_state() {
        let mut g = ReplayGuard::new();
        let a = fp();
        let b = fp();
        g.check_and_record(a, 7).unwrap();
        g.check_and_record(b, 7).unwrap();
        assert_eq!(g.check_and_record(a, 7), Err(Replay::AlreadySeen(7)));
        assert_eq!(g.check_and_record(b, 7), Err(Replay::AlreadySeen(7)));
    }
}
