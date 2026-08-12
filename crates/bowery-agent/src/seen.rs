//! A bounded, expiring "have I already handled this?" set.
//!
//! Two consumers, for two different reasons that happen to want exactly
//! the same structure:
//!
//! - **YARA push propagation.** A cyclic pinned-peer graph (A→B→C→A, or
//!   simply two peers pinned to each other) would bounce a push
//!   forever. Keyed by `(operator_fp, request_id)`, this makes each
//!   agent handle a given push once no matter how many paths reach it.
//! - **Corroboration claims.** A host being port-scanned observes one
//!   inbound connection per probe. Without collapsing repeats it would
//!   run one mesh round per probe, turning a noisy neighbour into a
//!   fleet-wide amplifier.
//!
//! Entries expire so a long-lived agent doesn't accumulate keys
//! forever, and the map is capped so a hostile flood of distinct keys
//! can't grow it without bound — oldest first.

use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct RecentlySeen {
    inner: std::sync::Mutex<Inner>,
    ttl: Duration,
    max_entries: usize,
}

#[derive(Debug)]
struct Inner {
    /// key → when it was first seen.
    seen: HashMap<(String, String), Instant>,
}

impl RecentlySeen {
    #[must_use]
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            inner: std::sync::Mutex::new(Inner {
                seen: HashMap::new(),
            }),
            ttl,
            max_entries,
        }
    }

    /// Record `(scope, id)` and report whether it is new. `false` means
    /// "already handled — drop it", which is what terminates
    /// propagation loops and collapses claim floods.
    pub fn check_and_record(&self, scope: &str, id: &str) -> bool {
        let now = Instant::now();
        let mut guard = self.inner.lock().expect("recently-seen mutex poisoned");
        // Drop expired entries first so a steady trickle keeps the map
        // small without a background task.
        guard
            .seen
            .retain(|_, first| now.duration_since(*first) < self.ttl);
        if guard.seen.len() >= self.max_entries {
            // Evict the oldest so a flood of distinct ids can't grow the
            // map without bound.
            if let Some(oldest) = guard
                .seen
                .iter()
                .min_by_key(|(_, first)| **first)
                .map(|(k, _)| k.clone())
            {
                guard.seen.remove(&oldest);
            }
        }
        guard
            .seen
            .insert((scope.to_string(), id.to_string()), now)
            .is_none()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .expect("recently-seen mutex poisoned")
            .seen
            .len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_repeats_and_scopes_separately() {
        let seen = RecentlySeen::new(Duration::from_mins(1), 8);
        // First delivery is handled; a second by another mesh path isn't.
        assert!(seen.check_and_record("op", "req-1"), "first is new");
        assert!(!seen.check_and_record("op", "req-1"), "repeat is dropped");
        // A different id in the same scope is still new.
        assert!(seen.check_and_record("op", "req-2"));
        // Same id in a *different* scope is a distinct thing.
        assert!(seen.check_and_record("op2", "req-1"));
    }

    #[test]
    fn evicts_when_full() {
        // A flood of distinct ids must not grow the map without bound.
        let seen = RecentlySeen::new(Duration::from_mins(1), 4);
        for i in 0..50 {
            seen.check_and_record("op", &format!("req-{i}"));
        }
        assert!(seen.len() <= 4, "capped, got {}", seen.len());
    }

    #[test]
    fn forgets_after_ttl() {
        let seen = RecentlySeen::new(Duration::from_millis(50), 8);
        assert!(seen.check_and_record("op", "req"));
        std::thread::sleep(Duration::from_millis(80));
        // After the TTL the same key is legitimately new again — an
        // operator can re-push a rule, and a connection that recurs an
        // hour later deserves to be asked about again.
        assert!(
            seen.check_and_record("op", "req"),
            "expired entry is new again"
        );
    }
}
