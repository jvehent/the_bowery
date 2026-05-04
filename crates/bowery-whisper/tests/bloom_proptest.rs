//! Phase-8 slice 3: properties of the Tier-1 `BloomFilter`.
//!
//! The asker-side optimisation (skip a peer's QA dial when its
//! published advert says "I haven't seen this") only stays correct
//! if the filter never returns `false` for an inserted fingerprint.
//! These properties beat that contract against random input shapes
//! the unit tests don't enumerate.
//!
//! Invariants checked:
//!
//! 1. **No false negatives**: every inserted fingerprint must
//!    `contains()` true afterwards.
//! 2. **Merge preserves no-FN**: after `a.merge(&b)`, every fp ever
//!    inserted into either `a` or `b` is still `contains()`.
//! 3. **Empty-filter never falsely contains**: a fresh filter
//!    returns `false` for any query at default parameters (this is
//!    a no-FP property, not a no-FN; serves as a baseline sanity
//!    check on the index function).

use bowery_whisper::{BloomFilter, Tier1Fingerprint};
use proptest::collection::vec;
use proptest::prelude::*;

/// Generate a random tier-1 fingerprint.
fn arb_tier1() -> impl Strategy<Value = Tier1Fingerprint> {
    any::<[u8; 8]>().prop_map(Tier1Fingerprint::from_bytes)
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    /// Insertion never triggers a false-negative.
    #[test]
    fn inserted_fingerprints_always_contained(
        fps in vec(arb_tier1(), 1..200),
    ) {
        let mut bloom = BloomFilter::with_defaults();
        for fp in &fps {
            bloom.insert(*fp);
        }
        for fp in &fps {
            prop_assert!(
                bloom.contains(*fp),
                "false negative: inserted fp {:?} is not contained",
                fp.as_bytes()
            );
        }
    }

    /// Merge is OR over the bit arrays, so it can only ADD bits.
    /// Every fp ever inserted into either operand must remain
    /// contained.
    #[test]
    fn merge_preserves_no_false_negatives(
        a_fps in vec(arb_tier1(), 1..50),
        b_fps in vec(arb_tier1(), 1..50),
    ) {
        let mut a = BloomFilter::with_defaults();
        let mut b = BloomFilter::with_defaults();
        for fp in &a_fps {
            a.insert(*fp);
        }
        for fp in &b_fps {
            b.insert(*fp);
        }
        a.merge(&b).unwrap();
        for fp in &a_fps {
            prop_assert!(a.contains(*fp), "merged filter lost A's fp {:?}", fp.as_bytes());
        }
        for fp in &b_fps {
            prop_assert!(a.contains(*fp), "merged filter lost B's fp {:?}", fp.as_bytes());
        }
    }

    /// A fresh filter has no bits set; `contains` must return false
    /// for every input. This is a no-false-POSITIVE property and
    /// catches index-function bugs that wrap to bit 0.
    #[test]
    fn empty_filter_never_contains(fp in arb_tier1()) {
        let bloom = BloomFilter::with_defaults();
        prop_assert!(
            !bloom.contains(fp),
            "fresh filter falsely contained {:?}",
            fp.as_bytes()
        );
    }
}
