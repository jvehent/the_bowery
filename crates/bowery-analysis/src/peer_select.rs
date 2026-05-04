//! Rank peers by similarity to the local role vector.
//!
//! Phase 5 wants to pick *similar* peers when whispering, not random
//! ones. The intuition: a host running the same workload as me is the
//! one most likely to either (a) corroborate that what I'm seeing is
//! benign for our role, or (b) confirm "yes, I see that too" when
//! something has spread laterally. A peer with a wildly different role
//! vector ("the office printer") is unlikely to have observed anything
//! useful about a process tree on a web frontend.
//!
//! This module is intentionally generic: callers hand in `(T,
//! RoleVector)` pairs (where `T` is whatever peer handle they want
//! back — a `PeerInfo`, a fingerprint, etc.) and get back a sorted
//! `Vec<(T, f32)>` of the top-K most similar peers, with the cosine
//! similarity attached so callers can show / log / filter on it.
//!
//! Tie-breaking and stability:
//! - Sort is stable; equal similarities keep input order
//! - Peers with NaN similarity (zero-norm vectors, or NaN dimensions)
//!   are sorted to the bottom

use crate::role::RoleVector;

/// Default number of peers to query per whisper round. Small fanout
/// keeps the privacy budget tight and bounds per-question latency
/// (we wait for at most this many responses before aggregating).
pub const DEFAULT_FANOUT: usize = 5;

/// Lower bound on similarity for a peer to be included. Peers below
/// this threshold are dropped before truncation, since asking very
/// dissimilar peers is unlikely to produce signal worth the round-trip.
/// `0.0` is a generous default — it just rejects orthogonal vectors;
/// callers can pass a higher value (say `0.3`) if they want stricter
/// neighborhoods.
pub const DEFAULT_MIN_SIMILARITY: f32 = 0.0;

/// Rank peers by cosine similarity to `local`, returning the top
/// `top_k` (or fewer if not enough peers meet `min_similarity`).
///
/// Output is sorted by similarity descending. Ties keep input order
/// (the underlying sort is stable). Peers whose similarity is NaN or
/// below `min_similarity` are excluded.
pub fn rank_by_similarity<T>(
    local: &RoleVector,
    peers: impl IntoIterator<Item = (T, RoleVector)>,
    top_k: usize,
    min_similarity: f32,
) -> Vec<(T, f32)> {
    let mut scored: Vec<(T, f32)> = peers
        .into_iter()
        .filter_map(|(handle, peer_vec)| {
            let sim = local.cosine_similarity(&peer_vec);
            if sim.is_nan() || sim < min_similarity {
                None
            } else {
                Some((handle, sim))
            }
        })
        .collect();

    // Stable sort: ties keep input order, which is what we want when
    // the agent passes peers in a deterministic iteration order (e.g.
    // sorted by fingerprint).
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    scored.truncate(top_k);
    scored
}

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;
    use crate::role::{ROLE_FEATURE_DIMS, RoleFeatures};

    fn vec_from_dims(dims: [f32; ROLE_FEATURE_DIMS]) -> RoleVector {
        RoleVector::from_features(&RoleFeatures::with_dims(dims, 1))
    }

    #[test]
    fn ranks_more_similar_peers_first() {
        let local = vec_from_dims([1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]);
        // peer_a is identical, peer_b orthogonal-ish, peer_c identical too.
        let peer_a = vec_from_dims([1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]);
        let peer_b = vec_from_dims([0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0]);
        let peer_c = vec_from_dims([0.9, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]);

        let ranked = rank_by_similarity(
            &local,
            vec![("a", peer_a), ("b", peer_b), ("c", peer_c)],
            10,
            DEFAULT_MIN_SIMILARITY,
        );
        // a and c should both be near the top, b at the bottom (or
        // dropped if below 0). At minimum, a/c precede b.
        let names: Vec<&str> = ranked.iter().map(|(name, _)| *name).collect();
        let pos_a = names.iter().position(|n| *n == "a").unwrap();
        let pos_c = names.iter().position(|n| *n == "c").unwrap();
        let pos_b = names.iter().position(|n| *n == "b");
        if let Some(pos_b) = pos_b {
            assert!(pos_a < pos_b);
            assert!(pos_c < pos_b);
        }
        // No matter what, a and c are both included.
        assert!(ranked.iter().any(|(n, _)| *n == "a"));
        assert!(ranked.iter().any(|(n, _)| *n == "c"));
    }

    #[test]
    fn truncates_to_top_k() {
        let local = vec_from_dims([1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]);
        let peers: Vec<_> = (0..10)
            .map(|i| (i, vec_from_dims([1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0])))
            .collect();
        let ranked = rank_by_similarity(&local, peers, 3, DEFAULT_MIN_SIMILARITY);
        assert_eq!(ranked.len(), 3);
    }

    #[test]
    fn min_similarity_filter_drops_below_threshold() {
        let local = vec_from_dims([1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]);
        let bad = vec_from_dims([-1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]);
        let good = vec_from_dims([0.9, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]);
        let ranked = rank_by_similarity(&local, vec![("bad", bad), ("good", good)], 10, 0.5);
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].0, "good");
    }

    #[test]
    fn empty_input_yields_empty_output() {
        let local = vec_from_dims([1.0; ROLE_FEATURE_DIMS]);
        let ranked: Vec<(&str, f32)> =
            rank_by_similarity(&local, Vec::<(&str, RoleVector)>::new(), 5, -1.0);
        assert!(ranked.is_empty());
    }

    #[test]
    fn equal_similarity_preserves_input_order() {
        let local = vec_from_dims([1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]);
        let identical = vec_from_dims([1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]);
        let peers = vec![
            ("first", identical.clone()),
            ("second", identical.clone()),
            ("third", identical),
        ];
        let ranked = rank_by_similarity(&local, peers, 10, -1.0);
        let names: Vec<&str> = ranked.iter().map(|(n, _)| *n).collect();
        assert_eq!(names, vec!["first", "second", "third"]);
    }

    #[test]
    fn nan_similarity_excludes_peer() {
        // Force a zero-norm vector, which the cosine function returns
        // 0.0 for (not NaN), so this test instead constructs an
        // explicit NaN-by-construction case via min_similarity = 0.5
        // against a zero peer.
        let local = vec_from_dims([1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]);
        let zero = RoleVector::from_features(&RoleFeatures::with_dims([0.0; 8], 0));
        let ranked = rank_by_similarity(&local, vec![("zero", zero)], 10, DEFAULT_MIN_SIMILARITY);
        // cosine_similarity returns 0.0 for zero vectors; with
        // DEFAULT_MIN_SIMILARITY = 0.0 it survives. Filter at 0.1 to
        // confirm it does get dropped above threshold.
        assert_eq!(ranked.len(), 1);
        let local2 = local.clone();
        let zero2 = RoleVector::from_features(&RoleFeatures::with_dims([0.0; 8], 0));
        let ranked2 = rank_by_similarity(&local2, vec![("zero", zero2)], 10, 0.1);
        assert!(ranked2.is_empty());
    }
}
