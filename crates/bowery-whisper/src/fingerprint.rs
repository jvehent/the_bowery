//! Two-tier privacy fingerprints for the whispering protocol.
//!
//! The whispering protocol exchanges hints about *what each agent has
//! seen* without leaking the underlying hashes to anyone who hasn't
//! already observed the same artifact. We do that with two tiers:
//!
//! - **Tier-1** — a 64-bit truncation of `SHA256(domain || full_sha256)`.
//!   Coarse enough to permit collisions (~1 in 2^64), so seeing a
//!   tier-1 fingerprint in a peer's bloom advert tells you only that
//!   they've observed *something* that hashes to the same 8 bytes.
//!   Cheap to gossip in bulk via [`BloomFilter`].
//!
//! - **Tier-2** — the original 32-byte sha256. Released only inside an
//!   end-to-end-encrypted whisper capsule, after both sides have agreed
//!   that the tier-1 hint is worth following up on.
//!
//! This module owns the tier-1 derivation and the bloom filter; tier-2
//! is just `[u8; 32]` and travels through the existing [`crate::envelope`]
//! sealing.
//!
//! Domain separation prevents the tier-1 hash from being confused with
//! any other 64-bit hash floating around the codebase (mesh KV keys,
//! HMAC outputs, etc.). [`TIER1_DOMAIN`] is the canonical prefix.

use sha2::{Digest, Sha256};
use thiserror::Error;

/// Domain separator for tier-1 fingerprint derivation. Hashing
/// `domain || sha256` instead of `sha256` directly stops anyone who
/// knows a hash from being able to recognise it inside our protocol
/// without also knowing the domain string.
pub const TIER1_DOMAIN: &[u8] = b"bowery/whisper/tier1/v1";

/// Width of a tier-1 fingerprint in bytes.
pub const TIER1_LEN: usize = 8;

/// 64-bit Tier-1 fingerprint derived from a full sha256.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct Tier1Fingerprint(pub [u8; TIER1_LEN]);

impl Tier1Fingerprint {
    /// Derive a tier-1 fingerprint from a tier-2 sha256 input. The
    /// input is typically `enrich::sha256_file` of a binary, but the
    /// function is generic over byte slices so callers can apply the
    /// same scheme to network endpoints, file paths, etc.
    pub fn derive(tier2: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(TIER1_DOMAIN);
        hasher.update(tier2);
        let digest = hasher.finalize();
        let mut out = [0u8; TIER1_LEN];
        out.copy_from_slice(&digest[..TIER1_LEN]);
        Self(out)
    }

    /// Construct directly from raw bytes (e.g. when received from a
    /// peer over the wire).
    pub fn from_bytes(bytes: [u8; TIER1_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; TIER1_LEN] {
        &self.0
    }

    /// 64-bit numeric view, used to drive bloom-filter bit positions.
    pub fn as_u64(&self) -> u64 {
        u64::from_be_bytes(self.0)
    }
}

impl std::fmt::Display for Tier1Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Bloom filter
// ---------------------------------------------------------------------------

/// Default filter size (in bits). 65 536 bits = 8 KiB on the wire,
/// which gives us roughly 1 % false-positive rate at ~6 800 inserted
/// items with k=6 — plenty of headroom for a single host's binary set.
pub const DEFAULT_BIT_COUNT: usize = 64 * 1024;

/// Default number of hash positions per insert. Tuned alongside
/// [`DEFAULT_BIT_COUNT`] for the same target FP rate.
pub const DEFAULT_K: u8 = 6;

/// Hard cap on filter size in bits. 256 KiB; anything larger is almost
/// certainly a malformed advert, and we want to bound memory either way.
pub const MAX_BIT_COUNT: usize = 256 * 1024 * 8;

/// Minimum sensible hash count. Using 0 would make `contains` return
/// `true` for everything, which would be a worse footgun than rejecting.
pub const MIN_K: u8 = 1;

/// Maximum hash count. 32 is far more than any reasonable
/// {fp-rate, capacity} target needs and keeps `insert` work bounded.
pub const MAX_K: u8 = 32;

#[derive(Debug, Error)]
pub enum BloomError {
    #[error("filter bit_count {0} is not a multiple of 8 (we serialise byte-aligned)")]
    NotByteAligned(usize),

    #[error("filter bit_count {got} exceeds cap {MAX_BIT_COUNT}")]
    TooLarge { got: usize },

    #[error("filter bit_count must be > 0")]
    Empty,

    #[error("k = {0} outside allowed range [{MIN_K}, {MAX_K}]")]
    BadK(u8),

    #[error("byte buffer length {got} doesn't match bit_count {expected_bits} (expected {expected_bytes} bytes)")]
    LengthMismatch {
        got: usize,
        expected_bits: usize,
        expected_bytes: usize,
    },
}

/// A counting-free bloom filter over Tier-1 fingerprints.
///
/// Indices are derived via the standard double-hashing trick: from a
/// single 64-bit input `h`, we treat the high 32 bits as `h1` and the
/// low 32 bits as `h2`, then index `(h1 + i*h2) mod bit_count` for
/// `i` in `0..k`. With `k=6` and `bit_count=2^16` this is uniform enough
/// for our fp-rate target, and crucially needs no extra hashing per insert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BloomFilter {
    bits: Vec<u8>,
    bit_count: usize,
    k: u8,
}

impl BloomFilter {
    /// Create an empty filter. `bit_count` must be a positive multiple
    /// of 8 (we serialise byte-aligned) and within [`MAX_BIT_COUNT`].
    pub fn new(bit_count: usize, k: u8) -> Result<Self, BloomError> {
        Self::validate_params(bit_count, k)?;
        Ok(Self {
            bits: vec![0u8; bit_count / 8],
            bit_count,
            k,
        })
    }

    /// Build with the recommended defaults.
    pub fn with_defaults() -> Self {
        // unwrap is safe: defaults satisfy validate_params by construction.
        Self::new(DEFAULT_BIT_COUNT, DEFAULT_K).expect("default bloom params validate")
    }

    /// Wrap an existing byte buffer (e.g. one received over the wire).
    pub fn from_bytes(bytes: Vec<u8>, bit_count: usize, k: u8) -> Result<Self, BloomError> {
        Self::validate_params(bit_count, k)?;
        let expected_bytes = bit_count / 8;
        if bytes.len() != expected_bytes {
            return Err(BloomError::LengthMismatch {
                got: bytes.len(),
                expected_bits: bit_count,
                expected_bytes,
            });
        }
        Ok(Self {
            bits: bytes,
            bit_count,
            k,
        })
    }

    fn validate_params(bit_count: usize, k: u8) -> Result<(), BloomError> {
        if bit_count == 0 {
            return Err(BloomError::Empty);
        }
        if !bit_count.is_multiple_of(8) {
            return Err(BloomError::NotByteAligned(bit_count));
        }
        if bit_count > MAX_BIT_COUNT {
            return Err(BloomError::TooLarge { got: bit_count });
        }
        if !(MIN_K..=MAX_K).contains(&k) {
            return Err(BloomError::BadK(k));
        }
        Ok(())
    }

    pub fn bit_count(&self) -> usize {
        self.bit_count
    }

    pub fn k(&self) -> u8 {
        self.k
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bits
    }

    /// Add a Tier-1 fingerprint to the filter.
    pub fn insert(&mut self, fp: Tier1Fingerprint) {
        for idx in indices(fp, self.bit_count, self.k) {
            let byte = idx / 8;
            let bit = idx % 8;
            self.bits[byte] |= 1u8 << bit;
        }
    }

    /// Test whether a Tier-1 fingerprint *might* be in the filter.
    /// Returns `false` only if the fingerprint definitely has not been
    /// inserted; `true` may be a false positive (~1 % at default
    /// parameters).
    pub fn contains(&self, fp: Tier1Fingerprint) -> bool {
        indices(fp, self.bit_count, self.k).all(|idx| {
            let byte = idx / 8;
            let bit = idx % 8;
            self.bits[byte] & (1u8 << bit) != 0
        })
    }

    /// OR-merge `other` into `self`. Useful for aggregating per-peer
    /// adverts into a neighbourhood view, or for older filters that get
    /// rolled forward into a newer epoch's filter.
    pub fn merge(&mut self, other: &Self) -> Result<(), BloomError> {
        if self.bit_count != other.bit_count {
            return Err(BloomError::LengthMismatch {
                got: other.bit_count,
                expected_bits: self.bit_count,
                expected_bytes: self.bits.len(),
            });
        }
        if self.k != other.k {
            return Err(BloomError::BadK(other.k));
        }
        for (a, b) in self.bits.iter_mut().zip(other.bits.iter()) {
            *a |= *b;
        }
        Ok(())
    }

    /// Estimated number of distinct insertions, via the standard
    /// inverse-occupancy formula: `n ≈ -(m/k) * ln(1 - x/m)` where `x`
    /// is the population count. Useful for sanity-checking that a peer
    /// hasn't sent a maliciously dense filter.
    #[allow(clippy::cast_precision_loss)] // bit_count ≤ MAX_BIT_COUNT (2 097 152) << 2^53; popcount fits in u32 << 2^53
    pub fn estimated_cardinality(&self) -> f64 {
        let m = self.bit_count as f64;
        let k = f64::from(self.k);
        let x = f64::from(self.popcount());
        if x >= m {
            return f64::INFINITY;
        }
        -(m / k) * (1.0 - x / m).ln()
    }

    fn popcount(&self) -> u32 {
        self.bits.iter().map(|b| b.count_ones()).sum()
    }
}

/// `k` bit positions for `fp`, derived via double hashing. Free
/// function (rather than a method) so callers can hold a `&mut` to the
/// bits without conflicting with the iterator's borrow.
#[allow(clippy::cast_possible_truncation)] // bit_count ≤ MAX_BIT_COUNT (≪ usize::MAX); modulo bound makes the cast safe
fn indices(fp: Tier1Fingerprint, bit_count: usize, k: u8) -> impl Iterator<Item = usize> {
    let h = fp.as_u64();
    let h1 = (h >> 32) as u32;
    let h2 = (h & 0xFFFF_FFFF) as u32;
    let bit_count = bit_count as u64;
    (0..k).map(move |i| {
        let i = u64::from(i);
        let combined = u64::from(h1).wrapping_add(i.wrapping_mul(u64::from(h2)));
        (combined % bit_count) as usize
    })
}

#[cfg(test)]
#[allow(clippy::float_cmp)] // exact comparisons against constructed fixtures
mod tests {
    use super::*;

    #[test]
    fn tier1_is_deterministic() {
        let a = Tier1Fingerprint::derive(b"hello");
        let b = Tier1Fingerprint::derive(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn tier1_changes_with_input() {
        let a = Tier1Fingerprint::derive(b"hello");
        let b = Tier1Fingerprint::derive(b"hello world");
        assert_ne!(a, b);
    }

    #[test]
    fn tier1_changes_with_domain() {
        // We can't actually swap the domain without forking the function,
        // but we can confirm domain bytes participate in the digest by
        // checking that the tier1 doesn't equal a plain truncated sha256.
        let plain: [u8; 32] = Sha256::digest(b"hello").into();
        let tier1 = Tier1Fingerprint::derive(b"hello");
        assert_ne!(tier1.as_bytes(), &plain[..TIER1_LEN]);
    }

    #[test]
    fn tier1_display_is_hex() {
        let fp = Tier1Fingerprint([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
        assert_eq!(fp.to_string(), "0123456789abcdef");
    }

    #[test]
    fn bloom_inserts_and_finds() {
        let mut bf = BloomFilter::with_defaults();
        let fp = Tier1Fingerprint::derive(b"sneaky-binary");
        assert!(!bf.contains(fp));
        bf.insert(fp);
        assert!(bf.contains(fp));
    }

    #[test]
    fn bloom_independent_inputs_dont_collide_at_default_size() {
        let mut bf = BloomFilter::with_defaults();
        let a = Tier1Fingerprint::derive(b"a");
        let b = Tier1Fingerprint::derive(b"b");
        bf.insert(a);
        // With default params, an unrelated single insertion shouldn't
        // happen to flip every one of `b`'s 6 bit positions. The
        // mathematical probability of a one-item false positive at
        // these parameters is ~(k/m)^k, which is vanishingly small.
        assert!(!bf.contains(b));
    }

    #[test]
    fn bloom_merge_unions_membership() {
        let mut a = BloomFilter::with_defaults();
        let mut b = BloomFilter::with_defaults();
        let alpha = Tier1Fingerprint::derive(b"alpha");
        let beta = Tier1Fingerprint::derive(b"beta");
        a.insert(alpha);
        b.insert(beta);
        a.merge(&b).unwrap();
        assert!(a.contains(alpha));
        assert!(a.contains(beta));
    }

    #[test]
    fn bloom_merge_rejects_mismatched_size() {
        let mut a = BloomFilter::new(1024, 6).unwrap();
        let b = BloomFilter::new(2048, 6).unwrap();
        assert!(matches!(a.merge(&b), Err(BloomError::LengthMismatch { .. })));
    }

    #[test]
    fn bloom_merge_rejects_mismatched_k() {
        let mut a = BloomFilter::new(1024, 6).unwrap();
        let b = BloomFilter::new(1024, 7).unwrap();
        assert!(matches!(a.merge(&b), Err(BloomError::BadK(7))));
    }

    #[test]
    fn bloom_rejects_zero_size() {
        assert!(matches!(BloomFilter::new(0, 6), Err(BloomError::Empty)));
    }

    #[test]
    fn bloom_rejects_unaligned_size() {
        assert!(matches!(
            BloomFilter::new(7, 6),
            Err(BloomError::NotByteAligned(7))
        ));
    }

    #[test]
    fn bloom_rejects_oversize() {
        assert!(matches!(
            BloomFilter::new(MAX_BIT_COUNT + 8, 6),
            Err(BloomError::TooLarge { .. })
        ));
    }

    #[test]
    fn bloom_rejects_zero_k() {
        assert!(matches!(BloomFilter::new(1024, 0), Err(BloomError::BadK(0))));
    }

    #[test]
    fn bloom_from_bytes_roundtrip() {
        let mut original = BloomFilter::with_defaults();
        for s in ["alpha", "beta", "gamma", "delta"] {
            original.insert(Tier1Fingerprint::derive(s.as_bytes()));
        }
        let bytes = original.as_bytes().to_vec();
        let recovered = BloomFilter::from_bytes(bytes, original.bit_count(), original.k()).unwrap();
        assert_eq!(original, recovered);
        for s in ["alpha", "beta", "gamma", "delta"] {
            assert!(recovered.contains(Tier1Fingerprint::derive(s.as_bytes())));
        }
    }

    #[test]
    fn bloom_from_bytes_rejects_length_mismatch() {
        let res = BloomFilter::from_bytes(vec![0u8; 100], DEFAULT_BIT_COUNT, DEFAULT_K);
        assert!(matches!(res, Err(BloomError::LengthMismatch { .. })));
    }

    #[test]
    fn bloom_estimated_cardinality_tracks_inserts() {
        let mut bf = BloomFilter::with_defaults();
        for i in 0..100u32 {
            bf.insert(Tier1Fingerprint::derive(&i.to_be_bytes()));
        }
        let est = bf.estimated_cardinality();
        // The estimator is approximate; allow a generous ±25 % band.
        assert!((75.0..=125.0).contains(&est), "estimate was {est}");
    }

    #[test]
    fn bloom_false_positive_rate_in_target_band() {
        // Insert 5 000 items into a default-sized filter (capacity is
        // ~6 800 at 1 % FP). Sample 50 000 unrelated queries; FP rate
        // should be well under 5 %.
        let mut bf = BloomFilter::with_defaults();
        for i in 0..5_000u32 {
            bf.insert(Tier1Fingerprint::derive(&i.to_be_bytes()));
        }
        let mut fps = 0;
        let trials = 50_000u32;
        for i in 1_000_000..(1_000_000 + trials) {
            if bf.contains(Tier1Fingerprint::derive(&i.to_be_bytes())) {
                fps += 1;
            }
        }
        let rate = f64::from(fps) / f64::from(trials);
        assert!(rate < 0.05, "FP rate {rate} above sanity ceiling");
    }
}
