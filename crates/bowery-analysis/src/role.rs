//! Self-learned role vector.
//!
//! Phase 3 derives a fixed-length role vector from the local baseline
//! using purely deterministic operations (no LLM dependency, see
//! [DESIGN.md §8.7](../../DESIGN.md)). The pipeline is:
//!
//! 1. Walk the baseline and bin observed binaries by path-prefix taxonomy
//!    (8 buckets covering distro paths, container runtimes, user dirs,
//!    writable temp dirs, etc.). The result is a normalised
//!    [`RoleFeatures`] vector.
//! 2. Project the 8-dim feature vector into a 32-dim signature using a
//!    seeded sparse-random projection with a fixed seed shared across
//!    the fleet. This gives every node a comparable embedding without
//!    leaking the raw histogram.
//!
//! Other nodes consume the vector via the chitchat KV layer; the
//! consumer ranks neighbors by cosine similarity to its own vector and
//! prefers similar peers when whispering.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bowery_baseline::Baseline;
use serde::Serialize;

/// Number of feature buckets emitted by [`RoleFeatures::from_baseline`].
pub const ROLE_FEATURE_DIMS: usize = 8;

/// Number of dimensions in the projected [`RoleVector`] published on the
/// mesh. Tuned so the vector fits in a small KV value (32 × 4 B = 128 B).
pub const ROLE_VECTOR_DIMS: usize = 32;

/// Fleet-wide fixed seed for the random projection. Every node uses the
/// same matrix so vectors are comparable. Bumping this constant rotates
/// the projection (forces a fleet-wide recomputation, intentional).
pub const ROLE_PROJECTION_SEED: u64 = 0xB05E_0000_0001_0001;

/// Static taxonomy of path-prefix buckets. Order matters: it defines the
/// indexing of [`RoleFeatures`].
const PATH_BUCKETS: [&str; ROLE_FEATURE_DIMS] = [
    "/usr/bin/",       // 0: distro userland
    "/usr/local/bin/", // 1: locally-installed userland
    "/usr/sbin/",      // 2: distro sysadmin
    "/opt/",           // 3: third-party packages
    "/home/",          // 4: user homedirs
    "/tmp/",           // 5: writable temp (also covers /var/tmp/, /dev/shm/)
    "/var/lib/",       // 6: stateful service dirs
    "/proc/",          // 7: kernel / ephemeral
];

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RoleFeatures {
    pub dims: [f32; ROLE_FEATURE_DIMS],
    pub binary_count: u64,
}

impl RoleFeatures {
    /// Compute the local feature vector from the baseline. Bucket counts
    /// are normalised to sum to 1.0; the absolute total is preserved
    /// separately so a host with 3 binaries doesn't look identical to one
    /// with 3 000.
    pub fn from_baseline(baseline: &Baseline) -> Result<Self, bowery_baseline::Error> {
        // Phase 3 limited surface: we don't have per-binary path stored
        // in the baseline yet (only sha256). This is intentionally a
        // placeholder that returns a uniform vector when any binaries
        // exist. Phase 2-BPF will populate per-binary path metadata, at
        // which point we replace this with a real histogram.
        let total = baseline.count_binaries()?;
        let mut dims = [0.0_f32; ROLE_FEATURE_DIMS];
        if total == 0 {
            return Ok(Self {
                dims,
                binary_count: 0,
            });
        }
        #[allow(clippy::cast_precision_loss)] // ROLE_FEATURE_DIMS is a tiny constant
        let share = 1.0 / (ROLE_FEATURE_DIMS as f32);
        dims.fill(share);
        Ok(Self {
            dims,
            binary_count: total,
        })
    }

    /// Manually-constructed features (mostly for tests).
    #[must_use]
    pub fn with_dims(dims: [f32; ROLE_FEATURE_DIMS], binary_count: u64) -> Self {
        Self { dims, binary_count }
    }

    /// Index of a path bucket, if any.
    #[must_use]
    pub fn bucket_for_path(path: &str) -> Option<usize> {
        if path.starts_with("/var/tmp/") || path.starts_with("/dev/shm/") {
            return Some(5);
        }
        for (i, prefix) in PATH_BUCKETS.iter().enumerate() {
            if path.starts_with(prefix) {
                return Some(i);
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Projection
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RoleVector {
    pub dims: [f32; ROLE_VECTOR_DIMS],
    pub binary_count: u64,
}

impl RoleVector {
    /// Project [`RoleFeatures`] into a 32-dim role vector.
    pub fn from_features(features: &RoleFeatures) -> Self {
        let matrix = projection_matrix(ROLE_PROJECTION_SEED);
        let mut dims = [0.0_f32; ROLE_VECTOR_DIMS];
        for (j, dim) in dims.iter_mut().enumerate() {
            let mut sum = 0.0_f32;
            for (i, &f) in features.dims.iter().enumerate() {
                sum += f * matrix[i * ROLE_VECTOR_DIMS + j];
            }
            *dim = sum;
        }
        Self {
            dims,
            binary_count: features.binary_count,
        }
    }

    /// Encode for transmission via mesh KV. 4 bytes per dim, little-endian,
    /// followed by 8 bytes of `binary_count`, the whole thing base64'd.
    #[must_use]
    pub fn to_base64(&self) -> String {
        let mut bytes = [0u8; ROLE_VECTOR_DIMS * 4 + 8];
        for (i, v) in self.dims.iter().enumerate() {
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&v.to_le_bytes());
        }
        let count_offset = ROLE_VECTOR_DIMS * 4;
        bytes[count_offset..count_offset + 8].copy_from_slice(&self.binary_count.to_le_bytes());
        BASE64.encode(bytes)
    }

    /// Inverse of [`Self::to_base64`].
    pub fn from_base64(s: &str) -> Option<Self> {
        let bytes = BASE64.decode(s.as_bytes()).ok()?;
        if bytes.len() != ROLE_VECTOR_DIMS * 4 + 8 {
            return None;
        }
        let mut dims = [0.0_f32; ROLE_VECTOR_DIMS];
        for (i, dim) in dims.iter_mut().enumerate() {
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
            *dim = f32::from_le_bytes(buf);
        }
        let mut count_buf = [0u8; 8];
        let count_offset = ROLE_VECTOR_DIMS * 4;
        count_buf.copy_from_slice(&bytes[count_offset..count_offset + 8]);
        Some(Self {
            dims,
            binary_count: u64::from_le_bytes(count_buf),
        })
    }

    /// Cosine similarity in `[-1, 1]`, defined as 0 when either vector is
    /// the zero vector.
    #[must_use]
    pub fn cosine_similarity(&self, other: &Self) -> f32 {
        let dot: f32 = self
            .dims
            .iter()
            .zip(other.dims.iter())
            .map(|(a, b)| a * b)
            .sum();
        let na: f32 = self.dims.iter().map(|a| a * a).sum::<f32>().sqrt();
        let nb: f32 = other.dims.iter().map(|a| a * a).sum::<f32>().sqrt();
        if na == 0.0 || nb == 0.0 {
            0.0
        } else {
            dot / (na * nb)
        }
    }
}

/// Build the deterministic projection matrix for a given seed.
///
/// 8 (features) × 32 (vector) entries, each in `{-√3, 0, +√3}` per
/// Achlioptas' sparse random projection (1/6, 2/3, 1/6 mass). Computed
/// from a SplitMix64-driven PRNG keyed by `seed` so every node produces
/// the same matrix for the same seed.
fn projection_matrix(seed: u64) -> [f32; ROLE_FEATURE_DIMS * ROLE_VECTOR_DIMS] {
    let mut m = [0.0_f32; ROLE_FEATURE_DIMS * ROLE_VECTOR_DIMS];
    let mut state = seed;
    let scale = (3.0_f32).sqrt();
    for entry in &mut m {
        let bits = splitmix64(&mut state);
        // Map u64 to [0, 1) via the high 53 bits, which is exactly
        // representable in an f64 mantissa.
        #[allow(clippy::cast_precision_loss)]
        let r = ((bits >> 11) as f64) / ((1u64 << 53) as f64);
        *entry = if r < 1.0 / 6.0 {
            -scale
        } else if r < 5.0 / 6.0 {
            0.0
        } else {
            scale
        };
    }
    m
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[cfg(test)]
#[allow(clippy::float_cmp)] // intentional exact comparisons over deterministic projection / bit-preserving roundtrips
mod tests {
    use super::*;

    #[test]
    fn projection_matrix_is_seed_stable() {
        let m1 = projection_matrix(ROLE_PROJECTION_SEED);
        let m2 = projection_matrix(ROLE_PROJECTION_SEED);
        assert_eq!(m1, m2);
    }

    #[test]
    fn different_seeds_yield_different_matrices() {
        let m1 = projection_matrix(ROLE_PROJECTION_SEED);
        let m2 = projection_matrix(ROLE_PROJECTION_SEED.wrapping_add(1));
        assert_ne!(m1, m2);
    }

    #[test]
    fn role_vector_base64_roundtrip() {
        let features = RoleFeatures::with_dims([0.1, 0.2, 0.0, 0.3, 0.0, 0.4, 0.0, 0.0], 17);
        let vec = RoleVector::from_features(&features);
        let encoded = vec.to_base64();
        let decoded = RoleVector::from_base64(&encoded).expect("roundtrip");
        assert_eq!(vec, decoded);
    }

    #[test]
    fn cosine_similarity_self_is_one_for_nonzero() {
        let features = RoleFeatures::with_dims([0.1, 0.2, 0.0, 0.3, 0.0, 0.4, 0.0, 0.0], 17);
        let vec = RoleVector::from_features(&features);
        let sim = vec.cosine_similarity(&vec);
        assert!((sim - 1.0).abs() < 1e-5, "self similarity {sim}");
    }

    #[test]
    fn cosine_similarity_zero_vectors_is_zero() {
        let zero = RoleVector::from_features(&RoleFeatures::with_dims([0.0; ROLE_FEATURE_DIMS], 0));
        let other = zero.clone();
        assert_eq!(zero.cosine_similarity(&other), 0.0);
    }

    #[test]
    fn from_baseline_handles_empty_baseline() {
        let baseline = Baseline::open_in_memory().unwrap();
        let f = RoleFeatures::from_baseline(&baseline).unwrap();
        assert_eq!(f.binary_count, 0);
        assert_eq!(f.dims.iter().sum::<f32>(), 0.0);
    }

    #[test]
    fn from_baseline_after_inserts_has_unit_sum() {
        let baseline = Baseline::open_in_memory().unwrap();
        baseline.upsert_binary(&[1; 32]).unwrap();
        baseline.upsert_binary(&[2; 32]).unwrap();
        let f = RoleFeatures::from_baseline(&baseline).unwrap();
        assert_eq!(f.binary_count, 2);
        let sum: f32 = f.dims.iter().sum();
        assert!((sum - 1.0).abs() < 1e-5, "feature sum {sum}");
    }

    #[test]
    fn bucket_for_path_recognises_writable_dirs() {
        assert_eq!(RoleFeatures::bucket_for_path("/tmp/x"), Some(5));
        assert_eq!(RoleFeatures::bucket_for_path("/var/tmp/x"), Some(5));
        assert_eq!(RoleFeatures::bucket_for_path("/dev/shm/x"), Some(5));
    }

    #[test]
    fn bucket_for_path_recognises_distro_dirs() {
        assert_eq!(RoleFeatures::bucket_for_path("/usr/bin/curl"), Some(0));
        assert_eq!(RoleFeatures::bucket_for_path("/usr/sbin/sshd"), Some(2));
        assert_eq!(RoleFeatures::bucket_for_path("/opt/foo/bar"), Some(3));
    }

    #[test]
    fn bucket_for_path_unknown_returns_none() {
        assert_eq!(RoleFeatures::bucket_for_path("/random/path"), None);
    }
}
