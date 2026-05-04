//! Phase-5 bloom-advert publisher.
//!
//! Periodically scans the local baseline, derives a tier-1 fingerprint
//! for every binary, builds a [`BloomFilter`], encodes it as a
//! [`bowery_proto::BloomAdvert`] message, base64s the result, and
//! publishes it under [`KEY_BLOOM_ADVERT`] in the mesh KV.
//!
//! Peers consume the advert when ranking whisper-Q&A candidates: an
//! advert that doesn't `contain` the asker's tier-1 is a definitive
//! "no" (modulo bloom false positives, which run at ~1 % at default
//! params). That lets askers skip dials that wouldn't have produced
//! useful answers anyway.
//!
//! Epoch handling: the advert carries an `epoch` field that receivers
//! use to discard stale data. We seed the in-memory counter with
//! `wall_clock_secs` at startup so it remains monotonic across agent
//! restarts; subsequent ticks bump by 1 each publish.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bowery_baseline::Baseline;
use bowery_mesh::{KEY_BLOOM_ADVERT, Mesh};
use bowery_proto::BloomAdvert;
use bowery_whisper::fingerprint::{BloomFilter, Tier1Fingerprint};
use prost::Message as _;
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::agent::AgentEvent;
use crate::config::BloomConfig;

#[allow(clippy::too_many_arguments)] // explicit wiring at the call site
pub(crate) fn spawn_bloom_publisher_task(
    mesh: Arc<Mesh>,
    baseline: Arc<Baseline>,
    cfg: BloomConfig,
    events_tx: broadcast::Sender<AgentEvent>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    let initial_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map_or(1, |d| d.as_secs());
    let epoch = Arc::new(AtomicU64::new(initial_epoch));

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(cfg.publish_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // First tick fires immediately — publish on startup so peers
        // see this agent's advert without waiting for a full cycle.
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Err(e) = publish_one(
                        mesh.as_ref(),
                        baseline.as_ref(),
                        &cfg,
                        epoch.fetch_add(1, Ordering::Relaxed),
                        &events_tx,
                    )
                    .await {
                        warn!(error = %e, "bloom advert publish failed");
                    }
                }
                _ = shutdown_rx.changed() => break,
            }
        }
    })
}

async fn publish_one(
    mesh: &Mesh,
    baseline: &Baseline,
    cfg: &BloomConfig,
    epoch: u64,
    events_tx: &broadcast::Sender<AgentEvent>,
) -> Result<(), PublishError> {
    // Build the filter on the current task. The publisher runs at low
    // frequency (default 60s) and a single scan is well under 10ms at
    // fleet-realistic sizes (10k binaries), so the cost of a
    // spawn_blocking handoff would dominate. If this ever shows up in
    // a flame graph we'll wrap the scan in spawn_blocking.
    let mut filter = BloomFilter::new(cfg.bit_count, cfg.k).map_err(PublishError::Bloom)?;
    let mut inserted: u64 = 0;
    baseline
        .for_each_binary(|rec| {
            filter.insert(Tier1Fingerprint::derive(&rec.sha256));
            inserted += 1;
        })
        .map_err(PublishError::Baseline)?;

    let bit_count = u32::try_from(filter.bit_count()).map_err(|_| PublishError::SizeOverflow)?;
    let advert = BloomAdvert {
        epoch,
        bit_count,
        k: u32::from(filter.k()),
        bits: filter.as_bytes().to_vec(),
    };
    let bytes = advert.encode_to_vec();
    let encoded = BASE64.encode(&bytes);

    mesh.set_state(KEY_BLOOM_ADVERT, encoded)
        .await
        .map_err(PublishError::Mesh)?;

    debug!(
        epoch,
        inserted,
        bit_count = filter.bit_count(),
        k = filter.k(),
        "published bloom advert"
    );

    let _ = events_tx.send(AgentEvent::BloomAdvertPublished {
        epoch,
        bit_count: filter.bit_count(),
        k: filter.k(),
        inserted_count: inserted,
    });

    Ok(())
}

#[derive(Debug, thiserror::Error)]
enum PublishError {
    #[error("bloom: {0}")]
    Bloom(bowery_whisper::fingerprint::BloomError),
    #[error("baseline scan: {0}")]
    Baseline(bowery_baseline::Error),
    #[error("bit_count exceeds u32 range")]
    SizeOverflow,
    #[error("mesh: {0}")]
    Mesh(bowery_mesh::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A round-trip of the encode path: build a filter, populate it
    /// from a baseline, encode as `BloomAdvert`, base64 it, decode it
    /// back, and confirm membership invariants. This is what the
    /// publisher does over the wire (minus the mesh push).
    #[test]
    fn encode_decode_roundtrip_preserves_membership() {
        let baseline = Baseline::open_in_memory().unwrap();
        let sha_a = [11u8; 32];
        let sha_b = [22u8; 32];
        baseline.upsert_binary(&sha_a).unwrap();
        baseline.upsert_binary(&sha_b).unwrap();

        let mut filter = BloomFilter::new(1024, 6).unwrap();
        baseline
            .for_each_binary(|rec| {
                filter.insert(Tier1Fingerprint::derive(&rec.sha256));
            })
            .unwrap();

        let advert = BloomAdvert {
            epoch: 7,
            bit_count: u32::try_from(filter.bit_count()).unwrap(),
            k: u32::from(filter.k()),
            bits: filter.as_bytes().to_vec(),
        };
        let bytes = advert.encode_to_vec();
        let encoded = BASE64.encode(&bytes);

        // Receiver-side decode (what a peer would do):
        let raw = BASE64.decode(encoded.as_bytes()).unwrap();
        let decoded = BloomAdvert::decode(raw.as_slice()).unwrap();
        assert_eq!(decoded.epoch, 7);
        assert_eq!(decoded.k, 6);

        let recovered = BloomFilter::from_bytes(
            decoded.bits,
            decoded.bit_count as usize,
            u8::try_from(decoded.k).unwrap(),
        )
        .unwrap();
        assert!(recovered.contains(Tier1Fingerprint::derive(&sha_a)));
        assert!(recovered.contains(Tier1Fingerprint::derive(&sha_b)));
        // Spot-check a non-member.
        assert!(!recovered.contains(Tier1Fingerprint::derive(b"never inserted")));
    }
}
