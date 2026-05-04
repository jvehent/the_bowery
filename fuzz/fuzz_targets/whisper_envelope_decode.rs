//! Fuzz the prost decoder for `WhisperEnvelope`.
//!
//! Hot path: every inbound QUIC stream calls `WhisperEnvelope::decode`
//! on a length-prefixed frame from the network. A malformed frame
//! must not panic, OOM, or recurse without bound — failure mode is
//! always `Err`.
//!
//! Run: `cargo +nightly fuzz run whisper_envelope_decode`
#![no_main]

use bowery_proto::WhisperEnvelope;
use libfuzzer_sys::fuzz_target;
use prost::Message;

fuzz_target!(|data: &[u8]| {
    // Decoding must never panic. Errors are fine; we expect lots.
    let _ = WhisperEnvelope::decode(data);
});
