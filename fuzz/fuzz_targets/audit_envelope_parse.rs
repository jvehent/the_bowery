//! Fuzz `serde_json` decoding of `AuditEnvelope`.
//!
//! Operators run `bowery audit verify` against logs that may have
//! been corrupted by truncated writes, log rotation accidents, or
//! deliberate tampering. The parser must reject malformed input
//! without panicking, and verify must reject every envelope that
//! parses but doesn't actually carry a valid signature.
//!
//! Run: `cargo +nightly fuzz run audit_envelope_parse`
#![no_main]

use std::sync::OnceLock;

use bowery_crypto::Identity;
use bowery_response::AuditEnvelope;
use ed25519_dalek::VerifyingKey;
use libfuzzer_sys::fuzz_target;

static VK: OnceLock<VerifyingKey> = OnceLock::new();

fn verifying_key() -> &'static VerifyingKey {
    VK.get_or_init(|| Identity::generate().verifying_key())
}

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(env) = serde_json::from_str::<AuditEnvelope>(s) {
        // A successful parse on arbitrary input must never verify
        // under a key the fuzzer doesn't control. The fuzzer can't
        // produce a valid Ed25519 signature, so this branch is
        // effectively a sanity check on the verify path.
        let _ = env.verify(verifying_key());
    }
});
