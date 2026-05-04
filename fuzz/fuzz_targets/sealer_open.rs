//! Fuzz `Verifier::open` against arbitrary inbound bytes.
//!
//! Combines envelope decode + signature verification + replay/skew
//! gating. The verifier holds the resolver (a single random pubkey
//! the fuzzer can never produce a signature for) so success is
//! impossible by construction — we only assert the function never
//! panics.
//!
//! Run: `cargo +nightly fuzz run sealer_open`
#![no_main]

use std::sync::OnceLock;

use bowery_crypto::Identity;
use bowery_whisper::{StaticResolver, Verifier};
use libfuzzer_sys::fuzz_target;

static VERIFIER: OnceLock<Verifier<StaticResolver>> = OnceLock::new();

fn verifier() -> &'static Verifier<StaticResolver> {
    VERIFIER.get_or_init(|| {
        let identity = Identity::generate();
        let mut resolver = StaticResolver::new();
        resolver.insert(identity.verifying_key());
        Verifier::new(resolver)
    })
}

fuzz_target!(|data: &[u8]| {
    let _ = verifier().open(data);
});
