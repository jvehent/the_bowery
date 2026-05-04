# Phase-8 fuzz targets

Wire-format hot paths fuzzed with `cargo-fuzz`. This crate is its own
workspace so libfuzzer-sys doesn't infect the main dependency graph.

## Targets

| Target | What it covers | Module |
|---|---|---|
| `whisper_envelope_decode` | `prost`-decoding arbitrary bytes as a `WhisperEnvelope`. | `bowery-proto` |
| `sealer_open` | Full `Verifier::open` path: decode + length checks + signature verify + skew + replay. | `bowery-whisper` |
| `audit_envelope_parse` | `serde_json`-decoding then verifying an `AuditEnvelope`. | `bowery-response` |

Each target is a `fuzz_target!(|data: &[u8]| { ... })` that exercises
the hot path against arbitrary input. The contract is "must not
panic"; every other failure mode (parse error, signature mismatch,
replay) is a normal `Err` we expect to see frequently.

## Running

```sh
# One-time install on the build host:
cargo install cargo-fuzz

# Run a target (nightly required; libfuzzer-sys needs the sanitizer):
cargo +nightly fuzz run whisper_envelope_decode

# Run for a fixed time and print stats:
cargo +nightly fuzz run sealer_open -- -max_total_time=60

# Reproduce a crash from an artifact:
cargo +nightly fuzz run sealer_open fuzz/artifacts/sealer_open/crash-<hash>
```

`cargo-fuzz` writes a corpus under `fuzz/corpus/<target>/` and crash
artifacts under `fuzz/artifacts/<target>/`. Both are gitignored.

## What's NOT fuzzed (yet)

- The Q&A state machine (`qa::ask` / `qa::answer_one`) — needs
  per-stream framing input shape; planned for Phase 8 slice 3.
- The eBPF pipeline's userspace ringbuf decoder — Phase 8 follow-up.
- The baseline SQLite schema migration — covered by deterministic
  tests; fuzzing SQL is low-yield.
