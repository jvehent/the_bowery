# The Bowery

A distributed Linux EDR built around a peer-to-peer **whispering protocol**: agents validate anomalies with their neighbors instead of phoning home to a central backend.

> **Status:** pre-alpha. Phase 0 of the [implementation plan](DESIGN.md#13-phased-delivery). Not production-ready. Not yet useful.

## What it is

- A lightweight Rust agent that runs on Linux hosts and observes process, syscall, file, and network activity at the kernel level via eBPF + KRSI (BPF-LSM).
- An embedded LLM that synthesizes baseline-deviating behavior into investigative questions.
- A gossip-based mesh that lets agents whisper "have you seen this?" to similar-role neighbors with privacy-preserving fingerprints.
- A signed CLI for operators — there is no backend to operate.

## Why

Existing EDRs send everything home and decide centrally. The Bowery flips that: each agent decides locally, but only after asking the neighborhood whether the activity is normal *here*. It's a neighborhood watch for production fleets.

## Documents

- [the_bowery_design.md](the_bowery_design.md) — original product requirements.
- [DESIGN.md](DESIGN.md) — engineering design, locked decisions, phasing.

## Repository layout

```
crates/
  bowery-agent/   # the daemon
  bowery-cli/     # operator CLI
  bowery-crypto/  # identity keys, signing, fingerprints
deploy/
  systemd/        # service unit
```

More crates are introduced as their phase begins; see DESIGN.md §13.

## Building (Phase 0)

```sh
cargo build --release
cargo test
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

## License

[MPL 2.0](LICENSE).
