# The Bowery

A distributed Linux EDR built around a peer-to-peer **whispering protocol**: agents validate anomalies with their neighbors instead of phoning home to a central backend.

> **Status:** pre-alpha, Phase 0 → 6a of the [implementation plan](DESIGN.md#13-phased-delivery) complete. Phase 6b (operator commands) and Phase 7 (response engine) are open. Not production-ready, but every layer below the response engine is end-to-end testable today.

## What it is

- A lightweight Rust agent that observes process exec / exit and outgoing TCP connections at the kernel level via eBPF tracepoints, with KRSI (BPF-LSM) hooks coming for response enforcement.
- A small embedded LLM (Qwen3-0.6B Q4_K_M via llama.cpp, feature-gated) that turns rule + baseline signal into a refined verdict + rationale.
- A gossip-based mesh (chitchat) with mTLS-pinned QUIC RPC for direct peer-to-peer whisper Q&A — agents ask role-similar peers "have you seen this fingerprint?" and aggregate the answers as additional context for the LLM.
- A signed operator CLI that connects to any agent, drains a per-agent alert inbox, and prints (or JSON-streams) high-suspicion verdicts. There is no backend.

## Why

Existing EDRs send everything home and decide centrally. The Bowery flips that: each agent decides locally, but only after asking the neighborhood whether the activity is normal *here*. It's a neighborhood watch for production fleets. Detection is local + corroborated; only operator-facing alerts cross the trust boundary, signed end-to-end.

## Documents

- [the_bowery_design.md](the_bowery_design.md) — original product brief.
- [DESIGN.md](DESIGN.md) — engineering design, locked decisions, phased delivery plan.
- [IMPLEMENTATION.md](IMPLEMENTATION.md) — deep dive: every crate, every protocol, every architectural decision and why.
- [INSTALL.md](INSTALL.md) — building, installing, configuring, and operating an agent.
- [docs/REMOTE_TESTING.md](docs/REMOTE_TESTING.md) — driving a Linux VM as the build/test target via `scripts/xtest`. Required if your dev machine doesn't have BPF-LSM (macOS, WSL2, etc.).

## Repository layout

```
crates/
  bowery-agent/            # daemon (binary + library)
  bowery-analysis/         # rules, baseline scorer, role vectors, peer ranking
  bowery-baseline/         # SQLite-backed observation store
  bowery-cli/              # operator CLI (`bowery`)
  bowery-crypto/           # Ed25519 identity + fingerprint + atomic-write key file
  bowery-ebpf/             # kernel-side eBPF programs (separate workspace)
  bowery-ebpf-loader/      # userspace loader for the BPF object
  bowery-events/           # typed event schema + /proc enrichment
  bowery-llm/              # LLM analyzer trait, mock backend, llama.cpp backend
  bowery-mesh/             # chitchat wrapper + role-vector KV
  bowery-proto/            # prost messages (envelope, payloads)
  bowery-whisper/          # envelope sealing, replay guard, mTLS, QUIC, Q&A, fingerprints
deploy/systemd/            # service unit + slice
scripts/
  build-ebpf               # wraps `cargo +nightly build` for the BPF target
  xtest                    # SSH-based remote-VM driver (sync, build, run, push-model, …)
docs/REMOTE_TESTING.md
DESIGN.md
IMPLEMENTATION.md
INSTALL.md
```

## Quick build

```sh
# Userspace, default features (mock LLM):
cargo build --release
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check

# With real Qwen3-0.6B inference (needs cmake + clang):
cargo build --release --features llm-llama-cpp -p bowery-agent

# Kernel-side BPF programs (needs nightly + bpf-linker):
./scripts/build-ebpf

# Remote VM workflow (one shot: sync + build BPF + build agent + run):
./scripts/xtest run-agent --push-model
```

`bowery doctor` on a candidate Linux host tells you whether the kernel is ready (BPF-LSM, BTF, bpffs, lsm= cmdline). `INSTALL.md §1.2` lists distros that work out of the box.

## What's implemented

- **Phase 0** — workspace skeleton, identity keys, CI, packaging.
- **Phase 1** — chitchat membership, signed envelopes, replay guard, QUIC mTLS, TOFU pinning.
- **Phase 2** — three eBPF tracepoints (`sched_process_exec`, `sched_process_exit`, `sock/inet_sock_set_state`) with concurrent ringbuf drains; `/proc` enrichment; SQLite baseline.
- **Phase 3** — pre-filter rules, baseline scoring, episode aggregation, deterministic role vectors (Achlioptas projection from a fixed seed).
- **Phase 4 / 4b** — LLM analyzer framework (mock + queue + outcomes bridge); real Qwen3-0.6B inference via `llama-cpp-2`.
- **Phase 5** — whisper Q&A: two-tier privacy fingerprints (8-byte truncation of `SHA256(domain ‖ sha256)`), bloom filter primitives, role-similarity peer selection by cosine similarity, asker/responder protocol over the existing QUIC transport, per-round aggregator.
- **Phase 6a** — operator alert inbox: per-agent in-memory ring with TTL retention, signed `Subscribe` over the QUIC transport, `bowery alerts tail` CLI for roaming operators, curated model registry (`bowery model fetch`).

## What's next

- **Phase 6b** — `OperatorCommand` / `OperatorResult` payloads, `bowery query`, `bowery action ...`, OSQuery subprocess integration.
- **Phase 7** — response engine: BPF-LSM hooks that block exec / file-open / connect under standing authorisations.
- **Phase 8** — fuzzing, key rotation ceremony, neighbor add/remove protocol, Sybil-resistance hardening.

## License

[MPL 2.0](LICENSE).
