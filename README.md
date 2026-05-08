# The Bowery

A distributed Linux EDR built around a peer-to-peer **whispering protocol**: agents validate anomalies with their neighbors instead of phoning home to a central backend.

> **Status:** pre-alpha, Phase 0 → 9 of the [implementation plan](DESIGN.md#13-phased-delivery) complete. Native Phase-9 SQL surface ([`bowery-sql` + `bowery-tables`](DESIGN-NATIVE-SQL.md)) ships 13 procfs/sysfs-backed tables plus 4 Bowery-internal views, streamed over the operator wire with one-hop multi-agent fan-out. Not production-ready, but every layer is end-to-end testable today.

## What it is

- A lightweight Rust agent that observes process exec / exit and outgoing TCP connections at the kernel level via eBPF tracepoints, with KRSI (BPF-LSM) hooks for response enforcement.
- A small embedded LLM (Qwen3-0.6B Q4_K_M via llama.cpp, feature-gated) that turns rule + baseline signal into a refined verdict + rationale.
- A gossip-based mesh (chitchat) with mTLS-pinned QUIC RPC for direct peer-to-peer whisper Q&A — agents ask role-similar peers "have you seen this fingerprint?" and aggregate the answers as additional context for the LLM.
- A native, pure-Rust SQL surface (`bowery-sql` + `bowery-tables`) that turns each agent into a queryable host-state engine — 13 procfs/sysfs/etc-backed tables plus 4 Bowery-internal views, streamed back over the operator wire with end-to-end signed multi-agent fan-out.
- A signed operator CLI that connects to any agent, drains a per-agent alert inbox, prints (or JSON-streams) high-suspicion verdicts, and fans SQL queries across the mesh. There is no backend.

## Why

Existing EDRs send everything home and decide centrally. The Bowery flips that: each agent decides locally, but only after asking the neighborhood whether the activity is normal *here*. It's a neighborhood watch for production fleets. Detection is local + corroborated; only operator-facing alerts cross the trust boundary, signed end-to-end.

## Documents

- [the_bowery_design.md](the_bowery_design.md) — original product brief.
- [DESIGN.md](DESIGN.md) — engineering design, locked decisions, phased delivery plan.
- [DESIGN-NATIVE-SQL.md](DESIGN-NATIVE-SQL.md) — Phase-9 design rationale + operator guide for the native SQL surface.
- [IMPLEMENTATION.md](IMPLEMENTATION.md) — deep dive: every crate, every protocol, every architectural decision and why. §22 covers the Phase-9 SQL surface in detail.
- [SECURITY-AUDIT-PHASE9.md](SECURITY-AUDIT-PHASE9.md) — two-pass audit of the SQL/fan-out surface and what shipped to address each finding.
- [INSTALL.md](INSTALL.md) — building, installing, configuring, and operating an agent.
- [docs/REMOTE_TESTING.md](docs/REMOTE_TESTING.md) — driving a Linux VM as the build/test target via `scripts/xtest`. Required if your dev machine doesn't have BPF-LSM (macOS, WSL2, etc.).

## Repository layout

```
crates/
  bowery-agent/            # daemon (binary + library)
  bowery-analysis/         # rules, baseline scorer, role vectors, peer ranking
  bowery-baseline/         # SQLite-backed observation store
  bowery-cli/              # operator CLI (`bowery`) — lib + bin
  bowery-console/          # ncurses operator workspace (`bowery-console`, ratatui)
  bowery-crypto/           # Ed25519 identity + fingerprint + atomic-write key file
  bowery-ebpf/             # kernel-side eBPF programs (separate workspace)
  bowery-ebpf-loader/      # userspace loader for the BPF object
  bowery-events/           # typed event schema + /proc enrichment
  bowery-llm/              # LLM analyzer + chat traits, mock + llama.cpp backends
  bowery-mesh/             # chitchat wrapper + role-vector KV
  bowery-proto/            # prost messages (envelope, payloads)
  bowery-response/         # Phase-7 action engine (block_exec / kill_process)
  bowery-sql/              # Phase-9 in-process SQL engine (rusqlite)
  bowery-tables/           # Phase-9 default table set (procfs/sysfs/etc-backed)
  bowery-whisper/          # envelope sealing, replay guard, mTLS, QUIC, Q&A,
                           # persistent peer-connection pool, fingerprints
deploy/systemd/            # service unit + slice
scripts/
  build-ebpf               # wraps `cargo +nightly build` for the BPF target
  integration-sql-test.sh  # end-to-end operator → agent SQL CI smoke
  xtest                    # SSH-based remote-VM driver (sync, build, run-agent,
                           # run-console, push-model, …)
docs/CONSOLE.md            # operator handbook for `bowery-console` (also
                           # rendered in-pane via Help, hotkey 8)
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

# Agent with real Qwen3-0.6B inference (needs cmake + clang):
cargo build --release --features llm-llama-cpp -p bowery-agent

# Operator console with real Gemma 4 chatbot:
cargo build --release --features llm-llama-cpp -p bowery-console

# Kernel-side BPF programs (needs nightly + bpf-linker):
./scripts/build-ebpf

# Remote VM workflow:
./scripts/xtest run-agent  --push-model        # agent on the test VM
./scripts/xtest run-console -- --agent-addr …  # console + Gemma 4 on the test VM
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
- **Phase 6b** — typed `OperatorCommand` / `OperatorResult` envelopes for operator → agent dispatch.
- **Phase 7** — response engine with BPF-LSM block-exec hooks, default-deny policy, signed audit log (Phase-8 hash-chain).
- **Phase 8** — replay guards, per-recipient envelope binding, fuzzing harness.
- **Phase 9** — native SQL surface: `bowery-sql` engine + `bowery-tables` 13 default + 4 Bowery-internal views + 7 scalar file/hash functions; streamed as chunked `OperatorResult::SqlChunk` envelopes over QUIC; multi-agent fan-out with operator-signed delegation (`OperatorAuthorization`); peers seal chunks **directly for the operator** (relay can drop but cannot forge); SELECT-only authorizer; per-operator rate limit; 16 KiB per-cell cap; SQLite progress-handler cancellation; `bowery peers add/list/remove` operator manifest. Every CRIT/HIGH/MEDIUM finding from [`SECURITY-AUDIT-PHASE9.md`](SECURITY-AUDIT-PHASE9.md) closed.
- **Phase 10 (slices 1–3)** — persistent peer-connection pool (`bowery_whisper::pool::PeerConnections`): outbound connections cached per fingerprint, lazy + watcher-driven eviction, inbound handler runs on outbound-pooled connections so peers can stream back without their own listener. Whisper Q&A migrated to bidirectional QUIC streams (`request` / `accept_request` / `Reply`) so `ask()` shares the pooled socket with the inbound handler without racing it. Heartbeat + Q&A both reuse the pool; operator transport untouched.
- **Operator console (`bowery-console`, phases C-1..C-6)** — ratatui workspace built on top of the `bowery-cli` library refactor. Eight panes: Query (SQL REPL), Alerts (live tail), Map (1-hop topology), Audit (snapshot), Peers (manifest), Doctor (local + remote readiness), Chat (Gemma 4 via llama.cpp, drafts SQL — press `x` to run), Help (in-pane operator handbook from [`docs/CONSOLE.md`](docs/CONSOLE.md)). Command palette (`:connect / :peers / :export / :quit`), input history persisted to `~/.bowery/console-history`. Model registry (`bowery model fetch`) gained Gemma-4-E2B-it with pinned SHA-256 verification.

## What's next

- **F-7 / F-17** observability tightening — EOF-accounting transcript envelope so the operator can verify "all expected peers reported" in fan-out; per-peer warn rate-limit on the relay's logs.
- **Phase 10 slice 4+** — outbound-only mode (config flag to disable the inbound listener for fully-firewalled agents), per-fingerprint dial-in-progress slot.
- **Phase 11+ (deferred)** — fleet-scale Sybil resistance, key rotation ceremony, neighbor add/remove protocol.

## License

[MPL 2.0](LICENSE).
