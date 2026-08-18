# The Bowery — Implementation Notes

A reading guide to the codebase, focused on *why*. [DESIGN.md](DESIGN.md)
is the engineering plan and locked decisions; this document explains
how those decisions land in code, the patterns we reach for, and the
specific tradeoffs taken at each layer. If you're new to the project,
read [README.md](README.md) first for orientation, then this for depth.

This document tracks Phase 0 → 8, plus the now-shipped Phase 6b
(operator command issuance), which is everything currently
implemented. Phase 9 (deferred Tier-2 follow-ups: race-free pidfd
kill + LSM inode-keyed blocking) and the operator-command audit-
envelope follow-up sections will be added when those land.

## Contents

1. [Reading order](#1-reading-order)
2. [Workspace topology](#2-workspace-topology)
3. [Concurrency model](#3-concurrency-model)
4. [Identity and crypto](#4-identity-and-crypto)
5. [Wire format and envelope crypto](#5-wire-format-and-envelope-crypto)
6. [mTLS pinning](#6-mtls-pinning)
7. [Mesh layer](#7-mesh-layer)
8. [eBPF pipeline](#8-ebpf-pipeline)
9. [Event pipeline and enrichment](#9-event-pipeline-and-enrichment)
10. [Baseline storage](#10-baseline-storage)
11. [Analyzer: rules, scorer, role vector](#11-analyzer-rules-scorer-role-vector)
12. [LLM analyzer](#12-llm-analyzer)
13. [Whisper Q&A](#13-whisper-qa)
14. [Operator inbox and Subscribe](#14-operator-inbox-and-subscribe)
15. [Operator CLI](#15-operator-cli)
16. [Response engine](#16-response-engine)
17. [Build and test infrastructure](#17-build-and-test-infrastructure)
18. [Patterns we keep using](#18-patterns-we-keep-using)
19. [What we explicitly don't do](#19-what-we-explicitly-dont-do)
20. [Phase 8 hardening](#20-phase-8-hardening)
21. [Phase 6b operator commands](#21-phase-6b-operator-commands)
22. [Phase 9 native SQL surface](#22-phase-9-native-sql-surface)

---

## 1. Reading order

The codebase is small but layered. From cheapest-to-understand to
most-coupled:

1. [`bowery-crypto`](crates/bowery-crypto/src/lib.rs) — 200 LOC, no
   project dependencies. Defines `Identity` (Ed25519 keypair) and
   `Fingerprint` (SHA-256 of the verifying key). Everything else
   refers to fingerprints.
2. [`bowery-proto`](crates/bowery-proto/src/lib.rs) — prost-derived
   wire types. The `WhisperEnvelope`, the `WhisperPayload` oneof, and
   each variant.
3. [`bowery-events`](crates/bowery-events/src/lib.rs) — typed event
   schema: `ProcessExec`, `ProcessExit`, `NetworkConnect`. Plus an
   `EventSource` trait so the pipeline can be driven by mock events,
   noop, or the BPF loader.
4. [`bowery-baseline`](crates/bowery-baseline/src/lib.rs) — SQLite
   wrapper. `binaries` and `process_lineage` tables, upsert helpers.
5. [`bowery-whisper`](crates/bowery-whisper/src/lib.rs) — the protocol
   layer: envelope sealing, replay guard, mTLS-pinned QUIC transport,
   tier-1 fingerprints, bloom filter, and the Q&A asker/responder.
6. [`bowery-mesh`](crates/bowery-mesh/src/lib.rs) — chitchat wrapper.
7. [`bowery-analysis`](crates/bowery-analysis/src/lib.rs) — rules,
   baseline scorer, episode, role vector, peer-similarity ranker.
8. [`bowery-llm`](crates/bowery-llm/src/lib.rs) — LLM analyzer
   abstraction; mock + llama.cpp backends; inference queue.
9. [`bowery-ebpf-loader`](crates/bowery-ebpf-loader/src/lib.rs) — aya
   userspace loader, three-ringbuf drain, parsers.
10. [`bowery-ebpf`](crates/bowery-ebpf/src/main.rs) — the kernel-side
    code. Separate workspace, `bpfel-unknown-none` target.
11. [`bowery-agent`](crates/bowery-agent/src/agent.rs) — wires
    everything together; pin / accept / heartbeat / pipeline /
    role-publisher / llm-outcomes / whisper-qa tasks.
12. [`bowery-cli`](crates/bowery-cli/src/main.rs) — operator
    commands: `key`, `doctor`, `alerts tail`, `model {list, fetch}`.

Reading them in that order means each crate's dependencies are
already familiar by the time you reach it.

## 2. Workspace topology

### 2.1 Two workspaces

The repo has two cargo workspaces:

- The **main** workspace at the repo root, containing every userspace
  crate.
- The **bowery-ebpf** sub-workspace ([`crates/bowery-ebpf/Cargo.toml`](crates/bowery-ebpf/Cargo.toml))
  whose only member compiles for `bpfel-unknown-none` with nightly +
  `bpf-linker` + `-Z build-std=core`. It's listed in the root
  `Cargo.toml`'s `exclude` so a normal `cargo build` from the repo
  root never tries to compile it.

The sub-workspace boundary lets us keep workspace-wide lints (e.g.
`unsafe_code = "deny"`) on stable code without forcing them onto a
crate that runs in BPF land where stable doesn't even apply. It also
lets the BPF crate use a panic-abort profile and a different opt-level
without polluting the userspace builds.

The build script — [`scripts/build-ebpf`](scripts/build-ebpf) —
is the only entry point that crosses the boundary: it cd's into
`crates/bowery-ebpf/` and runs `cargo +nightly build --release`. The
agent's userspace loader expects the resulting object on disk; nothing
links against it directly.

### 2.2 Crate boundaries

We aim for sharp, single-purpose crates. The biggest sin would be a
single mega-crate that depends on the world; what we get instead is
clear arrows:

```text
                    +---------- bowery-crypto -------+
                    |                                |
                    v                                v
              bowery-proto <--- bowery-whisper ---> bowery-mesh
                    ^                ^                ^
                    |                |                |
                    +--- bowery-llm  |    bowery-baseline
                              ^      |          ^
                              |      |          |
                              +--- bowery-analysis
                                          ^
                                          |
                              bowery-events  bowery-ebpf-loader
                                  ^                    ^
                                  +------+      +------+
                                         |      |
                                       bowery-agent
                                            ^
                                            |
                                       bowery-cli (operator side only)
```

`bowery-cli` and `bowery-agent` are the only "leaf" binaries; every
other crate is a library and free of binary entrypoints.

### 2.3 Workspace-wide lints

Set in the root `Cargo.toml`:

```toml
[workspace.lints.rust]
unsafe_code = "deny"        # not "forbid" — see below
unreachable_pub = "warn"
missing_debug_implementations = "warn"

[workspace.lints.clippy]
all = { level = "warn", priority = -1 }
pedantic = { level = "warn", priority = -1 }
module_name_repetitions = "allow"
must_use_candidate = "allow"
missing_errors_doc = "allow"
missing_panics_doc = "allow"
```

`unsafe_code = "deny"` (rather than `"forbid"`) is deliberate.
`bowery-ebpf-loader` parses kernel-produced byte records via
`ptr::read_unaligned` and sets test env vars unsafely; both are
unavoidable. The crate opts in with a top-of-file `#![allow(unsafe_code)]`
and a comment explaining why. Every other crate stays unsafe-free.

Pedantic clippy is on workspace-wide. The "allow" list at the bottom
is what we've decided is too noisy or too pedantic for this codebase
(e.g. `module_name_repetitions` flags `bowery_proto::WhisperPayload`,
which is the right name).

CI runs `cargo clippy --workspace --all-targets --features llm-llama-cpp -- -D warnings`,
so a single new pedantic warning fails CI. That's been worth it —
catching things like `cast_possible_truncation` early forced us to
think about the actual integer ranges instead of casting blindly.

## 3. Concurrency model

The agent is a tokio multi-threaded runtime hosting six long-running
tasks, plus one thread (the LLM worker) that is *not* a tokio task.
Communication channels are picked deliberately:

| Channel type | Where used | Why |
|---|---|---|
| `tokio::sync::watch` | shutdown signal from `Agent::shutdown()` | One sender, many receivers, latest-value semantics. Background tasks `.changed().await` to know when to exit. |
| `tokio::sync::broadcast` | `AgentEvent` fan-out | Many subscribers (tests, the `bowery alerts tail` flow eventually, ops dashboards). Lossy by design — slow consumers see `Lagged(n)` instead of stalling the producer. |
| `tokio::sync::mpsc` | event source → pipeline; LLM trigger queue; whisper-QA trigger | Single consumer, bounded backpressure. Producers can `.send().await` and get told if the channel is closed. |
| `tokio::sync::oneshot` | LLM worker readiness; per-question response | One-shot, send/recv pair. Cheap. |

Tasks held by the agent struct (handles let `shutdown()` join them):

| Task | Purpose | Spawn site |
|---|---|---|
| `pin_task` | watches `Mesh::peers_watcher` and TOFU-pins newcomers | [agent.rs:spawn_pin_task](crates/bowery-agent/src/agent.rs) |
| `accept_task` | accepts incoming QUIC connections; dispatches Question/Subscribe payloads | `spawn_accept_task` |
| `heartbeat_task` | periodic signed Heartbeat to every pinned peer | `spawn_heartbeat_task` |
| `pipeline_task` | drains the EventSource; runs analyzer; submits to LLM; emits whisper triggers; appends Alerts | `spawn_pipeline_task` |
| `role_publisher_task` | recomputes the local RoleVector and pushes it to mesh KV | `spawn_role_publisher_task` |
| `llm_outcomes_task` | turns `InferenceOutcome`s into broadcast events | `spawn_llm_outcomes_task` |
| `whisper_qa_task` | runs whisper Q&A rounds on triggers | `spawn_whisper_qa_task` |

### 3.1 The dedicated-thread escape hatch

Some workloads aren't tokio-friendly:

- **llama.cpp**: `LlamaModel` and `LlamaContext` are not `Send`. We
  can't move them across `.await` points or task boundaries.
- **Inference is multi-second**: even if it were `Send`, holding a
  tokio worker thread for that long would starve the runtime.

The pattern, used in [`bowery-llm/src/llama_cpp.rs`](crates/bowery-llm/src/llama_cpp.rs):

```text
+-- main runtime ------------+      +-- bowery-llm-worker (OS thread) -+
|                            |      |                                  |
|  Submitter ─────────────►  |      |   while let Some(req) =          |
|         (mpsc<Request>)    | ───► |     request_rx.blocking_recv() { |
|                            |      |     let resp = worker.run(...);  |
|                            |      |     req.responder.send(resp);    |
|  resp_rx.await ◄────────── | ◄─── |   }                              |
|         (oneshot<...>)     |      |                                  |
+----------------------------+      +----------------------------------+
```

`mpsc::UnboundedSender` is `Send`, the worker thread owns the
non-`Send` `LlamaModel`, and each `Request` carries its own
`oneshot::Sender` for the response. Tokio sees zero blocking work; the
worker thread blocks freely. Readiness is signalled via a separate
oneshot at startup so `LlamaCppAnalyzer::new` doesn't return until the
GGUF is loaded.

### 3.2 Shutdown

Every long-running task has the same skeleton:

```rust
loop {
    tokio::select! {
        biased;
        _ = shutdown_rx.changed() => break,
        item = work_rx.recv() => { /* ... */ }
    }
}
```

`Agent::shutdown` sets the watch channel to `true`, closes the QUIC
endpoint, then `.await`s every JoinHandle. The mesh shuts down last
(it owns the chitchat handle which has its own teardown).

### 3.3 No global state

Nothing is `static`, `lazy_static`, or `OnceCell`-backed. Every long-
lived resource is owned by the `Agent` struct (or a sub-task) and
plumbed in explicitly. This makes tests trivial: spin up two agents in
the same process, give them different config, watch them gossip.

## 4. Identity and crypto

### 4.1 Identity

[`crates/bowery-crypto/src/lib.rs`](crates/bowery-crypto/src/lib.rs).

`Identity` is a thin wrapper around `ed25519_dalek::SigningKey`. Two
fields: the keypair itself, and the cached verifying key for fast
fingerprint computation.

The on-disk format is intentionally minimal — 32 bytes of seed in a
file at mode `0600`. We use `pkcs8` only when interoperating with
external tooling; the agent's own state files use the raw seed because
parsing PEM/PKCS8 to verify mode-0600 invariants on every startup is
needless work for a key we generated ourselves.

`Identity::load_or_generate(path)` is the standard call site. It
either decodes an existing file or generates a fresh keypair and
atomically writes it (write-temp + fsync + rename, mode 0600). Atomic
writes matter because a torn write would leave us with a half-key file
on next start.

### 4.2 Fingerprint

```rust
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    pub fn from_verifying_key(vk: &VerifyingKey) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(vk.as_bytes());
        Self(hasher.finalize().into())
    }
}
```

That's the core: a fingerprint is `SHA-256(verifying_key_bytes)`. It's
how every other layer refers to a peer:

- the wire format's `sender_fingerprint` field
- the TOFU pin store's primary key
- the mesh KV's chitchat node id
- the operator inbox's `originator_fp` field

We never put a verifying key on the wire — only its fingerprint and a
signature over the signing input. The verifying key is exchanged at
TLS handshake time (it's the cert's public key) and bound to the
fingerprint by the `PinnedCertVerifier`, so by the time we're checking
an envelope's signature we already know which key corresponds to the
fingerprint.

### 4.3 Why Ed25519 + SHA-256

- **Ed25519**: deterministic signatures, no per-signature randomness
  to leak, fast verification (~50 µs on a modern core), small
  signatures (64 bytes), no curve-choice bikeshed.
- **SHA-256 for fingerprints**: 32 bytes is a comfortable size to put
  in TOML / JSON, broad library support, no preimage attacks at this
  cost level. We don't need SHA-3 or BLAKE3's speed for an operation
  that runs once per peer.

## 5. Wire format and envelope crypto

### 5.1 Why prost (no `protoc`)

[`bowery-proto`](crates/bowery-proto/src/lib.rs) uses prost's derive
macros directly — no `.proto` IDL, no `protoc` build dependency, no
`build.rs`. The struct definitions are the source of truth and the
DESIGN doc references the field tags.

Tradeoffs:

- **Pro**: zero external build deps. `cargo build` Just Works on a
  clean machine.
- **Pro**: refactoring works through rust-analyzer.
- **Con**: no language-agnostic schema. If someone wants to write a
  Go client they have to read our Rust. We'd add a `.proto` if/when
  that day comes.

### 5.2 Envelope structure

```rust
pub struct WhisperEnvelope {
    sender_fingerprint: Vec<u8>,  // 32 bytes
    nonce:             u64,        // monotonic per-sender
    ts_unix_ms:        u64,
    payload:           Vec<u8>,    // prost-encoded WhisperPayload
    signature:         Vec<u8>,    // 64 bytes (Ed25519)
}
```

The `payload` field is double-encoded: the inner `WhisperPayload` is
prost-encoded into bytes, then those bytes go into the envelope's
`payload` field. That's deliberate — the signature covers the *bytes*
of the payload, not the parsed structure, so a malicious modifier
can't change the prost tags or field order without invalidating the
signature.

### 5.3 Signing input

```text
domain ‖ recipient_fingerprint ‖ sender_fingerprint ‖ nonce_be ‖ ts_be ‖ payload_bytes
```

Domain prefix `b"bowery/whisper/envelope/v2"` ([`CANONICAL_SIG_DOMAIN`](crates/bowery-proto/src/lib.rs))
is the standard Ed25519 domain separation trick: if our keys are ever
loaded into another protocol, that protocol's signature inputs won't
collide with ours.

The big-endian fixed-width encoding makes the canonical string
unambiguous regardless of endianness. We include both nonce and ts so
neither one can be tampered with.

`recipient_fingerprint` was added in Phase-8 (H1) to defend against
cross-recipient replay: an envelope captured from Alice→Bob can no
longer be replayed against Carol within the 5-min skew window, even
though both Bob and Carol pin Alice. The recipient_fp is **not** on
the wire — each receiver supplies its own self-fp when computing the
canonical input. A signature for Bob therefore cannot verify under
Carol's input. The Sealer takes recipient_fp per
`seal_for(recipient, payload)` call; the Verifier takes self_fp at
construction. Domain bumped from `v1` → `v2` so any pre-fix peer
fails loudly with `BadSignature` rather than confusing the operator
with a "not pinned" error.

### 5.4 Verifier checks

[`crates/bowery-whisper/src/envelope.rs::Verifier::open`](crates/bowery-whisper/src/envelope.rs)
does, in order:

1. Decode the outer prost envelope.
2. Length-check fingerprint (32) and signature (64).
3. Resolve the sender's verifying key from a `FingerprintResolver`
   (the TOFU store, an operator registry, or a composite of both).
4. Verify the Ed25519 signature.
5. Clock-skew gate: the timestamp must be within ±5 minutes of local
   wall clock. Configurable.
6. Replay guard: nonces must be either monotonically increasing past
   the high-water-mark or within a sliding window of recently-seen
   ones (handles minor reordering).
7. Decode the inner `WhisperPayload`.

Order matters: signature verification *before* replay guard so a
malicious peer can't poison our replay state with bogus nonces.

### 5.5 Replay guard

[`crates/bowery-whisper/src/replay.rs`](crates/bowery-whisper/src/replay.rs).

A sliding window per sender. We keep the high-water-mark nonce and a
bitset for the previous 1024 nonces. New arrivals:

- `nonce > hwm`: shift the window, set the bit.
- `nonce ∈ [hwm-1024, hwm]`: check the bit; reject if seen.
- `nonce < hwm-1024`: reject as too-old.
- A single huge jump forward resets the window — handles peer
  restarts.

The whole state is bounded: 32 bytes fingerprint + ~150 bytes
per-sender state, capped at the size of the pin store. A 5k-node mesh
is well under 1 MB.

## 6. mTLS pinning

### 6.1 The shape

QUIC needs TLS. Bowery uses raw-public-key TLS via rustls' "dangerous"
custom verifier hook:

- We generate a self-signed Ed25519 certificate at startup that
  carries our identity public key (rcgen). The cert never expires
  because we're not using PKI — we throw the cert away on next
  restart.
- The remote side's `PinnedCertVerifier` extracts the SubjectPublicKey
  from the presented cert and computes its fingerprint, then asks a
  `FingerprintResolver` whether that fingerprint is recognised.
- mTLS: both sides do the same. Client cert verification rides the
  same path.

[`crates/bowery-whisper/src/tls.rs`](crates/bowery-whisper/src/tls.rs)
contains the rcgen-driven cert generation; [`crates/bowery-whisper/src/transport.rs`](crates/bowery-whisper/src/transport.rs)
wires the rustls `ClientConfig` and `ServerConfig` for both directions.

### 6.2 PinnedCertVerifier

The verifier has two modes:

- `PinnedCertVerifier::new(resolver)` — accept any cert whose
  fingerprint resolves. Used on the accept side, where we don't know
  *which* peer is dialing us.
- `PinnedCertVerifier::expecting(resolver, target)` — accept *only*
  the cert with fingerprint `target`. Used on the dial side, where we
  know exactly who we're trying to reach.

The "expecting" form is what makes pinning robust: even if an attacker
somehow had a valid cert for a different fingerprint in the resolver,
they couldn't impersonate the specific peer we're dialing.

### 6.3 CompositeResolver

Phase 6a introduced a wrinkle: the agent needs to accept signatures
from both peer agents (TOFU-pinned via `KnownNeighbors`) and operators
(explicitly configured via `[operators] pubkeys_b64`). We don't want
to conflate the two stores — operators shouldn't gossip back as peers,
peer agents shouldn't drain alert inboxes.

Solution: [`CompositeResolver<A, B>`](crates/bowery-whisper/src/envelope.rs)
which delegates to two `FingerprintResolver`s in order. The agent
wires it as `CompositeResolver(known_neighbors, operators)` for both
TLS verification and envelope verification.

Authorization is then enforced *separately* per-payload type: when the
accept handler gets a `Subscribe`, it re-checks the sender against the
*operators-only* resolver before responding, so a peer agent's
fingerprint resolving via the composite doesn't grant inbox access.

## 7. Mesh layer

### 7.1 Why chitchat

Chitchat is a SWIM-style gossip library originally written for
quickwit. We picked it for:

- **Pure UDP**: no listening port for cluster join, no TCP handshake
  hell.
- **Per-key versioning** on the KV: peers can announce their
  `whisper_addr` once, and gossip propagates it to every other peer
  in O(log N) rounds.
- **Failure detection**: built-in. Peers we haven't heard from are
  declared dead and removed from `peers_watcher`.

[`crates/bowery-mesh/src/lib.rs`](crates/bowery-mesh/src/lib.rs) is a
thin wrapper. The two interesting bits:

### 7.2 KV keys

```rust
const KEY_WHISPER_ADDR: &str = "whisper_addr";
const KEY_AGENT_VERSION: &str = "agent_version";
const KEY_ROLE_VECTOR: &str  = "role_vector";
```

Each agent publishes its `whisper_addr` at startup (so peers know
where to dial), the `agent_version` for ops dashboards, and (Phase 3+)
its `role_vector` periodically.

Chitchat enforces no schema; we just treat KV values as strings and
parse on read. The role vector is a base64-encoded packed `[f32;
32]` plus a `u64` count — see §11.4.

### 7.3 PeerInfo assembly

The `peers_watcher` channel emits `Vec<PeerInfo>` whenever the cluster
membership changes. Each `PeerInfo` is built by:

1. Walking chitchat's live cluster state.
2. Skipping our own node id.
3. Decoding the chitchat node id as a hex fingerprint.
4. Reading `KEY_WHISPER_ADDR`, `KEY_AGENT_VERSION`, `KEY_ROLE_VECTOR`.
5. Skipping the peer if any required field is missing or malformed.

The verifying key isn't in the chitchat KV — peers exchange it via TLS
on the first dial. Until that happens, we know the peer's fingerprint
but not its key. The agent's `pin_task` resolves this on the inbound
side: it watches `peers_watcher`, tries to TOFU-pin via
`KnownNeighbors::try_pin`, and the pin only succeeds once we've
actually dialed/been-dialed-by that peer (which happens on the next
heartbeat tick).

## 8. eBPF pipeline

### 8.1 Kernel-side programs

[`crates/bowery-ebpf/src/main.rs`](crates/bowery-ebpf/src/main.rs).
Three tracepoint programs, three ring buffers:

| Program | Tracepoint | Ring buffer | Purpose |
|---|---|---|---|
| `sched_process_exec` | `sched/sched_process_exec` | `EVENTS` (256 KiB) | every successful exec |
| `sched_process_exit` | `sched/sched_process_exit` | `EXIT_EVENTS` (64 KiB) | thread-group leaders only |
| `inet_sock_set_state` | `sock/inet_sock_set_state` | `CONNECT_EVENTS` (256 KiB) | outgoing TCP connect (CLOSE→SYN_SENT) |

We chose tracepoints over kprobes for stability — the kernel's
tracepoint ABI is stable across versions, kprobes break when the
kernel reorganizes its internals. The downside is we're constrained
to the fields the tracepoint exposes; that bites in a couple of
places (no exit_code in `sched_process_exit`, so we ship 0 as the
sentinel).

### 8.2 Why three rings instead of one tagged ring

A single ringbuf with a discriminator byte would save kernel-side
code, but a per-event-type ring:

- avoids a kernel-side branch on every record-write
- lets each program reserve from its own buffer (less contention
  under load)
- gives userspace a single-type parser per drain (no enum
  dispatch on every record)

The cost is three `AsyncFd`s and three drain tasks userspace, which
is cheap.

### 8.3 inet_sock_set_state filtering

The `sock/inet_sock_set_state` tracepoint fires on *every* socket
state change — TCP and UDP, every direction. We filter inside the
kernel program:

```rust
if oldstate != TCP_CLOSE || newstate != TCP_SYN_SENT { return Ok(()); }
if protocol != IPPROTO_TCP { return Ok(()); }
```

This narrows the firehose to "outgoing TCP connect attempts," which
is what the analyzer wants. The filter runs in BPF, so the userspace
side doesn't even see the records we drop — important on busy hosts
where socket state changes are very high-rate.

### 8.4 Wire format between kernel and userspace

Each program reserves a fixed-size struct in its ring buffer and
writes the fields directly. Both sides have a `#[repr(C)]` declaration
of the same struct layout:

```rust
// kernel: crates/bowery-ebpf/src/main.rs
#[repr(C)] pub struct ConnectEvent {
    pub pid: u32,
    pub family: u16,
    pub dport: u16,
    pub daddr_v4: [u8; 4],
    pub daddr_v6: [u8; 16],
    pub comm: [u8; 16],
}

// userspace: crates/bowery-ebpf-loader/src/lib.rs
#[repr(C)] #[derive(Clone, Copy)]
struct RawConnectEvent { /* same fields, same order */ }
```

A duplicate struct definition is a small price for not pulling
`bowery-events` into a no_std crate. The kernel-side struct must stay
in lock-step with the userspace one; tests that round-trip a record
through the parser would catch divergence, but in practice the two
files are rarely changed together by accident.

### 8.5 Userspace loader

[`crates/bowery-ebpf-loader/src/lib.rs`](crates/bowery-ebpf-loader/src/lib.rs).
Built on `aya` 0.13. The flow:

1. `Ebpf::load_file(obj_path)` — parses the BPF ELF.
2. `attach_tp(name, category, name)` — for each of the three
   programs, get-program-by-name → load → attach.
3. `take_ring(name)` — for each ring buffer, take ownership of the
   `MapData` and wrap in `aya::maps::ring_buf::RingBuf`.
4. `tokio::try_join!(drain_ring(exec_ring, ...), drain_ring(exit_ring, ...), drain_ring(connect_ring, ...))`.

`drain_ring` is generic over a parser closure:

```rust
async fn drain_ring<F>(
    mut ring: RingBuf<MapData>,
    tx: mpsc::Sender<Event>,
    parse: F,
    name: &'static str,
) -> Result<(), LoaderError>
where
    F: Fn(&[u8]) -> Option<Event>,
```

It wraps the ring's raw fd in a tokio `AsyncFd`, awaits readability,
then drains every record with `ring.next()` until the buffer is empty.
Each record goes through `parse` (which does `ptr::read_unaligned`,
network-byte-order conversion for `dport`, IPv4/IPv6 dispatch, and
`/proc` enrichment).

The `try_join!` ties the three tasks' lifetimes together: if one
drain fails, the others get cancelled. That's the right semantic —
losing a tracepoint mid-flight is a fatal-to-this-source error, and
the agent will fall back to NoopEventSource if the BPF source exits.

### 8.6 BPF object discovery

The agent looks for the BPF object in this order:

1. `/usr/local/lib/bowery/bowery-ebpf`
2. `/usr/lib/bowery/bowery-ebpf`
3. `BOWERY_BPF_OBJ_PATH` env var — only when `BOWERY_BPF_DEV_MODE=1`
   is also set (Phase-8 H8). Production agents reject the override.

Each candidate is integrity-checked at load: must exist as a
regular file (no symlinks; `symlink_metadata`, not `metadata`),
owned by uid 0, mode `0o644` or stricter. Anything failing those
checks returns `LoaderError::InsecureObject` and the agent falls
back to `NoopEventSource`. The cwd-relative dev fallback is gone —
`xtest run-agent` sets both env vars so in-tree development still
works.

Missing → `NoopEventSource` and a WARN log. The agent keeps running;
mesh + heartbeat + Q&A still work, the pipeline is just idle.

## 9. Event pipeline and enrichment

### 9.1 The Event enum

[`crates/bowery-events/src/lib.rs`](crates/bowery-events/src/lib.rs):

```rust
pub enum Event {
    ProcessExec(ProcessExec),
    ProcessExit(ProcessExit),
    FileOpen(FileOpen),       // not yet emitted
    NetworkConnect(NetworkConnect),
}
```

Phase 2 emits exec / exit / network. `FileOpen` is reserved for a
later phase. Each variant is a struct with named fields; `pid()` and
`timestamp()` accessors handle the dispatch.

Sticking to a closed enum (rather than `Box<dyn Event>`) lets the
analyzer pattern-match and gives the type system a fighting chance of
catching us when we add a new variant without a handler.

### 9.2 EventSource trait

```rust
pub trait EventSource: Send + 'static {
    fn start(self: Box<Self>) -> mpsc::Receiver<Event>;
}
```

Three implementations:

- [`MockEventSource`](crates/bowery-events/src/source.rs) — fixed
  list, optional inter-event delay. Drives the integration tests.
- [`NoopEventSource`](crates/bowery-events/src/source.rs) — never
  produces, never closes. Production fallback when the BPF source
  isn't available.
- [`BpfEventSource`](crates/bowery-ebpf-loader/src/lib.rs) — wraps
  the loader.

The `start` method consumes `self` (via `Box<Self>` to make the trait
object-safe with by-value receivers) and returns a receiver. The
producer task lives in the box and stays alive as long as the agent's
shutdown channel hasn't fired.

### 9.3 /proc enrichment

[`crates/bowery-events/src/enrich.rs`](crates/bowery-events/src/enrich.rs)
turns a kernel-issued PID into:

- `pid_exe_path(pid)` — readlinks `/proc/<pid>/exe`.
- `pid_cmdline(pid)` — reads `/proc/<pid>/cmdline` and splits on null
  bytes.
- `sha256_file(path)` — streaming SHA-256 over the binary contents.

Race: the process can exit between the BPF event firing and us
opening `/proc/<pid>/exe`. We accept that — the result is `None` for
exe_path and the analyzer skips the binary. Capturing the binary at
exec-time would require a much heavier approach (LSM hook, copy the
ELF into a stash) which we'd rather defer to a phase that explicitly
needs it.

### 9.4 The pipeline task

[`crates/bowery-agent/src/agent.rs::spawn_pipeline_task`](crates/bowery-agent/src/agent.rs)
is the central junction:

```text
EventSource ──── mpsc ──► pipeline_task
                              │
                              ├── (ProcessExec)
                              │       │
                              │       ▼
                              │   sha256_file (spawn_blocking)
                              │       │
                              │       ▼
                              │   Analyzer::analyze (spawn_blocking)
                              │       │
                              │       ▼
                              │   Baseline::upsert_binary (spawn_blocking)
                              │       │
                              │       ▼
                              │   ┌───────────────────────────────┐
                              │   │ if susp ≥ llm_threshold:      │
                              │   │   llm_submitter.submit(ctx)   │
                              │   │ if susp ≥ whisper_threshold:  │
                              │   │   whisper_qa_tx.send(trigger) │
                              │   │ if susp ≥ alert_threshold:    │
                              │   │   inbox.append(alert)         │
                              │   │ events_tx.send(EpisodeAnalyzed)│
                              │   └───────────────────────────────┘
                              │
                              └── (ProcessExit | NetworkConnect | FileOpen)
                                  silently consumed (for now)
```

Three thresholds, three independent gates. They can be configured
independently (typical: `llm < whisper ≤ alert`, so cheap LLM
invocations happen on more events than expensive Q&A rounds, and only
the highest-scoring verdicts become Alerts).

## 10. Baseline storage

### 10.1 Schema

[`crates/bowery-baseline/src/lib.rs`](crates/bowery-baseline/src/lib.rs).
SQLite via rusqlite, bundled (no system dependency). WAL mode +
synchronous=NORMAL — durable enough for the audit trail, fast enough
on workloads with thousands of execs/s.

```sql
CREATE TABLE binaries (
    sha256       BLOB PRIMARY KEY,
    first_seen   INTEGER NOT NULL,
    last_seen    INTEGER NOT NULL,
    seen_count   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE process_lineage (
    parent_sha   BLOB NOT NULL,
    child_sha    BLOB NOT NULL,
    first_seen   INTEGER NOT NULL,
    last_seen    INTEGER NOT NULL,
    seen_count   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(parent_sha, child_sha)
);
CREATE INDEX idx_lineage_child ON process_lineage(child_sha);
```

Two tables: per-binary observations and parent→child lineage edges.
The schema is intentionally narrow — the analyzer just needs
"have we seen this? when? how many times? what's the parent?" Adding
more columns (path, signing info, container metadata) is cheap when
we need them; we don't yet.

### 10.2 Concurrency

The connection lives behind `Mutex<Connection>`. Every read or write
takes the lock briefly. SQLite serialises writers anyway, so the
mutex isn't a new bottleneck. The agent's pipeline holds the lock for
the duration of a single upsert — a few hundred microseconds — which
is fine even at thousands of execs/s.

We deliberately skip a connection pool. SQLite's writer is
single-threaded; multiple connections would just serialize on the
filesystem locks.

### 10.3 for_each_binary

Phase 5 (whisper Q&A) added `Baseline::for_each_binary(visitor)` —
callback-driven full-table scan. The whisper responder uses it to
aggregate sightings by tier-1 fingerprint:

```rust
let _ = baseline.for_each_binary(|rec| {
    if Tier1Fingerprint::derive(&rec.sha256) != target { return; }
    // accumulate seen_count, first_seen, last_seen ...
});
```

O(N) over the binary table. At 10k binaries (a typical host) this is
a few milliseconds; if it ever shows up in a profile we can add an
indexed `tier1` column. Keeping it as a scan today means the tier-1
derivation can change without a schema migration.

## 11. Analyzer: rules, scorer, role vector

### 11.1 Episode

[`crates/bowery-analysis/src/episode.rs`](crates/bowery-analysis/src/episode.rs).
An `Episode` aggregates whatever a Phase-3 rule + scorer wants to look
at: the rooting `ProcessExec`, an `episode_id` (string uuid-shape, not
strictly v4), and a timestamp. As more event types light up
(ProcessExit, NetworkConnect, FileOpen), the episode model expands
to thread them together.

### 11.2 Rules

[`crates/bowery-analysis/src/rule.rs`](crates/bowery-analysis/src/rule.rs).
Trait-based:

```rust
pub trait Rule: Send + Sync {
    fn id(&self) -> &'static str;
    fn check(&self, episode: &Episode) -> Option<RuleHit>;
}
```

Stateless by contract — rules can be cloned/shared freely. Today's
default rules:

- `WritablePathExec` — exec from `/tmp/`, `/var/tmp/`, `/dev/shm/`,
  `/home/.../tmp/`. Medium severity.
- `ShortPath` — exe path under 8 characters (suspicious in itself).
  Low severity.

`evaluate_all(rules, episode)` runs everything and collects hits. We
don't short-circuit on first hit — multiple rules can fire on the
same episode, and we want the LLM to see all of them.

### 11.3 Baseline scorer

[`crates/bowery-analysis/src/score.rs`](crates/bowery-analysis/src/score.rs).
Single signal today: how often we've seen this binary before.

```rust
score = 1 / (1 + seen_count / k)    // k = 10 by default
```

Never-seen binary: score 1.0. Tenth time we see it: 0.5. Hundredth
time: 0.09. That curve gives "novel" execs a strong signal without
being too noisy on the long tail of medium-rare binaries.

### 11.4 Role vector

[`crates/bowery-analysis/src/role.rs`](crates/bowery-analysis/src/role.rs)
is the most mathematical bit of the analyzer.

A node's role is a 32-dim vector that summarises *what kind of host
it is*, derived deterministically from the local baseline. Two hosts
running the same workload should produce similar vectors; a web
frontend and a database server should produce dissimilar ones.

The pipeline:

1. **Histogram** the baseline's binaries into 8 path-prefix buckets:
   `/usr/bin/`, `/usr/local/bin/`, `/usr/sbin/`, `/opt/`, `/home/`,
   `/tmp/`, `/var/lib/`, `/proc/`. Normalise to sum 1.0.
2. **Project** the 8-dim feature vector into a 32-dim signature using
   a sparse random projection (Achlioptas 2003): a fixed-seed
   pseudo-random matrix with entries in `{−√3, 0, +√3}` at frequencies
   `(1/6, 2/3, 1/6)`.

The seed is `0xB05E_0000_0001_0001`, hardcoded in
[`role.rs`](crates/bowery-analysis/src/role.rs). Every node uses the
same matrix so vectors are comparable across the fleet. Bumping the
seed would force a fleet-wide recomputation — which is intentional;
that's how we'd rotate the projection if we ever needed to.

### 11.5 Why a deterministic projection

We could've used an LLM-derived embedding. We didn't because:

- It's reproducible across fleet versions.
- It's debuggable — given a vector you can trace exactly which
  binaries contributed which dimensions.
- It has no LLM dependency, so even hosts running the mock backend
  produce real role vectors.
- It's cheap: a few hundred microseconds per recomputation.

The LLM-derived alternative is in DESIGN.md's "future work" list as a
later phase that could ship alongside the deterministic baseline.

### 11.6 Peer ranking

[`crates/bowery-analysis/src/peer_select.rs::rank_by_similarity`](crates/bowery-analysis/src/peer_select.rs).
Generic over the peer-handle type:

```rust
pub fn rank_by_similarity<T>(
    local: &RoleVector,
    peers: impl IntoIterator<Item = (T, RoleVector)>,
    top_k: usize,
    min_similarity: f32,
) -> Vec<(T, f32)>
```

Cosine similarity, NaN/threshold filtering, stable sort (input order
breaks ties). Returns the top-K most similar peers with their
similarity score attached. `T` is generic so callers don't pay the
cost of pulling `bowery-mesh` into `bowery-analysis`.

## 12. LLM analyzer

### 12.1 Trait

[`crates/bowery-llm/src/backend.rs`](crates/bowery-llm/src/backend.rs):

```rust
#[async_trait]
pub trait LlmAnalyzer: Send + Sync {
    async fn analyze(&self, ctx: &AnalysisContext) -> Result<LlmVerdict, LlmError>;
    fn name(&self) -> &str;
}
```

Two implementations:

- `MockLlmAnalyzer` — deterministic, three modes: Echo (returns the
  pre-verdict's suspicion + canned actions), Quiet (always returns
  suspicion 0.0), Failing (always errors).
- `LlamaCppAnalyzer` — real Qwen3-0.6B inference, feature-gated.

The trait is `async`, so the analyzer can do whatever it wants
(network calls, blocking work via `spawn_blocking`, etc.). The
inference queue (next section) is what insulates the agent from slow
analyzers.

### 12.2 AnalysisContext

[`context.rs`](crates/bowery-llm/src/context.rs). What the LLM sees:

```rust
pub struct AnalysisContext {
    pub pre_verdict: Verdict,             // Phase 3 score + rule hits
    pub exe_path: Option<PathBuf>,
    pub exe_sha256_hex: Option<String>,
    pub args: Vec<String>,
    pub local_role_summary: String,
    pub extra: Vec<(String, String)>,     // for whisper sightings, later
}
```

The LLM gets the *aggregated* signal from Phase 3, not the raw events.
This is deliberate: the LLM's job is to *explain* and *recommend*, not
to re-derive what the deterministic layer already computed. A future
commit will populate `extra` with whisper sightings before submitting,
giving the LLM richer context for its rationale.

### 12.3 Inference queue

[`crates/bowery-llm/src/queue.rs`](crates/bowery-llm/src/queue.rs).

A bounded mpsc-driven worker that calls `analyzer.analyze` with a
per-request deadline:

```text
process_exec ──► Submitter::submit(ctx)
                       │
                       ▼ (mpsc, capacity = queue_capacity)
                  worker task
                       │
                       ▼ (tokio::time::timeout)
                  analyzer.analyze(&ctx).await
                       │
                       ▼
                  InferenceOutcome { Verdict | Failed | Shed }
                       │
                       ▼ (mpsc)
                  llm_outcomes_task ──► AgentEvent::LlmVerdict / LlmShed
```

`Submitter::submit` is non-blocking — it returns `Err(QueueFull)`
immediately if the queue is at capacity. The pipeline doesn't `.await`
on submission, so a hung LLM can't stall the event pipeline; instead
we lose verdicts on the floor and emit `AgentEvent::LlmShed` so ops
can size the queue.

Default config: capacity 32, deadline 10s. Tunable per-deployment.

### 12.4 Prompt + parse

[`prompt.rs`](crates/bowery-llm/src/prompt.rs) builds a Qwen3-style
chatml prompt with the AnalysisContext rendered as fields. We ask
the model for a JSON object with four keys:

```json
{
  "suspicion": 0.0–1.0,
  "rationale": "one or two sentences",
  "suggested_actions": ["alert", "kill_process", "snapshot"],
  "whisper_query": "optional follow-up question to peers"
}
```

[`parse.rs`](crates/bowery-llm/src/parse.rs) is lenient on framing
(we handle ` ```json … ``` ` fences, leading prose like "Here's my
assessment:") but strict on structure. Unknown action ids are
filtered out; suspicion is clamped to [0, 1]. Malformed JSON returns
`Err(BadResponse)` and the agent emits `LlmShed::Failed`.

### 12.5 llama.cpp backend

[`crates/bowery-llm/src/llama_cpp.rs`](crates/bowery-llm/src/llama_cpp.rs)
is feature-gated behind `llama-cpp` so default builds skip the C++
build dependency. It uses [`llama-cpp-2`](https://crates.io/crates/llama-cpp-2)
which compiles llama.cpp from source at build time.

Key implementation choices:

- **Dedicated thread**: `LlamaModel` and `LlamaContext` are not
  `Send`, so we put them on an OS thread (see §3.1). Tokio sees zero
  blocking work.
- **Greedy sampling**: temperature is configurable, but defaults to
  0.2 with a greedy sampler. We need stable JSON output, not
  creativity.
- **Streaming UTF-8 decode**: Qwen3's tokenizer emits multibyte UTF-8
  sequences across token boundaries. We accumulate raw bytes from
  `token_to_piece_bytes(64, false, None)` and lossy-decode at the end
  rather than decode-per-token.
- **Per-call context reset**: each `run` builds a fresh `LlamaContext`
  from the model. Slightly wasteful, but it sidesteps the question
  of how to reset internal KV-cache state safely between unrelated
  prompts.

Resource budget on the test VM (Ubuntu 26.04 / kernel 7.0, 2 vCPU):

- 380 MB GGUF on disk
- ~600 MB resident
- ~50–200 tok/s on a single x86_64 core
- ~5–15s per typical Bowery prompt+response

### 12.6 The CPU-feature footgun

llama.cpp's runtime CPU dispatch can pick an AVX/AVX2 code path that
the *runtime* CPU doesn't support, even when GGML's build flags say
otherwise. The result is SIGILL with no Rust-level error — the
worker thread dies, the main thread's `oneshot::Receiver` sees the
sender drop, and you get a silent process exit somewhere shortly
after `loading Qwen3 GGUF (this is slow)`.

The fix is to build with `RUSTFLAGS="-C target-cpu=native"`, which
flips llama-cpp-sys-2's `GGML_NATIVE=ON` and rebuilds llama.cpp for
the exact CPU. Safe whenever build host == run host (the typical case
for an in-place dev iteration on the VM); explicitly *not* safe if
you build on a beefier CPU and ship the binary to a smaller one. The
production packaging path will need a `target-cpu=x86-64-v2` style
baseline.

`xtest run-agent` sets `RUSTFLAGS=-C target-cpu=native` automatically
when building with `llm-llama-cpp`. If you build the agent by hand,
remember to do the same on hosts without AVX/AVX2.

## 13. Whisper Q&A

### 13.1 Two-tier privacy fingerprints

[`crates/bowery-whisper/src/fingerprint.rs`](crates/bowery-whisper/src/fingerprint.rs).

The whispering protocol's privacy goal: a peer can confirm "I saw
something like that" without leaking what they've actually seen to
anyone who hasn't already independently observed the same artifact.

Two tiers:

- **Tier-1**: 8 bytes = first 8 bytes of `SHA256(domain ‖ sha256)`.
  Domain is `b"bowery/whisper/tier1/v1"`. Collidable on purpose: ~1 in
  2^64 chance two artifacts share a tier-1, so seeing a tier-1 in a
  peer's bloom advert tells you only that they've seen *something*
  with that 8-byte hash. Cheap to gossip.
- **Tier-2**: the original 32-byte sha256. Released only inside an
  encrypted whisper capsule, after both sides agreed the tier-1 hint
  is worth chasing.

Phase 5 implements tier-1 + the Q&A protocol. Tier-2 escalation lands
in a follow-up.

### 13.2 Bloom filter

Same module. Standard counting-free filter with double-hashing
indices: from a single 64-bit input `h`, we treat the high 32 bits as
`h1` and the low 32 bits as `h2`, then index `(h1 + i*h2) mod
bit_count` for `i ∈ 0..k`. This avoids extra hashing per insert; with
default `k=6` and `bit_count=2^16` it gives ~1% FP rate at ~6800
inserted items.

The advert *is* on the wire (Phase 5 polish, see §13.6):
[`bloom_publisher.rs`](crates/bowery-agent/src/bloom_publisher.rs)
periodically rebuilds a filter over the local baseline's tier-1
fingerprints and publishes it to mesh KV. Askers consult that filter
before dialling — a `false` bit at a candidate's tier-1 index proves
the peer hasn't seen the artifact, so we skip them. False positives
flow through to a normal Q&A round-trip; false negatives don't
exist by construction.

### 13.3 Asker / Responder

[`crates/bowery-whisper/src/qa.rs`](crates/bowery-whisper/src/qa.rs).

Wire pattern: one connection, two unidirectional QUIC streams.

```text
Asker                                    Responder
  │  open_uni { sealed Question }   ─►     │
  │  ◄─  open_uni { sealed Answer }        │
```

`ask(conn, sealer, verifier, question, timeout)`:

1. Seal the Question with our identity.
2. `conn.send_envelope(...)` — opens a uni stream, writes the framed
   bytes, finishes, awaits `stopped` so the peer has time to read
   before we drop.
3. `conn.recv_envelope().await` — accepts the responder's uni back.
4. Verify the envelope (signature + replay + skew).
5. Match the body type, episode_id, tier1_fp against what we asked
   (defends against responders mixing up multiplexed queries).
6. Return the typed Answer.

All of step 2–5 wrapped in `tokio::time::timeout(timeout, ...)`. A
peer that never replies trips the timeout cleanly without leaking
state.

`answer_one(conn, sealer, verifier, lookup, note)`:

1. `conn.recv_envelope().await` — read the inbound Question.
2. Verify the envelope.
3. Validate Question fields (tier1_fp length, episode_id length).
4. Drop expired questions silently (TTL is absolute milliseconds).
5. Run the caller's `lookup` closure to find local sightings.
6. Build an Answer that echoes the asker's `episode_id` and
   `tier1_fp`, send sealed.

`lookup` is a closure so the agent can wire it to the baseline scan
(see §10.3) and tests can pass a fake.

### 13.4 Agent integration

[`crates/bowery-agent/src/whisper_qa.rs`](crates/bowery-agent/src/whisper_qa.rs).

The pipeline emits `WhisperQaTrigger { episode_id, sha, suspicion }`
when a verdict crosses `whisper.qa.threshold`. The whisper-QA task
receives them on an mpsc, and for each:

1. Compute the tier-1 fingerprint from the sha.
2. Compute the local role vector (cheap; recompute per round).
3. Snapshot live mesh peers, drop unpinned and self.
4. Decode each peer's published role vector; drop peers without one.
5. `peer_select::rank_by_similarity` → top-K most similar peers.
6. `futures::future::join_all` over per-peer dial+ask, with
   per-peer timeout.
7. Aggregate replies into a `WhisperContext { tier1_fp, peers,
   total_seen_count, corroborating_peers }`.
8. Compute the quorum verdict and, when confirmed, append a
   superseding alert (§13.5).
9. Emit `AgentEvent::WhisperContextReady`.
10. Stash the context against `episode_id` so the LLM analyzer can
    pick it up when it dequeues that episode.

Each round runs in its own `tokio::spawn` so a slow peer can't block
the next trigger, bounded by a `whisper.qa.max_concurrent_rounds`
semaphore. A full semaphore *sheds* the trigger rather than queueing
it: a late confirmation is worth less than a responsive agent, and
the underlying alert has already been delivered either way. The aggregator is liberal on errors — a peer that
times out or fails the dial just gets `sighting: None` in the result;
the rest of the round proceeds.

The responder side lives in [`crates/bowery-agent/src/agent.rs::handle_connection`](crates/bowery-agent/src/agent.rs):
when an inbound envelope's body is `Question`, we run a baseline scan
in `spawn_blocking` and reply. Same connection, same envelope crypto.

Inbound questions are rate-limited per authenticated sender
(`RateLimit::whisper_qa`, 1/s sustained, burst 10) because each one
costs an O(baseline) scan, and expired questions — `ttl_ms` is an
absolute deadline — are dropped before that scan runs.

The asker pre-flight (Phase 5 polish): before each dial, look up the
peer's published bloom advert in mesh KV and check if our tier-1 hits
*any* of the advertised filter bits. If not, skip — the peer can't
have seen the artifact. This is the only place in the agent that
shortcuts a network round-trip on a probabilistic structure; the
correctness argument is one-sided (no false negatives) so worst-case
we lose a single peer's `total_seen_count` contribution.

**The pre-flight stands down when `whisper.qa.quorum > 0`**, for two
reasons that both matter:

- It would skip exactly the peers a quorum needs. Confirmation counts
  peers that have *never* seen the binary, and the filter removes
  precisely those from the round — left enabled, `peers_unseen` would
  sit at ~0 and nothing could ever confirm.
- Bloom adverts ride plain chitchat KV gossip with no envelope and no
  signature. As a dial-avoidance hint a forged advert costs one
  skipped query; as quorum evidence it would let anyone who can reach
  the mesh manufacture CONFIRMED alerts. Confirmation is built only
  from signed `Answer` envelopes.

### 13.5 Quorum-confirmed alerts

A peer answering `seen_count > 0` means *"I have this binary too"* —
that is **prevalence**, and prevalence argues the binary is a normal
fleet artifact, i.e. more benign. So confirmation is driven by the
opposite signal: peers that report **never seen it**. Of the peers
actually asked:

| bucket | meaning | counts toward quorum |
| --- | --- | --- |
| `peers_unseen` | replied, `seen_count == 0` | **yes** |
| `peers_seen` | replied, `seen_count > 0` | no (argues benign) |
| `peers_no_reply` | timeout / dial failure | no — silence isn't evidence |

Confirmed when `peers_unseen >= whisper.qa.quorum`. Both signals are
reported so an operator can tell "nobody has this" from "everybody
has this" rather than being handed a single number.

Confirmation arrives as a **second, superseding alert** for the same
`episode_id`, not an edit of the first. The original alert is appended
before the round starts, the inbox has no update path, and operators
drain it with a monotonic cursor — mutating an already-delivered alert
would be invisible to anyone who had read past it. The LLM refinement
path establishes the same supersede-by-`episode_id` pattern, and
consumers (console, CLI) dedup on that key.

Operator surface: `confirmed` / `peers_asked` / `peers_unseen` /
`peers_seen` columns on `bowery_alerts` (NULL when no round ran), a
`conf` badge column plus red-bold row highlight in the console alerts
pane with the full breakdown in the detail overlay, and a `mesh:` line
in `bowery alerts` human output / a `confirmation` object in its JSON.

Out of scope for now, and deliberately: gating *enforcement* on
quorum. `DESIGN.md` specifies hard actions requiring standing operator
authorization or k-of-n quorum, but the response engine never receives
a `WhisperContext`. This work makes the signal available and
operator-visible first.

### 13.7 Append-only event log

[`crates/bowery-eventlog`](crates/bowery-eventlog/src/lib.rs) +
[`eventlog_writer.rs`](crates/bowery-agent/src/eventlog_writer.rs).

The baseline stores *aggregates* — how many times a sha has been seen,
which parent spawned which child — which answers "is this normal here?"
but folds away the individual observations, so it cannot reconstruct a
timeline. The event log keeps the observations.

**Ordering: record first, analyse second.** `process_event` writes to the
log before dispatching to the analyzer, because the value of a history is
that it contains the things nobody thought were interesting at the time.
It is also the only retention for `ProcessExit` / `NetworkConnect` /
`FileOpen`, which have no scoring path and were previously produced by
the eBPF loader and dropped.

**Never block detection.** The handle is a bounded channel written with
`try_send`. A full queue *drops* — an fsync stall must not become a
detection stall — but every drop is counted and surfaced via
`bowery_eventlog_status.dropped`, because a silent gap looks exactly like
a quiet host. Writes are batched with `recv_many`: a quiet host commits
one row at a time, a busy one amortises the transaction across hundreds,
with no timer to tune.

**Retention** applies both an age bound and a hard row ceiling, whichever
bites first. The row ceiling is the one that protects a small disk — age
alone is unbounded, since an exec storm can write more in an hour than a
quiet week. Trimming is by `seq`, not timestamp: `seq` is the true append
order, and a backwards clock step (NTP, a VM resuming) would make a
timestamp-ordered trim delete the wrong rows.

**Query path.** Unlike every other Bowery table, `bowery_events` is not
materialised. `BoweryTable::register` runs *before* the SELECT-only
authorizer is installed, so it `ATTACH`es the log file `mode=ro` and
creates a TEMP view over it — queries then use the log's own indexes and
registration is O(1) rather than O(rows). Two SQLite constraints shape
this: a view in `main` may not reference an attached database (`temp` is
the exemption), and the read-only attach is what enforces immutability at
registration time, before the authorizer exists.

Checkpointing is about bounding WAL growth, **not** visibility: a
read-only attach does see un-checkpointed rows, because reader and writer
share the `-shm` index. `crates/bowery-eventlog/tests/attach_probe.rs`
pins that, since the opposite would silently turn the maintenance
interval into a query-lag window.

### 13.8 Revocation propagation

`RevokePush` mirrors `YaraPush`'s transport (operator command, TTL,
per-peer relay piping sealed reports back), with one structural
difference that simplifies the security argument: **the payload
authorises itself.** A `Revocation` carries an operator signature over
its own fields, so every agent it reaches verifies it directly rather
than trusting the chain of peers that relayed it. A compromised relay
can therefore *drop* a revocation — it cannot forge one, and cannot use
the relay path to eject healthy agents. Dropping is the residual risk,
which is why `bowery_revocations` is queryable fleet-wide: convergence
is checked, not assumed.

Propagation terminates on the revocation store rather than a separate
seen-set. Revocations are permanent, so `insert` returns "new" exactly
once per identity, and an agent forwards only what was new — a flood
over a cyclic peer graph converges instead of echoing. `ttl` (clamped to
`MAX_REVOKE_TTL = 8`) remains as an independent structural bound.

Eviction happens inline on receipt rather than waiting for the next
gossip tick, so the window between "this peer is known compromised" and
"we stop trusting it" is as close to zero as the code allows.

### 13.6 Bloom advert publisher

[`crates/bowery-agent/src/bloom_publisher.rs`](crates/bowery-agent/src/bloom_publisher.rs).

A periodic background task (interval from `[bloom]` config). Each
tick:

1. `Baseline::for_each_binary` scans every binary's sha256.
2. For each, derive its tier-1 fingerprint, insert into a fresh
   `BloomFilter`.
3. Encode the bit array + epoch + (`bit_count`, `k`) parameters and
   `mesh.set_state(KEY_BLOOM_ADVERT, ...)`.
4. Emit `AgentEvent::BloomAdvertPublished` with the inserted count
   for dashboards.

Off-bus rebuild — the publisher reads the baseline through the same
read-only API as everything else, so no extra locking. Filter
parameters are part of the published payload so an asker doesn't need
to know what the responder is using.

## 14. Operator inbox and Subscribe

### 14.1 Why an inbox

DESIGN.md §10.2 specifies a per-operator alert inbox per agent. The
goal: a roaming operator (laptop, intermittent connectivity) can
connect to *any* agent and receive every alert addressed to them since
their last cursor.

Phase 6a's simplification: a single shared inbox per agent (not per
operator). Authorisation is enforced at Subscribe-time — the
envelope's sender must be on the configured `[operators]` list. We'll
revisit the per-operator partition when there's a reason to (Phase 6b
or later).

### 14.2 The ring

[`crates/bowery-agent/src/inbox.rs`](crates/bowery-agent/src/inbox.rs).

Bounded VecDeque under a Mutex. Two operations:

- `append(alert)` — push back; if at capacity, pop front. Returns
  the new length.
- `read_since(cursor_ms, max_items)` — sweep expired entries lazily
  (TTL applied on read), then collect every alert with `ts >=
  cursor_ms`, capped at `max_items`. Returns `(items, new_cursor)`
  where `new_cursor = max(items[].ts) + 1` or echoes the input if
  empty.

The cursor is monotonic-by-construction and durable across operator
reconnects. An operator dialing a *different* agent will see only that
agent's alerts (until cross-agent replication lands), but the cursor
contract still holds.

### 14.3 Subscribe handler

[`agent.rs::respond_to_subscribe`](crates/bowery-agent/src/agent.rs).

Two layers of authentication for an inbox drain:

1. **TLS handshake**: `PinnedCertVerifier` accepts the operator's
   cert because the operator's pubkey is in the composite resolver.
2. **Envelope verification**: same — the composite resolver finds the
   operator's verifying key, signature checks out.
3. **Operator-only check**: before responding, we ask the
   `operators` resolver (without `KnownNeighbors`) whether this
   sender is an operator. A pinned peer agent's signature would have
   passed the previous two checks but fails this one.

That third check is what stops a peer agent from drainin operator
inboxes if it gets MITM'd or compromised — defence-in-depth on top of
mTLS pinning.

### 14.4 Alert authoring

[`agent.rs::process_exec`](crates/bowery-agent/src/agent.rs) builds
the Alert when `verdict.suspicion >= alerts.threshold`:

```rust
Alert {
    originator_fp: fingerprint.as_bytes().to_vec(),
    episode_id: verdict.episode_id.clone(),
    exe_sha256_hex: sha_to_hex(&sha),
    exe_path: exec.exe_path.map(|p| p.display().to_string()),
    suspicion: verdict.suspicion,
    rationale: first_rule_message(&verdict).unwrap_or(...),
    suggested_actions: vec![],   // TODO: from LLM verdict
    ts_unix_ms: current_unix_ms(),
    backend: backend_label,
}
```

We emit on the *pre-verdict* so an alert exists immediately, even
when the LLM is shed or slow. The LLM-outcomes bridge then *re-emits*
a refined Alert when the model's verdict lands, carrying the
rationale + `suggested_actions` (see [`agent.rs::handle_llm_outcome`](crates/bowery-agent/src/agent.rs)).
Operators see two entries per episode_id; ops dashboards dedup on
episode_id at display time if they want a single record. The LLM may
have lowered the suspicion below `alerts.threshold` — in that case we
don't append the second entry.

## 15. Operator CLI

[`crates/bowery-cli/src/main.rs`](crates/bowery-cli/src/main.rs).
Single binary, `bowery`. Subcommands:

| Subcommand | Module |
|---|---|
| `key {generate, fingerprint, info}` | inline in main.rs |
| `doctor` | [`doctor.rs`](crates/bowery-cli/src/doctor.rs) |
| `alerts tail` | [`alerts.rs`](crates/bowery-cli/src/alerts.rs) |
| `model {list, fetch}` | [`model.rs`](crates/bowery-cli/src/model.rs) |
| `audit verify` | [`audit.rs`](crates/bowery-cli/src/audit.rs) |
| `exec sql` | [`exec.rs`](crates/bowery-cli/src/exec.rs) |

### 15.1 doctor

A read-only host-readiness check: kernel version, BTF presence,
BPF-LSM in `/sys/kernel/security/lsm`, bpffs mount, `lsm=` cmdline,
and a CONFIG check via `/proc/config.gz` or `/boot/config-$(uname
-r)`. JSON output via `--json`, exit code 0 ready / 1 not.

This is the only subcommand that reads the host filesystem. It's
intentionally root-free — operators run it before deciding whether a
host is a viable target.

### 15.2 alerts tail

[`alerts.rs`](crates/bowery-cli/src/alerts.rs) builds a transient
QUIC endpoint on a loopback ephemeral port, dials the configured
agent's whisper port with a `PinnedCertVerifier::expecting(target)`,
sends a sealed `Subscribe { since_unix_ms, max_items: 0 }`, awaits
`Alerts`, prints. With `--follow`, sleeps for `--interval` between
batches and re-dials.

We require `--agent-fp` and `--agent-pubkey-b64` because operators
don't ride the TOFU pin store — the operator authenticates *outwards*,
and pins the agent inwards. Both come from `journalctl -u bowery-agent
| grep 'identity'` on the agent host, or from a future
`bowery agent info` lookup.

### 15.3 model fetch

[`model.rs`](crates/bowery-cli/src/model.rs). Curated registry,
hardcoded in source:

```rust
const REGISTRY: &[ModelEntry] = &[ModelEntry {
    name: "qwen3-0.6b-q4_k_m",
    url: "https://huggingface.co/unsloth/Qwen3-0.6B-GGUF/resolve/main/Qwen3-0.6B-Q4_K_M.gguf",
    sha256_hex: None,
    expected_bytes: 380 * 1024 * 1024,
}];
```

`fetch <name>`:

1. Look up the entry.
2. Resolve the cache directory (`$HOME/.bowery/models/` by default).
3. If the target file exists and validates, skip.
4. Shell out to `curl --fail --location` (or `wget --tries=3`) writing
   to `<target>.downloading`.
5. Validate: GGUF magic bytes (`GGUF`), size within ±25% of expected,
   sha256 if pinned.
6. Rename `.downloading` → `<name>.gguf`.
7. Print the `model_path = "..."` line ready to paste into agent.toml.

Why shell-out instead of a Rust HTTP client: the CLI's dependency
graph stays small, no TLS-cert-store wrangling, and curl/wget are
universally available. A future commit might switch to `ureq` or
similar if we need to push downloads over the operator key (signed
manifest fetch per DESIGN.md §11).

The validator is what saved us from a silent llama.cpp abort: a stale
HuggingFace URL had been returning HTML "Entry not found" pages, the
old curl in INSTALL.md saved that as the "model file", and the agent
crashed on startup with no error visible from Rust. The magic + size
check catches that immediately and removes the partial.

### 15.4 audit verify

[`crates/bowery-cli/src/audit.rs`](crates/bowery-cli/src/audit.rs).
Operator-side validator for the JSONL audit log the agent emits when
`[response] audit_log_path` is configured (see §16.5). Walks every
line, verifies under the host's pubkey, exits 0 on full pass and 1
on the first signature/parse failure.

The pubkey can come from `--pubkey-b64` (paste from `bowery key
info` on the agent host) or `--pubkey-from <agent identity file>`.
`--json` emits one `LineReport { line, ok, error?, episode_id?,
action_id?, engine? }` per audit line for ops dashboards.

The fail-loud-on-first-bad-line stance is deliberate: tamper
evidence is only useful if operators *act on* a mismatch. A noisy
exit code in CI / cron is the right shape for that.

## 16. Response engine

Phase 7. Three crates collaborate: [`bowery-response`](crates/bowery-response)
owns the typed [`Action`] / [`ActionOutcome`] / [`ResponsePolicy`]
types and the `ResponseEngine` trait, [`bowery-ebpf`](crates/bowery-ebpf)
adds the BPF-LSM `bprm_check_security` hook, and
[`bowery-ebpf-loader`](crates/bowery-ebpf-loader) exposes a
`BpfBlocker` userspace helper that manages the kernel-side
`BLOCKED_COMMS` map.

### 16.1 Three engines, one trait

[`crates/bowery-response/src/engine.rs`](crates/bowery-response/src/engine.rs).

```rust
#[async_trait]
pub trait ResponseEngine: Send + Sync {
    async fn execute(&self, action: &Action) -> Result<ActionOutcome, ActionError>;
    fn policy(&self) -> &ResponsePolicy;
    fn name(&self) -> &'static str;
}
```

Selected by config (`[response] engine = "noop" | "process-kill" |
"bpf-lsm"`):

- **`NoopEngine`** — observe-only. Returns `Suppressed { reason:
  "observe-only engine" }` for every permitted action, `policy
  denied` otherwise. The default; always safe to deploy.
- **`ProcessKillEngine`** — `kill(2)`-via-`nix`. Maps `KillProcess`
  to `SIGKILL` delivery. Returns `AlreadyGone` on `ESRCH` (the
  target died between LLM inference and signal delivery — *not* an
  error). Other errnos surface as `ActionError::KillFailed`.
- **`BpfLsmEngine`** — kernel-side blocking. Lives in
  [`crates/bowery-agent/src/response_bpf.rs`](crates/bowery-agent/src/response_bpf.rs)
  rather than `bowery-response` so the aya + loader dep graph
  doesn't infect the response crate.

Each engine handles only the actions it implements; non-applicable
variants return `Suppressed { reason: "<engine> doesn't implement
<action>; switch to <other-engine>" }`. That suppress-with-reason
shape (rather than an error) keeps the audit-log story uniform —
every `execute` call produces an `ActionOutcome`.

### 16.2 Action / Policy types

[`crates/bowery-response/src/action.rs`](crates/bowery-response/src/action.rs).

```rust
pub enum Action {
    KillProcess { pid: u32, episode_id: String },
    BlockExec { comm: String, episode_id: String },
}
```

Action ids on the wire (in `LlmVerdict.suggested_actions`) are
strings the LLM was prompted to choose from. `from_id(id, episode,
pid, comm) -> Option<Action>` turns those strings into typed
actions. Unknown ids return `None` so an LLM that hallucinates
`isolate_host` doesn't crash the pipeline.

[`crates/bowery-response/src/policy.rs`](crates/bowery-response/src/policy.rs)
is a deliberately tiny default-deny gate:

```rust
pub struct ResponsePolicy {
    pub allowed_actions: Vec<String>,
    pub disabled: bool,
}
```

`permits(id)` answers "may this id execute autonomously?" — `false`
when `disabled` or when `id ∉ allowed_actions`. Future work
(DESIGN.md §9.2) adds per-host conditions, ttl-bounded standing
authorisations, and signed updates; we ship strings today so the
migration is `String → struct` and not a schema overhaul.

### 16.3 BPF-LSM hook

[`crates/bowery-ebpf/src/main.rs::block_exec`](crates/bowery-ebpf/src/main.rs).

```rust
#[lsm(hook = "bprm_check_security")]
pub fn block_exec(_ctx: LsmContext) -> i32 {
    let mut comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    normalise_comm(&mut comm);
    if unsafe { BLOCKED_COMMS.get(&comm) }.is_some() {
        -1   // EPERM
    } else {
        0
    }
}
```

`bprm_check_security` is called on every `execve`. We look the
task's 16-byte `comm` up in a `HashMap<[u8; 16], u8>` and return
`-EPERM` on a hit. Loader-side, [`BpfBlocker`](crates/bowery-ebpf-loader/src/lib.rs)
attaches the program via `aya::Btf::from_sys_fs()` and exposes
`block_comm(name)` / `unblock_comm(name)` on the map.

The `normalise_comm` step zeros trailing whitespace bytes. We learned
the hard way that `echo bowery-blocked` ends up with a trailing
newline in `comm` (the kernel populates it from `argv[0]` with
shell-quoted whitespace), and a literal-bytes `HashMap` lookup misses.
Normalising at the BPF side rather than userspace means an attacker
can't sneak past by appending whitespace to their argv.

Capability-wise: `BpfLsmEngine` startup needs `CAP_BPF` +
`CAP_MAC_ADMIN` (to attach the LSM program) and a kernel built with
`CONFIG_BPF_LSM=y` and
`bpf` listed in the boot cmdline's `lsm=` enumeration. `bowery
doctor` flags any of those missing — the engine refuses to start
otherwise rather than silently downgrading. Note the shipped systemd
unit does NOT grant `CAP_MAC_ADMIN`; add it to
`CapabilityBoundingSet` when enabling this engine.

### 16.4 The response_bpf module

[`crates/bowery-agent/src/response_bpf.rs`](crates/bowery-agent/src/response_bpf.rs).

Wraps `BpfBlocker` behind a `tokio::sync::Mutex`. aya's
`HashMap::insert/remove` borrow the underlying `MapData` mutably,
so concurrent `execute()` calls would race without serialisation.
Lock hold time is microseconds (one `bpf` syscall) — contention is
irrelevant at realistic action rates.

`Action::KillProcess` returns `Suppressed` (delegated to the
process-kill engine); `Action::BlockExec { comm, .. }` calls
`blocker.block_comm(comm)` and returns `Executed { at_unix_ms }`.
Map operations that fail (e.g. map full) surface as
`ActionError::Invalid` rather than panicking.

### 16.5 Signed audit envelopes

[`crates/bowery-response/src/audit.rs`](crates/bowery-response/src/audit.rs).

Every successful or suppressed `execute` call produces an
[`AuditRecord`] which is then signed with the agent's identity to
form an [`AuditEnvelope`]. The point isn't secrecy (the operator
reading the local sink already trusts the host) — it's *tamper
evidence*. A future per-host attacker who can write the audit log
can't forge entries without the signing key, and operators can
verify a sample of envelopes against the host's pinned verifying key
to confirm the action stream wasn't selectively edited.

```rust
pub struct AuditRecord {
    pub version: u32,
    pub host_fp_hex: String,
    pub engine: String,
    pub episode_id: String,
    pub action_id: String,
    pub action: Action,
    pub outcome: ActionOutcome,
    pub recorded_at_unix_ms: u64,
}
```

Canonical encoding is `serde_json::to_vec` with fields in
declaration order. The signature covers `AUDIT_SIG_DOMAIN ||
canonical_record_bytes`, where `AUDIT_SIG_DOMAIN =
b"bowery/audit/envelope/v1"` — the per-payload domain separator
pattern (§18.5) keeps this signing context disjoint from envelope
sigs and any future Ed25519 use.

`AuditSink` is a tiny trait with two impls today:

- `NoopSink` — drop silently (the default).
- `JsonlFileSink` — newline-delimited JSON, fsynced after each line.
  Holds the file behind a mutex so concurrent action attempts don't
  interleave bytes.

The sink is `Arc<dyn AuditSink>` so tests can drop in a recording
sink without going through config-file plumbing. Operators turn it
on with `[response] audit_log_path = "/var/log/bowery/audit.jsonl"`.

`audit::record(&sink, &identity, engine_name, episode, action,
outcome)` is the single funnel from `handle_llm_outcome` — sink
errors are logged but never propagated, so a transient disk problem
can't stall the LLM-outcomes loop.

### 16.6 Why the engine lives in two crates

`bowery-response` is small and dependency-light (`async-trait`,
`nix`, `serde`, `tokio`). `BpfLsmEngine` would force the response
crate to depend on `aya` + the loader's whole graph (LLVM, btf,
mio, ...) just to expose one extra trait impl. Splitting it keeps
`bowery-response` reusable from CLI tools and tests; agents that
actually want kernel blocking pull in
[`crates/bowery-agent/src/response_bpf.rs`](crates/bowery-agent/src/response_bpf.rs)
which is gated behind the engine-selection match in the agent's
config.

## 17. Build and test infrastructure

### 17.1 The xtest script

[`scripts/xtest`](scripts/xtest) is an SSH-based driver that turns a
remote Linux VM into a transparent build/test target. It exists
because:

- WSL2 doesn't expose BPF-LSM (no securityfs).
- macOS isn't Linux at all.
- The user's primary dev machine is one of those, and we still want
  to iterate on kernel-side code.

Subcommands worth knowing:

| Subcommand | Use case |
|---|---|
| `setup` | one-time: install Rust + system deps + bpffs mount on the VM. Runs in a single `ssh -tt` session so sudo prompts once. |
| `sync` | rsync the workspace local→VM (excludes `target/` and `crates/*/target/` so VM-built BPF objects survive). |
| `build / test / clippy / fmt-check / ci` | each does sync + the named cargo command. |
| `doctor` | builds bowery-cli on the VM and runs `bowery doctor`. |
| `exec [-t] CMD` | run an arbitrary command in the workdir; `-t` allocates a pseudo-tty for sudo. |
| `push-model [NAME]` | rsync `$HOME/.bowery/models/<NAME>.gguf` to the same path on the VM. No-op when remote already has the file. |
| `run-agent [...]` | sync + (optional) push-model + build BPF + build agent + run under sudo. The one-shot dev iteration. |

The `setup` subcommand is the only place that bakes opinions about
the target — Ubuntu/Debian package names, the IPv4-forced apt config
(VirtualBox NAT IPv6 stalls), the bpffs mount + fstab persist. Other
distros are technically supported via manual setup; the script just
doesn't automate them yet.

### 17.2 The BPF subworkspace

The `crates/bowery-ebpf/` workspace is built differently from
everything else:

```toml
# crates/bowery-ebpf/Cargo.toml
[profile.dev]
opt-level = 3
debug = 2          # REQUIRED: bpf-linker derives .BTF from DWARF
overflow-checks = false
panic = "abort"

[profile.release]
opt-level = 3
debug = 2          # REQUIRED: see above
panic = "abort"
codegen-units = 1
lto = true
```

`scripts/build-ebpf` cd's into the directory and runs a plain:

```bash
cargo build --release
```

There is deliberately no `+nightly` override: the crate pins its
toolchain in `crates/bowery-ebpf/rust-toolchain.toml`
(`channel = "nightly-2026-06-01"`), and the target plus `build-std`
come from `crates/bowery-ebpf/.cargo/config.toml`.

Four things make it different from a normal Rust crate:

1. `bpfel-unknown-none` target — no std, no alloc, no OS.
2. Nightly `-Z build-std=core` — we compile core for the BPF target
   from source (it's not pre-built).
3. `bpf-linker` — the LLVM-backed linker that produces BPF bytecode.
   Installed via `cargo install bpf-linker` during setup. **Its LLVM
   major version must match the pinned nightly's** (bpf-linker 0.10.4
   ↔ LLVM 22); a floating nightly silently produces a BTF-less object.
4. `-C link-arg=--btf` — bpf-linker only emits the object's `.BTF`
   section when explicitly asked. Without BTF the agent's loader (aya
   CO-RE + the LSM program) cannot use the object, so `build-ebpf`
   verifies `.BTF` is present after the build and fails loudly if not.

The output is a single ELF file at `target/bpfel-unknown-none/release/bowery-ebpf`
that the userspace loader mmaps + parses with aya.

### 17.3 CI

`.github/workflows/` (not in scope here) runs:

1. `cargo fmt --all -- --check`
2. `cargo clippy --workspace --all-targets --features llm-llama-cpp -- -D warnings`
3. `cargo test --workspace --features llm-llama-cpp`
4. `cargo build --workspace --release`

CI doesn't build the BPF crate (no bpf-linker on hosted runners by
default) — that's validated locally via `xtest run-agent` or `xtest
build-ebpf`.

CI runs with `--locked`, so a Cargo.lock that hasn't been updated
after a dependency change fails the build. We've been bitten by this
twice; the fix is always "scp Cargo.lock back from the VM after
building there" since that's where new deps actually get added to
the lockfile.

### 17.4 Fuzz harness

[`fuzz/`](fuzz/) — separate workspace (excluded from the main one)
with three `cargo-fuzz` targets covering the wire-format hot paths:
`whisper_envelope_decode`, `sealer_open`, `audit_envelope_parse`.
The contract is "must never panic"; every parse / signature / replay
failure is a normal `Err`. See [`fuzz/README.md`](fuzz/README.md) for
how to run.

The fuzz crate keeps its own workspace because libfuzzer-sys
requires nightly + sanitizer flags and we don't want either bleeding
into the main dep graph.

## 18. Patterns we keep using

### 18.1 Owned Arc, not borrowed lifetimes

Long-lived resources are `Arc<T>` and cheaply cloned into the tasks
that need them:

```rust
let baseline = Arc::new(open_baseline(&config.baseline.path)?);
let analyzer = Arc::new(Analyzer::with_default_rules(baseline.clone()));
// ... pass analyzer.clone() / baseline.clone() to spawn_pipeline_task
```

Yes, we could carry lifetimes, but tokio tasks can't hold references
to the outer scope without `'static` bounds, and pinning the
references properly turns into a tower of `for<'a>` types nobody
enjoys. `Arc<T>` is cheap enough.

### 18.2 spawn_blocking for sync I/O on hot paths

Every SQLite call, every `enrich::sha256_file`, every baseline scan
runs in `tokio::task::spawn_blocking`. That keeps the tokio runtime's
worker threads free for actual async work and lets the OS schedule
the blocking work on dedicated blocking-pool threads.

### 18.3 broadcast::Sender for observability

`AgentEvent` is a broadcast channel. Every observable thing gets
emitted (PeerPinned, EpisodeAnalyzed, AlertEmitted, …). Tests
subscribe before triggering and assert on what they see; an eventual
`bowery follow` CLI would do the same.

Broadcast is lossy on slow consumers — that's a feature here, not a
bug. We never want a stalled subscriber to backpressure the agent.

### 18.4 Generic peer-handle types

Peer-ranking, sealed-envelope tests, and similar utilities take a
generic `T` for "whatever the caller wants back" instead of pinning
to one specific concrete type. Lets the analyzer crate stay free of
mesh dependencies, lets tests use string identifiers, and the agent
plug in `PeerInfo` at the call site.

### 18.5 Per-payload domain separators

Every signed/hashed value gets a domain prefix:

- Envelope signature: `b"bowery/whisper/envelope/v1"`
- Tier-1 fingerprint: `b"bowery/whisper/tier1/v1"`
- (Future) Bloom advert: `b"bowery/whisper/bloom/v1"`

The `/v1` suffix gives us a path to rotate the domain (and thus
invalidate everything signed under the old one) if we ever need to.
Cheap insurance.

### 18.6 Mock-first design for I/O traits

Every external integration starts with a mock implementation:

- `EventSource` → `MockEventSource`, `NoopEventSource`, then
  `BpfEventSource`.
- `LlmAnalyzer` → `MockLlmAnalyzer { Echo, Quiet, Failing }`, then
  `LlamaCppAnalyzer`.
- `FingerprintResolver` → `StaticResolver`, then `KnownNeighbors`.

The mocks aren't afterthoughts — they're the primary tool for
end-to-end integration tests. The "two agents" test runs the entire
mesh+envelope+pipeline+heartbeat surface against `NoopEventSource`,
because what's being tested is the surrounding wiring, not the BPF
events themselves.

### 18.7 `#[non_exhaustive]` … not yet

We intentionally don't `#[non_exhaustive]` our public enums. The
project is small enough that breaking match patterns on a new variant
is the right behavior — it forces every consumer to acknowledge the
new event type.

If the project grows past the point where every consumer is in this
repo, we'll revisit.

## 19. What we explicitly don't do

A few approaches we've ruled out, with reasoning:

- **No singleton state**. Every long-lived value is owned by a
  visible struct or task. No `lazy_static`, no `OnceCell` in
  application code (only in deeply-internal crypto setup).

- **No global tokio runtime**. The runtime is created in
  `main.rs::run`, owned for the life of the process, and explicitly
  passed to `block_on`. Avoids the "what runtime are we in?"
  confusion the moment you embed the agent in a different host.

- **No async traits in hot paths**. `LlmAnalyzer` is async because
  it calls out to llama.cpp; `EventSource::start` is sync because
  it just spins up the producer task. We don't async-trait every
  trait by reflex.

- **No serde on prost types**. `bowery-proto` types implement only
  prost's `Message` trait. If we want JSON for an Alert (e.g.
  `bowery alerts tail --json`), we serialize by hand or with a small
  helper. Saves a dep, keeps the wire format and the textual format
  decoupled.

- **No build.rs in the userspace crates**. Compile times are short
  enough that we don't reach for codegen. (The sole exception is
  `llama-cpp-2` which builds C++ at build time — that's why we
  feature-gate it.)

- **No HTTP server in the agent**. The agent has one listening
  socket, and it's the QUIC endpoint. Operators reach the agent over
  the same QUIC transport via signed envelopes. Adding a "management
  HTTP" surface would double the attack surface for marginal
  ergonomic gain.

- **No global config**. Every crate that needs config takes it as a
  struct in its constructor. The agent's `Config` is the union of
  the per-component configs; it's parsed once in main and passed
  through.

- **No process supervision in-tree**. We rely on systemd. The agent
  is a long-running process that exits on fatal error and gets
  restarted by the unit. No try-restart, no in-process supervision
  trees.

- **No observability framework yet**. `tracing` for logs, the
  `AgentEvent` broadcast for structured events. Metrics (Prometheus,
  StatsD) and distributed tracing are deferred until there's a real
  ops story for a deployed fleet.

## 20. Phase 8 hardening

A security audit on 2026-05-04 produced 1 critical / 14 high /
~25 medium findings across the stack. The fixes shipped in two
tiers as 13 logical commits; this section is a map of what landed
where, so readers don't have to grep `git log` to find the security
posture as of v0.1.

### 20.1 Tier 1 — fail-shut wins, immediate impact

| Finding | Fix | Files |
|---|---|---|
| **C1+H13 prompt injection** via `argv` / `exe_path` / `comm` / rule reasons | `sanitise(s, max_len)` neutralises chatml token leadins (`<|...|>` → zero-width-space split), replaces control chars with visible glyphs, truncates per-field at safe caps. | [`bowery-llm/src/prompt.rs`](crates/bowery-llm/src/prompt.rs) |
| **H2 Ed25519 lenient verify** at three call sites | Switched to `verify_strict` (RFC 8032 §5.1.7); added a malleability-test that constructs `s' = s + L`. | [`bowery-whisper/src/envelope.rs`](crates/bowery-whisper/src/envelope.rs), [`bowery-crypto/src/lib.rs`](crates/bowery-crypto/src/lib.rs), [`bowery-response/src/audit.rs`](crates/bowery-response/src/audit.rs) |
| **H3 mutex panic on poison** | `unwrap_or_else(into_inner)` recovery + `tracing::error!`. The replay-guard's bitmap is monotone, so recovering yields a valid (slightly stale) state. | [`bowery-whisper/src/envelope.rs`](crates/bowery-whisper/src/envelope.rs) |
| **M31 NaN suspicion** bypassing every threshold | `is_nan()` gate before `clamp` returns `BadResponse`; ±Inf still saturates. | [`bowery-llm/src/parse.rs`](crates/bowery-llm/src/parse.rs) |
| **M20+M21+M22 LLM channel** correctness | Bounded mpsc to the llama worker (32 deep); `analyze` honors `LlamaCppConfig.max_tokens`; doc updated to call shedding "shed-newest" honestly. | [`bowery-llm/src/llama_cpp.rs`](crates/bowery-llm/src/llama_cpp.rs), [`bowery-llm/src/queue.rs`](crates/bowery-llm/src/queue.rs) |
| **H10 pid-reuse / kill-init** risk | Forbidden-pid skip-list (0/1/2 + `std::process::id()`); pre-kill `/proc/<pid>/comm` cross-check refuses kills on critical-service comms. | [`bowery-response/src/process_kill.rs`](crates/bowery-response/src/process_kill.rs) |
| **H11 BlockExec comm-spoofing** DoSing critical services | `permits_block_exec_comm` deny-list with built-in defaults (sshd, systemd, login, etc.) plus operator extensions; `BpfLsmEngine` consults it before every `block_comm`. | [`bowery-response/src/policy.rs`](crates/bowery-response/src/policy.rs), [`bowery-agent/src/response_bpf.rs`](crates/bowery-agent/src/response_bpf.rs) |

### 20.2 Tier 2 — architectural changes

| Finding | Fix | Files |
|---|---|---|
| **H4+H5 TOFU/QUIC** resource-exhaustion | Default `bootstrap_window` 7d → 2h. New `KnownNeighborsConfig.max_pinned_peers` (default 1024) with `PinOutcome::AtCapacity`. Quinn `TransportConfig` adds `max_idle_timeout=30s`, `keep_alive_interval=10s`, `max_concurrent_uni_streams=8`. `MAX_FRAME_BYTES` 1MiB → 64KiB. | [`bowery-whisper/src/transport.rs`](crates/bowery-whisper/src/transport.rs), [`bowery-whisper/src/known_neighbors.rs`](crates/bowery-whisper/src/known_neighbors.rs), [`bowery-agent/src/config.rs`](crates/bowery-agent/src/config.rs) |
| **H7+H8 BPF map + loader** | `BLOCKED_COMMS`: `HashMap` → `LruHashMap`, capacity 256 → 4096. Loader integrity check (root-owned, mode `0o644`, no symlinks) on every candidate path. `BOWERY_BPF_OBJ_PATH` env var only honored when `BOWERY_BPF_DEV_MODE=1`. `Ebpf::load_file` wrapped in `catch_unwind`. | [`bowery-ebpf/src/main.rs`](crates/bowery-ebpf/src/main.rs), [`bowery-ebpf-loader/src/lib.rs`](crates/bowery-ebpf-loader/src/lib.rs) |
| **H9 audit log deletion-blind** | Hash-chain via new signed fields `seq: u64` + `prev_sig_hex`. `JsonlFileSink` recovers chain state on `open()`. `bowery audit verify` detects gaps and broken links. Schema bumped 1 → 2. | [`bowery-response/src/audit.rs`](crates/bowery-response/src/audit.rs), [`bowery-cli/src/audit.rs`](crates/bowery-cli/src/audit.rs) |
| **H1 envelope cross-recipient replay** | Signing input now includes `recipient_fp`; not on the wire, each side computes it locally. `Sealer::seal_for(recipient, payload)` and `Verifier::new(resolver, self_fp)`. Domain `v1` → `v2`. | [`bowery-proto/src/lib.rs`](crates/bowery-proto/src/lib.rs), [`bowery-whisper/src/envelope.rs`](crates/bowery-whisper/src/envelope.rs), [`bowery-whisper/src/qa.rs`](crates/bowery-whisper/src/qa.rs), [`bowery-agent/src/agent.rs`](crates/bowery-agent/src/agent.rs) |

### 20.3 Deferred to Phase 9

Two items the audit flagged that need bigger scope than fail-shut
fixes:

- **P9-1: race-free pidfd kill.** Tier-1 H10 closes the
  catastrophic case; the residual race (pid recycled between
  `/proc` snapshot and `kill(2)`) wants `pidfd_open` +
  `pidfd_send_signal`. Needs `pid_starttime` plumbing through
  `Action::KillProcess`.
- ~~**P9-2: H6 LSM keys on inode.**~~ **Done** — see §28c. The hook
  reads `bprm->file->f_inode` through offsets resolved from the
  running kernel's BTF rather than through aya CO-RE, which does not
  emit relocations; `block_exec_by_inode` is the resulting action, and
  it refuses rather than degrading when the kernel cannot arm it. The
  `comm`-keyed `block_exec` in §16.3 remains for hosts without BTF.

Tracking: `memory/project_phase9_remaining.md` — P9-1 only.

## 21. Phase 6b operator commands

Phase 6 originally shipped only the alert *inbox* (6a) — `bowery
alerts tail` lets operators drain alerts but they couldn't *do*
anything to an agent. The proto stubs `OperatorCommand` /
`OperatorResult` were empty bodies. Phase 6b closes that gap.

### 21.1 Wire shape

[`crates/bowery-proto/src/lib.rs`](crates/bowery-proto/src/lib.rs).

```text
OperatorCommand
  request_id  : String          (caller-chosen correlation)
  timeout_ms  : u32             (per-handler deadline)
  command     : oneof
    Sql       { sql, fanout, peers }       (11)
  forwarded_from_operator : bytes         (3; relay-pass-through)

OperatorResult
  request_id  : String          (echo)
  result      : oneof
    Error     { kind, message }       (11)
    SqlChunk  { columns, rows, end, agent_fp }  (12)
```

New commands extend the oneof — never via free-form strings, so
every command's input surface stays visible at code review. The
`request_id` lets the CLI match concurrent in-flight requests
against the same agent.

### 21.2 Agent dispatch

[`crates/bowery-agent/src/agent.rs::respond_to_operator_command`](crates/bowery-agent/src/agent.rs).

Mirrors `respond_to_subscribe`'s structure:

1. Operator-only gate — envelope-verified-as-pinned-peer is **not**
   enough; the sender must be in the configured `[operators]` set.
2. Clamp the operator's requested timeout to
   `min(request, [sql] max_timeout)` so a stolen operator key
   can't hang the host with an unbounded query.
3. Dispatch to a per-command handler. The handler streams
   `OperatorResultBody::SqlChunk` envelopes back to the operator
   on success, or returns a single `OperatorResultBody::Error
   { kind, message }` with stable programmatic kinds
   (`policy_denied`, `timeout`, `output_too_large`,
   `handler_error`, `unsupported_command`).
4. Seal the result back to the operator and emit
   `AgentEvent::OperatorCommandHandled { operator, request_id, kind }`
   for ops dashboards.

A new `OperatorCommandRouter` bundle holds the per-command handler
references; `None` for any handler means the corresponding command
returns `policy_denied` at dispatch time. This is the Phase-7
"engines as Arc<dyn>" pattern adapted to operator commands.

### 21.3 SQL handler

The Phase-9 native SQL surface (`bowery-sql` + `bowery-tables`) is
the only command body. Streaming behaviour, per-cell caps,
authorizer policy, and fan-out are documented in detail in §22.

### 21.4 Operator CLI

[`crates/bowery-cli/src/exec.rs`](crates/bowery-cli/src/exec.rs).

```sh
bowery exec sql \
    --operator-key /path/to/op.key \
    --agent-addr 10.0.0.5:9902 \
    --agent-fp <64-hex> --agent-pubkey-b64 <base64> \
    --sql 'select pid, name from processes limit 5' \
    --timeout 5s
```

The CLI wraps the exchange in `(operator_request_timeout + 2s)` so
a stalled agent doesn't hang the operator. JSON mode emits one row
per line; table mode buffers and prints on close.

### 21.5 What's deferred

- **Audit-envelope on operator commands.** The Phase-7 audit chain
  (§16.5) is per-action by design; operator commands are a
  different concept and warrant their own envelope type. A future
  follow-up will add `OperatorCommandRecord` to the audit log so
  operators can verify "what did this agent run, when, on whose
  request." For now, dispatch fires `AgentEvent::OperatorCommandHandled`
  but doesn't sign it — the signed envelope already came in
  (`OperatorCommand`) and went out (`OperatorResult`); the audit
  story is "verify those bytes against the operator's pubkey + the
  agent's pubkey."
- **More commands.** `inspect-baseline`, `list-pinned-peers`,
  `trigger-baseline-rescan`, and operator-signed grants for the
  Phase-7 response engine all extend the same pattern: add a oneof
  variant to `OperatorCommandBody`, wire a handler in the router.
- **Native SQL surface (Phase 9).** `bowery-sql` + `bowery-tables`
  ship a pure-Rust rusqlite-backed engine and a growing set of
  procfs/sysfs/etc-backed tables (`processes`, `listening_ports`,
  `users`, `systemd_units`, ...). The streaming wire path
  (`OperatorCommand::Sql` → chunked `OperatorResultBody::SqlChunk`)
  shipped in slice 6 — see [`DESIGN-NATIVE-SQL.md`](DESIGN-NATIVE-SQL.md)
  for the full slice plan, and §22 below for the implementation
  reference.

## 22. Phase 9 native SQL surface

Phase 9 builds a pure-Rust SQL surface over Bowery's host-state
view, with end-to-end signed multi-agent fan-out. The full slice
plan lives in [`DESIGN-NATIVE-SQL.md`](DESIGN-NATIVE-SQL.md);
this section is the in-tree reference for what shipped.

### 22.1 Crates

- [`crates/bowery-sql/`](crates/bowery-sql/) — async SQL engine
  on top of `rusqlite`. Each `query()` opens a fresh in-memory
  Connection, registers every table, runs the operator's SQL
  inside `tokio::task::spawn_blocking` wrapped in
  `tokio::time::timeout`, and returns
  `Vec<Row>`. Bounded by `DEFAULT_ROW_CAP` (1M) and a wall-clock
  deadline.
- [`crates/bowery-tables/`](crates/bowery-tables/) — every
  Phase-9 table impl. Each implements
  `BoweryTable { name(), register(&Connection) }`. Slice-1
  through slice-5 ship 13 tables backed by procfs / sysfs /
  /etc / utmp.

### 22.2 Default table set

| Table | Slice | Source |
|---|---|---|
| `os_version` | 1 | `/etc/os-release` (+ `/usr/lib/os-release` fallback) |
| `system_info` | 1 | `/proc/sys/kernel/{hostname,osrelease}`, `/proc/cpuinfo`, `/proc/meminfo`, `/sys/class/dmi/id/*` |
| `processes` | 2a | `procfs::process::all_processes()` (`cmdline` opt-in via `[sql] expose_cmdline`) |
| `mounts` | 2a | `/proc/self/mountinfo` |
| `kernel_modules` | 2a | `/proc/modules` |
| `interfaces` | 2a | `/sys/class/net/*` |
| `listening_ports` | 3 | `/proc/net/{tcp,tcp6,udp,udp6}` |
| `process_open_sockets` | 3 | per-pid fd-walk + inode lookup against the four protocol tables |
| `users` | 4 | `/etc/passwd` |
| `logged_in_users` | 4 | `/var/run/utmp` |
| `last` | 4 | `/var/log/wtmp` |
| `systemd_units` | 5 | unit-file walk under standard search paths |
| `crontab` | 5 | `/etc/crontab` + `/etc/cron.d/*` |

### 22.2.1 Scalar file/hash functions (final-7)

[`crates/bowery-tables/src/file_funcs.rs`](crates/bowery-tables/src/file_funcs.rs)
registers seven SQL scalar functions that take a path argument
and return file metadata or content hashes. Operator must
supply each path explicitly — no enumeration possible — which
satisfies the slice-2b safety constraint without the rusqlite
vtab boilerplate originally planned.

| Function | Returns | Notes |
|---|---|---|
| `bowery_file_exists(path)` | INTEGER 0/1 | |
| `bowery_file_size(path)` | INTEGER bytes | NULL on stat fail |
| `bowery_file_mode(path)` | INTEGER (raw `st_mode`) | |
| `bowery_file_mtime_unix(path)` | INTEGER seconds | |
| `bowery_file_owner_uid(path)` | INTEGER | |
| `bowery_file_owner_gid(path)` | INTEGER | |
| `bowery_file_sha256_hex(path)` | TEXT 64-char hex | NULL for non-regular files; reads capped at 16 MiB |

Registered with `SQLITE_DIRECTONLY` so they can't be invoked
from inside views or triggers (which the SELECT-only authorizer
already forbids anyway, but defence in depth).

### 22.3 Streaming wire format (slice 6)

Operator-facing entry: `OperatorCommandBody::Sql(SqlQuery)`. The
agent streams the response as one or more
`OperatorResultBody::SqlChunk` envelopes, each on its own QUIC
unidirectional stream:

- First chunk per agent carries the column names; subsequent
  chunks leave them empty.
- `end = true` terminates that agent's stream.
- `agent_fp` (slice-7 onwards) tags rows with the producing
  agent.
- 256 rows per chunk by default
  ([`SQL_CHUNK_ROW_LIMIT`](crates/bowery-agent/src/agent.rs)).
- Errors collapse to a single `OperatorResultBody::Error` —
  decoder treats either form as a stream terminator.

### 22.4 Multi-agent fan-out via relay (slice 7 + final-1)

`SqlQuery { fanout: true, peers: [...] }` turns the dialled
agent into a relay: it runs the query locally and dispatches
`fanout: false` copies in parallel to its pinned peers
(filtered by the `peers` array, or all of them if empty),
multiplexing per-peer chunks back to the operator. Cycle
prevention is enforced both at the relay (always sets
`fanout: false` on outbound) AND at peer-side receive (rejects
forwarded commands with `fanout: true` as `policy_denied`).

Per-peer dial / send / receive failures collapse to a synthetic
relay-signed terminal chunk for that peer, so the operator-side
decoder always observes EOF for every peer it expected.

**Mesh prerequisites + completion terminator (tailnet deploy
work).** The relay dispatches only to peers that are *both*
discovered in the gossip mesh *and* pinned, dialing each peer's
gossiped `whisper_addr` — so the fleet must actually form a mesh
with routable advertised addresses first: `[mesh] advertise_addr`,
`[whisper] advertise_addr` (bind a wildcard for boot robustness,
advertise the routable `100.x`), and `[mesh] seeds`. The
step-by-step bring-up is [`deploy/remote/MESH.md`](deploy/remote/MESH.md).
Because the operator can't know the peer count ahead of time, the
relay emits an explicit **fan-out completion terminator** once every
peer has finished (and even with zero peers) — a chunk with an empty
`agent_fp` and `end = true`, which no real chunk carries — and the
operator ends its read loop on it. Previously the operator waited for
the QUIC connection to close, which the relay never did, so every
fan-out blocked until the client's exchange timeout. Related: the
operator client binds the *unspecified* address, not `127.0.0.1`, so
cross-host dials egress the correct interface (a loopback bind reaches
only locally-deliverable addresses, silently stranding every remote
agent).

**End-to-end signing (Phase-9 final-1):** the operator signs an
`OperatorAuthorization` (operator_fp + ts + request_id +
command_digest) and embeds it in the outbound command's
`forwarded_from_operator` field. The relay copies the
authorisation verbatim into each peer-bound command. Peers
verify the operator's signature against their own `[operators]`
set and seal `SqlChunk` envelopes **directly for the operator's
fingerprint**. The relay forwards peer envelope bytes verbatim
via `BoweryConnection::send_envelope`. Relay can drop peer
chunks but cannot forge or tamper with their content.

**Fleet-config requirement:** Each peer must list the original
operator in its `[operators]` config. The relay does **not**
need to be in any peer's `[operators]` — it's authenticated as
a pinned-peer (KnownNeighbors) sender, and its forwarding right
comes from carrying the operator's signed delegation. A
compromised relay key cannot grant SQL authority over peers.

### 22.5 Bonus tables (slice 8)

Seven agent-state-aware tables plumbed in via
`Sql::with_extra_table(Arc<dyn BoweryTable>)`. They live under
[`crates/bowery-agent/src/sql_tables.rs`](crates/bowery-agent/src/sql_tables.rs)
because they hold `Arc`s to agent state (`KnownNeighbors`,
`Baseline`, `AlertInbox`, audit-log path, mesh peer watch) that
`bowery-tables` intentionally doesn't depend on:

- `bowery_peers` — fingerprints in the agent's KnownNeighbors (the
  *pinned* set).
- `bowery_mesh_peers` — peers currently *discovered* over the gossip
  mesh (fingerprint_hex, whisper_addr, agent_version, pinned,
  has_role_vector, has_bloom_advert), backed by the mesh peer
  watch-channel. `pinned = 1` when a discovered peer is also in
  KnownNeighbors; querying it on agent A confirms A is discovering
  agent B. Added with the tailnet mesh deploy work.
- `bowery_monitor_rules` — the operator's `[monitor]` file/process watch
  rules, so "what is this agent watching?" is answerable over SQL.
- `bowery_yara_rules` — YARA rules distributed to this agent, so "did my
  rule reach every node?" is answerable with `--fanout`.
- `bowery_baseline_binaries` — every SHA the baseline has seen.
- `bowery_alerts` — alerts in the in-memory inbox.
- `bowery_audit` — Phase-7 audit log entries (parsed JSONL).

These expose Bowery's own awareness of the mesh — questions a
generic host-state SQL surface can't answer.

### 22.6 Operator CLI (slice 6 + 8 + final-8)

```sh
# Single agent
bowery exec sql --operator-key ... --agent-addr ... --agent-fp ... --agent-pubkey-b64 ... \
    --sql 'SELECT pid, name FROM processes LIMIT 5'

# Multi-agent fan-out via relay (auto-loads ~/.bowery/peers.toml)
bowery exec sql ... --fanout --sql 'SELECT * FROM bowery_alerts WHERE suspicion >= 0.95'

# Output formats: tsv (default, streams), json (streams), table (buffers)
bowery exec sql ... --format=table --sql 'SELECT * FROM listening_ports'

# File / hash via scalar functions (final-7) — operator supplies path
bowery exec sql ... --sql "SELECT bowery_file_sha256_hex('/usr/bin/sshd')"

# Operator peer manifest (final-8) — pre-loaded for fan-out verification.
# Optional --addr records a whisper dial address, enabling `peers check`.
bowery peers add --name web-1 --fp <hex> --pubkey-b64 <b64> --addr 100.111.5.24:9902
bowery peers list
bowery peers check --operator-key ~/.bowery/operator.key   # dial each addressed peer, report reachability
bowery peers remove --fp <hex>
```

Forming the mesh that `--fanout` relays across (seeds + routable
advertise addresses + pinning) is covered in
[`deploy/remote/MESH.md`](deploy/remote/MESH.md).

`bowery doctor` (slice 8c) runs `SELECT 1` against an in-process
`bowery-sql` engine, catching build-time SQL surface breakage
without requiring a live agent.

### 22.7 Resource caps

- Per-query row cap (`DEFAULT_ROW_CAP = 1M`) — defends against
  a query joining every table to itself.
- Per-query wall-clock timeout, clamped to
  `[sql] max_timeout` agent-side so a stolen operator key
  can't pin the host indefinitely. SQLite progress-handler
  cancellation (final-6) interrupts the running query within
  ~1024 VDBE ops of timeout, releasing the blocking-pool slot.
- Per-cell cap: `MAX_CELL_BYTES = 16 KiB` (final-3). Wide cells
  truncate to a `Text("<truncated N bytes>")` placeholder.
- Per-chunk size: 256 rows, well under `MAX_FRAME_BYTES`.
- Concurrency cap: `[sql] max_concurrent_queries = 4` (final-5)
  semaphore-gates concurrent operator queries.
- Per-peer fan-out tasks share a 64-slot mpsc channel; back-
  pressure forces slow peers to wait for the relay→operator
  link. The whole fan-out runs in a `JoinSet` that aborts on
  operator disconnect.
- Per-operator fan-out rate limit (final-2): token bucket
  keyed on operator fp, 1 token / 5 s, burst 6. Bucket-empty
  returns `OperatorError { kind: "rate_limited" }`.
- `bowery_audit` table reads through `BufReader` capped at
  64 MiB so an operator query can't OOM the agent against a
  multi-GB audit log.

### 22.8 Security audit findings — every CRIT/HIGH/MEDIUM closed

A two-pass security audit
([`SECURITY-AUDIT-PHASE9.md`](SECURITY-AUDIT-PHASE9.md)) surfaced
15 findings. As of the Phase-9 final-1..8 rollout, every CRIT,
HIGH, and MEDIUM finding is fixed (or partly fixed where the
remaining gap is documentation rather than security). Highlights:

- **F-1/F-2/F-3** End-to-end peer→operator signing via
  `OperatorAuthorization`. Peers seal `SqlChunk` envelopes for
  the original operator's fp; the relay forwards bytes verbatim
  and can no longer forge or tamper with peer rows. Cycle
  prevention is enforced both at relay-outbound and peer-receive
  sides.
- **F-4** `FanoutRateLimit` token bucket (1 / 5 s, burst 6) per
  operator fp.
- **F-6** `MAX_CELL_BYTES = 16 KiB` cap in `encode_row`; oversize
  cells become `Text("<truncated N bytes>")`.
- **F-8** `processes.cmdline` opt-in via `[sql] expose_cmdline =
  false` default.
- **F-9** Baseline mutex now snapshot-then-iterate.
- **F-12** `bowery_audit` `BufReader`-capped at 64 MiB.
- **F-13** `[sql] max_concurrent_queries = 4` semaphore.
- **F-14** SQLite `progress_handler` polls a shared `AtomicBool`
  for cooperative cancellation.
- **F-15** SQLite `set_authorizer` allows Select/Read/Function
  /Recursive only, denies Attach/Pragma-writes/Drop/etc.
- **F-16** Per-peer fan-out tasks live on a `JoinSet`,
  `abort_all()` on operator disconnect.

Slice 2b's `file` / `hash` shipped as **scalar functions**
(`bowery_file_size`, `bowery_file_sha256_hex`, etc.) instead of
tables — operator supplies the path, no enumeration possible.

### 22.9 What's deferred (LOW priority)

- **F-7** EOF accounting in fan-out decoder (operator UX —
  distinguishing "all peers reported" from "relay disconnected
  early"). Tracked as an observability follow-up.
- **F-17** Per-peer fan-out warning log rate limit. Currently a
  malicious operator can cause a few warn lines per failed
  query; a token bucket on the warn emission would close the
  log-disk DoS edge.

## 23. Phase 10 — persistent peer-connection pool

Phase 10 splits Bowery's whisper transport into three slices, all
shipped. The goal: agents in restrictive networks (no inbound
9902/UDP) participate fully by riding a persistent outbound
connection that one of their pinned peers initiated.

### 23.1 `PeerConnections` (slice 1)

[`crates/bowery-whisper/src/pool.rs`](crates/bowery-whisper/src/pool.rs).

Cache of `BoweryConnection`s keyed by `Fingerprint`. API:

- `PeerConnections::new(endpoint)` — pool with no inbound
  handler (operator CLI use).
- `PeerConnections::with_handler(endpoint, InboundHandler)` —
  agent use; runs `handler(fp, conn)` on every fresh outbound
  dial.
- `get_or_dial(peer_fp, addr, verifier)` — returns a cached
  connection (verifying it isn't closed) or dials fresh.
- `invalidate(peer_fp)` — drop after a known send failure.

Eviction is multi-level:

- **Lazy on get**: `BoweryConnection::is_closed()` checked
  before returning a cached entry.
- **Background watcher**: per-entry tokio task awaits Quinn's
  `closed()` future and removes the slot. Watcher dedupes
  against `stable_id` so a racing redial doesn't lose its
  successor.
- **Explicit invalidate**: caller-driven for "send failed"
  paths.

Quinn's existing 10 s keep-alive + 30 s idle timeout (see
[`hardened_transport_config`](crates/bowery-whisper/src/transport.rs#L261)) keep idle pooled connections alive
without protocol changes.

### 23.2 `InboundHandler` on outbound (slice 2)

The agent constructs an `InboundHandler` closure that captures
the same Arcs `handle_connection` needs (verifier, sealer,
baseline, inbox, op_router, events). On every fresh outbound
dial, the closure spawns a new `handle_connection` task on the
dialed connection. Net effect: A → B outbound connection serves
both directions. B can `open_uni` / `open_bi` at any time and
A's task picks it up — B never has to dial A's listener.

This is the load-bearing change for "no inbound port required."
Agents behind firewalls can still participate as long as they
can dial *one* reachable seed; that connection then carries
peer-initiated whispers back through the same socket.

### 23.3 Bidi streams for whisper Q&A (slice 3)

Slice 2 introduced a race: the asker's `recv_envelope` (call to
`accept_uni`) competes with the inbound handler's
`accept_uni` for the responder's reply. Solution: migrate Q&A
to a single bidirectional stream so the response shares the
exact stream the question went out on.

[`crates/bowery-whisper/src/transport.rs`](crates/bowery-whisper/src/transport.rs):

- `BoweryConnection::request(question_bytes) -> Result<answer_bytes>` —
  open_bi → write question → finish send half → read one
  length-prefixed reply on the same stream.
- `BoweryConnection::accept_request() -> Result<(bytes, Reply)>` —
  pairs with `request`; returns the question bytes and a
  `Reply` send-half wrapper.
- `Reply::send(answer_bytes)` — writes the reply, finishes,
  waits for the asker to consume before letting the connection
  drop.

[`crates/bowery-whisper/src/qa.rs`](crates/bowery-whisper/src/qa.rs) wraps
these. `qa::ask` calls `conn.request`; `qa::answer_one` accepts
via `conn.accept_request` and replies through the `Reply`.

[`crates/bowery-agent/src/agent.rs::handle_connection`](crates/bowery-agent/src/agent.rs)
splits into two parallel readers:

- `handle_uni_stream_loop`: heartbeats, `Subscribe`,
  `OperatorCommand`. Replies still ride fresh outbound uni
  streams.
- `handle_bi_stream_loop`: whisper `Question`. Reply rides the
  same stream via `Reply::send`.

The loops run via `tokio::join!`; a single connection close
exits both.

### 23.4 Heartbeat + Q&A both reuse the pool

[`agent::send_heartbeat`](crates/bowery-agent/src/agent.rs) and
[`whisper_qa::ask_one`](crates/bowery-agent/src/whisper_qa.rs) call
`pool.get_or_dial(peer.fp, peer.whisper_addr, verifier)` instead
of `endpoint.dial(...)`. Transport-shaped errors invalidate the
entry so the next round redials cleanly.

Operator transport (`bowery exec sql`, `bowery alerts tail`) is
single-shot by design and stays out of the pool.

### 23.5 What's deferred

- **Outbound-only mode**. Config flag (`[whisper] accept = false`)
  to disable the inbound listener entirely for fully-firewalled
  agents. Currently every agent still binds 9902/UDP — slice 4.
- **Per-fingerprint dial-in-progress slot**. Two concurrent
  callers asking for the same fp while the cache is cold both
  dial; one wins the insert. Heartbeats are 30 s apart per peer
  so the dedupe window almost never fires; revisit if
  empirically it does.

## 24. Operator console (`bowery-console`)

Phases C-1..C-6. Ratatui workspace built on top of the
[`bowery-cli`](crates/bowery-cli/) library refactor. Eight panes,
schema-aware chatbot, embedded operator handbook.

### 24.1 `bowery-cli` lib + bin (C-1)

`bowery-cli` exposes a public library
[`bowery_cli`](crates/bowery-cli/src/lib.rs) re-exporting:

- `alerts` (`run`, `poll_once`)
- `audit` (`verify`)
- `doctor` (`run`, `Report`, `Check`, `Status`, `Verdict`,
  `print_human`)
- `exec` (`sql`, `SqlSink`, `make_stdout_sink`, `CollectSink`,
  `CollectedRow`, `SqlFormat`)
- `model` (`fetch`, `list`, `default_out_dir`)
- `peers` (`Manifest`, `Peer`, `default_path`, `add`, `list`,
  `remove`)

`exec::sql` takes a `&mut dyn SqlSink`. The binary passes
`make_stdout_sink(format, fanout)`; the console passes
`&mut CollectSink::default()` and reads `sink.rows` /
`sink.columns` after the await.

### 24.2 Console architecture

[`crates/bowery-console/`](crates/bowery-console/).

```
src/
  main.rs       — clap arg parsing, model auto-fetch prompt,
                  ratatui terminal lifecycle.
  app.rs        — App state, render loop, EngineEvent dispatch,
                  global hotkey routing.
  input.rs      — single-line editor with persisted history
                  (~/.bowery/console-history).
  palette.rs    — `:command` parser.
  theme.rs      — centralized styles.
  panes/
    query.rs    — SQL REPL (uses CollectSink).
    alerts.rs   — live tail (5 s poll via alerts::poll_once).
    map.rs      — 1-hop topology tree (SELECT FROM bowery_peers).
    audit.rs    — bowery_audit snapshot.
    peers.rs    — manifest CRUD via bowery_cli::peers.
    doctor.rs   — local doctor::run() + remote `SELECT 1`.
    chat.rs     — Gemma 4 dialog + draft-SQL extraction.
    chat_system_prompt.txt — schema-grounded prompt with examples.
    help.rs     — renders docs/CONSOLE.md (include_str!).
```

Backed by a single tokio multi-thread runtime. The render loop
uses `tokio::select!` over `crossterm::EventStream` and an
`mpsc::Receiver<EngineEvent>`. Background work (queries,
alert polling, chat completions) sends results via the channel;
the UI never blocks.

### 24.3 Chat pane (Gemma 4 via llama.cpp)

Behind the `llm-llama-cpp` feature on `bowery-console`. Loads
`gemma-4-e2b-it-q4_k_m.gguf` (2.96 GiB; pinned SHA in the model
registry) via the new `bowery_llm::Chat` trait.

[`crates/bowery-llm/src/chat.rs`](crates/bowery-llm/src/chat.rs):
- `Chat: Send + Sync` async trait, `complete(messages) -> reply`.
- `MockChat` — always-on echo backend.
- `render_gemma_prompt(messages)` — folds `system` into the
  first `user` turn (Gemma has no `system` marker, matches the
  Transformers chat template).

[`crates/bowery-llm/src/chat_llama_cpp.rs`](crates/bowery-llm/src/chat_llama_cpp.rs):
- `LlamaCppChat` — same dedicated-OS-thread + tokio-channel
  pattern as `LlamaCppAnalyzer`. Tokens streamed lossily
  (UTF-8 may straddle), end-of-turn marker stripped.

The Chat pane:

- Multi-turn buffer, system prompt seeded on every `complete()`
  call (Gemma's template re-folds it into the first user turn
  automatically).
- After each reply, scans for ```` ```sql … ``` ```` blocks; the
  most recent draft sits in a "DRAFT SQL" footer.
- `x` hotkey takes the draft, switches to the Query pane, and
  dispatches via the existing `query_pane.submit` path.

Privacy: prompts stay on-host; `bowery_alerts` / `bowery_audit`
rows are NOT auto-fed into the prompt — operators paste what
they want grounded.

### 24.4 Model registry + auto-fetch

[`crates/bowery-cli/src/model.rs`](crates/bowery-cli/src/model.rs).
Curated registry with two entries today:

| name | url | sha256 | size |
|---|---|---|---|
| `qwen3-0.6b-q4_k_m` | unsloth/Qwen3-0.6B-GGUF | `ac2d977…0d524a` | 378 MiB |
| `gemma-4-e2b-it-q4_k_m` | unsloth/gemma-4-E2B-it-GGUF | `9378bc4…b8672d` | 2.96 GiB |

`validate()` runs three checks post-download: GGUF magic, size
band (±25 %), SHA-256. The console's launch-time
`prompt_and_fetch_gemma` call uses the same `bowery_cli::model::fetch`
function, so the GGUF lands at `~/.bowery/models/<name>.gguf`
verified against the pinned hash.

### 24.5 Help pane = handbook

[`docs/CONSOLE.md`](docs/CONSOLE.md) is the canonical operator
reference. The Help pane includes it via `include_str!` so the
binary stays self-contained. The chatbot's system prompt is a
condensed mirror of the same content (schema, palette, rules,
few-shot examples) — same source of truth, three audiences.

### 24.6 xtest integration

[`scripts/xtest`](scripts/xtest):

- `xtest build` and `xtest ci` now also run
  `cargo build --release -p bowery-console --features llm-llama-cpp`
  on the test VM so the LLM-on path doesn't rot.
- `xtest run-console [-- ARGS...]` — sync + build console with
  the LLM feature + run. `--push-model` rsyncs the GGUF ahead
  of launch.

---

## 25. Cross-host corroboration

[`crates/bowery-whisper/src/corroborate.rs`](crates/bowery-whisper/src/corroborate.rs)
(transport) +
[`crates/bowery-agent/src/corroboration/`](crates/bowery-agent/src/corroboration/mod.rs)
(engine, registry, kinds).

A whole class of detections has the same shape: the host that sees the
event cannot tell whether it is benign, and exactly one other party can.
An inbound connection is the motivating case — normal from here, normal
from there, alarming only if the host it came from has no record of
making it.

The temptation is to build that one detection. We built the round
instead, and made the detection data.

### 25.1 Why generic

Written per-detection, each one grows its own message pair, its own
timeout handling, its own tally, its own idea of what silence means. The
parts that rot are the security-relevant ones: one ends up without a rate
limit, or counting a timeout as agreement, or letting a peer answer a
question it was never asked.

So the wire carries a `kind` string and an opaque list of key/value
attributes, and nothing below the handler ever interprets them:

```
CorroborationQuery  { query_id, kind, deadline_unix_ms, window, subject: [Attribute] }
CorroborationAnswer { query_id, kind, outcome, evidence: [Attribute], reason }

enum Corroboration { Unspecified=0, Corroborated=1, Denied=2, Refused=3 }
```

`Unspecified` is the proto3 default, so it is what a garbled or
older-build answer decodes to — and it is treated exactly like `Refused`.
Reading a zero as a denial would let a decoding bug anywhere in the fleet
manufacture alerts.

These replaced `ConnectionQuery`/`ConnectionAnswer` on tags 10/11. **Tags
10 and 11 are retired and must never be reused**: an agent still running
the old build would decode a tag-10 field as a connection query and answer
it under the old rules. Skipping to 12/13 makes the mismatch a clean
"unknown field → `body: None` → ignored" on both sides.

### 25.2 The round

```
detector ──raise(Claim)──► engine ──► audience ──► ask each peer
                              │                        │
                              └──── Tally ◄────────────┘
                                     │
                          Rule::confirms(&tally)
                                     │
                                 Alert (quorum-backed)
```

A `Claim` says what was observed (`kind` + attributes), who could know
(`Audience`), and what would make it alarming (`Rule`). The engine owns
everything else: dedup, the concurrency ceiling, peer resolution,
sealing, timeouts, the tally, and the alert.

`Audience` has two primitives. `PeerAtAddress` asks whoever the *live
mesh view* says owns an address — never anything the observation itself
asserts, and never an unpinned peer. `Neighbourhood { limit }` asks up to
N pinned peers, for claims with no particular counterparty.

`Tally` has four buckets, not two, and that is the point:

| bucket | meaning | counts toward quorum |
| --- | --- | --- |
| `corroborated` | "yes, that was me" | no — it *clears* the claim |
| `denied` | "I looked; I have no record" | **yes — the finding** |
| `refused` | "I won't / can't say" | no |
| `no_reply` | timed out, failed to dial | no |

Collapsing `refused` or `no_reply` into `denied` is the mistake the type
exists to prevent. Treating silence as agreement would let an attacker
manufacture alerts by taking peers offline, and would make a partitioned
mesh alert about everything it sees.

### 25.3 Two properties that make the alert trustworthy

**The responder decides what it is willing to be asked.** A generic "ask
a peer about its history" primitive is a generic *enumeration* primitive
unless every handler constrains queries to facts the asker already knows.
`net.inbound_connect` requires the named address to be the **asker's
own**, as this host's mesh view reports it — so a peer only ever learns
about traffic it was already party to, having observed the other half
itself. The trait doc states this as a contract rather than leaving each
implementation to remember it.

**A denial is only sent after actually looking.** `EventLog::covers_since`
gates it: if the log's oldest row is newer than the query window, the
honest answer is "I would not have recorded that either way", and the
handler refuses. Without it, every freshly-installed agent denies every
connection made before it was installed, and every agent whose retention
trimmed the window denies whatever fell off the end. Those false
accusations look exactly like the real finding and would vastly
outnumber it.

### 25.3.1 The same guard, retrofitted to the prevalence round

The coverage rule generalises, and not applying it everywhere was a real
bug. The binary-prevalence round (§13, `whisper_qa.rs`) had no
equivalent: a peer whose baseline was empty answered `seen_count: 0` to
every question, and since a quorum of "never seen it" is what confirms
an alert, an agent with a dead event source silently rubber-stamped
every alert its neighbours raised.

Found running on a live fleet — two Pis with no eBPF object, baselines
at zero, unanimously confirming `/usr/bin/ssh` as an anomaly.

The fix mirrors `covers_since`: `Answer` gained a `refused` field (tag
7), `local_knowledge` returns `Insufficient` below
`[whisper.qa] min_baseline_binaries`, and `PeerSighting.sighting:
Option<LocalSighting>` became `PeerReply` with three states — because
`Option` could only encode two, and the missing third state *was* the
bug. A hit outranks the threshold: "I have this too" is honest however
little else you have observed.

### 25.4 Adding a kind

Two functions and one registration. Nothing shared changes — not the wire
format, not the dispatcher, not the rate limiter, not the alert path:

1. **A claim builder** — `fn claim_for(observation) -> Option<Claim>`,
   returning `None` when there is nothing worth asking.
2. **A responder** — `impl CorroborationResponder`, which applies its own
   policy check and consults local state. Refuse rather than deny
   whenever the honest answer is "I can't say".
3. **Register it** in `Agent::start_with_llm`'s `ResponderRegistry`, and
   call the builder from wherever the observation arrives.

An unregistered kind is refused, not guessed at, so a rolling upgrade
where one host knows a kind and another doesn't degrades to "that peer
declined" rather than to a false finding.

### 25.5 Operator surface

The round reuses `AlertConfirmation` rather than adding a parallel
concept, because both whisper rounds ask the same question in different
words — *does anyone else have a record of this?* — and in both, a peer
answering **no** is what confirms. `peers_refused` (tag 7) was added for
the outcome the binary-prevalence round has no way to express.

The alert therefore appears in the same inbox, the same `bowery_alerts`
view, the same console badge, and the same CLI output as every other
confirmed alert.

### 25.6 What's deferred

- **The claim is raised, then forgotten.** A corroborated answer carries
  process attribution the observing host could never derive on its own;
  today it is logged and broadcast on `AgentEvent::CorroborationRound`,
  but not written back into the event log where an investigation would
  find it later.
- **Only one kind is registered.** Destination rarity
  (`Audience::Neighbourhood` over the `net_destinations` table) is the
  obvious next one, and needs no new machinery.
- **`deny_quorum` is necessarily 1 for counterparty claims** — one host
  made the connection, so only that host can deny it. The refusal path
  carries the weight a larger quorum would elsewhere.

---

## 26. Sensor self-attestation (roadmap phase A)

[`bowery-events/src/source.rs`](crates/bowery-events/src/source.rs) (the
`ProbeHealth` type), [`bowery-ebpf-loader`](crates/bowery-ebpf-loader/src/lib.rs)
(populating it), [`probe_watchdog.rs`](crates/bowery-agent/src/probe_watchdog.rs)
(acting on it), `bowery_probe_status` (exposing it).

Two agents ran for days observing nothing — no BPF object, a silent fall
back to the no-op source, one WARN at startup — while gossiping,
answering SQL, and voting in whisper quorums as though healthy. It was
found by accident, from a row count that looked wrong.

**Nothing downstream could tell "quiet" from "blind".** That is what
this closes.

### 26.1 The kernel counts what it drops

`RingBuf::reserve` returns `None` when a ring is full and the probe
discards the event. Nothing about that was visible from userspace: a
saturated sensor and an idle host produced byte-identical output. A
`PerCpuArray` counter incremented at each reserve failure, polled every
10s, is the only place that fact exists. Per-CPU so it needs no atomics
and cannot lose increments to a race.

Drops report as **NULL, never 0**, on an object built before the counter
existed. "No drops" and "cannot tell" are the exact distinction that let
the original failure hide, and an object without the map still loads —
an agent has to survive its own rollout.

### 26.2 What is and isn't an alert

`EventSource::health()` returning `None` means the source cannot report,
which is treated as **blind** rather than unknown, because that is
precisely the production failure. A source that *stops* is equally
blind; previously that was a log line and nothing else.

A **quiet host is deliberately not an alert.** "No events recently" is
indistinguishable from an idle machine, and paging whenever a Pi idles
overnight is how the alert gets ignored. Staleness is reported in SQL
for a human to judge.

A 30-second startup grace applies only to a source that might still come
up. The first live run alerted `SENSOR BLIND` one millisecond before the
probes attached — a false alarm at every boot, which is the crying-wolf
failure this module's own docs warn against. A *missing* source still
alerts immediately: nothing is coming, and waiting to say so is time
spent believing the host is covered.

---

## 27. File-write monitoring (roadmap phase B)

[`bowery-ebpf/src/main.rs`](crates/bowery-ebpf/src/main.rs) (the probe),
[`file_watch.rs`](crates/bowery-analysis/src/file_watch.rs) (the rules).

The kernel sensor watched no file operations, which is why persistence,
credential access, defense evasion and impact were four empty rows in
the roadmap's coverage table — they are overwhelmingly file-shaped.

### 27.1 Why a tracepoint, not an LSM hook

LSM hooks are the natural choice and are unusable fleet-wide:
Raspberry Pi kernels ship `CONFIG_BPF_LSM=n`, found while bringing eBPF
up on dartagnan. `sys_enter_openat` works everywhere the existing probes
do.

**Filtered in the kernel**, on write intent
(`O_WRONLY`/`O_RDWR`/`O_CREAT`/`O_TRUNC`/`O_APPEND`). Reads outnumber
writes by orders of magnitude; shipping them all would saturate the ring
and force exactly the drops §26 exists to report. Write intent is what
persistence, tampering and ransomware have in common.

### 27.2 The offsets are verified, not assumed

Argument N of any syscall-enter tracepoint sits at `16 + 8*N` — that is
structural, from `struct syscall_trace_enter`, not per-architecture
guesswork. It still gets checked against the kernel's published format
file at attach time, and the probe **refuses to attach on a proven
mismatch**.

This project has already shipped one bug from assumed tracepoint offsets
that every test agreed with (byte-swapped ports), and this failure is
quieter: a wrong offset yields a garbage pointer and silently empty
paths, indistinguishable from a host that opens no files. An unreadable
format file is an inability to check rather than a mismatch, so it warns
and proceeds.

### 27.3 Two limits recorded rather than hidden

Paths are captured to 256 bytes and **flagged when truncated**, because
a silently shortened path is one that quietly stops matching a rule.
Relative paths — an `openat` against a dirfd the probe cannot resolve —
are stored but never matched, since guessing would attribute a write to
a file nobody touched.

### 27.4 The watch set

Fifteen built-in rules across persistence (`ld.so.preload`, systemd
units, cron, `authorized_keys`, PAM, udev, shell rc), privilege
escalation (`sudoers`), credentials (`shadow`, `passwd`, SSH keys) and
log tampering. Built in rather than configured: an operator should not
have to know in advance that `/etc/ld.so.preload` is how a host gets
owned. Configuration is for paths specific to their estate.

Every rule carries an explanation, and a test enforces that they are
real ones — it caught two of the author's that were too thin to help
anyone at 03:00.

**No suppression by process name.** A package upgrade writes systemd
units and it is tempting to ignore `dpkg`, but `comm` is 16 bytes any
process can set with `prctl`, so a suppression list keyed on it is an
instruction for how to evade the rule. Package writes produce hits; the
honest fix is fleet corroboration (a write every host makes at the same
moment is an upgrade), and that substrate exists, unwired.

### 27.5 Credential-access reads

The probe originally shipped only write-intent opens, which left reading
`/etc/shadow` or an SSH key invisible — a whole ATT&CK phase at zero.

Reads are now shipped too, but only where the path **ends in** a
credential name. The suffix anchoring is not a style choice: finding the
basename by scanning for the last slash is a 256-iteration loop over a
map-backed buffer, and the verifier explores one state per iteration —
the program was rejected after eight seconds of analysis, with the log
showing it unrolling that loop byte by byte. Anchoring each pattern at
the end of the string needs one computed offset per pattern and no loop
over the path at all. Patterns begin with `/` so they match a whole
final component: `/shadow` matches `/etc/shadow`, not `/var/lib/myshadow`.

The kernel filter is deliberately permissive and userspace decides: a
false positive in the kernel costs one ring slot, a false positive in
the rules costs an operator's attention.

Sixteen read rules, ranked by how routine the read is. `sshd` reads host
keys at every startup and `sudo` reads its own policy on every
invocation, so those sit well below an `/etc/shadow` read by something
that is not a password tool. Reading and writing the same path are
separate rules with separate wording, because they mean different
things — reading `/etc/shadow` is credential theft, writing it is an
account change.

Verified on hardware: `cat /etc/shadow` and `cat ~/.ssh/id_rsa` both
alerted, `unix_chkpwd` and `sudo` were caught and correctly ranked as
routine, and `/etc/hosts` produced nothing.

### 27.6 Set-id binaries

A setuid-root binary is how an unprivileged process becomes root, and
distributions ship a short well-known list of them. One that **no
package owns**, or that a package owns but no longer matches, is how a
foothold becomes permanent root without touching a service file.

This is provenance and file metadata composed: the set-id bits come from
a `stat`, the judgement comes from the package index. `sudo`, `su` and
`passwd` are packaged and intact, so they stay silent — alerting on them
would fire on every privilege escalation a human performs. Only
root-owned set-id counts; a setuid binary owned by an unprivileged user
grants only that user's own authority.

---

## 28. Provenance and lineage (roadmap phase C)

[`provenance.rs`](crates/bowery-analysis/src/provenance.rs),
[`lineage.rs`](crates/bowery-analysis/src/lineage.rs).

### 28.1 Package provenance

A binary never seen before scored 1.0, which made ordinary distro
binaries the loudest thing in the stream — the live fleet
quorum-confirmed `/usr/bin/ssh`, `/usr/bin/nice` and `/usr/bin/pkexec`
as anomalies.

A binary the package manager installed whose contents still match is
**damped to 15%**: it was on disk before anyone logged in. Damped, not
zeroed, because `bash` and `curl` ship with the distro and the
writable-path, suspicious-args and lineage rules must still be able to
carry an episode alone.

The same index is a detection: a **mismatch** means a packaged system
binary has been rewritten, scored 1.0.

Three deliberate asymmetries, all in the fail-safe direction: an
unreadable file is `Unknown` (never `Modified`) so losing a race with
`rm` cannot accuse a binary; no package database is `Unknown` (never
`Unpackaged`) so a non-dpkg host does not mark its whole system
suspicious; and md5 is used because it is what dpkg records — an
attacker who can rewrite `/usr/bin/nice` can rewrite the `.md5sums`
beside it, so this catches the ordinary case, not a determined one.
SHA-256 remains the identity.

Only executable paths are indexed (~2,400 of dpkg's ~226,000 entries on
otter1); the rest is memory a Pi should not spend on paths never looked
up.

**Two bugs worth recording**, both found by running it rather than
reasoning about it. It was first gated on `baseline_seen_count == 0`,
but the rarity curve decays slowly (0.89, 0.80, 0.73 for the next three
runs) so every one of those stayed above the alert threshold with
provenance never consulted — `/usr/bin/column` alerted at 0.80 on a host
whose index had loaded fine. And the load was *awaited* at startup,
which on a runner with 53,000 packaged executables took five seconds and
delayed every later task including the file monitor: five seconds of a
"ready" agent not watching. It now loads in a detached task and answers
`Unknown` until it arrives.

### 28.2 Lineage

"nginx spawned a shell" needs no new sensor, and the agent could not
express it — `process_lineage` sat in the baseline schema being neither
written nor read.

Lineage needs the parent, and `sched_process_exec` carries none.
Fetching it in the probe means `task->real_parent` via CO-RE, which
needs kernel BTF, which Pi kernels do not ship — the same constraint
that ruled out LSM file hooks. So it is read from `/proc` right after
the exec, beside the `exe_path` and cmdline enrichment already
happening there.

`/proc/<pid>/stat` is parsed from after the **last** `)`, not by
splitting on whitespace: field 2 is the comm in parentheses, and a
process may legally name itself `evil) 0 0 (` to forge its own
ancestry.

Four rules, ranked: service→shell (0.95), service→downloader (0.9),
scheduler→downloader (0.8), service→interpreter (0.75, since CGI stacks
do this legitimately). The most important test is a negative — **sshd
starting a shell must not alert**, since it exists to start shells and
firing on every login would teach an operator to ignore the rule set.

Applied *after* provenance deliberately: `/bin/sh` is packaged and
unmodified, so it would otherwise be damped to 15% at exactly the moment
nginx started it.

### 28.3 Privilege transitions

[`escalation.rs`](crates/bowery-analysis/src/escalation.rs).

Becoming root is not suspicious — Linux ships `sudo`, `su` and `pkexec`
precisely so people can. What is suspicious is reaching uid 0 *without*
going through one of them: the privilege came from somewhere else.

The rule is therefore a transition plus an exemption. A process runs as
uid 0, its parent's real uid is non-zero, and the exec did **not** go
through a packaged, unmodified setuid binary. Two findings come out of
it: `privesc.uid_transition_untrusted_setuid` (0.95) when the binary is
setuid but not one a package vouches for, and
`privesc.uid_transition_no_helper` (0.9) when no setuid helper was
involved at all — which is the shape a kernel or service exploit leaves
behind.

Three details each fix a specific way this would otherwise be wrong:

**The exemption is anchored on package provenance, not on a name.** A
list of `["sudo", "su", "pkexec"]` would exempt exactly the thing being
looked for: a binary *called* `sudo` that no package owns. Provenance
answers the question the name only pretends to.

**Both uids are the real uid.** `bpf_get_current_uid_gid` returns
`current_uid()`, the real uid, and `pid_uid` reads the first field of
`/proc/<pid>/status`'s `Uid:` line, which is also the real one. This is
load-bearing: a setuid binary changes the *effective* uid while the real
one still names whoever ran it, so mixing the two would report a
transition for every `sudo` and none for a genuine escalation.

**An unknown parent reports nothing.** The parent is read from `/proc`
and is often already gone. Treating "cannot read" as "was not root"
would alert on most root processes on a booting host.

### 28.4 Discovery bursts

Same file. `whoami` is not a detection — it runs constantly, on every
host, in scripts nobody wrote for an attacker. What distinguishes
reconnaissance is the *burst*: several different discovery commands, in
seconds, from one place.

So the tracker counts **distinct** commands per **parent** in a sliding
window (defaults: five distinct within one minute, `[detection]` in
`agent.toml`). Both words carry weight:

- *Distinct* — a script running `id` in a loop is not reconnaissance and
  never trips this, no matter how many times it runs.
- *Parent* — each `whoami` is its own short-lived pid; what ties a burst
  together is the shell or script that ran them. Keying on the process
  itself would make every burst a set of unrelated singletons.

About fifty commands are recognised, grouped by the question they answer
— who am I, where am I, who else is here, what is running, what can I
reach, what is on disk, what is installed. Matching is on the basename,
so the table holds bare command names.

A burst reports **once** and then clears that parent's history, so a
shell that keeps poking around produces one alert per window rather than
one per command. The finding folds into the completing exec's verdict at
0.75 rather than becoming its own alert, which means it arrives carrying
the ancestry, cmdline and open files that say *who* was running it —
context a standalone burst alert would not have.

The tracker is bounded at 1024 parents and clears wholesale when full: a
fork bomb should not be able to grow it without limit, and a cleared
tracker re-learns within one window.

### 28.5 The ATT&CK coverage map

[`attack.rs`](crates/bowery-analysis/src/attack.rs) →
[`docs/ATTACK-COVERAGE.md`](docs/ATTACK-COVERAGE.md).

A coverage map that lives only in Markdown drifts the first time someone
adds a rule and forgets to write it down, and it fails in the worst
available direction: a document claiming coverage the code does not
have. So the map is a table in code, and the document is generated from
it (`BOWERY_UPDATE_DOCS=1 cargo test -p bowery-analysis`).

Four tests hold it honest:

- **Every rule the agent can fire appears on the map.** Each rule module
  exposes `rule_ids()`, and the map's test unions them. Adding a
  detection without placing it on a technique fails the build.
- **The map names no rule that no longer exists.** A rename would
  otherwise leave the map pointing at nothing while still claiming the
  coverage. Four ids produced by subsystems rather than rule tables
  (`baseline.rarity`, `yara.match`, `probe.sensor_blind`,
  `corroborate.net_inbound_connect`) are exempted by an explicit,
  reviewable list rather than by a wildcard.
- **Every technique names its gap** — including the well-covered ones.
  There is deliberately no grade above `Good`: no host sensor covers a
  technique completely, and a map that says "complete" invites an
  operator to stop looking.
- **The checked-in document matches the table.**

The `rule_ids()` accessors are themselves hand-maintained where the
rules are `if` arms rather than table rows (lineage, setid, escalation),
so each of those modules has a test that drives its classifier
exhaustively over its own input sets and asserts the reachable ids equal
the declared ones.

Today: 12 good, 10 partial, 3 uncovered across 25 techniques. The
uncovered rows — kernel modules, C2 beaconing, ransomware — are the
useful half.

---

## 28b. Making the agent discard its own noise

The fleet's inbox, pulled live: **63 alerts in 24 minutes, 61 of them
`sshd` and `unix_chkpwd` doing their job.**

| count | reader | suspicion | path |
| --- | --- | --- | --- |
| 12 | `sshd` | 0.85 | `/etc/ssh/ssh_host_rsa_key` |
| 12 | `sshd` | 0.85 | `/etc/ssh/ssh_host_ecdsa_key` |
| 12 | `sshd` | 0.85 | `/etc/ssh/ssh_host_ed25519_key` |
| 12 | `sshd` | 0.90 | `/etc/shadow` |
| 12 | `sshd` | 0.60 | `~/.ssh/authorized_keys` |
| 1 | `unix_chkpwd` | 0.90 | `/etc/shadow` |
| 2 | — | 1.00 | `/usr/bin/bowery` |

Five distinct defects, not one.

### 28b.1 The rule already knew

`cred.read_ssh_host_key`'s own rationale reads *"an SSH host private key
was read. sshd does this at startup; anything else can impersonate this
host."* The exemption was written in English, shown to the operator, and
implemented nowhere.

Each rule now carries `sanctioned_readers`: absolute exe paths whose
**job** requires that path. [`reader_is_sanctioned`] requires two things
and both matter:

1. The reader's resolved exe is one the rule names.
2. Package provenance says [`PackagedIntact`].

The second makes the first safe. A path list alone is defeated by
writing to one of those paths; requiring the package to vouch for the
contents means the exemption covers the distribution's `sshd` and not a
trojanised one — the case that matters most, since a backdoored `sshd`
reading every host key is exactly what this is supposed to catch.

**Never keyed on `comm`.** The file-watch module already refused to
suppress *writes* by process name, for a reason that applies with more
force here: `comm` is 16 bytes any process sets with `prctl`, so a
name-keyed allowlist would be a published recipe for reading every
credential on the host in silence. The exe comes from
`/proc/<pid>/exe`.

**It fails closed**, which inverts the default used by the uid-transition
rule. There, an unreadable parent reports *nothing*, because a transition
could not be established. Here an unreadable exe reports the finding,
because an exemption must be *earned* — and a detection that goes quiet
whenever it cannot look is one an attacker only has to outrun.

The reader sets were taken from the fleet rather than guessed, which
caught something a plausible list would have missed: Debian 13 ships
OpenSSH 9.8+, which splits per-connection work into `sshd-session` and
`sshd-auth`, and Debian 12 does not. Omitting them would have left the
newer hosts alerting on every login while the older ones went quiet —
a detection that looks like it works until you notice *which* hosts are
silent.

### 28b.2 The same event, twice

pid 410930 read `ssh_host_rsa_key` twice in the same second and produced
two alerts; sshd opens each key more than once per connection.

[`suppress.rs`](crates/bowery-analysis/src/suppress.rs) folds identical
findings — same rule, same path, same **reader exe** — into one report
per window (`[detection] repeat_window`, default 1h). The exe is part of
the key so a noisy legitimate reader can never provide cover for a quiet
illegitimate one.

The count travels with the alert rather than being dropped. "`sshd` read
a host key" and "`sshd` read a host key 4,000 times in the last hour" are
different events, and the second is the interesting one.

### 28b.2a Naming a process that has already exited

With the flood gone, one source of credential-read noise remained on the
fleet: `unix_chkpwd`, roughly one alert per hour per host. PAM forks it,
it reads `/etc/shadow`, it exits — all in milliseconds. By the time the
agent read `/proc/<pid>/exe` the process was gone, so the reader could
not be named, the exemption could not be earned, and the alert fired.

That was *correct*: the exemption must be demonstrated, not assumed. But
it was useless, because the question could not be asked at all.

The obvious fix is to join `file_open` against the `exec` row for the
same pid — the agent already records every exec with a resolved
`exe_path`, and that is exactly the join `file_access_seen` uses. It
does not work here. [`EventLogHandle`] records through an `mpsc` drained
by a writer task, so the exec row is usually **not committed yet** when
the file-open for that pid is processed. The lookup would race, and lose
precisely for the short-lived processes it exists to catch.

So [`proc_table.rs`](crates/bowery-agent/src/proc_table.rs) keeps a
bounded pid → exe map, filled synchronously by the same pipeline task
that dispatches both events, in channel order. `/proc` is still tried
first — it is authoritative for a process that still exists — and the
table answers only when `/proc` cannot.

This does not weaken failing closed. It improves the agent's ability to
*look*; when neither source can name the binary, the finding is still
raised.

Three bounds, because a wrong answer here can only ever **grant** an
exemption, which is the direction that turns a finding into silence:

- **The exec must precede the access.** A later exec cannot explain an
  earlier read, and answering with it would attribute a file access to a
  binary that had not started yet.
- **A 5-minute TTL.** A pid can be reused by a process that `fork`s
  without `exec`ing; such a child inherits its parent's binary, so the
  recorded path would name the wrong one and no exec would overwrite it.
- **A cap, and eviction on `ProcessExit`**, which closes the reuse window
  as soon as the kernel says so rather than waiting out the TTL.

The alert's `exe` context attribute is now populated from the same
resolution rather than re-reading `/proc`, so the context cannot
disagree with the rationale about who the reader was.

### 28b.3 Our own deploy was the loudest thing on the host

`dpkg -S /usr/bin/bowery` → *no path found*. `deploy/remote/` `scp`s the
binary, so provenance said `Unpackaged`, rarity stayed undamped, and the
CLI scored **1.00** on every node.

The detection was right. A binary in `/usr/bin` that no package owns
genuinely is the shape it exists to find; the deploy method was wrong.
`package-agent.sh` now builds a real `.deb` with `dpkg-deb` — no
`cargo-deb` dependency, and cross-arch is one `Architecture:` line. What
matters is `DEBIAN/md5sums`, which dpkg installs to
`/var/lib/dpkg/info/`, the exact file `PackageIndex` reads. That is what
makes the agent's own binaries `PackagedIntact`, and it is also what
makes a *modified* copy of the agent a finding afterwards.

One upgrade hazard is handled explicitly: the loader searches
`/usr/local/lib/bowery` **before** `/usr/lib`, so an object left by an
older tarball install would silently shadow the packaged one and the
agent would keep running the old probe after an upgrade that appeared to
succeed. The `postinst` moves it aside and says so.

### 28b.4 One row per episode

An episode produces several alerts as it is refined, each superseding the
last. The console and `bowery notify` have always collapsed them;
`bowery_alerts` did not, so the fleet reported `/usr/bin/bowery` twice
for one finding and an operator comparing the two surfaces got different
counts for the same inbox.

A blank `episode_id` is deliberately not an identity — those are distinct
findings sharing an empty field, and keying on it would hide all but the
last.

### 28b.5a What that round could not answer, and why

It ran 24 times on a live fleet and corroborated **nothing**. The
downgrade path — the entire point of the kind — never once executed.

The cause was in how a peer attributed an access to a binary.
`file_open` rows carry `comm` and no `exe_path`, because resolving the
exe for every write-intent open would put a readlink on the agent's
hottest path, so the responder joined against the `exec` row for the
same pid. That works only for a process the agent watched start. Every
long-running daemon — `sshd`, `cron`, `systemd` — was running before the
agent, so it has no exec row. And those daemons are exactly what reads
credential files. The kind could not answer the question it was built to
ask.

The second half was worse than the first. Unable to attribute, the
responder answered **Denied** — "I do not see that" — when the honest
answer was "I cannot tell". That is the blind-peer problem in its third
appearance: fixed for prevalence with `min_baseline_binaries`, fixed for
`net_inbound` with `covers_since`, and reintroduced here because
coverage was checked for the *time window* and not for *attribution
capability*. It was harmless only by luck: `deny_quorum: 0` means the
round cannot raise an alert, so a false denial cost a missed downgrade
rather than a false accusation.

Both halves are fixed:

**Evidence has three states, not two.** `AccessEvidence::Seen` /
`NotSeen` / `CannotAttribute`, and the last refuses. A host that has
attributed no access at all in the window says so, because its silence
is not evidence of anything.

**Accesses are recorded with their binary.** When a path matches a watch
rule, the agent already resolves the reader's exe — for the sanctioned
check and for the alert. That resolution is now kept, as a `file_access`
row. Only rule-matched paths are enriched, so the hot path is untouched
and the rows that exist are exactly the ones a peer is ever asked about.

Recorded **before** the sanctioned-reader check and regardless of
whether an alert follows. The question a peer asks is "does this happen
on your host", not "is it a finding there" — a host whose own `sshd` is
sanctioned must still be able to say that its `sshd` reads host keys, or
the only agents able to corroborate would be the ones with the same
problem you are asking about.

### 28b.5 The mesh can now take a finding back

Every corroboration kind until this one could only make things worse: the
round ran, the rule fired, an alert appeared. That shape cannot express
the most useful answer a neighbourhood can give — *"we all do that"* —
which is exactly what separates a management agent from credential
theft.

[`file_access.rs`](crates/bowery-agent/src/corroboration/file_access.rs)
asks up to three peers whether the same binary touches the same file on
their hosts. [`Claim`] gained `supersedes` + `explained_suspicion`, and a
round that finds corroboration without confirming appends a superseding
alert re-scored to 0.15. Since `bowery notify` keeps the newest alert per
episode and filters by `min_suspicion`, the downgraded version is what
reaches the operator — or nothing at all.

Four properties keep it honest:

- **The local finding is raised first and always.** A detection that
  waits for the mesh says nothing on a single-node install, on a
  partitioned network, or when every peer is down — the moments it
  matters most. The round can only ever take a finding *back*.
- **`deny_quorum: 0`.** This round can never raise an alert of its own.
  A second alert saying "and nobody else does this" would double every
  credential finding on the fleet rather than clarify it.
- **Zero corroborating peers never downgrades anything.** The same rule
  that stops a blind peer confirming an alert, applied in the other
  direction: silence is not evidence, whichever way it would point.
- **A peer answers only about paths its own watch set covers.** Without
  that bound the query would be a filesystem-enumeration oracle — ask
  about any path and learn from the answer whether it exists and who
  touched it. Restricted to the watch set, a peer discloses only the same
  class of fact the asker already observed for itself.

The exe is recovered by joining `file_open` rows against the `exec` row
for the same pid. `file_open` carries no `exe_path` and adding one would
put a readlink on the agent's hottest path — the sensor reports *every*
write-intent open on the host. Pid reuse is the known imprecision; it
biases towards corroborating, which can only ever downgrade a finding
that was already reported, never delete it.

---

## 28c. Blocking a file rather than a name

`block_exec` keyed on `comm` — 16 bytes any process sets with
`prctl(PR_SET_NAME)`. That is bypassable by renaming yourself and, worse,
*weaponisable*: name a process `sshd` and the agent adds `sshd` to the
kernel blocklist, locking out the real one. The roadmap called it theatre
and it was right.

The fix is to key on the file: `(dev, ino)`. A rename keeps the inode so
the block follows the file; a copy gets a new one so the block does not
follow content it was never about.

### 28c.1 CO-RE was unavailable, and the workaround had to be safe

Reading `bprm->file->f_inode` inside `bprm_check_security` needs field
offsets that differ per kernel build. The portable answer is CO-RE.

aya implements the *loader* half: `aya-obj` handles
`BPF_CORE_FIELD_BYTE_OFFSET`, resolves against the target kernel's BTF,
and rewrites instructions. It does not implement the *compiler* half —
checked in both releases, neither `aya-ebpf` 0.1.1 nor 0.2.1 provides a
`bpf_core_read!`, and a plain Rust field access emits no `bpf_core_relo`
record. Half the machinery, and the half that is present cannot be used
without the half that is not.

Hardcoding offsets was never an option, and the reason is the asymmetry
of this particular hook. Elsewhere a wrong offset costs a missed
detection. Here the return value **denies an exec**, so a wrong offset
means reading an arbitrary kernel address and denying arbitrary
binaries, as root, on a running host — the failure mode is bricking the
machine the agent exists to protect.

So offsets are resolved at load time from `/sys/kernel/btf/vmlinux` by
[`btf.rs`](crates/bowery-ebpf-loader/src/btf.rs) and written into an
`EXEC_OFFSETS` map. This is the shape `sys_enter_openat` already uses —
verify against the kernel's own metadata, refuse on a proven mismatch.
`aya-obj` keeps its BTF members `pub(crate)`, so the offsets cannot be
borrowed from it; this is a small parser of the type section that skips
every kind it does not need by size. It agrees with `bpftool btf dump
format raw` on all five offsets.

### 28c.2 The dangerous state is unreachable, not merely avoided

Two orderings carry the safety, and both are structural:

**Slot 0 is an arming word, written last.** The hook reads it first and
returns "no opinion" unless it holds the magic. An object loaded without
userspace resolving offsets — an old object, a kernel with no BTF, a
partial map write — cannot block by inode at all. Not "should not":
cannot.

**Every failure path allows.** Not armed, an offset missing, any
`bpf_probe_read_kernel` failing, a null pointer anywhere in the chain —
each yields `None` and the exec proceeds. The worst outcome of a bug in
the walk is a missed block. Denying on a failed read would turn a
transient kernel-memory read failure into an unbootable host.

And when the kernel cannot arm, an inode block is **refused** rather
than downgraded to a comm block. A caller that asked to block a file and
silently got a spoofable name match would believe it had containment it
does not have.

### 28c.3 The inode key removes spoofing, not targeting

An attacker cannot make their file share `sshd`'s inode. They can still
try to get a verdict to *name* `sshd`, and the block would then be
unspoofable — strictly worse than the comm path it replaces. So the
protected-path list survives, keyed on what actually gets resolved:
`sshd` and its OpenSSH 9.8+ helpers, `sudo`, `su`, `login`, systemd, and
the agent's own binaries. Blocking your own agent means no restart and
no way to undo the block short of single-user mode.

For the same reason `block_exec_by_inode` is deliberately **not**
constructible from `action::from_id`: it needs a real path to `stat`,
and resolving one there would mean trusting whatever string reached the
function and skipping the guard.

### 28c.4 What proves it

Offsets resolving and maps existing prove nothing about whether the
kernel actually denies the right file. A root-gated integration test
does: it blocks a temp script's inode and asserts the kernel refuses it,
that an unrelated file still runs, that renaming the blocked file does
not escape the block, that a *copy* does run, and that unblocking
restores execution. It skips — loudly — on a host without BPF-LSM, BTF
or root, because Pi kernels have none of them and a red build for a
legitimate cannot-run-here teaches people to ignore it.

It passes on otter1 (6.8.0, `lsm=bpf`, BTF present). It did not pass the
first time, and what it caught is the reason the test runs a real binary
instead of checking that the map has an entry: `stat` reports `st_dev`
in glibc's packing, the kernel stores `super_block.s_dev` in its own,
and the two are different numbers for the same filesystem. The insert
succeeded, the hook ran, the comparison never matched, and nothing was
blocked — with no error anywhere, because a map insert cannot tell you
its key means something else.

It hides unusually well. For major 0 the two encodings coincide, and a
tempdir on tmpfs has major 0 — so on most hosts this test would have
gone green over a feature that did nothing. otter1's `/tmp` is ext4.
`kernel_dev_from_stat_dev` reconciles them, and the tmpfs case is now
its own test named for the fact that it hides the bug.

---

## 29. Reaching an operator who isn't watching

### 29.1 `bowery notify`

[`notify.rs`](crates/bowery-cli/src/notify.rs). Drains alerts over the
existing signed `Subscribe` transport and emails a digest. Runs on an
operator box, never on agents: a notification credential on every
monitored host is one every compromised host has.

The subject is built only from manifest host names and counts, which
makes header injection impossible by construction rather than
filtered-for. The body carries triage detail with control characters
flattened and fields capped, and says plainly that those fields came
from the monitored host.

### 29.1a Caps that bound hostility, not caps that tidy output

Every field is capped, because the body is assembled from strings the
monitored host controls. But the caps were one number, 160, applied
uniformly — and the rationale is not like the other fields. It is
*composed*: the analyzer's sentence plus a clause each from provenance,
set-id, lineage, discovery and the repeat-fold note, joined with ` | `.
A real credential-read rationale is ~240 characters and a fully chained
exec rationale runs past 800.

So every one of them arrived cut mid-sentence. The operator read as far
as "Legitimate for `su`, `sudo`, `login` and PAM; from anything el…" and
lost exactly the half that says what to do about it — in the one field
the email exists to deliver.

The rationale now has its own cap (4096) chosen against the longest
chain the agent can compose rather than against a line width, and long
values **wrap with a hanging indent** instead of truncating, so a
continuation cannot be misread as a new field. A single overlong token —
a path, a hash — is emitted whole rather than broken, because a split
path is one an investigator cannot paste anywhere.

Bounded is still not uncapped: a compromised agent must not be able to
mail its operator a megabyte, and `MAX_ENUMERATED` still holds the alert
count. When a cap *is* reached the text now names how many characters
were dropped and points at `bowery alerts` — a bare ellipsis reads as
"and so on" when what it means is "go and look".

Cursors advance only after a successful send; one unreachable agent does
not suppress the rest; a failed run exits non-zero.

### 29.1.1 Alert context

An alert saying "a rare binary ran" sends an operator to the host to
find out the same five things every time. `Alert.context` carries them:
timestamp (always present, and previously just not rendered), full
command line, uid, cwd, process ancestry, open files, and TCP peers
resolved from `/proc/net/tcp` — because "held 3 sockets" is not
actionable and "connected to 198.51.100.7:80" is.

Untyped key/value pairs reusing `Attribute`, so a detection can attach
what it needs without the alert path gaining a field each time an
exec alert wants ancestry and a file alert wants the writing process.

**Sampled once, at exec time.** The LLM-refined alert reuses that
sample rather than re-reading `/proc`, because by the time inference
returns the process is usually gone and a second read would report
"already exited" for something that was alive when it mattered. The
same context is pushed onto the analysis context, so the model sees the
command line and ancestry too — previously invisible to it as well.

Anything unavailable is **omitted rather than reported as empty**: a
short-lived process is gone before its file descriptors can be read, and
"opened nothing" must not look like "could not look".

### 29.2 VirusTotal screening

[`virustotal.rs`](crates/bowery-cli/src/virustotal.rs). Operator-side
only — a hash lookup discloses to VT, and anyone with Intelligence
access, that somebody is investigating that hash, and adversaries watch
VT for their own samples.

**It may only ever suppress on a positive clean verdict, and must fail
open.** Missing key, spent quota, API outage, unparseable response,
zero-engine result, or an unknown hash all send the alert anyway.
`Verdict::may_suppress` encodes it and a test asserts no malformed body
can reach a suppressing state.

Verdicts are rendered **per alert**, not only as a digest total: an
operator triaging one finding needs the verdict for *that* binary, and
the first version reported just "2 hash(es) checked", which said nothing
about either. A flagged hash sorts to the front of its host's list and
into the subject line, and unknown hashes are counted separately —
"2 checked" with no further detail reads as reassurance when it may mean
VirusTotal has never seen either one.

### 29.3 `--verbose-whisper`

Narrates a fan-out query: the outbound command, every chunk as it
lands, envelope nonce/timestamp/signature sizes, and a per-agent tally.
It also makes a security property observable — rows are attributed to
the envelope signer, never the self-declared `agent_fp`, and a
disagreement is called out loudly.

---

This document is meant to be a living reference. When a phase lands
that introduces a new pattern, the owning section gets a new
sub-heading; when something we said we'd do here turns out to be
wrong in practice, we update it rather than leave the discrepancy.

If you find something that doesn't match the code, that's a doc bug
worth filing — the code is the source of truth, this document is the
guided tour.
