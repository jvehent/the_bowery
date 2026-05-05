# The Bowery — Implementation Notes

A reading guide to the codebase, focused on *why*. [DESIGN.md](DESIGN.md)
is the engineering plan and locked decisions; this document explains
how those decisions land in code, the patterns we reach for, and the
specific tradeoffs taken at each layer. If you're new to the project,
read [README.md](README.md) first for orientation, then this for depth.

This document tracks Phase 0 → 8, which is everything currently
implemented. Phase 6b (operator command issuance) and Phase 9
(deferred Tier-2 follow-ups: race-free pidfd kill + LSM
inode-keyed blocking) sections will be added when those land.

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

The advert *is* on the wire (Phase 5 polish, see §13.5):
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
8. Emit `AgentEvent::WhisperContextReady`.
9. Stash the context against `episode_id` so the LLM analyzer can
   pick it up when it dequeues that episode.

Each round runs in its own `tokio::spawn` so a slow peer can't block
the next trigger. The aggregator is liberal on errors — a peer that
times out or fails the dial just gets `sighting: None` in the result;
the rest of the round proceeds.

The responder side lives in [`crates/bowery-agent/src/agent.rs::handle_connection`](crates/bowery-agent/src/agent.rs):
when an inbound envelope's body is `Question`, we run a baseline scan
in `spawn_blocking` and reply. Same connection, same envelope crypto.

The asker pre-flight (Phase 5 polish): before each dial, look up the
peer's published bloom advert in mesh KV and check if our tier-1 hits
*any* of the advertised filter bits. If not, skip — the peer can't
have seen the artifact. This is the only place in the agent that
shortcuts a network round-trip on a probabilistic structure; the
correctness argument is one-sided (no false negatives) so worst-case
we lose a single peer's `total_seen_count` contribution.

### 13.5 Bloom advert publisher

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
`CAP_SYS_ADMIN` and a kernel built with `CONFIG_BPF_LSM=y` and
`bpf` listed in the boot cmdline's `lsm=` enumeration. `bowery
doctor` flags any of those missing — the engine refuses to start
otherwise rather than silently downgrading.

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
debug = false
overflow-checks = false
panic = "abort"

[profile.release]
opt-level = 3
debug = false
panic = "abort"
codegen-units = 1
lto = true
```

`scripts/build-ebpf` cd's into the directory and runs:

```bash
cargo +nightly build --release \
    --target bpfel-unknown-none \
    -Z build-std=core
```

Three things that make it different from a normal Rust crate:

1. `bpfel-unknown-none` target — no std, no alloc, no OS.
2. Nightly `-Z build-std=core` — we compile core for the BPF target
   from source (it's not pre-built).
3. `bpf-linker` — the LLVM-backed linker that produces BPF bytecode.
   Installed via `cargo install bpf-linker` during setup.

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
- **P9-2: H6 LSM keys on inode.** Today's BPF-LSM hook keys on the
  caller's `comm`, defeated by `prctl(PR_SET_NAME)`. Tier-1+2
  defense (critical-comm deny-list, forbidden-pid list, LRU map,
  integrity-checked loader) blocks the catastrophic outcomes; the
  full fix needs aya CO-RE access to `bprm->file->f_inode->i_ino`
  and a wire-format change for the action.

Tracking: `memory/project_phase9_remaining.md`.

---

This document is meant to be a living reference. When a phase lands
that introduces a new pattern, the owning section gets a new
sub-heading; when something we said we'd do here turns out to be
wrong in practice, we update it rather than leave the discrepancy.

If you find something that doesn't match the code, that's a doc bug
worth filing — the code is the source of truth, this document is the
guided tour.
