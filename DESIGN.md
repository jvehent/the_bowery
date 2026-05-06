# The Bowery — Engineering Design

This document is the engineering source of truth for the implementation. It complements the high-level requirements in [the_bowery_design.md](the_bowery_design.md) by pinning architecture, technology choices, protocols, and phasing. Decisions captured here are considered locked unless explicitly revisited; deviations should be proposed by amending this document, not by drift in the code.

**Status:** Draft v0 — pre-implementation. Last updated 2026-05-02.

---

## 1. Goals and non-goals

### Goals

- Distributed Linux EDR agent that detects malicious behavior using local kernel-level visibility plus peer validation.
- No central backend. Operators interact with the fleet via a signed CLI that injects messages into the mesh and collects results back from any node.
- Anomaly detection is **collaborative**: agents compare observed behavior with their neighbors via an encrypted whispering protocol before deciding whether something is malicious.
- Lightweight, resource-bounded, autonomous within a configurable policy envelope.

### Non-goals (v0.1)

- Non-Linux platforms.
- Kernels older than 5.13 (BPF-LSM / KRSI required; no fallback path).
- Mass-market UX: this is a tool for security operators, not end users.
- A managed control plane: the operator is the control plane.
- Real-world threat-intel federation: pure peer-driven baseline first.

---

## 2. Locked decisions

| Topic | Decision | Rationale |
|---|---|---|
| Language | Rust, edition 2024 | Resource control, memory safety, kernel-side via aya |
| eBPF | `aya` (pure Rust) | Avoid libbpf C dependency; idiomatic build |
| Kernel floor | ≥ 5.13 with `CONFIG_BPF_LSM=y`, `bpf` in active LSMs | No fallback path; fail fast |
| Discovery | Gossip-only, cloud-first | Multicast unavailable in VPC/k8s |
| Mesh stack | `chitchat` (SWIM gossip + KV) + `quinn` (QUIC RPC) | chitchat for membership + state; QUIC for direct + bulk |
| Mesh scale | 1–5k nodes per neighborhood; shard above | Stays within chitchat headroom |
| LLM | `candle` default; `llama-cpp-2` optional for GPU; pre-filtered input | LLM is for synthesis, not detection |
| Model fetch | Signed manifest mirror; HuggingFace acceptable for v0.1 | Small agent + side-loaded weights |
| Role tags | Self-learned; deterministic feature vector + seeded random projection | No LLM coupling for role advertisement |
| Whisper privacy | Two-tier: coarse Phase-1 always, encrypted Phase-2 on match | Privacy gradient without full PSI cost |
| Operator IO | Roaming-capable; 72h mesh inbox keyed by operator pubkey fingerprint | Operator can reconnect to any node |
| Hard-action gating | Operator standing authorization OR k-of-n peer quorum | Two-tier autonomy policy |
| License | MPL 2.0 | Per Julien |
| Repo posture | Public from day one | Per Julien |

---

## 3. System architecture

### 3.1 Component map

```
┌──────────────────────────── Linux host ────────────────────────────┐
│                                                                    │
│  ┌──── kernel ────┐    ┌────────────── user-space agent ───────┐  │
│  │ eBPF programs  │───▶│  Event ingestion (ringbuf drain)      │  │
│  │  - LSM hooks   │    │  Enrichment (pid→exe, cgroup→ctr)     │  │
│  │  - tracepoints │    │  Behavioral aggregator → episodes     │  │
│  │  - kprobes     │    │  ┌──────────────┬──────────────────┐  │  │
│  └────────────────┘    │  │ [A] rule     │ [B] baseline     │  │  │
│                        │  │     filter   │     scorer       │  │  │
│                        │  └──────┬───────┴────────┬─────────┘  │  │
│                        │         └─── candidate ──┘            │  │
│                        │                  │                    │  │
│                        │                  ▼                    │  │
│                        │     [C] context builder ─▶ LLM        │  │
│                        │                  │                    │  │
│                        │                  ▼                    │  │
│                        │     verdict ─▶ response engine        │  │
│                        │                  │                    │  │
│                        │      ┌───────────┼──────────────┐     │  │
│                        │      ▼           ▼              ▼     │  │
│                        │  whisper      actions        alerts   │  │
│                        │  composer  (kill/block/etc)  to mesh  │  │
│                        └──────────────────────────────────────┘  │
│                                       │                            │
│                          ┌────────────┴────────────┐               │
│                          ▼                         ▼               │
│                   ┌────────────┐           ┌────────────┐          │
│                   │ chitchat   │           │ QUIC RPC   │          │
│                   │ (gossip)   │           │ (quinn)    │          │
│                   └────────────┘           └────────────┘          │
└────────────────────────────────────────────────────────────────────┘
                       │                              │
       Membership, role vectors,            Whisper Q/A capsules,
       inbox refs, alert summary            operator results, bulk
                       │                              │
                       ▼                              ▼
         ┌────────────────────────────────────────────────┐
         │             The Bowery mesh                    │
         └────────────────────────────────────────────────┘
                                ▲
                                │
                         ┌──────┴──────┐
                         │ Operator CLI │
                         │ (offline key)│
                         └─────────────┘
```

### 3.2 Crate layout

```
bowery/
├── Cargo.toml                    # workspace
├── DESIGN.md                     # this document
├── the_bowery_design.md          # original requirements
├── README.md
├── LICENSE                       # MPL 2.0
├── crates/
│   ├── bowery-agent/             # daemon binary
│   ├── bowery-cli/               # operator CLI binary
│   ├── bowery-crypto/            # identity keys, signing, fingerprints
│   ├── bowery-events/            # shared event schemas
│   ├── bowery-ebpf/              # no_std eBPF programs (aya-ebpf)
│   ├── bowery-ebpf-loader/       # user-space loader for the above
│   ├── bowery-baseline/          # sqlite-backed baseline store
│   ├── bowery-llm/               # Analyzer trait + candle/llama.cpp impls
│   ├── bowery-whisper/           # protocol: handshake, RPC, fingerprints
│   ├── bowery-mesh/              # chitchat integration, role gossip, inbox
│   ├── bowery-response/          # action engine
│   ├── bowery-sql/               # Phase-9 in-process SQL engine (rusqlite)
│   ├── bowery-tables/            # Phase-9 default table set + scalar file/hash funcs
│   └── bowery-proto/             # wire types (prost)
├── deploy/
│   ├── systemd/                  # bowery-agent.service
│   └── packaging/                # cargo-deb / cargo-generate-rpm config
├── ebpf/                         # any raw .bpf.c if needed (CO-RE escape hatch)
└── tests/e2e/                    # multi-VM harness
```

Phases 0–2 do not require all crates to exist; they're added as their phase begins.

---

## 4. Kernel-side instrumentation

### 4.1 Required kernel features

| Feature | Why |
|---|---|
| BPF-LSM (`CONFIG_BPF_LSM=y`, `bpf` in `lsm=`) | KRSI hooks for blocking decisions |
| BTF (`CONFIG_DEBUG_INFO_BTF=y`) | CO-RE; portable across kernel versions |
| Ring buffer (`BPF_MAP_TYPE_RINGBUF`) | Low-overhead event transport |
| `fentry`/`fexit` (≥ 5.5) | Cheaper than kprobes for hot paths |

Agent refuses to start if these aren't present, with a precise diagnostic.

### 4.2 Hook map

| Concern | Hook |
|---|---|
| Process exec / fork / exit | `tracepoint/sched/sched_process_*`, `lsm/bprm_check_security` |
| High-value syscalls | `fentry/fexit` on `execve`, `openat`, `connect`, `ptrace`, `bpf`, `init_module`, `finit_module`, `setuid`, `setresuid` |
| File operations | `lsm/file_open`, `lsm/inode_unlink`, `lsm/inode_rename`, `lsm/inode_setxattr` |
| Network | `cgroup/connect4`, `cgroup/connect6`, `kprobe/tcp_connect`, `sock_ops` |
| Capabilities / privesc | `lsm/capable`, `lsm/task_fix_setuid` |
| Module / lockdown | `lsm/kernel_module_request`, `lsm/locked_down` |
| Container context | cgroup ID + namespace IDs read in BPF; resolved user-side |

### 4.3 Backpressure

Each event class has its own ringbuf and a per-class token bucket implemented in BPF. Under load, events are dropped at the source rather than queued; counter maps export drop stats so we know we lost fidelity. Drop events themselves count as a low-fidelity signal.

### 4.4 Blocking semantics

Only LSM-BPF hooks return non-zero to deny. Tracepoints and kprobes are observe-only. Blocking is gated by the response engine's policy (§9), never by the kernel program in isolation — kernel programs publish "block intent" events; the response engine evaluates policy and re-issues a synchronous block decision via a separate LSM map shared between user-space and the LSM program.

---

## 5. Event pipeline (user-space)

### 5.1 Stages

1. **Ringbuf drain** — `aya::maps::RingBuf` polled by tokio task.
2. **Decoder** — zero-copy parse of fixed-layout BPF structs into Rust event types.
3. **Enricher** — short-TTL caches: pid→exe path, exe path→sha256, cgroup→container, IP→ASN+geo, fd→path. Cache misses fall back to /proc reads.
4. **Aggregator** — groups events into **episodes** (causally and temporally related event clusters keyed by process tree). 1000:1 typical reduction before any heavier analysis.
5. **Pre-filter [A]** — deterministic suspicious-pattern checks (fast path).
6. **Baseline scorer [B]** — statistical deviation against sqlite baseline. Score in [0,1].
7. **Triage** — A-hits or B-score > threshold → candidate queue.
8. **Context builder [C]** — assembles structured prompt with episode timeline, top-N similar past episodes, role context, recent neighbor whispers.
9. **LLM analyzer** — produces `Verdict`.
10. **Whisper composer** — if verdict requests peer validation, builds Phase-1 fingerprint + Phase-2 capsule.
11. **Response engine** — applies policy to verdict + whisper outcome; emits actions and alerts.

### 5.2 Episode model

An episode is a bounded time-window aggregation rooted at a process. It carries:
- root process info (sha256, cmdline class, parent class, uid class)
- event timeline (typed sequence with timestamps)
- net summary (destination class histogram)
- file summary (zone access histogram)
- syscall-class histogram
- derived shape hash (locality-sensitive over event sequence shape)

Episodes are the unit of baseline lookup, scoring, LLM invocation, and whispering.

---

## 6. LLM analyzer

### 6.1 Trait

```rust
pub trait Analyzer: Send + Sync {
    async fn analyze(&self, ctx: &AnalysisContext) -> Result<Verdict>;
}

pub struct Verdict {
    pub suspicion: f32,
    pub rationale: String,
    pub whisper_query: Option<WhisperQuery>,
    pub suggested_actions: Vec<ActionHint>,
}
```

### 6.2 Backends

- **`candle`** (default): pure Rust; CPU and CUDA. No Python runtime dependency.
- **`llama-cpp-2`** (optional, behind feature flag): GGUF + GPU offload.

### 6.3 Models

Default: small instruction-tuned, 1–3B params, 4-bit quantized. Candidates: Gemma-3-1B-it, Phi-3.5-mini, Qwen2.5-1.5B. Output is grammar-constrained JSON. The LLM is invoked at most a few times per minute on a healthy host.

### 6.4 Resource control

Agent installs itself in cgroup v2 slice `bowery.slice`:
- `MemoryHigh`, `MemoryMax` (default 2 GiB)
- `CPUWeight`, `CPUQuota` (default 100% of one core)
- GPU offload optional; default 0 layers

A bounded inference queue applies SLO-based shedding: oldest non-critical episodes are dropped if backlog grows.

### 6.5 Model loading

Models live at `/var/lib/bowery/models/<name>.gguf`. Selected by name in config. Loaded after signature verification against the operator's pubkey using the manifest in §10.

---

## 7. Baseline database

SQLite via `rusqlite`, bundled, WAL mode, at `/var/lib/bowery/baseline.db`.

### 7.1 Schema (sketch)

| Table | Purpose |
|---|---|
| `binaries(sha256 PK, path_first, path_last, signer_class, count)` | Known executables |
| `process_lineage(parent_sha, child_sha, count, first, last)` | Parent→child exec edges |
| `network_peers(ip, asn, port, proto, count, first, last)` | Outbound destination histogram |
| `syscall_freq(binary_sha, syscall_nr, bucket_15m, count)` | Per-binary syscall rates |
| `file_access(binary_sha, path_glob, mode, count)` | What each binary touches |
| `users(uid, name, last_seen)` | Identities |
| `episodes(id, ts, summary, score, verdict_json, whispered)` | Audit trail |
| `role_features(version, vector_blob, computed_at)` | Snapshots of self-role vector |

### 7.2 Bootstrap and decay

- Configurable bootstrap window (default 7 days): everything recorded, nothing alerted on.
- Post-bootstrap: append-mostly with EWMA decay so the baseline adapts.
- Episodes table is bounded with TTL.

---

## 8. Whispering protocol

### 8.1 Discovery and membership

- `chitchat` over UDP for SWIM-style membership + cluster KV.
- Bootstrap via `--seeds` configurable seed list (no multicast assumption).
- Cluster KV holds: role vectors, operator inbox refs, alert summaries, neighbor liveness, software version.

### 8.2 Identity and trust

- Each agent generates an Ed25519 identity keypair on first start.
- Private key stored TPM-sealed when available (`tpm2-tss`); otherwise `/etc/bowery/keys/identity.key` mode 0600.
- Public-key fingerprint = `SHA-256(pubkey)` (32 bytes).
- TOFU bootstrap: during a configurable window after first start, mDNS-or-seed-discovered peers are pinned by fingerprint.
- Post-bootstrap: new fingerprints require either operator-signed `add-neighbor` OR k-of-n attestation by existing pinned peers.
- Key rotation: agent emits a signed rotation message referring to the old key; neighbors verify with old key and pin new key.

### 8.3 Transport

- **QUIC** (`quinn`) over UDP/443 by default; TLS 1.3-over-TCP fallback.
- mTLS via Ed25519 raw public keys (RFC 7250). No PKI.
- Authentication = fingerprint pinning, not certificate chain validation.

### 8.4 Wire format

Protobuf (via `prost`):

```protobuf
message WhisperEnvelope {
  bytes  sender_fingerprint = 1;   // 32-byte SHA-256(pubkey)
  uint64 nonce              = 2;
  uint64 ts_unix_ms         = 3;
  bytes  payload            = 4;   // ChaCha20-Poly1305 ciphertext
  bytes  signature          = 5;   // Ed25519 over (1..4)
}

message WhisperPayload {
  oneof body {
    Question         question  = 1;
    Answer           answer    = 2;
    Alert            alert     = 3;
    OperatorCommand  command   = 4;
    OperatorResult   result    = 5;
    Heartbeat        hb        = 6;
    NeighborOp       neighbor  = 7;
  }
}
```

Per-pair session keys derived via X25519 ECDH at handshake; rotated every N minutes. Replay protection via nonce + timestamp window + per-peer LRU of recent nonces.

### 8.5 Two-tier privacy fingerprints

**Phase 1 — coarse fingerprint** (always sent, low information):

```
{
  binary_signer_class: "unsigned" | "distro" | "vendor:<sha-of-cert>",
  binary_sha256_prefix: 6 bytes,           // birthday-bounded
  parent_class:        "shell" | "service" | "user-app" | "unknown",
  syscall_class_set:   bitmap of syscall classes,
  net_dest:            "loopback" | "rfc1918" | "asn:NNNN" | "unknown",
  file_zone:           "etc" | "var" | "home" | "tmp" | "proc" | ...,
  episode_shape_hash:  LSH over event sequence shape
}
```

No paths, PIDs, IPs, or usernames leak. Neighbors evaluate against their own baseline using the identical fingerprinting function and answer:

- `not_seen`
- `seen_but_baseline` (matches but is normal here)
- `seen_anomaly` (matches and was flagged here too)

**Phase 2 — encrypted capsule** (only sent to neighbors who Phase-1-matched and asked for it):

```
ChaCha20-Poly1305(
  rich_context_blob,
  key = X25519(my_ephemeral, their_pinned)
)
```

Rich context = full sha256, LLM-generated investigative question, narrowly-scoped paths/IPs/usernames if necessary. Capsule is unicast over QUIC, never gossiped.

### 8.6 Question/answer mechanics

- TTL + `max_hops` (default 2) on every question.
- Per-peer rate limit (sustained 1/s, burst 10).
- Originator aggregates answers over a window (default 5s) before deciding.
- Dedup LRU on `(asker_fingerprint, question_id)`.

### 8.7 Self-learned role tags

Each node periodically computes a 32-dim role vector from its own baseline:

1. Build feature vector from baseline (~64 dims): syscall-class freq, port-class freq, ASN-class freq, file-zone access ratios, top-binary-category histogram (categories from a static taxonomy: web/db/devtool/container-runtime/...). Never raw paths or names.
2. Project to 32 dims via fixed seeded random projection (deterministic across the fleet).
3. Sign and publish via chitchat KV.
4. Recompute every N minutes; large jumps require attestation.

When asking a whisper question, originator picks top-K neighbors by cosine similarity to its own role vector. Web servers ask web-shaped hosts; databases ask database-shaped hosts.

Anti-fishing: a host whose advertised role drifts significantly without behavioral support is downweighted by neighbors during peer selection.

---

## 9. Response engine

### 9.1 Action classes

- **Soft (autonomous)**: alert, throttle network, quarantine writes (LSM-deny writes from suspect process; reads still pass).
- **Hard (gated)**: kill process, block file access, kill connection.

### 9.2 Policy file (`/etc/bowery/policy.yaml`)

```yaml
soft_actions:
  - alert
  - throttle_network
  - quarantine_file_writes
hard_actions:
  - kill_process
  - block_file
  - kill_connection
gating:
  hard_actions_require:
    any_of:
      - operator_standing_authorization
      - quorum: { peers: 3, agreement: "not_seen" }
rules:
  - match: { suspicion: ">=0.9", whisper_consensus: "not_seen" }
    actions: [alert, throttle_network]
  - match: { suspicion: ">=0.95", whisper_consensus: "not_seen", role_tag: "endpoint" }
    actions: [alert, kill_process]
```

### 9.3 Standing authorizations

Operator can issue a signed grant: "this fleet may autonomously hard-action under conditions X for Y days." Agents verify the signature against the operator pubkey and honor the grant within its expiry. Grants are inspectable via the CLI.

### 9.4 Audit

Every action emits a signed audit record to:
- the local journald,
- the mesh (gossip-replicated for retention window so an operator can later reconstruct the timeline).

---

## 10. Operator I/O

### 10.1 CLI surface (sketch)

```
bowery key generate                       # offline operator keypair
bowery key fingerprint <path>
bowery query 'select * from processes where name="curl"' \
       --target role-similar-to=role.json --timeout 30s
bowery action kill-process --pid 1234 --target host=h7
bowery hunt --binary-sha256=<hash> --since 24h
bowery alerts tail
bowery agent enroll --bootstrap host1.internal,host2.internal
bowery authorization grant --condition "..." --ttl 7d
bowery model push <file>                  # air-gapped model load
```

The operator key never lives on agents. The CLI signs every outbound envelope and prints the envelope hash for audit.

### 10.2 Mesh-buffered I/O (roaming operator)

Two virtual streams keyed by `op_fp`:
- `inbox/<op_fp>/results/<query_id>`
- `inbox/<op_fp>/alerts`

Mechanics:

1. Every node maintains an LRU+TTL store, default retention **72h**, per-operator size cap (default 10k messages).
2. Agent answers an operator query → signs result → small results gossip via chitchat KV; large results announced via gossip and pulled point-to-point over QUIC.
3. Alerts: same path. Alert dedup by `(originator_fp, episode_id)`.
4. Operator connects to ANY node and sends signed `Subscribe { since: cursor }`:
   1. That node returns all locally-buffered messages for `op_fp` since `cursor`.
   2. The node also issues a mesh-wide signed pull request; remote nodes stream missing fragments back over QUIC.
   3. Operator advances cursor; next reconnect (possibly to a different node) resumes.

Failure modes covered by tests:
- Partition during result accumulation (results buffered locally, gossip on rejoin).
- Retention expiry mid-query (CLI flags incomplete results).
- Operator key rotation mid-query.

### 10.3 SQL surface

`bowery exec sql` runs against the native, in-process SQL
engine: `bowery-sql` (rusqlite + a SELECT-only authorizer) fed
by `bowery-tables` (13 default procfs/sysfs/etc-backed tables +
4 Bowery-internal views — peers, baseline binaries, alerts,
audit — + 7 scalar file/hash functions). Streams chunked
`OperatorResult::SqlChunk` envelopes over QUIC. Multi-agent
fan-out uses operator-signed delegation: the original
operator's Ed25519 signature on an `OperatorAuthorization`
rides inside the relay-forwarded envelope; peers verify
against their own `[operators]` set and seal `SqlChunk`
envelopes directly for the operator, so the relay can drop
but cannot forge or tamper. See
[`DESIGN-NATIVE-SQL.md`](DESIGN-NATIVE-SQL.md) for the full
design + slice plan.

---

## 11. Build, packaging, deployment

- `cargo build --release` builds agent and CLI.
- eBPF crate compiled for `bpfel-unknown-none`, embedded as a static byte slice in the loader binary.
- Distribution: `.deb` via `cargo-deb`, `.rpm` via `cargo-generate-rpm`. Static musl build for the CLI.
- Systemd unit with `CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_NET_ADMIN`, `NoNewPrivileges=yes`, `ProtectSystem=strict`, dedicated `bowery.slice`.
- Reproducible builds. Release binaries signed with a separate release key.
- Model manifest server hosts signed `manifest.json` per model:

```json
{
  "name": "gemma-3-1b-it-q4_k_m",
  "version": "1.0.0",
  "size": 870123456,
  "sha256": "…",
  "signed_by": "<operator_pubkey_fp>",
  "signature": "<base64 ed25519 sig over (name,version,size,sha256)>"
}
```

For v0.1 the mirror may proxy HuggingFace; the manifest signature is what the agent trusts.

---

## 12. Testing strategy

- **Unit**: per-crate.
- **eBPF verifier tests**: each program built and verifier-loaded in CI on multiple kernels via `vmlinux` fixtures.
- **Protocol fuzzing**: `cargo-fuzz` on envelope decoding, signature verification, question/answer state machine.
- **Multi-node E2E**: `tests/e2e/` harness spawning 5 firecracker microVMs; runs known-malicious behavior on one; asserts (a) detection, (b) whisper exchange, (c) configured response fires, (d) alert reaches an operator on any other node.
- **Adversarial**: Sybil neighbor injection, replay, key-rotation race, partition recovery, malformed envelope DoS.
- **Performance**: continuous benchmark of CPU / RAM / event-drop rate under workload generators (`stress-ng`, `nginx`, `postgres`).

---

## 13. Phased delivery

| Phase | Scope | Crates introduced |
|---|---|---|
| **0. Skeleton** | Workspace, CI, packaging, identity-key gen, no-op agent | `bowery-agent`, `bowery-cli`, `bowery-crypto` |
| **1. Mesh** | chitchat membership + QUIC RPC + signed envelopes + TOFU + fingerprint pinning | `bowery-proto`, `bowery-mesh`, `bowery-whisper` (skeleton) |
| **2. Visibility** | eBPF program set, ringbuf drain, enrichment, sqlite baseline (read-only mode) | `bowery-events`, `bowery-ebpf`, `bowery-ebpf-loader`, `bowery-baseline` |
| **3. Pre-filter + scoring** | Rules + baseline scorer + behavior aggregator + role-vector computation | (within `bowery-baseline` + `bowery-mesh`) |
| **4. LLM analyzer** | candle backend, model fetch, cgroup caps, structured prompts, context builder | `bowery-llm` |
| **5. Whisper Q&A** | Two-tier privacy fingerprints, role-similarity peer selection, capsule exchange | `bowery-whisper` (full) |
| **6. Operator IO** | CLI commands, typed `OperatorCommand` / `OperatorResult` envelopes, mesh inbox + roaming subscribe | expand `bowery-cli` |
| **7. Response** | Action engine, two-tier autonomy gating, standing authorization | `bowery-response` |
| **8. Hardening** | Fuzzing, adversarial tests, key rotation, neighbor add/remove protocol | (all) |
| **9. Native SQL surface** | Pure-Rust SQL engine + table set, streaming wire, multi-agent fan-out with operator-signed delegation, scalar file/hash funcs, operator peer manifest CLI, security audit closure | `bowery-sql`, `bowery-tables` |

Phases 0–9 shipped. Estimated 5–6 months for one engineer to defensible v0.1.

---

## 14. Open questions / future work

Recorded here so they don't get lost; not blocking for v0.1.

- Real PSI for binary-hash sets if Phase-1 fingerprint privacy proves insufficient.
- LLM-generated role embeddings as a richer alternative to deterministic vectors.
- Multi-OS support (macOS via Endpoint Security framework; Windows via ETW + Defender).
- Cross-neighborhood federation (sharding strategy above 5k nodes per neighborhood).
- Operator key rotation ceremony (currently described informally).
- Differential privacy on role vectors for small / heterogeneous fleets.
