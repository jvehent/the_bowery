# The Bowery — Why This Exists

*A distributed Linux EDR in which agents ask their neighbors before deciding
something is malicious.*

This document is the project's "why". It is meant to stand on its own: if you
have never seen the code, this should tell you what problem The Bowery is
trying to solve, what we want it to become, how the pieces actually work, and
which parts are real today. [DESIGN.md](DESIGN.md) is the engineering source of
truth, [IMPLEMENTATION.md](IMPLEMENTATION.md) is the code-level walkthrough, and
[INSTALL.md](INSTALL.md) is how you run it. This is the argument behind all
three.

---

## 1. The problem

Every mainstream endpoint detection product is built the same way. An agent on
each host collects telemetry, ships it to a central service, and that service
decides what is malicious. The agent is a sensor; the intelligence lives
somewhere else.

That design has real advantages — a central view can correlate across hosts,
and detection content can be updated once for everyone. But it carries costs
that are structural, not incidental:

**You send everything, forever, to decide almost nothing.** The overwhelming
majority of collected telemetry is never looked at by anyone. It is shipped,
stored, indexed, and billed for, so that a small fraction of it can answer a
question later. The economics of that push vendors toward sampling and
retention limits, which quietly remove the data you needed on the day you
needed it.

**"Normal" is defined globally, but abnormality is local.** A central model
knows what is common across its whole customer base. It does not know that on
*your* build host, a compiler spawning a linker at 3 a.m. is routine, while the
same event on a database primary is not. Fleet-wide baselines produce the
familiar failure mode: alerts that are technically accurate and operationally
useless, tuned into silence within a quarter.

**The pipe is a single point of failure and a single point of leverage.** If
the connection to the control plane is down, the fleet is blind. If the control
plane is compromised, everything it can see is exposed and everything it can
command is under someone else's control. And the data in transit is your
production estate's most sensitive operational record: every process, every
path, every connection.

**Detection latency is bounded by a round trip you don't control.** Local
decisions are gated on a remote service's availability and queue depth.

None of this means centralized EDR is wrong. It means there is an unexplored
point in the design space, and that point has properties worth wanting.

---

## 2. The idea

> Instead of every agent reporting to a central authority, each agent asks the
> other agents.

The Bowery is a **neighborhood watch for production fleets**. When an agent
observes something it cannot immediately explain, it does not phone home. It
whispers to a handful of peers that look like it — same role, similar software
profile — and asks a narrow question:

> *"I just saw this binary run. Have you ever seen it?"*

The answers change what the local agent believes. If every peer has seen it,
it's a normal fleet artifact and the alert is probably noise. If none of them
has ever seen it, this host is doing something the rest of the neighborhood
doesn't do — and that is exactly the shape of an intrusion.

That single question does something a central pipeline structurally cannot: it
computes **relative rarity within your actual environment**, at the moment of
the event, without anyone shipping their process table anywhere.

### Why "The Bowery"

A bowery is a neighborhood: people who don't report to a central authority,
but who know what normal looks like on their own block and notice when
something isn't. That is the whole thesis in one word. Agents are neighbors,
not sensors.

### The three properties we're buying

1. **Detection is local and immediate.** No round trip to a control plane. An
   agent that is cut off from every peer still detects, still alerts, still
   enforces — with less context, but it does not go blind.
2. **Only conclusions cross the trust boundary, not raw data.** Agents exchange
   truncated fingerprints, not paths, arguments, or file contents. Operators
   receive alerts, not firehoses. Queries are answered where the data lives.
3. **There is no central thing to compromise.** There is no server holding
   every host's telemetry, and no credential that unlocks the fleet. The
   operator is a key, not a service.

---

## 3. What we want it to be

**A security tool for people who run their own infrastructure and want to
understand it.** Operators, not end users. The interface is a signed CLI, a SQL
surface, and a terminal console — because that is what someone investigating an
incident at 2 a.m. actually wants.

**Honest about what it knows.** A recurring design rule, applied everywhere: an
absence of alerts must never be indistinguishable from an absence of
monitoring. If the event queue overflows, the drops are counted and queryable.
If enforcement fails, it is recorded as *failed*, not as *suppressed by
policy*. If a host stopped recording an hour ago, `bowery_eventlog_status` says
so. A silent EDR is worse than no EDR, because it buys confidence it hasn't
earned.

**Small enough to run anywhere.** The reference deployment includes Raspberry
Pis on a Tailscale network alongside x86 servers. Static musl binaries, no
runtime dependencies, bounded memory and CPU. If it can't run on a Pi, it's too
heavy for the edge of a real fleet.

**Auditable end to end.** Every enforcement action produces a signed envelope
in a hash-chained log. Every operator command is signed. Every alert is
attributable to the agent that raised it, cryptographically, all the way to the
console.

### Explicit non-goals

- **Not a SIEM.** We are not building a place where all the data goes. That is
  the design we're reacting to.
- **Not cross-platform, yet.** Linux ≥ 5.13 with BPF-LSM. No fallback path, by
  choice — a degraded second implementation is how visibility claims become
  lies.
- **Not a managed service.** The operator is the control plane. There is
  nothing to sign up for.
- **Not LLM-first.** The embedded model writes rationale and assists triage. It
  is not the detector. A system whose detection quality depends on a 600M-
  parameter model's mood is not a security tool.

---

## 4. How it works

### 4.1 The shape of an agent

```
┌───────────────────────── Linux host ──────────────────────────┐
│                                                               │
│  kernel                    user-space agent                   │
│  ┌────────────────┐        ┌──────────────────────────────┐   │
│  │ eBPF           │──ring─▶│ enrich → record → analyse    │   │
│  │  tracepoints   │  buf   │                              │   │
│  │  LSM hook      │◀──map──│ baseline · rules · LLM       │   │
│  └────────────────┘ block  └──────────────────────────────┘   │
│                                    │                          │
│           ┌────────────────────────┼────────────────────┐     │
│           ▼                        ▼                    ▼     │
│    append-only              whisper round         response    │
│    event log                 (ask peers)          engine +    │
│    (SQLite)                       │              signed audit │
│           │                       │                           │
└───────────┼───────────────────────┼───────────────────────────┘
            │                       │
      SQL surface            gossip mesh (UDP 9901)
      (operator queries)     whisper RPC (QUIC 9902)
```

### 4.2 Kernel visibility

Instrumentation is eBPF via [aya](https://aya-rs.dev) — pure Rust, no libbpf C
dependency. Three tracepoints (process exec, exit, socket state change) plus an
LSM hook on `bprm_check_security`, which is both an observation point and the
enforcement point for execution blocking.

The kernel floor is 5.13 with `CONFIG_BPF_LSM=y` and `bpf` in the active LSM
list. There is deliberately no fallback: an agent that silently degrades to
weaker visibility on an unsupported kernel is an agent whose coverage claims
can't be trusted. It fails fast and says why.

Events are enriched in user space (pid → exe path, sha256, cgroup → container)
and folded into *episodes* — a process and the activity attributable to it —
which are what the analyzer reasons about.

### 4.3 Local analysis

Three layers, cheapest first:

**Baseline.** A local SQLite store of what this host has seen before: binaries
by SHA-256 with first/last-seen and a count, plus process lineage (which parent
spawned which child, how often). First-time-ever execution of a binary scores
high on its own. This is the fastest and most valuable signal on a stable
server, and it costs one indexed lookup.

**Rules.** A small deterministic rule set (execution from a world-writable
path, missing exe path, suspicious argument patterns) plus **operator-defined
rules** from config: watch these files, alert on these process shapes. Operator
rules are queryable over SQL, so "what is this fleet actually watching?" is a
question you can answer across every host at once.

**The LLM.** Optional and feature-gated; the default build ships a
deterministic mock analyzer. When enabled, a small local model (Gemma 4, Qwen3
via llama.cpp) receives a *pre-filtered* episode — only things that already
scored suspicious — along with the neighborhood context from the whisper round,
and produces a human-readable rationale and suggested actions. It runs entirely
on the host. Nothing is sent anywhere.

The ordering matters: the LLM is the last and most expensive stage, it never
sees the majority of events, and removing it degrades explanation quality
rather than detection.

### 4.4 The whispering protocol

This is the part that makes the project what it is.

**Discovery.** [chitchat](https://github.com/quickwit-oss/chitchat) — SWIM-style
gossip over UDP — handles membership and a replicated key-value store. Agents
publish their role vector, a bloom summary of what they've seen, their whisper
address, and their membership grant. Bootstrap is via a seed list; no multicast
assumption, because multicast doesn't exist in a VPC.

**Transport.** QUIC via [quinn](https://github.com/quinn-rs/quinn), with mTLS
over raw Ed25519 public keys (RFC 7250). There is no PKI and no certificate
chain validation — authentication is **fingerprint pinning**. Every message is
a signed envelope, bound to its recipient, with a replay guard and clock-skew
bounds. Connections are pooled and bidirectional, so a peer can whisper back
through the same socket without needing its own reachable listener.

**Privacy: two-tier fingerprints.** Agents never exchange file paths, hashes,
or contents. They exchange a *tier-1 fingerprint*: the first 8 bytes of
`SHA-256(domain ‖ sha256)`. That is enough to ask "have you seen this thing?"
and not enough to enumerate what a peer has. Peers also publish a bloom filter
summarizing their tier-1 set, which lets an asker skip peers that definitely
haven't seen an artifact without dialing them at all.

**Who gets asked.** Not everyone — that would be a broadcast storm and a
privacy leak. Each agent computes a **role vector**: a deterministic feature
vector derived from its own baseline (what kinds of binaries it runs, in what
proportions), projected into a fixed-width space. Peers are ranked by cosine
similarity, and the top-K most similar are asked. A web server asks other web
servers. This is self-learned; nobody labels hosts.

**Quorum confirmation — and the trap in it.** When the answers come back, the
agent computes a verdict. Here is the subtlety that shaped the implementation:

> A peer answering "yes, I have this binary too" is reporting **prevalence**.
> Prevalence argues the binary is a *normal fleet artifact* — that is,
> **more benign**.

So the intuitive reading is exactly backwards. Confirmation is driven by peers
that report **never seen it**: rarity is the anomalous signal. Of the peers
actually asked:

| bucket | meaning | counts toward quorum |
| --- | --- | --- |
| `peers_unseen` | replied, never seen it | **yes** — rarity is the signal |
| `peers_seen` | replied, has it too | no — argues normal fleet artifact |
| `peers_no_reply` | timeout or dial failure | no — silence is not evidence |

Both numbers are reported, so an operator can distinguish "nobody has this"
from "everybody has this" rather than being handed a single opaque score. When
`peers_unseen` meets the configured quorum, the agent appends a *superseding*
alert marked confirmed, and the console highlights it.

This same insight forced a second change. The bloom pre-filter — an
optimization that skips peers who definitely haven't seen an artifact — filters
out **precisely the peers a quorum needs**. Left enabled, `peers_unseen` would
sit at zero forever and nothing could ever confirm. It now stands down when
confirmation is on. There is a second, independent reason: bloom summaries ride
plain unauthenticated gossip, and as a dial-avoidance hint a forged one costs a
skipped query, but as *quorum evidence* it would let anyone who can reach the
mesh manufacture confirmed alerts. Confirmation is built only from signed
answers.

### 4.5 History: the append-only event log

An alert that fires at 14:32 is useless if you cannot ask what the host was
doing at 14:32. The baseline stores aggregates — counts, first-seen, last-seen
— which answers "is this normal here?" but folds away the individual
observations, so it cannot reconstruct a timeline.

So each agent keeps its own **append-only event log**: one SQLite row per
observed event (exec, exit, network connect, file open, file change), in append
order, exposed as the `bowery_events` SQL view.

Several decisions here are worth stating because they generalize:

- **Record first, analyse second.** Every event goes to the log regardless of
  whether anything scores it. The value of a history is precisely that it
  contains the things nobody thought were interesting at the time. (This is
  also the only retention for process exits and network connections, which the
  analyzer has no scoring path for yet.)
- **Recording must never block detection.** The write path is a bounded channel
  written without blocking; when it saturates, events are *dropped* — an fsync
  stall must not become a detection stall. But every drop is counted and
  surfaced, because a silent gap looks exactly like a quiet host.
- **Append-only, with a policy pruner.** Nothing rewrites a recorded row. The
  only deletion is retention, oldest-first, bounded by both an age limit and a
  hard row ceiling. Sequence numbers are never reused, so a deletion is visible
  as a gap.
- **Queries don't copy the log.** The SQL surface attaches the log file
  read-only and views it, so a multi-million-row history costs nothing to
  register and queries use its real indexes.

Nothing is shipped anywhere. The fleet-wide timeline is reconstructed by
*asking the hosts*, which is the same principle as the whisper protocol applied
to investigation instead of detection.

### 4.6 The SQL surface

Agents expose their own state — and the host's — through a native SQL engine:
`processes`, `listening_ports`, `users`, `os_version`, `kernel_modules`, and
Bowery-specific
views like `bowery_alerts`, `bowery_events`, `bowery_peers`,
`bowery_mesh_peers`, `bowery_revocations`, `bowery_audit`.

```sql
SELECT ts_unix_ms, kind, comm, exe_path, dst_addr, dst_port
FROM bowery_events
WHERE ts_unix_ms BETWEEN ? AND ?
ORDER BY seq;
```

The engine is SELECT-only, enforced by a SQLite authorizer that denies every
non-read operation, with per-query timeouts, row caps, cell-size caps, and
cooperative cancellation.

**Fan-out** is where it gets interesting. `--fanout` relays a query across the
mesh, and each peer **seals its results directly for the operator** — the
relaying agent forwards bytes it cannot read or forge. One question, answered
by every host, with no central store and no relay in a position to lie about
the answers.

### 4.7 Response and audit

Two actions today: `kill_process` (SIGKILL by pid) and `block_exec` (add a
`comm` to a kernel-side LSM blocklist so subsequent execs get `EPERM`).

Every action produces a **signed audit envelope** in a hash-chained local log,
recording the episode that motivated it and what actually happened. The outcome
vocabulary is deliberately precise: `Executed`, `Suppressed` (policy said no),
`AlreadyGone`, and `Failed`. That last one exists because of a real bug — the
systemd unit didn't grant `CAP_KILL`, so kills against non-root targets
returned `EPERM` and were recorded as `Suppressed`, indistinguishable in the
audit log from a deliberate policy decision. Enforcement that silently doesn't
work reads as containment. It must not.

### 4.8 The operator

There is no server. An operator is an Ed25519 key.

- **`bowery` CLI** — signed commands to any agent: SQL queries, alert tailing,
  YARA distribution, trust operations, reachability checks.
- **`bowery-console`** — a ratatui terminal console: SQL REPL, live alert tail,
  mesh map, audit view, peer manifest, readiness doctor, and an LLM chat that
  drafts SQL. Every pane is browsable, every row opens a detail view, and
  detail views *pivot*: from an alert you can jump to the audit entries for its
  episode, the baseline row for its hash, the processes currently running that
  binary, or the file's state on disk right now.
- **Roaming inbox.** Alerts land in a per-agent inbox keyed by operator
  fingerprint, drained with a monotonic cursor. An operator can disconnect,
  move, and reconnect to any node without losing alerts.

---

## 5. The trust model

This is a security product, so the question "what can an attacker do?" deserves
a direct answer.

### Identity

Every agent and every operator is an Ed25519 keypair. A fingerprint is
`SHA-256(pubkey)`. All authentication is fingerprint pinning; there is no CA
and no chain validation, because a PKI would be a central authority in a system
whose entire premise is not having one.

### Admission: how an agent joins the mesh

The original model was trust-on-first-use: during a bootstrap window, pin any
peer seen gossiping. The problem is that gossip is plain, unauthenticated UDP —
so "can send a packet to this port during a window" was the *entire* admission
control, and once pinned there was no way back out.

Admission is now an operator-signed **membership grant**: a statement that a
given agent fingerprint belongs in a given cluster, signed by a key every agent
already trusts. Agents publish their own grant in gossip; peers verify it
offline. Three bindings make a publicly-readable grant safe to publish:

- bound to **one agent fingerprint**, so a grant harvested off the wire is
  useless under any other key;
- bound to **one cluster**, so a staging grant can't admit a peer to production;
- optionally bound to a **time window**.

A pleasant consequence: **trust distributes itself.** A grant is
bearer-verifiable, so a new agent carries its own admission ticket. Adding a
host requires zero changes to the existing fleet — no command to fan out, no
convergence to worry about.

TOFU remains the default, because flipping an existing fleet to grant-only
before every agent has a grant would partition it. The migration is checkable
before you commit to it:

```sql
SELECT fingerprint_hex, grant_state FROM bowery_mesh_peers;  -- with --fanout
```

### Ejection: revocation

An operator-signed revocation permanently removes an identity. It outranks an
existing pin — evicted on receipt, not at the next restart — because a revoked
peer that stays pinned means containment contained nothing. There is no
un-revoke: an attacker who can make an agent *forget* a revocation has undone
the containment, so re-admitting a rebuilt host means giving it a new key.

Revocations propagate across the mesh, and the security argument is different
from a grant's in an instructive way. A revocation is **self-authenticating** —
it carries an operator signature over its own fields, so every agent verifies it
directly rather than trusting the peers that relayed it. A compromised relay can
*drop* a revocation; it cannot forge one, and cannot use the relay path to eject
healthy agents (which would hand any single compromised peer a fleet-wide
denial of service).

The asymmetry between the two is principled: **a grant is presented by its
subject, so it self-distributes; a revocation is about a third party who has
every reason not to relay it, so it must be pushed and confirmed.** Hence
`bowery_revocations` is queryable fleet-wide — convergence is verified, not
assumed.

### What a compromised peer can and cannot do

Assume an attacker fully controls one enrolled agent.

**Can:** lie about its own answers (claim it has or hasn't seen a binary),
influencing quorum by one vote; refuse to relay; drop results passing through
it; consume its rate-limited share of neighbors' query budget.

**Cannot:** read other agents' data (results are sealed for the operator, not
the relay); forge another agent's alerts or query results (attribution is bound
to the authenticated envelope sender, never a self-declared field); forge a
membership grant or revocation (both need an operator key); truncate a fan-out
result stream (the completion terminator is honored only from the authenticated
relay — a real bug we found and fixed, where any peer could silently end the
fleet's results); or manufacture confirmed alerts (confirmation is built only
from signed answers, never from unauthenticated gossip).

### Host hardening

The agent runs under a hardened systemd unit: a minimal capability set
(`CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN`, `CAP_KILL`, `CAP_SYS_PTRACE`), no
ambient capabilities, a syscall allowlist, and `MemoryDenyWriteExecute=yes`.
Keys are mode 0600, TPM-sealed where available. Every trust file on disk is
re-verified against operator signatures on load, so editing one can *remove* a
trust decision but never manufacture one.

---

## 6. Design principles

These emerged from building it, and they're worth stating because they explain
choices that would otherwise look arbitrary.

**Fail visible, never silent.** Every degradation is countable and queryable.
Dropped events, failed enforcement, unreachable peers, hosts that stopped
recording. The worst outcome for a security tool is a calm dashboard produced
by a broken sensor.

**Bound everything.** Every queue, every rate, every hop count, every row
count, every cell size, every retention policy. An unbounded path in a system
that talks to peers is an amplification primitive waiting to be found.

**Degrade, don't refuse.** An agent whose event log won't open still detects and
alerts; it logs the failure and continues. An agent that refuses to start
because a disk is full has converted a storage problem into a security
incident.

**Evidence, not assertion.** Trust decisions are backed by artifacts that can be
re-verified: signed grants, signed revocations, signed audit envelopes, signed
results. Files hold the signed artifacts themselves rather than digests of
them, so the file has no authority of its own.

**Verify at the edge.** Every agent verifies every claim itself, against keys it
already holds. No component is trusted because of where it sits in the topology.

**Ask the hosts.** Whether the question is "have you seen this binary?" or "what
happened at 14:32?", the answer is computed where the data already lives.
Nothing is centralized because centralizing it would recreate the thing we're
avoiding.

---

## 7. What's real, and what isn't

Being straight about this matters more than looking finished.

**Built and running** on a live fleet (an Ubuntu host plus Raspberry Pis over
Tailscale): eBPF process monitoring with LSM-based exec blocking; local baseline
and rule scoring; the whisper Q&A protocol with role-similarity peer selection
and quorum-confirmed alerts; the append-only event log; the native SQL surface
with cross-fleet fan-out; operator-defined file and process monitoring; YARA
rule distribution that propagates across the mesh; signed hash-chained audit
logging; signed mesh enrollment and revocation with propagation; the operator
CLI and terminal console; a Pi/Tailscale deploy kit with hardened systemd units.

**Honestly missing**, in rough order of how much it matters:

1. **Detection content.** There is a rule engine with a handful of rules. A
   detection *engine* with no detection *library* is a framework, not a
   product. Persistence mechanisms, privilege escalation, credential access,
   defense evasion, and above all lateral movement are unwritten — as is a
   coverage map against a framework like ATT&CK.
2. **Cross-host correlation.** This is the capability the architecture exists
   for and the one that isn't built yet. Lateral movement is invisible on one
   host and obvious across two: agent B sees an inbound SSH and whispers *"did
   anyone just open an outbound SSH to me?"*, and agent A confirms. No per-host
   EDR can make that call. Nothing else in this list is as differentiating.
3. **Rarity as a general primitive.** The whisper round answers exactly one
   question today (have you seen this binary?). The same machinery generalizes
   to parent→child process pairs, listening ports, and outbound destinations.
   The process-lineage table is already populated on every exec — and read by
   nothing.
4. **Coverage telemetry.** The event log reports whether it's recording. The
   eBPF layer doesn't yet report whether its probes are still attached or
   whether the kernel ring buffer is dropping.
5. **Quorum-gated enforcement.** The design specifies hard actions requiring
   standing operator authorization *or* k-of-n peer quorum. The quorum signal
   now exists and is operator-visible, but the response engine doesn't yet
   consume it.
6. **Peer-witnessed audit.** Root on a host means deleting the local audit log.
   Peers could witness the chain head, making deletion detectable — an attacker
   can't retract hashes their neighbors already hold. This falls naturally out
   of the protocol that already exists.
7. **Identity rotation**, richer response actions (network isolation, dry-run
   mode), and YARA scanning on aarch64-musl (the crate lacks bindings; rules
   still store and propagate there, they just don't execute).

---

## 8. Where this goes

The near-term work is unglamorous and necessary: detection content, coverage
telemetry, and the DoS hardening pass. Those are what make it usable on
something you care about.

The interesting work is the part only this architecture can do. Centralized EDR
has spent fifteen years getting good at collecting everything and deciding
centrally. The unexplored questions are the ones that only make sense when the
agents can talk to each other:

- **Rarity as a detection primitive**, computed across a live fleet without
  central collection, and without any host revealing what it runs.
- **Distributed detections** that no single host could make, where the evidence
  is split across two machines and the correlation happens between them.
- **Herd immunity** — one agent confirms a bad artifact and the fleet blocks it
  within seconds, with no console round trip.
- **Tamper-evidence through mutual witness**, where the property that makes
  logs trustworthy is that your neighbors remember what you told them.

The substrate for all of that — identity, signed transport, a gossip mesh, peer
selection, a query language, a local history — is built. What remains is
teaching the neighborhood what to talk about.

---

*The Bowery is MPL-2.0 and public from day one. See [README.md](README.md) to
get oriented, [INSTALL.md](INSTALL.md) to run it, [DESIGN.md](DESIGN.md) for
architecture decisions, and [IMPLEMENTATION.md](IMPLEMENTATION.md) for how the
code is put together.*
