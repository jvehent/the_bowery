# Design — operator-signed alert silencing over the mesh

An operator looks at an alert, judges it benign, and says so once. Every
agent in the mesh stops raising that shape of finding, or raises it at a
reduced weight. The judgement travels as an operator-signed record over
the transport that already carries YARA rules and revocations.

This is the most dangerous feature in the system, and the design is
mostly about that. Everything else here fails toward noise; this fails
toward **silence**, which is the one direction the whole project refuses.
Read §4 before §3.

---

## 1. The problem the obvious design does not solve

An `episode_id` is unique per occurrence:

```
file-cred.read_netrc-1787054761
ep-484358-1787016759570261094
```

Silencing *that id* silences nothing — it will never recur. So
"annotate an alert by id" has to derive a **pattern** that matches future
alerts, and choosing that pattern is the entire design. Get it too narrow
and the operator re-annotates the same noise forever; too wide and they
have quietly turned off a detection they still believe is running.

### The key

The codebase already folds repeats on `(rule_id, path, exe)`
([`suppress.rs`](crates/bowery-analysis/src/suppress.rs)). A signed
silence uses the same triple, with the binary named by **hash** rather
than by name:

| field | on an exec alert | on a file alert |
| --- | --- | --- |
| `rule_id` | what fired | what fired |
| `exe_sha256` | the binary that ran | the **reader's** binary |
| `exe_path` | the binary's path | the file that was touched |

Anchoring on the hash is what keeps this from becoming an evasion
primitive. A silence covering `git-remote-http` reading `~/.netrc` does
**not** cover a trojanised `git-remote-http`, because the hash differs.
That is the same rule `sanctioned_readers` already follows — exempt on a
resolved exe path *and* package provenance, never on a name, because
`comm` is 16 bytes any process sets with `prctl`.

**Default match is the full triple.** Widening is explicit
(`--any-path`), and dropping the hash requires `--any-binary`, which the
CLI refuses without it.

### Blocker: `Alert` has no `rule_id`

`Alert` carries `episode_id`, `exe_sha256_hex`, `exe_path`, `suspicion`,
`rationale`, `context` — and no rule id. For file alerts the rule is
embedded in the episode string; for exec alerts the id is
`ep-<pid>-<ts>` and the rule appears only as prose at the front of the
rationale.

So there is nothing structured to key a silence on. `rule_id` becomes a
first-class field (§7 slice 1). It improves `bowery_alerts` regardless —
today you cannot ask "which rule produced these alerts" in SQL.

---

## 2. What a reduction means

`weight: f32` in `[0, 1]`, applied as a multiplier on `suspicion`:

```
silence   weight 0.0    0.95 → 0.00     never alerts
reduce    weight 0.3    0.95 → 0.285    below threshold, silent
stage     weight 1.0    unchanged       record the pattern, watch it
```

Damping rather than sampling, deliberately. Sampling silences at random
regardless of how bad a particular instance is, and makes "why did this
alert once and not the other nine times" unanswerable. Damping composes
with the threshold that already exists: a damped episode that *also*
trips something severe can still clear the bar, which is the behaviour
an operator actually wants from "this is usually fine".

`weight 1.0` is not a no-op — it records the pattern and counts matches
without changing any score, which is how you measure a silence's blast
radius before committing to it.

---

## 3. The record

```rust
/// Domain separator, distinct from every other signing domain.
pub const ALERT_SILENCE_DOMAIN: &[u8] = b"bowery/mesh/alert-silence/v1";

pub struct AlertSilence {
    /// Content id: SHA-256 over the match spec. Stable, so re-issuing
    /// the same judgement updates rather than duplicates.
    pub id: String,
    /// Mesh cluster. A staging silence must not reach production.
    pub cluster_id: String,

    // -- match spec; an empty field is a wildcard --
    pub rule_id: String,
    pub exe_sha256_hex: String,
    pub exe_path: String,
    /// Empty = fleet-wide. Set = only this host honours it.
    pub host_fp: Vec<u8>,

    /// 0.0 silences, 1.0 records without changing anything.
    pub weight: f32,
    /// Free text, carried for the audit trail. Required by the CLI.
    pub reason: String,

    pub issued_unix_ms: u64,
    /// Mandatory. An unbounded silence is a permanent blind spot.
    pub expires_unix_ms: u64,

    pub operator_fp: Vec<u8>,
    pub sig: Vec<u8>,
}
```

Self-authenticating, exactly as `Revocation` is: the record carries its
own operator signature, so a relaying peer can **drop** a silence but
never **forge** one, and every hop verifies independently rather than
trusting whoever handed it over.

Supersession is last-writer-wins on `(id, issued_unix_ms)`. Revoking a
silence is re-issuing it with `weight: 1.0` — or `bowery alerts
unsilence <id>`, which does that for you.

---

## 4. Threat model

Every other detection in this system fails toward noise. This one fails
toward silence. That changes what an operator key is worth: today it
reads data and runs queries; afterwards it can blind the fleet, quietly,
fleet-wide, for as long as the expiry allows.

The controls are load-bearing, not hardening:

| control | why |
| --- | --- |
| **Mandatory expiry**, capped at 1 year, default 90 days | An unbounded silence is a permanent blind spot nobody revisits |
| **`bowery_silences` view with `matched_count`** | A silence that suppressed 40,000 alerts must be visible as such |
| **`bowery_detections` still counts** | Record the fire *before* suppressing, so the counter never lies about what fired. `fired` stays honest; only the alert is withheld |
| **Hash required** unless `--any-binary` | A path-only silence is inherited by whatever an attacker puts at that path |
| **Cluster-bound** | A staging silence cannot reach production, same as `MembershipGrant` |
| **Operator signature verified at every hop** | Never learn a silence from a peer on the peer's say-so |
| **Written to the audit log** | A silence is an operator action against this host's behaviour, and belongs in the same signed, hash-chained record as a response action |

### Explicit non-goal: agents must never learn silences on their own

A mesh that infers "three peers suppress this, so it is probably fine
here" is a mesh where compromising one host silences the fleet. Every
silence originates with an operator signature and is verified
independently by each agent. There is no automatic path, and there
should not be one.

### Honest residual risk

An attacker holding an operator key can silence a detection *before*
using the technique it detects. Nothing here prevents that; the controls
make it **loud after the fact** — the silence is signed, attributed,
expiring, counted, queryable fleet-wide, and in the audit log. That is
detection-after-the-fact, not prevention, and the docs should say so
rather than implying otherwise.

---

## 5. Where it applies

**`AlertInbox::append`** — one choke point every alert path already goes
through.

There are 25 `Alert` construction sites across the agent. Applying the
check at each would guarantee a future detection forgets one, and the
failure mode of forgetting is an alert that *should* have been silenced
still firing — merely annoying. But the inverse arrangement, where the
check lives in a helper some paths skip, gives inconsistent behaviour
nobody can reason about. One choke point, no exceptions.

At `append`, in order:

1. `detections.record(rule_id)` — the counter is never affected by a
   silence.
2. Match against the silence store.
3. On a match, increment that silence's `matched_count` and stamp
   `last_matched_unix_ms`.
4. Apply the weight. If the result is below `alerts.threshold`, do not
   append; otherwise append with the damped suspicion and a note in the
   rationale saying which silence damped it and by how much.

Step 4's note matters: an alert that arrives at 0.4 because a silence
took it down from 0.95 reads very differently from one that was always
0.4, and an operator must be able to tell.

---

## 6. Propagation

Mirrors `RevokePush` end to end:

- `SilencePush { silence_bytes, ttl, fanout }` as `OperatorCommandBody`
  tag 14.
- Multi-hop, bounded by the `ttl` hop counter plus the per-agent
  `(operator_fp, request_id)` seen-set, so a cyclic peer graph converges
  instead of looping.
- Persisted as signed JSONL alongside `revocations.json`, re-verified on
  load — a line that fails verification is logged and skipped, never
  fatal, so one bad paste does not cost an agent every valid silence it
  holds.
- Expired entries are swept on load and on a slow timer, and the sweep
  logs what it dropped.

---

## 7. Work breakdown

Each slice ships green: `fmt`, `clippy -D warnings`, workspace tests,
and where it touches detection, a `bowery-prove` provocation.

**Slice 1 — `rule_id` on `Alert`.** Proto field, all construction sites,
`bowery_alerts` column. A required new field is exactly the pressure that
makes `AlertBuilder` worth finishing, so this slice completes the
migration that has been 2-of-13 done since it was introduced.

**Slice 2 — `bowery_analysis::silence`.** The pure logic: match spec,
wildcard semantics, weight application, expiry. No I/O, heavily tested —
including that a wildcard hash cannot be constructed by accident, and
that an expired silence matches nothing.

**Slice 3 — proto + signing.** `AlertSilence`, its domain separator,
`signing_input`, verification. Round-trip and cross-domain-replay tests
(a signature minted as a revocation must not verify as a silence).

**Slice 4 — `SilenceStore`.** Load, verify, persist, bound, sweep. Mirror
`RevocationStore`.

**Slice 5 — enforcement + visibility.** Wire into `AlertInbox::append`;
`bowery_silences` SQL view; counters; the damped-rationale note.

**Slice 6 — propagation.** `SilencePush` handling, multi-hop, seen-set,
audit-log entry on receipt.

**Slice 7 — CLI.** `bowery alerts silence <episode-id>`, `unsilence`,
`silences list`. The important part is the **blast-radius preview**:
before signing, fetch the derived pattern's match count against the local
inbox and print what it would have silenced, requiring confirmation.
Signing a silence blind is the mistake to design against.

**Slice 8 — integration + docs.** Two-agent test: operator silences on
alpha, beta honours it after propagation, and a *different* binary at the
same path still alerts. README/USAGE/ROADMAP, and an ATT&CK note that
silencing is a coverage-reducing control with its own visibility.

Slices 1–2 are independently useful and land first. Slice 5 is the point
of no return for review: after it, an unsigned bug can suppress alerts.

---

## 8. What this deliberately does not do

- **No regex or glob matching.** Exact fields with explicit wildcards. A
  pattern language is a place for a silence to match more than its author
  read.
- **No silencing by host name or `comm`.** Both are attacker-controlled.
- **No silence without a reason string.** The audit trail is the point.
- **No unbounded silence.** Expiry is mandatory.
- **No automatic learning.** See §4.
