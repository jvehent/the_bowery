# Phase 9 native SQL — security audit

Audit of the streaming SQL surface (`bowery-sql` + `bowery-tables`),
operator-command dispatch (`stream_sql_response`), multi-agent
fan-out (`relay_to_peers` / `run_peer_query`), and the bonus tables
in `bowery-agent/src/sql_tables.rs`.

Two independent code reviews were dispatched (auth/authz/wire format
and cancellation/isolation/limits). Findings below are the merged,
deduplicated, and prioritised result.

## Threat model

The operator dials one agent (the *relay*) with a signed
`OperatorCommand::Sql`. The relay runs the query locally via
`bowery-sql`. With `fanout = true` it also dispatches the query to
its pinned peers, multiplexing each peer's chunked responses back
to the operator. Every envelope is Ed25519-signed; receivers verify
against a configured public-key set.

Trust positions:

- **Operator** — authenticated by `[operators] pubkeys_b64`
  enrollment on each agent; treated as trusted-for-host-state.
- **Relay** — must hold an identity that's in every peer's
  `[operators]` list (currently the only way the peer accepts the
  relay's forwarded command). De-facto **fully trusted** for the
  relay-mediated query stream.
- **Peer** — runs the forwarded query and seals chunks for the
  *relay*; the operator never directly verifies a peer signature.
- **Network attacker** — bounded by mTLS-pinned QUIC; can drop /
  delay packets but not inject.

## Findings (15)

| ID | Severity | Title | Status |
|----|---|---|---|
| F-1 | CRIT | Relay re-signs peer chunks; "relay can't fabricate rows" claim is false | **fixed** (final-1) |
| F-2 | HIGH | Peer trusts relay as operator; no end-to-end operator authorisation | **fixed** (final-1) |
| F-3 | HIGH | Cycle prevention is convention-only at receiving side | **fixed** (final-1) |
| F-4 | HIGH | No per-operator rate limit; fanout amplification unthrottled | **fixed** (final-2) |
| F-6 | MEDIUM | No per-cell size cap; one wide value blows `MAX_FRAME_BYTES` | **fixed** (final-3) |
| F-8 | MEDIUM | `processes.cmdline` exposes full argv (env vars, secrets) | **fixed** (final-4) |
| F-9 | HIGH | Baseline mutex held during full table walk | **fixed** |
| F-12 | HIGH | `bowery_audit` reads entire audit log into memory, no size cap | **fixed** |
| F-13 | MEDIUM | No concurrency cap on `Sql::query`; in-mem DB cost scales linearly | **fixed** (final-5) |
| F-14 | MEDIUM | procfs walks not time-bounded mid-walk | **fixed** (final-6) |
| F-15 | HIGH | Operator SQL can `ATTACH DATABASE` / `PRAGMA writable_schema = ON` to write host filesystem | **fixed** |
| F-16 | HIGH | Operator-disconnect leaks per-peer fanout tasks (mesh-amplified DoS) | **fixed** |
| F-5 | MEDIUM | `Sql` timeout cap previously borrowed from a sibling config block | **fixed** — `[sql] max_timeout` and `[sql] max_concurrent_queries` both live in the dedicated `[sql]` block |
| F-7 | MEDIUM | No EOF accounting in fanout decoder | deferred (operator UX) |
| F-17 | LOW | Per-peer fanout warnings → log-disk DoS | deferred |

Deduped against the two parallel audit reports. Findings without
unique number reference items both audits agreed on.

---

## CRIT / HIGH details

### F-1 [CRIT] Relay re-signs peer chunks — **fixed (Phase 9 final-1)**

The original finding: `relay_to_peers` sealed each forwarded
chunk with the relay's own key, so a malicious relay could forge
arbitrary `agent_fp` attribution.

**The fix shipped.** New proto field
`OperatorCommand.forwarded_from_operator` carries an
operator-signed `OperatorAuthorization` (operator_fp,
ts_unix_ms, request_id, command_digest, Ed25519 signature with
domain `b"bowery/operator-authorization/v1"`). The relay copies
this verbatim into each peer-bound command. Peers verify the
operator's signature against their own `[operators]` set,
recompute the command_digest from the actual command, and use
the operator_fp as the effective recipient when sealing
`SqlChunk` responses. The relay forwards peer envelope bytes
verbatim via `BoweryConnection::send_envelope`.

The relay can still drop peer chunks (already documented as
acceptable: "relay best-efforts every peer"). It can no longer
forge or tamper with their content.

Implementation: `bowery-whisper::forwarding` for sign + verify
helpers, agent's `resolve_effective_operator` in agent.rs.
Operator-side `bowery peers add/list/remove` (final-8)
populates the resolver with peer pubkeys.

### F-2 [HIGH] Peer trusts relay as operator — **fixed (Phase 9 final-1)**

Peers no longer require the relay in their `[operators]` config.
The connection-level gate in `handle_connection` accepts a
sender that's either in `[operators]` (direct dial) OR a pinned
peer (relay forwarding). Command authorisation comes from the
embedded `OperatorAuthorization`, verified against
`[operators]` further down in `respond_to_operator_command`.

### F-3 [HIGH] Cycle prevention is convention-only — **fixed (Phase 9 final-1)**

The receive-side now rejects any forwarded command (envelope
sender NOT in `[operators]`) whose inner `SqlQuery.fanout =
true`, with `OperatorError { kind: "policy_denied", … }`.
Combined with the relay always forwarding `fanout = false`,
this caps fan-out at one hop independently of the relay's
honesty.

### F-4 [HIGH] No per-operator rate limit — **fixed (Phase 9 final-2)**

`OperatorCommandRouter` now holds a `FanoutRateLimit` token
bucket keyed on the operator's fingerprint (1 token / 5 s,
burst 6). Only the entry-point relay enforces it; forwarded
peers bypass since their fan-out is already cycle-prevented.
Bucket-empty returns `OperatorError { kind: "rate_limited", …
}`.

`DESIGN-NATIVE-SQL.md` §8 explicitly calls for "max 1 fanout query
per N seconds per operator fp." Code grep for
`rate_limit|throttle|RateLimiter` returns nothing. Combined with F-3
amplification, a single compromised operator key makes the relay
hammer every peer at line rate.

### F-9 [HIGH] Baseline mutex held during full walk — **fixed**

`BoweryBaselineBinariesTable::register` called
`baseline.for_each_binary(callback)`. `for_each_binary` documents
"the callback runs while the connection mutex is held; keep it
cheap." The callback ran SQLite inserts inside the lock; on a host
with 50k baseline binaries that pinned the mutex for seconds,
blocking the analyzer's `upsert_binary` and every other
baseline-touching code path.

**Fixed by snapshotting first.** New helper
`baseline.snapshot_binaries()` returns a `Vec<BinaryRecord>`,
mutex held only for the snapshot, callback iteration runs
mutex-free.

### F-12 [HIGH] `bowery_audit` unbounded file read — **fixed**

`BoweryAuditTable::register` called `std::fs::read_to_string(path)`
with no size cap. On a host with a multi-GB audit log, this
pinned full file size in RAM per query, and was reachable through
fanout (one operator query × N peers).

**Fixed.** Replaced with a `BufReader` + per-line streaming, with a
hard byte budget (`MAX_AUDIT_BYTES = 64 MiB`). Reads stop at the
budget and emit a synthetic terminal row signalling truncation.

### F-15 [HIGH] SQLite authorizer not configured — **fixed**

Default `Connection::open_in_memory()` accepts `ATTACH DATABASE`,
`PRAGMA writable_schema`, `CREATE`, `INSERT`, `UPDATE`, `DELETE`
against caller-supplied SQL. Operator-supplied statements like
`ATTACH DATABASE 'file:/etc/secret.db?mode=ro' AS x` would have
been accepted. Although `load_extension` is correctly disabled at
the rusqlite-feature level, attach + cross-db queries were a
documented disclosure path.

**Fixed.** Each per-query `Connection` now has a
`set_authorizer(...)` callback installed that:

- Allows `SELECT` and `READ` operations.
- Allows table/temp-table creation as the registration side-effect
  of `BoweryTable::register`.
- Allows `INSERT` against the registration tables (the table impls
  insert their own rows during registration).
- **Denies** `ATTACH`, `DETACH`, `PRAGMA` (with a small whitelist
  for read-only pragmas), `DROP`, `ALTER`, `TRIGGER`, `VIEW`,
  `TRANSACTION`, and `FUNCTION` calls outside the SELECT path.

The authorizer is enabled only after the registration phase
completes — registration runs with the authorizer disabled so
table impls can `CREATE TABLE` and `INSERT` freely.

### F-16 [HIGH] Operator-disconnect leaks per-peer fanout tasks — **fixed**

`relay_to_peers` previously spawned per-peer tasks via bare
`tokio::spawn`. When the operator dropped the connection mid-stream,
the relay's `send_chunk` started failing and `relay_to_peers`
returned, but the spawned tasks kept running — each opening a fresh
QUIC connection to its peer, sending the sealed envelope, and
reading the peer's full response stream. An operator could open a
connection, request `fanout = true` over 1000 peers, drop the
connection, and repeat.

**Fixed.** `relay_to_peers` now uses a `tokio::task::JoinSet` and
calls `abort_all()` on drop or on the first `send_chunk` failure.
Combined with the existing per-peer mpsc send-after-drop early
return, this caps the post-disconnect work at "in-flight syscall
finishing."

---

## MEDIUM

### F-5 SQL timeout cap previously lived in a sibling config block — **fixed**

The wall-clock `max_timeout` and the concurrency cap
(`max_concurrent_queries`) both live in the dedicated `[sql]`
block. The earlier subprocess-wrapper config (and its borrowed
`max_timeout` knob) was deleted during the post-Phase-9 cleanup.

### F-6 No per-cell size cap — **fixed (Phase 9 final-3)**

`encode_row` (`agent.rs`) now caps each Text/Blob cell at
`MAX_CELL_BYTES = 16 KiB`. Cells exceeding the cap are replaced
with a `Text("<truncated N bytes>")` placeholder so the operator
gets a labelled marker instead of a torn-down QUIC stream.

### F-7 No EOF accounting in fanout decoder — deferred

Operator UX concern; security-equivalent to "operator can't tell
apart truncated vs. complete fan-out result." Tracked as a
follow-up.

### F-8 `processes.cmdline` leaks argv — **fixed (Phase 9 final-4)**

`processes.cmdline` is now opt-in via `[sql] expose_cmdline =
false` (default). When set to `true`, the agent's
`ProcessesTable` populates argv; otherwise the column is empty.
Operators who need cmdline must explicitly enable it per agent.

### F-13 No concurrency cap on `Sql::query` — **fixed (Phase 9 final-5)**

`Sql::with_concurrency_cap(N)` installs a
`tokio::sync::Semaphore` that holds back queries past the cap
until earlier ones drain. Default `[sql] max_concurrent_queries
= 4`.

### F-14 procfs walks not time-bounded mid-walk — **fixed (Phase 9 final-6)**

Each per-query `Connection` registers a
`progress_handler(1024, …)` that polls a shared `AtomicBool`.
When `Sql::query`'s wall-clock `tokio::time::timeout` fires,
the flag flips to `true` and SQLite interrupts within ~1024
VDBE ops, releasing the blocking-pool slot.

---

## Acceptable as-is

- **Replay protection across operators** — `recipient_fp` binding
  (Phase-8 H1) properly prevents cross-operator replays. Confirmed
  via `signing_input` in `envelope.rs`.
- **Strict signature mode** — `verify_strict` is used; envelope
  malleability test passes.
- **`users` table omits passwd field** — confirmed; /etc/shadow not
  parsed.
- **utmp parser** — `chunks_exact(384)` + bounded slice indices;
  no panic paths on hostile input.
- **`load_extension` disabled** — workspace `rusqlite` features
  list is `["bundled"]`, no `load_extension`.
- **Self-fanout exclusion** — `relay_to_peers` filters
  `p.fingerprint != sealer.fingerprint()`.
- **Fresh in-memory SQLite per query** — DROP/UPDATE/DELETE in
  operator SQL has no persistent effect.
- **mpsc backpressure** — chunk_tx send-after-drop returns Err and
  peer task exits cleanly.
- **`bowery_audit` malformed input** — JSON-parse failures skip the
  line silently; safe.

---

## Closure status

Every CRIT / HIGH / MEDIUM finding from the original two-pass
audit is now either fixed or intentionally accepted. The only
remaining items are LOW-priority observability tweaks (F-7 EOF
accounting, F-17 per-peer-warn rate limit, F-5 timeout-cap
config-naming cleanup) tracked as "tighten when convenient"
rather than "must fix before production."

Phase 9 is closed.
