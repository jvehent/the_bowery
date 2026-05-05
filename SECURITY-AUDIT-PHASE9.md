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
| F-1 | CRIT | Relay re-signs peer chunks; "relay can't fabricate rows" claim is false | **doc-fixed**; code fix deferred |
| F-2 | HIGH | Peer trusts relay as operator; no end-to-end operator authorisation | **doc-fixed**; code fix deferred |
| F-3 | HIGH | Cycle prevention is convention-only at receiving side | **doc-fixed**; code fix deferred |
| F-4 | HIGH | No per-operator rate limit; fanout amplification unthrottled | deferred |
| F-9 | HIGH | Baseline mutex held during full table walk | **fixed** |
| F-12 | HIGH | `bowery_audit` reads entire audit log into memory, no size cap | **fixed** |
| F-15 | HIGH | Operator SQL can `ATTACH DATABASE` / `PRAGMA writable_schema = ON` to write host filesystem | **fixed** |
| F-16 | HIGH | Operator-disconnect leaks per-peer fanout tasks (mesh-amplified DoS) | **fixed** |
| F-6 | MEDIUM | No per-cell size cap; one wide value blows `MAX_FRAME_BYTES` | deferred |
| F-7 | MEDIUM | No EOF accounting in fanout decoder | deferred |
| F-8 | MEDIUM | `processes.cmdline` exposes full argv (env vars, secrets) | deferred |
| F-13 | MEDIUM | No concurrency cap on `Sql::query`; in-mem DB cost scales linearly | deferred |
| F-14 | MEDIUM | procfs walks not time-bounded mid-walk | deferred |
| F-5 | MEDIUM | `Sql` timeout cap silently borrowed from `[sysquery]` config | deferred |
| F-17 | LOW | Per-peer fanout warnings → log-disk DoS | deferred |

Deduped against the two parallel audit reports. Findings without
unique number reference items both audits agreed on.

---

## CRIT / HIGH details

### F-1 [CRIT] Relay re-signs peer chunks

`relay_to_peers` (`crates/bowery-agent/src/agent.rs`) seals each
forwarded chunk with the relay's own key:

```rust
chunk.agent_fp = peer_fp.as_bytes().to_vec();
send_chunk(conn, sealer, &operator, request_id, chunk).await?;
```

The peer's signature is consumed and discarded by `run_peer_query`'s
`envelope_verifier.open(...)`. Each chunk reaching the operator is
sealed by the relay, not the peer.

**Implication:** a malicious relay can forge `SqlChunk` with
arbitrary `agent_fp` attribution. The `agent_fp` field is an
unauthenticated label, not a cryptographic attestation.

**`DESIGN-NATIVE-SQL.md` §8 claimed** "relay can't fabricate rows."
The doc has been updated (this audit pass) to admit that the relay
is fully trusted in the current implementation; the e2e
peer→operator signing path is queued as a follow-up under "What's
deferred."

**Code fix (deferred to slice 9):** propagate the operator's
original signed envelope as `OperatorCommand.forwarded_from_operator`
(new bytes field) to peers; peers seal `SqlChunk` envelopes
**directly for the operator**; relay forwards bytes verbatim via a
new `send_envelope_raw(bytes)` API. Operator-side verifier needs
each peer's pubkey in the static resolver; the operator-side
"peer manifest" idea (`bowery peers add`) becomes load-bearing.

### F-2 [HIGH] Peer trusts relay as operator

`run_peer_query` constructs an `OperatorCommand` and seals it with
the relay's `Sealer`. The peer's `handle_connection` gates on
`operators.resolve(&env.sender)` — `env.sender` is the relay.
Therefore **the peer's `[operators]` set must include the relay's
pubkey**. The original operator's signature is never propagated.

A relay's compromise = full SQL-surface authority on every peer
that lists it as operator, even when no human operator is online.

Linked to F-1; same architectural fix
(`forwarded_from_operator`).

### F-3 [HIGH] Cycle prevention is convention-only

`respond_to_operator_command` unconditionally honors
`SqlQuery.fanout`. Cycle prevention relies on `run_peer_query`
hard-coding `fanout: false` when the relay forwards to peers.
Nothing on the receive side rejects a `fanout = true` command from
an operator-equivalent sender.

A relay-key holder (or compromised operator) can dial peer Y
directly with `Sql{ fanout: true }` and turn Y into the apex of a
new fanout. With N agents trusting the attacker as operator, the
attacker generates ~N×|peers| queries.

**Fix (deferred):** with `forwarded_from_operator` (F-1) in place,
the receive-side gate becomes "if `forwarded_from_operator` is
present AND `fanout = true` → reject `policy_denied`."
Alternatively a hop-count varint capped at 1.

### F-4 [HIGH] No per-operator rate limit

`DESIGN-NATIVE-SQL.md` §8 explicitly calls for "max 1 fanout query
per N seconds per operator fp." Code grep for
`rate_limit|throttle|RateLimiter` returns nothing. Combined with F-3
amplification, a single compromised operator key makes the relay
hammer every peer at line rate.

**Fix (deferred):** per-operator-fp token bucket on
`respond_to_operator_command`; emit
`OperatorError { kind: "rate_limited" }` on bucket empty.

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

## MEDIUM (not fixed in this pass)

### F-5 `[sysquery] max_timeout` reused for SQL

The router's `max_timeout` is shared across both command kinds.
Add a separate `[sql] max_timeout` config in a follow-up.

### F-6 No per-cell size cap

`SQL_CHUNK_ROW_LIMIT = 256` rows per chunk but no cap on cell
size. A query like `SELECT randomblob(80000)` returns a row larger
than `MAX_FRAME_BYTES`. `send_envelope` errors with `FrameTooLarge`,
the connection dies, and the operator sees an unstructured
transport failure. Design §8 mandated 64 KiB per-cell; not
implemented.

Fix: pre-flight check in `encode_row` / chunk assembly; truncate
oversize cells with a `Text("<truncated N bytes>")` placeholder, OR
emit a structured `OperatorError { kind: "cell_too_large" }`.

### F-7 No EOF accounting in fanout decoder

CLI loop reads until connection close. If the relay disconnects
mid-stream (network glitch / malicious truncation), the operator
sees rows that arrived and exits cleanly — they cannot tell apart
"all peers reported in" from "relay disconnected after 3/N peers."

Fix (depends on F-1): relay sends a final `transcript` envelope
listing `(peer_fp, status: ok|timeout|dial_failed)` for every
dispatched peer, signed for the operator.

### F-8 `processes.cmdline` leaks argv

Full argv is joined and surfaced as TEXT with no redaction. argv
routinely contains DB connection strings, API tokens, secrets
passed via `--token=` flags. Cross-host fanout amplifies the leak.

Fix options:
- Per-column ACL: gate `cmdline` behind `[sql] expose_cmdline = false` default.
- Redaction list: regex-strip common secret-bearing flag patterns.
- Document in operator guide.

### F-13 No concurrency cap on `Sql::query`

Each query opens a fresh in-memory SQLite, registers all 13
default tables + 4 extras. On a 10k-process host one query is
30–50 MB resident. Concurrent operators scale that linearly with
no semaphore.

Fix: `tokio::sync::Semaphore` in `Sql` (e.g. 4 permits); acquire
before `spawn_blocking`.

### F-14 procfs walks not time-bounded mid-walk

Once `spawn_blocking` is dispatched, the operator's wall-clock
timeout has no effect on the procfs walk. On a 50k-process host,
`processes.collect()` can take seconds and holds a blocking-pool
slot.

Fix: install a SQLite `progress_handler` that polls a shared
`AtomicBool` set by the timeout watcher, or wire
`Connection::get_interrupt_handle` into a sibling task.

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

## Priority for next pass

1. **F-1 + F-2 + F-3** are coupled. Either implement
   `forwarded_from_operator` + opt-A pass-through (peers seal for
   the operator directly), or accept the current trust model and
   re-shape the `agent_fp` field to be honest about being
   relay-attested (rename / extra comment).
2. **F-4** rate limit. Easy, high value.
3. **F-6** per-cell cap. Bounded code change.
4. **F-8** cmdline redaction / opt-in. Operational concern.

The remainder are tightening + observability improvements.
