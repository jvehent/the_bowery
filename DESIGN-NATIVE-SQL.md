# The Bowery — Native SQL surface (Phase 9)

**Status:** shipped. Phase 9 slices 1–8 are in tree. The native
engine (`bowery-sql`) lives alongside `bowery-sysquery` (the
renamed subprocess wrapper); operators choose between them via
`bowery exec sql` (native, default) and `bowery exec sysquery`
(subprocess fallback). This document is the design rationale +
operator guide; for the in-tree implementation reference see
[`IMPLEMENTATION.md` § 22](IMPLEMENTATION.md#22-phase-9-native-sql-surface).

This document scopes a pure-Rust replacement for osquery: a SQL
surface over a curated set of host-state tables, queryable by an
operator from anywhere in the mesh, with results streaming back
over time and an explicit multi-agent fan-out model.

## 1. Goals

1. **Pure Rust, single binary.** No subprocess, no bundled C++
   binary. A query runs in-process inside the agent.
2. **Fast.** Cold start under 5 ms (vs osqueryi's ~50–200 ms);
   per-row marshalling under 100 µs.
3. **Streaming.** Rows flow back to the operator as they are
   produced — slow tables don't block fast ones.
4. **Multi-agent.** One operator query reaches N agents
   simultaneously, with each row tagged by the agent that
   produced it, so an operator can ask "show me all listening
   ports across the fleet" with a single command.
5. **Queryable from the operator-CLI side**, using the existing
   `bowery exec` channel and Phase-6b operator-only auth gate.

## 2. Non-goals

- **Cross-platform.** Linux only. Phase 10+ may revisit macOS /
  Windows; until then, osquery's portability cost is not paid.
- **Feature parity with osquery's 250 tables.** Fifteen are in
  scope (§4). Others arrive when an operator workflow demands
  one.
- **File integrity monitoring (FIM) / continuous file events.**
  osquery's `file_events` table requires kernel hookup we don't
  want to take on yet. Operators get point-in-time `file` and
  `hash` lookups; continuous file change detection stays a
  separate eBPF-fed event stream (Phase 11).
- **Operator-defined extensions.** osquery's extension SDK is
  out of scope. New tables ship as code review against this
  repo.

## 3. Crates

```
bowery-sql                    new
    Wraps rusqlite + a virtual-table per table from §4. Owns no
    long-lived state — each query gets a fresh in-memory
    SQLite connection with the vtab modules registered.

bowery-tables                 new
    The actual table implementations. One module per table;
    each exposes a `register(conn: &rusqlite::Connection)`
    function. Split from bowery-sql so adding a new table
    doesn't touch SQL plumbing.

bowery-stream                 new
    Helper for producing chunked OperatorResult streams over a
    BoweryConnection. Chunk = batch of N rows + an EOF marker.
    Used by both the local-agent path and the relay path.
```

`bowery-sysquery` (formerly `bowery-osquery`) stays around as the
subprocess-backed path for operators who want the wider third-party-
binary table set; the native engine is always wired and is the
default surface (`bowery exec sql`).

## 4. Tables

The 15 tables operators have asked for, with implementation
substrate per table.

| Table | Substrate | Notes |
|---|---|---|
| `processes` | `procfs` crate, `/proc/<pid>/{stat,status,cmdline,exe,environ}` | Columns: pid, ppid, uid, gid, name, cmdline, exe_path, start_time_unix, state, threads, rss_bytes, vsize_bytes. /proc walk is racy; use `procfs::process::all_processes()` and ignore ESRCH on per-pid reads. |
| `process_open_sockets` | `/proc/<pid>/fd/*` symlinks → `socket:[INODE]`, joined with `/proc/net/{tcp,udp,tcp6,udp6,unix}` | The classic socket-inode dance. Build a `HashMap<inode, NetSocket>` once per query, then walk fds. Columns: pid, socket, family, protocol, local_addr, local_port, remote_addr, remote_port, state. |
| `listening_ports` | Same socket-inode map, filtered to `state = LISTEN` (TCP) or all UDP | Subset view of `process_open_sockets` for the common operator case. Columns: pid, socket, family, protocol, address, port. |
| `users` | `/etc/passwd` parse | Columns: uid, gid, username, description, directory, shell. nsswitch / LDAP-backed users are out of scope; SOC operators querying logged-in users care about local accounts. |
| `logged_in_users` | `/var/run/utmp` | Use the `utmp-rs` crate or hand-roll: 384-byte records. Columns: user, tty, host, login_time_unix, type, pid. |
| `kernel_modules` | `/proc/modules` | Columns: name, size, used_by_count, used_by, status, address. |
| `mounts` | `/proc/self/mountinfo` | mountinfo > mounts (extra columns: mount_id, parent_id, root, mount_options). Columns: mount_id, parent_id, device, fs_type, mount_point, mount_options. |
| `interfaces` | netlink via `netlink-packet-route` + `rtnetlink` crates | RTM_GETLINK + RTM_GETADDR. Columns: name, mac, mtu, flags, ipv4_addr, ipv4_mask, ipv6_addr, ipv6_prefix, link_speed_mbps. |
| `systemd_units` | `zbus` async D-Bus to `org.freedesktop.systemd1.Manager.ListUnits` | Columns: id, description, load_state, active_state, sub_state, fragment_path, unit_file_state. Slow: ~50 ms first call (D-Bus connection setup). Cache the connection per-process. |
| `crontab` | Parse `/etc/crontab` + `/etc/cron.d/*` + `/var/spool/cron/crontabs/*` (root-readable) | Columns: source_file, user, minute, hour, day_of_month, month, day_of_week, command. Anacron tabs are a follow-up. |
| `last` | `/var/log/wtmp` | Same record format as utmp; reverse-iterate. Columns: user, tty, host, login_time_unix, logout_time_unix, duration_secs, type. |
| `os_version` | `/etc/os-release` parse | Columns: id, name, version, version_id, codename, build_id, pretty_name. |
| `system_info` | `/proc/cpuinfo` + `/proc/meminfo` + `uname()` + `/sys/class/dmi/id/*` | Columns: hostname, uuid (DMI), cpu_brand, cpu_count, cpu_logical_cores, hardware_model, hardware_vendor, board_model, physical_memory_bytes, kernel_version. |
| `file` | `std::fs::metadata` + directory walk | Indexed by `path` (vtab BEST_INDEX hint). Operators MUST `WHERE path LIKE '/etc/%'` or similar — table refuses unbounded scans (no `SELECT * FROM file`). Columns: path, type, mode, uid, gid, size, mtime_unix, ctime_unix, atime_unix, btime_unix, inode, hard_links. |
| `hash` | sha256/sha1/md5 of a path | Same WHERE-required indexing as `file`. Columns: path, sha256, sha1, md5. Reuses `bowery-events::enrich::sha256_file`. |

### 4.1 Bowery-native bonus tables (write once we have the vtab framework)

These ride along for free because the vtab interface is generic.
None are in osquery; they expose Bowery's own state.

- `bowery_peers` — known_neighbors store: fingerprint, vk_b64, pinned_at, role_vector_hex.
- `bowery_baseline_binaries` — baseline DB rows: sha256, first_seen, last_seen, seen_count.
- `bowery_alerts` — alert inbox: episode_id, suspicion, exe_path, ts.
- `bowery_audit` — last N audit envelopes: seq, action, outcome, recorded_at.

These are what makes the reimplementation worth doing — operator
queries that join host state with the agent's own observation
state.

## 5. SQL engine

### 5.1 rusqlite virtual tables

Each table from §4 implements `rusqlite::vtab::VTab`. Per-query
lifecycle:

1. Operator's SQL arrives at the agent.
2. Agent constructs a fresh `rusqlite::Connection::open_in_memory()`.
3. Each table's `register(&conn)` runs, creating a vtab module.
4. Agent prepares the statement, steps it row-by-row, marshals
   each row into a `bowery_proto::QueryRow`, sends as a chunk.

The vtab `xBestIndex` hook is non-trivial for `file` / `hash` /
`process_open_sockets` — they need filter pushdown (e.g., the
socket table accepts a pid-list filter so a query like
`WHERE pid = 1234` doesn't scan all of /proc).

**Memory cost:** rusqlite + bundled SQLite ≈ 1.5 MB binary
growth.

### 5.2 Query budget

| Bound | Limit |
|---|---|
| Total rows per query (all tables, all agents) | 1,000,000 |
| Per-agent runtime | clamped to operator request, max 60 s |
| Per-agent stdout-equivalent serialised bytes | 64 MiB |
| Per-row cell size | 64 KiB (truncate longer with `…`) |

Caps prevent a malicious or buggy operator from wedging an agent
with an unbounded scan.

## 6. Wire format

### 6.1 New OperatorCommandBody variant

```rust
pub enum OperatorCommandBody {
    Sysquery(SysqueryQuery),                  // existing subprocess path
    Sql(SqlQuery),                            // native engine
}

pub struct SqlQuery {
    pub sql: String,
    pub timeout_ms: u32,
    /// When true, agent fans this query out to its pinned peers
    /// and streams aggregated results back. When false, only the
    /// directly-dialled agent runs the query.
    pub fanout: bool,
    /// Optional explicit peer-fp filter for fanout. Empty =
    /// every pinned peer in the relay's KnownNeighbors.
    pub peers: Vec<Vec<u8>>,
}
```

### 6.2 New OperatorResultBody variants — streaming

```rust
pub enum OperatorResultBody {
    Sysquery(SysqueryResult),   // subprocess path
    Error(OperatorError),       // shared
    QueryRow(QueryRow),         // emitted N times per agent (slice-7+ shape)
    QueryEof(QueryEof),         // terminator per agent (slice-7+ shape)
}

pub struct QueryRow {
    /// Which agent produced this row.
    pub agent_fp: Vec<u8>,
    /// The SQL row, JSON-encoded `{column: value, ...}`.
    /// Strings, ints, floats, nulls. No nested objects.
    pub row_json: String,
}

pub struct QueryEof {
    pub agent_fp: Vec<u8>,
    /// Per-agent terminal status. Distinct from
    /// OperatorResultBody::Error which terminates the *whole*
    /// stream; this only marks one agent done.
    pub status: QueryAgentStatus,
}

pub struct QueryAgentStatus {
    pub kind: String,              // "ok" | "timeout" | "error"
    pub message: String,           // human-readable
    pub rows_produced: u64,
}
```

### 6.3 Stream framing

One QUIC connection per operator session. The operator sends
exactly one `OperatorCommand`. The agent (relay or local)
emits a sequence of `OperatorResult` envelopes:

```
operator → relay:    OperatorCommand { request_id, Sql{ sql, fanout=true } }

relay → operator:    OperatorResult { request_id, QueryRow{ agent_fp=A, row_json=… } }
relay → operator:    OperatorResult { request_id, QueryRow{ agent_fp=B, row_json=… } }
relay → operator:    OperatorResult { request_id, QueryRow{ agent_fp=A, row_json=… } }
…
relay → operator:    OperatorResult { request_id, QueryEof{ agent_fp=A, status=ok, … } }
relay → operator:    OperatorResult { request_id, QueryEof{ agent_fp=B, status=ok, … } }
relay → operator:    OperatorResult { request_id, QueryEof{ agent_fp=relay, status=ok, … } }
                     # final eof from relay itself signals stream done
```

Each envelope is a separately signed envelope on a separate
unidirectional QUIC stream — the agent owns send order and the
operator demultiplexes by `agent_fp`.

The operator's CLI accumulates / streams to stdout as it sees
fit. JSON mode emits one line per row; table mode buffers and
prints on close.

## 7. Multi-agent fan-out

Two operating modes per `SqlQuery.fanout`:

### 7.1 fanout = false

Local-only. Same shape as the slice-6 streaming Sql path. The
relay-agent is the sole producer; rows carry `agent_fp =
self_fp`; the stream ends with a single `QueryEof`.

### 7.2 fanout = true — relay pattern

The agent the operator dialed (the **relay**) receives the
operator-signed envelope, runs the query locally, **and** spawns
per-peer tasks to forward the query to its pinned neighbors.

```
operator
    | (signed OperatorCommand, addressed to relay)
    v
  relay  ──── sealed peer-forward (signed *by relay*, recipient = peer) ───>  peer A
   |                                                                         |
   |    ◄── sealed reply stream (signed by peer A, recipient = relay) ◄──────┘
   |                                                                         |
   |    ──── peer-forward signed by relay ─>  peer B ──── reply stream ──────|
   v
operator (multiplexed: relay's own rows + per-peer rows + final EOF)
```

#### 7.2.1 Trust at the relay → peer hop

The relay forwards the operator's query to a peer in a *new*
envelope of body `Body::OperatorCommand` signed by the relay
itself. **Crucially**, it includes the operator's *original*
signed envelope bytes inside a new wrapping field so the peer
can verify the operator approved the query — not just the
relay.

New proto field:

```rust
pub struct OperatorCommand {
    pub request_id: String,
    pub timeout_ms: u32,
    pub command: Option<OperatorCommandBody>,
    /// Set when this command is a peer-forward of an operator-
    /// signed command. Carries the original operator envelope
    /// bytes verbatim so the peer can verify the operator's
    /// signature itself, not just the relay's.
    pub forwarded_from_operator: Vec<u8>,    // empty = direct from operator
}
```

Peer-side gate becomes: "envelope from a known peer **and**
either (a) sender is in [operators], or (b) `forwarded_from_operator`
opens cleanly under our [operators] resolver." (b) is what
authorises peer-forwarded queries.

#### 7.2.2 Per-row authentication

Rows produced by peer A flow back through the relay, but the
operator wants to verify **A signed those rows**, not the relay.
Two options:

- **(opt-A) Pass-through bytes.** A's sealed `OperatorResult`
  envelope (`{request_id, QueryRow{agent_fp=A, row_json=…}}`) is
  forwarded **verbatim** by the relay, with no re-sealing. The
  operator's verifier sees A's signature directly.
- **(opt-B) Aggregate-then-resign.** Relay collects A's rows,
  re-signs each as the relay. Simpler operator side (one
  signature chain) but the operator now has to trust the relay
  to honestly forward A's data.

(opt-A) is correct. The relay is just a byte router; cross-
signature verification happens end-to-end. The relay's role is
discovery + fan-out; it has no opinion on row content.

This requires the **operator's pubkey to be in every peer's
[operators] config** — peers verify the operator's wrapped
envelope, then sign their replies for the operator (not for the
relay). Operator must also have every peer's pubkey to verify
the per-peer replies. Realistic deployment: operators hold a
small file `peers.toml` with `(fp, pubkey_b64)` per agent in
the fleet, populated from `bowery key info` calls during fleet
setup.

#### 7.2.3 No further hops

Peer-forwarded commands carry a `hop_count: u8` (or just a
bool) indicating "do not forward further." Peers run-and-reply
only. This keeps the routing graph bounded at one hop and
prevents storms.

#### 7.2.4 Operator-side aggregation

CLI buffers `(agent_fp, row_json)` pairs as they arrive. On
table mode (`bowery exec sql --format=table`), prints in a
header-row schema. On JSON mode, one line per row prefixed with
`agent_fp` so `jq` or downstream tooling can group.

Partial results: if the relay sees agent C never responds, the
relay fires its own `QueryEof{agent_fp=C, status=timeout}`
after the per-peer deadline and continues. The operator never
sees a hung CLI — every started agent gets exactly one EOF.

#### 7.2.5 Cycle / recursion prevention

The peer-forward envelope is `forwarded_from_operator != empty`.
A peer that receives such an envelope knows it MUST NOT relay
again. Implemented as: dispatch ignores the `fanout` flag when
`forwarded_from_operator` is set. Single hop, full stop.

## 8. Security model

| Concern | Defense |
|---|---|
| Untrusted operator | Same Phase-6a/6b gate — operator key must be in `[operators]` config of every agent that responds. |
| Untrusted relay | Per-row envelope is end-to-end signed peer→operator; relay can't fabricate rows. Relay can however **drop** rows; partial-result detection requires the operator to know which agents *should* have responded (via a fleet-wide peer manifest at the operator side). |
| Cycle / amplification | One-hop fan-out only. Relay runs query against pinned peers from its own KnownNeighbors — bounded set. |
| Per-agent DoS | All Phase-6b/8 caps still apply: max_timeout, output_too_large, kill_on_drop. SQL adds: max-rows cap (1M), max-cell-size (64 KiB). |
| Mesh-flood DoS via fan-out | Per-operator rate limit on the relay: max 1 fanout query per N seconds per operator fp. |
| File system traversal via `file` table | `file` and `hash` tables refuse unbounded queries — vtab requires a `path` filter at xBestIndex time. Unbounded scan returns `OperatorError::Invalid("file table requires WHERE path …")`. |
| Information disclosure (e.g., `/etc/shadow` via `file` table) | Path filter still allows `/etc/shadow` if root-readable. Defense: path-based deny-list configurable in `[sql] forbidden_paths` (`/etc/shadow`, `/proc/*/maps`, key files). |

## 9. CLI surface

```sh
# Single-agent (default; the slice-6 streaming Sql shape):
bowery exec sql \
    --operator-key … --agent-addr … --agent-fp … --agent-pubkey-b64 … \
    --sql 'SELECT pid, name FROM processes LIMIT 5'

# Multi-agent fan-out via the relay:
bowery exec sql \
    --operator-key … --agent-addr … --agent-fp … --agent-pubkey-b64 … \
    --fanout \
    --sql 'SELECT pid, name FROM processes WHERE name = "sshd"'

# Output as a table (default streams as JSON):
bowery exec sql … --format=table

# Save peer manifest for operator-side verification:
bowery peers add --name web-1 --fp … --pubkey-b64 …
```

The `bowery peers` set is operator-side only — it parallels
the agent's `KnownNeighbors`. Stored at
`$HOME/.bowery/peers.toml`.

## 10. Slice plan

Eight slices at roughly one week each, sequenced for landable
intermediate states. Each slice compiles + tests + ships
through CI; no slice leaves the agent broken.

### Slice 1 — `bowery-sql` framework + 2 starter tables (1 week)

- New crates: `bowery-sql`, `bowery-tables`. Empty workspace
  member entries.
- `Sql::query(sql, timeout) -> impl Stream<Item = Row>` API.
- Tables: `os_version`, `system_info` (the simplest two). Used
  to validate vtab plumbing.
- Tests: in-process unit tests that exercise SELECT against
  each starter table.

### Slice 2 — Process / FS tables (2 weeks)

- Tables: `processes`, `mounts`, `kernel_modules`, `interfaces`,
  `file`, `hash`.
- The `file` and `hash` tables include xBestIndex filter
  pushdown so `WHERE path = …` doesn't fall back to scan.
- Forbidden-path policy in agent config.

### Slice 3 — Network tables (1 week)

- `process_open_sockets`, `listening_ports`. The socket-inode
  join is shared infrastructure; each table is a thin filter
  over it.

### Slice 4 — Identity / login tables (1 week)

- `users`, `logged_in_users`, `last`. utmp/wtmp parsers.

### Slice 5 — Service tables (1 week)

- `systemd_units` (zbus connection cached), `crontab`.

### Slice 6 — Wire format + streaming (single-agent) (1 week)

- New proto variants: `SqlQuery`, `QueryRow`, `QueryEof`.
- Agent-side handler streams rows via per-row OperatorResult
  envelopes.
- CLI-side streaming receive: print one row per envelope.
- The `sysquery` (subprocess) handler stays in place; operators
  choose via `bowery exec sql` (native) vs `bowery exec sysquery`
  (subprocess).

### Slice 7 — Multi-agent fan-out (2 weeks)

- `forwarded_from_operator` field on `OperatorCommand`.
- Relay-side: receive operator's envelope, run locally **and**
  fan out to pinned peers, multiplex per-peer reply streams to
  the operator.
- Per-peer timeout + EOF synthesis on dead peers.
- Cycle prevention: peer rejects further-fanout when
  `forwarded_from_operator` is set.
- Cross-signature verify: operator's pubkey must be in every
  peer's [operators] (documented as a fleet-setup precondition).
- CLI `--fanout` flag.

### Slice 8 — Operator ergonomics + bonus tables (1 week)

- `bowery peers add/list/remove` for operator-side peer
  manifest.
- `--format=table` table renderer.
- Bonus tables: `bowery_peers`, `bowery_baseline_binaries`,
  `bowery_alerts`, `bowery_audit` — Bowery-internal state no
  third-party SQL surface can reach.
- `bowery doctor` learns to run a smoke query (`SELECT 1`) so
  operators can verify the SQL surface is alive.

**Total: ~10 weeks, ~12k LOC, 8 commits.** The sysquery
(subprocess) handler stays alongside the entire time; once
slice 6 lands, operators choose between `bowery exec sql` (native)
and `bowery exec sysquery` (wider third-party-binary table set).

## 11. Open questions

1. **JOIN across tables in one query.** rusqlite supports it
   natively, but a JOIN on `processes × process_open_sockets`
   walks `/proc` twice. Materialise once into a CTE? Cache for
   the lifetime of the query?
2. **utmp byte format** has subtle libc-version-specific
   padding. Test against multiple distros (Debian, Ubuntu,
   Fedora, Arch) before claiming `last` works. The `utmp-rs`
   crate handles this; verify it before depending on it.
3. **Streaming back-pressure.** A slow operator (network
   bandwidth) shouldn't block fast agents. Per-peer bounded
   buffer at the relay; drop oldest on overflow with a
   `OperatorError::Lagged` chunk.
4. **JSON column encoding.** Strings as JSON strings, ints as
   JSON numbers, but Linux `mtime_unix` is u64 which exceeds
   JSON's safe integer range. Encode as string for u64
   columns? Document the schema's JSON shape.
5. **Bowery-native tables** (§4.1) introduce a coupling: the
   table's data source lives in another agent crate. Cleanest
   architecturally: `bowery-tables` depends on the data crates;
   they need to expose a query API that doesn't grab a long-
   lived lock. The `Baseline::for_each_binary` pattern is the
   model.

## 12. Effort summary

| Item | Estimate |
|---|---|
| Wall-clock | 10 weeks of focused work |
| Code | ~12k LOC of Rust |
| New crates | 3 (`bowery-sql`, `bowery-tables`, `bowery-stream`) |
| Wire-format additions | 2 command bodies, 2 result bodies, 1 forwarded envelope field |
| Existing-test impact | low — native engine ships alongside; sysquery tests stay green |
| Removed code (eventually) | `bowery-sysquery` crate (~400 LOC) and its config knob, once the native table set covers operator needs |

Trigger to start: the bundled subprocess binary in production
growing past 40 MB, or operator workflows starting to want the
Bowery-native
tables (§4.1).
