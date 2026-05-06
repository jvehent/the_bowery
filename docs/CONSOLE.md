# `bowery-console` — operator handbook

The Bowery console is an ncurses workspace (ratatui under the hood)
that gives an operator a live view of the agent fleet. Every action
the `bowery` CLI exposes is reachable through the console, plus a
schema-grounded chatbot that drafts SQL for you.

This document is the canonical reference. The chatbot in the **Chat**
pane is also primed with a condensed copy of it, so it knows the
exact schema and palette commands described here. You can read the
same content inside the console at any time by switching to the
**Help** pane (hotkey **8**).

---

## 1. Launching

```bash
bowery-console \
    --operator-key  ~/.bowery/operator.key \
    --agent-addr    10.0.0.5:9902 \
    --agent-fp      <hex>           \
    --agent-pubkey-b64 <base64>     \
    --chat-model    ~/.bowery/models/gemma-4-e2b-it-q4_k_m.gguf
```

`--chat-model` is optional. If the file is missing on launch the
console prompts on stdin:

```
The Chat pane needs Gemma 4 (GGUF, ~3 GB).
  expected at:  /home/you/.bowery/models/gemma-4-e2b-it-q4_k_m.gguf
  registry id:  gemma-4-e2b-it-q4_k_m
Download now? [y/N]
```

`y` triggers the same fetch path as `bowery model fetch
gemma-4-e2b-it-q4_k_m` and drops the GGUF into
`~/.bowery/models/`. Anything else (or `Enter`) falls back to the
deterministic mock chat backend — the pane is still reachable for
keybind testing but doesn't actually generate SQL.

You can also fetch ahead of time:

```bash
bowery model fetch gemma-4-e2b-it-q4_k_m
```

Build with the LLM feature on if you want real Gemma 4 inference:

```bash
cargo build --release --features llm-llama-cpp -p bowery-console
```

Without that feature the binary stays small (~few MB) and the chat
pane is mock-only — at startup the console prints a banner telling
you so.

On the test VM the same flag is passed for you by:

```bash
./scripts/xtest run-console -- \
    --operator-key /tmp/operator.key \
    --agent-addr 127.0.0.1:9902 \
    --agent-fp <hex> --agent-pubkey-b64 <base64>
```

`xtest run-console` syncs the workspace, builds the console with
`--features llm-llama-cpp`, and launches it. The console will then
prompt you for the Gemma download on first run.

---

## 2. Layout

```
┌── bowery │ relay=…  (10.0.0.5:9902)  │ status … ─────────────────┐  status bar
│  [1] Query  [2] Alerts  [3] Map  [4] Audit  [5] Peers …          │  tabs
│ ┌────────────────────────────────────────────────────────────┐   │
│ │   active pane content                                      │   │
│ └────────────────────────────────────────────────────────────┘   │
│ ┌── input ───────────────────────────────────────────────────┐   │
│ │ query > _                                                  │   │
│ └────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

- **Status bar** shows the current relay (its short fingerprint +
  socket address) and the most recent action message.
- **Tabs row** lists every pane with its hotkey. The active one is
  highlighted.
- **Input bar** is the per-pane prompt. `:`-prefixed lines invoke
  the global command palette (see §6).

---

## 3. Hotkeys (when the input is empty)

| Key   | Action                                                 |
|-------|--------------------------------------------------------|
| 1–8   | Switch to that pane                                    |
| `r`   | Refresh the current pane (re-poll / re-query)          |
| `x`   | Run the chat pane's draft SQL against the current relay |
| `:`   | Open the command palette (see §6)                       |
| Esc   | Cancel the palette / clear the input                    |
| Ctrl-C | Quit                                                   |

History (Up/Down) is remembered per-session and persisted to
`~/.bowery/console-history` between runs.

---

## 4. Panes

### 4.1 `[1] Query` — SQL REPL

Type a `SELECT` statement at the prompt and press Enter. Result
renders as an aligned table. Latency + row count appear above the
table.

The agent's SQL surface is read-only (`set_authorizer` rejects
everything but `SELECT`). The **schema** is in §5.

Examples:

```sql
SELECT pretty_name, version_id FROM os_version;

SELECT pid, name, rss_bytes
  FROM processes
  ORDER BY rss_bytes DESC
  LIMIT 10;

SELECT pid, port FROM listening_ports WHERE port = 22;

SELECT p.pid, p.name, s.local_port
  FROM processes p
  JOIN process_open_sockets s ON s.pid = p.pid
  WHERE s.state = 'LISTEN';
```

### 4.2 `[2] Alerts` — live tail

On first activation the pane spawns a background poller that calls
`Subscribe` against the current relay every 5 seconds. New alerts
appear at the top. The pane keeps the most recent 500 entries.

Title bar shows the buffered count and any poll error.

### 4.3 `[3] Map` — topology

Renders the relay's 1-hop neighborhood as an ASCII tree:

```
◆ relay  25781c94907396bd…  10.11.178.126:9902
├── ◆ 9e511c8a3b3c2f00…
├── ◆ 4290a9c29f8e36c7…
└── ◆ a3f201bb35a84e36…
```

Press `r` to refresh. Phase-10 multi-hop fan-out, when it lands,
populates deeper levels in the same pane.

### 4.4 `[4] Audit` — Phase-7 enforcement log snapshot

Runs `SELECT seq, ts_unix_ms, episode_id, action_id, outcome_kind
FROM bowery_audit ORDER BY seq DESC LIMIT 200`. Press `r` to
refresh.

### 4.5 `[5] Peers` — operator-side manifest

Reads `~/.bowery/peers.toml` and renders it as a table. The same
file `bowery peers add/list/remove` writes. Press `r` to reload
after manual edits, or use the palette (`:peers add/remove/reload`).

### 4.6 `[6] Doctor` — local + remote readiness

Two sections:

- **LOCAL**: `bowery_cli::doctor::run()` (kernel version, BPF-LSM,
  BTF, bpffs, `lsm=` cmdline, kernel config, Phase-9 SQL smoke).
  Each check renders with `[OK]` / `[WARN]` / `[FAIL]` / `[N/A]`.
- **REMOTE**: dispatches `SELECT 1 AS one` to the current relay and
  reports the round-trip latency.

Press `r` to re-run both.

### 4.7 `[7] Chat` — natural-language SQL helper

Type in plain English. The model proposes a SQL query in a fenced
```sql … ``` block; the proposed query appears in a **DRAFT SQL**
panel at the bottom of the pane. Press `x` to send the draft to
the Query pane and run it against the current relay.

The model is grounded in the schema below (§5). It will refuse to
invent tables or columns. Multi-turn — you can refine the same
query across turns.

Example dialogue:

```
> list every sshd process and its parent pid
```

Bot:
```sql
SELECT pid, ppid, name FROM processes WHERE name = 'sshd' LIMIT 50;
```

Press `x` → Query pane shows the rows.

```
> filter that to ones whose parent isn't init
```

Bot:
```sql
SELECT pid, ppid, name FROM processes
  WHERE name = 'sshd' AND ppid != 1
  LIMIT 50;
```

Press `x` again.

The chat keeps history within the session. Restart the console to
reset.

#### Privacy

The chatbot runs entirely on your workstation — nothing leaves the
host. No alerts / audit rows are auto-fed into the prompt; if you
want to ground a question in a specific row, paste it yourself.

### 4.8 `[8] Help` — this document, in-pane

Renders a built-in copy of `docs/CONSOLE.md` so you don't have to
leave the console to look something up. Up/Down to scroll, Esc to
return to the previous pane.

---

## 5. Schema reference

### 5.1 Host-state tables (13)

| Table | Columns |
|---|---|
| `processes` | pid, ppid, uid, gid, name, cmdline, exe_path, start_time_unix, state, threads, rss_bytes, vsize_bytes |
| `process_open_sockets` | pid, socket, family, protocol, local_addr, local_port, remote_addr, remote_port, state |
| `listening_ports` | pid, socket, family, protocol, address, port |
| `users` | uid, gid, username, description, directory, shell |
| `logged_in_users` | user, tty, host, login_time_unix, type, pid |
| `last` | user, tty, host, login_time_unix, logout_time_unix, duration_secs, type |
| `kernel_modules` | name, size, used_by_count, used_by, status, address |
| `mounts` | mount_id, parent_id, device, fs_type, mount_point, mount_options |
| `interfaces` | name, mac, mtu, flags, ipv4_addr, ipv4_mask, ipv6_addr, ipv6_prefix, link_speed_mbps |
| `systemd_units` | id, description, load_state, active_state, sub_state, fragment_path, unit_file_state |
| `crontab` | source_file, user, minute, hour, day_of_month, month, day_of_week, command |
| `os_version` | id, name, version, version_id, codename, build_id, pretty_name |
| `system_info` | hostname, uuid, cpu_brand, cpu_count, cpu_logical_cores, hardware_model, hardware_vendor, board_model, physical_memory_bytes, kernel_version |

`processes.cmdline` is empty unless `[sql] expose_cmdline = true` is
set in the agent config.

### 5.2 Bowery-internal views (4)

| Table | Columns |
|---|---|
| `bowery_peers` | fingerprint_hex |
| `bowery_baseline_binaries` | sha256_hex, first_seen_unix, last_seen_unix, seen_count |
| `bowery_alerts` | episode_id, suspicion, exe_path, ts_unix_ms |
| `bowery_audit` | seq, ts_unix_ms, episode_id, action_id, outcome_kind |

### 5.3 Scalar file/hash functions (7)

Each takes a path. The operator must supply paths explicitly — no
filesystem enumeration via these functions.

```
bowery_file_exists(path)         -> 0/1
bowery_file_size(path)           -> bytes
bowery_file_mode(path)           -> mode bits
bowery_file_mtime_unix(path)     -> modified time
bowery_file_owner_uid(path)      -> owner uid
bowery_file_owner_gid(path)      -> owner gid
bowery_file_sha256_hex(path)     -> hex sha256
```

`bowery_file_sha256_hex` reads up to 16 MiB; non-regular files
(sockets/pipes/devices) return NULL. Hashes returned without the
`0x` prefix.

---

## 6. Command palette

Type `:` (input must be empty) to enter palette mode. Recognised
verbs:

| Command | What it does |
|---|---|
| `:connect <fp> [<host:port>]` | Switch the current relay |
| `:peers add <name> <fp> <pubkey_b64>` | Append to `~/.bowery/peers.toml` |
| `:peers remove <fp>` | Drop a peer from the manifest |
| `:peers reload` | Re-read the manifest from disk |
| `:export query <path>` | Dump the Query pane's last result as JSON |
| `:quit` / `:q` | Exit cleanly |

Each command updates the status bar with a confirmation or an
error message.

---

## 7. Recipes

### Find binaries seen on this host but nowhere else

Step 1 — pull the baseline-binary view:

```sql
SELECT sha256_hex, seen_count, last_seen_unix
  FROM bowery_baseline_binaries
  WHERE seen_count = 1
  ORDER BY last_seen_unix DESC
  LIMIT 50;
```

Step 2 — when Phase-10 multi-hop ships, `--fanout` the same query
to ask every reachable peer "have you seen this hash?" and
correlate.

### Listening port audit

```sql
SELECT lp.port, p.pid, p.name, p.exe_path
  FROM listening_ports lp
  JOIN processes p ON p.pid = lp.pid
  ORDER BY lp.port;
```

### Hash all SUID binaries on `$PATH`

The console can't enumerate the filesystem (by design — see §5.3).
Pipe paths in via `VALUES`:

```sql
SELECT path,
       bowery_file_mode(path)       AS mode,
       bowery_file_owner_uid(path)  AS uid,
       bowery_file_sha256_hex(path) AS sha
  FROM (VALUES
        ('/usr/bin/sudo'),
        ('/usr/bin/su'),
        ('/usr/bin/passwd')
       ) AS t(path);
```

### Recent enforcement-engine activity

```sql
SELECT seq, ts_unix_ms, action_id, outcome_kind
  FROM bowery_audit
  ORDER BY seq DESC
  LIMIT 20;
```

The Audit pane runs essentially this query on activation; refresh
with `r`.

### Fresh logins in the last 5 minutes

```sql
SELECT user, tty, host, login_time_unix
  FROM logged_in_users
  WHERE login_time_unix > unixepoch() - 300;
```

### Process tree depth heuristic

```sql
SELECT name, COUNT(*) AS instances
  FROM processes
  GROUP BY name
  HAVING instances > 1
  ORDER BY instances DESC;
```

### Chatbot prompts that work well

- "list every process owned by uid 0 with rss above 100MB"
- "which kernel modules are loaded but unused"
- "fingerprints of every peer this relay has pinned"
- "hash sshd and openssh-server's main binary"
- "show audit entries where outcome was denied"

The model produces tighter SQL when you name the table you want, but
it can usually pick the right one from the schema if the question is
specific enough.

---

## 8. Limits to keep in mind

- **One in-flight Query at a time.** A second Enter while the
  first is running shows a "still running" error.
- **`processes.cmdline` is empty by default** — agent operators must
  opt in per host because argv routinely contains DB strings and
  API tokens.
- **Audit log size cap**: `bowery_audit` reads at most 16 MiB of
  the agent's audit log. Older lines may not appear.
- **Map shows 1-hop only** until Phase-10 multi-hop ships.
- **Chatbot can be wrong.** Always read the draft SQL before
  pressing `x`. The agent will refuse anything but `SELECT`, but a
  badly-shaped query can still pull noisy data.

---

## 9. Troubleshooting

### "agent refused query: ..."

The relay returned an `OperatorError` with a structured `kind`:

| `kind`                  | Meaning |
|-------------------------|---------|
| `policy_denied`         | The operator's pubkey isn't in the agent's `[operators]` list, or the SQL violated the SELECT-only authorizer |
| `unsupported_command`   | Old agent / new client mismatch |
| `timeout`               | Query exceeded the agent's `[sql] max_timeout` |
| `output_too_large`      | Result exceeded the row/byte cap |
| `rate_limited`          | You're hitting the per-operator fanout rate cap (1/5s, burst 6) |

### "BadSignature" from a peer in fan-out

Peer's pubkey isn't in your `~/.bowery/peers.toml`. Add it via
`:peers add` or `bowery peers add`.

### Chat says "(mock chat — no model loaded)"

Either the binary wasn't built with `--features llm-llama-cpp`, or
the GGUF at `--chat-model` doesn't exist. Check `bowery model list`
and `bowery model fetch gemma-4-e2b-it-q4_k_m`.

### Doctor pane crashes

Should be fixed in current main. If it ever recurs, `RUST_LOG=debug`
on launch will surface the panic origin.
