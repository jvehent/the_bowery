# The Bowery

![The Bowery](assets/hero.png)

A distributed Linux EDR built around a peer-to-peer **whispering protocol**: agents validate anomalies with their neighbors instead of phoning home to a central backend.

> **Status:** pre-alpha, Phase 0 → 9 of the [implementation plan](DESIGN.md#13-phased-delivery) complete. Native Phase-9 SQL surface ([`bowery-sql` + `bowery-tables`](DESIGN-NATIVE-SQL.md)) ships 13 procfs/sysfs-backed tables plus 7 Bowery-internal views, streamed over the operator wire with one-hop multi-agent fan-out — deployable as a multi-node mesh over a Tailscale tailnet ([deploy/remote/MESH.md](deploy/remote/MESH.md)). Not production-ready, but every layer is end-to-end testable today.

## What it is

- A lightweight Rust agent that observes process exec / exit and outgoing TCP connections at the kernel level via eBPF tracepoints, with KRSI (BPF-LSM) hooks for response enforcement.
- A small embedded LLM (Qwen3-0.6B Q4_K_M via llama.cpp, feature-gated) that turns rule + baseline signal into a refined verdict + rationale.
- A gossip-based mesh (chitchat) with mTLS-pinned QUIC RPC for direct peer-to-peer whisper Q&A — agents ask role-similar peers "have you seen this fingerprint?", aggregate the answers as additional context for the LLM, and **confirm** an alert when a quorum of peers reports never having seen the binary. Confirmed alerts are highlighted to the operator in the console, the `bowery_alerts` SQL view, and the CLI.
- A generic corroboration round over the same mesh — an agent that sees something it can't judge alone asks the host that *can*: "did you connect to me?" answered from the peer's own outbound history, with a denial as the finding. The wire is kind-tagged and untyped, so new questions are handler registrations, not protocol changes.
- A native, pure-Rust SQL surface (`bowery-sql` + `bowery-tables`) that turns each agent into a queryable host-state engine — 13 procfs/sysfs/etc-backed tables plus 7 Bowery-internal views, streamed back over the operator wire with end-to-end signed multi-agent fan-out.
- A signed operator CLI that connects to any agent, drains a per-agent alert inbox, prints (or JSON-streams) high-suspicion verdicts, and fans SQL queries across the mesh. There is no backend.

## Getting started

[**USAGE.md**](USAGE.md) walks a new operator from an empty machine to a
running fleet: concepts, build (including the pinned `bpf-linker` and the
architecture-neutral eBPF object), signed enrollment, the everyday
commands, and an honest section on the three things that routinely
confuse people. [INSTALL.md](INSTALL.md) is the per-option config
reference.

## Why

Existing EDRs send everything home and decide centrally. The Bowery flips that: each agent decides locally, but only after asking the neighborhood whether the activity is normal *here*. It's a neighborhood watch for production fleets. Detection is local + corroborated; only operator-facing alerts cross the trust boundary, signed end-to-end.

## Documents

- [the_bowery_design.md](the_bowery_design.md) — original product brief.
- [DESIGN.md](DESIGN.md) — engineering design, locked decisions, phased delivery plan.
- [DESIGN-NATIVE-SQL.md](DESIGN-NATIVE-SQL.md) — Phase-9 design rationale + operator guide for the native SQL surface.
- [DESIGN-ALERT-SILENCING.md](DESIGN-ALERT-SILENCING.md) — planned: operator-signed alert silencing over the mesh, and why a detection-disabling primitive needs its threat model written first.
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
  bowery-yara/             # YARA rule scanning (feature-gated libyara engine)
deploy/systemd/            # service unit + slice
scripts/
  build-console            # console build with llama.cpp + target-cpu=native
  build-install-operator   # build+install CLI/console/agent (all features) and
                           # restart the agent on an operator workstation
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

# Agent with real Qwen3-0.6B inference (needs cmake + clang).
# RUSTFLAGS pins the build to this host's CPU — llama.cpp otherwise
# SIGILLs when its dispatch picks an instruction the runtime core
# lacks. Build on the same CPU you deploy to.
RUSTFLAGS='-C target-cpu=native' \
  cargo build --release --features llm-llama-cpp -p bowery-agent

# Operator console with real Gemma 4 chatbot (same CPU caveat —
# the wrapper sets the flag for you):
./scripts/build-console

# Kernel-side BPF programs (needs nightly + bpf-linker):
./scripts/build-ebpf

# Remote VM workflow:
./scripts/xtest run-agent  --push-model        # agent on the test VM
./scripts/xtest run-console -- --agent-addr …  # console + Gemma 4 on the test VM
```

`bowery doctor` on a candidate Linux host tells you whether the kernel is ready (BPF-LSM, BTF, bpffs, lsm= cmdline). `INSTALL.md §1.2` lists distros that work out of the box.

## What it detects

<!-- BEGIN GENERATED: capabilities — edit crates/bowery-analysis/src/attack.rs, then BOWERY_UPDATE_DOCS=1 cargo test -p bowery-analysis -->

The agent watches 6 kernel probes and scores what they produce against 63 detections, mapped onto 30 ATT&CK techniques — **12 covered well, 16 partially, 2 not at all**.

**Initial Access** — 1 uncovered  
Valid Accounts

**Execution** — 2 partial  
Unix Shell · Malicious File

**Persistence** — 5 good, 2 partial  
systemd Service · Cron · SSH Authorized Keys · Unix Shell Configuration Modification · Kernel Modules · Event Triggered Execution (udev rules) · Pluggable Authentication Modules

**Privilege Escalation** — 2 good, 1 partial  
Sudo and Sudo Caching · Setuid and Setgid · Exploitation for Privilege Escalation

**Defense Evasion** — 2 good, 4 partial  
Clear Linux or Mac System Logs · Dynamic Linker Hijacking · Disable or Modify Tools · Disable or Modify System Firewall · Process Injection · File Deletion

**Credential Access** — 3 good  
/etc/passwd and /etc/shadow · Credentials In Files · Private Keys

**Discovery** — 3 partial  
Account Discovery · System Information Discovery · System Network Connections Discovery

**Lateral Movement** — 1 partial  
SSH

**Command and Control** — 2 partial, 1 uncovered  
Ingress Tool Transfer · Web Protocols · Protocol Tunneling

**Impact** — 1 partial  
Data Encrypted for Impact

Every entry names what it *misses* as well as what it catches, and there is deliberately no grade above "good": no host sensor covers a technique completely, and a map claiming otherwise invites an operator to stop looking. Per-technique detail is in [`docs/ATTACK-COVERAGE.md`](docs/ATTACK-COVERAGE.md), generated from the same table.

<!-- END GENERATED: capabilities -->

### What the mesh adds

A single host cannot answer certain questions about itself, and those are
the ones worth asking.

- **An inbound connection nobody admits making.** Unremarkable here,
  unremarkable there, alarming only when the host it came from has no
  record of it — so the receiving agent asks, and a *denial* is the
  finding. Either that peer is blind or tampered with, or the source
  address was spoofed.
- **Rarity judged across the fleet, not the host.** A binary this machine
  has never run is ordinary; one that a quorum of role-similar peers has
  *also* never run is not. Confirmation counts peers that have **never
  seen it**, because a peer that has it argues the opposite.
- **A neighbourhood taking a finding back.** Peers can answer *"we all do
  that"*, which supersedes the local alert with a lower score instead of
  adding to it — the only corroboration direction that can make an alert
  go away.
- **Peers noticing an agent stop.** The one failure a host cannot report
  about itself. When *every* peer vanishes at once the finding is raised
  about **this** host instead, since that is almost always its own
  network.
- **A peer that has not seen enough refuses rather than answers.** Two
  agents with dead sensors were once found unanimously confirming every
  alert their neighbour raised. Silence and refusals never satisfy a
  quorum.

### What it deliberately does not do

- **No central collection.** Nothing is shipped to a lake; queries are
  answered where the data lives, and history is reconstructed by asking
  the hosts.
- **No enforcement unless you arm it.** `[response] mode` defaults to
  `off` and the policy defaults to deny-all. Naming an engine does not
  arm a host — an upgrade must never start killing processes on an
  operator's behalf.
- **No agent-side third-party lookups.** A hash sent to VirusTotal tells
  anyone watching that this hash is being investigated. Screening is
  operator-side, opt-in, and may only ever *suppress* on a clean verdict.
- **No alerting on a quiet host.** Indistinguishable from an idle one.
  Blindness alerts; silence does not.

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
- **Phase 9** — native SQL surface: `bowery-sql` engine + `bowery-tables` 13 default + 7 Bowery-internal views + 7 scalar file/hash functions; streamed as chunked `OperatorResult::SqlChunk` envelopes over QUIC; multi-agent fan-out with operator-signed delegation (`OperatorAuthorization`); peers seal chunks **directly for the operator** (relay can drop but cannot forge); SELECT-only authorizer; per-operator rate limit; 16 KiB per-cell cap; SQLite progress-handler cancellation; `bowery peers add/list/remove` operator manifest. Every CRIT/HIGH/MEDIUM finding from [`SECURITY-AUDIT-PHASE9.md`](SECURITY-AUDIT-PHASE9.md) closed.
- **Phase 10 (slices 1–3)** — persistent peer-connection pool (`bowery_whisper::pool::PeerConnections`): outbound connections cached per fingerprint, lazy + watcher-driven eviction, inbound handler runs on outbound-pooled connections so peers can stream back without their own listener. Whisper Q&A migrated to bidirectional QUIC streams (`request` / `accept_request` / `Reply`) so `ask()` shares the pooled socket with the inbound handler without racing it. Heartbeat + Q&A both reuse the pool; operator transport untouched.
- **Operator console (`bowery-console`, phases C-1..C-6)** — ratatui workspace built on top of the `bowery-cli` library refactor. Eight panes: Query (SQL REPL), Alerts (live tail), Map (1-hop topology), Audit (snapshot), Peers (manifest), Doctor (local + remote readiness), Chat (Gemma 4 via llama.cpp, drafts SQL — press `x` to run), Help (in-pane operator handbook from [`docs/CONSOLE.md`](docs/CONSOLE.md)). Command palette (`:connect / :peers / :export / :quit`), input history persisted to `~/.bowery/console-history`. Model registry (`bowery model fetch`) gained Gemma-4-E2B-it with pinned SHA-256 verification.
- **Operator-configurable monitoring** — a `[monitor]` config section defines file watches (userspace inotify; a change to a watched path always alerts) and operator process detections (`exe_prefix` / `comm` / `arg_substr`, layered onto the built-in analyzer rules). Both are queryable fleet-wide via the `bowery_monitor_rules` SQL view.
- **YARA rule distribution** — `bowery exec yara --rules r.yar --target /tmp --fanout` ships an operator-signed rule to an agent, which stores it (content-addressed), scans the requested paths, alerts on matches, and propagates it across the mesh. Propagation is multi-hop, bounded by a TTL hop counter and a per-agent `(operator_fp, request_id)` seen-set so a cyclic peer graph converges instead of looping. Scanning is a build-time opt-in (`--features yara`, libyara); without it agents still store and forward rules. Stored rules are listed by the `bowery_yara_rules` SQL view.
- **Signed mesh enrollment + revocation** — admission was trust-on-first-use over the gossip mesh, and gossip is unauthenticated UDP, so "can reach port 9901 during the bootstrap window" was the entire admission control — with no way back out once pinned. `[known_neighbors] enrollment = "grant"` now requires an operator-signed `MembershipGrant` naming the peer's own fingerprint and cluster, verified against the operator keys agents already trust (no new trust root, no enrollment handshake — the grant rides the same gossip KV as the role vector). Grants are bound to one identity so a harvested one is useless to anyone else. `bowery trust revoke` mints a signed revocation that evicts a peer from the pin set and permanently refuses re-pinning, and pushes it across the mesh peer-to-peer (each hop verifies the operator signature itself, so a relay can drop a revocation but never forge one; forwarding only what was new makes a flood converge instead of echo); `bowery_revocations` and `bowery_mesh_peers.grant_state` make delivery and migration-readiness queryable fleet-wide. Default stays `tofu` so upgrading a fleet doesn't partition it.
- **Fleet connection graph** — every outbound connection is folded into a per-host destination baseline (`bowery_net_destinations`), so `--fanout` answers "which hosts have ever talked to this endpoint?" and "which endpoints has exactly one host ever contacted?" across the whole fleet. That second question is the shape of C2, exfil, and lateral movement, and it is not answerable from any single host — the two halves of a hop live on different machines and neither is remarkable alone. Joins against `bowery_events` to recover the process that made the connection.
- **Append-only event log** — every observed event (`exec`, `exit`, `connect`, `file_open`, `file_change`) is recorded to a per-agent `SQLite` history and exposed as the `bowery_events` SQL view, so an alert at 14:32 can be turned into "what was this host doing at 14:32" instead of a dead end. Nothing is shipped to a central lake: the timeline is reconstructed by asking the hosts, and `--fanout` federates it across the fleet. This is also the only retention for `ProcessExit` and `NetworkConnect`, which the eBPF loader had been producing and the pipeline discarding. Recording is bounded (age + hard row ceiling, oldest-first) and never blocks detection — a full writer queue sheds events and counts them, and `bowery_eventlog_status` reports `recording` / `queryable` / `dropped` so a blind host is distinguishable from a quiet one. The SQL surface `ATTACH`es the log read-only rather than copying it, so a multi-million-row history costs nothing to query.
- **Quorum-confirmed alerts** — when a whisper round comes back, the agent turns the answers into a verdict and, if the neighbourhood corroborates, appends a superseding alert marked confirmed. The polarity is deliberate: a peer that *has* the binary argues it's a normal fleet artifact, so confirmation counts peers that have **never seen it**, and non-responders count for nothing. A peer must also have *observed enough to have an opinion*: below `[whisper.qa] min_baseline_binaries` it refuses rather than answering "never seen it", because `seen_count: 0` otherwise conflates "I watch this fleet and your binary isn't part of it" with "I am not watching". That distinction was not hypothetical — two agents with dead event sources were found unanimously confirming every alert their neighbour raised, `/usr/bin/ssh` included. Refusals are reported separately (`peers_refused`) and never satisfy a quorum. Configurable via `[whisper.qa] quorum` (0 disables). Surfaced as `confirmed` / `peers_asked` / `peers_unseen` / `peers_seen` columns on `bowery_alerts`, a red-bold `conf` badge in the console, and a `mesh:` line in `bowery alerts`. The bloom pre-filter stands down when confirmation is on — it would skip exactly the peers a quorum needs, and its input is unauthenticated gossip, so quorum evidence is built only from signed answers. The Q&A path is now rate-limited in both directions (a concurrent-round semaphore outbound, a per-sender token bucket inbound, and TTL enforcement before the baseline scan).
- **Cross-host corroboration** — an inbound connection is unremarkable here, unremarkable there, and alarming only if the host it came from has no record of making it. Agents now ask: on an inbound connection from a mesh peer, the receiving agent whispers *"did you connect to me?"*, and a **denial** raises an alert carrying the denial as evidence (either that peer's agent is blind or tampered with, or the source address was spoofed). A corroborating answer instead returns the process attribution the accepting host can never derive on its own — the kernel's accept-side transition runs in softirq context, so inbound events carry no pid. The mechanism is deliberately **generic**: the wire carries a `kind` string plus opaque key/value attributes (`CorroborationQuery`/`CorroborationAnswer`), and a new kind of suspicion is a handler registration rather than a protocol change, so rate limiting, deadlines, replay guards and the quorum rule are inherited rather than reimplemented per detection. Two properties make the alert trustworthy: a responder only answers about **the asker's own address** (as its own mesh view reports it, so the message can't become an enumeration primitive), and it **refuses rather than denies** when its history doesn't cover the window — otherwise every freshly-installed agent would accuse every peer that ever talked to it. Refusals and timeouts are counted separately from denials and never satisfy a quorum. Configurable via `[whisper.corroboration]`.
- **File-write monitoring, with detections that explain themselves** — the kernel sensor watched no file operations at all, which is why persistence, credential access, defense evasion and impact were empty rows: they are all file-shaped. A `sys_enter_openat` probe now reports write-intent opens with path, process and flags, filtered **in the kernel** because reads outnumber writes by orders of magnitude and shipping them all would saturate the ring. LSM file hooks would be the natural choice and are unusable fleet-wide — Raspberry Pi kernels ship `CONFIG_BPF_LSM=n` — so tracepoints it is, with the argument offsets **verified at runtime against the kernel's own format file** and the probe refusing to attach on a proven mismatch (a wrong offset yields a garbage pointer and silently empty paths, which looks exactly like a host that opens no files). On top sit 15 built-in rules — `ld.so.preload`, systemd units, cron, `authorized_keys`, PAM, udev, shell rc, `sudoers`, `shadow`/`passwd`, SSH keys, auth/wtmp logs — each naming the process and pid and stating *why that path matters*, because an alert has to explain itself to someone woken at 03:00. Deliberately **not** suppressed by process name: `comm` is 16 bytes any process can set with `prctl`, so a "ignore dpkg" list is an evasion recipe.
- **Credential-access reads and set-id backdoors** — reading `/etc/shadow` or an SSH private key was invisible, because the file probe filtered to *write* intent. It now also ships reads whose path ends in a credential name (`/shadow`, `/id_rsa`, `/credentials`, `/.pgpass`, `_key`, …), matched **in the kernel by suffix**: finding the basename by scanning meant a 256-iteration loop over a map buffer, and the verifier rejected that program after eight seconds of analysis, so patterns anchor at the end of the string and match a whole final path component. Sixteen read rules distinguish theft from routine — `sshd` reads host keys at startup and `sudo` reads its own policy, so those rank below an `/etc/shadow` read by something that is not a password tool. Reading and writing the same path are separate findings with separate wording, because they mean different things. Alongside: a **setuid-root binary that no package owns** (or one that a package owns but no longer matches) is how a foothold becomes permanent root without touching a service file — which composes provenance with file metadata, and stays silent for the distro's own `sudo`/`su`/`passwd`.
- **Package provenance and process lineage** — a first execution scored 1.0, which made ordinary distro binaries the loudest thing in the alert stream (the live fleet quorum-confirmed `/usr/bin/nice` as an anomaly). A binary the package manager installed whose contents still match is damped to 15%: it was on disk before anyone logged in. Damped rather than zeroed, since `bash` and `curl` ship with the distro and other signals must still be able to carry an episode. The same index makes a **mismatch** a finding — a packaged system binary whose contents changed is trojanised. Alongside it, lineage rules judge *who asked*: a network service spawning a shell is the canonical webshell, while `sshd` spawning one is a login and must never alert. The parent comes from `/proc` at exec time, because `sched_process_exec` carries none and CO-RE cannot fetch it without the BTF Pi kernels lack.
- **Privilege transitions and reconnaissance bursts** — a process running as root whose parent was not is either an escalation you sanctioned or one you didn't, and telling those apart is the whole detection. The sanctioned path *must* be exempt or the rule fires on every administrative action a human takes — but the exemption is anchored on **package provenance, not on a name**: a binary called `sudo` that no package owns is the finding, not the exemption. Both uids compared are the **real** uid (`bpf_get_current_uid_gid` returns `current_uid()`), because a setuid binary changes the *effective* uid while the real one still names whoever ran it — mix the two and every `sudo` looks like a transition and every genuine one looks like nothing. An unreadable parent reports nothing rather than guessing, since on a booting host most root processes have already lost theirs. Alongside it: `whoami` is not a detection — it runs constantly, in scripts nobody wrote for an attacker — but **five different discovery commands from one parent inside a minute** is someone working out where they are. *Distinct* is what makes it usable (a script running `id` in a loop never trips it) and *parent* is what makes it possible (each `whoami` is its own short-lived pid; the shell that ran them is what ties them together). It reports once per window rather than once per command, and folds into the completing exec's verdict so the alert arrives carrying the ancestry that says who ran it. Tunable via `[detection]`, on by default — these are things an agent should do on a host nobody configured.
- **An ATT&CK coverage map that cannot lie** ([`docs/ATTACK-COVERAGE.md`](docs/ATTACK-COVERAGE.md)) — a coverage map kept in Markdown drifts the first time someone adds a rule and forgets to write it down, and it fails in the worst available direction: a document claiming coverage the code does not have. So the map is a table in [`attack.rs`](crates/bowery-analysis/src/attack.rs), the document is generated from it, and tests assert that every rule the agent can fire appears on the map, that the map names no rule that no longer exists, and that the checked-in file matches. There is deliberately **no grade above "good"** — no host sensor covers a technique completely, and a map that says "complete" invites an operator to stop looking — and every entry, including the well-covered ones, is required to name its own gap. The tally is in [What it detects](#what-it-detects), generated from the same table — it read *12 good, 10 partial, 3 uncovered across 25 techniques* here for long enough to be wrong in the flattering direction, which is why no number in this file is now typed by hand.
- **Alerts the agent can discard itself** — the live fleet produced 63 alerts in 24 minutes and 61 of them were `sshd` and `unix_chkpwd` doing exactly what they exist to do. Three separate mechanisms produced that flood and each needed a different answer. **The rule already knew**: `cred.read_ssh_host_key`'s own text reads *"sshd does this at startup"*, and it alerted anyway — so each credential rule now names the binaries whose job requires that path, exempt only when the resolved exe matches **and** package provenance vouches for it, meaning a trojanised or impostor `sshd` is still caught. Anchored on `/proc/<pid>/exe`, never on `comm`, for the same reason the file-watch layer already refused to suppress writes by process name: `comm` is 16 bytes any process sets with `prctl`, so a name-keyed allowlist is an instruction for reading every key on the host in silence. It fails **closed** — an unreadable exe earns no exemption, because a detection that goes quiet whenever it cannot look is one an attacker only has to outrun. **The repeat**: the same pid read the same key twice in the same second and alerted twice, so identical findings now fold into one report per window that states how many it stands for — counted, never discarded, since "read a host key" and "read a host key 4,000 times" are different events. **And our own deploy**: `/usr/bin/bowery` scored 1.00 on every node because the installer `scp`'d it, leaving it owned by no package. The detection was right; a binary in `/usr/bin` that no package owns genuinely is the shape it looks for. The deploy kit now builds a real `.deb`, so the agent stops reporting its own installation and starts reporting a *modified* copy of itself.
- **The mesh can take a finding back** (`file.access`) — every corroboration kind until now could only make things worse: the round ran, the rule fired, an alert appeared. That shape cannot express the most useful thing a neighbourhood can say, which is *"we all do that"*. Agents now ask up to three peers whether the same binary touches the same file on their hosts, and a corroborated answer appends a **superseding, downgraded** alert rather than a new one — so `bowery notify`, which keeps the newest alert per episode, sends the explained version or nothing at all. Three properties keep it honest: the finding is raised locally **first and always**, because a detection that waits for the mesh says nothing on a single-node install or a partitioned network; corroboration from **zero** peers never downgrades anything, the same rule that stops a blind peer confirming an alert applied in the other direction; and a peer answers only about paths **its own watch set already covers**, so the query cannot become a filesystem-enumeration oracle. The exe is resolved by joining `file_open` rows against the `exec` row for the same pid — `file_open` carries no exe path, and resolving one per open would put a readlink on the agent's hottest path.
- **Alerts that explain themselves** — "a rare binary ran" is not actionable. Every alert now carries a timestamp, the full command line, uid, working directory, the **process ancestry** (`systemd → sshd → bash → curl`), and a snapshot of the files and TCP peers the process had open, resolved from `/proc/net/tcp` so "held 3 sockets" becomes "connected to 198.51.100.7:80". The ancestry is usually what decides an alert: the same binary run by a human over SSH and run by a web server mean very different things. Carried as untyped key/value pairs so a new detection can attach what it needs without the alert path growing a field each time, sampled **once at exec time** while the process is still alive (by the time LLM inference returns it usually isn't), and rendered in the email, the CLI and the console. Unavailable context is omitted rather than shown as empty — "opened nothing" and "already exited" are different facts.
- **VirusTotal screening, operator-side only** (`bowery vt`, and an opt-in filter in `bowery notify`) — holds back alerts whose binary no engine flags, which pairs with package provenance to leave the genuinely unexplained binaries. Agents never call it: a hash lookup discloses to VT (and anyone with Intelligence access) that somebody is investigating that hash, and adversaries watch VT for their own samples — so an automatic lookup from a compromised host is a tip-off sent before an operator has decided what to do. It also keeps the API key off every monitored host, and the public quota (4/min) could not survive one busy host's first-exec stream. The governing rule is that it may only ever **suppress on a positive clean verdict and must fail open**: missing key, spent quota, API outage, unparseable response, or a hash VT has never seen all send the alert anyway, because a monitor that goes quiet when a third-party API breaks has failed in the one direction it must not. Each alert carries its own verdict line, a flagged binary leads both its host's list and the subject, and the digest counts hashes VT has never seen separately — because "2 checked" on its own reads as reassurance when it may mean the opposite.
- **Sensor self-attestation** (`bowery_probe_status`) — two agents once ran for days observing nothing: no BPF object, a silent fall back to the no-op source, one WARN at startup, while still gossiping, answering SQL, and voting in whisper quorums as though healthy. Nothing downstream could tell *quiet* from *blind*. Now each probe reports attached / emitted / parse-failed / kernel-drops / last-event, and blindness raises an **alert** — on transition and hourly after — so it reaches the console, the SQL surface, and `bowery notify` like any other finding. The kernel counts its own losses: `RingBuf::reserve` failing was invisible from userspace, so a per-CPU counter in the BPF object records every discarded event, polled every 10s. Drops read as NULL rather than 0 on an object built before the counter, because "no drops" and "cannot tell" are the exact distinction that let the original failure hide. A quiet host is deliberately *not* an alert — indistinguishable from an idle one, and paging on it is how the alert gets ignored.
- **Corroboration that answers instead of refusing** — the neighbourhood watch asked peers "have you seen sha256 X?" and read a quorum of *no* as evidence the binary was anomalous. Measured on the reference fleet, that question has no information in it: the x86-64 host shares **zero** of its 366 baseline hashes with either aarch64 host, and the two same-architecture hosts share 5 of ~100. The same program compiled for a different target is a different file, so "never seen it" was true of every binary in existence — including `/usr/bin/dash`, which the mesh duly reported as `CONFIRMED 2/2`, as did essentially every other alert that ran a round. This is the structural sibling of the bug that produced `Answer.refused`: that one let a responder say *"I am not watching"*, and it does nothing for *"I am watching a different architecture"* — a peer that is healthy, fully observing, and still incapable of a meaningful answer.

  Three things followed, in order, because each was only reachable once the one before it existed. **Peers that cannot be compared against** land in a bucket that never counts toward a quorum, and an unknown platform counts as incomparable rather than comparable — the cost of that choice is a confirmation that does not happen rather than an alert that is not raised. **The baseline learned what a hash *was***: it recorded only a sha256 and nothing else, so an agent could not answer "do you have this program at a different build" because it did not record which program a hash belonged to. It now keeps path, size, owning package and platform per hash, the package name coming free from the `.md5sums` filename the provenance index was already reading, architecture qualifier stripped. And **peers now answer with recognition**: the question carries the package and path, the answer carries whether the responder has that program, and a peer that holds it at another build replies *familiar* — neither a sighting nor a denial, never part of a quorum, and enough to break one the denials would otherwise have reached. Measured after descriptors filled: those three hosts share **zero** binary hashes and **seven** packages — `bash`, `coreutils`, `dash`, `systemd`, `openssh-server` among them. A recognised program supersedes its alert at a proportionally lower score, never to zero, because recognition says the *program* is fleet-normal and says nothing about whether this copy is intact — that is provenance's job, and prevalence must not talk over it.

  A responder answers from what is **installed**, not only from what it has run: asked about `/usr/bin/hostname`, peers that had the file and had never executed it were answering "never seen it" — true of the hash and useless as an answer. `file.access` was widened the same way, so a peer recognises its own copy of a daemon wherever that copy lives rather than only at the asker's exact path.

  Three states an operator could not previously distinguish now read differently everywhere — console, digest, SQL view, audit trail: **confirmed**, **could not check** (no comparable peer), and **known program**. `bowery_mesh_peers.comparable` answers "can this mesh corroborate itself at all" without running a round, and `bowery_corroboration_status` says per claim kind what became of every claim — including `no_audience`, which on a host whose inbound connections come from outside the mesh is nearly all of them and is not a fault. A kind that has raised nothing is a row of zeroes, not an absent row, for the same reason `bowery_detections` lists rules that never fired.

  `DT_NEEDED` and build-id were measured as further dimensions and **declined**: the first barely discriminates and would let a binary dropped in `/tmp` be "recognised" for linking `libc` and `libcurl`, which is a signal an attacker picks; the second is strictly narrower than the hash it would supplement. See [DESIGN-FUZZY-CORROBORATION.md](DESIGN-FUZZY-CORROBORATION.md) for the measurements behind both.

- **Privilege transitions judged by what actually granted the privilege** — `privesc.uid_transition_no_helper` fired 206 times a fortnight on one host, and the rule was checking the wrong process each time. It looks at the *parent* for a set-id helper, which is right for `sudo` — it forks, and the child execs as root beneath it. `pkexec` does not fork. It execs its target inside the same pid, so at the moment of the transition the parent is whatever launched it (`update-notifier`, not set-id) and the current binary is the target (`dash`, not set-id); the helper is the pid's own previous exec and nothing was looking there. The process table keeps one step of history so it can be, and only a *packaged, unmodified* set-id-root previous exec is accepted — a binary merely called `pkexec` is the finding, not the exemption. What remained after that was a lost race: `sudo` exits between the uid read that decides the check is worth making and the `/proc/<ppid>/exe` read it depends on, so the agent now trusts the parent exec it watched rather than racing `/proc` for something already recorded. The diagnostic that found both shapes reports *which* check declined, because an ordinary deploy and a real escalation had been producing identical log lines.

- **Operator-side alert history** (`bowery alerts history`, and the console's Alerts pane) — an agent's inbox is a bounded in-memory ring with a 72-hour TTL that dies with the process, which makes it a delivery buffer and not a record. "What did this host alert on last week" was not a missing view; the data did not exist. The security consequence is the one that decided where this lives: a record kept only on the machine it accuses is a record that machine's owner can revoke, so whoever roots a host can erase every alert about themselves by waiting three days or restarting a service. Both pollers — `bowery notify` on its timer and the console while open — now write every alert they drain to a local SQLite archive, and it is written **before** the notification filter and before the episode collapse, because the filter says what is worth waking someone for while the archive says what was observed; conflating them means raising `min_suspicion` silently erases history. Every superseding version is kept rather than only the newest, since a verdict *moves* (pre-filter → LLM → quorum → a mesh downgrade), and "raised at 0.9, downgraded to 0.3 when four peers said they all do that" is a different story from "0.3". Re-recording is a no-op on the natural key, so overlapping pollers and reset cursors cannot duplicate. The console's Alerts pane renders a query against it, which fixed three things at once: history predates the session, **every** agent in the manifest appears in one time-ordered list instead of only the connected relay, and searching is the same mechanism as browsing (`watchdog`, `agent:otter1`, `rule:cred.read_aws`, `min:0.8`, `since:7d`). The count is always rendered as "12 of 4318" — a filtered total on its own reads as a quiet fleet.

- **A queryable surface you can find your way around** (`bowery tables`, `:schema`) — the SQL surface was the most capable thing here and the least discoverable: knowing SQL does not tell you that `bowery_events` exists, that `ts_unix_ms` is milliseconds, or that `crontab` and `systemd_units` are joinable against it. There is now a catalogue of every table with its columns and a set of questions paired with the query that answers each, printed by `bowery tables` and rendered on the console's idle Query pane — the one moment somebody is looking for something to type. `:schema` asks the connected agent directly for the live list. The catalogue is checked against a running agent's real registry by a test, **in both directions**: an entry naming a table that no longer exists is a trap that reads as the tool being broken, and a table you can query but that nothing documents is capability that may as well not exist. That reverse check immediately found thirteen undocumented tables — `processes`, `listening_ports`, `crontab`, `systemd_units` and the rest of the live host-state surface, roughly half of what is queryable.

- **Email notifications without a backend** (`bowery notify`) — alerts otherwise wait in a per-agent inbox until somebody looks; a confirmed finding at 03:00 sits there until morning. This is a one-shot CLI on a systemd timer that drains every agent in the peer manifest over the **existing signed `Subscribe` transport**, collapses superseding alerts to one entry per episode, and sends a single digest through any SMTP relay you already have (Gmail documented first). It runs on one always-on box you own — deliberately **not** on the agents, because a notification credential on every monitored host is a credential every compromised host has, and lets an attacker flood you, read the secret, or watch for their own detection. The subject is built only from host names and counts so header injection is impossible by construction; the body carries triage detail with control characters stripped and a footer stating that those fields came from the monitored host and are leads rather than facts. It sends `multipart/alternative`: the full digest as text, and an HTML rendering for the client that will show it. HTML replaces "this cannot render as markup" with "this is escaped", so the escaping is what now holds that line — every interpolated value goes through it, and the order is load-bearing, because capping an already-escaped string severs entities. The HTML fetches **nothing** — no image, stylesheet or font, all styles inline — since a remote fetch would tell whoever serves it the moment an operator opened an alert about a compromise. Each alert carries the **episode id and a filled-in `bowery alerts silence` command**, because the id needed to quiet a recurring false positive was in the message all along but reading it off an 80-column wall and retyping a 64-hex fingerprint is not triage anyone does from a phone. The reason placeholder is one a shell *rejects*: pasted unedited it fails, where a `…` would have signed a fleet-wide silence justified by an ellipsis. Fields are capped, but the **rationale is capped for hostility, not for tidiness** — it is composed from the analyzer's verdict plus provenance, set-id, lineage, discovery and repeat-fold clauses, so a real one runs past 800 characters and a 160-char cap was cutting every credential alert mid-sentence. It now wraps with a hanging indent instead of truncating, and when a cap *is* hit the text says how many characters were dropped and where to read the rest — a bare ellipsis reads as "and so on" when it means "go look". Cursors advance only after a successful send, and a failed run exits non-zero — a notifier that fails quietly is the failure it exists to prevent. See [`deploy/notify/`](deploy/notify/).
- **Remote deployment + mesh over Tailscale** — [`deploy/remote/`](deploy/remote/) is a turnkey installer (static musl agent + bundled CLI, hardened systemd unit) for nodes reached over a tailnet, and [`deploy/remote/MESH.md`](deploy/remote/MESH.md) is a step-by-step multi-node mesh bring-up so `bowery exec sql --fanout` relays a query across the fleet. Supporting pieces: `[whisper] advertise_addr` (bind the wildcard for boot robustness, gossip the routable `100.x`), the fan-out completion terminator (fan-out returns promptly instead of waiting out the timeout), the operator client binding the unspecified address (cross-host dials work, not just loopback), and two operator diagnostics — `bowery peers check` (dials each agent, reports reachability) and the `bowery_mesh_peers` SQL view (gossip-discovered peers vs. the pinned set).

## What's next

- **F-7 / F-17** observability tightening — EOF-accounting transcript envelope so the operator can verify "all expected peers reported" in fan-out; per-peer warn rate-limit on the relay's logs.
- **Phase 10 slice 4+** — outbound-only mode (config flag to disable the inbound listener for fully-firewalled agents), per-fingerprint dial-in-progress slot.
- **Phase 11+ (deferred)** — fleet-scale Sybil resistance, key rotation ceremony, neighbor add/remove protocol.

## License

[MPL 2.0](LICENSE).
