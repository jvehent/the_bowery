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
- **VirusTotal screening, operator-side only** (`bowery vt`, and an opt-in filter in `bowery notify`) — holds back alerts whose binary no engine flags, which pairs with package provenance to leave the genuinely unexplained binaries. Agents never call it: a hash lookup discloses to VT (and anyone with Intelligence access) that somebody is investigating that hash, and adversaries watch VT for their own samples — so an automatic lookup from a compromised host is a tip-off sent before an operator has decided what to do. It also keeps the API key off every monitored host, and the public quota (4/min) could not survive one busy host's first-exec stream. The governing rule is that it may only ever **suppress on a positive clean verdict and must fail open**: missing key, spent quota, API outage, unparseable response, or a hash VT has never seen all send the alert anyway, because a monitor that goes quiet when a third-party API breaks has failed in the one direction it must not. Each alert carries its own verdict line, a flagged binary leads both its host's list and the subject, and the digest counts hashes VT has never seen separately — because "2 checked" on its own reads as reassurance when it may mean the opposite.
- **Sensor self-attestation** (`bowery_probe_status`) — two agents once ran for days observing nothing: no BPF object, a silent fall back to the no-op source, one WARN at startup, while still gossiping, answering SQL, and voting in whisper quorums as though healthy. Nothing downstream could tell *quiet* from *blind*. Now each probe reports attached / emitted / parse-failed / kernel-drops / last-event, and blindness raises an **alert** — on transition and hourly after — so it reaches the console, the SQL surface, and `bowery notify` like any other finding. The kernel counts its own losses: `RingBuf::reserve` failing was invisible from userspace, so a per-CPU counter in the BPF object records every discarded event, polled every 10s. Drops read as NULL rather than 0 on an object built before the counter, because "no drops" and "cannot tell" are the exact distinction that let the original failure hide. A quiet host is deliberately *not* an alert — indistinguishable from an idle one, and paging on it is how the alert gets ignored.
- **Email notifications without a backend** (`bowery notify`) — alerts otherwise wait in a per-agent inbox until somebody looks; a confirmed finding at 03:00 sits there until morning. This is a one-shot CLI on a systemd timer that drains every agent in the peer manifest over the **existing signed `Subscribe` transport**, collapses superseding alerts to one entry per episode, and sends a single digest through any SMTP relay you already have (Gmail documented first). It runs on one always-on box you own — deliberately **not** on the agents, because a notification credential on every monitored host is a credential every compromised host has, and lets an attacker flood you, read the secret, or watch for their own detection. The subject is built only from host names and counts so header injection is impossible by construction; the body carries triage detail with control characters stripped, fields capped, `text/plain` only, and a footer stating that those fields came from the monitored host and are leads rather than facts. Cursors advance only after a successful send, and a failed run exits non-zero — a notifier that fails quietly is the failure it exists to prevent. See [`deploy/notify/`](deploy/notify/).
- **Remote deployment + mesh over Tailscale** — [`deploy/remote/`](deploy/remote/) is a turnkey installer (static musl agent + bundled CLI, hardened systemd unit) for nodes reached over a tailnet, and [`deploy/remote/MESH.md`](deploy/remote/MESH.md) is a step-by-step multi-node mesh bring-up so `bowery exec sql --fanout` relays a query across the fleet. Supporting pieces: `[whisper] advertise_addr` (bind the wildcard for boot robustness, gossip the routable `100.x`), the fan-out completion terminator (fan-out returns promptly instead of waiting out the timeout), the operator client binding the unspecified address (cross-host dials work, not just loopback), and two operator diagnostics — `bowery peers check` (dials each agent, reports reachability) and the `bowery_mesh_peers` SQL view (gossip-discovered peers vs. the pinned set).

## What's next

- **F-7 / F-17** observability tightening — EOF-accounting transcript envelope so the operator can verify "all expected peers reported" in fan-out; per-peer warn rate-limit on the relay's logs.
- **Phase 10 slice 4+** — outbound-only mode (config flag to disable the inbound listener for fully-firewalled agents), per-fingerprint dial-in-progress slot.
- **Phase 11+ (deferred)** — fleet-scale Sybil resistance, key rotation ceremony, neighbor add/remove protocol.

## License

[MPL 2.0](LICENSE).
