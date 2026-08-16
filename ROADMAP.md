# Roadmap — from "observes execs" to "protects the host"

Companion to [MOTIVATION.md](MOTIVATION.md), which says why this exists,
and [IMPLEMENTATION.md](IMPLEMENTATION.md), which says how the built
parts work. This one is about the distance between what the agent can
surface today and what it would take to actually defend the machine it
runs on.

It is written to be uncomfortable. The substrate is genuinely good and
the detection content is genuinely thin, and conflating the two is how a
project like this fools itself.

---

## 1. What the agent can see today

**Kernel sensors** (eBPF, three tracepoints):

| probe | yields |
| --- | --- |
| `sched_process_exec` | pid, uid, comm |
| `sched_process_exit` | pid, comm |
| `sock/inet_sock_set_state` | TCP connect, both directions, addrs + ports |

**Userspace enrichment** (`/proc`, after the fact): `exe_path`,
sha256 of the exe, `cmdline`, `cgroup`.

**Operator-configured**: inotify watches on explicitly listed paths;
process rules matching `exe_prefix` / `comm` / `arg_substr`; YARA rules
pushed across the mesh.

That is the entire input surface. Everything the agent knows is derived
from it.

### What it can conclude

- **Three built-in rules**: exec from a world-writable path, exec with no
  resolvable `exe_path`, exec with suspicious args.
- **Local rarity**: a binary not in the baseline scores 1.0.
- **Fleet rarity**: `bowery_net_destinations` answers "which hosts ever
  contacted this endpoint" — queryable, but nothing alerts on it.
- **Neighbourhood prevalence**: a quorum of role-similar peers that have
  never seen a binary confirms an alert.
- **Cross-host correlation**: an inbound connection the source host has
  no record of making raises an alert with the denial as evidence.

### What it can do about any of it

Two actions: `kill_process`, and `block_exec` — the latter keyed by the
kernel's 16-byte `comm`.

---

## 2. Measured against how Linux hosts actually get compromised

Walking the phases of a real intrusion rather than a feature list:

| phase | what we'd catch today |
| --- | --- |
| Initial access | **nothing** — no visibility into the vector |
| Execution | partial — exec events, 3 rules, YARA when pushed |
| **Persistence** | **nothing** |
| **Privilege escalation** | **almost nothing** — `uid` is recorded, never analysed |
| **Defense evasion** | **nothing** — no file deletes, no log tampering, and `comm`-keyed blocking is itself trivially evaded |
| **Credential access** | **nothing** — no file reads at all |
| Discovery | **nothing** — no recon-pattern analysis |
| **Lateral movement** | **partial, and genuinely ahead** — the corroboration work |
| Collection / exfil | partial — connect events + destination rarity, queryable, not alerting |
| Impact (ransomware, wipers) | **nothing** — no mass-write signal |

The pattern is stark. We have unusually good infrastructure for the one
phase most products handle worst (lateral movement, because it needs two
hosts to agree), and near-zero coverage of the phases every intrusion
passes through on one host.

### The three structural gaps

**No file visibility.** The kernel sensors don't watch file operations at
all. inotify covers only paths an operator listed in advance. This one
gap is why persistence, credential access, defense evasion, and impact
are all empty rows: they are overwhelmingly file-shaped, and we are
blind to files.

**Nothing reads the process tree.** `process_lineage` is populated on
every exec and read by nothing. "`nginx` spawned `sh`" is the oldest
detection in the book, needs no new sensor, and we can't express it.

**The response engine can be lied to.** `block_exec` keys on `comm`,
which is attacker-controlled (`prctl(PR_SET_NAME)`, or just rename the
file). It is bypassed by an attacker who reads this paragraph, and worse,
it is *weaponisable*: name a process `sshd` and the blocklist locks out
the real one.

### And the meta-problem: the alerts aren't trustworthy yet

We spent this week watching the fleet quorum-confirm `/usr/bin/ssh`,
`/usr/bin/nice` and `/usr/bin/pkexec` as anomalies. Two root causes are
now fixed (blind peers, young peers). The third is not: **a first
execution of a distro-packaged binary scores 1.0 and alerts.** An EDR
that cries wolf about `nice` trains its operator to close the tab, and
every detection added below inherits that fate until it's fixed.

---

## 3. The plan

Ordered by "how much attack coverage per unit of work", with the
constraint that nothing below matters on an agent that isn't watching.

### Phase A — Make the sensor trustworthy *(BUILT)*

We discovered two agents observing nothing by noticing a SQL result
looked odd, days after deployment. That must be impossible to miss.

- **Probe health telemetry** — `bowery_probe_status` reports per probe:
  attached, events emitted, parse failures, kernel drops, last event.
- **The kernel counts what it drops.** `RingBuf::reserve` returning
  `None` was invisible: a saturated sensor and a quiet host produced
  identical output. A per-CPU counter in the BPF object, polled every
  10s, is the only place that fact exists. Reported as NULL rather than
  zero on an object that predates it — "no drops" and "cannot tell" are
  the distinction the whole phase is about.
- **Blindness is an alert**, raised on transition and repeated hourly,
  so it reaches the console, SQL, and `bowery notify` like any finding.

Deliberately excluded: **a quiet host**. "No events recently" is
indistinguishable from an idle machine, and paging someone whenever a Pi
idles overnight is how the alert gets ignored. Staleness is reported for
a human to judge.

Two bugs found by running it on hardware rather than reasoning about it:
the watchdog alerted `SENSOR BLIND` one millisecond before the probes
attached (fixed with a startup grace that applies only to a source that
might still come up), and a missing object correctly alerts immediately
because nothing is coming.

**Still open from this phase:** peers noticing for each other. A
neighbour that stops answering, or refuses everything, is visible in the
corroboration tallies already on the wire but nothing acts on it.

### Phase B — Close the file gap *(largest coverage win)*

Add file operations to the kernel sensor: open-for-write, create,
rename, unlink, chmod/chown, with path resolution. Then ship
**built-in** watch sets rather than leaving it to operator config:

- **Persistence**: systemd units and timers, cron, `authorized_keys`,
  shell rc files, `/etc/ld.so.preload`, kernel modules, udev rules, PAM.
- **Credential access**: `/etc/shadow`, `~/.ssh/id_*`, `~/.aws`,
  `~/.kube`, kernel keyring, `/proc/*/mem` and ptrace.
- **Impact**: mass-rename / mass-write rate per process, the shape of
  ransomware.

This single phase turns four empty rows into populated ones.

*Note the kernel constraint discovered on the Pis: `CONFIG_BPF_LSM` is
off on Raspberry Pi kernels, so LSM-hook-based file monitoring won't run
there. Prefer tracepoints/kprobes where possible and degrade explicitly
where not — with Phase A making the degradation visible.*

### Phase C — Detection content on data we already collect *(cheap)*

No new sensors required:

- **Package provenance**, which is also the fix for the noise problem: a
  binary owned by an installed package and unmodified since install is
  not interesting on first execution. This kills the `/usr/bin/nice`
  class outright and lets rarity mean something again.
- **Lineage rules**: service → shell, shell → network client, web
  server → interpreter. The table is already there.
- **uid-transition rules**: setuid exec, a non-root process becoming
  root, capability changes.
- **Discovery patterns**: the recon burst that precedes most lateral
  movement.
- **An ATT&CK coverage map**, honestly scored, kept in-repo.

### Phase D — Make response worth arming

- **Inode/sha-keyed `block_exec`** replacing the `comm` key (already
  scoped as P9-2). Until then, blocking is theatre.
- **Network isolation** as an action, and **dry-run mode** so an operator
  can watch what enforcement *would* have done.
- **Quorum-gated enforcement**: `DESIGN.md` has always specified hard
  actions requiring standing authorization *or* k-of-n peer agreement.
  The quorum signal now exists and is trustworthy; the response engine
  still never sees it. Connect them.

### Phase E — The things only this architecture can do

Deliberately after the fundamentals, because a distributed detection
built on a blind sensor is still blind.

- **More corroboration kinds** — the substrate is generic and has one
  registered kind. Destination rarity, persistence-file rarity, and
  "did an operator really push you this rule?" all fit with no protocol
  change.
- **Peer-witnessed audit.** Root on a host means deleting the local
  audit log. Peers holding the chain head make deletion detectable — an
  attacker cannot retract hashes their neighbours already have.
- **Herd immunity**: one agent confirms a bad artifact, the fleet blocks
  it within seconds, no console round trip. This is Phase D's response
  engine plus Phase E's quorum, and it is the single most compelling
  thing the architecture can offer.

### Phase F — Self-protection

- Agent liveness and integrity witnessed by peers (a stopped agent is an
  event on *other* machines).
- Off-box witnessing of the event log so local deletion is detectable.

---

## 4. Reaching an operator who isn't looking

Every alert currently lands in a per-agent inbox and waits for somebody
to run `bowery alerts` or open the console. A confirmed lateral-movement
finding at 03:00 sits there until morning. That is a real gap, and it
must be closed **without standing up a backend**, which is the whole
premise of the project.

### The two things that make this harder than it looks

**A webhook body is an exfil channel.** Notifications naturally want to
carry `exe_path`, `rationale`, `comm` — all attacker-influenced strings.
An attacker who can create `/tmp/<encoded-secret>` and get it executed
has just used *your* notification pipeline to egress data to an external
service, authenticated with your credential. Any design that forwards
detection text verbatim to a third party has built a covert channel.

**Notification volume is an attack surface.** Flooding the operator's
phone is both a denial of attention and a way to bury the one alert that
matters. Whatever sends must be budgeted, and the budget must be
enforced on the sending side, not hoped for.

### Built: an operator-side bridge, not agent egress

`bowery notify` — a CLI subcommand that drains alerts through the
**existing signed `Subscribe` / fan-out path**, filters to confirmed or
above-threshold, and POSTs a digest to a webhook. Run it from a systemd
timer on any always-on box you already own (a Pi is ideal).

Why this shape:

- **No new agent code, no new protocol.** It composes the alert
  transport that already exists.
- **No credential on monitored hosts.** The webhook secret lives on one
  machine of your choosing. A compromised monitored host cannot spam
  you, cannot read the credential, and cannot suppress delivery.
- **No new egress from monitored machines.** They keep talking only to
  the mesh.
- **Alerts are verified before they notify.** They arrive in signed
  envelopes over the operator transport, so an attacker cannot inject a
  notification without an operator key.
- **"Not having the CLI open" is satisfied** — the timer holds it open
  on your behalf.

Targets are whatever the operator already uses: Slack / Discord /
Matrix / Telegram / ntfy / Pushover / Gotify incoming webhooks, or SMTP
via their own relay for email. None of it is infrastructure we run.

### The rules that make it safe

- **Nothing attacker-controlled reaches a header.** The subject is
  built from manifest host names and counts only. Header injection
  becomes impossible by construction rather than filtered-for.
- **How much detail the body carries depends on where it lands.** For a
  *webhook*, pointer-only: host, count, episode id — the body traverses
  a third-party service and is a plausible exfil channel. For *email to
  the operator's own mailbox*, the detail goes in, sanitised and capped,
  because it lands somewhere the attacker cannot read and the cost of
  withholding it is someone woken at 03:00 who cannot triage without a
  laptop. The email footer says plainly that those fields came from the
  monitored host and are leads, not facts.
- **Digest, don't stream.** One message per window per host, with
  counts. Bounded by design.
- **Delivery failure is itself visible.** A notifier that silently stops
  is the event-log-writer bug wearing a different hat, so failures and
  last-success land in SQL / exit status rather than only in a log line.
- **Secret from a 0600 file**, never from the config file, never logged.

### Still open: `[notify]` in the agent

For fleets with no always-on operator box, the same sink can live in the
agent — same pointer-not-payload rule, same budget, plus a hard
per-agent rate limit because now the credential *is* on a monitored
host. Off by default, and documented as the weaker option with the
reasons above. Worth building second, and only if the bridge proves
insufficient.

---

## 5. What we deliberately won't do

- **Not more LLM.** The embedded model refines rationales; it is not a
  detection strategy, and more inference on thin signal is still thin.
- **Not more SQL tables.** The query surface is ahead of the data worth
  querying. Feed it, don't widen it.
- **Not agentless / central collection.** The whole thesis is that the
  answer is computed where the data lives.
- **Not detections we can't test.** Every phase above lands with the
  two-agent integration coverage the corroboration work established, and
  gets verified on real hardware — which is how all four bugs this week
  were found.

---

## 6. Sequencing

```
A (sensor trust) ──► B (file gap) ──► C (content) ──► D (response) ──► E (mesh-native)
      │                                    │
      └─ small, unblocks everything        └─ C also fixes the alert-noise problem,
                                              which gates operator trust in all of it

§4 (notification bridge) ── independent of the above; small; do it early
```

A is small and unblocks judgement of everything else. B is the largest
single coverage win. C is cheap and fixes the credibility problem. D
makes enforcement safe to arm. E is the differentiator and reads better
on a foundation that works.

The notification bridge (§4) doesn't depend on any of it and is a few
hundred lines against transport that already exists. It is worth doing
early — but only *after* C, because paging someone about `/usr/bin/nice`
at 03:00 is how you get told to turn it off.

If only one thing gets done: **C's package provenance**, because an
operator who has learned to ignore the alerts is a defence that has
already failed — and a notifier bolted onto untrustworthy alerts makes
that worse, not better.
