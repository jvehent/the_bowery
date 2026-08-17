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

Assessed before phases A–C; the right-hand column is where it stands
now.

| phase | at assessment | today |
| --- | --- | --- |
| Initial access | nothing | nothing — no visibility into the vector |
| Execution | partial | partial + provenance and lineage damp the noise |
| **Persistence** | **nothing** | rules for units, cron, `authorized_keys`, `ld.so.preload`, PAM, udev, shell rc |
| **Privilege escalation** | almost nothing | `sudoers`, set-id binaries no package owns, uid transitions to root outside the sanctioned path |
| **Defense evasion** | **nothing** | auth/wtmp tampering; `comm`-keyed blocking still evadable |
| **Credential access** | **nothing** | writes *and* reads: `shadow`, SSH keys, `~/.aws`, `~/.kube`, `.pgpass`, and eleven more |
| **Discovery** | **nothing** | recon bursts — five distinct discovery commands from one parent in a minute |
| **Lateral movement** | partial, genuinely ahead | unchanged — the corroboration work |
| Collection / exfil | partial | partial — destination rarity queryable, not alerting |
| Impact (ransomware) | **nothing** | nothing — no mass-write rate signal |

Per-technique detail, generated from the rule tables so it cannot drift
from the code, is in [`docs/ATTACK-COVERAGE.md`](docs/ATTACK-COVERAGE.md).

The pattern is stark. We have unusually good infrastructure for the one
phase most products handle worst (lateral movement, because it needs two
hosts to agree), and near-zero coverage of the phases every intrusion
passes through on one host.

### The three structural gaps

**No file visibility.** *(closed in phase B.)* The kernel sensors watched
no file operations at all, and inotify covered only paths an operator
listed in advance. This one gap was why persistence, credential access,
defense evasion and impact were empty rows — they are overwhelmingly
file-shaped. A `sys_enter_openat` probe now reports write-intent opens,
and credential *reads* alongside them (matched in the kernel by suffix).
Mass-write rates remain unbuilt, which is why Impact is still an empty
row.

**Nothing reads the process tree.** *(closed in phase C.)*
"`nginx` spawned `sh`" is the oldest detection in the book and needed no
new sensor. Correcting the original claim: `process_lineage` was neither
written nor read — dead schema — and the parent had to come from
`/proc`, since `sched_process_exec` carries none and CO-RE cannot fetch
it without the BTF Pi kernels lack.

**The response engine can be lied to.** `block_exec` keys on `comm`,
which is attacker-controlled (`prctl(PR_SET_NAME)`, or just rename the
file). It is bypassed by an attacker who reads this paragraph, and worse,
it is *weaponisable*: name a process `sshd` and the blocklist locks out
the real one.

### And the meta-problem: the alerts aren't trustworthy yet

We spent this week watching the fleet quorum-confirm `/usr/bin/ssh`,
`/usr/bin/nice` and `/usr/bin/pkexec` as anomalies. All three root
causes are now addressed: blind peers (phase A), young peers
(`min_baseline_age`), and first executions of distro-packaged binaries
(phase C provenance, plus optional VirusTotal screening at the notify
boundary).

Then the credential-read rules shipped and the fleet produced **63
alerts in 24 minutes, 61 of them `sshd` doing its job** — the same
lesson in a new place. Four causes, all now fixed: rules that named
their own exemption in prose and never applied it; every `open()`
alerting separately; `bowery_alerts` counting superseding alerts twice;
and our own installer dropping unpackaged binaries into `/usr/bin`,
which made `/usr/bin/bowery` the highest-suspicion thing on the host.

The recurring shape is worth naming, because it will happen again: a
detection is written, it is correct, and the *benign* case that
dominates real hosts was never enumerated. Shipping a rule now means
pulling the fleet's inbox a day later and reading what it actually
produced.

What remains after all of it is a binary that is **rare here, owned by
no package, and unknown to the industry** — a much shorter list, and the
one worth reading. Keeping it that way is the standing constraint on
every detection added below: an EDR that cries wolf about `nice` trains
its operator to close the tab.

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

**Closed since:** peers noticing for each other. `peer_watchdog` reports
a neighbour that stops gossiping while other peers remain visible — the
one failure a host cannot report about itself, and the cheapest way to
defeat every other detection at once. The mesh had known within seconds
all along: chitchat's failure detector drops the node, `bowery-mesh`
republishes the set, and that fact was consumed in six places, every one
of them routing and none of them as a finding.

The care is in the negative case. When *every* peer vanishes the cause
is almost always this host's own network, so the finding is raised about
**this** agent rather than as N accusations against neighbours who are
fine — the same rule the corroboration engine applies in the other
direction, that silence is not evidence whichever way it points.

Still open: an agent left *running* but tampered with still gossips, so
it looks alive to every peer watching for silence. That needs attested
liveness, not observed liveness — Phase F.

### Phase B — Close the file gap *(BUILT: sensor + persistence/credential rules)*

Add file operations to the kernel sensor: open-for-write, create,
rename, unlink, chmod/chown, with path resolution. Then ship
**built-in** watch sets rather than leaving it to operator config:

- **Persistence**: systemd units and timers, cron, `authorized_keys`,
  shell rc files, `/etc/ld.so.preload`, kernel modules, udev rules, PAM.
- **Credential access**: `/etc/shadow`, `~/.ssh/id_*`, `~/.aws`,
  `~/.kube`, kernel keyring, `/proc/*/mem` and ptrace.
- **Impact**: mass-rename / mass-write rate per process, the shape of
  ransomware.

**Built:** a `sys_enter_openat` probe filtered kernel-side to write
intent (reads outnumber writes by orders of magnitude and would saturate
the ring), with its assumed argument offsets verified against the
kernel's own format file and the probe refusing to attach on a proven
mismatch. Plus a built-in watch set covering persistence
(`ld.so.preload`, systemd units, cron, `authorized_keys`, PAM, udev,
shell rc), privilege escalation (`sudoers`), credentials (`shadow`,
`passwd`, private keys) and log tampering — each alert naming the
process and explaining why the path matters.

Two limits are recorded rather than hidden: paths are captured to 256
bytes and flagged when truncated, and relative paths (an `openat`
against a dirfd the probe cannot resolve) are stored but never matched,
because guessing would attribute a write to a file nobody touched.

**Still open in this phase:** mass-write rate detection for ransomware.
Credential reads landed — matched in the kernel by path suffix, since
scanning for the basename produced a program the verifier rejected. Package-manager writes will produce
hits — deliberately not suppressed by process name, since `comm` is
attacker-controlled and a suppression list is an evasion recipe. Fleet
corroboration is the right answer there and the substrate already
exists.

*Note the kernel constraint discovered on the Pis: `CONFIG_BPF_LSM` is
off on Raspberry Pi kernels, so LSM-hook-based file monitoring won't run
there. Prefer tracepoints/kprobes where possible and degrade explicitly
where not — with Phase A making the degradation visible.*

### Phase C — Detection content on data we already collect *(BUILT)*

No new sensors required:

- **Package provenance** *(built)* — the fix for the noise problem. A
  binary owned by an installed package and unmodified since install is
  damped to 15% on first execution, which kills the `/usr/bin/nice`
  class. The same index makes a *mismatch* a finding: a packaged system
  binary whose contents changed is trojanised, scored 1.0.
- **Lineage rules** *(built)* — service → shell, service → downloader,
  service → interpreter, scheduler → downloader. Correcting the note
  above: `process_lineage` was neither written nor read, and lineage
  needed the parent, which `sched_process_exec` does not carry and CO-RE
  cannot fetch without the BTF Pi kernels lack. It is read from `/proc`
  at exec time instead. One hop only; deeper ancestry needs a process
  table that survives exits.
- **uid-transition rules** *(built)* — a process running as root whose
  parent was not. The *sanctioned* path has to be exempt or this fires
  on every administrative action a human takes, and the exemption is
  anchored on **package provenance, not on a name**: a binary called
  `sudo` that no package owns is the finding, not the exemption. Both
  uids are the **real** uid — `bpf_get_current_uid_gid` returns
  `current_uid()`, and comparing a real uid against an effective one
  would call every `sudo` a transition and every genuine one nothing.
  An unknown parent reports nothing rather than guessing; on a booting
  host most root processes have already lost their parent.
  Capability changes remain unbuilt — there is no sensor for them.
- **Discovery patterns** *(built)* — five *distinct* recon commands
  (about fifty are recognised, from `whoami` to `getcap`) from one
  parent inside a minute. Distinct is what makes it work: a script
  running `id` in a loop never trips it. Keyed on the parent, because
  each `whoami` is its own short-lived pid and what ties them together
  is the shell that ran them. Reports once per window, not once per
  command, and folds into the completing exec's verdict so the alert
  arrives with the ancestry that says who ran it.
- **An ATT&CK coverage map** *(built)* — [`docs/ATTACK-COVERAGE.md`],
  generated from [`attack.rs`] rather than written, because a map that
  lives only in Markdown drifts the first time someone adds a rule and
  forgets to write it down — and the failure mode is the worst one
  available: a document claiming coverage the code does not have. A
  test asserts every rule the agent can fire appears on the map, that
  the map names no rule that no longer exists, and that the checked-in
  document matches the table. There is deliberately no grade above
  "good": no host sensor covers a technique completely, and every
  entry must name its gap. Today: 12 good, 10 partial, 3 uncovered.

[`docs/ATTACK-COVERAGE.md`]: docs/ATTACK-COVERAGE.md
[`attack.rs`]: crates/bowery-analysis/src/attack.rs

### Phase D — Make response worth arming *(dry-run + mode gate BUILT)*

- **Dry-run mode** *(built)* — the missing middle. Arming an EDR is a
  step operators are right to be slow about, and nothing in an
  observe-only deployment told you what *would* have happened, so the
  real choice was between running blind and running armed. Most people
  sensibly choose blind forever. Now every gate runs, only the final
  effect is skipped, and the audit log holds exactly the actions arming
  this host would have taken against its real traffic.

  It reports `would_execute`, deliberately **not** `suppressed`. Those
  are opposite facts: a suppression means a gate said no, and reading
  approved actions as policy refusals would tell an operator their
  policy was working when it had in fact approved every one — which
  would make a dry run worse than no dry run.

- **A `mode` separate from `engine`** *(built)* — `engine` says *how* a
  host would be acted on, `mode` says *whether*. Conflating them was
  what made the middle step impossible. `off` is the default, and a host
  cannot be armed by naming an engine: an upgrade must never arm
  enforcement on an operator's behalf.

- **Inode/sha-keyed `block_exec`** *(open)* replacing the `comm` key
  (already scoped as P9-2). Until then, blocking is theatre — and
  weaponisable. Needs the LSM hook to read `bprm->file->f_inode` via
  CO-RE, which needs BTF, which Pi kernels do not ship; those hosts
  cannot run BPF-LSM at all, so this lands as a capability that degrades
  explicitly rather than one that works fleet-wide.
- **Network isolation** as an action.
- **Quorum-gated enforcement**: `DESIGN.md` has always specified hard
  actions requiring standing authorization *or* k-of-n peer agreement.
  The quorum signal now exists and is trustworthy; the response engine
  still never sees it. Connect them.

### Phase E — The things only this architecture can do

Deliberately after the fundamentals, because a distributed detection
built on a blind sensor is still blind.

- **More corroboration kinds** — the substrate is generic and has two
  registered kinds. `file.access` *(built)* asks "does this binary touch
  this file on your host too?", and is the first round that can
  **downgrade** rather than escalate: every earlier kind could only make
  things worse, which could not express the most useful answer a
  neighbourhood gives — *"we all do that"*. It supersedes the local
  alert with a lower score, never raises one of its own, never runs
  before the local finding, and treats corroboration from zero peers as
  the non-evidence it is. Destination rarity and "did an operator really
  push you this rule?" still fit with no protocol change.
- **Peer-witnessed liveness** *(built)* — see Phase A. A stopped agent
  is now an event on its neighbours.
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
