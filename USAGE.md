# USAGE — standing up a Bowery network from scratch

A start-to-finish guide: build it, admit hosts to a mesh, and use it.
[MOTIVATION.md](MOTIVATION.md) is why this exists,
[IMPLEMENTATION.md](IMPLEMENTATION.md) is how the internals work, and
[ROADMAP.md](ROADMAP.md) is honest about what it does not yet detect.
This one assumes you want a working fleet by the end of the afternoon.

---

## 1. Concepts, in the order they matter

**There is no server.** No console, no database, no queue, nothing to
run in a cloud. Every agent holds its own history and answers questions
about itself. The operator CLI is a client that talks to agents
directly. If your laptop is off, the fleet keeps working; you simply
aren't asking it anything.

**An agent is an identity.** On first start each agent generates an
Ed25519 keypair. Its **fingerprint** — `SHA-256` of the public key — is
its permanent name. Everything is signed with it and pinned to it, so
"which host said this" is a cryptographic fact rather than a hostname
you hope is right.

**The mesh is two channels.**

| | port | what it carries | authenticated? |
| --- | --- | --- | --- |
| gossip (chitchat) | UDP 9901 | who exists, addresses, role vectors | **no** |
| whisper (QUIC) | UDP 9902 | every actual message | yes, signed + pinned |

Gossip is only discovery. Nothing trusts it. All real traffic goes over
whisper with signed envelopes bound to a specific recipient.

**Enrollment decides who gets pinned.** Two policies:

- `tofu` — pin anything seen gossiping during the bootstrap window.
  Since gossip is unauthenticated UDP, this means *"whoever can reach
  port 9901 during that window"* is your admission control. Fine for a
  lab, and the default so upgrades don't partition a fleet.
- `grant` — pin only agents presenting an **operator-signed membership
  grant** naming their own fingerprint and cluster. This is what you
  want. Grants are minted offline and bound to one identity, so a stolen
  one is useless elsewhere.

**Revocation is permanent.** `bowery trust revoke` mints a signed
artifact that evicts a peer and refuses to ever re-pin it. It propagates
peer-to-peer, and each hop verifies the operator signature itself — a
relay can drop a revocation but never forge one.

**The operator is also a key.** You generate an operator identity and
put its *public* key in each agent's config. That is what lets you drain
alerts and run queries. There is no password anywhere.

**What it detects, on one host.** Rule hits (exec from a world-writable
path, suspicious arguments), rarity (a binary this host has not run
before), **file writes to paths that matter** (`ld.so.preload`, systemd
units, cron, `authorized_keys`, PAM, `sudoers`, `shadow`, auth logs),
**reads of credentials** (`/etc/shadow`, SSH private keys, `~/.aws`,
`~/.kube`, `.pgpass`, `.netrc`), **set-id backdoors** (a setuid-root
binary no package owns), **lineage** (a network service spawning a
shell), **privilege transitions** (a process running as root whose
parent was not, outside the sanctioned `sudo`/`su`/`pkexec` path), and
**reconnaissance bursts** (five different discovery commands from one
parent inside a minute), **ransomware-shaped write sweeps** (many
files, many directories, one extension normal software does not
produce), and **C2 beaconing** (a timer to a destination this host has
not known long). Four things damp
the noise: a binary the package manager installed and has not modified
is not interesting on first run; `sshd` starting a shell is a login; a
binary whose **job** is reading a credential file (a packaged, unmodified
`sshd` reading host keys, `unix_chkpwd` reading `/etc/shadow`) is not a
finding; and repeats of an identical finding fold into one alert that
says how many it stands for.

That third one is anchored on the reader's **exe path plus package
provenance**, never on its process name — so a trojanised `sshd`, or
something merely *called* `sshd` from `/tmp`, is still caught. If the exe
cannot be read at all, the alert is raised: the exemption has to be
earned.

Per-technique detail, including what is *not* covered, is in
[`docs/ATTACK-COVERAGE.md`](docs/ATTACK-COVERAGE.md). It is generated
from the rule tables, so it cannot claim coverage the code does not
have.

**The mesh is what makes it more than N separate agents.** Three whisper
kinds run today, plus one thing that needs no question asked at all:

- *Prevalence* — "have you seen this binary?" A quorum of peers that
  have **never** seen it confirms an alert, because a binary none of
  your fleet runs is anomalous for your fleet.
- *Corroboration* — "did you connect to me?" An inbound connection the
  source host has no record of making is either a blind agent or a
  spoofed address. Neither is visible from one machine.
- *Access shape* — "does this binary touch this file on your host too?"
  Peers that see the same thing turn a local finding into how the fleet
  is built, and the alert is **superseded by a downgraded one** rather
  than a second alert. It can only ever take a finding back, never raise
  one, and it never runs before the local alert.
- *Liveness* — not a question but an observation: a peer that stops
  gossiping while others remain visible is reported by its neighbours.
  An agent that is not running detects nothing, so stopping it is the
  cheapest way to defeat everything else — and it is the one failure a
  host cannot report about itself. If *every* peer vanishes at once the
  finding is raised about **this** host instead, because that is what a
  lost network looks like and accusing the whole fleet would be N false
  findings.

Every one of them refuses rather than guesses when it lacks standing — a
peer with an empty or young baseline, or whose history does not cover
the window asked about, says "I can't say" rather than voting; and an
agent that can see no peers at all reports its own isolation rather than
accusing the fleet. That distinction is load-bearing; see §9.

---

## 2. Build

### Operator workstation + any x86-64 host you monitor

```bash
sudo apt install -y build-essential pkg-config clang libclang-dev cmake curl git
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

git clone https://github.com/jvehent/the_bowery && cd the_bowery
cargo build --release --workspace
```

Binaries land in `target/release/`: `bowery` (operator CLI),
`bowery-agent`, `bowery-console`.

On a host that is *also* a monitored node, install them with
`./scripts/build-install-operator` rather than by hand. It packages each
binary and installs it with `dpkg`, which matters more than it sounds:
a binary dropped into `/usr/bin` by `install` is owned by no package, so
the agent's own provenance check scores it as an unpackaged newcomer and
alerts on your own tooling. That is not a false positive — it is the
detection working on a badly-deployed binary.

### The eBPF object — build once, ship everywhere

The kernel sensor is a separate artifact. It targets
`bpfel-unknown-none` (BPF bytecode), which has **no host-architecture
component**: one file runs on x86-64 and aarch64 alike.

```bash
cargo install bpf-linker --version 0.10.4    # PINNED — see below
./scripts/build-ebpf
```

> **Use that exact version.** `bpf-linker` is coupled to an LLVM major
> version, and bare `cargo install bpf-linker` fetches a release wanting
> a newer LLVM than the pinned nightly emits. When it mismatches it does
> not fail — it links happily and silently drops the `.BTF` section,
> producing an object the agent cannot load. `build-ebpf` checks for
> that and refuses.
>
> If the toolchain fights you, don't fix it twice: build the object on
> one machine that works and copy it. It is architecture-neutral.

Without this object the agent still runs, meshes, and answers SQL — and
observes **nothing**. It will alert about its own blindness (§9).

### Raspberry Pis and other ARM nodes

```bash
cargo install cross --git https://github.com/cross-rs/cross    # needs Docker
./deploy/remote/package-agent.sh          # → deploy/remote/dist/*.tar.gz
```

The tarball carries the agent, the CLI, the systemd units, a config
template, the eBPF object, and — where `dpkg-deb` is available on the
build host — a **`.deb`**. `install-agent.sh` prefers the `.deb`, and you
want it to: a binary dropped into `/usr/bin` by `install` is owned by no
package, so the agent's own provenance check scores it as an unpackaged
newcomer. That is not a false positive, it is the detection working on a
badly-deployed binary — ours. Installed through dpkg, the agent stops
reporting its own deploy and starts reporting a *modified* copy of
itself, which is the finding worth having.

`package-agent.sh` refuses to build without the eBPF object, because a
package that silently produces a blind agent is worse than one that
fails.

> **Pi kernels have `CONFIG_BPF_LSM` off.** Process and network
> monitoring work fine. Exec *blocking* cannot, so never set
> `[response] engine = "bpf-lsm"` there — the agent treats a missing
> blocker as a startup error and will refuse to boot.

---

## 3. Operator identity

Do this once, on the machine you will run commands from.

```bash
mkdir -p ~/.bowery && chmod 700 ~/.bowery
bowery key generate --path ~/.bowery/operator.key
bowery key info --path ~/.bowery/operator.key
```

Keep the fingerprint and the base64 pubkey. The pubkey goes into every
agent's config; the private key never leaves this machine.

---

## 4. Install an agent

Native host:

```bash
sudo ./scripts/build-install-operator     # agent + CLI + console + eBPF object, then restarts
```

Remote node, from the tarball:

```bash
scp deploy/remote/dist/bowery-agent-aarch64-unknown-linux-musl.tar.gz node:
ssh node 'tar xzf bowery-agent-*.tar.gz && cd bowery-agent-* && sudo ./install-agent.sh'
```

`install-agent.sh` restarts an already-running service, so it is safe to
re-run for upgrades, and it prints whether kernel monitoring actually
came up.

### `/etc/bowery/agent.toml`

The parts that matter for a new network:

```toml
[mesh]
listen_addr    = "0.0.0.0:9901"
advertise_addr = "100.64.0.5:9901"      # THIS node's routable address
cluster_id     = "prod-eu"              # peers with different ids ignore each other
seeds          = ["100.64.0.4:9901"]    # any one or two existing members

[whisper]
bind_addr      = "0.0.0.0:9902"
advertise_addr = "100.64.0.5:9902"

[operators]
pubkeys_b64 = ["PASTE_YOUR_OPERATOR_PUBKEY"]

[known_neighbors]
enrollment = "tofu"                     # switch to "grant" in §6
```

> **Bind the wildcard, advertise the routable address.** On a tailnet or
> any interface that appears late in boot, binding a specific IP fails
> if the agent starts first. Binding `0.0.0.0` and advertising `100.x`
> is what makes both boot order and peer dialing work.

Nothing above turns detections on — the built-in ones are already
running. `[detection]` exists only to tune them, and every key shown is
the default:

```toml
[detection]
uid_transitions     = true   # root whose parent was not, outside sudo/su/pkexec
discovery_bursts    = true   # several different recon commands from one parent
discovery_window    = "1m"
discovery_threshold = 5      # DISTINCT commands; `id` in a loop never trips it
repeat_window       = "1h"   # fold identical file findings into one alert
beacons             = true   # C2-shaped periodic callbacks to new destinations
mass_writes         = true   # ransomware-shaped write sweeps
peer_liveness       = true   # neighbours report an agent that goes silent
peer_grace          = "5m"   # ...after this long, to survive reboots and upgrades
```

`repeat_window` is what stops one process reading one file from alerting
every time it does so. The repeats are **counted, not dropped**: the next
report says how many it stands for, because "sshd read a host key" and
"sshd read a host key 4,000 times in the last hour" are different events.
Set it to `"0s"` to report every occurrence.

Turn one off only on a host where it is structurally noisy — a build box
whose every script runs `uname` and `dpkg`, say. Unlike `[monitor]`,
which is empty until you write a rule, these are on for a host nobody
configured.

Restart, then collect each node's identity:

```bash
ssh node 'sudo bowery key info --path /var/lib/bowery/identity.key'
```

---

## 5. Tell your CLI about the fleet

```bash
bowery peers add --name web-1 \
  --fp   <fingerprint-hex> \
  --pubkey-b64 <pubkey> \
  --addr 100.64.0.5:9902

bowery peers list
bowery peers check          # dials each; reports reachability
```

The manifest is what turns fingerprints into readable names in output,
and what lets fan-out verify chunks each peer sealed for you directly.

---

## 6. Move to signed enrollment

TOFU is a bootstrap convenience. Once the fleet is up, close it.

```bash
# One grant per agent, minted offline.
bowery trust grant \
  --operator-key ~/.bowery/operator.key \
  --agent-fp <that agent's fingerprint> \
  --cluster-id prod-eu \
  --valid-for 365d \
  --out web-1-grant.b64

scp web-1-grant.b64 node:/tmp/
ssh node 'sudo install -m 644 /tmp/web-1-grant.b64 /var/lib/bowery/grant.b64'
```

Point the agent at it and flip the policy:

```toml
[known_neighbors]
enrollment = "grant"
grant_path = "/var/lib/bowery/grant.b64"
```

**Distribute every grant before flipping any node**, then confirm:

```bash
bowery exec sql --fanout --sql \
  "SELECT fingerprint_hex, grant_state FROM bowery_mesh_peers"
```

Every row should read `valid`. Flipping first and distributing second
partitions the mesh.

Ejecting a host:

```bash
bowery trust revoke --operator-key ~/.bowery/operator.key \
  --agent-fp <compromised> --cluster-id prod-eu --out revoke.b64
```

---

## 7. Everyday commands

All of these take the connection flags
`--operator-key/--agent-addr/--agent-fp/--agent-pubkey-b64`; a shell
alias is worth setting up.

**Query one host, or the whole fleet:**

```bash
bowery exec sql --sql "SELECT pid, name FROM processes WHERE name LIKE '%ssh%'"
bowery exec sql --fanout --sql "SELECT COUNT(*) FROM bowery_baseline_binaries"
```

**Read alerts:**

```bash
bowery alerts tail                 # drain once
bowery alerts tail --follow        # keep watching
```

**The console** — eight panes, live alert tail, SQL REPL, topology map:

```bash
bowery-console
```

**Email alerts when nobody is watching** — see [INSTALL.md](INSTALL.md)
for the Gmail app-password setup and the systemd timer:

```bash
bowery notify --dry-run
bowery notify --dry-run --html-out /tmp/digest.html   # preview the HTML
```

The digest goes out as text *and* HTML; each alert carries its episode
id and a pre-filled `bowery alerts silence` command, so a recurring
false positive can be quieted from the mail itself.

**Check a hash against VirusTotal** (operator-side only; see
[INSTALL.md](INSTALL.md) for the optional `bowery notify` filter):

```bash
bowery vt <sha256>      # exit 0 clean, 1 flagged, 2 unknown/unavailable
```

A lookup discloses to VirusTotal that somebody is investigating that
hash. Adversaries watch VT for their own samples, so for a suspected
targeted implant this is a deliberate decision, not a reflex — which is
why agents never do it and the key lives only on your box.

**Push a YARA rule across the mesh:**

```bash
bowery exec yara --rules ./rule.yar --target /tmp --fanout
```

**Watch the mesh work:**

```bash
bowery exec sql --fanout --verbose-whisper --sql "SELECT 1"
```

Prints every envelope exchanged, named by your manifest, with timings
and a per-agent tally — the fastest way to answer "did all my peers
actually report?". It goes to stderr, so redirecting stdout still gives
a clean result file.

---

## 8. Useful queries

**Don't memorise any of this.** `bowery tables` prints every queryable
table with its columns, plus a set of questions and the query that
answers each; the console's Query pane shows the same reference on its
idle screen (↑↓ scrolls it), and `:schema` / `:schema <table>` asks the
connected agent directly.

A test in `bowery-agent` **runs every example against a real agent**, so
a query that cannot execute fails the build. It also checks the table
list in both directions — an entry naming a table that does not exist,
and a table you can query that nothing documents.

**Start here: has each detection ever actually fired?**

```sql
SELECT rule_id, fired, last_fired_unix_ms FROM bowery_detections ORDER BY fired
```

Every rule the agent knows is a row, including the ones at zero — a
detection that has never fired is a visible `0`, not a missing row. Both
failure shapes show up here and almost nowhere else. A rule stuck at zero
is usually one that *cannot* fire; a rule with an implausibly large count
is one firing on the wrong thing. Six defects were found this way in a
single day, three of each kind.

Two counts, because they answer different questions. `fired` is since
this agent started; `fired_since_install` is the durable total, folded
into the baseline every five minutes and at shutdown. The second is the
one that answers *has this ever fired here* — the first misled twice in
one session, reading as a dead rule when the agent had simply restarted
minutes earlier. `since_unix_ms` says which window `fired` covers.

`fired` really does cover that whole window: the periodic flush folds a
*delta* into the baseline rather than resetting the counter. It did reset
it once, which meant a rule that had fired five hundred times could read
`0` against a three-hour-old `since_unix_ms` — the same "a zero that does
not mean never" this table exists to abolish, reintroduced by the table's
own bookkeeping.


| question | query |
| --- | --- |
| Is every host actually watching? | `SELECT probe, watching, emitted, kernel_drops FROM bowery_probe_status` |
| Is every host running the same sensor? | `SELECT DISTINCT object_sha256 FROM bowery_probe_status --fanout` |
| What is alerting? | `SELECT episode_id, rule_id, suspicion, confirmed, exe_path FROM bowery_alerts` |
| Which rules are producing the noise? | `SELECT rule_id, COUNT(*) FROM bowery_alerts GROUP BY rule_id ORDER BY 2 DESC` |
| What am I not being told about? | `SELECT id, rule_id, weight, matched, reason FROM bowery_silences ORDER BY matched DESC` |

### Which build is running where

Every binary reports its crate version plus the commit it was built
from, and `-dirty` when the tree had uncommitted changes:

```bash
bowery --version            # bowery 0.2.0+2bff539
bowery-agent --version
bowery-console --version
```

The commit is the half that matters. A crate version alone cannot tell
two builds of the same release apart, which is the only question anyone
asks it during a rollout. `-dirty` means the named commit does **not**
describe that binary — treat it as unidentified rather than as that
commit.

The agent gossips this, so fleet-wide skew is one query rather than an
ssh loop:

```sql
SELECT fingerprint_hex, agent_version FROM bowery_mesh_peers
```

Pair it with `SELECT DISTINCT object_sha256 FROM bowery_probe_status
--fanout`, which catches the same skew in the eBPF object.

### When the mesh cannot check something

The neighbourhood watch asks peers whether they have seen a binary's
hash, and a quorum of "never" is what confirms an alert. That question
only means something between hosts that *could* have the same file. The
same program compiled for a different architecture is a different file,
so an aarch64 peer asked about an x86-64 binary has never seen it,
never will, and saying so is not evidence.

Measured on a three-host fleet: the x86-64 host shared **zero** of its
366 baseline hashes with either aarch64 host. Every alert that ran a
round was confirmed, including one on `/usr/bin/dash`.

Questions and answers now carry the sender's platform. A peer that
cannot be compared against goes in its own bucket and never counts
toward a quorum:

```sql
SELECT episode_id, rule_id, confirmed, peers_unseen, peers_incomparable
FROM bowery_alerts
```

A round where nothing could be compared reads as **"could not check"**,
not "not confirmed" — in the console, the digest and the audit trail.
Those are opposite facts and they had been sharing a word. If you see it
constantly, your fleet cannot corroborate itself, and that is worth
knowing before an incident rather than during one.

Ask whether the mesh can corroborate itself at all:

```sql
SELECT platform, COUNT(*) AS peers, SUM(comparable) AS can_compare
FROM bowery_mesh_peers GROUP BY platform
```

`comparable = 0` is not a fault. That peer is reachable, healthy, and
simply on another architecture, so its answers about your binaries
cannot mean anything. Worth knowing before an incident rather than
during one — which is why the platform is gossiped rather than
discovered a round at a time.

Peers that run the same *program* at a different build now say so, and
that answer counts as recognition rather than denial:

```sql
SELECT episode_id, rule_id, confirmed, peers_unseen, peers_familiar,
       peers_incomparable
FROM bowery_alerts
```

Same-architecture is necessary, not sufficient — the two aarch64 hosts
above still share only 5 of ~100 hashes. Narrowing that is what the
remaining slices in `DESIGN-FUZZY-CORROBORATION.md` cover.

### Alert history, and why it is operator-side

An agent's inbox is an in-memory ring with a 72-hour TTL that dies with
the process. It is a delivery buffer, not a record — so "what did this
host alert on last week" was not a missing feature, the data did not
exist. And a record kept only on the machine it accuses is one that
machine's owner can revoke: whoever roots a host can erase every alert
about themselves by waiting three days or restarting a service.

So `bowery notify` and the console both write every alert they poll to
`~/.bowery/alerts.db` as they drain it. That archive is the only view
that outlives an agent.

```bash
bowery alerts history                        # newest verdict per episode
bowery alerts history watchdog               # substring: path, rationale, rule, context
bowery alerts history --agent otter1 --since 7d
bowery alerts history --rule cred.read_aws --confirmed
bowery alerts history --all-versions         # keep superseded verdicts
bowery alerts history --stats                # what the archive covers
bowery alerts history --json                 # one object per line
```

Everything polled is archived — *before* `min_suspicion` and before the
episode collapse. The notification filter says what is worth waking
someone for; the archive says what was observed. Conflating them would
mean raising a threshold silently erases history, and the low-scoring
alert nobody wanted emailed is routinely the one that matters later.

`--all-versions` exists because a verdict *moves*: the pre-filter raises
it, the LLM refines it, a quorum confirms it, corroboration can
downgrade it. "Raised at 0.9, downgraded to 0.3 when four peers said
they all do that" is a different story from "0.3", and only one of them
survives if you keep the last write.

Turn it off with `bowery notify --no-archive`, or point it elsewhere
with `--archive <path>`.

### Silencing a benign alert

```bash
bowery alerts silence <episode-id> \
    --operator-key ~/.bowery/operator.key \
    --agent-addr 100.x:9902 --agent-fp … --agent-pubkey-b64 … \
    --cluster-id my-tailnet \
    --reason "git reads its own netrc" \
    --fanout
```

The episode id is a *handle*, not the thing silenced — it names one
occurrence that will never recur. What gets signed is the rule, the
binary's SHA-256 and the path that alert stands for, and the command
prints that pattern plus **how many alerts it would have covered** before
asking you to confirm. Signing blind is the mistake it exists to prevent:
a pattern one field wider than intended looks identical on the command
line and behaves nothing alike.

Defaults are the narrowest useful thing: this rule, this binary, this
path, every host. `--any-path` widens to the binary anywhere;
`--this-host-only` narrows to the host that raised it. `--any-binary` is
refused unless you pass it explicitly, because a silence that does not
name a binary is inherited by whatever an attacker later writes at that
path.

`--weight 0` silences outright; `--weight 0.3` damps the score, so the
finding still surfaces if something else about the episode is bad enough;
`--weight 1` changes nothing and only counts matches, which is how you
measure a pattern before committing to it.

Every silence expires — 90 days by default, a year at most. Check what is
in force, and what it has swallowed, with the `bowery_silences` query
above.
| Who talked to this endpoint? | `SELECT * FROM bowery_net_destinations WHERE dst_addr = '203.0.113.4'` |
| What happened at 14:32? | `SELECT ts_unix_ms, kind, comm, path FROM bowery_events WHERE ts_unix_ms BETWEEN … ORDER BY seq` |
| Is the history recording? | `SELECT recording, rows, oldest_ts_unix_ms FROM bowery_eventlog_status` |
| What files are being written? | `SELECT comm, path FROM bowery_events WHERE kind='file_open' ORDER BY seq DESC` |
| Who is in the mesh? | `SELECT fingerprint_hex, whisper_addr, pinned, grant_state FROM bowery_mesh_peers` |

Add `--fanout` to any of them to ask the whole fleet at once.

---

## 9. Reading the fleet honestly

Three things routinely confuse people, and all three are the system
being deliberately careful.

**"An agent says it's blind."** It means it. No eBPF object, or the
sensor stopped. Every detection on that host is inactive, and its
whisper answers are worthless as evidence of absence. Check
`bowery_probe_status`; the usual cause is a missing object.

**"Every probe is attached, but a detection never fires."** Check
`object_sha256` across the fleet before suspecting the rule. The agent
and the kernel object install separately, and a host can run a new agent
against a stale object: every probe reports attached and healthy, and
whatever the newer object added is simply absent. This has happened here.
More than one `DISTINCT object_sha256` across hosts you deployed together
means one of them did not take:

```sql
SELECT DISTINCT object_sha256 FROM bowery_probe_status
```

**"Peers `declined` instead of voting."** A peer only answers "never
seen it" once it has observed enough for that to mean anything —
`[whisper.qa] min_baseline_binaries` (64) **and** `min_baseline_age`
(72h). A host that booted yesterday has run a few dozen binaries and
would truthfully report "never seen it" about nearly everything you run,
which is youth, not rarity. New nodes abstain for three days and then
join in on their own.

**"An agent alerts on ordinary binaries."** A first execution scores
high by design — rarity is a real signal. Two things should be damping
it: package provenance (a distro binary that still matches its package
drops to 15%) and, optionally, VirusTotal screening in `bowery notify`.
If you are still seeing `/usr/bin/nice` at 1.00, check the agent logged
`package provenance index loaded executables=N` at startup; without that
line the index did not load and nothing is being damped.

What remains after both is a binary that is **rare here, not owned by
any package, and unknown to the industry** — which is a much shorter
list, and the one worth reading.

---

## 10. Adding a host later

1. Install the agent and eBPF object (§2, §4).
2. Set `cluster_id` to match and `seeds` to any existing member.
3. Mint and install its grant (§6).
4. `bowery peers add` on your workstation (§5).
5. Confirm: `bowery peers check` and the `bowery_probe_status` query.
6. Wait three days before its whisper votes count. It is watching and
   alerting the whole time — it just doesn't vote on other hosts'
   findings until its own baseline means something.
