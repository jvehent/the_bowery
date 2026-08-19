# Fuzzy corroboration — making the neighbourhood watch mean something

**Status:** slices 1–3 implemented; slices 4–6 proposed.

## 1. The finding

The neighbourhood watch asks peers one question — *"have you seen the
artifact whose sha256 is X?"* — and treats a quorum of "no" as
confirmation that the artifact is anomalous.

Measured on the live fleet on 2026-08-19:

```
baseline binaries:  otter1 366   legolas 100   dartagnan 107
shared hashes:      otter1 ∩ legolas    = 0
                    otter1 ∩ dartagnan  = 0
                    legolas ∩ dartagnan = 5
                    all three           = 0
```

otter1 is x86-64; legolas and dartagnan are aarch64. Cross-architecture
the intersection is not small, it is **empty**, and it is empty for
reasons that have nothing to do with security. Even between the two
same-architecture Pis it is 5 of ~100.

So the answer to "has anyone else seen this hash" is *no* for every
binary on the fleet, including `/bin/sh`. With the default `quorum: 2`,
every alert that runs a round and reaches two responsive peers is
confirmed. The first confirmed alert in the new archive was:

```
CONFIRMED 2/2  privesc.uid_transition_no_helper  /usr/bin/dash
```

`/usr/bin/dash` is on every host in the fleet. The mesh said no one had
ever seen it, and the mesh was telling the literal truth.

**The confirmation signal carries no information.** It is not weak, it
is structurally vacuous — and it is worse than absent, because the
console highlights confirmed alerts, the digest leads with them, and an
operator learns to trust a word that means nothing.

### This is the `refused` bug's structural sibling

`Answer.refused` exists because two agents with dead event sources had
empty baselines and answered `seen_count: 0` to everything, confirming
every alert on their neighbour. The fix let a responder say *"I have
observed too little for my 'no' to mean anything."*

That fix addressed **"I am not watching."** It does nothing for **"I am
watching a different architecture."** These baselines are not empty.
They are full, healthy, and incomparable. The responder has no way to
say *"I cannot compare myself to you on this axis"*, so it says "no",
and "no" is read as evidence.

The general defect: **the system answers a question it cannot answer,
and answers it in the alarming direction.**

## 2. What the agent would need, and does not have

```sql
-- bowery_baseline_binaries, actual schema
sha256_hex, first_seen_unix, last_seen_unix, seen_count
```

The baseline is keyed on the hash and records **nothing else** — no
path, no size, no package, no ELF metadata. An agent literally cannot
answer "do you have the same program at a different hash", because it
does not record which program a hash was.

Any fuzzy scheme therefore needs a **descriptor** before it needs a
protocol. That ordering matters: adding comparison logic to a store
that has nothing to compare would produce the same vacuous answer more
expensively.

## 3. Design

### 3.1 Answers become evidence vectors, not booleans

A responder returns, per dimension, one of `Match` / `Differ` /
`Absent` / `Cannot-compare`, plus what it compared against.

The fourth state is the whole point. `Cannot-compare` is what an
aarch64 host must return when asked about an x86-64 build, and it must
propagate all the way to the verdict as *"this question was not
answerable here"* — never as evidence of rarity.

Proposed dimensions for an executable, cheapest first:

| dimension | signal when it matches | cost |
|---|---|---|
| `sha256` | identical build | free (already have it) |
| `path` | same program installed | needs the path in the baseline |
| `basename` | same program, relocated | free once path exists |
| `pkg name+version` | same distro artifact — **survives arch** | dpkg/rpm query, cached |
| `elf.build_id` | same build inputs | one read of `.note.gnu.build-id` |
| `elf.needed` | same library dependency set — largely arch-independent | ELF parse, cached |
| `elf.machine/class` | tells the two hosts they are comparable **at all** | ELF parse |
| `size class` | weak, but cheap and non-zero | stat |

`pkg name+version` and `elf.needed` are the two that cross the
architecture boundary, which is exactly where today's scheme fails.
`elf.machine` is what lets a responder say `Cannot-compare` *honestly*
rather than guessing.

### 3.2 The verdict becomes graded, with an explicit unknown

```rust
enum Corroborated {
    /// Peers positively recognise this. Downgrade.
    Familiar { score: f32, basis: Vec<Dimension> },
    /// Peers compared on axes that work here and found nothing. Evidence.
    Anomalous { score: f32, basis: Vec<Dimension> },
    /// No peer could compare. NOT evidence, and must be said out loud.
    Incomparable { reason: &'static str },
}
```

`Incomparable` must be visible in the alert, the SQL view and the
digest. A fleet where corroboration cannot work should *say so
continuously*, the same way `bowery_probe_status` distinguishes quiet
from blind. Otherwise this whole feature reverts to decorative the next
time someone adds a host of a different shape.

The rule that replaces `peers_unseen >= quorum`:

- Confirmation requires **positive comparability** — at least one peer
  that could compare on at least one dimension — before any count of
  denials means anything.
- A match on a *strong* dimension (pkg identity, build-id) explains the
  finding even if the hash differs. This is the case that is 100%
  mishandled today.
- Denials only count from peers that established comparability.

### 3.3 Generalising beyond binaries

The generic `Claim` / `Audience` / `Rule` framework in
`corroboration/` is already the right shape — opaque `kind` + attribute
subject, per-kind responder, tally, superseding alerts. It should
absorb the binary case, which currently lives in the older, separate,
exact-match `whisper_qa.rs` path.

The change to the framework is to replace the three-bucket
`Corroboration` answer with the evidence vector above, and to let each
responder declare which dimensions it can speak to. Then:

| claim kind | fuzzy question |
|---|---|
| `bin.identity` (new; replaces the tier-1 Q&A) | same program, any build? |
| `file.access` (exists) | does *your* copy of this software touch this path? — currently exact-path |
| `net.destination` | does anyone reach this ASN/domain, not just this IP? |
| `lineage.pair` | does this parent→child shape occur anywhere, by program identity rather than hash? |
| `persist.unit` | does an equivalent unit/cron entry exist elsewhere? |
| `privesc.setid` | do peers have a set-id binary at this path, and is theirs packaged? |

`privesc.uid_transition_no_helper` — the rule that fired 206× in a
fortnight and produced the vacuous `dash` confirmation — becomes
answerable: *"do your hosts also transition to root from this program,
by package identity?"*

### 3.4 Privacy and abuse

Richer descriptors leak more. Constraints:

- Peers are already pinned and authenticated; `file_access` already
  sends real paths, so this is not a new class of disclosure.
- Descriptors must be **derived, not raw**: send `pkg:coreutils@9.4-3`
  and hashed `DT_NEEDED` sets, not file contents.
- A responder still decides what it will answer, per dimension. The
  existing rate limits and TTL apply unchanged.
- A compromised agent asking many questions is a fleet-enumeration
  oracle. The existing per-sender bucket bounds it; the wider
  descriptor raises the value of that bound, so it should be tightened
  and per-dimension.

## 4. Sequencing

Each slice is useful alone and none breaks the wire format
irreversibly.

1. ~~**Say `Incomparable` out loud.**~~ **Done.** `Question` carries
   `asker_platform`, `Answer` carries `platform`, and a peer on a
   different platform is classified `PeerReply::Incomparable` — a
   fourth bucket that never counts toward a quorum. An unknown platform
   (a peer too old to say) is treated as incomparable, which is the
   safe direction: the cost is a confirmation that does not happen
   rather than an alert that is not raised.

   Surfaced everywhere a verdict is read: `bowery_alerts.peers_incomparable`,
   the console detail (`COULD NOT CHECK (no comparable peer)`), the
   digest (amber `NOT CHECKED`, not grey "not confirmed"), the archive,
   and `Dropped::NotComparable` in the audit trail. A round that could
   compare nothing also warns every time, because the only moment
   anyone would otherwise notice is during an incident.
2. ~~**Give the baseline a descriptor.**~~ **Partly done.** A
   `binary_descriptors` table records path, size, owning package name
   and platform per hash, written once on first sight so the per-exec
   upsert stays a two-column write. `bowery_baseline_binaries` gained
   those columns, so the view can finally say *which program* a hash
   was.

   Package name comes free from the `.md5sums` filename the provenance
   index already reads, with the architecture qualifier stripped —
   `coreutils`, not `coreutils:amd64` — because an identity meant to
   cross architectures must not carry one. `Baseline::hashes_for_package`
   and `hashes_for_path` are the lookups a responder needs.

   NULL means *not recorded*, never *not packaged*: the package index
   loads asynchronously, so a write during startup can legitimately not
   know, and a later write never clears a known package with NULL.

   **Still outstanding for this slice:** package *version*, build-id and
   `DT_NEEDED` — all three need either `/var/lib/dpkg/status` parsing or
   an ELF reader, and neither belongs on the exec path without
   measurement first.
3. ~~**Evidence-vector answers.**~~ **Done for package + path.** The
   question now carries `pkg` and `exe_path` alongside the tier-1
   fingerprint, and the answer carries `pkg_match`, `pkg_builds` and
   `path_match`. A peer that lacks the file but has the program replies
   `PeerReply::Familiar`, which is neither a sighting nor a denial and
   never counts toward a quorum.

   Measured on the reference fleet the day this landed: three hosts
   share **zero** binary hashes across x86-64/aarch64 and **seven**
   packages — `bash`, `coreutils`, `dash`, `systemd`, `openssh-server`,
   `debianutils`, `bowery-agent`. Every one of those was previously
   unrecognisable to every peer.

   Package before path, and path never explains a finding on its own: a
   package is an identity the distribution assigned, a path is a
   location an attacker picks.

   A responder answers from **two** sources: its descriptor store (what
   it has run) and its package database (what is installed). The second
   was added after the first live round exposed the gap — a peer asked
   about `/usr/bin/hostname` had the file and had never executed it, so
   it answered "never seen it". `pkg_builds: 0` alongside `pkg_match`
   is the honest distinction between "we run this too" and "we have it
   on disk".

   A recognised program **supersedes its alert at a lower score**,
   reusing the downgrade shape the `file.access` corroboration already
   had. Without it the answer was discarded: only a confirmation
   superseded, so a round ending in recognition left the alert with
   `confirmation: None` and every peer column NULL. Damping is
   proportional to how much of the neighbourhood recognised it and
   never reaches zero — recognition says the *program* is fleet-normal
   and says nothing about whether this copy is intact, which is
   provenance's job.

   Still on the evidence-vector list: build-id and `DT_NEEDED`, both of
   which need an ELF reader.
4. **Retire `whisper_qa.rs`'s exact-match path** once (3) covers it.
5. **Port the other kinds** to fuzzy dimensions, one per slice.
6. ~~**Operator surface.**~~ **Done.** `peers_incomparable` and
   `peers_familiar` in `bowery_alerts`, distinct wording in the console
   and the digest, and the platform gossiped so
   `bowery_mesh_peers.platform` / `.comparable` answer "can this mesh
   corroborate itself" without running a round.

## 5. What I would not do

- **Not** ML/embedding similarity. The dimensions above are explainable
  and an operator can act on "same package, different build". A cosine
  score is not something anyone can argue with at 03:00.
- **Not** fuzzy hashing (ssdeep/TLSH) as the primary signal. It answers
  "are these bytes similar", which for two independent compilations of
  the same source is often *no* — the same trap one level down. Worth
  having as one weak dimension, not as the mechanism.
- **Not** treating `Incomparable` as mildly suspicious. It is the
  absence of a measurement.

## 5a. Where mesh evidence is applied

Several paths append a superseding alert for one episode and the last
one wins at display time. The whisper round knows what the
neighbourhood said; the LLM refinement knows what the model said;
neither waits for the other. Arrival order decided the outcome, which
meant a recognition downgrade was silently undone by a refinement that
re-scored from the pre-filter.

Both halves are now applied at the **inbox**, the one place every alert
passes through:

- The verdict is carried forward onto a later alert that has none. An
  alert saying nothing about the mesh is not asserting the mesh said
  nothing — it did not ask.
- The score is damped there too, so it reaches every writer for the
  episode rather than only the round that discovered the recognition.

Rescoring at append is not novel here: silences already work this way,
for the same reason.

The damp is idempotent — an alert passes through once as itself and
again as an inherited verdict, and compounding turns a 0.75 into 0.12,
which is a suppression nobody asked for. The explanatory note is also
the marker that it has already run.

What remains open is whether the *model* should see the mesh verdict
and weigh it directly, rather than having the damp applied around it.
That needs `bowery-llm` to know the type, and it is a genuine question
about where judgement belongs rather than a missing patch.

## 6. Open questions

- Does `quorum` stay a count, or become a confidence threshold? A count
  is explainable; confidence composes better across dimensions.
- Should an agent publish its descriptor set in gossip (bloom-style) so
  askers can skip peers that cannot compare, rather than asking and
  being told? Cheaper, but leaks the fleet's software inventory more
  broadly than point-to-point questions do.
- How far back should comparability be recomputed — is a peer that
  *used* to run this program a corroborator?
