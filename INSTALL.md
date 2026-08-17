# Installing The Bowery

> **Status:** Phase 0 → 10 complete, plus the operator console,
> operator-configurable monitoring (`[monitor]`), and YARA rule
> distribution. The agent observes process exec / exit and outgoing TCP
> connects via eBPF, pins peers over QUIC mTLS, gossips role vectors,
> corroborates suspicious episodes with similar peers, answers operator
> SQL (with mesh fan-out), watches operator-specified files, runs
> distributed YARA rules, and surfaces alerts to roaming operators over
> a signed `Subscribe` flow. A response engine exists (`block_exec` /
> `kill_process`); enforcement is opt-in and off by default —
> `[response] mode = "off"` ships as the default, so an agent is
> observe-only until you turn it on. `mode = "dry-run"` is the middle
> step: every gate runs, nothing touches the host, and the audit log
> records what arming it *would* have done.

---

## 1. Requirements

### 1.1 Kernel

| Requirement | Why |
|---|---|
| Linux ≥ 5.13 (5.7 minimum) | BPF-LSM hooks for KRSI |
| `CONFIG_BPF_LSM=y` | LSM-BPF program type |
| `CONFIG_DEBUG_INFO_BTF=y` | CO-RE — eBPF programs portable across kernels |
| `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y` | core BPF |
| `bpf` listed in active LSMs | the kernel's `lsm=` cmdline includes `bpf` |
| `bpffs` mounted at `/sys/fs/bpf` | BPF objects need somewhere to be pinned |

Run `bowery doctor` on each candidate host (instructions below). Exit code
0 means ready, 1 means not.

### 1.2 Distros that work out of the box

| Distro | Default kernel ready? |
|---|---|
| Ubuntu 22.04, 24.04 | yes |
| Debian 12 (bookworm) | yes |
| RHEL / Rocky / Alma 9 | yes |
| Fedora ≥ 36 | yes |
| Amazon Linux 2023 | yes |
| Bottlerocket | yes |
| **RHEL 8** | no — `CONFIG_BPF_LSM` not enabled |
| **Amazon Linux 2** | no — kernel too old |
| **Raspberry Pi OS / Raspbian** (stock `linux-rpi-*`) | no — `CONFIG_BPF_LSM` not enabled |
| **WSL2 default kernel** | no — securityfs / BPF-LSM not exposed |

If your target distro isn't ready, options are:
- **Switch to a stock distro kernel** (Pi: `apt install linux-image-arm64` on Bookworm; loses Pi-specific drivers).
- **Build a custom kernel** with the required `CONFIG_*=y` options. ~hours on weaker hardware.
- **Run a Linux VM and drive it remotely** — see [docs/REMOTE_TESTING.md](docs/REMOTE_TESTING.md) for the
  `scripts/xtest` driver that pushes builds to a VirtualBox VM via SSH.
- **Move to a different host** for development; treat the unready box as a *candidate deployment target* you'll validate later.

### 1.3 Build host

| Requirement | Notes |
|---|---|
| Rust ≥ 1.85 (edition 2024) | `rust-toolchain.toml` pins 1.95.0 — `rustup` honours it |
| C compiler (cc, gcc, or clang) | `bowery-baseline` builds bundled SQLite from C source |
| ~600 MB free disk for `target/` | release build is ~20 MB total |
| `git`, `cargo` | standard |

To bootstrap a fresh host:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
  | sh -s -- -y --default-toolchain stable --profile minimal
. "$HOME/.cargo/env"
sudo apt install -y build-essential pkg-config   # Debian/Ubuntu
# or:
sudo dnf groupinstall -y 'Development Tools'     # RHEL/Fedora
```

---

## 2. Quick check: is this host ready?

After building (next section) you can run:

```bash
./target/release/bowery doctor
```

Sample output on a ready host:

```
== Bowery host readiness ==

  PASS kernel version  6.1.0-37-amd64
  PASS BTF             /sys/kernel/btf/vmlinux (5928712 bytes)
  PASS BPF-LSM active  capability,lockdown,yama,bpf
  PASS bpffs           mounted at /sys/fs/bpf
  PASS boot lsm= flag  lsm=lockdown,yama,bpf
  PASS kernel config   4/4 required options enabled

Result: ready
```

`bowery doctor --json` produces a structured report for fleet sweeps. Exit
code is 0 when ready (warnings allowed) and 1 when one or more checks
fail.

---

## 3. Building from source

```bash
git clone https://github.com/jvehent/the_bowery
cd the_bowery
cargo build --release
```

Output binaries:

| Binary | Purpose |
|---|---|
| `target/release/bowery-agent` | the daemon, runs on every protected host |
| `target/release/bowery` | operator CLI; also useful on agent hosts for `bowery doctor` |

Run the test suite:

```bash
cargo test --workspace
```

~330 tests should pass. The most informative end-to-end tests are:
- `two_agents_discover_pin_and_heartbeat` — chitchat + TOFU pinning +
  QUIC mTLS + signed envelopes
- `high_suspicion_exec_triggers_whisper_round_and_aggregates_beta_sighting`
  — Phase-5 whisper Q&A round driven by a real `ProcessExec` event
- `high_suspicion_exec_appears_in_operator_inbox_via_subscribe` —
  Phase-6a alert inbox + signed `Subscribe`

Each runs in seconds; run the full suite with `cargo test --workspace`.

---

## 4b. Optional: real Qwen3-0.6B inference (LLM analyzer)

By default the agent ships with a deterministic mock LLM backend, which
is fine for plumbing tests but doesn't write rationales or recommend
nuanced actions. To get real inference, build with `--features
llm-llama-cpp` and provide a Qwen3-0.6B GGUF.

### Prerequisites

The feature pulls in `llama-cpp-2`, which compiles `llama.cpp` from
source at build time. You need:

- `cmake` ≥ 3.16
- A C++17 compiler (`g++`/`clang++`)
- ~2 GB RAM during the build, ~600 MB resident at runtime

`scripts/xtest setup` installs cmake + clang on the remote target. On
the local build host: `apt install -y cmake clang build-essential`.

### Get the model

Use the CLI's curated registry:

```sh
bowery model list
bowery model fetch qwen3-0.6b-q4_k_m
# downloads to ~/.bowery/models/qwen3-0.6b-q4_k_m.gguf and prints the
# config snippet to copy into agent.toml.
```

For a system-wide install, point `--out` at the agent's state dir:

```sh
sudo install -d -m 0755 -o bowery -g bowery /var/lib/bowery/models
sudo -u bowery bowery model fetch qwen3-0.6b-q4_k_m \
    --out /var/lib/bowery/models
```

`fetch` validates the GGUF magic + size before declaring success; if
the URL ever returns an HTML error page (we hit this once when
HuggingFace renamed the upstream repo), the validator catches it and
the partial download is removed. The agent never downloads at runtime
or compile time — it only reads from the configured `model_path`.

A signed-manifest fetcher (DESIGN.md §10) lands in a follow-up; for
now the registry is hardcoded in source and bumped via code review.

### Build the agent with the feature

```sh
cargo build --release --features llm-llama-cpp -p bowery-agent
```

First build adds ~60 seconds for `llama.cpp` itself; incremental
builds after that are fast.

### Configure

In `/etc/bowery/agent.toml`, add a `[llm.llama_cpp]` block:

```toml
[llm]
invocation_threshold = 0.7

[llm.llama_cpp]
model_path = "/var/lib/bowery/models/qwen3-0.6b-q4_k_m.gguf"
n_ctx = 4096
n_threads = 0       # 0 = llama.cpp default
n_gpu_layers = 0    # 0 = pure CPU; CPU is plenty for 0.6B
max_tokens = 256
temperature = 0.2   # low temp keeps JSON output stable
```

Without the `llama_cpp` block, the agent uses the mock backend even
when the feature is compiled in.

### Verify

Start the agent. Look for:

```
INFO bowery_agent: loading Qwen3 GGUF via llama-cpp ...
INFO bowery_llm::llama_cpp: loading Qwen3 GGUF (this is slow)
INFO bowery_agent::agent: agent ready ... llm_backend=llama-cpp/qwen3-0.6b
```

Trigger a `ProcessExec` event with suspicion above
`invocation_threshold` (e.g. exec something from `/tmp`); the agent
emits an `LlmVerdict` log line with the model's rationale.

### Resource budgeting

- Cold-start: 1–3 seconds to load the GGUF
- Inference: ~50–200 tokens/s on a single modern x86_64 core
- A typical Bowery prompt + response is ~700 tokens → 5–15 seconds per
  invocation. The Phase 4 inference queue caps backlog at 32 by
  default and sheds the deadline (10s); tune both in `[llm]` if your
  hardware is slower.

## 4a. Building the eBPF programs (Linux + KRSI hosts)

The kernel-side programs live in `crates/bowery-ebpf/` and compile to
the `bpfel-unknown-none` target. They're a separate Rust workspace
(see [crates/bowery-ebpf/Cargo.toml](crates/bowery-ebpf/Cargo.toml))
because the BPF target needs nightly + `bpf-linker` + the unstable
`build-std` feature.

The agent loads the resulting object at startup. If it isn't found,
the agent runs without kernel events (mesh + heartbeat continue to
work), so this step is technically optional for an isolated host but
required for the actual EDR signal.

Prerequisites (`scripts/xtest setup` does this on the remote target,
otherwise install manually):

```sh
# The eBPF crate PINS its nightly in crates/bowery-ebpf/rust-toolchain.toml
# (rustup auto-installs it on build). bpf-linker is coupled to an LLVM
# major version, so a floating nightly silently breaks the build — see the
# note in that file. Install bpf-linker so it can load the matching LLVM:
cargo install bpf-linker
```

> **The LLVM version must match.** `bpf-linker 0.10.4` needs **LLVM 22**
> (`llvm-sys 221`), which is why the toolchain is pinned to a nightly that
> ships LLVM 22.1. `bpf-linker` loads that LLVM either from a system
> install (`apt install llvm` when it's v22) or from the toolchain via
> `rustup component add rustc-dev llvm-tools`. If the toolchain's
> `libLLVM-<ver>.so` is a GNU-ld `INPUT(...)` stub rather than a symlink to
> the real `libLLVM.so.*`, recreate it as a symlink. `build-ebpf` verifies
> the resulting object actually carries a `.BTF` section and fails loudly
> otherwise.

Build:

```sh
./scripts/build-ebpf
# → crates/bowery-ebpf/target/bpfel-unknown-none/release/bowery-ebpf
```

At runtime the agent looks for the object in this order:

1. `/usr/local/lib/bowery/bowery-ebpf`
2. `/usr/lib/bowery/bowery-ebpf`
3. `$BOWERY_BPF_OBJ_PATH` (env var) — only honored when
   `BOWERY_BPF_DEV_MODE=1` is also set; production agents reject the
   override.

Each candidate path is integrity-checked (Phase-8 H8) and rejected
unless: it exists as a regular file (not a symlink), is owned by
uid 0, and has mode `0o644` or stricter (no group/world write).
The cwd-relative dev fallback was removed — `xtest run-agent` sets
both `BOWERY_BPF_DEV_MODE` and `BOWERY_BPF_OBJ_PATH` so the
in-tree build still works for development.

For production install:

```sh
sudo install -d -m 0755 /usr/local/lib/bowery
sudo install -m 0644 -o root -g root \
    crates/bowery-ebpf/target/bpfel-unknown-none/release/bowery-ebpf \
    /usr/local/lib/bowery/bowery-ebpf
```

The agent needs `CAP_BPF` + `CAP_PERFMON` (or root) at runtime to load
the program. The shipped systemd unit grants these.

## 4. Installing the agent (root)

> **Remote / cross-arch node (e.g. a Raspberry Pi over Tailscale)?**
> Use the turnkey kit in [`deploy/remote/`](deploy/remote/README.md):
> `package-agent.sh` cross-compiles a tarball on your laptop and
> `install-agent.sh` sets up the user, systemd unit, and config on
> the node. The steps below are the manual, same-arch equivalent.

```bash
# 4.1 Dedicated user/group
sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin bowery

# 4.2 Binary
sudo install -m 0755 target/release/bowery-agent /usr/local/bin/bowery-agent
sudo install -m 0755 target/release/bowery       /usr/local/bin/bowery

# 4.3 Config
sudo install -d -m 0755 /etc/bowery
sudo install -m 0644 deploy/agent.toml.example /etc/bowery/agent.toml

# 4.4 State directories (owned by the bowery user)
sudo install -d -m 0750 -o bowery -g bowery /var/lib/bowery
sudo install -d -m 0750 -o bowery -g bowery /var/log/bowery

# 4.5 systemd unit + slice
sudo install -m 0644 deploy/systemd/bowery-agent.service /etc/systemd/system/
sudo install -m 0644 deploy/systemd/bowery.slice         /etc/systemd/system/
sudo systemctl daemon-reload
```

---

## 5. Configuration

Edit `/etc/bowery/agent.toml`. The example ships with sane defaults; the
full surface as of Phase 6a:

```toml
[identity]
path = "/var/lib/bowery/identity.key"

[known_neighbors]
path             = "/var/lib/bowery/known_neighbors.json"
bootstrap_window = "2h"
max_pinned_peers = 1024

[mesh]
listen_addr = "0.0.0.0:9901"
seeds       = ["seed1.internal:9901", "seed2.internal:9901", "seed3.internal:9901"]
cluster_id  = "prod-us-east"
# advertise_addr = "10.0.5.7:9901"   # gossip addr peers use; set if listen != dialable

[whisper]
bind_addr = "0.0.0.0:9902"
# advertise_addr = "10.0.5.7:9902"   # whisper dial addr peers use for fan-out;
                                     # set when bind_addr is a wildcard (0.0.0.0)

# Phase 5 — neighborhood Q&A
[whisper.qa]
threshold      = 0.6        # suspicion at which we ask peers
fanout         = 5          # number of role-similar peers per round
timeout        = "5s"
min_similarity = 0.0        # cosine cutoff; raise for stricter neighborhoods
quorum         = 2          # peers that must report NEVER SEEN to confirm
                            # an alert (0 disables confirmation)
max_concurrent_rounds = 4   # Q&A rounds in flight; extras are shed
# Standing to answer "never seen it". A peer below EITHER bound refuses,
# and a refusal never counts toward a quorum.
min_baseline_binaries = 64  # distinct binaries observed. A floor against a
                            # just-booted agent (an empty baseline answers
                            # "never seen it" to everything and unanimously
                            # confirms every alert its neighbours raise).
min_baseline_age = "72h"    # how long the baseline has been accumulating.
                            # This is the bound that matters. A host that
                            # has watched for 19 hours has run a few dozen
                            # binaries and truthfully reports "never seen
                            # it" about nearly everything its neighbours
                            # run — youth, not rarity. Observed live:
                            # two 19-hour-old agents quorum-confirmed
                            # /usr/bin/nice and /usr/bin/pkexec as
                            # anomalies. Set either to 0 to disable it.

# Cross-host corroboration — asking the mesh to account for something
# this host saw but cannot judge alone. Today that means "did you
# connect to me?"; the mechanism is generic and gains new questions by
# registering a handler, not by changing these knobs.
[whisper.corroboration]
enabled        = true
timeout        = "5s"       # per-peer deadline for one query
half_window    = "5m"       # how far either side of the observation the
                            # peer searches. Wide on purpose: too NARROW
                            # produces false denials (the peer really did
                            # connect, but its clock disagrees), and a
                            # false denial is an accusation. Too wide only
                            # suppresses an alert. Capped at 10m total by
                            # the responder regardless.
dedup_window   = "5m"       # same claim isn't asked twice inside this.
                            # Decides whether a port scan costs one round
                            # or one per probe.
dedup_entries  = 4096
queue_capacity = 256        # claims buffered; over-full sheds, never blocks
max_concurrent_rounds = 4
suspicion      = 0.85       # stamped on an alert a round confirms

[heartbeat]
interval = "30s"

# Mesh trust (Phase 3). `enrollment` decides how a peer earns a pin.
#   tofu  — pin anything seen gossiping during the bootstrap window.
#           Gossip is unauthenticated UDP, so under tofu "can reach
#           port 9901 during the window" IS the admission control.
#   grant — pin only peers presenting an operator-signed membership
#           grant naming their own fingerprint and this cluster.
# Default is tofu so upgrading an existing fleet doesn't partition it.
# See "Migrating to signed enrollment" below before flipping it.
[known_neighbors]
path       = "/var/lib/bowery/known_neighbors.json"
enrollment = "tofu"
# grant_path = "/var/lib/bowery/grant.b64"   # required under "grant"
revocations_path = "/var/lib/bowery/revocations.b64"

[baseline]
path = "/var/lib/bowery/baseline.db"

# Append-only local history — what the SQL surface queries to answer
# "what happened on this host between 14:20 and 14:40?".
[eventlog]
enabled  = true
path     = "/var/lib/bowery/events.db"
retention = "7d"            # age bound; "0s" disables
max_rows = 500_000          # hard ceiling, oldest-first (~100 MB at
                            # ~200 B/row). This is the bound that
                            # actually protects a small disk — an exec
                            # storm can write more in an hour than a
                            # quiet week. On an SD-card-backed Pi,
                            # consider lowering it.
maintenance_interval = "5m" # retention + WAL checkpoint cadence
queue_capacity = 4096       # in-flight buffer; when full, events are
                            # DROPPED rather than stalling the pipeline,
                            # and counted in bowery_eventlog_status

[role]
publish_interval = "60s"

[llm]
invocation_threshold = 0.5
queue_capacity       = 32
request_deadline     = "10s"

# Optional: real Qwen3-0.6B inference (only loaded when the agent was
# built with --features llm-llama-cpp). Without this block, the
# default mock backend stands in.
[llm.llama_cpp]
model_path  = "/var/lib/bowery/models/qwen3-0.6b-q4_k_m.gguf"
n_ctx       = 4096
n_threads   = 0       # 0 = llama.cpp default
n_gpu_layers = 0
max_tokens  = 256
temperature = 0.2

# Phase 6a — operator I/O
[operators]
# Base64 of each authorised operator's 32-byte verifying key. Get the
# value from `bowery key generate --out …` or `bowery key info`.
pubkeys_b64 = [
    "8KChxFSe2t0i91xtXDj7swk0QYL1cOCXGea3cx5kaqQ=",
]

[inbox]
capacity  = 10000   # ring size; FIFO eviction at capacity
retention = "72h"   # TTL on individual alerts (lazy sweep)

[alerts]
threshold = 0.7     # suspicion at which a verdict becomes an Alert

# Response. Two separate questions, deliberately not one knob:
#   mode   — WHETHER this agent may change the host
#   engine — HOW it would, if it may
# Naming an engine does not arm anything. An upgrade must never arm
# enforcement on your behalf, so `off` is the default.
[response]
mode   = "off"          # off | dry-run | enforce
engine = "noop"         # noop | process-kill | bpf-lsm
# policy_path    = "/etc/bowery/response-policy.toml"   # deny-all by default
# audit_log_path = "/var/log/bowery/actions.jsonl"      # signed, one line per action
#
# In the policy file, `require_corroboration = ["kill_process"]` holds a
# listed action until the whisper round for its episode confirms — the
# k-of-n half of DESIGN.md's "standing authorization OR peer agreement".
# It defaults to EMPTY on purpose: corroboration can only come from
# peers, so on a single-node install, a partitioned host, or an episode
# below the whisper threshold none is ever coming, and an operator who
# had deliberately armed enforcement would find it silently inert. A
# held action that is never confirmed is dropped and recorded as
# suppressed with the reason, never silently forgotten.
#
# `dry-run` is the step to take before `enforce`: every gate runs, the
# host is never touched, and each action is recorded as `would_execute`
# — NOT as `suppressed`, which means a gate refused it. Read the audit
# log (or `SELECT * FROM bowery_audit`) for a week; if it names nothing
# you would not have wanted done, arming is an informed decision rather
# than a leap.

# Built-in behavioural detections. Unlike [monitor] below, these are ON
# for a host nobody configured — the block exists to tune them, and every
# value shown is the default. Turn one off only where it is structurally
# noisy (a build box whose every script runs `uname` and `dpkg`).
[detection]
uid_transitions     = true   # a process running as root whose parent was not,
                             # outside the sanctioned sudo/su/pkexec path. The
                             # exemption is anchored on package provenance, not
                             # on a name — a binary *called* sudo that no
                             # package owns is the finding, not the exemption.
discovery_bursts    = true   # several DIFFERENT recon commands from one parent
discovery_window    = "1m"
discovery_threshold = 5      # distinct commands; `id` in a loop never trips it
peer_liveness       = true   # report a peer that stops gossiping while others remain
                             # visible. A host cannot report its own death; its
                             # neighbours can, and `systemctl stop bowery-agent`
                             # otherwise defeats every detection silently.
peer_grace          = "5m"   # how long a peer may be missing first. Sits on top of
                             # chitchat's failure detector and is sized to cover a
                             # reboot and an agent upgrade.
repeat_window       = "1h"   # fold an identical file finding (same rule, same path,
                             # same reader binary) into one alert per window. Repeats
                             # are COUNTED, not dropped: the next report says how many
                             # it stands for. "0s" reports every occurrence.

# Operator-configurable monitoring (both lists default empty = feature off).
# Query the effective rules with: SELECT * FROM bowery_monitor_rules
[monitor]

# Watch specific files. A matching change ALWAYS alerts (you asked to be
# told), with `severity` setting the alert's suspicion. Userspace inotify:
# no extra capabilities, but observe-only and no pid attribution.
[[monitor.file_rules]]
id       = "sudoers"                            # optional; defaults to the basename
path     = "/etc/sudoers"
ops      = ["modify", "attrib", "delete", "move"]   # this is also the default set
severity = "high"                               # info | low | medium | high

# Operator process detections, layered onto the built-in rules. Every
# matcher you set must hit (AND). A rule with no matchers is rejected at
# startup (it would fire on every exec).
[[monitor.process_rules]]
id         = "netcat-reverse-shell"
exe_prefix = "/usr/bin/nc"    # exe_path starts with
comm       = "nc"             # task->comm exact match
arg_substr = "-e"             # any argv element contains
severity   = "high"           # high (0.9) clears the default alerts threshold
```

Notes:

- **File watches are directory-based under the hood** — the agent watches
  the file's parent directory and filters by name, so atomic-replace edits
  (write temp + `rename()`, what most editors and package managers do) are
  caught, not just in-place writes.
- **Process rules feed the analyzer**, so they compose with baseline
  novelty and obey `[alerts] threshold` via their severity weight
  (high 0.9, medium 0.6, low 0.3, info 0.1). File rules bypass the
  threshold by design.
- Rules are loaded once at startup; changing them needs a restart. The
  same is true of `[detection]`.
- **What the built-in detections do and do not cover** is in
  [`docs/ATTACK-COVERAGE.md`](docs/ATTACK-COVERAGE.md), generated from
  the rule tables so it cannot claim coverage the code does not have.

### Sizing notes

- `[mesh] seeds`: 3–5 well-connected peers is plenty. Chitchat fan-out
  takes care of the rest.
- `[mesh] cluster_id`: peers with mismatched cluster ids ignore each
  other. Use this to keep dev / staging / prod meshes separate even when
  they share a network.
- `[known_neighbors] bootstrap_window`: during this window, every peer
  the mesh discovers is auto-pinned. After it closes, only operator-signed
  add-neighbor messages can extend the pin set (Phase 5+). The default is
  **2 hours** post Phase-8 hardening (was 7 days) — short enough that
  bootstrap is a deliberate operator activity, long enough for fleet
  rollouts. Lengthen it temporarily for staged deployments; do not set
  it back to multi-day defaults in production.
- `[known_neighbors] max_pinned_peers`: hard cap on the pin set (default
  1024). Defends against chitchat-mesh-flood attacks that race-publish
  synthetic identities during the bootstrap window.

### Identity key

The agent generates an Ed25519 identity key on first start at the path
set by `[identity]`. The key is the agent's mesh identity; SHA-256 of its
public key is the **fingerprint** used everywhere in the protocol.

The key file is mode `0600` and owned by the agent user. Do not back it
up to anywhere with weaker protection. Losing it doesn't lose data — the
agent will generate a fresh one on next start — but the new fingerprint
is unrecognised by the mesh, so the host has to be re-pinned (only
possible during a bootstrap window or via an operator add-neighbor).

---

## 6. Running

```bash
sudo systemctl enable --now bowery-agent
journalctl -u bowery-agent -f
```

Healthy startup looks like:

```
INFO bowery_agent: generated new identity key on first start
     fingerprint=9e51…
INFO bowery_agent::agent: agent ready
     fingerprint=9e51…  mesh=0.0.0.0:9901  whisper=0.0.0.0:9902
     baseline=/var/lib/bowery/baseline.db
```

After other agents come up and gossip catches them, you'll see:

```
INFO bowery_agent::agent: pinned new neighbor peer=a3f2…
INFO bowery_agent::agent: received envelope sender=a3f2… nonce=…
```

---

## 7. Operator workstation

The operator CLI does not need root and does not need to be on the same
host as any agent. Install it as your normal user:

```bash
mkdir -p ~/.bowery
bowery key generate --out ~/.bowery/operator.key
# Output:
#   wrote identity to /home/julien/.bowery/operator.key
#   fingerprint: 4290a9c2efbe37aed0aa4dafe1d8535987d01c638156ef3c97f1bcde8f8e36c7
#   pubkey_b64:  8KChxFSe2t0i91xtXDj7swk0QYL1cOCXGea3cx5kaqQ=
```

Add the printed `pubkey_b64` to every agent's `[operators] pubkeys_b64`
list and roll the config (a future phase will let you do this via a
signed `add-operator` envelope; for now it's a config push).

Treat the operator key as the most sensitive secret in your stack: it
authorises drains of every alert inbox in the mesh, and Phase 6b will
extend it to action commands.

### Reading alerts

`bowery alerts tail` connects to a single agent, signs a `Subscribe`
with the operator key, and streams back every Alert in that agent's
inbox. With `--follow` it keeps re-polling forever; without, it exits
after one batch.

```bash
bowery alerts tail \
    --operator-key  ~/.bowery/operator.key \
    --agent-addr    10.0.0.5:9902 \
    --agent-fp      <agent_fp_hex> \
    --agent-pubkey-b64 <agent_pubkey_b64> \
    --follow --interval 5s
```

You need the agent's fingerprint and pubkey out-of-band — operators
don't ride the TOFU pin store. Get them from `journalctl -u
bowery-agent | grep 'identity'` on the agent host.

### Querying host state with `bowery exec sql`

`bowery exec sql` is the primary investigation tool: every agent
runs a pure-Rust SQL engine over a curated set of host-state
tables, and the operator can query it directly over QUIC.

```bash
bowery exec sql \
    --operator-key  ~/.bowery/operator.key \
    --agent-addr    10.0.0.5:9902 \
    --agent-fp      <agent_fp_hex> \
    --agent-pubkey-b64 <agent_pubkey_b64> \
    --sql 'SELECT pid, ppid, name FROM processes WHERE name = "sshd"'
```

Available tables: `processes`, `mounts`, `kernel_modules`,
`interfaces`, `listening_ports`, `process_open_sockets`,
`users`, `logged_in_users`, `last`, `systemd_units`, `crontab`,
`os_version`, `system_info`, plus seven Bowery-internal views
(`bowery_peers`, `bowery_mesh_peers`, `bowery_monitor_rules`,
`bowery_yara_rules`, `bowery_baseline_binaries`, `bowery_alerts`,
`bowery_audit`, `bowery_events`, `bowery_eventlog_status`,
`bowery_revocations`, `bowery_net_destinations`). Plus seven scalar
functions for per-path file
inspection: `bowery_file_exists`, `_size`, `_mode`,
`_mtime_unix`, `_owner_uid`, `_owner_gid`, `_sha256_hex`.

`--format=table` renders an aligned ASCII table (buffered);
`--format=json` streams one JSON object per row preceded by a
column-name array; `--format=tsv` (default) streams one
tab-separated line per row. See
[`DESIGN-NATIVE-SQL.md`](DESIGN-NATIVE-SQL.md) for the full
schema and security model.

### The fleet connection graph

Every outbound connection is folded into a per-host destination
baseline, exposed as `bowery_net_destinations`. Under `--fanout` that
becomes the fleet-wide connection graph, which is what makes lateral
movement legible: the two halves of a hop live on different hosts and
neither is remarkable alone.

```bash
# Which hosts have ever contacted this endpoint?
bowery exec sql --fanout --sql \
  "SELECT _agent_name, seen_count, first_seen_unix
   FROM bowery_net_destinations WHERE dst_key = '10.0.0.5:22'"

# Endpoints exactly one host in the fleet has ever contacted.
bowery exec sql --fanout --sql \
  "SELECT dst_key, COUNT(*) AS hosts FROM bowery_net_destinations
   GROUP BY dst_key HAVING hosts = 1"
```

That second query is the useful one for hunting: an endpoint a single
host has ever talked to is the shape of C2, exfil, or a first hop.
Cross-reference it against `bowery_events` on that host to get the
process that made the connection:

```bash
bowery exec sql --sql \
  "SELECT ts_unix_ms, pid, comm, exe_path FROM bowery_events
   WHERE kind = 'connect' AND dst_addr = '10.0.0.5' AND dst_port = 22"
```

### Mesh trust: signed enrollment and revocation

Under the default `enrollment = "tofu"`, any host that can send UDP to
the gossip port during an agent's bootstrap window becomes a permanently
trusted mesh member. Signed enrollment replaces that with an
operator-signed grant.

**Issue a grant per agent** (offline; needs only the operator key):

```bash
bowery trust grant \
  --operator-key ~/.bowery/operator.key \
  --agent-fp <agent fingerprint hex> \
  --cluster-id bowery-tailnet \
  --out grant.b64
```

Copy `grant.b64` to the agent and point `[known_neighbors] grant_path`
at it, then restart. The agent gossips the grant so peers can verify it.

A valid grant **bypasses the bootstrap window**. That window exists to
bound TOFU — when "showed up on the gossip port" is the only admission
evidence, it has to expire — but an operator signature is stronger
evidence and doesn't. Without this, a granted agent could never join a
fleet that had been running longer than its window, which is the exact
friction grants remove. Revocation and the pin-count cap still apply.

Grants are honoured even by agents still running `enrollment = "tofu"`,
which is what makes the migration below incremental.

**Migrating to signed enrollment.** Flipping `enrollment` to `grant`
while any peer lacks a valid grant partitions the mesh — those peers
stop being pinnable. Issue grants to every agent first, then confirm
fleet-wide before flipping:

```bash
bowery exec sql --fanout --sql \
  "SELECT fingerprint_hex, grant_state FROM bowery_mesh_peers"
```

Every row must read `grant_state = valid`. `absent` means that agent has
no grant yet; `invalid: …` names the failing check — most often
`ClusterMismatch`, because the grant's `--cluster-id` must match the
agent's `[mesh] cluster_id` exactly (the remote installer defaults to
`bowery-tailnet`, while `bowery trust grant` defaults to `bowery`).

Note that flipping `enrollment` to `grant` does **not** unpin peers that
were already TOFU-pinned — it only governs *new* pins, so the switch
can't partition a running mesh. The corollary is that flipping alone
does not retroactively close the TOFU hole: to require proof from every
peer, stop the agent, delete `known_neighbors.json`, and restart, at
which point it re-pins only peers presenting valid grants.

**Revoking a compromised agent:**

```bash
bowery trust revoke \
  --operator-key ~/.bowery/operator.key \
  --agent-fp <fingerprint> --cluster-id bowery-tailnet \
  --reason "compromised" --out revocation.b64
```

**Push it to the fleet** in the same command — the revocation spreads
peer-to-peer from the agent you dial:

```bash
bowery trust revoke \
  --operator-key ~/.bowery/operator.key \
  --agent-fp <fingerprint being revoked> --cluster-id bowery-tailnet \
  --reason "compromised" \
  --agent-addr 100.64.0.5:9902 \
  --relay-fp <fingerprint of the agent you're dialling> \
  --relay-pubkey-b64 <its pubkey> \
  --fanout
```

Each agent verifies the revocation itself — it carries an operator
signature over its own fields, so a relaying peer can *drop* it but
cannot forge one, and cannot use the relay path to eject healthy agents.
Each hop applies it and forwards only if it was new, so a flood
converges instead of echoing around a cyclic peer graph; `--ttl`
(clamped to 8) is a second, structural bound.

Because a peer can drop rather than relay, delivery is confirmed, not
assumed — see the query below.

Alternatively, append the base64 line to each agent's
`revocations_path` by hand. The file is one signed revocation per line
and every line is re-verified against the configured operator keys on
load, so a hand-edited or forged entry is skipped, not trusted. On
start, and on the next gossip tick, the agent evicts the revoked peer
from its pin set and refuses to re-pin it.

Confirm delivery either way:

```bash
bowery exec sql --fanout --sql "SELECT fingerprint_hex FROM bowery_revocations"
```

A revocation only binds agents that have received it — an agent missing
it still trusts the revoked peer. There is no un-revoke: re-admitting a
rebuilt host means giving it a new identity key.

### Multi-agent fan-out

`--fanout` turns the dialled agent into a relay that runs the
query locally **and** dispatches it to every pinned peer in
parallel. Rows from each agent are prefixed with two attribution
columns: `_agent_name` (the operator-assigned name from
`~/.bowery/peers.toml`, or `?` if the fingerprint isn't in the
manifest) and `_agent_fp` (the raw fingerprint). Attribution is
derived from the authenticated envelope sender, not a
self-declared field, so a peer can't spoof another host's rows.

```bash
bowery exec sql ... --fanout \
    --sql 'SELECT port FROM listening_ports WHERE port = 22'
# → _agent_name  _agent_fp            port
#   web-1        3f9a…                22
```

Fan-out relays only to peers that are both **discovered in the
gossip mesh and pinned** — so the agents must actually form a
mesh first (seeds + routable advertise addresses + pinning).
For a standalone deployment over a tailnet, the step-by-step
bring-up is in [`deploy/remote/MESH.md`](deploy/remote/MESH.md).
Check what a relay currently sees with the `bowery_mesh_peers`
view (`pinned = 1` means it will fan out to that peer).

For fan-out to verify peer signatures end-to-end, the operator's
CLI needs each peer's public key. Maintain that list in
`~/.bowery/peers.toml`:

```bash
bowery peers add --name web-1 \
    --fp <peer_fp_hex> --pubkey-b64 <peer_pubkey_b64> \
    --addr 100.111.5.24:9902          # optional: enables `peers check`
bowery peers list
bowery peers check --operator-key ~/.bowery/operator.key   # dial each, report reachability
bowery peers remove --fp <peer_fp_hex>
```

`bowery exec sql --fanout` auto-loads the manifest before
dialing. Peers absent from the manifest will surface as
`BadSignature` rejections — visible failure mode rather than
silent drop.

Fan-out has a per-operator rate limit (1 query / 5 s, burst 6)
to prevent mesh amplification, and a single-hop cap (peers
reject relay-forwarded commands that themselves request
fanout). Each agent independently authorises the original
operator — the relay does **not** need to be in any peer's
`[operators]` list — so a compromised relay key cannot grant
SQL authority over peers.

### YARA rule distribution

Push a YARA rule to an agent, scan paths with it, and (optionally)
propagate it across the whisper mesh so every agent stores and runs it:

```bash
# scan one agent
bowery exec yara --operator-key ~/.bowery/operator.key \
    --agent-addr 100.105.157.53:9902 --agent-fp <hex> --agent-pubkey-b64 <b64> \
    --rules ./webshell.yar --target /var/www --target /tmp

# distribute across the whole mesh (each hop decrements --ttl)
bowery exec yara ... --rules ./webshell.yar --target /tmp --fanout --ttl 4
```

Matches become alerts (visible via `bowery alerts tail`), and each agent
reports its own results back. Confirm distribution landed everywhere:

```bash
bowery exec sql ... --fanout --sql 'SELECT rule_id FROM bowery_yara_rules'
```

How it's bounded and secured:

- **The rule is operator-signed.** Every agent it reaches verifies *your*
  signature over the exact rule bytes and targets, so a relaying agent
  can drop a rule but cannot forge, alter, or redirect one.
- **Loops terminate.** Each agent remembers `(operator_fp, request_id)`
  and drops a push it has already handled, so a cyclic peer graph
  converges instead of flooding forever. `--ttl` is an independent
  structural bound; agents clamp it to their own `[yara] max_ttl`.
- **Rules are content-addressed** by SHA-256, so the same rule arriving
  by several mesh paths stores once.
- **Caps** live in `[yara]`: `max_rules`, `max_rule_bytes` (48 KiB
  default — the transport frame cap makes larger pushes impossible),
  `max_concurrent_scans`, `max_file_bytes`, `max_files_per_scan`,
  `max_depth`.

> **The scanning engine is opt-in at build time.** Build the agent with
> `--features yara` to link libyara. Without it agents still accept,
> store, and propagate rules — they just report `engine not compiled in`
> instead of scanning. It's off by default so the static aarch64-musl Pi
> build doesn't take on a C dependency. Note libyara here is built with
> crypto disabled, so rules cannot use the `hash` module; use the
> `bowery_file_sha256_hex` SQL function for hashing instead.

### Models

The agent expects an already-on-disk GGUF. Fetch one:

```bash
bowery model list
bowery model fetch qwen3-0.6b-q4_k_m       # agent-side analyzer
bowery model fetch gemma-4-e2b-it-q4_k_m   # operator-side console chat
```

`fetch` validates every download in three steps before declaring
success:

1. **GGUF magic** — first 4 bytes must be `GGUF`. Catches HTTP error
   pages saved as the file.
2. **Size band** — actual size must be within ±25 % of the
   registry's expected count.
3. **SHA-256** — registry pins the upstream LFS hash; the
   downloader streams the file post-download and bails on
   mismatch.

The agent never downloads at runtime or compile time.

For the dev VM workflow, see `xtest run-agent --push-model` and
`xtest run-console` in [docs/REMOTE_TESTING.md](docs/REMOTE_TESTING.md).

### Interactive console (`bowery-console`)

For day-to-day investigation, install the ratatui workspace
binary alongside `bowery`:

```bash
./scripts/build-console          # RUSTFLAGS='-C target-cpu=native' for you
sudo install -m755 target/release/bowery-console /usr/bin/
```

> The wrapper pins the build to this host's CPU. A plain
> `cargo build --features llm-llama-cpp -p bowery-console` can abort
> at chat-model load with `Illegal instruction (core dumped)` when
> llama.cpp's dispatch picks an instruction the running core lacks;
> the resulting native binary is not portable to a different CPU.

### One-shot rebuild + install on an operator host

When the operator workstation is also a monitored node, this builds all
three binaries with every feature on, installs them, refreshes the
systemd unit, restarts the agent, and prints the lines that prove it
actually came back healthy:

```bash
./scripts/build-install-operator
```

| Binary | Features enabled |
|---|---|
| `bowery-agent` | `llm-llama-cpp` + `yara` |
| `bowery-console` | `llm-llama-cpp` |
| `bowery` | (none optional) |

Useful flags: `--no-console` (skip the slow llama.cpp console build),
`--no-agent` (operator tools only), `--no-restart`, `--skip-unit`,
`--dry-run`.

It refreshes `bowery-agent.service` + the `10-remote-node.conf` drop-in
because capability and seccomp changes (`CAP_SYS_PTRACE` for `/proc`
enrichment, `bpf`/`perf_event_open` for the eBPF load path) don't take
effect from a new binary alone. Each binary is smoke-tested before it
replaces the running one, so a build that won't execute can't take your
monitoring down.

> **Native build only.** Everything is compiled with
> `-C target-cpu=native`, so these binaries are tuned to this machine's
> CPU — don't copy them to another host. The Raspberry Pis take the
> cross-compiled static musl tarball from
> `deploy/remote/package-agent.sh` instead.

It pulls in eight panes — Query (SQL REPL), Alerts (live tail),
Map (1-hop topology), Audit, Peers (manifest CRUD), Doctor (local
+ remote readiness), Chat (Gemma 4 chatbot that drafts SQL —
press `x` to run), Help (operator handbook). The full reference
(hotkeys, palette, schema, recipes, troubleshooting) is in
[docs/CONSOLE.md](docs/CONSOLE.md), and the same content renders
in-pane via the Help tab (hotkey `8`).

Launch:

```bash
bowery-console \
    --operator-key  ~/.bowery/operator.key \
    --agent-addr    10.0.0.5:9902 \
    --agent-fp      <hex>           \
    --agent-pubkey-b64 <base64>
```

On first launch the console offers to download Gemma 4 if the
GGUF isn't on disk yet:

```
The Chat pane needs Gemma 4 (GGUF, ~3 GB).
  expected at:  /home/you/.bowery/models/gemma-4-e2b-it-q4_k_m.gguf
  registry id:  gemma-4-e2b-it-q4_k_m
Download now? [y/N]
```

`y` runs the same `bowery model fetch` path with full
GGUF-magic + size + SHA-256 verification. Without the
`llm-llama-cpp` feature the chat pane falls back to a deterministic
mock backend and prints a banner explaining the rebuild
incantation.

---

## 8. Troubleshooting

### `bowery doctor` says **BPF-LSM active: FAIL**

The kernel was compiled with `CONFIG_BPF_LSM=y` but the bootline doesn't
turn it on. On Debian / Ubuntu:

```bash
sudo cp /etc/default/grub /etc/default/grub.bak
# Append `lsm=lockdown,yama,bpf` (or extend the existing list with `,bpf`).
sudo sed -i 's|^GRUB_CMDLINE_LINUX="|GRUB_CMDLINE_LINUX="lsm=lockdown,yama,bpf |' /etc/default/grub
sudo update-grub
sudo reboot
```

On RHEL / Rocky / Alma:

```bash
sudo grubby --update-kernel=ALL --args="lsm=lockdown,yama,bpf"
sudo reboot
```

After reboot, `cat /sys/kernel/security/lsm` must include `bpf`.

### `bowery doctor` says **bpffs: WARN** (not mounted)

```bash
sudo mount -t bpf bpf /sys/fs/bpf
echo 'bpf  /sys/fs/bpf  bpf  defaults  0  0' | sudo tee -a /etc/fstab
```

### `bowery doctor` says **kernel config: FAIL** (missing `CONFIG_BPF_LSM`)

Your kernel was not built with BPF-LSM. Either install a distro kernel
that has it (see §1.2) or rebuild your kernel with `CONFIG_BPF_LSM=y`,
`CONFIG_DEBUG_INFO_BTF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`.

### Agent fails to bind one of its UDP ports

```bash
ss -ulpn | grep -E '9901|9902'
```

If something else holds the port, edit the config or stop the conflicting
service. Both ports are UDP.

### Two agents don't see each other

- `cluster_id` matches on both?
- Mesh ports reachable end-to-end? Test with `nc -uz peer 9901` (rough; UDP).
- `bowery-agent` logs `pinned new neighbor` for each side once gossip
  finds them. If not, check chitchat seed connectivity.
- Both within the bootstrap window? Once the window closes, agents
  refuse to auto-pin new peers.

### Wipe agent state and restart

```bash
sudo systemctl stop bowery-agent
sudo rm -rf /var/lib/bowery/identity.key \
            /var/lib/bowery/known_neighbors.json \
            /var/lib/bowery/baseline.db*
sudo systemctl start bowery-agent
```

The agent will regenerate everything on next start. **You will need to be
re-pinned by the rest of the fleet** (new fingerprint).

---

## 9. Uninstalling

```bash
sudo systemctl disable --now bowery-agent
sudo rm /etc/systemd/system/bowery-agent.service \
        /etc/systemd/system/bowery.slice
sudo rm /usr/local/bin/bowery-agent /usr/local/bin/bowery
sudo rm -rf /etc/bowery /var/lib/bowery /var/log/bowery
sudo userdel bowery
sudo systemctl daemon-reload
```

---

## 10. What's not yet shipping

Phases 0 → 10 are in tree (see [README](README.md#whats-implemented)).
Known gaps, smallest first:

- **YARA scanning on the Raspberry Pis.** Rules still distribute and
  persist there, but `yara-sys` ships no pre-generated libyara bindings
  for `aarch64-unknown-linux-musl`, so the cross-build can't enable the
  engine — those agents report `engine not compiled in`. Build natively
  on the Pi if you need scanning (see `deploy/remote/package-agent.sh`).
- **Enforcement caveats.** `block_exec` matches on `task->comm`, which
  an attacker controls, and `kill_process` has a PID-reuse window
  between the `/proc` check and the signal. Both are documented
  follow-ups (inode-keyed blocking, `pidfd`).
- **Mesh trust bootstrap.** Peers are pinned trust-on-first-use during
  the bootstrap window and there is no revocation path; an
  operator-signed enrollment + un-pin protocol is still open.
- **F-7 / F-17** — fan-out EOF accounting (so an operator can prove
  every expected peer reported) and per-peer relay log rate-limiting.
- **Phase 11+** — key rotation ceremony, Sybil resistance at fleet
  scale, multi-OS.

---

## Email notifications (`bowery notify`)

Alerts otherwise wait in a per-agent inbox until somebody looks. This
emails them, with **no backend to run**: a one-shot CLI on a timer,
pulling over the same signed transport `bowery alerts` uses.

Install it on **one always-on machine you already own** — not on the
monitored agents. Agents get no SMTP credential and no new egress path;
a compromised host therefore cannot flood you, read the secret, or watch
for its own detection.

### 1. A Gmail app password

Gmail rejects normal account passwords over SMTP. You need an
**App Password**, which requires 2-Step Verification on the account:

1. Turn on 2-Step Verification (myaccount.google.com → Security).
2. Security → **App passwords** → generate one for "Mail".
3. Store the 16-character value, spaces removed:

```bash
install -m 600 /dev/null ~/.bowery/smtp-password
printf '%s' 'abcdefghijklmnop' > ~/.bowery/smtp-password
```

`bowery notify` **refuses to run** if that file is group- or
world-readable. A secret every account on the box can read is not a
secret.

### 2. `~/.bowery/notify.toml`

```toml
[email]
to            = ["julien.vehent@gmail.com"]
from          = "julien.vehent@gmail.com"   # Gmail: must equal `username`
smtp_host     = "smtp.gmail.com"
smtp_port     = 587
username      = "julien.vehent@gmail.com"
password_file = "~/.bowery/smtp-password"
starttls      = true       # 587 STARTTLS; set false for 465 implicit TLS

[filter]
min_suspicion  = 0.9       # below this, don't wake anyone
confirmed_only = false     # true = only peer-quorum-confirmed alerts
```

Any SMTP relay works — your own server, SES, Postmark, Fastmail. Gmail
is just the documented first case.

### 3. Try it without sending

```bash
bowery notify --dry-run
```

Polls every agent in `~/.bowery/peers.toml`, prints the exact message,
and **does not advance the cursors** — so you can run it repeatedly
while tuning `min_suspicion`. Needs no SMTP credential.

### 4. Put it on a timer

On a host where the operator is a real user account — including a
combined agent + operator box — run it as a **user service**. Nothing to
edit, and `%h` / `HOME` resolve on their own:

```bash
mkdir -p ~/.config/systemd/user
cp deploy/notify/bowery-notify.{service,timer} ~/.config/systemd/user/
sudo loginctl enable-linger "$USER"     # required: see below
systemctl --user daemon-reload
systemctl --user enable --now bowery-notify.timer
systemctl --user list-timers bowery-notify.timer
```

**`enable-linger` is not optional.** Without it the user manager exits
when you log out, and a headless box silently stops notifying — which is
the exact failure this exists to prevent. Check it with
`loginctl show-user "$USER" -p Linger`.

Where there is no operator login account to run as, install to
`/etc/systemd/system/` instead and `systemctl edit` the unit to set
`User=` and `Environment=HOME=`.

Default cadence is 15 minutes. Nothing is sent when nothing is new, so a
short interval costs only a few QUIC round trips.

Verify a run end to end:

```bash
systemctl --user start bowery-notify.service    # fire it now
systemctl --user status bowery-notify.service   # exit status + output
journalctl --user -u bowery-notify.service -n 20
```

### What the message contains, and why

The **subject** is built only from host names and counts — never from
alert text. That is what makes header injection impossible by
construction rather than by escaping, because `exe_path` is whatever an
attacker managed to execute.

The **body** carries the detail you need to triage from a phone
(suspicion, episode, path, sha, rationale), with control characters
stripped, every field length-capped, `text/plain` only, and a footer
saying plainly that those fields came from the monitored host and are
leads rather than facts. Verify against the signed source before acting.

Alerts that supersede each other — the pre-filter's, the LLM's
refinement, the quorum's confirmation — collapse to one entry per
episode, newest kept, worst first.

### VirusTotal screening (optional)

Cuts false positives by holding back alerts whose binary no antivirus
engine flags.

```bash
install -m 600 /dev/null ~/.bowery/virustotal.key
printf '%s' 'YOUR_VT_API_KEY' > ~/.bowery/virustotal.key
```

```toml
[virustotal]
enabled              = true
api_key_file         = "~/.bowery/virustotal.key"
suppress_known_clean = true   # drop alerts no engine flags
max_lookups          = 20     # per run; public API allows 4/min, 500/day
```

Check one hash by hand at any time:

```bash
bowery vt <sha256>      # exit 0 clean, 1 flagged, 2 unknown/unavailable
```

**Understand what a lookup discloses.** Querying VirusTotal tells VT — and
anyone with Intelligence access — that somebody is investigating that
hash. Adversaries watch VT for their own samples, so for a suspected
targeted implant an automatic lookup is a tip-off, sent before you have
decided what to do. That is why this is off by default, why agents never
do it, and why the key lives only on your box. Hashes only; no file is
ever uploaded.

**It can only ever suppress, never silence.** An alert is held back only
on a positive clean verdict. A missing key, a spent quota, an API
outage, an unparseable response, a hash VT has never seen — every one of
those sends the alert anyway. A monitoring system must not go quiet
because a third-party API had a bad day.

Each alert carries its own verdict, and enough context to judge it
without logging in to the host:

```
  suspicion : 1.00
  when      : 2026-08-17 01:25:01 UTC
  exe       : /usr/local/bin/updater
  sha256    : 7947969…
  why       : exec from world-writable path
  vt        : VirusTotal: 41/62 engines flag this
  uid       : 1000
  cmdline   : /usr/local/bin/updater --fetch http://198.51.100.7/x.sh
  cwd       : /tmp
  ancestry  : systemd[1] → sshd[812] → bash[4410] → updater[4457]
  connections: 10.0.0.5:44120 -> 198.51.100.7:80
```

The ancestry is usually what decides it: the same binary run by a human
over SSH and run by a web server mean very different things. Open files
and connections are a **snapshot** — a short-lived process is gone
before they can be read, and in that case the alert says so rather than
showing an empty list, because "opened nothing" and "already exited" are
not the same fact.

A flagged binary **leads its host's list and the subject line**
(`[1 VT-FLAGGED]`), so the worst thing is visible without scrolling.

Every digest also states what screening did as a whole — including how
many hashes VirusTotal had never seen, because `2 hash(es) checked` on
its own reads as "checked and fine" when it may mean the opposite.
Held-back alerts stay readable with `bowery alerts`.

Verdicts are cached for a week in `~/.bowery/vt-cache.json` to stay
inside the quota. Failures are never cached — that would turn one outage
into a week of not looking.

### Operational notes

- **Cursors** live in `~/.bowery/notify-cursor.json`, keyed by agent
  fingerprint, and advance **only after a successful send**. A failed
  SMTP attempt re-sends next run rather than dropping alerts.
- **A failed run exits non-zero**, including when some agents were
  unreachable, so `systemctl status` and `OnFailure=` see it. A notifier
  that fails quietly is the thing it was built to prevent.
- **One unreachable agent doesn't suppress the rest** — the digest goes
  out with what was collected, and the failure is reported alongside.
