# Installing The Bowery

> **Status:** Phase 0 → 6a complete (kernel events, baseline, analyzer,
> LLM, whisper Q&A, operator alert inbox + tail CLI). The agent runs,
> observes process exec / exit and outgoing TCP connects via eBPF,
> pins peers over QUIC mTLS, gossips role vectors, asks similar peers
> for corroboration on suspicious episodes, and surfaces high-suspicion
> verdicts to roaming operators via a signed `Subscribe` flow. Phase 7
> (response engine — kill / block) is open; the agent is observe-only
> today.

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

~170 tests should pass. The most informative end-to-end tests are:
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
rustup toolchain install nightly --profile minimal --component rust-src
cargo install bpf-linker
```

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
# advertise_addr = "10.0.5.7:9901"   # set if listen != dialable

[whisper]
bind_addr = "0.0.0.0:9902"

# Phase 5 — neighborhood Q&A
[whisper.qa]
threshold      = 0.6        # suspicion at which we ask peers
fanout         = 5          # number of role-similar peers per round
timeout        = "5s"
min_similarity = 0.0        # cosine cutoff; raise for stricter neighborhoods

[heartbeat]
interval = "30s"

[baseline]
path = "/var/lib/bowery/baseline.db"

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
# value from `bowery key generate --out …` or `bowery key fingerprint`.
pubkeys_b64 = [
    "8KChxFSe2t0i91xtXDj7swk0QYL1cOCXGea3cx5kaqQ=",
]

[inbox]
capacity  = 10000   # ring size; FIFO eviction at capacity
retention = "72h"   # TTL on individual alerts (lazy sweep)

[alerts]
threshold = 0.7     # suspicion at which a verdict becomes an Alert
```

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

### Models

The agent expects an already-on-disk GGUF. Fetch one:

```bash
bowery model list
bowery model fetch qwen3-0.6b-q4_k_m   # → ~/.bowery/models/qwen3-0.6b-q4_k_m.gguf
```

`fetch` validates the GGUF magic and approximate size before declaring
success; if a HuggingFace mirror starts returning HTML error pages
(we've seen it), the validator catches it and removes the partial. The
agent never downloads at runtime or compile time.

For the dev VM workflow, see `xtest run-agent --push-model` in
[docs/REMOTE_TESTING.md](docs/REMOTE_TESTING.md).

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

Today's binary covers Phase 0 → 6a. **Not** wired up yet (per
[DESIGN.md §13](DESIGN.md#13-phased-delivery)):

- **Phase 6b** — operator-issued `OperatorCommand` (e.g. `bowery
  query 'select * from processes ...'`, `bowery action kill-process
  ...`). The wire format placeholders exist; the agent's command
  handler doesn't. OSQuery subprocess integration is in this phase.
- **Phase 7** — response engine. The agent is observe-only today.
  When this lands, BPF-LSM hooks will gate `kill_process`,
  `block_open`, `block_connect`, etc. under standing authorisations
  recorded in `/etc/bowery/policy.yaml`.
- **Phase 8** — fuzzing, key rotation ceremony, neighbor add/remove
  signing, Sybil-resistance hardening, multi-OS.

The whisper context built in Phase 5 (`AgentEvent::WhisperContextReady`)
is observable via the broadcast channel but not yet fed into the LLM's
`AnalysisContext.extra` — that's a small follow-up commit, deliberately
staged separately so the protocol + observability hook landed first.
