# Installing The Bowery

> **Status, 2026-05-03:** Phase 0–2 (userspace) is implemented. The agent
> runs, gossips, and pins neighbors over QUIC; the event pipeline is wired
> in but uses a `NoopEventSource` until the eBPF source lands. The KRSI
> requirements below describe what the *finished* agent needs — you can
> install today on a host that doesn't satisfy them and the agent will
> still run, just without kernel visibility.

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

All 67 tests should pass. The end-to-end `two_agents_discover_pin_and_heartbeat`
test is the most informative — it exercises chitchat, TOFU pinning, QUIC
mTLS, and signed envelopes in ~1.3 s.

---

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

1. `$BOWERY_BPF_OBJ_PATH` (env var)
2. `/usr/local/lib/bowery/bowery-ebpf`
3. `/usr/lib/bowery/bowery-ebpf`
4. `crates/bowery-ebpf/target/bpfel-unknown-none/release/bowery-ebpf`
   (handy when running from a workspace checkout)

For production install:

```sh
sudo install -d -m 0755 /usr/local/lib/bowery
sudo install -m 0644 crates/bowery-ebpf/target/bpfel-unknown-none/release/bowery-ebpf \
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
fields you'll typically tune:

```toml
[mesh]
listen_addr   = "0.0.0.0:9901"
seeds         = ["seed1.internal:9901", "seed2.internal:9901", "seed3.internal:9901"]
cluster_id    = "prod-us-east"
# advertise_addr = "10.0.5.7:9901"   # set if listen != dialable

[whisper]
bind_addr = "0.0.0.0:9902"

[heartbeat]
interval = "30s"

[known_neighbors]
path             = "/var/lib/bowery/known_neighbors.json"
bootstrap_window = "7d"

[baseline]
path = "/var/lib/bowery/baseline.db"

[identity]
path = "/var/lib/bowery/identity.key"
```

### Sizing notes

- `[mesh] seeds`: 3–5 well-connected peers is plenty. Chitchat fan-out
  takes care of the rest.
- `[mesh] cluster_id`: peers with mismatched cluster ids ignore each
  other. Use this to keep dev / staging / prod meshes separate even when
  they share a network.
- `[known_neighbors] bootstrap_window`: during this window, every peer
  the mesh discovers is auto-pinned. After it closes, only operator-signed
  add-neighbor messages can extend the pin set (Phase 5+). Pick a window
  that comfortably exceeds the time it takes to roll out the agent across
  the fleet — 7 days is a conservative default.

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

The operator CLI does not need root. Install it as your normal user:

```bash
mkdir -p ~/.bowery
bowery key generate --out ~/.bowery/operator.key
bowery key fingerprint ~/.bowery/operator.key
```

The fingerprint is what the agent fleet will be configured to trust for
signed commands (Phase 6+ — operator commands aren't wired up yet).
Treat the operator key as the most sensitive secret in your stack: it
authorises mass actions across the mesh.

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

For transparency, today's binary covers Phase 0–2 (userspace). The
following are **not** wired up yet (per [DESIGN.md §13](DESIGN.md#13-phased-delivery)):

- eBPF / KRSI program loading (Phase 2 BPF — the doctor checks the
  kernel will *be able to* run them)
- LLM analyzer (Phase 4)
- Whisper Q&A with role-similarity peer selection (Phase 5)
- Operator CLI commands beyond `key generate` / `fingerprint` / `doctor` (Phase 6)
- Response engine — kill / block / quarantine (Phase 7)

The agent currently does: discover peers via gossip, TOFU-pin them, and
exchange signed Heartbeat envelopes over QUIC mTLS. That's enough to
validate cluster topology and identity infrastructure end-to-end.
