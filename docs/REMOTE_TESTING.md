# Remote testing on a VirtualBox VM

This repo includes [`scripts/xtest`](../scripts/xtest), an SSH-based driver
that runs builds, tests, and `bowery doctor` on a remote Linux VM. Use it
when your dev machine can't run the agent end-to-end (WSL2 lacks BPF-LSM,
macOS isn't Linux at all) but you have a Linux VM that does.

## 1. Provision the VM

### 1.1 Create the VM

In VirtualBox:

1. New VM, type Linux, version Ubuntu 64-bit.
2. **Memory**: 4 GiB minimum (8 GiB if you'll add the LLM analyzer in
   Phase 4b).
3. **Disk**: 25 GiB (Cargo target dirs + a Qwen3 GGUF later).
4. **Processors**: 2+.

Install **Ubuntu Server 24.04** (or 22.04). Both ship with
`CONFIG_BPF_LSM=y` and BTF, and `lsm=` already includes `bpf`.

### 1.2 Networking — pick one

**Option A: NAT with port-forward** (simplest, host-only access).

- Settings → Network → Adapter 1 → Attached to: NAT.
- Advanced → Port Forwarding → add a rule:

  | Name | Protocol | Host port | Guest port |
  |---|---|---|---|
  | ssh | TCP | 2222 | 22 |

- In `.xtest.env`: `XTEST_HOST=127.0.0.1`, `XTEST_PORT=2222`.

**Option B: Bridged adapter** (VM is a peer on your LAN; useful for
multi-host mesh tests).

- Settings → Network → Adapter 1 → Attached to: Bridged Adapter.
- Inside the VM, `ip a` shows a LAN IP (e.g. `192.168.1.42`).
- In `.xtest.env`: `XTEST_HOST=192.168.1.42`, `XTEST_PORT=22`.

### 1.3 Enable SSH

```sh
sudo apt update
sudo apt install -y openssh-server
sudo systemctl enable --now ssh
```

### 1.4 Push your SSH key

From the host:

```sh
ssh-copy-id -p 2222 ubuntu@127.0.0.1   # NAT case
# or
ssh-copy-id ubuntu@192.168.1.42        # bridged case
```

## 2. Configure xtest

```sh
cp scripts/.xtest.env.example .xtest.env
# Edit .xtest.env — set XTEST_HOST, XTEST_USER, XTEST_PORT.
```

The file is git-ignored.

## 3. Bootstrap the VM (one time)

```sh
./scripts/xtest setup
```

The whole setup runs in **one** interactive SSH session (a single pty
the entire time) so sudo only prompts once — typical Ubuntu sudo
caches its timestamp per-tty, and using separate SSH calls would
re-prompt on every multiplexed channel. **Run this from a real
terminal**; sudo cannot prompt through pipes or detached shells.

If you'd rather skip the prompt entirely (recommended for a dedicated
dev VM), give your user passwordless sudo on the guest:

```sh
echo "$USER ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/$USER-nopasswd
sudo chmod 440 /etc/sudoers.d/$USER-nopasswd
```

Then `xtest setup` and any future `sudo`-using subcommand runs silently.

`xtest setup` installs:

- `build-essential`, `pkg-config`, `cmake` — for `rusqlite` and future
  Phase 4b llama-cpp builds
- `clang`, `llvm`, `libbpf-dev`, `linux-headers-$(uname -r)`, `bpftool`,
  `bpftrace` — for Phase 2 BPF
- `rustup` + the stable toolchain (honors the repo's `rust-toolchain.toml`
  on first `cargo` invocation)
- mounts `bpffs` at `/sys/fs/bpf` and adds an fstab entry so it persists

The script is idempotent — re-running is safe.

## 4. Verify the kernel is ready

```sh
./scripts/xtest doctor
```

This builds `bowery-cli` on the VM (first time only — subsequent runs
hit the build cache) and runs `bowery doctor`. Healthy output:

```
== Bowery host readiness ==
  PASS kernel version  6.8.0-...
  PASS BTF             /sys/kernel/btf/vmlinux (5.9 MiB)
  PASS BPF-LSM active  capability,lockdown,yama,bpf
  PASS bpffs           mounted at /sys/fs/bpf
  PASS boot lsm= flag  lsm=lockdown,yama,bpf
  PASS kernel config   4/4 required options enabled
Result: ready
```

If any check fails, the doctor prints a remediation hint. See
[INSTALL.md §8](../INSTALL.md#8-troubleshooting) for the full list.

## 5. Daily use

| Command | What it does |
|---|---|
| `xtest sync` | rsync workspace (excludes `target/`, `.git/objects`) |
| `xtest build` | sync + `cargo build --workspace` |
| `xtest build --release` | sync + release build |
| `xtest test` | sync + `cargo test --workspace` |
| `xtest test -p bowery-whisper` | passes args through to cargo |
| `xtest clippy` | sync + `cargo clippy ... -D warnings` |
| `xtest fmt-check` | sync + `cargo fmt --check` |
| `xtest ci` | full CI mirror: fmt-check + clippy + test + release build |
| `xtest doctor` | run `bowery doctor` on the target |
| `xtest probe` | print kernel / distro / BPF readiness summary |
| `xtest exec '<cmd>'` | run an arbitrary command in the workdir |
| `xtest shell` | interactive SSH session in the workdir |
| `xtest stop-ssh` | tear down the SSH ControlMaster |

`xtest` keeps an SSH `ControlMaster` socket open for ~10 minutes after
each session, so back-to-back commands amortise the TLS handshake.

## 6. Tips

- **First sync is slow.** `target/` is excluded, so the workspace is
  small (~few MB). Subsequent syncs are incremental and finish in <1s.
- **First build is slow.** Cargo on a fresh VM downloads ~250 MB of
  crate sources and compiles for ~3-5 min. After that, incremental
  builds are quick.
- **Run multi-host mesh tests on a bridged VM.** With bridged
  networking, you can spin up two VMs and let them gossip natively.
- **Snapshot the VM** after `xtest setup` succeeds — rebuilding the
  Rust toolchain from scratch is otherwise painful.
- **Phase 4b** (real Qwen3-0.6B inference) needs the same VM with
  ~1 GB extra disk for the GGUF weights. The build deps are already
  installed by `xtest setup`.
