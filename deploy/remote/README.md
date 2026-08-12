> **The eBPF object is architecture-neutral.** It builds for
> `bpfel-unknown-none` — BPF bytecode, little-endian variant — which has no
> host-arch component, so the *same* `bowery-ebpf` file runs on x86_64 and
> aarch64 alike. Build it once with `./scripts/build-ebpf`; only the agent
> binary is cross-compiled. `package-agent.sh` refuses to build a tarball
> without it, because an agent missing this file still meshes and still
> answers SQL while observing **no kernel events at all** — which is a much
> quieter failure than a crash.

# Deploying a Bowery agent to a remote node (Raspberry Pi over Tailscale)

This kit installs the agent on a remote Linux node you reach over
Tailscale and lets you query it from your laptop with the `bowery`
CLI / `bowery-console`. It's built for the single-node case: one
remote host, no mesh peers, operator connects directly.

To join several nodes into a mesh so one `bowery exec sql --fanout`
query relays across all of them, follow [MESH.md](MESH.md) after the
per-node install below.

## What you get (and what you don't) on a Raspberry Pi

Raspberry Pi OS ships **without BPF-LSM**, so the agent runs in its
degraded fallback (`NoopEventSource`). Concretely:

| Works on a stock Pi | Needs a BPF-LSM kernel (not on stock Pi OS) |
|---|---|
| Full SQL host-state surface (`processes`, `listening_ports`, `users`, `mounts`, `systemd_units`, `bowery_file_*`, …) queryable over Tailscale | Real-time eBPF exec / exit / TCP-connect event stream |
| Alert inbox + `bowery alerts tail` | `block_exec` LSM enforcement |
| Baseline of observed binaries | `kill_process` driven by live events |
| Rule + baseline scoring, mock LLM analyzer | — |

So the Pi becomes a **remote host-visibility node** you can query
live over the tailnet. `bowery doctor` on it will report BPF-LSM
"not ready" — that's expected, not a failure.

## Prerequisites

- **On the Pi:** a 64-bit OS (`uname -m` → `aarch64`), systemd,
  Tailscale up (`tailscale ip -4` returns a `100.x` address), and SSH
  access from your laptop over the tailnet.
- **On your laptop:** this repo, an operator key
  (`~/.bowery/operator.key`), the `bowery` CLI built, and — for the
  cross-build — `cross` + Docker:
  ```bash
  cargo install cross --git https://github.com/cross-rs/cross
  ```
  `Cross.toml` at the repo root configures that build: it passes
  `YARA_CRYPTO_LIB` into the container and installs clang there. Note
  the agent's `yara` feature is **not** enabled for this target —
  `yara-sys` ships no libyara bindings for `aarch64-unknown-linux-musl`.
  Pi agents still store and propagate YARA rules; they just don't scan.
  See the note at the top of `package-agent.sh`.

## Step 1 — get your operator public key (laptop)

```bash
bowery key info ~/.bowery/operator.key
#   fingerprint: <hex>
#   pubkey_b64:  <base64>       ← this is what the node must trust
```
Copy the `pubkey_b64`.

## Step 2 — build the deployable package (laptop)

```bash
./deploy/remote/package-agent.sh            # aarch64 (Pi 3/4/5, 64-bit OS)
# 32-bit Pi OS instead:
# ./deploy/remote/package-agent.sh armv7-unknown-linux-musleabihf
```
Produces `deploy/remote/dist/bowery-agent-<target>.tar.gz` — a
self-contained tarball (binary + systemd unit + config template +
installer). Default features only (mock LLM); no llama.cpp, so the
cross-build is quick and the artifact is small.

## Step 3 — ship + install (Pi)

```bash
# from the laptop:
scp deploy/remote/dist/bowery-agent-aarch64-unknown-linux-musl.tar.gz  pi5:      # tailnet name or 100.x IP
ssh pi5

# on the Pi:
tar xzf bowery-agent-aarch64-unknown-linux-musl.tar.gz
sudo ./bowery-agent-aarch64-unknown-linux-musl/install-agent.sh \
    --operator-pubkey '<paste pubkey_b64 from step 1>' \
    --cluster-id my-tailnet
```
The installer creates the `bowery` system user + dirs, installs the
binary + hardened systemd unit, writes `/etc/bowery/agent.toml` with
your operator key trusted, and — because a real operator key is
present — enables and starts the service. Re-run it any time to
upgrade the binary; it won't clobber an existing config.

## Step 4 — read the node's identity (Pi)

The agent generates its Ed25519 identity on first start and logs the
fingerprint:
```bash
journalctl -u bowery-agent | grep fingerprint
#   ... agent ready fingerprint=<64-hex> ... whisper=0.0.0.0:9902 ...
```
You need both the **fingerprint** (`--agent-fp`) and the node's
**pubkey_b64** (`--agent-pubkey-b64`). The package bundles the `bowery`
CLI, so read both directly on the node (the identity key is root-owned,
so use plain `sudo`):
```bash
sudo bowery key info /var/lib/bowery/identity.key
#   fingerprint: <64-hex>
#   pubkey_b64:  <base64>
```
The installer also prints this at the end of `install-agent.sh`. (The
journal line above has the fingerprint but not the pubkey.)

## Step 5 — connect from your laptop

Use the Pi's tailnet name (MagicDNS) or `100.x` address:
```bash
bowery exec sql \
    --operator-key ~/.bowery/operator.key \
    --agent-addr   pi5:9902 \
    --agent-fp     <node-fingerprint> \
    --agent-pubkey-b64 <node-pubkey_b64> \
    --sql 'SELECT pretty_name FROM os_version'
```
Or drive it interactively:
```bash
bowery-console \
    --operator-key ~/.bowery/operator.key \
    --agent-addr   pi5:9902 \
    --agent-fp     <node-fingerprint> \
    --agent-pubkey-b64 <node-pubkey_b64>
```

Tailscale gives clean end-to-end `100.x` addressing (WireGuard, no
NAT source-IP rewriting), so the QUIC transport works without the
ECN / source-address quirks you hit over the Hyper-V/WSL2 path.

## Hardening: restrict the ports to the tailnet

The config binds `0.0.0.0:9901-9902` for start-up robustness (binding
a specific `100.x` IP fails if the agent starts before Tailscale
assigns it). The agent's own mTLS + key-pinning already reject anyone
without a pinned cert, but for defense-in-depth restrict the ports to
the `tailscale0` interface. With `ufw`:
```bash
sudo ufw allow in on tailscale0 to any port 9901:9902 proto udp
sudo ufw deny 9901:9902/udp
```
Or nftables (allow only the tailnet 100.64.0.0/10 range):
```bash
sudo nft add rule inet filter input udp dport 9901-9902 ip saddr != 100.64.0.0/10 drop
```
Apply firewall rules carefully on a remote box — don't lock yourself
out of SSH.

## Troubleshooting

**`bowery-agent.service: Main process exited, code=killed, status=31/SYS`**
(restart-looping right after "starting agent"). `status=31/SYS` is
SIGSYS — the systemd unit's `SystemCallFilter` rejected a syscall. The
known cause is **`fchown`**: the agent runs as root and its SQLite
baseline `fchown()`s its WAL/SHM (or journal) to the DB owner when
root, but `fchown` isn't in `@system-service`. Both the current fleet
unit and this kit's drop-in (`10-remote-node.conf`) re-allow the
`@chown` family. If you're on an older unit without it, add the
drop-in manually:
The shipped drop-in carries three directives, not just `@chown` — the
other two matter on a KRSI host (the eBPF load path calls `bpf(2)` and
`perf_event_open(2)`, both in the denied `@privileged` group) and for
`/proc` enrichment of other users' processes:
```bash
sudo mkdir -p /etc/systemd/system/bowery-agent.service.d
sudo tee /etc/systemd/system/bowery-agent.service.d/10-remote-node.conf <<'EOF'
[Service]
SystemCallFilter=@chown
SystemCallFilter=bpf perf_event_open
CapabilityBoundingSet=CAP_SYS_PTRACE
EOF
sudo systemctl daemon-reload && sudo systemctl restart bowery-agent
```
(Or just install `deploy/remote/10-remote-node.conf` from the kit.)
Every other sandbox control (ProtectSystem, NoNewPrivileges,
RestrictAddressFamilies, MemoryDenyWriteExecute, capability bounding)
stays in force. If a node still SIGSYS-dies on a *different* syscall,
capture it and add that group too (last resort: a bare
`SystemCallFilter=` clears the whole list):
```bash
sudo journalctl -k -b | grep -iE "seccomp|audit.*syscall=" | tail
# arch=c00000b7 → aarch64 ; map the number via `ausyscall aarch64 <n>`
```

**`bowery doctor` says BPF-LSM not ready.** Expected on a stock Pi —
see the top of this README. The agent runs degraded (SQL + alerts).

**`libc.so.6: version 'GLIBC_2.xx' not found`** when running a bundled
binary. You packaged a dynamically-linked `…-gnu` build whose glibc is
newer than the Pi's. `package-agent.sh` now defaults to a **static musl
target** (no glibc dependency, runs on any Pi OS version) — re-run it
and redeploy. `file bowery-agent` should say `statically linked`.

## Upgrading

Re-run steps 2–3. The installer overwrites the binary and reloads
systemd; your config and identity key are preserved.

## Uninstall

```bash
sudo systemctl disable --now bowery-agent
sudo rm -f /usr/bin/bowery-agent \
           /lib/systemd/system/bowery-agent.service \
           /lib/systemd/system/bowery.slice
sudo systemctl daemon-reload
# state (identity, baseline) is under /var/lib/bowery — remove if desired.
```

## Quick smoke-test without packaging (dev only)

If you just want to bring the agent up on the Pi from source to try
it, and the Pi has a Rust toolchain, `scripts/xtest` drives any
SSH-reachable host:
```bash
XTEST_HOST=<pi-tailnet-ip> XTEST_USER=<you> ./scripts/xtest run-agent --no-bpf
```
That builds on the Pi and runs from `target/release` under sudo — fine
for a smoke test, but use the packaged install above for a real
deployment (systemd-managed, dedicated user, no source tree).
