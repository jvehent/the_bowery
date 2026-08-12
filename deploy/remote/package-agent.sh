#!/usr/bin/env bash
# package-agent.sh — cross-compile the Bowery agent and assemble a
# self-contained install tarball for a remote node (default target:
# 64-bit Raspberry Pi / aarch64, statically linked against musl).
#
# Why musl (static): the binaries have NO glibc dependency, so they
# run on any Pi OS version regardless of its glibc. A dynamically
# linked (…-gnu) build fails at runtime on an older Pi with
# `GLIBC_2.xx not found` when the build image's glibc is newer than
# the target's. musl sidesteps that entirely.
#
# Run ON YOUR LAPTOP (the build host):
#   ./deploy/remote/package-agent.sh                 # aarch64 musl (Pi 3/4/5, 64-bit OS)
#   ./deploy/remote/package-agent.sh armv7-unknown-linux-musleabihf   # 32-bit Pi OS
#
# Requires `cross` (Docker-based; no local cross-linker needed):
#   cargo install cross --git https://github.com/cross-rs/cross
# Docker or Podman must be running.
#
# NOTE ON YARA: the agent's `yara` feature is deliberately NOT enabled
# for this cross-build. The `yara-sys` crate ships no pre-generated
# libyara bindings for aarch64-unknown-linux-musl, and its bindgen
# fallback doesn't engage for that target, so the build fails in the
# build script. libyara itself cross-compiles fine — it's the bindings
# that are missing. Options if you want scanning on a Pi:
#   1. Build natively ON the Pi (slow but works; needs clang):
#        sudo apt install -y clang libclang-dev build-essential
#        YARA_CRYPTO_LIB=disable cargo build --release -p bowery-agent \
#            --features yara
#   2. Leave it off. The agent still stores and PROPAGATES rules across
#      the mesh; it just reports `engine not compiled in` instead of
#      scanning, so distribution to the Pis still works.
#
# Output: deploy/remote/dist/bowery-agent-<target>.tar.gz
# The tarball extracts to a directory containing the binaries, the
# systemd unit + slice, the config template, and install-agent.sh.

set -euo pipefail

TARGET="${1:-aarch64-unknown-linux-musl}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

command -v cross >/dev/null 2>&1 || {
    echo "error: 'cross' not found. Install it (Docker required):" >&2
    echo "  cargo install cross --git https://github.com/cross-rs/cross" >&2
    exit 1
}

echo "==> cross build bowery-agent + bowery CLI for $TARGET (default features = mock LLM)"
# No --features llm-llama-cpp: llama.cpp cross-compilation is heavy and
# a low-RAM Pi shouldn't run local inference. Mock analyzer + rule +
# baseline scoring + the full SQL surface all work without it. The CLI
# is bundled so the node can print its own fingerprint + pubkey
# (`bowery key info`) and run `bowery doctor` locally.
cross build --release --target "$TARGET" -p bowery-agent -p bowery-cli --locked

BIN="target/$TARGET/release/bowery-agent"
CLI="target/$TARGET/release/bowery"
[[ -f "$BIN" ]] || { echo "error: build produced no agent binary at $BIN" >&2; exit 1; }
[[ -f "$CLI" ]] || { echo "error: build produced no CLI binary at $CLI" >&2; exit 1; }

# The eBPF object. NOT cross-compiled, and deliberately not built here:
# its target is `bpfel-unknown-none` — BPF bytecode, little-endian
# variant — which has no host-arch component at all. One object is valid
# on every little-endian Linux host, x86_64 and aarch64 alike, and the
# structs it shares with the loader use only fixed-width types, so
# `#[repr(C)]` layout matches on both. Verified by loading an
# x86_64-built object on an aarch64 Pi 5 and capturing real events.
#
# Shipping it matters more than it looks: without it the agent falls
# back to NoopEventSource and runs as a mesh node that observes nothing
# — no execs, no baseline, no rules. Two Pis ran that way for days,
# and because an empty baseline answered "never seen it" to every
# whisper question, they quorum-confirmed every alert their neighbour
# raised. A missing file, not a missing feature.
EBPF_OBJ="crates/bowery-ebpf/target/bpfel-unknown-none/release/bowery-ebpf"
if [[ ! -f "$EBPF_OBJ" ]]; then
    echo "error: no eBPF object at $EBPF_OBJ" >&2
    echo "  build it first:  ./scripts/build-ebpf" >&2
    echo "  (it is architecture-neutral — build once, ship to every node)" >&2
    exit 1
fi

STAGE_NAME="bowery-agent-$TARGET"
DIST="deploy/remote/dist"
STAGE="$DIST/$STAGE_NAME"
rm -rf "$STAGE"
mkdir -p "$STAGE"

echo "==> staging $STAGE"
install -m 0755 "$BIN"                                   "$STAGE/bowery-agent"
install -m 0755 "$CLI"                                   "$STAGE/bowery"
install -m 0644 "$EBPF_OBJ"                              "$STAGE/bowery-ebpf"
install -m 0644 deploy/systemd/bowery-agent.service      "$STAGE/bowery-agent.service"
install -m 0644 deploy/systemd/bowery.slice              "$STAGE/bowery.slice"
install -m 0644 deploy/remote/10-remote-node.conf        "$STAGE/10-remote-node.conf"
install -m 0644 deploy/remote/agent.toml                 "$STAGE/agent.toml"
install -m 0755 deploy/remote/install-agent.sh           "$STAGE/install-agent.sh"
install -m 0644 deploy/remote/README.md                  "$STAGE/README.md"

TARBALL="$DIST/$STAGE_NAME.tar.gz"
tar -C "$DIST" -czf "$TARBALL" "$STAGE_NAME"
echo
echo "built: $TARBALL"
echo "binary: $(file -b "$STAGE/bowery-agent" 2>/dev/null || echo "$BIN")"
echo
echo "Next:"
echo "  scp $TARBALL <pi-tailscale-name>:"
echo "  ssh <pi-tailscale-name> 'tar xzf $STAGE_NAME.tar.gz && sudo ./$STAGE_NAME/install-agent.sh --operator-pubkey <your-b64>'"
