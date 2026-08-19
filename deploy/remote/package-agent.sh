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
    echo "  build it:  ./scripts/build-ebpf" >&2
    echo "" >&2
    echo "  If the bpf-linker/LLVM setup is not working on this machine, you do" >&2
    echo "  NOT need to fix it here. The object targets bpfel-unknown-none and" >&2
    echo "  is architecture-neutral, so any host with a working toolchain can" >&2
    echo "  build it for the whole fleet:" >&2
    echo "    scp <buildhost>:.../crates/bowery-ebpf/target/bpfel-unknown-none/release/bowery-ebpf \\\\" >&2
    echo "        $EBPF_OBJ" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# A real .deb, so the agent's own binaries are not the loudest thing it
# reports.
#
# `install`ing a binary into /usr/bin leaves it owned by no package, so
# package provenance classifies it Unpackaged and rarity scores its first
# execution 1.00. On the live fleet that made `/usr/bin/bowery` — our own
# CLI — the highest-suspicion alert on the host. The detection was right;
# a scp'd binary in /usr/bin genuinely is the shape it exists to find. The
# deploy method was wrong.
#
# Built with dpkg-deb rather than cargo-deb: no extra toolchain, and
# cross-arch is one `Architecture:` line. What matters is DEBIAN/md5sums,
# which dpkg installs to /var/lib/dpkg/info/<pkg>.md5sums — the exact file
# PackageIndex reads. That is what makes these binaries PackagedIntact,
# and it is also what makes a *modified* one a finding afterwards.
# ---------------------------------------------------------------------------
build_deb() {
    command -v dpkg-deb >/dev/null 2>&1 || {
        echo "note: dpkg-deb not found; skipping .deb (tarball still built)." >&2
        echo "      The tarball installer works, but leaves the agent's own" >&2
        echo "      binaries unpackaged, which makes them alert on themselves." >&2
        return 0
    }
    case "$TARGET" in
        aarch64-*) DEB_ARCH=arm64 ;;
        x86_64-*)  DEB_ARCH=amd64 ;;
        armv7-*)   DEB_ARCH=armhf ;;
        *) echo "note: no Debian arch mapping for $TARGET; skipping .deb" >&2; return 0 ;;
    esac

    local root="$DIST/deb-$TARGET"
    rm -rf "$root"
    install -d -m 0755 "$root/DEBIAN" "$root/usr/bin" "$root/usr/lib/bowery" \
                       "$root/lib/systemd/system" "$root/etc/bowery"
    install -m 0755 "$BIN"                              "$root/usr/bin/bowery-agent"
    install -m 0755 "$CLI"                              "$root/usr/bin/bowery"
    install -m 0644 "$EBPF_OBJ"                         "$root/usr/lib/bowery/bowery-ebpf"
    install -m 0644 deploy/systemd/bowery-agent.service "$root/lib/systemd/system/bowery-agent.service"
    install -m 0644 deploy/systemd/bowery.slice         "$root/lib/systemd/system/bowery.slice"
    install -m 0644 deploy/remote/agent.toml            "$root/etc/bowery/agent.toml.example"

    cat > "$root/DEBIAN/control" <<EOF
Package: bowery-agent
Version: $DEB_VERSION
Section: admin
Priority: optional
Architecture: $DEB_ARCH
Maintainer: The Bowery <noreply@example.invalid>
Depends: adduser
Description: The Bowery distributed EDR agent
 Each agent observes its host via eBPF, scores anomalies with a local
 rule + baseline pipeline, and validates findings against neighbour
 agents over a peer-to-peer mesh. No central backend.
EOF
    echo "/etc/bowery/agent.toml.example" > "$root/DEBIAN/conffiles"

    # The whole reason for building a package at all. Paths are relative
    # with no leading slash, two spaces between digest and path — dpkg's
    # format, and what PackageIndex parses.
    ( cd "$root" && find usr lib etc -type f -print0 \
        | LC_ALL=C sort -z \
        | xargs -0 md5sum > DEBIAN/md5sums )

    # The agent runs as its own user and the unit must survive an
    # upgrade-in-place, exactly as install-agent.sh arranges.
    cat > "$root/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
getent group bowery >/dev/null 2>&1 || addgroup --system bowery
getent passwd bowery >/dev/null 2>&1 || \
    adduser --system --ingroup bowery --home /var/lib/bowery \
            --no-create-home --shell /usr/sbin/nologin bowery
install -d -m 0750 -o bowery -g bowery /var/lib/bowery /var/log/bowery
install -d -m 0755 /etc/bowery

# A tarball install left the eBPF object at /usr/local/lib/bowery, and
# the loader searches that path BEFORE /usr/lib. Left in place it would
# silently shadow the one this package just installed, so the agent would
# keep running the old object after an upgrade that appeared to succeed.
# Moved aside rather than deleted — it is not ours to destroy, and the
# suffix says what happened.
STALE=/usr/local/lib/bowery/bowery-ebpf
if [ -f "$STALE" ]; then
    mv "$STALE" "$STALE.superseded-by-dpkg"
    echo "note: moved $STALE aside; it would have shadowed the packaged object" >&2
fi
systemctl daemon-reload >/dev/null 2>&1 || true
EOF
    chmod 0755 "$root/DEBIAN/postinst"

    DEB="$DIST/bowery-agent_${DEB_VERSION}_${DEB_ARCH}.deb"
    dpkg-deb --root-owner-group --build "$root" "$DEB" >/dev/null
    echo "built: $DEB"
}

STAGE_NAME="bowery-agent-$TARGET"
DIST="deploy/remote/dist"
STAGE="$DIST/$STAGE_NAME"
rm -rf "$STAGE"
mkdir -p "$STAGE"

DEB_VERSION="$(grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')"
build_deb

echo "==> staging $STAGE"
install -m 0755 "$BIN"                                   "$STAGE/bowery-agent"
install -m 0755 "$CLI"                                   "$STAGE/bowery"
install -m 0644 "$EBPF_OBJ"                              "$STAGE/bowery-ebpf"
install -m 0644 deploy/systemd/bowery-agent.service      "$STAGE/bowery-agent.service"
install -m 0644 deploy/systemd/bowery.slice              "$STAGE/bowery.slice"
install -m 0644 deploy/remote/10-remote-node.conf        "$STAGE/10-remote-node.conf"
install -m 0644 deploy/remote/agent.toml                 "$STAGE/agent.toml"
install -m 0755 deploy/remote/install-agent.sh           "$STAGE/install-agent.sh"

# Name the .deb this tarball ships, so the installer does not have to
# guess. It used to guess with `ls | head -1`, and since `tar` leaves
# previously-extracted .debs in place, the oldest version won on every
# upgrade — three deployments in a row installed 0.0.1 over 0.0.1 and
# reported success.
printf 'BOWERY_DEB=%s\nBOWERY_VERSION=%s\n' \
    "$(basename "$DEB")" "$DEB_VERSION" > "$STAGE/manifest.env"
chmod 0644 "$STAGE/manifest.env"
install -m 0644 deploy/remote/README.md                  "$STAGE/README.md"
# Ship the .deb inside the tarball: install-agent.sh prefers it when
# dpkg is present, which is what stops the agent alerting on its own
# binaries.
if [[ -n "${DEB:-}" && -f "$DEB" ]]; then
    install -m 0644 "$DEB" "$STAGE/$(basename "$DEB")"
fi

TARBALL="$DIST/$STAGE_NAME.tar.gz"
tar -C "$DIST" -czf "$TARBALL" "$STAGE_NAME"
echo
echo "built: $TARBALL"
echo "binary: $(file -b "$STAGE/bowery-agent" 2>/dev/null || echo "$BIN")"
echo
echo "Next:"
echo "  scp $TARBALL <pi-tailscale-name>:"
echo "  ssh <pi-tailscale-name> 'tar xzf $STAGE_NAME.tar.gz && sudo ./$STAGE_NAME/install-agent.sh --operator-pubkey <your-b64>'"
