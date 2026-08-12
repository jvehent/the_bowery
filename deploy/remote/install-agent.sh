#!/usr/bin/env bash
# install-agent.sh — install the Bowery agent on a remote node from a
# staged tarball (produced by package-agent.sh). Idempotent; safe to
# re-run for upgrades. Mirrors the .deb maintainer scripts but works
# on any systemd distro and any arch (it just installs the files it's
# shipped with).
#
# Run ON the target node as root:
#   sudo ./install-agent.sh --operator-pubkey <b64> [options]
#
# Options:
#   --operator-pubkey <b64>   Operator verifying key allowed to query
#                             this node (from `bowery key info` on your
#                             laptop). Required to actually use the node.
#   --whisper-bind <addr>     Operator-facing QUIC bind. Default
#                             0.0.0.0:9902. Use a 100.x tailnet IP for
#                             least exposure (see README on the ordering
#                             caveat).
#   --mesh-listen <addr>      Chitchat bind. Default 0.0.0.0:9901.
#   --cluster-id <name>       Mesh cluster id. Default bowery-tailnet.
#   --start                   Enable + start the service now. Implied
#                             when --operator-pubkey is a real key.
#   --no-start                Install only; don't enable/start.
#   --strict-syscalls         Skip the syscall-filter drop-in. By default a
#                             drop-in re-allows the @chown family, which the
#                             root agent needs (SQLite fchown()s its WAL/SHM
#                             as root) — without it the agent is SIGSYS-killed
#                             at startup (status=31/SYS). Use --strict-syscalls
#                             only if your unit already allows @chown.
#   -h, --help                This help.

set -euo pipefail

WHISPER_BIND="0.0.0.0:9902"
MESH_LISTEN="0.0.0.0:9901"
CLUSTER_ID="bowery-tailnet"
OPERATOR_PUBKEY=""
DO_START="auto"
STRICT_SYSCALLS="no"

die() { echo "error: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --operator-pubkey) OPERATOR_PUBKEY="${2:?}"; shift 2 ;;
        --whisper-bind)    WHISPER_BIND="${2:?}";    shift 2 ;;
        --mesh-listen)     MESH_LISTEN="${2:?}";     shift 2 ;;
        --cluster-id)      CLUSTER_ID="${2:?}";      shift 2 ;;
        --start)           DO_START="yes";           shift ;;
        --no-start)        DO_START="no";            shift ;;
        --strict-syscalls) STRICT_SYSCALLS="yes";    shift ;;
        -h|--help)         sed -n '2,34p' "$0";      exit 0 ;;
        *) die "unknown flag: $1 (see --help)" ;;
    esac
done

[[ $EUID -eq 0 ]] || die "must run as root (use sudo)"

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Two supported layouts:
#   1. Packaged tarball  — every file sits next to this script.
#   2. Repo checkout      — this script is at deploy/remote/, the systemd
#      units are at deploy/systemd/, and the freshly-built binaries are
#      at target/release/. Resolve either.
REPO="$(cd "$SRC/../.." 2>/dev/null && pwd || echo "$SRC")"
pick() { local p; for p in "$@"; do [[ -f "$p" ]] && { printf '%s' "$p"; return 0; }; done; printf '%s' "$1"; }

BIN="$(pick "$SRC/bowery-agent"          "$REPO/target/release/bowery-agent")"
CLI="$(pick "$SRC/bowery"                "$REPO/target/release/bowery")"
EBPF="$(pick "$SRC/bowery-ebpf" \
             "$REPO/crates/bowery-ebpf/target/bpfel-unknown-none/release/bowery-ebpf")"
SVC="$(pick "$SRC/bowery-agent.service"  "$REPO/deploy/systemd/bowery-agent.service")"
SLICE="$(pick "$SRC/bowery.slice"        "$REPO/deploy/systemd/bowery.slice")"
CFG_TEMPLATE="$SRC/agent.toml"
DROPIN="$SRC/10-remote-node.conf"

for f in "$BIN" "$SVC" "$SLICE" "$CFG_TEMPLATE" "$DROPIN"; do
    [[ -f "$f" ]] || die "missing file: $f
       run from the extracted tarball, or from a repo checkout after \`cargo build --release\`"
done

# Sanity: refuse to install an x86_64 binary on an arm host, etc.
if command -v file >/dev/null 2>&1; then
    host_arch="$(uname -m)"
    bin_desc="$(file -b "$BIN" || true)"
    case "$host_arch:$bin_desc" in
        aarch64:*x86-64*|arm*:*x86-64*|x86_64:*aarch64*)
            die "binary arch mismatch: host is $host_arch but $BIN is: $bin_desc
       rebuild for the right target (see package-agent.sh)" ;;
    esac
fi

echo "==> creating bowery system user + directories"
getent group bowery >/dev/null 2>&1 || groupadd --system bowery
getent passwd bowery >/dev/null 2>&1 || \
    useradd --system --gid bowery --home-dir /var/lib/bowery \
            --no-create-home --shell /usr/sbin/nologin \
            --comment "Bowery agent" bowery
install -d -m 0750 -o bowery -g bowery /var/lib/bowery
install -d -m 0750 -o bowery -g bowery /var/log/bowery
install -d -m 0755 /etc/bowery

echo "==> installing binary + unit"
install -m 0755 "$BIN"   /usr/bin/bowery-agent

# The eBPF object. Optional — an agent without it still meshes, alerts
# on operator file rules, and serves SQL — but it observes no kernel
# events at all, which is most of the point. Absence is therefore loud.
#
# root-owned 0644 is not incidental: the loader refuses any object whose
# owner is not root, on the grounds that loading a BPF program a
# lower-privileged user could have edited is full kernel-memory access.
# `install` here runs as root, so this is the correct ownership by
# construction — but a hand-copied object under a user account will be
# rejected at startup, with that reason in the log.
if [[ -f "$EBPF" ]]; then
    echo "==> installing eBPF object"
    install -d -m 0755 /usr/local/lib/bowery
    install -o root -g root -m 0644 "$EBPF" /usr/local/lib/bowery/bowery-ebpf
else
    echo "WARNING: no eBPF object found; this agent will run WITHOUT kernel"
    echo "         events — no exec, exit, or connection monitoring, and an"
    echo "         empty baseline. Build it with ./scripts/build-ebpf and"
    echo "         re-run, or repackage with deploy/remote/package-agent.sh."
fi
install -m 0644 "$SVC"   /lib/systemd/system/bowery-agent.service
install -m 0644 "$SLICE" /lib/systemd/system/bowery.slice

# Operator CLI (resolved above from the tarball or target/release). Handy
# on the node itself for `bowery key info` (to read the node's fingerprint
# + pubkey) and `bowery doctor`. Optional — the agent works without it.
if [[ -f "$CLI" ]]; then
    echo "==> installing bowery CLI"
    install -m 0755 "$CLI" /usr/bin/bowery
fi

# Remote-node drop-in: re-allows the @chown syscall family, which the
# root agent needs (SQLite fchown()s its WAL/SHM as root). Without it
# the strict fleet-unit filter SIGSYS-kills the agent at baseline init.
# All other sandbox controls stay in force. Skip with --strict-syscalls.
if [[ "$STRICT_SYSCALLS" == "yes" ]]; then
    echo "==> --strict-syscalls: NOT installing the @chown syscall drop-in"
    echo "    (if the agent SIGSYS-dies with status=31/SYS, remove --strict-syscalls)"
    rm -f /etc/systemd/system/bowery-agent.service.d/10-remote-node.conf 2>/dev/null || true
else
    echo "==> installing remote-node drop-in (re-allows @chown syscalls)"
    install -d -m 0755 /etc/systemd/system/bowery-agent.service.d
    install -m 0644 "$DROPIN" /etc/systemd/system/bowery-agent.service.d/10-remote-node.conf
fi

CFG=/etc/bowery/agent.toml
if [[ -f "$CFG" ]]; then
    echo "==> keeping existing $CFG (not overwritten)"
    echo "    to re-generate, remove it and re-run this installer"
else
    echo "==> writing $CFG"
    [[ -n "$OPERATOR_PUBKEY" ]] || \
        echo "    WARNING: no --operator-pubkey given; the node will accept" \
             "no operator until you edit $CFG"
    op="${OPERATOR_PUBKEY:-PASTE_OPERATOR_PUBKEY_B64_HERE}"
    sed -e "s|@@WHISPER_BIND@@|$WHISPER_BIND|" \
        -e "s|@@MESH_LISTEN@@|$MESH_LISTEN|" \
        -e "s|@@CLUSTER_ID@@|$CLUSTER_ID|" \
        -e "s|@@OPERATOR_PUBKEY@@|$op|" \
        "$CFG_TEMPLATE" > "$CFG"
    chmod 0644 "$CFG"
fi

systemctl daemon-reload

# Decide whether to start. Real key present → start unless told not to.
have_real_key="no"
if grep -q 'PASTE_OPERATOR_PUBKEY_B64_HERE' "$CFG"; then have_real_key="no"; else have_real_key="yes"; fi
case "$DO_START" in
    yes) start_now="yes" ;;
    no)  start_now="no" ;;
    auto) start_now="$have_real_key" ;;
esac

if [[ "$start_now" == "yes" ]]; then
    # `enable --now` STARTS a stopped service but does nothing at all to
    # a running one, so on an upgrade it silently leaves the old binary
    # and the old eBPF object in memory. That failure is quiet and
    # convincing: the install reports success, the service is "active",
    # and every symptom you were upgrading to fix is still there.
    # Restart explicitly when it is already running.
    if systemctl is-active --quiet bowery-agent.service; then
        echo "==> restarting bowery-agent (upgrade over a running service)"
        systemctl enable bowery-agent.service >/dev/null 2>&1 || true
        systemctl restart bowery-agent.service
    else
        echo "==> enabling + starting bowery-agent"
        systemctl enable --now bowery-agent.service
    fi
    sleep 1
    systemctl --no-pager --lines=8 status bowery-agent.service || true

    # Say plainly whether kernel monitoring came up. The agent degrades
    # to "meshes fine, observes nothing" when the object is missing or
    # the kernel can't load it, and that is far too easy to miss.
    if journalctl -u bowery-agent.service -b --no-pager 2>/dev/null \
        | grep -q "attached BPF event source"; then
        echo "==> kernel event monitoring: ACTIVE"
    else
        echo "WARNING: kernel event monitoring did NOT start — this agent is"
        echo "         observing nothing. Check: journalctl -u bowery-agent | grep -i bpf"
    fi
else
    echo "==> installed but NOT started (no operator key yet)."
    echo "    1. edit $CFG → set [operators] pubkeys_b64"
    echo "    2. systemctl enable --now bowery-agent"
fi

echo
echo "Node identity — pass these to the operator laptop as --agent-fp / --agent-pubkey-b64:"
KEYFILE=/var/lib/bowery/identity.key
if [[ -f "$KEYFILE" ]]; then
    # We are root here, and the key is root-owned 0600 (the service runs
    # as root), so read it directly — no `sudo -u bowery`.
    if command -v bowery >/dev/null 2>&1; then
        bowery key info "$KEYFILE" || true
    else
        echo "  install the 'bowery' CLI on this node, then:"
        echo "     sudo bowery key info $KEYFILE"
        echo "  (fingerprint alone is also in: journalctl -u bowery-agent | grep fingerprint)"
    fi
else
    echo "  identity key not generated yet — created on first start."
    echo "  after starting:  sudo bowery key info $KEYFILE   (or grep the journal for the fp)"
fi
