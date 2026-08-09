#!/usr/bin/env bash
# integration-sql-test — end-to-end smoke test of the operator → agent
# SQL surface. Spins up a local bowery-agent, generates an operator key,
# allow-lists it, runs two queries via `bowery exec sql`, and asserts
# the rows that come back.
#
# Used by CI (.github/workflows/ci.yml) and runnable locally:
#
#     cargo build --release -p bowery-agent -p bowery-cli
#     ./scripts/integration-sql-test.sh
#
# Optional env:
#     BOWERY_BIN=path/to/bowery       (default: target/release/bowery)
#     BOWERY_AGENT_BIN=path/to/agent  (default: target/release/bowery-agent)
#     BOWERY_TEST_DIR=path            (default: /tmp/bowery-integration)
#     BOWERY_TEST_PORT_BASE=N         (default: 19900; uses N+1 mesh, N+2 whisper)

set -euo pipefail

BOWERY_BIN="${BOWERY_BIN:-target/release/bowery}"
BOWERY_AGENT_BIN="${BOWERY_AGENT_BIN:-target/release/bowery-agent}"
TEST_DIR="${BOWERY_TEST_DIR:-/tmp/bowery-integration}"
PORT_BASE="${BOWERY_TEST_PORT_BASE:-19900}"
MESH_PORT=$((PORT_BASE + 1))
WHISPER_PORT=$((PORT_BASE + 2))

if [[ ! -x "$BOWERY_BIN" ]]; then
    echo "error: bowery CLI not found at $BOWERY_BIN" >&2
    echo "       run: cargo build --release -p bowery-cli" >&2
    exit 2
fi
if [[ ! -x "$BOWERY_AGENT_BIN" ]]; then
    echo "error: bowery-agent not found at $BOWERY_AGENT_BIN" >&2
    echo "       run: cargo build --release -p bowery-agent" >&2
    exit 2
fi

cleanup() {
    local rc=$?
    if [[ -f "$TEST_DIR/agent.pid" ]]; then
        local pid
        pid=$(cat "$TEST_DIR/agent.pid")
        kill "$pid" 2>/dev/null || true
        # Drain the agent log to stderr if we failed, so CI logs show why.
        if [[ $rc -ne 0 && -f "$TEST_DIR/agent.log" ]]; then
            echo "--- agent log ---" >&2
            tail -50 "$TEST_DIR/agent.log" >&2
        fi
    fi
}
trap cleanup EXIT

rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR/state" "$TEST_DIR/op"

echo "==> generate operator key"
"$BOWERY_BIN" key generate --out "$TEST_DIR/op/operator.key" >/dev/null
OP_PUBKEY=$("$BOWERY_BIN" key info "$TEST_DIR/op/operator.key" | awk '/^pubkey_b64:/ {print $2}')
[[ -n "$OP_PUBKEY" ]] || { echo "could not read operator pubkey" >&2; exit 1; }

echo "==> write agent config"
cat > "$TEST_DIR/agent.toml" <<EOF
[identity]
path = "$TEST_DIR/state/identity.key"
[known_neighbors]
path = "$TEST_DIR/state/known_neighbors.json"
[mesh]
listen_addr = "127.0.0.1:$MESH_PORT"
[whisper]
bind_addr = "127.0.0.1:$WHISPER_PORT"
[baseline]
path = ":memory:"
[operators]
pubkeys_b64 = ["$OP_PUBKEY"]

# Operator-configurable monitoring. The file rule also drives the
# file-alert check further down (touching \$TEST_DIR/watched.conf).
[monitor]
[[monitor.file_rules]]
id = "watched-conf"
path = "$TEST_DIR/watched.conf"
ops = ["modify"]
severity = "high"

[[monitor.process_rules]]
id = "netcat-exec"
comm = "nc"
arg_substr = "-e"
severity = "high"
EOF

# The watched file must exist before the agent starts so the watch on its
# parent directory is registered against a real target.
touch "$TEST_DIR/watched.conf"

echo "==> start agent (no BPF, mock LLM)"
"$BOWERY_AGENT_BIN" --config "$TEST_DIR/agent.toml" >"$TEST_DIR/agent.log" 2>&1 &
echo $! > "$TEST_DIR/agent.pid"

echo "==> wait for whisper listener on 127.0.0.1:$WHISPER_PORT"
for _ in $(seq 1 60); do
    if ss -lun 2>/dev/null | grep -q "127.0.0.1:$WHISPER_PORT"; then
        break
    fi
    sleep 0.5
done
if ! ss -lun 2>/dev/null | grep -q "127.0.0.1:$WHISPER_PORT"; then
    echo "FAIL: agent did not bind whisper port within 30s" >&2
    exit 1
fi

echo "==> read agent identity"
AGENT_INFO=$("$BOWERY_BIN" key info "$TEST_DIR/state/identity.key")
AGENT_FP=$(echo "$AGENT_INFO" | awk '/^fingerprint:/ {print $2}')
AGENT_PUB=$(echo "$AGENT_INFO" | awk '/^pubkey_b64:/ {print $2}')
[[ -n "$AGENT_FP" && -n "$AGENT_PUB" ]] || {
    echo "could not read agent identity" >&2
    exit 1
}

run_sql() {
    "$BOWERY_BIN" exec sql \
        --operator-key "$TEST_DIR/op/operator.key" \
        --agent-addr "127.0.0.1:$WHISPER_PORT" \
        --agent-fp "$AGENT_FP" \
        --agent-pubkey-b64 "$AGENT_PUB" \
        --sql "$1"
}

# Fan-out against this single agent (no mesh peers). Exercises the
# relay path + the fan-out completion terminator: with a short 3s
# timeout, a regression to the old "hang until timeout" behaviour would
# make this error out instead of returning the local row promptly.
run_sql_fanout() {
    "$BOWERY_BIN" exec sql \
        --operator-key "$TEST_DIR/op/operator.key" \
        --agent-addr "127.0.0.1:$WHISPER_PORT" \
        --agent-fp "$AGENT_FP" \
        --agent-pubkey-b64 "$AGENT_PUB" \
        --fanout --timeout 3s \
        --sql "$1"
}

echo "==> smoke: SELECT 1"
OUT=$(run_sql 'SELECT 1 AS hello')
echo "$OUT"
[[ "$(echo "$OUT" | awk 'NR==2')" == "1" ]] || {
    echo "FAIL: expected row '1', got '$(echo "$OUT" | awk 'NR==2')'" >&2
    exit 1
}

echo "==> exercise os_version table"
OUT=$(run_sql 'SELECT pretty_name FROM os_version')
echo "$OUT"
[[ "$(echo "$OUT" | head -1)" == "pretty_name" ]] || {
    echo "FAIL: expected header 'pretty_name', got '$(echo "$OUT" | head -1)'" >&2
    exit 1
}
[[ "$(echo "$OUT" | wc -l)" -ge 2 ]] || {
    echo "FAIL: expected at least one data row from os_version" >&2
    exit 1
}

echo "==> exercise scalar function"
OUT=$(run_sql "SELECT bowery_file_exists('/etc/passwd') AS x")
echo "$OUT"
[[ "$(echo "$OUT" | awk 'NR==2')" == "1" ]] || {
    echo "FAIL: bowery_file_exists('/etc/passwd') did not return 1" >&2
    exit 1
}

echo "==> exercise bowery_mesh_peers view (registers + queryable)"
# A single agent has no gossip peers, so the view is empty — but it must
# register and be queryable (a broken register() would fail every query).
OUT=$(run_sql 'SELECT COUNT(*) AS n FROM bowery_mesh_peers')
echo "$OUT"
[[ "$(echo "$OUT" | head -1)" == "n" ]] || {
    echo "FAIL: expected header 'n' from bowery_mesh_peers, got '$(echo "$OUT" | head -1)'" >&2
    exit 1
}
[[ "$(echo "$OUT" | awk 'NR==2')" == "0" ]] || {
    echo "FAIL: expected 0 mesh peers for a solo agent, got '$(echo "$OUT" | awk 'NR==2')'" >&2
    exit 1
}

echo "==> exercise bowery_monitor_rules view (operator-configured rules)"
# Both rules from [monitor] in the config above must be listed, so an
# operator can query "what is this agent watching?" over SQL.
OUT=$(run_sql "SELECT kind, rule_id, severity FROM bowery_monitor_rules ORDER BY kind")
echo "$OUT"
echo "$OUT" | grep -q "watched-conf" || {
    echo "FAIL: file rule 'watched-conf' missing from bowery_monitor_rules" >&2
    exit 1
}
echo "$OUT" | grep -q "netcat-exec" || {
    echo "FAIL: process rule 'netcat-exec' missing from bowery_monitor_rules" >&2
    exit 1
}

echo "==> file monitor: changing a watched file raises an alert"
# inotify IN_CLOSE_WRITE on the watched path -> Event::FileChange -> alert.
printf 'tampered\n' > "$TEST_DIR/watched.conf"
ALERTED=0
for _ in $(seq 1 20); do
    N=$(run_sql "SELECT COUNT(*) AS n FROM bowery_alerts WHERE exe_path = '$TEST_DIR/watched.conf'" | awk 'NR==2')
    if [[ "${N:-0}" -ge 1 ]]; then ALERTED=1; break; fi
    sleep 0.5
done
[[ "$ALERTED" == "1" ]] || {
    echo "FAIL: no alert for the watched file within 10s" >&2
    exit 1
}
echo "watched-file alert observed"

echo "==> fan-out with no peers returns local row promptly (terminator, not a 12s hang)"
START=$(date +%s)
OUT=$(run_sql_fanout 'SELECT 1 AS hello')
ELAPSED=$(( $(date +%s) - START ))
echo "$OUT"
# Fan-out output prepends an `_agent_fp` column, so the value is the
# last tab-separated field of the data row.
GOT=$(echo "$OUT" | awk -F'\t' 'NR==2 {print $NF}')
[[ "$GOT" == "1" ]] || {
    echo "FAIL: expected fan-out to return local row value '1', got '$GOT'" >&2
    exit 1
}
[[ "$ELAPSED" -lt 3 ]] || {
    echo "FAIL: 0-peer fan-out took ${ELAPSED}s (expected <3s); terminator likely not sent" >&2
    exit 1
}

echo "==> all integration checks passed"
