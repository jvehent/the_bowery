# Forming a mesh across remote nodes (so `--fanout` works)

By default each remote node is standalone: the operator queries it
directly. Joining several nodes into a **chitchat mesh** lets you send
one query to any node and have it relay to the others:

```bash
bowery exec sql --fanout --sql 'SELECT COUNT(*) FROM processes'
# → one section of rows per agent, attributed by `_agent_name` + `_agent_fp`
```

Fan-out relays only to peers that are BOTH discovered in the gossip
mesh AND pinned. So three things must be true on every node:

1. **Gossip forms** — each node seeds the others' mesh addresses.
2. **Advertised addresses are routable** — a node bound to `0.0.0.0`
   must advertise its `100.x` tailnet address for both mesh (9901) and
   whisper (9902), or peers learn `0.0.0.0` and can't dial back.
3. **Peers get pinned** — pinning happens only while a node's TOFU
   *bootstrap window* is open, so we re-open it during bring-up.

This kit uses trust-on-first-use pinning: within the bootstrap window,
a node pins whoever it discovers in the mesh. Bring all nodes up inside
the window and they pin each other. (There's no static pin list or
runtime add-neighbor command yet.)

> **Requires the mesh-capable agent build** — the one with
> `[whisper] advertise_addr` and the fan-out completion terminator. An
> older agent will (a) reject `advertise_addr` as an unknown config key
> (`deny_unknown_fields`) and (b) hang the operator for the full
> timeout on every fan-out. Redeploy the binary (Step 1) **before**
> editing configs.

---

## Worked example: otter1 + dartagnan + legolas

Substitute your own node names, tailnet IPs, and fingerprints. Get a
node's tailnet IP with `tailscale ip -4`, and its fingerprint from
`journalctl -u bowery-agent | grep 'agent ready'`.

| Node | Tailnet IP | Fingerprint |
|---|---|---|
| otter1 | `100.105.157.53` | `03d14cc1…56cd0328` |
| dartagnan | `100.111.5.24` | `afb99024…dddd934a3` |
| legolas | `100.126.81.123` | `b923ba65…637a30d4` |

Ports: **9901** gossip (mesh), **9902** whisper (QUIC RPC).

---

## Step 1 — redeploy the mesh-capable agent to every node

From your build host (rebuild the static musl binary, then upgrade each
node in place — the installer preserves existing config + identity):

```bash
./deploy/remote/package-agent.sh                       # aarch64 musl tarball
TARBALL=deploy/remote/dist/bowery-agent-aarch64-unknown-linux-musl.tar.gz
for h in otter1 dartagnan legolas; do
  scp "$TARBALL" "$h":
  ssh "$h" 'tar xzf bowery-agent-aarch64-unknown-linux-musl.tar.gz && \
            sudo ./bowery-agent-aarch64-unknown-linux-musl/install-agent.sh \
                 --operator-pubkey <your-operator-pubkey-b64> \
                 --cluster-id my-tailnet'
done
```

**`--cluster-id` must be identical on all three** — nodes with
different cluster ids ignore each other in gossip. (otter1, if it was
installed with a different cluster id, must be reinstalled/edited to
match.)

## Step 2 — edit `/etc/bowery/agent.toml` on each node

On each node, set that node's own advertise addresses and seed it with
the **other two** nodes' mesh addresses. Also widen the bootstrap
window so pinning has time to happen during bring-up.

**otter1** (`sudo $EDITOR /etc/bowery/agent.toml`):
```toml
[known_neighbors]
bootstrap_window = "30m"        # was 5m — re-opened for mesh pinning

[mesh]
seeds = ["100.111.5.24:9901", "100.126.81.123:9901"]
advertise_addr = "100.105.157.53:9901"

[whisper]
advertise_addr = "100.105.157.53:9902"
```

**dartagnan**:
```toml
[known_neighbors]
bootstrap_window = "30m"
[mesh]
seeds = ["100.105.157.53:9901", "100.126.81.123:9901"]
advertise_addr = "100.111.5.24:9901"
[whisper]
advertise_addr = "100.111.5.24:9902"
```

**legolas**:
```toml
[known_neighbors]
bootstrap_window = "30m"
[mesh]
seeds = ["100.105.157.53:9901", "100.111.5.24:9901"]
advertise_addr = "100.126.81.123:9901"
[whisper]
advertise_addr = "100.126.81.123:9902"
```

Leave `listen_addr`/`bind_addr` as the wildcard binds — advertising the
`100.x` address while binding `0.0.0.0` is exactly the point (boot
robustness without an unroutable advertised address).

## Step 3 — re-open the TOFU window on each node

Pinning happens only while a node's bootstrap window is open. The
window is set from `bootstrap_window` at start **and persisted once the
first peer is pinned** — so behaviour depends on whether the pin store
already exists:

- **File absent** (`/var/lib/bowery/known_neighbors.json` doesn't
  exist — the common case for nodes that never formed a mesh): the
  window is recomputed as `now + bootstrap_window` on **every restart**.
  Nothing to do here; the restart in Step 4 opens a fresh window.
- **File present**: it pins the persisted (possibly already-closed)
  window, so wipe it to start fresh:
  ```bash
  for h in otter1 dartagnan legolas; do
    ssh "$h" 'sudo rm -f /var/lib/bowery/known_neighbors.json'
  done
  ```

Either way, make sure `bootstrap_window` (Step 2) is long enough that
all nodes are up together inside it — `30m` is comfortable.

## Step 4 — restart all three within the window

```bash
for h in otter1 dartagnan legolas; do
  ssh "$h" 'sudo systemctl restart bowery-agent'
done
```

Give gossip ~30–60s to converge and pin.

## Step 5 — verify discovery + pinning

Query each node **directly** (no `--fanout`) and look at the mesh view.
Each node should list the other two, with `pinned = 1`:

```bash
bowery exec sql \
  --operator-key ~/.bowery/operator.key \
  --agent-addr 100.105.157.53:9902 \
  --agent-fp 03d14cc1…56cd0328 \
  --agent-pubkey-b64 <otter1-pubkey> \
  --sql 'SELECT fingerprint_hex, whisper_addr, pinned FROM bowery_mesh_peers'
```

Expected on otter1 (2 rows):

```
fingerprint_hex     whisper_addr          pinned
afb99024…dddd934a3  100.111.5.24:9902     1
b923ba65…637a30d4   100.126.81.123:9902   1
```

- **0 rows** → gossip hasn't converged: check seeds, `cluster_id`
  matches, and UDP 9901 is open on `tailscale0` (see Troubleshooting).
- **rows with `whisper_addr = 0.0.0.0:9902`** → the peer didn't set
  `[whisper] advertise_addr` (Step 2). Fan-out to it will fail to dial.
- **`pinned = 0`** → discovered but not pinned: its bootstrap window was
  closed when it discovered this node. Redo Step 3 on that node and
  restart it within the window.

## Step 6 — run the fan-out query

`--fanout` auto-loads `~/.bowery/peers.toml` (already holds all three
pubkeys, so peer response signatures verify). Point it at any node:

```bash
bowery exec sql \
  --operator-key ~/.bowery/operator.key \
  --agent-addr 100.105.157.53:9902 \
  --agent-fp 03d14cc1…56cd0328 \
  --agent-pubkey-b64 <otter1-pubkey> \
  --fanout \
  --sql 'SELECT fingerprint_hex FROM bowery_mesh_peers'
```

You should get rows from all three agents, each row tagged with its
source `_agent_name` + `_agent_fp`, returning promptly (no 12s hang).

---

## Troubleshooting

**`bowery_mesh_peers` is empty on every node.** Gossip never formed.
Check, on each node:
- `sudo ss -lunp | grep 9901` — the mesh socket is bound.
- UDP **9901** is reachable over the tailnet. If you applied the
  firewall hardening, confirm it allows the gossip port too:
  `sudo ufw allow in on tailscale0 to any port 9901:9902 proto udp`.
- `cluster_id` is identical across nodes (`grep cluster_id
  /etc/bowery/agent.toml`).
- `seeds` point at the *other* nodes' `100.x:9901` (not `0.0.0.0`, not
  self).

**Discovered but `whisper_addr = 0.0.0.0:9902`.** The peer is on an old
binary or didn't set `[whisper] advertise_addr`. Redeploy Step 1 and
set Step 2 on that node.

**Discovered, `pinned = 0`, won't pin.** The node's bootstrap window is
closed. `bootstrap_active` is persisted; `rm known_neighbors.json` +
restart re-opens it. Make sure `bootstrap_window` is long enough that
all nodes are up simultaneously inside it.

**Fan-out still slow / partial.** Confirm each addressed peer is
reachable on its own with `bowery peers check`. A peer that's
discovered+pinned but whose `whisper_addr` isn't dialable (wrong
advertise, firewall) will just be missing from the results.

**Agent won't start after editing config**
(`unknown field 'advertise_addr'`). The node is still on the old
binary. Redeploy Step 1 first, then edit the config.
