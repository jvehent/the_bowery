/* The Bowery — browser console.
 *
 * One rule runs through this file: nothing from the API is ever
 * assigned to innerHTML. Every value here — a rationale, an argv, a
 * path, a peer's verdict — was written by, or shaped by, a process on
 * a monitored host. That is the same trust boundary the notification
 * email draws, and it is drawn here by construction: `el()` sets
 * textContent, and the only markup is built from literals in this
 * file.
 */
'use strict';

const $ = (sel) => document.querySelector(sel);
const state = { pane: 'query', alerts: [], selected: null, mesh: null, sim: null };

/* ---------- tiny DOM helpers (textContent only) ---------- */

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = String(text);
  return n;
}
function svgEl(tag, attrs) {
  const n = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const k in attrs) n.setAttribute(k, attrs[k]);
  return n;
}
function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

/* ---------- status + fetch ---------- */

function setStatus(kind, text) {
  const s = $('#status');
  s.className = 'status' + (kind ? ' ' + kind : '');
  $('#status-text').textContent = text;
}

async function api(path, opts) {
  setStatus('busy', 'working…');
  try {
    const res = await fetch(path, opts);
    const body = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
    if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
    setStatus('ok', 'ok');
    return body;
  } catch (e) {
    setStatus('err', String(e.message || e));
    throw e;
  }
}
const getJSON = (p) => api(p);
const postJSON = (p, body) => api(p, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify(body),
});

function showError(container, e) {
  clear(container);
  container.appendChild(el('pre', 'err', String(e.message || e)));
}

/* ---------- table rendering ---------- */

function renderTable(container, table) {
  clear(container);
  if (!table.columns.length) {
    container.appendChild(el('p', 'muted', 'no columns returned'));
    return;
  }
  const multiAgent = table.agents.some((a) => a !== '');
  const t = el('table');
  const thead = el('thead');
  const hr = el('tr');
  if (multiAgent) hr.appendChild(el('th', null, 'agent'));
  table.columns.forEach((c) => hr.appendChild(el('th', null, c)));
  thead.appendChild(hr);
  t.appendChild(thead);

  const tb = el('tbody');
  table.rows.forEach((row, i) => {
    const tr = el('tr');
    if (multiAgent) tr.appendChild(el('td', 'agentcol', table.agents[i] || '—'));
    row.forEach((v) => {
      if (v === null) { tr.appendChild(el('td', 'null', 'NULL')); return; }
      const num = typeof v === 'number';
      tr.appendChild(el('td', num ? 'num' : null, num ? v : String(v)));
    });
    tb.appendChild(tr);
  });
  t.appendChild(tb);
  container.appendChild(t);
  if (!table.rows.length) container.appendChild(el('p', 'muted', 'no rows'));
}

async function loadTable(container, name, fanout) {
  try {
    const q = `/api/table/${encodeURIComponent(name)}?limit=500${fanout ? '&fanout=true' : ''}`;
    renderTable(container, await getJSON(q));
  } catch (e) { showError(container, e); }
}

/* ---------- Query pane ---------- */

const EXAMPLES = [
  ['detections that fired', 'SELECT rule_id, fired, fired_since_install FROM bowery_detections WHERE fired > 0 ORDER BY fired DESC'],
  ['sensor health', 'SELECT probe, attached, emitted, kernel_drops, stopped_reason FROM bowery_probe_status'],
  ['corroboration', 'SELECT * FROM bowery_corroboration_status'],
  ['live alerts', 'SELECT rule_id, suspicion, exe_path, backend, model_explanation FROM bowery_alerts ORDER BY ts_unix_ms DESC LIMIT 30'],
  ['recent execs', "SELECT pid, comm, exe_path, substr(args,1,80) AS args FROM bowery_events WHERE kind='exec' ORDER BY ts_unix_ms DESC LIMIT 40"],
  ['outbound peers', 'SELECT addr, port, seen_count, last_seen_unix FROM bowery_net_destinations ORDER BY seen_count DESC LIMIT 30'],
];

function buildExamples() {
  const box = $('#q-examples');
  EXAMPLES.forEach(([label, sql]) => {
    const c = el('button', 'chip', label);
    c.addEventListener('click', () => { $('#q-sql').value = sql; runQuery(); });
    box.appendChild(c);
  });
}

async function runQuery() {
  const out = $('#q-result');
  try {
    renderTable(out, await postJSON('/api/query', {
      sql: $('#q-sql').value,
      fanout: $('#q-fanout').checked,
    }));
  } catch (e) { showError(out, e); }
}

/* ---------- Alerts ---------- */

function sevClass(s) { return s >= 0.8 ? 'hi' : (s >= 0.5 ? 'md' : 'lo'); }
function when(ms) {
  const d = new Date(ms);
  return isNaN(d) ? '—' : d.toISOString().replace('T', ' ').slice(0, 19) + 'Z';
}

async function loadAlerts() {
  const list = $('#a-list');
  try {
    const p = new URLSearchParams({ limit: '300' });
    const text = $('#a-text').value.trim();
    if (text) p.set('text', text);
    if ($('#a-confirmed').checked) p.set('confirmed_only', 'true');
    state.alerts = await getJSON('/api/alerts?' + p.toString());
    clear(list);
    if (!state.alerts.length) { list.appendChild(el('p', 'muted', 'nothing archived matches')); return; }
    state.alerts.forEach((a) => {
      const row = el('div', 'arow');
      row.dataset.episode = a.episode_id;
      const r1 = el('div', 'r1');
      r1.appendChild(el('span', 'sev ' + sevClass(a.suspicion), a.suspicion.toFixed(2)));
      r1.appendChild(el('span', 'rule', a.rule_id || '(no rule)'));
      r1.appendChild(el('span', 'when', when(a.ts_unix_ms)));
      row.appendChild(r1);
      const sub = [a.agent_name || a.agent_fp.slice(0, 12), a.exe_path || ''].filter(Boolean).join(' · ');
      row.appendChild(el('div', 'sub', sub));
      row.addEventListener('click', () => selectAlert(a.episode_id, row));
      list.appendChild(row);
    });
  } catch (e) { showError(list, e); }
}

async function selectAlert(episode, row) {
  document.querySelectorAll('.arow.sel').forEach((n) => n.classList.remove('sel'));
  if (row) row.classList.add('sel');
  const pane = $('#a-detail');
  try {
    const versions = await getJSON('/api/alerts/' + encodeURIComponent(episode));
    state.selected = versions;
    renderAlertDetail(pane, versions);
  } catch (e) { showError(pane, e); }
}

function dl(parent, pairs) {
  const d = el('dl', 'kv');
  pairs.forEach(([k, v]) => {
    if (v === null || v === undefined || v === '') return;
    d.appendChild(el('dt', null, k));
    d.appendChild(el('dd', null, v));
  });
  parent.appendChild(d);
}

function renderAlertDetail(pane, versions) {
  clear(pane);
  // The newest version is what an operator acts on; the earlier ones
  // are how it got there, and the timeline below keeps them.
  const a = versions[versions.length - 1];

  const head = el('div');
  const h = el('h2');
  h.appendChild(el('span', 'sev ' + sevClass(a.suspicion), a.suspicion.toFixed(2)));
  h.appendChild(document.createTextNode(' '));
  h.appendChild(document.createTextNode(a.rule_id || '(no rule)'));
  h.style.margin = '0 0 4px';
  h.style.fontSize = '15px';
  head.appendChild(h);
  head.appendChild(el('div', 'muted', when(a.ts_unix_ms) + ' · ' + (a.agent_name || a.agent_fp)));
  pane.appendChild(head);

  dl(pane, [
    ['episode', a.episode_id],
    ['exe', a.exe_path],
    ['sha256', a.exe_sha256],
    ['analyser', a.backend],
  ]);

  // What the rule found. Kept apart from what the model said, because
  // one is a measurement and the other is an inference.
  const why = el('div', 'block');
  why.appendChild(el('h3', null, 'what the host saw'));
  why.appendChild(el('div', null, a.rationale || '(no rationale)'));
  pane.appendChild(why);

  if (a.model_explanation) {
    const m = el('div', 'block');
    m.appendChild(el('h3', null, 'what the local model made of it'));
    const box = el('div', 'saidby');
    box.appendChild(el('span', 'who', a.backend || 'model'));
    box.appendChild(document.createTextNode(a.model_explanation));
    m.appendChild(box);
    pane.appendChild(m);
  }

  renderWhisper(pane, a);

  // Context, minus the peer verdicts already drawn above.
  const ctx = Object.entries(a.context).filter(([k]) => !k.startsWith('peer.'));
  if (ctx.length) {
    const c = el('div', 'block');
    c.appendChild(el('h3', null, 'triage context'));
    const d = el('dl', 'kv');
    ctx.forEach(([k, v]) => { d.appendChild(el('dt', null, k)); d.appendChild(el('dd', null, v)); });
    c.appendChild(d);
    pane.appendChild(c);
  }

  if (versions.length > 1) {
    const t = el('div', 'block');
    t.appendChild(el('h3', null, `how this episode developed (${versions.length} writes)`));
    const ul = el('ul', 'timeline');
    versions.forEach((v) => {
      const li = el('li');
      li.appendChild(el('span', 'sev ' + sevClass(v.suspicion), v.suspicion.toFixed(2)));
      li.appendChild(document.createTextNode(' ' + (v.rule_id || '') + ' — ' + when(v.ts_unix_ms)));
      ul.appendChild(li);
    });
    t.appendChild(ul);
    pane.appendChild(t);
  }
}

/* ---------- the whisper round, drawn ----------
 *
 * Hub and spoke, not a force layout: the shape of this question is
 * fixed — one host asked, N peers answered — and a simulation would
 * move it around for no information. The edge tells you the stance,
 * the label tells you the sentence the peer actually sent.
 */
function renderWhisper(pane, a) {
  const asked = a.peers_asked || 0;
  const block = el('div', 'block');
  block.appendChild(el('h3', null, 'what the neighbourhood said'));

  if (!asked && !a.peer_verdicts.length) {
    block.appendChild(el('p', 'muted',
      'No whisper round ran for this alert. That is not the mesh disagreeing — it is the mesh never having been asked.'));
    pane.appendChild(block);
    return;
  }

  const tally = [
    ['same sighting', a.peers_seen, 'seen'],
    ['no record', a.peers_unseen, 'unseen'],
    ['familiar', a.peers_familiar, 'familiar'],
  ].filter(([, n]) => n !== null && n !== undefined);
  const sum = el('div', 'muted');
  sum.textContent = `asked ${asked}` + (tally.length ? ' — ' + tally.map(([l, n]) => `${n} ${l}`).join(', ') : '') +
    (a.confirmed ? ' — quorum reached' : '');
  block.appendChild(sum);

  const W = 520, H = 240, cx = 150, cy = H / 2;
  const svg = svgEl('svg', { viewBox: `0 0 ${W} ${H}`, style: 'height:240px' });

  const peers = a.peer_verdicts;
  const n = Math.max(peers.length, 1);
  peers.forEach((p, i) => {
    // Fan the peers down the right-hand side so long verdicts have
    // room to be read rather than truncated into uselessness.
    const y = n === 1 ? cy : 40 + i * ((H - 80) / (n - 1));
    const x = 330;
    svg.appendChild(svgEl('path', {
      d: `M ${cx + 34} ${cy} C ${cx + 120} ${cy}, ${x - 120} ${y}, ${x - 26} ${y}`,
      class: 'edge ' + p.stance, fill: 'none',
    }));
    const g = svgEl('g', { class: 'node' });
    g.appendChild(svgEl('circle', { cx: x, cy: y, r: 20 }));
    const label = svgEl('text', { x, y: y + 4 });
    label.textContent = p.fp.slice(0, 6);
    g.appendChild(label);
    const verdict = svgEl('text', { x: x + 30, y: y + 4, class: 'edgelabel', 'text-anchor': 'start' });
    verdict.textContent = p.verdict.length > 46 ? p.verdict.slice(0, 45) + '…' : p.verdict;
    g.appendChild(verdict);
    const title = svgEl('title');
    title.textContent = p.fp + ' — ' + p.verdict;
    g.appendChild(title);
    svg.appendChild(g);
  });

  const origin = svgEl('g', { class: 'node origin' });
  origin.appendChild(svgEl('circle', { cx, cy, r: 34 }));
  const ot = svgEl('text', { x: cx, y: cy + 2 });
  ot.textContent = (a.agent_name || a.agent_fp.slice(0, 8));
  origin.appendChild(ot);
  const os = svgEl('text', { x: cx, y: cy + 15, class: 'sub' });
  os.textContent = 'origin';
  origin.appendChild(os);
  svg.appendChild(origin);

  block.appendChild(svg);

  if (!peers.length) {
    block.appendChild(el('p', 'muted',
      `${asked} peer(s) were asked but no per-peer verdict was archived with this alert.`));
  }
  pane.appendChild(block);
}

/* ---------- Mesh graph ---------- */

function stopSim() { if (state.sim) { cancelAnimationFrame(state.sim); state.sim = null; } }

async function loadMesh() {
  const note = $('#mesh-note');
  try {
    const g = await getJSON('/api/mesh');
    state.mesh = g;
    note.textContent = `${g.nodes.length} node(s), ${g.edges.length} gossip edge(s)` +
      (g.silent.length ? ` — in the manifest but unseen: ${g.silent.join(', ')}` : '');
    drawMesh(g);
  } catch (e) { showError(note, e); }
}

function drawMesh(g) {
  stopSim();
  const svg = $('#mesh-svg');
  clear(svg);
  const wrap = svg.parentElement;
  const W = wrap.clientWidth || 900, H = wrap.clientHeight || 420;
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);

  const nodes = g.nodes.map((n, i) => ({
    ...n,
    x: W / 2 + Math.cos((i / g.nodes.length) * 6.283) * 140,
    y: H / 2 + Math.sin((i / g.nodes.length) * 6.283) * 140,
    vx: 0, vy: 0,
  }));
  const byFp = new Map(nodes.map((n) => [n.short_fp, n]));
  const edges = g.edges.filter((e) => byFp.has(e.from) && byFp.has(e.to));

  const eg = svgEl('g');
  const ng = svgEl('g');
  svg.appendChild(eg);
  svg.appendChild(ng);

  const lines = edges.map((e) => {
    const l = svgEl('line', { class: 'edge' + (e.pinned ? ' pinned' : '') });
    const title = svgEl('title');
    title.textContent = `${e.from} sees ${e.to}` + (e.grant_state ? ` (${e.grant_state})` : '');
    l.appendChild(title);
    eg.appendChild(l);
    return { l, a: byFp.get(e.from), b: byFp.get(e.to) };
  });

  const gs = nodes.map((n) => {
    const grp = svgEl('g', { class: 'node' + (n.reporting ? ' reporting' : '') });
    grp.appendChild(svgEl('circle', { r: n.reporting ? 26 : 20 }));
    const t = svgEl('text', { y: 4 });
    t.textContent = n.name || n.short_fp.slice(0, 8);
    grp.appendChild(t);
    const s = svgEl('text', { y: 17, class: 'sub' });
    s.textContent = n.platform || (n.reporting ? 'answering' : 'named only');
    grp.appendChild(s);
    grp.addEventListener('click', () => showNodeCard(n, edges));
    // Dragging: an operator untangling a cluster is the whole reason
    // this is a live simulation rather than a static picture.
    grp.addEventListener('pointerdown', (ev) => {
      n.pinnedByUser = true;
      const move = (m) => {
        const r = svg.getBoundingClientRect();
        n.x = ((m.clientX - r.left) / r.width) * W;
        n.y = ((m.clientY - r.top) / r.height) * H;
      };
      const up = () => {
        n.pinnedByUser = false;
        window.removeEventListener('pointermove', move);
        window.removeEventListener('pointerup', up);
      };
      window.addEventListener('pointermove', move);
      window.addEventListener('pointerup', up);
      ev.preventDefault();
    });
    ng.appendChild(grp);
    return { grp, n };
  });

  function tick() {
    // Repulsion, springs, and a pull to centre. Small and explicit
    // beats a library we would have to fetch from someone else's CDN.
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i], b = nodes[j];
        let dx = b.x - a.x, dy = b.y - a.y;
        let d2 = dx * dx + dy * dy || 0.01;
        const f = 14000 / d2;
        const d = Math.sqrt(d2);
        const ux = dx / d, uy = dy / d;
        a.vx -= ux * f; a.vy -= uy * f;
        b.vx += ux * f; b.vy += uy * f;
      }
    }
    lines.forEach(({ a, b }) => {
      const dx = b.x - a.x, dy = b.y - a.y;
      const d = Math.sqrt(dx * dx + dy * dy) || 0.01;
      const f = (d - 190) * 0.012;
      const ux = dx / d, uy = dy / d;
      a.vx += ux * f; a.vy += uy * f;
      b.vx -= ux * f; b.vy -= uy * f;
    });
    nodes.forEach((n) => {
      n.vx += (W / 2 - n.x) * 0.0016;
      n.vy += (H / 2 - n.y) * 0.0016;
      if (!n.pinnedByUser) {
        n.vx *= 0.82; n.vy *= 0.82;
        n.x += n.vx; n.y += n.vy;
      } else { n.vx = 0; n.vy = 0; }
      n.x = Math.max(40, Math.min(W - 40, n.x));
      n.y = Math.max(36, Math.min(H - 36, n.y));
    });
    lines.forEach(({ l, a, b }) => {
      l.setAttribute('x1', a.x); l.setAttribute('y1', a.y);
      l.setAttribute('x2', b.x); l.setAttribute('y2', b.y);
    });
    gs.forEach(({ grp, n }) => grp.setAttribute('transform', `translate(${n.x},${n.y})`));
    state.sim = requestAnimationFrame(tick);
  }
  tick();
}

function showNodeCard(n, edges) {
  const card = $('#mesh-card');
  clear(card);
  card.classList.add('show');
  card.appendChild(el('h4', null, n.name || n.short_fp));
  const seenBy = edges.filter((e) => e.to === n.short_fp).length;
  const sees = edges.filter((e) => e.from === n.short_fp).length;
  dl(card, [
    ['fingerprint', n.short_fp],
    ['platform', n.platform],
    ['version', n.version],
    ['status', n.reporting ? 'answered for itself' : 'named by gossip only'],
    ['sees', String(sees)],
    ['seen by', String(seenBy)],
  ]);
  const close = el('button', 'ghost', 'close');
  close.addEventListener('click', () => card.classList.remove('show'));
  card.appendChild(close);
}

/* ---------- Help ---------- */

function buildHelp() {
  const b = $('#help-body');
  const add = (tag, cls, text) => b.appendChild(el(tag, cls, text));
  add('p', null, 'The same panes as bowery-console, over the same data: live tables come from the relay agent through the whisper transport, and alerts come from the operator-side archive.');
  add('h3', null, 'keys');
  const ul = el('ul');
  [['1 … 9', 'switch pane'], ['r', 'refresh the active pane'], ['ctrl/⌘ + enter', 'run the query']]
    .forEach(([k, v]) => ul.appendChild(el('li', null, `${k} — ${v}`)));
  b.appendChild(ul);
  add('h3', null, 'where the numbers come from');
  const ul2 = el('ul');
  [
    'Alerts, and every per-peer whisper verdict, come from ~/.bowery/alerts.db — the agent\'s own bowery_alerts table does not carry an alert\'s context.',
    'The mesh graph is a fan-out: every agent\'s own view of its neighbours, not one host\'s opinion of the fleet.',
    'A node drawn hollow was named by somebody else\'s gossip and did not answer for itself.',
  ].forEach((t) => ul2.appendChild(el('li', null, t)));
  b.appendChild(ul2);
  add('h3', null, 'this listener is unauthenticated');
  add('p', 'muted', 'Anything that can reach this port holds the operator\'s authority. It binds to loopback unless told otherwise; reach it remotely with an SSH tunnel rather than by binding wider.');
}

/* ---------- pane wiring ---------- */

const LOADERS = {
  query: () => {},
  alerts: loadAlerts,
  mesh: loadMesh,
  audit: () => loadTable($('#audit-result'), 'bowery_audit'),
  peers: async () => {
    const man = $('#peers-manifest');
    try {
      const list = await getJSON('/api/peers');
      renderTable(man, {
        columns: ['name', 'fingerprint', 'addr'],
        agents: list.map(() => ''),
        rows: list.map((p) => [p.name, p.fp, p.addr]),
      });
    } catch (e) { showError(man, e); }
    loadTable($('#peers-mesh'), 'bowery_mesh_peers');
  },
  silences: () => loadTable($('#silences-result'), 'bowery_silences'),
  doctor: () => {
    loadTable($('#doctor-probes'), 'bowery_probe_status');
    loadTable($('#doctor-detections'), 'bowery_detections');
  },
  chat: () => {},
  help: () => {},
};

function switchPane(name) {
  if (!LOADERS[name]) return;
  if (state.pane === 'mesh' && name !== 'mesh') stopSim();
  state.pane = name;
  document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t.dataset.pane === name));
  document.querySelectorAll('.pane').forEach((p) => p.classList.toggle('active', p.id === 'pane-' + name));
  LOADERS[name]();
}

function init() {
  buildExamples();
  buildHelp();
  document.querySelectorAll('.tab').forEach((t) =>
    t.addEventListener('click', () => switchPane(t.dataset.pane)));
  $('#q-run').addEventListener('click', runQuery);
  $('#a-run').addEventListener('click', loadAlerts);
  $('#a-text').addEventListener('keydown', (e) => { if (e.key === 'Enter') loadAlerts(); });
  $('#m-run').addEventListener('click', loadMesh);
  $('#refresh').addEventListener('click', () => LOADERS[state.pane]());
  $('#q-sql').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); runQuery(); }
  });

  const order = ['query', 'alerts', 'mesh', 'audit', 'peers', 'silences', 'doctor', 'chat', 'help'];
  window.addEventListener('keydown', (e) => {
    const typing = /^(INPUT|TEXTAREA)$/.test(document.activeElement.tagName);
    if (typing) return;
    if (e.key >= '1' && e.key <= '9') switchPane(order[Number(e.key) - 1]);
    if (e.key === 'r') LOADERS[state.pane]();
  });
  window.addEventListener('resize', () => { if (state.pane === 'mesh' && state.mesh) drawMesh(state.mesh); });

  getJSON('/api/health').then((h) => {
    $('#relay-info').textContent = `relay ${h.relay_addr} · ${h.relay_fp.slice(0, 12)} · ${h.version}`;
    setStatus('ok', 'connected');
  }).catch(() => setStatus('err', 'no relay'));

  runQuery();
}

document.addEventListener('DOMContentLoaded', init);
