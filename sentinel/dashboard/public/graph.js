// Incident graph: deterministic lane layout + SVG renderer.
// layoutGraph() is pure (no DOM), so the tests can check it in Node: every node gets a position, and
// nothing is dropped however large the graph is (the server caps it at MAX_GRAPH_NODES, fail-loud).
// renderGraph() draws into an <svg>. All capture text goes through textContent. No markup is
// built from data.

export const LANE_TITLES = {
  input: 'Input (system / user)',
  untrusted: 'Untrusted data (tool results, documents)',
  action: 'Agent actions (tool calls)',
  sink: 'Egress sinks',
  detection: 'Detections (SentinelProxy)',
};

const LANE_H = 92;
const LANE_LABEL_W = 0;
const NODE_H = 46;
const PAD_X = 24;
const PAD_TOP = 30;

/** Column width shrinks for wide graphs so a 200-call chain stays scrollable, not a 30k px strip. */
export function columnWidth(cols) {
  if (cols <= 10) return 168;
  if (cols <= 40) return 124;
  return 100;
}

/**
 * Pure layout. Nodes are placed in replay order. A node goes in the first column that is after the
 * last node in its lane and not before any already-placed predecessor (so edges run left to right
 * whenever the data allows).
 * @returns {{positions: Map<string,{x:number,y:number,w:number,h:number,col:number}>, width:number, height:number, cols:number, colW:number}}
 */
export function layoutGraph(graph) {
  const lanes = graph.lanes;
  const laneIdx = new Map(lanes.map((l, i) => [l, i]));
  const preds = new Map();
  for (const e of graph.edges) {
    if (!preds.has(e.to)) preds.set(e.to, []);
    preds.get(e.to).push(e.from);
  }
  const ordered = [...graph.nodes].sort((a, b) => a.order - b.order);
  const col = new Map();
  const lastCol = new Map();
  for (const n of ordered) {
    let c = (lastCol.get(n.lane) ?? -1) + 1;
    for (const p of preds.get(n.id) ?? []) if (col.has(p)) c = Math.max(c, col.get(p));
    col.set(n.id, c);
    lastCol.set(n.lane, c);
  }
  const cols = ordered.length ? Math.max(...col.values()) + 1 : 0;
  const colW = columnWidth(cols);
  const w = colW - 24;
  const positions = new Map();
  for (const n of ordered) {
    const li = laneIdx.get(n.lane) ?? lanes.length - 1;
    positions.set(n.id, {
      col: col.get(n.id),
      x: LANE_LABEL_W + PAD_X + col.get(n.id) * colW,
      y: PAD_TOP + li * LANE_H + (LANE_H - NODE_H) / 2,
      w,
      h: NODE_H,
    });
  }
  return {
    positions,
    cols,
    colW,
    width: LANE_LABEL_W + PAD_X * 2 + Math.max(cols, 1) * colW,
    height: PAD_TOP + lanes.length * LANE_H + 8,
  };
}

const SVG_NS = 'http://www.w3.org/2000/svg';
function el(name, attrs = {}, parent) {
  const e = document.createElementNS(SVG_NS, name);
  for (const [k, v] of Object.entries(attrs)) if (v != null) e.setAttribute(k, String(v));
  if (parent) parent.appendChild(e);
  return e;
}

/** Fit a label to the node width for display only. The full text is in <title> and the detail pane. */
function fit(label, w) {
  const max = Math.max(4, Math.floor((w - 14) / 6.4));
  return label.length > max ? `${label.slice(0, max - 1)}…` : label;
}

const ICON = { malicious: '⚠', truncated: '⋯', unresolved: '?', not_recorded: '∅', denied: '⛔', exfil_received: '⇥' };

/**
 * @param {SVGSVGElement} svg
 * @param {object} replay   /api/replay body
 * @param {{revealed:Set<string>, focus:Set<string>, onSelect:(node)=>void, selected?:string}} view
 */
export function renderGraph(svg, replay, view) {
  const { graph } = replay;
  const L = layoutGraph(graph);
  svg.replaceChildren();
  svg.setAttribute('viewBox', `0 0 ${L.width} ${L.height}`);
  svg.setAttribute('width', String(L.width));
  svg.setAttribute('height', String(L.height));

  const defs = el('defs', {}, svg);
  // userSpaceOnUse: a perfectly horizontal edge has a zero-height bounding box, and a bbox-relative
  // filter region would make that edge disappear entirely.
  const glow = el('filter', { id: 'taint-glow', filterUnits: 'userSpaceOnUse', x: 0, y: 0, width: L.width, height: L.height }, defs);
  el('feGaussianBlur', { stdDeviation: '3.5', result: 'b' }, glow);
  const merge = el('feMerge', {}, glow);
  el('feMergeNode', { in: 'b' }, merge);
  el('feMergeNode', { in: 'SourceGraphic' }, merge);
  for (const [id, cls] of [['arrow', 'arrow'], ['arrow-taint', 'arrow taint']]) {
    const m = el('marker', { id, viewBox: '0 0 10 10', refX: '9', refY: '5', markerUnits: 'userSpaceOnUse', markerWidth: '8', markerHeight: '8', orient: 'auto-start-reverse' }, defs);
    el('path', { d: 'M0,0 L10,5 L0,10 z', class: cls }, m);
  }

  // lanes
  const lanesG = el('g', { class: 'lanes' }, svg);
  graph.lanes.forEach((lane, i) => {
    const y = PAD_TOP + i * LANE_H;
    el('rect', { x: 0, y, width: L.width, height: LANE_H, class: `lane lane-${lane} ${i % 2 ? 'odd' : ''}` }, lanesG);
    const t = el('text', { x: 8, y: y + 14, class: 'lane-title' }, lanesG);
    t.textContent = LANE_TITLES[lane] ?? lane;
  });

  const pos = L.positions;
  const byId = new Map(graph.nodes.map(n => [n.id, n]));
  const edgesG = el('g', { class: 'edges' }, svg);
  const taintG = el('g', { class: 'edges taint-layer' }, svg);
  for (const e of graph.edges) {
    const a = pos.get(e.from);
    const b = pos.get(e.to);
    if (!a || !b) continue;
    const shown = view.revealed.has(e.from) && view.revealed.has(e.to);
    const x1 = a.x + a.w;
    const y1 = a.y + a.h / 2;
    const x2 = b.x;
    const y2 = b.y + b.h / 2;
    let d;
    if (x2 > x1 + 4) {
      const mx = (x1 + x2) / 2;
      d = `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`;
    } else if (a.col === b.col) {
      // same column, different lane: straight vertical link between node edges
      const xs = a.x + a.w / 2;
      d = y2 > y1 ? `M${xs},${a.y + a.h} L${xs},${b.y}` : `M${xs},${a.y} L${xs},${b.y + b.h}`;
    } else {
      // backwards: arc above the lanes so it never hides behind nodes
      const lift = Math.min(a.y, b.y) - 22 - Math.min(60, Math.abs(x1 - x2) / 20);
      d = `M${a.x + a.w / 2},${a.y} C${a.x + a.w / 2},${lift} ${b.x + b.w / 2},${lift} ${b.x + b.w / 2},${b.y}`;
    }
    const isTaint = e.taint === true;
    const cls = ['edge', `edge-${e.kind}`, isTaint ? 'taint' : '', shown ? '' : 'hidden', view.focus.has(e.id) ? 'focus' : ''].join(' ');
    const p = el('path', { d, class: cls, 'marker-end': isTaint ? 'url(#arrow-taint)' : 'url(#arrow)', filter: isTaint && shown ? 'url(#taint-glow)' : null }, isTaint ? taintG : edgesG);
    const t = el('title', {}, p);
    t.textContent = `${e.kind}: ${byId.get(e.from)?.label ?? e.from} → ${byId.get(e.to)?.label ?? e.to}`;
  }

  const nodesG = el('g', { class: 'nodes' }, svg);
  for (const n of graph.nodes) {
    const p = pos.get(n.id);
    const flags = new Set(n.flags ?? []);
    const shown = view.revealed.has(n.id);
    const cls = [
      'node', `kind-${n.kind}`, `lane-${n.lane}`,
      ...[...flags].map(f => `f-${f}`),
      shown ? '' : 'hidden',
      view.focus.has(n.id) ? 'focus' : '',
      view.selected === n.id ? 'selected' : '',
      n.kind === 'alert' && n.severity != null ? `sev-${n.severity >= 90 ? 'critical' : n.severity >= 70 ? 'serious' : n.severity >= 50 ? 'warning' : 'low'}` : '',
    ].join(' ');
    const g = el('g', { class: cls, transform: `translate(${p.x},${p.y})`, tabindex: shown ? '0' : '-1', role: 'button', 'data-id': n.id }, nodesG);
    el('rect', { width: p.w, height: p.h, rx: 7, class: 'node-box', filter: flags.has('taint') && shown ? 'url(#taint-glow)' : null }, g);
    const icon = ['malicious', 'truncated', 'unresolved', 'denied', 'exfil_received', 'not_recorded'].find(f => flags.has(f));
    const label = el('text', { x: 8, y: 19, class: 'node-label' }, g);
    label.textContent = fit(`${icon ? `${ICON[icon]} ` : ''}${n.label}`, p.w);
    const sub = el('text', { x: 8, y: 36, class: 'node-sub' }, g);
    sub.textContent = fit(nodeSubtitle(n), p.w);
    const title = el('title', {}, g);
    title.textContent = `${n.label}\n${nodeSubtitle(n)}${flags.size ? `\nflags: ${[...flags].join(', ')}` : ''}`;
    if (shown) {
      g.addEventListener('click', () => view.onSelect(n));
      g.addEventListener('keydown', ev => {
        if (ev.key === 'Enter' || ev.key === ' ') {
          ev.preventDefault();
          view.onSelect(n);
        }
      });
    }
  }
  return L;
}

export function nodeSubtitle(n) {
  if (n.kind === 'truncation_marker') return 'TaintPath truncated by T4';
  if (n.kind === 'alert') return `${n.severityName ?? ''} · sev ${n.severity ?? '?'}`;
  if (n.kind === 'canary_hit') return 'attacker endpoint received data';
  if (n.kind === 'sink') return 'egress destination';
  if (n.rowCount != null) return `${n.rowCount.toLocaleString('en-US')} rows · ${fmtBytes(n.bytes)}`;
  if (n.recorded === false) return 'body not recorded';
  if (n.kind === 'tool_call') return n.decision ? `decision: ${n.decision}` : `${fmtBytes(n.bytes)} args`;
  if (n.bytes != null) return fmtBytes(n.bytes);
  return n.kind.replace(/_/g, ' ');
}

export function fmtBytes(b) {
  if (b == null) return '—';
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1024 / 1024).toFixed(2)} MB`;
}
