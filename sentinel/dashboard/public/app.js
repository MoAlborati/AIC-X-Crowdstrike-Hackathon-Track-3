// Dashboard controller. Fetches /api/* and drives the replay player.
// All capture/alert text is inserted as DOM text nodes (textContent); no data is ever parsed as markup.
import { renderGraph, fmtBytes, nodeSubtitle } from './graph.js';
import { viewAt, twinPair, latestGate } from './replay-view.js';
import { headlineView } from './headline-view.js';

const $ = (id) => document.getElementById(id);
const h = (tag, attrs = {}, ...kids) => {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? '' : String(v));
  }
  for (const k of kids.flat()) if (k != null && k !== false) e.append(k instanceof Node ? k : String(k));
  return e;
};

const state = { captures: [], replay: null, step: -1, timer: null, selected: null };
// Rapid capture switches race their /api/replay fetches; only the newest request may render.
const replayGate = latestGate();

// ---- theme ------------------------------------------------------------------------------------
try {
  const t = localStorage.getItem('sentinel-theme');
  if (t) document.documentElement.dataset.theme = t;
} catch { /* storage unavailable: default theme */ }
$('theme').addEventListener('click', () => {
  const dark = matchMedia('(prefers-color-scheme: dark)').matches;
  const cur = document.documentElement.dataset.theme ?? (dark ? 'dark' : 'light');
  const next = cur === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem('sentinel-theme', next); } catch { /* ignore */ }
});

// ---- banners ----------------------------------------------------------------------------------
function banner(kind, title, text) {
  $('banners').append(h('div', { class: `banner banner-${kind}`, role: kind === 'error' ? 'alert' : 'status' }, h('strong', {}, title), ' ', text));
}
function clearBanners() {
  $('banners').replaceChildren();
}

async function getJson(url) {
  const res = await fetch(url);
  let body;
  try {
    body = await res.json();
  } catch {
    body = { error: `HTTP ${res.status}` };
  }
  return { ok: res.ok, status: res.status, body };
}

function boundText(b) {
  return b.bound ? `${b.bound}: size ${Number(b.size).toLocaleString('en-US')} > cap ${Number(b.cap).toLocaleString('en-US')} (${b.action}). ` : '';
}

// ---- capture list -----------------------------------------------------------------------------
async function loadList() {
  const r = await getJson('/api/captures');
  if (!r.ok) {
    banner('error', `Capture index failed (HTTP ${r.status}).`, boundText(r.body) + (r.body.error ?? ''));
    return;
  }
  state.captures = r.body.captures;
  $('bounds').textContent = `Bounds (fail-loud, never truncated): ${Object.entries(r.body.bounds).map(([k, v]) => `${k}=${Number(v).toLocaleString('en-US')}`).join(' · ')}`;
  const sel = $('capture');
  sel.replaceChildren();
  const groups = new Map();
  for (const c of state.captures) {
    const g = c.source === 'placeholder' ? 'Placeholder fixtures'
      : c.id.startsWith('variants/') ? `T6 eval corpus (${c.expectedLabel ?? 'unlabeled'})`
        : c.id.startsWith('benign/') ? 'Benign captures (T1)' : 'Attack captures (T1)';
    if (!groups.has(g)) groups.set(g, h('optgroup', { label: g }));
    const label = c.error ? `⚠ ${c.id} — ${c.error}` : `${c.title ?? c.id}${c.placeholder ? ' [PLACEHOLDER]' : ''}`;
    groups.get(g).append(h('option', { value: c.id, disabled: Boolean(c.error) }, label));
  }
  for (const g of groups.values()) sel.append(g);
  const broken = state.captures.filter(c => c.error);
  if (broken.length) banner('error', `${broken.length} capture(s) failed to load.`, broken.map(c => `${c.id}: ${c.error}`).join(' | '));
  const params = new URLSearchParams(location.search);
  const want = params.get('id');
  const first = state.captures.find(c => c.id === want && !c.error) ?? state.captures.find(c => !c.error);
  if (first) {
    sel.value = first.id;
    fillRuns(first, params.get('run'));
    const st = params.get('step');
    await loadReplay(st === 'last' ? Infinity : st != null && /^\d+$/.test(st) ? Number(st) - 1 : 0);
  }
}

function fillRuns(c, want) {
  const sel = $('run');
  sel.replaceChildren(...(c.runs ?? []).map(r => h('option', { value: r.key }, `${r.label} · ${r.role}`)));
  if (want && c.runs?.some(r => r.key === want)) sel.value = want;
}

$('capture').addEventListener('change', async () => {
  const c = state.captures.find(x => x.id === $('capture').value);
  fillRuns(c);
  await loadReplay();
});
$('run').addEventListener('change', () => loadReplay());

async function loadScoring() {
  const r = await getJson('/api/scoring');
  const v = headlineView(r.body);
  $('det-rate').textContent = v.det;
  $('fp-rate').textContent = v.fp;
  $('det-rate').classList.toggle('pending', v.pending);
  $('fp-rate').classList.toggle('pending', v.pending);
  $('scoring-note').textContent = v.note;
}

// ---- replay -----------------------------------------------------------------------------------
async function loadReplay(initialStep = 0) {
  const token = replayGate.begin();
  stop();
  clearBanners();
  const id = $('capture').value;
  const run = $('run').value;
  history.replaceState(null, '', `?id=${encodeURIComponent(id)}&run=${encodeURIComponent(run)}`);
  const r = await getJson(`/api/replay?id=${encodeURIComponent(id)}&run=${encodeURIComponent(run)}`);
  if (!replayGate.isCurrent(token)) return; // a newer loadReplay superseded this one
  if (!r.ok) {
    state.replay = null;
    banner('error', `Replay refused (HTTP ${r.status}).`, boundText(r.body) + (r.body.error ?? ''));
    $('graph').replaceChildren();
    $('feed').replaceChildren();
    $('timeline').replaceChildren();
    return;
  }
  const rp = r.body;
  state.replay = rp;
  state.selected = null;
  if (rp.capture.placeholder || rp.alertSource.placeholder) {
    banner('placeholder', 'PLACEHOLDER DATA.', [rp.capture.placeholderNote, rp.alertSource.note, rp.alertSource.placeholder ? `Alerts from ${rp.alertSource.origin}.` : null].filter(Boolean).join(' '));
  }
  for (const w of rp.warnings) banner('warn', 'Replay warning:', w);
  const invalid = rp.alerts.filter(a => a.invalid);
  if (invalid.length) banner('error', `${invalid.length} alert(s) failed T4 schema validation.`, 'Shown in the feed and flagged, not dropped.');

  $('buildms').textContent = `${rp.dashboardBuildMs.toFixed(2)} ms`;
  $('graph-size').textContent = `${rp.graph.nodes.length.toLocaleString('en-US')} nodes · ${rp.graph.edges.length.toLocaleString('en-US')} edges · ${fmtBytes(rp.capture.bytes)} capture`;
  const L = rp.metrics.detectionLatencyMs;
  $('latency').textContent = L.n ? `${L.median} ms` : '—';
  $('latency-note').textContent = L.n ? `median of ${L.n} alert(s) · p95 ${L.p95} ms · max ${L.max} ms (T4 DetectionLatencyMs)` : 'no detector verdicts for this run';
  $('alert-source').textContent = `Alerts: ${rp.alertSource.origin} · validator: ${rp.alertSource.validator}`;
  renderTwin(rp);
  setStep(rp.timeline.length ? initialStep : -1);
}

function setStep(s) {
  const rp = state.replay;
  if (!rp) return;
  state.step = Math.max(-1, Math.min(s, rp.timeline.length - 1));
  const v = viewAt(rp, state.step);
  $('stepinfo').textContent = `step ${v.step + 1} / ${rp.timeline.length}`;
  renderTimeline(rp, v);
  renderFeed(rp, v);
  renderGauge(v.trust);
  renderGraph($('graph'), rp, { revealed: v.revealed, focus: v.focus, selected: state.selected, onSelect: (n) => selectNode(n) });
  const cur = document.querySelector('#timeline .current');
  cur?.scrollIntoView({ block: 'nearest' });
  // Keep the current step's node in view inside the graph's own scroller (never scrolls the page).
  // Prefer a malicious / truncation-marker node so the final step lands on the interesting part.
  const focusNode = document.querySelector('#graph .node.focus.f-malicious, #graph .node.focus.f-truncated, #graph .node.focus');
  const scroller = document.querySelector('.graph-scroll');
  if (focusNode && scroller) {
    const box = focusNode.getBBox();
    const m = focusNode.transform.baseVal.consolidate()?.matrix;
    const x = (m?.e ?? 0) + box.width / 2;
    if (x < scroller.scrollLeft + 40 || x > scroller.scrollLeft + scroller.clientWidth - 40) scroller.scrollLeft = Math.max(0, x - scroller.clientWidth / 2);
  }
}

function renderTimeline(rp, v) {
  const ol = $('timeline');
  ol.replaceChildren(...rp.timeline.map((t, i) => h('li', {
    class: `tl tl-${t.kind} ${i === v.step ? 'current' : ''} ${i > v.step ? 'future' : ''}`,
    onclick: () => { stop(); setStep(i); },
  }, h('span', { class: 'tl-n' }, String(i + 1)), h('span', { class: 'tl-kind' }, t.kind.replace(/_/g, ' ')), h('span', { class: 'tl-label' }, t.label))));
}

function sevClass(sev) {
  return sev >= 90 ? 'critical' : sev >= 70 ? 'serious' : sev >= 50 ? 'warning' : 'low';
}

function renderFeed(rp, v) {
  const feed = $('feed');
  if (!rp.alerts.length) {
    const gt = rp.groundTruth;
    feed.replaceChildren(h('div', { class: 'empty' },
      h('p', {}, 'No detector verdicts recorded for this run.'),
      gt ? h('p', { class: 'muted' }, `DVAA ground truth (not a detection): exfil ${gt.exfilExecuted ? 'EXECUTED' : gt.exfilAttempted ? 'attempted, not executed' : 'not attempted'}${gt.exfilTargetUrl ? ` → ${gt.exfilTargetUrl}` : ''}${gt.aim?.enforced ? ` · AIM ${gt.aim.allowed === false ? 'denied' : 'allowed'}` : ''}.`) : null));
    return;
  }
  const pending = rp.alerts.length - v.alerts.length;
  const kids = v.alerts.map(a => alertCard(a));
  if (pending) kids.push(h('p', { class: 'muted' }, `${pending} alert(s) later in the replay.`));
  feed.replaceChildren(...kids);
}

function alertCard(a) {
  const sc = sevClass(a.severity ?? 0);
  const icon = { critical: '⛔', serious: '▲', warning: '◆', low: '●' }[sc];
  const cc = a.caseCard;
  return h('article', { class: `alert sev-${sc} ${a.invalid ? 'invalid' : ''}` },
    h('header', { class: 'alert-head' },
      h('span', { class: `sev-badge sev-${sc}` }, `${icon} ${a.severityName} ${a.severity ?? '?'}`),
      h('span', { class: 'alert-name' }, a.detectName),
      h('span', { class: `disp disp-${a.disposition}` }, a.disposition),
      h('span', { class: 'alert-lat' }, a.latencyMs != null ? `${a.latencyMs} ms` : '— ms')),
    a.invalid ? h('p', { class: 'invalid-note' }, `Schema problems: ${a.problems.join('; ')}`) : null,
    h('div', { class: 'casecard' },
      h('div', { class: 'cc-title' }, 'Case card'),
      h('p', { class: 'narrative' }, cc.narrative ?? '—'),
      h('ol', { class: 'cc-chain' },
        h('li', {}, h('b', {}, 'Originated in '), cc.originatedIn ?? '—'),
        h('li', {}, h('b', {}, 'Influenced '), cc.influencedToolCall ?? '—'),
        h('li', {}, h('b', {}, 'Decided by '), cc.decidedByRule ?? '—'))),
    h('details', { class: 'layers', open: true },
      h('summary', {}, `Detection layers (${cc.layers.length})`),
      h('table', {},
        h('thead', {}, h('tr', {}, h('th', {}, 'layer'), h('th', {}, 'rule'), h('th', {}, 'fired'), h('th', { class: 'num' }, 'ms'))),
        h('tbody', {}, ...cc.layers.map(l => h('tr', { class: l.truncated ? 'trunc' : '' },
          h('td', {}, l.layer ?? ''), h('td', {}, l.rule ?? ''), h('td', {}, l.truncated ? `${l.omitted} omitted` : l.fired ? '✔ fired' : '– no'), h('td', { class: 'num' }, l.latencyMs ?? '')))))),
    h('details', { class: 'path' },
      h('summary', {}, `Taint path (${a.taintPath.length} hops${a.taintPathTruncated ? ', truncated by T4' : ''})`),
      h('ol', {}, ...a.taintPath.map(p => h('li', { class: `hop hop-${p.kind}` }, p.kind === 'truncated' ? `⋯ ${p.omittedHops ?? '?'} hops omitted` : `${p.kind}: ${p.label}`)))),
    h('footer', { class: 'tags' },
      a.technique.id ? h('span', { class: 'tag' }, `${a.technique.id} ${a.technique.name ?? ''}`) : null,
      ...a.tags.owaspLlm.map(t => h('span', { class: 'tag' }, t)),
      ...a.tags.owaspAgentic.map(t => h('span', { class: 'tag' }, t)),
      a.tags.oasb ? h('span', { class: 'tag' }, a.tags.oasb) : null,
      a.entities.sink?.destination ? h('span', { class: 'tag sink' }, `sink ${a.entities.sink.destination}`) : null));
}

function renderTwin(rp) {
  const box = $('twin');
  const pair = twinPair(rp.runs);
  if (!pair) {
    box.replaceChildren();
    box.hidden = true;
    return;
  }
  box.hidden = false;
  const side = (r, title) => h('div', { class: `twin-side ${r.outcome.exfilExecuted ? 'bad' : 'good'}` },
    h('div', { class: 'twin-title' }, title),
    h('div', { class: 'twin-agent' }, r.label),
    h('div', { class: 'twin-out' }, r.outcome.exfilExecuted ? '✖ data left the sandbox' : r.outcome.blocked ? '✔ action denied' : '– no exfil recorded'),
    r.outcome.denialReason ? h('div', { class: 'twin-reason' }, r.outcome.denialReason) : null,
    r.outcome.trustScore != null ? h('div', { class: 'twin-trust' }, `AIM trust score ${r.outcome.trustScore}`) : null,
    r.key !== rp.run.key ? h('button', { class: 'linkish', onclick: () => { $('run').value = r.key; loadReplay(); } }, 'replay this run →') : h('span', { class: 'muted' }, 'viewing'));
  box.replaceChildren(
    h('div', { class: 'twin-head' }, 'AIM twin contrast · same agent code, guard off vs on (recorded by DVAA)'),
    h('div', { class: 'twin-grid' }, side(pair.vuln, 'Unprotected'), side(pair.prot, 'AIM-protected twin')));
}

function renderGauge(t) {
  const svg = $('gauge');
  const NS = 'http://www.w3.org/2000/svg';
  const mk = (n, a) => { const e = document.createElementNS(NS, n); for (const [k, v] of Object.entries(a)) e.setAttribute(k, String(v)); svg.append(e); return e; };
  svg.replaceChildren();
  const cx = 60, cy = 62, r = 48;
  const arc = (from, to) => {
    const p = (f) => [cx - r * Math.cos(Math.PI * f), cy - r * Math.sin(Math.PI * f)];
    const [x1, y1] = p(from);
    const [x2, y2] = p(to);
    return `M${x1},${y1} A${r},${r} 0 0 1 ${x2},${y2}`;
  };
  mk('path', { d: arc(0, 1), class: 'gauge-track' });
  const v = t.value;
  if (v != null) {
    const band = v >= 70 ? 'good' : v >= 40 ? 'warning' : 'critical';
    mk('path', { d: arc(0, Math.max(0.001, v / 100)), class: `gauge-val g-${band}` });
  }
  const txt = mk('text', { x: cx, y: cy - 6, 'text-anchor': 'middle', class: 'gauge-num' });
  txt.textContent = v == null ? '—' : String(v);
  const band = v == null ? '' : v >= 70 ? ' (healthy)' : v >= 40 ? ' (degraded)' : ' (compromised)';
  $('gauge-text').textContent = `${v == null ? '' : `${v}/100${band} · `}${t.note}`;
}

function selectNode(n) {
  state.selected = n.id;
  const d = $('detail');
  const rows = [
    ['kind', n.kind.replace(/_/g, ' ')], ['lane', n.lane], ['trust', n.trust], ['tool call id', n.toolCallId],
    ['rows', n.rowCount != null ? n.rowCount.toLocaleString('en-US') : null], ['size', n.bytes != null ? fmtBytes(n.bytes) : null],
    ['decision', n.decision], ['destination', n.destination], ['flags', n.flags?.length ? n.flags.join(', ') : null],
    ['omitted hops', n.omittedHops],
  ].filter(([, v]) => v != null && v !== '');
  d.replaceChildren(
    ...[h('h3', {}, n.label),
      h('p', { class: 'muted' }, nodeSubtitle(n)),
      h('dl', {}, ...rows.flatMap(([k, v]) => [h('dt', {}, k), h('dd', {}, String(v))])),
      n.text != null ? h('pre', { class: 'node-text' }, n.text || '(empty)') : null].filter(Boolean));
  setStep(state.step);
}

// ---- player -----------------------------------------------------------------------------------
function stop() {
  if (state.timer) clearInterval(state.timer);
  state.timer = null;
  $('play').textContent = '▶ Play';
}
function play() {
  const rp = state.replay;
  if (!rp) return;
  if (state.timer) return stop();
  if (state.step >= rp.timeline.length - 1) setStep(0);
  $('play').textContent = '❚❚ Pause';
  state.timer = setInterval(() => {
    if (state.step >= rp.timeline.length - 1) return stop();
    setStep(state.step + 1);
  }, 800);
}
$('play').addEventListener('click', play);
$('first').addEventListener('click', () => { stop(); setStep(0); });
$('prev').addEventListener('click', () => { stop(); setStep(state.step - 1); });
$('next').addEventListener('click', () => { stop(); setStep(state.step + 1); });
$('last').addEventListener('click', () => { stop(); setStep(Infinity); });
document.addEventListener('keydown', (e) => {
  if (e.target.closest('select, input, textarea')) return;
  if (e.key === 'ArrowRight') { stop(); setStep(state.step + 1); }
  else if (e.key === 'ArrowLeft') { stop(); setStep(state.step - 1); }
  else if (e.key === 'Home') { stop(); setStep(0); }
  else if (e.key === 'End') { stop(); setStep(Infinity); }
  else if (e.key === ' ' && !e.target.closest('button')) { e.preventDefault(); play(); }
});

loadScoring();
loadList();
