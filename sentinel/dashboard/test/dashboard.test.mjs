// Dashboard tests. Real seams: real T1 captures from captures/, real T4 buildAlert/validateAlert,
// the real HTTP server. Nothing in the feature path is mocked.
//   node --test sentinel/dashboard/test/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, mkdir, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';

import { indexCaptures, loadCapture, normalizeCapture, defaultRoots, REPO_ROOT } from '../lib/capture-loader.mjs';
import { adaptAlerts } from '../lib/alert-adapter.mjs';
import { buildReplay } from '../lib/replay.mjs';
import { BOUNDS, BoundExceededError } from '../lib/bounds.mjs';
import { replayPayload, createServer } from '../server.mjs';
import { layoutGraph } from '../public/graph.js';
import { viewAt } from '../public/replay-view.js';
import { generate, DATA_RICH_ROWS, LONG_PATH_HOPS, policyDocument } from '../fixtures/make-placeholders.mjs';
import { buildAlert } from '../../alerts/index.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DASH = path.resolve(HERE, '..');
const REAL_CAPTURE_IDS = [
  'attack/aim-ab.demo', 'attack/repo.demo', 'attack/flight.demo',
  'benign/7001_securebot', 'benign/7002_helperbot', 'benign/7003_legacybot',
  'benign/7005_ragbot', 'benign/7014_ragbot-aim', 'benign/7022_repobot',
];

const strip = (body) => {
  const { dashboardBuildMs, ...rest } = body;
  return rest;
};

async function allRuns(index) {
  const out = [];
  for (const [id, entry] of index) {
    const c = await loadCapture(entry);
    for (const r of c.runs) out.push([id, r.key]);
  }
  return out;
}

const percentile = (sorted, p) => sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1))];

async function withServer(roots, fn) {
  const srv = createServer({ roots });
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    return await fn(base);
  } finally {
    await new Promise(r => srv.close(r));
  }
}

// ---- real-capture seam ------------------------------------------------------------------------
test('every real T1 capture is indexed, normalized and replays with HTTP 200', async () => {
  const index = await indexCaptures();
  for (const id of REAL_CAPTURE_IDS) assert.ok(index.has(id), `missing real capture ${id}`);
  const runs = await allRuns(index);
  assert.ok(runs.length >= 14, `expected >=14 runs, got ${runs.length}`);
  for (const [id, run] of runs) {
    const r = await replayPayload(index, id, run);
    assert.equal(r.status, 200, `${id}#${run}: ${JSON.stringify(r.body).slice(0, 200)}`);
    assert.ok(r.body.graph.nodes.length > 0);
    assert.ok(r.body.timeline.length > 0);
  }
});

test('aim-ab runA: the malicious node is the real recorded tool call and the taint path reaches the real canary sink', async () => {
  const index = await indexCaptures();
  const raw = JSON.parse(await readFile(path.join(REPO_ROOT, 'captures/attack/aim-ab.demo.json'), 'utf8'));
  const { body } = await replayPayload(index, 'attack/aim-ab.demo', 'runA');
  const realId = raw.runA.toolCalls[0].id;
  assert.deepEqual(body.taint.maliciousNodeIds, [`call:${realId}`]);
  const sinkId = `sink:${raw.runA.dvaa.exfilTargetUrl}`;
  assert.ok(body.taint.nodeIds.includes(sinkId), 'taint glow reaches the egress sink');
  assert.ok(body.graph.nodes.some(n => n.kind === 'canary_hit'), 'canary hit recorded by T1 is drawn');
  assert.equal(body.metrics.trustScore, 10, 'trust = 100 - Critical(90)');
  assert.equal(body.alerts[0].caseCard.narrative.startsWith('Instruction originated in'), true, 'T4 narrative case card present');
  // AIM twin: runB is the protected run of the same capture, and DVAA recorded it as blocked.
  const twin = body.runs.find(r => r.role === 'protected');
  assert.equal(twin.outcome.blocked, true);
  assert.equal(twin.outcome.exfilExecuted, false);
});

test('without placeholder alerts, an attack run shows labeled dvaa{} ground truth, never a fake detection', async () => {
  const index = await indexCaptures(defaultRoots({ SENTINEL_HIDE_PLACEHOLDERS: '1' }));
  const entry = index.get('attack/flight.demo');
  const c = await loadCapture(entry);
  const run = c.runs.find(r => r.key === 'act2');
  const replay = buildReplay({ id: 'flight#act2', agent: run.agent, exchanges: run.exchanges, toolResults: run.toolResults }, []);
  assert.equal(replay.metrics.alertCount, 0);
  assert.equal(replay.metrics.trustScore, null);
  assert.equal(replay.taint.nodeIds.length, 0, 'no detector taint glow without a detector verdict');
  assert.ok(replay.groundTruthPath.edgeIds.length > 0);
  assert.ok(replay.timeline.some(s => s.kind === 'ground_truth'));
});

// ---- determinism ------------------------------------------------------------------------------
test('replay is deterministic: identical output across repeated builds for every capture run', async () => {
  const index = await indexCaptures();
  for (const [id, run] of await allRuns(index)) {
    const a = strip((await replayPayload(index, id, run)).body);
    for (let i = 0; i < 3; i++) assert.deepEqual(strip((await replayPayload(index, id, run)).body), a, `${id}#${run} differs on build ${i + 2}`);
    assert.deepEqual(layoutGraph(a.graph).positions, layoutGraph(a.graph).positions);
  }
});

test('placeholder fixtures are generated deterministically and the committed files are current', async () => {
  const a = await generate();
  const b = await generate();
  assert.deepEqual(a.files, b.files);
  for (const [rel, obj] of Object.entries(a.files)) {
    const onDisk = await readFile(path.join(DASH, 'fixtures', rel), 'utf8');
    assert.equal(onDisk, `${JSON.stringify(obj, null, 2)}\n`, `${rel} is stale: run npm run fixtures`);
  }
  // Every placeholder alert passes T4's own validator.
  const { validateAlert } = await import('../../alerts/schema.js');
  for (const obj of Object.values(a.files)) {
    const alerts = obj.alerts ?? Object.values(obj.runs ?? {}).flat();
    for (const al of alerts) assert.deepEqual(validateAlert(al), [], al.AlertId);
  }
});

// ---- data-rich --------------------------------------------------------------------------------
test(`data-rich capture: ${DATA_RICH_ROWS}-row tool output and >8 KB document are one node each, complete, and nothing is dropped`, async () => {
  const index = await indexCaptures();
  const { status, body } = await replayPayload(index, 'placeholder/data-rich-orders', 'run');
  assert.equal(status, 200);
  const orders = body.graph.nodes.find(n => n.source === 'db:orders');
  assert.equal(orders.rowCount, DATA_RICH_ROWS);
  assert.equal(orders.text.split('\n').length, DATA_RICH_ROWS, 'all rows present in the node text');
  assert.ok(orders.text.includes(`ORD-${100000 + DATA_RICH_ROWS - 1}`), 'last row present (beyond any 8 KB window)');
  const doc = body.graph.nodes.find(n => n.source === 'kb/travel-policy.md');
  assert.ok(doc.bytes > 8192, `doc is ${doc.bytes} B`);
  assert.equal(doc.text, policyDocument(), 'document text kept in full');
  // the detector's taint path runs doc -> orders -> real T1 tool call
  assert.ok(body.taint.nodeIds.includes(doc.id) && body.taint.nodeIds.includes(orders.id));
  const L = layoutGraph(body.graph);
  assert.equal(L.positions.size, body.graph.nodes.length, 'every node is laid out');
  const v = viewAt(body, body.timeline.length - 1);
  assert.equal(v.revealed.size, body.graph.nodes.length, 'every node is visible at the end of the replay');
});

test('graph at scale: 990 nodes all laid out; MAX_GRAPH_NODES+1 fails loud, never a partial graph', () => {
  const capWith = (calls) => normalizeCapture({
    exchanges: [{
      request: { messages: [{ role: 'user', content: 'list records' }] },
      response: { choices: [{ message: { role: 'assistant', content: '', tool_calls: Array.from({ length: calls }, (_, i) => ({ id: `r${i}`, function: { name: `read_record_${i}`, arguments: '{}' } })) } }] },
    }],
  }, { id: 'scale', source: 'test' });
  const toReplay = (c) => buildReplay({ id: 'scale', agent: c.runs[0].agent, exchanges: c.runs[0].exchanges, toolResults: c.runs[0].toolResults }, []);
  const ok = toReplay(capWith(988)); // 1 user + 1 agent + 988 calls = 990
  assert.equal(ok.graph.nodes.length, 990);
  assert.equal(layoutGraph(ok.graph).positions.size, 990);
  assert.throws(() => toReplay(capWith(BOUNDS.MAX_GRAPH_NODES)), (e) => e instanceof BoundExceededError && e.bound === 'MAX_GRAPH_NODES');
});

// ---- T4 truncation marker ---------------------------------------------------------------------
test(`long taint path: ${LONG_PATH_HOPS} hops through T4 buildAlert render a visible truncation-marker node on the glowing path`, async () => {
  const index = await indexCaptures();
  const { body } = await replayPayload(index, 'placeholder/long-taint-path', 'run');
  const alert = body.alerts[0];
  assert.equal(alert.taintPathTruncated, true);
  assert.equal(alert.taintPath.length, 64);
  const marker = body.graph.nodes.find(n => n.kind === 'truncation_marker');
  assert.ok(marker, 'marker node exists');
  assert.equal(marker.omittedHops, LONG_PATH_HOPS - 63);
  assert.match(marker.label, /137 hops omitted/);
  assert.ok(marker.flags.includes('taint') && marker.flags.includes('truncated'));
  const into = body.graph.edges.filter(e => e.taint && e.to === marker.id);
  const out = body.graph.edges.filter(e => e.taint && e.from === marker.id);
  assert.equal(into.length, 1);
  assert.equal(out.length, 1);
  assert.deepEqual(body.taint.maliciousNodeIds, [`call:step_${LONG_PATH_HOPS}`]);
  assert.ok(layoutGraph(body.graph).positions.has(marker.id));
  assert.equal(body.warnings.length, 0, 'every kept hop resolved to a real node');
});

test('a TaintPath longer than T4 allows is refused loudly by the adapter, not sliced', async () => {
  const sample = JSON.parse(await readFile(path.join(HERE, 'fixtures/t4-sample-alert.json'), 'utf8'));
  const hops = Array.from({ length: BOUNDS.MAX_PROVENANCE_EDGES_PER_ALERT + 2 }, (_, i) => ({ Step: i + 1, Kind: 'propagate', Label: `step_${i + 1}`, ToolCallId: null, Trust: null }));
  await assert.rejects(adaptAlerts([{ ...sample, TaintPath: hops }], 'x'), (e) => e instanceof BoundExceededError && e.bound === 'MAX_PROVENANCE_EDGES_PER_ALERT');
});

test('an invalid alert is kept in the feed and flagged, not dropped', async () => {
  const sample = JSON.parse(await readFile(path.join(HERE, 'fixtures/t4-sample-alert.json'), 'utf8'));
  const { alerts } = await adaptAlerts([sample, { ...sample, AlertId: 'broken', Severity: 'high' }], 'x');
  assert.equal(alerts.length, 2);
  assert.equal(alerts[0].invalid, false);
  assert.equal(alerts[1].invalid, true);
  assert.ok(alerts[1].problems.length > 0);
});

// ---- bug fix: result edges looping back into the requesting turn ------------------------------
// Delete-the-fix proof recorded in the PR: with the old fallback (edge to assistant:<same turn>), this
// test is RED; with the fix it is GREEN.
test('a tool result with no later agent turn draws no backward edge into the turn that requested it', async () => {
  const index = await indexCaptures();
  const { body } = await replayPayload(index, 'placeholder/long-taint-path', 'run');
  const back = body.graph.edges.filter(e => e.from.startsWith('result:') && e.to === 'assistant:0');
  assert.equal(back.length, 0, `${back.length} backward result->assistant:0 edges`);
  // and where a later turn exists, the result does feed it
  const rich = (await replayPayload(index, 'placeholder/data-rich-orders', 'run')).body;
  assert.ok(rich.graph.edges.some(e => e.from.startsWith('result:') && e.to === 'assistant:1'));
});

// ---- view state -------------------------------------------------------------------------------
test('replay player: alerts and trust drop are revealed at the alert step, not before', async () => {
  const index = await indexCaptures();
  const { body } = await replayPayload(index, 'attack/aim-ab.demo', 'runA');
  const alertStep = body.timeline.findIndex(s => s.kind === 'alert');
  const before = viewAt(body, alertStep - 1);
  const at = viewAt(body, alertStep);
  assert.equal(before.alerts.length, 0);
  assert.equal(before.trust.value, 100);
  assert.equal(at.alerts.length, 1);
  assert.equal(at.trust.value, 10);
  assert.ok(at.focus.has(body.taint.maliciousNodeIds[0]));
});

// ---- HTTP: fail-loud bounds and id handling ---------------------------------------------------
test('oversize capture is refused with 413 naming the bound; it is listed with its error, not hidden', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'sentinel-dash-'));
  try {
    const filler = 'ordinary record line\n'.repeat(Math.ceil((BOUNDS.MAX_CAPTURE_BYTES + 1024) / 21));
    await writeFile(path.join(dir, 'huge.json'), JSON.stringify({ request: { messages: [{ role: 'user', content: filler }] }, response: {} }));
    await withServer([{ dir, source: 'captures' }], async (base) => {
      const r = await fetch(`${base}/api/replay?id=huge`);
      assert.equal(r.status, 413);
      const j = await r.json();
      assert.equal(j.bound, 'MAX_CAPTURE_BYTES');
      assert.ok(j.size > j.cap);
      assert.equal(j.action, 'rejected');
      const list = await (await fetch(`${base}/api/captures`)).json();
      assert.equal(list.captures.length, 1);
      assert.equal(list.captures[0].bound, 'MAX_CAPTURE_BYTES');
    });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('more than MAX_CAPTURE_FILES captures returns 507; the index never lists only the first N', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'sentinel-dash-'));
  try {
    await mkdir(path.join(dir, 'many'));
    const body = JSON.stringify({ request: { messages: [{ role: 'user', content: 'hi' }] }, response: {} });
    await Promise.all(Array.from({ length: BOUNDS.MAX_CAPTURE_FILES + 1 }, (_, i) => writeFile(path.join(dir, 'many', `c${i}.json`), body)));
    await withServer([{ dir, source: 'captures' }], async (base) => {
      const r = await fetch(`${base}/api/captures`);
      assert.equal(r.status, 507);
      assert.equal((await r.json()).bound, 'MAX_CAPTURE_FILES');
    });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('unknown ids and path-traversal attempts are 404 (ids are map keys, never file paths)', async () => {
  await withServer(defaultRoots(), async (base) => {
    for (const id of ['nope', '../../etc/passwd', 'attack/../../package', '/etc/hosts', 'attack/aim-ab.demo.json', '..%2F..%2Fsentinel%2Fdashboard%2Fpackage']) {
      const r = await fetch(`${base}/api/replay?id=${encodeURIComponent(id)}`);
      assert.equal(r.status, 404, id);
    }
    const bad = await fetch(`${base}/api/replay?id=attack/aim-ab.demo&run=nope`);
    assert.equal(bad.status, 404);
    for (const p of ['/../server.mjs', '/public/app.js', '/lib/bounds.mjs']) assert.equal((await fetch(`${base}${p}`)).status, 404, p);
  });
});

test('static UI is served with a CSP and the UI never assigns innerHTML (capture text is untrusted)', async () => {
  await withServer(defaultRoots(), async (base) => {
    for (const p of ['/', '/app.js', '/graph.js', '/replay-view.js', '/styles.css']) {
      const r = await fetch(`${base}${p}`);
      assert.equal(r.status, 200, p);
      assert.match(r.headers.get('content-security-policy'), /default-src 'self'/);
    }
  });
  for (const f of ['app.js', 'graph.js', 'replay-view.js']) {
    const src = await readFile(path.join(DASH, 'public', f), 'utf8');
    assert.doesNotMatch(src, /innerHTML|outerHTML|insertAdjacentHTML|document\.write/, f);
  }
});

// ---- latency ----------------------------------------------------------------------------------
test('latency: replay build median/p95 on the data-rich and long-path captures', async (t) => {
  const index = await indexCaptures();
  for (const id of ['placeholder/data-rich-orders', 'placeholder/long-taint-path', 'attack/aim-ab.demo']) {
    const c = await loadCapture(index.get(id));
    const run = c.runs[0];
    const { alerts } = await adaptAlerts(c.alerts ?? (await import('../lib/alert-store.mjs').then(m => m.alertsFor(c, run.key))).alerts, id);
    const samples = [];
    for (let i = 0; i < 60; i++) {
      const t0 = performance.now();
      const rp = buildReplay({ id, agent: run.agent, exchanges: run.exchanges, toolResults: run.toolResults }, alerts, { canaryHits: c.canaryHits });
      layoutGraph(rp.graph);
      samples.push(performance.now() - t0);
    }
    samples.sort((a, b) => a - b);
    const med = percentile(samples, 50);
    const p95 = percentile(samples, 95);
    t.diagnostic(`${id}: build+layout median ${med.toFixed(2)} ms, p95 ${p95.toFixed(2)} ms (n=60)`);
    assert.ok(p95 < 100, `${id} p95 ${p95.toFixed(1)} ms exceeds 100 ms`);
  }
});

test('T4 buildAlert is the real producer of the long-path marker (no hand-written marker)', () => {
  const warnings = [];
  const a = buildAlert({
    category: 'taint_flow_exfil', ruleId: 'r', disposition: 'report', detectionLatencyMs: 1, timestamp: '2026-10-12T00:00:00Z',
    entities: { agent: { name: 'A' }, session: { id: 's' }, toolCall: { id: 'step_200', name: 'step_200' }, sink: { type: 'http', destination: 'https://collector.example.test/in' } },
    taintPath: Array.from({ length: 200 }, (_, i) => ({ kind: i === 0 ? 'source' : i === 199 ? 'sink' : 'propagate', label: `step_${i + 1}` })),
  }, { onWarning: (m) => warnings.push(m) });
  assert.equal(a.TaintPath.filter(h => h.Kind === 'truncated').length, 1);
  assert.equal(warnings.length, 1, 'T4 warns loudly about the truncation');
});
