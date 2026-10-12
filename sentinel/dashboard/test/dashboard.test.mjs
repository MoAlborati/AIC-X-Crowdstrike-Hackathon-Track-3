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
import { replayPayload, createServer, isAllowedHost, assertLoopbackBind } from '../server.mjs';
import { layoutGraph, displayLabel } from '../public/graph.js';
import { viewAt, latestGate } from '../public/replay-view.js';
import { headlineView } from '../public/headline-view.js';
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
  // Port 0 draws from the kernel's ephemeral range, which this shared WSL host exhausts (4,096 ports,
  // >15k sockets in TIME-WAIT from concurrent agents' test runs), giving EADDRINUSE on listen in ~1/15
  // runs. So bind an explicit port below that range and retry on collision. Any other error is thrown.
  for (let attempt = 1; ; attempt++) {
    const port = 20000 + Math.floor(Math.random() * 20000);
    try {
      await new Promise((resolve, reject) => {
        srv.once('error', reject);
        srv.listen(port, '127.0.0.1', () => {
          srv.off('error', reject);
          resolve();
        });
      });
      break;
    } catch (err) {
      if (err.code !== 'EADDRINUSE' || attempt >= 20) throw err;
    }
  }
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
    const { alerts } = await adaptAlerts((await import('../lib/alert-store.mjs').then(m => m.alertsFor(c, run.key))).alerts, id);
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

// ---- T6 corpus (captures/variants) ------------------------------------------------------------
test('T6 corpus is indexed through its manifest: every listed case replays, labels carried, non-case JSON not indexed', async () => {
  const manifest = JSON.parse(await readFile(path.join(REPO_ROOT, 'captures/variants/manifest.json'), 'utf8'));
  const index = await indexCaptures();
  for (const c of manifest.cases) {
    const id = `variants/${c.path.replace(/\.json$/, '')}`;
    const entry = index.get(id);
    assert.ok(entry, `manifest case ${c.id} not indexed`);
    assert.equal(entry.expected, c.groundTruth === 'negative' ? 'benign' : 'attack');
    const r = await replayPayload(index, id, 'run');
    assert.equal(r.status, 200, `${id}: ${r.body.error}`);
    assert.equal(r.body.capture.expectedLabel, entry.expected);
  }
  assert.ok(![...index.keys()].some(k => /^variants\/(corpus|tools|tests)\/|manifest/.test(k)), 'generator inputs are not listed as captures');
  const { loadScoring } = await import('../lib/scoring.mjs');
  const s = await loadScoring(index, { SENTINEL_SCORING_FILE: path.join(os.tmpdir(), 'no-such-results.json') });
  assert.equal(s.corpus.benign, 6 + manifest.cases.filter(c => c.groundTruth === 'negative').length);
});

test('T6 data-rich benign case (400-row tool output, >32 KB) is kept whole in the graph', async () => {
  const index = await indexCaptures();
  const raw = JSON.parse(await readFile(path.join(REPO_ROOT, 'captures/variants/fixtures/benign/benign-toolrows.json'), 'utf8'));
  const { body } = await replayPayload(index, 'variants/fixtures/benign/benign-toolrows', 'run');
  // Since PR #15 the 400 rows are the tool-role result of a lookup_per_diem call, not the user message.
  const toolMsg = raw.request.messages.find(m => m.role === 'tool');
  assert.ok(toolMsg, 'fixture carries a tool-role message');
  assert.ok(toolMsg.content.length > 32 * 1024, 'fixture tool output is >32 KB');
  assert.equal((toolMsg.content.match(/"id":\d+/g) ?? []).length, 400, 'fixture has 400 rows');
  const node = body.graph.nodes.find(n => n.text === toolMsg.content);
  assert.ok(node, `the whole 400-row tool output is one graph node (kinds: ${[...new Set(body.graph.nodes.map(n => n.kind))].join(', ')})`);
  assert.equal(node.kind, 'tool_result');
  assert.ok(node.bytes > 32 * 1024);
  assert.ok(node.text.includes('"id":400'), 'row 400 present: nothing truncated');
});

test('T8 contrast dir is indexed through its manifest: every *.demo.json recording replays, its derived artifacts are never parsed as captures', async () => {
  const dir = path.join(REPO_ROOT, 'captures', 'contrast');
  const manifest = JSON.parse(await readFile(path.join(dir, 'manifest.json'), 'utf8'));
  const listed = new Set(manifest.cases.map(c => c.path));
  // Drift guard: a new recording that is not in the manifest would be silently skipped, so fail loud.
  const { readdir } = await import('node:fs/promises');
  const demos = (await readdir(path.join(dir, 'runs'))).filter(f => f.endsWith('.demo.json')).map(f => `runs/${f}`);
  assert.ok(demos.length >= 4, `expected >= 4 contrast recordings, got ${demos.length}`);
  for (const d of demos) assert.ok(listed.has(d), `captures/contrast/${d} is not listed in captures/contrast/manifest.json`);
  assert.equal(listed.size, demos.length, 'manifest lists only real *.demo.json recordings');

  const index = await indexCaptures();
  const ids = [...index.keys()].filter(id => id.startsWith('contrast/'));
  assert.deepEqual(ids.sort(), demos.map(d => `contrast/${d.replace(/\.json$/, '')}`).sort());
  for (const nonCapture of ['contrast/runs/contrast', 'contrast/runs/run-meta', 'contrast/standin-inspector.config']) {
    assert.ok(!index.has(nonCapture), `${nonCapture} must not be indexed as a capture`);
  }
  for (const id of ids) {
    const c = await loadCapture(index.get(id));
    for (const r of c.runs) assert.equal((await replayPayload(index, id, r.key)).status, 200, `${id}#${r.key}`);
  }
});

test('a manifest case that is missing stays in the capture list with its error (never silently skipped)', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'sentinel-dash-'));
  try {
    await mkdir(path.join(dir, 'variants', 'fixtures'), { recursive: true });
    await writeFile(path.join(dir, 'variants', 'manifest.json'), JSON.stringify({ cases: [{ id: 'A', path: 'fixtures/a.json', groundTruth: 'negative' }, { id: 'B', path: 'fixtures/gone.json' }, { id: 'C', path: '../../escape.json' }] }));
    await writeFile(path.join(dir, 'variants', 'fixtures', 'a.json'), JSON.stringify({ id: 'A', request: { messages: [{ role: 'user', content: 'hello' }] }, label: { groundTruth: 'negative' } }));
    await withServer([{ dir, source: 'captures' }], async (base) => {
      const list = (await (await fetch(`${base}/api/captures`)).json()).captures;
      assert.equal(list.length, 3);
      assert.ok(!list.find(c => c.id === 'variants/fixtures/a').error);
      assert.match(list.find(c => c.id === 'variants/fixtures/gone').error, /missing/);
      assert.match(list.find(c => /escape/.test(c.id)).error, /escapes/);
      assert.equal((await fetch(`${base}/api/replay?id=variants/fixtures/gone`)).status, 422);
    });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// ---- PR #11 review follow-ups -----------------------------------------------------------------
import http from 'node:http';
import { spawn } from 'node:child_process';
import { symlink } from 'node:fs/promises';

/** Raw GET with an explicit (or absent) Host header; fetch() does not let us set Host. */
function rawGet(base, pathname, host) {
  const { port } = new URL(base);
  return new Promise((resolve, reject) => {
    const headers = host === undefined ? {} : { host };
    const req = http.request({ host: '127.0.0.1', port, path: pathname, method: 'GET', headers, setHost: false }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (d) => { body += d; });
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', reject);
    req.end();
  });
}

test('DNS rebinding: any Host other than loopback:<port> gets 421 on every route and leaks no capture data', async () => {
  await withServer(defaultRoots(), async (base) => {
    const port = Number(new URL(base).port);
    for (const host of [`127.0.0.1:${port}`, `localhost:${port}`, `LOCALHOST:${port}`, `[::1]:${port}`]) {
      assert.equal((await rawGet(base, '/api/captures', host)).status, 200, host);
    }
    const bad = ['evil.example', `evil.example:${port}`, `127.0.0.1.evil.example:${port}`, `localhost.evil.example:${port}`,
      `127.0.0.1:${port + 1}`, '127.0.0.1', `0.0.0.0:${port}`, `192.168.1.10:${port}`, `127.0.0.1:${port}@evil.example`, ''];
    for (const host of bad) {
      for (const p of ['/api/captures', `/api/replay?id=attack/aim-ab.demo`, '/api/scoring', '/', '/app.js', '/health']) {
        const r = await rawGet(base, p, host);
        assert.equal(r.status, 421, `${JSON.stringify(host)} ${p}`);
        assert.doesNotMatch(r.body, /aim-ab|canary|captures/i, 'refusal body carries no capture data');
      }
    }
    // No Host at all on HTTP/1.1: node:http itself refuses with 400 before our handler runs.
    const none = await rawGet(base, '/api/captures', undefined);
    assert.equal(none.status, 400);
    assert.doesNotMatch(none.body, /aim-ab|canary/i);
  });
  assert.equal(isAllowedHost(undefined, 9100), false);
  assert.equal(isAllowedHost('localhost', 80), true, 'port may be omitted only for :80');
  assert.equal(isAllowedHost('localhost', 9100), false);
});

test('non-loopback --host is refused: the CLI exits 2 with a loud error and never listens', async () => {
  for (const h of ['127.0.0.1', 'localhost', '::1']) assert.doesNotThrow(() => assertLoopbackBind(h), h);
  for (const h of ['0.0.0.0', '::', '192.168.1.10', 'example.com']) assert.throws(() => assertLoopbackBind(h), /refusing to bind/, h);
  const port = 20000 + Math.floor(Math.random() * 20000);
  const child = spawn(process.execPath, [path.join(DASH, 'server.mjs'), '--host', '0.0.0.0', '--port', String(port)], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stderr = '';
  let stdout = '';
  child.stderr.on('data', (d) => { stderr += d; });
  child.stdout.on('data', (d) => { stdout += d; });
  const timer = setTimeout(() => child.kill('SIGKILL'), 10_000);
  const code = await new Promise((r) => child.on('exit', r));
  clearTimeout(timer);
  assert.equal(code, 2, `exit code (stdout: ${stdout})`);
  assert.match(stderr, /ERROR refusing to bind --host 0\.0\.0\.0/);
  assert.doesNotMatch(stdout, /dashboard →/);
});

test('favicon request is answered (204), not a console 404', async () => {
  await withServer(defaultRoots(), async (base) => {
    assert.equal((await fetch(`${base}/favicon.ico`)).status, 204);
  });
  assert.match(await readFile(path.join(DASH, 'public', 'index.html'), 'utf8'), /rel="icon" href="data:,"/);
});

test('manifest escape guard uses real paths: a symlink out of the tree is an escape; a relative captures dir works', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'sentinel-dash-'));
  const outside = await mkdtemp(path.join(os.tmpdir(), 'sentinel-outside-'));
  const cwd = process.cwd();
  try {
    await mkdir(path.join(dir, 'variants', 'fixtures'), { recursive: true });
    const ok = { id: 'A', request: { messages: [{ role: 'user', content: 'hello' }] }, label: { groundTruth: 'negative' } };
    await writeFile(path.join(dir, 'variants', 'fixtures', 'a.json'), JSON.stringify(ok));
    await writeFile(path.join(outside, 'secret.json'), JSON.stringify({ ...ok, id: 'S' }));
    await symlink(path.join(outside, 'secret.json'), path.join(dir, 'variants', 'fixtures', 'link.json'));
    await writeFile(path.join(dir, 'variants', 'manifest.json'), JSON.stringify({ cases: [
      { id: 'A', path: 'fixtures/a.json', groundTruth: 'negative' },
      { id: 'L', path: 'fixtures/link.json', groundTruth: 'negative' },
    ] }));
    const index = await indexCaptures([{ dir, source: 'captures' }]);
    assert.equal(index.get('variants/fixtures/a').error, undefined);
    assert.match(index.get('variants/fixtures/link').error, /escapes/);
    assert.equal((await replayPayload(index, 'variants/fixtures/link', 'run').catch(e => e)).name, 'CaptureFormatError');

    // Relative SENTINEL_CAPTURES_DIR: previously every manifest case read as "escapes".
    process.chdir(path.dirname(dir));
    const rel = await indexCaptures(defaultRoots({ SENTINEL_CAPTURES_DIR: path.basename(dir), SENTINEL_HIDE_PLACEHOLDERS: '1' }));
    assert.equal(rel.get('variants/fixtures/a').error, undefined, 'relative dir: in-tree case is not an escape');
    assert.equal((await replayPayload(rel, 'variants/fixtures/a', 'run')).status, 200);
    assert.match(rel.get('variants/fixtures/link').error, /escapes/);
  } finally {
    process.chdir(cwd);
    await rm(dir, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});

test('a malformed alert sidecar is a 422 naming the sidecar, not a generic 500', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'sentinel-alerts-'));
  const prev = process.env.SENTINEL_ALERTS_DIR;
  try {
    process.env.SENTINEL_ALERTS_DIR = dir;
    await writeFile(path.join(dir, 'attack__aim-ab.demo.alerts.json'), '{"runs": {"runA": [');
    await withServer(defaultRoots(), async (base) => {
      const r = await fetch(`${base}/api/replay?id=attack/aim-ab.demo&run=runA`);
      assert.equal(r.status, 422);
      assert.match((await r.json()).error, /alert sidecar .*attack__aim-ab\.demo\.alerts\.json: invalid JSON/);
      await writeFile(path.join(dir, 'attack__aim-ab.demo.alerts.json'), JSON.stringify({ runs: { runA: { not: 'an array' } } }));
      const r2 = await fetch(`${base}/api/replay?id=attack/aim-ab.demo&run=runA`);
      assert.equal(r2.status, 422);
      assert.match((await r2.json()).error, /runs\.runA is not an array/);
    });
  } finally {
    if (prev === undefined) delete process.env.SENTINEL_ALERTS_DIR;
    else process.env.SENTINEL_ALERTS_DIR = prev;
    await rm(dir, { recursive: true, force: true });
  }
});

test('long-path truncation marker keeps "N omitted" visible at the narrowest column width', async () => {
  const index = await indexCaptures();
  const { body } = await replayPayload(index, 'placeholder/long-taint-path', 'run');
  const marker = body.graph.nodes.find(n => n.kind === 'truncation_marker');
  const { positions } = layoutGraph(body.graph);
  const w = positions.get(marker.id).w;
  const shown = displayLabel(marker, w, 'truncated');
  assert.equal(shown, `⋯ ${LONG_PATH_HOPS - 63} omitted`);
  assert.ok(!shown.endsWith('…'), 'marker label is not cut by fit()');
  // Ordinary labels are still fitted for display (full text stays in <title> / detail pane).
  const long = body.graph.nodes.find(n => n.kind !== 'truncation_marker' && n.label.length > 40);
  if (long) assert.match(displayLabel(long, w, null), /…$/);
});

test('rapid capture switching: a stale replay response cannot overwrite a newer one', async () => {
  const gate = latestGate();
  const rendered = [];
  const load = async (id, delayMs) => {
    const t = gate.begin();
    await new Promise(r => setTimeout(r, delayMs));
    if (gate.isCurrent(t)) rendered.push(id);
  };
  await Promise.all([load('slow-old', 40), load('fast-new', 5)]);
  assert.deepEqual(rendered, ['fast-new']);
  const src = await readFile(path.join(DASH, 'public', 'app.js'), 'utf8');
  assert.match(src, /replayGate\.begin\(\)[\s\S]*await getJson\(`\/api\/replay[\s\S]*if \(!replayGate\.isCurrent\(token\)\) return;/, 'loadReplay checks the gate after its fetch');
});

test('headline shows T7 headline.status ("awaiting t3", "error: …") instead of a bare "—", and never a rate beside a non-ok status', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'sentinel-scoring-'));
  try {
    const index = await indexCaptures();
    const file = path.join(dir, 'results.json');
    const t7 = (over) => ({
      schema: 'sentinel-scoring/v1', headline: { detector: null, mode: 'enforce', metric: 'blocking', status: 'awaiting t3: T3 detector not present at sentinel/detectors/index.js (T3 not merged)' },
      detectionRate: null, recall: null, precision: null, falsePositiveRate: null, latencyMs: { median: null, p95: null }, counts: null, ...over,
    });
    await writeFile(file, JSON.stringify(t7({})));
    let s = await loadScoringFrom(index, file);
    assert.equal(s.status, t7({}).headline.status);
    let v = headlineView(s);
    assert.equal(v.det, 'awaiting t3');
    assert.equal(v.fp, 'awaiting t3');
    assert.ok(v.pending);
    assert.match(v.note, /T3 detector not present/);

    // T7 review finding 1: an errored run must not read as 100% even if rates are present.
    await writeFile(file, JSON.stringify(t7({ headline: { status: 'error: 15 cases errored' }, recall: 1, falsePositiveRate: 1, counts: { attack: 2, benign: 12, fp: 12, fn: 0 } })));
    v = headlineView(await loadScoringFrom(index, file));
    assert.equal(v.det, 'error');
    assert.doesNotMatch(`${v.det} ${v.fp}`, /%/);
    assert.match(v.note, /15 cases errored/);

    await writeFile(file, JSON.stringify(t7({ headline: { status: 'ok' }, recall: 0.825, falsePositiveRate: 0 })));
    v = headlineView(await loadScoringFrom(index, file));
    assert.deepEqual([v.det, v.fp, v.pending], ['82.5%', '0.0%', false]);

    assert.equal(headlineView({ available: false, corpus: { attack: 3, benign: 9 } }).det, 'awaiting T7');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

async function loadScoringFrom(index, file) {
  const { loadScoring } = await import('../lib/scoring.mjs');
  return loadScoring(index, { SENTINEL_SCORING_FILE: file });
}

// ---- embedded alerts on a multi-run capture (PR #23 finding, alert-store.mjs:28) ---------------
// Real seam: the real aim-ab T1 capture (runA/runB), copied into a temp captures root with T4 alerts
// embedded, served through the real HTTP server. Before the fix, embedded alerts on any multi-run
// capture were dropped silently and every run showed 0 alerts with no error.
async function withEmbeddedAlertsCapture(alerts, fn) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'sentinel-embedded-'));
  try {
    const raw = JSON.parse(await readFile(path.join(REPO_ROOT, 'captures', 'attack', 'aim-ab.demo.json'), 'utf8'));
    await mkdir(path.join(dir, 'attack'));
    await writeFile(path.join(dir, 'attack', 'aim-ab.demo.json'), JSON.stringify({ ...raw, alerts }));
    await withServer([{ dir, source: 'captures' }], fn);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

const sampleAlerts = async (n, prefix) => {
  const sample = JSON.parse(await readFile(path.join(HERE, 'fixtures/t4-sample-alert.json'), 'utf8'));
  return Array.from({ length: n }, (_, i) => ({ ...sample, AlertId: `${prefix}-${String(i).padStart(4, '0')}` }));
};

test('multi-run capture with alerts keyed by run surfaces every embedded alert on its own run (data-rich)', async () => {
  const runA = await sampleAlerts(240, 'embedded-runA');
  const runB = await sampleAlerts(3, 'embedded-runB');
  await withEmbeddedAlertsCapture({ runA, runB }, async (base) => {
    const a = await (await fetch(`${base}/api/replay?id=attack/aim-ab.demo&run=runA`)).json();
    assert.equal(a.alerts.length, 240, 'runA must show all 240 embedded alerts, not 0');
    assert.equal(a.alertSource.origin, 'embedded in capture');
    assert.equal(new Set(a.alerts.map(x => x.id)).size, 240, 'every alert id kept, none collapsed');
    const b = await (await fetch(`${base}/api/replay?id=attack/aim-ab.demo&run=runB`)).json();
    assert.equal(b.alerts.length, 3, 'runB must show its own 3 embedded alerts');
    assert.equal(b.alertSource.origin, 'embedded in capture');
  });
});

test('multi-run capture with a flat alerts[] array is ambiguous and fails loudly (422), never 0 alerts', async () => {
  await withEmbeddedAlertsCapture(await sampleAlerts(5, 'flat'), async (base) => {
    for (const run of ['runA', 'runB']) {
      const r = await fetch(`${base}/api/replay?id=attack/aim-ab.demo&run=${run}`);
      assert.equal(r.status, 422, `${run} must be rejected, not shown with 0 alerts`);
      assert.match((await r.json()).error, /alerts\[\] is ambiguous on a capture with 2 runs \(runA, runB\)/);
    }
  });
});

test('embedded alerts with an unknown run key or a non-array value fail loudly (422)', async () => {
  const one = await sampleAlerts(1, 'bad');
  for (const [alerts, re] of [
    [{ runa: one }, /alerts\.runa names no run of this capture \(runs: runA, runB\)/],
    [{ runA: { not: 'an array' } }, /alerts\.runA is not an array/],
    ['not-a-list', /alerts must be an array or an object keyed by run/],
  ]) {
    await withEmbeddedAlertsCapture(alerts, async (base) => {
      const r = await fetch(`${base}/api/replay?id=attack/aim-ab.demo&run=runA`);
      assert.equal(r.status, 422, JSON.stringify(alerts).slice(0, 60));
      assert.match((await r.json()).error, re);
    });
  }
});
