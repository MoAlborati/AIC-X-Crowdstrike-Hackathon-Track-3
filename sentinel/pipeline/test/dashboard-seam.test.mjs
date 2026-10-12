// Real seam: the REAL T5 dashboard (PR #11): capture-loader, alert-store, alert-adapter (with T4's
// real validateAlert), replay builder and its HTTP server. It reads what the pipeline wrote, which
// came from a REAL T2 proxy session. This closes the gap the integration checks on #11/#13/#14 found.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { createPipeline } from '../pipeline.mjs';
import { PipelineSink } from '../sink.mjs';
import { standinInspectors, loadStandinConfig } from '../standin.mjs';
import {
  importProxy, importDashboard, startUpstream, proxyConfig, post, tmp, evasionRequest, benignRequest, exfilResponse, benignResponse,
} from './helpers.mjs';

const STANDIN = loadStandinConfig();
let outDir;
let dash;
let savedEnv;

before(async () => {
  const { createProxy, JsonlCaptureSink } = await importProxy();
  dash = await importDashboard();
  const dir = await tmp();
  outDir = path.join(dir, 'out');
  const capturePath = path.join(dir, 'proxy.jsonl');
  let n = 0;
  const up = await startUpstream(() => ({ json: n++ === 0 ? benignResponse() : exfilResponse({ extraCalls: 299, exfilAt: 249 }) }));
  try {
    const pipeline = createPipeline({ outDir, log: () => {}, canaries: STANDIN.honeytokens.map((h) => ({ ...h })), proxyCapturePath: capturePath });
    await pipeline.init();
    const config = proxyConfig({ upstreamPort: up.port, mode: 'block', capturePath });
    const proxy = createProxy(config, { sink: new PipelineSink(new JsonlCaptureSink(config.capture), pipeline), inspectors: standinInspectors(STANDIN), logAlert: () => {} });
    const { port } = await proxy.listen();
    try {
      // Session A: blocked request (request-side). Session B: benign turn, then an exfil reply
      // with 300 tool calls (response-side). Session A never reaches the upstream, so call 0 is B.1.
      await post(port, evasionRequest(), { 'x-sentinel-session': 'session-a' });
      await post(port, benignRequest(), { 'x-sentinel-session': 'session-b' });
      await post(port, benignRequest(), { 'x-sentinel-session': 'session-b' });
    } finally {
      await proxy.close();
    }
  } finally {
    await up.close();
  }
  savedEnv = { ...process.env };
  process.env.SENTINEL_CAPTURES_DIR = path.join(outDir, 'captures');
  process.env.SENTINEL_ALERTS_DIR = path.join(outDir, 'alerts');
  process.env.SENTINEL_HIDE_PLACEHOLDERS = '1';
  process.env.SENTINEL_HIDE_STAGE = '1'; // T5-stage recordings (sentinel/dashboard/stage) are not pipeline output
});

after(() => {
  for (const k of ['SENTINEL_CAPTURES_DIR', 'SENTINEL_ALERTS_DIR', 'SENTINEL_HIDE_PLACEHOLDERS', 'SENTINEL_HIDE_STAGE']) {
    if (savedEnv[k] === undefined) delete process.env[k]; else process.env[k] = savedEnv[k];
  }
});

test('T5 loader + alert-store + adapter: pipeline output loads, every alert valid under T4 validateAlert', async () => {
  const { loader, store, adapter } = dash;
  const index = await loader.indexCaptures(loader.defaultRoots());
  assert.deepEqual([...index.keys()].sort(), ['live/session-a', 'live/session-b']);
  for (const id of index.keys()) {
    const cap = await loader.loadCapture(index.get(id));
    assert.equal(cap.shape, 'openai');
    assert.equal(cap.runs.length, 1);
    const src = await store.alertsFor(cap, cap.runs[0].key);
    assert.equal(src.origin, path.relative(path.resolve(dash.root), path.join(outDir, 'alerts', `${id.replace('/', '__')}.alerts.json`)));
    assert.equal(src.placeholder, true, 'stand-in alerts carry the PLACEHOLDER banner');
    assert.match(src.note, /STAND-IN/);
    const { alerts, validatorOrigin } = await adapter.adaptAlerts(src.alerts, id);
    assert.equal(validatorOrigin, 'sentinel/alerts/schema.js', 'real T4 validator, not the dashboard fallback');
    assert.ok(alerts.length > 0);
    for (const a of alerts) assert.equal(a.invalid, false, `${a.id}: ${a.problems.join('; ')}`);
  }
});

test('T5 HTTP server: /api/captures lists both sessions; /api/replay shows direction-labeled alerts in graph + case card', async () => {
  const server = dash.server.createServer();
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const list = await (await fetch(`${base}/api/captures`)).json();
    const ids = list.captures.map((c) => c.id).sort();
    assert.deepEqual(ids, ['live/session-a', 'live/session-b']);
    assert.ok(list.captures.every((c) => !c.error), JSON.stringify(list.captures.filter((c) => c.error)));

    const a = await (await fetch(`${base}/api/replay?id=live/session-a&run=run`)).json();
    assert.ok(a.alerts.length >= 1);
    for (const al of a.alerts) {
      assert.equal(al.blocked, true);
      assert.match(al.caseCard.narrative, /^\[request-side · blocking\]/);
    }
    assert.equal(a.alertSource.placeholder, true);

    const b = await fetch(`${base}/api/replay?id=live/session-b&run=run`);
    assert.equal(b.status, 200);
    const bj = await b.json();
    assert.equal(bj.run.exchanges.length, 2);
    assert.equal(bj.run.exchanges[1].assistant.toolCalls.length, 300, 'all 300 tool calls reach the graph');
    assert.equal(bj.alerts.length, 3);
    for (const al of bj.alerts) {
      assert.equal(al.blocked, false, 'response-side is never shown as blocked');
      assert.equal(al.reportOnly, true);
      assert.match(al.caseCard.narrative, /response-side · alert_only/);
    }
    // The alert's sink node is the real exfil destination, in the incident graph.
    assert.ok(bj.graph.nodes.some((n) => JSON.stringify(n).includes('127.0.0.1:40447')), 'sink node present in graph');
    assert.ok(bj.taint.maliciousNodeIds.length > 0, 'alert marks a malicious node');
    assert.equal(bj.metrics.invalidAlertCount, 0);
    assert.equal(bj.metrics.blockedCount, 0);
  } finally {
    await new Promise((r) => server.close(r));
  }
});
