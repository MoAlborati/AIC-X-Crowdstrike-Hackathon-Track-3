// Replays T1's REAL DVAA captures (captures/benign, captures/attack) through the proxy. A real local
// HTTP server serves the exact captured response bytes as the upstream; the proxy is not mocked.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { startUpstream, startProxy, makeConfig, readCapture, post } from './helpers.mjs';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const CAPTURES = join(REPO, 'captures');
const T4_SAMPLE_VERDICT = join(REPO, 'sentinel', 'alerts', 'examples', 'sample-verdict.json');

function benignPairs() {
  const dir = join(CAPTURES, 'benign');
  return readdirSync(dir).filter((f) => f.endsWith('.req.json')).sort().map((f) => {
    const stem = f.slice(0, -'.req.json'.length);
    return { stem, req: readFileSync(join(dir, f)), resp: readFileSync(join(dir, `${stem}.resp.json`)) };
  });
}

/** RAGBot 7005's vulnerable turn from DVAA's aim-ab demo, rebuilt as the chat.completion it served. */
function aimAbVulnerableReply() {
  const demo = JSON.parse(readFileSync(join(CAPTURES, 'attack', 'aim-ab.demo.json'), 'utf8'));
  const a = demo.runA;
  assert.equal(a.dvaa.exfilExecuted, true, 'fixture must be a ground-truth positive');
  return {
    demo,
    body: Buffer.from(JSON.stringify({
      id: 'chatcmpl-ragbot-replay', object: 'chat.completion', created: 0, model: 'ragbot',
      choices: [{ index: 0, message: { role: 'assistant', content: a.message, tool_calls: a.toolCalls }, finish_reason: a.finishReason }],
      dvaa: a.dvaa,
    })),
  };
}

test('benign DVAA captures (every agent) replay byte-identical in observe mode and are logged in full', async () => {
  const pairs = benignPairs();
  assert.ok(pairs.length >= 6, `expected >=6 benign pairs, got ${pairs.length}`);
  const byContent = new Map(pairs.map((p) => [JSON.parse(p.req).messages.at(-1).content, p.resp]));
  const up = await startUpstream(({ body }) => ({ body: byContent.get(JSON.parse(body).messages.at(-1).content) }));
  const cfg = makeConfig({ target: { port: up.port } });
  const { proxy, url } = await startProxy(cfg);
  try {
    for (const p of pairs) {
      const r = await post(`${url}/v1/chat/completions`, p.req);
      assert.equal(r.status, 200, p.stem);
      assert.ok(r.body.equals(p.resp), `${p.stem}: response must be byte-identical`);
    }
    await proxy.sink.flush();
    const recs = readCapture(cfg.capture.path).filter((x) => x.type === 'exchange');
    assert.equal(recs.length, pairs.length);
    recs.forEach((rec, i) => {
      assert.equal(rec.request.body.data, pairs[i].req.toString('utf8'));
      assert.equal(rec.response.body.data, pairs[i].resp.toString('utf8'));
      assert.equal(rec.action, 'forwarded');
    });
  } finally { await proxy.close(); await up.close(); }
});

test('aim-ab attack capture: observe forwards + logs dvaa{} ground truth; block withholds the exfil reply', async () => {
  const { demo, body } = aimAbVulnerableReply();
  const honeytoken = 'dvaa-admin-secret'; // FAKE planted secret seen at the canary in this capture
  assert.ok(demo.canary.hits[0].query.data.includes(honeytoken));
  const up = await startUpstream(() => ({ body }));
  const req = { messages: [{ role: 'user', content: 'Summarise the indexed onboarding document.' }] };

  for (const mode of ['observe', 'block']) {
    const cfg = makeConfig({ target: { port: up.port }, mode, inspect: { flagSubstrings: [honeytoken] } });
    const { proxy, url } = await startProxy(cfg);
    try {
      const r = await post(`${url}/v1/chat/completions`, req);
      await proxy.sink.flush();
      const recs = readCapture(cfg.capture.path);
      const ex = recs.find((x) => x.type === 'exchange');
      const alert = recs.find((x) => x.type === 'alert');
      assert.equal(alert.phase, 'response');
      if (mode === 'observe') {
        assert.equal(r.status, 200);
        assert.ok(r.body.equals(body), 'observe mode: unchanged');
        assert.equal(alert.action, 'would_block_observe_only');
        assert.equal(JSON.parse(ex.response.body.data).dvaa.exfilExecuted, true, 'ground truth logged');
      } else {
        assert.equal(r.status, 403);
        assert.ok(!r.body.includes(honeytoken), 'secret withheld from client');
        assert.ok(!r.body.includes('canary'), 'exfil URL withheld from client');
        assert.equal(alert.action, 'blocked');
        assert.equal(JSON.parse(ex.upstream_response.body.data).dvaa.exfilTargetUrl, demo.runA.dvaa.exfilTargetUrl);
      }
    } finally { await proxy.close(); }
  }
  await up.close();
});

test('T4-shaped verdict (sentinel/alerts sample) blocks via disposition and never echoes evidence', async () => {
  const sample = JSON.parse(readFileSync(T4_SAMPLE_VERDICT, 'utf8'));
  assert.equal(sample.disposition, 'block');
  const up = await startUpstream(() => ({ body: { ok: true } }));
  const cfg = makeConfig({ target: { port: up.port }, mode: 'block' });
  const { proxy, url } = await startProxy(cfg, { inspectors: [async ({ phase }) => (phase === 'request' ? sample : null)] });
  try {
    const r = await post(`${url}/v1/chat/completions`, { messages: [] });
    assert.equal(r.status, 403);
    const body = JSON.parse(r.body);
    assert.equal(body.sentinel.verdict_count, 1);
    assert.equal(body.sentinel.verdicts, undefined, 'verdict content stays in the log');
    assert.ok(!r.body.includes(sample.canary.value), 'canary value must not be echoed');
    assert.ok(!r.body.includes(sample.entities.sink.destination), 'sink destination must not be echoed');
    assert.equal(up.received.length, 0);
    await proxy.sink.flush();
    const alert = readCapture(cfg.capture.path).find((x) => x.type === 'alert');
    assert.equal(alert.verdicts[0].evidence, sample.evidence, 'full verdict kept in the log');
  } finally { await proxy.close(); await up.close(); }
});
