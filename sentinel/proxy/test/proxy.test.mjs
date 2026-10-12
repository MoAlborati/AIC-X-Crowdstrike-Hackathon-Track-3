// T2 proxy tests — real proxy, real upstream HTTP server, real JSONL capture file.
import { test, describe, after } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  startUpstream, startProxy, makeConfig, readCapture, post, dvaaCompletion,
  bigRequestWithMiddleSignal, manyRows,
} from './helpers.mjs';
import { DRAIN_LIMIT_BYTES } from '../server.mjs';

const HONEYTOKEN = 'sk-sentinel-HONEY-7f3a9c2e1b';

describe('observe mode', () => {
  test('forwards to upstream and returns status, headers and body bytes unchanged', async () => {
    const reply = Buffer.from(JSON.stringify(dvaaCompletion('[RAGBot] hello there')));
    const up = await startUpstream(() => ({ status: 200, headers: { 'x-dvaa-agent': 'ragbot' }, body: reply }));
    const cfg = makeConfig({ target: { port: up.port } });
    const { proxy, url } = await startProxy(cfg);
    try {
      const reqBody = { model: 'ragbot', messages: [{ role: 'user', content: 'hello' }] };
      const r = await post(`${url}/v1/chat/completions`, reqBody);
      assert.equal(r.status, 200);
      assert.ok(r.body.equals(reply), 'body bytes must be identical to upstream');
      assert.equal(r.headers['x-dvaa-agent'], 'ragbot');
      assert.equal(r.headers['content-type'], 'application/json');
      assert.equal(up.received.length, 1);
      assert.deepEqual(JSON.parse(up.received[0].body), reqBody, 'upstream sees the exact request body');
      assert.equal(up.received[0].url, '/v1/chat/completions');
    } finally {
      await proxy.close(); await up.close();
    }
  });

  test('passes upstream error statuses through unchanged', async () => {
    const up = await startUpstream(() => ({ status: 404, headers: { 'content-type': 'text/plain' }, body: 'Not found' }));
    const { proxy, url } = await startProxy(makeConfig({ target: { port: up.port } }));
    try {
      const r = await post(`${url}/v1/chat/completions`, {});
      assert.equal(r.status, 404);
      assert.equal(r.body.toString(), 'Not found');
    } finally { await proxy.close(); await up.close(); }
  });

  test('>8KB request and multi-hundred-row response are captured IN FULL (no head/tail truncation)', async () => {
    const rows = manyRows(600); // ~50KB data-rich tool-output-like table
    const reply = Buffer.from(JSON.stringify(dvaaCompletion(rows)));
    const up = await startUpstream(() => ({ body: reply }));
    const cfg = makeConfig({ target: { port: up.port } });
    const { proxy, url } = await startProxy(cfg);
    try {
      const reqBody = bigRequestWithMiddleSignal(HONEYTOKEN, 200 * 1024);
      const raw = Buffer.from(JSON.stringify(reqBody));
      assert.ok(raw.length > 200 * 1024);
      const mid = raw.indexOf(HONEYTOKEN);
      assert.ok(mid > 8192 && mid < raw.length - 8192, 'signal lies outside head/tail 8KB windows');

      const r = await post(`${url}/v1/chat/completions`, raw);
      assert.equal(r.status, 200);
      assert.ok(r.body.equals(reply));
      await proxy.sink.flush();

      const [rec] = readCapture(cfg.capture.path).filter((x) => x.type === 'exchange');
      assert.equal(rec.action, 'forwarded');
      assert.equal(rec.request.body.encoding, 'utf8');
      assert.equal(rec.request.body.bytes, raw.length);
      assert.equal(rec.request.body.data, raw.toString('utf8'), 'full request body logged byte-for-byte');
      assert.equal(rec.response.body.data, reply.toString('utf8'), 'full response body logged byte-for-byte');
      assert.equal(JSON.parse(rec.response.body.data).choices[0].message.content.split('\n').length, 600);
      assert.equal(rec.response.status, 200);
      assert.equal(typeof rec.latency_ms, 'number');
      assert.equal(rec.mode, 'observe');
    } finally { await proxy.close(); await up.close(); }
  });

  test('flagged request is still forwarded, with a would-block ALERT in the capture', async () => {
    const up = await startUpstream(() => ({ body: dvaaCompletion('ok') }));
    const cfg = makeConfig({ target: { port: up.port }, inspect: { flagSubstrings: [HONEYTOKEN] } });
    const { proxy, url } = await startProxy(cfg);
    try {
      const r = await post(`${url}/v1/chat/completions`, bigRequestWithMiddleSignal(HONEYTOKEN));
      assert.equal(r.status, 200);
      assert.equal(up.received.length, 1);
      await proxy.sink.flush();
      const recs = readCapture(cfg.capture.path);
      const alert = recs.find((x) => x.type === 'alert');
      assert.equal(alert.action, 'would_block_observe_only');
      assert.equal(alert.phase, 'request');
      assert.equal(alert.verdicts[0].detector, 'substring');
      const ex = recs.find((x) => x.type === 'exchange');
      assert.equal(ex.verdicts.length, 1);
      assert.equal(ex.action, 'forwarded');
    } finally { await proxy.close(); await up.close(); }
  });

  test('binary (non-UTF8) bodies are logged in full as base64', async () => {
    const bin = Buffer.from([0xff, 0xfe, 0x00, 0x01, 0x80, 0x81]);
    const up = await startUpstream(() => ({ headers: { 'content-type': 'application/octet-stream' }, body: bin }));
    const cfg = makeConfig({ target: { port: up.port } });
    const { proxy, url } = await startProxy(cfg);
    try {
      const r = await post(`${url}/v1/chat/completions`, '{}');
      assert.ok(r.body.equals(bin));
      await proxy.sink.flush();
      const [rec] = readCapture(cfg.capture.path);
      assert.equal(rec.response.body.encoding, 'base64');
      assert.ok(Buffer.from(rec.response.body.data, 'base64').equals(bin));
    } finally { await proxy.close(); await up.close(); }
  });

  test('every path is inspected (no bypass via /health, trailing slash, or other agent routes)', async () => {
    const up = await startUpstream(() => ({ body: { status: 'ok' } }));
    const cfg = makeConfig({ target: { port: up.port }, mode: 'block', inspect: { flagSubstrings: [HONEYTOKEN] } });
    const { proxy, url } = await startProxy(cfg);
    try {
      for (const p of ['/health', '/v1/chat/completions/', '//v1/chat/completions', '/a2a/tasks/send', '/mcp']) {
        const r = await post(`${url}${p}`, { messages: [{ role: 'user', content: HONEYTOKEN }] });
        assert.equal(r.status, 403, p);
      }
      assert.equal(up.received.length, 0);
      const ok = await post(`${url}/health`, '{}');
      assert.equal(ok.status, 200);
      assert.equal(JSON.parse(ok.body).status, 'ok');
    } finally { await proxy.close(); await up.close(); }
  });

  test('50 concurrent requests each get their own response and capture record', async () => {
    const up = await startUpstream(({ body }) => ({ body: dvaaCompletion(`echo:${JSON.parse(body).messages[0].content}`) }));
    const cfg = makeConfig({ target: { port: up.port } });
    const { proxy, url } = await startProxy(cfg);
    try {
      const results = await Promise.all(Array.from({ length: 50 }, (_, i) =>
        post(`${url}/v1/chat/completions`, { messages: [{ role: 'user', content: `msg-${i}` }] })));
      results.forEach((r, i) => assert.equal(JSON.parse(r.body).choices[0].message.content, `echo:msg-${i}`));
      await proxy.sink.flush();
      const recs = readCapture(cfg.capture.path).filter((x) => x.type === 'exchange');
      assert.equal(recs.length, 50);
      assert.equal(new Set(recs.map((r) => r.request_id)).size, 50);
      for (const rec of recs) {
        const sent = JSON.parse(rec.request.body.data).messages[0].content;
        assert.equal(JSON.parse(rec.response.body.data).choices[0].message.content, `echo:${sent}`);
      }
    } finally { await proxy.close(); await up.close(); }
  });
});

describe('block mode', () => {
  test('flagged request (signal mid-payload, outside 8KB head/tail) short-circuits with a structured refusal', async () => {
    const up = await startUpstream(() => ({ body: dvaaCompletion('should never be reached') }));
    const cfg = makeConfig({ target: { port: up.port }, mode: 'block', inspect: { flagSubstrings: [HONEYTOKEN] } });
    const { proxy, url } = await startProxy(cfg);
    try {
      const r = await post(`${url}/v1/chat/completions`, bigRequestWithMiddleSignal(HONEYTOKEN, 100 * 1024));
      assert.equal(r.status, 403);
      assert.equal(up.received.length, 0, 'upstream must never be contacted');
      const body = JSON.parse(r.body);
      assert.equal(body.error.type, 'sentinel_blocked');
      assert.equal(body.error.code, 'flagged_request');
      assert.equal(body.sentinel.blocked, true);
      assert.equal(body.sentinel.phase, 'request');
      assert.equal(body.sentinel.mode, 'block');
      assert.equal(body.sentinel.verdicts[0].detector, 'substring');
      assert.deepEqual(Object.keys(body.sentinel.verdicts[0]).sort(), ['detector', 'reasons'], 'no evidence echoed to client');
      assert.ok(!r.body.includes(HONEYTOKEN), 'refusal must not echo the matched secret');
      assert.equal(r.headers['x-sentinel-request-id'], body.sentinel.request_id);
      await proxy.sink.flush();
      const recs = readCapture(cfg.capture.path);
      const alert = recs.find((x) => x.type === 'alert');
      assert.equal(alert.action, 'blocked');
      assert.ok(alert.verdicts[0].hits[0].offset > 8192, 'full evidence (offset beyond 8KB head) kept in the log');
      const ex = recs.find((x) => x.type === 'exchange');
      assert.equal(ex.action, 'blocked_request');
      assert.ok(ex.request.body.data.includes(HONEYTOKEN), 'blocked request still logged in full');
    } finally { await proxy.close(); await up.close(); }
  });

  test('unflagged request in block mode is forwarded unchanged', async () => {
    const reply = Buffer.from(JSON.stringify(dvaaCompletion('fine')));
    const up = await startUpstream(() => ({ body: reply }));
    const cfg = makeConfig({ target: { port: up.port }, mode: 'block', inspect: { flagSubstrings: [HONEYTOKEN] } });
    const { proxy, url } = await startProxy(cfg);
    try {
      const r = await post(`${url}/v1/chat/completions`, { messages: [{ role: 'user', content: 'benign' }] });
      assert.equal(r.status, 200);
      assert.ok(r.body.equals(reply));
    } finally { await proxy.close(); await up.close(); }
  });

  test('flagged RESPONSE (egress of honeytoken) is withheld; upstream original kept in capture', async () => {
    const leak = dvaaCompletion(`${manyRows(300)}\nadmin key: ${HONEYTOKEN}\n${manyRows(300)}`);
    const up = await startUpstream(() => ({ body: leak }));
    const cfg = makeConfig({ target: { port: up.port }, mode: 'block', inspect: { flagSubstrings: [HONEYTOKEN] } });
    const { proxy, url } = await startProxy(cfg);
    try {
      const r = await post(`${url}/v1/chat/completions`, { messages: [{ role: 'user', content: 'list users' }] });
      assert.equal(r.status, 403);
      assert.ok(!r.body.includes(HONEYTOKEN), 'secret must not reach the client');
      assert.equal(JSON.parse(r.body).sentinel.phase, 'response');
      await proxy.sink.flush();
      const ex = readCapture(cfg.capture.path).find((x) => x.type === 'exchange');
      assert.equal(ex.action, 'blocked_response');
      assert.ok(ex.upstream_response.body.data.includes(HONEYTOKEN), 'original upstream reply captured for forensics');
    } finally { await proxy.close(); await up.close(); }
  });

  test('custom inspector hook (T3 seam) receives the full body and can block', async () => {
    const up = await startUpstream(() => ({ body: dvaaCompletion('x') }));
    const cfg = makeConfig({ target: { port: up.port }, mode: 'block' });
    const seen = [];
    const inspector = async (ctx) => {
      seen.push({ phase: ctx.phase, bytes: ctx.body.length });
      return ctx.phase === 'request' && ctx.body.includes('EXFIL') ? { flagged: true, detector: 't3-stub', reasons: ['r'] } : null;
    };
    const { proxy, url } = await startProxy(cfg, { inspectors: [inspector] });
    try {
      const big = bigRequestWithMiddleSignal('EXFIL', 300 * 1024);
      const raw = Buffer.from(JSON.stringify(big));
      const r = await post(`${url}/v1/chat/completions`, raw);
      assert.equal(r.status, 403);
      assert.deepEqual(seen, [{ phase: 'request', bytes: raw.length }]);
      assert.equal(JSON.parse(r.body).sentinel.verdicts[0].detector, 't3-stub');
    } finally { await proxy.close(); await up.close(); }
  });
});

describe('bounds + fail-loud', () => {
  test('oversize request (Content-Length) -> 413 + ALERT {payload_size, cap, action}; never forwarded', async () => {
    const up = await startUpstream(() => ({ body: dvaaCompletion('nope') }));
    const cfg = makeConfig({ target: { port: up.port }, limits: { maxRequestBytes: 32 * 1024 } });
    const alerts = [];
    const { proxy, url } = await startProxy(cfg, { logAlert: (a) => alerts.push(a) });
    try {
      const raw = Buffer.from(JSON.stringify(bigRequestWithMiddleSignal('x', 64 * 1024)));
      const r = await post(`${url}/v1/chat/completions`, raw);
      assert.equal(r.status, 413);
      const body = JSON.parse(r.body);
      assert.equal(body.error.code, 'request_too_large');
      assert.equal(body.sentinel.detail.payload_size, raw.length);
      assert.equal(body.sentinel.detail.cap, 32 * 1024);
      assert.equal(body.sentinel.detail.action, 'rejected_not_forwarded');
      assert.equal(up.received.length, 0);
      const a = alerts.find((x) => x.reason === 'request_too_large');
      assert.ok(a, 'ALERT emitted to the alert log');
      assert.equal(a.payload_size, raw.length);
      assert.equal(a.cap, 32 * 1024);
      await proxy.sink.flush();
      assert.ok(readCapture(cfg.capture.path).some((x) => x.type === 'alert' && x.reason === 'request_too_large'));
    } finally { await proxy.close(); await up.close(); }
  });

  test('oversize chunked request (no Content-Length) -> 413 + ALERT, never forwarded', async () => {
    const up = await startUpstream(() => ({ body: dvaaCompletion('nope') }));
    const cfg = makeConfig({ target: { port: up.port }, limits: { maxRequestBytes: 32 * 1024 } });
    const { proxy, url } = await startProxy(cfg);
    try {
      const raw = Buffer.from(JSON.stringify(bigRequestWithMiddleSignal('x', 256 * 1024)));
      const r = await post(`${url}/v1/chat/completions`, raw, { chunked: true });
      assert.equal(r.status, 413);
      const d = JSON.parse(r.body).sentinel.detail;
      assert.equal(d.size_is_lower_bound, false, 'drained to the end, so the size is exact');
      assert.equal(d.payload_size, raw.length);
      assert.equal(up.received.length, 0);
    } finally { await proxy.close(); await up.close(); }
  });

  test('client still uploading when 413 is sent receives the 413 (drain, no TCP reset)', async () => {
    // Coverage for the bounded drain: the proxy answers 413 while the client is still streaming
    // and keeps discarding (not buffering) the rest so the client reliably reads the refusal.
    const up = await startUpstream(() => ({ body: dvaaCompletion('nope') }));
    const cfg = makeConfig({ target: { port: up.port }, limits: { maxRequestBytes: 32 * 1024 } });
    const { proxy, url } = await startProxy(cfg);
    try {
      const raw = Buffer.alloc(4 * 1024 * 1024, 0x61);
      for (let i = 0; i < 3; i += 1) {
        const r = await post(`${url}/v1/chat/completions`, raw, { chunked: true, paced: true });
        assert.equal(r.status, 413);
        assert.equal(JSON.parse(r.body).error.code, 'request_too_large');
      }
      assert.equal(up.received.length, 0);
    } finally { await proxy.close(); await up.close(); }
  });

  test('upload beyond cap + DRAIN_LIMIT_BYTES is cut off: alert logged, never forwarded, memory bounded', async () => {
    const up = await startUpstream(() => ({ body: dvaaCompletion('nope') }));
    const cfg = makeConfig({ target: { port: up.port }, limits: { maxRequestBytes: 32 * 1024 } });
    const alerts = [];
    const { proxy, url } = await startProxy(cfg, { logAlert: (a) => alerts.push(a) });
    try {
      const raw = Buffer.alloc(DRAIN_LIMIT_BYTES + 4 * 1024 * 1024, 0x62);
      let outcome;
      try {
        const r = await post(`${url}/v1/chat/completions`, raw, { chunked: true });
        outcome = r.status;
        assert.equal(JSON.parse(r.body).sentinel.detail.size_is_lower_bound, true);
      } catch (err) {
        outcome = err.code; // the proxy may reset an abusive uploader after replying; that is allowed
        assert.ok(['ECONNRESET', 'EPIPE'].includes(err.code), err.message);
      }
      assert.ok([413, 'ECONNRESET', 'EPIPE'].includes(outcome));
      const a = alerts.find((x) => x.reason === 'request_too_large');
      assert.ok(a, 'ALERT emitted');
      assert.equal(a.size_is_lower_bound, true);
      assert.ok(a.payload_size > 32 * 1024 + DRAIN_LIMIT_BYTES);
      assert.equal(up.received.length, 0);
    } finally { await proxy.close(); await up.close(); }
  });

  test('request exactly at the cap is accepted (boundary)', async () => {
    const up = await startUpstream(() => ({ body: dvaaCompletion('ok') }));
    const cap = 16 * 1024;
    const cfg = makeConfig({ target: { port: up.port }, limits: { maxRequestBytes: cap } });
    const { proxy, url } = await startProxy(cfg);
    try {
      const prefix = '{"messages":[{"role":"user","content":"';
      const suffix = '"}]}';
      const raw = Buffer.from(prefix + 'a'.repeat(cap - prefix.length - suffix.length) + suffix);
      assert.equal(raw.length, cap);
      assert.equal((await post(`${url}/v1/chat/completions`, raw)).status, 200);
      const over = Buffer.from(prefix + 'a'.repeat(cap - prefix.length - suffix.length + 1) + suffix);
      assert.equal((await post(`${url}/v1/chat/completions`, over)).status, 413);
    } finally { await proxy.close(); await up.close(); }
  });

  test('oversize upstream response -> 502 + ALERT, response not returned', async () => {
    const huge = Buffer.from(JSON.stringify(dvaaCompletion(manyRows(5000))));
    const up = await startUpstream(() => ({ body: huge }));
    const cfg = makeConfig({ target: { port: up.port }, limits: { maxResponseBytes: 64 * 1024 } });
    const alerts = [];
    const { proxy, url } = await startProxy(cfg, { logAlert: (a) => alerts.push(a) });
    try {
      const r = await post(`${url}/v1/chat/completions`, {});
      assert.equal(r.status, 502);
      const d = JSON.parse(r.body).sentinel.detail;
      assert.equal(d.payload_size, huge.length);
      assert.equal(d.cap, 64 * 1024);
      assert.ok(alerts.some((a) => a.reason === 'response_too_large'));
    } finally { await proxy.close(); await up.close(); }
  });

  test('oversize chunked upstream response -> 502 (streamed, no Content-Length)', async () => {
    const up = await startUpstream(({ res }) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      for (let i = 0; i < 40; i += 1) res.write('x'.repeat(4096));
      res.end();
    });
    const cfg = makeConfig({ target: { port: up.port }, limits: { maxResponseBytes: 64 * 1024 } });
    const { proxy, url } = await startProxy(cfg);
    try {
      const r = await post(`${url}/v1/chat/completions`, {});
      assert.equal(r.status, 502);
      assert.equal(JSON.parse(r.body).sentinel.detail.size_is_lower_bound, true);
    } finally { await proxy.close(); await up.close(); }
  });

  test('inspector crash: block mode fails CLOSED (503), observe mode forwards + ALERT', async () => {
    const up = await startUpstream(() => ({ body: dvaaCompletion('ok') }));
    const boom = async () => { throw new Error('detector exploded'); };
    for (const mode of ['block', 'observe']) {
      const cfg = makeConfig({ target: { port: up.port }, mode });
      const alerts = [];
      const { proxy, url } = await startProxy(cfg, { inspectors: [boom], logAlert: (a) => alerts.push(a) });
      try {
        const r = await post(`${url}/v1/chat/completions`, { messages: [] });
        assert.equal(r.status, mode === 'block' ? 503 : 200);
        assert.ok(alerts.some((a) => a.reason === 'inspector_error'));
      } finally { await proxy.close(); }
    }
    assert.equal(up.received.length, 1, 'only the observe-mode request was forwarded');
    await up.close();
  });

  test('capture sink full -> 503 + ALERT; exchange is never returned unlogged', async () => {
    const reply = dvaaCompletion(manyRows(200));
    const up = await startUpstream(() => ({ body: reply }));
    const cfg = makeConfig({ target: { port: up.port }, capture: { maxFileBytes: 4096 } });
    const alerts = [];
    const { proxy, url } = await startProxy(cfg, { logAlert: (a) => alerts.push(a) });
    try {
      const r = await post(`${url}/v1/chat/completions`, { messages: [] });
      assert.equal(r.status, 503);
      assert.equal(JSON.parse(r.body).error.code, 'capture_unavailable');
      assert.ok(!r.body.includes('user1@example.test'));
      const a = alerts.find((x) => x.reason === 'capture_write_failed');
      assert.ok(a.payload_size > 4096);
      assert.equal(a.cap, 4096);
    } finally { await proxy.close(); await up.close(); }
  });

  test('upstream unreachable -> 502 structured; upstream timeout -> 504', async () => {
    const dead = await startUpstream(() => ({ body: {} }));
    const deadPort = dead.port;
    await dead.close();
    let cfg = makeConfig({ target: { port: deadPort } });
    let { proxy, url } = await startProxy(cfg);
    try {
      const r = await post(`${url}/v1/chat/completions`, {});
      assert.equal(r.status, 502);
      assert.equal(JSON.parse(r.body).error.code, 'upstream_unreachable');
    } finally { await proxy.close(); }

    const slow = await startUpstream(() => new Promise(() => {})); // never responds
    cfg = makeConfig({ target: { port: slow.port }, limits: { upstreamTimeoutMs: 200 } });
    ({ proxy, url } = await startProxy(cfg));
    try {
      const r = await post(`${url}/v1/chat/completions`, {});
      assert.equal(r.status, 504);
      assert.equal(JSON.parse(r.body).error.code, 'upstream_timeout');
    } finally { await proxy.close(); await slow.close(); }
  });
});

describe('latency (proxy overhead vs real local upstream)', () => {
  const tmp = mkdtempSync(join(tmpdir(), 'sentinel-lat-'));
  after(() => writeFileSync(join(tmp, 'done'), ''));
  test('records median + p95 for 200 requests with a 50KB body', async () => {
    const reply = Buffer.from(JSON.stringify(dvaaCompletion(manyRows(300))));
    const up = await startUpstream(() => ({ body: reply }));
    const cfg = makeConfig({ target: { port: up.port }, inspect: { flagSubstrings: [HONEYTOKEN] } });
    const { proxy, url } = await startProxy(cfg);
    const body = Buffer.from(JSON.stringify(bigRequestWithMiddleSignal('benign', 50 * 1024)));
    const time = async (target) => {
      const out = [];
      for (let i = 0; i < 200; i += 1) {
        const t = process.hrtime.bigint();
        await post(target, body);
        out.push(Number(process.hrtime.bigint() - t) / 1e6);
      }
      return out.sort((a, b) => a - b);
    };
    try {
      const direct = await time(`http://127.0.0.1:${up.port}/v1/chat/completions`);
      const via = await time(`${url}/v1/chat/completions`);
      const pct = (a, p) => a[Math.min(a.length - 1, Math.floor(a.length * p))];
      const stats = {
        direct_median_ms: pct(direct, 0.5), direct_p95_ms: pct(direct, 0.95),
        proxied_median_ms: pct(via, 0.5), proxied_p95_ms: pct(via, 0.95),
      };
      stats.overhead_median_ms = stats.proxied_median_ms - stats.direct_median_ms;
      console.log(`[latency] ${JSON.stringify(Object.fromEntries(Object.entries(stats).map(([k, v]) => [k, Number(v.toFixed(3))])))}`);
      assert.ok(stats.proxied_median_ms < 50, 'proxied median should be well under 50ms locally');
    } finally { await proxy.close(); await up.close(); }
  });
});
