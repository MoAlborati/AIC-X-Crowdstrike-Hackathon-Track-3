// T2 proxy tests — real proxy, real upstream HTTP server, real JSONL capture file.
import { test, describe, after } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, readFileSync, mkdtempSync, statSync, chmodSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import zlib from 'node:zlib';
import net from 'node:net';
import http from 'node:http';
import {
  startUpstream, startProxy, makeConfig, readCapture, post, send, dvaaCompletion, deadPort,
  bigRequestWithMiddleSignal, manyRows,
} from './helpers.mjs';
import { DRAIN_LIMIT_BYTES, REFUSAL_CODES, createProxy } from '../server.mjs';
import { ConfigError } from '../../config/load.mjs';
import { DISPOSITIONS, buildAlert } from '../../alerts/index.js';

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
      const [rec] = readCapture(cfg.capture.path).filter((x) => x.type === 'exchange');
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
      assert.equal(body.sentinel.verdict_count, 1);
      assert.equal(body.sentinel.verdicts, undefined, 'no verdict content (detector/reasons/evidence) echoed to client');
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
      assert.equal(JSON.parse(r.body).sentinel.verdict_count, 1);
      await proxy.sink.flush();
      assert.equal(readCapture(cfg.capture.path).find((x) => x.type === 'alert').verdicts[0].detector, 't3-stub', 'detector name kept in the log');
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
    let cfg = makeConfig({ target: { port: await deadPort() } });
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

// ---------------------------------------------------------------------------------------------
// PR #14 review fixes. Real upstream servers + real proxy + real capture file throughout.
// ---------------------------------------------------------------------------------------------

const DVAA_TOKEN = 'dvaa{FAKE_HONEYTOKEN_7c1e9b}';
const ENCODERS = { gzip: zlib.gzipSync, deflate: zlib.deflateSync, br: zlib.brotliCompressSync };
/** Data-rich leak: 300 rows, token, 300 rows (>8KB, token outside the head/tail 8KB windows). */
const leakReply = () => Buffer.from(JSON.stringify(dvaaCompletion(`${manyRows(300)}\n${DVAA_TOKEN}\n${manyRows(300)}`)));
/** Assert a client-facing body carries no part of the secret (any 8+ char slice of it). */
function assertNoSecret(buf, secret, label) {
  const text = buf.toString('utf8');
  for (let i = 0; i + 8 <= secret.length; i += 1) {
    assert.ok(!text.includes(secret.slice(i, i + 8)), `${label}: leaked secret fragment ${JSON.stringify(secret.slice(i, i + 8))}`);
  }
}

describe('H1 content-encoding is decoded before inspection (block mode)', () => {
  for (const coding of Object.keys(ENCODERS)) {
    test(`${coding}-encoded RESPONSE carrying the honeytoken is withheld (403), never returned`, async () => {
      const plain = leakReply();
      assert.ok(plain.indexOf(DVAA_TOKEN) > 8192 && plain.indexOf(DVAA_TOKEN) < plain.length - 8192);
      const up = await startUpstream(() => ({ headers: { 'content-encoding': coding }, body: ENCODERS[coding](plain) }));
      const cfg = makeConfig({ target: { port: up.port }, mode: 'block', inspect: { flagSubstrings: [DVAA_TOKEN] } });
      const { proxy, url } = await startProxy(cfg);
      try {
        const r = await post(`${url}/v1/chat/completions`, { messages: [{ role: 'user', content: 'list users' }] });
        assert.equal(r.status, 403);
        assert.equal(JSON.parse(r.body).error.code, 'flagged_response');
        assertNoSecret(r.body, DVAA_TOKEN, coding);
        await proxy.sink.flush();
        const ex = readCapture(cfg.capture.path).find((x) => x.type === 'exchange');
        assert.ok(ex.upstream_response.decoded_body.data.includes(DVAA_TOKEN), 'decoded upstream reply kept for forensics');
      } finally { await proxy.close(); await up.close(); }
    });

    test(`${coding}-encoded REQUEST carrying the honeytoken is refused (403) and never forwarded`, async () => {
      const up = await startUpstream(() => ({ body: dvaaCompletion('should never be reached') }));
      const cfg = makeConfig({ target: { port: up.port }, mode: 'block', inspect: { flagSubstrings: [DVAA_TOKEN] } });
      const { proxy, url } = await startProxy(cfg);
      try {
        const raw = Buffer.from(JSON.stringify(bigRequestWithMiddleSignal(DVAA_TOKEN, 100 * 1024)));
        const r = await post(`${url}/v1/chat/completions`, ENCODERS[coding](raw), { headers: { 'content-encoding': coding } });
        assert.equal(r.status, 403);
        assert.equal(JSON.parse(r.body).error.code, 'flagged_request');
        assert.equal(up.received.length, 0, 'upstream must never be contacted');
      } finally { await proxy.close(); await up.close(); }
    });
  }

  test('observe mode: encoded response is returned byte-identical (still encoded) with a would-block ALERT', async () => {
    const enc = zlib.gzipSync(leakReply());
    const up = await startUpstream(() => ({ headers: { 'content-encoding': 'gzip' }, body: enc }));
    const cfg = makeConfig({ target: { port: up.port }, inspect: { flagSubstrings: [DVAA_TOKEN] } });
    const alerts = [];
    const { proxy, url } = await startProxy(cfg, { logAlert: (a) => alerts.push(a) });
    try {
      const r = await post(`${url}/v1/chat/completions`, {});
      assert.equal(r.status, 200);
      assert.ok(r.body.equals(enc));
      assert.equal(r.headers['content-encoding'], 'gzip');
      assert.ok(alerts.some((a) => a.reason === 'flagged' && a.phase === 'response'));
    } finally { await proxy.close(); await up.close(); }
  });

  test('unsupported / stacked / corrupt encodings fail CLOSED in block mode; observe forwards + ALERT', async () => {
    const up = await startUpstream(({ req }) => (req.url === '/resp-zstd'
      ? { headers: { 'content-encoding': 'zstd' }, body: Buffer.from(DVAA_TOKEN) }
      : { body: dvaaCompletion('ok') }));
    for (const mode of ['block', 'observe']) {
      const cfg = makeConfig({ target: { port: up.port }, mode, inspect: { flagSubstrings: [DVAA_TOKEN] } });
      const alerts = [];
      const { proxy, url } = await startProxy(cfg, { logAlert: (a) => alerts.push(a) });
      try {
        const before = up.received.length;
        const cases = [
          { 'content-encoding': 'compress' },
          { 'content-encoding': 'gzip, gzip, gzip, gzip, gzip' },
          { 'content-encoding': 'gzip' }, // body is not gzip -> corrupt
        ];
        for (const headers of cases) {
          const r = await post(`${url}/v1/chat/completions`, Buffer.from(DVAA_TOKEN), { headers });
          if (mode === 'block') {
            assert.equal(r.status, 415, JSON.stringify(headers));
            assert.equal(JSON.parse(r.body).error.code, 'uninspectable_encoding');
          } else assert.equal(r.status, 200);
        }
        assert.equal(up.received.length - before, mode === 'block' ? 0 : cases.length);
        const rz = await post(`${url}/resp-zstd`, {});
        assert.equal(rz.status, mode === 'block' ? 502 : 200);
        if (mode === 'block') assertNoSecret(rz.body, DVAA_TOKEN, 'zstd response');
        assert.equal(alerts.filter((a) => a.reason === 'uninspectable_encoding').length, cases.length + 1);
      } finally { await proxy.close(); }
    }
    await up.close();
  });

  test('zip bomb: decoded size over the cap -> 413/502 + ALERT, inflate stops at the cap', async () => {
    const bomb = zlib.gzipSync(Buffer.alloc(64 * 1024 * 1024, 0x61)); // ~64KB on the wire, 64MiB decoded
    assert.ok(bomb.length < 128 * 1024);
    const up = await startUpstream(({ req }) => (req.url === '/bomb'
      ? { headers: { 'content-encoding': 'gzip' }, body: bomb } : { body: dvaaCompletion('ok') }));
    const cfg = makeConfig({ target: { port: up.port }, mode: 'block' });
    const alerts = [];
    const { proxy, url } = await startProxy(cfg, { logAlert: (a) => alerts.push(a) });
    try {
      const r = await post(`${url}/v1/chat/completions`, bomb, { headers: { 'content-encoding': 'gzip' } });
      assert.equal(r.status, 413);
      assert.equal(JSON.parse(r.body).sentinel.detail.decoded, true);
      assert.equal(up.received.length, 0);
      const rr = await post(`${url}/bomb`, {});
      assert.equal(rr.status, 502);
      assert.equal(JSON.parse(rr.body).error.code, 'response_too_large');
      assert.ok(alerts.some((a) => a.reason === 'request_too_large' && a.decoded));
      assert.ok(alerts.some((a) => a.reason === 'response_too_large' && a.decoded));
    } finally { await proxy.close(); await up.close(); }
  });
});

describe('H2 verdicts: T4 case-insensitive dispositions; malformed verdicts fail closed', () => {
  for (const disposition of ['Blocked', 'BLOCK', 'block', 'blocked']) {
    test(`disposition ${JSON.stringify(disposition)} blocks`, async () => {
      const up = await startUpstream(() => ({ body: dvaaCompletion('x') }));
      const cfg = makeConfig({ target: { port: up.port }, mode: 'block' });
      const { proxy, url } = await startProxy(cfg, { inspectors: [async ({ phase }) => (phase === 'request' ? { ruleId: 'taint.x', disposition } : null)] });
      try {
        const r = await post(`${url}/v1/chat/completions`, { messages: [] });
        assert.equal(r.status, 403);
        assert.equal(up.received.length, 0);
      } finally { await proxy.close(); await up.close(); }
    });
  }

  test('allow-type dispositions (Allowed / ReportOnly) do not block', async () => {
    const up = await startUpstream(() => ({ body: dvaaCompletion('x') }));
    for (const disposition of ['Allowed', 'ReportOnly', 'report']) {
      const cfg = makeConfig({ target: { port: up.port }, mode: 'block' });
      const { proxy, url } = await startProxy(cfg, { inspectors: [async () => ({ ruleId: 'r', disposition })] });
      try { assert.equal((await post(`${url}/v1/chat/completions`, {})).status, 200, disposition); } finally { await proxy.close(); }
    }
    await up.close();
  });

  const MALFORMED = [{ flagged: 'true' }, { flagged: 1 }, {}, { disposition: 'maybe' }, { disposition: 42 },
    { disposition: 'hold' }, { disposition: 'Hold' }, { disposition: 'constructor' }, 'block', true, 42, ['flagged']];
  test('malformed verdicts -> block: 503 inspector_error (never forwarded); observe: forwarded + ALERT', async () => {
    for (const v of MALFORMED) {
      for (const mode of ['block', 'observe']) {
        const up = await startUpstream(() => ({ body: dvaaCompletion('x') }));
        const cfg = makeConfig({ target: { port: up.port }, mode });
        const alerts = [];
        const { proxy, url } = await startProxy(cfg, { inspectors: [async () => v], logAlert: (a) => alerts.push(a) });
        try {
          const r = await post(`${url}/v1/chat/completions`, {});
          assert.equal(r.status, mode === 'block' ? 503 : 200, `${mode} ${JSON.stringify(v)}`);
          if (mode === 'block') {
            assert.equal(JSON.parse(r.body).error.code, 'inspector_error');
            assert.equal(up.received.length, 0, JSON.stringify(v));
          }
          assert.ok(alerts.some((a) => a.reason === 'inspector_error'), JSON.stringify(v));
        } finally { await proxy.close(); await up.close(); }
      }
    }
  });
});

describe('H3 refusals carry only static codes (no inspector text, reasons or internal errors)', () => {
  test('JSON.parse-throwing inspector over a honeytoken body: 503 carries no token fragment', async () => {
    const up = await startUpstream(() => ({ headers: { 'content-type': 'text/plain' }, body: `${DVAA_TOKEN} ${manyRows(400)}` }));
    const cfg = makeConfig({ target: { port: up.port }, mode: 'block' });
    const alerts = [];
    const parse = async ({ body }) => { JSON.parse(body.toString('utf8')); return null; };
    const { proxy, url } = await startProxy(cfg, { inspectors: [parse], logAlert: (a) => alerts.push(a) });
    try {
      const r = await post(`${url}/v1/chat/completions`, {});
      assert.equal(r.status, 503);
      const body = JSON.parse(r.body);
      assert.equal(body.error.code, 'inspector_error');
      assert.ok(!r.body.includes('JSON'), 'no exception text');
      assertNoSecret(r.body, DVAA_TOKEN, 'inspector error refusal');
      const a = alerts.find((x) => x.reason === 'inspector_error');
      assert.match(a.error, /JSON/, 'the real error text is kept in the log');
    } finally { await proxy.close(); await up.close(); }
  });

  test('verdict reasons / detector containing the secret never reach the client', async () => {
    const up = await startUpstream(() => ({ body: dvaaCompletion('x') }));
    const cfg = makeConfig({ target: { port: up.port }, mode: 'block' });
    const leaky = async () => ({ flagged: true, detector: `det-${DVAA_TOKEN}`, reasons: [`found ${DVAA_TOKEN}`], evidence: DVAA_TOKEN });
    const { proxy, url } = await startProxy(cfg, { inspectors: [leaky] });
    try {
      const r = await post(`${url}/v1/chat/completions`, {});
      assert.equal(r.status, 403);
      assertNoSecret(r.body, DVAA_TOKEN, 'reasons leak');
      await proxy.sink.flush();
      assert.ok(readCapture(cfg.capture.path).find((x) => x.type === 'alert').verdicts[0].reasons[0].includes(DVAA_TOKEN), 'kept in log');
    } finally { await proxy.close(); await up.close(); }
  });

  test('upstream_unreachable and the 500 handler expose no error text, address or port', async () => {
    const dport = await deadPort();
    let { proxy, url } = await startProxy(makeConfig({ target: { port: dport } }));
    try {
      const r = await post(`${url}/v1/chat/completions`, {});
      assert.equal(r.status, 502);
      const t = r.body.toString();
      for (const bad of ['ECONNREFUSED', '127.0.0.1:1', '127.0.0.1', 'connect']) assert.ok(!t.includes(bad), `leaked ${bad}`);
    } finally { await proxy.close(); }

    // Force the internal-error path: the alert logger throws (with the secret in its message) on the
    // 'flagged' alert, so handle() rejects and the 500 handler runs.
    const up = await startUpstream(() => ({ body: dvaaCompletion('x') }));
    const cfg = makeConfig({ target: { port: up.port }, mode: 'block', inspect: { flagSubstrings: [DVAA_TOKEN] } });
    ({ proxy, url } = await startProxy(cfg, {
      logAlert: (a) => { if (a.reason === 'flagged') throw new Error(`logger exploded on ${DVAA_TOKEN}`); },
    }));
    try {
      const r = await post(`${url}/v1/chat/completions`, { messages: [{ role: 'user', content: DVAA_TOKEN }] });
      assert.equal(r.status, 500);
      assert.equal(JSON.parse(r.body).error.code, 'internal_error');
      assert.ok(!r.body.includes('exploded'));
      assertNoSecret(r.body, DVAA_TOKEN, '500 handler');
      assert.equal(up.received.length, 0);
    } finally { await proxy.close(); await up.close(); }
  });

  test('every refusal code is from the static enum', () => {
    for (const c of REFUSAL_CODES) assert.match(c, /^[a-z_]+$/);
  });
});

describe('H4 inspector deadline', () => {
  for (const phase of ['request', 'response']) {
    test(`hung ${phase} inspector: block -> 503 inspector_timeout + ALERT; observe -> forwarded + ALERT`, async () => {
      const up = await startUpstream(() => ({ body: dvaaCompletion('x') }));
      for (const mode of ['block', 'observe']) {
        const cfg = makeConfig({ target: { port: up.port }, mode, limits: { inspectorTimeoutMs: 150 } });
        const alerts = [];
        let aborted = false;
        const hang = (ctx) => (ctx.phase === phase
          ? new Promise(() => { ctx.signal.addEventListener('abort', () => { aborted = true; }); })
          : null);
        const { proxy, url } = await startProxy(cfg, { inspectors: [hang], logAlert: (a) => alerts.push(a) });
        try {
          const before = up.received.length;
          const t0 = Date.now();
          const r = await post(`${url}/v1/chat/completions`, {});
          const elapsed = Date.now() - t0;
          assert.ok(elapsed < 2000, `deadline fired promptly (${elapsed}ms)`);
          assert.equal(r.status, mode === 'block' ? 503 : 200);
          if (mode === 'block') assert.equal(JSON.parse(r.body).error.code, 'inspector_timeout');
          const a = alerts.find((x) => x.reason === 'inspector_timeout');
          assert.ok(a, 'ALERT emitted');
          assert.equal(a.phase, phase);
          assert.ok(aborted, 'inspector got an abort signal');
          const forwarded = up.received.length - before;
          assert.equal(forwarded, phase === 'request' && mode === 'block' ? 0 : 1);
        } finally { await proxy.close(); }
      }
      await up.close();
    });
  }
});

describe('M6 URL + headers are inspected, not just the body', () => {
  test('honeytoken in query string (raw, percent-encoded, double-encoded) or a request header -> 403', async () => {
    const up = await startUpstream(() => ({ body: { ok: true } }));
    const cfg = makeConfig({ target: { port: up.port }, mode: 'block', inspect: { flagSubstrings: [DVAA_TOKEN] } });
    const { proxy, url } = await startProxy(cfg);
    try {
      const once = encodeURIComponent(DVAA_TOKEN);
      const twice = encodeURIComponent(once);
      for (const q of [`?k=${DVAA_TOKEN}`, `?k=${once}`, `?k=${twice}`, `?a=%ZZ&k=${once}`]) {
        const r = await send(`${url}/x${q}`);
        assert.equal(r.status, 403, q);
      }
      const h = await send(`${url}/x`, { headers: { 'x-exfil': DVAA_TOKEN } });
      assert.equal(h.status, 403);
      assert.equal(up.received.length, 0);
      assert.equal((await send(`${url}/x?k=benign`)).status, 200);
    } finally { await proxy.close(); await up.close(); }
  });

  test('honeytoken in a RESPONSE header -> 403 in block mode', async () => {
    const up = await startUpstream(() => ({ headers: { 'x-debug': DVAA_TOKEN }, body: { ok: true } }));
    const cfg = makeConfig({ target: { port: up.port }, mode: 'block', inspect: { flagSubstrings: [DVAA_TOKEN] } });
    const { proxy, url } = await startProxy(cfg);
    try {
      const r = await send(`${url}/x`);
      assert.equal(r.status, 403);
      assert.equal(r.headers['x-debug'], undefined);
      assertNoSecret(r.body, DVAA_TOKEN, 'response header');
    } finally { await proxy.close(); await up.close(); }
  });
});

describe('M7 aggregate bounds: in-flight cap + client timeout', () => {
  test('requests beyond limits.maxInFlight -> 503 overloaded + ALERT, not forwarded', async () => {
    let release;
    const gate = new Promise((r) => { release = r; });
    const up = await startUpstream(async () => { await gate; return { body: dvaaCompletion('x') }; });
    const cfg = makeConfig({ target: { port: up.port }, limits: { maxInFlight: 2 } });
    const alerts = [];
    const { proxy, url } = await startProxy(cfg, { logAlert: (a) => alerts.push(a) });
    try {
      const held = [post(`${url}/a`, {}), post(`${url}/b`, {})];
      while (up.received.length < 2) await new Promise((r) => setTimeout(r, 5));
      const r = await post(`${url}/c`, {});
      assert.equal(r.status, 503);
      assert.equal(JSON.parse(r.body).error.code, 'overloaded');
      const a = alerts.find((x) => x.reason === 'overloaded');
      assert.equal(a.cap, 2);
      release();
      for (const h of await Promise.all(held)) assert.equal(h.status, 200);
      assert.equal(up.received.length, 2);
      assert.equal(proxy.inFlight, 0, 'slots released');
      assert.equal((await post(`${url}/d`, {})).status, 200);
    } finally { release(); await proxy.close(); await up.close(); }
  });

  test('slow-drip uploader is cut at limits.clientTimeoutMs with 408 + ALERT; never forwarded', async () => {
    const up = await startUpstream(() => ({ body: dvaaCompletion('x') }));
    const cfg = makeConfig({ target: { port: up.port }, limits: { clientTimeoutMs: 400 } });
    const alerts = [];
    const { proxy, port } = await startProxy(cfg, { logAlert: (a) => alerts.push(a) });
    try {
      const t0 = Date.now();
      const got = await new Promise((resolve) => {
        const s = net.connect(port, '127.0.0.1', () => s.write('POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\n{"a":'));
        let buf = '';
        const drip = setInterval(() => { if (s.writable) s.write(' '); }, 50);
        s.on('data', (d) => { buf += d; });
        s.on('close', () => { clearInterval(drip); resolve(buf); });
        s.on('error', () => {});
      });
      assert.ok(Date.now() - t0 < 4000, 'cut off near the deadline, not after 300s');
      assert.match(got, /^HTTP\/1\.1 408/);
      assert.ok(got.includes('client_timeout'));
      assert.ok(alerts.some((a) => a.reason === 'client_timeout'));
      assert.equal(up.received.length, 0);
    } finally { await proxy.close(); await up.close(); }
  });
});

describe('M8 Expect: 100-continue', () => {
  test('declared oversize Content-Length gets 413 immediately, never "100 Continue"', async () => {
    const up = await startUpstream(() => ({ body: dvaaCompletion('x') }));
    const cfg = makeConfig({ target: { port: up.port }, limits: { maxRequestBytes: 32 * 1024 } });
    const { proxy, port } = await startProxy(cfg);
    try {
      const got = await new Promise((resolve) => {
        const s = net.connect(port, '127.0.0.1', () => s.write(`POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Length: ${10 * 1024 * 1024}\r\nExpect: 100-continue\r\n\r\n`));
        let buf = '';
        s.on('data', (d) => { buf += d; if (buf.includes('\r\n\r\n')) s.destroy(); });
        s.on('close', () => resolve(buf));
        s.on('error', () => {});
      });
      assert.match(got, /^HTTP\/1\.1 413/);
      assert.ok(!got.includes('100 Continue'));
      assert.equal(up.received.length, 0);
    } finally { await proxy.close(); await up.close(); }
  });

  test('in-cap Expect: 100-continue still gets 100 Continue and is forwarded', async () => {
    const up = await startUpstream(() => ({ body: dvaaCompletion('ok') }));
    const { proxy, port } = await startProxy(makeConfig({ target: { port: up.port } }));
    try {
      const body = Buffer.from(JSON.stringify({ messages: [{ role: 'user', content: 'hi' }] }));
      const status = await new Promise((resolve, reject) => {
        const req = http.request({ host: '127.0.0.1', port, method: 'POST', path: '/v1/chat/completions', headers: { expect: '100-continue', 'content-length': body.length } });
        req.on('continue', () => req.end(body));
        req.on('response', (res) => { res.resume(); resolve(res.statusCode); });
        req.on('error', reject);
      });
      assert.equal(status, 200);
      assert.equal(up.received.length, 1);
    } finally { await proxy.close(); await up.close(); }
  });
});

describe('M9 write-ahead request record', () => {
  test('observe mode with a full sink: the request is NOT forwarded (no side effect without a record)', async () => {
    const up = await startUpstream(() => ({ body: dvaaCompletion('x') }));
    const cfg = makeConfig({ target: { port: up.port }, capture: { maxFileBytes: 600 } });
    const alerts = [];
    const { proxy, url } = await startProxy(cfg, { logAlert: (a) => alerts.push(a) });
    try {
      const r = await post(`${url}/v1/chat/completions`, { messages: [{ role: 'user', content: manyRows(20) }] });
      assert.equal(r.status, 503);
      assert.equal(JSON.parse(r.body).error.code, 'capture_unavailable');
      assert.equal(up.received.length, 0, 'upstream must not be hit before the request is on disk');
      assert.ok(alerts.some((a) => a.reason === 'capture_write_failed' && a.action === 'refused_not_forwarded'));
    } finally { await proxy.close(); await up.close(); }
  });

  test('the request record is on disk before the upstream sees the request', async () => {
    let capturePath;
    let seenOnDisk = null;
    const up = await startUpstream(() => {
      seenOnDisk = readCapture(capturePath).some((x) => x.type === 'request');
      return { body: dvaaCompletion('x') };
    });
    const cfg = makeConfig({ target: { port: up.port } });
    capturePath = cfg.capture.path;
    const { proxy, url } = await startProxy(cfg);
    try {
      assert.equal((await post(`${url}/v1/chat/completions`, { messages: [] })).status, 200);
      assert.equal(seenOnDisk, true);
    } finally { await proxy.close(); await up.close(); }
  });
});

describe('LOW fixes', () => {
  test('L10 HEAD on a large upstream resource: no false 502, Content-Length preserved', async () => {
    const up = await startUpstream(({ res }) => {
      res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': String(100 * 1024 * 1024) });
      res.end();
    });
    const cfg = makeConfig({ target: { port: up.port }, limits: { maxResponseBytes: 64 * 1024 } });
    const { proxy, url } = await startProxy(cfg);
    try {
      const r = await send(`${url}/big.bin`, { method: 'HEAD' });
      assert.equal(r.status, 200);
      assert.equal(r.headers['content-length'], String(100 * 1024 * 1024));
    } finally { await proxy.close(); await up.close(); }
  });

  test('L11 capture file is owner-only (0600), and an existing 0644 file is tightened', async () => {
    const up = await startUpstream(() => ({ body: dvaaCompletion('x') }));
    const cfg = makeConfig({ target: { port: up.port } });
    let { proxy, url } = await startProxy(cfg);
    try {
      await post(`${url}/v1/chat/completions`, {});
      await proxy.sink.flush();
      assert.equal(statSync(cfg.capture.path).mode & 0o777, 0o600);
    } finally { await proxy.close(); }
    const cfg2 = makeConfig({ target: { port: up.port } });
    writeFileSync(cfg2.capture.path, '');
    chmodSync(cfg2.capture.path, 0o644);
    ({ proxy, url } = await startProxy(cfg2));
    try {
      await post(`${url}/v1/chat/completions`, {});
      await proxy.sink.flush();
      assert.equal(statSync(cfg2.capture.path).mode & 0o777, 0o600);
    } finally { await proxy.close(); await up.close(); }
  });
});

describe('H5 loopback-only at the proxy API (defence in depth)', () => {
  test('listen() on a non-loopback host rejects with ConfigError; createProxy refuses a remote target', async () => {
    const cfg = makeConfig();
    const proxy = createProxy(cfg, { logAlert: () => {} });
    for (const host of ['0.0.0.0', '::', '192.168.1.5']) {
      await assert.rejects(proxy.listen(0, host), ConfigError, host);
    }
    assert.equal(proxy.server.listening, false);
    const remote = { ...cfg, target: { host: 'evil.example.com', port: 80 } };
    assert.throws(() => createProxy(remote), ConfigError);
    assert.ok(!existsSync(cfg.capture.path));
  });
});

describe('T2 <-> T4 cross-module: every T4 disposition through the real proxy', () => {
  // Uses T4's own sample verdict and T4's own buildAlert() as the oracle: whatever T4 accepts with a
  // Blocked disposition must be blocked; what T4 accepts as Allowed/ReportOnly must pass; what T4
  // rejects must fail closed (503 inspector_error), never be forwarded.
  const sample = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'alerts', 'examples', 'sample-verdict.json'), 'utf8'));
  const spellings = new Set(['hold', 'Hold', 'HOLD', ' Blocked ', 'block ', 'deny', '']);
  for (const [key, canonical] of Object.entries(DISPOSITIONS)) {
    for (const s of [key, key.toUpperCase(), canonical, canonical.toLowerCase(), canonical.toUpperCase(), key[0].toUpperCase() + key.slice(1)]) spellings.add(s);
  }

  test(`${spellings.size} disposition spellings agree with T4 buildAlert() (block mode)`, async () => {
    const up = await startUpstream(() => ({ body: dvaaCompletion('x') }));
    const outcomes = {};
    try {
      for (const disposition of spellings) {
        const verdict = { ...sample, disposition };
        let t4;
        try { t4 = buildAlert(verdict).PatternDispositionDescription; } catch { t4 = 'rejected'; }
        const expected = { Blocked: 403, Allowed: 200, ReportOnly: 200, rejected: 503 }[t4];
        const cfg = makeConfig({ target: { port: up.port }, mode: 'block' });
        const { proxy, url } = await startProxy(cfg, { inspectors: [async ({ phase }) => (phase === 'request' ? verdict : null)] });
        try {
          const before = up.received.length;
          const r = await post(`${url}/v1/chat/completions`, { messages: [] });
          outcomes[JSON.stringify(disposition)] = `${t4}->${r.status}`;
          assert.equal(r.status, expected, `disposition ${JSON.stringify(disposition)}: T4 says ${t4}, proxy gave ${r.status}`);
          assert.equal(up.received.length - before, expected === 200 ? 1 : 0, `forwarding for ${JSON.stringify(disposition)}`);
          assertNoSecret(r.body, sample.canary.value, disposition);
        } finally { await proxy.close(); }
      }
    } finally { await up.close(); }
    for (const k of ['"Blocked"', '"BLOCK"', '"blocked"', '"block"']) assert.equal(outcomes[k], 'Blocked->403', k);
    assert.equal(outcomes['"hold"'], 'rejected->503');
  });
});

// Flake-fix root cause (pipeline egress-seam 212 !== 211, proxy-seam rotation): the log scrubber redacted
// ~1 in 8,000 random request_ids (a Luhn-valid digit run across the UUID hyphens), so that alert record no
// longer joined its exchange record. These UUIDs are ones the scrubber's payment-card pattern rewrites.
test('alert records keep the exact request_id even when the UUID looks like a payment card to the scrubber', async () => {
  const MANGLED = ['41812006-4939-4383-b200-5e9cf9c4a341', '05a8cdf0-e9c1-4d5e-9649-560352079702', '23702694-7103-4115-9f49-4b0e9c45662a'];
  const up = await startUpstream(() => ({ body: leakReply() }));
  const cfg = makeConfig({ target: { port: up.port }, mode: 'observe', inspect: { flagSubstrings: [DVAA_TOKEN] } });
  const ids = [...MANGLED];
  const logged = [];
  const { proxy, url } = await startProxy(cfg, { logAlert: (a) => logged.push(a), newRequestId: () => ids.shift() });
  try {
    for (let i = 0; i < MANGLED.length; i++) assert.equal((await post(`${url}/v1/chat/completions`, {})).status, 200);
  } finally { await proxy.close(); await up.close(); }
  const recs = readCapture(cfg.capture.path);
  const exchanges = recs.filter((r) => r.type === 'exchange').map((r) => r.request_id);
  const alerts = recs.filter((r) => r.type === 'alert' && r.reason === 'flagged');
  assert.deepEqual(exchanges, MANGLED);
  assert.deepEqual(alerts.map((a) => a.request_id), MANGLED, 'every alert joins its exchange by the unredacted id');
  assert.deepEqual(logged.filter((a) => a.reason === 'flagged').map((a) => a.request_id), MANGLED);
  // The scrubber still runs on everything else in the alert record.
  assert.ok(!JSON.stringify(alerts).includes(DVAA_TOKEN), 'canary still redacted in alert records');
});
