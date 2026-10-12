// Live replay: SentinelProxy (server.mjs, shipped T2 substring + T3 inspector set) in front of the REAL
// DVAA fleet (127.0.0.1:7001-7023). No upstream mocks. Ported from the retired PR #21 test/live.test.js
// (issue #37): every case that exercised a real DVAA behaviour is kept, re-pointed at the .mjs proxy.
// SENTINEL_REQUIRE_DVAA=1 (set by scripts/eval.sh when the fleet is up) turns a down agent into a FAIL.
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import {
  CAPTURES, DVAA_HOST, RAGBOT_PORT, requireDvaa, readCaptureFile, dvaaUserTurnRequest, loadLiveConfig,
  dvaaGroundTruthInspector, startProxy, post, readCapture,
} from './helpers.mjs';
import { decodeBody, sha256 } from '../server.mjs';
import { buildDefaultInspectors } from '../default-inspectors.mjs';

const CLI = join(dirname(fileURLToPath(import.meta.url)), '..', 'cli.mjs');
const BENIGN = readdirSync(join(CAPTURES, 'benign'))
  .filter((f) => f.endsWith('.req.json'))
  .sort()
  .map((f) => ({ file: f, port: Number(f.split('_')[0]) }));
const EVASION = JSON.parse(readFileSync(join(CAPTURES, 'variants/fixtures/evasion/eva-pos-middle-001.json'), 'utf8'));
const quiet = { write: () => {} };

/** DVAA stamps id/created with Date.now(); everything else must match exactly. */
const stable = (buf) => {
  const { id, created, ...rest } = JSON.parse(buf.toString('utf8'));
  return rest;
};

/** >8KB request: real T6 corpus (22KB KB doc + 400-row tool output), multibyte UTF-8, marker mid-body. */
function bigRequest(marker = 'MID-BODY-SIGNAL-7f3a') {
  const kb = readFileSync(join(CAPTURES, 'variants/corpus/benign-kb-long.md'), 'utf8');
  const rows = readFileSync(join(CAPTURES, 'variants/corpus/benign-toolrows-400.json'), 'utf8');
  const content = `${kb}\n\nTool output (400 rows):\n${rows.slice(0, rows.length >> 1)}\n[${marker}] — résumé ✓ 日本語 🚀\n${rows.slice(rows.length >> 1)}\n\nSummarize the travel policy.`;
  return Buffer.from(JSON.stringify({ messages: [{ role: 'user', content }] }));
}

/** Shipped proxy (T2 substring + real T3) on a config built by the real loader. */
async function shipped(opts = {}, extra = []) {
  const cfg = loadLiveConfig(opts);
  const { inspectors } = buildDefaultInspectors(cfg, quiet);
  const p = await startProxy(cfg, { inspectors: [...inspectors, ...extra] });
  return {
    ...p,
    cfg,
    chat: `${p.url}/v1/chat/completions`,
    records: async () => { await p.proxy.sink.flush(); return readCapture(cfg.capture.path); },
    close: () => p.proxy.close(),
  };
}
const exchangeOf = (recs) => recs.find((r) => r.type === 'exchange');
const direct = (port, body) => post(`http://${DVAA_HOST}:${port}/v1/chat/completions`, body);

describe('observe mode — live DVAA passthrough', () => {
  test('every benign capture, against its own agent (target picked by SENTINEL_TARGET_PORT): reply unchanged, captured byte-for-byte, no T3 false positive', async (t) => {
    for (const { port } of BENIGN) if (!(await requireDvaa(t, port))) return;
    assert.ok(BENIGN.length >= 6, `expected >=6 benign captures, got ${BENIGN.length}`);
    for (const { file, port } of BENIGN) {
      const p = await shipped({ env: { SENTINEL_TARGET_PORT: String(port) } });
      try {
        assert.equal(p.cfg.target.port, port);
        assert.equal(p.cfg.source.overrides['target.port'], 'env SENTINEL_TARGET_PORT');
        const body = readCaptureFile(`benign/${file}`);
        const via = await post(p.chat, body);
        const dir = await direct(port, body);
        assert.equal(via.status, 200, file);
        assert.equal(via.status, dir.status, file);
        assert.deepEqual(stable(via.body), stable(dir.body), `${file}: proxied reply differs from direct reply`);
        assert.equal(stable(via.body).dvaa, undefined, `${file}: benign turn must carry no dvaa{} block`);
        const recs = await p.records();
        assert.equal(recs.filter((r) => r.type === 'alert').length, 0, `${file}: benign capture raised an alert (false positive)`);
        const ex = exchangeOf(recs);
        assert.equal(ex.action, 'forwarded');
        assert.ok(decodeBody(ex.response.body).equals(via.body), `${file}: client body is not byte-identical to the captured upstream body`);
        assert.equal(ex.response.body.sha256, sha256(via.body));
        assert.ok(decodeBody(ex.request.body).equals(body), `${file}: request not captured byte-for-byte`);
        assert.equal(via.headers['x-sentinel-request-id'], ex.request_id);
        assert.equal(via.headers['content-type'], dir.headers['content-type']);
        assert.ok(ex.timings.upstream_ms > 0 && ex.timings.proxy_overhead_ms >= 0, JSON.stringify(ex.timings));
      } finally {
        await p.close();
      }
    }
  });

  test('a >8KB request (real 70KB corpus, 400 tool rows, multibyte UTF-8) and its reply are logged in full, byte-for-byte', async (t) => {
    if (!(await requireDvaa(t, RAGBOT_PORT, 'RAGBot'))) return;
    const body = bigRequest();
    assert.ok(body.length > 64 * 1024, `fixture must be data-rich, got ${body.length}B`);
    const p = await shipped();
    try {
      const res = await post(p.chat, body);
      assert.equal(res.status, 200);
      const ex = exchangeOf(await p.records());
      const logged = decodeBody(ex.request.body);
      assert.equal(ex.request.body.encoding, 'utf8');
      assert.equal(ex.request.body.bytes, body.length);
      assert.equal(ex.request.body.sha256, sha256(body));
      assert.ok(logged.equals(body), 'request body in the capture differs from the bytes sent');
      const at = logged.indexOf('MID-BODY-SIGNAL-7f3a');
      assert.ok(at > 8192 && at < body.length - 8192, `marker offset ${at} must be outside head/tail 8KB`);
      assert.ok(decodeBody(ex.response.body).equals(res.body));
      assert.ok(!JSON.stringify(ex).includes('TRUNCATED'), 'capture must not contain a truncation marker');
    } finally {
      await p.close();
    }
  });

  test("a non-UTF-8 request is captured losslessly (base64) and DVAA's reply passes through unchanged", async (t) => {
    if (!(await requireDvaa(t, RAGBOT_PORT, 'RAGBot'))) return;
    const body = Buffer.concat([Buffer.from('{"messages":[{"role":"user","content":"'), Buffer.from([0xff, 0xfe, 0x80, 0xc3]), Buffer.from('"}]}')]);
    const p = await shipped();
    try {
      const res = await post(p.chat, body);
      const dir = await direct(RAGBOT_PORT, body);
      assert.equal(res.status, dir.status);
      assert.deepEqual(stable(res.body), stable(dir.body));
      const ex = exchangeOf(await p.records());
      assert.equal(ex.request.body.encoding, 'base64');
      assert.ok(decodeBody(ex.request.body).equals(body));
      assert.ok(decodeBody(ex.response.body).equals(res.body));
    } finally {
      await p.close();
    }
  });

  test('T6 8KB-evasion replay (dvaaUserTurnRequest): real T3 flags the request (would-block), DVAA runs the tool server-side and reports dvaa{}, reply passes through unchanged', async (t) => {
    if (!(await requireDvaa(t, RAGBOT_PORT, 'RAGBot'))) return;
    const body = Buffer.from(JSON.stringify(dvaaUserTurnRequest(EVASION)));
    assert.ok(body.length > 16384, `evasion replay must exceed DVAA's head+tail 8KB windows, got ${body.length}B`);
    const p = await shipped();
    try {
      const res = await post(p.chat, body);
      assert.equal(res.status, 200);
      assert.equal(JSON.parse(res.body).dvaa.exfilAttempted, true, 'real DVAA reply must carry the dvaa{} ground truth');
      const recs = await p.records();
      const ex = exchangeOf(recs);
      assert.ok(decodeBody(ex.response.body).equals(res.body), 'observe mode must pass the reply through unchanged');
      assert.equal(ex.action, 'forwarded');
      const reqAlert = recs.find((r) => r.type === 'alert' && r.phase === 'request' && r.reason === 'flagged');
      assert.ok(reqAlert, 'T3 must flag the evasion request');
      assert.equal(reqAlert.action, 'would_block_observe_only');
      assert.ok(reqAlert.verdicts.some((v) => v.detector === 'sentinel-t3'));
    } finally {
      await p.close();
    }
  });

  test('channel-faithful T6 fixture (payload in a role:"tool" message) does NOT trigger DVAA, which is why the replays deliver the document as the user turn', async (t) => {
    if (!(await requireDvaa(t, RAGBOT_PORT, 'RAGBot'))) return;
    const res = await direct(RAGBOT_PORT, Buffer.from(JSON.stringify(EVASION.request)));
    assert.equal(res.status, 200);
    assert.equal(JSON.parse(res.body).dvaa, undefined, 'DVAA now acts on tool-role content: dvaaUserTurnRequest() is stale, replay fx.request directly');
  });

  test('an inspector that mutates ctx.body / ctx.headers cannot change what is forwarded, returned or captured', async (t) => {
    if (!(await requireDvaa(t, RAGBOT_PORT, 'RAGBot'))) return;
    async function vandal({ phase, body, rawBody, headers }) {
      body.fill(phase === 'request' ? 0x41 : 0x42);
      rawBody.fill(0x43);
      headers['content-type'] = 'text/plain';
      return null;
    }
    const p = await shipped({}, [vandal]);
    try {
      const body = readCaptureFile('benign/7005_ragbot.req.json');
      const res = await post(p.chat, body);
      assert.equal(res.status, 200);
      assert.equal(JSON.parse(res.body).model, 'ragbot');
      const ex = exchangeOf(await p.records());
      assert.ok(decodeBody(ex.request.body).equals(body));
      assert.ok(decodeBody(ex.response.body).equals(res.body));
      assert.equal(ex.request.headers['content-type'], 'application/json');
    } finally {
      await p.close();
    }
  });
});

describe('block mode — live DVAA', () => {
  test('T6 evasion replay: real T3 refuses the request pre-forward (prevention): DVAA is never contacted', async (t) => {
    if (!(await requireDvaa(t, RAGBOT_PORT, 'RAGBot'))) return;
    const body = Buffer.from(JSON.stringify(dvaaUserTurnRequest(EVASION)));
    const p = await shipped({ mode: 'block' });
    try {
      const res = await post(p.chat, body);
      assert.equal(res.status, 403);
      const j = JSON.parse(res.body);
      assert.equal(j.error.code, 'flagged_request');
      assert.equal(j.sentinel.phase, 'request');
      const recs = await p.records();
      assert.equal(recs.filter((r) => r.type === 'request').length, 0, 'no write-ahead record: the request was never forwarded');
      const ex = exchangeOf(recs);
      assert.equal(ex.action, 'blocked_request');
      assert.equal(ex.timings.upstream_ms, null, 'upstream must not be contacted');
      assert.ok(decodeBody(ex.request.body).equals(body), 'blocked request is still captured in full');
    } finally {
      await p.close();
    }
  });

  test('an unflagged request is forwarded unchanged in block mode', async (t) => {
    if (!(await requireDvaa(t, RAGBOT_PORT, 'RAGBot'))) return;
    const p = await shipped({ mode: 'block' });
    try {
      const res = await post(p.chat, readCaptureFile('benign/7005_ragbot.req.json'));
      assert.equal(res.status, 200);
      assert.ok(decodeBody(exchangeOf(await p.records()).response.body).equals(res.body));
    } finally {
      await p.close();
    }
  });

  test("response hook on the real dvaa{} block: reply withheld, refusal states the tool already ran inside DVAA", async (t) => {
    if (!(await requireDvaa(t, RAGBOT_PORT, 'RAGBot'))) return;
    // Request-phase T3 is left out here on purpose so the request reaches DVAA and the response hook fires.
    const cfg = loadLiveConfig({ mode: 'block' });
    const p = await startProxy(cfg, { inspectors: [dvaaGroundTruthInspector] });
    try {
      const res = await post(`${p.url}/v1/chat/completions`, Buffer.from(JSON.stringify(dvaaUserTurnRequest(EVASION))));
      assert.equal(res.status, 403);
      const j = JSON.parse(res.body);
      assert.equal(j.error.code, 'flagged_response');
      assert.equal(j.sentinel.phase, 'response');
      assert.equal(j.sentinel.detail.upstream_tool_calls_already_executed, true);
      assert.ok(!res.body.includes('dvaa-admin-secret'), 'blocked reply must not leak the upstream body to the client');
      assert.ok(!res.body.includes('canary'), 'blocked reply must not leak the exfil URL to the client');
      await p.proxy.sink.flush();
      const ex = exchangeOf(readCapture(cfg.capture.path));
      assert.equal(ex.upstream_response.status, 200, 'the upstream reply is captured for forensics');
      assert.equal(JSON.parse(decodeBody(ex.upstream_response.body)).dvaa.exfilAttempted, true);
    } finally {
      await p.proxy.close();
    }
  });
});

describe('caps — live DVAA', () => {
  test('a request of exactly maxRequestBytes (boundary, set by --max-request-bytes) is forwarded and logged in full', async (t) => {
    if (!(await requireDvaa(t, RAGBOT_PORT, 'RAGBot'))) return;
    const cap = 65536;
    const p = await shipped({ argv: ['--max-request-bytes', String(cap)] });
    try {
      assert.equal(p.cfg.limits.maxRequestBytes, cap);
      const shell = JSON.stringify({ messages: [{ role: 'user', content: '' }] });
      const body = Buffer.from(JSON.stringify({ messages: [{ role: 'user', content: 'x'.repeat(cap - shell.length) }] }));
      assert.equal(body.length, cap);
      const res = await post(p.chat, body);
      assert.equal(res.status, 200);
      assert.ok(decodeBody(exchangeOf(await p.records()).request.body).equals(body));
      const over = await post(p.chat, Buffer.concat([body, Buffer.from(' ')]));
      assert.equal(over.status, 413, 'one byte over the cap is refused');
    } finally {
      await p.close();
    }
  });

  test('a real DVAA reply over maxResponseBytes -> 502 response_too_large + loud {payload_size, cap, action}', async (t) => {
    if (!(await requireDvaa(t, RAGBOT_PORT, 'RAGBot'))) return;
    const p = await shipped({ limits: { maxResponseBytes: 100 } });
    try {
      const res = await post(p.chat, readCaptureFile('benign/7005_ragbot.req.json'));
      assert.equal(res.status, 502);
      assert.equal(JSON.parse(res.body).error.code, 'response_too_large');
      const recs = await p.records();
      const alert = recs.find((r) => r.type === 'alert' && r.reason === 'response_too_large');
      assert.equal(alert.cap, 100);
      assert.ok(alert.payload_size > 100);
      assert.equal(alert.action, 'rejected_not_returned');
      assert.ok(!res.body.includes('ragbot'), 'the over-cap reply is not returned');
    } finally {
      await p.close();
    }
  });
});

describe('config switching — live DVAA, no code edits', () => {
  test('the CLI, started with only flags + env (CLI wins over env), proxies to the selected live agent', async (t) => {
    if (!(await requireDvaa(t, 7001, 'SecureBot'))) return;
    const capture = join(mkdtempSync(join(tmpdir(), 'sentinel-cli-')), 'ex.jsonl');
    const child = spawn(process.execPath, [CLI, '--listen-port', '0', '--target-port', '7001', '--capture-path', capture], {
      env: { ...process.env, SENTINEL_MODE: 'block', SENTINEL_TARGET_PORT: '7003' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    try {
      const ready = await new Promise((resolve, reject) => {
        createInterface({ input: child.stdout }).once('line', (l) => resolve(JSON.parse(l)));
        child.once('exit', (code) => reject(new Error(`cli exited ${code}`)));
      });
      assert.equal(ready.mode, 'block');
      assert.equal(ready.target.port, 7001);
      assert.equal(ready.capture, capture);
      assert.deepEqual(ready.overrides, {
        mode: 'env SENTINEL_MODE', 'target.port': 'CLI --target-port', 'listen.port': 'CLI --listen-port', 'capture.path': 'CLI --capture-path',
      });
      const res = await post(`http://127.0.0.1:${ready.port}/v1/chat/completions`, readCaptureFile('benign/7001_securebot.req.json'));
      assert.equal(res.status, 200);
      assert.equal(JSON.parse(res.body).model, 'securebot');
    } finally {
      await new Promise((r) => { child.once('exit', r); child.kill('SIGTERM'); });
    }
  });
});
