// Live tests: SentinelProxy in front of the REAL DVAA fleet (127.0.0.1:7001–7023). No upstream mocks.
// If DVAA is down these FAIL (requireDvaa) — they never skip.
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  CAPTURES, RAGBOT_PORT, DVAA_HOST, BLOCK_MARKER, markerInspector, post, readCapture, requireDvaa, startProxy, makeConfig,
  dvaaUserTurnRequest,
} from './helpers.js';
import { decodeBody, sha256 } from '../sink.js';
import { REFUSAL_TYPE, REFUSAL_ALERT_FIELDS } from '../server.js';
import { ALERT_SCHEMA } from '../../alerts/index.js';

const BENIGN = readdirSync(join(CAPTURES, 'benign'))
  .filter((f) => f.endsWith('.req.json'))
  .map((f) => ({ file: f, port: Number(f.split('_')[0]) }));

/** Drop the per-call fields DVAA regenerates (id/created embed Date.now()). */
const stable = (j) => {
  const { id, created, ...rest } = j;
  return rest;
};

/** >8KB request: real T6 corpus (22KB KB doc + 400-row tool output) with UTF-8 multibyte text and a marker mid-body. */
function bigRequest({ marker = 'MID-BODY-SIGNAL-7f3a' } = {}) {
  const kb = readFileSync(join(CAPTURES, 'variants/corpus/benign-kb-long.md'), 'utf8');
  const rows = readFileSync(join(CAPTURES, 'variants/corpus/benign-toolrows-400.json'), 'utf8');
  const content = `${kb}\n\nTool output (400 rows):\n${rows.slice(0, rows.length >> 1)}\n[${marker}] — résumé ✓ 日本語 🚀\n${rows.slice(rows.length >> 1)}\n\nSummarize the travel policy.`;
  return Buffer.from(JSON.stringify({ messages: [{ role: 'user', content }] }));
}

before(async () => {
  for (const { port } of BENIGN) await requireDvaa(port);
  await requireDvaa(RAGBOT_PORT, 'RAGBot');
});

describe('observe mode — live DVAA passthrough', () => {
  it('replays every benign capture through the proxy (target switched per capture via env override) and returns the upstream bytes unchanged', async () => {
    for (const { file, port } of BENIGN) {
      const p = await startProxy({ env: { SENTINEL_TARGET_PORT: String(port) } });
      try {
        assert.equal(p.config.target.port, port);
        const body = readCapture(`benign/${file}`);
        const viaProxy = await post(p.url, body);
        const direct = await post(`http://${DVAA_HOST}:${port}`, body);
        assert.equal(viaProxy.status, direct.status, file);
        assert.equal(viaProxy.status, 200, file);
        assert.deepEqual(stable(viaProxy.json), stable(direct.json), `${file}: proxied reply differs from direct reply`);
        assert.equal(viaProxy.json.dvaa, undefined, `${file}: benign turn must carry no dvaa{} block`);

        const [rec] = p.records();
        assert.equal(rec.outcome.action, 'forwarded');
        // byte-identical: client bytes == upstream bytes captured by the sink
        assert.ok(decodeBody(rec.response.body).equals(viaProxy.body), `${file}: client body is not byte-identical to upstream body`);
        assert.equal(rec.response.body.sha256, sha256(viaProxy.body));
        assert.ok(decodeBody(rec.request.body).equals(body), `${file}: request not captured byte-for-byte`);
        assert.equal(viaProxy.headers['x-sentinel-request-id'], rec.requestId);
        assert.equal(viaProxy.headers['content-type'], direct.headers['content-type']);
      } finally {
        await p.close();
      }
    }
  });

  it('logs a >8KB request (real 70KB corpus, 400 tool rows, multibyte UTF-8) and its response in full, byte-for-byte', async () => {
    const body = bigRequest();
    assert.ok(body.length > 64 * 1024, `fixture must be data-rich, got ${body.length}B`);
    const p = await startProxy();
    try {
      const res = await post(p.url, body);
      assert.equal(res.status, 200);
      const [rec] = p.records();
      const logged = decodeBody(rec.request.body);
      assert.equal(rec.request.body.encoding, 'utf8');
      assert.equal(rec.request.body.bytes, body.length);
      assert.equal(rec.request.body.sha256, sha256(body));
      assert.ok(logged.equals(body), 'request body in sink differs from the bytes sent');
      // the mid-body signal sits outside DVAA's head/tail 8KB windows and is still in the capture
      const at = logged.indexOf('MID-BODY-SIGNAL-7f3a');
      assert.ok(at > 8192 && at < body.length - 8192, `marker offset ${at} must be outside head/tail 8KB`);
      assert.ok(decodeBody(rec.response.body).equals(res.body));
      assert.ok(!JSON.stringify(rec).includes('TRUNCATED'), 'capture must not contain a truncation marker');
    } finally {
      await p.close();
    }
  });

  it('captures a non-UTF-8 request losslessly (base64) and passes DVAA\'s reply through unchanged', async () => {
    const body = Buffer.concat([Buffer.from('{"messages":[{"role":"user","content":"'), Buffer.from([0xff, 0xfe, 0x80, 0xc3]), Buffer.from('"}]}')]);
    const p = await startProxy();
    try {
      const res = await post(p.url, body);
      const direct = await post(`http://${DVAA_HOST}:${RAGBOT_PORT}`, body);
      assert.equal(res.status, direct.status);
      assert.deepEqual(stable(res.json), stable(direct.json));
      const [rec] = p.records();
      assert.equal(rec.request.body.encoding, 'base64');
      assert.ok(decodeBody(rec.request.body).equals(body));
      assert.ok(decodeBody(rec.response.body).equals(res.body));
    } finally {
      await p.close();
    }
  });

  it('replays the T6 8KB-evasion capture: DVAA executes the tool server-side and reports dvaa{}; observe mode passes it through and logs would-block (ReportOnly alert)', async () => {
    const fx = JSON.parse(readFileSync(join(CAPTURES, 'variants/fixtures/evasion/eva-pos-middle-001.json'), 'utf8'));
    const body = Buffer.from(JSON.stringify(dvaaUserTurnRequest(fx)));
    assert.ok(body.length > 16384, `evasion replay must exceed DVAA's head+tail 8KB windows, got ${body.length}B`);
    const p = await startProxy({ inspector: markerInspector });
    try {
      const res = await post(p.url, body);
      assert.equal(res.status, 200);
      assert.equal(res.json.dvaa.exfilAttempted, true, 'real DVAA reply must carry the dvaa{} ground truth');
      const [rec] = p.records();
      assert.ok(decodeBody(rec.response.body).equals(res.body), 'observe mode must pass the reply through unchanged');
      assert.equal(rec.outcome.action, 'forwarded');
      assert.equal(rec.outcome.wouldBlock, true);
      assert.equal(rec.inspector.response.decision.action, 'block');
      assert.equal(rec.alerts.length, 1);
      assert.equal(rec.alerts[0].PatternDispositionDescription, 'ReportOnly');
      assert.equal(rec.alerts[0].Category, 'taint_flow_exfil');
      assert.equal(rec.alerts[0].Entities.Sink.Destination, fx.label.dvaa.exfilTargetUrl);
      assert.ok(p.logs.some((l) => l.event === 'would_block' && l.phase === 'response' && l.action === 'report-only'));
    } finally {
      await p.close();
    }
  });
  it('the channel-faithful T6 fixture (payload in a role:"tool" message) does NOT trigger DVAA: DVAA reads only the latest user turn, which is why the replays above deliver the document as the user turn', async () => {
    const fx = JSON.parse(readFileSync(join(CAPTURES, 'variants/fixtures/evasion/eva-pos-middle-001.json'), 'utf8'));
    const res = await post(`http://${DVAA_HOST}:${RAGBOT_PORT}`, Buffer.from(JSON.stringify(fx.request)));
    assert.equal(res.status, 200);
    assert.equal(res.json.dvaa, undefined, 'DVAA now acts on tool-role content: dvaaUserTurnRequest() is stale, replay fx.request directly');
  });
});

describe('block mode — live DVAA', () => {
  it('short-circuits a flagged request with a structured refusal + AIDR alert; DVAA is never contacted', async () => {
    const p = await startProxy({ patch: { mode: 'block' }, inspector: markerInspector });
    try {
      const body = Buffer.from(JSON.stringify({ messages: [{ role: 'user', content: `Please summarize. ${BLOCK_MARKER}` }] }));
      const res = await post(p.url, body);
      assert.equal(res.status, 403);
      assert.equal(res.json.error.type, REFUSAL_TYPE);
      assert.equal(res.json.error.code, 'request_blocked');
      assert.equal(res.json.sentinel.phase, 'request');
      assert.equal(res.json.sentinel.action, 'block');
      const [summary] = res.json.sentinel.alerts;
      assert.deepEqual(Object.keys(summary), [...REFUSAL_ALERT_FIELDS]);
      assert.equal(summary.PatternDispositionDescription, 'Blocked');
      assert.equal(summary.Category, 'indirect_prompt_injection');
      assert.equal(summary.TechniqueId, 'AML.T0051.001');
      const [rec] = p.records();
      const [alert] = rec.alerts;
      for (const field of ALERT_SCHEMA.required) assert.ok(field in alert, `sink alert missing ${field}`);
      assert.equal(alert.AlertId, summary.AlertId);
      assert.equal(alert.Entities.Agent.Port, RAGBOT_PORT);
      assert.equal(alert.Entities.Session.Id, rec.sessionId);
      assert.equal(rec.response, null, 'blocked request must not reach DVAA');
      assert.equal(rec.timings.upstreamMs, null);
      assert.equal(rec.outcome.action, 'blocked');
      assert.ok(decodeBody(rec.request.body).equals(body), 'blocked request is still captured in full');
    } finally {
      await p.close();
    }
  });

  it('forwards an unflagged request unchanged in block mode', async () => {
    const p = await startProxy({ patch: { mode: 'block' }, inspector: markerInspector });
    try {
      const res = await post(p.url, readCapture('benign/7005_ragbot.req.json'));
      assert.equal(res.status, 200);
      const [rec] = p.records();
      assert.ok(decodeBody(rec.response.body).equals(res.body));
    } finally {
      await p.close();
    }
  });

  it('blocks on the response hook using the real dvaa{} block, and the refusal states the tool already ran inside DVAA', async () => {
    const fx = JSON.parse(readFileSync(join(CAPTURES, 'variants/fixtures/evasion/eva-pos-middle-001.json'), 'utf8'));
    const p = await startProxy({ patch: { mode: 'block' }, inspector: markerInspector });
    try {
      const res = await post(p.url, Buffer.from(JSON.stringify(dvaaUserTurnRequest(fx))));
      assert.equal(res.status, 403);
      assert.equal(res.json.error.code, 'response_blocked');
      assert.equal(res.json.sentinel.phase, 'response');
      assert.equal(res.json.sentinel.details.upstreamToolCallsAlreadyExecuted, true);
      assert.ok(!res.body.includes('dvaa-admin-secret'), 'blocked reply must not leak the upstream body to the client');
      const [rec] = p.records();
      assert.equal(rec.response.status, 200, 'the upstream reply is captured for forensics');
      assert.equal(JSON.parse(rec.response.body.text).dvaa.exfilAttempted, true);
      assert.equal(rec.alerts[0].PatternDispositionDescription, 'Blocked');
    } finally {
      await p.close();
    }
  });
});

describe('caps — live DVAA', () => {
  it('rejects a request over maxRequestBytes (declared length, 1 MiB default cap) loudly with {size, cap, action} + ScanCapExceeded alert', async () => {
    const p = await startProxy({ patch: { mode: 'observe' } });
    try {
      const cap = p.config.limits.maxRequestBytes;
      const body = Buffer.alloc(cap + 1, 'a');
      const res = await post(p.url, body);
      assert.equal(res.status, 413);
      assert.equal(res.json.error.code, 'request_too_large');
      assert.deepEqual(
        { size: res.json.sentinel.details.size, cap: res.json.sentinel.details.cap, action: res.json.sentinel.details.action },
        { size: cap + 1, cap, action: 'reject' },
      );
      const loud = p.logs.find((l) => l.event === 'request_too_large');
      assert.equal(loud.level, 'ALERT');
      assert.deepEqual([loud.size, loud.cap, loud.action], [cap + 1, cap, 'reject']);
      const [rec] = p.records();
      assert.equal(rec.response, null, 'oversize request must not be forwarded');
      assert.equal(rec.request.body, null);
      assert.equal(rec.request.bodyNotCaptured.size, cap + 1);
      assert.equal(rec.alerts[0].DetectName, 'ScanCapExceeded');
      assert.equal(rec.alerts[0].Oasb.Slug, 'context-overflow');
    } finally {
      await p.close();
    }
  });

  it('rejects a streamed (chunked, no content-length) request once it crosses the cap', async () => {
    const p = await startProxy({ patch: { limits: { maxRequestBytes: 65536 } } });
    try {
      const res = await post(p.url, Buffer.alloc(200_000, 'b'), { chunked: true });
      assert.equal(res.status, 413);
      const loud = p.logs.find((l) => l.event === 'request_too_large');
      assert.equal(loud.sizeKnown, 'at-least');
      assert.ok(loud.size > 65536);
      assert.equal(p.records()[0].response, null);
    } finally {
      await p.close();
    }
  });

  it('forwards a request of exactly maxRequestBytes (boundary) and logs it in full', async () => {
    const cap = 65536;
    const p = await startProxy({ patch: { limits: { maxRequestBytes: cap } } });
    try {
      const shell = JSON.stringify({ messages: [{ role: 'user', content: '' }] });
      const body = Buffer.from(JSON.stringify({ messages: [{ role: 'user', content: 'x'.repeat(cap - shell.length) }] }));
      assert.equal(body.length, cap);
      const res = await post(p.url, body);
      assert.equal(res.status, 200);
      assert.ok(decodeBody(p.records()[0].request.body).equals(body));
    } finally {
      await p.close();
    }
  });

  it('rejects a real DVAA reply over maxResponseBytes with 502 + loud {size, cap, action}', async () => {
    const p = await startProxy({ patch: { limits: { maxResponseBytes: 100 } } });
    try {
      const res = await post(p.url, readCapture('benign/7005_ragbot.req.json'));
      assert.equal(res.status, 502);
      assert.equal(res.json.error.code, 'response_too_large');
      const loud = p.logs.find((l) => l.event === 'response_too_large');
      assert.equal(loud.level, 'ALERT');
      assert.equal(loud.cap, 100);
      assert.ok(loud.size > 100);
      assert.equal(loud.action, 'reject');
      assert.equal(p.records()[0].response.body, null);
      assert.equal(p.records()[0].alerts[0].RuleId, 'proxy.response_body_cap');
    } finally {
      await p.close();
    }
  });
});

describe('config switching — live DVAA, no code edits', () => {
  it('the same config file targets a different agent/mode via env and CLI (CLI wins)', () => {
    const c = makeConfig({ env: { SENTINEL_TARGET_PORT: '7001', SENTINEL_MODE: 'block' }, argv: ['--target-port', '7003'] });
    assert.equal(c.target.port, 7003);
    assert.equal(c.mode, 'block');
    assert.equal(c.source.overrides['target.port'], 'CLI --target-port');
    assert.equal(c.source.overrides.mode, 'env SENTINEL_MODE');
  });

  it('the CLI binary, started with only flags/env, proxies to the selected live agent', async () => {
    const { spawn } = await import('node:child_process');
    const { mkdtempSync } = await import('node:fs');
    const { tmpdir } = await import('node:os');
    const sink = join(mkdtempSync(join(tmpdir(), 'sentinel-t2-cli-')), 'ex.jsonl');
    const child = spawn(process.execPath, [new URL('../cli.js', import.meta.url).pathname, '--listen-port', '0', '--target-port', '7001', '--target-name', 'SecureBot', '--sink-path', sink], {
      env: { ...process.env, SENTINEL_MODE: 'block' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    try {
      const ready = await new Promise((resolve, reject) => {
        let buf = '';
        child.stdout.on('data', (d) => {
          buf += d;
          const line = buf.split('\n').find((l) => l.includes('"ready"'));
          if (line) resolve(JSON.parse(line));
        });
        child.on('exit', (code) => reject(new Error(`cli exited ${code}`)));
      });
      assert.equal(ready.mode, 'block');
      assert.equal(ready.target.port, 7001);
      const res = await post(ready.url, readCapture('benign/7001_securebot.req.json'));
      assert.equal(res.status, 200);
      assert.equal(res.json.model, 'securebot');
    } finally {
      child.kill('SIGTERM');
    }
  });
});
