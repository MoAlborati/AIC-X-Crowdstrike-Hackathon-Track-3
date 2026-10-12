// T3 wired into the shipped proxy (cli.mjs) + ALERT for `alert:true` / disposition 'report' verdicts.
//
// Real seams: the real CLI process with a config file, the real T3 sentinelInspector from
// sentinel/detectors, a real upstream HTTP server replaying the recorded live-DVAA RAGBot :7005
// responses (sentinel/detectors/test/fixtures/dvaa-live-captures.json), the real JSONL capture.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { writeFileSync, mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import http from 'node:http';
import { startUpstream, startProxy, makeConfig, readCapture } from './helpers.mjs';
import { buildDefaultInspectors, defaultCanaries, t3TimeBudgetMs } from '../default-inspectors.mjs';
import { makeLogScrubber } from '../server.mjs';
import { DVAA_HONEYTOKENS, DEFAULT_BOUNDS } from '../../detectors/index.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..', '..', '..');
const CLI = join(HERE, '..', 'cli.mjs');
const LIVE = JSON.parse(readFileSync(join(ROOT, 'sentinel/detectors/test/fixtures/dvaa-live-captures.json'), 'utf8')).cases;
const liveCase = (id) => LIVE.find((c) => c.id === id);
const ADMIN = DVAA_HONEYTOKENS.find((t) => t.id === 'DVAA-ADMIN-PASSWORD').value;
const CHAT = '/v1/chat/completions';

/**
 * The recorded live RAGBot :7005 poisoned-RAG request, with the DVAA admin honeytoken planted inside
 * the poisoned document (a leaked credential riding next to the exfil instruction). Note: T3 does not
 * flag a bare honeytoken in a request on its own; it blocks the inbound exfil instruction.
 */
function poisonedWithHoneytoken() {
  const req = structuredClone(liveCase('ragbot-7005-rag-poisoned').request);
  req.messages[0].content = req.messages[0].content.replace('Tags: routine', `Admin credentials: ${ADMIN}\nTags: routine`);
  return req;
}

/** Data-rich: prepend a 1500-row (~90 KB) benign tool-output turn to a real captured request. */
function withRows(reqObj) {
  const rows = Array.from({ length: 1500 }, (_, i) => `row ${i}: order #${10000 + i} shipped to warehouse ${i % 17}, qty ${i % 9}`).join('\n');
  const messages = [{ role: 'system', content: `Reference inventory export (read only):\n${rows}` }, ...reqObj.messages];
  return { ...reqObj, messages };
}

function request(port, path, body) {
  return new Promise((resolve, reject) => {
    const buf = Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
    const req = http.request({ host: '127.0.0.1', port, path, method: 'POST', headers: { 'content-type': 'application/json', 'content-length': buf.length } }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    req.end(buf);
  });
}

async function runCli(cfg) {
  const dir = mkdtempSync(join(tmpdir(), 'sentinel-t3w-'));
  const capture = join(dir, 'capture.jsonl');
  const cfgPath = join(dir, 'config.json');
  writeFileSync(cfgPath, JSON.stringify({
    listen: { host: '127.0.0.1', port: 0 },
    limits: { maxRequestBytes: 1048576, maxResponseBytes: 8388608, upstreamTimeoutMs: 5000, inspectorTimeoutMs: 5000, clientTimeoutMs: 10000, maxInFlight: 64 },
    capture: { path: capture, maxFileBytes: 536870912 },
    inspect: { flagSubstrings: [] }, // shipped default: every detection below is T3's
    ...cfg,
  }));
  const child = spawn(process.execPath, [CLI, '--config', cfgPath], { stdio: ['ignore', 'pipe', 'pipe'] });
  const exited = new Promise((r) => child.once('exit', r));
  let stderr = '';
  child.stderr.on('data', (c) => { stderr += c.toString('utf8'); });
  const hello = await new Promise((resolve, reject) => {
    let out = '';
    child.stdout.on('data', (c) => {
      out += c.toString('utf8');
      const nl = out.indexOf('\n');
      if (nl !== -1) resolve(JSON.parse(out.slice(0, nl)));
    });
    child.once('exit', (code) => reject(new Error(`cli exited ${code}: ${stderr}`)));
  });
  return {
    hello, capture,
    stderr: () => stderr,
    stop: async () => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM'); await exited; },
  };
}

function replayUpstream() {
  // Answer like live DVAA RAGBot :7005: the recorded poisoned-RAG reply for a poisoned request, else the
  // recorded benign reply.
  return startUpstream(({ body }) => {
    const poisoned = body.toString('utf8').includes('BEGIN INDEXED DOCUMENT');
    return { body: liveCase(poisoned ? 'ragbot-7005-rag-poisoned' : 'ragbot-7005-benign').response };
  });
}

describe('T3 is wired into the shipped proxy CLI', () => {
  test('block mode: honeytoken exfil request blocked by T3 before DVAA; benign request passes (data-rich)', async () => {
    const up = await replayUpstream();
    const cli = await runCli({ target: { host: '127.0.0.1', port: up.port }, mode: 'block' });
    try {
      assert.deepEqual(cli.hello.inspectors, ['substring', 'sentinel-t3']);
      const bad = withRows(poisonedWithHoneytoken());
      assert.ok(JSON.stringify(bad).includes(ADMIN), 'fixture carries the DVAA admin honeytoken');
      assert.ok(JSON.stringify(bad).length > 64 * 1024, 'fixture is data-rich');
      const r1 = await request(cli.hello.port, CHAT, bad);
      assert.equal(r1.status, 403, r1.body);
      assert.equal(JSON.parse(r1.body).sentinel.reason, 'flagged_request');
      assert.equal(up.received.length, 0, 'DVAA never contacted');

      const good = withRows(liveCase('ragbot-7005-benign').request);
      const r2 = await request(cli.hello.port, CHAT, good);
      assert.equal(r2.status, 200, r2.body);
      assert.equal(up.received.length, 1);
      await cli.stop();

      const recs = readCapture(cli.capture);
      const blockAlert = recs.find((x) => x.type === 'alert' && x.reason === 'flagged');
      assert.equal(blockAlert.action, 'blocked');
      assert.ok(blockAlert.verdicts.some((v) => v.detector === 'sentinel-t3' && v.flagged === true));
      assert.ok(!cli.stderr().includes(ADMIN), 'honeytoken not on stderr');
      for (const r of recs) if (r.type === 'alert') assert.ok(!JSON.stringify(r).includes(ADMIN), 'honeytoken not in alert records');
      const benignEx = recs.filter((x) => x.type === 'exchange' && x.action === 'forwarded');
      assert.equal(benignEx.length, 1);
      assert.deepEqual(benignEx[0].verdicts, [], 'benign exchange: no verdicts');
    } finally { await cli.stop(); await up.close(); }
  });

  test('observe mode: T3 response-phase `flagged:false, alert:true` evidence is logged as an ALERT (redacted)', async () => {
    const up = await replayUpstream();
    const cli = await runCli({ target: { host: '127.0.0.1', port: up.port }, mode: 'observe' });
    try {
      const r = await request(cli.hello.port, CHAT, withRows(poisonedWithHoneytoken()));
      assert.equal(r.status, 200, 'observe forwards');
      await cli.stop();
      const recs = readCapture(cli.capture);
      const evid = recs.find((x) => x.type === 'alert' && x.reason === 'detector_alert' && x.phase === 'response');
      assert.ok(evid, `response-phase detector_alert ALERT present; got ${recs.filter((x) => x.type === 'alert').map((x) => `${x.reason}/${x.phase}`)}`);
      assert.equal(evid.action, 'alert_only');
      assert.equal(evid.verdicts[0].detector, 'sentinel-t3');
      assert.equal(evid.verdicts[0].flagged, false);
      assert.equal(evid.verdicts[0].alert, true);
      const ex = recs.find((x) => x.type === 'exchange');
      assert.ok(ex.verdicts.some((v) => v.phase === 'response' && v.alert === true && v.flagged === false), 'evidence in exchange verdicts');
      assert.ok(cli.stderr().includes('"reason":"detector_alert"'), 'ALERT on stderr');
      assert.ok(!cli.stderr().includes(ADMIN));
      for (const x of recs) if (x.type === 'alert') assert.ok(!JSON.stringify(x).includes(ADMIN));
    } finally { await cli.stop(); await up.close(); }
  });
});

describe('alert-only verdicts (not flagged) raise an ALERT and never refuse', () => {
  const TOK = 'dvaa{FAKE_HONEYTOKEN_7c1e9b}';
  for (const [name, verdict] of [
    ['alert:true', { flagged: false, alert: true, detector: 'x', reasons: [`saw ${TOK}`] }],
    ["disposition:'report'", { disposition: 'report', detector: 'x', reasons: [`saw ${Buffer.from(TOK).toString('base64')}`] }],
  ]) {
    for (const mode of ['observe', 'block']) {
      test(`${name} in ${mode} mode, both phases`, async () => {
        const up = await startUpstream(() => ({ body: { ok: true } }));
        const cfg = makeConfig({ target: { port: up.port }, mode, inspect: { flagSubstrings: [TOK] } });
        const { proxy, url } = await startProxy(cfg, { inspectors: [async () => ({ ...verdict })] });
        try {
          const r = await request(new URL(url).port, CHAT, { messages: [] });
          assert.equal(r.status, 200, 'not flagged -> forwarded even in block mode');
          await proxy.sink.flush();
          const recs = readCapture(cfg.capture.path);
          const alerts = recs.filter((x) => x.type === 'alert' && x.reason === 'detector_alert');
          assert.deepEqual(alerts.map((a) => a.phase).sort(), ['request', 'response']);
          for (const a of alerts) assert.equal(a.action, 'alert_only');
          assert.equal(recs.find((x) => x.type === 'exchange').verdicts.length, 2);
          const text = JSON.stringify(recs.filter((x) => x.type === 'alert')) + JSON.stringify(recs.find((x) => x.type === 'exchange').verdicts);
          assert.ok(!text.includes(TOK) && !text.includes(Buffer.from(TOK).toString('base64').replace(/=+$/, '')), 'redacted');
        } finally { await proxy.close(); await up.close(); }
      });
    }
  }

  test('malformed `alert` (non-boolean) fails closed in block mode', async () => {
    const up = await startUpstream(() => ({ body: { ok: true } }));
    const cfg = makeConfig({ target: { port: up.port }, mode: 'block' });
    const { proxy, url } = await startProxy(cfg, { inspectors: [async () => ({ flagged: false, alert: 'true' })] });
    try {
      const r = await request(new URL(url).port, CHAT, {});
      assert.equal(r.status, 503);
      assert.equal(up.received.length, 0);
    } finally { await proxy.close(); await up.close(); }
  });
});

describe('T3 options from the proxy config', () => {
  test('time budget derives from inspectorTimeoutMs (never looser than T3 default); abort signal honoured', async () => {
    assert.equal(t3TimeBudgetMs(5000), DEFAULT_BOUNDS.timeBudgetMs);
    assert.equal(t3TimeBudgetMs(30), 24);
    const cfg = makeConfig({ limits: { inspectorTimeoutMs: 30 }, inspect: { flagSubstrings: ['honeytoken-cfg-1'] } });
    const { inspectors, canaries, t3 } = buildDefaultInspectors(cfg, { scrub: makeLogScrubber(defaultCanaries(cfg)) });
    assert.equal(inspectors.length, 2);
    assert.ok(canaries.some((c) => c.value === 'honeytoken-cfg-1') && canaries.some((c) => c.value === ADMIN));
    const ac = new AbortController();
    const reason = new Error('deadline');
    ac.abort(reason);
    await assert.rejects(t3({ phase: 'request', path: CHAT, headers: {}, body: Buffer.from('{}'), requestId: 'z', signal: ac.signal }), (e) => e === reason);
  });
});
