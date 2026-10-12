// T10 egress adapter: T12 egress inspector JSONL -> T4 alerts (Direction "egress") -> T5 dashboard.
//
// Real seams, no mock of the feature:
//   - fixtures/egress-block-demo.jsonl is the UNEDITED log written by the REAL T12 inspector during
//     `scripts/egress-demo.sh block` (RAGBot 7005 + RepoBot 7022 against the real DVAA image, attacker
//     server received nothing). Re-timed copies of those same records are used for correlation tests.
//   - chat-proxy records come from the REAL T2 proxy (stock JsonlCaptureSink) in front of a real HTTP upstream
//   - output is loaded by the REAL T5 dashboard (loader, alert-store, adapter w/ T4 validateAlert, HTTP server)
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { createPipeline } from '../pipeline.mjs';
import { readJsonl } from '../jsonl.mjs';
import { correlate, loadEgressHoneytokens, EGRESS_SESSION } from '../egress.mjs';
import { T3_CANARIES } from '../t3.mjs';
import { standinInspectors, loadStandinConfig } from '../standin.mjs';
import {
  importProxy, importDashboard, startUpstream, proxyConfig, post, tmp, benignRequest, exfilResponse, PIPELINE_DIR, silentLog, allAlerts, readCaptures, readSidecars,
} from './helpers.mjs';

const FIXTURE = path.join(PIPELINE_DIR, 'test', 'fixtures', 'egress-block-demo.jsonl');
const REAL = readFileSync(FIXTURE, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
const CLI = path.join(PIPELINE_DIR, 'cli.mjs');
const STANDIN = loadStandinConfig();
const CANARIES = [...T3_CANARIES.map((c) => ({ ...c })), ...loadEgressHoneytokens(), ...STANDIN.honeytokens.filter((h) => !T3_CANARIES.some((c) => c.id === h.id)).map((h) => ({ ...h }))];
const SESSIONS = 210; // data-rich: correlation must hold past position 200
let PROXY_JSONL;
let PROXY_RECS;

const writeJsonl = (file, recs) => writeFileSync(file, recs.map((r) => JSON.stringify(r)).join('\n') + '\n');
const exchanges = () => PROXY_RECS.filter((r) => r.type === 'exchange');
/** A real egress record re-timed to `atMs` with a fresh request_id. */
const retime = (src, atMs, i) => ({ ...src, at: new Date(atMs).toISOString(), request_id: `retimed-${i}-${src.request_id}` });
const mid = (ex) => Date.parse(ex.ts) + Math.max(1, ex.latency_ms) / 2;

async function convert({ proxy = PROXY_JSONL, egress, caps, log = silentLog() } = {}) {
  const outDir = path.join(await tmp(), 'out');
  const p = createPipeline({ outDir, caps, log, canaries: CANARIES, t3: null, egressCapturePath: egress ?? null });
  await p.init();
  if (proxy) await readJsonl(proxy, (r, n) => p.ingest(r, n), { log });
  if (egress) await readJsonl(egress, (r, n) => p.ingest(r, n), { log });
  await p.finish();
  return { outDir, p, log };
}

before(async () => {
  assert.equal(REAL.length, 4, 'real block-mode egress log: RAGBot CONNECT + exfil GET, RepoBot bootstrap + credential GET');
  assert.ok(REAL.every((r) => r.direction === 'egress' && r.mode === 'block' && r.action === 'deny'));
  const { createProxy } = await importProxy();
  PROXY_JSONL = path.join(await tmp(), 'proxy.jsonl');
  // 20 ms per turn: a realistic in-flight window. Turns are back to back, so a window boundary shares a
  // millisecond with the next turn's start; egress is placed mid-turn, as DVAA's in-process tool call is.
  const up = await startUpstream(() => ({ json: exfilResponse() }), { delayMs: 20 });
  try {
    const proxy = createProxy(proxyConfig({ upstreamPort: up.port, mode: 'observe', capturePath: PROXY_JSONL }), { inspectors: standinInspectors(STANDIN), logAlert: () => {} });
    const { port } = await proxy.listen();
    try {
      for (let i = 0; i < SESSIONS; i++) await post(port, benignRequest(), { 'x-sentinel-session': `s${String(i).padStart(3, '0')}` });
    } finally { await proxy.close(); }
  } finally { await up.close(); }
  PROXY_RECS = readFileSync(PROXY_JSONL, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
  assert.equal(exchanges().length, SESSIONS);
});

test('real block-mode egress log: 4 PREVENTIVE egress alerts in a standalone egress incident, valid T4', async () => {
  const { outDir, p } = await convert({ proxy: null, egress: FIXTURE });
  const s = p.stats();
  assert.equal(s.egress.alerts, 4);
  assert.equal(s.egress.standalone, 4);
  assert.deepEqual(s.byDirection, { request: 0, response: 0, egress: 4 });
  assert.equal(s.preventive, 4);
  const caps = readCaptures(outDir);
  assert.deepEqual(caps.map((c) => c.file), ['egress-boundary.json']);
  const doc = caps[0].doc;
  assert.equal(doc.scenario, 'egress-boundary');
  assert.match(doc.title, /^EGRESS incident · tool boundary · 4 prevented \/ 4 alerts/);
  const alerts = allAlerts(outDir);
  for (const a of alerts) {
    assert.equal(a.PipelineContext.Direction, 'egress');
    assert.equal(a.PipelineContext.Enforcement, 'preventive');
    assert.equal(a.PipelineContext.Preventive, true);
    assert.equal(a.PipelineContext.Outcome, 'denied_before_send_bytes_never_left');
    assert.equal(a.PipelineContext.StandIn, false);
    assert.equal(a.PatternDispositionDescription, 'Blocked');
    assert.match(a.CaseCard.Narrative, /^\[egress \(tool boundary\) · preventive\]/);
    assert.match(a.CaseCard.Narrative, /PREVENTED/);
  }
  const names = alerts.map((a) => a.DetectName).sort();
  assert.deepEqual(names, ['HoneytokenExfiltrationAttempt', 'HoneytokenExfiltrationAttempt', 'NonAllowlistedEgressDestination', 'NonAllowlistedEgressDestination']);
  assert.ok(alerts.some((a) => a.Canary?.Id === 'DVAA-AWS-KEY-ID'), 'RepoBot credential post names its canary');
  assert.ok(alerts.some((a) => a.Canary?.Id === 'DVAA-ADMIN-PASSWORD'), 'RAGBot exfil names its canary');
  // No canary value anywhere in what the dashboard reads.
  const out = JSON.stringify([caps, readSidecars(outDir)]);
  for (const c of CANARIES) assert.ok(!out.includes(c.value), `canary ${c.id} leaked into pipeline output`);
});

test('T5 dashboard (real server): egress incident replays, no PLACEHOLDER banner, preventive labeling visible', async () => {
  const dash = await importDashboard();
  const outDir = path.join(await tmp(), 'out');
  execFileSync(process.execPath, [CLI, 'convert', PROXY_JSONL, '--egress', FIXTURE, '--out', outDir, '--clean'], { stdio: ['ignore', 'pipe', 'pipe'] });
  const saved = { ...process.env };
  process.env.SENTINEL_CAPTURES_DIR = path.join(outDir, 'captures');
  process.env.SENTINEL_ALERTS_DIR = path.join(outDir, 'alerts');
  process.env.SENTINEL_HIDE_PLACEHOLDERS = '1';
  process.env.SENTINEL_HIDE_STAGE = '1'; // count only this pipeline output, not the dashboard's stage recordings
  const server = dash.server.createServer();
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    const base = `http://127.0.0.1:${server.address().port}`;
    const list = await (await fetch(`${base}/api/captures`)).json();
    const eg = list.captures.find((c) => c.id === `live/${EGRESS_SESSION}`);
    assert.ok(eg, 'egress incident listed next to the chat-proxy sessions');
    assert.ok(!eg.error && eg.placeholder === false, JSON.stringify(eg));
    assert.equal(list.captures.length, SESSIONS + 1);
    const r = await fetch(`${base}/api/replay?id=${encodeURIComponent(`live/${EGRESS_SESSION}`)}&run=run`);
    assert.equal(r.status, 200);
    const rp = await r.json();
    // app.js shows the PLACEHOLDER banner iff capture.placeholder || alertSource.placeholder.
    assert.equal(rp.capture.placeholder, false);
    assert.equal(rp.alertSource.placeholder, false);
    assert.doesNotMatch(String(rp.alertSource.note), /STAND-IN|PLACEHOLDER/);
    assert.equal(rp.alerts.length, 4);
    assert.equal(rp.metrics.invalidAlertCount, 0);
    assert.equal(rp.metrics.blockedCount, 4, 'every egress deny shows as Blocked');
    for (const a of rp.alerts) assert.match(a.caseCard.narrative, /egress \(tool boundary\) · preventive/);
    assert.match(rp.run.exchanges[0].assistant.content ?? JSON.stringify(rp.run.exchanges[0]), /PREVENTED \(denied before send\)/);
    // Contrast in the same output: chat-proxy response-side alerts stay alert-only.
    const chat = await (await fetch(`${base}/api/replay?id=live/s000&run=run`)).json();
    assert.ok(chat.alerts.length > 0);
    for (const a of chat.alerts) assert.match(a.caseCard.narrative, /response-side · alert_only/);
  } finally {
    await new Promise((r) => server.close(r));
    for (const k of ['SENTINEL_CAPTURES_DIR', 'SENTINEL_ALERTS_DIR', 'SENTINEL_HIDE_PLACEHOLDERS']) {
      if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k];
    }
  }
});

test(`data-rich: ${SESSIONS} sessions, egress inside each turn correlates to THAT agent session (positions 1, 100, 200, 201, 210)`, async () => {
  const dir = await tmp();
  const egress = path.join(dir, 'egress.jsonl');
  const recs = exchanges().map((ex, i) => retime(REAL[i % REAL.length], mid(ex), i));
  // One more, long after every turn: must stay standalone.
  const last = exchanges().at(-1);
  recs.push(retime(REAL[3], Date.parse(last.ts) + last.latency_ms + 60_000, 'late'));
  writeJsonl(egress, recs);
  const { outDir, p } = await convert({ egress });
  assert.equal(p.stats().egress.correlated, SESSIONS);
  assert.equal(p.stats().egress.standalone, 1);
  const bySession = new Map(readSidecars(outDir).map((s) => [s.doc.pipeline.session, s.doc]));
  for (const pos of [1, 100, 200, 201, SESSIONS]) {
    const session = `s${String(pos - 1).padStart(3, '0')}`;
    const doc = bySession.get(session);
    const eg = doc.runs.run.filter((a) => a.PipelineContext.Direction === 'egress');
    assert.equal(eg.length, 1, `session ${session} (position ${pos}) has its egress alert`);
    assert.equal(eg[0].PipelineContext.Correlation.method, 'time_window');
    assert.equal(eg[0].Entities.Session.Id, session);
    assert.ok(eg[0].Entities.Agent.Port, 'egress alert names the agent port of the chat turn');
    assert.ok(doc.runs.run.some((a) => a.PipelineContext.Direction === 'response'), 'sits next to the chat-proxy alerts');
    assert.equal(doc.pipeline.byDirection.egress, 1);
  }
  assert.equal(bySession.get(EGRESS_SESSION).runs.run.length, 1);
});

test('correlation: port, ambiguity and evicted history never guess', () => {
  const agentA = { name: 'a', id: 'a', port: 7005 };
  const agentB = { name: 'b', id: 'b', port: 7022 };
  const windows = [
    { start: 1000, end: 5000, session: 'A', agent: agentA, requestId: 'ra' },
    { start: 2000, end: 6000, session: 'B', agent: agentB, requestId: 'rb' },
  ];
  const at = (ms, extra = {}) => ({ ...REAL[1], at: new Date(ms).toISOString(), ...extra });
  const amb = correlate(at(3000), { windows });
  assert.equal(amb.method, 'none');
  assert.match(amb.reason, /ambiguous/);
  assert.equal(amb.candidateCount, 2);
  assert.equal(correlate(at(3000, { agent_port: 7022 }), { windows }).session, 'B', 'explicit port disambiguates');
  const byPort = correlate(at(99_000, { agent_port: 7005 }), { windows, sessionByPort: new Map([[7005, { session: 'A', agent: agentA }]]) });
  assert.equal(byPort.method, 'port');
  assert.equal(correlate(at(1200), { windows }).session, 'A');
  assert.equal(correlate(at(5300), { windows }).session, 'B', 'strict containment wins over slack');
  assert.match(correlate(at(1200), { windows, horizon: 2000 }).reason, /correlation_history_evicted/);
});

test('MAX_CORRELATION_WINDOWS overflow: oldest evicted with ALERT, early egress shown standalone (not misattributed)', async () => {
  const dir = await tmp();
  const egress = path.join(dir, 'egress.jsonl');
  const ex = exchanges();
  writeJsonl(egress, [retime(REAL[1], mid(ex[0]), 0), retime(REAL[1], mid(ex[SESSIONS - 1]), 1)]);
  const { outDir, log } = await convert({ egress, caps: { MAX_CORRELATION_WINDOWS: 50 } });
  assert.ok(log.entries.some((e) => e.reason === 'correlation_window_evicted' && e.cap === 50));
  const alerts = allAlerts(outDir).filter((a) => a.PipelineContext.Direction === 'egress');
  const first = alerts.find((a) => a.PipelineContext.RequestId.startsWith('retimed-0-'));
  const lastA = alerts.find((a) => a.PipelineContext.RequestId.startsWith('retimed-1-'));
  assert.equal(first.Entities.Session.Id, EGRESS_SESSION);
  assert.match(first.PipelineContext.Correlation.reason, /correlation_history_evicted/);
  assert.equal(lastA.Entities.Session.Id, `s${String(SESSIONS - 1).padStart(3, '0')}`);
});

test('MAX_PENDING_EGRESS overflow fails loud', async () => {
  const dir = await tmp();
  const egress = path.join(dir, 'egress.jsonl');
  writeJsonl(egress, Array.from({ length: 6 }, (_, i) => retime(REAL[0], Date.parse(REAL[0].at) + i, i)));
  await assert.rejects(convert({ proxy: null, egress, caps: { MAX_PENDING_EGRESS: 5 } }), { name: 'PipelineBoundError', bound: 'MAX_PENDING_EGRESS' });
});

test('raw hosts / URLs in egress records are redacted (redactDeep before buildAlert); unknown canary id fails loud', async () => {
  const aws = T3_CANARIES.find((c) => c.id === 'DVAA-AWS-KEY-ID').value;
  const ssn = T3_CANARIES.find((c) => c.id === 'DVAA-SSN-JOHN').value;
  const leaky = structuredClone(REAL[3]);
  leaky.request_id = 'leaky-1';
  leaky.host = `${aws}.exfil.example`; // DNS-label exfil: the host IS the secret
  leaky.url = `http://${aws}.exfil.example/c?ssn=${ssn}`;
  leaky.alert.Entities.Sink.Destination = leaky.url;
  leaky.alert.Evidence = `egress GET ${leaky.url} raw`;
  const unknown = structuredClone(REAL[3]);
  unknown.request_id = 'unknown-canary';
  unknown.alert.Canary = { Id: 'NOT-A-KNOWN-CANARY', ValueSha256: '0' };
  const dir = await tmp();
  const egress = path.join(dir, 'egress.jsonl');
  writeJsonl(egress, [leaky]);
  const { outDir } = await convert({ proxy: null, egress });
  const [a] = allAlerts(outDir);
  assert.ok(a.PipelineContext.RawRecordRedactions >= 3, `raw record redactions: ${a.PipelineContext.RawRecordRedactions}`);
  const all = readdirSync(path.join(outDir, 'captures', 'live')).map((f) => readFileSync(path.join(outDir, 'captures', 'live', f), 'utf8')).join('')
    + readdirSync(path.join(outDir, 'alerts')).map((f) => readFileSync(path.join(outDir, 'alerts', f), 'utf8')).join('');
  assert.ok(!all.includes(aws) && !all.includes(ssn), 'raw secret from egress host/URL leaked into dashboard output');
  assert.match(a.Entities.Sink.Destination, /\[REDACTED(-INPUT)?:canary:DVAA-AWS-KEY-ID:/, 'redacted before buildAlert (T4 marks pre-redacted input as REDACTED-INPUT)');
  writeJsonl(egress, [unknown]);
  await assert.rejects(convert({ proxy: null, egress }), /NOT-A-KNOWN-CANARY/);
});

test('observe-mode egress (forward) is labeled alert_only, never preventive', async () => {
  const obs = REAL.map((r, i) => ({ ...structuredClone(r), mode: 'observe', action: 'forward', request_id: `obs-${i}` }));
  const dir = await tmp();
  const egress = path.join(dir, 'egress.jsonl');
  writeJsonl(egress, obs);
  const { outDir, p } = await convert({ proxy: null, egress });
  assert.equal(p.stats().preventive, 0);
  for (const a of allAlerts(outDir)) {
    assert.equal(a.PipelineContext.Enforcement, 'alert_only');
    assert.equal(a.PipelineContext.Outcome, 'forwarded_observe_only_would_block');
    assert.equal(a.PatternDispositionDescription, 'Allowed');
  }
});

test('tail: egress followed live lands in the alerts sink after the min hold', async () => {
  const { spawn } = await import('node:child_process');
  const dir = await tmp();
  const egress = path.join(dir, 'egress.jsonl');
  const outDir = path.join(dir, 'out');
  writeJsonl(egress, REAL);
  const child = spawn(process.execPath, [CLI, 'tail', '--egress', egress, '--out', outDir, '--poll-ms', '50'], { stdio: ['ignore', 'pipe', 'pipe'] });
  try {
    const deadline = Date.now() + 15_000;
    let found = [];
    while (Date.now() < deadline) {
      try { found = allAlerts(outDir); } catch { found = []; }
      if (found.length === 4) break;
      await new Promise((r) => setTimeout(r, 100));
    }
    assert.equal(found.length, 4);
    assert.ok(found.every((a) => a.PipelineContext.Enforcement === 'preventive'));
  } finally { child.kill('SIGTERM'); }
});
