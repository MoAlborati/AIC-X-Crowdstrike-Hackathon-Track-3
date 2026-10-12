// Bounds (fail-loud), JSONL reader, CLI convert/tail and determinism. Input is a JSONL written by the
// REAL T2 proxy with its stock JsonlCaptureSink during the test, not a hand-written record file.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { spawn, execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, appendFileSync, readdirSync, existsSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { createPipeline } from '../pipeline.mjs';
import { readJsonl, followJsonl } from '../jsonl.mjs';
import { PipelineBoundError, resolveCaps } from '../bounds.mjs';
import { standinInspectors, loadStandinConfig } from '../standin.mjs';
import {
  importProxy, startUpstream, proxyConfig, post, tmp, evasionRequest, benignRequest, exfilResponse, PIPELINE_DIR, silentLog, allAlerts, readCaptures,
} from './helpers.mjs';

const STANDIN = loadStandinConfig();
const CANARIES = STANDIN.honeytokens.map((h) => ({ ...h }));
const CLI = path.join(PIPELINE_DIR, 'cli.mjs');
let JSONL; // real proxy capture: 6 sessions, observe mode, both directions
let LINES;

before(async () => {
  const { createProxy } = await importProxy();
  const dir = await tmp();
  JSONL = path.join(dir, 'proxy.jsonl');
  const up = await startUpstream(() => ({ json: exfilResponse() }));
  try {
    const proxy = createProxy(proxyConfig({ upstreamPort: up.port, mode: 'observe', capturePath: JSONL }), { inspectors: standinInspectors(STANDIN), logAlert: () => {} });
    const { port } = await proxy.listen();
    try {
      for (let i = 0; i < 6; i++) await post(port, i % 2 ? benignRequest() : evasionRequest(), { 'x-sentinel-session': `s${i}` });
    } finally { await proxy.close(); }
  } finally { await up.close(); }
  LINES = readFileSync(JSONL, 'utf8').split('\n').filter(Boolean);
  const types = LINES.map((l) => JSON.parse(l).type);
  assert.ok(types.includes('exchange') && types.includes('alert') && types.includes('request'), `real proxy wrote ${[...new Set(types)]}`);
});

async function convert(caps, { jsonl = JSONL, log = silentLog() } = {}) {
  const outDir = path.join(await tmp(), 'out');
  const p = createPipeline({ outDir, caps, log, canaries: CANARIES });
  await p.init();
  await readJsonl(jsonl, (r, n) => p.ingest(r, n), { log });
  await p.finish();
  return { outDir, p, log };
}

test('baseline: 6 sessions, both directions, write-ahead records counted not converted', async () => {
  const { outDir, p } = await convert();
  const st = p.stats();
  assert.equal(st.captures, 6);
  assert.equal(st.exchanges, 6);
  assert.equal(st.writeAhead, 6);
  assert.equal(st.pending, 0);
  assert.ok(st.byDirection.request > 0 && st.byDirection.response > 0);
  assert.equal(allAlerts(outDir).length, st.alerts);
});

test('MAX_CAPTURES overflow -> PipelineBoundError (fail-loud), logged ALERT with size/cap', async () => {
  const log = silentLog();
  await assert.rejects(convert({ MAX_CAPTURES: 3 }, { log }), (err) => err instanceof PipelineBoundError && err.bound === 'MAX_CAPTURES' && err.size === 4 && err.cap === 3);
  assert.ok(log.entries.some((e) => e.level === 'ALERT' && e.bound === 'MAX_CAPTURES'));
});

test('MAX_EMBED_EXCHANGE_BYTES: oversize exchange -> explicit marker + ALERT + ops record, alerts still kept', async () => {
  const { outDir, log, p } = await convert({ MAX_EMBED_EXCHANGE_BYTES: 8 * 1024 });
  const omitted = log.entries.filter((e) => e.reason === 'embed_omitted');
  assert.equal(omitted.length, 3, 'the three 22 KB evasion exchanges');
  for (const e of omitted) assert.ok(e.size > e.cap);
  const ops = readFileSync(path.join(outDir, 'ops-alerts.jsonl'), 'utf8');
  assert.equal(ops.split('\n').filter((l) => l.includes('"embed_omitted"')).length, 3);
  const cap = readCaptures(outDir).find((c) => c.doc.pipeline.session === 's0');
  assert.match(cap.doc.exchanges[0].request.messages[0].content, /exceeds the display embed cap 8192 B.*request_id=/);
  assert.equal(allAlerts(outDir).length, p.stats().alerts, 'every alert written');
  assert.ok(allAlerts(outDir).some((a) => a.PipelineContext.Direction === 'request'));
});

test('MAX_EXCHANGES_PER_CAPTURE / MAX_ALERTS_PER_CAPTURE rotate (split, never drop)', async () => {
  // Re-key all 6 exchanges into one session, then cap parts at 2 exchanges.
  const dir = await tmp();
  const one = path.join(dir, 'one.jsonl');
  writeFileSync(one, LINES.map((l) => {
    const r = JSON.parse(l);
    if (r.request?.headers) r.request.headers['x-sentinel-session'] = 'one';
    return JSON.stringify(r);
  }).join('\n') + '\n');
  const { outDir, p } = await convert({ MAX_EXCHANGES_PER_CAPTURE: 2 }, { jsonl: one });
  assert.equal(readCaptures(outDir).length, 3);
  assert.equal(readCaptures(outDir).reduce((n, c) => n + c.doc.exchanges.length, 0), 6);
  assert.equal(allAlerts(outDir).length, p.stats().alerts);
  // One exchange's alerts must fit a part; a cap smaller than that is a hard error, not a split.
  await assert.rejects(convert({ MAX_ALERTS_PER_CAPTURE: 1 }, { jsonl: one }), (e) => e.bound === 'MAX_ALERTS_PER_CAPTURE');
});

test('MAX_VERDICTS_PER_EXCHANGE: stand-in inspector and pipeline both refuse past the cap', async () => {
  await assert.rejects(convert({ MAX_VERDICTS_PER_EXCHANGE: 1 }), (e) => e.bound === 'MAX_VERDICTS_PER_EXCHANGE');
  const [, resInspector] = standinInspectors(STANDIN, { caps: resolveCaps({ MAX_VERDICTS_PER_EXCHANGE: 1 }) });
  await assert.rejects(resInspector({ phase: 'response', body: Buffer.from(JSON.stringify(exfilResponse())), requestId: 'r' }), PipelineBoundError);
});

test('MAX_PENDING_ALERTS: alert records with no exchange overflow loudly', async () => {
  const p = createPipeline({ outDir: path.join(await tmp(), 'out'), caps: { MAX_PENDING_ALERTS: 2 }, log: () => {}, canaries: CANARIES });
  await p.init();
  const flagged = (id) => ({ type: 'alert', ts: '2026-10-12T00:00:00.000Z', request_id: id, mode: 'block', reason: 'flagged', phase: 'request', verdicts: [{ detector: 'x', flagged: true, reasons: [] }], action: 'blocked' });
  await p.ingest(flagged('a'));
  await p.ingest(flagged('b'));
  await assert.rejects(p.ingest(flagged('c')), (e) => e.bound === 'MAX_PENDING_ALERTS');
});

test('orphan: flagged alert whose exchange failed to capture is still converted (not lost)', async () => {
  const log = silentLog();
  const p = createPipeline({ outDir: path.join(await tmp(), 'out'), log, canaries: CANARIES });
  await p.init();
  await p.ingest({ type: 'alert', ts: '2026-10-12T00:00:00.000Z', request_id: 'r1', mode: 'block', reason: 'flagged', phase: 'request', verdicts: [{ detector: 'substring', flagged: true, reasons: ['matched configured substring at byte 9'] }], action: 'blocked' });
  await p.ingest({ type: 'alert', ts: '2026-10-12T00:00:00.001Z', request_id: 'r1', mode: 'block', reason: 'capture_write_failed', action: 'refused_exchange', error: 'capture sink full' });
  await p.finish();
  assert.equal(p.stats().alerts, 1);
  assert.equal(p.stats().opsAlerts, 1, 'the capture failure itself is an ops alert');
  assert.ok(log.entries.some((e) => e.reason === 'alerts_without_exchange'));
  const [a] = allAlerts(p.store.outDir);
  assert.equal(a.PatternDispositionDescription, 'Blocked');
  assert.equal(a.Entities.Session.Id, 'proxy-unattributed');
});

test('JSONL reader: MAX_LINE_BYTES overflow, malformed line, trailing partial line, unknown type', async () => {
  await assert.rejects(readJsonl(JSONL, () => {}, { maxLineBytes: 4096 }), (e) => e instanceof PipelineBoundError && e.bound === 'MAX_LINE_BYTES');
  const dir = await tmp();
  const bad = path.join(dir, 'bad.jsonl');
  writeFileSync(bad, `${LINES[0]}\n{not json\n`);
  await assert.rejects(readJsonl(bad, () => {}), /line 2: invalid JSON/);
  const partial = path.join(dir, 'partial.jsonl');
  writeFileSync(partial, `${LINES[0]}\n${LINES[1].slice(0, 50)}`);
  const log = silentLog();
  const seen = [];
  const r = await readJsonl(partial, (rec) => seen.push(rec), { log });
  assert.equal(seen.length, 1);
  assert.equal(r.trailingBytes, 50);
  assert.ok(log.entries.some((e) => e.reason === 'incomplete_trailing_line'));
  const p = createPipeline({ outDir: path.join(dir, 'out'), log: () => {} });
  await p.init();
  await assert.rejects(p.ingest({ type: 'mystery' }, 7), /line 7: unknown record type/);
});

test('followJsonl: picks up appended lines, refuses a file that shrinks', async () => {
  const dir = await tmp();
  const f = path.join(dir, 'grow.jsonl');
  writeFileSync(f, `${LINES[0]}\n`);
  const seen = [];
  const ac = new AbortController();
  const done = followJsonl(f, (r) => { seen.push(r); }, { pollMs: 20, signal: ac.signal });
  await waitFor(() => seen.length === 1);
  appendFileSync(f, `${LINES[1]}\n${LINES[2].slice(0, 30)}`);
  await waitFor(() => seen.length === 2);
  appendFileSync(f, `${LINES[2].slice(30)}\n`);
  await waitFor(() => seen.length === 3);
  assert.deepEqual(seen[2], JSON.parse(LINES[2]), 'line split across two appends parsed once, whole');
  ac.abort();
  await done;
  const g = path.join(dir, 'shrink.jsonl');
  writeFileSync(g, `${LINES[0]}\n${LINES[1]}\n`);
  const ac2 = new AbortController();
  const p2 = followJsonl(g, () => {}, { pollMs: 20, signal: ac2.signal });
  await new Promise((r) => setTimeout(r, 80));
  writeFileSync(g, `${LINES[0].slice(0, 10)}\n`);
  await assert.rejects(p2, /shrank/);
});

async function waitFor(pred, ms = 10000) {
  const t0 = Date.now();
  while (!pred()) {
    if (Date.now() - t0 > ms) throw new Error('waitFor timed out');
    await new Promise((r) => setTimeout(r, 20));
  }
}

test('CLI convert is deterministic: same JSONL -> byte-identical captures + sidecars', async () => {
  const a = path.join(await tmp(), 'a');
  const b = path.join(await tmp(), 'b');
  for (const out of [a, b]) execFileSync(process.execPath, [CLI, 'convert', JSONL, '--out', out], { stdio: ['ignore', 'pipe', 'pipe'] });
  const files = (d) => ['captures/live', 'alerts'].flatMap((s) => readdirSync(path.join(d, s)).map((f) => `${s}/${f}`)).sort();
  assert.deepEqual(files(a), files(b));
  assert.equal(files(a).length, 12);
  for (const f of files(a)) assert.equal(readFileSync(path.join(a, f), 'utf8'), readFileSync(path.join(b, f), 'utf8'), f);
});

test('CLI tail: live mode for the demo picks up records appended after start-up', async () => {
  const dir = await tmp();
  const f = path.join(dir, 'live.jsonl');
  const out = path.join(dir, 'out');
  const child = spawn(process.execPath, [CLI, 'tail', f, '--out', out, '--poll-ms', '30'], { stdio: ['ignore', 'pipe', 'pipe'] });
  const events = [];
  createInterface({ input: child.stdout }).on('line', (l) => events.push(JSON.parse(l)));
  try {
    await waitFor(() => events.some((e) => e.event === 'following'));
    const half = Math.ceil(LINES.length / 2);
    appendFileSync(f, LINES.slice(0, half).join('\n') + '\n');
    await waitFor(() => events.some((e) => e.event === 'flushed'));
    appendFileSync(f, LINES.slice(half).join('\n') + '\n');
    await waitFor(() => existsSync(path.join(out, 'alerts')) && readdirSync(path.join(out, 'alerts')).length === 6);
  } finally {
    const exit = new Promise((r) => child.once('exit', r));
    child.kill('SIGTERM');
    assert.equal(await exit, 0);
  }
  const summary = events.find((e) => e.event === 'summary');
  assert.equal(summary.exchanges, 6);
  assert.equal(summary.captures, 6);
});

test('CLI: usage error exits 2; live without the T2 proxy in-tree fails loudly with exit 2', async () => {
  const r = spawnSync([CLI, 'bogus']);
  assert.equal(r.status, 2);
  const live = spawnSync([CLI, 'live'], { SENTINEL_PROXY_ROOT: path.join(await tmp(), 'nowhere') });
  assert.equal(live.status, 2);
  assert.match(live.stderr, /needs the T2 proxy/);
});

function spawnSync(args, env = {}) {
  try {
    const stdout = execFileSync(process.execPath, args, { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, ...env } });
    return { status: 0, stdout: String(stdout), stderr: '' };
  } catch (e) {
    return { status: e.status, stdout: String(e.stdout), stderr: String(e.stderr) };
  }
}
