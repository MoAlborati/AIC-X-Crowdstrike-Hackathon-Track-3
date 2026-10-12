// Live seam: `cli.mjs live` (REAL T2 proxy in-process + stand-in inspectors + pipeline sink) in front
// of the REAL DVAA RAGBot :7005 container. Skipped LOUDLY when DVAA is down. Set
// SENTINEL_REQUIRE_DVAA=1 to turn a missing DVAA into a failure (do this for the delivery gate).
//
// DVAA is the organizer-provided, intentionally vulnerable sandbox on localhost. The exfil target in
// the T6 fixture is DVAA's own 127.0.0.1:40447 canary path inside the container.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { writeFileSync, readFileSync, readdirSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { validateAlert } from '../../alerts/index.js';
import { proxyRoot, tmp, post, evasionRequest, liveExfilRequest, dvaaUp, PIPELINE_DIR, allAlerts, readCaptures, proxyConfig } from './helpers.mjs';

const PORT = Number(process.env.SENTINEL_LIVE_DVAA_PORT ?? 7005);
const CLI = path.join(PIPELINE_DIR, 'cli.mjs');

async function live({ standin }) {
  const dir = await tmp();
  const cfg = path.join(dir, 'proxy.json');
  const out = path.join(dir, 'out');
  writeFileSync(cfg, JSON.stringify(proxyConfig({ upstreamPort: PORT, mode: 'block', capturePath: path.join(dir, 'proxy.jsonl') })));
  const sc = path.join(dir, 'standin.json');
  if (standin) writeFileSync(sc, JSON.stringify(standin));
  const child = spawn(process.execPath, [CLI, 'live', '--config', cfg, '--out', out, ...(standin ? ['--standin', '--standin-config', sc] : [])], {
    stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, SENTINEL_PROXY_ROOT: proxyRoot() },
  });
  let stderr = '';
  child.stderr.on('data', (d) => { stderr += d; });
  const first = await new Promise((resolve, reject) => {
    createInterface({ input: child.stdout }).once('line', (l) => resolve(JSON.parse(l)));
    child.once('exit', (code) => reject(new Error(`cli live exited ${code}: ${stderr}`)));
  });
  return {
    port: first.port, out, first,
    stop: () => new Promise((r) => { child.once('exit', r); child.kill('SIGTERM'); }),
  };
}

const baseConfig = JSON.parse(readFileSync(path.join(PIPELINE_DIR, 'standin.config.json'), 'utf8'));

async function requireDvaa(t) {
  if (await dvaaUp(PORT)) return true;
  if (process.env.SENTINEL_REQUIRE_DVAA === '1') assert.fail(`DVAA not reachable on :${PORT}`);
  t.skip(`DVAA not reachable on :${PORT}. Start it (scripts/setup-dvaa.sh up) to run the live seam`);
  return false;
}

test(`live DVAA :${PORT}: request-side injection (>8KB, mid-body) blocked before RAGBot runs`, async (t) => {
  if (!(await requireDvaa(t))) return;
  const l = await live({ standin: baseConfig });
  try {
    assert.match(l.first.inspectors, /STAND-IN/);
    const r = await post(l.port, evasionRequest());
    assert.equal(r.status, 403);
  } finally { await l.stop(); }
  const alerts = allAlerts(l.out);
  assert.ok(alerts.length >= 1);
  for (const a of alerts) {
    assert.deepEqual(validateAlert(a), []);
    assert.equal(a.PipelineContext.Direction, 'request');
    assert.equal(a.PatternDispositionDescription, 'Blocked');
    assert.equal(a.PipelineContext.Outcome, 'blocked_before_agent');
    assert.equal(a.Entities.Agent.Port, PORT);
  }
});

test(`live DVAA :${PORT}: response-side exfil (tool already executed in-process) is alert-only`, async (t) => {
  if (!(await requireDvaa(t))) return;
  // Request-side rules off, so the request reaches RAGBot and it runs submit_to_index.
  const l = await live({ standin: { ...baseConfig, requestSide: false } });
  try {
    const r = await post(l.port, liveExfilRequest());
    assert.equal(r.status, 403, 'T2 withholds the flagged reply');
  } finally { await l.stop(); }
  const alerts = allAlerts(l.out);
  const cats = alerts.map((a) => a.Category);
  assert.ok(cats.includes('honeytoken_exfil') && cats.includes('egress_unallowlisted_domain'), cats.join(','));
  for (const a of alerts) {
    assert.deepEqual(validateAlert(a), []);
    assert.equal(a.PipelineContext.Direction, 'response');
    assert.equal(a.PipelineContext.Enforcement, 'alert_only');
    assert.equal(a.PatternDispositionDescription, 'ReportOnly');
    assert.equal(a.Entities.ToolCall.Name, 'submit_to_index');
    assert.equal(a.Entities.Agent.Name, `ragbot :${PORT}`);
  }
  // DVAA's own ground truth confirms the tool ran before the proxy saw the reply.
  const [cap] = readCaptures(l.out);
  assert.equal(cap.doc.exchanges[0].response.dvaa.exfilAttempted, true);
});

test(`live DVAA :${PORT}: DEFAULT source is real T3; RAGBot exfil reply -> alert-only T3 alerts, no stand-in`, async (t) => {
  if (!(await requireDvaa(t))) return;
  const l = await live({ standin: null });
  let r;
  try {
    assert.match(l.first.inspectors, /^T3 /);
    r = await post(l.port, liveExfilRequest());
  } finally { await l.stop(); }
  const alerts = allAlerts(l.out);
  assert.ok(alerts.length >= 1, `T3 alerted (status ${r.status})`);
  for (const a of alerts) {
    assert.deepEqual(validateAlert(a), []);
    assert.equal(a.PipelineContext.Detector, 'sentinel-t3');
    assert.equal(a.PipelineContext.StandIn, false);
    assert.equal(a.Entities.Agent.Port, PORT);
    if (a.PipelineContext.Direction === 'response') {
      assert.equal(a.PipelineContext.Enforcement, 'alert_only');
      assert.equal(a.PatternDispositionDescription, 'ReportOnly');
    }
  }
  if (r.status === 200) {
    // T3 let the request through: RAGBot ran its tool in-process; T3 reports it from the reply.
    assert.ok(alerts.some((a) => a.PipelineContext.Direction === 'response' && a.Category === 'honeytoken_exfil'), alerts.map((a) => a.Category).join(','));
    assert.equal(readCaptures(l.out)[0].doc.exchanges[0].response.dvaa.exfilAttempted, true);
  } else {
    // T3 refused the request before RAGBot ran.
    assert.equal(r.status, 403);
    assert.ok(alerts.every((a) => a.PipelineContext.Direction === 'request' && a.PatternDispositionDescription === 'Blocked'));
  }
  for (const s of readdirSync(path.join(l.out, 'alerts'))) {
    assert.equal(JSON.parse(readFileSync(path.join(l.out, 'alerts', s), 'utf8')).placeholder, false);
  }
});
