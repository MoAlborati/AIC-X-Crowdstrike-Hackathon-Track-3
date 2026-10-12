// T13 layered lens: "T3 blocks, DVAA queues", derived per case from the committed results.json (353 real
// cases: T1 captures + T6 variants). Fixtures are the real file or targeted mutations of it, never dicts
// typed by hand, so the join runs against the real perCase rows the harness writes.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { computeLayered } from '../src/layered.mjs';
import { renderMarkdown } from '../src/report.mjs';
import { REPO_ROOT } from './helpers.mjs';

const DIR = path.join(REPO_ROOT, 'sentinel', 'scoring');
const load = () => JSON.parse(readFileSync(path.join(DIR, 'results.json'), 'utf8'));

test('real results.json is data-rich and has both perCase lists', () => {
  const r = load();
  assert.ok(r.corpus.total >= 200, `corpus ${r.corpus.total}`);
  assert.equal(r.detectors.t3.perCase.length, r.corpus.total);
  assert.equal(r.detectors['dvaa-baseline'].perCase.length, r.corpus.total);
});

test('layered numbers match an independent per-case recount of the real rows', () => {
  const r = load();
  const Y = computeLayered(r);
  assert.equal(Y.status, 'ok', Y.reason);
  const dv = new Map(r.detectors['dvaa-baseline'].perCase.map((x) => [x.id, x]));
  let tp = 0, ptp = 0, fp = 0, qb = 0, qa = 0;
  for (const a of r.detectors.t3.perCase) {
    const b = dv.get(a.id);
    const q = b.detectedAny && !a.blockedEnforce;
    if (a.groundTruth === 'positive') { tp += a.detectedAny || b.detectedAny; ptp += a.preventedEnforce; qa += q; }
    else { fp += a.blockedEnforce; qb += q; }
  }
  assert.equal(Y.detection.tp, tp);
  assert.equal(Y.prevention.tp, ptp);
  assert.equal(Y.benignAutoBlocked, fp);
  assert.equal(Y.benignQueuedForReview, qb);
  assert.equal(Y.attacksQueuedForReview, qa);
});

test('T3 headline numbers are untouched: layered prevention == T3 prevention, FP == T3 block FP', () => {
  const r = load();
  const Y = computeLayered(r);
  const t3 = r.detectors.t3.modes.enforce;
  assert.equal(Y.prevention.tp, t3.prevention.tp);
  assert.equal(Y.prevention.recall, r.preventionRecall);
  assert.equal(Y.benignAutoBlocked, t3.blocking.fp);
  assert.equal(Y.detection.fp, r.counts.fp);
  // the union can only add detections
  assert.ok(Y.detection.tp >= t3.anyFinding.tp);
  assert.ok(Y.detection.tp >= r.detectors['dvaa-baseline'].modes.enforce.anyFinding.tp);
});

test('DVAA benign hits are queued, not counted as FP; real fixture gives 21 queued, 0 auto-blocked', () => {
  const r = load();
  const Y = computeLayered(r);
  assert.equal(Y.benignAutoBlocked, 0);
  assert.equal(Y.benignQueuedForReview, r.detectors['dvaa-baseline'].falsePositivesAnyFinding.length);
  assert.equal(Y.benignQueuedForReview, 21);
  assert.deepEqual(new Set(Y.benignQueuedIds), new Set(r.detectors['dvaa-baseline'].falsePositivesAnyFinding.map((x) => x.id)));
});

test('a benign case T3 blocks counts as FP and is NOT also queued', () => {
  const r = load();
  const qid = r.detectors['dvaa-baseline'].falsePositivesAnyFinding[0].id;
  r.detectors.t3.perCase.find((x) => x.id === qid).blockedEnforce = true;
  const Y = computeLayered(r);
  assert.equal(Y.benignAutoBlocked, 1);
  assert.equal(Y.benignQueuedForReview, 20);
  assert.ok(!Y.benignQueuedIds.includes(qid));
});

test('join is by case id, not row position', () => {
  const r = load();
  const before = computeLayered(r);
  r.detectors['dvaa-baseline'].perCase.reverse();
  assert.deepEqual(computeLayered(r), before);
});

test('fail-loud: every malformed join withholds the lens with a reason (no silent partial union)', () => {
  const cases = {
    'dvaa unavailable': (r) => { r.detectors['dvaa-baseline'] = { available: false, unavailableReason: 'no checkout' }; },
    'headline withheld': (r) => { r.headline.status = 'withheld: detector errors'; },
    'detector errors': (r) => { r.detectors.t3.errors = [{ id: 'x', error: 'boom' }]; },
    'dropped row': (r) => { r.detectors['dvaa-baseline'].perCase.pop(); },
    'id mismatch': (r) => { r.detectors['dvaa-baseline'].perCase[300].id = 'not-a-case'; },
    'duplicate id': (r) => { const p = r.detectors.t3.perCase; p[1] = { ...p[0] }; },
    'groundTruth mismatch': (r) => { const x = r.detectors['dvaa-baseline'].perCase[250]; x.groundTruth = x.groundTruth === 'positive' ? 'negative' : 'positive'; },
    'errored row': (r) => { r.detectors.t3.perCase[260].errored = true; },
  };
  for (const [name, mutate] of Object.entries(cases)) {
    const r = load();
    mutate(r);
    const Y = computeLayered(r);
    assert.equal(Y.status, 'withheld', name);
    assert.ok(Y.reason, name);
    if (r.headline.status === 'ok') assert.match(renderMarkdown(r), /Layered lens \(T13\): WITHHELD/, name);
  }
});

test('committed RESULTS.md is exactly renderMarkdown(results.json): generated, never hand-typed', () => {
  const r = load();
  const md = readFileSync(path.join(DIR, 'RESULTS.md'), 'utf8');
  assert.equal(md, `${renderMarkdown(r)}\n`);
  const Y = computeLayered(r);
  assert.ok(md.includes(`| layered (t3 blocks, DVAA queues) | detection (T3 or DVAA finding) | ${(Y.detection.recall * 100).toFixed(1)}%`));
  assert.match(md, /benign queued for review 21\/164 \(12\.8%\)/);
});
