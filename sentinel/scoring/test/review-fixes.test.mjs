// Regression tests for the PR #13 review findings. All run against the real corpus (T1 captures + T6
// variants, incl. the >8KB middle-of-document cases and the 400-row tool output) through the real harness.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, appendFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { runScoring, runDetector, exitCode } from '../src/harness.mjs';
import { dvaaDrift, dvaaBaselineDetector, DVAA_PINNED_COMMIT } from '../src/detectors.mjs';
import { loadCorpus } from '../src/corpus.mjs';
import { REPO_ROOT, realDvaa, fnDetector } from './helpers.mjs';

const { cases } = loadCorpus(REPO_ROOT);
const attackIds = cases.filter((c) => c.groundTruth === 'positive').map((c) => c.id);
const benignIds = cases.filter((c) => c.groundTruth === 'negative').map((c) => c.id);

// The reviewer's probe: flags everything (a "perfect" recall detector) but crashes on all attack cases
// except the first two. Pre-fix this produced headline.status "ok", recall 1, counts.attack 2.
const CRASH_ON = new Set(attackIds.slice(2));
const crashProbe = () => fnDetector('probe', (c) => {
  if (CRASH_ON.has(c.id)) throw new Error(`probe crash on ${c.id}`);
  return { fired: [{ ruleId: 'probe.all', wouldBlock: true }] };
});

// --- Finding 1 (BLOCKING): errored cases never drop out -----------------------------------------------

test('finding 1: a crashing headline detector does not report ok; errored cases stay in the denominators', () => {
  assert.ok(CRASH_ON.size >= 10, 'data-rich: most attack cases crash');
  const r = runScoring({ detectors: [crashProbe()], iterations: 1, headline: 'probe' });
  // headline withheld, with an error status T5 can show
  assert.notEqual(r.headline.status, 'ok');
  assert.match(r.headline.status, new RegExp(`^error: ${CRASH_ON.size} of ${cases.length} cases errored in probe`));
  for (const k of ['detectionRate', 'recall', 'precision', 'falsePositiveRate']) assert.equal(r[k], null, k);
  assert.equal(r.counts, null);
  assert.equal(r.errorCount, CRASH_ON.size);
  assert.equal(exitCode(r), 1);
  // per-detector numbers: denominators are the full corpus, errored attacks are misses
  const d = r.detectors.probe;
  const m = d.modes.enforce.blocking;
  assert.equal(d.perCase.length, cases.length, 'no case dropped');
  assert.equal(m.positives, attackIds.length);
  assert.equal(m.negatives, benignIds.length);
  assert.equal(m.fn, CRASH_ON.size);
  assert.equal(m.tp, attackIds.length - CRASH_ON.size);
  assert.ok(m.recall < 0.2, `recall ${m.recall} must reflect the crashes, not 1.0`);
  assert.deepEqual(d.falseNegatives.filter((f) => f.errored).map((f) => f.id).sort(), [...CRASH_ON].sort());
  assert.ok(d.errors.every((e) => e.scoredAs === 'fn'));
});

test('finding 1: an errored benign case is scored as a fail-closed block (FP), never dropped', () => {
  const victim = benignIds[0];
  const det = fnDetector('benign-crash', (c) => {
    if (c.id === victim) throw new Error('boom');
    return { fired: [] };
  });
  const r = runScoring({ detectors: [det], iterations: 1, headline: 'benign-crash' });
  const m = r.detectors['benign-crash'].modes.enforce.blocking;
  assert.equal(m.negatives, benignIds.length);
  assert.equal(m.fp, 1);
  assert.deepEqual(r.detectors['benign-crash'].falsePositives.map((f) => [f.id, f.errored]), [[victim, true]]);
  assert.equal(r.detectors['benign-crash'].errors[0].scoredAs, 'fp');
  assert.match(r.headline.status, /^error: 1 of/);
  assert.equal(r.recall, null);
});

test('finding 1 (CLI, the seam T5 reads): written results.json carries the error status, not a perfect score', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 't7-probe-'));
  const mod = path.join(dir, 'probe.mjs');
  writeFileSync(mod, `const crash = new Set(${JSON.stringify([...CRASH_ON])});
export default { name: 'probe', inspect(c) {
  if (crash.has(c.id)) throw new Error('probe crash on ' + c.id);
  return { fired: [{ ruleId: 'probe.all', wouldBlock: true }] };
} };
`);
  const out = path.join(dir, 'results.json');
  const cli = path.join(REPO_ROOT, 'sentinel', 'scoring', 'cli.mjs');
  const res = spawnSync(process.execPath, [cli, '--iterations', '1', '--allow-replica', '--detector-module', mod, '--headline', 'probe',
    '--out', out, '--md', path.join(dir, 'RESULTS.md')], { encoding: 'utf8' });
  assert.equal(res.status, 1, res.stderr);
  const r = JSON.parse(readFileSync(out, 'utf8'));
  assert.match(r.headline.status, /^error: /);
  assert.equal(r.recall, null);
  assert.equal(r.detectionRate, null);
  assert.equal(r.counts, null);
  assert.equal(r.detectors.probe.modes.enforce.blocking.positives, attackIds.length);
});

// --- Finding 4: determinism key covers failClosed / alwaysEnforce ----------------------------------------

test('finding 4: a failClosed or alwaysEnforce flip between iterations is a non-determinism error', () => {
  const target = cases[0].id;
  let n = 0;
  const fcFlip = fnDetector('fc-flip', (c) => ({ fired: [], failClosed: c.id === target ? (n++ % 2 === 1) : false }));
  let m = 0;
  const aeFlip = fnDetector('ae-flip', (c) => ({
    fired: [{ ruleId: 'r', wouldBlock: true, alwaysEnforce: c.id === target ? (m++ % 2 === 1) : false }],
  }));
  for (const det of [fcFlip, aeFlip]) {
    const run = runDetector(det, cases, { iterations: 2 });
    assert.deepEqual(run.errors.map((e) => e.id), [target], det.name);
    assert.match(run.errors[0].error, /non-deterministic/);
    assert.equal(run.perCase.length, cases.length);
  }
});

// --- Finding 5: stand-in override stats honor --rule-mode --------------------------------------------

test('finding 5: a report-only rule gets fires but no holds/approvals/denials in stand-in stats', () => {
  const det = fnDetector('rm', () => ({ fired: [{ ruleId: 'r.soft', wouldBlock: true }, { ruleId: 'r.hard', wouldBlock: true }] }));
  const r = runScoring({ detectors: [det], iterations: 1, ruleModes: { 'r.soft': 'report-only' } });
  const s = Object.fromEntries(r.detectors.rm.overrides.standIn.map((x) => [x.ruleId, x]));
  assert.equal(s['r.soft'].fires, cases.length);
  assert.equal(s['r.soft'].holds, 0);
  assert.equal(s['r.soft'].approvals + s['r.soft'].denials, 0);
  assert.equal(s['r.soft'].overrideRate, null);
  assert.equal(s['r.hard'].holds, cases.length);
  assert.equal(s['r.hard'].approvals, benignIds.length);
});

// --- Finding 2: label rule matches the labels; injection-only positives are split out --------------------

test('finding 2: injection-only positives (DS-PI-001) are reported separately from exfil positives', async () => {
  const ds = cases.find((c) => c.id === 'DS-PI-001');
  assert.equal(ds.groundTruth, 'positive');
  assert.notEqual(ds.dvaa.exfilAttempted, true);
  const dvaa = await realDvaa();
  const det = dvaa ?? fnDetector('none', () => ({ fired: [] }));
  const r = runScoring({ detectors: [det], iterations: 1 });
  assert.ok(r.corpus.injectionOnlyPositives.includes('DS-PI-001'));
  assert.match(r.labelRule, /injection-only positives/);
  const k = r.detectors[det.name].recallByPositiveKind;
  assert.equal(k.exfil.positives + k.injectionOnly.positives, r.corpus.positives);
  assert.equal(k.injectionOnly.positives, r.corpus.injectionOnlyPositives.length);
  if (dvaa) assert.ok(k.injectionOnly.fn >= 1, 'DVAA misses DS-PI-001 (injection-only)');
});

// --- Finding 3: DVAA commit/cleanliness is asserted -----------------------------------------------------

test('finding 3: dvaaDrift flags a wrong commit, a dirty tree and unknown cleanliness', () => {
  const ok = { source: 'dvaa-real', dvaaCommit: DVAA_PINNED_COMMIT, dvaaDirty: false };
  assert.equal(dvaaDrift(ok), null);
  assert.match(dvaaDrift({ ...ok, dvaaCommit: 'deadbeef' }), /dvaa-baseline drift: commit deadbeef != pinned/);
  assert.match(dvaaDrift({ ...ok, dvaaDirty: true }), /uncommitted changes/);
  assert.match(dvaaDrift({ ...ok, dvaaDirty: null }), /cleanliness unknown/);
  assert.equal(dvaaDrift({ source: 'replica-subset' }), null);
});

test('finding 3 (real seam): a dirty DVAA checkout via $DVAA_SRC is refused before any DVAA code is imported', async (t) => {
  const pinned = await realDvaa();
  if (!pinned) return t.skip('no DVAA checkout');
  const clean = runScoring({ detectors: [pinned], iterations: 1 });
  assert.equal(clean.detectors['dvaa-baseline'].provenance.dvaaDirty, false);
  assert.ok(!clean.warnings.some((w) => w.startsWith('dvaa-baseline drift')), clean.warnings.join('; '));

  const src = execFileSync('node', ['-e', "import('" + path.join(REPO_ROOT, 'captures/variants/tools/baseline.mjs') + "').then(async m => process.stdout.write((await m.loadBaseline()).root))"], { encoding: 'utf8' });
  const dir = path.join(mkdtempSync(path.join(tmpdir(), 't7-dvaa-')), 'dvaa');
  execFileSync('git', ['clone', '-q', src, dir]);
  assert.ok(existsSync(path.join(dir, 'src/core/vulnerabilities.js')));
  appendFileSync(path.join(dir, 'README.md'), '\nlocal edit\n');
  const prev = process.env.DVAA_SRC;
  process.env.DVAA_SRC = dir;
  try {
    // Since PR #15 the T6 bridge (captures/variants/tools/baseline.mjs) verifies the checkout before
    // importing any DVAA code and refuses a dirty tree outright. That is stricter than the warn-and-exit-1
    // path this test was written for, so assert the refusal: a dirty DVAA is never scored.
    await assert.rejects(dvaaBaselineDetector(), /refusing to import DVAA code from \$DVAA_SRC=.*tree not clean/);
  } finally {
    if (prev === undefined) delete process.env.DVAA_SRC;
    else process.env.DVAA_SRC = prev;
  }
});
