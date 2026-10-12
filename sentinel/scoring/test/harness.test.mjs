import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import path from 'node:path';
import { runScoring, runDetector } from '../src/harness.mjs';
import { noopDetector, t3Detector } from '../src/detectors.mjs';
import { loadCorpus, textUnits } from '../src/corpus.mjs';
import { REPO_ROOT, realDvaa, fnDetector } from './helpers.mjs';

const dvaa = await realDvaa();

test('real DVAA detectAttacks(): misses exactly the evadesBaseline=true middle cases, catches the start/end controls', { skip: !dvaa && 'no DVAA checkout' }, () => {
  const r = runScoring({ detectors: [noopDetector(), dvaa], iterations: 1 });
  const d = r.detectors['dvaa-baseline'];
  assert.equal(d.provenance.source, 'dvaa-real');
  assert.equal(d.provenance.dvaaCommit, '57918267d8d529ceec6d40fc9836ab09d128eee4');
  const flagged = new Set(d.perCase.filter((x) => x.flagged).map((x) => x.id));
  for (const id of ['EVA-POS-MIDDLE-001', 'EVA-BENCH-MIDDLE-001']) assert.equal(flagged.has(id), false, id);
  for (const id of ['EVA-POS-START-001', 'EVA-POS-END-001', 'EVA-BENCH-START-001', 'EVA-BENCH-END-001']) assert.equal(flagged.has(id), true, id);
  assert.deepEqual(r.beatsBaseline.baselineMismatch, []);
  assert.deepEqual(r.beatsBaseline.eligible.sort(), ['EVA-BENCH-MIDDLE-001', 'EVA-POS-MIDDLE-001']);
  // every FN / FP is itemized and the counts agree with the confusion matrix
  const m = d.modes.enforce.blocking;
  assert.equal(d.falseNegatives.length, m.fn);
  assert.equal(d.falsePositives.length, m.fp);
  assert.equal(m.tp + m.fn, r.corpus.positives);
  assert.equal(m.fp + m.tn, r.corpus.negatives);
});

test('deterministic: two runs give identical verdicts, itemization and digest (latency excluded)', { skip: !dvaa && 'no DVAA checkout' }, () => {
  const strip = (r) => {
    const o = structuredClone(r);
    delete o.generatedAt;
    for (const d of Object.values(o.detectors)) {
      delete d.latencyMs;
      for (const p of d.perCase ?? []) delete p.latencyMs;
    }
    delete o.latencyMs;
    return o;
  };
  const a = runScoring({ detectors: [noopDetector(), dvaa], iterations: 2 });
  const b = runScoring({ detectors: [noopDetector(), dvaa], iterations: 3 });
  delete a.iterations;
  delete b.iterations;
  assert.deepEqual(strip(a), strip(b));
});

test('no invented numbers: headline is null while the T3 detector is not present', async () => {
  const t3 = await t3Detector({ modulePath: path.join(REPO_ROOT, 'sentinel', 'detectors', '__absent__.js') });
  assert.equal(t3.available, false);
  const r = runScoring({ detectors: [noopDetector(), t3], iterations: 1 });
  assert.equal(r.headline.detector, null);
  assert.match(r.headline.status, /^awaiting t3/);
  for (const k of ['detectionRate', 'recall', 'precision', 'falsePositiveRate']) assert.equal(r[k], null, k);
  assert.equal(r.detectors.t3.available, false);
  const n = r.detectors.noop.modes.enforce.blocking;
  assert.equal(n.tp, 0);
  assert.equal(n.precision, null, 'precision with no predictions is n/a, not 0 or 1');
  assert.equal(n.recall, 0);
});

test('real T3 wiring: default adapter loads sentinel/detectors from the branch and scores the full corpus with zero errors', async () => {
  // Real seam: the merged T3 module at its default path, no stub. Asserts properties of the verdicts, not
  // exact rates, so corpus growth (T6b) does not make this brittle.
  const t3 = await t3Detector();
  assert.equal(t3.available, true, t3.unavailableReason);
  assert.equal(t3.provenance.module, path.join('sentinel', 'detectors', 'index.js'));
  const r = runScoring({ detectors: [noopDetector(), t3], iterations: 1 });
  const d = r.detectors.t3;
  assert.equal(r.errorCount, 0);
  assert.deepEqual(d.errors, []);
  assert.deepEqual(d.failClosed, [], 'no corpus case may trip a fail-closed path');
  assert.equal(r.headline.detector, 't3');
  assert.equal(r.headline.status, 'ok');
  assert.equal(d.perCase.length, r.corpus.total, 'every corpus case scored, none dropped');
  assert.deepEqual(d.falsePositives, [], 'no benign case blocked');
  assert.equal(d.recallByPositiveKind.exfil.fn, 0, 'every exfil-bearing attack blocked');
  if (dvaa) {
    const both = runScoring({ detectors: [dvaa, t3], iterations: 1 });
    const bt = both.beatsBaseline.byDetector.t3;
    assert.equal(bt.beaten, bt.eligible, `t3 must catch every evadesBaseline case: ${both.beatsBaseline.eligible.join(', ')}`);
  }
});

test('prevention lens: a post-execution-only finding counts toward detection but NOT prevention', async () => {
  // Synthetic seam: every positive gets ONLY a post-execution finding (would-block by policy, prevents:false).
  const post = fnDetector('post-only', (c) => ({
    fired: c.groundTruth === 'positive' ? [{ ruleId: 'test.post', wouldBlock: true, prevents: false, direction: 'response', postExecution: true }] : [],
  }));
  const r = runScoring({ detectors: [post], iterations: 1, headline: 'post-only' });
  const m = r.detectors['post-only'].modes.enforce;
  assert.equal(m.anyFinding.recall, 1, 'detected');
  assert.equal(m.prevention.recall, 0, 'post-execution must not count as prevention');
  assert.equal(m.prevention.tp, 0);
  assert.equal(r.detectionRecall, 1);
  assert.equal(r.preventionRecall, 0);
  assert.equal(r.recall, 1, 'legacy rule-intent field unchanged (dashboard-compatible)');
  assert.equal(r.detectors['post-only'].detectedNotPrevented.length, r.corpus.positives);

  // Real seam: the T1 aim-ab capture is caught by T3 only through response tool-call findings on an
  // in-process agent (post-execution): detected, not prevented.
  const t3 = await t3Detector();
  const rt = runScoring({ detectors: [t3], iterations: 1 });
  const row = rt.detectors.t3.perCase.find((x) => x.id === 'attack/aim-ab.demo.json#runA');
  assert.equal(row.detectedAny, true);
  assert.equal(row.preventedEnforce, false, 'post-execution T3 finding scored as a block');
  assert.ok(rt.preventionRecall <= rt.detectionRecall);
  assert.ok(rt.preventionRecall < rt.recall, 'prevention must be stricter than rule-intent block on this corpus');
});

test('headline comes from the named detector (enforce/blocking) with the fields T5 reads', () => {
  // Full-payload "oracle" built from the labels' own signal surface: flags any unit mentioning a URL/email
  // sink or an injection keyword. Test-only; proves wiring, not detection quality.
  const sink = /(https?:\/\/|@evil\.example|attacker\.example|ignore (all )?previous|send .* to)/i;
  const det = fnDetector('full-scan', (c) => ({
    fired: textUnits(c).some((u) => sink.test(u.text)) ? [{ ruleId: 'test.sink', wouldBlock: true }] : [],
  }));
  const r = runScoring({ detectors: [det], iterations: 1, headline: 'full-scan' });
  const m = r.detectors['full-scan'].modes.enforce.blocking;
  assert.equal(r.headline.status, 'ok');
  assert.equal(r.recall, m.recall);
  assert.equal(r.detectionRate, m.recall);
  assert.equal(r.falsePositiveRate, m.falsePositiveRate);
  assert.equal(r.precision, m.precision);
  assert.deepEqual(r.counts, { attack: m.positives, benign: m.negatives, fp: m.fp, fn: m.fn });
  assert.ok(Number.isFinite(r.latencyMs.median) && Number.isFinite(r.latencyMs.p95));
  // the full scan sees the middle-of-document signal, so it beats the baseline on those cases
  assert.equal(r.beatsBaseline.byDetector['full-scan'].beaten, 2);
});

test('modes: per-rule report-only does not block in enforce; fail-closed blocks even in report-only', () => {
  const det = fnDetector('modes', (c) => ({
    fired: c.groundTruth === 'positive'
      ? [{ ruleId: 'r.soft', wouldBlock: true }]
      : c.id === 'BEN-WIKI-001' ? [{ ruleId: 'failclosed.detector_error', wouldBlock: true, alwaysEnforce: true }] : [],
  }));
  const { cases } = loadCorpus(REPO_ROOT);
  const run = runDetector(det, cases, { iterations: 1, ruleModes: { 'r.soft': 'report-only' } });
  const pos = run.perCase.find((r) => r.groundTruth === 'positive');
  assert.equal(pos.flagged, true);
  assert.equal(pos.blocked.enforce, false, 'rule set report-only does not block in enforce');
  const fc = run.perCase.find((r) => r.id === 'BEN-WIKI-001');
  assert.equal(fc.blocked['report-only'], true, 'fail-closed is a dead-man switch');
  const r = runScoring({ detectors: [det], iterations: 1 });
  const d = r.detectors.modes;
  assert.equal(d.modes['report-only'].blocking.tp, 0);
  assert.equal(d.modes['report-only'].blocking.fp, 1);
  assert.deepEqual(d.falsePositives.map((f) => [f.id, f.rules[0].ruleId]), [['BEN-WIKI-001', 'failclosed.detector_error']]);
});

test('fail-loud: a throwing or non-deterministic detector is itemized and errorCount > 0', () => {
  let n = 0;
  const flaky = fnDetector('flaky', () => ({ fired: n++ % 2 ? [{ ruleId: 'x', wouldBlock: true }] : [] }));
  const boom = fnDetector('boom', (c) => {
    if (c.id === 'IA-DS-001') throw new Error('kaboom');
    return { fired: [] };
  });
  const r = runScoring({ detectors: [flaky, boom], iterations: 2 });
  assert.equal(r.detectors.boom.errors.length, 1);
  assert.match(r.detectors.boom.errors[0].error, /kaboom/);
  assert.ok(r.detectors.flaky.errors.every((e) => /non-deterministic/.test(e.error)));
  assert.equal(r.errorCount, r.detectors.flaky.errors.length + 1);
});

test('iterations are bounded (fail-loud)', () => {
  assert.throws(() => runScoring({ detectors: [noopDetector()], iterations: 101 }), /MAX_LATENCY_ITERATIONS/);
});

test('module detectors load through the documented default-export contract', async () => {
  const { moduleDetector } = await import('../src/detectors.mjs');
  const { writeFileSync, mkdtempSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const dir = mkdtempSync(path.join(tmpdir(), 't7-mod-'));
  const f = path.join(dir, 'det.mjs');
  writeFileSync(f, "export default async () => ({ name: 'ext', inspect: () => ({ fired: [] }) });\n");
  const d = await moduleDetector(f);
  assert.equal(d.name, 'ext');
  assert.equal(d.available, true);
  assert.ok(pathToFileURL(f).href);
});
