// deck-data.test.mjs: the live deck's numbers equal the committed data files, every "ours" has a paired baseline,
// and a missing file or key renders a visible warning rather than a number.
//
// Run: node --test demo/slides/test/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as D from '../deck-data.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const read = (f) => fs.readFileSync(path.join(ROOT, f), 'utf8');

function loadRaw() {
  const raw = {};
  for (const [k, f] of Object.entries(D.FILES)) {
    const t = read(f);
    raw[k] = f.endsWith('.json') ? JSON.parse(t) : t;
  }
  return raw;
}

const raw = loadRaw();
const R = raw.scoring;
const model = D.deriveAll(raw);

test('every data file the deck fetches is committed at the path the page uses', () => {
  for (const f of Object.values(D.FILES)) assert.ok(fs.existsSync(path.join(ROOT, f)), `missing ${f}`);
  const html = read('demo/slides/deck.html');
  assert.match(html, /const DATA_ROOT = '\.\.\/\.\.\/'/, 'page resolves files relative to the repo root');
});

test('main-corpus numbers equal sentinel/scoring/results.json, read independently', () => {
  const s = model.scoring;
  const enf = (d, mode) => R.detectors[d].modes.enforce[mode];
  for (const [who, det] of [['t3', 't3'], ['dvaa', 'dvaa-baseline']]) {
    assert.equal(s.detection[who].recall.num, enf(det, 'anyFinding').tp);
    assert.equal(s.detection[who].recall.den, enf(det, 'anyFinding').positives);
    assert.equal(s.prevention[who].recall.num, enf(det, 'prevention').tp);
    assert.equal(s.prevention[who].recall.den, enf(det, 'prevention').positives);
    assert.equal(s.prevention[who].fp.num, enf(det, 'prevention').fp);
    assert.equal(s.prevention[who].fp.den, enf(det, 'prevention').negatives);
    assert.equal(s.exfil[who].num, R.detectors[det].recallByPositiveKindPrevention.exfil.tp);
    assert.equal(s.exfil[who].den, R.detectors[det].recallByPositiveKindPrevention.exfil.positives);
    assert.equal(s.latency[who].median.v, R.detectors[det].latencyMs.median);
    assert.equal(s.latency[who].p95.v, R.detectors[det].latencyMs.p95);
  }
  assert.equal(s.corpus.positives.v, R.corpus.positives);
  assert.equal(s.corpus.negatives.v, R.corpus.negatives);
  assert.equal(s.generatedAt.v, R.generatedAt);
  // The headline lenses the harness reports agree with the per-mode numbers the deck uses.
  assert.equal(s.detection.t3.recall.num, R.headlineLenses.detection.tp);
  assert.equal(s.prevention.t3.recall.num, R.headlineLenses.prevention.tp);
});

test('the slide-7 / venture pairs match the committed values (detection, prevention, benign FP, exfil subset)', () => {
  const s = model.scoring;
  // Pinned to the committed results.json; if it is regenerated these move together with the file.
  const pairs = [
    [s.detection.t3.recall, s.detection.dvaa.recall],
    [s.prevention.t3.recall, s.prevention.dvaa.recall],
    [s.prevention.t3.fp, s.prevention.dvaa.fp],
    [s.exfil.t3, s.exfil.dvaa],
  ];
  for (const [ours, theirs] of pairs) {
    assert.ok(ours.ok && theirs.ok, 'both halves of every pair are sourced');
    assert.equal(ours.den, theirs.den, 'pairs share a denominator');
  }
  assert.equal(D.fmt(s.prevention.t3.fp, 'frac'), `${R.detectors.t3.modes.enforce.prevention.fp}/${R.corpus.negatives}`);
  assert.equal(D.fmt(s.exfil.t3, 'frac'), `${R.detectors.t3.recallByPositiveKindPrevention.exfil.tp}/71`);
  assert.equal(D.fmt(s.exfil.dvaa, 'frac'), `${R.detectors['dvaa-baseline'].recallByPositiveKindPrevention.exfil.tp}/71`);
});

test('8KB evasion: T3 from beatsBaseline, DVAA from its own perCase verdicts on the same ids (n = 2)', () => {
  const e = model.scoring.evasion;
  assert.deepEqual(e.ids, R.beatsBaseline.eligible);
  assert.equal(e.t3.detected.num, R.beatsBaseline.byDetector.t3.beaten);
  assert.equal(e.t3.detected.den, R.beatsBaseline.byDetector.t3.eligible);
  assert.equal(e.t3.prevented.num, R.beatsBaseline.byDetector.t3.beatenPrevention);
  const dvaaHits = R.beatsBaseline.eligible.filter((id) => R.detectors['dvaa-baseline'].perCase.find((c) => c.id === id).detectedAny).length;
  assert.equal(e.dvaa.num, dvaaHits);
  assert.equal(e.dvaa.den, R.beatsBaseline.eligible.length);
});

test('held-out tables: parsed fractions match the RESULTS.md text, and each set is paired', () => {
  const h = model.holdouts;
  const expectFrac = (m, s) => { assert.ok(m.ok, `sourced: ${m.src}`); assert.equal(`${m.num}/${m.den}`, s, m.src); };
  // Each expected string is checked to literally appear in the file's overall table row, so this is not a copy.
  const rowHas = (file, rowRe, s) => {
    const line = read(file).split('\n').find((l) => rowRe.test(l));
    assert.ok(line && line.includes(s), `${file}: "${s}" in its row`);
  };
  const cases = [
    ['hf', D.HOLDOUT_SPECS.hf, { t3: ['171/600', '0/600', '0/400'], dvaa: ['364/600', '364/600', '22/400'] }],
    ['ipi', D.HOLDOUT_SPECS.ipi, { t3: ['30/370', '12/370', '0/200'], dvaa: ['190/370', '190/370', '18/200'] }],
    ['hma', D.HOLDOUT_SPECS.hma, { t3: ['31/328', '2/328', '0/164'], dvaa: ['208/328', '208/328', '21/164'] }],
  ];
  for (const [k, spec, exp] of cases) {
    for (const who of ['t3', 'dvaa']) {
      const re = who === 't3' ? spec.ours : spec.base;
      ['det', 'prev', 'fp'].forEach((key, i) => {
        rowHas(spec.file, re, exp[who][i]);
        expectFrac(h[k][who][key], exp[who][i]);
      });
    }
  }
  assert.equal(D.fmt(h.ipi.t3.prev, 'pct'), '3.2%');
  assert.equal(D.fmt(h.ipi.dvaa.prev, 'pct'), '51.4%');
});

test('held-out parser fails visibly, not with a number, when the table changes shape', () => {
  const broken = D.parseHoldoutMd('# nothing here\n', D.HOLDOUT_SPECS.hf);
  for (const who of ['t3', 'dvaa']) for (const k of ['det', 'prev', 'fp']) {
    assert.equal(broken[who][k].ok, false);
    assert.match(D.fmt(broken[who][k]), /^⚠ missing: captures\/holdout-hf\/RESULTS\.md#/);
  }
  const renamed = read(D.HOLDOUT_SPECS.ipi.file).replace('Prevention recall', 'Blocked share');
  const p = D.parseHoldoutMd(renamed, D.HOLDOUT_SPECS.ipi);
  assert.equal(p.t3.prev.ok, false, 'a renamed column is missing, not silently another column');
  assert.equal(p.t3.det.ok, true);
});

test('OpsBot (Path A): 5 stacks x 4 scenarios, outcomes follow the leaked / blockedBy / benignOk fields', () => {
  const t = model.track3a;
  const rows = raw.track3a;
  assert.equal(t.stacks.length, 5);
  assert.equal(t.scenarios.length, 4);
  for (const r of rows) {
    const c = t.cells[`${r.stack}|${r.scenario}`];
    assert.ok(c.ok, c.src);
    if (r.kind === 'attack') assert.equal(c.v.label, r.leaked ? 'LEAKED' : 'BLOCKED');
    else assert.equal(c.v.label, r.benignOk ? 'OK' : 'FALSE BLOCK');
  }
  // "No single layer is enough": every single-layer stack leaks at least one attack; only layered stacks stop all.
  const stopped = (s) => t.summary[s].stopped;
  assert.ok(stopped('chat-proxy').num < stopped('chat-proxy').den);
  assert.ok(stopped('hardened').num < stopped('hardened').den);
  assert.equal(stopped('proxy+egress').num, stopped('proxy+egress').den);
  assert.equal(stopped('full').num, stopped('full').den);
  for (const s of t.stacks) assert.equal(t.summary[s].benignOk.num, t.summary[s].benignOk.den);
});

test('contrast, exploit, proxy block, egress and alert are read from their files', () => {
  const c = raw.contrast;
  assert.equal(model.contrast.rows.find((r) => r.key === 'vulnerable').canaryHits.v, c.columns.vulnerable.canaryHits);
  assert.equal(model.contrast.rows.find((r) => r.key === 'block').status.v, c.columns.proxy.block.proxyStatus);
  assert.equal(model.contrast.rows.find((r) => r.key === 'aim').canaryHits.v, c.columns.defended.aim.canaryHits);
  assert.equal(model.exploit.tool.v, raw.aimAb.runA.toolCalls[0].function.name);
  assert.equal(model.exploit.canaryData.v, raw.aimAb.canary.hits[0].query.data);
  assert.equal(model.proxyBlock.status.v, 403);
  assert.match(model.proxyBlock.reasons.v, /exfil_instruction_inbound/);
  const lines = D.parseJsonl(raw.egressEvidence).filter((r) => r.direction === 'egress');
  assert.equal(model.egress.denies.v, lines.filter((r) => r.action === 'deny').length);
  assert.equal(model.egress.passes.v, 0, 'nothing was let out in the recorded block run');
  assert.match(raw.egressStage.provenance.groundTruth, new RegExp(`logged ${model.egress.canaryHits.v} CANARY_HIT`));
  assert.equal(model.alert.detectName.v, raw.egressStage.alerts.run[0].DetectName);
  assert.equal(model.alert.disposition.v, raw.egressStage.alerts.run[0].PatternDispositionDescription);
});

test('a missing file yields "⚠ missing: <file>#<key>" everywhere, never a number', () => {
  const empty = D.deriveAll({});
  const seen = [];
  const walk = (o) => {
    if (o && typeof o === 'object' && 'ok' in o && 'src' in o) { seen.push(o); return; }
    if (o && typeof o === 'object') for (const v of Object.values(o)) walk(v);
  };
  walk(empty.scoring); walk(empty.holdouts); walk(empty.contrast); walk(empty.exploit);
  walk(empty.proxyBlock); walk(empty.egress); walk(empty.alert);
  assert.ok(seen.length > 50);
  for (const m of seen) {
    assert.equal(m.ok, false, m.src);
    assert.match(D.fmt(m), /^⚠ missing: \S+#/);
  }
  assert.equal(empty.track3a.ok, false);
  // A single absent key (not the whole file) is also reported by name.
  const partial = structuredClone(R);
  delete partial.detectors.t3.recallByPositiveKindPrevention.exfil.tp;
  const m = D.deriveScoring(partial).exfil.t3;
  assert.equal(D.fmt(m), '⚠ missing: sentinel/scoring/results.json#detectors.t3.recallByPositiveKindPrevention.exfil.tp / detectors.t3.recallByPositiveKindPrevention.exfil.positives');
});

test('the page binds only model paths that exist, and never hard-codes a scored number', () => {
  const html = read('demo/slides/deck.html');
  const paths = [...html.matchAll(/data-m="([^"]+)"/g)].map((x) => x[1]);
  assert.ok(paths.length > 40);
  for (const p of paths) {
    const m = D.getPath(model, p);
    assert.ok(m && typeof m === 'object' && 'src' in m, `data-m="${p}" resolves to a metric`);
    assert.ok(m.ok, `data-m="${p}" is sourced in the committed data (${m.src})`);
  }
  // Strip notes (spoken script lines, which the runner checks separately) and comments, then look for the
  // committed headline numbers as literals in the slide markup.
  const markup = html.replace(/<aside class="notes"[\s\S]*?<\/aside>/g, '').replace(/<!--[\s\S]*?-->/g, '').replace(/<script[\s\S]*?<\/script>/g, '');
  for (const lit of ['57/71', '64/71', '0/164', '21/164', '41.8', '63.0', '67.7', '65.6', '0/600', '364/600', '12/370', '190/370', '31/328', '208/328']) {
    assert.ok(!markup.includes(lit), `slide markup hard-codes ${lit}`);
  }
});

test('wording rules (#123, #110 pass 3) hold in the slide markup', () => {
  const html = read('demo/slides/deck.html');
  const markup = html.replace(/<!--[\s\S]*?-->/g, '');
  for (const banned of [/100% precision/i, /slice of Falcon AIDR/i, /blocks what it catches/i, /we block any destination that came only from untrusted content/i, /spacing bypass/i, /\bintegrated\b/i, /0\/40/, /40\/40/]) {
    assert.ok(!banned.test(markup), `banned wording: ${banned}`);
  }
  assert.match(markup, /labelled by DVAA's ground truth and the published benchmarks/);
  assert.match(markup, /holds against every non-allowlisted destination we tried/);
  assert.match(markup, /on public indirect-injection sets that name a destination we prevent/);
  assert.match(markup, /our request-side rule is narrow, which is why default-deny egress is the control/i);
  assert.match(markup, /1 of 22 in our test/);
  // Every slide has a speaker-notes budget; the main flow sums to roughly 6 minutes.
  const budgets = [...html.matchAll(/<aside class="notes" data-budget="(\d+)"/g)].map((x) => Number(x[1]));
  const total = budgets.reduce((a, b) => a + b, 0);
  assert.equal(budgets.length, [...html.matchAll(/<section class="slide"/g)].length);
  assert.ok(total >= 330 && total <= 420, `main flow ~6:00 (got ${total}s)`);
});
