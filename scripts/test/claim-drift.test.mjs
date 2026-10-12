// scripts/claim-drift.mjs: quoted T3/DVAA percentages in the pitch docs must match sentinel/scoring/results.json.
// Run: node --test scripts/test/claim-drift.test.mjs   (also run by `scripts/eval.sh gate`)
// Real seams: the committed results.json and the committed docs, copied into a temp repo and mutated there.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, copyFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { allowedRates, checkDoc, matches, DEFAULT_DOCS } from '../claim-drift.mjs';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const SCRIPT = path.join(REPO, 'scripts', 'claim-drift.mjs');
const RESULTS = path.join(REPO, 'sentinel', 'scoring', 'results.json');
const results = JSON.parse(readFileSync(RESULTS, 'utf8'));
const rates = allowedRates(results);

function tempRepo() {
  const dir = mkdtempSync(path.join(REPO, '.eval', 'claim-drift-'));
  for (const f of [...DEFAULT_DOCS, 'sentinel/scoring/results.json']) {
    mkdirSync(path.dirname(path.join(dir, f)), { recursive: true });
    copyFileSync(path.join(REPO, f), path.join(dir, f));
  }
  return dir;
}
const cli = (dir) => spawnSync(process.execPath, [SCRIPT, '--repo', dir], { encoding: 'utf8' });
mkdirSync(path.join(REPO, '.eval'), { recursive: true });

test('allowed rates come from results.json (T3 lenses + DVAA baseline)', () => {
  for (const r of [results.headlineLenses.detection.recall, results.headlineLenses.prevention.recall,
    results.headlineLenses.detection.falsePositiveRate,
    results.detectors['dvaa-baseline'].modes.enforce.prevention.recall,
    results.detectors['dvaa-baseline'].modes.enforce.detection.falsePositiveRate]) {
    assert.ok(rates.includes(r), `missing ${r}`);
  }
  assert.ok(!rates.some((r) => matches('83.1', r)), '83.1% must not be a current value');
});

test('matches() compares at the precision the doc quotes', () => {
  assert.ok(matches('41.8', 0.418));
  assert.ok(matches('63.0', 0.6296));
  assert.ok(matches('63', 0.6296));
  assert.ok(matches('0', 0));
  assert.ok(!matches('41.9', 0.418));
  assert.ok(!matches('83.1', 0.6772));
});

test('the committed docs have no claim drift (CLI exit 0)', () => {
  const r = spawnSync(process.execPath, [SCRIPT, '--repo', REPO], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stdout + r.stderr);
});

test('delete-the-fix: a stale 83.1% detection claim injected into the real README goes RED', () => {
  const dir = tempRepo();
  try {
    const p = path.join(dir, 'README.md');
    writeFileSync(p, readFileSync(p, 'utf8') + '\n\nSentinelProxy T3 detection recall is 83.1% on the DVAA corpus.\n');
    const r = cli(dir);
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.match(r.stdout, /README\.md:\d+\s+83\.1%/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('delete-the-fix: stale 83.1% in each pitch doc (QA-PREP mid-paragraph, DECK, SUBMISSION) goes RED', () => {
  for (const doc of DEFAULT_DOCS) {
    const dir = tempRepo();
    try {
      const p = path.join(dir, doc);
      const src = readFileSync(p, 'utf8').replace(/67\.7%/, '83.1%');
      const injected = src.includes('83.1%') ? src : src + '\n\nOur prevention recall is 83.1%.\n';
      writeFileSync(p, injected);
      const r = cli(dir);
      assert.equal(r.status, 1, `${doc}: ${r.stdout}${r.stderr}`);
      assert.ok(r.stdout.includes(`${doc}:`) && r.stdout.includes('83.1%'), `${doc}: ${r.stdout}`);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }
});

test('delete-the-fix: results.json moving under the docs (re-score) turns the quoted 41.8% RED', () => {
  const dir = tempRepo();
  try {
    const p = path.join(dir, 'sentinel/scoring/results.json');
    const j = JSON.parse(readFileSync(p, 'utf8'));
    j.preventionRecall = 0.5; j.headlineLenses.prevention.recall = 0.5;
    for (const m of Object.values(j.detectors?.t3?.modes ?? {})) if (m.prevention) m.prevention.recall = 0.5;
    writeFileSync(p, JSON.stringify(j));
    const r = cli(dir);
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.match(r.stdout, /41\.8%/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('held-out labelled numbers are allowlisted; numbers before the label are still checked', () => {
  const ok = 'On a held-out set of 1000 cases, T3 detected 83.1% and prevented 0%, with 2.0% false positives.\n';
  assert.deepEqual(checkDoc('x.md', ok, rates), []);
  const multi = 'On the held-out set T3 detected 28.5%.\nDVAA detected and prevented 60.7% (5.5% FP).\n';
  assert.deepEqual(checkDoc('x.md', multi, rates), []);
  const before = 'T3 detection recall is 83.1% on the corpus. Held-out benign: 3.1% blocked.\n';
  const d = checkDoc('x.md', before, rates);
  assert.equal(d.length, 1);
  assert.equal(d[0].pct, '83.1%');
  // A held-out label does not leak into the next paragraph.
  const next = 'Held-out: 28.5% detected.\n\nT3 prevention recall is 83.1%.\n';
  assert.equal(checkDoc('x.md', next, rates).length, 1);
});

test('unfilled <<METRIC:...>> placeholders are OK; current values pass; out-of-scope % ignored', () => {
  const doc = [
    '| **Detection recall** | <<METRIC:t3.detection.recall>> | <<METRIC:baseline.detection.recall>> |',
    '| Prevention recall · benign FP | `<<METRIC>>` · `<<METRIC>>` |',
    'Detection recall 67.7% vs DVAA 65.6%; prevention 41.8% vs 63.0%; FP 0% vs 12.8%; precision 100%.',
    '',
    'Coffee consumption rose 83.1% during the hackathon.',
  ].join('\n');
  assert.deepEqual(checkDoc('x.md', doc, rates), []);
});

test('third-party vendor figures (AIDR) are not T3/DVAA claims', () => {
  assert.deepEqual(checkDoc('x.md', 'Detection: AIDR quotes "Up to 99% efficacy".\n', rates), []);
});
