// Confusion-matrix / precision / recall / F1 block: the derived numbers must match the committed
// counts in results.json exactly, and must appear verbatim in the rendered RESULTS.md. This guards the
// judge-facing P/R/F1 table (gap #164) against drift: it reads the REAL committed results.json
// (353 cases, data-rich) and asserts the derivation against the stored tp/fp/tn/fn, never a fixture.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { f1, accuracy, round } from '../src/metrics.mjs';
import { renderMarkdown } from '../src/report.mjs';
import { REPO_ROOT } from './helpers.mjs';

const RESULTS = JSON.parse(readFileSync(path.join(REPO_ROOT, 'sentinel', 'scoring', 'results.json'), 'utf8'));
const LENSES = ['detection', 'prevention', 'blocking'];

test('f1 helper: harmonic mean, with null/zero edges defined', () => {
  assert.equal(f1(1, 0.6772), round((2 * 1 * 0.6772) / (1 + 0.6772)));
  assert.equal(f1(1, 0), 0);        // precision ok, recall 0 → F1 0 (defined)
  assert.equal(f1(0, 0), 0);        // both 0 → 0, not NaN
  assert.equal(f1(null, 0.5), null); // no precision data → null, never read as 0
  assert.equal(f1(0.5, null), null);
});

test('accuracy helper: (TP+TN)/total, null when empty', () => {
  assert.equal(accuracy({ tp: 128, fp: 0, tn: 164, fn: 61 }), round(292 / 353));
  assert.equal(accuracy({ tp: 0, fp: 0, tn: 0, fn: 0 }), null);
});

test('derived precision/recall match the committed headline-lens counts exactly', () => {
  assert.ok(RESULTS.headlineLenses, 'results.json has headlineLenses');
  for (const lens of LENSES) {
    const m = RESULTS.headlineLenses[lens];
    assert.ok(m, `headlineLenses.${lens} present`);
    // counts are internally consistent with the corpus
    assert.equal(m.tp + m.fn, RESULTS.corpus.positives, `${lens}: TP+FN = positives`);
    assert.equal(m.fp + m.tn, RESULTS.corpus.negatives, `${lens}: FP+TN = negatives`);
    // precision/recall derived from counts equal the stored rates
    assert.equal(round(m.tp / (m.tp + m.fp)), m.precision, `${lens}: precision = TP/(TP+FP)`);
    assert.equal(round(m.tp / (m.tp + m.fn)), m.recall, `${lens}: recall = TP/(TP+FN)`);
  }
});

test('committed data: zero false positives → precision exactly 1 in every headline lens', () => {
  for (const lens of LENSES) {
    const m = RESULTS.headlineLenses[lens];
    assert.equal(m.fp, 0, `${lens}: FP is 0 across the benign corpus`);
    assert.equal(m.precision, 1, `${lens}: precision is exactly 1`);
  }
});

test('RESULTS.md confusion-matrix block renders the derived P/R/F1/accuracy for each lens', () => {
  const md = renderMarkdown(RESULTS);
  assert.match(md, /### Confusion matrix & precision \/ recall \/ F1/);
  const D = RESULTS.headlineLenses.detection;
  // the 2x2 matrix cells
  assert.match(md, new RegExp(`TP ${D.tp} \\| FN ${D.fn}`));
  assert.match(md, new RegExp(`FP ${D.fp} \\| TN ${D.tn}`));
  const fmt = (x) => `${(Math.round(x * 1000) / 10).toFixed(1)}%`;
  for (const lens of LENSES) {
    const m = RESULTS.headlineLenses[lens];
    const expectedF1 = fmt(f1(m.precision, m.recall));
    const expectedAcc = fmt(accuracy(m));
    // the lens row carries precision, recall, F1, accuracy and the four counts
    const row = new RegExp(
      `\\| ${fmt(m.precision)} \\| ${fmt(m.recall)} \\| ${expectedF1} \\| ${expectedAcc} \\| ${m.tp} \\| ${m.fp} \\| ${m.tn} \\| ${m.fn} \\|`,
    );
    assert.match(md, row, `${lens}: P/R/F1/accuracy row present and derived from counts`);
  }
});
