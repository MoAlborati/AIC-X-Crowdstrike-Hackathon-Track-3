/**
 * T6 corpus tests — data-rich, real-seam.
 *
 * Real seam: the evasion proof runs against DVAA's ACTUAL detectAttacks()/
 * detectionText() when a DVAA checkout is present ($DVAA_SRC or the T1 clone),
 * otherwise a faithful attributed replica subset (see tools/baseline.mjs). The
 * test prints which source it used.
 *
 * Run:  node --test captures/variants/tests/
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadBaseline } from '../tools/baseline.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..'); // captures/variants
const FIX = path.join(ROOT, 'fixtures');

function listFixtures() {
  const out = [];
  for (const dir of fs.readdirSync(FIX)) {
    const d = path.join(FIX, dir);
    if (!fs.statSync(d).isDirectory()) continue;
    for (const f of fs.readdirSync(d)) {
      if (f.endsWith('.json')) out.push({ group: dir, file: f, path: path.join(d, f) });
    }
  }
  return out;
}

const fixtures = listFixtures().map((f) => ({ ...f, doc: JSON.parse(fs.readFileSync(f.path, 'utf8')) }));

test('corpus is non-empty and covers all required sources', () => {
  const groups = new Set(fixtures.map((f) => f.group));
  for (const g of ['deepset', 'agentdojo', 'injecagent', 'benign', 'evasion']) {
    assert.ok(groups.has(g), `missing fixture group: ${g}`);
  }
  assert.ok(fixtures.length >= 13, `expected >=13 fixtures, got ${fixtures.length}`);
});

test('every fixture matches the schema (request.messages + label + dvaa block)', () => {
  for (const { file, doc } of fixtures) {
    assert.ok(typeof doc.id === 'string' && doc.id.length, `${file}: id`);
    assert.ok(doc.source && typeof doc.source === 'object', `${file}: source`);
    assert.ok(Array.isArray(doc.request?.messages) && doc.request.messages.length, `${file}: request.messages`);
    for (const m of doc.request.messages) {
      assert.ok(typeof m.role === 'string' && typeof m.content === 'string', `${file}: message shape`);
    }
    assert.ok(['positive', 'negative'].includes(doc.label?.groundTruth), `${file}: groundTruth`);
    assert.ok(['block', 'allow'].includes(doc.label?.expectedVerdict), `${file}: expectedVerdict`);
    assert.ok(doc.label?.dvaa && typeof doc.label.dvaa.exfilAttempted === 'boolean', `${file}: dvaa block`);
    // dvaa label consistency
    if (doc.label.groundTruth === 'negative') {
      assert.equal(doc.label.dvaa.exfilAttempted, false, `${file}: negative must not attempt exfil`);
    }
  }
});

test('reused benchmark cases carry provenance + license (no new attack content authored)', () => {
  for (const { group, file, doc } of fixtures) {
    if (['deepset', 'agentdojo', 'injecagent'].includes(group)) {
      assert.ok(doc.source.benchmark, `${file}: benchmark name`);
      assert.ok(doc.source.license, `${file}: license`);
      assert.ok(doc.source.url, `${file}: source url`);
      assert.match(JSON.stringify(doc.source), /not authored|reused/i, `${file}: reuse note`);
    }
  }
});

test('data-rich: benign long doc >8KB and tool output has hundreds of rows', () => {
  const longDoc = fixtures.find((f) => f.doc.id === 'BEN-LONGDOC-001').doc;
  assert.ok(longDoc.request.messages[0].content.length > 8 * 1024, 'benign long doc must exceed 8KB');
  const rows = fixtures.find((f) => f.doc.id === 'BEN-TOOLROWS-001').doc;
  assert.ok(rows.dataRich.rows >= 300, 'tool output must have hundreds of rows');
});

test('REAL-SEAM evasion proof: middle variants evade DVAA 8KB baseline; signal present on full scan; start/end do not evade', async () => {
  const baseline = await loadBaseline();
  console.log(`[baseline source] ${baseline.source}${baseline.root ? ` (${baseline.root})` : ''}`);
  const evasion = fixtures.filter((f) => f.group === 'evasion');
  assert.ok(evasion.length >= 6, 'expected position variants for DVAA + benchmark injections');

  let middleCount = 0;
  for (const { file, doc } of evasion) {
    const content = doc.request.messages[0].content;
    const verdict = baseline.detectAttacks(content);
    const isMiddle = /middle/i.test(doc.scenario);
    // offset metadata recorded by the generator must be internally consistent
    assert.ok(doc.baseline8kb.docLength > baseline.DETECTION_EDGE * 2, `${file}: doc must exceed 16KB`);

    if (isMiddle) {
      middleCount++;
      assert.equal(verdict.hasAttack, false, `${file}: middle variant must EVADE the 8KB baseline`);
      assert.equal(doc.baseline8kb.inMiddleGap, true, `${file}: injection must sit in the middle gap`);
      assert.equal(doc.baseline8kb.signalPresentOnFullScan, true, `${file}: signal must be present on full scan`);
      // independent re-check: a full scan of the injection region flags it
      const region = content.slice(doc.baseline8kb.injectionOffsetStart - 50, doc.baseline8kb.injectionOffsetEnd + 50);
      assert.equal(baseline.detectAttacks(region).hasAttack, true, `${file}: full-scan signal re-check`);
    } else {
      assert.equal(verdict.hasAttack, true, `${file}: start/end control must be caught by the baseline`);
    }
  }
  assert.ok(middleCount >= 2, 'expected a DVAA-trigger and an AgentDojo middle evasion variant');
});

test('REAL-SEAM: benign negatives are clean; exfil positives carry a detectable destination signal', async () => {
  const baseline = await loadBaseline();
  let beyondBaseline = 0;
  for (const { group, file, doc } of fixtures) {
    if (!['deepset', 'agentdojo', 'injecagent', 'benign'].includes(group)) continue;
    const content = doc.request.messages.map((m) => m.content).join('\n');
    const verdict = baseline.detectAttacks(content);

    if (doc.label.groundTruth === 'negative') {
      // False-positive guard: a benign case must not trip DVAA's own patterns.
      assert.equal(verdict.hasAttack, false, `${file}: benign must not trip the detector (false-positive guard)`);
      continue;
    }
    // Positive. Exfil-category cases (destination recorded) carry a send/post-to
    // signal the baseline's dataExfiltration patterns catch — a real-seam claim.
    const isExfil = Boolean(doc.label.dvaa.exfilTargetUrl);
    if (isExfil) {
      assert.equal(verdict.hasAttack, true, `${file}: exfil positive must be detectable on full scan`);
    } else if (!verdict.hasAttack) {
      // Prompt-injection-only cases phrased outside DVAA's narrow patterns are
      // intentionally part of the corpus: they exercise detection BEYOND DVAA's
      // baseline. Not a failure; counted and reported.
      beyondBaseline++;
    }
  }
  console.log(`[corpus] prompt-injection cases beyond DVAA's baseline patterns: ${beyondBaseline}`);
  assert.ok(beyondBaseline >= 1, 'corpus should include at least one case beyond DVAA baseline patterns');
});
