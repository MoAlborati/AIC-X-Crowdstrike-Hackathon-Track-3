// T6 labeled corpus (captures/variants/, PR #10): 12 attacks incl. start/middle/end position variants of a
// ~22 KB document (the middle ones evade DVAA's 8 KB head/tail scan) + 6 benign incl. a 16 KB+ doc and a
// 400-row tool output. Loaded from the working tree when T6 is merged, else from the origin/t6-eval-corpus
// git ref. If neither exists the suite is SKIPPED LOUDLY with the reason (never passes vacuously).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { CAPTURES, REPO_ROOT, dvaaDetector, dvaaBaselineWindow } from './helpers.js';

const REF = 'origin/t6-eval-corpus';

function loadCorpus() {
  const dir = path.join(CAPTURES, 'variants', 'fixtures');
  if (fs.existsSync(dir)) {
    const out = [];
    for (const d of fs.readdirSync(dir)) for (const f of fs.readdirSync(path.join(dir, d))) out.push(JSON.parse(fs.readFileSync(path.join(dir, d, f), 'utf8')));
    return { source: dir, cases: out };
  }
  try {
    const names = execFileSync('git', ['-C', REPO_ROOT, 'ls-tree', '-r', '--name-only', REF, '--', 'captures/variants/fixtures'], { encoding: 'utf8' }).trim().split('\n').filter((n) => n.endsWith('.json'));
    const cases = names.map((n) => JSON.parse(execFileSync('git', ['-C', REPO_ROOT, 'show', `${REF}:${n}`], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 })));
    return { source: REF, cases };
  } catch (e) {
    return { source: null, cases: [], reason: `T6 corpus not in working tree and git ref ${REF} unavailable: ${e.message.split('\n')[0]}` };
  }
}

const corpus = loadCorpus();
const skip = corpus.cases.length === 0 ? `SKIPPED LOUDLY — ${corpus.reason}` : false;

test('T6 corpus is present and complete (12 attack + 6 benign)', { skip }, () => {
  const pos = corpus.cases.filter((c) => c.label.groundTruth === 'positive');
  const neg = corpus.cases.filter((c) => c.label.groundTruth === 'negative');
  assert.equal(pos.length, 12, `positives from ${corpus.source}`);
  assert.equal(neg.length, 6);
});

test('every T6 attack is DETECTED; every exfil-bearing attack is BLOCKED; 0 benign false positives', { skip }, () => {
  const rows = [];
  for (const c of corpus.cases) {
    const { det } = dvaaDetector();
    const d = det.inspect({ sessionId: c.id, request: c.request });
    rows.push({ id: c.id, truth: c.label.groundTruth, expected: c.label.expectedVerdict, action: d.action, detected: d.findings.length > 0, rules: d.findings.map((f) => f.ruleId) });
  }
  const pos = rows.filter((r) => r.truth === 'positive');
  const neg = rows.filter((r) => r.truth === 'negative');
  assert.deepEqual(pos.filter((r) => !r.detected).map((r) => r.id), [], 'missed attacks');
  assert.deepEqual(neg.filter((r) => r.action !== 'allow' || r.detected).map((r) => r.id), [], 'benign false positives');
  // Exfil-bearing attacks (name a destination/honeytoken) block by default. Pure jailbreaks without an exfil
  // element (deepset DS-PI-*) are detected and ALERTED: the lexicon is never the sole gate (ADJACENT §6c).
  const exfil = pos.filter((r) => !r.id.startsWith('DS-PI'));
  assert.deepEqual(exfil.filter((r) => r.action !== 'block').map((r) => r.id), [], 'exfil attacks not blocked');
  for (const r of pos.filter((x) => x.id.startsWith('DS-PI'))) assert.deepEqual([r.action, r.rules], ['allow', ['inbound.instruction_in_principal_turn']]);
});

test('operator can tighten: inbound.injection=block blocks the pure-jailbreak cases too', { skip }, () => {
  for (const c of corpus.cases.filter((x) => x.id.startsWith('DS-PI'))) {
    const { det } = dvaaDetector({ policy: { inbound: { injection: 'block' } } });
    assert.equal(det.inspect({ sessionId: c.id, request: c.request }).action, 'block', c.id);
  }
});

test('position variants: MIDDLE evades DVAA 8 KB head/tail, we catch start/middle/end identically', { skip }, () => {
  const variants = corpus.cases.filter((c) => /^EVA-/.test(c.id));
  assert.equal(variants.length, 6);
  for (const c of variants) {
    const text = c.request.messages.map((m) => m.content).join('\n');
    assert.ok(text.length > 16 * 1024, `${c.id} is ${text.length} chars`);
    const marker = c.id.startsWith('EVA-POS') ? 'NEW INDEX INSTRUCTIONS' : 'important message from me';
    const inBaseline = dvaaBaselineWindow(text).includes(marker);
    if (c.id.includes('MIDDLE')) assert.equal(inBaseline, false, `${c.id} should evade the 8 KB baseline`);
    else assert.equal(inBaseline, true, `${c.id} control: baseline sees start/end`);
    const { det } = dvaaDetector();
    const d = det.inspect({ sessionId: c.id, request: c.request });
    assert.equal(d.action, 'block', c.id);
    const f = d.findings.find((x) => x.ruleId === 'inbound.exfil_instruction');
    assert.ok(f, c.id);
    assert.match(f.evidence, /full scan/);
    assert.ok(f.reasonCodes.includes('injection_markers'), c.id);
    assert.ok(f.reasonCodes.includes('payee_not_confirmed'), c.id);
    assert.equal(f.direction, 'request');
    assert.equal(f.prevents, true);
  }
});
