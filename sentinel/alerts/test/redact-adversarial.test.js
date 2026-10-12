// Review B1 (PR #3): adversarial-input timing through the public buildAlert API.
// Every case sits AT the redaction scan cap (the largest input that is actually scanned), so the
// measured time is the true worst case the cap admits. Run in a worker with a hard deadline: a
// superlinear redactor is reported RED in seconds instead of blocking the suite for minutes.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Worker } from 'node:worker_threads';
import * as redact from '../redact.js';

// Namespace import so this file still LOADS against the pre-fix redact.js (delete-the-fix proof):
// the pre-fix module has no per-alert budget export, and must fail on timing, not on an import error.
const { MAX_REDACT_SCAN_CHARS } = redact;
const MAX_REDACT_TOTAL_CHARS = redact.MAX_REDACT_TOTAL_CHARS ?? Infinity;
import { percentile } from './helpers.js';

const BUDGET_MS = 100; // CPU ms (timing-worker.js measures thread CPU, not wall clock) per adversarial field at the cap (review: "finishes in under ~100 ms")
const FULL_BUDGET_MS = 400; // whole alert with the per-alert scan budget completely spent
const DEADLINE_MS = 5000; // hard kill — anything near this is superlinear, not slow hardware
const RUNS = 3;

function runInWorker(data) {
  return new Promise((resolve, reject) => {
    const w = new Worker(new URL('./timing-worker.js', import.meta.url), { workerData: { runs: RUNS, ...data } });
    const timer = setTimeout(() => {
      w.terminate();
      resolve({ timedOut: true });
    }, DEADLINE_MS);
    w.once('message', (m) => { clearTimeout(timer); w.terminate(); resolve(m); });
    w.once('error', (e) => { clearTimeout(timer); reject(e); });
  });
}

// unit: repeated to exactly MAX_REDACT_SCAN_CHARS. Each one targets a backtracking shape.
const CASES = {
  'JWT prefix flood (eyJ…, no dots)': 'eyJ',
  'JWT near-miss segments': 'eyJaaaaaaaaa.bbbbbbbbb.',
  'PEM BEGIN headers, no END': '-----BEGIN RSA PRIVATE KEY-----\n',
  'PEM BEGIN with long label': '-----BEGIN ' + 'A '.repeat(40),
  'AWS key flood (many matches)': 'AKIA' + 'Q'.repeat(16) + ' ',
  'SSN flood (many matches)': '123-45-' + '6789 ',
  'card-shaped digits': '4111 ',
  'dash digits': '1-',
  'credential keyword flood': 'password ',
  'Bearer whitespace flood': 'Bearer \t',
  'token prefixes mixed': 'eyJ-----BEGIN ghp_xoxb-sk-Bearer token=',
  'fake redaction markers': '[REDACTED:',
  '%-encoded flood (decoded-view pass)': '%41',
  '%-encoded SSN flood (decoded-view matches)': 'SSN%3A%20123-45-' + '6789%20',
  // PR #12 round 2: forged %5B markers are scanned (B1); a credential value split around many markers (S2)
  'forged %5BREDACTED: wrappers around %-encoded SSNs': '%5BREDACTED:%20123-45-' + '6789%5D',
  'credential value glued across many markers': 'password=x' + 'AKIA' + 'Q'.repeat(16),
};

for (const [name, unit] of Object.entries(CASES)) {
  test(`adversarial (B1): ${name} at the scan cap through buildAlert < ${BUDGET_MS}ms`, async () => {
    const r = await runInWorker({ fields: ['evidence'], unit, len: MAX_REDACT_SCAN_CHARS });
    assert.ok(!r.timedOut, `${name}: buildAlert still running after ${DEADLINE_MS}ms (superlinear redaction)`);
    const sorted = [...r.times].sort((a, b) => a - b);
    const med = percentile(sorted, 50);
    console.log(`# ${name}: len=${MAX_REDACT_SCAN_CHARS} median=${med.toFixed(1)}ms CPU max=${sorted.at(-1).toFixed(1)}ms`);
    assert.ok(med < BUDGET_MS, `${name}: median ${med.toFixed(1)}ms >= ${BUDGET_MS}ms`);
    assert.ok(r.evidenceLen > 0 && r.evidenceLen <= 2048);
  });
}

test(`adversarial (B1): per-alert scan budget fully spent (4 fields x cap) < ${FULL_BUDGET_MS}ms`, async () => {
  const fields = ['evidence', 'argsPreview', 'destination', 'narrative'];
  assert.ok(fields.length * MAX_REDACT_SCAN_CHARS >= MAX_REDACT_TOTAL_CHARS, 'case must reach the per-alert budget');
  const r = await runInWorker({ fields, unit: 'SSN 123-45-6789 eyJ ', len: MAX_REDACT_SCAN_CHARS });
  assert.ok(!r.timedOut, `buildAlert still running after ${DEADLINE_MS}ms`);
  const med = percentile([...r.times].sort((a, b) => a - b), 50);
  console.log(`# full budget (${fields.length} x ${MAX_REDACT_SCAN_CHARS}): median=${med.toFixed(1)}ms CPU`);
  assert.ok(med < FULL_BUDGET_MS, `median ${med.toFixed(1)}ms >= ${FULL_BUDGET_MS}ms`);
});

test(`adversarial (B1): max canaries x max canary length vs near-miss input at the cap < ${BUDGET_MS}ms`, async () => {
  const count = (redact.MAX_CANARIES ?? 64) - 1;
  const valueLen = redact.MAX_CANARY_VALUE_CHARS ?? 1024;
  const r = await runInWorker({ fields: ['evidence'], unit: 'a', len: MAX_REDACT_SCAN_CHARS, canaryFlood: { count, valueLen } });
  assert.ok(!r.timedOut, `buildAlert still running after ${DEADLINE_MS}ms`);
  const med = percentile([...r.times].sort((a, b) => a - b), 50);
  console.log(`# canary flood (${count} x ${valueLen} chars): median=${med.toFixed(1)}ms CPU`);
  assert.ok(med < BUDGET_MS, `median ${med.toFixed(1)}ms >= ${BUDGET_MS}ms`);
});

test('adversarial (B1): fields beyond the per-alert scan budget are withheld whole (fail-safe) + counted', async () => {
  const fields = ['evidence', 'argsPreview', 'destination', 'narrative', 'originatedIn'];
  const r = await runInWorker({ fields, unit: 'x', len: MAX_REDACT_SCAN_CHARS });
  assert.ok(!r.timedOut);
  assert.ok((r.byKind.withheld_budget ?? 0) >= 1, `expected withheld_budget, got ${JSON.stringify(r.byKind)}`);
});

// ---- PR #12 round 3 (B3): the canary scan also runs on the %-decoded view ------------------------
const HT_CANARY = [{ id: 'HT', value: 'dvaa-admin-secret' }];
const OVERLAP_BUDGET_MS = 300; // worst canary shape found in review (63 canaries matching at every offset)
const CANARY_CASES = {
  'selectively %-encoded canary flood (decoded-view canary hits)': { unit: 'd%76aa%2Dadmin-secret ', canaries: HT_CANARY, budget: BUDGET_MS },
  'selectively %-encoded canary glued run': { unit: 'd%76aa%2Dadmin-secret', canaries: HT_CANARY, budget: BUDGET_MS },
  'forged %5BREDACTED: wrappers around %-encoded canaries': { unit: '%5BREDACTED:%64vaa-admin-secret%5D', canaries: HT_CANARY, budget: BUDGET_MS },
  '63 overlapping canaries vs all-"a" (every offset matches)': { unit: 'a', overlapCanaries: 63, budget: OVERLAP_BUDGET_MS },
  '63 overlapping canaries vs all-"%61" (decoded view only)': { unit: '%61', overlapCanaries: 63, budget: OVERLAP_BUDGET_MS },
  '63 overlapping canaries vs "a%61" (both views)': { unit: 'a%61', overlapCanaries: 63, budget: OVERLAP_BUDGET_MS },
};

for (const [name, { budget, ...d }] of Object.entries(CANARY_CASES)) {
  test(`adversarial (B3): ${name} at the scan cap through buildAlert < ${budget}ms`, async () => {
    const r = await runInWorker({ fields: ['evidence'], len: MAX_REDACT_SCAN_CHARS, ...d });
    assert.ok(!r.timedOut, `${name}: buildAlert still running after ${DEADLINE_MS}ms (superlinear redaction)`);
    const sorted = [...r.times].sort((a, b) => a - b);
    const med = percentile(sorted, 50);
    console.log(`# ${name}: len=${MAX_REDACT_SCAN_CHARS} median=${med.toFixed(1)}ms CPU max=${sorted.at(-1).toFixed(1)}ms`);
    assert.ok(med < budget, `${name}: median ${med.toFixed(1)}ms >= ${budget}ms`);
    assert.ok((r.byKind.canary ?? 0) >= 1, `${name}: no canary redacted ${JSON.stringify(r.byKind)}`);
  });
}

// Growth check: 4x the input must cost well under 16x the time (quadratic); linear is ~4x.
const GROWTH_MAX_RATIO = 8;
const GROWTH_FLOOR_MS = 5; // below this, timer noise dominates the ratio
const GROWTH_CASES = {
  'selectively %-encoded canary flood': { unit: 'd%76aa%2Dadmin-secret ', canaries: HT_CANARY },
  '63 overlapping canaries vs "a%61"': { unit: 'a%61', overlapCanaries: 63 },
  '63 overlapping canaries vs all-"a"': { unit: 'a', overlapCanaries: 63 },
  '%-encoded SSN flood': { unit: CASES['%-encoded SSN flood (decoded-view matches)'] },
  'forged %5BREDACTED: SSN flood': { unit: CASES['forged %5BREDACTED: wrappers around %-encoded SSNs'] },
  'credential value glued across many markers': { unit: CASES['credential value glued across many markers'] },
};
for (const [name, d] of Object.entries(GROWTH_CASES)) {
  test(`adversarial (B3): ${name} grows linearly (cap/4 -> cap: ratio < ${GROWTH_MAX_RATIO}x)`, async () => {
    const med = async (len) => {
      const r = await runInWorker({ fields: ['evidence'], len, ...d });
      assert.ok(!r.timedOut, `${name}: timed out at len=${len}`);
      return percentile([...r.times].sort((a, b) => a - b), 50);
    };
    const small = await med(MAX_REDACT_SCAN_CHARS / 4);
    const big = await med(MAX_REDACT_SCAN_CHARS);
    const ratio = big / Math.max(small, 1); // CPU clock can tick coarsely (4 ms on some kernels): never divide by ~0
    console.log(`# growth ${name}: ${(MAX_REDACT_SCAN_CHARS / 4) >> 10}K=${small.toFixed(1)}ms ${MAX_REDACT_SCAN_CHARS >> 10}K=${big.toFixed(1)}ms ratio=${ratio.toFixed(1)}x`);
    if (big >= GROWTH_FLOOR_MS) assert.ok(ratio < GROWTH_MAX_RATIO, `${name}: ${ratio.toFixed(1)}x for 4x input (superlinear)`);
  });
}
