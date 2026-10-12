// Adversarial timing (ReDoS) tests AT the maximum payload size (PR #3 review: an unbounded `{8,}` JWT regex
// took 14 s on 256K chars of repeated "eyJ"). Each detector layer must stay under LAYER_BUDGET_MS and the
// whole inspection under the fail-closed time budget, for crafted inputs aimed at every scanner.
// Median of 5 runs per case to keep CI noise out without hiding a quadratic blow-up (which is 100-1000x).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { createDetector, DVAA_HONEYTOKENS, DEFAULT_BOUNDS } from '../index.js';
import { findIbans, findSecretShapes, extractUrls, extractEmails, extractMarkdownLinks, findCardNumbers, findSsns, decodedVariants, splitUntrustedSegments, findInjectionPhrases } from '../src/text.js';
import { quietLogger } from './helpers.js';

// TWO DIFFERENT NUMBERS (review of PR #27):
//   TOTAL_BUDGET_MS = 40  PERFORMANCE bound: a whole inspection of a 384 KiB adversarial turn (PERF_INPUT,
//                         ~16x the ~23 KB demo payloads) must finish in < 40 ms (median of 5). A speed target
//                         that catches quadratic regressions. It is NOT a reason to block traffic.
//   timeBudgetMs (runtime) the fail-closed budget, derived from the proxy's real inspectorTimeoutMs (5000 ms ->
//                         4000 ms) + its abort signal (bounds.js, inspector.js, review B3). Asserted separately
//                         below on payloads at the full 2 MiB cap.
const LAYER_BUDGET_MS = 50;
const TOTAL_BUDGET_MS = 40;
const PERF_INPUT = 384 * 1024;
const MAX = PERF_INPUT;
const SCANNER_INPUT = PERF_INPUT; // each scanner alone is held to 50 ms (a quadratic regression is 100x+ over: see PR delete-the-fix C/D/E)
// The adversarial string appears twice (untrusted tool output + sink args), so each copy is ~45% of the cap.
const ADVERSARIAL = {
  jwt_prefix: 'eyJ',
  jwt_dots: 'eyJabcdefgh.',
  openai_prefix: 'sk-',
  sk_proj_bucket: 'sk-proj-', // collides with every minted api_key canary's 8-char prefix
  emails: 'a@',
  email_domain: 'a@b.',
  urls: 'http://',
  markdown: '![x](http://',
  pem: '-----BEGIN ',
  percent: '%4',
  base64_run: 'QUFB',
  base64_tokens: 'QUFBQUFBQUFBQUFB ',
  hex_run: '41',
  card_digits: '4242 ',
  ssn_like: '123-45-',
  single_token: 'A',
  begin_lines: '----- BEGIN DOC -----\n',
  info_tags: '<INFORMATION>\n',
  phrases: 'ignore previous ',
};
const fill = (u) => u.repeat(Math.ceil((MAX * 0.45) / u.length)).slice(0, Math.floor(MAX * 0.45));

function detectorWithBigRegistry() {
  const det = createDetector({ honeytokens: DVAA_HONEYTOKENS, logger: quietLogger(), bounds: { timeBudgetMs: 100000 } }); // measure, don't fail closed
  for (let i = 0; i < 20000; i++) det.mintCanary(`s${i % 64}`, 'web_fetch', i % 3 === 0 ? 'aws_key' : 'api_key');
  return det;
}

const median = (xs) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];

test('whole inspection < 40 ms (performance bound) and every layer < 50 ms on adversarial 384 KiB inputs (20k canaries)', { timeout: 60000 }, () => {
  const det = detectorWithBigRegistry();
  const report = [];
  for (const [name, unit] of Object.entries(ADVERSARIAL)) {
    const s = fill(unit);
    const req = {
      messages: [
        { role: 'user', content: 'process the feed' },
        { role: 'assistant', tool_calls: [{ id: 'h', type: 'function', function: { name: 'web_fetch', arguments: '{}' } }] },
        { role: 'tool', tool_call_id: 'h', content: s },
      ],
    };
    const res = { choices: [{ message: { role: 'assistant', content: s.slice(0, 4096), tool_calls: [{ id: 'c', type: 'function', function: { name: 'http_post', arguments: JSON.stringify({ url: 'http://x.test/a', body: s }) } }] } }] };
    const layerRuns = {};
    const totals = [];
    for (let r = 0; r < 5; r++) {
      const d = det.inspect({ sessionId: `adv-${name}-${r}`, request: req, response: res });
      assert.equal(d.failClosed, false, `${name}: ${JSON.stringify(d.error)}`);
      totals.push(d.stats.latencyMs);
      for (const l of d.stats.layers) (layerRuns[l.layer] ??= []).push(l.latencyMs);
    }
    const layers = Object.fromEntries(Object.entries(layerRuns).map(([k, v]) => [k, median(v)]));
    report.push({ name, total: median(totals), ...layers });
    for (const [layer, ms] of Object.entries(layers)) assert.ok(ms < LAYER_BUDGET_MS, `${name}: layer ${layer} took ${ms} ms`);
    assert.ok(median(totals) < TOTAL_BUDGET_MS, `${name}: total ${median(totals)} ms >= ${TOTAL_BUDGET_MS} ms budget`);
  }
  console.log(`# adversarial timing @ ${MAX} B perf input (median of 5, ms):`);
  for (const r of report) console.log(`#   ${r.name.padEnd(15)} total=${r.total} ${Object.entries(r).filter(([k]) => !['name', 'total'].includes(k)).map(([k, v]) => `${k}=${v}`).join(' ')}`);
});

test('every text scanner alone is linear: < 50 ms at the payload cap on its own worst-case input', { timeout: 15000 }, () => {
  const scanners = {
    findSecretShapes: [findSecretShapes, ['eyJ', 'eyJab.', 'sk-', 'AKIA', 'ghp_', '-----BEGIN ']],
    extractUrls: [extractUrls, ['http://', 'https://a', 'http://@']],
    extractEmails: [extractEmails, ['a@', '@b.', 'a.@b-']],
    extractMarkdownLinks: [extractMarkdownLinks, ['](http://', '![', '[](https://']],
    findCardNumbers: [findCardNumbers, ['4242 ', '1-', '9']],
    findSsns: [findSsns, ['123-45-', '1-2-3']],
    decodedVariants: [(t) => decodedVariants(t, { depth: 3, minRun: 12 }), ['QUFB', '%25', '41', 'QUFBQUFBQUFBQUFB ']],
    splitUntrustedSegments: [splitUntrustedSegments, ['----- BEGIN A -----\n', '[BEGIN A]\n', '<INFORMATION>\n', `${'-'.repeat(199)}\n`]],
    findInjectionPhrases: [findInjectionPhrases, ['ignore previous ', 'aaaa']],
    findIbans: [findIbans, ['US13300000012121 ', 'US133000000121212121212121212121212']],
  };
  for (const [name, [fn, units]] of Object.entries(scanners)) {
    for (const u of units) {
      const s = u.repeat(Math.ceil(SCANNER_INPUT / u.length)).slice(0, SCANNER_INPUT);
      const runs = [];
      for (let r = 0; r < 3; r++) {
        const t = performance.now();
        fn(s);
        runs.push(performance.now() - t);
      }
      const ms = median(runs);
      assert.ok(ms < LAYER_BUDGET_MS, `${name}(${JSON.stringify(u)} x ${SCANNER_INPUT}) took ${ms.toFixed(1)} ms`);
    }
  }
});

test('honeytoken index stays O(1) per position with 50k canaries sharing the "sk-proj-" prefix', { timeout: 15000 }, () => {
  const det = createDetector({ logger: quietLogger(), bounds: { timeBudgetMs: 100000 } });
  for (let i = 0; i < 50000; i++) det.mintCanary(`s${i}`, 't', 'api_key');
  const s = 'sk-proj-'.repeat(Math.floor(SCANNER_INPUT / 8));
  const runs = [];
  for (let r = 0; r < 3; r++) {
    const t = performance.now();
    det.registry.scan(s);
    runs.push(performance.now() - t);
  }
  assert.ok(median(runs) < LAYER_BUDGET_MS, `registry.scan took ${median(runs).toFixed(1)} ms`);
});

test('runtime budget: adversarial turns at the FULL 2 MiB payload cap finish far inside the runtime fail-closed budget (default 4000 ms)', { timeout: 60000 }, () => {
  const det = detectorWithBigRegistry();
  const CAP = DEFAULT_BOUNDS.maxPayloadBytes;
  const worst = [];
  for (const [name, unit] of Object.entries(ADVERSARIAL)) {
    const s = unit.repeat(Math.ceil((CAP * 0.4) / unit.length)).slice(0, Math.floor(CAP * 0.4));
    const req = { messages: [{ role: 'user', content: 'process' }, { role: 'assistant', tool_calls: [{ id: 'h', type: 'function', function: { name: 'web_fetch', arguments: '{}' } }] }, { role: 'tool', tool_call_id: 'h', content: s }] };
    const res = { choices: [{ message: { role: 'assistant', content: 'ok', tool_calls: [{ id: 'c', type: 'function', function: { name: 'http_post', arguments: JSON.stringify({ url: 'http://x.test/a', body: s }) } }] } }] };
    const d = det.inspect({ sessionId: `cap-${name}`, request: req, response: res });
    if (d.failClosed) assert.equal(d.error.bound, 'maxPayloadBytes', `${name}: ${JSON.stringify(d.error)}`);
    worst.push([name, d.stats.latencyMs]);
    assert.ok(d.stats.latencyMs < DEFAULT_BOUNDS.timeBudgetMs / 4, `${name}: ${d.stats.latencyMs} ms at the 2 MiB cap`);
  }
  console.log(`# adversarial @ ${CAP} B cap (runtime budget ${DEFAULT_BOUNDS.timeBudgetMs} ms): ${worst.map(([n, ms]) => `${n}=${ms}`).join(' ')}`);
});
