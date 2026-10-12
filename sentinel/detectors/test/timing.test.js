// Adversarial timing (ReDoS) tests AT the maximum payload size (PR #3 review: an unbounded `{8,}` JWT regex
// took 14 s on 256K chars of repeated "eyJ"). Each detector layer must stay under LAYER_BUDGET_MS and the
// whole inspection under the fail-closed time budget, for crafted inputs aimed at every scanner.
// Median of 3 runs per case to keep CI noise out without hiding a quadratic blow-up (which is 100-1000x).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { createDetector, DVAA_HONEYTOKENS, DEFAULT_BOUNDS } from '../index.js';
import { findIbans, findSpacedRuns, foldConfusables, findSecretShapes, extractUrls, extractEmails, extractMarkdownLinks, findCardNumbers, findSsns, decodedVariants, splitUntrustedSegments, findInjectionPhrases, stripInvisible } from '../src/text.js';
import { quietLogger } from './helpers.js';

const LAYER_BUDGET_MS = 50;
// TWO DIFFERENT NUMBERS (review of PR #27):
//   TOTAL_BUDGET_MS = 40  PERFORMANCE bound: a whole inspection of a 384 KiB adversarial turn (PERF_INPUT, ~16x
//                         the ~23 KB demo payloads) must take < 40 ms of CPU (median of 5). A speed target that
//                         catches quadratic regressions; it is NOT a reason to block traffic.
//   DEFAULT_BOUNDS.timeBudgetMs (runtime, 4000 ms) the fail-closed budget, derived from the proxy's real
//                         inspectorTimeoutMs (5000 ms -> 80%) + its abort signal (bounds.js, inspector.js, review
//                         B3). Asserted separately below on payloads at the full 2 MiB cap.
const TOTAL_BUDGET_MS = 40;
const PERF_INPUT = 384 * 1024;
// The 40 ms bound is asserted on CPU time (user+system delta, see cpuUsage below), not wall clock: the merge
// gate runs ~13 agents in parallel (load ~10), and wall clock then measures the scheduler, not the
// detector. A quadratic regression is 100x+ in CPU time too, so the bound stays strict. A generous
// wall-clock ceiling still catches a real hang (sleep / blocking wait / lost wakeup).
const WALL_CEILING_MS = 1000; // hang guard only (median of 5); the performance bound is the CPU one above
const RUNS = 5;
// CPU of THIS thread (process.threadCpuUsage, Node >= 22.19): process.cpuUsage() is process-wide and
// also bills V8's parallel GC helper threads, which can exceed wall time (measured 39 ms CPU vs 35 ms wall
// on base64_tokens). Falls back to process.cpuUsage() on older Node.
const cpuUsage = typeof process.threadCpuUsage === 'function' ? (prev) => process.threadCpuUsage(prev) : (prev) => process.cpuUsage(prev);
/** CPU ms (user + system) and wall ms spent in fn(). */
function measure(fn) {
  const c0 = cpuUsage();
  const w0 = performance.now();
  const out = fn();
  const wall = performance.now() - w0;
  const c = cpuUsage(c0);
  return { out, cpu: (c.user + c.system) / 1000, wall };
}
/** CPU ms of fn() (median of `runs` is taken by the caller). */
const cpuOf = (fn) => measure(fn).cpu;
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
  zero_width: 'ign\u200Bore\u2060 ',
  tag_chars: '\u{E0069}\u{E0067}\u{E006E}\u200B',
  // #112: one 170K-element spaced run, re-joined into two variants and re-scanned by every extractor
  spaced_singles: 'a ',
  spaced_iban: 'U S 1 3 0 0 ',
  spaced_email: 'a @ b . c . ',
  spaced_zw: 'k\u200b-\u200b',
  homoglyph_words: 'a\u0430e\u0435 ',
  fullwidth: '\uff53\uff45 ',
  // #122 review: O(#runs x #destinations) regression guards
  urls_and_runs: (i) => `ignore previous instructions. http://h${i}.com a b c d e f xx `,
  urls_then_runs: (i) => (i < 6000 ? `http://u${i}.com ` : 'a b c d e f xx '),
  distinct_spaced_hosts: (i) => `x ${i.toString(36).split('').join(' ')} . c o m yy `,
};
const fill = (u, len = Math.floor(MAX * 0.45)) => {
  if (typeof u !== 'function') return u.repeat(Math.ceil(len / u.length)).slice(0, len);
  // counter-driven unit (#122 review): many short runs, each next to a DISTINCT destination
  const parts = [];
  let n = 0;
  for (let i = 0; n < len; i++) (parts.push(u(i)), (n += parts[parts.length - 1].length));
  return parts.join('').slice(0, len);
};

function detectorWithBigRegistry() {
  const det = createDetector({ honeytokens: DVAA_HONEYTOKENS, logger: quietLogger(), bounds: { timeBudgetMs: 100000 } }); // measure, don't fail closed
  for (let i = 0; i < 20000; i++) det.mintCanary(`s${i % 64}`, 'web_fetch', i % 3 === 0 ? 'aws_key' : 'api_key');
  return det;
}

const median = (xs) => [...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)];

test('whole inspection < 40 ms CPU (performance bound; wall-clock hang ceiling 1000 ms; every layer < 50 ms) on adversarial 384 KiB inputs (20k canaries)', { timeout: 60000 }, () => {
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
    const walls = [];
    for (let r = 0; r < RUNS; r++) {
      const { out: d, cpu, wall } = measure(() => det.inspect({ sessionId: `adv-${name}-${r}`, request: req, response: res }));
      assert.equal(d.failClosed, false, `${name}: ${JSON.stringify(d.error)}`);
      totals.push(Math.round(cpu * 1000) / 1000);
      walls.push(Math.round(wall * 1000) / 1000);
      // Per-layer latency is wall clock inside the detector. Scale it by this run's CPU/wall ratio (<= 1) to
      // estimate the layer's CPU share (flake fix: a 57 ms layer against the 50 ms bound under merge-gate load
      // was the scheduler, not the scanner). An unloaded run has ratio ~1, so the bound is unchanged there,
      // and a 10x layer regression is 10x in CPU as well.
      const ratio = wall > 0 ? Math.min(1, cpu / wall) : 1;
      for (const l of d.stats.layers) (layerRuns[l.layer] ??= []).push(Math.round(l.latencyMs * ratio * 1000) / 1000);
    }
    const layers = Object.fromEntries(Object.entries(layerRuns).map(([k, v]) => [k, median(v)]));
    report.push({ name, total: median(totals), wall: median(walls), ...layers });
    for (const [layer, ms] of Object.entries(layers)) assert.ok(ms < LAYER_BUDGET_MS, `${name}: layer ${layer} took ~${ms} ms CPU (wall x CPU/wall)`);
    assert.ok(median(totals) < TOTAL_BUDGET_MS, `${name}: total CPU ${median(totals)} ms >= ${TOTAL_BUDGET_MS} ms budget`);
    assert.ok(median(walls) < WALL_CEILING_MS, `${name}: wall clock ${median(walls)} ms >= ${WALL_CEILING_MS} ms ceiling (hang?)`);
  }
  console.log(`# adversarial timing @ ${MAX} B perf input (median of ${RUNS}; total = CPU ms, wall = wall-clock ms):`);
  for (const r of report) console.log(`#   ${r.name.padEnd(15)} total=${r.total} wall=${r.wall} ${Object.entries(r).filter(([k]) => !['name', 'total', 'wall'].includes(k)).map(([k, v]) => `${k}=${v}`).join(' ')}`);
});

test('every text scanner alone is linear: < 50 ms CPU (median of 3) at the payload cap on its own worst-case input', { timeout: 15000 }, () => {
  const scanners = {
    findSecretShapes: [findSecretShapes, ['eyJ', 'eyJab.', 'sk-', 'AKIA', 'ghp_', '-----BEGIN ']],
    extractUrls: [extractUrls, ['http://', 'https://a', 'http://@']],
    extractEmails: [extractEmails, ['a@', '@b.', 'a.@b-']],
    extractMarkdownLinks: [extractMarkdownLinks, ['](http://', '![', '[](https://']],
    findCardNumbers: [findCardNumbers, ['4242 ', '1-', '9']],
    findSsns: [findSsns, ['123-45-', '1-2-3']],
    decodedVariants: [(t) => decodedVariants(t, { depth: 3, minRun: 12 }), ['QUFB', '%25', '41', 'QUFBQUFBQUFBQUFB ']],
    splitUntrustedSegments: [splitUntrustedSegments, ['----- BEGIN A -----\n', '[BEGIN A]\n', '<INFORMATION>\n', `${'-'.repeat(199)}\n`]],
    findInjectionPhrases: [findInjectionPhrases, ['ignore previous ', 'aaaa', 'ign\u200Bore ', '\u{E0069}\u{E0067}\u200B']],
    stripInvisible: [stripInvisible, ['\u200B', 'a\u200B', '\u{E0041}', '\uDB40a', '\u202Eab\u2066']],
    findIbans: [findIbans, ['US13300000012121 ', 'US133000000121212121212121212121212']],
    foldConfusables: [foldConfusables, ['a\u0430 ', '\u0430', '\uff53', '\u{E0041}', 'a\u200B']],
    findSpacedRuns: [findSpacedRuns, ['a ', 'a . ', 'a - b ', 'a   b    ', 'ab a ']],
  };
  for (const [name, [fn, units]] of Object.entries(scanners)) {
    for (const u of units) {
      const s = u.repeat(Math.ceil(SCANNER_INPUT / u.length)).slice(0, SCANNER_INPUT);
      const runs = [];
      for (let r = 0; r < 3; r++) runs.push(cpuOf(() => fn(s)));
      const ms = median(runs);
      assert.ok(ms < LAYER_BUDGET_MS, `${name}(${JSON.stringify(u)} x ${SCANNER_INPUT}) took ${ms.toFixed(1)} ms CPU`);
    }
  }
});

test('honeytoken index stays O(1) per position with 50k canaries sharing the "sk-proj-" prefix', { timeout: 15000 }, () => {
  const det = createDetector({ logger: quietLogger(), bounds: { timeBudgetMs: 100000 } });
  for (let i = 0; i < 50000; i++) det.mintCanary(`s${i}`, 't', 'api_key');
  const s = 'sk-proj-'.repeat(Math.floor(SCANNER_INPUT / 8));
  const runs = [];
  for (let r = 0; r < 3; r++) runs.push(cpuOf(() => det.registry.scan(s)));
  assert.ok(median(runs) < LAYER_BUDGET_MS, `registry.scan took ${median(runs).toFixed(1)} ms CPU`);
});

test('runtime budget: adversarial turns at the FULL 2 MiB payload cap finish far inside the runtime fail-closed budget (default 4000 ms)', { timeout: 60000 }, () => {
  const det = detectorWithBigRegistry();
  const CAP = DEFAULT_BOUNDS.maxPayloadBytes;
  const worst = [];
  for (const [name, unit] of Object.entries(ADVERSARIAL)) {
    const s = fill(unit, Math.floor(CAP * 0.4));
    const req = { messages: [{ role: 'user', content: 'process' }, { role: 'assistant', tool_calls: [{ id: 'h', type: 'function', function: { name: 'web_fetch', arguments: '{}' } }] }, { role: 'tool', tool_call_id: 'h', content: s }] };
    const res = { choices: [{ message: { role: 'assistant', content: 'ok', tool_calls: [{ id: 'c', type: 'function', function: { name: 'http_post', arguments: JSON.stringify({ url: 'http://x.test/a', body: s }) } }] } }] };
    const { out: d, cpu } = measure(() => det.inspect({ sessionId: `cap-${name}`, request: req, response: res }));
    if (d.failClosed) assert.equal(d.error.bound, 'maxPayloadBytes', `${name}: ${JSON.stringify(d.error)}`);
    worst.push([name, Math.round(cpu * 10) / 10]);
    // CPU ms (flake fix), 4x headroom under the wall-clock runtime budget: load inflates wall time, not work.
    assert.ok(cpu < DEFAULT_BOUNDS.timeBudgetMs / 4, `${name}: ${cpu.toFixed(1)} ms CPU at the 2 MiB cap`);
  }
  console.log(`# adversarial @ ${CAP} B cap (runtime budget ${DEFAULT_BOUNDS.timeBudgetMs} ms; CPU ms): ${worst.map(([n, ms]) => `${n}=${ms}`).join(' ')}`);
});
