#!/usr/bin/env node
// fill-submission-metrics.mjs — fill the <<METRIC:...>> placeholders in SUBMISSION.md from the T7
// scoring output (sentinel/scoring/results.json). Deterministic: same results.json in, same text out.
//
// Usage:
//   node scripts/fill-submission-metrics.mjs [--results PATH] [--in PATH] [--out PATH]
//                                            [--path-a auto|include|exclude] [--video URL | --video-pending]
//                                            [--check]
//
//   --results       results.json to read          (default: sentinel/scoring/results.json)
//   --in / --out    template and output            (default: SUBMISSION.md, written in place)
//   --path-a        keep or strip the <!-- PATH-A:BEGIN/END --> blocks. `auto` (the default) keeps them
//                   only if track3a/run-demo.mjs exists in this checkout, i.e. PR #62 is merged.
//   --video URL     fill <<VIDEO_URL>>. Without it the run FAILS unless --video-pending is given
//                   (the video is recorded last, so the 15:00 rescore uses --video-pending).
//   --check         compute and print everything, write nothing.
//
// FAIL-LOUD (exit 1, nothing written) when: results.json is missing/unparseable or has an unexpected
// schema; a metric is missing or non-finite; a placeholder names an unknown metric; the template has
// no placeholders left to fill (already filled; restore it with `git checkout SUBMISSION.md`); the
// recomputed T3 lens counts disagree with results.json's own headlineLenses; PATH-A markers are
// unbalanced; or ANY <<...>> placeholder is still present after filling.
//
// Metrics are recomputed from the FULL perCase arrays (no sampling, no caps), the same way the harness
// and sentinel/scoring/RESULTS.md compute them.

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const EXPECTED_SCHEMA = /^sentinel\.scoring\/1\./;

function die(msg) {
  console.error(`fill-submission-metrics: FAIL: ${msg}`);
  process.exit(1);
}

function parseArgs(argv) {
  const o = { results: 'sentinel/scoring/results.json', in: 'SUBMISSION.md', out: null, pathA: 'auto', video: null, videoPending: false, check: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const val = () => (i + 1 < argv.length ? argv[++i] : die(`${a} needs a value`));
    if (a === '--results') o.results = val();
    else if (a === '--in') o.in = val();
    else if (a === '--out') o.out = val();
    else if (a === '--path-a') o.pathA = val();
    else if (a === '--video') o.video = val();
    else if (a === '--video-pending') o.videoPending = true;
    else if (a === '--check') o.check = true;
    else if (a === '-h' || a === '--help') { console.log(readFileSync(fileURLToPath(import.meta.url), 'utf8').split('\n').slice(1, 23).map((l) => l.replace(/^\/\/ ?/, '')).join('\n')); process.exit(0); }
    else die(`unknown argument: ${a}`);
  }
  if (!['auto', 'include', 'exclude'].includes(o.pathA)) die(`--path-a must be auto|include|exclude, got ${o.pathA}`);
  if (o.video !== null && !/^https?:\/\/\S+$/.test(o.video)) die(`--video must be an http(s) URL, got ${o.video}`);
  o.out ??= o.in;
  return o;
}

const pct = (x) => `${(x * 100).toFixed(1)}%`;
const ms = (x) => `${x.toFixed(3)} ms`;

function need(value, name) {
  if (typeof value !== 'number' || !Number.isFinite(value)) die(`results.json: ${name} is missing or not a finite number (got ${JSON.stringify(value)})`);
  return value;
}

function confusion(perCase, pred, name) {
  if (!Array.isArray(perCase) || perCase.length === 0) die(`results.json: ${name}.perCase is missing or empty`);
  let tp = 0, fp = 0, tn = 0, fn = 0;
  for (const c of perCase) {
    if (c.groundTruth !== 'positive' && c.groundTruth !== 'negative') die(`results.json: ${name} case ${c.id} has groundTruth ${JSON.stringify(c.groundTruth)}`);
    const p = pred(c);
    if (typeof p !== 'boolean') die(`results.json: ${name} case ${c.id} lacks a boolean prediction field`);
    if (c.groundTruth === 'positive') p ? tp++ : fn++; else p ? fp++ : tn++;
  }
  const div = (a, b, what) => (b === 0 ? die(`${name}: ${what} has a zero denominator`) : a / b);
  return { tp, fp, tn, fn, recall: div(tp, tp + fn, 'recall'), precision: div(tp, tp + fp, 'precision'), fpr: div(fp, fp + tn, 'benign FP rate') };
}

function cmpWord(a, b) {
  if (Math.abs(a - b) < 1e-9) return 'equal to';
  return a > b ? 'above' : 'below';
}

function computeMetrics(r) {
  if (!EXPECTED_SCHEMA.test(String(r.schema))) die(`results.json: unexpected schema ${JSON.stringify(r.schema)} (want sentinel.scoring/1.x)`);
  if (need(r.errorCount, 'errorCount') !== 0) die(`results.json: errorCount is ${r.errorCount}; rescore before filling`);
  const t3 = r.detectors?.t3, base = r.detectors?.['dvaa-baseline'];
  if (!t3?.available) die('results.json: detectors.t3 is missing or unavailable');
  if (!base?.available) die('results.json: detectors.dvaa-baseline is missing or unavailable (no baseline to compare against)');
  if (base.provenance?.source !== 'dvaa-real') die(`results.json: baseline provenance is ${JSON.stringify(base.provenance?.source)}, not dvaa-real`);

  const t3Det = confusion(t3.perCase, (c) => c.detectedAny, 't3');
  const t3Prev = confusion(t3.perCase, (c) => c.preventedEnforce, 't3');
  const bDet = confusion(base.perCase, (c) => c.detectedAny, 'dvaa-baseline');
  const bPrev = confusion(base.perCase, (c) => c.preventedEnforce, 'dvaa-baseline');

  // Cross-check our recomputation against the harness's own headline lenses for t3.
  for (const [lens, mine] of [['detection', t3Det], ['prevention', t3Prev]]) {
    const theirs = r.headlineLenses?.[lens];
    if (!theirs) die(`results.json: headlineLenses.${lens} missing`);
    for (const k of ['tp', 'fp', 'tn', 'fn']) {
      if (theirs[k] !== mine[k]) die(`t3 ${lens}.${k}: recomputed ${mine[k]} but results.json says ${theirs[k]}`);
    }
  }

  const attack = need(r.counts?.attack, 'counts.attack'), benign = need(r.counts?.benign, 'counts.benign');
  if (attack !== t3Det.tp + t3Det.fn || benign !== t3Det.fp + t3Det.tn) die('results.json: counts.attack/benign disagree with t3.perCase');

  const eligible = r.beatsBaseline?.eligible;
  if (!Array.isArray(eligible) || eligible.length === 0) die('results.json: beatsBaseline.eligible (8KB evasion cases) missing or empty');
  const caught = (perCase, ids) => ids.filter((id) => {
    const c = perCase.find((x) => x.id === id);
    if (!c) die(`evasion case ${id} not found in perCase`);
    return c.detectedAny;
  }).length;

  const digest = String(r.corpus?.digest ?? '');
  if (!/^sha256:[0-9a-f]{64}$/.test(digest)) die(`results.json: corpus.digest malformed: ${digest}`);
  const t3Commit = String(t3.provenance?.commit ?? ''), dvaaCommit = String(base.provenance?.dvaaCommit ?? '');
  if (!/^[0-9a-f]{40}$/.test(t3Commit)) die(`results.json: detectors.t3.provenance.commit malformed: ${t3Commit}`);
  if (!/^[0-9a-f]{40}$/.test(dvaaCommit)) die(`results.json: dvaa-baseline.provenance.dvaaCommit malformed: ${dvaaCommit}`);
  const gen = new Date(r.generatedAt);
  if (Number.isNaN(gen.getTime())) die(`results.json: generatedAt unparseable: ${r.generatedAt}`);

  return {
    'meta.generatedAt': `${gen.toISOString().replace(/\.\d{3}Z$/, 'Z')}`,
    'meta.t3Commit': t3Commit.slice(0, 7),
    'meta.dvaaCommit': dvaaCommit.slice(0, 7),
    'corpus.total': String(need(r.corpus?.total, 'corpus.total')),
    'corpus.attack': String(attack),
    'corpus.benign': String(benign),
    'corpus.digest': `${digest.slice(0, 19)}…`,
    't3.detection.recall': pct(t3Det.recall),
    't3.prevention.recall': pct(t3Prev.recall),
    't3.detection.precision': pct(t3Det.precision),
    't3.benignFpRate': pct(t3Det.fpr),
    't3.fp': String(t3Det.fp),
    't3.latency.median': ms(need(t3.latencyMs?.median, 't3.latencyMs.median')),
    't3.latency.p95': ms(need(t3.latencyMs?.p95, 't3.latencyMs.p95')),
    'baseline.detection.recall': pct(bDet.recall),
    'baseline.prevention.recall': pct(bPrev.recall),
    'baseline.detection.precision': pct(bDet.precision),
    'baseline.benignFpRate': pct(bDet.fpr),
    'baseline.fp': String(bDet.fp),
    'baseline.latency.median': ms(need(base.latencyMs?.median, 'dvaa-baseline.latencyMs.median')),
    'baseline.latency.p95': ms(need(base.latencyMs?.p95, 'dvaa-baseline.latencyMs.p95')),
    'evasion.eligible': String(eligible.length),
    'evasion.t3Caught': String(caught(t3.perCase, eligible)),
    'evasion.baselineCaught': String(caught(base.perCase, eligible)),
    'cmp.detection': cmpWord(t3Det.recall, bDet.recall),
    'cmp.prevention': cmpWord(t3Prev.recall, bPrev.recall),
  };
}

function applyPathA(text, mode) {
  const begins = (text.match(/<!-- PATH-A:BEGIN -->/g) ?? []).length;
  const ends = (text.match(/<!-- PATH-A:END -->/g) ?? []).length;
  if (begins !== ends) die(`unbalanced PATH-A markers: ${begins} BEGIN vs ${ends} END`);
  const include = mode === 'include' || (mode === 'auto' && existsSync(resolve(REPO, 'track3a/run-demo.mjs')));
  const re = /<!-- PATH-A:BEGIN -->\n?([\s\S]*?)<!-- PATH-A:END -->\n?/g;
  let out = text.replace(re, (_, body) => (include ? body : ''));
  if (!include) out = out.replace(/\n{3,}/g, '\n\n'); // a stripped block leaves no double blank line
  if (/PATH-A:(BEGIN|END)/.test(out)) die('nested or malformed PATH-A markers');
  return { out, include, blocks: begins };
}

function main() {
  const o = parseArgs(process.argv.slice(2));
  const resultsPath = resolve(REPO, o.results), inPath = resolve(REPO, o.in), outPath = resolve(REPO, o.out);
  if (!existsSync(resultsPath)) die(`results file not found: ${resultsPath} (run scripts/eval.sh score / the T7 harness first)`);
  if (!existsSync(inPath)) die(`template not found: ${inPath}`);

  let results;
  try { results = JSON.parse(readFileSync(resultsPath, 'utf8')); } catch (e) { die(`cannot parse ${resultsPath}: ${e.message}`); }
  const metrics = computeMetrics(results);

  let text = readFileSync(inPath, 'utf8');
  const names = [...text.matchAll(/<<METRIC:([A-Za-z0-9_.]+)>>/g)].map((m) => m[1]);
  if (names.length === 0) die(`no <<METRIC:...>> placeholders in ${o.in}; already filled? restore with: git checkout ${o.in}`);
  const unknown = [...new Set(names.filter((n) => !(n in metrics)))];
  if (unknown.length) die(`unknown metric placeholder(s): ${unknown.join(', ')}`);
  text = text.replace(/<<METRIC:([A-Za-z0-9_.]+)>>/g, (_, n) => metrics[n]);

  const pa = applyPathA(text, o.pathA);
  text = pa.out;

  if (o.video) text = text.replaceAll('<<VIDEO_URL>>', o.video);

  const leftover = [...new Set([...text.matchAll(/<<[^<>\n]+>>/g)].map((m) => m[0]))];
  const blocking = leftover.filter((p) => !(p === '<<VIDEO_URL>>' && o.videoPending));
  if (blocking.length) die(`unfilled placeholder(s) remain: ${blocking.join(', ')}${blocking.includes('<<VIDEO_URL>>') ? ' (pass --video URL, or --video-pending before the video exists)' : ''}`);

  console.log(`filled ${names.length} placeholders (${new Set(names).size} distinct) from ${o.results}`);
  for (const k of Object.keys(metrics).sort()) console.log(`  ${k.padEnd(28)} ${metrics[k]}`);
  console.log(`Path A blocks: ${pa.blocks} → ${pa.include ? 'INCLUDED' : 'STRIPPED'} (--path-a ${o.pathA})`);
  if (leftover.includes('<<VIDEO_URL>>')) console.log('WARN: <<VIDEO_URL>> left pending (--video-pending). Fill it before submitting.');

  if (o.check) { console.log('--check: nothing written'); return; }
  writeFileSync(outPath, text);
  console.log(`wrote ${o.out}`);
}

main();
