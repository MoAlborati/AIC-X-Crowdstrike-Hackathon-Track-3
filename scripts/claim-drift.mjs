#!/usr/bin/env node
// claim-drift.mjs — fail when a T3/DVAA detection, prevention or FP percentage quoted in the pitch docs does not
// match sentinel/scoring/results.json (overseer recommendation #1, issue #110).
//
// Usage: node scripts/claim-drift.mjs [--repo DIR] [--results FILE] [doc ...]
//   default docs: README.md SUBMISSION.md demo/QA-PREP.md demo/DECK.md
//   exit 0 = every in-scope percentage matches results.json; 1 = drift (each offending line printed); 2 = usage/IO
//
// Rules:
//   * In scope: a percentage ("41.8%", "0%") on a line that talks about detection, prevention, recall, blocking,
//     precision or false positives (FP). Other percentages are ignored.
//   * Allowed values: every recall / precision / falsePositiveRate in results.json for the T3 headline lenses and
//     for the t3 and dvaa-baseline detectors (all modes and lenses, plus recall by positive kind). A quoted number
//     matches when it equals value*100 at the precision it is written with (41.8% ~ 0.418, 63% ~ 0.6296).
//   * Held-out allowlist: numbers from a different evaluation set are fine when they are clearly labelled. Inside a
//     paragraph, every percentage AFTER the first "held-out"/"holdout" label is skipped; ones before it are checked.
//   * Unfilled `<<METRIC...>>` placeholders are fine; they are removed before scanning.
//   * Third-party vendor figures are not T3/DVAA claims: a line naming AIDR / Falcon / CrowdStrike is skipped.
//   * A line containing `claim-drift: ignore` is skipped (escape hatch; use sparingly).
import { readFileSync } from 'node:fs';
import { resolve, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

export const DEFAULT_DOCS = ['README.md', 'SUBMISSION.md', 'demo/QA-PREP.md', 'demo/DECK.md'];
const SCOPE_RE = /detect|prevent|recall|block|precision|false[- ]positive|\bFPs?\b/i;
const HELDOUT_RE = /held[- ]?out|holdout/i;
const PCT_RE = /(\d+(?:\.\d+)?)\s?%/g;
const IGNORE_RE = /claim-drift:\s*ignore|\bAIDR\b|\bFalcon\b|CrowdStrike/i;
const METRIC_RE = /<<METRIC[^>]*>>/g;

/** Every rate in results.json that a doc may quote, as fractions in [0,1]. */
export function allowedRates(results) {
  const out = new Set();
  const take = (o) => {
    if (!o || typeof o !== 'object') return;
    for (const k of ['recall', 'precision', 'falsePositiveRate']) if (typeof o[k] === 'number') out.add(o[k]);
  };
  for (const k of ['detectionRate', 'recall', 'precision', 'falsePositiveRate', 'detectionRecall', 'preventionRecall']) {
    if (typeof results[k] === 'number') out.add(results[k]);
  }
  for (const lens of Object.values(results.headlineLenses ?? {})) take(lens);
  for (const name of ['t3', 'dvaa-baseline']) {
    const d = results.detectors?.[name];
    if (!d) continue;
    take(d);
    for (const mode of Object.values(d.modes ?? {})) for (const lens of Object.values(mode ?? {})) take(lens);
    for (const [k, v] of Object.entries(d)) {
      if (k.startsWith('recallByPositiveKind')) for (const kind of Object.values(v ?? {})) take(kind);
    }
  }
  return [...out];
}

/** Does the quoted text (e.g. "41.8" or "63") equal rate*100 at the precision it is written with? */
export function matches(text, rate) {
  const decimals = text.includes('.') ? text.split('.')[1].length : 0;
  return (rate * 100).toFixed(decimals) === Number(text).toFixed(decimals);
}

/** Split markdown into paragraphs (blank line or new list item / heading starts one), keeping line numbers. */
function paragraphs(lines) {
  const paras = [];
  let cur = [];
  const flush = () => { if (cur.length) paras.push(cur); cur = []; };
  lines.forEach((text, i) => {
    if (!text.trim()) { flush(); return; }
    if (/^\s*([-*+]|\d+\.|#{1,6}|\|)\s/.test(text) || /^\s*\*\*\d+\./.test(text)) flush();
    cur.push({ n: i + 1, text });
  });
  flush();
  return paras;
}

/** Returns [{file, line, pct, text}] for every in-scope percentage that matches no results.json rate. */
export function checkDoc(file, content, rates) {
  const drift = [];
  for (const para of paragraphs(content.split('\n'))) {
    let heldOut = false;
    for (const { n, text } of para) {
      if (IGNORE_RE.test(text)) continue;
      const clean = text.replace(METRIC_RE, '');
      const heldIdx = heldOut ? 0 : clean.search(HELDOUT_RE);
      const inScope = SCOPE_RE.test(clean) || (para.length > 1 && para.some((l) => SCOPE_RE.test(l.text)));
      for (const m of clean.matchAll(PCT_RE)) {
        if (heldIdx >= 0 && m.index >= heldIdx) continue;     // after a held-out label in this paragraph
        if (!inScope) continue;
        if (!rates.some((r) => matches(m[1], r))) drift.push({ file, line: n, pct: `${m[1]}%`, text: text.trim() });
      }
      if (heldIdx >= 0) heldOut = true;
    }
  }
  return drift;
}

export function run({ repo, resultsPath, docs }) {
  const results = JSON.parse(readFileSync(resultsPath, 'utf8'));
  const rates = allowedRates(results);
  if (rates.length === 0) throw new Error(`no rates found in ${resultsPath}`);
  const drift = [];
  for (const doc of docs) {
    const p = resolve(repo, doc);
    let content;
    try { content = readFileSync(p, 'utf8'); } catch { continue; }   // a doc not on this branch is not drift
    drift.push(...checkDoc(relative(repo, p), content, rates));
  }
  return { drift, rates };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  let repo = resolve(fileURLToPath(import.meta.url), '../..');
  let resultsPath = null;
  const docs = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--repo') repo = resolve(args[++i]);
    else if (args[i] === '--results') resultsPath = resolve(args[++i]);
    else docs.push(args[i]);
  }
  resultsPath ??= resolve(repo, 'sentinel/scoring/results.json');
  try {
    const { drift, rates } = run({ repo, resultsPath, docs: docs.length ? docs : DEFAULT_DOCS });
    const allowed = rates.map((r) => `${(r * 100).toFixed(1)}%`).sort().join(' ');
    if (drift.length) {
      console.log(`claim drift: ${drift.length} quoted percentage(s) do not match ${relative(repo, resultsPath)}`);
      for (const d of drift) console.log(`  ${d.file}:${d.line}  ${d.pct}  | ${d.text.slice(0, 160)}`);
      console.log(`  allowed (from results.json): ${allowed}`);
      console.log('  fix: quote the number from results.json, label a different-set number "held-out", or use a <<METRIC:...>> slot');
      process.exit(1);
    }
    console.log(`claim drift: none (${(docs.length ? docs : DEFAULT_DOCS).join(', ')} vs ${relative(repo, resultsPath)})`);
  } catch (e) {
    console.error(`claim drift: ERROR ${e.message}`);
    process.exit(2);
  }
}
