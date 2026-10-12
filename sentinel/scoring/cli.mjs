#!/usr/bin/env node
// T7 scoring CLI — headless, reads only captures/ (+ an optional decision log), writes results.json + RESULTS.md.
//
//   node sentinel/scoring/cli.mjs [--iterations N] [--out FILE] [--md FILE] [--no-write]
//        [--allow-replica] [--detector-module FILE.mjs]... [--headline NAME]
//        [--decision-log FILE.jsonl] [--rule-mode RULE=report-only]... [--set main|holdout-hf]
//
// --set holdout-hf scores the T6c Hugging Face held-out set (captures/holdout-hf) ON ITS OWN and writes
// captures/holdout-hf/results.json + captures/holdout-hf/SCORING.md by default. It never touches the main
// results (sentinel/scoring/results.json), so held-out numbers are never merged into the headline.
//
// Exit codes: 0 scored cleanly; 1 detector errors (headline withheld), label warnings or DVAA pin drift
// (results are still written, with the reason in headline.status / warnings); 2 bound/corpus error (nothing written).

import { writeFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { REPO_ROOT, loadSet, SETS } from './src/corpus.mjs';
import { builtinDetectors, moduleDetector } from './src/detectors.mjs';
import { runScoring, exitCode } from './src/harness.mjs';
import { renderMarkdown } from './src/report.mjs';

const { values: a } = parseArgs({
  options: {
    iterations: { type: 'string', default: '5' },
    out: { type: 'string' },
    md: { type: 'string' },
    set: { type: 'string', default: 'main' },
    'no-write': { type: 'boolean', default: false },
    'allow-replica': { type: 'boolean', default: false },
    'detector-module': { type: 'string', multiple: true, default: [] },
    headline: { type: 'string', default: 't3' },
    'decision-log': { type: 'string' },
    'rule-mode': { type: 'string', multiple: true, default: [] },
    root: { type: 'string', default: REPO_ROOT },
  },
});

try {
  const ruleModes = Object.fromEntries(a['rule-mode'].map((s) => {
    const [rule, mode] = s.split('=');
    if (!rule || !['enforce', 'report-only'].includes(mode)) throw new Error(`--rule-mode ${s}: expected RULE=enforce|report-only`);
    return [rule, mode];
  }));
  if (!SETS.includes(a.set)) throw new Error(`--set ${a.set}: expected ${SETS.join('|')}`);
  const outDir = a.set === 'main' ? path.join(REPO_ROOT, 'sentinel', 'scoring') : path.join(a.root, 'captures', a.set);
  a.out ??= path.join(outDir, 'results.json');
  a.md ??= path.join(outDir, a.set === 'main' ? 'RESULTS.md' : 'SCORING.md');
  const iterations = Number(a.iterations);
  if (!Number.isInteger(iterations)) throw new Error('--iterations must be an integer');
  const detectors = await builtinDetectors({ root: a.root, allowReplica: a['allow-replica'] });
  for (const f of a['detector-module']) detectors.push(await moduleDetector(f));
  const defaultLog = path.join(a.root, 'sentinel', 'scoring', 'decisions.jsonl');
  const decisionLog = a['decision-log'] ?? (existsSync(defaultLog) ? defaultLog : null);

  const corpus = a.set === 'main' ? null : await loadSet(a.root, a.set);
  const results = runScoring({ detectors, root: a.root, iterations, ruleModes, decisionLog, headline: a.headline, corpus, set: a.set });
  const md = renderMarkdown(results);
  process.stdout.write(`${md}\n`);
  if (!a['no-write']) {
    writeFileSync(a.out, `${JSON.stringify(results, null, 2)}\n`);
    writeFileSync(a.md, `${md}\n`);
    console.error(`wrote ${path.relative(process.cwd(), a.out)} and ${path.relative(process.cwd(), a.md)}`);
  }
  process.exit(exitCode(results));
} catch (err) {
  console.error(JSON.stringify({ level: 'ERROR', event: 'sentinel.scoring.failed', error: err.name, message: err.message, ...(err.toJSON?.() ?? {}) }));
  process.exit(2);
}
