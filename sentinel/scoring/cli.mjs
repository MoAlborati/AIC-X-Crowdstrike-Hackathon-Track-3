#!/usr/bin/env node
// T7 scoring CLI — headless, reads only captures/ (+ an optional decision log), writes results.json + RESULTS.md.
//
//   node sentinel/scoring/cli.mjs [--iterations N] [--out FILE] [--md FILE] [--no-write]
//        [--allow-replica] [--detector-module FILE.mjs]... [--headline NAME]
//        [--decision-log FILE.jsonl] [--rule-mode RULE=report-only]...
//
// Exit codes: 0 scored cleanly; 1 detector errors (headline withheld), label warnings or DVAA pin drift
// (results are still written, with the reason in headline.status / warnings); 2 bound/corpus error (nothing written).

import { writeFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { REPO_ROOT } from './src/corpus.mjs';
import { builtinDetectors, moduleDetector } from './src/detectors.mjs';
import { runScoring, exitCode } from './src/harness.mjs';
import { renderMarkdown } from './src/report.mjs';

const { values: a } = parseArgs({
  options: {
    iterations: { type: 'string', default: '5' },
    out: { type: 'string', default: path.join(REPO_ROOT, 'sentinel', 'scoring', 'results.json') },
    md: { type: 'string', default: path.join(REPO_ROOT, 'sentinel', 'scoring', 'RESULTS.md') },
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
  const iterations = Number(a.iterations);
  if (!Number.isInteger(iterations)) throw new Error('--iterations must be an integer');
  const detectors = await builtinDetectors({ root: a.root, allowReplica: a['allow-replica'] });
  for (const f of a['detector-module']) detectors.push(await moduleDetector(f));
  const defaultLog = path.join(a.root, 'sentinel', 'scoring', 'decisions.jsonl');
  const decisionLog = a['decision-log'] ?? (existsSync(defaultLog) ? defaultLog : null);

  const results = runScoring({ detectors, root: a.root, iterations, ruleModes, decisionLog, headline: a.headline });
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
