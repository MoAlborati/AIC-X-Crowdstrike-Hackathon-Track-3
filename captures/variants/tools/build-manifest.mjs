/**
 * Build manifest.json — the single labeled index T7's scoring harness loads.
 * Scans fixtures/ and emits one row per case. Deterministic (sorted).
 * Usage: node captures/variants/tools/build-manifest.mjs
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const FIX = path.join(ROOT, 'fixtures');

const rows = [];
for (const group of fs.readdirSync(FIX).sort()) {
  const d = path.join(FIX, group);
  if (!fs.statSync(d).isDirectory()) continue;
  for (const f of fs.readdirSync(d).sort()) {
    if (!f.endsWith('.json')) continue;
    const doc = JSON.parse(fs.readFileSync(path.join(d, f), 'utf8'));
    rows.push({
      id: doc.id,
      path: `fixtures/${group}/${f}`,
      group,
      scenario: doc.scenario,
      benchmark: doc.source?.benchmark ?? null,
      license: doc.source?.license ?? null,
      channel: doc.channel ?? null,
      groundTruth: doc.label.groundTruth,
      expectedVerdict: doc.label.expectedVerdict,
      category: doc.label.category,
      exfilTargetUrl: doc.label.dvaa?.exfilTargetUrl ?? null,
      evadesBaseline: doc.baseline8kb?.evadesBaseline ?? null,
    });
  }
}
rows.sort((a, b) => a.path.localeCompare(b.path));

const manifest = {
  ticket: 'T6',
  description: 'Labeled evaluation corpus for the SentinelProxy detector (T3) and scoring harness (T7).',
  schema: 'captures/variants/README.md#fixture-schema',
  counts: {
    total: rows.length,
    positive: rows.filter((r) => r.groundTruth === 'positive').length,
    negative: rows.filter((r) => r.groundTruth === 'negative').length,
    evasionMiddle: rows.filter((r) => r.evadesBaseline === true).length,
  },
  cases: rows,
};
fs.writeFileSync(path.join(ROOT, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
console.log(`manifest.json: ${rows.length} cases (` +
  `${manifest.counts.positive} pos / ${manifest.counts.negative} neg / ` +
  `${manifest.counts.evasionMiddle} baseline-evading)`);
