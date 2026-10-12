// Headline pair: detection rate beside benign-run FP rate (T7). T7 has no output yet, so this reads
// sentinel/scoring/results.json (override: $SENTINEL_SCORING_FILE) when present. Accepted fields
// (first match wins):
//   detectionRate | recall,  falsePositiveRate | fpRate,  precision,
//   latencyMs: {median, p95} | medianLatencyMs/p95LatencyMs,  counts: {attack, benign, fp, fn}
// When the file is absent the dashboard shows the slot as "awaiting T7". It does NOT invent rates.
// It reports only the real corpus composition (attack vs benign captures found).

import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { REPO_ROOT } from './capture-loader.mjs';

const first = (...v) => v.find(x => Number.isFinite(x)) ?? null;

export async function loadScoring(index, env = process.env) {
  const file = env.SENTINEL_SCORING_FILE || path.join(REPO_ROOT, 'sentinel', 'scoring', 'results.json');
  const corpus = { attack: 0, benign: 0, placeholder: 0 };
  for (const e of index.values()) {
    if (e.source === 'placeholder') corpus.placeholder++;
    else if (/^benign\//.test(e.id)) corpus.benign++;
    else corpus.attack++;
  }
  let raw;
  try {
    raw = JSON.parse(await readFile(file, 'utf8'));
  } catch (err) {
    if (err.code === 'ENOENT') return { available: false, file: path.relative(REPO_ROOT, file), corpus };
    // Present but unreadable: say so loudly, don't fall back to "awaiting".
    return { available: false, error: `${path.relative(REPO_ROOT, file)}: ${err.message}`, corpus };
  }
  return {
    available: true,
    file: path.relative(REPO_ROOT, file),
    corpus,
    detectionRate: first(raw.detectionRate, raw.recall),
    fpRate: first(raw.falsePositiveRate, raw.fpRate),
    precision: first(raw.precision),
    latencyMs: { median: first(raw.latencyMs?.median, raw.medianLatencyMs), p95: first(raw.latencyMs?.p95, raw.p95LatencyMs) },
    counts: raw.counts ?? null,
  };
}
