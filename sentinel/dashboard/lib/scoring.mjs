// Headline metrics from T7's sentinel/scoring/results.json (override: $SENTINEL_SCORING_FILE).
//
// Two results.json shapes are read:
//   * lens shape (T7 PR #28, t7-real-metrics): `detectionRecall` (any finding fired, alert-only included)
//     and `preventionRecall` (only pre-forward `prevents:true`), plus `headlineLenses.{detection,prevention}`.
//     The DVAA baseline for each lens is read from detectors['dvaa-baseline'].modes[<headline.mode>]:
//     `anyFinding` for detection and `prevention` for prevention. These are the same rows T7's own
//     RESULTS.md report uses.
//   * legacy shape (T7 before PR #28): only `detectionRate | recall`, which is the rule-intent BLOCK lens.
//     `lensSource: 'legacy'`; detectionRecall and preventionRecall are null (the legacy recall is NOT a
//     detection rate and is never presented as one); the UI shows "n/a" with a visible note.
// Other fields: falsePositiveRate | fpRate, precision, latencyMs {median, p95} | medianLatencyMs/p95LatencyMs,
// counts, headline.status ("ok" | "awaiting t3: …" | "error: …"; any non-ok status replaces the numbers).
// When the file is absent the slot reads "awaiting T7". Nothing here invents a rate: a field that is not
// a finite number in results.json stays null.

import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { REPO_ROOT } from './capture-loader.mjs';
import { BOUNDS } from './bounds.mjs';

const num = (x) => (typeof x === 'number' && Number.isFinite(x) ? x : null);
const first = (...v) => v.map(num).find(x => x !== null) ?? null;

/** DVAA baseline numbers for the lenses actually shown. All null when the baseline is absent. */
export function baselineFrom(raw, lensSource) {
  const base = raw?.detectors?.['dvaa-baseline'];
  const mode = typeof raw?.headline?.mode === 'string' ? raw.headline.mode : 'enforce';
  const metric = typeof raw?.headline?.metric === 'string' ? raw.headline.metric : 'blocking';
  const m = base?.available === false ? null : base?.modes?.[mode];
  if (!m) return { available: false, detection: null, prevention: null, fpRate: null, fpDetection: null, fpPrevention: null, latencyMedianMs: null, mode, metric };
  const legacy = lensSource === 'legacy';
  return {
    available: true,
    mode,
    metric,
    detection: legacy ? first(m[metric]?.recall) : first(m.anyFinding?.recall),
    prevention: legacy ? null : first(m.prevention?.recall),
    // Same metric as the candidate's headline falsePositiveRate.
    fpRate: first(m[metric]?.falsePositiveRate),
    // Per-lens FP, so each headline tile compares like with like.
    fpDetection: legacy ? null : first(m.anyFinding?.falsePositiveRate),
    fpPrevention: legacy ? null : first(m.prevention?.falsePositiveRate),
    latencyMedianMs: first(base?.latencyMs?.median),
  };
}

export async function loadScoring(index, env = process.env) {
  const file = env.SENTINEL_SCORING_FILE || path.join(REPO_ROOT, 'sentinel', 'scoring', 'results.json');
  const rel = path.relative(REPO_ROOT, file);
  const corpus = { attack: 0, benign: 0, placeholder: 0 };
  for (const e of index.values()) {
    if (e.source === 'placeholder') corpus.placeholder++;
    else if (e.expected === 'benign' || (!e.expected && /^benign\//.test(e.id))) corpus.benign++;
    else corpus.attack++;
  }
  let raw;
  try {
    const { size } = await stat(file);
    if (size > BOUNDS.MAX_SCORING_BYTES) {
      const msg = `MAX_SCORING_BYTES exceeded: size=${size} cap=${BOUNDS.MAX_SCORING_BYTES} — refusing to truncate`;
      console.error(`[sentinel-dashboard] ALERT ${rel}: ${msg}`);
      return { available: false, error: `${rel}: ${msg}`, corpus };
    }
    raw = JSON.parse(await readFile(file, 'utf8'));
  } catch (err) {
    if (err.code === 'ENOENT') return { available: false, file: rel, corpus };
    // Present but unreadable: say so loudly, don't fall back to "awaiting".
    return { available: false, error: `${rel}: ${err.message}`, corpus };
  }
  const legacyRecall = first(raw.detectionRate, raw.recall);
  const lensDetection = first(raw.detectionRecall, raw.headlineLenses?.detection?.recall);
  const lensPrevention = first(raw.preventionRecall, raw.headlineLenses?.prevention?.recall);
  const hasLens = lensDetection !== null || lensPrevention !== null;
  const lensSource = hasLens ? 'lenses' : 'legacy';
  return {
    available: true,
    file: rel,
    corpus,
    lensSource,
    detectionRecall: hasLens ? lensDetection : null,
    preventionRecall: hasLens ? lensPrevention : null,
    // Legacy `recall` (rule-intent blocking) is kept so the note can name it; it is not a tile in lens mode.
    legacyRecall,
    // Back-compat alias for older callers.
    detectionRate: legacyRecall,
    fpRate: first(raw.falsePositiveRate, raw.fpRate),
    // Each lens's own benign FP rate (headlineLenses.<lens>.falsePositiveRate). Not filled from the
    // top-level falsePositiveRate, which belongs to the legacy blocking lens.
    lensFp: { detection: first(raw.headlineLenses?.detection?.falsePositiveRate), prevention: first(raw.headlineLenses?.prevention?.falsePositiveRate) },
    precision: first(raw.precision),
    latencyMs: { median: first(raw.latencyMs?.median, raw.medianLatencyMs), p95: first(raw.latencyMs?.p95, raw.p95LatencyMs) },
    counts: raw.counts ?? null,
    baseline: baselineFrom(raw, lensSource),
    // T7 `headline.status` ("ok" | "awaiting t3: …" | "error: …"). The UI shows it instead of numbers.
    status: typeof raw.headline?.status === 'string' ? raw.headline.status : null,
  };
}
