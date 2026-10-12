// T7 scoring harness: replay every labeled case through every available detector, compare verdicts with
// the ground-truth labels, and build the results object (sentinel/scoring/results.json, read by T5).
//
// Modes (per-rule policy, BACKLOG T7):
//   enforce      — a fired rule that would block DOES block (unless that rule is set report-only in ruleModes).
//   report-only  — rules only alert; nothing blocks except fail-closed rules (alwaysEnforce).
// "flagged" (= detection) is the same in both modes: a rule that would block fired. "blocked" differs.
// Precision / recall / FP rate are reported for both detection and blocking in each mode.
//
// Determinism: corpus, labels, verdicts, itemized FP/FN and override stats are deterministic for a given
// checkout. Latency fields and generatedAt are measurements and vary run to run.

import { performance } from 'node:perf_hooks';
import { createHash } from 'node:crypto';
import { loadCorpus } from './corpus.mjs';
import { enforce } from './bounds.mjs';
import { confusion, rates, latencySummary, median, round } from './metrics.mjs';
import { standInEvents, overrideStats, readDecisionLog } from './decision-log.mjs';

export const RESULTS_SCHEMA = 'sentinel.scoring/1.0.0';
export const MODES = ['enforce', 'report-only'];
export const LABEL_RULE =
  'positive iff the data-exfil action was attempted (T1: dvaa.exfilAttempted, incl. AIM-denied twin runs) ' +
  'or T6 label.groundTruth=positive; benign captures/fixtures are negative';

function verdicts(fired, ruleModes) {
  const flagged = fired.some((f) => f.wouldBlock || f.alwaysEnforce);
  const enforceBlocked = fired.some((f) => f.alwaysEnforce || (f.wouldBlock && ruleModes[f.ruleId] !== 'report-only'));
  const reportOnlyBlocked = fired.some((f) => f.alwaysEnforce);
  return { flagged, blocked: { enforce: enforceBlocked, 'report-only': reportOnlyBlocked } };
}

const firedKey = (fired) => fired.map((f) => `${f.ruleId}:${f.wouldBlock ? 1 : 0}`).join('|');

/** Run one detector over all cases. Exceptions are captured per case (fail-loud via `errors`). */
export function runDetector(det, cases, { iterations = 5, ruleModes = {} } = {}) {
  enforce('MAX_LATENCY_ITERATIONS', iterations, `iterations for ${det.name}`);
  if (iterations < 1) throw new Error('iterations must be >= 1');
  const perCase = [];
  const errors = [];
  for (const c of cases) {
    const times = [];
    let first = null;
    try {
      for (let i = 0; i < iterations; i++) {
        const t0 = performance.now();
        const out = det.inspect(c);
        times.push(performance.now() - t0);
        const fired = [...(out?.fired ?? [])].sort((a, b) => a.ruleId.localeCompare(b.ruleId));
        if (first === null) first = { fired, failClosed: out?.failClosed === true };
        else if (firedKey(fired) !== firedKey(first.fired)) {
          throw new Error(`non-deterministic verdict on iteration ${i + 1}: ${firedKey(fired)} vs ${firedKey(first.fired)}`);
        }
      }
    } catch (err) {
      errors.push({ id: c.id, error: `${err.name}: ${err.message}` });
      console.error(JSON.stringify({ level: 'ERROR', event: 'sentinel.scoring.detector_error', detector: det.name, case: c.id, message: err.message }));
      continue;
    }
    perCase.push({
      id: c.id,
      source: c.source,
      group: c.group,
      groundTruth: c.groundTruth,
      evadesBaseline: c.evadesBaseline,
      fired: first.fired,
      failClosed: first.failClosed,
      ...verdicts(first.fired, ruleModes),
      latencyMs: round(median(times)),
    });
  }
  return { perCase, errors };
}

function scoreDetector(det, run, cases) {
  const { perCase, errors } = run;
  const modes = {};
  for (const mode of MODES) {
    modes[mode] = {
      detection: rates(confusion(perCase, (r) => r.flagged)),
      blocking: rates(confusion(perCase, (r) => r.blocked[mode])),
    };
  }
  const bySource = {};
  for (const src of [...new Set(cases.map((c) => c.source))].sort()) {
    bySource[src] = rates(confusion(perCase.filter((r) => r.source === src), (r) => r.flagged));
  }
  const rulesOf = (r) => r.fired.filter((f) => f.wouldBlock || f.alwaysEnforce).map((f) => ({ ruleId: f.ruleId, evidence: f.evidence ?? null }));
  return {
    kind: det.kind,
    description: det.description,
    available: true,
    provenance: det.provenance,
    latencyMs: latencySummary(perCase.map((r) => r.latencyMs)),
    modes,
    bySource,
    // Itemized on detection (flagged). In enforce mode each FP is a benign BLOCK; in report-only an alert.
    falsePositives: perCase.filter((r) => r.groundTruth === 'negative' && r.flagged)
      .map((r) => ({ id: r.id, source: r.source, group: r.group, rules: rulesOf(r) })),
    falseNegatives: perCase.filter((r) => r.groundTruth === 'positive' && !r.flagged)
      .map((r) => ({ id: r.id, source: r.source, group: r.group, notes: cases.find((c) => c.id === r.id)?.notes ?? '' })),
    failClosed: perCase.filter((r) => r.failClosed).map((r) => r.id),
    errors,
    perCase: perCase.map(({ id, groundTruth, fired, flagged, blocked, latencyMs }) => ({
      id, groundTruth, rules: fired.map((f) => f.ruleId), flagged, blockedEnforce: blocked.enforce, latencyMs,
    })),
    overrides: { standIn: overrideStats(standInEvents(det.name, perCase)) },
  };
}

function corpusSummary(cases, excluded) {
  const count = (pred) => cases.filter(pred).length;
  const bySource = {};
  for (const c of cases) {
    bySource[c.source] ??= { positive: 0, negative: 0 };
    bySource[c.source][c.groundTruth]++;
  }
  const digest = createHash('sha256')
    .update(JSON.stringify(cases.map((c) => [c.id, c.groundTruth, c.evadesBaseline, c.request, c.response])))
    .digest('hex');
  return {
    total: cases.length,
    positives: count((c) => c.groundTruth === 'positive'),
    negatives: count((c) => c.groundTruth === 'negative'),
    evadesBaseline: count((c) => c.evadesBaseline === true),
    bySource,
    excluded,
    digest: `sha256:${digest}`,
  };
}

function beatsBaseline(cases, scored) {
  const eligible = cases.filter((c) => c.evadesBaseline === true).map((c) => c.id);
  const base = scored['dvaa-baseline'];
  const flaggedBy = (name) => new Set((scored[name]?.perCase ?? []).filter((r) => r.flagged).map((r) => r.id));
  const out = { eligible, baselineAvailable: Boolean(base?.available), baselineMismatch: [], byDetector: {} };
  if (base?.available) {
    // T6 says DVAA's real detectAttacks() misses these. If our run of it catches one, the label is stale.
    const bf = flaggedBy('dvaa-baseline');
    out.baselineMismatch = eligible.filter((id) => bf.has(id));
  }
  for (const [name, s] of Object.entries(scored)) {
    if (!s.available || name === 'dvaa-baseline') continue;
    const f = flaggedBy(name);
    const caught = eligible.filter((id) => f.has(id));
    out.byDetector[name] = { eligible: eligible.length, beaten: caught.length, cases: caught };
  }
  return out;
}

/**
 * @param {object} o
 * @param {object[]} o.detectors     harness detectors (see detectors.mjs)
 * @param {string}   [o.root]        repo root holding captures/
 * @param {number}   [o.iterations]  latency repetitions per case (median taken)
 * @param {object}   [o.ruleModes]   { ruleId: 'report-only' } overrides for enforce mode
 * @param {string}   [o.decisionLog] path of the real append-only decision log (JSONL)
 * @param {string}   [o.headline]    detector whose numbers fill the top-level fields (default 't3')
 */
export function runScoring({ detectors, root, iterations = 5, ruleModes = {}, decisionLog = null, headline = 't3' }) {
  const { cases, excluded, t6Present } = loadCorpus(root);
  const warnings = [];
  if (!t6Present) warnings.push('T6 corpus (captures/variants/manifest.json) not found: scored T1 captures only');
  const scored = {};
  for (const det of detectors) {
    if (!det.available) {
      scored[det.name] = { kind: det.kind, description: det.description, available: false, unavailableReason: det.unavailableReason, provenance: det.provenance };
      continue;
    }
    scored[det.name] = scoreDetector(det, runDetector(det, cases, { iterations, ruleModes }), cases);
  }
  const bb = beatsBaseline(cases, scored);
  if (bb.baselineMismatch.length) warnings.push(`dvaa-baseline flagged case(s) T6 labels evadesBaseline=true: ${bb.baselineMismatch.join(', ')}`);
  const errorCount = Object.values(scored).reduce((n, s) => n + (s.errors?.length ?? 0), 0);

  const h = scored[headline];
  const hm = h?.available ? h.modes.enforce.blocking : null;
  const top = hm
    ? {
      headline: { detector: headline, mode: 'enforce', metric: 'blocking', status: 'ok' },
      detectionRate: hm.recall,
      recall: hm.recall,
      precision: hm.precision,
      falsePositiveRate: hm.falsePositiveRate,
      latencyMs: { median: h.latencyMs.median, p95: h.latencyMs.p95 },
      counts: { attack: hm.positives, benign: hm.negatives, fp: hm.fp, fn: hm.fn },
    }
    : {
      // No invented numbers: the SentinelProxy headline stays empty until its detector is scorable.
      headline: { detector: null, mode: 'enforce', metric: 'blocking', status: `awaiting ${headline}: ${h?.unavailableReason ?? 'not configured'}` },
      detectionRate: null,
      recall: null,
      precision: null,
      falsePositiveRate: null,
      latencyMs: { median: null, p95: null },
      counts: null,
    };

  return {
    schema: RESULTS_SCHEMA,
    generatedAt: new Date().toISOString(),
    node: process.version,
    iterations,
    labelRule: LABEL_RULE,
    ...top,
    corpus: corpusSummary(cases, excluded),
    detectors: scored,
    beatsBaseline: bb,
    overrides: { flagThreshold: 0.9, real: realOverrides(decisionLog) },
    errorCount,
    warnings,
  };
}

function realOverrides(file) {
  if (!file) return { log: null, events: 0, rules: [], note: 'no decision log configured; stand-in only (until S5)' };
  const events = readDecisionLog(file);
  return { log: file, events: events.length, rules: overrideStats(events) };
}
