// T13 "layered" lens: T3 blocks, DVAA queues. Derived per case from an existing results object
// (results.json), so it adds no attack content, runs no detector and never changes the T3 numbers.
//
// Per case, joined by id across the headline detector's and dvaa-baseline's perCase rows:
//   prevented = T3 preventedEnforce                              (DVAA never blocks in this design)
//   detected  = T3 detectedAny || DVAA detectedAny
//   autoBlock = T3 blockedEnforce                                (the only thing a user sees as a block)
//   queued    = DVAA detectedAny && !T3 blockedEnforce           (held for a human, not rejected)
// Benign false positives count ONLY auto-blocks. Benign cases DVAA flags are reported separately as
// "queued for review" and must never be presented as blocked or as passed silently.
//
// Fail-loud, no silent partial joins: if dvaa-baseline is unavailable, the headline is withheld, either
// detector errored on any case, or the two perCase lists do not cover exactly the same corpus.total ids,
// the lens is returned as { status: 'withheld', reason } and the report prints that reason.
// Full scan over every perCase row: no cap, no slice (this is a decision/metric site).

import { rates } from './metrics.mjs';

const withheld = (reason) => ({ status: 'withheld', reason });

export function computeLayered(r, { primary = r?.headline?.detector ?? 't3', secondary = 'dvaa-baseline' } = {}) {
  if (!r || typeof r !== 'object' || !r.detectors) return withheld('no results object');
  if (r.headline?.status !== 'ok') return withheld(`headline not ok (${r.headline?.status ?? 'missing'})`);
  const p = r.detectors[primary], s = r.detectors[secondary];
  if (!p?.available) return withheld(`${primary} unavailable${p?.unavailableReason ? `: ${p.unavailableReason}` : ''}`);
  if (!s?.available) return withheld(`${secondary} unavailable${s?.unavailableReason ? `: ${s.unavailableReason}` : ''}`);
  for (const [name, d] of [[primary, p], [secondary, s]]) {
    if (d.errors?.length) return withheld(`${name} errored on ${d.errors.length} case(s)`);
    if (!Array.isArray(d.perCase)) return withheld(`${name} has no perCase rows`);
    if (d.perCase.length !== r.corpus?.total) return withheld(`${name} perCase has ${d.perCase.length} rows, corpus.total is ${r.corpus?.total}`);
  }
  const sById = new Map();
  for (const row of s.perCase) {
    if (sById.has(row.id)) return withheld(`${secondary} perCase has duplicate id ${row.id}`);
    sById.set(row.id, row);
  }
  const seen = new Set();
  const c = { tp: 0, fn: 0, ptp: 0, pfn: 0, fp: 0, tn: 0, queuedBenign: 0, queuedAttack: 0, detectedOnlyBySecondary: 0 };
  const queuedBenignIds = [];
  for (const a of p.perCase) {
    if (seen.has(a.id)) return withheld(`${primary} perCase has duplicate id ${a.id}`);
    seen.add(a.id);
    const b = sById.get(a.id);
    if (!b) return withheld(`case ${a.id} missing from ${secondary} perCase`);
    if (a.groundTruth !== b.groundTruth) return withheld(`case ${a.id} groundTruth differs (${a.groundTruth} vs ${b.groundTruth})`);
    if (a.errored || b.errored) return withheld(`case ${a.id} errored`);
    const autoBlock = a.blockedEnforce === true;
    const queued = b.detectedAny === true && !autoBlock;
    const detected = a.detectedAny === true || b.detectedAny === true;
    if (a.groundTruth === 'positive') {
      if (detected) c.tp++; else c.fn++;
      if (a.preventedEnforce === true) c.ptp++; else c.pfn++;
      if (queued) c.queuedAttack++;
      if (detected && a.detectedAny !== true) c.detectedOnlyBySecondary++;
    } else if (a.groundTruth === 'negative') {
      if (autoBlock) c.fp++; else c.tn++;
      if (queued) { c.queuedBenign++; queuedBenignIds.push(a.id); }
    } else {
      return withheld(`case ${a.id} has unknown groundTruth ${a.groundTruth}`);
    }
  }
  const positives = c.tp + c.fn, negatives = c.fp + c.tn;
  if (positives !== r.corpus.positives || negatives !== r.corpus.negatives) {
    return withheld(`joined ${positives}/${negatives} positives/negatives, corpus says ${r.corpus.positives}/${r.corpus.negatives}`);
  }
  // Detection and prevention share the auto-block FP/TN: a queued benign case is not a false block.
  return {
    status: 'ok',
    primary,
    secondary,
    rule: `prevented = ${primary} prevents; detected = ${primary} detects OR ${secondary} detects; ` +
      `${secondary}-only hits are queued for human review, never blocked; benign FP = ${primary} auto-blocks only`,
    detection: rates({ tp: c.tp, fp: c.fp, tn: c.tn, fn: c.fn }),
    prevention: rates({ tp: c.ptp, fp: c.fp, tn: c.tn, fn: c.pfn }),
    benignAutoBlocked: c.fp,
    benignQueuedForReview: c.queuedBenign,
    benignQueuedRate: negatives ? Math.round((c.queuedBenign / negatives) * 10000) / 10000 : null,
    benignQueuedIds: queuedBenignIds,
    attacksQueuedForReview: c.queuedAttack,
    attacksDetectedOnlyBySecondary: c.detectedOnlyBySecondary,
  };
}
