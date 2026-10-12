// Pure view-state helpers for the replay player (no DOM), shared by app.js and the tests.

/**
 * What is visible at timeline step `step` (0-based, inclusive).
 * At the last step everything is revealed, so a node that no step mentions (for example a sink known
 * only from dvaa{}) is still drawn by the end of the replay. Nothing is ever left out of the graph.
 */
export function viewAt(replay, step) {
  const tl = replay.timeline;
  const last = tl.length - 1;
  const s = Math.max(-1, Math.min(step, last));
  const revealed = new Set();
  const alertIds = new Set();
  for (let i = 0; i <= s; i++) {
    for (const id of tl[i].nodeIds) revealed.add(id);
    for (const id of tl[i].alertIds ?? []) alertIds.add(id);
  }
  if (s >= last) for (const n of replay.graph.nodes) revealed.add(n.id);
  const cur = s >= 0 ? tl[s] : null;
  const focus = new Set([...(cur?.nodeIds ?? []), ...(cur?.edgeIds ?? [])]);
  const alerts = replay.alerts.filter(a => alertIds.has(a.id));
  return { step: s, last, revealed, focus, alerts, current: cur, trust: trustAt(replay, alerts, s >= last) };
}

/**
 * Gauge value. Detector-derived when alerts are revealed (100 − max Severity, the formula in
 * lib/replay.mjs). Otherwise DVAA's own AIM score if the capture recorded one, labeled as such.
 */
export function trustAt(replay, revealedAlerts, atEnd) {
  if (revealedAlerts.length) {
    const max = revealedAlerts.reduce((m, a) => Math.max(m, a.severity ?? 0), 0);
    return { value: Math.max(0, 100 - max), source: 'detector', note: `100 − max alert severity (${max})` };
  }
  const aim = replay.groundTruth?.aim?.trustScore ?? replay.run?.outcome?.trustScore ?? null;
  if (atEnd && Number.isFinite(aim)) return { value: aim, source: 'aim', note: 'DVAA AIM trust score (recorded ground truth)' };
  if (!replay.alerts.length) return { value: null, source: 'none', note: 'no detector verdicts recorded for this run' };
  return { value: 100, source: 'detector', note: 'no alert revealed yet' };
}

/** Pair a vulnerable run with its protected (AIM) twin from the run list, if the capture has both. */
export function twinPair(runs) {
  const vuln = runs.find(r => r.role === 'vulnerable');
  const prot = runs.find(r => r.role === 'protected');
  return vuln && prot ? { vuln, prot } : null;
}

/** Rates from T7 are fractions in [0,1]. */
export function pct(x) {
  return Number.isFinite(x) ? `${(x * 100).toFixed(1)}%` : '—';
}
