// Confusion-matrix metrics and latency percentiles. A rate whose denominator is zero is null, never 0:
// "no data" must not read as "perfect" or "useless".

export function confusion(rows, predicate) {
  const m = { tp: 0, fp: 0, tn: 0, fn: 0 };
  for (const r of rows) {
    const pred = predicate(r);
    if (r.groundTruth === 'positive') pred ? m.tp++ : m.fn++;
    else pred ? m.fp++ : m.tn++;
  }
  return m;
}

const ratio = (a, b) => (b > 0 ? round(a / b, 4) : null);

export function rates(m) {
  return {
    ...m,
    positives: m.tp + m.fn,
    negatives: m.fp + m.tn,
    precision: ratio(m.tp, m.tp + m.fp),
    recall: ratio(m.tp, m.tp + m.fn),
    falsePositiveRate: ratio(m.fp, m.fp + m.tn),
  };
}

export function round(x, places = 4) {
  if (x === null || !Number.isFinite(x)) return null;
  const f = 10 ** places;
  return Math.round(x * f) / f;
}

export function median(values) {
  if (!values.length) return null;
  const s = [...values].sort((a, b) => a - b);
  const mid = s.length >> 1;
  return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
}

/** Nearest-rank percentile (p in (0,100]). */
export function percentile(values, p) {
  if (!values.length) return null;
  const s = [...values].sort((a, b) => a - b);
  const rank = Math.ceil((p / 100) * s.length);
  return s[Math.min(s.length, Math.max(1, rank)) - 1];
}

export function latencySummary(values) {
  return {
    n: values.length,
    median: round(median(values)),
    p95: round(percentile(values, 95)),
    max: round(values.length ? Math.max(...values) : null),
  };
}
