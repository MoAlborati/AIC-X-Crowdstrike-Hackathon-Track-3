// T7 scoring harness bounds. Every cap is fail-loud: overflow throws ScoringBoundError with
// {bound, size, cap, action}. Nothing is truncated or skipped on overflow. None of these caps sit on a
// decision path as a "first N" scan: the harness either scores the whole corpus or refuses to run.

export const BOUNDS = Object.freeze({
  // Total cases in one scoring run. The corpus today is ~30 cases; 2,000 leaves room for T6 growth
  // while keeping one run under a few seconds. Beyond it: refuse the run (split the corpus).
  MAX_CASES: 2000,
  // One fixture/capture file on disk. The largest real fixture is ~34KB (T6 400-row tool output);
  // 4 MiB is far above any replayable chat turn. Beyond it: refuse to load that file.
  MAX_FIXTURE_BYTES: 4 * 1024 * 1024,
  // Text units (messages + tool calls + ledger actions) extracted from one case. Beyond it: refuse.
  MAX_UNITS_PER_CASE: 1000,
  // Latency repetitions per case per detector (median taken). Beyond it: refuse (bad CLI arg).
  MAX_LATENCY_ITERATIONS: 100,
  // Append-only decision log (override tracking). Beyond either cap: refuse to read; rotate the log.
  MAX_DECISION_LOG_BYTES: 16 * 1024 * 1024,
  MAX_DECISION_LOG_LINES: 100000,
  // One decision-log line. Beyond it: refuse the log (a giant line is corruption or abuse).
  MAX_DECISION_LINE_BYTES: 16 * 1024,
});

export class ScoringBoundError extends Error {
  constructor(bound, size, cap, where) {
    super(`${bound} exceeded: size=${size} cap=${cap} at ${where} — refusing (never truncated)`);
    this.name = 'ScoringBoundError';
    this.bound = bound;
    this.size = size;
    this.cap = cap;
    this.where = where;
    this.action = 'reject';
  }
  toJSON() {
    return { error: this.name, bound: this.bound, size: this.size, cap: this.cap, where: this.where, action: this.action };
  }
}

export function enforce(bound, size, where) {
  const cap = BOUNDS[bound];
  if (cap === undefined) throw new Error(`unknown bound ${bound}`);
  if (size > cap) {
    const err = new ScoringBoundError(bound, size, cap, where);
    console.error(JSON.stringify({ level: 'ERROR', event: 'sentinel.scoring.bound_exceeded', ...err.toJSON() }));
    throw err;
  }
  return size;
}

/** Corpus/label problems (missing file, unknown scenario, inconsistent label). Always fatal. */
export class CorpusError extends Error {
  constructor(message) {
    super(message);
    this.name = 'CorpusError';
  }
}
