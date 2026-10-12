// Every cap the T10 alert pipeline introduces, with why that value and what happens on overflow.
// Team rule: bounded + fail-loud. Nothing here truncates silently.
//
// These are STORAGE/DISPLAY caps. They only shape what is written for the T5 dashboard. Block/allow
// decisions are made earlier, by the proxy's inspectors over the FULL request/response body. No cap
// here can change a verdict.

export const BOUNDS = Object.freeze({
  // Capture files the pipeline writes into one output dir (one per session part).
  // T5 indexes at most MAX_CAPTURE_FILES=2000 and answers 507 beyond that, so we stop at 400 and keep
  // headroom for its placeholder fixtures. Overflow: PipelineBoundError. `tail` exits 3. `live`
  // makes the proxy sink throw, so the proxy refuses the exchange with 503 + ALERT.
  MAX_CAPTURES: 400,

  // Exchanges in one capture part. Past this the session rotates to a new part (`--p002`, …). That
  // is a split, not a drop: every exchange is written. 100 keeps one replay graph well under T5's
  // MAX_GRAPH_NODES=1000 (each exchange adds a few nodes).
  MAX_EXCHANGES_PER_CAPTURE: 100,

  // T4 alerts in one capture part. T5 throws past MAX_ALERTS_PER_CAPTURE=500. Overflow rotates to a
  // new part, the same as above.
  MAX_ALERTS_PER_CAPTURE: 400,

  // Estimated incident-graph nodes in one capture part. T5 throws past MAX_GRAPH_NODES=1000 for a
  // replay. Estimate per exchange = messages + 1 assistant + 2 per tool call (call + sink) + 2 per
  // alert. That overestimates, which is the safe direction. Overflow rotates to a new part. One
  // exchange that alone exceeds the budget still gets its own part, and T5 then refuses it loudly
  // (413 naming MAX_GRAPH_NODES). Nothing is dropped here.
  MAX_DISPLAY_NODES_PER_CAPTURE: 800,

  // Serialized bytes of one capture part. T5 rejects captures over MAX_CAPTURE_BYTES=8 MiB with 413.
  // 6 MiB leaves headroom. Overflow rotates to a new part.
  MAX_CAPTURE_BYTES: 6 * 1024 * 1024,

  // Bytes of ONE exchange embedded in a capture. One proxied exchange can be 1 MiB + 8 MiB (T2
  // limits), which would not fit any part. Over this, the bodies are replaced by an explicit
  // omission marker (bytes, sha256, request_id, and where the full body is). A stderr ALERT is
  // logged, and an `embed_omitted` record goes to ops-alerts.jsonl. The full body stays in the
  // proxy JSONL, and the verdicts were computed on it.
  MAX_EMBED_EXCHANGE_BYTES: 2 * 1024 * 1024,

  // One JSONL line from the proxy capture. Worst case T2 record: 1 MiB request + 8 MiB response,
  // plus the upstream response again when flagged, base64 or JSON escaping on top. 64 MiB covers
  // that. Overflow: PipelineBoundError naming the byte offset. We never parse part of a line.
  MAX_LINE_BYTES: 64 * 1024 * 1024,

  // Flagged verdicts on one exchange. Real exchanges carry a handful. 256 still allows a response
  // with hundreds of tool calls to flag many of them. Overflow: PipelineBoundError (the stand-in
  // inspector throws the same error inside the proxy, which then fails closed in block mode).
  MAX_VERDICTS_PER_EXCHANGE: 256,

  // Proxy `alert` records waiting for their `exchange` record (same request_id). The proxy writes
  // them back to back, so only in-flight requests are pending. Overflow: PipelineBoundError.
  MAX_PENDING_ALERTS: 4096,

  // T12 egress records waiting for agent correlation (tail: held until no chat-proxy request that
  // started before them is still in flight, or EGRESS_MAX_HOLD_MS passes; convert: held until end of
  // input). The demo writes a handful per turn. Overflow: PipelineBoundError (never dropped).
  MAX_PENDING_EGRESS: 4096,

  // Chat-proxy exchange windows [ts, ts+latency_ms] kept for egress time-window correlation. Overflow
  // evicts the OLDEST window and logs ALERT `correlation_window_evicted`. Any later egress record older
  // than the evicted horizon is labeled `correlation_history_evicted` and shown as a standalone egress
  // incident: attribution is lost loudly, never guessed. Correlation is display/attribution only; the
  // egress inspector already made the allow/deny decision.
  MAX_CORRELATION_WINDOWS: 20000,

  // Write-ahead `request` records whose exchange has not arrived (in-flight chat turns). Used to decide
  // that a pending egress record may still belong to an unfinished turn. Overflow: PipelineBoundError.
  MAX_INFLIGHT_REQUESTS: 4096,

  // Hard hold (ms) for an egress record in `tail` while an earlier chat turn is still in flight. Past
  // this the record is converted as a standalone egress incident with reason `in_flight_turn_timeout`.
  // 120 s covers DVAA's slowest agent turn (LLM latency) with headroom. Never infinite.
  EGRESS_MAX_HOLD_MS: 120000,

  // Minimum hold (ms) in `tail` before a pending egress record is resolved, so the proxy follower
  // (separate file, separate poll) has read the write-ahead record of the turn that caused it.
  EGRESS_MIN_HOLD_MS: 1500,
});

export class PipelineBoundError extends Error {
  constructor(bound, size, cap, context = '', action = 'rejected') {
    super(`${bound} exceeded: size=${size} cap=${cap}${context ? ` (${context})` : ''}. Refusing to truncate`);
    this.name = 'PipelineBoundError';
    this.bound = bound;
    this.size = size;
    this.cap = cap;
    this.action = action;
  }

  toJSON() {
    return { error: this.message, bound: this.bound, size: this.size, cap: this.cap, action: this.action };
  }
}

/** Throw (and log loudly) when size > cap. `caps` lets tests and the CLI lower a cap. */
export function enforce(bound, size, context, caps = BOUNDS, log = defaultLog) {
  const cap = caps[bound];
  if (cap === undefined) throw new Error(`unknown bound ${bound}`);
  if (size > cap) {
    const err = new PipelineBoundError(bound, size, cap, context);
    log({ level: 'ALERT', ...err.toJSON() });
    throw err;
  }
}

export function defaultLog(entry) {
  process.stderr.write(`[sentinel-pipeline] ${entry.level ?? 'INFO'} ${JSON.stringify(entry)}\n`);
}

/** Merge caller overrides onto BOUNDS. An unknown or non-positive cap is a programming error: throw. */
export function resolveCaps(overrides = {}) {
  const caps = { ...BOUNDS };
  for (const [k, v] of Object.entries(overrides)) {
    if (!(k in BOUNDS)) throw new Error(`unknown bound override ${k}`);
    if (!Number.isInteger(v) || v <= 0) throw new Error(`bound ${k} must be a positive integer, got ${v}`);
    caps[k] = v;
  }
  return Object.freeze(caps);
}
