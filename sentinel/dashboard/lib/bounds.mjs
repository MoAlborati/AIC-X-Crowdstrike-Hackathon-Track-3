// Every cap the dashboard introduces lives here, with why and what happens on overflow.
// Team rule: bounded + fail-loud. Nothing here truncates silently. Exceeding a cap throws
// BoundExceededError, which the server returns as a structured error ({bound, size, cap, action})
// and the UI renders as a red banner.

export const BOUNDS = Object.freeze({
  // One capture file. The largest realistic capture (multi-hundred-row tool output plus a
  // >8KB poisoned document) is a few hundred KB. 8 MiB keeps JSON.parse in the browser well under
  // 100 ms and still leaves room for much larger captures.
  // Overflow: the capture is rejected with HTTP 413, and the listing marks it as an error.
  MAX_CAPTURE_BYTES: 8 * 1024 * 1024,

  // Number of capture files the server will index (captures/ + one subdirectory level).
  // T1 plans 3-5 captures and T6 adds a few dozen variants. Overflow: /api/captures returns HTTP 507
  // naming the count. The dashboard does not list only the first N.
  MAX_CAPTURE_FILES: 500,

  // Incident-graph node budget. Nodes are messages, tool calls, tool results, sinks and alerts.
  // Tool-output ROWS are not nodes: a 500-row result is one node carrying rowCount, so this budget
  // does not grow with data volume. Overflow: the replay build throws and the UI shows an error. It
  // never draws a partial graph.
  MAX_GRAPH_NODES: 1000,

  // Alerts attached to one capture. Overflow: the replay build throws and the UI shows an error.
  MAX_ALERTS_PER_CAPTURE: 500,

  // Provenance edges per alert (narrative case card). Overflow: throws.
  MAX_PROVENANCE_EDGES_PER_ALERT: 64,

  // T7 sentinel/scoring/results.json. With per-case detail for 3 detectors over the 353-case corpus it
  // is ~0.4 MB; 16 MiB leaves room for a corpus ~40x larger. Overflow: /api/scoring reports the file as
  // an error (the headline tiles show ERROR with size and cap). It never parses a partial file.
  MAX_SCORING_BYTES: 16 * 1024 * 1024,
});

export class BoundExceededError extends Error {
  constructor(bound, size, cap, context = '') {
    super(`${bound} exceeded: size=${size} cap=${cap}${context ? ` (${context})` : ''} — refusing to truncate`);
    this.name = 'BoundExceededError';
    this.bound = bound;
    this.size = size;
    this.cap = cap;
    this.action = 'rejected';
  }

  toJSON() {
    return { error: this.message, bound: this.bound, size: this.size, cap: this.cap, action: this.action };
  }
}

export function enforce(bound, size, context) {
  const cap = BOUNDS[bound];
  if (cap === undefined) throw new Error(`unknown bound ${bound}`);
  if (size > cap) {
    const err = new BoundExceededError(bound, size, cap, context);
    // Loud: log on the server, too, so an overflow is never visible only in a browser tab.
    console.error(`[sentinel-dashboard] ALERT ${err.message}`);
    throw err;
  }
}
