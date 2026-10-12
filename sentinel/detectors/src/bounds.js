// SentinelProxy T3 — every cap the detector enforces, in one place, plus the fail-loud error types.
//
// Firm rule (bounded + fail-loud): every input the detector scans or accumulates has a hard cap. On
// overflow the detector RAISES (these errors) or returns a fail-closed BLOCK verdict carrying
// {payload_size, cap, action}, and logs it at ERROR. It never truncates silently. DVAA's own
// `detectionText()` keeps only the first and last 8 KiB of a long input and drops the middle; that
// head/tail window is the anti-pattern this module exists to beat. Nothing below is a scan window.
// Each cap is a reject threshold: the payload is scanned in full or refused in full.

export const DEFAULT_BOUNDS = Object.freeze({
  // Whole turn (request + response JSON) the detector will scan. The cap bounds TIME, not just bytes:
  // every scanner is linear, and the measured worst case over crafted inputs (test/timing.test.js, 20k
  // canaries registered) is ~63 ms at 1 MiB, ~30 ms at 512 KiB, ~24 ms at 384 KiB on the build box.
  // The T2 proxy enforces a ~50 ms inspector timeout; 512 KiB measured 40.6 ms under the merge gate's
  // parallel load, so the cap is 384 KiB (~24 ms worst case solo) to keep real headroom under our 40 ms
  // budget. DVAA accepts requests up to 1 MiB (MAX_AGENT_BODY_BYTES); a turn above 384 KiB is refused in
  // full, never truncated. Demo payloads are ~23 KB. Beyond it -> fail-closed BLOCK + scan_cap_exceeded.
  maxPayloadBytes: 384 * 1024,
  // Messages in one request history. OpenAI clients resend the whole history; 2,000 turns is far
  // beyond any agent session we replay. Beyond it -> fail closed (same path as payload size).
  maxMessages: 2000,
  // Tool calls in one assistant response. DVAA's largest is 5 (RepoBot). Beyond -> fail closed.
  maxToolCallsPerResponse: 256,
  // Cooperative time budget for one inspection, below T2's ~50 ms inspector timeout so a slow scan
  // becomes OUR fail-closed BLOCK verdict (with reason codes) rather than a proxy timeout. Checked between
  // phases; exceeded -> failclosed.detector_error (ScannerTimeoutError). Single-threaded JS cannot be
  // preempted mid-phase; the payload cap is what bounds a single phase (see maxPayloadBytes).
  timeBudgetMs: 40,
  // Base64/hex/URL decode passes per string when looking for encoded honeytokens. Each pass only
  // shrinks the text (decoding never grows bytes), so total work is bounded by maxPayloadBytes x depth.
  maxDecodeDepth: 3,
  // Minimum length of a base64 / hex run worth decoding. Shorter runs carry too few bytes to hold a
  // honeytoken (minimum token length is 8).
  minEncodedRunChars: 12,
  // Canary registry (per-session minted canaries + seeded fake records). Expired entries (TTL) are
  // evicted first; if still full -> RegistryFullError -> fail closed. Static tokens do not count.
  maxCanaries: 50000,
  canaryTtlMs: 24 * 60 * 60 * 1000,
  // Session store (mandate grant + HMAC key + cumulative ledger). Idle sessions past TTL are evicted
  // (their history is over, not truncated); if still full -> LedgerFullError -> fail closed.
  maxSessions: 10000,
  sessionTtlMs: 60 * 60 * 1000,
  // Distinct tools tracked per session in the cumulative ledger. Beyond -> LedgerFullError.
  maxLedgerKeysPerSession: 512,
  // Entries in one mandate grant (destinations + tools). Beyond -> MandateOverflowError -> fail closed.
  maxGrantEntries: 256,
  // Shingle length for the copied-untrusted-substring rule (BACKLOG: ">=8-char shingle"). A hit needs
  // a contiguous copied span of at least minCopiedSpanChars so one URL scheme cannot fire it.
  shingleChars: 8,
  minCopiedSpanChars: 24,
  // Longest single token classified by the anchored secret tests. Longer runs are still scanned for
  // honeytokens (index lookup) and decoded; only the shape tests use prefix checks. Bounds per-token
  // regex work so total regex cost is O(payload x 512) worst case, never quadratic.
  maxTokenChars: 512,
});

/** Base class: every overflow carries the exact {payload_size, cap, action} triple the gate asks for. */
export class SentinelBoundError extends Error {
  constructor(name, message, { payload_size, cap, action = 'block', bound }) {
    super(`${message} (payload_size=${payload_size}, cap=${cap}, action=${action})`);
    this.name = name;
    this.payload_size = payload_size;
    this.cap = cap;
    this.action = action;
    this.bound = bound;
  }
  toJSON() {
    return { error: this.name, bound: this.bound, payload_size: this.payload_size, cap: this.cap, action: this.action };
  }
}

export class DetectorOverflowError extends SentinelBoundError {
  constructor(details) {
    super('DetectorOverflowError', `input exceeds ${details.bound}; refusing to scan a truncated payload`, details);
  }
}
export class RegistryFullError extends SentinelBoundError {
  constructor(details) {
    super('RegistryFullError', 'canary registry is full; refusing to evict live canaries silently', details);
  }
}
export class LedgerFullError extends SentinelBoundError {
  constructor(details) {
    super('LedgerFullError', `session ledger is full (${details.bound}); refusing to drop history silently`, details);
  }
}
export class MandateOverflowError extends SentinelBoundError {
  constructor(details) {
    super('MandateOverflowError', 'mandate grant exceeds its entry cap; refusing a partial grant', details);
  }
}
export class ScannerTimeoutError extends SentinelBoundError {
  constructor(details) {
    super('ScannerTimeoutError', 'detector exceeded its time budget', details);
  }
}
export class PolicyError extends Error {
  constructor(issues) {
    super(`invalid policy — ${issues.length} issue(s):\n  - ${issues.join('\n  - ')}`);
    this.name = 'PolicyError';
    this.issues = issues;
  }
}

export function resolveBounds(overrides = {}) {
  const out = { ...DEFAULT_BOUNDS };
  for (const [k, v] of Object.entries(overrides)) {
    if (!(k in DEFAULT_BOUNDS)) throw new PolicyError([`unknown bound "${k}"`]);
    if (!Number.isFinite(v) || v <= 0) throw new PolicyError([`bound "${k}" must be a positive number`]);
    out[k] = v;
  }
  return Object.freeze(out);
}
