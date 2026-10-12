// SentinelProxy T3 — every cap the detector enforces, in one place, plus the fail-loud error types.
//
// Firm rule (bounded + fail-loud): every input the detector scans or accumulates has a hard cap. On
// overflow the detector RAISES (these errors) or returns a fail-closed BLOCK verdict carrying
// {payload_size, cap, action}, and logs it at ERROR. It never truncates silently. DVAA's own
// `detectionText()` keeps only the first and last 8 KiB of a long input and drops the middle; that
// head/tail window is the anti-pattern this module exists to beat. Nothing below is a scan window.
// Each cap is a reject threshold: the payload is scanned in full or refused in full.

export const DEFAULT_BOUNDS = Object.freeze({
  // Whole turn (request + response JSON) the detector will scan. 1 MiB = DVAA's own
  // MAX_AGENT_BODY_BYTES, so any request DVAA accepts is scanned in full. The cap bounds TIME as well
  // as bytes: every scanner is linear, and the adversarial timing tests run AT this size.
  // Beyond it -> fail-closed BLOCK + scan_cap_exceeded alert (or DetectorOverflowError).
  maxPayloadBytes: 1024 * 1024,
  // Messages in one request history. OpenAI clients resend the whole history; 2,000 turns is far
  // beyond any agent session we replay. Beyond it -> fail closed (same path as payload size).
  maxMessages: 2000,
  // Tool calls in one assistant response. DVAA's largest is 5 (RepoBot). Beyond -> fail closed.
  maxToolCallsPerResponse: 256,
  // Cooperative time budget for one inspection. Checked between phases; exceeded -> fail closed
  // with failclosed.scanner_timeout. Detection is single-threaded JS, so this is a post-phase check,
  // not a preemptive kill (documented in the PR).
  timeBudgetMs: 250,
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
