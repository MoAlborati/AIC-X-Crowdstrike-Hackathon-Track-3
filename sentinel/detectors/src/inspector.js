// Tourniquet T3 -> T2 adapter. Matches the proxy's inspector hook (sentinel/proxy/inspectors.mjs, PR #14):
//
//   async function inspector({ phase, path, headers, body, requestId, status? })
//     -> { flagged, detector, reasons: string[], disposition, ... } | null
//
// Wiring T3 into the proxy is one line:
//   inspectors: [sentinelInspector({ honeytokens: DVAA_HONEYTOKENS, agent: { name: 'RAGBot', port: 7005 } })]
//
// Phases. The proxy calls inspectors twice per exchange with ONE body each. The detector needs both: the
// request (principal turns, tool outputs, mandate) and the response (the tool calls about to execute).
//   request  -> inbound screen over the full request; the raw request is parked under `requestId`.
//   response -> the parked request + this response are inspected together (taint, mandate, egress).
// Parking is BOUNDED (entries + total bytes + TTL). If it is full, or a response arrives with no parked
// request, the verdict is a fail-closed BLOCK (reason codes request_context_full / request_context_missing),
// never an uninspected pass.
// Only clean requests use that map; flagged ones go to a small FIFO map (S1), so blocked attack volume
// can never lock out benign traffic. Sessions are keyed by x-sentinel-session or a stable conversation
// hash, never the request id (B2). Time budget = 80% of the proxy's inspectorTimeoutMs, and the proxy's
// abort `signal` is honoured (B3). URL path/query and headers are scanned for honeytokens (S5).
//
// Verdicts are SECRET-FREE (PR #14 review): `reasons` are static reason codes plus canary IDs
// (`honeytoken_crossed_egress`, `canary:DVAA-ADMIN-PASSWORD`); findings carry canary {id, sha256} only and
// redacted strings. `disposition` uses T4's values (block | allow | report).
//
// Mode. Run the detector in `enforce` and let the proxy's own observe|block mode decide what happens to a
// flagged verdict (observe = forward + would-block ALERT). `flagged` is true exactly when the detector
// would block.
//
// Direction (T8 finding, PR #16): DVAA executes tools IN-PROCESS, so by the time a response reaches the
// proxy the data has already left. The PREVENTIVE path is the request phase (pre-forward). Response-phase
// tool-call findings are `postExecution: true, prevents: false`: evidence, never claimed prevention.
// Most are `flagged: false, alert: true`. EXCEPTION (review B1): a honeytoken or strong secret in the
// tool-call args is `flagged: true` (disposition block, enforcement withhold_reply) so the proxy withholds
// the reply that would carry the result back to the client — still prevents:false, postExecution:true. Every verdict carries `direction` and `prevents`. (toolExecution: "client" restores
// response-side blocking for agents whose client executes tool_calls.)

import { createHash } from 'node:crypto';
import { createDetector } from './detector.js';

// Fraction of the proxy's inspector deadline the detector may spend before failing closed itself (so the
// verdict carries reason codes instead of a bare proxy 503). The rest is headroom for the proxy.
const BUDGET_FRACTION = 0.8;
// Flagged requests are parked separately (review S1): in block mode the proxy refuses them and no
// response ever arrives, so they must never occupy the benign pending map. Oldest evicted first; a
// response for an evicted flagged request gets request_context_missing (fail closed, already flagged).
const MAX_FLAGGED_PENDING = 256;

const CHAT_PATHS = new Set(['/v1/chat/completions', '/chat/completions']);

export function sentinelInspector(opts = {}) {
  // B3: the runtime time budget comes from the proxy's REAL inspector deadline (limits.inspectorTimeoutMs,
  // 5000 ms in sentinel/config/sentinel.config.json), not an assumed ~50 ms. An explicit bounds.timeBudgetMs wins.
  const proxyTimeoutMs = opts.inspectorTimeoutMs ?? opts.limits?.inspectorTimeoutMs;
  let detOpts = opts;
  if (Number.isFinite(proxyTimeoutMs) && proxyTimeoutMs > 0 && opts.bounds?.timeBudgetMs === undefined) {
    detOpts = { ...opts, bounds: { ...(opts.bounds ?? {}), timeBudgetMs: Math.max(1, Math.floor(proxyTimeoutMs * BUDGET_FRACTION)) } };
  }
  const det = opts.detector ?? createDetector(detOpts);
  const sessionHeader = (opts.sessionHeader ?? 'x-sentinel-session').toLowerCase();
  const maxPending = opts.maxPendingRequests ?? 1024;
  const maxPendingBytes = opts.maxPendingBytes ?? 64 * 1024 * 1024;
  const pendingTtlMs = opts.pendingTtlMs ?? 120000;
  const now = opts.now ?? Date.now;
  const pending = new Map(); // requestId -> {text, bytes, at, sessionId}
  let pendingBytes = 0;
  const flaggedPending = new Map(); // requestId -> {text, at, sessionId}  (S1: separate, FIFO-bounded)
  const maxFlaggedPending = opts.maxFlaggedPending ?? MAX_FLAGGED_PENDING;
  const maxFlaggedPendingBytes = Math.min(maxPendingBytes, 16 * 1024 * 1024);
  let flaggedBytes = 0;
  let flaggedEvicted = 0;
  const dropFlagged = (id) => {
    const p = flaggedPending.get(id);
    if (p) {
      flaggedBytes -= p.bytes;
      flaggedPending.delete(id);
    }
    return p;
  };

  const drop = (id) => {
    const p = pending.get(id);
    if (p) {
      pendingBytes -= p.bytes;
      pending.delete(id);
    }
    return p;
  };
  const sweep = () => {
    const t = now();
    for (const [id, p] of pending) if (t - p.at > pendingTtlMs) drop(id);
  };

  async function sentinel({ phase, path, headers = {}, body, requestId, signal }) {
    const p = String(path ?? '').split('?')[0];
    if (!CHAT_PATHS.has(p)) return null;
    const text = Buffer.isBuffer(body) ? body.toString('utf8') : String(body ?? '');
    // S5: URL path/query (request phase) and headers (both phases) are scanned for honeytokens too.
    const meta = { phase, path: phase === 'request' ? String(path ?? '') : '', headers: headers ?? {} };

    if (phase === 'request') {
      const bytes = Buffer.byteLength(text);
      if (pending.size >= maxPending || pendingBytes + bytes > maxPendingBytes) sweep();
      if (pending.size >= maxPending || pendingBytes + bytes > maxPendingBytes) {
        return contextFailure('request_context_full', { payload_size: pendingBytes + bytes, cap: maxPendingBytes, entries: pending.size, max_entries: maxPending });
      }
      // B2: a STABLE session key — the x-sentinel-session header, else a hash of the conversation's
      // opening turns (OpenAI clients resend the history, so it is the same on every turn). Never the
      // per-request id: that allocated one session per request and locked the detector out after 10k.
      const sessionId = String(headers[sessionHeader] ?? conversationKey(text)).slice(0, 128);
      const decision = det.inspect({ sessionId, request: text, meta, signal });
      const verdict = toInspectorVerdict(decision, 'request');
      if (verdict?.flagged) {
        // S1: a flagged request is NOT parked with benign ones. In observe mode the proxy forwards it and
        // the response still needs context, so it goes to the small FIFO-bounded flagged map instead.
        if (bytes <= maxFlaggedPendingBytes) {
          while (flaggedPending.size >= maxFlaggedPending || flaggedBytes + bytes > maxFlaggedPendingBytes) {
            dropFlagged(flaggedPending.keys().next().value);
            flaggedEvicted++;
          }
          flaggedPending.set(requestId, { text, bytes, at: now(), sessionId });
          flaggedBytes += bytes;
        }
        return verdict;
      }
      pending.set(requestId, { text, bytes, at: now(), sessionId });
      pendingBytes += bytes;
      return verdict;
    }

    if (phase === 'response') {
      const parked = drop(requestId) ?? dropFlagged(requestId);
      if (!parked) return contextFailure('request_context_missing', { requestId: String(requestId).slice(0, 64) });
      const decision = det.inspect({ sessionId: parked.sessionId, request: parked.text, response: text, meta, signal });
      return toInspectorVerdict(decision, 'response');
    }
    return null;
  }

  sentinel.detector = det;
  sentinel.pendingStats = () => ({ entries: pending.size, bytes: pendingBytes, maxPending, maxPendingBytes, flaggedEntries: flaggedPending.size, flaggedEvicted, maxFlaggedPending });
  return sentinel;
}

/**
 * Map a detector decision to the proxy hook's verdict shape, keeping only findings of this phase's
 * DIRECTION (request-phase findings were already reported pre-forward; the response phase reports
 * response-direction findings only). Returns null when nothing fired.
 *   flagged / disposition "block"  -> the proxy refuses; `prevents: true` says that refusal stops the harm.
 *   alert: true, flagged: false    -> post-execution evidence (in-process tools already ran): log an ALERT.
 */
export function toInspectorVerdict(decision, phase = null) {
  const findings = phase ? decision.findings.filter((f) => f.direction === phase || f.ruleId.startsWith('failclosed') || f.ruleId.startsWith('bounds')) : decision.findings;
  if (!findings.length) return null;
  const flagged = findings.some((f) => f.disposition === 'block');
  const would = findings.some((f) => f.wouldBlock);
  const reasons = [];
  const add = (r) => r && !reasons.includes(r) && reasons.push(r);
  for (const f of findings) {
    add(f.reason);
    for (const r of f.reasonCodes ?? []) add(r);
    if (f.canary?.id) add(`canary:${f.canary.id}`);
  }
  return {
    flagged,
    alert: true,
    detector: 'sentinel-t3',
    direction: phase ?? (findings.some((f) => f.direction === 'response') ? 'response' : 'request'),
    disposition: flagged ? 'block' : would ? (findings.some((f) => f.mode === 'report-only' && f.wouldBlock && !f.postExecution) ? 'report' : 'allow') : 'allow',
    prevents: findings.some((f) => f.prevents),
    postExecution: findings.some((f) => f.postExecution),
    toolExecution: decision.toolExecution,
    reasons,
    ruleIds: [...new Set(findings.map((f) => f.ruleId))],
    blockedToolCallIds: decision.blockedToolCallIds,
    failClosed: decision.failClosed,
    latencyMs: decision.stats.latencyMs,
    findings,
  };
}

/**
 * Stable conversation key when no session header is sent: sha256 over the model plus the first system
 * and first user turn. Constant across the turns of one conversation (history is resent), distinct across
 * conversations. Unparseable bodies get a per-body key (the detector fails them closed anyway).
 */
export function conversationKey(text) {
  const h = createHash('sha256');
  try {
    const req = JSON.parse(text);
    const msgs = Array.isArray(req?.messages) ? req.messages : [];
    const first = (role) => msgs.find((m) => m?.role === role)?.content ?? null;
    h.update(JSON.stringify([req?.model ?? null, first('system'), first('user')]));
  } catch {
    h.update(text);
  }
  return `conv:${h.digest('hex').slice(0, 32)}`;
}

function contextFailure(code, detail) {
  console.error(JSON.stringify({ level: 'ERROR', event: 'sentinel.inspector.fail_closed', reason: code, action: 'block', ...detail }));
  return { flagged: true, alert: true, detector: 'sentinel-t3', direction: code === 'request_context_missing' ? 'response' : 'request', disposition: 'block', prevents: code !== 'request_context_missing', postExecution: false, reasons: [code], ruleIds: ['failclosed.detector_error'], failClosed: true, findings: [] };
}
