// SentinelProxy T3 -> T2 adapter. Matches the proxy's inspector hook (sentinel/proxy/inspectors.mjs, PR #14):
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
// tool-call findings are returned with `flagged: false, alert: true, postExecution: true`: evidence, never
// claimed prevention. Every verdict carries `direction` and `prevents`. (toolExecution: "client" restores
// response-side blocking for agents whose client executes tool_calls.)

import { createDetector } from './detector.js';

const CHAT_PATHS = new Set(['/v1/chat/completions', '/chat/completions']);

export function sentinelInspector(opts = {}) {
  const det = opts.detector ?? createDetector(opts);
  const sessionHeader = (opts.sessionHeader ?? 'x-sentinel-session').toLowerCase();
  const maxPending = opts.maxPendingRequests ?? 1024;
  const maxPendingBytes = opts.maxPendingBytes ?? 64 * 1024 * 1024;
  const pendingTtlMs = opts.pendingTtlMs ?? 120000;
  const now = opts.now ?? Date.now;
  const pending = new Map(); // requestId -> {text, bytes, at, sessionId}
  let pendingBytes = 0;

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

  async function sentinel({ phase, path, headers = {}, body, requestId }) {
    const p = String(path ?? '').split('?')[0];
    if (!CHAT_PATHS.has(p)) return null;
    const text = Buffer.isBuffer(body) ? body.toString('utf8') : String(body ?? '');
    const sessionId = String(headers[sessionHeader] ?? requestId ?? 'unknown-session').slice(0, 128);

    if (phase === 'request') {
      const bytes = Buffer.byteLength(text);
      if (pending.size >= maxPending || pendingBytes + bytes > maxPendingBytes) sweep();
      if (pending.size >= maxPending || pendingBytes + bytes > maxPendingBytes) {
        return contextFailure('request_context_full', { payload_size: pendingBytes + bytes, cap: maxPendingBytes, entries: pending.size, max_entries: maxPending });
      }
      const decision = det.inspect({ sessionId, request: text });
      // Park even a flagged request: in observe mode the proxy forwards it and the response still needs
      // its context. (A block-mode refusal never produces a response; the entry ages out via TTL.)
      pending.set(requestId, { text, bytes, at: now(), sessionId });
      pendingBytes += bytes;
      return toInspectorVerdict(decision, 'request');
    }

    if (phase === 'response') {
      const parked = drop(requestId);
      if (!parked) return contextFailure('request_context_missing', { requestId: String(requestId).slice(0, 64) });
      const decision = det.inspect({ sessionId: parked.sessionId, request: parked.text, response: text });
      return toInspectorVerdict(decision, 'response');
    }
    return null;
  }

  sentinel.detector = det;
  sentinel.pendingStats = () => ({ entries: pending.size, bytes: pendingBytes, maxPending, maxPendingBytes });
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

function contextFailure(code, detail) {
  console.error(JSON.stringify({ level: 'ERROR', event: 'sentinel.inspector.fail_closed', reason: code, action: 'block', ...detail }));
  return { flagged: true, alert: true, detector: 'sentinel-t3', direction: code === 'request_context_missing' ? 'response' : 'request', disposition: 'block', prevents: code !== 'request_context_missing', postExecution: false, reasons: [code], ruleIds: ['failclosed.detector_error'], failClosed: true, findings: [] };
}
