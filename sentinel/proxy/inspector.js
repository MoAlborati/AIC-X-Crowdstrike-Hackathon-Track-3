// SentinelProxy T2 — the inspector hook contract (T3 implements it).
//
// An inspector is a plain object with any of:
//   name: string
//   inspectRequest(ctx)  -> Decision | undefined | Promise<Decision | undefined>   (pre-forward)
//   inspectResponse(ctx) -> Decision | undefined | Promise<Decision | undefined>   (post-response)
//
// Decision:
//   {
//     action: 'allow' | 'block',            // required
//     reason?: string,                      // human-readable, goes into the refusal + capture record
//     ruleId?: string,                      // defaults to verdict.ruleId
//     verdict?: <T4 verdict>,               // sentinel/alerts VERDICT_SHAPE. The proxy fills in
//                                           // `disposition` (from mode + action), `detectionLatencyMs`
//                                           // (measured, if absent), `entities.agent` (target) and
//                                           // `entities.session` (if absent), then calls buildAlert().
//   }
// `undefined`/`null` means allow with nothing to report.
//
// Request ctx  : { phase:'request', requestId, sessionId, mode, target, method, path, headers,
//                  body: Buffer, text: string, json: object|null, limits }
// Response ctx : { phase:'response', ...request ctx fields, request: { headers, body, text, json },
//                  response: { status, headers, body, text, json }, dvaa: object|null, toolCalls: array }
// Both bodies are COMPLETE (bounded by limits.maxRequestBytes / maxResponseBytes; anything larger was
// rejected before the inspector runs). Inspectors must treat ctx as read-only.
//
// Failure semantics (enforced by runInspector + server.js):
//   throw / reject / exceed limits.inspectorTimeoutMs / return a malformed Decision
//     -> block mode: fail CLOSED (deny + ALERT)   observe mode: forward + loud ALERT log.
//   A synchronous infinite loop cannot be pre-empted in-process; inspectors must be bounded themselves.

export const ACTIONS = Object.freeze(['allow', 'block']);

/** Default inspector: allow everything, report nothing. */
export const NOOP_INSPECTOR = Object.freeze({
  name: 'noop',
  inspectRequest: () => undefined,
  inspectResponse: () => undefined,
});

export class InspectorFailure extends Error {
  /** @param {'error'|'timeout'|'contract'} kind */
  constructor(kind, message, cause) {
    super(message, { cause });
    this.name = 'InspectorFailure';
    this.kind = kind;
  }
}

export function normalizeDecision(raw) {
  if (raw === undefined || raw === null) return { action: 'allow', reason: null, ruleId: null, verdict: null };
  if (typeof raw !== 'object' || Array.isArray(raw)) {
    throw new InspectorFailure('contract', `inspector returned ${Array.isArray(raw) ? 'array' : typeof raw}, expected Decision object or undefined`);
  }
  if (!ACTIONS.includes(raw.action)) {
    throw new InspectorFailure('contract', `inspector Decision.action=${JSON.stringify(raw.action)} must be one of ${ACTIONS.join('|')}`);
  }
  if (raw.verdict !== undefined && raw.verdict !== null && (typeof raw.verdict !== 'object' || Array.isArray(raw.verdict))) {
    throw new InspectorFailure('contract', 'inspector Decision.verdict must be an object (sentinel/alerts verdict)');
  }
  return {
    action: raw.action,
    reason: raw.reason == null ? null : String(raw.reason),
    ruleId: raw.ruleId ?? raw.verdict?.ruleId ?? null,
    verdict: raw.verdict ?? null,
  };
}

/**
 * Run one inspector phase under a timeout. Never throws for inspector misbehaviour: returns
 * { ok: true, decision, latencyMs } or { ok: false, failure: InspectorFailure, latencyMs }.
 */
export async function runInspector(inspector, phase, ctx, timeoutMs) {
  const fn = phase === 'request' ? inspector.inspectRequest : inspector.inspectResponse;
  const t0 = performance.now();
  if (typeof fn !== 'function') return { ok: true, decision: normalizeDecision(undefined), latencyMs: 0 };
  let timer;
  try {
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(
        () => reject(new InspectorFailure('timeout', `inspector "${inspector.name ?? 'anonymous'}" ${phase} phase exceeded ${timeoutMs}ms`)),
        timeoutMs,
      );
    });
    const raw = await Promise.race([Promise.resolve().then(() => fn.call(inspector, ctx)), timeout]);
    return { ok: true, decision: normalizeDecision(raw), latencyMs: performance.now() - t0 };
  } catch (err) {
    const failure =
      err instanceof InspectorFailure
        ? err
        : new InspectorFailure('error', `inspector "${inspector.name ?? 'anonymous'}" ${phase} phase threw: ${err?.message ?? err}`, err);
    return { ok: false, failure, latencyMs: performance.now() - t0 };
  } finally {
    clearTimeout(timer);
  }
}
