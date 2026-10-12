// Proxy record -> T4 verdict(s) -> T4 `buildAlert` -> alert + PipelineContext (direction labels).
//
// Input: one T2 capture record (sentinel/proxy/server.mjs, PR #14):
//   exchange: { type:'exchange', ts, request_id, mode, target, request:{method,path,headers,body},
//               response:{status,headers,body}, upstream_response?, verdicts:[{phase,...}], action,
//               latency_ms }
//   alert:    { type:'alert', ts, request_id, mode, reason, phase?, verdicts?, payload_size?, cap?, ... }
//   request:  { type:'request', ... } write-ahead record (PR #14 27212c7). The exchange record follows.
// Bodies are { encoding:'utf8'|'base64'|'omitted', bytes, data }. When the wire body was
// content-encoded (gzip/br/deflate), T2 also records `decoded_body`, and that is what we parse.
//
// Three verdict shapes are accepted:
//   1. T3/T4-shaped     { category, ruleId, disposition?, ... }       one alert, passed through
//   2. findings list    { findings:[{category, ruleId, ...}], detector, standIn? }   one alert per finding.
//                       Real T3 (`detector: 'sentinel-t3'`, the default source) or the stand-in fallback
//                       (`standIn: true`). T3 canaries are {id, sha256}; buildOne rehydrates them with
//                       T3's toAlertVerdict() right before buildAlert.
//   3. generic flagged  { flagged:true, detector, reasons, hits? }     one alert. This is the T2
//                       placeholder substring inspector, so it is labeled stand-in.

import { buildAlert, sinkPhrase } from '../alerts/index.js';
import { T3_DETECTOR } from './t3.mjs';

export const PIPELINE_SCHEMA = 'sentinel.pipeline/1.0.0';

// Direction policy, as data. Why response-side can never block: DVAA agents run their tools
// IN-PROCESS while producing the reply (e.g. RAGBot's submit_to_index POSTs before it answers). By
// the time the proxy sees the response, the side effect has already happened. Withholding the reply
// does not undo it.
export const DIRECTION_POLICY = Object.freeze({
  request: Object.freeze({
    label: 'request-side',
    enforcement: 'blocking',
    note: 'Checked before the agent sees the request. In block mode the proxy refuses it, so no tool runs.',
  }),
  response: Object.freeze({
    label: 'response-side',
    enforcement: 'alert_only',
    note: 'Alert only: DVAA executes tools in-process before replying, so the side effect already happened when the proxy saw the response.',
  }),
});

/** T4 disposition + outcome for a verdict, given its direction and what the proxy actually did. */
export function dispositionFor(direction, record) {
  const action = record.action ?? null;
  if (direction === 'request') {
    if (action === 'blocked_request') return { disposition: 'block', outcome: 'blocked_before_agent' };
    return { disposition: 'report', outcome: record.mode === 'observe' ? 'would_block_observe_only' : 'not_blocked' };
  }
  if (direction === 'response') {
    return {
      disposition: 'report',
      outcome: action === 'blocked_response' ? 'reply_withheld_tool_already_executed' : 'reply_delivered_tool_already_executed',
    };
  }
  throw new Error(`unknown direction ${JSON.stringify(direction)}`);
}

export function decodeBody(b) {
  if (!b || b.encoding === 'omitted' || typeof b.data !== 'string') return null;
  return b.encoding === 'base64' ? Buffer.from(b.data, 'base64').toString('utf8') : b.data;
}

/** The body the inspectors saw: `decoded_body` when the wire body was content-encoded, else `body`. */
export const inspectedBody = (part) => part?.decoded_body ?? part?.body;

export function parseJsonBody(b) {
  const text = decodeBody(b);
  if (text == null) return null;
  try { return JSON.parse(text); } catch { return null; }
}

const SESSION_HEADERS = ['x-sentinel-session', 'x-session-id'];
const SAFE_ID = /^[A-Za-z0-9_.-]{1,64}$/;

/** Session key: explicit header, then OpenAI `user`, then one session per proxy target. */
export function sessionOf(record, reqJson = parseJsonBody(inspectedBody(record.request))) {
  const h = record.request?.headers ?? {};
  for (const k of SESSION_HEADERS) if (typeof h[k] === 'string' && h[k].trim()) return h[k].trim();
  if (typeof reqJson?.user === 'string' && reqJson.user.trim()) return reqJson.user.trim();
  const port = String(record.target ?? '').split(':').pop();
  return port ? `proxy-${port}` : 'proxy-unknown-target';
}

/** Filesystem-safe session slug. Anything odd is replaced, so no session id can traverse paths. */
export function sessionSlug(session) {
  const s = String(session).replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 64);
  return SAFE_ID.test(s) && s.replace(/_/g, '') ? s : 'session';
}

export function agentOf(record, resJson) {
  const port = Number(String(record.target ?? '').split(':').pop()) || null;
  const model = typeof resJson?.model === 'string' && resJson.model ? resJson.model : null;
  return {
    name: model ? `${model}${port ? ` :${port}` : ''}` : `dvaa${port ? ` :${port}` : ''}`,
    id: model ? `dvaa-${model}` : `dvaa-port-${port ?? 'unknown'}`,
    ...(port ? { port } : {}),
  };
}

const VERB = { block: 'blocked', report: 'reported (alert-only)', allow: 'allowed (observed)' };

// The bracket prefix states what actually happened ("blocking" only when this verdict blocked), so an
// observe-mode / forwarded record never reads as a block. With no tool call, say what the instruction
// asked for instead of "influenced tool call no tool call".
function narrativeFor({ policy, outcome, originatedIn, toolCall, sink, disposition, ruleId }) {
  const enforcement = disposition === 'block' ? 'blocking' : 'alert_only';
  const action = toolCall ? `influenced tool call ${toolCall.name}(${toolCall.id})${sink ? ` → toward ${sinkPhrase(sink)}` : ''}`
    : sink ? `asked the agent to send session data to ${sinkPhrase(sink)}` : 'no tool call was made';
  const note = disposition === 'block' || policy.label !== 'request-side' ? policy.note
    : 'Checked before the agent saw the request, but this exchange was not refused, so the agent ran.';
  return `[${policy.label} · ${enforcement}] Instruction originated in ${originatedIn} → ${action} → ` +
    `${VERB[disposition]} by rule ${ruleId}. Outcome: ${outcome}. ${note}`;
}

/** Normalize one recorded verdict into T4-verdict "parts" (before entities/disposition are filled). */
export function verdictParts(v, record) {
  if (Array.isArray(v.findings)) {
    return v.findings.map((f) => ({ ...f, standIn: v.standIn === true || f.standIn === true, detector: v.detector ?? 'standin' }));
  }
  if (typeof v.category === 'string' && typeof v.ruleId === 'string') {
    return [{ ...v, standIn: v.standIn === true, detector: v.detector ?? v.ruleId, requestedDisposition: v.disposition ?? null }];
  }
  // Generic flagged verdict (T2 placeholder substring inspector or anything else T3-unaware).
  const needles = Array.isArray(v.hits) ? v.hits.map((h) => h?.needle).filter((n) => typeof n === 'string' && n) : [];
  const phase = v.phase;
  return [{
    category: phase === 'request' ? 'indirect_prompt_injection' : 'honeytoken_exfil',
    ruleId: `proxy.${v.detector ?? 'inspector'}`,
    evidence: `${v.detector ?? 'inspector'}: ${(v.reasons ?? []).map(String).join('; ') || 'flagged'}`,
    canaries: needles.map((value, i) => ({ id: `${v.detector ?? 'inspector'}-needle-${i + 1}`, value })),
    standIn: true,
    detector: v.detector ?? 'inspector',
    requestedDisposition: v.disposition ?? null,
    latencyMs: Number.isFinite(v.detectionLatencyMs) ? v.detectionLatencyMs : undefined,
  }];
}

/**
 * Build T4 alerts for every verdict on an exchange record.
 * @param {object} record  T2 `exchange` record
 * @param {{session: string, captureRef?: object, canaries?: {id,value}[], onWarning?: Function}} ctx
 * @returns {object[]} frozen T4 alerts, each with an added PipelineContext
 */
export function alertsForExchange(record, ctx) {
  const resJson = parseJsonBody(inspectedBody(record.upstream_response ?? record.response));
  const agent = agentOf(record, resJson);
  const reqBytes = record.request?.body?.bytes ?? 0;
  const out = [];
  const counters = { request: 0, response: 0 };
  for (const v of record.verdicts ?? []) {
    const direction = v.phase;
    if (!DIRECTION_POLICY[direction]) throw new Error(`verdict on request ${record.request_id} has no valid phase: ${JSON.stringify(direction)}`);
    for (const part of verdictParts(v, record)) {
      out.push(buildOne({ record, ctx, agent, direction, part, n: counters[direction]++, reqBytes, resJson }));
    }
  }
  return out;
}

/** T4 alerts for proxy `alert` records that are detections in their own right (scan cap hits). */
export function alertsForProxyAlert(record, ctx) {
  if (record.reason !== 'request_too_large' && record.reason !== 'response_too_large') return [];
  const direction = record.phase === 'response' ? 'response' : 'request';
  const part = {
    category: 'scan_cap_exceeded',
    ruleId: `proxy.${record.reason}`,
    evidence: `payload_size=${record.payload_size}${record.size_is_lower_bound ? '+' : ''} cap=${record.cap} action=${record.action}`,
    standIn: false,
    detector: 'proxy.bounds',
  };
  const synthetic = { ...record, action: direction === 'request' ? 'blocked_request' : 'blocked_response', target: ctx.target ?? record.target };
  return [buildOne({ record: synthetic, ctx, agent: ctx.agent ?? agentOf(synthetic, null), direction, part, n: 0, reqBytes: record.payload_size ?? 0, idSuffix: 'cap' })];
}

/** Tool call by id in a recorded response, for ArgsPreview (verdicts carry ids, not raw args). */
function recordedToolCall(resJson, id) {
  for (const c of Array.isArray(resJson?.choices) ? resJson.choices : []) {
    for (const tc of Array.isArray(c?.message?.tool_calls) ? c.message.tool_calls : []) {
      if (tc?.id === id) {
        const a = tc.function?.arguments ?? tc.arguments;
        return typeof a === 'string' ? a : a == null ? null : JSON.stringify(a);
      }
    }
  }
  return null;
}

function buildOne({ record, ctx, agent, direction, part: rawPart, n, reqBytes, idSuffix = '', resJson = null }) {
  let part = rawPart;
  if (part.detector === T3_DETECTOR) {
    // T3 findings are secret-free; T4 needs the canary value to hash + redact. Rehydrate by id, only here.
    if (typeof ctx.t3?.toAlertVerdict !== 'function') {
      throw new Error(`T3 verdict on request ${record.request_id} but the pipeline has no T3 registry to rehydrate its canaries`);
    }
    const v = ctx.t3.toAlertVerdict(part);
    // The proxy target names the agent; T3's inspector is not configured per agent.
    part = { ...v, entities: { ...(v.entities ?? {}), agent: undefined }, standIn: false, detector: T3_DETECTOR };
  }
  const policy = DIRECTION_POLICY[direction];
  const { disposition, outcome } = dispositionFor(direction, record);
  const originatedIn = direction === 'request'
    ? `request body (${reqBytes} B; user turn and any supplied document)`
    : 'request content (source provenance not tracked by this detector)';
  let toolCall = part.toolCall ?? part.entities?.toolCall ?? null;
  if (toolCall && toolCall.argsPreview === undefined && resJson) {
    const args = recordedToolCall(resJson, toolCall.id);
    if (args != null) toolCall = { ...toolCall, argsPreview: args };
  }
  let canary = part.canary;
  if (!canary && part.canaryId) {
    canary = (ctx.canaries ?? []).find((c) => c.id === part.canaryId);
    // A verdict naming a honeytoken we do not know cannot be redacted reliably: fail loud.
    if (!canary) throw new Error(`verdict on request ${record.request_id} names canary ${part.canaryId}, which is not in the pipeline's canary list`);
  }
  let sink = part.sink ?? part.entities?.sink ?? null;
  let tc = toolCall;
  // Sink categories need a tool call + sink. When a verdict did not name one, the reply itself is the
  // sink, and it is labeled as such instead of being invented.
  if (['honeytoken_exfil', 'taint_flow_exfil', 'egress_secret_pattern', 'egress_markdown_image', 'egress_unallowlisted_domain'].includes(part.category) && (!tc || !sink)) {
    tc = tc ?? { id: `${direction}:${record.request_id}`, name: direction === 'request' ? 'request_body' : 'assistant_reply' };
    sink = sink ?? { type: direction === 'request' ? 'agent_input' : 'chat_response', destination: direction === 'request' ? `agent ${record.target ?? ''}`.trim() : 'proxy client' };
  }
  const taintPath = part.taintPath ?? [
    { kind: 'source', label: originatedIn, trust: 'untrusted' },
    ...(sink ? [{ kind: 'sink', label: `${tc?.name ?? 'sink'} → ${sink.destination}`, toolCallId: tc?.id, trust: 'external' }] : []),
  ];
  const alertId = `${record.request_id ?? 'no-request-id'}:${direction}:${n}${idSuffix ? `:${idSuffix}` : ''}`;
  const latency = [part.latencyMs, part.detectionLatencyMs].find((x) => Number.isFinite(x) && x >= 0);
  const verdict = {
    category: part.category,
    ruleId: part.ruleId,
    disposition,
    // Inspector latency when the detector reported it. Otherwise the proxy's whole-exchange latency,
    // labeled as such in PipelineContext.LatencySource.
    detectionLatencyMs: latency ?? (Number.isFinite(record.latency_ms) ? record.latency_ms : 0),
    entities: {
      agent: part.entities?.agent ?? agent,
      session: { id: ctx.session },
      ...(tc ? { toolCall: tc } : {}),
      ...(sink ? { sink } : {}),
    },
    taintPath,
    evidence: part.evidence,
    ...(canary ? { canary } : {}),
    canaries: [...(ctx.canaries ?? []), ...(part.canaries ?? [])],
    layers: part.layers ?? [{ layer: part.standIn ? 'standin' : (part.detector ?? 'detector'), rule: part.ruleId, fired: true, ...(latency !== undefined ? { latencyMs: latency } : {}) }],
    ...(Number.isFinite(part.severity) ? { severity: part.severity } : {}),
    caseCard: {
      ...(part.caseCard ?? {}),
      // No tool call: say why, instead of T3/T4's literal "no tool call".
      ...(tc ? {} : { influencedToolCall: disposition === 'block' && direction === 'request' ? 'none: refused before the agent saw the request' : 'none recorded' }),
      narrative: narrativeFor({ policy, outcome, originatedIn: part.caseCard?.originatedIn ?? originatedIn, toolCall: tc, sink, disposition, ruleId: part.ruleId }),
    },
    timestamp: record.ts,
    alertId,
  };
  const alert = buildAlert(verdict, ctx.onWarning ? { onWarning: ctx.onWarning } : {});
  return Object.freeze({
    ...alert,
    PipelineContext: Object.freeze({
      Schema: PIPELINE_SCHEMA,
      Direction: direction,
      DirectionLabel: policy.label,
      Enforcement: policy.enforcement,
      Outcome: outcome,
      ProxyMode: record.mode ?? null,
      ProxyAction: record.action ?? null,
      RequestId: record.request_id ?? null,
      Detector: part.detector ?? null,
      StandIn: part.standIn === true,
      RequestedDisposition: part.requestedDisposition ?? null,
      LatencySource: latency !== undefined ? 'detector' : 'proxy_exchange_latency',
      ProxyCapture: ctx.captureRef ?? null,
    }),
  });
}
