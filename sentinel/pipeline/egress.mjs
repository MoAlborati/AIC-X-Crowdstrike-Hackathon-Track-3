// T12 egress JSONL record -> T4 `buildAlert` alert (direction "egress") + agent correlation.
//
// Input: one line of the T12 tool-boundary egress inspector log (sentinel/egress/inspector.mjs, #45):
//   { at, kind:'ALERT'|'egress', direction:'egress', action:'deny'|'forward', mode:'block'|'observe',
//     reasons:[...], failClosed, host, proto:'http'|'connect', method, url_bytes, body_bytes, size, cap,
//     url_sha256, canary_ids:[...], secret_kinds:[...], request_id, latency_ms, alert:<T4 alert>|null }
//
// Redaction first: the egress record is UNTRUSTED for secrecy. It can carry raw hosts / URLs / paths
// (a DNS-exfil hostname can itself be the secret; egress log redaction is being fixed separately on
// t12-fix). So the WHOLE record goes through T4 `redactDeep` with every known canary before any field
// is read, and buildAlert redacts again. Nothing from the raw record reaches the alert unredacted.
//
// Enforcement label: a `deny` at this boundary happens BEFORE the bytes leave the sandbox, so it is
// PREVENTIVE. That is the opposite of response-side chat-proxy alerts, which are alert-only (DVAA runs
// the tool in-process before replying). A `forward` (observe mode, or a secret-pattern-only hit) is
// alert-only.
//
// Correlation (attribution only: it never changes a verdict, the inspector already decided):
//   1. explicit port on the record (`agent_port` / `agent.port`) when T12 provides one
//   2. time window: the egress `at` falls inside exactly one chat-proxy session's in-flight windows
//      [ts, ts + latency_ms] (strict first; ± CORRELATION_SLACK_MS only if no window strictly
//      contains it). DVAA runs tools in-process during the turn, so
//      an egress inside a turn's window came from that turn's agent.
//   Zero matches or several candidate sessions -> standalone egress incident (never a guess).

import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildAlert } from '../alerts/index.js';
import { redactDeep } from '../alerts/redact.js';
import { PIPELINE_SCHEMA } from './convert.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const EGRESS_HONEYTOKENS_PATH = path.resolve(HERE, '..', 'egress', 'honeytokens.json');
export const EGRESS_DETECTOR = 'sentinel-egress';
export const EGRESS_SESSION = 'egress-boundary';
export const EGRESS_AGENT = Object.freeze({ name: 'DVAA tool boundary (agent not attributed)', id: 'egress-boundary' });

// Clock slack between the inspector container and the proxy host clock (same machine; ms skew).
export const CORRELATION_SLACK_MS = 500;
// Candidate sessions listed in PipelineContext.Correlation when ambiguous. DISPLAY cap only: the
// ambiguity decision uses the full candidate set; `CandidateCount` is always the full count.
const MAX_LISTED_CANDIDATES = 8;

export const EGRESS_POLICY = Object.freeze({
  label: 'egress (tool boundary)',
  preventive: Object.freeze({
    enforcement: 'preventive',
    note: 'PREVENTED: denied at the tool-boundary egress inspector before any byte left the sandbox.',
  }),
  alertOnly: Object.freeze({
    enforcement: 'alert_only',
    note: 'Alert only: the egress inspector forwarded this request (observe mode or evidence-only finding).',
  }),
});

/** Is this JSONL record a T12 egress inspector record (not a T2 proxy record)? */
export const isEgressRecord = (r) => !!r && typeof r === 'object' && r.type === undefined && r.direction === 'egress';

/** T12 deployment honeytokens (sentinel/egress/honeytokens.json) as {id, value}; [] when absent. */
export function loadEgressHoneytokens(file = EGRESS_HONEYTOKENS_PATH) {
  if (!existsSync(file)) return [];
  const list = JSON.parse(readFileSync(file, 'utf8'));
  if (!Array.isArray(list)) throw new Error(`${file}: expected an array of {id, value}`);
  return list.map(({ id, value }) => ({ id, value }));
}

/** Port named explicitly on the record (future T12 field), else null. */
export function explicitPort(rec) {
  const p = Number(rec?.agent_port ?? rec?.agent?.port);
  return Number.isInteger(p) && p > 0 && p < 65536 ? p : null;
}

/** Category + rule from the inspector's own alert, else from its reason codes (same order as T12 policy). */
function categoryOf(rec) {
  if (typeof rec.alert?.Category === 'string' && typeof rec.alert?.RuleId === 'string') return [rec.alert.Category, rec.alert.RuleId];
  const reasons = Array.isArray(rec.reasons) ? rec.reasons : [];
  if (reasons.includes('honeytoken_match')) return ['honeytoken_exfil', 'egress.honeytoken_match'];
  if (rec.failClosed && reasons.length) return ['scan_cap_exceeded', `egress.failclosed.${reasons[0]}`];
  if (reasons.includes('destination_not_allowlisted')) return ['egress_unallowlisted_domain', 'egress.destination_not_allowlisted'];
  return ['egress_secret_pattern', 'egress.secret_pattern_match'];
}

export function outcomeOf(rec) {
  if (rec.action === 'deny') return rec.failClosed ? 'denied_fail_closed_bytes_never_left' : 'denied_before_send_bytes_never_left';
  return rec.mode === 'observe' ? 'forwarded_observe_only_would_block' : 'forwarded_alert_only';
}

/**
 * Correlate one egress record to a chat-proxy session.
 * @param {object} rec  redacted egress record
 * @param {{windows: Array<{start,end,session,agent,requestId}>, horizon: number, sessionByPort: Map}} index
 */
export function correlate(rec, { windows, horizon = -Infinity, sessionByPort = new Map() }) {
  const at = Date.parse(rec.at);
  const port = explicitPort(rec);
  if (!Number.isFinite(at)) return { method: 'none', reason: 'egress record has no parseable `at` timestamp' };
  if (at < horizon) return { method: 'none', reason: 'correlation_history_evicted (MAX_CORRELATION_WINDOWS)', port };
  // Strict containment first (back-to-back turns are often < SLACK apart); slack only when nothing contains it.
  const inWindow = (slack) => windows.filter((w) => at >= w.start - slack && at <= w.end + slack
    && (port == null || w.agent?.port === port));
  let hits = inWindow(0);
  if (!hits.length) hits = inWindow(CORRELATION_SLACK_MS);
  const sessions = [...new Map(hits.map((w) => [w.session, w])).values()];
  if (sessions.length === 1) {
    const w = sessions[0];
    return { method: port != null ? 'port+time_window' : 'time_window', session: w.session, agent: w.agent, requestIds: hits.map((h) => h.requestId) };
  }
  if (sessions.length > 1) {
    return {
      method: 'none',
      reason: 'ambiguous: egress falls inside the in-flight window of several sessions',
      candidateCount: sessions.length,
      candidates: sessions.slice(0, MAX_LISTED_CANDIDATES).map((w) => ({ session: w.session, port: w.agent?.port ?? null, requestId: w.requestId })),
    };
  }
  if (port != null && sessionByPort.has(port)) {
    const s = sessionByPort.get(port);
    return { method: 'port', session: s.session, agent: s.agent };
  }
  return { method: 'none', reason: 'no chat-proxy exchange in flight at this time', ...(port != null ? { port } : {}) };
}

/**
 * Build the T4 alert for one flagged egress record. Returns null for an unflagged (allowed) record.
 * @param {object} raw   egress JSONL record as read from disk (possibly with raw hosts)
 * @param {{canaries: {id,value}[], correlation: object, captureRef?: object, onWarning?: Function}} ctx
 */
export function alertForEgress(raw, ctx) {
  if (!isEgressRecord(raw)) throw new Error('alertForEgress: not a T12 egress record');
  const canaries = ctx.canaries ?? [];
  // Redact the WHOLE record before reading any field (raw hosts / URLs / paths may hold secrets).
  const { value: rec, findings } = redactDeep(raw, { canaries });
  const flagged = rec.kind === 'ALERT' || rec.alert != null || rec.failClosed === true;
  if (!flagged) return null;
  const [category, ruleId] = categoryOf(rec);
  const deny = rec.action === 'deny';
  const policy = deny ? EGRESS_POLICY.preventive : EGRESS_POLICY.alertOnly;
  const outcome = outcomeOf(rec);
  const corr = ctx.correlation ?? { method: 'none', reason: 'not correlated' };
  const correlated = corr.method !== 'none';
  const agent = correlated ? corr.agent : { ...EGRESS_AGENT, ...(corr.port ? { port: corr.port } : {}) };
  const session = correlated ? corr.session : EGRESS_SESSION;
  const proto = typeof rec.proto === 'string' ? rec.proto : 'unknown';
  const method = typeof rec.method === 'string' ? rec.method : (proto === 'connect' ? 'CONNECT' : 'UNKNOWN');
  const host = typeof rec.host === 'string' && rec.host ? rec.host : '[host not recorded]';
  const destination = rec.alert?.Entities?.Sink?.Destination ?? (proto === 'connect' ? `connect://${host}` : `${proto}://${host}`);
  const toolCall = { id: String(rec.request_id ?? `egress:${rec.at}`), name: `egress.${proto}.${method}` };
  const sink = { type: proto === 'connect' ? 'connect_tunnel' : 'http_egress', destination };
  const originatedIn = correlated
    ? `agent turn on ${agent.name} (chat-proxy request ${(corr.requestIds ?? []).join(', ') || 'by port'})`
    : 'unattributed agent turn (no single chat-proxy exchange in flight)';
  let canary;
  const canaryId = rec.alert?.Canary?.Id;
  if (typeof canaryId === 'string' && canaryId) {
    canary = canaries.find((c) => c.id === canaryId);
    // An id we cannot rehydrate cannot be redacted reliably: fail loud (same rule as proxy verdicts).
    if (!canary) throw new Error(`egress record ${rec.request_id} names canary ${canaryId}, which is not in the pipeline's canary list`);
  }
  const reasons = Array.isArray(rec.reasons) ? rec.reasons.map(String) : [];
  const latency = Number.isFinite(rec.latency_ms) && rec.latency_ms >= 0 ? rec.latency_ms : 0;
  const verdict = {
    category,
    ruleId,
    disposition: deny ? 'block' : 'allow',
    detectionLatencyMs: latency,
    entities: { agent, session: { id: session }, toolCall, sink },
    taintPath: [
      { kind: 'source', label: originatedIn, trust: 'untrusted' },
      { kind: 'sink', label: `tool-boundary egress ${method} → ${destination}`, toolCallId: toolCall.id, trust: 'external' },
    ],
    evidence: typeof rec.alert?.Evidence === 'string' ? rec.alert.Evidence
      : `egress ${method} ${destination} size=${rec.size} reasons=[${reasons.join(',')}] mode=${rec.mode} action=${rec.action}`,
    ...(canary ? { canary } : {}),
    canaries,
    layers: (reasons.length ? reasons : ['flagged']).map((r) => ({ layer: 'egress', rule: `egress.${r}`, fired: true, latencyMs: latency })),
    caseCard: {
      originatedIn,
      narrative: `[${EGRESS_POLICY.label} · ${policy.enforcement}] Instruction originated in ${originatedIn} → ` +
        `influenced tool call ${toolCall.name}(${toolCall.id}) → toward ${sink.type}:${destination} → ` +
        `${deny ? 'blocked' : 'allowed (observed)'} by rule ${ruleId}. Outcome: ${outcome}. ${policy.note}`,
    },
    timestamp: rec.at,
    alertId: `egress:${toolCall.id}`,
  };
  const alert = buildAlert(verdict, ctx.onWarning ? { onWarning: ctx.onWarning } : {});
  return Object.freeze({
    ...alert,
    PipelineContext: Object.freeze({
      Schema: PIPELINE_SCHEMA,
      Direction: 'egress',
      DirectionLabel: EGRESS_POLICY.label,
      Enforcement: policy.enforcement,
      Preventive: deny,
      Outcome: outcome,
      ProxyMode: rec.mode ?? null,
      ProxyAction: rec.action ?? null,
      RequestId: rec.request_id ?? null,
      Detector: EGRESS_DETECTOR,
      StandIn: false,
      RequestedDisposition: deny ? 'block' : 'allow',
      LatencySource: 'detector',
      Correlation: Object.freeze({ ...corr, agent: undefined, ...(correlated ? { session, port: agent.port ?? null } : {}) }),
      // Secrets/patterns found in the RAW egress record before the alert was built (count only).
      RawRecordRedactions: findings.length,
      ProxyCapture: ctx.captureRef ?? null,
    }),
  });
}

/** One-line, already-redacted summary of an egress alert for the incident capture's stub exchange. */
export function egressSummaryLine(alert) {
  const pc = alert.PipelineContext;
  const verb = pc.Preventive ? 'PREVENTED (denied before send)' : 'ALERT ONLY (forwarded)';
  return `${alert.Timestamp} ${verb} ${alert.Entities?.ToolCall?.Name ?? 'egress'} → ${alert.Entities?.Sink?.Destination ?? '?'} · ${alert.DetectName} (${alert.SeverityName}) · rule ${alert.RuleId}`;
}
