// Output store: writes what the T5 dashboard (PR #11) reads.
//
//   <outDir>/captures/live/<session>[--pNNN].json      capture, `openai` shape with exchanges[]
//   <outDir>/alerts/live__<session>[--pNNN].alerts.json T4 sidecar {captureId, runs:{run:[alert…]}}
//   <outDir>/ops-alerts.jsonl                          proxy operational alerts (not detections)
//
// Point the dashboard at it with
//   SENTINEL_CAPTURES_DIR=<outDir>/captures SENTINEL_ALERTS_DIR=<outDir>/alerts
// The capture id is the path under captures/ without `.json` (T5 capture-loader). The sidecar name
// is that id with '/' -> '__' (T5 alert-store `sidecarName`).
//
// Files are written atomically (tmp + rename), so the dashboard never reads half a file. Mode is
// 0600: bodies hold the same (fake, sandbox) secrets as the proxy JSONL.

import { mkdir, rename, writeFile, appendFile, rm } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { BOUNDS, enforce, defaultLog } from './bounds.mjs';
import { decodeBody, sessionSlug, inspectedBody } from './convert.mjs';

export const CAPTURE_SUBDIR = 'live';
export const RUN_KEY = 'run'; // T5 normalizeOpenAI always names the single run 'run'

export const STANDIN_NOTE =
  'STAND-IN verdicts: produced by sentinel/pipeline/standin.mjs (or the T2 placeholder substring inspector) ' +
  'because T3 (origin/t3-detector-core) does not exist yet. Real T4 alerts built by buildAlert, but NOT T3 detector output.';

const sha = (s) => createHash('sha256').update(s).digest('hex').slice(0, 16);

function bodyForDisplay(b) {
  const text = decodeBody(b);
  if (text == null) {
    return { json: null, note: b?.encoding === 'omitted' ? `[body not recorded by proxy: ${b.reason ?? 'omitted'}, ${b.bytes ?? '?'} B]` : '[no body]' };
  }
  try { return { json: JSON.parse(text) }; } catch { return { json: null, note: `[non-JSON body, ${Buffer.byteLength(text)} B]`, raw: text }; }
}

/** One capture exchange built from a T2 exchange record. Bodies kept whole (subject to the embed cap). */
export function captureExchange(record, { proxyCapturePath, line } = {}) {
  const req = bodyForDisplay(inspectedBody(record.request));
  const shown = inspectedBody(record.response);
  const upstream = inspectedBody(record.upstream_response);
  const res = bodyForDisplay(upstream ?? shown);
  const request = req.json && typeof req.json === 'object'
    ? req.json
    : { messages: [{ role: 'user', content: req.raw ?? req.note }] };
  let response = res.json && typeof res.json === 'object' ? res.json : { choices: [{ message: { role: 'assistant', content: res.raw ?? res.note }, finish_reason: null }] };
  // Request refused before the agent ran: there is no agent reply. Show the proxy refusal, labeled.
  if (record.action === 'blocked_request' || (!upstream && record.response?.status >= 400 && response?.error?.type?.startsWith?.('sentinel_'))) {
    const refusal = res.json;
    response = {
      choices: [{ message: { role: 'assistant', content: `[SentinelProxy refused this request before it reached the agent: ${refusal?.sentinel?.reason ?? record.action}]` }, finish_reason: 'sentinel_blocked' }],
      sentinelRefusal: refusal ?? null,
    };
  }
  return {
    request,
    response,
    sentinel: {
      requestId: record.request_id ?? null,
      ts: record.ts ?? null,
      mode: record.mode ?? null,
      action: record.action ?? null,
      status: record.response?.status ?? null,
      upstreamStatus: record.upstream_response?.status ?? null,
      latencyMs: record.latency_ms ?? null,
      proxyCapture: proxyCapturePath ? { path: proxyCapturePath, line: line ?? null } : null,
    },
  };
}

function omittedExchange(record, bytes, cap, ref) {
  const where = ref?.path ? `${ref.path} line ${ref.line ?? '?'}` : 'the proxy JSONL';
  const msg = `[SentinelProxy pipeline: exchange of ${bytes} B exceeds the display embed cap ${cap} B, so its bodies are not embedded here. Full bodies: ${where}, request_id=${record.request_id}. Verdicts were computed by the proxy on the full bodies.]`;
  return {
    request: { messages: [{ role: 'user', content: msg }] },
    response: { choices: [{ message: { role: 'assistant', content: msg }, finish_reason: null }] },
    sentinel: { requestId: record.request_id ?? null, ts: record.ts ?? null, mode: record.mode ?? null, action: record.action ?? null, embedOmitted: { bytes, cap }, proxyCapture: ref ?? null },
  };
}

/** Conservative estimate of the T5 graph nodes one exchange adds (see MAX_DISPLAY_NODES_PER_CAPTURE). */
export function estimateNodes(ex, alertCount) {
  const msgs = Array.isArray(ex.request?.messages) ? ex.request.messages.length : 1;
  let calls = 0;
  for (const c of Array.isArray(ex.response?.choices) ? ex.response.choices : []) {
    if (Array.isArray(c?.message?.tool_calls)) calls += c.message.tool_calls.length;
  }
  return msgs + 1 + 2 * calls + 2 * alertCount;
}

export class OutputStore {
  /**
   * @param {{outDir: string, caps?: object, log?: Function, proxyCapturePath?: string}} opts
   */
  constructor({ outDir, caps = BOUNDS, log = defaultLog, proxyCapturePath = null }) {
    this.outDir = outDir;
    this.capturesDir = path.join(outDir, 'captures', CAPTURE_SUBDIR);
    this.alertsDir = path.join(outDir, 'alerts');
    this.opsPath = path.join(outDir, 'ops-alerts.jsonl');
    this.caps = caps;
    this.log = log;
    this.proxyCapturePath = proxyCapturePath;
    this.sessions = new Map(); // session -> { slug, partNo, current }
    this.parts = new Map(); // captureId -> part
    this.slugs = new Map(); // slug -> session (collision guard)
    this.dirty = new Set();
    this.opsCount = 0;
  }

  async init({ clean = false } = {}) {
    if (clean) {
      await rm(this.capturesDir, { recursive: true, force: true });
      await rm(this.alertsDir, { recursive: true, force: true });
      await rm(this.opsPath, { force: true });
    }
    await mkdir(this.capturesDir, { recursive: true, mode: 0o700 });
    await mkdir(this.alertsDir, { recursive: true, mode: 0o700 });
  }

  _slugFor(session) {
    const known = this.sessions.get(session);
    if (known) return known.slug;
    let slug = sessionSlug(session);
    // Two different session ids that sanitize to the same slug get distinct, deterministic slugs.
    if (this.slugs.has(slug) && this.slugs.get(slug) !== session) slug = `${slug.slice(0, 47)}-${sha(session)}`;
    this.slugs.set(slug, session);
    return slug;
  }

  _newPart(session, meta) {
    const s = this.sessions.get(session) ?? { slug: this._slugFor(session), partNo: 0, current: null };
    s.partNo += 1;
    enforce('MAX_CAPTURES', this.parts.size + 1, `starting part ${s.partNo} of session ${session}`, this.caps, this.log);
    const suffix = s.partNo === 1 ? '' : `--p${String(s.partNo).padStart(3, '0')}`;
    const captureId = `${CAPTURE_SUBDIR}/${s.slug}${suffix}`;
    const part = {
      captureId,
      session,
      partNo: s.partNo,
      agent: meta.agent,
      exchanges: [],
      exchangeBytes: 0,
      nodes: 0,
      alerts: [],
      standInCount: 0,
    };
    s.current = part;
    this.sessions.set(session, s);
    this.parts.set(captureId, part);
    return part;
  }

  /**
   * Add one exchange and its alerts to the session's current part. Rotates to a new part when a
   * per-part cap would be exceeded. Rotation is a split: nothing is dropped.
   */
  addExchange({ session, agent, record, alerts, line }) {
    const ref = this.proxyCapturePath ? { path: this.proxyCapturePath, line } : (line ? { path: null, line } : null);
    let ex = captureExchange(record, { proxyCapturePath: this.proxyCapturePath, line });
    let exBytes = Buffer.byteLength(JSON.stringify(ex));
    if (exBytes > this.caps.MAX_EMBED_EXCHANGE_BYTES) {
      const entry = { level: 'ALERT', reason: 'embed_omitted', bound: 'MAX_EMBED_EXCHANGE_BYTES', size: exBytes, cap: this.caps.MAX_EMBED_EXCHANGE_BYTES, request_id: record.request_id, action: 'bodies_replaced_by_marker_full_body_in_proxy_jsonl' };
      this.log(entry);
      this.recordOps(entry);
      ex = omittedExchange(record, exBytes, this.caps.MAX_EMBED_EXCHANGE_BYTES, ref);
      exBytes = Buffer.byteLength(JSON.stringify(ex));
    }
    // A single exchange's alerts must fit in one part. More than that cannot be split across parts
    // without separating alerts from their exchange, so it is a hard error.
    enforce('MAX_ALERTS_PER_CAPTURE', alerts.length, `alerts on request ${record.request_id}`, this.caps, this.log);
    const nodes = estimateNodes(ex, alerts.length);
    if (nodes > this.caps.MAX_DISPLAY_NODES_PER_CAPTURE) {
      this.log({ level: 'ALERT', reason: 'exchange_exceeds_display_node_budget', bound: 'MAX_DISPLAY_NODES_PER_CAPTURE', size: nodes, cap: this.caps.MAX_DISPLAY_NODES_PER_CAPTURE, request_id: record.request_id, action: 'own_part_dashboard_may_refuse_replay' });
    }
    let part = this.sessions.get(session)?.current;
    const fits = part
      && part.nodes + nodes <= this.caps.MAX_DISPLAY_NODES_PER_CAPTURE
      && part.exchanges.length + 1 <= this.caps.MAX_EXCHANGES_PER_CAPTURE
      && part.alerts.length + alerts.length <= this.caps.MAX_ALERTS_PER_CAPTURE
      && part.exchangeBytes + exBytes <= this.caps.MAX_CAPTURE_BYTES - 64 * 1024; // 64 KiB for the envelope
    if (!fits) {
      if (part) this.log({ level: 'INFO', reason: 'capture_rotated', session, from: part.captureId, exchanges: part.exchanges.length, alerts: part.alerts.length, bytes: part.exchangeBytes });
      part = this._newPart(session, { agent });
    }
    part.exchanges.push(ex);
    part.exchangeBytes += exBytes;
    part.nodes += nodes;
    part.alerts.push(...alerts);
    part.standInCount += alerts.filter((a) => a.PipelineContext?.StandIn).length;
    if (!part.agent?.port && agent?.port) part.agent = agent;
    this.dirty.add(part.captureId);
    return part.captureId;
  }

  /** Alerts with no exchange record (e.g. the exchange could not be captured). Own part per session. */
  addOrphanAlerts({ session, agent, alerts }) {
    if (!alerts.length) return null;
    enforce('MAX_ALERTS_PER_CAPTURE', alerts.length, `orphan alerts for session ${session}`, this.caps, this.log);
    let part = this.sessions.get(session)?.current;
    if (!part || part.alerts.length + alerts.length > this.caps.MAX_ALERTS_PER_CAPTURE) part = this._newPart(session, { agent });
    part.alerts.push(...alerts);
    part.standInCount += alerts.filter((a) => a.PipelineContext?.StandIn).length;
    this.dirty.add(part.captureId);
    return part.captureId;
  }

  recordOps(entry) {
    this.opsCount += 1;
    this._opsQueue = (this._opsQueue ?? Promise.resolve()).then(() => appendFile(this.opsPath, `${JSON.stringify(entry)}\n`, { mode: 0o600 }));
    return this._opsQueue;
  }

  captureDoc(part) {
    const port = part.agent?.port ?? null;
    return {
      title: `LIVE proxy · ${part.session}${part.partNo > 1 ? ` · part ${part.partNo}` : ''} · ${part.agent?.name ?? 'agent'}`,
      scenario: 'live-proxy',
      role: 'single',
      agent: { name: part.agent?.name ?? 'agent', port },
      pipeline: {
        schema: 'sentinel.pipeline.capture/1.0.0',
        session: part.session,
        part: part.partNo,
        exchangeCount: part.exchanges.length,
        alertCount: part.alerts.length,
        standInAlerts: part.standInCount,
        proxyCapture: this.proxyCapturePath,
      },
      // Orphan-only parts have no exchanges. T5 rejects an empty exchanges[], so add a labeled stub.
      exchanges: part.exchanges.length ? part.exchanges : [{
        request: { messages: [{ role: 'user', content: '[no exchange recorded: the proxy logged alerts for this session without an exchange record]' }] },
        response: { choices: [{ message: { role: 'assistant', content: '' }, finish_reason: null }] },
      }],
    };
  }

  sidecarDoc(part) {
    const standIn = part.standInCount > 0;
    return {
      captureId: part.captureId,
      placeholder: standIn,
      note: standIn
        ? `${STANDIN_NOTE} ${part.standInCount} of ${part.alerts.length} alerts are stand-in.`
        : 'Alerts built by T4 buildAlert from proxy verdicts (sentinel/pipeline).',
      pipeline: {
        schema: 'sentinel.pipeline.sidecar/1.0.0',
        session: part.session,
        part: part.partNo,
        byDirection: {
          request: part.alerts.filter((a) => a.PipelineContext?.Direction === 'request').length,
          response: part.alerts.filter((a) => a.PipelineContext?.Direction === 'response').length,
        },
      },
      runs: { [RUN_KEY]: part.alerts },
    };
  }

  static sidecarName(captureId) {
    return `${captureId.replace(/\//g, '__')}.alerts.json`;
  }

  async _atomicWrite(file, text) {
    const tmp = `${file}.tmp-${process.pid}`;
    await writeFile(tmp, text, { mode: 0o600 });
    await rename(tmp, file);
  }

  /** Write every part changed since the last flush. Sidecar first, then the capture that it annotates. */
  async flush() {
    const ids = [...this.dirty];
    this.dirty.clear();
    for (const id of ids) {
      const part = this.parts.get(id);
      // Compact, so the per-part byte accounting in addExchange matches what lands on disk.
      const capText = `${JSON.stringify(this.captureDoc(part))}\n`;
      // Guard against the envelope pushing the file past the dashboard's cap (fail loud, not skip).
      enforce('MAX_CAPTURE_BYTES', Buffer.byteLength(capText), `capture ${id}`, this.caps, this.log);
      await this._atomicWrite(path.join(this.alertsDir, OutputStore.sidecarName(id)), `${JSON.stringify(this.sidecarDoc(part), null, 1)}\n`);
      await this._atomicWrite(path.join(this.capturesDir, `${path.basename(id)}.json`), capText);
    }
    await this._opsQueue;
    return ids;
  }

  stats() {
    let exchanges = 0;
    let alerts = 0;
    let standIn = 0;
    const byDirection = { request: 0, response: 0 };
    for (const p of this.parts.values()) {
      exchanges += p.exchanges.length;
      alerts += p.alerts.length;
      standIn += p.standInCount;
      for (const a of p.alerts) byDirection[a.PipelineContext.Direction] += 1;
    }
    return { captures: this.parts.size, sessions: this.sessions.size, exchanges, alerts, standIn, byDirection, opsAlerts: this.opsCount };
  }
}
