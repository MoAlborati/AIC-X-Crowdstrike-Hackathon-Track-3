// SentinelProxy T2 — reverse proxy in front of one DVAA agent's OpenAI-compatible endpoint.
//
//   client ──POST /v1/chat/completions──▶ [ read (capped) → inspectRequest → forward (timeout, capped)
//                                           → inspectResponse → capture → reply ] ──▶ DVAA agent
//
// observe mode: every request is forwarded and the upstream reply returned byte-for-byte; inspector
//               "block" decisions are logged as would-block (alert disposition ReportOnly).
// block mode:   an inspector "block" decision (or inspector failure) short-circuits with a structured
//               refusal; on the request phase DVAA is never contacted.
// Both modes:   cap overflows, upstream timeout/unreachable and overload are rejected loudly with a
//               structured refusal + `{size, cap, action}` log — nothing is ever silently truncated.

import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { buildAlert } from '../alerts/index.js';
import { NOOP_INSPECTOR, runInspector } from './inspector.js';
import { CaptureSink, encodeBody } from './sink.js';

export const PROXIED_PATHS = Object.freeze(['/v1/chat/completions', '/chat/completions']);
export const HEALTH_PATH = '/sentinel/health';
export const SESSION_HEADER = 'x-sentinel-session-id';
export const REFUSAL_TYPE = 'sentinel_refusal';

// Milliseconds the proxy keeps discarding the rest of a rejected request body (so the client can read
// the refusal instead of a TCP reset) before it destroys the socket. Data is discarded, never buffered.
export const REJECT_DRAIN_MS = 2000;

/** Discard the rest of a rejected body (bounded by REJECT_DRAIN_MS). Resolves true if it fully drained. */
function drain(req) {
  return new Promise((resolve) => {
    if (req.complete) return resolve(true);
    const timer = setTimeout(() => resolve(false), REJECT_DRAIN_MS);
    timer.unref();
    const done = (ok) => {
      clearTimeout(timer);
      resolve(ok);
    };
    req.once('end', () => done(true));
    req.once('close', () => done(req.complete));
    req.once('error', () => done(false));
    req.resume();
  });
}

/** Reply only after the rejected body is drained, so the client reads the refusal instead of a TCP reset. */
async function drainThenReply(req, res, reply) {
  const drained = await drain(req);
  if (!drained) res.once('finish', () => req.destroy());
  reply();
}

const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'trailers',
  'transfer-encoding', 'upgrade', 'content-length', 'host',
]);

/** JSON-lines logger to a stream (default stderr). Loud levels: ALERT, ERROR. */
export function createLogger(stream = process.stderr) {
  return (level, event, fields = {}) => {
    stream.write(JSON.stringify({ ts: new Date().toISOString(), level, event, ...fields }) + '\n');
  };
}

// The refusal goes back to the caller, which may be the injected agent itself, so it carries only the
// alert's classification. Evidence, entities, taint path and case card stay in the capture sink.
export const REFUSAL_ALERT_FIELDS = Object.freeze([
  'SchemaVersion', 'AlertId', 'DetectName', 'Category', 'RuleId', 'Severity', 'SeverityName', 'Tactic', 'TacticId',
  'Technique', 'TechniqueId', 'PatternDispositionDescription', 'Timestamp',
]);
const alertSummary = (a) => Object.fromEntries(REFUSAL_ALERT_FIELDS.map((k) => [k, a[k]]));

function forwardHeaders(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    if (HOP_BY_HOP.has(k) || k.startsWith('x-sentinel-')) continue;
    out[k] = v;
  }
  return out;
}

function tryJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

/** Read the request body under `cap`. Resolves { ok, body } or { ok:false, size, sizeKnown }. */
function readBody(req, cap) {
  return new Promise((resolve) => {
    const declared = req.headers['content-length'];
    if (declared !== undefined && Number(declared) > cap) {
      resolve({ ok: false, size: Number(declared), sizeKnown: 'content-length' });
      return;
    }
    const chunks = [];
    let size = 0;
    let settled = false;
    const settle = (v) => {
      if (!settled) {
        settled = true;
        resolve(v);
      }
    };
    req.on('data', (chunk) => {
      if (settled) return;
      size += chunk.length;
      if (size > cap) {
        chunks.length = 0;
        settle({ ok: false, size, sizeKnown: 'at-least' });
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => settle({ ok: true, body: Buffer.concat(chunks, size) }));
    req.on('error', (err) => settle({ ok: false, aborted: true, message: err.message }));
    req.on('close', () => {
      if (!req.complete) settle({ ok: false, aborted: true, message: 'client closed before sending the full body' });
    });
  });
}

/** Forward to the target. Resolves { ok:true, status, headers, body, upstreamMs } or { ok:false, kind, ... }. */
function forward({ target, limits, agent }, req, body) {
  return new Promise((resolve) => {
    const t0 = performance.now();
    let settled = false;
    let upstream;
    const done = (v) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ ...v, upstreamMs: performance.now() - t0 });
    };
    const timer = setTimeout(() => {
      upstream?.destroy();
      done({ ok: false, kind: 'timeout', message: `upstream did not answer within ${limits.upstreamTimeoutMs}ms` });
    }, limits.upstreamTimeoutMs);

    const headers = { ...forwardHeaders(req.headers), host: `${target.host}:${target.port}`, 'content-length': body.length };
    upstream = http.request({ host: target.host, port: target.port, method: req.method, path: req.url, headers, agent }, (resp) => {
      const cap = limits.maxResponseBytes;
      const declared = resp.headers['content-length'];
      if (declared !== undefined && Number(declared) > cap) {
        resp.destroy();
        done({ ok: false, kind: 'too_large', status: resp.statusCode, size: Number(declared), sizeKnown: 'content-length', cap });
        return;
      }
      const chunks = [];
      let size = 0;
      resp.on('data', (chunk) => {
        if (settled) return;
        size += chunk.length;
        if (size > cap) {
          chunks.length = 0;
          resp.destroy();
          done({ ok: false, kind: 'too_large', status: resp.statusCode, size, sizeKnown: 'at-least', cap });
          return;
        }
        chunks.push(chunk);
      });
      resp.on('end', () =>
        done({ ok: true, status: resp.statusCode, statusMessage: resp.statusMessage, headers: resp.headers, body: Buffer.concat(chunks, size) }),
      );
      resp.on('error', (err) => done({ ok: false, kind: 'error', message: `upstream response error: ${err.message}` }));
    });
    upstream.on('error', (err) =>
      done({ ok: false, kind: err.code === 'ECONNREFUSED' ? 'unreachable' : 'error', message: `${err.code ?? 'error'}: ${err.message}` }),
    );
    upstream.end(body);
  });
}

/**
 * Create a SentinelProxy instance.
 * @param {object} config  result of loadConfig()
 * @param {{ inspector?: object, log?: Function, sink?: CaptureSink, onRecord?: (record: object) => void }} [deps]
 */
export function createProxy(config, deps = {}) {
  const inspector = deps.inspector ?? NOOP_INSPECTOR;
  const log = deps.log ?? createLogger();
  const sink = deps.sink ?? new CaptureSink(config.sink, log);
  const { mode, target, limits } = config;
  const agent = new http.Agent({ keepAlive: true, maxSockets: limits.maxInFlight });
  const stats = { inFlight: 0, total: 0, forwarded: 0, blocked: 0, rejected: 0, errors: 0 };
  const agentEntity = { name: target.name, id: `dvaa-${target.name.toLowerCase()}`, port: target.port };

  function makeAlert(verdict, events) {
    try {
      return buildAlert(verdict, {
        onWarning: (msg, detail) => events.push({ level: 'WARN', event: 'alert_field_truncated', message: msg, detail }),
      });
    } catch (err) {
      events.push({ level: 'ERROR', event: 'alert_build_failed', message: err.message });
      log('ERROR', 'alert_build_failed', { message: err.message, ruleId: verdict?.ruleId ?? null });
      return null;
    }
  }

  function capAlert(ruleId, sessionId, evidence, events) {
    return makeAlert(
      {
        category: 'scan_cap_exceeded',
        ruleId,
        disposition: 'block',
        detectionLatencyMs: 0,
        entities: { agent: agentEntity, session: { id: sessionId } },
        evidence,
      },
      events,
    );
  }

  async function inspectPhase(phase, ctx, sessionId, events, alerts) {
    const r = await runInspector(inspector, phase, ctx, limits.inspectorTimeoutMs);
    const name = inspector.name ?? 'anonymous';
    if (!r.ok) {
      const fields = { phase, inspector: name, kind: r.failure.kind, message: r.failure.message, mode, action: mode === 'block' ? 'deny' : 'forward' };
      log('ALERT', 'inspector_failed', { requestId: ctx.requestId, ...fields });
      events.push({ level: 'ALERT', event: 'inspector_failed', ...fields });
      return {
        enforced: mode === 'block',
        failed: true,
        record: { inspector: name, ok: false, failure: { kind: r.failure.kind, message: r.failure.message }, latencyMs: r.latencyMs, decision: null, wouldBlock: mode === 'block', failClosed: mode === 'block' },
      };
    }
    const d = r.decision;
    const wouldBlock = d.action === 'block';
    const enforced = wouldBlock && mode === 'block';
    if (d.verdict) {
      const v = d.verdict;
      const alert = makeAlert(
        {
          ...v,
          disposition: d.action === 'allow' ? 'allow' : enforced ? 'block' : 'report',
          detectionLatencyMs: v.detectionLatencyMs ?? r.latencyMs,
          entities: { ...v.entities, agent: v.entities?.agent ?? agentEntity, session: v.entities?.session ?? { id: sessionId } },
        },
        events,
      );
      if (alert) alerts.push(alert);
    }
    if (wouldBlock) {
      const fields = { phase, inspector: name, reason: d.reason, ruleId: d.ruleId, mode, action: enforced ? 'block' : 'report-only' };
      log(enforced ? 'ALERT' : 'WARN', enforced ? 'blocked' : 'would_block', { requestId: ctx.requestId, ...fields });
      events.push({ level: enforced ? 'ALERT' : 'WARN', event: enforced ? 'blocked' : 'would_block', ...fields });
    }
    return {
      enforced,
      failed: false,
      decision: d,
      record: { inspector: name, ok: true, latencyMs: r.latencyMs, decision: { action: d.action, reason: d.reason, ruleId: d.ruleId }, wouldBlock, failClosed: false },
    };
  }

  function sendJson(res, status, payload, extraHeaders = {}) {
    if (res.headersSent) return;
    const body = Buffer.from(JSON.stringify(payload));
    res.writeHead(status, { 'content-type': 'application/json', 'content-length': body.length, ...extraHeaders });
    res.end(body);
  }

  function refusalPayload({ status, code, phase, reason, requestId, alerts, details }) {
    return {
      status,
      payload: {
        error: { message: `SentinelProxy refused this ${phase}: ${reason}`, type: REFUSAL_TYPE, code },
        sentinel: { requestId, mode, phase, action: 'block', code, reason, details: details ?? null, alerts: alerts.map(alertSummary) },
      },
    };
  }

  /** Persist a record. Returns false (after a loud log) if the sink could not write it. */
  function persist(record) {
    try {
      sink.write(record);
      deps.onRecord?.(record);
      return true;
    } catch (err) {
      log('ALERT', 'sink_write_failed', { requestId: record.requestId, path: sink.path, message: err.message, mode, action: mode === 'block' ? 'deny' : 'deliver-unaudited' });
      return false;
    }
  }

  async function handle(req, res) {
    const t0 = performance.now();
    const requestId = randomUUID();
    const sessionId = String(req.headers[SESSION_HEADER] ?? requestId);
    const path = (req.url ?? '/').split('?')[0];
    const ids = { 'x-sentinel-request-id': requestId, 'x-sentinel-mode': mode };
    res.on('error', (err) => log('WARN', 'client_write_failed', { requestId, message: err.message }));

    if (req.method === 'GET' && path === HEALTH_PATH) {
      sendJson(res, 200, { status: 'ok', service: 'sentinel-proxy', mode, target, inspector: inspector.name ?? 'anonymous', stats });
      return;
    }
    if (req.method !== 'POST' || !PROXIED_PATHS.includes(path)) {
      log('WARN', 'route_not_proxied', { requestId, method: req.method, path });
      req.resume();
      sendJson(res, 404, refusalPayload({ status: 404, code: 'route_not_proxied', phase: 'request', reason: `${req.method} ${path} is not an inspected route`, requestId, alerts: [] }).payload, ids);
      return;
    }

    stats.total++;
    const events = [];
    const alerts = [];
    const record = {
      ts: new Date().toISOString(),
      requestId,
      sessionId,
      mode,
      target,
      request: { method: req.method, path: req.url, headers: req.headers, body: null },
      response: null,
      inspector: { name: inspector.name ?? 'anonymous', request: null, response: null },
      outcome: null,
      alerts,
      events,
      timings: { totalMs: null, upstreamMs: null, proxyOverheadMs: null, inspectRequestMs: null, inspectResponseMs: null },
    };
    const finish = (status, outcome, payload, headers, rawBody, statusMessage) => {
      record.outcome = { status, ...outcome };
      record.timings.totalMs = performance.now() - t0;
      record.timings.proxyOverheadMs = record.timings.totalMs - (record.timings.upstreamMs ?? 0);
      const persisted = persist(record);
      if (!persisted && mode === 'block' && outcome.action === 'forwarded') {
        stats.errors++;
        const r = refusalPayload({ status: 503, code: 'capture_failed', phase: 'response', reason: 'capture sink write failed; fail-closed in block mode', requestId, alerts });
        sendJson(res, r.status, r.payload, ids);
        return;
      }
      if (rawBody) {
        res.writeHead(status, statusMessage || http.STATUS_CODES[status] || 'unknown', { ...headers, ...ids, 'content-length': rawBody.length });
        res.end(rawBody);
      } else {
        sendJson(res, status, payload, { ...ids, ...headers });
      }
    };
    const refuse = (status, code, phase, reason, details, extraHeaders = {}) => {
      const r = refusalPayload({ status, code, phase, reason, requestId, alerts, details });
      if (code === 'request_blocked' || code === 'response_blocked' || code === 'inspector_failed') stats.blocked++;
      else stats.rejected++;
      finish(status, { action: code.endsWith('_blocked') || code === 'inspector_failed' ? 'blocked' : 'rejected', code, phase, wouldBlock: true }, r.payload, extraHeaders);
    };

    if (stats.inFlight >= limits.maxInFlight) {
      const fields = { size: stats.inFlight + 1, cap: limits.maxInFlight, action: 'reject' };
      log('ALERT', 'proxy_overloaded', { requestId, ...fields });
      events.push({ level: 'ALERT', event: 'proxy_overloaded', ...fields });
      record.request.bodyNotCaptured = { reason: 'rejected before read: maxInFlight reached', ...fields };
      await drainThenReply(req, res, () => refuse(503, 'proxy_overloaded', 'request', `in-flight requests at cap ${limits.maxInFlight}`, fields));
      return;
    }

    stats.inFlight++;
    try {
      // 1) read request under cap
      const read = await readBody(req, limits.maxRequestBytes);
      if (!read.ok && read.aborted) {
        log('WARN', 'client_aborted', { requestId, message: read.message });
        events.push({ level: 'WARN', event: 'client_aborted', message: read.message });
        record.outcome = { status: null, action: 'aborted', code: 'client_aborted', phase: 'request', wouldBlock: false };
        persist(record);
        return;
      }
      if (!read.ok) {
        const fields = { size: read.size, sizeKnown: read.sizeKnown, cap: limits.maxRequestBytes, action: 'reject' };
        log('ALERT', 'request_too_large', { requestId, ...fields });
        events.push({ level: 'ALERT', event: 'request_too_large', ...fields });
        record.request.bodyNotCaptured = { reason: 'request body exceeded limits.maxRequestBytes; not buffered past the cap', ...fields };
        const alert = capAlert('proxy.request_body_cap', sessionId, `request body ${read.sizeKnown === 'at-least' ? '>= ' : ''}${read.size} bytes exceeds maxRequestBytes=${limits.maxRequestBytes}; action=reject`, events);
        if (alert) alerts.push(alert);
        await drainThenReply(req, res, () => refuse(413, 'request_too_large', 'request', `request body exceeds ${limits.maxRequestBytes} bytes`, fields));
        return;
      }
      const body = read.body;
      record.request.body = encodeBody(body);
      const text = body.toString('utf8');
      // Inspectors get copies: nothing they do can change the bytes or headers that are forwarded.
      const reqCtx = Object.freeze({
        phase: 'request', requestId, sessionId, mode, target, method: req.method, path: req.url, headers: structuredClone(req.headers),
        body: Buffer.from(body), text, json: tryJson(text), limits,
      });

      // 2) pre-forward inspection
      const ri = await inspectPhase('request', reqCtx, sessionId, events, alerts);
      record.inspector.request = ri.record;
      record.timings.inspectRequestMs = ri.record.latencyMs;
      if (ri.enforced) {
        if (ri.failed) refuse(503, 'inspector_failed', 'request', `inspector failed (${ri.record.failure.kind}); fail-closed in block mode`, ri.record.failure);
        else refuse(403, 'request_blocked', 'request', ri.decision.reason ?? 'blocked by inspector', { ruleId: ri.decision.ruleId });
        return;
      }

      // 3) forward
      const up = await forward({ target, limits, agent }, req, body);
      record.timings.upstreamMs = up.upstreamMs;
      if (!up.ok) {
        stats.errors++;
        if (up.kind === 'too_large') {
          const fields = { size: up.size, sizeKnown: up.sizeKnown, cap: up.cap, action: 'reject', upstreamStatus: up.status };
          log('ALERT', 'response_too_large', { requestId, ...fields });
          events.push({ level: 'ALERT', event: 'response_too_large', ...fields });
          record.response = { status: up.status, headers: null, body: null, bodyNotCaptured: { reason: 'upstream response exceeded limits.maxResponseBytes; not buffered past the cap', ...fields } };
          const alert = capAlert('proxy.response_body_cap', sessionId, `upstream response ${up.sizeKnown === 'at-least' ? '>= ' : ''}${up.size} bytes exceeds maxResponseBytes=${up.cap}; action=reject`, events);
          if (alert) alerts.push(alert);
          refuse(502, 'response_too_large', 'response', `upstream response exceeds ${up.cap} bytes`, fields);
        } else {
          const code = up.kind === 'timeout' ? 'upstream_timeout' : up.kind === 'unreachable' ? 'upstream_unreachable' : 'upstream_error';
          const fields = { target: `${target.host}:${target.port}`, message: up.message, timeoutMs: limits.upstreamTimeoutMs };
          log('ALERT', code, { requestId, ...fields });
          events.push({ level: 'ALERT', event: code, ...fields });
          refuse(up.kind === 'timeout' ? 504 : 502, code, 'upstream', up.message, fields);
        }
        return;
      }
      record.response = { status: up.status, headers: up.headers, body: encodeBody(up.body) };

      // 4) post-response inspection (DVAA has already executed any tool calls by now)
      const respText = up.body.toString('utf8');
      const respJson = tryJson(respText);
      const respCtx = Object.freeze({
        ...reqCtx,
        phase: 'response',
        request: Object.freeze({ headers: reqCtx.headers, body: reqCtx.body, text, json: reqCtx.json }),
        response: Object.freeze({ status: up.status, headers: structuredClone(up.headers), body: Buffer.from(up.body), text: respText, json: respJson }),
        dvaa: respJson?.dvaa ?? null,
        toolCalls: respJson?.choices?.[0]?.message?.tool_calls ?? [],
      });
      const rr = await inspectPhase('response', respCtx, sessionId, events, alerts);
      record.inspector.response = rr.record;
      record.timings.inspectResponseMs = rr.record.latencyMs;
      if (rr.enforced) {
        if (rr.failed) refuse(503, 'inspector_failed', 'response', `inspector failed (${rr.record.failure.kind}); fail-closed in block mode`, rr.record.failure);
        else refuse(403, 'response_blocked', 'response', rr.decision.reason ?? 'blocked by inspector', { ruleId: rr.decision.ruleId, upstreamToolCallsAlreadyExecuted: respCtx.toolCalls.length > 0 || respCtx.dvaa !== null });
        return;
      }

      // 5) pass through byte-for-byte
      stats.forwarded++;
      finish(up.status, { action: 'forwarded', code: null, phase: null, wouldBlock: ri.record.wouldBlock || rr.record.wouldBlock }, null, forwardHeaders(up.headers), up.body, up.statusMessage);
    } catch (err) {
      stats.errors++;
      log('ERROR', 'proxy_internal_error', { requestId, message: err.message, stack: err.stack });
      events.push({ level: 'ERROR', event: 'proxy_internal_error', message: err.message });
      if (!res.headersSent) refuse(500, 'proxy_internal_error', 'proxy', err.message, null);
    } finally {
      stats.inFlight--;
    }
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch((err) => log('ERROR', 'proxy_unhandled', { message: err.message }));
  });

  return {
    server,
    sink,
    stats,
    config,
    listen(port = config.listen.port, host = config.listen.host) {
      return new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, host, () => {
          server.off('error', reject);
          const a = server.address();
          log('INFO', 'proxy_listening', { listen: `${a.address}:${a.port}`, target: `${target.host}:${target.port}`, targetName: target.name, mode, inspector: inspector.name ?? 'anonymous', limits, sink: config.sink });
          resolve({ host: a.address, port: a.port, url: `http://${a.address}:${a.port}` });
        });
      });
    },
    close() {
      agent.destroy();
      server.closeAllConnections?.();
      return new Promise((resolve) => server.close(() => resolve()));
    },
  };
}
