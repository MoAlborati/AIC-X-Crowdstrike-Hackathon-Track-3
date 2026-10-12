// SentinelProxy reverse proxy (T2 skeleton). Zero deps, Node >= 22.
//
// Pipeline per request:
//   1. Read the client body with a HARD cap (limits.maxRequestBytes). Over cap -> 413 + ALERT,
//      nothing is forwarded (fail-closed; we never forward or scan a truncated body).
//   2. Run request-phase inspectors over the FULL body (hook for T3 detectors / T4 alerts).
//        block mode   + flagged -> structured 403 refusal, upstream is never contacted.
//        observe mode + flagged -> forwarded unchanged, a would-block ALERT is logged.
//      Inspector crash -> block mode: 503 refusal (fail-closed); observe mode: forward + ALERT.
//   3. Forward to the configured DVAA target and buffer the response with a HARD cap
//      (limits.maxResponseBytes). Over cap -> 502 + ALERT (cannot log/inspect it in full).
//   4. Run response-phase inspectors over the FULL response body (same block/observe semantics).
//   5. Write the full exchange to the capture sink BEFORE replying. Sink failure -> 503 + ALERT, so
//      nothing reaches the client unlogged.
//   6. Reply. In observe mode the upstream status, headers (minus hop-by-hop) and body bytes are
//      returned unchanged.

import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { isUtf8 } from 'node:buffer';
import { JsonlCaptureSink } from './capture-sink.mjs';
import { substringInspector } from './inspectors.mjs';

// Every request and response is inspected, whatever its path. Keying inspection on an exact path
// (e.g. only /v1/chat/completions) would let a path variant an upstream happens to accept, or a
// non-OpenAI agent route (MCP/A2A), bypass the guard. Cost is one full-body scan per exchange.

// RFC 7230 §6.1 hop-by-hop headers, plus ones we recompute ourselves.
const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer',
  'transfer-encoding', 'upgrade', 'proxy-connection', 'content-length',
]);

// After an oversize request crosses the cap we drain (read + discard, never buffer) at most this
// many further bytes before answering and closing. Bounds bandwidth spent on an abusive upload.
export const DRAIN_LIMIT_BYTES = 16 * 1024 * 1024;

export class PayloadTooLargeError extends Error {
  constructor({ payload_size, cap, phase, size_is_lower_bound = false }) {
    super(`${phase} body ${size_is_lower_bound ? '>=' : ''}${payload_size}B exceeds cap ${cap}B`);
    this.name = 'PayloadTooLargeError';
    Object.assign(this, { payload_size, cap, phase, size_is_lower_bound });
  }
}

function stripHopByHop(headers) {
  const out = {};
  const connectionTokens = String(headers.connection ?? '')
    .split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  for (const [k, v] of Object.entries(headers)) {
    const key = k.toLowerCase();
    if (HOP_BY_HOP.has(key) || connectionTokens.includes(key)) continue;
    out[key] = v;
  }
  return out;
}

/** Encode a body for the capture log: full content, utf8 when valid, else base64. */
export function encodeBody(buf) {
  if (isUtf8(buf)) return { encoding: 'utf8', bytes: buf.length, data: buf.toString('utf8') };
  return { encoding: 'base64', bytes: buf.length, data: buf.toString('base64') };
}

/**
 * Read a request body fully, enforcing a hard cap. Rejects with PayloadTooLargeError on overflow.
 *
 * Overflow handling is a bounded "lingering close": once over the cap we stop buffering but keep
 * reading-and-discarding until the client finishes sending, THEN reject (so the 413 is written to a
 * client that is listening). Replying mid-upload and closing a socket with unread inbound bytes
 * makes the kernel send a TCP RST, which can destroy the 413 before the client reads it.
 * The drain is bounded by DRAIN_LIMIT_BYTES: past that we reject immediately with
 * drain_exceeded=true and the caller closes the connection (abusive uploads may then see a reset).
 * A declared Content-Length over the cap is known exactly before reading any byte.
 */
function readRequestBody(req, cap) {
  return new Promise((resolveBody, reject) => {
    const declaredRaw = req.headers['content-length'];
    const declared = declaredRaw === undefined ? null : Number(declaredRaw);
    const chunks = [];
    let size = 0;
    let overflowed = declared !== null && declared > cap;
    let settled = false;
    const tooLarge = (drainExceeded) => {
      if (settled) return;
      settled = true;
      const exact = declared !== null && declared > cap;
      const err = new PayloadTooLargeError({
        payload_size: exact ? declared : size,
        cap,
        phase: 'request',
        size_is_lower_bound: !exact && drainExceeded,
      });
      err.drain_exceeded = drainExceeded;
      reject(err);
    };
    req.on('data', (chunk) => {
      size += chunk.length;
      if (!overflowed && size > cap) {
        overflowed = true;
        chunks.length = 0; // stop holding anything once over the cap
      }
      if (overflowed) {
        if (size > cap + DRAIN_LIMIT_BYTES) {
          req.pause();
          tooLarge(true);
        }
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (overflowed) tooLarge(false);
      else if (!settled) { settled = true; resolveBody(Buffer.concat(chunks, size)); }
    });
    req.on('error', (err) => { if (!settled) { settled = true; reject(err); } });
  });
}

/** Forward to upstream and buffer the response with a hard cap. */
function forward({ target, method, path, headers, body, cap, timeoutMs }) {
  return new Promise((resolveRes, reject) => {
    const upstreamHeaders = stripHopByHop(headers);
    upstreamHeaders.host = `${target.host}:${target.port}`;
    // Ask for identity so the capture log holds readable bodies, not gzip bytes.
    upstreamHeaders['accept-encoding'] = 'identity';
    if (body.length > 0 || method === 'POST' || method === 'PUT' || method === 'PATCH') {
      upstreamHeaders['content-length'] = String(body.length);
    }
    const upstreamReq = http.request({
      host: target.host, port: target.port, method, path, headers: upstreamHeaders,
    });
    const timer = setTimeout(() => {
      const err = new Error(`upstream timeout after ${timeoutMs}ms`);
      err.code = 'UPSTREAM_TIMEOUT';
      upstreamReq.destroy(err);
    }, timeoutMs);
    upstreamReq.on('response', (res) => {
      const declared = res.headers['content-length'];
      if (declared !== undefined && Number(declared) > cap) {
        clearTimeout(timer);
        res.destroy();
        reject(new PayloadTooLargeError({ payload_size: Number(declared), cap, phase: 'response' }));
        return;
      }
      const chunks = [];
      let size = 0;
      let overflowed = false;
      res.on('data', (chunk) => {
        size += chunk.length;
        if (size > cap) {
          overflowed = true;
          clearTimeout(timer);
          res.destroy();
          reject(new PayloadTooLargeError({ payload_size: size, cap, phase: 'response', size_is_lower_bound: true }));
          return;
        }
        chunks.push(chunk);
      });
      res.on('end', () => {
        clearTimeout(timer);
        if (overflowed) return;
        resolveRes({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks, size) });
      });
      res.on('error', (err) => { clearTimeout(timer); if (!overflowed) reject(err); });
    });
    upstreamReq.on('error', (err) => { clearTimeout(timer); reject(err); });
    upstreamReq.end(body);
  });
}

// A verdict counts as "flagged" if it says so explicitly, or carries a T4-style blocking
// disposition (sentinel/alerts verdicts use `disposition: 'block' | 'hold'` + `ruleId`).
const BLOCKING_DISPOSITIONS = new Set(['block', 'hold']);
function isFlagged(v) {
  return Boolean(v) && (v.flagged === true || BLOCKING_DISPOSITIONS.has(v.disposition));
}

async function runInspectors(inspectors, ctx) {
  const verdicts = [];
  for (const inspect of inspectors) {
    const v = await inspect(ctx);
    if (isFlagged(v)) {
      verdicts.push({ detector: v.detector ?? v.ruleId ?? inspect.name ?? 'anonymous', reasons: v.reasons ?? [], ...v });
    }
  }
  return verdicts;
}

function jsonBuffer(obj) {
  return Buffer.from(JSON.stringify(obj));
}

/**
 * Client-facing view of a verdict: detector name + reasons ONLY. Full verdicts (which may carry the
 * matched secret, offsets, evidence) go to the capture/alert log, never back to the client — echoing
 * evidence in a refusal would itself be an exfil channel.
 */
export function publicVerdict(v) {
  return {
    detector: String(v.detector ?? v.ruleId ?? 'anonymous'),
    reasons: Array.isArray(v.reasons) ? v.reasons.map(String) : [],
  };
}

/** Structured refusal returned instead of forwarding (block mode) — the hook T3/T4 plug into. */
export function buildRefusal({ requestId, phase, reason, verdicts = [], mode, detail }) {
  return {
    error: {
      type: 'sentinel_blocked',
      code: reason,
      message: `SentinelProxy refused this ${phase}: ${reason}`,
    },
    sentinel: {
      request_id: requestId,
      blocked: true,
      mode,
      phase,
      reason,
      verdicts: verdicts.map(publicVerdict),
      ...(detail ? { detail } : {}),
    },
  };
}

/**
 * Create the proxy. Returns { server, sink, listen(), close() }.
 * @param {object} config validated config (see sentinel/config/load.mjs)
 * @param {{inspectors?: Function[], sink?: {write: Function, flush: Function}, logAlert?: Function}} [deps]
 */
export function createProxy(config, deps = {}) {
  const sink = deps.sink ?? new JsonlCaptureSink(config.capture);
  const inspectors = deps.inspectors ?? [substringInspector(config.inspect.flagSubstrings)];
  const logAlert = deps.logAlert ?? ((alert) => process.stderr.write(`[sentinel] ALERT ${JSON.stringify(alert)}\n`));
  const { mode, target, limits } = config;

  async function emitAlert(requestId, alert) {
    const record = { type: 'alert', ts: new Date().toISOString(), request_id: requestId, mode, ...alert };
    logAlert(record);
    try {
      await sink.write(record);
    } catch (err) {
      logAlert({ type: 'alert', request_id: requestId, reason: 'capture_write_failed', error: err.message });
    }
    return record;
  }

  async function handle(req, res) {
    const requestId = randomUUID();
    const started = process.hrtime.bigint();
    const path = req.url ?? '/';
    const record = {
      type: 'exchange',
      ts: new Date().toISOString(),
      request_id: requestId,
      mode,
      target: `${target.host}:${target.port}`,
      request: { method: req.method, path, headers: req.headers },
      response: null,
      verdicts: [],
      action: null,
    };

    // reply() always captures first; if capture fails we refuse instead (fail-loud, never unlogged).
    const reply = async (status, headers, body, action) => {
      record.action = action;
      record.response = { status, headers, body: encodeBody(body) };
      record.latency_ms = Number(process.hrtime.bigint() - started) / 1e6;
      try {
        await sink.write(record);
      } catch (err) {
        await emitAlert(requestId, {
          reason: 'capture_write_failed', action: 'refused_exchange', error: err.message,
          ...(err.payload_size !== undefined ? { payload_size: err.payload_size, cap: err.cap } : {}),
        });
        status = 503;
        body = jsonBuffer(buildRefusal({ requestId, phase: 'capture', reason: 'capture_unavailable', mode }));
        headers = { 'content-type': 'application/json' };
      }
      res.writeHead(status, { ...headers, 'content-length': body.length, 'x-sentinel-request-id': requestId });
      res.end(body);
    };
    const refuse = (status, phase, reason, verdicts, detail) => {
      const body = jsonBuffer(buildRefusal({ requestId, phase, reason, verdicts, mode, detail }));
      return reply(status, { 'content-type': 'application/json' }, body, `blocked_${phase}`);
    };

    // 1. bounded request read
    let reqBody;
    try {
      reqBody = await readRequestBody(req, limits.maxRequestBytes);
    } catch (err) {
      if (err instanceof PayloadTooLargeError) {
        record.request.body = { encoding: 'omitted', bytes: err.payload_size, reason: 'over_cap' };
        const detail = { payload_size: err.payload_size, cap: err.cap, size_is_lower_bound: err.size_is_lower_bound, action: 'rejected_not_forwarded' };
        await emitAlert(requestId, { reason: 'request_too_large', phase: 'request', ...detail });
        if (err.drain_exceeded) res.shouldKeepAlive = false;
        return refuse(413, 'request', 'request_too_large', [], detail);
      }
      throw err;
    }
    record.request.body = encodeBody(reqBody);

    // 2. request-phase inspection over the FULL body
    {
      let verdicts;
      try {
        verdicts = await runInspectors(inspectors, { phase: 'request', path, headers: req.headers, body: reqBody, requestId });
      } catch (err) {
        await emitAlert(requestId, { reason: 'inspector_error', phase: 'request', error: err.message, action: mode === 'block' ? 'fail_closed' : 'forwarded_uninspected' });
        if (mode === 'block') return refuse(503, 'request', 'inspector_error', [], { error: err.message });
        verdicts = [];
      }
      record.verdicts.push(...verdicts.map((v) => ({ phase: 'request', ...v })));
      if (verdicts.length > 0) {
        await emitAlert(requestId, { reason: 'flagged', phase: 'request', verdicts, action: mode === 'block' ? 'blocked' : 'would_block_observe_only' });
        if (mode === 'block') return refuse(403, 'request', 'flagged_request', verdicts);
      }
    }

    // 3. forward with bounded response read
    let upstream;
    try {
      upstream = await forward({
        target, method: req.method, path, headers: req.headers, body: reqBody,
        cap: limits.maxResponseBytes, timeoutMs: limits.upstreamTimeoutMs,
      });
    } catch (err) {
      if (err instanceof PayloadTooLargeError) {
        const detail = { payload_size: err.payload_size, cap: err.cap, size_is_lower_bound: err.size_is_lower_bound, action: 'rejected_not_returned' };
        await emitAlert(requestId, { reason: 'response_too_large', phase: 'response', ...detail });
        return refuse(502, 'response', 'response_too_large', [], detail);
      }
      const timeout = err.code === 'UPSTREAM_TIMEOUT';
      await emitAlert(requestId, { reason: timeout ? 'upstream_timeout' : 'upstream_error', phase: 'forward', error: err.message, action: 'refused' });
      return refuse(timeout ? 504 : 502, 'forward', timeout ? 'upstream_timeout' : 'upstream_unreachable', [], { error: err.message });
    }

    // 4. response-phase inspection over the FULL body
    {
      let verdicts;
      try {
        verdicts = await runInspectors(inspectors, { phase: 'response', path, headers: upstream.headers, body: upstream.body, status: upstream.status, requestId });
      } catch (err) {
        await emitAlert(requestId, { reason: 'inspector_error', phase: 'response', error: err.message, action: mode === 'block' ? 'fail_closed' : 'returned_uninspected' });
        if (mode === 'block') return refuse(503, 'response', 'inspector_error', [], { error: err.message });
        verdicts = [];
      }
      record.verdicts.push(...verdicts.map((v) => ({ phase: 'response', ...v })));
      if (verdicts.length > 0) {
        record.upstream_response = { status: upstream.status, headers: upstream.headers, body: encodeBody(upstream.body) };
        await emitAlert(requestId, { reason: 'flagged', phase: 'response', verdicts, action: mode === 'block' ? 'blocked' : 'would_block_observe_only' });
        if (mode === 'block') return refuse(403, 'response', 'flagged_response', verdicts);
      }
    }

    // 6. return upstream response unchanged
    return reply(upstream.status, stripHopByHop(upstream.headers), upstream.body, 'forwarded');
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch(async (err) => {
      try {
        await emitAlert(null, { reason: 'proxy_internal_error', error: err.message, action: 'refused' });
      } finally {
        if (!res.headersSent) {
          res.writeHead(500, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: { type: 'sentinel_internal_error', message: err.message } }));
        } else {
          res.destroy(err);
        }
      }
    });
  });

  return {
    server,
    sink,
    config,
    listen(port = config.listen.port, host = config.listen.host) {
      return new Promise((resolveListen, reject) => {
        server.once('error', reject);
        server.listen(port, host, () => {
          server.off('error', reject);
          resolveListen(server.address());
        });
      });
    },
    async close() {
      await new Promise((r) => { server.close(() => r()); server.closeAllConnections(); });
      await sink.flush();
    },
  };
}
