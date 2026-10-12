// Tourniquet reverse proxy (T2 skeleton). Zero deps, Node >= 22.
//
// Pipeline per request:
//   0. Admission: at most limits.maxInFlight exchanges at once (over -> 503 `overloaded` + ALERT).
//      Client must deliver headers+body within limits.clientTimeoutMs (else 408 + ALERT).
//      `Expect: 100-continue` with a declared Content-Length over the cap -> 413 before any upload.
//   1. Read the client body with a HARD cap (limits.maxRequestBytes). Over cap -> 413 + ALERT,
//      nothing is forwarded (fail-closed; we never forward or scan a truncated body).
//   2. Decode `content-encoding` (gzip/deflate/br, bounded by the same cap) so inspectors see the
//      plaintext. Unsupported/undecodable encoding: block -> refused; observe -> forward + ALERT.
//      A decoded REQUEST body that is not valid UTF-8 (binary/unknown content): block -> 415
//      `uninspectable_content`; observe -> forward + ALERT (#157).
//   3. Run request-phase inspectors over the FULL decoded body + URL + headers, under a deadline
//      (limits.inspectorTimeoutMs).
//        block mode   + flagged -> structured 403 refusal, upstream is never contacted.
//        observe mode + flagged -> forwarded unchanged, a would-block ALERT is logged.
//      Inspector crash / malformed verdict / deadline -> block: 503 (fail-closed); observe: forward + ALERT.
//   4. Write-ahead: the request record goes to the capture sink BEFORE forwarding. Sink failure ->
//      503, the request is NOT forwarded (no agent side effect without a record).
//   5. Forward to the configured DVAA target and buffer the response with a HARD cap
//      (limits.maxResponseBytes). Over cap -> 502 + ALERT (cannot log/inspect it in full).
//   6. Decode + run response-phase inspectors over the FULL response (same semantics).
//   7. Write the full exchange to the capture sink BEFORE replying. Sink failure -> 503 + ALERT, so
//      nothing reaches the client unlogged.
//   8. Reply. In observe mode the upstream status, headers (minus hop-by-hop) and body bytes are
//      returned unchanged (still encoded, if the upstream encoded them).
//
// Client-facing refusals carry ONLY static reason codes (REFUSAL_CODES), the phase, mode, request id
// and numeric size details. Inspector reasons/messages and internal error text go to the log only.

import http from 'node:http';
import zlib from 'node:zlib';
import { promisify } from 'node:util';
import { randomUUID, createHash } from 'node:crypto';
import { isUtf8 } from 'node:buffer';
import { JsonlCaptureSink } from './capture-sink.mjs';
import { substringInspector, flagSubstringId } from './inspectors.mjs';
import { ConfigError, isLoopbackHost } from '../config/load.mjs';
// Single source of truth for verdict dispositions: T4's table (sentinel/alerts/schema.js). The
// proxy never keeps its own list, so the two modules cannot drift apart.
import { DISPOSITIONS } from '../alerts/index.js';
import { prepareCanaries, redactDeep } from '../alerts/redact.js';

// The proxy runs every registered inspector on every request and response, whatever the path. What an
// inspector then CHECKS depends on the inspector: T3 parses only the chat-completions paths and returns
// null elsewhere. Other routes (DVAA `POST /chat`, A2A `/a2a/message`, MCP) get the honeytoken
// backstops from default-inspectors.mjs (exact canary values in body/headers/URL, both phases, plus
// encoded canaries in non-chat POST bodies), not T3's injection/mandate/egress analysis (#126).

// RFC 7230 §6.1 hop-by-hop headers, plus ones we recompute ourselves.
const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer',
  'transfer-encoding', 'upgrade', 'proxy-connection', 'content-length',
]);

// After an oversize request crosses the cap we drain (read + discard, never buffer) at most this
// many further bytes before answering and closing. Bounds bandwidth spent on an abusive upload.
export const DRAIN_LIMIT_BYTES = 16 * 1024 * 1024;
// More stacked content-codings than this is refused as uninspectable (bounds decode work).
export const MAX_ENCODING_LAYERS = 4;
// Hard ceiling on open sockets (idle keep-alive included) relative to the in-flight cap. Excess
// connections are dropped by Node; each drop is ALERTed.
export const CONNECTIONS_PER_IN_FLIGHT = 4;

// The complete set of codes a client can ever see. Static strings; nothing inspector-derived.
export const REFUSAL_CODES = Object.freeze([
  'flagged_request', 'flagged_response', 'inspector_error', 'inspector_timeout',
  'request_too_large', 'response_too_large', 'uninspectable_encoding', 'uninspectable_content', 'capture_unavailable',
  'upstream_unreachable', 'upstream_timeout', 'overloaded', 'client_timeout', 'internal_error',
]);
const STATIC_DETAIL_ACTIONS = new Set(['rejected_not_forwarded', 'rejected_not_returned']);

export class PayloadTooLargeError extends Error {
  constructor({ payload_size, cap, phase, size_is_lower_bound = false, decoded = false }) {
    super(`${phase} body ${size_is_lower_bound ? '>=' : ''}${payload_size}B ${decoded ? '(decoded) ' : ''}exceeds cap ${cap}B`);
    this.name = 'PayloadTooLargeError';
    Object.assign(this, { payload_size, cap, phase, size_is_lower_bound, decoded });
  }
}

export class UninspectableEncodingError extends Error {
  constructor(message, encoding) {
    super(message);
    this.name = 'UninspectableEncodingError';
    this.encoding = encoding;
  }
}

export class InvalidVerdictError extends Error {
  constructor(message) {
    super(message);
    this.name = 'InvalidVerdictError';
  }
}

export class InspectorTimeoutError extends Error {
  constructor(timeoutMs) {
    super(`inspectors did not finish within ${timeoutMs}ms`);
    this.name = 'InspectorTimeoutError';
    this.timeoutMs = timeoutMs;
  }
}

class ClientAbortedError extends Error {
  constructor(cause) {
    super('client aborted the request before the body was complete');
    this.name = 'ClientAbortedError';
    this.cause = cause;
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

/** sha256 hex of the exact wire bytes. */
export const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

/**
 * Encode a body for the capture log: full content, utf8 when valid, else base64. `bytes` + `sha256`
 * describe the exact wire bytes, so a consumer can verify byte-for-byte fidelity (decodeBody()).
 */
export function encodeBody(buf) {
  if (isUtf8(buf)) return { encoding: 'utf8', bytes: buf.length, sha256: sha256(buf), data: buf.toString('utf8') };
  return { encoding: 'base64', bytes: buf.length, sha256: sha256(buf), data: buf.toString('base64') };
}

/** Inverse of encodeBody(): the exact bytes that crossed the wire. */
export function decodeBody(body) {
  if (body == null || body.data === undefined) return null;
  return Buffer.from(body.data, body.encoding === 'base64' ? 'base64' : 'utf8');
}

/**
 * Did DVAA already run tools for this reply? DVAA executes tool calls inside the agent before it
 * answers, so a response-phase block contains the output but cannot undo the side effect. The
 * refusal says so (boolean only, never the tool data).
 */
export function upstreamToolCallsExecuted(decodedResponse) {
  let j;
  try { j = JSON.parse(decodedResponse.toString('utf8')); } catch { return false; }
  if (j === null || typeof j !== 'object') return false;
  const calls = j.choices?.[0]?.message?.tool_calls;
  return (Array.isArray(calls) && calls.length > 0) || (j.dvaa !== undefined && j.dvaa !== null);
}

const gunzip = promisify(zlib.gunzip);
const inflate = promisify(zlib.inflate);
const inflateRaw = promisify(zlib.inflateRaw);
const brotli = promisify(zlib.brotliDecompress);
const DECODERS = {
  gzip: gunzip,
  'x-gzip': gunzip,
  // RFC 9110 "deflate" is zlib-wrapped; some servers send raw DEFLATE, so fall back to that.
  deflate: async (buf, opts) => {
    try { return await inflate(buf, opts); } catch (err) {
      if (err.code === 'ERR_BUFFER_TOO_LARGE') throw err;
      return inflateRaw(buf, opts);
    }
  },
  br: brotli,
};

/**
 * Undo `content-encoding` so inspectors see plaintext. Output is bounded by `cap` (zip-bomb safe:
 * zlib stops at maxOutputLength) and overflow raises PayloadTooLargeError, never a truncated body.
 * Unknown codings, too many layers, or corrupt data raise UninspectableEncodingError.
 */
export async function decodeContent(buf, contentEncoding, cap, phase) {
  if (contentEncoding === undefined || buf.length === 0) return { body: buf, encodings: [] };
  const codings = String(contentEncoding).split(',').map((s) => s.trim().toLowerCase())
    .filter((s) => s !== '' && s !== 'identity');
  if (codings.length === 0) return { body: buf, encodings: [] };
  if (codings.length > MAX_ENCODING_LAYERS) {
    throw new UninspectableEncodingError(`${codings.length} stacked content-codings (max ${MAX_ENCODING_LAYERS})`, 'stacked');
  }
  let out = buf;
  for (const coding of [...codings].reverse()) { // codings are listed in the order they were applied
    const decode = DECODERS[coding];
    if (!decode) throw new UninspectableEncodingError(`unsupported content-coding ${JSON.stringify(coding)}`, coding);
    try {
      out = await decode(out, { maxOutputLength: cap });
    } catch (err) {
      if (err.code === 'ERR_BUFFER_TOO_LARGE') {
        throw new PayloadTooLargeError({ payload_size: cap + 1, cap, phase, size_is_lower_bound: true, decoded: true });
      }
      throw new UninspectableEncodingError(`cannot decode ${coding} body: ${err.code ?? err.message}`, coding);
    }
  }
  return { body: out, encodings: codings };
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
    req.on('error', (err) => { if (!settled) { settled = true; reject(new ClientAbortedError(err)); } });
  });
}

/** Responses that never carry a body, whatever their Content-Length says (RFC 9110 §6.4.1). */
const bodiless = (method, status) => method === 'HEAD' || status === 204 || status === 304 || (status >= 100 && status < 200);

/** Forward to upstream and buffer the response with a hard cap. */
function forward({ target, method, path, headers, body, cap, timeoutMs }) {
  return new Promise((resolveRes, reject) => {
    const upstreamHeaders = stripHopByHop(headers);
    upstreamHeaders.host = `${target.host}:${target.port}`;
    // Ask for identity so the capture log holds readable bodies. Upstreams may ignore this; any
    // encoded response is decoded before inspection (decodeContent), never inspected raw.
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
      if (!bodiless(method, res.statusCode) && declared !== undefined && Number(declared) > cap) {
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

/**
 * Classify one inspector result: 'clean' | 'flagged'. Anything malformed throws InvalidVerdictError
 * so the caller fails CLOSED in block mode. Error messages here are static (no verdict content).
 * `disposition` is normalised exactly as T4's validate() does (`DISPOSITIONS[d.toLowerCase()]`), so
 * `Blocked`, `BLOCK` and `blocked` all block, and a value T4 rejects (e.g. `hold`) is malformed.
 */
export function classifyVerdict(v) {
  if (v === null || v === undefined) return 'clean';
  if (typeof v !== 'object' || Array.isArray(v)) throw new InvalidVerdictError('verdict must be an object, null or undefined');
  const hasFlag = v.flagged !== undefined;
  const hasDisposition = v.disposition !== undefined;
  if (!hasFlag && !hasDisposition) throw new InvalidVerdictError('verdict has neither `flagged` nor `disposition`');
  if (hasFlag && typeof v.flagged !== 'boolean') throw new InvalidVerdictError('verdict `flagged` must be a boolean');
  if (v.alert !== undefined && typeof v.alert !== 'boolean') throw new InvalidVerdictError('verdict `alert` must be a boolean');
  let blocking = false;
  if (hasDisposition) {
    if (typeof v.disposition !== 'string') throw new InvalidVerdictError('verdict `disposition` must be a string');
    const key = v.disposition.toLowerCase();
    if (!Object.hasOwn(DISPOSITIONS, key)) throw new InvalidVerdictError('verdict `disposition` is not a T4 disposition');
    blocking = DISPOSITIONS[key] === 'Blocked';
  }
  return v.flagged === true || blocking ? 'flagged' : 'clean'; // on conflict, flagged wins
}

/**
 * Run every inspector. Returns { verdicts, alertOnly }:
 *   verdicts  - flagged verdicts (block mode refuses on these).
 *   alertOnly - NOT flagged but `alert: true` or disposition 'report' (T3 response-phase post-execution evidence: DVAA already
 *               ran the tool in-process, so it is logged as an ALERT, never claimed as a block).
 */
async function runInspectors(inspectors, ctx) {
  const verdicts = [];
  const alertOnly = [];
  for (const inspect of inspectors) {
    const v = await inspect(ctx);
    const cls = classifyVerdict(v);
    // Not flagged, but evidence: `alert: true` (T3 post-execution) or a ReportOnly disposition ('report').
    const reportOnly = typeof v?.disposition === 'string' && DISPOSITIONS[v.disposition.toLowerCase()] === 'ReportOnly';
    if (cls === 'clean' && v?.alert !== true && !reportOnly) continue;
    const entry = { detector: v.detector ?? v.ruleId ?? inspect.name ?? 'anonymous', reasons: v.reasons ?? [], ...v };
    (cls === 'flagged' ? verdicts : alertOnly).push(entry);
  }
  return { verdicts, alertOnly };
}

/** Run a phase's inspectors under a deadline. Rejects with InspectorTimeoutError when it passes. */
async function runInspectorsWithDeadline(inspectors, ctx, timeoutMs) {
  const ac = new AbortController();
  let timer;
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => {
      const err = new InspectorTimeoutError(timeoutMs);
      ac.abort(err);
      reject(err);
    }, timeoutMs);
  });
  try {
    return await Promise.race([runInspectors(inspectors, { ...ctx, signal: ac.signal }), deadline]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Log scrubber: everything that goes to stderr or into a capture record EXCEPT the exchange bodies,
 * path and headers (kept raw as evidence; the capture file is 0600) passes through this.
 * JSON round-trip first so toJSON()/Buffers/Dates are seen as the strings that would be logged
 * (a Buffer is decoded, so a secret carried as bytes is still redacted). redactDeep is linear and
 * bounded (MAX_REDACT_SCAN_CHARS per string, MAX_REDACT_TOTAL_CHARS per call); over budget it
 * WITHHOLDS the whole string (marker with length + hash), never passes an unscanned tail.
 */
export function flagSubstringCanaries(flagSubstrings) {
  return flagSubstrings.map((value, i) => ({ id: flagSubstringId(i), value }));
}

/** @param {Array<{id:string, value:string}>} canaries honeytokens to redact (raw/%/hex/base64 forms) */
export function makeLogScrubber(canaries) {
  try {
    prepareCanaries(canaries); // validate once, at startup: fail loud on a value redaction can't cover
  } catch (err) {
    throw new ConfigError(`inspect.flagSubstrings / honeytokens cannot be used as log-redaction canaries: ${err.message}`);
  }
  const toLoggable = (_k, v) => {
    if (v && v.type === 'Buffer' && Array.isArray(v.data)) {
      const b = Buffer.from(v.data);
      return isUtf8(b) ? b.toString('utf8') : `base64:${b.toString('base64')}`;
    }
    return v;
  };
  return (value) => {
    const json = JSON.stringify(value, toLoggable);
    if (json === undefined) return value;
    return redactDeep(JSON.parse(json), { canaries }).value;
  };
}

function jsonBuffer(obj) {
  return Buffer.from(JSON.stringify(obj));
}

/** Only numbers, booleans and known static action strings survive into a client-facing detail. */
function safeDetail(detail) {
  if (!detail) return null;
  const out = {};
  for (const [k, v] of Object.entries(detail)) {
    if (typeof v === 'number' || typeof v === 'boolean') out[k] = v;
    else if (k === 'action' && STATIC_DETAIL_ACTIONS.has(v)) out[k] = v;
  }
  return Object.keys(out).length > 0 ? out : null;
}

/**
 * Structured refusal returned instead of forwarding (block mode) — the hook T3/T4 plug into.
 * Client-facing, so it carries ONLY static codes, the request id and numeric size details.
 * Verdict content (detector names, reasons, evidence) and error messages stay in the log; echoing
 * them would turn the refusal into an exfil channel.
 */
export function buildRefusal({ requestId, phase, reason, verdicts = [], mode, detail }) {
  const code = REFUSAL_CODES.includes(reason) ? reason : 'internal_error';
  const safe = safeDetail(detail);
  return {
    error: {
      type: 'sentinel_blocked',
      code,
      message: `Tourniquet refused this ${phase}: ${code}`,
    },
    sentinel: {
      request_id: requestId,
      blocked: true,
      mode,
      phase,
      reason: code,
      verdict_count: verdicts.length,
      ...(safe ? { detail: safe } : {}),
    },
  };
}

/**
 * Create the proxy. Returns { server, sink, listen(), close() }.
 * @param {object} config validated config (see sentinel/config/load.mjs)
 * @param {{inspectors?: Function[], sink?: {write: Function, flush: Function}, logAlert?: Function, scrub?: Function}} [deps]
 */
export function createProxy(config, deps = {}) {
  const { mode, target, limits } = config;
  // Defence in depth: validateConfig already enforces this, but createProxy is also a public API.
  if (!isLoopbackHost(target.host)) throw new ConfigError(`target.host must be a loopback address, got ${JSON.stringify(target.host)}`);
  const sink = deps.sink ?? new JsonlCaptureSink(config.capture);
  const inspectors = deps.inspectors ?? [substringInspector(config.inspect.flagSubstrings)];
  const logAlert = deps.logAlert ?? ((alert) => process.stderr.write(`[sentinel] ALERT ${JSON.stringify(alert)}\n`));
  // Every alert / verdict / error string is scrubbed before logAlert or the sink sees it.
  // deps.scrub: the CLI builds one scrubber over T3's honeytokens + flagSubstrings and shares it with T3's logger.
  const scrub = deps.scrub ?? makeLogScrubber(flagSubstringCanaries(config.inspect.flagSubstrings));
  const block = mode === 'block';
  // deps.newRequestId: test seam only (pins a UUID the scrubber would mangle); production uses randomUUID.
  const newRequestId = deps.newRequestId ?? randomUUID;
  let inFlight = 0;

  // request_id is the proxy's own randomUUID(), never client data, and it is the ONLY key that joins an alert
  // record to its exchange record (which is not scrubbed). The scrubber's payment-card / digit-run patterns
  // match ~1 in 8,000 UUIDs (e.g. 41812006-4939-4383-…: a Luhn-valid run across the hyphens). A redacted
  // id orphaned that alert from its exchange (pipeline flake: extra `proxy-unattributed` capture, ~2.5% of
  // 210-request runs). So the id is re-pinned after scrubbing; every other field stays redacted.
  const scrubAlert = (requestId, fields) => ({ ...scrub(fields), request_id: requestId });

  async function emitAlert(requestId, alert) {
    const record = scrubAlert(requestId, { type: 'alert', ts: new Date().toISOString(), request_id: requestId, mode, ...alert });
    logAlert(record);
    try {
      await sink.write(record);
    } catch (err) {
      logAlert(scrubAlert(requestId, { type: 'alert', request_id: requestId, reason: 'capture_write_failed', error: err.message }));
    }
    return record;
  }

  async function handle(req, res, requestId, { expectContinue = false } = {}) {
    const started = process.hrtime.bigint();
    const path = req.url ?? '/';
    let upstreamMs = null;
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
    const reply = async (status, headers, body, action, { contentLength = body.length, decodedBody } = {}) => {
      record.action = action;
      record.response = { status, headers, body: encodeBody(body), ...(decodedBody ? { decoded_body: decodedBody } : {}) };
      record.latency_ms = Number(process.hrtime.bigint() - started) / 1e6;
      // proxy_overhead_ms = total - upstream: the proxy's own share of the latency budget.
      record.timings = { total_ms: record.latency_ms, upstream_ms: upstreamMs, proxy_overhead_ms: record.latency_ms - (upstreamMs ?? 0) };
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
        contentLength = body.length;
      }
      res.writeHead(status, { ...headers, 'content-length': contentLength, 'x-sentinel-request-id': requestId });
      res.end(body);
    };
    const refuse = (status, phase, reason, verdicts, detail) => {
      const body = jsonBuffer(buildRefusal({ requestId, phase, reason, verdicts, mode, detail }));
      return reply(status, { 'content-type': 'application/json' }, body, `blocked_${phase}`);
    };
    const tooLarge = async (err, phase) => {
      const request = phase === 'request';
      const detail = {
        payload_size: err.payload_size, cap: err.cap, size_is_lower_bound: err.size_is_lower_bound,
        ...(err.decoded ? { decoded: true } : {}),
        action: request ? 'rejected_not_forwarded' : 'rejected_not_returned',
      };
      await emitAlert(requestId, { reason: request ? 'request_too_large' : 'response_too_large', phase, ...detail });
      return refuse(request ? 413 : 502, phase, request ? 'request_too_large' : 'response_too_large', [], detail);
    };

    /**
     * Decode + inspect one phase. Returns { stop: Promise } when the exchange ends here (refused),
     * else { decoded } (null when the body could not be decoded and observe mode forwards anyway).
     */
    const inspectPhase = async (phase, raw, headers, extraCtx) => {
      let decoded;
      let encodings = [];
      try {
        ({ body: decoded, encodings } = await decodeContent(raw, headers['content-encoding'], phase === 'request' ? limits.maxRequestBytes : limits.maxResponseBytes, phase));
      } catch (err) {
        if (err instanceof PayloadTooLargeError) return { stop: tooLarge(err, phase) };
        if (!(err instanceof UninspectableEncodingError)) throw err;
        await emitAlert(requestId, { reason: 'uninspectable_encoding', phase, encoding: err.encoding, error: err.message, action: block ? 'fail_closed' : `${phase === 'request' ? 'forwarded' : 'returned'}_uninspected` });
        if (block) return { stop: refuse(phase === 'request' ? 415 : 502, phase, 'uninspectable_encoding') };
        return { decoded: null };
      }
      // #157: a request body that is not valid UTF-8 after content-decoding (octet-stream, binary
      // multipart parts, images, unknown binary types) cannot be parsed by T3 and is only byte-scanned
      // for raw canaries. Block mode refuses it before forwarding (fail-closed); observe forwards + ALERT.
      // Text bodies of ANY content-type (JSON, text, form, base64 data URIs inside JSON) are inspected as before.
      if (phase === 'request' && decoded.length > 0 && !isUtf8(decoded)) {
        await emitAlert(requestId, {
          reason: 'uninspectable_content', phase, content_type: String(headers['content-type'] ?? '').slice(0, 100),
          bytes: decoded.length, action: block ? 'fail_closed' : 'forwarded_uninspected',
        });
        if (block) return { stop: refuse(415, phase, 'uninspectable_content') };
      }
      let verdicts;
      let alertOnly = [];
      // Inspectors get COPIES: nothing an inspector does to ctx.body / rawBody / headers can change the
      // bytes or headers that are forwarded, returned or captured (ported from the PR #21 proxy).
      const bodyCopy = Buffer.from(decoded);
      const rawCopy = decoded === raw ? bodyCopy : Buffer.from(raw);
      try {
        ({ verdicts, alertOnly } = await runInspectorsWithDeadline(inspectors, {
          phase, method: req.method, path, headers: structuredClone(headers), body: bodyCopy, rawBody: rawCopy,
          contentEncoding: encodings, requestId, ...extraCtx,
        }, limits.inspectorTimeoutMs));
      } catch (err) {
        const reason = err instanceof InspectorTimeoutError ? 'inspector_timeout' : 'inspector_error';
        await emitAlert(requestId, { reason, phase, error: err.message, action: block ? 'fail_closed' : `${phase === 'request' ? 'forwarded' : 'returned'}_uninspected` });
        if (block) return { stop: refuse(503, phase, reason) };
        verdicts = [];
      }
      // Verdicts are logged in the exchange record, so they are scrubbed; the bodies are not.
      record.verdicts.push(...verdicts.map((v) => scrub({ phase, ...v })));
      if (alertOnly.length > 0) {
        // Not flagged, so nothing is refused, but the evidence must reach the logs (redacted like the rest).
        record.verdicts.push(...alertOnly.map((v) => scrub({ phase, ...v })));
        await emitAlert(requestId, { reason: 'detector_alert', phase, verdicts: alertOnly, action: 'alert_only' });
      }
      return { decoded, encodings, verdicts };
    };

    // 0. Expect: 100-continue — refuse a declared oversize body before inviting the upload.
    if (expectContinue) {
      const declared = Number(req.headers['content-length']);
      if (Number.isFinite(declared) && declared > limits.maxRequestBytes) {
        res.shouldKeepAlive = false; // the client may still send the body; never read it
        record.request.body = { encoding: 'omitted', bytes: declared, reason: 'over_cap' };
        return tooLarge(new PayloadTooLargeError({ payload_size: declared, cap: limits.maxRequestBytes, phase: 'request' }), 'request');
      }
      res.writeContinue();
    }

    // 1. bounded request read
    let reqBody;
    try {
      reqBody = await readRequestBody(req, limits.maxRequestBytes);
    } catch (err) {
      if (err instanceof PayloadTooLargeError) {
        record.request.body = { encoding: 'omitted', bytes: err.payload_size, reason: 'over_cap' };
        if (err.drain_exceeded) res.shouldKeepAlive = false;
        return tooLarge(err, 'request');
      }
      if (err instanceof ClientAbortedError) {
        await emitAlert(requestId, { reason: 'client_aborted', phase: 'request', error: err.cause?.message, action: 'dropped_not_forwarded' });
        res.destroy();
        return undefined;
      }
      throw err;
    }
    record.request.body = encodeBody(reqBody);

    // 2-3. decode + request-phase inspection over the FULL body, URL and headers
    {
      const r = await inspectPhase('request', reqBody, req.headers, {});
      if (r.stop) return r.stop;
      if (r.encodings?.length) record.request.decoded_body = encodeBody(r.decoded);
      if (r.verdicts?.length > 0) {
        await emitAlert(requestId, { reason: 'flagged', phase: 'request', verdicts: r.verdicts, action: block ? 'blocked' : 'would_block_observe_only' });
        if (block) return refuse(403, 'request', 'flagged_request', r.verdicts);
      }
    }

    // 4. write-ahead: no agent side effect without a request record on disk
    try {
      await sink.write({ type: 'request', ts: new Date().toISOString(), request_id: requestId, mode, target: record.target, request: record.request });
    } catch (err) {
      await emitAlert(requestId, {
        reason: 'capture_write_failed', phase: 'request', action: 'refused_not_forwarded', error: err.message,
        ...(err.payload_size !== undefined ? { payload_size: err.payload_size, cap: err.cap } : {}),
      });
      return refuse(503, 'capture', 'capture_unavailable');
    }

    // 5. forward with bounded response read
    let upstream;
    const upstreamStarted = process.hrtime.bigint();
    try {
      upstream = await forward({
        target, method: req.method, path, headers: req.headers, body: reqBody,
        cap: limits.maxResponseBytes, timeoutMs: limits.upstreamTimeoutMs,
      });
    } catch (err) {
      upstreamMs = Number(process.hrtime.bigint() - upstreamStarted) / 1e6;
      if (err instanceof PayloadTooLargeError) return tooLarge(err, 'response');
      const timeout = err.code === 'UPSTREAM_TIMEOUT';
      await emitAlert(requestId, { reason: timeout ? 'upstream_timeout' : 'upstream_error', phase: 'forward', error: err.message, action: 'refused' });
      return refuse(timeout ? 504 : 502, 'forward', timeout ? 'upstream_timeout' : 'upstream_unreachable');
    }

    upstreamMs = Number(process.hrtime.bigint() - upstreamStarted) / 1e6;

    // 6. decode + response-phase inspection over the FULL body and headers
    let decodedBody;
    {
      const r = await inspectPhase('response', upstream.body, upstream.headers, { status: upstream.status });
      if (r.stop) return r.stop;
      if (r.encodings?.length) decodedBody = encodeBody(r.decoded);
      if (r.verdicts?.length > 0) {
        record.upstream_response = { status: upstream.status, headers: upstream.headers, body: encodeBody(upstream.body), ...(decodedBody ? { decoded_body: decodedBody } : {}) };
        await emitAlert(requestId, { reason: 'flagged', phase: 'response', verdicts: r.verdicts, action: block ? 'blocked' : 'would_block_observe_only' });
        if (block) {
          return refuse(403, 'response', 'flagged_response', r.verdicts, {
            upstream_tool_calls_already_executed: upstreamToolCallsExecuted(r.decoded),
          });
        }
      }
    }

    // 8. return upstream response unchanged. HEAD keeps the upstream's Content-Length (no body sent).
    const outHeaders = stripHopByHop(upstream.headers);
    const headLength = req.method === 'HEAD' && upstream.headers['content-length'] !== undefined
      ? upstream.headers['content-length'] : undefined;
    return reply(upstream.status, outHeaders, upstream.body, 'forwarded', {
      decodedBody, ...(headLength !== undefined ? { contentLength: headLength } : {}),
    });
  }

  const staticJson = (status, reason, requestId) => {
    const body = JSON.stringify(buildRefusal({ requestId, phase: 'proxy', reason, mode }));
    return { status, body, headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body), 'x-sentinel-request-id': requestId } };
  };

  function dispatch(req, res, opts) {
    const requestId = newRequestId();
    if (inFlight >= limits.maxInFlight) {
      // Admission control: refuse before reading/buffering anything. The unread body is discarded
      // (no memory held); the connection closes after the reply.
      res.shouldKeepAlive = false;
      req.resume();
      const out = staticJson(503, 'overloaded', requestId);
      emitAlert(requestId, { reason: 'overloaded', in_flight: inFlight, cap: limits.maxInFlight, action: 'refused_not_forwarded' })
        .catch(() => {})
        .finally(() => { res.writeHead(out.status, out.headers); res.end(out.body); });
      return;
    }
    inFlight += 1;
    handle(req, res, requestId, opts).catch(async (err) => {
      try {
        await emitAlert(requestId, { reason: 'proxy_internal_error', error: err.message, action: 'refused' });
      } catch (alertErr) {
        let msg;
        try { msg = scrub(String(alertErr?.message)); } catch { msg = '[unredactable error message withheld]'; }
        process.stderr.write(`[sentinel] ALERT-PATH FAILURE request_id=${requestId}: ${msg}\n`);
      } finally {
        if (!res.headersSent) {
          const out = staticJson(500, 'internal_error', requestId);
          res.writeHead(out.status, out.headers);
          res.end(out.body);
        } else {
          res.destroy();
        }
      }
    }).finally(() => { inFlight -= 1; });
  }

  const server = http.createServer({
    requestTimeout: limits.clientTimeoutMs,
    headersTimeout: limits.clientTimeoutMs,
    connectionsCheckingInterval: Math.min(1000, limits.clientTimeoutMs),
  }, (req, res) => dispatch(req, res, {}));
  server.maxConnections = limits.maxInFlight * CONNECTIONS_PER_IN_FLIGHT;
  server.on('checkContinue', (req, res) => dispatch(req, res, { expectContinue: true }));
  server.on('drop', (data) => {
    emitAlert(null, { reason: 'connection_dropped', cap: server.maxConnections, remote: data?.remoteAddress, action: 'dropped' }).catch(() => {});
  });
  server.on('clientError', (err, socket) => {
    const timeout = err.code === 'ERR_HTTP_REQUEST_TIMEOUT';
    if (timeout) {
      emitAlert(null, { reason: 'client_timeout', cap_ms: limits.clientTimeoutMs, action: 'refused_not_forwarded' }).catch(() => {});
    }
    if (!socket.writable || err.code === 'ECONNRESET') { socket.destroy(); return; }
    const status = timeout ? 408 : 400;
    const body = timeout ? JSON.stringify(buildRefusal({ requestId: null, phase: 'request', reason: 'client_timeout', mode })) : '';
    socket.end(`HTTP/1.1 ${status} ${http.STATUS_CODES[status]}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`);
  });

  return {
    server,
    sink,
    config,
    get inFlight() { return inFlight; },
    listen(port = config.listen.port, host = config.listen.host) {
      if (!isLoopbackHost(host)) {
        return Promise.reject(new ConfigError(`listen host must be a loopback address, got ${JSON.stringify(host)}`));
      }
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
