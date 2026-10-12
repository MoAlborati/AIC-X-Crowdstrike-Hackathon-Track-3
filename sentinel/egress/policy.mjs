// SentinelProxy T12 — tool-boundary egress policy (pure function, no I/O).
//
//   inspectEgress(request, config) -> verdict  (same envelope as T3's toInspectorVerdict, direction "egress")
//
// The inspector (inspector.mjs) calls this for every outbound request DVAA's agents make. The decision
// is computed over the FULL URL + FULL body (never a head/tail window) and over their %-decoded views.
// Every reason is a STATIC code from REASON_CODES: no host, token value or other request data is ever
// interpolated into a reason (dynamic detail lives in bounded, redacted alert fields instead).
//
// Fail-closed: oversize input, decode depth exceeded, scan error and scan time-budget overrun all DENY
// in BOTH modes (observe|block) with a loud ALERT. Observe mode only relaxes *policy* hits (honeytoken,
// allowlist): they are forwarded and alerted as "Allowed".

import { createHash, randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { buildAlert } from '../alerts/schema.js';
import { MAX_CANARIES, MIN_CANARY_VALUE_CHARS } from '../alerts/redact.js';
import { HoneytokenRegistry, DVAA_HONEYTOKENS } from '../detectors/src/honeytokens.js';
import { decodedVariants, findSecretShapes, findSsns } from '../detectors/src/text.js';

export { DVAA_HONEYTOKENS };

export const REASON_CODES = Object.freeze({
  HONEYTOKEN_MATCH: 'honeytoken_match',
  SECRET_PATTERN_MATCH: 'secret_pattern_match',
  DESTINATION_NOT_ALLOWLISTED: 'destination_not_allowlisted',
  EGRESS_OVER_CAP: 'egress_over_cap',
  DECODE_DEPTH_EXCEEDED: 'decode_depth_exceeded',
  SCAN_TIMEOUT: 'scan_timeout',
  SCAN_ERROR: 'scan_error',
  REQUEST_TIMEOUT: 'request_timeout',
  PROXY_PARSE_ERROR: 'proxy_parse_error',
  BAD_PROXY_REQUEST: 'bad_proxy_request',
  CLIENT_NOT_ALLOWED: 'client_not_allowed',
  LOG_WRITE_FAILED: 'log_write_failed',
});
const CODES = new Set(Object.values(REASON_CODES));
// Fail-closed codes deny regardless of mode.
export const FAIL_CLOSED_CODES = Object.freeze(new Set([
  REASON_CODES.EGRESS_OVER_CAP, REASON_CODES.DECODE_DEPTH_EXCEEDED, REASON_CODES.SCAN_TIMEOUT,
  REASON_CODES.SCAN_ERROR, REASON_CODES.REQUEST_TIMEOUT, REASON_CODES.PROXY_PARSE_ERROR,
  REASON_CODES.BAD_PROXY_REQUEST, REASON_CODES.CLIENT_NOT_ALLOWED, REASON_CODES.LOG_WRITE_FAILED,
]));

// ---- Bounds (documented in the PR "Bounds introduced" section) ---------------------------------------
export const DEFAULTS = Object.freeze({
  MAX_EGRESS_BYTES: 64 * 1024, // URL + body scanned in full; above -> 413 + ALERT, never forwarded
  MAX_DECODE_ROUNDS: 4, // %-/\\u-decode iterations (double/triple/mixed encoding); still changing after -> deny
  SCAN_BUDGET_MS: 250, // measured scan time; over -> deny + ALERT scan_timeout
  MAX_HONEYTOKENS: MAX_CANARIES, // registry size = T4 redact.js canary cap; over -> config load throws
  MIN_HONEYTOKEN_CHARS: MIN_CANARY_VALUE_CHARS, // shorter values would false-positive; config load throws
});

const sha16 = (s) => createHash('sha256').update(s).digest('hex').slice(0, 16);

/**
 * Decoded views of `text` via T3's linear-time `decodedVariants` (repeated %, form '+', \\u/\\x escapes,
 * base64 and hex runs: a whole run is decoded, so a canary at ANY byte offset inside a larger base64 blob
 * is found). It runs one level deeper than allowed so that encoding nested beyond `maxRounds` is
 * DETECTED (overDepth -> fail closed) rather than silently left undecoded.
 */
export function decodedViews(text, maxRounds = DEFAULTS.MAX_DECODE_ROUNDS) {
  const vars = decodedVariants(text, { depth: maxRounds + 1 });
  // JSON-stringified escapes ("\\\\u0073") keep a doubled backslash after %-decoding: add ONE extra pass over
  // each view with "\\\\" collapsed (bounded: at most one extra decode tree, same depth cap).
  for (const v of [...vars]) {
    if (v.text.indexOf('\\\\') === -1) continue;
    for (const w of decodedVariants(v.text.replace(/\\\\/g, '\\'), { depth: maxRounds + 1 })) {
      vars.push({ text: w.text, encoding: v.encoding === 'raw' ? w.encoding : `${v.encoding}+${w.encoding}` });
    }
  }
  const depthOf = (enc) => (enc === 'raw' ? 0 : enc.split('+').length);
  return {
    views: vars.filter((v) => depthOf(v.encoding) <= maxRounds).map((v) => v.text),
    overDepth: vars.some((v) => depthOf(v.encoding) > maxRounds),
  };
}

/** Validate + normalise the honeytoken registry. Throws (fail loud) on a bad registry. */
export function loadHoneytokens(list, { max = DEFAULTS.MAX_HONEYTOKENS, minChars = DEFAULTS.MIN_HONEYTOKEN_CHARS } = {}) {
  if (!Array.isArray(list)) throw new TypeError('honeytokens must be an array of {id, value}');
  if (list.length > max) throw new RangeError(`honeytoken registry has ${list.length} entries, cap ${max}`);
  const out = [];
  for (const [i, t] of list.entries()) {
    if (!t || typeof t.id !== 'string' || typeof t.value !== 'string') throw new TypeError(`honeytokens[${i}] must be {id, value}`);
    if (t.value.length < minChars) throw new RangeError(`honeytokens[${i}] (${t.id}) shorter than ${minChars} chars`);
    out.push({ id: t.id, value: t.value });
  }
  // T3's pool-size-independent registry does the matching; the plain list feeds T4 alert redaction.
  const registry = new HoneytokenRegistry({ maxCanaries: 0 });
  for (const t of out) registry.addStatic({ id: t.id, value: t.value, label: t.id });
  Object.defineProperty(out, 'registry', { value: registry, enumerable: false });
  return Object.freeze(out);
}

/** Host allowlist: exact hostname match (case-insensitive). No wildcard, no suffix match. */
export function makeAllowlist(hosts) {
  return new Set((hosts ?? []).map((h) => String(h).trim().toLowerCase()).filter(Boolean));
}

/**
 * Inspect one outbound request.
 * @param {{kind:'http'|'connect', method:string, url:string, host:string, port?:number, body?:Buffer, size?:number}} req
 *   url  = absolute-form request target (http) or "host:port" (connect)
 *   size = total bytes received (URL + body) — may exceed body.length when the body was capped
 * @param {{mode:'observe'|'block', allow:Set<string>, honeytokens:Array, maxBytes?:number, maxDecodeRounds?:number,
 *          scanBudgetMs?:number, agentLabel?:string, faults?:{scan?:'error'|'slow'}, now?:()=>number}} cfg
 */
export function inspectEgress(req, cfg) {
  const t0 = performance.now();
  const maxBytes = cfg.maxBytes ?? DEFAULTS.MAX_EGRESS_BYTES;
  const reasons = [];
  const add = (r) => { if (!CODES.has(r)) throw new Error(`non-static reason code ${r}`); if (!reasons.includes(r)) reasons.push(r); };
  const facts = { urlBytes: Buffer.byteLength(req.url ?? ''), bodyBytes: req.body?.length ?? 0, canaryIds: [], secretKinds: [] };
  const size = req.size ?? facts.urlBytes + facts.bodyBytes;
  facts.size = size;
  let matchedCanary = null;

  if (!cfg.allow.has(String(req.host ?? '').toLowerCase())) add(REASON_CODES.DESTINATION_NOT_ALLOWLISTED);

  if (size > maxBytes) {
    add(REASON_CODES.EGRESS_OVER_CAP); // never scan a partial payload and call it clean
  } else {
    try {
      if (cfg.faults?.scan === 'error') throw new Error('injected scan fault');
      const texts = [req.url ?? ''];
      if (req.body?.length) texts.push(req.body.toString('utf8'));
      for (const text of texts) {
        const { views, overDepth } = decodedViews(text, cfg.maxDecodeRounds);
        if (overDepth) add(REASON_CODES.DECODE_DEPTH_EXCEEDED);
        for (const v of views) {
          for (const { entry } of cfg.honeytokens.registry.scan(v)) {
            add(REASON_CODES.HONEYTOKEN_MATCH);
            if (!facts.canaryIds.includes(entry.id)) facts.canaryIds.push(entry.id);
            matchedCanary ??= { id: entry.id, value: entry.value };
          }
          // T3's tokenizer keeps URL delimiters inside a token ("k=ghp_..."): split them for shape tests only.
          const sv = v.replace(/[/?&=#:;,]/g, ' ');
          for (const f of [...findSecretShapes(sv), ...findSsns(v)]) {
            add(REASON_CODES.SECRET_PATTERN_MATCH);
            const k = f.kind ?? 'ssn';
            if (!facts.secretKinds.includes(k)) facts.secretKinds.push(k);
          }
        }
      }
      if (cfg.faults?.scan === 'slow') { const end = performance.now() + (cfg.scanBudgetMs ?? DEFAULTS.SCAN_BUDGET_MS) + 5; while (performance.now() < end); }
    } catch {
      add(REASON_CODES.SCAN_ERROR);
    }
  }
  const latencyMs = +(performance.now() - t0).toFixed(3);
  if (latencyMs > (cfg.scanBudgetMs ?? DEFAULTS.SCAN_BUDGET_MS)) add(REASON_CODES.SCAN_TIMEOUT);

  return decide(req, cfg, reasons, facts, matchedCanary, latencyMs);
}

/** Verdict for a request that failed before it could be scanned (parse error, timeout, client check). */
export function failClosedVerdict(code, req, cfg) {
  return decide(req, cfg, [code], { urlBytes: Buffer.byteLength(req.url ?? ''), bodyBytes: 0, size: req.size ?? 0, canaryIds: [], secretKinds: [] }, null, 0);
}

function decide(req, cfg, reasons, facts, matchedCanary, latencyMs) {
  const failClosed = reasons.some((r) => FAIL_CLOSED_CODES.has(r));
  // secret_pattern_match is evidence only (generic patterns, e.g. Luhn on 13-digit epoch ms, would FP on
  // allowlisted traffic); it never decides a deny on its own.
  const policyHit = reasons.includes(REASON_CODES.HONEYTOKEN_MATCH) || reasons.includes(REASON_CODES.DESTINATION_NOT_ALLOWLISTED);
  const flagged = failClosed || policyHit || reasons.includes(REASON_CODES.SECRET_PATTERN_MATCH);
  const action = failClosed || (policyHit && cfg.mode === 'block') ? 'deny' : 'forward';
  const verdict = {
    flagged,
    alert: flagged,
    detector: 'sentinel-egress',
    direction: 'egress',
    disposition: action === 'deny' ? 'block' : 'allow',
    prevents: action === 'deny', // the request has not left yet: a deny at this boundary stops the bytes
    action,
    mode: cfg.mode,
    failClosed,
    reasons,
    requestId: randomUUID(),
    latencyMs,
    host: req.host ?? null,
    kind: req.kind,
    method: req.method,
    urlBytes: facts.urlBytes,
    bodyBytes: facts.bodyBytes,
    size: facts.size,
    urlSha256: req.url ? sha16(req.url) : null,
    canaryIds: facts.canaryIds,
    secretKinds: facts.secretKinds,
    alertDoc: null,
  };
  if (flagged) verdict.alertDoc = toAlert(req, cfg, verdict, matchedCanary);
  return verdict;
}

function primaryCategory(reasons) {
  if (reasons.includes(REASON_CODES.HONEYTOKEN_MATCH)) return ['honeytoken_exfil', 'egress.honeytoken_match'];
  const fc = reasons.find((r) => FAIL_CLOSED_CODES.has(r));
  if (fc) return ['scan_cap_exceeded', `egress.failclosed.${fc}`];
  if (reasons.includes(REASON_CODES.DESTINATION_NOT_ALLOWLISTED)) return ['egress_unallowlisted_domain', 'egress.destination_not_allowlisted'];
  return ['egress_secret_pattern', 'egress.secret_pattern_match'];
}

/** Build the T4 alert. buildAlert redacts canaries/secrets and bounds every string. */
function toAlert(req, cfg, v, matchedCanary) {
  const [category, ruleId] = primaryCategory(v.reasons);
  let dest = req.kind === 'connect' ? `connect://${req.url}` : null;
  if (!dest) {
    try { const u = new URL(req.url); dest = `${u.protocol}//${u.host}${u.pathname}`; } catch { dest = `unparsed:${v.host ?? 'unknown'}`; }
  }
  const alert = buildAlert({
    category,
    ruleId,
    disposition: v.action === 'deny' ? 'block' : 'allow',
    detectionLatencyMs: v.latencyMs,
    entities: {
      agent: { name: cfg.agentLabel ?? 'dvaa', id: 'egress-boundary' },
      // Correlation to a chat turn is out of scope (T12 known limitation): session is unattributed.
      session: { id: 'egress-unattributed' },
      toolCall: { id: v.requestId, name: `egress.${req.kind}.${req.method ?? 'CONNECT'}` },
      sink: { type: req.kind === 'connect' ? 'connect_tunnel' : 'http_egress', destination: dest },
    },
    taintPath: [{ kind: 'sink', label: `tool-boundary egress -> ${v.host ?? 'unknown'}`, trust: 'external' }],
    layers: v.reasons.map((r) => ({ layer: 'egress', rule: `egress.${r}`, fired: true, latencyMs: v.latencyMs })),
    evidence: `egress ${req.method ?? 'CONNECT'} ${dest} url_bytes=${v.urlBytes} body_bytes=${v.bodyBytes} size=${v.size} ` +
      `reasons=[${v.reasons.join(',')}] canaries=[${v.canaryIds.join(',')}] mode=${cfg.mode} action=${v.action}`,
    ...(matchedCanary ? { canary: matchedCanary } : {}),
    canaries: cfg.honeytokens,
  }, { onWarning: () => {} });
  return alert;
}
