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
import { redactString, MAX_CANARIES, MIN_CANARY_VALUE_CHARS } from '../alerts/redact.js';

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

/** Tolerant %-decoder: decodes every %XX run as UTF-8 bytes; malformed sequences are left as-is. */
export function pctDecode(s) {
  return s.replace(/(?:%[0-9a-fA-F]{2})+/g, (run) => Buffer.from(run.replace(/%/g, ''), 'hex').toString('utf8'));
}

/** Decode JS/JSON-style escapes: \\uXXXX, \\u{X..}, \\xXX. Malformed escapes are left as-is. */
export function escDecode(s) {
  return s
    .replace(/\\u\{([0-9a-fA-F]{1,6})\}/g, (m, h) => { const cp = parseInt(h, 16); return cp <= 0x10ffff ? String.fromCodePoint(cp) : m; })
    .replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
}

/**
 * All decoded views of a string: raw, then iterative (%-decode + form '+' -> ' ' + \\u/\\x-unescape)
 * until stable. One round applies all three, so mixed forms (%5Cu0064 -> \\u0064 -> d) need 2 rounds.
 * Returns { views, overDepth } — overDepth means it was still changing after MAX_DECODE_ROUNDS.
 */
export function decodedViews(s, maxRounds = DEFAULTS.MAX_DECODE_ROUNDS) {
  const views = [s];
  let cur = s;
  for (let i = 0; i < maxRounds; i++) {
    const next = escDecode(pctDecode(cur.replace(/\+/g, ' ')));
    if (next === cur) return { views, overDepth: false };
    views.push(next);
    cur = next;
  }
  return { views, overDepth: escDecode(pctDecode(cur.replace(/\+/g, ' '))) !== cur };
}

/** Validate + normalise the honeytoken registry. Throws (fail loud) on a bad registry. */
export function loadHoneytokens(list, { max = DEFAULTS.MAX_HONEYTOKENS, minChars = DEFAULTS.MIN_HONEYTOKEN_CHARS } = {}) {
  if (!Array.isArray(list)) throw new TypeError('honeytokens must be an array of {id, value}');
  if (list.length > max) throw new RangeError(`honeytoken registry has ${list.length} entries, cap ${max}`);
  const out = [];
  for (const [i, t] of list.entries()) {
    if (!t || typeof t.id !== 'string' || typeof t.value !== 'string') throw new TypeError(`honeytokens[${i}] must be {id, value}`);
    if (t.value.length < minChars) throw new RangeError(`honeytokens[${i}] (${t.id}) shorter than ${minChars} chars`);
    // redact.js expands each canary into its own encoded variants (case, separators, base64, hex, %).
    out.push({ id: t.id, value: t.value });
  }
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
          // T4 redact.js is the single canary/secret matcher: canaries first, then generic patterns.
          const { findings, withheld } = redactString(v, { canaries: cfg.honeytokens });
          if (withheld) add(REASON_CODES.EGRESS_OVER_CAP);
          for (const f of findings) {
            if (f.kind === 'canary') {
              add(REASON_CODES.HONEYTOKEN_MATCH);
              if (!facts.canaryIds.includes(f.canaryId)) facts.canaryIds.push(f.canaryId);
              matchedCanary ??= cfg.honeytokens.find((h) => h.id === f.canaryId);
            } else {
              add(REASON_CODES.SECRET_PATTERN_MATCH);
              if (!facts.secretKinds.includes(f.kind)) facts.secretKinds.push(f.kind);
            }
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
