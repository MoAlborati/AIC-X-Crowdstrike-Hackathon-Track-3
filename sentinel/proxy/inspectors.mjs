// Inspector contract (the hook T3 detectors plug into):
//
//   async function inspector({ phase, method, path, headers, body, rawBody, contentEncoding,
//                              requestId, status?, signal })
//     -> verdict | null
//
// `body` is the FULL, DECODED Buffer: when the message carried `content-encoding: gzip|deflate|br`
// the proxy inflated it (bounded by limits.max{Request,Response}Bytes, which reject loudly on
// overflow) before calling you. `rawBody` is the bytes as they travel on the wire. Inspectors must
// scan all of `body` — no head/tail windows — and should also look at `path` (request phase) and
// `headers`, because a secret can leave in a query string or a header as easily as in a body.
//
// `signal` is an AbortSignal that fires when limits.inspectorTimeoutMs expires. The proxy does not
// wait past the deadline (block mode: 503 `inspector_timeout`; observe mode: forward + ALERT), so a
// long-running inspector should stop work when it fires.
//
// Verdict shape. Return null/undefined for "nothing found". Otherwise return an object with
//   - `flagged: boolean`, and/or
//   - `disposition: string` (T4 shape): normalised exactly like sentinel/alerts validate(), i.e.
//     DISPOSITIONS[disposition.toLowerCase()]. 'Blocked' (block/blocked/BLOCK/...) -> flagged;
//     'Allowed' / 'ReportOnly' -> not flagged. A value T4 rejects (e.g. 'hold') is malformed.
// Anything else (non-object, `flagged:'true'`, unknown disposition, neither field) is treated as an
// inspector error and FAILS CLOSED in block mode. If the two fields disagree, flagged wins.
//
// Secrets: `detector`/`ruleId`, `reasons` and any extra fields go to the capture/alert log ONLY.
// The client-facing refusal carries static reason codes and the request id, nothing from the
// verdict. Even so, reasons must be secret-free: describe what matched (rule, offset, location),
// never the matched value. Throwing is allowed: the proxy fails closed in block mode and logs an
// ALERT in observe mode; the error message is logged, never returned to the client.
//
// Defence in depth: before any verdict, alert or error text reaches stderr or the capture JSONL, the
// proxy passes it through sentinel/alerts redactDeep() with every configured flagSubstring as a canary
// (raw, %-encoded, hex, base64 forms) plus T4's secret patterns. A detector that does leak a matched
// value therefore logs a `[REDACTED:...]` marker instead. Exchange bodies are NOT redacted (evidence).

// Bound on percent-decoding rounds for the URL scan (defeats double/triple encoding of a marker).
export const MAX_URL_DECODE_ROUNDS = 3;

/** Percent-decode at the byte level; malformed escapes are left as-is (never throws). */
function percentDecode(str, plusAsSpace) {
  const s = plusAsSpace ? str.replace(/\+/g, ' ') : str;
  const bytes = [];
  for (let i = 0; i < s.length; i += 1) {
    if (s[i] === '%' && /^[0-9A-Fa-f]{2}$/.test(s.slice(i + 1, i + 3))) {
      bytes.push(parseInt(s.slice(i + 1, i + 3), 16));
      i += 2;
    } else {
      for (const b of Buffer.from(s[i], 'utf8')) bytes.push(b);
    }
  }
  return Buffer.from(bytes).toString('utf8');
}

/** Every spelling of the URL we scan: raw, then up to MAX_URL_DECODE_ROUNDS decodes (with and without '+'). */
export function urlVariants(path) {
  const out = new Set([path]);
  for (const plus of [false, true]) {
    let cur = path;
    for (let i = 0; i < MAX_URL_DECODE_ROUNDS; i += 1) {
      const next = percentDecode(cur, plus);
      out.add(next);
      if (next === cur) break;
      cur = next;
    }
  }
  return [...out];
}

function headerLines(headers) {
  return Object.entries(headers ?? {}).map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : v}`);
}

/**
 * Placeholder detector until T3 lands: flags any configured substring (e.g. a planted honeytoken)
 * in the decoded body, the header block, or (request phase) the URL in every decoded spelling.
 * Full-buffer scans via Buffer#indexOf, so a marker anywhere in a multi-MB body is found.
 * Headers/URL are bounded by Node's maxHeaderSize (16 KiB), so their scan is bounded too.
 *
 * The verdict carries ONLY ids (`flag-<index into flagSubstrings>`), locations, byte offsets and static
 * reason codes, never the matched text: the verdict is logged to stderr and the capture JSONL, and a
 * honeytoken copied into a log is a leaked honeytoken.
 * A needle is either a string (id `flag-<index>`) or a canary `{id, value}` (id kept as given), so
 * the default stack can seed it with every honeytoken, not just flagSubstrings (#126).
 * @param {ReadonlyArray<string | {id: string, value: string}>} needles
 */
export function substringInspector(needles) {
  const encoded = needles.map((n, i) => (typeof n === 'string'
    ? { id: flagSubstringId(i), buf: Buffer.from(n, 'utf8') }
    : { id: n.id, buf: Buffer.from(n.value, 'utf8') }));
  return async function substring({ phase, path, headers, body }) {
    if (encoded.length === 0) return null;
    const meta = [];
    if (phase === 'request' && typeof path === 'string') meta.push({ where: 'url', buf: Buffer.from(urlVariants(path).join('\n'), 'utf8') });
    meta.push({ where: 'headers', buf: Buffer.from(headerLines(headers).join('\n'), 'utf8') });
    const hits = [];
    for (const { id, buf } of encoded) {
      const at = body.indexOf(buf);
      if (at !== -1) hits.push({ needle_id: id, where: 'body', offset: at });
      for (const m of meta) {
        const mAt = m.buf.indexOf(buf);
        if (mAt !== -1) hits.push({ needle_id: id, where: m.where, offset: mAt });
      }
    }
    if (hits.length === 0) return null;
    return {
      flagged: true,
      detector: 'substring',
      reasons: hits.map((h) => `substring_match:${h.where}`),
      hits,
    };
  };
}

/** Stable id for flagSubstrings[i]; shared with the proxy's log-redaction canary list. */
export function flagSubstringId(i) {
  return `flag-${i}`;
}

/** Base64 substrings fully determined by `buf` at each byte alignment (mod 3) inside a larger encoding. */
function base64Cores(buf) {
  const cores = [];
  for (let k = 0; k < 3; k += 1) {
    const enc = Buffer.concat([Buffer.alloc(k), buf]).toString('base64');
    cores.push(enc.slice(Math.ceil((8 * k) / 6), Math.floor((8 * (k + buf.length)) / 6)));
  }
  return cores;
}

/**
 * #126: request-side canary check for POSTs to routes T3 does not parse (DVAA `POST /chat {message}`,
 * A2A `/a2a/message`, `/`, ...). T3 returns null for those paths, so without this a honeytoken could be
 * carried into them in a cheap encoding the raw substring backstop does not see.
 *
 * Scans the FULL decoded body for every canary as: percent-decoded (any subset of chars encoded, up to
 * MAX_URL_DECODE_ROUNDS), hex (either case), base64 and base64url at all three byte alignments. The raw
 * form is the substring backstop's job. Paths in `skipPaths` (T3's chat paths) are left to T3, which
 * already parses and judges them, so benign chat-completions traffic is unchanged.
 *
 * The proxy turns a flagged verdict into a 403 `flagged_request` in block mode (never forwarded) and a
 * would-block ALERT in observe mode. The verdict carries canary ids, forms and offsets only.
 * @param {ReadonlyArray<{id: string, value: string}>} canaries
 * @param {{skipPaths?: Iterable<string>}} [opts]
 */
export function nonChatCanaryInspector(canaries, { skipPaths = [] } = {}) {
  const skip = new Set(skipPaths);
  const needles = [];
  for (const c of canaries) {
    const buf = Buffer.from(c.value, 'utf8');
    needles.push({ id: c.id, form: 'percent', text: c.value, view: 'decoded' });
    needles.push({ id: c.id, form: 'hex', text: buf.toString('hex'), view: 'lower' });
    for (const core of base64Cores(buf)) {
      needles.push({ id: c.id, form: 'base64', text: core, view: 'raw' });
      const url = core.replace(/\+/g, '-').replace(/\//g, '_');
      if (url !== core) needles.push({ id: c.id, form: 'base64url', text: url, view: 'raw' });
    }
  }
  return async function nonChatCanary({ phase, method, path, body }) {
    if (phase !== 'request' || method !== 'POST' || needles.length === 0) return null;
    if (skip.has(String(path ?? '').split('?')[0])) return null;
    const raw = Buffer.isBuffer(body) ? body.toString('utf8') : String(body ?? '');
    if (raw.length === 0) return null;
    // Percent-decoded spellings (with and without '+'): urlVariants() minus the raw spelling itself.
    const decoded = urlVariants(raw).filter((v) => v !== raw).join('\n');
    const views = { raw, lower: raw.toLowerCase(), decoded };
    const hits = [];
    for (const n of needles) {
      const at = views[n.view].indexOf(n.text);
      if (at !== -1) hits.push({ needle_id: n.id, where: 'body', form: n.form, offset: at });
    }
    if (hits.length === 0) return null;
    return {
      flagged: true,
      detector: 'non-chat-canary',
      reasons: [...new Set(hits.map((h) => `canary_encoded_non_chat_route:${h.form}`))],
      hits,
    };
  };
}
