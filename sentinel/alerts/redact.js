// SentinelProxy T4 — secret redaction for alert bodies.
//
// Rule: an alert NEVER carries a secret value. Any string matching a secret pattern, or containing a
// known canary (honeytoken) value — raw, case-varied, separator-split, base64/base64url, hex,
// %-encoded — is replaced by `[REDACTED:<kind>:sha256=<16 hex>]` (canaries additionally carry their
// id). The hash lets an analyst correlate "same secret seen twice" without the alert body becoming a
// second exfil channel.
//
// COST BOUND (review B1 on PR #3): every scan here is LINEAR in the input length.
//   - Regex patterns are either fixed-length, have bounded quantifiers, or are structured so a failed
//     attempt cannot re-scan an unbounded run (each pattern's adversarial input is timed in tests).
//   - The two patterns that were superlinear as regexes (JWT, PEM private key) are linear scanners.
//   - "Am I inside one of my own markers?" is a precomputed range list walked by a monotone cursor
//     (the old per-match lastIndexOf was itself O(n) per match → O(n²) on many-match inputs).
// Size bounds that make the time bound real:
//   - MAX_REDACT_SCAN_CHARS per string. Longer strings are WITHHELD entirely (marker with length +
//     hash) — never "scan the first N chars and pass the rest through" (the DVAA 8KB-window anti-pattern).
//   - MAX_REDACT_TOTAL_CHARS per redactDeep call (one alert). Once spent, every further string is
//     withheld whole. Fail-safe: withholding can lose context, never leak.
//   - MAX_CANARIES / MAX_CANARY_VALUE_CHARS: the canary list is caller data, so it is capped (throws).

import { createHash } from 'node:crypto';

export const MAX_REDACT_SCAN_CHARS = 256 * 1024; // per string field (alert display keeps ≤ 2 KiB anyway)
export const MAX_REDACT_TOTAL_CHARS = 1024 * 1024; // per alert, across all string fields
export const MAX_CANARIES = 64;
export const MAX_CANARY_VALUE_CHARS = 1024;
export const MIN_CANARY_VARIANT_CHARS = 8; // shorter encoded/normalized forms are too unspecific to match
export const HASH_HEX_CHARS = 16;

export const sha256Short = (s) => createHash('sha256').update(String(s)).digest('hex').slice(0, HASH_HEX_CHARS);

// ---- linear scanners for the two shapes that are superlinear as backtracking regexes -------------

const TOKEN_RUN = /[A-Za-z0-9_.-]+/g; // single class, greedy, never backtracks into itself
const JWT_SEG_MIN = 8;

/**
 * JWT: `eyJ<≥8 token chars>.<≥8>.<≥8>`, may be glued to word chars on the left (no \b).
 * Equivalent to /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g but O(n): each maximal
 * token run is split on '.' once; within a segment only the FIRST "eyJ" can matter (it has the most
 * room after it).
 */
function findJwt(str) {
  const out = [];
  TOKEN_RUN.lastIndex = 0;
  let m;
  while ((m = TOKEN_RUN.exec(str)) !== null) {
    const run = m[0];
    if (run.length < 3 + JWT_SEG_MIN * 3 + 2 || run.indexOf('.') === -1) continue;
    const segs = run.split('.');
    if (segs.length < 3) continue;
    const starts = new Array(segs.length);
    for (let i = 0, off = 0; i < segs.length; i++) {
      starts[i] = off;
      off += segs[i].length + 1;
    }
    for (let i = 0; i + 2 < segs.length; ) {
      const j = segs[i].indexOf('eyJ');
      if (j !== -1 && segs[i].length - j - 3 >= JWT_SEG_MIN && segs[i + 1].length >= JWT_SEG_MIN && segs[i + 2].length >= JWT_SEG_MIN) {
        const index = m.index + starts[i] + j;
        const end = m.index + starts[i + 2] + segs[i + 2].length;
        out.push({ index, text: str.slice(index, end) });
        i += 3;
      } else {
        i += 1;
      }
    }
  }
  return out;
}

const PEM_BEGIN = '-----BEGIN ';
const PEM_END = '-----END ';
const PEM_BEGIN_HDR = /-----BEGIN [A-Z ]{0,64}PRIVATE KEY-----/y; // sticky, bounded label
const PEM_END_HDR = /-----END [A-Z ]{0,64}PRIVATE KEY-----/y;

/**
 * PEM private key block: BEGIN header … first matching END footer (lazy, like `[\s\S]*?`).
 * O(n): header/footer checks are bounded sticky matches; once no valid footer exists after position p,
 * none exists after any later p either, so the search stops instead of re-scanning per BEGIN.
 */
function findPem(str) {
  const out = [];
  let pos = 0;
  let endSearchFrom = 0; // footers before this offset were already rejected as invalid
  let noMoreEnds = false;
  while (!noMoreEnds) {
    const b = str.indexOf(PEM_BEGIN, pos);
    if (b === -1) break;
    PEM_BEGIN_HDR.lastIndex = b;
    if (!PEM_BEGIN_HDR.test(str)) {
      pos = b + 1;
      continue;
    }
    const bodyFrom = PEM_BEGIN_HDR.lastIndex;
    let e = str.indexOf(PEM_END, Math.max(bodyFrom, endSearchFrom));
    let footerEnd = -1;
    while (e !== -1) {
      PEM_END_HDR.lastIndex = e;
      if (PEM_END_HDR.test(str)) {
        footerEnd = PEM_END_HDR.lastIndex;
        break;
      }
      e = str.indexOf(PEM_END, e + 1);
    }
    if (footerEnd === -1) {
      noMoreEnds = true; // no valid footer anywhere after bodyFrom → no later BEGIN can complete
      break;
    }
    endSearchFrom = e;
    out.push({ index: b, text: str.slice(b, footerEnd) });
    pos = footerEnd;
  }
  return out;
}

// Prefix-shaped tokens deliberately have NO leading \b: a secret glued to word characters
// ("xAKIA…", "dataghp_…") must still be caught. Over-redaction is the safe failure for an alert body.
// Ordered: most specific first. `group` (optional) = capture group holding the secret value; the rest
// of the match (e.g. "password=") is kept so the analyst still sees what kind of field leaked.
// Each regex is linear on adversarial input (see test/redact-adversarial.test.js timing tests):
//   - whitespace / label quantifiers are bounded ({0,16}, {1,64}, {0,64}, {13,19});
//   - an open-ended value class `{n,}` is the LAST element of its pattern, so a greedy attempt either
//     succeeds (consuming the run — no re-scan) or fails within n chars. Values are deliberately NOT
//     capped: `{16,4096}` would let the tail of an over-long token pass through unredacted.
export const SECRET_PATTERNS = Object.freeze([
  { kind: 'private_key', find: findPem },
  { kind: 'aws_access_key', re: /(?:AKIA|ASIA)[0-9A-Z]{16}/g },
  { kind: 'github_token', re: /gh[pousr]_[A-Za-z0-9]{30,}/g },
  { kind: 'slack_token', re: /xox[abprs]-[A-Za-z0-9-]{10,}/g },
  { kind: 'api_key_sk', re: /sk-[A-Za-z0-9_-]{16,}/g },
  { kind: 'jwt', find: findJwt },
  { kind: 'bearer_token', re: /\b(Bearer\s{1,64})([A-Za-z0-9._~+/-]{16,}={0,3})/gi, group: 2 },
  {
    kind: 'credential_assignment',
    re: /\b((?:password|passwd|pwd|secret|client_secret|api[_-]?key|access[_-]?key|auth[_-]?token|token)["']?\s{0,16}[:=]\s{0,16}["']?)([^\s"',;}{]{6,})/gi,
    group: 2,
  },
  { kind: 'us_ssn', re: /\b\d{3}-\d{2}-\d{4}\b/g },
  { kind: 'payment_card', re: /\b(?:\d[ -]?){13,19}\b/g, check: luhnOk },
]);

function luhnOk(match) {
  const digits = match.replace(/[^0-9]/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = digits.charCodeAt(digits.length - 1 - i) - 48;
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}

const MARKER_OPEN = '[REDACTED:';
export const FORGED_MARKER_OPEN = '[REDACTED-INPUT:';

/** Sorted, non-overlapping [start, end) ranges of our own `[REDACTED:…]` markers in `s`. O(n). */
function markerRanges(s) {
  const ranges = [];
  let i = s.indexOf(MARKER_OPEN);
  while (i !== -1) {
    const close = s.indexOf(']', i);
    if (close === -1) break;
    ranges.push([i, close + 1]);
    i = s.indexOf(MARKER_OPEN, close + 1);
  }
  return ranges;
}

const marker = (kind, secret, canaryId) =>
  canaryId
    ? `[REDACTED:canary:${canaryId}:sha256=${sha256Short(secret)}]`
    : `[REDACTED:${kind}:sha256=${sha256Short(secret)}]`;

// ---- canaries: raw + encoded variants, matched on a separator-insensitive normalized view ----------

/** Lowercase alphanumerics only. Matching on this view catches case variants and split forms
 *  ("D V A A_canary", "dvaa-canary-…"); %XX and hex forms collapse to the same hex digits. */
const normalize = (s) => s.replace(/[^A-Za-z0-9]/g, '').toLowerCase(); // ASCII-only, same fold as the scan

/** Base64 substrings that appear whenever `buf` sits at byte offset ≡ k (mod 3) inside ANY encoded
 *  plaintext (only characters fully determined by `buf` are kept). */
function base64Cores(buf) {
  const cores = [];
  for (let k = 0; k < 3; k++) {
    const enc = Buffer.concat([Buffer.alloc(k), buf]).toString('base64');
    const from = Math.ceil((8 * k) / 6);
    const to = Math.floor((8 * (k + buf.length)) / 6);
    cores.push(enc.slice(from, to));
  }
  return cores;
}

/**
 * Validate + expand canaries once per alert. Throws (fail loud) on caller-data overflow.
 * @returns {Array<{id:string, value:string, sha:string, needles:Array<{form:string, norm:string}>}>}
 */
export function prepareCanaries(canaries = []) {
  if (!Array.isArray(canaries)) throw new TypeError('canaries must be an array');
  if (canaries.length > MAX_CANARIES) throw new RangeError(`${canaries.length} canaries > MAX_CANARIES=${MAX_CANARIES}`);
  const prepared = [];
  for (const c of canaries) {
    if (!c || typeof c.value !== 'string' || c.value.length === 0) throw new TypeError('canary must be {id, value} with a non-empty string value');
    if (c.value.length > MAX_CANARY_VALUE_CHARS) throw new RangeError(`canary value length ${c.value.length} > MAX_CANARY_VALUE_CHARS=${MAX_CANARY_VALUE_CHARS}`);
    const buf = Buffer.from(c.value, 'utf8');
    const forms = [
      ['raw', c.value],
      ['url', encodeURIComponent(c.value)],
      ['hex', buf.toString('hex')], // also covers full %XX encoding and \xXX after normalization
      ...base64Cores(buf).map((b) => ['base64', b]), // url-safe alphabet differs only in +/ vs -_, both stripped
    ];
    const seen = new Set();
    const needles = [];
    for (const [form, text] of forms) {
      const norm = normalize(text);
      if (norm.length < MIN_CANARY_VARIANT_CHARS || seen.has(norm)) continue;
      seen.add(norm);
      needles.push({ form, norm });
    }
    prepared.push({ id: typeof c.id === 'string' && c.id ? c.id : 'unknown', value: c.value, sha: sha256Short(c.value), needles });
  }
  // longest first so overlapping canaries redact fully
  prepared.sort((a, b) => b.value.length - a.value.length);
  return prepared;
}

/** Replace each [start,end) span (sorted by start, may overlap) with replacement(span). O(n + spans). */
function applySpans(str, spans, replacement) {
  if (spans.length === 0) return str;
  spans.sort((a, b) => a.start - b.start || b.end - a.end);
  let out = '';
  let cursor = 0;
  for (const s of spans) {
    if (s.start < cursor) continue; // overlaps an earlier, already-redacted span (merged into it)
    out += str.slice(cursor, s.start) + replacement(s);
    cursor = s.end;
  }
  return out + str.slice(cursor);
}

function redactCanaries(str, prepared, findings) {
  if (prepared.length === 0) return str;
  const spans = [];
  // 1) exact raw substring (any length, any characters — the original contract)
  for (const c of prepared) {
    let i = str.indexOf(c.value);
    while (i !== -1) {
      spans.push({ start: i, end: i + c.value.length, c, form: 'raw' });
      i = str.indexOf(c.value, i + c.value.length);
    }
  }
  // 2) encoded / case-varied / separator-split forms on the normalized view, mapped back to `str`.
  //    Per-code-unit ASCII fold (NOT String#toLowerCase, which can change length, e.g. "İ"), so an
  //    attacker cannot desync the position map; non-ASCII is dropped like any separator.
  const posMap = new Int32Array(str.length);
  const codes = new Uint8Array(str.length);
  let n = 0;
  for (let i = 0; i < str.length; i++) {
    let ch = str.charCodeAt(i);
    if (ch >= 65 && ch <= 90) ch += 32;
    if ((ch >= 97 && ch <= 122) || (ch >= 48 && ch <= 57)) {
      posMap[n] = i;
      codes[n++] = ch;
    }
  }
  const norm = Buffer.from(codes.buffer, 0, n).toString('latin1');
  for (const c of prepared) {
    for (const nd of c.needles) {
      let i = norm.indexOf(nd.norm);
      while (i !== -1) {
        spans.push({ start: posMap[i], end: posMap[i + nd.norm.length - 1] + 1, c, form: nd.form });
        i = norm.indexOf(nd.norm, i + nd.norm.length);
      }
    }
  }
  return applySpans(str, spans, (s) => {
    findings.push({ kind: 'canary', canaryId: s.c.id, sha256: s.c.sha, encoding: s.form });
    return marker('canary', s.c.value, s.c.id);
  });
}

/** Spans (in `view` coordinates) where pattern `p` matches outside our own markers. */
function patternSpans(view, p) {
  const ranges = markerRanges(view);
  let r = 0;
  const overlapsMarker = (start, end) => {
    while (r < ranges.length && ranges[r][1] <= start) r++; // matches arrive in increasing offset order
    return r < ranges.length && ranges[r][0] < end;
  };
  const spans = [];
  const consider = (index, whole, groups) => {
    if (overlapsMarker(index, index + whole.length)) return;
    if (p.check && !p.check(whole)) return;
    if (p.group) {
      const secret = groups[p.group - 1];
      if (typeof secret !== 'string') return;
      const keep = groups.slice(0, p.group - 1).join('');
      spans.push({ start: index + keep.length, end: index + keep.length + secret.length, secret });
    } else {
      spans.push({ start: index, end: index + whole.length, secret: whole });
    }
  };
  if (p.find) {
    for (const m of p.find(view)) consider(m.index, m.text, []);
  } else {
    p.re.lastIndex = 0;
    let m;
    while ((m = p.re.exec(view)) !== null) consider(m.index, m[0], m.slice(1));
  }
  return spans;
}

const isHex = (c) => (c >= 48 && c <= 57) || (c >= 65 && c <= 70) || (c >= 97 && c <= 102);

/** %XX-decoded view of `s` with, per decoded char, its [start, end) in `s`. null if nothing to decode. O(n). */
function percentDecodedView(s) {
  if (s.indexOf('%') === -1) return null;
  const parts = [];
  const from = new Int32Array(s.length);
  const to = new Int32Array(s.length);
  let n = 0;
  let runStart = 0;
  let decodedAny = false;
  for (let i = 0; i < s.length; ) {
    if (s.charCodeAt(i) === 37 && i + 2 < s.length && isHex(s.charCodeAt(i + 1)) && isHex(s.charCodeAt(i + 2))) {
      if (runStart < i) parts.push(s.slice(runStart, i));
      parts.push(String.fromCharCode(parseInt(s.substr(i + 1, 2), 16)));
      from[n] = i;
      to[n++] = i + 3;
      i += 3;
      runStart = i;
      decodedAny = true;
    } else {
      from[n] = i;
      to[n++] = i + 1;
      i += 1;
    }
  }
  if (runStart < s.length) parts.push(s.slice(runStart));
  return decodedAny ? { view: parts.join(''), from, to } : null;
}

function redactPatterns(str, findings) {
  let out = str;
  // Pass 1: the string as-is.
  for (const p of SECRET_PATTERNS) {
    out = applySpans(out, patternSpans(out, p), (s) => {
      findings.push({ kind: p.kind, sha256: sha256Short(s.secret) });
      return marker(p.kind, s.secret);
    });
  }
  // Pass 2: %-decoded view (URL query strings are the main exfil vector). Encoding hides secrets from
  // pass 1 two ways: delimiters become %XX ("password%3Dhunter2"), and "%20" glues digits onto the
  // value so \b anchors fail ("SSN%3A%20123-45-6789"). The view is built ONCE; every pattern's matches
  // are mapped back onto original spans, and overlapping spans are merged into their union (never
  // dropped — a dropped partial overlap could leave a secret's tail behind).
  const dv = percentDecodedView(out);
  if (dv) {
    const all = [];
    for (const p of SECRET_PATTERNS) {
      for (const sp of patternSpans(dv.view, p)) all.push({ start: dv.from[sp.start], end: dv.to[sp.end - 1], kind: p.kind, secret: sp.secret });
    }
    all.sort((x, y) => x.start - y.start);
    const merged = [];
    for (const sp of all) {
      const last = merged[merged.length - 1];
      if (last && sp.start < last.end) {
        if (sp.end > last.end) {
          last.end = sp.end;
          last.secret = null; // union of several matches: hash the original span instead
        }
      } else merged.push({ ...sp });
    }
    out = applySpans(out, merged, (sp) => {
      const secret = sp.secret ?? out.slice(sp.start, sp.end);
      findings.push({ kind: sp.kind, sha256: sha256Short(secret), encoding: 'url' });
      return marker(sp.kind, secret);
    });
  }
  return out;
}

function withhold(str, kind, findings, label, cap) {
  const h = sha256Short(str);
  findings.push({ kind, sha256: h });
  return `[WITHHELD:${label} len=${str.length} cap=${cap} sha256=${h}]`;
}

function redactWithPrepared(str, prepared) {
  const findings = [];
  if (typeof str !== 'string' || str.length === 0) return { value: str, findings, withheld: false };
  if (str.length > MAX_REDACT_SCAN_CHARS) {
    // Too big to scan within budget: withhold the WHOLE value (never pass an unscanned tail through).
    return { value: withhold(str, 'withheld_oversize', findings, 'oversize', MAX_REDACT_SCAN_CHARS), findings, withheld: true };
  }
  // Neutralize marker look-alikes already in the INPUT: pattern scans skip text inside our own
  // `[REDACTED:…]` markers, so a forged "[REDACTED: <secret> ]" would otherwise smuggle the secret
  // through. After this, every `[REDACTED:` in the string is one we inserted.
  let out = str.includes(MARKER_OPEN) ? str.split(MARKER_OPEN).join(FORGED_MARKER_OPEN) : str;
  out = redactCanaries(out, prepared, findings);
  out = redactPatterns(out, findings);
  return { value: out, findings, withheld: false };
}

/**
 * Redact one string. Returns { value, findings: [{kind, sha256, canaryId?, encoding?}], withheld }.
 * @param {string} str
 * @param {{canaries?: Array<{id:string, value:string}>}} [opts]
 */
export function redactString(str, { canaries = [] } = {}) {
  return redactWithPrepared(str, prepareCanaries(canaries));
}

/**
 * Deep-redact every string leaf of a plain JSON-ish value (objects/arrays). Returns a new value.
 * Total scanned chars are capped by MAX_REDACT_TOTAL_CHARS: strings past the budget are withheld whole.
 * @returns {{ value: any, findings: Array<object>, withheldCount: number }}
 */
export function redactDeep(value, opts = {}) {
  const prepared = prepareCanaries(opts.canaries ?? []);
  const findings = [];
  let withheldCount = 0;
  let budget = MAX_REDACT_TOTAL_CHARS;
  const walk = (v) => {
    if (typeof v === 'string') {
      if (v.length > budget && v.length <= MAX_REDACT_SCAN_CHARS) {
        withheldCount++;
        return withhold(v, 'withheld_budget', findings, 'scan-budget', MAX_REDACT_TOTAL_CHARS);
      }
      if (v.length <= MAX_REDACT_SCAN_CHARS) budget -= v.length;
      const r = redactWithPrepared(v, prepared);
      findings.push(...r.findings);
      if (r.withheld) withheldCount++;
      return r.value;
    }
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === 'object') {
      const o = {};
      for (const [k, x] of Object.entries(v)) o[k] = walk(x);
      return o;
    }
    return v;
  };
  return { value: walk(value), findings, withheldCount };
}
