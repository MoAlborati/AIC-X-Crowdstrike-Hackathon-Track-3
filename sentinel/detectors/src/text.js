// SentinelProxy T3 — linear-time text scanners for attacker-controlled input.
//
// ReDoS rule (PR #3 review): no regex with an unbounded quantifier is ever run across attacker text.
// Everything here is one of:
//   (a) indexOf / charCode loops with bounded expansion (URLs, emails, markdown images, PEM blocks), or
//   (b) a single linear tokenizer (/[charclass]+/g, a maximal run with nothing after it, so it cannot
//       backtrack) followed by ANCHORED, BOUNDED tests on each token no longer than maxTokenChars.
// Total cost is O(n) plus O(tokens x maxTokenChars) <= O(n x 512), never quadratic. The adversarial timing
// tests (test/timing.test.js) run every function here at the maximum payload size.

const MAX_URL_CHARS = 8192; // a URL longer than this is reported with its first 8 KiB (display only) plus the full host
const MAX_EMAIL_LOCAL = 64; // RFC 5321 local-part limit
const MAX_EMAIL_DOMAIN = 255; // RFC 5321 domain limit

// ---- character classes (charCode tests, no regex) ----------------------------------------------
const isAlnum = (c) => (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122);
const isHostChar = (c) => isAlnum(c) || c === 45 || c === 46; // - .
const isEmailLocalChar = (c) => isAlnum(c) || c === 46 || c === 95 || c === 37 || c === 43 || c === 45; // . _ % + -
const URL_STOP = new Set([32, 9, 10, 13, 34, 39, 60, 62, 96, 41, 93, 125, 0]); // ws " ' < > ` ) ] } NUL

/** Find every http(s) URL. Linear: one indexOf sweep per scheme, bounded forward expansion. */
export function extractUrls(text) {
  const out = [];
  if (typeof text !== 'string' || text.length === 0) return out;
  for (const scheme of ['http://', 'https://']) {
    let from = 0;
    for (;;) {
      const i = text.indexOf(scheme, from);
      if (i === -1) break;
      let j = i + scheme.length;
      const limit = Math.min(text.length, i + MAX_URL_CHARS);
      while (j < limit && !URL_STOP.has(text.charCodeAt(j))) j++;
      const url = text.slice(i, j);
      const host = hostOf(url);
      if (host) out.push({ url, host, index: i });
      // Continue after this URL even if it hit the display bound: the rest is ordinary text.
      from = j > i + scheme.length ? j : i + scheme.length;
    }
  }
  out.sort((a, b) => a.index - b.index);
  return out;
}

/** Host of an absolute http(s) URL, lower-cased, without port/userinfo. Linear. */
export function hostOf(url) {
  const s = url.indexOf('://');
  if (s === -1) return null;
  let i = s + 3;
  const end = Math.min(url.length, i + MAX_EMAIL_DOMAIN + 128);
  // skip userinfo (anything up to '@' before the first '/')
  let at = -1;
  for (let k = i; k < end; k++) {
    const c = url.charCodeAt(k);
    if (c === 47 || c === 63 || c === 35) break; // / ? #
    if (c === 64) at = k;
  }
  if (at !== -1) i = at + 1;
  let j = i;
  while (j < end && isHostChar(url.charCodeAt(j))) j++;
  const host = url.slice(i, j).toLowerCase().replace(/\.$/, '');
  return host.length > 0 ? host : null;
}

/** Find every email address. Linear: indexOf('@') + bounded expansion either side. */
export function extractEmails(text) {
  const out = [];
  if (typeof text !== 'string') return out;
  let from = 0;
  for (;;) {
    const at = text.indexOf('@', from);
    if (at === -1) break;
    let l = at;
    const lmin = Math.max(0, at - MAX_EMAIL_LOCAL);
    while (l > lmin && isEmailLocalChar(text.charCodeAt(l - 1))) l--;
    let r = at + 1;
    const rmax = Math.min(text.length, at + 1 + MAX_EMAIL_DOMAIN);
    while (r < rmax && isHostChar(text.charCodeAt(r))) r++;
    let domain = text.slice(at + 1, r);
    while (domain.endsWith('.') || domain.endsWith('-')) domain = domain.slice(0, -1);
    const local = text.slice(l, at);
    // Must look like a real address: non-empty local, dotted domain, alphabetic TLD >= 2.
    const dot = domain.lastIndexOf('.');
    const tld = dot === -1 ? '' : domain.slice(dot + 1);
    if (local.length > 0 && dot > 0 && tld.length >= 2 && /^[a-z]{2,24}$/i.test(tld)) {
      out.push({ email: `${local}@${domain}`.toLowerCase(), domain: domain.toLowerCase(), index: l });
    }
    from = at + 1;
  }
  return out;
}

/**
 * Markdown images/links whose target is an absolute URL: `![alt](url)` and `[text](url)`.
 * Linear: indexOf('](') then bounded backward check for '!' / '[' and forward URL expansion.
 */
export function extractMarkdownLinks(text) {
  const out = [];
  if (typeof text !== 'string') return out;
  let from = 0;
  for (;;) {
    const k = text.indexOf('](', from);
    if (k === -1) break;
    const urlStart = k + 2;
    const urls = text.startsWith('http://', urlStart) || text.startsWith('https://', urlStart);
    if (urls) {
      // Walk back (bounded) to the opening '['.
      // Bounded AND non-overlapping: never walk back past the previous match, so total backward work
      // over the whole text is O(n) even for "](http://" repeated (timing test).
      let b = k - 1;
      const bmin = Math.max(0, k - 256, from - 1);
      while (b >= bmin && text.charCodeAt(b) !== 91 && text.charCodeAt(b) !== 10) b--;
      const isImage = b > 0 && text.charCodeAt(b) === 91 && text.charCodeAt(b - 1) === 33;
      let j = urlStart;
      const limit = Math.min(text.length, urlStart + MAX_URL_CHARS);
      while (j < limit && !URL_STOP.has(text.charCodeAt(j))) j++;
      const url = text.slice(urlStart, j);
      out.push({ url, host: hostOf(url), isImage, index: k });
    }
    from = k + 2;
  }
  return out;
}

/**
 * Linear tokenizer: maximal runs of [A-Za-z0-9+/=_.~-]. Regex `/[...]+/g` matches a maximal run and
 * resumes after it, so it never backtracks across the input. Yields {token, index}.
 */
const TOKEN_RE = /[A-Za-z0-9+/=_.~-]+/g;
export function* tokens(text) {
  TOKEN_RE.lastIndex = 0;
  let m;
  while ((m = TOKEN_RE.exec(text)) !== null) yield { token: m[0], index: m.index };
}

/** Shannon entropy in bits/char. Linear in token length. */
export function entropy(s) {
  if (!s) return 0;
  const freq = new Map();
  for (let i = 0; i < s.length; i++) freq.set(s[i], (freq.get(s[i]) || 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

// ---- decoding (for encoded-honeytoken checks) ---------------------------------------------------

/** decodeURIComponent that never throws; also maps '+' to space (form encoding). */
export function safeUrlDecode(s) {
  if (s.indexOf('%') === -1 && s.indexOf('+') === -1) return s;
  try {
    return decodeURIComponent(s.replace(/\+/g, ' '));
  } catch {
    // Malformed escapes: decode the valid %XX triplets individually (linear).
    return s.replace(/\+/g, ' ').replace(/%[0-9A-Fa-f]{2}/g, (t) => {
      try {
        return decodeURIComponent(t);
      } catch {
        return t;
      }
    });
  }
}

const B64_ALPHABET = /^[A-Za-z0-9+/_-]+={0,2}$/;
const HEX_ALPHABET = /^(?:[0-9a-fA-F]{2})+$/;

/**
 * All decoded variants of `text` worth scanning for honeytokens: URL-decoded, plus base64/hex
 * decodings of long encoded runs, recursively up to `depth`. Decoding never grows the byte count,
 * so total work is bounded by |text| x depth.
 */
export function decodedVariants(text, { depth = 3, minRun = 12 } = {}) {
  const out = [];
  const seen = new Set();
  const queue = [{ s: text, d: 0, enc: 'raw' }];
  // Index-based queue (Array#shift is O(n) and made this quadratic on 60k-token inputs — timing test).
  for (let qi = 0; qi < queue.length; qi++) {
    const { s, d, enc } = queue[qi];
    if (seen.has(s)) continue;
    seen.add(s);
    out.push({ text: s, encoding: enc });
    if (d >= depth) continue;
    const tag = (e) => (enc === 'raw' ? e : `${enc}+${e}`);
    const u = safeUrlDecode(s);
    if (u !== s) queue.push({ s: u, d: d + 1, enc: tag('url') });
    // All decoded runs of one source are batched into ONE variant per encoding (joined by newlines), so
    // the number of variants stays <= 1 + 3 x depth regardless of how many encoded runs the text holds.
    const hex = [];
    const b64 = [];
    for (const { token: whole } of tokens(s)) {
      if (whole.length < minRun) continue;
      // `key=<base64>` (query strings, env lines): '=' is base64 padding only at the END of a run, so an
      // interior '=' separates a key from the encoded value -> decode the value part.
      const eq = whole.replace(/=+$/, '').lastIndexOf('=');
      const token = eq === -1 ? whole : whole.slice(eq + 1);
      if (token.length < minRun) continue;
      const t = token.replace(/^[.~]+|[.~]+$/g, '');
      if (t.length >= minRun && t.length % 2 === 0 && HEX_ALPHABET.test(t)) {
        const dec = Buffer.from(t, 'hex').toString('utf8');
        if (isMostlyPrintable(dec)) hex.push(dec);
      } else if (t.length >= minRun && B64_ALPHABET.test(t)) {
        const dec = Buffer.from(t.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
        if (isMostlyPrintable(dec)) b64.push(dec);
      }
    }
    if (hex.length) queue.push({ s: hex.join('\n'), d: d + 1, enc: tag('hex') });
    if (b64.length) queue.push({ s: b64.join('\n'), d: d + 1, enc: tag('base64') });
  }
  return out;
}

function isMostlyPrintable(s) {
  if (s.length === 0) return false;
  let ok = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if ((c >= 32 && c < 127) || c === 9 || c === 10 || c === 13) ok++;
  }
  return ok / s.length >= 0.9;
}

// ---- secret / PII shape tests --------------------------------------------------------------------
// Each test is ANCHORED and BOUNDED and runs on ONE token of length <= maxTokenChars, never on the
// whole text. The JWT shape below is exactly the one that took 14 s unbounded in PR #3's review; here
// it is a split-on-'.' check over a bounded token.

const TOKEN_SECRET_TESTS = [
  { kind: 'openai_key', test: (t) => /^sk-(?:proj-|ant-|live-)?[A-Za-z0-9_-]{16,200}$/.test(t) },
  { kind: 'aws_access_key', test: (t) => /^(?:AKIA|ASIA)[0-9A-Z]{16}$/.test(t) },
  { kind: 'github_token', test: (t) => /^(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,80}$/.test(t) },
  { kind: 'slack_token', test: (t) => /^xox[abprs]-[A-Za-z0-9-]{10,200}$/.test(t) },
  { kind: 'google_api_key', test: (t) => /^AIza[0-9A-Za-z_-]{35}$/.test(t) },
  { kind: 'stripe_key', test: (t) => /^(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,99}$/.test(t) },
  { kind: 'jwt', test: isJwtShape },
];

function isJwtShape(t) {
  if (!t.startsWith('eyJ')) return false;
  const parts = t.split('.');
  if (parts.length !== 3) return false;
  return parts.every((p) => p.length >= 8 && p.length <= 400 && /^[A-Za-z0-9_-]+$/.test(p));
}

/**
 * Secret-shaped tokens in `text`. Linear tokenizer + bounded per-token tests. Also finds PEM private
 * key headers by indexOf. Returns [{kind, value, index}].
 */
export function findSecretShapes(text, { maxTokenChars = 512, entropyMinLen = 24, entropyBits = 4.0 } = {}) {
  const out = [];
  if (typeof text !== 'string') return out;
  let from = 0;
  for (;;) {
    const i = text.indexOf('-----BEGIN ', from);
    if (i === -1) break;
    const lineEnd = text.indexOf('-----', i + 11);
    const header = lineEnd === -1 ? '' : text.slice(i, Math.min(lineEnd + 5, i + 80));
    if (header.includes('PRIVATE KEY')) out.push({ kind: 'private_key', value: header, index: i });
    from = i + 11;
  }
  for (const { token, index } of tokens(text)) {
    const t = token.replace(/^[.~=]+|[.~]+$/g, '');
    if (t.length < 8) continue;
    if (t.length > maxTokenChars) {
      // Prefix checks only: an over-long run is still reported, never silently skipped.
      if (t.startsWith('eyJ') || t.startsWith('sk-') || t.startsWith('AKIA') || t.startsWith('ghp_')) {
        out.push({ kind: 'oversize_secret_like_token', value: t.slice(0, 32), index });
      }
      continue;
    }
    let matched = false;
    for (const { kind, test } of TOKEN_SECRET_TESTS) {
      if (test(t)) {
        out.push({ kind, value: t, index });
        matched = true;
        break;
      }
    }
    if (!matched && t.length >= entropyMinLen && looksLikeKeyMaterial(t) && entropy(t) >= entropyBits) {
      out.push({ kind: 'high_entropy', value: t, index });
    }
  }
  return out;
}

// Key material mixes classes; prose words, paths and plain numbers do not.
function looksLikeKeyMaterial(t) {
  let lower = 0, upper = 0, digit = 0;
  for (let i = 0; i < t.length; i++) {
    const c = t.charCodeAt(i);
    if (c >= 97 && c <= 122) lower++;
    else if (c >= 65 && c <= 90) upper++;
    else if (c >= 48 && c <= 57) digit++;
  }
  return digit > 0 && (lower > 0) + (upper > 0) + (digit > 0) >= 3 && !t.includes('/');
}

/** US SSNs (fixed width; linear). */
export function findSsns(text) {
  const out = [];
  const re = /(?<![0-9-])\d{3}-\d{2}-\d{4}(?![0-9-])/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    const [a, b, c] = m[0].split('-');
    if (a !== '000' && a !== '666' && a[0] !== '9' && b !== '00' && c !== '0000') out.push({ kind: 'ssn', value: m[0], index: m.index });
  }
  return out;
}

/** Payment card numbers (13–19 digits, optional single space/dash separators) passing Luhn. Linear. */
export function findCardNumbers(text) {
  const out = [];
  let i = 0;
  const n = text.length;
  while (i < n) {
    if (!isDigit(text.charCodeAt(i)) || (i > 0 && isDigit(text.charCodeAt(i - 1)))) {
      i++;
      continue;
    }
    let j = i;
    let digits = '';
    while (j < n && digits.length < 20) {
      const c = text.charCodeAt(j);
      if (isDigit(c)) {
        digits += text[j];
        j++;
      } else if ((c === 32 || c === 45) && j + 1 < n && isDigit(text.charCodeAt(j + 1)) && digits.length > 0) {
        j++;
      } else break;
    }
    if (digits.length >= 13 && digits.length <= 19 && luhn(digits)) out.push({ kind: 'card_number', value: text.slice(i, j), index: i });
    i = j > i ? j : i + 1;
  }
  return out;
}
const isDigit = (c) => c >= 48 && c <= 57;
function luhn(d) {
  let sum = 0;
  let alt = false;
  for (let i = d.length - 1; i >= 0; i--) {
    let x = d.charCodeAt(i) - 48;
    if (alt) {
      x *= 2;
      if (x > 9) x -= 9;
    }
    sum += x;
    alt = !alt;
  }
  return sum % 10 === 0;
}

/** Currency amounts like "$400", "400 USD", "USD 1,250.50". Bounded quantifiers only. */
export function findAmounts(text) {
  const out = [];
  const re = /(?:[$€£]\s?|\b(?:USD|EUR|GBP)\s)(\d{1,3}(?:,\d{3}){0,5}|\d{1,15})(?:\.\d{1,2})?|\b(\d{1,3}(?:,\d{3}){0,5}|\d{1,15})(?:\.\d{1,2})?\s(?:USD|EUR|GBP|dollars)\b/gi;
  let m;
  while ((m = re.exec(text)) !== null) {
    const num = Number(m[0].replace(/[^0-9.]/g, ''));
    if (Number.isFinite(num)) out.push(num);
  }
  return out;
}

// ---- untrusted segments inside a principal turn (spotlighting / retrieved-document delimiters) --

const BEGIN_LINE = /^\s{0,8}-{3,20}\s{0,4}BEGIN ([A-Z][A-Z0-9 _]{0,40}?)\s{0,4}-{3,20}\s{0,8}$/;
const BRACKET_BEGIN = /^\s{0,8}\[BEGIN ([A-Z][A-Z0-9 _]{0,40}?)\]\s{0,8}$/;
const INFO_OPEN = /^\s{0,8}<INFORMATION>\s{0,8}$/i;
const INFO_CLOSE = /^\s{0,8}<\/INFORMATION>\s{0,8}$/i;
const UNTRUSTED_OPEN = /^\s{0,8}<<UNTRUSTED(?:\s[^>]{0,80})?>>\s{0,8}$/;
const UNTRUSTED_CLOSE = /^\s{0,8}<<\/UNTRUSTED>>\s{0,8}$/;

/**
 * Split text into trusted and untrusted segments. Untrusted = content between
 * `----- BEGIN <LABEL> -----` / `----- END <LABEL> -----` lines (DVAA's RAG payload framing),
 * `[BEGIN <LABEL>]` / `[END <LABEL>]` (DVAA indexed-document metadata), `<INFORMATION>` /
 * `</INFORMATION>` (AgentDojo's injection wrapper) or `<<UNTRUSTED ...>>` / `<</UNTRUSTED>>` spotlight
 * delimiters. An unclosed block runs to the end of the text (ambiguity resolves to *less* trust).
 * Linear: one pass over lines; each line regex is anchored and length-bounded (lines > 200 chars
 * cannot be delimiters and are not tested).
 */
export function splitUntrustedSegments(text) {
  const trusted = [];
  const untrusted = [];
  if (typeof text !== 'string' || text.length === 0) return { trusted: '', untrusted };
  let mode = null; // null | {endLine, label, start}
  let buf = [];
  let lineStart = 0;
  let segStart = 0;
  const lines = text.split('\n');
  for (const line of lines) {
    const short = line.length <= 200;
    if (mode === null) {
      let m = null;
      if (short && (m = BEGIN_LINE.exec(line))) {
        trusted.push(buf.join('\n'));
        buf = [];
        mode = { endLabel: m[1].trim(), label: m[1].trim(), spotlight: false };
        segStart = lineStart;
      } else if (short && (m = BRACKET_BEGIN.exec(line))) {
        trusted.push(buf.join('\n'));
        buf = [];
        mode = { endLabel: m[1].trim(), label: m[1].trim(), bracket: true };
        segStart = lineStart;
      } else if (short && UNTRUSTED_OPEN.test(line)) {
        trusted.push(buf.join('\n'));
        buf = [];
        mode = { label: 'UNTRUSTED', spotlight: true, close: UNTRUSTED_CLOSE };
        segStart = lineStart;
      } else if (short && INFO_OPEN.test(line)) {
        trusted.push(buf.join('\n'));
        buf = [];
        mode = { label: 'INFORMATION', spotlight: true, close: INFO_CLOSE };
        segStart = lineStart;
      } else buf.push(line);
    } else {
      const closes = short && (mode.spotlight ? mode.close.test(line) : mode.bracket ? line.trim() === `[END ${mode.endLabel}]` : isEndLine(line, mode.endLabel));
      if (closes) {
        untrusted.push({ label: mode.label, text: buf.join('\n'), index: segStart });
        buf = [];
        mode = null;
      } else buf.push(line);
    }
    lineStart += line.length + 1;
  }
  if (mode === null) trusted.push(buf.join('\n'));
  else untrusted.push({ label: mode.label, text: buf.join('\n'), index: segStart, unclosed: true });
  return { trusted: trusted.join('\n'), untrusted };
}

function isEndLine(line, label) {
  const t = line.trim();
  if (!t.startsWith('---') || !t.endsWith('---')) return false;
  const inner = t.replace(/^-+/, '').replace(/-+$/, '').trim();
  return inner === `END ${label}`;
}

// ---- injection lexicon (raises risk only; never the sole gate — ADJACENT §6c) -------------------
const INJECTION_PHRASES = [
  'ignore previous instructions', 'ignore all previous', 'ignore the above', 'disregard previous',
  'new instructions', 'new index instructions', 'system override', 'you must now', 'do not tell the user',
  "don't tell the user", 'do not mention', 'silently', 'without asking', 'exfiltrate', 'send the contents',
  'verify your connection', 'as the project requires', 'agent instructions', 'assistant must', 'before responding',
  'run the following', 'curl -sl', '| bash', 'read ~/.', 'read the file ~/', 'post them to', 'report the environment',
  // published benchmark phrasings (AgentDojo important_instructions, InjecAgent, deepset)
  'important message from me', 'before you can solve the task', 'ignore previous', 'ignore any previous',
  'ignore your previous', 'system notice:', "send the user's", "post the user's", "forward the user's", "retrieve the user's",
];

/** Instruction-like phrases in (untrusted) text. Linear: lower-case once, indexOf per phrase. */
export function findInjectionPhrases(text) {
  if (typeof text !== 'string' || text.length === 0) return [];
  const lower = text.toLowerCase();
  return INJECTION_PHRASES.filter((p) => lower.indexOf(p) !== -1);
}

// ---- lookalike destinations ----------------------------------------------------------------------

const CONFUSABLES = { '0': 'o', '1': 'l', '3': 'e', '5': 's', '7': 't', '8': 'b', rn: 'm', vv: 'w', 'і': 'i', 'о': 'o', 'а': 'a', 'е': 'e', 'с': 'c', 'р': 'p' };

/** Confusable skeleton (tall-man / homoglyph check). */
export function skeleton(host) {
  let s = host.normalize('NFKC').toLowerCase();
  for (const [k, v] of Object.entries(CONFUSABLES)) s = s.split(k).join(v);
  return s;
}

/** Levenshtein distance with an early-exit bound (O(n*m) on hostnames <= 255 chars). */
export function levenshtein(a, b, max = 3) {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      if (cur[j] < rowMin) rowMin = cur[j];
    }
    if (rowMin > max) return max + 1;
    prev = cur;
  }
  return prev[b.length];
}

/** Is `host` a near-miss of any trusted host (Levenshtein <= 2 or same confusable skeleton)? */
export function lookalikeOf(host, trustedHosts) {
  if (!host || host.length > 255) return null;
  const sk = skeleton(host);
  for (const t of trustedHosts) {
    if (!t || t === host) continue;
    if (t.length > 255) continue;
    if (skeleton(t) === sk || levenshtein(host, t, 2) <= 2) return t;
  }
  return null;
}

/** Host matches an allowlist entry exactly or as a subdomain (`api.github.com` vs `github.com`). */
export function hostAllowed(host, list) {
  if (!host) return false;
  for (const entry of list) {
    const e = String(entry).toLowerCase();
    if (host === e || host.endsWith(`.${e}`)) return true;
  }
  return false;
}
