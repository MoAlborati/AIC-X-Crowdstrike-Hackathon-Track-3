// SentinelProxy T4 — secret redaction for alert bodies.
//
// Rule: an alert NEVER carries a secret value. Any string matching a secret pattern, or equal to /
// containing a known canary (honeytoken) value, is replaced by `[REDACTED:<kind>:sha256=<16 hex>]`
// (canaries additionally carry their id). The hash lets an analyst correlate "same secret seen twice"
// without the alert body becoming a second exfil channel.
//
// Bound: strings longer than MAX_REDACT_SCAN_CHARS are not regex-scanned (cost bound); they are
// WITHHELD entirely (fail-safe: replaced by a marker with length + hash) and a warning is raised.
// Never "scan the first N chars and pass the rest through" — that is the DVAA 8KB-window anti-pattern.

import { createHash } from 'node:crypto';

export const MAX_REDACT_SCAN_CHARS = 1024 * 1024; // 1 MiB per string field
export const HASH_HEX_CHARS = 16;

export const sha256Short = (s) => createHash('sha256').update(String(s)).digest('hex').slice(0, HASH_HEX_CHARS);

// Prefix-shaped tokens deliberately have NO leading \b: a secret glued to word characters
// ("xAKIA…", "dataghp_…") must still be caught. Over-redaction is the safe failure for an alert body.
// Ordered: most specific first. `group` (optional) = capture group holding the secret value; the rest
// of the match (e.g. "password=") is kept so the analyst still sees what kind of field leaked.
export const SECRET_PATTERNS = Object.freeze([
  { kind: 'private_key', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
  { kind: 'aws_access_key', re: /(?:AKIA|ASIA)[0-9A-Z]{16}/g },
  { kind: 'github_token', re: /gh[pousr]_[A-Za-z0-9]{30,}/g },
  { kind: 'slack_token', re: /xox[abprs]-[A-Za-z0-9-]{10,}/g },
  { kind: 'api_key_sk', re: /sk-[A-Za-z0-9_-]{16,}/g },
  { kind: 'jwt', re: /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g },
  { kind: 'bearer_token', re: /\b(Bearer\s+)([A-Za-z0-9._~+/-]{16,}=*)/gi, group: 2 },
  {
    kind: 'credential_assignment',
    re: /\b((?:password|passwd|pwd|secret|client_secret|api[_-]?key|access[_-]?key|auth[_-]?token|token)["']?\s*[:=]\s*["']?)([^\s"',;}{]{6,})/gi,
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

function insideMarker(src, offset) {
  const open = src.lastIndexOf('[REDACTED:', offset);
  if (open === -1) return false;
  const close = src.indexOf(']', open);
  return close !== -1 && close >= offset;
}

const marker = (kind, secret, canaryId) =>
  canaryId
    ? `[REDACTED:canary:${canaryId}:sha256=${sha256Short(secret)}]`
    : `[REDACTED:${kind}:sha256=${sha256Short(secret)}]`;

/**
 * Redact one string. Returns { value, findings: [{kind, sha256, canaryId?}], withheld }.
 * @param {string} str
 * @param {{canaries?: Array<{id:string, value:string}>}} [opts]
 */
export function redactString(str, { canaries = [] } = {}) {
  const findings = [];
  if (typeof str !== 'string' || str.length === 0) return { value: str, findings, withheld: false };

  if (str.length > MAX_REDACT_SCAN_CHARS) {
    // Too big to scan within budget: withhold the WHOLE value (never pass an unscanned tail through).
    const h = sha256Short(str);
    findings.push({ kind: 'withheld_oversize', sha256: h });
    return {
      value: `[WITHHELD:oversize len=${str.length} cap=${MAX_REDACT_SCAN_CHARS} sha256=${h}]`,
      findings,
      withheld: true,
    };
  }

  let out = str;
  // 1) Known canaries first (exact substring, longest first so overlapping canaries redact fully).
  const sorted = [...canaries].filter((c) => c && typeof c.value === 'string' && c.value.length > 0);
  sorted.sort((a, b) => b.value.length - a.value.length);
  for (const c of sorted) {
    if (out.includes(c.value)) {
      const m = marker('canary', c.value, c.id ?? 'unknown');
      const n = out.split(c.value).length - 1;
      out = out.split(c.value).join(m);
      for (let i = 0; i < n; i++) findings.push({ kind: 'canary', canaryId: c.id ?? 'unknown', sha256: sha256Short(c.value) });
    }
  }
  // 2) Generic secret patterns.
  for (const p of SECRET_PATTERNS) {
    p.re.lastIndex = 0;
    out = out.replace(p.re, (whole, ...rest) => {
      const src = rest[rest.length - 1];
      const offset = rest[rest.length - 2];
      const groups = rest.slice(0, -2);
      if (whole.includes('[REDACTED:')) return whole;
      // Never re-match inside one of our own markers (e.g. the hex digest after "sha256=").
      if (insideMarker(src, offset)) return whole;
      if (p.check && !p.check(whole)) return whole;
      if (p.group) {
        const secret = groups[p.group - 1];
        if (typeof secret !== 'string' || secret.startsWith('[REDACTED:')) return whole;
        findings.push({ kind: p.kind, sha256: sha256Short(secret) });
        return groups.slice(0, p.group - 1).join('') + marker(p.kind, secret);
      }
      findings.push({ kind: p.kind, sha256: sha256Short(whole) });
      return marker(p.kind, whole);
    });
  }
  return { value: out, findings, withheld: false };
}

/**
 * Deep-redact every string leaf of a plain JSON-ish value (objects/arrays). Returns a new value.
 * @returns {{ value: any, findings: Array<object>, withheldCount: number }}
 */
export function redactDeep(value, opts = {}) {
  const findings = [];
  let withheldCount = 0;
  const walk = (v) => {
    if (typeof v === 'string') {
      const r = redactString(v, opts);
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
