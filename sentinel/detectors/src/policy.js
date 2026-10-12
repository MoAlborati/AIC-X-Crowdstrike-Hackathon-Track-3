// Tourniquet T3 — the ONE policy.json (BACKLOG T3 "One config, not three").
//
// Mandate, destination provenance and per-tool policy are evaluated as one pure function over this
// object: `static` (operator-authored per-tool limits, mode report-only|enforce) ∩ `mandate`
// (per-session, principal-derived; see mandate.js). Destination provenance is the `destination`
// dimension: allowed = static.allowlist ∪ mandate.destinations, reason code `payee_not_confirmed`.
//
// Shape (all keys optional; validatePolicy() fails loud on anything unknown or mistyped):
// {
//   "mode": "enforce" | "report-only",            // also accepts T2's "block" | "observe"
//   "allowlist": { "hosts": ["api.example.com"], "emails": ["ops@example.com"] },
//   "tools": {
//     "<tool name>": {
//       "kind": "untrusted_source" | "sensitive_read" | "read" | "egress" | "exec" | "write",
//       "mode": "enforce" | "report-only",          // per-tool override (CSP report-only rollout)
//       "banned": false,
//       "allowlist": ["hooks.example.com"],         // extra hosts for this tool only
//       "pathJail": ["/srv/app/"],                  // path args must start with one of these
//       "maxArgBytes": 65536,                       // single-call byte cap
//       "maxAmount": 500,                           // single-call amount cap
//       "maxCallsPerSession": 20,                   // cumulative caps (velocity)
//       "maxBytesPerSession": 1048576,
//       "maxAmountPerSession": 2000,
//       "structuringThreshold": 3,                  // N calls each >= 80% of a single-call cap -> HOLD
//       "onViolation": "block" | "hold" | "alert"   // pre-declared corrective action
//     }
//   },
//   "sinks": { "assistant_content": { "honeytoken": "block" | "alert" } },
//   "inbound": { "injection": "alert" | "block", "exfilInstruction": "block" | "alert" },
//   "mandate": {
//     "ttlMs": 1800000,
//     "defaultTools": "*" | ["tool", ...],          // tools granted when no template matches
//     "templates": [{ "name": "flight-search", "match": "flight", "tools": ["search_flights"],
//                     "destinations": [], "maxAmount": 0 }]
//   }
// }

import { PolicyError } from './bounds.js';

export const TOOL_KINDS = Object.freeze(['untrusted_source', 'sensitive_read', 'read', 'egress', 'exec', 'write']);
export const SINK_KINDS = new Set(['egress', 'exec', 'write']);
const MODES = { enforce: 'enforce', block: 'enforce', 'report-only': 'report-only', report_only: 'report-only', observe: 'report-only' };
const VIOLATION_ACTIONS = ['block', 'hold', 'alert'];

const TOOL_KEYS = new Set(['kind', 'mode', 'banned', 'allowlist', 'pathJail', 'maxArgBytes', 'maxAmount', 'maxCallsPerSession', 'maxBytesPerSession', 'maxAmountPerSession', 'structuringThreshold', 'onViolation']);
const TOP_KEYS = new Set(['mode', 'allowlist', 'tools', 'sinks', 'mandate', 'inbound']);

/** Normalize + validate. Throws PolicyError listing EVERY issue (fail loud, never partial). */
export function validatePolicy(input = {}) {
  const issues = [];
  if (input === null || typeof input !== 'object' || Array.isArray(input)) throw new PolicyError(['policy must be an object']);
  for (const k of Object.keys(input)) if (!TOP_KEYS.has(k)) issues.push(`unknown top-level key "${k}"`);
  const mode = MODES[input.mode ?? 'enforce'];
  if (!mode) issues.push(`mode "${input.mode}" must be enforce|report-only (or block|observe)`);

  const hosts = (input.allowlist?.hosts ?? []).map((h) => String(h).toLowerCase());
  const emails = (input.allowlist?.emails ?? []).map((h) => String(h).toLowerCase());
  if (input.allowlist && (!Array.isArray(input.allowlist.hosts ?? []) || !Array.isArray(input.allowlist.emails ?? []))) {
    issues.push('allowlist.hosts and allowlist.emails must be arrays');
  }

  const tools = {};
  for (const [name, t] of Object.entries(input.tools ?? {})) {
    if (!t || typeof t !== 'object') {
      issues.push(`tools.${name} must be an object`);
      continue;
    }
    for (const k of Object.keys(t)) if (!TOOL_KEYS.has(k)) issues.push(`tools.${name}: unknown key "${k}"`);
    if (t.kind !== undefined && !TOOL_KINDS.includes(t.kind)) issues.push(`tools.${name}.kind "${t.kind}" not in ${TOOL_KINDS.join('|')}`);
    if (t.mode !== undefined && !MODES[t.mode]) issues.push(`tools.${name}.mode "${t.mode}" invalid`);
    if (t.onViolation !== undefined && !VIOLATION_ACTIONS.includes(t.onViolation)) issues.push(`tools.${name}.onViolation must be ${VIOLATION_ACTIONS.join('|')}`);
    for (const k of ['maxArgBytes', 'maxAmount', 'maxCallsPerSession', 'maxBytesPerSession', 'maxAmountPerSession', 'structuringThreshold']) {
      if (t[k] !== undefined && (!Number.isFinite(t[k]) || t[k] < 0)) issues.push(`tools.${name}.${k} must be a number >= 0`);
    }
    for (const k of ['allowlist', 'pathJail']) if (t[k] !== undefined && !Array.isArray(t[k])) issues.push(`tools.${name}.${k} must be an array`);
    tools[name] = {
      ...t,
      mode: t.mode ? MODES[t.mode] : undefined,
      allowlist: (t.allowlist ?? []).map((h) => String(h).toLowerCase()),
      onViolation: t.onViolation ?? 'block',
    };
  }

  const contentAction = input.sinks?.assistant_content?.honeytoken ?? 'block';
  if (!['block', 'alert'].includes(contentAction)) issues.push('sinks.assistant_content.honeytoken must be block|alert');

  // Inbound (request-side) screening. The injection lexicon raises risk only by default ("alert"; it is
  // never the sole gate, ADJACENT §6c). A lexicon hit that ALSO names an exfil element (destination /
  // honeytoken / secret) in the same untrusted text is a high-confidence exfil instruction -> "block".
  const inbound = { injection: input.inbound?.injection ?? 'alert', exfilInstruction: input.inbound?.exfilInstruction ?? 'block' };
  for (const k of ['injection', 'exfilInstruction']) if (!['block', 'alert'].includes(inbound[k])) issues.push(`inbound.${k} must be block|alert`);

  const m = input.mandate ?? {};
  const templates = [];
  for (const [i, t] of (m.templates ?? []).entries()) {
    if (!t || typeof t.match !== 'string' || !Array.isArray(t.tools)) {
      issues.push(`mandate.templates[${i}] needs {match: string, tools: []}`);
      continue;
    }
    if (t.match.length > 200) issues.push(`mandate.templates[${i}].match must be <= 200 chars (literal, case-insensitive)`);
    templates.push({ name: t.name ?? `template-${i}`, match: t.match.toLowerCase(), tools: t.tools, destinations: (t.destinations ?? []).map((d) => String(d).toLowerCase()), maxAmount: t.maxAmount });
  }
  const defaultTools = m.defaultTools ?? '*';
  if (defaultTools !== '*' && !Array.isArray(defaultTools)) issues.push('mandate.defaultTools must be "*" or an array');
  const ttlMs = m.ttlMs ?? 30 * 60 * 1000;
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) issues.push('mandate.ttlMs must be > 0');

  if (issues.length) throw new PolicyError(issues);
  return Object.freeze({
    mode,
    allowlist: Object.freeze({ hosts, emails }),
    tools,
    sinks: { assistant_content: { honeytoken: contentAction } },
    inbound,
    mandate: { ttlMs, defaultTools, templates },
  });
}

// ---- tool classification -------------------------------------------------------------------------
// Name-based defaults when policy.tools[name].kind is absent. Order matters (first match wins).
// These are literal-substring checks on a tool NAME (<= 128 chars), not scans of attacker text.
const NAME_RULES = [
  ['exec', ['shell', 'exec', 'run_command', 'bash', 'terminal', 'subprocess', 'eval']],
  ['egress', ['http_post', 'http_request', 'post', 'send', 'email', 'mail', 'upload', 'submit', 'webhook', 'publish', 'share', 'slack', 'notify', 'tweet', 'transfer', 'pay_', 'make_payment']],
  ['untrusted_source', ['fetch', 'browse', 'web', 'read_repo', 'search_web', 'scrape', 'download', 'read_url', 'get_page', 'retriev', 'rag', 'read_email', 'inbox', 'ticket', 'read_issue']],
  ['sensitive_read', ['secret', 'credential', 'password', 'vault', 'keychain', 'customer', 'user_db', 'list_users', 'query_db', 'sql', 'wallet', 'payment_method']],
  ['write', ['write', 'delete', 'update', 'create', 'commit', 'push', 'rm_', 'move']],
  ['read', ['read', 'get', 'list', 'search', 'lookup', 'find', 'query']],
];

// Path patterns that make a generic read a SENSITIVE read (literal substrings, bounded path length).
const SENSITIVE_PATH_MARKERS = ['.aws/credentials', '.ssh/', 'id_rsa', 'id_ed25519', '.env', '.netrc', '.npmrc', '.pypirc', '.git-credentials', '.docker/config.json', '.kube/config', '/etc/shadow', '/etc/passwd', 'secrets', 'credentials', 'wallet', '.gnupg', 'keychain'];

export function classifyTool(name, args, policy) {
  const explicit = policy.tools[name]?.kind;
  let kind = explicit;
  if (!kind) {
    const n = String(name).toLowerCase().slice(0, 128);
    kind = 'read';
    for (const [k, needles] of NAME_RULES) {
      if (needles.some((s) => n.includes(s))) {
        kind = k;
        break;
      }
    }
  }
  if ((kind === 'read' || kind === 'untrusted_source') && !explicit) {
    for (const p of pathArgs(args)) {
      const lp = p.toLowerCase().slice(0, 4096);
      if (SENSITIVE_PATH_MARKERS.some((m) => lp.includes(m))) return 'sensitive_read';
    }
  }
  return kind;
}

/** String values of path-like args (`path`, `file`, `filename`, `filepath`, `dir`). */
export function pathArgs(args) {
  const out = [];
  if (!args || typeof args !== 'object') return out;
  for (const [k, v] of Object.entries(args)) {
    if (typeof v === 'string' && /^(?:path|file|filename|filepath|file_path|dir|directory|target)$/i.test(k)) out.push(v);
  }
  return out;
}

/** Numeric amount args (`amount`, `value`, `price`, `total`, `sum`, `quantity`). */
export function amountArgs(args) {
  const out = [];
  if (!args || typeof args !== 'object') return out;
  for (const [k, v] of Object.entries(args)) {
    if (/^(?:amount|value|price|total|sum|usd|amount_usd)$/i.test(k)) {
      const n = typeof v === 'number' ? v : Number(String(v).replace(/[^0-9.]/g, ''));
      if (Number.isFinite(n)) out.push(n);
    }
  }
  return out;
}

export function effectiveMode(policy, toolName) {
  return policy.tools[toolName]?.mode ?? policy.mode;
}
