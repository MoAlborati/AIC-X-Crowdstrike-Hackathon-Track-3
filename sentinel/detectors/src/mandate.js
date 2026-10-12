// SentinelProxy T3 — user-turn mandate + the single policy evaluation (BACKLOG T3, ADJACENT §10.3a).
//
// A mandate is a per-session grant {tools, destinations, maxAmount, expires} derived ONLY from
// principal (user/system) turns, excluding untrusted segments embedded in them, plus an optional
// operator template per task. Ambiguity resolves to NARROWER:
//   * destinations come only from explicit URLs/emails in principal text (bare words never widen);
//   * if the principal names no amount, the amount grant is 0 (an amount-bearing call is out of grant);
//   * a template narrows tools; derived/sub-call grants can only intersect (narrowGrant, RFC 8693-style).
// Content (tool output, retrieved documents) can never widen it: it is not an input to deriveGrant.
//
// The grant is HMAC-SHA256 signed with a per-session random key (never a default secret) and verified
// before every evaluation; a tampered grant fails closed.
//
// evaluateCall() is the ONE pure function over policy.static ∩ mandate. Every violation names the
// dimension that failed: tool | destination | amount | expiry | static_limit.

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { MandateOverflowError, LedgerFullError } from './bounds.js';
import { extractUrls, extractEmails, findAmounts, hostAllowed } from './text.js';
import { pathArgs, amountArgs, SINK_KINDS } from './policy.js';

export const DIMENSIONS = Object.freeze(['tool', 'destination', 'amount', 'expiry', 'static_limit']);

// ---- session store (grant key + ledger), bounded ---------------------------------------------------

export class SessionStore {
  constructor({ maxSessions = 10000, sessionTtlMs = 3600000, maxLedgerKeysPerSession = 512, now = Date.now } = {}) {
    this.max = maxSessions;
    this.ttl = sessionTtlMs;
    this.maxKeys = maxLedgerKeysPerSession;
    this.now = now;
    this.sessions = new Map();
  }

  get(id) {
    let s = this.sessions.get(id);
    if (s) {
      s.lastSeen = this.now();
      return s;
    }
    if (this.sessions.size >= this.max) {
      this.sweep();
      if (this.sessions.size >= this.max) {
        throw new LedgerFullError({ bound: 'maxSessions', payload_size: this.sessions.size + 1, cap: this.max, action: 'block' });
      }
    }
    s = { id, key: randomBytes(32), createdAt: this.now(), lastSeen: this.now(), grant: null, ledger: new Map() };
    this.sessions.set(id, s);
    return s;
  }

  /** Evict sessions idle past TTL (their history is finished, not truncated). */
  sweep() {
    const t = this.now();
    for (const [id, s] of this.sessions) if (t - s.lastSeen > this.ttl) this.sessions.delete(id);
  }

  ledgerEntry(session, tool) {
    let e = session.ledger.get(tool);
    if (!e) {
      if (session.ledger.size >= this.maxKeys) {
        throw new LedgerFullError({ bound: 'maxLedgerKeysPerSession', payload_size: session.ledger.size + 1, cap: this.maxKeys, action: 'block' });
      }
      e = { count: 0, bytes: 0, amount: 0, nearCap: 0 };
      session.ledger.set(tool, e);
    }
    return e;
  }
}

// ---- grant derivation + signing ---------------------------------------------------------------

/**
 * @param {{principalText: string, policy: object, session: object, maxGrantEntries: number, now?: number}} p
 */
export function deriveGrant({ principalText, policy, session, maxGrantEntries, now = Date.now() }) {
  const text = principalText ?? '';
  const destinations = new Set();
  for (const u of extractUrls(text)) destinations.add(u.host);
  for (const e of extractEmails(text)) destinations.add(e.email);

  const lower = text.toLowerCase();
  const template = policy.mandate.templates.find((t) => lower.includes(t.match)) ?? null;
  let tools = policy.mandate.defaultTools === '*' ? '*' : [...policy.mandate.defaultTools];
  if (template) {
    tools = tools === '*' ? [...template.tools] : tools.filter((t) => template.tools.includes(t));
    for (const d of template.destinations) destinations.add(d);
  }

  const amounts = findAmounts(text);
  let maxAmount = amounts.length ? Math.max(...amounts) : 0;
  if (template && Number.isFinite(template.maxAmount)) maxAmount = Math.min(maxAmount, template.maxAmount);

  const entries = destinations.size + (tools === '*' ? 1 : tools.length);
  if (entries > maxGrantEntries) {
    throw new MandateOverflowError({ bound: 'maxGrantEntries', payload_size: entries, cap: maxGrantEntries, action: 'block' });
  }
  const grant = {
    session: session.id,
    tools: tools === '*' ? '*' : [...new Set(tools)].sort(),
    destinations: [...destinations].sort(),
    maxAmount,
    expires: session.createdAt + policy.mandate.ttlMs,
    template: template?.name ?? null,
    derivedFrom: 'principal',
    issuedAt: now,
  };
  return signGrant(grant, session.key);
}

const canonical = (g) => JSON.stringify({ s: g.session, t: g.tools, d: g.destinations, a: g.maxAmount, e: g.expires, p: g.template, f: g.derivedFrom });

export function signGrant(grant, key) {
  const sig = createHmac('sha256', key).update(canonical(grant)).digest('hex');
  return Object.freeze({ ...grant, sig });
}

export function verifyGrant(grant, key) {
  if (!grant || typeof grant.sig !== 'string') return false;
  const want = Buffer.from(createHmac('sha256', key).update(canonical(grant)).digest('hex'));
  const got = Buffer.from(grant.sig);
  return want.length === got.length && timingSafeEqual(want, got);
}

/** A derived/sub-call grant can only NARROW its parent (intersection on every dimension). */
export function narrowGrant(parent, child, key) {
  if (!verifyGrant(parent, key)) throw new Error('narrowGrant: parent grant signature invalid');
  const tools =
    parent.tools === '*' ? (child.tools ?? '*') : (child.tools === '*' || !child.tools ? parent.tools : child.tools.filter((t) => parent.tools.includes(t)));
  const destinations = (child.destinations ?? parent.destinations).filter((d) => parent.destinations.includes(d));
  return signGrant(
    {
      ...parent,
      tools,
      destinations,
      maxAmount: Math.min(parent.maxAmount, child.maxAmount ?? parent.maxAmount),
      expires: Math.min(parent.expires, child.expires ?? parent.expires),
      derivedFrom: `narrowed:${parent.derivedFrom}`,
    },
    key,
  );
}

// ---- the single evaluation ------------------------------------------------------------------------

// Keys whose values ARE recipients. Emails/URLs mentioned inside a data field (a body, a CSV) are data,
// not destinations: treating every address in a 14,000-row body as a payee made destination checks
// O(rows x findings) (found by the bounds test; see PR "bug found + delete-the-fix").
const RECIPIENT_KEY = /^(?:to|cc|bcc|recipients?|email|emails|address|addresses|send_to|sendto|mail_to|channel|webhook|webhook_url|endpoint|url|uri|href|link|host|hostname|domain|target|target_url|callback|callback_url|destination|dest)$/i;
const COMMAND_KEY = /^(?:command|cmd|script|shell|code)$/i;

/**
 * Destinations a tool call SENDS to: (a) any string arg whose value starts with http(s):// (it is an
 * endpoint wherever it sits), (b) URLs inside shell/command args (curl/wget), (c) emails and URLs under
 * recipient-named keys. Each destination appears once.
 */
export function callDestinations(args) {
  const out = [];
  const seen = new Set();
  const addUrl = (u, path) => {
    if (!seen.has(u.host)) {
      seen.add(u.host);
      out.push({ type: 'http', destination: u.host, url: u.url, argPath: path });
    }
  };
  walkStrings(args, (s, path, key) => {
    const head = s.trimStart();
    if (head.startsWith('http://') || head.startsWith('https://')) {
      const u = extractUrls(head.slice(0, 8192))[0];
      if (u) addUrl(u, path);
    } else if (COMMAND_KEY.test(key ?? '')) {
      for (const u of extractUrls(s)) addUrl(u, path);
    }
    if (RECIPIENT_KEY.test(key ?? '') && !head.startsWith('http')) {
      for (const e of extractEmails(s)) {
        if (!seen.has(e.email)) {
          seen.add(e.email);
          out.push({ type: 'email', destination: e.email, url: null, argPath: path });
        }
      }
    }
  });
  return out;
}

export function walkStrings(v, fn, path = '$', depth = 0, key = null) {
  if (depth > 32) return;
  if (typeof v === 'string') fn(v, path, key);
  else if (Array.isArray(v)) v.forEach((x, i) => walkStrings(x, fn, `${path}[${i}]`, depth + 1, key));
  else if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) walkStrings(x, fn, `${path}.${k}`, depth + 1, k);
}

/**
 * Evaluate one tool call against static policy ∩ mandate. Pure function.
 * @returns {Array<{dimension, reason, detail, destination?}>}
 */
export function evaluateCall({ call, kind, grant, policy, now = Date.now() }) {
  const v = [];
  const tp = policy.tools[call.name] ?? {};
  const isSink = SINK_KINDS.has(kind);

  if (tp.banned) v.push({ dimension: 'static_limit', reason: 'banned_tool', detail: `${call.name} is banned by policy` });
  if (grant.tools !== '*' && !grant.tools.includes(call.name)) {
    v.push({ dimension: 'tool', reason: 'attempted_escalation', detail: `${call.name} is outside the session mandate (granted: ${grant.tools.join(', ') || 'none'})` });
  }
  if (isSink && now > grant.expires) v.push({ dimension: 'expiry', reason: 'mandate_expired', detail: `mandate expired at ${new Date(grant.expires).toISOString()}` });

  // Destination provenance applies to sinks. A read tool's URL (e.g. web_fetch) is an ingress, not a
  // payee; data smuggled in a read URL's query is caught by the honeytoken/secret egress scans instead.
  if (isSink) {
    const hosts = [...policy.allowlist.hosts, ...(tp.allowlist ?? [])];
    // One violation per call listing every unconfirmed destination (decision uses all of them; the
    // detail text names the first 10 and states the total — display bound, not a decision bound).
    const bad = call.destinations.filter((d) =>
      d.type === 'email'
        ? !(policy.allowlist.emails.includes(d.destination) || grant.destinations.includes(d.destination) || hostAllowed(d.destination.split('@')[1], hosts))
        : !(hostAllowed(d.destination, hosts) || grant.destinations.includes(d.destination)),
    );
    if (bad.length) {
      const names = bad.slice(0, 10).map((d) => d.destination).join(', ') + (bad.length > 10 ? ` (+${bad.length - 10} more, ${bad.length} total)` : '');
      v.push({ dimension: 'destination', reason: 'payee_not_confirmed', detail: `${names} ${bad.length === 1 ? 'is' : 'are'} not in the allowlist and not named by the principal`, destination: bad[0], destinations: bad });
    }
  }

  for (const amt of amountArgs(call.args)) {
    if (Number.isFinite(tp.maxAmount) && amt > tp.maxAmount) v.push({ dimension: 'static_limit', reason: 'amount_over_static_cap', detail: `amount ${amt} > static cap ${tp.maxAmount}` });
    if (amt > grant.maxAmount) v.push({ dimension: 'amount', reason: 'attempted_escalation', detail: `amount ${amt} > mandate ${grant.maxAmount}` });
  }
  if (Array.isArray(tp.pathJail) && tp.pathJail.length) {
    for (const p of pathArgs(call.args)) {
      if (!tp.pathJail.some((j) => p.startsWith(j)) || p.includes('..')) v.push({ dimension: 'static_limit', reason: 'path_outside_jail', detail: `${p} outside ${tp.pathJail.join(', ')}` });
    }
  }
  if (Number.isFinite(tp.maxArgBytes) && call.argBytes > tp.maxArgBytes) {
    v.push({ dimension: 'static_limit', reason: 'arg_bytes_over_cap', detail: `${call.argBytes} bytes > cap ${tp.maxArgBytes}` });
  }
  return v;
}

/**
 * Cumulative caps (velocity / anti-structuring). Mutates the session ledger; returns violations.
 * Every call is recorded (not just violating ones) so N-just-under-the-cap structuring is visible.
 */
export function recordAndCheckLedger({ store, session, call, policy }) {
  const tp = policy.tools[call.name] ?? {};
  const e = store.ledgerEntry(session, call.name);
  const amount = amountArgs(call.args).reduce((a, b) => a + b, 0);
  e.count++;
  e.bytes += call.argBytes;
  e.amount += amount;
  const near =
    (Number.isFinite(tp.maxArgBytes) && tp.maxArgBytes > 0 && call.argBytes >= 0.8 * tp.maxArgBytes && call.argBytes <= tp.maxArgBytes) ||
    (Number.isFinite(tp.maxAmount) && tp.maxAmount > 0 && amount >= 0.8 * tp.maxAmount && amount <= tp.maxAmount);
  if (near) e.nearCap++;
  const v = [];
  if (Number.isFinite(tp.maxCallsPerSession) && e.count > tp.maxCallsPerSession) v.push({ dimension: 'static_limit', reason: 'velocity_calls', detail: `${e.count} calls to ${call.name} > ${tp.maxCallsPerSession}/session` });
  if (Number.isFinite(tp.maxBytesPerSession) && e.bytes > tp.maxBytesPerSession) v.push({ dimension: 'static_limit', reason: 'velocity_bytes', detail: `${e.bytes} bytes via ${call.name} > ${tp.maxBytesPerSession}/session` });
  if (Number.isFinite(tp.maxAmountPerSession) && e.amount > tp.maxAmountPerSession) v.push({ dimension: 'static_limit', reason: 'velocity_amount', detail: `cumulative amount ${e.amount} via ${call.name} > ${tp.maxAmountPerSession}/session` });
  const n = tp.structuringThreshold ?? 3;
  if (near && e.nearCap >= n && (Number.isFinite(tp.maxArgBytes) || Number.isFinite(tp.maxAmount))) {
    v.push({ dimension: 'static_limit', reason: 'structuring', detail: `${e.nearCap} calls to ${call.name} each just under the single-call cap` });
  }
  return v;
}
