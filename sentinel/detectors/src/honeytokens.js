// SentinelProxy T3 — honeytoken tripwire registry.
//
// Three kinds of planted markers, one index:
//   static          operator-declared planted secrets (DVAA's SENSITIVE_DATA etc.). Never expire.
//   canary          minted per `session+tool` by mintCanary(); realistic, indistinguishable from real
//                   secrets; the hit names the session, the tool that fetched it and the sink.
//   seeded_record   3–5 fake "Agloe" records seeded into readable data (seedRecords()).
//
// Lookup is POOL-SIZE INDEPENDENT (team rule: no capped list scan on a decision path): every token is
// indexed by its first 8 (and 16) chars, and a scan is one linear pass over the text with an O(1) Map lookup per
// position. 10 tokens or 50,000 tokens cost the same per byte. A token at registry position 49,999 is
// found exactly like one at position 1 (test/honeytoken.test.js proves it).
//
// Bound: maxCanaries live minted entries. Expired (TTL) entries are evicted first; if the registry is
// still full, mint/seed throws RegistryFullError and the detector fails closed. Live canaries are never
// silently evicted.

import { randomBytes, randomInt, createHash } from 'node:crypto';
import { RegistryFullError } from './bounds.js';

export const MIN_TOKEN_CHARS = 8;
const KEY = MIN_TOKEN_CHARS;
// Two-level index: 8-char prefix -> {short: tokens < 16 chars, long: Map(16-char prefix -> tokens)}.
// Minted canaries share prefixes (every api_key canary starts "sk-proj-"), so an 8-char bucket alone
// would hold 50,000 entries and adversarial text repeating "sk-proj-" would cost O(n x 50,000). The
// 16-char second level keeps per-position work O(1) for random tokens (timing test proves it).
const KEY2 = 16;
const BASE = 257;
let POW = 1; // BASE^(KEY-1) mod 2^32
for (let k = 1; k < KEY; k++) POW = Math.imul(POW, BASE) >>> 0;
function hashKey(str) {
  let h = 0;
  for (let k = 0; k < KEY; k++) h = (Math.imul(h, BASE) + str.charCodeAt(k)) >>> 0;
  return h;
}

const BASE62 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const rand62 = (n) => Array.from(randomBytes(n), (b) => BASE62[b % 62]).join('');
const randUpper = (n) => Array.from(randomBytes(n), (b) => 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'[b % 32]).join('');

/**
 * DVAA's planted fake secrets (src/core/vulnerabilities.js SENSITIVE_DATA, dev-machine.fixture.js,
 * flight-wallet.fixture.js at pinned commit 57918267). All are FAKE training values.
 * Use as `createDetector({ honeytokens: DVAA_HONEYTOKENS })` when fronting DVAA.
 */
export const DVAA_HONEYTOKENS = Object.freeze([
  { id: 'DVAA-OPENAI-KEY', value: 'sk-dvaa-openai-test-key-do-not-use-in-production-12345', label: 'DVAA SENSITIVE_DATA.apiKeys.openai' },
  { id: 'DVAA-ANTHROPIC-KEY', value: 'sk-ant-dvaa-test-anthropic-key-67890', label: 'DVAA SENSITIVE_DATA.apiKeys.anthropic' },
  { id: 'DVAA-INTERNAL-KEY', value: 'dvaa-internal-api-key-abcdef', label: 'DVAA SENSITIVE_DATA.apiKeys.internal' },
  { id: 'DVAA-DB-PASSWORD', value: 'dvaa-db-password-123', label: 'DVAA SENSITIVE_DATA.credentials.database.password' },
  { id: 'DVAA-ADMIN-PASSWORD', value: 'dvaa-admin-secret', label: 'DVAA SENSITIVE_DATA.credentials.admin.password' },
  { id: 'DVAA-SSN-JOHN', value: '123-45-6789', label: 'DVAA SENSITIVE_DATA.pii.users[0].ssn' },
  { id: 'DVAA-SSN-JANE', value: '987-65-4321', label: 'DVAA SENSITIVE_DATA.pii.users[1].ssn' },
  { id: 'DVAA-AWS-KEY-ID', value: 'AKIAFAKEFAKEFAKEFAKE00', label: 'DVAA dev-machine ~/.aws/credentials' },
  { id: 'DVAA-AWS-SECRET', value: 'FAKEnotarealsecretkeyFAKEnotarealFAKE00', label: 'DVAA dev-machine ~/.aws/credentials' },
  { id: 'DVAA-SSH-KEY', value: 'FAKE-PRIVATE-KEY-MATERIAL-THIS-IS-NOT-A-KEY-FAKE', label: 'DVAA dev-machine ~/.ssh/id_rsa' },
  { id: 'DVAA-PASSPORT', value: 'X00000000 (FAKE)', label: 'DVAA flight wallet passport' },
  { id: 'DVAA-LOYALTY-ONEPASS', value: 'OP-FAKE-88273', label: 'DVAA flight wallet loyalty' },
  { id: 'DVAA-LOYALTY-SKYMILES', value: 'SM-FAKE-41902', label: 'DVAA flight wallet loyalty' },
  { id: 'DVAA-CARD-AMEX', value: '3782 822463 10005', label: 'DVAA flight wallet amex' },
]);

export class HoneytokenRegistry {
  /**
   * @param {{ maxCanaries?: number, canaryTtlMs?: number, now?: () => number }} opts
   */
  constructor({ maxCanaries = 50000, canaryTtlMs = 24 * 3600 * 1000, now = Date.now } = {}) {
    this.maxCanaries = maxCanaries;
    this.ttlMs = canaryTtlMs;
    this.now = now;
    this.entries = new Map(); // value -> entry
    this.ids = new Map(); // id -> entry (targeted lookup for toAlertVerdict)
    this.index = new Map(); // first KEY chars -> {key, short, long}
    this.hashIndex = new Map(); // hashKey(first KEY chars) -> [bucket] (collision list)
    this.filter = new Uint16Array(65536); // counting prefilter over the hash: skips the Map lookup for ~all positions
    this.minted = 0;
    this.seq = 0;
  }

  get size() {
    return this.entries.size;
  }

  /** Register a static (operator-planted) token. Static tokens do not count toward maxCanaries. */
  addStatic({ id, value, label }) {
    return this.#add({ id: id ?? `HT-${++this.seq}`, value, label: label ?? id, kind: 'static', session: null, tool: null });
  }

  /**
   * Mint a realistic per-session canary for `tool` (`kind`: api_key | aws_key | password | db_url).
   * Returns {id, value}. Throws RegistryFullError if full of live canaries.
   */
  mintCanary(session, tool, kind = 'api_key') {
    const value = {
      api_key: () => `sk-proj-${rand62(40)}`,
      aws_key: () => `AKIA${randUpper(16)}`,
      password: () => `${rand62(6)}-${rand62(6)}-${rand62(6)}`,
      db_url: () => `postgres://svc_${rand62(6).toLowerCase()}:${rand62(20)}@db-internal-${randomInt(10, 99)}.corp.local:5432/prod`,
    }[kind]?.();
    if (!value) throw new TypeError(`unknown canary kind "${kind}"`);
    const id = `CANARY-${session}-${++this.seq}`;
    this.#ensureRoom(1);
    this.#add({ id, value, label: `${kind} canary minted for session ${session} via ${tool}`, kind: 'canary', session, tool, expires: this.now() + this.ttlMs });
    return { id, value };
  }

  /**
   * Seed `n` (3–5) fake "Agloe" customer records for `session`; each field is registered as a canary.
   * Returns the records to splice into readable data (tool output / DB fixture).
   */
  seedRecords(session, tool = 'seeded_data', n = 4) {
    if (!Number.isInteger(n) || n < 3 || n > 5) throw new RangeError('seedRecords: n must be 3..5');
    this.#ensureRoom(n * 3);
    const records = [];
    for (let i = 0; i < n; i++) {
      const first = ['Agloe', 'Mabel', 'Lillian', 'Otto', 'Mountweazel'][i];
      const tag = rand62(6).toLowerCase();
      const rec = {
        name: `${first} ${['Fenwick', 'Okafor', 'Lindqvist', 'Haruna', 'Delacroix'][i]}`,
        email: `${first.toLowerCase()}.${tag}@example-mail.net`,
        ssn: `${randomInt(100, 665)}-${String(randomInt(10, 99))}-${String(randomInt(1000, 9999))}`,
        account: `ACCT-${randUpper(10)}`,
      };
      const expires = this.now() + this.ttlMs;
      for (const field of ['email', 'ssn', 'account']) {
        this.#add({ id: `AGLOE-${session}-${i}-${field}`, value: rec[field], label: `seeded record ${rec.name}.${field} for session ${session} via ${tool}`, kind: 'seeded_record', session, tool, expires });
      }
      records.push(rec);
    }
    return records;
  }

  /** Drop expired minted entries. Returns how many were removed. */
  sweep() {
    const t = this.now();
    let n = 0;
    for (const [v, e] of this.entries) {
      if (e.expires !== undefined && e.expires <= t) {
        this.#remove(v, e);
        n++;
      }
    }
    return n;
  }

  /**
   * Every registered token occurring in `text`. One linear pass: at each position, an O(1) lookup of
   * the next 8 chars. Expired canaries still match until swept (a late leak is still a leak).
   * Returns [{entry, index}].
   */
  scan(text, { all = false } = {}) {
    const hits = [];
    if (typeof text !== 'string' || text.length < KEY || this.index.size === 0) return hits;
    const seen = new Set();
    const check = (list, i) => {
      for (const e of list) {
        if ((all || !seen.has(e.value)) && text.startsWith(e.value, i)) {
          seen.add(e.value);
          hits.push({ entry: e, index: i });
        }
      }
    };
    // Allocation-free rolling hash of the 8-char window (no substring per position). A hash hit is then
    // verified exactly, so collisions cost a lookup, never a false match.
    let h = 0;
    for (let k = 0; k < KEY; k++) h = (Math.imul(h, BASE) + text.charCodeAt(k)) >>> 0;
    const last = text.length - KEY;
    for (let i = 0; ; i++) {
      const bucket = this.filter[(h ^ (h >>> 16)) & 0xffff] === 0 ? undefined : this.hashIndex.get(h);
      if (bucket !== undefined) {
        for (const b of bucket) {
          if (!text.startsWith(b.key, i)) continue;
          if (b.short.length) check(b.short, i);
          if (b.long.size && i + KEY2 <= text.length) {
            const list = b.long.get(text.substr(i, KEY2));
            if (list) check(list, i);
          }
        }
      }
      if (i === last) break;
      h = (Math.imul((h - Math.imul(text.charCodeAt(i), POW)) >>> 0, BASE) + text.charCodeAt(i + KEY)) >>> 0;
    }
    return hits;
  }

  /** Targeted lookup by id (O(1); never a scan). */
  byId(id) {
    return this.ids.get(id) ?? null;
  }

  /** All values (for T4's `canaries` redaction list). */
  values() {
    return [...this.entries.values()].map((e) => ({ id: e.id, value: e.value }));
  }

  #ensureRoom(k) {
    if (this.minted + k <= this.maxCanaries) return;
    this.sweep();
    if (this.minted + k > this.maxCanaries) {
      throw new RegistryFullError({ bound: 'maxCanaries', payload_size: this.minted + k, cap: this.maxCanaries, action: 'block' });
    }
  }

  #add(e) {
    if (typeof e.value !== 'string' || e.value.length < MIN_TOKEN_CHARS) {
      throw new TypeError(`honeytoken "${e.id}" must be a string of >= ${MIN_TOKEN_CHARS} chars`);
    }
    if (this.entries.has(e.value)) return this.entries.get(e.value);
    e.sha256 = createHash('sha256').update(e.value).digest('hex').slice(0, 16);
    this.entries.set(e.value, e);
    this.ids.set(e.id, e);
    const k = e.value.slice(0, KEY);
    if (!this.index.has(k)) {
      const nb = { key: k, short: [], long: new Map() };
      this.index.set(k, nb);
      const hk = hashKey(k);
      if (!this.hashIndex.has(hk)) this.hashIndex.set(hk, []);
      this.hashIndex.get(hk).push(nb);
      this.filter[(hk ^ (hk >>> 16)) & 0xffff]++;
    }
    const b = this.index.get(k);
    if (e.value.length < KEY2) b.short.push(e);
    else {
      const k2 = e.value.slice(0, KEY2);
      if (!b.long.has(k2)) b.long.set(k2, []);
      b.long.get(k2).push(e);
    }
    if (e.kind !== 'static') this.minted++;
    return e;
  }

  #remove(v, e) {
    this.entries.delete(v);
    this.ids.delete(e.id);
    const k = v.slice(0, KEY);
    const b = this.index.get(k);
    if (b) {
      const list = v.length < KEY2 ? b.short : b.long.get(v.slice(0, KEY2));
      const i = list ? list.indexOf(e) : -1;
      if (i !== -1) list.splice(i, 1);
      if (list && list.length === 0 && v.length >= KEY2) b.long.delete(v.slice(0, KEY2));
      if (b.short.length === 0 && b.long.size === 0) {
        this.index.delete(k);
        const hk = hashKey(k);
        const hb = this.hashIndex.get(hk);
        if (hb) {
          const j = hb.indexOf(b);
          if (j !== -1) {
            hb.splice(j, 1);
            this.filter[(hk ^ (hk >>> 16)) & 0xffff]--;
          }
          if (hb.length === 0) this.hashIndex.delete(hk);
        }
      }
    }
    if (e.kind !== 'static') this.minted--;
  }
}
