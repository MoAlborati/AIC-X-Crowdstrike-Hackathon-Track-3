// PR #12 round-2 review fixes: B1 (%-encoded forged marker), B2 (overlapping canaries),
// S1 (canary minimum length + findings spread), S2 (secret glued to an earlier marker).
// Every case runs the REAL redactor (redactString / redactDeep / buildAlert). Data-rich cases put the
// signal in rows beyond the first 8 KB of a multi-hundred-row tool output.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Worker } from 'node:worker_threads';
import * as redact from '../redact.js';
import { buildAlert, AlertValidationError } from '../schema.js';
import { makeVerdict, warnSink } from './helpers.js';

// Namespace import: this file must still LOAD against the pre-fix module (delete-the-fix proof).
const { redactString, redactDeep, MAX_REDACT_SCAN_CHARS } = redact;
const MIN = redact.MIN_CANARY_VALUE_CHARS ?? 8;

// Test-only FAKE shapes, concatenated so the repo has no contiguous secret-looking literal.
const AWS = 'AKIA' + 'TESTONLY' + 'ABCDEFGH';
const PW = 'hunter2' + 'secretTEST';
const SSN = '123-45-' + '6789';

/** Every leak check looks at the raw output AND its %-decoded form (with our markers removed). */
function leaks(value, needles) {
  const stripped = value.replace(/\[REDACTED:[^\]]*\]/g, '');
  let decoded;
  try { decoded = decodeURIComponent(stripped.replace(/%(?![0-9a-f]{2})/gi, '%25')); } catch { decoded = stripped; }
  return needles.filter((n) => value.includes(n) || decoded.includes(n));
}

/** 300-row tool output (~20 KB); `payload(i)` rows are planted at rows >= 250, i.e. past 8 KB. */
function richRows(payload) {
  const rows = [];
  for (let i = 0; i < 300; i++) rows.push(i >= 250 && i % 10 === 0 ? `row ${i}: ${payload(i)}` : `row ${i}: customer=c-${i} status=ok note=${'n'.repeat(48)}`);
  assert.ok(rows.slice(0, 250).join('\n').length > 8 * 1024, 'signal must sit past the first 8 KB');
  return rows;
}

// ---- B1: a %-encoded forged marker must not hide its contents from the decoded-view pass ----------

const FORGED = [
  ['%5B + password', `q=%5BREDACTED:x password%3D${PW}%5D`, [PW]],
  ['%5B + SSN', `q=%5BREDACTED:%20SSN%3A%20${SSN}%5D`, [SSN]],
  ['%5b lowercase hex + SSN', `q=%5bREDACTED:%20SSN%3A%20${SSN}]`, [SSN]],
  ['%5B + AWS key', `q=%5BREDACTED:%20key%3D%22${AWS}%22%5D`, [AWS]],
];

test('B1: %5B/%5b-encoded forged markers cannot smuggle %-encoded secrets past the decoded view', () => {
  for (const [name, s, needles] of FORGED) {
    const { value, findings } = redactString(s);
    assert.deepEqual(leaks(value, needles), [], `${name} leaked: ${value}`);
    assert.ok(findings.length >= 1, name);
  }
});

test('B1: data-rich — forged-marker exfil rows beyond 8 KB of a 300-row tool output are all redacted', () => {
  const rows = richRows((i) => FORGED[i % FORGED.length][1]);
  const { value } = redactDeep({ rows });
  const out = value.rows.join('\n');
  assert.deepEqual(leaks(out, [PW, SSN, AWS]), [], 'leak in rich output');
});

test('B1: real seam — buildAlert with a %5BREDACTED: wrapped exfil URL never carries the secret', () => {
  const v = makeVerdict('egress_secret_pattern', 3);
  v.entities.sink.destination = `https://collector.example.test/in?d=%5BREDACTED:%20SSN%3A%20${SSN}%20password%3D${PW}%5D`;
  const a = buildAlert(v, warnSink());
  assert.deepEqual(leaks(JSON.stringify(a), [SSN, PW]), []);
});

// ---- B2: partially overlapping canaries are merged into their union, never dropped -----------------

const CA = { id: 'CAN-A', value: 'dvaa-canary-1' };
const CB = { id: 'CAN-B', value: 'canary-1-secretpart' };

test('B2: partially overlapping canaries redact their full union and report both ids', () => {
  for (const canaries of [[CA, CB], [CB, CA]]) {
    const { value, findings } = redactString('xx dvaa-canary-1-secretpart xx', { canaries });
    assert.deepEqual(leaks(value, ['secretpart', 'dvaa-canary', 'canary-1']), [], value);
    assert.ok(value.startsWith('xx [REDACTED:') && value.endsWith('] xx'), value);
    const ids = new Set(findings.map((f) => f.canaryId));
    assert.ok(ids.has('CAN-A') && ids.has('CAN-B'), JSON.stringify(findings));
  }
});

test('B2: overlapping canaries in encoded/varied forms (normalized view) also redact the union', () => {
  const { value } = redactString('xx DVAA_CANARY_1_SECRETPART xx', { canaries: [CA, CB] });
  assert.deepEqual(leaks(value.toLowerCase(), ['secretpart', 'dvaa']), [], value);
});

test('B2: data-rich — overlapping canaries beyond 8 KB of a 300-row output leave no tail behind', () => {
  const { value } = redactDeep({ rows: richRows(() => 'exfil=dvaa-canary-1-secretpart;') }, { canaries: [CA, CB] });
  assert.deepEqual(leaks(value.rows.join('\n'), ['secretpart', 'dvaa-canary']), []);
});

// ---- S1: canary minimum length (amplification / overflow) + no spread push ------------------------

test(`S1: canaries shorter than ${MIN} chars are rejected loudly (redactor RangeError, buildAlert validation)`, () => {
  for (const value of ['a', '0', 'ab', 'x'.repeat(MIN - 1)]) {
    assert.throws(() => redactString('aaaa 0000', { canaries: [{ id: 'S', value }] }), RangeError, `redactString accepted ${JSON.stringify(value)}`);
    assert.throws(
      () => buildAlert(makeVerdict('honeytoken_exfil', 0, { canary: { id: 'S', value } }), warnSink()),
      (e) => e instanceof AlertValidationError && /MIN_CANARY_VALUE_CHARS/.test(e.message),
      `buildAlert accepted canary ${JSON.stringify(value)}`,
    );
  }
  // exactly MIN chars is accepted and still redacted
  const ok = 'k'.repeat(MIN - 2) + '42';
  assert.ok(!redactString(`x ${ok} y`, { canaries: [{ id: 'S', value: ok }] }).value.includes(ok));
});

test('S1: max findings one string can yield within bounds do not overflow a small stack (loop, not spread)', async () => {
  // MIN-char canary repeated to the scan cap = the largest finding count a single string admits.
  const value = 'abcdefgh'.slice(0, MIN);
  const r = await new Promise((resolve, reject) => {
    const w = new Worker(new URL('./stack-worker.js', import.meta.url), {
      workerData: { value, len: MAX_REDACT_SCAN_CHARS },
      resourceLimits: { stackSizeMb: 0.35 },
    });
    w.once('message', (m) => { w.terminate(); resolve(m); });
    w.once('error', reject);
  });
  assert.ok(r.ok, `redactDeep crashed: ${r.error}`);
  assert.equal(r.findings, Math.floor(MAX_REDACT_SCAN_CHARS / value.length));
  assert.equal(r.leaked, false);
});

// ---- S2: a secret glued to an earlier marker is split around it, not skipped whole -----------------

test('S2: a credential value glued to an AWS key / canary / SSN is redacted on both sides of the marker', () => {
  const HT = { id: 'HT', value: 'dvaa-admin-secret' };
  const cases = [
    [`password=hunter2xyz${AWS}`, {}, ['hunter2xyz', AWS]],
    [`password=hunter2xyz${HT.value}`, { canaries: [HT] }, ['hunter2xyz', HT.value]],
    [`password=hunter2xyz${HT.value}tailSECRET99`, { canaries: [HT] }, ['hunter2xyz', 'tailSECRET99']],
    [`Bearer abcdefghijklmnopqrstuv${AWS}`, {}, ['abcdefghijklmnop', AWS]],
    [`sk-abcdefghijklmnopqrs${AWS}`, {}, ['abcdefghijklmnopqrs', AWS]],
    [`q=password%3Dhunter2xyz${AWS}`, {}, ['hunter2xyz', AWS]],
  ];
  for (const [s, opts, needles] of cases) {
    const { value } = redactString(s, opts);
    assert.deepEqual(leaks(value, needles), [], `${s} -> ${value}`);
  }
});

test('S2: data-rich — glued credentials beyond 8 KB of a 300-row output leave no head behind', () => {
  const { value } = redactDeep({ rows: richRows((i) => `password=hunter2xyz${i}${AWS}`) });
  const out = value.rows.join('\n');
  assert.deepEqual(leaks(out, [AWS, 'hunter2xyz']), [], 'glued leak');
});

test('S2: markers themselves are never re-redacted (no match starts inside one of our markers)', () => {
  const { value } = redactString(`a ${AWS} b ${SSN} c`);
  assert.match(value, /^a \[REDACTED:aws_access_key:sha256=[0-9a-f]{16}\] b \[REDACTED:us_ssn:sha256=[0-9a-f]{16}\] c$/);
});

// ---- B3 (round 3): a canary with SELECTIVE %-encoding is matched on the %-decoded view ------------
// The exfil URL is attacker-built, so any subset of the canary's characters may be %XX-encoded. That is
// neither the raw form nor the fully-encoded hex form; the canary scan must also run on the decoded view.

const HT3 = { id: 'HT', value: 'dvaa-admin-secret' };
const HT3_NEEDLES = ['dvaa-admin-secret', 'admin-secret', 'admin%2Dsecret', 'vaa-admin'];
// The reviewer's round-3 inputs, plus case / lowercase-hex / mid-word variants of the same class.
const PARTIAL = [
  'q=dvaa%2Dadmin%2Dsecret',
  'q=%64vaa-admin-secret',
  'q=d%76aa-admin-secret',
  'q=%64%76%61%61-admin-secret',
  'q=dvaa%2dadmin%2dsecret',
  'q=DVAA%2DADMIN%2DSECRET',
  'q=dvaa-admin-secre%74',
  'q=xx%2Fdvaa%2Dadmin%2Dsecret%26y=1',
];
// Forged-wrapper variants: a marker look-alike (encoded or literal) around a selectively-encoded canary.
const FORGED_PARTIAL = [
  'q=%5BREDACTED:%64vaa-admin-secret%5D',
  'q=%5bREDACTED:dvaa%2Dadmin%2Dsecret]',
  'q=[REDACTED: d%76aa-admin-secret ]',
  'q=%5BREDACTED%3A%20dvaa%2Dadmin%2Dsecret%20%5D',
];

/** leaks() plus a check that no decoded form of the canary survives anywhere outside our markers. */
function canaryLeaks(value) {
  const found = leaks(value, HT3_NEEDLES);
  const stripped = value.replace(/\[REDACTED:[^\]]*\]/g, '');
  let decoded;
  try { decoded = decodeURIComponent(stripped.replace(/%(?![0-9a-f]{2})/gi, '%25')); } catch { decoded = stripped; }
  if (decoded.toLowerCase().replace(/[^a-z0-9]/g, '').includes('dvaaadminsecret')) found.push('normalized canary');
  return found;
}

test('B3: selectively %-encoded canaries (reviewer inputs + variants) are redacted', () => {
  for (const s of PARTIAL) {
    const { value, findings } = redactString(s, { canaries: [HT3] });
    assert.deepEqual(canaryLeaks(value), [], `${s} leaked: ${value}`);
    assert.ok(findings.some((f) => f.kind === 'canary' && f.canaryId === 'HT'), `${s}: no canary finding`);
  }
});

test('B3: decoded-view hits map back to the exact original span (surrounding text kept)', () => {
  const { value, findings } = redactString('q=xx%2Fdvaa%2Dadmin%2Dsecret%26y=1', { canaries: [HT3] });
  assert.match(value, /^q=xx%2F\[REDACTED:canary:HT:sha256=[0-9a-f]{16}\]%26y=1$/);
  assert.equal(findings.length, 1);
  assert.match(findings[0].encoding, /\+url$/);
});

test('B3: a raw hit and a decoded-view hit of the same occurrence merge into one marker', () => {
  // raw form present AND decodable bytes around it -> both scans hit the same span
  const { value, findings } = redactString('a dvaa-admin-secret%20b', { canaries: [HT3] });
  assert.match(value, /^a \[REDACTED:canary:HT:sha256=[0-9a-f]{16}\]%20b$/);
  assert.equal(findings.length, 1);
});

test('B3: near-miss selectively-encoded strings are NOT redacted (no over-match)', () => {
  for (const s of ['q=dvaa%2Dadmin%2Dsecreu', 'q=%64vaa-admin-secre', 'q=%64vaa-admin-sec%72e']) {
    const { value, findings } = redactString(s, { canaries: [HT3] });
    assert.equal(value, s, `over-redacted ${s}`);
    assert.equal(findings.length, 0, s);
  }
  // "[" between parts is a separator: still the canary (separator-split form), still redacted
  assert.deepEqual(canaryLeaks(redactString('q=dvaa%2Dadmin%2D%5Bsecret', { canaries: [HT3] }).value), []);
});

test('B3: forged-wrapper variants (%5B / %5b / literal / %3A) cannot hide a selectively-encoded canary', () => {
  for (const s of FORGED_PARTIAL) {
    const { value, findings } = redactString(s, { canaries: [HT3] });
    assert.deepEqual(canaryLeaks(value), [], `${s} leaked: ${value}`);
    assert.ok(findings.some((f) => f.canaryId === 'HT'), s);
  }
});

test('B3: data-rich — selectively-encoded canaries beyond 8 KB of a 300-row tool output are all redacted', () => {
  const variants = [...PARTIAL, ...FORGED_PARTIAL];
  const rows = richRows((i) => `GET https://collector.example.test/in?${variants[i % variants.length].slice(2)}&n=${i}`);
  const { value, findings } = redactDeep({ rows }, { canaries: [HT3] });
  const out = value.rows.join('\n');
  assert.deepEqual(canaryLeaks(out), [], 'canary leaked from rich output');
  assert.equal(findings.filter((f) => f.canaryId === 'HT').length, rows.filter((r) => r.includes('collector')).length);
});

test('B3: data-rich — one large (>8 KB both sides) tool output string with the canary in the middle', () => {
  const pad = (k) => Array.from({ length: 200 }, (_, i) => `row ${k}${i}: status=ok note=${'n'.repeat(40)}`).join('\n');
  const s = `${pad('a')}\nfetch https://x.example.test/?d=d%76aa%2Dadmin-secret&z=1\n${pad('b')}`;
  assert.ok(s.indexOf('d%76aa') > 8 * 1024 && s.length - s.indexOf('d%76aa') > 8 * 1024);
  const { value } = redactString(s, { canaries: [HT3] });
  assert.deepEqual(canaryLeaks(value), []);
  assert.equal(value.length - s.length, value.match(/\[REDACTED:canary:HT:[^\]]*\]/)[0].length - 'd%76aa%2Dadmin-secret'.length);
});

test('B3: real seam — buildAlert never carries a selectively %-encoded canary (verdict canary)', () => {
  const v = makeVerdict('honeytoken_exfil', 4, { canary: HT3 });
  assert.ok(v.entities.sink && v.entities.toolCall, 'honeytoken_exfil verdicts carry a sink + tool call');
  v.entities.sink.destination = 'https://collector.example.test/in?k=%64vaa%2Dadmin-secret';
  v.entities.toolCall.argsPreview = '{"url":"https://c.example.test/?q=dvaa%2Dadmin%2Dsecret"}';
  v.evidence = 'tool output: ' + 'x'.repeat(9000) + ' leaked q=%5BREDACTED:d%76aa-admin-secret%5D ' + 'y'.repeat(9000);
  const a = buildAlert(v, warnSink());
  assert.deepEqual(canaryLeaks(JSON.stringify(a)), []);
  assert.ok(a.Redactions.ByKind.canary >= 1, JSON.stringify(a.Redactions));
});
