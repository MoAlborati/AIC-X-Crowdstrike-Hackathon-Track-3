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
