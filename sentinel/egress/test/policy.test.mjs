// T12 — egress policy over the REAL T4 redact.js matcher + REAL buildAlert (no mocks of the feature).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  inspectEgress, loadHoneytokens, makeAllowlist, decodedViews, REASON_CODES, DEFAULTS,
} from '../policy.mjs';
import { validateAlert } from '../../alerts/schema.js';
import { defaultHoneytokens } from '../inspector.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RAW_TOKENS = defaultHoneytokens();
const HT = loadHoneytokens(RAW_TOKENS);
const STATIC = new Set(Object.values(REASON_CODES));
const cfg = (mode = 'block', allow = ['canary']) => ({ mode, allow: makeAllowlist(allow), honeytokens: HT });
const http = (url, body, host = new URL(url).hostname) =>
  ({ kind: 'http', method: body ? 'POST' : 'GET', url, host, body: body ? Buffer.from(body) : undefined });
const noSecrets = (v) => {
  const s = JSON.stringify(v);
  for (const t of RAW_TOKENS) assert.ok(!s.includes(t.value), `verdict/alert leaked honeytoken ${t.id}`);
};

test('every DVAA planted honeytoken is caught raw, %-encoded, double-%-encoded, +-form and base64', () => {
  for (const t of RAW_TOKENS) {
    const forms = [
      t.value,
      encodeURIComponent(t.value),
      [...Buffer.from(t.value)].map((b) => '%' + b.toString(16).padStart(2, '0')).join(''), // every byte %XX
      encodeURIComponent(encodeURIComponent(t.value)),
      Buffer.from(t.value).toString('base64'),
    ];
    for (const f of forms) {
      const v = inspectEgress(http(`http://canary:8080/x?d=${f}`), cfg());
      assert.ok(v.reasons.includes(REASON_CODES.HONEYTOKEN_MATCH), `${t.id} form ${f.slice(0, 40)}`);
      assert.ok(v.canaryIds.includes(t.id));
      assert.equal(v.action, 'deny');
      noSecrets(v);
    }
  }
});

test('reasons are static codes only; alerts are valid T4 alerts with direction egress and no secret values', () => {
  const v = inspectEgress(http('http://evil.example:9/api/canary/exfil-test?data=Admin%20credentials%3A%20dvaa-admin-secret%20%7C%20SSN%3A%20123-45-6789'), cfg('block', []));
  assert.equal(v.direction, 'egress');
  assert.equal(v.detector, 'sentinel-egress');
  assert.deepEqual(v.reasons.sort(), ['destination_not_allowlisted', 'honeytoken_match', 'secret_pattern_match']);
  for (const r of v.reasons) assert.ok(STATIC.has(r) && !r.includes(':'), r);
  assert.deepEqual(validateAlert(v.alertDoc), []);
  assert.equal(v.alertDoc.DetectName, 'HoneytokenExfiltrationAttempt');
  assert.equal(v.alertDoc.PatternDispositionDescription, 'Blocked');
  assert.equal(v.alertDoc.Canary.Id, 'DVAA-ADMIN-PASSWORD');
  assert.ok(!JSON.stringify(v.alertDoc).includes('data='), 'query string never copied into the alert');
  noSecrets(v);
});

test('observe mode forwards policy hits but alerts them as Allowed', () => {
  const v = inspectEgress(http('http://canary:8080/x?d=dvaa-admin-secret'), cfg('observe'));
  assert.equal(v.action, 'forward');
  assert.equal(v.alertDoc.PatternDispositionDescription, 'Allowed');
});

test('destination allowlist: exact host only; benign allowlisted egress is not flagged', () => {
  assert.equal(inspectEgress(http('http://canary:8080/api/x?q=weather&ts=1728760000000'), cfg()).flagged, false);
  for (const h of ['canary.evil.example', 'evilcanary', 'CANARY2']) {
    const v = inspectEgress(http(`http://${h}/x`), cfg());
    assert.deepEqual(v.reasons, ['destination_not_allowlisted']);
    assert.equal(v.action, 'deny');
  }
  const c = inspectEgress({ kind: 'connect', method: 'CONNECT', url: 'api.oa2a.org:443', host: 'api.oa2a.org' }, cfg());
  assert.equal(c.action, 'deny');
  assert.equal(c.alertDoc.Entities.Sink.Type, 'connect_tunnel');
});

test('data-rich: 12 KiB body with the honeytoken AFTER the first 8 KiB is caught (full-payload scan)', () => {
  const body = 'x'.repeat(9000) + ' dvaa-admin-secret ' + 'y'.repeat(3000);
  assert.ok(body.length > 12000 && body.indexOf('dvaa-admin-secret') > 8192);
  const v = inspectEgress(http('http://canary:8080/upload', body), cfg());
  assert.ok(v.reasons.includes('honeytoken_match'));
  assert.equal(v.bodyBytes, body.length);
});

test('data-rich: 300-row tool output with one honeytoken row at 287 is caught; clean 300 rows pass', () => {
  const rows = Array.from({ length: 300 }, (_, i) => `${i},user${i},user${i}@example.com,ok`);
  assert.equal(inspectEgress(http('http://canary:8080/rows', rows.join('\n')), cfg()).flagged, false);
  rows[287] = '287,Jane Smith,jane@example.com,987-65-4321';
  const v = inspectEgress(http('http://canary:8080/rows', rows.join('\n')), cfg());
  assert.deepEqual(v.canaryIds, ['DVAA-SSN-JANE']);
  assert.equal(v.action, 'deny');
});

test('data-rich: 20 KiB URL (over Node\'s 16 KiB default header limit) with the token past 16 KiB is caught', () => {
  const url = 'http://canary:8080/' + 'p'.repeat(20000) + '/api/canary/exfil-test?data=sk-ant-dvaa-test-anthropic-key-67890';
  assert.ok(url.length > 16384 && url.indexOf('sk-ant') > 16384);
  const v = inspectEgress(http(url), cfg());
  assert.deepEqual(v.canaryIds, ['DVAA-ANTHROPIC-KEY']);
});

test('fail-closed: over-cap payload denies in OBSERVE mode, is never scanned partially, and alerts loudly', () => {
  const v = inspectEgress({ ...http('http://canary:8080/u', 'z'), size: DEFAULTS.MAX_EGRESS_BYTES + 1 }, cfg('observe'));
  assert.equal(v.action, 'deny');
  assert.ok(v.failClosed);
  assert.deepEqual(v.reasons, ['egress_over_cap']);
  assert.equal(v.alertDoc.DetectName, 'ScanCapExceeded');
  assert.equal(v.alertDoc.RuleId, 'egress.failclosed.egress_over_cap');
});

test('fail-closed: scan error and scan time-budget overrun deny in observe mode', () => {
  const e = inspectEgress(http('http://canary:8080/u'), { ...cfg('observe'), faults: { scan: 'error' } });
  assert.deepEqual([e.action, e.reasons], ['deny', ['scan_error']]);
  const s = inspectEgress(http('http://canary:8080/u'), { ...cfg('observe'), scanBudgetMs: 5, faults: { scan: 'slow' } });
  assert.equal(s.action, 'deny');
  assert.ok(s.reasons.includes('scan_timeout'));
});

test('fail-closed: %-encoding nested deeper than MAX_DECODE_ROUNDS denies', () => {
  let s = [...Buffer.from('dvaa-admin-secret')].map((b) => '%' + b.toString(16).padStart(2, '0')).join('');
  for (let i = 0; i < DEFAULTS.MAX_DECODE_ROUNDS + 1; i++) s = encodeURIComponent(s);
  assert.equal(decodedViews(s).overDepth, true);
  const v = inspectEgress(http(`http://canary:8080/x?d=${s}`), cfg('observe'));
  assert.equal(v.action, 'deny');
  assert.ok(v.reasons.includes('decode_depth_exceeded'));
});

test('#12 gap: double-%-encoded and \\u-escaped canaries in a URL query are caught (bounded iterative decode)', () => {
  const tok = 'sk-dvaa-openai-test-key-do-not-use-in-production-12345';
  const pctAll = [...Buffer.from(tok)].map((b) => '%' + b.toString(16).padStart(2, '0')).join('');
  const uEsc = [...tok].map((c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join('');
  const forms = {
    double_pct: encodeURIComponent(pctAll), // %2573%256b... -> %73%6b... -> sk...
    u_escaped: uEsc, // \u0073\u006b...
    u_escaped_in_json: encodeURIComponent(JSON.stringify({ k: uEsc })),
    pct_encoded_u_escape: encodeURIComponent(uEsc), // %5Cu0073... (mixed: 2 rounds)
    x_escaped: [...tok].map((c) => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0')).join(''),
  };
  for (const [name, f] of Object.entries(forms)) {
    const v = inspectEgress(http(`http://canary:8080/x?q=hello&d=${f}&z=1`), cfg('block'));
    assert.ok(v.reasons.includes('honeytoken_match'), name);
    assert.deepEqual(v.canaryIds, ['DVAA-OPENAI-KEY'], name);
    assert.equal(v.action, 'deny', name);
    noSecrets(v);
  }
});

test('#18 review (2): canary inside a larger base64 blob is caught at every byte offset (0, 1, 2)', () => {
  for (const tok of ['dvaa-admin-secret', 'sk-dvaa-openai-test-key-do-not-use-in-production-12345']) {
    for (let off = 0; off < 3; off++) {
      const blob = Buffer.from('P'.repeat(off) + 'report rows: ' + 'r,'.repeat(200) + tok + ' end of export').toString('base64');
      for (const where of [`?d=${blob}`, `?d=${encodeURIComponent(blob)}`]) {
        const v = inspectEgress(http(`http://canary:8080/x${where}`), cfg('block'));
        assert.ok(v.reasons.includes('honeytoken_match'), `offset ${off} ${where.slice(0, 12)}`);
      }
      const b = inspectEgress(http('http://canary:8080/x', JSON.stringify({ attachment: blob })), cfg('block'));
      assert.ok(b.reasons.includes('honeytoken_match'), `body offset ${off}`);
    }
  }
});

test('generic secret patterns are evidence only (never deny allowlisted traffic on their own)', () => {
  const v = inspectEgress(http('http://canary:8080/x?k=ghp_' + 'aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6'), cfg());
  assert.deepEqual(v.reasons, ['secret_pattern_match']);
  assert.equal(v.action, 'forward');
});

test('honeytoken registry is bounded and validated (fail loud on load)', () => {
  assert.throws(() => loadHoneytokens([{ id: 'x', value: 'abc' }]), /shorter than/);
  assert.throws(() => loadHoneytokens(Array.from({ length: DEFAULTS.MAX_HONEYTOKENS + 1 }, (_, i) => ({ id: `t${i}`, value: `token-${i}-xyz` }))), new RegExp(`cap ${DEFAULTS.MAX_HONEYTOKENS}`));
  assert.throws(() => loadHoneytokens([{ id: 'x', value: 'abcdefg' }]), /shorter than 8/);
  assert.throws(() => loadHoneytokens({}), /array/);
});

test('latency on data-rich inputs is recorded (median/p95 over 200 runs of a 60 KiB body)', () => {
  const body = 'r,'.repeat(30000) + 'dvaa-db-password-123';
  const xs = [];
  for (let i = 0; i < 200; i++) xs.push(inspectEgress(http('http://canary:8080/u', body), cfg()).latencyMs);
  xs.sort((a, b) => a - b);
  const med = xs[100], p95 = xs[190];
  console.log(`# egress scan latency 60KiB body: median=${med}ms p95=${p95}ms`);
  assert.ok(p95 < DEFAULTS.SCAN_BUDGET_MS, `p95 ${p95}ms within scan budget`);
});
