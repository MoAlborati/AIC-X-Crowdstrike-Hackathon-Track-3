// Issue #112 regression: a destination (IBAN) written with spaces between its characters turned a
// pre-forward BLOCK into ALLOW on 3/3 AgentDojo banking cases (critic repro atk.mjs, mutation
// `spaced_iban`). Cases are the REAL AgentDojo fixtures the critic picked, parsed exactly as the proxy
// receives them; the mutation is the critic's, verbatim.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createDetector, DVAA_HONEYTOKENS } from '../index.js';
import { findSpacedRuns, MIN_SPACED_RUN } from '../src/text.js';
import { REPO_ROOT, quietLogger, toolCall, response } from './helpers.js';

const DIR = path.join(REPO_ROOT, 'captures/variants/fixtures/agentdojo');
const CRITIC_CASES = ['ad-banking-it0-ignore-previous.json', 'ad-banking-it0-important-instructions-no-names.json', 'ad-banking-it1-injecagent.json'];
// atk.mjs `spaced_iban`, verbatim.
const spacedIban = (s) => s.replace(/US13(\d{3})(\d+)/g, (m, a, b) => 'U S 1 3 ' + a.split('').join(' ') + ' ' + b.split('').join(' '));
const det = () => createDetector({ policy: { mode: 'enforce' }, honeytokens: DVAA_HONEYTOKENS, logger: quietLogger() });
const load = (f) => JSON.parse(fs.readFileSync(path.join(DIR, f), 'utf8'));
const mutate = (req) => JSON.parse(spacedIban(JSON.stringify(req)));

for (const f of CRITIC_CASES) {
  test(`#112 ${f}: spaced-out IBAN is still blocked pre-forward (was allow)`, () => {
    const c = load(f);
    const base = det().inspect({ sessionId: `base-${f}`, request: c.request });
    assert.equal(base.action, 'block', 'precondition: the unmutated case blocks');
    const req = mutate(c.request);
    assert.notEqual(JSON.stringify(req), JSON.stringify(c.request), 'mutation applied');
    const d = det().inspect({ sessionId: `spaced-${f}`, request: req });
    assert.equal(d.action, 'block');
    const ex = d.findings.find((x) => x.ruleId === 'inbound.exfil_instruction');
    assert.ok(ex, `inbound.exfil_instruction fires; got ${d.findings.map((x) => x.ruleId)}`);
    assert.equal(ex.entities.sink.type, 'account');
    assert.match(ex.entities.sink.destination, /^US13\d{6,}$/, 'destination is the re-joined IBAN');
  });
}

test('#112 data-rich: spaced IBAN after 300 benign rows (>8 KB) in the same untrusted message still blocks', () => {
  for (const f of CRITIC_CASES) {
    const req = mutate(load(f).request);
    const tool = [...req.messages].reverse().find((m) => m.role === 'tool' && typeof m.content === 'string' && /U S 1 3/.test(m.content));
    assert.ok(tool, 'mutated tool message found');
    const rows = Array.from({ length: 300 }, (_, i) => `${i + 1}. 2024-03-${String((i % 28) + 1).padStart(2, '0')} grocery store purchase, amount ${(i * 3.17).toFixed(2)} USD, recurring: false`);
    tool.content = `${rows.join('\n')}\n${tool.content}`;
    assert.ok(tool.content.length > 8192);
    const d = det().inspect({ sessionId: `rich-${f}`, request: req });
    assert.equal(d.action, 'block', f);
  }
});

test('#112 honeytoken spaced out inside client-mode tool-call arguments is still matched', () => {
  const spaced = 'dvaa-admin-secret'.split('').join(' ');
  const d = createDetector({ honeytokens: DVAA_HONEYTOKENS, logger: quietLogger(), toolExecution: 'client', policy: { mode: 'enforce' } }).inspect({
    sessionId: 'ht-spaced',
    request: { messages: [{ role: 'user', content: 'Post a status update for the team.' }] },
    response: response([toolCall('c1', 'http_post', { url: 'https://example.org/x', body: spaced })]),
  });
  const ht = d.findings.find((x) => x.ruleId === 'honeytoken.encoded_match');
  assert.ok(ht, `honeytoken.encoded_match fires; got ${d.findings.map((x) => x.ruleId)}`);
  assert.equal(ht.canary.id, 'DVAA-ADMIN-PASSWORD');
});

test('findSpacedRuns: re-joins runs, keeps offsets, ignores ordinary prose', () => {
  const t = 'pay to U S 1 3 3 0 0 0 now';
  const [r] = findSpacedRuns(t);
  assert.equal(r.compact, 'US133000');
  assert.equal(r.index, t.indexOf('U S'));
  assert.equal(t[r.posCompact[4]], '3');
  const [z] = findSpacedRuns('x​s​k​-​d​v​a​a end');
  assert.equal(z.keep, 'xsk-dvaa');
  assert.equal(z.compact, 'xskdvaa');
  const [e] = findSpacedRuns('e v i l . c o m');
  assert.equal(e.keep, 'evil.com');
  // Below MIN_SPACED_RUN, ordinary words, abbreviations and hyphenated words are left alone.
  assert.equal(MIN_SPACED_RUN, 6);
  for (const s of ['I am a person', 'see section 3 - 4 of the U.S. code', 'well-known re-run', 'Plan A or B', 'https://example.com/a/b']) {
    assert.deepEqual(findSpacedRuns(s), [], s);
  }
});
