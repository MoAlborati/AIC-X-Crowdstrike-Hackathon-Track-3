// Cumulative caps (velocity / anti-structuring) over a bounded session+tool ledger.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDetector, LedgerFullError } from '../index.js';
import { response, toolCall, quietLogger } from './helpers.js';

const user = (c) => ({ messages: [{ role: 'user', content: c }] });

test('structuring: N calls each just under the single-call byte cap -> HOLD on the Nth', () => {
  const det = createDetector({ toolExecution: 'client', policy: { allowlist: { hosts: ['api.example.test'] }, tools: { http_post: { maxArgBytes: 1000, structuringThreshold: 3 } } }, logger: quietLogger() });
  const call = (i) => response([toolCall(`c${i}`, 'http_post', { url: 'https://api.example.test/x', body: 'a'.repeat(900) })]);
  assert.equal(det.inspect({ sessionId: 'st', request: user('sync'), response: call(1) }).action, 'allow');
  assert.equal(det.inspect({ sessionId: 'st', request: user('sync'), response: call(2) }).action, 'allow');
  const d = det.inspect({ sessionId: 'st', request: user('sync'), response: call(3) });
  assert.equal(d.action, 'block');
  const f = d.findings.find((x) => x.reason === 'structuring');
  assert.equal(f.enforcement, 'hold');
  assert.equal(f.ruleId, 'velocity.cumulative_cap');
  assert.equal(f.proposedCategory, 'cumulative_cap_exceeded');
  // a different session is unaffected (per session+tool)
  assert.equal(det.inspect({ sessionId: 'other', request: user('sync'), response: call(1) }).action, 'allow');
});

test('count, bytes and summed-amount velocity caps', () => {
  const det = createDetector({
    policy: { allowlist: { hosts: ['pay.test'] }, tools: { make_payment: { maxCallsPerSession: 3, maxAmountPerSession: 250 } } },
    logger: quietLogger(),
  });
  const pay = (i, amt) => det.inspect({ sessionId: 'v', request: user('Pay up to $100 each to https://pay.test'), response: response([toolCall(`p${i}`, 'make_payment', { url: 'https://pay.test', amount: amt })]) });
  assert.equal(pay(1, 100).action, 'allow');
  assert.equal(pay(2, 100).action, 'allow');
  const third = pay(3, 100);
  assert.ok(third.findings.some((f) => f.reason === 'velocity_amount'), JSON.stringify(third.findings.map((f) => f.reason)));
  const fourth = pay(4, 10);
  assert.ok(fourth.findings.some((f) => f.reason === 'velocity_calls'));
});

test('ledger is bounded: too many distinct tools in one session -> LedgerFullError -> fail closed + ERROR log', () => {
  const logger = quietLogger();
  const det = createDetector({ toolExecution: 'client', bounds: { maxLedgerKeysPerSession: 5 }, logger });
  const calls = Array.from({ length: 6 }, (_, i) => toolCall(`c${i}`, `lookup_${i}`, {}));
  const d = det.inspect({ sessionId: 'big', request: user('look things up'), response: response(calls) });
  assert.equal(d.failClosed, true);
  assert.equal(d.action, 'block');
  assert.equal(d.error.error, 'LedgerFullError');
  assert.deepEqual([logger.errors[0].payload_size, logger.errors[0].cap, logger.errors[0].action], [6, 5, 'block']);
});

test('session store is bounded: full of live sessions -> fail closed; idle sessions past TTL are evicted', () => {
  let t = 0;
  const logger = quietLogger();
  const det = createDetector({ toolExecution: 'client', bounds: { maxSessions: 3, sessionTtlMs: 1000 }, now: () => t, logger });
  // Only exchanges with tool calls allocate a stored session (B2); these record a lookup in the ledger.
  const rec = () => response([toolCall('c', 'lookup', {})]);
  for (const s of ['a', 'b', 'c']) assert.equal(det.inspect({ sessionId: s, request: user('hi'), response: rec() }).failClosed, false);
  const full = det.inspect({ sessionId: 'd', request: user('hi'), response: rec() });
  assert.equal(full.failClosed, true);
  assert.equal(full.error.bound, 'maxSessions');
  assert.ok(full.error instanceof Object && !(full.error instanceof LedgerFullError));
  t += 1001;
  assert.equal(det.inspect({ sessionId: 'd', request: user('hi'), response: rec() }).failClosed, false);
  // Plain chat (no tool calls) never needs a stored session, so a full store cannot fail it closed (B2).
  for (const s of ['e', 'f', 'g', 'h']) det.inspect({ sessionId: s, request: user('hi'), response: rec() });
  assert.equal(det.inspect({ sessionId: 'z', request: user('hi'), response: response([]) }).failClosed, false);
});
