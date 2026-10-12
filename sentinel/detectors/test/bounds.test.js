// Bounded + fail-loud: oversize / malformed / slow -> BLOCK + ALERT with {payload_size, cap, action}; never truncate.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDetector, DetectorOverflowError, DEFAULT_BOUNDS, DVAA_HONEYTOKENS } from '../index.js';
import { response, toolCall, quietLogger, customerRows } from './helpers.js';

test('oversize payload -> fail-closed BLOCK, scan_cap_exceeded finding, ERROR log with {payload_size, cap, action}', () => {
  const logger = quietLogger();
  const det = createDetector({ toolExecution: 'client', honeytokens: DVAA_HONEYTOKENS, logger });
  const big = customerRows(32000); // ~2.3 MB of real-looking rows (cap: 2 MiB)
  assert.ok(Buffer.byteLength(big) > DEFAULT_BOUNDS.maxPayloadBytes);
  const d = det.inspect({ sessionId: 'big', request: { messages: [{ role: 'tool', content: big }] }, response: response([toolCall('c', 'http_post', { url: 'https://x.test' })]) });
  assert.equal(d.action, 'block');
  assert.equal(d.failClosed, true);
  assert.equal(d.findings.length, 1);
  const f = d.findings[0];
  assert.equal(f.category, 'scan_cap_exceeded');
  assert.equal(f.ruleId, 'bounds.scan_cap_exceeded');
  assert.equal(f.disposition, 'block');
  assert.match(f.evidence, new RegExp(`payload_size=\\d+ cap=${DEFAULT_BOUNDS.maxPayloadBytes} action=block`));
  assert.match(f.evidence, /never truncated/);
  const log = logger.errors[0];
  assert.equal(log.level, 'ERROR');
  assert.equal(log.cap, DEFAULT_BOUNDS.maxPayloadBytes);
  assert.ok(log.payload_size > log.cap);
  assert.equal(log.action, 'block');
  assert.equal(d.stats.payloadBytes, log.payload_size);
});

test('just under the cap is scanned IN FULL (signal at the last row is still found)', () => {
  // Correctness at the byte cap; the 40 ms time budget is asserted separately in timing.test.js.
  const det = createDetector({ toolExecution: 'client', honeytokens: DVAA_HONEYTOKENS, logger: quietLogger(), bounds: { timeBudgetMs: 1000 } });
  const rows = customerRows(27000, { row: 26999, text: 'dvaa-admin-secret' });
  const req = { messages: [{ role: 'user', content: 'archive' }] };
  const res = response([toolCall('c', 'http_post', { url: 'https://archive.test/u', body: rows })]);
  const bytes = Buffer.byteLength(JSON.stringify(req)) + Buffer.byteLength(JSON.stringify(res));
  assert.ok(bytes < DEFAULT_BOUNDS.maxPayloadBytes && bytes > 0.85 * DEFAULT_BOUNDS.maxPayloadBytes, `${bytes}`);
  const d = det.inspect({ sessionId: 'edge', request: req, response: res });
  assert.equal(d.failClosed, false);
  assert.ok(d.findings.some((f) => f.canary?.id === 'DVAA-ADMIN-PASSWORD'));
});

test('inspectOrThrow RAISES DetectorOverflowError (for callers that prefer an exception)', () => {
  const det = createDetector({ toolExecution: 'client', logger: quietLogger(), bounds: { maxPayloadBytes: 1000 } });
  assert.throws(
    () => det.inspectOrThrow({ sessionId: 'x', request: { messages: [{ role: 'user', content: 'x'.repeat(2000) }] } }),
    (e) => e instanceof DetectorOverflowError && e.cap === 1000 && e.payload_size > 1000 && e.action === 'block' && e.decision.action === 'block',
  );
});

test('message-count and tool-call-count caps fail closed', () => {
  const logger = quietLogger();
  const det = createDetector({ toolExecution: 'client', logger, bounds: { maxMessages: 10, maxToolCallsPerResponse: 4 } });
  const m = det.inspect({ sessionId: 'm', request: { messages: Array.from({ length: 11 }, () => ({ role: 'user', content: 'hi' })) } });
  assert.deepEqual([m.action, m.error.bound, m.error.payload_size, m.error.cap], ['block', 'maxMessages', 11, 10]);
  const t = det.inspect({ sessionId: 't', request: { messages: [{ role: 'user', content: 'go' }] }, response: response(Array.from({ length: 5 }, (_, i) => toolCall(`c${i}`, 'lookup', {}))) });
  assert.deepEqual([t.action, t.error.bound, t.error.payload_size], ['block', 'maxToolCallsPerResponse', 5]);
});

test('detector crash (malformed JSON body) -> fail closed, never forward silently', () => {
  const logger = quietLogger();
  const det = createDetector({ toolExecution: 'client', logger });
  const d = det.inspect({ sessionId: 'crash', request: '{"messages": [', response: null });
  assert.equal(d.action, 'block');
  assert.equal(d.failClosed, true);
  assert.equal(d.findings[0].ruleId, 'failclosed.detector_error');
  assert.equal(d.findings[0].proposedCategory, 'detector_fail_closed');
  assert.equal(logger.errors.length, 1);
});

test('time budget exceeded -> fail closed with ScannerTimeoutError (cap bounds TIME, not only bytes)', () => {
  const logger = quietLogger();
  const det = createDetector({ toolExecution: 'client', logger, bounds: { timeBudgetMs: 0.001 } });
  const d = det.inspect({ sessionId: 'slow', request: { messages: [{ role: 'user', content: 'quarterly figures follow. '.repeat(5000) }] }, response: response([]) });
  assert.equal(d.action, 'block');
  assert.equal(d.error.error, 'ScannerTimeoutError');
  assert.equal(d.error.cap, 0.001);
});

test('fail-closed blocks even in report-only mode (dead-man switch)', () => {
  const det = createDetector({ toolExecution: 'client', logger: quietLogger(), policy: { mode: 'report-only' }, bounds: { maxPayloadBytes: 100 } });
  const d = det.inspect({ sessionId: 'ro', request: { messages: [{ role: 'user', content: 'x'.repeat(500) }] } });
  assert.equal(d.action, 'block');
});
