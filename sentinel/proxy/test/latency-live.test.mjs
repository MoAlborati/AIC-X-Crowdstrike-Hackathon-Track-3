// Proxy-added latency on the REAL DVAA RAGBot (median + p95), small and >8KB data-rich payloads, with the
// shipped inspector set (T2 substring + T3). Ported from the retired PR #21 test/latency.test.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { RAGBOT_PORT, requireDvaa } from './helpers.mjs';
import { measure } from '../bench/latency.mjs';

test('proxy-added latency vs live DVAA: median well under the 30ms demo budget, both payload sizes', async (t) => {
  if (!(await requireDvaa(t, RAGBOT_PORT, 'RAGBot'))) return;
  const r = await measure({ n: 100, port: RAGBOT_PORT, warmup: 10 });
  t.diagnostic(JSON.stringify(r));
  for (const [name, res] of Object.entries(r.results)) {
    assert.equal(res.proxyAddedMs.n, 100);
    assert.ok(res.proxyAddedMs.median < 30, `${name}: median proxy-added ${res.proxyAddedMs.median}ms`);
  }
  assert.ok(r.results.big.bodyBytes > 64 * 1024);
  assert.equal(r.inProcessOverheadMs.n, 2 * (100 + 10), 'one capture record per proxied call');
});
