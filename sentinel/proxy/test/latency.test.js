// Proxy-added latency on the real DVAA RAGBot (median + p95), small and >8KB data-rich payloads.
import { it, before } from 'node:test';
import assert from 'node:assert/strict';
import { RAGBOT_PORT, requireDvaa } from './helpers.js';
import { measure } from '../bench/latency.js';

before(async () => {
  await requireDvaa(RAGBOT_PORT, 'RAGBot');
});

it('measures proxy-added latency (median + p95) and keeps the median well under the 30ms demo budget', async (t) => {
  const r = await measure({ n: 100, port: RAGBOT_PORT, warmup: 10 });
  t.diagnostic(JSON.stringify(r));
  for (const [name, res] of Object.entries(r.results)) {
    assert.equal(res.proxyAddedMs.n, 100);
    assert.ok(res.proxyAddedMs.median < 30, `${name}: median proxy-added ${res.proxyAddedMs.median}ms`);
  }
  assert.ok(r.results.big.bodyBytes > 64 * 1024);
});
