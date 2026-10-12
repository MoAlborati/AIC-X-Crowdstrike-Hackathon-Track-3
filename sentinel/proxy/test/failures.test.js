// Failure-mode tests: inspector crash/timeout/contract, upstream timeout/unreachable, overload, sink failure.
// The proxy runs for real; only DEPENDENCIES are stubbed (a misbehaving inspector, a hanging/closed
// upstream port, a failing sink). The happy-path upstream is the real DVAA RAGBot.
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { RAGBOT_PORT, closedPort, post, readCapture, requireDvaa, startHangingUpstream, startProxy } from './helpers.js';
import { decodeBody } from '../sink.js';

const benign = () => readCapture('benign/7005_ragbot.req.json');

const throwing = { name: 'throws', inspectRequest: () => { throw new Error('detector exploded'); } };
const rejecting = { name: 'rejects', inspectResponse: async () => { throw new Error('async detector exploded'); } };
const hanging = { name: 'hangs', inspectRequest: () => new Promise(() => {}) };
const malformed = { name: 'malformed', inspectRequest: () => ({ action: 'maybe' }) };

before(async () => {
  await requireDvaa(RAGBOT_PORT, 'RAGBot');
});

describe('inspector failure: fail-closed in block mode, loud in observe mode', () => {
  for (const [label, inspector, phase] of [
    ['throws (request)', throwing, 'request'],
    ['rejects (response)', rejecting, 'response'],
    ['times out (request)', hanging, 'request'],
    ['returns a malformed Decision (request)', malformed, 'request'],
  ]) {
    it(`block mode: inspector that ${label} → 503 inspector_failed + ALERT`, async () => {
      const p = await startProxy({ patch: { mode: 'block', limits: { inspectorTimeoutMs: 50 } }, inspector });
      try {
        const res = await post(p.url, benign());
        assert.equal(res.status, 503);
        assert.equal(res.json.error.code, 'inspector_failed');
        assert.equal(res.json.sentinel.phase, phase);
        const loud = p.logs.find((l) => l.event === 'inspector_failed');
        assert.equal(loud.level, 'ALERT');
        assert.equal(loud.action, 'deny');
        const [rec] = p.records();
        assert.equal(rec.outcome.action, 'blocked');
        assert.equal(rec.inspector[phase].failClosed, true);
        if (phase === 'request') assert.equal(rec.response, null, 'fail-closed request must not reach DVAA');
      } finally {
        await p.close();
      }
    });

    it(`observe mode: inspector that ${label} → forwarded unchanged + loud ALERT log`, async () => {
      const p = await startProxy({ patch: { mode: 'observe', limits: { inspectorTimeoutMs: 50 } }, inspector });
      try {
        const res = await post(p.url, benign());
        assert.equal(res.status, 200);
        const loud = p.logs.find((l) => l.event === 'inspector_failed');
        assert.equal(loud.level, 'ALERT');
        assert.equal(loud.action, 'forward');
        const [rec] = p.records();
        assert.ok(decodeBody(rec.response.body).equals(res.body));
        assert.equal(rec.inspector[phase].ok, false);
      } finally {
        await p.close();
      }
    });
  }

  it('the timeout bound is enforced: a hung inspector is cut off near inspectorTimeoutMs', async () => {
    const p = await startProxy({ patch: { mode: 'block', limits: { inspectorTimeoutMs: 80 } }, inspector: hanging });
    try {
      const t0 = performance.now();
      await post(p.url, benign());
      const ms = performance.now() - t0;
      assert.ok(ms >= 75 && ms < 1000, `expected ~80ms, took ${ms}`);
      assert.equal(p.records()[0].inspector.request.failure.kind, 'timeout');
    } finally {
      await p.close();
    }
  });
});

describe('inspector isolation', () => {
  it('an inspector that mutates ctx.body / ctx.headers cannot change what is forwarded or returned', async () => {
    const vandal = {
      name: 'vandal',
      inspectRequest(ctx) {
        ctx.body.fill(0x41);
        ctx.headers['content-type'] = 'text/plain';
      },
      inspectResponse(ctx) {
        ctx.response.body.fill(0x42);
      },
    };
    const p = await startProxy({ inspector: vandal });
    try {
      const body = benign();
      const res = await post(p.url, body);
      assert.equal(res.status, 200);
      assert.equal(res.json.model, 'ragbot');
      const [rec] = p.records();
      assert.ok(decodeBody(rec.request.body).equals(body));
      assert.ok(decodeBody(rec.response.body).equals(res.body));
    } finally {
      await p.close();
    }
  });
});

describe('upstream failures', () => {
  it('upstream that never answers → 504 upstream_timeout after upstreamTimeoutMs, loud', async () => {
    const up = await startHangingUpstream();
    const p = await startProxy({ patch: { target: { port: up.port }, limits: { upstreamTimeoutMs: 150 } } });
    try {
      const res = await post(p.url, benign());
      assert.equal(res.status, 504);
      assert.equal(res.json.error.code, 'upstream_timeout');
      assert.equal(p.logs.find((l) => l.event === 'upstream_timeout').level, 'ALERT');
      assert.ok(p.records()[0].timings.upstreamMs >= 145);
    } finally {
      await p.close();
      await up.close();
    }
  });

  it('nothing listening on the target port → 502 upstream_unreachable, loud', async () => {
    const port = await closedPort();
    const p = await startProxy({ patch: { target: { port } } });
    try {
      const res = await post(p.url, benign());
      assert.equal(res.status, 502);
      assert.equal(res.json.error.code, 'upstream_unreachable');
      assert.match(p.logs.find((l) => l.event === 'upstream_unreachable').message, /ECONNREFUSED/);
    } finally {
      await p.close();
    }
  });
});

describe('overload + routing', () => {
  it('maxInFlight: the request past the cap is rejected 503 with {size, cap, action}', async () => {
    const up = await startHangingUpstream();
    const p = await startProxy({ patch: { target: { port: up.port }, limits: { maxInFlight: 1, upstreamTimeoutMs: 1000 } } });
    try {
      const first = post(p.url, benign());
      await new Promise((r) => setTimeout(r, 100));
      const second = await post(p.url, benign());
      assert.equal(second.status, 503);
      assert.equal(second.json.error.code, 'proxy_overloaded');
      assert.deepEqual([second.json.sentinel.details.size, second.json.sentinel.details.cap, second.json.sentinel.details.action], [2, 1, 'reject']);
      assert.equal((await first).status, 504);
    } finally {
      await p.close();
      await up.close();
    }
  });

  it('non-inspected routes are not forwarded (no uninspected bypass)', async () => {
    const p = await startProxy();
    try {
      const res = await post(p.url, benign(), { path: '/v1/completions' });
      assert.equal(res.status, 404);
      assert.equal(res.json.error.code, 'route_not_proxied');
      assert.equal(p.records().length, 0);
    } finally {
      await p.close();
    }
  });
});

describe('capture sink failure', () => {
  const brokenSink = { path: '/dev/null/broken', write: () => { throw new Error('ENOSPC: no space left on device'); } };

  it('block mode: a forwarded reply that cannot be captured is refused (503 capture_failed) — no unaudited delivery', async () => {
    const p = await startProxy({ patch: { mode: 'block' }, sink: brokenSink });
    try {
      const res = await post(p.url, benign());
      assert.equal(res.status, 503);
      assert.equal(res.json.error.code, 'capture_failed');
      assert.equal(p.logs.find((l) => l.event === 'sink_write_failed').level, 'ALERT');
    } finally {
      await p.close();
    }
  });

  it('observe mode: reply is delivered, and the lost capture is logged loudly', async () => {
    const p = await startProxy({ patch: { mode: 'observe' }, sink: brokenSink });
    try {
      const res = await post(p.url, benign());
      assert.equal(res.status, 200);
      const loud = p.logs.find((l) => l.event === 'sink_write_failed');
      assert.equal(loud.level, 'ALERT');
      assert.equal(loud.action, 'deliver-unaudited');
    } finally {
      await p.close();
    }
  });
});
