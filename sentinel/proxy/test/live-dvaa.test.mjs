// Live-seam test: real CLI process -> real DVAA agent container. Skipped (loudly) when DVAA is not
// reachable. Set SENTINEL_LIVE_DVAA_PORT to choose the agent (default RAGBot 7005), or
// SENTINEL_REQUIRE_DVAA=1 to turn a missing DVAA into a failure instead of a skip.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline';
import { post, readCapture, bigRequestWithMiddleSignal } from './helpers.mjs';

const DVAA_PORT = Number(process.env.SENTINEL_LIVE_DVAA_PORT ?? 7005);
const CLI = join(dirname(fileURLToPath(import.meta.url)), '..', 'cli.mjs');

async function dvaaUp() {
  try {
    const r = await fetch(`http://127.0.0.1:${DVAA_PORT}/health`, { signal: AbortSignal.timeout(1500) });
    return r.ok;
  } catch { return false; }
}

async function startCli(mode, flag) {
  const dir = mkdtempSync(join(tmpdir(), 'sentinel-live-'));
  const cfgPath = join(dir, 'cfg.json');
  const capture = join(dir, 'capture.jsonl');
  writeFileSync(cfgPath, JSON.stringify({
    listen: { host: '127.0.0.1', port: 0 },
    target: { host: '127.0.0.1', port: DVAA_PORT },
    mode,
    limits: {
      maxRequestBytes: 1048576, maxResponseBytes: 8388608, upstreamTimeoutMs: 10000,
      inspectorTimeoutMs: 5000, clientTimeoutMs: 30000, maxInFlight: 64,
    },
    capture: { path: capture, maxFileBytes: 536870912 },
    inspect: { flagSubstrings: flag ? [flag] : [] },
  }));
  const child = spawn(process.execPath, [CLI, '--config', cfgPath], { stdio: ['ignore', 'pipe', 'pipe'] });
  const first = await new Promise((resolve, reject) => {
    const rl = createInterface({ input: child.stdout });
    rl.once('line', (l) => resolve(JSON.parse(l)));
    child.once('exit', (code) => reject(new Error(`cli exited ${code}`)));
  });
  return { child, port: first.port, capture, stop: () => new Promise((r) => { child.once('exit', r); child.kill('SIGTERM'); }) };
}

// DVAA stamps id/created with Date.now(); everything else must match exactly.
const normalise = (buf) => {
  const j = JSON.parse(buf);
  delete j.id; delete j.created;
  return j;
};

test(`live DVAA :${DVAA_PORT} — observe mode returns the agent response unchanged; >8KB logged in full`, async (t) => {
  if (!(await dvaaUp())) {
    if (process.env.SENTINEL_REQUIRE_DVAA === '1') assert.fail(`DVAA not reachable on :${DVAA_PORT}`);
    t.skip(`DVAA not reachable on :${DVAA_PORT} — start it (docker compose up) to run the live seam`);
    return;
  }
  const cli = await startCli('observe');
  try {
    const reqBody = bigRequestWithMiddleSignal('please summarise the knowledge base', 40 * 1024);
    const raw = Buffer.from(JSON.stringify(reqBody));
    const direct = await post(`http://127.0.0.1:${DVAA_PORT}/v1/chat/completions`, raw);
    const via = await post(`http://127.0.0.1:${cli.port}/v1/chat/completions`, raw);
    assert.equal(via.status, direct.status);
    assert.deepEqual(normalise(via.body), normalise(direct.body));
    await new Promise((r) => setTimeout(r, 100));
    const ex = readCapture(cli.capture).find((x) => x.type === 'exchange');
    assert.equal(ex.request.body.data, raw.toString('utf8'));
    assert.equal(ex.response.body.data, via.body.toString('utf8'));
    assert.equal(ex.target, `127.0.0.1:${DVAA_PORT}`);
  } finally { await cli.stop(); }
});

test(`live DVAA :${DVAA_PORT} — block mode refuses a flagged request before it reaches the agent`, async (t) => {
  if (!(await dvaaUp())) {
    if (process.env.SENTINEL_REQUIRE_DVAA === '1') assert.fail(`DVAA not reachable on :${DVAA_PORT}`);
    t.skip(`DVAA not reachable on :${DVAA_PORT}`);
    return;
  }
  const flag = 'sk-sentinel-HONEY-live-0001';
  const cli = await startCli('block', flag);
  try {
    const r = await post(`http://127.0.0.1:${cli.port}/v1/chat/completions`, bigRequestWithMiddleSignal(flag, 40 * 1024));
    assert.equal(r.status, 403);
    assert.equal(JSON.parse(r.body).sentinel.reason, 'flagged_request');
    const ok = await post(`http://127.0.0.1:${cli.port}/v1/chat/completions`, { model: 'x', messages: [{ role: 'user', content: 'hello' }] });
    assert.equal(ok.status, 200);
    assert.match(JSON.parse(ok.body).choices[0].message.content, /\S/);
  } finally { await cli.stop(); }
});
