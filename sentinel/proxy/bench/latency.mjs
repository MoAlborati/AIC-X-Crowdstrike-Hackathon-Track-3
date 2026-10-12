#!/usr/bin/env node
// Proxy-added latency against the REAL DVAA agent (default RAGBot :7005).
//   node sentinel/proxy/bench/latency.mjs [--n 300] [--port 7005]
// Interleaves direct and proxied calls (same keep-alive client settings) so DVAA load drifts hit both
// equally, then reports median/p95 for direct, proxied, and the paired difference (proxy-added).
// Also reports the proxy's own in-process overhead (record.timings.proxy_overhead_ms = total − upstream).
// The proxy runs the SHIPPED inspector set (T2 substring + T3), so the numbers include detection time.

import http from 'node:http';
import { readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createProxy } from '../server.mjs';
import { loadConfig } from '../../config/load.mjs';
import { buildDefaultInspectors } from '../default-inspectors.mjs';

function summarize(samples) {
  const s = [...samples].sort((a, b) => a - b);
  const q = (p) => s[Math.min(s.length - 1, Math.max(0, Math.ceil(p * s.length) - 1))];
  return { n: s.length, median: q(0.5), p95: q(0.95), max: s.at(-1) };
}

const CAPTURES = fileURLToPath(new URL('../../../captures/', import.meta.url));

export function payloads() {
  const benign = readFileSync(join(CAPTURES, 'benign/7005_ragbot.req.json'));
  const kb = readFileSync(join(CAPTURES, 'variants/corpus/benign-kb-long.md'), 'utf8');
  const rows = readFileSync(join(CAPTURES, 'variants/corpus/benign-toolrows-400.json'), 'utf8');
  const big = Buffer.from(JSON.stringify({ messages: [{ role: 'user', content: `${kb}\n${rows}\nSummarize.` }] }));
  return { benign, big };
}

function timedPost(agent, port, body) {
  return new Promise((resolve, reject) => {
    const t0 = performance.now();
    const req = http.request(
      { host: '127.0.0.1', port, method: 'POST', path: '/v1/chat/completions', agent, headers: { 'content-type': 'application/json', 'content-length': body.length } },
      (res) => {
        res.resume();
        res.on('end', () => (res.statusCode === 200 ? resolve(performance.now() - t0) : reject(new Error(`status ${res.statusCode}`))));
      },
    );
    req.on('error', reject);
    req.end(body);
  });
}

export async function measure({ n = 300, port = 7005, warmup = 20 } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'sentinel-bench-'));
  const shipped = fileURLToPath(new URL('../../config/sentinel.config.json', import.meta.url));
  const config = loadConfig({ path: shipped, env: {}, argv: ['--listen-port', '0', '--target-port', String(port), '--capture-path', join(dir, 'ex.jsonl')] });
  const { inspectors } = buildDefaultInspectors(config, { write: () => {} });
  const proxy = createProxy(config, { inspectors, logAlert: () => {} });
  const { port: proxyPort } = await proxy.listen(0, '127.0.0.1');
  const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
  const out = { target: `127.0.0.1:${port}`, n, node: process.version, results: {} };
  try {
    for (const [name, body] of Object.entries(payloads())) {
      for (let i = 0; i < warmup; i++) {
        await timedPost(agent, port, body);
        await timedPost(agent, proxyPort, body);
      }
      const direct = [];
      const proxied = [];
      const diff = [];
      for (let i = 0; i < n; i++) {
        const swap = i % 2 === 1;
        const a = await timedPost(agent, swap ? proxyPort : port, body);
        const b = await timedPost(agent, swap ? port : proxyPort, body);
        const [d, p] = swap ? [b, a] : [a, b];
        direct.push(d);
        proxied.push(p);
        diff.push(p - d);
      }
      out.results[name] = { bodyBytes: body.length, directMs: summarize(direct), proxiedMs: summarize(proxied), proxyAddedMs: summarize(diff) };
    }
    await proxy.sink.flush();
    const overhead = readFileSync(config.capture.path, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l))
      .filter((r) => r.type === 'exchange').map((r) => r.timings.proxy_overhead_ms);
    out.inProcessOverheadMs = summarize(overhead);
  } finally {
    agent.destroy();
    await proxy.close();
  }
  return out;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const get = (f, d) => (args.includes(f) ? Number(args[args.indexOf(f) + 1]) : d);
  const r = await measure({ n: get('--n', 300), port: get('--port', 7005) });
  const round = (o) => JSON.parse(JSON.stringify(o, (k, v) => (typeof v === 'number' && !Number.isInteger(v) ? Math.round(v * 1000) / 1000 : v)));
  process.stdout.write(JSON.stringify(round(r), null, 2) + '\n');
}
