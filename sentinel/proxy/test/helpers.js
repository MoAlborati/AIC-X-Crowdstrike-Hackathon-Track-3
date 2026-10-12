// Shared helpers for T2 tests. Live tests talk to the REAL DVAA fleet on 127.0.0.1 (real seam).
import http from 'node:http';
import net from 'node:net';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createProxy } from '../server.js';
import { loadConfig } from '../config.js';

export const REPO_ROOT = fileURLToPath(new URL('../../../', import.meta.url));
export const CAPTURES = join(REPO_ROOT, 'captures');
export const DVAA_HOST = '127.0.0.1';
export const RAGBOT_PORT = 7005;

export const readCapture = (rel) => readFileSync(join(CAPTURES, rel));

/** Raw HTTP POST returning the exact response bytes. `chunked: true` omits content-length. */
export function post(url, body, { headers = {}, chunked = false, path = '/v1/chat/completions', method = 'POST' } = {}) {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const h = { 'content-type': 'application/json', ...headers };
    if (!chunked && body) h['content-length'] = body.length;
    const req = http.request({ host: u.hostname, port: u.port, method, path, headers: h, agent: false }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const buf = Buffer.concat(chunks);
        let json = null;
        try {
          json = JSON.parse(buf.toString('utf8'));
        } catch {}
        resolve({ status: res.statusCode, headers: res.headers, body: buf, json });
      });
      res.on('error', reject);
    });
    req.on('error', reject);
    if (body && chunked) {
      // send in 16KiB pieces so the proxy sees a streamed body with no declared length
      for (let i = 0; i < body.length; i += 16384) req.write(body.subarray(i, i + 16384));
      req.end();
    } else req.end(body);
  });
}

export function getJson(url) {
  return new Promise((resolve, reject) => {
    http
      .get(url, { agent: false }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          try {
            resolve({ status: res.statusCode, json: JSON.parse(Buffer.concat(chunks).toString('utf8')) });
          } catch (e) {
            reject(e);
          }
        });
      })
      .on('error', reject);
  });
}

/** Fail LOUDLY if the DVAA agent is not reachable — live tests must never silently skip. */
export async function requireDvaa(port, expectedAgent) {
  let health;
  try {
    health = await getJson(`http://${DVAA_HOST}:${port}/health`);
  } catch (err) {
    assert.fail(`DVAA agent on ${DVAA_HOST}:${port} is UNREACHABLE (${err.message}). Live T2 tests need the real DVAA fleet: scripts/setup-dvaa.sh up`);
  }
  assert.equal(health.status, 200, `DVAA ${port}/health returned ${health.status}`);
  assert.equal(health.json.status, 'ok', `DVAA ${port}/health not ok: ${JSON.stringify(health.json)}`);
  if (expectedAgent) assert.equal(health.json.agent, expectedAgent, `port ${port} is ${health.json.agent}, expected ${expectedAgent}`);
  return health.json;
}

export const BASE_CONFIG = Object.freeze({
  listen: { host: '127.0.0.1', port: 0 },
  target: { host: DVAA_HOST, port: RAGBOT_PORT, name: 'RAGBot' },
  mode: 'observe',
  limits: { maxRequestBytes: 1048576, maxResponseBytes: 4194304, upstreamTimeoutMs: 15000, inspectorTimeoutMs: 500, maxInFlight: 32 },
  sink: { path: 'set-per-test', maxFileBytes: 67108864, maxFiles: 5 },
});

/** Build a config through the real loader (inline JSON + env/argv overrides). */
export function makeConfig({ patch = {}, env = {}, argv = [] } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'sentinel-t2-'));
  const json = structuredClone(BASE_CONFIG);
  json.sink.path = join(dir, 'exchanges.jsonl');
  for (const [k, v] of Object.entries(patch)) {
    if (v && typeof v === 'object' && !Array.isArray(v)) json[k] = { ...json[k], ...v };
    else json[k] = v;
  }
  return loadConfig({ json, env, argv });
}

/** Start a proxy; returns { proxy, url, logs, records(), close() }. */
export async function startProxy(opts = {}) {
  const config = opts.config ?? makeConfig(opts);
  const logs = [];
  const log = (level, event, fields = {}) => logs.push({ level, event, ...fields });
  const proxy = createProxy(config, { inspector: opts.inspector, log, sink: opts.sink });
  const addr = await proxy.listen(0, '127.0.0.1');
  return {
    proxy,
    config,
    url: addr.url,
    logs,
    records: () => readRecords(config.sink.path),
    close: () => proxy.close(),
  };
}

export function readRecords(path) {
  if (!existsSync(path)) return [];
  return readFileSync(path, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l));
}

/** A TCP server that accepts connections and never answers (upstream-timeout dependency stub). */
export async function startHangingUpstream() {
  const sockets = new Set();
  const server = net.createServer((s) => {
    sockets.add(s);
    s.on('error', () => {});
    s.resume();
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return {
    port: server.address().port,
    close: () => {
      for (const s of sockets) s.destroy();
      return new Promise((r) => server.close(r));
    },
  };
}

/** A port with nothing listening on it. */
export async function closedPort() {
  const server = net.createServer();
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  await new Promise((r) => server.close(r));
  return port;
}

export function quantile(sorted, q) {
  const i = Math.min(sorted.length - 1, Math.max(0, Math.ceil(q * sorted.length) - 1));
  return sorted[i];
}

export function summarize(samples) {
  const s = [...samples].sort((a, b) => a - b);
  return { n: s.length, median: quantile(s, 0.5), p95: quantile(s, 0.95), max: s.at(-1) };
}

// ---- test-only inspector stub (a DEPENDENCY stub standing in for T3, not a mock of the proxy) ----
export const BLOCK_MARKER = 'SENTINEL-TEST-BLOCK-MARKER';

export const markerInspector = Object.freeze({
  name: 'test-marker',
  inspectRequest(ctx) {
    if (!ctx.text.includes(BLOCK_MARKER)) return undefined;
    return {
      action: 'block',
      reason: `request contains ${BLOCK_MARKER}`,
      verdict: {
        category: 'indirect_prompt_injection',
        ruleId: 'test.marker_in_request',
        evidence: `marker at offset ${ctx.text.indexOf(BLOCK_MARKER)} of ${ctx.body.length} bytes`,
        taintPath: [{ kind: 'source', label: 'user turn (test marker)', trust: 'untrusted' }],
      },
    };
  },
  inspectResponse(ctx) {
    if (!ctx.dvaa?.exfilAttempted) return undefined;
    const tc = ctx.toolCalls[0];
    return {
      action: 'block',
      reason: `DVAA reports exfil attempt to ${ctx.dvaa.exfilTargetUrl}`,
      verdict: {
        category: 'taint_flow_exfil',
        ruleId: 'test.dvaa_exfil_reported',
        entities: {
          toolCall: { id: tc?.id ?? 'unknown', name: tc?.function?.name ?? 'unknown', argsPreview: tc?.function?.arguments?.slice(0, 200) },
          sink: { type: 'http', destination: ctx.dvaa.exfilTargetUrl },
        },
        taintPath: [
          { kind: 'source', label: 'rag document in user turn', trust: 'untrusted' },
          { kind: 'sink', label: `${tc?.function?.name} → ${ctx.dvaa.exfilTargetUrl}`, toolCallId: tc?.id, trust: 'external' },
        ],
      },
    };
  },
});
