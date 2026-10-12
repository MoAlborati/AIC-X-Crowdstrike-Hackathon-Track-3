// Test helpers: a REAL local upstream HTTP server (DVAA-shaped OpenAI-compatible endpoint) and a
// real proxy instance writing to a real JSONL file. Nothing here mocks the proxy.

import http from 'node:http';
import { mkdtempSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { validateConfig } from '../../config/load.mjs';
import { createProxy } from '../server.mjs';

/**
 * Start a real upstream. `handler(reqInfo)` returns {status?, headers?, body} or a raw function
 * (req, res, bodyBuf) for streaming/odd cases. Every received request is recorded in `.received`.
 */
export async function startUpstream(handler) {
  const received = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', async () => {
      const body = Buffer.concat(chunks);
      received.push({ method: req.method, url: req.url, headers: req.headers, body });
      const out = await handler({ req, res, body });
      if (out === undefined) return; // handler wrote the response itself
      const payload = Buffer.isBuffer(out.body) ? out.body : Buffer.from(typeof out.body === 'string' ? out.body : JSON.stringify(out.body));
      res.writeHead(out.status ?? 200, { 'content-type': 'application/json', 'content-length': payload.length, ...(out.headers ?? {}) });
      res.end(payload);
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return {
    server,
    port: server.address().port,
    received,
    close: () => new Promise((r) => { server.close(() => r()); server.closeAllConnections(); }),
  };
}

/** DVAA-shaped chat.completion echoing a canned reply (mirrors the real 7005 response format). */
export function dvaaCompletion(content, extra = {}) {
  return {
    id: 'chatcmpl-ragbot-1791828887632',
    object: 'chat.completion',
    created: 1791828887,
    model: 'ragbot',
    choices: [{ index: 0, message: { role: 'assistant', content }, finish_reason: 'stop' }],
    usage: { prompt_tokens: 100, completion_tokens: 50, total_tokens: 150 },
    ...extra,
  };
}

export function makeConfig(overrides = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'sentinel-t2-'));
  const base = {
    listen: { host: '127.0.0.1', port: 0 },
    target: { host: '127.0.0.1', port: 7005 },
    mode: 'observe',
    limits: {
      maxRequestBytes: 1048576, maxResponseBytes: 8388608, upstreamTimeoutMs: 5000,
      inspectorTimeoutMs: 2000, clientTimeoutMs: 10000, maxInFlight: 64,
    },
    capture: { path: join(dir, 'capture.jsonl'), maxFileBytes: 536870912 },
    inspect: { flagSubstrings: [] },
  };
  const merged = {
    ...base,
    ...overrides,
    listen: { ...base.listen, ...(overrides.listen ?? {}) },
    target: { ...base.target, ...(overrides.target ?? {}) },
    limits: { ...base.limits, ...(overrides.limits ?? {}) },
    capture: { ...base.capture, ...(overrides.capture ?? {}) },
    inspect: { ...base.inspect, ...(overrides.inspect ?? {}) },
  };
  return validateConfig(merged);
}

export async function startProxy(config, deps) {
  const proxy = createProxy(config, { logAlert: () => {}, ...deps });
  const addr = await proxy.listen(0, '127.0.0.1');
  return { proxy, port: addr.port, url: `http://127.0.0.1:${addr.port}` };
}

export function readCapture(path) {
  if (!existsSync(path)) return [];
  return readFileSync(path, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
}

// Keep-alive client agent: the latency test fires hundreds of requests per run, and a fresh TCP
// connection each time exhausts small ephemeral port ranges (TIME_WAIT) on CI/WSL.
const agent = new http.Agent({ keepAlive: true, maxSockets: 64 });

/** Raw POST returning status, headers and exact body bytes. */
export function post(url, body, { headers = {}, chunked = false, paced = false } = {}) {
  return new Promise((resolve, reject) => {
    const buf = Buffer.isBuffer(body) ? body : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
    const u = new URL(url);
    const h = { 'content-type': 'application/json', ...headers };
    if (!chunked) h['content-length'] = buf.length;
    const req = http.request({ host: u.hostname, port: u.port, path: u.pathname, method: 'POST', headers: h, agent }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
      res.on('error', reject);
    });
    req.on('error', reject);
    if (chunked && paced) {
      // Slow uploader: one 64KB piece per 2ms, so the client is provably still sending when the
      // proxy answers. Write errors (EPIPE after the proxy cuts us off) surface via 'error'.
      let i = 0;
      const tick = () => {
        if (req.destroyed) return;
        if (i >= buf.length) { req.end(); return; }
        req.write(buf.subarray(i, i + 65536));
        i += 65536;
        setTimeout(tick, 2);
      };
      tick();
    } else if (chunked) {
      // write in 64KB pieces so the proxy sees a streamed body with no Content-Length
      for (let i = 0; i < buf.length; i += 65536) req.write(buf.subarray(i, i + 65536));
      req.end();
    } else {
      req.end(buf);
    }
  });
}

/**
 * General request: any method, full path incl. query string, arbitrary headers, optional body.
 * Returns status, headers and exact body bytes.
 */
export function send(url, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const buf = body === undefined ? null : (Buffer.isBuffer(body) ? body : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body)));
    const h = { ...headers };
    if (buf) h['content-length'] = buf.length;
    const req = http.request({ host: u.hostname, port: u.port, path: `${u.pathname}${u.search}`, method, headers: h, agent }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.end(buf ?? undefined);
  });
}

/**
 * Build a >8KB chat request whose signal sits in the MIDDLE, outside DVAA's head+tail 8KB windows.
 */
export function bigRequestWithMiddleSignal(signal, totalBytes = 64 * 1024) {
  const filler = 'lorem ipsum dolor sit amet consectetur adipiscing elit '.repeat(Math.ceil(totalBytes / 55));
  const half = Math.floor(totalBytes / 2);
  const content = filler.slice(0, half) + signal + filler.slice(0, half);
  return { model: 'ragbot', messages: [{ role: 'user', content }] };
}

/** Multi-hundred-row tool-output-like content (data-rich fixture). */
export function manyRows(n = 500) {
  const rows = [];
  for (let i = 0; i < n; i += 1) {
    rows.push(`| ${String(i).padStart(4, '0')} | user${i}@example.test | 555-01-${String(i % 10000).padStart(4, '0')} | balance=${(i * 37.11).toFixed(2)} |`);
  }
  return rows.join('\n');
}
