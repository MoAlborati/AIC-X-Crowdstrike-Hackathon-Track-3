// SentinelProxy T12 — tool-boundary egress inspector (second enforcement point, next to the chat proxy).
//
// A zero-dependency HTTP forward proxy. DVAA runs with NODE_USE_ENV_PROXY=1 + HTTP(S)_PROXY pointing here,
// on an `internal: true` Docker network whose only exit is this process (compose.egress.yml). Every tool
// egress therefore arrives here BEFORE it reaches its destination:
//   http://  absolute-form -> full URL (incl. ?data=) + full body scanned; verdict logged before forwarding
//   CONNECT host:port      -> TLS is opaque (no MITM): allow/deny by host allowlist only
//
// Fail-closed (deny + loud ALERT on stderr and in the JSONL log, in BOTH modes): payload over cap,
// header/URL over parser limit, body read timeout, scan error, scan time budget overrun, %-decode depth
// exceeded, a client outside the allowed networks, and a decision that could not be logged.
//
// Network exposure: listens on LISTEN_HOST, which must be loopback or a private (RFC 1918 / ULA) address,
// and accepts clients only from ALLOW_CLIENT_CIDRS. No port is published to the host.
//
// Env: MODE=observe|block  ALLOW_HOSTS=a,b  HONEYTOKENS_FILE=path.json  LOG=/path.jsonl  PORT=8899
//      LISTEN_HOST=127.0.0.1  ALLOW_CLIENT_CIDRS=127.0.0.0/8,10.231.12.0/24  MAX_EGRESS_BYTES=65536
//      REQUEST_TIMEOUT_MS=5000  UPSTREAM_TIMEOUT_MS=5000  SCAN_BUDGET_MS=250  AGENT_LABEL=dvaa

import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  inspectEgress, failClosedVerdict, loadHoneytokens, makeAllowlist, DEFAULTS, REASON_CODES, DVAA_HONEYTOKENS,
} from './policy.mjs';

/** DVAA's planted honeytokens (T3 DVAA_HONEYTOKENS) + this deployment's extras (honeytokens.json). */
export function defaultHoneytokens(extrasFile = path.join(HERE, 'honeytokens.json')) {
  const extras = JSON.parse(fs.readFileSync(extrasFile, 'utf8'));
  return [...DVAA_HONEYTOKENS.map(({ id, value }) => ({ id, value })), ...extras];
}

/**
 * Parse a CONNECT authority: "host:port", "[v6]:port". Returns {host, port} or null (-> fail closed).
 * Never split on ':' (an IPv6 literal contains colons).
 */
export function parseConnectTarget(authority) {
  if (typeof authority !== 'string' || authority.length > 300) return null;
  const m = /^\[([0-9A-Fa-f:.]+)\]:(\d{1,5})$/.exec(authority) ?? /^([^\s:\[\]\/@]+):(\d{1,5})$/.exec(authority);
  if (!m) return null;
  const port = Number(m[2]);
  if (port < 1 || port > 65535) return null;
  if (authority.startsWith('[') && !net.isIPv6(m[1])) return null;
  return { host: m[1].toLowerCase(), port };
}

const HERE = path.dirname(fileURLToPath(import.meta.url));

/** Is `ip` loopback or private (RFC 1918, ULA, link-local excluded)? */
export function isPrivateOrLoopback(ip) {
  const v4 = ip.startsWith('::ffff:') ? ip.slice(7) : ip;
  if (net.isIPv4(v4)) {
    const [a, b] = v4.split('.').map(Number);
    return a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
  }
  if (net.isIPv6(ip)) return ip === '::1' || /^f[cd]/i.test(ip);
  return false;
}

function parseCidrs(spec) {
  const list = new net.BlockList();
  for (const c of String(spec).split(',').map((s) => s.trim()).filter(Boolean)) {
    const [addr, bits] = c.split('/');
    const type = net.isIPv6(addr) ? 'ipv6' : 'ipv4';
    if (!net.isIP(addr)) throw new Error(`ALLOW_CLIENT_CIDRS: bad address ${addr}`);
    if (!isPrivateOrLoopback(addr)) throw new Error(`ALLOW_CLIENT_CIDRS: ${c} is not loopback/private`);
    list.addSubnet(addr, Number(bits ?? (type === 'ipv4' ? 32 : 128)), type);
  }
  return list;
}

export function configFromEnv(env = process.env) {
  const htFile = env.HONEYTOKENS_FILE || path.join(HERE, 'honeytokens.json');
  return {
    mode: env.MODE === 'block' ? 'block' : 'observe',
    allowHosts: (env.ALLOW_HOSTS || '').split(','),
    honeytokens: defaultHoneytokens(htFile),
    log: env.LOG || null,
    port: Number(env.PORT || 8899),
    listenHost: env.LISTEN_HOST || '127.0.0.1',
    allowClientCidrs: env.ALLOW_CLIENT_CIDRS || '127.0.0.0/8',
    maxBytes: Number(env.MAX_EGRESS_BYTES || DEFAULTS.MAX_EGRESS_BYTES),
    requestTimeoutMs: Number(env.REQUEST_TIMEOUT_MS || 5000),
    upstreamTimeoutMs: Number(env.UPSTREAM_TIMEOUT_MS || 5000),
    scanBudgetMs: Number(env.SCAN_BUDGET_MS || DEFAULTS.SCAN_BUDGET_MS),
    agentLabel: env.AGENT_LABEL || 'dvaa',
  };
}

/**
 * Create the inspector. Returns { server, listen(): Promise<{port}>, close() }.
 * `opts.faults` is a test-only dependency fault hook ({scan:'error'|'slow', log:'fail'}).
 */
export function createEgressInspector(opts) {
  if (!['observe', 'block'].includes(opts.mode)) throw new Error(`MODE must be observe|block, got ${opts.mode}`);
  if (!net.isIP(opts.listenHost) || !isPrivateOrLoopback(opts.listenHost)) {
    throw new Error(`LISTEN_HOST ${opts.listenHost} must be a loopback/private IP literal (never 0.0.0.0 or public)`);
  }
  if (!Number.isInteger(opts.maxBytes) || opts.maxBytes <= 0) throw new Error('MAX_EGRESS_BYTES must be a positive integer');
  const clients = parseCidrs(opts.allowClientCidrs);
  const cfg = {
    mode: opts.mode,
    allow: makeAllowlist(opts.allowHosts),
    honeytokens: loadHoneytokens(opts.honeytokens),
    maxBytes: opts.maxBytes,
    scanBudgetMs: opts.scanBudgetMs ?? DEFAULTS.SCAN_BUDGET_MS,
    agentLabel: opts.agentLabel,
    faults: opts.faults,
  };
  const sink = opts.onRecord ?? null;

  // Every decision is recorded BEFORE any byte is forwarded. If the record cannot be written, the request
  // is denied (an unrecorded egress is worse than a refused one).
  function record(v) {
    const rec = {
      at: new Date().toISOString(), kind: v.flagged ? 'ALERT' : 'egress', direction: 'egress',
      action: v.action, mode: v.mode, reasons: v.reasons, failClosed: v.failClosed, host: v.host,
      proto: v.kind, method: v.method, url_bytes: v.urlBytes, body_bytes: v.bodyBytes, size: v.size,
      cap: cfg.maxBytes, url_sha256: v.urlSha256, canary_ids: v.canaryIds, secret_kinds: v.secretKinds,
      request_id: v.requestId, latency_ms: v.latencyMs, alert: v.alertDoc,
    };
    const line = JSON.stringify(rec);
    if (opts.faults?.log === 'fail') throw new Error('injected log fault');
    if (opts.log) fs.appendFileSync(opts.log, line + '\n');
    if (v.flagged) {
      process.stderr.write(`ALERT sentinel-egress ${v.action.toUpperCase()} reasons=[${v.reasons}] host=${v.host} size=${v.size} cap=${cfg.maxBytes} mode=${v.mode}\n`);
    }
    sink?.(rec);
    return rec;
  }
  function safeRecord(v) {
    try { record(v); return v; } catch {
      const lf = failClosedVerdict(REASON_CODES.LOG_WRITE_FAILED, { kind: v.kind, method: v.method, url: '', host: v.host, size: v.size }, cfg);
      process.stderr.write(`ALERT sentinel-egress DENY reasons=[${lf.reasons}] (decision could not be logged)\n`);
      try { sink?.({ kind: 'ALERT', direction: 'egress', action: 'deny', reasons: lf.reasons, failClosed: true }); } catch {}
      return lf;
    }
  }

  const deny = (res, status, v) => {
    if (res.headersSent) return res.destroy();
    res.writeHead(status, { 'content-type': 'application/json', connection: 'close' })
      .end(JSON.stringify({ blocked_by: 'sentinel-egress', reasons: v.reasons, request_id: v.requestId }));
  };

  const server = http.createServer({
    // Raised above the cap so an oversize URL reaches our fail-loud path; anything beyond this is a
    // parser error, which is also fail-closed (clientError below) — never Node's silent 431.
    maxHeaderSize: Math.max(cfg.maxBytes * 2, 16384),
    requestTimeout: opts.requestTimeoutMs ?? 5000,
    headersTimeout: opts.requestTimeoutMs ?? 5000,
  }, (req, res) => {
    let url;
    const host0 = () => { try { return url?.hostname ?? null; } catch { return null; } };
    try { url = new URL(req.url); } catch { url = null; }
    if (!url || url.protocol !== 'http:') {
      req.resume();
      const v = safeRecord(failClosedVerdict(REASON_CODES.BAD_PROXY_REQUEST, { kind: 'http', method: req.method, url: '', host: null, size: 0 }, cfg));
      return deny(res, 400, v);
    }
    const chunks = [];
    let size = Buffer.byteLength(req.url);
    let over = size > cfg.maxBytes;
    let done = false;
    const timer = setTimeout(() => {
      if (done) return; done = true;
      const v = safeRecord(failClosedVerdict(REASON_CODES.REQUEST_TIMEOUT, { kind: 'http', method: req.method, url: req.url, host: host0(), size }, cfg));
      deny(res, 408, v); req.destroy();
    }, opts.requestTimeoutMs ?? 5000);
    req.on('data', (c) => {
      size += c.length;
      if (size > cfg.maxBytes) { over = true; chunks.length = 0; return; } // stop buffering; never forward
      chunks.push(c);
    });
    req.on('error', () => {});
    req.on('end', () => {
      if (done) return; done = true; clearTimeout(timer);
      const body = over ? Buffer.alloc(0) : Buffer.concat(chunks);
      let v;
      try {
        v = inspectEgress({ kind: 'http', method: req.method, url: req.url, host: url.hostname, body, size }, cfg);
      } catch {
        v = failClosedVerdict(REASON_CODES.SCAN_ERROR, { kind: 'http', method: req.method, url: req.url, host: url.hostname, size }, cfg);
      }
      v = safeRecord(v);
      if (v.action === 'deny') return deny(res, v.reasons.includes(REASON_CODES.EGRESS_OVER_CAP) ? 413 : 403, v);
      const headers = { ...req.headers };
      delete headers['proxy-connection']; delete headers['proxy-authorization'];
      const up = http.request(url, { method: req.method, headers, timeout: opts.upstreamTimeoutMs ?? 5000 }, (upRes) => {
        res.writeHead(upRes.statusCode, upRes.headers); upRes.pipe(res);
      });
      up.on('timeout', () => up.destroy(new Error('upstream timeout')));
      up.on('error', () => { if (!res.headersSent) res.writeHead(502, { 'content-type': 'text/plain' }).end('sentinel-egress: upstream error'); else res.destroy(); });
      up.end(body);
    });
  });

  server.on('connection', (sock) => {
    const ip = sock.remoteAddress ?? '';
    const v4 = ip.startsWith('::ffff:') ? ip.slice(7) : ip;
    if (!clients.check(v4, net.isIPv6(v4) ? 'ipv6' : 'ipv4')) {
      safeRecord(failClosedVerdict(REASON_CODES.CLIENT_NOT_ALLOWED, { kind: 'http', method: null, url: '', host: null, size: 0 }, cfg));
      sock.destroy();
    }
  });

  server.on('clientError', (err, sock) => {
    safeRecord(failClosedVerdict(REASON_CODES.PROXY_PARSE_ERROR, { kind: 'http', method: null, url: '', host: null, size: 0 }, cfg));
    if (sock.writable) sock.end('HTTP/1.1 400 Bad Request\r\nconnection: close\r\n\r\n'); else sock.destroy();
  });

  server.on('connect', (req, sock, head) => {
    const t = parseConnectTarget(req.url);
    let v;
    if (!t) v = failClosedVerdict(REASON_CODES.BAD_PROXY_REQUEST, { kind: 'connect', method: 'CONNECT', url: '', host: null, size: 0 }, cfg);
    else {
      try { v = inspectEgress({ kind: 'connect', method: 'CONNECT', url: req.url, host: t.host, port: t.port }, cfg); }
      catch { v = failClosedVerdict(REASON_CODES.SCAN_ERROR, { kind: 'connect', method: 'CONNECT', url: req.url, host: t.host }, cfg); }
    }
    v = safeRecord(v);
    if (v.action === 'deny') { sock.end('HTTP/1.1 403 Forbidden\r\nconnection: close\r\n\r\n'); return; }
    const up = net.connect(t.port, t.host, () => {
      sock.write('HTTP/1.1 200 Connection Established\r\n\r\n'); up.write(head); up.pipe(sock); sock.pipe(up);
    });
    up.setTimeout(opts.upstreamTimeoutMs ?? 5000, () => up.destroy());
    up.on('error', () => sock.destroy()); sock.on('error', () => up.destroy());
  });

  return {
    server,
    cfg,
    listen: () => new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(opts.port ?? 0, opts.listenHost, () => resolve({ port: server.address().port }));
    }),
    close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); }),
  };
}

// CLI entry
if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const c = configFromEnv();
  const insp = createEgressInspector(c);
  insp.listen().then(({ port }) => {
    console.log(`sentinel-egress listening ${c.listenHost}:${port} mode=${c.mode} allow=[${[...insp.cfg.allow]}] ` +
      `honeytokens=${insp.cfg.honeytokens.length / 2} max=${c.maxBytes} clients=${c.allowClientCidrs}`);
  }, (e) => { console.error(`sentinel-egress failed to start: ${e.message}`); process.exit(1); });
}
