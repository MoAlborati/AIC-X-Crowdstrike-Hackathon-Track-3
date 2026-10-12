// SPIKE (throwaway) — tool-boundary egress inspector for DVAA.
//
// A plain HTTP forward proxy. DVAA's agents reach it because the DVAA container
// runs with NODE_USE_ENV_PROXY=1 + HTTP(S)_PROXY (Node >=24 core http/https and
// fetch then send every outbound request here). No DVAA source change.
//
//   http://  absolute-form request -> full URL (incl. ?data=...) + body visible;
//            decision logged BEFORE anything is forwarded.
//   https:// CONNECT host:port      -> only host:port visible (TLS is opaque
//            without MITM); allow/deny by host allowlist.
//
// Env: MODE=observe|block  ALLOW_HOSTS=a,b  HONEYTOKENS=t1,t2  LOG=/path.jsonl
//      MAX_EGRESS_BYTES (default 65536)
// Bound: URL+body > MAX_EGRESS_BYTES -> 413 + ALERT, never forwarded (fail-closed,
// never silently truncated).
import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs';

const MODE = process.env.MODE === 'block' ? 'block' : 'observe';
const ALLOW = new Set((process.env.ALLOW_HOSTS || '').split(',').map(s => s.trim()).filter(Boolean));
const TOKENS = (process.env.HONEYTOKENS || '').split(',').map(s => s.trim()).filter(Boolean);
const MAX = Number(process.env.MAX_EGRESS_BYTES || 65536);
const LOG = process.env.LOG || '/dev/stdout';
const PORT = Number(process.env.PORT || 8899);

function log(ev) {
  const line = JSON.stringify({ at: new Date().toISOString(), ...ev });
  fs.appendFileSync(LOG, line + '\n');
  if (LOG !== '/dev/stdout') console.log(line);
}

function decide(host, haystack) {
  const reasons = [];
  if (!ALLOW.has(host)) reasons.push(`destination_not_allowlisted:${host}`);
  for (const t of TOKENS) {
    // check raw, URL-decoded and base64 forms of the honeytoken
    const forms = [t, encodeURIComponent(t), Buffer.from(t).toString('base64')];
    if (forms.some(f => haystack.includes(f))) reasons.push(`honeytoken:${t}`);
  }
  const flagged = reasons.length > 0;
  return { flagged, reasons, action: flagged && MODE === 'block' ? 'deny' : 'forward' };
}

// maxHeaderSize raised above MAX so an oversize URL reaches our fail-loud path
// instead of Node's default 16 KiB header limit (which would 431 silently).
const server = http.createServer({ maxHeaderSize: Math.max(MAX * 2, 16384) }, (req, res) => {
  let url;
  try { url = new URL(req.url); } catch {
    res.writeHead(400).end('egress-inspector: expected absolute-form proxy request');
    return;
  }
  const chunks = []; let size = Buffer.byteLength(req.url); let over = false;
  req.on('data', c => {
    size += c.length;
    if (size > MAX) { over = true; return; }
    chunks.push(c);
  });
  req.on('end', () => {
    if (over) {
      log({ kind: 'ALERT', reason: 'egress_over_cap', payload_size: size, cap: MAX, action: 'deny', url: req.url.slice(0, 256) });
      res.writeHead(413, { 'content-type': 'text/plain' }).end('egress-inspector: payload over cap, denied');
      return;
    }
    const body = Buffer.concat(chunks);
    let decodedUrl = req.url; try { decodedUrl = decodeURIComponent(req.url); } catch {}
    const verdict = decide(url.hostname, `${req.url}\n${decodedUrl}\n${body.toString('utf8')}`);
    // Logged BEFORE forwarding: the inspector sees the tool call at the boundary.
    log({ kind: 'egress', method: req.method, url: req.url, host: url.hostname,
          query: Object.fromEntries(url.searchParams), body_bytes: body.length,
          ua: req.headers['user-agent'], mode: MODE, ...verdict });
    if (verdict.action === 'deny') {
      res.writeHead(403, { 'content-type': 'application/json' })
        .end(JSON.stringify({ blocked_by: 'sentinel-egress', reasons: verdict.reasons }));
      return;
    }
    const headers = { ...req.headers }; delete headers['proxy-connection'];
    const up = http.request(url, { method: req.method, headers }, upRes => {
      res.writeHead(upRes.statusCode, upRes.headers); upRes.pipe(res);
    });
    up.on('error', e => { log({ kind: 'upstream_error', url: req.url, error: e.code }); res.writeHead(502).end(); });
    up.end(body);
  });
});

server.on('clientError', (err, sock) => {
  log({ kind: 'ALERT', reason: 'proxy_parse_error', error: err.code, action: 'deny' });
  sock.end('HTTP/1.1 400 Bad Request\r\n\r\n');
});

server.on('connect', (req, sock, head) => {
  const [host, port] = req.url.split(':');
  const verdict = decide(host, req.url);
  log({ kind: 'connect', target: req.url, host, mode: MODE, note: 'TLS opaque: path/query/body not visible without MITM', ...verdict });
  if (verdict.action === 'deny') { sock.end('HTTP/1.1 403 Forbidden\r\n\r\n'); return; }
  const up = net.connect(Number(port) || 443, host, () => {
    sock.write('HTTP/1.1 200 Connection Established\r\n\r\n'); up.write(head); up.pipe(sock); sock.pipe(up);
  });
  up.on('error', () => sock.destroy()); sock.on('error', () => up.destroy());
});

server.listen(PORT, () => console.log(`egress-inspector listening :${PORT} mode=${MODE} allow=[${[...ALLOW]}] max=${MAX}`));
