// T12 — the real inspector server over real sockets (local upstream stands in for the destination).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createEgressInspector, parseConnectTarget, defaultHoneytokens } from '../inspector.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const TOKENS = defaultHoneytokens();
let upstream, upPort, hits;

before(async () => {
  hits = [];
  upstream = http.createServer((req, res) => { hits.push(req.url); req.resume(); req.on('end', () => res.end('ok')); });
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  upPort = upstream.address().port;
});
after(() => upstream.close());

async function withInspector(over, fn) {
  const log = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 't12-')), 'egress.jsonl');
  const records = [];
  const insp = createEgressInspector({
    mode: 'block', allowHosts: ['127.0.0.1'], honeytokens: TOKENS, log, port: 0, listenHost: '127.0.0.1',
    allowClientCidrs: '127.0.0.0/8', maxBytes: 65536, requestTimeoutMs: 1500, onRecord: (r) => records.push(r), ...over,
  });
  const { port } = await insp.listen();
  try { return await fn({ port, records, log }); } finally { await insp.close(); }
}

// Absolute-form proxy request, exactly what Node's env-proxy agent sends for http:// targets.
function viaProxy(port, target, { method = 'GET', body, slow } = {}) {
  return new Promise((resolve) => {
    const req = http.request({ host: '127.0.0.1', port, method, path: target, headers: { host: new URL(target).host } }, (res) => {
      res.resume(); res.on('end', () => resolve(res.statusCode));
    });
    req.on('error', (e) => resolve(e.code));
    if (slow) { req.write('a'); return; } // never finish the body
    req.end(body);
  });
}

test('benign allowlisted request is forwarded and logged before forwarding', async () => {
  await withInspector({}, async ({ port, records, log }) => {
    const before = hits.length;
    assert.equal(await viaProxy(port, `http://127.0.0.1:${upPort}/ok?q=1`), 200);
    assert.equal(hits.length, before + 1);
    assert.equal(records[0].kind, 'egress');
    assert.equal(JSON.parse(fs.readFileSync(log, 'utf8').trim()).direction, 'egress');
  });
});

test('honeytoken in a 12 KiB POST body past 8 KiB -> 403, nothing reaches upstream', async () => {
  await withInspector({}, async ({ port, records }) => {
    const before = hits.length;
    const body = 'x'.repeat(9000) + 'dvaa-internal-api-key-abcdef' + 'y'.repeat(3000);
    assert.equal(await viaProxy(port, `http://127.0.0.1:${upPort}/in`, { method: 'POST', body }), 403);
    assert.equal(hits.length, before);
    assert.deepEqual(records[0].reasons, ['honeytoken_match']);
    assert.ok(!JSON.stringify(records).includes('dvaa-internal-api-key-abcdef'));
  });
});

test('40 KiB URL is parsed in full (maxHeaderSize raised) and the tail token is caught', async () => {
  await withInspector({}, async ({ port, records }) => {
    const target = `http://127.0.0.1:${upPort}/x?data=${'p'.repeat(40000)}dvaa-admin-secret`;
    assert.equal(await viaProxy(port, target), 403);
    assert.deepEqual(records[0].reasons, ['honeytoken_match']);
    assert.ok(records[0].url_bytes > 40000);
  });
});

test('over-cap 100 KiB body -> 413 + ALERT egress_over_cap even in observe mode, never forwarded', async () => {
  await withInspector({ mode: 'observe' }, async ({ port, records }) => {
    const before = hits.length;
    assert.equal(await viaProxy(port, `http://127.0.0.1:${upPort}/big`, { method: 'POST', body: 'z'.repeat(100 * 1024) }), 413);
    assert.equal(hits.length, before);
    assert.equal(records[0].kind, 'ALERT');
    assert.deepEqual(records[0].reasons, ['egress_over_cap']);
    assert.equal(records[0].cap, 65536);
    assert.ok(records[0].size > 100 * 1024);
  });
});

test('headers beyond the parser limit -> proxy_parse_error ALERT, fail-closed 400', async () => {
  await withInspector({ maxBytes: 4096 }, async ({ port, records }) => {
    const target = `http://127.0.0.1:${upPort}/x?d=${'q'.repeat(30000)}`;
    const code = await viaProxy(port, target);
    assert.ok(code === 400 || code === 'ECONNRESET', String(code));
    assert.deepEqual(records[0].reasons, ['proxy_parse_error']);
    assert.equal(records[0].action, 'deny');
  });
});

test('stalled body -> request_timeout ALERT + 408, never forwarded', async () => {
  await withInspector({ requestTimeoutMs: 300 }, async ({ port, records }) => {
    const before = hits.length;
    const code = await viaProxy(port, `http://127.0.0.1:${upPort}/slow`, { method: 'POST', slow: true });
    assert.ok(code === 408 || code === 'ECONNRESET', String(code));
    assert.equal(hits.length, before);
    assert.ok(records.some((r) => r.reasons.includes('request_timeout') || r.reasons.includes('proxy_parse_error')));
  });
});

test('decision that cannot be logged -> denied (log_write_failed)', async () => {
  await withInspector({ faults: { log: 'fail' } }, async ({ port, records }) => {
    const before = hits.length;
    assert.equal(await viaProxy(port, `http://127.0.0.1:${upPort}/ok`), 403);
    assert.equal(hits.length, before);
    assert.deepEqual(records[0].reasons, ['log_write_failed']);
  });
});

test('network exposure: refuses non-private LISTEN_HOST; drops clients outside ALLOW_CLIENT_CIDRS', async () => {
  for (const h of ['0.0.0.0', '8.8.8.8', 'localhost', '::']) {
    assert.throws(() => createEgressInspector({ mode: 'block', allowHosts: [], honeytokens: TOKENS, listenHost: h, allowClientCidrs: '127.0.0.0/8', maxBytes: 65536 }), /LISTEN_HOST/);
  }
  assert.throws(() => createEgressInspector({ mode: 'block', allowHosts: [], honeytokens: TOKENS, listenHost: '127.0.0.1', allowClientCidrs: '0.0.0.0/0', maxBytes: 65536 }), /not loopback\/private/);
  await withInspector({ allowClientCidrs: '10.231.12.0/24' }, async ({ port, records }) => {
    const code = await viaProxy(port, `http://127.0.0.1:${upPort}/ok`);
    assert.ok(code === 'ECONNRESET' || code === 'EPIPE' || code === 'ECONNREFUSED', String(code));
    assert.deepEqual(records[0].reasons, ['client_not_allowed']);
  });
});

test('CONNECT: allowlist decides, TLS opaque; non-allowlisted host denied', async () => {
  await withInspector({}, async ({ port, records }) => {
    const res = await new Promise((resolve) => {
      const s = net.connect(port, '127.0.0.1', () => s.write('CONNECT api.oa2a.org:443 HTTP/1.1\r\nhost: api.oa2a.org:443\r\n\r\n'));
      let d = ''; s.on('data', (c) => { d += c; }); s.on('close', () => resolve(d)); s.on('error', () => resolve(d));
    });
    assert.match(res, /403/);
    assert.equal(records[0].proto, 'connect');
    assert.deepEqual(records[0].reasons, ['destination_not_allowlisted']);
  });
});

test('#18 review (1): no-body GET with a 64-128 KiB URL -> 413 egress_over_cap (URL counts toward the cap), never scanned/forwarded', async () => {
  await withInspector({ mode: 'observe' }, async ({ port, records }) => {
    const before = hits.length;
    for (const n of [65 * 1024, 100 * 1024, 120 * 1024]) {
      records.length = 0;
      const target = `http://127.0.0.1:${upPort}/u?d=${'a'.repeat(n)}`;
      assert.equal(await viaProxy(port, target), 413, `url ${n}`);
      assert.deepEqual(records[0].reasons, ['egress_over_cap']);
      assert.equal(records[0].body_bytes, 0);
      assert.ok(records[0].url_bytes > 65536);
    }
    assert.equal(hits.length, before);
  });
});

test('#18 review (3): CONNECT targets parsed without split(":"): IPv6 literals work, malformed fail closed', async () => {
  assert.deepEqual(parseConnectTarget('[::1]:443'), { host: '::1', port: 443 });
  assert.deepEqual(parseConnectTarget('[2001:db8::7]:8443'), { host: '2001:db8::7', port: 8443 });
  assert.deepEqual(parseConnectTarget('API.oa2a.org:443'), { host: 'api.oa2a.org', port: 443 });
  for (const bad of ['::1:443', '[::1]', '[not-v6]:443', 'h:0', 'h:70000', 'u@h:443', 'h:443/x', '']) assert.equal(parseConnectTarget(bad), null, bad);
  const connect = (port, target) => new Promise((resolve) => {
    const s = net.connect(port, '127.0.0.1', () => s.write(`CONNECT ${target} HTTP/1.1\r\nhost: ${target}\r\n\r\n`));
    let d = ''; s.on('data', (c) => { d += c; if (/\r\n\r\n/.test(d)) s.destroy(); }); s.on('close', () => resolve(d)); s.on('error', () => resolve(d));
  });
  await withInspector({ allowHosts: ['::1'] }, async ({ port, records }) => {
    const ok6 = await connect(port, `[::1]:${upPort}`);
    assert.match(ok6, /200 Connection Established|^$/);
    assert.equal(records[0].host, '::1');
    assert.equal(records[0].action, 'forward');
    records.length = 0;
    assert.match(await connect(port, `[2001:db8::7]:443`), /403/);
    assert.equal(records[0].host, null, 'non-allowlisted host is logged as hash + length only');
    assert.equal(records[0].host_len, '2001:db8::7'.length);
    assert.deepEqual(records[0].reasons, ['destination_not_allowlisted']);
    records.length = 0;
    assert.match(await connect(port, '::1:443'), /403/);
    assert.deepEqual(records[0].reasons, ['bad_proxy_request']);
  });
});

test('#18 review (4): the compose overlay defaults to block mode with a host allowlist', () => {
  const y = fs.readFileSync(path.join(HERE, '..', 'compose.egress.yml'), 'utf8');
  assert.match(y, /MODE: \$\{EGRESS_MODE:-block\}/);
  assert.match(y, /ALLOW_HOSTS: \$\{EGRESS_ALLOW:-[a-z]/);
  const demo = fs.readFileSync(path.join(HERE, '..', '..', '..', 'scripts', 'egress-demo.sh'), 'utf8');
  assert.match(demo, /EGRESS_MODE="\$mode"/, 'demo sets the mode explicitly per phase; block is the last phase');
});
