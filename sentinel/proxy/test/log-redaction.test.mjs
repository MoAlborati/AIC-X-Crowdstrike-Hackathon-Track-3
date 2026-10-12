// T10 / PR #26 fix: planted honeytokens must never reach stderr or the verdict/alert fields of the
// capture JSONL. Exchange bodies stay raw (evidence) in a 0600 file.
//
// Real seams: the real CLI process (its real stderr), a real upstream HTTP server, the real JSONL
// capture file. Data-rich: ~96 KB request with a 600-row tool output, the honeytoken placed far past
// the 8 KB head window, plus URL (%-encoded) and header placements.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { writeFileSync, mkdtempSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import http from 'node:http';
import { startUpstream, startProxy, makeConfig, readCapture, dvaaCompletion } from './helpers.mjs';
import { substringInspector } from '../inspectors.mjs';
import { createProxy } from '../server.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, '..', 'cli.mjs');
// Canary-only token: matches none of T4's generic secret patterns, so only the honeytoken (canary)
// redaction can hide it. A second token that also looks like an API key covers the pattern path.
const TOKENS = ['dvaa{FAKE_HONEYTOKEN_7c1e9b}', 'sk-sentinel-HONEY-7f3a9c2e1b'];

/** Every spelling we grep for: raw, %-encoded, base64, base64url (with and without padding), hex. */
function spellings(tok) {
  const b = Buffer.from(tok, 'utf8');
  const b64 = b.toString('base64');
  return [
    ['raw', tok],
    ['raw-lower', tok.toLowerCase()],
    ['url', encodeURIComponent(tok)],
    ['url-full', [...b].map((x) => `%${x.toString(16).padStart(2, '0').toUpperCase()}`).join('')],
    ['base64', b64.replace(/=+$/, '')],
    ['base64url', b.toString('base64url')],
    ['hex', b.toString('hex')],
  ];
}

function assertNoToken(text, where) {
  const hay = text.toLowerCase();
  for (const tok of TOKENS) {
    for (const [form, s] of spellings(tok)) {
      assert.ok(!hay.includes(s.toLowerCase()), `${where}: honeytoken leaked (${form}) "${s}"`);
    }
  }
}

/** Non-body capture content: whole alert records + every exchange's verdicts. */
function loggedVerdictText(recs) {
  const parts = [];
  for (const r of recs) {
    if (r.type === 'alert') parts.push(JSON.stringify(r));
    if (r.type === 'exchange') parts.push(JSON.stringify(r.verdicts ?? []));
  }
  return parts.join('\n');
}

function dataRichBody(tok) {
  const rows = Array.from({ length: 600 }, (_, i) => ({ id: i, name: `customer-${i}`, note: 'x'.repeat(120) }));
  const tool = JSON.stringify(rows);
  const at = Math.floor(tool.length * 0.75); // far beyond 8 KB
  const content = `${tool.slice(0, at)} ${tok} ${tool.slice(at)}`;
  return JSON.stringify({ model: 'ragbot', messages: [{ role: 'tool', content }, { role: 'user', content: 'summarize' }] });
}

function request(port, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const buf = Buffer.from(body);
    const req = http.request({ host: '127.0.0.1', port, path, method: 'POST', headers: { 'content-type': 'application/json', 'content-length': buf.length, ...headers } }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    req.end(buf);
  });
}

async function runCli(configPath) {
  const child = spawn(process.execPath, [CLI, '--config', configPath], { stdio: ['ignore', 'pipe', 'pipe'] });
  const exited = new Promise((r) => child.once('exit', r));
  let stderr = '';
  child.stderr.on('data', (c) => { stderr += c.toString('utf8'); });
  const port = await new Promise((resolve, reject) => {
    let out = '';
    child.stdout.on('data', (c) => {
      out += c.toString('utf8');
      const nl = out.indexOf('\n');
      if (nl !== -1) resolve(JSON.parse(out.slice(0, nl)).port);
    });
    child.once('exit', (code) => reject(new Error(`cli exited ${code}: ${stderr}`)));
  });
  return {
    port,
    stderr: () => stderr,
    stop: async () => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM'); await exited; },
  };
}

describe('log redaction: honeytokens never reach stderr or logged verdicts', () => {
  for (const mode of ['observe', 'block']) {
    test(`real CLI (${mode}): default substring inspector, token in body >8KB, URL and header`, async () => {
      const up = await startUpstream(({ req }) => ({ body: dvaaCompletion(req.url.includes('reply-leak') ? `here: ${TOKENS[0]}` : 'ok') }));
      const dir = mkdtempSync(join(tmpdir(), 'sentinel-plog-'));
      const capture = join(dir, 'capture.jsonl');
      const cfgPath = join(dir, 'config.json');
      writeFileSync(cfgPath, JSON.stringify({
        listen: { host: '127.0.0.1', port: 0 },
        target: { host: '127.0.0.1', port: up.port },
        mode,
        limits: { maxRequestBytes: 1048576, maxResponseBytes: 8388608, upstreamTimeoutMs: 5000, inspectorTimeoutMs: 2000, clientTimeoutMs: 10000, maxInFlight: 64 },
        capture: { path: capture, maxFileBytes: 536870912 },
        inspect: { flagSubstrings: TOKENS },
      }));
      const cli = await runCli(cfgPath);
      try {
        const body0 = dataRichBody(TOKENS[0]);
        assert.ok(body0.length > 64 * 1024 && body0.indexOf(TOKENS[0]) > 8192, 'fixture: data-rich, token outside 8 KB');
        const results = [
          await request(cli.port, '/v1/chat/completions', body0),
          await request(cli.port, '/v1/chat/completions', dataRichBody(TOKENS[1])),
          await request(cli.port, `/v1/chat/completions?q=${encodeURIComponent(TOKENS[0])}`, '{}'),
          await request(cli.port, '/v1/chat/completions', '{}', { 'x-api-key': TOKENS[1] }),
          await request(cli.port, '/v1/chat/completions/reply-leak', '{}'), // response-phase hit
        ];
        for (const r of results) assert.equal(r.status, mode === 'block' ? 403 : 200);
        await cli.stop();

        const err = cli.stderr();
        assert.equal((err.match(/\[sentinel\] ALERT /g) ?? []).length, 5, 'one flagged ALERT per request on real stderr');
        assertNoToken(err, 'stderr');

        const recs = readCapture(capture);
        const alerts = recs.filter((x) => x.type === 'alert');
        assert.equal(alerts.length, 5);
        for (const a of alerts) {
          assert.equal(a.verdicts[0].detector, 'substring');
          assert.match(a.verdicts[0].hits[0].needle_id, /^flag-[01]$/, 'hit identified by id');
          assert.match(a.verdicts[0].reasons[0], /^substring_match:(body|url|headers)$/, 'static reason code');
        }
        assert.ok(alerts[0].verdicts[0].hits[0].offset > 8192, 'offset evidence (past 8 KB) still logged');
        assertNoToken(loggedVerdictText(recs), 'capture verdict/alert fields');

        // Evidence stays raw: the exchange bodies/URL/headers carry the token verbatim.
        const ex = recs.filter((x) => x.type === 'exchange' || x.type === 'request');
        assert.ok(ex.some((x) => x.request.body?.data?.includes(TOKENS[0])), 'request body kept raw');
        assert.ok(ex.some((x) => x.request.path.includes(encodeURIComponent(TOKENS[0]))), 'request path kept raw');
        assert.ok(ex.some((x) => x.request.headers['x-api-key'] === TOKENS[1]), 'request header kept raw');
        if (mode === 'observe') {
          assert.ok(recs.some((x) => x.type === 'exchange' && JSON.stringify(x.response).includes(TOKENS[0])), 'response body kept raw');
        }
        assert.equal(statSync(capture).mode & 0o777, 0o600, 'capture file is owner-only');
      } finally {
        await cli.stop().catch(() => {});
        await up.close();
      }
    });
  }

  test('placeholder inspector verdict carries only ids, locations, offsets and static codes', async () => {
    const insp = substringInspector(TOKENS);
    const body = Buffer.from(dataRichBody(TOKENS[0]));
    const v = await insp({ phase: 'request', path: `/x?a=${encodeURIComponent(TOKENS[1])}`, headers: { 'x-k': TOKENS[0] }, body });
    assert.equal(v.flagged, true);
    assert.deepEqual(v.hits.map((h) => `${h.needle_id}@${h.where}`).sort(), ['flag-0@body', 'flag-0@headers', 'flag-1@url']);
    assertNoToken(JSON.stringify(v), 'inspector verdict');
  });

  test('defence in depth: a leaky future detector (raw, %-encoded, base64, Buffer, error text) is redacted on stderr + JSONL', async () => {
    const tok = TOKENS[0];
    const up = await startUpstream(() => ({ body: dvaaCompletion('ok') }));
    const cfg = makeConfig({ target: { port: up.port }, mode: 'observe', inspect: { flagSubstrings: TOKENS } });
    const leaky = async ({ phase }) => {
      if (phase === 'response') throw new Error(`parser choked near ${tok} / ${Buffer.from(tok).toString('base64')}`);
      return {
        flagged: true,
        detector: `det-${tok}`,
        reasons: [`found ${tok}`, `found ${encodeURIComponent(tok)}`, `b64 ${Buffer.from(tok).toString('base64')}`, `b64url ${Buffer.from(tok).toString('base64url')}`],
        evidence: { snippet: `...${tok}...`, bytes: Buffer.from(`ctx ${TOKENS[1]} ctx`), nested: [[`deep ${tok.toUpperCase()}`]] },
      };
    };
    // Real default logAlert (process.stderr), captured at the stream.
    const writes = [];
    const orig = process.stderr.write.bind(process.stderr);
    process.stderr.write = (chunk, ...rest) => { writes.push(String(chunk)); return true; };
    const proxy = createProxy(cfg, { inspectors: [leaky] });
    let port;
    try {
      ({ port } = await proxy.listen(0, '127.0.0.1'));
      const r = await request(port, '/v1/chat/completions', dataRichBody(tok));
      assert.equal(r.status, 200);
      await proxy.sink.flush();
    } finally {
      process.stderr.write = orig;
      await proxy.close(); await up.close();
    }
    const err = writes.join('');
    assert.ok(err.includes('"reason":"flagged"') && err.includes('"reason":"inspector_error"'), 'both alerts reached stderr');
    assert.ok(err.includes('[REDACTED:'), 'redaction markers present');
    assertNoToken(err, 'stderr');
    const recs = readCapture(cfg.capture.path);
    assertNoToken(loggedVerdictText(recs), 'capture verdict/alert fields');
    assert.ok(recs.find((x) => x.type === 'exchange').request.body.data.includes(tok), 'exchange body stays raw evidence');
  });

  test('flagSubstrings that redaction cannot cover fail loud at startup (no silent gap)', async () => {
    assert.throws(() => createProxy(makeConfig({ inspect: { flagSubstrings: ['short'] } })), /log-redaction canaries/);
    assert.throws(() => createProxy(makeConfig({ inspect: { flagSubstrings: Array.from({ length: 65 }, (_, i) => `honeytoken-${i}`) } })), /log-redaction canaries/);
    // startProxy helper still works with valid tokens
    const { proxy } = await startProxy(makeConfig({ inspect: { flagSubstrings: TOKENS } }));
    await proxy.close();
  });
});
