import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { join, isAbsolute } from 'node:path';
import { loadConfig, validateConfig, isLoopbackHost, ConfigError, DEFAULT_CONFIG_PATH, REPO_ROOT, HARD_LIMITS } from '../../config/load.mjs';

const tmp = () => mkdtempSync(join(tmpdir(), 'sentinel-cfg-'));

test('shipped default config is valid (observe mode, DVAA RAGBot 7005)', () => {
  const cfg = loadConfig({ path: DEFAULT_CONFIG_PATH, env: {} });
  assert.equal(cfg.mode, 'observe');
  assert.equal(cfg.target.port, 7005);
  assert.ok(isAbsolute(cfg.capture.path));
  assert.ok(cfg.capture.path.startsWith(REPO_ROOT));
  assert.ok(cfg.limits.maxRequestBytes > 8192, 'cap must exceed DVAA 8KB window');
});

test('config file selects target port + mode without code edits', () => {
  const dir = tmp();
  const file = join(dir, 'c.json');
  writeFileSync(file, JSON.stringify({
    target: { port: 7003 }, mode: 'block',
    limits: { maxRequestBytes: 1000, maxResponseBytes: 2000, upstreamTimeoutMs: 10, inspectorTimeoutMs: 10, clientTimeoutMs: 10, maxInFlight: 1 },
    capture: { path: join(dir, 'x.jsonl'), maxFileBytes: 100000 },
  }));
  const cfg = loadConfig({ path: file, env: {} });
  assert.equal(cfg.mode, 'block');
  assert.equal(cfg.target.port, 7003);
});

test('env overrides win over file (SENTINEL_MODE / SENTINEL_TARGET_PORT / SENTINEL_CONFIG)', () => {
  const dir = tmp();
  const file = join(dir, 'c.json');
  writeFileSync(file, JSON.stringify({
    target: { port: 7005 }, mode: 'observe',
    limits: { maxRequestBytes: 1000, maxResponseBytes: 2000, upstreamTimeoutMs: 10, inspectorTimeoutMs: 10, clientTimeoutMs: 10, maxInFlight: 1 },
    capture: { path: 'rel/x.jsonl', maxFileBytes: 100000 },
  }));
  const cfg = loadConfig({ env: { SENTINEL_CONFIG: file, SENTINEL_MODE: 'block', SENTINEL_TARGET_PORT: '7014', SENTINEL_LISTEN_PORT: '0' } });
  assert.equal(cfg.mode, 'block');
  assert.equal(cfg.target.port, 7014);
  assert.equal(cfg.listen.port, 0);
  assert.equal(cfg.capture.path, join(REPO_ROOT, 'rel/x.jsonl'));
});

test('invalid values fail loud (no silent defaults)', () => {
  const good = {
    target: { port: 7005 }, mode: 'observe',
    limits: { maxRequestBytes: 1, maxResponseBytes: 1, upstreamTimeoutMs: 1, inspectorTimeoutMs: 1, clientTimeoutMs: 1, maxInFlight: 1 },
    capture: { path: '/tmp/x', maxFileBytes: 1 },
  };
  assert.doesNotThrow(() => validateConfig(good));
  const bad = [
    { ...good, mode: 'monitor' },
    { ...good, mode: undefined },
    { ...good, target: { port: 70000 } },
    { ...good, target: { port: 'abc' } },
    { ...good, target: { port: 0 } },
    { ...good, limits: { ...good.limits, maxRequestBytes: 0 } },
    { ...good, limits: { ...good.limits, maxResponseBytes: undefined } },
    { ...good, capture: { path: '', maxFileBytes: 1 } },
    { ...good, inspect: { flagSubstrings: [''] } },
  ];
  for (const b of bad) assert.throws(() => validateConfig(b), ConfigError, JSON.stringify(b));
  assert.throws(() => loadConfig({ path: '/nonexistent/sentinel.json', env: {} }), ConfigError);
});

// PR #14 review H5: listen + target must be loopback.
const GOOD = {
  target: { port: 7005 }, mode: 'observe',
  limits: { maxRequestBytes: 1, maxResponseBytes: 1, upstreamTimeoutMs: 1, inspectorTimeoutMs: 1, clientTimeoutMs: 1, maxInFlight: 1 },
  capture: { path: '/tmp/x', maxFileBytes: 1 },
};
const NON_LOOPBACK = ['0.0.0.0', '::', '[::]', '192.168.1.5', '10.0.0.1', '8.8.8.8', 'evil.example.com', 'localhost.evil.com',
  '127.0.0.1.evil.com', '2130706433', '127.1', '::2', 'fe80::1', '::ffff:10.0.0.1', '0:0:0:0:0:0:0:0'];
const LOOPBACK = ['127.0.0.1', '127.5.6.7', '127.255.255.254', 'localhost', 'LOCALHOST', '::1', '[::1]', '0:0:0:0:0:0:0:1', '::ffff:127.0.0.1'];

test('isLoopbackHost: only localhost, 127.0.0.0/8 and ::1 forms', () => {
  for (const h of LOOPBACK) assert.equal(isLoopbackHost(h), true, h);
  for (const h of NON_LOOPBACK) assert.equal(isLoopbackHost(h), false, h);
});

test('non-loopback listen.host or target.host -> ConfigError (file and env)', () => {
  for (const host of NON_LOOPBACK) {
    assert.throws(() => validateConfig({ ...GOOD, listen: { host } }), ConfigError, `listen ${host}`);
    assert.throws(() => validateConfig({ ...GOOD, target: { host, port: 7005 } }), ConfigError, `target ${host}`);
  }
  for (const host of LOOPBACK) {
    assert.doesNotThrow(() => validateConfig({ ...GOOD, listen: { host }, target: { host, port: 7005 } }), host);
  }
  assert.throws(() => loadConfig({ path: DEFAULT_CONFIG_PATH, env: { SENTINEL_LISTEN_HOST: '0.0.0.0' } }), ConfigError);
  assert.throws(() => loadConfig({ path: DEFAULT_CONFIG_PATH, env: { SENTINEL_TARGET_HOST: 'evil.example.com' } }), ConfigError);
});

test('CLI exits 2 on SENTINEL_LISTEN_HOST=0.0.0.0 / SENTINEL_TARGET_HOST=evil.example.com', () => {
  const cli = join(dirname(fileURLToPath(import.meta.url)), '..', 'cli.mjs');
  for (const env of [{ SENTINEL_LISTEN_HOST: '0.0.0.0' }, { SENTINEL_TARGET_HOST: 'evil.example.com' }]) {
    const r = spawnSync(process.execPath, [cli], { env: { ...process.env, ...env, SENTINEL_LISTEN_PORT: '0' }, encoding: 'utf8', timeout: 10000 });
    assert.equal(r.status, 2, JSON.stringify(env) + r.stderr);
    assert.match(r.stderr, /loopback/);
  }
});

test('new limits (inspectorTimeoutMs, clientTimeoutMs, maxInFlight) are required positive ints', () => {
  for (const k of ['inspectorTimeoutMs', 'clientTimeoutMs', 'maxInFlight']) {
    assert.throws(() => validateConfig({ ...GOOD, limits: { ...GOOD.limits, [k]: undefined } }), ConfigError, k);
    assert.throws(() => validateConfig({ ...GOOD, limits: { ...GOOD.limits, [k]: 0 } }), ConfigError, k);
  }
});

// ---- ported from the retired PR #21 loader tests (issue #37) ----------------------------------------
const issuesOf = (fn) => {
  try {
    fn();
  } catch (err) {
    assert.ok(err instanceof ConfigError, `expected ConfigError, got ${err}`);
    assert.ok(Array.isArray(err.issues) && err.issues.length > 0);
    return err.issues;
  }
  return assert.fail('expected ConfigError');
};
const writeCfg = (obj) => {
  const file = join(tmp(), 'c.json');
  writeFileSync(file, JSON.stringify(obj));
  return file;
};
const FULL = {
  listen: { host: '127.0.0.1', port: 8080 }, target: { host: '127.0.0.1', port: 7005 }, mode: 'observe',
  limits: { maxRequestBytes: 1048576, maxResponseBytes: 8388608, upstreamTimeoutMs: 1000, inspectorTimeoutMs: 500, clientTimeoutMs: 1000, maxInFlight: 4 },
  capture: { path: '/tmp/x.jsonl', maxFileBytes: 1048576 }, inspect: { flagSubstrings: [] },
};

test('precedence: CLI flag > env > file, and source.overrides names where each field came from', () => {
  const file = writeCfg(FULL);
  const cfg = loadConfig({ path: file, env: { SENTINEL_MODE: 'block', SENTINEL_TARGET_PORT: '7001', SENTINEL_MAX_IN_FLIGHT: '8' }, argv: ['--mode=observe', '--max-request-bytes', '2048'] });
  assert.equal(cfg.mode, 'observe');
  assert.equal(cfg.target.port, 7001);
  assert.equal(cfg.limits.maxInFlight, 8);
  assert.equal(cfg.limits.maxRequestBytes, 2048);
  assert.deepEqual(cfg.source.overrides, {
    mode: 'CLI --mode', 'target.port': 'env SENTINEL_TARGET_PORT', 'limits.maxRequestBytes': 'CLI --max-request-bytes', 'limits.maxInFlight': 'env SENTINEL_MAX_IN_FLIGHT',
  });
  assert.equal(loadConfig({ env: {}, argv: ['--config', file] }).source.file, file, '--config picks the file');
});

test('collects EVERY problem (file, env and CLI) in one loud ConfigError', () => {
  const bad = structuredClone(FULL);
  bad.mode = 'enforce';
  bad.target.port = 70000;
  bad.limits.maxRequestBytes = -1;
  bad.limits.extra = 1;
  bad.typo = true;
  delete bad.limits.clientTimeoutMs;
  const issues = issuesOf(() => loadConfig({ path: writeCfg(bad), env: { SENTINEL_LISTEN_PORT: 'eighty' }, argv: ['--bogus', 'x', '--mode'] }));
  for (const needle of ['"enforce"', 'target.port', 'limits.maxRequestBytes', 'unknown key limits.extra', 'unknown top-level key "typo"',
    'limits.clientTimeoutMs', 'listen.port', '"eighty"', 'unknown CLI flag "--bogus"', 'CLI flag --mode needs a value']) {
    assert.ok(issues.some((i) => i.includes(needle)), `missing issue containing ${needle}:\n${issues.join('\n')}`);
  }
});

test('caps above the hard ceilings are rejected, whatever the source (file, env, CLI)', () => {
  assert.ok(issuesOf(() => loadConfig({ path: writeCfg(FULL), env: {}, argv: ['--max-request-bytes', String(HARD_LIMITS.maxRequestBytes + 1)] }))
    .some((i) => i.startsWith('limits.maxRequestBytes=') && i.includes('hard ceiling')));
  assert.ok(issuesOf(() => loadConfig({ path: writeCfg(FULL), env: { SENTINEL_MAX_IN_FLIGHT: String(HARD_LIMITS.maxInFlight + 1) } }))
    .some((i) => i.startsWith('limits.maxInFlight=')));
  assert.ok(issuesOf(() => validateConfig({ ...FULL, capture: { path: '/tmp/x', maxFileBytes: HARD_LIMITS.captureMaxFileBytes + 1 } }))
    .some((i) => i.startsWith('capture.maxFileBytes=')));
  for (const [k, v] of Object.entries(HARD_LIMITS)) if (k !== 'captureMaxFileBytes') assert.doesNotThrow(() => validateConfig({ ...FULL, limits: { ...FULL.limits, [k]: v } }), k);
});

test('unknown keys are errors (typo guard); `_comment`-style keys are allowed (T8 stand-in config loads)', () => {
  assert.ok(issuesOf(() => validateConfig({ ...FULL, capture: { ...FULL.capture, maxFileByte: 1 } })).some((i) => i.includes('unknown key capture.maxFileByte')));
  const standin = fileURLToPath(new URL('../../../captures/contrast/standin-inspector.config.json', import.meta.url));
  assert.equal(loadConfig({ path: standin, env: {} }).mode, 'block');
});

test('CLI: unknown flag exits 2 listing every issue; --inspector must default-export a function', () => {
  const cli = join(dirname(fileURLToPath(import.meta.url)), '..', 'cli.mjs');
  const r = spawnSync(process.execPath, [cli, '--bogus', '1', '--mode', 'enforce'], { env: { ...process.env, SENTINEL_LISTEN_PORT: '0' }, encoding: 'utf8', timeout: 10000 });
  assert.equal(r.status, 2, r.stderr);
  assert.match(r.stderr, /unknown CLI flag "--bogus"/);
  assert.match(r.stderr, /"enforce"/);
  const mod = join(tmp(), 'not-an-inspector.mjs');
  writeFileSync(mod, 'export default { inspectRequest() {} };\n');
  const r2 = spawnSync(process.execPath, [cli, '--inspector', mod], { env: { ...process.env, SENTINEL_LISTEN_PORT: '0' }, encoding: 'utf8', timeout: 10000 });
  assert.equal(r2.status, 2, r2.stderr);
  assert.match(r2.stderr, /default export must be an inspector function/);
});

test('CLI --inspector <module>: the extra inspector runs alongside the shipped set and can block', async () => {
  const { startUpstream, post } = await import('./helpers.mjs');
  const { spawn } = await import('node:child_process');
  const { createInterface } = await import('node:readline');
  const up = await startUpstream(() => ({ body: { ok: true } }));
  const dir = tmp();
  const mod = join(dir, 'extra.mjs');
  writeFileSync(mod, "export default async function extra({ phase, body }) { return phase === 'request' && body.includes('EXTRA-MARK') ? { flagged: true, detector: 'extra' } : null; }\n");
  const cli = join(dirname(fileURLToPath(import.meta.url)), '..', 'cli.mjs');
  const child = spawn(process.execPath, [cli, `--inspector=${mod}`, '--mode', 'block', '--listen-port', '0', '--target-port', String(up.port), '--capture-path', join(dir, 'c.jsonl')], { env: { ...process.env }, stdio: ['ignore', 'pipe', 'pipe'] });
  try {
    const ready = await new Promise((resolve, reject) => {
      createInterface({ input: child.stdout }).once('line', (l) => resolve(JSON.parse(l)));
      child.once('exit', (code) => reject(new Error(`cli exited ${code}`)));
    });
    assert.deepEqual(ready.inspectors, ['substring', 'sentinel-t3', 'extra']);
    const url = `http://127.0.0.1:${ready.port}/v1/chat/completions`;
    assert.equal((await post(url, { messages: [{ role: 'user', content: 'hi EXTRA-MARK' }] })).status, 403);
    assert.equal(up.received.length, 0, 'flagged request never forwarded');
    assert.equal((await post(url, { messages: [{ role: 'user', content: 'hi' }] })).status, 200);
  } finally {
    await new Promise((r) => { child.once('exit', r); child.kill('SIGTERM'); });
    await up.close();
  }
});
