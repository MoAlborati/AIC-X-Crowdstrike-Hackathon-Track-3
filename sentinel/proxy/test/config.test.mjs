import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { join, isAbsolute } from 'node:path';
import { loadConfig, validateConfig, isLoopbackHost, ConfigError, DEFAULT_CONFIG_PATH, REPO_ROOT } from '../../config/load.mjs';

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
