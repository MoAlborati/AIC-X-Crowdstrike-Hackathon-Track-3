import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, isAbsolute } from 'node:path';
import { loadConfig, validateConfig, ConfigError, DEFAULT_CONFIG_PATH, REPO_ROOT } from '../../config/load.mjs';

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
    limits: { maxRequestBytes: 1000, maxResponseBytes: 2000, upstreamTimeoutMs: 10 },
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
    limits: { maxRequestBytes: 1000, maxResponseBytes: 2000, upstreamTimeoutMs: 10 },
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
    limits: { maxRequestBytes: 1, maxResponseBytes: 1, upstreamTimeoutMs: 1 },
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
