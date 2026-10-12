import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { loadConfig, ConfigError, DEFAULT_CONFIG_PATH, SINK_RECORD_OVERHEAD_BYTES } from '../config.js';
import { BASE_CONFIG } from './helpers.js';

const shipped = () => JSON.parse(readFileSync(DEFAULT_CONFIG_PATH, 'utf8'));
const issuesOf = (fn) => {
  try {
    fn();
  } catch (err) {
    assert.ok(err instanceof ConfigError, `expected ConfigError, got ${err}`);
    return err.issues;
  }
  assert.fail('expected ConfigError');
};

describe('config', () => {
  it('the shipped sentinel/config/proxy.json loads and resolves sink.path against its own directory', () => {
    const c = loadConfig({ env: {} });
    assert.equal(c.mode, 'observe');
    assert.equal(c.target.port, 7005);
    assert.equal(c.limits.maxRequestBytes, 1048576);
    assert.equal(c.sink.path, join(dirname(DEFAULT_CONFIG_PATH), '../proxy/.capture/exchanges.jsonl'));
    assert.deepEqual(c.source.overrides, {});
  });

  it('a config file chosen via SENTINEL_CONFIG / --config selects target + mode without code edits', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sentinel-cfg-'));
    const f = join(dir, 'p.json');
    writeFileSync(f, JSON.stringify({ ...shipped(), mode: 'block', target: { host: '127.0.0.1', port: 7014, name: 'RAGBot-AIM' } }));
    for (const c of [loadConfig({ env: { SENTINEL_CONFIG: f } }), loadConfig({ env: {}, argv: ['--config', f] })]) {
      assert.equal(c.mode, 'block');
      assert.equal(c.target.port, 7014);
      assert.equal(c.sink.path, join(dir, '../proxy/.capture/exchanges.jsonl'));
    }
  });

  it('precedence: CLI > env > file', () => {
    const c = loadConfig({ json: BASE_CONFIG, env: { SENTINEL_MODE: 'block', SENTINEL_TARGET_PORT: '7001' }, argv: ['--mode=observe'] });
    assert.equal(c.mode, 'observe');
    assert.equal(c.target.port, 7001);
    assert.deepEqual(c.source.overrides, { mode: 'CLI --mode', 'target.port': 'env SENTINEL_TARGET_PORT' });
  });

  it('collects EVERY problem in one loud ConfigError', () => {
    const bad = structuredClone(BASE_CONFIG);
    bad.mode = 'enforce';
    bad.target.port = 70000;
    bad.limits.maxRequestBytes = -1;
    bad.limits.extra = 1;
    bad.typo = true;
    delete bad.sink.maxFiles;
    const issues = issuesOf(() => loadConfig({ json: bad, env: { SENTINEL_LISTEN_PORT: 'eighty' }, argv: ['--bogus', 'x'] }));
    for (const needle of ['mode="enforce"', 'target.port=70000', 'limits.maxRequestBytes=-1', 'unknown key limits.extra', 'unknown top-level key "typo"', 'sink.maxFiles is required', 'SENTINEL_LISTEN_PORT="eighty"', 'unknown CLI flag "--bogus"']) {
      assert.ok(issues.some((i) => i.includes(needle)), `missing issue containing ${needle}:\n${issues.join('\n')}`);
    }
  });

  it('rejects caps above the hard ceilings', () => {
    const issues = issuesOf(() => loadConfig({ json: BASE_CONFIG, env: {}, argv: ['--max-request-bytes', String(64 * 1024 * 1024)] }));
    assert.ok(issues.some((i) => i.startsWith('limits.maxRequestBytes=')));
  });

  it('rejects a sink file too small to hold a worst-case record (so rotation never splits/drops a record)', () => {
    const issues = issuesOf(() => loadConfig({ json: BASE_CONFIG, env: {}, argv: ['--sink-max-file-bytes', '1000000'] }));
    const floor = 2 * (1048576 + 4194304) + SINK_RECORD_OVERHEAD_BYTES;
    assert.ok(issues.some((i) => i.includes(`floor`) && i.includes(String(floor))), issues.join('\n'));
  });

  it('unreadable config file fails loud', () => {
    const issues = issuesOf(() => loadConfig({ file: '/nonexistent/proxy.json', env: {} }));
    assert.match(issues[0], /cannot read config file/);
  });
});
