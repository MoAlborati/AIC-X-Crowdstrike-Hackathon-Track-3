// T6c held-out set: verbatim provenance, determinism, size budget, disjointness, harness separation.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { buildAll, manifestFor, HOLDOUT_ROOT, INDIRECT_TOOL } from '../tools/build.mjs';

const sha = (s) => createHash('sha256').update(s, 'utf8').digest('hex');
const UP = path.join(HOLDOUT_ROOT, 'upstream');
const upstream = readdirSync(UP).filter((f) => f.endsWith('.json')).sort().map((f) => JSON.parse(readFileSync(path.join(UP, f), 'utf8')));
const fixtures = buildAll();

test('3 datasets, each pinned to a 40-hex revision with a pinned file sha256 and a permissive license', () => {
  const pins = JSON.parse(readFileSync(path.join(HOLDOUT_ROOT, 'tools', 'pins.json'), 'utf8'));
  assert.equal(upstream.length, 3);
  for (const u of upstream) {
    assert.match(u.revision, /^[0-9a-f]{40}$/);
    assert.equal(u.fileSha256, pins[u.slug], `${u.slug} file hash != pins.json`);
    assert.ok(['Apache-2.0', 'MIT', 'CC-BY-4.0'].includes(u.license), u.license);
    assert.notEqual(u.repo, 'deepset/prompt-injections', 'deepset is already in the main corpus');
    for (const k of ['positive', 'negative']) assert.ok((u.rows[k] ?? []).length <= u.selection.perClass);
  }
});

test('every payload is the upstream row verbatim, in the right channel/role', () => {
  const rows = new Map();
  for (const u of upstream) for (const k of ['positive', 'negative']) for (const r of u.rows[k]) rows.set(`${u.repo}#${r.rowIdx}`, { ...r, gt: k });
  assert.equal(fixtures.length, 2 * rows.size, 'one direct + one indirect fixture per sampled row');
  for (const fx of fixtures) {
    const r = rows.get(`${fx.source.upstream.repo}#${fx.source.upstream.rowIdx}`);
    assert.ok(r, fx.id);
    assert.equal(fx.label.groundTruth, r.gt, fx.id);
    assert.equal(sha(r.text), r.sha256);
    const msgs = fx.request.messages;
    const payload = fx.injectionChannel === 'direct' ? msgs[0] : msgs[2];
    if (fx.injectionChannel === 'direct') {
      assert.equal(fx.channel, 'user_message');
      assert.equal(msgs.length, 1);
      assert.equal(payload.role, 'user');
    } else {
      assert.equal(fx.channel, 'tool_output');
      assert.equal(msgs.length, 3);
      assert.equal(payload.role, 'tool');
      assert.equal(payload.name, INDIRECT_TOOL);
      assert.equal(msgs[1].tool_calls[0].id, payload.tool_call_id);
    }
    assert.equal(payload.content, r.text, `${fx.id} payload not byte-identical`);
    assert.equal(sha(payload.content), fx.source.upstream.sha256);
    assert.equal(fx.source.fidelity, 'verbatim');
    assert.equal(fx.label.injectionChannel, fx.injectionChannel);
    assert.equal(fx.label.dvaa.exfilAttempted, false);
    assert.equal(fx.label.expectedVerdict, r.gt === 'positive' ? 'block' : 'allow');
  }
});

test('committed manifest.json equals the deterministic build output', () => {
  const committed = readFileSync(path.join(HOLDOUT_ROOT, 'manifest.json'), 'utf8');
  assert.equal(committed, `${JSON.stringify(manifestFor(fixtures), null, 1)}\n`);
  assert.deepEqual(buildAll(), fixtures, 'build is deterministic');
});

test('committed data stays under the 2 MB budget', () => {
  const files = ['manifest.json', 'LICENSES.md', 'RESULTS.md', ...readdirSync(UP).map((f) => `upstream/${f}`)];
  const total = files.filter((f) => existsSync(path.join(HOLDOUT_ROOT, f))).reduce((n, f) => n + statSync(path.join(HOLDOUT_ROOT, f)).size, 0);
  assert.ok(total < 2 * 1024 * 1024, `held-out data is ${total} bytes`);
});

test('held-out rows are disjoint from the main corpus (captures/variants) and from each other', () => {
  const main = new Set();
  const walk = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith('.json')) {
        const fx = JSON.parse(readFileSync(p, 'utf8'));
        for (const m of fx.request?.messages ?? []) if (typeof m.content === 'string') main.add(m.content.trim());
      }
    }
  };
  walk(path.join(HOLDOUT_ROOT, '..', 'variants', 'fixtures'));
  const seen = new Set();
  for (const u of upstream) for (const k of ['positive', 'negative']) for (const r of u.rows[k]) {
    assert.ok(!main.has(r.text.trim()), `${u.slug} row ${r.rowIdx} is in the main corpus`);
    assert.ok(!seen.has(r.text.trim().toLowerCase()), `${u.slug} row ${r.rowIdx} duplicates another held-out row`);
    seen.add(r.text.trim().toLowerCase());
  }
});

test('LICENSES.md attributes every dataset at its pinned revision', () => {
  const lic = readFileSync(path.join(HOLDOUT_ROOT, 'LICENSES.md'), 'utf8');
  for (const u of upstream) {
    assert.ok(lic.includes(u.repo), u.repo);
    assert.ok(lic.includes(u.revision), u.revision);
    assert.ok(lic.includes(u.fileSha256), u.fileSha256);
  }
});
