import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { rates, percentile, median, latencySummary } from '../src/metrics.mjs';
import { REPO_ROOT } from './helpers.mjs';

test('rates: zero denominators are null, not 0', () => {
  const r = rates({ tp: 0, fp: 0, tn: 5, fn: 3 });
  assert.equal(r.precision, null);
  assert.equal(r.recall, 0);
  assert.equal(r.falsePositiveRate, 0);
  assert.equal(rates({ tp: 0, fp: 0, tn: 0, fn: 0 }).falsePositiveRate, null);
  assert.equal(rates({ tp: 3, fp: 1, tn: 9, fn: 1 }).precision, 0.75);
});

test('percentile is nearest-rank; median averages the middle pair', () => {
  const xs = Array.from({ length: 400 }, (_, i) => i + 1);
  assert.equal(percentile(xs, 95), 380);
  assert.equal(percentile([7], 95), 7);
  assert.equal(median([1, 2, 3, 4]), 2.5);
  assert.deepEqual(latencySummary([]), { n: 0, median: null, p95: null, max: null });
});

test('CLI runs headless from captures/ and writes the results file T5 reads', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 't7-cli-'));
  const out = path.join(dir, 'results.json');
  const md = path.join(dir, 'RESULTS.md');
  const cli = path.join(REPO_ROOT, 'sentinel', 'scoring', 'cli.mjs');
  const res = spawnSync(process.execPath, [cli, '--iterations', '2', '--out', out, '--md', md, '--allow-replica'], { encoding: 'utf8' });
  assert.equal(res.status, 0, res.stderr);
  const r = JSON.parse(readFileSync(out, 'utf8'));
  assert.equal(r.schema, 'sentinel.scoring/1.0.0');
  // fields sentinel/dashboard/lib/scoring.mjs (T5) reads — present even when null
  for (const k of ['detectionRate', 'recall', 'falsePositiveRate', 'precision', 'latencyMs', 'counts']) assert.ok(k in r, k);
  assert.ok('median' in r.latencyMs && 'p95' in r.latencyMs);
  assert.ok(r.detectors.noop && r.detectors['dvaa-baseline']);
  assert.match(readFileSync(md, 'utf8'), /\| detector \| kind \| mode \| precision \| recall \| benign FP rate/);
});

test('CLI: bad argument exits 2 and writes nothing', () => {
  const cli = path.join(REPO_ROOT, 'sentinel', 'scoring', 'cli.mjs');
  const res = spawnSync(process.execPath, [cli, '--iterations', '1000', '--no-write'], { encoding: 'utf8' });
  assert.equal(res.status, 2);
  assert.match(res.stderr, /MAX_LATENCY_ITERATIONS/);
  assert.ok(execFileSync);
});
