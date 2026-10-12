/**
 * T8 contrast tests. Run: node --test captures/contrast/tests/contrast.test.mjs
 *
 * Real seam: every test starts from the run captured from the live DVAA fleet by run-contrast.sh
 * (captures/contrast/runs/ — DVAA's own demo output + SentinelProxy's own JSONL capture log).
 * Nothing about the feature is mocked; data-rich variants are built by padding those real files.
 * Live re-capture: T8_LIVE=1 also drives run-contrast.sh against the running dvaa-t1 fleet.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  buildContrast, findExchangesForCanary, readJsonlBounded, loadJsonBounded,
  ContrastInputError, MAX_INPUT_BYTES,
} from '../build-contrast.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const RUNS = path.join(ROOT, 'runs');
const BENIGN_LONG = path.resolve(ROOT, '..', 'variants', 'corpus', 'benign-kb-long.md');

function copyRun() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 't8-contrast-'));
  for (const f of fs.readdirSync(RUNS)) fs.copyFileSync(path.join(RUNS, f), path.join(dir, f));
  return dir;
}
const readJson = (dir, f) => JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
const writeJson = (dir, f, o) => fs.writeFileSync(path.join(dir, f), JSON.stringify(o));
const readLines = (dir, f) => fs.readFileSync(path.join(dir, f), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
const writeLines = (dir, f, rs) => fs.writeFileSync(path.join(dir, f), rs.map((r) => JSON.stringify(r)).join('\n') + '\n');

test('captured run: all three columns hold their ground truth', () => {
  const c = buildContrast(RUNS);
  assert.deepEqual(c.failures, []);
  assert.equal(c.ok, true);
  const { vulnerable, defended, proxy } = c.columns;
  assert.equal(vulnerable.exfilExecuted, true);
  assert.match(JSON.stringify(vulnerable.leaked), /dvaa-admin-secret/);
  assert.equal(defended.aim.exfilAttempted, true, 'same attack lands on the AIM twin');
  assert.equal(defended.aim.exfilExecuted, false);
  assert.equal(defended.aim.canaryHits, 0);
  assert.equal(defended.securebot.canaryHits, 0);
  assert.equal(defended.securebot.toolCalls, 0);
  assert.equal(proxy.block.proxyAction, 'blocked_request');
  assert.equal(proxy.block.proxyStatus, 403);
  assert.equal(proxy.block.agentInvoked, false);
  assert.equal(proxy.block.canaryHits, 0);
  assert.equal(proxy.observe.exfilExecuted, true, 'observe mode is detection-only; documented limit');
  for (const ctl of Object.values(c.controls)) assert.equal(ctl.exfilExecuted, true, 'every file has a run-A positive control');
});

test('captured run: column 3 is labelled as the stand-in until T3 exists', () => {
  const c = buildContrast(RUNS);
  if (/t3/.test(c.meta.sentinel_ref)) {
    assert.equal(c.meta.inspector, 't3-detector');
  } else {
    assert.equal(c.meta.inspector, 'standin-substring');
    assert.equal(c.columns.proxy.block.inspector, 'standin-substring');
  }
});

test('data-rich: run B record is found by full scan among 600 large exchanges (>8KB bodies)', () => {
  const dir = copyRun();
  const filler = fs.readFileSync(BENIGN_LONG, 'utf8');
  assert.ok(filler.length > 8192, 'filler body must exceed the 8KB head/tail window');
  const real = readLines(dir, 'proxy-block.proxy.jsonl');
  const fake = (i) => ({
    type: 'exchange', request_id: `filler-${i}`, action: 'forwarded',
    request: { method: 'POST', path: '/v1/chat/completions', body: { encoding: 'utf8', data: `${filler}\n#${i}` } },
    response: { status: 200 }, verdicts: [],
  });
  // 300 before, 300 after: the real record sits far past any first-N window.
  const padded = [...Array.from({ length: 300 }, (_, i) => fake(i)), ...real, ...Array.from({ length: 300 }, (_, i) => fake(300 + i))];
  writeLines(dir, 'proxy-block.proxy.jsonl', padded);
  assert.ok(fs.statSync(path.join(dir, 'proxy-block.proxy.jsonl')).size > 6 * 1024 * 1024);
  const c = buildContrast(dir);
  assert.deepEqual(c.failures, []);
  assert.equal(c.columns.proxy.block.proxyAction, 'blocked_request');
});

test('data-rich: canary URL buried past 8KB of body text is still matched (no head/tail window)', () => {
  const dir = copyRun();
  const canary = readJson(dir, 'proxy-block.demo.json').canary.url;
  const filler = fs.readFileSync(BENIGN_LONG, 'utf8');
  const recs = readLines(dir, 'proxy-block.proxy.jsonl').map((r) => {
    if (r.type !== 'exchange' || !r.request?.body?.data?.includes(canary)) return r;
    const data = `${filler}${r.request.body.data}${filler}`;
    return { ...r, request: { ...r.request, body: { ...r.request.body, data, bytes: Buffer.byteLength(data) } } };
  });
  const hit = findExchangesForCanary(recs, canary);
  assert.equal(hit.length, 1);
  assert.ok(hit[0].request.body.data.indexOf(canary) > 16384, 'signal sits outside the first 16KB');
  assert.ok(hit[0].request.body.data.length - hit[0].request.body.data.indexOf(canary) > 16384, 'and outside the last 16KB');
});

test('negative control: a forwarded run B in block mode fails loudly', () => {
  const dir = copyRun();
  const canary = readJson(dir, 'proxy-block.demo.json').canary.url;
  const recs = readLines(dir, 'proxy-block.proxy.jsonl').map((r) => (
    r.type === 'exchange' && r.request?.body?.data?.includes(canary) ? { ...r, action: 'forwarded', response: { status: 200 } } : r));
  writeLines(dir, 'proxy-block.proxy.jsonl', recs);
  const c = buildContrast(dir);
  assert.equal(c.ok, false);
  assert.ok(c.failures.some((f) => /blocked_request/.test(f)));
  assert.ok(c.failures.some((f) => /forwarded to the agent/.test(f)));
});

test('negative control: a second canary hit (run B leaked) fails every defended column', () => {
  const dir = copyRun();
  for (const f of ['baseline-aim.demo.json', 'securebot.demo.json', 'proxy-block.demo.json']) {
    const d = readJson(dir, f);
    d.canary.hits.push({ ...d.canary.hits[0], at: 'later' });
    writeJson(dir, f, d);
  }
  const c = buildContrast(dir);
  assert.equal(c.ok, false);
  for (const who of ['AIM twin', 'SecureBot', 'proxy-block']) {
    assert.ok(c.failures.some((f) => f.startsWith(who) && /canary saw 1 hit/.test(f)), `${who} must fail`);
  }
});

test('negative control: no positive control (run A did not exfil) fails', () => {
  const dir = copyRun();
  const d = readJson(dir, 'proxy-block.demo.json');
  d.runA.dvaa.exfilExecuted = false;
  writeJson(dir, 'proxy-block.demo.json', d);
  const c = buildContrast(dir);
  assert.ok(c.failures.some((f) => /proxy-block: run A .* no positive control/.test(f)));
});

test('bound: input over the cap is refused loudly with {size, cap, action}, never truncated', () => {
  const dir = copyRun();
  const f = path.join(dir, 'proxy-block.proxy.jsonl');
  const size = fs.statSync(f).size;
  assert.throws(() => readJsonlBounded(f, size - 1), (err) => {
    assert.ok(err instanceof ContrastInputError);
    assert.equal(err.size, size);
    assert.equal(err.cap, size - 1);
    assert.equal(err.action, 'refused');
    return true;
  });
  assert.throws(() => loadJsonBounded(path.join(dir, 'run-meta.json'), 10), ContrastInputError);
  assert.equal(MAX_INPUT_BYTES, 64 * 1024 * 1024);
});

test('malformed JSONL line is an error, not silently skipped', () => {
  const dir = copyRun();
  fs.appendFileSync(path.join(dir, 'proxy-block.proxy.jsonl'), '{not json\n');
  assert.throws(() => buildContrast(dir), /not JSON/);
});

test('live: run-contrast.sh re-captures a passing contrast from the dvaa-t1 fleet', { skip: process.env.T8_LIVE !== '1' && 'set T8_LIVE=1 with DVAA up' }, () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 't8-live-'));
  execFileSync(path.join(ROOT, 'run-contrast.sh'), [out], { stdio: 'pipe', timeout: 120000 });
  const c = buildContrast(out);
  assert.deepEqual(c.failures, []);
});
