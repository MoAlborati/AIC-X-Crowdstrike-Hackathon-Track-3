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
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  buildContrast, findExchangesForCanary, readJsonlBounded, loadJsonBounded,
  ContrastInputError, MAX_INPUT_BYTES, inspectorFromLogs, toMarkdown,
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

test('captured run: inspector label is derived from the detector the proxy logged', () => {
  const c = buildContrast(RUNS);
  const logged = inspectorFromLogs(readLines(RUNS, 'proxy-block.proxy.jsonl'), readLines(RUNS, 'proxy-observe.proxy.jsonl'));
  assert.equal(c.meta.inspector, logged.label, 'run-meta label must equal the logged detector, not the ref name');
  assert.equal(c.columns.proxy.block.inspector, logged.label);
  assert.equal(c.columns.proxy.observe.inspector, logged.label, 'observe column records its inspector too');
  if (logged.standIn) {
    assert.equal(logged.label, 'standin-substring');
    assert.equal(c.meta.inspector_config_is_standin, true);
    assert.match(toMarkdown(c), /\| 3\. Vulnerable \+ SentinelProxy \(block, \*\*stand-in inspector\*\*\) \|/);
  }
});

// Review finding 1 (delete-the-fix target): a T3-sounding label on a run whose proxy logged the stand-in.
test('provenance: run-meta claiming t3-detector while the proxy logged "substring" fails loudly', () => {
  const dir = copyRun();
  const meta = readJson(dir, 'run-meta.json');
  writeJson(dir, 'run-meta.json', { ...meta, inspector: 't3-detector' });
  const c = buildContrast(dir);
  assert.equal(c.ok, false);
  assert.ok(c.failures.some((f) => /run-meta\.json says "t3-detector" but the proxy logged detector\(s\) \[substring\]/.test(f)), c.failures.join('\n'));
  assert.equal(c.columns.proxy.block.inspector, 'standin-substring', 'column label comes from the log, not run-meta');
});

test('provenance: a T3 ref paired with the stand-in inspector fails even when the label is honest', () => {
  const dir = copyRun();
  const meta = readJson(dir, 'run-meta.json');
  writeJson(dir, 'run-meta.json', { ...meta, sentinel_ref: 'origin/t3-detector-core' });
  const c = buildContrast(dir);
  assert.equal(c.ok, false);
  assert.ok(c.failures.some((f) => /t3-detector-core ran with the stand-in/.test(f)), c.failures.join('\n'));
});

test('provenance: the label follows the logged detector (non-stand-in detector -> no stand-in header)', () => {
  const dir = copyRun();
  for (const f of ['proxy-block.proxy.jsonl', 'proxy-observe.proxy.jsonl']) {
    writeLines(dir, f, readLines(dir, f).map((r) => (r.type === 'exchange'
      ? { ...r, verdicts: (r.verdicts ?? []).map((v) => ({ ...v, detector: 'prompt-injection' })) } : r)));
  }
  // An unchanged run-meta (still "standin-substring") must now be caught as a mismatch...
  assert.ok(buildContrast(dir).failures.some((f) => /run-meta\.json says "standin-substring"/.test(f)));
  // ...and once run-meta matches the log, the header drops the stand-in caveat.
  writeJson(dir, 'run-meta.json', { ...readJson(dir, 'run-meta.json'), inspector: 'detector:prompt-injection' });
  const c = buildContrast(dir);
  assert.deepEqual(c.failures, []);
  assert.equal(c.columns.proxy.block.inspectorStandIn, false);
  assert.doesNotMatch(toMarkdown(c), /stand-in inspector/);
});

test('provenance: mixed stand-in + other detectors, or no verdicts at all, fail loudly', () => {
  const mixed = copyRun();
  writeLines(mixed, 'proxy-observe.proxy.jsonl', readLines(mixed, 'proxy-observe.proxy.jsonl').map((r) => (r.type === 'exchange'
    ? { ...r, verdicts: (r.verdicts ?? []).map((v) => (v.phase === 'response' ? { ...v, detector: 'other' } : v)) } : r)));
  const cm = buildContrast(mixed);
  assert.ok(cm.failures.some((f) => /mix the stand-in/.test(f)), cm.failures.join('\n'));
  assert.ok(cm.failures.some((f) => /not the same inspector/.test(f)));

  const none = copyRun();
  for (const f of ['proxy-block.proxy.jsonl', 'proxy-observe.proxy.jsonl']) {
    writeLines(none, f, readLines(none, f).map((r) => ({ ...r, verdicts: [] })));
  }
  assert.ok(buildContrast(none).failures.some((f) => /cannot establish which inspector ran/.test(f)));
});

test('run-contrast.sh refuses a T3 ref with the stand-in config (before touching DVAA)', () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 't8-refuse-'));
  const r = spawnSync(path.join(ROOT, 'run-contrast.sh'), [out], {
    env: { ...process.env, SENTINEL_REF: 'origin/t3-detector-core', SENTINEL_ALLOW_STANDIN: '1', DVAA_CONTAINER: 'no-such-container' },
    encoding: 'utf8', timeout: 30000,
  });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /T3 ref but SENTINEL_CONFIG=.*stand-in config/);
  assert.equal(fs.existsSync(path.join(out, 'run-meta.json')), false, 'nothing captured');
});

test('vulnerable canary count is computed from the capture and cross-checked', () => {
  const c = buildContrast(RUNS);
  const base = readJson(RUNS, 'baseline-aim.demo.json');
  assert.equal(c.columns.vulnerable.canaryHits, base.canary.hits.length - c.columns.defended.aim.canaryHits);

  const dir = copyRun();
  const d = readJson(dir, 'baseline-aim.demo.json');
  d.canary.hits = [];
  writeJson(dir, 'baseline-aim.demo.json', d);
  const c0 = buildContrast(dir);
  assert.equal(c0.columns.vulnerable.canaryHits, 0, 'no hardcoded 1');
  assert.ok(c0.failures.some((f) => /vulnerable: expected run A to hit the canary once, saw 0/.test(f)));

  const wrong = copyRun();
  const w = readJson(wrong, 'baseline-aim.demo.json');
  w.canary.hits[0].query.data = 'something else';
  writeJson(wrong, 'baseline-aim.demo.json', w);
  assert.ok(buildContrast(wrong).failures.some((f) => /does not carry the data run A/.test(f)));
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
