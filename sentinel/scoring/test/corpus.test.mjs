import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, rmSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { loadCorpus, textUnits } from '../src/corpus.mjs';
import { BOUNDS, ScoringBoundError, CorpusError } from '../src/bounds.mjs';
import { REPO_ROOT, scratchRoot, writeJson } from './helpers.mjs';

test('real corpus: every T1 capture run and every T6 manifest case is loaded and labeled', () => {
  const { cases, excluded, t6Present } = loadCorpus(REPO_ROOT);
  assert.equal(t6Present, true);
  const manifest = JSON.parse(readFileSync(path.join(REPO_ROOT, 'captures/variants/manifest.json'), 'utf8'));
  const t6 = cases.filter((c) => c.source === 't6-variant');
  assert.equal(t6.length, manifest.cases.length);
  for (const m of manifest.cases) assert.equal(t6.find((c) => c.id === m.id).groundTruth, m.groundTruth, m.id);

  const t1 = cases.filter((c) => c.source === 't1-capture');
  // 3 attack demos x 2 runs (minus flight#act3, excluded with a reason) + 6 benign pairs
  assert.equal(t1.filter((c) => c.group === 'attack').length, 5);
  assert.equal(t1.filter((c) => c.group === 'benign').length, 6);
  assert.deepEqual(excluded.map((e) => e.id), ['captures/attack/flight.demo.json#act3']);
  assert.match(excluded[0].reason, /not the attempted http:post payload/);
});

test('AIM-denied twin runs are positives (attempted), with exfilExecuted=false kept', () => {
  const { cases } = loadCorpus(REPO_ROOT);
  const runB = cases.find((c) => c.id === 'attack/aim-ab.demo.json#runB');
  assert.equal(runB.groundTruth, 'positive');
  assert.equal(runB.dvaa.exfilExecuted, false);
  const beat3 = cases.find((c) => c.id === 'attack/repo.demo.json#beat3');
  assert.equal(beat3.groundTruth, 'positive');
  assert.equal(beat3.dvaa.exfilExecuted, false);
  const beat2 = cases.find((c) => c.id === 'attack/repo.demo.json#beat2');
  assert.equal(beat2.dvaa.exfilExecuted, true);
  for (const c of cases.filter((x) => x.group === 'benign' || x.id.startsWith('BEN-'))) assert.equal(c.groundTruth, 'negative', c.id);
});

test('data-rich: >16KB payloads (signal outside the 8KB window) and the 400-row tool output are scanned whole', () => {
  const { cases } = loadCorpus(REPO_ROOT);
  const big = cases.filter((c) => textUnits(c).some((u) => u.text.length > 16 * 1024));
  assert.ok(big.length >= 8, `expected >= 8 cases over 16KB, got ${big.length}`);
  const rows = cases.find((c) => c.id === 'BEN-TOOLROWS-001');
  const text = textUnits(rows)[0].text;
  assert.ok(text.includes('"id":400'), 'row 400 present: nothing truncated');
  const mid = cases.find((c) => c.id === 'EVA-POS-MIDDLE-001');
  assert.equal(mid.evadesBaseline, true);
  assert.ok(textUnits(mid)[0].text.length > 20000);
});

test('fail-loud: unknown attack scenario is a CorpusError, not a skip', () => {
  const root = scratchRoot();
  try {
    writeJson(path.join(root, 'captures/attack/new.demo.json'), { scenario: 'brand-new' });
    assert.throws(() => loadCorpus(root), (e) => e instanceof CorpusError && /unknown scenario "brand-new"/.test(e.message));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fail-loud: benign response without request, and request without response', () => {
  const root = scratchRoot();
  try {
    rmSync(path.join(root, 'captures/benign/7002_helperbot.req.json'));
    assert.throws(() => loadCorpus(root), /response\(s\) without request: 7002_helperbot/);
    writeJson(path.join(root, 'captures/benign/7002_helperbot.req.json'), { messages: [] });
    rmSync(path.join(root, 'captures/benign/7003_legacybot.resp.json'));
    assert.throws(() => loadCorpus(root), /7003_legacybot.req.json has no matching/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fail-loud: T6 manifest/fixture label disagreement and missing fixture', () => {
  const root = scratchRoot();
  try {
    const mf = path.join(root, 'captures/variants/manifest.json');
    const m = JSON.parse(readFileSync(mf, 'utf8'));
    m.cases[0].groundTruth = m.cases[0].groundTruth === 'positive' ? 'negative' : 'positive';
    writeFileSync(mf, JSON.stringify(m));
    assert.throws(() => loadCorpus(root), /manifest groundTruth/);
    m.cases[0].groundTruth = m.cases[0].groundTruth === 'positive' ? 'negative' : 'positive';
    m.cases[0].path = 'fixtures/nope.json';
    writeFileSync(mf, JSON.stringify(m));
    assert.throws(() => loadCorpus(root), /not found/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fail-loud: oversized fixture is refused (ScoringBoundError), never truncated', () => {
  const root = scratchRoot();
  try {
    const f = path.join(root, 'captures/benign/7001_securebot.req.json');
    writeFileSync(f, JSON.stringify({ messages: [{ role: 'user', content: 'x'.repeat(BOUNDS.MAX_FIXTURE_BYTES) }] }));
    assert.throws(() => loadCorpus(root), (e) => e instanceof ScoringBoundError && e.bound === 'MAX_FIXTURE_BYTES' && e.size > e.cap);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('data-rich: a 1,990-case T6 corpus loads; one past MAX_CASES refuses the whole run', () => {
  const root = scratchRoot();
  try {
    const dir = path.join(root, 'captures/variants');
    const make = (n) => {
      const cases = [];
      for (let i = 0; i < n; i++) {
        const id = `GEN-${i}`;
        const gt = i % 3 ? 'negative' : 'positive';
        writeJson(path.join(dir, 'gen', `${id}.json`), {
          id, request: { messages: [{ role: 'user', content: `row ${i}` }] },
          label: { groundTruth: gt, dvaa: { exfilAttempted: gt === 'positive' } },
        });
        cases.push({ id, path: `gen/${id}.json`, group: 'gen', groundTruth: gt });
      }
      writeJson(path.join(dir, 'manifest.json'), { counts: { total: n }, cases });
    };
    make(BOUNDS.MAX_CASES - 11); // + 11 T1 cases = exactly MAX_CASES
    assert.equal(loadCorpus(root).cases.length, BOUNDS.MAX_CASES);
    make(BOUNDS.MAX_CASES - 10);
    assert.throws(() => loadCorpus(root), (e) => e instanceof ScoringBoundError && e.bound === 'MAX_CASES');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
