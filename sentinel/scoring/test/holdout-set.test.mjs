// T6c: the holdout-hf set is scored separately and never mixed into the main corpus / headline.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadCorpus, loadSet } from '../src/corpus.mjs';
import { runScoring } from '../src/harness.mjs';
import { noopDetector } from '../src/detectors.mjs';

test('main corpus contains no held-out case', () => {
  const { cases } = loadCorpus();
  assert.equal(cases.filter((c) => c.source === 'hf-holdout' || c.id.startsWith('HF-')).length, 0);
});

test('--set holdout-hf loads only the held-out cases, with real labels and both channels', async () => {
  const { cases } = await loadSet(undefined, 'holdout-hf');
  assert.equal(cases.length, 1000);
  assert.ok(cases.every((c) => c.source === 'hf-holdout'));
  assert.equal(cases.filter((c) => c.groundTruth === 'positive').length, 600);
  assert.equal(cases.filter((c) => c.channel === 'tool_output').length, 500);
  assert.equal(cases.filter((c) => c.channel === 'user_message').length, 500);
});

test('unknown set is refused', async () => {
  await assert.rejects(loadSet(undefined, 'nope'), /unknown set/);
});

test('holdout scoring is labeled as a separate set and reports per-group lenses', async () => {
  const corpus = await loadSet(undefined, 'holdout-hf');
  const r = runScoring({ detectors: [noopDetector()], iterations: 1, corpus, set: 'holdout-hf', headline: 'noop' });
  assert.equal(r.set, 'holdout-hf');
  assert.match(r.setNote, /NOT part of the main-corpus headline/);
  assert.equal(r.corpus.total, 1000);
  const g = r.detectors.noop.byGroup;
  assert.deepEqual(Object.keys(g), ['GAN-direct', 'GAN-indirect', 'JBC-direct', 'JBC-indirect', 'SPML-direct', 'SPML-indirect']);
  assert.equal(g['JBC-direct'].prevention.recall, 0);
  assert.equal(g['JBC-direct'].prevention.falsePositiveRate, 0);
  assert.equal(g['GAN-direct'].prevention.falsePositiveRate, null, 'no benign rows -> null, never 0');
});

test('main scoring output is unchanged in shape (no set/byGroup fields)', () => {
  const r = runScoring({ detectors: [noopDetector()], iterations: 1, headline: 'noop' });
  assert.equal(r.set, undefined);
  assert.equal(r.detectors.noop.byGroup, undefined);
});

test('--set holdout-ipi loads only its own held-out cases and never mixes with main or holdout-hf', async () => {
  const { cases: main } = loadCorpus();
  assert.equal(main.filter((c) => c.source === 'ipi-holdout' || c.id.startsWith('IPI-')).length, 0);
  const { cases } = await loadSet(undefined, 'holdout-ipi');
  assert.equal(cases.length, 770);
  assert.ok(cases.every((c) => c.source === 'ipi-holdout' && c.id.startsWith('IPI-')));
  assert.equal(cases.filter((c) => c.groundTruth === 'positive').length, 370);
  assert.equal(cases.filter((c) => c.channel === 'tool_output').length, 385);
  const r = runScoring({ detectors: [noopDetector()], iterations: 1, corpus: { cases, excluded: [], t6Present: true }, set: 'holdout-ipi', headline: 'noop' });
  assert.equal(r.set, 'holdout-ipi');
  assert.match(r.setNote, /NOT part of the main-corpus headline/);
});
