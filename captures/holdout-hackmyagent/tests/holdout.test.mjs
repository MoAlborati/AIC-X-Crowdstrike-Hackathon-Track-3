// Held-out set (opena2a-org/hackmyagent): verbatim provenance, determinism, placement, disjointness,
// size budget, harness separation. Run: node --test captures/holdout-hackmyagent/tests/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { buildAll, manifestFor, ROOT, INDIRECT_TOOL, INDIRECT_USER_TURN } from '../tools/build.mjs';
import { loadCorpus, textUnits, REPO_ROOT } from '../../../sentinel/scoring/src/corpus.mjs';

const sha = (s) => createHash('sha256').update(s, 'utf8').digest('hex');
const UP = path.join(ROOT, 'upstream');
const upstream = readdirSync(UP).filter((f) => f.endsWith('.json')).sort().map((f) => JSON.parse(readFileSync(path.join(UP, f), 'utf8')));
const fixtures = buildAll();

test('pinned to one Apache-2.0 commit; 164 payloads across 16 categories', () => {
  const pins = JSON.parse(readFileSync(path.join(ROOT, 'tools', 'pins.json'), 'utf8'));
  assert.equal(pins.repo, 'opena2a-org/hackmyagent');
  assert.match(pins.revision, /^[0-9a-f]{40}$/);
  assert.equal(pins.license, 'Apache-2.0');
  assert.equal(upstream.length, 16, '16 categories');
  let total = 0;
  for (const u of upstream) {
    assert.equal(u.revision, pins.revision, `${u.slug} revision != pins.json`);
    assert.equal(u.license, 'Apache-2.0');
    assert.ok(u.rows.positive.length > 0);
    total += u.rows.positive.length;
  }
  assert.equal(total, 164, '164 payloads');
});

test('every payload string is the hackmyagent row VERBATIM (sha256 re-checked)', () => {
  for (const u of upstream) for (const r of u.rows.positive) assert.equal(sha(r.text), r.sha256, `${u.slug} ${r.id}`);
});

test('each payload is emitted direct + indirect (328 fixtures); only indirect scaffolding is authored', () => {
  assert.equal(fixtures.length, 328, '164 x 2 placements');
  for (const fx of fixtures) {
    assert.equal(fx.label.groundTruth, 'positive');
    const msgs = fx.request.messages;
    if (fx.injectionChannel === 'direct') {
      assert.equal(fx.channel, 'user_message');
      assert.equal(msgs.length, 1);
      assert.equal(msgs[0].role, 'user');
      assert.equal(sha(msgs[0].content), fx.source.upstream.sha256, `${fx.id} direct payload not verbatim`);
    } else {
      assert.equal(fx.channel, 'tool_output');
      assert.equal(msgs[0].content, INDIRECT_USER_TURN, 'authored benign user turn');
      assert.equal(msgs[2].role, 'tool');
      assert.equal(msgs[2].name, INDIRECT_TOOL);
      assert.equal(sha(msgs[2].content), fx.source.upstream.sha256, `${fx.id} indirect payload not verbatim`);
    }
  }
});

test('disjoint from the main corpus (captures/variants + T1): no payload string is reused there', () => {
  const main = loadCorpus(REPO_ROOT);
  const mainTexts = new Set();
  for (const c of main.cases) for (const u of textUnits(c)) mainTexts.add(u.text);
  const overlap = [];
  for (const fx of fixtures) {
    const payload = fx.injectionChannel === 'direct' ? fx.request.messages[0].content : fx.request.messages[2].content;
    if (mainTexts.has(payload)) overlap.push(fx.id);
  }
  assert.deepEqual(overlap, [], `held-out payloads must not appear in the main corpus; found: ${overlap.slice(0, 5)}`);
});

test('manifest.json on disk matches the build output (determinism)', () => {
  const onDisk = readFileSync(path.join(ROOT, 'manifest.json'), 'utf8');
  assert.equal(onDisk, `${JSON.stringify(manifestFor(fixtures), null, 1)}\n`, 'run tools/build.mjs to regenerate');
});

test('committed footprint stays under the size budget (only upstream/*.json + manifest.json)', () => {
  let bytes = statSync(path.join(ROOT, 'manifest.json')).size;
  for (const f of readdirSync(UP)) bytes += statSync(path.join(UP, f)).size;
  assert.ok(bytes < 2 * 1024 * 1024, `committed set ${bytes} bytes exceeds 2 MB budget`);
});
