// Headline tiles: Detected | Prevented (each beside DVAA, and its own FP vs DVAA FP) | in-detector latency. Real seams: the real loadScoring() reading real T7 results.json snapshots through the
// filesystem, and the real headlineView(). Nothing in the feature path is mocked.
//   fixtures/t7-results-lens.json            = origin/t7-real-metrics afad512 (PR #28), 353-case corpus
//   fixtures/t7-results-legacy-awaiting.json = origin/main c6cb1ba (pre-#28 shape, headline "awaiting t3")
// The legacy-ok shape is derived from the lens snapshot by deleting exactly the fields PR #28 added,
// so every number in it is still a real T7 number.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, rm, open } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { loadScoring } from '../lib/scoring.mjs';
import { BOUNDS } from '../lib/bounds.mjs';
import { headlineView, TILE_KEYS } from '../public/headline-view.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const LENS = JSON.parse(await readFile(path.join(HERE, 'fixtures', 't7-results-lens.json'), 'utf8'));
const LEGACY_AWAITING = JSON.parse(await readFile(path.join(HERE, 'fixtures', 't7-results-legacy-awaiting.json'), 'utf8'));
const pct = (x) => `${(x * 100).toFixed(1)}%`;
const clone = (x) => structuredClone(x);
const index = new Map(); // corpus counts are not under test here

/** Pre-#28 T7 output: no lens fields, baseline modes carry only detection/blocking. */
function legacyOk() {
  const r = clone(LENS);
  delete r.detectionRecall;
  delete r.preventionRecall;
  delete r.headlineLenses;
  for (const d of Object.values(r.detectors)) {
    for (const m of Object.values(d.modes ?? {})) { delete m.anyFinding; delete m.prevention; }
  }
  return r;
}

async function viewOf(raw) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'sentinel-lens-'));
  try {
    const file = path.join(dir, 'results.json');
    await writeFile(file, typeof raw === 'string' ? raw : JSON.stringify(raw));
    const s = await loadScoring(index, { SENTINEL_SCORING_FILE: file });
    return { s, v: headlineView(s) };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

const allText = (v) => TILE_KEYS.map(k => `${v.tiles[k].value} ${v.tiles[k].base} ${v.tiles[k].fp}`).join(' | ');

test('lens shape (T7 PR #28): Detected / Prevented, each beside DVAA and its own FP vs DVAA FP', async () => {
  assert.equal(LENS.corpus.total, 353, 'data-rich snapshot: full 353-case corpus');
  const { s, v } = await viewOf(LENS);
  const base = LENS.detectors['dvaa-baseline'].modes[LENS.headline.mode];
  assert.equal(s.lensSource, 'lenses');
  assert.equal(v.legacy, false);
  assert.equal(v.lensNote, null);
  assert.notEqual(LENS.detectionRecall, LENS.recall);
  assert.equal(v.tiles.det.value, pct(LENS.detectionRecall));
  assert.equal(v.tiles.prev.value, pct(LENS.preventionRecall));
  assert.equal(v.tiles.det.base, `DVAA ${pct(base.anyFinding.recall)}`);
  assert.equal(v.tiles.prev.base, `DVAA ${pct(base.prevention.recall)}`);
  assert.equal(v.tiles.det.fp, `FP ${pct(LENS.headlineLenses.detection.falsePositiveRate)} vs DVAA ${pct(base.anyFinding.falsePositiveRate)}`);
  assert.equal(v.tiles.prev.fp, `FP ${pct(LENS.headlineLenses.prevention.falsePositiveRate)} vs DVAA ${pct(base.prevention.falsePositiveRate)}`);
  // Latency: the in-detector figure only (no DVAA or dashboard timing next to it).
  assert.equal(v.tiles.lat.value, `${LENS.latencyMs.median.toFixed(3)} ms`);
  assert.equal(v.tiles.lat.base, 'p95 0.379 ms');
  assert.equal(v.tiles.lat.sub, 'median per case, detector only');
  // Pinned to the snapshot.
  assert.deepEqual(TILE_KEYS.map(k => v.tiles[k].value), ['63.0%', '41.8%', '0.067 ms']);
  assert.deepEqual([v.tiles.det.base, v.tiles.det.fp, v.tiles.prev.base, v.tiles.prev.fp],
    ['DVAA 65.6%', 'FP 0.0% vs DVAA 12.8%', 'DVAA 63.0%', 'FP 0.0% vs DVAA 12.8%']);
  assert.ok(TILE_KEYS.every(k => !v.tiles[k].pending));
  // The legacy 44.4% never appears anywhere in the headline.
  assert.doesNotMatch(JSON.stringify(v), /44\.4/);
});

test('lens baseline uses the anyFinding row, not the legacy blocking row', async () => {
  // In the real snapshot DVAA's enforce blocking and anyFinding recall are equal (65.6%), so perturb only
  // the blocking row: the Detected baseline must not move.
  const r = clone(LENS);
  r.detectors['dvaa-baseline'].modes.enforce.blocking.recall = 0.111;
  r.detectors['dvaa-baseline'].modes.enforce.blocking.falsePositiveRate = 0.999;
  const { v } = await viewOf(r);
  assert.equal(v.tiles.det.base, 'DVAA 65.6%');
  assert.equal(v.tiles.det.fp, 'FP 0.0% vs DVAA 12.8%');
  const ro = clone(LENS);
  ro.headline.mode = 'report-only';
  const { v: v2 } = await viewOf(ro);
  assert.equal(v2.tiles.det.base, `DVAA ${pct(LENS.detectors['dvaa-baseline'].modes['report-only'].anyFinding.recall)}`);
  assert.equal(v2.tiles.prev.base, 'DVAA 0.0%');
});

test('per-lens FP is not filled from the top-level (blocking-lens) falsePositiveRate', async () => {
  const r = clone(LENS);
  delete r.headlineLenses.detection.falsePositiveRate;
  r.falsePositiveRate = 0.5;
  const { v } = await viewOf(r);
  assert.equal(v.tiles.det.fp, 'FP n/a vs DVAA 12.8%');
});

test('lens fields read from headlineLenses when the top-level lens fields are absent', async () => {
  const r = clone(LENS);
  delete r.detectionRecall;
  delete r.preventionRecall;
  const { v } = await viewOf(r);
  assert.equal(v.legacy, false);
  assert.equal(v.tiles.det.value, pct(LENS.headlineLenses.detection.recall));
  assert.equal(v.tiles.prev.value, pct(LENS.headlineLenses.prevention.recall));
});

test('legacy shape: legacy recall is NEVER shown as Detected; both tiles n/a with a visible note', async () => {
  const raw = legacyOk();
  const { s, v } = await viewOf(raw);
  assert.equal(s.lensSource, 'legacy');
  assert.equal(s.detectionRecall, null);
  assert.equal(v.legacy, true);
  assert.deepEqual([v.tiles.det.value, v.tiles.prev.value], ['n/a', 'n/a']);
  assert.ok(v.tiles.det.pending && v.tiles.prev.pending);
  assert.match(v.lensNote, /detectionRecall \/ preventionRecall are absent/);
  assert.doesNotMatch(JSON.stringify(v), new RegExp(pct(raw.recall).replace('.', '\\.')), 'legacy recall appears nowhere');
  assert.doesNotMatch(`${v.tiles.det.base} ${v.tiles.prev.base} ${v.tiles.det.fp} ${v.tiles.prev.fp}`, /%/);
  assert.equal(v.tiles.lat.value, '0.067 ms');
});

test('legacy shape with non-ok headline.status (real origin/main snapshot): status replaces every number', async () => {
  const { v } = await viewOf(LEGACY_AWAITING);
  for (const k of TILE_KEYS) {
    assert.equal(v.tiles[k].value, 'awaiting t3');
    assert.equal(v.tiles[k].base, '');
    assert.equal(v.tiles[k].fp, '');
  }
  assert.ok(v.pending);
  assert.match(v.note, /T3 detector not present/);
  assert.doesNotMatch(allText(v), /%|ms/);
});

test('lens shape with non-ok headline.status: no rate or baseline is shown beside an errored run', async () => {
  const r = clone(LENS);
  r.headline.status = 'error: 15 cases errored';
  const { v } = await viewOf(r);
  assert.deepEqual(TILE_KEYS.map(k => v.tiles[k].value), ['error', 'error', 'error']);
  assert.doesNotMatch(allText(v), /%|ms|\d/);
  assert.match(v.note, /15 cases errored/);
});

test('missing pieces are shown as missing, never filled in', async () => {
  let r = clone(LENS);
  delete r.detectors['dvaa-baseline'];
  let { v } = await viewOf(r);
  assert.equal(v.tiles.det.value, '63.0%');
  for (const k of ['det', 'prev']) assert.equal(v.tiles[k].base, 'DVAA baseline not in results.json');
  assert.equal(v.tiles.det.fp, 'FP 0.0%');

  r = clone(LENS);
  delete r.detectors['dvaa-baseline'].modes.enforce.prevention;
  ({ v } = await viewOf(r));
  assert.equal(v.tiles.prev.base, 'DVAA n/a');
  assert.equal(v.tiles.prev.fp, 'FP 0.0% vs DVAA n/a');

  r = clone(LENS);
  delete r.preventionRecall;
  delete r.headlineLenses.prevention;
  ({ v } = await viewOf(r));
  assert.equal(v.legacy, false);
  assert.equal(v.tiles.prev.value, '—');
  assert.ok(v.tiles.prev.pending);
  assert.match(v.note, /missing from results.json: prev/);

  r = clone(LENS);
  r.detectionRecall = '0.9';
  r.headlineLenses.detection.recall = null;
  ({ v } = await viewOf(r));
  assert.equal(v.tiles.det.value, '—');
});

test('results.json larger than MAX_SCORING_BYTES is rejected loudly, never parsed partially', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'sentinel-lens-big-'));
  try {
    const file = path.join(dir, 'results.json');
    const fh = await open(file, 'w');
    await fh.truncate(BOUNDS.MAX_SCORING_BYTES + 1); // sparse: no 16 MiB write
    await fh.close();
    const errs = [];
    const orig = console.error;
    console.error = (...a) => errs.push(a.join(' '));
    let s;
    try { s = await loadScoring(index, { SENTINEL_SCORING_FILE: file }); } finally { console.error = orig; }
    assert.equal(s.available, false);
    assert.match(s.error, new RegExp(`size=${BOUNDS.MAX_SCORING_BYTES + 1} cap=${BOUNDS.MAX_SCORING_BYTES}`));
    assert.ok(errs.some(e => /ALERT .*MAX_SCORING_BYTES/.test(e)), 'server log ALERT');
    const v = headlineView(s);
    assert.ok(TILE_KEYS.every(k => v.tiles[k].value === 'ERROR'));
    assert.match(v.note, /MAX_SCORING_BYTES/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('page markup and controller carry all four headline tiles and the lens note', async () => {
  const html = await readFile(path.join(HERE, '..', 'public', 'index.html'), 'utf8');
  for (const id of ['tile-det', 'det-rate', 'det-base', 'det-fp', 'tile-prev', 'prev-rate', 'prev-base', 'prev-fp', 'tile-lat', 't7-lat', 'lat-base', 'lens-note']) {
    assert.match(html, new RegExp(`id="${id}"`), id);
  }
  const app = await readFile(path.join(HERE, '..', 'public', 'app.js'), 'utf8');
  assert.match(app, /\$\('lens-note'\)\.hidden = !v\.lensNote/);
});
