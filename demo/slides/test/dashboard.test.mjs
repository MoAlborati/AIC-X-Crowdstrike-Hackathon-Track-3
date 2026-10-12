// dashboard.test.mjs: the numbers dashboard (demo/slides/dashboard.html) derives every value from the committed files
// through deck-data.mjs, pairs each of ours with DVAA's, never hard-codes a scored number, and is built not to scroll.
//
// Run: node --test demo/slides/test/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as D from '../deck-data.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const read = (f) => fs.readFileSync(path.join(ROOT, f), 'utf8');
const raw = {};
for (const [k, f] of Object.entries(D.FILES)) raw[k] = f.endsWith('.json') ? JSON.parse(read(f)) : read(f);
const R = raw.scoring;
const model = D.deriveAll(raw);
const html = read('demo/slides/dashboard.html');
const DET = { t3: 't3', dvaa: 'dvaa-baseline' };

test('KPI strip equals sentinel/scoring/results.json, read independently, and every tile is paired', () => {
  const kpis = D.deriveKpis(model);
  assert.ok(kpis.length >= 4 && kpis.length <= 6);
  const by = Object.fromEntries(kpis.map((k) => [k.key, k]));
  for (const [who, d] of Object.entries(DET)) {
    const enf = R.detectors[d].modes.enforce;
    assert.deepEqual([by.detection[who].num, by.detection[who].den], [enf.anyFinding.tp, enf.anyFinding.positives]);
    assert.deepEqual([by.prevention[who].num, by.prevention[who].den], [enf.prevention.tp, enf.prevention.positives]);
    assert.deepEqual([by.benign[who].num, by.benign[who].den], [enf.prevention.fp, enf.prevention.negatives]);
    const ex = R.detectors[d].recallByPositiveKindPrevention.exfil;
    assert.deepEqual([by.exfil[who].num, by.exfil[who].den], [ex.tp, ex.positives]);
    assert.equal(by.latency[who].v, R.detectors[d].latencyMs.median);
  }
  const bb = R.beatsBaseline.byDetector.t3;
  assert.deepEqual([by.evasion.t3.num, by.evasion.t3.den], [bb.beaten, bb.eligible]);
  for (const k of kpis) {
    assert.ok(k.t3.ok, `${k.key} ours sourced: ${k.t3.src}`);
    assert.ok(k.dvaa.ok, `${k.key} DVAA sourced: ${k.dvaa.src}`);
    assert.ok(k.t3.src.startsWith(D.FILES.scoring) && k.dvaa.src.startsWith(D.FILES.scoring));
  }
  // The headline pairs the brief names, as text the page prints.
  assert.equal(`${D.fmt(by.benign.t3, 'frac')} vs ${D.fmt(by.benign.dvaa, 'frac')}`, `${R.detectors.t3.modes.enforce.prevention.fp}/164 vs ${R.detectors['dvaa-baseline'].modes.enforce.prevention.fp}/164`);
  for (const k of ['detection', 'prevention', 'benign', 'exfil']) assert.match(by[k].label, k === 'detection' ? /any finding/ : /request-side/);
  assert.match(by.latency.label, /in-detector, median/);
});

test('scored-corpus lens x kind selector equals results.json for every combination', () => {
  for (const lens of ['detection', 'prevention']) {
    for (const kind of ['all', 'exfil', 'injectionOnly']) {
      const p = D.deriveRecallByKind(R, lens, kind);
      for (const [who, d] of Object.entries(DET)) {
        const det = R.detectors[d];
        const want = kind === 'all'
          ? det.modes.enforce[lens === 'prevention' ? 'prevention' : 'anyFinding']
          : det[lens === 'prevention' ? 'recallByPositiveKindPrevention' : 'recallByPositiveKindAnyFinding'][kind];
        assert.ok(p[who].ok, `${lens}/${kind}/${who}: ${p[who].src}`);
        assert.deepEqual([p[who].num, p[who].den], [want.tp, want.positives], `${lens}/${kind}/${who}`);
      }
    }
  }
  // 'all' agrees with the deck's own headline derivation, and the per-kind numerators sum to it.
  for (const lens of ['detection', 'prevention']) {
    const all = D.deriveRecallByKind(R, lens, 'all');
    const ex = D.deriveRecallByKind(R, lens, 'exfil');
    const inj = D.deriveRecallByKind(R, lens, 'injectionOnly');
    for (const who of ['t3', 'dvaa']) {
      assert.deepEqual(all[who], model.scoring[lens][who].recall);
      assert.equal(ex[who].num + inj[who].num, all[who].num);
      assert.equal(ex[who].den + inj[who].den, all[who].den);
    }
  }
});

test('a missing results.json renders warnings naming file#key, never numbers', () => {
  const empty = D.deriveAll({});
  for (const k of D.deriveKpis(empty)) {
    for (const who of ['t3', 'dvaa']) assert.match(D.fmt(k[who], k.how), /^⚠ missing: sentinel\/scoring\/results\.json#/);
  }
  const p = D.deriveRecallByKind(undefined, 'prevention', 'exfil');
  assert.match(D.fmt(p.t3), /⚠ missing: .*recallByPositiveKindPrevention\.exfil\.tp/);
});

test('dashboard binds only sourced model paths and hard-codes no scored number', () => {
  const paths = [...html.matchAll(/data-m="([^"]+)"/g)].map((x) => x[1]);
  assert.ok(paths.length > 20);
  for (const p of paths) {
    const m = D.getPath(model, p);
    assert.ok(m && typeof m === 'object' && 'src' in m && m.ok, `data-m="${p}" is sourced`);
  }
  const markup = html.replace(/<!--[\s\S]*?-->/g, '').replace(/<script[\s\S]*?<\/script>/g, '');
  for (const lit of ['57/71', '64/71', '0/164', '21/164', '41.8', '63.0', '67.7', '65.6', '0.094', '12/370', '190/370']) {
    assert.ok(!markup.includes(lit), `dashboard markup hard-codes ${lit}`);
  }
  assert.match(html, /const DATA_ROOT = '\.\.\/\.\.\/'/);
  assert.match(html, /import\('\.\/deck-data\.mjs'\)/);
});

test('wording rules hold on the dashboard', () => {
  const markup = html.replace(/<!--[\s\S]*?-->/g, '');
  for (const banned of [/100% precision/i, /0% FP/i, /slice of Falcon AIDR/i, /\bintegrated\b/i, /nothing gets out/i]) {
    assert.ok(!banned.test(markup), `banned wording: ${banned}`);
  }
  assert.match(markup, /labelled by DVAA's ground truth and the published benchmarks/);
  assert.match(markup, /egress is not in the scored harness/i);
  assert.match(markup, /UNSCORED \/ REPLAY/);
  assert.match(markup, /Policy replay \(not a live run\)/);
  assert.match(markup, /numbers: <span class="mono">sentinel\/scoring\/results\.json<\/span> · generated <span data-m="scoring\.generatedAt">/);
});

test('one screen: fixed 100vh grid, overflow hidden, clamp() type, six keyboard tabs with a hash', () => {
  assert.match(html, /html, body \{[^}]*height: 100%; overflow: hidden;/);
  assert.match(html, /height: 100vh; display: grid; grid-template-rows: auto auto auto minmax\(0, 1fr\) auto;/);
  assert.match(html, /main \{ min-height: 0; overflow: hidden;/);
  assert.match(html, /--fs: clamp\(/);
  for (const id of ['scored', 'heldout', 'egress', 'contrast', 'opsbot', 'alert']) assert.match(html, new RegExp(`id: '${id}'`));
  assert.match(html, /\^\[1-6\]\$/);
  assert.match(html, /ArrowRight/);
  assert.match(html, /history\.replaceState/);
  assert.ok(!/https?:\/\/(?!127\.0\.0\.1)/.test(html.replace(/<!--[\s\S]*?-->/g, '')), 'no external URLs (offline)');
});

test('deck links to the dashboard and serve-deck.sh prints its URL', () => {
  assert.match(read('demo/slides/deck.html'), /href="dashboard\.html"/);
  assert.match(read('demo/slides/serve-deck.sh'), /\/demo\/slides\/dashboard\.html/);
});
