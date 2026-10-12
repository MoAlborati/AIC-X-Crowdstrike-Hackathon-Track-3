// Pure view model for the headline row. No DOM, so it is unit-tested.
// Tiles: detection recall | prevention recall | benign FP rate | median latency. Each rate sits next to
// the DVAA baseline for the same lens.
// - Lens shape (T7 PR #28): detectionRecall + preventionRecall.
// - Legacy shape: only `recall`. It fills the detection tile, prevention reads "n/a", and `lensNote`
//   is a visible note saying the lens fields are absent. No number is ever estimated.
// T7's `headline.status` ("ok", "awaiting t3: …", "error: N cases errored", …): any status other than
// "ok" replaces every number. A bare "—" would hide WHY there is no number, and rates next to an error
// status would present a bad run as a real score.
import { pct } from './replay-view.js';

export const TILE_KEYS = ['det', 'prev', 'fp', 'lat'];

export function fmtMs(x) {
  if (!Number.isFinite(x)) return '—';
  if (x < 1) return `${x.toFixed(3)} ms`;
  if (x < 100) return `${x.toFixed(1)} ms`;
  return `${Math.round(x)} ms`;
}

// Subtitle under each tile label. In legacy mode the detection tile holds T7's legacy `recall`, which
// counts rule-intent blocks, not any finding, so its subtitle says that instead.
export const SUBS = { det: 'any finding fired', prev: 'blocked before forwarding', fp: 'lower is better', lat: 'per case, full corpus' };
const LEGACY_DET_SUB = 'LEGACY recall: rule-intent block';

const tile = (value, base = '', pending = false) => ({ value, base, pending });
const allTiles = (value, pending) => Object.fromEntries(TILE_KEYS.map(k => [k, { ...tile(value, '', pending), sub: SUBS[k] }]));

function view(tiles, note, lensNote = null, legacy = false) {
  const pending = TILE_KEYS.every(k => tiles[k].pending);
  // `det` / `fp` mirror the tile values for older callers.
  return { tiles, det: tiles.det.value, fp: tiles.fp.value, pending, legacy, lensNote, note };
}

/**
 * @returns {{tiles: Record<'det'|'prev'|'fp'|'lat', {value:string, base:string, pending:boolean}>,
 *            det:string, fp:string, pending:boolean, legacy:boolean, lensNote:string|null, note:string}}
 */
export function headlineView(s) {
  if (!s?.available) {
    const c = s?.corpus ?? {};
    const value = s?.error ? 'ERROR' : 'awaiting T7';
    return view(allTiles(value, true),
      `${s?.error ? `ERROR ${s.error}. ` : 'No scoring results yet; rates are not estimated. '}Corpus on disk: ${c.attack ?? 0} attack, ${c.benign ?? 0} benign, ${c.placeholder ?? 0} placeholder.`);
  }
  const counts = s.counts ? ` · ${Object.entries(s.counts).map(([k, v]) => `${k} ${v}`).join(', ')}` : '';
  const status = typeof s.status === 'string' && s.status.trim() ? s.status.trim() : null;
  if (status && status.toLowerCase() !== 'ok') {
    // Short form in the tiles ("awaiting t3"), full reason in the note.
    const short = status.split(':')[0].trim();
    return view(allTiles(short, true), `T7 headline status: ${status} · ${s.file}${counts}`);
  }

  const legacy = s.lensSource === 'legacy';
  const b = s.baseline ?? {};
  const baseTxt = (x, fmt = pct) => (b.available ? `DVAA baseline ${Number.isFinite(x) ? fmt(x) : 'n/a'}` : 'DVAA baseline not in results.json');
  const rate = (x) => { const v = pct(x); return tile(v, '', v === '—'); };

  const det = rate(s.detectionRecall);
  det.base = baseTxt(b.detection);
  let prev;
  if (legacy) {
    prev = tile('n/a', 'needs T7 preventionRecall', true);
  } else {
    prev = rate(s.preventionRecall);
    prev.base = baseTxt(b.prevention);
  }
  const fp = rate(s.fpRate);
  fp.base = baseTxt(b.fpRate);
  const latV = fmtMs(s.latencyMs?.median);
  const lat = tile(latV, '', latV === '—');
  lat.base = [
    Number.isFinite(s.latencyMs?.p95) ? `p95 ${fmtMs(s.latencyMs.p95)}` : null,
    b.available && Number.isFinite(b.latencyMedianMs) ? `DVAA ${fmtMs(b.latencyMedianMs)}` : null,
  ].filter(Boolean).join(' · ');

  const tiles = { det, prev, fp, lat };
  for (const k of TILE_KEYS) tiles[k].sub = SUBS[k];
  if (legacy) det.sub = LEGACY_DET_SUB;
  const missing = TILE_KEYS.filter(k => k !== 'prev' || !legacy).filter(k => tiles[k].pending);
  const lensNote = legacy
    ? `Legacy T7 results: detectionRecall / preventionRecall absent. Detection shows legacy \`recall\` (${s.baseline?.metric ?? 'blocking'} metric); prevention is not reported.`
    : null;
  const note = `T7 scoring · ${s.file}`
    + (!legacy && Number.isFinite(s.legacyRecall) ? ` · legacy block recall ${pct(s.legacyRecall)}` : '')
    + (Number.isFinite(s.precision) ? ` · precision ${pct(s.precision)}` : '')
    + (missing.length ? ` · missing from results.json: ${missing.join(', ')}` : '')
    + counts;
  return view(tiles, note, lensNote, legacy);
}
