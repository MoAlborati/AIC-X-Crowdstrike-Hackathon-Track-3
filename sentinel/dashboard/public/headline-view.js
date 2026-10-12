// Pure view model for the headline row. No DOM, so it is unit-tested.
// One consistent metrics set, read from T7 results.json lens fields only:
//   Detected  X%  (detectionRecall: any finding fired)      DVAA x% · FP a% vs DVAA b%
//   Prevented Y%  (preventionRecall: pre-forward prevents)  DVAA y% · FP c% vs DVAA d%
//   In-detector latency (latencyMs.median of the candidate detector, p95 underneath)
// The FP pair under each tile is that lens's own benign FP rate (headlineLenses.<lens>.falsePositiveRate)
// against DVAA's FP rate on the same lens.
// Legacy shape (no lens fields): both rate tiles read "n/a" with a visible note. T7's legacy `recall`
// (rule-intent block lens) is never shown as "Detected" (mock-judge finding: it was mislabeled).
// T7's `headline.status`: any status other than "ok" replaces every number.
import { pct } from './replay-view.js';

export const TILE_KEYS = ['det', 'prev', 'lat'];
export const SUBS = { det: 'any finding fired', prev: 'stopped before forwarding', lat: 'median per case, detector only' };

export function fmtMs(x) {
  if (!Number.isFinite(x)) return '—';
  if (x < 1) return `${x.toFixed(3)} ms`;
  if (x < 100) return `${x.toFixed(1)} ms`;
  return `${Math.round(x)} ms`;
}

const tile = (k, value, pending, base = '', fp = '') => ({ value, base, fp, pending, sub: SUBS[k] });
const allTiles = (value) => Object.fromEntries(TILE_KEYS.map(k => [k, tile(k, value, true)]));

function view(tiles, note, lensNote = null, legacy = false) {
  const pending = TILE_KEYS.every(k => tiles[k].pending);
  return { tiles, det: tiles.det.value, prev: tiles.prev.value, pending, legacy, lensNote, note };
}

/**
 * @returns {{tiles: Record<'det'|'prev'|'lat', {value:string, base:string, fp:string, pending:boolean, sub:string}>,
 *            det:string, prev:string, pending:boolean, legacy:boolean, lensNote:string|null, note:string}}
 */
export function headlineView(s) {
  if (!s?.available) {
    const c = s?.corpus ?? {};
    return view(allTiles(s?.error ? 'ERROR' : 'awaiting T7'),
      `${s?.error ? `ERROR ${s.error}. ` : 'No scoring results yet; rates are not estimated. '}Corpus on disk: ${c.attack ?? 0} attack, ${c.benign ?? 0} benign, ${c.placeholder ?? 0} placeholder.`);
  }
  const counts = s.counts ? ` · ${Object.entries(s.counts).map(([k, v]) => `${k} ${v}`).join(', ')}` : '';
  const status = typeof s.status === 'string' && s.status.trim() ? s.status.trim() : null;
  if (status && status.toLowerCase() !== 'ok') {
    const short = status.split(':')[0].trim();
    return view(allTiles(short), `T7 headline status: ${status} · ${s.file}${counts}`);
  }

  const b = s.baseline ?? {};
  const fin = Number.isFinite;
  const lat = tile('lat', fmtMs(s.latencyMs?.median), !fin(s.latencyMs?.median), fin(s.latencyMs?.p95) ? `p95 ${fmtMs(s.latencyMs.p95)}` : '');

  if (s.lensSource === 'legacy') {
    const tiles = {
      det: tile('det', 'n/a', true, 'needs T7 detectionRecall'),
      prev: tile('prev', 'n/a', true, 'needs T7 preventionRecall'),
      lat,
    };
    return view(tiles,
      `T7 scoring · ${s.file}${counts}`,
      'Legacy T7 results.json: detectionRecall / preventionRecall are absent, so no Detected / Prevented numbers are shown. Re-run T7 scoring (PR #28) to fill them.',
      true);
  }

  const rateTile = (k, x, bx, fpx, bfpx) => {
    const v = pct(x);
    const base = b.available ? `DVAA ${fin(bx) ? pct(bx) : 'n/a'}` : 'DVAA baseline not in results.json';
    const fp = `FP ${fin(fpx) ? pct(fpx) : 'n/a'}${b.available ? ` vs DVAA ${fin(bfpx) ? pct(bfpx) : 'n/a'}` : ''}`;
    return tile(k, v, v === '—', base, fp);
  };
  const tiles = {
    det: rateTile('det', s.detectionRecall, b.detection, s.lensFp?.detection, b.fpDetection),
    prev: rateTile('prev', s.preventionRecall, b.prevention, s.lensFp?.prevention, b.fpPrevention),
    lat,
  };
  const missing = TILE_KEYS.filter(k => tiles[k].pending);
  const note = `T7 scoring · ${s.file}`
    + (missing.length ? ` · missing from results.json: ${missing.join(', ')}` : '')
    + counts;
  return view(tiles, note, null, false);
}
