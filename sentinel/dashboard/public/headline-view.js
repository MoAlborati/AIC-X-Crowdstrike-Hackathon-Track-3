// Pure view model for the headline pair (detection rate | benign FP rate). No DOM, so it is unit-tested.
// T7's results.json carries `headline.status` ("ok", "awaiting t3: …", "error: N cases errored", …).
// Any status other than "ok" is shown in place of the rates: a bare "—" would hide WHY there is no
// number, and rates next to an error status would present a bad run as a real score.
import { pct } from './replay-view.js';

/** @returns {{det:string, fp:string, pending:boolean, note:string}} */
export function headlineView(s) {
  if (!s?.available) {
    const c = s?.corpus ?? {};
    return {
      det: 'awaiting T7', fp: 'awaiting T7', pending: true,
      note: `${s?.error ? `ERROR ${s.error}. ` : 'No scoring results yet; rates are not estimated. '}Corpus on disk: ${c.attack ?? 0} attack, ${c.benign ?? 0} benign, ${c.placeholder ?? 0} placeholder.`,
    };
  }
  const counts = s.counts ? ` · ${JSON.stringify(s.counts)}` : '';
  const status = typeof s.status === 'string' && s.status.trim() ? s.status.trim() : null;
  if (status && status.toLowerCase() !== 'ok') {
    // Short form in the tile ("awaiting t3"), full reason in the note.
    const short = status.split(':')[0].trim();
    return { det: short, fp: short, pending: true, note: `T7 headline status: ${status} · ${s.file}${counts}` };
  }
  const det = pct(s.detectionRate);
  const fp = pct(s.fpRate);
  const missing = det === '—' || fp === '—';
  return {
    det, fp, pending: missing,
    note: `T7 scoring · ${s.file}${missing ? ' · a rate is missing from results.json (no headline.status given)' : ''}${counts}`,
  };
}
