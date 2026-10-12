// Where detector verdicts (T4 alerts) for a capture come from, in priority order:
//   1. alerts embedded in the capture itself: `alerts: [...]` on a single-run capture (T6 variants),
//      or `alerts: { <runKey>: [...] }` on any capture. capture-loader normalizes both to a per-run
//      map and rejects a flat array on a multi-run capture as ambiguous (422), never 0 alerts.
//      A run absent from the map falls through to the sidecars below.
//   2. $SENTINEL_ALERTS_DIR/<capture-id>.alerts.json
//   3. sentinel/scoring/alerts/<capture-id>.alerts.json   (expected T3/T7 replay output)
//   4. sentinel/dashboard/fixtures/alerts/<capture-id>.alerts.json   (PLACEHOLDER, only with ?dev=1)
//   5. sentinel/dashboard/alerts/<capture-id>.alerts.json   (real T3 replay verdicts, fixtures/make-real-alerts.mjs)
// The capture id's '/' becomes '__' in the filename. Sidecar shape:
//   { captureId, placeholder?: bool, note?: string, runs: { <runKey>: [<T4 alert>, ...] } }
// A run with no sidecar has no detector verdicts. The UI then shows "no detector verdicts recorded"
// and the dvaa{} ground truth, clearly labeled as such. It never presents ground truth as a detection.

import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { DASHBOARD_DIR, REPO_ROOT, CaptureFormatError } from './capture-loader.mjs';
import { enforce } from './bounds.mjs';

export function alertDirs(env = process.env) {
  const dirs = [];
  if (env.SENTINEL_ALERTS_DIR) dirs.push({ dir: env.SENTINEL_ALERTS_DIR, placeholder: false });
  dirs.push({ dir: path.join(REPO_ROOT, 'sentinel', 'scoring', 'alerts'), placeholder: false });
  if (!env.SENTINEL_HIDE_PLACEHOLDERS) dirs.push({ dir: path.join(DASHBOARD_DIR, 'fixtures', 'alerts'), placeholder: true });
  // Real T3 verdicts over the recorded stage traffic (fixtures/make-real-alerts.mjs). Never placeholder.
  // Last, so ?dev=1 still shows the placeholder fixtures where they exist; the stage view (no ?dev=1)
  // filters placeholder dirs out and lands here.
  dirs.push({ dir: path.join(DASHBOARD_DIR, 'alerts'), placeholder: false });
  return dirs;
}

export const sidecarName = (captureId) => `${captureId.replace(/\//g, '__')}.alerts.json`;

/** @returns {Promise<{alerts: object[], origin: string, placeholder: boolean, note: string|null}>} */
export async function alertsFor(capture, runKey, dirs = alertDirs()) {
  const embedded = capture.alerts?.[runKey];
  if (embedded) {
    return { alerts: embedded, origin: 'embedded in capture', placeholder: capture.placeholder, note: null };
  }
  for (const { dir, placeholder } of dirs) {
    const file = path.join(dir, sidecarName(capture.id));
    let st;
    try {
      st = await stat(file);
    } catch (err) {
      if (err.code === 'ENOENT') continue;
      throw err;
    }
    enforce('MAX_CAPTURE_BYTES', st.size, `alert sidecar ${file}`);
    const rel = path.relative(REPO_ROOT, file);
    let doc;
    try {
      doc = JSON.parse(await readFile(file, 'utf8'));
    } catch (err) {
      if (!(err instanceof SyntaxError)) throw err;
      // Same contract as a malformed capture: 422 naming the file, never a generic 500.
      throw new CaptureFormatError(capture.id, `alert sidecar ${rel}: invalid JSON: ${err.message}`);
    }
    const list = doc?.runs?.[runKey];
    if (list === undefined) continue; // sidecar exists but has nothing for this run
    if (!Array.isArray(list)) throw new CaptureFormatError(capture.id, `alert sidecar ${rel}: runs.${runKey} is not an array`);
    return {
      alerts: list,
      origin: path.relative(REPO_ROOT, file),
      placeholder: placeholder || doc.placeholder === true,
      note: doc.note ?? null,
    };
  }
  return { alerts: [], origin: 'none', placeholder: false, note: null };
}
