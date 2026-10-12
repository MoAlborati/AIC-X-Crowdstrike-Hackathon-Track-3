import { mkdtempSync, mkdirSync, writeFileSync, cpSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { REPO_ROOT } from '../src/corpus.mjs';
import { dvaaBaselineDetector } from '../src/detectors.mjs';

export { REPO_ROOT };

/** A scratch repo root with copies of the real captures (T1 + T6), for failure-mode tests. */
export function scratchRoot({ withT6 = true } = {}) {
  const root = mkdtempSync(path.join(tmpdir(), 't7-root-'));
  cpSync(path.join(REPO_ROOT, 'captures', 'attack'), path.join(root, 'captures', 'attack'), { recursive: true });
  cpSync(path.join(REPO_ROOT, 'captures', 'benign'), path.join(root, 'captures', 'benign'), { recursive: true });
  if (withT6) cpSync(path.join(REPO_ROOT, 'captures', 'variants'), path.join(root, 'captures', 'variants'), { recursive: true });
  return root;
}

export function writeJson(file, obj) {
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, JSON.stringify(obj));
}

/** Real DVAA baseline, or null with a loud note (the suite then skips only the DVAA-dependent asserts). */
export async function realDvaa() {
  const d = await dvaaBaselineDetector();
  if (!d.available) {
    console.error(`[t7-tests] REAL DVAA NOT AVAILABLE — ${d.unavailableReason}. DVAA-baseline assertions skipped.`);
    return null;
  }
  return d;
}

/** Test-only detector: an inline harness detector built from a function over the case. */
export function fnDetector(name, fn, kind = 'candidate') {
  return { name, kind, description: `test detector ${name}`, available: true, provenance: { test: true }, inspect: fn };
}
