// Default verdict source: the REAL T3 detector core (sentinel/detectors, merged in #24), wired through its
// own T2 inspector adapter `sentinelInspector()`. The stand-in inspectors (standin.mjs) are an explicitly
// flagged fallback only (`cli.mjs live --standin`).
//
// Two T3 contract details the pipeline has to handle:
//
// 1. Canaries are carried SECRET-FREE as {id, sha256}. T4's buildAlert needs the value to hash and redact,
//    so convert.mjs calls `toAlertVerdict(finding)` (T3's registry lookup by id) right before buildAlert.
//    An id the registry does not know throws: an unredactable verdict fails loud and is never rendered.
//
// 2. Response-side findings arrive as `flagged: false, alert: true` (DVAA runs tools in-process, so the
//    reply is evidence, not prevention). Since #41 the T2 proxy records these alert-only verdicts in the
//    exchange record itself (and emits a `detector_alert` alert record), so the pipeline no longer parks
//    them. Parking them as well produced every response-side alert twice. `convert`/`tail` over a JSONL
//    written by the stock proxy CLI therefore see the same alert-only verdicts as the live path.

import { createDetector, sentinelInspector, DVAA_HONEYTOKENS } from '../detectors/index.js';

export const T3_DETECTOR = 'sentinel-t3';

/** T3 honeytokens as the pipeline's {id, value} canary list (for T4 redaction of every alert). */
export const T3_CANARIES = Object.freeze(DVAA_HONEYTOKENS.map(({ id, value }) => Object.freeze({ id, value })));

/**
 * @param {{detector?: object, detectorOptions?: object}} [opts]
 * @returns {{inspectors: Function[], detector: object, toAlertVerdict: Function}}
 */
export function createT3Source({ detector, detectorOptions = {} } = {}) {
  const det = detector ?? createDetector({ honeytokens: DVAA_HONEYTOKENS, ...detectorOptions });
  const inner = sentinelInspector({ detector: det });
  // Named so the proxy's verdict `detector` fallback and logs read 'sentinelT3'; T3 sets `detector` itself.
  async function sentinelT3(ctx) {
    return inner(ctx);
  }
  return {
    inspectors: [sentinelT3],
    detector: det,
    toAlertVerdict: (finding) => det.toAlertVerdict(finding),
  };
}

/** Rehydrator only (convert/tail): T3's registry, no inspection. */
export function t3Rehydrator() {
  const det = createDetector({ honeytokens: DVAA_HONEYTOKENS });
  return { toAlertVerdict: (finding) => det.toAlertVerdict(finding) };
}
