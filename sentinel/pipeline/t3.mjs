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
//    reply is evidence, not prevention). The T2 proxy records only FLAGGED verdicts in its exchange
//    record, so these would be dropped. The wrapper below parks each alert-only verdict by request id in a
//    bounded map, and PipelineSink merges it into that request's exchange record before it is written
//    (tagged `recordedBy: 'sentinel-pipeline'`). The reply is still delivered: the proxy sees the same
//    unflagged verdict T3 returned. Bound: MAX_PENDING_ALERTS request ids; overflow throws
//    PipelineBoundError, which the proxy turns into a fail-closed inspector error. Nothing is dropped.
//    Limitation: `convert`/`tail` over a JSONL written by the STOCK proxy CLI only see flagged verdicts.

import { createDetector, sentinelInspector, DVAA_HONEYTOKENS } from '../detectors/index.js';
import { BOUNDS, PipelineBoundError } from './bounds.mjs';

export const T3_DETECTOR = 'sentinel-t3';

/** T3 honeytokens as the pipeline's {id, value} canary list (for T4 redaction of every alert). */
export const T3_CANARIES = Object.freeze(DVAA_HONEYTOKENS.map(({ id, value }) => Object.freeze({ id, value })));

/**
 * @param {{detector?: object, caps?: object, detectorOptions?: object}} [opts]
 * @returns {{inspectors: Function[], detector: object, toAlertVerdict: Function, takeAlertOnly: Function, pendingAlertOnly: Function}}
 */
export function createT3Source({ detector, caps = BOUNDS, detectorOptions = {} } = {}) {
  const det = detector ?? createDetector({ honeytokens: DVAA_HONEYTOKENS, ...detectorOptions });
  const inner = sentinelInspector({ detector: det });
  const alertOnly = new Map(); // requestId -> [phase-tagged verdict]

  async function sentinelT3(ctx) {
    const v = await inner(ctx);
    if (v && v.flagged !== true && v.alert === true) {
      const list = alertOnly.get(ctx.requestId);
      if (!list && alertOnly.size >= caps.MAX_PENDING_ALERTS) {
        throw new PipelineBoundError('MAX_PENDING_ALERTS', alertOnly.size + 1, caps.MAX_PENDING_ALERTS, 'T3 alert-only verdicts waiting for their exchange record');
      }
      const next = [...(list ?? []), { phase: ctx.phase, ...v, recordedBy: 'sentinel-pipeline' }];
      if (next.length > caps.MAX_VERDICTS_PER_EXCHANGE) {
        throw new PipelineBoundError('MAX_VERDICTS_PER_EXCHANGE', next.length, caps.MAX_VERDICTS_PER_EXCHANGE, `T3 alert-only verdicts for request ${ctx.requestId}`);
      }
      alertOnly.set(ctx.requestId, next);
    }
    return v;
  }

  return {
    inspectors: [sentinelT3],
    detector: det,
    toAlertVerdict: (finding) => det.toAlertVerdict(finding),
    /** Remove and return the alert-only verdicts parked for a request (empty when none). */
    takeAlertOnly(requestId) {
      const list = alertOnly.get(requestId) ?? [];
      alertOnly.delete(requestId);
      return list;
    },
    pendingAlertOnly: () => alertOnly.size,
  };
}

/** Rehydrator only (convert/tail): T3's registry, no inspection. */
export function t3Rehydrator() {
  const det = createDetector({ honeytokens: DVAA_HONEYTOKENS });
  return { toAlertVerdict: (finding) => det.toAlertVerdict(finding) };
}
