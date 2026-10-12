// The inspector set the shipped proxy CLI registers: T3's detector composed with the T2 substring
// inspector.
//
//   [ substringInspector(flagSubstrings), t3 ]
//
// Why both: T3's sentinelInspector() only looks at chat paths (/v1/chat/completions, /chat/completions)
// and at bodies. The substring inspector also scans every path, the URL in all decoded spellings, and the
// header block, so composing them keeps that coverage.
//
// T3 is configured from the proxy config:
//   - honeytokens: T3's DVAA_HONEYTOKENS plus every inspect.flagSubstrings entry.
//   - agent: the proxied target port.
//   - bounds.timeBudgetMs: derived from limits.inspectorTimeoutMs. It is set to 80% of the proxy deadline,
//     and never above T3's own default. That way a slow scan becomes T3's fail-closed BLOCK, with reason
//     codes, before the proxy's generic inspector_timeout fires. This setting only tightens T3's budget.
//   - The proxy's abort `signal` is passed through. T3's inspect() is synchronous, so the signal is
//     checked before the call, and a deadline that already fired is not answered with a stale verdict.
//   - logger: T3's ERROR/WARN lines go through the same log scrubber as proxy alerts, so they are
//     redacted before they reach stderr.
//
// The same honeytoken list is returned as `canaries`. createProxy uses it for log redaction.

import { sentinelInspector, DVAA_HONEYTOKENS, DEFAULT_BOUNDS } from '../detectors/index.js';
import { substringInspector, flagSubstringId } from './inspectors.mjs';

export const T3_TIME_BUDGET_FRACTION = 0.8;

export function t3TimeBudgetMs(inspectorTimeoutMs) {
  return Math.max(1, Math.min(DEFAULT_BOUNDS.timeBudgetMs, Math.floor(inspectorTimeoutMs * T3_TIME_BUDGET_FRACTION)));
}

/** Honeytokens shared by T3 detection and proxy log redaction. Ids are unique. */
export function defaultCanaries(config) {
  const seen = new Set();
  const out = [];
  const all = [
    ...DVAA_HONEYTOKENS.map((t) => ({ id: t.id, value: t.value })),
    ...config.inspect.flagSubstrings.map((value, i) => ({ id: flagSubstringId(i), value })),
  ];
  for (const c of all) {
    if (seen.has(c.value)) continue; // a flagSubstring equal to a DVAA token keeps the DVAA id
    seen.add(c.value);
    out.push(c);
  }
  return out;
}

/**
 * @param {object} config validated proxy config
 * @param {{scrub?: (v:any)=>any, write?: (line:string)=>void, detectorOpts?: object}} [opts]
 * @returns {{inspectors: Function[], canaries: Array<{id:string,value:string}>, t3: Function}}
 */
export function buildDefaultInspectors(config, opts = {}) {
  const canaries = defaultCanaries(config);
  const scrub = opts.scrub ?? ((v) => v);
  const write = opts.write ?? ((line) => process.stderr.write(line));
  const logger = {
    error: (o) => write(`[sentinel] T3 ERROR ${JSON.stringify(scrub(o))}\n`),
    warn: (o) => write(`[sentinel] T3 WARN ${JSON.stringify(scrub(o))}\n`),
  };
  const inner = sentinelInspector({
    honeytokens: canaries,
    agent: { port: config.target.port },
    bounds: { timeBudgetMs: t3TimeBudgetMs(config.limits.inspectorTimeoutMs) },
    logger,
    ...(opts.detectorOpts ?? {}),
  });
  async function t3(ctx) {
    if (ctx.signal?.aborted) throw ctx.signal.reason ?? new Error('inspector deadline passed');
    return inner(ctx);
  }
  t3.detector = inner.detector;
  return { inspectors: [substringInspector(config.inspect.flagSubstrings), t3], canaries, t3 };
}
