// T10 alert pipeline core: T2 proxy capture records in, T5-readable captures + T4 sidecars out.
//
//   const p = createPipeline({ outDir });
//   await p.init();
//   await p.ingest(record, lineNo);   // any T2 record: 'exchange' or 'alert'
//   await p.flush();                 // write changed parts (tail/live call this per record)
//
// Record handling:
//   exchange                  -> capture exchange + one T4 alert per flagged verdict (both directions)
//   request (write-ahead)     -> counted only; its exchange record follows
//   alert reason=flagged      -> duplicate of the exchange's verdicts. Held until that exchange
//                                arrives, then dropped. If the exchange never comes
//                                (capture_write_failed), it is converted on its own (orphan alerts).
//   alert request/response_too_large -> T4 `scan_cap_exceeded` alert, attached to the exchange
//   any other alert           -> operational (upstream_error, inspector_error, …): written to
//                                ops-alerts.jsonl and logged. Not a detection, and never dropped silently.

import { BOUNDS, enforce, defaultLog, resolveCaps } from './bounds.mjs';
import { alertsForExchange, alertsForProxyAlert, agentOf, parseJsonBody, sessionOf, inspectedBody } from './convert.mjs';
import { OutputStore } from './store.mjs';

export function createPipeline({ outDir, caps: capOverrides, log = defaultLog, canaries = [], proxyCapturePath = null, onWarning, t3 = null } = {}) {
  if (!outDir) throw new Error('createPipeline: outDir is required');
  const caps = capOverrides ? resolveCaps(capOverrides) : BOUNDS;
  const store = new OutputStore({ outDir, caps, log, proxyCapturePath });
  const pending = new Map(); // request_id -> [{record, line}]
  const warnings = [];
  const warn = onWarning ?? ((msg, detail) => { warnings.push({ msg, detail }); log({ level: 'WARN', reason: 't4_alert_field_bounded', msg, detail }); });
  let chain = Promise.resolve();
  let records = 0;
  let writeAhead = 0;

  const ctxFor = (session, line, extra = {}) => ({
    session,
    canaries,
    t3,
    onWarning: warn,
    captureRef: proxyCapturePath ? { path: proxyCapturePath, line } : { path: null, line },
    ...extra,
  });

  function holdAlert(record, line) {
    const list = pending.get(record.request_id) ?? [];
    list.push({ record, line });
    pending.set(record.request_id, list);
    enforce('MAX_PENDING_ALERTS', pending.size, 'proxy alert records waiting for their exchange record', caps, log);
  }

  function orphan(requestId, extra = {}) {
    const held = pending.get(requestId) ?? [];
    pending.delete(requestId);
    const session = extra.session ?? 'proxy-unattributed';
    const alerts = [];
    for (const { record, line } of held) {
      if (record.reason === 'flagged') {
        // Rebuild an exchange-shaped record from the alert so the same converter applies.
        const pseudo = { ...record, target: extra.target, verdicts: (record.verdicts ?? []).map((v) => ({ phase: record.phase, ...v })), action: record.action === 'blocked' ? `blocked_${record.phase}` : 'forwarded' };
        alerts.push(...alertsForExchange(pseudo, ctxFor(session, line)));
      } else {
        alerts.push(...alertsForProxyAlert(record, ctxFor(session, line, { target: extra.target })));
      }
    }
    if (alerts.length) {
      log({ level: 'ALERT', reason: 'alerts_without_exchange', request_id: requestId, alerts: alerts.length, action: 'written_as_orphan_alerts' });
      store.addOrphanAlerts({ session, agent: { name: 'unknown agent', id: 'unknown' }, alerts });
    }
  }

  async function handle(record, line) {
    records += 1;
    if (!record || typeof record !== 'object') throw new Error(`line ${line}: record is not an object`);
    if (record.type === 'exchange') {
      const reqJson = parseJsonBody(inspectedBody(record.request));
      const session = sessionOf(record, reqJson);
      const resJson = parseJsonBody(inspectedBody(record.upstream_response ?? record.response));
      const agent = agentOf(record, resJson);
      enforce('MAX_VERDICTS_PER_EXCHANGE', (record.verdicts ?? []).length, `exchange ${record.request_id}`, caps, log);
      const alerts = alertsForExchange(record, ctxFor(session, line));
      enforce('MAX_VERDICTS_PER_EXCHANGE', alerts.length, `alerts built for exchange ${record.request_id}`, caps, log);
      // Held proxy alerts for this request: scan-cap ones become detections, `flagged` ones are
      // duplicates of the verdicts above and are dropped here on purpose.
      for (const { record: a, line: aLine } of pending.get(record.request_id) ?? []) {
        alerts.push(...alertsForProxyAlert(a, { ...ctxFor(session, aLine), agent, target: record.target }));
      }
      pending.delete(record.request_id);
      store.addExchange({ session, agent, record, alerts, line });
      return;
    }
    if (record.type === 'request') {
      // T2 write-ahead record: the request is on disk before the agent runs. The matching exchange
      // record carries the same request plus the response, so there is nothing to convert yet.
      writeAhead += 1;
      return;
    }
    if (record.type === 'alert') {
      const entry = { level: 'ALERT', source: 'proxy', line, ...record };
      if (record.reason === 'flagged' || record.reason === 'request_too_large' || record.reason === 'response_too_large') {
        if (record.request_id) { holdAlert(record, line); return; }
      }
      if (record.reason === 'capture_write_failed' && record.request_id && pending.has(record.request_id)) {
        orphan(record.request_id);
      }
      // Operational alert: never a T4 detection, never silent.
      await store.recordOps({ source: 'proxy', line, ...record });
      if (record.reason !== 'flagged') log(entry);
      return;
    }
    throw new Error(`line ${line}: unknown record type ${JSON.stringify(record.type)}`);
  }

  return {
    store,
    caps,
    warnings,
    init: (opts) => store.init(opts),
    /** Serialized: concurrent callers (the live proxy sink) never interleave. */
    ingest(record, line = null) {
      const p = chain.then(() => handle(record, line));
      chain = p.catch(() => {});
      return p;
    },
    async flush() {
      await chain;
      return store.flush();
    },
    /** End of input: anything still pending had no exchange, so convert it on its own. */
    async finish() {
      await chain;
      for (const id of [...pending.keys()]) orphan(id);
      return store.flush();
    },
    stats: () => ({ records, writeAhead, pending: pending.size, ...store.stats() }),
  };
}
