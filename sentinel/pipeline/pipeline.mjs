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
//   alert reason=flagged|detector_alert -> duplicate of the exchange's verdicts (detector_alert = #41's
//                                alert-only verdicts, e.g. T3 response-side). Held until that exchange
//                                arrives, then dropped. If the exchange never comes
//                                (capture_write_failed), it is converted on its own (orphan alerts).
//   alert request/response_too_large -> T4 `scan_cap_exceeded` alert, attached to the exchange
//   any other alert           -> operational (upstream_error, inspector_error, …): written to
//                                ops-alerts.jsonl and logged. Not a detection, and never dropped silently.

import { BOUNDS, enforce, defaultLog, resolveCaps } from './bounds.mjs';
import { alertsForExchange, alertsForProxyAlert, agentOf, parseJsonBody, sessionOf, inspectedBody } from './convert.mjs';
import { OutputStore } from './store.mjs';
import { isEgressRecord, alertForEgress, correlate, EGRESS_SESSION, EGRESS_AGENT } from './egress.mjs';

// Proxy alert reasons whose verdicts are also on the request's exchange record (T2 #14, #41).
const DUPLICATE_OF_EXCHANGE = new Set(['flagged', 'detector_alert']);

export function createPipeline({ outDir, caps: capOverrides, log = defaultLog, canaries = [], proxyCapturePath = null, egressCapturePath = null, onWarning, t3 = null, now = Date.now } = {}) {
  if (!outDir) throw new Error('createPipeline: outDir is required');
  const caps = capOverrides ? resolveCaps(capOverrides) : BOUNDS;
  const store = new OutputStore({ outDir, caps, log, proxyCapturePath });
  const pending = new Map(); // request_id -> [{record, line}]
  const warnings = [];
  const warn = onWarning ?? ((msg, detail) => { warnings.push({ msg, detail }); log({ level: 'WARN', reason: 't4_alert_field_bounded', msg, detail }); });
  let chain = Promise.resolve();
  let records = 0;
  let writeAhead = 0;
  // Egress correlation state (T12 records). Attribution only: it never changes a verdict.
  const pendingEgress = []; // [{record, line, receivedAt}] in arrival order
  const windows = []; // chat-proxy exchange windows, oldest first
  const sessionByPort = new Map(); // agent port -> most recent {session, agent} (targeted lookup)
  const inflight = new Map(); // request_id -> start ms (write-ahead seen, exchange not yet)
  let horizon = -Infinity; // egress older than this lost its correlation history (evicted, logged)
  const egressCounts = { records: 0, allowed: 0, alerts: 0, correlated: 0, standalone: 0 };

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
      if (DUPLICATE_OF_EXCHANGE.has(record.reason)) {
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
      // Held proxy alerts for this request: scan-cap ones become detections, `flagged` / `detector_alert`
      // ones are duplicates of the verdicts above and are dropped here on purpose.
      for (const { record: a, line: aLine } of pending.get(record.request_id) ?? []) {
        if (DUPLICATE_OF_EXCHANGE.has(a.reason)) continue;
        alerts.push(...alertsForProxyAlert(a, { ...ctxFor(session, aLine), agent, target: record.target }));
      }
      pending.delete(record.request_id);
      store.addExchange({ session, agent, record, alerts, line });
      noteWindow(record, session, agent);
      return;
    }
    if (record.type === 'request') {
      // T2 write-ahead record: the request is on disk before the agent runs. The matching exchange
      // record carries the same request plus the response, so there is nothing to convert yet.
      writeAhead += 1;
      const start = Date.parse(record.ts);
      if (record.request_id && Number.isFinite(start)) {
        inflight.set(record.request_id, start);
        enforce('MAX_INFLIGHT_REQUESTS', inflight.size, 'write-ahead requests waiting for their exchange record', caps, log);
      }
      return;
    }
    if (record.type === 'alert') {
      const entry = { level: 'ALERT', source: 'proxy', line, ...record };
      if (DUPLICATE_OF_EXCHANGE.has(record.reason) || record.reason === 'request_too_large' || record.reason === 'response_too_large') {
        if (record.request_id) { holdAlert(record, line); return; }
      }
      if (record.reason === 'capture_write_failed' && record.request_id && pending.has(record.request_id)) {
        orphan(record.request_id);
      }
      // Operational alert: never a T4 detection, never silent.
      await store.recordOps({ source: 'proxy', line, ...record });
      if (!DUPLICATE_OF_EXCHANGE.has(record.reason)) log(entry);
      return;
    }
    if (isEgressRecord(record)) {
      egressCounts.records += 1;
      pendingEgress.push({ record, line, receivedAt: now() });
      enforce('MAX_PENDING_EGRESS', pendingEgress.length, 'egress records waiting for agent correlation', caps, log);
      return;
    }
    throw new Error(`line ${line}: unknown record type ${JSON.stringify(record.type)}`);
  }

  function noteWindow(record, session, agent) {
    inflight.delete(record.request_id);
    const start = Date.parse(record.ts);
    if (!Number.isFinite(start)) return;
    const end = start + (Number.isFinite(record.latency_ms) ? record.latency_ms : 0);
    windows.push({ start, end, session, agent, requestId: record.request_id ?? null });
    if (agent?.port) sessionByPort.set(agent.port, { session, agent });
    if (windows.length > caps.MAX_CORRELATION_WINDOWS) {
      const evicted = windows.shift();
      horizon = Math.max(horizon, evicted.end + 1);
      log({ level: 'ALERT', reason: 'correlation_window_evicted', bound: 'MAX_CORRELATION_WINDOWS', size: windows.length + 1, cap: caps.MAX_CORRELATION_WINDOWS, horizon: new Date(horizon).toISOString(), action: 'older_egress_shown_as_standalone' });
    }
  }

  /** Convert pending egress records. `all` (end of input) resolves everything; otherwise only ready ones. */
  function resolveEgress(all) {
    const t = now();
    while (pendingEgress.length) {
      const { record, line, receivedAt } = pendingEgress[0];
      let extra = null;
      if (!all) {
        const held = t - receivedAt;
        if (held < caps.EGRESS_MIN_HOLD_MS) break;
        const at = Date.parse(record.at);
        const earlierInFlight = [...inflight.values()].some((s) => !Number.isFinite(at) || s <= at);
        if (earlierInFlight && held < caps.EGRESS_MAX_HOLD_MS) break;
        if (earlierInFlight) extra = { reason: 'in_flight_turn_timeout (EGRESS_MAX_HOLD_MS)' };
      }
      pendingEgress.shift();
      let correlation = correlate(record, { windows, horizon, sessionByPort });
      if (extra && correlation.method === 'none') correlation = { ...correlation, ...extra };
      const ctx = {
        canaries,
        correlation,
        onWarning: warn,
        captureRef: { path: egressCapturePath, line },
      };
      const alert = alertForEgress(record, ctx);
      if (!alert) { egressCounts.allowed += 1; continue; }
      egressCounts.alerts += 1;
      if (correlation.method !== 'none') {
        egressCounts.correlated += 1;
        store.addEgressAlerts({ session: correlation.session, agent: correlation.agent, alerts: [alert], standalone: false });
      } else {
        egressCounts.standalone += 1;
        log({ level: 'ALERT', source: 'egress', reason: 'egress_incident_standalone', request_id: record.request_id ?? null, action: record.action, why: correlation.reason });
        store.addEgressAlerts({ session: EGRESS_SESSION, agent: EGRESS_AGENT, alerts: [alert], standalone: true });
      }
    }
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
      resolveEgress(false);
      return store.flush();
    },
    /** End of input: anything still pending had no exchange, so convert it on its own. */
    async finish() {
      await chain;
      for (const id of [...pending.keys()]) orphan(id);
      resolveEgress(true);
      return store.flush();
    },
    stats: () => ({ records, writeAhead, pending: pending.size, pendingEgress: pendingEgress.length, egress: { ...egressCounts }, ...store.stats() }),
  };
}
