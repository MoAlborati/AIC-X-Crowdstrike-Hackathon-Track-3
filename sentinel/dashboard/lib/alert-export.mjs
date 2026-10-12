// SOC handoff: "Copy alert JSON" on the case card. Returns the raw T4 alert (Falcon/AIDR-shaped,
// `sentinel.alert/1.0.0`, with its MITRE ATLAS / ATT&CK / OWASP LLM / OWASP Agentic / OASB tags) exactly
// as T4 built it, after a second redaction pass. This is defense in depth: T4 buildAlert already redacts.
//
// The second pass is T4's own redactDeep with the capture's recorded canary values as known secrets
// (the attacker endpoint's received data, e.g. the planted admin secret). The result must still pass
// T4 validateAlert, and no canary value may survive anywhere in the JSON. Either failure is an error
// response (422 / 500). A payload that could leak a secret or break the T4 contract is never returned.
//
// Bounds: alerts per capture are capped by MAX_ALERTS_PER_CAPTURE (enforced, throws). Canary values
// are capped at T4's MAX_CANARIES; more is a 413, never a silent subset.

import { loadCapture } from './capture-loader.mjs';
import { alertsFor } from './alert-store.mjs';
import { enforce } from './bounds.mjs';
import { redactDeep, validateAlert, MAX_CANARIES, MAX_CANARY_VALUE_CHARS, MIN_CANARY_VALUE_CHARS } from '../../alerts/index.js';

/**
 * Secret strings the attacker endpoint received in this capture: each recorded query value, plus each
 * `a | b | c` segment and the value after `label:` in it ("Admin credentials: dvaa-admin-secret").
 * @returns {string[]} distinct values (any length; callers decide what fits T4's canary limits)
 */
export function canaryValues(canaryHits = []) {
  const out = new Set();
  for (const h of canaryHits) {
    for (const v of Object.values(h?.query ?? {})) {
      if (typeof v !== 'string') continue;
      out.add(v.trim());
      for (const seg of v.split('|')) {
        out.add(seg.trim());
        const i = seg.lastIndexOf(':');
        if (i > -1) out.add(seg.slice(i + 1).trim());
      }
    }
  }
  return [...out].filter(Boolean);
}

export class ExportError extends Error {
  constructor(status, message, extra = {}) {
    super(message);
    this.status = status;
    this.extra = extra;
  }
}

/** Redact + validate one raw T4 alert for export. Throws ExportError on any failure (fail loud). */
export function prepareExport(rawAlert, canaryHits = []) {
  const values = canaryValues(canaryHits);
  const usable = values.filter(v => v.length >= MIN_CANARY_VALUE_CHARS && v.length <= MAX_CANARY_VALUE_CHARS);
  if (usable.length > MAX_CANARIES) {
    throw new ExportError(413, `alert export: ${usable.length} canary values > MAX_CANARIES=${MAX_CANARIES}; refusing to redact a subset`,
      { bound: 'MAX_CANARIES', size: usable.length, cap: MAX_CANARIES, action: 'rejected' });
  }
  const { value, findings, withheldCount } = redactDeep(rawAlert, { canaries: usable.map((v, i) => ({ id: `capture-canary-${i + 1}`, value: v })) });
  const problems = validateAlert(value);
  if (problems.length) throw new ExportError(422, `alert export: T4 validateAlert failed after redaction: ${problems.join('; ')}`, { problems });
  // Residual check over the serialized payload, for every recorded value long enough to be specific
  // (including any too long to register as a T4 canary).
  const json = JSON.stringify(value);
  const leaked = values.filter(v => v.length >= MIN_CANARY_VALUE_CHARS && json.includes(v));
  if (leaked.length) throw new ExportError(500, `alert export: ${leaked.length} recorded canary value(s) survived redaction; refusing to export`);
  return { alert: value, redaction: { secondPassFindings: findings.length, withheld: withheldCount, canaryValuesChecked: values.filter(v => v.length >= MIN_CANARY_VALUE_CHARS).length } };
}

/** GET /api/alert-export?id=<capture>&run=<run>&alert=<AlertId> */
export async function exportAlert(index, id, runKey, alertId) {
  const entry = index.get(id); // targeted lookup; ids never become file paths
  if (!entry) return { status: 404, body: { error: `unknown capture id ${id}` } };
  const capture = await loadCapture(entry);
  const run = runKey ? capture.runs.find(r => r.key === runKey) : capture.runs[0];
  if (!run) return { status: 404, body: { error: `capture ${id} has no run ${runKey}` } };
  const src = await alertsFor(capture, run.key);
  enforce('MAX_ALERTS_PER_CAPTURE', src.alerts.length, `capture ${id}`);
  const raw = src.alerts.find(a => a?.AlertId === alertId);
  if (!raw) return { status: 404, body: { error: `capture ${id}#${run.key} has no alert ${alertId}` } };
  try {
    const out = prepareExport(raw, capture.canaryHits);
    return {
      status: 200,
      body: { ...out, source: src.origin, placeholder: src.placeholder === true, validator: 'sentinel/alerts/schema.js validateAlert' },
    };
  } catch (err) {
    if (err instanceof ExportError) {
      console.error(`[sentinel-dashboard] ALERT ${err.message}`);
      return { status: err.status, body: { error: err.message, ...err.extra } };
    }
    throw err;
  }
}
