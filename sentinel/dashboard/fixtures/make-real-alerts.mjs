#!/usr/bin/env node
// Real detector verdicts for the stage captures (no placeholders):
//   recorded aim-ab traffic -> T3 sentinelInspector (request phase, then response phase)
//   -> sentinel/pipeline convert.mjs (T3 toAlertVerdict() rehydration + T4 buildAlert, direction labels)
//   -> sentinel/dashboard/alerts/<capture>.alerts.json, keyed by run.
//
// The request each run received is the APWN-DE-003 poisoned document DVAA sent as the user turn, rebuilt
// byte-for-byte from DVAA's template + the recorded canary URL (capture-loader poisonedRagDocument). The
// response is the recorded reply + tool calls. These runs went DIRECT to DVAA (no proxy), so verdicts are
// a retrospective replay in observe mode: request-side findings are "would block", and on runA (canary
// hit recorded) every finding is post-execution evidence. Nothing here claims a block that did not happen.
// The third stage capture (stage/proxy-blocked-t3) already embeds the alerts its live proxy run produced.
//
// Deterministic: fixed request ids and timestamps from the capture; detector latency is measured, so it is
// the only field that varies between runs. Usage: node sentinel/dashboard/fixtures/make-real-alerts.mjs [--check]

import { readFile, writeFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { poisonedRagDocument } from '../lib/capture-loader.mjs';
import { sidecarName } from '../lib/alert-store.mjs';
import { createT3Source, T3_CANARIES } from '../../pipeline/t3.mjs';
import { alertsForExchange } from '../../pipeline/convert.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const REAL_ALERTS_DIR = path.resolve(HERE, '..', 'alerts');
const REPO = path.resolve(HERE, '..', '..', '..');

// Stage captures with a recorded (or exactly reconstructable) input. repo/flight are not here: their
// untrusted content was not recorded, so there is nothing real to run the detector on.
export const REAL_ALERT_CAPTURES = Object.freeze([{ id: 'attack/aim-ab.demo', file: 'captures/attack/aim-ab.demo.json', runs: ['runA', 'runB'] }]);

const body = (obj) => {
  const data = JSON.stringify(obj);
  return { encoding: 'utf8', bytes: Buffer.byteLength(data), data };
};

/** Run real T3 over one recorded demo-ab run and build its T4 alerts through the pipeline converter. */
export async function realAlertsForRun(raw, runKey, captureId) {
  const run = raw[runKey];
  const doc = poisonedRagDocument(raw);
  if (!doc) throw new Error(`${captureId}: request is not reconstructable (not aim-ab / APWN-DE-003 with a canary URL)`);
  const t3 = createT3Source();
  const [inspect] = t3.inspectors;
  const requestId = `replay-${captureId.replace(/[^a-z0-9]+/gi, '-')}-${runKey}`;
  const reqObj = { messages: [{ role: 'user', content: doc }] };
  const resObj = { choices: [{ index: 0, message: { role: 'assistant', content: run.message ?? '', tool_calls: run.toolCalls ?? [] }, finish_reason: run.finishReason ?? null }] };
  const p = '/v1/chat/completions';
  const reqV = await inspect({ phase: 'request', path: p, headers: { 'x-sentinel-session': requestId }, body: JSON.stringify(reqObj), requestId });
  const resV = await inspect({ phase: 'response', path: p, headers: { 'x-sentinel-session': requestId }, body: JSON.stringify(resObj), requestId });
  const ts = raw.canary?.hits?.[0]?.at ?? '2026-10-12T00:00:00.000Z';
  const record = {
    type: 'exchange', ts, request_id: requestId, mode: 'observe', target: `http://127.0.0.1:${runKey === 'runA' ? 7005 : 7014}`,
    request: { method: 'POST', path: p, headers: {}, body: body(reqObj) },
    response: { status: 200, headers: {}, body: body(resObj) },
    verdicts: [reqV && { phase: 'request', ...reqV }, resV && { phase: 'response', ...resV }].filter(Boolean),
    action: 'forwarded', // the recorded run went straight to DVAA: nothing was refused
  };
  const alerts = alertsForExchange(record, { session: requestId, canaries: T3_CANARIES, t3, captureRef: { replayOf: captureId, run: runKey } });
  const executed = run.dvaa?.exfilExecuted === true;
  const aimDenied = run.dvaa?.aim?.allowed === false;
  return alerts.map(a => {
    let cc = a.CaseCard;
    // convert.mjs assumes a response-side tool call already ran (true for a bare DVAA agent). On the AIM
    // twin DVAA recorded the call as DENIED, so say that instead of "tool already executed".
    if (aimDenied && !executed && /tool_already_executed/.test(cc.Narrative)) {
      cc = { ...cc, Narrative: cc.Narrative.replace(/Outcome: [a-z_]+\./, 'Outcome: tool call denied by DVAA AIM (capability grant); exfil not executed.') };
    }
    return { ...a, CaseCard: cc, Direction: a.PipelineContext.Direction, Prevents: false, PostExecution: executed };
  });
}

export async function generateRealAlerts() {
  const out = new Map();
  for (const c of REAL_ALERT_CAPTURES) {
    const raw = JSON.parse(await readFile(path.join(REPO, c.file), 'utf8'));
    const runs = {};
    for (const k of c.runs) runs[k] = await realAlertsForRun(raw, k, c.id);
    out.set(c.id, {
      captureId: c.id,
      placeholder: false,
      note: 'REAL T3 detector verdicts (sentinel/detectors via sentinelInspector) over the recorded traffic, built by T3 toAlertVerdict + T4 buildAlert (sentinel/pipeline/convert.mjs). Retrospective observe-mode replay: these runs went direct to DVAA, so nothing was blocked. Regenerate: node sentinel/dashboard/fixtures/make-real-alerts.mjs',
      generator: 'sentinel/dashboard/fixtures/make-real-alerts.mjs',
      runs,
    });
  }
  return out;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const out = await generateRealAlerts();
  await mkdir(REAL_ALERTS_DIR, { recursive: true });
  for (const [id, doc] of out) {
    const file = path.join(REAL_ALERTS_DIR, sidecarName(id));
    await writeFile(file, `${JSON.stringify(doc, null, 2)}\n`);
    console.log(`[make-real-alerts] ${path.relative(REPO, file)}: ${Object.entries(doc.runs).map(([k, v]) => `${k}=${v.length} alert(s) [${v.map(a => `${a.Direction}:${a.RuleId}`).join(', ')}]`).join(' · ')}`);
  }
}
