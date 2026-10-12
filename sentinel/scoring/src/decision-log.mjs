// Per-rule override-rate tracking (BACKLOG T7; planning/ADJACENT.md §10.3a).
//
// Source of truth: an APPEND-ONLY JSONL decision log, one event per line:
//   { ts, ruleId, sessionId?, caseId?, detector?, event: 'fire'|'hold'|'approve'|'deny',
//     actor: { type: 'human'|'agent'|'system', id }, channel: 'side-channel'|<other>, reason? }
// Policy encoded here:
//   - An override (approve) counts ONLY when actor.type === 'human' AND channel === 'side-channel'.
//     Any other approve (the agent approving itself, an approval in-band in the chat) is NOT an override;
//     it is counted under `rejectedOverrides` and the hold stays a denial.
//   - `reason` is never used for scoring, and an agent-supplied reason is dropped on read.
//   - overrideRate = approvals / (approvals + denials). A rule with overrideRate > 0.9 is flagged
//     `retire-or-tighten`: if humans wave it through >90% of the time it protects almost nothing.
// Until S5 provides real approvals, the benign corpus stands in: every hold on a benign (negative) case is
// treated as a simulated human approval, every hold on an attack (positive) case as a denial. Stand-in
// events are generated in memory, marked `simulated: true`, and never written to the real log.

import { appendFileSync, existsSync, readFileSync, statSync } from 'node:fs';
import { enforce, CorpusError } from './bounds.mjs';

export const OVERRIDE_FLAG_THRESHOLD = 0.9;
const EVENTS = new Set(['fire', 'hold', 'approve', 'deny']);

export function validateDecision(e, where = 'decision') {
  if (!e || typeof e !== 'object') throw new CorpusError(`${where}: not an object`);
  if (typeof e.ruleId !== 'string' || !e.ruleId) throw new CorpusError(`${where}: ruleId required`);
  if (!EVENTS.has(e.event)) throw new CorpusError(`${where}: event must be fire|hold|approve|deny`);
  if (e.event === 'approve' || e.event === 'deny') {
    if (!e.actor || typeof e.actor.type !== 'string') throw new CorpusError(`${where}: ${e.event} requires actor.type`);
  }
  return e;
}

/** Append one event. Opens with O_APPEND ('a'); never rewrites or truncates the log. */
export function appendDecision(file, event) {
  const e = validateDecision({ ts: new Date().toISOString(), ...event });
  const line = JSON.stringify(e);
  enforce('MAX_DECISION_LINE_BYTES', Buffer.byteLength(line), file);
  appendFileSync(file, `${line}\n`, { flag: 'a' });
  return e;
}

/** Read the whole log, bounded and fail-loud. A malformed line is fatal (with its line number). */
export function readDecisionLog(file) {
  if (!file || !existsSync(file)) return [];
  enforce('MAX_DECISION_LOG_BYTES', statSync(file).size, file);
  const lines = readFileSync(file, 'utf8').split('\n').filter((l) => l.trim());
  enforce('MAX_DECISION_LOG_LINES', lines.length, file);
  return lines.map((l, i) => {
    enforce('MAX_DECISION_LINE_BYTES', Buffer.byteLength(l), `${file}:${i + 1}`);
    let e;
    try {
      e = JSON.parse(l);
    } catch (err) {
      throw new CorpusError(`${file}:${i + 1}: invalid JSON (${err.message})`);
    }
    validateDecision(e, `${file}:${i + 1}`);
    if (e.actor?.type !== 'human') delete e.reason; // agent-supplied reasons are ignored
    return e;
  });
}

export const isHumanSideChannel = (e) => e.actor?.type === 'human' && e.channel === 'side-channel';

/** Per-rule fires/holds/approvals/denials/overrideRate from a list of events. */
export function overrideStats(events) {
  const byRule = new Map();
  const get = (r) => {
    if (!byRule.has(r)) byRule.set(r, { ruleId: r, fires: 0, holds: 0, approvals: 0, denials: 0, rejectedOverrides: 0, simulated: 0 });
    return byRule.get(r);
  };
  for (const e of events) {
    const s = get(e.ruleId);
    if (e.simulated) s.simulated++;
    if (e.event === 'fire') s.fires++;
    else if (e.event === 'hold') s.holds++;
    else if (e.event === 'deny') s.denials++;
    else if (e.event === 'approve') {
      if (isHumanSideChannel(e)) s.approvals++;
      else {
        s.rejectedOverrides++;
        s.denials++; // a non-human / in-band approval does not release the hold
      }
    }
  }
  return [...byRule.values()]
    .map((s) => {
      const resolved = s.approvals + s.denials;
      const overrideRate = resolved ? s.approvals / resolved : null;
      return {
        ...s,
        overrideRate,
        flag: overrideRate !== null && overrideRate > OVERRIDE_FLAG_THRESHOLD ? 'retire-or-tighten' : null,
      };
    })
    .sort((a, b) => a.ruleId.localeCompare(b.ruleId));
}

/**
 * Stand-in events from a scored enforce-mode run (until S5): fire for every fired rule; for each rule that
 * would block, a hold, then a simulated human side-channel approve (benign case) or deny (attack case).
 */
export function standInEvents(detectorName, caseResults) {
  const out = [];
  for (const r of caseResults) {
    for (const f of r.fired) {
      const base = { ruleId: f.ruleId, caseId: r.id, detector: detectorName, simulated: true };
      out.push({ ...base, event: 'fire' });
      if (!f.wouldBlock && !f.alwaysEnforce) continue;
      out.push({ ...base, event: 'hold' });
      out.push({
        ...base,
        event: r.groundTruth === 'negative' ? 'approve' : 'deny',
        actor: { type: 'human', id: 'benign-corpus-standin' },
        channel: 'side-channel',
      });
    }
  }
  return out;
}
