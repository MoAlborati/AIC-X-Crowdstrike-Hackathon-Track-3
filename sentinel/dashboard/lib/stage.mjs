// What a detector verdict actually achieved, so the dashboard never claims a block it did not make.
//
// Prevention boundary (AGENTS.md endgame policy, T8 finding PR #16): DVAA executes tools in-process, so a
// response-side verdict arrives after the data has already left. Only two kinds of verdict prevent harm:
//   * request-side, pre-forward verdicts (T3 `direction: "request"`, `prevents: true`, not post-execution)
//   * egress-boundary denies (T12 sentinel/egress: RuleId `egress.*`, Entities.Agent.Id "egress-boundary",
//     disposition Blocked). The bytes have not left yet when that deny happens.
// Everything else is alert-only, whatever T4's PatternDispositionDescription says:
//   * any alert on a run whose canary listener recorded a hit (the secret reached the attacker; every
//     alert step comes after the canary step in the replay timeline) -> "post-execution (alert-only)"
//   * response-side or postExecution verdicts -> "post-execution (alert-only)"
//   * a verdict whose side is not recorded -> "alert-only". T4 alerts do not carry direction today, so a
//     T4 "Blocked" without a direction hint is NOT shown as Blocked: unproven prevention is not prevention.
// Direction hints are read from the raw alert when a producer adds them (Direction / Prevents /
// PostExecution, top level or in CaseCard, or the sentinel/pipeline narrative prefix). None are invented.

export const STAGE_LABEL = Object.freeze({
  prevented_request: 'Blocked · pre-forward',
  prevented_egress: 'Blocked · egress (denied before send)',
  post_execution: 'Detected · post-execution (alert-only)',
  alert_only: 'Detected · alert-only',
});

const pick = (raw, key) => {
  const lc = key[0].toLowerCase() + key.slice(1);
  for (const v of [raw?.[key], raw?.[lc], raw?.CaseCard?.[key], raw?.CaseCard?.[lc]]) if (v !== undefined && v !== null) return v;
  return undefined;
};

// sentinel/pipeline (convert.mjs DIRECTION_POLICY) records direction as a case-card narrative prefix:
// "[request-side · blocking] …" (T4 block only when the proxy actually refused: action blocked_request)
// or "[response-side · alert_only] …".
const PIPELINE_PREFIX = /^\[(request|response)-side · (blocking|alert_only)\]/;

/** Direction hints a producer recorded on the raw T4 alert. */
export function stageHints(raw) {
  const d = pick(raw, 'Direction');
  const p = pick(raw, 'Prevents');
  const x = pick(raw, 'PostExecution');
  const hints = {
    direction: typeof d === 'string' ? d.toLowerCase() : null,
    prevents: typeof p === 'boolean' ? p : null,
    postExecution: typeof x === 'boolean' ? x : null,
  };
  const m = typeof raw?.CaseCard?.Narrative === 'string' ? PIPELINE_PREFIX.exec(raw.CaseCard.Narrative) : null;
  if (m && hints.direction === null) {
    hints.direction = m[1];
    if (hints.prevents === null) hints.prevents = m[1] === 'request' && m[2] === 'blocking';
  }
  return hints;
}

/**
 * @param {object} a  adapted alert (lib/alert-adapter.mjs), with `hints` from stageHints()
 * @param {{canaryHit: boolean}} ctx  canaryHit = the run's attacker endpoint received the exfil
 * @returns {{stage: keyof STAGE_LABEL, shownDisposition: string, prevented: boolean}}
 */
export function classifyStage(a, { canaryHit = false } = {}) {
  const t4Blocked = a.t4Blocked ?? a.blocked === true;
  const h = a.hints ?? {};
  const egressDeny = t4Blocked && /^egress\./.test(a.ruleId ?? '') && a.entities?.agent?.Id === 'egress-boundary';
  const preForward = t4Blocked && h.direction === 'request' && h.prevents === true && h.postExecution !== true;
  const postExec = canaryHit || h.direction === 'response' || h.postExecution === true;
  let stage;
  if (postExec) stage = 'post_execution';
  else if (egressDeny) stage = 'prevented_egress';
  else if (preForward) stage = 'prevented_request';
  else stage = 'alert_only';
  return { stage, shownDisposition: STAGE_LABEL[stage], prevented: stage.startsWith('prevented_') };
}

/** Apply classifyStage to every alert of one run. Returns new objects; `blocked` becomes the honest value. */
export function stageAlerts(alerts, { canaryHit = false } = {}) {
  return alerts.map(a => {
    const s = classifyStage(a, { canaryHit });
    const narrative = a.caseCard?.narrative && !s.prevented
      ? a.caseCard.narrative.replace(/→ blocked by rule/g, '→ detected (alert-only, not blocked) by rule')
      : a.caseCard?.narrative ?? null;
    return { ...a, ...s, t4Disposition: a.disposition, t4Blocked: a.t4Blocked ?? a.blocked === true, blocked: s.prevented, caseCard: { ...a.caseCard, narrative } };
  });
}
