// THE single adapter between T4 alerts and the dashboard view model. If the alert schema changes,
// only this file changes.
//
// Contract: T4 `sentinel.alert/1.0.0` (sentinel/alerts/schema.js, PR #3 @ b51f32b). Reference
// example: test/fixtures/t4-sample-alert.json (copied verbatim from sentinel/alerts/examples/).
//
// Validation: if sentinel/alerts/schema.js is present (T4 merged), its validateAlert() is used.
// Otherwise a local mirror of ALERT_SCHEMA.required is used. Either way an invalid alert is NOT
// dropped. It is kept in the feed with `invalid: true` and its problems listed, so a bad
// detector output shows up loudly on screen.
//
// TaintPath truncation: T4 caps TaintPath at 64 hops and replaces the middle with a
// {Kind:"truncated", OmittedHops:n} marker. The adapter keeps that marker as a path element. The
// replay builder turns it into a visible graph node. It is never filtered out.

import { BOUNDS, enforce } from './bounds.mjs';
import { stageHints } from './stage.mjs';

export const SUPPORTED_SCHEMA = 'sentinel.alert/1.0.0';

const REQUIRED_FALLBACK = [
  'SchemaVersion', 'AlertId', 'DetectName', 'DetectDescription', 'Category', 'RuleId', 'Severity',
  'SeverityName', 'Tactic', 'TacticId', 'Technique', 'TechniqueId', 'MitreAtlas', 'MitreAttack',
  'OwaspLlm', 'OwaspAgentic', 'Oasb', 'Entities', 'TaintPath', 'PatternDispositionDescription',
  'PatternDispositionFlags', 'DetectionLatencyMs', 'Timestamp', 'State', 'CaseCard', 'Canary',
  'Evidence', 'Redactions', 'Truncations', 'MappingVersion', 'AtlasDataVersion',
];

function fallbackValidate(alert) {
  if (!alert || typeof alert !== 'object') return ['alert must be an object'];
  const problems = REQUIRED_FALLBACK.filter(k => !(k in alert)).map(k => `missing ${k}`);
  if (alert.SchemaVersion !== SUPPORTED_SCHEMA) problems.push(`SchemaVersion ${alert.SchemaVersion} != ${SUPPORTED_SCHEMA}`);
  if (!Number.isInteger(alert.Severity) || alert.Severity < 0 || alert.Severity > 100) problems.push('Severity not int 0–100');
  if (!Array.isArray(alert.TaintPath)) problems.push('TaintPath not an array');
  if (typeof alert.CaseCard?.Narrative !== 'string' || !alert.CaseCard.Narrative) problems.push('CaseCard.Narrative missing');
  return problems;
}

let validatorPromise = null;
/** Resolve the validator once: T4's own validateAlert when available, else the local mirror. */
export function getValidator() {
  validatorPromise ??= import('../../alerts/schema.js')
    .then(m => ({ validate: m.validateAlert, origin: 'sentinel/alerts/schema.js' }))
    .catch(() => ({ validate: fallbackValidate, origin: 'dashboard fallback (T4 schema.js not present)' }));
  return validatorPromise;
}

const str = v => (v == null ? null : String(v));

function adaptHop(h, i) {
  if (h?.Kind === 'truncated') {
    return {
      index: i,
      kind: 'truncated',
      label: str(h.Label) ?? 'truncated',
      omittedHops: Number.isFinite(h.OmittedHops) ? h.OmittedHops : null,
      toolCallId: null,
      trust: null,
    };
  }
  return {
    index: i,
    step: h?.Step ?? null,
    kind: ['source', 'propagate', 'sink'].includes(h?.Kind) ? h.Kind : 'unknown',
    label: str(h?.Label) ?? `hop ${i + 1}`,
    toolCallId: str(h?.ToolCallId),
    trust: str(h?.Trust),
  };
}

/**
 * Adapt one raw T4 alert to the dashboard view model.
 * @param {object} raw     T4 alert JSON
 * @param {(a:object)=>string[]} validate
 */
export function adaptAlert(raw, validate = fallbackValidate, position = 0) {
  const problems = validate(raw);
  const a = raw && typeof raw === 'object' ? raw : {};
  const path = Array.isArray(a.TaintPath) ? a.TaintPath : [];
  // T4 already caps at 64 (+ marker). If something hands us more, refuse loudly rather than drop.
  enforce('MAX_PROVENANCE_EDGES_PER_ALERT', Math.max(0, path.length - 1), `alert ${a.AlertId ?? position} TaintPath`);
  const card = a.CaseCard ?? {};
  const disposition = a.PatternDispositionDescription ?? 'Unknown';
  return {
    id: str(a.AlertId) ?? `alert-${position}`,
    invalid: problems.length > 0,
    problems,
    detectName: str(a.DetectName) ?? 'UnknownDetection',
    description: str(a.DetectDescription),
    ruleId: str(a.RuleId),
    category: str(a.Category),
    severity: Number.isFinite(a.Severity) ? a.Severity : null,
    severityName: str(a.SeverityName) ?? 'Unknown',
    tactic: { name: str(a.Tactic), id: str(a.TacticId) },
    technique: { name: str(a.Technique), id: str(a.TechniqueId) },
    tags: {
      atlas: (a.MitreAtlas ?? []).map(t => t.TechniqueId),
      attack: (a.MitreAttack ?? []).map(t => t.TechniqueId),
      owaspLlm: (a.OwaspLlm ?? []).map(t => t.Id),
      owaspAgentic: (a.OwaspAgentic ?? []).map(t => t.Id),
      oasb: a.Oasb ? `${a.Oasb.Benchmark}:${a.Oasb.Slug ?? a.Oasb.Category}` : null,
    },
    disposition,
    blocked: a.PatternDispositionFlags?.Blocked === true || disposition === 'Blocked',
    reportOnly: a.PatternDispositionFlags?.ReportOnly === true || disposition === 'ReportOnly',
    // Direction hints, if the producer recorded any. lib/stage.mjs decides what may be shown as Blocked.
    hints: stageHints(a),
    latencyMs: Number.isFinite(a.DetectionLatencyMs) ? a.DetectionLatencyMs : null,
    timestamp: str(a.Timestamp),
    state: str(a.State),
    entities: {
      agent: a.Entities?.Agent ?? null,
      session: a.Entities?.Session?.Id ?? null,
      toolCall: a.Entities?.ToolCall ? { id: str(a.Entities.ToolCall.Id), name: str(a.Entities.ToolCall.Name), argsPreview: str(a.Entities.ToolCall.ArgsPreview) } : null,
      sink: a.Entities?.Sink ? { type: str(a.Entities.Sink.Type), destination: str(a.Entities.Sink.Destination) } : null,
    },
    taintPath: path.map(adaptHop),
    taintPathTruncated: path.some(h => h?.Kind === 'truncated'),
    caseCard: {
      narrative: str(card.Narrative),
      originatedIn: str(card.OriginatedIn),
      influencedToolCall: str(card.InfluencedToolCall),
      decidedByRule: str(card.DecidedByRule),
      layers: (card.DetectionLayers ?? []).map(l => ({
        layer: str(l.Layer),
        rule: str(l.Rule),
        fired: l.Fired === true,
        latencyMs: Number.isFinite(l.LatencyMs) ? l.LatencyMs : null,
        truncated: l.Layer === 'truncated',
        omitted: l.OmittedLayers ?? null,
      })),
    },
    evidence: str(a.Evidence),
    canaryId: a.Canary?.Id ?? null,
    redactionCount: a.Redactions?.Count ?? 0,
    truncations: Array.isArray(a.Truncations) ? a.Truncations : [],
  };
}

/** Adapt every alert on a capture. Enforces MAX_ALERTS_PER_CAPTURE (throws, never slices). */
export async function adaptAlerts(rawAlerts, captureId = '') {
  enforce('MAX_ALERTS_PER_CAPTURE', rawAlerts.length, `capture ${captureId}`);
  const { validate, origin } = await getValidator();
  return { alerts: rawAlerts.map((r, i) => adaptAlert(r, validate, i)), validatorOrigin: origin };
}

export { BOUNDS };
