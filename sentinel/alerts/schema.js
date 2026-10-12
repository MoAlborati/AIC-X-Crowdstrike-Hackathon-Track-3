// SentinelProxy T4 — AIDR/Falcon-shaped alert builder.
//
//   buildAlert(verdict, opts) -> frozen alert object (JSON-serializable)
//
// Pipeline (order matters):
//   1. validate the detector verdict (fail loud: AlertValidationError lists EVERY missing/invalid field)
//   2. resolve framework tags through mapping.js (single data-driven table; unknown category throws)
//   3. bound list-shaped fields (TaintPath, DetectionLayers) — keep source + sink, insert explicit marker
//   4. redact secrets in every string (BEFORE truncation, so a cut can never split a secret past the regex)
//   5. bound string fields with an explicit `…[TRUNCATED …]` marker + warning + Truncations[] record
//   6. final serialized-size guard (AlertOverflowError) — should be unreachable given 3–5; fail loud if not
//
// The alert is a REPORT/DISPLAY artifact. Decisions (block/allow) are made by the T3 detector over the
// FULL payload; the caps here never feed back into a decision path.
//
// Verdict input shape (contract with T3 — see VERDICT_SHAPE below; documented as data so it can be
// printed/validated, not only read):
//   {
//     category: string            // key of mapping.CATEGORY_MAP                       [required]
//     ruleId: string              // id of the rule that fired, e.g. "taint.untrusted_to_sink" [required]
//     disposition: 'block'|'allow'|'report' (or 'Blocked'|'Allowed'|'ReportOnly')     [required]
//     detectionLatencyMs: number  // >= 0                                              [required]
//     entities: {
//       agent:    { name: string, id?: string, port?: number }                         [required]
//       session:  { id: string }                                                       [required]
//       toolCall: { id: string, name: string, argsPreview?: string }   [required if category requiresSink]
//       sink:     { type: string, destination: string }                [required if category requiresSink]
//     }
//     taintPath?: [{ kind: 'source'|'propagate'|'sink', label: string, toolCallId?: string, trust?: string }]
//     evidence?: string           // redacted + bounded
//     canary?: { id: string, value: string }  // value is NEVER written; only id + sha256 prefix
//     canaries?: [{ id, value }]  // extra known honeytokens to redact anywhere in the alert
//     caseCard?: { originatedIn?, influencedToolCall?, decidedByRule?, narrative? }
//     layers?: [{ layer: string, rule: string, fired: boolean, latencyMs?: number }]
//     severity?: number           // 0–100 override of the category default
//     state?: 'new'|'in_progress'|'true_positive'|'false_positive'|'closed'  (default 'new')
//     timestamp?: ISO string | Date | epoch ms   (default: now)
//     alertId?: string            (default: random UUID)
//   }

import { randomUUID } from 'node:crypto';
import { getMapping, severityName, MAPPING_VERSION, ATLAS_DATA_VERSION } from './mapping.js';
import { redactDeep, sha256Short } from './redact.js';

export const SCHEMA_VERSION = 'sentinel.alert/1.0.0';

// ---- Bounds (each documented in the PR "Bounds introduced" section) -----------------------------
export const BOUNDS = Object.freeze({
  MAX_STRING_CHARS: 2048, // free-text fields (Evidence, Narrative, descriptions)
  MAX_LABEL_CHARS: 256, // short identifiers/labels (hop labels, names, ids, destinations)
  MAX_TAINT_HOPS: 64, // TaintPath length kept (head + tail; source and sink always kept)
  MAX_LAYERS: 16, // DetectionLayers entries kept
  MAX_REDACTION_KINDS: 32, // Redactions.Samples entries kept
  MAX_ALERT_BYTES: 128 * 1024, // final JSON size guard -> AlertOverflowError
});

export const DISPOSITIONS = Object.freeze({
  block: 'Blocked',
  allow: 'Allowed',
  report: 'ReportOnly',
  blocked: 'Blocked',
  allowed: 'Allowed',
  reportonly: 'ReportOnly',
  report_only: 'ReportOnly',
});
export const STATES = Object.freeze(['new', 'in_progress', 'true_positive', 'false_positive', 'closed']);
export const HOP_KINDS = Object.freeze(['source', 'propagate', 'sink']);

export const TRUNCATION_MARKER_PREFIX = '…[TRUNCATED';

export class AlertValidationError extends Error {
  constructor(issues) {
    super(`invalid detector verdict — ${issues.length} issue(s):\n  - ${issues.join('\n  - ')}`);
    this.name = 'AlertValidationError';
    this.issues = issues;
  }
}

export class AlertOverflowError extends Error {
  constructor(size, cap) {
    super(`alert JSON is ${size} bytes, exceeds MAX_ALERT_BYTES=${cap}; refusing to emit a silently-cut alert`);
    this.name = 'AlertOverflowError';
    this.size = size;
    this.cap = cap;
  }
}

/** Machine-readable description of the emitted alert (the "documented schema"). */
export const ALERT_SCHEMA = Object.freeze({
  $id: SCHEMA_VERSION,
  description: 'SentinelProxy AIDR/Falcon-shaped detection alert',
  required: [
    'SchemaVersion', 'AlertId', 'DetectName', 'DetectDescription', 'Category', 'RuleId', 'Severity',
    'SeverityName', 'Tactic', 'TacticId', 'Technique', 'TechniqueId', 'MitreAtlas', 'MitreAttack',
    'OwaspLlm', 'OwaspAgentic', 'Oasb', 'Entities', 'TaintPath', 'PatternDispositionDescription',
    'PatternDispositionFlags', 'DetectionLatencyMs', 'Timestamp', 'State', 'CaseCard', 'Canary',
    'Evidence', 'Redactions', 'Truncations', 'MappingVersion', 'AtlasDataVersion',
  ],
  fields: {
    SchemaVersion: 'string — this schema id/version',
    AlertId: 'string — unique alert id',
    DetectName: 'string — Falcon-style detect name (from mapping table)',
    DetectDescription: 'string',
    Category: 'string — detector category key',
    RuleId: 'string — detector rule that fired',
    Severity: 'integer 0–100',
    SeverityName: 'Informational|Low|Medium|High|Critical',
    Tactic: 'string — primary MITRE ATLAS tactic name', TacticId: 'AML.TAxxxx',
    Technique: 'string — primary MITRE ATLAS technique name', TechniqueId: 'AML.Txxxx[.xxx]',
    MitreAtlas: '[{TechniqueId, Technique, TacticId, Tactic}] — [0] is primary',
    MitreAttack: '[{TechniqueId, Technique, TacticId, Tactic}] — may be empty',
    OwaspLlm: '[{Id: LLM0x, Name}]', OwaspAgentic: '[{Id: ASI0x, Name}]',
    Oasb: '{Benchmark: "OASB-1", Category, Slug}',
    Entities: '{Agent:{Name,Id,Port}, Session:{Id}, ToolCall:{Id,Name,ArgsPreview}|null, Sink:{Type,Destination}|null}',
    TaintPath: '[{Step, Kind: source|propagate|sink|truncated, Label, ToolCallId, Trust, OmittedHops?}]',
    PatternDispositionDescription: 'Blocked|Allowed|ReportOnly',
    PatternDispositionFlags: '{Blocked: bool, ReportOnly: bool}',
    DetectionLatencyMs: 'number >= 0',
    Timestamp: 'ISO-8601 UTC', State: STATES.join('|'),
    CaseCard: '{Narrative, OriginatedIn, InfluencedToolCall, DecidedByRule, Disposition, DetectionLayers:[{Layer,Rule,Fired,LatencyMs}]}',
    Canary: '{Id, ValueSha256} | null — honeytoken id + sha256 prefix, never the value',
    Evidence: 'string | null — redacted + bounded',
    Redactions: '{Count, ByKind:{kind:n}, Samples:[{Kind, Sha256, CanaryId?}]}',
    Truncations: '[{Field, OriginalLength, Kept, Cap}] — every bounded field is listed here',
  },
});

/** Machine-readable verdict contract (input). */
export const VERDICT_SHAPE = Object.freeze({
  required: ['category', 'ruleId', 'disposition', 'detectionLatencyMs', 'entities.agent.name', 'entities.session.id'],
  requiredWhenSinkCategory: ['entities.toolCall.id', 'entities.toolCall.name', 'entities.sink.type', 'entities.sink.destination'],
});

// ---- helpers ------------------------------------------------------------------------------------
const isNonEmptyString = (v) => typeof v === 'string' && v.trim().length > 0;

function defaultWarn(msg, detail) {
  process.emitWarning(msg, { code: 'SENTINEL_ALERT_TRUNCATED', detail: JSON.stringify(detail) });
}

function toIsoTimestamp(ts, issues) {
  if (ts === undefined || ts === null) return new Date().toISOString();
  const d = ts instanceof Date ? ts : new Date(ts);
  if (Number.isNaN(d.getTime())) {
    issues.push(`timestamp is not a valid date: ${String(ts).slice(0, 64)}`);
    return null;
  }
  return d.toISOString();
}

function validate(verdict) {
  const issues = [];
  if (!verdict || typeof verdict !== 'object') throw new AlertValidationError(['verdict must be an object']);
  const v = verdict;
  if (!isNonEmptyString(v.category)) issues.push('category is required');
  if (!isNonEmptyString(v.ruleId)) issues.push('ruleId is required');
  if (!isNonEmptyString(v.disposition)) issues.push('disposition is required (block|allow|report)');
  else if (!DISPOSITIONS[v.disposition.toLowerCase()]) issues.push(`disposition "${v.disposition}" is not block|allow|report`);
  if (v.detectionLatencyMs === undefined || v.detectionLatencyMs === null) issues.push('detectionLatencyMs is required');
  else if (!Number.isFinite(v.detectionLatencyMs) || v.detectionLatencyMs < 0) issues.push('detectionLatencyMs must be a finite number >= 0');
  const e = v.entities;
  if (!e || typeof e !== 'object') issues.push('entities is required');
  if (!isNonEmptyString(e?.agent?.name)) issues.push('entities.agent.name is required');
  if (!isNonEmptyString(e?.session?.id)) issues.push('entities.session.id is required');
  if (v.state !== undefined && !STATES.includes(v.state)) issues.push(`state "${v.state}" not in ${STATES.join('|')}`);
  if (v.severity !== undefined && (!Number.isFinite(v.severity) || v.severity < 0 || v.severity > 100)) {
    issues.push('severity override must be a number in [0,100]');
  }
  if (v.taintPath !== undefined) {
    if (!Array.isArray(v.taintPath)) issues.push('taintPath must be an array');
    else
      v.taintPath.forEach((h, i) => {
        if (!h || !HOP_KINDS.includes(h.kind)) issues.push(`taintPath[${i}].kind must be ${HOP_KINDS.join('|')}`);
        if (!isNonEmptyString(h?.label)) issues.push(`taintPath[${i}].label is required`);
      });
  }
  if (v.layers !== undefined && !Array.isArray(v.layers)) issues.push('layers must be an array');
  if (v.canary !== undefined && (!isNonEmptyString(v.canary?.id) || !isNonEmptyString(v.canary?.value))) {
    issues.push('canary must be {id, value} with non-empty strings');
  }
  return issues;
}

/** Bound an array: keep head + tail around an explicit marker element. Never drops silently. */
function boundList(list, cap, makeMarker) {
  if (list.length <= cap) return { list, omitted: 0 };
  const keep = cap - 1; // one slot for the marker
  const head = Math.ceil(keep / 2);
  const tail = keep - head;
  const omitted = list.length - keep;
  return { list: [...list.slice(0, head), makeMarker(omitted), ...list.slice(list.length - tail)], omitted };
}

/** Bound a string with an explicit marker. Returns the bounded string (or the original). */
function boundString(str, cap, field, truncations, warn) {
  if (typeof str !== 'string' || str.length <= cap) return str;
  const marker = `${TRUNCATION_MARKER_PREFIX} field=${field} kept=${cap} of ${str.length} chars sha256=${sha256Short(str)}]`;
  const kept = Math.max(0, cap - marker.length);
  const out = str.slice(0, kept) + marker;
  const rec = { Field: field, OriginalLength: str.length, Kept: kept, Cap: cap };
  truncations.push(rec);
  warn(`sentinel alert field "${field}" truncated: ${str.length} > cap ${cap} chars`, rec);
  return out;
}

// ---- builder ------------------------------------------------------------------------------------
/**
 * Build an AIDR/Falcon-shaped alert from a detector verdict.
 * @param {object} verdict  see header comment / VERDICT_SHAPE
 * @param {{ onWarning?: (msg: string, detail: object) => void, now?: () => Date }} [opts]
 */
export function buildAlert(verdict, opts = {}) {
  const warn = opts.onWarning ?? defaultWarn;
  const issues = validate(verdict);

  let mapping = null;
  if (isNonEmptyString(verdict.category)) {
    try {
      mapping = getMapping(verdict.category);
    } catch (err) {
      issues.push(err.message);
    }
  }
  const e = verdict.entities ?? {};
  if (mapping?.requiresSink) {
    if (!isNonEmptyString(e.toolCall?.id)) issues.push(`entities.toolCall.id is required for category ${verdict.category}`);
    if (!isNonEmptyString(e.toolCall?.name)) issues.push(`entities.toolCall.name is required for category ${verdict.category}`);
    if (!isNonEmptyString(e.sink?.type)) issues.push(`entities.sink.type is required for category ${verdict.category}`);
    if (!isNonEmptyString(e.sink?.destination)) issues.push(`entities.sink.destination is required for category ${verdict.category}`);
  }
  const ts = verdict.timestamp === undefined && opts.now ? opts.now().toISOString() : toIsoTimestamp(verdict.timestamp, issues);
  if (issues.length) throw new AlertValidationError(issues);

  const disposition = DISPOSITIONS[verdict.disposition.toLowerCase()];
  const severity = Math.round(verdict.severity ?? mapping.severity);
  const truncations = [];

  // 3) bound list-shaped fields (source = first hop, sink = last hop always kept)
  const rawHops = (verdict.taintPath ?? []).map((h, i) => ({
    Step: i + 1,
    Kind: h.kind,
    Label: h.label,
    ToolCallId: h.toolCallId ?? null,
    Trust: h.trust ?? null,
  }));
  const hops = boundList(rawHops, BOUNDS.MAX_TAINT_HOPS, (omitted) => ({
    Step: null,
    Kind: 'truncated',
    Label: `${TRUNCATION_MARKER_PREFIX} ${omitted} intermediate hops omitted of ${rawHops.length}]`,
    ToolCallId: null,
    Trust: null,
    OmittedHops: omitted,
  }));
  if (hops.omitted) {
    const rec = { Field: 'TaintPath', OriginalLength: rawHops.length, Kept: BOUNDS.MAX_TAINT_HOPS - 1, Cap: BOUNDS.MAX_TAINT_HOPS };
    truncations.push(rec);
    warn(`sentinel alert TaintPath truncated: ${rawHops.length} hops > cap ${BOUNDS.MAX_TAINT_HOPS}`, rec);
  }

  const rawLayers = (verdict.layers ?? []).map((l) => ({
    Layer: String(l?.layer ?? 'unknown'),
    Rule: String(l?.rule ?? 'unknown'),
    Fired: Boolean(l?.fired),
    LatencyMs: Number.isFinite(l?.latencyMs) ? l.latencyMs : null,
  }));
  if (rawLayers.length === 0) {
    rawLayers.push({ Layer: mapping.layer, Rule: verdict.ruleId, Fired: true, LatencyMs: verdict.detectionLatencyMs });
  }
  const layers = boundList(rawLayers, BOUNDS.MAX_LAYERS, (omitted) => ({
    Layer: 'truncated',
    Rule: `${TRUNCATION_MARKER_PREFIX} ${omitted} layers omitted of ${rawLayers.length}]`,
    Fired: false,
    LatencyMs: null,
    OmittedLayers: omitted,
  }));
  if (layers.omitted) {
    const rec = { Field: 'CaseCard.DetectionLayers', OriginalLength: rawLayers.length, Kept: BOUNDS.MAX_LAYERS - 1, Cap: BOUNDS.MAX_LAYERS };
    truncations.push(rec);
    warn(`sentinel alert DetectionLayers truncated: ${rawLayers.length} > cap ${BOUNDS.MAX_LAYERS}`, rec);
  }

  // case card (narrative): "instruction originated in X → influenced tool call Y → blocked by rule Z"
  const cc = verdict.caseCard ?? {};
  const firstSource = rawHops.find((h) => h.Kind === 'source');
  const originatedIn = cc.originatedIn ?? firstSource?.Label ?? 'unattributed source';
  const influencedToolCall =
    cc.influencedToolCall ?? (e.toolCall ? `${e.toolCall.name}(${e.toolCall.id})` : 'no tool call');
  const decidedByRule = cc.decidedByRule ?? verdict.ruleId;
  const verb = { Blocked: 'blocked', Allowed: 'allowed (observed)', ReportOnly: 'reported (report-only)' }[disposition];
  const narrative =
    cc.narrative ??
    `Instruction originated in ${originatedIn} → influenced tool call ${influencedToolCall}` +
      (e.sink ? ` → toward ${e.sink.type}:${e.sink.destination}` : '') +
      ` → ${verb} by rule ${decidedByRule}`;

  const primary = mapping.MitreAtlas[0];
  let alert = {
    SchemaVersion: SCHEMA_VERSION,
    AlertId: verdict.alertId ?? randomUUID(),
    DetectName: mapping.detectName,
    DetectDescription: mapping.description,
    Category: verdict.category,
    RuleId: verdict.ruleId,
    Severity: severity,
    SeverityName: severityName(severity),
    Tactic: primary.Tactic,
    TacticId: primary.TacticId,
    Technique: primary.Technique,
    TechniqueId: primary.TechniqueId,
    MitreAtlas: mapping.MitreAtlas,
    MitreAttack: mapping.MitreAttack,
    OwaspLlm: mapping.OwaspLlm,
    OwaspAgentic: mapping.OwaspAgentic,
    Oasb: mapping.Oasb,
    Entities: {
      Agent: { Name: e.agent.name, Id: e.agent.id ?? null, Port: e.agent.port ?? null },
      Session: { Id: e.session.id },
      ToolCall: e.toolCall
        ? { Id: e.toolCall.id ?? null, Name: e.toolCall.name ?? null, ArgsPreview: e.toolCall.argsPreview ?? null }
        : null,
      Sink: e.sink ? { Type: e.sink.type ?? null, Destination: e.sink.destination ?? null } : null,
    },
    TaintPath: hops.list,
    PatternDispositionDescription: disposition,
    PatternDispositionFlags: { Blocked: disposition === 'Blocked', ReportOnly: disposition === 'ReportOnly' },
    DetectionLatencyMs: verdict.detectionLatencyMs,
    Timestamp: ts,
    State: verdict.state ?? 'new',
    CaseCard: {
      Narrative: narrative,
      OriginatedIn: originatedIn,
      InfluencedToolCall: influencedToolCall,
      DecidedByRule: decidedByRule,
      Disposition: disposition,
      DetectionLayers: layers.list,
    },
    Evidence: verdict.evidence ?? null,
  };

  // 4) redact every string BEFORE truncation (canary values + generic secret patterns)
  const canaries = [...(verdict.canaries ?? []), ...(verdict.canary ? [verdict.canary] : [])];
  const red = redactDeep(alert, { canaries });
  alert = red.value;
  const byKind = {};
  for (const f of red.findings) byKind[f.kind] = (byKind[f.kind] ?? 0) + 1;
  const samples = [];
  const seen = new Set();
  for (const f of red.findings) {
    const key = `${f.kind}:${f.sha256}`;
    if (seen.has(key)) continue;
    seen.add(key);
    samples.push({ Kind: f.kind, Sha256: f.sha256, ...(f.canaryId ? { CanaryId: f.canaryId } : {}) });
  }
  const boundedSamples = boundList(samples, BOUNDS.MAX_REDACTION_KINDS, (omitted) => ({
    Kind: 'truncated',
    Sha256: null,
    OmittedSamples: omitted,
  }));
  if (boundedSamples.omitted) {
    const rec = { Field: 'Redactions.Samples', OriginalLength: samples.length, Kept: BOUNDS.MAX_REDACTION_KINDS - 1, Cap: BOUNDS.MAX_REDACTION_KINDS };
    truncations.push(rec);
    warn(`sentinel alert Redactions.Samples truncated: ${samples.length} > cap ${BOUNDS.MAX_REDACTION_KINDS}`, rec);
  }
  if (red.withheldCount) {
    warn(`sentinel alert: ${red.withheldCount} oversize string field(s) withheld unscanned (redaction scan cap)`, {
      withheld: red.withheldCount,
    });
  }

  // 5) bound strings (explicit marker + warning + Truncations record)
  const b = (s, cap, field) => boundString(s, cap, field, truncations, warn);
  const L = BOUNDS.MAX_LABEL_CHARS;
  const S = BOUNDS.MAX_STRING_CHARS;
  alert.AlertId = b(alert.AlertId, L, 'AlertId');
  alert.RuleId = b(alert.RuleId, L, 'RuleId');
  alert.Evidence = b(alert.Evidence, S, 'Evidence');
  const ent = alert.Entities;
  ent.Agent.Name = b(ent.Agent.Name, L, 'Entities.Agent.Name');
  if (typeof ent.Agent.Id === 'string') ent.Agent.Id = b(ent.Agent.Id, L, 'Entities.Agent.Id');
  ent.Session.Id = b(ent.Session.Id, L, 'Entities.Session.Id');
  if (ent.ToolCall) {
    ent.ToolCall.Id = b(ent.ToolCall.Id, L, 'Entities.ToolCall.Id');
    ent.ToolCall.Name = b(ent.ToolCall.Name, L, 'Entities.ToolCall.Name');
    ent.ToolCall.ArgsPreview = b(ent.ToolCall.ArgsPreview, S, 'Entities.ToolCall.ArgsPreview');
  }
  if (ent.Sink) {
    ent.Sink.Type = b(ent.Sink.Type, L, 'Entities.Sink.Type');
    ent.Sink.Destination = b(ent.Sink.Destination, S, 'Entities.Sink.Destination');
  }
  alert.TaintPath.forEach((h, i) => {
    h.Label = b(h.Label, L, `TaintPath[${i}].Label`);
    if (typeof h.ToolCallId === 'string') h.ToolCallId = b(h.ToolCallId, L, `TaintPath[${i}].ToolCallId`);
    if (typeof h.Trust === 'string') h.Trust = b(h.Trust, L, `TaintPath[${i}].Trust`);
  });
  const card = alert.CaseCard;
  card.Narrative = b(card.Narrative, S, 'CaseCard.Narrative');
  card.OriginatedIn = b(card.OriginatedIn, L, 'CaseCard.OriginatedIn');
  card.InfluencedToolCall = b(card.InfluencedToolCall, L, 'CaseCard.InfluencedToolCall');
  card.DecidedByRule = b(card.DecidedByRule, L, 'CaseCard.DecidedByRule');
  card.DetectionLayers.forEach((l, i) => {
    l.Layer = b(l.Layer, L, `CaseCard.DetectionLayers[${i}].Layer`);
    l.Rule = b(l.Rule, L, `CaseCard.DetectionLayers[${i}].Rule`);
  });

  alert.Canary = verdict.canary ? { Id: verdict.canary.id, ValueSha256: sha256Short(verdict.canary.value) } : null;
  alert.Redactions = { Count: red.findings.length, ByKind: byKind, Samples: boundedSamples.list };
  alert.Truncations = truncations;
  alert.MappingVersion = MAPPING_VERSION;
  alert.AtlasDataVersion = ATLAS_DATA_VERSION;

  // 6) final size guard — fail loud, never emit a silently-cut alert
  const size = Buffer.byteLength(JSON.stringify(alert), 'utf8');
  if (size > BOUNDS.MAX_ALERT_BYTES) throw new AlertOverflowError(size, BOUNDS.MAX_ALERT_BYTES);

  return deepFreeze(alert);
}

function deepFreeze(o) {
  for (const v of Object.values(o)) if (v && typeof v === 'object' && !Object.isFrozen(v)) deepFreeze(v);
  return Object.freeze(o);
}

/**
 * Structural check of an emitted alert against ALERT_SCHEMA.required (+ a few type checks).
 * Returns [] when valid. Used by tests and by consumers (T5 dashboard) to reject malformed input loudly.
 */
export function validateAlert(alert) {
  const problems = [];
  if (!alert || typeof alert !== 'object') return ['alert must be an object'];
  for (const k of ALERT_SCHEMA.required) if (!(k in alert)) problems.push(`missing ${k}`);
  if (alert.SchemaVersion !== SCHEMA_VERSION) problems.push(`SchemaVersion ${alert.SchemaVersion} != ${SCHEMA_VERSION}`);
  if (!Number.isInteger(alert.Severity) || alert.Severity < 0 || alert.Severity > 100) problems.push('Severity not int 0–100');
  if (!['Blocked', 'Allowed', 'ReportOnly'].includes(alert.PatternDispositionDescription)) problems.push('bad PatternDispositionDescription');
  if (!STATES.includes(alert.State)) problems.push('bad State');
  if (Number.isNaN(Date.parse(alert.Timestamp))) problems.push('bad Timestamp');
  if (!/^AML\.TA\d{4}$/.test(alert.TacticId ?? '')) problems.push('TacticId not an ATLAS tactic id');
  if (!/^AML\.T\d{4}(\.\d{3})?$/.test(alert.TechniqueId ?? '')) problems.push('TechniqueId not an ATLAS technique id');
  if (!Array.isArray(alert.MitreAtlas) || alert.MitreAtlas.length === 0) problems.push('MitreAtlas empty');
  if (!isNonEmptyString(alert.Entities?.Agent?.Name)) problems.push('Entities.Agent.Name missing');
  if (!isNonEmptyString(alert.Entities?.Session?.Id)) problems.push('Entities.Session.Id missing');
  if (!isNonEmptyString(alert.CaseCard?.Narrative)) problems.push('CaseCard.Narrative missing');
  return problems;
}
