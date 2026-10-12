// SentinelProxy T4 — detector category -> framework mapping (single, data-driven table).
//
// Every framework ID used by an alert comes from the CATALOG below, and every detector category's tags
// come from CATEGORY_MAP below. No call site hard-codes a framework ID; schema.js resolves everything
// through getMapping(category). Unknown categories THROW (fail loud) — there is no "default" mapping.
//
// Sources (see planning/RESEARCH.md for the framework list):
//   - MITRE ATLAS: verified against mitre-atlas/atlas-data dist/v6/ATLAS-2026.09.yaml (modified
//     2026-09-15), the data behind https://atlas.mitre.org. Technique->tactic links taken from the
//     data's `achieves` relationships, not guessed.
//   - MITRE ATT&CK Enterprise: https://attack.mitre.org (TA0010 Exfiltration; T1041, T1567).
//   - OWASP Top 10 for LLM Applications 2025: https://genai.owasp.org/llm-top-10/
//   - OWASP Top 10 for Agentic Applications (ASI01–ASI10, Dec 2025): https://genai.owasp.org
//   - OASB-1 (Open Agent Security Benchmark) categories as listed in the DVAA README
//     (opena2a-org/damn-vulnerable-ai-agent, "Attack Categories", https://oasb.ai).

export const MAPPING_VERSION = '1.0.0';
export const ATLAS_DATA_VERSION = '2026.09';

const deepFreeze = (o) => {
  for (const v of Object.values(o)) if (v && typeof v === 'object') deepFreeze(v);
  return Object.freeze(o);
};

// ---- Framework catalogs (ID -> canonical name) --------------------------------------------------
export const CATALOG = deepFreeze({
  atlasTactics: {
    'AML.TA0005': 'Execution',
    'AML.TA0007': 'Defense Evasion',
    'AML.TA0010': 'Exfiltration',
  },
  // technique ID -> { name, tactic } (tactic from ATLAS `achieves` relationship)
  atlasTechniques: {
    'AML.T0051.000': { name: 'LLM Prompt Injection: Direct', tactic: 'AML.TA0005' }, // PR #15 deepset rows
    'AML.T0051.001': { name: 'LLM Prompt Injection: Indirect', tactic: 'AML.TA0005' },
    'AML.T0053': { name: 'AI Agent Tool Invocation', tactic: 'AML.TA0005' },
    'AML.T0057': { name: 'LLM Data Leakage', tactic: 'AML.TA0010' },
    'AML.T0068': { name: 'LLM Prompt Obfuscation', tactic: 'AML.TA0007' },
    'AML.T0086': { name: 'Exfiltration via AI Agent Tool Invocation', tactic: 'AML.TA0010' },
  },
  attackTactics: {
    TA0010: 'Exfiltration',
  },
  attackTechniques: {
    T1041: { name: 'Exfiltration Over C2 Channel', tactic: 'TA0010' },
    T1567: { name: 'Exfiltration Over Web Service', tactic: 'TA0010' },
  },
  owaspLlm: {
    LLM01: 'Prompt Injection',
    LLM02: 'Sensitive Information Disclosure',
    LLM06: 'Excessive Agency',
  },
  owaspAgentic: {
    ASI01: 'Agent Goal Hijack',
    ASI02: 'Tool Misuse and Exploitation',
  },
  // OASB-1 category slug -> display name (DVAA README "Attack Categories")
  oasb: {
    'prompt-injection': 'Prompt Injection',
    'data-exfiltration': 'Data Exfiltration',
    'capability-abuse': 'Capability Abuse',
    'context-overflow': 'Context Overflow',
  },
});

// Falcon-style severity bands (numeric 0–100 + name).
export const SEVERITY_BANDS = deepFreeze([
  { min: 90, name: 'Critical' },
  { min: 70, name: 'High' },
  { min: 50, name: 'Medium' },
  { min: 20, name: 'Low' },
  { min: 0, name: 'Informational' },
]);

export function severityName(score) {
  if (!Number.isFinite(score) || score < 0 || score > 100) {
    throw new RangeError(`severity must be a number in [0,100], got ${score}`);
  }
  return SEVERITY_BANDS.find((b) => score >= b.min).name;
}

// ---- The single mapping table -------------------------------------------------------------------
// atlas[0] is the PRIMARY technique; it drives the top-level Falcon Tactic/Technique fields.
// requiresSink: alert must carry Entities.sink + Entities.toolCall (egress-shaped detections).
export const CATEGORY_MAP = deepFreeze({
  honeytoken_exfil: {
    detectName: 'HoneytokenExfiltrationAttempt',
    description: 'A planted honeytoken (canary secret) reached an egress sink via an agent tool call.',
    severity: 95,
    layer: 'honeytoken',
    requiresSink: true,
    atlas: ['AML.T0086', 'AML.T0057', 'AML.T0051.001'],
    attack: ['T1567', 'T1041'],
    owaspLlm: ['LLM02', 'LLM01', 'LLM06'],
    owaspAgentic: ['ASI01', 'ASI02'],
    oasb: 'data-exfiltration',
  },
  taint_flow_exfil: {
    detectName: 'PromptInjectionDrivenExfiltration',
    description:
      'Data derived from an untrusted source flowed through a sensitive read into an external sink in one agent turn.',
    severity: 90,
    layer: 'taint',
    requiresSink: true,
    atlas: ['AML.T0086', 'AML.T0051.001', 'AML.T0053'],
    attack: ['T1567', 'T1041'],
    owaspLlm: ['LLM01', 'LLM02', 'LLM06'],
    owaspAgentic: ['ASI01', 'ASI02'],
    oasb: 'data-exfiltration',
  },
  indirect_prompt_injection: {
    detectName: 'IndirectPromptInjection',
    description: 'Instruction-like content arrived via an untrusted tool output / retrieved document.',
    severity: 70,
    layer: 'taint',
    requiresSink: false,
    atlas: ['AML.T0051.001'],
    attack: [],
    owaspLlm: ['LLM01'],
    owaspAgentic: ['ASI01'],
    oasb: 'prompt-injection',
  },
  egress_secret_pattern: {
    detectName: 'SensitiveDataEgress',
    description: 'Secret/PII-shaped data (pattern or entropy match) was observed in an outbound tool call.',
    severity: 75,
    layer: 'egress',
    requiresSink: true,
    atlas: ['AML.T0057', 'AML.T0086'],
    attack: ['T1567', 'T1041'],
    owaspLlm: ['LLM02'],
    owaspAgentic: ['ASI02'],
    oasb: 'data-exfiltration',
  },
  egress_markdown_image: {
    detectName: 'MarkdownImageExfiltration',
    description: 'Response contains a markdown image/link whose URL encodes data toward an external host.',
    severity: 75,
    layer: 'egress',
    requiresSink: true,
    atlas: ['AML.T0057', 'AML.T0051.001'],
    attack: ['T1567'],
    owaspLlm: ['LLM01', 'LLM02'],
    owaspAgentic: ['ASI01'],
    oasb: 'data-exfiltration',
  },
  egress_unallowlisted_domain: {
    detectName: 'NonAllowlistedEgressDestination',
    description: 'Agent tool call targeted a destination outside the egress allowlist.',
    severity: 55,
    layer: 'egress',
    requiresSink: true,
    atlas: ['AML.T0086', 'AML.T0053'],
    attack: ['T1567', 'T1041'],
    owaspLlm: ['LLM06'],
    owaspAgentic: ['ASI02'],
    oasb: 'capability-abuse',
  },
  scan_cap_exceeded: {
    detectName: 'ScanCapExceeded',
    description:
      'Input exceeded the configured full-payload scan cap; raised loudly instead of silently truncating (possible context-padding evasion).',
    severity: 50,
    layer: 'bounds',
    requiresSink: false,
    atlas: ['AML.T0068'],
    attack: [],
    owaspLlm: ['LLM01'],
    owaspAgentic: ['ASI01'],
    oasb: 'context-overflow',
  },
});

export const CATEGORIES = Object.freeze(Object.keys(CATEGORY_MAP));

export class UnknownCategoryError extends Error {
  constructor(category) {
    super(`unknown detector category "${category}"; known: ${CATEGORIES.join(', ')}`);
    this.name = 'UnknownCategoryError';
    this.category = category;
  }
}

/**
 * Resolve a detector category to fully-expanded framework tags. Throws on unknown category.
 * Pure lookup (O(1)) — no capped scan on the decision path.
 */
export function getMapping(category) {
  if (!Object.hasOwn(CATEGORY_MAP, category)) throw new UnknownCategoryError(category);
  const m = CATEGORY_MAP[category];
  const atlas = m.atlas.map((id) => {
    const t = CATALOG.atlasTechniques[id];
    return { TechniqueId: id, Technique: t.name, TacticId: t.tactic, Tactic: CATALOG.atlasTactics[t.tactic] };
  });
  const attack = m.attack.map((id) => {
    const t = CATALOG.attackTechniques[id];
    return { TechniqueId: id, Technique: t.name, TacticId: t.tactic, Tactic: CATALOG.attackTactics[t.tactic] };
  });
  return {
    category,
    detectName: m.detectName,
    description: m.description,
    severity: m.severity,
    layer: m.layer,
    requiresSink: m.requiresSink,
    MitreAtlas: atlas,
    MitreAttack: attack,
    OwaspLlm: m.owaspLlm.map((id) => ({ Id: id, Name: CATALOG.owaspLlm[id] })),
    OwaspAgentic: m.owaspAgentic.map((id) => ({ Id: id, Name: CATALOG.owaspAgentic[id] })),
    Oasb: { Benchmark: 'OASB-1', Category: CATALOG.oasb[m.oasb], Slug: m.oasb },
  };
}

/**
 * Self-check: every ID referenced by CATEGORY_MAP exists in CATALOG, every technique's tactic exists,
 * and every category has a primary ATLAS technique. Returns [] when consistent; list of problems else.
 * Run at import time (below) so a bad edit to the table fails loud on first load.
 */
export function validateMappingTable(map = CATEGORY_MAP, catalog = CATALOG) {
  const problems = [];
  for (const [cat, m] of Object.entries(map)) {
    if (!m.detectName) problems.push(`${cat}: missing detectName`);
    if (!Array.isArray(m.atlas) || m.atlas.length === 0) problems.push(`${cat}: needs >=1 ATLAS technique`);
    for (const id of m.atlas ?? []) {
      const t = catalog.atlasTechniques[id];
      if (!t) problems.push(`${cat}: unknown ATLAS technique ${id}`);
      else if (!catalog.atlasTactics[t.tactic]) problems.push(`${cat}: ATLAS ${id} has unknown tactic ${t.tactic}`);
    }
    for (const id of m.attack ?? []) {
      const t = catalog.attackTechniques[id];
      if (!t) problems.push(`${cat}: unknown ATT&CK technique ${id}`);
      else if (!catalog.attackTactics[t.tactic]) problems.push(`${cat}: ATT&CK ${id} has unknown tactic ${t.tactic}`);
    }
    for (const id of m.owaspLlm ?? []) if (!catalog.owaspLlm[id]) problems.push(`${cat}: unknown OWASP LLM ${id}`);
    for (const id of m.owaspAgentic ?? []) if (!catalog.owaspAgentic[id]) problems.push(`${cat}: unknown ASI ${id}`);
    if (!catalog.oasb[m.oasb]) problems.push(`${cat}: unknown OASB-1 category ${m.oasb}`);
    try {
      severityName(m.severity);
    } catch (e) {
      problems.push(`${cat}: ${e.message}`);
    }
  }
  return problems;
}

const _problems = validateMappingTable();
if (_problems.length) {
  throw new Error(`sentinel/alerts/mapping.js table is inconsistent:\n  - ${_problems.join('\n  - ')}`);
}
