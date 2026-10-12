// Shared fixtures for T4 tests. Verdicts follow the T3 contract documented in schema.js (VERDICT_SHAPE).
import { CATEGORY_MAP } from '../mapping.js';

export function makeVerdict(category, i = 0, overrides = {}) {
  const sink = CATEGORY_MAP[category].requiresSink;
  return {
    category,
    ruleId: `${CATEGORY_MAP[category].layer}.rule_${i % 7}`,
    disposition: ['block', 'allow', 'report'][i % 3],
    detectionLatencyMs: (i % 50) / 10,
    timestamp: Date.UTC(2026, 9, 12, 12, 0, 0) + i * 1000,
    entities: {
      agent: { name: `Agent-${i % 21}`, id: `agent-${i % 21}`, port: 3000 + (i % 21) },
      session: { id: `sess-${Math.floor(i / 5)}` },
      ...(sink
        ? {
            toolCall: { id: `tc-${i}`, name: ['http_post', 'send_email', 'fetch_url'][i % 3], argsPreview: `{"n":${i}}` },
            sink: { type: 'http', destination: `https://collector-${i % 9}.example.test/in` },
          }
        : {}),
    },
    taintPath: [
      { kind: 'source', label: `rag:doc-${i}`, trust: 'untrusted' },
      { kind: 'propagate', label: `db:customers#row-${i}`, trust: 'sensitive' },
      { kind: 'sink', label: 'http_post', toolCallId: `tc-${i}`, trust: 'external' },
    ],
    ...overrides,
  };
}

/** Collect warnings instead of printing them. */
export function warnSink() {
  const warnings = [];
  return { warnings, onWarning: (msg, detail) => warnings.push({ msg, detail }) };
}

export function percentile(sorted, p) {
  return sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))];
}
