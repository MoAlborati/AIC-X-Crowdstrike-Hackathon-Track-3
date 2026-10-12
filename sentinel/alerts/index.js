// SentinelProxy T4 — public entry point for alert building.
export * from './schema.js';
export * from './mapping.js';
export {
  redactString, redactDeep, prepareCanaries, SECRET_PATTERNS, MAX_REDACT_SCAN_CHARS, MAX_REDACT_TOTAL_CHARS,
  MAX_CANARIES, MAX_CANARY_VALUE_CHARS,
} from './redact.js';
