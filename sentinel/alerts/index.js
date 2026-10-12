// SentinelProxy T4 — public entry point for alert building.
export * from './schema.js';
export * from './mapping.js';
export { redactString, redactDeep, SECRET_PATTERNS, MAX_REDACT_SCAN_CHARS } from './redact.js';
