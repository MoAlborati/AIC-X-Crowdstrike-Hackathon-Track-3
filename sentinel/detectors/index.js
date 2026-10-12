// SentinelProxy T3 — detector core public entry point. Zero dependencies; Node >= 22.
export { createDetector, RULES, DECISION_SCHEMA } from './src/detector.js';
export { HoneytokenRegistry, DVAA_HONEYTOKENS, MIN_TOKEN_CHARS } from './src/honeytokens.js';
export { validatePolicy, classifyTool, TOOL_KINDS } from './src/policy.js';
export { deriveGrant, verifyGrant, narrowGrant, evaluateCall, DIMENSIONS } from './src/mandate.js';
export {
  DEFAULT_BOUNDS, resolveBounds, SentinelBoundError, DetectorOverflowError, RegistryFullError, LedgerFullError,
  MandateOverflowError, ScannerTimeoutError, PolicyError,
} from './src/bounds.js';
