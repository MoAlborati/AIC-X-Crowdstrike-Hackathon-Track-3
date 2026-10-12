// SentinelProxy config loader. Pure Node (no deps), Node >= 22.
//
// Resolution order (later wins):
//   1. sentinel/config/sentinel.config.json (or the file named by --config / SENTINEL_CONFIG)
//   2. Environment overrides: SENTINEL_MODE, SENTINEL_TARGET_HOST, SENTINEL_TARGET_PORT,
//      SENTINEL_LISTEN_HOST, SENTINEL_LISTEN_PORT, SENTINEL_CAPTURE_PATH
//
// Validation is strict and fail-loud: an unknown mode, a non-integer port, a missing/non-positive
// limit, or a NON-LOOPBACK listen/target host throws ConfigError. We never fall back to a default
// silently once a value was supplied.
//
// Loopback-only (both directions): the proxy is unauthenticated and its capture log holds full
// plaintext bodies, so it must never listen on a network-reachable address; and the only authorized
// target is the local DVAA sandbox, so it must never forward to a remote host. Accepted hosts:
// `localhost`, any IPv4 in 127.0.0.0/8, `::1` (any spelling), `::ffff:127.x.y.z`. There is no
// opt-out flag on purpose.

import { readFileSync } from 'node:fs';
import { isIP } from 'node:net';
import { dirname, resolve, isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';

export const MODES = Object.freeze(['observe', 'block']);
export const DEFAULT_CONFIG_PATH = resolve(dirname(fileURLToPath(import.meta.url)), 'sentinel.config.json');
// Repo root = two levels above sentinel/config/. Relative capture paths resolve against it so the
// proxy logs to the same place no matter which cwd it was launched from.
export const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');

export class ConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ConfigError';
  }
}

function asPort(value, field) {
  const n = typeof value === 'string' && value.trim() !== '' ? Number(value) : value;
  // Port 0 is allowed for listen (ephemeral, used by tests); targets must be 1..65535.
  if (!Number.isInteger(n) || n < 0 || n > 65535) {
    throw new ConfigError(`${field} must be an integer port 0-65535, got ${JSON.stringify(value)}`);
  }
  return n;
}

function asPositiveInt(value, field) {
  if (!Number.isInteger(value) || value <= 0) {
    throw new ConfigError(`${field} must be a positive integer, got ${JSON.stringify(value)}`);
  }
  return value;
}

/** True only for loopback hosts: `localhost`, 127.0.0.0/8, ::1, ::ffff:127.0.0.0/104. */
export function isLoopbackHost(value) {
  if (typeof value !== 'string') return false;
  let h = value.trim().toLowerCase();
  if (h === 'localhost') return true;
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);
  const family = isIP(h);
  if (family === 4) return h.split('.')[0] === '127';
  if (family === 6) {
    // WHATWG URL canonicalises every IPv6 spelling (0:0:0:0:0:0:0:1, ::ffff:127.0.0.1, ...).
    const canon = new URL(`http://[${h}]/`).hostname;
    return canon === '[::1]' || /^\[::ffff:7f[0-9a-f]{2}:[0-9a-f]{1,4}\]$/.test(canon);
  }
  return false; // hostnames other than localhost, 0.0.0.0, ::, LAN/public IPs, numeric shorthands
}

function asHost(value, field) {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new ConfigError(`${field} must be a non-empty host string, got ${JSON.stringify(value)}`);
  }
  if (!isLoopbackHost(value)) {
    throw new ConfigError(`${field} must be a loopback address (localhost, 127.0.0.0/8 or ::1), got ${JSON.stringify(value)}`);
  }
  return value.trim();
}

/**
 * Validate and normalise a raw config object. Returns a new frozen object.
 * @param {object} raw
 * @param {{baseDir?: string}} [opts] baseDir for resolving a relative capture.path
 */
export function validateConfig(raw, { baseDir = REPO_ROOT } = {}) {
  if (raw === null || typeof raw !== 'object') throw new ConfigError('config must be a JSON object');
  const mode = raw.mode;
  if (!MODES.includes(mode)) {
    throw new ConfigError(`mode must be one of ${MODES.join('|')}, got ${JSON.stringify(mode)}`);
  }
  const listen = raw.listen ?? {};
  const target = raw.target ?? {};
  const limits = raw.limits ?? {};
  const capture = raw.capture ?? {};
  const inspect = raw.inspect ?? {};

  const targetPort = asPort(target.port, 'target.port');
  if (targetPort === 0) throw new ConfigError('target.port must be 1-65535 (0 is not a valid upstream)');

  if (typeof capture.path !== 'string' || capture.path === '') {
    throw new ConfigError('capture.path must be a non-empty string');
  }
  const flagSubstrings = inspect.flagSubstrings ?? [];
  if (!Array.isArray(flagSubstrings) || flagSubstrings.some((s) => typeof s !== 'string' || s === '')) {
    throw new ConfigError('inspect.flagSubstrings must be an array of non-empty strings');
  }

  return Object.freeze({
    listen: Object.freeze({
      host: asHost(listen.host ?? '127.0.0.1', 'listen.host'),
      port: asPort(listen.port ?? 8080, 'listen.port'),
    }),
    target: Object.freeze({
      host: asHost(target.host ?? '127.0.0.1', 'target.host'),
      port: targetPort,
    }),
    mode,
    limits: Object.freeze({
      maxRequestBytes: asPositiveInt(limits.maxRequestBytes, 'limits.maxRequestBytes'),
      maxResponseBytes: asPositiveInt(limits.maxResponseBytes, 'limits.maxResponseBytes'),
      upstreamTimeoutMs: asPositiveInt(limits.upstreamTimeoutMs, 'limits.upstreamTimeoutMs'),
      inspectorTimeoutMs: asPositiveInt(limits.inspectorTimeoutMs, 'limits.inspectorTimeoutMs'),
      clientTimeoutMs: asPositiveInt(limits.clientTimeoutMs, 'limits.clientTimeoutMs'),
      maxInFlight: asPositiveInt(limits.maxInFlight, 'limits.maxInFlight'),
    }),
    capture: Object.freeze({
      path: isAbsolute(capture.path) ? capture.path : resolve(baseDir, capture.path),
      maxFileBytes: asPositiveInt(capture.maxFileBytes, 'capture.maxFileBytes'),
    }),
    inspect: Object.freeze({ flagSubstrings: Object.freeze([...flagSubstrings]) }),
  });
}

/** Apply SENTINEL_* environment overrides onto a raw (unvalidated) config object. */
export function applyEnvOverrides(raw, env = process.env) {
  const out = structuredClone(raw);
  out.listen ??= {};
  out.target ??= {};
  out.capture ??= {};
  if (env.SENTINEL_MODE !== undefined) out.mode = env.SENTINEL_MODE;
  if (env.SENTINEL_TARGET_HOST !== undefined) out.target.host = env.SENTINEL_TARGET_HOST;
  if (env.SENTINEL_TARGET_PORT !== undefined) out.target.port = env.SENTINEL_TARGET_PORT;
  if (env.SENTINEL_LISTEN_HOST !== undefined) out.listen.host = env.SENTINEL_LISTEN_HOST;
  if (env.SENTINEL_LISTEN_PORT !== undefined) out.listen.port = env.SENTINEL_LISTEN_PORT;
  if (env.SENTINEL_CAPTURE_PATH !== undefined) out.capture.path = env.SENTINEL_CAPTURE_PATH;
  return out;
}

/**
 * Load config from disk, apply env overrides, validate.
 * @param {{path?: string, env?: NodeJS.ProcessEnv}} [opts]
 */
export function loadConfig({ path, env = process.env } = {}) {
  const file = path ?? env.SENTINEL_CONFIG ?? DEFAULT_CONFIG_PATH;
  let text;
  try {
    text = readFileSync(file, 'utf8');
  } catch (err) {
    throw new ConfigError(`cannot read config file ${file}: ${err.message}`);
  }
  let raw;
  try {
    raw = JSON.parse(text);
  } catch (err) {
    throw new ConfigError(`config file ${file} is not valid JSON: ${err.message}`);
  }
  return validateConfig(applyEnvOverrides(raw, env));
}
