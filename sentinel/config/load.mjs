// SentinelProxy config loader. Pure Node (no deps), Node >= 22.
//
// Resolution order (later wins; ported CLI flags from the retired PR #21 loader):
//   1. sentinel/config/sentinel.config.json (or the file named by --config / SENTINEL_CONFIG)
//   2. Environment overrides (OVERRIDES below): SENTINEL_MODE, SENTINEL_TARGET_HOST, SENTINEL_TARGET_PORT,
//      SENTINEL_LISTEN_HOST, SENTINEL_LISTEN_PORT, SENTINEL_CAPTURE_PATH, SENTINEL_MAX_* / *_MS limits
//   3. CLI flags (--mode, --target-port, --listen-port, --capture-path, --max-request-bytes, ...)
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

// Absolute ceilings (ported from the retired PR #21 loader): a config may lower any cap freely but can
// never raise one past these, whatever the file, env or CLI says.
export const HARD_LIMITS = Object.freeze({
  maxRequestBytes: 16 * 1024 * 1024,
  maxResponseBytes: 64 * 1024 * 1024,
  upstreamTimeoutMs: 120_000,
  inspectorTimeoutMs: 10_000,
  clientTimeoutMs: 300_000,
  maxInFlight: 1024,
  captureMaxFileBytes: 1024 * 1024 * 1024,
});

// Every key the loader understands. Anything else is a ConfigError (catches typos such as
// `maxRequestByte`, which would otherwise be silently ignored). Keys starting with `_` are comments.
const SHAPE = Object.freeze({
  listen: ['host', 'port'],
  target: ['host', 'port'],
  mode: null,
  limits: ['maxRequestBytes', 'maxResponseBytes', 'upstreamTimeoutMs', 'inspectorTimeoutMs', 'clientTimeoutMs', 'maxInFlight'],
  capture: ['path', 'maxFileBytes'],
  inspect: ['flagSubstrings'],
});

// key path -> env var + CLI flag. Precedence (highest first): CLI flag > env > file.
export const OVERRIDES = Object.freeze({
  mode: { env: 'SENTINEL_MODE', flag: '--mode', type: 'string' },
  'listen.host': { env: 'SENTINEL_LISTEN_HOST', flag: '--listen-host', type: 'string' },
  'listen.port': { env: 'SENTINEL_LISTEN_PORT', flag: '--listen-port', type: 'int' },
  'target.host': { env: 'SENTINEL_TARGET_HOST', flag: '--target-host', type: 'string' },
  'target.port': { env: 'SENTINEL_TARGET_PORT', flag: '--target-port', type: 'int' },
  'limits.maxRequestBytes': { env: 'SENTINEL_MAX_REQUEST_BYTES', flag: '--max-request-bytes', type: 'int' },
  'limits.maxResponseBytes': { env: 'SENTINEL_MAX_RESPONSE_BYTES', flag: '--max-response-bytes', type: 'int' },
  'limits.upstreamTimeoutMs': { env: 'SENTINEL_UPSTREAM_TIMEOUT_MS', flag: '--upstream-timeout-ms', type: 'int' },
  'limits.inspectorTimeoutMs': { env: 'SENTINEL_INSPECTOR_TIMEOUT_MS', flag: '--inspector-timeout-ms', type: 'int' },
  'limits.clientTimeoutMs': { env: 'SENTINEL_CLIENT_TIMEOUT_MS', flag: '--client-timeout-ms', type: 'int' },
  'limits.maxInFlight': { env: 'SENTINEL_MAX_IN_FLIGHT', flag: '--max-in-flight', type: 'int' },
  'capture.path': { env: 'SENTINEL_CAPTURE_PATH', flag: '--capture-path', type: 'string' },
  'capture.maxFileBytes': { env: 'SENTINEL_CAPTURE_MAX_FILE_BYTES', flag: '--capture-max-file-bytes', type: 'int' },
});

/**
 * Fail-loud config error. Carries EVERY problem found (`issues`), so one bad deploy shows all of its
 * mistakes at once instead of one per restart.
 */
export class ConfigError extends Error {
  /** @param {string|string[]} issues */
  constructor(issues) {
    const list = Array.isArray(issues) ? issues : [issues];
    super(list.length === 1 ? list[0] : `${list.length} config issues:\n  - ${list.join('\n  - ')}`);
    this.name = 'ConfigError';
    this.issues = list;
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

/** Unknown top-level / section keys (comment keys starting with `_` are allowed). */
function unknownKeyIssues(raw) {
  const issues = [];
  for (const k of Object.keys(raw)) {
    if (!k.startsWith('_') && !Object.hasOwn(SHAPE, k)) {
      issues.push(`unknown top-level key "${k}" (allowed: ${Object.keys(SHAPE).join(', ')})`);
    }
  }
  for (const [section, keys] of Object.entries(SHAPE)) {
    const v = raw[section];
    if (keys === null || v === undefined) continue;
    if (v === null || typeof v !== 'object' || Array.isArray(v)) {
      issues.push(`${section} must be an object`);
      continue;
    }
    for (const k of Object.keys(v)) {
      if (!k.startsWith('_') && !keys.includes(k)) issues.push(`unknown key ${section}.${k} (allowed: ${keys.join(', ')})`);
    }
  }
  return issues;
}

/**
 * Validate and normalise a raw config object. Returns a new frozen object. Every problem is collected
 * and thrown together in one ConfigError (`err.issues`).
 * @param {object} raw
 * @param {{baseDir?: string}} [opts] baseDir for resolving a relative capture.path
 */
export function validateConfig(raw, { baseDir = REPO_ROOT } = {}) {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) throw new ConfigError('config must be a JSON object');
  const issues = unknownKeyIssues(raw);
  const check = (fn) => {
    try {
      return fn();
    } catch (err) {
      if (!(err instanceof ConfigError)) throw err;
      issues.push(...err.issues);
      return undefined;
    }
  };
  const section = (k) => (raw[k] !== null && typeof raw[k] === 'object' && !Array.isArray(raw[k]) ? raw[k] : {});
  const listen = section('listen');
  const target = section('target');
  const limits = section('limits');
  const capture = section('capture');
  const inspect = section('inspect');
  const capped = (value, field, ceiling) => {
    const n = asPositiveInt(value, field);
    if (n > ceiling) throw new ConfigError(`${field}=${n} exceeds the hard ceiling ${ceiling}`);
    return n;
  };

  const mode = check(() => {
    if (!MODES.includes(raw.mode)) throw new ConfigError(`mode must be one of ${MODES.join('|')}, got ${JSON.stringify(raw.mode)}`);
    return raw.mode;
  });
  const targetPort = check(() => {
    const p = asPort(target.port, 'target.port');
    if (p === 0) throw new ConfigError('target.port must be 1-65535 (0 is not a valid upstream)');
    return p;
  });
  const capturePath = check(() => {
    if (typeof capture.path !== 'string' || capture.path === '') throw new ConfigError('capture.path must be a non-empty string');
    return isAbsolute(capture.path) ? capture.path : resolve(baseDir, capture.path);
  });
  const flagSubstrings = check(() => {
    const f = inspect.flagSubstrings ?? [];
    if (!Array.isArray(f) || f.some((s) => typeof s !== 'string' || s === '')) {
      throw new ConfigError('inspect.flagSubstrings must be an array of non-empty strings');
    }
    return f;
  });
  const out = {
    listen: {
      host: check(() => asHost(listen.host ?? '127.0.0.1', 'listen.host')),
      port: check(() => asPort(listen.port ?? 8080, 'listen.port')),
    },
    target: {
      host: check(() => asHost(target.host ?? '127.0.0.1', 'target.host')),
      port: targetPort,
    },
    mode,
    limits: {
      maxRequestBytes: check(() => capped(limits.maxRequestBytes, 'limits.maxRequestBytes', HARD_LIMITS.maxRequestBytes)),
      maxResponseBytes: check(() => capped(limits.maxResponseBytes, 'limits.maxResponseBytes', HARD_LIMITS.maxResponseBytes)),
      upstreamTimeoutMs: check(() => capped(limits.upstreamTimeoutMs, 'limits.upstreamTimeoutMs', HARD_LIMITS.upstreamTimeoutMs)),
      inspectorTimeoutMs: check(() => capped(limits.inspectorTimeoutMs, 'limits.inspectorTimeoutMs', HARD_LIMITS.inspectorTimeoutMs)),
      clientTimeoutMs: check(() => capped(limits.clientTimeoutMs, 'limits.clientTimeoutMs', HARD_LIMITS.clientTimeoutMs)),
      maxInFlight: check(() => capped(limits.maxInFlight, 'limits.maxInFlight', HARD_LIMITS.maxInFlight)),
    },
    capture: {
      path: capturePath,
      maxFileBytes: check(() => capped(capture.maxFileBytes, 'capture.maxFileBytes', HARD_LIMITS.captureMaxFileBytes)),
    },
    inspect: { flagSubstrings: Object.freeze([...(flagSubstrings ?? [])]) },
  };
  if (issues.length > 0) throw new ConfigError(issues);
  return Object.freeze({
    listen: Object.freeze(out.listen),
    target: Object.freeze(out.target),
    mode: out.mode,
    limits: Object.freeze(out.limits),
    capture: Object.freeze(out.capture),
    inspect: Object.freeze(out.inspect),
  });
}

function setPath(o, path, value) {
  const keys = path.split('.');
  let cur = o;
  for (const k of keys.slice(0, -1)) {
    if (cur[k] === null || typeof cur[k] !== 'object' || Array.isArray(cur[k])) cur[k] = {};
    cur = cur[k];
  }
  cur[keys.at(-1)] = value;
}

/** Env/CLI values are strings: digits become numbers for int fields; anything else is kept as given so
 *  validation reports it verbatim (e.g. `limits.maxInFlight must be a positive integer, got "lots"`). */
function coerce(value, type) {
  if (type === 'int' && typeof value === 'string' && /^\d+$/.test(value.trim())) return Number(value);
  return value;
}

function applyOverrides(raw, pick, applied, labelOf) {
  const out = structuredClone(raw);
  for (const [path, o] of Object.entries(OVERRIDES)) {
    const v = pick(o);
    if (v === undefined) continue;
    setPath(out, path, coerce(v, o.type));
    if (applied) applied[path] = labelOf(o);
  }
  return out;
}

/** Apply SENTINEL_* environment overrides onto a raw (unvalidated) config object. */
export function applyEnvOverrides(raw, env = process.env, applied = null) {
  return applyOverrides(raw, (o) => env[o.env], applied, (o) => `env ${o.env}`);
}

/**
 * Parse CLI argv into { '--flag': value }. Accepts `--flag value` and `--flag=value`. Unknown flags,
 * positional arguments and flags without a value are pushed onto `issues` (never ignored).
 * @param {string[]} argv
 * @param {string[]} issues
 */
export function parseArgv(argv, issues) {
  const known = new Set(['--config', ...Object.values(OVERRIDES).map((o) => o.flag)]);
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (!arg.startsWith('--')) {
      issues.push(`unexpected CLI argument "${arg}"`);
      continue;
    }
    const eq = arg.indexOf('=');
    const flag = eq === -1 ? arg : arg.slice(0, eq);
    let value = eq === -1 ? undefined : arg.slice(eq + 1);
    if (!known.has(flag)) {
      issues.push(`unknown CLI flag "${flag}" (known: ${[...known].join(', ')})`);
      continue;
    }
    if (value === undefined) {
      value = argv[i + 1];
      if (value === undefined || value.startsWith('--')) {
        issues.push(`CLI flag ${flag} needs a value`);
        continue;
      }
      i += 1;
    }
    out[flag] = value;
  }
  return out;
}

/**
 * Load config from disk, apply env then CLI overrides, validate. Precedence: CLI flag > env > file.
 * `source.overrides` records which field came from which env var / flag.
 * @param {{path?: string, env?: NodeJS.ProcessEnv, argv?: string[]}} [opts]
 */
export function loadConfig({ path, env = process.env, argv = [] } = {}) {
  const issues = [];
  const flags = parseArgv(argv, issues);
  const file = flags['--config'] ?? path ?? env.SENTINEL_CONFIG ?? DEFAULT_CONFIG_PATH;
  let raw;
  try {
    raw = JSON.parse(readFileSync(file, 'utf8'));
  } catch (err) {
    const what = err instanceof SyntaxError ? `config file ${file} is not valid JSON: ${err.message}` : `cannot read config file ${file}: ${err.message}`;
    throw new ConfigError([what, ...issues]);
  }
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) throw new ConfigError([`config file ${file} must hold a JSON object`, ...issues]);
  const applied = {};
  const withEnv = applyEnvOverrides(raw, env, applied);
  const withCli = applyOverrides(withEnv, (o) => flags[o.flag], applied, (o) => `CLI ${o.flag}`);
  let config;
  try {
    config = validateConfig(withCli);
  } catch (err) {
    if (err instanceof ConfigError) throw new ConfigError([...issues, ...err.issues]);
    throw err;
  }
  if (issues.length > 0) throw new ConfigError(issues);
  return Object.freeze({ ...config, source: Object.freeze({ file: resolve(file), overrides: Object.freeze(applied) }) });
}
