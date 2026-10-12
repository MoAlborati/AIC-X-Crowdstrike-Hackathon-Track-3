// SentinelProxy T2 — config loading + validation.
//
//   loadConfig({ file?, env?, argv? }) -> frozen, fully-resolved config
//
// Precedence (highest first): CLI flag > environment variable > JSON file > nothing.
// There are NO silent defaults for the file itself: every field must be present in the JSON (the shipped
// file is `sentinel/config/proxy.json`). Every problem is collected and thrown together in one
// ConfigError so a bad deploy fails loud at startup, never at the first request.

import { readFileSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const MODES = Object.freeze(['observe', 'block']);
export const DEFAULT_CONFIG_PATH = fileURLToPath(new URL('../config/proxy.json', import.meta.url));

// Absolute ceilings: a config may lower caps freely but cannot raise them past these.
export const HARD_LIMITS = Object.freeze({
  maxRequestBytes: 16 * 1024 * 1024,
  maxResponseBytes: 64 * 1024 * 1024,
  upstreamTimeoutMs: 120_000,
  inspectorTimeoutMs: 10_000,
  maxInFlight: 1024,
  maxFileBytes: 1024 * 1024 * 1024,
  maxFiles: 100,
});

// Per-record overhead allowance (headers, metadata, decisions, alerts) used by the sink-size floor.
export const SINK_RECORD_OVERHEAD_BYTES = 256 * 1024;

export class ConfigError extends Error {
  constructor(issues, source) {
    super(`invalid SentinelProxy config (${source}) — ${issues.length} issue(s):\n  - ${issues.join('\n  - ')}`);
    this.name = 'ConfigError';
    this.issues = issues;
  }
}

// key path -> { env, flag, type }
export const OVERRIDES = Object.freeze({
  'listen.host': { env: 'SENTINEL_LISTEN_HOST', flag: '--listen-host', type: 'string' },
  'listen.port': { env: 'SENTINEL_LISTEN_PORT', flag: '--listen-port', type: 'port0' },
  'target.host': { env: 'SENTINEL_TARGET_HOST', flag: '--target-host', type: 'string' },
  'target.port': { env: 'SENTINEL_TARGET_PORT', flag: '--target-port', type: 'port' },
  'target.name': { env: 'SENTINEL_TARGET_NAME', flag: '--target-name', type: 'string' },
  mode: { env: 'SENTINEL_MODE', flag: '--mode', type: 'mode' },
  'limits.maxRequestBytes': { env: 'SENTINEL_MAX_REQUEST_BYTES', flag: '--max-request-bytes', type: 'int' },
  'limits.maxResponseBytes': { env: 'SENTINEL_MAX_RESPONSE_BYTES', flag: '--max-response-bytes', type: 'int' },
  'limits.upstreamTimeoutMs': { env: 'SENTINEL_UPSTREAM_TIMEOUT_MS', flag: '--upstream-timeout-ms', type: 'int' },
  'limits.inspectorTimeoutMs': { env: 'SENTINEL_INSPECTOR_TIMEOUT_MS', flag: '--inspector-timeout-ms', type: 'int' },
  'limits.maxInFlight': { env: 'SENTINEL_MAX_IN_FLIGHT', flag: '--max-in-flight', type: 'int' },
  'sink.path': { env: 'SENTINEL_SINK_PATH', flag: '--sink-path', type: 'path' },
  'sink.maxFileBytes': { env: 'SENTINEL_SINK_MAX_FILE_BYTES', flag: '--sink-max-file-bytes', type: 'int' },
  'sink.maxFiles': { env: 'SENTINEL_SINK_MAX_FILES', flag: '--sink-max-files', type: 'int' },
});

const SHAPE = Object.freeze({
  listen: ['host', 'port'],
  target: ['host', 'port', 'name'],
  mode: null,
  limits: ['maxRequestBytes', 'maxResponseBytes', 'upstreamTimeoutMs', 'inspectorTimeoutMs', 'maxInFlight'],
  sink: ['path', 'maxFileBytes', 'maxFiles'],
});

const getPath = (o, path) => path.split('.').reduce((v, k) => (v == null ? undefined : v[k]), o);
function setPath(o, path, value) {
  const keys = path.split('.');
  let cur = o;
  for (const k of keys.slice(0, -1)) {
    if (cur[k] === null || typeof cur[k] !== 'object') cur[k] = {};
    cur = cur[k];
  }
  cur[keys.at(-1)] = value;
}

/** Coerce a string from env/CLI into the field's type. Returns { value } or { error }. */
function coerce(raw, type, label) {
  if (type === 'string' || type === 'path' || type === 'mode') return { value: raw };
  if (!/^\d+$/.test(String(raw).trim())) return { error: `${label}="${raw}" is not a non-negative integer` };
  return { value: Number(raw) };
}

/** Parse argv into { flag: value }. Accepts `--flag value` and `--flag=value`. Unknown flags are errors. */
export function parseArgv(argv, issues) {
  const known = new Set(['--config', ...Object.values(OVERRIDES).map((o) => o.flag)]);
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith('--')) {
      issues.push(`unexpected CLI argument "${arg}"`);
      continue;
    }
    let [flag, value] = arg.includes('=') ? [arg.slice(0, arg.indexOf('=')), arg.slice(arg.indexOf('=') + 1)] : [arg, undefined];
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
      i++;
    }
    out[flag] = value;
  }
  return out;
}

function validate(cfg, issues) {
  for (const [section, keys] of Object.entries(SHAPE)) {
    if (keys === null) continue;
    const v = cfg[section];
    if (!v || typeof v !== 'object' || Array.isArray(v)) {
      issues.push(`${section} must be an object`);
      continue;
    }
    for (const k of Object.keys(v)) if (!keys.includes(k)) issues.push(`unknown key ${section}.${k} (allowed: ${keys.join(', ')})`);
    for (const k of keys) if (v[k] === undefined) issues.push(`${section}.${k} is required`);
  }
  for (const k of Object.keys(cfg)) if (!(k in SHAPE)) issues.push(`unknown top-level key "${k}" (allowed: ${Object.keys(SHAPE).join(', ')})`);

  const str = (p) => {
    const v = getPath(cfg, p);
    if (v !== undefined && (typeof v !== 'string' || v.trim() === '')) issues.push(`${p} must be a non-empty string`);
  };
  const intIn = (p, min, max) => {
    const v = getPath(cfg, p);
    if (v === undefined) return;
    if (!Number.isInteger(v) || v < min || v > max) issues.push(`${p}=${JSON.stringify(v)} must be an integer in [${min}, ${max}]`);
  };
  str('listen.host');
  str('target.host');
  str('target.name');
  str('sink.path');
  intIn('listen.port', 0, 65535);
  intIn('target.port', 1, 65535);
  if (cfg.mode !== undefined && !MODES.includes(cfg.mode)) issues.push(`mode="${cfg.mode}" must be one of ${MODES.join('|')}`);
  if (cfg.mode === undefined) issues.push('mode is required (observe|block)');
  intIn('limits.maxRequestBytes', 1, HARD_LIMITS.maxRequestBytes);
  intIn('limits.maxResponseBytes', 1, HARD_LIMITS.maxResponseBytes);
  intIn('limits.upstreamTimeoutMs', 1, HARD_LIMITS.upstreamTimeoutMs);
  intIn('limits.inspectorTimeoutMs', 1, HARD_LIMITS.inspectorTimeoutMs);
  intIn('limits.maxInFlight', 1, HARD_LIMITS.maxInFlight);
  intIn('sink.maxFileBytes', 1, HARD_LIMITS.maxFileBytes);
  intIn('sink.maxFiles', 1, HARD_LIMITS.maxFiles);

  // A worst-case record (both bodies at cap, JSON-escaped up to 2x) must fit in one sink file, so
  // rotation never has to split or drop a record.
  const req = getPath(cfg, 'limits.maxRequestBytes');
  const resp = getPath(cfg, 'limits.maxResponseBytes');
  const file = getPath(cfg, 'sink.maxFileBytes');
  if (Number.isInteger(req) && Number.isInteger(resp) && Number.isInteger(file)) {
    const floor = 2 * (req + resp) + SINK_RECORD_OVERHEAD_BYTES;
    if (file < floor) {
      issues.push(`sink.maxFileBytes=${file} is below the floor 2*(maxRequestBytes+maxResponseBytes)+${SINK_RECORD_OVERHEAD_BYTES}=${floor}`);
    }
  }
}

/**
 * Load, override and validate the proxy config.
 * @param {{ file?: string, env?: Record<string,string|undefined>, argv?: string[], json?: object }} [opts]
 *   `json` supplies the file contents directly (tests); `file` defaults to SENTINEL_CONFIG / --config /
 *   sentinel/config/proxy.json. Relative `sink.path` from the file resolves against the file's directory;
 *   from env/CLI it resolves against process.cwd().
 */
export function loadConfig(opts = {}) {
  const env = opts.env ?? process.env;
  const issues = [];
  const flags = parseArgv(opts.argv ?? [], issues);
  const file = flags['--config'] ?? opts.file ?? env.SENTINEL_CONFIG ?? DEFAULT_CONFIG_PATH;
  const source = opts.json ? 'inline json' : file;

  let cfg;
  if (opts.json) {
    cfg = structuredClone(opts.json);
  } else {
    try {
      cfg = JSON.parse(readFileSync(file, 'utf8'));
    } catch (err) {
      throw new ConfigError([`cannot read config file ${file}: ${err.message}`, ...issues], source);
    }
  }
  if (!cfg || typeof cfg !== 'object' || Array.isArray(cfg)) throw new ConfigError(['config must be a JSON object', ...issues], source);
  const baseDir = opts.json ? process.cwd() : dirname(resolve(file));
  if (typeof cfg.sink?.path === 'string' && !isAbsolute(cfg.sink.path)) cfg.sink.path = resolve(baseDir, cfg.sink.path);

  const applied = {};
  for (const [path, o] of Object.entries(OVERRIDES)) {
    for (const [raw, label] of [
      [env[o.env], `env ${o.env}`],
      [flags[o.flag], `CLI ${o.flag}`],
    ]) {
      if (raw === undefined || raw === '') continue;
      const c = coerce(raw, o.type, label);
      if (c.error) {
        issues.push(c.error);
        continue;
      }
      setPath(cfg, path, o.type === 'path' && !isAbsolute(c.value) ? resolve(process.cwd(), c.value) : c.value);
      applied[path] = label;
    }
  }

  validate(cfg, issues);
  if (issues.length) throw new ConfigError(issues, source);
  return Object.freeze({
    listen: Object.freeze({ ...cfg.listen }),
    target: Object.freeze({ ...cfg.target }),
    mode: cfg.mode,
    limits: Object.freeze({ ...cfg.limits }),
    sink: Object.freeze({ ...cfg.sink }),
    source: Object.freeze({ file: opts.json ? null : resolve(file), overrides: Object.freeze(applied) }),
  });
}
