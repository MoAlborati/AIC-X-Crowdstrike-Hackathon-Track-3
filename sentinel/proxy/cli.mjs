#!/usr/bin/env node
// Start Tourniquet.
//   node sentinel/proxy/cli.mjs [--config path/to/config.json] [--mode observe|block] [--target-port N]
//                               [--listen-port N] [--capture-path FILE] [--max-request-bytes N] ...
//                               [--inspector ./extra-inspector.mjs]
// Precedence: CLI flag > env (SENTINEL_*) > config file. The full flag/env list is OVERRIDES in
// sentinel/config/load.mjs. A bad config exits 2 and lists EVERY problem at once.
//
// --inspector <module>: optional ESM module whose default export is an inspector FUNCTION (contract in
// inspectors.mjs). It runs AFTER the shipped set (substring + T3); it can add verdicts, never remove the
// shipped ones.

import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { loadConfig, ConfigError } from '../config/load.mjs';
import { createProxy, makeLogScrubber } from './server.mjs';
import { buildDefaultInspectors, defaultCanaries } from './default-inspectors.mjs';

const configFail = (err) => {
  process.stderr.write(`[sentinel] config error: ${err.message}\n`);
  process.exit(2);
};

const argv = process.argv.slice(2);
let inspectorPath = null;
const at = argv.findIndex((a) => a === '--inspector' || a.startsWith('--inspector='));
if (at !== -1) {
  inspectorPath = argv[at].includes('=') ? argv[at].slice(argv[at].indexOf('=') + 1) : argv[at + 1];
  argv.splice(at, argv[at].includes('=') ? 1 : 2);
  if (!inspectorPath || inspectorPath.startsWith('--')) configFail(new ConfigError('CLI flag --inspector needs a module path'));
}

let config;
try {
  config = loadConfig({ argv });
} catch (err) {
  if (err instanceof ConfigError) configFail(err);
  throw err;
}

let extraInspector = null;
if (inspectorPath) {
  let mod;
  try {
    mod = await import(pathToFileURL(resolve(inspectorPath)).href);
  } catch (err) {
    configFail(new ConfigError(`--inspector ${inspectorPath} cannot be loaded: ${err.message}`));
  }
  if (typeof mod.default !== 'function') {
    configFail(new ConfigError(`--inspector ${inspectorPath}: default export must be an inspector function (see inspectors.mjs)`));
  }
  extraInspector = mod.default;
}

// Shipped inspector set: T2 substring inspector + T3 detector (see default-inspectors.mjs). One scrubber,
// over T3's honeytokens + flagSubstrings, redacts proxy alerts, verdicts and T3's own log lines.
let proxy;
const names = ['substring', 'sentinel-t3'];
try {
  const scrub = makeLogScrubber(defaultCanaries(config));
  const { inspectors } = buildDefaultInspectors(config, { scrub });
  if (extraInspector) {
    inspectors.push(extraInspector);
    names.push(extraInspector.name || 'extra');
  }
  proxy = createProxy(config, { inspectors, scrub });
} catch (err) {
  if (err instanceof ConfigError) configFail(err);
  throw err;
}
const addr = await proxy.listen();
// Machine-readable first line so scripts/tests can discover an ephemeral port.
process.stdout.write(`${JSON.stringify({ event: 'listening', host: addr.address, port: addr.port, mode: config.mode, target: config.target, inspectors: names, capture: config.capture.path, overrides: config.source.overrides })}\n`);

const shutdown = async () => {
  await proxy.close();
  process.exit(0);
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
