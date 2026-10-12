#!/usr/bin/env node
// SentinelProxy T2 — CLI.  node sentinel/proxy/cli.js [--config file] [--mode observe|block] [--target-port N] ...
// Flags override env (SENTINEL_*), which overrides the JSON config. Bad config exits 2 with every issue listed.
//
// --inspector <module path>: optional ESM module whose default export is an inspector object
// (see inspector.js). Omitted -> NOOP_INSPECTOR (allow everything).

import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createProxy, createLogger } from './server.js';
import { loadConfig, ConfigError } from './config.js';
import { NOOP_INSPECTOR } from './inspector.js';

const log = createLogger();
const argv = process.argv.slice(2);
let inspectorPath = null;
const i = argv.findIndex((a) => a === '--inspector' || a.startsWith('--inspector='));
if (i !== -1) {
  inspectorPath = argv[i].includes('=') ? argv[i].split('=').slice(1).join('=') : argv[i + 1];
  argv.splice(i, argv[i].includes('=') ? 1 : 2);
}

let config;
try {
  config = loadConfig({ argv });
} catch (err) {
  if (err instanceof ConfigError) {
    log('ERROR', 'config_invalid', { issues: err.issues });
    process.stderr.write(err.message + '\n');
    process.exit(2);
  }
  throw err;
}

let inspector = NOOP_INSPECTOR;
if (inspectorPath) {
  const mod = await import(pathToFileURL(resolve(inspectorPath)).href);
  inspector = mod.default;
  if (!inspector || (typeof inspector.inspectRequest !== 'function' && typeof inspector.inspectResponse !== 'function')) {
    log('ERROR', 'inspector_invalid', { path: inspectorPath, message: 'default export must have inspectRequest and/or inspectResponse' });
    process.exit(2);
  }
}

const proxy = createProxy(config, { inspector, log });
const addr = await proxy.listen();
process.stdout.write(JSON.stringify({ event: 'ready', url: addr.url, mode: config.mode, target: config.target, overrides: config.source.overrides }) + '\n');

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, async () => {
    await proxy.close();
    process.exit(0);
  });
}
