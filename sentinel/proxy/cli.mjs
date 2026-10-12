#!/usr/bin/env node
// Start SentinelProxy.
//   node sentinel/proxy/cli.mjs [--config path/to/config.json]
// Env overrides: SENTINEL_CONFIG, SENTINEL_MODE (observe|block), SENTINEL_TARGET_HOST,
// SENTINEL_TARGET_PORT, SENTINEL_LISTEN_HOST, SENTINEL_LISTEN_PORT, SENTINEL_CAPTURE_PATH.

import { parseArgs } from 'node:util';
import { loadConfig, ConfigError } from '../config/load.mjs';
import { createProxy } from './server.mjs';

const { values } = parseArgs({ options: { config: { type: 'string' } } });

let config;
try {
  config = loadConfig({ path: values.config });
} catch (err) {
  if (err instanceof ConfigError) {
    process.stderr.write(`[sentinel] config error: ${err.message}\n`);
    process.exit(2);
  }
  throw err;
}

const proxy = createProxy(config);
const addr = await proxy.listen();
// Machine-readable first line so scripts/tests can discover an ephemeral port.
process.stdout.write(`${JSON.stringify({ event: 'listening', host: addr.address, port: addr.port, mode: config.mode, target: config.target, capture: config.capture.path })}\n`);

const shutdown = async () => {
  await proxy.close();
  process.exit(0);
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
