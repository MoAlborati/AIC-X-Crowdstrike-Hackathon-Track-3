#!/usr/bin/env node
// SentinelProxy T10 alert pipeline: proxy verdicts -> T4 alerts -> T5 dashboard.
//
//   node sentinel/pipeline/cli.mjs convert <proxy.jsonl> [--out DIR] [--clean]
//       Batch: convert a finished proxy capture once. Deterministic: the same input gives
//       byte-identical output.
//   node sentinel/pipeline/cli.mjs tail <proxy.jsonl> [--out DIR] [--clean]
//       Live: follow a capture the stock proxy CLI is writing (`node sentinel/proxy/cli.mjs`).
//       Only verdicts the proxy recorded are converted (by default the T2 substring inspector).
//   node sentinel/pipeline/cli.mjs live [--config sentinel/config/sentinel.config.json] [--out DIR]
//                                      [--standin-config FILE] [--clean]
//       Demo: start the T2 proxy in-process with the STAND-IN inspectors and the pipeline sink.
//       Before PR #14 merges, set SENTINEL_PROXY_ROOT to a checkout of t2-proxy-skeleton.
//
// Then run the dashboard against the output:
//   SENTINEL_CAPTURES_DIR=<out>/captures SENTINEL_ALERTS_DIR=<out>/alerts node sentinel/dashboard/server.mjs
//
// Default --out: sentinel/pipeline/out (gitignored). Exit codes: 0 ok, 2 usage/config, 3 bound
// exceeded (fail-loud), 1 other error. Every stderr line is `[sentinel-pipeline] LEVEL {json}`.
// stdout carries one JSON event per line (`listening`, `flushed`, `summary`).

import { parseArgs } from 'node:util';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createPipeline } from './pipeline.mjs';
import { readJsonl, followJsonl } from './jsonl.mjs';
import { PipelineBoundError, defaultLog } from './bounds.mjs';
import { loadStandinConfig, standinInspectors, STANDIN_CONFIG_PATH } from './standin.mjs';
import { PipelineSink } from './sink.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
export const DEFAULT_OUT = path.join(HERE, 'out');

const emit = (obj) => process.stdout.write(`${JSON.stringify(obj)}\n`);

function fail(err) {
  const code = err instanceof PipelineBoundError ? 3 : err.code === 'USAGE' ? 2 : 1;
  defaultLog({ level: code === 3 ? 'ALERT' : 'ERROR', error: err.message, ...(err.toJSON ? err.toJSON() : {}), exit: code });
  process.exit(code);
}

function usage(msg) {
  const err = new Error(`${msg}\nusage: cli.mjs convert|tail <proxy.jsonl> [--out DIR] [--clean] | live [--config FILE] [--out DIR] [--standin-config FILE] [--clean]`);
  err.code = 'USAGE';
  return err;
}

/** Honeytokens are also passed to buildAlert for redaction, even when stand-in rules are not run. */
function canariesFrom(standinConfigPath) {
  return loadStandinConfig(standinConfigPath).honeytokens.map((h) => ({ id: h.id, value: h.value }));
}

// SENTINEL_PROXY_ROOT: a checkout root that holds sentinel/proxy + sentinel/config, used while PR #14
// is unmerged (e.g. `git worktree add /tmp/t2 origin/t2-proxy-skeleton`). Default: this repo.
async function importProxy(root = process.env.SENTINEL_PROXY_ROOT || REPO) {
  const server = path.join(root, 'sentinel', 'proxy', 'server.mjs');
  const load = path.join(root, 'sentinel', 'config', 'load.mjs');
  if (!existsSync(server) || !existsSync(load)) {
    const err = usage('live mode needs the T2 proxy (sentinel/proxy/server.mjs + sentinel/config/load.mjs, PR #14). It is not in this checkout. Merge #14, or use `tail` next to the proxy CLI.');
    throw err;
  }
  const [{ createProxy }, { loadConfig, ConfigError }, { JsonlCaptureSink }] = await Promise.all([
    import(pathToFileURL(server).href),
    import(pathToFileURL(load).href),
    import(pathToFileURL(path.join(root, 'sentinel', 'proxy', 'capture-sink.mjs')).href),
  ]);
  return { createProxy, loadConfig, ConfigError, JsonlCaptureSink };
}

export async function main(argv = process.argv.slice(2)) {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      out: { type: 'string' },
      clean: { type: 'boolean', default: false },
      config: { type: 'string' },
      'standin-config': { type: 'string' },
      'poll-ms': { type: 'string' },
    },
  });
  const [cmd, input] = positionals;
  const outDir = path.resolve(values.out ?? DEFAULT_OUT);
  const standinPath = values['standin-config'] ?? STANDIN_CONFIG_PATH;

  if (cmd === 'convert' || cmd === 'tail') {
    if (!input) throw usage(`${cmd}: missing <proxy.jsonl>`);
    const jsonl = path.resolve(input);
    const pipeline = createPipeline({ outDir, canaries: canariesFrom(standinPath), proxyCapturePath: path.relative(REPO, jsonl) });
    await pipeline.init({ clean: values.clean });
    if (cmd === 'convert') {
      const r = await readJsonl(jsonl, (rec, line) => pipeline.ingest(rec, line));
      await pipeline.finish();
      emit({ event: 'summary', mode: 'convert', input: jsonl, out: outDir, lines: r.lines, ...pipeline.stats() });
      return;
    }
    const ac = new AbortController();
    const stop = () => ac.abort();
    process.on('SIGINT', stop);
    process.on('SIGTERM', stop);
    emit({ event: 'following', input: jsonl, out: outDir, pid: process.pid });
    await followJsonl(jsonl, (rec, line) => pipeline.ingest(rec, line), {
      signal: ac.signal,
      pollMs: Number(values['poll-ms'] ?? 200),
      onIdle: async () => {
        const written = await pipeline.flush();
        if (written.length) emit({ event: 'flushed', captures: written, ...pipeline.stats() });
      },
    });
    await pipeline.finish();
    emit({ event: 'summary', mode: 'tail', out: outDir, ...pipeline.stats() });
    return;
  }

  if (cmd === 'live') {
    const { createProxy, loadConfig, ConfigError, JsonlCaptureSink } = await importProxy();
    let config;
    try {
      config = loadConfig({ path: values.config });
    } catch (err) {
      if (err instanceof ConfigError) { err.code = 'USAGE'; }
      throw err;
    }
    const standin = loadStandinConfig(standinPath);
    const pipeline = createPipeline({
      outDir,
      canaries: standin.honeytokens.map((h) => ({ id: h.id, value: h.value })),
      proxyCapturePath: path.relative(REPO, config.capture.path),
    });
    await pipeline.init({ clean: values.clean });
    const sink = new PipelineSink(new JsonlCaptureSink(config.capture), pipeline);
    const proxy = createProxy(config, { sink, inspectors: standinInspectors(standin) });
    const addr = await proxy.listen();
    emit({
      event: 'listening', host: addr.address, port: addr.port, mode: config.mode, target: config.target,
      capture: config.capture.path, out: outDir, inspectors: 'STAND-IN (sentinel/pipeline/standin.mjs) until T3 lands',
      dashboard: `SENTINEL_CAPTURES_DIR=${path.join(outDir, 'captures')} SENTINEL_ALERTS_DIR=${path.join(outDir, 'alerts')} node sentinel/dashboard/server.mjs`,
    });
    const shutdown = async () => {
      await proxy.close();
      emit({ event: 'summary', mode: 'live', out: outDir, ...pipeline.stats() });
      process.exit(0);
    };
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
    return;
  }

  throw usage(cmd ? `unknown command ${cmd}` : 'missing command');
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(fail);
}
