#!/usr/bin/env node
// Tourniquet T10 alert pipeline: proxy verdicts -> T4 alerts -> T5 dashboard.
//
//   node sentinel/pipeline/cli.mjs convert <proxy.jsonl> [--out DIR] [--clean]
//       Batch: convert a finished proxy capture once. Deterministic: the same input gives
//       byte-identical output.
//   node sentinel/pipeline/cli.mjs tail <proxy.jsonl> [--out DIR] [--clean]
//       Live: follow a capture the stock proxy CLI is writing (`node sentinel/proxy/cli.mjs`).
//       Only verdicts the proxy recorded are converted (by default the T2 substring inspector).
//   node sentinel/pipeline/cli.mjs convert|tail [<proxy.jsonl>] --egress <egress.jsonl> [...]
//       Also convert the T12 tool-boundary egress inspector log (sentinel/egress, LOG=...egress.jsonl).
//       Each flagged egress record becomes a T4 alert with Direction "egress" (Enforcement "preventive"
//       when the inspector denied it). It joins the chat session of the agent whose turn was in flight
//       at that time, or else a standalone `egress-boundary` incident capture. The proxy JSONL is
//       optional when --egress is given.
//   node sentinel/pipeline/cli.mjs live [--config sentinel/config/sentinel.config.json] [--out DIR]
//                                      [--standin [--standin-config FILE]] [--clean]
//       Demo: start the T2 proxy in-process with the pipeline sink. Verdicts come from the REAL T3
//       detector (sentinel/detectors via t3.mjs). `--standin` swaps in the stand-in inspectors as an
//       explicitly flagged fallback (alerts StandIn, sidecar placeholder). Uses the in-repo T2 proxy.
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
import { createT3Source, t3Rehydrator, T3_CANARIES } from './t3.mjs';
import { loadEgressHoneytokens } from './egress.mjs';

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
  const err = new Error(`${msg}\nusage: cli.mjs convert|tail [<proxy.jsonl>] [--egress egress.jsonl] [--out DIR] [--clean] | live [--config FILE] [--out DIR] [--standin [--standin-config FILE]] [--clean]`);
  err.code = 'USAGE';
  return err;
}

/** Honeytokens are also passed to buildAlert for redaction, even when stand-in rules are not run. */
function canariesFrom(standinConfigPath) {
  // Keyed by id: stand-in and T3 name the same fake value differently, and verdicts look canaries up by id.
  const out = new Map(T3_CANARIES.map((c) => [c.id, { id: c.id, value: c.value }]));
  for (const h of loadStandinConfig(standinConfigPath).honeytokens) if (!out.has(h.id)) out.set(h.id, { id: h.id, value: h.value });
  // T12 deployment honeytokens: egress alerts name them by id, and egress records are redacted with them.
  for (const h of loadEgressHoneytokens()) if (!out.has(h.id)) out.set(h.id, h);
  return [...out.values()];
}

// SENTINEL_PROXY_ROOT: optional override for the checkout root that holds sentinel/proxy + sentinel/config.
// Default: this repo (T2 merged in #14).
async function importProxy(root = process.env.SENTINEL_PROXY_ROOT || REPO) {
  const server = path.join(root, 'sentinel', 'proxy', 'server.mjs');
  const load = path.join(root, 'sentinel', 'config', 'load.mjs');
  if (!existsSync(server) || !existsSync(load)) {
    const err = usage('live mode needs the T2 proxy (sentinel/proxy/server.mjs + sentinel/config/load.mjs). It is not under the proxy root. Unset SENTINEL_PROXY_ROOT to use this repo, or use `tail` next to the proxy CLI.');
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
      standin: { type: 'boolean', default: false },
      'standin-config': { type: 'string' },
      'poll-ms': { type: 'string' },
      egress: { type: 'string' },
    },
  });
  const [cmd, input] = positionals;
  const outDir = path.resolve(values.out ?? DEFAULT_OUT);
  const standinPath = values['standin-config'] ?? STANDIN_CONFIG_PATH;

  if (cmd === 'convert' || cmd === 'tail') {
    if (!input && !values.egress) throw usage(`${cmd}: missing <proxy.jsonl> (or --egress <egress.jsonl>)`);
    const jsonl = input ? path.resolve(input) : null;
    const egress = values.egress ? path.resolve(values.egress) : null;
    const pipeline = createPipeline({
      outDir,
      canaries: canariesFrom(standinPath),
      t3: t3Rehydrator(),
      proxyCapturePath: jsonl ? path.relative(REPO, jsonl) : null,
      egressCapturePath: egress ? path.relative(REPO, egress) : null,
    });
    await pipeline.init({ clean: values.clean });
    if (cmd === 'convert') {
      // Proxy first, so every chat turn window is known before egress records are correlated.
      const r = jsonl ? await readJsonl(jsonl, (rec, line) => pipeline.ingest(rec, line)) : { lines: 0 };
      const e = egress ? await readJsonl(egress, (rec, line) => pipeline.ingest(rec, line)) : { lines: 0 };
      await pipeline.finish();
      emit({ event: 'summary', mode: 'convert', input: jsonl, egressInput: egress, out: outDir, lines: r.lines, egressLines: e.lines, ...pipeline.stats() });
      return;
    }
    const ac = new AbortController();
    const stop = () => ac.abort();
    process.on('SIGINT', stop);
    process.on('SIGTERM', stop);
    emit({ event: 'following', input: jsonl, egressInput: egress, out: outDir, pid: process.pid });
    const pollMs = Number(values['poll-ms'] ?? 200);
    const onIdle = async () => {
      const written = await pipeline.flush();
      if (written.length) emit({ event: 'flushed', captures: written, ...pipeline.stats() });
    };
    // Pending egress records are released by time (EGRESS_MIN_HOLD_MS), not only by new bytes, so a
    // periodic flush runs even when neither file grows.
    const ticker = egress ? setInterval(() => { onIdle().catch((err) => { ac.abort(); fail(err); }); }, Math.max(pollMs, 250)) : null;
    try {
      await Promise.all([
        jsonl ? followJsonl(jsonl, (rec, line) => pipeline.ingest(rec, line), { signal: ac.signal, pollMs, onIdle }) : null,
        egress ? followJsonl(egress, (rec, line) => pipeline.ingest(rec, line), { signal: ac.signal, pollMs, onIdle }) : null,
      ]);
    } finally {
      if (ticker) clearInterval(ticker);
    }
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
    if (values['standin-config'] && !values.standin) throw usage('--standin-config needs --standin (the default verdict source is T3)');
    const t3 = values.standin ? null : createT3Source();
    const pipeline = createPipeline({
      outDir,
      canaries: canariesFrom(standinPath),
      t3: t3 ?? t3Rehydrator(),
      proxyCapturePath: path.relative(REPO, config.capture.path),
    });
    await pipeline.init({ clean: values.clean });
    const sink = new PipelineSink(new JsonlCaptureSink(config.capture), pipeline);
    const inspectors = t3 ? t3.inspectors : standinInspectors(loadStandinConfig(standinPath));
    if (!t3) defaultLog({ level: 'WARN', reason: 'standin_fallback', msg: 'STAND-IN inspectors selected with --standin: alerts are labeled StandIn and the dashboard shows PLACEHOLDER' });
    const proxy = createProxy(config, { sink, inspectors });
    const addr = await proxy.listen();
    emit({
      event: 'listening', host: addr.address, port: addr.port, mode: config.mode, target: config.target,
      capture: config.capture.path, out: outDir, inspectors: t3 ? 'T3 (sentinel/detectors sentinelInspector)' : 'STAND-IN FALLBACK (sentinel/pipeline/standin.mjs, --standin)',
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
