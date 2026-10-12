#!/usr/bin/env node
// SentinelProxy dashboard server. Zero dependencies, node:http only, binds 127.0.0.1 by default.
//   node sentinel/dashboard/server.mjs [--port 9100] [--host 127.0.0.1]
// Replays recorded captures. No live LLM or DVAA calls happen here.

import http from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';
import { indexCaptures, loadCapture, defaultRoots, CaptureFormatError } from './lib/capture-loader.mjs';
import { adaptAlerts } from './lib/alert-adapter.mjs';
import { alertsFor } from './lib/alert-store.mjs';
import { buildReplay } from './lib/replay.mjs';
import { loadScoring } from './lib/scoring.mjs';
import { BOUNDS, BoundExceededError } from './lib/bounds.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC = path.join(HERE, 'public');
const STATIC = new Map([
  ['/', ['index.html', 'text/html; charset=utf-8']],
  ['/index.html', ['index.html', 'text/html; charset=utf-8']],
  ['/app.js', ['app.js', 'text/javascript; charset=utf-8']],
  ['/graph.js', ['graph.js', 'text/javascript; charset=utf-8']],
  ['/replay-view.js', ['replay-view.js', 'text/javascript; charset=utf-8']],
  ['/styles.css', ['styles.css', 'text/css; charset=utf-8']],
]);

/** Build the full replay payload for one capture run. Exported for tests and the CLI. */
export async function replayPayload(index, id, runKey) {
  const entry = index.get(id); // targeted lookup; ids never become file paths
  if (!entry) return { status: 404, body: { error: `unknown capture id ${id}` } };
  const capture = await loadCapture(entry);
  const run = runKey ? capture.runs.find(r => r.key === runKey) : capture.runs[0];
  if (!run) return { status: 404, body: { error: `capture ${id} has no run ${runKey}`, runs: capture.runs.map(r => r.key) } };

  const src = await alertsFor(capture, run.key);
  const t0 = performance.now();
  const { alerts, validatorOrigin } = await adaptAlerts(src.alerts, `${id}#${run.key}`);
  const replay = buildReplay(
    { id: `${id}#${run.key}`, agent: run.agent, exchanges: run.exchanges, toolResults: run.toolResults },
    alerts,
    { canaryHits: run.outcome.exfilExecuted ? capture.canaryHits : [] },
  );
  const buildMs = performance.now() - t0;

  return {
    status: 200,
    body: {
      capture: {
        id: capture.id, title: capture.title, scenario: capture.scenario, shape: capture.shape, payload: capture.payload,
        placeholder: capture.placeholder, placeholderNote: capture.placeholderNote, expectedLabel: capture.expectedLabel,
        bytes: capture.bytes, canaryHits: capture.canaryHits,
      },
      run: { key: run.key, label: run.label, role: run.role, agent: run.agent, outcome: run.outcome, exchanges: run.exchanges, toolResults: run.toolResults },
      runs: capture.runs.map(r => ({ key: r.key, label: r.label, role: r.role, outcome: r.outcome })),
      alerts,
      alertSource: { origin: src.origin, placeholder: src.placeholder, note: src.note, validator: validatorOrigin },
      ...replay,
      // Wall-clock, so not part of the deterministic replay. Shown as "dashboard build" latency.
      dashboardBuildMs: Number(buildMs.toFixed(2)),
    },
  };
}

async function listPayload(index) {
  const items = [];
  for (const entry of index.values()) {
    try {
      const c = await loadCapture(entry);
      items.push({ id: c.id, title: c.title, source: c.source, placeholder: c.placeholder, scenario: c.scenario, expectedLabel: c.expectedLabel, bytes: c.bytes, runs: c.runs.map(r => ({ key: r.key, label: r.label, role: r.role })) });
    } catch (err) {
      // A broken capture stays in the list with its error. It is never silently hidden.
      items.push({ id: entry.id, source: entry.source, error: err.message, bound: err.bound ?? null });
    }
  }
  return items;
}

function send(res, status, body, type = 'application/json; charset=utf-8') {
  const data = typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body);
  res.writeHead(status, {
    'content-type': type,
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'content-security-policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:",
  });
  res.end(data);
}

export function createServer({ roots = defaultRoots() } = {}) {
  return http.createServer(async (req, res) => {
    try {
      if (req.method !== 'GET') return send(res, 405, { error: 'GET only' });
      const url = new URL(req.url, 'http://localhost');
      if (STATIC.has(url.pathname)) {
        const [file, type] = STATIC.get(url.pathname);
        return send(res, 200, await readFile(path.join(PUBLIC, file)), type);
      }
      if (url.pathname === '/api/captures') {
        const index = await indexCaptures(roots);
        return send(res, 200, { captures: await listPayload(index), bounds: BOUNDS });
      }
      if (url.pathname === '/api/replay') {
        const index = await indexCaptures(roots);
        const r = await replayPayload(index, url.searchParams.get('id') ?? '', url.searchParams.get('run'));
        return send(res, r.status, r.body);
      }
      if (url.pathname === '/api/scoring') {
        const index = await indexCaptures(roots);
        return send(res, 200, await loadScoring(index));
      }
      if (url.pathname === '/health') return send(res, 200, { ok: true });
      return send(res, 404, { error: 'not found' });
    } catch (err) {
      if (err instanceof BoundExceededError) return send(res, err.bound === 'MAX_CAPTURE_FILES' ? 507 : 413, err.toJSON());
      if (err instanceof CaptureFormatError) return send(res, 422, { error: err.message });
      console.error('[sentinel-dashboard]', err);
      return send(res, 500, { error: err.message });
    }
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const arg = (k, d) => {
    const i = process.argv.indexOf(k);
    return i > -1 ? process.argv[i + 1] : d;
  };
  const port = Number(arg('--port', process.env.PORT ?? 9100));
  const host = arg('--host', '127.0.0.1');
  createServer().listen(port, host, () => console.log(`SentinelProxy dashboard → http://${host}:${port}`));
}
