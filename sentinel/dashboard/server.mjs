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
import { alertsFor, alertDirs } from './lib/alert-store.mjs';
import { stageAlerts } from './lib/stage.mjs';
import { buildReplay } from './lib/replay.mjs';
import { loadScoring } from './lib/scoring.mjs';
import { BOUNDS, BoundExceededError } from './lib/bounds.mjs';
import { resolveStage } from './lib/stage-set.mjs';
import { exportAlert } from './lib/alert-export.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC = path.join(HERE, 'public');
const STATIC = new Map([
  ['/', ['index.html', 'text/html; charset=utf-8']],
  ['/index.html', ['index.html', 'text/html; charset=utf-8']],
  ['/app.js', ['app.js', 'text/javascript; charset=utf-8']],
  ['/graph.js', ['graph.js', 'text/javascript; charset=utf-8']],
  ['/replay-view.js', ['replay-view.js', 'text/javascript; charset=utf-8']],
  ['/styles.css', ['styles.css', 'text/css; charset=utf-8']],
  ['/headline-view.js', ['headline-view.js', 'text/javascript; charset=utf-8']],
  ['/stage-view.js', ['stage-view.js', 'text/javascript; charset=utf-8']],
]);

// ---- DNS-rebinding defense -------------------------------------------------------------------
// The dashboard is loopback-only. Binding 127.0.0.1 alone does not stop DNS rebinding: a page on
// evil.example can re-point its name at 127.0.0.1 and read /api/* same-origin. The browser still
// sends `Host: evil.example:<port>`, so every request whose Host is not a loopback name on our own
// port is refused with 421 before routing. Missing Host (HTTP/1.0 tools) is refused too.
export const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1']);

/** True iff `hostHeader` names a loopback host on exactly `port` (port may be omitted only for 80). */
export function isAllowedHost(hostHeader, port) {
  if (typeof hostHeader !== 'string' || !hostHeader) return false;
  const m = hostHeader.toLowerCase().match(/^(\[::1\]|[^:\[\]]+)(?::(\d{1,5}))?$/);
  if (!m) return false;
  const name = m[1] === '[::1]' ? '::1' : m[1];
  if (!LOOPBACK_HOSTS.has(name)) return false;
  const p = m[2] === undefined ? 80 : Number(m[2]);
  return p === port;
}

/**
 * Refuse a non-loopback bind. With the Host allowlist above, a LAN bind could only ever answer 421,
 * and without it the replay data would be exposed to the network, so there is no useful override.
 * Throws with a loud message; the CLI prints it and exits 2.
 */
export function assertLoopbackBind(host) {
  if (!LOOPBACK_HOSTS.has(String(host).toLowerCase())) {
    throw new Error(`refusing to bind --host ${host}: the dashboard is loopback-only (allowed: ${[...LOOPBACK_HOSTS].join(', ')}). ` +
      'Binding a non-loopback address would expose replay data to the network.');
  }
}

const PLACEHOLDER_HIDDEN = 'placeholder data is hidden on the stage view; open the dashboard with ?dev=1 to see it';

/**
 * Build the full replay payload for one capture run. Exported for tests and the CLI.
 * `dev: false` (what the HTTP server uses unless the page has ?dev=1) hides placeholder-only captures and
 * placeholder alert sidecars, so the PLACEHOLDER banner cannot appear on the stage captures. The
 * programmatic default keeps them, since the fixtures are what the bounds tests replay.
 */
export async function replayPayload(index, id, runKey, { dev = true } = {}) {
  const entry = index.get(id); // targeted lookup; ids never become file paths
  if (!entry) return { status: 404, body: { error: `unknown capture id ${id}` } };
  if (!dev && entry.source === 'placeholder') return { status: 404, body: { error: `${id}: ${PLACEHOLDER_HIDDEN}` } };
  const capture = await loadCapture(entry);
  if (!dev && capture.placeholder) return { status: 404, body: { error: `${id}: ${PLACEHOLDER_HIDDEN}` } };
  const run = runKey ? capture.runs.find(r => r.key === runKey) : capture.runs[0];
  if (!run) return { status: 404, body: { error: `capture ${id} has no run ${runKey}`, runs: capture.runs.map(r => r.key) } };

  const src = await alertsFor(capture, run.key, alertDirs(process.env).filter(d => dev || !d.placeholder));
  const t0 = performance.now();
  const adapted = await adaptAlerts(src.alerts, `${id}#${run.key}`);
  const { validatorOrigin } = adapted;
  // Honest dispositions: on a run where the exfil landed, every alert is post-execution (alert-only).
  const exfilLanded = run.outcome.exfilExecuted === true;
  const alerts = stageAlerts(adapted.alerts, { canaryHit: exfilLanded });
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

async function listPayload(index, { dev = true } = {}) {
  const items = [];
  let hidden = 0;
  for (const entry of index.values()) {
    if (!dev && entry.source === 'placeholder') { hidden++; continue; }
    try {
      const c = await loadCapture(entry);
      if (!dev && c.placeholder) { hidden++; continue; }
      items.push({ id: c.id, title: c.title, source: c.source, placeholder: c.placeholder, scenario: c.scenario, expectedLabel: c.expectedLabel, bytes: c.bytes, runs: c.runs.map(r => ({ key: r.key, label: r.label, role: r.role })) });
    } catch (err) {
      // A broken capture stays in the list with its error. It is never silently hidden.
      items.push({ id: entry.id, source: entry.source, error: err.message, bound: err.bound ?? null });
    }
  }
  return { items, hiddenPlaceholders: hidden };
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

const isDev = (url) => url.searchParams.get('dev') === '1';

export function createServer({ roots = defaultRoots() } = {}) {
  const server = http.createServer(async (req, res) => {
    try {
      const port = server.address()?.port;
      if (!isAllowedHost(req.headers.host, port)) {
        console.warn(`[sentinel-dashboard] ALERT refused request with Host ${JSON.stringify(req.headers.host ?? null)} (allowed: loopback:${port}); possible DNS rebinding`);
        return send(res, 421, { error: 'misdirected request: Host must be 127.0.0.1, localhost or [::1] on this port' });
      }
      if (req.method !== 'GET') return send(res, 405, { error: 'GET only' });
      const url = new URL(req.url, 'http://localhost');
      // No favicon asset; answer 204 so the browser console stays clean (index.html also sets data:,).
      if (url.pathname === '/favicon.ico') return send(res, 204, '');
      if (STATIC.has(url.pathname)) {
        const [file, type] = STATIC.get(url.pathname);
        return send(res, 200, await readFile(path.join(PUBLIC, file)), type);
      }
      if (url.pathname === '/api/captures') {
        const index = await indexCaptures(roots);
        const { items, hiddenPlaceholders } = await listPayload(index, { dev: isDev(url) });
        return send(res, 200, { captures: items, hiddenPlaceholders, stage: resolveStage(items), dev: isDev(url), bounds: BOUNDS });
      }
      if (url.pathname === '/api/replay') {
        const index = await indexCaptures(roots);
        const r = await replayPayload(index, url.searchParams.get('id') ?? '', url.searchParams.get('run'), { dev: isDev(url) });
        return send(res, r.status, r.body);
      }
      if (url.pathname === '/api/alert-export') {
        const index = await indexCaptures(roots);
        const r = await exportAlert(index, url.searchParams.get('id') ?? '', url.searchParams.get('run'), url.searchParams.get('alert') ?? '', { dev: isDev(url) });
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
  return server;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const arg = (k, d) => {
    const i = process.argv.indexOf(k);
    return i > -1 ? process.argv[i + 1] : d;
  };
  const port = Number(arg('--port', process.env.PORT ?? 9100));
  const host = arg('--host', '127.0.0.1');
  try {
    assertLoopbackBind(host);
  } catch (err) {
    console.error(`[sentinel-dashboard] ERROR ${err.message}`);
    process.exit(2);
  }
  createServer().listen(port, host, () => console.log(`SentinelProxy dashboard → http://${host}:${port}`));
}
