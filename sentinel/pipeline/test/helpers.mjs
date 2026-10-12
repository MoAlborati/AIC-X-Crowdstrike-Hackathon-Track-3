// Test seams. Nothing here mocks the feature:
//   - the REAL T2 proxy (createProxy, PR #14) proxies to a REAL HTTP upstream (or live DVAA)
//   - the REAL T5 dashboard code (PR #11) loads what the pipeline wrote
// While #14/#11 are unmerged, their code is taken from the PR branches with `git archive` into a temp
// root. Once merged, the in-tree copy is used. A missing branch AND a missing in-tree copy is a hard
// failure, not a skip: these seams are the point of T10.

import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, symlinkSync, readFileSync, readdirSync } from 'node:fs';
import { mkdtemp, readFile } from 'node:fs/promises';
import http from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const HERE = path.dirname(fileURLToPath(import.meta.url));
export const PIPELINE_DIR = path.resolve(HERE, '..');
export const REPO = path.resolve(PIPELINE_DIR, '..', '..');

const roots = new Map();
/** Root that holds `sentinel/<dir>` from this repo, or from `ref` via git archive. Cached per process. */
export function rootWith(dirs, ref) {
  const key = `${dirs.join(',')}@${ref}`;
  if (roots.has(key)) return roots.get(key);
  let root;
  if (dirs.every((d) => existsSync(path.join(REPO, d)))) {
    root = REPO;
  } else {
    root = mkdtempSync(path.join(tmpdir(), 'sentinel-t10-seam-'));
    const tar = execFileSync('git', ['-C', REPO, 'archive', ref, ...dirs], { maxBuffer: 256 * 1024 * 1024 });
    execFileSync('tar', ['-x', '-C', root], { input: tar });
    // Real T4 for the dashboard's validator + buildAlert imports (relative ../../alerts).
    mkdirSync(path.join(root, 'sentinel'), { recursive: true });
    if (!existsSync(path.join(root, 'sentinel', 'alerts'))) symlinkSync(path.join(REPO, 'sentinel', 'alerts'), path.join(root, 'sentinel', 'alerts'));
  }
  roots.set(key, root);
  return root;
}

export const proxyRoot = () => rootWith(['sentinel/proxy', 'sentinel/config'], 'origin/t2-proxy-skeleton');
export const dashboardRoot = () => rootWith(['sentinel/dashboard'], 'origin/t5-dashboard');

export async function importProxy() {
  const root = proxyRoot();
  const [server, sink] = await Promise.all([
    import(pathToFileURL(path.join(root, 'sentinel/proxy/server.mjs')).href),
    import(pathToFileURL(path.join(root, 'sentinel/proxy/capture-sink.mjs')).href),
  ]);
  return { ...server, ...sink, root };
}

export async function importDashboard() {
  const root = dashboardRoot();
  const lib = (f) => import(pathToFileURL(path.join(root, 'sentinel/dashboard', f)).href);
  const [loader, store, adapter, replay, server] = await Promise.all([
    lib('lib/capture-loader.mjs'), lib('lib/alert-store.mjs'), lib('lib/alert-adapter.mjs'), lib('lib/replay.mjs'), lib('server.mjs'),
  ]);
  return { loader, store, adapter, replay, server, root };
}

export const tmp = (prefix = 'sentinel-t10-') => mkdtemp(path.join(tmpdir(), prefix));

/** Real HTTP upstream that answers every request with `respond(reqBody, req)` -> {status, json}. */
export async function startUpstream(respond) {
  const hits = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      hits.push({ path: req.url, bytes: body.length });
      const { status = 200, json } = respond(body, req);
      const out = Buffer.from(JSON.stringify(json));
      res.writeHead(status, { 'content-type': 'application/json', 'content-length': out.length });
      res.end(out);
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { port: server.address().port, hits, close: () => new Promise((r) => { server.closeAllConnections(); server.close(r); }) };
}

export function proxyConfig({ upstreamPort, mode, capturePath, maxRequestBytes = 1048576 }) {
  return {
    listen: { host: '127.0.0.1', port: 0 },
    target: { host: '127.0.0.1', port: upstreamPort },
    mode,
    limits: { maxRequestBytes, maxResponseBytes: 8388608, upstreamTimeoutMs: 10000, inspectorTimeoutMs: 5000, clientTimeoutMs: 30000, maxInFlight: 64 },
    capture: { path: capturePath, maxFileBytes: 536870912 },
    inspect: { flagSubstrings: [] },
  };
}

export async function post(port, body, headers = {}) {
  const res = await fetch(`http://127.0.0.1:${port}/v1/chat/completions`, {
    method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: typeof body === 'string' ? body : JSON.stringify(body),
  });
  return { status: res.status, text: await res.text() };
}

// ---- real recorded content -------------------------------------------------------------------
export const readJson = async (p) => JSON.parse(await readFile(p, 'utf8'));

/** T6 evasion fixture: 22 KB request, injection instruction in the middle (past the first 8 KB). */
export function evasionRequest() {
  const d = JSON.parse(readFileSync(path.join(REPO, 'captures/variants/fixtures/evasion/eva-pos-middle-001.json'), 'utf8'));
  return d.request.body ?? d.request;
}

/** Benign T1 request to RAGBot :7005. */
export function benignRequest() {
  return JSON.parse(readFileSync(path.join(REPO, 'captures/benign/7005_ragbot.req.json'), 'utf8'));
}
export function benignResponse() {
  return JSON.parse(readFileSync(path.join(REPO, 'captures/benign/7005_ragbot.resp.json'), 'utf8'));
}

/** OpenAI-shaped response rebuilt from the REAL T1 RAGBot runA turn (message, tool call, dvaa{}). */
export function exfilResponse({ extraCalls = 0, exfilAt = 0 } = {}) {
  const cap = JSON.parse(readFileSync(path.join(REPO, 'captures/attack/aim-ab.demo.json'), 'utf8'));
  const run = cap.runA;
  const real = run.toolCalls[0];
  const calls = [];
  const total = extraCalls + 1;
  for (let i = 0; i < total; i++) {
    if (i === exfilAt) calls.push(real);
    else calls.push({ id: `call_lookup_${i}`, type: 'function', function: { name: 'lookup_order', arguments: JSON.stringify({ order_id: `ORD-${100000 + i}`, fields: ['status', 'eta'] }) } });
  }
  return {
    id: 'chatcmpl-ragbot-replay', object: 'chat.completion', created: 0, model: 'ragbot',
    choices: [{ index: 0, message: { role: 'assistant', content: run.message, tool_calls: calls }, finish_reason: run.finishReason }],
    dvaa: run.dvaa,
  };
}

export function readSidecars(outDir) {
  const dir = path.join(outDir, 'alerts');
  return readdirSync(dir).filter((f) => f.endsWith('.alerts.json')).sort().map((f) => ({ file: f, doc: JSON.parse(readFileSync(path.join(dir, f), 'utf8')) }));
}

export function readCaptures(outDir) {
  const dir = path.join(outDir, 'captures', 'live');
  return readdirSync(dir).filter((f) => f.endsWith('.json')).sort().map((f) => ({ file: f, doc: JSON.parse(readFileSync(path.join(dir, f), 'utf8')) }));
}

export const allAlerts = (outDir) => readSidecars(outDir).flatMap((s) => s.doc.runs.run);

export const silentLog = () => {
  const entries = [];
  const log = (e) => entries.push(e);
  log.entries = entries;
  return log;
};

export async function dvaaUp(port) {
  try {
    const r = await fetch(`http://127.0.0.1:${port}/health`, { signal: AbortSignal.timeout(1500) });
    return r.ok;
  } catch { return false; }
}
