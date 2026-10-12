// Capture discovery + parsing. Captures are real DVAA recordings from T1 (captures/README.md) and,
// later, T6 variants. The dashboard replays them and never calls a live LLM.
//
// Every capture shape is normalized to the same internal model:
//   { id, source, placeholder, title, scenario, payload, expected, runs: [Run], canaryHits }
//   Run = { key, label, role: 'vulnerable'|'protected'|'benign'|'single', agent:{name,port},
//           exchanges:[{index, messages:[...], assistant:{content, toolCalls:[...]}, dvaa}],
//           toolResults:[...], outcome:{exfilExecuted, blocked, denialReason, trustScore} }
//
// Shapes understood (detected structurally, see detectShape):
//   'demo-ab'     DVAA `demo aim-ab --json`: {scenario, payload, canary, runA, runB}
//   'demo-ledger' DVAA `demo repo --json`:   {beat1, beat2:{ledger}, beat3:{ledger}, canary}
//   'demo-acts'   DVAA `demo flight --json`: {act1, act2, act3, canary, target}
//   'pair'        benign/<port>_<agent>.req.json + .resp.json (OpenAI request + response)
//   'openai'      {request, response} | {exchanges:[...]} with optional toolResults/alerts.
//                 Used by placeholder fixtures and by T6 variants ({id, request, label:{groundTruth, dvaa}}),
//                 which are indexed through captures/variants/manifest.json.
//
// Text that the capture did NOT record (e.g. the body of the poisoned RAG doc in aim-ab) is never
// invented. Those nodes carry `recorded:false` and a descriptor naming what is missing.

import { readdir, readFile, realpath, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { enforce } from './bounds.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const DASHBOARD_DIR = path.resolve(HERE, '..');
export const REPO_ROOT = path.resolve(DASHBOARD_DIR, '..', '..');

// Agent/port for each DVAA demo beat, from captures/README.md (T1). The demo JSON names the agent
// but not the port.
const DEMO_AGENTS = {
  'aim-ab': { runA: ['RAGBot', 7005, 'vulnerable'], runB: ['RAGBot-AIM', 7014, 'protected'] },
  repo: { beat2: ['RepoBot', 7022, 'vulnerable'], beat3: ['RepoBot-AIM', 7023, 'protected'] },
  flight: { act2: ['FlightBot', 7017, 'vulnerable'], act3: ['FlightBot-AIM', 7018, 'protected'] },
};

export function defaultRoots(env = process.env) {
  const roots = [{ dir: env.SENTINEL_CAPTURES_DIR || path.join(REPO_ROOT, 'captures'), source: 'captures' }];
  if (!env.SENTINEL_HIDE_PLACEHOLDERS) roots.push({ dir: path.join(DASHBOARD_DIR, 'fixtures', 'captures'), source: 'placeholder' });
  return roots;
}

// A directory with a manifest.json listing `cases[].path` (T6 `captures/variants/`) is indexed through
// that manifest: exactly the listed cases, nothing else from that tree (its corpus/, tools/ and tests/
// hold inputs and generators, not captures). A listed case that is missing or points outside the
// directory stays in the index carrying an error, so the list shows it instead of skipping it.
async function manifestCases(dir) {
  let raw;
  try {
    raw = await readFile(path.join(dir, 'manifest.json'), 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw err;
  }
  let m;
  try {
    m = JSON.parse(raw);
  } catch (err) {
    throw new CaptureFormatError(path.join(dir, 'manifest.json'), `invalid JSON: ${err.message}`);
  }
  if (!Array.isArray(m?.cases) || !m.cases.every(c => typeof c?.path === 'string')) return null;
  // Containment is checked on real paths, not lexically: a symlink inside the tree that points
  // outside it counts as an escape, and a relative SENTINEL_CAPTURES_DIR still resolves correctly.
  const realDir = await realpath(path.resolve(dir));
  const out = [];
  for (const c of m.cases) {
    const file = path.resolve(dir, c.path);
    let real;
    try {
      real = await realpath(file);
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
      // Missing target (or dangling symlink): check the lexical path against the real dir, and
      // leave the "missing" error to the indexer's stat.
      real = path.resolve(realDir, path.relative(path.resolve(dir), file));
    }
    const inside = real.startsWith(realDir + path.sep);
    out.push({ file, manifestCase: c, error: inside ? null : `manifest path escapes ${dir}: ${c.path}` });
  }
  return out;
}

async function jsonFilesIn(dir, depth) {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch (err) {
    if (err.code === 'ENOENT') return [];
    throw err;
  }
  const out = [];
  for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    const full = path.join(dir, e.name);
    if (e.isDirectory() && depth > 0) {
      const cases = await manifestCases(full);
      if (cases) out.push(...cases);
      else out.push(...(await jsonFilesIn(full, depth - 1)));
    } else if (e.isFile() && e.name.endsWith('.json') && !e.name.endsWith('.schema.json')) out.push({ file: full });
  }
  return out;
}

/**
 * Index every capture under the roots. Returns a Map keyed by capture id, so lookups are targeted
 * and no file path is ever built from request input. `x.req.json` + `x.resp.json` merge into one
 * 'pair' entry. Throws BoundExceededError past MAX_CAPTURE_FILES. It never indexes a subset.
 */
export async function indexCaptures(roots = defaultRoots()) {
  const index = new Map();
  let total = 0;
  for (const { dir, source } of roots) {
    const files = await jsonFilesIn(dir, 2);
    total += files.length;
    enforce('MAX_CAPTURE_FILES', total, `while indexing ${dir}`);
    for (const { file, manifestCase, error } of files) {
      let rel = path.relative(dir, file).split(path.sep).join('/').replace(/\.json$/, '');
      const pairPart = manifestCase ? null : rel.match(/^(.*)\.(req|resp)$/);
      if (pairPart) rel = pairPart[1];
      const id = source === 'placeholder' ? `placeholder/${rel}` : rel;
      const entry = index.get(id) ?? { id, source, files: {}, bytes: 0 };
      if (manifestCase) {
        entry.expected = manifestCase.groundTruth === 'negative' ? 'benign' : manifestCase.groundTruth === 'positive' ? 'attack' : null;
      }
      let size = 0;
      if (error) entry.error = error;
      else {
        try {
          ({ size } = await stat(file));
        } catch (err) {
          if (err.code !== 'ENOENT') throw err;
          entry.error = `listed in manifest but missing: ${path.relative(dir, file)}`;
        }
      }
      if (pairPart) entry.files[pairPart[2]] = file;
      else entry.files.main = file;
      entry.bytes += size;
      index.set(id, entry);
    }
  }
  return index;
}

export class CaptureFormatError extends Error {
  constructor(id, msg) {
    super(`capture ${id}: ${msg}`);
    this.name = 'CaptureFormatError';
  }
}

async function readJson(file, id) {
  const text = await readFile(file, 'utf8');
  return { text, json: (() => {
    try {
      return JSON.parse(text);
    } catch (err) {
      throw new CaptureFormatError(id, `invalid JSON in ${path.basename(file)}: ${err.message}`);
    }
  })() };
}

export async function loadCapture(entry) {
  if (entry.error) throw new CaptureFormatError(entry.id, entry.error);
  enforce('MAX_CAPTURE_BYTES', entry.bytes, `capture ${entry.id}`);
  let raw;
  let bytes = 0;
  if (entry.files.main) {
    const r = await readJson(entry.files.main, entry.id);
    raw = r.json;
    bytes = Buffer.byteLength(r.text);
  } else {
    if (!entry.files.req || !entry.files.resp) {
      throw new CaptureFormatError(entry.id, `request/response pair incomplete (have: ${Object.keys(entry.files).join(', ')})`);
    }
    const req = await readJson(entry.files.req, entry.id);
    const resp = await readJson(entry.files.resp, entry.id);
    raw = { __pair: true, request: req.json, response: resp.json };
    bytes = Buffer.byteLength(req.text) + Buffer.byteLength(resp.text);
  }
  // Re-check after reading: a file can grow between stat() and readFile().
  enforce('MAX_CAPTURE_BYTES', bytes, `capture ${entry.id}`);
  return normalizeCapture(raw, { ...entry, bytes });
}

// ---------------------------------------------------------------------------------------------
export function detectShape(raw) {
  if (raw.__pair) return 'pair';
  if (raw.runA || raw.runB) return 'demo-ab';
  if (raw.beat2 || raw.beat3) return 'demo-ledger';
  if (raw.act2 || raw.act3) return 'demo-acts';
  if (raw.request || raw.response || Array.isArray(raw.exchanges)) return 'openai';
  return null;
}

const asText = (c) =>
  typeof c === 'string' ? c : Array.isArray(c) ? c.map(p => (typeof p === 'string' ? p : p?.text ?? JSON.stringify(p))).join('\n') : c == null ? '' : JSON.stringify(c);

function parseArgs(raw) {
  if (raw && typeof raw === 'object') return { text: JSON.stringify(raw), parsed: raw };
  if (typeof raw !== 'string') return { text: '', parsed: null };
  try {
    return { text: raw, parsed: JSON.parse(raw) };
  } catch {
    return { text: raw, parsed: null };
  }
}

function toolCallsFrom(list, prefix) {
  return (Array.isArray(list) ? list : []).map((tc, j) => {
    const args = parseArgs(tc.function?.arguments ?? tc.arguments);
    return { id: tc.id || `${prefix}_call${j}`, name: tc.function?.name ?? tc.name ?? 'unknown_tool', argsText: args.text, args: args.parsed, decision: tc.decision ?? null };
  });
}

const bodyOf = (x) => (x && typeof x === 'object' ? (x.body && typeof x.body === 'object' ? x.body : x) : {});

function openaiExchange(req, res, i, dvaaOverride) {
  const r = bodyOf(req);
  const s = bodyOf(res);
  const choice = Array.isArray(s.choices) ? s.choices[0] : null;
  const msg = choice?.message ?? {};
  return {
    index: i,
    messages: (Array.isArray(r.messages) ? r.messages : []).map((m, k) => ({
      index: k, role: m.role ?? 'user', name: m.name, toolCallId: m.tool_call_id, content: asText(m.content), recorded: true,
    })),
    assistant: { content: asText(msg.content), toolCalls: toolCallsFrom(msg.tool_calls, `ex${i}`), finishReason: choice?.finish_reason ?? null },
    dvaa: dvaaOverride ?? s.dvaa ?? null,
  };
}

function notRecorded(description) {
  return { index: 0, role: 'tool', name: 'untrusted_input', content: description, recorded: false };
}

function payloadLabel(p) {
  return p ? `${p.attackId ?? 'payload'} · ${p.name ?? ''}`.trim() : 'attack payload';
}

function trustOf(t) {
  if (t == null) return null;
  return typeof t === 'object' ? t.score ?? null : t;
}

function normalizeDemoAB(raw) {
  const agents = DEMO_AGENTS[raw.scenario] ?? DEMO_AGENTS['aim-ab'];
  return ['runA', 'runB'].filter(k => raw[k]).map(key => {
    const run = raw[key];
    const [name, port, role] = agents[key] ?? [key, null, 'single'];
    const exchange = {
      index: 0,
      messages: [notRecorded(`Poisoned document from payload ${payloadLabel(raw.payload)} delivered via POST /v1/chat/completions (document body not stored in the T1 capture)`)],
      assistant: { content: asText(run.message), toolCalls: toolCallsFrom(run.toolCalls, key), finishReason: run.finishReason ?? null },
      dvaa: run.dvaa ?? null,
    };
    return {
      key, role, label: `${name} :${port}`, agent: { name, port },
      exchanges: [exchange], toolResults: [],
      outcome: {
        exfilExecuted: run.dvaa?.exfilExecuted === true,
        blocked: run.dvaa?.aim?.allowed === false,
        denialReason: run.dvaa?.aim?.denialReason ?? null,
        trustScore: trustOf(run.dvaa?.aim?.trustScore),
      },
    };
  });
}

function normalizeDemoLedger(raw) {
  const agents = DEMO_AGENTS[raw.scenario] ?? DEMO_AGENTS.repo;
  const source = raw.payload?.deliveredBy ?? 'repo-local config';
  return ['beat2', 'beat3'].filter(k => raw[k]).map(key => {
    const beat = raw[key];
    const [name, port, role] = agents[key] ?? [beat.agent ?? key, null, 'single'];
    const toolCalls = (beat.ledger ?? []).map((l, j) => {
      const args = { target: l.target, decision: l.decision, enforced: l.enforced, executed: l.executed };
      if (/^https?:/i.test(l.target ?? '')) args.url = l.target;
      return { id: `${key}:ledger:${j}`, name: l.action, argsText: JSON.stringify(args), args, decision: l.decision };
    });
    const exfil = (beat.ledger ?? []).find(l => /^http:post$/i.test(l.action));
    return {
      key, role, label: `${beat.agent ?? name} :${port}`, agent: { name: beat.agent ?? name, port },
      exchanges: [{
        index: 0,
        messages: [notRecorded(`${source} in repo ${raw.beat1?.repo ?? '?'} carries payload ${payloadLabel(raw.payload)} (file body not stored in the T1 capture)`)],
        assistant: { content: `${beat.agent ?? name} action ledger (${toolCalls.length} actions)`, toolCalls, finishReason: 'tool_calls' },
        dvaa: {
          exfilAttempted: Boolean(exfil),
          exfilExecuted: beat.exfiltrated === true,
          exfilTargetUrl: exfil?.target ?? null,
          aim: beat.blocked ? { enforced: true, allowed: false, trustScore: beat.trustScore } : { enforced: false },
        },
      }],
      toolResults: [],
      outcome: { exfilExecuted: beat.exfiltrated === true, blocked: beat.blocked === true, denialReason: beat.blocked ? `${beat.deniedCount ?? '?'} actions denied by AIM` : null, trustScore: trustOf(beat.trustScore) },
    };
  });
}

function normalizeDemoActs(raw) {
  const agents = DEMO_AGENTS[raw.scenario] ?? DEMO_AGENTS.flight;
  return ['act2', 'act3'].filter(k => raw[k]).map(key => {
    const act = raw[key];
    const [name, port, role] = agents[key] ?? [act.agent ?? key, null, 'single'];
    const url = act.httpPostTargetUrl ?? (act.blocked ? raw.canary?.url : null);
    const toolCalls = url
      ? [{ id: `${key}:http_post`, name: 'http:post', argsText: JSON.stringify({ url }), args: { url }, decision: act.blocked ? 'denied' : 'allowed' }]
      : [];
    return {
      key, role, label: `${act.agent ?? name} :${port}`, agent: { name: act.agent ?? name, port },
      exchanges: [{
        index: 0,
        messages: [notRecorded(`Web page ${raw.target ?? '?'} returned by flight search (${raw.act1?.results ?? '?'} results) carries payload ${payloadLabel(raw.payload)} (page body not stored in the T1 capture)`)],
        assistant: { content: act.blocked ? `[AIM] ${act.denialReason ?? 'denied'}` : `${act.agent ?? name} posted wallet data`, toolCalls, finishReason: 'tool_calls' },
        dvaa: { exfilAttempted: Boolean(url), exfilExecuted: act.exfiltrated === true, exfilTargetUrl: url, aim: act.blocked ? { enforced: true, allowed: false, denialReason: act.denialReason, trustScore: act.trustScore } : { enforced: false } },
      }],
      toolResults: [],
      outcome: { exfilExecuted: act.exfiltrated === true, blocked: act.blocked === true, denialReason: act.denialReason ?? null, trustScore: trustOf(act.trustScore) },
    };
  });
}

function normalizeOpenAI(raw, entry) {
  const exRaw = Array.isArray(raw.exchanges) ? raw.exchanges : [{ request: raw.request, response: raw.response }];
  if (!exRaw.length) throw new CaptureFormatError(entry.id, 'exchanges[] is empty');
  // T6 fixtures carry their ground truth in label.dvaa (pre-computed, not a recorded run).
  const labelDvaa = !Array.isArray(raw.exchanges) && raw.label?.dvaa ? raw.label.dvaa : undefined;
  const exchanges = exRaw.map((ex, i) => openaiExchange(ex.request, ex.response, i, ex.dvaa ?? labelDvaa));
  const port = raw.agent?.port ?? raw.port ?? (entry.id.match(/(\d{4})_/)?.[1] ? Number(entry.id.match(/(\d{4})_/)[1]) : null);
  const name = raw.agent?.name ?? raw.agentName ?? entry.id.match(/\d{4}_([\w-]+)$/)?.[1] ?? 'agent';
  const dv = exchanges.map(e => e.dvaa).find(Boolean);
  return [{
    key: 'run', role: raw.__pair ? 'benign' : raw.role ?? 'single', label: `${name}${port ? ` :${port}` : ''}`, agent: { name, port },
    exchanges,
    toolResults: (Array.isArray(raw.toolResults) ? raw.toolResults : []).map((t, i) => ({
      index: i, toolCallId: t.toolCallId ?? null, name: t.name ?? 'tool', source: t.source ?? `tool_result:${i}`,
      trust: t.trust ?? 'untrusted', content: asText(t.content ?? ''), rows: Array.isArray(t.rows) ? t.rows : null,
    })),
    outcome: { exfilExecuted: dv?.exfilExecuted === true, blocked: dv?.aim?.allowed === false, denialReason: dv?.aim?.denialReason ?? null, trustScore: trustOf(dv?.aim?.trustScore) },
  }];
}

/** Normalize to the internal model. Pure; no I/O. */
export function normalizeCapture(raw, entry = { id: raw?.id ?? 'inline', source: 'inline' }) {
  if (!raw || typeof raw !== 'object') throw new CaptureFormatError(entry.id, 'capture is not an object');
  const shape = detectShape(raw);
  if (!shape) throw new CaptureFormatError(entry.id, 'unrecognized capture shape (expected runA/runB, beat2/beat3, act2/act3, request/response or exchanges[])');
  const runs =
    shape === 'demo-ab' ? normalizeDemoAB(raw)
      : shape === 'demo-ledger' ? normalizeDemoLedger(raw)
        : shape === 'demo-acts' ? normalizeDemoActs(raw)
          : normalizeOpenAI(raw, entry);
  if (!runs.length) throw new CaptureFormatError(entry.id, 'no runs found');
  const hits = Array.isArray(raw.canary?.hits) ? raw.canary.hits : [];
  return {
    id: entry.id,
    source: entry.source,
    shape,
    placeholder: raw.placeholder === true || entry.source === 'placeholder',
    placeholderNote: raw.placeholderNote ?? null,
    title: raw.title ?? (raw.label && raw.id ? `${raw.id} · ${raw.scenario ?? ''} [T6 ${raw.label.groundTruth ?? 'unlabeled'}]` : null) ?? (raw.payload?.name ? `${raw.scenario ?? ''} · ${raw.payload.name}`.replace(/^ · /, '') : raw.scenario ?? entry.id),
    scenario: raw.scenario ?? (shape === 'pair' ? 'benign' : null),
    payload: raw.payload ?? null,
    expectedLabel: raw.expectedLabel ?? (raw.label?.groundTruth === 'negative' ? 'benign' : raw.label?.groundTruth === 'positive' ? 'attack' : null) ?? (shape === 'pair' ? 'benign' : runs.some(r => r.outcome.exfilExecuted) ? 'attack' : null),
    canaryHits: hits.map(h => ({ at: h.at ?? null, kind: h.kind ?? 'exfil', path: h.path ?? null, query: h.query ?? {} })),
    runs,
    alerts: Array.isArray(raw.alerts) ? raw.alerts : null,
    bytes: entry.bytes ?? null,
  };
}
