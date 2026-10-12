// Test helpers: load REAL DVAA captures (T1's captures/ + this ticket's live raw captures) and build
// data-rich synthetic turns. Captures are parsed with JSON.parse exactly as the proxy receives them.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createDetector, DVAA_HONEYTOKENS } from '../index.js';

const here = path.dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = path.resolve(here, '../../..');
export const CAPTURES = path.join(REPO_ROOT, 'captures');

export const readJson = (p) => JSON.parse(fs.readFileSync(p, 'utf8'));

/** Raw request/response pairs captured from an isolated live DVAA fleet (scripts/capture-dvaa-fixtures.mjs). */
export function liveCaptures() {
  return readJson(path.join(here, 'fixtures', 'dvaa-live-captures.json')).cases;
}
export const liveCase = (id) => {
  const c = liveCaptures().find((x) => x.id === id);
  if (!c) throw new Error(`no live capture ${id}`);
  return c;
};

/** T1 benign corpus: captures/benign/<port>_<id>.{req,resp}.json — real request + real response. */
export function t1Benign() {
  const dir = path.join(CAPTURES, 'benign');
  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.req.json'));
  if (files.length < 6) throw new Error(`expected >= 6 T1 benign captures in ${dir}, found ${files.length}`);
  return files.map((f) => {
    const base = f.replace(/\.req\.json$/, '');
    return { id: base, port: Number(base.split('_')[0]), request: readJson(path.join(dir, f)), response: readJson(path.join(dir, `${base}.resp.json`)) };
  });
}

/**
 * T1 attack captures are DVAA's own `demo --json` output. For aim-ab, runA/runB hold the agent's real
 * reply fields ({message, finishReason, toolCalls, dvaa}) that DVAA's demo runner lifted out of the
 * chat-completion response; this rebuilds the response envelope DVAA sent (src/index.js:1866-1876).
 */
export function t1AimAbResponse(run, model) {
  return {
    id: `chatcmpl-${model}-t1`,
    object: 'chat.completion',
    model,
    choices: [{ index: 0, message: { role: 'assistant', content: run.message, tool_calls: run.toolCalls }, finish_reason: run.finishReason }],
    dvaa: run.dvaa,
  };
}

/**
 * T1's repo capture records each tool call as a DVAA ledger entry {action, target}. Map the ledger back to
 * the exact tool_calls DVAA emits for those actions (src/index.js repo path: repo:read->read_repo{path},
 * shell:exec->run_shell{command}, fs:read->read_file{path}, http:post->http_post{url}).
 */
export function t1RepoLedgerResponse(beat, model) {
  const map = {
    'repo:read': (t) => ['read_repo', { path: t }],
    'shell:exec': (t) => ['run_shell', { command: t }],
    'fs:read': (t) => ['read_file', { path: t }],
    'http:post': (t) => ['http_post', { url: t }],
  };
  const tool_calls = beat.ledger.map((e, i) => {
    const [name, args] = map[e.action](e.target);
    return { id: `call_t1_${i}`, type: 'function', function: { name, arguments: JSON.stringify(args) } };
  });
  return { id: `chatcmpl-${model}-t1`, model, choices: [{ index: 0, message: { role: 'assistant', content: `[${beat.agent}] Reviewed.`, tool_calls }, finish_reason: 'tool_calls' }] };
}

export const quietLogger = () => {
  const errors = [];
  return { errors, error: (o) => errors.push(o), warn: () => {} };
};

export function dvaaDetector(extra = {}) {
  const logger = quietLogger();
  const det = createDetector({ honeytokens: DVAA_HONEYTOKENS, logger, ...extra });
  return { det, logger };
}

export const toolCall = (id, name, args) => ({ id, type: 'function', function: { name, arguments: typeof args === 'string' ? args : JSON.stringify(args) } });
export const response = (toolCalls = [], content = '') => ({ id: 'chatcmpl-test', model: 'test-agent', choices: [{ index: 0, message: { role: 'assistant', content, ...(toolCalls.length ? { tool_calls: toolCalls } : {}) } }] });

/** N-row CSV of fake customers (data-rich tool output). `inject` = {row, text} places a payload at a row. */
export function customerRows(n, inject = null) {
  const rows = ['id,name,email,city,plan,balance'];
  for (let i = 1; i <= n; i++) {
    let line = `${i},Customer ${i},customer${i}@example-corp.test,City ${i % 97},${['free', 'pro', 'team'][i % 3]},${(i * 37) % 10000}.00`;
    if (inject && inject.row === i) line += `,${inject.text}`;
    rows.push(line);
  }
  return rows.join('\n');
}

/** DVAA's baseline (src/core/vulnerabilities.js detectionText, DETECTION_EDGE = 8 KiB): head + tail only. */
export function dvaaBaselineWindow(text, edge = 8 * 1024) {
  if (text.length <= edge * 2) return text;
  return `${text.slice(0, edge)}\n\u0000\n${text.slice(text.length - edge)}`;
}
