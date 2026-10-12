/**
 * Verify every VERBATIM string in upstream-cases.mjs against the real upstream sources (review F7).
 *
 * Each source is checked only when a local copy is available; otherwise it reports an explicit
 * SKIPPED line (never a silent pass). UPSTREAM_REQUIRE=1 turns any SKIPPED into a failure.
 *
 *   DEEPSET_ROWS=<file.jsonl>   rows of deepset/prompt-injections split=test, one JSON object per line
 *                               with {idx,text,label} (e.g. from the HF datasets-server /rows API at
 *                               the pinned revision)
 *   AGENTDOJO_SRC=<repo root>   git clone of ethz-spylab/agentdojo
 *   INJECAGENT_SRC=<repo root>  git clone of uiuc-kang-lab/InjecAgent
 *   DVAA: resolved like tools/baseline.mjs ($DVAA_SRC, $DVAA_DIR, setup-dvaa.sh default dir)
 *
 * Usage: node captures/variants/tools/verify-upstream.mjs
 */
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { DEEPSET, AGENTDOJO, INJECAGENT, DVAA, renderAgentDojo } from './upstream-cases.mjs';
import { dvaaCandidates } from './baseline.mjs';

const read = (p) => fs.readFileSync(p, 'utf8');

/** Source text of a top-level `class <name>(` block (up to the next top-level class/decorator). */
function classBlock(src, name) {
  const start = src.indexOf(`class ${name}(`);
  if (start < 0) throw new Error(`class ${name} not found`);
  const rest = src.slice(start + 1);
  const next = rest.search(/\n(?:@|class )/);
  return next < 0 ? src.slice(start) : src.slice(start, start + 1 + next);
}

/** Python double-quoted literal(s) -> JS string (the upstream literals use only JSON-compatible escapes). */
const pyStr = (lit) => JSON.parse(lit);

function checkDeepset(env) {
  if (!env.DEEPSET_ROWS) return { status: 'skipped', detail: 'set DEEPSET_ROWS=<test-split rows .jsonl>' };
  const rows = new Map();
  for (const line of read(env.DEEPSET_ROWS).split('\n')) {
    if (!line.trim()) continue;
    const r = JSON.parse(line);
    rows.set(r.idx ?? r.row_idx, r);
  }
  const bad = [];
  for (const [idx, want] of Object.entries(DEEPSET.rows)) {
    const got = rows.get(Number(idx));
    if (!got || got.text !== want.text || got.label !== want.label) bad.push(`row ${idx}`);
  }
  return bad.length ? { status: 'mismatch', detail: bad.join(', ') } : { status: 'ok', detail: `${Object.keys(DEEPSET.rows).length} rows` };
}

function checkAgentDojo(env) {
  const root = env.AGENTDOJO_SRC;
  if (!root) return { status: 'skipped', detail: 'set AGENTDOJO_SRC=<agentdojo clone>' };
  const bad = [];
  // Template: ImportantInstructionsAttack._JB_STRING = ( "..." "..." )
  const cls = classBlock(read(path.join(root, AGENTDOJO.templateFile)), 'ImportantInstructionsAttack');
  const jb = cls.match(/_JB_STRING = \(([\s\S]*?)\n\s*\)/);
  const template = jb ? [...jb[1].matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => pyStr(`"${m[1]}"`)).join('') : null;
  if (template !== AGENTDOJO.template) bad.push('template');
  const base = read(path.join(root, 'src/agentdojo/attacks/base_attacks.py'));
  if (!base.includes(`DEFAULT_USER_NAME = ${JSON.stringify(AGENTDOJO.user)}`)) bad.push('DEFAULT_USER_NAME');
  if (!base.includes(`DEFAULT_MODEL_NAME = ${JSON.stringify(AGENTDOJO.model)}`)) bad.push('DEFAULT_MODEL_NAME');
  for (const [key, c] of Object.entries(AGENTDOJO.cases)) {
    const blk = classBlock(read(path.join(root, c.file)), c.injectionTask);
    const consts = Object.fromEntries([...blk.matchAll(/^\s+(_[A-Z_]+) = "((?:[^"\\]|\\.)*)"$/gm)].map((m) => [m[1], pyStr(`"${m[2]}"`)]));
    const g = blk.match(/^\s+GOAL = f"((?:[^"\\]|\\.)*)"$/m);
    const goal = g ? pyStr(`"${g[1]}"`).replace(/\{(_[A-Z_]+)\}/g, (_, n) => consts[n] ?? `{${n}}`) : null;
    if (goal !== c.goal) bad.push(`${key}.goal`);
    const ut = classBlock(read(path.join(root, c.userTask.file)), c.userTask.name);
    if (!ut.includes(`PROMPT = ${JSON.stringify(c.userTask.prompt)}`)) bad.push(`${key}.userTask.prompt`);
    if (!ut.includes(`function="${c.userTask.tool}"`)) bad.push(`${key}.userTask.tool`);
    if (!renderAgentDojo(c.goal).includes(c.target)) bad.push(`${key}.target`);
  }
  return bad.length ? { status: 'mismatch', detail: bad.join(', ') } : { status: 'ok', detail: `template + ${Object.keys(AGENTDOJO.cases).length} cases` };
}

function checkInjecAgent(env) {
  const root = env.INJECAGENT_SRC;
  if (!root) return { status: 'skipped', detail: 'set INJECAGENT_SRC=<InjecAgent clone>' };
  const data = JSON.parse(read(path.join(root, INJECAGENT.file)));
  const bad = [];
  for (const c of INJECAGENT.cases) {
    const u = data[c.caseIndex];
    const ok =
      u &&
      u['Tool Response'] === c.toolResponse &&
      u['Attacker Instruction'] === c.attackerInstruction &&
      u['User Instruction'] === c.userInstruction &&
      u['User Tool'] === c.userTool &&
      u['Tool Parameters'] === c.toolParameters;
    if (!ok) bad.push(`case ${c.caseIndex}`);
  }
  return bad.length ? { status: 'mismatch', detail: bad.join(', ') } : { status: 'ok', detail: `${INJECAGENT.cases.length} cases` };
}

async function checkDvaa(env) {
  if (env.DVAA_SRC === 'replica') return { status: 'skipped', detail: 'DVAA_SRC=replica' };
  const hit = dvaaCandidates(env).find((c) => fs.existsSync(path.join(c.root, DVAA.file)));
  if (!hit && env.DVAA_SRC) return { status: 'mismatch', detail: `DVAA_SRC=${env.DVAA_SRC} has no ${DVAA.file}` };
  if (!hit) return { status: 'skipped', detail: 'no DVAA checkout (scripts/setup-dvaa.sh clone, or DVAA_SRC)' };
  const mod = await import(pathToFileURL(path.join(hit.root, DVAA.file)).href);
  const got = mod[DVAA.fn](DVAA.canary);
  return got === DVAA.document ? { status: 'ok', detail: `${DVAA.fn}() output (${hit.root})` } : { status: 'mismatch', detail: `${DVAA.fn}() output differs` };
}

export async function verifyUpstream(env = process.env) {
  return [
    { source: 'deepset/prompt-injections', ...checkDeepset(env) },
    { source: 'AgentDojo', ...checkAgentDojo(env) },
    { source: 'InjecAgent', ...checkInjecAgent(env) },
    { source: 'DVAA', ...(await checkDvaa(env)) },
  ];
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const results = await verifyUpstream();
  let fail = false;
  for (const r of results) {
    const tag = r.status === 'ok' ? 'OK' : r.status === 'skipped' ? 'SKIPPED' : 'MISMATCH';
    console.log(`${tag.padEnd(8)} ${r.source}: ${r.detail}`);
    if (r.status === 'mismatch' || (r.status === 'skipped' && process.env.UPSTREAM_REQUIRE === '1')) fail = true;
  }
  process.exit(fail ? 1 : 0);
}
