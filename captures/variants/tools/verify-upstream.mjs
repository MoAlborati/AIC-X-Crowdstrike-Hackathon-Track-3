/**
 * Verify every VERBATIM string in upstream-cases.mjs against the real upstream sources (review F7),
 * and that each local source is the PINNED upstream version (review L2).
 *
 * Each source is checked only when a local copy is available; otherwise it reports an explicit
 * SKIPPED line (never a silent pass). UPSTREAM_REQUIRE=1 turns any SKIPPED into a failure.
 *
 *   DEEPSET_ROWS=<file.jsonl>   rows of deepset/prompt-injections split=test at the pinned revision,
 *                               one JSON object per line: {"idx": <row_idx>, "text": ..., "label": ...}.
 *                               Recipe (revision-pinned; the datasets-server /rows API is NOT):
 *                                 curl -sSLo test.parquet \
 *                                   https://huggingface.co/datasets/deepset/prompt-injections/resolve/<DEEPSET.revision>/<DEEPSET.parquetFile>
 *                                 sha256sum test.parquet   # must equal DEEPSET.parquetSha256
 *                                 python3 -c 'import json,pyarrow.parquet as pq; t=pq.read_table("test.parquet").to_pylist(); [print(json.dumps({"idx":i,"text":r["text"],"label":r["label"]})) for i,r in enumerate(t)]' > rows.jsonl
 *                               (row order in the parquet file = row_idx). Set DEEPSET_PARQUET=<file> as
 *                               well to have the verifier check the parquet's sha256 against the pin.
 *   AGENTDOJO_SRC=<repo root>   git clone of ethz-spylab/agentdojo  (must be at AGENTDOJO.commit, clean)
 *   INJECAGENT_SRC=<repo root>  git clone of uiuc-kang-lab/InjecAgent (must be at INJECAGENT.commit, clean)
 *   DVAA: resolved and verified like tools/baseline.mjs ($DVAA_SRC, $DVAA_DIR, <repo>/.dvaa/dvaa-target);
 *         pin + clean tree are checked BEFORE its code is imported.
 *
 * A clone at the wrong commit or with a dirty tree is a MISMATCH (exit 1), not a skip.
 *
 * Usage: node captures/variants/tools/verify-upstream.mjs
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { DEEPSET, AGENTDOJO, INJECAGENT, DVAA, renderAgentDojo } from './upstream-cases.mjs';
import { resolveVerifiedDvaa, verifyCheckout, DVAA_PIN } from './baseline.mjs';
import { sha256 } from './fixture-lib.mjs';

const read = (p) => fs.readFileSync(p, 'utf8');

/** Pin + clean-tree check for a benchmark clone; returns a mismatch result or null when OK. */
function pinProblem(name, root, commit) {
  const v = verifyCheckout(root, commit);
  return v.ok ? null : { status: 'mismatch', detail: `${name} clone ${root}: ${v.problem}` };
}

/**
 * Args of the FunctionCall(function="<tool>", args={...}) in a user task's ground truth.
 * Upstream writes them as a Python dict of string literals, which is JSON once trailing commas go.
 */
function groundTruthArgs(block, tool) {
  const m = block.match(new RegExp(`function="${tool}",\\s*args=(\\{[\\s\\S]*?\\})\\s*,?\\s*\\)`));
  if (!m) return null;
  try {
    return JSON.parse(m[1].replace(/,(\s*\})/g, '$1'));
  } catch {
    return null;
  }
}

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
  if (!env.DEEPSET_ROWS) return { status: 'skipped', detail: 'set DEEPSET_ROWS=<test-split rows .jsonl> (recipe in this file header)' };
  if (env.DEEPSET_PARQUET) {
    const got = crypto.createHash('sha256').update(fs.readFileSync(env.DEEPSET_PARQUET)).digest('hex');
    if (got !== DEEPSET.parquetSha256) return { status: 'mismatch', detail: `parquet sha256 ${got} != pinned ${DEEPSET.parquetSha256}` };
  }
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
  const parquet = env.DEEPSET_PARQUET ? ', parquet sha256 pinned' : ' (parquet sha256 not checked: set DEEPSET_PARQUET)';
  return bad.length ? { status: 'mismatch', detail: bad.join(', ') } : { status: 'ok', detail: `${Object.keys(DEEPSET.rows).length} rows${parquet}` };
}

function checkAgentDojo(env) {
  const root = env.AGENTDOJO_SRC;
  if (!root) return { status: 'skipped', detail: 'set AGENTDOJO_SRC=<agentdojo clone>' };
  const pin = pinProblem('AgentDojo', root, AGENTDOJO.commit);
  if (pin) return pin;
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
    else if (JSON.stringify(groundTruthArgs(ut, c.userTask.tool)) !== JSON.stringify(c.userTask.args)) bad.push(`${key}.userTask.args`);
    if (!renderAgentDojo(c.goal).includes(c.target)) bad.push(`${key}.target`);
  }
  return bad.length ? { status: 'mismatch', detail: bad.join(', ') } : { status: 'ok', detail: `@${AGENTDOJO.commit.slice(0, 8)} clean: template + ${Object.keys(AGENTDOJO.cases).length} cases` };
}

function checkInjecAgent(env) {
  const root = env.INJECAGENT_SRC;
  if (!root) return { status: 'skipped', detail: 'set INJECAGENT_SRC=<InjecAgent clone>' };
  const pin = pinProblem('InjecAgent', root, INJECAGENT.commit);
  if (pin) return pin;
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
  return bad.length ? { status: 'mismatch', detail: bad.join(', ') } : { status: 'ok', detail: `@${INJECAGENT.commit.slice(0, 8)} clean: ${INJECAGENT.cases.length} cases` };
}

async function checkDvaa(env) {
  if (env.DVAA_SRC === 'replica') return { status: 'skipped', detail: 'DVAA_SRC=replica' };
  if (DVAA.commit !== DVAA_PIN) return { status: 'mismatch', detail: `upstream-cases DVAA.commit ${DVAA.commit} != baseline DVAA_PIN ${DVAA_PIN}` };
  let hit;
  try {
    hit = resolveVerifiedDvaa(DVAA.file, env); // pin + clean tree verified BEFORE the import below
  } catch (e) {
    return { status: 'mismatch', detail: e.message };
  }
  if (!hit.root) return { status: 'skipped', detail: 'no DVAA checkout (scripts/setup-dvaa.sh clone, or DVAA_SRC)' };
  const mod = await import(pathToFileURL(path.join(hit.root, DVAA.file)).href);
  const got = mod[DVAA.fn](DVAA.canary);
  return got === DVAA.document
    ? { status: 'ok', detail: `@${hit.commit.slice(0, 8)} clean: ${DVAA.fn}() output (${hit.root})` }
    : { status: 'mismatch', detail: `${DVAA.fn}() output differs` };
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
