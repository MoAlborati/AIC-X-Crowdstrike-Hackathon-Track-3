/**
 * T6b: extract VERBATIM deepset + InjecAgent rows from local pinned upstream copies into committed JSON
 * (upstream-deepset.json, upstream-injecagent.json). Deterministic: fixed selection rules, sorted output.
 *
 *   deepset    : ALL rows of split=test at the pinned revision (116 rows; 60 label=1, 56 label=0). Taking
 *                every row avoids any selection bias in the positive/negative mix.
 *   InjecAgent : one case per attacker case of test_cases_ds_enhanced.json and test_cases_dh_enhanced.json,
 *                user tool rotating (injecagentPick in upstream-pins.mjs: index a*17 + (a mod 17)), so every
 *                attacker instruction and every user tool appears.
 *
 * Usage: DEEPSET_ROWS=<rows.jsonl> [DEEPSET_PARQUET=<parquet>] INJECAGENT_SRC=<clone> \
 *          node captures/variants/tools/extract-upstream.mjs
 * (rows.jsonl recipe: README "Reproduce"). Pins are checked first; a wrong pin / dirty clone throws.
 * verify-upstream.mjs re-checks every committed string against the same sources.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEEPSET_PIN, INJECAGENT_PIN, INJECAGENT_USER_TOOLS, INJECAGENT_FILES, injecagentPick } from './upstream-pins.mjs';
import { verifyCheckout } from './baseline.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const env = process.env;
const die = (m) => {
  console.error(`extract-upstream: ${m}`);
  process.exit(1);
};

// ---- deepset ----------------------------------------------------------------------------------
if (!env.DEEPSET_ROWS) die('set DEEPSET_ROWS=<test-split rows .jsonl>');
if (env.DEEPSET_PARQUET) {
  const got = crypto.createHash('sha256').update(fs.readFileSync(env.DEEPSET_PARQUET)).digest('hex');
  if (got !== DEEPSET_PIN.parquetSha256) die(`parquet sha256 ${got} != pinned ${DEEPSET_PIN.parquetSha256}`);
}
const rows = fs
  .readFileSync(env.DEEPSET_ROWS, 'utf8')
  .split('\n')
  .filter((l) => l.trim())
  .map((l) => JSON.parse(l))
  .map((r) => ({ idx: r.idx ?? r.row_idx, label: r.label, text: r.text }))
  .sort((a, b) => a.idx - b.idx);
if (rows.length !== DEEPSET_PIN.rowCount) die(`expected ${DEEPSET_PIN.rowCount} rows, got ${rows.length}`);
rows.forEach((r, i) => {
  if (r.idx !== i) die(`row_idx gap at ${i}`);
  if (r.label !== 0 && r.label !== 1) die(`row ${i}: label ${r.label}`);
});
fs.writeFileSync(path.join(HERE, 'upstream-deepset.json'), JSON.stringify({ ...DEEPSET_PIN, rows }, null, 1) + '\n');

// ---- InjecAgent -------------------------------------------------------------------------------
const root = env.INJECAGENT_SRC;
if (!root) die('set INJECAGENT_SRC=<InjecAgent clone>');
const v = verifyCheckout(root, INJECAGENT_PIN.commit);
if (!v.ok) die(`InjecAgent clone ${root}: ${v.problem}`);
const cases = [];
for (const [setting, file] of Object.entries(INJECAGENT_FILES)) {
  const data = JSON.parse(fs.readFileSync(path.join(root, file), 'utf8'));
  const tools = new Set(data.map((u) => u['User Tool']));
  if (tools.size !== INJECAGENT_USER_TOOLS || data.length % INJECAGENT_USER_TOOLS) die(`${file}: unexpected layout`);
  for (const i of injecagentPick(data.length)) {
    const u = data[i];
    if (u['User Tool'] !== data[i % INJECAGENT_USER_TOOLS]['User Tool']) die(`${file}[${i}]: layout is not attacker-major`);
    cases.push({
      setting,
      file,
      caseIndex: i,
      attackType: u['Attack Type'],
      userTool: u['User Tool'],
      userInstruction: u['User Instruction'],
      toolParameters: u['Tool Parameters'],
      attackerInstruction: u['Attacker Instruction'],
      attackerTools: u['Attacker Tools'],
      toolResponse: u['Tool Response'],
    });
  }
}
fs.writeFileSync(path.join(HERE, 'upstream-injecagent.json'), JSON.stringify({ ...INJECAGENT_PIN, selection: 'index = a*17 + (a mod 17) per attacker case a', cases }, null, 1) + '\n');
console.log(`deepset rows ${rows.length}; InjecAgent cases ${cases.length}`);
