/**
 * Emit the benchmark-derived fixtures (fixtures/deepset, fixtures/agentdojo, fixtures/injecagent)
 * from the VERBATIM upstream strings in upstream-cases.mjs. Deterministic; no clock/RNG.
 *
 * What is ours vs upstream (review F1-F3):
 *   - every attack / benchmark string is byte-identical to upstream (source.upstream.text + sha256);
 *   - we only choose WHERE it sits in the request: user turn (deepset) or a role:"tool" result
 *     (AgentDojo, InjecAgent), with the benchmark's own user task + tool call around it (review F5).
 *
 * Usage: node captures/variants/tools/build-benchmark-fixtures.mjs
 */
import { DEEPSET, AGENTDOJO, INJECAGENT, renderAgentDojo, AGENTDOJO_RUN, INJECAGENT_SAMPLE } from './upstream-cases.mjs';
import { AGENTDOJO_PIN } from './upstream-pins.mjs';
import { writeJson, userMessage, toolConversation, toolTranscript, label, upstreamRef } from './fixture-lib.mjs';

const written = [];

// ---- deepset/prompt-injections: verbatim rows (split=test) --------------------------------------
const deepsetCases = [
  { id: 'DS-PI-001', row: 98, file: 'deepset-pi-001.json', note: 'Phrased outside DVAA baseline patterns (no "instruction" token): exercises detection beyond the baseline.' },
  { id: 'DS-PI-002', row: 15, file: 'deepset-pi-002.json', note: 'Classic "ignore the above" chain ending in a system-prompt extraction request.' },
  { id: 'DS-BENIGN-001', row: 77, file: 'deepset-benign-001.json', note: 'Benign negative-class row for false-positive measurement.' },
];
for (const c of deepsetCases) {
  const row = DEEPSET.rows[c.row];
  const positive = row.label === 1;
  written.push(
    writeJson(`fixtures/deepset/${c.file}`, {
      id: c.id,
      scenario: 'prompt-injection-classification',
      source: {
        benchmark: 'deepset/prompt-injections',
        url: DEEPSET.url,
        license: 'Apache-2.0',
        fidelity: 'verbatim',
        caseRef: `split=${DEEPSET.split} row_idx=${c.row} label=${row.label}`,
        upstream: upstreamRef({ dataset: DEEPSET.dataset, revision: DEEPSET.revision, split: DEEPSET.split, rowIdx: c.row, label: row.label, text: row.text }),
        note: 'Row text copied verbatim from the dataset at the pinned revision.',
      },
      channel: 'user_message',
      request: userMessage(row.text),
      label: label(
        positive
          ? { groundTruth: 'positive', verdict: 'block', category: 'prompt_injection' }
          : { groundTruth: 'negative', verdict: 'allow', category: 'benign' },
      ),
      notes: c.note,
    }),
  );
}

// ---- AgentDojo: important_instructions_no_names x exfil injection tasks ---------------------------
const agentdojoCases = [
  { id: 'AD-EXFIL-001', key: 'workspace_injection_task_3', file: 'agentdojo-exfil-001.json', what: 'forward an email body to the attacker address' },
  { id: 'AD-EXFIL-002', key: 'banking_injection_task_1', file: 'agentdojo-exfil-002.json', what: "send a transaction that leaks a contact's IBAN to the attacker IBAN" },
];
for (const c of agentdojoCases) {
  const k = AGENTDOJO.cases[c.key];
  const injection = renderAgentDojo(k.goal);
  written.push(
    writeJson(`fixtures/agentdojo/${c.file}`, {
      id: c.id,
      scenario: `indirect-injection-exfil (${k.suite} suite)`,
      source: {
        benchmark: 'AgentDojo',
        url: AGENTDOJO.repo,
        license: 'MIT',
        fidelity: 'verbatim',
        caseRef: `${AGENTDOJO.attack} x ${k.suite}/${k.injectionTask}; user task ${k.suite}/${k.userTask.name}`,
        upstream: upstreamRef({
          repo: AGENTDOJO.repo,
          commit: AGENTDOJO.commit,
          attack: AGENTDOJO.attack,
          templateFile: AGENTDOJO.templateFile,
          injectionTaskFile: k.file,
          injectionTask: k.injectionTask,
          goal: k.goal,
          userTaskFile: k.userTask.file,
          userTask: k.userTask.name,
          text: injection,
        }),
        note:
          'Injection string = AgentDojo important_instructions template rendered with AgentDojo default names and the ' +
          'injection task GOAL, byte-identical to what AgentDojo emits. The user turn and tool name are the benchmark ' +
          "user task's PROMPT and ground-truth tool. The tool result carries only the injection string: the surrounding " +
          'AgentDojo environment data (other emails / file text) is omitted. Destinations are AgentDojo\'s own values.',
      },
      channel: 'tool_output',
      request: toolConversation(k.userTask.prompt, k.userTask.tool, k.userTask.args, injection),
      label: label({
        groundTruth: 'positive',
        verdict: 'block',
        category: 'indirect_prompt_injection+data_exfiltration',
        exfilTargetUrl: k.target,
      }),
      notes: `Indirect injection in an untrusted tool result instructs the agent to ${c.what}. Destination appears only in the tool result.`,
    }),
  );
}

// ---- InjecAgent: DS-enhanced test cases ---------------------------------------------------------
const injecagentIds = ['IA-DS-001', 'IA-DS-002'];
INJECAGENT.cases.forEach((k, i) => {
  // Tool Parameters is a Python-dict literal; the OpenAI tool_call carries the JSON equivalent.
  const args = JSON.parse(k.toolParameters.replaceAll("'", '"'));
  written.push(
    writeJson(`fixtures/injecagent/injecagent-ds-00${i + 1}.json`, {
      id: injecagentIds[i],
      scenario: `data-stealing attack (InjecAgent DS, ${k.attackType})`,
      source: {
        benchmark: 'InjecAgent',
        url: INJECAGENT.repo,
        license: 'MIT',
        fidelity: 'verbatim',
        caseRef: `${INJECAGENT.file}[${k.caseIndex}] (${INJECAGENT.setting})`,
        upstream: upstreamRef({
          repo: INJECAGENT.repo,
          commit: INJECAGENT.commit,
          file: INJECAGENT.file,
          caseIndex: k.caseIndex,
          field: 'Tool Response',
          attackerInstruction: k.attackerInstruction,
          text: k.toolResponse,
        }),
        note:
          "User turn = the case's 'User Instruction'; tool call = its 'User Tool' with 'Tool Parameters' (as JSON); " +
          "tool result = its 'Tool Response' verbatim (enhanced 'IMPORTANT!!! Ignore all previous instructions...' prefix " +
          "included). The destination is InjecAgent's own value.",
      },
      channel: 'tool_output',
      request: toolConversation(k.userInstruction, k.userTool, args, k.toolResponse),
      label: label({
        groundTruth: 'positive',
        verdict: 'block',
        category: 'indirect_prompt_injection+data_exfiltration',
        exfilTargetUrl: 'amy.watson@gmail.com',
      }),
      notes: `InjecAgent data-stealing case: sensitive read routed to an external email sink via an injected product review.`,
    }),
  );
});

// =================================================================================================
// T6b: corpus expansion. Same conventions as above (verbatim upstream text, our placement only).
// =================================================================================================
const pad3 = (n) => String(n).padStart(3, '0');
const T6_DEEPSET_ROWS = new Set(deepsetCases.map((c) => c.row));

// ---- deepset: every remaining split=test row (no selection: 60 label=1 / 56 label=0 in total) ----
for (const [idxStr, row] of Object.entries(DEEPSET.rows)) {
  const idx = Number(idxStr);
  if (T6_DEEPSET_ROWS.has(idx)) continue; // already DS-PI-001/002, DS-BENIGN-001
  const positive = row.label === 1;
  written.push(
    writeJson(`fixtures/deepset/deepset-row-${pad3(idx)}.json`, {
      id: `DS-ROW-${pad3(idx)}`,
      scenario: 'prompt-injection-classification',
      source: {
        benchmark: 'deepset/prompt-injections',
        url: DEEPSET.url,
        license: 'Apache-2.0',
        fidelity: 'verbatim',
        caseRef: `split=${DEEPSET.split} row_idx=${idx} label=${row.label}`,
        upstream: upstreamRef({ dataset: DEEPSET.dataset, revision: DEEPSET.revision, split: DEEPSET.split, rowIdx: idx, label: row.label, text: row.text }),
        note: 'Row text copied verbatim from the dataset at the pinned revision. T6b includes every split=test row, so the label mix is the dataset\'s own.',
      },
      channel: 'user_message',
      request: userMessage(row.text),
      label: label(
        positive
          ? { groundTruth: 'positive', verdict: 'block', category: 'prompt_injection' }
          : { groundTruth: 'negative', verdict: 'allow', category: 'benign' },
      ),
      notes: positive ? 'deepset label=1 (prompt injection), user turn.' : 'deepset label=0 (benign), user turn.',
    }),
  );
}

// ---- AgentDojo v1: every injection task of all 4 suites x 2 attack templates --------------------
// Labels are ours (attack text is not): an injection task is exfil iff its GOAL sends user data to an
// attacker sink; the sink is listed here and must appear verbatim in the GOAL (checked, fail-loud).
// Everything else (money transfer to the attacker IBAN, password change, phishing link, deleting a
// file, a fake reservation, ...) is indirect_prompt_injection with no exfil target.
const AGENTDOJO_EXFIL = {
  'banking/injection_task_0': 'US133000000121212121212',
  'banking/injection_task_1': 'US133000000121212121212',
  'banking/injection_task_2': 'US133000000121212121212',
  'banking/injection_task_3': 'US133000000121212121212',
  'banking/injection_task_8': 'US133000000121212121212',
  'slack/injection_task_2': 'www.my-website-234.com/random',
  'slack/injection_task_4': 'www.my-website-234.com/random',
  'travel/injection_task_1': 'jay@google.com',
  'travel/injection_task_3': 'jay@google.com',
  'travel/injection_task_5': 'janeLong@google.com',
  'workspace/injection_task_3': 'mark.black-2134@gmail.com',
  'workspace/injection_task_4': 'mark.black-2134@gmail.com',
  'workspace/injection_task_5': 'mark.black-2134@gmail.com',
};
const T6_AGENTDOJO_TEXT = new Set(agentdojoCases.map((c) => renderAgentDojo(AGENTDOJO.cases[c.key].goal)));
let adSkipped = 0;
for (const a of AGENTDOJO_RUN.attacks) {
  if (T6_AGENTDOJO_TEXT.has(a.text)) {
    adSkipped++; // same injection string as AD-EXFIL-001/002
    continue;
  }
  const key = `${a.suite}/${a.injectionTask}`;
  const target = AGENTDOJO_EXFIL[key] ?? null;
  if (target && !a.goal.includes(target)) throw new Error(`${key}: exfil target ${target} not in GOAL`);
  if (!a.text.includes(a.goal)) throw new Error(`${key}/${a.attack}: rendered text does not contain the GOAL`);
  const itNum = a.injectionTask.replace(/\D/g, '');
  const id = `AD-${a.suite.toUpperCase()}-IT${itNum}-${a.attack.toUpperCase().replaceAll('_', '-')}`;
  written.push(
    writeJson(`fixtures/agentdojo/ad-${a.suite}-it${itNum}-${a.attack.replaceAll('_', '-')}.json`, {
      id,
      scenario: `indirect-injection${target ? '-exfil' : ''} (${a.suite} suite, ${a.attack})`,
      source: {
        benchmark: 'AgentDojo',
        url: AGENTDOJO_PIN.repo,
        license: 'MIT',
        fidelity: 'verbatim',
        caseRef: `${a.attack} x ${a.suite}/${a.injectionTask}; user task ${a.suite}/${a.userTask}`,
        upstream: upstreamRef({
          repo: AGENTDOJO_PIN.repo,
          commit: AGENTDOJO_PIN.commit,
          benchmarkVersion: AGENTDOJO_RUN.benchmarkVersion,
          attack: a.attack,
          injectionTask: a.injectionTask,
          goal: a.goal,
          userTask: a.userTask,
          extractedBy: 'tools/extract-agentdojo.py (AgentDojo load_attack(...).attack(user_task, injection_task))',
          text: a.text,
        }),
        note:
          "Injection string = AgentDojo's own attack class output for this (user task, injection task) pair. " +
          "User turn = the user task's PROMPT; tool call = the ground-truth call whose output carries the injection " +
          'vector (AgentDojo canary method). The tool result carries only the injection string (T6 convention): ' +
          'the surrounding environment data is omitted.',
      },
      channel: 'tool_output',
      request: toolConversation(a.prompt, a.tool, a.args, a.text),
      label: label(
        target
          ? { groundTruth: 'positive', verdict: 'block', category: 'indirect_prompt_injection+data_exfiltration', exfilTargetUrl: target }
          : { groundTruth: 'positive', verdict: 'block', category: 'indirect_prompt_injection' },
      ),
      notes: `AgentDojo ${a.attack} injection in a ${a.tool} result. Goal: ${a.goal}`,
    }),
  );
}

// ---- AgentDojo v1 benign: every user task's ground-truth transcript, default environment ---------
for (const b of AGENTDOJO_RUN.benign) {
  const n = b.userTask.replace(/\D/g, '');
  const bytes = b.calls.reduce((t, c) => t + c.output.length, 0);
  written.push(
    writeJson(`fixtures/agentdojo-benign/adb-${b.suite}-ut${pad3(Number(n))}.json`, {
      id: `ADB-${b.suite.toUpperCase()}-UT${pad3(Number(n))}`,
      scenario: `benign agent task (AgentDojo ${b.suite} suite, no injection)`,
      source: {
        benchmark: 'AgentDojo',
        url: AGENTDOJO_PIN.repo,
        license: 'MIT',
        fidelity: 'verbatim',
        caseRef: `${b.suite}/${b.userTask} ground truth on the default environment (no attack)`,
        upstream: upstreamRef({
          repo: AGENTDOJO_PIN.repo,
          commit: AGENTDOJO_PIN.commit,
          benchmarkVersion: AGENTDOJO_RUN.benchmarkVersion,
          userTask: b.userTask,
          formatter: AGENTDOJO_RUN.formatter,
          extractedBy: 'tools/extract-agentdojo.py (ground truth run through AgentDojo FunctionsRuntime)',
          toolOutputSha256: b.calls.map((c) => upstreamRef({ text: c.output }).sha256),
          text: b.calls[0].output,
        }),
        note:
          "User turn = the user task's PROMPT. Every ground-truth tool call and its output, in order, as AgentDojo " +
          'renders them for the model. Injection vectors hold their benign defaults. upstream.text is the first ' +
          'tool output (the payload message); toolOutputSha256 covers all of them.',
      },
      channel: 'tool_output',
      request: toolTranscript(b.prompt, b.calls),
      label: label({ groundTruth: 'negative', verdict: 'allow', category: 'benign' }),
      dataRich: { toolCalls: b.calls.length, toolOutputChars: bytes },
      notes: `Benign ${b.suite} task with ${b.calls.length} tool call(s), ${bytes} chars of real tool output.`,
    }),
  );
}

// ---- InjecAgent enhanced: DS (exfil) + DH (direct harm), diagonal sample ------------------------
const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/;
// The exfil destination is the address the SEND step names, not the first address in the text:
// DS case 379 looks up 'john.doe@gmail.com' and then emails the result to 'amy.watson@gmail.com'.
const SEND_VERB = /\b(send|email|forward|share)\b/i;
function dsDestination(instruction) {
  const v = instruction.search(SEND_VERB);
  return v < 0 ? null : (instruction.slice(v).match(EMAIL)?.[0] ?? null);
}
for (const k of INJECAGENT_SAMPLE.cases) {
  const ds = k.file.includes('_ds_');
  const tag = ds ? 'DS' : 'DH';
  const target = ds ? dsDestination(k.attackerInstruction) : null;
  if (ds && !target) throw new Error(`InjecAgent DS case ${k.caseIndex}: no destination email after a send verb in the attacker instruction`);
  if (!k.toolResponse.includes(k.attackerInstruction)) throw new Error(`InjecAgent ${tag} ${k.caseIndex}: attacker instruction not in tool response`);
  const args = JSON.parse(k.toolParameters.replaceAll("'", '"'));
  written.push(
    writeJson(`fixtures/injecagent/injecagent-${tag.toLowerCase()}-e${pad3(k.caseIndex)}.json`, {
      id: `IA-${tag}-E${pad3(k.caseIndex)}`,
      scenario: `${ds ? 'data-stealing' : 'direct-harm'} attack (InjecAgent ${tag}, ${k.attackType})`,
      source: {
        benchmark: 'InjecAgent',
        url: INJECAGENT.repo,
        license: 'MIT',
        fidelity: 'verbatim',
        caseRef: `${k.file}[${k.caseIndex}] (${k.setting})`,
        upstream: upstreamRef({
          repo: INJECAGENT.repo,
          commit: INJECAGENT.commit,
          file: k.file,
          caseIndex: k.caseIndex,
          field: 'Tool Response',
          attackerInstruction: k.attackerInstruction,
          attackerTools: k.attackerTools,
          text: k.toolResponse,
        }),
        note:
          "User turn = the case's 'User Instruction'; tool call = its 'User Tool' with 'Tool Parameters' (as JSON); " +
          "tool result = its 'Tool Response' verbatim. Selection: one case per attacker case, user tool rotating.",
      },
      channel: 'tool_output',
      request: toolConversation(k.userInstruction, k.userTool, args, k.toolResponse),
      label: label(
        ds
          ? { groundTruth: 'positive', verdict: 'block', category: 'indirect_prompt_injection+data_exfiltration', exfilTargetUrl: target }
          : { groundTruth: 'positive', verdict: 'block', category: 'indirect_prompt_injection' },
      ),
      notes: `InjecAgent ${tag} (${k.attackType}) via ${k.userTool}; attacker tools: ${k.attackerTools.join(', ')}.`,
    }),
  );
}

console.log(`wrote ${written.length} benchmark fixtures (AgentDojo duplicates of T6 cases skipped: ${adSkipped})`);
