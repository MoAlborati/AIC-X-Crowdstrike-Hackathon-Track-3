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
import { DEEPSET, AGENTDOJO, INJECAGENT, renderAgentDojo } from './upstream-cases.mjs';
import { writeJson, userMessage, toolConversation, label, upstreamRef } from './fixture-lib.mjs';

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

console.log(`wrote ${written.length} benchmark fixtures`);
