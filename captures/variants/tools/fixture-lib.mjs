/**
 * Shared helpers for the T6 fixture builders: message shapes per channel, labels,
 * framework tags, provenance hashes. Pure functions, no clock/RNG.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..'); // captures/variants

export const sha256 = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

export function writeJson(rel, obj) {
  const p = path.join(ROOT, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(obj, null, 2) + '\n');
  return rel;
}

// ---- Channels -> message shape -----------------------------------------------------------------
// user_message : the payload IS the user turn.
// tool_output  : user asks -> assistant calls a tool -> payload arrives in a role:"tool" message.
// rag_document : same OpenAI tool-call shape; the tool is a retrieval tool and the payload is the
//                retrieved document. Provenance of the untrusted text is therefore the message role,
//                not just the `channel` label (review F5).
export const CHANNELS = Object.freeze(['user_message', 'tool_output', 'rag_document']);
export const PAYLOAD_ROLE = Object.freeze({ user_message: 'user', tool_output: 'tool', rag_document: 'tool' });

export function userMessage(content) {
  return { messages: [{ role: 'user', content }] };
}

/**
 * OpenAI chat shape for an untrusted tool result / retrieved document.
 * @param {string} userTurn   the (trusted) user request
 * @param {string} toolName   function the assistant called
 * @param {object} args       function arguments (serialized to JSON, OpenAI convention)
 * @param {string} payload    the untrusted tool result / retrieved document text
 */
export function toolConversation(userTurn, toolName, args, payload) {
  const id = 'call_0001';
  return {
    messages: [
      { role: 'user', content: userTurn },
      {
        role: 'assistant',
        content: '',
        tool_calls: [{ id, type: 'function', function: { name: toolName, arguments: JSON.stringify(args) } }],
      },
      { role: 'tool', tool_call_id: id, name: toolName, content: payload },
    ],
  };
}

/** Index of the message that carries the payload for a fixture's channel. */
export function payloadIndex(fixture) {
  const role = PAYLOAD_ROLE[fixture.channel];
  const msgs = fixture.request.messages;
  const idx = role === 'user' ? msgs.findIndex((m) => m.role === 'user') : msgs.findIndex((m) => m.role === 'tool');
  if (idx < 0) throw new Error(`${fixture.id}: no ${role} message for channel ${fixture.channel}`);
  return idx;
}

// ---- Framework tags (review F8, L3) ------------------------------------------------------------
// IDs/names verified against MITRE ATLAS data (ATLAS.yaml; AML.T0051.000/.001, AML.T0057, AML.T0086),
// OWASP Top 10 for LLM Applications 2025, OWASP Top 10 for Agentic Applications (Dec 2025), and the
// OASB-1 category slugs. Every ID must exist in sentinel/alerts/mapping.js CATALOG (T4) so a T7 join
// on the CATALOG never hits an unknown ID — enforced in tests/corpus.test.mjs — with ONE declared
// exception, PENDING_T4_CATALOG below. Unknown category -> throw (no default).
export const FRAMEWORKS_BY_CATEGORY = Object.freeze({
  prompt_injection: {
    // Direct PI (the payload IS the user turn). In mapping.js CATALOG since PR #12.
    atlas: ['AML.T0051.000'], // LLM Prompt Injection: Direct
    owaspLlm: ['LLM01'], // Prompt Injection
    owaspAgentic: ['ASI01'], // Agent Goal Hijack
    oasb: ['prompt-injection'],
  },
  'indirect_prompt_injection+data_exfiltration': {
    // Indirect PI; Exfiltration via AI Agent Tool Invocation; LLM Data Leakage
    atlas: ['AML.T0051.001', 'AML.T0086', 'AML.T0057'],
    // Prompt Injection; Sensitive Information Disclosure; Excessive Agency
    owaspLlm: ['LLM01', 'LLM02', 'LLM06'],
    // Agent Goal Hijack; Tool Misuse and Exploitation
    owaspAgentic: ['ASI01', 'ASI02'],
    // same slugs as mapping.js indirect_prompt_injection / taint_flow_exfil
    oasb: ['prompt-injection', 'data-exfiltration'],
  },
  benign: { atlas: [], owaspLlm: [], owaspAgentic: [], oasb: [] },
});

/**
 * Framework IDs used above that are valid upstream but NOT yet in mapping.js CATALOG. Each entry is a
 * request to T4 (add it to CATALOG.atlasTechniques). The corpus test fails if an entry here appears
 * in CATALOG (remove it from this list then) or if any other ID is missing from CATALOG.
 */
export const PENDING_T4_CATALOG = Object.freeze({});

export function frameworksFor(category) {
  const f = FRAMEWORKS_BY_CATEGORY[category];
  if (!f) throw new Error(`no framework mapping for category "${category}"`);
  return { atlas: [...f.atlas], owaspLlm: [...f.owaspLlm], owaspAgentic: [...f.owaspAgentic], oasb: [...f.oasb] };
}

export function label({ groundTruth, verdict, category, exfilTargetUrl = null }) {
  return {
    groundTruth, // "positive" | "negative"
    expectedVerdict: verdict, // "block" | "allow"
    category,
    frameworks: frameworksFor(category),
    // dvaa{}-compatible ground-truth block (T1 schema). exfilExecuted is null: these are
    // PRE-COMPUTED/recorded fixtures, not run live through DVAA.
    dvaa: {
      exfilAttempted: groundTruth === 'positive' && exfilTargetUrl !== null,
      exfilExecuted: null,
      exfilTargetUrl,
    },
  };
}

// ---- Provenance (review F1-F4, F7) -------------------------------------------------------------
// fidelity:
//   "verbatim" - the attack string is byte-identical to upstream (upstream.text, upstream.sha256);
//                only its placement in the request (which message / carrier) is ours.
//   "authored" - written for this corpus (benign material only; no attack text is authored).
export function upstreamRef({ text, ...locator }) {
  return { ...locator, sha256: sha256(text), text };
}
