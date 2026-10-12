// SentinelProxy T3 — structural injection signals (T3-recall). Pure, zero dependencies, linear-time.
//
// The phrase lexicon in text.js matches known benchmark wordings. These rules instead match the SHAPE of an
// injection, so they generalize to wordings the lexicon has never seen:
//
//   structural.role_impersonation   chat-template / role delimiters or a forged prompt boundary inside text
//                                   that should be plain data: `(system_message)`, `<|im_start|>`, `[INST]`,
//                                   `<<SYS>>`, `<system>`, a line opening with `System message:` / `[system notice]:`,
//                                   `======END`. Untrusted content has no reason to speak as a chat role.
//   structural.directive_to_agent   (untrusted content only) a line that opens with an agent-directive label
//                                   (`TODO:`, `Task:`, `Instruction:`, `Note to the assistant:` …)
//                                   immediately followed by an action verb (send, transfer, delete, visit …).
//                                   A web page / transaction memo / review is data, not a work order.
//   structural.third_person_user    (untrusted content only) an imperative action verb that opens a sentence
//                                   and whose object refers to "the user" in the third person
//                                   ("Send … the user's phone model", "Change the password of the user").
//                                   Text addressed to the end user says "you"; text that talks ABOUT the user
//                                   while giving orders is addressed to the agent.
//   structural.context_reset        an instruction to discard prior context: forget/ignore/disregard +
//                                   everything / all previous / the above / what I told you, in EN, DE, ES.
//   structural.prompt_extraction    a request to print/reveal the system/initial prompt, "the text above",
//                                   or model internals (embeddings), in EN and DE.
//   structural.output_override      pins every future answer ("answer every question with …") or suppresses
//                                   refusal ("you are supposed to answer at all times", "never refuse").
//   structural.task_switch          a forged hand-over to a new task ("now comes a new task", "here comes
//                                   the second test", "jetzt kommt eine neue Aufgabe").
//
// Every rule returns a marker string like `structural.context_reset:"forget everything"` which the detector
// treats exactly like a lexicon phrase (pass 1 of the pre-forward scan): it raises an alert-level
// `taint.instruction_in_untrusted_content` / `inbound.instruction_in_principal_turn`, and escalates to a
// pre-forward BLOCK (`inbound.exfil_instruction`) only when the same text also names a destination the
// principal never named. Markers alone never block (policy.inbound.injection defaults to "alert").
//
// Bounds: every regex is anchored or uses bounded quantifiers ({0,N}) with no nested repetition, so each is
// linear in the text length. A text yields at most MAX_MARKERS markers (the signal is boolean per rule; the
// cap bounds the evidence string, not the scan — every rule still runs over the full text).

export const MAX_MARKERS = 12;

const ACTION_VERBS =
  'send|transfer|wire|pay|forward|e-?mail|post|upload|share|publish|delete|remove|erase|change|reset|update|' +
  'modify|visit|open|navigate|go to|click|create|make|invite|add|grant|give|book|reserve|schedule|tell|reveal|' +
  'print|show|disclose|ignore|disregard|forget|execute|run|call|download|install|get|retrieve|concatenate|' +
  'collect|export|copy|move';

const ROLE_IMPERSONATION = [
  /\(\s{0,2}system[_ ]message\s{0,2}\)/i,
  /<\|\s{0,2}(?:im_start|im_end|system|start_header_id|end_header_id|eot_id)\s{0,2}\|>/i,
  /\[\/?INST\]/,
  /<<\/?SYS>>/,
  /<\/?\s{0,2}(?:system|system_prompt|sys)\s{0,2}>/i,
  // A role label needs a qualifier noun: a bare `system:` is an ordinary YAML/JS key in code and config.
  /(?:^|\n)[ \t>#*\[]{0,8}(?:system|developer)\s{1,3}(?:message|prompt|notice|instruction|override)s?\]?\s{0,3}:/i,
  /={4,}\s{0,4}END\b/,
];

const DIRECTIVE_PREFIX = new RegExp(
  `(?:^|\\n)[ \\t>*\\-]{0,8}(?:TODO|TO-DO|TASK|ACTION(?: REQUIRED)?|INSTRUCTIONS?|NOTE TO (?:THE )?(?:AI|ASSISTANT|AGENT|MODEL|BOT)|` +
    `(?:AI|ASSISTANT|AGENT|BOT) INSTRUCTIONS?)\\s{0,3}[:\\-–]\\s{0,4}(?:please\\s{1,3})?(?:${ACTION_VERBS})\\b`,
  'i',
);

// Sentence-initial imperative ... "the user" (third person) within the same sentence (<= 200 chars).
const THIRD_PERSON_USER = new RegExp(
  `(?:^|[\\n.!?:]\\s{0,4})(?:please\\s{1,3})?(?:${ACTION_VERBS})\\b[^.!?\\n]{0,200}?\\b(?:the user(?:'s|s')?|this user(?:'s)?|the victim(?:'s)?)\\b`,
  'i',
);

const CONTEXT_RESET = [
  // EN: forget/ignore/disregard (+ up to 3 words) + a scope that means "everything before this".
  /\b(?:forget|ignore|disregard|discard|overlook)\b(?:\s{1,3}[\w']{1,12}){0,3}?\s{1,3}(?:everything|all (?:previous|prior|earlier|the previous|of the above|provided|of your|your|instructions|orders|context)|(?:the|your|any|all)? ?(?:previous|prior|earlier|above|preceding|original) (?:instructions?|orders|directions|context|tasks?|prompts?|rules)|(?:the|all) (?:above|previous|provided context)|what(?:'s| is)? (?:before|above)|wh?a?t'?s before|what (?:i|we) (?:said|told you|have told you|wrote)(?: before| earlier| so far)?)/i,
  /\bforget about (?:all|everything)\b/i,
  // DE
  /\bvergiss(?:t)?\b(?:\s{1,3}\S{1,14}){0,2}?\s{1,3}(?:alles|alle (?:bisherigen|vorherigen))/i,
  /\bignorier(?:e|en)?(?: sie)?\s{1,3}(?:die obigen|das obige|alle (?:vorherigen|bisherigen)|alles)/i,
  /\bhöre? nicht auf alles\b/i,
  // ES
  /\bolvid(?:a|e|en)\s{1,3}todo\b/i,
  /\bignora\s{1,3}(?:todo|las instrucciones)\b/i,
];

const PROMPT_EXTRACTION = [
  // A reveal verb is required: merely mentioning "the system prompt" is ordinary technical prose.
  /\b(?:print|show|reveal|repeat|output|display|tell me|give me|what (?:are|were|is|was)|sagen? (?:sie )?mir|zeig(?:e|en sie)? mir)\b[^.!?\n]{0,30}?\b(?:your|the|deine|ihre)\s{1,3}(?:initial|original|system|hidden|secret|ursprünglichen|anfänglichen)\s{1,3}(?:instructions?|prompts?|anweisungen|directives)\b/i,
  /\b(?:print|show|reveal|repeat|output|display|spell[- ]?check|return)\b(?:\s{1,3}[\w']{1,10}){0,4}?\s{1,3}(?:(?:the|all of the|all|your)\s{1,3})?(?:text above|above (?:prompt|text|instructions)|prompt texts?|system prompt|your (?:prompt|instructions|embeddings|weights))\b/i,
  /\b(?:obige(?:n)? (?:eingabeaufforderung|textes|text|anweisungen)|prompt-texte)\b/i,
];

const TASK_SWITCH = [
  /\b(?:now|but now|here)\s{1,3}(?:comes?|come)\s{1,3}(?:a\s{1,3}|the\s{1,3})?(?:new|next|second|another)\s{1,3}(?:tasks?|assignments?|tests?|orders?)\b/i,
  /\bjetzt kommt\s{1,3}(?:eine\s{1,3}|die\s{1,3})?(?:neue|nächste|zweite)\s{1,3}(?:aufgabe|test|auftrag)\b/i,
  /\bneue aufgaben\b/i,
];

// Forced-output / refusal suppression: pins every future answer, or forbids the model's normal refusal.
const OUTPUT_OVERRIDE = [
  /\b(?:answer|respond|reply)\s{1,3}(?:to\s{1,3})?(?:every|all|each|any)\s{1,3}(?:questions?|prompts?|messages?|inputs?|requests?)\s{1,3}(?:only\s{1,3})?with\b/i,
  /\byou(?:'re| are)\s{1,3}(?:not\s{1,3})?supposed to\s{1,3}(?:answer|respond|reply|tell me)\b/i,
  /\b(?:do not|don't|never|you must not|you may not)\s{1,3}(?:refuse|decline)\b/i,
];

function firstHit(res, text) {
  for (const re of res) {
    const m = re.exec(text);
    if (m) return m[0];
  }
  return null;
}

const clip = (s) => s.replace(/\s+/g, ' ').trim().slice(0, 60);

/**
 * Structural injection markers in `text`. `untrusted` = the text is tool output / an embedded untrusted block
 * (enables the two rules that are only meaningful for data that should not address the agent).
 * Returns marker strings `structural.<rule>:"<matched text>"` (at most MAX_MARKERS).
 */
export function findStructuralMarkers(text, { untrusted = false } = {}) {
  if (typeof text !== 'string' || text.length === 0) return [];
  const out = [];
  const add = (rule, hit) => {
    if (hit && out.length < MAX_MARKERS) out.push(`structural.${rule}:"${clip(hit)}"`);
  };
  add('role_impersonation', firstHit(ROLE_IMPERSONATION, text));
  add('context_reset', firstHit(CONTEXT_RESET, text));
  add('prompt_extraction', firstHit(PROMPT_EXTRACTION, text));
  add('task_switch', firstHit(TASK_SWITCH, text));
  add('output_override', firstHit(OUTPUT_OVERRIDE, text));
  if (untrusted) {
    add('directive_to_agent', firstHit([DIRECTIVE_PREFIX], text));
    add('third_person_user', firstHit([THIRD_PERSON_USER], text));
  }
  return out;
}

// ---- scheme-less destinations ---------------------------------------------------------------------
// extractUrls() only sees http(s):// URLs. Injected instructions usually name a bare host
// ("post them to www.my-site.com/x"). Only `www.`-prefixed hosts are matched: a bare `label.tld` is too
// ambiguous (file names like "notes.txt", versions like "v1.2") to treat as a destination.
const WWW_HOST = /\bwww\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?){1,4}\b/gi;
const MAX_BARE_HOSTS = 32;

/** `www.`-prefixed hosts without a scheme, lower-cased, deduplicated, at most MAX_BARE_HOSTS (fail-loud flag). */
export function extractBareHosts(text) {
  const hosts = new Set();
  if (typeof text !== 'string' || text.length === 0) return { hosts: [], overflow: false };
  let overflow = false;
  WWW_HOST.lastIndex = 0;
  let m;
  while ((m = WWW_HOST.exec(text)) !== null) {
    const prev = m.index > 0 ? text[m.index - 1] : '';
    if (prev === '/' || prev === '@' || prev === '.') continue; // part of a scheme URL / email / longer host
    if (hosts.size >= MAX_BARE_HOSTS) {
      overflow = true;
      break;
    }
    hosts.add(m[0].toLowerCase());
  }
  return { hosts: [...hosts], overflow };
}
