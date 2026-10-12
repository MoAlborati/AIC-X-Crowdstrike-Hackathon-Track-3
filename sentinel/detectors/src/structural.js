// Tourniquet T3 — structural injection signals (T3-recall). Pure, zero dependencies, linear-time.
//
// ALERT-ONLY by construction. These markers feed the dedicated rule `taint.structural_injection_marker`,
// whose action is always "alert". A marker never blocks, never marks a principal turn suspect (so it cannot
// narrow the mandate), and never sets the session's untrusted-input taint flag. Blocking stays with the
// existing strong signals: lexicon instruction + payee_not_confirmed, honeytokens, staged secrets, mandate.
//
// Each rule is a CONJUNCTION OF CLASSES, not a phrase. A single word class (e.g. "ignore") never fires on its own:
//
//   structural.role_delimiter      chat-template control tokens (ChatML `<|im_start|>`, Llama `[INST]` /
//                                  `<<SYS>>`, Llama-3 `<|start_header_id|>`) or a bracketed SYSTEM role tag
//                                  (`<system>`, `[system prompt]`, `(system message)`). Retrieved data has no
//                                  reason to carry the delimiters a model uses to separate roles.
//   structural.instruction_reset   DISMISS-verb  ∧  PRIOR-qualifier  ∧  INSTRUCTION-noun in one sentence
//                                  ("set aside the earlier guidance", "vergessen Sie alle vorherigen
//                                  Anweisungen"). "Ignore the previous email" has no instruction noun -> no hit.
//   structural.prompt_disclosure   REVEAL-verb  ∧  the model's OWN instructions ("your system prompt",
//                                  "the instructions you were given") in one sentence.
//   structural.addressed_to_ai     untrusted text that addresses its reader as an AI model ("you, the AI
//                                  language model", "Attention LLM:", "Note to the AI:"). Documents are
//                                  written for people; text written to the model is an instruction channel.
//
// Bounds: sentence splitting is a single linear pass; each sentence is tested only up to MAX_SENTENCE_CHARS
// per window, and longer sentences are tested in overlapping windows (never truncated: every character is
// covered). Every regex uses bounded quantifiers without nested repetition. At most MAX_MARKERS markers are
// returned (one per rule, so the cap is never reached; it bounds the evidence string).

export const MAX_MARKERS = 8;
export const MAX_SENTENCE_CHARS = 400;

const ROLE_DELIMITER = [
  /<\|\s{0,2}(?:im_start|im_end|start_header_id|end_header_id|eot_id|system)\s{0,2}\|>/i,
  /\[\/?INST\]|<<\/?SYS>>/,
  /<\/?\s{0,2}system\s{0,2}>/i,
  /[\[(]\s{0,2}system[ _-](?:message|prompt|instructions?|override)\s{0,2}[\])]/i,
];

const DISMISS =
  /\b(?:ignore|ignoring|disregard|disregarding|forget|forgetting|set aside|pay no attention to|discard|abandon|stop following|no longer follow|vergiss|vergessen|ignorier\w{0,3}|missachte\w{0,2}|olvid[ae]\w{0,3}|ignora\w{0,3}|oublie\w{0,2}|ignorez)\b/i;
const PRIOR =
  /\b(?:previous|prior|earlier|preceding|above|original|initial|so far|until now|at the start|you were (?:given|told)|you've been (?:given|told)|you have been (?:given|told)|vorherigen|bisherigen|früheren|vorigen|obigen|anteriores|previas|précédentes|antérieures)\b/i;
const INSTRUCTION_NOUN =
  /\b(?:instructions?|directions|directives?|guidance|guidelines|rules|prompts?|system prompt|orders|commands|whatever you were told|what you were told|anweisungen|instruktionen|vorgaben|befehle|regeln|instrucciones|órdenes|reglas|consignes)\b/i;

const REVEAL = /\b(?:print|show|reveal|repeat(?: back)?|output|display|tell me|give me|share|disclose|dump|recite|write out|list|zeig\w{0,3}|nenne\w{0,2}|gib|muestra\w{0,2}|revela\w{0,2})\b/i;
const OWN_INSTRUCTIONS =
  /\b(?:your (?:system prompt|initial prompt|hidden prompt|original prompt|instructions|directives|guidelines|rules|prompt)|(?:instructions|rules|guidelines|prompt) (?:that )?you were given|deine(?:n)? (?:anweisungen|systemprompt|prompt)|ihre (?:anweisungen|systemanweisungen)|tus instrucciones)\b/i;

const ADDRESSED_TO_AI = [
  /\byou,?\s{1,3}(?:the|an?)\s{1,3}(?:ai|a\.i\.|llm|language model|ai (?:language model|assistant|model|agent)|chatbot)\b/i,
  /\b(?:dear|attention|hey|hello|hi|note to|message (?:to|for)|instructions? (?:to|for))\s{1,3}(?:the\s{1,3})?(?:ai|llm|language model|ai (?:assistant|model|agent)|chatbot)\s{0,2}[,:!-]/i,
  /\b(?:if|since|because|as) you(?:'re| are)\s{1,3}(?:an?|the)\s{1,3}(?:ai|llm|language model|ai (?:assistant|model|agent)|chatbot)\b/i,
];

/** Sentences (split on . ! ? and newlines), each yielded as <= MAX_SENTENCE_CHARS windows overlapping by half. */
function* windows(text) {
  let start = 0;
  for (let i = 0; i <= text.length; i++) {
    const c = i < text.length ? text.charCodeAt(i) : 10;
    if (c === 46 || c === 33 || c === 63 || c === 10 || c === 59) {
      if (i > start) {
        const s = text.slice(start, i);
        if (s.length <= MAX_SENTENCE_CHARS) yield s;
        else for (let j = 0; j < s.length; j += MAX_SENTENCE_CHARS / 2) yield s.slice(j, j + MAX_SENTENCE_CHARS);
      }
      start = i + 1;
    }
  }
}

const clip = (s) => s.replace(/\s+/g, ' ').trim().slice(0, 80);

/**
 * Structural injection markers in `text`. `untrusted` = tool output / embedded untrusted block; the
 * addressed_to_ai rule only applies there (a principal may of course talk to its own assistant).
 * Returns marker strings `structural.<rule>:"<matched text>"`.
 */
export function findStructuralMarkers(text, { untrusted = false } = {}) {
  if (typeof text !== 'string' || text.length === 0) return [];
  const out = [];
  const add = (rule, hit) => {
    if (hit && out.length < MAX_MARKERS) out.push(`structural.${rule}:"${clip(hit)}"`);
  };
  for (const re of ROLE_DELIMITER) {
    const m = re.exec(text);
    if (m) {
      add('role_delimiter', m[0]);
      break;
    }
  }
  if (untrusted) {
    for (const re of ADDRESSED_TO_AI) {
      const m = re.exec(text);
      if (m) {
        add('addressed_to_ai', m[0]);
        break;
      }
    }
  }
  let reset = null;
  let disclose = null;
  for (const s of windows(text)) {
    if (!reset && DISMISS.test(s) && PRIOR.test(s) && INSTRUCTION_NOUN.test(s)) reset = s;
    if (!disclose && REVEAL.test(s) && OWN_INSTRUCTIONS.test(s)) disclose = s;
    if (reset && disclose) break;
  }
  add('instruction_reset', reset);
  add('prompt_disclosure', disclose);
  return out;
}
