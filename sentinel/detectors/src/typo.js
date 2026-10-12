// SentinelProxy COMP-3: typoglycemia-tolerant injection-phrase matching.
//
// Gap (#140): `findInjectionPhrases` (text.js) is an exact lower-cased indexOf, so a scrambled spelling
// ("ignroe all prevoius instrcutions") or a scrambled Best-of-N case variant ("IgNrOe PrEvIoUs ...")
// evades it. Readers (human and LLM) still understand such text when the first and last letters of each
// word stay put. This module matches words by a scramble-invariant SIGNATURE:
//   first letter + last letter + sorted interior letters + length
// against the key words of a SMALL set of high-signal, multi-word injection phrases.
//
// False-positive control (benign corpora must produce zero hits, asserted in test/typo.test.js):
//   * a phrase is reported only when ALL its slots match consecutively, allowing at most ONE filler word
//     in the whole match ("ignore ALL previous instructions");
//   * at least one matched word must be actually scrambled (exact spellings are text.js's job, so this
//     module never double-reports them);
//   * scramble-matching applies only to words of length >= 4 (shorter words must match exactly);
//   * only phrases whose words together are instruction-override language are listed, never single words.
//
// Bounds (team rule: bounded + fail-loud, see bounds.js). One linear pass over the text, O(n) in its
// length: each token is at most MAX_KEYWORD_LEN letters before it is signed (longer runs cannot match and
// are skipped whole, not cut), and phrase matching looks at most MAX_SLOTS + 1 tokens ahead. The number of
// tokens examined per text is capped at MAX_TYPO_TOKENS = maxPayloadBytes / 2 (a token needs a letter and
// a separator, so a payload within the 2 MiB cap cannot reach it). If the cap is hit anyway, the scan
// does NOT stop silently: it returns the label `typo:scan_cap_exceeded`, which the detector treats like
// any other injection marker (the text is raised, i.e. fail-closed), and the label carries the counts.
import { DEFAULT_BOUNDS } from './bounds.js';

export const MAX_TYPO_TOKENS = Math.floor(DEFAULT_BOUNDS.maxPayloadBytes / 2);
export const TYPO_LABEL_PREFIX = 'typo:';
const MIN_SCRAMBLE_LEN = 4;

// Each phrase: a label (the canonical phrase it stands for) and slots; each slot lists accepted words.
const IGNORE = ['ignore', 'disregard', 'forget', 'override', 'bypass'];
const PRIOR = ['previous', 'prior', 'above', 'earlier', 'preceding', 'former'];
const INSTRUCTIONS = ['instructions', 'instruction', 'directions', 'directives', 'guidelines', 'rules', 'prompts', 'commands'];
const PHRASES = [
  { label: 'ignore previous instructions', slots: [IGNORE, PRIOR, INSTRUCTIONS] },
  { label: 'ignore your instructions', slots: [IGNORE, INSTRUCTIONS] },
  { label: 'system override', slots: [['system'], ['override']] },
  { label: 'do not tell the user', slots: [['do'], ['not'], ['tell', 'inform', 'mention', 'alert', 'notify'], ['user']] },
  { label: 'do not tell the user', slots: [['dont'], ['tell', 'inform', 'mention', 'alert', 'notify'], ['user']] },
];
const MAX_SLOTS = Math.max(...PHRASES.map((p) => p.slots.length));

const KEYWORDS = new Set(PHRASES.flatMap((p) => p.slots.flat()));
const MAX_KEYWORD_LEN = Math.max(...[...KEYWORDS].map((w) => w.length));

/** Scramble-invariant signature: first + last letter, sorted interior, length (documentation / tests). */
export function typoSignature(word) {
  if (word.length < MIN_SCRAMBLE_LEN) return null;
  const interior = word.slice(1, -1).split('').sort().join('');
  return `${word[0]}${word[word.length - 1]}${interior}${word.length}`;
}

// (first letter, last letter, length) -> keywords with that shape. A token is only letter-counted when its
// shape matches a keyword, so ordinary words cost one Map lookup and no allocation.
const shapeKey = (first, last, len) => first * 65536 + last * 64 + len;
const SHAPES = new Map();
for (const w of KEYWORDS) {
  const k = shapeKey(w.charCodeAt(0), w.charCodeAt(w.length - 1), w.length);
  if (!SHAPES.has(k)) SHAPES.set(k, []);
  SHAPES.get(k).push(w);
}
// Pre-built resolutions (no per-token allocation): { words, scrambled }.
const EXACT = new Map([...KEYWORDS].map((w) => [w, Object.freeze({ words: [w], scrambled: false })]));
const SCRAMBLED = new Map([...KEYWORDS].map((w) => [w, Object.freeze({ words: [w], scrambled: true })]));
const SLOT_SETS = PHRASES.map((p) => ({ label: p.label, slots: p.slots.map((s) => new Set(s)) }));

const counts = new Int32Array(26);
/** lower[start, start+len) is `w` spelled exactly (0), with its interior letters permuted (1), or neither (-1). */
function compare(lower, start, len, w) {
  let same = true;
  for (let k = 1; k < len - 1; k++) if (lower.charCodeAt(start + k) !== w.charCodeAt(k)) { same = false; break; }
  if (same) return 0;
  if (len < MIN_SCRAMBLE_LEN) return -1;
  counts.fill(0);
  for (let k = 1; k < len - 1; k++) { counts[lower.charCodeAt(start + k) - 97]++; counts[w.charCodeAt(k) - 97]--; }
  for (let k = 0; k < 26; k++) if (counts[k] !== 0) return -1;
  return 1;
}

/** Resolve the token lower[start, start+len) (letters only) to a keyword resolution, or null. */
function resolveSpan(lower, start, len) {
  if (len > MAX_KEYWORD_LEN) return null;
  const cands = SHAPES.get(shapeKey(lower.charCodeAt(start), lower.charCodeAt(start + len - 1), len));
  if (!cands) return null;
  let scr = null;
  for (const w of cands) {
    const c = compare(lower, start, len, w);
    if (c === 0) return EXACT.get(w);
    if (c === 1) scr = scr ? { words: [...scr.words, w], scrambled: true } : SCRAMBLED.get(w);
  }
  return scr;
}

const isLetter = (c) => c >= 97 && c <= 122; // a-z after lower-casing
const isApos = (c) => c === 39 || c === 0x2019; // ' and the typographic right single quote

/**
 * Linear tokenizer: runs of ASCII letters in the lower-cased text, each resolved in place against the
 * keyword shapes. An apostrophe inside a word ("don't") is dropped: such a token is resolved from a small
 * copy without it. Tokens that cannot match resolve to null but still occupy a position, so adjacency is
 * exact. Returns { resolved, capped }.
 */
function tokenize(lower, maxTokens) {
  const resolved = [];
  let seen = 0;
  let i = 0;
  const n = lower.length;
  while (i < n) {
    if (!isLetter(lower.charCodeAt(i))) { i++; continue; }
    const start = i;
    let apos = false;
    while (i < n) {
      const c = lower.charCodeAt(i);
      if (isLetter(c)) { i++; continue; }
      if (isApos(c) && i + 1 < n && isLetter(lower.charCodeAt(i + 1))) { apos = true; i++; continue; }
      break;
    }
    if (++seen > maxTokens) return { resolved, capped: true };
    if (!apos) resolved.push(resolveSpan(lower, start, i - start));
    else if (i - start > MAX_KEYWORD_LEN + 2) resolved.push(null);
    else { const w = lower.slice(start, i).replace(/['\u2019]/g, ''); resolved.push(resolveSpan(w, 0, w.length)); }
  }
  return { resolved, capped: false };
}

/**
 * Scrambled (typoglycemia) injection phrases in text. Returns labels `typo:<canonical phrase>` (deduped),
 * or `typo:scan_cap_exceeded (...)` when the token cap is hit (fail-loud, never a silent partial scan).
 */
export function findTypoPhrases(text, { maxTokens = MAX_TYPO_TOKENS } = {}) {
  if (typeof text !== 'string' || text.length === 0) return [];
  const { resolved, capped } = tokenize(text.toLowerCase(), maxTokens);
  const found = new Set();
  for (let i = 0; i < resolved.length; i++) {
    if (!resolved[i]) continue;
    // Phrases are ordered most-specific first; the first one that matches at i claims the position, so
    // "ignroe prevoius instrcutions" is one finding, not also the 2-slot "ignore your instructions".
    for (const p of SLOT_SETS) {
      if (matchAt(resolved, i, p.slots)) { found.add(p.label); break; }
    }
  }
  const out = [...found].map((l) => TYPO_LABEL_PREFIX + l);
  if (capped) out.push(`${TYPO_LABEL_PREFIX}scan_cap_exceeded (tokens>${maxTokens}, cap=${maxTokens}, action=raise)`);
  return out;
}

const fits = (r, slot) => r !== null && r !== undefined && r.words.some((w) => slot.has(w));

/** All slots match from token i, consecutively, with at most one filler token; >= 1 scrambled word. */
function matchAt(resolved, i, slots) {
  if (!fits(resolved[i], slots[0])) return false;
  let scrambled = resolved[i].scrambled;
  let j = i + 1;
  let filler = 0;
  for (let k = 1; k < slots.length; k++) {
    if (fits(resolved[j], slots[k])) { scrambled ||= resolved[j].scrambled; j++; continue; }
    if (filler === 0 && j + 1 < resolved.length && fits(resolved[j + 1], slots[k])) {
      filler = 1;
      scrambled ||= resolved[j + 1].scrambled;
      j += 2;
      continue;
    }
    return false;
  }
  return scrambled;
}

export const _internals = Object.freeze({ PHRASES, MAX_SLOTS, MAX_KEYWORD_LEN, KEYWORDS });
