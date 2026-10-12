/**
 * DVAA 8KB head/tail baseline bridge — REAL SEAM for T6 evasion proof.
 *
 * SentinelProxy is a DEFENSIVE detector. This module lets the T6 corpus prove,
 * against DVAA's own baseline scanner, that an evasion variant slips past the
 * 8KB head/tail window while still carrying a live exfil signal (the thing our
 * full-payload detector, T3, must catch).
 *
 * Primary path (real seam): dynamically import DVAA's shipped
 * `src/core/vulnerabilities.js` — `detectAttacks()` and `detectionText()` — from
 * a real DVAA checkout. Resolution order:
 *   1. $DVAA_SRC               (explicit override: path to DVAA repo root)
 *   2. the pinned clone recorded by T1 (scratchpad), if present
 * Fallback path (offline/CI, no DVAA checkout): a faithful, attributed replica
 * of DETECTION_EDGE + detectionText + the two ATTACK_PATTERNS categories the
 * corpus exercises (promptInjection, dataExfiltration). The replica is a subset
 * and is clearly labelled as such in `source`.
 *
 * Provenance of the replica: copied verbatim from
 *   damn-vulnerable-ai-agent @ 57918267d8d529ceec6d40fc9836ab09d128eee4
 *   src/core/vulnerabilities.js  (DETECTION_EDGE, detectionText, ATTACK_PATTERNS)
 * DVAA is the organizer-provided, intentionally-vulnerable training sandbox.
 */

import { pathToFileURL } from 'node:url';
import fs from 'node:fs';
import path from 'node:path';

const PINNED_CLONE =
  '/tmp/claude-1000/-home-gingy-crowdstrike/8b7285cd-421f-4ce5-bd06-21e5e39a65eb/scratchpad/dvaa';

// --- Faithful replica (subset) ------------------------------------------------
// Verbatim from DVAA src/core/vulnerabilities.js @ 5791826.
const DETECTION_EDGE = 8 * 1024;
const WORD_CHAR = /\w/;

function detectionTextReplica(input) {
  const text = typeof input === 'string' ? input : String(input ?? '');
  if (text.length <= DETECTION_EDGE * 2) return text;
  let headEnd = DETECTION_EDGE;
  while (headEnd < DETECTION_EDGE + 64 && WORD_CHAR.test(text[headEnd])) headEnd++;
  let tailStart = text.length - DETECTION_EDGE;
  while (tailStart > text.length - DETECTION_EDGE - 64 && WORD_CHAR.test(text[tailStart - 1])) tailStart--;
  return `${text.slice(0, headEnd)}\n\u0000\n${text.slice(tailStart)}`;
}

// Subset of ATTACK_PATTERNS the corpus exercises (promptInjection + dataExfiltration),
// copied verbatim. Other categories are omitted in the replica only.
const ATTACK_PATTERNS_REPLICA = {
  promptInjection: [
    /ignore.{0,200}(?:previous|above|prior|all).{0,200}instruction/i,
    /disregard.{0,200}(?:previous|system|safety)/i,
    /new.{0,200}(?:instruction|directive|task)/i,
    /\[(?:INST|SYSTEM|ADMIN)\]/i,
    /<<<.{0,200}>>>/,
    /(?<!-)---+\s*(?:SYSTEM|ADMIN|OVERRIDE)/i,
    /forget.{0,200}(?:everything|rules|instructions)/i,
    /\byou\w{0,10}\b.{0,100}\b(?:are|must|will)\b.{0,100}\b(?:now|actually)\b/i,
  ],
  dataExfiltration: [
    /(?:reveal|show|tell|give|what\s+(?:is|are)).{0,200}(?:system|initial).{0,200}(?:prompt|instruction)/i,
    /(?:reveal|expose|show).{0,200}(?:api|secret|private)\s*key/i,
    /(?:what|show|tell|give|reveal|share|expose|list|print|dump|leak).{0,40}(?:password|passwd|credential|secret|api\s*key|access\s*key|\btoken\b)/i,
    /(?:admin|database|db|root|user|login|account)\s*(?:password|passwd|credential|secret)/i,
    /what.{0,100}(?:were|are).{0,100}(?:you|instructions).{0,100}told/i,
    /\b(?:send|post|transmit).{0,200}?(?:\b(?:to|https?|webhooks?)\b|\bwith\s+(?:[\w-]{1,40}\s+){0,3}?(?:conversation|chat|session)\s+history\b)/i,
    /(?:context|token).{0,200}(?:window|limit|length)/i,
    /(?:previous|other).{0,200}(?:user|conversation|session)/i,
    /training.{0,200}data/i,
  ],
};

function detectAttacksReplica(input) {
  const detected = {};
  const text = detectionTextReplica(input);
  for (const [category, patterns] of Object.entries(ATTACK_PATTERNS_REPLICA)) {
    detected[category] = patterns.some((p) => p.test(text));
  }
  return {
    ...detected,
    hasAttack: Object.values(detected).some((v) => v),
    categories: Object.entries(detected).filter(([, v]) => v).map(([k]) => k),
  };
}

// --- Loader -------------------------------------------------------------------
function dvaaRoot() {
  const env = process.env.DVAA_SRC;
  if (env === 'replica') return null; // force the offline fallback (used by CI parity checks)
  if (env && fs.existsSync(path.join(env, 'src/core/vulnerabilities.js'))) return env;
  if (fs.existsSync(path.join(PINNED_CLONE, 'src/core/vulnerabilities.js'))) return PINNED_CLONE;
  return null;
}

/**
 * Returns { detectAttacks, detectionText, DETECTION_EDGE, source }.
 * `source` is "dvaa-real" (real seam) or "replica-subset" (offline fallback).
 */
export async function loadBaseline() {
  const root = dvaaRoot();
  if (root) {
    const mod = await import(pathToFileURL(path.join(root, 'src/core/vulnerabilities.js')).href);
    return {
      detectAttacks: mod.detectAttacks,
      detectionText: mod.detectionText,
      DETECTION_EDGE: mod.DETECTION_EDGE,
      source: 'dvaa-real',
      root,
    };
  }
  return {
    detectAttacks: detectAttacksReplica,
    detectionText: detectionTextReplica,
    DETECTION_EDGE,
    source: 'replica-subset',
    root: null,
  };
}

export { DETECTION_EDGE };
