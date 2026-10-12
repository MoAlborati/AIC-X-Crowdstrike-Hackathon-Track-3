// SPDX-License-Identifier: Apache-2.0
//
// Portions of this file (DETECTION_EDGE, WORD_CHAR, detectionTextReplica, the
// ATTACK_PATTERNS_REPLICA regexes, and detectAttacksReplica) are copied from
// damn-vulnerable-ai-agent (DVAA), src/core/vulnerabilities.js, at commit
// 57918267d8d529ceec6d40fc9836ab09d128eee4.
//   Copyright OpenA2A (https://github.com/opena2a-org/damn-vulnerable-ai-agent)
//   Licensed under the Apache License, Version 2.0 (the "License"); you may not
//   use this file except in compliance with the License. You may obtain a copy
//   of the License at http://www.apache.org/licenses/LICENSE-2.0
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
//   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// MODIFICATIONS (Apache-2.0 §4(b)): this is a SUBSET of DVAA's ATTACK_PATTERNS
// (only the promptInjection and dataExfiltration categories); identifiers were
// renamed with a "Replica" suffix; the loader, scanFull(), and the parity
// helpers below are new code written for this repo.
/**
 * DVAA 8KB head/tail baseline bridge — REAL SEAM for the T6 evasion proof.
 *
 * SentinelProxy is a DEFENSIVE detector. This module lets the T6 corpus prove,
 * against DVAA's own baseline scanner, that an evasion variant slips past the
 * 8KB head/tail window while still carrying an exfil signal (the thing our
 * full-payload detector, T3, must catch).
 *
 * Real path: dynamically import DVAA's shipped `src/core/vulnerabilities.js`
 * from a DVAA checkout. Resolution order (first hit wins):
 *   1. $DVAA_SRC                       explicit path to a DVAA repo root
 *   2. $DVAA_DIR                       the dir scripts/setup-dvaa.sh clones into
 *   3. ${TMPDIR:-/tmp}/dvaa-target     setup-dvaa.sh's default clone dir
 * Get a checkout with:  scripts/setup-dvaa.sh clone
 *
 * Fallback (no checkout): an attributed replica subset (above). It is never
 * used silently: `source` is "replica-subset", tests print an explicit
 * "SKIPPED real-DVAA" line, and DVAA_REQUIRE_REAL=1 turns a missing checkout
 * into a thrown error (use it in CI / on the demo machine).
 * DVAA_SRC=replica forces the fallback (parity checks).
 */

import { pathToFileURL } from 'node:url';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const DVAA_PIN = '57918267d8d529ceec6d40fc9836ab09d128eee4';
const VULN_REL = 'src/core/vulnerabilities.js';

// --- Replica (subset), copied from DVAA src/core/vulnerabilities.js @ 5791826 ---
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

// Subset of ATTACK_PATTERNS (promptInjection + dataExfiltration), copied verbatim.
export const ATTACK_PATTERNS_REPLICA = {
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

function makeDetect(patterns, cut) {
  return (input) => {
    const detected = {};
    const text = cut(input);
    for (const [category, list] of Object.entries(patterns)) {
      detected[category] = list.some((p) => p.test(text));
    }
    return {
      ...detected,
      hasAttack: Object.values(detected).some((v) => v),
      categories: Object.entries(detected).filter(([, v]) => v).map(([k]) => k),
    };
  };
}

const detectAttacksReplica = makeDetect(ATTACK_PATTERNS_REPLICA, detectionTextReplica);
const asText = (input) => (typeof input === 'string' ? input : String(input ?? ''));

// --- Loader -------------------------------------------------------------------
/** Candidate DVAA roots in resolution order (no hardcoded machine paths). */
export function dvaaCandidates(env = process.env) {
  // An explicit $DVAA_SRC is the ONLY candidate: a bad path must fail, not fall through to a default.
  if (env.DVAA_SRC && env.DVAA_SRC !== 'replica') return [{ from: '$DVAA_SRC', root: env.DVAA_SRC }];
  const out = [];
  if (env.DVAA_DIR) out.push({ from: '$DVAA_DIR', root: env.DVAA_DIR });
  out.push({ from: 'setup-dvaa.sh default', root: path.join(env.TMPDIR || os.tmpdir() || '/tmp', 'dvaa-target') });
  if (!env.TMPDIR) out.push({ from: 'setup-dvaa.sh default', root: '/tmp/dvaa-target' });
  return out;
}

function gitHead(root) {
  try {
    return execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch {
    return null;
  }
}

function resolveRoot(env) {
  if (env.DVAA_SRC === 'replica') return { root: null, reason: 'DVAA_SRC=replica forces the replica' };
  const tried = [];
  for (const c of dvaaCandidates(env)) {
    if (fs.existsSync(path.join(c.root, VULN_REL))) return { root: c.root, from: c.from };
    tried.push(`${c.from}=${c.root}`);
  }
  if (env.DVAA_SRC) {
    // An explicit path that does not resolve is an error, never a quiet fallback.
    throw new Error(`DVAA_SRC=${env.DVAA_SRC} has no ${VULN_REL}`);
  }
  return { root: null, reason: `no DVAA checkout found (tried ${tried.join(', ')}); run scripts/setup-dvaa.sh clone or set DVAA_SRC` };
}

/**
 * Returns { detectAttacks, detectionText, scanFull, DETECTION_EDGE, ATTACK_PATTERNS,
 *           source, root, commit, pinMatch, reason }.
 * `source` is "dvaa-real" (real seam) or "replica-subset" (fallback).
 * `scanFull(text)` applies the same patterns to the WHOLE text (no head/tail cut).
 * Throws when DVAA_REQUIRE_REAL=1 and no real checkout at the pinned commit is found.
 */
export async function loadBaseline(env = process.env) {
  const requireReal = env.DVAA_REQUIRE_REAL === '1';
  const { root, from, reason } = resolveRoot(env);
  if (root) {
    const mod = await import(pathToFileURL(path.join(root, VULN_REL)).href);
    const commit = gitHead(root);
    const pinMatch = commit === DVAA_PIN;
    if (requireReal && !pinMatch) {
      throw new Error(`DVAA_REQUIRE_REAL=1 but ${root} is at ${commit ?? 'unknown commit'}, expected ${DVAA_PIN}`);
    }
    return {
      detectAttacks: mod.detectAttacks,
      detectionText: mod.detectionText,
      scanFull: makeDetect(mod.ATTACK_PATTERNS, asText),
      DETECTION_EDGE: mod.DETECTION_EDGE,
      ATTACK_PATTERNS: mod.ATTACK_PATTERNS,
      source: 'dvaa-real',
      root,
      from,
      commit,
      pinMatch,
      reason: null,
    };
  }
  if (requireReal) throw new Error(`DVAA_REQUIRE_REAL=1 but ${reason}`);
  return replicaBaseline(reason);
}

/** The replica, independent of environment (used by the generator for byte-stable output). */
export function replicaBaseline(reason = 'replica requested') {
  return {
    detectAttacks: detectAttacksReplica,
    detectionText: detectionTextReplica,
    scanFull: makeDetect(ATTACK_PATTERNS_REPLICA, asText),
    DETECTION_EDGE,
    ATTACK_PATTERNS: ATTACK_PATTERNS_REPLICA,
    source: 'replica-subset',
    root: null,
    from: null,
    commit: null,
    pinMatch: null,
    reason,
  };
}

export { DETECTION_EDGE };
