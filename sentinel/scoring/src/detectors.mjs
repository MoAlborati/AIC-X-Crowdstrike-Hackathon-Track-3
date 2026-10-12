// T7 detector interface + built-in adapters.
//
// A harness detector is a small object:
//   {
//     name: string, kind: 'noop' | 'baseline' | 'candidate',
//     description: string, available: boolean, unavailableReason?: string, provenance: object,
//     inspect(case) -> { fired: [{ ruleId, wouldBlock, alwaysEnforce?, evidence? }], failClosed?: boolean }
//     (inspect throwing is a detector ERROR: the case is itemized and the run exits non-zero)
//   }
// `fired` lists every rule that matched. `wouldBlock` says whether the rule asks for a block when it runs
// in enforce mode. `alwaysEnforce` marks fail-closed rules that block even in report-only mode (T3's
// dead-man switch). The harness, not the detector, applies the per-rule mode (see harness.mjs).
//
// Built-ins:
//   noop            — clearly labeled NO-OP baseline: never fires. Floor for every metric.
//   dvaa-baseline   — DVAA's own detectAttacks() (src/core/vulnerabilities.js, 8KB head/tail scan),
//                     loaded from a real DVAA checkout through T6's bridge (captures/variants/tools/baseline.mjs).
//   t3              — SentinelProxy T3 detector core (sentinel/detectors/index.js) when it is on the branch.
// Any other detector: --detector-module <file.mjs> whose default export is (async) a harness detector.

import { existsSync, readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { REPO_ROOT, textUnits } from './corpus.mjs';

export function noopDetector() {
  return {
    name: 'noop',
    kind: 'noop',
    description: 'NO-OP baseline: allows everything, fires no rule. Sets the floor (recall 0, FP 0); it is not a detector.',
    available: true,
    provenance: { builtin: true },
    inspect: () => ({ fired: [] }),
  };
}

// The DVAA commit the baseline numbers (and T6's evadesBaseline labels) were produced against.
export const DVAA_PINNED_COMMIT = '57918267d8d529ceec6d40fc9836ab09d128eee4';

/** null when git cannot tell (not a repo); otherwise true iff `git status --porcelain` is non-empty. */
export function gitDirty(dir) {
  try {
    return execFileSync('git', ['-C', dir, 'status', '--porcelain'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim() !== '';
  } catch {
    return null;
  }
}

/**
 * Drift check for a dvaa-real baseline: returns a warning string, or null when the checkout is exactly the
 * pinned commit and clean. Unknown commit / unknown cleanliness count as drift (fail-loud, not "probably ok").
 */
export function dvaaDrift(prov) {
  if (prov?.source !== 'dvaa-real') return null;
  const problems = [];
  if (prov.dvaaCommit !== DVAA_PINNED_COMMIT) problems.push(`commit ${prov.dvaaCommit ?? 'unknown'} != pinned ${DVAA_PINNED_COMMIT}`);
  if (prov.dvaaDirty !== false) problems.push(prov.dvaaDirty ? 'checkout has uncommitted changes' : 'checkout cleanliness unknown');
  return problems.length ? `dvaa-baseline drift: ${problems.join('; ')} (baseline numbers not comparable)` : null;
}

function gitHead(dir) {
  try {
    return execFileSync('git', ['-C', dir, 'rev-parse', 'HEAD'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch {
    return null;
  }
}

/**
 * DVAA detectAttacks() baseline. Each text unit of a case (every message, the reply, every tool call) is
 * scanned on its own, the way DVAA scans each input. Rule id = `dvaa.<category>`.
 * Real DVAA only, unless allowReplica (then labeled `replica-subset` in provenance).
 */
export async function dvaaBaselineDetector({ root = REPO_ROOT, allowReplica = false } = {}) {
  const bridge = path.join(root, 'captures', 'variants', 'tools', 'baseline.mjs');
  const base = {
    name: 'dvaa-baseline',
    kind: 'baseline',
    description: "DVAA's own detectAttacks() (8KB head/tail scan), applied to every text unit of a case.",
  };
  if (!existsSync(bridge)) {
    return { ...base, available: false, unavailableReason: `T6 baseline bridge not found at ${bridge}`, provenance: {}, inspect: null };
  }
  const { loadBaseline } = await import(pathToFileURL(bridge).href);
  const b = await loadBaseline();
  if (b.source !== 'dvaa-real' && !allowReplica) {
    return {
      ...base,
      available: false,
      unavailableReason: 'no DVAA checkout found (set DVAA_SRC=<dvaa repo>); replica refused without --allow-replica',
      provenance: { source: b.source },
      inspect: null,
    };
  }
  const commit = b.root ? gitHead(b.root) : null;
  return {
    ...base,
    available: true,
    provenance: {
      source: b.source,
      dvaaCheckout: !b.root ? null : b.root === process.env.DVAA_SRC ? '$DVAA_SRC' : 'pinned T1 clone',
      dvaaCommit: commit,
      dvaaPinnedCommit: DVAA_PINNED_COMMIT,
      dvaaDirty: b.root ? gitDirty(b.root) : null,
      DETECTION_EDGE: b.DETECTION_EDGE,
    },
    inspect(c) {
      const fired = new Map();
      for (const u of textUnits(c)) {
        const r = b.detectAttacks(u.text);
        for (const cat of r.categories) {
          const ruleId = `dvaa.${cat}`;
          if (!fired.has(ruleId)) fired.set(ruleId, { ruleId, wouldBlock: true, evidence: u.where });
        }
      }
      return { fired: [...fired.values()] };
    },
  };
}

/** OpenAI-shaped response for detectors that take the wire format (T3). */
export function toOpenAIResponse(c) {
  if (!c.response) return null;
  const calls = c.response.toolCalls ?? [];
  return {
    object: 'chat.completion',
    model: c.agent?.name ?? 'replay',
    choices: [{
      index: 0,
      message: {
        role: 'assistant',
        content: c.response.content ?? '',
        ...(calls.length ? { tool_calls: calls.map((t, i) => ({ id: t.id ?? `call_${i}`, type: 'function', function: { name: t.name, arguments: t.arguments } })) } : {}),
      },
      finish_reason: calls.length ? 'tool_calls' : 'stop',
    }],
  };
}

/**
 * T3 adapter. Contract (sentinel/detectors/src/detector.js header):
 *   createDetector({ policy, honeytokens, agent }).inspect({ sessionId, request, response }) ->
 *   { action, failClosed, findings: [{ ruleId, wouldBlock, mode, disposition, ... }] }
 * One fresh detector per case so session state (taint, ledgers) never leaks across cases.
 */
export async function t3Detector({ root = REPO_ROOT, modulePath, policyPath } = {}) {
  const mod = modulePath ?? process.env.SENTINEL_T3_MODULE ?? path.join(root, 'sentinel', 'detectors', 'index.js');
  const base = { name: 't3', kind: 'candidate', description: 'SentinelProxy T3 detector core (full-payload scan).' };
  if (!existsSync(mod)) {
    return { ...base, available: false, unavailableReason: `T3 detector not present at ${path.relative(root, mod)} (T3 not merged)`, provenance: {}, inspect: null };
  }
  const t3 = await import(pathToFileURL(mod).href);
  if (typeof t3.createDetector !== 'function') {
    return { ...base, available: false, unavailableReason: `${mod} has no createDetector export`, provenance: {}, inspect: null };
  }
  const pol = policyPath ?? process.env.SENTINEL_T3_POLICY;
  // Score the rules' own verdicts in enforce; the harness applies report-only itself.
  const policy = { ...(pol ? JSON.parse(readFileSync(pol, 'utf8')) : {}), mode: 'enforce' };
  const quiet = { error: () => {}, warn: () => {} };
  return {
    ...base,
    available: true,
    provenance: { module: path.relative(root, mod), commit: gitHead(path.dirname(mod)), policy: pol ?? null },
    inspect(c) {
      const det = t3.createDetector({ policy, honeytokens: t3.DVAA_HONEYTOKENS ?? [], agent: c.agent ?? undefined, logger: quiet });
      const d = det.inspect({ sessionId: `t7:${c.id}`, agent: c.agent ?? undefined, request: c.request, response: toOpenAIResponse(c) });
      const fired = (d.findings ?? []).map((f) => ({
        ruleId: f.ruleId,
        wouldBlock: f.wouldBlock !== false,
        alwaysEnforce: d.failClosed === true,
        evidence: typeof f.evidence === 'string' ? f.evidence.slice(0, 200) : undefined,
      }));
      // Fail-closed is a real (blocking) decision by design, so it is scored, and also itemized.
      return { fired, failClosed: d.failClosed === true };
    },
  };
}

export async function moduleDetector(file) {
  const m = await import(pathToFileURL(path.resolve(file)).href);
  const det = typeof m.default === 'function' ? await m.default() : m.default;
  if (!det || typeof det.name !== 'string') throw new Error(`${file}: default export is not a harness detector`);
  return { kind: 'candidate', available: true, provenance: { module: file }, description: '', ...det };
}

export async function builtinDetectors(opts = {}) {
  return [noopDetector(), await dvaaBaselineDetector(opts), await t3Detector(opts)];
}
