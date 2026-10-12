// STAND-IN detectors for T10. They are NOT the T3 detector core.
//
// They exist so a live proxy session can produce real T4 alerts before `origin/t3-detector-core`
// exists. Every verdict they return carries `standIn: true`. The pipeline copies that into
// `PipelineContext.StandIn` and marks the sidecar `placeholder: true`, so the dashboard shows its
// PLACEHOLDER banner. Delete this file's use (not the pipeline) once T3 lands. T3-shaped verdicts
// (`category` + `ruleId`) already pass through the pipeline unchanged.
//
// They follow the T2 inspector contract (sentinel/proxy/inspectors.mjs, PR #14):
//   async inspector({ phase, path, headers, body: Buffer, requestId, status? })
//     -> { flagged: true, detector, reasons: string[], ... } | null
// and they scan the FULL body. There is no head/tail window: every tool call is checked, and every
// byte of the request is searched.
//
// Rules (deliberately few, deterministic, no LLM):
//   request  standin.request.injection_phrase   override phrase anywhere in the request body
//   response standin.response.honeytoken_in_tool_args   planted honeytoken in tool-call args
//                                                       (raw or URL-decoded)
//   response standin.response.unallowlisted_egress      tool-call arg URL whose host is not on
//                                                       the egress allowlist
//   response standin.response.honeytoken_in_reply       honeytoken in the reply outside any tool call
//
// Verdicts carry ids only: honeytoken id, tool-call id/name, destination without its query string.
// The T2 proxy logs whole verdicts to stderr and to its JSONL `alert` records, so a verdict that held
// the secret or the raw tool args would leak it there. The pipeline rebuilds ArgsPreview from the
// recorded response and the canary from its config by id, and T4 redacts both.
//
// Ground truth is NEVER read here. The `dvaa{}` block in a DVAA response is the label source for
// scoring, and using it as a verdict would be cheating.

import { readFileSync } from 'node:fs';
import { performance } from 'node:perf_hooks';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BOUNDS, PipelineBoundError } from './bounds.mjs';

export const STANDIN_CONFIG_PATH = join(dirname(fileURLToPath(import.meta.url)), 'standin.config.json');

export function loadStandinConfig(path = STANDIN_CONFIG_PATH) {
  const raw = JSON.parse(readFileSync(path, 'utf8'));
  return validateStandinConfig(raw, path);
}

export function validateStandinConfig(raw, origin = 'inline') {
  const problems = [];
  const honeytokens = raw?.honeytokens ?? [];
  if (!Array.isArray(honeytokens)) problems.push('honeytokens must be an array');
  else honeytokens.forEach((h, i) => {
    if (typeof h?.id !== 'string' || !h.id) problems.push(`honeytokens[${i}].id required`);
    // Short needles would match ordinary text and flood the feed with false positives.
    if (typeof h?.value !== 'string' || h.value.length < 8) problems.push(`honeytokens[${i}].value must be a string of >= 8 chars`);
  });
  const allow = raw?.egressAllowlist ?? [];
  if (!Array.isArray(allow) || !allow.every((h) => typeof h === 'string')) problems.push('egressAllowlist must be string[] of host names');
  const patterns = raw?.injectionPatterns ?? [];
  if (!Array.isArray(patterns) || !patterns.every((p) => typeof p === 'string')) problems.push('injectionPatterns must be string[]');
  const compiled = [];
  if (Array.isArray(patterns)) for (const p of patterns) {
    try { compiled.push({ source: p, re: new RegExp(p, 'i') }); } catch (err) { problems.push(`injectionPatterns: ${err.message}`); }
  }
  if (problems.length) throw new Error(`stand-in config ${origin} invalid:\n  - ${problems.join('\n  - ')}`);
  return Object.freeze({
    honeytokens: honeytokens.map((h) => Object.freeze({ id: h.id, value: h.value })),
    egressAllowlist: new Set(allow.map((h) => h.toLowerCase())),
    injectionPatterns: compiled,
  });
}

const safeDecode = (s) => {
  try { return decodeURIComponent(s); } catch { return s; }
};

// Host-ish URL extraction. Linear: one char class, no nested quantifiers.
const URL_RE = /https?:\/\/[^\s"'<>\\]+/gi;

function hostOf(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch { return null; }
}

function stripQuery(url) {
  const i = url.search(/[?#]/);
  return i === -1 ? url : url.slice(0, i);
}

function capFindings(findings, requestId, caps) {
  if (findings.length > caps.MAX_VERDICTS_PER_EXCHANGE) {
    throw new PipelineBoundError('MAX_VERDICTS_PER_EXCHANGE', findings.length, caps.MAX_VERDICTS_PER_EXCHANGE, `stand-in findings for request ${requestId}`);
  }
}

/** Request-side stand-in. Scans the whole body for configured override phrases. */
export function standinRequestInspector(config, { caps = BOUNDS } = {}) {
  return async function standinRequest({ phase, body, requestId }) {
    if (phase !== 'request' || config.injectionPatterns.length === 0) return null;
    const t0 = performance.now();
    const text = body.toString('utf8');
    const findings = [];
    for (const { source, re } of config.injectionPatterns) {
      const m = re.exec(text);
      if (m) findings.push({
        category: 'indirect_prompt_injection',
        ruleId: 'standin.request.injection_phrase',
        evidence: `request body (${body.length} B) matches override pattern /${source}/i at char ${m.index}`,
        offset: m.index,
      });
    }
    capFindings(findings, requestId, caps);
    if (!findings.length) return null;
    const latencyMs = performance.now() - t0;
    for (const f of findings) f.latencyMs = latencyMs;
    return {
      flagged: true,
      standIn: true,
      detector: 'standin.request',
      // Client-visible (T2 publicVerdict): rule ids + offsets only, never matched text.
      reasons: findings.map((f) => `${f.ruleId} at char ${f.offset}`),
      findings,
    };
  };
}

function toolCallsOf(json) {
  const out = [];
  for (const choice of Array.isArray(json?.choices) ? json.choices : []) {
    const calls = choice?.message?.tool_calls;
    if (Array.isArray(calls)) out.push(...calls);
  }
  return out;
}

/** Response-side stand-in. Checks every tool call (no sampling), plus the reply text. */
export function standinResponseInspector(config, { caps = BOUNDS } = {}) {
  return async function standinResponse({ phase, body, requestId }) {
    if (phase !== 'response') return null;
    const t0 = performance.now();
    const text = body.toString('utf8');
    let json = null;
    try { json = JSON.parse(text); } catch { /* non-JSON reply: only the raw honeytoken scan applies */ }
    const findings = [];
    const calls = toolCallsOf(json);
    calls.forEach((tc, idx) => {
      const name = String(tc?.function?.name ?? tc?.name ?? 'unknown_tool');
      const id = String(tc?.id ?? `tool_call_${idx}`);
      const rawArgs = tc?.function?.arguments ?? tc?.arguments ?? '';
      const args = typeof rawArgs === 'string' ? rawArgs : JSON.stringify(rawArgs);
      const decoded = safeDecode(args);
      const urls = [...new Set([...(args.match(URL_RE) ?? []), ...(decoded.match(URL_RE) ?? [])])];
      const dest = urls.length ? stripQuery(urls[0]) : `tool:${name}`;
      const sinkType = urls.length ? 'http' : 'tool';
      for (const h of config.honeytokens) {
        if (args.includes(h.value) || decoded.includes(h.value)) {
          findings.push({
            category: 'honeytoken_exfil',
            ruleId: 'standin.response.honeytoken_in_tool_args',
            toolCall: { id, name },
            sink: { type: sinkType, destination: dest },
            canaryId: h.id,
            evidence: `tool call #${idx + 1} of ${calls.length} (${name}) carries honeytoken ${h.id} in its arguments`,
          });
        }
      }
      for (const u of urls) {
        const host = hostOf(u);
        if (host && !config.egressAllowlist.has(host)) {
          findings.push({
            category: 'egress_unallowlisted_domain',
            ruleId: 'standin.response.unallowlisted_egress',
            toolCall: { id, name },
            sink: { type: 'http', destination: stripQuery(u) },
            evidence: `tool call #${idx + 1} of ${calls.length} (${name}) targets non-allowlisted host ${host}`,
          });
          break; // one egress finding per tool call; the honeytoken rule above is separate
        }
      }
    });
    if (!findings.some((f) => f.category === 'honeytoken_exfil')) {
      for (const h of config.honeytokens) {
        const at = text.indexOf(h.value);
        if (at !== -1) findings.push({
          category: 'honeytoken_exfil',
          ruleId: 'standin.response.honeytoken_in_reply',
          toolCall: { id: `reply:${requestId}`, name: 'assistant_reply' },
          sink: { type: 'chat_response', destination: 'proxy client' },
          canaryId: h.id,
          evidence: `honeytoken ${h.id} appears in the agent reply at byte ${at} of ${body.length}`,
        });
      }
    }
    capFindings(findings, requestId, caps);
    if (!findings.length) return null;
    const latencyMs = performance.now() - t0;
    for (const f of findings) f.latencyMs = latencyMs;
    return {
      flagged: true,
      standIn: true,
      detector: 'standin.response',
      reasons: findings.map((f) => `${f.ruleId} (${f.toolCall.name})`),
      findings,
    };
  };
}

export function standinInspectors(config = loadStandinConfig(), opts = {}) {
  return [standinRequestInspector(config, opts), standinResponseInspector(config, opts)];
}
