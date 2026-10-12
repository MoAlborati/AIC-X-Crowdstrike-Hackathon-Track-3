// SentinelProxy T3 — detector pipeline. Pure library: no network, no LLM, no I/O except the logger.
//
//   const det = createDetector({ policy, honeytokens: DVAA_HONEYTOKENS, agent: {name:'RAGBot', port:7005} });
//   const decision = det.inspect({ sessionId, request, response });   // never throws; fails closed
//   decision.action            -> 'allow' | 'block'   (what the proxy must do now)
//   decision.findings[]        -> each one IS a T4 verdict (sentinel/alerts buildAlert input)
//
// Pipeline, in build order (BACKLOG T3):
//   0. bounds        payload/messages/tool-call caps; overflow -> fail-closed BLOCK + scan_cap_exceeded
//   1. honeytoken    exact planted-secret match (raw + URL/base64/hex-decoded) in any tool call or reply
//   2. taint         session flags A=untrusted input, B=sensitive read, C=egress; A+B then C -> block;
//                    an untrusted span (>= 8-char shingles, >= 24 contiguous chars) copied into sink args
//   3. egress        secret/PII shapes + entropy, markdown-image exfil
//   4. mandate       static policy ∩ principal-derived grant (tool | destination | amount | expiry |
//                    static_limit); destination provenance = `payee_not_confirmed`
//   5. velocity      cumulative per session+tool ledger (count, bytes, amount, structuring)
// Any exception, timeout or full registry/ledger -> fail closed: BLOCK + ALERT, logged at ERROR.

import { performance } from 'node:perf_hooks';
import { randomUUID } from 'node:crypto';
import { resolveBounds, SentinelBoundError, DetectorOverflowError, ScannerTimeoutError } from './bounds.js';
import { HoneytokenRegistry } from './honeytokens.js';
import { validatePolicy, classifyTool, effectiveMode, SINK_KINDS } from './policy.js';
import { SessionStore, deriveGrant, verifyGrant, evaluateCall, recordAndCheckLedger, callDestinations } from './mandate.js';
import {
  decodedVariants, findSecretShapes, findSsns, findCardNumbers, extractMarkdownLinks, splitUntrustedSegments,
  findInjectionPhrases, hostAllowed, lookalikeOf, extractUrls, extractEmails,
} from './text.js';

export const DECISION_SCHEMA = 'sentinel.decision/1.0.0';

// T4 categories (sentinel/alerts/mapping.js CATEGORY_MAP keys). Findings with no exact T4 category use
// the closest existing one and carry `proposedCategory` (explained in the PR; schema not forked).
export const RULES = Object.freeze({
  'honeytoken.exact_match': { category: 'honeytoken_exfil', layer: 'honeytoken' },
  'honeytoken.encoded_match': { category: 'honeytoken_exfil', layer: 'honeytoken' },
  'honeytoken.in_response_content': { category: 'honeytoken_exfil', layer: 'honeytoken' },
  'taint.untrusted_read_to_external_send': { category: 'taint_flow_exfil', layer: 'taint' },
  'taint.untrusted_span_copied_to_sink': { category: 'taint_flow_exfil', layer: 'taint' },
  'taint.instruction_in_untrusted_content': { category: 'indirect_prompt_injection', layer: 'taint' },
  'inbound.instruction_in_principal_turn': { category: 'indirect_prompt_injection', layer: 'taint' },
  'inbound.exfil_instruction': { category: 'indirect_prompt_injection', layer: 'taint' },
  'egress.secret_pattern': { category: 'egress_secret_pattern', layer: 'egress' },
  'egress.pii_pattern': { category: 'egress_secret_pattern', layer: 'egress' },
  'egress.markdown_image_exfil': { category: 'egress_markdown_image', layer: 'egress' },
  'destination.payee_not_confirmed': { category: 'egress_unallowlisted_domain', layer: 'mandate' },
  'mandate.out_of_grant': { category: 'egress_unallowlisted_domain', layer: 'mandate', proposedCategory: 'mandate_violation' },
  'policy.static_limit': { category: 'egress_unallowlisted_domain', layer: 'mandate', proposedCategory: 'tool_policy_violation' },
  'velocity.cumulative_cap': { category: 'egress_unallowlisted_domain', layer: 'velocity', proposedCategory: 'cumulative_cap_exceeded' },
  'bounds.scan_cap_exceeded': { category: 'scan_cap_exceeded', layer: 'bounds' },
  'failclosed.detector_error': { category: 'scan_cap_exceeded', layer: 'bounds', proposedCategory: 'detector_fail_closed' },
});

const STRONG_SECRET_KINDS = new Set(['private_key', 'aws_access_key', 'openai_key', 'github_token', 'slack_token', 'google_api_key', 'stripe_key', 'jwt', 'oversize_secret_like_token']);

export function createDetector(opts = {}) {
  const bounds = resolveBounds(opts.bounds);
  const policy = validatePolicy(opts.policy ?? {});
  const now = opts.now ?? Date.now;
  const logger = opts.logger ?? { error: (o) => console.error(JSON.stringify(o)), warn: (o) => console.warn(JSON.stringify(o)) };
  const registry = opts.registry ?? new HoneytokenRegistry({ maxCanaries: bounds.maxCanaries, canaryTtlMs: bounds.canaryTtlMs, now });
  for (const t of opts.honeytokens ?? []) registry.addStatic(t);
  const store = new SessionStore({ maxSessions: bounds.maxSessions, sessionTtlMs: bounds.sessionTtlMs, maxLedgerKeysPerSession: bounds.maxLedgerKeysPerSession, now });

  function inspect(input) {
    const t0 = performance.now();
    const ctx = {
      sessionId: String(input?.sessionId ?? 'unknown-session'),
      agent: input?.agent ?? opts.agent ?? null,
      t0,
      findings: [],
      layerMs: { bounds: 0, honeytoken: 0, taint: 0, egress: 0, mandate: 0, velocity: 0 },
      fired: new Set(),
      timestamp: new Date(now()).toISOString(),
    };
    try {
      return run(input, ctx);
    } catch (err) {
      return failClosed(ctx, err);
    }
  }

  /** Same as inspect(), but an oversize payload RAISES DetectorOverflowError instead of returning a block. */
  function inspectOrThrow(input) {
    const d = inspect(input);
    if (d.failClosed && d.error?.error === 'DetectorOverflowError') throw Object.assign(new DetectorOverflowError(d.error), { decision: d });
    return d;
  }

  function checkBudget(ctx, phase) {
    const el = performance.now() - ctx.t0;
    if (el > bounds.timeBudgetMs) {
      throw new ScannerTimeoutError({ bound: `timeBudgetMs (after ${phase})`, payload_size: Math.round(el), cap: bounds.timeBudgetMs, action: 'block' });
    }
  }

  function run(input, ctx) {
    // ---- 0. bounds -------------------------------------------------------------------------
    let ts = performance.now();
    const reqStr = typeof input?.request === 'string' ? input.request : JSON.stringify(input?.request ?? {});
    const resStr = input?.response == null ? '' : typeof input.response === 'string' ? input.response : JSON.stringify(input.response);
    const payloadBytes = Buffer.byteLength(reqStr) + Buffer.byteLength(resStr);
    if (payloadBytes > bounds.maxPayloadBytes) {
      throw new DetectorOverflowError({ bound: 'maxPayloadBytes', payload_size: payloadBytes, cap: bounds.maxPayloadBytes, action: 'block' });
    }
    const request = typeof input?.request === 'string' ? JSON.parse(input.request) : (input?.request ?? {});
    const response = typeof input?.response === 'string' ? JSON.parse(input.response) : (input?.response ?? null);
    const messages = Array.isArray(request.messages) ? request.messages : [];
    if (messages.length > bounds.maxMessages) {
      throw new DetectorOverflowError({ bound: 'maxMessages', payload_size: messages.length, cap: bounds.maxMessages, action: 'block' });
    }
    const respMsg = response?.choices?.[0]?.message ?? null;
    const respCalls = Array.isArray(respMsg?.tool_calls) ? respMsg.tool_calls : [];
    if (respCalls.length > bounds.maxToolCallsPerResponse) {
      throw new DetectorOverflowError({ bound: 'maxToolCallsPerResponse', payload_size: respCalls.length, cap: bounds.maxToolCallsPerResponse, action: 'block' });
    }
    if (!ctx.agent) ctx.agent = { name: String(response?.model ?? request.model ?? 'unknown-agent') };
    ctx.responseId = String(response?.id ?? `resp-${randomUUID()}`);
    const session = store.get(ctx.sessionId);
    ctx.layerMs.bounds += performance.now() - ts;

    // ---- history: principal text, untrusted sources, prior tool calls ----------------------
    ts = performance.now();
    const principal = [];
    const untrusted = []; // {label, text, toolCallId?, kind}
    const flags = { untrustedInput: false, sensitiveRead: false, egress: false };
    const path = { sources: [], propagate: [] };
    const histNames = new Map();
    messages.forEach((m, i) => {
      const role = m?.role;
      const text = contentText(m?.content);
      if (role === 'user' || role === 'system' || role === 'developer') {
        const { trusted, untrusted: segs } = splitUntrustedSegments(text);
        principal.push({ i, role, text: trusted });
        for (const s of segs) {
          const label = `${role} turn #${i} embedded "${s.label}" block (untrusted)`;
          untrusted.push({ label, text: s.text, kind: 'segment' });
          flags.untrustedInput = true;
          path.sources.push({ kind: 'source', label, trust: 'untrusted' });
        }
      } else if (role === 'assistant' && Array.isArray(m.tool_calls)) {
        for (const tc of m.tool_calls) {
          const name = tc?.function?.name ?? 'unknown_tool';
          const args = parseArgs(tc?.function?.arguments);
          histNames.set(tc?.id, { name, args });
          const kind = classifyTool(name, args, policy);
          if (kind === 'sensitive_read') {
            flags.sensitiveRead = true;
            path.propagate.push({ kind: 'propagate', label: `${name}(${preview(args)}) (sensitive read, earlier turn)`, toolCallId: tc?.id, trust: 'sensitive' });
          }
          if (SINK_KINDS.has(kind)) flags.egress = true;
        }
      } else if (role === 'tool' || role === 'function') {
        const h = histNames.get(m.tool_call_id) ?? { name: m.name ?? 'unknown_tool', args: {} };
        const kind = classifyTool(h.name, h.args, policy);
        const label = `${h.name} result (msg #${i})`;
        untrusted.push({ label: `${label} (untrusted tool output)`, text, toolCallId: m.tool_call_id, kind: 'tool_output' });
        if (kind === 'untrusted_source') {
          flags.untrustedInput = true;
          path.sources.push({ kind: 'source', label: `${h.name}(${preview(h.args)}) (untrusted)`, toolCallId: m.tool_call_id, trust: 'untrusted' });
        }
        if (kind === 'sensitive_read' || registry.scan(text).length) {
          flags.sensitiveRead = true;
          path.propagate.push({ kind: 'propagate', label: `${label} (sensitive data)`, toolCallId: m.tool_call_id, trust: 'sensitive' });
        }
      }
    });
    // Inbound screening (full payload, every message): instruction-like phrases in untrusted text, and in
    // principal turns themselves (benchmarks and DVAA paste retrieved content into the user role). A
    // principal turn carrying injection phrases is SUSPECT: it cannot widen the mandate (ambiguity ->
    // narrower), so destinations named only there stay unconfirmed.
    const inboundTexts = [
      ...untrusted.map((u) => ({ label: u.label, text: u.text, toolCallId: u.toolCallId, principal: false })),
      ...principal.map((p) => ({ label: `${p.role} turn #${p.i}`, text: p.text, principal: true, ref: p })),
    ];
    for (const u of inboundTexts) {
      const phrases = findInjectionPhrases(u.text);
      if (!phrases.length) continue;
      if (u.principal) u.ref.suspect = true;
      if (!flags.untrustedInput) path.sources.push({ kind: 'source', label: `${u.label}${u.principal ? ' (instruction-bearing, treated as untrusted)' : ''}`, toolCallId: u.toolCallId, trust: 'untrusted' });
      flags.untrustedInput = true;
      const dests = [...extractUrls(u.text).map((x) => x.host), ...extractEmails(u.text).map((x) => x.email)];
      const tokensHit = registry.scan(u.text).map((h) => h.entry.id);
      const exfil = dests.length > 0 || tokensHit.length > 0;
      const action = exfil ? policy.inbound.exfilInstruction : policy.inbound.injection;
      push(ctx, {
        ruleId: exfil ? 'inbound.exfil_instruction' : u.principal ? 'inbound.instruction_in_principal_turn' : 'taint.instruction_in_untrusted_content',
        action,
        mode: policy.mode,
        evidence:
          `instruction-like phrases in ${u.label} (${u.text.length} chars, full scan): ${phrases.slice(0, 5).map((p) => `"${p}"`).join(', ')}` +
          (dests.length ? `; names destination(s) ${[...new Set(dests)].slice(0, 5).join(', ')}` : '') +
          (tokensHit.length ? `; carries honeytoken(s) ${tokensHit.slice(0, 5).join(', ')}` : ''),
        originatedIn: u.label,
        reason: exfil ? 'exfil_instruction_inbound' : 'instruction_in_untrusted_content',
      });
    }
    const principalText = principal.filter((p) => !p.suspect).map((p) => p.text).join('\n');
    const shingles = buildShingleIndex(untrusted, bounds.shingleChars);
    ctx.layerMs.taint += performance.now() - ts;
    checkBudget(ctx, 'history');

    // ---- mandate grant (principal-only), verified before use ----------------------------------
    ts = performance.now();
    session.grant = deriveGrant({ principalText, policy, session, maxGrantEntries: bounds.maxGrantEntries, now: now() });
    if (!verifyGrant(session.grant, session.key)) throw new Error('mandate grant failed HMAC verification');
    const grant = session.grant;
    ctx.layerMs.mandate += performance.now() - ts;

    // ---- response tool calls, in order --------------------------------------------------------
    const blocked = new Set();
    for (const tc of respCalls) {
      const name = String(tc?.function?.name ?? 'unknown_tool');
      const rawArgs = typeof tc?.function?.arguments === 'string' ? tc.function.arguments : JSON.stringify(tc?.function?.arguments ?? {});
      const args = parseArgs(rawArgs);
      const kind = classifyTool(name, args, policy);
      const call = { id: String(tc?.id ?? `call-${randomUUID()}`), name, args, rawArgs, argBytes: Buffer.byteLength(rawArgs), kind, destinations: callDestinations(args) };
      const mode = effectiveMode(policy, name);
      const isSink = SINK_KINDS.has(kind);
      const sinkEnt = sinkEntity(call, isSink);
      const callLabel = `${name}(${preview(args)})`;

      ts = performance.now();
      if (kind === 'untrusted_source') {
        flags.untrustedInput = true;
        path.sources.push({ kind: 'source', label: `${callLabel} (untrusted)`, toolCallId: call.id, trust: 'untrusted' });
      }
      if (kind === 'sensitive_read') {
        flags.sensitiveRead = true;
        path.propagate.push({ kind: 'propagate', label: `${callLabel} (sensitive read)`, toolCallId: call.id, trust: 'sensitive' });
      }
      if (isSink) flags.egress = true;
      ctx.layerMs.taint += performance.now() - ts;

      const variants = decodedVariants(rawArgs, { depth: bounds.maxDecodeDepth, minRun: bounds.minEncodedRunChars });
      checkBudget(ctx, `decode ${name}`);
      const sinkHop = { kind: 'sink', label: `${callLabel} → ${sinkEnt.destination}`, toolCallId: call.id, trust: isSink ? 'external' : 'internal' };
      const taintPath = () => [...path.sources.slice(0, 4), ...path.propagate.slice(0, 8), sinkHop];

      // 1. honeytoken -------------------------------------------------------------------------
      ts = performance.now();
      const seenTokens = new Set();
      for (const v of variants) {
        for (const { entry } of registry.scan(v.text)) {
          if (seenTokens.has(entry.value)) continue;
          seenTokens.add(entry.value);
          push(ctx, {
            ruleId: v.encoding === 'raw' ? 'honeytoken.exact_match' : 'honeytoken.encoded_match',
            action: 'block',
            mode,
            call, sinkEnt, taintPath: taintPath(),
            canary: { id: entry.id, value: entry.value },
            evidence: `${name} arguments carried honeytoken ${entry.id} (${entry.label})${v.encoding === 'raw' ? '' : ` in ${v.encoding}-encoded form`}`,
            originatedIn: entry.kind === 'static' ? `planted secret ${entry.id}` : `${entry.kind} ${entry.id} minted for session ${entry.session} via ${entry.tool}`,
            canarySession: entry.session,
            reason: 'honeytoken_crossed_egress',
          });
          blocked.add(call.id);
        }
      }
      ctx.layerMs.honeytoken += performance.now() - ts;

      // 2. taint -------------------------------------------------------------------------------
      ts = performance.now();
      if (isSink && flags.untrustedInput && flags.sensitiveRead) {
        push(ctx, {
          ruleId: 'taint.untrusted_read_to_external_send', action: 'block', mode, call, sinkEnt, taintPath: taintPath(),
          evidence: `session saw untrusted input (A) and a sensitive read (B) before ${kind} call ${name} (C)`,
          originatedIn: path.sources[0]?.label, reason: 'source_to_sink_flow',
        });
        blocked.add(call.id);
      }
      if (isSink && shingles.index.size) {
        const span = copiedSpan(rawArgs, shingles, bounds, principalText);
        if (span) {
          const unconfirmed = call.destinations.some((d) => !destOk(d, grant, policy, name));
          const hard = (flags.untrustedInput && flags.sensitiveRead) || unconfirmed;
          push(ctx, {
            ruleId: 'taint.untrusted_span_copied_to_sink', action: hard ? 'block' : 'alert', mode, call, sinkEnt, taintPath: taintPath(),
            evidence: `${span.length}-char span from ${span.source} copied into ${name} arguments`,
            originatedIn: span.source, reason: 'untrusted_span_in_sink',
          });
          if (hard) blocked.add(call.id);
        }
      }
      ctx.layerMs.taint += performance.now() - ts;

      // 3. egress shapes -------------------------------------------------------------------------
      ts = performance.now();
      if (isSink || call.destinations.length) {
        const shapes = [];
        for (const v of variants) {
          for (const s of findSecretShapes(v.text, { maxTokenChars: bounds.maxTokenChars })) shapes.push({ ...s, encoding: v.encoding });
          for (const s of findSsns(v.text)) shapes.push({ ...s, encoding: v.encoding });
          for (const s of findCardNumbers(v.text)) shapes.push({ ...s, encoding: v.encoding });
        }
        const kinds = [...new Set(shapes.map((s) => s.kind))];
        if (kinds.length) {
          const strong = kinds.some((k) => STRONG_SECRET_KINDS.has(k));
          const pii = kinds.every((k) => k === 'ssn' || k === 'card_number');
          const hard = strong || (flags.untrustedInput && !pii) || (flags.untrustedInput && pii && isSink);
          push(ctx, {
            ruleId: pii ? 'egress.pii_pattern' : 'egress.secret_pattern', action: hard ? 'block' : 'alert', mode, call, sinkEnt, taintPath: taintPath(),
            evidence: `${name} arguments contain ${kinds.join(', ')} (${shapes.length} match${shapes.length === 1 ? '' : 'es'})`,
            originatedIn: path.sources[0]?.label, reason: pii ? 'pii_in_egress' : 'secret_in_egress',
          });
          if (hard) blocked.add(call.id);
        }
      }
      ctx.layerMs.egress += performance.now() - ts;
      checkBudget(ctx, `egress ${name}`);

      // 4. mandate / destination provenance / static policy ---------------------------------------
      ts = performance.now();
      for (const v of evaluateCall({ call, kind, grant, policy, now: now() })) {
        let ruleId = v.dimension === 'destination' ? 'destination.payee_not_confirmed' : v.dimension === 'static_limit' ? 'policy.static_limit' : 'mandate.out_of_grant';
        const tp = policy.tools[name] ?? {};
        const action = tp.onViolation === 'alert' ? 'alert' : tp.onViolation === 'hold' ? 'hold' : 'block';
        let evidence = `${v.dimension}: ${v.detail}`;
        let originatedIn = path.sources[0]?.label ?? 'no principal turn named it';
        if (v.destination) {
          // Provenance of the destination(s): which untrusted text names them (first 10 checked; bounded).
          for (const dd of v.destinations.slice(0, 10)) {
            const inUntrusted = untrusted.find((u) => u.text.includes(dd.destination));
            if (inUntrusted) {
              originatedIn = inUntrusted.label;
              evidence += `; ${dd.destination} appears only in ${inUntrusted.label}`;
              break;
            }
          }
          const trustedHosts = [...policy.allowlist.hosts, ...grant.destinations];
          for (const dd of v.destinations.slice(0, 10)) {
            const near = lookalikeOf(dd.destination, trustedHosts);
            if (near) {
              evidence += `; ${dd.destination} is a lookalike of trusted destination ${near}`;
              break;
            }
          }
        }
        push(ctx, {
          ruleId, action, mode, call, sinkEnt: v.destination ? { type: v.destination.type, destination: v.destination.url ?? v.destination.destination } : sinkEnt,
          taintPath: taintPath(), evidence, originatedIn, reason: v.reason, dimension: v.dimension,
        });
        if (action !== 'alert') blocked.add(call.id);
      }
      ctx.layerMs.mandate += performance.now() - ts;

      // 5. velocity -------------------------------------------------------------------------------
      ts = performance.now();
      for (const v of recordAndCheckLedger({ store, session, call, policy })) {
        push(ctx, {
          ruleId: 'velocity.cumulative_cap', action: 'hold', mode, call, sinkEnt, taintPath: taintPath(),
          evidence: v.detail, originatedIn: path.sources[0]?.label, reason: v.reason, dimension: v.dimension,
        });
        blocked.add(call.id);
      }
      ctx.layerMs.velocity += performance.now() - ts;
    }

    // ---- assistant reply content as a sink ---------------------------------------------------------
    const content = contentText(respMsg?.content);
    if (content) {
      ts = performance.now();
      const contentCall = { id: `${ctx.responseId}#content`, name: 'assistant_response', rawArgs: content, args: {} };
      const contentSink = { type: 'chat_response', destination: 'client (assistant reply)' };
      const hop = { kind: 'sink', label: 'assistant reply → client', toolCallId: contentCall.id, trust: 'external' };
      const seen = new Set();
      for (const v of decodedVariants(content, { depth: bounds.maxDecodeDepth, minRun: bounds.minEncodedRunChars })) {
        for (const { entry } of registry.scan(v.text)) {
          if (seen.has(entry.value)) continue;
          seen.add(entry.value);
          push(ctx, {
            ruleId: 'honeytoken.in_response_content', action: policy.sinks.assistant_content.honeytoken === 'alert' ? 'alert' : 'block', mode: policy.mode,
            call: contentCall, sinkEnt: contentSink, taintPath: [...path.sources.slice(0, 4), ...path.propagate.slice(0, 8), hop],
            canary: { id: entry.id, value: entry.value }, evidence: `assistant reply disclosed honeytoken ${entry.id} (${entry.label})`,
            originatedIn: entry.kind === 'static' ? `planted secret ${entry.id}` : `${entry.kind} ${entry.id} for session ${entry.session} via ${entry.tool}`,
            reason: 'honeytoken_in_reply',
          });
        }
      }
      ctx.layerMs.honeytoken += performance.now() - ts;
      ts = performance.now();
      for (const link of extractMarkdownLinks(content)) {
        if (!link.isImage || !link.host) continue;
        const trusted = hostAllowed(link.host, policy.allowlist.hosts) || grant.destinations.includes(link.host);
        const carriesData = link.url.includes('?') || link.url.length > 200 || registry.scan(link.url).length > 0;
        if (!trusted && carriesData) {
          push(ctx, {
            ruleId: 'egress.markdown_image_exfil', action: 'block', mode: policy.mode, call: { ...contentCall, rawArgs: link.url },
            sinkEnt: { type: 'markdown_image', destination: link.url }, taintPath: [...path.sources.slice(0, 4), { ...hop, label: `markdown image → ${link.host}` }],
            evidence: `reply renders an image from non-allowlisted ${link.host} with data in the URL (zero-click exfil, EchoLeak pattern)`,
            originatedIn: path.sources[0]?.label, reason: 'markdown_image_exfil',
          });
        }
      }
      ctx.layerMs.egress += performance.now() - ts;
    }
    checkBudget(ctx, 'complete');
    return finish(ctx, { payloadBytes, flags, blocked, respCalls: respCalls.length, failClosed: false, grant });
  }

  // ---- finding construction (T4 verdict shape) --------------------------------------------------
  function push(ctx, f) {
    const rule = RULES[f.ruleId];
    const enforced = f.action !== 'alert';
    const disposition = !enforced ? 'allow' : f.mode === 'report-only' ? 'report' : 'block';
    ctx.fired.add(f.ruleId);
    const entities = {
      agent: ctx.agent,
      session: { id: ctx.sessionId },
    };
    if (f.call) entities.toolCall = { id: f.call.id, name: f.call.name, argsPreview: String(f.call.rawArgs ?? '').slice(0, 512) };
    if (f.sinkEnt) entities.sink = f.sinkEnt;
    const decided = f.ruleId;
    const narrative =
      `Instruction/data originated in ${f.originatedIn ?? 'an unattributed source'}` +
      (f.call ? ` → influenced ${f.call.name}(${preview(f.call.args)})` : '') +
      (f.sinkEnt ? ` toward ${f.sinkEnt.destination}` : '') +
      ` → ${disposition === 'block' ? 'blocked' : disposition === 'report' ? 'would be blocked (report-only)' : 'alerted'} by ${f.reason ?? decided}` +
      ` in session ${ctx.sessionId}${f.canarySession && f.canarySession !== ctx.sessionId ? ` (canary belongs to session ${f.canarySession})` : ''}.`;
    const finding = {
      category: rule.category,
      ruleId: f.ruleId,
      disposition,
      detectionLatencyMs: 0, // set in finish()
      timestamp: ctx.timestamp,
      entities,
      ...(f.taintPath ? { taintPath: f.taintPath } : {}),
      ...(f.canary ? { canary: f.canary } : {}),
      evidence: f.evidence,
      caseCard: { originatedIn: f.originatedIn ?? null, influencedToolCall: f.call ? `${f.call.name}#${f.call.id}` : null, decidedByRule: decided, narrative },
      // T3 extras (ignored by T4's validator; consumed by T5/T7):
      reason: f.reason ?? null,
      dimension: f.dimension ?? null,
      enforcement: f.action, // block | hold | alert  (hold -> DENY until S5 approval exists)
      wouldBlock: enforced,
      mode: f.mode,
      ...(rule.proposedCategory ? { proposedCategory: rule.proposedCategory } : {}),
    };
    ctx.findings.push(finding);
  }

  function finish(ctx, { payloadBytes, flags, blocked, respCalls, failClosed, error, grant }) {
    const latency = round(performance.now() - ctx.t0);
    const layers = Object.entries(ctx.layerMs).map(([layer, ms]) => ({
      layer,
      rule: [...ctx.fired].find((r) => RULES[r].layer === layer) ?? `${layer}.none`,
      fired: [...ctx.fired].some((r) => RULES[r].layer === layer),
      latencyMs: round(ms),
    }));
    // Every honeytoken that fired in this decision, so T4 redacts it anywhere in any alert (argsPreview,
    // evidence). Bounded by the number of findings, independent of registry size.
    const hitCanaries = [...new Map(ctx.findings.filter((f) => f.canary).map((f) => [f.canary.value, f.canary])).values()];
    for (const f of ctx.findings) {
      f.detectionLatencyMs = latency;
      f.layers = layers;
      if (hitCanaries.length) f.canaries = hitCanaries;
    }
    const block = ctx.findings.some((f) => f.disposition === 'block');
    const wouldBlock = ctx.findings.some((f) => f.wouldBlock);
    return {
      schema: DECISION_SCHEMA,
      sessionId: ctx.sessionId,
      agent: ctx.agent,
      timestamp: ctx.timestamp,
      mode: policy.mode,
      action: block ? 'block' : 'allow',
      wouldAction: wouldBlock ? 'block' : 'allow',
      failClosed,
      ...(error ? { error } : {}),
      blockedToolCallIds: [...(blocked ?? [])],
      findings: ctx.findings,
      taint: flags ?? null,
      grant: grant ? { tools: grant.tools, destinations: grant.destinations, maxAmount: grant.maxAmount, expires: grant.expires, template: grant.template } : null,
      stats: { payloadBytes: payloadBytes ?? null, toolCalls: respCalls ?? 0, latencyMs: latency, layers },
    };
  }

  function failClosed(ctx, err) {
    const isBound = err instanceof SentinelBoundError;
    const details = isBound ? err.toJSON() : { error: err?.name ?? 'Error', bound: null, payload_size: null, cap: null, action: 'block', message: String(err?.message ?? err).slice(0, 500) };
    logger.error({ level: 'ERROR', event: 'sentinel.detector.fail_closed', sessionId: ctx.sessionId, ...details });
    if (!ctx.agent) ctx.agent = { name: 'unknown-agent' };
    const ruleId = err instanceof DetectorOverflowError ? 'bounds.scan_cap_exceeded' : 'failclosed.detector_error';
    ctx.findings = [];
    ctx.fired = new Set([ruleId]);
    push(ctx, {
      ruleId,
      action: 'block',
      mode: 'enforce', // dead-man switch: fail-closed blocks even in report-only mode
      evidence: isBound
        ? `${details.error}: ${details.bound} payload_size=${details.payload_size} cap=${details.cap} action=${details.action} — payload refused in full, never truncated`
        : `detector error (${details.error}): ${details.message} — egress denied (fail-closed)`,
      originatedIn: 'detector bounds',
      reason: isBound ? details.error : 'detector_error',
    });
    return finish(ctx, { payloadBytes: isBound && details.bound === 'maxPayloadBytes' ? details.payload_size : null, failClosed: true, error: details });
  }

  return {
    inspect,
    inspectOrThrow,
    registry,
    sessions: store,
    policy,
    bounds,
    mintCanary: (session, tool, kind) => registry.mintCanary(session, tool, kind),
    seedRecords: (session, tool, n) => registry.seedRecords(session, tool, n),
  };
}

// ---- helpers -------------------------------------------------------------------------------------

function contentText(c) {
  if (typeof c === 'string') return c;
  if (Array.isArray(c)) return c.map((p) => (typeof p === 'string' ? p : typeof p?.text === 'string' ? p.text : '')).join('\n');
  return '';
}

function parseArgs(raw) {
  if (raw && typeof raw === 'object') return raw;
  if (typeof raw !== 'string' || raw.length === 0) return {};
  try {
    const v = JSON.parse(raw);
    return v && typeof v === 'object' ? v : { _raw: raw };
  } catch {
    return { _raw: raw }; // malformed args are still scanned as a raw string
  }
}

// Short human label for a call's args. Never serializes the whole args object (it can be ~1 MiB and is
// rendered once per finding): only the first two keys, each value cut to 60 chars.
function preview(args) {
  if (!args || typeof args !== 'object') return '';
  const parts = [];
  for (const k in args) {
    if (parts.length === 2) break;
    const v = args[k];
    const sv = typeof v === 'string' ? v : v && typeof v === 'object' ? (Array.isArray(v) ? `[${v.length} items]` : '{…}') : String(v);
    parts.push(`${k}=${sv.length > 60 ? `${sv.slice(0, 60)}…` : sv}`);
  }
  return parts.join(', ');
}

function sinkEntity(call, isSink) {
  const d = call.destinations[0];
  if (d) return { type: d.type, destination: d.url ?? d.destination };
  const t = call.kind === 'exec' ? 'shell' : call.kind === 'write' ? 'filesystem' : isSink ? 'tool' : 'tool';
  return { type: t, destination: `${call.name} (no network destination)` };
}

function destOk(d, grant, policy, toolName) {
  const hosts = [...policy.allowlist.hosts, ...(policy.tools[toolName]?.allowlist ?? [])];
  if (d.type === 'email') return policy.allowlist.emails.includes(d.destination) || grant.destinations.includes(d.destination);
  return hostAllowed(d.destination, hosts) || grant.destinations.includes(d.destination);
}

/**
 * Index untrusted text by `k`-char shingles at every k-th position (winnowing-style). A copied span
 * of >= 3k chars always contains >= 2 aligned shingles, so sampling loses nothing at the hit
 * threshold while keeping the index at |untrusted|/k entries.
 */
function buildShingleIndex(untrusted, k) {
  const index = new Map();
  const parts = [];
  let offset = 0;
  const sources = [];
  for (const u of untrusted) {
    parts.push(u.text);
    sources.push({ start: offset, end: offset + u.text.length, label: u.label });
    offset += u.text.length + 1;
  }
  const text = parts.join('\u0000');
  for (let i = 0; i + k <= text.length; i += k) {
    const sh = text.substr(i, k);
    if (sh.includes('\u0000')) continue;
    if (!index.has(sh)) index.set(sh, i);
  }
  return { index, text, sources, k };
}

/** Longest contiguous span (>= minCopiedSpanChars) of `sinkText` copied from untrusted text, not present in principal text. */
function copiedSpan(sinkText, sh, bounds, principalText) {
  const { index, text, k } = sh;
  const variants = [sinkText];
  // URL-encoded copies are still copies.
  if (sinkText.includes('%')) variants.push(decodeSafe(sinkText));
  let best = null;
  for (const s of variants) {
    for (let p = 0; p + k <= s.length; p++) {
      const q = index.get(s.substr(p, k));
      if (q === undefined) continue;
      // extend right and left from the aligned match (bounded by both strings)
      let r = 0;
      while (p + r < s.length && q + r < text.length && s[p + r] === text[q + r] && text[q + r] !== '\u0000') r++;
      let l = 0;
      while (p - l - 1 >= 0 && q - l - 1 >= 0 && s[p - l - 1] === text[q - l - 1] && text[q - l - 1] !== '\u0000') l++;
      const len = l + r;
      if (len >= bounds.minCopiedSpanChars && (!best || len > best.length)) {
        const span = s.substr(p - l, Math.min(len, 256));
        if (!principalText.includes(span)) {
          const src = sh.sources.find((x) => q >= x.start && q < x.end);
          best = { length: len, source: src?.label ?? 'untrusted content', text: span };
        }
      }
      p += Math.max(0, r - 1); // skip past the matched run: keeps the scan linear
    }
  }
  return best;
}

function decodeSafe(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

const round = (x) => Math.round(x * 1000) / 1000;
