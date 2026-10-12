// Deterministic replay builder: normalized capture + adapted alerts -> {timeline, graph, metrics}.
// Pure function. No clock, no randomness, no I/O. The same input always yields the same output, which
// is what "replays deterministically" means for the demo (tested by deep-equality across builds).
//
// Graph model (Falcon-style incident graph, laid out left->right in replay order):
//   lanes: input (system/user turns) | untrusted (tool results / retrieved docs) | action (tool calls)
//          | sink (egress destinations) | detection (alerts)
//   Tool-output ROWS are never nodes. A 500-row result is one node with rowCount=500 and its byte
//   size, so the node budget does not scale with data volume and nothing is dropped.
//
// Taint path (red glow) comes from the DETECTOR (T4 alert TaintPath). Each hop is resolved by
// targeted Map lookup (ToolCallId -> node), not a list scan. A hop that resolves to nothing becomes
// a visible "unresolved" node, and a T4 truncation marker becomes a visible "… N hops omitted" node.
// With no alerts, the path is derived from DVAA's dvaa{} ground truth and labeled `groundTruth`, so
// the UI never presents ground truth as a detector verdict.

import { enforce } from './bounds.mjs';

export const LANES = ['input', 'untrusted', 'action', 'sink', 'detection'];

const URL_RE = /\bhttps?:\/\/[^\s"'<>\\)]+/gi;

function byteLen(s) {
  return Buffer.byteLength(s ?? '', 'utf8');
}

function sinkDestinations(toolCall) {
  const out = new Set();
  const a = toolCall.args;
  for (const k of ['url', 'endpoint', 'webhook', 'to', 'recipient', 'destination']) {
    if (a && typeof a[k] === 'string' && a[k]) out.add(stripQuery(a[k]));
  }
  if (out.size === 0) for (const m of toolCall.argsText.matchAll(URL_RE)) out.add(stripQuery(m[0]));
  return [...out];
}

function stripQuery(u) {
  // Keep the node label readable. The full argument text stays on the tool-call node.
  const i = u.indexOf('?');
  return i === -1 ? u : u.slice(0, i);
}

/**
 * @param {{id:string, agent:{name:string}, exchanges:any[], toolResults:any[]}} capture  one run
 * @param {object[]} alerts  adapted alerts (alert-adapter.mjs)
 * @param {{canaryHits?: object[]}} [extra]  canary-listener hits recorded by T1 (vulnerable run only)
 */
export function buildReplay(capture, alerts, extra = {}) {
  const nodes = [];
  const nodeById = new Map();
  const edges = [];
  const edgeKeys = new Set();
  const timeline = [];
  const toolCallNode = new Map(); // toolCallId -> node id
  const toolCallExchange = new Map(); // toolCallId -> exchange index
  const toolResultNode = new Map(); // toolCallId -> node id
  const sinkNode = new Map(); // destination -> node id
  const warnings = [];
  let order = 0;

  const addNode = (n) => {
    if (nodeById.has(n.id)) return nodeById.get(n.id);
    enforce('MAX_GRAPH_NODES', nodes.length + 1, `capture ${capture.id}`);
    const node = { order: order++, flags: [], ...n };
    nodes.push(node);
    nodeById.set(node.id, node);
    return node;
  };
  const addEdge = (from, to, kind = 'flow') => {
    const id = `${kind}:${from}->${to}`;
    if (edgeKeys.has(id)) return id;
    edgeKeys.add(id);
    edges.push({ id, from, to, kind });
    return id;
  };
  const step = (kind, label, nodeIds, edgeIds = [], alertIds = [], detail = null) =>
    timeline.push({ step: timeline.length, kind, label, nodeIds, edgeIds, alertIds, detail });

  // ---- 1. conversation + tool activity, in recorded order ----------------------------------
  let prevInput = null;
  for (const ex of capture.exchanges) {
    for (const m of ex.messages) {
      const id = `msg:${ex.index}:${m.index}`;
      if (m.role === 'tool') {
        const n = addNode({
          id, lane: 'untrusted', kind: 'tool_result',
          label: m.recorded === false ? 'untrusted input (body not recorded)' : `tool result${m.name ? ` · ${m.name}` : ''}`,
          trust: 'untrusted', bytes: m.recorded === false ? null : byteLen(m.content), text: m.content,
          toolCallId: m.toolCallId ?? null, recorded: m.recorded !== false,
          flags: m.recorded === false ? ['not_recorded'] : [],
        });
        prevInput = n.id;
        if (m.toolCallId) {
          toolResultNode.set(m.toolCallId, n.id);
          if (toolCallNode.has(m.toolCallId)) addEdge(toolCallNode.get(m.toolCallId), n.id);
        }
        step('tool_result', n.label, [n.id]);
      } else {
        const n = addNode({
          id, lane: 'input', kind: `${m.role}_message`, label: `${m.role} turn`, trust: m.role === 'system' ? 'system' : 'user',
          bytes: byteLen(m.content), text: m.content,
        });
        const e = prevInput ? [addEdge(prevInput, n.id, 'sequence')] : [];
        prevInput = n.id;
        step('message', `${m.role} message (${n.bytes.toLocaleString('en-US')} B)`, [n.id], e);
      }
    }

    const agentId = `assistant:${ex.index}`;
    const agentNode = addNode({
      id: agentId, lane: 'action', kind: 'agent_turn', label: `${capture.agent.name} reply`,
      text: ex.assistant.content, bytes: byteLen(ex.assistant.content),
    });
    const agentEdges = prevInput ? [addEdge(prevInput, agentId)] : [];
    step('agent_turn', `${capture.agent.name} responds`, [agentId], agentEdges);

    for (const tc of ex.assistant.toolCalls) {
      const id = `call:${tc.id}`;
      const n = addNode({
        id, lane: 'action', kind: 'tool_call', label: `${tc.name}()`, toolCallId: tc.id, text: tc.argsText,
        bytes: byteLen(tc.argsText), decision: tc.decision ?? null, flags: tc.decision === 'denied' ? ['denied'] : [],
      });
      toolCallNode.set(tc.id, id);
      toolCallExchange.set(tc.id, ex.index);
      const e = [addEdge(agentId, id)];
      const sinkIds = [];
      for (const dest of sinkDestinations(tc)) {
        const sid = `sink:${dest}`;
        addNode({ id: sid, lane: 'sink', kind: 'sink', label: dest, destination: dest });
        sinkNode.set(dest, sid);
        sinkIds.push(sid);
        e.push(addEdge(id, sid, 'egress'));
      }
      step('tool_call', `${tc.name}${tc.decision ? ` [${tc.decision}]` : ''} · ${tc.argsText.length.toLocaleString('en-US')} chars of args`, [id, ...sinkIds], e);
    }
    if (ex.dvaa?.exfilTargetUrl) {
      const dest = stripQuery(ex.dvaa.exfilTargetUrl);
      if (!sinkNode.has(dest)) {
        const sid = `sink:${dest}`;
        addNode({ id: sid, lane: 'sink', kind: 'sink', label: dest, destination: dest });
        sinkNode.set(dest, sid);
      }
    }
  }

  // Explicit tool results (e.g. RAG retrievals, DB reads) recorded alongside the exchange.
  for (const tr of capture.toolResults) {
    const id = `result:${tr.index}`;
    const rowCount = tr.rows ? tr.rows.length : null;
    const text = tr.rows ? tr.rows.map(r => (typeof r === 'string' ? r : JSON.stringify(r))).join('\n') : tr.content;
    const n = addNode({
      id, lane: 'untrusted', kind: 'tool_result', label: `${tr.name} · ${tr.source}${rowCount != null ? ` (${rowCount} rows)` : ''}`,
      trust: tr.trust, source: tr.source, rowCount, bytes: byteLen(text), text, toolCallId: tr.toolCallId,
    });
    const e = [];
    if (tr.toolCallId) {
      toolResultNode.set(tr.toolCallId, id);
      if (toolCallNode.has(tr.toolCallId)) e.push(addEdge(toolCallNode.get(tr.toolCallId), id));
    }
    // A result feeds the agent turn after the one that requested it.
    const exIdx = tr.toolCallId != null && toolCallExchange.has(tr.toolCallId) ? toolCallExchange.get(tr.toolCallId) : -1;
    const next = nodeById.has(`assistant:${exIdx + 1}`) ? `assistant:${exIdx + 1}` : `assistant:${Math.max(0, exIdx)}`;
    e.push(addEdge(id, next));
    step('tool_result', `${n.label} · ${n.bytes.toLocaleString('en-US')} B`, [id], e);
  }

  // Canary hits: proof the secret actually arrived at the attacker endpoint (T1 recorded these).
  for (const [i, h] of (extra.canaryHits ?? []).entries()) {
    const id = `canary:${i}`;
    const text = JSON.stringify(h.query ?? {});
    const target = [...sinkNode.entries()].find(([dest]) => h.path && dest.endsWith(h.path))?.[1] ?? null;
    addNode({ id, lane: 'sink', kind: 'canary_hit', label: `canary hit · ${h.kind ?? 'exfil'} ${h.path ?? ''}`.trim(), text, bytes: byteLen(text), at: h.at ?? null, flags: ['exfil_received'] });
    const e = target ? [addEdge(target, id, 'egress')] : [];
    step('canary_hit', `attacker endpoint received ${byteLen(text).toLocaleString('en-US')} B (${h.path ?? '?'})`, [id], e);
  }

  // ---- 2. detector verdicts (T4 alerts) and their taint paths ---------------------------------
  const taintNodeIds = new Set();
  const taintEdgeIds = new Set();
  const maliciousNodeIds = new Set();

  const resolveHop = (hop, alert, hopIdx) => {
    if (hop.kind === 'truncated') {
      const id = `trunc:${alert.id}:${hopIdx}`;
      addNode({
        id, lane: 'untrusted', kind: 'truncation_marker',
        label: hop.omittedHops != null ? `… ${hop.omittedHops} hops omitted (T4 TaintPath cap)` : hop.label,
        omittedHops: hop.omittedHops, flags: ['truncated'],
      });
      return id;
    }
    if (hop.toolCallId) {
      // source/propagate hops refer to the data a call returned. A sink hop refers to the call itself.
      const preferResult = hop.kind !== 'sink';
      const hit = preferResult
        ? toolResultNode.get(hop.toolCallId) ?? toolCallNode.get(hop.toolCallId)
        : toolCallNode.get(hop.toolCallId) ?? toolResultNode.get(hop.toolCallId);
      if (hit) return hit;
    }
    if (hop.kind === 'source' && !hop.toolCallId) {
      // No call id: the source is the untrusted input itself (e.g. a poisoned doc delivered in the
      // request). Resolve it only when exactly one such node exists. Otherwise leave it unresolved.
      const untrusted = nodes.filter(n => n.lane === 'untrusted' && n.kind === 'tool_result');
      if (untrusted.length === 1) return untrusted[0].id;
    }
    if (hop.kind === 'sink' && alert.entities.sink?.destination) {
      const s = sinkNode.get(stripQuery(alert.entities.sink.destination));
      if (s) return s;
    }
    // Unresolved: keep it visible as a node named after the hop label.
    const id = `hop:${alert.id}:${hopIdx}`;
    addNode({
      id, lane: hop.kind === 'sink' ? 'action' : 'untrusted', kind: `unresolved_${hop.kind}`,
      label: hop.label, trust: hop.trust, toolCallId: hop.toolCallId, flags: ['unresolved'],
    });
    warnings.push(`alert ${alert.id}: taint hop ${hopIdx + 1} (${hop.label}) has no matching node in the capture; shown as unresolved`);
    return id;
  };

  for (const alert of alerts) {
    const alertNodeId = `alert:${alert.id}`;
    addNode({
      id: alertNodeId, lane: 'detection', kind: 'alert', label: `${alert.detectName} · ${alert.disposition}`,
      severity: alert.severity, severityName: alert.severityName, flags: alert.invalid ? ['invalid'] : [],
    });
    const pathNodes = alert.taintPath.map((h, i) => resolveHop(h, alert, i));
    const stepNodes = new Set([alertNodeId, ...pathNodes]);
    const stepEdges = [];
    for (let i = 1; i < pathNodes.length; i++) {
      const eid = addEdge(pathNodes[i - 1], pathNodes[i], 'taint');
      taintEdgeIds.add(eid);
      stepEdges.push(eid);
    }
    pathNodes.forEach(id => taintNodeIds.add(id));

    // Malicious node = the tool call the detector flagged (Entities.ToolCall). Resolve it by id.
    const tcId = alert.entities.toolCall?.id;
    const flagged = tcId ? toolCallNode.get(tcId) : null;
    const last = pathNodes[pathNodes.length - 1];
    const malicious = flagged ?? last ?? null;
    if (malicious) {
      maliciousNodeIds.add(malicious);
      stepNodes.add(malicious);
      // Extend the glow onto the egress destination the sink call targeted.
      const dest = alert.entities.sink?.destination ? sinkNode.get(stripQuery(alert.entities.sink.destination)) : null;
      if (dest && dest !== malicious) {
        const eid = addEdge(malicious, dest, 'taint');
        taintEdgeIds.add(eid);
        taintNodeIds.add(dest);
        stepEdges.push(eid);
        stepNodes.add(dest);
      }
      stepEdges.push(addEdge(malicious, alertNodeId, 'verdict'));
    }
    step('alert', `${alert.severityName} · ${alert.detectName} → ${alert.disposition}`, [...stepNodes], stepEdges, [alert.id], {
      latencyMs: alert.latencyMs, narrative: alert.caseCard.narrative,
    });
  }

  // ---- 3. ground-truth fallback (no detector verdicts recorded) -------------------------------
  let groundTruth = null;
  const dvaas = capture.exchanges.map(e => e.dvaa).filter(Boolean);
  if (dvaas.length) {
    const d = dvaas.find(x => x.exfilAttempted) ?? dvaas[0];
    groundTruth = {
      exfilAttempted: d.exfilAttempted === true,
      exfilExecuted: d.exfilExecuted === true,
      exfilTargetUrl: d.exfilTargetUrl ?? null,
      aim: d.aim ?? null,
    };
  }
  let groundTruthPath = null;
  if (alerts.length === 0 && groundTruth?.exfilAttempted) {
    const gtNodes = [];
    const gtEdges = [];
    const firstUntrusted = nodes.find(n => n.lane === 'untrusted') ?? nodes.find(n => n.kind === 'user_message');
    const calls = nodes.filter(n => n.kind === 'tool_call');
    const sink = groundTruth.exfilTargetUrl ? sinkNode.get(stripQuery(groundTruth.exfilTargetUrl)) : null;
    let prev = firstUntrusted?.id ?? null;
    if (prev) gtNodes.push(prev);
    for (const c of calls) {
      if (prev) gtEdges.push(addEdge(prev, c.id, 'ground_truth'));
      gtNodes.push(c.id);
      prev = c.id;
    }
    if (sink && prev) {
      gtEdges.push(addEdge(prev, sink, 'ground_truth'));
      gtNodes.push(sink);
    }
    groundTruthPath = { nodeIds: gtNodes, edgeIds: gtEdges };
    step('ground_truth', `dvaa{} ground truth: exfil ${groundTruth.exfilExecuted ? 'EXECUTED' : 'attempted'} → ${groundTruth.exfilTargetUrl ?? '?'}`, gtNodes, gtEdges);
  }

  for (const id of taintNodeIds) nodeById.get(id).flags.push('taint');
  for (const id of maliciousNodeIds) nodeById.get(id).flags.push('malicious');
  for (const e of edges) if (taintEdgeIds.has(e.id)) e.taint = true;

  return {
    graph: { nodes, edges, lanes: LANES },
    timeline,
    taint: { nodeIds: [...taintNodeIds], edgeIds: [...taintEdgeIds], maliciousNodeIds: [...maliciousNodeIds] },
    groundTruth,
    groundTruthPath,
    metrics: computeMetrics(alerts, groundTruth),
    warnings,
  };
}

/**
 * Trust score, documented formula: start at 100 and subtract the highest Severity (0-100, T4)
 * among alerts revealed so far, floor 0. A single Critical (90) leaves 10. `trustAfterStep` gives the
 * gauge value at each timeline step, so the replay animates the drop when the alert lands.
 */
export function trustScore(alerts) {
  const max = alerts.reduce((m, a) => Math.max(m, a.severity ?? 0), 0);
  return Math.max(0, 100 - max);
}

function percentile(sorted, p) {
  if (!sorted.length) return null;
  const idx = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return sorted[Math.max(0, idx)];
}

export function computeMetrics(alerts, groundTruth) {
  const lat = alerts.map(a => a.latencyMs).filter(Number.isFinite).sort((a, b) => a - b);
  return {
    alertCount: alerts.length,
    blockedCount: alerts.filter(a => a.blocked).length,
    invalidAlertCount: alerts.filter(a => a.invalid).length,
    trustScore: alerts.length ? trustScore(alerts) : null,
    aimTrustScore: groundTruth?.aim?.trustScore ?? null,
    detectionLatencyMs: { median: percentile(lat, 50), p95: percentile(lat, 95), max: lat.at(-1) ?? null, n: lat.length },
  };
}
