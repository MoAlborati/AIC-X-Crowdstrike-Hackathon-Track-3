// Real seam: REAL T2 proxy (PR #14 createProxy) -> REAL HTTP upstream replaying recorded DVAA content
// -> PipelineSink -> T4 buildAlert -> files. Assertions use the REAL T4 validateAlert.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { readFileSync } from 'node:fs';
import { validateAlert } from '../../alerts/index.js';
import { createPipeline } from '../pipeline.mjs';
import { PipelineSink } from '../sink.mjs';
import { standinInspectors, loadStandinConfig, validateStandinConfig } from '../standin.mjs';
import {
  importProxy, startUpstream, proxyConfig, post, tmp, evasionRequest, benignRequest, benignResponse, exfilResponse,
  readSidecars, readCaptures, allAlerts, silentLog,
} from './helpers.mjs';

const STANDIN = loadStandinConfig();
const HONEY = STANDIN.honeytokens.map((h) => h.value);

/** Run requests through the real proxy with the pipeline sink. Returns statuses + output dir. */
async function session({ mode, respond, requests, inspectors = standinInspectors(STANDIN), caps, maxRequestBytes, headers }) {
  const { createProxy, JsonlCaptureSink } = await importProxy();
  const dir = await tmp();
  const outDir = path.join(dir, 'out');
  const capturePath = path.join(dir, 'proxy.jsonl');
  const up = await startUpstream(respond);
  const log = silentLog();
  const statuses = [];
  let pipeline;
  try {
    pipeline = createPipeline({ outDir, caps, log, canaries: STANDIN.honeytokens.map((h) => ({ ...h })), proxyCapturePath: capturePath });
    await pipeline.init();
    const config = proxyConfig({ upstreamPort: up.port, mode, capturePath, maxRequestBytes });
    const proxy = createProxy(config, { sink: new PipelineSink(new JsonlCaptureSink(config.capture), pipeline), inspectors, logAlert: () => {} });
    const { port } = await proxy.listen();
    try {
      for (const r of requests) statuses.push(await post(port, r, headers));
    } finally {
      await proxy.close();
    }
  } finally {
    await up.close();
  }
  return { outDir, capturePath, statuses, upstreamHits: up.hits, log, stats: pipeline.stats() };
}

const assertValid = (alerts) => {
  for (const a of alerts) assert.deepEqual(validateAlert(a), [], `T4 validateAlert on ${a.AlertId}`);
};

test('request-side: >8KB request with mid-body injection, block mode -> 403, Blocked, labeled blocking + stand-in', async () => {
  const req = evasionRequest();
  const s = await session({ mode: 'block', respond: () => ({ json: exfilResponse() }), requests: [req] });
  assert.equal(s.statuses[0].status, 403);
  assert.equal(s.upstreamHits.length, 0, 'blocked before the agent ran');
  const alerts = allAlerts(s.outDir);
  assertValid(alerts);
  assert.ok(alerts.length >= 1);
  for (const a of alerts) {
    assert.equal(a.PipelineContext.Direction, 'request');
    assert.equal(a.PipelineContext.Enforcement, 'blocking');
    assert.equal(a.PipelineContext.Outcome, 'blocked_before_agent');
    assert.equal(a.PatternDispositionDescription, 'Blocked');
    assert.equal(a.PipelineContext.StandIn, true);
    assert.equal(a.Category, 'indirect_prompt_injection');
    assert.match(a.CaseCard.Narrative, /^\[request-side · blocking\]/);
  }
  // Signal is past the first 8 KB: a head-window scan would have missed it.
  const offset = Number(alerts[0].Evidence.match(/at char (\d+)/)[1]);
  assert.ok(offset > 8192, `signal offset ${offset} should be beyond 8KB`);
  assert.ok(JSON.stringify(req).length > 16 * 1024);
  const [side] = readSidecars(s.outDir);
  assert.equal(side.doc.placeholder, true, 'stand-in sidecar shows the PLACEHOLDER banner');
  assert.match(side.doc.note, /STAND-IN/);
});

test('response-side: exfil tool call in reply, block mode -> alert-only ReportOnly even though the proxy withheld the reply', async () => {
  const s = await session({ mode: 'block', respond: () => ({ json: exfilResponse() }), requests: [benignRequest()] });
  assert.equal(s.upstreamHits.length, 1, 'agent ran (tool executed in-process)');
  assert.equal(s.statuses[0].status, 403, 'T2 withholds a flagged reply in block mode');
  const alerts = allAlerts(s.outDir);
  assertValid(alerts);
  const cats = alerts.map((a) => a.Category).sort();
  assert.deepEqual(cats, ['egress_unallowlisted_domain', 'honeytoken_exfil', 'honeytoken_exfil'].sort(),
    'admin secret + fake SSN honeytokens, plus non-allowlisted host');
  for (const a of alerts) {
    assert.equal(a.PipelineContext.Direction, 'response');
    assert.equal(a.PipelineContext.Enforcement, 'alert_only');
    assert.equal(a.PatternDispositionDescription, 'ReportOnly', 'response-side is never Blocked');
    assert.equal(a.PatternDispositionFlags.Blocked, false);
    assert.equal(a.PipelineContext.Outcome, 'reply_withheld_tool_already_executed');
    assert.match(a.CaseCard.Narrative, /response-side · alert_only/);
    assert.match(a.CaseCard.Narrative, /executes tools in-process before replying/);
    assert.equal(a.Entities.ToolCall.Name, 'submit_to_index');
    assert.equal(a.Entities.Sink.Destination, 'http://127.0.0.1:40447/api/canary/exfil-test');
    assert.match(a.Entities.ToolCall.ArgsPreview, /canary\/exfil-test/, 'ArgsPreview rebuilt from the recorded reply');
    assert.ok(a.Redactions.Count > 0, 'honeytokens in ArgsPreview were redacted by T4');
  }
  // Honeytoken values never appear in the sidecar (T4 redaction), even though args carried them.
  const sideText = readFileSync(path.join(s.outDir, 'alerts', readSidecars(s.outDir)[0].file), 'utf8');
  for (const v of HONEY) assert.ok(!sideText.includes(v), `sidecar leaks ${v}`);
});

test('observe mode: request-side would-block is ReportOnly; response-side alert-only; both directions in one capture', async () => {
  const s = await session({ mode: 'observe', respond: () => ({ json: exfilResponse() }), requests: [evasionRequest()] });
  assert.equal(s.statuses[0].status, 200);
  const alerts = allAlerts(s.outDir);
  assertValid(alerts);
  const req = alerts.filter((a) => a.PipelineContext.Direction === 'request');
  const res = alerts.filter((a) => a.PipelineContext.Direction === 'response');
  assert.ok(req.length >= 1 && res.length >= 1);
  for (const a of req) {
    assert.equal(a.PatternDispositionDescription, 'ReportOnly');
    assert.equal(a.PipelineContext.Outcome, 'would_block_observe_only');
    assert.equal(a.PipelineContext.Enforcement, 'blocking');
  }
  for (const a of res) assert.equal(a.PipelineContext.Outcome, 'reply_delivered_tool_already_executed');
  const [side] = readSidecars(s.outDir);
  assert.deepEqual(side.doc.pipeline.byDirection, { request: req.length, response: res.length });
  const [cap] = readCaptures(s.outDir);
  assert.equal(cap.doc.exchanges.length, 1);
  assert.equal(cap.doc.exchanges[0].response.dvaa.exfilExecuted, true, 'dvaa{} ground truth kept for display, never used as a verdict');
});

test('data-rich response: 300 tool calls, exfil is call #250 -> alerts name exactly that call', async () => {
  const resp = exfilResponse({ extraCalls: 299, exfilAt: 249 });
  assert.equal(resp.choices[0].message.tool_calls.length, 300);
  const s = await session({ mode: 'observe', respond: () => ({ json: resp }), requests: [benignRequest()] });
  const alerts = allAlerts(s.outDir);
  assertValid(alerts);
  assert.equal(alerts.length, 3);
  for (const a of alerts) {
    assert.equal(a.Entities.ToolCall.Id, resp.choices[0].message.tool_calls[249].id);
    if (a.Category !== 'egress_unallowlisted_domain') assert.match(a.Evidence, /tool call #250 of 300/);
  }
});

test('data-rich session: 250 exchanges rotate into 3 parts, every exchange and alert kept', async () => {
  let i = 0;
  const s = await session({
    mode: 'observe',
    respond: () => ({ json: (i++ % 2 === 0) ? exfilResponse() : benignResponse() }),
    requests: Array.from({ length: 250 }, () => benignRequest()),
    headers: { 'x-sentinel-session': 'demo-session-250' },
  });
  const caps = readCaptures(s.outDir);
  assert.deepEqual(caps.map((c) => c.file), ['demo-session-250--p002.json', 'demo-session-250--p003.json', 'demo-session-250.json']);
  assert.equal(caps.reduce((n, c) => n + c.doc.exchanges.length, 0), 250);
  const alerts = allAlerts(s.outDir);
  assert.equal(alerts.length, 125 * 3, '125 exfil replies x 3 alerts, none dropped');
  assertValid(alerts);
  assert.equal(new Set(alerts.map((a) => a.AlertId)).size, alerts.length, 'alert ids unique');
  assert.ok(s.log.entries.some((e) => e.reason === 'capture_rotated'), 'rotation is logged');
});

test('T3-shaped verdicts pass through: not stand-in, response-side block request downgraded to ReportOnly and recorded', async () => {
  const t3 = async ({ phase }) => (phase === 'response'
    ? {
      flagged: true, category: 'taint_flow_exfil', ruleId: 'taint.untrusted_read_to_external_send', disposition: 'block', detectionLatencyMs: 1.25,
      entities: { toolCall: { id: 'tc-1', name: 'submit_to_index' }, sink: { type: 'http', destination: 'http://127.0.0.1:40447/api/canary/exfil-test' } },
      taintPath: [{ kind: 'source', label: 'rag doc (untrusted)', trust: 'untrusted' }, { kind: 'sink', label: 'submit_to_index', toolCallId: 'tc-1', trust: 'external' }],
    }
    : null);
  const s = await session({ mode: 'observe', respond: () => ({ json: exfilResponse() }), requests: [benignRequest()], inspectors: [t3] });
  const alerts = allAlerts(s.outDir);
  assertValid(alerts);
  assert.equal(alerts.length, 1);
  const [a] = alerts;
  assert.equal(a.PipelineContext.StandIn, false);
  assert.equal(a.PipelineContext.RequestedDisposition, 'block');
  assert.equal(a.PatternDispositionDescription, 'ReportOnly');
  assert.equal(a.DetectionLatencyMs, 1.25);
  assert.equal(a.PipelineContext.LatencySource, 'detector');
  assert.equal(a.TaintPath[0].Label, 'rag doc (untrusted)');
  assert.equal(readSidecars(s.outDir)[0].doc.placeholder, false, 'real detector output is not labeled placeholder');
});

test('T2 default substring inspector (generic verdict) maps to a stand-in alert with the needle redacted', async () => {
  const { substringInspector } = await import(path.join((await importProxy()).root, 'sentinel/proxy/inspectors.mjs'));
  const needle = 'sk-sentinel-HONEY-t10-0001';
  const req = { messages: [{ role: 'user', content: `${'filler '.repeat(3000)} key=${needle} ${'filler '.repeat(500)}` }] };
  const s = await session({ mode: 'block', respond: () => ({ json: benignResponse() }), requests: [req], inspectors: [substringInspector([needle])] });
  assert.equal(s.statuses[0].status, 403);
  const alerts = allAlerts(s.outDir);
  assertValid(alerts);
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].RuleId, 'proxy.substring');
  assert.equal(alerts[0].PipelineContext.StandIn, true);
  assert.equal(alerts[0].PatternDispositionDescription, 'Blocked');
  const sideText = readFileSync(path.join(s.outDir, 'alerts', readSidecars(s.outDir)[0].file), 'utf8');
  assert.ok(!sideText.includes(needle), 'needle redacted from the alert');
});

test('oversize request -> proxy 413 -> scan_cap_exceeded alert attached to the exchange, request-side Blocked', async () => {
  const big = { messages: [{ role: 'user', content: 'x'.repeat(70 * 1024) }] };
  const s = await session({ mode: 'observe', respond: () => ({ json: benignResponse() }), requests: [big], maxRequestBytes: 64 * 1024 });
  assert.equal(s.statuses[0].status, 413);
  const alerts = allAlerts(s.outDir);
  assertValid(alerts);
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].Category, 'scan_cap_exceeded');
  assert.equal(alerts[0].RuleId, 'proxy.request_too_large');
  assert.equal(alerts[0].PipelineContext.Direction, 'request');
  assert.equal(alerts[0].PatternDispositionDescription, 'Blocked');
  assert.match(alerts[0].Evidence, /cap=65536/);
  assert.equal(readCaptures(s.outDir)[0].doc.exchanges.length, 1);
});

test('stand-in config validation is fail-loud', () => {
  assert.throws(() => validateStandinConfig({ honeytokens: [{ id: 'x', value: 'short' }] }), />= 8 chars/);
  assert.throws(() => validateStandinConfig({ injectionPatterns: ['('] }), /injectionPatterns/);
});
