import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildAlert, validateAlert, AlertValidationError, BOUNDS, TRUNCATION_MARKER_PREFIX, SCHEMA_VERSION,
} from '../schema.js';
import { CATEGORIES } from '../mapping.js';
import { MAX_REDACT_SCAN_CHARS } from '../redact.js';
import { makeVerdict, warnSink, percentile } from './helpers.js';

test('sample verdict renders a valid AIDR-shaped alert with case card', () => {
  const { warnings, onWarning } = warnSink();
  const a = buildAlert(makeVerdict('taint_flow_exfil', 0), { onWarning });
  assert.deepEqual(validateAlert(a), []);
  assert.equal(a.SchemaVersion, SCHEMA_VERSION);
  assert.equal(a.PatternDispositionDescription, 'Blocked');
  assert.equal(a.SeverityName, 'Critical');
  assert.equal(a.TacticId, 'AML.TA0010');
  assert.equal(a.Entities.Sink.Destination, 'https://collector-0.example.test/in');
  assert.match(a.CaseCard.Narrative, /^Instruction originated in rag:doc-0 → influenced tool call http_post\(tc-0\) → .* → blocked by rule taint\.rule_0$/);
  assert.equal(a.CaseCard.DetectionLayers[0].Layer, 'taint');
  assert.equal(warnings.length, 0);
  assert.ok(Object.isFrozen(a) && Object.isFrozen(a.Entities));
});

test('dispositions map to Blocked / Allowed / ReportOnly', () => {
  const { onWarning } = warnSink();
  const d = (x) => buildAlert(makeVerdict('egress_secret_pattern', 0, { disposition: x }), { onWarning });
  assert.equal(d('block').PatternDispositionDescription, 'Blocked');
  assert.equal(d('allow').PatternDispositionDescription, 'Allowed');
  assert.equal(d('report').PatternDispositionDescription, 'ReportOnly');
  assert.equal(d('ReportOnly').PatternDispositionFlags.ReportOnly, true);
  assert.match(d('report').CaseCard.Narrative, /reported \(report-only\) by rule/);
});

test('fail loud: missing required fields throw AlertValidationError listing every issue', () => {
  const err = (() => { try { buildAlert({}); } catch (e) { return e; } })();
  assert.ok(err instanceof AlertValidationError);
  for (const f of ['category', 'ruleId', 'disposition', 'detectionLatencyMs', 'entities.agent.name', 'entities.session.id']) {
    assert.ok(err.issues.some((i) => i.startsWith(f)), `expected issue for ${f}: ${err.issues}`);
  }
  assert.throws(() => buildAlert(null), AlertValidationError);
});

test('fail loud: sink categories require toolCall + sink entities', () => {
  const v = makeVerdict('honeytoken_exfil');
  delete v.entities.sink;
  delete v.entities.toolCall;
  assert.throws(() => buildAlert(v), (e) => e instanceof AlertValidationError && e.issues.length === 4);
  // non-sink category is fine without them
  const { onWarning } = warnSink();
  assert.doesNotThrow(() => buildAlert(makeVerdict('indirect_prompt_injection'), { onWarning }));
});

test('fail loud: bad enum/number values', () => {
  const bad = [
    { disposition: 'maybe' }, { detectionLatencyMs: -1 }, { detectionLatencyMs: Number.NaN },
    { state: 'whatever' }, { severity: 400 }, { timestamp: 'not-a-date' }, { category: 'nope' },
    { taintPath: [{ kind: 'teleport', label: 'x' }] }, { canary: { id: 'c1' } },
  ];
  for (const o of bad) assert.throws(() => buildAlert(makeVerdict('taint_flow_exfil', 0, o)), AlertValidationError, JSON.stringify(o));
});

test('data-rich: 700 alerts built in a loop across every category — all valid, unique ids, latency measured', () => {
  const { warnings, onWarning } = warnSink();
  const N = 700;
  const ids = new Set();
  const times = [];
  for (let i = 0; i < N; i++) {
    const v = makeVerdict(CATEGORIES[i % CATEGORIES.length], i);
    const t0 = process.hrtime.bigint();
    const a = buildAlert(v, { onWarning });
    times.push(Number(process.hrtime.bigint() - t0) / 1e6);
    assert.deepEqual(validateAlert(a), [], `alert ${i}`);
    ids.add(a.AlertId);
    // decision/lookups at scale: alert #i still carries its own entities (no capped scan anywhere)
    assert.equal(a.Entities.Session.Id, `sess-${Math.floor(i / 5)}`);
  }
  assert.equal(ids.size, N);
  assert.equal(warnings.length, 0);
  times.sort((x, y) => x - y);
  const median = percentile(times, 50);
  const p95 = percentile(times, 95);
  console.log(`# buildAlert latency over ${N} alerts: median=${median.toFixed(3)}ms p95=${p95.toFixed(3)}ms`);
  assert.ok(p95 < 50, `p95 ${p95}ms too slow`);
});

test('very long TaintPath (5000 hops) is bounded with explicit marker + warning; source and sink kept', () => {
  const { warnings, onWarning } = warnSink();
  const hops = [{ kind: 'source', label: 'rag:poisoned-doc' }];
  for (let i = 0; i < 4998; i++) hops.push({ kind: 'propagate', label: `hop-${i}` });
  hops.push({ kind: 'sink', label: 'http_post:attacker' });
  const a = buildAlert(makeVerdict('taint_flow_exfil', 1, { taintPath: hops }), { onWarning });
  assert.equal(a.TaintPath.length, BOUNDS.MAX_TAINT_HOPS);
  assert.equal(a.TaintPath[0].Label, 'rag:poisoned-doc');
  assert.equal(a.TaintPath.at(-1).Label, 'http_post:attacker');
  assert.equal(a.TaintPath.at(-1).Step, 5000);
  const marker = a.TaintPath.find((h) => h.Kind === 'truncated');
  assert.ok(marker, 'explicit truncation marker hop present');
  assert.equal(marker.OmittedHops, 5000 - (BOUNDS.MAX_TAINT_HOPS - 1));
  assert.ok(marker.Label.startsWith(TRUNCATION_MARKER_PREFIX));
  assert.ok(warnings.some((w) => /TaintPath truncated: 5000 hops/.test(w.msg)), 'warning emitted');
  assert.deepEqual(a.Truncations.find((t) => t.Field === 'TaintPath'), {
    Field: 'TaintPath', OriginalLength: 5000, Kept: BOUNDS.MAX_TAINT_HOPS - 1, Cap: BOUNDS.MAX_TAINT_HOPS,
  });
  assert.equal(a.CaseCard.OriginatedIn, 'rag:poisoned-doc');
  assert.deepEqual(validateAlert(a), []);
});

test('oversized string fields are bounded with explicit marker + warning, never cut silently', () => {
  const { warnings, onWarning } = warnSink();
  const big = 'x'.repeat(200_000);
  const v = makeVerdict('egress_secret_pattern', 2, {
    evidence: big,
    caseCard: { narrative: 'n'.repeat(10_000), originatedIn: 'o'.repeat(5000) },
    taintPath: [{ kind: 'source', label: 'L'.repeat(3000) }, { kind: 'sink', label: 'sink' }],
  });
  v.entities.sink.destination = `https://exfil.example.test/?d=${'q'.repeat(9000)}`;
  const a = buildAlert(v, { onWarning });
  const checks = [
    ['Evidence', a.Evidence, BOUNDS.MAX_STRING_CHARS],
    ['CaseCard.Narrative', a.CaseCard.Narrative, BOUNDS.MAX_STRING_CHARS],
    ['CaseCard.OriginatedIn', a.CaseCard.OriginatedIn, BOUNDS.MAX_LABEL_CHARS],
    ['TaintPath[0].Label', a.TaintPath[0].Label, BOUNDS.MAX_LABEL_CHARS],
    ['Entities.Sink.Destination', a.Entities.Sink.Destination, BOUNDS.MAX_STRING_CHARS],
  ];
  for (const [field, val, cap] of checks) {
    assert.ok(val.length <= cap, `${field} length ${val.length} <= ${cap}`);
    assert.ok(val.includes(`${TRUNCATION_MARKER_PREFIX} field=${field} kept=${cap} of `), `${field} has marker`);
    assert.ok(a.Truncations.some((t) => t.Field === field), `${field} recorded in Truncations`);
    assert.ok(warnings.some((w) => w.msg.includes(`"${field}"`)), `${field} warning emitted`);
  }
  assert.equal(a.Truncations.find((t) => t.Field === 'Evidence').OriginalLength, 200_000);
  assert.ok(Buffer.byteLength(JSON.stringify(a)) <= BOUNDS.MAX_ALERT_BYTES);
});

test('default warning path uses process.emitWarning (loud even with no handler passed)', async () => {
  const seen = [];
  const h = (w) => seen.push(w);
  process.on('warning', h);
  buildAlert(makeVerdict('taint_flow_exfil', 3, { evidence: 'z'.repeat(5000) }));
  await new Promise((r) => setImmediate(r));
  process.off('warning', h);
  assert.ok(seen.some((w) => w.code === 'SENTINEL_ALERT_TRUNCATED'));
});

test('worst case: every field at max still fits MAX_ALERT_BYTES (size guard never silently cuts)', () => {
  const { onWarning } = warnSink();
  const huge = 'w'.repeat(100_000);
  const hops = Array.from({ length: 1000 }, (_, i) => ({
    kind: i === 0 ? 'source' : i === 999 ? 'sink' : 'propagate', label: huge, toolCallId: huge, trust: huge,
  }));
  const layers = Array.from({ length: 500 }, () => ({ layer: huge, rule: huge, fired: true, latencyMs: 1 }));
  const v = makeVerdict('honeytoken_exfil', 4, {
    taintPath: hops, layers, evidence: huge, ruleId: huge, alertId: huge,
    caseCard: { narrative: huge, originatedIn: huge, influencedToolCall: huge, decidedByRule: huge },
  });
  v.entities.agent.name = huge; v.entities.agent.id = huge; v.entities.session.id = huge;
  v.entities.toolCall = { id: huge, name: huge, argsPreview: huge };
  v.entities.sink = { type: huge, destination: huge };
  const a = buildAlert(v, { onWarning });
  const size = Buffer.byteLength(JSON.stringify(a));
  console.log(`# worst-case alert size: ${size} bytes (cap ${BOUNDS.MAX_ALERT_BYTES})`);
  assert.ok(size <= BOUNDS.MAX_ALERT_BYTES);
  assert.equal(a.CaseCard.DetectionLayers.length, BOUNDS.MAX_LAYERS);
});

test('string beyond the redaction scan cap is withheld whole (not partially scanned) + warning', () => {
  const { warnings, onWarning } = warnSink();
  const secret = 'AKIAZZZZZZZZZZZZZZZZ';
  const evidence = 'a'.repeat(MAX_REDACT_SCAN_CHARS) + secret; // secret sits past the scan cap
  const a = buildAlert(makeVerdict('egress_secret_pattern', 5, { evidence }), { onWarning });
  assert.ok(!JSON.stringify(a).includes(secret));
  assert.match(a.Evidence, /^\[WITHHELD:oversize len=\d+ cap=\d+ sha256=[0-9a-f]{16}\]$/);
  assert.ok(warnings.some((w) => /withheld unscanned/.test(w.msg)));
  assert.equal(a.Redactions.ByKind.withheld_oversize, 1);
});

test('golden: examples/sample-verdict.json renders exactly examples/sample-alert.json (contract for T5)', async () => {
  const fs = await import('node:fs');
  const read = (f) => JSON.parse(fs.readFileSync(new URL(`../examples/${f}`, import.meta.url), 'utf8'));
  const a = buildAlert(read('sample-verdict.json'));
  assert.deepEqual(JSON.parse(JSON.stringify(a)), read('sample-alert.json'));
  assert.deepEqual(validateAlert(a), []);
});
