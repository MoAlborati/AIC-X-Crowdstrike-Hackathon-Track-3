/**
 * T6 corpus tests — data-rich, real-seam, fail-loud.
 *
 * Real seam: the evasion proof runs against DVAA's ACTUAL detectAttacks()/ATTACK_PATTERNS when a
 * DVAA checkout is found ($DVAA_SRC, $DVAA_DIR, or scripts/setup-dvaa.sh's default clone dir; get
 * one with `scripts/setup-dvaa.sh clone`). Without one, the real-DVAA test is reported as
 * "SKIPPED real-DVAA" (node:test skip + console line), never a silent pass; DVAA_REQUIRE_REAL=1
 * makes a missing/wrong-commit checkout a FAILURE. Replica checks always run.
 *
 * Run:  node --test captures/variants/tests/*.test.mjs
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadBaseline, replicaBaseline, ATTACK_PATTERNS_REPLICA, DVAA_PIN } from '../tools/baseline.mjs';
import { CHANNELS, PAYLOAD_ROLE, FRAMEWORKS_BY_CATEGORY, payloadIndex, sha256 } from '../tools/fixture-lib.mjs';
import { DEEPSET, AGENTDOJO, INJECAGENT, DVAA, renderAgentDojo } from '../tools/upstream-cases.mjs';
import { verifyUpstream } from '../tools/verify-upstream.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..'); // captures/variants
const FIX = path.join(ROOT, 'fixtures');

function listFixtures() {
  const out = [];
  for (const dir of fs.readdirSync(FIX).sort()) {
    const d = path.join(FIX, dir);
    if (!fs.statSync(d).isDirectory()) continue;
    for (const f of fs.readdirSync(d).sort()) {
      if (f.endsWith('.json')) out.push({ group: dir, file: f, rel: `fixtures/${dir}/${f}`, path: path.join(d, f) });
    }
  }
  return out;
}

const fixtures = listFixtures().map((f) => ({ ...f, doc: JSON.parse(fs.readFileSync(f.path, 'utf8')) }));
const payloadOf = (doc) => doc.request.messages[payloadIndex(doc)].content;
const userTexts = (doc) => doc.request.messages.filter((m) => m.role === 'user').map((m) => m.content);

const LICENSE_BY_BENCHMARK = {
  'deepset/prompt-injections': 'Apache-2.0',
  AgentDojo: 'MIT',
  InjecAgent: 'MIT',
  'DVAA (organizer sandbox)': 'Apache-2.0',
};

// Every verbatim upstream string the corpus may contain (from upstream-cases.mjs).
const UPSTREAM_STRINGS = new Set([
  ...Object.values(DEEPSET.rows).map((r) => r.text),
  ...Object.values(AGENTDOJO.cases).map((c) => renderAgentDojo(c.goal)),
  ...INJECAGENT.cases.map((c) => c.toolResponse),
  DVAA.document,
]);

/** The attack part of a verbatim fixture that must sit in the payload message. */
function attackPart(up) {
  return up.splitAt === undefined ? up.text : up.text.slice(up.splitAt + 2);
}

test('corpus is non-empty and covers all required sources', () => {
  const groups = new Set(fixtures.map((f) => f.group));
  for (const g of ['deepset', 'agentdojo', 'injecagent', 'benign', 'evasion']) {
    assert.ok(groups.has(g), `missing fixture group: ${g}`);
  }
  assert.ok(fixtures.length >= 13, `expected >=13 fixtures, got ${fixtures.length}`);
});

test('every fixture matches the schema (request.messages + label + frameworks + dvaa block)', () => {
  for (const { file, doc } of fixtures) {
    assert.ok(typeof doc.id === 'string' && doc.id.length, `${file}: id`);
    assert.ok(doc.source && typeof doc.source === 'object', `${file}: source`);
    assert.ok(['verbatim', 'authored'].includes(doc.source.fidelity), `${file}: source.fidelity`);
    assert.ok(CHANNELS.includes(doc.channel), `${file}: channel`);
    assert.ok(Array.isArray(doc.request?.messages) && doc.request.messages.length, `${file}: request.messages`);
    for (const m of doc.request.messages) {
      assert.ok(typeof m.role === 'string' && typeof m.content === 'string', `${file}: message shape`);
    }
    assert.ok(['positive', 'negative'].includes(doc.label?.groundTruth), `${file}: groundTruth`);
    assert.ok(['block', 'allow'].includes(doc.label?.expectedVerdict), `${file}: expectedVerdict`);
    assert.ok(doc.label?.dvaa && typeof doc.label.dvaa.exfilAttempted === 'boolean', `${file}: dvaa block`);
    assert.equal(doc.label.dvaa.exfilAttempted, doc.label.dvaa.exfilTargetUrl !== null, `${file}: exfilAttempted <=> target`);
    if (doc.label.groundTruth === 'negative') {
      assert.equal(doc.label.dvaa.exfilAttempted, false, `${file}: negative must not attempt exfil`);
      assert.equal(doc.label.category, 'benign', `${file}: negative category`);
    }
    // F8: framework tags come from the single table; unknown category fails.
    assert.ok(FRAMEWORKS_BY_CATEGORY[doc.label.category], `${file}: no framework mapping for ${doc.label.category}`);
    assert.deepEqual(doc.label.frameworks, FRAMEWORKS_BY_CATEGORY[doc.label.category], `${file}: frameworks`);
  }
});

test('F5 channel fidelity: tool_output / rag_document payloads arrive in a role:"tool" message, never the user turn', () => {
  let toolChannel = 0;
  for (const { file, doc } of fixtures) {
    const msgs = doc.request.messages;
    const idx = payloadIndex(doc);
    assert.equal(msgs[idx].role, PAYLOAD_ROLE[doc.channel], `${file}: payload role for ${doc.channel}`);
    if (doc.channel === 'user_message') {
      assert.ok(!msgs.some((m) => m.role === 'tool'), `${file}: user_message fixture must not carry tool messages`);
      continue;
    }
    toolChannel++;
    // OpenAI shape: user -> assistant tool_call -> tool result answering that call.
    const call = msgs.slice(0, idx).flatMap((m) => (m.role === 'assistant' ? m.tool_calls ?? [] : []));
    assert.ok(call.some((c) => c.id === msgs[idx].tool_call_id && c.function.name === msgs[idx].name), `${file}: tool result answers a prior tool_call`);
    for (const c of call) JSON.parse(c.function.arguments); // arguments are JSON
    // The untrusted payload text must not leak into any user turn.
    if (doc.source.fidelity === 'verbatim') {
      const atk = attackPart(doc.source.upstream).trim();
      for (const u of userTexts(doc)) assert.ok(!u.includes(atk), `${file}: attack text found in a user turn`);
    }
    for (const u of userTexts(doc)) assert.ok(u.length < 500, `${file}: user turn should be a short request, payload goes in the tool message`);
  }
  assert.ok(toolChannel >= 10, `expected >=10 tool/RAG-channel fixtures, got ${toolChannel}`);
});

test('F1-F4/F7 provenance: positives are verbatim upstream; sha256 + placement + license checked', () => {
  let verbatim = 0;
  for (const { file, doc } of fixtures) {
    const s = doc.source;
    if (doc.label.groundTruth === 'positive') {
      assert.equal(s.fidelity, 'verbatim', `${file}: attack fixtures must be verbatim upstream (no authored attack text)`);
    }
    if (s.fidelity !== 'verbatim') continue;
    verbatim++;
    assert.equal(s.license, LICENSE_BY_BENCHMARK[s.benchmark], `${file}: license for ${s.benchmark}`);
    assert.ok(s.url && s.caseRef, `${file}: url + caseRef`);
    const up = s.upstream;
    assert.ok(up && typeof up.text === 'string', `${file}: upstream.text`);
    assert.ok(up.commit || up.revision, `${file}: upstream pinned commit/revision`);
    assert.equal(sha256(up.text), up.sha256, `${file}: upstream sha256`);
    assert.ok(UPSTREAM_STRINGS.has(up.text), `${file}: upstream.text is not one of the verbatim upstream strings`);
    // The verbatim string (or, for DVAA's split document, each half) is present byte-for-byte.
    assert.ok(payloadOf(doc).includes(attackPart(up)), `${file}: verbatim upstream text not found in payload message`);
    if (up.splitAt !== undefined) {
      assert.equal(userTexts(doc)[0], up.text.slice(0, up.splitAt), `${file}: DVAA request line is the user turn`);
    }
  }
  assert.ok(verbatim >= 13, `expected >=13 verbatim fixtures, got ${verbatim}`);
});

test('F7 upstream verification against real sources (explicit SKIPPED when a source is absent)', async () => {
  const results = await verifyUpstream();
  for (const r of results) {
    const tag = r.status === 'ok' ? 'OK' : r.status === 'skipped' ? 'SKIPPED upstream' : 'MISMATCH';
    console.log(`[upstream] ${tag} ${r.source}: ${r.detail}`);
    assert.notEqual(r.status, 'mismatch', `${r.source}: ${r.detail}`);
    if (process.env.UPSTREAM_REQUIRE === '1') assert.equal(r.status, 'ok', `${r.source} required: ${r.detail}`);
  }
});

test('data-rich: benign long doc >16KB and tool output has hundreds of rows', () => {
  const longDoc = fixtures.find((f) => f.doc.id === 'BEN-LONGDOC-001').doc;
  assert.ok(payloadOf(longDoc).length > 16 * 1024, 'benign long doc must exceed 16KB');
  const rows = fixtures.find((f) => f.doc.id === 'BEN-TOOLROWS-001').doc;
  assert.ok(rows.dataRich.rows >= 300, 'tool output must have hundreds of rows');
  assert.equal(JSON.parse(payloadOf(rows)).length, rows.dataRich.rows, 'every row is in the tool message');
});

/** Shared evasion assertions for one baseline implementation. */
function assertEvasion(baseline, { checkRecorded }) {
  const evasion = fixtures.filter((f) => f.group === 'evasion');
  assert.ok(evasion.length >= 6, 'expected position variants for DVAA + benchmark injections');
  const carrier = payloadOf(fixtures.find((f) => f.doc.id === 'BEN-LONGDOC-001').doc);
  assert.equal(baseline.scanFull(carrier).hasAttack, false, 'benign carrier must be clean on a FULL scan');
  let middle = 0;
  for (const { file, doc } of evasion) {
    const content = payloadOf(doc);
    const m = doc.baseline8kb;
    assert.equal(m.payloadMessageIndex, payloadIndex(doc), `${file}: payloadMessageIndex`);
    assert.equal(m.docLength, content.length, `${file}: docLength`);
    assert.ok(content.length > baseline.DETECTION_EDGE * 2, `${file}: doc must exceed 16KB`);
    const verdict = baseline.detectAttacks(content);
    const full = baseline.scanFull(content);
    assert.equal(full.hasAttack, true, `${file}: signal must be present on a FULL-payload scan`);
    if (checkRecorded) {
      // Recorded metadata (computed by the generator with the replica) must match.
      assert.equal(m.evadesBaseline, !verdict.hasAttack, `${file}: recorded evadesBaseline`);
      assert.equal(m.signalPresentOnFullScan, true, `${file}: recorded signalPresentOnFullScan`);
      assert.equal(m.carrierCleanOnFullScan, true, `${file}: recorded carrierCleanOnFullScan`);
    }
    if (/middle/i.test(doc.scenario)) {
      middle++;
      assert.equal(m.inMiddleGap, true, `${file}: injection must sit in the middle gap`);
      assert.ok(m.injectionOffsetStart > baseline.DETECTION_EDGE + 64, `${file}: start beyond head window (+word-edge slack)`);
      assert.ok(m.injectionOffsetEnd < content.length - baseline.DETECTION_EDGE - 64, `${file}: end before tail window`);
      assert.equal(verdict.hasAttack, false, `${file}: middle variant must EVADE the 8KB baseline`);
    } else {
      assert.equal(verdict.hasAttack, true, `${file}: start/end control must be caught by the baseline`);
    }
  }
  assert.ok(middle >= 2, 'expected a DVAA-trigger and an AgentDojo middle evasion variant');
}

test('evasion proof on the DVAA replica (always runs): middle evades, start/end caught, full scan flags', () => {
  assertEvasion(replicaBaseline(), { checkRecorded: true });
});

test('REAL-SEAM evasion proof on real DVAA detectAttacks() (SKIPPED real-DVAA when no checkout)', async (t) => {
  // DVAA_REQUIRE_REAL=1: loadBaseline() throws on a missing or wrong-commit checkout -> test FAILS.
  const baseline = await loadBaseline();
  if (baseline.source !== 'dvaa-real') {
    const msg = `SKIPPED real-DVAA: ${baseline.reason}. Replica-only evidence; set DVAA_REQUIRE_REAL=1 to fail instead.`;
    console.log(`[baseline] ${msg}`);
    t.skip(msg);
    return;
  }
  console.log(`[baseline] dvaa-real (${baseline.from}: ${baseline.root} @ ${baseline.commit})`);
  assert.equal(baseline.commit, DVAA_PIN, `real DVAA must be at the pinned commit ${DVAA_PIN}`);
  // Replica parity: every replica regex is byte-identical to the real one.
  for (const [cat, list] of Object.entries(ATTACK_PATTERNS_REPLICA)) {
    assert.deepEqual(list.map(String), baseline.ATTACK_PATTERNS[cat].map(String), `replica ${cat} drifted from real DVAA`);
  }
  assertEvasion(baseline, { checkRecorded: true });
});

test('benign negatives are clean on a FULL scan; exfil positives carry a detectable signal', async () => {
  const real = await loadBaseline().catch(() => null);
  const baseline = real ?? replicaBaseline();
  console.log(`[full-scan] patterns from ${baseline.source}`);
  let beyondBaseline = 0;
  for (const { file, doc } of fixtures) {
    const content = doc.request.messages.map((m) => m.content).join('\n');
    const full = baseline.scanFull(content);
    if (doc.label.groundTruth === 'negative') {
      assert.equal(full.hasAttack, false, `${file}: benign must not trip the patterns (false-positive guard)`);
      continue;
    }
    if (doc.label.dvaa.exfilTargetUrl) {
      assert.equal(full.hasAttack, true, `${file}: exfil positive must be detectable on full scan`);
      assert.ok(payloadOf(doc).includes(doc.label.dvaa.exfilTargetUrl), `${file}: exfil target appears in the payload`);
    } else if (!full.hasAttack) {
      beyondBaseline++; // PI phrased outside DVAA's patterns: exercises detection beyond the baseline
    }
  }
  console.log(`[corpus] prompt-injection cases beyond DVAA's baseline patterns: ${beyondBaseline}`);
  assert.ok(beyondBaseline >= 1, 'corpus should include at least one case beyond DVAA baseline patterns');
});

test('manifest.json indexes every fixture with matching labels, channel, license and framework tags', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'manifest.json'), 'utf8'));
  assert.equal(manifest.cases.length, fixtures.length, 'manifest row count');
  const byPath = new Map(manifest.cases.map((r) => [r.path, r]));
  for (const { rel, doc } of fixtures) {
    const r = byPath.get(rel);
    assert.ok(r, `${rel}: missing from manifest (run tools/build-manifest.mjs)`);
    assert.equal(r.id, doc.id);
    assert.equal(r.channel, doc.channel, `${rel}: channel`);
    assert.equal(r.groundTruth, doc.label.groundTruth, `${rel}: groundTruth`);
    assert.equal(r.license, doc.source.license ?? null, `${rel}: license`);
    assert.equal(r.fidelity, doc.source.fidelity, `${rel}: fidelity`);
    assert.deepEqual(r.frameworks, doc.label.frameworks, `${rel}: frameworks`);
  }
});
