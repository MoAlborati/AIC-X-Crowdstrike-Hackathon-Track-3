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
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import {
  loadBaseline,
  replicaBaseline,
  ATTACK_PATTERNS_REPLICA,
  DVAA_PIN,
  DEFAULT_DVAA_DIR,
  REPO_ROOT,
  dvaaCandidates,
  resolveVerifiedDvaa,
} from '../tools/baseline.mjs';
import { CHANNELS, PAYLOAD_ROLE, FRAMEWORKS_BY_CATEGORY, PENDING_T4_CATALOG, payloadIndex, sha256 } from '../tools/fixture-lib.mjs';
import { CATALOG } from '../../../sentinel/alerts/mapping.js';
import { DEEPSET, AGENTDOJO, INJECAGENT, DVAA, renderAgentDojo, allUpstreamStrings, AGENTDOJO_RUN, INJECAGENT_SAMPLE } from '../tools/upstream-cases.mjs';
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

// Every verbatim upstream string the corpus may contain (from upstream-cases.mjs, incl. T6b extracts).
const UPSTREAM_STRINGS = allUpstreamStrings();

/** The attack part of a verbatim fixture that must sit in the payload message. */
function attackPart(up) {
  return up.splitAt === undefined ? up.text : up.text.slice(up.splitAt + 2);
}

test('corpus is non-empty and covers all required sources', () => {
  const groups = new Set(fixtures.map((f) => f.group));
  for (const g of ['deepset', 'agentdojo', 'agentdojo-benign', 'injecagent', 'benign', 'evasion']) {
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
    // Upstream user-task prompts run up to ~0.7KB (AgentDojo workspace); the payload is never in them.
    for (const u of userTexts(doc)) assert.ok(u.length < 1024, `${file}: user turn should be a short request, payload goes in the tool message`);
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

test('T6b: data-rich corpus, >=60 attack and >=60 benign, every source and template represented', () => {
  const pos = fixtures.filter((f) => f.doc.label.groundTruth === 'positive');
  const neg = fixtures.filter((f) => f.doc.label.groundTruth === 'negative');
  assert.ok(pos.length >= 60, `expected >=60 attack cases, got ${pos.length}`);
  assert.ok(neg.length >= 60, `expected >=60 benign cases, got ${neg.length}`);
  // Benign must not be only short user turns: >=60 benign cases arrive through the tool channel.
  const toolBenign = neg.filter((f) => f.doc.channel !== 'user_message');
  assert.ok(toolBenign.length >= 60, `expected >=60 tool-channel benign cases, got ${toolBenign.length}`);
  // Every extracted upstream case became a fixture (no silent drop), every suite + template is present.
  const ids = new Set(fixtures.map((f) => f.doc.id));
  assert.equal(fixtures.filter((f) => f.group === 'agentdojo-benign').length, AGENTDOJO_RUN.benign.length, 'one benign fixture per AgentDojo user task');
  for (const k of INJECAGENT_SAMPLE.cases) {
    const tag = k.file.includes('_ds_') ? 'DS' : 'DH';
    assert.ok(ids.has(`IA-${tag}-E${String(k.caseIndex).padStart(3, '0')}`), `InjecAgent ${tag} ${k.caseIndex} missing`);
  }
  assert.equal(fixtures.filter((f) => f.group === 'deepset').length, Object.keys(DEEPSET.rows).length, 'every deepset split=test row');
  const adAttack = fixtures.filter((f) => f.group === 'agentdojo').map((f) => f.doc.source.upstream);
  for (const suite of AGENTDOJO_RUN.suites) {
    const inSuite = fixtures.filter((f) => f.group === 'agentdojo' && f.doc.source.caseRef.includes(` x ${suite}/`));
    const tasks = new Set(AGENTDOJO_RUN.attacks.filter((a) => a.suite === suite).map((a) => a.injectionTask));
    const covered = new Set(inSuite.map((f) => f.doc.source.upstream.injectionTask));
    for (const t of tasks) assert.ok(covered.has(t), `AgentDojo ${suite}/${t} has no attack fixture`);
  }
  for (const a of [AGENTDOJO_RUN.primaryAttack, ...AGENTDOJO_RUN.extraAttacks]) assert.ok(adAttack.some((u) => u.attack === a), `AgentDojo attack template ${a} missing`);
  // Data-rich benign tool outputs: multi-call transcripts and large outputs exist and are carried whole.
  const adb = fixtures.filter((f) => f.group === 'agentdojo-benign').map((f) => f.doc);
  assert.ok(adb.some((d) => d.dataRich.toolCalls >= 3), 'expected multi-call benign transcripts');
  assert.ok(adb.some((d) => d.dataRich.toolOutputChars > 16 * 1024), 'expected a benign tool output > 16KB');
  for (const d of adb) {
    const tools = d.request.messages.filter((m) => m.role === 'tool');
    assert.equal(tools.length, d.dataRich.toolCalls, `${d.id}: every ground-truth call has its tool message`);
    assert.deepEqual(tools.map((m) => sha256(m.content)), d.source.upstream.toolOutputSha256, `${d.id}: tool outputs are the upstream bytes`);
  }
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
  // Same baseline as the REAL-SEAM test; a load error (bad DVAA_SRC, unverified checkout,
  // DVAA_REQUIRE_REAL=1 without a checkout) fails this test too instead of silently using the replica.
  const baseline = await loadBaseline();
  console.log(`[full-scan] patterns from ${baseline.source}`);
  // Hard guards apply to what THIS repo authored (benign carriers) and to T6's original exfil cases.
  // T6b's verbatim upstream rows are NOT filtered by DVAA's patterns: a benchmark benign row that trips
  // them is a real baseline false positive, and an upstream attack the patterns miss is a real baseline
  // miss. Filtering on either would cherry-pick the corpus toward (or against) the baseline. Counted below.
  const T6_EXFIL = new Set(['AD-EXFIL-001', 'AD-EXFIL-002', 'IA-DS-001', 'IA-DS-002']);
  let beyondBaseline = 0;
  let upstreamBenignFlagged = 0;
  let exfilMissedByPatterns = 0;
  for (const { file, doc } of fixtures) {
    const content = doc.request.messages.map((m) => m.content).join('\n');
    const full = baseline.scanFull(content);
    if (doc.label.groundTruth === 'negative') {
      if (doc.source.fidelity === 'authored') {
        assert.equal(full.hasAttack, false, `${file}: authored benign must not trip the patterns (false-positive guard)`);
      } else if (full.hasAttack) upstreamBenignFlagged++;
      continue;
    }
    if (doc.label.dvaa.exfilTargetUrl) {
      assert.ok(payloadOf(doc).includes(doc.label.dvaa.exfilTargetUrl), `${file}: exfil target appears in the payload`);
      assert.ok(!userTexts(doc).some((u) => u.includes(doc.label.dvaa.exfilTargetUrl)), `${file}: exfil target must not come from the user turn`);
      if (T6_EXFIL.has(doc.id) || doc.group === 'evasion') {
        assert.equal(full.hasAttack, true, `${file}: exfil positive must be detectable on full scan`);
      } else if (!full.hasAttack) exfilMissedByPatterns++;
    } else if (!full.hasAttack) {
      beyondBaseline++; // PI phrased outside DVAA's patterns: exercises detection beyond the baseline
    }
  }
  console.log(`[corpus] prompt-injection cases beyond DVAA's baseline patterns: ${beyondBaseline}`);
  console.log(`[corpus] upstream benign rows DVAA's patterns flag (baseline FPs): ${upstreamBenignFlagged}`);
  console.log(`[corpus] upstream exfil cases DVAA's patterns miss on a full scan: ${exfilMissedByPatterns}`);
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

// ---- Framework vocabulary = sentinel/alerts/mapping.js CATALOG (review L3) ---------------------
const CATALOG_KEY = { atlas: 'atlasTechniques', owaspLlm: 'owaspLlm', owaspAgentic: 'owaspAgentic', oasb: 'oasb' };

test('L3 framework tags use mapping.js CATALOG IDs (only declared PENDING_T4_CATALOG exceptions)', () => {
  const used = new Set();
  for (const [category, f] of Object.entries(FRAMEWORKS_BY_CATEGORY)) {
    assert.deepEqual(Object.keys(f).sort(), Object.keys(CATALOG_KEY).sort(), `${category}: framework keys`);
    if (category !== 'benign') assert.ok(f.oasb.length >= 1, `${category}: needs an OASB-1 tag`);
    for (const [fw, ids] of Object.entries(f)) {
      for (const id of ids) {
        used.add(id);
        if (Object.hasOwn(PENDING_T4_CATALOG, id)) {
          assert.equal(PENDING_T4_CATALOG[id].kind, CATALOG_KEY[fw], `${id}: pending entry kind`);
          continue;
        }
        assert.ok(Object.hasOwn(CATALOG[CATALOG_KEY[fw]], id), `${category}: ${fw} ${id} is not in mapping.js CATALOG.${CATALOG_KEY[fw]}`);
      }
    }
  }
  for (const [id, p] of Object.entries(PENDING_T4_CATALOG)) {
    assert.ok(used.has(id), `${id}: pending entry is unused; remove it`);
    // Once T4 adds the ID, this fails so the exception gets removed (no stale allowlist).
    assert.ok(!Object.hasOwn(CATALOG[p.kind], id), `${id} is now in mapping.js CATALOG; remove it from PENDING_T4_CATALOG`);
    assert.ok(CATALOG.atlasTactics[p.tactic], `${id}: tactic ${p.tactic} must exist in CATALOG`);
  }
  console.log(`[frameworks] pending T4 CATALOG additions: ${Object.keys(PENDING_T4_CATALOG).join(', ') || 'none'}`);
});

// ---- DVAA trust gate: verify pin + clean tree BEFORE importing (review L1) ----------------------
const gitIn = (cwd, ...args) => execFileSync('git', ['-C', cwd, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
const GIT_ID = ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false'];

/** A git checkout whose DVAA files record an import side effect (a marker file) if ever imported. */
function plantedCheckout(dir, marker) {
  for (const rel of ['src/core/vulnerabilities.js', DVAA.file]) {
    fs.mkdirSync(path.join(dir, path.dirname(rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), `import fs from 'node:fs';\nfs.writeFileSync(${JSON.stringify(marker)}, 'imported');\nexport const DETECTION_EDGE = 1;\nexport function ${DVAA.fn}() { return ''; }\n`);
  }
  gitIn(dir, 'init', '-q');
  gitIn(dir, 'add', '-A');
  gitIn(dir, ...GIT_ID, 'commit', '-q', '-m', 'planted');
}

test('L1 default DVAA dir is repo-local (not /tmp) and is listed once', () => {
  assert.equal(DEFAULT_DVAA_DIR, path.join(REPO_ROOT, '.dvaa', 'dvaa-target'));
  const env = { PATH: process.env.PATH };
  const c = dvaaCandidates(env);
  assert.deepEqual(c.map((x) => x.root), [DEFAULT_DVAA_DIR]);
  assert.ok(!c.some((x) => x.root.startsWith('/tmp/')), 'no world-writable /tmp default');
  assert.equal(dvaaCandidates({ DVAA_DIR: DEFAULT_DVAA_DIR }).length, 1, 'no duplicate candidate');
  assert.match(fs.readFileSync(path.join(REPO_ROOT, '.gitignore'), 'utf8'), /^\.dvaa\/$/m, '.dvaa/ is gitignored');
});

test('L1 a wrong-commit DVAA checkout is rejected BEFORE its code is imported (baseline + verifier)', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 't6-planted-'));
  try {
    const marker = path.join(tmp, 'IMPORTED');
    const repo = path.join(tmp, 'dvaa');
    fs.mkdirSync(repo);
    plantedCheckout(repo, marker);
    for (const env of [{ DVAA_SRC: repo }, { DVAA_DIR: repo }, { DVAA_DIR: repo, DVAA_REQUIRE_REAL: '1' }]) {
      await assert.rejects(loadBaseline(env), /refusing to import DVAA code .*expected pinned/, JSON.stringify(Object.keys(env)));
    }
    const dv = (await verifyUpstream({ DVAA_DIR: repo })).find((r) => r.source === 'DVAA');
    assert.equal(dv.status, 'mismatch', `verifier: ${dv.detail}`);
    assert.match(dv.detail, /expected pinned/);
    assert.equal(fs.existsSync(marker), false, 'planted code must never be imported');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('L1 a pinned but DIRTY DVAA checkout is rejected before import (SKIPPED without a real checkout)', async (t) => {
  let real;
  try {
    real = resolveVerifiedDvaa('src/core/vulnerabilities.js');
  } catch (e) {
    real = { root: null, reason: e.message };
  }
  if (!real.root) {
    const msg = `SKIPPED real-DVAA dirty-tree check: ${real.reason}`;
    console.log(`[baseline] ${msg}`);
    t.skip(msg);
    return;
  }
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 't6-dirty-'));
  try {
    const repo = path.join(tmp, 'dvaa');
    execFileSync('git', ['clone', '-q', '--no-checkout', '--shared', real.root, repo]);
    gitIn(repo, 'checkout', '-q', DVAA_PIN);
    const marker = path.join(tmp, 'IMPORTED');
    // (a) modified tracked file
    const vuln = path.join(repo, 'src/core/vulnerabilities.js');
    fs.appendFileSync(vuln, `\nimport fs_ from 'node:fs'; fs_.writeFileSync(${JSON.stringify(marker)}, 'x');\n`);
    await assert.rejects(loadBaseline({ DVAA_SRC: repo }), /refusing to import DVAA code .*tree not clean/);
    assert.equal((await verifyUpstream({ DVAA_SRC: repo })).find((r) => r.source === 'DVAA').status, 'mismatch');
    gitIn(repo, 'checkout', '-q', '--', '.');
    // (b) untracked file only
    fs.writeFileSync(path.join(repo, 'src/core/extra.js'), 'export {};\n');
    await assert.rejects(loadBaseline({ DVAA_SRC: repo }), /tree not clean/);
    fs.rmSync(path.join(repo, 'src/core/extra.js'));
    // (c) clean again -> accepted
    const ok = await loadBaseline({ DVAA_SRC: repo });
    assert.equal(ok.source, 'dvaa-real');
    assert.equal(ok.commit, DVAA_PIN);
    assert.equal(fs.existsSync(marker), false, 'modified code must never be imported');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// ---- Verifier checks the pinned commits (review L2) ---------------------------------------------
test('L2 verify-upstream rejects AgentDojo / InjecAgent clones not at the pinned commit', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 't6-pin-'));
  try {
    const marker = path.join(tmp, 'IMPORTED');
    const repo = path.join(tmp, 'clone');
    fs.mkdirSync(repo);
    plantedCheckout(repo, marker);
    const res = await verifyUpstream({ DVAA_SRC: 'replica', AGENTDOJO_SRC: repo, INJECAGENT_SRC: repo });
    for (const name of ['AgentDojo', 'InjecAgent']) {
      const r = res.find((x) => x.source === name);
      assert.equal(r.status, 'mismatch', `${name}: ${r.detail}`);
      assert.match(r.detail, /expected pinned/);
    }
    const ne = await verifyUpstream({ DVAA_SRC: 'replica', AGENTDOJO_SRC: path.join(tmp, 'nope') });
    assert.equal(ne.find((x) => x.source === 'AgentDojo').status, 'mismatch', 'non-git path is a mismatch');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('L2 deepset: rows file is checked against the pinned parquet sha256 when DEEPSET_PARQUET is set', async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 't6-deepset-'));
  try {
    const rows = path.join(tmp, 'rows.jsonl');
    fs.writeFileSync(rows, Object.entries(DEEPSET.rows).map(([idx, r]) => JSON.stringify({ idx: Number(idx), ...r })).join('\n') + '\n');
    const pq = path.join(tmp, 'test.parquet');
    fs.writeFileSync(pq, 'not the pinned parquet');
    const deep = async (env) => (await verifyUpstream({ DVAA_SRC: 'replica', ...env })).find((r) => r.source === 'deepset/prompt-injections');
    assert.equal((await deep({ DEEPSET_ROWS: rows })).status, 'ok');
    const bad = await deep({ DEEPSET_ROWS: rows, DEEPSET_PARQUET: pq });
    assert.equal(bad.status, 'mismatch');
    assert.match(bad.detail, /parquet sha256/);
    assert.match(DEEPSET.parquetSha256, /^[0-9a-f]{64}$/);
    assert.match(DEEPSET.parquetFile, /^data\/test-.*\.parquet$/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// ---- T6b: the verifier catches a changed upstream string (not just a missing source) -------------
test('T6b verify-upstream: a deepset rows file that differs from the committed extract is a MISMATCH', async () => {
  const { DEEPSET_ALL } = await import('../tools/upstream-cases.mjs');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 't6b-rows-'));
  const rowsFile = path.join(dir, 'rows.jsonl');
  const write = (rows) => fs.writeFileSync(rowsFile, rows.map((r) => JSON.stringify(r)).join('\n') + '\n');
  try {
    write(DEEPSET_ALL.rows);
    const ok = (await verifyUpstream({ DEEPSET_ROWS: rowsFile })).find((r) => r.source.startsWith('deepset'));
    assert.equal(ok.status, 'ok', ok.detail);
    // flip one T6b row (not one of T6's original three) by one character
    write(DEEPSET_ALL.rows.map((r) => (r.idx === 101 ? { ...r, text: r.text + ' ' } : r)));
    const bad = (await verifyUpstream({ DEEPSET_ROWS: rowsFile })).find((r) => r.source.startsWith('deepset'));
    assert.equal(bad.status, 'mismatch');
    assert.match(bad.detail, /row 101/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
