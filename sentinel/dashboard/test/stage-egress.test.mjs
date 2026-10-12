// Stage capture 4 (egress guard, block mode): sentinel/dashboard/stage/egress-blocked-t12.json, generated
// by scripts/stage-egress-capture.sh from a real scripts/egress-demo.sh block run. Real seams: the real
// capture index, the real HTTP server, the committed pipeline alerts, the deployment honeytokens.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createServer } from '../server.mjs';
import { STAGE_ENTRIES } from '../lib/stage-set.mjs';
import { STAGE_LABEL } from '../lib/stage.mjs';
import { parseDeepLink, chooseInitial, cleanNarrative } from '../public/stage-view.js';
import { nodeSubtitle } from '../public/graph.js';
import { loadEgressHoneytokens } from '../../pipeline/egress.mjs';
import { DVAA_HONEYTOKENS } from '../../detectors/index.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FILE = path.join(HERE, '..', 'stage', 'egress-blocked-t12.json');
const ID = 'stage/egress-blocked-t12';

async function withServer(fn) {
  const srv = createServer();
  await new Promise((resolve) => srv.listen(0, '127.0.0.1', resolve));
  try { return await fn(`http://127.0.0.1:${srv.address().port}`); } finally { await new Promise(r => srv.close(r)); }
}
const getJson = async (url) => { const r = await fetch(url); return { status: r.status, body: await r.json() }; };

test('stage 4 is registered: key egress-blocked, deep link ?stage=1&capture=egress-blocked (and by id)', async () => {
  const e = STAGE_ENTRIES.at(-1);
  assert.equal(e.key, 'egress-blocked');
  assert.equal(e.label, '4 · Tool boundary: egress guard denied the exfil (attacker received nothing)');
  await withServer(async (base) => {
    const { body } = await getJson(`${base}/api/captures`);
    const s = body.stage.find(x => x.key === 'egress-blocked');
    assert.deepEqual([s.id, s.run, s.error], [ID, 'run', undefined]);
    for (const q of ['?stage=1&capture=egress-blocked', `?stage=1&capture=${ID}`, `?capture=${ID}`]) {
      const pick = chooseInitial(parseDeepLink(q), body.captures, body.stage);
      assert.deepEqual([pick.id, pick.run, pick.warning], [ID, 'run', null], q);
    }
  });
});

test('stage 4 loads with >=1 preventive egress alert shown as "Blocked · egress (denied before send)"; no unresolved/placeholder text', async () => {
  await withServer(async (base) => {
    const { status, body: rp } = await getJson(`${base}/api/replay?id=${encodeURIComponent(ID)}&run=run`);
    assert.equal(status, 200);
    assert.deepEqual(rp.warnings, []);
    assert.equal(rp.capture.placeholder, false);
    assert.equal(rp.alertSource.placeholder, false);
    assert.ok(rp.alerts.length >= 1);
    assert.ok(rp.alerts.some(a => a.ruleId === 'egress.honeytoken_match'), 'the honeytoken exfil itself was denied');
    for (const a of rp.alerts) {
      assert.equal(a.invalid, false, a.id);
      assert.equal(a.stage, 'prevented_egress', a.id);
      assert.equal(a.shownDisposition, 'Blocked · egress (denied before send)', a.id);
      assert.equal(a.shownDisposition, STAGE_LABEL.prevented_egress);
      assert.match(cleanNarrative(a.caseCard.narrative), /denied_before_send_bytes_never_left/);
    }
    // Every taint source resolves to a recorded user turn (one per driven agent turn), never a stub.
    const nodes = new Map(rp.graph.nodes.map(n => [n.id, n]));
    const srcs = rp.taint.nodeIds.map(id => nodes.get(id)).filter(n => n.lane === 'input');
    assert.equal(srcs.length, 2, 'RAGBot and RepoBot turns');
    assert.ok(srcs.every(n => n.kind === 'user_message' && !/^\[/.test(n.text)));
    const text = rp.graph.nodes.map(n => `${n.label} ${nodeSubtitle(n)} ${(n.flags ?? []).join(' ')} ${n.kind} ${n.text ?? ''}`).join('\n');
    assert.doesNotMatch(text, /unresolved|placeholder|not recorded|no exchange recorded|tool-boundary egress incident:/i);
    // Ground truth: the attacker received nothing, so no canary-hit node and no "post-execution" claim.
    assert.ok(!rp.graph.nodes.some(n => n.kind === 'canary_hit'));
    assert.ok(!rp.alerts.some(a => /post-execution/.test(a.shownDisposition)));
  });
});

test('stage 4 file: real block run provenance, no honeytoken value anywhere', async () => {
  const raw = await readFile(FILE, 'utf8');
  const doc = JSON.parse(raw);
  assert.ok(doc.provenance.demoResult.includes('EGRESS DEMO: PASS'));
  assert.match(doc.provenance.groundTruth, /0 CANARY_HIT/);
  assert.ok(doc.alerts.run.every(a => a.PipelineContext.Direction === 'egress' && a.PipelineContext.Preventive === true && a.PipelineContext.ProxyMode === 'block'));
  const values = [...loadEgressHoneytokens(), ...DVAA_HONEYTOKENS].map(h => h.value).filter(v => typeof v === 'string' && v.length >= 6);
  assert.ok(values.length >= 2, 'honeytoken list loaded');
  for (const v of values) assert.ok(!raw.includes(v), `honeytoken value leaked into the stage file (${v.length} chars)`);
  // Case cards name the agent turn in flight (same turn the graph resolves the source hop to), never "unattributed".
  assert.doesNotMatch(raw, /unattributed/i);
  for (const a of doc.alerts.run) {
    const turn = doc.exchanges.find(e => { const at = Date.parse(a.Timestamp); return at >= e.sentinel.turnWindow.t0 && at <= e.sentinel.turnWindow.t1; });
    assert.equal(a.CaseCard.OriginatedIn, `${turn.sentinel.agent} agent turn (in flight when the call was denied)`);
  }
});
