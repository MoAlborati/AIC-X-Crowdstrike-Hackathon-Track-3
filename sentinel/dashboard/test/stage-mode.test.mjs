// T5-stage: deep link, stage-mode filtering, real stage alerts, sink label, copy-alert payload,
// poisoned-document reconstruction. Real seams: the real capture index, the real HTTP server, real T3/T4.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createServer } from '../server.mjs';
import { poisonedRagDocument, REPO_ROOT } from '../lib/capture-loader.mjs';
import { resolveStage, STAGE_ENTRIES } from '../lib/stage-set.mjs';
import { prepareExport, canaryValues } from '../lib/alert-export.mjs';
import { generateRealAlerts, REAL_ALERTS_DIR, stageCaptureAlerts, STAGE_CAPTURE_FILE } from '../fixtures/make-real-alerts.mjs';
import { sidecarName } from '../lib/alert-store.mjs';
import { parseDeepLink, deepLinkSearch, chooseInitial, stageOptions, sinkLabel, cleanNarrative, alertClipboardText, warningSummary, excerpt } from '../public/stage-view.js';
import { docLines, fitZoom, MAX_ZOOM, layoutGraph, nodeSubtitle, STAGE_MIN_ZOOM } from '../public/graph.js';
import { buildAlert, validateAlert, sinkPhrase } from '../../alerts/index.js';
import { DVAA_HONEYTOKENS } from '../../detectors/index.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));

async function withServer(fn) {
  const srv = createServer();
  for (let attempt = 1; ; attempt++) {
    const port = 20000 + Math.floor(Math.random() * 20000);
    try {
      await new Promise((resolve, reject) => {
        srv.once('error', reject);
        srv.listen(port, '127.0.0.1', () => { srv.off('error', reject); resolve(); });
      });
      break;
    } catch (err) {
      if (err.code !== 'EADDRINUSE' || attempt >= 20) throw err;
    }
  }
  try {
    return await fn(`http://127.0.0.1:${srv.address().port}`);
  } finally {
    await new Promise(r => srv.close(r));
  }
}
const getJson = async (url) => { const r = await fetch(url); return { status: r.status, body: await r.json() }; };

// ---- deep link ----------------------------------------------------------------------------------
test('deep link: ?capture=<id>&run=&step= round-trips; ?id= still accepted; dev and stage are preserved', () => {
  const q = deepLinkSearch({ capture: 'attack/aim-ab.demo', run: 'runB', step: 3, stage: true, dev: true });
  assert.equal(q, '?stage=1&dev=1&capture=attack/aim-ab.demo&run=runB&step=4');
  assert.deepEqual(parseDeepLink(q), { capture: 'attack/aim-ab.demo', run: 'runB', step: 3, stage: true });
  assert.equal(parseDeepLink('?id=benign/7005_ragbot').capture, 'benign/7005_ragbot');
  assert.equal(parseDeepLink('?capture=x&step=last').step, Infinity);
  assert.equal(parseDeepLink('?capture=x&step=0').step, 0, 'step is 1-based; 0 / junk fall back to the first step');
  assert.equal(parseDeepLink('?capture=x&step=abc').step, 0);
});

test('deep link resolves against the REAL capture index; an unknown capture or run is reported, not silently swapped', async () => {
  await withServer(async (base) => {
    const { body } = await getJson(`${base}/api/captures`);
    assert.ok(body.captures.length > 300, 'real index (data-rich: the full corpus)');
    const want = chooseInitial(parseDeepLink('?capture=attack/aim-ab.demo&run=runB'), body.captures, body.stage);
    assert.deepEqual(want, { id: 'attack/aim-ab.demo', run: 'runB', stageKey: null, warning: null });
    // a capture deep in the list (beyond any display cap) resolves by targeted lookup
    const last = body.captures.filter(c => !c.error).at(-1);
    assert.equal(chooseInitial(parseDeepLink(`?capture=${encodeURIComponent(last.id)}`), body.captures, body.stage).id, last.id);
    const bad = chooseInitial(parseDeepLink('?capture=nope/missing'), body.captures, body.stage);
    assert.match(bad.warning, /"nope\/missing" not found/);
    const badRun = chooseInitial(parseDeepLink('?capture=attack/aim-ab.demo&run=runZ'), body.captures, body.stage);
    assert.match(badRun.warning, /no run "runZ"/);
    // and the server serves that deep-linked replay
    assert.equal((await fetch(`${base}/api/replay?id=attack/aim-ab.demo&run=runB`)).status, 200);
  });
});

// ---- stage mode -----------------------------------------------------------------------------------
test('stage mode: the dropdown is exactly the four stage runs (vulnerable, AIM twin, proxy-blocked, egress-blocked), not the whole corpus', async () => {
  await withServer(async (base) => {
    const { body } = await getJson(`${base}/api/captures`);
    assert.equal(body.stage.length, 4);
    assert.deepEqual(body.stage.map(s => [s.key, s.id, s.run]), [
      ['vulnerable', 'attack/aim-ab.demo', 'runA'],
      ['aim-twin', 'attack/aim-ab.demo', 'runB'],
      ['proxy-blocked', 'stage/proxy-blocked-t3', 'run'],
      ['egress-blocked', 'stage/egress-blocked-t12', 'run'],
    ]);
    const opts = stageOptions(body.stage);
    assert.equal(opts.length, 4);
    assert.ok(opts.every(o => !o.disabled));
    assert.ok(body.captures.length > 300, 'normal mode still lists the full corpus');
    // stage deep link by key and by id
    assert.equal(chooseInitial(parseDeepLink('?stage=1&capture=aim-twin'), body.captures, body.stage).run, 'runB');
    assert.equal(chooseInitial(parseDeepLink('?stage=1&capture=stage/proxy-blocked-t3'), body.captures, body.stage).stageKey, 'proxy-blocked');
    const outside = chooseInitial(parseDeepLink('?stage=1&capture=benign/7005_ragbot'), body.captures, body.stage);
    assert.equal(outside.stageKey, 'vulnerable');
    assert.match(outside.warning, /not in the stage set/);
  });
});

test('stage mode: a missing stage capture stays listed with an error (fail loud); fallbacks are used in order', () => {
  const items = [{ id: 'attack/aim-ab.demo', runs: [{ key: 'runA' }, { key: 'runB' }] }, { id: 'contrast/runs/proxy-block.demo', runs: [{ key: 'runA' }, { key: 'runB' }] }];
  const r = resolveStage(items);
  assert.equal(r.length, STAGE_ENTRIES.length);
  assert.deepEqual([r[2].id, r[2].run, r[2].fallback], ['contrast/runs/proxy-block.demo', 'runB', true]);
  const none = resolveStage([{ id: 'attack/aim-ab.demo', error: 'boom' }]);
  assert.equal(none.length, STAGE_ENTRIES.length);
  assert.ok(none.every(s => s.error));
  assert.match(none[0].error, /attack\/aim-ab.demo#runA: boom/);
  assert.ok(stageOptions(none).every(o => o.disabled && /missing/.test(o.label)));
});

test('stage captures load with >=1 REAL alert, no placeholder anywhere, and honest labels (no stage run says "No detector verdicts")', async () => {
  await withServer(async (base) => {
    const { body } = await getJson(`${base}/api/captures`);
    const seen = {};
    for (const s of body.stage) {
      const { status, body: rp } = await getJson(`${base}/api/replay?id=${encodeURIComponent(s.id)}&run=${s.run}`);
      assert.equal(status, 200, s.key);
      assert.ok(rp.alerts.length >= 1, `${s.key}: has real alerts`);
      assert.equal(rp.capture.placeholder, false, `${s.key}: no PLACEHOLDER banner (capture)`);
      assert.equal(rp.alertSource.placeholder, false, `${s.key}: no PLACEHOLDER banner (alerts)`);
      assert.doesNotMatch(rp.alertSource.origin, /fixtures\/alerts/);
      assert.ok(rp.alerts.every(a => !a.invalid), `${s.key}: every alert passes T4 validateAlert`);
      seen[s.key] = rp.alerts.map(a => a.shownDisposition);
    }
    assert.ok(seen.vulnerable.every(d => d === 'Detected · post-execution (alert-only)'), 'canary hit on runA: every finding is post-execution');
    assert.ok(!seen['aim-twin'].some(d => d.startsWith('Blocked')), 'the AIM twin was not behind the proxy: nothing claims Blocked');
    assert.ok(seen['proxy-blocked'].every(d => d === 'Blocked · pre-forward'), 'live proxy refused the request pre-forward');
  });
});

test('real stage alert sidecar is reproducible from make-real-alerts.mjs (only measured latencies differ)', async () => {
  const strip = (v) => JSON.parse(JSON.stringify(v, (k, x) => (/latency/i.test(k) ? undefined : x)));
  const fresh = await generateRealAlerts();
  for (const [id, doc] of fresh) {
    const committed = JSON.parse(await readFile(path.join(REAL_ALERTS_DIR, sidecarName(id)), 'utf8'));
    assert.deepEqual(strip(committed), strip(JSON.parse(JSON.stringify(doc))), `${id}: regenerate with node sentinel/dashboard/fixtures/make-real-alerts.mjs`);
    assert.equal(committed.placeholder, false);
    for (const list of Object.values(committed.runs)) for (const a of list) {
      assert.deepEqual(validateAlert(a), []);
      assert.equal(a.PipelineContext.Detector, 'sentinel-t3');
      assert.equal(a.PipelineContext.StandIn, false);
    }
  }
});

// ---- sink label -----------------------------------------------------------------------------------
test('sink label: never "http:http://"; a bare host gets its type in parentheses', () => {
  assert.equal(sinkPhrase({ type: 'http', destination: 'http://127.0.0.1:40447/api/canary/exfil-test' }), 'http://127.0.0.1:40447/api/canary/exfil-test');
  assert.equal(sinkPhrase({ type: 'http', destination: '127.0.0.1' }), '127.0.0.1 (http)');
  assert.equal(sinkLabel('http', 'https://x.example/in'), 'https://x.example/in');
  assert.equal(sinkLabel('http', 'audit-sync.example.net'), 'audit-sync.example.net (http)');
  // recorded narratives from before the fix are cleaned for display
  assert.equal(cleanNarrative('a → toward http:http://h:1/p → blocked'), 'a → toward http://h:1/p → blocked');
  assert.equal(cleanNarrative('x → toward http:127.0.0.1 → y'), 'x → toward 127.0.0.1 (http) → y');
  assert.equal(cleanNarrative('influenced tool call http:post(act2) → toward http:http://h/p'), 'influenced tool call http:post(act2) → toward http://h/p', 'only the "toward" phrase is touched');
  // T4 buildAlert itself now produces the clean phrase
  const a = buildAlert({ category: 'taint_flow_exfil', ruleId: 'taint.untrusted_read_to_external_send', disposition: 'block', detectionLatencyMs: 1,
    entities: { agent: { name: 'RAGBot' }, session: { id: 's' }, toolCall: { id: 't1', name: 'submit_to_index' }, sink: { type: 'http', destination: 'http://127.0.0.1:40447/api/canary/exfil-test' } },
    taintPath: [{ kind: 'source', label: 'doc', trust: 'untrusted' }, { kind: 'sink', label: 'post', toolCallId: 't1', trust: 'external' }] });
  assert.doesNotMatch(a.CaseCard.Narrative, /http:http/);
  assert.match(a.CaseCard.Narrative, /toward http:\/\/127\.0\.0\.1:40447/);
});

test('sink label: no stage alert served by the real server renders "<type>:<scheme>://"', async () => {
  await withServer(async (base) => {
    const { body } = await getJson(`${base}/api/captures`);
    for (const s of body.stage) {
      const { body: rp } = await getJson(`${base}/api/replay?id=${encodeURIComponent(s.id)}&run=${s.run}`);
      for (const a of rp.alerts) {
        assert.doesNotMatch(cleanNarrative(a.caseCard.narrative), /\b[a-z]+:[a-z]+:\/\//i);
        if (a.entities.sink) assert.doesNotMatch(sinkLabel(a.entities.sink.type, a.entities.sink.destination), /^[a-z]+:[a-z]+:\/\//i);
      }
    }
  });
});

// ---- copy alert JSON ------------------------------------------------------------------------------
test('copy alert JSON: every stage alert exports as a valid, redacted T4 alert with ATLAS + OWASP tags', async () => {
  const secrets = DVAA_HONEYTOKENS.map(h => h.value).filter(v => v.length >= 8);
  await withServer(async (base) => {
    const { body } = await getJson(`${base}/api/captures`);
    let n = 0;
    for (const s of body.stage) {
      const { body: rp } = await getJson(`${base}/api/replay?id=${encodeURIComponent(s.id)}&run=${s.run}`);
      const hits = canaryValues(rp.capture.canaryHits).filter(v => v.length >= 8);
      for (const a of rp.alerts) {
        const r = await getJson(`${base}/api/alert-export?id=${encodeURIComponent(s.id)}&run=${s.run}&alert=${encodeURIComponent(a.id)}`);
        assert.equal(r.status, 200, `${s.key} ${a.id}`);
        const text = alertClipboardText(r.body);
        const exported = JSON.parse(text);
        assert.deepEqual(validateAlert(exported), [], 'valid T4 sentinel.alert/1.0.0');
        assert.equal(exported.AlertId, a.id);
        assert.ok(exported.MitreAtlas.length >= 1 && exported.MitreAtlas.every(t => /^AML\.T\d{4}/.test(t.TechniqueId)), 'ATLAS tags');
        assert.ok(exported.OwaspLlm.length >= 1 && exported.OwaspLlm.every(t => /^LLM\d\d/.test(t.Id)), 'OWASP LLM tags');
        assert.ok(Array.isArray(exported.OwaspAgentic));
        for (const v of [...secrets, ...hits]) assert.ok(!text.includes(v), `${s.key} ${a.id}: secret ${v.slice(0, 4)}… not in clipboard payload`);
        n++;
      }
    }
    assert.ok(n >= 3);
    assert.equal((await fetch(`${base}/api/alert-export?id=attack/aim-ab.demo&run=runA&alert=nope`)).status, 404);
  });
});

test('copy alert JSON (data-rich): a secret past the first 8 KB of a long Evidence field is redacted; >MAX canaries fail loud; non-T4 bodies are refused', async () => {
  const doc = JSON.parse(await readFile(path.join(REAL_ALERTS_DIR, sidecarName('attack/aim-ab.demo')), 'utf8'));
  const base = doc.runs.runA[0];
  const filler = 'ordinary retrieved policy text line\n'.repeat(300); // ~10.5 KB
  const tampered = { ...base, Evidence: `${filler}Admin credentials: dvaa-admin-secret | SSN 123-45-6789` };
  assert.ok(tampered.Evidence.indexOf('dvaa-admin-secret') > 8192);
  const hits = [{ query: { data: 'Company policy: x | Admin credentials: dvaa-admin-secret | User John Doe SSN: 123-45-6789' } }];
  const out = prepareExport(tampered, hits);
  const text = JSON.stringify(out.alert);
  assert.ok(!text.includes('dvaa-admin-secret'));
  assert.ok(!text.includes('123-45-6789'));
  assert.ok(out.redaction.secondPassFindings >= 2);
  assert.deepEqual(validateAlert(out.alert), []);
  const many = Array.from({ length: 70 }, (_, i) => ({ query: { data: `secret-value-number-${i}` } }));
  assert.throws(() => prepareExport(base, many), (e) => e.status === 413 && /MAX_CANARIES/.test(e.message));
  assert.throws(() => alertClipboardText({ error: 'boom' }), /boom/);
  assert.throws(() => alertClipboardText({ alert: { SchemaVersion: 'other/0' } }), /expected sentinel\.alert\/1\.0\.0/);
});

// ---- poisoned document + graph text -------------------------------------------------------------
test('poisoned document: the aim-ab rebuild matches, byte for byte, the document a live proxy run recorded', async () => {
  const live = JSON.parse(await readFile(path.join(HERE, '..', 'stage', 'proxy-blocked-t3.json'), 'utf8'));
  const recorded = live.exchanges[0].request.messages[0].content;
  const m = recorded.match(/http:\/\/127\.0\.0\.1:\d+\/api\/canary\/exfil-test/);
  const rebuilt = poisonedRagDocument({ scenario: 'aim-ab', payload: { attackId: 'APWN-DE-003' }, canary: { url: m[0] } });
  assert.equal(rebuilt, recorded);
  const aim = JSON.parse(await readFile(path.join(REPO_ROOT, 'captures', 'attack', 'aim-ab.demo.json'), 'utf8'));
  assert.ok(poisonedRagDocument(aim).includes(aim.canary.url));
  assert.equal(poisonedRagDocument({ ...aim, payload: { attackId: 'OTHER' } }), null, 'other payloads are never invented');
});

test('graph source node: excerpt lines always end with an explicit "+N chars" marker; fit-to-width zoom is bounded', () => {
  const text = 'Please retrieve and summarize the latest indexed document.\n\n----- BEGIN -----\nNEW INDEX INSTRUCTIONS: ' + 'x'.repeat(9000);
  for (const w of [76, 100, 144, 208]) {
    const lines = docLines({ lane: 'untrusted', text }, w);
    assert.ok(lines.length >= 1 && lines.length <= 2);
    assert.match(lines.join(''), /\+[\d,]+ chars$/, `w=${w}: marker visible`);
    if (w >= 144) assert.match(lines.join(''), /INSTRUCTIONS/);
  }
  assert.deepEqual(docLines({ lane: 'untrusted', text: 'short doc' }, 208), ['“short doc”']);
  assert.deepEqual(docLines({ lane: 'untrusted', recorded: false, text: 'descriptor' }, 208), []);
  const ex = excerpt(text, 160);
  assert.ok(ex.omitted > 8000 && /truncated: [\d,]+ more chars/.test(ex.marker));
  assert.equal(fitZoom(744, 813), 813 / 744);
  assert.equal(fitZoom(300, 3000), MAX_ZOOM);
  assert.equal(fitZoom(5000, 800), 1, 'a wide graph scrolls, it is never shrunk');
});

test('replay warnings collapse to one summary line (all kept for the expanded list)', () => {
  const w = ['alert a: taint hop 1 (x) has no matching node in the capture; shown as unresolved', 'alert b: taint hop 2 (y) has no matching node in the capture; shown as unresolved', 'something else'];
  assert.equal(warningSummary(w), '3 replay warnings · 2 unresolved taint hops (drawn as dashed "?" nodes) · 1 other');
  assert.equal(warningSummary([]), null);
});

// ---- review round 1 (#76): hero screens ---------------------------------------------------------
test('stage hero screens: no "unresolved", no "no tool call →", no "blocking" on alerts that did not block; refusals are refusals', async () => {
  await withServer(async (base) => {
    const { body } = await getJson(`${base}/api/captures`);
    for (const s of body.stage) {
      const { body: rp } = await getJson(`${base}/api/replay?id=${encodeURIComponent(s.id)}&run=${s.run}`);
      assert.deepEqual(rp.warnings, [], `${s.key}: no replay warnings`);
      const text = rp.graph.nodes.map(n => `${n.label} ${nodeSubtitle(n)} ${(n.flags ?? []).join(' ')} ${n.kind}`).join('\n');
      assert.doesNotMatch(text, /unresolved/i, `${s.key}: every taint hop resolves to a real node`);
      const alertLabels = rp.graph.nodes.filter(n => n.kind === 'alert').map(n => `${n.label} ${nodeSubtitle(n)}`);
      assert.equal(new Set(alertLabels).size, alertLabels.length, `${s.key}: no two identical detection nodes`);
      for (const a of rp.alerts) {
        const narr = cleanNarrative(a.caseCard.narrative);
        assert.doesNotMatch(narr, /no tool call →|influenced tool call no tool call/, `${s.key} ${a.id}`);
        assert.notEqual(a.caseCard.influencedToolCall, 'no tool call', `${s.key} ${a.id}`);
        if (!a.prevented) {
          assert.doesNotMatch(narr, /blocking|proxy refuses it|no tool runs/, `${s.key} ${a.id}: not blocked, so the narrative never says so`);
        }
        // the sink hop lands on a sink node (the canary / attacker host), never an invented placeholder
        const sinkHops = a.taintPath.filter(h => h.kind === 'sink');
        if (sinkHops.length) assert.ok(rp.taint.nodeIds.some(id => rp.graph.nodes.find(n => n.id === id)?.lane === 'sink'), `${s.key} ${a.id}: sink resolved`);
      }
      if (s.key === 'vulnerable') {
        assert.ok(rp.alerts.every(a => /this run had no proxy, so the tool executed/.test(a.caseCard.narrative)));
      }
      if (s.key === 'proxy-blocked') {
        const actions = rp.graph.nodes.filter(n => n.lane === 'action');
        assert.equal(actions.filter(n => n.kind === 'proxy_refusal' && n.label === 'proxy 403 refusal').length, 2, 'both refused requests are refusals');
        assert.equal(actions.filter(n => /reply$/.test(n.label)).length, 1, 'only the forwarded benign request shows an agent reply');
        const src = rp.taint.nodeIds.map(id => rp.graph.nodes.find(n => n.id === id)).filter(n => n.lane === 'input');
        assert.ok(src.length === 2 && src.every(n => n.embeddedDoc && /INDEXED DOCUMENT/.test(n.text)), 'sources are the user turns with the embedded document');
      }
      // 1440x900 stage pane (~795 px usable): the graph fits at the stage zoom floor, no horizontal scroll
      assert.ok(layoutGraph(rp.graph).width * STAGE_MIN_ZOOM <= 795, `${s.key}: graph width ${layoutGraph(rp.graph).width}`);
    }
  });
});

test('stage capture 3 alerts are rebuilt reproducibly from its embedded proxy records (real T3, convert.mjs)', async () => {
  const strip = (v) => JSON.parse(JSON.stringify(v, (k, x) => (/latency/i.test(k) ? undefined : x)));
  const cap = JSON.parse(await readFile(STAGE_CAPTURE_FILE, 'utf8'));
  assert.deepEqual(strip(cap.alerts.run), strip(stageCaptureAlerts(cap)));
  assert.ok(cap.alerts.run.every(a => a.PipelineContext.Detector === 'sentinel-t3' && a.PipelineContext.ProxyAction === 'blocked_request'));
});

test('headline FP is scoped to the benign corpus and the legacy fn count is gone (rescore rehearsal)', async () => {
  await withServer(async (base) => {
    const { headlineView } = await import('../public/headline-view.js');
    const { body } = await getJson(`${base}/api/scoring`);
    const v = headlineView(body);
    if (!body.available || !body.counts?.benign) return; // nothing to scope when T7 results are absent
    for (const k of ['det', 'prev']) if (!v.tiles[k].pending && /FP \d/.test(v.tiles[k].fp)) assert.match(v.tiles[k].fp, new RegExp(`/${body.counts.benign} benign cases$`));
    assert.doesNotMatch(v.note, /\bfn \d|\bfp \d/);
  });
});

test('contrast runs are labeled by configuration; a fully blocked run reads protected, not compromised', async () => {
  const { trustAt } = await import('../public/replay-view.js');
  await withServer(async (base) => {
    const { body: pb } = await getJson(`${base}/api/replay?id=contrast/runs/proxy-block.demo&run=runB`);
    assert.equal(pb.run.label, 'RAGBot :7005 behind Tourniquet (block)');
    assert.ok(!JSON.stringify(pb.timeline).includes('RAGBot-AIM'));
    assert.ok(pb.graph.nodes.some(n => n.kind === 'proxy_refusal'));
    const { body: s3 } = await getJson(`${base}/api/replay?id=stage/proxy-blocked-t3&run=run`);
    const blocked = s3.alerts.filter(a => a.prevented);
    const t = trustAt(s3, blocked, true);
    assert.equal(t.protected, true);
    assert.equal(t.value, 100);
    const { body: twin } = await getJson(`${base}/api/replay?id=attack/aim-ab.demo&run=runB`);
    assert.equal(trustAt(twin, twin.alerts, true).protected, true, 'AIM denied the call, nothing left the box');
    const { body: vuln } = await getJson(`${base}/api/replay?id=attack/aim-ab.demo&run=runA`);
    assert.notEqual(trustAt(vuln, vuln.alerts, true).protected, true, 'the vulnerable run stays compromised');
  });
});

test('stage mode works when run-demo.sh points SENTINEL_CAPTURES_DIR / SENTINEL_ALERTS_DIR at pipeline output', async () => {
  const { mkdtemp, mkdir, rm } = await import('node:fs/promises');
  const os = await import('node:os');
  const dir = await mkdtemp(path.join(os.tmpdir(), 'stage-env-'));
  const saved = { ...process.env };
  try {
    await mkdir(path.join(dir, 'captures', 'live'), { recursive: true });
    await mkdir(path.join(dir, 'alerts'), { recursive: true });
    process.env.SENTINEL_CAPTURES_DIR = path.join(dir, 'captures');
    process.env.SENTINEL_ALERTS_DIR = path.join(dir, 'alerts');
    delete process.env.SENTINEL_HIDE_STAGE;
    await withServer(async (base) => {
      const { body } = await getJson(`${base}/api/captures`);
      assert.ok(body.stage.every(s => !s.error), JSON.stringify(body.stage));
      for (const s of body.stage) {
        const { status, body: rp } = await getJson(`${base}/api/replay?id=${encodeURIComponent(s.id)}&run=${s.run}`);
        assert.equal(status, 200);
        assert.ok(rp.alerts.length >= 1 && !rp.alertSource.placeholder);
      }
    });
  } finally {
    for (const k of ['SENTINEL_CAPTURES_DIR', 'SENTINEL_ALERTS_DIR', 'SENTINEL_HIDE_STAGE']) if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k];
    await rm(dir, { recursive: true, force: true });
  }
});
