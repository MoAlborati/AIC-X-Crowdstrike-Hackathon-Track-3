// T7 corpus loader: turns T1 captures (captures/attack, captures/benign) and the T6 labeled corpus
// (captures/variants/manifest.json) into one list of normalized, labeled cases.
//
// Normalized case:
//   { id, source: 't1-capture'|'t6-variant', group, channel, agent,
//     groundTruth: 'positive'|'negative', labelBasis, dvaa: {exfilAttempted, exfilExecuted, exfilTargetUrl},
//     evadesBaseline: true|false|null,
//     request: { messages: [{role, content}] },
//     response: { content, toolCalls: [{id, name, arguments}] } | null,
//     notes }
//
// Labeling rule. T1 captures: a case is POSITIVE iff the data-exfil action was ATTEMPTED
// (dvaa.exfilAttempted === true). T6 cases: label.groundTruth is used as-is; it includes injection-only
// positives with no exfil attempt (deepset prompt-injection, e.g. DS-PI-001), so the harness reports recall
// split exfil vs injection-only (recallByPositiveKind). The AIM-defended twin runs in
// T1 (runB / beat3) are therefore positives: the agent still tried to send the data, AIM denied it at
// egress. A proxy in front of the agent sees that attempt, so blocking it is a true positive, not a false
// one. `dvaa.exfilExecuted` is kept on every case so the execution-based label can be recomputed.
//
// Everything that cannot be labeled or replayed is fatal (CorpusError), except cases whose capture has
// no observable attempt payload. Those are listed in `excluded` with a reason, never dropped silently.

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { enforce, CorpusError } from './bounds.mjs';

export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

function readJson(file) {
  enforce('MAX_FIXTURE_BYTES', statSync(file).size, file);
  try {
    return JSON.parse(readFileSync(file, 'utf8'));
  } catch (err) {
    throw new CorpusError(`${file}: invalid JSON (${err.message})`);
  }
}

const rel = (root, f) => path.relative(root, f).split(path.sep).join('/');

function labelFromDvaa(dvaa, where) {
  if (dvaa == null) return { groundTruth: 'negative', labelBasis: 'no dvaa{} block (benign turn)' };
  if (typeof dvaa.exfilAttempted !== 'boolean') throw new CorpusError(`${where}: dvaa.exfilAttempted is not boolean`);
  return {
    groundTruth: dvaa.exfilAttempted ? 'positive' : 'negative',
    labelBasis: `dvaa.exfilAttempted=${dvaa.exfilAttempted}`,
  };
}

function normDvaa(d) {
  return {
    exfilAttempted: d?.exfilAttempted ?? false,
    exfilExecuted: d?.exfilExecuted ?? null,
    exfilTargetUrl: d?.exfilTargetUrl ?? null,
  };
}

function toolCallsFromOpenAI(calls = []) {
  return calls.map((c) => ({ id: c.id ?? null, name: c.function?.name ?? c.name, arguments: c.function?.arguments ?? c.arguments ?? '' }));
}

function toolCallsFromLedger(ledger = []) {
  return ledger.map((e, i) => ({ id: `ledger-${i}`, name: e.action, arguments: JSON.stringify({ target: e.target }) }));
}

function exfilFromLedger(ledger, where) {
  if (!Array.isArray(ledger)) throw new CorpusError(`${where}: missing ledger[]`);
  const sends = ledger.filter((e) => /^http:(post|put)|^net:send|^email:send/.test(e.action));
  return {
    exfilAttempted: sends.length > 0,
    exfilExecuted: sends.length > 0 ? sends.some((e) => e.executed === true) : null,
    exfilTargetUrl: sends[0]?.target?.split('?')[0] ?? null,
  };
}

// --- T1 attack demo captures -------------------------------------------------------------------
// Each scenario's runs, agent ports from captures/README.md. Unknown scenario => fatal.
const ATTACK_SCENARIOS = {
  'aim-ab': (doc, file) => {
    const out = [];
    for (const [key, agent] of [['runA', { name: 'RAGBot', port: 7005 }], ['runB', { name: 'RAGBot-AIM', port: 7014 }]]) {
      const run = doc[key];
      if (!run) throw new CorpusError(`${file}: missing ${key}`);
      out.push({
        key, agent, dvaa: run.dvaa,
        response: { content: run.message ?? '', toolCalls: toolCallsFromOpenAI(run.toolCalls) },
      });
    }
    return { cases: out, excluded: [] };
  },
  repo: (doc, file) => {
    const out = [];
    for (const [key, agent] of [['beat2', { name: 'RepoBot', port: 7022 }], ['beat3', { name: 'RepoBot-AIM', port: 7023 }]]) {
      const beat = doc[key];
      if (!beat) throw new CorpusError(`${file}: missing ${key}`);
      out.push({
        key, agent, dvaa: exfilFromLedger(beat.ledger, `${file}#${key}`),
        response: { content: '', toolCalls: toolCallsFromLedger(beat.ledger) },
      });
    }
    return { cases: out, excluded: [] };
  },
  flight: (doc, file) => {
    const a2 = doc.act2;
    const a3 = doc.act3;
    if (!a2 || !a3) throw new CorpusError(`${file}: missing act2/act3`);
    if (!a2.httpPostTargetUrl) throw new CorpusError(`${file}#act2: missing httpPostTargetUrl`);
    const cases = [{
      key: 'act2',
      agent: { name: 'FlightBot', port: 7017 },
      dvaa: { exfilAttempted: true, exfilExecuted: a2.exfiltrated === true, exfilTargetUrl: a2.httpPostTargetUrl.split('?')[0] },
      response: { content: '', toolCalls: [{ id: 'act2-http-post', name: 'http:post', arguments: JSON.stringify({ url: a2.httpPostTargetUrl }) }] },
    }];
    // act3 records only the AIM denial, not the attempted call, so there is nothing for a detector to see.
    const excluded = [{
      id: `${rel(REPO_ROOT, file)}#act3`,
      reason: 'capture records only the AIM denial (denialReason/trustScore), not the attempted http:post payload; ' +
        'scoring it would measure the capture, not the detector',
    }];
    return { cases, excluded };
  },
};

export function loadT1Captures(root = REPO_ROOT) {
  const cases = [];
  const excluded = [];
  const attackDir = path.join(root, 'captures', 'attack');
  const benignDir = path.join(root, 'captures', 'benign');
  if (!existsSync(attackDir) || !existsSync(benignDir)) throw new CorpusError(`T1 captures not found under ${root}/captures`);

  for (const name of readdirSync(attackDir).filter((f) => f.endsWith('.demo.json')).sort()) {
    const file = path.join(attackDir, name);
    const doc = readJson(file);
    const parse = ATTACK_SCENARIOS[doc.scenario];
    if (!parse) throw new CorpusError(`${file}: unknown scenario "${doc.scenario}" — add a parser, do not skip`);
    const r = parse(doc, file);
    excluded.push(...r.excluded);
    for (const run of r.cases) {
      const id = `${rel(root, file).replace(/^captures\//, '')}#${run.key}`;
      const dvaa = normDvaa(run.dvaa);
      cases.push({
        id,
        source: 't1-capture',
        group: 'attack',
        channel: 'agent_turn',
        agent: run.agent,
        ...labelFromDvaa(dvaa, id),
        dvaa,
        evadesBaseline: null,
        request: { messages: [] }, // DVAA demo JSON does not record the bundled payload document
        response: run.response,
        notes: `${doc.payload?.attackId ?? ''} ${doc.payload?.name ?? ''}`.trim(),
      });
    }
  }

  const benignFiles = readdirSync(benignDir).sort();
  const reqs = benignFiles.filter((f) => f.endsWith('.req.json'));
  const resps = new Set(benignFiles.filter((f) => f.endsWith('.resp.json')));
  for (const reqName of reqs) {
    const base = reqName.replace(/\.req\.json$/, '');
    const respName = `${base}.resp.json`;
    if (!resps.has(respName)) throw new CorpusError(`captures/benign/${reqName} has no matching ${respName}`);
    resps.delete(respName);
    const req = readJson(path.join(benignDir, reqName));
    const resp = readJson(path.join(benignDir, respName));
    const msg = resp.choices?.[0]?.message;
    if (!msg) throw new CorpusError(`captures/benign/${respName}: no choices[0].message`);
    const id = `benign/${base}`;
    const [port, agentId] = base.split('_');
    cases.push({
      id,
      source: 't1-capture',
      group: 'benign',
      channel: 'user_message',
      agent: { name: resp.model ?? agentId, port: Number(port) || null },
      ...labelFromDvaa(resp.dvaa, id),
      dvaa: normDvaa(resp.dvaa),
      evadesBaseline: null,
      request: { messages: req.messages ?? [] },
      response: { content: msg.content ?? '', toolCalls: toolCallsFromOpenAI(msg.tool_calls) },
      notes: 'T1 benign capture',
    });
  }
  if (resps.size) throw new CorpusError(`captures/benign: response(s) without request: ${[...resps].join(', ')}`);
  return { cases, excluded };
}

// --- T6 labeled variants -------------------------------------------------------------------------
export function loadT6Variants(root = REPO_ROOT) {
  const dir = path.join(root, 'captures', 'variants');
  const manifestFile = path.join(dir, 'manifest.json');
  if (!existsSync(manifestFile)) return { cases: [], excluded: [], present: false };
  const manifest = readJson(manifestFile);
  if (!Array.isArray(manifest.cases)) throw new CorpusError(`${manifestFile}: cases[] missing`);
  const cases = [];
  for (const entry of manifest.cases) {
    const file = path.join(dir, entry.path);
    if (!existsSync(file)) throw new CorpusError(`T6 manifest case ${entry.id}: ${entry.path} not found`);
    const fx = readJson(file);
    if (fx.id !== entry.id) throw new CorpusError(`T6 ${entry.path}: id ${fx.id} != manifest id ${entry.id}`);
    const gt = fx.label?.groundTruth;
    if (gt !== 'positive' && gt !== 'negative') throw new CorpusError(`T6 ${fx.id}: label.groundTruth must be positive|negative`);
    if (entry.groundTruth !== gt) throw new CorpusError(`T6 ${fx.id}: manifest groundTruth ${entry.groundTruth} != fixture ${gt}`);
    const dvaa = normDvaa(fx.label.dvaa);
    // T6 groundTruth is authoritative (deepset prompt-injection positives carry exfilAttempted=false).
    // The one contradiction we refuse: a "benign" case that records an exfil attempt.
    if (gt === 'negative' && dvaa.exfilAttempted === true) {
      throw new CorpusError(`T6 ${fx.id}: groundTruth=negative but dvaa.exfilAttempted=true`);
    }
    if (!Array.isArray(fx.request?.messages)) throw new CorpusError(`T6 ${fx.id}: request.messages[] missing`);
    cases.push({
      id: fx.id,
      source: 't6-variant',
      group: entry.group,
      channel: fx.channel ?? entry.channel ?? null,
      agent: null,
      groundTruth: gt,
      labelBasis: `T6 label.groundTruth=${gt}`,
      dvaa,
      evadesBaseline: fx.baseline8kb?.evadesBaseline ?? entry.evadesBaseline ?? null,
      request: { messages: fx.request.messages },
      response: null,
      notes: fx.notes ?? '',
    });
  }
  const c = manifest.counts;
  if (c && c.total !== cases.length) throw new CorpusError(`T6 manifest counts.total=${c.total} but ${cases.length} cases listed`);
  return { cases, excluded: [], present: true };
}

export function loadCorpus(root = REPO_ROOT) {
  const t1 = loadT1Captures(root);
  const t6 = loadT6Variants(root);
  const cases = [...t1.cases, ...t6.cases];
  enforce('MAX_CASES', cases.length, 'corpus');
  const seen = new Set();
  for (const c of cases) {
    if (seen.has(c.id)) throw new CorpusError(`duplicate case id ${c.id}`);
    seen.add(c.id);
  }
  return { cases, excluded: [...t1.excluded, ...t6.excluded], t6Present: t6.present };
}

/** Every text unit a content scanner can see in a case, each scanned on its own (DVAA scans per input). */
export function textUnits(c) {
  const units = [];
  for (const [i, m] of (c.request?.messages ?? []).entries()) {
    if (typeof m.content === 'string' && m.content) units.push({ where: `request.messages[${i}]`, text: m.content });
  }
  if (c.response?.content) units.push({ where: 'response.content', text: c.response.content });
  for (const [i, t] of (c.response?.toolCalls ?? []).entries()) {
    units.push({ where: `response.toolCalls[${i}]`, text: `${t.name} ${t.arguments}` });
  }
  enforce('MAX_UNITS_PER_CASE', units.length, c.id);
  return units;
}
