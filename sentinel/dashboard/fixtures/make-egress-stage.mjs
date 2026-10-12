#!/usr/bin/env node
// Stage capture 4: "Tool boundary: egress guard denied the exfil (attacker received nothing)".
//
//   node sentinel/dashboard/fixtures/make-egress-stage.mjs <pipeline-out-dir> <egress-demo.log> <turns.jsonl> [out.json]
//
// Input is the REAL output of `scripts/stage-egress-capture.sh`: a `scripts/egress-demo.sh block` run,
// converted by `sentinel/pipeline/cli.mjs convert --egress`. This script only merges the pipeline's
// `captures/live/egress-boundary.json` with its `alerts/live__egress-boundary.alerts.json` sidecar into
// one stage file (alerts embedded keyed by run, like stage/proxy-blocked-t3.json), and replaces the
// pipeline's stub exchange with the two agent turns the demo actually drove (EGRESS_TURN_LOG: full user
// message, reply, recorded [t0, t1]), redacted with T4 redactDeep + the deployment honeytokens. The
// dashboard resolves each unattributed egress alert to the one turn in flight at its timestamp.
// Nothing is invented: every alert is T4 buildAlert output from an inspector record, kept verbatim. It fails loud unless the demo log says
// the block run PASSED with 0 attacker hits and every alert is a preventive egress deny.

import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadEgressHoneytokens } from '../../pipeline/egress.mjs';
import { redactDeep } from '../../alerts/redact.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_OUT = path.join(HERE, '..', 'stage', 'egress-blocked-t12.json');

const die = (msg) => { process.stderr.write(`make-egress-stage: ${msg}\n`); process.exit(1); };
const [outDir, demoLog, turnLog, outFile = DEFAULT_OUT] = process.argv.slice(2);
if (!outDir || !demoLog || !turnLog) die('usage: make-egress-stage.mjs <pipeline-out-dir> <egress-demo.log> <turns.jsonl> [out.json]');
const honeytokens = loadEgressHoneytokens();
if (!honeytokens.length) die('no egress honeytokens loaded: cannot redact or leak-check');

const log = readFileSync(demoLog, 'utf8');
for (const must of ['EGRESS MODE=block', 'RESULT block: PREVENTED', 'RESULT repobot block: PREVENTED', 'EGRESS DEMO: PASS', '(no canary hits)']) {
  if (!log.includes(must)) die(`demo log does not show "${must}": refusing to stage a run that did not prevent the exfil`);
}

const capture = JSON.parse(readFileSync(path.join(outDir, 'captures', 'live', 'egress-boundary.json'), 'utf8'));
const sidecar = JSON.parse(readFileSync(path.join(outDir, 'alerts', 'live__egress-boundary.alerts.json'), 'utf8'));
const allAlerts = sidecar.runs?.run;
if (!Array.isArray(allAlerts) || !allAlerts.length) die('sidecar has no alerts under runs.run');
const notPreventive = allAlerts.filter((a) => a.PipelineContext?.Direction !== 'egress' || a.PipelineContext?.Preventive !== true);
if (notPreventive.length) die(`${notPreventive.length} alert(s) are not preventive egress denies`);

const turns = readFileSync(turnLog, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
if (turns.map((t) => t.agent).join(',') !== 'RAGBot,RepoBot') die(`expected the RAGBot then RepoBot turns, got [${turns.map((t) => t.agent)}]`);
const claimOf = (d) => (d ? {
  exfilExecuted: d.exfilExecuted ?? null,
  exfilStatusCode: d.exfilResult?.statusCode ?? null,
  reportedClean: d.reportedClean ?? null,
  ledger: (d.ledger ?? []).map((l) => `${l.action}:${l.decision}/${l.executed ? 'executed' : 'not-executed'}`),
} : null);
const exchanges = turns.map((t) => redactDeep({
  request: { messages: [{ role: 'user', content: t.user }] },
  response: { choices: [{ message: { role: 'assistant', content: t.reply }, finish_reason: 'stop' }] },
  // DVAA's own `dvaa{}` block is NOT ground truth here: it reports exfilExecuted:true even when the egress
  // inspector answered 403. Kept for reference under sentinel.dvaaClaim (never read as an outcome); the
  // ground truth is the attacker collector (0 CANARY_HIT lines, checked above).
  sentinel: { agent: `${t.agent} :${t.port}`, turnWindow: { t0: t.t0, t1: t.t1 }, dvaaClaim: claimOf(t.dvaa) },
}, { canaries: honeytokens }).value);
// Stage scope = the exfil: the alerts raised while a driven agent turn was in flight (exactly one turn's
// recorded window). Anything outside every window (e.g. a CONNECT DVAA makes while booting, before the
// first turn) is not part of the attack. It is excluded here and listed in provenance, never hidden.
const inTurns = (a) => turns.filter((t) => { const at = Date.parse(a.Timestamp); return at >= t.t0 && at <= t.t1; }).length;
const alerts = allAlerts.filter((a) => inTurns(a) === 1);
const outside = allAlerts.filter((a) => inTurns(a) === 0);
const ambiguous = allAlerts.filter((a) => inTurns(a) > 1);
if (ambiguous.length) die(`${ambiguous.length} alert(s) fall in several turn windows`);
if (!alerts.some((a) => a.RuleId === 'egress.honeytoken_match')) die('no honeytoken exfil deny fell inside a driven agent turn');

const inWindow = (t) => alerts.filter((a) => { const at = Date.parse(a.Timestamp); return at >= t.t0 && at <= t.t1; }).length;
const doc = {
  ...capture,
  agent: { name: 'sandboxed DVAA', port: null },
  exchanges,
  title: `Egress guard (block mode, T12) · RAGBot :7005 + RepoBot :7022 · ${alerts.length} exfil requests denied before send`,
  provenance: {
    recordedAt: alerts.map((a) => a.Timestamp).sort()[0],
    how: 'Real `scripts/egress-demo.sh block` run (DVAA in an internal-only sandbox network; its only exit is the T12 '
      + 'tool-boundary egress inspector). Inspector log converted by `sentinel/pipeline/cli.mjs convert --egress`; '
      + 'capture written by sentinel/pipeline/store.mjs, alerts built by T4 buildAlert and embedded here keyed by run. '
      + 'Regenerate: scripts/stage-egress-capture.sh.',
    exchangesNote: 'Exchanges are the two agent turns egress-demo.sh drove (EGRESS_TURN_LOG), redacted with the deployment honeytokens; the pipeline incident capture itself has only a stub exchange.',
    excludedOutsideAgentTurns: outside.map((a) => ({ AlertId: a.AlertId, Timestamp: a.Timestamp, RuleId: a.RuleId, Destination: a.Entities?.Sink?.Destination ?? null,
      why: 'raised while no driven agent turn was in flight (before the first turn: DVAA start-up traffic), so not part of the exfil; still denied' })),
    windows: turns.map((t) => ({ agent: `${t.agent} :${t.port}`, from: new Date(t.t0).toISOString(), to: new Date(t.t1).toISOString() })),
    groundTruth: 'Attacker collector (`canary` service) logged 0 CANARY_HIT lines: the attacker received nothing.',
    demoResult: log.split('\n').filter((l) => l.startsWith('RESULT ') || l.startsWith('EGRESS DEMO:')),
    deniedPerTurn: Object.fromEntries(turns.map((t) => [`${t.agent} :${t.port}`, inWindow(t)])),
    hostNote: 'Destination hosts appear as host[sha256=…,len=…]: the inspector never logs raw hostnames (a DNS-exfil hostname can itself be the secret).',
    alertsNote: sidecar.note,
    pipeline: sidecar.pipeline,
  },
  alerts: { run: alerts },
};

// Honeytoken values must never be in a committed stage file.
const text = JSON.stringify(doc, null, 1);
const leaked = honeytokens.filter((h) => h.value && text.includes(h.value)).map((h) => h.id);
if (leaked.length) die(`honeytoken value(s) present in output: ${leaked.join(', ')}`);

writeFileSync(outFile, `${text}\n`);
process.stdout.write(`${JSON.stringify({ wrote: outFile, alerts: alerts.length, preventive: alerts.length })}\n`);
