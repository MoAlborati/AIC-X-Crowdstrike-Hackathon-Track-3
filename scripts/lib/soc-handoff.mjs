#!/usr/bin/env node
// SOC handoff adapter: Tourniquet T4 alerts (sentinel.alert/1.0.0) -> Track 1 SOC Brief, offline.
//
//   node scripts/lib/soc-handoff.mjs --block <t4-alerts.json> --observe <t4-alerts.json> \
//        --egress <t4-alerts.json> --out <brief.md>
//
// Each input is a T10 pipeline sidecar ({placeholder, runs: {name: [alert...]}}). The adapter picks:
//   * proxy-blocked T3 alerts   -> request-side alerts with PatternDispositionFlags.Blocked (from --block)
//   * egress-deny alerts        -> every "[egress" alert with Blocked (from --egress)
//   * one post-execution alert  -> the highest-severity "[response-side" ReportOnly alert (from --observe)
// It runs SOC Brief's own deterministic path (vendored normalize + runChain with no model), so no
// API key or network is used. The SOC Brief core is vendored at scripts/lib/vendor/soc-brief/
// (copied from the Track 1 repo; see its PROVENANCE.md). Nothing in sentinel/ is modified.
//
// Fail-loud: a placeholder sidecar, a non-sentinel.alert record, an empty category, more than
// MAX_ALERTS alerts in the brief, or a known honeytoken value in the rendered brief exits non-zero.

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { fileURLToPath, pathToFileURL } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const imp = (rel) => import(pathToFileURL(path.join(REPO, rel)).href);

const { normalize } = await imp('scripts/lib/vendor/soc-brief/normalize.js');
const { runChain } = await imp('scripts/lib/vendor/soc-brief/chain.js');
const { dispositionRank } = await imp('scripts/lib/vendor/soc-brief/signals.js');

// Hard cap on briefs in one handoff. The demo selection is 6; a capture with more is a different
// input than this script was built for, so it stops instead of silently truncating.
export const MAX_ALERTS = 20;

function die(msg, code = 1) {
  process.stderr.write(`[soc-handoff] ERROR ${msg}\n`);
  process.exit(code);
}

function loadSidecar(file, label) {
  let doc;
  try {
    doc = JSON.parse(readFileSync(file, 'utf8'));
  } catch (err) {
    die(`${label}: cannot read ${file}: ${err.message}`);
  }
  if (doc.placeholder !== false) die(`${label}: ${file} is not a real capture (placeholder=${doc.placeholder})`);
  const alerts = Object.values(doc.runs || {}).flat();
  for (const a of alerts) {
    if (!String(a?.SchemaVersion || '').startsWith('sentinel.alert')) {
      die(`${label}: ${file} holds a record that is not sentinel.alert (SchemaVersion=${a?.SchemaVersion})`);
    }
  }
  return { file, captureId: doc.captureId || null, alerts };
}

const narrative = (a) => String(a.CaseCard?.Narrative || '');
const blocked = (a) => a.PatternDispositionFlags?.Blocked === true;
const reportOnly = (a) => a.PatternDispositionFlags?.ReportOnly === true;
const outcome = (a) => (narrative(a).match(/Outcome:\s*([a-z_]+)/) || [])[1] || 'unknown';

const STAGES = {
  t3: 'Prevented · proxy blocked the request before the agent saw it',
  egress: 'Prevented · egress inspector denied the call before any byte left',
  post: 'Detected · post-execution (alert-only): the tool already ran when the proxy saw the reply',
};

export function select({ block, observe, egress }) {
  const t3 = block.alerts.filter((a) => blocked(a) && narrative(a).startsWith('[request-side'));
  const eg = egress.alerts.filter((a) => blocked(a) && narrative(a).startsWith('[egress'));
  const post = observe.alerts
    .filter((a) => reportOnly(a) && narrative(a).startsWith('[response-side'))
    .sort((x, y) => (Number(y.Severity) || 0) - (Number(x.Severity) || 0))
    .slice(0, 1);
  const missing = [['proxy-blocked T3', t3], ['egress-deny', eg], ['post-execution', post]]
    .filter(([, list]) => list.length === 0)
    .map(([name]) => name);
  if (missing.length) die(`no ${missing.join(', ')} alert in the inputs`);
  const picked = [
    ...t3.map((alert) => ({ kind: 't3', alert, from: block })),
    ...eg.map((alert) => ({ kind: 'egress', alert, from: egress })),
    ...post.map((alert) => ({ kind: 'post', alert, from: observe })),
  ];
  if (picked.length > MAX_ALERTS) die(`${picked.length} alerts selected, cap is ${MAX_ALERTS}; refusing to truncate`, 3);
  return picked;
}

const tags = (list, fmt) => (Array.isArray(list) && list.length ? list.map(fmt).join('; ') : 'none on alert');

function section(i, { kind, alert, from }, briefing) {
  const rel = path.relative(REPO, from.file) || from.file;
  const lines = [
    `## ${i}. ${alert.DetectName} (${alert.SeverityName || alert.Severity})`,
    '',
    `- **Verdict:** ${briefing.disposition.toUpperCase()}`,
    `- **Priority:** ${briefing.priority}`,
    `- **Tourniquet stage:** ${STAGES[kind]} (disposition ${alert.PatternDispositionDescription}, outcome \`${outcome(alert)}\`)`,
    `- **What happened:** ${briefing.headline} ${briefing.explain}`,
    `- **Why:** ${briefing.why.join(' ')}`,
    `- **Recommended action:** ${briefing.whatToDo}`,
  ];
  lines.push(
    `- **MITRE ATLAS:** ${tags(alert.MitreAtlas, (t) => `${t.TechniqueId} ${t.Technique}`)}`,
    `- **MITRE ATT&CK:** ${tags(alert.MitreAttack, (t) => `${t.TechniqueId} ${t.Technique}`)}`,
    `- **OWASP LLM:** ${tags(alert.OwaspLlm, (t) => `${t.Id} ${t.Name}`)}`,
    `- **OWASP Agentic:** ${tags(alert.OwaspAgentic, (t) => `${t.Id} ${t.Name}`)}`,
    `- **Source:** \`${rel}\` · AlertId \`${alert.AlertId}\` · rule \`${alert.RuleId}\` · SOC Brief rule \`${briefing.ruleId}\` · model: ${briefing.model ? 'used' : 'none (offline)'}`,
    '',
  );
  return lines.join('\n');
}

export async function buildBrief(inputs) {
  const picked = select(inputs);
  const rows = [];
  for (const item of picked) {
    const card = normalize({ id: item.alert.AlertId, record: item.alert }, []);
    if (card.source !== 'sentinel') die(`SOC Brief did not read ${item.alert.AlertId} as a Tourniquet alert (source=${card.source})`);
    // No `complete` function: SOC Brief's deterministic offline path, never a model call.
    const { briefing, model } = await runChain(card);
    if (model.status !== 'skipped') die(`expected offline briefing, got model status ${model.status}`);
    rows.push({ item, briefing });
  }
  const top = rows.reduce((a, b) => (dispositionRank(b.briefing.disposition) > dispositionRank(a.briefing.disposition) ? b : a));
  const counts = { t3: 0, egress: 0, post: 0 };
  for (const { item } of rows) counts[item.kind] += 1;
  const head = [
    '# SOC handoff brief: Tourniquet -> SOC Brief',
    '',
    `**Overall verdict: ${top.briefing.disposition.toUpperCase()} · ${top.briefing.priority}** (${rows.length} alerts: ${counts.t3} proxy-blocked T3, ${counts.egress} egress-deny, ${counts.post} post-execution)`,
    '',
    'Generated offline by SOC Brief from real Tourniquet T4 alerts. No LLM key, no network. Honeytoken values are never printed; alerts name canaries by id only.',
    '',
  ].join('\n');
  return { markdown: `${head}\n${rows.map((r, i) => section(i + 1, r.item, r.briefing)).join('\n')}`, rows, top };
}

/** Known honeytoken values (T3 detector, T12 egress, stand-in config). Values only, for leak checks. */
export async function honeytokenValues() {
  const { DVAA_HONEYTOKENS } = await imp('sentinel/detectors/index.js');
  const { loadEgressHoneytokens } = await imp('sentinel/pipeline/egress.mjs');
  const { loadStandinConfig } = await imp('sentinel/pipeline/standin.mjs');
  const values = [
    ...DVAA_HONEYTOKENS.map((h) => h.value),
    ...loadEgressHoneytokens().map((h) => h.value),
    ...loadStandinConfig().honeytokens.map((h) => h.value),
  ];
  return [...new Set(values.filter((v) => typeof v === 'string' && v.length >= 4))];
}

async function main() {
  const { values } = parseArgs({
    options: {
      block: { type: 'string' },
      observe: { type: 'string' },
      egress: { type: 'string' },
      out: { type: 'string' },
    },
  });
  for (const k of ['block', 'observe', 'egress', 'out']) if (!values[k]) die(`missing --${k}`, 2);
  const inputs = {
    block: loadSidecar(values.block, 'block'),
    observe: loadSidecar(values.observe, 'observe'),
    egress: loadSidecar(values.egress, 'egress'),
  };
  const { markdown } = await buildBrief(inputs);
  const leaked = (await honeytokenValues()).filter((v) => markdown.includes(v));
  if (leaked.length) die(`brief contains ${leaked.length} honeytoken value(s); not writing it`, 3);
  mkdirSync(path.dirname(values.out), { recursive: true });
  writeFileSync(values.out, markdown);
  process.stdout.write(markdown);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
