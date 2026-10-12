// Markdown/terminal table for a results object. Display only: every number comes from results.json.

const pct = (x) => (x === null || x === undefined ? 'n/a' : `${(Math.round(x * 1000) / 10).toFixed(1)}%`);
const ms = (x) => (x === null || x === undefined ? 'n/a' : `${x.toFixed(3)} ms`);

export function renderMarkdown(r) {
  const L = [];
  L.push('# T7 scoring results', '');
  L.push(`Generated ${r.generatedAt} on Node ${r.node}, ${r.iterations} latency iterations per case (median per case).`);
  L.push(`Corpus: ${r.corpus.total} cases (${r.corpus.positives} attack, ${r.corpus.negatives} benign), digest \`${r.corpus.digest.slice(0, 19)}…\`.`);
  L.push(`Label rule: ${r.labelRule}.`, '');
  L.push(`**Headline (SentinelProxy, enforce):** ${r.headline.status === 'ok'
    ? `recall ${pct(r.recall)} · benign FP rate ${pct(r.falsePositiveRate)} · precision ${pct(r.precision)} · median ${ms(r.latencyMs.median)}`
    : r.headline.status}`, '');
  L.push('| detector | kind | mode | precision | recall | benign FP rate | TP | FP | TN | FN | median latency | p95 latency |');
  L.push('|---|---|---|---|---|---|---|---|---|---|---|---|');
  for (const [name, d] of Object.entries(r.detectors)) {
    if (!d.available) {
      L.push(`| ${name} | ${d.kind} | — | unavailable: ${d.unavailableReason} |||||||||`);
      continue;
    }
    for (const [mode, m] of Object.entries(d.modes)) {
      for (const [what, x] of [['detect', m.detection], ['block', m.blocking]]) {
        if (mode === 'enforce' && what === 'detect') continue; // identical to enforce/block unless rules are report-only
        L.push(`| ${name} | ${d.kind} | ${mode}/${what} | ${pct(x.precision)} | ${pct(x.recall)} | ${pct(x.falsePositiveRate)} | ${x.tp} | ${x.fp} | ${x.tn} | ${x.fn} | ${ms(d.latencyMs.median)} | ${ms(d.latencyMs.p95)} |`);
      }
    }
  }
  L.push('');
  const bb = r.beatsBaseline;
  L.push(`**Beats DVAA baseline** (cases T6 marks evadesBaseline=true: ${bb.eligible.join(', ') || 'none'}):`);
  for (const [name, b] of Object.entries(bb.byDetector)) L.push(`- ${name}: ${b.beaten}/${b.eligible}${b.cases.length ? ` (${b.cases.join(', ')})` : ''}`);
  if (bb.baselineMismatch.length) L.push(`- WARNING: dvaa-baseline flagged ${bb.baselineMismatch.join(', ')} although T6 says it evades`);
  L.push('');
  for (const [name, d] of Object.entries(r.detectors)) {
    if (!d.available) continue;
    L.push(`## ${name}`, '');
    const k = d.recallByPositiveKind;
    L.push(`Recall by positive kind: exfil ${pct(k.exfil.recall)} (${k.exfil.tp}/${k.exfil.positives}) · injection-only ${pct(k.injectionOnly.recall)} (${k.injectionOnly.tp}/${k.injectionOnly.positives})`, '');
    L.push(`False positives (benign cases flagged; blocks in enforce): ${d.falsePositives.length || 'none'}`);
    for (const f of d.falsePositives) L.push(`- ${f.id} — ${f.errored ? `DETECTOR ERROR (scored as fail-closed block): ${f.error}` : f.rules.map((x) => x.ruleId).join(', ')}`);
    L.push(`False negatives (attacks missed): ${d.falseNegatives.length || 'none'}`);
    for (const f of d.falseNegatives) L.push(`- ${f.id}${f.errored ? ` — DETECTOR ERROR (scored as miss): ${f.error}` : f.notes ? ` — ${f.notes.slice(0, 100)}` : ''}`);
    if (d.errors.length) L.push(`ERRORS (${d.errors.length}, each scored as a failure above): ${d.errors.map((e) => `${e.id}: ${e.error}`).join('; ')}`);
    const rules = d.overrides.standIn;
    if (rules.length) {
      L.push('', 'Override tracking (stand-in: benign corpus = simulated human approvals, until S5):', '');
      L.push('| rule | fires | holds | approvals | denials | override rate | flag |', '|---|---|---|---|---|---|---|');
      for (const s of rules) L.push(`| ${s.ruleId} | ${s.fires} | ${s.holds} | ${s.approvals} | ${s.denials} | ${pct(s.overrideRate)} | ${s.flag ?? ''} |`);
    }
    L.push('');
  }
  if (r.corpus.excluded.length) {
    L.push('## Excluded from scoring', '');
    for (const e of r.corpus.excluded) L.push(`- ${e.id}: ${e.reason}`);
    L.push('');
  }
  if (r.warnings.length) L.push('## Warnings', '', ...r.warnings.map((w) => `- ${w}`), '');
  return L.join('\n');
}
