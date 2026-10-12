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
    ? `${r.headlineLenses ? `detection recall ${pct(r.detectionRecall)} · **prevention recall ${pct(r.preventionRecall)}** · rule-intent block recall ${pct(r.recall)} (legacy \`recall\`)` : `recall ${pct(r.recall)}`} · benign FP rate ${pct(r.falsePositiveRate)} · precision ${pct(r.precision)} · median ${ms(r.latencyMs.median)}`
    : r.headline.status}`, '');
  if (r.headline.status === 'ok' && r.headlineLenses) {
    const H = r.headlineLenses;
    const base = r.detectors['dvaa-baseline'];
    const bb0 = r.beatsBaseline.byDetector[r.headline.detector];
    L.push('**Honest lenses (enforce).** *Detection* = any finding fired (alert-only and post-execution findings included). ' +
      '*Prevention* = a finding with `prevents:true`: it acts before the agent runs (pre-forward) or withholds the reply. ' +
      'Response-side tool-call findings on an in-process agent (DVAA) fire after the tool already ran: alert + evidence only, ' +
      'counted in detection, NOT in prevention. *Rule-intent block* = the original `recall` field (any would-block rule fired); it overstates prevention.', '');
    {
      const bD = base?.modes?.enforce?.anyFinding, bP = base?.modes?.enforce?.prevention;
      const cmp = (b, t) => (b.recall > t.recall ? 'higher' : b.recall < t.recall ? 'lower' : 'equal');
      const recallLine = bD && bP
        ? `Against ${r.headline.detector}, the DVAA baseline's recall is ${cmp(bD, H.detection)} on detection and ${cmp(bP, H.prevention)} on prevention, at a ${pct(bD.falsePositiveRate)} benign FP rate; the only structural win claimed outright is the evadesBaseline set below. `
        : '';
      L.push(`**Scope.** Benign FP rates are on the ${r.corpus.negatives}-case benign corpus. ` + recallLine +
        'On 32 hand-written held-out benign docs, 1 is blocked on main (a security-awareness memo quoting an injection phrase; pre-existing lexicon behavior), 0 once #92 lands, and 4 raise an alert without a block — see PR #46.', '');
    }
    L.push('| detector | lens | recall | precision | benign FP rate | TP | FP | TN | FN | evades DVAA 8KB window (evadesBaseline) |', '|---|---|---|---|---|---|---|---|---|---|');
    const row = (name, lens, m, beat) => L.push(`| ${name} | ${lens} | ${pct(m.recall)} | ${pct(m.precision)} | ${pct(m.falsePositiveRate)} | ${m.tp} | ${m.fp} | ${m.tn} | ${m.fn} | ${beat} |`);
    row(r.headline.detector, '**detection (any finding)**', H.detection, bb0 ? `${bb0.beaten}/${bb0.eligible}` : 'n/a');
    row(r.headline.detector, '**prevention (prevents:true)**', H.prevention, bb0 ? `${bb0.beatenPrevention}/${bb0.eligible}` : 'n/a');
    row(r.headline.detector, 'rule-intent block (legacy `recall`)', H.blocking, bb0 ? `${bb0.beaten}/${bb0.eligible}` : 'n/a');
    if (base?.available) {
      row('dvaa-baseline', 'detection (any finding)', base.modes.enforce.anyFinding, '—');
      row('dvaa-baseline', 'prevention (request-side hit)', base.modes.enforce.prevention, '—');
    }
    L.push('');
  }
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
  L.push(`**Evades the DVAA 8KB window** (cases T6 marks evadesBaseline=true: ${bb.eligible.join(', ') || 'none'}):`);
  for (const [name, b] of Object.entries(bb.byDetector)) L.push(`- ${name}: ${b.beaten}/${b.eligible}${b.cases.length ? ` (${b.cases.join(', ')})` : ''} · prevented ${b.beatenPrevention ?? 'n/a'}/${b.eligible}`);
  if (bb.baselineMismatch.length) L.push(`- WARNING: dvaa-baseline flagged ${bb.baselineMismatch.join(', ')} although T6 says it evades`);
  L.push('');
  for (const [name, d] of Object.entries(r.detectors)) {
    if (!d.available) continue;
    L.push(`## ${name}`, '');
    const k = d.recallByPositiveKind;
    const kk = (x) => `exfil ${pct(x.exfil.recall)} (${x.exfil.tp}/${x.exfil.positives}) · injection-only ${pct(x.injectionOnly.recall)} (${x.injectionOnly.tp}/${x.injectionOnly.positives})`;
    L.push(`Recall by positive kind (rule-intent block): ${kk(k)}`);
    if (d.recallByPositiveKindAnyFinding) L.push(`Recall by positive kind (detection, any finding): ${kk(d.recallByPositiveKindAnyFinding)}`);
    if (d.recallByPositiveKindPrevention) L.push(`Recall by positive kind (prevention): ${kk(d.recallByPositiveKindPrevention)}`);
    L.push('');
    if (d.detectedNotPrevented?.length) {
      L.push(`Detected but NOT prevented (alert + evidence only): ${d.detectedNotPrevented.length}`);
      for (const x of d.detectedNotPrevented) L.push(`- ${x.id} — ${x.rules.map((f) => `${f.ruleId}${f.postExecution ? ' [post-execution]' : f.direction ? ` [${f.direction}]` : ''}${f.prevents ? ' [prevents]' : ''}`).join(', ')}`);
      L.push('');
    }
    if (d.falsePositivesAnyFinding?.length) {
      L.push(`Benign cases with any finding (alert-only included): ${d.falsePositivesAnyFinding.map((x) => `${x.id} (${x.rules.join(', ')})`).join('; ')}`, '');
    }
    L.push(`False positives (benign cases flagged; blocks in enforce): ${d.falsePositives.length || 'none'}`);
    for (const f of d.falsePositives) L.push(`- ${f.id} — ${f.errored ? `DETECTOR ERROR (scored as fail-closed block): ${f.error}` : f.rules.map((x) => x.ruleId).join(', ')}`);
    L.push(`False negatives (attacks missed): ${d.falseNegatives.length || 'none'}`);
    for (const f of d.falseNegatives) L.push(`- ${f.id}${f.errored ? ` — DETECTOR ERROR (scored as miss): ${f.error}` : f.notes ? ` — ${f.notes.slice(0, 100)}` : ''}`);
    if (d.errors.length) L.push(`ERRORS (${d.errors.length}, each scored as a failure above): ${d.errors.map((e) => `${e.id}: ${e.error}`).join('; ')}`);
    const rules = d.overrides.standIn;
    if (rules.length) {
      L.push('', 'Override tracking (simulated until a real decision log is wired: benign holds = approvals, attack holds = denials):', '');
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
