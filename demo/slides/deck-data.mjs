// deck-data.mjs: pure functions that turn the repo's committed result files into the numbers the live deck shows.
//
// The page (demo/slides/deck.html) and the tests (demo/slides/test/deck-data.test.mjs) both import this module, so a
// number on a slide is always the number in the data file. Nothing here hard-codes a metric value or a fallback:
// when a file or key is absent, the metric comes back { ok: false, src } and the page shows "⚠ missing: <src>".
//
// This module has no imports and no side effects, so the page can load it from a Blob URL when the static server
// sends .mjs with the wrong MIME type.

/** Repo-relative paths of every data file the deck reads. */
export const FILES = Object.freeze({
  scoring: 'sentinel/scoring/results.json',
  holdoutHf: 'captures/holdout-hf/RESULTS.md',
  holdoutIpi: 'captures/holdout-ipi/RESULTS.md',
  holdoutHma: 'captures/holdout-hackmyagent/RESULTS.md',
  track3a: 'track3a/runs/results.json',
  contrast: 'captures/contrast/runs/contrast.json',
  aimAb: 'captures/attack/aim-ab.demo.json',
  proxyBlock: 'captures/contrast/runs/proxy-block.proxy.jsonl',
  egressEvidence: 'sentinel/egress/evidence-block.jsonl',
  egressStage: 'sentinel/dashboard/stage/egress-blocked-t12.json',
});

/** A metric that could not be sourced. The page renders it as a visible warning. */
export function missing(src, why) {
  return { ok: false, src, why: why || 'not found' };
}

/** A plain value metric. */
export function value(v, src) {
  return { ok: true, kind: 'value', v, src };
}

/** Read a dotted path ("a.b.0.c") out of an object. Returns undefined when any step is absent. */
export function getPath(obj, path) {
  let cur = obj;
  for (const part of path.split('.')) {
    if (cur === null || cur === undefined || typeof cur !== 'object') return undefined;
    cur = cur[part];
  }
  return cur;
}

/** A scalar at file#path, or missing. Accepts numbers and strings; null counts as missing. */
export function pick(obj, file, path) {
  const src = `${file}#${path}`;
  if (!obj) return missing(src, 'file not loaded');
  const v = getPath(obj, path);
  if (v === undefined || v === null || (typeof v !== 'number' && typeof v !== 'string' && typeof v !== 'boolean')) {
    return missing(src);
  }
  return value(v, src);
}

/** A fraction num/den from two keys of the same file. */
export function frac(obj, file, numPath, denPath) {
  const src = `${file}#${numPath} / ${denPath}`;
  if (!obj) return missing(src, 'file not loaded');
  const num = getPath(obj, numPath);
  const den = getPath(obj, denPath);
  if (!Number.isFinite(num) || !Number.isFinite(den) || den <= 0) return missing(src);
  return { ok: true, kind: 'frac', num, den, src };
}

/** A fraction parsed from text (RESULTS.md cells). */
function fracFromText(num, den, src) {
  if (!Number.isFinite(num) || !Number.isFinite(den) || den <= 0) return missing(src);
  return { ok: true, kind: 'frac', num, den, src };
}

// ---------------------------------------------------------------------------------------------------------------
// sentinel/scoring/results.json: the main-corpus headline (T3 vs DVAA's own detectAttacks() baseline)
// ---------------------------------------------------------------------------------------------------------------

export const OURS = 't3';
export const BASELINE = 'dvaa-baseline';

/**
 * Every scored number for the deck, always as a { t3, dvaa } pair so a slide can never show ours without theirs.
 * Lens keys follow the harness: detection = modes.enforce.anyFinding, prevention = modes.enforce.prevention.
 */
export function deriveScoring(r) {
  const F = FILES.scoring;
  const lens = (det, mode) => ({
    recall: frac(r, F, `detectors.${det}.modes.enforce.${mode}.tp`, `detectors.${det}.modes.enforce.${mode}.positives`),
    fp: frac(r, F, `detectors.${det}.modes.enforce.${mode}.fp`, `detectors.${det}.modes.enforce.${mode}.negatives`),
  });
  const pair = (fn) => ({ t3: fn(OURS), dvaa: fn(BASELINE) });
  const detection = pair((d) => lens(d, 'anyFinding'));
  const prevention = pair((d) => lens(d, 'prevention'));

  const exfil = pair((d) =>
    frac(r, F, `detectors.${d}.recallByPositiveKindPrevention.exfil.tp`, `detectors.${d}.recallByPositiveKindPrevention.exfil.positives`));
  const injectionOnly = pair((d) =>
    frac(r, F, `detectors.${d}.recallByPositiveKindPrevention.injectionOnly.tp`, `detectors.${d}.recallByPositiveKindPrevention.injectionOnly.positives`));

  const latency = pair((d) => ({
    median: pick(r, F, `detectors.${d}.latencyMs.median`),
    p95: pick(r, F, `detectors.${d}.latencyMs.p95`),
  }));

  return {
    generatedAt: pick(r, F, 'generatedAt'),
    schema: pick(r, F, 'schema'),
    corpus: {
      total: pick(r, F, 'corpus.total'),
      positives: pick(r, F, 'corpus.positives'),
      negatives: pick(r, F, 'corpus.negatives'),
      t1Positives: pick(r, F, 'corpus.bySource.t1-capture.positive'),
      t1Negatives: pick(r, F, 'corpus.bySource.t1-capture.negative'),
      t6Positives: pick(r, F, 'corpus.bySource.t6-variant.positive'),
      t6Negatives: pick(r, F, 'corpus.bySource.t6-variant.negative'),
      digest: pick(r, F, 'corpus.digest'),
    },
    detection,
    prevention,
    exfil,
    injectionOnly,
    latency,
    evasion: deriveEvasion(r),
    provenance: {
      t3Commit: pick(r, F, `detectors.${OURS}.provenance.commit`),
      t3Module: pick(r, F, `detectors.${OURS}.provenance.module`),
      dvaaCommit: pick(r, F, `detectors.${BASELINE}.provenance.dvaaCommit`),
      dvaaDirty: pick(r, F, `detectors.${BASELINE}.provenance.dvaaDirty`),
      dvaaSource: pick(r, F, `detectors.${BASELINE}.provenance.source`),
      node: pick(r, F, 'node'),
      iterations: pick(r, F, 'iterations'),
      errorCount: pick(r, F, 'errorCount'),
    },
  };
}

/**
 * 8KB evasion: the fixtures that evade DVAA's head/tail scan (beatsBaseline.eligible). T3's count comes from
 * beatsBaseline.byDetector.t3; DVAA's count is read from its own perCase verdicts on those same ids, not assumed.
 */
export function deriveEvasion(r) {
  const F = FILES.scoring;
  const t3 = {
    detected: frac(r, F, `beatsBaseline.byDetector.${OURS}.beaten`, `beatsBaseline.byDetector.${OURS}.eligible`),
    prevented: frac(r, F, `beatsBaseline.byDetector.${OURS}.beatenPrevention`, `beatsBaseline.byDetector.${OURS}.eligible`),
  };
  const src = `${F}#detectors.${BASELINE}.perCase[id ∈ beatsBaseline.eligible].detectedAny`;
  const eligible = r ? getPath(r, 'beatsBaseline.eligible') : undefined;
  const perCase = r ? getPath(r, `detectors.${BASELINE}.perCase`) : undefined;
  let dvaa = missing(src, r ? 'not found' : 'file not loaded');
  if (Array.isArray(eligible) && eligible.length > 0 && Array.isArray(perCase)) {
    const rows = eligible.map((id) => perCase.find((c) => c && c.id === id));
    if (rows.every(Boolean)) {
      dvaa = fracFromText(rows.filter((c) => c.detectedAny === true).length, eligible.length, src);
    }
  }
  return { ids: Array.isArray(eligible) ? eligible.slice() : [], t3, dvaa };
}

// ---------------------------------------------------------------------------------------------------------------
// Held-out RESULTS.md files: no committed JSON exists (results.json there is gitignored), so the overall table is
// parsed by column header. Any header or row the spec can't find becomes a visible "missing".
// ---------------------------------------------------------------------------------------------------------------

/**
 * Per-set parsing spec. `fpPick` chooses which fraction in the FP cell to use (ipi's clean-benign cell holds
 * "det / prev"; we take prevention, index 1).
 */
export const HOLDOUT_SPECS = Object.freeze({
  hf: {
    file: FILES.holdoutHf,
    label: 'Jailbreak + injection text (3 Hugging Face sets)',
    section: /^##\s+Overall\b/,
    sectionName: 'Overall',
    ours: /^\|\s*\*\*T3\*\*/,
    base: /^\|\s*DVAA baseline\b/,
    det: /^detection/i,
    prev: /^prevention/i,
    fp: /^benign fp \(prevention\)/i,
    fpPick: 0,
    fpNote: 'benign rows',
  },
  ipi: {
    file: FILES.holdoutIpi,
    label: 'Indirect injection that names a destination (LLMail-Inject + BIPIA)',
    section: /^##\s+Overall\b/,
    sectionName: 'Overall',
    ours: /^\|\s*\*\*T3\*\*/,
    base: /^\|\s*DVAA baseline\b/,
    det: /^detection/i,
    prev: /^prevention/i,
    fp: /^benign fp, clean/i,
    fpPick: 1,
    fpNote: 'clean benign emails',
  },
  hma: {
    file: FILES.holdoutHma,
    label: "hackmyagent (DVAA authors' own battery)",
    section: /^##\s+Headline\b/,
    sectionName: 'Headline',
    ours: /^\|\s*\*\*SentinelProxy T3\*\*/,
    base: /^\|\s*DVAA baseline\b/,
    det: /^detection/i,
    prev: /^prevention/i,
    fp: /^benign fp/i,
    fpPick: 0,
    fpNote: 'benign rows reused from the main corpus',
  },
});

function splitRow(line) {
  const t = line.trim().replace(/^\|/, '').replace(/\|$/, '');
  return t.split('|').map((c) => c.trim());
}

function fractionsIn(cell) {
  const out = [];
  const re = /(\d[\d,]*)\/(\d[\d,]*)/g;
  let m;
  while ((m = re.exec(cell)) !== null) out.push([Number(m[1].replace(/,/g, '')), Number(m[2].replace(/,/g, ''))]);
  return out;
}

/** Parse one held-out RESULTS.md into { t3: {det, prev, fp}, dvaa: {det, prev, fp} } fraction metrics. */
export function parseHoldoutMd(md, spec) {
  const anchor = (row, col) => `${spec.file}#${row} row · "${col}"`;
  const blank = () => ({
    t3: { det: missing(anchor('T3', 'detection')), prev: missing(anchor('T3', 'prevention')), fp: missing(anchor('T3', 'benign FP')) },
    dvaa: { det: missing(anchor('DVAA', 'detection')), prev: missing(anchor('DVAA', 'prevention')), fp: missing(anchor('DVAA', 'benign FP')) },
  });
  if (typeof md !== 'string' || md.length === 0) return blank();
  const lines = md.split(/\r?\n/);
  const start = lines.findIndex((l) => spec.section.test(l));
  if (start < 0) return blank();
  // First table after the section heading.
  let i = start + 1;
  while (i < lines.length && !lines[i].trim().startsWith('|')) {
    if (/^##\s/.test(lines[i])) return blank();
    i++;
  }
  const table = [];
  while (i < lines.length && lines[i].trim().startsWith('|')) table.push(lines[i++]);
  if (table.length < 3) return blank();
  const header = splitRow(table[0]);
  const colOf = (re) => header.findIndex((h) => re.test(h));
  const cols = { det: colOf(spec.det), prev: colOf(spec.prev), fp: colOf(spec.fp) };
  const rowOf = (re) => table.slice(2).find((l) => re.test(l));
  const out = blank();
  for (const [who, re] of [['t3', spec.ours], ['dvaa', spec.base]]) {
    const line = rowOf(re);
    if (!line) continue;
    const cells = splitRow(line);
    for (const k of ['det', 'prev', 'fp']) {
      const c = cols[k];
      if (c < 0 || c >= cells.length) continue;
      const fr = fractionsIn(cells[c]);
      const idx = k === 'fp' ? spec.fpPick : 0;
      const src = `${spec.file}#${spec.sectionName} table · ${who === 't3' ? 'T3' : 'DVAA baseline'} row · "${header[c]}"`;
      out[who][k] = fr[idx] ? fracFromText(fr[idx][0], fr[idx][1], src) : missing(src);
    }
  }
  return out;
}

/** All held-out sets, keyed by spec name. `mds` maps spec name → markdown text (or undefined if the fetch failed). */
export function deriveHoldouts(mds) {
  const out = {};
  for (const [k, spec] of Object.entries(HOLDOUT_SPECS)) {
    out[k] = { label: spec.label, file: spec.file, fpNote: spec.fpNote, ...parseHoldoutMd(mds ? mds[k] : undefined, spec) };
  }
  return out;
}

// ---------------------------------------------------------------------------------------------------------------
// track3a/runs/results.json: OpsBot (Path A), 5 stacks × 4 scenarios
// ---------------------------------------------------------------------------------------------------------------

/** Display names for the stack ids in track3a/runs/results.json (the wording of track3a/RESULTS.md). */
export const STACK_LABELS = Object.freeze({
  undefended: 'Undefended OpsBot',
  'chat-proxy': '+ SentinelProxy chat proxy',
  'proxy+egress': '+ chat proxy + egress guard',
  hardened: 'Hardened OpsBot (mandate only)',
  full: 'Hardened + chat proxy + egress guard',
});

export function deriveTrack3a(rows) {
  const F = FILES.track3a;
  if (!Array.isArray(rows) || rows.length === 0) return { ok: false, src: `${F}#[]`, stacks: [], scenarios: [], cells: {} };
  const stacks = [];
  const scenarios = [];
  const cells = {};
  rows.forEach((r, i) => {
    if (!r || typeof r.stack !== 'string' || typeof r.scenario !== 'string') return;
    if (!stacks.includes(r.stack)) stacks.push(r.stack);
    if (!scenarios.includes(r.scenario)) scenarios.push(r.scenario);
    const src = `${F}#[${i}] (stack=${r.stack}, scenario=${r.scenario}) .leaked/.blockedBy/.benignOk`;
    let outcome;
    if (r.kind === 'attack') {
      if (r.leaked === true) outcome = { label: 'LEAKED', tone: 'leak', detail: `${(r.leakedCanaries || []).length} secrets` };
      else if (r.leaked === false && Array.isArray(r.blockedBy) && r.blockedBy.length) outcome = { label: 'BLOCKED', tone: 'held', detail: r.blockedBy.join(', ') };
      else outcome = null;
    } else if (r.kind === 'benign') {
      if (r.benignOk === true) outcome = { label: 'OK', tone: 'ok', detail: 'benign passed' };
      else if (r.benignOk === false) outcome = { label: 'FALSE BLOCK', tone: 'leak', detail: 'benign refused' };
      else outcome = null;
    }
    cells[`${r.stack}|${r.scenario}`] = outcome ? { ok: true, kind: 'value', v: outcome, src } : missing(src);
  });
  const summary = {};
  for (const s of stacks) {
    const attacks = rows.filter((r) => r && r.stack === s && r.kind === 'attack');
    const benign = rows.filter((r) => r && r.stack === s && r.kind === 'benign');
    summary[s] = {
      stopped: fracFromText(attacks.filter((r) => r.leaked === false).length, attacks.length, `${F}#[stack=${s}, kind=attack].leaked==false`),
      benignOk: fracFromText(benign.filter((r) => r.benignOk === true).length, benign.length, `${F}#[stack=${s}, kind=benign].benignOk`),
    };
  }
  return { ok: true, src: F, stacks, scenarios, cells, summary };
}

// ---------------------------------------------------------------------------------------------------------------
// captures/contrast/runs/contrast.json: same attack, different outcomes
// ---------------------------------------------------------------------------------------------------------------

export function deriveContrast(c) {
  const F = FILES.contrast;
  const col = (path, tone) => ({
    agent: pick(c, F, `${path}.agent`),
    outcome: pick(c, F, `${path}.outcome`),
    canaryHits: pick(c, F, `${path}.canaryHits`),
    tone,
  });
  return {
    attackId: pick(c, F, 'attack.attackId'),
    attackName: pick(c, F, 'attack.name'),
    capturedAt: pick(c, F, 'meta.captured_at'),
    sentinelSha: pick(c, F, 'meta.sentinel_sha'),
    rows: [
      { key: 'vulnerable', ...col('columns.vulnerable', 'leak') },
      { key: 'observe', ...col('columns.proxy.observe', 'leak') },
      { key: 'block', ...col('columns.proxy.block', 'held'), status: pick(c, F, 'columns.proxy.block.proxyStatus') },
      { key: 'aim', ...col('columns.defended.aim', 'held') },
      { key: 'securebot', ...col('columns.defended.securebot', 'held') },
    ],
    aimDenial: pick(c, F, 'columns.defended.aim.denialReason'),
    leakedData: pick(c, F, 'columns.vulnerable.leaked.data'),
  };
}

// ---------------------------------------------------------------------------------------------------------------
// The exploit (Path B), the recorded proxy block, the egress evidence and a real AIDR-shaped alert
// ---------------------------------------------------------------------------------------------------------------

export function deriveExploit(a) {
  const F = FILES.aimAb;
  return {
    tool: pick(a, F, 'runA.toolCalls.0.function.name'),
    exfilExecuted: pick(a, F, 'runA.dvaa.exfilExecuted'),
    canaryData: pick(a, F, 'canary.hits.0.query.data'),
    canaryHits: a && Array.isArray(getPath(a, 'canary.hits')) ? value(getPath(a, 'canary.hits').length, `${F}#canary.hits.length`) : missing(`${F}#canary.hits.length`),
    twinExfil: pick(a, F, 'runB.dvaa.exfilExecuted'),
    twinDenial: pick(a, F, 'runB.dvaa.aim.denialReason'),
  };
}

/** Parse JSONL text into objects, skipping blank or malformed lines. */
export function parseJsonl(text) {
  if (typeof text !== 'string') return null;
  const out = [];
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (!t) continue;
    try { out.push(JSON.parse(t)); } catch { /* skip */ }
  }
  return out;
}

export function deriveProxyBlock(records) {
  const F = FILES.proxyBlock;
  const src = `${F}#[type=exchange, action=blocked_request][0]`;
  if (!Array.isArray(records)) return { status: missing(`${src}.response.status`), detector: missing(`${src}.verdicts[flagged].detector`), reasons: missing(`${src}.verdicts[flagged].reasons`) };
  const ex = records.find((r) => r && r.type === 'exchange' && r.action === 'blocked_request');
  if (!ex) return { status: missing(`${src}.response.status`), detector: missing(`${src}.verdicts[flagged].detector`), reasons: missing(`${src}.verdicts[flagged].reasons`) };
  const flagged = (ex.verdicts || []).find((v) => v && v.flagged === true);
  const status = getPath(ex, 'response.status');
  return {
    status: Number.isFinite(status) ? value(status, `${src}.response.status`) : missing(`${src}.response.status`),
    detector: flagged && flagged.detector ? value(flagged.detector, `${src}.verdicts[flagged].detector`) : missing(`${src}.verdicts[flagged].detector`),
    reasons: flagged && Array.isArray(flagged.reasons) ? value(flagged.reasons.join(' · '), `${src}.verdicts[flagged].reasons`) : missing(`${src}.verdicts[flagged].reasons`),
  };
}

export function deriveEgress(records, stage) {
  const F = FILES.egressEvidence;
  const S = FILES.egressStage;
  const egress = Array.isArray(records) ? records.filter((r) => r && r.direction === 'egress') : null;
  const denies = egress ? egress.filter((r) => r.action === 'deny') : null;
  const passes = egress ? egress.filter((r) => r.action !== 'deny') : null;
  const gt = stage ? getPath(stage, 'provenance.groundTruth') : undefined;
  const m = typeof gt === 'string' ? gt.match(/logged\s+(\d+)\s+CANARY_HIT/) : null;
  return {
    denies: denies ? value(denies.length, `${F}#[direction=egress, action=deny].length`) : missing(`${F}#[direction=egress, action=deny].length`),
    passes: passes ? value(passes.length, `${F}#[direction=egress, action≠deny].length`) : missing(`${F}#[direction=egress, action≠deny].length`),
    destinationOnly: denies
      ? value(denies.filter((r) => Array.isArray(r.reasons) && r.reasons.length === 1 && r.reasons[0] === 'destination_not_allowlisted').length,
        `${F}#[action=deny, reasons=[destination_not_allowlisted]].length`)
      : missing(`${F}#[action=deny, reasons=[destination_not_allowlisted]].length`),
    canaryHits: m ? value(Number(m[1]), `${S}#provenance.groundTruth ("logged N CANARY_HIT")`) : missing(`${S}#provenance.groundTruth`),
    recordedAt: pick(stage, S, 'provenance.recordedAt'),
  };
}

export function deriveAlert(stage) {
  const S = FILES.egressStage;
  const base = 'alerts.run.0';
  const list = (path, field) => {
    const arr = stage ? getPath(stage, path) : undefined;
    const src = `${S}#${path}[].${field}`;
    return Array.isArray(arr) && arr.length ? value(arr.map((x) => x && x[field]).filter(Boolean).join(' · '), src) : missing(src);
  };
  return {
    detectName: pick(stage, S, `${base}.DetectName`),
    description: pick(stage, S, `${base}.DetectDescription`),
    ruleId: pick(stage, S, `${base}.RuleId`),
    severity: pick(stage, S, `${base}.Severity`),
    severityName: pick(stage, S, `${base}.SeverityName`),
    tactic: pick(stage, S, `${base}.Tactic`),
    techniqueId: pick(stage, S, `${base}.TechniqueId`),
    technique: pick(stage, S, `${base}.Technique`),
    attack: list(`${base}.MitreAttack`, 'TechniqueId'),
    owaspLlm: list(`${base}.OwaspLlm`, 'Id'),
    owaspAgentic: list(`${base}.OwaspAgentic`, 'Id'),
    oasb: pick(stage, S, `${base}.Oasb.Benchmark`),
    sink: pick(stage, S, `${base}.Entities.Sink.Destination`),
    disposition: pick(stage, S, `${base}.PatternDispositionDescription`),
    latencyMs: pick(stage, S, `${base}.DetectionLatencyMs`),
    timestamp: pick(stage, S, `${base}.Timestamp`),
    schema: pick(stage, S, `${base}.SchemaVersion`),
  };
}

// ---------------------------------------------------------------------------------------------------------------
// Everything at once
// ---------------------------------------------------------------------------------------------------------------

/**
 * Build the deck's whole data model from the raw loaded files. `raw` keys match FILES; a JSON file is a parsed
 * object, a .md file is text, a .jsonl file is text. Missing keys yield missing metrics, never defaults.
 */
export function deriveAll(raw) {
  const r = raw || {};
  return {
    scoring: deriveScoring(r.scoring),
    holdouts: deriveHoldouts({ hf: r.holdoutHf, ipi: r.holdoutIpi, hma: r.holdoutHma }),
    track3a: deriveTrack3a(r.track3a),
    contrast: deriveContrast(r.contrast),
    exploit: deriveExploit(r.aimAb),
    proxyBlock: deriveProxyBlock(parseJsonl(r.proxyBlock)),
    egress: deriveEgress(parseJsonl(r.egressEvidence), r.egressStage),
    alert: deriveAlert(r.egressStage),
  };
}

// ---------------------------------------------------------------------------------------------------------------
// Formatting (shared so the tests check exactly what the page prints)
// ---------------------------------------------------------------------------------------------------------------

export function pct(num, den, digits = 1) {
  return `${((100 * num) / den).toFixed(digits)}%`;
}

/** Text for a metric in a given format. Missing metrics always render as a warning naming file#key. */
export function fmt(m, how = 'auto') {
  if (!m || !m.ok) return `⚠ missing: ${m ? m.src : 'unknown'}`;
  if (m.kind === 'frac') {
    if (how === 'pct') return pct(m.num, m.den);
    if (how === 'pct0') return pct(m.num, m.den, 0);
    if (how === 'frac') return `${m.num}/${m.den}`;
    if (how === 'of') return `${m.num} of ${m.den}`;
    return `${m.num}/${m.den} (${pct(m.num, m.den)})`;
  }
  if (how === 'ms' && typeof m.v === 'number') return `${m.v.toFixed(3)} ms`;
  if (how === 'ms2' && typeof m.v === 'number') return `${m.v.toFixed(2)} ms`;
  return String(m.v);
}
