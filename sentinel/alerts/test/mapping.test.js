import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  CATEGORY_MAP, CATEGORIES, CATALOG, getMapping, validateMappingTable, severityName, UnknownCategoryError,
} from '../mapping.js';
import { buildAlert } from '../schema.js';
import { makeVerdict, warnSink } from './helpers.js';

test('mapping table is internally consistent (every ID resolves in the catalog)', () => {
  assert.deepEqual(validateMappingTable(), []);
});

test('validateMappingTable flags an unknown framework id (fail loud on bad edit)', () => {
  const bad = { x: { ...CATEGORY_MAP.taint_flow_exfil, atlas: ['AML.T9999'], oasb: 'nope' } };
  const problems = validateMappingTable(bad);
  assert.ok(problems.some((p) => p.includes('AML.T9999')));
  assert.ok(problems.some((p) => p.includes('OASB-1')));
});

test('ATLAS IDs verified against ATLAS 2026.09 data: names + technique->tactic links', () => {
  const t = CATALOG.atlasTechniques;
  assert.deepEqual(t['AML.T0086'], { name: 'Exfiltration via AI Agent Tool Invocation', tactic: 'AML.TA0010' });
  assert.deepEqual(t['AML.T0057'], { name: 'LLM Data Leakage', tactic: 'AML.TA0010' });
  assert.deepEqual(t['AML.T0051.001'], { name: 'LLM Prompt Injection: Indirect', tactic: 'AML.TA0005' });
  // ATLAS-2026.09: AML.T0051.000 "Direct" specializes AML.T0051, achieves AML.TA0005 (PR #15 follow-up)
  assert.deepEqual(t['AML.T0051.000'], { name: 'LLM Prompt Injection: Direct', tactic: 'AML.TA0005' });
  assert.equal(CATALOG.atlasTactics[t['AML.T0051.000'].tactic], 'Execution');
  assert.deepEqual(t['AML.T0068'], { name: 'LLM Prompt Obfuscation', tactic: 'AML.TA0007' });
  assert.equal(CATALOG.atlasTactics['AML.TA0010'], 'Exfiltration');
  for (const id of Object.keys(t)) assert.match(id, /^AML\.T\d{4}(\.\d{3})?$/);
});

test('STRATEGY §6 coverage: ATT&CK T1041/T1567, OWASP LLM01/02/06, ASI01/02, OASB-1 all used', () => {
  const used = (k) => new Set(Object.values(CATEGORY_MAP).flatMap((m) => [].concat(m[k])));
  for (const id of ['T1041', 'T1567']) assert.ok(used('attack').has(id), id);
  for (const id of ['LLM01', 'LLM02', 'LLM06']) assert.ok(used('owaspLlm').has(id), id);
  for (const id of ['ASI01', 'ASI02']) assert.ok(used('owaspAgentic').has(id), id);
  assert.ok(used('oasb').has('data-exfiltration'));
});

test('every category resolves; unknown category throws (no silent default)', () => {
  for (const c of CATEGORIES) {
    const m = getMapping(c);
    assert.ok(m.MitreAtlas.length >= 1);
    assert.equal(m.Oasb.Benchmark, 'OASB-1');
  }
  assert.throws(() => getMapping('made_up'), UnknownCategoryError);
  assert.throws(() => getMapping('__proto__'), UnknownCategoryError);
  assert.throws(() => getMapping('toString'), UnknownCategoryError);
});

test('data-driven: alert tags come from the single table for every category', () => {
  const { onWarning } = warnSink();
  for (const c of CATEGORIES) {
    const a = buildAlert(makeVerdict(c), { onWarning });
    const m = getMapping(c);
    assert.deepEqual(a.MitreAtlas, m.MitreAtlas);
    assert.deepEqual(a.MitreAttack, m.MitreAttack);
    assert.deepEqual(a.OwaspLlm, m.OwaspLlm);
    assert.deepEqual(a.OwaspAgentic, m.OwaspAgentic);
    assert.deepEqual(a.Oasb, m.Oasb);
    assert.deepEqual(a.References, m.References);
    assert.equal(a.TechniqueId, m.MitreAtlas[0].TechniqueId);
    assert.equal(a.DetectName, m.detectName);
  }
});

test('reference attribution: EchoLeak CVE maps ONLY to the markdown/image-exfil class; others carry no CVE', () => {
  // The catalog entry is accurate (CVE id, NVD url, CVSS), not fabricated.
  assert.deepEqual(CATALOG.references['CVE-2025-32711'], {
    Type: 'CVE',
    Name: 'EchoLeak — zero-click data exfiltration from Microsoft 365 Copilot via markdown image rendering',
    Url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-32711',
    Cvss: 9.3,
  });

  // egress_markdown_image is the ONLY class with a CVE reference, and it resolves fully.
  const md = getMapping('egress_markdown_image');
  assert.deepEqual(md.References, [{
    Id: 'CVE-2025-32711',
    Type: 'CVE',
    Name: 'EchoLeak — zero-click data exfiltration from Microsoft 365 Copilot via markdown image rendering',
    Url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-32711',
    Cvss: 9.3,
  }]);

  // Every other category: no CVE invented — References is empty, so it falls back to the taxonomy tags.
  for (const c of CATEGORIES) {
    const m = getMapping(c);
    assert.ok(Array.isArray(m.References), `${c}: References is an array`);
    if (c === 'egress_markdown_image') continue;
    assert.deepEqual(m.References, [], `${c}: no CVE attached (taxonomy tags only)`);
    // Classes without a CVE still carry taxonomy attribution (ATLAS/OWASP), never empty attribution.
    assert.ok(m.MitreAtlas.length >= 1 && (m.OwaspLlm.length >= 1 || m.OwaspAgentic.length >= 1), `${c}: has taxonomy tags`);
  }
});

test('reference attribution is carried onto the emitted alert only for matching finding types', () => {
  const { onWarning } = warnSink();
  const md = buildAlert(makeVerdict('egress_markdown_image'), { onWarning });
  assert.equal(md.References.length, 1);
  assert.equal(md.References[0].Id, 'CVE-2025-32711');
  assert.equal(md.References[0].Type, 'CVE');
  // A non-matching class (e.g. a plain honeytoken egress) carries an empty reference list, not a CVE.
  const ht = buildAlert(makeVerdict('honeytoken_exfil'), { onWarning });
  assert.deepEqual(ht.References, []);
  assert.ok(!JSON.stringify(ht).includes('CVE-2025-32711'), 'no CVE attached to a non-matching class');
});

test('validateMappingTable flags an unknown reference id (fail loud on bad edit)', () => {
  const bad = { x: { ...CATEGORY_MAP.egress_markdown_image, references: ['CVE-0000-00000'] } };
  const problems = validateMappingTable(bad);
  assert.ok(problems.some((p) => p.includes('unknown reference CVE-0000-00000')), problems.join('; '));
});

test('table is frozen (cannot be mutated at a call site)', () => {
  assert.throws(() => { CATEGORY_MAP.taint_flow_exfil.severity = 1; }, TypeError);
});

test('severity bands', () => {
  assert.equal(severityName(95), 'Critical');
  assert.equal(severityName(70), 'High');
  assert.equal(severityName(50), 'Medium');
  assert.equal(severityName(20), 'Low');
  assert.equal(severityName(0), 'Informational');
  assert.throws(() => severityName(101), RangeError);
  assert.throws(() => severityName(Number.NaN), RangeError);
});
