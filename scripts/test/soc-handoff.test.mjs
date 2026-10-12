// scripts/soc-handoff.sh: Tourniquet alerts -> SOC Brief, offline.
// Run: node --test scripts/test/soc-handoff.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { honeytokenValues } from '../lib/soc-handoff.mjs';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const SCRIPT = path.join(REPO, 'scripts', 'soc-handoff.sh');
const ADAPTER = path.join(REPO, 'scripts', 'lib', 'soc-handoff.mjs');
const BLOCK = path.join(REPO, 'captures', 'contrast', 'runs', 'proxy-block.t4-alerts.json');

// Generic secret shapes, on top of the exact honeytoken values.
const SECRET_SHAPES = [
  /\bsk-[A-Za-z0-9-]{16,}/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\b\d{3}-\d{2}-\d{4}\b/,
];

function run(env = {}) {
  const out = mkdtempSync(path.join(tmpdir(), 'soc-handoff-'));
  const res = spawnSync('bash', [SCRIPT, out], { encoding: 'utf8', env: { ...process.env, ...env } });
  const brief = res.status === 0 ? readFileSync(path.join(out, 'brief.md'), 'utf8') : '';
  return { res, brief, out };
}

test('brief is written offline with the expected verdict and all three alert kinds', () => {
  // A fake key must not switch SOC Brief to a model: the script unsets it and never passes a model.
  const { res, brief, out } = run({ OPENAI_API_KEY: 'test-not-a-real-key', LLM_API_KEY: 'test-not-a-real-key' });
  try {
    assert.equal(res.status, 0, res.stderr);
    assert.equal(res.stdout.trim(), brief.trim(), 'stdout and brief.md match');
    assert.match(brief, /\*\*Overall verdict: ESCALATE · P1\*\* \(6 alerts: 1 proxy-blocked T3, 4 egress-deny, 1 post-execution\)/);
    const sections = brief.split('\n## ').slice(1);
    assert.equal(sections.length, 6);
    for (const s of sections) {
      for (const field of ['Verdict', 'Priority', 'What happened', 'Recommended action', 'MITRE ATLAS', 'OWASP LLM']) {
        assert.match(s, new RegExp(`\\*\\*${field}:\\*\\* \\S`), `${field} in: ${s.slice(0, 60)}`);
      }
      assert.match(s, /\*\*Verdict:\*\* ESCALATE/);
      assert.match(s, /model: none \(offline\)/);
    }
    assert.match(brief, /IndirectPromptInjection[\s\S]*Prevented · proxy blocked the request/);
    assert.match(brief, /Prevented · egress inspector denied the call/);
    // The post-execution (report-only) card carries SOC Brief's own report-only wording; no handoff workaround.
    const post = sections.find((s) => s.includes('Detected · post-execution (alert-only)'));
    assert.ok(post, 'post-execution section present');
    // #141 taxonomy (Option A): the report-only case is handled by the one
    // `sentinel.agent_exfil` rule, which emits report-only wording ("treat the
    // data as sent", never "stopped the send"). The old `sentinel-agent-report-only`
    // rule id is not restored.
    assert.match(post, /SOC Brief rule `sentinel\.agent_exfil`/);
    assert.match(post, /treat the data as sent/i);
    assert.doesNotMatch(post, /stopped the send|Leave the block in place|Handoff note/);
    assert.match(brief, /AML\.T0086/);
    assert.match(brief, /LLM01 Prompt Injection/);
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
});

test('brief contains no honeytoken value and no secret-shaped string', async () => {
  const values = await honeytokenValues();
  assert.ok(values.length >= 6, `leak check has values to compare (${values.length})`);
  const { res, brief, out } = run();
  try {
    assert.equal(res.status, 0, res.stderr);
    for (const v of values) assert.ok(!brief.includes(v), 'a honeytoken value is in the brief');
    for (const re of SECRET_SHAPES) assert.doesNotMatch(brief, re);
    // Canaries are named by id only.
    assert.match(brief, /DVAA-ADMIN-PASSWORD/);
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
});

test('leak guard refuses to write a brief that would carry a honeytoken value', async () => {
  const [value] = await honeytokenValues();
  const dir = mkdtempSync(path.join(tmpdir(), 'soc-handoff-leak-'));
  try {
    const doc = JSON.parse(readFileSync(BLOCK, 'utf8'));
    const alert = Object.values(doc.runs).flat()[0];
    // Smuggle a honeytoken value into a field the handoff renders verbatim into the brief: the adapter
    // builds the section heading straight from alert.DetectName (not via the swappable SOC Brief engine),
    // so this value WOULD reach the brief regardless of signal wording. The only thing that must stop it
    // is the leak guard — build the brief without the guard and the value appears (see the leak proof).
    alert.DetectName = `${alert.DetectName} leaked=${value}`;
    const bad = path.join(dir, 'bad.alerts.json');
    writeFileSync(bad, JSON.stringify(doc));
    const outFile = path.join(dir, 'brief.md');
    // Observe/egress inputs come from a real run so only the block input is tampered.
    const ok = run();
    const obs = path.join(ok.out, 'pipeline', 'observe', 'alerts', 'live__proxy-7005.alerts.json');
    const egr = path.join(ok.out, 'pipeline', 'egress', 'alerts', 'live__egress-boundary.alerts.json');
    const res = spawnSync(process.execPath, [ADAPTER, '--block', bad, '--observe', obs, '--egress', egr, '--out', outFile], { encoding: 'utf8' });
    rmSync(ok.out, { recursive: true, force: true });
    assert.equal(res.status, 3, res.stderr);
    assert.match(res.stderr, /honeytoken value/);
    assert.ok(!res.stdout.includes(value));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('placeholder sidecars are refused (only real captures are handed off)', () => {
  const placeholder = path.join(REPO, 'sentinel', 'dashboard', 'fixtures', 'alerts', 'attack__aim-ab.demo.alerts.json');
  const res = spawnSync(process.execPath, [ADAPTER, '--block', placeholder, '--observe', placeholder, '--egress', placeholder, '--out', path.join(tmpdir(), 'never.md')], { encoding: 'utf8' });
  assert.notEqual(res.status, 0);
  assert.match(res.stderr, /not a real capture/);
});
