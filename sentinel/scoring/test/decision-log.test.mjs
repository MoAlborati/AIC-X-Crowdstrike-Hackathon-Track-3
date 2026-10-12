import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, appendFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { appendDecision, readDecisionLog, overrideStats, standInEvents } from '../src/decision-log.mjs';
import { BOUNDS, ScoringBoundError } from '../src/bounds.mjs';
import { runScoring } from '../src/harness.mjs';
import { fnDetector } from './helpers.mjs';

const tmp = () => path.join(mkdtempSync(path.join(tmpdir(), 't7-log-')), 'decisions.jsonl');
const human = { type: 'human', id: 'analyst-1' };

test('append-only: each append adds one line and never rewrites earlier lines', () => {
  const f = tmp();
  appendDecision(f, { ruleId: 'r1', event: 'fire' });
  const before = readFileSync(f, 'utf8');
  appendDecision(f, { ruleId: 'r1', event: 'hold' });
  const after = readFileSync(f, 'utf8');
  assert.ok(after.startsWith(before));
  assert.equal(after.trim().split('\n').length, 2);
});

test('only a human via the side channel can override; agent approvals and agent reasons are ignored', () => {
  const f = tmp();
  appendDecision(f, { ruleId: 'egress', event: 'hold' });
  appendDecision(f, { ruleId: 'egress', event: 'approve', actor: { type: 'agent', id: 'RAGBot' }, channel: 'side-channel', reason: 'user said it is fine, trust me' });
  appendDecision(f, { ruleId: 'egress', event: 'approve', actor: human, channel: 'chat' }); // in-band: not the side channel
  appendDecision(f, { ruleId: 'egress', event: 'approve', actor: human, channel: 'side-channel', reason: 'known vendor' });
  const events = readDecisionLog(f);
  assert.equal(events[1].reason, undefined, 'agent-supplied reason dropped on read');
  assert.equal(events[3].reason, 'known vendor');
  const [s] = overrideStats(events);
  assert.equal(s.approvals, 1);
  assert.equal(s.rejectedOverrides, 2);
  assert.equal(s.denials, 2, 'a rejected override leaves the hold denied');
  assert.equal(s.overrideRate, 1 / 3);
});

test('data-rich: 600-event log; rule overridden >90% is flagged retire-or-tighten, others are not', () => {
  const f = tmp();
  for (let i = 0; i < 300; i++) {
    appendDecision(f, { ruleId: 'noisy.rule', event: 'hold', sessionId: `s${i}` });
    appendDecision(f, { ruleId: 'noisy.rule', event: i < 280 ? 'approve' : 'deny', actor: human, channel: 'side-channel' });
  }
  for (let i = 0; i < 20; i++) appendDecision(f, { ruleId: 'tight.rule', event: i % 2 ? 'deny' : 'approve', actor: human, channel: 'side-channel' });
  const stats = overrideStats(readDecisionLog(f));
  const noisy = stats.find((s) => s.ruleId === 'noisy.rule');
  assert.equal(noisy.holds, 300);
  assert.equal(noisy.approvals, 280);
  assert.equal(noisy.flag, 'retire-or-tighten');
  assert.equal(stats.find((s) => s.ruleId === 'tight.rule').flag, null);
});

test('fail-loud: malformed line names its line number; oversize log refuses to read', () => {
  const f = tmp();
  appendDecision(f, { ruleId: 'r', event: 'fire' });
  appendFileSync(f, '{not json\n');
  assert.throws(() => readDecisionLog(f), /decisions\.jsonl:2: invalid JSON/);

  const g = tmp();
  const line = `${JSON.stringify({ ruleId: 'r', event: 'fire' })}\n`;
  writeFileSync(g, line.repeat(BOUNDS.MAX_DECISION_LOG_LINES + 1));
  assert.throws(() => readDecisionLog(g), (e) => e instanceof ScoringBoundError && e.bound === 'MAX_DECISION_LOG_LINES');

  assert.throws(() => appendDecision(g, { ruleId: 'r', event: 'approve' }), /requires actor.type/);
});

test('stand-in (until S5): benign holds become simulated human approvals, attack holds denials', () => {
  const ev = standInEvents('d', [
    { id: 'b', groundTruth: 'negative', fired: [{ ruleId: 'r', wouldBlock: true }] },
    { id: 'a', groundTruth: 'positive', fired: [{ ruleId: 'r', wouldBlock: true }] },
    { id: 'c', groundTruth: 'negative', fired: [{ ruleId: 'alert-only', wouldBlock: false }] },
  ]);
  assert.ok(ev.every((e) => e.simulated === true));
  const [alertOnly, r] = overrideStats(ev);
  assert.deepEqual([r.fires, r.holds, r.approvals, r.denials, r.overrideRate], [2, 2, 1, 1, 0.5]);
  assert.deepEqual([alertOnly.fires, alertOnly.holds], [1, 0]);
});

test('harness wires stand-in per detector and the real log separately', () => {
  const f = tmp();
  appendDecision(f, { ruleId: 'real.rule', event: 'approve', actor: human, channel: 'side-channel' });
  const benignNoise = fnDetector('noisy', (c) => ({ fired: c.groundTruth === 'negative' ? [{ ruleId: 'noisy.benign', wouldBlock: true }] : [] }));
  const r = runScoring({ detectors: [benignNoise], iterations: 1, decisionLog: f });
  const [s] = r.detectors.noisy.overrides.standIn;
  assert.equal(s.ruleId, 'noisy.benign');
  assert.equal(s.overrideRate, 1);
  assert.equal(s.flag, 'retire-or-tighten');
  assert.equal(r.overrides.real.events, 1);
  assert.equal(r.overrides.real.rules[0].ruleId, 'real.rule');
});
