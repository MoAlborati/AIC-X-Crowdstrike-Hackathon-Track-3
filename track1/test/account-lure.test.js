// Ported from #141 (@shrutidoshi94): a pasted tax-return / "log back in" note escalates as an account lure,
// including a paste with no mail headers. Real seams: the real parser, normalizer, rules, and HTTP server.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createApp, parseEmailText } from '../server.mjs';
import { brief } from '../src/briefing.js';
import { buildQueue } from '../src/cases.js';
import { normalize } from '../src/normalize.js';
import { deriveTags } from '../src/tags.js';

const TAX_NOTE = [
  'Hey Alex,',
  'It looks like your federal tax return was rejected by the IRS.',
  'The Primary Taxpayer did not enter a valid Identity Protection Personal Identification Number (IP PIN).',
  'You can log back into Credit Karma Tax to adjust your return.',
  'Edit My Return',
  '-The Credit Karma Tax Team',
].join('\n');

function emailCard(record, id = 'mail-test') {
  return normalize({ id, record: { source: 'email', ...record } }, new Map());
}

test('parseEmailText keeps a pasted note that has no headers', () => {
  const parsed = parseEmailText(TAX_NOTE);
  assert.equal(parsed.from, 'unknown sender');
  assert.equal(parsed.subject, '(no subject)');
  assert.match(parsed.body, /Hey Alex/);
  assert.match(parsed.body, /Edit My Return/);
});

test('a headerless tax-return login note escalates as an account lure', () => {
  const b = brief(emailCard(parseEmailText(TAX_NOTE)));
  assert.equal(b.ruleId, 'account-lure');
  assert.equal(b.activity, 'account_lure');
  assert.equal(b.disposition, 'escalate');
  assert.equal(b.priority, 'P1');
  assert.match(b.headline, /tax return/);
  assert.match(b.whatToDo, /Do not click Edit My Return/);
});

test('a "log back in" lure from an outside sender escalates; internal mail without a lure stays quiet', () => {
  const lure = brief(emailCard({ from: 'support@acct-help.test', subject: 'Notice', body: 'Please log back in to keep your account.' }));
  assert.equal(lure.ruleId, 'account-lure');
  assert.equal(lure.disposition, 'escalate');
  const internal = brief(emailCard({ from: 'it@smith.russellmitchell.com', subject: 'Lunch', body: 'Team lunch is at noon.' }));
  assert.notEqual(internal.ruleId, 'account-lure');
});

test('account_lure gets phishing framework and stage tags', () => {
  const card = emailCard(parseEmailText(TAX_NOTE));
  const labels = deriveTags(card, brief(card)).map((t) => t.label);
  assert.ok(labels.includes('#account-lure'));
  assert.ok(labels.includes('#ATT&CK:T1566'));
  assert.ok(labels.includes('#phase:initial-access'));
});

test('no curated queue item changes verdict because of the account-lure rule', () => {
  for (const item of buildQueue()) {
    assert.notEqual(brief(item.card, { relatedCount: item.relatedCount }).ruleId, 'account-lure', item.card.id);
  }
});

test('POST /api/triage escalates the headerless tax paste end to end', async () => {
  const app = createApp({ complete: null });
  const { createServer } = await import('node:http');
  const server = createServer(app);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    const { port } = server.address();
    const res = await fetch(`http://127.0.0.1:${port}/api/triage`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ emailText: TAX_NOTE }),
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.briefing.disposition, 'escalate');
    assert.equal(body.briefing.activity, 'account_lure');
    assert.ok(body.tags.some((t) => t.label === '#account-lure'));
  } finally {
    await new Promise((r) => server.close(r));
  }
});
