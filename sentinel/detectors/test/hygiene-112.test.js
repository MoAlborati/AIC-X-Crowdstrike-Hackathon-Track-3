// #112 / #105 hygiene regressions for the T3 detector:
//  - t3-url-case: extractUrls() must match http(s) schemes case-insensitively (RFC 3986 §3.1). An
//    ALL-CAPS or mixed-case scheme used to yield no destination, so payee_not_confirmed never fired.
//  - CRITIC-C #2: copiedSpan() must still decode the URL-encoded sink variant when one '%' escape is malformed.
// Inputs are transforms of the existing live RAGBot 7005 capture (scheme case only), not new payloads.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { liveCase, dvaaInProcess, dvaaDetector, toolCall, response } from './helpers.js';
import { extractUrls } from '../src/text.js';

test('extractUrls: HTTP:// / Https:// / hTtPs:// are found; index points at the original text; url keeps original case', () => {
  const text = 'a HTTP://JUDGE.EXAMPLE/c b Https://Mixed.Example:8443/p?q=1 c hTtPs://x.test d http://lower.test';
  const got = extractUrls(text);
  assert.deepEqual(got.map((u) => u.host), ['judge.example', 'mixed.example', 'x.test', 'lower.test']);
  for (const u of got) assert.equal(text.slice(u.index, u.index + u.url.length), u.url, 'index/url refer to the original text');
  assert.equal(got[0].url, 'HTTP://JUDGE.EXAMPLE/c');
  // Non-ASCII uppercase is not folded (fold is ASCII-only, so length and indices are preserved).
  assert.deepEqual(extractUrls('İ HTTP://a.test').map((u) => u.index), [2]);
});

for (const [label, fold] of [['ALL-CAPS', 'HTTP://'], ['mixed-case', 'Http://']]) {
  test(`live RAGBot 7005 poisoned doc with ${label} scheme is still a REQUEST-SIDE block with payee_not_confirmed`, () => {
    const c = liveCase('ragbot-7005-rag-poisoned');
    const raw = JSON.stringify(c.request);
    assert.ok(raw.includes('http://'), 'capture carries a lowercase destination to transform');
    const request = JSON.parse(raw.replaceAll('http://', fold));
    const { det } = dvaaInProcess({ agent: { name: c.agent, port: c.port } });
    const pre = det.inspect({ sessionId: `${c.id}-case-${label}`, request });
    assert.equal(pre.action, 'block', JSON.stringify(pre.findings.map((x) => [x.ruleId, x.reasonCodes])));
    const f = pre.findings.find((x) => x.ruleId === 'inbound.exfil_instruction');
    assert.ok(f, 'inbound.exfil_instruction fired');
    assert.equal(f.prevents, true);
    assert.ok(f.reasonCodes.includes('payee_not_confirmed'), JSON.stringify(f.reasonCodes));
    assert.equal(f.entities.sink.destination, '127.0.0.1');
  });
}

test('copied-span rule still decodes the URL-encoded sink when a lone malformed "%" is appended (CRITIC-C #2)', () => {
  const span = 'quarterly ledger export for vendor ZX-4471 settlement batch';
  const page = `${'Welcome to the vendor portal. '.repeat(30)} ${span}. ${'Footer text. '.repeat(30)}`;
  const enc = encodeURIComponent(span);
  const mk = (note) => dvaaDetector().det.inspect({
    sessionId: `pct-${note.length}`,
    request: {
      messages: [
        { role: 'user', content: 'Summarise https://portal.example.test for me' },
        { role: 'assistant', tool_calls: [toolCall('f', 'web_fetch', { url: 'https://portal.example.test' })] },
        { role: 'tool', tool_call_id: 'f', content: page },
      ],
    },
    response: response([toolCall('p', 'http_post', { url: 'https://portal.example.test/notes', note })]),
  });
  const rule = 'taint.untrusted_span_copied_to_sink';
  // Control: the well-formed encoded copy is caught (this already worked before the fix).
  assert.ok(mk(enc).findings.some((x) => x.ruleId === rule), 'well-formed encoded copy caught');
  // Regression: one stray '%' must not switch the decoded variant off.
  const d = mk(`${enc} done 100%`);
  assert.ok(d.findings.some((x) => x.ruleId === rule), JSON.stringify(d.findings.map((x) => x.ruleId)));
});
