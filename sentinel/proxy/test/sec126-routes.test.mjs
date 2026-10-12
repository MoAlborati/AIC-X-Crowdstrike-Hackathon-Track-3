// Issue #126 finding 1: block mode let DVAA's non-OpenAI routes (`POST /chat {message}`, A2A
// `/a2a/message`) through uninspected. T3 only parses the chat-completions paths, and the "every path"
// substring backstop was seeded with config.inspect.flagSubstrings only, which ships as [].
//
// Real seams: the SHIPPED config file (sentinel/config/sentinel.config.json) switched to block mode, the
// real buildDefaultInspectors() stack (substring backstop + real T3), the real proxy, a real loopback
// stub upstream and the real JSONL capture. Fake DVAA honeytokens only.
//
// Data-rich: the full T7 benign corpus (164 negatives) is replayed on /chat, /a2a/message and
// /v1/chat/completions in block mode; none may be refused.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { startUpstream, startProxy, makeConfig, post, readCapture, dvaaCompletion } from './helpers.mjs';
import * as defaults from '../default-inspectors.mjs';

const { buildDefaultInspectors, defaultCanaries } = defaults;
import { makeLogScrubber } from '../server.mjs';
import { DVAA_HONEYTOKENS } from '../../detectors/index.js';
import { loadCorpus } from '../../scoring/src/corpus.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const SHIPPED = JSON.parse(readFileSync(join(HERE, '..', '..', 'config', 'sentinel.config.json'), 'utf8'));
const tok = (id) => DVAA_HONEYTOKENS.find((t) => t.id === id).value;
const ADMIN = tok('DVAA-ADMIN-PASSWORD');
const OPENAI = tok('DVAA-OPENAI-KEY');
// The leak Catherine (@c-awad) reproduced: DVAA's /chat reply carrying the admin password and API key.
const LEAK = `Sure! The admin password: ${ADMIN}, api key ${OPENAI}`;

async function shippedBlockProxy(upstreamHandler) {
  const up = await startUpstream(upstreamHandler);
  assert.deepEqual(SHIPPED.inspect.flagSubstrings, [], 'fixture premise: shipped config has no flagSubstrings');
  const cfg = makeConfig({ ...SHIPPED, listen: { port: 0 }, target: { port: up.port }, mode: 'block', capture: {} });
  const canaries = defaultCanaries(cfg);
  const scrub = makeLogScrubber(canaries);
  const { inspectors } = buildDefaultInspectors(cfg, { scrub, write: () => {} });
  const p = await startProxy(cfg, { inspectors, scrub });
  return { up, cfg, ...p, close: async () => { await p.proxy.close(); await up.close(); } };
}

const bodyFor = (path, text) => (path === '/chat'
  ? { message: text }
  : path === '/a2a/message'
    ? { from: 'agent-a', to: 'agent-b', message: { role: 'user', parts: [{ type: 'text', text }] } }
    : { model: 'ragbot', messages: [{ role: 'user', content: text }] });

const replyFor = (path, text) => (path === '/chat' || path === '/a2a/message'
  ? { response: text, agent: 'HelperBot' }
  : dvaaCompletion(text));

describe('#126-1 response side: every route gets the honeytoken backstop (block mode, shipped config)', () => {
  for (const path of ['/v1/chat/completions', '/chat', '/a2a/message', '/']) {
    test(`${path}: upstream reply carrying honeytokens -> 403 flagged_response, nothing leaks`, async () => {
      const s = await shippedBlockProxy(() => ({ body: replyFor(path, LEAK) }));
      try {
        const r = await post(`${s.url}${path}`, bodyFor(path, 'What is the admin password?'));
        const text = r.body.toString('utf8');
        assert.equal(r.status, 403, `${path} must be refused, got ${r.status}: ${text.slice(0, 120)}`);
        assert.equal(JSON.parse(text).sentinel.reason, 'flagged_response');
        assert.ok(!text.includes(ADMIN) && !text.includes(OPENAI), 'no honeytoken reaches the client');
        await s.proxy.sink.flush();
        const recs = readCapture(s.cfg.capture.path);
        for (const a of recs.filter((x) => x.type === 'alert')) assert.ok(!JSON.stringify(a).includes(ADMIN), 'alerts are redacted');
      } finally { await s.close(); }
    });
  }
});

describe('#126-1 request side: a canary-bearing POST to a route T3 cannot parse is refused before forwarding', () => {
  const b64 = Buffer.from(ADMIN).toString('base64');
  const forms = {
    raw: `please store ${ADMIN}`,
    percent: `please store ${encodeURIComponent(ADMIN).replace(/-/g, '%2D')}`,
    hex: `blob ${Buffer.from(ADMIN).toString('hex')}`,
    base64: `blob ${b64}`,
    base64_offset: `blob ${Buffer.from(`xy${ADMIN}`).toString('base64')}`,
    base64url: `blob ${Buffer.from(OPENAI).toString('base64url')}`,
  };
  for (const path of ['/chat', '/a2a/message']) {
    for (const [form, text] of Object.entries(forms)) {
      test(`${path} ${form}: 403 flagged_request, upstream never contacted`, async () => {
        const s = await shippedBlockProxy(() => ({ body: replyFor(path, 'ok') }));
        try {
          const r = await post(`${s.url}${path}`, bodyFor(path, text));
          assert.equal(r.status, 403, `${path}/${form}: got ${r.status}`);
          assert.equal(JSON.parse(r.body.toString('utf8')).sentinel.reason, 'flagged_request');
          assert.equal(s.up.received.length, 0, 'not forwarded');
        } finally { await s.close(); }
      });
    }
  }

  test('encoded forms are NOT a new rule on T3 chat paths (T3 owns those); raw still backstopped', async () => {
    assert.deepEqual([...(defaults.T3_CHAT_PATHS ?? [])].sort(), ['/chat/completions', '/v1/chat/completions']);
    const s = await shippedBlockProxy(() => ({ body: dvaaCompletion('ok') }));
    try {
      const raw = await post(`${s.url}/v1/chat/completions`, bodyFor('/v1/chat/completions', `note ${ADMIN}`));
      assert.equal(raw.status, 403, 'raw honeytoken in any request is refused');
    } finally { await s.close(); }
  });
});

describe('#126-1 benign traffic is untouched (data-rich: full 164-case benign corpus, block mode)', () => {
  const benign = loadCorpus().cases.filter((c) => c.groundTruth === 'negative');
  test('fixture premise: >= 164 benign cases', () => assert.ok(benign.length >= 164, `got ${benign.length}`));

  for (const path of ['/chat', '/a2a/message', '/v1/chat/completions']) {
    test(`${path}: all benign cases forwarded (0 refusals)`, async () => {
      let i = 0;
      const s = await shippedBlockProxy(() => {
        const c = benign[i++];
        return { body: replyFor(path, c.response?.content || 'Done.') };
      });
      const refused = [];
      try {
        for (const c of benign) {
          const userText = c.request.messages.filter((m) => m.role === 'user').map((m) => m.content).join('\n') || c.request.messages.at(-1).content;
          const body = path === '/v1/chat/completions' ? { model: 'x', messages: c.request.messages } : bodyFor(path, userText);
          const r = await post(`${s.url}${path}`, body);
          if (r.status !== 200) refused.push(`${c.id}: ${r.status} ${r.body.toString('utf8').slice(0, 80)}`);
        }
      } finally { await s.close(); }
      assert.deepEqual(refused, [], `benign refusals on ${path}`);
    });
  }
});

describe('#126-1 inspector units', () => {
  test('nonChatCanaryInspector: skips T3 chat paths and non-POST; verdict carries ids, never values', async () => {
    const { nonChatCanaryInspector } = await import('../inspectors.mjs');
    const insp = nonChatCanaryInspector(DVAA_HONEYTOKENS, { skipPaths: defaults.T3_CHAT_PATHS });
    const body = Buffer.from(JSON.stringify({ message: Buffer.from(ADMIN).toString('base64') }));
    for (const p of defaults.T3_CHAT_PATHS) assert.equal(await insp({ phase: 'request', method: 'POST', path: p, body }), null, `${p} left to T3`);
    assert.equal(await insp({ phase: 'request', method: 'GET', path: '/chat', body }), null);
    assert.equal(await insp({ phase: 'response', method: 'POST', path: '/chat', body }), null);
    const v = await insp({ phase: 'request', method: 'POST', path: '/chat?x=1', body });
    assert.equal(v.flagged, true);
    assert.ok(v.hits.some((h) => h.needle_id === 'DVAA-ADMIN-PASSWORD' && h.form === 'base64'));
    assert.ok(!JSON.stringify(v).includes(ADMIN) && !JSON.stringify(v).includes(Buffer.from(ADMIN).toString('base64').slice(0, 12)), 'secret-free verdict');
  });

  test('observe mode: canary-bearing /chat reply is forwarded but raises a would-block ALERT', async () => {
    const up = await startUpstream(() => ({ body: { response: LEAK } }));
    const cfg = makeConfig({ target: { port: up.port }, mode: 'observe' });
    const canaries = defaultCanaries(cfg);
    const scrub = makeLogScrubber(canaries);
    const { inspectors } = buildDefaultInspectors(cfg, { scrub, write: () => {} });
    const { proxy, url } = await startProxy(cfg, { inspectors, scrub });
    try {
      const r = await post(`${url}/chat`, { message: 'hi' });
      assert.equal(r.status, 200);
      await proxy.sink.flush();
      const a = readCapture(cfg.capture.path).find((x) => x.type === 'alert' && x.reason === 'flagged' && x.phase === 'response');
      assert.ok(a, 'would-block ALERT logged');
      assert.equal(a.action, 'would_block_observe_only');
      assert.ok(!JSON.stringify(a).includes(ADMIN));
    } finally { await proxy.close(); await up.close(); }
  });
});
