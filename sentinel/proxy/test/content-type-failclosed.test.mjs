// #157: request bodies by content-type / encoding. Benign fixtures only (no canaries, no attack text).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import zlib from 'node:zlib';
import { startUpstream, startProxy, makeConfig, post, dvaaCompletion } from './helpers.mjs';

const BINARY = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0xff, 0xfe, 0x00, 0x80, 0xc3]); // PNG-like header + invalid UTF-8
const chat = (content) => Buffer.from(JSON.stringify({ model: 'm', messages: [{ role: 'user', content }] }));
const BENIGN = [
  ['application/json', chat('What is the weather like in Santa Clara today?')],
  ['application/json; charset=utf-8', chat('Summarise this paragraph about gardening, please.')],
  ['text/plain', Buffer.from('hello, just a plain note')],
  ['application/x-www-form-urlencoded', Buffer.from('q=hello+world&page=2')],
  ['multipart/form-data; boundary=b', Buffer.from('--b\r\nContent-Disposition: form-data; name="note"\r\n\r\nhi there\r\n--b--\r\n')],
  ['application/json', chat(`see image data:image/png;base64,${BINARY.toString('base64')}`)], // base64 data URI is text
  [undefined, chat('no content-type header at all')],
  ['application/x-unknown-type', Buffer.from('unknown type but plain text')],
];

for (const mode of ['block', 'observe']) {
  test(`${mode}: benign text bodies of any content-type pass through unaffected`, async () => {
    const up = await startUpstream(() => ({ body: dvaaCompletion('ok') }));
    const alerts = [];
    const { proxy, url } = await startProxy(makeConfig({ target: { port: up.port }, mode }), { logAlert: (a) => alerts.push(a) });
    try {
      for (const [ct, body] of BENIGN) {
        const r = await post(`${url}/v1/chat/completions`, body, { headers: ct ? { 'content-type': ct } : {} });
        assert.equal(r.status, 200, `${ct}`);
      }
      // gzip / deflate encoded benign JSON is decoded and inspected, not refused
      for (const [enc, fn] of [['gzip', zlib.gzipSync], ['deflate', zlib.deflateSync]]) {
        const r = await post(`${url}/v1/chat/completions`, fn(chat('compressed hello')), { headers: { 'content-type': 'application/json', 'content-encoding': enc } });
        assert.equal(r.status, 200, enc);
      }
      assert.equal(up.received.length, BENIGN.length + 2);
      assert.equal(alerts.filter((a) => a.reason === 'uninspectable_content').length, 0);
    } finally { await proxy.close(); await up.close(); }
  });

  test(`${mode}: binary request bodies (octet-stream, unknown, gzip-wrapped binary) -> block refuses 415, observe forwards + ALERT`, async () => {
    const up = await startUpstream(() => ({ body: dvaaCompletion('ok') }));
    const alerts = [];
    const { proxy, url } = await startProxy(makeConfig({ target: { port: up.port }, mode }), { logAlert: (a) => alerts.push(a) });
    try {
      const cases = [
        [{ 'content-type': 'application/octet-stream' }, BINARY],
        [{ 'content-type': 'image/png' }, BINARY],
        [{}, BINARY],
        [{ 'content-type': 'application/json', 'content-encoding': 'gzip' }, zlib.gzipSync(BINARY)],
        [{ 'content-type': 'multipart/form-data; boundary=b' }, Buffer.concat([Buffer.from('--b\r\n\r\n'), BINARY, Buffer.from('\r\n--b--\r\n')])],
      ];
      for (const [headers, body] of cases) {
        for (const path of ['/v1/chat/completions', '/chat']) {
          const r = await post(`${url}${path}`, body, { headers });
          if (mode === 'block') {
            assert.equal(r.status, 415, JSON.stringify(headers));
            assert.equal(JSON.parse(r.body).error.code, 'uninspectable_content');
          } else assert.equal(r.status, 200);
        }
      }
      assert.equal(up.received.length, mode === 'block' ? 0 : cases.length * 2);
      const a = alerts.filter((x) => x.reason === 'uninspectable_content');
      assert.equal(a.length, cases.length * 2);
      assert.ok(a.every((x) => x.action === (mode === 'block' ? 'fail_closed' : 'forwarded_uninspected')));
    } finally { await proxy.close(); await up.close(); }
  });
}

test('binary RESPONSE bodies are unchanged (prevention boundary: response side is not refused for content type)', async () => {
  const up = await startUpstream(() => ({ headers: { 'content-type': 'application/octet-stream' }, body: BINARY }));
  const { proxy, url } = await startProxy(makeConfig({ target: { port: up.port }, mode: 'block' }), { logAlert: () => {} });
  try {
    const r = await post(`${url}/file`, chat('fetch'), { headers: { 'content-type': 'application/json' } });
    assert.equal(r.status, 200);
    assert.ok(r.body.equals(BINARY));
  } finally { await proxy.close(); await up.close(); }
});
