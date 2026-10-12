// #164: egress decodes content-encoding (gzip/deflate/br), embedded gzip/zip and UTF-16 before scanning.
// Our own fake canary only. Fail closed (uninspectable_body) on corrupt / over-cap encoded bodies.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import zlib from 'node:zlib';
import { inspectEgress, loadHoneytokens, makeAllowlist, REASON_CODES } from '../policy.mjs';

const CANARY = 'sk-sentinel-HONEY-7f3a9c2e1b';
const HT = loadHoneytokens([{ id: 'sentinel-honey', value: CANARY }]);
const cfg = (mode = 'block') => ({ mode, allow: makeAllowlist(['canary']), honeytokens: HT });
const send = (body, headers = '', mode) => inspectEgress({ kind: 'http', method: 'POST', url: 'http://canary/up', host: 'canary', headers, body }, cfg(mode));
const BENIGN = Buffer.from(JSON.stringify({ q: 'weather in Santa Clara', n: 3, note: 'hello world' }));

test('canary inside gzip / deflate / br / x-gzip content-encoding is denied', () => {
  const p = Buffer.from(`note ${CANARY}`);
  for (const [enc, b] of [['gzip', zlib.gzipSync(p)], ['x-gzip', zlib.gzipSync(p)], ['deflate', zlib.deflateSync(p)],
    ['deflate', zlib.deflateRawSync(p)], ['br', zlib.brotliCompressSync(p)], ['gzip, br', zlib.brotliCompressSync(zlib.gzipSync(p))]]) {
    const v = send(b, `Content-Encoding: ${enc}\r\n`);
    assert.equal(v.action, 'deny', enc);
    assert.ok(v.reasons.includes(REASON_CODES.HONEYTOKEN_MATCH), enc);
  }
});

test('canary in UTF-16LE/BE with and without BOM, and in an embedded gzip/zip, is denied', () => {
  const t = `note ${CANARY}`;
  const be = Buffer.from(t, 'utf16le'); be.swap16();
  for (const b of [Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(t, 'utf16le')]), Buffer.from(t, 'utf16le'),
    Buffer.concat([Buffer.from([0xfe, 0xff]), be]), be,
    Buffer.concat([Buffer.from('--b\r\n\r\n'), zlib.gzipSync(t), Buffer.from('\r\n--b--\r\n')])]) {
    assert.equal(send(b).action, 'deny');
  }
});

test('corrupt, unknown, stacked or over-cap encoded bodies fail closed (deny in block AND observe)', () => {
  const bomb = zlib.gzipSync(Buffer.alloc(1024 * 1024, 0x61)); // 1 MiB of 'a' -> ~1 KiB compressed, egress cap 64 KiB
  for (const [b, h] of [[Buffer.from('not gzip at all'), 'content-encoding: gzip\r\n'], [BENIGN, 'content-encoding: zstd\r\n'],
    [BENIGN, 'content-encoding: gzip,gzip,gzip,gzip,gzip\r\n'], [bomb, 'content-encoding: gzip\r\n']]) {
    for (const mode of ['block', 'observe']) {
      const v = send(b, h, mode);
      assert.equal(v.action, 'deny', `${h} ${mode}`);
      assert.ok(v.reasons.includes(REASON_CODES.UNINSPECTABLE_BODY), h);
    }
  }
});

test('benign traffic is unaffected: plain, gzip, deflate, identity, UTF-16, embedded gzip without canary all forward', () => {
  for (const [b, h] of [[BENIGN, ''], [zlib.gzipSync(BENIGN), 'content-encoding: gzip\r\n'], [zlib.deflateSync(BENIGN), 'content-encoding: deflate\r\n'],
    [BENIGN, 'content-encoding: identity\r\n'], [Buffer.from('hello world', 'utf16le'), ''],
    [Buffer.concat([Buffer.from('--b\r\n\r\n'), zlib.gzipSync('just a file'), Buffer.from('\r\n--b--\r\n')]), ''],
    [Buffer.from([0x1f, 0x8b, 0x08, 0, 1, 2, 3, 0x50, 0x4b, 0x03, 0x04, 9, 9]), '']]) { // sniffed-but-junk magic is ignored
    const v = send(b, h);
    assert.equal(v.action, 'forward', h || b.toString('hex').slice(0, 20));
    assert.deepEqual(v.reasons, []);
  }
});
