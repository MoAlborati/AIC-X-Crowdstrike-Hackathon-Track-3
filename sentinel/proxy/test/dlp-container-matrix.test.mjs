// #157 empirical DLP matrix: our OWN fake canary wrapped in containers/encodings, pushed through the REAL
// createProxy (block mode, stub upstream; request + response phases) and the REAL egress inspectEgress.
// Only sensitive content = the project's fake honeytoken. No injection/instruction text.
// Prints a markdown matrix (set DLP_MATRIX_OUT=path to also write it). Asserts only the cases the #157
// fix closes; everything else is recorded as-is for the known-limitations table.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import zlib from 'node:zlib';
import { writeFileSync } from 'node:fs';
import { startUpstream, startProxy, makeConfig, post, dvaaCompletion } from './helpers.mjs';
import { buildDefaultInspectors } from '../default-inspectors.mjs';
import { inspectEgress, loadHoneytokens, makeAllowlist } from '../../egress/policy.mjs';

const CANARY = 'sk-sentinel-HONEY-7f3a9c2e1b';
const crc = (b) => zlib.crc32(b);
function pngWithText(text) {
  const chunk = (type, data) => { const len = Buffer.alloc(4); len.writeUInt32BE(data.length); const td = Buffer.concat([Buffer.from(type), data]); const c = Buffer.alloc(4); c.writeUInt32BE(crc(td)); return Buffer.concat([len, td, c]); };
  const ihdr = Buffer.from([0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0]);
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', ihdr),
    chunk('tEXt', Buffer.from(`Comment\0${text}`)), chunk('IDAT', zlib.deflateSync(Buffer.from([0, 0]))), chunk('IEND', Buffer.alloc(0))]);
}
function jpegWithComment(text) {
  const c = Buffer.from(text); const len = Buffer.alloc(2); len.writeUInt16BE(c.length + 2);
  return Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xfe]), len, c, Buffer.from([0xff, 0xd9])]);
}
function zipWithText(name, text) {
  const data = zlib.deflateRawSync(Buffer.from(text)); const n = Buffer.from(name);
  const h = Buffer.alloc(30); h.writeUInt32LE(0x04034b50, 0); h.writeUInt16LE(20, 4); h.writeUInt16LE(8, 8);
  h.writeUInt32LE(crc(Buffer.from(text)), 14); h.writeUInt32LE(data.length, 18); h.writeUInt32LE(text.length, 22); h.writeUInt16LE(n.length, 26);
  return Buffer.concat([h, n, data]);
}
const json = (s) => Buffer.from(JSON.stringify({ model: 'm', messages: [{ role: 'user', content: s }] }));
const b64 = Buffer.from(CANARY).toString('base64');
const CASES = [
  ['plain JSON (control)', { 'content-type': 'application/json' }, json(`note ${CANARY}`)],
  ['gzip body', { 'content-type': 'application/json', 'content-encoding': 'gzip' }, zlib.gzipSync(json(`note ${CANARY}`))],
  ['deflate body', { 'content-type': 'application/json', 'content-encoding': 'deflate' }, zlib.deflateSync(json(`note ${CANARY}`))],
  ['base64 in JSON', { 'content-type': 'application/json' }, json(`blob ${b64}`)],
  ['data URI (text/plain;base64)', { 'content-type': 'application/json' }, json(`data:text/plain;base64,${b64}`)],
  ['multipart file part (text)', { 'content-type': 'multipart/form-data; boundary=b' }, Buffer.from(`--b\r\nContent-Disposition: form-data; name="f"; filename="a.txt"\r\nContent-Type: text/plain\r\n\r\n${CANARY}\r\n--b--\r\n`)],
  ['multipart file part (gzip file)', { 'content-type': 'multipart/form-data; boundary=b' }, Buffer.concat([Buffer.from('--b\r\nContent-Disposition: form-data; name="f"; filename="a.gz"\r\n\r\n'), zlib.gzipSync(CANARY), Buffer.from('\r\n--b--\r\n')])],
  ['octet-stream (raw text)', { 'content-type': 'application/octet-stream' }, Buffer.from(CANARY)],
  ['PNG tEXt chunk', { 'content-type': 'image/png' }, pngWithText(CANARY)],
  ['JPEG COM segment', { 'content-type': 'image/jpeg' }, jpegWithComment(CANARY)],
  ['zip (deflated text file)', { 'content-type': 'application/zip' }, zipWithText('a.txt', CANARY)],
  ['JSON labelled image/png', { 'content-type': 'image/png' }, json(`note ${CANARY}`)],
  ['text labelled octet-stream', { 'content-type': 'application/octet-stream' }, Buffer.from(`note ${CANARY}`)],
  ['UTF-16LE with BOM', { 'content-type': 'text/plain; charset=utf-16' }, Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(`note ${CANARY}`, 'utf16le')])],
  ['UTF-16LE no BOM', { 'content-type': 'text/plain; charset=utf-16le' }, Buffer.from(`note ${CANARY}`, 'utf16le')],
];
// Cases the #157 fix must close on the proxy request side (binary after decoding).
const FIX_CLOSES = new Set(['multipart file part (gzip file)', 'PNG tEXt chunk', 'JPEG COM segment', 'zip (deflated text file)', 'UTF-16LE with BOM']);

test('#157 DLP container matrix (proxy req/resp + egress), block mode', async () => {
  let respBody = null; let respHeaders = {};
  const up = await startUpstream(({ req }) => (req.url === '/resp' ? { headers: respHeaders, body: respBody } : { body: dvaaCompletion('ok') }));
  const cfg = makeConfig({ target: { port: up.port }, mode: 'block', inspect: { flagSubstrings: [CANARY] } });
  const { inspectors } = buildDefaultInspectors(cfg, { write: () => {} }); // the REAL shipped stack (CLI wiring)
  const { proxy, url } = await startProxy(cfg, { inspectors, logAlert: () => {} });
  const ecfg = { mode: 'block', allow: makeAllowlist(['canary']), honeytokens: loadHoneytokens([{ id: 'sentinel-honey', value: CANARY }]) };
  const rows = [];
  try {
    for (const [name, headers, body] of CASES) {
      const rows0 = {};
      for (const path of ['/v1/chat/completions', '/chat']) {
        const before = up.received.length;
        const r = await post(`${url}${path}`, body, { headers });
        const forwarded = up.received.length > before;
        rows0[path] = forwarded ? 'LEAK (forwarded)' : `blocked ${r.status} ${JSON.parse(r.body).error?.code ?? ''}`.trim();
      }
      respBody = body; respHeaders = { 'content-type': headers['content-type'], ...(headers['content-encoding'] ? { 'content-encoding': headers['content-encoding'] } : {}) };
      const rr = await post(`${url}/resp`, {});
      const resp = rr.status === 200 ? 'LEAK (returned)' : `blocked ${rr.status} ${JSON.parse(rr.body).error?.code ?? ''}`.trim();
      const hdrText = Object.entries(headers).map(([k, v]) => `${k}: ${v}\r\n`).join('');
      const ev = inspectEgress({ kind: 'http', method: 'POST', url: 'http://canary/upload', host: 'canary', headers: hdrText, body }, ecfg);
      const egress = ev.action === 'deny' ? `blocked (${ev.reasons?.join?.('+') ?? ev.reason_code ?? 'deny'})` : 'LEAK (forwarded)';
      rows.push({ name, chatReq: rows0['/v1/chat/completions'], otherReq: rows0['/chat'], resp, egress });
    }
  } finally { await proxy.close(); await up.close(); }
  const md = ['| container | proxy req /v1/chat/completions | proxy req /chat | proxy response | egress inspectEgress |', '|---|---|---|---|---|',
    ...rows.map((r) => `| ${r.name} | ${r.chatReq} | ${r.otherReq} | ${r.resp} | ${r.egress} |`)].join('\n');
  console.log(`\n${md}\n`);
  if (process.env.DLP_MATRIX_OUT) writeFileSync(process.env.DLP_MATRIX_OUT, md);
  for (const r of rows) {
    if (FIX_CLOSES.has(r.name)) {
      assert.ok(!r.chatReq.startsWith('LEAK'), `${r.name} chat req`);
      assert.ok(!r.otherReq.startsWith('LEAK'), `${r.name} /chat req`);
    }
  }
  assert.ok(!rows[0].chatReq.startsWith('LEAK'), 'control must be blocked');
});
