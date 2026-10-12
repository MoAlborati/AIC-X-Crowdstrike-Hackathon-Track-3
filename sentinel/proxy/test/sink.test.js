import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CaptureSink, encodeBody, decodeBody, sha256 } from '../sink.js';
import { CAPTURES } from './helpers.js';

const rows = readFileSync(join(CAPTURES, 'variants/corpus/benign-toolrows-400.json'));

describe('capture sink', () => {
  it('encodes bodies losslessly: utf8 when valid, base64 otherwise', () => {
    for (const buf of [rows, Buffer.from('résumé ✓ 🚀'), Buffer.from([0xff, 0x00, 0xc3, 0x28]), Buffer.alloc(0)]) {
      const e = encodeBody(buf);
      assert.equal(e.bytes, buf.length);
      assert.equal(e.sha256, sha256(buf));
      assert.ok(decodeBody(e).equals(buf));
    }
    assert.equal(encodeBody(Buffer.from([0xff])).encoding, 'base64');
  });

  it('rotates by size, keeps at most maxFiles, logs each deletion loudly, never splits a record', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sentinel-sink-'));
    const logs = [];
    const sink = new CaptureSink({ path: join(dir, 'x.jsonl'), maxFileBytes: 200_000, maxFiles: 3 }, (level, event, f) => logs.push({ level, event, ...f }));
    const N = 20; // 20 × ~48KB 400-row bodies ≈ 1MB through a 3 × 200KB budget
    for (let i = 0; i < N; i++) sink.write({ requestId: `r${i}`, request: { body: encodeBody(rows) } });
    const files = readdirSync(dir).sort();
    assert.deepEqual(files, ['x.jsonl', 'x.jsonl.1', 'x.jsonl.2']);
    const seen = [];
    for (const f of files) {
      assert.ok(statSync(join(dir, f)).size <= 200_000, `${f} exceeds maxFileBytes`);
      for (const line of readFileSync(join(dir, f), 'utf8').split('\n').filter(Boolean)) {
        const r = JSON.parse(line);
        assert.ok(decodeBody(r.request.body).equals(rows), 'every kept record holds the full 400-row body');
        seen.push(Number(r.requestId.slice(1)));
      }
    }
    const deletions = logs.filter((l) => l.event === 'sink_rotated_out');
    assert.ok(deletions.length > 0);
    assert.ok(deletions.every((l) => l.level === 'WARN' && l.action === 'delete-oldest'));
    // what is kept is exactly the newest contiguous run ending at the last write
    seen.sort((a, b) => a - b);
    assert.equal(seen.at(-1), N - 1);
    assert.deepEqual(seen, Array.from({ length: seen.length }, (_, k) => N - seen.length + k));
  });

  it('a single record larger than maxFileBytes becomes a loud stub, not a partial line', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sentinel-sink-'));
    const logs = [];
    const sink = new CaptureSink({ path: join(dir, 'x.jsonl'), maxFileBytes: 10_000, maxFiles: 2 }, (level, event, f) => logs.push({ level, event, ...f }));
    sink.write({ requestId: 'big', request: { method: 'POST', body: encodeBody(rows) }, response: null, outcome: { action: 'forwarded' } });
    const [line] = readFileSync(join(dir, 'x.jsonl'), 'utf8').split('\n').filter(Boolean);
    const r = JSON.parse(line);
    assert.equal(r.request.body, null);
    assert.equal(r.captureFailed.cap, 10_000);
    assert.ok(r.captureFailed.size > 10_000);
    assert.equal(r.captureFailed.action, 'stub-record-written');
    assert.equal(logs.find((l) => l.event === 'sink_record_too_large').level, 'ALERT');
  });
});
