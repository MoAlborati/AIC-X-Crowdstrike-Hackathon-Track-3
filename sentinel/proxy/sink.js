// SentinelProxy T2 — capture sink: one JSON line per exchange, full bodies, size-bounded rotation.
//
// Bodies are stored whole (never head/tail-cut). A body that is valid UTF-8 is stored as `text`;
// anything else is stored as `base64`. `bytes` + `sha256` always describe the exact wire bytes, so a
// consumer can verify byte-for-byte fidelity.
//
// Bounds:
//   maxFileBytes — the active file rotates BEFORE a write would push it past this size.
//   maxFiles     — total files kept (active + rotated). Rotating past it deletes the oldest file and
//                  logs a loud `sink_rotated_out` event naming it (bounded disk, never a silent drop).
//   A record bigger than maxFileBytes on its own is NOT written partially: a stub record carrying
//   `captureFailed: {size, cap, action}` is written instead and an ALERT is logged. Config validation
//   sizes maxFileBytes so this is unreachable for bodies within the request/response caps.

import { appendFileSync, existsSync, mkdirSync, renameSync, statSync, unlinkSync } from 'node:fs';
import { dirname } from 'node:path';
import { createHash } from 'node:crypto';

export const SINK_SCHEMA_VERSION = 'sentinel.capture/1.0.0';

export const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

/** Encode a body Buffer losslessly for the sink. */
export function encodeBody(buf) {
  if (buf == null) return null;
  const text = buf.toString('utf8');
  const lossless = Buffer.byteLength(text, 'utf8') === buf.length && Buffer.from(text, 'utf8').equals(buf);
  return lossless
    ? { bytes: buf.length, sha256: sha256(buf), encoding: 'utf8', text }
    : { bytes: buf.length, sha256: sha256(buf), encoding: 'base64', base64: buf.toString('base64') };
}

/** Decode a sink body back to the exact wire bytes. */
export function decodeBody(body) {
  if (body == null) return null;
  return body.encoding === 'utf8' ? Buffer.from(body.text, 'utf8') : Buffer.from(body.base64, 'base64');
}

export class CaptureSink {
  /**
   * @param {{ path: string, maxFileBytes: number, maxFiles: number }} opts
   * @param {(level: string, event: string, fields: object) => void} log
   */
  constructor({ path, maxFileBytes, maxFiles }, log) {
    this.path = path;
    this.maxFileBytes = maxFileBytes;
    this.maxFiles = maxFiles;
    this.log = log;
    mkdirSync(dirname(path), { recursive: true });
    this.size = existsSync(path) ? statSync(path).size : 0;
    this.records = 0;
  }

  rotatedPath(i) {
    return `${this.path}.${i}`;
  }

  rotate() {
    const oldest = this.rotatedPath(this.maxFiles - 1);
    if (this.maxFiles === 1) {
      this.log('WARN', 'sink_rotated_out', { file: this.path, bytes: this.size, cap: this.maxFileBytes, maxFiles: 1, action: 'delete-oldest' });
      unlinkSync(this.path);
    } else {
      if (existsSync(oldest)) {
        this.log('WARN', 'sink_rotated_out', { file: oldest, bytes: statSync(oldest).size, maxFiles: this.maxFiles, action: 'delete-oldest' });
        unlinkSync(oldest);
      }
      for (let i = this.maxFiles - 2; i >= 1; i--) {
        if (existsSync(this.rotatedPath(i))) renameSync(this.rotatedPath(i), this.rotatedPath(i + 1));
      }
      renameSync(this.path, this.rotatedPath(1));
      this.log('INFO', 'sink_rotated', { file: this.path, to: this.rotatedPath(1), bytes: this.size, cap: this.maxFileBytes });
    }
    this.size = 0;
  }

  /** Append one record. Synchronous so a record is on disk before the client gets its response. */
  write(record) {
    let line = JSON.stringify({ schema: SINK_SCHEMA_VERSION, ...record }) + '\n';
    let bytes = Buffer.byteLength(line);
    if (bytes > this.maxFileBytes) {
      const captureFailed = { size: bytes, cap: this.maxFileBytes, action: 'stub-record-written' };
      this.log('ALERT', 'sink_record_too_large', { requestId: record.requestId, ...captureFailed });
      line = JSON.stringify({
        schema: SINK_SCHEMA_VERSION,
        requestId: record.requestId,
        ts: record.ts,
        captureFailed,
        request: record.request && { ...record.request, body: null, bodyOmittedReason: 'record exceeded sink.maxFileBytes' },
        response: record.response && { ...record.response, body: null, bodyOmittedReason: 'record exceeded sink.maxFileBytes' },
        outcome: record.outcome,
      }) + '\n';
      bytes = Buffer.byteLength(line);
    }
    if (this.size > 0 && this.size + bytes > this.maxFileBytes) this.rotate();
    appendFileSync(this.path, line);
    this.size += bytes;
    this.records++;
    return bytes;
  }
}
