// Bounded JSONL reader for the T2 proxy capture file. Two modes:
//   readJsonl(path, onRecord)          whole file, once
//   followJsonl(path, onRecord, opts)  tail -f: reads what exists, then polls for appended bytes
//
// Bounds (fail-loud): a line longer than MAX_LINE_BYTES throws PipelineBoundError with the byte
// offset. A partial line is only parsed once its '\n' arrives, so a record that is still being
// written is never half-parsed. A malformed complete line throws, naming the line number. A file
// that shrinks under us (truncated or rotated) throws, so we never resume at a stale offset.
//
// Polling (stat every pollMs), not fs.watch: fs.watch is unreliable on WSL2/network filesystems,
// and a missed event would silently stall the live feed.

import { open, stat } from 'node:fs/promises';
import { BOUNDS, PipelineBoundError, defaultLog } from './bounds.mjs';

const CHUNK = 1024 * 1024;

class LineSplitter {
  constructor(maxLineBytes, onLine) {
    this.max = maxLineBytes;
    this.onLine = onLine;
    this.parts = [];
    this.partBytes = 0;
    this.offset = 0; // file offset of the start of the current partial line
    this.lineNo = 0;
  }

  async push(buf) {
    let start = 0;
    while (start < buf.length) {
      const nl = buf.indexOf(0x0a, start);
      const end = nl === -1 ? buf.length : nl;
      const piece = buf.subarray(start, end);
      if (this.partBytes + piece.length > this.max) {
        throw new PipelineBoundError('MAX_LINE_BYTES', this.partBytes + piece.length, this.max, `JSONL line ${this.lineNo + 1} starting at byte ${this.offset}`, 'stopped_reading');
      }
      if (piece.length) { this.parts.push(Buffer.from(piece)); this.partBytes += piece.length; }
      if (nl === -1) break;
      const line = Buffer.concat(this.parts, this.partBytes).toString('utf8');
      this.lineNo += 1;
      const lineNo = this.lineNo;
      this.offset += this.partBytes + 1;
      this.parts = [];
      this.partBytes = 0;
      if (line.trim()) {
        let rec;
        try { rec = JSON.parse(line); } catch (err) { throw new Error(`JSONL line ${lineNo}: invalid JSON (${err.message})`); }
        await this.onLine(rec, lineNo);
      }
      start = nl + 1;
    }
  }
}

async function readRange(fh, from, to, splitter) {
  const buf = Buffer.allocUnsafe(Math.min(CHUNK, Math.max(1, to - from)));
  let pos = from;
  while (pos < to) {
    const { bytesRead } = await fh.read(buf, 0, Math.min(buf.length, to - pos), pos);
    if (bytesRead === 0) break;
    await splitter.push(buf.subarray(0, bytesRead));
    pos += bytesRead;
  }
  return pos;
}

/** Read every complete line once. A trailing line without '\n' is reported loudly, not dropped quietly. */
export async function readJsonl(path, onRecord, { maxLineBytes = BOUNDS.MAX_LINE_BYTES, log = defaultLog } = {}) {
  const splitter = new LineSplitter(maxLineBytes, onRecord);
  const fh = await open(path, 'r');
  try {
    const { size } = await fh.stat();
    await readRange(fh, 0, size, splitter);
  } finally {
    await fh.close();
  }
  if (splitter.partBytes > 0) {
    log({ level: 'ALERT', reason: 'incomplete_trailing_line', path, bytes: splitter.partBytes, line: splitter.lineNo + 1, action: 'not_parsed_record_still_being_written' });
  }
  return { lines: splitter.lineNo, trailingBytes: splitter.partBytes };
}

/**
 * Follow a growing JSONL file. Resolves when `signal` aborts; rejects on any bound/parse/IO error.
 * The file may not exist yet; we wait for it.
 */
export async function followJsonl(path, onRecord, { maxLineBytes = BOUNDS.MAX_LINE_BYTES, pollMs = 200, signal, onIdle } = {}) {
  const splitter = new LineSplitter(maxLineBytes, onRecord);
  let pos = 0;
  const sleep = (ms) => new Promise((r) => {
    const t = setTimeout(r, ms);
    signal?.addEventListener('abort', () => { clearTimeout(t); r(); }, { once: true });
  });
  while (!signal?.aborted) {
    let size;
    try {
      ({ size } = await stat(path));
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
      await sleep(pollMs);
      continue;
    }
    if (size < pos) throw new Error(`followJsonl: ${path} shrank from ${pos} to ${size} bytes (truncated or rotated); refusing to resume at a stale offset`);
    if (size > pos) {
      const fh = await open(path, 'r');
      try { pos = await readRange(fh, pos, size, splitter); } finally { await fh.close(); }
      await onIdle?.();
    }
    await sleep(pollMs);
  }
  return { lines: splitter.lineNo, offset: pos };
}
