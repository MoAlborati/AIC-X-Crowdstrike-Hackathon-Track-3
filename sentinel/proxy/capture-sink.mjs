// Append-only JSONL capture sink. Every proxied exchange and every alert becomes one line.
//
// Bodies are written IN FULL (never head/tail truncated). The per-record size is bounded upstream by
// limits.maxRequestBytes + limits.maxResponseBytes; the file as a whole is bounded by
// capture.maxFileBytes. When a write would push the file past that cap the sink throws
// CaptureFullError (fail-loud) instead of dropping or truncating the record. The proxy turns that
// into a 503 + stderr ALERT, so an exchange is never forwarded without being logged.
//
// The file holds full plaintext secrets, so it is owner-only: created 0600 (directory 0700 when we
// create it), and an existing file with group/other bits is tightened to 0600 before the first write.

import { appendFile, chmod, mkdir, stat } from 'node:fs/promises';

export const CAPTURE_FILE_MODE = 0o600;
import { dirname } from 'node:path';

export class CaptureFullError extends Error {
  constructor({ fileBytes, recordBytes, cap }) {
    super(`capture sink full: file=${fileBytes}B + record=${recordBytes}B exceeds cap=${cap}B`);
    this.name = 'CaptureFullError';
    this.payload_size = fileBytes + recordBytes;
    this.cap = cap;
    this.action = 'refused_exchange';
  }
}

export class JsonlCaptureSink {
  /** @param {{path: string, maxFileBytes: number}} opts */
  constructor({ path, maxFileBytes }) {
    this.path = path;
    this.maxFileBytes = maxFileBytes;
    this._bytes = null; // lazily initialised from the existing file size
    this._chain = Promise.resolve(); // serialises appends so lines never interleave
  }

  async _init() {
    if (this._bytes !== null) return;
    await mkdir(dirname(this.path), { recursive: true, mode: 0o700 });
    try {
      const st = await stat(this.path);
      if ((st.mode & 0o077) !== 0) await chmod(this.path, CAPTURE_FILE_MODE);
      this._bytes = st.size;
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
      this._bytes = 0;
    }
  }

  /**
   * Append one record. Resolves once the line is on disk; rejects (fail-loud) on cap or I/O error.
   * @param {object} record
   */
  write(record) {
    const run = async () => {
      await this._init();
      const line = JSON.stringify(record) + '\n';
      const recordBytes = Buffer.byteLength(line);
      if (this._bytes + recordBytes > this.maxFileBytes) {
        throw new CaptureFullError({ fileBytes: this._bytes, recordBytes, cap: this.maxFileBytes });
      }
      await appendFile(this.path, line, { mode: CAPTURE_FILE_MODE });
      this._bytes += recordBytes;
    };
    const p = this._chain.then(run);
    // Keep the chain alive after a failure; the caller still sees the rejection via `p`.
    this._chain = p.catch(() => {});
    return p;
  }

  /** Resolves when every write queued so far has settled. */
  flush() {
    return this._chain;
  }
}
