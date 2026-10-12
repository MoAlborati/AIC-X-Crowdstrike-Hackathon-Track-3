// Worker for the S1 (PR #12 review) stack test: runs the REAL redactDeep on the largest finding count
// one string can produce within the canary/scan bounds, under a deliberately small stack. A
// `findings.push(...r.findings)` spread puts every finding on the stack as an argument and overflows;
// a plain loop does not. Reports the outcome instead of throwing so the parent can assert on it.
import { parentPort, workerData } from 'node:worker_threads';
import * as redact from '../redact.js';

const { value, len } = workerData;
try {
  const r = redact.redactDeep({ rows: [value.repeat(Math.floor(len / value.length))] }, { canaries: [{ id: 'STK', value }] });
  parentPort.postMessage({ ok: true, findings: r.findings.length, leaked: r.value.rows[0].includes(value) });
} catch (e) {
  parentPort.postMessage({ ok: false, error: `${e.name}: ${e.message}` });
}
