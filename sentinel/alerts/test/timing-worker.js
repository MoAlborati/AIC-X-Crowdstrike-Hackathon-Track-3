// Worker for test/redact-adversarial.test.js: runs the REAL buildAlert on an adversarial verdict and
// reports per-run CPU time of this worker thread (and wall time, for the log). Runs in a worker thread so the parent can enforce a hard deadline
// (terminate) — a superlinear regex blocks synchronously and could not be interrupted in-process.
import { parentPort, workerData } from 'node:worker_threads';
import { buildAlert } from '../schema.js';
import { makeVerdict } from './helpers.js';

const fill = (unit, n) => unit.repeat(Math.ceil(n / unit.length)).slice(0, n);

function verdictFor({ fields, unit, len, canaryFlood, overlapCanaries, canaries }) {
  const v = makeVerdict('egress_secret_pattern', 0);
  if (canaries) v.canaries = canaries;
  if (overlapCanaries) {
    // canaries 'a'x8 … 'a'x(8+count-1): against an all-'a' (or all-'%61') input every offset matches
    // every canary — the most expensive canary shape found in review round 3 (one merged group).
    v.canaries = Array.from({ length: overlapCanaries }, (_, i) => ({ id: `O${i}`, value: 'a'.repeat(8 + i) }));
  }
  if (canaryFlood) {
    // max canary count x max value length, each a near-miss of the input (worst case for substring search)
    v.canaries = Array.from({ length: canaryFlood.count }, (_, i) => ({
      id: `C${i}`, value: 'a'.repeat(canaryFlood.valueLen - 4) + 'b' + String(i).padStart(3, '0'),
    }));
  }
  const s = fill(unit, len);
  for (const f of fields) {
    if (f === 'evidence') v.evidence = s;
    else if (f === 'argsPreview') v.entities.toolCall.argsPreview = s;
    else if (f === 'destination') v.entities.sink.destination = s;
    else if (f === 'narrative') v.caseCard = { ...(v.caseCard ?? {}), narrative: s };
    else if (f === 'originatedIn') v.caseCard = { ...(v.caseCard ?? {}), originatedIn: s };
    else throw new Error(`unknown field ${f}`);
  }
  return v;
}

const warnings = [];
const onWarning = (msg) => warnings.push(msg);
buildAlert(makeVerdict('egress_secret_pattern', 1, { evidence: 'warm-up eyJ AKIA 123-45-6789' }), { onWarning });
// CPU time, not wall clock (flake fix): under merge-gate load (~16 runnable agents) wall clock measures the
// scheduler, not the redactor (SSN flood measured 488 ms wall vs ~20 ms CPU). threadCpuUsage bills only
// THIS worker thread (not GC helper threads); process.cpuUsage is the fallback on Node < 22.19. A superlinear
// regression is 10-1000x in CPU time too, so the budgets keep their meaning; the parent's DEADLINE_MS
// wall-clock kill still catches a real hang.
const cpuUsage = typeof process.threadCpuUsage === 'function' ? (prev) => process.threadCpuUsage(prev) : (prev) => process.cpuUsage(prev);
const times = [];
const walls = [];
let last;
for (let i = 0; i < workerData.runs; i++) {
  const v = verdictFor(workerData); // fresh verdict each run; construction is outside the timed region
  const c0 = cpuUsage();
  const t0 = performance.now();
  last = buildAlert(v, { onWarning });
  walls.push(performance.now() - t0);
  const c = cpuUsage(c0);
  times.push((c.user + c.system) / 1000);
}
parentPort.postMessage({ times, walls, byKind: last.Redactions.ByKind, evidenceLen: last.Evidence?.length ?? 0 });
