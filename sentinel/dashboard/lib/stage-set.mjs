// Stage mode (`?stage=1`): the capture dropdown lists only the stage runs the on-stage demo walks
// through, in order, instead of every indexed capture (357+). Each entry names a capture id + run key.
// An entry may list fallbacks; the first one present in the index wins (targeted Map lookups on the
// full index, never a scan of a capped list). An entry with no present candidate is returned with an
// `error`, and the UI shows it as a red banner and a disabled option. It is never silently dropped.

export const STAGE_ENTRIES = Object.freeze([
  {
    key: 'vulnerable',
    label: '1 · Vulnerable RAGBot: data leaves the sandbox',
    candidates: [{ id: 'attack/aim-ab.demo', run: 'runA' }],
  },
  {
    key: 'aim-twin',
    label: '2 · AIM twin: capability grant denies the call',
    candidates: [{ id: 'attack/aim-ab.demo', run: 'runB' }],
  },
  {
    key: 'proxy-blocked',
    label: '3 · Behind Tourniquet: blocked before the agent',
    candidates: [
      { id: 'stage/proxy-blocked-t3', run: 'run' },
      // T8 contrast recording (stand-in inspector); used only if the T3 stage recording is absent.
      { id: 'contrast/runs/proxy-block.demo', run: 'runB' },
    ],
  },
  {
    // T12 egress guard, block mode: real scripts/egress-demo.sh run (scripts/stage-egress-capture.sh).
    key: 'egress-blocked',
    label: '4 · Tool boundary: egress guard denied the exfil (attacker received nothing)',
    candidates: [{ id: 'stage/egress-blocked-t12', run: 'run' }],
  },
]);

/**
 * Resolve stage entries against the capture list (`/api/captures` items, which carry `runs`).
 * @param {Array<{id:string, error?:string, runs?:Array<{key:string}>}>} items
 * @returns {Array<{key, label, id?, run?, error?}>}
 */
export function resolveStage(items, entries = STAGE_ENTRIES) {
  const byId = new Map(items.map(c => [c.id, c]));
  return entries.map(e => {
    const tried = [];
    for (const c of e.candidates) {
      const cap = byId.get(c.id);
      if (!cap) { tried.push(`${c.id}#${c.run}: not indexed`); continue; }
      if (cap.error) { tried.push(`${c.id}#${c.run}: ${cap.error}`); continue; }
      if (!cap.runs?.some(r => r.key === c.run)) { tried.push(`${c.id}#${c.run}: no such run`); continue; }
      return { key: e.key, label: e.label, id: c.id, run: c.run, fallback: c !== e.candidates[0] };
    }
    return { key: e.key, label: e.label, error: `stage capture missing (${tried.join('; ')})` };
  });
}
