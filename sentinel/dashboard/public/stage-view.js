// Pure helpers for stage presentation (no DOM), shared by app.js and the Node tests:
// deep links, stage-mode option list, sink/narrative display fixes, document excerpts, warning
// summaries and the "Copy alert JSON" clipboard payload.

export const SCHEMA_VERSION = 'sentinel.alert/1.0.0';

/**
 * Parse the page query. `?capture=<id>` is the deep link (`?id=` still accepted). `run`, `step`
 * (1-based number or `last`) and `stage=1` are optional.
 */
export function parseDeepLink(search) {
  const p = new URLSearchParams(search);
  const st = p.get('step');
  return {
    capture: p.get('capture') ?? p.get('id'),
    run: p.get('run'),
    step: st === 'last' ? Infinity : st != null && /^\d+$/.test(st) && Number(st) > 0 ? Number(st) - 1 : 0,
    stage: ['1', 'true', 'on'].includes((p.get('stage') ?? '').toLowerCase()),
  };
}

/** Query string for the current view, so the address bar is always a shareable deep link. */
export function deepLinkSearch({ capture, run, step = null, stage = false }) {
  const p = new URLSearchParams();
  if (stage) p.set('stage', '1');
  if (capture) p.set('capture', capture);
  if (run) p.set('run', run);
  if (step != null && Number.isFinite(step) && step > 0) p.set('step', String(step + 1));
  return `?${p.toString().replace(/%2F/g, '/')}`;
}

/**
 * Pick what to load from a deep link.
 * In stage mode the choice is restricted to resolved stage entries (`capture` may be a stage key or a
 * capture id). Returns {id, run, stageKey, warning}. `warning` is set when the link named something
 * that cannot be shown, so the UI can say so instead of silently showing something else.
 */
export function chooseInitial(link, captures, stage) {
  if (link.stage) {
    const usable = (stage ?? []).filter(s => !s.error);
    if (!usable.length) return { id: null, run: null, stageKey: null, warning: 'stage mode: no stage capture is available' };
    if (link.capture) {
      const hit = usable.find(s => s.key === link.capture && (!link.run || s.run === link.run))
        ?? usable.find(s => s.id === link.capture && (!link.run || s.run === link.run))
        ?? usable.find(s => s.id === link.capture);
      if (hit) return { id: hit.id, run: hit.run, stageKey: hit.key, warning: null };
      return { id: usable[0].id, run: usable[0].run, stageKey: usable[0].key, warning: `capture "${link.capture}" is not in the stage set; showing ${usable[0].label}` };
    }
    return { id: usable[0].id, run: usable[0].run, stageKey: usable[0].key, warning: null };
  }
  const ok = captures.filter(c => !c.error);
  const want = link.capture ? captures.find(c => c.id === link.capture) : null;
  if (want && !want.error) {
    const run = link.run && want.runs?.some(r => r.key === link.run) ? link.run : want.runs?.[0]?.key ?? null;
    const warning = link.run && run !== link.run ? `capture ${want.id} has no run "${link.run}"; showing ${run}` : null;
    return { id: want.id, run, stageKey: null, warning };
  }
  const first = ok[0] ?? null;
  const warning = link.capture ? `capture "${link.capture}" ${want ? `failed to load: ${want.error}` : 'not found'}; showing ${first?.id ?? 'nothing'}` : null;
  return { id: first?.id ?? null, run: first?.runs?.[0]?.key ?? null, stageKey: null, warning };
}

/** Options for the capture dropdown: only the three stage entries in stage mode, missing ones disabled. */
export function stageOptions(stage) {
  return (stage ?? []).map(s => ({
    value: `stage:${s.key}`,
    label: s.error ? `⚠ ${s.label} (missing)` : s.label,
    disabled: Boolean(s.error),
    id: s.id ?? null,
    run: s.run ?? null,
  }));
}

/** Sink text: a destination that already has a scheme is shown as-is (never "http:http://…"). */
export function sinkLabel(type, destination) {
  const d = String(destination ?? '');
  if (!d) return type ? String(type) : '';
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(d) || !type) return d;
  return `${d} (${type})`;
}

/**
 * Narratives recorded before the T4 fix say "toward http:http://h/p" or "toward http:127.0.0.1".
 * Display them as "toward http://h/p" and "toward 127.0.0.1 (http)". Only the T4 template phrase
 * "toward <type>:<destination>" is touched.
 */
export function cleanNarrative(text) {
  if (typeof text !== 'string') return text;
  return text.replace(/\btoward ([a-z][a-z0-9+.-]*):(?!\/\/)(\S+)/gi, (_, type, dest) => `toward ${sinkLabel(type, dest)}`);
}

/**
 * Excerpt for on-screen display with an explicit truncation marker. Prefers the first line that looks
 * like an instruction or URL (the part of a poisoned document that matters), else the start.
 * @returns {{text:string, shown:number, total:number, omitted:number, marker:string|null}}
 */
export function excerpt(text, max = 160) {
  const full = String(text ?? '');
  const total = full.length;
  if (total <= max) return { text: full, shown: total, total, omitted: 0, marker: null };
  const lines = full.split('\n');
  const key = lines.findIndex(l => /instruction|ignore (all|previous)|https?:\/\/|exfil|send .* to/i.test(l));
  const startLine = key > 0 ? key : 0;
  const start = lines.slice(0, startLine).reduce((n, l) => n + l.length + 1, 0);
  let cut = full.slice(start, start + max);
  const sp = cut.lastIndexOf(' ');
  if (sp > max * 0.6) cut = cut.slice(0, sp);
  const omitted = total - cut.length;
  return { text: `${start > 0 ? '… ' : ''}${cut}`, shown: cut.length, total, omitted, marker: `⋯ [truncated: ${omitted.toLocaleString('en-US')} more chars; click for full text]` };
}

/** One-line summary for replay warnings ("4 replay warnings · 4 unresolved taint hops"). */
export function warningSummary(warnings) {
  const n = warnings?.length ?? 0;
  if (!n) return null;
  const unresolved = warnings.filter(w => /no matching node/.test(w)).length;
  const other = n - unresolved;
  const parts = [];
  if (unresolved) parts.push(`${unresolved} unresolved taint hop${unresolved === 1 ? '' : 's'} (drawn as dashed "?" nodes)`);
  if (other) parts.push(`${other} other`);
  return `${n} replay warning${n === 1 ? '' : 's'} · ${parts.join(' · ')}`;
}

/**
 * Clipboard text for "Copy alert JSON": the /api/alert-export body's alert, pretty-printed.
 * Refuses (throws) anything that is not a T4 `sentinel.alert/1.0.0` alert, so the SOC never receives
 * an adapted view model or an error body by mistake.
 */
export function alertClipboardText(body) {
  const a = body?.alert;
  if (!a || typeof a !== 'object') throw new Error(body?.error ?? 'no alert in export response');
  if (a.SchemaVersion !== SCHEMA_VERSION) throw new Error(`export is ${a.SchemaVersion}, expected ${SCHEMA_VERSION}`);
  return JSON.stringify(a, null, 2);
}
