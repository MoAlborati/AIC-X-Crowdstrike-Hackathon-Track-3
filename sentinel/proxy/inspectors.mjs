// Inspector contract (the hook T3 detectors plug into):
//
//   async function inspector({ phase, path, headers, body, requestId, status? })
//     -> { flagged: boolean, detector: string, reasons: string[], ...extra } | null
//
// `body` is the FULL Buffer (bounded only by limits.max{Request,Response}Bytes, which reject loudly
// on overflow). Inspectors must scan all of it — no head/tail windows. Throwing is allowed: the proxy
// fails closed in block mode and logs an ALERT in observe mode.

/**
 * Placeholder detector until T3 lands: flags a body containing any configured substring
 * (e.g. a planted honeytoken). Full-buffer scan via Buffer#indexOf, so a marker anywhere in a
 * multi-MB body is found.
 * @param {readonly string[]} needles
 */
export function substringInspector(needles) {
  const encoded = needles.map((n) => ({ text: n, buf: Buffer.from(n, 'utf8') }));
  return async function substring({ body }) {
    const hits = [];
    for (const { text, buf } of encoded) {
      const at = body.indexOf(buf);
      if (at !== -1) hits.push({ needle: text, offset: at });
    }
    if (hits.length === 0) return null;
    return {
      flagged: true,
      detector: 'substring',
      reasons: hits.map((h) => `matched configured substring at byte ${h.offset}`),
      hits,
    };
  };
}
