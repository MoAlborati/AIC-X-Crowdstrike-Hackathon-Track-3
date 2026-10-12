#!/usr/bin/env node
// DATA-ONLY extractor for the hackmyagent payload corpus (held-out eval set).
// It NEVER imports or runs any hackmyagent module. For each payload object in
// src/attack/payloads/*.ts it lexes the field values, and for the `payload:` RHS
// it constant-folds ONLY that isolated string-literal expression ('...' , `...`
// with no interpolation, or '...' + '...') inside a capability-free vm sandbox
// (no globals, no require, 1s timeout). No attack-engine code path executes.

import { readFileSync, readdirSync, writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import vm from 'node:vm';

const HMA = process.argv[2];                 // hackmyagent checkout
const OUT = process.argv[3];                 // captures/holdout-hackmyagent/upstream
const PIN = process.argv[4];                 // pinned commit sha
const PAYDIR = path.join(HMA, 'src', 'attack', 'payloads');

const sha256 = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

// map hackmyagent source file -> short slug + kind (= the category string)
const FIELD_KEYS = ['id', 'category', 'name', 'description', 'intensity', 'payload',
  'successIndicators', 'blockedIndicators', 'severity', 'oasbControl', 'remediation',
  'detectionNote', 'expectedBehavior', 'tags', 'variant', 'a2aMessage', 'mcpTool'];

// Fold one isolated constant string expression. Rejects anything that is not a
// pure string-literal concatenation (identifiers -> ReferenceError -> throw).
function foldString(expr) {
  const code = `"use strict"; (${expr})`;
  // Only pure, side-effect-free intrinsics needed to fold the literal expressions
  // ('x' + Array(n).fill('y').join('')). No I/O, no require, no process, no network.
  const ctx = vm.createContext({ Array, String, Number });
  const val = vm.runInContext(code, ctx, { timeout: 1000, displayErrors: false });
  if (typeof val !== 'string') throw new Error(`payload expr did not fold to a string: ${expr.slice(0, 60)}`);
  return val;
}

function extractFile(file) {
  const text = readFileSync(file, 'utf8');
  const lines = text.split('\n');
  const records = [];
  let cur = null;
  const single = (line, key) => {
    // field may appear anywhere on the line (fields are packed, e.g. `id: 'x', category: 'y'`)
    const m = line.match(new RegExp(`(?:^|[\\s,{])${key}:\\s*'((?:[^'\\\\]|\\\\.)*)'`));
    return m ? m[1] : null;
  };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const idv = single(line, 'id');
    if (idv && /^ATK-/.test(idv)) { cur = { id: idv, _line: i + 1 }; records.push(cur); /* same line may carry more fields */ }
    if (!cur) continue;
    if (cur.category == null) { const v = single(line, 'category'); if (v != null) cur.category = v; }
    if (cur.name == null) { const v = single(line, 'name'); if (v != null) cur.name = v; }
    if (cur.intensity == null) { const v = single(line, 'intensity'); if (v != null) cur.intensity = v; }
    if (cur.severity == null) { const v = single(line, 'severity'); if (v != null) cur.severity = v; }
    if (cur.payload == null && /(?:^|[\s,{])payload:\s*/.test(line)) {
      // capture the RHS expression, continuing across lines until the next known field key
      let rhs = line.replace(/^.*?(?:^|[\s,{])payload:\s*/, '');
      let j = i;
      const isNextField = (l) => new RegExp(`^\\s*(${FIELD_KEYS.join('|')}):`).test(l) && !/^\s*payload:/.test(l);
      while (!isNextField(lines[j + 1] ?? '') && (lines[j + 1] ?? '').trim() !== '},' && (lines[j + 1] ?? '').trim() !== '}') {
        j++;
        rhs += '\n' + lines[j];
        if (j - i > 40) break; // safety
      }
      rhs = rhs.replace(/,\s*$/, ''); // strip trailing comma separating the field
      cur.payload = foldString(rhs);
    }
  }
  return records;
}

const files = readdirSync(PAYDIR).filter((f) => f.endsWith('.ts') && f !== 'index.ts').sort();
mkdirSync(OUT, { recursive: true });
let grand = 0;
const summary = [];
for (const f of files) {
  const recs = extractFile(path.join(PAYDIR, f));
  if (!recs.length) throw new Error(`no payloads extracted from ${f}`);
  const category = recs[0].category;
  for (const r of recs) {
    if (!r.category || !r.name || !r.payload || !r.intensity) throw new Error(`incomplete record ${r.id} in ${f}`);
    if (r.category !== category) throw new Error(`mixed categories in ${f}: ${r.category} vs ${category}`);
  }
  const slug = f.replace(/\.ts$/, '');
  const rows = recs.map((r) => ({
    id: r.id,
    name: r.name,
    intensity: r.intensity,
    severity: r.severity ?? null,
    text: r.payload,
    sha256: sha256(r.payload),
  }));
  const up = {
    slug,
    category,
    repo: 'opena2a-org/hackmyagent',
    revision: PIN,
    file: `src/attack/payloads/${f}`,
    license: 'Apache-2.0',
    kind: category,
    url: `https://github.com/opena2a-org/hackmyagent/blob/${PIN}/src/attack/payloads/${f}`,
    count: rows.length,
    rows: { positive: rows },
  };
  writeFileSync(path.join(OUT, `${slug}.json`), JSON.stringify(up, null, 1) + '\n');
  grand += rows.length;
  summary.push(`${slug.padEnd(30)} ${category.padEnd(30)} ${rows.length}`);
}
console.log(summary.join('\n'));
console.log(`TOTAL payloads: ${grand} across ${files.length} categories`);
