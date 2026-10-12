#!/usr/bin/env node
// Held-out set (opena2a-org/hackmyagent): build fixtures + manifest from upstream/*.json.
// Deterministic: same upstream JSON -> byte-identical fixtures and manifest.
//
//   node captures/holdout-hackmyagent/tools/build.mjs                  # rewrite manifest.json
//   node captures/holdout-hackmyagent/tools/build.mjs --check          # fail if committed manifest differs
//   node captures/holdout-hackmyagent/tools/build.mjs --write-fixtures # also write fixtures/<id>.json
//
// Mirrors captures/holdout-hf/tools/build.mjs. Every `payload` string is the hackmyagent row VERBATIM
// (sha256 recorded and re-checked). Each payload is emitted twice, once per injection channel:
//   direct   -> channel user_message: [user = payload]
//   indirect -> channel tool_output:  [user = authored benign request, assistant tool_call, tool = payload]
// The ONLY authored text is the benign scaffolding of the indirect variant (INDIRECT_USER_TURN / tool name).
// hackmyagent's code is NEVER imported or executed: the payload strings were extracted as DATA (see LICENSES.md).
//
// label.category uses the corpus framework keys (prompt_injection | indirect_prompt_injection), NOT the 16
// hackmyagent categories. The hackmyagent category is preserved on every case as `group` and `hmaCategory`,
// so the scorer's per-group table (loadSet -> byGroup) is per hackmyagent category. All rows are attacks
// (positive); hackmyagent ships no benign rows, so benign negatives are reused from the main corpus by the
// T7 loader (see captures/holdout-hackmyagent/LICENSES.md and sentinel/scoring/src/corpus.mjs).

import { readFileSync, writeFileSync, readdirSync, mkdirSync, rmSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256, userMessage, toolConversation, label } from '../../variants/tools/fixture-lib.mjs';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const INDIRECT_USER_TURN = 'Please summarize the document I just fetched for me.';
export const INDIRECT_TOOL = 'fetch_document';
const CATEGORY = { direct: 'prompt_injection', indirect: 'indirect_prompt_injection' };

export function buildAll() {
  const files = readdirSync(path.join(ROOT, 'upstream')).filter((f) => f.endsWith('.json')).sort();
  const fixtures = [];
  for (const f of files) {
    const up = JSON.parse(readFileSync(path.join(ROOT, 'upstream', f), 'utf8'));
    for (const row of up.rows.positive ?? []) {
      if (sha256(row.text) !== row.sha256) throw new Error(`${up.slug} ${row.id}: sha256 mismatch (not verbatim)`);
      for (const injectionChannel of ['direct', 'indirect']) {
        const channel = injectionChannel === 'direct' ? 'user_message' : 'tool_output';
        const id = `HMA-${injectionChannel === 'direct' ? 'D' : 'I'}-${row.id}`; // row.id is ATK-...
        fixtures.push({
          id,
          scenario: `hackmyagent held-out ${up.category} (${injectionChannel})`,
          source: {
            benchmark: up.repo,
            url: up.url,
            license: up.license,
            fidelity: 'verbatim',
            caseRef: `${up.repo}@${up.revision.slice(0, 12)} ${up.file} ${row.id} (${row.name}; intensity ${row.intensity})`,
            upstream: { repo: up.repo, revision: up.revision, file: up.file, payloadId: row.id, sha256: row.sha256, sample: `upstream/${up.slug}.json` },
            note: injectionChannel === 'direct'
              ? 'payload = the user turn, verbatim'
              : `payload = the ${INDIRECT_TOOL} tool result, verbatim; the user turn and tool name are authored benign scaffolding`,
          },
          channel,
          injectionChannel,
          hmaCategory: up.category,
          request: injectionChannel === 'direct'
            ? userMessage(row.text)
            : toolConversation(INDIRECT_USER_TURN, INDIRECT_TOOL, { doc_id: `${up.slug}-${row.id}` }, row.text),
          label: { ...label({ groundTruth: 'positive', verdict: 'block', category: CATEGORY[injectionChannel] }), injectionChannel, hmaCategory: up.category, hmaIntensity: row.intensity },
          notes: `held-out (hackmyagent ${row.id} ${up.category}); never used to build or tune T3`,
        });
      }
    }
  }
  const ids = new Set();
  for (const fx of fixtures) {
    if (ids.has(fx.id)) throw new Error(`duplicate id ${fx.id}`);
    ids.add(fx.id);
  }
  return fixtures;
}

export function manifestFor(fixtures) {
  const count = (p) => fixtures.filter(p).length;
  const byCategory = {};
  for (const fx of fixtures) {
    byCategory[fx.hmaCategory] ??= { direct: 0, indirect: 0 };
    byCategory[fx.hmaCategory][fx.injectionChannel]++;
  }
  return {
    ticket: 'holdout-hackmyagent',
    set: 'holdout-hackmyagent',
    separateSet: true,
    description: 'HELD-OUT evaluation set: the DVAA authors\' own attack battery (opena2a-org/hackmyagent), 164 payloads x 16 categories, each placed direct + indirect. Payload strings copied VERBATIM as data; hackmyagent code is never executed. Scored separately (sentinel/scoring --set holdout-hackmyagent); NEVER merged into the headline.',
    schema: 'captures/variants/README.md#fixture-schema',
    source: { repo: 'opena2a-org/hackmyagent', revision: '033f4fa1fa3c1477272fb0942f298d6196d8e156', license: 'Apache-2.0' },
    counts: {
      total: fixtures.length,
      positive: count((f) => f.label.groundTruth === 'positive'),
      negative: count((f) => f.label.groundTruth === 'negative'),
      byInjectionChannel: { direct: count((f) => f.injectionChannel === 'direct'), indirect: count((f) => f.injectionChannel === 'indirect') },
      categories: Object.keys(byCategory).length,
      byCategory,
    },
    cases: fixtures.map((fx) => ({
      id: fx.id,
      group: fx.hmaCategory,
      channel: fx.channel,
      injectionChannel: fx.injectionChannel,
      dataset: fx.source.benchmark,
      hmaCategory: fx.hmaCategory,
      groundTruth: fx.label.groundTruth,
    })),
  };
}

const ser = (o) => `${JSON.stringify(o, null, 1)}\n`;

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const fixtures = buildAll();
  const manifest = manifestFor(fixtures);
  const mf = path.join(ROOT, 'manifest.json');
  if (process.argv.includes('--check')) {
    const same = existsSync(mf) && readFileSync(mf, 'utf8') === ser(manifest);
    console.log(same ? `OK manifest.json matches ${fixtures.length} built fixtures` : 'FAIL manifest.json differs from build output');
    process.exit(same ? 0 : 1);
  }
  writeFileSync(mf, ser(manifest));
  if (process.argv.includes('--write-fixtures')) {
    const fxDir = path.join(ROOT, 'fixtures');
    rmSync(fxDir, { recursive: true, force: true });
    mkdirSync(fxDir, { recursive: true });
    for (const fx of fixtures) writeFileSync(path.join(fxDir, `${fx.id}.json`), ser(fx));
  }
  console.log(`built ${fixtures.length} fixtures; wrote manifest.json`, JSON.stringify(manifest.counts));
}
