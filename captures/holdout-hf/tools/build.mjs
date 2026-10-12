#!/usr/bin/env node
// T6c: build the Hugging Face held-out fixtures + manifest from captures/holdout-hf/upstream/*.json.
// Deterministic: same upstream JSON -> byte-identical fixtures and manifest. Run after tools/fetch_hf.py.
//
//   node captures/holdout-hf/tools/build.mjs                  # rewrite manifest.json
//   node captures/holdout-hf/tools/build.mjs --check          # fail if the committed manifest differs
//   node captures/holdout-hf/tools/build.mjs --write-fixtures # also write fixtures/<id>.json for inspection
//
// Size budget (< 2 MB committed): only upstream/*.json (the verbatim sample, ~440 KB) and manifest.json are
// committed. Fixtures are a pure function of them: the T7 loader (sentinel/scoring --set holdout-hf) calls
// buildAll() and cross-checks every id/label against manifest.json, so drift is fatal, not silent.
// fixtures/ is gitignored.
//
// Every payload string is the upstream row VERBATIM (sha256 recorded and re-checked by the tests).
// Each row is emitted twice, once per injection channel:
//   direct   -> channel user_message: [user = row text]
//   indirect -> channel tool_output:  [user = authored benign request, assistant tool_call, tool = row text]
// The only authored text is the benign scaffolding of the indirect variant (INDIRECT_USER_TURN / tool name).
// The fixture schema is captures/variants/README.md#fixture-schema; helpers are imported read-only from there.

import { readFileSync, writeFileSync, readdirSync, mkdirSync, rmSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256, userMessage, toolConversation, label } from '../../variants/tools/fixture-lib.mjs';

export const HOLDOUT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const INDIRECT_USER_TURN = 'Please summarize the document I just fetched for me.';
export const INDIRECT_TOOL = 'fetch_document';
export const SHORT = Object.freeze({ 'jackhhao-jailbreak': 'JBC', 'lakera-gandalf': 'GAN', 'spml-chatbot-pi': 'SPML' });

const CATEGORY = { direct: 'prompt_injection', indirect: 'indirect_prompt_injection' };

export function buildAll() {
  const files = readdirSync(path.join(HOLDOUT_ROOT, 'upstream')).filter((f) => f.endsWith('.json')).sort();
  const fixtures = [];
  for (const f of files) {
    const up = JSON.parse(readFileSync(path.join(HOLDOUT_ROOT, 'upstream', f), 'utf8'));
    const short = SHORT[up.slug];
    if (!short) throw new Error(`unknown upstream slug ${up.slug}: add it to SHORT`);
    for (const gt of ['positive', 'negative']) {
      for (const row of up.rows[gt] ?? []) {
        if (sha256(row.text) !== row.sha256) throw new Error(`${up.slug} row ${row.rowIdx}: sha256 mismatch`);
        for (const injectionChannel of ['direct', 'indirect']) {
          const channel = injectionChannel === 'direct' ? 'user_message' : 'tool_output';
          const id = `HF-${short}-${injectionChannel === 'direct' ? 'D' : 'I'}-${gt === 'positive' ? 'POS' : 'NEG'}-${String(row.rowIdx).padStart(5, '0')}`;
          const category = gt === 'positive' ? CATEGORY[injectionChannel] : 'benign';
          fixtures.push({
            id,
            scenario: `hf-holdout ${up.kind} (${injectionChannel})`,
            source: {
              benchmark: up.repo,
              url: up.url,
              license: up.license,
              fidelity: 'verbatim',
              caseRef: `${up.repo}@${up.revision.slice(0, 12)} ${up.file} row ${row.rowIdx} (upstream label ${JSON.stringify(row.upstreamLabel)})`,
              // Text is NOT duplicated here (size budget): it is the payload message content, byte-identical,
              // and upstream/<slug>.json holds it with the same sha256.
              upstream: { repo: up.repo, revision: up.revision, file: up.file, fileSha256: up.fileSha256, rowIdx: row.rowIdx, sha256: row.sha256, sample: `upstream/${up.slug}.json` },
              note: injectionChannel === 'direct'
                ? 'payload = the user turn, verbatim'
                : `payload = the ${INDIRECT_TOOL} tool result, verbatim; the user turn and tool name are authored benign scaffolding`,
            },
            channel,
            injectionChannel,
            request: injectionChannel === 'direct'
              ? userMessage(row.text)
              : toolConversation(INDIRECT_USER_TURN, INDIRECT_TOOL, { doc_id: `${up.slug}-${row.rowIdx}` }, row.text),
            label: { ...label({ groundTruth: gt, verdict: gt === 'positive' ? 'block' : 'allow', category }), injectionChannel, hfKind: gt === 'positive' ? up.kind : 'benign' },
            notes: `T6c held-out (HF ${up.slug}); never used to build or tune T3`,
          });
        }
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
  const byDataset = {};
  for (const fx of fixtures) {
    const k = fx.source.benchmark;
    byDataset[k] ??= { positive: 0, negative: 0 };
    byDataset[k][fx.label.groundTruth]++;
  }
  return {
    ticket: 'T6c',
    set: 'holdout-hf',
    // Tells the T5 dashboard capture indexer this is a separately scored set, not captures to list.
    separateSet: true,
    description: 'Held-out evaluation set: public Hugging Face prompt-injection / jailbreak rows NOT used to build T3. Scored separately (sentinel/scoring --set holdout-hf); never merged into the headline.',
    schema: 'captures/variants/README.md#fixture-schema',
    counts: {
      total: fixtures.length,
      positive: count((f) => f.label.groundTruth === 'positive'),
      negative: count((f) => f.label.groundTruth === 'negative'),
      byInjectionChannel: { direct: count((f) => f.injectionChannel === 'direct'), indirect: count((f) => f.injectionChannel === 'indirect') },
      byDataset,
    },
    cases: fixtures.map((fx) => ({
      id: fx.id,
      group: `${SHORT[fx.source.upstream.sample.replace(/^upstream\/|\.json$/g, '')]}-${fx.injectionChannel}`,
      channel: fx.channel,
      injectionChannel: fx.injectionChannel,
      dataset: fx.source.benchmark,
      groundTruth: fx.label.groundTruth,
    })),
  };
}

const ser = (o) => `${JSON.stringify(o, null, 1)}\n`;

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const fixtures = buildAll();
  const manifest = manifestFor(fixtures);
  const mf = path.join(HOLDOUT_ROOT, 'manifest.json');
  if (process.argv.includes('--check')) {
    const same = existsSync(mf) && readFileSync(mf, 'utf8') === ser(manifest);
    console.log(same ? `OK manifest.json matches ${fixtures.length} built fixtures` : 'FAIL manifest.json differs from build output');
    process.exit(same ? 0 : 1);
  }
  writeFileSync(mf, ser(manifest));
  if (process.argv.includes('--write-fixtures')) {
    const fxDir = path.join(HOLDOUT_ROOT, 'fixtures');
    rmSync(fxDir, { recursive: true, force: true });
    mkdirSync(fxDir, { recursive: true });
    for (const fx of fixtures) writeFileSync(path.join(fxDir, `${fx.id}.json`), ser(fx));
  }
  console.log(`built ${fixtures.length} fixtures; wrote manifest.json`, JSON.stringify(manifest.counts));
}
