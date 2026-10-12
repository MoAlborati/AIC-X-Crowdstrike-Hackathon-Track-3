/**
 * Pins and fixed selection rules for the T6b upstream extracts (upstream-*.json). Kept separate from
 * upstream-cases.mjs so the extractors can import them without loading the generated JSON.
 */
export const DEEPSET_PIN = Object.freeze({
  dataset: 'deepset/prompt-injections',
  url: 'https://huggingface.co/datasets/deepset/prompt-injections',
  revision: '4f61ecb038e9c3fb77e21034b22511b523772cdd',
  split: 'test',
  parquetFile: 'data/test-00000-of-00001-701d16158af87368.parquet',
  parquetSha256: '39ac797cabc157eeed58435a08593b2952bb6cb16fc394a2d383f447cc7b246e',
  rowCount: 116,
});

export const INJECAGENT_PIN = Object.freeze({
  repo: 'https://github.com/uiuc-kang-lab/InjecAgent',
  commit: 'f19c9f2c79a41046eb13c03c51a24c567a8ffa07',
});
// Upstream case files are laid out attacker-case-major over 17 user tools: index = a*17 + u.
// Diagonal walk: one case per attacker case a, with the user tool rotating (u = a mod 17), so every
// attacker instruction AND every user tool is covered. (T6's original picks 17, 34 stay as IA-DS-001/002.)
export const INJECAGENT_USER_TOOLS = 17;
export const injecagentPick = (n) => Array.from({ length: Math.floor(n / INJECAGENT_USER_TOOLS) }, (_, a) => a * INJECAGENT_USER_TOOLS + (a % INJECAGENT_USER_TOOLS));
export const INJECAGENT_FILES = Object.freeze({
  'Data Stealing (DS), enhanced': 'data/test_cases_ds_enhanced.json',
  'Direct Harm (DH), enhanced': 'data/test_cases_dh_enhanced.json',
});

export const AGENTDOJO_PIN = Object.freeze({
  repo: 'https://github.com/ethz-spylab/agentdojo',
  commit: '089ed468cf3ed0322acc66b0211f26d9d90dbf60',
});
