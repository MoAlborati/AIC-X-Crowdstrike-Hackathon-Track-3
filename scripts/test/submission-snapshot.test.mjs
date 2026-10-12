// scripts/make-submission-snapshot.sh: the public-release scan must catch planted secrets and local
// paths wherever they hide in the snapshot tree, and the allowlist must not mask a real value.
// Run: node --test scripts/test/submission-snapshot.test.mjs
// Planted values are assembled from pieces so this file does not trip the scan it tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, copyFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@example.invalid',
  GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@example.invalid',
  SNAPSHOT_NO_GITLEAKS: '1',
};
const A = 'AK' + 'IA';
const KEY = {
  aws: A + 'ABCDEFGHIJKLMNOP',
  awsIgnored: A + 'QQQQQQQQQQQQQQQQ',
  ghExportIgnored: 'gh' + 'p_' + 'ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrq',
  fakeExtended: 'sk-' + 'ant-dvaa-test-anthropic-key-67890' + 'REALSUFFIXREAL',
  openaiUnderscore: 'sk-' + 'proj-' + 'ab_cdEFGHijklMNOPqrstUVWXyz0123456789ABCD',
  awsBesideFake: A + 'ZZZZZZZZZZZZZZZZ',
};
const HOME_PATH = '/' + 'home/someone/project';

function git(cwd, ...args) {
  const r = spawnSync('git', args, { cwd, encoding: 'utf8', env: ENV });
  assert.equal(r.status, 0, `git ${args.join(' ')}: ${r.stderr}`);
  return r.stdout.trim();
}

// A throwaway repo holding the real script + allowlist, with HEAD == origin/main.
function makeRepo(files, { gitignore = '', gitattributes = '' } = {}) {
  const dir = mkdtempSync(path.join(tmpdir(), 'snaptest-'));
  git(dir, 'init', '-q');
  mkdirSync(path.join(dir, 'scripts'));
  for (const f of ['make-submission-snapshot.sh', 'submission-scan-allowlist.tsv']) {
    copyFileSync(path.join(REPO, 'scripts', f), path.join(dir, 'scripts', f));
  }
  writeFileSync(path.join(dir, 'README.md'), '# test\n');
  if (gitignore) writeFileSync(path.join(dir, '.gitignore'), gitignore);
  if (gitattributes) writeFileSync(path.join(dir, '.gitattributes'), gitattributes);
  for (const [p, body] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(dir, p)), { recursive: true });
    writeFileSync(path.join(dir, p), body);
  }
  git(dir, 'add', '-A', '-f');
  git(dir, 'commit', '-qm', 'fixture');
  git(dir, 'update-ref', 'refs/remotes/origin/main', 'HEAD');
  return dir;
}

function snapshot(dir) {
  const r = spawnSync('bash', ['scripts/make-submission-snapshot.sh', '--skip-tests', '--no-fetch'],
    { cwd: dir, encoding: 'utf8', env: ENV });
  const branch = spawnSync('git', ['rev-parse', '-q', '--verify', 'refs/heads/submission-snapshot'],
    { cwd: dir, encoding: 'utf8' }).status === 0;
  return { status: r.status, out: r.stdout + r.stderr, branch };
}

test('clean tree with only allowlisted fakes passes and creates the local refs', () => {
  const dir = makeRepo({ 'docs/fixture.md': `honeytoken ${A}FAKEFAKEFAKEFAKE\n` });
  try {
    const r = snapshot(dir);
    assert.equal(r.status, 0, r.out);
    assert.match(r.out, /SNAPSHOT PASS/);
    assert.ok(r.branch);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('planted secrets and paths fail the scan wherever they hide; no ref is created', () => {
  const dir = makeRepo({
    'plant/plain.md': `aws ${KEY.aws}\npath ${HOME_PATH}\n`,
    'plant/mixed.md': `both ${A}FAKEFAKEFAKEFAKE ${KEY.awsBesideFake}\n`,
    'plant/extended.md': `key ${KEY.fakeExtended}\n`,
    'plant/openai.md': `key ${KEY.openaiUnderscore}\n`,
    // tracked although gitignored: still in the published commit
    '.secret': `${KEY.awsIgnored}\n`,
    // export-ignore: `git archive` drops it, the pushed commit does not
    'plant/exported.md': `${KEY.ghExportIgnored}\n`,
  }, { gitignore: '.secret\n', gitattributes: 'plant/exported.md export-ignore\n' });
  try {
    const r = snapshot(dir);
    assert.equal(r.status, 1, r.out);
    assert.match(r.out, /SNAPSHOT FAIL/);
    assert.equal(r.branch, false, 'no branch on a failed scan');
    for (const [name, v] of Object.entries(KEY)) {
      assert.ok(r.out.includes(v), `scan missed ${name}:\n${r.out}`);
    }
    assert.match(r.out, /HIT {2}local-path {2}plant\/plain\.md:2/);
    assert.ok(!r.out.includes(`${A}FAKEFAKEFAKEFAKE\n`), 'the allowlisted fake itself is inert');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('the script never pushes', () => {
  const src = spawnSync('grep', ['-nE', '^[^#]*\\bgit\\b[^#]*\\bpush\\b',
    path.join(REPO, 'scripts', 'make-submission-snapshot.sh')], { encoding: 'utf8' });
  // Only the printed owner instructions (indented heredoc lines) may mention git push.
  for (const line of src.stdout.split('\n').filter(Boolean)) {
    assert.match(line, /^\d+: {4}git push /, `unexpected push: ${line}`);
  }
});
