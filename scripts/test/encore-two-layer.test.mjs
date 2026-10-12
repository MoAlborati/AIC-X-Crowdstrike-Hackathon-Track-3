// scripts/encore-two-layer.sh smoke test.
//   - Always: bash -n, usage errors, bash 3.2 constructs absent, and a docker-less PATH exits 3 (SKIP).
//   - Live (docker + DVAA image present): block mode against the real DVAA image => 0 canary hits, exit 0.
//     Without docker/the image the live test SKIPS, unless ENCORE_REQUIRE_REAL=1 (then it fails loud).
// Isolation: a unique compose project + a /24 under 10.233.0.0/16 not used by any docker network, so it
// never shares containers or a subnet with a concurrent gate, the live egress suite (10.232.x) or a demo.
// Run: node --test scripts/test/encore-two-layer.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const SCRIPT = path.join(REPO, 'scripts', 'encore-two-layer.sh');
const IMAGE = process.env.DVAA_IMAGE || 'dvaa-t1-dvaa';
const run = (args, env = {}, timeout = 240000) =>
  spawnSync('bash', [SCRIPT, ...args], { env: { ...process.env, ...env }, encoding: 'utf8', timeout });

test('script parses and rejects bad arguments', () => {
  assert.equal(spawnSync('bash', ['-n', SCRIPT]).status, 0);
  assert.equal(run(['nonsense']).status, 2);
  assert.equal(run(['block', 'bad/label']).status, 2);
  assert.equal(run(['block', '..']).status, 2, 'run-label .. would rm -rf the parent of ENCORE_OUT');
  assert.equal(run(['block', '.']).status, 2);
});

test('bash 3.2 safe: no bash-4-only constructs', () => {
  const src = fs.readFileSync(SCRIPT, 'utf8').split('\n').map((l) => l.replace(/(^|\s)#.*$/, '')).join('\n'); // code only
  for (const bad of [/\bmapfile\b/, /\breadarray\b/, /declare -A/, /\$\{[A-Za-z_]+,,\}/, /\$\{[A-Za-z_]+\^\^\}/, /%N/, /&>>/]) {
    assert.doesNotMatch(src, bad);
  }
});

test('without docker the script skips cleanly (exit 3)', () => {
  const bin = fs.mkdtempSync(path.join(os.tmpdir(), 'encore-nodocker-'));
  fs.writeFileSync(path.join(bin, 'docker'), '#!/bin/sh\nexit 1\n', { mode: 0o755 });
  const r = run(['block', 'nodocker'], { PATH: `${bin}:${process.env.PATH}` }, 30000);
  fs.rmSync(bin, { recursive: true, force: true });
  assert.equal(r.status, 3, r.stderr);
  assert.match(r.stderr, /SKIP: docker not available/);
});

const haveDocker = spawnSync('docker', ['info'], { stdio: 'ignore' }).status === 0;
const haveImage = haveDocker && spawnSync('docker', ['image', 'inspect', IMAGE], { stdio: 'ignore' }).status === 0;
if (!haveImage && process.env.ENCORE_REQUIRE_REAL === '1') throw new Error(`ENCORE_REQUIRE_REAL=1 but docker/${IMAGE} unavailable`);

function freePrefix() {
  const ids = spawnSync('docker', ['network', 'ls', '-q'], { encoding: 'utf8' }).stdout.split('\n').filter(Boolean);
  const out = ids.length ? spawnSync('docker', ['network', 'inspect', '--format', '{{range .IPAM.Config}}{{.Subnet}} {{end}}', ...ids], { encoding: 'utf8' }).stdout : '';
  const used = new Set(out.split(/\s+/).filter(Boolean).map((c) => c.split('/')[0].split('.').slice(0, 3).join('.')));
  for (let i = 0; i < 64; i++) { const p = `10.233.${1 + randomBytes(1)[0] % 254}`; if (!used.has(p)) return p; }
  throw new Error('no free 10.233.x.0/24 subnet');
}

test('live: block mode, attacker receives 0 canary hits', { skip: haveImage ? false : `docker image ${IMAGE} unavailable` }, () => {
  const id = `${process.pid}-${randomBytes(3).toString('hex')}`;
  const out = path.join(REPO, '.eval', `encore-test-${id}`); // under the repo: Colima shares $HOME, not /tmp
  let r;
  for (let attempt = 0; attempt < 3; attempt++) { // a subnet raced by a concurrent run: retry on a fresh one
    r = run(['block', `t${attempt}`], { ENCORE_PROJECT: `sentinel-encore-test-${id}`, ENCORE_NET: freePrefix(), ENCORE_OUT: out });
    if (!/compose up failed/.test(r.stderr)) break;
  }
  try {
    assert.equal(r.status, 0, `${r.stdout}\n${r.stderr}`);
    assert.match(r.stdout, /GROUND_TRUTH canary hits for enc-t\d: 0 /);
    assert.match(r.stdout, /deny http .*honeytoken_match/);
    assert.match(r.stdout, /ENCORE PASS: block mode/);
    const left = spawnSync('docker', ['ps', '-aq', '--filter', `label=com.docker.compose.project=sentinel-encore-test-${id}`], { encoding: 'utf8' }).stdout.trim();
    assert.equal(left, '', 'script must remove its own containers');
  } finally {
    spawnSync('docker', ['run', '--rm', '-v', `${out}:/o`, 'node:24-alpine', 'chmod', '-R', 'a+rwX', '/o'], { stdio: 'ignore' });
    fs.rmSync(out, { recursive: true, force: true });
  }
});
