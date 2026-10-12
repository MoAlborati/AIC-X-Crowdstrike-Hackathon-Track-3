// demo/run-demo.sh: a dashboard that fails to start must never end in "demo run clean".
// Critic D (#112) saw `demo run clean — no failing beats` while :9100 was held by another process and no dashboard
// came up, so the presenter could walk on stage with an empty right-hand screen.
// Real seam: the real runner, the real scripts/eval.sh dashboard and the real dashboard server; the only fake is a
// foreign HTTP listener holding the dashboard port (what another agent's dashboard looks like).
// Run: node --test scripts/test/run-demo-dashboard.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const RUNNER = path.join(REPO, 'demo', 'run-demo.sh');

// The holder runs in a CHILD process: the test blocks in spawnSync, so a server in this process could not accept
// connections and would stop looking busy once its backlog filled.
async function holdPort() {   // a foreign process answering 200 on the port, as another dashboard would
  const child = spawn(process.execPath, ['-e', `
    const s = require('node:http').createServer((q, r) => { r.writeHead(200); r.end('not ours'); });
    s.listen(0, '127.0.0.1', () => process.stdout.write(String(s.address().port) + '\\n'));`], { stdio: ['ignore', 'pipe', 'inherit'] });
  const port = await new Promise((resolve, reject) => {
    child.stdout.once('data', (d) => resolve(Number(String(d).trim())));
    child.once('exit', (c) => reject(new Error(`port holder exited ${c}`)));
  });
  return { port, close: () => child.kill() };
}

function runDemo(env) {
  const e = { ...process.env, ...env };
  delete e.EVAL_OUT; delete e.EVAL_REPO;   // behave as on stage: the runner's own repo and .eval/
  const res = spawnSync('bash', [RUNNER, '--auto', '--no-dvaa'], { cwd: REPO, encoding: 'utf8', env: e, timeout: 240_000 });
  return { status: res.status, out: `${res.stdout ?? ''}${res.stderr ?? ''}` };
}

test('busy dashboard port and no free port to move to: run FAILS, never "demo run clean"', async () => {
  const srv = await holdPort();
  const busy = srv.port;
  try {
    const { status, out } = runDemo({ EVAL_DASHBOARD_PORT: String(busy), DEMO_DASHBOARD_PORT_SCAN: '0' });
    assert.doesNotMatch(out, /demo run clean/, 'a run with no dashboard must not report clean');
    assert.notEqual(status, 0, `exit code must be non-zero, got ${status}`);
    assert.match(out, /preflight: dashboard\s+FAIL/, 'the dashboard row must be a FAIL in the Summary');
  } finally {
    srv.close();
  }
});

test('busy dashboard port: run moves to a free port, verifies the stage alerts there and prints that URL', async () => {
  const srv = await holdPort();
  const busy = srv.port;
  try {
    const { status, out } = runDemo({ EVAL_DASHBOARD_PORT: String(busy) });
    const m = out.match(/preflight: dashboard\s+PASS\s+up :(\d+) \(moved from busy :(\d+)\)/);
    assert.ok(m, `Summary must show the dashboard moved off the busy port:\n${out.slice(-3000)}`);
    const moved = Number(m[1]);
    assert.equal(Number(m[2]), busy);
    assert.notEqual(moved, busy);
    // The stage tabs on the NEW port carry the real block alerts (stage_verify ran against it).
    assert.match(out, /preflight: stage alerts\s+PASS/);
    assert.ok(out.includes(`http://127.0.0.1:${moved}/?stage=1&capture=proxy-blocked&step=last`), 'deep links use the new port');
    assert.ok(!out.includes(`http://127.0.0.1:${busy}/?stage=1`), 'no deep link may point at the busy port');
    if (/demo run clean/.test(out)) {
      assert.ok(out.includes(`demo run clean — no failing beats · dashboard http://127.0.0.1:${moved}/`),
        '"clean" must name the dashboard URL it actually started');
      assert.equal(status, 0);
    }
  } finally {
    srv.close();
  }
});
