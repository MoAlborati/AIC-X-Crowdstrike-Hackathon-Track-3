// scripts/chat-poll.sh: the chat intake poller, driven with fixture GitHub JSON through a stubbed `gh`
// on PATH (the stub applies the script's real --jq filter to the fixture with jq). `sleep` is stubbed too.
// Run: node --test scripts/test/chat-poll.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, chmodSync, mkdirSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const SCRIPT = path.join(REPO, 'scripts', 'chat-poll.sh');
const MARK = '<!-- orchestrator-reply -->';
const NOW = Date.parse('2026-10-12T20:00:00Z') / 1000; // 13:00 PDT
const iso = (secsAgo) => new Date((NOW - secsAgo) * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');

// Stub gh: `gh api [--paginate] <path> [--jq F]`. Routes the path to a fixture file and logs every call.
const GH_STUB = `#!/usr/bin/env bash
set -u
p=""; jqf="."
while [ $# -gt 0 ]; do
  case "$1" in api|--paginate) ;; --jq) shift; jqf="$1" ;; *) p="$1" ;; esac; shift
done
echo "$p" >> "$FIX/calls.log"
case "$p" in
  */issues\\?state=open*)   f="$FIX/open.json" ;;
  */issues\\?state=closed*) f="$FIX/closed.json" ;;
  */comments\\?*) n="\${p%/comments*}"; n="\${n##*/}"; f="$FIX/comments-$n.json" ;;
  */issues/*) f="$FIX/issue-\${p##*/}.json" ;;
  *) echo "gh stub: unknown path $p" >&2; exit 1 ;;
esac
[ -f "$f" ] || f="$FIX/empty.json"
jq -r "$jqf" "$f"
`;
const SLEEP_STUB = `#!/usr/bin/env bash
echo "$1" >> "$FIX/sleep.log"
`;

let cid = 1000;
const issue = (number, title, { state = 'open', labels = [], body = 'hi', createdAgo = 7200, user = 'alice' } = {}) => ({
  number, title, state, body, user: { login: user },
  labels: labels.map((name) => ({ name })), created_at: iso(createdAgo), updated_at: iso(60),
});
const comment = (login, body, ago) => ({ id: ++cid, body, user: { login }, created_at: iso(ago) });

function setup({ open = [], closed = [], comments = {}, seen = null }) {
  const fix = mkdtempSync(path.join(tmpdir(), 'chat-poll-'));
  const bin = path.join(fix, 'bin');
  mkdirSync(bin);
  writeFileSync(path.join(bin, 'gh'), GH_STUB); chmodSync(path.join(bin, 'gh'), 0o755);
  writeFileSync(path.join(bin, 'sleep'), SLEEP_STUB); chmodSync(path.join(bin, 'sleep'), 0o755);
  writeFileSync(path.join(fix, 'open.json'), JSON.stringify(open));
  writeFileSync(path.join(fix, 'closed.json'), JSON.stringify(closed));
  writeFileSync(path.join(fix, 'empty.json'), '[]');
  for (const i of [...open, ...closed]) writeFileSync(path.join(fix, `issue-${i.number}.json`), JSON.stringify(i));
  for (const [n, cs] of Object.entries(comments)) writeFileSync(path.join(fix, `comments-${n}.json`), JSON.stringify(cs));
  const state = path.join(fix, 'state');
  if (seen) { mkdirSync(state); writeFileSync(path.join(state, 'seen.txt'), seen.join('\n') + '\n'); }
  return { fix, bin, state };
}

function run(ctx, env = {}) {
  const res = spawnSync('bash', [SCRIPT], {
    encoding: 'utf8', timeout: 15000,
    env: {
      ...process.env, PATH: `${ctx.bin}:${process.env.PATH}`, FIX: ctx.fix, CHAT_REPO: 'o/r',
      CHAT_STATE_DIR: ctx.state, CHAT_MAX_POLLS: '1', CHAT_NOW: String(NOW), ...env,
    },
  });
  const events = (res.stdout || '').split('\n').filter((l) => l.startsWith('CHAT_EVENT'));
  return { res, events };
}
const has = (events, re) => events.some((e) => re.test(e));

test('closed issue with an unanswered human comment emits CHAT_EVENT (#72/#54 regression)', () => {
  const ctx = setup({
    closed: [issue(72, 'Fix the demo', { state: 'closed' }), issue(54, 'Rehearsal notes', { state: 'closed' }),
      issue(55, 'Answered', { state: 'closed' }), issue(56, 'Closed silently', { state: 'closed' })],
    comments: {
      72: [comment('orch', `done ${MARK}`, 3000), comment('shruti', 'still broken on main', 600)],
      54: [comment('moalborati', 'many issues without responses/updates since the refresh', 300)],
      55: [comment('shruti', 'q?', 900), comment('orch', `answer ${MARK}`, 800)],
    },
  });
  const { res, events } = run(ctx);
  assert.equal(res.status, 0, res.stderr);
  assert.ok(has(events, /prio=normal issue=#72 from=shruti /), events.join('\n'));
  assert.ok(has(events, /issue=#54 from=moalborati /), events.join('\n'));
  assert.ok(!has(events, /issue=#55 /), 'last comment carries the marker: answered');
  assert.ok(!has(events, /issue=#56 /), 'closed with no comments: nothing to answer');
  const calls = readFileSync(path.join(ctx.fix, 'calls.log'), 'utf8');
  const since = calls.match(/state=closed&since=([0-9TZ:-]+)/);
  assert.ok(since, `closed issues must be listed with a since= window:\n${calls}`);
  assert.equal(Date.parse(since[1]) / 1000, NOW - 6 * 3600, 'window is the last 6h');
});

test('a comment from an agent without the marker still counts as unanswered', () => {
  const ctx = setup({
    open: [issue(80, 'q')],
    comments: { 80: [comment('orch', `ack ${MARK}`, 900), comment('orch', 'oops, no marker', 100)] },
  });
  const { events } = run(ctx);
  assert.ok(has(events, /issue=#80 from=orch /), events.join('\n'));
});

test('startup re-emits unanswered items even if a previous run marked them seen', () => {
  const comments = { 61: [comment('alice', 'ping', 120)] };
  const ctx = setup({ open: [issue(61, 'Open question')], comments, seen: [`61:${cid}`] });
  const { events } = run(ctx);
  assert.ok(has(events, /issue=#61 from=alice key=61:\d+ /), `stale seen.txt must not hide it:\n${events.join('\n')}`);
});

test('within one run an unanswered item is emitted once, not every poll', () => {
  const ctx = setup({ open: [issue(62, 'q')], comments: { 62: [comment('alice', 'x', 120)] } });
  const { events } = run(ctx, { CHAT_MAX_POLLS: '3' });
  assert.equal(events.filter((e) => /issue=#62 /.test(e)).length, 1, events.join('\n'));
});

test('STALE: needs-human / deadline issues with no orchestrator reply for >=30 min', () => {
  const ctx = setup({
    open: [
      issue(90, 'Pick the demo video', { labels: ['needs-human'] }),          // last reply 45 min ago
      issue(91, 'Slides final - deadline 15:00', { createdAgo: 2400 }),       // no reply, opened 40 min ago
      issue(92, 'Approve merge', { labels: ['needs-human'] }),                // reply 10 min ago
      issue(93, 'Plain question', { createdAgo: 7200 }),                      // neither label nor deadline
      issue(94, 'Submit form by 15:30', { createdAgo: 600 }),                 // deadline, opened 10 min ago
    ],
    comments: {
      90: [comment('orch', `asked ${MARK}`, 2700)],
      92: [comment('orch', `asked ${MARK}`, 600)],
      93: [comment('orch', `answer ${MARK}`, 7000)],
    },
  });
  const { events } = run(ctx);
  assert.ok(has(events, /^CHAT_EVENT prio=STALE issue=#90 /), events.join('\n'));
  assert.ok(has(events, /^CHAT_EVENT prio=STALE issue=#91 .* title=Slides final - deadline 15:00$/), events.join('\n'));
  assert.ok(!has(events, /prio=STALE issue=#92 /), 'replied 10 min ago: not stale');
  assert.ok(!has(events, /prio=STALE issue=#93 /), 'no needs-human label, no deadline: never stale');
  assert.ok(!has(events, /prio=STALE issue=#94 /), 'opened 10 min ago: not stale yet');
});

test('STALE is emitted at most once per issue per 30 min', () => {
  const ctx = setup({ open: [issue(90, 'x', { labels: ['needs-human'] })], comments: { 90: [comment('orch', MARK, 2700)] } });
  // 4 polls, clock advancing 10 min per poll: t=0 (emit), 10, 20 (suppressed), 30 min (emit again).
  const { events } = run(ctx, { CHAT_MAX_POLLS: '4', CHAT_NOW_STEP: '600' });
  assert.equal(events.filter((e) => /prio=STALE issue=#90 /.test(e)).length, 2, events.join('\n'));
});

test('poll interval is at least 30s', () => {
  const ctx = setup({ open: [] });
  run(ctx, { CHAT_MAX_POLLS: '2', CHAT_INTERVAL: '5' });
  const sleeps = readFileSync(path.join(ctx.fix, 'sleep.log'), 'utf8').trim().split('\n');
  assert.deepEqual(sleeps, ['30']);
});

test('data-rich: 250 open + 120 closed issues, every unanswered one beyond position 200 is emitted', () => {
  const open = []; const closed = []; const comments = {};
  for (let n = 1; n <= 250; n++) {
    open.push(issue(n, `open ${n}`));
    comments[n] = n % 2 ? [comment('human', 'q', 300)] : [comment('human', 'q', 400), comment('orch', MARK, 300)];
  }
  for (let n = 1001; n <= 1120; n++) {
    closed.push(issue(n, `closed ${n}`, { state: 'closed' }));
    comments[n] = [comment('human', 'reopen?', 200)];
  }
  const ctx = setup({ open, closed, comments });
  const { res, events } = run(ctx);
  assert.equal(res.status, 0, res.stderr);
  const nums = new Set(events.map((e) => Number(e.match(/issue=#(\d+)/)[1])));
  assert.equal(events.length, 125 + 120, `expected 245 events, got ${events.length}`);
  for (const n of [1, 199, 201, 249, 1001, 1120]) assert.ok(nums.has(n), `missing #${n}`);
  for (const n of [2, 200, 250]) assert.ok(!nums.has(n), `#${n} is answered`);
  assert.ok(existsSync(path.join(ctx.state, 'seen.txt')));
});
