# EVAL — evaluate SentinelProxy locally with one command

For teammates and judges. Everything runs on your machine against DVAA, the organizers'
intentionally vulnerable training sandbox, published on `127.0.0.1` only. No API keys are needed and no
LLM is called.

```bash
git clone https://github.com/shrutidoshi94/AIC-X-Crowdstrike-Hackathon-Track-3.git && cd AIC-X-Crowdstrike-Hackathon-Track-3
scripts/eval.sh all
```

`all` runs `doctor → up → test → score → contrast → dashboard` and ends with a summary table. Each step
also runs on its own (`scripts/eval.sh <step>`). Before merging a PR, run `scripts/eval.sh gate <PR#>`
(see the merge gate section below).

## Merge gate (required before ANY merge)

```bash
scripts/eval.sh gate <PR#>
```

**Run this before merging any PR, and do not merge on a non-zero exit.** Two PRs can each be green on
their own and still break each other's tests once both land on `main`. That happened with #15 and #16. The gate:

1. fetches `origin/main` and `pull/<PR#>/head`;
2. merges the PR into the current `origin/main` in a throwaway worktree under `.eval/gate-worktrees/`.
   A merge conflict is a `GATE FAIL`;
3. runs `test` on that merged tree. Every directory under `sentinel/` and `captures/` that contains a
   `*.test.js` or `*.test.mjs` file is a suite, **found by glob**, so a new suite is gated without editing
   the script. The exact files are run with `node --test` (keeping any `--test-*` flags from the package's
   own test script), so no file can fall outside a `package.json` glob;
4. prints `GATE PASS` (exit 0) or `GATE FAIL ... Do not merge.` (exit 1), and keeps logs in `.eval/gate-pr<N>/`.

Any failing test, a suite that runs zero tests, or a suite that hits `EVAL_SUITE_TIMEOUT` fails the gate.
Merge `main` into the PR again and re-run the gate if `main` moved after you ran it. `EVAL_KEEP=1` keeps
the merge worktree for debugging. Also run `scripts/eval.sh up` first so the live-DVAA seams run
instead of skipping.

## Requirements

| Need | Why | Check |
|---|---|---|
| Linux, macOS or WSL2 with bash | the scripts | — |
| Node ≥ 22 (24 preferred) | every suite is plain `node --test` with zero npm dependencies | `eval.sh` uses `node` on PATH if it is ≥ 24, otherwise the newest nvm install ≥ 24, otherwise any Node ≥ 22 (with a WARN) |
| Docker with the compose v2 plugin | runs the DVAA fleet (DVAA itself needs Node 24, and the image pins it) | `docker info` |
| git, curl, python3, timeout | cloning DVAA, health checks, table output | `doctor` |
| Network access on first run | clones DVAA at the pinned commit `5791826` (v0.9.3) into `.dvaa/`, builds the image | later runs work offline |

## What each step shows

| Step | What it does | Expected output |
|---|---|---|
| `doctor` | Checks the tools above and the pinned DVAA checkout (through `scripts/setup-dvaa.sh clone`), and reports whether the fleet is up. Every FAIL prints a `fix:` line. | One `PASS` line per check. `WARN DVAA fleet ... not running` before the first `up` is normal. |
| `up` | Starts DVAA as docker project `dvaa-t1` through `scripts/setup-dvaa.sh up`. A fleet that is already healthy is left as is. It then health-checks all 22 ports and **fails if any port is published beyond 127.0.0.1**. | `PASS all 22 DVAA ports answer 200`, `PASS every published port is bound to 127.0.0.1`, and the pinned commit the fleet was built from. The first build takes a few minutes. |
| `test` | Runs every suite found by glob (any dir under `sentinel/` or `captures/` with `*.test.js`/`*.test.mjs`). Known components are labeled with their ticket: `sentinel/proxy` (T2), `sentinel/detectors` (T3), `sentinel/alerts` (T4), `sentinel/dashboard` (T5), `sentinel/scoring` (T7), `captures/variants` (T6), `captures/contrast` (T8). A known component with no tests on the branch shows NOT YET MERGED, and new suites show `(new)`. Exits 1 on any failure. Real seams are switched on: `DVAA_SRC` points at the pinned checkout with `DVAA_REQUIRE_REAL=1`, and `SENTINEL_REQUIRE_DVAA=1` is set while the fleet is up. | A table `SUITE / TICKET / RESULT / PASS / FAIL / SKIP / TIME / NOTES`, then any explicit `SKIPPED` notices the suites printed, then every failing test by name. Full logs are in `.eval/test/`. |
| `score` | Runs the T7 harness (`sentinel/scoring/cli.mjs`) over the T1 captures and the T6 corpus, and scores each detector against DVAA's `dvaa{}` ground truth. | The markdown results table (precision, recall, **benign FP rate**, TP/FP/TN/FN, median/p95 latency), the "beats DVAA baseline" cases, and per-rule override rates. Written to `.eval/score/`, so the committed `sentinel/scoring/results.json` is not modified. |
| `contrast` | T8: recomputes the recorded vulnerable / AIM-defended / proxied A/B from `captures/contrast/runs` (on a copy in `.eval/contrast/`) and checks every cell against ground truth. `EVAL_LIVE=1` also re-captures it from the live fleet. | The three-column table and `PASS recorded contrast holds`. |
| `dashboard` | Starts the T5 dashboard in the background on `127.0.0.1:9100` (loopback only, DNS-rebinding guarded). If `score` ran, it shows the fresh `.eval/score/results.json`. | `open: http://127.0.0.1:9100/` plus the number of replayable captures. Stop it with `scripts/eval.sh dashboard-stop`. |

**Status words.** `PASS` means the step ran and passed. `FAIL` means it ran and failed, and the script
exits 1. `NOT YET MERGED` means the component's ticket has not landed on this branch yet. It is printed,
never skipped silently, and by default it does not fail the run. Set **`EVAL_STRICT=1`** to make it fail,
which is the setting for judging the final build.

## Knobs

| Variable | Default | Effect |
|---|---|---|
| `EVAL_STRICT` | `0` | `1` makes NOT YET MERGED a failure |
| `EVAL_LIVE` | `0` | `1` makes `contrast` re-capture from the live fleet (needs `up` and `git fetch origin`) |
| `EVAL_SUITE_TIMEOUT` | `600` | Wall-clock cap per suite, in seconds. A suite that hits it is a FAIL ("TIMED OUT"). |
| `EVAL_SCORE_ITERATIONS` | `5` | Latency iterations per case for `score` |
| `EVAL_DASHBOARD_PORT` | `9100` | Dashboard port (always bound to 127.0.0.1) |
| `DVAA_DIR`, `DVAA_PROJECT`, `DVAA_PIN` | `.dvaa/dvaa-target`, `dvaa-t1`, pinned | Passed through to `scripts/setup-dvaa.sh` |

`scripts/eval.sh down` stops the fleet. Don't run it on a shared machine while others are using `dvaa-t1`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `FAIL Node >= 22 is required` | `nvm install 24` (or install Node 24) and re-run. If you already have nvm's Node 24, the script finds it. |
| `WARN node v22...` | It works, but `sentinel/alerts` declares `engines >=24`. Run `nvm install 24`. |
| `FAIL docker daemon not reachable` | WSL: Docker Desktop → Settings → Resources → WSL integration on. Plain Linux: `sudo service docker start`, and add yourself to the `docker` group. |
| `FAIL scripts/setup-dvaa.sh clone failed` | Needs github.com on the first run. Read `.eval/setup-dvaa-clone.log`. A checkout with local edits is refused on purpose. Run `git -C .dvaa/dvaa-target status` and reset it. |
| `FAIL unhealthy DVAA ports: ...` | `docker compose -p dvaa-t1 logs --tail 50`. Another process on 7001-7023 or 9000? Check with `ss -ltnp`. Then `scripts/eval.sh down && scripts/eval.sh up`. |
| `FAIL fleet publishes ports beyond loopback` | Something started DVAA with `-p 7005:7005` (0.0.0.0). Stop it and use `scripts/eval.sh up`. |
| `WARN fleet built from '...' not verifiably the pin` | The running fleet came from another checkout. To rebuild from the pin: `scripts/eval.sh down && scripts/eval.sh up`. |
| `FAIL port 9100 is already in use` | `EVAL_DASHBOARD_PORT=9101 scripts/eval.sh dashboard` |
| A suite FAILs | The failing test names are listed under the table. The full output is in `.eval/test/<suite>.log`. |
| `SKIPPED upstream AgentDojo / InjecAgent / deepset` | These are optional: they verify T6's recorded upstream cases against fresh clones. Set `AGENTDOJO_SRC`, `INJECAGENT_SRC` and `DEEPSET_ROWS` (see `captures/variants/README.md`). |
| `score` headline says "awaiting t3" | T3 (`sentinel/detectors`) is not merged, so the table shows only the noop and DVAA-baseline rows. |
