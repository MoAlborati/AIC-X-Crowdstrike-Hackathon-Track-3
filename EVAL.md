# EVAL — evaluate Tourniquet locally with one command

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
| Linux, WSL2 or macOS, bash ≥ 3.2 | the scripts (stock macOS `/bin/bash` 3.2 and BSD userland work; no Homebrew bash or coreutils needed) | `doctor` prints OS, arch and bash version |
| Node 24 (`.nvmrc`); 22 works with a WARN | every suite is plain `node --test` with zero npm dependencies. The detectors timing budget is calibrated on 24 and fails on Node 26 (#61) | `eval.sh` uses `node` on PATH if it is major 24, otherwise an nvm v24 or keg-only Homebrew `node@24`, otherwise `node` on PATH ≥ 22. `doctor` WARNs on anything but 24 and prints the `nvm use` / `brew install node@24` fix |
| Docker with the compose v2 plugin: Docker Desktop, or Colima on macOS | runs the DVAA fleet (DVAA itself needs Node 24, and the image pins it) | `doctor` (also detects Docker Desktop vs Colima on macOS, and the image architecture) |
| git, curl, python3, jq | cloning DVAA, health checks, table output, the demo beats | `doctor` |
| `timeout` (optional) | per-suite cap; falls back to Homebrew `gtimeout`, then a perl or pure-bash shim (`scripts/lib/portable.sh`) | `doctor` |
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

`scripts/eval.sh track3a` runs the Track 3 Path A demo (`node track3a/run-demo.mjs`, PR #62); it prints NOT YET MERGED while `track3a/` is not on the branch, and writes its run outputs to the gitignored `.eval/track3a/` (override `TRACK3A_OUT`; before #113 it rewrote `track3a/runs/`). It needs Node >= 24 (`nvm use 24`; v24.16.0 on the team box) and exits 2 on Node < 24, so it is not part of `all`. `test` also discovers suites under `track3a/` and `track1/` and reports a missing dir as `not present`.

`scripts/eval.sh down` stops the fleet. Don't run it on a shared machine while others are using `dvaa-t1`.

## SOC handoff

Tourniquet's alerts go to Track 1's SOC Brief, which turns them into a plain-English analyst brief. It runs offline, with no LLM key and no network.

```bash
scripts/soc-handoff.sh            # prints the brief and writes .eval/soc-handoff/brief.md
node --test scripts/test/soc-handoff.test.mjs
```

- **Inputs** are committed stage captures, converted by the real T10 pipeline:
  - the proxy-blocked T3 alert: `captures/contrast/runs/proxy-block.t4-alerts.json`
  - four egress-deny alerts: `sentinel/egress/evidence-block.jsonl`
  - the highest-severity post-execution (report-only) alert: `captures/contrast/runs/proxy-observe.proxy.jsonl`
- **Output** gives, for each alert: the verdict, priority, what happened, the Tourniquet stage, the recommended action, and the MITRE ATLAS/ATT&CK and OWASP LLM/Agentic tags. The expected overall verdict is `ESCALATE · P1` across 6 alerts.
- **Safety:** placeholder sidecars are refused. If the rendered brief contains any known honeytoken value, the script exits 3 and writes nothing. Canaries appear by id only.
- **Known SOC Brief limit:** it uses one wording for every Tourniquet alert ("the proxy stopped the send"). For the report-only alert, the brief adds a handoff note saying the data should be treated as already sent.

## Submission snapshot (#73)

The judged repo is a NEW public repo holding **one commit** with main's exact tree, so this repo's history stays private.

```bash
git checkout --detach origin/main     # clean tree, HEAD == origin/main, or the script refuses
scripts/make-submission-snapshot.sh   # [--skip-tests] [--no-fetch] [--force]
```

1. It checks that the tree is clean and that HEAD == `origin/main` after a fetch.
2. It runs `scripts/eval.sh test` (`--skip-tests` skips this). Run it from a checkout outside `/tmp`, since two isolation tests assert repo-local paths.
3. It writes a parentless commit of `HEAD^{tree}`, "Tourniquet — CrowdStrike Track 3 submission (squashed snapshot of main @ <sha>)", with the Co-Authored-By trailer.
4. It scans that tree, minus gitignored paths, for three things:
   - secrets (`gitleaks` if installed, else a built-in regex set; `SNAPSHOT_NO_GITLEAKS=1` forces the regex set);
   - local home or scratch paths;
   - internal tooling words.

   URLs are not checked for paths or words. Known-inert test data and benchmark strings (honeytokens, AWS's documented example key, fake key shapes in tests, see `captures/variants/LICENSES.md`) are listed in `scripts/submission-scan-allowlist.tsv`. Each entry has a path glob, the exact literal, and a reason. **Any other hit fails the run, and no branch or tag is created.**
5. It creates the local branch `submission-snapshot` and the annotated tag `v1.0-submission`, then re-checks that there is 1 commit and that `git diff main submission-snapshot` is empty.
6. It prints the owner's publish commands. **It never pushes.** The owner pushes `submission-snapshot:main` and the tag to the new repo (`gh repo create <owner>/AIC-X-Crowdstrike-Hackathon-Track-3-submission --public`, then `git push <url> submission-snapshot:main v1.0-submission`). Don't use `gh repo create --source . --push`: it pushes the current branch **with its full history**. Then set SUBMISSION.md's Repository link to `https://github.com/<owner>/AIC-X-Crowdstrike-Hackathon-Track-3-submission`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `FAIL Node >= 22 is required` | `nvm install 24 && nvm use` (or `brew install node@24` on macOS) and re-run. If you already have nvm's Node 24 or Homebrew's `node@24`, the script finds it. |
| `WARN node v22...` / `WARN node v26...` | `.nvmrc` pins 24. Older: `sentinel/alerts` declares `engines >=24`. Newer: the detectors timing test fails on 26 (#61). Run `nvm install 24 && nvm use`, or `brew install node@24` (eval.sh finds the keg itself). |
| `FAIL docker daemon not reachable` | WSL: Docker Desktop → Settings → Resources → WSL integration on. Plain Linux: `sudo service docker start`, and add yourself to the `docker` group. |
| `FAIL scripts/setup-dvaa.sh clone failed` | Needs github.com on the first run. Read `.eval/setup-dvaa-clone.log`. A checkout with local edits is refused on purpose. Run `git -C .dvaa/dvaa-target status` and reset it. |
| `FAIL unhealthy DVAA ports: ...` | `docker compose -p dvaa-t1 logs --tail 50`. Another process on 7001-7023 or 9000? Check with `ss -ltnp` (Linux) or `lsof -nP -iTCP -sTCP:LISTEN` (macOS); `doctor` names the holder when `lsof` exists. Then `scripts/eval.sh down && scripts/eval.sh up`. |
| `FAIL fleet publishes ports beyond loopback` | Something started DVAA with `-p 7005:7005` (0.0.0.0). Stop it and use `scripts/eval.sh up`. |
| `WARN fleet built from '...' not verifiably the pin` | The running fleet came from another checkout. To rebuild from the pin: `scripts/eval.sh down && scripts/eval.sh up`. |
| `FAIL port 9100 is already in use` | `EVAL_DASHBOARD_PORT=9101 scripts/eval.sh dashboard` |
| A suite FAILs | The failing test names are listed under the table. The full output is in `.eval/test/<suite>.log`. |
| `SKIPPED upstream AgentDojo / InjecAgent / deepset` | These are optional: they verify T6's recorded upstream cases against fresh clones. Set `AGENTDOJO_SRC`, `INJECAGENT_SRC` and `DEEPSET_ROWS` (see `captures/variants/README.md`). |
| `score` headline says "awaiting t3" | T3 (`sentinel/detectors`) is not merged, so the table shows only the noop and DVAA-baseline rows. |

## macOS quickstart

Tested against Catherine's Mac QA (#34): macOS 26, Apple Silicon, stock bash 3.2, Homebrew Node, Colima, no
GNU coreutils. The scripts need **no** Homebrew bash or coreutils.

```bash
# 1. Tools (skip what you have). git/python3 come with the Command Line Tools.
xcode-select --install            # only if git/python3 prompt to install
brew install node@24 jq           # node@24 is keg-only; eval.sh finds it, or: export PATH="$(brew --prefix node@24)/bin:$PATH"
# Docker: EITHER Docker Desktop (brew install --cask docker; open -a Docker)
#         OR Colima (brew install colima docker docker-compose; colima start --cpu 4 --memory 6)

# 2. Clone under your home directory (Colima only shares $HOME into its VM)
cd ~ && git clone https://github.com/shrutidoshi94/AIC-X-Crowdstrike-Hackathon.git && cd AIC-X-Crowdstrike-Hackathon

# 3. Check, start, evaluate, demo (on the demo Mac with Colima + Homebrew Node 26, the one install is:
#    brew install node@24 && export PATH=/opt/homebrew/opt/node@24/bin:$PATH)
scripts/eval.sh doctor            # every FAIL/WARN prints the exact macOS fix
scripts/eval.sh up                # first build ~1 min; builds a native arm64 DVAA image
scripts/eval.sh all
demo/run-demo.sh --auto --keep-dvaa
```

What differs on a Mac, and how the scripts handle it:

| Topic | Behavior |
|---|---|
| bash 3.2 | No `mapfile`, associative arrays or `${v,,}`; empty arrays are guarded under `set -u` (#58). |
| No GNU `timeout` | The per-suite cap uses `timeout`, else `gtimeout` (`brew install coreutils`), else a perl shim (perl ships with macOS), else a pure-bash shim. Exit 124 on timeout either way (#59). |
| Node version | `.nvmrc` = 24. `eval.sh` prefers a major-24 Node (PATH, nvm, or `/opt/homebrew/opt/node@24`) over a newer Homebrew `node` (#61). |
| Apple Silicon | DVAA is built locally from the pinned source, natively for arm64: its base image `node:24-alpine` (pinned by digest) is a multi-arch index with `linux/arm64`, and its only native npm dependency (`onnxruntime-node`) ships linux/arm64 binaries. The published `opena2a/dvaa:0.9.2` image is multi-arch as well, but we don't use it (the pin is v0.9.3 source). If a native build ever fails, `DVAA_PLATFORM=linux/amd64 scripts/eval.sh up` builds the amd64 image under emulation (slower). `doctor` WARNs if the built image's arch differs from the engine's. |
| Colima vs Docker Desktop | `doctor` detects which one is running. Colima shares only `$HOME` into its VM, so the repo must live under `~`, and bind mounts from `/tmp` or `$TMPDIR` (`/var/folders/...`) are empty inside containers (#60, egress live tests). Docker Desktop shares `/Users`, `/Volumes`, `/private`, `/tmp` and `/var/folders` by default. |
| Loopback | Every port is published on `127.0.0.1` only; Docker Desktop and Colima both forward that to the Mac's loopback. No `host.docker.internal` or host networking is used. |
| Ports | `doctor` checks that 7001-7023 + 9000 (DVAA), 8080/8005 (proxy configs) and 9100 (dashboard) are free, and names the holder with `lsof`. |
| `sha256sum` | `captures/contrast/run-contrast.sh` falls back to `shasum -a 256`. |
