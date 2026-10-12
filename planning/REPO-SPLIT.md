# REPO-SPLIT — splitting this repo into Track 1 and Track 3

**Status:** PREP ONLY. Nothing has been split or pushed. Repo/remote creation and visibility are on hold
with Mo (#73). This file is the runbook a human executes **at 15:30 PDT** (Mo, #175: "We will split this
up into 2 different repos at 3:30 PST (track 1 and track 3)").

**What is already done (prepped, in a scratch clone — not pushed anywhere):**
- Track 1 history-preserving split branch (`git subtree split --prefix=track1`) was produced and verified:
  `npm test` → 35/35 pass, `npm run eval` → clean, standalone from the split branch.
- Track 3 "remove `track1/` in one commit" was produced and verified: `scripts/eval.sh doctor` all PASS,
  full history preserved (291 commits), and the full test suite runs. The **only** split-caused failure is
  `scripts/soc-handoff.test.mjs` (see Coupling). Two other failures seen in the scratch run
  (`captures/variants` L1, `sentinel/egress` isolation) are **not** caused by the split — they fail only
  because the scratch clone lives under `/tmp` and those tests assert paths are not under `os.tmpdir()`.
  They were reproduced with `track1/` still present, so they are environmental, not a split regression.

Base for both: current `main` (`origin/main` @ `6f08e7a` at time of writing — use the actual tip of `main` at 15:30).

---

## What goes where

| Content | Track 1 repo | Track 3 repo |
|---|---|---|
| `track1/` subtree (SOC Brief) | **root of the repo** (contents hoisted) | removed |
| `sentinel/`, `scripts/`, `captures/`, `demo/`, `track3a/`, `spike/`, `docs/`, `gates/`, `prompts/`, `planning/`, `handoffs/` | — | kept |
| Root governance (`AGENTS.md`, `LOOP.md`, `STATE.md`, `BACKLOG.md`, `GOAL.md`, `EVAL.md`, `RESUME.md`, `CHAT.md`, `README.md`) | — | kept |
| `SUBMISSION.md` | `track1/SUBMISSION.md` → becomes **root `SUBMISSION.md`** | root `SUBMISSION.md` (Tourniquet) — already Track 3's |
| `.github/` issue+PR templates | — (optional copy) | kept |

Each track already has its own submission:
- **Track 1 repo uses** its own `SUBMISSION.md` — "SOC Brief: Track 1 submission (AI for SOC Analyst)", lead
  @shrutidoshi94. In the subtree split it is already at the repo root (it was `track1/SUBMISSION.md`).
- **Track 3 repo uses** the existing root `SUBMISSION.md` — "Tourniquet: an inline detection-and-response
  guardrail for AI agents". No change.

There is **no root `package.json`**. `track1/package.json` (`track1-soc-brief`, node >=22) is self-contained and
becomes the Track 1 repo's root manifest. Track 3 has no root manifest; its sub-projects
(`track3a/package.json` node >=24) and `scripts/eval.sh` are the entry points, unchanged.

---

## Commands a human runs at 15:30 PDT

Prerequisite (per #73): the two empty GitHub repos exist and their URLs are known. Below they are
`$T1_REMOTE` and `$T3_REMOTE`. Do **not** run this before Mo confirms repo creation/visibility.

```bash
# 0. Set up. Run from a fresh working copy of the current repo on the latest main.
export SRC=/home/gingy/crowdstrike                 # or a fresh clone of the current repo
export T1_REMOTE=git@github.com:<org>/<track1-repo>.git
export T3_REMOTE=git@github.com:<org>/<track3-repo>.git
cd "$SRC"
git fetch origin main
git checkout main && git pull --ff-only

# ---------- TRACK 1 repo (history-preserving subtree split) ----------
git subtree split --prefix=track1 -b split-track1        # track1/ history, hoisted to root
git push "$T1_REMOTE" split-track1:main                  # push the split branch as the new repo's main
# (optional) verify standalone before/after push:
#   git worktree add /tmp/t1verify split-track1 && cd /tmp/t1verify && npm test && npm run eval

# ---------- TRACK 3 repo (everything except track1/, full history) ----------
git checkout main
git checkout -b split-track3
git rm -r track1
git commit -m "Split: track1/ moves to its own Track 1 repo"
# Apply the SOC-handoff decoupling first (see next section) if you want the full suite green, then:
git push "$T3_REMOTE" split-track3:main                  # push as the new repo's main
```

Notes:
- `git subtree split` keeps only the commits that touched `track1/`, rewritten so `track1/` is the root.
  That is the standard history-preserving extract; the resulting `main` is a clean Track 1 history.
- The Track 3 side keeps the **entire** repo history (one extra commit that deletes `track1/`). If a
  history-free `track1/` is wanted instead, that is a larger `git filter-repo` job — not needed here.
- Neither command creates a repo or changes visibility; a human does that in the GitHub UI per #73.

---

## The one real cross-track coupling: SOC handoff

**What couples:** `scripts/lib/soc-handoff.mjs` (invoked by `scripts/soc-handoff.sh`, tested by
`scripts/test/soc-handoff.test.mjs`) imports **Track 1 source directly**:

```js
const { normalize }        = await imp('track1/src/normalize.js');
const { runChain }         = await imp('track1/src/chain.js');
const { dispositionRank }  = await imp('track1/src/signals.js');
```

This lives on the **Track 3** side of the split, so after `track1/` is removed the handoff and its test fail
with `ERR_MODULE_NOT_FOUND: .../track1/src/normalize.js`. This was confirmed in the verification run and the
import is still live on `origin/main` (the merged `fix-soc-handoff` branch did not decouple it).

The handoff runs SOC Brief's **deterministic path only** (normalize + `runChain` with no model), so there are
no network/LLM/key dependencies — only the three source modules and their transitive closure within
`track1/src`. The full closure is **6 files, ~38 KB, zero npm deps**:
`normalize.js`, `chain.js`, `signals.js`, `briefing.js`, `prompts.js`, `labels.js`
(`normalize → labels`; `chain → briefing, prompts`; `briefing → labels, signals`; `prompts`/`signals`/`labels`
are leaves; `llm.js` is **not** reached because no model is used).

### How to preserve or stub the cross-track link after the split

**The SOC handoff is not in the T3 frozen minimum** (honeytoken tripwire, destination provenance, full-payload
fail-closed request-side scan, T4 verdicts). It is a demo nicety, so pick by time budget:

- **Option A — vendor (recommended; keeps Track 3 self-contained and the test green).**
  Copy the 6 modules into the Track 3 repo (e.g. `scripts/lib/vendor/soc-brief/`) and repoint the three
  imports in `scripts/lib/soc-handoff.mjs` from `track1/src/...` to `./vendor/soc-brief/...`. No npm deps to
  carry. Add a one-line provenance note in the vendor dir pointing at the Track 1 repo. Trade-off: a copy that
  can drift from Track 1 — acceptable for a frozen hackathon deliverable. Re-run `node --test
  scripts/test/soc-handoff.test.mjs` to confirm green.

- **Option B — git submodule.** Add the new Track 1 repo as a submodule at e.g. `vendor/track1` and repoint
  imports to `vendor/track1/src/...`. Single source of truth, but needs the Track 1 repo to exist/push first
  and adds submodule clone/update steps for anyone running the handoff. Heavier than this demo warrants.

- **Option C — stub + skip (zero-risk, fastest).** Make `scripts/soc-handoff.sh` / `soc-handoff.mjs` fail-loud
  with a clear message ("SOC handoff requires the Track 1 repo; set `TRACK1_SRC=<path>`") and guard
  `scripts/test/soc-handoff.test.mjs` to SKIP when Track 1 source is absent. Keeps the handoff documented as a
  cross-repo demo without carrying code. Use this if there is no time for A before the push.

If none of A/B/C is applied before pushing Track 3, the suite ships with one known failure
(`scripts/soc-handoff.test.mjs`) — record it under "Known limitations" per the endgame max-2-fix-rounds rule.

---

## Other coupling — all cosmetic / graceful (no action required to split)

- **`scripts/eval.sh`** lists `track1` in `SUITE_ROOTS` and `KNOWN_SUITES` (`"track1|track1"`). Discovery is
  by glob and already handles absence: with `track1/` gone it prints `WARN track1/ not present` and a
  `NOT YET MERGED` row, then continues. **Verified** on the Track 3 split: doctor + all other suites still
  run. Optional cleanup: drop the two `track1` entries so the WARN/row disappears — not required.
- **`EVAL.md`** (§ test discovery) mentions `track1/` as a discovered suite — doc text only.
- **`README.md` (root)** does not functionally link to `track1/`; only a Track-3 hackathon line. No change.
- **`.github/`** has issue/PR templates only — **no GitHub Actions workflows**, so there is no CI to break on
  either side.
- **`STATE.md`, `BACKLOG.md`, `planning/PROACTIVE.md`, `prompts/archetypes/advisor.md`** reference `track1/` as
  a separate track — narrative only; they stay in the Track 3 repo and need no code change.
- **Track 1 internal paths** (`track1/eval-heldout/*`, `track1/scripts/*`, `ATTRIBUTION.md`) reference
  `track1/...` prefixes. After the subtree split these become repo-root-relative; the READMEs still say
  `track1/...`. Cosmetic only — tests and `npm run eval` pass without edits (they resolve relative to the
  module). Optional: tidy the `track1/` prefixes in the Track 1 README after the split.
- **`.gitignore`**: `track1/.gitignore` (data/, *.zip) becomes the Track 1 repo's root `.gitignore` via the
  subtree split. The root `.gitignore` stays with Track 3. No conflict.

---

## Verification evidence (from the prepped scratch clones)

- **Track 1** (`split-track1`, hoisted to root): `npm test` → `# pass 35 # fail 0`; `npm run eval` →
  `activity 17/17`, full disposition table printed. Standalone, no Track 3 files.
- **Track 3** (`track1/` removed, full history): `scripts/eval.sh doctor` → all PASS (node 24, docker, pinned
  DVAA). `scripts/eval.sh test` → every suite PASS except `scripts/soc-handoff.test.mjs`
  (`ERR_MODULE_NOT_FOUND track1/src/normalize.js` — the coupling above). The `captures/variants` L1 and
  `sentinel/egress` isolation failures are `/tmp`-path artifacts of the scratch location and reproduce with
  `track1/` present, so they are not split regressions.
