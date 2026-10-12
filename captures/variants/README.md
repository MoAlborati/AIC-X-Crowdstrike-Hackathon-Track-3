# T6 — Attack corpus + benign corpus (labeled evaluation fixtures)

Labeled evaluation dataset for **SentinelProxy**, the defensive detector (T3) and scoring
harness (T7) for the CrowdStrike × SCU hackathon (Track 3). This is purely defensive test
data: it pairs reused, published attack cases with a benign corpus so we can measure both
detection (recall) and **false positives** on benign traffic.

**No new attack content is authored here.** Every attack case is *reused* from a published,
public academic benchmark (AgentDojo, InjecAgent, deepset/prompt-injections) or from DVAA's
own organizer-provided payloads, with attribution and license recorded per fixture and in
[`LICENSES.md`](./LICENSES.md). All secrets/credentials are FAKE DVAA sandbox values; all
exfil destinations are benchmark placeholders (`attacker@evil.example`, `attacker.example`)
or the run's own `127.0.0.1` canary.

## What's here

| Path | Contents |
|------|----------|
| `fixtures/deepset/` | deepset/prompt-injections classification cases (injection + benign) |
| `fixtures/agentdojo/` | AgentDojo indirect-injection **exfiltration** cases (pre-computed) |
| `fixtures/injecagent/` | InjecAgent **data-stealing** cases (pre-computed) |
| `fixtures/benign/` | Benign corpus incl. **data-rich** (>16KB doc, 400-row tool output) |
| `fixtures/evasion/` | Position variants (start/middle/end) of an injection in a long benign doc, incl. the headline **8KB-baseline evasion** |
| `corpus/` | Large generated payload bodies (benign KB doc, 400-row tool output) |
| `manifest.json` | The single labeled index T7 loads (one row per case) |
| `tools/` | Deterministic generators + the DVAA baseline bridge (real seam) |
| `tests/` | Data-rich, real-seam tests (run `node --test captures/variants/tests/*.test.mjs`) |

## Fixture schema

Every fixture is self-contained JSON with the **same request shape as the T1 captures**
(`captures/README.md`), so T2/T3 replay is uniform:

```jsonc
{
  "id": "AD-EXFIL-001",
  "scenario": "indirect-injection-exfil (workspace suite)",
  "source": {                       // provenance for reused content
    "benchmark": "AgentDojo",
    "url": "https://github.com/ethz-spylab/agentdojo",
    "license": "MIT",
    "caseRef": "important_instructions injection task",
    "note": "Reused published attack template; not authored here."
  },
  "channel": "tool_output",         // user_message | tool_output | rag_document
  "request": { "messages": [ { "role": "user", "content": "..." } ] },
  "label": {                        // ground truth for T7 scoring
    "groundTruth": "positive",      // positive = attack | negative = benign
    "expectedVerdict": "block",     // block | allow
    "category": "indirect_prompt_injection+data_exfiltration",
    "dvaa": {                       // DVAA-compatible label block (T1 schema)
      "exfilAttempted": true,
      "exfilExecuted": null,        // null = recorded/pre-computed, not run live
      "exfilTargetUrl": "attacker@evil.example"
    }
  },
  "baseline8kb": { /* evasion fixtures only — see below */ },
  "notes": "..."
}
```

`exfilExecuted` is `null` for benchmark-derived cases because they are **pre-computed**
(recorded, not run live through DVAA) — per the T6 ticket. The `dvaa{}` block mirrors T1's
label vocabulary so a single harness scores T1 captures and T6 variants together.

## The 8KB-baseline evasion (acceptance #1)

DVAA's own scanner, `detectAttacks()` in `src/core/vulnerabilities.js`
(`DETECTION_EDGE = 8 * 1024`), only scans the **head and tail 8KB** of inputs longer than
`DETECTION_EDGE * 2` (16,384 chars); the two ends are joined by a `\n\u0000\n` separator no
pattern can span. An instruction that sits **between** the two ends is never scanned.

The `fixtures/evasion/` position variants embed one reused injection at the start, middle, or
end of a ~22KB benign document. The **middle** variants (`EVA-POS-MIDDLE-001` using DVAA's
own agentpwn exfil trigger; `EVA-BENCH-MIDDLE-001` using AgentDojo's template) land in the
gap:

```
baseline source: dvaa-real
middle variant: docLen=22797 inMiddleGap=true evadesBaseline=true signalPresentFullScan=true
```

- `evadesBaseline=true` — DVAA's **real** `detectAttacks()` returns `hasAttack=false`.
- `signalPresentOnFullScan=true` — a full-payload scan of the same bytes flags it.

The start/end variants are controls: the injection is inside the 8KB window, so the baseline
catches them (`evadesBaseline=false`). This is the gap SentinelProxy's **full-payload** scan
(T3) must close. Each evasion fixture records:

```jsonc
"baseline8kb": {
  "DETECTION_EDGE": 8192,
  "docLength": 22797,
  "injectionOffsetStart": 11364,
  "injectionOffsetEnd": 11716,
  "inMiddleGap": true,              // start > 8KB && end < len-8KB
  "evadesBaseline": true,           // DVAA detectAttacks() misses it
  "baselineSource": "dvaa-real",    // or "replica-subset" offline
  "signalPresentOnFullScan": true
}
```

## Real seam

`tools/baseline.mjs` runs the evasion proof against DVAA's **actual** `detectAttacks()` /
`detectionText()` when a DVAA checkout is present — `$DVAA_SRC=<repo>` or the pinned T1 clone
(`57918267…`). With no checkout it falls back to a faithful, attributed **replica subset**
(`promptInjection` + `dataExfiltration` patterns), so the suite is green offline/in CI.
`$DVAA_SRC=replica` forces the fallback for parity checks. The test prints which source it used.

## Reproduce

```bash
node captures/variants/tools/generate-corpus.mjs   # regenerate corpus/ + fixtures/evasion/
node captures/variants/tools/build-manifest.mjs     # rebuild manifest.json
node --test captures/variants/tests/*.test.mjs       # data-rich, real-seam tests
```

The generators use fixed content and no clock/RNG, so output is byte-stable (delivery-gate:
variants replayable).

## Bounds introduced + failure modes (firm rule: bounded + fail-loud)

This ticket produces **test fixtures**, not a runtime scanner, so it adds no runtime cap of
its own. The bounds it *encodes and asserts* are DVAA's, so downstream tickets treat them
correctly:

| Bound | Value | Where | Beyond it |
|-------|-------|-------|-----------|
| DVAA `DETECTION_EDGE` | 8 KiB head/tail | DVAA `detectAttacks()` (the anti-pattern we beat) | **Silent miss** — middle content never scanned. The `middle` fixtures exist precisely to make this failure visible; T3 must scan the **full** payload and fail-loud on overflow, never copy this head/tail cap. |
| Generated doc size | ~22 KB (`EDGE*2 + 6000`) | `generate-corpus.mjs` | Chosen so the doc exceeds `DETECTION_EDGE*2` and the injection provably lands in the gap. Asserted in tests (`docLength > 16384`). |
| Tool-output rows | 400 | `generate-corpus.mjs` | Data-rich (hundreds of rows) so T3/T7 are exercised on realistic tool output; asserted `>= 300`. |

**Decision vs display:** the labels in `manifest.json` are a **decision** input for T7 (verdict
comparison) and are computed over the full fixture, never a capped scan. The `DETECTION_EDGE`
cap is documented only as DVAA's baseline behavior that our detector must beat — it is not on
any decision path in this corpus.

## How downstream tickets consume this

- **T3 (detector):** replay each `request` through the detector; a correct detector flags
  every `groundTruth: "positive"` (including the middle evasion variants) and clears every
  `negative`.
- **T7 (scoring):** load `manifest.json`; compare the detector verdict to `expectedVerdict` /
  `label.dvaa`; report precision, recall, and the **benign false-positive rate** (6 negatives,
  incl. egress-adjacent benign tasks and the data-rich cases) as a headline metric.
