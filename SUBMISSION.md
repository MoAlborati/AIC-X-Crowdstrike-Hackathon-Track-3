# SentinelProxy: an inline detection-and-response guardrail for AI agents

**Pitch:** SentinelProxy catches an indirect prompt injection and blocks the data theft before it happens. It sits in front of a vulnerable agent and at its tool boundary, and it turns each attempt into a Falcon AIDR-shaped alert mapped to MITRE ATLAS and OWASP.

> Channel-agnostic write-up. Each `##` section stands alone, so you can paste it into any form field. The numbers in **Results** come from `sentinel/scoring/results.json` via `node scripts/fill-submission-metrics.mjs`. Nothing in that section is typed by hand.

## Team

- **Mo Alborati** ([@MoAlborati](https://github.com/MoAlborati))
- **Shruti Doshi** ([@shrutidoshi94](https://github.com/shrutidoshi94))
- **Catherine** ([@c-awad](https://github.com/c-awad)), presenter

## Track

CrowdStrike x Santa Clara University, **Track 3: "Secure: Attack & Defend the Agent"**. This is one Track 3 submission.

- **Path B (main entry):** we attack and defend an existing vulnerable agent. SentinelProxy runs against **DVAA** (Damn Vulnerable AI Agent, by OpenA2A), the organizers' intentionally vulnerable sandbox.
<!-- PATH-A:BEGIN -->
- **Path A (add-on):** we build our own agent, attack it, and defend it. **OpsBot** (`track3a/`) is defended by the same unmodified SentinelProxy components.
<!-- PATH-A:END -->

## Problem

> "AI is rewriting the enterprise attack surface at breakneck speed. Each prompt becomes an entry point for the adversary." (George Kurtz, CEO & founder, CrowdStrike)

An AI agent with tools is a **confused deputy** (Hardy, "The Confused Deputy", ACM SIGOPS OSR 22(4):36–38, 1988). It acts with the user's authority, but it follows instructions from any text it reads. In an **indirect prompt injection** (Greshake et al., "Not What You've Signed Up For", AISec '23), the attack arrives inside a tool result or a retrieved document, not from the user, and the agent sends private data to the attacker. This is the "lethal trifecta": private data, untrusted content, external communication (Simon Willison, Jun 2025).

It is a real-world risk. EchoLeak (CVE-2025-32711) was a zero-click prompt injection that leaked data from Microsoft 365 Copilot, rated CVSS 9.3 Critical by Microsoft (June 2025). OWASP lists this class as **LLM01 Prompt Injection** and **LLM02 Sensitive Information Disclosure**. In the OWASP Top 10 for Agentic Applications 2026 it is **ASI01 Agent Goal Hijack** and **ASI02 Tool Misuse**.

DVAA ships its own detector, `detectAttacks()`, but it scans only the first and last 8KB of a payload. An injection placed in the middle of a long tool result gets past it.

*All claims here use the verified wording in [`planning/CITATIONS.md`](planning/CITATIONS.md).*

## What we built

1. **Request-side proxy with T3 detectors** (`sentinel/proxy`, `sentinel/detectors`). This reverse proxy sits in front of the agent's OpenAI-compatible `/v1/chat/completions`. It scans the **full** payload, with no 8KB window, for:
   - honeytokens, including encoded forms;
   - destination provenance: did the user or system turns authorize this destination, or did it appear only in untrusted tool output?
   - taint flow and secret shapes.

   It is bounded and **fails closed**: an error, a timeout, or an oversize payload is blocked and alerted. A malicious request is **blocked before it is forwarded**, so the agent never acts on it.
2. **Egress guard at the tool boundary** (`sentinel/egress`). This forward proxy sits on an internal Docker network whose only exit is the guard. It decides every outbound tool call **before the call leaves**, using honeytoken matching, an exact-host allowlist, and fail-closed handling of oversize or over-encoded payloads. It stops attacks the agent reads inside its own process, which the request-side proxy cannot see.
3. **AIDR-shaped alerts (T4)** (`sentinel/alerts`). Every verdict becomes a Falcon/AIDR-shaped alert. Each alert is mapped to MITRE ATLAS (for example AML.T0051.001 "LLM Prompt Injection: Indirect" and AML.T0086 "Exfiltration via AI Agent Tool Invocation") and to the OWASP LLM and Agentic Top 10 IDs, and secrets are redacted.
4. **Pipeline to dashboard** (`sentinel/pipeline` → `sentinel/dashboard`). Proxy and egress verdicts flow into alerts and then into a loopback-only dashboard (`127.0.0.1:9100`). It shows an alert feed, an incident graph, and deterministic replay of the recorded attacks.
5. **Scoring harness against the DVAA baseline** (`sentinel/scoring`). It scores SentinelProxy and DVAA's own `detectAttacks()` on the same pinned corpus of real DVAA exploit captures, published benchmark attacks, and benign look-alikes. It reports detection, prevention, precision, benign false positives, and latency, and it includes a dedicated set of 8KB-window evasion cases.

<!-- PATH-A:BEGIN -->
**Path A: OpsBot** (`track3a/`). OpsBot is our own OpenAI-compatible support agent built with the lethal trifecta. It has three tools: `read_ticket` (untrusted input), `lookup_customer` (private data, with fake honeytokens) and `http_post` (egress). We attack it with an indirect injection hidden in a ticket and with a direct injection in the user turn. We defend it with three layers: the unmodified SentinelProxy chat proxy, the egress guard, and OpsBot's own user-turn mandate. `node track3a/run-demo.mjs` regenerates the table below in about 2 seconds on `127.0.0.1`:

| Stack | Indirect injection | Direct injection | Benign (2) |
|---|---|---|---|
| Undefended | leaked (3 secrets) | leaked (3 secrets) | OK |
| + chat proxy | leaked | blocked (request) | OK |
| + chat proxy + egress guard | blocked (egress) | blocked (request) | OK |
| Hardened OpsBot only | blocked (mandate) | leaked | OK |
| Hardened + proxy + egress | blocked | blocked | OK |

No single layer stops both attacks. The chat proxy cannot see an injection that arrives in a tool result, and the mandate trusts its principal. Together the layers stop both attacks with zero benign false positives.
<!-- PATH-A:END -->

## How to run

You need Node 22 or newer (24 preferred), Docker with compose v2, git, curl, python3 and `timeout`. No API keys are needed, and no LLM is called. Everything binds to `127.0.0.1`.

```bash
git clone https://github.com/shrutidoshi94/AIC-X-Crowdstrike-Hackathon-Track-3
cd AIC-X-Crowdstrike-Hackathon-Track-3

scripts/eval.sh doctor          # checks prerequisites and the pinned DVAA checkout; every FAIL prints a fix
scripts/eval.sh up              # starts the DVAA fleet (22 agents, loopback only)
scripts/eval.sh all             # doctor, up, test, score, contrast, dashboard, then a summary table

demo/run-demo.sh --auto         # the full demo, replayed deterministically from committed captures
scripts/egress-demo.sh both     # egress guard: RAGBot + RepoBot exfil, first observed, then blocked
```
<!-- PATH-A:BEGIN -->

Path A: `node track3a/run-demo.mjs`, and `node --test track3a/test/*.test.mjs` for its tests.
<!-- PATH-A:END -->

[`EVAL.md`](EVAL.md) is the full guide: what each step prints, the knobs, troubleshooting, and the merge gate. `EVAL_STRICT=1 scripts/eval.sh all` is the setting for judging the final build.

**macOS notes**

- `scripts/eval.sh` uses `mapfile`, which needs bash 4 or newer. macOS ships bash 3.2, so run `brew install bash` and make sure the Homebrew bash is first on `PATH`. The scripts use `#!/usr/bin/env bash`.
- `timeout` is not built into macOS. Run `brew install coreutils`, which installs it as `gtimeout`, and put the coreutils `gnubin` directory on `PATH` so that `timeout` resolves.
- Use Docker Desktop, or Colima, with the compose v2 plugin. The first `up` builds the DVAA image, which takes a few minutes.
- `demo/run-demo.sh --auto --no-dvaa` runs the replay demo without Docker.

## Results

Source: `sentinel/scoring/results.json`. The file was generated <<METRIC:meta.generatedAt>> by the harness at detector commit `<<METRIC:meta.t3Commit>>`, against DVAA pinned at `<<METRIC:meta.dvaaCommit>>`. The corpus has <<METRIC:corpus.total>> cases: <<METRIC:corpus.attack>> attack and <<METRIC:corpus.benign>> benign, with digest `<<METRIC:corpus.digest>>`. To reproduce, run `scripts/eval.sh score`.

| Metric | SentinelProxy (T3, enforce mode) | DVAA baseline (`detectAttacks()`, 8KB head/tail) |
|---|---|---|
| **Detection recall**: any finding fired, alert-only included | <<METRIC:t3.detection.recall>> | <<METRIC:baseline.detection.recall>> |
| **Prevention recall**: stopped before the agent acts | <<METRIC:t3.prevention.recall>> | <<METRIC:baseline.prevention.recall>> (request-side hit) |
| **Precision** (detection) | <<METRIC:t3.detection.precision>> | <<METRIC:baseline.detection.precision>> |
| **Benign false-positive rate** | **<<METRIC:t3.benignFpRate>>** (<<METRIC:t3.fp>> / <<METRIC:corpus.benign>>) | <<METRIC:baseline.benignFpRate>> (<<METRIC:baseline.fp>> / <<METRIC:corpus.benign>>) |
| **Detector latency** per case, median / p95 | <<METRIC:t3.latency.median>> / <<METRIC:t3.latency.p95>> | <<METRIC:baseline.latency.median>> / <<METRIC:baseline.latency.p95>> |
| **8KB evasion**: injection in the middle of a long tool result | **caught <<METRIC:evasion.t3Caught>> of <<METRIC:evasion.eligible>>** | caught <<METRIC:evasion.baselineCaught>> of <<METRIC:evasion.eligible>> |

**Live egress check (T12, `scripts/egress-demo.sh both`).** In observe mode, the RAGBot and RepoBot secrets reach the local attacker canary and are alerted. In block mode the canary receives no hits, and each attempt produces a `deny` / `honeytoken_match` alert. A direct-dial bypass from inside the sandbox also fails. The attacker's canary receipt is the ground truth, not DVAA's self-report.

**Honest framing.** We optimized for **zero false alarms and fail-closed prevention**, not for raw recall. SentinelProxy's detection recall is <<METRIC:cmp.detection>> the baseline's and its prevention recall is <<METRIC:cmp.prevention>> the baseline's. The baseline gets its recall with <<METRIC:baseline.fp>> benign false positives, while SentinelProxy has <<METRIC:t3.fp>>. In a SOC, a guardrail that blocks legitimate work gets switched off. Detection and prevention are reported separately on purpose. DVAA runs its tools in-process, so a finding on the response side fires only after the tool has run. Those findings count as detections (alert and evidence), but never as preventions. Our "prevention" number counts only what is stopped before forwarding or at egress. The positives include injection-only cases that never attempt exfiltration, and our deterministic rules often flag those without blocking them. The baseline misses the 8KB evasion cases by construction. They are a small set, and we present them as a demonstrated structural gap, not as a headline percentage. The latency figure is detector time per case in-process, not end-to-end proxy latency.

## Limitations

- **Response-side checks are alert-only on DVAA.** Its agents run tools in-process, so prevention happens at only two points: before the request is forwarded, and at the egress guard.
- **The egress guard does not intercept HTTPS.** It decides CONNECT by host only. It does not link egress events to chat turns, and loopback SSRF inside the container never reaches it.
- **There are known redaction gaps in T4 alert text.** These include a card number that follows a short digit group, and double %-encoded or `\u`-escaped canaries. The egress guard decodes these forms for its *blocking* decision, but alert redaction does not.
- **Detection is deterministic,** built from honeytokens, taint, provenance and pattern rules, with no ML classifier. Injections that never try to exfiltrate are often detected without being blocked.
- **Corpus scope:** a single pinned DVAA version, published benchmark strings and our own benign set. The evasion set is small.
<!-- PATH-A:BEGIN -->
- **OpsBot (Path A)** uses a deterministic regex planner instead of a real LLM, which keeps replays exact. Its egress guard scans full bodies only for core `http.request`, and `fetch()` traffic tunnels through CONNECT, so only the host is checked.
<!-- PATH-A:END -->

## Provenance and licenses

- Every **attack** string in the corpus is copied verbatim from a published benchmark or from DVAA. Each one is pinned to an upstream commit with its locator and sha256, and `captures/variants/tools/verify-upstream.mjs` re-checks them. The team wrote only the benign material.
- **Sources:**
  - deepset/prompt-injections (Apache-2.0)
  - AgentDojo, Debenedetti et al., NeurIPS 2024 (MIT)
  - InjecAgent, Zhan et al., ACL Findings 2024 (MIT)
  - DVAA v0.9.3 by OpenA2A (Apache-2.0). Copied DVAA code keeps its SPDX header and notice.

  The full table is in [`captures/variants/LICENSES.md`](captures/variants/LICENSES.md).
- Exfiltration destinations are the benchmarks' own static values or a local `127.0.0.1` canary. No real secrets are used, and nothing leaves the machine.
- The repository has no top-level license file yet. Third-party content stays under its upstream license.
- This is an authorized hackathon project, and all of the work is defensive. DVAA is the organizers' training sandbox, run only on localhost.

## Repository

https://github.com/shrutidoshi94/AIC-X-Crowdstrike-Hackathon-Track-3

Start with [`README.md`](README.md), then [`EVAL.md`](EVAL.md) and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Demo video

<<VIDEO_URL>>

## How we built it

An autonomous multi-agent goal loop built SentinelProxy. An orchestrator dispatched implementer, tester and reviewer agents, one branch and PR per ticket, and every merge had to pass SE, tester, reviewer and `scripts/eval.sh gate` checks (see [`LOOP.md`](LOOP.md)).
