# SentinelProxy: an inline detection-and-response guardrail for AI agents

**Pitch:** SentinelProxy catches prompt-injection-driven data exfiltration and tool misuse, and is designed to block them before forwarding or at egress; it prevents 57 of 71 exfil attempts in our corpus (79 of 189 attacks overall, 128 detected). It sits in front of a vulnerable agent and at its tool boundary, and it turns each attempt into a Falcon AIDR-shaped alert mapped to MITRE ATLAS and OWASP.

> Channel-agnostic write-up. Each `##` section stands alone, so you can paste it into any form field. The numbers in **Results** come from `sentinel/scoring/results.json` via `node scripts/fill-submission-metrics.mjs`. Nothing in that section is typed by hand.

**Scope.** SentinelProxy is designed to stop prompt-injection-driven *exfiltration and tool misuse*; it prevents 57 of 71 exfil attempts in our corpus. Generic jailbreak text with no action is out of scope for blocking (alerted at most); pair it with a jailbreak classifier such as Prompt Guard.

## Team

- **Mo Alborati** ([@MoAlborati](https://github.com/MoAlborati))
- **Shruti Doshi** ([@shrutidoshi94](https://github.com/shrutidoshi94))
- **Catherine** ([@c-awad](https://github.com/c-awad)), presenter

## Track

CrowdStrike x Santa Clara University, **Track 3: "Secure: Attack & Defend the Agent"**. This is one Track 3 submission.

- **Path B (main entry):** we attack and defend an existing vulnerable agent. SentinelProxy runs against **DVAA** (Damn Vulnerable AI Agent, by OpenA2A), the organizers' intentionally vulnerable sandbox.
- **Path A (add-on):** we build our own agent, attack it, and defend it. **OpsBot** (`track3a/`) is defended by the same unmodified SentinelProxy components.

## Problem

> "AI is rewriting the enterprise attack surface at breakneck speed. Each prompt becomes an entry point for the adversary." (George Kurtz, CEO & founder, CrowdStrike)

An AI agent with tools is a **confused deputy** (Hardy, "The Confused Deputy", ACM SIGOPS OSR 22(4):36–38, 1988). It acts with the user's authority, but it follows instructions from any text it reads. In an **indirect prompt injection** (Greshake et al., "Not What You've Signed Up For", AISec '23), the attack arrives inside a tool result or a retrieved document, not from the user, and the agent sends private data to the attacker. This is the "lethal trifecta": private data, untrusted content, external communication (Simon Willison, Jun 2025).

It is a real-world risk. EchoLeak (CVE-2025-32711) was a zero-click prompt injection that leaks data from Microsoft 365 Copilot (no known in-the-wild exploitation), rated CVSS 9.3 Critical by Microsoft (June 2025). OWASP lists this class as **LLM01 Prompt Injection** and **LLM02 Sensitive Information Disclosure**. In the OWASP Top 10 for Agentic Applications 2026 it is **ASI01 Agent Goal Hijack** and **ASI02 Tool Misuse**.

DVAA ships its own detector, `detectAttacks()`, but it scans only the first and last 8KB of a payload. An injection placed in the middle of a long tool result gets past it.

*All claims here use the verified wording in [`planning/CITATIONS.md`](planning/CITATIONS.md).*

## What we built

1. **Request-side proxy with T3 detectors** (`sentinel/proxy`, `sentinel/detectors`). This reverse proxy sits in front of the agent's OpenAI-compatible `/v1/chat/completions`. It scans the **full** payload, with no 8KB window, for:
   - honeytokens, including encoded forms;
   - destination provenance: did the user or system turns authorize this destination, or did it appear only in untrusted tool output?
   - taint flow and secret shapes.

   It is bounded and **fails closed**: in block mode, an error, a timeout, or an oversize payload is blocked and alerted (observe mode forwards with an alert). A malicious request is **blocked before it is forwarded**, so the agent never acts on it.
2. **Egress guard at the tool boundary** (`sentinel/egress`). This forward proxy sits on an internal Docker network whose only exit is the guard. It decides every outbound tool call **before the call leaves**, using honeytoken matching, an exact-host allowlist, and fail-closed handling of oversize or over-encoded payloads. It stops attacks the agent reads inside its own process, which the request-side proxy cannot see.
3. **AIDR-shaped alerts (T4)** (`sentinel/alerts`). Every verdict becomes a Falcon/AIDR-shaped alert. Each alert is mapped to MITRE ATLAS (for example AML.T0051.001 "LLM Prompt Injection: Indirect" and AML.T0086 "Exfiltration via AI Agent Tool Invocation") and to the OWASP LLM and Agentic Top 10 IDs, and secrets are redacted.
4. **Pipeline to dashboard** (`sentinel/pipeline` → `sentinel/dashboard`). Proxy and egress verdicts flow into alerts and then into a loopback-only dashboard (`127.0.0.1:9100`). It shows an alert feed, an incident graph, and deterministic replay of the recorded attacks.
5. **Scoring harness against the DVAA baseline** (`sentinel/scoring`). It scores SentinelProxy and DVAA's own `detectAttacks()` on the same pinned corpus of real DVAA exploit captures, published benchmark attacks, and benign look-alikes. It reports detection, prevention, precision, benign false positives, and latency, and it includes a dedicated set of 8KB-window evasion cases.

**Path A: OpsBot** (`track3a/`). OpsBot is our own OpenAI-compatible support agent built with the lethal trifecta. It has three tools: `read_ticket` (untrusted input), `lookup_customer` (private data, with fake honeytokens) and `http_post` (egress). We attack it with an indirect injection hidden in a ticket and with a direct injection in the user turn. We defend it with three layers: the unmodified SentinelProxy chat proxy, the egress guard, and OpsBot's own user-turn mandate. `node track3a/run-demo.mjs` (Node ≥ 24) runs the demo in about 2 seconds on `127.0.0.1` and writes its output to the gitignored `.eval/track3a/`. `node track3a/run-demo.mjs --write-results` also regenerates the committed table below:

| Stack | Indirect injection | Direct injection | Benign (2) |
|---|---|---|---|
| Undefended | leaked (3 secrets) | leaked (3 secrets) | OK |
| + chat proxy | leaked | blocked (request) | OK |
| + chat proxy + egress guard | blocked (egress) | blocked (request) | OK |
| Hardened OpsBot only | blocked (mandate) | leaked | OK |
| Hardened + proxy + egress | blocked | blocked | OK |

No single layer stops both attacks. The chat proxy cannot see an injection that arrives in a tool result, and the mandate trusts its principal. Together the layers stop both attacks, with 0/2 benign false positives.

## How to run

You need Node 22 or newer (24 preferred; Path A, `track3a/`, needs Node 24 or newer and exits 2 on older Node), Docker with compose v2, git, curl, python3 and `timeout`. No API keys are needed, and no LLM is called. Everything binds to `127.0.0.1`.

```bash
git clone https://github.com/shrutidoshi94/AIC-X-Crowdstrike-Hackathon-Track-3
cd AIC-X-Crowdstrike-Hackathon-Track-3

scripts/eval.sh doctor          # checks prerequisites and the pinned DVAA checkout; every FAIL prints a fix
scripts/eval.sh up              # starts the DVAA fleet (21 agents + the :9000 dashboard, 22 ports, loopback only)
scripts/eval.sh all             # doctor, up, test, score, contrast, dashboard, then a summary table

demo/run-demo.sh --auto         # the full demo, replayed deterministically from committed captures
scripts/egress-demo.sh both     # egress guard: RAGBot + RepoBot exfil, first observed, then blocked
```

Path A: `node track3a/run-demo.mjs`, and `node --test track3a/test/*.test.mjs` for its tests.

[`EVAL.md`](EVAL.md) is the full guide: what each step prints, the knobs, troubleshooting, and the merge gate. `EVAL_STRICT=1 scripts/eval.sh all` is the setting for judging the final build.

**macOS notes**

- `scripts/eval.sh` uses `mapfile`, which needs bash 4 or newer. macOS ships bash 3.2, so run `brew install bash` and make sure the Homebrew bash is first on `PATH`. The scripts use `#!/usr/bin/env bash`.
- `timeout` is not built into macOS. Run `brew install coreutils`, which installs it as `gtimeout`, and put the coreutils `gnubin` directory on `PATH` so that `timeout` resolves.
- Use Docker Desktop, or Colima, with the compose v2 plugin. The first `up` builds the DVAA image, which takes a few minutes.
- `demo/run-demo.sh --auto --no-dvaa` runs the replay demo without Docker.

## Results

Source: `sentinel/scoring/results.json`. The file was generated 2026-10-12T20:10:38Z by the harness at detector commit `2976fed`, against DVAA pinned at `5791826`. The corpus has 353 cases: 189 attack and 164 benign, with digest `sha256:0506bc620c84…`. To reproduce, run `scripts/eval.sh score`.

| Metric | SentinelProxy (T3, enforce mode) | DVAA baseline (`detectAttacks()`, 8KB head/tail) |
|---|---|---|
| **Detection recall**: any finding fired, alert-only included | 67.7% | 65.6% |
| **Prevention recall**: stopped before the agent acts | 41.8% | 63.0% (request-side hit) |
| **Precision** (detection) | 100.0% | 85.5% |
| **Benign false-positive rate** | **0.0%** (0 / 164) | 12.8% (21 / 164) |
| **Detector latency** per case, median / p95 | 0.082 ms / 0.416 ms | 0.014 ms / 0.264 ms |
| **8KB evasion**: injection in the middle of a long tool result | **caught 2 of 2** | caught 0 of 2 |

**Live egress check (T12, `scripts/egress-demo.sh both`).** In observe mode, the RAGBot and RepoBot secrets reach the local attacker canary and are alerted. In block mode the canary receives no hits, and each attempt produces a `deny` / `honeytoken_match` alert. A direct-dial bypass from inside the sandbox also fails. The attacker's canary receipt is the ground truth, not DVAA's self-report.

**Honest framing.** We optimized for **no blocks or alerts on the 164-case benign corpus and fail-closed prevention**, not for raw recall. SentinelProxy's detection recall is above the baseline's, but the baseline has the higher prevention recall, at a 12.8% benign FP rate. The only structural win we claim outright is catching 2 of 2 cases that evade the baseline's 8KB window. SentinelProxy's detection recall is above the baseline's and its prevention recall is below the baseline's. The baseline gets its recall with 21 benign false positives, while SentinelProxy has 0, both on the 164-case benign corpus. Held-out benign: 1/32 blocked (a security-awareness memo quoting an injection phrase; same as before #46), and 4/32 raise an alert without a block. Held-out attacks: 14 of 16 hand-written paraphrases detected, but on an independent reviewer's 6 further paraphrases, 1 detected, so recall on novel phrasings is limited — see PR #46. In a SOC, a guardrail that blocks legitimate work gets switched off. Detection and prevention are reported separately on purpose. DVAA runs its tools in-process, so a finding on the response side fires only after the tool has run. Those findings count as detections (alert and evidence), but never as preventions. Our "prevention" number is detector-only: it counts what is stopped before forwarding (or a withheld reply); the egress guard is not in the scoring harness and is shown separately by the live egress check. The positives include injection-only cases that never attempt exfiltration, and our deterministic rules often flag those without blocking them. The baseline misses the 8KB evasion cases by construction. They are a small set, and we present them as a demonstrated structural gap, not as a headline percentage. The latency figure is detector time per case in-process, not end-to-end proxy latency.

## Limitations

- **Generic jailbreaks are out of scope for blocking.** On a held-out set of 600 attack and 400 benign cases from 3 public Hugging Face sets of generic jailbreaks and injections, none carrying an exfil destination, T3 detected 28.5% and prevented 0%, with 0/400 false positives (detection by set: Gandalf 58%, SPML 19%, jailbreak-classification about 8%); DVAA detected and prevented 60.7%, with 22/400 (5.5%) false positives. Held-out; see [`captures/holdout-hf/RESULTS.md`](captures/holdout-hf/RESULTS.md).
- **Response-side checks are alert-only for prevention on DVAA.** Its agents run tools in-process, so a response-side finding fires after the tool ran; in block mode it withholds the reply. Prevention happens at only two points: before the request is forwarded, and at the egress guard.
- **The egress guard does not intercept HTTPS.** It decides CONNECT by host only. It links egress events to chat turns by best-effort time-window attribution only, reporting them standalone when the match is ambiguous, and loopback SSRF inside the container never reaches it.
- **There are known redaction gaps in T4 alert text.** These include a card number that follows a short digit group, and double %-encoded or `\u`-escaped canaries. The egress guard decodes these forms for its *blocking* decision, but alert redaction does not.
- **Detection is deterministic,** built from honeytokens, taint, provenance and pattern rules, with no ML classifier. Injections that never try to exfiltrate are often detected without being blocked.
- **Corpus scope:** a single pinned DVAA version, published benchmark strings and our own benign set. The evasion set is small.
- **OpsBot (Path A)** uses a deterministic regex planner instead of a real LLM, which keeps replays exact. Its egress guard scans full bodies only for core `http.request`, and `fetch()` traffic tunnels through CONNECT, so only the host is checked.

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

Video: available on request / shown live

## How we built it

An autonomous multi-agent goal loop built SentinelProxy. An orchestrator dispatched implementer, tester and reviewer agents, one branch and PR per ticket, and every merge had to pass SE, tester, reviewer and `scripts/eval.sh gate` checks (see [`LOOP.md`](LOOP.md)).
