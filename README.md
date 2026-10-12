# AIC X Crowdstrike Hackathon

> **SentinelProxy** — this repo's Track 3 project. (Repo title preserved from `main`.)

**SentinelProxy** is an inline, tool-boundary **detection-and-response guardrail** for AI agents — a
working slice of CrowdStrike Falcon AIDR. It sits as a reverse proxy in front of an agent's
OpenAI-compatible `/v1/chat/completions`, turns an indirect prompt injection into a Falcon/AIDR-shaped
alert (mapped to MITRE ATLAS + OWASP), and detects + **blocks** data exfiltration the instant the agent
tries it at the tool boundary — even when the attack evades the baseline 8KB scanner. Our target is
**DVAA** (Damn Vulnerable AI Agent), the organizers' intentionally-vulnerable training sandbox, run
offline on localhost. This is an authorized, sanctioned hackathon; all work is defensive.

## Repo map
| Path | What |
|---|---|
| `GOAL.md` | North star + Definition of Done (the 7-item winning minimum). |
| `LOOP.md` | The autonomous PR-driven goal-loop protocol + model policy + degradation protocol. |
| `STATE.md` | Living loop state (phase, active ticket, open PRs, blockers, decision log). |
| `BACKLOG.md` | Ordered tickets T1–T9 + stretch, deps graph, parallel waves. |
| `AGENTS.md` | Roles, model policy, status-line contract, how `handoffs/` works. |
| `gates/` | SE / tester / reviewer / delivery checklists (encode the firm's data-scale rules). |
| `prompts/` | Reusable child-agent prompt templates the orchestrator fills per ticket. |
| `handoffs/` | Per-ticket handoff files written on a degradation/safety stop. |
| `sentinel/` | The product: `proxy/`, `detectors/`, `alerts/`, `dashboard/`, `scoring/`. |
| `captures/` | Deterministic exploit transcripts + variants + contrast (replayed on stage). |
| `demo/` | `<3-min` demo script, `run-demo.sh`, rehearsal logs. |
| `planning/` | `STRATEGY.md` (why/how) + `RESEARCH.md` (evidence + citations). |

## How the loop works
The build runs as an autonomous, **PR-review-gated** loop: an orchestrator (main Opus 5.5 session) picks
tickets from `BACKLOG.md`, dispatches child agents (`model: "opus"`) to implement/test/review each on its
own branch, runs the `gates/`, and opens one PR per ticket for the operator to review. It pauses at each
PR and advances other unblocked tickets meanwhile. Full protocol: **`LOOP.md`**. Degradation/handoff
handling: `AGENTS.md`.

## Chat with the orchestrator
Open an issue with the **"Chat with the orchestrator"** template, or comment on pinned issue **#32**. This is a
priority async intake that runs in parallel with the build loop: the orchestrator answers chat before other
work, usually in about a minute. Ask about status, decisions, or request work. Label `chat-urgent` to be answered
first. Details: **[`CHAT.md`](CHAT.md)**.

## How to review PRs
Each PR links its ticket + DoD item and fills `.github/pull_request_template.md` with gate evidence
(SE / tester / reviewer / delivery), the bounds it introduced + their fail-loud failure modes, and how to
verify locally. Check the gate boxes, confirm bounds are fail-loud (never silent truncation), then
approve/merge. The orchestrator never merges its own PR without operator approval.

## Evaluate everything locally
`scripts/eval.sh all` runs doctor, DVAA up, every test suite, scoring, the contrast and the dashboard. See
**[`EVAL.md`](EVAL.md)** for what each step shows and how to fix failures.

## Quickstart (placeholder — filled by T1/T2)
```bash
# 1. Bring up DVAA offline (organizer sandbox; no API key needed)
#    Docker: docker run -p 127.0.0.1:9000:9000 -p 127.0.0.1:7001-7021:7001-7021 opena2a/dvaa:0.9.2
#    Source: npm install && npm start   (Node >=24)   dashboard: http://localhost:9000
#
# 2. Run SentinelProxy in front of a target agent port   (added by T2)
#    node sentinel/proxy/...   --target 7005 --mode block
#
# 3. Replay the demo deterministically from captures/     (added by T9)
#    ./demo/run-demo.sh
```
