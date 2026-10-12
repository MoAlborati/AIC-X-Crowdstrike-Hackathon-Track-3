# Delivery Gate — live-drive on the data-rich environment

Run by the orchestrator after any ticket that touches **detection or demo**, and as the final gate before
we call the demo ready. A fresh-project / toy-fixture pass is INSUFFICIENT — this gate runs against the
**real DVAA fleet** and data-rich payloads. Encodes the team's data-scale reliability rule: demo on a data-rich environment.

## Data-rich environment
- [ ] The run uses the **real DVAA agents** (the recommended fleet: RAGBot 7005 ↔ AIM 7014,
      RepoBot 7022 ↔ 7023, LegacyBot 7003, SecureBot 7001) and/or **real captures** from `captures/`
      — never hand-written toy JSON.
- [ ] Payloads exercised include >8KB bodies and multi-hundred-row tool outputs (the data-scale regime).

## End-to-end arc
- [ ] Exploit → detect → block → AIDR alert → incident graph (taint path) → scoring table all run from
      captures, deterministically (no live cold LLM/API calls in the demo window).
- [ ] Honeytoken tripwire fires deterministically on the planted secret.
- [ ] Latency number renders; precision/recall vs `dvaa{}` ground truth renders.
- [ ] Secure-by-design contrast shown: same attack fails on the AIM twin + SecureBot.

## Convergence (hackathon-scaled — stated adaptation)
> The team's convergence rule asks for ≥15 consecutive clean runs. **For this 8-hour hackathon we adapt that to
> ≥5 consecutive clean demo replays** — enough to prove the deterministic replay is not a lucky run,
> without burning the build window. This adaptation is deliberate and recorded here.
- [ ] **≥5 consecutive clean** `demo/run-demo.sh` replays, no errors, no nondeterministic variance.
- [ ] Each replay's result (pass + latency) logged in STATE.md.
- [ ] Fallback demo video recorded and checklist in `demo/` complete.

**Verdict:** PASS only with ≥5 green consecutive replays on the data-rich environment. Record in STATE.md.
