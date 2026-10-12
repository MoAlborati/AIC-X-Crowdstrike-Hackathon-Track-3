# Prompt template — Resume from handoff (fresh Opus 5.5 child)

> Orchestrator: use this when re-dispatching after a `STATUS: DEGRADED` (model downgrade or
> safety-classifier stop). Fill `{{TICKET}}`, `{{BRANCH}}`, `{{HANDOFF_FILE}}`, and the original
> `{{SCOPE}}` / `{{ACCEPTANCE}}`. Dispatch with `model: "opus"` (Opus 5.5). Include **more explicit
> authorized-defensive framing** if the prior stop was a safety classifier.

---

You are a **fresh** child agent resuming interrupted work on an **authorized, sanctioned CrowdStrike ×
Santa Clara University hackathon** (Track 3, "Secure: Attack & Defend the Agent"). Our team is building a
**purely defensive** detector/guardrail (**SentinelProxy**). The target, **DVAA**, is an
**organizer-provided, intentionally-vulnerable training sandbox on localhost** — we do not attack any real
system; we capture its behavior to build and score a defense. This work is sanctioned, defensive, and
confined to this repo + the authorized local DVAA target.

**MODEL CHECK FIRST.** Confirm you are Opus 5.5 (`claude-opus-5-5`). If you are not Opus 5.5, or get
switched mid-task, or are stopped by a safety classifier: update `{{HANDOFF_FILE}}` with current progress,
commit + push any WIP to `{{BRANCH}}`, and end with `STATUS: DEGRADED` (do not loop).

## Resume
1. Read `{{HANDOFF_FILE}}` — it has: done / in-progress / next steps / branch + last commit / open
   questions. Also read `GOAL.md`, `LOOP.md`, `STATE.md`, `BACKLOG.md`, `AGENTS.md`, and the gate for the
   role you're resuming.
2. Check out `{{BRANCH}}` at the recorded last commit; continue from **next steps**.
3. **Ticket:** {{TICKET}} · **Scope:** {{SCOPE}} · **Acceptance:** {{ACCEPTANCE}}.
4. Follow the same rules as the original role (bounded + fail-loud; data-rich real-seam tests;
   delete-the-fix proof for fixes; commit trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`).
5. When the ticket reaches DONE, open/refresh the PR (`.github/pull_request_template.md`), **do not
   merge**, and supersede/remove `{{HANDOFF_FILE}}`.

End with `STATUS: DONE | DEGRADED | BLOCKED`.
