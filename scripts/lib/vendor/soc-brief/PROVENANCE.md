# Vendored: SOC Brief deterministic core (Track 1)

These six files are a verbatim copy of the Track 1 "SOC Brief" deterministic path,
vendored so the Tourniquet SOC-handoff adapter (`scripts/lib/soc-handoff.mjs`) stays
self-contained after `track1/` moved to its own repository.

- Source of truth: **MoAlborati/Tourniquet-SOC-Brief-Track1** (`src/`), the Track 1 repo.
- Copied from mono-repo `track1/src/` at the #197 re-land (teach-the-verdict + severity grouping).
- Files: `normalize.js`, `chain.js`, `signals.js`, `briefing.js`, `prompts.js`, `labels.js`
  (the full closure of the deterministic handoff path; `llm.js` is not reached — no model is used).
- Zero npm dependencies. Only `scripts/lib/soc-handoff.mjs` imports these.

This is a copy and can drift from Track 1. For the frozen hackathon deliverable that is acceptable;
update it from the Track 1 repo if the SOC Brief core changes.
