# Demo videos

Recorded on the frozen submission build (tag `v1.0-submission`, commit `cb2b7f5`). Product: **Tourniquet** — it stops the data bleed.

| Track | File | What it shows |
|---|---|---|
| Track 3 (Tourniquet) | `track3-tourniquet/full-demo.mp4` | Full `run-demo.sh --auto`: live 200 (benign) → 403 (attack) at the proxy, then the live egress block (Beat 4b). Combined terminal + dashboard. |
| Track 3 (Tourniquet) | `track3-tourniquet/track3-terminal.mp4` | Terminal-only capture of the same run. |
| Track 3A (OpsBot) | `track3a-opsbot/track3a-opsbot.mp4` | Path A: OpsBot layered defense table (`node track3a/run-demo.mjs`). |
| Track 1 (SOC Brief) | `track1-socbrief/` | SOC Brief queue UI + `soc-handoff.sh` P1 brief. *(added in a follow-up commit)* |
| Encore | `encore/` | The "403 that lied": observe-mode control (attacker gets the key) vs block-mode (0 hits). *(follow-up)* |

**How to view:** download and play any `.mp4`, or open on GitHub. These mirror the live 18:00 demo; the recorded fallback for the stage is `track3-tourniquet/full-demo.mp4`.
