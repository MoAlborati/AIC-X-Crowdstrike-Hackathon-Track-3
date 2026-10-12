# Demo videos — Tourniquet (CrowdStrike x SCU, Track 3 + Track 1)

Offline screen recordings of the demos, one subfolder per track/item. Everything runs on
`127.0.0.1`; every secret shown is a **FAKE DVAA honeytoken** (e.g. `DVAA-AWS-KEY-ID`,
`DVAA-SSH-KEY`, `DVAA-ADMIN-PASSWORD`) — no real credentials.

**Submission build:** tag `v1.0-submission` = commit **cb2b7f5**. Most clips were captured on
`cb2b7f5`; the exceptions are noted per row below (and in each clip's `.caption.txt`).

**How to view:** download the `.mp4` and open it in any player (VLC, browser, QuickTime), or
preview it in the GitHub file view. H.264 / yuv420p, faststart; each clip is < 35 MB and
well under GitHub's 100 MB/file limit (no Git LFS needed).

## Index

| Track / item | File | SHA | Duration | What it demonstrates |
|---|---|---|---|---|
| **Track 3 — Tourniquet (3B)** | [`track3-tourniquet/track3-terminal.mp4`](track3-tourniquet/track3-terminal.mp4) | `e97e2f0` * | 0:32 | `demo/run-demo.sh --auto`: preflight, exploit, 8 KB-evasion catch, **live benign HTTP 200 + live attack HTTP 403** (verdict `sentinel-t3`), Beat 4b egress guard denies every unlisted destination. Green run, no failing beats. |
| **Track 3 — Tourniquet (3B)** | [`track3-tourniquet/track3-dashboard.mp4`](track3-tourniquet/track3-dashboard.mp4) | `cb2b7f5` | 0:29 | Playwright walk (1440x900) of the T5 incident-replay dashboard: the 4 stage captures — vulnerable → aim-twin → proxy-blocked → egress-blocked — showing real Tourniquet alerts (`HoneytokenExfiltrationAttempt` / `NonAllowlistedEgressDestination` · Blocked). |
| **Track 3 — Tourniquet (3B)** | [`track3-tourniquet/full-demo.mp4`](track3-tourniquet/full-demo.mp4) | `1146e14` ** | 0:51 | Combined terminal + dashboard walkthrough (1080p). Includes the **live** Beat 4b egress run. Backup / fallback reel. |
| **Track 3 — Path A (OpsBot)** | [`track3a-opsbot/track3a-opsbot.mp4`](track3a-opsbot/track3a-opsbot.mp4) | `cb2b7f5` | 0:12 | `node track3a/run-demo.mjs`: our own agent attacked (indirect + direct injection) and defended in layers — undefended → chat proxy → + egress guard → hardened → full. Attacks stopped, 0 benign FPs, per-layer latency. |
| **Track 1 — SOC Brief** | [`track1-socbrief/track1-queue.mp4`](track1-socbrief/track1-queue.mp4) | `cb2b7f5` | 0:17 | Playwright walk (1440x900) of the SOC Brief queue UI: 22-alert queue, severity grouping, Escalate / Needs-a-human dispositions, 100% needs-human recall. Offline, deterministic. |
| **Track 1 — SOC Brief** | [`track1-socbrief/track1-soc-handoff.mp4`](track1-socbrief/track1-soc-handoff.mp4) | `cb2b7f5` | 0:24 | `scripts/soc-handoff.sh`: hands Tourniquet's real T4 alerts to SOC Brief, which produces the plain-English **P1 brief** fully offline (model: none). |
| **Encore — "the 403 that lied"** | [`encore/encore-two-layer.mp4`](encore/encore-two-layer.mp4) | `cb2b7f5` | 0:15 | `scripts/encore-two-layer.sh` observe vs block, live in an isolated docker sandbox: observe → 403 returned but key still exfiltrated (2 canary hits, the 403 *lied*); block → egress inspector denies 3x, attacker gets 0 hits. |

\* **`track3-terminal.mp4`** was captured on `e97e2f0`, the direct parent of tag `v1.0-submission`
(`cb2b7f5`). The only commit between them (`cb2b7f5`, "harden macOS no-free-port dashboard test")
is test-hardening with **no demo-runtime effect**; the recorded beats are identical.

\*\* **`full-demo.mp4`** was recorded earlier on `1146e14` (the SentinelProxy→Tourniquet rebrand
build; runtime identical to the submission) and is the only clip that caught the **live** Beat 4b
egress socket. Its terminal frames show a local build path (`/home/gingy/crowdstrike-video2`,
cosmetic) and only fake honeytokens. Kept as the polished fallback reel.

## How these were recorded (offline, headless WSL)

- **Terminal clips:** `script(1)` capture of the real command through a pty (ANSI colour), then
  rendered frame-by-frame with PIL and encoded with ffmpeg. Local home paths are sanitized to
  `~/tourniquet` before rendering.
- **Dashboard / queue clips:** Playwright (cached Chromium + bundled ffmpeg) recording at
  1440x900 against the shipped servers on loopback.

See [`demo/SCRIPT.md`](../SCRIPT.md) for the presenter script each beat follows.
