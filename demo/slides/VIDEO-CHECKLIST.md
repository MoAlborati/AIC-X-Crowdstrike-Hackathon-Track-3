# VIDEO-CHECKLIST: silent fallback recording (Catherine, Mac, 16:00–16:30)

This was task C from #34, drafted for Catherine now that she's presenting. The defaults come from #66: a **silent** screen
recording on Catherine's Mac, made between **16:00 and 16:30**, with **Cmd-Shift-5**, and saved **outside the repo**.
On stage at 18:00, the video replaces any beat that breaks (see `demo/PRESENTER.md`, "If X breaks").

Sources: `demo/PRESENTER.md` (T-30 and After), `demo/SCRIPT.md` (the beats, on main after #50), `demo/run-demo.sh`.
If anything here disagrees with `run-demo.sh`, the runner wins.

> **Deep links.** #76 (`t5-stage`, `?stage=1&capture=…`) is **not merged** as of this writing. Use the **main**
> column below. Once #76 merges, use the `?stage=1` column instead: its dropdown shows only the 3 stage captures.

## 1. Pre-flight (15:45, from PRESENTER T-30)

- [ ] `colima start --cpu 4 --memory 6`, then confirm with `docker info | head -3`
- [ ] `export PATH=/opt/homebrew/opt/node@24/bin:$PATH`, then confirm `node --version` prints `v24.x`
- [ ] `git pull`, then `scripts/eval.sh doctor`. Expect all PASS. If #70 isn't merged, run `git checkout mac-compat` first.
- [ ] `scripts/eval.sh up`. Expect `all 22 DVAA ports answer 200` and `bound to 127.0.0.1`.
- [ ] `EVAL_DASHBOARD_PORT=9100 scripts/eval.sh dashboard`, then open the three tabs from §3 (in order, in a **fresh browser window**).
- [ ] Dry run: `demo/run-demo.sh --auto --keep-dvaa --no-teardown`. The Summary must say `demo run clean`. **Do not record until it does.**
- [ ] Quit Slack, Mail, Messages, Calendar, and every other app except Terminal, the browser and the slides. Turn on **Do Not Disturb** (Control Center → Focus).
- [ ] Display at **1920×1080** or the "Default" scaling (System Settings → Displays). Dock set to auto-hide (System Settings → Desktop & Dock).
- [ ] Terminal: font at least **20pt** (Cmd-+), dark theme. Terminal on the **left half**, dashboard on the **right half**.
- [ ] Clean the terminal (see §6): `export PS1='$ '`, then `clear`.
- [ ] Slides open on slide 2, in a window you can bring to the front with one Cmd-Tab.

## 2. Recording settings (exact)

| Setting | Value | Why |
|---|---|---|
| Tool | **Cmd-Shift-5** (macOS Screenshot toolbar) | built in, no install |
| Mode | **Record Selected Portion**, sized to the terminal + browser area, **below the menu bar** | Not *Record Selected Window*: one window can't follow you from the terminal to the dashboard to the slides. Not *Record Entire Screen*: it captures the menu-bar clock and notification badges. |
| Resolution | display at 1920×1080 / "Default". Retina records at 2× (about 3840×2160), and §5 scales it to 1920 wide. | matches the projector and the stage layout |
| Options → Microphone | **None** | silent recording (#66). Catherine narrates live over it. |
| Options → Show Mouse Clicks | **On** | the audience can see which tab you clicked |
| Options → Show Floating Thumbnail | **Off** | otherwise the file lands late and the thumbnail covers the corner |
| Options → Save to | **Desktop** | the raw file is `~/Desktop/Screen Recording <date>.mov` |
| Final name | rename to `~/Desktop/fallback-demo-raw.mov`. §5 produces **`~/Desktop/fallback-demo.mov`**. | PRESENTER opens this exact path in QuickTime |
| Where it must **not** go | anywhere inside the repo. `*.mov` is **not** gitignored, and `git add -A` would commit 100+ MB. | |

> `demo/REHEARSAL.md` still says `demo/fallback-demo.mp4`. That's stale. #66 and PRESENTER set the path to `~/Desktop/fallback-demo.mov`.

Stop the recording with the ⏹ in the menu bar, or **Cmd-Ctrl-Esc**.

## 3. Shot list (video time = stage clock)

The video's timestamps match the stage clock, so "play the video from 0:40" lands on Beat 3. Run **interactive**
(`demo/run-demo.sh --keep-dvaa --no-teardown`, not `--auto`) and press **Enter** on the target time. `--auto` runs
too fast for the timestamps to line up. Start the run first and let the 3 preflights pass. **Then** start recording, sitting at the first "press Enter".

Dashboard deep links (port 9100):

| tab | main (use now) | after #76 merges |
|---|---|---|
| vulnerable | `http://127.0.0.1:9100/?id=attack/aim-ab.demo&run=runA` | `http://127.0.0.1:9100/?stage=1&capture=vulnerable` |
| aim-twin | `http://127.0.0.1:9100/?id=attack/aim-ab.demo&run=runB` | `http://127.0.0.1:9100/?stage=1&capture=aim-twin` |
| proxy-blocked | `http://127.0.0.1:9100/?id=contrast/runs/proxy-block.demo` | `http://127.0.0.1:9100/?stage=1&capture=proxy-blocked&step=last` |

| video time | beat | action (exact) | on screen (must be visible) | dashboard tab |
|---|---|---|---|---|
| 0:00–0:20 | 1 Hook | slides, slide 2 (Cmd-Tab to slides) | two incidents and the Kurtz quote | — |
| 0:20–0:40 | 2 Structure | slide 3 | confused-deputy diagram | — |
| **0:40** | **3** Exploit (red) | Cmd-Tab to Terminal, **Enter**. At about 0:50 click the `vulnerable` tab. | `submit_to_index`, `true`, `dvaa-admin-secret … 123-45-6789` | vulnerable |
| **1:00** | **3b** 8KB evasion | back to Terminal, **Enter** | `inMiddleGap:true`, `evadesDvaaBaseline:true`, `t3Caught:2` | — |
| **1:20** | **4** Live block | **Enter**. Wait for both codes, then click the `proxy-blocked` tab. | live `HTTP 200`, then `HTTP 403`, `sentinel-t3`, the T4 alert (ATLAS, OWASP LLM01). **Must not show** `WARN live proxy unavailable`. | proxy-blocked |
| **1:40** | **4b** Egress | back to Terminal, **Enter** | `deny` rows, `RESULT block: PREVENTED`, `(no canary hits)` | — |
| **1:50** | **5a** AIM twin | **Enter**, click the `aim-twin` tab, then at about 2:00 Cmd-Tab to slide 6 | `false` + the denial reason, then the red / green / green columns | aim-twin |
| 2:05–2:30 | 6 How | slide 7 | field → mechanism → rule | — |
| **2:30** | **7** Close | Cmd-Tab to Terminal, **Enter**. Hold on the table for 8 s, then slides 8 → 10. | T3 vs DVAA table: recall, FP, `8KB evasion 2/2`, p95 < 0.5 ms; Summary `demo run clean` | — |
| 2:50–3:00 | end | slide 10 held. **Stop recording.** | — | — |
| (separate clip) | 3A OpsBot encore, optional | new recording, same settings: `node track3a/run-demo.mjs` (about 2 s), hold 10 s | the layering table: Undefended LEAKED ×2 … all blocked, benign OK | — |

Save the encore as `~/Desktop/fallback-opsbot.mov`. Record it only if there's time left before 16:30.

## 4. Retake policy

- **Retake** if any of these happen: a beat prints `FAIL` or `NOT YET MERGED`; Beat 4 prints `WARN … showing the recording`
  (the fallback should show the *live* 200/403); a notification, another app, or a home-directory path shows up on screen;
  a beat starts more than **10 s** off its target time; the total runs over **3:10**.
- **Don't retake** for mouse wobble, a slightly slow tab click, or a pause shorter than 3 s. Those get trimmed or ignored.
- Before every retake: `clear`, then rerun `demo/run-demo.sh --keep-dvaa --no-teardown` up to the first "press Enter". Delete the bad raw file.
- **At most 3 takes.** At **16:25** stop and keep the best one, even if it isn't perfect. If no take is clean, keep the best
  one anyway and post on #66 which beat is bad, so Catherine knows not to cut to that beat.
- If Beat 4 can't go live (DVAA or Colima down) by 16:15, record with `demo/run-demo.sh --no-dvaa --no-teardown` and note
  "Beat 4 is the recording" on #66.

## 5. Post-recording: trim, compress, upload

1. Watch it once, end to end, and note the **start** (first frame of slide 2) and **end** (slide 10 held) timestamps.
2. Trim and compress **with ffmpeg** (`which ffmpeg`; `brew install ffmpeg` only if there's time):

   ```bash
   ffmpeg -ss 00:00:01.5 -to 00:03:01 -i ~/Desktop/fallback-demo-raw.mov \
     -vf "scale=1920:-2,fps=30" -c:v libx264 -preset slow -crf 23 -pix_fmt yuv420p \
     -an -movflags +faststart ~/Desktop/fallback-demo.mov
   ```

   Set `-ss` and `-to` to the timestamps from step 1. `-an` drops audio (it's silent). The result plays in QuickTime and is about 20–60 MB.
3. **Without ffmpeg (QuickTime):** open the raw file, **Edit → Trim** (Cmd-T), drag the yellow handles, **Trim**, then
   **File → Export As → 1080p**, and save as `~/Desktop/fallback-demo.mov`.
4. Check it: open `~/Desktop/fallback-demo.mov` in QuickTime and scrub to **0:40, 1:20 and 2:30**. Each should land on that beat.
5. Copy to USB: `cp ~/Desktop/fallback-demo.mov /Volumes/<USB>/`.
6. Upload (**pending #66**): **YouTube unlisted** or **Google Drive** (link-only, anyone with the link can view). Post the
   link as a comment on #66. **Never** commit the file or attach it to a repo release.
7. Before 18:00 (PRESENTER T-30): leave it open in QuickTime, paused at 0:00.

## 6. What NOT to show

- **No terminal history with paths.** Before recording: `export PS1='$ '` and `clear`. Don't press ↑ while recording.
  Don't `cd`, `ls ~` or `pwd` on camera. If the prompt shows `/Users/<name>/…`, retake.
- **No other apps.** Only Terminal, the browser (one fresh window: just the 3 dashboard tabs, bookmarks bar hidden with Cmd-Shift-B,
  no extensions popping up) and the slides. No Finder windows, no IDE, no chat.
- **No notifications.** Do Not Disturb on; Slack, Mail, Messages and Calendar quit. Check that nothing is pending in Notification Center before you start.
- **No menu bar or Dock.** The Selected Portion sits below the menu bar, and the Dock is hidden.
- **No secrets beyond the sandbox ones.** `dvaa-admin-secret`, `123-45-6789` and the `DVAA-*` canaries are fake sandbox values
  and are meant to be seen. No `.env`, tokens, `gh auth`, or browser autofill.
- **No `git` output** on camera (it shows branch names and remotes).
