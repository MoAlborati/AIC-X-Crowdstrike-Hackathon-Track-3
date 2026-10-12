# VIDEO-CHECKLIST: silent fallback recording (Catherine, Mac, 16:00–16:30)

This was task C from #34, drafted for Catherine now that she's presenting. The defaults come from #66: a **silent** screen
recording on Catherine's Mac, made between **16:00 and 16:30**, with **Cmd-Shift-5**, and saved **outside the repo**.
On stage at 18:00, the video replaces any beat that breaks (see `demo/PRESENTER.md`, "If X breaks").

Sources: `demo/PRESENTER.md` (T-30 and After), `demo/SCRIPT.md` (the beats, on main after #50), `demo/run-demo.sh`.
If anything here disagrees with `run-demo.sh`, the runner wins.

> **Deep links.** #76 (stage mode) and #97 (egress stage capture) are merged. Use the `?stage=1` links in §3, each
> opened at its last step. The spoken lines follow the script cut (critic D, #112): 372 words, about 2:47.

## 1. Pre-flight (15:45, from PRESENTER T-30)

- [ ] `caffeinate -dimsu &` so the Mac can't sleep mid-recording
- [ ] `colima start` (plain, no `--cpu`/`--memory`), then confirm with `docker info | head -3`
- [ ] A Node 24 on PATH (Catherine: `export PATH=$HOME/.cache/node24/bin:$PATH`), then confirm `node --version` prints `v24.x`
- [ ] `git pull`, then `scripts/eval.sh doctor`. Expect all PASS. If #70 isn't merged, run `git checkout mac-compat` first.
- [ ] `scripts/eval.sh up`. Expect `all 22 DVAA ports answer 200` and `bound to 127.0.0.1`.
- [ ] Clean slate: `scripts/eval.sh dashboard-stop; rm -rf .eval/score`. **Never run `docker system prune` before 18:00.**
- [ ] Dry run: `demo/run-demo.sh --auto --no-dvaa --no-teardown`. The Summary must end `demo run clean — no failing beats ·
      dashboard http://127.0.0.1:<port>/`. **Do not record until it does.** It starts the dashboard itself; if :9100 is
      busy it moves to the next free port and prints it, so use that port in the §3 links.
- [ ] Warm the live Beat 4b run: `scripts/encore-two-layer.sh block` once (cold about 22 s; must end `ENCORE PASS`).
- [ ] Open the three tabs from §3 (in order, in a **fresh browser window**).
- [ ] Quit Slack, Mail, Messages, Calendar, and every other app except Terminal, the browser and the slides. Turn on **Do Not Disturb** (Control Center → Focus).
- [ ] Display at **1920×1080** or the "Default" scaling (System Settings → Displays). Dock set to auto-hide (System Settings → Desktop & Dock).
- [ ] Terminal: **18pt**, full height, dark theme. Terminal on the **left half**, dashboard on the **right half**. **Cmd-K before every Enter.**
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

Stop the recording with the ⏹ in the menu bar, or **Cmd-Ctrl-Esc**.

## 3. Shot list (video time = stage clock)

The video's timestamps match the stage clock, so "play the video from 0:35" lands on Beat 3. Run **interactive**
(`demo/run-demo.sh --no-dvaa --no-teardown`, not `--auto`) and press **Enter** on the target time. `--auto` runs
too fast for the timestamps to line up. Interactive mode pauses after **each** of Preflight 1/3, 2/3 and 3/3: press
Enter through them, **park at the prompt after "Preflight 3/3"**, Cmd-K, and **then** start recording. Beat 4 also
pauses once after the live 200/403: press Enter at about 1:18.

Dashboard deep links (port 9100, or the port `run-demo.sh` printed):

| tab | link |
|---|---|
| vulnerable | `http://127.0.0.1:9100/?stage=1&capture=vulnerable&step=last` |
| proxy-blocked | `http://127.0.0.1:9100/?stage=1&capture=proxy-blocked&step=last` |
| egress-blocked | `http://127.0.0.1:9100/?stage=1&capture=egress-blocked&step=last` |

| video time | beat | action (exact) | on screen (must be visible) | dashboard tab |
|---|---|---|---|---|
| 0:00–0:14 | 1 Hook | slides, slide 2 (Cmd-Tab to slides) | two incidents and the Kurtz quote | — |
| 0:14–0:35 | 2 Structure | slide 3 | confused-deputy diagram | — |
| **0:35** | **3** Exploit (red) | Cmd-Tab to Terminal, Cmd-K, **Enter**. At about 0:45 click the `vulnerable` tab. | `submit_to_index`, `true`, `dvaa-admin-secret … 123-45-6789` | vulnerable |
| **0:50** | **3b** 8KB evasion | back to Terminal, Cmd-K, **Enter** | `inMiddleGap:true`, `evadesDvaaBaseline:true`, `t3Caught:2` | — |
| **1:04** | **4** Live block | Cmd-K, **Enter**. Wait for both codes, click the `proxy-blocked` tab, then Cmd-K, **Enter** at about 1:18 (mid-beat pause). | live `HTTP 200`, then `HTTP 403`. **Must not show** `WARN live proxy unavailable`. | proxy-blocked |
| **1:24** | **4b** Egress (live) | back to Terminal, Cmd-K, **Enter**, then the `egress-blocked` tab | live `GROUND_TRUTH canary hits …: 0`, `ENCORE PASS` (or the WARN fallback: `RESULT block: PREVENTED`) | egress-blocked |
| **1:41** | **5a** AIM twin | Cmd-K, **Enter**, then Cmd-Tab straight to **slide 6** | the red / green / green columns | — (Slide 6 only) |
| 1:53–2:06 | 6 Guest list | slide 7 | field → mechanism → rule | — |
| **2:06** | **7** Close | Cmd-Tab to Terminal, Cmd-K, **Enter**. Hold on the table for 8 s, then slides 8 → 10. | T3 vs DVAA table, then Summary `demo run clean … dashboard http://127.0.0.1:<port>/` | — |
| 2:47–3:00 | end | slide 10 held. **Stop recording.** | — | — |
| (separate clip) | 3A OpsBot encore, optional | new recording, same settings: `node track3a/run-demo.mjs` (about 2 s), hold 10 s | the layering table: Undefended LEAKED ×2 … all blocked, benign OK | — |

Save the encore as `~/Desktop/fallback-opsbot.mov`. Record it only if there's time left before 16:30.

## 4. Retake policy

- **Retake** if any of these happen: a beat prints `FAIL` or `NOT YET MERGED`; Beat 4 prints `WARN … showing the recording`
  (the fallback should show the *live* 200/403); a notification, another app, or a home-directory path shows up on screen;
  a beat starts more than **10 s** off its target time; the total runs over **3:10**.
- **Don't retake** for mouse wobble, a slightly slow tab click, or a pause shorter than 3 s. Those get trimmed or ignored.
- Before every retake: `clear`, then rerun `demo/run-demo.sh --no-dvaa --no-teardown` and park at the prompt after "Preflight 3/3". Delete the bad raw file.
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
4. Check it: open `~/Desktop/fallback-demo.mov` in QuickTime and scrub to **0:35, 1:04 and 2:06**. Each should land on that beat.
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
