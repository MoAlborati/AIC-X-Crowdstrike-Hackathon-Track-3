# T3 — Detector core: implementation spec (se-gate prep)

Prepared before T2 (proxy skeleton) has a PR, so the T3 implementer can start the moment it lands.
This is a **defensive detector spec** for the sanctioned CrowdStrike × SCU hackathon (Track 3). DVAA is
the organizer-provided, intentionally vulnerable localhost sandbox; every secret named here is one of its
FAKE planted honeytokens.

- **Pinned inputs:** repo `main` @ `c56dbf4`; DVAA checkout @ `5791826` (= T1's pinned
  `57918267d8d…`, `captures/README.md:9`). All `damn-vulnerable-ai-agent/…` line numbers refer to that commit.
- **Scope of T3:** `sentinel/detectors/` only (BACKLOG.md:47). This spec lives in `planning/` and touches
  nothing under `sentinel/`.
- Assumptions about T2 are collected in §8, so they can be reconciled against T2's PR in one place.

---

## 1. se-gate checklist for T3 (`gates/se-gate.md`)

### Spec clarity
- [x] **Ticket / DoD / deps / scope:** T3, DoD 2, deps T2, scope `sentinel/detectors/` (BACKLOG.md:43-47).
  Disjoint from T2 (`sentinel/proxy/`, `sentinel/config/`), T4 (`sentinel/alerts/`), T5, T6, T7.
  T3 **reads** `sentinel/alerts` (to round-trip verdicts through `buildAlert`) but never edits it. Any T4 change
  T3 needs (§5.4) is a separate follow-up ticket.
- [x] **Acceptance criteria are concrete:** each BACKLOG T3 criterion maps to a named fixture and assertion in §7.
- [x] **Real seams:** DVAA RAGBot 7005 (`damn-vulnerable-ai-agent/src/core/agents.js:306`), RAGBot-AIM 7014
  (`agents.js:346`), RepoBot 7022 (`agents.js:540`), FlightBot 7017 (`agents.js:462`); captures
  `captures/attack/*.json`, `captures/benign/*`, `captures/variants/manifest.json`; consumer
  `sentinel/alerts/schema.js` `buildAlert()` (`schema.js:212`).

### Bounds & fail-loud
Each cap is enforced **before** any partial result can become an `allow`. On overflow the detector returns
a `scan_cap_exceeded` verdict carrying `overflow: {payload_size, cap, action}` (BACKLOG.md:57-58) and logs
that object. It never scans a prefix and passes the rest through, which is the DVAA anti-pattern
(`vulnerabilities.js:382-405`).

| Cap (proposed name) | Value | Why this value | Beyond it |
|---|---|---|---|
| `MAX_REQUEST_SCAN_BYTES` | 1,048,576 (1 MiB) | Equals DVAA's own body cap `MAX_AGENT_BODY_BYTES` (`src/index.js:1405`, 413 at `index.js:1440-1450`) and T2's draft `limits.maxRequestBytes` (§8). DVAA can't receive anything larger, so a bigger cap adds no coverage. | `scan_cap_exceeded`, `action: "block"` in enforce (request refused, not forwarded); `action: "forward_unscanned_alerted"` in report-only (see Q6) |
| `MAX_RESPONSE_SCAN_BYTES` | 4,194,304 (4 MiB) | T2 draft `limits.maxResponseBytes`. The largest DVAA reply seen is under 5 KB (repo: 5 tool calls, ≤1 KB `creds`, `index.js:903`). 4 MiB leaves room for data-rich replies. | `scan_cap_exceeded`, `action: "withhold"` in enforce (reply replaced by a structured refusal); alert in report-only |
| `MAX_MESSAGES` | 256 per request | DVAA reads only the last user turn (`index.js:1495-1515`), but T3 scans **every** message, since history and `role:tool` turns are where indirect injection lives. 256 turns is far above any capture (all have 1). | `scan_cap_exceeded`, block/alert as above |
| `MAX_TOOL_CALLS` | 64 per response | DVAA's maximum is 5 (repo path: read_repo, run_shell, read_file ×2, http_post; `index.js:844-913`). | `scan_cap_exceeded`, withhold/alert |
| `MAX_DECODE_DEPTH` | 3 nested decodes (URL → base64 → hex, any order) | Covers `encodeURIComponent` inside JSON-in-JSON (`index.js:1204`, `1210`) plus one deliberate re-encode layer. | Decoding stops at depth 3 and the verdict records `decodeDepthExhausted: true` with a `report` disposition. This is a **raise-risk** signal, not a silent stop. |
| `MAX_DECODED_BYTES` | 4 × scanned bytes, ≤ 8 MiB total | Base64 inflates input by at most 4/3 per layer. 4× covers 3 layers with margin. | `scan_cap_exceeded` (`action: block/withhold`) |
| `MAX_ENCODED_CANDIDATES` | 8,192 base64/hex runs (≥16 chars) per payload | A 1 MiB payload of benign JSON rows yields far fewer runs (the 400-row corpus has 0 runs ≥16 chars of `[A-Za-z0-9+/]`). An attacker spraying runs to exhaust the decoder trips this. | `scan_cap_exceeded`. Runs are never skipped. |
| `INSPECT_TIMEOUT_MS` | 500 ms per hook | T2 draft `limits.inspectorTimeoutMs`. Target latency is <30 ms (STRATEGY.md:27). 500 ms is a hang guard, not a budget. | **Fail-closed:** `scan_cap_exceeded` with `ruleId: "bounds.inspector_timeout"`, deny/withhold + ALERT (BACKLOG.md:72-73) |
| `HONEYTOKEN_REGISTRY_MAX` | 4,096 entries (static DVAA set ≈ 20 + per-session canaries), TTL 60 min for per-session ones | 1,024 sessions × ~4 minted canaries per session. | Expired entries are dropped with a log line. If the registry is still full, `RegistryFullError` → fail-closed for **new** canary mints + ALERT (`ruleId: "bounds.registry_full"`). Existing entries are never evicted to make room. |
| `SESSION_LEDGER_MAX_SESSIONS` | 1,024, idle TTL 30 min | Demo plus scoring needs fewer than 100. | After TTL sweep, still full → `LedgerFullError`, fail-closed on egress for the new session + ALERT (`bounds.ledger_full`) |
| `SESSION_LEDGER_MAX_ENTRIES` | 10,000 calls per session | Cumulative caps need the full per-session history. | `LedgerFullError` → HOLD/deny that session's egress + ALERT |
| `MANDATE_MAX_GRANTS` | 32 grant entries per session | A user turn naming more than 32 distinct tool/destination pairs is not a realistic task. Ambiguity resolves narrower. | `MandateOverflowError` → mandate is **empty** (narrowest), so egress is denied + ALERT (`mandate.overflow`) |
| `MAX_SINK_SHINGLES` | 65,536 8-char shingles drawn from sink args | Sink args are small (aim-ab args = 412 chars, `aim-ab.demo.json:31`). The shingle set is built from the **sink** side, and the untrusted text is streamed past it once, so the untrusted side is never capped. | `scan_cap_exceeded` (sink args > ~64 KB is itself anomalous) |
| `MAX_FINDINGS_DISPLAYED` | 256 per verdict | **Display only** (§1 resolution vs display). | Rendered list gets a `{omitted: n}` marker. The decision was already made over all findings. |
| Evidence / argsPreview text | 2,048 chars | **Display only.** T4 applies it anyway (`sentinel/alerts/schema.js:49`). T3 passes full evidence and lets T4 bound + redact it. | T4's explicit `…[TRUNCATED` marker (`schema.js:194-204`) |

- [x] Every input that T3 assembles or scans has a cap (table above).
- [x] Overflow is fail-loud with `{payload_size, cap, action}` (verdict field `overflow`, §5).
- [x] Each cap documents why the value was chosen and what happens beyond it. The implementer copies this table into the PR's "Bounds introduced" section.

### Resolution vs display caps
- [x] **Decision paths use full data:** the honeytoken match, taint flags, destination provenance and
  policy evaluation run over the **entire** request (all messages) and the entire response (content plus
  every `tool_calls[].function.arguments`, parsed). Honeytoken lookup is a targeted per-token `indexOf`
  (or Aho-Corasick) over each normalized form, never a "first N findings then decide" pattern.
- [x] **Display-only caps** (`MAX_FINDINGS_DISPLAYED`, evidence 2,048) are labeled as such and sit after the
  decision has been made.

### Data-rich by design
- [x] Validated against the >16 KB evasion docs (22.8 KB, `captures/variants/fixtures/evasion/*`), the
  400-row tool output (33,435 chars, `fixtures/benign/benign-toolrows.json`), a generated 1 MiB+1 oversize
  body, and a 400-row tool output with a honeytoken in row 200 (§7). These are not 2-3 row toys.

**se-gate verdict: PASS for spec** once Q2 and Q3 (§9) are answered. Those two change verdict wiring, not detection logic.

---

## 2. Signal map — where the exfil signal is, per hook

Hooks: **PRE** = pre-forward (request body, before DVAA sees it). **POST** = post-response (DVAA's reply,
after its server-side tools already ran; see §3).

### 2.1 Facts about DVAA's endpoint that drive the map
- DVAA answers only the **latest `role:user` message** and ignores `role:tool`, `role:system` and earlier turns
  (`src/index.js:1495-1515`). Its own scanner runs only on that text (`index.js:1843-1849`). T3 must scan
  all messages anyway. A real agent client sends tool results as `role:tool`, and the delete-the-fix
  proof in §7 checks that an injection in an earlier tool message is still caught.
- The reply is `choices[0].message` with `tool_calls` (`index.js:1866-1867`) plus a top-level `dvaa{}` block
  when the handler returns one (`index.js:1877`). `tool_calls[].function.arguments` is a **JSON string**
  (`index.js:1210`, `808`, `866`, `912`, `1098`), so secrets inside it are JSON-escaped and must be parsed,
  not regex-matched raw.
- `dvaa{}` is **ground truth for scoring (T7) only**. T3 must never read it to decide: it doesn't exist in a
  non-DVAA deployment, and keying on it would test the label, not the detector. A test asserts the verdict
  is identical with `dvaa{}` stripped.

### 2.2 T1 attack captures

| Capture | P