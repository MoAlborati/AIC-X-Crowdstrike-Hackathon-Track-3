# SentinelProxy — proxy skeleton (T2)

A reverse proxy in front of **one** DVAA agent's OpenAI-compatible `POST /v1/chat/completions`
(DVAA is the organizer-provided, intentionally vulnerable sandbox on `127.0.0.1`). It logs every
exchange in full, runs a pluggable inspector **before forwarding** and **after the reply**, and in
`block` mode turns an inspector "block" into a structured refusal. Zero dependencies, Node ≥ 24, ESM.

```
client ──▶ read body (cap) ──▶ inspectRequest ──▶ forward (timeout, response cap) ──▶ inspectResponse ──▶ capture ──▶ reply
                │ over cap: 413          │ block-mode block: 403 (DVAA never called)        │ block-mode block: 403
```

## Run

```bash
# DVAA fleet must be up (scripts/setup-dvaa.sh up); then:
node sentinel/proxy/cli.js                                   # sentinel/config/proxy.json → :8005 → RAGBot :7005, observe
node sentinel/proxy/cli.js --mode block --target-port 7014   # same file, different agent + mode, no code edits
SENTINEL_MODE=block SENTINEL_TARGET_PORT=7022 node sentinel/proxy/cli.js
node sentinel/proxy/cli.js --inspector ./my-inspector.js     # ESM module, default export = inspector

curl -s localhost:8005/v1/chat/completions -H 'content-type: application/json' \
  --data-binary @captures/benign/7005_ragbot.req.json
curl -s localhost:8005/sentinel/health
```

Bad config exits with code 2 and lists **every** problem at once (`ConfigError.issues`).

## Config — `sentinel/config/proxy.json`

All fields are required. Unknown keys are errors (catches typos). Precedence: **CLI flag > env > file**.
`--config <file>` / `SENTINEL_CONFIG` picks the file. A relative `sink.path` in the file resolves against
the file's directory. A relative path from env or CLI resolves against the current working directory.

| field | env | flag | shipped value |
|---|---|---|---|
| `listen.host` / `listen.port` | `SENTINEL_LISTEN_HOST` / `_PORT` | `--listen-host` / `--listen-port` | `127.0.0.1` / `8005` (`0` = ephemeral) |
| `target.host` / `target.port` / `target.name` | `SENTINEL_TARGET_HOST` / `_PORT` / `_NAME` | `--target-host` / `--target-port` / `--target-name` | `127.0.0.1` / `7005` / `RAGBot` |
| `mode` | `SENTINEL_MODE` | `--mode` | `observe` (`observe` \| `block`) |
| `limits.maxRequestBytes` | `SENTINEL_MAX_REQUEST_BYTES` | `--max-request-bytes` | 1 MiB |
| `limits.maxResponseBytes` | `SENTINEL_MAX_RESPONSE_BYTES` | `--max-response-bytes` | 4 MiB |
| `limits.upstreamTimeoutMs` | `SENTINEL_UPSTREAM_TIMEOUT_MS` | `--upstream-timeout-ms` | 15000 |
| `limits.inspectorTimeoutMs` | `SENTINEL_INSPECTOR_TIMEOUT_MS` | `--inspector-timeout-ms` | 500 |
| `limits.maxInFlight` | `SENTINEL_MAX_IN_FLIGHT` | `--max-in-flight` | 32 |
| `sink.path` | `SENTINEL_SINK_PATH` | `--sink-path` | `sentinel/proxy/.capture/exchanges.jsonl` (gitignored) |
| `sink.maxFileBytes` / `sink.maxFiles` | `SENTINEL_SINK_MAX_FILE_BYTES` / `_MAX_FILES` | `--sink-max-file-bytes` / `--sink-max-files` | 64 MiB / 5 |

## Bounds — every cap, why that value, what happens beyond it

Nothing in the proxy is silently truncated. Every overflow is rejected and logged at `ALERT` level with
`{size, cap, action}`. A `{size, cap, action}` that is shown as "at-least" (`sizeKnown: "at-least"`)
means the body was streamed without a `content-length` header. Reading stopped at the cap, so the true
size is unknown.

| bound | value | why | beyond it |
|---|---|---|---|
| `maxRequestBytes` | 1 MiB (ceiling 16 MiB) | Equals DVAA's own `MAX_AGENT_BODY_BYTES` (`src/index.js`). DVAA would return 413 above it anyway, and it keeps T3's full-payload scan bounded. That is 64× the 16 KiB where DVAA's head/tail scanner starts skipping the middle. | **Both modes:** `413 request_too_large`, ALERT log `{size, sizeKnown, cap, action:"reject"}`, plus a `ScanCapExceeded` AIDR alert (`scan_cap_exceeded`, OASB `context-overflow`). The body past the cap is never buffered. The capture record has `request.body:null` and `bodyNotCaptured:{reason,size,cap,action}`, and DVAA is never contacted. |
| `maxResponseBytes` | 4 MiB (ceiling 64 MiB) | DVAA replies are around 0.3–3 KB. 4 MiB leaves headroom for BYOK-LLM replies while bounding memory per exchange. | **Both modes:** the upstream is aborted. The client gets `502 response_too_large` with an ALERT `{size, sizeKnown, cap, action:"reject"}` and a `ScanCapExceeded` alert (`proxy.response_body_cap`). An uninspected reply is never passed through. |
| `upstreamTimeoutMs` | 15 s (ceiling 120 s) | Canned DVAA answers in under 5 ms. The BYOK LLM path can take seconds. | `504 upstream_timeout`, ALERT log, upstream socket destroyed. A closed port gives `502 upstream_unreachable`. |
| `inspectorTimeoutMs` | 500 ms (ceiling 10 s) | The demo budget is sub-30 ms detection, so 500 ms catches a wedged detector without false-tripping. | The inspector is treated as failed (see below). |
| `maxInFlight` | 32 (ceiling 1024) | Memory bound: 32 × (1 + 4) MiB is at most 160 MiB of buffered bodies. Also the keep-alive socket pool size. | `503 proxy_overloaded`, ALERT `{size, cap, action:"reject"}`. The rejected body is discarded, not buffered. |
| `sink.maxFileBytes` | 64 MiB (ceiling 1 GiB) | The floor is validated: `≥ 2·(maxRequestBytes+maxResponseBytes) + 256 KiB`, so a worst-case JSON-escaped record always fits one file. | Rotation: `x.jsonl → x.jsonl.1 → …` (INFO `sink_rotated`). A single record still too big (unreachable under the floor) is replaced by a stub `{captureFailed:{size,cap,action:"stub-record-written"}}` plus an ALERT. A partial line is never written. |
| `sink.maxFiles` | 5 (ceiling 100) | Bounded disk: 5 × 64 MiB = 320 MiB. | The oldest file is deleted and a WARN `sink_rotated_out {file, bytes, action:"delete-oldest"}` is logged naming it. |
| headers | Node default 16 KiB | `http.maxHeaderSize`. | Node answers `431` before the handler runs. |
| rejected-body drain | 2 s (`REJECT_DRAIN_MS`) | Lets the client finish its upload and read the 413/503 instead of a TCP reset. Data is discarded, not buffered. | The socket is destroyed. |

**Resolution vs display:** none of these caps feed a decision on partial data. A body over the cap is
rejected, never inspected in part. The inspector always gets the **complete** request and response.

## Failure semantics

| failure | `block` mode | `observe` mode |
|---|---|---|
| inspector throws / rejects / times out / returns a malformed Decision | **fail closed:** `503 inspector_failed`, ALERT `inspector_failed {phase, kind, action:"deny"}`. On the request phase DVAA is not called. | forwarded unchanged, ALERT `inspector_failed {action:"forward"}` |
| inspector says `block` | `403 request_blocked` / `response_blocked` + AIDR alert (disposition `Blocked`) | forwarded unchanged. WARN `would_block`, alert disposition `ReportOnly`, `outcome.wouldBlock:true` |
| capture sink write fails (disk full, permissions) | `503 capture_failed`: no unaudited delivery | delivered. ALERT `sink_write_failed {action:"deliver-unaudited"}` |
| any other route or method | `404 route_not_proxied` (not forwarded, so nothing bypasses inspection) | same |

## Refusal shape (block path)

```json
{
  "error": { "message": "SentinelProxy refused this request: …", "type": "sentinel_refusal", "code": "request_blocked" },
  "sentinel": {
    "requestId": "…", "mode": "block", "phase": "request|response|upstream|proxy", "action": "block",
    "code": "request_blocked|response_blocked|inspector_failed|request_too_large|response_too_large|upstream_timeout|upstream_unreachable|upstream_error|proxy_overloaded|capture_failed",
    "reason": "…", "details": { … },
    "alerts": [ { "AlertId", "DetectName", "Category", "RuleId", "Severity", "SeverityName", "Tactic", "TacticId",
                  "Technique", "TechniqueId", "PatternDispositionDescription", "Timestamp", "SchemaVersion" } ]
  }
}
```

The `error` object follows the OpenAI error shape, so OpenAI-style clients surface it. The refusal carries
only the **classification** fields of each alert (`REFUSAL_ALERT_FIELDS`). The full AIDR alert, with
evidence, entities, taint path and case card, is written to the capture sink. The caller may be the
hijacked agent itself, and echoing evidence back would make the refusal a second exfil channel: the
live test found a URL-encoded honeytoken in `ArgsPreview` that the T4 redactor does not decode.

## Inspector hook (T3 implements this) — `inspector.js`

```js
export default {
  name: 'sentinel-detectors',
  inspectRequest(ctx)  { /* pre-forward  */ return { action: 'block', reason, verdict } | undefined },
  inspectResponse(ctx) { /* post-response */ return { action: 'allow' } | undefined },
};
```

- **`ctx` (request):** `{phase, requestId, sessionId, mode, target, method, path, headers, body: Buffer, text, json, limits}`.
- **`ctx` (response):** the request fields, plus `request:{headers,body,text,json}`,
  `response:{status,headers,body,text,json}`, `dvaa` (the reply's `dvaa{}` block or `null`) and `toolCalls`
  (`choices[0].message.tool_calls`).
- **Decision:** `{action: 'allow'|'block', reason?, ruleId?, verdict?}`. `verdict` is a **sentinel/alerts
  verdict** (`VERDICT_SHAPE` in `sentinel/alerts/schema.js`). The proxy fills in:
  - `disposition`: `block` in block mode, `report` in observe mode, `allow` for an allow decision
  - `detectionLatencyMs`: measured, if absent
  - `entities.agent`: the configured target
  - `entities.session`: `x-sentinel-session-id` header, or the request id

  It then calls `buildAlert()`. If `buildAlert` rejects the verdict, the proxy logs `alert_build_failed`
  and still enforces the decision.
- Default inspector: `NOOP_INSPECTOR` (allow everything).
- Session correlation: clients may send `x-sentinel-session-id`. `x-sentinel-*` headers are stripped
  before forwarding.
- A synchronous infinite loop inside an inspector cannot be pre-empted in-process. Inspectors must bound
  their own work (T3's caps).

## What the proxy can and cannot prevent (DVAA runs tools server-side)

DVAA agents execute their tool calls **inside the agent process, before replying**. For example,
RAGBot's `submit_to_index` performs the HTTP POST and then reports it in `tool_calls` and in
`dvaa{exfilAttempted, exfilExecuted, exfilTargetUrl, exfilResult}`. The live test replays
`captures/variants/fixtures/evasion/eva-pos-middle-001.json` and shows the reply already says
`exfilExecuted:true` by the time the proxy sees it.

- **Request hook = prevention.** A request blocked pre-forward never reaches DVAA, so no tool runs. This
  is the only point where SentinelProxy can *stop* a DVAA-side exfil. It needs a decision from the inbound
  text alone (the user turn, and any RAG or tool content the client embeds in it).
- **Response hook = containment + detection, not prevention.** Blocking the reply keeps the tainted output
  (secrets echoed in content, tool arguments, follow-on instructions) from reaching the client or the next
  agent hop, and raises the alert. But any tool DVAA already executed **has already happened**. The
  refusal says so: `details.upstreamToolCallsAlreadyExecuted: true`.
- **Out of reach:** tool I/O that DVAA performs internally without echoing it in the reply. Anything not
  sent to `/v1/chat/completions` (other routes are refused, not proxied). Clients that talk to DVAA ports
  directly (the proxy only protects traffic routed through it).

## Capture sink format — one JSON line per exchange

`{schema:"sentinel.capture/1.0.0", ts, requestId, sessionId, mode, target, request:{method,path,headers,body},
response:{status,headers,body}|null, inspector:{name,request,response}, outcome:{status,action,code,phase,wouldBlock},
alerts:[full AIDR alerts], events:[loud events], timings:{totalMs,upstreamMs,proxyOverheadMs,inspectRequestMs,inspectResponseMs}}`

- **Bodies:** `{bytes, sha256, encoding:"utf8", text}`, or `encoding:"base64"` when the bytes are not
  valid UTF-8. `decodeBody()` returns the exact wire bytes.
- **Write order:** the record is written synchronously **before** the reply is sent.
- **`proxyOverheadMs`:** `totalMs − upstreamMs`, measured before the sink write.

## Proxy-added latency (measured)

`node sentinel/proxy/bench/latency.js --n 300`: real RAGBot :7005, Node v26.10.0. 300 interleaved
direct/proxied pairs per payload, keep-alive, no-op inspector, sink on.

| payload | direct median / p95 | proxied median / p95 | **proxy-added median / p95** |
|---|---|---|---|
| benign capture (158 B) | 0.284 / 0.401 ms | 0.495 / 0.758 ms | **0.209 / 0.377 ms** |
| T6 corpus, 400 tool rows (79 KB) | 1.415 / 3.972 ms | 2.644 / 4.946 ms | **1.012 / 2.524 ms** |

The in-process overhead (`timings.proxyOverheadMs`, n=640) is a median of 0.193 ms and a p95 of
0.55 ms. That is the proxy's share of the sub-30 ms budget. T3's detectors add their own time on top.

## Tests

```bash
cd sentinel/proxy && node --test "test/*.test.js"     # needs the DVAA fleet; FAILS (never skips) if it is down
```

The live tests talk to the real DVAA fleet:
- every `captures/benign/*` replayed against its own agent port
- the >8KB (≈70 KB) corpus request logged byte-for-byte
- the T6 evasion capture, for the response hook and its real `dvaa{}` block
- request caps: oversize (declared and chunked) and boundary
- the response cap, against a real reply
- the CLI started with flags and env only

Only dependencies are stubbed: a misbehaving inspector, a hanging or closed upstream port, a failing sink.
`test/helpers.js#markerInspector` is a dependency stub standing in for T3, not a mock of the proxy.

## SE gate (`gates/se-gate.md`) — PASS

- [x] Ticket T2, DoD 2 (foundation), deps T1 (merged). File scope `sentinel/proxy/`, `sentinel/config/` is
  disjoint from T3 (`sentinel/detectors/`), T4 (`sentinel/alerts/`, imported read-only), T5 and T6.
- [x] Acceptance is concrete and tested: observe passthrough is byte-identical, full-body capture,
  block-mode refusal, config switching without code edits.
- [x] Real seam: DVAA `POST /v1/chat/completions` on RAGBot :7005, plus every benign-capture agent (7001,
  7002, 7003, 7005, 7014, 7022). Captures come from `captures/benign/`, `captures/variants/corpus/` and
  `captures/variants/fixtures/evasion/eva-pos-middle-001.json`. The verdict follows the
  `sentinel/alerts` `VERDICT_SHAPE`.
- [x] Every assembled or scanned input has a cap: request body, response body, header size, in-flight
  count, sink file and file count, upstream and inspector time. See the Bounds table.
- [x] Overflow is fail-loud with `{size, cap, action}`, never silently truncated. An over-cap body is
  rejected, not head/tail-cut (DVAA's 8KB anti-pattern).
- [x] Each cap documents its value, why, and what happens beyond it (the table above, mirrored in the PR
  "Bounds introduced").
- [x] No decision runs on a capped scan: the inspector gets complete bodies or none. The proxy has no
  display caps.
- [x] Data-rich validation: a ≈70 KB request built from the T6 corpus (22 KB KB doc + 400-row tool output)
  with a marker outside the head/tail 8 KB, the 22 KB evasion fixture, and a 1 MiB+1 oversize body.
