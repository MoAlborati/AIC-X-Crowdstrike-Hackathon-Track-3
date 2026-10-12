# Tourniquet — reverse proxy (T2)

A reverse proxy in front of a DVAA agent's OpenAI-compatible HTTP API (DVAA is the organizer-provided,
intentionally vulnerable sandbox on `127.0.0.1`). It logs every exchange in full, runs the inspector set
**before forwarding** and **after the reply**, and in `block` mode turns a flagged verdict into a
structured refusal. Zero dependencies, ESM (`.mjs`), Node ≥ 24 (≥ 22 runs with a warning in `scripts/eval.sh`).

This is the canonical proxy (PR #14, issue #37). The PR #21 `.js` proxy was retired. Its live-DVAA
replay tests, CLI flags, config checks and inspector isolation were ported here (see "Ported from #21").

```
client ─▶ admission (maxInFlight, clientTimeoutMs) ─▶ read body (cap) ─▶ decode content-encoding (cap)
       ─▶ request inspectors (deadline) ─▶ write-ahead capture ─▶ forward (timeout, response cap)
       ─▶ decode ─▶ response inspectors (deadline) ─▶ capture ─▶ reply
```

## Run

```bash
scripts/eval.sh up                                             # DVAA fleet (docker project dvaa-t1)
node sentinel/proxy/cli.mjs                                    # sentinel/config/sentinel.config.json → :8080 → RAGBot :7005, observe
node sentinel/proxy/cli.mjs --mode block --target-port 7014    # same file, different agent + mode, no code edits
SENTINEL_MODE=block SENTINEL_TARGET_PORT=7022 node sentinel/proxy/cli.mjs
node sentinel/proxy/cli.mjs --inspector ./my-inspector.mjs     # extra inspector, runs AFTER the shipped set

curl -s localhost:8080/v1/chat/completions -H 'content-type: application/json' \
  --data-binary @captures/benign/7005_ragbot.req.json
```

The first stdout line is machine-readable:
`{"event":"listening","host","port","mode","target","inspectors":["substring","sentinel-t3",...],"capture","overrides"}`.
A bad config exits with code 2 and lists **every** problem at once (`ConfigError.issues`).

## Config — `sentinel/config/sentinel.config.json` (loader: `sentinel/config/load.mjs`)

Precedence: **CLI flag > env > file**. `--config <file>` / `SENTINEL_CONFIG` picks the file. Unknown
keys are errors (typo guard). Keys starting with `_` are comments. A relative `capture.path` resolves
against the repo root, whatever the cwd. Listen and target hosts must be loopback; there is no opt-out.

| field | env | flag | shipped value | hard ceiling |
|---|---|---|---|---|
| `listen.host` / `listen.port` | `SENTINEL_LISTEN_HOST` / `_PORT` | `--listen-host` / `--listen-port` | `127.0.0.1` / `8080` (`0` = ephemeral) | loopback only |
| `target.host` / `target.port` | `SENTINEL_TARGET_HOST` / `_PORT` | `--target-host` / `--target-port` | `127.0.0.1` / `7005` | loopback only |
| `mode` | `SENTINEL_MODE` | `--mode` | `observe` (`observe` \| `block`) | |
| `limits.maxRequestBytes` | `SENTINEL_MAX_REQUEST_BYTES` | `--max-request-bytes` | 1 MiB | 16 MiB |
| `limits.maxResponseBytes` | `SENTINEL_MAX_RESPONSE_BYTES` | `--max-response-bytes` | 8 MiB | 64 MiB |
| `limits.upstreamTimeoutMs` | `SENTINEL_UPSTREAM_TIMEOUT_MS` | `--upstream-timeout-ms` | 30000 | 120000 |
| `limits.inspectorTimeoutMs` | `SENTINEL_INSPECTOR_TIMEOUT_MS` | `--inspector-timeout-ms` | 5000 | 10000 |
| `limits.clientTimeoutMs` | `SENTINEL_CLIENT_TIMEOUT_MS` | `--client-timeout-ms` | 30000 | 300000 |
| `limits.maxInFlight` | `SENTINEL_MAX_IN_FLIGHT` | `--max-in-flight` | 64 | 1024 |
| `capture.path` | `SENTINEL_CAPTURE_PATH` | `--capture-path` | `sentinel/proxy/logs/proxy-capture.jsonl` (gitignored, 0600) | |
| `capture.maxFileBytes` | `SENTINEL_CAPTURE_MAX_FILE_BYTES` | `--capture-max-file-bytes` | 512 MiB | 1 GiB |
| `inspect.flagSubstrings` | | | `[]` | |

## Bounds and failure modes

Nothing is silently truncated. Every overflow is refused and ALERTed (stderr + capture JSONL).

| bound | beyond it |
|---|---|
| `maxRequestBytes` | `413 request_too_large`, never forwarded, ALERT `{payload_size, cap, action}`. Declared `Content-Length` over the cap with `Expect: 100-continue` is refused before upload. An over-cap upload is drained (not buffered) up to `DRAIN_LIMIT_BYTES` (16 MiB) so the client reads the 413, then the socket is closed. |
| `maxResponseBytes` | `502 response_too_large`, upstream aborted, the reply is never returned uninspected. |
| decoded size (gzip/deflate/br) | Bounded by the same caps (zip-bomb safe). Over the cap: 413/502. More than `MAX_ENCODING_LAYERS` (4), unknown or corrupt codings: block mode refuses (`uninspectable_encoding`), observe forwards + ALERT. |
| binary request body (#157) | A request body that is not valid UTF-8 after content-decoding (octet-stream, binary multipart, unknown binary types): block mode refuses 415 `uninspectable_content` before forwarding; observe forwards + ALERT. Text bodies of any content-type are inspected as before. Responses are unchanged (alert-only boundary). |
| `inspectorTimeoutMs` | block: `503 inspector_timeout` (fail closed); observe: forwarded + ALERT. |
| `upstreamTimeoutMs` | `504 upstream_timeout`; a closed port gives `502 upstream_unreachable`. |
| `clientTimeoutMs` | Slow-drip clients get `408 client_timeout` + ALERT, never forwarded. |
| `maxInFlight` | `503 overloaded` + ALERT, body discarded unread. Open sockets are capped at `4 × maxInFlight` (each drop ALERTed). |
| `capture.maxFileBytes` | The sink refuses the write (`CaptureFullError`) → `503 capture_unavailable`. Nothing is forwarded without a write-ahead record, and nothing is returned unlogged. There is no rotation: evidence is never deleted to make room. |

## Failure semantics

| failure | `block` mode | `observe` mode |
|---|---|---|
| inspector throws / malformed verdict / deadline | `503 inspector_error` / `inspector_timeout` (fail closed) | forwarded unchanged + ALERT |
| verdict flagged | `403 flagged_request` (DVAA never called) / `403 flagged_response` | forwarded unchanged + would-block ALERT |
| verdict `alert:true` or disposition `report` (not flagged) | ALERT `detector_alert`, never refused | same |
| capture write fails | `503 capture_unavailable` | `503 capture_unavailable` (no unaudited side effect) |

Every path is passed to every inspector and forwarded; there is no route allow-list. Depth differs by route: T3 parses
only `/v1/chat/completions` and `/chat/completions`. Every other route (DVAA `POST /chat`, A2A `/a2a/message`, MCP)
gets the honeytoken backstops only: exact canary values in body, headers and URL in both phases, plus percent/hex/base64
canaries in non-chat POST bodies (#126).

## Refusal shape

```json
{ "error": { "type": "sentinel_blocked", "code": "flagged_request", "message": "Tourniquet refused this request: flagged_request" },
  "sentinel": { "request_id": "…", "blocked": true, "mode": "block", "phase": "request|response|forward|capture|proxy",
                "reason": "<REFUSAL_CODES>", "verdict_count": 1, "detail": { "payload_size": 0, "cap": 0, "upstream_tool_calls_already_executed": true } } }
```

The refusal carries only static codes (`REFUSAL_CODES`), the request id and numeric/boolean details.
Verdict content, detector reasons and error text go to the log only. The caller may be the hijacked
agent, and echoing evidence back would make the refusal a second exfil channel.

## Inspector hook — `inspectors.mjs`

`async inspector({ phase, method, path, headers, body, rawBody, contentEncoding, requestId, status?, signal }) → verdict | null`

- `body` is the FULL decoded body; `rawBody` the wire bytes. Both, and `headers`, are **copies**: an
  inspector that mutates them cannot change what is forwarded, returned or captured.
- Verdict: `{flagged: boolean}` and/or `{disposition}` (T4 `DISPOSITIONS`, case-insensitive). Optional
  `alert: true` logs evidence without refusing. Anything else is malformed and fails closed in block mode.
- Shipped set (`default-inspectors.mjs`): T2 substring inspector (body, URL in every decoded spelling,
  headers) + T3 `sentinelInspector`. Verdicts and alerts are redacted (honeytokens) before logging.

## What the proxy can and cannot prevent (DVAA runs tools server-side)

DVAA agents execute tool calls **inside the agent process, before replying**. The live replay test
(`test/live-replay.test.mjs`) sends `captures/variants/fixtures/evasion/eva-pos-middle-001.json` as the user
turn (`dvaaUserTurnRequest`, #30) and the reply already says `exfilAttempted:true` when the proxy sees it.

- **Request hook = prevention.** A request blocked pre-forward never reaches DVAA, so no tool runs. The
  same live test shows real T3 refusing that request in block mode with no write-ahead record.
- **Response hook = containment + detection.** Blocking the reply keeps tainted output from the client,
  but the tool already ran. The refusal says so: `detail.upstream_tool_calls_already_executed: true`.
- **Out of reach:** tool I/O DVAA performs without echoing it, and clients that bypass the proxy. The
  egress guard (`sentinel/egress`, T12) covers the tool boundary.

## Capture format — one JSON line per record (`capture-sink.mjs`, 0600)

- `type:"request"`: write-ahead record, on disk before the upstream sees the request.
- `type:"exchange"`: `{request_id, mode, target, request:{method,path,headers,body,decoded_body?}, response:{status,headers,body}, upstream_response?, verdicts, action, latency_ms, timings:{total_ms, upstream_ms, proxy_overhead_ms}}`.
- `type:"alert"`: redacted alert records.
- Bodies: `{encoding:"utf8"|"base64", bytes, sha256, data}`. `decodeBody()` (server.mjs) returns the exact wire bytes.

## Proxy-added latency (measured)

`node sentinel/proxy/bench/latency.mjs --n 100`: real RAGBot :7005, Node v22.22.3, shipped inspector set
(substring + T3), 100 interleaved direct/proxied pairs per payload, keep-alive.

| payload | **proxy-added median / p95** |
|---|---|
| benign capture (158 B) | **1.28 / 1.69 ms** |
| T6 corpus, 400 tool rows (79 KB) | **5.86 / 7.45 ms** |

In-process overhead (`timings.proxy_overhead_ms`, n=240): median 2.93 ms, p95 4.95 ms, including T3 detection.

## Tests

```bash
cd sentinel/proxy && node --test "test/*.test.mjs"
SENTINEL_REQUIRE_DVAA=1 node --test "test/*.test.mjs"   # what scripts/eval.sh sets when the fleet is up
```

Live seams (`live-replay.test.mjs`, `live-dvaa.test.mjs`, `latency-live.test.mjs`) talk to the real DVAA
fleet. With `SENTINEL_REQUIRE_DVAA=1` a down agent is a FAILURE, otherwise a loud SKIP. They cover:
every `captures/benign/*` replayed against its own agent port, the 70 KB corpus logged byte-for-byte, a
non-UTF-8 body, the T6 evasion replay in observe and block mode, the response hook on DVAA's real
`dvaa{}` block, the request-cap boundary, the response cap on a real reply, and the CLI started with
flags + env only. Other suites use a real local HTTP upstream; only dependencies are stubbed.

## Ported from #21 (issue #37)

Ported: CLI flags for every config field (CLI > env > file, `source.overrides`), `--inspector`, all
config issues reported at once, unknown-key rejection, hard ceilings, inspector isolation (copies),
`sha256` per captured body + `decodeBody()`, `timings`, `upstream_tool_calls_already_executed`, the live
DVAA replay suite (`dvaaUserTurnRequest`), and the live latency bench.

Not ported (weaker than, or in conflict with, the `.mjs` design): `/sentinel/health` and the
`/v1/chat/completions` route allow-list (`.mjs` inspects every path), alert classification fields in the
refusal body (`.mjs` returns static codes only), size-based sink rotation that deletes the oldest
capture file (`.mjs` refuses loudly at the cap instead), the no-op default inspector (`.mjs` ships
T2 + T3), `target.name`, and `x-sentinel-session-id` stripping.
