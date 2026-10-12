# SentinelProxy architecture

This page covers the data flow, the components, and where each one prevents an attack versus only
detecting it. Start with the [README](../README.md).

## Data flow

```
                         request-side (prevents)                     tool boundary (prevents)
 agent client ──chat──▶ [ sentinel/proxy  + T3 detectors ] ──▶ DVAA agent ──tool call──▶ [ sentinel/egress (T12) ] ──▶ allowlisted hosts only
      ▲                        │  ▲                               │                               │
      └──────── response ──────┘  └──── response (alert-only) ────┘                               │
                               │ verdict                                                          │ verdict
                               ▼                                                                  ▼
                        [ T4 alerts: ATLAS + OWASP mapping, redaction ] ──▶ [ T10 pipeline ] ──▶ [ T5 dashboard ]

 T1 captures + T6 corpus ──▶ [ T7 scoring: detection and prevention lenses, vs the DVAA baseline ] ──▶ RESULTS.md
```

## Components

| Ticket | Path | Role | Fails how |
|---|---|---|---|
| T2 | `sentinel/proxy` | Reverse proxy for `/v1/chat/completions`, observe or block mode, full-body capture | Over-cap → 413 + ALERT in both modes; inspector failure → 503 fail-closed in block mode, forward + ALERT in observe mode |
| T3 | `sentinel/detectors` | Pure detector library: bounds, honeytoken, taint, egress shapes, mandate/destination provenance, velocity | Any exception, timeout or full registry → BLOCK + ALERT |
| T12 | `sentinel/egress` (PR #45) | Forward proxy on an internal Docker network, reuses T3 matchers, exact-host allowlist | Oversize, decode depth, scan timeout → deny + ALERT, in observe mode too |
| T4 | `sentinel/alerts` | Falcon/AIDR-shaped alert schema, MITRE ATLAS + OWASP LLM / Agentic mapping, secret redaction | Oversize strings are withheld whole, never passed through partly scanned |
| T10 | `sentinel/pipeline` | Turns proxy verdicts into T4 alerts and writes them to the dashboard sink | Display caps only (never change a verdict); overflow rotates to a new part or raises `PipelineBoundError`, never drops |
| T5 | `sentinel/dashboard` | Deterministic replay, incident graph, alert feed on `127.0.0.1:9100` | Loopback only, DNS-rebinding guarded |
| T7 | `sentinel/scoring` | Precision, recall, benign FP rate, latency and override rate for each detector | Missing detector → reported as unavailable, never scored as zero |
| T8 | `captures/contrast` | Same attack against vulnerable DVAA, AIM-defended DVAA, and DVAA behind SentinelProxy | Every cell is checked against ground truth |

## Where prevention happens

- **Before the request is forwarded.** Taint and destination-provenance checks, together with honeytoken
  matches in the request, block the turn, so the model never sees a request that would complete the
  exfiltration.
- **At egress.** The agent decides some actions in-process (for example, a poisoned repo file read by
  RepoBot). The chat proxy can only raise an alert for those. The egress guard denies the outbound call
  itself. Its ground truth is what the attacker server received, not DVAA's own `exfilExecuted` flag.
- **Response side.** This is alert-only, because DVAA executes tools inside the agent process.

## Bounds

Every cap fails loud: payload size, decode depth, scan budget and redaction scan size all end in a
reject, deny or withhold plus an ALERT. Storage caps rotate instead of dropping. Nothing is silently
truncated, and no cap makes a decision on partial data. Each PR lists its bounds and failure modes, and
[`EVAL.md`](../EVAL.md) shows how to run the suites that check them.
