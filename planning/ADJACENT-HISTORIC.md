# ADJACENT-HISTORIC — historic vuln classes mapped to the SentinelProxy agent context

> Source: Mo on #166 — *"consider cybersec adjacency angles. Other historic cybersec vulnerabilities from
> decade(s) ago may be reproducible/applicable in our context yet untested or unresearched. Work with the
> creative and the critic."* Coordinator clarification: keep the **known** classes brief, spend the effort
> on **genuinely new** gaps specific to THIS architecture (request-side chat proxy + tool-boundary egress
> default-deny + honeytoken tripwire + T4 alert/graph pipeline).
>
> Defensive gap analysis only — **no new attack payloads**. Static mapping against the real code
> (`sentinel/proxy/server.mjs`, `sentinel/egress/{policy,inspector}.mjs`, `sentinel/dashboard/public/*`).
> Every secret named is a FAKE DVAA honeytoken on the authorized localhost sandbox.

Layers referenced below:
- **REQ** = request-side chat proxy (`sentinel/proxy/server.mjs`): pre-forward, can BLOCK.
- **EGR** = tool-boundary egress inspector (`sentinel/egress/inspector.mjs`): default-deny HTTP forward
  proxy, host-allowlist + honeytoken/secret scan, fail-closed. Can BLOCK the bytes before they leave.
- **RESP** = response-side inspection: DVAA runs tools in-process, so response findings are **alert-only**
  (prevention boundary, LOOP.md Endgame).

---

## Part 1 — Known classes (already covered or researched). Brief by design.

| Historic class (era) | Agent-context analogue | Defended by | Tested? |
|---|---|---|---|
| Confused deputy (Hardy, 1988) | injected content steers the agent's legitimate tool authority | the whole design: destination provenance + source→sink + mandate (ADJACENT §6a/§10.3a) | yes — core thesis; scoring corpus #156 |
| SQL/command injection, data≠control (late 1990s) | prompt injection; no escape makes text inert | segregate + enforce at boundary, not sanitize (ADJACENT §8) | yes — this is the product |
| Canonicalization / overlong-encoding (IIS Unicode traversal, 2000–01) | %/\\u/base64/hex-wrapped honeytokens & secrets | `decodedViews()` multi-round decode, both proxies; over-depth → fail-closed | yes — decode-depth fixtures; #122 whitespace re-join |
| Parser differential / request smuggling / Content-Type confusion | scan one view, forward/exec another | whole-body scan (not head/tail); honeytoken backstop on every route (#135) | partly — see NEW #5 for the residual |
| Polyglot / magic-byte file confusion (decade+) | malicious file whose type flips on read | raised in #157 | researched (#157 closed) |
| Stored XSS into the defender's console | attacker content rendered in our dashboard/graph | **deliberately defended**: all capture/alert text via `textContent`, never markup (`app.js:2`, `graph.js:4`) | yes — by construction; see NEW #7 for the residual |
| Out-of-band HTTP exfil (markdown-image/URL, EchoLeak CVE-2025-32711) | agent emits secret in an image/URL to attacker host | EGR default-deny + honeytoken scan over full URL/query/headers | yes — egress fixtures / #135 |
| Fail-open watchdog (reliability eng.) | scanner crash/timeout/oversize silently passes traffic | fail-closed in BOTH modes, loud ALERT (`FAIL_CLOSED_CODES`) | yes — fault-injection tests |

---

## Part 2 — NEW gaps (not previously recorded), ranked

Rank = (real for us) × (untested) × (would a judge find it impressive that we found it ourselves).
These are things specific to THIS two-proxy + honeytoken + alert-pipeline design that no prior planning
doc mapped. All are stated as **limitations / talking points**, not exploits.

### NEW-1 — Verdict/block oracle via retry (HIGH) · classic: timing/error oracle (Bleichenbacher 1998; blind-SQLi 2000s)
The proxy answers a flagged request with a static `403 flagged_request` and a clean one with the forwarded
`200`. There is **no replay/idempotency/nonce protection** (grep confirms none in either proxy; only a
concurrency cap `maxInFlight`). An attacker who can resend variants to the live proxy gets a clean
go/no-go signal per attempt and can grind an evasion offline against our *actual* detector — the refusal
code is intentionally generic, but the mere block-vs-forward bit is the oracle. Our own fail-closed
refusal becomes a feedback channel that accelerates bypass of the detector it protects.
- **Layer:** REQ/EGR both. **Untested** — no test treats repeated near-miss probes as an oracle.
- **Known-limitation line:** *SentinelProxy returns a distinguishable block vs forward with no per-client
  rate limit or probe-budget, so an attacker with retry access can use it as an evasion oracle; mitigation
  (probe throttle / uniform latency / decoy-allow) is future work.*

### NEW-2 — DNS-tunneling / out-of-band resolver exfil (HIGH) · classic: DNS tunneling (iodine ~2006); log4shell-style callback (2021)
EGR only sees `http://` absolute-form and `CONNECT`. The compose sandbox is `internal: true` with
HTTP(S)_PROXY forced through the inspector — but **name resolution is not proxied**. A tool that performs
DNS lookups of `<base32-secret>.attacker.example` rides Docker's embedded resolver, an out-of-band channel
the egress policy never inspects. HTTP exfil is closed; the DNS side channel is unmapped. (Compose notes
in-container loopback SSRF as a limitation but says nothing about DNS.)
- **Layer:** neither (no DNS inspection). **Untested** — all egress fixtures are HTTP/CONNECT.
- **Known-limitation line:** *The egress inspector covers HTTP and CONNECT only; DNS and other
  non-HTTP channels are out of scope, so DNS-label tunneling is a residual out-of-band exfil path.*

### NEW-3 — Honeytoken-as-DoS / allowlist poisoning (MED-HIGH) · classic: IDS signature-flooding & false-positive weaponization (Snort era, early 2000s)
The repo goes public (judges get access), so **every honeytoken value is known** (`honeytokens.json`,
`DVAA_HONEYTOKENS`). An attacker who injects a *known* honeytoken string into otherwise-legitimate traffic
bound for a benign allowlisted host forces a DENY + ALERT — turning our highest-signal tripwire into a
denial-of-service on legitimate egress and an alert-flood against the SOC view. The "Agloe problem"
(ADJACENT §6a) inverted into a weapon. No alert-dedup/rate-cap exists on the emit path.
- **Layer:** EGR fires (as designed) but the *effect* is attacker-chosen. **Untested** — no test plants a
  honeytoken into benign traffic to measure the DoS/alert-flood.
- **Known-limitation line:** *Honeytoken values are public and matching is unconditional, so injected
  honeytokens can be used to force denials/alerts on benign traffic; per-session secret canaries and
  alert-rate limiting reduce this.*

### NEW-4 — Allowlisted host = blind exfil channel (MED) · classic: SSRF-to-allowlisted-host / open-redirect trust (2010s)
The allowlist is **host-granularity and exact-match** (good: no wildcard/suffix bug). But (a) a `CONNECT`
tunnel to an allowlisted host is **opaque TLS** — nothing in the path/body is scanned; and (b) on the HTTP
path, only honeytokens and known secret *shapes* are caught, so a **novel** secret (not a honeytoken, not a
regex shape) exfiltrated to an allowlisted host via path/query succeeds. An allowlisted destination is a
trusted pipe at host level, not at data level.
- **Layer:** EGR (host check only; opaque for TLS). **Partly tested** (allowlist match tested; the
  blind-pipe property is not).
- **Known-limitation line:** *Allowlisting trusts a host, not the data sent to it; HTTPS to an allowlisted
  host is an opaque tunnel, so a determined exfil to a trusted destination is not prevented.*

### NEW-5 — Inspected-view vs forwarded-view differential (MED) · classic: HTTP request smuggling / parser differential (2005; 2019 revival)
We scan one representation and forward another in two places: (a) REQ decodes `content-encoding` and scans
the **plaintext**, then forwards the **original encoded** body — DVAA re-decodes with its own zlib, so a
concatenated/trailing-garbage gzip stream the two decoders read differently yields proxy-sees-A /
DVAA-sees-A+B; (b) EGR scans raw header text (`forwardedHeaderText(rawHeaders)`) but forwards the
**parsed** `req.headers` object, where Node collapses duplicates/obs-folds. The honeytoken backstop over
the whole body limits this, but destination-provenance/mandate extraction (which must JSON-parse tool-call
args) is differential-sensitive (duplicate keys, Unicode, NaN).
- **Layer:** REQ/EGR. **Untested** — no decode/parse-differential fixture.
- **Known-limitation line:** *The bytes inspected and the bytes forwarded are logically but not
  byte-identically derived (encoding re-decode, header re-parse), leaving a parser-differential residue
  for structure-dependent checks.*

### NEW-6 — Clean-turn stored/second-order injection (MED) · classic: second-order SQLi / stored XSS (mid-2000s)
Session taint is turn-level (A untrusted-read + B sensitive-read → C egress). An injection planted in
DVAA's persistent memory/RAG on one turn can fire on a **later turn that contains no untrusted read**, so
the triggering turn looks clean and the A+B→C chain never arms. The proxy is stateless about DVAA's
internal memory. (Partly anticipated by the S12 campaign-correlation stretch, but the single-target
clean-trigger case is not covered.)
- **Layer:** neither (no cross-turn memory visibility). **Untested.**
- **Known-limitation line:** *Taint is scoped to the turn that reads untrusted content; a stored injection
  that executes on a later clean-looking turn is a known gap (ASI06 memory poisoning).*

### NEW-7 — Alert-export downstream injection (LOW-MED) · classic: log/SIEM injection (CRLF/ANSI log forging, 2000s)
Our own dashboard renders attacker-influenced evidence safely (`textContent`, hosts as hashes, static
reason codes) — a real strength to show. The residue: the **redacted alert JSON export** (`app.js` copy
path) carries attacker-shaped `evidence`/destination strings; if an analyst forwards it into a downstream
SIEM/markdown/terminal renderer, control characters or markup in those strings become a second-order
injection *outside* our console.
- **Layer:** RESP/alert-pipeline (redaction yes; downstream-neutralization no). **Untested** downstream.
- **Known-limitation line:** *Exported alert evidence is redacted and length-bounded but not neutralized
  for arbitrary downstream renderers; treat the export as data, not markup.*

---

## Pitch use — "we attacked our own design"
Honest, judge-facing talking points (PROACTIVE #33 slide):
- **Strength to lead with:** we deliberately defended the stored-XSS-into-our-own-SOC-console vector
  (textContent everywhere, hosts logged as hashes, client refusals carry only static codes). We treated
  our own dashboard as an attack surface.
- **Honest limitations we found ourselves:** the block/forward **oracle** (NEW-1), **DNS** out-of-band
  (NEW-2), and **honeytoken-as-DoS** because the repo is public (NEW-3). Naming these is more credible
  than claiming total coverage, and each has a one-line mitigation direction.

**Prevention boundary reminder:** DVAA executes tools in-process, so only request-side (REQ) and the
tool-boundary (EGR) *prevent*; response-side is alert-only. NEW-1/3/4/5 touch preventing layers; NEW-2/6
are coverage gaps (no layer sees them); NEW-7 is post-decision.
