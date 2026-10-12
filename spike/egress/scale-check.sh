#!/usr/bin/env bash
# SPIKE — data-rich bounds check for the inspector (block mode):
#  1. 12 KiB POST body, honeytoken placed AFTER the first 8 KiB  -> must be denied
#  2. 40 KiB URL query (over Node's default 16 KiB header limit)  -> must be seen + denied
#  3. 100 KiB body (> MAX_EGRESS_BYTES 64 KiB)                   -> 413 + ALERT, never forwarded
set -euo pipefail
cd "$(dirname "$0")"
DC=(docker compose -f compose.yml)
rm -rf logs && mkdir -p logs && chmod 777 logs
EGRESS_MODE=block EGRESS_ALLOW=canary "${DC[@]}" up -d --force-recreate >/dev/null 2>&1
sleep 3
# Uses node:http request (absolute-form via env proxy) - the same primitive as
# DVAA's executeSubmitToIndex(). NOTE: global fetch() tunnels via CONNECT even for
# http:// targets, so a fetch-based tool is only visible as host:port (see SPIKE-EGRESS.md).
"${DC[@]}" exec -T dvaa node --input-type=module -e '
  import http from "node:http";
  const pad = n => "x".repeat(n);
  const go = (name, url, body) => new Promise(r => {
    const q = http.request(new URL(url), { method: body ? "POST" : "GET", timeout: 5000 }, res => {
      console.log(name, "->", res.statusCode); res.resume(); res.on("end", r); });
    q.on("error", e => { console.log(name, "-> error", e.code); r(); });
    q.end(body || undefined);
  });
  await go("0 benign-allowlisted", "http://canary:8080/api/x?q=weather", null);
  await go("1 body12k-tail-token", "http://canary:8080/api/x", pad(9000) + " dvaa-admin-secret " + pad(3000));
  await go("2 url40k", "http://canary:8080/api/x?data=" + pad(40000) + "123-45-6789", null);
  await go("3 body100k-overcap", "http://canary:8080/api/x", pad(100000));
  const f = await fetch("http://canary:8080/api/x?via=fetch"); console.log("4 fetch-benign ->", f.status);
'
sleep 1
echo "--- inspector ---"; cut -c1-260 logs/egress.jsonl | grep -v api.oa2a.org
echo "--- canary ---"; "${DC[@]}" logs --no-log-prefix canary | grep CANARY_HIT || echo "(no canary hits)"
cp logs/egress.jsonl evidence-scale.jsonl
"${DC[@]}" down -v >/dev/null 2>&1
