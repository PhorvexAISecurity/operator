#!/usr/bin/env bash
# batchp.sh — pod-level battery from a "compromised" voice-bot (exec = the foothold):
#   GP8 environment mapping, GP6 lateral movement, GP7 C2 beacon + Phorvex reaction.
# Secrets discipline: env VALUES are masked (names + lengths only).
set -uo pipefail
NSV=voice; NSX=phorvex-system; CTRL=phorvex-phorvex
OUT=/tmp/px-batchp; mkdir -p "$OUT"
BOT=$(kubectl get pods -n $NSV -o jsonpath='{.items[0].metadata.name}')
echo "compromised pod: $BOT" | tee "$OUT/target.txt"

echo; echo "=== GP8: environment mapping (as the attacker sees it) ==="
kubectl exec -n $NSV $BOT -- python3 -c "
import os, socket, pathlib
print('-- env var NAMES (values masked: name[len]) --')
for k in sorted(os.environ):
    v = os.environ[k]
    print(f'   {k}[{len(v)}]' if any(s in k for s in (\"KEY\",\"TOKEN\",\"SECRET\",\"URI\",\"PASS\")) else f'   {k}={v[:60]}')
print('-- service account token mounted:', pathlib.Path(\"/var/run/secrets/kubernetes.io/serviceaccount/token\").exists())
print('-- resolv.conf:', pathlib.Path(\"/etc/resolv.conf\").read_text().splitlines()[:2])
" | tee "$OUT/gp8.txt"

echo; echo "=== GP6: lateral reachability from the foothold ==="
kubectl exec -n $NSV $BOT -- python3 -c "
import socket, urllib.request
targets = [
  ('chroma  http ', 'http://chroma.document-store.svc.cluster.local:8000/api/v2/heartbeat'),
  ('litellm http ', 'http://litellm.litellm.svc.cluster.local:4000/health/readiness'),
  ('mcp     http ', 'http://mcp-server.mcp.svc.cluster.local:8000/'),
  ('crm     http ', 'http://crm.crm.svc.cluster.local:80/'),
]
for name, url in targets:
    try:
        r = urllib.request.urlopen(url, timeout=4); print(f'   {name} REACHABLE http {r.status}')
    except Exception as e: print(f'   {name} {type(e).__name__}: {str(e)[:60]}')
try:
    s = socket.create_connection(('mongo.document-store.svc.cluster.local', 27017), timeout=4)
    print('   mongo  wire   REACHABLE tcp/27017'); s.close()
except Exception as e: print('   mongo ', e)
" | tee "$OUT/gp6.txt"

echo; echo "=== GP7: C2 beacon — bot dials out to attacker listener, then Phorvex reacts ==="
nc -l -p 28001 -k > "$OUT/gp7-beacon.txt" 2>/dev/null &
NC=$!
sleep 1
kubectl exec -n $NSV $BOT -- python3 -c "
import socket, time
s = socket.create_connection(('172.27.11.153', 28001), timeout=8)
for i in range(24):
    s.sendall(b'beacon-alive seq=%d\n' % i); time.sleep(5)
" &
BEACON=$!
sleep 7
echo "-- listener saw (first lines):"; head -3 "$OUT/gp7-beacon.txt"
echo "-- firing redteam SecurityEvent at the beaconing pod (the detector noticing the C2) --"
T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
kubectl apply -f - <<EOF
apiVersion: amtd.r6security.com/v1beta1
kind: SecurityEvent
metadata:
  name: gp7-c2-beacon
spec:
  rule:
    type: CommandAndControl
    threatLevel: critical
    source: redteam
  targets:
    - $NSV/$BOT
  description: "GP7: long-lived outbound C2 beacon from the bot pod"
  anomalyScore: "0.97"
EOF
: > "$OUT/gp7-decision.txt"
for i in $(seq 1 12); do
  sleep 5
  kubectl logs -n $NSX deploy/$CTRL --since-time="$T0" 2>/dev/null | grep -i "$BOT" | grep -iE "decision|rotate" | tail -2 > "$OUT/gp7-decision.txt" || true
  [ -s "$OUT/gp7-decision.txt" ] && { cat "$OUT/gp7-decision.txt"; break; }
  echo "  ...waiting ($i)"
done
echo "-- beacon after rotate (connection should be dead — pod killed):"
wait $BEACON 2>/dev/null; echo "   beacon sender exited rc=$? (killed with the pod)"
tail -2 "$OUT/gp7-beacon.txt"
echo "-- attacker simply re-dials from a re-entered foothold (BOUND: motion kills the session, not the reachability):"
kubectl exec -n $NSV $(kubectl get pods -n $NSV -o jsonpath='{.items[0].metadata.name}') -- python3 -c "
import socket
s = socket.create_connection(('172.27.11.153', 28001), timeout=8)
s.sendall(b'beacon-reestablished post-rotate\n'); print('   reconnected from a bot pod — Service-DNS/egress unchanged')
" 2>/dev/null || echo "   (exec raced the rollout — reachability itself is unchanged by design)"
tail -1 "$OUT/gp7-beacon.txt"
kill $NC 2>/dev/null
kubectl delete securityevent gp7-c2-beacon --ignore-not-found
kubectl get pods -n $NSV | tee "$OUT/pods-after.txt"
echo done
