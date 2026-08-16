#!/usr/bin/env bash
# gp7final.sh — listener runs in the EXISTING mcp-server pod (python already there, Ready).
set -uo pipefail
NSV=voice; NSX=phorvex-system; CTRL=phorvex-phorvex
OUT=/tmp/px-gp7f; mkdir -p "$OUT"
MCP=$(kubectl get pods -n mcp -o jsonpath='{.items[0].metadata.name}')
MCPIP=$(kubectl get pod -n mcp $MCP -o jsonpath='{.status.podIP}')
echo "attacker listener: $MCP ($MCPIP:9099)"

kubectl exec -n mcp $MCP -- sh -c 'nohup python3 -c "
import socket, threading, time
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((\"0.0.0.0\", 9099)); srv.listen(4)
def h(c, a):
    while True:
        try: d = c.recv(256)
        except Exception: break
        if not d: break
        print(time.strftime(\"%H:%M:%S\"), a, d.decode().strip(), flush=True)
    print(time.strftime(\"%H:%M:%S\"), a, \"CLOSED\", flush=True)
while True:
    c, a = srv.accept()
    print(time.strftime(\"%H:%M:%S\"), a, \"CONNECTED\", flush=True)
    threading.Thread(target=h, args=(c, a), daemon=True).start()
" > /tmp/listener.log 2>&1 & sleep 1; echo started'
BOT=$(kubectl get pods -n $NSV --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
echo "beacon source: $BOT"
kubectl exec -n $NSV $BOT -- python3 -c "
import socket, time
s = socket.create_connection(('$MCPIP', 9099), timeout=8)
for i in range(60):
    try: s.sendall(b'beacon seq=%d\n' % i)
    except Exception: print('beacon died', flush=True); break
    time.sleep(2)
" &
sleep 6
echo "-- listener before event:"; kubectl exec -n mcp $MCP -- tail -3 /tmp/listener.log | tee "$OUT/before.txt"

T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
kubectl apply -f - <<EOF
apiVersion: amtd.r6security.com/v1beta1
kind: SecurityEvent
metadata:
  name: gp7-c2-final
spec:
  rule:
    type: CommandAndControl
    threatLevel: critical
    source: redteam
  targets:
    - $NSV/$BOT
  description: "GP7 final: live beacon bytes flowing; detector fires; rotate must kill the session"
  anomalyScore: "0.97"
EOF
for i in $(seq 1 15); do
  sleep 5
  D=$(kubectl logs -n $NSX deploy/$CTRL --since-time="$T0" 2>/dev/null | grep "$BOT" | grep -i rotate | tail -1)
  [ -n "$D" ] && { echo "$D" | grep -oE '\"action\":\"[a-z-]+\"|\"net\":[0-9.]+|\"why\":\"[^\"]*' | head -3; break; }
  echo "  ...waiting ($i)"
done
sleep 8
echo "-- listener after rotate (expect CLOSED):"; kubectl exec -n mcp $MCP -- tail -3 /tmp/listener.log | tee "$OUT/after.txt"
kubectl delete securityevent gp7-c2-final --ignore-not-found

echo "-- re-dial after replacement Ready:"
kubectl wait -n $NSV --for=condition=Ready pod -l app=voice-bot --timeout=180s >/dev/null 2>&1
NEWBOT=$(kubectl get pods -n $NSV --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n $NSV $NEWBOT -- python3 -c "
import socket; s = socket.create_connection(('$MCPIP', 9099), timeout=8)
s.sendall(b'beacon RE-ESTABLISHED post-rotate\n'); print('re-dialed OK from', socket.gethostname())"
sleep 1; kubectl exec -n mcp $MCP -- tail -2 /tmp/listener.log | tee "$OUT/redial.txt"

kubectl exec -n mcp $MCP -- sh -c 'pkill -f "9099" 2>/dev/null; rm -f /tmp/listener.log' 2>/dev/null || true
kubectl get pods -n $NSV | tee "$OUT/pods-after.txt"
echo done
