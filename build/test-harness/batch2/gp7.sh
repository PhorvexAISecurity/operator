#!/usr/bin/env bash
# gp7.sh — GP7 redo with a proper python listener: beacon lives, rotate kills it, re-dial proves BOUND.
set -uo pipefail
NSV=voice; NSX=phorvex-system; CTRL=phorvex-phorvex
OUT=/tmp/px-gp7; mkdir -p "$OUT"

python3 - >"$OUT/listener.log" 2>&1 <<'PY' &
import socket, threading, time, sys
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", 28001)); srv.listen(4)
print("listening on 28001", flush=True)
def h(c, a):
    with c:
        while True:
            try: d = c.recv(256)
            except Exception: break
            if not d: break
            print(f"{time.strftime('%H:%M:%S')} {a} {d.decode().strip()}", flush=True)
    print(f"{time.strftime('%H:%M:%S')} {a} CLOSED", flush=True)
while True:
    c, a = srv.accept()
    print(f"{time.strftime('%H:%M:%S')} {a} CONNECTED", flush=True)
    threading.Thread(target=h, args=(c, a), daemon=True).start()
PY
LP=$!; sleep 1
grep -q listening "$OUT/listener.log" && echo "[listener up]" || { echo "listener failed"; cat "$OUT/listener.log"; exit 1; }

BOT=$(kubectl get pods -n $NSV -o jsonpath='{.items[?(@.status.phase=="Running")].metadata.name}' | cut -d' ' -f1)
echo "beacon source pod: $BOT"
kubectl exec -n $NSV $BOT -- python3 -c "
import socket, time
s = socket.create_connection(('172.27.11.153', 28001), timeout=8)
for i in range(40):
    try: s.sendall(b'beacon seq=%d\n' % i)
    except Exception as e: print('beacon died:', e, flush=True); break
    time.sleep(3)
" &
BEACON=$!
sleep 5
echo "-- beacon traffic before event:"; grep -c CONNECTED "$OUT/listener.log"; tail -2 "$OUT/listener.log"

T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
kubectl apply -f - <<EOF
apiVersion: amtd.r6security.com/v1beta1
kind: SecurityEvent
metadata:
  name: gp7-c2-redo
spec:
  rule:
    type: CommandAndControl
    threatLevel: critical
    source: redteam
  targets:
    - $NSV/$BOT
  description: "GP7 redo: live C2 beacon — detector fires, expect rotate kills the session"
  anomalyScore: "0.97"
EOF
for i in $(seq 1 15); do
  sleep 5
  D=$(kubectl logs -n $NSX deploy/$CTRL --since-time="$T0" 2>/dev/null | grep "$BOT" | grep -iE "\"decision\"" | tail -1)
  [ -n "$D" ] && { echo "$D" | grep -oE '"(action|net|why)":[^,]*' | head -3; break; }
  echo "  ...waiting ($i)"
done
echo "-- beacon traffic after rotate (expect CLOSED):"
sleep 8; tail -3 "$OUT/listener.log"
kubectl delete securityevent gp7-c2-redo --ignore-not-found

echo "-- waiting for replacement pod Ready, then re-dial (BOUND: reachability survives motion):"
kubectl wait -n $NSV --for=condition=Ready pod -l app=voice-bot --timeout=180s >/dev/null 2>&1
NEWBOT=$(kubectl get pods -n $NSV --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n $NSV $NEWBOT -- python3 -c "
import socket
s = socket.create_connection(('172.27.11.153', 28001), timeout=8)
s.sendall(b'beacon RE-ESTABLISHED post-rotate (new pod)\n'); print('re-dialed OK from', __import__('socket').gethostname())
"
sleep 1; tail -2 "$OUT/listener.log"
kill $LP 2>/dev/null
kubectl get pods -n $NSV | tee "$OUT/pods-after.txt"
echo done
