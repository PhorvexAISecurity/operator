#!/usr/bin/env bash
# b3full.sh — B3 endpoint-rotate, full-effect re-run after the RBAC fix.
# Staging tells the complete story: the Service pins the route-key (attacker mapped
# "route-key=ep-old" -> pod A). endpoint-rotate must re-key the pod AND restitch the
# Service selector to the new key: the route FOLLOWS the pod (zero downtime) while the
# attacker's pinned route identity goes stale.
set -euo pipefail
NS=vllm; NSX=phorvex-system; CTRL=phorvex-phorvex; POL=vllm-defense
OUT=/tmp/px-battery; mkdir -p "$OUT"

echo "=== RBAC fix: add services get/update/patch to phorvex-actuation (missing rule found by T-battery) ==="
kubectl patch clusterrole phorvex-actuation --type json -p \
  '[{"op":"add","path":"/rules/-","value":{"apiGroups":[""],"resources":["services"],"verbs":["get","update","patch"]}}]'
kubectl get clusterrole phorvex-actuation -o jsonpath='{.rules}' | grep -o services

POD=$(kubectl get pods -n $NS -o jsonpath='{.items[0].metadata.name}')
echo "target: $POD"

echo "=== stage: route-key=ep-old pinned by the Service (attacker's mapped route identity) ==="
kubectl label pod -n $NS "$POD" phorvex.ai/route-key=ep-old --overwrite
kubectl annotate pod -n $NS "$POD" phorvex.ai/route-service=vllm-infer --overwrite
kubectl patch svc -n $NS vllm-infer --type merge -p '{"spec":{"selector":{"app":"vllm","phorvex.ai/route-key":"ep-old"}}}'
sleep 2
echo "BEFORE:" | tee "$OUT/b3f-before.txt"
kubectl get svc -n $NS vllm-infer -o jsonpath='  selector={.spec.selector}{"\n"}' | tee -a "$OUT/b3f-before.txt"
kubectl get endpoints -n $NS vllm-infer -o jsonpath='  endpoints={.subsets[*].addresses[*].ip}{"\n"}' 2>/dev/null | tee -a "$OUT/b3f-before.txt" || true
kubectl get pod -n $NS "$POD" -o jsonpath='  uid={.metadata.uid}{"\n"}  route-key={.metadata.labels.phorvex\.ai/route-key}{"\n"}' | tee -a "$OUT/b3f-before.txt"

echo "=== policy scope [rotate,endpoint-rotate], minAvail=2 (rotate pruned) ==="
kubectl patch phorvexpolicy -n $NS $POL --type merge -p \
  '{"spec":{"actions":{"enabled":["rotate","endpoint-rotate"]},"slo":{"minAvailableReplicas":2}}}'

echo "=== fire ==="
T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
kubectl apply -f - <<EOF
apiVersion: amtd.r6security.com/v1beta1
kind: SecurityEvent
metadata:
  name: b3f-endpoint-pinning
spec:
  rule:
    type: EndpointPinning
    threatLevel: critical
    source: redteam
  targets:
    - $NS/$POD
  description: "B3-full: attacker pinned the vLLM serving route (route-key=ep-old) for extraction/SSRF"
  anomalyScore: "0.95"
EOF
date -Is

echo "=== watch ==="
: > "$OUT/b3f.log"
for i in $(seq 1 15); do
  sleep 8
  kubectl logs -n $NSX deploy/$CTRL --since-time="$T0" 2>/dev/null | grep -i "$POD" > "$OUT/b3f.log" || true
  if grep -qiE "endpoint-rotate|infeasible|error" "$OUT/b3f.log"; then cat "$OUT/b3f.log"; break; fi
  echo "  ...waiting for tick ($i)"
done

echo "=== AFTER ==="
kubectl get svc -n $NS vllm-infer -o jsonpath='  selector={.spec.selector}{"\n"}' | tee "$OUT/b3f-selector-after.txt"
kubectl get endpoints -n $NS vllm-infer -o jsonpath='  endpoints={.subsets[*].addresses[*].ip}{"\n"}' 2>/dev/null | tee -a "$OUT/b3f-selector-after.txt" || true
kubectl get pod -n $NS "$POD" -o jsonpath='  uid={.metadata.uid}{"\n"}  route-key={.metadata.labels.phorvex\.ai/route-key}{"\n"}  phase={.status.phase}{"\n"}' | tee "$OUT/b3f-pod-after.txt"

kubectl delete securityevent b3f-endpoint-pinning --ignore-not-found
echo done
