#!/usr/bin/env bash
# batch3d.sh — T39 (B4·G2): model-shard-replace selection via the K1 recipe.
# Policy scoped to [rotate,model-shard-replace]; rotate is floor-gated (1 replica, minAvail:1)
# AND conformal-cost-gated (F6) on the GPU pod -> model-shard-replace is the sole feasible
# candidate. Effect expected to FAIL-CLOSED (no phorvex.ai/model-shard label, no warm shadow).
# Policy backed up + restored as-found.
set -uo pipefail
NSX=phorvex-system; NSV=vllm
OUT=/tmp/px-batch3d; mkdir -p "$OUT"
say(){ printf '\n=== %s ===\n' "$*"; }
VPOD=$(kubectl get pods -n $NSV -l app=vllm --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
[ -z "$VPOD" ] && VPOD=$(kubectl get pods -n $NSV -o jsonpath='{.items[0].metadata.name}')
echo "vllm pod: $VPOD" | tee "$OUT/target.txt"
date -Is | tee "$OUT/start.txt"

say "0) backup as-found policy"
kubectl get phorvexpolicy -n $NSV vllm-defense -o yaml > "$OUT/vllm-defense.backup.yaml"
kubectl get phorvexpolicy -n $NSV vllm-defense -o jsonpath='{.spec.actions.enabled} reactiveOnly={.spec.triggers.reactiveOnly}{"\n"}' | tee "$OUT/policy-asfound.txt"

say "1) scope policy to [rotate,model-shard-replace], reactiveOnly:true"
kubectl patch phorvexpolicy -n $NSV vllm-defense --type merge -p '{"spec":{"actions":{"enabled":["rotate","model-shard-replace"]},"triggers":{"eventDriven":true,"reactiveOnly":true}}}'
kubectl get phorvexpolicy -n $NSV vllm-defense -o jsonpath='{.spec.actions.enabled} reactiveOnly={.spec.triggers.reactiveOnly}{"\n"}' | tee "$OUT/policy-scoped.txt"
sleep 8

say "2) fire ModelTampering critical event"
T0=$(date -u +%Y-%m-%dT%H:%M:%SZ); echo "event at $T0 pod $VPOD" | tee "$OUT/event.txt"
kubectl apply -f - <<EOF
apiVersion: amtd.r6security.com/v1beta1
kind: SecurityEvent
metadata: {name: redteam-b4-$(date +%s)}
spec:
  rule: {type: ModelTampering, threatLevel: critical, source: redteam}
  targets: ["$NSV/$VPOD"]
  description: "B4: served-model weight tamper / extraction fingerprint"
  anomalyScore: "0.95"
EOF

say "3) watch 150s for selection (decision log)"
OP=$(kubectl get pods -n $NSX -l app.kubernetes.io/name=phorvex -o jsonpath='{.items[0].metadata.name}')
FOUND=""
for i in $(seq 1 30); do
  sleep 5
  L=$(kubectl logs -n $NSX $OP --since=4m 2>/dev/null | grep "$NSV/$VPOD" | grep -E "model-shard-replace|decision" | tail -2)
  if echo "$L" | grep -q "model-shard-replace"; then FOUND=yes; echo "$L" | tee "$OUT/selection.txt"; break; fi
done
if [ -z "$FOUND" ]; then
  echo "no model-shard-replace selection in 150s — capture tick state + lambda" | tee "$OUT/selection.txt"
  kubectl logs -n $NSX $OP --since=4m 2>/dev/null | grep "$NSV" | tail -6 | tee -a "$OUT/selection.txt"
fi

say "4) enactment result (expect fail-closed: no model-shard label / no warm shadow)"
kubectl logs -n $NSX $OP --since=4m 2>/dev/null | grep -iE "shard|actuate|fail" | tail -6 | tee "$OUT/enact.txt"
kubectl get pod -n $NSV $VPOD -o jsonpath='uid={.metadata.uid} labels={.metadata.labels}' | tee "$OUT/pod-after.txt"; echo

say "5) restore policy as-found + delete event"
kubectl replace -f "$OUT/vllm-defense.backup.yaml" --force 2>/dev/null || kubectl apply -f "$OUT/vllm-defense.backup.yaml"
kubectl get phorvexpolicy -n $NSV vllm-defense -o jsonpath='{.spec.actions.enabled} reactiveOnly={.spec.triggers.reactiveOnly}{"\n"}' | tee "$OUT/policy-restored.txt"
for e in $(kubectl get securityevent -o jsonpath='{.items[?(@.spec.rule.source=="redteam")].metadata.name}' 2>/dev/null); do kubectl delete securityevent $e --wait=false 2>/dev/null; done
date -Is | tee "$OUT/end.txt"
