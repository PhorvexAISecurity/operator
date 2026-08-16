#!/usr/bin/env bash
# batch3c2.sh — T43 (V17) clean re-run: lingering critical SecurityEvents are cluster-scoped and
# TTL-less (v1 evidence: 4 rotate decisions in 30s, loop on fresh pods — recorded as F15).
# This run: clean event slate first, ONE event, 90s window to slow the loop, delete the event
# the moment rotation lands, capture the payload on the REPLACEMENT pod.
set -uo pipefail
NSX=phorvex-system; NST=pxv17
OUT=/tmp/px-batch3c2; mkdir -p "$OUT"
say(){ printf '\n=== %s ===\n' "$*"; }
OP=$(kubectl get pods -n $NSX -l app.kubernetes.io/name=phorvex -o jsonpath='{.items[0].metadata.name}')
date -Is | tee "$OUT/start.txt"

say "0) clean slate: delete ALL redteam-source events (they are TTL-less — the v1 loop cause)"
for e in $(kubectl get securityevent -o jsonpath='{.items[?(@.spec.rule.source=="redteam")].metadata.name}' 2>/dev/null); do
  echo "deleting lingering event: $e" | tee -a "$OUT/event-cleanup.txt"
  kubectl delete securityevent $e --wait=false 2>/dev/null
done
sleep 3

say "1) stage canary (tolerations; 90s anti-over-rotation window)"
kubectl delete ns $NST --ignore-not-found --wait=false 2>/dev/null; sleep 8
kubectl create ns $NST --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -n $NST -f - <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata: {name: bootmark}
spec:
  replicas: 2
  selector: {matchLabels: {app: bootmark}}
  template:
    metadata:
      labels: {app: bootmark, data-class: restricted}
    spec:
      tolerations:
      - operator: Exists
      containers:
      - name: c
        image: busybox:1.36
        command: ["sh","-c","echo \"SPEC-BORNE-PAYLOAD booted=$(date -u +%H:%M:%SZ)\" > /tmp/payload; sleep 3600"]
        resources: {requests: {cpu: 10m, memory: 16Mi}, limits: {memory: 64Mi}}
EOF
kubectl wait -n $NST --for=condition=Ready pod -l app=bootmark --timeout=150s
kubectl apply -f - <<'EOF'
apiVersion: phorvex.ai/v1alpha1
kind: PhorvexPolicy
metadata: {name: pxv17-defense, namespace: pxv17}
spec:
  tenant: pxv17
  selector: {matchLabels: {app: bootmark}}
  actions: {enabled: ["rotate"]}
  assetValue:
    blastRadiusFromGraph: true
    fromLabels: {data-class: {internal: "0.4", public: "0.1", restricted: "1.0"}}
    weightSecrets: "0.8"
  objective: {costWeights: {flowDisruption: "0.6", normSparsity: "0.4"}, lambda: "0.4"}
  budget: {antiOverRotationWindow: 90s, maxMovesPerTick: 1, proactiveFloor: 15m, tickInterval: 5s}
  mode: active
  triggers: {eventDriven: true, reactiveOnly: true}
  slo: {minAvailableReplicas: 1}
EOF
kubectl get pods -n $NST -o jsonpath='{range .items[*]}{.metadata.name} uid={.metadata.uid}{"\n"}{end}' | tee "$OUT/uids-before.txt"
P0=$(kubectl get pods -n $NST -l app=bootmark -o jsonpath='{.items[0].metadata.name}')
echo "payload in target $P0 BEFORE:" | tee "$OUT/payload-before.txt"
kubectl exec -n $NST $P0 -- cat /tmp/payload | tee -a "$OUT/payload-before.txt"

say "2) ONE critical event at $P0"
T0=$(date -u +%Y-%m-%dT%H:%M:%SZ); echo "event at $T0" | tee "$OUT/event.txt"
EV=redteam-v17b-$(date +%s)
kubectl apply -f - <<EOF
apiVersion: amtd.r6security.com/v1beta1
kind: SecurityEvent
metadata: {name: $EV}
spec:
  rule: {type: SupplyChainRCE, threatLevel: critical, source: redteam}
  targets: ["$NST/$P0"]
  description: "V17: poisoned startup dep detected in pod"
  anomalyScore: "0.95"
EOF

say "3) wait for rotation of the TARGET pod, then IMMEDIATELY delete the event"
ROT=""
for i in $(seq 1 36); do
  sleep 5
  kubectl get pod -n $NST $P0 >/dev/null 2>&1 || { ROT=yes; break; }
done
if [ -n "$ROT" ]; then
  echo "TARGET ROTATED at $(date -u +%H:%M:%SZ)" | tee "$OUT/rotate.txt"
  kubectl delete securityevent $EV --wait=false 2>/dev/null
  echo "event $EV deleted immediately after rotation (stops the F15 loop)" | tee -a "$OUT/rotate.txt"
else
  echo "target NOT rotated in 180s" | tee "$OUT/rotate.txt"
fi
kubectl logs -n $NSX $OP --since=4m 2>/dev/null | grep "$NST" | grep "decision" | grep -o '"pod": "[^"]*", "action": "[^"]*", "selected": [a-z]*' | tail -6 | tee -a "$OUT/rotate.txt"
kubectl wait -n $NST --for=condition=Ready pod -l app=bootmark --timeout=150s 2>/dev/null
kubectl get pods -n $NST -o jsonpath='{range .items[*]}{.metadata.name} uid={.metadata.uid}{"\n"}{end}' | tee "$OUT/uids-after.txt"

say "4) oracle: payload on the REPLACEMENT pod(s)"
for p in $(kubectl get pods -n $NST -l app=bootmark --field-selector=status.phase=Running -o jsonpath='{.items[*].metadata.name}'); do
  echo "--- $p ---" | tee -a "$OUT/payload-after.txt"
  kubectl exec -n $NST $p -- cat /tmp/payload 2>&1 | tee -a "$OUT/payload-after.txt"
done
echo "(a payload with a boot time AFTER the event time on a NEW uid = spec-borne poison re-executed post-rotation)" | tee -a "$OUT/payload-after.txt"

say "5) cleanup"
for e in $(kubectl get securityevent -o jsonpath='{.items[?(@.spec.rule.source=="redteam")].metadata.name}' 2>/dev/null); do kubectl delete securityevent $e --wait=false 2>/dev/null; done
kubectl delete ns $NST --wait=false 2>/dev/null
date -Is | tee "$OUT/end.txt"
