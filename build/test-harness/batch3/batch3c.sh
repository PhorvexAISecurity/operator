#!/usr/bin/env bash
# batch3c.sh — T43 (V17): image/spec-borne poison vs rotate (canary sim).
# A "startup payload" baked into the pod spec executes at EVERY boot (stand-in for a poisoned
# dependency/model artifact in the image). Rotate the pod -> the payload reappears on the fresh
# pod. Proves: rotation dwell-caps image-borne poison but cannot cure it.
# Isolated namespace pxv17; fully cleaned up after.
set -uo pipefail
NSX=phorvex-system; NST=pxv17
OUT=/tmp/px-batch3c; mkdir -p "$OUT"
say(){ printf '\n=== %s ===\n' "$*"; }
date -Is | tee "$OUT/start.txt"

say "0) stage: ns + 2-replica canary whose spec writes a payload marker at every boot"
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
      # throwaway pod must tolerate every taint (harness convention: real clusters taint nodes)
      tolerations:
      - operator: Exists
      containers:
      - name: c
        image: busybox:1.36
        # stand-in for a poisoned dep/model artifact: executes at EVERY container start
        command: ["sh","-c","echo \"SPEC-BORNE-PAYLOAD booted=$(date -u +%H:%M:%SZ)\" > /tmp/payload; echo payload-written; sleep 3600"]
        resources: {requests: {cpu: 10m, memory: 16Mi}, limits: {memory: 64Mi}}
EOF
kubectl wait -n $NST --for=condition=Ready pod -l app=bootmark --timeout=120s
kubectl get pods -n $NST -o jsonpath='{range .items[*]}{.metadata.name} uid={.metadata.uid}{"\n"}{end}' | tee "$OUT/uids-before.txt"
P0=$(kubectl get pods -n $NST -l app=bootmark -o jsonpath='{.items[0].metadata.name}')
echo "payload in $P0 BEFORE rotate:" | tee "$OUT/payload-before.txt"
kubectl exec -n $NST $P0 -- cat /tmp/payload | tee -a "$OUT/payload-before.txt"

say "1) policy: [rotate], reactiveOnly"
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
  budget: {antiOverRotationWindow: 10s, maxMovesPerTick: 1, proactiveFloor: 15m, tickInterval: 5s}
  mode: active
  triggers: {eventDriven: true, reactiveOnly: true}
  slo: {minAvailableReplicas: 1}
EOF

say "2) detector fires (startup-RCE foothold reported)"
T0=$(date -u +%Y-%m-%dT%H:%M:%SZ); echo "event at $T0" | tee "$OUT/event.txt"
kubectl apply -f - <<EOF
apiVersion: amtd.r6security.com/v1beta1
kind: SecurityEvent
metadata: {name: redteam-v17-$(date +%s)}
spec:
  rule: {type: SupplyChainRCE, threatLevel: critical, source: redteam}
  targets: ["$NST/$P0"]
  description: "V17: poisoned startup dep detected in pod"
  anomalyScore: "0.95"
EOF

say "3) watch for rotate (up to 150s)"
OP=$(kubectl get pods -n $NSX -l app.kubernetes.io/name=phorvex -o jsonpath='{.items[0].metadata.name}')
ROTATED=""
for i in $(seq 1 30); do
  sleep 5
  if ! kubectl get pod -n $NST $P0 >/dev/null 2>&1; then ROTATED=yes; break; fi
done
if [ -n "$ROTATED" ]; then
  echo "POD ROTATED (old pod $P0 gone)" | tee "$OUT/rotate.txt"
else
  echo "NO ROTATION in 150s" | tee "$OUT/rotate.txt"
fi
kubectl logs -n $NSX $OP --since=4m 2>/dev/null | grep "$NST" | grep -E "decision|rotate" | tail -4 | tee -a "$OUT/rotate.txt"
kubectl wait -n $NST --for=condition=Ready pod -l app=bootmark --timeout=120s 2>/dev/null
kubectl get pods -n $NST -o jsonpath='{range .items[*]}{.metadata.name} uid={.metadata.uid}{"\n"}{end}' | tee "$OUT/uids-after.txt"

say "4) oracle: does the FRESH pod carry the payload? (spec-borne => yes => rotate cannot cure)"
PN=$(kubectl get pods -n $NST -l app=bootmark --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
echo "payload in FRESH pod $PN AFTER rotate:" | tee "$OUT/payload-after.txt"
kubectl exec -n $NST $PN -- cat /tmp/payload | tee -a "$OUT/payload-after.txt"
echo "(new boot timestamp = the payload was re-executed at boot on the replacement pod)" | tee -a "$OUT/payload-after.txt"

say "5) cleanup"
kubectl delete securityevent -A -l redteam 2>/dev/null || true
kubectl delete ns $NST --wait=false
date -Is | tee "$OUT/end.txt"
