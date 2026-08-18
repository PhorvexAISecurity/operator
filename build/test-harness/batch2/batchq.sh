#!/usr/bin/env bash
# batchq.sh — Q3 (single-replica stateful store -> nothing feasible = the None-gap, queue #3)
# and queue #2 (same store at minAvail:0 -> quarantine selected; NP cosmetic — T6-class).
# Target: mongo (Deployment + RWO PVC). Watch sprawl: replacement will Pend on the PVC (bounded).
set -uo pipefail
NSX=phorvex-system; CTRL=phorvex-phorvex; NSD=document-store
OUT=/tmp/px-batchq; mkdir -p "$OUT"
say(){ printf '\n=== %s ===\n' "$*"; }

say "0) baseline"
kubectl get pods -n $NSD -o jsonpath='{range .items[*]}{.metadata.name} uid={.metadata.uid}{"\n"}{end}' | tee "$OUT/uids-before.txt"

mkpolicy(){ # $1 = minAvail
kubectl apply -f - <<EOF
apiVersion: phorvex.ai/v1alpha1
kind: PhorvexPolicy
metadata:
  name: mongo-defense
  namespace: $NSD
spec:
  tenant: document-store
  selector: {matchLabels: {app: mongo}}
  actions: {enabled: ["rotate", "quarantine"]}
  assetValue:
    blastRadiusFromGraph: true
    fromLabels: {data-class: {internal: "0.4", public: "0.1", restricted: "1.0"}}
    weightSecrets: "0.8"
  objective: {costWeights: {flowDisruption: "0.6", normSparsity: "0.4"}, lambda: "0.4"}
  budget: {antiOverRotationWindow: 10s, maxMovesPerTick: 1, proactiveFloor: 15m, tickInterval: 5s}
  mode: active
  triggers: {eventDriven: true, reactiveOnly: true}
  slo: {minAvailableReplicas: $1}
EOF
}
fireevent(){ # $1 = name
POD=$(kubectl get pods -n $NSD -l app=mongo --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
kubectl apply -f - <<EOF
apiVersion: amtd.r6security.com/v1beta1
kind: SecurityEvent
metadata:
  name: $1
spec:
  rule: {type: Panic, threatLevel: critical, source: redteam}
  targets: ["$NSD/$POD"]
  description: "queue test on stateful mongo"
  anomalyScore: "0.95"
EOF
}

say "1) Q3: minAvail=1 — expect NOTHING feasible (rotate: stateful+floored, quarantine: floored)"
mkpolicy 1
sleep 45   # enrollment (learned from M3b)
echo "-- ticks (expect infeasible:1):"
kubectl logs -n $NSX deploy/$CTRL --since=20s 2>/dev/null | grep 'tenant": "document-store"' | tail -2
fireevent q3-mongo-none
sleep 60
echo "-- decisions in window (expect NONE — that IS the result):"
kubectl logs -n $NSX deploy/$CTRL --since-time="$T0" 2>/dev/null | grep -i "$NSD/" | grep -iE "decision|rotate|quarantine" | tail -5 | tee "$OUT/q3.txt"
echo "(empty = correctly nothing: the None-gap proven live)"
kubectl delete securityevent q3-mongo-none --ignore-not-found >/dev/null
MONGO_POD=$(kubectl get pods -n $NSD -l app=mongo --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
kubectl get pod -n $NSD $MONGO_POD -o jsonpath='  mongo uid={.metadata.uid} (unchanged = no motion){"\n"}' | tee -a "$OUT/q3.txt"

say "2) queue#2: minAvail=0 — expect quarantine selected (cosmetic NP; sprawl capped by RWO PVC)"
mkpolicy 0
sleep 20
fireevent q2-mongo-quar
for i in $(seq 1 18); do
  sleep 5
  D=$(kubectl logs -n $NSX deploy/$CTRL --since-time="$T0" 2>/dev/null | grep -i "$NSD/" | grep -iE "quarantine|decision" | tail -1)
  [ -n "$D" ] && { echo "$D" | head -c 380; echo; break; }
  echo "  ...waiting ($i)"
done
kubectl delete securityevent q2-mongo-quar --ignore-not-found >/dev/null
echo "-- pod/namespace state after quarantine:"
kubectl get pods -n $NSD -o wide | tee "$OUT/q2-pods.txt"
kubectl get networkpolicy -n $NSD 2>/dev/null | tee "$OUT/q2-np.txt"
echo "-- mongo still answers (NP unenforced on this CNI = cosmetic, T6-established):"
kubectl exec -n $NSD $MONGO_POD -- mongosh --quiet --eval 'print("mongo live:", db.runCommand({ping:1}).ok)' 2>/dev/null || echo "  (exec blocked — check)"

say "3) cleanup: policy off, NP off, pod set reconciled"
kubectl delete phorvexpolicy -n $NSD mongo-defense --ignore-not-found
kubectl delete networkpolicy -n $NSD --all 2>/dev/null || true
# if quarantine detached the pod from the RS, delete leftovers so the Deployment reconciles cleanly
for p in $(kubectl get pods -n $NSD -l app=mongo -o jsonpath='{.items[*].metadata.name}'); do
  OWNER=$(kubectl get pod -n $NSD $p -o jsonpath='{.metadata.ownerReferences[0].kind}' 2>/dev/null)
  PH=$(kubectl get pod -n $NSD $p -o jsonpath='{.status.phase}' 2>/dev/null)
  echo "  pod $p owner=$OWNER phase=$PH"
  if [ "$OWNER" != "ReplicaSet" ] || [ "$PH" = "Pending" ]; then
    echo "  -> deleting $p (adopted/stuck) for clean reconcile"
    kubectl delete pod -n $NSD $p --force --wait=false 2>/dev/null
  fi
done
sleep 15
kubectl wait -n $NSD --for=condition=Ready pod -l app=mongo --timeout=240s
kubectl get pods -n $NSD | tee "$OUT/pods-after.txt"
kubectl exec -n $NSD $(kubectl get pods -n $NSD -l app=mongo --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}') -- mongosh --quiet --eval 'print("post-cleanup ping:", db.runCommand({ping:1}).ok)'
echo done
