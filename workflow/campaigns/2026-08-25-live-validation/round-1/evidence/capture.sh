#!/usr/bin/env bash
# Phorvex live-campaign capture harness — Round 1
# NDJSON/raw capture with aligned UTC timestamps. Runs under nohup on the jump host.
set -uo pipefail
OUT=${OUT:-/tmp/campaign/round1}
mkdir -p "$OUT"
ts() { date -u +%FT%T.%3NZ; }
log() { echo "[$(ts)] $*" >> "$OUT/capture.log"; }

log "capture starting; build context:"
kubectl get deploy phorvex-phorvex -n phorvex-system -o jsonpath='{.spec.template.spec.containers[*].image}' > "$OUT/build.txt" 2>&1
echo >> "$OUT/build.txt"; date -u >> "$OUT/build.txt"

# 1) brain decision/actuation log stream (follow, reconnect on exit)
brain_logs() {
  while true; do
    kubectl logs deploy/phorvex-phorvex -n phorvex-system -c manager -f --timestamps --since=2s 2>>"$OUT/capture.log" \
    | while IFS= read -r line; do
        printf '{"capture_ts":"%s","src":"brain","raw":%s}\n' "$(ts)" \
          "$(python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))' <<<"$line")" \
          >> "$OUT/brain-log.ndjson"
      done
    log "brain log stream exited ($?); restarting in 5s"
    sleep 5
  done
}

# 2) brain /metrics via supervised port-forward, every 30s
brain_metrics() {
  while true; do
    kubectl port-forward deploy/phorvex-phorvex 18080:8080 -n phorvex-system >/dev/null 2>>"$OUT/capture.log" &
    PF=$!
    sleep 4
    while kill -0 $PF 2>/dev/null; do
      { echo "### $(ts)"; curl -s --max-time 5 localhost:18080/metrics; echo; } >> "$OUT/metrics-brain.txt"
      sleep 30
    done
    log "brain port-forward died; restarting in 5s"
    sleep 5
  done
}

# 3) vllm engine metrics via supervised port-forward, every 60s
vllm_metrics() {
  while true; do
    kubectl port-forward svc/vllm 18000:8000 -n vllm >/dev/null 2>>"$OUT/capture.log" &
    PF=$!
    sleep 4
    while kill -0 $PF 2>/dev/null; do
      { echo "### $(ts)"; curl -s --max-time 5 localhost:18000/metrics; echo; } >> "$OUT/metrics-vllm.txt"
      sleep 60
    done
    log "vllm port-forward died; restarting in 10s"
    sleep 10
  done
}

# 4) k8s events, all namespaces, snapshot poll every 60s (dedup at analysis)
events_loop() {
  while true; do
    { echo "### $(ts)"; kubectl get events -A --sort-by=.lastTimestamp 2>&1; echo; } >> "$OUT/events.txt"
    sleep 60
  done
}

# 5) pod state for campaign namespaces, every 60s
pods_loop() {
  while true; do
    for ns in cv1-control vllm; do
      kubectl get pods -n "$ns" -o json 2>/dev/null | python3 -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit(0)
for p in d.get('items',[]):
    m=p['metadata']; s=p.get('status',{})
    print(json.dumps({'capture_ts':'$(ts)','ns':m['namespace'],'pod':m['name'],
      'phase':s.get('phase'),'restarts':sum(c.get('restartCount',0) for c in s.get('containerStatuses',[])),
      'deletionTimestamp':m.get('deletionTimestamp'),
      'labels':{k:v for k,v in m.get('labels',{}).items() if 'r6th' in k or 'phorvex' in k or k=='app'},
      'node':p.get('spec',{}).get('nodeName')}))
" >> "$OUT/pods.ndjson"
    done
    sleep 60
  done
}

# 6) GPU utilization/memory from the vllm pod, every 60s
gpu_loop() {
  while true; do
    VPOD=$(kubectl get pods -n vllm -l r6th.io/rotation-target=true -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    if [ -n "$VPOD" ]; then
      R=$(kubectl exec -n vllm "$VPOD" -- nvidia-smi --query-gpu=utilization.gpu,memory.used,memory.total --format=csv,noheader 2>/dev/null)
      [ -n "$R" ] && printf '{"capture_ts":"%s","src":"gpu","raw":%s}\n' "$(ts)" \
        "$(python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().strip()))' <<<"$R")" >> "$OUT/gpu.ndjson"
    fi
    sleep 60
  done
}

# 7) SecurityEvents census, every 60s
sev_loop() {
  while true; do
    kubectl get securityevents -A -o json 2>/dev/null | python3 -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit(0)
print(json.dumps({'capture_ts':'$(ts)','count':len(d.get('items',[])),
  'items':[{'ns':i['metadata']['namespace'],'name':i['metadata']['name'],
            'type':i.get('spec',{}).get('rule',{}).get('type'),
            'source':i.get('spec',{}).get('rule',{}).get('source'),
            'targets':i.get('spec',{}).get('targets')} for i in d.get('items',[])]}))
" >> "$OUT/securityevents.ndjson"
    sleep 60
  done
}

brain_logs & echo $! > "$OUT/pid.brain"
brain_metrics & echo $! > "$OUT/pid.metrics"
vllm_metrics & echo $! > "$OUT/pid.vllm"
events_loop & echo $! > "$OUT/pid.events"
pods_loop & echo $! > "$OUT/pid.pods"
gpu_loop & echo $! > "$OUT/pid.gpu"
sev_loop & echo $! > "$OUT/pid.sev"

log "all loops started: $(cat "$OUT"/pid.* | tr '\n' ' ')"
wait
