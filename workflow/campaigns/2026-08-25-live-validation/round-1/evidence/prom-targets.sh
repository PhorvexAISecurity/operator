#!/usr/bin/env bash
set -uo pipefail
echo "=== 1. Prometheus scrape jobs (targets) ==="
kubectl exec -n gpu-telemetry deploy/prometheus -- wget -qO- 'localhost:9090/api/v1/targets?state=active' 2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin)
jobs={}
for t in d.get('data',{}).get('activeTargets',[]):
    j=t.get('labels',{}).get('job','?'); jobs[j]=jobs.get(j,0)+1
for j,c in sorted(jobs.items()): print(f'  {c:3d} targets  job={j}')
"
echo "=== 2. other metrics stacks on the cluster ==="
kubectl get deploy,ds -A 2>/dev/null | grep -iE "prom|metric|cadvisor|node-exporter|dcgm" | head -10
echo "=== 3. sample of what metric names DO exist ==="
kubectl exec -n gpu-telemetry deploy/prometheus -- wget -qO- 'localhost:9090/api/v1/label/__name__/values' 2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin); names=d.get('data',[])
print('  total metric names:', len(names))
import re
fams=sorted(set(re.sub(r'(_total|_sum|_count|_bucket|_seconds|_bytes.*)$','',n) for n in names))
print('  families sample:', [f for f in fams][:40])
"
