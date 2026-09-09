#!/usr/bin/env bash
set -uo pipefail
TARGET="prometheus-kube-prom-stack-kube-prome-prometheus-0"
NS="monitoring"
q() {
  local query="$1"
  local enc
  enc=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))" "$query")
  kubectl exec -n "$NS" "$TARGET" -c prometheus -- wget -qO- "localhost:9090/api/v1/query?query=$enc" 2>/dev/null \
    | python3 -c "
import json,sys
label=sys.argv[1]
try:
    d=json.load(sys.stdin); r=d.get('data',{}).get('result',[])
    extra=''
    if r: extra='  e.g. %s/%s=%s' % (r[0]['metric'].get('namespace','?'), r[0]['metric'].get('pod','?'), r[0]['value'][1])
    print('  %-58s -> %d series%s' % (label[:58], len(r), extra))
except Exception:
    print('  %-58s -> QUERY FAILED' % label[:58])
" "$query"
}
echo "=== controls ==="
q 'container_network_receive_bytes_total{namespace="vllm"}'
q 'container_network_transmit_bytes_total{namespace="cv1-control"}'
q 'sum by (pod) (rate(http_requests_total[1m]))'
echo "=== ConnCount / physics inputs ==="
q 'container_network_tcp_usage_total'
q 'count(container_network_tcp_usage_total)'
q 'container_network_tcp_usage_total{namespace="vllm"}'
echo "=== brain SigGPUUtil source ==="
q 'DCGM_FI_DEV_GPU_UTIL'
echo "=== http_requests_total variants (what app-level metrics exist) ==="
kubectl exec -n "$NS" "$TARGET" -c prometheus -- wget -qO- 'localhost:9090/api/v1/label/__name__/values' 2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin); names=d.get('data',[])
print('  total metric names:', len(names))
hits=[n for n in names if ('tcp' in n or 'http_requests' in n)]
print('  tcp/http_requests names:', hits if hits else 'NONE')
net=[n for n in names if n.startswith('container_network')]
print('  container_network_*:', net if net else 'NONE')
"
