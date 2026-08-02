#!/usr/bin/env bash
# PHORVEXSEC-35 controlled AWS collector. Run only from a host whose kubectl context
# is the intended EKS cluster. Every mutation is fenced into one disposable namespace.
set -euo pipefail

PROBE=${COSTPROBE:-./costprobe}
EVALUATOR=${COST_EVALUATOR:-./cost_validation.py}
CATALOG=${ACTION_CATALOG:-./action-catalog.json}
RUN_ID=${RUN_ID:-$(date -u +%Y%m%d%H%M%S)}
NS="phorvex-cost-validate-${RUN_ID}"
OUT_DIR=${OUT_DIR:-"./cost-validation-${RUN_ID}"}
OBS="$OUT_DIR/cost-validation-observations.jsonl"
ENVIRONMENT="$OUT_DIR/cost-validation-environment.json"
REVISION=${REVISION:-unknown}
CLUSTER=$(kubectl config current-context)
PROBE_SHA256=$(sha256sum "$PROBE" | awk '{print $1}')
PORT=${PORT:-18085}
PROXY_BASE="http://127.0.0.1:${PORT}/api/v1/namespaces/${NS}/services/http:costbench:8080/proxy"
PF_PID=""
LOAD_PID=""

if [[ ! -x "$PROBE" ]]; then
  echo "COSTPROBE is not executable: $PROBE" >&2
  exit 2
fi
if [[ "$NS" != phorvex-cost-validate-* ]]; then
  echo "namespace guard failed: $NS" >&2
  exit 3
fi

mkdir -p "$OUT_DIR"
: >"$OBS"

cleanup_processes() {
  [[ -z "$LOAD_PID" ]] || kill "$LOAD_PID" >/dev/null 2>&1 || true
  [[ -z "$PF_PID" ]] || kill "$PF_PID" >/dev/null 2>&1 || true
  LOAD_PID=""
  PF_PID=""
}

cleanup() {
  cleanup_processes
  kubectl delete namespace "$NS" --wait=false --ignore-not-found >/dev/null 2>&1 || true
}
trap cleanup EXIT

kubectl create namespace "$NS" >/dev/null
kubectl label namespace "$NS" phorvex.ai/benchmark=cost-validation --overwrite >/dev/null

python3 - "$ENVIRONMENT" "$CLUSTER" "$NS" "$REVISION" "$PROBE_SHA256" <<'PY'
import json, platform, subprocess, sys
path, cluster, namespace, revision, probe_sha256 = sys.argv[1:]
def output(*args):
    return subprocess.check_output(args, text=True).strip()
doc = {
    "schema_version": "phorvex.cost-validation-environment.v1",
    "cluster": cluster,
    "namespace": namespace,
    "benchmark_revision": revision,
    "costprobe_sha256": probe_sha256,
    "collector_host": platform.node(),
    "kubectl_version": output("kubectl", "version", "--client"),
    "server_version": output("kubectl", "version"),
    "node_inventory": output("kubectl", "get", "nodes", "-o", "wide"),
    "mutation_scope": "disposable benchmark namespace only",
    "production_workloads_mutated": False,
    "observed_label_weights": "equal mean of available normalized disruption terms",
}
open(path, "w").write(json.dumps(doc, indent=2, sort_keys=True) + "\n")
PY

reset_namespace_objects() {
  cleanup_processes
  kubectl -n "$NS" delete deployment,statefulset,service,pod,configmap,networkpolicy --all --ignore-not-found --wait=true >/dev/null 2>&1 || true
}

deploy_scenario() {
  local scenario=$1 seed=$2 replicas=$3 workload_type=$4 load_profile=$5 latency_ms=$6 tokens=$7 startup_delay=$8 stateful=$9
  reset_namespace_objects
  kubectl -n "$NS" create configmap costbench-app --from-literal=app.py="$(cat <<'PY'
import json, os, statistics, threading, time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

LOCK = threading.Lock()
LATENCIES = deque(maxlen=500)
COMPLETIONS = deque(maxlen=5000)
ACTIVE = 0
START = time.monotonic()
STARTUP_DELAY = float(os.getenv("STARTUP_DELAY", "0"))
BASE_LATENCY = float(os.getenv("BASE_LATENCY_MS", "20")) / 1000.0
TOKENS = float(os.getenv("TOKENS_PER_REQUEST", "50"))
STATE_VERSION = os.getenv("STATE_VERSION", "")
if STARTUP_DELAY:
    time.sleep(STARTUP_DELAY)

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def send_json(self, payload):
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        global ACTIVE
        parsed = urlparse(self.path)
        if parsed.path in ("/healthz", "/readyz"):
            self.send_json({"ok": True})
            return
        if parsed.path == "/work":
            started = time.monotonic()
            with LOCK:
                ACTIVE += 1
            try:
                time.sleep(BASE_LATENCY)
                elapsed = (time.monotonic() - started) * 1000
                with LOCK:
                    LATENCIES.append(elapsed)
                    COMPLETIONS.append((time.monotonic(), TOKENS))
                self.send_json({"tokens": TOKENS, "latency_ms": elapsed})
            finally:
                with LOCK:
                    ACTIVE -= 1
            return
        if parsed.path == "/hold":
            duration = min(60.0, max(0.0, float(parse_qs(parsed.query).get("seconds", ["10"])[0])))
            with LOCK:
                ACTIVE += 1
            try:
                time.sleep(duration)
                self.send_json({"held_sec": duration})
            finally:
                with LOCK:
                    ACTIVE -= 1
            return
        if parsed.path == "/snapshot":
            now = time.monotonic()
            with LOCK:
                recent = [(stamp, count) for stamp, count in COMPLETIONS if now - stamp <= 10]
                ordered = sorted(LATENCIES)
                p99 = ordered[min(len(ordered)-1, int(0.99 * len(ordered)))] if ordered else None
                active = ACTIVE
            payload = {
                "p99_ms": p99,
                "tokens_per_sec": sum(count for _, count in recent) / 10.0,
                "request_rate": len(recent) / 10.0,
                "active_connections": active,
                "state_version": STATE_VERSION,
                "kv_epoch": STATE_VERSION,
                "kv_rebuild_sec": STARTUP_DELAY,
                "gpu_util": None,
                "vram_pressure": None,
                "gpu_allocation_delay_sec": None,
                "gpu_recompute_burden": None,
            }
            self.send_json(payload)
            return
        self.send_error(404)

ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
PY
)" >/dev/null

  local controller="Deployment"
  [[ "$stateful" == true ]] && controller="StatefulSet"
  cat <<YAML | kubectl -n "$NS" apply -f - >/dev/null
apiVersion: v1
kind: Service
metadata:
  name: costbench
spec:
  selector:
    phorvex.ai/swap-group: bench-group
    phorvex.ai/role: leader
    phorvex.ai/serving: "true"
  ports:
  - name: http
    port: 8080
    targetPort: http
---
apiVersion: apps/v1
kind: ${controller}
metadata:
  name: costbench
spec:
  replicas: ${replicas}
  $( [[ "$controller" == StatefulSet ]] && printf 'serviceName: costbench' )
  selector:
    matchLabels:
      app: costbench
  template:
    metadata:
      labels:
        app: costbench
        phorvex.ai/serving: "true"
        phorvex.ai/swap-group: bench-group
        phorvex.ai/model-shard: bench-shard
        phorvex.ai/role: leader
        phorvex.ai/model-loaded: "true"
        phorvex.ai/route-key: ep-initial
        phorvex.ai/lora-enabled: "true"
        phorvex.ai/guardrail-tier: "true"
      annotations:
        phorvex.ai/route-service: costbench
        phorvex.ai/model-id: costbench-model
        phorvex.ai/lora-adapter: benchmark-adapter
        phorvex.ai/guardrail-variant: a
        phorvex.ai/guardrail-variants: a,b
    spec:
      terminationGracePeriodSeconds: 1
      tolerations:
      - key: CriticalAddonsOnly
        operator: Exists
        effect: NoSchedule
      containers:
      - name: app
        image: python:3.12-alpine
        command: ["python", "/app/app.py"]
        env:
        - {name: STARTUP_DELAY, value: "${startup_delay}"}
        - {name: BASE_LATENCY_MS, value: "${latency_ms}"}
        - {name: TOKENS_PER_REQUEST, value: "${tokens}"}
        - {name: STATE_VERSION, value: "${scenario}-${seed}"}
        ports:
        - {name: http, containerPort: 8080}
        readinessProbe:
          httpGet: {path: /readyz, port: http}
          periodSeconds: 1
          failureThreshold: 30
        resources:
          requests: {cpu: 10m, memory: 24Mi}
          limits: {cpu: 250m, memory: 96Mi}
        volumeMounts:
        - {name: app, mountPath: /app}
      volumes:
      - name: app
        configMap: {name: costbench-app}
YAML
  kubectl -n "$NS" rollout status "${controller,,}/costbench" --timeout=180s >/dev/null
}

start_port_forward_and_load() {
  local load_profile=$1
  cleanup_processes
  # The API Service proxy resolves a healthy backend on every request. A normal
  # `kubectl port-forward service/...` pins one pod and dies when rotate deletes it,
  # which would censor the post-action p99/TPS measurement.
  kubectl proxy --port="${PORT}" >/tmp/phorvex-cost-proxy.log 2>&1 &
  PF_PID=$!
  for _ in $(seq 1 30); do
    if curl -fsS "${PROXY_BASE}/healthz" >/dev/null 2>&1; then break; fi
    sleep 0.2
  done
  (
    while true; do
      case "$load_profile" in
        high|slo-hot) curl -fsS "${PROXY_BASE}/work" >/dev/null 2>&1 & ;;
        connections) curl -fsS "${PROXY_BASE}/hold?seconds=8" >/dev/null 2>&1 & ;;
        *) curl -fsS "${PROXY_BASE}/work" >/dev/null 2>&1; sleep 0.3 ;;
      esac
      sleep 0.05
    done
  ) &
  LOAD_PID=$!
  sleep 3
}

run_probe() {
  local scenario=$1 seed=$2 workload_type=$3 load_profile=$4 replicas=$5 stateful=$6 rag=$7 action=$8 feasibility=$9 security=${10} implementation=${11}
  local pod
  pod=$(kubectl -n "$NS" get pod -l app=costbench,phorvex.ai/role=leader -o jsonpath='{.items[0].metadata.name}')
  "$PROBE" \
    --namespace "$NS" --pod "$pod" --selector app=costbench --action "$action" \
    --scenario-id "$scenario" --seed "$seed" --tick-id "${scenario}-${seed}" \
    --workload-id costbench --workload-type "$workload_type" --load-profile "$load_profile" \
    --cluster "$CLUSTER" --revision "$REVISION" --metrics-url "${PROXY_BASE}/snapshot" \
    --output "$OBS" --implementation-status "$implementation" --feasibility "$feasibility" \
    --stateful="$stateful" --rag="$rag" --gpu=false --desired-replicas "$replicas" \
    --lambda 0.7 --security-value "$security" --slo-p99-ms 200 --timeout 180s --post-window 3s
}

scenario_spec() {
  case "$1" in
    stateless-low)  echo "3 stateless low 20 40 0.2 false false" ;;
    stateless-high) echo "3 stateless high 80 80 0.2 false false" ;;
    stateful)       echo "2 stateful low 30 40 0.5 true false" ;;
    low-replica)    echo "1 stateless low 20 40 0.2 false false" ;;
    rag)            echo "2 rag high 100 120 2.0 false true" ;;
    connections)    echo "3 stateless connections 40 40 0.2 false false" ;;
    slo-hot)        echo "3 stateless slo-hot 260 40 0.2 false false" ;;
    *) return 1 ;;
  esac
}

for scenario in stateless-low stateless-high stateful low-replica rag connections slo-hot; do
  read -r replicas workload_type load_profile latency tokens startup stateful rag <<<"$(scenario_spec "$scenario")"
  for seed in 1 2 3; do
    for action in noop rotate quarantine; do
      feasibility=feasible
      security=0
      [[ "$action" == rotate ]] && security=1.0
      [[ "$action" == quarantine ]] && security=0.82
      if [[ "$scenario" == stateful && "$action" == rotate ]]; then feasibility=blocked-stateful-integrity; fi
      if [[ "$scenario" == low-replica && "$action" != noop ]]; then feasibility=blocked-availability; fi
      if [[ "$scenario" == slo-hot && "$action" != noop ]]; then feasibility=blocked-slo; fi
      deploy_scenario "$scenario" "$seed" "$replicas" "$workload_type" "$load_profile" "$latency" "$tokens" "$startup" "$stateful"
      start_port_forward_and_load "$load_profile"
      run_probe "$scenario" "$seed" "$workload_type" "$load_profile" "$replicas" "$stateful" "$rag" "$action" "$feasibility" "$security" executable
      cleanup_processes
    done
  done
done

# One controlled live attempt for every remaining action. Precondition-dependent
# GPU/serving-stack moves are classified honestly even when their K8s half can run.
for action in debugger custom-inject disable identity-rotate route-rotate warm-swap mig-rebind kv-reset endpoint-rotate model-shard-replace adapter-rotate request-drain guardrail-rotate kv-migrate-invalidate; do
  implementation=executable
  case "$action" in
    disable) implementation="not implemented" ;;
    mig-rebind|kv-reset|adapter-rotate|guardrail-rotate|kv-migrate-invalidate) implementation="not executable" ;;
  esac
  deploy_scenario action-coverage 999 3 stateless low 20 40 0.2 false
  if [[ "$action" == warm-swap || "$action" == model-shard-replace ]]; then
    # A standalone Ready/model-loaded shadow supplies the handlers' documented precondition.
    leader=$(kubectl -n "$NS" get pod -l app=costbench -o jsonpath='{.items[0].metadata.name}')
    image=$(kubectl -n "$NS" get pod "$leader" -o jsonpath='{.spec.containers[0].image}')
    cat <<YAML | kubectl -n "$NS" apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: costbench-shadow
  labels:
    app: costbench-shadow
    phorvex.ai/serving: "true"
    phorvex.ai/swap-group: bench-group
    phorvex.ai/model-shard: bench-shard
    phorvex.ai/role: warm-shadow
    phorvex.ai/model-loaded: "true"
spec:
  tolerations:
  - key: CriticalAddonsOnly
    operator: Exists
    effect: NoSchedule
  containers:
  - name: app
    image: ${image}
    command: ["python", "-m", "http.server", "8080"]
    ports: [{name: http, containerPort: 8080}]
YAML
    kubectl -n "$NS" wait pod/costbench-shadow --for=condition=Ready --timeout=120s >/dev/null
  fi
  start_port_forward_and_load low
  run_probe action-coverage 999 stateless low 3 false false "$action" feasible 0.7 "$implementation"
  cleanup_processes
done

python3 "$EVALUATOR" --input "$OBS" --action-catalog "$CATALOG" --environment "$ENVIRONMENT" --output-dir "$OUT_DIR"
kubectl delete namespace "$NS" --wait=true --ignore-not-found >/dev/null
trap - EXIT
echo "TASK35_AWS_COLLECTION_COMPLETE output=$OUT_DIR"
