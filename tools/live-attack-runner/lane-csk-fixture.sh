#!/usr/bin/env bash
# lane-csk-fixture.sh — stand up (or tear down) the controller-stop+kinds family coverage
# fixture on a lane: a faithful demo-api clone OWNED BY A DAEMONSET (nginx + prometheus
# exporter behind a Service, steady load, PodMonitor, PhorvexPolicy enabled:[rotate]).
#
# WHY A DAEMONSET + >=2 PODS: the +kinds extension widens native rotate (Pod Eviction) owner
# eligibility to apps/v1 DaemonSet (internal/ownership/rotate.go). The brain only prices a
# POSITIVE-gain reactive rotate when the target carries a real protectable profile (Service
# graph + measured load + covered facts) — an isolated bare pod gets no reactive decision. And
# the availability floor (internal/feasibility/defaults.go availabilityFloor) requires
# readyReplicas-1 >= minAvailableReplicas, where minAvailableReplicas DEFAULTS TO 1
# (api/v1alpha1 defaults.go: a 0 is treated as unset) — so the workload MUST have >= 2 Ready
# pods or every rotate is infeasible. A DaemonSet reaches 2 pods by pinning to 2 nodes.
#
# NOTE: `phvx-attack.py fire T1053.007|T1543.005 --lane N` AUTO-PROVISIONS a fresh, uniquely
# named instance of exactly this workload (ControllerStopKindsFamily.setup) and tears it down,
# so each fire is a pristine first-rotate. This script is the MANUAL/inspectable equivalent —
# it stands up ONE persistent named workload you can look at or fire by hand. A workload's
# FIRST reactive rotate consumes its exposure-coverage (a 2nd rotate on the same workload
# prices <=0 and no-ops, persisting via the manager audit replay), so re-fire a FRESH clone.
#
# Usage:
#   lane-csk-fixture.sh <N> [name] [replicas]      # up   (default name ds-orch, replicas 2)
#   lane-csk-fixture.sh down <N> [name]            # down
set -euo pipefail
GW=phorvex-gw
k() { ssh "$GW" kubectl "$@"; }

WEB_IMG="public.ecr.aws/nginx/nginx-unprivileged:1.27-alpine@sha256:65e3e85dbaed8ba248841d9d58a899b6197106c23cb0ff1a132b7bfe0547e4c0"
EXP_IMG="public.ecr.aws/nginx/nginx-prometheus-exporter:1.5.3@sha256:85666e7fde7e253f1c6d978f9a961245df4c9cdb7677e1866d9bb28e8f9ee41d"
LOAD_IMG="public.ecr.aws/docker/library/busybox:1.37.0@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e"

if [[ "${1:-}" == "down" ]]; then
  N="${2:?lane number}"; NAME="${3:-ds-orch}"; DEMO="p${N}-demo"
  for kv in "phorvexpolicy ${NAME}-defense" "deployment ${NAME}-load" "podmonitor ${NAME}" \
            "service ${NAME}" "daemonset ${NAME}" "configmap ${NAME}-nginx"; do
    k delete $kv -n "$DEMO" --ignore-not-found --wait=false || true
  done
  echo "torn down $DEMO/$NAME"; exit 0
fi

N="${1:?lane number}"; NAME="${2:-ds-orch}"; REPLICAS="${3:-2}"; DEMO="p${N}-demo"

# Pick REPLICAS least-loaded headroom nodes whose taints are a subset of {CriticalAddonsOnly}
# (the untainted nodes are aws-cni IP-saturated on this oversubscribed farm). hostname list.
TMPN="$(mktemp)"; TMPP="$(mktemp)"; trap 'rm -f "$TMPN" "$TMPP"' EXIT
k get nodes -o json > "$TMPN"
k get pods -A -o json > "$TMPP"
mapfile -t NODES < <(python3 -I - "$REPLICAS" "$TMPN" "$TMPP" <<'PY'
import json,sys
want=int(sys.argv[1])
nodes=json.load(open(sys.argv[2]))['items']
pods=json.load(open(sys.argv[3]))['items']
load={}
for p in pods:
    n=p.get('spec',{}).get('nodeName'); ph=p.get('status',{}).get('phase')
    if n and ph not in ('Succeeded','Failed'): load[n]=load.get(n,0)+1
elig=[]
for nd in nodes:
    if nd.get('spec',{}).get('unschedulable'): continue
    if not any(c.get('type')=='Ready' and c.get('status')=='True' for c in nd.get('status',{}).get('conditions',[])): continue
    taints={t['key'] for t in (nd.get('spec',{}).get('taints') or [])}
    if not taints <= {'CriticalAddonsOnly'}: continue
    name=nd['metadata']['name']
    elig.append((('CriticalAddonsOnly' not in taints), load.get(name,0), name))
elig.sort()
for _,_,n in elig[:want]: print(n)
PY
)
if (( ${#NODES[@]} < REPLICAS )); then
  echo "ERROR: need $REPLICAS schedulable headroom nodes, found ${#NODES[@]}: ${NODES[*]}" >&2; exit 1
fi
echo "pinning $DEMO/$NAME ($REPLICAS pods) to: ${NODES[*]}"
AFF_VALUES="$(printf '                - %s\n' "${NODES[@]}")"

cat <<YAML | k apply -f -
apiVersion: v1
kind: ConfigMap
metadata: {name: ${NAME}-nginx, namespace: ${DEMO}, labels: {app.kubernetes.io/name: ${NAME}, app.kubernetes.io/part-of: phorvex-demo, phorvex.ai/redteam-runner: phvx-attack}}
data:
  default.conf: |
    server { listen 8080; location / { root /usr/share/nginx/html; index index.html; } }
    server { listen 127.0.0.1:8081; location = /stub_status { stub_status; } }
---
apiVersion: apps/v1
kind: DaemonSet
metadata: {name: ${NAME}, namespace: ${DEMO}, labels: {app.kubernetes.io/name: ${NAME}, app.kubernetes.io/part-of: phorvex-demo, phorvex.ai/redteam-runner: phvx-attack}}
spec:
  selector: {matchLabels: {app.kubernetes.io/name: ${NAME}}}
  template:
    metadata:
      labels: {app.kubernetes.io/name: ${NAME}, app.kubernetes.io/part-of: phorvex-demo, data-class: internal, r6th.io/rotation-target: "true"}
    spec:
      automountServiceAccountToken: false
      tolerations: [{key: CriticalAddonsOnly, operator: Exists}]
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
            - matchExpressions:
              - key: kubernetes.io/hostname
                operator: In
                values:
${AFF_VALUES}
      securityContext: {runAsNonRoot: true, seccompProfile: {type: RuntimeDefault}}
      containers:
      - name: web
        image: ${WEB_IMG}
        ports: [{name: http, containerPort: 8080}]
        readinessProbe: {httpGet: {path: /, port: http}, periodSeconds: 5}
        resources: {requests: {cpu: 10m, memory: 16Mi}, limits: {memory: 64Mi}}
        securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
        volumeMounts: [{name: tmp, mountPath: /tmp}, {name: nginx-conf, mountPath: /etc/nginx/conf.d, readOnly: true}]
      - name: exporter
        image: ${EXP_IMG}
        args: ["--nginx.scrape-uri=http://127.0.0.1:8081/stub_status"]
        ports: [{name: metrics, containerPort: 9113}]
        readinessProbe: {httpGet: {path: /metrics, port: metrics}, periodSeconds: 10}
        resources: {requests: {cpu: 5m, memory: 16Mi}, limits: {memory: 32Mi}}
        securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
      volumes: [{name: tmp, emptyDir: {}}, {name: nginx-conf, configMap: {name: ${NAME}-nginx}}]
---
apiVersion: v1
kind: Service
metadata: {name: ${NAME}, namespace: ${DEMO}, labels: {app.kubernetes.io/name: ${NAME}, app.kubernetes.io/part-of: phorvex-demo, phorvex.ai/redteam-runner: phvx-attack}}
spec:
  selector: {app.kubernetes.io/name: ${NAME}}
  ports: [{name: http, port: 80, targetPort: http}]
---
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata: {name: ${NAME}, namespace: ${DEMO}, labels: {app.kubernetes.io/name: ${NAME}, app.kubernetes.io/part-of: phorvex-demo, phorvex.ai/redteam-runner: phvx-attack}}
spec:
  selector: {matchLabels: {app.kubernetes.io/name: ${NAME}}}
  podMetricsEndpoints:
  - port: metrics
    interval: 15s
    metricRelabelings:
    - {action: keep, sourceLabels: [__name__], regex: nginx_http_requests_total|nginx_up}
    - {action: replace, sourceLabels: [__name__], regex: nginx_http_requests_total, targetLabel: __name__, replacement: http_requests_total}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: ${NAME}-load, namespace: ${DEMO}, labels: {app.kubernetes.io/name: ${NAME}-load, app.kubernetes.io/part-of: phorvex-demo, phorvex.ai/redteam-runner: phvx-attack}}
spec:
  replicas: 1
  selector: {matchLabels: {app.kubernetes.io/name: ${NAME}-load}}
  template:
    metadata: {labels: {app.kubernetes.io/name: ${NAME}-load, app.kubernetes.io/part-of: phorvex-demo}}
    spec:
      automountServiceAccountToken: false
      nodeSelector: {kubernetes.io/hostname: ${NODES[0]}}
      tolerations: [{key: CriticalAddonsOnly, operator: Exists}]
      securityContext: {runAsNonRoot: true, runAsUser: 65534, seccompProfile: {type: RuntimeDefault}}
      containers:
      - name: load
        image: ${LOAD_IMG}
        command: ["sh","-c","while true; do wget -q -O /dev/null -T 2 http://${NAME}/ || true; sleep 0.2; done"]
        resources: {requests: {cpu: 5m, memory: 8Mi}, limits: {memory: 16Mi}}
        securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
---
apiVersion: phorvex.ai/v1alpha1
kind: PhorvexPolicy
metadata: {name: ${NAME}-defense, namespace: ${DEMO}, labels: {app.kubernetes.io/part-of: phorvex-demo, phorvex.ai/redteam-runner: phvx-attack}}
spec:
  tenant: ${DEMO}
  mode: active
  selector: {matchLabels: {app.kubernetes.io/name: ${NAME}}}
  actions: {enabled: [rotate]}
  assetValue:
    blastRadiusFromGraph: true
    fromLabels: {data-class: {internal: "0.4", public: "0.1", restricted: "1.0"}}
    weightSecrets: "0.8"
  budget: {antiOverRotationWindow: 90s, maxGracePeriodSeconds: 30, maxMovesPerTick: 1, proactiveFloor: 15m, tickInterval: 5s}
  objective: {costWeights: {flowDisruption: "0.6", normSparsity: "0.4"}, disruptionAversion: "1", lambda: "0"}
  slo: {costCeiling: "1.2", minAvailableReplicas: 1}
  triggers: {eventAgeHorizon: 1h, eventDriven: true, reactiveOnly: true}
YAML
echo "applied $DEMO/$NAME — wait for: k -n $DEMO rollout status ds/$NAME (expect ${REPLICAS} ready)"
