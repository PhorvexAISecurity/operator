#!/usr/bin/env bash
# lane-throttle-fixture.sh <N> [up|ensure|down] — stand up the serving-rate (throttle)
# fixture on lane pN's demo namespace, parametrized to pN-demo via the operator's
# PHORVEX_THROTTLE_* profile (de-hardcoded cost-defense contract, branch
# feat/throttle-param-lane @ 80387795).
#
# Runs ON the gateway (local kubectl). The lane operator (pN-{phorvex,brain,sensor,
# actuator}) MUST already run the throttle-param images with the lane profile env
# (deploy step: set-image + set env PHORVEX_THROTTLE_*). This script provisions only the
# pN-demo serving-app substrate + the cluster RBAC its detector needs.
#
# Modes:
#   up      : apply the standing stack, then (re)calibrate + arm the budget (reference clients).
#   ensure  : apply the standing stack; calibrate+arm ONLY if the budget is not already armed
#             (idempotent; the per-fire entrypoint used by phvx-attack.py).
#   down    : delete the fixture (standing stack + any transient load + cluster RBAC).
#
# Env: FIX_IMG (fixture image by digest), SRC_SHA (64-hex approval token == the proxy image
#      digest hex), NODE (pin for pod-IP identity discipline).
set -euo pipefail

N="${1:?usage: lane-throttle-fixture.sh <N> [up|ensure|down]}"
MODE="${2:-ensure}"
DEMO="p${N}-demo"; OPNS="p${N}"; MGR="deploy/p${N}-phorvex"
FIX_IMG="${FIX_IMG:-753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex@sha256:97e9f88e46624cc0c7fecc8d5e1aef0a01f10773b3416578e1e9413d02fafc93}"
SRC_SHA="${SRC_SHA:-97e9f88e46624cc0c7fecc8d5e1aef0a01f10773b3416578e1e9413d02fafc93}"
NODE="${NODE:-ip-172-27-11-194.us-east-2.compute.internal}"
ABUSIVE="system:serviceaccount:${DEMO}:rate-abusive"
LEGIT="system:serviceaccount:${DEMO}:rate-legit"
log() { printf '\033[1;36m[throttle-fixture %s]\033[0m %s\n' "$DEMO" "$*"; }

render_stack() {
cat <<YAML
apiVersion: v1
kind: ServiceAccount
metadata: {name: rate-admission, namespace: ${DEMO}, labels: {phorvex.ai/fixture: serving-rate}}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: rate-detector, namespace: ${DEMO}, labels: {phorvex.ai/fixture: serving-rate}}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: rate-abusive, namespace: ${DEMO}, labels: {phorvex.ai/fixture: serving-rate}}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: rate-legit, namespace: ${DEMO}, labels: {phorvex.ai/fixture: serving-rate}}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: rate-admission, namespace: ${DEMO}, labels: {phorvex.ai/fixture: serving-rate}}
rules:
- {apiGroups: [""], resources: ["configmaps"], verbs: ["get","list","update"]}
- {apiGroups: [""], resources: ["pods"], verbs: ["get","list"]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: rate-admission, namespace: ${DEMO}, labels: {phorvex.ai/fixture: serving-rate}}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: rate-admission}
subjects: [{kind: ServiceAccount, name: rate-admission, namespace: ${DEMO}}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: rate-detector, namespace: ${DEMO}, labels: {phorvex.ai/fixture: serving-rate}}
rules:
- {apiGroups: [""], resources: ["configmaps","pods","services"], verbs: ["get","list"]}
- {apiGroups: ["apps"], resources: ["deployments","replicasets"], verbs: ["get","list"]}
- {apiGroups: ["phorvex.ai"], resources: ["phorvexpolicies"], verbs: ["get","list"]}
- {apiGroups: ["discovery.k8s.io"], resources: ["endpointslices"], verbs: ["get","list"]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: rate-detector, namespace: ${DEMO}, labels: {phorvex.ai/fixture: serving-rate}}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: rate-detector}
subjects: [{kind: ServiceAccount, name: rate-detector, namespace: ${DEMO}}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: ${OPNS}-rate-detector-se, labels: {phorvex.ai/fixture: serving-rate}}
rules:
- {apiGroups: ["amtd.r6security.com"], resources: ["securityevents"], verbs: ["get","list","watch","create"]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: ${OPNS}-rate-detector-se, labels: {phorvex.ai/fixture: serving-rate}}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: ${OPNS}-rate-detector-se}
subjects: [{kind: ServiceAccount, name: rate-detector, namespace: ${DEMO}}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: rate-target, namespace: ${DEMO}, labels: {app: rate-target}}
spec:
  replicas: 1
  selector: {matchLabels: {app: rate-target}}
  template:
    metadata: {labels: {app: rate-target}}
    spec:
      nodeSelector: {kubernetes.io/hostname: ${NODE}}
      automountServiceAccountToken: false
      securityContext: {runAsNonRoot: true, runAsUser: 65534, seccompProfile: {type: RuntimeDefault}}
      containers:
      - name: svc
        image: docker.io/hashicorp/http-echo:1.0.0
        args: ["-text=ok","-listen=:8080"]
        ports: [{containerPort: 8080}]
        resources: {requests: {cpu: 50m, memory: 32Mi}, limits: {cpu: 100m, memory: 64Mi}}
        securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}}
---
apiVersion: v1
kind: Service
metadata: {name: rate-target-backend, namespace: ${DEMO}, labels: {phorvex.ai/fixture: serving-rate}}
spec:
  selector: {app: rate-target}
  ports: [{port: 8080, targetPort: 8080}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: rate-admission, namespace: ${DEMO}, labels: {app: rate-admission}}
spec:
  replicas: 1
  strategy: {type: Recreate}
  selector: {matchLabels: {app: rate-admission}}
  template:
    metadata: {labels: {app: rate-admission}}
    spec:
      nodeSelector: {kubernetes.io/hostname: ${NODE}}
      serviceAccountName: rate-admission
      securityContext: {runAsNonRoot: true, seccompProfile: {type: RuntimeDefault}}
      containers:
      - name: proxy
        image: ${FIX_IMG}
        command: ["/cost-admission"]
        env:
        - {name: POD_NAMESPACE, valueFrom: {fieldRef: {fieldPath: metadata.namespace}}}
        - {name: POD_UID, valueFrom: {fieldRef: {fieldPath: metadata.uid}}}
        - {name: PHORVEX_THROTTLE_BACKEND, value: rate-target-backend}
        ports: [{containerPort: 8080}]
        resources: {requests: {cpu: 50m, memory: 32Mi}, limits: {cpu: 500m, memory: 128Mi}}
        securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}}
---
apiVersion: v1
kind: Service
metadata: {name: rate-target, namespace: ${DEMO}, labels: {phorvex.ai/fixture: serving-rate}}
spec:
  selector: {app: rate-admission}
  ports: [{port: 80, targetPort: 8080}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: rate-detector, namespace: ${DEMO}, labels: {app: rate-detector}}
spec:
  replicas: 1
  selector: {matchLabels: {app: rate-detector}}
  template:
    metadata: {labels: {app: rate-detector}}
    spec:
      nodeSelector: {kubernetes.io/hostname: ${NODE}}
      serviceAccountName: rate-detector
      securityContext: {runAsNonRoot: true, seccompProfile: {type: RuntimeDefault}}
      containers:
      - name: detector
        image: ${FIX_IMG}
        command: ["/cost-load-detector"]
        env:
        - {name: PHORVEX_THROTTLE_NAMESPACE, value: ${DEMO}}
        - {name: PHORVEX_THROTTLE_POLICY, value: serving-rate-defense}
        - {name: PHORVEX_THROTTLE_DETECTOR_IDENTITY, value: "system:serviceaccount:${DEMO}:rate-detector"}
        - {name: PHORVEX_THROTTLE_SOURCE, value: phorvex-rate-detector-${OPNS}}
        - {name: PHORVEX_THROTTLE_EVENT_LABEL, value: phorvex.ai/rate-detector-${OPNS}}
        - {name: PHORVEX_THROTTLE_DEPLOYMENT, value: rate-admission}
        - {name: PHORVEX_THROTTLE_SERVICE, value: rate-target}
        - {name: PHORVEX_THROTTLE_BACKEND, value: rate-target-backend}
        - {name: PHORVEX_THROTTLE_TARGET_APP, value: rate-target}
        - {name: PHORVEX_THROTTLE_SOURCE_SHA256, value: "${SRC_SHA}"}
        - {name: PHORVEX_THROTTLE_PROXY_IMAGE, value: "${FIX_IMG}"}
        resources: {requests: {cpu: 20m, memory: 32Mi}, limits: {cpu: 200m, memory: 64Mi}}
        securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}}
---
apiVersion: v1
kind: ConfigMap
metadata: {name: phorvex-throttle-journal, namespace: ${OPNS}, labels: {phorvex.ai/fixture: serving-rate}}
data: {}
---
apiVersion: phorvex.ai/v1alpha1
kind: PhorvexPolicy
metadata: {name: serving-rate-defense, namespace: ${DEMO}}
spec:
  mode: active
  tenant: ${DEMO}
  selector: {matchLabels: {app: rate-target}}
  actions: {enabled: ["throttle"]}
  assetValue: {blastRadiusFromGraph: true, fromLabels: {app: {rate-target: "1.0"}}, weightSecrets: "0.8"}
  budget: {antiOverRotationWindow: "10s", maxGracePeriodSeconds: 30, maxMovesPerTick: 2, proactiveFloor: "10s", tickInterval: "5s"}
  objective: {costWeights: {flowDisruption: "0.6", normSparsity: "0.4"}, lambda: "0.2"}
  slo: {costCeiling: "1.2", minAvailableReplicas: 1}
  triggers: {eventAgeHorizon: "1h", eventDriven: true, reactiveOnly: true}
YAML
}

render_budget() {
cat <<YAML
apiVersion: v1
kind: ConfigMap
metadata: {name: phorvex-serving-rate-budget, namespace: ${DEMO}, labels: {phorvex.ai/fixture: serving-rate}}
data:
  state.json: |
    {"version":1,"revision":1,"sourceSHA256":"${SRC_SHA}","proxyImage":"${FIX_IMG}","abusiveAccount":"${ABUSIVE}","legitimateAccount":"${LEGIT}","path":"/","calibrating":false,"enabled":false,"baseline":0,"reserved":0,"burst":0}
---
apiVersion: v1
kind: ConfigMap
metadata: {name: phorvex-serving-rate-status, namespace: ${DEMO}, labels: {phorvex.ai/fixture: serving-rate}}
data: {state.json: "{}"}
YAML
}

ref_client() { # name sa
cat <<YAML
apiVersion: batch/v1
kind: Job
metadata: {name: $1, namespace: ${DEMO}, labels: {phorvex.ai/fixture: serving-rate-ref}}
spec:
  activeDeadlineSeconds: 240
  ttlSecondsAfterFinished: 600
  backoffLimit: 0
  template:
    metadata: {labels: {app: $1}}
    spec:
      nodeSelector: {kubernetes.io/hostname: ${NODE}}
      serviceAccountName: $2
      automountServiceAccountToken: false
      restartPolicy: Never
      securityContext: {runAsNonRoot: true, runAsUser: 65532, seccompProfile: {type: RuntimeDefault}}
      containers:
      - name: client
        image: ${FIX_IMG}
        command: ["/cost-client"]
        args: ["--qps=2","--duration=120s","--url=http://rate-target.${DEMO}.svc/"]
        resources: {requests: {cpu: 20m, memory: 32Mi}, limits: {cpu: 200m, memory: 64Mi}}
        securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}}
YAML
}

budget_enabled() { kubectl -n "$DEMO" get cm phorvex-serving-rate-budget -o jsonpath='{.data.state\.json}' 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin).get("enabled"))' 2>/dev/null || echo MISSING; }
status_armed() { kubectl -n "$DEMO" get cm phorvex-serving-rate-status -o jsonpath='{.data.state\.json}' 2>/dev/null | python3 -c 'import sys,json;s=json.load(sys.stdin);print("ARMED" if (s.get("baseline",0)>0 and s.get("reserved",0)>0 and s["contract"]["enabled"] is False and s["contract"]["calibrating"] is False) else "NO")' 2>/dev/null || echo NO; }

down() {
  log "deleting fixture"
  kubectl -n "$DEMO" delete deploy,svc,cm,sa,role,rolebinding,job -l phorvex.ai/fixture --ignore-not-found --wait=false 2>/dev/null || true
  kubectl -n "$DEMO" delete job -l phorvex.ai/fixture=serving-rate-ref --ignore-not-found --wait=false 2>/dev/null || true
  kubectl -n "$DEMO" delete job -l phorvex.ai/fixture=serving-rate-load --ignore-not-found --wait=false 2>/dev/null || true
  kubectl -n "$DEMO" delete phorvexpolicy serving-rate-defense --ignore-not-found 2>/dev/null || true
  kubectl -n "$OPNS" delete cm phorvex-throttle-journal --ignore-not-found 2>/dev/null || true
  kubectl delete clusterrole,clusterrolebinding "${OPNS}-rate-detector-se" --ignore-not-found 2>/dev/null || true
  log "fixture down"
}

budget_exists() { kubectl -n "$DEMO" get cm phorvex-serving-rate-budget >/dev/null 2>&1 && echo yes || echo no; }

apply_stack() {
  # Core objects (SA/RBAC/deploys/svcs/journal/policy) — safe to re-apply (idempotent, no
  # restart on an unchanged spec). The stateful budget + status CMs are NOT here: they hold
  # the proxy's measured calibration + the live operation, so re-applying them would clobber
  # an armed budget. They are provisioned separately (apply_budget) only when fresh.
  log "applying standing stack (parametrized to ${DEMO})"
  render_stack | kubectl apply --server-side --force-conflicts -f - >/dev/null
  log "waiting proxy + detector + target Ready"
  kubectl -n "$DEMO" rollout status deploy/rate-admission --timeout=120s >/dev/null
  kubectl -n "$DEMO" rollout status deploy/rate-detector  --timeout=120s >/dev/null
  kubectl -n "$DEMO" rollout status deploy/rate-target    --timeout=120s >/dev/null
}

apply_budget() {
  log "provisioning fresh (unarmed) budget + status CMs"
  render_budget | kubectl apply --server-side --force-conflicts -f - >/dev/null
}

calibrate_arm() {
  log "launching quiet reference clients (both accounts) for calibration"
  kubectl -n "$DEMO" delete job rate-ref-abusive rate-ref-legit --ignore-not-found --wait=false >/dev/null 2>&1 || true
  ref_client rate-ref-abusive rate-abusive | kubectl apply -f - >/dev/null
  ref_client rate-ref-legit   rate-legit   | kubectl apply -f - >/dev/null
  for i in $(seq 1 20); do
    n=$(kubectl -n "$DEMO" get pods -l 'app in (rate-ref-abusive,rate-ref-legit)' -o jsonpath='{range .items[*]}{.status.phase}{"\n"}{end}' 2>/dev/null | grep -c Running || true)
    [ "${n:-0}" -ge 2 ] && break; sleep 3
  done
  sleep 6
  log "calibrate"
  kubectl -n "$OPNS" exec "$MGR" -c manager -- /cost-budget-admin --mode=calibrate
  log "waiting for measured quiet window (calibrationEnd)"
  for i in $(seq 1 25); do
    ready=$(kubectl -n "$DEMO" get cm phorvex-serving-rate-status -o jsonpath='{.data.state\.json}' | python3 -c 'import sys,json,datetime
s=json.load(sys.stdin);cs=s.get("calibrationStart","");ce=s.get("calibrationEnd","")
try:
  d=(datetime.datetime.fromisoformat(ce.replace("Z","+00:00"))-datetime.datetime.fromisoformat(cs.replace("Z","+00:00"))).total_seconds()
  print("1" if (d>=60 and s.get("baseline",0)>0 and s.get("reserved",0)>0) else "0")
except Exception: print("0")')
    [ "$ready" = "1" ] && { log "calibration complete"; break; }
    sleep 4
  done
  log "arm"
  kubectl -n "$OPNS" exec "$MGR" -c manager -- /cost-budget-admin --mode=arm
  kubectl -n "$DEMO" delete job rate-ref-abusive rate-ref-legit --ignore-not-found --wait=false >/dev/null 2>&1 || true
  [ "$(status_armed)" = "ARMED" ] || { echo "ERROR: budget not armed after calibrate/arm" >&2; exit 1; }
  log "ARMED: $(kubectl -n "$DEMO" get cm phorvex-serving-rate-status -o jsonpath='{.data.state\.json}' | python3 -c 'import sys,json;s=json.load(sys.stdin);print("baseline=%.3f reserved=%.3f"%(s["baseline"],s["reserved"]))')"
}

case "$MODE" in
  down) down ;;
  up)
    apply_stack
    apply_budget                 # force a fresh unarmed budget, then calibrate+arm
    kubectl -n "$OPNS" patch cm phorvex-throttle-journal --type merge -p '{"data":{"state.json":""}}' >/dev/null 2>&1 || true
    calibrate_arm
    ;;
  ensure)
    apply_stack
    [ "$(budget_exists)" = "no" ] && apply_budget
    if [ "$(status_armed)" = "ARMED" ] && [ "$(budget_enabled)" = "False" ]; then
      log "budget already armed+quiet — reusing standing fixture (budget/status CMs untouched)"
    else
      [ "$(budget_exists)" = "yes" ] || apply_budget
      calibrate_arm
    fi
    ;;
  *) echo "unknown mode $MODE (up|ensure|down)" >&2; exit 1 ;;
esac
log "done ($MODE)"
