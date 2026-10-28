#!/usr/bin/env bash
# lane-ncdr-fixture.sh <N> — stand up the node-cordon-drain-replace (node-recycle) fixture in
# lane pN. Reproducible + idempotent. Prereq: lane pN is UP and its operator stack runs a build
# that contains the node-cordon-drain-replace actuator (ECR tag :ncdr-p4; op-p4 @4d36a15).
#
# The node-recycle actuator's whole effect surface is k8s control-plane node/pod orchestration, so
# the substrate is a LANE-SCOPED kwok node-group (DISCLOSED fidelity: Node objects / scheduler /
# Eviction API / Node-delete are 100% real, only the kubelet/compute is simulated). kwok nodes
# consume NO aws-cni pod IPs, so this is safe under farm IP exhaustion.
#
# Stands up:
#   1. a lane-scoped kwok controller (manages ONLY nodes annotated phorvex.ai/kwok-lane=pN)
#   2. two kwok nodes  pN-node-a (compromised stand-in) + pN-node-b (healthy)
#   3. demo-api  = 3x pause, kwok-pinned (nodeSelector phorvex.ai/lane=pN + kwok toleration) + PDB
#   4. the node-defense PhorvexPolicy (enabled [node-cordon-drain-replace,rotate,quarantine])
#   5. cluster-scoped node/pod/eviction RBAC for the lane manager + actuator SAs
#
# The per-fire preconditions (nodes Ready, demo 3/3, a pod on node-a) are RE-ESTABLISHED by the
# phvx-attack.py node-recycle adapter on every `fire`, so this script is the one-time substrate.
#
# Usage:  ./lane-ncdr-fixture.sh <N>
# Env:    GW=phorvex-gw  KWOK_IMAGE=registry.k8s.io/kwok/kwok:v0.8.0
set -euo pipefail
N="${1:?usage: lane-ncdr-fixture.sh <N>  (N in 1..10)}"
[[ "$N" =~ ^([1-9]|10)$ ]] || { echo "N must be 1..10" >&2; exit 1; }
LANE="p${N}"; NS="$LANE"; DEMO="${LANE}-demo"
GW="${GW:-phorvex-gw}"
KWOK_IMAGE="${KWOK_IMAGE:-registry.k8s.io/kwok/kwok:v0.8.0}"
MGR_SA="${MGR_SA:-${LANE}-phorvex-manager}"
ACT_SA="${ACT_SA:-${LANE}-actuator}"
APPLY() { ssh -o BatchMode=yes "$GW" kubectl apply --server-side --force-conflicts -f - ; }
KUBE()  { ssh -o BatchMode=yes "$GW" kubectl "$@"; }
log() { printf '\033[1;35m[ncdr-fixture %s]\033[0m %s\n' "$LANE" "$*"; }

log "preflight: kwok CRDs + default Stage CRs present on cluster"
KUBE get crd stages.kwok.x-k8s.io >/dev/null 2>&1 || {
  echo "ERROR: kwok CRDs absent. Install kwok v0.8.0 stage + CRDs cluster-wide first." >&2; exit 1; }

# ---------------------------------------------------------------------------
# 1. lane-scoped kwok controller (hostNetwork -> no pod IP; tolerates CriticalAddonsOnly so it can
#    land on a lightly-loaded node; --enable-crds=Stage consumes the cluster's existing default
#    Stage CRs; CLI flags only (a partial --config zeroes parallelism defaults -> crashloop)).
# ---------------------------------------------------------------------------
log "kwok controller (manage-nodes-with-annotation-selector=phorvex.ai/kwok-lane=$LANE)"
cat <<YAML | APPLY
apiVersion: v1
kind: ServiceAccount
metadata: {name: kwok-controller-$LANE, namespace: $DEMO, labels: {app: kwok-controller-$LANE, phorvex.ai/lane: $LANE}}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: kwok-controller-$LANE, labels: {phorvex.ai/lane: $LANE}}
rules:
- {apiGroups: [""], resources: [events], verbs: [create,delete,get,list,patch,update,watch]}
- {apiGroups: [""], resources: [nodes], verbs: [get,list,watch]}
- {apiGroups: [""], resources: [nodes/status,pods/status], verbs: [patch,update]}
- {apiGroups: [""], resources: [pods], verbs: [delete,get,list,patch,update,watch]}
- {apiGroups: [coordination.k8s.io], resources: [leases], verbs: [create,get,list,patch,update,watch]}
- {apiGroups: [kwok.x-k8s.io], resources: [stages,metrics,attaches,clusterattaches,execs,clusterexecs,logs,clusterlogs,portforwards,clusterportforwards,resourceusages,clusterresourceusages], verbs: [get,list,watch]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: kwok-controller-$LANE, labels: {phorvex.ai/lane: $LANE}}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: kwok-controller-$LANE}
subjects: [{kind: ServiceAccount, name: kwok-controller-$LANE, namespace: $DEMO}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: kwok-controller-$LANE, namespace: $DEMO, labels: {app: kwok-controller-$LANE, phorvex.ai/lane: $LANE}}
spec:
  replicas: 1
  selector: {matchLabels: {app: kwok-controller-$LANE}}
  template:
    metadata: {labels: {app: kwok-controller-$LANE}}
    spec:
      serviceAccountName: kwok-controller-$LANE
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      tolerations:
      - {key: CriticalAddonsOnly, operator: Exists}
      containers:
      - name: kwok
        image: $KWOK_IMAGE
        args:
        - "--manage-all-nodes=false"
        - "--manage-nodes-with-annotation-selector=phorvex.ai/kwok-lane=$LANE"
        - "--node-ip=\$(POD_IP)"
        - "--node-lease-duration-seconds=40"
        - "--enable-crds=Stage"
        env:
        - {name: POD_IP, valueFrom: {fieldRef: {fieldPath: status.podIP}}}
YAML

log "waiting for kwok controller Ready"
KUBE -n "$DEMO" rollout status deploy/kwok-controller-$LANE --timeout=120s || true

# ---------------------------------------------------------------------------
# 2. two kwok nodes (node-a compromised stand-in, node-b healthy). Annotated into the lane's kwok
#    controller; NoSchedule taint phorvex.ai/kwok so ONLY kwok-tolerating fixture pods land here.
# ---------------------------------------------------------------------------
log "kwok nodes $LANE-node-a + $LANE-node-b"
for S in a b; do
cat <<YAML | APPLY
apiVersion: v1
kind: Node
metadata:
  name: $LANE-node-$S
  annotations: {node.alpha.kubernetes.io/ttl: "0", kwok.x-k8s.io/node: fake, phorvex.ai/kwok-lane: $LANE}
  labels: {type: kwok, phorvex.ai/lane: $LANE, kubernetes.io/hostname: $LANE-node-$S, kubernetes.io/arch: amd64, kubernetes.io/os: linux, node-role.kubernetes.io/agent: ""}
spec:
  taints: [{key: phorvex.ai/kwok, value: "true", effect: NoSchedule}]
  unschedulable: false
status:
  allocatable: {cpu: "32", memory: 256Gi, pods: "110"}
  capacity: {cpu: "32", memory: 256Gi, pods: "110"}
  nodeInfo: {kubeletVersion: fake-kwok}
YAML
done

# ---------------------------------------------------------------------------
# 3. demo-api = 3x pause, kwok-pinned. topologySpread keeps replicas across both nodes; PDB bounds
#    the drain. data-class=internal gives the policy a non-trivial asset value.
# ---------------------------------------------------------------------------
log "demo-api (3x pause, kwok-pinned) + PDB -> $DEMO"
cat <<YAML | APPLY
apiVersion: apps/v1
kind: Deployment
metadata: {name: demo-api, namespace: $DEMO, labels: {app.kubernetes.io/name: demo-api, app.kubernetes.io/part-of: phorvex-demo}}
spec:
  replicas: 3
  selector: {matchLabels: {app.kubernetes.io/name: demo-api}}
  template:
    metadata: {labels: {app.kubernetes.io/name: demo-api, app.kubernetes.io/part-of: phorvex-demo, data-class: internal}}
    spec:
      nodeSelector: {phorvex.ai/lane: $LANE}
      tolerations: [{key: phorvex.ai/kwok, operator: Equal, value: "true", effect: NoSchedule}]
      terminationGracePeriodSeconds: 5
      topologySpreadConstraints:
      - {maxSkew: 1, topologyKey: kubernetes.io/hostname, whenUnsatisfiable: ScheduleAnyway, labelSelector: {matchLabels: {app.kubernetes.io/name: demo-api}}}
      containers:
      - name: web
        image: registry.k8s.io/pause:3.9
        resources: {requests: {cpu: 100m, memory: 64Mi}}
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata: {name: demo-api, namespace: $DEMO}
spec: {maxUnavailable: 1, selector: {matchLabels: {app.kubernetes.io/name: demo-api}}}
YAML

# ---------------------------------------------------------------------------
# 4. node-defense PhorvexPolicy. Enables node-cordon-drain-replace alongside rotate+quarantine so
#    the brain must CHOOSE the node recycle for a host-escape (the AttackVector steers to it and
#    Gate 0 proves it beats both head-to-head). minAvailableReplicas 2, ceiling 1.2.
# ---------------------------------------------------------------------------
log "PhorvexPolicy node-defense (tenant $DEMO)"
cat <<YAML | APPLY
apiVersion: phorvex.ai/v1alpha1
kind: PhorvexPolicy
metadata: {name: node-defense, namespace: $DEMO, labels: {app.kubernetes.io/part-of: phorvex-demo}}
spec:
  tenant: $DEMO
  mode: active
  selector: {matchLabels: {app.kubernetes.io/name: demo-api}}
  actions: {enabled: [node-cordon-drain-replace, rotate, quarantine]}
  assetValue:
    blastRadiusFromGraph: true
    fromLabels: {data-class: {internal: "0.4", public: "0.1", restricted: "1.0"}}
    weightSecrets: "0.8"
  budget: {antiOverRotationWindow: 90s, maxGracePeriodSeconds: 30, maxMovesPerTick: 1, proactiveFloor: 15m, tickInterval: 5s}
  objective: {costWeights: {flowDisruption: "0.6", normSparsity: "0.4"}, disruptionAversion: "1", lambda: "0"}
  slo: {costCeiling: "1.2", minAvailableReplicas: 2}
  triggers: {eventAgeHorizon: 1h, eventDriven: true, reactiveOnly: true}
YAML

# ---------------------------------------------------------------------------
# 5. cluster-scoped node/pod/eviction RBAC for the manager (capability SSAR gate) + actuator SAs.
#    Node verbs are cluster-scoped (authz.Verb.ClusterScoped=true); stock lane-up grants neither SA
#    node verbs (only pods/eviction for rotate).
# ---------------------------------------------------------------------------
log "RBAC $LANE-node-cordon-drain-replace -> $MGR_SA + $ACT_SA"
cat <<YAML | APPLY
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: $LANE-node-cordon-drain-replace, labels: {phorvex.ai/lane: $LANE}}
rules:
- {apiGroups: [""], resources: [nodes], verbs: [get,list,watch,patch,update,delete]}
- {apiGroups: [""], resources: [pods], verbs: [get,list,delete]}
- {apiGroups: [""], resources: [pods/eviction], verbs: [create]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: $LANE-node-cordon-drain-replace, labels: {phorvex.ai/lane: $LANE}}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: $LANE-node-cordon-drain-replace}
subjects:
- {kind: ServiceAccount, name: $MGR_SA, namespace: $NS}
- {kind: ServiceAccount, name: $ACT_SA, namespace: $NS}
YAML

log "done. nodes:";  KUBE get nodes -l phorvex.ai/lane=$LANE 2>/dev/null || true
log "demo pods:";    KUBE -n "$DEMO" get pods -l app.kubernetes.io/name=demo-api -o wide 2>/dev/null || true
