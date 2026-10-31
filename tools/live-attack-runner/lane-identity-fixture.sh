#!/usr/bin/env bash
# lane-identity-fixture.sh <N> [ensure|down|ids] — stand up / tear down the ISOLATED
# identity-rotate substrate for Phorvex verification lane pN.
#
# RUNS ON THE GATEWAY (scp'd there + `bash lane-identity-fixture.sh N ensure`), so kubectl
# and aws run natively — no ssh arg-mangling. Fully additive + reversible; never touches
# phorvex-staging or console-identity-shared (the frozen reference / staging identity stack).
#
# The deployed lane brain image (cost-c1e9d5f0 == HEAD of feat/cost-harvest-newstack, which is
# STACKED on feat/identity-rotate-newstack @ 5879529c) carries the REAL identity-rotate port:
# model/identity_rotation.go, actuator/identity_rotation.go, internal/identityfixture, the
# un-gated gate/generator/recon/slo, the SSAR + kill-switch actuator authority. So a lane CAN
# select+actuate identity-rotate once its OWN identity substrate exists. This provisions it:
#
#   console-identity-pN (owned ns) + console-id-fixture Deployment/SA/Pod (the EXACT
#   identityfixture.Observe contract) + a console-id-fixture PhorvexPolicy (identity-rotate
#   enabled) + the sensor-reader & actuator-mutator Roles + a Profile ConfigMap (EKS/policy
#   pins) mounted on the lane sensor + an EKS Pod Identity association for pN-sensor (so the
#   sensor's identityfixture.FederationAbsent EKS read has credentials) + console-identity-pN
#   added to --policy-namespaces on the lane manager/sensor/actuator.
#
# Usage:  bash lane-identity-fixture.sh <N> ensure   # idempotent provision
#         bash lane-identity-fixture.sh <N> down     # full teardown
#         bash lane-identity-fixture.sh <N> ids      # print nsUID/policyUID/gen JSON
set -euo pipefail

N="${1:?usage: lane-identity-fixture.sh <N> [ensure|down|ids]}"
SUB="${2:-ensure}"
LANE="p${N}"
OPNS="${LANE}"                      # operator namespace (manager/brain/sensor/actuator + journal + killswitch)
FNS="console-identity-${LANE}"     # fixture namespace (MUST start with console-identity-)
FIX="console-id-fixture"           # run name: SA + Deployment + marker (MUST start with console-id-)
FLABEL="phorvex.ai/console-identity-fixture"
IMAGE="docker.io/library/python@sha256:e88e9763f943ec1834f992a4b51e0f24500486803e8bc534e5767af9ea65f6ce"
ROLE_ARN="arn:aws:iam::753556437180:role/phorvex-dev-operator-federation-read"
CLUSTER="phorvex-dev-eks"
REGION="us-east-2"
PROFILE_CM="${LANE}-identity-fixture-profile"
SENSOR="${LANE}-sensor"; MANAGER="${LANE}-phorvex"; ACTUATOR="${LANE}-actuator"

log(){ printf '\033[1;35m[id-fixture %s]\033[0m %s\n' "$LANE" "$*" >&2; }
apply(){ kubectl apply --server-side --force-conflicts -f - ; }

# --- add/remove FNS on a deployment's --policy-namespaces arg (targeted JSON patch) ---
scope_add(){
  local dep="$1"
  local idx cur
  idx=$(kubectl -n "$OPNS" get deploy "$dep" -o json | jq '.spec.template.spec.containers[0].args | map(startswith("--policy-namespaces=")) | index(true)')
  [ "$idx" = "null" ] && { log "WARN: $dep has no --policy-namespaces arg"; return 0; }
  cur=$(kubectl -n "$OPNS" get deploy "$dep" -o json | jq -r ".spec.template.spec.containers[0].args[$idx]")
  case ",${cur#--policy-namespaces=}," in *",$FNS,"*) log "$dep scope already has $FNS"; return 0;; esac
  kubectl -n "$OPNS" patch deploy "$dep" --type=json \
    -p "[{\"op\":\"replace\",\"path\":\"/spec/template/spec/containers/0/args/$idx\",\"value\":\"$cur,$FNS\"}]"
  log "$dep scope += $FNS"
}
scope_del(){
  local dep="$1"
  local idx cur new
  idx=$(kubectl -n "$OPNS" get deploy "$dep" -o json 2>/dev/null | jq '.spec.template.spec.containers[0].args | map(startswith("--policy-namespaces=")) | index(true)' 2>/dev/null || echo null)
  [ "$idx" = "null" ] && return 0
  cur=$(kubectl -n "$OPNS" get deploy "$dep" -o json | jq -r ".spec.template.spec.containers[0].args[$idx]")
  new=$(printf '%s' "$cur" | sed -e "s/,$FNS//g" -e "s/$FNS,//g")
  [ "$new" = "$cur" ] && return 0
  kubectl -n "$OPNS" patch deploy "$dep" --type=json \
    -p "[{\"op\":\"replace\",\"path\":\"/spec/template/spec/containers/0/args/$idx\",\"value\":\"$new\"}]"
  log "$dep scope -= $FNS"
}

# --- allow the lane detector (pN-attacks) to target the fixture ns in the pN-attacks-targets VAP ---
_find_vap(){ kubectl get validatingadmissionpolicy -o json | jq -r ".items[]|select(.metadata.name|startswith(\"${LANE}-attacks-targets-\"))|.metadata.name" | head -1; }
vap_scope_add(){
  local vap expr newexpr
  vap=$(_find_vap); [ -z "$vap" ] && { log "WARN: no ${LANE}-attacks-targets VAP found (fixture events may be denied)"; return 0; }
  expr=$(kubectl get validatingadmissionpolicy "$vap" -o jsonpath='{.spec.validations[0].expression}')
  case "$expr" in *"\"$FNS\""*) log "VAP $vap already allows $FNS"; return 0;; esac
  newexpr=$(printf '%s' "$expr" | sed "s/\[\"${LANE}-demo\"\]/[\"${LANE}-demo\",\"${FNS}\"]/")
  [ "$newexpr" = "$expr" ] && { log "WARN: could not inject $FNS into VAP $vap expression"; return 0; }
  kubectl patch validatingadmissionpolicy "$vap" --type=json \
    -p "[{\"op\":\"replace\",\"path\":\"/spec/validations/0/expression\",\"value\":$(printf '%s' "$newexpr" | jq -Rs .)}]"
  log "VAP $vap target-scope += $FNS"
}
vap_scope_del(){
  local vap expr newexpr
  vap=$(_find_vap); [ -z "$vap" ] && return 0
  expr=$(kubectl get validatingadmissionpolicy "$vap" -o jsonpath='{.spec.validations[0].expression}' 2>/dev/null || true)
  case "$expr" in *"\"$FNS\""*) ;; *) return 0;; esac
  newexpr=$(printf '%s' "$expr" | sed -e "s/,\"${FNS}\"//g" -e "s/\"${FNS}\",//g")
  [ "$newexpr" = "$expr" ] && return 0
  kubectl patch validatingadmissionpolicy "$vap" --type=json \
    -p "[{\"op\":\"replace\",\"path\":\"/spec/validations/0/expression\",\"value\":$(printf '%s' "$newexpr" | jq -Rs .)}]"
  log "VAP $vap target-scope -= $FNS"
}

ensure(){
  # 1. fixture namespace (owner-provisioned, otherwise unused; owned label)
  log "namespace $FNS (owned)"
  cat <<YAML | apply
apiVersion: v1
kind: Namespace
metadata:
  name: $FNS
  labels: {${FLABEL}: owned, phorvex.ai/lane: "$LANE", phorvex.ai/purpose: farm-lane-identity}
YAML

  # 2. dedicated ServiceAccount (labeled run; automount OFF so the pod carries ONE projected volume)
  log "ServiceAccount $FNS/$FIX"
  cat <<YAML | apply
apiVersion: v1
kind: ServiceAccount
metadata:
  name: $FIX
  namespace: $FNS
  labels: {${FLABEL}: $FIX}
automountServiceAccountToken: false
YAML

  # 3. fixture Deployment — the EXACT identityfixture.Observe contract (byte-identical to the
  #    staging console-id-fixture): 1 "workload" container, pinned python image, a non-terminating
  #    sleep command (NEVER a bounded sleep — the observer requires restartCount==0, so a workload
  #    that exits and is restarted makes the fixture permanently unobservable), 1 projected "api"
  #    volume (600s default-audience token + ca.crt + namespace), 1 readOnly mount at the default
  #    SA path, replicas 1. strategy=Recreate so a rollout never briefly runs two pods (the observer
  #    admits exactly one consumer Pod) and the old host-network IP is freed before the new pod.
  log "Deployment $FNS/$FIX"
  cat <<YAML | apply
apiVersion: apps/v1
kind: Deployment
metadata:
  name: $FIX
  namespace: $FNS
  labels: {${FLABEL}: $FIX}
spec:
  replicas: 1
  strategy: {type: Recreate}
  selector:
    matchLabels: {${FLABEL}: $FIX}
  template:
    metadata:
      labels: {${FLABEL}: $FIX}
    spec:
      serviceAccountName: $FIX
      automountServiceAccountToken: false
      # hostNetwork: the farm's warm /28 prefix pools are IP-exhausted under ~7 lanes, so a
      # CNI pod IP can be unassignable. This pod only sleeps (no ports, no network calls — the
      # projected token is a kubelet file mount), and identityfixture.Observe never inspects
      # pod networking, so host networking is a faithful, IP-free substrate.
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      containers:
      - name: workload
        image: $IMAGE
        command: ["python3", "-c", "import time; time.sleep(2147483647)"]
        volumeMounts:
        - name: api
          mountPath: /var/run/secrets/kubernetes.io/serviceaccount
          readOnly: true
      volumes:
      - name: api
        projected:
          defaultMode: 420
          sources:
          - serviceAccountToken: {expirationSeconds: 600, path: token}
          - configMap:
              name: kube-root-ca.crt
              items: [{key: ca.crt, path: ca.crt}]
          - downwardAPI:
              items: [{path: namespace, fieldRef: {apiVersion: v1, fieldPath: metadata.namespace}}]
YAML

  # 4. selecting PhorvexPolicy — identity-rotate enabled, active, selects the fixture pod.
  log "PhorvexPolicy $FNS/$FIX (identity-rotate enabled)"
  cat <<YAML | apply
apiVersion: phorvex.ai/v1alpha1
kind: PhorvexPolicy
metadata:
  name: $FIX
  namespace: $FNS
spec:
  mode: active
  tenant: $FNS
  actions:
    enabled: [identity-rotate]
  selector:
    matchLabels: {${FLABEL}: $FIX}
  assetValue: {blastRadiusFromGraph: true, weightSecrets: "0.8"}
  budget: {antiOverRotationWindow: 8s, maxGracePeriodSeconds: 30, maxMovesPerTick: 1, proactiveFloor: 6s, tickInterval: 3s}
  objective: {lambda: "0.4", costWeights: {flowDisruption: "0.6", normSparsity: "0.4"}}
  slo: {costCeiling: "1.2", minAvailableReplicas: 1}
  triggers: {eventDriven: true, reactiveOnly: false, eventAgeHorizon: 1h}
YAML

  # 5a. sensor reader Role (ingest identityfixture.Observe reads ns/pod/sa/rs/deploy/secrets/policy/marker)
  log "RBAC: ${LANE}-identity-fixture-reader -> $SENSOR"
  cat <<YAML | apply
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: ${LANE}-identity-fixture-reader, namespace: $FNS, labels: {phorvex.ai/lane: "$LANE"}}
rules:
- {apiGroups: [""], resources: [serviceaccounts], verbs: [get]}
- {apiGroups: [""], resources: [secrets], verbs: [get, list]}
- {apiGroups: [""], resources: [pods], verbs: [get, list]}
- {apiGroups: [""], resources: [configmaps], verbs: [get]}
- {apiGroups: [phorvex.ai], resources: [phorvexpolicies], verbs: [get]}
- {apiGroups: [apps], resources: [deployments, replicasets], verbs: [get]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: ${LANE}-identity-fixture-reader, namespace: $FNS, labels: {phorvex.ai/lane: "$LANE"}}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: ${LANE}-identity-fixture-reader}
subjects: [{kind: ServiceAccount, name: ${LANE}-sensor, namespace: $OPNS}]
YAML

  # 5b. actuator mutator Role (delete+recreate the dedicated SA (new UID); delete legacy token Secrets)
  log "RBAC: ${LANE}-identity-rotation -> $ACTUATOR"
  cat <<YAML | apply
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: ${LANE}-identity-rotation, namespace: $FNS, labels: {phorvex.ai/lane: "$LANE"}}
rules:
- {apiGroups: [""], resources: [serviceaccounts], verbs: [get, create, delete]}
- {apiGroups: [""], resources: [secrets], verbs: [get, delete]}
- {apiGroups: [""], resources: [pods], verbs: [get, list]}
- {apiGroups: [phorvex.ai], resources: [phorvexpolicies], verbs: [get]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: ${LANE}-identity-rotation, namespace: $FNS, labels: {phorvex.ai/lane: "$LANE"}}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: ${LANE}-identity-rotation}
subjects: [{kind: ServiceAccount, name: ${LANE}-actuator, namespace: $OPNS}]
YAML

  # 6. Profile ConfigMap in the OPERATOR namespace — EKS/policy pins read back from the live objects.
  kubectl -n "$FNS" rollout status deploy/$FIX --timeout=120s >&2 || true
  local NSUID POLUID POLGEN
  NSUID=$(kubectl get ns "$FNS" -o jsonpath='{.metadata.uid}')
  POLUID=$(kubectl -n "$FNS" get phorvexpolicy "$FIX" -o jsonpath='{.metadata.uid}')
  POLGEN=$(kubectl -n "$FNS" get phorvexpolicy "$FIX" -o jsonpath='{.metadata.generation}')
  log "Profile CM $OPNS/$PROFILE_CM (nsUID=$NSUID polUID=$POLUID liveGen=$POLGEN pin=bind-to-live)"
  # policyGeneration=0 binds the observer to the live, fully-reconciled generation of the
  # pinned-UID policy. Writing the live generation here (as this script used to) is race-prone:
  # any later re-apply or re-reconcile bumps .metadata.generation and the pinned profile would
  # then reject the real policy. The policy identity is still pinned by policyName + policyUID.
  local PROFILE_JSON
  PROFILE_JSON=$(cat <<JSON
{
  "journalNamespace": "$OPNS",
  "namespace": "$FNS",
  "namespaceUID": "$NSUID",
  "policyName": "$FIX",
  "policyUID": "$POLUID",
  "policyGeneration": 0,
  "eksCluster": "$CLUSTER",
  "awsRegion": "$REGION"
}
JSON
)
  kubectl -n "$OPNS" create configmap "$PROFILE_CM" --from-literal=profile.json="$PROFILE_JSON" \
    --dry-run=client -o yaml | apply

  # 7. mount the Profile on the lane sensor + set the loader env. Strategic-merge (volumes
  #    merge-key name, containers name, volumeMounts mountPath) so it creates absent arrays and
  #    is idempotent — the lane sensor runs plaintext gRPC so it starts with no volumes/mounts.
  log "sensor: ensure identity-fixture-profile volume + mount + loader env"
  kubectl -n "$OPNS" patch deploy "$SENSOR" --type=strategic -p "{\"spec\":{\"template\":{\"spec\":{\"volumes\":[{\"name\":\"identity-fixture-profile\",\"configMap\":{\"name\":\"$PROFILE_CM\"}}],\"containers\":[{\"name\":\"sensor\",\"volumeMounts\":[{\"name\":\"identity-fixture-profile\",\"mountPath\":\"/etc/phorvex/identity-fixture\",\"readOnly\":true}]}]}}}}" >&2
  kubectl -n "$OPNS" set env deploy/"$SENSOR" PHORVEX_CONSOLE_IDENTITY_FIXTURE=/etc/phorvex/identity-fixture/profile.json >&2

  # 8. EKS Pod Identity association for the lane sensor SA (credentials for FederationAbsent EKS read).
  if ! aws eks list-pod-identity-associations --cluster-name "$CLUSTER" --region "$REGION" \
        --namespace "$OPNS" --service-account "$SENSOR" --query 'associations[0].associationId' --output text 2>/dev/null | grep -q '^a-'; then
    log "EKS Pod Identity association $OPNS/$SENSOR -> $ROLE_ARN"
    aws eks create-pod-identity-association --cluster-name "$CLUSTER" --region "$REGION" \
      --namespace "$OPNS" --service-account "$SENSOR" --role-arn "$ROLE_ARN" >&2
  else
    log "EKS Pod Identity association $OPNS/$SENSOR already present"
  fi

  # 9. add the fixture namespace to the lane scope (manager ticks the policy + requests sensor
  #    scope; sensor collects the pod; actuator may enact there). First pin each roll to
  #    maxSurge=0/maxUnavailable=1 so the old pod's IP is freed BEFORE the new pod needs one
  #    (the farm is IP-pressured) — the new pod reuses the just-returned warm IP on the node.
  for dep in "$MANAGER" "$SENSOR" "$ACTUATOR"; do
    kubectl -n "$OPNS" patch deploy "$dep" --type=strategic \
      -p '{"spec":{"strategy":{"type":"RollingUpdate","rollingUpdate":{"maxSurge":0,"maxUnavailable":1}}}}' >&2 || true
  done
  scope_add "$MANAGER"; scope_add "$SENSOR"; scope_add "$ACTUATOR"

  # 9b. widen the lane detector's target-scope VAP so pN-attacks may create the pod-bound-api-auth
  #     SecurityEvent against the fixture ns (it is otherwise pinned to pN-demo, like staging).
  vap_scope_add

  # 10. settle: roll the services that changed and wait Ready.
  log "waiting for sensor/manager/actuator rollout (scope + sensor mount/creds)"
  kubectl -n "$OPNS" rollout status deploy/"$SENSOR"   --timeout=180s >&2 || true
  kubectl -n "$OPNS" rollout status deploy/"$MANAGER"  --timeout=180s >&2 || true
  kubectl -n "$OPNS" rollout status deploy/"$ACTUATOR" --timeout=180s >&2 || true
  kubectl -n "$FNS"  rollout status deploy/$FIX --timeout=120s >&2 || true
  log "ensure complete"
  ids
}

ids(){
  local NSUID POLUID POLGEN
  NSUID=$(kubectl get ns "$FNS" -o jsonpath='{.metadata.uid}' 2>/dev/null || true)
  POLUID=$(kubectl -n "$FNS" get phorvexpolicy "$FIX" -o jsonpath='{.metadata.uid}' 2>/dev/null || true)
  POLGEN=$(kubectl -n "$FNS" get phorvexpolicy "$FIX" -o jsonpath='{.metadata.generation}' 2>/dev/null || true)
  printf '{"fixtureNamespace":"%s","run":"%s","namespaceUID":"%s","policyUID":"%s","policyGeneration":"%s","operatorNamespace":"%s"}\n' \
    "$FNS" "$FIX" "$NSUID" "$POLUID" "$POLGEN" "$OPNS"
}

down(){
  log "teardown: revert scope + VAP + sensor mount/env, delete association, delete $FNS + profile CM"
  scope_del "$MANAGER"; scope_del "$SENSOR"; scope_del "$ACTUATOR"
  vap_scope_del
  kubectl -n "$OPNS" set env deploy/"$SENSOR" PHORVEX_CONSOLE_IDENTITY_FIXTURE- >&2 2>/dev/null || true
  # strip the profile volume + mount if present
  local vidx midx
  vidx=$(kubectl -n "$OPNS" get deploy "$SENSOR" -o json 2>/dev/null | jq '.spec.template.spec.volumes | map(.name=="identity-fixture-profile") | index(true)' 2>/dev/null || echo null)
  if [ "$vidx" != "null" ] && [ -n "$vidx" ]; then
    kubectl -n "$OPNS" patch deploy "$SENSOR" --type=json -p "[{\"op\":\"remove\",\"path\":\"/spec/template/spec/volumes/$vidx\"}]" >&2 || true
  fi
  midx=$(kubectl -n "$OPNS" get deploy "$SENSOR" -o json 2>/dev/null | jq '.spec.template.spec.containers[0].volumeMounts | map(.name=="identity-fixture-profile") | index(true)' 2>/dev/null || echo null)
  if [ "$midx" != "null" ] && [ -n "$midx" ]; then
    kubectl -n "$OPNS" patch deploy "$SENSOR" --type=json -p "[{\"op\":\"remove\",\"path\":\"/spec/template/spec/containers/0/volumeMounts/$midx\"}]" >&2 || true
  fi
  local AID
  AID=$(aws eks list-pod-identity-associations --cluster-name "$CLUSTER" --region "$REGION" \
        --namespace "$OPNS" --service-account "$SENSOR" --query 'associations[0].associationId' --output text 2>/dev/null || true)
  if printf '%s' "$AID" | grep -q '^a-'; then
    aws eks delete-pod-identity-association --cluster-name "$CLUSTER" --region "$REGION" --association-id "$AID" >&2 || true
  fi
  kubectl -n "$OPNS" delete configmap "$PROFILE_CM" --ignore-not-found >&2 || true
  kubectl delete ns "$FNS" --ignore-not-found --wait=false >&2 || true
  # drop any identity-rotation journals in the operator namespace
  kubectl -n "$OPNS" delete configmap -l phorvex.ai/identity-rotation-journal --ignore-not-found >&2 2>/dev/null || true
  for cm in $(kubectl -n "$OPNS" get configmap -o name 2>/dev/null | grep 'identity-rotation-' || true); do
    kubectl -n "$OPNS" delete "$cm" --ignore-not-found >&2 || true
  done
  log "teardown complete"
}

case "$SUB" in
  ensure) ensure ;;
  down)   down ;;
  ids)    ids ;;
  *) echo "unknown subcommand: $SUB (ensure|down|ids)" >&2; exit 2 ;;
esac
