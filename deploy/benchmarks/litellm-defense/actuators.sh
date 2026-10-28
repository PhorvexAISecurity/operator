#!/usr/bin/env bash
# New-actuator benchmark: five named catalogue attacks on the LiteLLM serving workload, each
# defended by the native actuator the attack library assigns it, with and without the operator.
#
#   defended   — operator acting (kill switch off): the attack is contained by its actuator.
#   undefended — operator actuation off (kill switch engaged): the attack lands.
#
# Each attack is a trusted SecurityEvent fired as the bench-redteam identity, carrying the typed
# observation the actuator needs (event rule.type + payload annotations), plus the matching
# workload state. The appropriate actuator is enabled on the policy for the run. No exploit code.
#
#   AML.T0081 Modify AI Agent Configuration -> k8s-object-revert  (restore a tampered ConfigMap)
#   AML.T0044 Full AI Model Access / C2      -> network-isolate    (egress-cut NetworkPolicy)
#   AML.T0010 AI Supply-Chain Compromise     -> registry-rollback  (roll image back to trusted pin)
#   AML.T0024 Exfiltration via Inference API -> credential-revoke  (delete the stolen SA token)
#   AML.T0029 Denial of AI Service           -> quarantine         (isolate the compromised replica)
#
# Run as root:  sudo deploy/benchmarks/litellm-defense/actuators.sh
# Then:         python3 deploy/benchmarks/litellm-defense/report-actuators.py
set -uo pipefail

OPNS="${OPNS:-phorvex-system}"; RELEASE="${RELEASE:-bench}"; NS="${NS:-litellm}"
APP="${APP:-litellm}"; POLICY="${POLICY:-$APP-defense}"; NGINX="${NGINX:-$APP-nginx}"  # target workload (override for vllm)
REDTEAM="${REDTEAM:-system:serviceaccount:phorvex-system:bench-redteam}"
WINDOW_DEF="${WINDOW_DEF:-120}"; WINDOW_UNDEF="${WINDOW_UNDEF:-45}"; POLL="${POLL:-4}"
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
CHART="$REPO_ROOT/phorvex/charts/phorvex"; DATA="$HERE/data"; RESULTS="$DATA/actuators.jsonl"
export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
K(){ k3s kubectl "$@"; }
say(){ printf '\n==> %s\n' "$*"; }
mgr="${RELEASE}-phorvex"
PIN="public.ecr.aws/nginx/nginx-unprivileged:1.26-alpine"   # registry-rollback target pin (!= running 1.27)

# atlasId|name|actuator
SCENARIOS="${SCENARIOS:-$(cat <<'EOF'
AML.T0081|Modify AI Agent Configuration|k8s-object-revert
AML.T0044|Full AI Model Access (C2 egress)|network-isolate
AML.T0010|AI Supply-Chain Compromise|registry-rollback
AML.T0024|Exfiltration via Inference API|credential-revoke
AML.T0029|Denial of AI Service|quarantine
EOF
)}"

grant_rbac(){   # the new actuators' verbs, in the workload namespace, for the operator SA
  local sa; sa="$(K -n "$OPNS" get deploy "$mgr" -o jsonpath='{.spec.template.spec.serviceAccountName}')"
  cat <<YAML | K apply -f - >/dev/null
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: bench-new-actuators, namespace: $NS}
rules:
- {apiGroups: [""], resources: [configmaps], verbs: [get, list, create, update, patch, delete]}
- {apiGroups: [""], resources: [secrets], verbs: [get, list, create, update, delete]}
- {apiGroups: [""], resources: [serviceaccounts], verbs: [get, update, patch]}
- {apiGroups: [""], resources: [services], verbs: [get, list]}
- {apiGroups: [""], resources: [pods], verbs: [get, list, update, patch, delete]}
- {apiGroups: ["apps"], resources: [deployments, replicasets], verbs: [get, list, update, patch]}
- {apiGroups: ["discovery.k8s.io"], resources: [endpointslices], verbs: [list]}
- {apiGroups: ["networking.k8s.io"], resources: [networkpolicies], verbs: [get, list, create, update, delete]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: bench-new-actuators, namespace: $NS}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: bench-new-actuators}
subjects: [{kind: ServiceAccount, name: $sa, namespace: $OPNS}]
YAML
}

set_defense(){ local kill=true; [ "$1" = on ] && kill=false
  say "defense $1 (globalKillSwitch=$kill)"
  helm upgrade "$RELEASE" "$CHART" -n "$OPNS" --reuse-values --set phorvex.globalKillSwitch="$kill" --wait --timeout 6m >/dev/null
  K -n "$OPNS" rollout status deploy/"$mgr" --timeout=5m >/dev/null; }

set_actuator(){ K -n "$NS" patch phorvexpolicy "$POLICY" --type merge -p "{\"spec\":{\"actions\":{\"enabled\":[\"$1\"]}}}" >/dev/null 2>&1 || true; }

clean(){ # reset all per-scenario state
  K delete securityevent.amtd.r6security.com -l benchmark=litellm-defense --ignore-not-found >/dev/null 2>&1 || true
  K -n "$NS" delete networkpolicy --all --ignore-not-found >/dev/null 2>&1 || true
  K -n "$NS" delete secret stolen-sa-token --ignore-not-found >/dev/null 2>&1 || true
  K -n "$NS" patch configmap "$NGINX" --type json -p '[{"op":"remove","path":"/data/benchmark-drift"}]' >/dev/null 2>&1 || true
  K -n "$NS" annotate configmap "$NGINX" phorvex.ai/trusted-config-snapshot- >/dev/null 2>&1 || true
  K -n "$NS" annotate deploy "$APP" phorvex.ai/trusted-image-ref- >/dev/null 2>&1 || true
  K -n "$NS" set image deploy/"$APP" web=public.ecr.aws/nginx/nginx-unprivileged:1.27-alpine >/dev/null 2>&1 || true  # reset after a registry-rollback
  local p; for p in $(K -n "$NS" get pod -l app.kubernetes.io/name=$APP -o jsonpath='{range .items[*]}{.metadata.name}{" "}{end}' 2>/dev/null); do
    K -n "$NS" label pod "$p" phorvex.ai/quarantine-epoch- >/dev/null 2>&1 || true; done
  K -n "$OPNS" get configmap -o name 2>/dev/null | grep -E 'phorvex-operation-|phorvex-quarantine-capacity-' | xargs -r -n1 K -n "$OPNS" delete >/dev/null 2>&1 || true
}

pick_pod(){ K -n "$NS" get pod -l app.kubernetes.io/name=$APP --field-selector=status.phase=Running \
  -o jsonpath='{range .items[*]}{.metadata.deletionTimestamp}{"~"}{.metadata.name}{"\n"}{end}' 2>/dev/null | awk -F'~' '$1==""{print $2; exit}'; }

# setup_and_fire <actuator> <pod> <puid> : set up precondition + create the typed SecurityEvent. Echoes nothing.
setup_and_fire(){
  local act="$1" pod="$2" puid="$3"
  local poluid polgen; poluid="$(K -n "$NS" get phorvexpolicy "$POLICY" -o jsonpath='{.metadata.uid}')"
  polgen="$(K -n "$NS" get phorvexpolicy "$POLICY" -o jsonpath='{.metadata.generation}')"
  local ev="redteam-${act}-$(date +%s)"
  case "$act" in
    k8s-object-revert)
      K -n "$NS" get configmap "$NGINX" -o json > /tmp/cm.json
      python3 - <<PY
import json,hashlib
cm=json.load(open("/tmp/cm.json")); data={k:v for k,v in cm.get("data",{}).items() if k!="benchmark-drift"}
patch={"metadata":{"annotations":{"phorvex.ai/trusted-config-snapshot":json.dumps(data)}},"data":{"benchmark-drift":"x"}}
open("/tmp/patch.json","w").write(json.dumps(patch))
drifted=dict(data); drifted["benchmark-drift"]="x"
open("/tmp/ev.env","w").write("OSHA=sha256:%s\nTSHA=sha256:%s\n"%(hashlib.sha256(json.dumps(drifted,sort_keys=True).encode()).hexdigest(),hashlib.sha256(json.dumps(data,sort_keys=True).encode()).hexdigest()))
PY
      . /tmp/ev.env
      K -n "$NS" patch configmap "$NGINX" --type merge --patch-file /tmp/patch.json >/dev/null
      cat <<YAML | K create --as="$REDTEAM" -f - >/dev/null
apiVersion: amtd.r6security.com/v1beta1
kind: SecurityEvent
metadata: {name: $ev, labels: {benchmark: litellm-defense}, annotations: {phorvex.ai/creator-identity: $REDTEAM, phorvex.ai/target-pod-uid: "$puid", phorvex.ai/config-object-name: litellm-nginx, phorvex.ai/config-observed-sha256: "$OSHA", phorvex.ai/config-trusted-sha256: "$TSHA"}}
spec: {description: "tampered agent ConfigMap", rule: {source: ExternalDetector, threatLevel: critical, type: phorvex.attack.config-object}, targets: ["$NS/$pod"]}
YAML
      ;;
    network-isolate)
      local payload; payload="$(python3 -c "import json;print(json.dumps({'targetPodUID':'$puid','policyName':'$POLICY','policyUID':'$poluid','policyGeneration':$polgen,'forbiddenEdges':['203.0.113.10/32']}))")"
      cat <<YAML | K create --as="$REDTEAM" -f - >/dev/null
apiVersion: amtd.r6security.com/v1beta1
kind: SecurityEvent
metadata: {name: $ev, labels: {benchmark: litellm-defense}, annotations: {phorvex.ai/creator-identity: $REDTEAM, phorvex.ai/network-edge-observation-v1: '$payload'}}
spec: {description: "C2 egress channel", rule: {source: ExternalDetector, threatLevel: critical, type: phorvex.attack.network-edge}, targets: ["$NS/$pod"]}
YAML
      ;;
    registry-rollback)
      K -n "$NS" annotate deploy "$APP" "phorvex.ai/trusted-image-ref=$PIN" --overwrite >/dev/null
      local rdg tdg; rdg="sha256:$(printf 'a%.0s' $(seq 64))"; tdg="sha256:$(printf 'c%.0s' $(seq 64))"
      cat <<YAML | K create --as="$REDTEAM" -f - >/dev/null
apiVersion: amtd.r6security.com/v1beta1
kind: SecurityEvent
metadata: {name: $ev, labels: {benchmark: litellm-defense}, annotations: {phorvex.ai/creator-identity: $REDTEAM, phorvex.ai/target-pod-uid: "$puid", phorvex.ai/running-image-digest: "$rdg", phorvex.ai/trusted-image-digest: "$tdg"}}
spec: {description: "poisoned image drifted from trusted pin", rule: {source: ExternalDetector, threatLevel: critical, type: phorvex.attack.image}, targets: ["$NS/$pod"]}
YAML
      ;;
    credential-revoke)
      cat <<YAML | K apply -f - >/dev/null
apiVersion: v1
kind: Secret
metadata: {name: stolen-sa-token, namespace: $NS, annotations: {kubernetes.io/service-account.name: default}}
type: kubernetes.io/service-account-token
YAML
      local payload; payload="$(python3 -c "import json;print(json.dumps({'targetPodUID':'$puid','policyName':'$POLICY','policyUID':'$poluid','policyGeneration':$polgen,'serviceAccountName':'default','credentialSecrets':['stolen-sa-token']}))")"
      cat <<YAML | K create --as="$REDTEAM" -f - >/dev/null
apiVersion: amtd.r6security.com/v1beta1
kind: SecurityEvent
metadata: {name: $ev, labels: {benchmark: litellm-defense}, annotations: {phorvex.ai/creator-identity: $REDTEAM, phorvex.ai/credential-revoke-observation-v1: '$payload'}}
spec: {description: "exfiltrated SA token reused", rule: {source: ExternalDetector, threatLevel: critical, type: phorvex.attack.credential-theft}, targets: ["$NS/$pod"]}
YAML
      ;;
    quarantine)
      cat <<YAML | K create --as="$REDTEAM" -f - >/dev/null
apiVersion: amtd.r6security.com/v1beta1
kind: SecurityEvent
metadata: {name: $ev, labels: {benchmark: litellm-defense}, annotations: {phorvex.ai/creator-identity: $REDTEAM}}
spec: {description: "attacker foothold (DoS)", rule: {source: ExternalDetector, threatLevel: critical, type: Panic}, targets: ["$NS/$pod"]}
YAML
      ;;
  esac
  echo "$ev"
}

# detect <actuator> <pod> : echo mechanism when contained, else empty
detect(){
  local act="$1" pod="$2"
  case "$act" in
    k8s-object-revert) [ -z "$(K -n "$NS" get configmap "$NGINX" -o jsonpath='{.data.benchmark-drift}' 2>/dev/null)" ] && echo "config-restored" ;;
    network-isolate)   K -n "$NS" get networkpolicy -o name 2>/dev/null | grep -q netisolate && echo "egress-isolated" ;;
    registry-rollback) [ "$(K -n "$NS" get deploy "$APP" -o jsonpath='{.spec.template.spec.containers[?(@.name=="web")].image}')" = "$PIN" ] && echo "image-rolled-back" ;;
    credential-revoke) ! K -n "$NS" get secret stolen-sa-token >/dev/null 2>&1 && echo "credential-revoked" ;;
    quarantine)        K -n "$NS" get networkpolicy -o name 2>/dev/null | grep -q quarantine && echo "quarantined" ;;
  esac
}

run_one(){ # mode defense atlas name actuator
  local mode="$1" defense="$2" atlas="$3" name="$4" act="$5"
  local window="$WINDOW_DEF"; [ "$mode" = undefended ] && window="$WINDOW_UNDEF"
  clean; set_actuator "$act"
  K -n "$NS" rollout status deploy/"$APP" --timeout=5m >/dev/null 2>&1 || true
  sleep 15
  local pod puid; pod="$(pick_pod)"; [ -n "$pod" ] || { echo "  no pod; skip $atlas"; return 0; }
  puid="$(K -n "$NS" get pod "$pod" -o jsonpath='{.metadata.uid}')"
  say "$mode: $atlas ($name) -> $act on $NS/$pod"
  local fired_at ev mech="" contained_at="null" t=0
  fired_at="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"; ev="$(setup_and_fire "$act" "$pod" "$puid")"
  while [ "$t" -lt "$window" ]; do
    mech="$(detect "$act" "$pod")"
    [ -n "$mech" ] && { contained_at="\"$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)\""; break; }
    sleep "$POLL"; t=$((t+POLL))
  done
  local dec; dec="$(K -n "$OPNS" logs deploy/"$mgr" -c manager --since=5m 2>/dev/null | { grep '"msg":"decision"' || true; } | { grep -- "$act" || true; } | tail -1)"
  [ -n "$dec" ] || dec=null
  python3 - "$RESULTS" "$mode" "$defense" "$atlas" "$name" "$act" "$fired_at" "$contained_at" "${mech:-}" "$ev" "$pod" "$dec" "$APP" <<'PY'
import sys,json
path,mode,defense,atlas,name,act,fired,contained,mech,ev,pod,dec,app=sys.argv[1:]
try: d=json.loads(dec)
except Exception: d=None
rec={"mode":mode,"defense":defense,"atlasId":atlas,"name":name,"actuator":act,"target":app,
     "firedAt":fired,"containedAt":json.loads(contained) if contained!="null" else None,
     "mechanism":mech or None,"attackId":ev,"targetPod":pod,"decision":d}
open(path,"a").write(json.dumps(rec)+"\n")
print("  recorded",mode,atlas,act,"contained="+(mech or "no"))
PY
}

run_mode(){ set_defense "$2"
  while IFS='|' read -r atlas name act; do [ -n "${atlas:-}" ] || continue
    run_one "$1" "$2" "$atlas" "$name" "$act"; done <<EOF
$SCENARIOS
EOF
}

mkdir -p "$DATA"; : > "$RESULTS"
say "grant new-actuator RBAC + restart manager (clears the capability-gate cache)"
grant_rbac
K -n "$OPNS" rollout restart deploy/"$mgr" >/dev/null; K -n "$OPNS" rollout status deploy/"$mgr" --timeout=5m >/dev/null; sleep 15
run_mode defended on
run_mode undefended off
set_defense on; clean
say "collected $(wc -l < "$RESULTS" | tr -d ' ') records in $RESULTS"
echo "build the report:  python3 $HERE/report-actuators.py"
