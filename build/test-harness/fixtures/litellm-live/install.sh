#!/usr/bin/env bash
# Install the LiteLLM Live client-policy gateway on the dev cluster (first batch:
# ai2-unbounded-consumption and ai2-query-extraction). Run on a host with cluster-admin
# kubectl, from this directory (it needs render.py and gateway.py next to it).
#
#   ./install.sh prepare   inert: Secrets, ConfigMaps and the console profile. No traffic change.
#   ./install.sh switch    adds the gateway sidecar to both LiteLLM Pods, then moves the
#                          litellm Service to it; reverts the Service if traffic fails.
#   ./install.sh status    read-only summary.
#   ./install.sh rollback  Service back to 4000 and the Deployment back to its pre-switch revision.
#
# The trial seed, status token and LiteLLM master key are never printed or logged; they only
# pass through a private temporary directory that is removed on exit. The litellm-defense
# policy change and the chart values go through GitOps separately.
set -euo pipefail
umask 077

HERE=$(cd "$(dirname "$0")" && pwd)
WORK="${LITELLM_LIVE_WORK:-$HOME/litellm-live-work}"
IMG="docker.io/library/python@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff"
SRC_SHA="4bf046ce690c280da4b4f0f613ac52d2b4511285454f18c25b2e144b574d5cc1"
SRC_CM="phorvex-litellm-admission-gateway-${SRC_SHA:0:12}"
AUDIT_ID="https://phorvex-phorvex-audit-source.phorvex-system.svc:8445|phorvex-phorvex-audit-source.phorvex-system.svc"
LITE_SECRETS="phorvex-litellm-master-key phorvex-litellm-trial-seed phorvex-litellm-status-token"
SYS_SECRETS="phorvex-litellm-trial-seed phorvex-litellm-status-token"
LITE_CMS="$SRC_CM phorvex-litellm-live-clients phorvex-litellm-client-policy"

say() { printf '%s %s\n' "$(date -u +%H:%M:%SZ)" "$*"; }
die() { say "STOP: $*"; exit 1; }
exists() { kubectl -n "$1" get "$2" "$3" >/dev/null 2>&1; }
sha_file() { python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$1"; }
in_pod_get() { # $1 pod $2 url -> HTTP status, authenticated with the Pod's own master-key env
  kubectl -n litellm exec "$1" -c litellm -- python3 -c '
import os,sys,urllib.request,urllib.error
req=urllib.request.Request(sys.argv[1],headers={"Authorization":"Bearer "+os.environ["LITELLM_MASTER_KEY"]})
try: print(urllib.request.urlopen(req,timeout=20).status)
except urllib.error.HTTPError as e: print(e.code)
except Exception as e: print("error", type(e).__name__)' "$2" 2>/dev/null | tail -1
}

prepare() {
  [ "$(sha_file "$HERE/gateway.py")" = "$SRC_SHA" ] || die "gateway.py is not the approved source $SRC_SHA"
  local found=""
  for s in $LITE_SECRETS; do exists litellm secret "$s" && found="$found litellm/secret/$s"; done
  for s in $SYS_SECRETS; do exists phorvex-system secret "$s" && found="$found phorvex-system/secret/$s"; done
  for c in $LITE_CMS phorvex-litellm-admission-gateway; do exists litellm configmap "$c" && found="$found litellm/configmap/$c"; done
  exists phorvex-system configmap phorvex-litellm-revoke-journal && found="$found phorvex-system/configmap/phorvex-litellm-revoke-journal"
  [ -z "$found" ] || die "already present, refusing to overwrite:$found"

  PRIV=$(mktemp -d); trap 'rm -rf "$PRIV"' EXIT
  kubectl -n litellm get deploy litellm -o json > "$PRIV/deploy.json"
  python3 - "$PRIV" <<'PY'
import json,os,secrets,sys
d=sys.argv[1]; dep=json.load(open(d+"/deploy.json"))
c=dep["spec"]["template"]["spec"]["containers"]
env=[e for e in c[0].get("env",[]) if e.get("name")=="LITELLM_MASTER_KEY"]
if len(c)!=1 or len(env)!=1 or not env[0].get("value","").startswith("sk-"):
    sys.exit("LiteLLM Deployment is not the single-container literal-master-key shape this installer expects")
open(d+"/master-key","w").write(env[0]["value"])
open(d+"/seed","wb").write(os.urandom(48))
open(d+"/token","w").write(secrets.token_hex(32))
PY
  rm -f "$PRIV/deploy.json"
  kubectl -n litellm create secret generic phorvex-litellm-master-key --from-file=master-key="$PRIV/master-key" -o name
  kubectl -n litellm create secret generic phorvex-litellm-trial-seed --from-file=seed="$PRIV/seed" -o name
  kubectl -n litellm create secret generic phorvex-litellm-status-token --from-file=token="$PRIV/token" -o name
  kubectl -n phorvex-system create secret generic phorvex-litellm-trial-seed --from-file=seed="$PRIV/seed" -o name
  kubectl -n phorvex-system create secret generic phorvex-litellm-status-token --from-file=token="$PRIV/token" -o name
  local seed_sha; seed_sha=$(sha_file "$PRIV/seed")

  mkdir -p "$WORK"; rm -rf "$WORK/phase1"
  python3 "$HERE/render.py" --seed-sha256 "$seed_sha" --gateway-image "$IMG" --output "$WORK/phase1" >/dev/null
  # render.py predates the digest-named source ConfigMap the manager and console now require.
  python3 - "$WORK/phase1/gateway-source-configmap.json" "$SRC_CM" <<'PY'
import json,sys
p,name=sys.argv[1],sys.argv[2]; m=json.load(open(p)); m["metadata"]["name"]=name; json.dump(m,open(p,"w"))
PY
  for f in gateway-source-configmap owned-clients-configmap client-policy-configmap protected-journal-configmap; do
    kubectl create -f "$WORK/phase1/$f.json" -o name
  done

  python3 - "$WORK" "$seed_sha" "$IMG" "$AUDIT_ID" "$SRC_SHA" <<'PY'
import hashlib,json,sys
work,seed_sha,img,audit,src_sha=sys.argv[1:6]
clients=json.load(open(work+"/phase1/owned-clients-configmap.json"))["data"]["clients.json"]
profile={"version":2,"sourceSHA256":src_sha,"gatewayImage":img,
         "clientsSHA256":hashlib.sha256(clients.encode()).hexdigest(),"seedSHA256":seed_sha,
         "policyName":"litellm-defense","modelAlias":"gpt-4o-mini",
         "eventCreator":"system:serviceaccount:phorvex-system:phorvex-phorvex-console",
         "auditSourceIdentity":audit,"maxRunSeconds":900}
raw=json.dumps(profile,separators=(",",":"),sort_keys=True)
sha=hashlib.sha256(raw.encode()).hexdigest()
name="phorvex-litellm-live-profile-"+sha[:12]
json.dump({"apiVersion":"v1","kind":"ConfigMap","immutable":True,
           "metadata":{"name":name,"namespace":"phorvex-system","labels":{"app.kubernetes.io/part-of":"phorvex"}},
           "data":{"profile.json":raw}},open(work+"/profile-configmap.json","w"))
json.dump({"profileConfigMap":name,"profileSHA256":sha,"seedSHA256":seed_sha,
           "clientsSHA256":profile["clientsSHA256"],"sourceSHA256":src_sha,"gatewayImage":img},
          open(work+"/state.json","w"),indent=1)
PY
  kubectl create -f "$WORK/profile-configmap.json" -o name
  say "prepare done. Nothing routes through the gateway yet."
  cat "$WORK/state.json"
  echo "policyConfigMapUID: $(kubectl -n litellm get configmap phorvex-litellm-client-policy -o jsonpath='{.metadata.uid}')"
}

live_pods() { # Running, not terminating
  kubectl -n litellm get pods -l app=litellm -o json | python3 -c '
import json,sys
print(" ".join(p["metadata"]["name"] for p in json.load(sys.stdin)["items"]
               if p["status"].get("phase")=="Running" and not p["metadata"].get("deletionTimestamp")))'
}

route() {
  local pods p s
  pods=$(live_pods)
  [ -n "$pods" ] || die "no running LiteLLM Pods"
  for p in $pods; do
    kubectl -n litellm get pod "$p" -o jsonpath='{.spec.containers[*].name}' | grep -qw litellm-admission-gateway ||
      die "$p has no gateway sidecar; Service left on 4000"
    s=$(in_pod_get "$p" "http://127.0.0.1:4001/v1/models" || true)
    [ "$s" = "200" ] || die "gateway on $p answered '$s' for an authenticated /v1/models; Service left on 4000"
  done
  say "gateway answers on every Pod; moving the Service to it"
  kubectl -n litellm patch svc litellm --type=json \
    -p '[{"op":"test","path":"/spec/ports/0/targetPort","value":4000},{"op":"replace","path":"/spec/ports/0/targetPort","value":4001}]'
  sleep 5
  p=$(echo "$pods" | awk '{print $1}')
  s=$(in_pod_get "$p" "http://litellm.litellm.svc:4000/v1/models" || true)
  if [ "$s" != "200" ]; then
    kubectl -n litellm patch svc litellm --type=json -p '[{"op":"replace","path":"/spec/ports/0/targetPort","value":4000}]'
    die "traffic through the Service answered '$s'; Service reverted to 4000"
  fi
  say "switch done: authenticated traffic flows through the gateway (HTTP 200)"
}

switch() {
  [ -f "$WORK/state.json" ] || die "run prepare first"
  local port; port=$(kubectl -n litellm get svc litellm -o jsonpath='{.spec.ports[0].targetPort}')
  [ "$port" = "4000" ] || die "litellm Service targetPort is $port, expected 4000"
  if kubectl -n litellm get deploy litellm -o jsonpath='{.spec.template.spec.containers[*].name}' | grep -qw litellm-admission-gateway; then
    say "gateway sidecar already in the Deployment; resuming at the Service step"
    kubectl -n litellm rollout status deploy/litellm --timeout=10m
    route
    return
  fi
  local ts; ts=$(date -u +%Y%m%dT%H%M%SZ); local orig="$WORK/originals-$ts"; mkdir -p "$orig"
  kubectl -n litellm get deploy litellm -o json > "$orig/deployment.json"
  kubectl -n litellm get svc litellm -o json > "$orig/service.json"
  kubectl -n litellm get phorvexpolicy litellm-defense -o json > "$orig/policy.json"
  kubectl -n litellm get deploy litellm -o jsonpath='{.metadata.annotations.deployment\.kubernetes\.io/revision}' > "$WORK/pre-switch-revision"
  local uid; uid=$(kubectl -n litellm get configmap phorvex-litellm-client-policy -o jsonpath='{.metadata.uid}')
  local seed_sha; seed_sha=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["seedSHA256"])' "$WORK/state.json")
  rm -rf "$WORK/phase2"
  python3 "$HERE/render.py" --seed-sha256 "$seed_sha" --gateway-image "$IMG" \
    --deployment-original "$orig/deployment.json" --service-original "$orig/service.json" \
    --policy-original "$orig/policy.json" --policy-cm-uid "$uid" --output "$WORK/phase2" >/dev/null
  python3 - "$WORK/phase2/deployment-json-patch.json" "$SRC_CM" <<'PY'
import json,sys
p,name=sys.argv[1],sys.argv[2]; ops=json.load(open(p)); n=0
for op in ops:
    v=op.get("value")
    for item in (v if isinstance(v,list) else [v]):
        if isinstance(item,dict) and item.get("name")=="litellm-live-gateway-source":
            item["configMap"]["name"]=name; n+=1
if n!=1: sys.exit("expected exactly one gateway source volume in the Deployment patch, found %d"%n)
json.dump(ops,open(p,"w"))
PY
  kubectl -n litellm patch deploy litellm --type=json --dry-run=server -o name \
    -p "$(cat "$WORK/phase2/deployment-json-patch.json")" >/dev/null || die "the API server rejects the Deployment patch; nothing changed"
  say "adding the gateway sidecar to the LiteLLM Deployment"
  kubectl -n litellm patch deploy litellm --type=json -p "$(cat "$WORK/phase2/deployment-json-patch.json")"
  kubectl -n litellm rollout status deploy/litellm --timeout=10m
  sleep 10  # let the replaced Pod finish terminating before the per-Pod checks
  route
}

rollback() {
  kubectl -n litellm patch svc litellm --type=json -p '[{"op":"replace","path":"/spec/ports/0/targetPort","value":4000}]' || true
  if [ -f "$WORK/pre-switch-revision" ]; then
    kubectl -n litellm rollout undo deploy/litellm --to-revision="$(cat "$WORK/pre-switch-revision")"
    kubectl -n litellm rollout status deploy/litellm --timeout=10m
  fi
  say "rollback done. Secrets and ConfigMaps are kept; they are inert without the sidecar."
}

status() {
  echo "Service targetPort: $(kubectl -n litellm get svc litellm -o jsonpath='{.spec.ports[0].targetPort}')"
  kubectl -n litellm get pods -l app=litellm -o custom-columns=POD:.metadata.name,READY:.status.containerStatuses[*].ready,CONTAINERS:.spec.containers[*].name --no-headers
  for s in $LITE_SECRETS; do echo "litellm/secret/$s: $(exists litellm secret "$s" && echo present || echo absent)"; done
  for s in $SYS_SECRETS; do echo "phorvex-system/secret/$s: $(exists phorvex-system secret "$s" && echo present || echo absent)"; done
  for c in $LITE_CMS; do echo "litellm/configmap/$c: $(exists litellm configmap "$c" && echo present || echo absent)"; done
  if [ -f "$WORK/state.json" ]; then cat "$WORK/state.json"; fi
}

case "${1:-}" in
  prepare) prepare ;;
  switch) switch ;;
  rollback) rollback ;;
  status) status ;;
  *) echo "usage: $0 prepare|switch|status|rollback"; exit 2 ;;
esac
