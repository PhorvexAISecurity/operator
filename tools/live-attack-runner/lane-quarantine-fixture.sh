#!/usr/bin/env bash
# lane-quarantine-fixture.sh <N> — prepare lane pN so a `quarantine`-family fire lands + certifies.
#
# The quarantine DEFENSE is driven by the fire itself: phvx-attack.py's QuarantineFamily injects a
# trusted SecurityEvent asserting a QUALIFIED protected-outcome (irreversible-catastrophic
# unauthorized-disclosure, at-risk) whose single requiredKeys names the target pod's networkIdentity
# fact. Quarantine's recon cover includes that key; rotate's does NOT — so the brain refuses rotate
# (no-sound-cover) and selects+actuates quarantine (existential>λ). Nothing about the WORKLOAD makes
# it existential — the event's outcome assertion does. This script only sets up the LANE SIDE so the
# fire can land and be certified:
#   1. >=3 Ready demo-api pods — quarantine removes one ready replica and the availabilityFloor needs
#      ready-1 >= minAvailableReplicas (2). On this IP-oversubscribed farm the untainted nodes are
#      aws-cni IP-starved, so pin demo-api to the least-loaded CriticalAddonsOnly HEADROOM nodes
#      (toleration + hostname nodeAffinity). The pin is purely for schedulability (NOT existential).
#   2. networkpolicies + pods/update RBAC for the lane manager SA (capability SSAR gate) and the
#      actuator SA (the writes) — a stock lane-up grants neither. Pre-granting warms the ~5-min SSAR
#      cache so the first fire is fast.
#   3. clear any stale durable shared-capacity reservation (phorvex-shared-capacity in the operator
#      ns): a crashed prior quarantine can leave one whose controllerUID no longer matches the live
#      pods, which makes the manager report `resource-capacity: capacity endpoint ... changed` and
#      refuse every quarantine. The manager recreates an empty ledger on the next reservation.
#
# Idempotent. phvx-attack.py's QuarantineFamily.arm() re-ensures (1-grant)+(3) too, so a fire works
# even without pre-running this; the script makes it fast + reproducible and documents the contract.
# Reversible: lane-down.sh removes the namespaces (and the RBAC); unpin with
#   kubectl -n pN-demo patch deploy demo-api --type=json -p '[{"op":"remove","path":"/spec/template/spec/affinity"},{"op":"remove","path":"/spec/template/spec/tolerations"}]'
set -euo pipefail
N="${1:?usage: lane-quarantine-fixture.sh <N>}"; [[ "$N" =~ ^([1-9]|10)$ ]] || { echo "N must be 1..10" >&2; exit 1; }
LANE="p${N}"; DEMO="${LANE}-demo"; GW="${GW:-phorvex-gw}"
PIN_COUNT="${PIN_COUNT:-3}"
log(){ printf '\033[1;36m[q-fixture %s]\033[0m %s\n' "$LANE" "$*"; }
k(){ ssh -o BatchMode=yes "$GW" kubectl "$@"; }
kapply(){ ssh -o BatchMode=yes "$GW" kubectl apply -f - ; }   # manifest on stdin

k get deploy demo-api -n "$DEMO" >/dev/null 2>&1 || {
  echo "demo-api not found in $DEMO — run lane-fixture.sh $N first" >&2; exit 1; }

# ── 1) pin demo-api to CriticalAddonsOnly headroom nodes (toleration + required hostname affinity)
log "selecting ${PIN_COUNT} least-loaded CriticalAddonsOnly headroom node(s)…"
NODES=$(k get nodes -o json | python3 -I -c '
import json,sys
nodes=json.load(sys.stdin)["items"]
want=int("'"$PIN_COUNT"'")
# load per node from a separate list is overkill here; rank by schedulability + CriticalAddonsOnly
elig=[]
for nd in nodes:
    sp=nd.get("spec",{})
    if sp.get("unschedulable"): continue
    conds=nd.get("status",{}).get("conditions",[])
    if not any(c.get("type")=="Ready" and c.get("status")=="True" for c in conds): continue
    taints={t["key"] for t in (sp.get("taints") or [])}
    if taints and taints!={"CriticalAddonsOnly"}: continue   # only tolerate CriticalAddonsOnly
    # prefer tainted headroom nodes (less contended) then name for determinism
    elig.append(((0 if "CriticalAddonsOnly" in taints else 1), nd["metadata"]["name"]))
elig.sort()
print(" ".join(n for _,n in elig[:want]))
')
[ -n "$NODES" ] || { echo "no eligible headroom nodes found" >&2; exit 1; }
log "pinning demo-api -> [$NODES]"
PATCH=$(python3 -I -c '
import json,sys
nodes=sys.argv[1].split()
print(json.dumps({"spec":{"template":{"spec":{
  "tolerations":[{"key":"CriticalAddonsOnly","operator":"Exists","effect":"NoSchedule"}],
  "affinity":{"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{"nodeSelectorTerms":[
    {"matchExpressions":[{"key":"kubernetes.io/hostname","operator":"In","values":nodes}]}]}}}
}}}}))' "$NODES")
printf '%s' "$PATCH" | ssh -o BatchMode=yes "$GW" kubectl -n "$DEMO" patch deploy demo-api --type=strategic --patch-file=/dev/stdin

# ── 2) quarantine RBAC for the lane manager + actuator SAs (idempotent)
log "granting networkpolicies+pods/update RBAC to ${LANE}-phorvex-manager + ${LANE}-actuator in ${DEMO}"
cat <<EOF | kapply
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: ${LANE}-phvx-quarantine, namespace: ${DEMO}, labels: {phorvex.ai/redteam-runner: phvx-attack}}
rules:
- {apiGroups: ["networking.k8s.io"], resources: ["networkpolicies"], verbs: ["get","list","create","update","delete"]}
- {apiGroups: [""], resources: ["pods"], verbs: ["get","list","update","patch"]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: ${LANE}-phvx-quarantine, namespace: ${DEMO}, labels: {phorvex.ai/redteam-runner: phvx-attack}}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: ${LANE}-phvx-quarantine}
subjects:
- {kind: ServiceAccount, name: ${LANE}-phorvex-manager, namespace: ${LANE}}
- {kind: ServiceAccount, name: ${LANE}-actuator, namespace: ${LANE}}
EOF

# ── 3) clear a stale durable shared-capacity reservation, if any references a non-live pod
log "shared-capacity ledger: clearing stale reservation(s) if present"
k get cm phorvex-shared-capacity -n "$LANE" -o json 2>/dev/null | python3 -I -c '
import json,sys,subprocess
raw=sys.stdin.read().strip()
if not raw: print("absent"); sys.exit()
cm=json.loads(raw)
try: recs=(json.loads((cm.get("data") or {}).get("ledger","{}")) or {}).get("records") or {}
except ValueError: recs={"_":{}}
if not recs: print("empty"); sys.exit()
# any record is suspect here (set-up time, before a fire) -> clear it; manager recreates empty
print("records present (%d) -> clearing" % len(recs))
' | tee /dev/stderr | grep -q "clearing" && k delete cm phorvex-shared-capacity -n "$LANE" --ignore-not-found || true

# ── wait for >=3 Ready demo-api pods
log "waiting for >=3 Ready demo-api pods…"
for i in $(seq 1 40); do
  R=$(k get pods -n "$DEMO" -l app.kubernetes.io/name=demo-api -o json \
      | python3 -I -c 'import json,sys; d=json.load(sys.stdin); print(sum(1 for p in d["items"] if p.get("status",{}).get("phase")=="Running" and all(c.get("ready") for c in (p.get("status",{}).get("containerStatuses") or [{}]))))')
  [ "${R:-0}" -ge 3 ] && { log "ready=$R  ✓"; break; }
  sleep 6
done
log "done. Fire e.g.: python3 attack-runner/phvx-attack.py fire AML.T0050 --lane ${LANE}"
