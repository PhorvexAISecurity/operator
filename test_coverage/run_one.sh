#!/usr/bin/env bash
# run_one.sh <ns> <attack_id> <route> <budget_s>
# Fires one Live attack via the console, follows its exact record to a terminal state,
# and prints one JSON line: {ns,attackId,route,firedResultId,fireResp,record}.
# Runs ON THE JUMP HOST (kubectl targets phorvex-dev-eks). Prints no secrets.
set -u
export NS="$1" AID="$2" ROUTE="$3"; BUDGET="${4:-300}"
T=$(kubectl create token phorvex-phorvex-console-e2e -n phorvex-system --audience phorvex-console --duration 40m 2>/dev/null)
PORT=$((18100 + RANDOM % 700))
kubectl -n phorvex-system port-forward deploy/phorvex-phorvex-console "$PORT:8090" >/tmp/pf.$PORT.log 2>&1 &
PF=$!
trap 'kill $PF 2>/dev/null' EXIT
sleep 4
case "$ROUTE" in
  /api/workload/attack) BODY="{\"namespace\":\"$NS\",\"action\":\"foothold\"}";;
  /api/vllm/attack)     BODY="{\"action\":\"$AID\"}";;
  *)                    BODY="{\"scenario\":\"$AID\"}";;
esac
export FIRE=$(curl -s -m 45 -X POST -H "Authorization: Bearer $T" -H "X-Phorvex-Lens: operator" \
  -H "Content-Type: application/json" -d "$BODY" "http://127.0.0.1:$PORT$ROUTE")
export ID=$(printf '%s' "$FIRE" | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("attackId",""))
except Exception: print("")' 2>/dev/null)
RECFILE="/tmp/rec.$PORT.json"; : > "$RECFILE"
if [ -n "$ID" ]; then
  DEADLINE=$(( $(date +%s) + BUDGET ))
  while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    sleep 15
    ST=$(curl -s -m 40 -H "Authorization: Bearer $T" -H "X-Phorvex-Lens: operator" \
      "http://127.0.0.1:$PORT/api/attack-results?includeObservations=true&id=$ID" | ID="$ID" RECFILE="$RECFILE" python3 -c '
import json,sys,os
try: rows=json.load(sys.stdin).get("attacks",[])
except Exception: print("_err"); sys.exit()
r=next((x for x in rows if x.get("id")==os.environ["ID"]),None)
if r is None: print("_absent"); sys.exit()
open(os.environ["RECFILE"],"w").write(json.dumps(r))
print(r.get("status","_none"))' 2>/dev/null)
    case "$ST" in done|partial|failed) break;; esac
  done
fi
export RECFILE
python3 -c '
import json,os
rec=None
try:
    s=open(os.environ["RECFILE"]).read()
    rec=json.loads(s) if s.strip() else None
except Exception: rec=None
print(json.dumps({
  "ns": os.environ["NS"], "attackId": os.environ["AID"], "route": os.environ["ROUTE"],
  "firedResultId": os.environ.get("ID",""), "fireResp": os.environ["FIRE"][:400], "record": rec,
}))'
rm -f "$RECFILE" "/tmp/pf.$PORT.log"
