"""Fixed in-Pod Voice memory Fire probes, embedded in the console binary.

All stdout is bounded JSON without note text or credentials. A caller can only
select one of the four server-owned operations through the Go runner.
"""

import asyncio
import base64
import hashlib
import http.client
import json
import os
import pathlib
import re
import signal
import sys
import time

signal.alarm(35)
operation = sys.argv[1]
payload = json.loads(base64.b64decode(sys.argv[2], validate=True))
if not isinstance(payload, dict):
    raise RuntimeError("invalid input")


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def output(value):
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))


def store():
    from pymongo import MongoClient
    client = MongoClient(os.environ["MONGO_URI"], serverSelectionTimeoutMS=3000,
                         connectTimeoutMS=3000, socketTimeoutMS=3000, retryWrites=False)
    return client[os.environ.get("MONGO_DB", "voice")][os.environ.get("MEMORY_COLLECTION", "caller_memory")]


def checked_caller():
    caller = payload["caller"]
    if not isinstance(caller, str) or not re.fullmatch(r"\+[1-9][0-9]{1,14}", caller):
        raise RuntimeError("caller invalid")
    return caller


if operation == "seed":
    from bson import ObjectId
    caller = checked_caller()
    owner = payload["owner"]
    attack, benign = payload["attackNote"], payload["benignNote"]
    if not isinstance(owner, str) or not re.fullmatch(r"voice-live-[a-z0-9]{12,32}", owner):
        raise RuntimeError("owner invalid")
    if not all(isinstance(v, str) and 10 <= len(v.encode("utf-8")) <= 512 for v in (attack, benign)):
        raise RuntimeError("note bound")
    collection = store()
    if collection.count_documents({"caller_id": caller}, limit=2) != 0:
        raise RuntimeError("caller already has memory")
    document = {"caller_id": caller, "owner": owner,
                "notes": [{"note": attack, "ts": time.time()}, {"note": benign, "ts": time.time()}]}
    inserted = collection.insert_one(document)
    if collection.count_documents({"caller_id": caller}, limit=2) != 1:
        raise RuntimeError("caller memory became ambiguous after insertion")
    output({"objectID": str(inserted.inserted_id), "callerSHA256": digest(caller),
            "attackSHA256": digest(attack), "benignSHA256": digest(benign), "inserted": True})

elif operation == "session":
    import aiohttp
    caller = checked_caller()
    sid = payload["callSID"]
    if not isinstance(sid, str) or not re.fullmatch(r"CA[a-zA-Z0-9]{12,62}", sid):
        raise RuntimeError("call SID invalid")
    path = pathlib.Path(os.environ.get("VOICE_MEMORY_STATE_DIR", "/var/lib/phorvex-voice-memory")) / ("context-" + digest(sid) + ".json")
    if path.exists():
        raise RuntimeError("call SID receipt already exists")

    async def run():
        timeout = aiohttp.ClientTimeout(total=25)
        async with aiohttp.ClientSession(timeout=timeout, trust_env=False) as client:
            async with client.ws_connect("http://127.0.0.1:8080/ws", timeout=5) as ws:
                await ws.send_json({"event": "connected", "protocol": "Call", "version": "1.0.0"})
                await ws.send_json({"event": "start", "sequenceNumber": "1", "streamSid": "MZ" + sid[2:],
                                    "start": {"streamSid": "MZ" + sid[2:], "callSid": sid,
                                              "accountSid": "AC" + sid[2:], "tracks": ["inbound"],
                                              "customParameters": {"caller": caller},
                                              "mediaFormat": {"encoding": "audio/x-mulaw", "sampleRate": 8000, "channels": 1}}})
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline:
                    if path.is_file():
                        data = path.read_bytes()
                        if len(data) > 4096:
                            raise RuntimeError("receipt bound")
                        receipt = json.loads(data)
                        if receipt.get("callSIDHash") != digest(sid) or receipt.get("callerSHA256") != digest(caller):
                            raise RuntimeError("receipt identity mismatch")
                        path.unlink()
                        output({"wsOpened": True, "receipt": receipt})
                        await ws.close()
                        return
                    await asyncio.sleep(0.2)
                raise RuntimeError("context receipt unavailable")

    asyncio.run(run())

elif operation == "state":
    token = pathlib.Path(os.environ.get("VOICE_MEMORY_STATE_TOKEN_FILE", "/etc/phorvex/voice-memory-state-token/token")).read_bytes()
    if not 32 <= len(token) <= 256 or any(c < 33 or c > 126 for c in token):
        raise RuntimeError("state credential invalid")
    connection = http.client.HTTPConnection("127.0.0.1", 8080, timeout=5)
    try:
        connection.request("GET", "/v1/voice-memory-policy/state", headers={"Authorization": "Bearer " + token.decode("ascii")})
        reply = connection.getresponse()
        raw = reply.read(4097)
        if len(raw) > 4096:
            raise RuntimeError("state reply bound")
        output({"status": reply.status, "body": json.loads(raw)})
    finally:
        connection.close()

elif operation == "cleanup":
    from bson import ObjectId
    caller = checked_caller()
    owner, object_id = payload["owner"], payload["objectID"]
    if not isinstance(owner, str) or not re.fullmatch(r"voice-live-[a-z0-9]{12,32}", owner):
        raise RuntimeError("owner invalid")
    if not isinstance(object_id, str) or not re.fullmatch(r"[0-9a-f]{24}", object_id):
        raise RuntimeError("object identity invalid")
    collection = store()
    document = collection.find_one({"_id": ObjectId(object_id), "owner": owner, "caller_id": caller})
    if document is None or len(document.get("notes", [])) != 2:
        raise RuntimeError("owned memory record unavailable")
    hashes = [digest(n["note"]) for n in document["notes"]]
    if hashes != [payload["attackSHA256"], payload["benignSHA256"]]:
        raise RuntimeError("owned memory record changed")
    result = collection.delete_one({"_id": document["_id"], "owner": owner, "caller_id": caller,
                                    "notes": document["notes"]})
    output({"deletedCount": result.deleted_count,
            "remaining": collection.count_documents({"_id": document["_id"]}, limit=1)})

else:
    raise RuntimeError("operation invalid")
