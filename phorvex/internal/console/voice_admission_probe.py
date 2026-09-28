"""Fixed bounded in-Pod admission trial. No credential, header or audio output.

The background client lifetime is capped at 420 seconds. It exists only to keep
one authorized control and one observed unsigned pipeline alive across normal
brain selection. Runtime-owned receipts are independently validated by Console.
"""
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


def read_private(path, bound=16384):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > bound:
            raise ValueError("private receipt invalid")
        raw = os.read(fd, bound + 1)
    finally:
        os.close(fd)
    value = json.loads(raw, object_pairs_hook=unique)
    if raw != canonical(value):
        raise ValueError("receipt noncanonical")
    return value


def write_private(path, value):
    temporary = path.with_suffix(".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(canonical(value))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def signing_headers():
    from twilio.request_validator import RequestValidator
    token = os.environ.get("TWILIO_AUTH_TOKEN", "")
    if os.environ.get("PUBLIC_HOST") != "voicebot.phorvex.ai" or not 16 <= len(token) <= 256:
        raise ValueError("production signing authority unavailable")
    return {"X-Twilio-Signature": RequestValidator(token).compute_signature("wss://voicebot.phorvex.ai/ws", {})}


def audio_bytes(frame, stream):
    if not isinstance(frame, dict) or frame.get("event") != "media":
        return b""
    if frame.get("streamSid") != stream or not isinstance(frame.get("media"), dict):
        raise ValueError("media stream mismatch")
    payload = frame["media"].get("payload")
    if not isinstance(payload, str):
        raise ValueError("media payload invalid")
    raw = base64.b64decode(payload, validate=True)
    if not 1 <= len(raw) <= 65536:
        raise ValueError("media payload bound")
    return raw


# This source is fixed in the embedded probe, never supplied by the requester.
WORKER = r'''
import asyncio, base64, hashlib, json, os, signal, sys, time
from pathlib import Path
import aiohttp
from twilio.request_validator import RequestValidator
signal.alarm(425)
run, audio, directory = sys.argv[1:]
audio = base64.b64decode(audio, validate=True)
root = Path(directory)
run_sha = hashlib.sha256(run.encode()).hexdigest()
def sha(s): return hashlib.sha256(s.encode()).hexdigest()
def canon(v): return json.dumps(v, sort_keys=True, separators=(",",":"), ensure_ascii=False).encode()
def save(value):
    temporary = root / "client.tmp"
    fd = os.open(temporary, os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd,"wb") as f: f.write(canon(value))
    os.replace(temporary,root / "client.json")
def receipt(sid, signed):
    found=[]
    for path in root.parent.glob("admission-session-*.json"):
        if path.stat().st_size > 8192: raise ValueError("receipt bound")
        v=json.loads(path.read_bytes())
        if v.get("runSHA256")==run_sha and v.get("callSIDHash")==sha(sid) and v.get("authenticated") is signed:
            found.append(v)
    if len(found)>1: raise ValueError("session ambiguous")
    return found[0] if found else None
report={"version":1,"runSHA256":run_sha,"pid":os.getpid(),"done":False,"error":"",
        "signedSIDHash":"","unsignedSIDHash":"","signedSessionID":"","unsignedSessionID":"",
        "pendingSessionID":"","signedBeforeFrames":0,"signedBeforeBytes":0,
        "signedAfterFrames":0,"signedAfterBytes":0,"unsignedFrames":0,"unsignedBytes":0,
        "unsignedClosed":False,"pendingClosed":False,"survivorRequested":False,"survivorComplete":False}
save(report)
async def main():
    started=time.monotonic()
    timeout=aiohttp.ClientTimeout(total=420)
    headers={"X-Twilio-Signature":RequestValidator(os.environ["TWILIO_AUTH_TOKEN"]).compute_signature("wss://voicebot.phorvex.ai/ws",{}),
             "X-Phorvex-Admission-Run":run}
    async with aiohttp.ClientSession(timeout=timeout,trust_env=False) as client:
        signed=await client.ws_connect("http://127.0.0.1:8080/ws",headers=headers,timeout=5,max_msg_size=65536)
        tasks=[]; sockets=[signed]
        async def start(ws,phase):
            sid="CA"+sha("voice-admission:"+run+":"+phase)[:32].upper(); stream="MZ"+sid[2:]
            await ws.send_json({"event":"connected","protocol":"Call","version":"1.0.0"})
            await ws.send_json({"event":"start","sequenceNumber":"1","streamSid":stream,
                "start":{"accountSid":"AC"+sid[2:],"callSid":sid,"streamSid":stream,"tracks":["inbound"],
                "customParameters":{"caller":"+1555"+str(int(sha(run+phase)[:12],16)%10000000).zfill(7),"admissionRunId":run},
                "mediaFormat":{"encoding":"audio/x-mulaw","sampleRate":8000,"channels":1}}})
            return sid,stream
        async def send(ws,stream):
            for index,offset in enumerate(range(0,len(audio),160),2):
                await ws.send_json({"event":"media","sequenceNumber":str(index),"streamSid":stream,
                    "media":{"track":"inbound","chunk":str(index-1),"timestamp":str((index-2)*20),
                             "payload":base64.b64encode(audio[offset:offset+160].ljust(160,b"\xff")).decode()}})
                await asyncio.sleep(.02)
        async def drain(ws,stream,key):
            count=size=0
            async for message in ws:
                if message.type != aiohttp.WSMsgType.TEXT: continue
                v=json.loads(message.data)
                if not isinstance(v,dict): raise ValueError("frame invalid")
                if v.get("event")!="media": continue
                if v.get("streamSid")!=stream or not isinstance(v.get("media"),dict): raise ValueError("media stream invalid")
                raw=base64.b64decode(v["media"]["payload"],validate=True)
                if not 1<=len(raw)<=65536: raise ValueError("audio frame invalid")
                count+=1;size+=len(raw)
                if count>2048 or size>1048576: raise ValueError("audio cap")
                report[key+"Frames"]=count; report[key+"Bytes"]=size;save(report)
            if key=="unsigned": report["unsignedClosed"]=True;save(report)
        async def wait_real(sid,is_signed):
            until=time.monotonic()+32
            while time.monotonic()<until:
                v=receipt(sid,is_signed)
                if v:
                    p=root.parent/("admission-provider-"+v["sessionID"]+".json")
                    if p.is_file():
                        provider=json.loads(p.read_bytes())
                        if all(provider.get(k,0)>0 for k in ("sttFrames","modelTextFrames","modelCompletions","ttsAudioFrames","ttsAudioBytes")) and v.get("sentAudioFrames",0)>0 and v.get("receivedAudioFrames",0)>0:
                            return v
                await asyncio.sleep(.2)
            raise ValueError("real pipeline unavailable")
        try:
            sid,stream=await start(signed,"signed")
            report["signedSIDHash"]=sha(sid)
            tasks.append(asyncio.create_task(drain(signed,stream,"signedAfter")))
            await send(signed,stream)
            before=await wait_real(sid,True)
            report["signedSessionID"]=before["sessionID"]
            report["signedBeforeFrames"]=report["signedAfterFrames"]; report["signedBeforeBytes"]=report["signedAfterBytes"]
            save(report)
            unsigned=await client.ws_connect("http://127.0.0.1:8080/ws",headers={"X-Phorvex-Admission-Run":run},timeout=5,max_msg_size=65536)
            sockets.append(unsigned)
            usid,ustream=await start(unsigned,"unsigned");report["unsignedSIDHash"]=sha(usid)
            tasks.append(asyncio.create_task(drain(unsigned,ustream,"unsigned")))
            await send(unsigned,ustream)
            first=await wait_real(usid,False);report["unsignedSessionID"]=first["sessionID"];save(report)
            # Open pending immediately before signaling; no client start is sent.
            pending=await client.ws_connect("http://127.0.0.1:8080/ws",headers={"X-Phorvex-Admission-Run":run},timeout=5,max_msg_size=65536)
            sockets.append(pending)
            async def pending_drain():
                async for _ in pending: pass
                report["pendingClosed"]=True;save(report)
            tasks.append(asyncio.create_task(pending_drain()))
            for _ in range(10):
                candidates=[]
                for path in root.parent.glob("admission-session-*.json"):
                    v=json.loads(path.read_bytes())
                    if v.get("runSHA256")==run_sha and v.get("callSIDHash")=="" and v.get("authenticated") is False:
                        candidates.append(v)
                if len(candidates)>1: raise ValueError("pending session ambiguous")
                if candidates: report["pendingSessionID"]=candidates[0]["sessionID"];save(report);break
                await asyncio.sleep(.1)
            while time.monotonic()-started<415 and not (root/"stop").exists():
                for task in tasks:
                    if task.done() and not task.cancelled() and task.exception(): raise task.exception()
                if (root/"survivor").exists() and not report["survivorRequested"]:
                    report["survivorRequested"]=True;save(report)
                    before_provider=json.loads((root.parent/("admission-provider-"+report["signedSessionID"]+".json")).read_bytes())
                    await send(signed,stream)
                    until=time.monotonic()+32
                    while time.monotonic()<until:
                        current=json.loads((root.parent/("admission-provider-"+report["signedSessionID"]+".json")).read_bytes())
                        if report["signedAfterFrames"]>report["signedBeforeFrames"] and current["modelCompletions"]>before_provider["modelCompletions"]:
                            report["survivorComplete"]=True;save(report);break
                        await asyncio.sleep(.2)
                await asyncio.sleep(.1)
        finally:
            for ws in sockets: await ws.close()
            for task in tasks:
                if not task.done(): task.cancel()
            await asyncio.gather(*tasks,return_exceptions=True)
try: asyncio.run(main())
except Exception: report["error"]="bounded-client-failed"
finally: report["done"]=True;save(report)
'''


def transcript_collection():
    from pymongo import MongoClient
    from urllib.parse import urlsplit
    uri = os.environ.get("MONGO_URI", "")
    parsed = urlsplit(uri)
    if parsed.scheme != "mongodb" or parsed.hostname != "mongo.document-store.svc.cluster.local" or parsed.port != 27017 or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("reviewed transcript endpoint unavailable")
    client = MongoClient(uri, serverSelectionTimeoutMS=3000, connectTimeoutMS=3000, socketTimeoutMS=3000, retryWrites=False)
    return client[os.environ.get("MONGO_DB", "voice")][os.environ.get("MONGO_COLLECTION", "transcripts")]


def owned_sids(run):
    return ["CA" + hashlib.sha256(("voice-admission:" + run + ":" + phase).encode()).hexdigest()[:32].upper()
            for phase in ("signed", "unsigned", "new")]


def main():
    signal.alarm(38)
    request = json.load(sys.stdin, object_pairs_hook=unique)
    if not isinstance(request, dict) or set(request) not in ({"operation", "run"}, {"operation", "run", "audio"}, {"operation", "run", "phase", "route"}):
        raise ValueError("fixed probe input invalid")
    operation, run = request["operation"], request["run"]
    if not isinstance(run, str) or not re.fullmatch(r"[a-z0-9]{8,24}", run):
        raise ValueError("run invalid")
    run_sha = hashlib.sha256(run.encode()).hexdigest()
    root = Path("/var/lib/phorvex-voice-memory/admission")
    if not root.is_dir() or root.is_symlink() or root.stat().st_mode & 0o077:
        raise ValueError("runtime receipt directory invalid")
    directory = root / ("client-" + run_sha)
    answer = {"version": 1, "operation": operation, "runSHA256": run_sha}
    if operation == "start":
        raw = base64.b64decode(request["audio"], validate=True)
        if not 1 <= len(raw) <= 65536:
            raise ValueError("audio cap")
        signing_headers()
        collection = transcript_collection()
        if any(collection.count_documents({"call_sid": sid}, limit=1) for sid in owned_sids(run)):
            raise ValueError("run-owned transcript identity occupied")
        directory.mkdir(mode=0o700)
        child = subprocess.Popen([sys.executable, "-B", "-c", WORKER, run, request["audio"], str(directory)],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 start_new_session=True, close_fds=True)
        answer["started"] = True
    elif operation in ("observe", "survivor", "finish", "cleanup"):
        if operation in ("survivor", "finish", "cleanup"):
            name = "survivor" if operation == "survivor" else "stop"
            if not (directory / name).exists():
                fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                os.close(fd)
        report = read_private(directory / "client.json")
        if report.get("runSHA256") != run_sha:
            raise ValueError("client identity differs")
        answer["client"] = report
        sessions, providers = [], []
        for path in sorted(root.glob("admission-session-*.json")):
            receipt = read_private(path)
            if receipt.get("runSHA256") != run_sha:
                continue
            if len(sessions) >= 8:
                raise ValueError("session cap")
            sessions.append(receipt)
            provider_path = root / ("admission-provider-" + receipt["sessionID"] + ".json")
            if provider_path.exists():
                provider = read_private(provider_path)
                if provider.get("sessionID") != receipt["sessionID"] or provider.get("runSHA256") != run_sha:
                    raise ValueError("provider identity differs")
                providers.append(provider)
        answer["sessions"], answer["providers"] = sessions, providers
        if operation == "observe" and report["unsignedSessionID"]:
            token = Path("/etc/phorvex/voice-memory-state-token/token").read_bytes()
            if not 32 <= len(token) <= 256 or any(c < 33 or c > 126 for c in token):
                raise ValueError("state authority invalid")
            connection = http.client.HTTPConnection("127.0.0.1", 8080, timeout=5)
            try:
                connection.request("GET", "/v1/voice-session-admission/evidence?sessionID=" + report["unsignedSessionID"],
                                   headers={"Authorization": "Bearer " + token.decode("ascii")})
                reply = connection.getresponse(); raw = reply.read(16385)
                if reply.status != 200 or len(raw) > 16384: raise ValueError("immutable loss evidence unavailable")
                answer["loss"] = json.loads(raw, object_pairs_hook=unique)
            finally:
                connection.close()
        if operation == "cleanup":
            until = time.monotonic() + 8
            while time.monotonic() < until and not read_private(directory / "client.json")["done"]:
                time.sleep(.1)
            if not read_private(directory / "client.json")["done"]:
                raise ValueError("client cleanup incomplete")
            until = time.monotonic() + 12
            while True:
                sessions = [read_private(path) for path in root.glob("admission-session-*.json")]
                sessions = [v for v in sessions if v["runSHA256"] == run_sha]
                if len(sessions) > 8: raise ValueError("session cap")
                if all(v["delegateCompleted"] and v["disconnectedAtUnixMs"] for v in sessions): break
                if time.monotonic() >= until: raise ValueError("delegate cleanup incomplete")
                time.sleep(.1)
            for receipt in sessions:
                for prefix in ("admission-session-", "admission-provider-", "admission-exposure-"):
                    path = root / (prefix + receipt["sessionID"] + ".json")
                    if path.exists(): path.unlink()
            collection = transcript_collection()
            for sid in owned_sids(run):
                rows = list(collection.find({"call_sid": sid}).limit(2))
                if len(rows) > 1: raise ValueError("run transcript ambiguous")
                if rows:
                    row = rows[0]
                    result = collection.delete_one({"_id": row["_id"], "call_sid": sid, "messages": row.get("messages")})
                    if result.deleted_count != 1 or collection.count_documents({"call_sid": sid}, limit=1):
                        raise ValueError("run transcript cleanup unconfirmed")
                context = root.parent / ("context-" + hashlib.sha256(sid.encode()).hexdigest() + ".json")
                if context.exists():
                    value = read_private(context)
                    if value.get("callSIDHash") != hashlib.sha256(sid.encode()).hexdigest():
                        raise ValueError("context receipt identity differs")
                    context.unlink()
            for path in directory.iterdir():
                if path.name not in ("stop", "survivor", "client.json", "client.tmp") or path.is_symlink():
                    raise ValueError("unexpected client evidence")
                path.unlink()
            directory.rmdir()
            answer["cleaned"] = True
    elif operation == "state":
        token = Path("/etc/phorvex/voice-memory-state-token/token").read_bytes()
        if not 32 <= len(token) <= 256 or any(c < 33 or c > 126 for c in token):
            raise ValueError("state authority invalid")
        connection = http.client.HTTPConnection("127.0.0.1", 8080, timeout=5)
        try:
            connection.request("GET", "/v1/voice-session-admission/state", headers={"Authorization": "Bearer " + token.decode("ascii")})
            reply = connection.getresponse(); raw = reply.read(8193)
            if len(raw) > 8192: raise ValueError("state cap")
            answer["status"], answer["state"] = reply.status, json.loads(raw, object_pairs_hook=unique)
        finally:
            connection.close()
    elif operation == "new-signed":
        import asyncio
        import aiohttp
        raw = base64.b64decode(request["audio"], validate=True)
        if not 1 <= len(raw) <= 65536: raise ValueError("audio cap")
        sid = "CA" + hashlib.sha256(("voice-admission:" + run + ":new").encode()).hexdigest()[:32].upper()
        stream = "MZ" + sid[2:]
        async def new_signed():
            frames = size = 0
            headers = signing_headers(); headers["X-Phorvex-Admission-Run"] = run
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=33), trust_env=False) as client:
                async with client.ws_connect("http://127.0.0.1:8080/ws", headers=headers, timeout=5, max_msg_size=65536) as ws:
                    await ws.send_json({"event": "connected", "protocol": "Call", "version": "1.0.0"})
                    await ws.send_json({"event": "start", "sequenceNumber": "1", "streamSid": stream,
                        "start": {"accountSid": "AC" + sid[2:], "callSid": sid, "streamSid": stream, "tracks": ["inbound"],
                        "customParameters": {"caller": "+1555" + str(int(hashlib.sha256((run + "new").encode()).hexdigest()[:12], 16) % 10000000).zfill(7), "admissionRunId": run},
                        "mediaFormat": {"encoding": "audio/x-mulaw", "sampleRate": 8000, "channels": 1}}})
                    async def send():
                        for index, offset in enumerate(range(0, len(raw), 160), 2):
                            await ws.send_json({"event": "media", "sequenceNumber": str(index), "streamSid": stream,
                                "media": {"track": "inbound", "chunk": str(index - 1), "timestamp": str((index - 2) * 20),
                                "payload": base64.b64encode(raw[offset:offset + 160].ljust(160, b"\xff")).decode()}})
                            await asyncio.sleep(.02)
                    sender = asyncio.create_task(send())
                    until = time.monotonic() + 29
                    try:
                        while time.monotonic() < until:
                            try: message = await ws.receive(timeout=.5)
                            except asyncio.TimeoutError: continue
                            if message.type != aiohttp.WSMsgType.TEXT: break
                            chunk = audio_bytes(json.loads(message.data), stream)
                            frames += bool(chunk); size += len(chunk)
                            if frames > 2048 or size > 1048576: raise ValueError("audio cap")
                            matching = [read_private(path) for path in root.glob("admission-session-*.json")]
                            matching = [v for v in matching if v["runSHA256"] == run_sha and v["callSIDHash"] == hashlib.sha256(sid.encode()).hexdigest()]
                            if len(matching) > 1: raise ValueError("session ambiguous")
                            if matching and frames > 0 and sender.done():
                                receipt = matching[0]
                                path = root / ("admission-provider-" + receipt["sessionID"] + ".json")
                                if path.exists():
                                    provider = read_private(path)
                                    if all(provider.get(k, 0) > 0 for k in ("sttFrames", "modelTextFrames", "modelCompletions", "ttsAudioFrames", "ttsAudioBytes")):
                                        return receipt, provider, frames, size
                        raise ValueError("new signed real audio unavailable")
                    finally:
                        sender.cancel()
                        await asyncio.gather(sender, return_exceptions=True)
        receipt, provider, frames, size = asyncio.run(new_signed())
        answer.update({"sessions": [receipt], "providers": [provider], "audioFrames": frames, "audioBytes": size})
    elif operation == "replay":
        import asyncio
        import aiohttp
        phase, route = request["phase"], request["route"]
        if phase not in ("unsigned", "malformed", "signed") or route not in ("pod", "service"):
            raise ValueError("replay scope invalid")
        headers = {"X-Phorvex-Admission-Run": run}
        if phase == "signed": headers.update(signing_headers())
        if phase == "malformed": headers["X-Twilio-Signature"] = "invalid"
        async def replay():
            url = "http://127.0.0.1:8080/ws" if route == "pod" else "http://voice-bot.voice.svc:8080/ws"
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30), trust_env=False) as client:
                try:
                    async with client.ws_connect(url, headers=headers, timeout=5, max_msg_size=65536):
                        return 101
                except aiohttp.WSServerHandshakeError as failure:
                    return failure.status
        answer["phase"], answer["route"], answer["httpStatus"] = phase, route, asyncio.run(replay())
    else:
        raise ValueError("operation invalid")
    print(canonical(answer).decode(), flush=True)


if __name__ == "__main__":
    main()
