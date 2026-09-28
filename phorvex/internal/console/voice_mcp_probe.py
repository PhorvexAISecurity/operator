"""Fixed direct-WebSocket Voice MCP observation. Runs only in an exact pinned bot Pod.

The signed test headers are made by the Voice bot, never by this client. This
probe reads an exact call's private SDK receipt and real saved Voice transcript;
it does not synthesize a model answer or mutate the MCP source.
"""

import asyncio
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time
from urllib.parse import urlsplit

RESPONSE_WAIT_SECONDS = 24
AUDIO_QUIET_SECONDS = 1
FINAL_TRANSCRIPT_WAIT_SECONDS = 20
FINAL_TRANSCRIPT_POLL_SECONDS = 0.25

signal.alarm(45)
request = json.load(sys.stdin)
if not isinstance(request, dict) or set(request) not in (
    {"operation", "run", "phase", "audio"}, {"operation", "run", "phase"}
):
    raise RuntimeError("fixed MCP probe input required")
operation, run, phase = request["operation"], request["run"], request["phase"]
if operation not in ("session", "observe", "cleanup", "state", "baseline") or not isinstance(run, str) or \
        not re.fullmatch(r"[a-z0-9]{8,24}", run) or phase not in ("attack", "replay", "benign"):
    raise RuntimeError("invalid MCP run or phase")
if (operation == "session") != ("audio" in request):
    raise RuntimeError("audio belongs only to fixed session")


def production_ws_headers():
    # Sign only the reviewed production URL. The token/header never leave memory.
    from twilio.request_validator import RequestValidator
    host = os.environ.get("PUBLIC_HOST")
    token = os.environ.get("TWILIO_AUTH_TOKEN", "")
    if host != "voicebot.phorvex.ai" or not 16 <= len(token) <= 256:
        raise RuntimeError("production Voice signing authority unavailable")
    return {"X-Twilio-Signature": RequestValidator(token).compute_signature(
        "wss://voicebot.phorvex.ai/ws", {})}


def sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeError("duplicate evidence key")
        result[key] = value
    return result


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def media_audio(text):
    value = json.loads(text, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise RuntimeError("Voice output frame shape differs")
    if value.get("event") != "media":
        return None
    if value.get("streamSid") != stream or not isinstance(value.get("media"), dict) or \
            not isinstance(value["media"].get("payload"), str):
        raise RuntimeError("Voice output media identity differs")
    audio = base64.b64decode(value["media"]["payload"], validate=True)
    if not audio:
        raise RuntimeError("Voice output media is empty")
    return audio


def wait_cleanup_transcript():
    # The unchanged bot inserts this exact row only in run_bot's finally,
    # after PipelineRunner has completed its local cleanup. Never delete an
    # early absent row while that producer can still create it.
    deadline = time.monotonic() + FINAL_TRANSCRIPT_WAIT_SECONDS
    previous = None
    while time.monotonic() < deadline:
        object_id, messages = transcript()
        if time.monotonic() >= deadline:
            break
        if object_id is not None:
            current = (object_id, canonical(messages))
            if previous is not None:
                if current != previous:
                    raise RuntimeError("completed Voice transcript changed before cleanup")
                return object_id
            previous = current
        elif previous is not None:
            raise RuntimeError("completed Voice transcript disappeared before cleanup")
        time.sleep(FINAL_TRANSCRIPT_POLL_SECONDS)
    raise RuntimeError("exact final Voice transcript unavailable for cleanup")


def emit(value):
    print(canonical(value).decode(), flush=True)


sid = "CA" + sha("voice-mcp:" + run + ":" + phase)[:32].upper()
stream = "MZ" + sid[2:]
nonce = sha("voice-mcp-nonce:" + run)[:12].upper()
run_sha = sha(run)
state_dir = Path(os.environ.get("VOICE_MEMORY_STATE_DIR", "/var/lib/phorvex-voice-memory"))


def sdk_receipt():
    directory = os.open(state_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(directory)
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077:
            raise RuntimeError("MCP receipt directory is not private")
        fd = os.open("mcp-call-" + sid + ".json", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > 4096:
                raise RuntimeError("MCP SDK receipt file invalid")
            raw = os.read(fd, 4097)
        finally:
            os.close(fd)
        value = json.loads(raw, object_pairs_hook=unique)
        if raw != canonical(value) or set(value) != {
            "version", "runSHA256", "phase", "callSid", "podUID", "sourceSHA256",
            "mcpSourceSHA256", "observedDescriptorSHA256", "effectiveDescriptorSHA256",
            "policyRevision", "policyRuleSHA256", "policyOperationId", "state", "fetchObserved"
        } or value["version"] != 1 or value["runSHA256"] != run_sha or value["phase"] != phase or \
                value["callSid"] != sid or value["podUID"] != os.environ.get("POD_UID") or \
                value["fetchObserved"] is not True or not all(
                    isinstance(value[key], str) and re.fullmatch(r"[0-9a-f]{64}", value[key])
                    for key in ("sourceSHA256", "mcpSourceSHA256", "observedDescriptorSHA256",
                                "effectiveDescriptorSHA256", "policyRuleSHA256")):
            raise RuntimeError("MCP SDK receipt identity or source differs")
        return value
    finally:
        os.close(directory)


def tool_receipts():
    directory = os.open(state_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    result = []
    try:
        for tool in ("store_directory", "check_promotions"):
            name = "mcp-tool-" + sid + "-" + tool + ".json"
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
            except FileNotFoundError:
                continue
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > 2048:
                    raise RuntimeError("MCP callback receipt file invalid")
                raw = os.read(fd, 2049)
            finally:
                os.close(fd)
            value = json.loads(raw, object_pairs_hook=unique)
            if raw != canonical(value) or set(value) != {
                "version", "runSHA256", "phase", "callSid", "podUID", "sourceSHA256",
                "mcpSourceSHA256", "toolName", "responseSHA256", "success", "callObserved"
            } or value["version"] != 1 or value["runSHA256"] != run_sha or \
                    value["phase"] != phase or value["callSid"] != sid or \
                    value["podUID"] != os.environ.get("POD_UID") or value["toolName"] != tool or \
                    value["callObserved"] is not True or type(value["success"]) is not bool or \
                    not all(isinstance(value[key], str) and re.fullmatch(r"[0-9a-f]{64}", value[key])
                            for key in ("sourceSHA256", "mcpSourceSHA256", "responseSHA256")):
                raise RuntimeError("MCP callback identity differs")
            result.append(value)
        return result
    finally:
        os.close(directory)


def transcript():
    from pymongo import MongoClient
    uri = os.environ.get("MONGO_URI", "")
    parsed = urlsplit(uri)
    if parsed.scheme != "mongodb" or parsed.hostname != "mongo.document-store.svc.cluster.local" or \
            parsed.port != 27017 or parsed.username or parsed.password or parsed.fragment:
        raise RuntimeError("reviewed transcript store endpoint unavailable")
    client = MongoClient(uri, serverSelectionTimeoutMS=3000, connectTimeoutMS=3000,
                         socketTimeoutMS=3000, retryWrites=False)
    collection = client[os.environ.get("MONGO_DB", "voice")][os.environ.get("MONGO_COLLECTION", "transcripts")]
    try:
        rows = list(collection.find({"call_sid": sid}).limit(2))
    finally:
        client.close()
    if len(rows) > 1 or any(row.get("call_sid") != sid for row in rows):
        raise RuntimeError("Voice transcript call identity ambiguous")
    if not rows:
        return None, []
    messages = rows[0].get("messages")
    if not isinstance(messages, list) or len(messages) > 128:
        raise RuntimeError("Voice transcript shape invalid")
    normalized = []
    for item in messages:
        if not isinstance(item, dict) or item.get("role") not in ("user", "assistant") or \
                not isinstance(item.get("content"), str) or len(item["content"]) > 8192:
            raise RuntimeError("Voice transcript message invalid")
        normalized.append({"role": item["role"], "content": item["content"]})
    return rows[0]["_id"], normalized


if operation == "baseline":
    production_ws_headers()  # Fail before a fixture write if signer/SDK is unavailable.
    row, _ = transcript()
    names = ["mcp-call-" + sid + ".json"] + [
        "mcp-tool-" + sid + "-" + tool + ".json" for tool in ("store_directory", "check_promotions")]
    occupied = any((state_dir / name).exists() for name in names)
    emit({"version": 1, "operation": operation, "phase": phase, "runSHA256": run_sha,
          "callSidSHA256": sha(sid), "empty": row is None and not occupied})

elif operation == "state":
    import http.client
    token = Path(os.environ.get("VOICE_MEMORY_STATE_TOKEN_FILE",
                                "/etc/phorvex/voice-memory-state-token/token")).read_bytes()
    if not 32 <= len(token) <= 256 or any(byte < 33 or byte > 126 for byte in token):
        raise RuntimeError("state token invalid")
    connection = http.client.HTTPConnection("127.0.0.1", 8080, timeout=5)
    try:
        connection.request("GET", "/v1/voice-mcp-tool-policy/state",
                           headers={"Authorization": "Bearer " + token.decode("ascii")})
        response = connection.getresponse()
        raw = response.read(4097)
        if len(raw) > 4096:
            raise RuntimeError("MCP state response exceeds bound")
        body = json.loads(raw, object_pairs_hook=unique)
        emit({"version": 1, "operation": operation, "phase": phase, "runSHA256": run_sha,
              "callSidSHA256": sha(sid), "status": response.status, "stateBody": body})
    finally:
        connection.close()

elif operation == "session":
    import aiohttp
    raw = base64.b64decode(request["audio"], validate=True)
    if not 1 <= len(raw) <= 65536:
        raise RuntimeError("fixed Voice audio exceeds bound")
    token_path = Path(os.environ.get("VOICE_MCP_TEST_TOKEN_FILE", "/etc/phorvex/voice-mcp-test-token/token"))
    token = token_path.read_bytes()
    if not 32 <= len(token) <= 256 or any(byte < 33 or byte > 126 for byte in token):
        raise RuntimeError("MCP test token invalid")
    signature = hmac.new(token, f"voice-mcp-descriptor-v1:{run}:{phase}:{sid}".encode(), hashlib.sha256).hexdigest()
    caller = "+1555" + str(int(sha("voice-mcp-caller:" + run)[:12], 16) % 10000000).zfill(7)
    account = "AC" + sha("voice-mcp-account:" + run)[:32].upper()

    async def session():
        received = audio_frames = audio_bytes = 0
        audio_digest = hashlib.sha256()
        last_audio = None
        audio_quiet = False
        timeout = aiohttp.ClientTimeout(total=38)
        async with aiohttp.ClientSession(timeout=timeout, trust_env=False) as client:
            async with client.ws_connect("http://127.0.0.1:8080/ws", timeout=5, max_msg_size=65536,
                                         headers=production_ws_headers(),
                                         autoclose=True, autoping=True) as ws:
                await ws.send_json({"event": "connected", "protocol": "Call", "version": "1.0.0"})
                await ws.send_json({"event": "start", "sequenceNumber": "1", "streamSid": stream,
                                    "start": {"accountSid": account, "callSid": sid, "streamSid": stream,
                                              "tracks": ["inbound"],
                                              "customParameters": {"caller": caller, "mcpRunId": run,
                                                                   "mcpPhase": phase, "mcpSignature": signature},
                                              "mediaFormat": {"encoding": "audio/x-mulaw", "sampleRate": 8000,
                                                              "channels": 1}}})

                async def drain():
                    nonlocal received, audio_frames, audio_bytes, last_audio
                    while True:
                        try:
                            frame = await ws.receive(timeout=0.5)
                        except asyncio.TimeoutError:
                            continue
                        if frame.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.ERROR):
                            return
                        received += 1
                        if received > 1024 or len(str(frame.data)) > 65536:
                            raise RuntimeError("Voice output exceeds frame bound")
                        if frame.type == aiohttp.WSMsgType.TEXT:
                            audio = media_audio(frame.data)
                            if audio is not None:
                                audio_frames += 1
                                audio_bytes += len(audio)
                                if audio_bytes > 1 << 20:
                                    raise RuntimeError("Voice output audio exceeds bound")
                                audio_digest.update(audio)
                                last_audio = time.monotonic()
                        elif frame.type == aiohttp.WSMsgType.BINARY:
                            raise RuntimeError("Voice output must be Twilio JSON media")

                reader = asyncio.create_task(drain())
                try:
                    for index, offset in enumerate(range(0, len(raw), 160), start=2):
                        chunk = raw[offset:offset + 160].ljust(160, b"\xff")
                        await ws.send_json({"event": "media", "sequenceNumber": str(index), "streamSid": stream,
                                            "media": {"track": "inbound", "chunk": str(index - 1),
                                                      "timestamp": str((index - 2) * 20),
                                                      "payload": base64.b64encode(chunk).decode("ascii")}})
                        await asyncio.sleep(0.02)
                    # A fixed eight-second disconnect can cancel the output
                    # queue before the actual assistant transcript aggregates.
                    # Audio quiet is a bounded transport observation, not a
                    # model-completion flag; durable transcript reads follow.
                    waiting = time.monotonic()
                    while time.monotonic() - waiting < RESPONSE_WAIT_SECONDS:
                        if reader.done():
                            await reader
                            break
                        await asyncio.sleep(0.1)
                    # Do not end early on a first-phrase/greeting gap. The full
                    # bounded window is retained before checking final quiet.
                    await ws.send_json({"event": "stop", "sequenceNumber": str(index + 1), "streamSid": stream,
                                        "stop": {"accountSid": account, "callSid": sid}})
                    await asyncio.sleep(0.2)
                    audio_quiet = (not reader.done() and last_audio is not None and
                                   time.monotonic() - last_audio >= AUDIO_QUIET_SECONDS)
                finally:
                    reader.cancel()
                    try:
                        await reader
                    except asyncio.CancelledError:
                        pass
        return received, audio_frames, audio_bytes, audio_digest.hexdigest(), audio_quiet

    frames, audio_frames, audio_bytes, audio_sha, audio_quiet = asyncio.run(session())
    emit({"version": 1, "operation": operation, "phase": phase, "runSHA256": run_sha,
          "callSidSHA256": sha(sid), "audioSHA256": hashlib.sha256(raw).hexdigest(),
          "mediaFrames": (len(raw) + 159) // 160, "receivedFrames": frames,
          "receivedAudioFrames": audio_frames, "receivedAudioBytes": audio_bytes,
          "receivedAudioSHA256": audio_sha, "audioQuietObserved": audio_quiet})

elif operation == "observe":
    receipt = sdk_receipt()
    calls = tool_receipts()
    object_id, messages = transcript()
    if object_id is None:
        raise RuntimeError("exact Voice transcript unavailable")
    emit({"version": 1, "operation": operation, "phase": phase, "runSHA256": run_sha,
          "callSidSHA256": sha(sid), "receipt": receipt, "messages": messages,
          "toolCalls": calls,
          "transcriptSHA256": hashlib.sha256(canonical(messages)).hexdigest(),
          "observedAtUnixMs": int(time.time() * 1000)})

else:
    object_id = wait_cleanup_transcript()
    from pymongo import MongoClient
    client = MongoClient(os.environ["MONGO_URI"], serverSelectionTimeoutMS=3000,
                         connectTimeoutMS=3000, socketTimeoutMS=3000, retryWrites=False)
    collection = client[os.environ.get("MONGO_DB", "voice")][os.environ.get("MONGO_COLLECTION", "transcripts")]
    if object_id is not None and collection.delete_one({"_id": object_id, "call_sid": sid}).deleted_count != 1:
        raise RuntimeError("exact Voice transcript cleanup unresolved")
    if collection.count_documents({"call_sid": sid}, limit=1) != 0:
        raise RuntimeError("exact Voice transcript cleanup unresolved")
    directory = os.open(state_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in ["mcp-call-" + sid + ".json"] + [
            "mcp-tool-" + sid + "-" + tool + ".json" for tool in ("store_directory", "check_promotions")]:
            try:
                os.unlink(name, dir_fd=directory)
            except FileNotFoundError:
                pass
            try:
                os.stat(name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise RuntimeError("exact SDK receipt cleanup unresolved")
        os.fsync(directory)
    finally:
        os.close(directory)
    emit({"version": 1, "operation": operation, "phase": phase, "runSHA256": run_sha,
          "callSidSHA256": sha(sid), "cleaned": True})
