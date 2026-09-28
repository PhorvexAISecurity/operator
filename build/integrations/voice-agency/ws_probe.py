"""One bounded, fixed direct-WebSocket Voice speech probe; no phone call.

The caller/order records must be created and pinned independently before this
client is invoked. This module never calls a CRM endpoint or injects an event.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urlparse

from websockets.asyncio.client import connect


AUDIO = Path(__file__).resolve().parent / "audio"
CLIP_SHA = {
    "attack": "be4b83510ff1f0a194938432f27821366ef2ef07ec64c140d96e33259fe4a81f",
    "replay": "be4b83510ff1f0a194938432f27821366ef2ef07ec64c140d96e33259fe4a81f",
    "benign": "99e1c867196a96fcdcbb09a5488b847fec2f137d0e3e70c5f903595347397630",
    "own-control": "deebe76b65645a0d320387e6732a31e3c0d4758fb45cef6a037c3d5eaa73a0c2",
}


def checked_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme != "ws" or parsed.hostname != "127.0.0.1" or parsed.path != "/ws" or \
            parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.port is None:
        raise ValueError("Voice URL must be an exact local port-forward /ws endpoint")
    return value


def identity(run: str, phase: str) -> tuple[str, str]:
    if not re.fullmatch(r"[a-z0-9]{8,24}", run) or phase not in CLIP_SHA:
        raise ValueError("invalid fixed run identity or phase")
    suffix = hashlib.sha256(f"{run}:{phase}".encode()).hexdigest()[:32].upper()
    return "MZ" + suffix, "CA" + suffix


def agency_phones(run: str) -> tuple[str, str]:
    if not re.fullmatch(r"[a-z0-9]{8,24}", run):
        raise ValueError("invalid run identity")
    numbers = [int.from_bytes(hashlib.sha256(f"{run}:{side}".encode()).digest()[:8], "big") % 10000000
               for side in ("A", "B")]
    if numbers[0] == numbers[1]:
        numbers[1] = (numbers[1] + 1) % 10000000
    return tuple(f"+1555{number:07d}" for number in numbers)


def account_identity(run: str) -> str:
    if not re.fullmatch(r"[a-z0-9]{8,24}", run):
        raise ValueError("invalid fixed run identity")
    return "AC" + hashlib.sha256(f"{run}:account".encode()).hexdigest()[:32].upper()


def clip(phase: str) -> bytes:
    if phase not in CLIP_SHA:
        raise ValueError("invalid phase")
    data = (AUDIO / f"{'attack' if phase == 'replay' else phase}.ulaw").read_bytes()
    if not 1 <= len(data) <= 65536 or hashlib.sha256(data).hexdigest() != CLIP_SHA[phase]:
        raise ValueError("fixed speech clip changed")
    return data


def received_audio(raw, stream):
    """Validate one received Twilio media frame; control frames carry no audio."""
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("Voice output frame shape differs")
    if value.get("event") != "media":
        return None
    media = value.get("media")
    if value.get("streamSid") != stream or not isinstance(media, dict) or \
            not isinstance(media.get("payload"), str):
        raise ValueError("Voice output media identity differs")
    audio = base64.b64decode(media["payload"], validate=True)
    if not audio:
        raise ValueError("Voice output media payload is empty")
    return audio


async def run_probe(url: str, run: str, phase: str, *, connector=connect) -> dict:
    checked_url(url)
    stream, call = identity(run, phase)
    caller, _ = agency_phones(run)
    account = account_identity(run)
    data = clip(phase)
    received = audio_frames = audio_bytes = 0
    audio_digest = hashlib.sha256()

    async def drain(ws) -> None:
        nonlocal received, audio_frames, audio_bytes
        while True:
            try:
                frame = await asyncio.wait_for(ws.recv(), timeout=0.5)
            except asyncio.TimeoutError:
                continue
            except Exception:
                return
            received += 1
            if received > 1024 or len(frame) > 65536:
                raise ValueError("Voice output exceeded fixed frame bound")
            if not isinstance(frame, str):
                raise ValueError("Voice output media must be Twilio JSON")
            audio = received_audio(frame, stream)
            if audio is not None:
                audio_frames += 1
                audio_bytes += len(audio)
                if audio_bytes > 1 << 20:
                    raise ValueError("Voice output audio bound")
                audio_digest.update(audio)

    async with asyncio.timeout(10):
        async with connector(url, open_timeout=2, close_timeout=1, max_size=65536, max_queue=8,
                             proxy=None, compression=None) as ws:
            await ws.send(json.dumps({"event": "connected", "protocol": "Call", "version": "1.0.0"}, separators=(",", ":")))
            await ws.send(json.dumps({"event": "start", "sequenceNumber": "1", "streamSid": stream,
                                      "start": {"accountSid": account, "callSid": call, "streamSid": stream,
                                                "tracks": ["inbound"], "customParameters": {"caller": caller,
                                                                                             "agencyRunId": run},
                                                "mediaFormat": {"encoding": "audio/x-mulaw", "sampleRate": 8000,
                                                                "channels": 1}}},
                                     separators=(",", ":")))
            reader = asyncio.create_task(drain(ws))
            try:
                for index, offset in enumerate(range(0, len(data), 160), start=2):
                    payload = data[offset:offset + 160].ljust(160, b"\xff")
                    await ws.send(json.dumps({"event": "media", "sequenceNumber": str(index), "streamSid": stream,
                                              "media": {"track": "inbound", "chunk": str(index - 1),
                                                        "timestamp": str((index - 2) * 20),
                                                        "payload": base64.b64encode(payload).decode("ascii")}},
                                             separators=(",", ":")))
                    await asyncio.sleep(0.02)
                await asyncio.sleep(1.4)
                stop = {"event": "stop", "sequenceNumber": str(index + 1), "streamSid": stream,
                        "stop": {"accountSid": account, "callSid": call}}
                await ws.send(json.dumps(stop, separators=(",", ":")))
                await asyncio.sleep(0.2)
            finally:
                reader.cancel()
                try:
                    await reader
                except asyncio.CancelledError:
                    pass
    return {"schema": 1, "phase": phase, "run": run, "callSid": call, "streamSid": stream,
            "caller": caller, "clipSHA256": CLIP_SHA[phase], "mediaFrames": (len(data) + 159) // 160,
            "receivedFrames": received, "receivedAudioFrames": audio_frames,
            "receivedAudioBytes": audio_bytes, "receivedAudioSHA256": audio_digest.hexdigest(), "note": "transport only; inspect exact CRM state for any tool effect"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--run", required=True)
    parser.add_argument("--phase", choices=sorted(CLIP_SHA), required=True)
    args = parser.parse_args()
    result = asyncio.run(run_probe(args.url, args.run, args.phase))
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
