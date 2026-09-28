"""
phorvex-loadgen — synthetic "real user" traffic for the demo apps on phorvex-dev-eks.

WHY IT EXISTS: the PhorvexPolicies in litellm/vllm/voice/nats only produce meaningful
uptime + defense numbers when there is a believable baseline of user traffic to protect.
A cluster that is idle between attack runs makes "attack landed / Phorvex / R6Blind"
charts read against a flat line. This generates that baseline.

WHAT IT IS NOT: an attack tool and not a benchmark. It drives each app the way its real
client does — the same endpoints, the same protocols, the same order of operations — at a
human rate (sessions per minute, not requests per second), with think-time between steps
and a diurnal shape over the day. Actuator endpoints (vllm /v1/drain, /v1/kv/invalidate,
chroma /api/v1/reset) are never called: those belong to the operator, not to users.

Each app gets a *driver* that plays one user session:

  crm        support-desk lookups, then sometimes a privileged write (the flow the voice
             agent's tools drive: account -> orders -> refund / reset / appointment)
  voice      a whole phone call: TwiML fetch, then /ws in the Twilio Media-Streams
             protocol, mu-law 8 kHz, 20 ms frames, paced in real time
  vllm       OpenAI-compatible chat/completions against the real Qwen model
  litellm    OpenAI-compatible chat through the proxy (see UPSTREAM KEY note in README)
  mcp        Streamable-HTTP MCP client: initialize -> initialized -> tools/list -> tools/call
  chroma     RAG reads against the knowledge_base collection (read-only, by design)

Arrivals are Poisson, not fixed-interval — real users do not arrive on a metronome, and a
metronome is trivially distinguishable from organic load in the very charts this feeds.

Deployed with no container build: python:3.11-slim + pip install + this file from a
ConfigMap, the same pattern the crm and mcp-server demo apps already use.
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import logging
import math
import os
import random
import signal
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable
from urllib.parse import urlsplit

import httpx
import websockets

# ── config ──────────────────────────────────────────────────────────────────────


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _env_f(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


def _env_i(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _env_b(name: str, default: bool) -> bool:
    return os.environ.get(name, "1" if default else "0").strip().lower() in ("1", "true", "yes", "on")


CRM_URL = _env("CRM_URL", "http://crm.crm.svc.cluster.local:8080")
VOICE_URL = _env("VOICE_URL", "http://voice-bot.voice.svc.cluster.local:8080")
VOICE_WS_URL = _env("VOICE_WS_URL", "ws://voice-bot.voice.svc.cluster.local:8080/ws")
VOICE_TWIML_STREAM_HOST = _env("VOICE_TWIML_STREAM_HOST", urlsplit(VOICE_WS_URL).hostname or "")
LITELLM_URL = _env("LITELLM_URL", "http://litellm.litellm.svc.cluster.local:4000")
LITELLM_KEY = _env("LITELLM_KEY", "sk-phorvex-demo-1234")
VLLM_URL = _env("VLLM_URL", "http://vllm.vllm.svc.cluster.local:8000")
VLLM_MODEL = _env("VLLM_MODEL", "Qwen/Qwen2.5-7B-Instruct-AWQ")
# vLLM enforces VLLM_API_KEY (Secret vllm-control, key api-key). Without it every request is a
# 401 and the "traffic" is pure error noise, so the key is mounted into this Deployment too.
VLLM_KEY = _env("VLLM_KEY", "")
MCP_URL = _env("MCP_URL", "http://mcp-server.mcp.svc.cluster.local:8000/mcp")
CHROMA_URL = _env("CHROMA_URL", "http://chroma.document-store.svc.cluster.local:8000")
CHROMA_COLLECTION = _env("CHROMA_COLLECTION", "knowledge_base")

ENABLED_APPS = {
    a.strip() for a in _env("LOADGEN_APPS", "crm,voice,vllm,litellm,mcp,chroma").split(",") if a.strip()
}
RATE_SCALE = _env_f("LOADGEN_RATE_SCALE", 1.0)
ENABLE_WRITES = _env_b("ENABLE_WRITES", True)
WRITES_PER_MIN = _env_f("WRITES_PER_MIN", 2.0)
DIURNAL = _env_b("DIURNAL", True)
TZ_OFFSET_HOURS = _env_f("TZ_OFFSET_HOURS", -8.0)  # cluster is us-east-2, users are Pacific
METRICS_PORT = _env_i("METRICS_PORT", 9090)
LOG_LEVEL = _env("LOG_LEVEL", "INFO")

# Voice receive bounds are deliberately independent of the WebSocket library's defaults.
# They bound parsing, evidence counters, and the optional in-memory echo corpus.
VOICE_MAX_TWIML_BYTES = 64 * 1024
VOICE_MAX_WS_MESSAGE_BYTES = 256 * 1024
VOICE_MAX_MEDIA_FRAME_BYTES = 64 * 1024
VOICE_MAX_VALID_MEDIA_FRAMES = 10_000
VOICE_MAX_VALID_MEDIA_BYTES = 4 * 1024 * 1024
VOICE_MAX_RETAINED_AUDIO_BYTES = 48_000  # six seconds of 8 kHz mu-law
VOICE_IO_TIMEOUT_SECONDS = 10.0
VOICE_READER_SETTLE_SECONDS = 1.0
VOICE_PRE_STOP_SETTLE_SECONDS = 0.05

# base sessions per minute at peak; the diurnal curve scales these down off-hours
BASE_SPM = {
    "crm": _env_f("CRM_SPM", 6.0),
    "voice": _env_f("VOICE_CPM", 1.2),
    "vllm": _env_f("VLLM_SPM", 4.0),
    "litellm": _env_f("LITELLM_SPM", 3.0),
    "mcp": _env_f("MCP_SPM", 2.5),
    "chroma": _env_f("CHROMA_SPM", 5.0),
}
MAX_CONCURRENCY = {
    "crm": _env_i("CRM_CONCURRENCY", 6),
    "voice": _env_i("VOICE_CONCURRENCY", 3),
    "vllm": _env_i("VLLM_CONCURRENCY", 4),
    "litellm": _env_i("LITELLM_CONCURRENCY", 4),
    "mcp": _env_i("MCP_CONCURRENCY", 4),
    "chroma": _env_i("CHROMA_CONCURRENCY", 6),
}

log = logging.getLogger("loadgen")

# ── metrics (hand-rolled Prometheus exposition; no client_python dependency) ─────

_HIST_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)
_QUOTE = '"'


def _le(bound: Any) -> str:
    """Render a histogram bucket's `le` label (kept out of the f-strings below, which
    cannot contain the escaped quotes this needs)."""
    return f"le={_QUOTE}{bound}{_QUOTE}"


class Metrics:
    """Minimal counter/gauge/histogram registry with a Prometheus text renderer."""

    def __init__(self) -> None:
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
        self._gauges: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
        self._hists: dict[tuple[str, tuple[tuple[str, str], ...]], list[float]] = {}
        self._lock = asyncio.Lock()

    @staticmethod
    def _key(name: str, labels: dict[str, str]) -> tuple[str, tuple[tuple[str, str], ...]]:
        return name, tuple(sorted(labels.items()))

    def inc(self, name: str, labels: dict[str, str] | None = None, value: float = 1.0) -> None:
        k = self._key(name, labels or {})
        self._counters[k] = self._counters.get(k, 0.0) + value

    def gauge(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        self._gauges[self._key(name, labels or {})] = value

    def observe(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        k = self._key(name, labels or {})
        h = self._hists.get(k)
        if h is None:
            # buckets..., +Inf count, sum
            h = [0.0] * (len(_HIST_BUCKETS) + 2)
            self._hists[k] = h
        for i, b in enumerate(_HIST_BUCKETS):
            if value <= b:
                h[i] += 1
        h[len(_HIST_BUCKETS)] += 1
        h[len(_HIST_BUCKETS) + 1] += value

    @staticmethod
    def _fmt_labels(labels: tuple[tuple[str, str], ...], extra: str = "") -> str:
        parts = [f'{k}="{str(v)}"' for k, v in labels]
        if extra:
            parts.append(extra)
        return "{" + ",".join(parts) + "}" if parts else ""

    def render(self) -> str:
        out: list[str] = []
        seen: set[str] = set()
        for (name, labels), v in sorted(self._counters.items()):
            if name not in seen:
                out.append(f"# TYPE {name} counter")
                seen.add(name)
            out.append(f"{name}{self._fmt_labels(labels)} {v:g}")
        for (name, labels), v in sorted(self._gauges.items()):
            if name not in seen:
                out.append(f"# TYPE {name} gauge")
                seen.add(name)
            out.append(f"{name}{self._fmt_labels(labels)} {v:g}")
        for (name, labels), h in sorted(self._hists.items()):
            if name not in seen:
                out.append(f"# TYPE {name} histogram")
                seen.add(name)
            for i, b in enumerate(_HIST_BUCKETS):
                out.append(f"{name}_bucket{self._fmt_labels(labels, _le(b))} {h[i]:g}")
            total = h[len(_HIST_BUCKETS)]
            out.append(f"{name}_bucket{self._fmt_labels(labels, _le('+Inf'))} {total:g}")
            out.append(f"{name}_sum{self._fmt_labels(labels)} {h[len(_HIST_BUCKETS) + 1]:g}")
            out.append(f"{name}_count{self._fmt_labels(labels)} {total:g}")
        return "\n".join(out) + "\n"


M = Metrics()


def record(app: str, op: str, status: str, dur: float) -> None:
    M.inc("loadgen_requests_total", {"app": app, "op": op, "status": status})
    M.observe("loadgen_request_duration_seconds", dur, {"app": app, "op": op})


# ── shared helpers ──────────────────────────────────────────────────────────────

SEED_PHONES = ["+15551230001", "+15551230002", "+15551230003"]
UNKNOWN_PHONES = ["+15559990001", "+15557770123", "+15553334444", "+15551119876"]
SEED_ORDERS = {"AC-1001": "OR-5001", "AC-1002": "OR-5002", "AC-1003": "OR-5003"}

# tag written into every synthetic mutation that has a free-text field, so demo data
# created by the generator can be told apart from data created by an attack run
SYNTH_TAG = _env("SYNTH_TAG", "[synthetic-loadgen]")


class TokenBucket:
    """Rate limit for mutating calls, so writes stay a trickle no matter the read rate."""

    def __init__(self, per_min: float, burst: float = 3.0) -> None:
        self.rate = max(per_min, 0.0) / 60.0
        self.burst = burst
        self.tokens = burst
        self.ts = time.monotonic()

    def take(self) -> bool:
        now = time.monotonic()
        self.tokens = min(self.burst, self.tokens + (now - self.ts) * self.rate)
        self.ts = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


WRITE_BUDGET = TokenBucket(WRITES_PER_MIN)


def may_write() -> bool:
    return ENABLE_WRITES and WRITE_BUDGET.take()


async def think(lo: float, hi: float) -> None:
    """Human pause between steps of a session."""
    await asyncio.sleep(random.uniform(lo, hi))


def diurnal_factor(now: float | None = None) -> float:
    """Business-day shape: a broad peak mid-morning-to-afternoon, a quiet night floor,
    and lighter weekends. Returns a multiplier in roughly [0.12, 1.0]."""
    if not DIURNAL:
        return 1.0
    t = now if now is not None else time.time()
    local = t + TZ_OFFSET_HOURS * 3600.0
    hour = (local % 86400.0) / 3600.0
    # bell centred on 13:00 local, sigma ~4h, floor so night is quiet but never dead
    bell = math.exp(-((hour - 13.0) ** 2) / (2 * 4.0**2))
    factor = 0.12 + 0.88 * bell
    weekday = int((local // 86400.0 + 4) % 7)  # epoch day 0 = Thursday
    if weekday in (5, 6):  # Sat/Sun
        factor *= 0.45
    return factor


async def timed(app: str, op: str, coro: Awaitable[Any]) -> Any:
    """Run an awaited call, recording duration + outcome. Never raises."""
    t0 = time.monotonic()
    try:
        result = await coro
        status = str(getattr(result, "status_code", "ok"))
        record(app, op, status, time.monotonic() - t0)
        return result
    except Exception as exc:  # noqa: BLE001 — a failing dependency is normal traffic data
        record(app, op, "exception", time.monotonic() - t0)
        M.inc("loadgen_errors_total", {"app": app, "op": op, "kind": type(exc).__name__})
        log.debug("%s/%s failed: %s: %s", app, op, type(exc).__name__, exc)
        return None


# ── mu-law codec + speech-shaped audio (voice driver) ───────────────────────────

_EXP_LUT = [0, 0, 1, 1] + [2] * 4 + [3] * 8 + [4] * 16 + [5] * 32 + [6] * 64 + [7] * 128
_ULAW_BIAS = 0x84
_ULAW_CLIP = 32635
ULAW_SILENCE = 0xFF  # linear2ulaw(0)


def linear2ulaw(sample: int) -> int:
    sign = 0x80 if sample < 0 else 0
    if sample < 0:
        sample = -sample
    if sample > _ULAW_CLIP:
        sample = _ULAW_CLIP
    sample += _ULAW_BIAS
    exponent = _EXP_LUT[(sample >> 7) & 0xFF]
    mantissa = (sample >> (exponent + 3)) & 0x0F
    return ~(sign | (exponent << 4) | mantissa) & 0xFF


def ulaw2linear(u: int) -> int:
    u = ~u & 0xFF
    sign = u & 0x80
    exponent = (u >> 4) & 0x07
    mantissa = u & 0x0F
    sample = ((mantissa << 3) + _ULAW_BIAS) << exponent
    sample -= _ULAW_BIAS
    return -sample if sign else sample


SAMPLE_RATE = 8000
FRAME_SAMPLES = 160  # 20 ms
FRAME_SECONDS = FRAME_SAMPLES / SAMPLE_RATE


def synth_speech_ulaw(seconds: float, rng: random.Random) -> bytes:
    """Voiced-speech-shaped mu-law audio: a jittered glottal pulse train filtered by three
    formants, gated by a ~4 Hz syllable envelope. It is not words — no STT will transcribe
    it — but it has the spectral and temporal signature a VAD gates on, so the bot's turn
    machinery runs. Real transcribable audio comes from the echo corpus below."""
    n = int(seconds * SAMPLE_RATE)
    f0 = rng.uniform(95.0, 190.0)
    formants = [
        (rng.uniform(500, 800), rng.uniform(0.9, 1.0)),
        (rng.uniform(1100, 1800), rng.uniform(0.4, 0.6)),
        (rng.uniform(2400, 3100), rng.uniform(0.15, 0.3)),
    ]
    syll_hz = rng.uniform(3.0, 5.0)
    syll_phase = rng.uniform(0, math.tau)
    out = bytearray(n)
    phase = 0.0
    for i in range(n):
        t = i / SAMPLE_RATE
        # prosodic drift on the fundamental
        f = f0 * (1.0 + 0.06 * math.sin(math.tau * 0.7 * t) + rng.uniform(-0.01, 0.01))
        phase += math.tau * f / SAMPLE_RATE
        s = 0.0
        for fc, amp in formants:
            k = max(1, int(round(fc / f)))
            s += amp * math.sin(phase * k)
        # syllable gating: dips toward zero between syllables, never fully silent
        env = 0.25 + 0.75 * max(0.0, math.sin(math.tau * syll_hz * t + syll_phase)) ** 0.6
        # a little breath noise so it is not a pure tone
        s = s * env * 0.28 + rng.gauss(0.0, 0.012)
        out[i] = linear2ulaw(int(max(-1.0, min(1.0, s)) * 20000))
    return bytes(out)


def silence_ulaw(seconds: float) -> bytes:
    return bytes([ULAW_SILENCE]) * int(seconds * SAMPLE_RATE)


# ── real speech via espeak-ng (offline, no external API) ────────────────────────
#
# The bot's pipeline is Deepgram STT -> LLM -> ElevenLabs TTS, and it does NOT greet the
# caller: it waits for the caller to say something. So a caller that emits only
# speech-shaped tones produces no transcript, no LLM turn, no TTS, and the call stops at
# the VAD. espeak-ng gives us actual words, offline and dependency-free, which Deepgram
# transcribes — that is what carries a call through the whole pipeline.

VOICE_USE_TTS = _env_b("VOICE_USE_TTS", True)
ESPEAK_BIN = _env("ESPEAK_BIN", "espeak-ng")
_tts_cache: dict[tuple[str, int, int], bytes] = {}
_tts_available: bool | None = None


def _wav_to_pcm16(wav: bytes) -> tuple[list[int], int]:
    """Minimal RIFF/WAVE reader for the mono 16-bit PCM espeak-ng emits."""
    if len(wav) < 12 or wav[:4] != b"RIFF" or wav[8:12] != b"WAVE":
        raise ValueError("not a RIFF/WAVE stream")
    pos, rate, channels, bits, data = 12, 22050, 1, 16, b""
    while pos + 8 <= len(wav):
        cid = wav[pos : pos + 4]
        size = int.from_bytes(wav[pos + 4 : pos + 8], "little")
        body = wav[pos + 8 : pos + 8 + size]
        if cid == b"fmt " and len(body) >= 16:
            channels = int.from_bytes(body[2:4], "little")
            rate = int.from_bytes(body[4:8], "little")
            bits = int.from_bytes(body[14:16], "little")
        elif cid == b"data":
            data = body
        pos += 8 + size + (size & 1)  # chunks are word-aligned
    if bits != 16 or not data:
        raise ValueError(f"unsupported wav: bits={bits} bytes={len(data)}")
    samples = list(memoryview(data).cast("h"))
    if channels > 1:  # downmix, though espeak is mono
        samples = [
            sum(samples[i : i + channels]) // channels for i in range(0, len(samples) - channels + 1, channels)
        ]
    return samples, rate


def _resample_to_8k(samples: list[int], rate: int) -> list[int]:
    """Linear interpolation down to 8 kHz — the rate Twilio Media Streams carries."""
    if rate == SAMPLE_RATE or not samples:
        return samples
    ratio = rate / SAMPLE_RATE
    out: list[int] = []
    n = int(len(samples) / ratio)
    for i in range(n):
        src = i * ratio
        lo = int(src)
        hi = min(lo + 1, len(samples) - 1)
        frac = src - lo
        out.append(int(samples[lo] * (1.0 - frac) + samples[hi] * frac))
    return out


async def tts_ulaw(text: str, rng: random.Random) -> bytes | None:
    """Speak `text` as mu-law 8 kHz, or None if espeak-ng is unavailable.

    Speed and pitch are jittered per utterance so repeat callers are not byte-identical,
    which also keeps the STT from seeing a single memorised waveform."""
    global _tts_available
    if not VOICE_USE_TTS or _tts_available is False:
        return None

    speed = rng.choice([140, 150, 160, 170])
    pitch = rng.choice([35, 45, 50, 60, 70])
    key = (text, speed, pitch)
    if key in _tts_cache:
        return _tts_cache[key]

    try:
        proc = await asyncio.create_subprocess_exec(
            ESPEAK_BIN, "-v", "en-us", "-s", str(speed), "-p", str(pitch), "-a", "160", "--stdout", text,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        wav, err = await asyncio.wait_for(proc.communicate(), timeout=20)
        if proc.returncode != 0 or not wav:
            raise RuntimeError(f"espeak rc={proc.returncode}: {err[:200]!r}")
        samples, rate = _wav_to_pcm16(wav)
        audio = bytes(linear2ulaw(s) for s in _resample_to_8k(samples, rate))
    except FileNotFoundError:
        log.warning("espeak-ng not installed — voice falls back to speech-shaped tones")
        _tts_available = False
        M.gauge("loadgen_voice_tts_available", 0)
        return None
    except Exception as exc:  # noqa: BLE001
        M.inc("loadgen_errors_total", {"app": "voice", "op": "tts", "kind": type(exc).__name__})
        log.warning("espeak failed: %s: %s", type(exc).__name__, exc)
        return None

    if _tts_available is None:
        _tts_available = True
        M.gauge("loadgen_voice_tts_available", 1)
    if len(_tts_cache) < 128:
        _tts_cache[key] = audio
    return audio


class EchoCorpus:
    """Real speech, bootstrapped from the bot itself.

    The bot answers in ElevenLabs TTS — genuine human-sounding mu-law. We keep a few of
    those clips and play them back as *caller* audio on later calls, which gives the STT
    something it can actually transcribe, so a call exercises the full
    VAD -> STT -> LLM -> tools -> TTS path rather than stopping at the VAD.
    """

    def __init__(self, max_clips: int = 8, max_seconds: float = 6.0) -> None:
        self.clips: list[bytes] = []
        self.max_clips = max_clips
        self.max_bytes = int(max_seconds * SAMPLE_RATE)

    def offer(self, audio: bytes) -> None:
        clip = self._trim_silence(audio)
        if len(clip) < SAMPLE_RATE:  # shorter than 1s is not a usable utterance
            return
        self.clips.append(clip[: self.max_bytes])
        if len(self.clips) > self.max_clips:
            self.clips.pop(0)
        M.gauge("loadgen_voice_echo_clips", len(self.clips))

    @staticmethod
    def _trim_silence(audio: bytes) -> bytes:
        lo, hi = 0, len(audio)
        while lo < hi and abs(ulaw2linear(audio[lo])) < 400:
            lo += 1
        while hi > lo and abs(ulaw2linear(audio[hi - 1])) < 400:
            hi -= 1
        return audio[lo:hi]

    def sample(self, rng: random.Random) -> bytes | None:
        if not self.clips:
            return None
        clip = rng.choice(self.clips)
        # vary gain a little so repeated turns are not byte-identical
        gain = rng.uniform(0.75, 1.0)
        if gain > 0.97:
            return clip
        return bytes(linear2ulaw(int(ulaw2linear(b) * gain)) for b in clip)


ECHO = EchoCorpus()
VOICE_USE_ECHO = _env_b("VOICE_USE_ECHO", True)


# ── drivers ─────────────────────────────────────────────────────────────────────


@dataclass
class Ctx:
    """Everything a driver session needs. One shared client per app keeps connection
    reuse realistic (a real client pools too)."""

    http: httpx.AsyncClient
    rng: random.Random


async def crm_session(ctx: Ctx) -> None:
    """A support interaction: identify the caller, look at their orders, sometimes act.

    Mirrors the order the voice agent's tools fire in, including the ~15% of calls from a
    number with no account (a real 404 path the app must handle)."""
    rng = ctx.rng
    known = rng.random() > 0.15
    phone = rng.choice(SEED_PHONES if known else UNKNOWN_PHONES)

    acct = await timed("crm", "account_by_phone", ctx.http.get(f"{CRM_URL}/accounts/by-phone/{phone}"))
    await think(0.4, 1.6)
    if acct is None or acct.status_code != 200:
        # unknown caller: the agent asks again and gives up. Nothing else to do.
        M.inc("loadgen_sessions_total", {"app": "crm", "outcome": "no_account"})
        return

    account_id = acct.json().get("account_id", "")
    orders_resp = await timed("crm", "orders_by_phone", ctx.http.get(f"{CRM_URL}/orders/by-phone/{phone}"))
    await think(0.8, 2.5)

    orders = []
    if orders_resp is not None and orders_resp.status_code == 200:
        orders = orders_resp.json().get("orders", [])

    roll = rng.random()
    if roll < 0.55:
        M.inc("loadgen_sessions_total", {"app": "crm", "outcome": "lookup_only"})
        return

    if roll < 0.70:  # book an appointment
        if not may_write():
            M.inc("loadgen_sessions_total", {"app": "crm", "outcome": "write_throttled"})
            return
        day = time.gmtime(time.time() + rng.randint(2, 21) * 86400)
        payload = {"phone": phone, "date": f"{day.tm_year:04d}-{day.tm_mon:02d}-{day.tm_mday:02d}"}
        await timed("crm", "book_appointment", ctx.http.post(f"{CRM_URL}/appointments", json=payload))
        M.inc("loadgen_writes_total", {"app": "crm", "op": "appointment"})
        M.inc("loadgen_sessions_total", {"app": "crm", "outcome": "appointment"})
        return

    if roll < 0.82:  # password reset
        if not may_write():
            M.inc("loadgen_sessions_total", {"app": "crm", "outcome": "write_throttled"})
            return
        await timed("crm", "password_reset", ctx.http.post(f"{CRM_URL}/password-resets", json={"phone": phone}))
        M.inc("loadgen_writes_total", {"app": "crm", "op": "reset"})
        M.inc("loadgen_sessions_total", {"app": "crm", "outcome": "reset"})
        return

    if roll < 0.93:  # refund against an order the caller actually owns
        order = rng.choice(orders) if orders else None
        order_id = order.get("order_id") if order else SEED_ORDERS.get(account_id, "OR-5001")
        full = float(order.get("amount", 50.0)) if order else 50.0
        if not may_write():
            M.inc("loadgen_sessions_total", {"app": "crm", "outcome": "write_throttled"})
            return
        amount = round(full * rng.choice([1.0, 1.0, 0.5, 0.25]), 2)
        reason = rng.choice(
            ["item arrived damaged", "wrong size", "never delivered", "changed my mind", "duplicate charge"]
        )
        await timed(
            "crm",
            "issue_refund",
            ctx.http.post(
                f"{CRM_URL}/refunds",
                json={"order_id": order_id, "amount": amount, "reason": f"{reason} {SYNTH_TAG}"},
            ),
        )
        M.inc("loadgen_writes_total", {"app": "crm", "op": "refund"})
        M.inc("loadgen_sessions_total", {"app": "crm", "outcome": "refund"})
        return

    # an ops person spot-checking what the agent has been doing
    await timed("crm", "audit", ctx.http.get(f"{CRM_URL}/audit"))
    M.inc("loadgen_sessions_total", {"app": "crm", "outcome": "audit"})


VLLM_PROMPTS = [
    "My order arrived with a cracked case. What are my options?",
    "How long does a refund usually take to show up on my card?",
    "Can you summarise your return policy in two sentences?",
    "I need to reschedule the delivery for my standing desk to next Tuesday.",
    "Do you price match if the item goes on sale a week after I buy it?",
    "What's the difference between the standard and gold membership tiers?",
    "The wireless headphones I bought won't pair with my laptop. Any ideas?",
    "Where is your nearest store to downtown Oakland and when does it close?",
    "I was charged twice for the same order. How do I get the duplicate reversed?",
    "Write a short, polite email asking to cancel an order that hasn't shipped.",
    "Is there a promo code for orders over fifty dollars right now?",
    "How do I reset the password on my account if I've lost access to my email?",
]

SUPPORT_SYSTEM = (
    "You are a concise customer support assistant for a consumer electronics retailer. "
    "Answer in at most three sentences."
)


async def _openai_chat(
    ctx: Ctx, app: str, base_url: str, model: str, headers: dict[str, str]
) -> None:
    """One chat turn, sometimes streamed — the two shapes a real client uses."""
    rng = ctx.rng
    messages = [{"role": "system", "content": SUPPORT_SYSTEM}]
    turns = rng.choices([1, 2, 3], weights=[0.6, 0.3, 0.1])[0]

    for turn in range(turns):
        messages.append({"role": "user", "content": rng.choice(VLLM_PROMPTS)})
        stream = rng.random() < 0.45
        body = {
            "model": model,
            "messages": messages,
            "max_tokens": rng.choice([64, 96, 128, 192]),
            "temperature": round(rng.uniform(0.2, 0.9), 2),
            "stream": stream,
        }
        t0 = time.monotonic()
        try:
            if stream:
                reply_parts: list[str] = []
                first_token_at: float | None = None
                async with ctx.http.stream(
                    "POST", f"{base_url}/v1/chat/completions", json=body, headers=headers
                ) as resp:
                    async for line in resp.aiter_lines():
                        if not line.startswith("data: "):
                            continue
                        chunk = line[6:].strip()
                        if chunk == "[DONE]":
                            break
                        if first_token_at is None:
                            first_token_at = time.monotonic()
                            M.observe("loadgen_ttft_seconds", first_token_at - t0, {"app": app})
                        with contextlib.suppress(Exception):
                            delta = json.loads(chunk)["choices"][0]["delta"].get("content")
                            if delta:
                                reply_parts.append(delta)
                    status = str(resp.status_code)
                reply = "".join(reply_parts)
            else:
                resp = await ctx.http.post(
                    f"{base_url}/v1/chat/completions", json=body, headers=headers
                )
                status = str(resp.status_code)
                reply = ""
                if resp.status_code == 200:
                    with contextlib.suppress(Exception):
                        reply = resp.json()["choices"][0]["message"]["content"] or ""
            record(app, "chat_completions_stream" if stream else "chat_completions", status, time.monotonic() - t0)
        except Exception as exc:  # noqa: BLE001
            record(app, "chat_completions", "exception", time.monotonic() - t0)
            M.inc("loadgen_errors_total", {"app": app, "op": "chat", "kind": type(exc).__name__})
            M.inc("loadgen_sessions_total", {"app": app, "outcome": "error"})
            return

        if status != "200":
            M.inc("loadgen_sessions_total", {"app": app, "outcome": f"http_{status}"})
            return
        messages.append({"role": "assistant", "content": reply})
        if turn < turns - 1:
            await think(2.0, 6.0)  # user reads the answer before following up

    M.inc("loadgen_sessions_total", {"app": app, "outcome": "ok"})


def _vllm_headers() -> dict[str, str]:
    """Bearer for vLLM, or no header when the deployment runs unauthenticated."""
    return {"Authorization": f"Bearer {VLLM_KEY}"} if VLLM_KEY else {}


async def vllm_session(ctx: Ctx) -> None:
    headers = _vllm_headers()
    if ctx.rng.random() < 0.08:
        await timed("vllm", "models", ctx.http.get(f"{VLLM_URL}/v1/models", headers=headers))
        return
    if ctx.rng.random() < 0.05:
        await timed("vllm", "guardrail_state", ctx.http.get(f"{VLLM_URL}/v1/guardrail/state", headers=headers))
        return
    await _openai_chat(ctx, "vllm", VLLM_URL, VLLM_MODEL, headers)


async def litellm_session(ctx: Ctx) -> None:
    headers = {"Authorization": f"Bearer {LITELLM_KEY}"}
    if ctx.rng.random() < 0.1:
        await timed("litellm", "models", ctx.http.get(f"{LITELLM_URL}/v1/models", headers=headers))
        return
    model = ctx.rng.choices(["gpt-4o-mini", "gpt-3.5-turbo"], weights=[0.75, 0.25])[0]
    await _openai_chat(ctx, "litellm", LITELLM_URL, model, headers)


# ── MCP (Streamable HTTP) ───────────────────────────────────────────────────────


def _parse_sse_json(text: str) -> dict[str, Any] | None:
    """Pull the first JSON-RPC payload out of an SSE response body."""
    for line in text.splitlines():
        if line.startswith("data: "):
            with contextlib.suppress(Exception):
                return json.loads(line[6:])
    return None


MCP_HEADERS = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}


async def mcp_session(ctx: Ctx) -> None:
    """A full agent-side MCP session: handshake, discover tools, call one or two.

    This is the trust-boundary surface the tool-poisoning / response-injection demos use,
    so a steady stream of *benign* sessions is what makes an injected description or
    response stand out at all."""
    rng = ctx.rng
    t0 = time.monotonic()
    try:
        init = await ctx.http.post(
            MCP_URL,
            headers=MCP_HEADERS,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "phorvex-voice-agent", "version": "1.0.0"},
                },
            },
        )
        record("mcp", "initialize", str(init.status_code), time.monotonic() - t0)
        session_id = init.headers.get("mcp-session-id")
        if init.status_code != 200 or not session_id:
            M.inc("loadgen_sessions_total", {"app": "mcp", "outcome": "handshake_failed"})
            return
    except Exception as exc:  # noqa: BLE001
        record("mcp", "initialize", "exception", time.monotonic() - t0)
        M.inc("loadgen_errors_total", {"app": "mcp", "op": "initialize", "kind": type(exc).__name__})
        M.inc("loadgen_sessions_total", {"app": "mcp", "outcome": "error"})
        return

    hdrs = {**MCP_HEADERS, "mcp-session-id": session_id}
    await timed(
        "mcp",
        "initialized",
        ctx.http.post(MCP_URL, headers=hdrs, json={"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    await timed(
        "mcp",
        "tools_list",
        ctx.http.post(MCP_URL, headers=hdrs, json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    )
    await think(0.3, 1.2)

    calls = [
        ("store_directory", {"topic": rng.choice(["hours", "locations", "returns"])}),
        ("check_promotions", {}),
    ]
    rng.shuffle(calls)
    for i, (tool, arguments) in enumerate(calls[: rng.choices([1, 2], weights=[0.65, 0.35])[0]]):
        resp = await timed(
            "mcp",
            f"tools_call:{tool}",
            ctx.http.post(
                MCP_URL,
                headers=hdrs,
                json={
                    "jsonrpc": "2.0",
                    "id": 10 + i,
                    "method": "tools/call",
                    "params": {"name": tool, "arguments": arguments},
                },
            ),
        )
        # a real client reads the result; counting isError separates "the call failed"
        # from "the server answered, and the answer was an error"
        if resp is not None and resp.status_code == 200:
            payload = _parse_sse_json(resp.text) or {}
            result = payload.get("result") or {}
            outcome = "error" if result.get("isError") else "ok"
            M.inc("loadgen_mcp_tool_results_total", {"tool": tool, "outcome": outcome})
        await think(0.4, 1.5)

    with contextlib.suppress(Exception):
        await ctx.http.delete(MCP_URL, headers=hdrs)  # polite session teardown
    M.inc("loadgen_sessions_total", {"app": "mcp", "outcome": "ok"})


# ── Chroma (RAG reads — read-only on purpose) ───────────────────────────────────

CHROMA_QUERIES = [
    "what is the return window for electronics",
    "store opening hours on weekends",
    "how do I track my delivery",
    "warranty coverage for headphones",
    "do you offer price matching",
    "how to cancel an order before it ships",
    "membership tier benefits",
    "shipping cost for orders under fifty dollars",
    "how to contact customer support by phone",
    "refund processing time",
]
CHROMA_DIM = _env_i("CHROMA_DIM", 384)
_collection_id_cache: dict[str, str] = {}


def pseudo_embedding(text: str, dim: int = CHROMA_DIM) -> list[float]:
    """A deterministic unit vector per query string. Not semantic — but a real embedder is
    also deterministic per query, so repeated questions hit the same neighbourhood and the
    HNSW index sees the access pattern it would see in production."""
    seed = hashlib.sha256(text.encode()).digest()
    rnd = random.Random(int.from_bytes(seed[:8], "big"))
    vec = [rnd.gauss(0.0, 1.0) for _ in range(dim)]
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


async def _chroma_collection_id(ctx: Ctx) -> str | None:
    if CHROMA_COLLECTION in _collection_id_cache:
        return _collection_id_cache[CHROMA_COLLECTION]
    resp = await timed("chroma", "list_collections", ctx.http.get(f"{CHROMA_URL}/api/v1/collections"))
    if resp is None or resp.status_code != 200:
        return None
    with contextlib.suppress(Exception):
        for c in resp.json():
            if c.get("name") == CHROMA_COLLECTION:
                _collection_id_cache[CHROMA_COLLECTION] = c["id"]
                return c["id"]
    return None


async def chroma_session(ctx: Ctx) -> None:
    """A RAG retrieval, the way the voice agent does it before answering.

    Read-only by design: the knowledge_base collection is the corpus the indirect
    prompt-injection demos poison, so writing synthetic documents into it would
    contaminate the very thing those tests measure."""
    rng = ctx.rng
    if rng.random() < 0.12:
        await timed("chroma", "heartbeat", ctx.http.get(f"{CHROMA_URL}/api/v1/heartbeat"))
        return

    cid = await _chroma_collection_id(ctx)
    if not cid:
        M.inc("loadgen_sessions_total", {"app": "chroma", "outcome": "no_collection"})
        return

    if rng.random() < 0.15:
        await timed("chroma", "count", ctx.http.get(f"{CHROMA_URL}/api/v1/collections/{cid}/count"))

    query = rng.choice(CHROMA_QUERIES)
    await timed(
        "chroma",
        "query",
        ctx.http.post(
            f"{CHROMA_URL}/api/v1/collections/{cid}/query",
            json={
                "query_embeddings": [pseudo_embedding(query)],
                "n_results": rng.choice([3, 3, 4, 5]),
                "include": ["documents", "distances", "metadatas"],
            },
        ),
    )
    M.inc("loadgen_sessions_total", {"app": "chroma", "outcome": "ok"})


# ── voice (a whole phone call over Twilio Media Streams) ────────────────────────
#
# Spoken phrasing, not typed phrasing: callers open by saying who they are and what they
# want, then follow up in short fragments. The bot's tools are account lookup, orders,
# refunds, resets and appointments, so these are the things a caller actually asks for.

VOICE_OPENERS = [
    "Hi, I'm calling about an order I placed last week.",
    "Hello, I'd like to check the status of my delivery.",
    "Hi there, I need help with a refund for something I bought.",
    "Hello, I think I was charged twice for the same order.",
    "Hi, I'd like to book an appointment at your store.",
    "Hello, I can't log into my account and I need a password reset.",
    "Hi, the headphones I ordered arrived damaged.",
    "Hello, I wanted to ask about your return policy.",
]
VOICE_FOLLOWUPS = [
    "Yes, that's right.",
    "Can you tell me how long that will take?",
    "What are your opening hours?",
    "Could you check if there's a promotion running at the moment?",
    "Okay, and will I get an email confirmation?",
    "How much of it can be refunded?",
    "Can we make it next Tuesday instead?",
    "Thanks, that's all I needed.",
    "Sorry, could you repeat that?",
]
VOICE_UTTERANCES = VOICE_OPENERS + VOICE_FOLLOWUPS


VOICE_OUTCOME_REASONS = frozenset(
    {
        "bidirectional-media",
        "cancelled",
        "early-close",
        "invalid-json",
        "invalid-media",
        "internal",
        "missing-media",
        "receive-limit",
        "twiml-http",
        "twiml-invalid",
        "twiml-stream-contract",
        "twiml-too-large",
        "twiml-transport",
        "wrong-stream",
        "ws-connect",
        "ws-receive",
        "ws-send",
    }
)


class VoiceCallFailure(Exception):
    """A bounded, export-safe voice outcome. Messages never contain call identity or media."""

    def __init__(self, reason: str):
        if reason not in VOICE_OUTCOME_REASONS:
            raise ValueError("unregistered voice outcome reason")
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class VoiceTwiMLResponse:
    status_code: int
    content: bytes


async def _fetch_twiml(ctx: Ctx, form: dict[str, str]) -> VoiceTwiMLResponse:
    """Fetch TwiML without buffering an unbounded response body."""
    started = time.monotonic()
    status: str | None = None
    try:
        async with ctx.http.stream(
            "POST",
            f"{VOICE_URL}/",
            data=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        ) as response:
            status = str(response.status_code)
            raw = bytearray()
            async for chunk in response.aiter_bytes():
                if len(raw) + len(chunk) > VOICE_MAX_TWIML_BYTES:
                    raise VoiceCallFailure("twiml-too-large")
                raw.extend(chunk)
            result = VoiceTwiMLResponse(response.status_code, bytes(raw))
        record("voice", "twiml", status, time.monotonic() - started)
        return result
    except VoiceCallFailure:
        record("voice", "twiml", status or "exception", time.monotonic() - started)
        raise
    except Exception as exc:  # noqa: BLE001
        record("voice", "twiml", "exception", time.monotonic() - started)
        M.inc("loadgen_errors_total", {"app": "voice", "op": "twiml", "kind": "transport"})
        raise VoiceCallFailure("twiml-transport") from exc


def _validate_twiml_stream(response: VoiceTwiMLResponse) -> None:
    if not 200 <= response.status_code < 300:
        raise VoiceCallFailure("twiml-http")
    raw = response.content
    if len(raw) > VOICE_MAX_TWIML_BYTES:
        raise VoiceCallFailure("twiml-too-large")
    try:
        root = ET.fromstring(raw)
    except (ET.ParseError, ValueError):
        raise VoiceCallFailure("twiml-invalid") from None
    if root.tag.rsplit("}", 1)[-1] != "Response":
        raise VoiceCallFailure("twiml-invalid")
    urls = [node.attrib.get("url", "") for node in root.iter() if node.tag.rsplit("}", 1)[-1] == "Stream"]
    if len(urls) != 1:
        raise VoiceCallFailure("twiml-stream-contract")
    actual = urlsplit(urls[0])
    expected = urlsplit(VOICE_WS_URL)
    if (
        actual.scheme not in {"ws", "wss"}
        or not actual.hostname
        or actual.hostname != VOICE_TWIML_STREAM_HOST.lower()
        or actual.path != expected.path
    ):
        raise VoiceCallFailure("twiml-stream-contract")


def _voice_attempt(outcome: str, reason: str, started: float) -> None:
    M.inc("loadgen_voice_call_attempts_total", {"outcome": outcome, "reason": reason})
    M.observe("loadgen_voice_call_duration_seconds", time.monotonic() - started, {"outcome": outcome})


async def voice_session(ctx: Ctx) -> None:
    """One synthetic inbound call.

    Plays the real Twilio sequence: the webhook POST that fetches TwiML, then the media
    WebSocket — connected frame, start frame carrying the caller number as a custom
    parameter, then 20 ms mu-law frames paced in wall-clock time, alternating caller
    utterances with the silence during which the bot speaks back.
    """
    rng = ctx.rng
    phone = rng.choice(SEED_PHONES if rng.random() > 0.2 else UNKNOWN_PHONES)
    call_sid = "CA" + uuid.uuid4().hex
    stream_sid = "MZ" + uuid.uuid4().hex
    account_sid = "AC" + uuid.uuid4().hex

    t0 = time.monotonic()
    received = bytearray()
    read_task: asyncio.Task[None] | None = None
    stop_sent = False
    successful = False
    try:
        if rng.random() < 0.25:  # some sessions also open the console page
            await timed("voice", "web_ui", ctx.http.get(f"{VOICE_URL}/web-ui"))

        # Twilio's webhook: fetch and validate the TwiML that points at this stream.
        twiml = await _fetch_twiml(
            ctx,
            {
                "From": phone,
                "To": "+15550100000",
                "CallSid": call_sid,
                "AccountSid": account_sid,
                "CallStatus": "ringing",
                "Direction": "inbound",
            },
        )
        _validate_twiml_stream(twiml)
        await think(0.2, 0.8)

        try:
            websocket = websockets.connect(
                VOICE_WS_URL,
                open_timeout=15,
                close_timeout=5,
                max_size=VOICE_MAX_WS_MESSAGE_BYTES,
            )
            ws = await websocket.__aenter__()
        except Exception as exc:  # noqa: BLE001
            raise VoiceCallFailure("ws-connect") from exc
        try:
            await asyncio.wait_for(
                ws.send(json.dumps({"event": "connected", "protocol": "Call", "version": "1.0.0"})),
                VOICE_IO_TIMEOUT_SECONDS,
            )
            await asyncio.wait_for(ws.send(
                json.dumps(
                    {
                        "event": "start",
                        "sequenceNumber": "1",
                        "start": {
                            "streamSid": stream_sid,
                            "accountSid": account_sid,
                            "callSid": call_sid,
                            "tracks": ["inbound"],
                            "customParameters": {"caller": phone},
                            "mediaFormat": {"encoding": "audio/x-mulaw", "sampleRate": 8000, "channels": 1},
                        },
                        "streamSid": stream_sid,
                    }
                )
            ), VOICE_IO_TIMEOUT_SECONDS)

            state = {"chunk": 0, "seq": 1}
            receive = {"frames": 0, "bytes": 0, "first": False}

            async def reader() -> None:
                """Validate returned media and retain only a small bounded echo sample."""
                try:
                    async for raw in ws:
                        if not isinstance(raw, str) or len(raw.encode("utf-8")) > VOICE_MAX_WS_MESSAGE_BYTES:
                            raise VoiceCallFailure("receive-limit")
                        try:
                            msg = json.loads(raw)
                        except (json.JSONDecodeError, UnicodeError):
                            raise VoiceCallFailure("invalid-json") from None
                        if not isinstance(msg, dict):
                            raise VoiceCallFailure("invalid-json")
                        ev = msg.get("event")
                        if ev == "media":
                            M.inc("loadgen_voice_media_frames_total", {"dir": "rx"})
                            if msg.get("streamSid") != stream_sid:
                                raise VoiceCallFailure("wrong-stream")
                            media = msg.get("media")
                            if not isinstance(media, dict):
                                raise VoiceCallFailure("invalid-media")
                            payload = media.get("payload")
                            if not isinstance(payload, str):
                                raise VoiceCallFailure("invalid-media")
                            try:
                                audio = base64.b64decode(payload, validate=True)
                            except (ValueError, TypeError):
                                raise VoiceCallFailure("invalid-media") from None
                            if not audio:
                                raise VoiceCallFailure("invalid-media")
                            if (
                                len(audio) > VOICE_MAX_MEDIA_FRAME_BYTES
                                or receive["frames"] >= VOICE_MAX_VALID_MEDIA_FRAMES
                                or receive["bytes"] + len(audio) > VOICE_MAX_VALID_MEDIA_BYTES
                            ):
                                raise VoiceCallFailure("receive-limit")
                            receive["frames"] += 1
                            receive["bytes"] += len(audio)
                            M.inc("loadgen_voice_valid_media_frames_total")
                            M.inc("loadgen_voice_valid_media_bytes_total", value=float(len(audio)))
                            if not receive["first"]:
                                receive["first"] = True
                                M.observe("loadgen_voice_first_valid_audio_seconds", time.monotonic() - t0)
                            room = VOICE_MAX_RETAINED_AUDIO_BYTES - len(received)
                            if room > 0:
                                received.extend(audio[:room])
                        elif ev == "clear":
                            M.inc("loadgen_voice_events_total", {"event": "clear"})
                        elif ev == "mark":
                            M.inc("loadgen_voice_events_total", {"event": "mark"})
                    if not stop_sent:
                        raise VoiceCallFailure("early-close")
                except VoiceCallFailure:
                    raise
                except websockets.exceptions.ConnectionClosedOK as exc:
                    if not stop_sent:
                        raise VoiceCallFailure("early-close") from exc
                except Exception as exc:  # noqa: BLE001
                    raise VoiceCallFailure("ws-receive") from exc

            def check_reader() -> None:
                if read_task is not None and read_task.done():
                    if read_task.cancelled():
                        if stop_sent:
                            return
                        raise VoiceCallFailure("ws-receive")
                    exc = read_task.exception()
                    if exc is not None:
                        raise exc

            async def send_audio(audio: bytes) -> None:
                """Push mu-law at wall-clock speed — pacing is what makes the bot's VAD and
                interruption logic behave as they do on a real call."""
                deadline = time.monotonic()
                for off in range(0, len(audio) - FRAME_SAMPLES + 1, FRAME_SAMPLES):
                    check_reader()
                    frame = audio[off : off + FRAME_SAMPLES]
                    state["chunk"] += 1
                    state["seq"] += 1
                    try:
                        await asyncio.wait_for(ws.send(
                            json.dumps(
                            {
                                "event": "media",
                                "sequenceNumber": str(state["seq"]),
                                "streamSid": stream_sid,
                                "media": {
                                    "track": "inbound",
                                    "chunk": str(state["chunk"]),
                                    "timestamp": str(int(state["chunk"] * FRAME_SECONDS * 1000)),
                                    "payload": base64.b64encode(frame).decode(),
                                },
                            })
                        ), VOICE_IO_TIMEOUT_SECONDS)
                    except websockets.exceptions.ConnectionClosedOK as exc:
                        check_reader()
                        raise VoiceCallFailure("early-close") from exc
                    except Exception as exc:  # noqa: BLE001
                        check_reader()
                        raise VoiceCallFailure("ws-send") from exc
                    M.inc("loadgen_voice_media_frames_total", {"dir": "tx"})
                    deadline += FRAME_SECONDS
                    delay = deadline - time.monotonic()
                    if delay > 0:
                        await asyncio.sleep(delay)

            read_task = asyncio.create_task(reader())
            try:
                # Give receive-side close/error frames a chance to become authoritative
                # before the send path starts buffering media.
                await asyncio.sleep(0)
                check_reader()
                # caller listens to the greeting first
                await send_audio(silence_ulaw(rng.uniform(2.0, 4.0)))

                turns = rng.choices([1, 2, 3, 4], weights=[0.2, 0.35, 0.3, 0.15])[0]
                for turn in range(turns):
                    # a call opens with the reason for calling, then follows up
                    line = rng.choice(VOICE_OPENERS if turn == 0 else VOICE_FOLLOWUPS)
                    # real words first (STT can transcribe these), then the bot's own
                    # recorded speech, then tones — each is a fallback for the one before
                    clip = await tts_ulaw(line, rng)
                    source = "tts"
                    if clip is None and VOICE_USE_ECHO:
                        clip = ECHO.sample(rng)
                        source = "echo"
                    if clip is None:
                        clip = synth_speech_ulaw(rng.uniform(1.5, 3.5), rng)
                        source = "synth"
                    M.inc("loadgen_voice_utterances_total", {"source": source})
                    await send_audio(clip)
                    # silence while the bot thinks and answers
                    await send_audio(silence_ulaw(rng.uniform(3.0, 6.0)))

                # Let a peer-initiated clean close become visible before emitting our
                # legitimate stop. Otherwise a buffered send can mask an early hang-up.
                await asyncio.sleep(VOICE_PRE_STOP_SETTLE_SECONDS)
                check_reader()
                await asyncio.wait_for(
                    ws.send(json.dumps({"event": "stop", "streamSid": stream_sid,
                                        "stop": {"accountSid": account_sid, "callSid": call_sid}})),
                    VOICE_IO_TIMEOUT_SECONDS,
                )
                stop_sent = True
                try:
                    await asyncio.wait_for(asyncio.shield(read_task), VOICE_READER_SETTLE_SECONDS)
                except asyncio.TimeoutError:
                    read_task.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await read_task
                check_reader()
                if receive["frames"] == 0:
                    raise VoiceCallFailure("missing-media")
            finally:
                if read_task is not None:
                    if not read_task.done():
                        read_task.cancel()
                    # The main path checks and propagates receive failures. This cleanup
                    # await retrieves any secondary terminal error without masking it.
                    with contextlib.suppress(asyncio.CancelledError, Exception):
                        await read_task
        finally:
            with contextlib.suppress(Exception):
                await websocket.__aexit__(None, None, None)

        record("voice", "call", "voice-bidirectional", time.monotonic() - t0)
        _voice_attempt("success", "bidirectional-media", t0)
        M.inc("loadgen_sessions_total", {"app": "voice", "outcome": "voice-bidirectional"})
        successful = True
    except asyncio.CancelledError:
        _voice_attempt("failure", "cancelled", t0)
        raise
    except VoiceCallFailure as exc:
        record("voice", "call", exc.reason, time.monotonic() - t0)
        _voice_attempt("failure", exc.reason, t0)
        M.inc("loadgen_errors_total", {"app": "voice", "op": "call", "kind": exc.reason})
        M.inc("loadgen_sessions_total", {"app": "voice", "outcome": "voice-failed"})
        log.debug("voice call failed: %s", exc.reason)
    except Exception:  # noqa: BLE001
        record("voice", "call", "internal", time.monotonic() - t0)
        _voice_attempt("failure", "internal", t0)
        M.inc("loadgen_errors_total", {"app": "voice", "op": "call", "kind": "internal"})
        M.inc("loadgen_sessions_total", {"app": "voice", "outcome": "voice-failed"})
        log.debug("voice call failed: internal error")

    if successful and VOICE_USE_ECHO and received:
        ECHO.offer(bytes(received))


# ── scheduler ───────────────────────────────────────────────────────────────────


@dataclass
class App:
    name: str
    driver: Callable[[Ctx], Awaitable[None]]
    timeout: float
    client_kwargs: dict[str, Any] = field(default_factory=dict)


APPS: list[App] = [
    App("crm", crm_session, 30.0),
    App("voice", voice_session, 180.0),
    App("vllm", vllm_session, 180.0),
    App("litellm", litellm_session, 120.0),
    App("mcp", mcp_session, 45.0),
    App("chroma", chroma_session, 30.0),
]


async def run_app(app: App, stop: asyncio.Event) -> None:
    """Poisson arrivals into a bounded worker pool, shaped by the diurnal curve."""
    limits = httpx.Limits(max_connections=MAX_CONCURRENCY[app.name] * 2, max_keepalive_connections=8)
    sem = asyncio.Semaphore(MAX_CONCURRENCY[app.name])
    inflight: set[asyncio.Task[Any]] = set()
    rng = random.Random(hashlib.sha256(app.name.encode()).digest()[0] ^ os.getpid())

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(app.timeout, connect=10.0),
        limits=limits,
        headers={"User-Agent": f"phorvex-loadgen/1.0 ({app.name})"},
        follow_redirects=True,
        **app.client_kwargs,
    ) as client:
        ctx = Ctx(http=client, rng=rng)

        async def one() -> None:
            async with sem:
                try:
                    await asyncio.wait_for(app.driver(ctx), timeout=app.timeout)
                except asyncio.TimeoutError:
                    M.inc("loadgen_errors_total", {"app": app.name, "op": "session", "kind": "Timeout"})
                    M.inc("loadgen_sessions_total", {"app": app.name, "outcome": "timeout"})
                except Exception as exc:  # noqa: BLE001 — one bad session must not kill the app loop
                    M.inc("loadgen_errors_total", {"app": app.name, "op": "session", "kind": type(exc).__name__})
                    log.warning("%s session crashed: %s: %s", app.name, type(exc).__name__, exc)

        while not stop.is_set():
            factor = diurnal_factor()
            rate_per_min = BASE_SPM[app.name] * RATE_SCALE * factor
            M.gauge("loadgen_target_sessions_per_min", rate_per_min, {"app": app.name})
            M.gauge("loadgen_diurnal_factor", factor)
            if rate_per_min <= 0:
                await asyncio.sleep(5)
                continue

            wait = rng.expovariate(rate_per_min / 60.0)
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=min(wait, 60.0))
            if stop.is_set():
                break
            if wait > 60.0:
                continue  # re-evaluate the rate rather than sleeping through a rate change

            if sem.locked():
                # every worker busy: a real arrival here would queue or hang up
                M.inc("loadgen_sessions_total", {"app": app.name, "outcome": "shed"})
                continue

            task = asyncio.create_task(one())
            inflight.add(task)
            task.add_done_callback(inflight.discard)
            M.gauge("loadgen_inflight_sessions", len(inflight), {"app": app.name})

        for task in list(inflight):
            task.cancel()
        await asyncio.gather(*inflight, return_exceptions=True)


# ── metrics / health server ─────────────────────────────────────────────────────


async def serve_metrics(port: int) -> asyncio.AbstractServer:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request = await asyncio.wait_for(reader.readline(), timeout=5)
            path = request.decode("latin-1").split(" ")[1] if b" " in request else "/"
            while True:  # drain headers
                line = await asyncio.wait_for(reader.readline(), timeout=5)
                if line in (b"\r\n", b"\n", b""):
                    break
            if path.startswith("/metrics"):
                body = M.render().encode()
                ctype = "text/plain; version=0.0.4"
            elif path.startswith("/healthz"):
                body = b'{"ok":true}'
                ctype = "application/json"
            else:
                body, ctype = b"phorvex-loadgen\n", "text/plain"
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: "
                + ctype.encode()
                + b"\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\nConnection: close\r\n\r\n"
                + body
            )
            await writer.drain()
        except Exception:  # noqa: BLE001
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    return await asyncio.start_server(handle, "0.0.0.0", port)


# ── main ────────────────────────────────────────────────────────────────────────


async def main() -> None:
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    apps = [a for a in APPS if a.name in ENABLED_APPS]
    log.info(
        "starting: apps=%s rate_scale=%.2f writes=%s (%.1f/min) diurnal=%s",
        [a.name for a in apps],
        RATE_SCALE,
        ENABLE_WRITES,
        WRITES_PER_MIN,
        DIURNAL,
    )
    M.gauge("loadgen_up", 1)
    M.gauge("loadgen_writes_enabled", 1 if ENABLE_WRITES else 0)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stop.set)

    server = await serve_metrics(METRICS_PORT)
    log.info("metrics on :%d/metrics", METRICS_PORT)

    async def heartbeat() -> None:
        while not stop.is_set():
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=60)
            if stop.is_set():
                return
            totals: dict[str, float] = {}
            for (name, labels), v in M._counters.items():  # noqa: SLF001 — internal by design
                if name == "loadgen_sessions_total":
                    app = dict(labels).get("app", "?")
                    totals[app] = totals.get(app, 0.0) + v
            log.info(
                "sessions so far: %s | diurnal=%.2f",
                " ".join(f"{k}={int(v)}" for k, v in sorted(totals.items())) or "none",
                diurnal_factor(),
            )

    tasks = [asyncio.create_task(run_app(a, stop)) for a in apps]
    tasks.append(asyncio.create_task(heartbeat()))
    try:
        await stop.wait()
    finally:
        log.info("shutting down")
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        server.close()
        with contextlib.suppress(Exception):
            await server.wait_closed()


if __name__ == "__main__":
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main())
