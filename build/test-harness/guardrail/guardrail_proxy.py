"""
Guardrail sidecar proxy — sits on the vLLM pod's serving port (8000), forwards to
vLLM on 127.0.0.1:8001. Two genuinely different prompt-injection classifiers
(ProtectAI DeBERTa v1 vs v2 — different training data, different blind spots) as the
rotatable variants. Phorvex's guardrail-rotate POSTs /v1/guardrail/reload to swap
the active variant; every chat/completions request is scanned by the ACTIVE variant.

Observe mode executes the same scoring path as enforcement and records a
prompt-free would-block verdict, but admits the request to one upstream attempt.
Admission does not claim a completed response or a safe prompt, and the proxy
never emits a SecurityEvent.
"""

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass
import importlib.metadata
import json
import math
import os
import sys
import threading
from typing import Mapping

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

UPSTREAM = "http://127.0.0.1:8001"
VARIANT_MODELS = {
    "pgv2": "protectai/deberta-v3-base-prompt-injection-v2",
    "pgv1": "protectai/deberta-v3-base-prompt-injection",
}
DEFAULT_THRESHOLD = 0.5
MODES = frozenset(("enforce", "observe"))


def _finite_threshold(name: str, raw: str) -> float:
    try:
        value = float(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a finite number in [0,1], got {raw!r}") from exc
    if not math.isfinite(value) or not 0 <= value <= 1:
        raise ValueError(f"{name} must be a finite number in [0,1], got {raw!r}")
    return value


@dataclass(frozen=True)
class GuardrailConfig:
    initial_variant: str
    mode: str
    thresholds: Mapping[str, float]


def load_config(environ: Mapping[str, str] | None = None) -> GuardrailConfig:
    env = os.environ if environ is None else environ
    initial = env.get("GUARDRAIL_INITIAL_VARIANT", "pgv2").strip()
    if initial not in VARIANT_MODELS:
        raise ValueError(f"GUARDRAIL_INITIAL_VARIANT must be one of {sorted(VARIANT_MODELS)}, got {initial!r}")
    mode = env.get("GUARDRAIL_MODE", "enforce").strip().lower()
    if mode not in MODES:
        raise ValueError(f"GUARDRAIL_MODE must be one of {sorted(MODES)}, got {mode!r}")
    thresholds = {
        variant: _finite_threshold(
            f"GUARDRAIL_THRESHOLD_{variant.upper()}",
            env.get(f"GUARDRAIL_THRESHOLD_{variant.upper()}", str(DEFAULT_THRESHOLD)),
        )
        for variant in VARIANT_MODELS
    }
    return GuardrailConfig(initial_variant=initial, mode=mode, thresholds=thresholds)


def _package_version(name: str) -> str:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


class GuardrailRuntime:
    """Mutable model/variant state; mode and thresholds are immutable startup config."""

    def __init__(self, config: GuardrailConfig):
        self.config = config
        self.thresholds = dict(config.thresholds)
        self.active = config.initial_variant
        self.classifiers = {}
        self.model_provenance = {
            name: {"model": model, "revision": "unknown"}
            for name, model in VARIANT_MODELS.items()
        }
        self.ready = False
        self.load_error = ""
        self.lock = threading.Lock()

    def install_classifier(self, variant: str, classifier, revision: str = "unknown") -> None:
        """Install a score producer. Tests use this seam but exercise all HTTP verdict logic."""
        if variant not in VARIANT_MODELS:
            raise ValueError(f"unknown variant {variant!r}")
        with self.lock:
            self.classifiers[variant] = classifier
            self.model_provenance[variant] = {
                "model": VARIANT_MODELS[variant],
                "revision": revision.strip() if isinstance(revision, str) and revision.strip() else "unknown",
            }
            self.ready = all(name in self.classifiers for name in VARIANT_MODELS)

    def load_all(self) -> None:
        try:
            import torch
            from transformers import pipeline

            torch.set_num_threads(2)
            for name, hf_id in VARIANT_MODELS.items():
                classifier = pipeline("text-classification", model=hf_id, truncation=True, max_length=512)
                revision = getattr(getattr(getattr(classifier, "model", None), "config", None), "_commit_hash", None)
                self.install_classifier(name, classifier, revision or "unknown")
                print(json.dumps({
                    "event": "guardrail_model_loaded",
                    "variant": name,
                    "model": hf_id,
                    "revision": revision or "unknown",
                }, separators=(",", ":")), flush=True)
        except Exception as exc:
            with self.lock:
                self.ready = False
                self.load_error = f"{type(exc).__name__}: {exc}"
            print(json.dumps({
                "event": "guardrail_model_load_failed",
                "error_type": type(exc).__name__,
            }, separators=(",", ":")), flush=True)

    def snapshot(self):
        with self.lock:
            active = self.active
            return active, self.config.mode, self.thresholds[active], self.ready, self.load_error

    def set_active(self, variant: str) -> None:
        with self.lock:
            self.active = variant

    def score(self, variant: str, text: str) -> float:
        with self.lock:
            classifier = self.classifiers.get(variant)
        if classifier is None:
            raise RuntimeError(f"classifier {variant!r} is unavailable")
        out = classifier(text[:4000])[0]  # pipeline truncates to 512 tokens
        label = str(out["label"]).upper()
        confidence = float(out["score"])
        score = confidence if ("INJ" in label or label == "LABEL_1") else 1.0 - confidence
        if not math.isfinite(score) or not 0 <= score <= 1:
            raise RuntimeError(f"classifier {variant!r} returned an invalid score")
        return score

    def public_state(self) -> dict:
        with self.lock:
            return {
                "ready": self.ready,
                "active": self.active,
                "mode": self.config.mode,
                "loaded": sorted(self.classifiers),
                "thresholds": dict(self.thresholds),
                "models": {name: dict(value) for name, value in self.model_provenance.items()},
                "runtime": {
                    "python": sys.version.split()[0],
                    "packages": {
                        name: _package_version(name)
                        for name in ("fastapi", "httpx", "torch", "transformers", "uvicorn")
                    },
                },
                **({"load_error": self.load_error} if self.load_error else {}),
            }


def _texts_from(payload):
    # Scan USER turns only — the system prompt is operator-trusted content (and would
    # false-positive on its own injection warnings).
    if not isinstance(payload, dict):
        return
    for message in payload.get("messages") or []:
        if not isinstance(message, dict) or message.get("role") != "user":
            continue
        content = message.get("content")
        if isinstance(content, str):
            yield content
    prompt = payload.get("prompt")
    if isinstance(prompt, str):
        yield prompt


def _verdict_log(*, variant: str, mode: str, threshold: float, score: float,
                 would_block: bool, outcome: str) -> None:
    # Deliberately omit prompt text and prompt-derived hashes. A request correlation ID
    # belongs at the caller boundary, where its privacy and cardinality can be governed.
    print(json.dumps({
        "event": "guardrail_verdict",
        "variant": variant,
        "mode": mode,
        "threshold": threshold,
        "score": score,
        "would_block": would_block,
        "outcome": outcome,
    }, separators=(",", ":"), sort_keys=True), flush=True)


def create_app(*, runtime: GuardrailRuntime | None = None, upstream: str = UPSTREAM,
               load_models: bool = True) -> FastAPI:
    runtime = runtime or GuardrailRuntime(load_config())
    inflight = set()  # asyncio tasks proxying generation requests — the drain target

    @asynccontextmanager
    async def lifespan(_app):
        if load_models:
            threading.Thread(target=runtime.load_all, daemon=True).start()
        yield

    app = FastAPI(lifespan=lifespan)
    app.state.guardrail_runtime = runtime

    @app.get("/v1/guardrail/state")
    def state():
        body = runtime.public_state()
        return body if body["ready"] else JSONResponse(body, status_code=503)

    @app.post("/v1/guardrail/reload")
    async def reload(req: Request):
        body = await req.json()
        variant = (body.get("variant") or "").strip() if isinstance(body, dict) else ""
        if variant not in VARIANT_MODELS:
            return JSONResponse({"error": f"unknown variant {variant!r}", "known": sorted(VARIANT_MODELS)}, status_code=400)
        _, _, _, ready, _ = runtime.snapshot()
        if not ready:
            return JSONResponse({"error": "guardrail still loading"}, status_code=503)
        runtime.set_active(variant)
        print(json.dumps({"event": "guardrail_variant_changed", "variant": variant}, separators=(",", ":")), flush=True)
        return {"active": variant, "applied": True}

    @app.post("/v1/guardrail/classify")
    async def classify_debug(req: Request):
        """Calibration/debug: score text under BOTH variants without blocking anything."""
        body = await req.json()
        text = (body.get("text") or "") if isinstance(body, dict) else ""
        _, _, _, ready, _ = runtime.snapshot()
        if not ready:
            return JSONResponse({"error": "guardrail still loading"}, status_code=503)
        try:
            return {variant: runtime.score(variant, text) for variant in VARIANT_MODELS}
        except Exception as exc:
            return JSONResponse({"error": "guardrail score unavailable", "error_type": type(exc).__name__}, status_code=503)

    @app.post("/v1/drain")
    async def drain(req: Request):
        """Deployment-specific drain-all: abort in-flight generation proxy tasks."""
        body = await req.json()
        aborted = 0
        if body.get("abort_inflight", True):
            for task in list(inflight):
                if not task.done():
                    task.cancel()
                    aborted += 1
        print(json.dumps({"event": "guardrail_drain", "aborted": aborted}, separators=(",", ":")), flush=True)
        return {"aborted": aborted}

    @app.post("/v1/kv/invalidate")
    async def kv_invalidate(req: Request):
        """Invalidate the deployment's worker-local vLLM prefix cache."""
        body = await req.json()
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(f"{upstream}/reset_prefix_cache")
        if response.status_code != 200:
            return JSONResponse({"invalidated": False, "upstream": response.status_code}, status_code=502)
        print(json.dumps({
            "event": "guardrail_kv_invalidate",
            "local": body.get("local"),
            "scope": "local-prefix-cache",
        }, separators=(",", ":")), flush=True)
        return {"invalidated": True, "scope": "local-prefix-cache"}

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"])
    async def proxy(path: str, req: Request):
        body = await req.body()
        if req.method == "POST" and path in ("v1/chat/completions", "v1/completions"):
            active, mode, threshold, ready, _ = runtime.snapshot()
            if not ready:
                return JSONResponse({"error": "guardrail still loading"}, status_code=503)
            try:
                payload = json.loads(body or b"{}")
            except Exception:
                payload = {}
            try:
                scores = [runtime.score(active, text) for text in _texts_from(payload)]
            except Exception as exc:
                return JSONResponse({"error": "guardrail score unavailable", "error_type": type(exc).__name__}, status_code=503)
            if scores:
                # One immutable config snapshot and the maximum score across every user
                # turn make a single coherent, conservative verdict for the request.
                score = max(scores)
                would_block = score >= threshold
                if would_block and mode == "enforce":
                    _verdict_log(variant=active, mode=mode, threshold=threshold, score=score,
                                 would_block=True, outcome="blocked")
                    return JSONResponse(
                        {"error": {"message": f"blocked by guardrail (variant={active}, injection-score={score:.3f})",
                                   "type": "guardrail_blocked"}},
                        status_code=403,
                    )
                # This verdict is emitted before the upstream request. "Admitted"
                # describes only the guardrail decision; it never claims that the
                # upstream accepted or completed the request.
                outcome = "admitted_observe" if mode == "observe" else "admitted_enforce"
                _verdict_log(variant=active, mode=mode, threshold=threshold, score=score,
                             would_block=would_block, outcome=outcome)

        url = f"{upstream}/{path}"
        headers = {key: value for key, value in req.headers.items()
                   if key.lower() not in ("host", "content-length", "accept-encoding")}
        headers["accept-encoding"] = "identity"
        track = req.method == "POST" and path in ("v1/chat/completions", "v1/completions")
        task = asyncio.current_task()
        if track and task is not None:
            inflight.add(task)
        client = httpx.AsyncClient(timeout=httpx.Timeout(300.0, connect=5.0))
        try:
            response = await client.send(
                client.build_request(req.method, url, content=body, headers=headers, params=req.query_params),
                stream=True,
            )
        except httpx.HTTPError as exc:
            await client.aclose()
            if track and task is not None:
                inflight.discard(task)
            return JSONResponse({"error": "upstream unavailable", "error_type": type(exc).__name__}, status_code=502)
        except BaseException:
            await client.aclose()
            if track and task is not None:
                inflight.discard(task)
            raise

        async def relay():
            try:
                async for chunk in response.aiter_raw():
                    yield chunk
            finally:
                await response.aclose()
                await client.aclose()
                if track and task is not None:
                    inflight.discard(task)

        passthrough = {key: value for key, value in response.headers.items() if key.lower() in ("content-type",)}
        return StreamingResponse(relay(), status_code=response.status_code, headers=passthrough)

    return app


# Invalid startup configuration raises before uvicorn begins serving; it never
# silently turns enforcement off.
CONFIG = load_config()
RUNTIME = GuardrailRuntime(CONFIG)
app = create_app(runtime=RUNTIME)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
