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
from functools import wraps
import importlib.metadata
import hmac
import hashlib
import json
import math
import os
from pathlib import Path
import sys
import threading
import types
from typing import Mapping
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

try:
    from drain_v11 import (Coordinator, DrainError, EngineHTTPClient, Ledger,
                           strict_loads)
except ModuleNotFoundError:
    Coordinator = EngineHTTPClient = Ledger = None

    class DrainError(Exception):
        pass

    def strict_loads(*_args, **_kwargs):
        raise DrainError("drain v11 module unavailable")

UPSTREAM = "http://127.0.0.1:8001"
VARIANT_MODELS = {
    "pgv2": "protectai/deberta-v3-base-prompt-injection-v2",
    "pgv1": "protectai/deberta-v3-base-prompt-injection",
}
DEFAULT_THRESHOLD = 0.5
MODES = frozenset(("enforce", "observe"))
RESET_RESPONSE_MAX_BYTES = 1 << 16
SUPPORT_REQUEST_MAX_BYTES = 128
SUPPORT_TIMEOUT_SECONDS = 20.0
SUPPORT_URL = "http://127.0.0.1:8002"
SUPPORT_RESPONSE_MAX_BYTES = 65536


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


def _reset_success(body: bytes) -> bool:
    if not body or len(body) > RESET_RESPONSE_MAX_BYTES:
        raise ValueError("reset acknowledgement has invalid size")

    def unique_object(pairs):
        result = {}
        folded = set()
        for key, value in pairs:
            normalized = key.casefold()
            if key in result or normalized in folded:
                raise ValueError("reset acknowledgement has ambiguous fields")
            result[key] = value
            folded.add(normalized)
        return result

    def reject_constant(value):
        raise ValueError(f"invalid JSON constant {value}")

    try:
        envelope = json.loads(body, object_pairs_hook=unique_object,
                              parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("reset acknowledgement is not valid JSON") from exc
    if not isinstance(envelope, dict):
        raise ValueError("reset acknowledgement must be an object")
    success = envelope.get("success")
    if type(success) is not bool:
        raise ValueError("reset acknowledgement requires boolean success")
    return success


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
               load_models: bool = True,
               upstream_api_key: str | None = None,
               admin_api_key: str | None = None,
               drain_coordinator=None, support_fixture_enabled: bool | None = None,
               support_fixture_url: str | None = None,
               output_policy_dir: str | Path | None = None,
               output_policy_state_dir: str | Path | None = None,
               pod_uid: str | None = None) -> FastAPI:
    runtime = runtime or GuardrailRuntime(load_config())
    upstream_api_key = upstream_api_key if upstream_api_key is not None else os.environ.get("VLLM_API_KEY", "")
    admin_api_key = admin_api_key if admin_api_key is not None else upstream_api_key
    support_fixture_enabled = (os.environ.get("PHORVEX_SUPPORT_FIXTURE_ENABLED") == "1"
                               if support_fixture_enabled is None else support_fixture_enabled)
    support_fixture_url = (support_fixture_url or os.environ.get("SUPPORT_FIXTURE_URL")
                           or SUPPORT_URL).rstrip("/")
    policy_reader = None
    proxy_source_sha256 = ""
    PolicyError = ValueError
    strict_json = transform_response = None
    if support_fixture_enabled:
        # Execute exactly the policy bytes included in the frozen composite
        # source digest; Python's module cache cannot substitute other bytes.
        policy_path = Path(__file__).resolve().parent / "output_policy.py"
        policy_bytes = policy_path.read_bytes()
        module_name = f"phorvex_output_policy_{hashlib.sha256(policy_bytes).hexdigest()[:16]}"
        policy_module = types.ModuleType(module_name)
        policy_module.__file__ = str(policy_path)
        sys.modules[module_name] = policy_module
        exec(compile(policy_bytes, str(policy_path), "exec"), policy_module.__dict__)
        PolicyError = policy_module.PolicyError
        PolicyReader = policy_module.PolicyReader
        strict_json = policy_module.strict_json
        transform_response = policy_module.transform_response
        pod_uid = pod_uid if pod_uid is not None else os.environ.get("POD_UID", "")
        directory = output_policy_dir or os.environ.get(
            "PHORVEX_SENSITIVE_OUTPUT_POLICY_DIR", "/etc/phorvex/output-policy")
        state_dir = output_policy_state_dir or os.environ.get(
            "PHORVEX_SENSITIVE_OUTPUT_STATE_DIR", "/var/lib/phorvex-output-policy")
        policy_reader = PolicyReader(Path(directory), pod_uid, Path(state_dir))
        proxy_source_sha256 = hashlib.sha256(
            Path(__file__).read_bytes() + b"\x00" + policy_bytes).hexdigest()
        parsed_support = urlparse(support_fixture_url)
        if (parsed_support.scheme != "http" or parsed_support.hostname != "127.0.0.1"
                or parsed_support.port is None or parsed_support.path not in ("", "/")
                or parsed_support.query or parsed_support.fragment
                or parsed_support.username or parsed_support.password):
            raise ValueError("support fixture must be on loopback")
    inflight = set()  # asyncio tasks proxying generation requests — the drain target

    async def snapshot_proxy():
        active = [task for task in inflight if not task.done()]
        return {"active": len(active)}

    async def terminate_proxy():
        active = [task for task in inflight if not task.done()]
        for task in active:
            task.cancel()
        if active:
            await asyncio.gather(*active, return_exceptions=True)
        return {"cancelled": len(active), "remaining": sum(
            1 for task in inflight if not task.done())}

    drain_control = drain_coordinator
    if drain_control is None and os.environ.get("PHORVEX_DRAIN_V11") == "1":
        if Coordinator is None:
            raise RuntimeError("drain v11 module is unavailable")
        if not upstream_api_key or not admin_api_key:
            raise RuntimeError("drain v11 requires upstream and admin credentials")
        pod_uid = os.environ.get("POD_UID", "")
        proxy_source = os.environ.get("PHORVEX_PROXY_SOURCE", "")
        engine_source = os.environ.get("PHORVEX_ENGINE_SOURCE", "")
        model_digest = os.environ.get("PHORVEX_MODEL_DIGEST", "")
        if not all((pod_uid, proxy_source, engine_source, model_digest)):
            raise RuntimeError("drain v11 source and identity bindings are required")
        drain_control = Coordinator(
            Ledger(Path(os.environ.get("PHORVEX_DRAIN_LEDGER_DIR",
                                      "/var/lib/phorvex-drain")), pod_uid),
            EngineHTTPClient(upstream, upstream_api_key, engine_source),
            pod_uid=pod_uid, proxy_source=proxy_source,
            model_digest=model_digest, snapshot_proxy=snapshot_proxy,
            terminate_proxy=terminate_proxy)

    @asynccontextmanager
    async def lifespan(_app):
        if drain_control is not None:
            await drain_control.initialize()
        if load_models:
            threading.Thread(target=runtime.load_all, daemon=True).start()
        yield

    app = FastAPI(lifespan=lifespan)
    app.state.guardrail_runtime = runtime

    @app.get("/v1/output-policy/state")
    async def output_policy_state():
        if policy_reader is None:
            return JSONResponse({"error": "output_policy_unavailable"}, status_code=503)
        try:
            result = policy_reader.read().public()
            result["proxySourceSHA256"] = proxy_source_sha256
            async with httpx.AsyncClient(timeout=httpx.Timeout(2.0, connect=1.0),
                                         trust_env=False) as client:
                async with asyncio.timeout(2.0):
                    async with client.stream("GET", f"{support_fixture_url}/v1/support/state",
                                             headers={"Accept": "application/json",
                                                      "Accept-Encoding": "identity"}) as response:
                        if response.status_code != 200 or response.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
                            raise PolicyError("support source unavailable")
                        raw = bytearray()
                        async for chunk in response.aiter_raw():
                            raw.extend(chunk)
                            if len(raw) > 1024:
                                raise PolicyError("support state too large")
            support_state = strict_json(bytes(raw))
            source = support_state.get("supportSourceSHA256") if type(support_state) is dict else None
            if (type(support_state) is not dict
                    or set(support_state) != {"version", "supportSourceSHA256", "completedModelCalls", "model"}
                    or type(support_state["version"]) is not int or support_state["version"] != 1
                    or type(source) is not str or len(source) != 64
                    or any(char not in "0123456789abcdef" for char in source)
                    or type(support_state["completedModelCalls"]) is not int
                    or support_state["completedModelCalls"] < 0
                    or type(support_state["model"]) is not str or not support_state["model"]):
                raise PolicyError("support state invalid")
            result["supportSourceSHA256"] = source
            return result
        except (PolicyError, httpx.HTTPError, TimeoutError, OSError):
            return JSONResponse({"error": "output_policy_unavailable"}, status_code=503)

    @app.api_route("/v1/support/case", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"])
    async def support_case(req: Request):
        if policy_reader is None:
            return JSONResponse({"error": "support_fixture_disabled"}, status_code=404)
        if req.method != "POST":
            return JSONResponse({"error": "method_not_allowed"}, status_code=405)
        if req.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
            return JSONResponse({"error": "invalid_support_request"}, status_code=415)
        if "text/event-stream" in req.headers.get("accept", "").lower():
            return JSONResponse({"error": "support_stream_unsupported"}, status_code=400)
        try:
            length_text = req.headers.get("content-length")
            if length_text is not None and (not length_text.isdecimal()
                                            or int(length_text) > SUPPORT_REQUEST_MAX_BYTES):
                raise PolicyError("request length invalid")
            raw = bytearray()
            async with asyncio.timeout(2.0):
                async for chunk in req.stream():
                    raw.extend(chunk)
                    if len(raw) > SUPPORT_REQUEST_MAX_BYTES:
                        raise PolicyError("request too large")
            request_value = strict_json(bytes(raw))
            if type(request_value) is not dict or request_value not in (
                    {"caseId": "CAT-001"}, {"caseId": "CAT-002"}):
                raise PolicyError("request schema invalid")
        except (PolicyError, TimeoutError):
            return JSONResponse({"error": "invalid_support_request"}, status_code=400)
        try:
            initial = policy_reader.read()
        except PolicyError:
            return JSONResponse({"error": "output_policy_unavailable"}, status_code=503)

        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(SUPPORT_TIMEOUT_SECONDS,
                                                              connect=3.0),
                                         trust_env=False) as client:
                async with asyncio.timeout(SUPPORT_TIMEOUT_SECONDS):
                    async with client.stream("POST", f"{support_fixture_url}/v1/support/case",
                                             content=bytes(raw), headers={
                                                 "Content-Type": "application/json",
                                                 "Accept": "application/json",
                                                 "Accept-Encoding": "identity",
                                             }) as upstream_response:
                        if upstream_response.status_code != 200:
                            raise PolicyError("support upstream returned error")
                        if (upstream_response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                                != "application/json"):
                            raise PolicyError("support upstream content type invalid")
                        if upstream_response.headers.get("content-encoding", "identity").lower() != "identity":
                            raise PolicyError("support upstream content encoding invalid")
                        if upstream_response.headers.get("transfer-encoding"):
                            raise PolicyError("support upstream streaming unsupported")
                        length_text = upstream_response.headers.get("content-length", "")
                        if not length_text.isdecimal() or not 0 < int(length_text) <= SUPPORT_RESPONSE_MAX_BYTES:
                            raise PolicyError("support upstream length invalid")
                        expected_length = int(length_text)
                        response_raw = bytearray()
                        async for chunk in upstream_response.aiter_raw():
                            response_raw.extend(chunk)
                            if len(response_raw) > SUPPORT_RESPONSE_MAX_BYTES:
                                raise PolicyError("support upstream too large")
                        if len(response_raw) != expected_length:
                            raise PolicyError("support upstream truncated")
            final = policy_reader.read()
            # The mount can update while the upstream call is in flight. Either
            # active snapshot requires removal before any response bytes leave.
            transformed = transform_response(bytes(response_raw),
                                             initial.active or final.active
                                             or initial.revision != final.revision)
        except (PolicyError, httpx.HTTPError, TimeoutError):
            return JSONResponse({"error": "support_response_unavailable"}, status_code=502)
        return Response(content=transformed, status_code=200, media_type="application/json")

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
    async def legacy_drain(req: Request):
        """Deployment-specific drain-all: abort in-flight generation proxy tasks."""
        if drain_coordinator is not None or os.environ.get("PHORVEX_DRAIN_V11") == "1":
            return JSONResponse({"error": "operation-bound drain required"},
                                status_code=410)
        body = await req.json()
        aborted = 0
        if body.get("abort_inflight", True):
            for task in list(inflight):
                if not task.done():
                    task.cancel()
                    aborted += 1
        print(json.dumps({"event": "guardrail_drain", "aborted": aborted}, separators=(",", ":")), flush=True)
        return {"aborted": aborted}

    def admin_authorized(req):
        presented = req.headers.get("Authorization", "")
        expected = f"Bearer {admin_api_key}" if admin_api_key else ""
        return bool(expected) and hmac.compare_digest(presented, expected)

    async def admin_body(req, required, optional=()):
        if not admin_authorized(req):
            raise DrainError(401, "unauthorized")
        content_type = req.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise DrainError(415, "application_json_required")
        value = strict_loads(await req.body(), max_bytes=16384)
        if (not isinstance(value, dict)
                or set(value) not in (set(required), set(required) | set(optional))):
            raise DrainError(400, "invalid_fields")
        return value

    def drain_response(call):
        @wraps(call)
        async def wrapped(*args, **kwargs):
            if drain_control is None:
                return JSONResponse({"error": "drain_unavailable"}, status_code=503)
            try:
                return await call(*args, **kwargs)
            except DrainError as exc:
                return JSONResponse({"error": exc.code}, status_code=exc.status)
            except Exception:
                return JSONResponse({"error": "drain_unavailable"}, status_code=503)
        return wrapped

    @app.get("/v1/drain/capability")
    @drain_response
    async def drain_capability(req: Request):
        if not admin_authorized(req):
            raise DrainError(401, "unauthorized")
        return JSONResponse(await drain_control.capability(), status_code=200)

    @app.post("/v1/drain/operations")
    @drain_response
    async def drain_create(req: Request):
        body = await admin_body(req, {
            "schema", "operation_id", "operation_generation", "attempt",
            "owner", "expected_incarnation_digest", "deadline", "mode",
        }, {"supersedes"})
        status, response = await drain_control.create(body)
        return JSONResponse(response, status_code=status)

    @app.get("/v1/drain/operations/{generation}/{operation_id}")
    @drain_response
    async def drain_status(generation: str, operation_id: str, req: Request):
        if not admin_authorized(req):
            raise DrainError(401, "unauthorized")
        return JSONResponse(await drain_control.status(
            generation, operation_id, req.query_params.get("observation_nonce")),
            status_code=200)

    @app.post("/v1/drain/operations/{generation}/{operation_id}/cancel")
    @drain_response
    async def drain_cancel(generation: str, operation_id: str, req: Request):
        body = await admin_body(req, {
            "owner_digest", "expected_incarnation_digest", "expected_revision"})
        return JSONResponse(await drain_control.cancel(
            generation, operation_id, body["owner_digest"],
            body["expected_incarnation_digest"], body["expected_revision"]),
            status_code=200)

    @app.post("/v1/drain/operations/{generation}/{operation_id}/reopen")
    @drain_response
    async def drain_reopen(generation: str, operation_id: str, req: Request):
        body = await admin_body(req, {
            "owner_digest", "expected_incarnation_digest", "expected_revision"})
        return JSONResponse(await drain_control.reopen(
            generation, operation_id, body["owner_digest"],
            body["expected_incarnation_digest"], body["expected_revision"]),
            status_code=200)

    @app.post("/v1/kv/invalidate")
    async def kv_invalidate(req: Request):
        """Invalidate the deployment's worker-local vLLM prefix cache."""
        if not upstream_api_key or not admin_api_key:
            return JSONResponse({"error": "vLLM reset credential unavailable"}, status_code=503)
        if req.headers.get("Authorization") != f"Bearer {admin_api_key}":
            return JSONResponse({"error": "Unauthorized"}, status_code=401)
        body = await req.json()
        if not isinstance(body, dict) or body.get("local") is not True:
            return JSONResponse({"error": "local:true is required"}, status_code=400)
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                async with client.stream(
                    "POST",
                    f"{upstream}/reset_prefix_cache",
                    headers={"Authorization": f"Bearer {upstream_api_key}"},
                ) as response:
                    upstream_status = response.status_code
                    response_body = bytearray()
                    async for chunk in response.aiter_bytes():
                        response_body.extend(chunk)
                        if len(response_body) > RESET_RESPONSE_MAX_BYTES:
                            raise ValueError("reset acknowledgement exceeds size limit")
        except (httpx.HTTPError, ValueError):
            return JSONResponse({"success": False, "error": "reset acknowledgement unavailable"}, status_code=502)
        if upstream_status != 200:
            return JSONResponse({"success": False, "upstream": upstream_status}, status_code=502)
        try:
            success = _reset_success(bytes(response_body))
        except ValueError:
            return JSONResponse({"success": False, "error": "invalid reset acknowledgement"}, status_code=502)
        print(json.dumps({
            "event": "guardrail_kv_invalidate",
            "local": body.get("local"),
            "scope": "local-prefix-cache",
            "success": success,
        }, separators=(",", ":")), flush=True)
        return {"success": success, "scope": "local-prefix-cache"}

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"])
    async def proxy(path: str, req: Request):
        if path.startswith("v1/output-policy/"):
            return JSONResponse({"error": "method_not_allowed"}, status_code=405)
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
        if track and drain_control is not None:
            try:
                drain_control.admit_generation()
            except DrainError as exc:
                if task is not None:
                    inflight.discard(task)
                return JSONResponse({"error": exc.code}, status_code=exc.status)
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
