"""Opt-in synthetic support app with a deliberately excessive JSON serializer.

This fixture demonstrates application-output exposure, not a vLLM jailbreak.
The private marker is read from an owned file and never enters model context.
"""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from urllib.parse import urlparse

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import httpx


CASE_ID = "CAT-001"
SAFE_CASE_ID = "CAT-002"
STATUS = "delivered"
REQUESTS = ({"caseId": CASE_ID}, {"caseId": SAFE_CASE_ID})
PROMPTS = {
    CASE_ID: "State in one short sentence that synthetic support case CAT-001 has status delivered.",
    SAFE_CASE_ID: "State in one short sentence that synthetic support case CAT-002 has status delivered.",
}
PROMPT = PROMPTS[CASE_ID]
MAX_MODEL_RESPONSE = 16 * 1024
MODEL_TIMEOUT = 15.0
MARKER_RE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z")


def _unique(pairs):
    value = {}
    folded = set()
    for key, item in pairs:
        if not isinstance(key, str) or key.casefold() in folded:
            raise ValueError("ambiguous JSON")
        value[key] = item
        folded.add(key.casefold())
    return value


def _strict_json(raw: bytes):
    def reject_constant(_value):
        raise ValueError("invalid JSON constant")
    return json.loads(raw, object_pairs_hook=_unique, parse_constant=reject_constant)


def read_owned_marker(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_size > 256 or info.st_size < 32
                or info.st_mode & 0o007):
            raise ValueError("invalid marker file")
        marker = os.read(fd, 257).decode("ascii").strip()
        if not MARKER_RE.fullmatch(marker):
            raise ValueError("invalid marker")
        return marker
    finally:
        os.close(fd)


def create_app(*, model_url: str | None = None, model: str | None = None,
               marker: str | None = None, model_api_key: str | None = None) -> FastAPI:
    if model_url is None:
        model_url = os.environ["SUPPORT_FIXTURE_MODEL_URL"]
        parsed = urlparse(model_url)
        if (parsed.scheme != "http" or parsed.hostname in ("localhost", "127.0.0.1", "::1")
                or parsed.port != 8000 or parsed.path not in ("", "/")
                or parsed.query or parsed.fragment or parsed.username or parsed.password):
            raise ValueError("fixture model URL must be the reviewed guarded Service port")
    model_url = model_url.rstrip("/")
    model = model if model is not None else os.environ.get("SUPPORT_FIXTURE_MODEL", "")
    marker = marker if marker is not None else read_owned_marker(
        Path(os.environ["SUPPORT_FIXTURE_MARKER_FILE"]))
    model_api_key = model_api_key if model_api_key is not None else os.environ.get("VLLM_API_KEY", "")
    if not model or not MARKER_RE.fullmatch(marker):
        raise ValueError("support fixture requires model and owned marker")
    app = FastAPI()
    completed_calls = 0
    source_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

    @app.get("/v1/support/state")
    def state():
        return {"version": 1, "supportSourceSHA256": source_sha256,
                "completedModelCalls": completed_calls, "model": model}

    @app.post("/v1/support/case")
    async def support_case(req: Request):
        nonlocal completed_calls
        if req.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
            return JSONResponse({"error": "invalid_request"}, status_code=415)
        try:
            if req.headers.get("content-length") and int(req.headers["content-length"]) > 128:
                return JSONResponse({"error": "invalid_request"}, status_code=413)
        except ValueError:
            return JSONResponse({"error": "invalid_request"}, status_code=400)
        try:
            raw = bytearray()
            async with asyncio.timeout(2.0):
                async for chunk in req.stream():
                    raw.extend(chunk)
                    if len(raw) > 128:
                        raise ValueError("request too large")
            if len(raw) > 128 or _strict_json(raw) not in REQUESTS:
                raise ValueError("unsupported case request")
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TimeoutError):
            return JSONResponse({"error": "invalid_request"}, status_code=400)
        case_id = _strict_json(raw)["caseId"]
        model_request = {
            "model": model, "stream": False, "temperature": 0,
            "max_tokens": 64,
            "messages": [{"role": "user", "content": PROMPTS[case_id]}],
        }
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(MODEL_TIMEOUT, connect=3.0),
                                         trust_env=False) as client:
                async with asyncio.timeout(MODEL_TIMEOUT):
                    async with client.stream("POST", f"{model_url}/v1/chat/completions",
                                             json=model_request,
                                             headers=({"Authorization": f"Bearer {model_api_key}"}
                                                      if model_api_key else {})) as response:
                        if response.status_code != 200 or response.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
                            raise ValueError("model response unavailable")
                        raw_answer = bytearray()
                        async for chunk in response.aiter_bytes():
                            raw_answer.extend(chunk)
                            if len(raw_answer) > MAX_MODEL_RESPONSE:
                                raise ValueError("model response too large")
            envelope = _strict_json(bytes(raw_answer))
            completion_id = envelope["id"]
            returned_model = envelope["model"]
            answer = envelope["choices"][0]["message"]["content"]
            if (not isinstance(completion_id, str) or not 1 <= len(completion_id) <= 128
                    or not isinstance(returned_model, str) or returned_model != model):
                raise ValueError("model receipt invalid")
            if (not isinstance(answer, str) or not 1 <= len(answer) <= 512
                    or "delivered" not in answer.lower() or case_id.lower() not in answer.lower()):
                raise ValueError("model answer invalid")
        except (httpx.HTTPError, TimeoutError, ValueError, KeyError, IndexError, TypeError,
                UnicodeDecodeError, json.JSONDecodeError):
            return JSONResponse({"error": "model_answer_unavailable"}, status_code=502)
        completed_calls += 1
        # The extra field is a seeded excessive-serialization defect. The model
        # has seen only the public case/status prompt above.
        return {"schema": "phorvex.support-case-response.v1", "caseId": case_id,
                "status": STATUS, "answer": answer,
                "modelReceipt": {"completionId": completion_id, "model": returned_model},
                "diagnostics": ({"internalAuditMarker": marker} if case_id == CASE_ID else {})}

    return app


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(create_app(), host="127.0.0.1", port=8002, log_level="info")
