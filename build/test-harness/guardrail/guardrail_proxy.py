"""
Guardrail sidecar proxy — sits on the vLLM pod's serving port (8000), forwards to
vLLM on 127.0.0.1:8001. Two genuinely different prompt-injection classifiers
(ProtectAI DeBERTa v1 vs v2 — different training data, different blind spots) as the
rotatable variants. Phorvex's guardrail-rotate POSTs /v1/guardrail/reload to swap
the active variant; every chat/completions request is scanned by the ACTIVE variant.
"""

import asyncio
import os
import threading

import httpx
import torch
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from transformers import pipeline

UPSTREAM = "http://127.0.0.1:8001"
VARIANTS = {
    # name -> (HF model, injection-block threshold)
    "pgv2": ("protectai/deberta-v3-base-prompt-injection-v2", 0.5),
    "pgv1": ("protectai/deberta-v3-base-prompt-injection", 0.5),
}
INITIAL = os.environ.get("GUARDRAIL_INITIAL_VARIANT", "pgv2")

torch.set_num_threads(2)
app = FastAPI()
_lock = threading.Lock()
_state = {"active": INITIAL, "models": {}, "ready": False}
INFLIGHT = set()  # asyncio tasks proxying generation requests — the drain target


def _load_all():
    for name, (hf_id, _) in VARIANTS.items():
        _state["models"][name] = pipeline("text-classification", model=hf_id, truncation=True, max_length=512)
        print(f"[guardrail] loaded variant {name} <- {hf_id}", flush=True)
    _state["ready"] = True


@app.on_event("startup")
def startup():
    threading.Thread(target=_load_all, daemon=True).start()


def _score(variant: str, text: str) -> float:
    clf = _state["models"].get(variant)
    if clf is None:
        return -1.0
    out = clf(text[:4000])[0]  # pipeline truncates to 512 tokens
    label = out["label"].upper()
    return float(out["score"]) if ("INJ" in label or label == "LABEL_1") else 1.0 - float(out["score"])


@app.get("/v1/guardrail/state")
def state():
    body = {
        "ready": _state["ready"],
        "active": _state["active"],
        "loaded": sorted(_state["models"].keys()),
        "thresholds": {k: v[1] for k, v in VARIANTS.items()},
    }
    return body if _state["ready"] else JSONResponse(body, status_code=503)


@app.post("/v1/guardrail/reload")
async def reload(req: Request):
    body = await req.json()
    variant = (body.get("variant") or "").strip()
    if variant not in VARIANTS:
        return JSONResponse({"error": f"unknown variant {variant!r}", "known": sorted(VARIANTS)}, status_code=400)
    if not _state["ready"]:
        return JSONResponse({"error": "guardrail still loading"}, status_code=503)
    with _lock:
        _state["active"] = variant
    print(f"[guardrail] active variant -> {variant}", flush=True)
    return {"active": variant, "applied": True}


@app.post("/v1/guardrail/classify")
async def classify_debug(req: Request):
    """Calibration/debug: score text under BOTH variants without blocking anything."""
    body = await req.json()
    text = body.get("text") or ""
    if not _state["ready"]:
        return JSONResponse({"error": "guardrail still loading"}, status_code=503)
    return {v: _score(v, text) for v in VARIANTS}


def _texts_from(payload):
    # scan USER turns only — the system prompt is operator-trusted content (and would
    # false-positive on its own injection warnings)
    for m in payload.get("messages") or []:
        if m.get("role") != "user":
            continue
        c = m.get("content")
        if isinstance(c, str):
            yield c
    p = payload.get("prompt")
    if isinstance(p, str):
        yield p


@app.post("/v1/drain")
async def drain(req: Request):
    """Deployment-specific drain-all (stock vLLM has none): really abort in-flight
    generation requests by cancelling their proxy tasks — clients see the stream cut."""
    body = await req.json()
    aborted = 0
    if body.get("abort_inflight", True):
        for t in list(INFLIGHT):
            if not t.done():
                t.cancel()
                aborted += 1
    print(f"[guardrail] drain: aborted {aborted} in-flight", flush=True)
    return {"aborted": aborted}


@app.post("/v1/kv/invalidate")
async def kv_invalidate(req: Request):
    """Disagg-connector local KV invalidate: on this deployment the worker-local KV is
    vLLM's prefix cache, so a local invalidate IS a real cache reset (measurable via
    /metrics prefix-cache hit counters)."""
    body = await req.json()
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.post(f"{UPSTREAM}/reset_prefix_cache")
    if r.status_code != 200:
        return JSONResponse({"invalidated": False, "upstream": r.status_code}, status_code=502)
    print(f"[guardrail] kv invalidate (local={body.get('local')}): prefix cache reset", flush=True)
    return {"invalidated": True, "scope": "local-prefix-cache"}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"])
async def proxy(path: str, req: Request):
    body = await req.body()
    if req.method == "POST" and path in ("v1/chat/completions", "v1/completions"):
        if not _state["ready"]:
            return JSONResponse({"error": "guardrail still loading"}, status_code=503)
        try:
            payload = __import__("json").loads(body or b"{}")
        except Exception:
            payload = {}
        active = _state["active"]
        threshold = VARIANTS[active][1]
        for text in _texts_from(payload):
            s = _score(active, text)
            if 0 <= s >= threshold:
                print(f"[guardrail] BLOCK score={s:.3f} variant={active} text={text[:80]!r}", flush=True)
                return JSONResponse(
                    {"error": {"message": f"blocked by guardrail (variant={active}, injection-score={s:.3f})",
                               "type": "guardrail_blocked"}},
                    status_code=403,
                )
    url = f"{UPSTREAM}/{path}"
    headers = {k: v for k, v in req.headers.items() if k.lower() not in ("host", "content-length", "accept-encoding")}
    headers["accept-encoding"] = "identity"  # httpx injects its own gzip default; we relay raw, so ask for plain
    track = req.method == "POST" and path in ("v1/chat/completions", "v1/completions")
    task = asyncio.current_task()
    if track and task is not None:
        INFLIGHT.add(task)
    try:
        client = httpx.AsyncClient(timeout=httpx.Timeout(300.0, connect=5.0))
        upstream = await client.send(
            client.build_request(req.method, url, content=body, headers=headers, params=req.query_params),
            stream=True,
        )
    except BaseException:
        if track and task is not None:
            INFLIGHT.discard(task)
        raise

    async def relay():
        try:
            async for chunk in upstream.aiter_raw():
                yield chunk
        finally:
            await upstream.aclose()
            await client.aclose()
            if track and task is not None:
                INFLIGHT.discard(task)

    passthrough = {k: v for k, v in upstream.headers.items() if k.lower() in ("content-type",)}
    return StreamingResponse(relay(), status_code=upstream.status_code, headers=passthrough)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
