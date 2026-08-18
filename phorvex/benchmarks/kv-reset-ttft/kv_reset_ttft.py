#!/usr/bin/env python3
"""Paired vLLM prefix-cache reset TTFT benchmark (PHORVEXSEC-93).

Each sample warms an identical prompt, measures its cached TTFT, resets vLLM's
prefix cache, then measures the first post-reset TTFT. The paired difference
isolates the user-visible penalty of kv-reset from slow drift in serving load.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import statistics
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable


DEFAULT_PROMPT_SENTENCE = (
    "The service processes a deterministic request and returns one concise factual token. "
)


@dataclass(frozen=True)
class PairedSample:
    sample: int
    cached_ttft_ms: float
    post_reset_ttft_ms: float
    penalty_ms: float


def _request_json(url: str, payload: dict[str, Any] | None, timeout: float) -> Any:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="GET" if payload is None else "POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read()
            if response.status < 200 or response.status >= 300:
                raise RuntimeError(f"HTTP {response.status} from {url}: {body[:400]!r}")
            return json.loads(body or b"null")
    except urllib.error.HTTPError as exc:
        body = exc.read(400)
        raise RuntimeError(f"HTTP {exc.code} from {url}: {body!r}") from exc


def discover_model(base_url: str, timeout: float) -> str:
    body = _request_json(f"{base_url.rstrip('/')}/v1/models", None, timeout)
    models = body.get("data", []) if isinstance(body, dict) else []
    if not models or not isinstance(models[0].get("id"), str):
        raise RuntimeError("/v1/models returned no usable model id")
    return models[0]["id"]


def streaming_ttft_ms(
    base_url: str, model: str, prompt: str, timeout: float
) -> float:
    payload = json.dumps(
        {
            "model": model,
            "prompt": prompt,
            "max_tokens": 1,
            "temperature": 0,
            "stream": True,
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        f"{base_url.rstrip('/')}/v1/completions",
        data=payload,
        headers={"Content-Type": "application/json", "Accept": "text/event-stream"},
        method="POST",
    )
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            for raw_line in response:
                line = raw_line.decode("utf-8", errors="replace").strip()
                if not line.startswith("data:"):
                    continue
                event = line[5:].strip()
                if not event or event == "[DONE]":
                    continue
                body = json.loads(event)
                choices = body.get("choices", [])
                if any(isinstance(choice.get("text"), str) and choice["text"] for choice in choices):
                    return (time.perf_counter() - started) * 1000.0
    except urllib.error.HTTPError as exc:
        body = exc.read(400)
        raise RuntimeError(f"completion HTTP {exc.code}: {body!r}") from exc
    raise RuntimeError("completion stream ended before a generated token arrived")


def reset_prefix_cache(base_url: str, timeout: float) -> None:
    result = _request_json(f"{base_url.rstrip('/')}/reset_prefix_cache", {}, timeout)
    # vLLM 0.7.x returns true; accept an object for forward compatibility, but
    # never accept an explicit false result as a successful reset.
    if result is False:
        raise RuntimeError("vLLM returned false from /reset_prefix_cache")


def nearest_rank(values: Iterable[float], percentile: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("cannot summarize an empty sample")
    rank = max(1, math.ceil(percentile * len(ordered)))
    return ordered[min(rank, len(ordered)) - 1]


def bootstrap_median_ci(
    values: list[float], *, iterations: int = 10_000, seed: int = 20260817
) -> tuple[float, float]:
    if not values:
        raise ValueError("cannot bootstrap an empty sample")
    rng = random.Random(seed)
    n = len(values)
    medians = sorted(
        statistics.median(values[rng.randrange(n)] for _ in range(n))
        for _ in range(iterations)
    )
    return nearest_rank(medians, 0.025), nearest_rank(medians, 0.975)


def summarize(samples: list[PairedSample]) -> dict[str, Any]:
    cached = [sample.cached_ttft_ms for sample in samples]
    post_reset = [sample.post_reset_ttft_ms for sample in samples]
    penalties = [sample.penalty_ms for sample in samples]
    ci_low, ci_high = bootstrap_median_ci(penalties)
    cached_median = statistics.median(cached)
    penalty_median = statistics.median(penalties)
    return {
        "sample_count": len(samples),
        "cached_ttft_ms": {
            "median": cached_median,
            "p95": nearest_rank(cached, 0.95),
        },
        "post_reset_ttft_ms": {
            "median": statistics.median(post_reset),
            "p95": nearest_rank(post_reset, 0.95),
        },
        "paired_penalty_ms": {
            "median": penalty_median,
            "p95": nearest_rank(penalties, 0.95),
            "median_bootstrap_95pct_ci": [ci_low, ci_high],
            "positive_pairs": sum(value > 0 for value in penalties),
        },
        "median_ttft_multiplier": (
            statistics.median(post_reset) / cached_median if cached_median > 0 else None
        ),
        "samples": [asdict(sample) for sample in samples],
    }


def run_benchmark(
    *,
    base_url: str,
    model: str,
    prompt: str,
    sample_count: int,
    timeout: float,
    settle_seconds: float,
) -> list[PairedSample]:
    samples: list[PairedSample] = []
    for index in range(1, sample_count + 1):
        # Populate the cache, then issue the same request again for a cached control.
        streaming_ttft_ms(base_url, model, prompt, timeout)
        cached = streaming_ttft_ms(base_url, model, prompt, timeout)
        reset_prefix_cache(base_url, timeout)
        post_reset = streaming_ttft_ms(base_url, model, prompt, timeout)
        sample = PairedSample(index, cached, post_reset, post_reset - cached)
        samples.append(sample)
        print(
            f"sample {index:02d}/{sample_count}: cached={cached:.3f} ms "
            f"post-reset={post_reset:.3f} ms penalty={sample.penalty_ms:+.3f} ms",
            flush=True,
        )
        if settle_seconds > 0 and index < sample_count:
            time.sleep(settle_seconds)
    return samples


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True, help="direct vLLM OpenAI API base URL")
    parser.add_argument("--model", help="model id; defaults to the first /v1/models result")
    parser.add_argument("--samples", type=int, default=30)
    parser.add_argument("--prompt-repeat", type=int, default=320)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--settle-seconds", type=float, default=0.2)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--confirm-reset",
        action="store_true",
        help="required acknowledgement that the benchmark repeatedly resets the prefix cache",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.confirm_reset:
        raise SystemExit("refusing to reset serving state without --confirm-reset")
    if args.samples < 3:
        raise SystemExit("--samples must be at least 3")
    if args.prompt_repeat < 1:
        raise SystemExit("--prompt-repeat must be positive")

    base_url = args.base_url.rstrip("/")
    model = args.model or discover_model(base_url, args.timeout)
    prompt = DEFAULT_PROMPT_SENTENCE * args.prompt_repeat
    started = time.time()
    samples = run_benchmark(
        base_url=base_url,
        model=model,
        prompt=prompt,
        sample_count=args.samples,
        timeout=args.timeout,
        settle_seconds=args.settle_seconds,
    )
    result = {
        "schema": "phorvex.kv-reset-ttft.v1",
        "measured_at_unix": started,
        "endpoint": base_url,
        "model": model,
        "method": "warm identical prompt; cached control; reset_prefix_cache; first post-reset request",
        "prompt": {
            "characters": len(prompt),
            "sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
            "repeat": args.prompt_repeat,
        },
        **summarize(samples),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in result.items() if key != "samples"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
