#!/usr/bin/env python3
"""Collect prompt-free classifier scores from /state and /classify only."""

import argparse
import datetime
import hashlib
import json
from pathlib import Path
import urllib.request


def request_json(url, body=None):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"} if data is not None else {},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def corpus_sha256(corpus):
    canonical = json.dumps(corpus, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(canonical).hexdigest()


def collect(base_url, corpus, source_sha):
    base_url = base_url.rstrip("/")
    state = request_json(base_url + "/v1/guardrail/state")
    observations = []
    for set_name in ("calibration", "held_out"):
        for case in corpus["sets"][set_name]:
            scores = request_json(base_url + "/v1/guardrail/classify", {"text": case["text"]})
            for variant, score in sorted(scores.items()):
                observations.append({
                    "set": set_name,
                    "id": case["id"],
                    "variant": variant,
                    "score": score,
                })
    return {
        "schema_version": 1,
        "corpus_id": corpus["corpus_id"],
        "corpus_sha256": corpus_sha256(corpus),
        "collected_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_sha": source_sha,
        "endpoint": base_url,
        "state": state,
        "observations": observations,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True, help="Guardrail proxy base URL")
    parser.add_argument("--corpus", required=True, type=Path)
    parser.add_argument("--source-sha", required=True, help="Exact source/config revision being evaluated")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    corpus = json.loads(args.corpus.read_text())
    result = collect(args.base_url, corpus, args.source_sha)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
