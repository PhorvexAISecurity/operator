#!/usr/bin/env python3
"""Evaluate retained guardrail scores at their retained effective thresholds."""

import argparse
from collections import defaultdict
import hashlib
import json
import math
from pathlib import Path


def _rate(numerator, denominator):
    return numerator / denominator if denominator else None


def corpus_sha256(corpus):
    canonical = json.dumps(corpus, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(canonical).hexdigest()


def _metrics(rows, labels, threshold):
    counts = {"true_positive": 0, "true_negative": 0, "false_positive": 0, "false_negative": 0}
    benign_scores = []
    malicious_scores = []
    for row in rows:
        label = labels[(row["set"], row["id"])]
        score = float(row["score"])
        if not math.isfinite(score) or not 0 <= score <= 1:
            raise ValueError(f"invalid score for {row['set']}/{row['id']}/{row['variant']}: {row['score']!r}")
        predicted_malicious = score >= threshold
        if label == "malicious":
            malicious_scores.append(score)
            counts["true_positive" if predicted_malicious else "false_negative"] += 1
        else:
            benign_scores.append(score)
            counts["false_positive" if predicted_malicious else "true_negative"] += 1
    max_benign = max(benign_scores)
    min_malicious = min(malicious_scores)
    return {
        "threshold": threshold,
        "counts": counts,
        "false_positive_rate": _rate(counts["false_positive"], counts["false_positive"] + counts["true_negative"]),
        "false_negative_rate": _rate(counts["false_negative"], counts["false_negative"] + counts["true_positive"]),
        "score_ranges": {
            "benign": {"min": min(benign_scores), "max": max_benign},
            "malicious": {"min": min_malicious, "max": max(malicious_scores)},
        },
        "perfect_separation_exists": max_benign < min_malicious,
        "separation_note": (
            "A threshold in [0,1] can separate these retained labels; this tool does not select or promote one."
            if max_benign < min_malicious
            else "No threshold in [0,1] separates these retained benign and malicious scores."
        ),
    }


def evaluate(corpus, retained):
    if corpus.get("schema_version") != 1 or retained.get("schema_version") != 1:
        raise ValueError("unsupported schema_version")
    if retained.get("corpus_id") != corpus.get("corpus_id"):
        raise ValueError("retained scores do not match the corpus_id")
    expected_corpus_sha = corpus_sha256(corpus)
    if retained.get("corpus_sha256") != expected_corpus_sha:
        raise ValueError(
            f"retained scores do not match the canonical corpus SHA256: "
            f"got {retained.get('corpus_sha256')!r}, want {expected_corpus_sha!r}"
        )
    for field in ("collected_at", "source_sha", "endpoint", "state"):
        if not retained.get(field):
            raise ValueError(f"retained provenance is missing {field}")
    state = retained["state"]
    thresholds = state.get("thresholds")
    if not isinstance(thresholds, dict) or not thresholds:
        raise ValueError("retained state has no effective thresholds")
    labels = {}
    expected = set()
    for set_name in ("calibration", "held_out"):
        cases = corpus.get("sets", {}).get(set_name)
        if not isinstance(cases, list) or not cases:
            raise ValueError(f"corpus set {set_name!r} is missing or empty")
        for case in cases:
            if case.get("label") not in ("benign", "malicious"):
                raise ValueError(f"invalid label for {set_name}/{case.get('id')}")
            key = (set_name, case["id"])
            if key in labels:
                raise ValueError(f"duplicate corpus case {set_name}/{case['id']}")
            labels[key] = case["label"]
            expected.update((set_name, case["id"], variant) for variant in thresholds)
        if {case["label"] for case in cases} != {"benign", "malicious"}:
            raise ValueError(f"corpus set {set_name!r} must contain both benign and malicious labels")

    observed = set()
    by_set_variant = defaultdict(list)
    for row in retained.get("observations", []):
        key = (row.get("set"), row.get("id"), row.get("variant"))
        if key in observed:
            raise ValueError(f"duplicate observation {key}")
        observed.add(key)
        if key[:2] not in labels or key[2] not in thresholds:
            raise ValueError(f"unexpected observation {key}")
        by_set_variant[(key[0], key[2])].append(row)
    if observed != expected:
        missing = sorted(expected - observed)
        extra = sorted(observed - expected)
        raise ValueError(f"observation coverage mismatch: missing={missing} extra={extra}")

    results = {}
    for set_name in ("calibration", "held_out"):
        results[set_name] = {}
        for variant, raw_threshold in sorted(thresholds.items()):
            threshold = float(raw_threshold)
            if not math.isfinite(threshold) or not 0 <= threshold <= 1:
                raise ValueError(f"invalid retained threshold for {variant}: {raw_threshold!r}")
            results[set_name][variant] = _metrics(by_set_variant[(set_name, variant)], labels, threshold)

    return {
        "schema_version": 1,
        "corpus_id": corpus["corpus_id"],
        "corpus_sha256": expected_corpus_sha,
        "source_sha": retained["source_sha"],
        "collected_at": retained["collected_at"],
        "endpoint": retained["endpoint"],
        "effective_config": {
            "active": state.get("active", "unknown"),
            "mode": state.get("mode", "unknown"),
            "thresholds": thresholds,
            "models": state.get("models", "unknown"),
            "runtime": state.get("runtime", "unknown"),
        },
        "results": results,
        "claim_limit": "Small synthetic interface corpus only; no threshold is selected or production-calibrated.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", required=True, type=Path)
    parser.add_argument("--observations", required=True, type=Path)
    parser.add_argument("--output", type=Path, help="Write report here; default is stdout")
    args = parser.parse_args()
    report = evaluate(json.loads(args.corpus.read_text()), json.loads(args.observations.read_text()))
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered)
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
