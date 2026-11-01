"""Join exact brain candidate exports to source-bound observed stage evidence."""
from __future__ import annotations

import argparse
import copy
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import tempfile

from .evidence import EvidenceError, Journal, Reducer, canonical, digest, sealed_sessions


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".stage-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(canonical(value) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def pricing_needed(candidate, worth_threshold):
    """Only a demonstrated existing veto makes a missing price irrelevant.

    This reads the source's fact weights without changing them. It follows the
    kernel's sorted, deduplicated sum solely to recognize V<=theta; invalid or
    unknown values cannot establish a known worth rejection.
    """
    if candidate.get("gates_known") and candidate.get("gates"):
        return False
    if candidate.get("containment") or not candidate.get("facts_known"):
        return True
    weights = {}
    for fact in candidate.get("facts") or []:
        key, weight = fact.get("id"), fact.get("weight")
        if not key or isinstance(weight, bool) or not isinstance(weight, (int, float)) or not math.isfinite(weight) or weight < 0:
            return True
        if key in weights and weights[key] != weight:
            return True
        weights[key] = weight
    value = 0.0
    for key in sorted(weights):
        value += weights[key]
    return not math.isfinite(value) or value > worth_threshold


def normalize(scope, records, exports, target, window, lookback, worth_threshold):
    for value in (target, window, lookback, worth_threshold):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise EvidenceError("study settings must be finite numbers")
    if not 0 < target < 1 or not 1 <= window <= 2592000 or not 1 <= lookback <= 2592000 or worth_threshold < 0:
        raise EvidenceError("invalid explicit study SLO/window/lookback/worth settings")
    if not 1 <= len(exports) <= 5000:
        raise EvidenceError("candidate export must contain 1..5000 ticks")
    exports = sorted(exports, key=lambda x: (x["at"], x["snapshot_digest"]))
    if len({x["snapshot_digest"] for x in exports}) != len(exports):
        raise EvidenceError("duplicate source snapshot")
    producers = {row.get("source_revision") for row in exports}
    if len(producers) != 1 or not re.fullmatch(r"[0-9a-f]{40}", next(iter(producers)) or ""):
        raise EvidenceError("one exact candidate producer source revision required")
    producer_source = next(iter(producers))
    record_source = records if callable(records) else lambda: iter(records)
    prefix = {"seq": 0, "hash": digest(scope)}
    def first_pass():
        for event in record_source():
            prefix.update(seq=event.get("seq"), hash=event.get("hash"))
            yield event
    seals = sealed_sessions(first_pass())
    reducer = Reducer(scope)
    observed = iter(record_source())
    next_event = next(observed, None)
    ticks, bindings, missing = [], [], {}
    for row in exports:
        expected = {"schema": "math-lab.study-candidates.v1", "snapshot_source_revision": scope["source_revision"],
                    "namespace": scope["namespace"], "policy_name": scope["policy_name"], "policy_uid": scope["policy_uid"],
                    "workload_uid": scope["workload_uid"], "max_moves_per_tick": 1,
                    "baseline_reproduced": True, "candidate_set_complete": True}
        for key, value in expected.items():
            if row.get(key) != value:
                raise EvidenceError("source candidate export mismatch: " + key)
        if producer_source != scope["source_revision"] and (row.get("cross_version") is not True or row.get("observational") is not True):
            raise EvidenceError("cross-source replay must explicitly retain observational provenance")
        at = row["at"]
        if isinstance(at, bool) or not isinstance(at, (float, int)) or not math.isfinite(at):
            raise EvidenceError("invalid source tick clock")
        while next_event is not None and next_event["at"] <= at:
            reducer.apply(next_event)
            next_event = next(observed, None)
        obs = reducer.snapshot(at, seals.get(reducer.session), require_sealed=True)
        reasons = list(row.get("missing") or []) + obs["reasons"]
        if row.get("spec_replicas") != obs["spec_replicas"]:
            reasons.append("SOURCE_OBSERVED_SPEC_REPLICAS_MISMATCH")
        if row.get("policy_generation") != obs["policy_generation"]:
            reasons.append("SOURCE_OBSERVED_POLICY_GENERATION_MISMATCH")
        full = obs["complete_from"] is not None and obs["complete_from"] <= at - max(window, lookback)
        if not full:
            reasons.append("DECLARED_STUDY_HISTORY_WINDOW_INCOMPLETE")
        candidates = copy.deepcopy(row["candidates"])
        for candidate in candidates:
            # Preserve all source-owned gate, value, class, containment and ID
            # fields. Only explicitly observed/study inputs may be enriched.
            if candidate.get("class") != obs["class"]:
                reasons.append("SOURCE_OBSERVED_WORKLOAD_CLASS_MISMATCH")
            action = candidate["action"]
            pod_uid = candidate["pod_uid"]
            if action not in ("rotate", "request-drain", "quarantine"):
                reasons.append("UNSUPPORTED_CALIBRATION_ACTION:" + action)
                continue
            if pod_uid not in (reducer.known_pods or set()):
                reasons.append("CANDIDATE_POD_NOT_IN_OBSERVED_WORKLOAD")
                continue
            # One logical backend is one exact Service target Pod UID. Multiple
            # EndpointSlices/addresses for that Pod are not charged twice.
            observed_k = 1 if pod_uid in obs["ready_pod_uids"] else 0
            if action == "quarantine" and obs["ready_pod_uids"]:
                observed_k = 1
            if candidate.get("k") is not None and candidate["k"] != observed_k:
                reasons.append("SOURCE_OBSERVED_ENDPOINT_MEMBERSHIP_MISMATCH")
            candidate["k"] = observed_k
            candidate["history_known"] = full
            candidate["samples"] = copy.deepcopy(obs["samples"])
            candidate["worth_threshold"] = worth_threshold
            if action == "quarantine" and candidate["k"] != 0 and pricing_needed(candidate, worth_threshold):
                cap = candidate.get("hold_cap")
                # Explicit zero is a known budget refusal in the shared kernel;
                # missing/invalid caps are unavailable evidence, not zero.
                if isinstance(cap, bool) or not isinstance(cap, (int, float)) or not math.isfinite(cap) or cap < 0:
                    reasons.append("candidates[" + candidate["id"] + "].hold_cap: QUARANTINE_HOLD_CAP_NOT_CONFIGURED")
        if reasons:
            missing[row["snapshot_digest"]] = sorted(set(reasons))
        ticks.append({"id": row["snapshot_digest"], "at": at, "workload_uid": scope["workload_uid"],
                      "policy_uid": scope["policy_uid"], "spec_replicas": row.get("spec_replicas"),
                      "slo": {"target": target, "window": window, "accepted": False, "study_assumption": True},
                      "ledger": {"at": at, "complete_from": obs["complete_from"], "authoritative": False,
                                 "measurement": scope["measurement"], "moves": obs["moves"]},
                      "candidates": candidates, "candidate_set_complete": row["candidate_set_complete"],
                      "mandatory_id": row.get("mandatory_id", "")})
        bindings.append({"snapshot_digest": row["snapshot_digest"], "original_tick_id": row["tick_id"],
                         "at": at, "candidate_export_sha256": digest(row), "journal_seq": obs["journal_seq"],
                         "journal_hash": obs["journal_hash"], "watch_session": reducer.session,
                         "sealed_until": obs["watermark"], "complete_from": obs["complete_from"]})
    trace = {"schema": "phorvex-bench.endpoint-trace.v1", "evidence": "recorded", "source_revision": producer_source, "ticks": ticks}
    metadata = {"schema": "phorvex-stage.normalization.v1", "state": "READY" if not missing else "BLOCKED",
                "scope": scope, "source_revision": producer_source, "snapshot_source_revision": scope["source_revision"],
                "cross_version": producer_source != scope["source_revision"],
                "journal_prefix": prefix,
                "snapshot_digests": [r["snapshot_digest"] for r in exports], "bindings": bindings,
                "missing": missing, "study_settings": {"target": target, "window": window, "lookback": lookback, "worth_threshold": worth_threshold},
                # Reducer.snapshot retains the complete as-of move/sample
                # history and original interval bounds. W/L filtering happens
                # only in the kernel, allowing evidence-bounded request changes.
                "retention": {"schema": "phorvex-stage.retained-history.v1", "moves": "all-observed",
                              "samples": "all-observed", "interval_clipping": False},
                "measurement": scope["measurement"], "move_origin": "controlled-stage-calibration",
                "authoritative_admission": False, "counterfactual_actual_charges": None,
                "limitations": ["Observed Service ready-backend intervals use collector serialized observation time; they are not measured application outages.",
                                "Physical calibration rotations are not brain-issued moves or counterfactual arm outcomes.",
                                "The isolated dryRun fixture and complete observed window establish a shadow study ledger only.",
                                "Study SLO, shorter windows and worth threshold are explicit experimental inputs, not tenant acceptance."]}
    return trace, metadata


def install(trace, metadata, data_dir, producer, before_publish=None, max_generation_bytes=512 << 20):
    if metadata["state"] != "READY" or metadata["missing"]:
        raise EvidenceError("incomplete observed inputs cannot be installed as a qualified recorded trace")
    scope = metadata["scope"]
    policy = scope["namespace"] + "/" + scope["policy_name"]
    target = Path(data_dir) / "mathlab/endpoint-traces" / (policy + ".json")
    payload = (canonical(trace) + "\n").encode()
    if len(payload) > 64 << 20:
        raise EvidenceError("qualified trace exceeds 64 MiB")
    if type(max_generation_bytes) is not int or not 1 << 20 <= max_generation_bytes <= 2 << 30:
        raise EvidenceError("generation capacity must be 1 MiB..2 GiB")
    trace_hash = hashlib.sha256(payload).hexdigest()
    generation = target.with_name(target.stem + "." + trace_hash + ".trace.json")
    manifest = {"schema": "phorvex-stage.endpoint-manifest.v1", "policy": policy, "policy_uid": scope["policy_uid"],
                "producer": producer, "source_revision": trace["source_revision"], "snapshot_source_revision": scope["source_revision"],
                "repository": scope["repository"],
                "image_digest": scope["image_digest"], "trace_sha256": trace_hash, "trace_file": generation.name,
                "snapshot_digests": metadata["snapshot_digests"], "normalization": metadata}
    target.parent.mkdir(parents=True, exist_ok=True)
    # Writers serialize per policy. Readers hold an immutable generation name
    # from one atomically replaced manifest; no active generation is deleted.
    with open(target.with_suffix(".install.lock"), "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if generation.exists():
            if generation.is_symlink() or sha(generation) != trace_hash:
                raise EvidenceError("immutable trace generation changed")
        else:
            owned = list(target.parent.glob(target.stem + ".*.trace.json"))
            if any(path.is_symlink() for path in owned):
                raise EvidenceError("trace generation ownership is invalid")
            if sum(path.stat().st_size for path in owned) + len(payload) > max_generation_bytes:
                raise EvidenceError("trace generation capacity exhausted; archive during an explicit reader maintenance window")
            atomic_json(generation, trace)
        if before_publish:
            before_publish()
        atomic_json(target.with_suffix(".manifest.json"), manifest)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--journal", required=True)
    parser.add_argument("--candidates", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--slo-target", type=float, required=True)
    parser.add_argument("--window", type=float, required=True)
    parser.add_argument("--lookback", type=float, required=True)
    parser.add_argument("--worth-threshold", type=float, required=True)
    parser.add_argument("--install-data-dir")
    args = parser.parse_args()
    journal = Journal(args.journal)
    if Path(args.candidates).stat().st_size > 64 << 20:
        raise EvidenceError("candidate export exceeds 64 MiB")
    exports = [json.loads(line) for line in Path(args.candidates).read_text().splitlines() if line.strip()]
    with journal.read_snapshot() as prefix:
        trace, metadata = normalize(journal.scope, lambda: journal.records(cutoff=prefix["seq"]), exports,
                                    args.slo_target, args.window, args.lookback, args.worth_threshold)
    output = Path(args.output_dir)
    atomic_json(output / "trace.json", trace)
    atomic_json(output / "normalization.json", metadata)
    if args.install_data_dir:
        install(trace, metadata, args.install_data_dir, "benchmark/stage/normalize.py:" + sha(args.candidates))
    print(json.dumps({"state": metadata["state"], "ticks": len(trace["ticks"]), "blocked_ticks": len(metadata["missing"]), "output_dir": str(output)}))
    return 0 if metadata["state"] == "READY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
