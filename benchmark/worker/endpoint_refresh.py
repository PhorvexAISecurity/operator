#!/usr/bin/env python3
"""Refresh a qualified stage endpoint dataset from real, continuously observed history.

Cluster access is read-only. No calibration, source installation, history
backdating or automatic deletion of journals/results is performed here.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime
import fcntl
import heapq
import json
import math
import os
from pathlib import Path
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import stage_cli
from mathlab import snapshots, stage_scope
from mathlab.common import read_json, sha256_file, utc
from benchmark.stage.evidence import EvidenceError, Journal, Reducer, canonical, digest, sealed_sessions
from benchmark.stage.normalize import atomic_json, install, normalize


class RefreshBlocked(ValueError):
    pass


@contextmanager
def wall_limit(seconds):
    """Bound discovery/sync as well as each replay subprocess on this Unix CLI."""
    def expired(_signum, _frame):
        raise RefreshBlocked("REFRESH_RUNTIME_LIMIT")
    previous = signal.signal(signal.SIGALRM, expired)
    old_timer = signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, *old_timer)
        signal.signal(signal.SIGALRM, previous)


def clock(value):
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("missing timezone")
        # The actual candidate exporter uses Header.DecidedAt.Unix().
        return math.floor(parsed.timestamp())
    except (AttributeError, TypeError, ValueError, OverflowError) as exc:
        raise RefreshBlocked("SNAPSHOT_DECISION_CLOCK_INVALID") from exc


def scope_matches(scope, pin, policy):
    namespace, name = stage_scope.policy(policy)
    expected = {"source_revision": pin["brain"]["git_sha"], "image_digest": pin["brain"]["image_digest"],
                "context": pin["kube_context"], "namespace": namespace, "policy_name": name,
                "policy_uid": pin["policies"][policy]["uid"]}
    for key, value in expected.items():
        if scope.get(key) != value:
            raise RefreshBlocked("JOURNAL_STAGE_PIN_MISMATCH:" + key)


def segment(journal, prefix, now=None, max_age=600):
    """Return only the latest actual continuous segment from one frozen prefix."""
    seals = sealed_sessions(journal.records(cutoff=prefix["seq"]))
    reducer = Reducer(journal.scope)
    for event in journal.records(cutoff=prefix["seq"]):
        reducer.apply(event)
    sealed = seals.get(reducer.session)
    if (reducer.coverage_from is None or reducer.reasons or sealed is None or
            not reducer.watermarks or sealed < reducer.coverage_from):
        raise RefreshBlocked("CONTINUOUS_OBSERVATION_UNAVAILABLE:" + ",".join(reducer.reasons or ["API_WATERMARK_MISSING"]))
    if now is not None and (sealed > now+5 or now-sealed > max_age):
        raise RefreshBlocked("OBSERVATION_WATERMARK_STALE_OR_FUTURE")
    return {"session": reducer.session, "complete_from": reducer.coverage_from,
            "sealed_until": sealed, "journal_prefix": prefix}


def select_entries(data_dir, pin, policy, observed, window, lookback, ticks):
    """Bound memory and select the newest eligible actual decision-clock ticks."""
    expected = stage_scope.snapshot_header(pin, policy)
    namespace, name = stage_scope.policy(policy)
    expected.update(namespace=namespace, policyName=name)
    first, last = observed["complete_from"] + max(window, lookback), observed["sealed_until"]
    if first > last:
        raise RefreshBlocked("OBSERVED_HISTORY_INSUFFICIENT: available=%s required=%s" %
                             (last-observed["complete_from"], max(window, lookback)))
    selected, scanned, eligible = [], 0, 0
    folder = Path(data_dir) / "mathlab/snapshots" / policy
    for path in folder.glob("*.pxms"):
        scanned += 1
        if scanned > 100000:
            raise RefreshBlocked("SNAPSHOT_CACHE_FILE_COUNT_LIMIT")
        if not snapshots.DIGEST.fullmatch(path.stem) or path.is_symlink() or not 0 < path.stat().st_size <= snapshots.MAX_SNAPSHOT_BYTES:
            continue
        try:
            header = snapshots.read_header(path)
            at = clock(header.get("decidedAt"))
        except (ValueError, OSError):
            continue
        if (any(header.get(key) != value for key, value in expected.items()) or
                header.get("finalized") is not True or header.get("unreplayableFields") or
                not first <= at <= last):
            continue
        eligible += 1
        entry = {"digest": path.stem, "size": path.stat().st_size, "header": header, "at": at}
        item = (at, path.stem, entry)
        if len(selected) < ticks:
            heapq.heappush(selected, item)
        elif item[:2] > selected[0][:2]:
            heapq.heapreplace(selected, item)
    if len(selected) < ticks:
        raise RefreshBlocked("ELIGIBLE_SNAPSHOTS_INSUFFICIENT: available=%d requested=%d decision_interval=[%s,%s]" %
                             (eligible, ticks, first, last))
    entries = [item[2] for item in sorted(selected)]
    stage_scope.cohort(pin, policy, entries)
    return entries


def bytes_in(folder):
    total = 0
    for path in Path(folder).rglob("*"):
        if path.is_symlink():
            raise RefreshBlocked("UNSAFE_WORKING_CACHE_SYMLINK")
        if path.is_file():
            total += path.stat().st_size
    return total


def cache_record_path(data_dir, policy):
    return Path(data_dir)/"mathlab/endpoint-refresh"/(policy+".cache.json")


def cache_records(data_dir, policy):
    path = cache_record_path(data_dir, policy)
    if path.exists() and path.stat().st_size > 16 << 20:
        raise RefreshBlocked("MANAGED_CACHE_REGISTRY_SIZE_LIMIT")
    record = read_json(path, {"schema": "phorvex-stage.endpoint-cache.v1", "policy": policy, "snapshots": {}})
    if record.get("schema") != "phorvex-stage.endpoint-cache.v1" or record.get("policy") != policy or not isinstance(record.get("snapshots"), dict):
        raise RefreshBlocked("MANAGED_CACHE_REGISTRY_INVALID")
    return record


def cache_scope(pin, policy):
    return {"source_revision": pin["brain"]["git_sha"], "brain_image": pin["brain"]["image"],
            "policy_uid": pin["policies"][policy]["uid"]}


def register_downloads(data_dir, pin, policy, downloaded):
    """Called under the policy's exclusive cache lock after verified sync."""
    if not isinstance(downloaded, list) or len(downloaded) > 5000:
        raise RefreshBlocked("SYNC_MANAGED_DIGESTS_INVALID")
    record = cache_records(data_dir, policy)
    expected = stage_scope.snapshot_header(pin, policy)
    namespace, name = stage_scope.policy(policy)
    expected.update(namespace=namespace, policyName=name)
    for value in downloaded:
        if not isinstance(value, str) or not snapshots.DIGEST.fullmatch(value):
            raise RefreshBlocked("SYNC_MANAGED_DIGESTS_INVALID")
        path = Path(data_dir)/"mathlab/snapshots"/policy/(value+".pxms")
        if path.is_symlink() or not path.is_file() or sha256_file(path) != value:
            raise RefreshBlocked("SYNC_MANAGED_CONTENT_ADDRESS_MISMATCH")
        header = snapshots.read_header(path)
        if any(header.get(key) != val for key, val in expected.items()):
            raise RefreshBlocked("SYNC_MANAGED_SCOPE_MISMATCH")
        record["snapshots"][value] = cache_scope(pin, policy)
    atomic_json(cache_record_path(data_dir, policy), record)


def prune_cache(data_dir, pin, policy, keep=256, protect=()):
    """Prune only this refresher's exact-scope cache under an exclusive lock.

    Every snapshot consumer must hold the shared counterpart through its frozen
    copy. The current pointer is protected independently; generations, journals,
    foreign/legacy cache entries and isolated run directories are never deleted.
    """
    record = cache_records(data_dir, policy)
    pointer = read_json(Path(data_dir)/"mathlab/endpoint-traces"/(policy+".manifest.json"), {}) or {}
    protected = pointer.get("snapshot_digests", [])
    if not isinstance(protected, list) or any(not isinstance(x, str) or not snapshots.DIGEST.fullmatch(x) for x in protected):
        raise RefreshBlocked("CURRENT_DATASET_COHORT_INVALID")
    protected = set(protected) | set(protect)
    expected = stage_scope.snapshot_header(pin, policy)
    namespace, name = stage_scope.policy(policy)
    expected.update(namespace=namespace, policyName=name)
    managed = []
    for value, identity in list(record["snapshots"].items()):
        if not snapshots.DIGEST.fullmatch(value) or identity != cache_scope(pin, policy):
            continue
        path = Path(data_dir)/"mathlab/snapshots"/policy/(value+".pxms")
        if not path.exists():
            del record["snapshots"][value]
            continue
        if path.is_symlink():
            raise RefreshBlocked("MANAGED_CACHE_SYMLINK")
        header = snapshots.read_header(path)
        if any(header.get(key) != val for key, val in expected.items()):
            raise RefreshBlocked("MANAGED_CACHE_SCOPE_CHANGED")
        managed.append((clock(header.get("decidedAt")), value, path))
    retain = {value for _, value, _ in sorted(managed)[-keep:]} | protected
    removed = 0
    for _, value, path in managed:
        if value not in retain:
            if sha256_file(path) != value:
                raise RefreshBlocked("MANAGED_CACHE_CONTENT_CHANGED")
            path.unlink()
            del record["snapshots"][value]
            removed += 1
    atomic_json(cache_record_path(data_dir, policy), record)
    return {"removed": removed, "retained_newest": keep, "protected_current": len(protected),
            "managed_remaining": len(record["snapshots"])}


def copy_cohort(data_dir, policy, entries, target, max_bytes):
    if sum(row["size"] for row in entries) > min(max_bytes, 512 << 20):
        raise RefreshBlocked("SNAPSHOT_COHORT_BYTE_LIMIT")
    target.mkdir()
    for entry in entries:
        source = Path(data_dir) / "mathlab/snapshots" / policy / (entry["digest"] + ".pxms")
        if source.is_symlink() or source.stat().st_size != entry["size"]:
            raise RefreshBlocked("SNAPSHOT_CHANGED_BEFORE_FREEZE")
        destination = target / source.name
        shutil.copyfile(source, destination)
        if sha256_file(destination) != entry["digest"] or snapshots.read_header(destination) != entry["header"]:
            raise RefreshBlocked("SNAPSHOT_CONTENT_ADDRESS_MISMATCH")


def run_replay(args, work, deadline, max_bytes):
    """Use no inherited credentials and bound both runtime and output writes."""
    remaining = deadline-time.monotonic()
    available = max_bytes-bytes_in(work)
    # Each invocation can create out, summary and a diagnostic file. An OS
    # per-file bound keeps a broken producer from filling the whole filesystem.
    file_limit = min(64 << 20, available // 3)
    if remaining <= 0:
        raise RefreshBlocked("REFRESH_RUNTIME_LIMIT")
    if file_limit < 1 << 20:
        raise RefreshBlocked("REFRESH_WORK_BYTE_LIMIT")
    def limit_output():
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))
    with tempfile.TemporaryDirectory(prefix="home-", dir=work) as home:
        env = {"PATH": "/usr/bin:/bin", "HOME": home, "TMPDIR": home, "LANG": "C.UTF-8"}
        log = Path(work) / "replay-last.log"
        with log.open("wb") as output:
            result = subprocess.run(args, stdout=output, stderr=subprocess.STDOUT, timeout=remaining,
                                    env=env, cwd=home, preexec_fn=limit_output)
        if result.returncode:
            raise RefreshBlocked("REPLAY_EXIT_%d: %s" % (result.returncode, log.read_text(errors="replace")[-1200:]))
    if bytes_in(work) > max_bytes:
        raise RefreshBlocked("REFRESH_WORK_BYTE_LIMIT")


def json_lines(path):
    if not Path(path).is_file() or Path(path).stat().st_size > 64 << 20:
        raise RefreshBlocked("REPLAY_OUTPUT_MISSING_OR_OVERSIZED")
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]


def exact_baseline(rows, digests, label):
    if (len(rows) != len(digests) or {row.get("snapshot", {}).get("snapshot_digest") for row in rows} != set(digests) or
            any(row.get("status") != "OK" or (row.get("baseline_check") or {}).get("reproduced") is not True for row in rows)):
        raise RefreshBlocked("BASELINE_NOT_EXACT:" + label)


def verify_live(pin, policy):
    actual = stage_cli.running_image(pin["kube_context"], pin["service_namespace"], pin["brain"]["deployment"], "brain")
    for key in ("git_sha", "image", "digest", "deployment_uid"):
        if actual.get(key) != pin["brain"].get(key):
            raise RefreshBlocked("LIVE_STAGE_CHANGED_BEFORE_PUBLICATION:" + key)
    namespace, name = stage_scope.policy(policy)
    pol = stage_cli.kube(pin["kube_context"], namespace, "get", "phorvexpolicy", name, "-o", "json")
    if pol["metadata"]["uid"] != pin["policies"][policy]["uid"]:
        raise RefreshBlocked("LIVE_POLICY_UID_CHANGED_BEFORE_PUBLICATION")


def refresh(data_dir, repo, policy, journal_path, *, target, window, lookback, worth_threshold,
            ticks=64, timeout=900, max_work_bytes=512 << 20, max_generation_bytes=512 << 20,
            max_corpus_bytes=2 << 30, max_observation_age=600):
    stage_scope.policy(policy)
    if (any(type(x) not in (float, int) or not math.isfinite(x) for x in (target, window, lookback, worth_threshold)) or
            not 0 < target < 1 or not 1 <= window <= 2592000 or not 1 <= lookback <= 2592000 or worth_threshold < 0):
        raise ValueError("invalid explicit study SLO/window/lookback/worth settings")
    if type(ticks) is not int or not 1 <= ticks <= 256 or not 10 <= timeout <= 1800:
        raise ValueError("refresh requires 1..256 ticks and 10..1800 seconds")
    if type(max_observation_age) is not int or not 60 <= max_observation_age <= 3600:
        raise ValueError("observation freshness bound must be 60..3600 seconds")
    for name, value, low, high in (("work", max_work_bytes, 16 << 20, 2 << 30),
                                   ("generation", max_generation_bytes, 1 << 20, 2 << 30),
                                   ("corpus", max_corpus_bytes, 16 << 20, 8 << 30)):
        if type(value) is not int or not low <= value <= high:
            raise ValueError("invalid " + name + " byte bound")
    data_dir = Path(data_dir).resolve()
    status_path = data_dir / "mathlab/endpoint-refresh" / (policy + ".status.json")
    status_path.parent.mkdir(parents=True, exist_ok=True)
    pointer = data_dir / "mathlab/endpoint-traces" / (policy + ".manifest.json")
    started = time.monotonic()
    deadline = started + timeout
    state = {"schema": "phorvex-stage.endpoint-refresh.v1", "state": "RUNNING", "policy": policy,
             "started_at": utc(), "phase": "DISCOVER", "requested_ticks": ticks,
             "study_settings": {"target": target, "window": window, "lookback": lookback, "worth_threshold": worth_threshold},
             "bounds": {"timeout_seconds": timeout, "work_bytes": max_work_bytes,
                        "generation_bytes": max_generation_bytes, "corpus_bytes": max_corpus_bytes,
                        "observation_age_seconds": max_observation_age}}
    with status_path.with_suffix(".lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RefreshBlocked("REFRESH_ALREADY_RUNNING") from exc
        atomic_json(status_path, state)
        try:
            with wall_limit(timeout):
                pin = stage_scope.load(data_dir, policy, repo)
                control = stage_scope.identity(data_dir, pin)
                engine = stage_scope.study_engine(data_dir, pin)
                # Only a real existing journal can be opened; a refresh cannot
                # manufacture the observation scope or start/backdate a session.
                if not Path(journal_path).is_file():
                    raise RefreshBlocked("OBSERVATION_JOURNAL_MISSING")
                journal = Journal(journal_path)
                try:
                    scope_matches(journal.scope, pin, policy)
                    corpus = data_dir / "mathlab/snapshots" / policy
                    namespace, policy_name = stage_scope.policy(policy)
                    with snapshots.cache_lock(data_dir, namespace, policy_name, exclusive=True):
                        state["cache_before_sync"] = prune_cache(data_dir, pin, policy, max(256, ticks))
                        available = max_corpus_bytes-bytes_in(corpus)
                    if available < snapshots.MAX_SNAPSHOT_BYTES:
                        raise RefreshBlocked("SNAPSHOT_CACHE_CAPACITY_EXHAUSTED")
                    state["phase"] = "SYNC"
                    state["sync"] = stage_cli.sync_stage(data_dir, repo, policy, sync_limit=max(256, ticks),
                                                          max_sync_bytes=min(available, max_work_bytes))
                    with snapshots.cache_lock(data_dir, namespace, policy_name, exclusive=True):
                        register_downloads(data_dir, pin, policy, state["sync"].get("downloaded_digests", []))
                        if bytes_in(corpus) > max_corpus_bytes:
                            raise RefreshBlocked("SNAPSHOT_CACHE_BYTE_LIMIT")
                    with journal.read_snapshot() as prefix:
                        observed = segment(journal, prefix, now=time.time(), max_age=max_observation_age)
                        state.update(phase="SELECT", observed_segment=observed)
                        with tempfile.TemporaryDirectory(prefix="refresh-", dir=status_path.parent) as temporary:
                            work = Path(temporary)
                            frozen = work / "cohort"
                            with snapshots.cache_lock(data_dir, namespace, policy_name):
                                entries = select_entries(data_dir, pin, policy, observed, window, lookback, ticks)
                                digests = [entry["digest"] for entry in entries]
                                state["snapshot_digests"] = digests
                                copy_cohort(data_dir, policy, entries, frozen, max_work_bytes // 2)
                            state["phase"] = "BASELINES"
                            for label, identity in (("capture-control", control), ("base-local", engine["base_local"])):
                                output = work / (label + ".jsonl")
                                run_replay([identity["path"], "-snapshots", str(frozen), "-out", str(output),
                                            "-summary", str(work / (label + ".summary.json"))], work, deadline, max_work_bytes)
                                exact_baseline(json_lines(output), digests, label)
                            candidate_output = work / "candidates.jsonl"
                            args = [engine["candidate"]["path"], "-snapshots", str(frozen),
                                    "-export-study-candidates", "-out", str(candidate_output)]
                            if engine["source_revision"] != pin["brain"]["git_sha"]:
                                args.append("-allow-cross-version")
                            state["phase"] = "EXPORT"
                            run_replay(args, work, deadline, max_work_bytes)
                            rows = json_lines(candidate_output)
                            if (len(rows) != len(entries) or {row.get("snapshot_digest") for row in rows} != set(digests) or
                                    any(row.get("source_revision") != engine["source_revision"] for row in rows)):
                                raise RefreshBlocked("CANDIDATE_EXPORT_COHORT_OR_PRODUCER_MISMATCH")
                            expected_at = {entry["digest"]: entry["at"] for entry in entries}
                            if any(row.get("at") != expected_at[row["snapshot_digest"]] for row in rows):
                                raise RefreshBlocked("CANDIDATE_EXPORT_DECISION_CLOCK_MISMATCH")
                            state["phase"] = "NORMALIZE"
                            trace, metadata = normalize(journal.scope, lambda: journal.records(cutoff=prefix["seq"]),
                                                        rows, target, window, lookback, worth_threshold)
                            state["normalization"] = {"state": metadata["state"], "missing": metadata["missing"]}
                            if metadata["state"] != "READY":
                                raise RefreshBlocked("RECORDED_INPUTS_INCOMPLETE")
                            if (metadata["journal_prefix"] != prefix or any(
                                    binding["watch_session"] != observed["session"] or
                                    binding["complete_from"] != observed["complete_from"] or
                                    binding["sealed_until"] != observed["sealed_until"] for binding in metadata["bindings"])):
                                raise RefreshBlocked("COHORT_CROSSES_OBSERVATION_SEGMENT")
                            metadata["refresh"] = {"schema": state["schema"], "capture_binary_sha256": control["binary_sha256"],
                                                   "study_binary_sha256": engine["candidate"]["binary_sha256"],
                                                   "base_binary_sha256": engine["base_local"]["binary_sha256"],
                                                   "candidate_export_sha256": sha256_file(candidate_output),
                                                   "baseline_exact_count": len(entries), "observed_segment": observed}
                            def revalidate():
                                if time.monotonic() >= deadline:
                                    raise RefreshBlocked("REFRESH_RUNTIME_LIMIT")
                                current = stage_scope.load(data_dir, policy, repo)
                                if canonical(current) != canonical(pin):
                                    raise RefreshBlocked("STAGE_PIN_CHANGED_BEFORE_PUBLICATION")
                                if canonical(stage_scope.identity(data_dir, current)) != canonical(control):
                                    raise RefreshBlocked("CAPTURE_ENGINE_CHANGED_BEFORE_PUBLICATION")
                                if canonical(stage_scope.study_engine(data_dir, current)) != canonical(engine):
                                    raise RefreshBlocked("STUDY_ENGINE_CHANGED_BEFORE_PUBLICATION")
                                verify_live(current, policy)
                            state["phase"] = "PUBLISH"
                            with snapshots.cache_lock(data_dir, namespace, policy_name, exclusive=True):
                                state["cache_before_publish"] = prune_cache(data_dir, pin, policy, max(256, ticks), protect=digests)
                                manifest = install(trace, metadata, data_dir, "benchmark/worker/endpoint_refresh.py:" + sha256_file(candidate_output),
                                                   before_publish=revalidate, max_generation_bytes=max_generation_bytes)
                            state.update(state="READY", phase="COMPLETE", published_trace_sha256=manifest["trace_sha256"],
                                         source_revision=manifest["source_revision"], snapshot_source_revision=manifest["snapshot_source_revision"],
                                         ticks=len(entries), reason=None)
                finally:
                    journal.close()
        except Exception as exc:
            state.update(state="BLOCKED", reason=str(exc)[:2000], error_type=type(exc).__name__)
        try:
            current_manifest = read_json(pointer, {}) or {}
        except (OSError, ValueError):
            current_manifest = {}
        state["current_dataset"] = {key: current_manifest.get(key) for key in
                                    ("trace_file", "trace_sha256", "source_revision", "snapshot_source_revision", "snapshot_digests")}
        state.update(finished_at=utc(), elapsed_seconds=round(time.monotonic()-started, 3))
        atomic_json(status_path, state)
        return state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("data", "repo", "policy", "journal"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--slo-target", type=float, required=True)
    parser.add_argument("--window", type=float, required=True)
    parser.add_argument("--lookback", type=float, required=True)
    parser.add_argument("--worth-threshold", type=float, required=True)
    parser.add_argument("--ticks", type=int, default=64)
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--max-work-bytes", type=int, default=512 << 20)
    parser.add_argument("--max-generation-bytes", type=int, default=512 << 20)
    parser.add_argument("--max-corpus-bytes", type=int, default=2 << 30)
    parser.add_argument("--max-observation-age", type=int, default=600)
    args = parser.parse_args()
    result = refresh(args.data, args.repo, args.policy, args.journal, target=args.slo_target,
                     window=args.window, lookback=args.lookback, worth_threshold=args.worth_threshold,
                     ticks=args.ticks, timeout=args.timeout, max_work_bytes=args.max_work_bytes,
                     max_generation_bytes=args.max_generation_bytes, max_corpus_bytes=args.max_corpus_bytes,
                     max_observation_age=args.max_observation_age)
    print(json.dumps(result, allow_nan=False))
    return 0 if result["state"] == "READY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
