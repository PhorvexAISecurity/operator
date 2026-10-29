#!/usr/bin/env python3
"""Strict, read-only verifier for Console catalogue campaign evidence."""

from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen


RECORD_SCHEMA = "phorvex.console-evidence-audit.record.v1"
BUNDLE_SCHEMA = "phorvex.console-evidence-audit.bundle.v1"
PROMETHEUS_SCHEMA = "phorvex.console-evidence-audit.prometheus.v1"
VERDICT_SCHEMA = "phorvex.console-evidence-audit.verdict.v1"
SUMMARY_SCHEMA = "phorvex.console-evidence-audit.summary.v1"
SCREENSHOT_SCHEMA = "phorvex.console-evidence-audit.screenshot-bindings.v1"
RUN_RECORD_SCHEMA = "phorvex.attack-catalogue-run.v1"
RESULT_SCHEMA = "phorvex.attack-catalogue-result.v1"
NATIVE_PROMETHEUS_SCHEMA = "phorvex.prometheus-run-evidence.v1"

STATUS_ORDER = {"PASS": 0, "BLOCKED": 1, "FAIL": 2, "INVALID": 3}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

# These are physical, two-sided observations, not names copied from catalogue
# metadata.  Relation values are evaluated over each observation's before/after
# values; a producer-supplied passed=true is never sufficient by itself.
ORACLE_SPECS: dict[str, tuple[str, dict[str, Any]]] = {
    "agent-action": (
        "app-action-denied-two-sided",
        {
            "abusive_action_blocked": ("transition", "allowed", "blocked"),
            "benign_action_preserved": ("equal",),
            "peer_unchanged": ("equal",),
        },
    ),
    "controller-stop": (
        "controller-stopped-availability",
        {
            "target_controller_stopped": ("transition", "running", "stopped"),
            "availability_preserved": ("after_true",),
        },
    ),
    "credential": (
        "credential-revoked-two-sided",
        {
            "credential_revoked": ("transition", "authenticated", "denied"),
            "benign_credential_valid": ("transition", "authenticated", "authenticated"),
        },
    ),
    "datastore": (
        "datastore-restored-readback",
        {"datastore_state_changed": ("different",), "legitimate_read_preserved": ("equal",)},
    ),
    "identity-sa-rotate": (
        "service-account-rotated-credential-replay",
        {
            "service_account_uid_changed": ("different",),
            "old_credential_revoked": ("transition", "authenticated", "denied"),
            "pod_uid_unchanged": ("equal",),
        },
    ),
    "image": (
        "image-rollback-runtime",
        {"image_digest_changed": ("different",), "availability_preserved": ("after_true",)},
    ),
    "network-edge": (
        "network-edge-blocked-two-sided",
        {
            "forbidden_edge_blocked": ("transition", "reached", "blocked"),
            "legitimate_edge_preserved": ("equal",),
            "target_pod_uid_unchanged": ("equal",),
        },
    ),
    "node-recycle": (
        "node-replaced-two-sided",
        {
            "target_pod_uid_changed": ("different",),
            "peer_node_unchanged": ("equal",),
            "availability_preserved": ("after_true",),
        },
    ),
    "pod-rotate": (
        "pod-uid-replaced-availability",
        {
            "target_pod_uid_changed": ("different",),
            "sibling_pod_uid_unchanged": ("equal",),
            "availability_preserved": ("after_true",),
        },
    ),
    "quarantine": (
        "pod-quarantined-network",
        {
            "forbidden_edge_blocked": ("transition", "reached", "blocked"),
            "legitimate_edge_preserved": ("equal",),
            "target_pod_uid_unchanged": ("equal",),
        },
    ),
    "sensitive-output": (
        "sensitive-output-blocked-two-sided",
        {
            "sensitive_output_blocked": ("transition", "disclosed", "blocked"),
            "benign_output_preserved": ("equal",),
        },
    ),
    "serving-kv": (
        "key-reset-two-sided",
        {
            "compromised_key_changed": ("different",),
            "benign_key_preserved": ("equal",),
            "serving_pods_consistent": ("after_true",),
        },
    ),
    "serving-rate": (
        "abusive-rate-throttled-two-sided",
        {
            "abusive_request_throttled": ("transition", "admitted", "throttled"),
            "legitimate_request_preserved": ("equal",),
        },
    ),
}


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def sha256_value(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def strict_json_loads(raw: bytes | str) -> Any:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON object key: {key!r}")
            value[key] = item
        return value

    def reject_constant(value: str) -> Any:
        raise ValueError(f"non-finite JSON number is forbidden: {value}")

    return json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)


def utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def issue(status: str, reason: str) -> tuple[str, str]:
    return status, reason


def check_result(name: str, issues: Iterable[tuple[str, str]]) -> dict[str, str]:
    found = list(issues)
    if not found:
        return {"name": name, "status": "PASS", "reason": "verified"}
    status = max((entry[0] for entry in found), key=STATUS_ORDER.__getitem__)
    reasons = sorted({reason for _, reason in found})
    return {"name": name, "status": status, "reason": "; ".join(reasons)}


def mapping(value: Any, label: str) -> tuple[dict[str, Any] | None, list[tuple[str, str]]]:
    if value is None:
        return None, [issue("BLOCKED", f"{label} is missing")]
    if not isinstance(value, dict):
        return None, [issue("INVALID", f"{label} must be an object")]
    return value, []


def exact_correlation(
    stage: dict[str, Any], record: dict[str, Any], label: str
) -> list[tuple[str, str]]:
    problems: list[tuple[str, str]] = []
    for key in ("catalogue_id", "run_id"):
        value = stage.get(key)
        if not isinstance(value, str) or not value:
            problems.append(issue("BLOCKED", f"{label}.{key} is missing"))
        elif value != record.get(key):
            problems.append(issue("INVALID", f"{label}.{key} does not match the record"))
    return problems


def stage_kind(
    stage: dict[str, Any], label: str, accepted: set[str]
) -> list[tuple[str, str]]:
    value = stage.get("evidence_kind")
    if value is None:
        return [issue("BLOCKED", f"{label}.evidence_kind is missing")]
    if value in {"metadata", "catalogue-metadata", "declared", "screenshot"}:
        return [issue("INVALID", f"{label} is metadata-only evidence")]
    if value not in accepted:
        return [issue("INVALID", f"{label}.evidence_kind {value!r} is not accepted")]
    return []


def time_field(
    stage: dict[str, Any], key: str, label: str
) -> tuple[datetime | None, list[tuple[str, str]]]:
    if key not in stage:
        return None, [issue("BLOCKED", f"{label}.{key} is missing")]
    value = parse_time(stage.get(key))
    if value is None:
        return None, [issue("INVALID", f"{label}.{key} is not a timezone-aware timestamp")]
    return value, []


def window(record: dict[str, Any]) -> tuple[datetime | None, datetime | None]:
    run = record.get("run")
    if not isinstance(run, dict):
        return None, None
    return parse_time(run.get("started_at")), parse_time(run.get("finished_at"))


def in_window(
    value: datetime | None, start: datetime | None, finish: datetime | None, label: str
) -> list[tuple[str, str]]:
    if value is None or start is None or finish is None:
        return []
    if value < start or value > finish:
        return [issue("INVALID", f"{label} is outside the run window")]
    return []


def validate_identity(record: dict[str, Any]) -> dict[str, str]:
    problems: list[tuple[str, str]] = []
    if record.get("schema") != RECORD_SCHEMA:
        problems.append(issue("INVALID", f"schema must be {RECORD_SCHEMA}"))
    for key in ("catalogue_id", "run_id", "family", "expected_action"):
        if not isinstance(record.get(key), str) or not record.get(key):
            problems.append(issue("BLOCKED", f"{key} is missing"))
    family = record.get("family")
    if isinstance(family, str) and family and family not in ORACLE_SPECS:
        problems.append(issue("INVALID", f"family {family!r} has no physical oracle contract"))
    if record.get("_merge_conflicts"):
        problems.append(issue("INVALID", "sources disagree: " + ", ".join(record["_merge_conflicts"])))
    if record.get("_identity_mismatch"):
        problems.append(issue("INVALID", record["_identity_mismatch"]))
    if record.get("_ambiguous_runs"):
        problems.append(issue("INVALID", "multiple runs exist for the same catalogue ID without an expected run"))
    if record.get("_missing_record"):
        problems.append(issue("BLOCKED", "the expected run record is missing"))
    return check_result("identity", problems)


def validate_window(record: dict[str, Any], as_of: datetime) -> dict[str, str]:
    run, problems = mapping(record.get("run"), "run")
    if run is None:
        return check_result("run_window", problems)
    problems.extend(exact_correlation(run, record, "run"))
    start, start_issues = time_field(run, "started_at", "run")
    finish, finish_issues = time_field(run, "finished_at", "run")
    problems.extend(start_issues + finish_issues)
    if start and finish and start >= finish:
        problems.append(issue("INVALID", "run.started_at must precede run.finished_at"))
    if start and start > as_of:
        problems.append(issue("INVALID", "run.started_at is in the future"))
    if finish and finish > as_of:
        problems.append(issue("INVALID", "run.finished_at is in the future"))
    return check_result("run_window", problems)


def validate_trigger(record: dict[str, Any]) -> dict[str, str]:
    problems: list[tuple[str, str]] = []
    trigger, trigger_issues = mapping(record.get("trigger"), "trigger")
    policy, policy_issues = mapping(record.get("policy"), "policy")
    problems.extend(trigger_issues + policy_issues)
    if trigger:
        problems.extend(exact_correlation(trigger, record, "trigger"))
        problems.extend(stage_kind(trigger, "trigger", {"runtime-config"}))
        mode = trigger.get("mode")
        if mode is None:
            problems.append(issue("BLOCKED", "trigger.mode is missing"))
        elif mode in {"active", "dryRun"}:
            problems.append(issue("INVALID", "trigger mode was conflated with active|dryRun policy mode"))
        elif mode != "reactive":
            problems.append(issue("FAIL", "trigger.mode is not reactive"))
    if policy:
        problems.extend(exact_correlation(policy, record, "policy"))
        problems.extend(stage_kind(policy, "policy", {"runtime-config"}))
        mode = policy.get("mode")
        if mode is None:
            problems.append(issue("BLOCKED", "policy.mode is missing"))
        elif mode not in {"active", "dryRun"}:
            problems.append(issue("INVALID", "policy.mode must be active or dryRun"))
        elif mode != "active":
            problems.append(issue("FAIL", "policy.mode is dryRun; physical actuation cannot be credited"))
    return check_result("trigger_policy", problems)


def validate_signal(record: dict[str, Any], max_age_seconds: int) -> dict[str, str]:
    signal, problems = mapping(record.get("signal"), "signal")
    if signal is None:
        return check_result("fresh_signal", problems)
    problems.extend(exact_correlation(signal, record, "signal"))
    problems.extend(stage_kind(signal, "signal", {"runtime-observation"}))
    if signal.get("observed") is not True:
        if signal.get("observed") is False:
            problems.append(issue("FAIL", "signal was not observed"))
        else:
            problems.append(issue("BLOCKED", "signal.observed=true is missing"))
    for key in ("event_uid", "target_uid"):
        if not isinstance(signal.get(key), str) or not signal.get(key):
            problems.append(issue("BLOCKED", f"signal.{key} is missing"))
    created, created_issues = time_field(signal, "created_at", "signal")
    observed, observed_issues = time_field(signal, "observed_at", "signal")
    problems.extend(created_issues + observed_issues)
    start, finish = window(record)
    problems.extend(in_window(created, start, finish, "signal.created_at"))
    problems.extend(in_window(observed, start, finish, "signal.observed_at"))
    if created and observed:
        age = (observed - created).total_seconds()
        if age < 0:
            problems.append(issue("INVALID", "signal was observed before it was created"))
        elif age > max_age_seconds:
            problems.append(issue("INVALID", f"signal is stale ({int(age)}s > {max_age_seconds}s)"))
    return check_result("fresh_signal", problems)


def validate_decision(record: dict[str, Any]) -> dict[str, str]:
    decision, problems = mapping(record.get("decision"), "decision")
    if decision is None:
        return check_result("selected_feasible_decision", problems)
    problems.extend(exact_correlation(decision, record, "decision"))
    problems.extend(stage_kind(decision, "decision", {"runtime-observation"}))
    signal = record.get("signal") if isinstance(record.get("signal"), dict) else {}
    for key in ("event_uid", "target_uid"):
        value = decision.get(key)
        if not isinstance(value, str) or not value:
            problems.append(issue("BLOCKED", f"decision.{key} is missing"))
        elif signal.get(key) and value != signal.get(key):
            problems.append(issue("INVALID", f"decision.{key} does not match signal.{key}"))
    if not isinstance(decision.get("decision_id"), str) or not decision.get("decision_id"):
        problems.append(issue("BLOCKED", "decision.decision_id is missing"))
    for key in ("selected", "feasible"):
        value = decision.get(key)
        if value is not True:
            problems.append(issue("FAIL" if value is False else "BLOCKED", f"decision.{key} is not true"))
    action = decision.get("action")
    if not isinstance(action, str) or not action:
        problems.append(issue("BLOCKED", "decision.action is missing"))
    elif action != record.get("expected_action"):
        problems.append(issue("INVALID", "decision.action does not match expected_action"))
    observed, observed_issues = time_field(decision, "observed_at", "decision")
    problems.extend(observed_issues)
    signal_time = parse_time(signal.get("observed_at"))
    if observed and signal_time and observed < signal_time:
        problems.append(issue("INVALID", "decision predates the signal observation"))
    start, finish = window(record)
    problems.extend(in_window(observed, start, finish, "decision.observed_at"))
    return check_result("selected_feasible_decision", problems)


def validate_actuator(record: dict[str, Any]) -> dict[str, str]:
    actuator, problems = mapping(record.get("actuator"), "actuator")
    if actuator is None:
        decision = record.get("decision")
        if isinstance(decision, dict) and decision.get("dispatch_outcome") == "emitted":
            problems.append(issue("INVALID", "dispatch was merely emitted; no accepted actuator receipt exists"))
        return check_result("accepted_actuator_receipt", problems)
    problems.extend(exact_correlation(actuator, record, "actuator"))
    problems.extend(stage_kind(actuator, "actuator", {"accepted-receipt"}))
    decision = record.get("decision") if isinstance(record.get("decision"), dict) else {}
    decision_id = actuator.get("decision_id")
    if not isinstance(decision_id, str) or not decision_id:
        problems.append(issue("BLOCKED", "actuator.decision_id is missing"))
    elif decision.get("decision_id") and decision_id != decision.get("decision_id"):
        problems.append(issue("INVALID", "actuator.decision_id does not match the decision"))
    if actuator.get("status") == "emitted":
        problems.append(issue("INVALID", "actuator evidence is merely emitted, not accepted"))
    elif actuator.get("status") != "accepted":
        problems.append(
            issue("FAIL" if actuator.get("status") in {"rejected", "failed"} else "BLOCKED", "actuator.status is not accepted")
        )
    if not isinstance(actuator.get("receipt_id"), str) or not actuator.get("receipt_id"):
        problems.append(issue("BLOCKED", "actuator.receipt_id is missing"))
    action = actuator.get("action")
    if not isinstance(action, str) or not action:
        problems.append(issue("BLOCKED", "actuator.action is missing"))
    elif action != decision.get("action") or action != record.get("expected_action"):
        problems.append(issue("INVALID", "actuator.action does not match the selected action"))
    accepted, accepted_issues = time_field(actuator, "accepted_at", "actuator")
    problems.extend(accepted_issues)
    decision_time = parse_time(decision.get("observed_at"))
    if accepted and decision_time and accepted < decision_time:
        problems.append(issue("INVALID", "actuator receipt predates the decision"))
    start, finish = window(record)
    problems.extend(in_window(accepted, start, finish, "actuator.accepted_at"))
    return check_result("accepted_actuator_receipt", problems)


def normalized_scalar(value: Any) -> Any:
    return value.strip().lower() if isinstance(value, str) else value


def relation_holds(before: Any, after: Any, relation: tuple[Any, ...]) -> bool:
    operator = relation[0]
    if operator == "different":
        return before != after
    if operator == "equal":
        return before == after
    if operator == "after_true":
        return after is True
    if operator == "transition":
        return normalized_scalar(before) == relation[1] and normalized_scalar(after) == relation[2]
    return False


def validate_oracle(record: dict[str, Any]) -> dict[str, str]:
    oracle, problems = mapping(record.get("oracle"), "oracle")
    if oracle is None:
        return check_result("family_physical_oracle", problems)
    problems.extend(exact_correlation(oracle, record, "oracle"))
    problems.extend(stage_kind(oracle, "oracle", {"physical-observation"}))
    family = record.get("family")
    spec = ORACLE_SPECS.get(family)
    if spec is None:
        problems.append(issue("INVALID", "record family has no physical oracle contract"))
        return check_result("family_physical_oracle", problems)
    expected_kind, expected_observations = spec
    if oracle.get("family") != family:
        problems.append(issue("INVALID", "oracle.family does not match record.family"))
    if oracle.get("kind") != expected_kind:
        problems.append(issue("INVALID", f"oracle.kind must be {expected_kind}"))
    if oracle.get("passed") is not True:
        problems.append(issue("FAIL" if oracle.get("passed") is False else "BLOCKED", "oracle.passed is not true"))
    observed_at, observed_issues = time_field(oracle, "observed_at", "oracle")
    problems.extend(observed_issues)
    actuator = record.get("actuator") if isinstance(record.get("actuator"), dict) else {}
    accepted_at = parse_time(actuator.get("accepted_at"))
    if observed_at and accepted_at and observed_at < accepted_at:
        problems.append(issue("INVALID", "physical oracle predates actuator acceptance"))
    start, finish = window(record)
    problems.extend(in_window(observed_at, start, finish, "oracle.observed_at"))

    observations = oracle.get("observations")
    if observations is None:
        problems.append(issue("BLOCKED", "oracle.observations is missing"))
        observations = []
    elif not isinstance(observations, list):
        problems.append(issue("INVALID", "oracle.observations must be a list"))
        observations = []
    by_name: dict[str, list[dict[str, Any]]] = {}
    for entry in observations:
        if not isinstance(entry, dict):
            problems.append(issue("INVALID", "oracle observation must be an object"))
            continue
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            problems.append(issue("INVALID", "oracle observation name is missing"))
            continue
        by_name.setdefault(name, []).append(entry)
    for name, relation in expected_observations.items():
        matches = by_name.get(name, [])
        if not matches:
            problems.append(issue("BLOCKED", f"physical observation {name!r} is missing"))
            continue
        if len(matches) != 1:
            problems.append(issue("INVALID", f"physical observation {name!r} is duplicated"))
            continue
        entry = matches[0]
        if "before" not in entry or "after" not in entry:
            problems.append(issue("BLOCKED", f"physical observation {name!r} lacks before/after values"))
        elif not relation_holds(entry.get("before"), entry.get("after"), relation):
            problems.append(issue("INVALID", f"physical observation {name!r} does not satisfy {relation[0]}"))
        if entry.get("passed") is not True:
            problems.append(issue("FAIL" if entry.get("passed") is False else "BLOCKED", f"physical observation {name!r} is not passed"))
        entry_time, entry_issues = time_field(entry, "observed_at", f"oracle.observations[{name}]")
        problems.extend(entry_issues)
        if entry_time and observed_at and entry_time > observed_at:
            problems.append(issue("INVALID", f"physical observation {name!r} postdates oracle.observed_at"))
        problems.extend(in_window(entry_time, start, finish, f"oracle.observations[{name}].observed_at"))
    unknown_observations = sorted(set(by_name) - set(expected_observations))
    if unknown_observations:
        problems.append(
            issue("INVALID", f"oracle contains observations outside the family contract: {unknown_observations}")
        )
    return check_result("family_physical_oracle", problems)


def prom_samples(payload: Any) -> list[tuple[float, float]]:
    samples: list[tuple[float, float]] = []
    if not isinstance(payload, dict):
        return samples

    def add(pair: Any) -> None:
        if not isinstance(pair, list) or len(pair) != 2:
            return
        try:
            timestamp = float(pair[0])
            value = float(pair[1])
        except (TypeError, ValueError):
            return
        if math.isfinite(timestamp) and math.isfinite(value):
            samples.append((timestamp, value))

    data = payload.get("data")
    if not isinstance(data, dict):
        return samples
    result = data.get("result")
    if not isinstance(result, list):
        return samples
    for series in result:
        if not isinstance(series, dict):
            continue
        add(series.get("value"))
        values = series.get("values")
        if isinstance(values, list):
            for pair in values:
                add(pair)
    return samples


def validate_prom_capture(
    capture: Any,
    label: str,
    start: datetime | None,
    finish: datetime | None,
    minimum_samples: int,
) -> tuple[list[tuple[str, str]], datetime | None, list[tuple[float, float]]]:
    value, problems = mapping(capture, label)
    if value is None:
        return problems, None, []
    captured_at, time_issues = time_field(value, "captured_at", label)
    problems.extend(time_issues)
    problems.extend(in_window(captured_at, start, finish, f"{label}.captured_at"))
    payload = value.get("payload")
    if payload is None:
        problems.append(issue("BLOCKED", f"{label}.payload is missing"))
        return problems, captured_at, []
    if not isinstance(payload, dict):
        problems.append(issue("INVALID", f"{label}.payload must be a Prometheus JSON object"))
        return problems, captured_at, []
    if payload.get("status") != "success":
        problems.append(issue("INVALID", f"{label}.payload is not a successful Prometheus response"))
    digest = value.get("sha256")
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        problems.append(issue("BLOCKED", f"{label}.sha256 is missing"))
    elif digest != sha256_value(payload):
        problems.append(issue("INVALID", f"{label}.sha256 does not match its payload"))
    samples = prom_samples(payload)
    if len(samples) < minimum_samples:
        problems.append(issue("INVALID", f"{label}.payload lacks raw numeric samples"))
    return problems, captured_at, samples


def validate_prometheus(record: dict[str, Any]) -> dict[str, str]:
    prom, problems = mapping(record.get("prometheus"), "prometheus")
    if prom is None:
        return check_result("prometheus_evidence", problems)
    problems.extend(exact_correlation(prom, record, "prometheus"))
    if prom.get("schema") != PROMETHEUS_SCHEMA:
        problems.append(issue("INVALID", f"prometheus.schema must be {PROMETHEUS_SCHEMA}"))
    if prom.get("status") != "COMPLETE":
        problems.append(issue("BLOCKED" if prom.get("status") is None else "INVALID", "prometheus.status is not COMPLETE"))
    if prom.get("errors") not in (None, []):
        problems.append(issue("INVALID", "prometheus.errors is not empty"))
    metrics = prom.get("metrics")
    if metrics is None:
        problems.append(issue("BLOCKED", "prometheus.metrics is missing"))
        metrics = []
    elif not isinstance(metrics, list):
        problems.append(issue("INVALID", "prometheus.metrics must be a list"))
        metrics = []
    elif not metrics:
        problems.append(issue("BLOCKED", "prometheus.metrics is empty"))
    start, finish = window(record)
    signal = record.get("signal") if isinstance(record.get("signal"), dict) else {}
    oracle = record.get("oracle") if isinstance(record.get("oracle"), dict) else {}
    signal_created = parse_time(signal.get("created_at"))
    oracle_observed = parse_time(oracle.get("observed_at"))
    seen_keys: set[str] = set()
    for index, metric in enumerate(metrics):
        label = f"prometheus.metrics[{index}]"
        if not isinstance(metric, dict):
            problems.append(issue("INVALID", f"{label} must be an object"))
            continue
        key = metric.get("key")
        query = metric.get("query")
        if not isinstance(key, str) or not key:
            problems.append(issue("BLOCKED", f"{label}.key is missing"))
        elif key in seen_keys:
            problems.append(issue("INVALID", f"duplicate Prometheus metric key {key!r}"))
        else:
            seen_keys.add(key)
        if not isinstance(query, str) or not query:
            problems.append(issue("BLOCKED", f"{label}.query is missing"))
        query_digest = metric.get("query_sha256")
        if not isinstance(query_digest, str) or not SHA256_RE.fullmatch(query_digest):
            problems.append(issue("BLOCKED", f"{label}.query_sha256 is missing"))
        elif isinstance(query, str) and query_digest != hashlib.sha256(query.encode()).hexdigest():
            problems.append(issue("INVALID", f"{label}.query_sha256 does not match query"))
        if metric.get("errors") not in (None, []):
            problems.append(issue("INVALID", f"{label}.errors is not empty"))
        baseline_issues, baseline_at, _ = validate_prom_capture(
            metric.get("baseline"), f"{label}.baseline", start, finish, 1
        )
        final_issues, final_at, _ = validate_prom_capture(
            metric.get("final"), f"{label}.final", start, finish, 1
        )
        raw_issues, raw_at, raw_samples = validate_prom_capture(
            metric.get("raw"), f"{label}.raw", start, finish, 2
        )
        problems.extend(baseline_issues + final_issues + raw_issues)
        if baseline_at and final_at and baseline_at >= final_at:
            problems.append(issue("INVALID", f"{label} baseline does not precede final"))
        if baseline_at and signal_created and baseline_at > signal_created:
            problems.append(issue("INVALID", f"{label} baseline was captured after signal creation"))
        if final_at and oracle_observed and final_at < oracle_observed:
            problems.append(issue("INVALID", f"{label} final was captured before the physical oracle"))
        if raw_at and final_at and raw_at < final_at:
            problems.append(issue("INVALID", f"{label} raw range was captured before final"))
        if raw_samples and baseline_at and min(t for t, _ in raw_samples) > baseline_at.timestamp():
            problems.append(issue("INVALID", f"{label} raw range does not cover baseline"))
        if raw_samples and final_at and max(t for t, _ in raw_samples) < final_at.timestamp():
            problems.append(issue("INVALID", f"{label} raw range does not cover final"))
    return check_result("prometheus_evidence", problems)


def validate_postflight(record: dict[str, Any]) -> dict[str, str]:
    postflight, problems = mapping(record.get("postflight"), "postflight")
    summary_clean = record.get("postflight_clean")
    if summary_clean is not True:
        problems.append(
            issue(
                "FAIL" if summary_clean is False else "BLOCKED",
                "top-level postflight_clean is not true",
            )
        )
    if postflight is None:
        return check_result("postflight_clean", problems)
    problems.extend(exact_correlation(postflight, record, "postflight"))
    problems.extend(stage_kind(postflight, "postflight", {"runtime-health"}))
    clean = postflight.get("clean")
    if clean is not True:
        problems.append(issue("FAIL" if clean is False else "BLOCKED", "postflight.clean is not true"))
    if isinstance(clean, bool) and isinstance(summary_clean, bool) and clean != summary_clean:
        problems.append(issue("INVALID", "postflight.clean disagrees with top-level postflight_clean"))
    digest = postflight.get("inventory_sha256")
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        problems.append(issue("BLOCKED", "postflight.inventory_sha256 is missing"))
    checked_at, checked_issues = time_field(postflight, "checked_at", "postflight")
    problems.extend(checked_issues)
    oracle = record.get("oracle") if isinstance(record.get("oracle"), dict) else {}
    oracle_time = parse_time(oracle.get("observed_at"))
    if checked_at and oracle_time and checked_at < oracle_time:
        problems.append(issue("INVALID", "postflight check predates the physical oracle"))
    start, finish = window(record)
    problems.extend(in_window(checked_at, start, finish, "postflight.checked_at"))
    return check_result("postflight_clean", problems)


def public_record(record: dict[str, Any]) -> dict[str, Any]:
    # Attachments may be added after the audit.  Excluding them keeps both the
    # authoritative evidence digest and its screenshot binding stable.
    return {
        key: value
        for key, value in record.items()
        if not key.startswith("_") and key not in {"attachments", "screenshots"}
    }


def validate_record(
    record: dict[str, Any],
    as_of: datetime,
    max_signal_age_seconds: int = 300,
    provenance: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    checks = [
        validate_identity(record),
        validate_window(record, as_of),
        validate_trigger(record),
        validate_signal(record, max_signal_age_seconds),
        validate_decision(record),
        validate_actuator(record),
        validate_oracle(record),
        validate_prometheus(record),
        validate_postflight(record),
    ]
    verdict = max((entry["status"] for entry in checks), key=STATUS_ORDER.__getitem__)
    evidence = public_record(record)
    return {
        "schema": VERDICT_SCHEMA,
        "catalogue_id": record.get("catalogue_id") if isinstance(record.get("catalogue_id"), str) else "",
        "run_id": record.get("run_id") if isinstance(record.get("run_id"), str) else "",
        "verdict": verdict,
        "audited_at": utc_text(as_of),
        "evidence_sha256": sha256_value(evidence),
        "checks": checks,
        "provenance": provenance or [],
    }


def deep_merge(target: dict[str, Any], incoming: dict[str, Any], path: str = "") -> list[str]:
    conflicts: list[str] = []
    for key, value in incoming.items():
        if key.startswith("_"):
            continue
        location = f"{path}.{key}" if path else key
        if key not in target or target[key] is None:
            target[key] = value
        elif isinstance(target[key], dict) and isinstance(value, dict):
            conflicts.extend(deep_merge(target[key], value, location))
        elif target[key] != value:
            conflicts.append(location)
    return conflicts


def normalize_console_run(document: dict[str, Any]) -> dict[str, Any]:
    result = document.get("attackCatalogueResult") or document.get("result") or {}
    run_id = result.get("runID") or document.get("id") or ""
    catalogue_id = result.get("catalogueID") or document.get("catalogueID") or ""
    trigger_mode = result.get("triggerMode") or document.get("triggerMode")
    execution_mode = result.get("executionMode") or document.get("executionMode")
    signal = result.get("signal") or {}
    decision = result.get("decision") or {}
    actuator = result.get("actuator") or {}
    physical = result.get("physicalValidation") or {}
    cleanup = result.get("cleanup") or {}

    def stage_identity(stage: dict[str, Any]) -> tuple[str, str]:
        return stage.get("catalogueID", catalogue_id), stage.get("runID", run_id)

    signal_catalogue_id, signal_run_id = stage_identity(signal)
    decision_catalogue_id, decision_run_id = stage_identity(decision)
    actuator_catalogue_id, actuator_run_id = stage_identity(actuator)
    physical_catalogue_id, physical_run_id = stage_identity(physical)
    record: dict[str, Any] = {
        "schema": RECORD_SCHEMA,
        "catalogue_id": catalogue_id,
        "run_id": run_id,
        "family": result.get("family", ""),
        "expected_action": result.get("expectedAction", ""),
        "postflight_clean": document.get("postflight_clean"),
        "run": {
            "catalogue_id": catalogue_id,
            "run_id": run_id,
            "started_at": result.get("startedAt"),
            "finished_at": result.get("finishedAt"),
        },
        "trigger": {
            "catalogue_id": catalogue_id,
            "run_id": run_id,
            "evidence_kind": "runtime-config",
            "mode": trigger_mode,
        },
        "policy": {
            "catalogue_id": catalogue_id,
            "run_id": run_id,
            "evidence_kind": "runtime-config",
            "mode": execution_mode,
        },
        "signal": {
            "catalogue_id": signal_catalogue_id,
            "run_id": signal_run_id,
            "evidence_kind": "runtime-observation",
            "observed": signal.get("observed"),
            "event_uid": signal.get("uid"),
            "target_uid": signal.get("targetUID"),
            "created_at": signal.get("createdAt"),
            "observed_at": signal.get("observedAt"),
        },
        "decision": {
            "catalogue_id": decision_catalogue_id,
            "run_id": decision_run_id,
            "evidence_kind": "runtime-observation",
            "event_uid": decision.get("eventUID"),
            "target_uid": decision.get("targetUID"),
            "decision_id": decision.get("id"),
            "observed_at": decision.get("observedAt"),
            "selected": decision.get("selected"),
            "feasible": decision.get("feasible"),
            "action": decision.get("action"),
            "dispatch_outcome": decision.get("dispatchOutcome"),
        },
        "actuator": {
            "catalogue_id": actuator_catalogue_id,
            "run_id": actuator_run_id,
            "evidence_kind": "accepted-receipt" if actuator.get("receiptObserved") else None,
            "decision_id": actuator.get("decisionID"),
            "receipt_id": actuator.get("receiptID"),
            "status": actuator.get("status"),
            "accepted_at": actuator.get("acceptedAt"),
            "action": actuator.get("handler"),
        },
        "oracle": {
            "catalogue_id": physical_catalogue_id,
            "run_id": physical_run_id,
            "evidence_kind": "physical-observation",
            "family": result.get("family"),
            "kind": physical.get("kind"),
            "native_kind": physical.get("oracle"),
            "passed": physical.get("validated"),
            "observed_at": physical.get("observedAt"),
            "observations": physical.get("observations"),
            "native_evidence": physical.get("evidence"),
        },
        # Console cleanup is not postflight health.  It is deliberately retained
        # only as a diagnostic extension and cannot satisfy postflight_clean.
        "console_cleanup": cleanup,
    }
    # Preserve the distinction between an absent native field (BLOCKED) and an
    # explicitly malformed/null field (INVALID).
    for normalized, native, fields in (
        (record["signal"], signal, {"created_at": "createdAt", "observed_at": "observedAt"}),
        (record["decision"], decision, {
            "event_uid": "eventUID", "target_uid": "targetUID", "observed_at": "observedAt",
        }),
        (record["actuator"], actuator, {
            "decision_id": "decisionID", "receipt_id": "receiptID", "status": "status",
            "accepted_at": "acceptedAt",
        }),
        (record["oracle"], physical, {
            "kind": "kind", "observed_at": "observedAt", "observations": "observations",
            "native_evidence": "evidence",
        }),
    ):
        for normalized_key, native_key in fields.items():
            if native_key not in native:
                normalized.pop(normalized_key, None)
    conflicts = []
    if document.get("schema") == RUN_RECORD_SCHEMA:
        if document.get("runID") != run_id:
            conflicts.append("runID")
        if document.get("catalogueID") != catalogue_id:
            conflicts.append("catalogueID")
        if document.get("triggerMode") != result.get("triggerMode"):
            conflicts.append("triggerMode")
        if document.get("executionMode") != result.get("executionMode"):
            conflicts.append("executionMode")
    if conflicts:
        record["_merge_conflicts"] = [f"native run record {field}" for field in conflicts]
    if isinstance(document.get("postflight"), dict):
        record["postflight"] = document["postflight"]
    prometheus = document.get("prometheusEvidence")
    if isinstance(prometheus, dict):
        record["prometheus"] = normalize_native_prometheus(prometheus)
    return record


def normalize_native_prometheus(value: dict[str, Any]) -> dict[str, Any]:
    def capture(source: Any) -> dict[str, Any] | None:
        if not isinstance(source, dict):
            return None
        return {
            "captured_at": source.get("capturedAt"),
            "sha256": source.get("sha256"),
            "payload": source.get("payload"),
            "raw_body_sha256": source.get("rawBodySHA256"),
            "response_body": source.get("responseBody"),
            "path": source.get("path"),
            "parameters": source.get("parameters"),
        }

    metrics = []
    for metric in value.get("metrics") or []:
        if not isinstance(metric, dict):
            continue
        metrics.append(
            {
                "key": metric.get("key"),
                "query": metric.get("query"),
                "query_sha256": metric.get("querySHA256"),
                "baseline": capture(metric.get("baselineCapture")),
                "final": capture(metric.get("finalCapture")),
                "raw": capture(metric.get("rawCapture")),
                "native_baseline": metric.get("baseline"),
                "native_final": metric.get("final"),
                "native_range": metric.get("range"),
                "errors": metric.get("errors"),
            }
        )
    return {
        "schema": PROMETHEUS_SCHEMA,
        "catalogue_id": value.get("catalogueID") or value.get("catalogue_id"),
        "run_id": value.get("runID") or value.get("run_id"),
        "status": value.get("status"),
        "metrics": metrics,
        "errors": value.get("errors"),
    }


def normalize_runner_record(document: dict[str, Any]) -> dict[str, Any]:
    evidence = document.get("evidence") if isinstance(document.get("evidence"), dict) else {}
    catalogue_id = document.get("attack") or evidence.get("catalogue_id") or ""
    run_id = document.get("run_id") or evidence.get("run_id") or ""
    return {
        "schema": RECORD_SCHEMA,
        "catalogue_id": catalogue_id,
        "run_id": run_id,
        "family": evidence.get("family", ""),
        "expected_action": evidence.get("expected_action", ""),
        "legacy_runner_evidence": document,
        "postflight_clean": document.get("postflight_clean"),
        "postflight": {
            "catalogue_id": catalogue_id,
            "run_id": run_id,
            "evidence_kind": "runtime-health",
            "clean": document.get("postflight_clean"),
            "checked_at": document.get("generated_at"),
            "inventory_sha256": evidence.get("postflight_inventory_sha256"),
        },
    }


def extract_document(
    document: Any, source_index: int
) -> tuple[list[dict[str, Any]], list[tuple[str, str]], list[dict[str, Any]]]:
    records: list[dict[str, Any]] = []
    expected: list[tuple[str, str]] = []
    companions: list[dict[str, Any]] = []
    if isinstance(document, list):
        for item in document:
            child_records, child_expected, child_companions = extract_document(item, source_index)
            records.extend(child_records)
            expected.extend(child_expected)
            companions.extend(child_companions)
        return records, expected, companions
    if not isinstance(document, dict):
        raise ValueError("top-level evidence must be an object or list")
    schema = document.get("schema")
    if schema == BUNDLE_SCHEMA:
        for item in document.get("expected_runs") or []:
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("catalogue_id"), str)
                or not item.get("catalogue_id")
                or not isinstance(item.get("run_id"), str)
                or not item.get("run_id")
            ):
                raise ValueError("bundle expected_runs entries require catalogue_id and run_id")
            expected.append((item["catalogue_id"], item["run_id"]))
        child_records, _, child_companions = extract_document(document.get("records") or [], source_index)
        records.extend(child_records)
        companions.extend(child_companions)
        return records, expected, companions
    if schema == RECORD_SCHEMA:
        record = dict(document)
        record["_source_indices"] = [source_index]
        records.append(record)
        return records, expected, companions
    if schema == PROMETHEUS_SCHEMA:
        companion = dict(document)
        companion["_source_indices"] = [source_index]
        companions.append(companion)
        return records, expected, companions
    if schema == NATIVE_PROMETHEUS_SCHEMA:
        companion = normalize_native_prometheus(document)
        companion["_source_indices"] = [source_index]
        companions.append(companion)
        return records, expected, companions
    if schema == RUN_RECORD_SCHEMA:
        record = normalize_console_run(document)
        record["_source_indices"] = [source_index]
        records.append(record)
        return records, expected, companions
    if schema == RESULT_SCHEMA:
        record = normalize_console_run({"attackCatalogueResult": document})
        record["_source_indices"] = [source_index]
        records.append(record)
        return records, expected, companions
    if isinstance(document.get("attackCatalogueResult"), dict):
        record = normalize_console_run(document)
        record["_source_indices"] = [source_index]
        records.append(record)
        return records, expected, companions
    if "attack" in document and "postflight_clean" in document:
        record = normalize_runner_record(document)
        record["_source_indices"] = [source_index]
        records.append(record)
        return records, expected, companions
    for key in ("records", "runs", "items", "results", "data"):
        if isinstance(document.get(key), list):
            return extract_document(document[key], source_index)
    raise ValueError("unrecognized evidence JSON shape")


def record_key(record: dict[str, Any]) -> tuple[str, str]:
    catalogue_id = record.get("catalogue_id")
    run_id = record.get("run_id")
    return (
        catalogue_id if isinstance(catalogue_id, str) else "",
        run_id if isinstance(run_id, str) else "",
    )


def merge_records(
    records: list[dict[str, Any]], companions: list[dict[str, Any]]
) -> dict[tuple[str, str], dict[str, Any]]:
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for record in records:
        key = record_key(record)
        if key not in merged:
            merged[key] = record
            continue
        source_indices = sorted(set(merged[key].get("_source_indices", []) + record.get("_source_indices", [])))
        conflicts = deep_merge(merged[key], record)
        merged[key]["_source_indices"] = source_indices
        merged[key].setdefault("_merge_conflicts", []).extend(conflicts)
    for companion in companions:
        key = record_key(companion)
        target = merged.get(key)
        if target is None:
            target = {
                "schema": RECORD_SCHEMA,
                "catalogue_id": key[0],
                "run_id": key[1],
                "_source_indices": companion.get("_source_indices", []),
            }
            merged[key] = target
        if "prometheus" not in target:
            target["prometheus"] = public_record(companion)
        else:
            conflicts = deep_merge(target["prometheus"], companion, "prometheus")
            target.setdefault("_merge_conflicts", []).extend(conflicts)
        target["_source_indices"] = sorted(
            set(target.get("_source_indices", []) + companion.get("_source_indices", []))
        )
    return merged


def select_campaign_records(
    records: dict[tuple[str, str], dict[str, Any]], expected: list[tuple[str, str]]
) -> list[dict[str, Any]]:
    if expected:
        if len(expected) != len(set(expected)):
            raise ValueError("expected_runs contains duplicate catalogue_id/run_id pairs")
        ids = [catalogue_id for catalogue_id, _ in expected]
        if len(ids) != len(set(ids)):
            raise ValueError("expected_runs must contain exactly one run per catalogue_id")
        selected = []
        for key in expected:
            if key in records:
                selected.append(records[key])
                continue
            other_runs = sorted(run_id for (catalogue_id, run_id) in records if catalogue_id == key[0])
            missing: dict[str, Any] = {
                "schema": RECORD_SCHEMA,
                "catalogue_id": key[0],
                "run_id": key[1],
                "_source_indices": [],
            }
            if other_runs:
                missing["_identity_mismatch"] = (
                    f"expected run {key[1]!r}, but only other run IDs were exported: {other_runs}"
                )
            else:
                missing["_missing_record"] = True
            selected.append(missing)
        return selected

    by_id: dict[str, list[dict[str, Any]]] = {}
    for record in records.values():
        by_id.setdefault(record_key(record)[0], []).append(record)
    selected = []
    for catalogue_id, candidates in sorted(by_id.items()):
        if len(candidates) == 1:
            selected.append(candidates[0])
            continue
        selected.append(
            {
                "schema": RECORD_SCHEMA,
                "catalogue_id": catalogue_id,
                "run_id": "",
                "_ambiguous_runs": sorted(record.get("run_id", "") for record in candidates),
                "_source_indices": sorted(
                    {index for record in candidates for index in record.get("_source_indices", [])}
                ),
            }
        )
    return selected


def safe_stem(value: str) -> str:
    prefix = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._-") or "missing-id"
    return f"{prefix[:80]}--{hashlib.sha256(value.encode()).hexdigest()[:10]}"


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def json_text(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def local_source(path: Path, retrieved_at: str) -> tuple[Any, dict[str, Any]]:
    raw = path.read_bytes()
    document = strict_json_loads(raw)
    exported_at = document.get("exported_at") if isinstance(document, dict) else None
    return document, {
        "kind": "file",
        "locator": str(path.resolve()),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "retrieved_at": retrieved_at,
        "source_exported_at": exported_at,
    }


def sanitized_url(value: str) -> str:
    parts = urlsplit(value)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def api_source(
    url: str, retrieved_at: str, timeout_seconds: int, bearer_token: str | None
) -> tuple[Any, dict[str, Any]]:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        raise ValueError("API sources must use an absolute http(s) URL")
    if parts.username or parts.password:
        raise ValueError("credentials in API URLs are forbidden; use --bearer-token-env")
    headers = {"Accept": "application/json", "User-Agent": "phorvex-console-evidence-audit/1"}
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    request = Request(url, headers=headers, method="GET")
    with urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310 - explicit http(s) validation
        raw = response.read(64 * 1024 * 1024 + 1)
        if len(raw) > 64 * 1024 * 1024:
            raise ValueError("API response exceeds 64 MiB")
        document = strict_json_loads(raw)
    exported_at = document.get("exported_at") if isinstance(document, dict) else None
    return document, {
        "kind": "http-get",
        "locator": sanitized_url(url),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "retrieved_at": retrieved_at,
        "source_exported_at": exported_at,
    }


def source_provenance_for(
    record: dict[str, Any], all_provenance: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    return [all_provenance[index] for index in record.get("_source_indices", [])]


CHECK_COLUMNS = [
    ("identity", "Identity"),
    ("trigger_policy", "Trigger"),
    ("fresh_signal", "Signal"),
    ("selected_feasible_decision", "Decision"),
    ("accepted_actuator_receipt", "Receipt"),
    ("family_physical_oracle", "Oracle"),
    ("prometheus_evidence", "Prometheus"),
    ("postflight_clean", "Postflight"),
]


def check_status(verdict: dict[str, Any], name: str) -> str:
    for entry in verdict["checks"]:
        if entry["name"] == name:
            return entry["status"]
    return "INVALID"


def write_reports(
    output: Path,
    verdicts: list[dict[str, Any]],
    provenance: list[dict[str, Any]],
    as_of: datetime,
    campaign_checks: list[dict[str, str]],
) -> dict[str, Any]:
    verdicts = sorted(verdicts, key=lambda value: (value["catalogue_id"], value["run_id"]))
    for verdict in verdicts:
        name = safe_stem(verdict["catalogue_id"])
        atomic_write(output / "verdicts" / f"{name}.json", json_text(verdict))

    csv_path = output / "matrix.csv"
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{csv_path.name}.", dir=csv_path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle, lineterminator="\n")
            writer.writerow(
                ["catalogue_id", "run_id", "verdict"]
                + [title.lower() for _, title in CHECK_COLUMNS]
                + ["evidence_sha256"]
            )
            for verdict in verdicts:
                writer.writerow(
                    [verdict["catalogue_id"], verdict["run_id"], verdict["verdict"]]
                    + [check_status(verdict, name) for name, _ in CHECK_COLUMNS]
                    + [verdict["evidence_sha256"]]
                )
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, csv_path)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise

    headers = ["Catalogue ID", "Run ID", "Verdict"] + [title for _, title in CHECK_COLUMNS]
    lines = [
        "# Console evidence audit matrix",
        "",
        f"Audited at `{utc_text(as_of)}`. Screenshots are informational attachments and do not affect verdicts.",
        "",
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for verdict in verdicts:
        cells = [verdict["catalogue_id"], verdict["run_id"], verdict["verdict"]]
        cells.extend(check_status(verdict, name) for name, _ in CHECK_COLUMNS)
        lines.append("| " + " | ".join(str(value).replace("|", "\\|") for value in cells) + " |")
    atomic_write(output / "matrix.md", "\n".join(lines) + "\n")

    bindings = []
    for verdict in verdicts:
        binding_material = f"v1\0{verdict['catalogue_id']}\0{verdict['run_id']}\0{verdict['evidence_sha256']}"
        binding_id = hashlib.sha256(binding_material.encode()).hexdigest()
        stem = f"{safe_stem(verdict['catalogue_id'])}--{binding_id[:10]}"
        bindings.append(
            {
                "catalogue_id": verdict["catalogue_id"],
                "run_id": verdict["run_id"],
                "evidence_sha256": verdict["evidence_sha256"],
                "binding_id": binding_id,
                "source_of_truth": False,
                "slots": {
                    "console": {
                        "filename": f"{stem}--console.png",
                        "captured_at": None,
                        "sha256": None,
                    },
                    "grafana": {
                        "filename": f"{stem}--grafana.png",
                        "captured_at": None,
                        "sha256": None,
                    },
                },
            }
        )
    screenshot_manifest = {
        "schema": SCREENSHOT_SCHEMA,
        "generated_at": utc_text(as_of),
        "authoritative_for_verdict": False,
        "bindings": bindings,
    }
    atomic_write(output / "screenshot-bindings.json", json_text(screenshot_manifest))

    counts = {status: sum(1 for verdict in verdicts if verdict["verdict"] == status) for status in STATUS_ORDER}
    campaign_status = "PASS"
    statuses = [verdict["verdict"] for verdict in verdicts] + [entry["status"] for entry in campaign_checks]
    if statuses:
        campaign_status = max(statuses, key=STATUS_ORDER.__getitem__)
    summary = {
        "schema": SUMMARY_SCHEMA,
        "audited_at": utc_text(as_of),
        "campaign_verdict": campaign_status,
        "counts": counts,
        "campaign_checks": campaign_checks,
        "provenance": provenance,
        "outputs": {
            "verdict_directory": "verdicts",
            "markdown_matrix": "matrix.md",
            "csv_matrix": "matrix.csv",
            "screenshot_bindings": "screenshot-bindings.json",
        },
    }
    atomic_write(output / "summary.json", json_text(summary))
    return summary


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="*", type=Path, help="exported run-history/evidence JSON")
    parser.add_argument("--console-api", action="append", default=[], help="read-only Console JSON endpoint (GET only)")
    parser.add_argument("--prometheus-api", action="append", default=[], help="read-only Prometheus/export JSON endpoint (GET only)")
    parser.add_argument("--bearer-token-env", help="environment variable holding an API bearer token")
    parser.add_argument("--http-timeout-seconds", type=int, default=15)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--as-of", help="audit clock as an ISO-8601 timestamp (default: current UTC)")
    parser.add_argument("--expected-count", type=int, help="campaign cardinality, normally 192")
    parser.add_argument("--max-signal-age-seconds", type=int, default=300)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    as_of = parse_time(args.as_of) if args.as_of else datetime.now(timezone.utc)
    if as_of is None:
        print("error: --as-of must be a timezone-aware ISO-8601 timestamp", file=sys.stderr)
        return 2
    if not args.inputs and not args.console_api and not args.prometheus_api:
        print("error: provide at least one JSON file or API endpoint", file=sys.stderr)
        return 2
    if args.max_signal_age_seconds < 1:
        print("error: --max-signal-age-seconds must be positive", file=sys.stderr)
        return 2
    if args.http_timeout_seconds < 1:
        print("error: --http-timeout-seconds must be positive", file=sys.stderr)
        return 2
    if args.expected_count is not None and args.expected_count < 1:
        print("error: --expected-count must be positive", file=sys.stderr)
        return 2
    if args.output.exists():
        if not args.output.is_dir():
            print(f"error: output path is not a directory: {args.output}", file=sys.stderr)
            return 2
        if any(args.output.iterdir()):
            print(f"error: output directory is not empty: {args.output}", file=sys.stderr)
            return 2
    token = None
    if args.bearer_token_env:
        token = os.environ.get(args.bearer_token_env)
        if not token:
            print(f"error: bearer token environment variable is empty: {args.bearer_token_env}", file=sys.stderr)
            return 2

    retrieved_at = utc_text(as_of)
    documents: list[Any] = []
    provenance: list[dict[str, Any]] = []
    try:
        for path in args.inputs:
            document, source = local_source(path, retrieved_at)
            documents.append(document)
            provenance.append(source)
        for url in [*args.console_api, *args.prometheus_api]:
            document, source = api_source(url, retrieved_at, args.http_timeout_seconds, token)
            documents.append(document)
            provenance.append(source)

        records: list[dict[str, Any]] = []
        expected: list[tuple[str, str]] = []
        companions: list[dict[str, Any]] = []
        for index, document in enumerate(documents):
            found_records, found_expected, found_companions = extract_document(document, index)
            records.extend(found_records)
            expected.extend(found_expected)
            companions.extend(found_companions)
        merged = merge_records(records, companions)
        campaign_records = select_campaign_records(merged, expected)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    campaign_checks: list[dict[str, str]] = []
    if not campaign_records:
        campaign_checks.append(
            {"name": "record_count", "status": "INVALID", "reason": "no catalogue records were found"}
        )
    if args.expected_count is not None:
        actual = len(expected) if expected else len(campaign_records)
        if actual == args.expected_count:
            campaign_checks.append(
                {"name": "expected_count", "status": "PASS", "reason": f"found {actual} IDs"}
            )
        else:
            campaign_checks.append(
                {
                    "name": "expected_count",
                    "status": "INVALID",
                    "reason": f"expected {args.expected_count} IDs, found {actual}",
                }
            )

    verdicts = []
    for record in campaign_records:
        record_provenance = source_provenance_for(record, provenance)
        verdicts.append(
            validate_record(record, as_of, args.max_signal_age_seconds, record_provenance)
        )
    summary = write_reports(args.output, verdicts, provenance, as_of, campaign_checks)
    print(
        f"{summary['campaign_verdict']}: {len(verdicts)} catalogue IDs; "
        f"matrix={args.output / 'matrix.md'}"
    )
    return 0 if summary["campaign_verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
