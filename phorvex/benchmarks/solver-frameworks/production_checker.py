#!/usr/bin/env python3
"""Solver-independent acceptance and Phorvex production feasibility checks.

The checker intentionally imports no PuLP, Pyomo, or OR-Tools code.  Its laws are a
Python projection of the production feasibility registry in
``phorvex/internal/feasibility`` plus the conformal gate in
``phorvex/internal/actionset/generator.go``.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from typing import Any, Mapping, Sequence


VALID_ACTIONS = {
    "rotate", "quarantine", "debugger", "custom-inject", "identity-rotate",
    "route-rotate", "warm-swap", "mig-rebind", "kv-reset", "endpoint-rotate",
    "model-shard-replace", "adapter-rotate", "request-drain",
    "guardrail-rotate", "kv-migrate-invalidate",
}
AI_ACTIONS = {
    "warm-swap", "mig-rebind", "model-shard-replace", "kv-reset",
    "endpoint-rotate", "adapter-rotate", "request-drain", "guardrail-rotate",
    "kv-migrate-invalidate",
}
GPU_PROVISIONING_ACTIONS = {"rotate", "warm-swap", "mig-rebind", "model-shard-replace"}
REMOVES_READY_REPLICA = {"rotate", "quarantine"}
CODE_EXEC_ACTIONS = {"debugger", "custom-inject"}
SYSTEM_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease", "kube-apiserver"}
VALID_SOLUTION_STATUSES = {"optimal", "feasible"}


@dataclass(frozen=True)
class CheckResult:
    passed: bool
    violations: tuple[str, ...]
    check_ms: float


@dataclass(frozen=True)
class AcceptanceResult:
    accepted: bool
    fallback: str
    violations: tuple[str, ...]


def _policy(record: Mapping[str, Any]) -> dict[str, Any]:
    """Return explicit safe defaults for legacy fixtures with no production state.

    The original 648 rows contain only coverage/cost data.  These defaults model the
    already-feasible action-set output: a replicated, non-stateful, cool, non-GPU pod.
    Targeted production fixtures override every field needed by the law under test.
    """
    return {
        "max_moves_per_tick": int(record.get("b", 0)),
        "min_available_replicas": 1,
        "p99_ms": 200,
        "min_tokens_per_sec": 0,
        "anti_over_rotation_seconds": 300.0,
        "enabled_actions": ["rotate", "quarantine"],
        "conformal_cost_ceiling": 0.0,
        **record.get("policy", {}),
    }


def _candidate_state(candidate: Mapping[str, Any]) -> dict[str, Any]:
    key = str(candidate.get("key", ""))
    namespace = key.split("/", 1)[0] if "/" in key else "default"
    return {
        "namespace": namespace,
        "desired_replicas": 3,
        "ready_replicas": 3,
        "stateful": False,
        "telemetry_present": True,
        "p99_ms": 50.0,
        "tokens_per_sec": 100.0,
        "seconds_since_last_move": 3600.0,
        "has_gpu": False,
        "model_id": "",
        "mig_device": "",
        "physics_scanned": False,
        "gpu_present": False,
        "vram_fraction": 0.0,
        "mig_geometry_valid": True,
        **candidate.get("state", {}),
    }


def candidate_violations(
    record: Mapping[str, Any], candidate: Mapping[str, Any]
) -> list[str]:
    """Evaluate one selected move against production hard laws."""
    violations: list[str] = []
    policy = _policy(record)
    state = _candidate_state(candidate)
    action = str(candidate.get("action", "rotate"))
    key = str(candidate.get("key", ""))
    prefix = f"candidate:{key}:{action}"

    if action not in VALID_ACTIONS:
        violations.append(f"{prefix}:invalid-action")
        return violations
    enabled = set(policy.get("enabled_actions") or ["rotate", "quarantine"])
    if action not in enabled:
        violations.append(f"{prefix}:action-disabled")

    if action in REMOVES_READY_REPLICA and int(state["desired_replicas"]) > 0:
        if int(state["ready_replicas"]) - 1 < int(policy["min_available_replicas"]):
            violations.append(f"{prefix}:availability-minimum-replicas")

    if (
        int(policy.get("p99_ms", 0)) > 0
        and bool(state.get("telemetry_present"))
        and float(state.get("p99_ms", 0)) > 0
        and float(state["p99_ms"]) >= float(policy["p99_ms"])
    ):
        violations.append(f"{prefix}:slo-p99-headroom")

    since = state.get("seconds_since_last_move")
    if since is not None and float(since) < float(policy.get("anti_over_rotation_seconds", 0)):
        violations.append(f"{prefix}:cooldown-anti-over-rotation")

    if action == "rotate" and bool(state.get("stateful")):
        violations.append(f"{prefix}:stateful-integrity")

    if action in AI_ACTIONS and not (bool(state.get("has_gpu")) or state.get("model_id")):
        violations.append(f"{prefix}:ai-context-required")
    if action == "mig-rebind" and not state.get("mig_device"):
        violations.append(f"{prefix}:mig-device-required")
    if action in CODE_EXEC_ACTIONS and state.get("namespace") in SYSTEM_NAMESPACES:
        violations.append(f"{prefix}:code-exec-system-namespace")

    if (
        bool(state.get("gpu_present"))
        and action in GPU_PROVISIONING_ACTIONS
        and float(state.get("vram_fraction", 0)) > 1.0
    ):
        violations.append(f"{prefix}:gpu-vram-conservation")
    if (
        state.get("mig_device")
        and bool(state.get("physics_scanned"))
        and action in GPU_PROVISIONING_ACTIONS
        and not bool(state.get("mig_geometry_valid"))
    ):
        violations.append(f"{prefix}:gpu-mig-validity")

    sole_server = int(state["desired_replicas"]) <= 1 and int(state["ready_replicas"]) <= 1
    token_floor = float(policy.get("min_tokens_per_sec", 0))
    tokens = float(state.get("tokens_per_sec", 0))
    if (
        action == "rotate"
        and token_floor > 0
        and bool(state.get("telemetry_present"))
        and sole_server
        and 0 < tokens < token_floor
    ):
        violations.append(f"{prefix}:tokens-per-second-floor")

    ceiling = float(policy.get("conformal_cost_ceiling", 0))
    if ceiling > 0 and float(candidate.get("chi", 0)) > ceiling:
        violations.append(f"{prefix}:conformal-slo-cost")
    return violations


def check_solution(
    record: Mapping[str, Any],
    x_values: Sequence[float],
    y_values: Mapping[str, float],
    objective: float,
    tolerance: float = 1e-7,
) -> CheckResult:
    """Independently check solver output and all represented production laws."""
    started = time.perf_counter()
    violations: list[str] = []
    candidates = list(record["cands"])
    facts = dict(record["weights"])

    if len(x_values) != len(candidates):
        violations.append(f"shape:x-count={len(x_values)} expected={len(candidates)}")
    if set(y_values) != set(facts):
        violations.append("shape:y-fact-keys-mismatch")

    for i, value in enumerate(x_values):
        if not math.isfinite(value) or abs(value - round(value)) > tolerance or value < -tolerance or value > 1 + tolerance:
            violations.append(f"integrality:x[{i}]={value}")
    for fact, value in y_values.items():
        if not math.isfinite(value) or abs(value - round(value)) > tolerance or value < -tolerance or value > 1 + tolerance:
            violations.append(f"integrality:y[{fact}]={value}")

    selected = [i for i, value in enumerate(x_values) if value >= 1 - tolerance]
    policy = _policy(record)
    budget = min(int(record["b"]), int(policy["max_moves_per_tick"]))
    if len(selected) > budget:
        violations.append(f"budget-max-moves:selected={len(selected)}>limit={budget}")

    selected_assets = [str(candidates[i].get("key", "")) for i in selected if i < len(candidates)]
    if len(selected_assets) != len(set(selected_assets)):
        violations.append("partition:at-most-one-action-per-asset")

    # Index the coverage edges once.  The old fact-by-candidate scan was O(KN)
    # and dominated end-to-end latency at larger N even though the input itself
    # contains only O(edges) coverage data.
    covered_value = {fact: 0.0 for fact in facts}
    for i, candidate in enumerate(candidates[:len(x_values)]):
        value = float(x_values[i])
        for fact in dict.fromkeys(map(str, candidate.get("cover", []))):
            if fact in covered_value:
                covered_value[fact] += value
    for fact, y_value in y_values.items():
        if y_value > covered_value.get(fact, 0.0) + tolerance:
            violations.append(f"coverage:{fact}:y-exceeds-selected-coverers")

    for i in selected:
        if i < len(candidates):
            violations.extend(candidate_violations(record, candidates[i]))

    selected_ids = {str(candidates[i].get("id", i)) for i in selected if i < len(candidates)}
    for i in selected:
        if i >= len(candidates):
            continue
        incompatible = set(map(str, candidates[i].get("incompatible_with", [])))
        conflict = sorted((incompatible & selected_ids) - {str(candidates[i].get("id", i))})
        if conflict:
            violations.append(f"incompatible:{candidates[i].get('id', i)}:{','.join(conflict)}")

    if math.isfinite(objective):
        recomputed = sum(float(facts[f]) * float(y_values.get(f, 0)) for f in facts)
        recomputed -= float(record["lambda"]) * sum(
            float(candidates[i]["ecost"]) * float(x_values[i])
            for i in range(min(len(candidates), len(x_values)))
        )
        recomputed += sum(
            float(candidates[i].get("future_reward", 0.0)) * float(x_values[i])
            for i in range(min(len(candidates), len(x_values)))
        )
        if abs(recomputed - objective) > tolerance:
            violations.append(f"objective:reported={objective:.12g},recomputed={recomputed:.12g}")
    else:
        violations.append(f"objective:not-finite={objective}")

    elapsed = (time.perf_counter() - started) * 1000
    return CheckResult(not violations, tuple(violations), elapsed)


def accept_or_fallback(status: str, check: CheckResult | None) -> AcceptanceResult:
    """Fail closed unless both solver status and independent checker are valid."""
    if status not in VALID_SOLUTION_STATUSES:
        return AcceptanceResult(False, "no-action", (f"solver-status:{status}",))
    if check is None:
        return AcceptanceResult(False, "no-action", ("checker:not-run",))
    if not check.passed:
        return AcceptanceResult(False, "no-action", check.violations)
    return AcceptanceResult(True, "none", ())
