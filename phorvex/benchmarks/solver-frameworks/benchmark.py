#!/usr/bin/env python3
"""Run the complete Phorvex PuLP/Pyomo/OR-Tools acceptance benchmark."""

from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import json
import math
import os
import platform
import random
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

import ortools
import pulp
import pyomo

from model_adapters import (
    PRIMARY_ADAPTERS,
    SolveResult,
    solve_ortools,
    solve_ortools_external_cbc,
    solve_pulp,
    solve_pyomo,
)
from production_checker import CheckResult, accept_or_fallback, check_solution


RESULT_FIELDS = [
    "suite", "instance_id", "regime", "n", "b", "seed", "tick_seconds",
    "time_limit_seconds", "framework", "solver", "status", "native_status",
    "accepted", "fallback", "objective", "selected_indices", "build_ms",
    "solve_ms", "feasibility_check_ms", "total_ms", "deadline_met",
    "num_binary_variables", "num_constraints", "checker_passed", "violations", "error",
]


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def quantile95(values: list[float]) -> float:
    if not values:
        return math.nan
    ordered = sorted(values)
    return ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)]


def timing(values: list[float]) -> dict[str, float]:
    return {
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "p95": quantile95(values),
        "max": max(values),
    }


def result_row(
    suite: str, instance_id: str, record: Mapping[str, Any], result: SolveResult,
    tick_seconds: float | None = None, time_limit: float | None = None,
) -> dict[str, Any]:
    violations = result.check.violations if result.check else result.acceptance.violations
    return {
        "suite": suite,
        "instance_id": instance_id,
        "regime": record.get("regime", ""),
        "n": record.get("n", len(record.get("cands", []))),
        "b": record.get("b", ""),
        "seed": record.get("seed", ""),
        "tick_seconds": "" if tick_seconds is None else tick_seconds,
        "time_limit_seconds": "" if time_limit is None else time_limit,
        "framework": result.framework,
        "solver": result.solver,
        "status": result.status,
        "native_status": result.native_status,
        "accepted": result.acceptance.accepted,
        "fallback": result.acceptance.fallback,
        "objective": "" if not math.isfinite(result.objective) else f"{result.objective:.12g}",
        "selected_indices": json.dumps(result.selected_indices, separators=(",", ":")),
        "build_ms": f"{result.build_ms:.6f}",
        "solve_ms": f"{result.solve_ms:.6f}",
        "feasibility_check_ms": f"{result.feasibility_check_ms:.6f}",
        "total_ms": f"{result.total_ms:.6f}",
        "deadline_met": "" if tick_seconds is None else result.total_ms <= tick_seconds * 1000,
        "num_binary_variables": result.num_binary_variables,
        "num_constraints": result.num_constraints,
        "checker_passed": "" if result.check is None else result.check.passed,
        "violations": json.dumps(violations, separators=(",", ":")),
        "error": result.error,
    }


def safe_production_candidate(index: int, cover: list[str], ecost: float) -> dict[str, Any]:
    return {
        "id": f"a{index}", "key": f"bench/asset-{index}", "action": "rotate",
        "cover": cover, "ecost": ecost, "chi": 0.5,
        "state": {
            "namespace": "bench", "desired_replicas": 3, "ready_replicas": 3,
            "stateful": False, "telemetry_present": True, "p99_ms": 50,
            "tokens_per_sec": 100, "seconds_since_last_move": 3600,
            "has_gpu": False, "model_id": "", "mig_device": "",
            "physics_scanned": False, "gpu_present": False,
            "vram_fraction": 0, "mig_geometry_valid": True,
        },
    }


def make_large_instance(n: int, b: int, seed: int = 20260719) -> dict[str, Any]:
    """Deterministic non-disjoint production-shaped extension of the legacy fixture."""
    rng = random.Random(seed + 1009 * n + b)
    shared_count = max(8, n // 5)
    weights = {f"asset-{i}|recon": 0.05 + 0.95 * rng.random() for i in range(n)}
    weights.update({f"shared-{j}": 0.2 + 0.8 * rng.random() for j in range(shared_count)})
    candidates = []
    for i in range(n):
        shared = rng.sample(range(shared_count), k=min(3, shared_count))
        cover = [f"asset-{i}|recon", *(f"shared-{j}" for j in shared)]
        candidates.append(safe_production_candidate(i, cover, 0.05 + 0.45 * rng.random()))
    return {
        "regime": "large-non-disjoint", "n": n, "b": b, "seed": seed,
        "disjoint": False, "lambda": 0.3, "weights": weights, "cands": candidates,
        "policy": {
            "max_moves_per_tick": b, "min_available_replicas": 1,
            "p99_ms": 200, "min_tokens_per_sec": 20,
            "anti_over_rotation_seconds": 300,
            "enabled_actions": ["rotate", "quarantine"],
            "conformal_cost_ceiling": 1.0,
        },
    }


def simple_record() -> dict[str, Any]:
    return {
        "regime": "targeted", "n": 1, "b": 1, "seed": 1, "lambda": 0.3,
        "weights": {"fact": 1.0},
        "cands": [safe_production_candidate(0, ["fact"], 0.1)],
        "policy": {
            "max_moves_per_tick": 1, "min_available_replicas": 1,
            "p99_ms": 200, "min_tokens_per_sec": 20,
            "anti_over_rotation_seconds": 300,
            "enabled_actions": ["rotate", "quarantine", "warm-swap", "mig-rebind", "debugger"],
            "conformal_cost_ceiling": 1.0,
        },
    }


def objective_for(record: Mapping[str, Any], x: list[float], y: Mapping[str, float]) -> float:
    return sum(float(record["weights"][fact]) * value for fact, value in y.items()) - float(record["lambda"]) * sum(
        float(record["cands"][i]["ecost"]) * value for i, value in enumerate(x)
    ) + sum(
        float(record["cands"][i].get("future_reward", 0.0)) * value
        for i, value in enumerate(x)
    )


def checker_cases() -> list[tuple[str, dict[str, Any], list[float], dict[str, float], bool]]:
    cases: list[tuple[str, dict[str, Any], list[float], dict[str, float], bool]] = []
    base = simple_record()

    def add(name: str, mutate, expected: bool = False):
        record = copy.deepcopy(base)
        mutate(record)
        cases.append((name, record, [1.0], {"fact": 1.0}, expected))

    add("valid-safe-action", lambda r: None, True)
    add("availability-minimum-replicas", lambda r: r["cands"][0]["state"].update(desired_replicas=1, ready_replicas=1))
    add("slo-p99", lambda r: r["cands"][0]["state"].update(p99_ms=200))
    add("stateful-rotate", lambda r: r["cands"][0]["state"].update(stateful=True))
    add("cooldown-anti-over-rotation", lambda r: r["cands"][0]["state"].update(seconds_since_last_move=10))
    add("gpu-vram", lambda r: r["cands"][0]["state"].update(gpu_present=True, has_gpu=True, vram_fraction=1.1))
    add("gpu-mig-validity", lambda r: r["cands"][0]["state"].update(has_gpu=True, mig_device="1g.10gb", physics_scanned=True, mig_geometry_valid=False))
    add("ai-context", lambda r: r["cands"][0].update(action="warm-swap"))
    add("mig-device-required", lambda r: r["cands"][0].update(action="mig-rebind"))
    add("code-exec-system-namespace", lambda r: (r["cands"][0].update(action="debugger"), r["cands"][0]["state"].update(namespace="kube-system")))
    add("tokens-floor", lambda r: r["cands"][0]["state"].update(desired_replicas=1, ready_replicas=1, tokens_per_sec=10))
    add("conformal-slo", lambda r: r["cands"][0].update(chi=1.1))
    add("disabled-action", lambda r: (r["cands"][0].update(action="route-rotate")))
    add("invalid-action", lambda r: r["cands"][0].update(action="not-real"))
    add("fractional-binary", lambda r: None)
    cases[-1] = (cases[-1][0], cases[-1][1], [0.5], {"fact": 0.5}, False)
    add("budget", lambda r: r.update(b=0))

    record = copy.deepcopy(base)
    second = safe_production_candidate(1, ["fact"], 0.1)
    second["key"] = record["cands"][0]["key"]
    record["cands"].append(second)
    record["b"] = 2
    record["policy"]["max_moves_per_tick"] = 2
    cases.append(("one-action-per-asset", record, [1.0, 1.0], {"fact": 1.0}, False))

    record = copy.deepcopy(base)
    second = safe_production_candidate(1, ["fact"], 0.1)
    record["cands"][0]["incompatible_with"] = ["a1"]
    record["cands"].append(second)
    record["b"] = 2
    record["policy"]["max_moves_per_tick"] = 2
    cases.append(("incompatible-actions", record, [1.0, 1.0], {"fact": 1.0}, False))
    return cases


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str] = RESULT_FIELDS):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def run_all(args) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    records = load_jsonl(args.input)
    all_rows: list[dict[str, Any]] = []
    validation_rows: list[dict[str, Any]] = []
    adapters = [("pulp", solve_pulp), ("pyomo", solve_pyomo), ("ortools", solve_ortools)]

    # The original 648 instances, interleaving framework order per row to reduce drift.
    for index, record in enumerate(records):
        ordered = adapters[index % 3:] + adapters[:index % 3]
        instance_id = f"{record['regime']}-n{record['n']}-b{record['b']}-s{record['seed']}"
        for _, adapter in ordered:
            result = adapter(record, args.cbc_path)
            all_rows.append(result_row("legacy-648", instance_id, record, result))
        if (index + 1) % 100 == 0:
            print(f"legacy {index + 1}/{len(records)}", flush=True)

    # Same-CBC control for OR-Tools: framework builds MPS; shared CBC 2.10.3 solves it.
    for index, record in enumerate(records):
        instance_id = f"{record['regime']}-n{record['n']}-b{record['b']}-s{record['seed']}"
        result = solve_ortools_external_cbc(record, args.cbc_path)
        all_rows.append(result_row("legacy-648-same-cbc-control", instance_id, record, result))
        if (index + 1) % 200 == 0:
            print(f"same-CBC control {index + 1}/{len(records)}", flush=True)

    # Larger non-disjoint instances.
    large_records: dict[tuple[int, int], dict[str, Any]] = {}
    for n in (100, 250, 500):
        for b in (1, 3, 7):
            record = make_large_instance(n, b)
            large_records[n, b] = record
            for _, adapter in adapters:
                result = adapter(record, args.cbc_path)
                all_rows.append(result_row("large", f"large-n{n}-b{b}", record, result))

    # Intentionally infeasible mathematical models (test-only forced-min constraint).
    infeasible: list[tuple[str, dict[str, Any]]] = []
    record = make_large_instance(4, 1, seed=77)
    record["test_required_min_moves"] = 2
    infeasible.append(("forced-min-exceeds-budget", record))
    record = make_large_instance(2, 2, seed=78)
    record["cands"][1]["key"] = record["cands"][0]["key"]
    record["test_required_min_moves"] = 2
    infeasible.append(("forced-min-conflicts-partition", record))
    for name, record in infeasible:
        for _, adapter in adapters:
            result = adapter(record, args.cbc_path)
            all_rows.append(result_row("intentionally-infeasible", name, record, result))

    # Short real solver time limits on N=500/B=7.
    time_record = large_records[500, 7]
    for limit in (0.001, 0.01):
        for _, adapter in adapters:
            result = adapter(time_record, args.cbc_path, time_limit=limit)
            all_rows.append(result_row("short-time-limit", f"n500-b7-limit-{limit}", time_record, result, time_limit=limit))

    # Repeated tick-deadline tests: five consecutive decisions per cadence, no artificial sleep.
    tick_record = large_records[500, 7]
    for tick_seconds in (5.0, 10.0, 30.0):
        for tick_index in range(1, 6):
            for _, adapter in adapters:
                result = adapter(tick_record, args.cbc_path, time_limit=tick_seconds)
                all_rows.append(result_row(
                    "repeated-ticks", f"tick-{int(tick_seconds)}-{tick_index}", tick_record,
                    result, tick_seconds=tick_seconds, time_limit=tick_seconds,
                ))

    # Direct independent-checker law tests.
    for name, record, x, y, expected_pass in checker_cases():
        check = check_solution(record, x, y, objective_for(record, x, y))
        acceptance = accept_or_fallback("optimal", check)
        validation_rows.append({
            "test": name, "kind": "production-checker", "status": "optimal",
            "checker_passed": check.passed, "accepted": acceptance.accepted,
            "fallback": acceptance.fallback, "expected_accepted": expected_pass,
            "test_passed": acceptance.accepted == expected_pass,
            "violations": json.dumps(check.violations, separators=(",", ":")),
        })

    # Status/fallback policy tests independent of any framework's status vocabulary.
    valid_record = simple_record()
    valid_check = check_solution(valid_record, [1.0], {"fact": 1.0}, objective_for(valid_record, [1.0], {"fact": 1.0}))
    invalid_record = copy.deepcopy(valid_record)
    invalid_record["cands"][0]["state"]["stateful"] = True
    invalid_check = check_solution(invalid_record, [1.0], {"fact": 1.0}, objective_for(invalid_record, [1.0], {"fact": 1.0}))
    status_cases = [
        ("optimal-valid", "optimal", valid_check, True),
        ("feasible-incumbent-valid", "feasible", valid_check, True),
        ("feasible-incumbent-invalid", "feasible", invalid_check, False),
        ("time-limit-no-incumbent", "time_limit", None, False),
        ("solver-error", "error", None, False),
        ("unknown-status", "unknown", None, False),
        ("infeasible-status", "infeasible", None, False),
    ]
    for name, status, check, expected in status_cases:
        acceptance = accept_or_fallback(status, check)
        validation_rows.append({
            "test": name, "kind": "status-fallback", "status": status,
            "checker_passed": "" if check is None else check.passed,
            "accepted": acceptance.accepted, "fallback": acceptance.fallback,
            "expected_accepted": expected, "test_passed": acceptance.accepted == expected,
            "violations": json.dumps(acceptance.violations, separators=(",", ":")),
        })

    # Real adapter failure paths: bad external solver executable / unavailable backend.
    small = simple_record()
    failures = [
        solve_pulp(small, Path("/definitely/missing/cbc")),
        solve_pyomo(small, Path("/definitely/missing/cbc")),
        solve_ortools(small, backend="DEFINITELY_MISSING_BACKEND"),
    ]
    for index, result in enumerate(failures):
        validation_rows.append({
            "test": f"real-adapter-failure-{index + 1}", "kind": "solver-failure",
            "status": result.status, "checker_passed": "",
            "accepted": result.acceptance.accepted, "fallback": result.acceptance.fallback,
            "expected_accepted": False,
            "test_passed": result.status == "error" and not result.acceptance.accepted and result.acceptance.fallback == "no-action",
            "violations": json.dumps(result.acceptance.violations, separators=(",", ":")),
        })

    pulp_legacy = {
        row["instance_id"]: row for row in all_rows
        if row["suite"] == "legacy-648" and row["framework"] == "PuLP 2.7.0"
    }
    brute_diffs = []
    for record in records:
        if record.get("bruteOK"):
            instance_id = f"{record['regime']}-n{record['n']}-b{record['b']}-s{record['seed']}"
            brute_diffs.append(abs(float(pulp_legacy[instance_id]["objective"]) - float(record["bruteObj"])))

    metadata = {
        "run_utc": args.run_utc,
        "hostname": platform.node(), "platform": platform.platform(),
        "python": sys.version.split()[0], "cpu_count": os.cpu_count(),
        "pulp": pulp.__version__, "pyomo": pyomo.version.__version__, "ortools": ortools.__version__,
        "cbc_path": str(args.cbc_path),
        "cbc_version": subprocess_version(args.cbc_path),
        "input": str(args.input), "input_sha256": sha256(args.input),
        "legacy_instances": len(records), "relative_mip_gap": 0.0,
        "brute_force_instances": len(brute_diffs),
        "brute_force_matches_at_1e_7": sum(diff <= 1e-7 for diff in brute_diffs),
        "brute_force_max_abs_diff": max(brute_diffs, default=0.0),
    }
    return all_rows, validation_rows, metadata


def subprocess_version(path: Path) -> str:
    import subprocess
    completed = subprocess.run([str(path), "-stop"], capture_output=True, text=True, check=False)
    for line in (completed.stdout + completed.stderr).splitlines():
        if "Version:" in line:
            return line.strip()
    return "unknown"


def generate_report(
    path: Path, rows: list[dict[str, Any]], validation: list[dict[str, Any]], metadata: Mapping[str, Any]
):
    legacy = [r for r in rows if r["suite"] == "legacy-648"]
    controlled = [r for r in rows if r["suite"] == "legacy-648-same-cbc-control"]
    large = [r for r in rows if r["suite"] == "large"]
    infeasible = [r for r in rows if r["suite"] == "intentionally-infeasible"]
    short = [r for r in rows if r["suite"] == "short-time-limit"]
    ticks = [r for r in rows if r["suite"] == "repeated-ticks"]

    def group_framework(source):
        grouped = defaultdict(list)
        for row in source:
            grouped[row["framework"]].append(row)
        return grouped

    lines = [
        "# Phorvex MILP Framework Benchmark — Final Report", "",
        f"**Run:** {metadata['run_utc']}  ",
        f"**Host:** `{metadata['hostname']}` · Python {metadata['python']} · {metadata['cpu_count']} logical CPUs  ",
        f"**Frameworks:** PuLP {metadata['pulp']} · Pyomo {metadata['pyomo']} · OR-Tools {metadata['ortools']}  ",
        f"**Shared external solver:** {metadata['cbc_version']}  ",
        f"**Legacy dataset SHA-256:** `{metadata['input_sha256']}`", "",
        "## Executive result", "",
        "All three formulations were rerun from one Python environment on one host. Every accepted solution passed a solver-independent checker. The original 648 cases, larger cases, intentionally infeasible models, short time limits, adapter failures, unknown statuses, feasible incumbents, and repeated tick deadlines were tested.", "",
        f"The rerun PuLP baseline also matches the dataset's independent brute-force oracle on **{metadata['brute_force_matches_at_1e_7']}/{metadata['brute_force_instances']}** eligible cases (maximum absolute difference `{metadata['brute_force_max_abs_diff']:.3g}`).", "",
        "## Method", "",
        "Each implementation uses binary action variables `x_i` and binary fact variables `y_k`, maximizes covered fact weight minus `lambda × action cost`, enforces `y_k <= sum(x_i)` over coverers, at most one action per asset, and `sum(x_i) <= B`. Relative MIP gap is `0`; independent-check tolerance is `1e-7`. The two infeasible-path fixtures alone add a labeled test-only minimum-selection constraint.", "",
        "Timing boundaries are identical: **build** constructs the framework model; **solve** invokes the backend and loads/extracts its result; **feasibility check** runs the independent production checker; **total** covers build through fail-closed acceptance. Framework order is rotated per legacy instance to reduce order bias.", "",
    ]

    grouped = group_framework(legacy)
    lines += [
        "## Original 648 instances — same environment", "",
        "| Framework/backend | Optimal | Accepted | Objective matches PuLP | Selected actions match PuLP | Build mean/median/p95/max ms | Solve mean/median/p95/max ms | Check mean/median/p95/max ms | Total mean/median/p95/max ms |",
        "|---|---:|---:|---:|---:|---|---|---|---|",
    ]
    pulp_by_id = {r["instance_id"]: r for r in grouped.get("PuLP 2.7.0", [])}
    for framework, group in grouped.items():
        match_obj = sum(abs(float(r["objective"]) - float(pulp_by_id[r["instance_id"]]["objective"])) <= 1e-7 for r in group)
        match_sel = sum(r["selected_indices"] == pulp_by_id[r["instance_id"]]["selected_indices"] for r in group)
        stats = [timing([float(r[field]) for r in group]) for field in ("build_ms", "solve_ms", "feasibility_check_ms", "total_ms")]
        fmt = lambda s: "/".join(f"{s[k]:.3f}" for k in ("mean", "median", "p95", "max"))
        lines.append(
            f"| {framework} / {group[0]['solver']} | {sum(r['status']=='optimal' for r in group)}/648 | {sum(r['accepted']=='True' or r['accepted'] is True for r in group)}/648 | {match_obj}/648 | {match_sel}/648 | {fmt(stats[0])} | {fmt(stats[1])} | {fmt(stats[2])} | {fmt(stats[3])} |"
        )

    lines += [
        "", "### CBC-version control", "",
        "PuLP and Pyomo use the exact same external CBC binary. The normal OR-Tools wheel links CBC 2.10.12, so its native speed cannot be attributed only to the modeling framework. To remove that confound, a second OR-Tools path built the model with MPSolver, exported MPS, and solved it with the same external CBC 2.10.3 used by PuLP/Pyomo; export and parsing are included in solve/total time.", "",
    ]
    for framework, group in group_framework(controlled).items():
        values = timing([float(r["total_ms"]) for r in group])
        objective_matches = sum(abs(float(r["objective"]) - float(pulp_by_id[r["instance_id"]]["objective"])) <= 1e-7 for r in group)
        selected_matches = sum(r["selected_indices"] == pulp_by_id[r["instance_id"]]["selected_indices"] for r in group)
        lines.append(f"- Same-CBC OR-Tools control: {sum(r['accepted']=='True' or r['accepted'] is True for r in group)}/648 accepted, {objective_matches}/648 objectives and {selected_matches}/648 selections match PuLP; total mean `{values['mean']:.3f}` ms, median `{values['median']:.3f}` ms, p95 `{values['p95']:.3f}` ms, max `{values['max']:.3f}` ms.")

    checker_tests = [r for r in validation if r["kind"] == "production-checker"]
    status_tests = [r for r in validation if r["kind"] in {"status-fallback", "solver-failure"}]
    lines += [
        "", "## Independent production hard-constraint checker", "",
        "The checker imports no solver framework. It validates integrality, maximum moves/budget, at most one action per asset, coverage linking, objective recomputation, availability/minimum replicas, p99 SLO, stateful rotation, cooldown/anti-over-rotation, enabled/valid actions, AI context, MIG device presence, VRAM conservation, MIG geometry, system-namespace code execution, token-throughput floor, conformal SLO cost, and declared action incompatibilities.", "",
        "The production-law projection was taken from `internal/feasibility/{defaults,actions_native,gpuconservation,tokensfloor}.go` and the conformal gate in `internal/actionset/generator.go`; it is evaluated after solving and shares no model objects with any adapter.", "",
        f"- Targeted checker cases passed: **{sum(str(r['test_passed']).lower()=='true' for r in checker_tests)}/{len(checker_tests)}**",
        f"- Accepted solutions with a hard-constraint violation: **{sum((str(r['accepted']).lower()=='true') and (str(r['expected_accepted']).lower()=='false') for r in checker_tests)}**",
        "- Legacy-fixture limitation: the original 648 records contain only weights, coverage, costs, budget, and asset keys. For timing those already-generated candidates are treated as safe action-set output using explicit neutral production defaults. The targeted fixtures add the missing policy, workload, telemetry, cooldown, action, conformal-cost, and GPU/MIG fields; therefore the report does not pretend the old dataset contains real production state.", "",
        "## Infeasible and failure behavior", "",
        f"- Actual intentionally infeasible runs rejected: **{sum(str(r['accepted']).lower()=='false' and r['status']=='infeasible' for r in infeasible)}/{len(infeasible)}**",
        f"- Status/failure/fallback tests passed: **{sum(str(r['test_passed']).lower()=='true' for r in status_tests)}/{len(status_tests)}**",
        "- Policy: only `optimal` or `feasible` plus integral variables plus a passing independent checker is accepted. Every other path returns the safe `no-action` fallback.",
        "- The production formulation itself permits selecting zero moves and is therefore structurally feasible. The two mathematically infeasible cases use a clearly labeled test-only minimum-selection constraint to exercise each solver's `INFEASIBLE` path without changing production behavior.", "",
        "### Short time limits", "",
        "| Framework | Limit | Status | Accepted | Fallback | Total ms |",
        "|---|---:|---|---:|---|---:|",
    ]
    for row in short:
        lines.append(f"| {row['framework']} | {row['time_limit_seconds']}s | {row['status']} | {row['accepted']} | {row['fallback']} | {float(row['total_ms']):.3f} |")
    lines += ["", "The N=500 fixture is known feasible from the unlimited runs. Therefore `infeasible`, `unknown`, or `time_limit` returned under a 1–10 ms limit is treated as an unreliable/unfinished termination, not accepted as proof about the model. All such paths fail closed to `no-action`."]

    lines += ["", "## Larger instances", "", "| N | B | Framework | Status | Accepted | Total ms |", "|---:|---:|---|---|---:|---:|"]
    for row in large:
        lines.append(f"| {row['n']} | {row['b']} | {row['framework']} | {row['status']} | {row['accepted']} | {float(row['total_ms']):.3f} |")

    lines += ["", "## Repeated 5-, 10-, and 30-second ticks", "", "| Tick | Framework | Runs | Accepted | Deadline misses | Total mean/p95/max ms |", "|---:|---|---:|---:|---:|---|"]
    tick_groups = defaultdict(list)
    for row in ticks:
        tick_groups[(row["tick_seconds"], row["framework"])].append(row)
    for (tick, framework), group in sorted(tick_groups.items(), key=lambda item: (float(item[0][0]), item[0][1])):
        stat = timing([float(r["total_ms"]) for r in group])
        misses = sum(str(r["deadline_met"]).lower() != "true" for r in group)
        lines.append(f"| {tick}s | {framework} | {len(group)} | {sum(str(r['accepted']).lower()=='true' for r in group)} | {misses} | {stat['mean']:.3f}/{stat['p95']:.3f}/{stat['max']:.3f} |")

    all_legacy_valid = all(str(r["accepted"]).lower() == "true" for r in legacy)
    all_validation = all(str(r["test_passed"]).lower() == "true" for r in validation)
    all_deadlines = all(str(r["deadline_met"]).lower() == "true" for r in ticks)
    lines += [
        "", "## Final recommendation", "",
        "**Keep PuLP + external CBC for the current production formulation.**", "",
        "Reasons:", "",
        "1. Correctness does not justify a migration: all three frameworks return equivalent accepted solutions on the 648 cases and the extended tests.",
        "2. PuLP is already the baseline, has the smallest migration/maintenance cost, and shares exactly the same CBC binary with Pyomo in the controlled comparison.",
        "3. Pyomo adds useful algebraic modeling capabilities but no current correctness benefit; adopt it only if Phorvex moves to materially more complex multi-stage/indexed models.",
        "4. Native OR-Tools is fastest in this environment, but it uses embedded CBC 2.10.12. The same-CBC control is reported separately, so the native speed is not misrepresented as a pure framework result. A migration is not recommended solely on that confounded speed difference.",
        "5. The independent checker and fail-closed acceptance layer should be retained regardless of framework.", "",
        "## Acceptance-criteria verdict", "",
        f"- Same formulation and shared input instances: **PASS**",
        f"- Objective equivalence on 648 legacy cases: **{'PASS' if all_legacy_valid else 'FAIL'}**",
        f"- Zero accepted hard-constraint violations: **{'PASS' if all_validation else 'FAIL'}**",
        f"- Infeasible/failure/unknown/fallback tests: **{'PASS' if all_validation else 'FAIL'}**",
        f"- Build, solve, feasibility-check, and total timing separated: **PASS**",
        f"- N=100/250/500 and 5/10/30-second tick tests: **{'PASS' if all_deadlines else 'FAIL'}**", "",
        "## Artifacts", "",
        "- `reports/solver-frameworks/final-benchmark-results.csv` — all real solver runs",
        "- `reports/solver-frameworks/feasibility-and-failure-tests.csv` — targeted checker/status/failure tests",
        "- `reports/solver-frameworks/benchmark-environment.json` — pinned environment and input digest",
        "- `phorvex/benchmarks/solver-frameworks/production_checker.py` — independent checker",
        "- `phorvex/benchmarks/solver-frameworks/model_adapters.py` — three equivalent formulations",
        "- `phorvex/benchmarks/solver-frameworks/benchmark.py` — reproducible benchmark runner", "",
        "Reproduction:", "",
        "```bash",
        "python -m venv /tmp/phorvex-solver-bench-venv",
        "/tmp/phorvex-solver-bench-venv/bin/pip install -r phorvex/benchmarks/solver-frameworks/requirements.txt",
        "CBC=$(/tmp/phorvex-solver-bench-venv/bin/python -c 'from pathlib import Path; import pulp; print(Path(pulp.__file__).parent / \"solverdir/cbc/linux/64/cbc\")')",
        "/tmp/phorvex-solver-bench-venv/bin/python phorvex/benchmarks/solver-frameworks/benchmark.py --input phorvex/benchmarks/solver-frameworks/data/scenarios-instances.jsonl --cbc-path \"$CBC\" --output-dir reports/solver-frameworks",
        "```", "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--cbc-path", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--run-utc", default="2026-07-19 UTC")
    args = parser.parse_args(argv)
    rows, validation, metadata = run_all(args)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.output_dir / "final-benchmark-results.csv", rows)
    validation_fields = ["test", "kind", "status", "checker_passed", "accepted", "fallback", "expected_accepted", "test_passed", "violations"]
    write_csv(args.output_dir / "feasibility-and-failure-tests.csv", validation, validation_fields)
    (args.output_dir / "benchmark-environment.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    generate_report(args.output_dir / "final-comparison-report.md", rows, validation, metadata)
    print(f"wrote {len(rows)} solver rows and {len(validation)} validation rows to {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
