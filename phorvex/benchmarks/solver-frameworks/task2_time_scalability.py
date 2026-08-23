#!/usr/bin/env python3
"""Task 2: PuLP/CBC time-budget and scalability benchmark.

Each recorded solve runs in a fresh worker process.  This keeps peak-RSS
measurements independent and prevents framework/allocator state from leaking from
one problem size into the next.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import platform
import random
import re
import resource
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Mapping


FIELDS = [
    "environment", "hostname", "platform", "python", "cpu_count", "framework",
    "solver", "cbc_version", "instance_id", "n", "b", "seed",
    "time_limit_seconds", "status", "native_status", "accepted", "fallback",
    "objective", "reference_objective", "best_bound", "solver_gap_percent",
    "reference_gap_percent", "selected_count", "checker_passed", "violations",
    "build_ms", "solve_ms", "feasibility_check_ms", "total_ms",
    "solver_limit_met", "end_to_end_limit_met", "python_peak_rss_mb",
    "cbc_peak_rss_mb", "combined_peak_rss_mb", "num_binary_variables",
    "num_constraints", "error",
]


def safe_production_candidate(index: int, cover: list[str], ecost: float) -> dict[str, Any]:
    """Use the same safe, explicit production defaults as the shared benchmark."""
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


def make_large_instance(n: int, b: int, seed: int) -> dict[str, Any]:
    """Deterministic non-disjoint fixture, identical to benchmark.make_large_instance."""
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


def cbc_version(path: Path) -> str:
    completed = subprocess.run([str(path), "-stop"], capture_output=True, text=True, check=False)
    for line in (completed.stdout + completed.stderr).splitlines():
        if "Version:" in line:
            return line.strip().replace("Version:", "").strip()
    return "unknown"


def parse_cbc_log(path: Path, status: str, objective: float) -> tuple[float, float]:
    """Return CBC's best bound and relative gap when the log exposes them."""
    text = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    bound_match = re.search(r"^Upper bound:\s*([-+0-9.eE]+)", text, re.MULTILINE)
    bound = float(bound_match.group(1)) if bound_match else math.nan
    if status == "optimal" and math.isfinite(objective):
        return objective, 0.0
    if math.isfinite(bound) and math.isfinite(objective):
        gap = max(0.0, bound - objective) / max(abs(objective), 1e-12) * 100.0
        return bound, gap
    return bound, math.nan


def rss_mb(who: int) -> float:
    # Linux reports ru_maxrss in KiB.
    return resource.getrusage(who).ru_maxrss / 1024.0


def solve_worker(record: Mapping[str, Any], cbc_path: Path, time_limit: float | None) -> dict[str, Any]:
    import pulp

    from production_checker import accept_or_fallback, check_solution

    total_started = time.perf_counter()
    build_ms = solve_ms = check_ms = 0.0
    status = "error"
    native_status = "exception"
    objective = best_bound = solver_gap = math.nan
    selected_count = 0
    checker_passed: bool | str = ""
    violations: tuple[str, ...] = ()
    fallback = "no-action"
    accepted = False
    error = ""
    candidates = list(record["cands"])
    facts = list(record["weights"])
    indices = list(range(len(candidates)))
    coverers: dict[str, list[int]] = {fact: [] for fact in facts}
    by_asset: dict[str, list[int]] = {}
    for i, candidate in enumerate(candidates):
        by_asset.setdefault(str(candidate["key"]), []).append(i)
        for fact in candidate.get("cover", []):
            coverers[fact].append(i)
    constraint_count = len(facts) + sum(len(v) > 1 for v in by_asset.values()) + 1

    try:
        build_started = time.perf_counter()
        problem = pulp.LpProblem("phorvex_task2_coverage", pulp.LpMaximize)
        x = [pulp.LpVariable(f"x_{i:06d}", cat="Binary") for i in indices]
        y = {fact: pulp.LpVariable(f"y_{j:06d}", cat="Binary") for j, fact in enumerate(facts)}
        problem += (
            pulp.lpSum(float(record["weights"][fact]) * y[fact] for fact in facts)
            - float(record["lambda"])
            * pulp.lpSum(float(candidates[i]["ecost"]) * x[i] for i in indices)
        )
        for fact in facts:
            problem += y[fact] <= pulp.lpSum(x[i] for i in coverers[fact])
        for asset_indices in by_asset.values():
            if len(asset_indices) > 1:
                problem += pulp.lpSum(x[i] for i in asset_indices) <= 1
        problem += pulp.lpSum(x) <= int(record["b"])
        build_ms = (time.perf_counter() - build_started) * 1000

        with tempfile.TemporaryDirectory(prefix="phorvex-task2-cbc-") as directory:
            log_path = Path(directory) / "cbc.log"
            solver = pulp.COIN_CMD(
                path=str(cbc_path), msg=False, gapRel=0.0,
                timeLimit=time_limit, logPath=str(log_path), threads=1,
            )
            solve_started = time.perf_counter()
            problem.solve(solver)
            solve_ms = (time.perf_counter() - solve_started) * 1000

            native_status = (
                f"{pulp.LpStatus.get(problem.status, problem.status)}/"
                f"{pulp.LpSolution.get(problem.sol_status, problem.sol_status)}"
            )
            if problem.status == pulp.LpStatusOptimal and problem.sol_status == pulp.LpSolutionOptimal:
                status = "optimal"
            elif problem.sol_status == pulp.LpSolutionIntegerFeasible:
                status = "feasible"
            elif problem.status == pulp.LpStatusInfeasible:
                status = "infeasible"
            elif problem.status == pulp.LpStatusUnbounded:
                status = "unbounded"
            elif problem.status == pulp.LpStatusNotSolved and time_limit is not None:
                status = "time_limit"
            else:
                status = "unknown"

            has_solution = status in {"optimal", "feasible"}
            if has_solution:
                x_values = [float(pulp.value(variable)) for variable in x]
                y_values = {fact: float(pulp.value(y[fact])) for fact in facts}
                objective = float(pulp.value(problem.objective))
                selected_count = sum(value >= 1 - 1e-7 for value in x_values)
                check = check_solution(record, x_values, y_values, objective, 1e-7)
                check_ms = check.check_ms
                checker_passed = check.passed
                acceptance = accept_or_fallback(status, check)
            else:
                acceptance = accept_or_fallback(status, None)
            accepted = acceptance.accepted
            fallback = acceptance.fallback
            violations = acceptance.violations
            best_bound, solver_gap = parse_cbc_log(log_path, status, objective)
    except Exception as exc:  # fail closed and preserve the raw error in the CSV
        error = f"{type(exc).__name__}: {exc}"
        status = "error"
        violations = ("solver-status:error",)

    total_ms = (time.perf_counter() - total_started) * 1000
    python_rss = rss_mb(resource.RUSAGE_SELF)
    cbc_rss = rss_mb(resource.RUSAGE_CHILDREN)
    limit_ms = math.inf if time_limit is None else time_limit * 1000
    return {
        "framework": f"PuLP {pulp.__version__}",
        "solver": "CBC external", "cbc_version": cbc_version(cbc_path),
        "status": status, "native_status": native_status,
        "accepted": accepted, "fallback": fallback,
        "objective": objective, "best_bound": best_bound,
        "solver_gap_percent": solver_gap, "selected_count": selected_count,
        "checker_passed": checker_passed,
        "violations": json.dumps(violations, separators=(",", ":")),
        "build_ms": build_ms, "solve_ms": solve_ms,
        "feasibility_check_ms": check_ms, "total_ms": total_ms,
        "solver_limit_met": "" if time_limit is None else solve_ms <= limit_ms,
        "end_to_end_limit_met": "" if time_limit is None else total_ms <= limit_ms,
        "python_peak_rss_mb": python_rss, "cbc_peak_rss_mb": cbc_rss,
        "combined_peak_rss_mb": python_rss + cbc_rss,
        "num_binary_variables": len(candidates) + len(facts),
        "num_constraints": constraint_count, "error": error,
    }


def json_number(value: Any) -> Any:
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def worker_main(args: argparse.Namespace) -> int:
    record = json.loads(Path(args.instance).read_text(encoding="utf-8"))
    limit = None if args.time_limit == "unlimited" else float(args.time_limit)
    result = solve_worker(record, Path(args.cbc_path), limit)
    print(json.dumps({key: json_number(value) for key, value in result.items()}, separators=(",", ":")))
    return 0


def parse_ints(value: str) -> list[int]:
    return [int(item) for item in value.split(",") if item]


def run_child(script: Path, instance: Path, cbc_path: Path, limit: str) -> dict[str, Any]:
    completed = subprocess.run(
        [sys.executable, str(script), "worker", "--instance", str(instance),
         "--cbc-path", str(cbc_path), "--time-limit", limit],
        capture_output=True, text=True, check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"worker exit {completed.returncode}: {completed.stderr[-1000:]}")
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    return json.loads(lines[-1])


def csv_value(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, float):
        return f"{value:.9f}"
    return value


def run_main(args: argparse.Namespace) -> int:
    script = Path(__file__).resolve()
    cbc_path = Path(args.cbc_path).resolve()
    sizes = parse_ints(args.sizes)
    seeds = parse_ints(args.seeds)
    rows: list[dict[str, Any]] = []
    references: dict[tuple[int, int], float] = {}
    run_modes = ["unlimited", "0.001", "0.1"]

    with tempfile.TemporaryDirectory(prefix="phorvex-task2-instances-") as directory:
        base = Path(directory)
        total = len(sizes) * len(seeds) * len(run_modes)
        completed_count = 0
        for n in sizes:
            for seed in seeds:
                record = make_large_instance(n, args.budget, seed)
                instance = base / f"n{n}-b{args.budget}-s{seed}.json"
                instance.write_text(json.dumps(record, separators=(",", ":")), encoding="utf-8")
                for limit in run_modes:
                    result = run_child(script, instance, cbc_path, limit)
                    if limit == "unlimited" and result["accepted"]:
                        references[n, seed] = float(result["objective"])
                    reference = references.get((n, seed))
                    objective = result.get("objective")
                    reference_gap = None
                    if reference is not None and objective is not None and result["accepted"]:
                        reference_gap = max(0.0, reference - float(objective)) / max(abs(reference), 1e-12) * 100
                    row = {
                        "environment": args.environment, "hostname": platform.node(),
                        "platform": platform.platform(), "python": platform.python_version(),
                        "cpu_count": os.cpu_count(), "instance_id": instance.stem,
                        "n": n, "b": args.budget, "seed": seed,
                        "time_limit_seconds": "" if limit == "unlimited" else limit,
                        "reference_objective": reference,
                        "reference_gap_percent": reference_gap,
                        **result,
                    }
                    rows.append({key: csv_value(row.get(key, "")) for key in FIELDS})
                    completed_count += 1
                    print(
                        f"{completed_count}/{total} env={args.environment} n={n} seed={seed} "
                        f"limit={limit} status={result['status']} accepted={result['accepted']} "
                        f"total_ms={result['total_ms']:.3f}",
                        flush=True,
                    )

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {len(rows)} rows -> {output}")
    return 0


def self_test_main() -> int:
    first = make_large_instance(20, 7, 123)
    second = make_large_instance(20, 7, 123)
    assert first == second
    assert len(first["cands"]) == 20
    assert len(first["weights"]) == 28
    assert all(candidate["state"]["ready_replicas"] == 3 for candidate in first["cands"])
    print("SELF_TEST_PASS")
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    worker = commands.add_parser("worker")
    worker.add_argument("--instance", required=True)
    worker.add_argument("--cbc-path", required=True)
    worker.add_argument("--time-limit", required=True)
    run = commands.add_parser("run")
    run.add_argument("--environment", required=True)
    run.add_argument("--cbc-path", required=True)
    run.add_argument("--output", required=True)
    run.add_argument("--sizes", default="500,750,1000,1500,2000")
    run.add_argument("--seeds", default="20260719,20260720,20260721")
    run.add_argument("--budget", type=int, default=7)
    commands.add_parser("self-test")
    return root


def main() -> int:
    args = parser().parse_args()
    if args.command == "worker":
        return worker_main(args)
    if args.command == "run":
        return run_main(args)
    return self_test_main()


if __name__ == "__main__":
    raise SystemExit(main())
