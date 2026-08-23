#!/usr/bin/env python3
"""Deadline-aware CP-SAT escalation tier for the Phorvex coverage model.

This module is a benchmark/prototype boundary, not live operator wiring.  It
always computes a valid greedy-plus-swaps incumbent first and never makes a
decision tick depend on the exact solver finishing successfully.
"""

from __future__ import annotations

import math
import multiprocessing
import queue
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from ortools.sat.python import cp_model

from production_checker import check_solution


TOLERANCE = 1e-7


@dataclass(frozen=True)
class HeuristicSolution:
    selected_indices: tuple[int, ...]
    x_values: tuple[float, ...]
    y_values: dict[str, float]
    objective: float


@dataclass
class CPSATResult:
    status: str
    native_status: str
    objective: float
    scaled_objective: float
    best_bound: float
    gap_percent: float
    selected_indices: tuple[int, ...]
    x_values: tuple[float, ...]
    y_values: dict[str, float]
    checker_passed: bool
    violations: tuple[str, ...]
    coefficient_scale: int
    max_coefficient_rounding_error: float
    prepare_ms: float
    variable_ms: float
    constraint_ms: float
    objective_ms: float
    hint_ms: float
    solve_ms: float
    extraction_ms: float
    checker_ms: float
    total_ms: float
    deadline_met: bool
    branches: int
    conflicts: int
    error: str = ""


@dataclass
class TierDecision:
    route: str
    solution_source: str
    solver_status: str
    selected_indices: tuple[int, ...]
    x_values: tuple[float, ...]
    y_values: dict[str, float]
    objective: float
    heuristic_objective: float
    exact_objective: float
    exact_best_bound: float
    exact_gap_percent: float
    exact_improved: bool
    fallback_used: bool
    checker_passed: bool
    deadline_met: bool
    total_ms: float
    exact: CPSATResult | None
    reason: str


def _prepared(record: Mapping[str, Any]):
    """Build de-duplicated coverage indices shared by every prototype path."""
    candidates = list(record["cands"])
    facts = list(record["weights"])
    known_facts = set(facts)
    coverers: dict[str, list[int]] = {fact: [] for fact in facts}
    covers: list[tuple[str, ...]] = []
    by_asset: dict[str, list[int]] = defaultdict(list)
    for index, candidate in enumerate(candidates):
        # Candidate inputs may contain repeated cover keys.  De-duplicate before
        # building either the heuristic or exact model so repeated keys cannot
        # inflate a marginal value or create duplicate coefficients.
        unique = tuple(dict.fromkeys(
            str(fact) for fact in candidate.get("cover", []) if str(fact) in known_facts
        ))
        covers.append(unique)
        by_asset[str(candidate.get("key", ""))].append(index)
        for fact in unique:
            coverers[fact].append(index)
    return candidates, facts, covers, coverers, by_asset


def _solution(record: Mapping[str, Any], selected: set[int], covers: list[tuple[str, ...]]) -> HeuristicSolution:
    candidates = list(record["cands"])
    covered = {fact for index in selected for fact in covers[index]}
    y_values = {
        fact: float(fact in covered and float(weight) > 0)
        for fact, weight in record["weights"].items()
    }
    x_values = tuple(float(index in selected) for index in range(len(candidates)))
    objective = sum(float(record["weights"][fact]) * value for fact, value in y_values.items())
    objective += sum(
        -float(record["lambda"]) * float(candidates[index]["ecost"])
        + float(candidates[index].get("future_reward", 0.0))
        for index in selected
    )
    return HeuristicSolution(tuple(sorted(selected)), x_values, y_values, objective)


def greedy_then_swaps(record: Mapping[str, Any]) -> HeuristicSolution:
    """Deterministic greedy selection followed by improving one-for-one swaps."""
    candidates, _, covers, _, _ = _prepared(record)
    budget = max(0, min(int(record["b"]), int(record.get("policy", {}).get("max_moves_per_tick", record["b"]))))
    selected: set[int] = set()
    used_assets: set[str] = set()
    covered: set[str] = set()

    while len(selected) < budget:
        best_index = None
        best_gain = TOLERANCE
        for index, candidate in enumerate(candidates):
            asset = str(candidate.get("key", ""))
            if index in selected or asset in used_assets:
                continue
            gain = sum(
                max(0.0, float(record["weights"][fact]))
                for fact in covers[index]
                if fact not in covered
            )
            gain -= float(record["lambda"]) * float(candidate["ecost"])
            gain += float(candidate.get("future_reward", 0.0))
            if gain > best_gain + TOLERANCE or (
                abs(gain - best_gain) <= TOLERANCE and best_index is not None and index < best_index
            ):
                best_gain = gain
                best_index = index
        if best_index is None:
            break
        selected.add(best_index)
        used_assets.add(str(candidates[best_index].get("key", "")))
        covered.update(covers[best_index])

    # Keep coverage multiplicities so evaluating a swap touches only the two
    # candidates' incident edges.  Rebuilding every fact for every possible
    # pair is quadratic in both candidates and facts and made the safe
    # incumbent itself the dominant cost at N=1000.
    coverage_count: dict[str, int] = defaultdict(int)
    for index in selected:
        for fact in covers[index]:
            coverage_count[fact] += 1
    action_value = [
        -float(record["lambda"]) * float(candidate["ecost"])
        + float(candidate.get("future_reward", 0.0))
        for candidate in candidates
    ]
    weights = {fact: max(0.0, float(value)) for fact, value in record["weights"].items()}
    current = _solution(record, selected, covers)
    while selected:
        best_delta = TOLERANCE
        best_pair: tuple[int, int] | None = None
        for old in sorted(selected):
            remaining = selected - {old}
            remaining_assets = {str(candidates[index].get("key", "")) for index in remaining}
            for new, candidate in enumerate(candidates):
                if new in selected or str(candidate.get("key", "")) in remaining_assets:
                    continue
                old_facts = set(covers[old])
                new_facts = set(covers[new])
                delta = action_value[new] - action_value[old]
                delta -= sum(
                    weights[fact] for fact in old_facts - new_facts
                    if coverage_count[fact] == 1
                )
                delta += sum(
                    weights[fact] for fact in new_facts - old_facts
                    if coverage_count[fact] == 0
                )
                if delta > best_delta + TOLERANCE:
                    best_delta = delta
                    best_pair = (old, new)
        if best_pair is None:
            break
        old, new = best_pair
        selected.remove(old)
        for fact in covers[old]:
            coverage_count[fact] -= 1
        selected.add(new)
        for fact in covers[new]:
            coverage_count[fact] += 1
    return _solution(record, selected, covers)


def coverage_is_disjoint(record: Mapping[str, Any]) -> bool:
    _, _, _, coverers, _ = _prepared(record)
    return all(len(indices) <= 1 for indices in coverers.values())


def solve_cp_sat(
    record: Mapping[str, Any],
    *,
    deadline_seconds: float,
    coefficient_scale: int = 1_000_000,
    incumbent: HeuristicSolution | None = None,
) -> CPSATResult:
    """Solve one scaled CP-SAT model within an end-to-end call deadline.

    All floating-point objective terms are first combined in original units,
    multiplied by one documented scale, then rounded once to the nearest
    integer.  Thus the per-term original-unit error is at most ``0.5/scale``.
    The returned solution is always re-evaluated against the unscaled objective.
    """
    started = time.perf_counter()
    empty: dict[str, float] = {}
    if coefficient_scale <= 0:
        raise ValueError("coefficient_scale must be positive")
    try:
        phase = time.perf_counter()
        candidates, facts, covers, coverers, by_asset = _prepared(record)
        prepare_ms = (time.perf_counter() - phase) * 1000

        model = cp_model.CpModel()
        phase = time.perf_counter()
        x = [model.new_bool_var(f"x_{index:06d}") for index in range(len(candidates))]
        y = {fact: model.new_bool_var(f"y_{index:06d}") for index, fact in enumerate(facts)}
        variable_ms = (time.perf_counter() - phase) * 1000

        phase = time.perf_counter()
        for fact in facts:
            if coverers[fact]:
                model.add(y[fact] <= sum(x[index] for index in coverers[fact]))
            else:
                model.add(y[fact] == 0)
        for asset_indices in by_asset.values():
            if len(asset_indices) > 1:
                model.add(sum(x[index] for index in asset_indices) <= 1)
        model.add(sum(x) <= int(record["b"]))
        if "test_required_min_moves" in record:
            model.add(sum(x) >= int(record["test_required_min_moves"]))
        constraint_ms = (time.perf_counter() - phase) * 1000

        phase = time.perf_counter()
        original_coefficients = [float(record["weights"][fact]) for fact in facts]
        action_coefficients = [
            -float(record["lambda"]) * float(candidate["ecost"])
            + float(candidate.get("future_reward", 0.0))
            for candidate in candidates
        ]
        scaled_fact = [int(round(value * coefficient_scale)) for value in original_coefficients]
        scaled_action = [int(round(value * coefficient_scale)) for value in action_coefficients]
        terms = [scaled_fact[index] * y[fact] for index, fact in enumerate(facts)]
        terms.extend(scaled_action[index] * x[index] for index in range(len(candidates)))
        model.maximize(sum(terms))
        rounding_errors = [
            abs(original - scaled / coefficient_scale)
            for original, scaled in zip(
                original_coefficients + action_coefficients,
                scaled_fact + scaled_action,
            )
        ]
        max_rounding_error = max(rounding_errors, default=0.0)
        objective_ms = (time.perf_counter() - phase) * 1000

        phase = time.perf_counter()
        if incumbent is not None:
            for index, variable in enumerate(x):
                model.add_hint(variable, int(incumbent.x_values[index]))
            for fact, variable in y.items():
                model.add_hint(variable, int(incumbent.y_values[fact]))
        hint_ms = (time.perf_counter() - phase) * 1000

        remaining = deadline_seconds - (time.perf_counter() - started)
        if remaining <= 0:
            total_ms = (time.perf_counter() - started) * 1000
            return CPSATResult(
                "time_limit", "deadline-before-search", math.nan, math.nan, math.nan,
                math.nan, (), (), empty, False, ("solver-status:time_limit",),
                coefficient_scale, max_rounding_error, prepare_ms, variable_ms,
                constraint_ms, objective_ms, hint_ms, 0.0, 0.0, 0.0, total_ms,
                False, 0, 0,
            )

        solver = cp_model.CpSolver()
        # Reserve part of the call budget for response extraction and the
        # independent checker.  CP-SAT's limit applies only inside Solve();
        # giving it the entire remaining wall clock would make the end-to-end
        # prototype late by construction.
        solver.parameters.max_time_in_seconds = max(0.000_001, remaining * 0.8)
        solver.parameters.num_search_workers = 1
        solver.parameters.random_seed = 0
        solver.parameters.cp_model_presolve = True
        phase = time.perf_counter()
        code = solver.solve(model)
        solve_ms = (time.perf_counter() - phase) * 1000
        native_status = solver.status_name(code)
        status = {
            cp_model.OPTIMAL: "optimal",
            cp_model.FEASIBLE: "feasible",
            cp_model.INFEASIBLE: "infeasible",
            cp_model.MODEL_INVALID: "error",
            cp_model.UNKNOWN: "time_limit",
        }.get(code, "unknown")

        phase = time.perf_counter()
        if status in {"optimal", "feasible"}:
            x_values = tuple(float(solver.value(variable)) for variable in x)
            y_values = {fact: float(solver.value(variable)) for fact, variable in y.items()}
            selected = tuple(index for index, value in enumerate(x_values) if value >= 1 - TOLERANCE)
            unscaled_objective = sum(
                float(record["weights"][fact]) * y_values[fact] for fact in facts
            ) + sum(action_coefficients[index] * x_values[index] for index in range(len(candidates)))
            scaled_objective = float(solver.objective_value) / coefficient_scale
            best_bound = float(solver.best_objective_bound) / coefficient_scale
            denominator = max(abs(float(solver.objective_value)), 1.0)
            gap_percent = max(0.0, float(solver.best_objective_bound - solver.objective_value)) / denominator * 100
        else:
            x_values, y_values, selected = (), {}, ()
            unscaled_objective = scaled_objective = best_bound = gap_percent = math.nan
        extraction_ms = (time.perf_counter() - phase) * 1000

        phase = time.perf_counter()
        if status in {"optimal", "feasible"}:
            check = check_solution(record, x_values, y_values, unscaled_objective, TOLERANCE)
            checker_passed = check.passed
            violations = check.violations
        else:
            checker_passed = False
            violations = (f"solver-status:{status}",)
        checker_ms = (time.perf_counter() - phase) * 1000
        total_ms = (time.perf_counter() - started) * 1000
        deadline_met = total_ms <= deadline_seconds * 1000
        return CPSATResult(
            status, native_status, unscaled_objective, scaled_objective,
            best_bound, gap_percent, selected, x_values, y_values,
            checker_passed, violations, coefficient_scale, max_rounding_error,
            prepare_ms, variable_ms, constraint_ms, objective_ms, hint_ms,
            solve_ms, extraction_ms, checker_ms, total_ms, deadline_met,
            int(solver.num_branches), int(solver.num_conflicts),
        )
    except Exception as exc:
        total_ms = (time.perf_counter() - started) * 1000
        return CPSATResult(
            "error", "exception", math.nan, math.nan, math.nan, math.nan,
            (), (), empty, False, ("solver-status:error",), coefficient_scale,
            math.nan, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
            total_ms, total_ms <= deadline_seconds * 1000, 0, 0,
            f"{type(exc).__name__}: {exc}",
        )


def _cp_sat_process(queue_out, record, deadline_seconds, coefficient_scale, incumbent):
    queue_out.put(solve_cp_sat(
        record,
        deadline_seconds=deadline_seconds,
        coefficient_scale=coefficient_scale,
        incumbent=incumbent,
    ))


def solve_cp_sat_hard_deadline(
    record: Mapping[str, Any],
    *,
    deadline_seconds: float,
    coefficient_scale: int,
    incumbent: HeuristicSolution,
) -> CPSATResult:
    """Isolate CP-SAT so model construction and Solve have one hard wall cap.

    CP-SAT's native limit starts only inside ``Solve``.  A separate process is
    therefore required for the runtime prototype: if Python model construction,
    native solving, extraction, or checking consumes the remaining tick budget,
    the parent terminates the attempt and immediately keeps its already-computed
    incumbent.  The direct ``solve_cp_sat`` function remains the benchmark path.
    """
    started = time.perf_counter()
    if deadline_seconds <= 0:
        return CPSATResult(
            status="time_limit", native_status="hard-deadline-before-start",
            objective=math.nan, scaled_objective=math.nan, best_bound=math.nan,
            gap_percent=math.nan, selected_indices=(), x_values=(), y_values={},
            checker_passed=False, violations=("solver-status:time_limit",),
            coefficient_scale=coefficient_scale, max_coefficient_rounding_error=math.nan,
            prepare_ms=0.0, variable_ms=0.0, constraint_ms=0.0,
            objective_ms=0.0, hint_ms=0.0, solve_ms=0.0,
            extraction_ms=0.0, checker_ms=0.0, total_ms=0.0,
            deadline_met=False, branches=0, conflicts=0,
        )

    # This benchmark/prototype is Linux-only, matching the Phorvex runtime and
    # AWS evidence hosts.  fork avoids spawn's interpreter startup dominating a
    # 50–500 ms decision budget.
    context = multiprocessing.get_context("fork")
    result_queue = context.Queue(maxsize=1)
    process = context.Process(
        target=_cp_sat_process,
        args=(result_queue, record, deadline_seconds, coefficient_scale, incumbent),
        daemon=True,
    )
    process.start()
    startup_elapsed = time.perf_counter() - started
    # Reserve 5% (5–50 ms) for termination/join/queue cleanup in the parent.
    # A fixed 3 ms reserve was too narrow under process-scheduling jitter.
    cleanup_guard = min(0.050, max(0.005, deadline_seconds * 0.05))
    join_budget = max(0.0, deadline_seconds - startup_elapsed - cleanup_guard)
    process.join(join_budget)
    if process.is_alive():
        process.terminate()
        process.join(0.002)
        total_ms = (time.perf_counter() - started) * 1000
        result_queue.close()
        return CPSATResult(
            status="time_limit", native_status="hard-deadline-terminated",
            objective=math.nan, scaled_objective=math.nan, best_bound=math.nan,
            gap_percent=math.nan, selected_indices=(), x_values=(), y_values={},
            checker_passed=False, violations=("solver-status:time_limit",),
            coefficient_scale=coefficient_scale, max_coefficient_rounding_error=math.nan,
            prepare_ms=0.0, variable_ms=0.0, constraint_ms=0.0,
            objective_ms=0.0, hint_ms=0.0, solve_ms=0.0,
            extraction_ms=0.0, checker_ms=0.0, total_ms=total_ms,
            deadline_met=False, branches=0, conflicts=0,
        )
    try:
        result = result_queue.get(timeout=0.002)
    except queue.Empty:
        total_ms = (time.perf_counter() - started) * 1000
        result = CPSATResult(
            status="error", native_status="child-exited-without-result",
            objective=math.nan, scaled_objective=math.nan, best_bound=math.nan,
            gap_percent=math.nan, selected_indices=(), x_values=(), y_values={},
            checker_passed=False, violations=("solver-status:error",),
            coefficient_scale=coefficient_scale, max_coefficient_rounding_error=math.nan,
            prepare_ms=0.0, variable_ms=0.0, constraint_ms=0.0,
            objective_ms=0.0, hint_ms=0.0, solve_ms=0.0,
            extraction_ms=0.0, checker_ms=0.0, total_ms=total_ms,
            deadline_met=False, branches=0, conflicts=0,
            error=f"CP-SAT child exit code {process.exitcode}",
        )
    finally:
        result_queue.close()
    result.total_ms = (time.perf_counter() - started) * 1000
    result.deadline_met = result.total_ms <= deadline_seconds * 1000
    return result


def run_exact_tier(
    record: Mapping[str, Any],
    *,
    deadline_seconds: float,
    enabled: bool = True,
    max_exact_candidates: int = 500,
    coefficient_scale: int = 1_000_000,
    solver_fn: Callable[..., CPSATResult] | None = None,
) -> TierDecision:
    """Apply the proposed router and return a safe solution on every path."""
    started = time.perf_counter()
    heuristic = greedy_then_swaps(record)

    def heuristic_decision(route: str, reason: str, exact: CPSATResult | None = None) -> TierDecision:
        elapsed_ms = (time.perf_counter() - started) * 1000
        return TierDecision(
            route, "greedy-plus-swaps", exact.status if exact else "not-run",
            heuristic.selected_indices, heuristic.x_values, heuristic.y_values,
            heuristic.objective, heuristic.objective,
            exact.objective if exact else math.nan,
            exact.best_bound if exact else math.nan,
            exact.gap_percent if exact else math.nan,
            False, exact is not None, True,
            elapsed_ms <= deadline_seconds * 1000,
            elapsed_ms, exact, reason,
        )

    if coverage_is_disjoint(record):
        return heuristic_decision("greedy-disjoint", "coverage sets are disjoint")
    if int(record["b"]) <= 1:
        return heuristic_decision("greedy-budget-one", "budget is one")
    if not enabled:
        return heuristic_decision("heuristic-exact-disabled", "exact tier disabled")
    if len(record["cands"]) > max_exact_candidates:
        return heuristic_decision("heuristic-size-cap", "candidate count exceeds exact-tier cap")

    remaining = deadline_seconds - (time.perf_counter() - started)
    if remaining <= 0:
        return heuristic_decision("heuristic-no-time", "heuristic consumed the tick deadline")
    solver_fn = solver_fn or solve_cp_sat_hard_deadline
    exact = solver_fn(
        record,
        deadline_seconds=remaining,
        coefficient_scale=coefficient_scale,
        incumbent=heuristic,
    )
    elapsed_ms = (time.perf_counter() - started) * 1000
    exact_usable = (
        exact.status in {"optimal", "feasible"}
        and exact.checker_passed
        and exact.deadline_met
        and elapsed_ms <= deadline_seconds * 1000
    )
    improved = exact_usable and exact.objective > heuristic.objective + TOLERANCE
    if not improved:
        reason = "exact result did not improve the incumbent" if exact_usable else "exact result was unavailable, invalid, or late"
        return heuristic_decision("exact-attempt-fallback", reason, exact)

    return TierDecision(
        "exact-escalation", "cp-sat", exact.status,
        exact.selected_indices, exact.x_values, exact.y_values, exact.objective,
        heuristic.objective, exact.objective, exact.best_bound,
        exact.gap_percent, True, False, True,
        elapsed_ms <= deadline_seconds * 1000, elapsed_ms, exact,
        "checker-passing exact solution improved the incumbent before the deadline",
    )
