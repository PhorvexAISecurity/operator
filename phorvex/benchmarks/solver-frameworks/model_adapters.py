#!/usr/bin/env python3
"""Equivalent PuLP, Pyomo, and OR-Tools implementations of the Phorvex MILP."""

from __future__ import annotations

import math
import subprocess
import tempfile
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import pulp
import pyomo.environ as pyo
from ortools.linear_solver import pywraplp
from pyomo.opt import SolverStatus, TerminationCondition

from production_checker import AcceptanceResult, CheckResult, accept_or_fallback, check_solution


@dataclass
class SolveResult:
    framework: str
    solver: str
    status: str
    native_status: str
    objective: float
    x_values: list[float]
    y_values: dict[str, float]
    selected_indices: list[int]
    build_ms: float
    solve_ms: float
    feasibility_check_ms: float
    total_ms: float
    num_binary_variables: int
    num_constraints: int
    check: CheckResult | None
    acceptance: AcceptanceResult
    error: str = ""


def _indices(record: Mapping[str, Any]):
    candidates = list(record["cands"])
    facts = list(record["weights"])
    indices = list(range(len(candidates)))
    coverers: dict[str, list[int]] = defaultdict(list)
    by_asset: dict[str, list[int]] = defaultdict(list)
    for i, candidate in enumerate(candidates):
        by_asset[str(candidate["key"])].append(i)
        for fact in candidate.get("cover", []):
            coverers[fact].append(i)
    constraint_count = len(facts) + sum(len(v) > 1 for v in by_asset.values()) + 1
    if "test_required_min_moves" in record:
        constraint_count += 1
    return candidates, facts, indices, coverers, by_asset, constraint_count


def _finish(
    *, framework: str, solver: str, status: str, native_status: str,
    objective: float, x_values: list[float], y_values: dict[str, float],
    build_ms: float, solve_ms: float, total_started: float,
    binary_count: int, constraint_count: int, record: Mapping[str, Any],
    tolerance: float, error: str = "",
) -> SolveResult:
    has_values = len(x_values) == len(record["cands"]) and set(y_values) == set(record["weights"])
    check = check_solution(record, x_values, y_values, objective, tolerance) if has_values else None
    acceptance = accept_or_fallback(status, check)
    selected = [i for i, value in enumerate(x_values) if value >= 1 - tolerance]
    return SolveResult(
        framework=framework,
        solver=solver,
        status=status,
        native_status=native_status,
        objective=objective,
        x_values=x_values,
        y_values=y_values,
        selected_indices=selected,
        build_ms=build_ms,
        solve_ms=solve_ms,
        feasibility_check_ms=check.check_ms if check else 0.0,
        total_ms=(time.perf_counter() - total_started) * 1000,
        num_binary_variables=len(record["cands"]) + len(record["weights"]),
        num_constraints=constraint_count,
        check=check,
        acceptance=acceptance,
        error=error,
    )


def _failed(framework: str, solver: str, started: float, error: Exception | str) -> SolveResult:
    message = f"{type(error).__name__}: {error}" if isinstance(error, Exception) else str(error)
    acceptance = accept_or_fallback("error", None)
    return SolveResult(
        framework, solver, "error", "exception", math.nan, [], [], [],
        0.0, 0.0, 0.0, (time.perf_counter() - started) * 1000,
        0, 0, None, acceptance, message,
    )


def solve_pulp(
    record: Mapping[str, Any], cbc_path: Path, time_limit: float | None = None,
    relative_mip_gap: float = 0.0, tolerance: float = 1e-7,
) -> SolveResult:
    total_started = time.perf_counter()
    try:
        build_started = time.perf_counter()
        candidates, facts, indices, coverers, by_asset, constraint_count = _indices(record)
        problem = pulp.LpProblem("phorvex_coverage", pulp.LpMaximize)
        x = [pulp.LpVariable(f"x_{i:06d}", cat="Binary") for i in indices]
        y = {fact: pulp.LpVariable(f"y_{j:06d}", cat="Binary") for j, fact in enumerate(facts)}
        problem += (
            pulp.lpSum(float(record["weights"][fact]) * y[fact] for fact in facts)
            - float(record["lambda"]) * pulp.lpSum(float(candidates[i]["ecost"]) * x[i] for i in indices)
            + pulp.lpSum(float(candidates[i].get("future_reward", 0.0)) * x[i] for i in indices)
        )
        for fact in facts:
            problem += y[fact] <= pulp.lpSum(x[i] for i in coverers[fact])
        for asset_indices in by_asset.values():
            if len(asset_indices) > 1:
                problem += pulp.lpSum(x[i] for i in asset_indices) <= 1
        problem += pulp.lpSum(x) <= int(record["b"])
        if "test_required_min_moves" in record:
            problem += pulp.lpSum(x) >= int(record["test_required_min_moves"])
        build_ms = (time.perf_counter() - build_started) * 1000

        solver = pulp.COIN_CMD(
            path=str(cbc_path), msg=False, gapRel=relative_mip_gap,
            timeLimit=time_limit,
        )
        solve_started = time.perf_counter()
        problem.solve(solver)
        solve_ms = (time.perf_counter() - solve_started) * 1000

        native = f"{pulp.LpStatus.get(problem.status, problem.status)}/{pulp.LpSolution.get(problem.sol_status, problem.sol_status)}"
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
        xv = [float(pulp.value(v)) for v in x] if has_solution else []
        yv = {fact: float(pulp.value(y[fact])) for fact in facts} if has_solution else {}
        obj = float(pulp.value(problem.objective)) if has_solution else math.nan
        return _finish(
            framework="PuLP 2.7.0", solver="CBC 2.10.3 external", status=status,
            native_status=native, objective=obj, x_values=xv, y_values=yv,
            build_ms=build_ms, solve_ms=solve_ms, total_started=total_started,
            binary_count=len(x) + len(y), constraint_count=constraint_count,
            record=record, tolerance=tolerance,
        )
    except Exception as exc:
        return _failed("PuLP 2.7.0", "CBC external", total_started, exc)


def solve_pyomo(
    record: Mapping[str, Any], cbc_path: Path, time_limit: float | None = None,
    relative_mip_gap: float = 0.0, tolerance: float = 1e-7,
) -> SolveResult:
    total_started = time.perf_counter()
    try:
        build_started = time.perf_counter()
        candidates, facts, indices, coverers, by_asset, constraint_count = _indices(record)
        model = pyo.ConcreteModel(name="phorvex-coverage")
        model.I = pyo.Set(initialize=indices, ordered=True)
        model.K = pyo.Set(initialize=facts, ordered=True)
        model.x = pyo.Var(model.I, domain=pyo.Binary)
        model.y = pyo.Var(model.K, domain=pyo.Binary)
        model.objective = pyo.Objective(
            expr=(
                sum(float(record["weights"][fact]) * model.y[fact] for fact in facts)
                - float(record["lambda"])
                * sum(float(candidates[i]["ecost"]) * model.x[i] for i in indices)
                + sum(
                    float(candidates[i].get("future_reward", 0.0)) * model.x[i]
                    for i in indices
                )
            ),
            sense=pyo.maximize,
        )
        model.coverage = pyo.ConstraintList()
        for fact in facts:
            model.coverage.add(model.y[fact] <= sum(model.x[i] for i in coverers[fact]))
        model.partition = pyo.ConstraintList()
        for asset_indices in by_asset.values():
            if len(asset_indices) > 1:
                model.partition.add(sum(model.x[i] for i in asset_indices) <= 1)
        model.budget = pyo.Constraint(expr=sum(model.x[i] for i in indices) <= int(record["b"]))
        if "test_required_min_moves" in record:
            model.test_required_min_moves = pyo.Constraint(
                expr=sum(model.x[i] for i in indices) >= int(record["test_required_min_moves"])
            )
        build_ms = (time.perf_counter() - build_started) * 1000

        solver = pyo.SolverFactory("cbc", executable=str(cbc_path))
        solver.options["ratioGap"] = relative_mip_gap
        if time_limit is not None:
            solver.options["seconds"] = time_limit
        solve_started = time.perf_counter()
        results = solver.solve(model, tee=False, load_solutions=False)
        solve_ms = (time.perf_counter() - solve_started) * 1000

        termination = results.solver.termination_condition
        native = f"{results.solver.status}/{termination}"
        solution_count = len(results.solution)
        if solution_count:
            model.solutions.load_from(results)
        if termination == TerminationCondition.optimal:
            status = "optimal"
        elif termination in (TerminationCondition.infeasible, TerminationCondition.infeasibleOrUnbounded):
            status = "infeasible"
        elif termination == TerminationCondition.unbounded:
            status = "unbounded"
        elif termination in (TerminationCondition.feasible, TerminationCondition.locallyOptimal):
            status = "feasible"
        elif termination == TerminationCondition.maxTimeLimit:
            status = "feasible" if solution_count else "time_limit"
        elif results.solver.status == SolverStatus.error:
            status = "error"
        else:
            status = "unknown"
        has_solution = status in {"optimal", "feasible"}
        xv = [float(pyo.value(model.x[i])) for i in indices] if has_solution else []
        yv = {fact: float(pyo.value(model.y[fact])) for fact in facts} if has_solution else {}
        obj = float(pyo.value(model.objective)) if has_solution else math.nan
        return _finish(
            framework="Pyomo 6.9.5", solver="CBC 2.10.3 external", status=status,
            native_status=native, objective=obj, x_values=xv, y_values=yv,
            build_ms=build_ms, solve_ms=solve_ms, total_started=total_started,
            binary_count=len(indices) + len(facts), constraint_count=constraint_count,
            record=record, tolerance=tolerance,
        )
    except Exception as exc:
        return _failed("Pyomo 6.9.5", "CBC external", total_started, exc)


ORTOOLS_STATUS = {
    pywraplp.Solver.OPTIMAL: "optimal",
    pywraplp.Solver.FEASIBLE: "feasible",
    pywraplp.Solver.INFEASIBLE: "infeasible",
    pywraplp.Solver.UNBOUNDED: "unbounded",
    pywraplp.Solver.ABNORMAL: "error",
    pywraplp.Solver.MODEL_INVALID: "error",
    pywraplp.Solver.NOT_SOLVED: "time_limit",
}


def _build_ortools(record: Mapping[str, Any], backend: str):
    solver = pywraplp.Solver.CreateSolver(backend)
    if solver is None:
        raise RuntimeError(f"OR-Tools backend unavailable: {backend}")
    candidates, facts, indices, coverers, by_asset, constraint_count = _indices(record)
    x = [solver.BoolVar(f"x_{i:06d}") for i in indices]
    y = {fact: solver.BoolVar(f"y_{j:06d}") for j, fact in enumerate(facts)}
    objective = solver.Objective()
    for fact in facts:
        objective.SetCoefficient(y[fact], float(record["weights"][fact]))
    for i in indices:
        objective.SetCoefficient(
            x[i],
            -float(record["lambda"]) * float(candidates[i]["ecost"])
            + float(candidates[i].get("future_reward", 0.0)),
        )
    objective.SetMaximization()
    for j, fact in enumerate(facts):
        con = solver.RowConstraint(-solver.infinity(), 0.0, f"cover_{j:06d}")
        con.SetCoefficient(y[fact], 1.0)
        for i in coverers[fact]:
            con.SetCoefficient(x[i], -1.0)
    for j, asset_indices in enumerate(v for v in by_asset.values() if len(v) > 1):
        con = solver.RowConstraint(-solver.infinity(), 1.0, f"asset_{j:06d}")
        for i in asset_indices:
            con.SetCoefficient(x[i], 1.0)
    budget = solver.RowConstraint(-solver.infinity(), float(record["b"]), "budget")
    for variable in x:
        budget.SetCoefficient(variable, 1.0)
    if "test_required_min_moves" in record:
        required = solver.RowConstraint(float(record["test_required_min_moves"]), solver.infinity(), "test_required_min_moves")
        for variable in x:
            required.SetCoefficient(variable, 1.0)
    return solver, objective, x, y, candidates, facts, indices, constraint_count


def solve_ortools(
    record: Mapping[str, Any], cbc_path: Path | None = None, time_limit: float | None = None,
    relative_mip_gap: float = 0.0, tolerance: float = 1e-7, backend: str = "CBC",
) -> SolveResult:
    """Run the native MPSolver backend (embedded CBC in the pinned wheel)."""
    del cbc_path
    total_started = time.perf_counter()
    try:
        build_started = time.perf_counter()
        solver, objective, x, y, candidates, facts, indices, constraint_count = _build_ortools(record, backend)
        solver.SetNumThreads(1)
        if time_limit is not None:
            solver.SetTimeLimit(max(1, math.ceil(time_limit * 1000)))
        build_ms = (time.perf_counter() - build_started) * 1000
        params = pywraplp.MPSolverParameters()
        params.SetDoubleParam(pywraplp.MPSolverParameters.RELATIVE_MIP_GAP, relative_mip_gap)
        solve_started = time.perf_counter()
        code = solver.Solve(params)
        solve_ms = (time.perf_counter() - solve_started) * 1000
        status = ORTOOLS_STATUS.get(code, "unknown")
        has_solution = status in {"optimal", "feasible"}
        xv = [float(v.solution_value()) for v in x] if has_solution else []
        yv = {fact: float(y[fact].solution_value()) for fact in facts} if has_solution else {}
        obj = float(objective.Value()) if has_solution else math.nan
        return _finish(
            framework="OR-Tools 9.14.6206 MPSolver", solver=solver.SolverVersion(),
            status=status, native_status=str(code), objective=obj, x_values=xv,
            y_values=yv, build_ms=build_ms, solve_ms=solve_ms,
            total_started=total_started, binary_count=len(x) + len(y),
            constraint_count=constraint_count, record=record, tolerance=tolerance,
        )
    except Exception as exc:
        return _failed("OR-Tools 9.14.6206 MPSolver", backend, total_started, exc)


def _parse_cbc_solution(path: Path, count_x: int, facts: list[str]):
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    first = text.splitlines()[0] if text else ""
    lower = first.lower()
    if lower.startswith("optimal"):
        status = "optimal"
    elif "infeasible" in lower:
        status = "infeasible"
    elif "stopped on time" in lower and "objective value" in lower:
        status = "feasible"
    elif "stopped on time" in lower:
        status = "time_limit"
    else:
        status = "unknown"
    values: dict[str, float] = {}
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 3:
            try:
                values[parts[1]] = float(parts[2])
            except ValueError:
                pass
    if status not in {"optimal", "feasible"}:
        return status, first, [], {}, math.nan
    xv = [values.get(f"x_{i:06d}", 0.0) for i in range(count_x)]
    yv = {fact: values.get(f"y_{j:06d}", 0.0) for j, fact in enumerate(facts)}
    try:
        obj = float(first.rsplit(" ", 1)[-1])
    except ValueError:
        obj = math.nan
    return status, first, xv, yv, obj


def solve_ortools_external_cbc(
    record: Mapping[str, Any], cbc_path: Path, time_limit: float | None = None,
    relative_mip_gap: float = 0.0, tolerance: float = 1e-7,
) -> SolveResult:
    """Build in MPSolver, then solve the exported MPS with the shared CBC binary.

    This controlled sensitivity path removes the CBC 2.10.3-vs-2.10.12 confound.
    Export and solution parsing are deliberately included in solve/end-to-end time.
    """
    total_started = time.perf_counter()
    try:
        build_started = time.perf_counter()
        solver, objective, x, y, candidates, facts, indices, constraint_count = _build_ortools(record, "CBC")
        build_ms = (time.perf_counter() - build_started) * 1000
        with tempfile.TemporaryDirectory(prefix="phorvex-ortools-cbc-") as directory:
            model_path = Path(directory) / "model.mps"
            solution_path = Path(directory) / "solution.sol"
            solve_started = time.perf_counter()
            model_path.write_text(solver.ExportModelAsMpsFormat(False, False), encoding="utf-8")
            command = [str(cbc_path), str(model_path), "-max", "-ratio", str(relative_mip_gap)]
            if time_limit is not None:
                command += ["-seconds", str(time_limit)]
            command += ["-solve", "-solu", str(solution_path)]
            completed = subprocess.run(command, capture_output=True, text=True, check=False)
            status, native, xv, yv, obj = _parse_cbc_solution(solution_path, len(x), facts)
            # CBC's text solution header rounds the objective.  Recompute it from the
            # full-precision source coefficients and parsed binary values before the
            # independent checker compares it.
            if status in {"optimal", "feasible"}:
                obj = sum(float(record["weights"][fact]) * yv[fact] for fact in facts)
                obj -= float(record["lambda"]) * sum(
                    float(candidates[i]["ecost"]) * xv[i] for i in indices
                )
                obj += sum(
                    float(candidates[i].get("future_reward", 0.0)) * xv[i]
                    for i in indices
                )
            solve_ms = (time.perf_counter() - solve_started) * 1000
            if completed.returncode != 0 and status not in {"optimal", "feasible", "infeasible"}:
                raise RuntimeError(f"CBC exit {completed.returncode}: {completed.stderr[-300:]}")
        return _finish(
            framework="OR-Tools 9.14.6206 MPSolver (MPS export)",
            solver="CBC 2.10.3 external", status=status, native_status=native,
            objective=obj, x_values=xv, y_values=yv, build_ms=build_ms,
            solve_ms=solve_ms, total_started=total_started,
            binary_count=len(x) + len(y), constraint_count=constraint_count,
            record=record, tolerance=tolerance,
        )
    except Exception as exc:
        return _failed("OR-Tools 9.14.6206 MPSolver (MPS export)", "CBC external", total_started, exc)


PRIMARY_ADAPTERS = {
    "pulp": solve_pulp,
    "pyomo": solve_pyomo,
    "ortools": solve_ortools,
}
