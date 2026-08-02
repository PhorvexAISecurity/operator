#!/usr/bin/env python3
"""Offline C0/C1/C2/C3 evaluator for PHORVEXSEC-35.

The evaluator consumes only real probe observations. Missing measurements remain
``None`` and cannot silently become zeros. C2 is a non-negative least-squares model
over the five ticket components; C3 is used only for offline selection/regret.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

FEATURES = ("c_norm", "c_flow", "c_state", "c_gpu", "c_availability")
MODELS = ("c0", "c1", "c2", "c3")
SCHEMA = "phorvex.cost-validation-evaluation.v1"


def finite(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        out = float(value)
    except (TypeError, ValueError):
        return None
    return out if math.isfinite(out) else None


def clamp01(value: float) -> float:
    return min(1.0, max(0.0, value))


def normalized_increase(before: float, after: float) -> float:
    return clamp01((after - before) / max(abs(before), 1.0))


def normalized_drop(before: float, after: float) -> float:
    return clamp01((before - after) / max(abs(before), 1e-9))


def observed_label(row: Mapping[str, Any]) -> tuple[float | None, int]:
    """Equal-weight mean of the available normalized disruption witnesses.

    Equal weighting is the primary label because the ticket does not supply business
    weights. The exact term count is retained so a sparse label cannot masquerade as a
    complete one.
    """

    terms: list[float] = []
    availability = finite(row.get("availability_loss"))
    if availability is not None:
        terms.append(clamp01(availability))
    p99_before, p99_after = finite(row.get("p99_before_ms")), finite(row.get("p99_after_ms"))
    if p99_before is not None and p99_after is not None:
        terms.append(normalized_increase(p99_before, p99_after))
    tps_before = finite(row.get("tokens_before_per_sec"))
    tps_after = finite(row.get("tokens_after_per_sec"))
    if tps_before is not None and tps_after is not None:
        terms.append(normalized_drop(tps_before, tps_after))
    ready = finite(row.get("time_to_ready_sec"))
    if ready is not None:
        terms.append(clamp01(ready / 400.0))
    state = finite(row.get("state_or_kv_loss"))
    if state is not None:
        terms.append(clamp01(state))
    gpu = finite(row.get("gpu_burden"))
    if gpu is not None:
        terms.append(clamp01(gpu))
    if not terms:
        return None, 0
    return statistics.fmean(terms), len(terms)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_no, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{line_no}: {exc}") from exc
        if row.get("schema_version") != "phorvex.cost-validation-observation.v1":
            raise ValueError(f"{path}:{line_no}: unsupported schema {row.get('schema_version')!r}")
        label, terms = observed_label(row)
        recorded = finite(row.get("cost_observed"))
        if label is not None and recorded is not None and abs(label - recorded) > 1e-9:
            raise ValueError(f"{path}:{line_no}: probe/evaluator observed-cost drift {recorded} vs {label}")
        row["cost_observed"] = label
        row["observed_label_terms"] = terms
        rows.append(row)
    return rows


def usable(row: Mapping[str, Any]) -> bool:
    if row.get("cost_observed") is None:
        return False
    if row.get("feasibility_status") != "feasible" or not row.get("candidate_generated", False):
        return False
    if row.get("action") == "noop":
        return not row.get("actuation_error")
    return bool(row.get("emitted")) and not row.get("actuation_error")


def feature_vector(row: Mapping[str, Any]) -> list[float] | None:
    values = [finite(row.get(name)) for name in FEATURES]
    if any(value is None for value in values):
        return None
    return [float(value) for value in values if value is not None]


def grouped_split(rows: Sequence[Mapping[str, Any]], salt: str = "primary") -> tuple[set[tuple[str, int]], set[tuple[str, int]]]:
    groups = sorted({(str(r["scenario_id"]), int(r["seed"])) for r in rows})
    if len(groups) < 2:
        raise ValueError("grouped 70/30 split requires at least two scenario/seed groups")
    ordered = sorted(groups, key=lambda group: hashlib.sha256(f"{salt}|{group[0]}|{group[1]}".encode()).digest())
    train_count = min(len(groups) - 1, max(1, int(math.floor(0.70 * len(groups)))))
    train = set(ordered[:train_count])
    return train, set(ordered[train_count:])


def split_name(row: Mapping[str, Any], train: set[tuple[str, int]]) -> str:
    return "train" if (str(row["scenario_id"]), int(row["seed"])) in train else "test"


def fit_nnls(rows: Sequence[Mapping[str, Any]], max_cost: float = 1.0) -> list[float]:
    samples = [(feature_vector(row), finite(row.get("cost_observed"))) for row in rows]
    complete = [(x, y) for x, y in samples if x is not None and y is not None]
    if not complete:
        raise ValueError("no complete C2 training samples")
    theta = [0.0] * len(FEATURES)
    for _ in range(20_000):
        previous = list(theta)
        for j in range(len(FEATURES)):
            denom = sum(x[j] * x[j] for x, _ in complete)
            if denom <= 1e-15:
                theta[j] = 0.0
                continue
            numer = 0.0
            for x, y in complete:
                residual_without_j = y - sum(theta[k] * x[k] for k in range(len(FEATURES)) if k != j)
                numer += x[j] * residual_without_j
            theta[j] = max(0.0, numer / denom)
        if max(abs(a - b) for a, b in zip(theta, previous)) < 1e-12:
            break
    # The constrained prediction is clipped; learned coefficients stay interpretable.
    if any(not math.isfinite(value) or value < 0 for value in theta):
        raise ValueError(f"invalid NNLS weights {theta}")
    return theta


def predict_c2(row: Mapping[str, Any], theta: Sequence[float], max_cost: float = 1.0) -> float | None:
    x = feature_vector(row)
    if x is None:
        return None
    return min(max_cost, max(0.0, sum(weight * value for weight, value in zip(theta, x))))


def percentile(values: Sequence[float], p: float) -> float:
    if not values:
        return math.nan
    ordered = sorted(values)
    index = (len(ordered) - 1) * p
    lo, hi = math.floor(index), math.ceil(index)
    if lo == hi:
        return ordered[lo]
    return ordered[lo] * (hi - index) + ordered[hi] * (index - lo)


def average_ranks(values: Sequence[float]) -> list[float]:
    order = sorted(range(len(values)), key=lambda index: values[index])
    ranks = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i + 1
        while j < len(order) and values[order[j]] == values[order[i]]:
            j += 1
        rank = (i + 1 + j) / 2.0
        for index in order[i:j]:
            ranks[index] = rank
        i = j
    return ranks


def pearson(xs: Sequence[float], ys: Sequence[float]) -> float:
    if len(xs) < 2:
        return math.nan
    mx, my = statistics.fmean(xs), statistics.fmean(ys)
    numerator = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    dx = sum((x - mx) ** 2 for x in xs)
    dy = sum((y - my) ** 2 for y in ys)
    if dx <= 0 or dy <= 0:
        return 0.0
    return numerator / math.sqrt(dx * dy)


def spearman(xs: Sequence[float], ys: Sequence[float]) -> float:
    return pearson(average_ranks(xs), average_ranks(ys))


def kendall_tau_b(xs: Sequence[float], ys: Sequence[float]) -> float:
    concordant = discordant = ties_x = ties_y = 0
    for i in range(len(xs)):
        for j in range(i + 1, len(xs)):
            dx, dy = xs[i] - xs[j], ys[i] - ys[j]
            if dx == 0 and dy == 0:
                continue
            if dx == 0:
                ties_x += 1
            elif dy == 0:
                ties_y += 1
            elif dx * dy > 0:
                concordant += 1
            else:
                discordant += 1
    denom = math.sqrt((concordant + discordant + ties_x) * (concordant + discordant + ties_y))
    return (concordant - discordant) / denom if denom else 0.0


def pairwise_accuracy(xs: Sequence[float], ys: Sequence[float]) -> float:
    scores: list[float] = []
    for i in range(len(xs)):
        for j in range(i + 1, len(xs)):
            truth = ys[i] - ys[j]
            if truth == 0:
                continue
            predicted = xs[i] - xs[j]
            scores.append(1.0 if predicted * truth > 0 else 0.5 if predicted == 0 else 0.0)
    return statistics.fmean(scores) if scores else math.nan


def prediction_metrics(rows: Sequence[Mapping[str, Any]], key: str) -> dict[str, float | int]:
    pairs = [(finite(row.get(key)), finite(row.get("cost_observed"))) for row in rows]
    pairs = [(pred, actual) for pred, actual in pairs if pred is not None and actual is not None]
    if not pairs:
        return {"n": 0, "mae": math.nan, "rmse": math.nan, "spearman": math.nan, "kendall": math.nan, "pairwise": math.nan}
    predictions, actuals = zip(*pairs)
    errors = [prediction - actual for prediction, actual in pairs]
    return {
        "n": len(pairs),
        "mae": statistics.fmean(abs(value) for value in errors),
        "rmse": math.sqrt(statistics.fmean(value * value for value in errors)),
        "spearman": spearman(predictions, actuals),
        "kendall": kendall_tau_b(predictions, actuals),
        "pairwise": pairwise_accuracy(predictions, actuals),
    }


def decision_key(row: Mapping[str, Any]) -> tuple[str, int, str, str]:
    return str(row["scenario_id"]), int(row["seed"]), str(row["tick_id"]), str(row.get("workload_id", ""))


def select_decisions(rows: Sequence[dict[str, Any]], flat_cost: float) -> dict[str, dict[str, Any]]:
    groups: dict[tuple[str, int, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        if usable(row):
            groups[decision_key(row)].append(row)
    selected: dict[str, dict[str, Any]] = {model: {} for model in MODELS}
    for group_key, candidates in groups.items():
        for model_name, cost_key in (("c0", "c0_cost"), ("c2", "c2_cost"), ("c3", "cost_observed")):
            eligible = [row for row in candidates if finite(row.get(cost_key)) is not None]
            if eligible:
                selected[model_name][group_key] = max(
                    eligible,
                    key=lambda row: (float(row["security_value"]) - float(row["lambda"]) * float(row[cost_key]), -eligible.index(row)),
                )
        selected["c1"][group_key] = max(
            candidates,
            key=lambda row: (float(row["security_value"]) - float(row["lambda"]) * flat_cost, -candidates.index(row)),
        )
    return selected


def decision_metrics(selected: Mapping[str, Mapping[Any, Mapping[str, Any]]], model_name: str) -> dict[str, float | int]:
    regrets: list[float] = []
    objective = security = observed_cost = availability = 0.0
    slo = 0
    flips = 0
    model_choices = selected[model_name]
    oracle = selected["c3"]
    c0 = selected["c0"]
    for key, choice in model_choices.items():
        oracle_choice = oracle.get(key)
        if oracle_choice is None:
            continue
        observed_objective = float(choice["security_value"]) - float(choice["lambda"]) * float(choice["cost_observed"])
        oracle_objective = float(oracle_choice["security_value"]) - float(oracle_choice["lambda"]) * float(oracle_choice["cost_observed"])
        regrets.append(max(0.0, oracle_objective - observed_objective))
        objective += observed_objective
        security += float(choice["security_value"])
        observed_cost += float(choice["cost_observed"])
        availability += float(choice.get("availability_loss") or 0)
        slo += int(bool(choice.get("slo_violation")))
        if model_name != "c0" and key in c0 and choice.get("action") != c0[key].get("action"):
            flips += 1
    return {
        "decisions": len(regrets),
        "mean_regret": statistics.fmean(regrets) if regrets else math.nan,
        "p95_regret": percentile(regrets, 0.95),
        "cumulative_objective": objective,
        "coverage_per_cost": security / observed_cost if observed_cost > 0 else math.inf,
        "slo_violations": slo,
        "availability_loss": availability,
        "decision_flips_vs_c0": flips,
    }


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fmt(value: Any, digits: int = 6) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        if math.isnan(value):
            return "n/a"
        if math.isinf(value):
            return "inf"
        return f"{value:.{digits}f}"
    return str(value)


def json_safe(value: Any) -> Any:
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, dict):
        return {key: json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    return value


def model_prediction(row: Mapping[str, Any], model_name: str, flat_cost: float) -> float | None:
    if model_name == "c0":
        return finite(row.get("c0_cost"))
    if model_name == "c1":
        return flat_cost
    if model_name == "c2":
        return finite(row.get("c2_cost"))
    return finite(row.get("cost_observed"))


def independent_decision_check(
    rows: Sequence[dict[str, Any]],
    selected: Mapping[str, Mapping[Any, Mapping[str, Any]]],
    flat_cost: float,
) -> dict[str, int]:
    """Recompute each argmax independently and enforce the hard selection boundary."""

    groups: dict[tuple[str, int, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        if usable(row):
            groups[decision_key(row)].append(row)
    checks = failures = 0
    model_keys = {"c0": "c0_cost", "c1": None, "c2": "c2_cost", "c3": "cost_observed"}
    for model_name, cost_key in model_keys.items():
        for key, candidates in groups.items():
            eligible = [row for row in candidates if cost_key is None or finite(row.get(cost_key)) is not None]
            if not eligible:
                continue
            checks += 1
            chosen = selected[model_name].get(key)
            if chosen is None or not usable(chosen):
                failures += 1
                continue
            chosen_cost = flat_cost if cost_key is None else float(chosen[cost_key])
            chosen_objective = float(chosen["security_value"]) - float(chosen["lambda"]) * chosen_cost
            best = max(
                float(row["security_value"])
                - float(row["lambda"]) * (flat_cost if cost_key is None else float(row[cost_key]))
                for row in eligible
            )
            if abs(chosen_objective - best) > 1e-10:
                failures += 1
    return {"checks": checks, "failures": failures}


def action_coverage(
    rows: Sequence[dict[str, Any]], catalog: Sequence[Mapping[str, Any]], selected: Mapping[str, Mapping[Any, Mapping[str, Any]]]
) -> list[dict[str, Any]]:
    by_action: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_action[str(row["action"])].append(row)
    c0_actions = Counter(str(row["action"]) for row in selected["c0"].values())
    c3_actions = Counter(str(row["action"]) for row in selected["c3"].values())
    out: list[dict[str, Any]] = []
    for item in catalog:
        action = str(item["action"])
        samples = [row for row in by_action[action] if usable(row)]
        observed = [float(row["cost_observed"]) for row in samples]
        errors = [abs(float(row["c0_cost"]) - float(row["cost_observed"])) for row in samples if finite(row.get("c0_cost")) is not None]
        implemented = item.get("unexecuted_classification") != "not implemented"
        executable = action == "noop" or any(
            row.get("implementation_status") == "executable"
            and bool(row.get("emitted"))
            and not row.get("actuation_error")
            for row in samples
        )
        classification = "executable" if executable else str(item.get("unexecuted_classification", "not executable"))
        out.append(
            {
                "action": action,
                "implemented": "yes" if implemented else "no",
                "executable": "yes" if executable else "no",
                "classification": classification,
                "candidate_generated": "yes" if item.get("candidate_generated") else "no",
                "cost_model_available": "yes" if item.get("cost_model_available") else "no",
                "cost_components_used": ",".join(item.get("cost_components_used", [])),
                "observed_cost_sample_count": len(observed),
                "mean_observed_cost": statistics.fmean(observed) if observed else None,
                "c0_prediction_mae": statistics.fmean(errors) if errors else None,
                "decision_impact": f"C0 selected {c0_actions[action]} vs oracle {c3_actions[action]}",
            }
        )
    return out


def write_csv(path: Path, rows: Sequence[Mapping[str, Any]], fields: Sequence[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fields is None:
        fields = sorted({key for row in rows for key in row})
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fields), extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            cooked = {key: json.dumps(value, separators=(",", ":"), sort_keys=True) if isinstance(value, (dict, list)) else value for key, value in row.items()}
            writer.writerow(cooked)


def evaluate(args: argparse.Namespace) -> dict[str, Any]:
    rows = load_jsonl(args.input)
    catalog = json.loads(args.action_catalog.read_text())
    if not isinstance(catalog, list):
        raise ValueError("action catalog must be a JSON list")
    valid = [row for row in rows if usable(row)]
    if not valid:
        raise ValueError("no usable executed/control observations")
    train_groups, test_groups = grouped_split(valid)
    for row in rows:
        row["split"] = split_name(row, train_groups)
    train_rows = [row for row in valid if row["split"] == "train"]
    test_rows = [row for row in valid if row["split"] == "test"]
    theta = fit_nnls(train_rows, args.max_cost)
    flat_cost = statistics.fmean(float(row["cost_observed"]) for row in train_rows)
    for row in rows:
        row["c1_cost"] = flat_cost
        row["c2_cost"] = predict_c2(row, theta, args.max_cost)
        for name, key in (("c0", "c0_cost"), ("c2", "c2_cost")):
            pred, actual = finite(row.get(key)), finite(row.get("cost_observed"))
            row[f"{name}_absolute_error"] = abs(pred - actual) if pred is not None and actual is not None else None

    selected = select_decisions([row for row in test_rows if feature_vector(row) is not None], flat_cost)
    for row in rows:
        key = decision_key(row)
        for model_name in MODELS:
            row[f"selected_{model_name}"] = selected[model_name].get(key) is row

    prediction = {
        "c0": prediction_metrics(test_rows, "c0_cost"),
        "c2": prediction_metrics(test_rows, "c2_cost"),
    }
    decisions = {name: decision_metrics(selected, name) for name in MODELS}

    scenario_calibration: dict[str, dict[str, dict[str, float | int]]] = {}
    for scenario in sorted({str(row["scenario_id"]) for row in test_rows}):
        subset = [row for row in test_rows if row["scenario_id"] == scenario]
        scenario_calibration[scenario] = {
            "c0": prediction_metrics(subset, "c0_cost"),
            "c2": prediction_metrics(subset, "c2_cost"),
        }

    stability_weights: list[list[float]] = []
    for index in range(5):
        split_train, _ = grouped_split(valid, f"stability-{index}")
        subset = [row for row in valid if (str(row["scenario_id"]), int(row["seed"])) in split_train]
        stability_weights.append(fit_nnls(subset, args.max_cost))
    stability: dict[str, dict[str, float]] = {}
    for index, name in enumerate(FEATURES):
        values = [weights[index] for weights in stability_weights]
        mean_value = statistics.fmean(values)
        std = statistics.pstdev(values)
        stability[name] = {"mean": mean_value, "std": std, "cv": std / mean_value if mean_value > 1e-12 else math.inf}

    def oos_metrics(train_predicate: Any, test_predicate: Any) -> dict[str, Any]:
        fit_rows = [row for row in valid if train_predicate(row) and feature_vector(row) is not None]
        eval_rows = [dict(row) for row in valid if test_predicate(row) and feature_vector(row) is not None]
        if not fit_rows or not eval_rows:
            return {"train_n": len(fit_rows), "test_n": len(eval_rows), "c0": {}, "c2": {}}
        fitted = fit_nnls(fit_rows, args.max_cost)
        for row in eval_rows:
            row["oos_c2_cost"] = predict_c2(row, fitted, args.max_cost)
        return {
            "train_n": len(fit_rows), "test_n": len(eval_rows),
            "weights": dict(zip(FEATURES, fitted)),
            "c0": prediction_metrics(eval_rows, "c0_cost"),
            "c2": prediction_metrics(eval_rows, "oos_c2_cost"),
        }

    cross_scenario = oos_metrics(
        lambda row: str(row.get("workload_type")) in {"stateless", "stateful"},
        lambda row: str(row.get("workload_type")) in {"gpu", "rag"},
    )
    load_generalization = oos_metrics(
        lambda row: str(row.get("load_profile")) == "low",
        lambda row: str(row.get("load_profile")) in {"high", "connections", "slo-hot"},
    )

    coverage = action_coverage(rows, catalog, selected)
    coverage_path = args.output_dir / "action-cost-coverage.csv"
    write_csv(coverage_path, coverage)
    results_path = args.output_dir / "cost-validation-results.csv"
    write_csv(results_path, rows)

    weights = {name.removeprefix("c_"): value for name, value in zip(FEATURES, theta)}
    weight_doc = {
        "schema_version": SCHEMA,
        "model": "C2 nonnegative unitless formula",
        "max_cost": args.max_cost,
        "weights": weights,
        "training_samples": len(train_rows),
        "training_groups": sorted([list(group) for group in train_groups]),
        "stability": stability,
    }
    weights_path = args.output_dir / "c2-weights.json"
    weights_path.write_text(json.dumps(json_safe(weight_doc), indent=2, sort_keys=True) + "\n")

    c0_regret = float(decisions["c0"]["mean_regret"])
    c2_regret = float(decisions["c2"]["mean_regret"])
    regret_reduction = (c0_regret - c2_regret) / c0_regret if c0_regret > 0 else (1.0 if c2_regret < c0_regret else 0.0)
    active_cvs = [value["cv"] for name, value in stability.items() if weights[name.removeprefix("c_")] > 1e-9]
    stable = bool(active_cvs) and max(active_cvs) <= 0.5
    high_availability = [
        row for row in test_rows
        if finite(row.get("c_availability")) is not None and float(row["c_availability"]) >= 0.5
    ]
    high_availability_error = (
        statistics.fmean(float(row["c0_cost"]) - float(row["cost_observed"]) for row in high_availability)
        if high_availability else math.nan
    )
    checker = independent_decision_check(
        [row for row in test_rows if feature_vector(row) is not None], selected, flat_cost
    )
    component_support = {
        feature: {
            "train_positive": sum(float(row[feature]) > 0 for row in train_rows if finite(row.get(feature)) is not None),
            "test_positive": sum(float(row[feature]) > 0 for row in test_rows if finite(row.get(feature)) is not None),
        }
        for feature in FEATURES
    }
    # A zero learned coefficient is not identifiable when the component never varies.
    # Promotion requires at least three positive training witnesses and one held-out
    # witness for every coefficient in the ticket's five-term formula.
    promotion_data_sufficient = all(
        support["train_positive"] >= 3 and support["test_positive"] >= 1
        for support in component_support.values()
    )
    c0_checks = {
        "beats_flat_cumulative_objective": decisions["c0"]["cumulative_objective"] > decisions["c1"]["cumulative_objective"],
        "positive_rank_correlation": prediction["c0"]["spearman"] > 0,
        "no_systematic_high_availability_underpricing": not high_availability or high_availability_error >= 0,
        "slo_violations_no_worse_than_oracle": decisions["c0"]["slo_violations"] <= decisions["c3"]["slo_violations"],
        "independent_checker_clean": checker["failures"] == 0,
    }
    c2_checks = {
        "regret_reduction_at_least_10pct": regret_reduction >= 0.10,
        "cumulative_objective_preserved": decisions["c2"]["cumulative_objective"] >= decisions["c0"]["cumulative_objective"],
        "slo_violations_not_increased": decisions["c2"]["slo_violations"] <= decisions["c0"]["slo_violations"],
        "availability_loss_not_increased": decisions["c2"]["availability_loss"] <= decisions["c0"]["availability_loss"] + 1e-12,
        "weights_stable": stable,
    }
    c0_numeric_pass = all(c0_checks.values())
    c2_numeric_pass = all(c2_checks.values())
    c2_pass = c2_numeric_pass and promotion_data_sufficient
    recommendation = "promote the calibrated formula" if c2_pass else "keep the current formula" if c0_numeric_pass else "collect more measurements"

    provenance = {
        "schema_version": SCHEMA,
        "input": str(args.input),
        "input_sha256": sha256(args.input),
        "action_catalog": str(args.action_catalog),
        "action_catalog_sha256": sha256(args.action_catalog),
        "evaluator_revision": args.evaluator_revision,
        "evaluator_sha256": sha256(Path(__file__).resolve()),
        "environment": json.loads(args.environment.read_text()) if args.environment else {},
        "post_run_health": json.loads(args.post_run_health.read_text()) if args.post_run_health else {},
        "post_run_health_sha256": sha256(args.post_run_health) if args.post_run_health else None,
        "observation_rows": len(rows),
        "usable_rows": len(valid),
        "train_rows": len(train_rows),
        "test_rows": len(test_rows),
        "train_groups": sorted([list(group) for group in train_groups]),
        "test_groups": sorted([list(group) for group in test_groups]),
        "label": "equal-weight mean of available normalized availability, p99, TPS, Ready, state/KV, and GPU terms",
    }
    provenance_path = args.output_dir / "cost-validation-provenance.json"
    provenance_path.write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n")

    summary = {
        "schema_version": SCHEMA,
        "requested_cost_model": args.cost_model,
        "recommendation": recommendation,
        "c0_numeric_acceptance": c0_numeric_pass,
        "c0_acceptance_checks": c0_checks,
        "c2_acceptance": c2_pass,
        "c2_numeric_criteria": c2_numeric_pass,
        "c2_acceptance_checks": c2_checks,
        "c2_regret_reduction": regret_reduction,
        "c0_high_availability_mean_error": high_availability_error,
        "independent_checker": checker,
        "component_support": component_support,
        "promotion_data_sufficient": promotion_data_sufficient,
        "weights": weights,
        "prediction": prediction,
        "decisions": decisions,
        "scenario_calibration": scenario_calibration,
        "weight_stability": stability,
        "cross_scenario": cross_scenario,
        "load_generalization": load_generalization,
        "coverage": coverage,
        "provenance": provenance,
    }
    (args.output_dir / "cost-validation-summary.json").write_text(json.dumps(json_safe(summary), indent=2, sort_keys=True) + "\n")
    write_summary(args.output_dir / "cost-validation-summary.md", summary)
    return summary


def write_summary(path: Path, summary: Mapping[str, Any]) -> None:
    prediction, decisions = summary["prediction"], summary["decisions"]
    lines = [
        "# Cost Model Validation Summary",
        "",
        f"**Recommendation: {summary['recommendation']}.**",
        "",
        "This is a unitless disruption-cost benchmark. It is not a dollar/ROI calibration. "
        "C3 is an offline oracle and is never deployable. Hard feasibility remained outside the fitted objective.",
        "",
        "## Data and split",
        "",
        f"- Observations: {summary['provenance']['observation_rows']} ({summary['provenance']['usable_rows']} usable)",
        f"- Grouped 70/30 split: {len(summary['provenance']['train_groups'])} train groups / {len(summary['provenance']['test_groups'])} held-out groups",
        f"- Input SHA-256: `{summary['provenance']['input_sha256']}`",
        f"- Observed label: {summary['provenance']['label']}",
        "",
        "Missing metrics stayed explicit and were omitted from the equal-weight label; `observed_label_terms` in the raw CSV shows each row's evidence count.",
        "",
        "## Learned C2 weights",
        "",
        "| component | weight | stability mean | stability std | stability CV |",
        "|---|---:|---:|---:|---:|",
    ]
    for component in FEATURES:
        short = component.removeprefix("c_")
        stability = summary["weight_stability"][component]
        lines.append(
            f"| {short} | {fmt(summary['weights'][short])} | {fmt(stability['mean'])} | {fmt(stability['std'])} | {fmt(stability['cv'])} |"
        )
    lines += [
        "",
        "## Held-out prediction and ranking",
        "",
        "| model | n | MAE | RMSE | Spearman | Kendall tau-b | pairwise accuracy |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for name in ("c0", "c2"):
        metric = prediction[name]
        lines.append(
            f"| {name.upper()} | {metric['n']} | {fmt(metric['mae'])} | {fmt(metric['rmse'])} | {fmt(metric['spearman'])} | {fmt(metric['kendall'])} | {fmt(metric['pairwise'])} |"
        )
    lines += [
        "",
        "## Held-out decision quality",
        "",
        "| model | decisions | mean regret | p95 regret | cumulative objective | coverage/cost | SLO violations | availability loss | flips vs C0 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name in MODELS:
        metric = decisions[name]
        lines.append(
            f"| {name.upper()} | {metric['decisions']} | {fmt(metric['mean_regret'])} | {fmt(metric['p95_regret'])} | {fmt(metric['cumulative_objective'])} | {fmt(metric['coverage_per_cost'])} | {metric['slo_violations']} | {fmt(metric['availability_loss'])} | {metric['decision_flips_vs_c0']} |"
        )
    lines += [
        "",
        f"C2 held-out mean-regret change versus C0: **{fmt(100 * summary['c2_regret_reduction'], 3)}% reduction** (ticket threshold: at least 10%).",
        "",
        "## Generalization",
        "",
        "| test | train n | test n | C0 MAE | C2 MAE | C0 Spearman | C2 Spearman |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for title, key in (("stateless+stateful → GPU/RAG", "cross_scenario"), ("low load → high/connections/SLO-hot", "load_generalization")):
        metric = summary[key]
        lines.append(
            f"| {title} | {metric['train_n']} | {metric['test_n']} | {fmt(metric.get('c0', {}).get('mae', math.nan))} | {fmt(metric.get('c2', {}).get('mae', math.nan))} | {fmt(metric.get('c0', {}).get('spearman', math.nan))} | {fmt(metric.get('c2', {}).get('spearman', math.nan))} |"
        )
    lines += [
        "",
        "## Full action-cost coverage matrix",
        "",
        "| action | implemented | executable | classification | candidate | cost model | components | samples | mean observed cost | C0 MAE | decision impact |",
        "|---|---|---|---|---|---|---|---:|---:|---:|---|",
    ]
    for row in summary["coverage"]:
        lines.append(
            f"| {row['action']} | {row['implemented']} | {row['executable']} | {row['classification']} | {row['candidate_generated']} | {row['cost_model_available']} | {row['cost_components_used']} | {row['observed_cost_sample_count']} | {fmt(row['mean_observed_cost'])} | {fmt(row['c0_prediction_mae'])} | {row['decision_impact']} |"
        )
    lines += [
        "",
        "## Acceptance decision",
        "",
        f"- C0 numeric acceptance checks passed: **{str(summary['c0_numeric_acceptance']).lower()}**.",
        f"- C2 numeric improvement criteria passed: **{str(summary['c2_numeric_criteria']).lower()}**.",
        f"- C2 final promotion checks passed: **{str(summary['c2_acceptance']).lower()}**.",
        f"- Promotion data sufficiency (all five coefficients identified in train and held-out data): **{str(summary['promotion_data_sufficient']).lower()}**.",
        f"- C0 mean signed error on high-availability-risk held-out rows: **{fmt(summary['c0_high_availability_mean_error'])}** (negative means systematic underpricing).",
        f"- Independent decision checker: **{summary['independent_checker']['checks']} checks, {summary['independent_checker']['failures']} failures**.",
        "- A lower prediction error alone was not treated as promotion evidence; decision regret and SLO/availability are controlling.",
        "- Unsupported/missing-prerequisite actions remain classified in the matrix rather than silently omitted.",
        "",
        "| acceptance check | passed |",
        "|---|---|",
    ]
    for check, passed in summary["c0_acceptance_checks"].items():
        lines.append(f"| C0: {check.replace('_', ' ')} | {str(passed).lower()} |")
    for check, passed in summary["c2_acceptance_checks"].items():
        lines.append(f"| C2: {check.replace('_', ' ')} | {str(passed).lower()} |")
    lines += [
        "",
        "Component support used by the promotion gate:",
        "",
        "| component | positive train rows | positive held-out rows |",
        "|---|---:|---:|",
    ]
    for component in FEATURES:
        support = summary["component_support"][component]
        lines.append(f"| {component.removeprefix('c_')} | {support['train_positive']} | {support['test_positive']} |")
    lines += [
        "",
        "## Artifacts",
        "",
        "- `cost-validation-results.csv` — candidate inputs, outcomes, predictions, selections, and errors",
        "- `c2-weights.json` — learned nonnegative weights and repeated-split stability",
        "- `action-cost-coverage.csv` — complete action vocabulary",
        "- `cost-validation-provenance.json` — environment/input/hash/split provenance",
        "- `cost-validation-summary.json` — machine-readable metrics",
    ]
    if summary["provenance"].get("post_run_health"):
        lines.append("- `aws-post-run-health.json` — final production readiness and benchmark cleanup proof")
    lines.append("")
    path.write_text("\n".join(lines))


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="probe observation JSONL")
    parser.add_argument("--action-catalog", type=Path, required=True)
    parser.add_argument("--environment", type=Path)
    parser.add_argument("--post-run-health", type=Path)
    parser.add_argument("--evaluator-revision", default="unknown")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--max-cost", type=float, default=1.0)
    parser.add_argument(
        "--cost-model",
        choices=("all", "current", "flat", "calibrated", "observed_oracle"),
        default="all",
        help="swappable offline scoring model; all emits the required C0-C3 comparison",
    )
    args = parser.parse_args(argv)
    if not (args.max_cost > 0 and math.isfinite(args.max_cost)):
        parser.error("--max-cost must be finite and positive")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    return args


def main() -> None:
    args = parse_args()
    summary = evaluate(args)
    print(json.dumps({
        "recommendation": summary["recommendation"],
        "c0_numeric_acceptance": summary["c0_numeric_acceptance"],
        "c2_acceptance": summary["c2_acceptance"],
        "results": str(args.output_dir / "cost-validation-results.csv"),
        "summary": str(args.output_dir / "cost-validation-summary.md"),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
