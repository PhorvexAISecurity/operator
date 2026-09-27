#!/usr/bin/env python3
"""
Independent validator for Phorvex audit decision records.

Each record is a `phorvex.audit.v2` envelope carrying a nested
`decisionTrace` (`phorvex.decision-trace.v2`, v3, economics-aware v4,
flow-regime-aware v5, capacity-aware v6, or resource-exclusion-aware v7).

The laws asserted here were derived by reading the Go source, NOT by fitting
the records (see README.md for the file:line of every law):

  phorvex/internal/model/decision_trace.go   struct tags, Canonical(), Validate()
  phorvex/internal/decision/coverage.go      selection loop (~343-400),
                                             buildDecisionTrace (~604-800),
                                             strictPositiveGain / legacyMixedGain (~171-177)
  phorvex/internal/model/types.go            MutatingActions (~105-114)

Stdlib only. Python 3.10+.

Usage:
  python3 audit_trace_validator.py <path>... [--report out.md] [--json out.json] [--strict-v3]
Exit 0 iff every record PASSes (no FAIL and no UNDECIDABLE check); 1 otherwise.
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Iterator

# --------------------------------------------------------------------------- constants

TRACE_V2 = "phorvex.decision-trace.v2"
TRACE_V3 = "phorvex.decision-trace.v3"
TRACE_V4 = "phorvex.decision-trace.v4"
TRACE_V5 = "phorvex.decision-trace.v5"
TRACE_V6 = "phorvex.decision-trace.v6"
TRACE_V7 = "phorvex.decision-trace.v7"
AUDIT_V2 = "phorvex.audit.v2"

ECON_LEGACY = "legacy-runtime-lambda-v1"
ECON_FIXED = "fixed-disruption-aversion-v1"
COEFF_LAMBDA = "lambdaRuntimeLegacy"
COEFF_BETA = "disruptionAversion"
MAX_COEFFICIENT = 10.0
FLOW_SEMANTICS_V1 = "conservative-regime-v1"
FLOW_MAXIMUM = 2.0

# decision_trace.go:25-29
COST_REPR_V1 = "weighted_dimensionless_v1"
CFLOW_UNIT = "confirmed_dimensionless_disruption_loss"
SELECTOR = "strict_gain_positive"
SELECTOR_M99 = "m99_bounded_full_containment"

# Canonical action order. Hard-coded copy of `MutatingActions` in
# phorvex/internal/model/types.go lines ~105-114 (the SINGLE SOURCE OF TRUTH
# comment there says order is load-bearing: rotate precedes quarantine so the
# strict-`>` tie-break stays byte-identical). The historical unmarked trace
# vocabulary is frozen at 15; output16 and voice17 retain exact later orders.
LEGACY_MUTATING_ACTIONS = [
    "rotate", "quarantine",
    "debugger", "custom-inject",
    "identity-rotate", "route-rotate",
    "warm-swap", "mig-rebind", "kv-reset", "endpoint-rotate", "model-shard-replace",
    "adapter-rotate", "request-drain", "guardrail-rotate", "kv-migrate-invalidate",
]
OUTPUT16_ACTIONS = LEGACY_MUTATING_ACTIONS + ["sensitive-output-policy-activate"]
VOICE17_ACTIONS = OUTPUT16_ACTIONS + ["voice-memory-note-revoke"]
LITELLM17_ACTIONS = OUTPUT16_ACTIONS + ["litellm-client-revoke"]
LIVE18_ACTIONS = OUTPUT16_ACTIONS + ["voice-memory-note-revoke", "litellm-client-revoke"]
MUTATING_ACTIONS = LIVE18_ACTIONS + ["voice-refund-pair-deny"]
ACTION_VOCABULARY_OUTPUT16 = "v2-output16"
ACTION_VOCABULARY_VOICE17 = "v3-voice17"
ACTION_VOCABULARY_LITELLM17 = "v3-litellm17"
ACTION_VOCABULARY_LIVE18 = "v4-live18"
ACTION_VOCABULARY_LIVE19 = "v5-live19"
ACTION_RANK = {a: i for i, a in enumerate(MUTATING_ACTIONS)}


def trace_action_vocabulary(tr: dict) -> tuple[list[str] | None, str | None]:
    if "actionVocabularyVersion" not in tr:
        return LEGACY_MUTATING_ACTIONS, None
    version = tr["actionVocabularyVersion"]
    if version == "":
        return LEGACY_MUTATING_ACTIONS, None
    if tr.get("schemaVersion") == TRACE_V2:
        return None, "decisionTrace.actionVocabularyVersion is not defined for v2 traces"
    if version == ACTION_VOCABULARY_OUTPUT16:
        return OUTPUT16_ACTIONS, None
    if version == ACTION_VOCABULARY_VOICE17:
        return VOICE17_ACTIONS, None
    if version == ACTION_VOCABULARY_LITELLM17:
        return LITELLM17_ACTIONS, None
    if version == ACTION_VOCABULARY_LIVE18:
        return LIVE18_ACTIONS, None
    if version == ACTION_VOCABULARY_LIVE19:
        return MUTATING_ACTIONS, None
    return None, f"decisionTrace.actionVocabularyVersion={version!r} is unknown"

# Candidate selectionReason strings, verbatim from coverage.go buildDecisionTrace.
SR_SELECTED = "selected_strict_positive_gain"
SR_REACTIVE_ONLY = "reactive_only_no_direct_foothold"
SR_PARTITION = "partition_other_action_selected"
SR_BUDGET = "move_budget_exhausted"
SR_NOT_EVAL = "not_evaluated_by_current_greedy"
SR_NOT_POSITIVE = "strict_gain_not_positive"
SR_NOT_SELECTED = "not_selected_by_current_greedy_ranking"
SR_EXCLUSION = "existing_generator_exclusion"

# noopReason strings, verbatim from coverage.go buildDecisionTrace (else-branch).
NOOP_REACTIVE = "reactive-only: no direct foothold"
NOOP_NO_CANDIDATE = "no candidate generated"
NOOP_PRICED_OUT = "priced-out: no net-positive feasible move"
NOOP_BUDGET = "budget-exhausted"
NOOP_NOT_SELECTED = "not selected by current greedy round"

TOL = 1e-9  # decision_trace.go Validate(): math.Abs(want-got) > 1e-9

# V3/V4 vocabularies mirrored from internal/model/decision_trace.go.
V3_STATUS = {"not-enabled", "not-installable", "no-cover", "candidate", "infeasible",
             "conformal-slo", "priced-out", "budget-exhausted", "selected",
             "not-evaluated-by-current-model", "ineligible"}
V3_EXCLUSION_KIND = {"not-enabled", "recon-cover", "feasibility", "cost-nan",
                     "slo-gate", "reactive-only", "selection", "none",
                     "not-installable", "no-rbac", "capability-unsupported",
                     "action-failure-cooldown", "operator-opt-out"}
V3_INELIGIBLE_EXCLUSIONS = {"no-rbac", "capability-unsupported",
                            "action-failure-cooldown", "operator-opt-out"}
V3_DISPATCH = {"not-attempted", "emitted", "emitted-false", "dispatch-error",
               "refused-no-effect", "already-satisfied", "reconciled-no-new-mutation",
               "declared-only"}

# Redaction patterns: the task's four, plus the Go patterns from decision_trace.go:189-192.
SECRET_PATTERNS = [
    ("bearer", re.compile(r"(?i)bearer\s+\S+")),
    ("authorization", re.compile(r"(?i)authorization\s*[:=]")),
    ("uri-userinfo", re.compile(r"://[^/@\s]+:[^/@\s]+@")),
    ("secret-kv", re.compile(r"(?i)(api[_-]?key|password|token|credential)\s*[:=]\s*\S+")),
    ("go-secret-kv", re.compile(r"(?i)\b(x-api-key|api[_-]?key|password|passwd|token|credential)\s*[:=]\s*[^\s,;]+")),
]

PASS, FAIL, SKIPPED, UNDECIDABLE = "PASS", "FAIL", "SKIPPED", "UNDECIDABLE"


# --------------------------------------------------------------------------- helpers

INFO_NOTES: list[str] = []  # informational, never affects pass/fail

@dataclass
class Opt:
    """A `{present, value}` optional as read from JSON, with its field path."""
    path: str
    present: bool | None          # None = malformed (missing/non-bool `present`)
    value: Any
    malformed: str = ""           # human-readable reason when not well-formed

    @property
    def ok(self) -> bool:
        """True iff well-formed AND present. Absent optionals are never treated as 0."""
        return self.present is True and not self.malformed

    @property
    def num(self) -> float:
        return float(self.value)


def optional(container: Any, key: str, path: str) -> Opt:
    """Read `container[key]` as a `{present, value}` object without ever defaulting to 0."""
    p = f"{path}.{key}"
    if not isinstance(container, dict) or key not in container:
        return Opt(p, None, None, "missing")
    raw = container[key]
    if not isinstance(raw, dict):
        return Opt(p, None, raw, f"not an object ({type(raw).__name__})")
    if "present" not in raw or not isinstance(raw["present"], bool):
        return Opt(p, None, raw.get("value"), "`present` missing or not boolean")
    if "value" not in raw:
        return Opt(p, raw["present"], None, "`value` missing")
    val = raw["value"]
    if raw["present"] and isinstance(val, (int, float)) and not isinstance(val, bool):
        if not math.isfinite(val):
            return Opt(p, True, val, "non-finite value")
    return Opt(p, raw["present"], val)


def approx(a: float, b: float) -> bool:
    """|a-b| <= 1e-9 absolute (Validate()) OR <= 1e-9 relative."""
    d = abs(a - b)
    return d <= TOL or d <= TOL * max(abs(a), abs(b))


def s(x: Any) -> str:
    return json.dumps(x, sort_keys=True) if not isinstance(x, str) else x


@dataclass
class Check:
    num: int
    name: str
    status: str
    message: str


@dataclass
class RecordResult:
    source: str
    decision_id: str
    tenant_pod: str
    trace_version: str
    brain_image: str
    selected_action: str
    checks: list[Check] = field(default_factory=list)
    census: dict[str, list[int]] = field(default_factory=dict)  # path -> [present, absent]

    @property
    def status(self) -> str:
        st = {c.status for c in self.checks}
        if FAIL in st:
            return FAIL
        if UNDECIDABLE in st:
            return UNDECIDABLE
        return PASS

    def failed(self) -> list[Check]:
        return [c for c in self.checks if c.status in (FAIL, UNDECIDABLE)]


def is_excluded(c: dict) -> bool:
    """Excluded-by-generator rows (coverage.go: TieBreakRank -1, selectionReason existing_generator_exclusion)."""
    return c.get("selectionReason") == SR_EXCLUSION or c.get("tieBreakRank", 0) == -1


def cover_keys(c: dict) -> list[str]:
    # Go marshals a nil []string as JSON null; treat null as an empty list.
    ck = c.get("coverKeys")
    return list(ck) if isinstance(ck, list) else []


def cand_path(i: int) -> str:
    return f"decisionTrace.candidates[{i}]"


# --------------------------------------------------------------------------- checks

def check_schema(rec: dict, tr: dict) -> Check:
    problems = []
    env = rec.get("schemaVersion")
    if env != AUDIT_V2:
        problems.append(f"schemaVersion={env!r} (want {AUDIT_V2!r})")
    tv = tr.get("schemaVersion")
    if tv not in (TRACE_V2, TRACE_V3, TRACE_V4, TRACE_V5, TRACE_V6, TRACE_V7):
        problems.append(f"decisionTrace.schemaVersion={tv!r} (want v2, v3, v4, v5, v6, or v7)")
    if problems:
        return Check(1, "schema", FAIL, "; ".join(problems))
    return Check(1, "schema", PASS, f"envelope {AUDIT_V2}; trace {tv}")


def check_identity(tr: dict) -> Check:
    # decision_trace.go Validate(): brainImage, gitSHA, decisionID, tickID, policyUID, assetUID mandatory
    missing = [f"decisionTrace.{k}" for k in
               ("brainImage", "gitSHA", "decisionID", "tickID", "policyUID", "assetUID")
               if not isinstance(tr.get(k), str) or tr.get(k) == ""]
    if missing:
        return Check(2, "identity", FAIL, "empty or missing: " + ", ".join(missing))
    return Check(2, "identity", PASS, "all six identity fields non-empty")


def walk_optionals(node: Any, path: str) -> Iterator[tuple[str, Any]]:
    """Yield (path, raw) for every object shaped like {present, value}."""
    if isinstance(node, dict):
        if set(node.keys()) == {"present", "value"}:
            yield path, node
            return
        for k, v in node.items():
            yield from walk_optionals(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from walk_optionals(v, f"{path}[{i}]")


def check_presence(tr: dict, census: dict[str, list[int]]) -> Check:
    bad = []
    n_present = n_absent = 0
    for path, raw in walk_optionals(tr, "decisionTrace"):
        pres = raw.get("present")
        if not isinstance(pres, bool):
            bad.append(f"{path}.present is {pres!r}, not boolean")
            continue
        val = raw.get("value")
        if pres and isinstance(val, (int, float)) and not isinstance(val, bool) and not math.isfinite(val):
            bad.append(f"{path}.value is non-finite while present=true")
        key = re.sub(r"\[\d+\]", "[]", path)
        census.setdefault(key, [0, 0])[0 if pres else 1] += 1
        if pres:
            n_present += 1
        else:
            n_absent += 1
    # Top-level float fields must be finite too (Validate()).
    for k in ("lambdaConfiguredSeed", "lambdaRuntime", "lambdaConfiguredPolicy", "lambdaRuntimeLegacy",
              "normWeight", "flowWeight"):
        v = tr.get(k)
        if not isinstance(v, (int, float)) or isinstance(v, bool) or not math.isfinite(v):
            bad.append(f"decisionTrace.{k} is not a finite number ({v!r})")
        elif k in ("normWeight", "flowWeight") and v < 0:
            bad.append(f"decisionTrace.{k}={v!r} must be non-negative")
    for k in ("lambdaConfiguredSeed", "lambdaRuntime", "lambdaConfiguredPolicy", "lambdaRuntimeLegacy"):
        v = tr.get(k)
        if isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) and not (0 <= v <= MAX_COEFFICIENT):
            bad.append(f"decisionTrace.{k}={v!r} is outside [0,{MAX_COEFFICIENT:g}]")
    du = tr.get("dualUpdate") or {}
    for k in ("lambdaBefore", "lambdaAfter"):
        v = du.get(k)
        if not isinstance(v, (int, float)) or isinstance(v, bool) or not math.isfinite(v):
            bad.append(f"decisionTrace.dualUpdate.{k} is not a finite number ({v!r})")
        elif not (0 <= v <= MAX_COEFFICIENT):
            bad.append(f"decisionTrace.dualUpdate.{k}={v!r} is outside [0,{MAX_COEFFICIENT:g}]")
    if bad:
        return Check(3, "presence-flags", FAIL, "; ".join(bad))
    return Check(3, "presence-flags", PASS,
                 f"{n_present + n_absent} optionals well-formed ({n_present} present, {n_absent} absent)")


def check_selection_reference(rec: dict, tr: dict) -> Check:
    # decision_trace.go Validate() lines ~421-430
    cands = tr.get("candidates") or []
    sel_action = tr.get("selectedAction")
    sel_key = tr.get("selectedCandidateKey", "")
    selected_idx = [i for i, c in enumerate(cands) if c.get("selected") is True]
    problems = []
    if sel_action == "noop":
        if selected_idx:
            problems.append("noop trace but selected=true on " + ", ".join(cand_path(i) for i in selected_idx))
        if sel_key:
            problems.append(f"noop trace but decisionTrace.selectedCandidateKey={sel_key!r}")
        if not tr.get("noopReason"):
            problems.append("noop trace but decisionTrace.noopReason empty/missing")
    else:
        if len(selected_idx) != 1:
            problems.append(f"expected exactly one selected candidate, found {len(selected_idx)}"
                            + (" (" + ", ".join(cand_path(i) for i in selected_idx) + ")" if selected_idx else ""))
        if not sel_key:
            problems.append("decisionTrace.selectedCandidateKey empty/missing on a selected trace")
        if len(selected_idx) == 1:
            c = cands[selected_idx[0]]
            p = cand_path(selected_idx[0])
            if c.get("candidateKey") != sel_key:
                problems.append(f"{p}.candidateKey={c.get('candidateKey')!r} != selectedCandidateKey={sel_key!r}")
            if c.get("action") != sel_action:
                problems.append(f"{p}.action={c.get('action')!r} != selectedAction={sel_action!r}")
            expected_reason = "selected_full_containment" if tr.get("selectorComparator") == SELECTOR_M99 else SR_SELECTED
            if c.get("selectionReason") != expected_reason:
                problems.append(f"{p}.selectionReason={c.get('selectionReason')!r} (want {expected_reason!r})")
        if tr.get("noopReason"):
            problems.append(f"selected trace carries noopReason={tr.get('noopReason')!r}")
    # envelope cross-reference (same record, cheap). The envelope's `action` is authoritative
    # only when selected=true: on an unselected record the v2 envelope names the best standalone
    # candidate as a FALLBACK (coverage.go fallback branch; register M-16 residual) while the
    # trace says noop. That disagreement is a known, out-of-T0-C-scope envelope quirk, so it is
    # reported as information, not as a reconstruction failure of the trace.
    if "action" in rec and rec["action"] != sel_action:
        if rec.get("selected") is True:
            problems.append(f"envelope action={rec['action']!r} != decisionTrace.selectedAction={sel_action!r}")
        else:
            INFO_NOTES.append(f"{tr.get('decisionID','?')[:12]}: envelope action={rec['action']!r} names the fallback candidate on an unselected record (M-16 residual); trace says {sel_action!r}")
    if "selected" in rec and rec["selected"] != (sel_action != "noop"):
        problems.append(f"envelope selected={rec['selected']!r} inconsistent with selectedAction={sel_action!r}")
    if problems:
        return Check(4, "selection-reference", FAIL, "; ".join(problems))
    return Check(4, "selection-reference", PASS,
                 f"selectedAction={sel_action!r}" + (f", key={sel_key!r}" if sel_key else ", no selected candidate"))


def check_ecost(tr: dict) -> Check:
    # decision_trace.go Validate() ~397-402; coverage.go: ECost = NormSparsity*Norm + FlowDisruption*Flow
    nw, fw = tr.get("normWeight"), tr.get("flowWeight")
    if not isinstance(nw, (int, float)) or not isinstance(fw, (int, float)):
        return Check(5, "ecost-law", FAIL, "decisionTrace.normWeight / flowWeight missing or non-numeric")
    fails, checked, skipped = [], 0, []
    for i, c in enumerate(tr.get("candidates") or []):
        p = cand_path(i)
        cn, cf, ec = optional(c, "cNorm", p), optional(c, "cFlow", p), optional(c, "expectedCost", p)
        absent = [o.path for o in (cn, cf, ec) if not o.ok]
        if absent:
            skipped.append(f"{p}: absent {', '.join(a.rsplit('.', 1)[1] for a in absent)}")
            continue
        want = nw * cn.num + fw * cf.num
        checked += 1
        if not approx(want, ec.num):
            fails.append(f"{ec.path}={ec.num!r} but normWeight*cNorm+flowWeight*cFlow={want!r}")
    if fails:
        return Check(5, "ecost-law", FAIL, "; ".join(fails))
    if checked == 0:
        return Check(5, "ecost-law", SKIPPED, "no candidate has cNorm, cFlow and expectedCost all present: "
                     + "; ".join(skipped))
    msg = f"{checked} candidate(s) reconstruct"
    if skipped:
        msg += f"; skipped {len(skipped)}: " + "; ".join(skipped)
    return Check(5, "ecost-law", PASS, msg)


def check_netgain(tr: dict) -> Check:
    # decision_trace.go Validate() ~390-396; coverage.go legacyMixedGain + lambdaContribution = lambda*ECost
    has_v4 = tr.get("schemaVersion") in (TRACE_V4, TRACE_V5, TRACE_V6, TRACE_V7)
    fixed = has_v4 and tr.get("economicsVersion") == ECON_FIXED
    coefficient = tr.get("effectiveCostCoefficient") if has_v4 else tr.get("lambdaRuntime")
    contribution_key = "objectiveCostContribution" if fixed else "lambdaContribution"
    fails, checked, skipped = [], 0, []
    for i, c in enumerate(tr.get("candidates") or []):
        p = cand_path(i)
        mc, pv, contribution, ng, ec = (optional(c, k, p) for k in
                                        ("marginalCoverage", "provenance", contribution_key, "netGain", "expectedCost"))
        if contribution.ok and ec.ok and isinstance(coefficient, (int, float)):
            want = coefficient * ec.num
            checked += 1
            if not approx(want, contribution.num):
                fails.append(f"{contribution.path}={contribution.num!r} but effective coefficient*expectedCost={want!r}")
        absent = [o for o in (mc, pv, contribution, ng) if not o.ok]
        if absent:
            skipped.append(f"{p}: absent {', '.join(o.path.rsplit('.', 1)[1] for o in absent)}")
            continue
        want = mc.num * pv.num - contribution.num
        checked += 1
        if not approx(want, ng.num):
            fails.append(f"{ng.path}={ng.num!r} but marginalCoverage*provenance-lambdaContribution={want!r}")
    if fails:
        return Check(6, "netgain-law", FAIL, "; ".join(fails))
    if checked == 0:
        return Check(6, "netgain-law", SKIPPED, "no candidate carries the terms: " + "; ".join(skipped))
    msg = f"{checked} identity(ies) reconstruct"
    if skipped:
        msg += f"; netGain skipped on {len(skipped)}: " + "; ".join(skipped)
    return Check(6, "netgain-law", PASS, msg)


def check_selection_reconstruction(tr: dict) -> Check:
    """P-C1. Replays coverage.go's greedy (lines ~343-380) + noopReason switch (~776-798)."""
    cands = tr.get("candidates") or []
    budget, spent = tr.get("budget"), tr.get("movesSpent")
    sel_action, sel_key, noop = tr.get("selectedAction"), tr.get("selectedCandidateKey", ""), tr.get("noopReason", "") or ""
    is_noop = sel_action == "noop"
    if not isinstance(budget, int) or not isinstance(spent, int):
        return Check(7, "selection-reconstruction", FAIL, "decisionTrace.budget / movesSpent missing or non-integer")

    generated = [(i, c) for i, c in enumerate(cands) if not is_excluded(c)]
    problems = []

    if tr.get("selectorComparator") == SELECTOR_M99 and not is_noop:
        selected = [(i, c) for i, c in generated if c.get("selected") is True]
        existential = tr.get("existential") or {}
        if len(selected) != 1:
            problems.append(f"M99 trace has {len(selected)} selected generated candidates")
        else:
            i, candidate = selected[0]
            proof = candidate.get("existential") or {}
            if not (proof.get("present") is True and proof.get("trustedEvidence") is True and
                    proof.get("constraintApplied") is True and proof.get("contains") is True):
                problems.append(f"{cand_path(i)} lacks trusted full-containment proof")
            if candidate.get("selectionReason") != "selected_full_containment":
                problems.append(f"{cand_path(i)} does not record selected_full_containment")
        if not (existential.get("present") is True and existential.get("trustedEvidence") is True and
                existential.get("constraintApplied") is True and existential.get("result") == "selected"):
            problems.append("decisionTrace.existential does not record a trusted selected constraint")
        if problems:
            return Check(7, "selection-reconstruction", FAIL, "; ".join(problems))
        return Check(7, "selection-reconstruction", PASS,
                     "M99 selected candidate carries trusted full-containment proof; ordinary net gain is informational")

    # Gate 1: reactiveOnly. The greedy skips un-attacked assets before scoring, so
    # every generated candidate carries reactive_only_no_direct_foothold and no netGain.
    reactive = [(i, c) for i, c in generated if c.get("selectionReason") == SR_REACTIVE_ONLY]
    if reactive:
        others = [cand_path(i) for i, c in generated if c.get("selectionReason") != SR_REACTIVE_ONLY]
        if others:
            problems.append("reactive-only gate is per-asset but these generated candidates are not flagged: "
                            + ", ".join(others))
        with_gain = [optional(c, "netGain", cand_path(i)).path for i, c in reactive
                     if optional(c, "netGain", cand_path(i)).ok]
        if with_gain:
            problems.append("reactive-only candidates were never scored yet carry netGain: " + ", ".join(with_gain))
        if not is_noop:
            problems.append(f"reactive-only gate active but selectedAction={sel_action!r}")
        if not noop.startswith("reactive-only"):
            problems.append(f"expected noopReason {NOOP_REACTIVE!r}, got {noop!r}")
        if problems:
            return Check(7, "selection-reconstruction", FAIL, "; ".join(problems))
        return Check(7, "selection-reconstruction", PASS,
                     f"reactive-only gate: {len(reactive)} generated candidate(s) skipped before scoring -> noop; "
                     f"noopReason consistent")

    # Gate 2: nothing generated.
    if not generated:
        if not is_noop:
            return Check(7, "selection-reconstruction", FAIL,
                         f"no generated candidate but selectedAction={sel_action!r}")
        if not cands and noop != NOOP_NO_CANDIDATE:
            problems.append(f"candidates empty: expected noopReason {NOOP_NO_CANDIDATE!r}, got {noop!r}")
        if cands and noop == NOOP_NO_CANDIDATE:
            problems.append(f"{len(cands)} excluded candidate(s) recorded but noopReason={NOOP_NO_CANDIDATE!r}")
        if problems:
            return Check(7, "selection-reconstruction", FAIL, "; ".join(problems))
        return Check(7, "selection-reconstruction", PASS,
                     f"no feasible candidate generated ({len(cands)} generator exclusion(s)) -> noop; "
                     f"noopReason={noop!r}")

    # Scoring. Every generated candidate of an asset is scored in the same round,
    # so netGain must be present on all or none.
    scored = [(i, c, optional(c, "netGain", cand_path(i))) for i, c in generated]
    present = [(i, c, o) for i, c, o in scored if o.ok]
    absent = [(i, c, o) for i, c, o in scored if not o.ok]
    if not present:
        missing = ", ".join(o.path for _, _, o in absent)
        reasons = sorted({c.get("selectionReason") for _, c, _ in absent})
        if budget <= 0 and is_noop:
            return Check(7, "selection-reconstruction", PASS,
                         f"budget={budget} <= 0: greedy never ran, noop forced (selectionReasons {reasons})")
        return Check(7, "selection-reconstruction", UNDECIDABLE,
                     f"no generated candidate carries netGain (absent: {missing}; selectionReasons {reasons}); "
                     f"the greedy argmax cannot be reconstructed from this record")
    if absent:
        problems.append("partially scored asset: netGain absent on " + ", ".join(o.path for _, _, o in absent))

    # argmax by netGain, ties -> lower tieBreakRank (coverage.go: strict `>` in candidate order)
    best_i, best_c, best_o = min(present, key=lambda t: (-t[2].num, t[1].get("tieBreakRank", 0)))
    best_gain = best_o.num
    best_path = cand_path(best_i)
    positive = best_gain > 0  # strictPositiveGain: no epsilon, equality fails

    if positive and budget > 0 and spent < budget:
        expected = "select"
    elif positive and budget > 0 and spent == budget:
        expected = "select-or-budget"  # this asset may have consumed the slot, or another asset did
    else:
        expected = "noop"

    if is_noop:
        if expected == "select":
            problems.append(f"{best_path}.netGain={best_gain!r} > 0 with budget={budget}, movesSpent={spent} "
                            f"(capacity left) but record is noop")
        elif expected == "select-or-budget":
            if noop != NOOP_BUDGET:
                problems.append(f"positive gain and movesSpent==budget: expected noopReason {NOOP_BUDGET!r}, got {noop!r}")
        else:
            if not positive and not noop.startswith("priced-out"):
                problems.append(f"best netGain={best_gain!r} <= 0: expected noopReason {NOOP_PRICED_OUT!r}, got {noop!r}")
            if positive and budget <= 0 and noop != NOOP_BUDGET:
                problems.append(f"positive gain but budget={budget}: expected noopReason {NOOP_BUDGET!r}, got {noop!r}")
        if not positive:
            wrong = [cand_path(i) for i, c, o in present if c.get("selectionReason") != SR_NOT_POSITIVE]
            if wrong:
                problems.append(f"netGain <= 0 everywhere yet selectionReason != {SR_NOT_POSITIVE!r} on " + ", ".join(wrong))
    else:
        if expected == "noop":
            why = f"netGain={best_gain!r} not > 0" if not positive else f"budget={budget}, movesSpent={spent}"
            problems.append(f"record selected {sel_action!r} but reconstruction says noop ({why})")
        else:
            if best_c.get("candidateKey") != sel_key:
                problems.append(f"argmax is {best_path} ({best_c.get('candidateKey')!r}, netGain={best_gain!r}) "
                                f"but selectedCandidateKey={sel_key!r}")
            if best_c.get("action") != sel_action:
                problems.append(f"argmax action {best_c.get('action')!r} != selectedAction {sel_action!r}")
            if not best_c.get("selected"):
                problems.append(f"{best_path}.selected is not true")
            sr = optional(tr, "selectionRound", "decisionTrace")
            if not sr.ok or not (1 <= int(sr.value) <= budget):
                problems.append(f"decisionTrace.selectionRound must be present in 1..budget on a selected trace "
                                f"(got present={sr.present}, value={sr.value!r})")
            losers = [cand_path(i) for i, c, _ in present
                      if i != best_i and c.get("selectionReason") != SR_PARTITION]
            if losers:
                problems.append(f"other scored candidates should read {SR_PARTITION!r}: " + ", ".join(losers))
    if problems:
        return Check(7, "selection-reconstruction", FAIL, "; ".join(problems))
    tie = sum(1 for _, _, o in present if o.num == best_gain)
    return Check(7, "selection-reconstruction", PASS,
                 f"argmax {best_c.get('candidateKey')!r} netGain={best_gain!r} "
                 f"({'tie of %d broken by tieBreakRank' % tie if tie > 1 else 'unique'}); "
                 f"budget={budget}, movesSpent={spent} -> {'noop' if is_noop else sel_action!r} as recorded")


def check_ordering(tr: dict) -> Check:
    # decision_trace.go Canonical(): facts by factKey; candidates by asset|rank|key; coverKeys sorted
    problems = []
    facts = tr.get("facts") or []
    keys = [f.get("factKey") for f in facts]
    if keys != sorted(keys, key=lambda k: k or ""):
        first = next(i for i in range(1, len(keys)) if keys[i] < keys[i - 1])
        problems.append(f"decisionTrace.facts not sorted by factKey (first inversion at facts[{first}]={keys[first]!r})")
    if len(set(keys)) != len(keys) or any(not k for k in keys):
        problems.append("decisionTrace.facts has empty or duplicate factKey")

    cands = tr.get("candidates") or []
    vocabulary, vocabulary_error = trace_action_vocabulary(tr)
    if vocabulary_error:
        problems.append(vocabulary_error)
        vocabulary = []
    rank = {action: i for i, action in enumerate(vocabulary)}

    def asset_key(ck: str) -> str:
        at = ck.rfind("|")
        return ck[:at] if at >= 0 else ck

    def sort_key(c: dict):
        ck = c.get("candidateKey") or ""
        return (asset_key(ck), rank.get(c.get("action"), len(vocabulary)), ck)

    order = [sort_key(c) for c in cands]
    if order != sorted(order):
        first = next(i for i in range(1, len(order)) if order[i] < order[i - 1])
        problems.append(f"decisionTrace.candidates not in canonical order (first inversion at "
                        f"{cand_path(first)}: action={cands[first].get('action')!r} after "
                        f"{cands[first - 1].get('action')!r})")
    ckeys = [c.get("candidateKey") for c in cands]
    if len(set(ckeys)) != len(ckeys) or any(not k for k in ckeys):
        problems.append("decisionTrace.candidates has empty or duplicate candidateKey")
    unknown = [f"{cand_path(i)}.action={c.get('action')!r}" for i, c in enumerate(cands)
               if c.get("action") not in rank]
    if unknown:
        problems.append("action not in MutatingActions: " + ", ".join(unknown))
    for i, c in enumerate(cands):
        ck = cover_keys(c)
        if ck != sorted(ck):
            problems.append(f"{cand_path(i)}.coverKeys not sorted")
        expected_prefix = f"{tr.get('assetNamespace')}/{tr.get('assetName')}|{c.get('action')}"
        if c.get("candidateKey") != expected_prefix:
            problems.append(f"{cand_path(i)}.candidateKey={c.get('candidateKey')!r} != "
                            f"assetNamespace/assetName|action={expected_prefix!r}")
    if problems:
        return Check(8, "ordering", FAIL, "; ".join(problems))
    return Check(8, "ordering", PASS,
                 f"{len(facts)} facts sorted; {len(cands)} candidates in canonical order; coverKeys sorted")


def check_cover_keys_resolve(tr: dict) -> Check:
    fact_keys = {f.get("factKey") for f in tr.get("facts") or []}
    unresolved = []
    total = 0
    for i, c in enumerate(tr.get("candidates") or []):
        for j, k in enumerate(cover_keys(c)):
            total += 1
            if k not in fact_keys:
                unresolved.append(f"{cand_path(i)}.coverKeys[{j}]={k!r}")
    if unresolved:
        return Check(9, "cover-keys-resolve", FAIL, "unresolved: " + ", ".join(unresolved))
    return Check(9, "cover-keys-resolve", PASS, f"{total} cover key(s) all resolve to facts[].factKey")


def check_dual_update(tr: dict) -> Check:
    # decision_trace.go Validate() ~406-419
    crv = tr.get("costRepresentationVersion", "")
    if not crv:
        return Check(10, "dual-update", SKIPPED, "costRepresentationVersion empty (pre-T0-B record)")
    problems = []
    if crv != COST_REPR_V1:
        problems.append(f"decisionTrace.costRepresentationVersion={crv!r} (want {COST_REPR_V1!r})")
    if tr.get("cFlowUnitStatus") != CFLOW_UNIT:
        problems.append(f"decisionTrace.cFlowUnitStatus={tr.get('cFlowUnitStatus')!r} (want {CFLOW_UNIT!r})")
    if tr.get("selectorComparator") not in (SELECTOR, SELECTOR_M99):
        problems.append(f"decisionTrace.selectorComparator={tr.get('selectorComparator')!r} is unknown")
    if tr.get("lambdaConfiguredPolicy") != tr.get("lambdaConfiguredSeed"):
        problems.append("decisionTrace.lambdaConfiguredPolicy != lambdaConfiguredSeed")
    if tr.get("lambdaRuntimeLegacy") != tr.get("lambdaRuntime"):
        problems.append("decisionTrace.lambdaRuntimeLegacy != lambdaRuntime")
    du = tr.get("dualUpdate")
    if not isinstance(du, dict):
        problems.append("decisionTrace.dualUpdate missing")
    else:
        pairs = [("demand", "candidateDemand"), ("spent", "movesSpent"), ("budget", "budget"),
                 ("lambdaBefore", "lambdaRuntimeLegacy")]
        for a, b in pairs:
            if du.get(a) != tr.get(b):
                problems.append(f"decisionTrace.dualUpdate.{a}={du.get(a)!r} != decisionTrace.{b}={tr.get(b)!r}")
        try:
            want = tr["candidateDemand"] - tr["budget"]
            if du.get("rawExcess") != want:
                problems.append(f"decisionTrace.dualUpdate.rawExcess={du.get('rawExcess')!r} != "
                                f"candidateDemand-budget={want!r}")
        except (KeyError, TypeError):
            problems.append("decisionTrace.candidateDemand / budget missing for rawExcess")
        if not du.get("updateReason"):
            problems.append("decisionTrace.dualUpdate.updateReason empty")
    if problems:
        return Check(10, "dual-update", FAIL, "; ".join(problems))
    return Check(10, "dual-update", PASS,
                 f"demand/spent/budget/rawExcess/lambdaBefore agree; updateReason={du.get('updateReason')!r}")


def walk_strings(node: Any, path: str) -> Iterator[tuple[str, str]]:
    if isinstance(node, str):
        yield path, node
    elif isinstance(node, dict):
        for k, v in node.items():
            yield from walk_strings(k, f"{path}.<key>")
            yield from walk_strings(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from walk_strings(v, f"{path}[{i}]")


def check_redaction(rec: dict) -> Check:
    hits = []
    n = 0
    for path, text in walk_strings(rec, "record"):
        n += 1
        for name, pat in SECRET_PATTERNS:
            m = pat.search(text)
            if m:
                hits.append(f"{path} matches {name} ({m.group(0)[:40]!r})")
                break
    if hits:
        return Check(11, "redaction", FAIL, "; ".join(hits))
    return Check(11, "redaction", PASS, f"{n} strings scanned, no secret-shaped content")


def check_economics(rec: dict, tr: dict) -> Check:
    """Reconstruct the V4 scoring coefficient and exact trace-off audit descriptor."""
    if tr.get("schemaVersion") not in (TRACE_V4, TRACE_V5, TRACE_V6, TRACE_V7):
        return Check(13, "economics-v4", SKIPPED, "trace is v2/v3; economics metadata is not required")

    problems = []
    mode = tr.get("economicsVersion")
    source = tr.get("costCoefficientSource")
    coefficient = tr.get("effectiveCostCoefficient")
    runtime = tr.get("lambdaRuntimeLegacy")
    for name, value in (("effectiveCostCoefficient", coefficient), ("lambdaRuntimeLegacy", runtime)):
        if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value) or not (0 <= value <= MAX_COEFFICIENT):
            problems.append(f"decisionTrace.{name}={value!r} is not a finite coefficient in [0,{MAX_COEFFICIENT:g}]")

    beta = optional(tr, "disruptionAversion", "decisionTrace")
    if mode == ECON_LEGACY:
        if "disruptionAversion" in tr:
            problems.append("legacy V4 must omit decisionTrace.disruptionAversion")
        if source != COEFF_LAMBDA:
            problems.append(f"legacy V4 costCoefficientSource={source!r}, want {COEFF_LAMBDA!r}")
        if coefficient != runtime:
            problems.append("legacy V4 effectiveCostCoefficient != exact lambdaRuntimeLegacy")
    elif mode == ECON_FIXED:
        if not beta.ok or not isinstance(beta.value, (int, float)) or isinstance(beta.value, bool) or not (0 <= beta.num <= MAX_COEFFICIENT):
            problems.append(f"fixed V4 disruptionAversion is missing, malformed, or outside [0,{MAX_COEFFICIENT:g}]")
        if source != COEFF_BETA:
            problems.append(f"fixed V4 costCoefficientSource={source!r}, want {COEFF_BETA!r}")
        if beta.ok and coefficient != beta.num:
            problems.append("fixed V4 effectiveCostCoefficient != exact disruptionAversion")
    else:
        problems.append(f"decisionTrace.economicsVersion={mode!r} is unknown")

    lambda_demand = tr.get("lambdaDemand")
    objective_demand = tr.get("objectiveCandidateDemand")
    for name, value in (("lambdaDemand", lambda_demand), ("objectiveCandidateDemand", objective_demand)):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            problems.append(f"decisionTrace.{name}={value!r} is not a non-negative integer")
    if lambda_demand != tr.get("candidateDemand"):
        problems.append("decisionTrace.lambdaDemand != candidateDemand compatibility alias")

    for i, candidate in enumerate(tr.get("candidates") or []):
        expected = optional(candidate, "expectedCost", cand_path(i))
        if not expected.ok:
            continue
        lam = optional(candidate, "lambdaContribution", cand_path(i))
        obj = optional(candidate, "objectiveCostContribution", cand_path(i))
        if mode == ECON_LEGACY:
            if not lam.ok or "objectiveCostContribution" in candidate:
                problems.append(f"{cand_path(i)} legacy contribution has wrong presence")
            elif isinstance(coefficient, (int, float)) and not approx(lam.num, coefficient * expected.num):
                problems.append(f"{lam.path} does not reconstruct from the effective coefficient")
        elif mode == ECON_FIXED:
            if "lambdaContribution" not in candidate or lam.present is not False or not obj.ok:
                problems.append(f"{cand_path(i)} fixed contribution has wrong presence")
            elif isinstance(coefficient, (int, float)) and not approx(obj.num, coefficient * expected.num):
                problems.append(f"{obj.path} does not reconstruct from the effective coefficient")

    envelope = rec.get("economics")
    if not isinstance(envelope, dict):
        problems.append("audit economics descriptor missing")
    else:
        envelope_beta = optional(envelope, "disruptionAversion", "economics")
        envelope_runtime = optional(envelope, "lambdaRuntimeLegacy", "economics")
        if not envelope_runtime.ok or not isinstance(envelope_runtime.value, (int, float)) or isinstance(envelope_runtime.value, bool) or not (0 <= envelope_runtime.num <= MAX_COEFFICIENT):
            problems.append("audit economics.lambdaRuntimeLegacy missing, malformed, or out of bounds")
        expected_beta_present = mode == ECON_FIXED
        if envelope_beta.ok != expected_beta_present:
            problems.append("audit economics.disruptionAversion presence disagrees with trace mode")
        if envelope.get("version") != mode or envelope.get("coefficientSource") != source or envelope.get("effectiveCostCoefficient") != coefficient:
            problems.append("audit economics mode/source/effective coefficient disagrees with trace")
        if envelope_runtime.ok and envelope_runtime.num != runtime:
            problems.append("audit exact lambdaRuntimeLegacy disagrees with trace")
        if expected_beta_present and beta.ok and (not envelope_beta.ok or envelope_beta.num != beta.num):
            problems.append("audit exact disruptionAversion disagrees with trace")
        if tr.get("schemaVersion") in (TRACE_V5, TRACE_V6, TRACE_V7):
            if tr.get("flowCostSemanticsVersion") != FLOW_SEMANTICS_V1:
                problems.append("V5 trace flowCostSemanticsVersion is missing or unknown")
            if envelope.get("flowCostSemanticsVersion") != FLOW_SEMANTICS_V1:
                problems.append("audit flowCostSemanticsVersion is missing or disagrees with V5 trace")

    if problems:
        return Check(13, "economics-v4", FAIL, "; ".join(problems))
    return Check(13, "economics-v4", PASS,
                 f"{mode} uses exact {source}={coefficient!r}; lambdaDemand={lambda_demand}, objectiveDemand={objective_demand}")


# --- v3 hooks --------------------------------------------------------------

def v3_action_status(tr: dict) -> list[str]:
    vocabulary, vocabulary_error = trace_action_vocabulary(tr)
    if vocabulary_error:
        return [vocabulary_error]
    assert vocabulary is not None
    rows = tr.get("actionStatus")
    if not isinstance(rows, list):
        return ["decisionTrace.actionStatus missing or not a list"]
    problems = []
    if len(rows) != len(vocabulary):
        problems.append(f"decisionTrace.actionStatus has {len(rows)} rows (want {len(vocabulary)})")
    if any(not isinstance(r, dict) for r in rows):
        return problems + ["decisionTrace.actionStatus contains a non-object row"]
    actions = [r.get("action") for r in rows]
    if any(not isinstance(action, str) for action in actions):
        return problems + ["decisionTrace.actionStatus contains a non-string action"]
    if len(set(actions)) != len(actions):
        problems.append("decisionTrace.actionStatus has duplicate actions")
    if actions != vocabulary:
        problems.append("decisionTrace.actionStatus rows not in the selected canonical action vocabulary")
    for i, candidate in enumerate(tr.get("candidates") or []):
        if not isinstance(candidate, dict) or candidate.get("action") not in vocabulary:
            problems.append(f"{cand_path(i)}.action is outside the selected action vocabulary")
    selected = tr.get("selectedAction")
    if selected and selected != "noop" and selected not in vocabulary:
        problems.append("decisionTrace.selectedAction is outside the selected action vocabulary")
    for i, r in enumerate(rows):
        p = f"decisionTrace.actionStatus[{i}]"
        st, ek = r.get("status"), r.get("exclusionKind")
        if st not in V3_STATUS:
            problems.append(f"{p}.status={st!r} not in vocabulary")
        if ek not in V3_EXCLUSION_KIND and not (ek == "resource-capacity" and tr.get("schemaVersion") == TRACE_V7):
            problems.append(f"{p}.exclusionKind={ek!r} not in vocabulary")
        if ek == "resource-capacity" and (st != "infeasible" or r.get("scored") is not False):
            problems.append(f"{p}: resource-capacity requires unscored infeasible status")
        if ek == "resource-capacity" and tr.get("schemaVersion") == TRACE_V7:
            matching = [c for c in tr.get("candidates") or []
                        if isinstance(c, dict) and c.get("action") == r.get("action")]
            if len(matching) != 1:
                problems.append(f"{p}: resource-capacity requires one matching exclusion candidate")
            else:
                c = matching[0]
                scored_fields = ("marginalCoverage", "netGain", "cNorm", "cFlow", "expectedCost",
                                 "costHigh", "lambdaContribution", "objectiveCostContribution",
                                 "feasible", "conformalQuantile", "conformalCalibrated",
                                 "gpuEnvelopeApplied", "gpuEnvelopeSlack", "sloGateResult",
                                 "selectionRound", "flowPredictedMean", "flowConservativeFloor",
                                 "flowUncertaintyBound", "flowUncertaintySlack",
                                 "conformalWindowReady", "conformalRegimeApplicable")
                scored = [name for name in scored_fields
                          if isinstance(c.get(name), dict) and c[name].get("present") is True]
                if (not c.get("existingExclusionReason") or c.get("selected") is True or scored
                        or c.get("resources") not in (None, []) or c.get("flowRegime") not in (None, "")):
                    problems.append(f"{p}: resource-capacity candidate carries scored or post-gate fields: {scored}")
        if st == "selected" and ek != "none":
            problems.append(f"{p}: status==selected requires exclusionKind==none (got {ek!r})")
        if ek == "cost-nan" and st != "infeasible":
            problems.append(f"{p}: exclusionKind==cost-nan requires status==infeasible (got {st!r})")
        if st == "not-installable" and ek != "not-installable":
            problems.append(f"{p}: status==not-installable requires exclusionKind==not-installable (got {ek!r})")
        if st == "ineligible" and ek not in V3_INELIGIBLE_EXCLUSIONS:
            problems.append(f"{p}: status==ineligible requires a recognized eligibility exclusion (got {ek!r})")
    return problems


def v3_cost_high(tr: dict) -> list[str]:
    problems = []
    rows = {r.get("action"): r for r in tr.get("actionStatus") or [] if isinstance(r, dict)}
    for i, c in enumerate(tr.get("candidates") or []):
        p = cand_path(i)
        row = rows.get(c.get("action"), {})
        if row.get("exclusionKind") == "cost-nan":
            continue
        ec, ch = optional(c, "expectedCost", p), optional(c, "costHigh", p)
        if not (ec.ok and ch.ok):
            continue
        extra = 0.0
        if c.get("action") == "rotate":
            cq = optional(c, "conformalQuantile", p)
            slack = optional(c, "gpuEnvelopeSlack", p)
            ga = c.get("gpuEnvelopeApplied")
            # 03 B.1 said plain bool; the diff encodes OptionalBool {present,value}. Accept both.
            applied = (ga is True) or (isinstance(ga, dict) and ga.get("present") is True and ga.get("value") is True)
            q = cq.num if cq.ok else 0.0
            g = slack.num if (applied and slack.ok) else 0.0
            extra = max(q, g)
        if tr.get("schemaVersion") in (TRACE_V5, TRACE_V6, TRACE_V7):
            uncertainty = optional(c, "flowUncertaintySlack", p)
            if uncertainty.ok:
                extra = max(extra, uncertainty.num)
        want = ec.num + extra
        if not approx(want, ch.num):
            problems.append(f"{ch.path}={ch.num!r} but expectedCost+extra={want!r}")
    return problems


def v3_covered_before(tr: dict) -> list[str]:
    problems = []
    ev = tr.get("evaluationRound")
    facts = tr.get("facts") or []
    weight_uncovered = {}
    for i, f in enumerate(facts):
        p = f"decisionTrace.facts[{i}]"
        cr = optional(f, "coveredRound", p)
        want = bool(cr.ok and isinstance(ev, int) and int(cr.value) < ev)
        if f.get("coveredBeforeDecision") is not want:
            problems.append(f"{p}.coveredBeforeDecision={f.get('coveredBeforeDecision')!r} but "
                            f"coveredRound={cr.value if cr.ok else 'absent'} vs evaluationRound={ev!r} -> {want}")
        if not f.get("coveredBeforeDecision"):
            weight_uncovered[f.get("factKey")] = f.get("finalWeight", 0.0)
    for i, c in enumerate(tr.get("candidates") or []):
        p = cand_path(i)
        mc = optional(c, "marginalCoverage", p)
        if not mc.ok:
            continue
        want = sum(weight_uncovered.get(k, 0.0) for k in cover_keys(c))
        if not approx(want, mc.num):
            problems.append(f"{mc.path}={mc.num!r} but sum(finalWeight of uncovered coverKeys)={want!r}")
    return problems


def v3_dispatch(tr: dict) -> list[str]:
    d = tr.get("dispatchOutcome")
    return [] if d in V3_DISPATCH else [f"decisionTrace.dispatchOutcome={d!r} not in {sorted(V3_DISPATCH)}"]


def check_v3(tr: dict, strict: bool) -> Check:
    if tr.get("schemaVersion") not in (TRACE_V3, TRACE_V4, TRACE_V5, TRACE_V6, TRACE_V7):
        if strict:
            return Check(12, "v3-hooks", FAIL, f"--strict-v3: trace is {tr.get('schemaVersion')!r}, not v3/v4/v5/v6/v7")
        return Check(12, "v3-hooks", SKIPPED, "trace is v2; v3 laws (actionStatus/costHigh/coveredBefore/dispatch) not applicable")
    problems = v3_action_status(tr) + v3_cost_high(tr) + v3_covered_before(tr) + v3_dispatch(tr)
    if problems:
        return Check(12, "v3-hooks", FAIL, "; ".join(problems))
    return Check(12, "v3-hooks", PASS, "actionStatus, costHigh, coveredBeforeDecision, dispatchOutcome laws hold")


def check_flow_v5(tr: dict) -> Check:
    if tr.get("schemaVersion") not in (TRACE_V5, TRACE_V6, TRACE_V7):
        return Check(14, "flow-regime-v5", SKIPPED, "historical trace; V5 flow-regime contract is not applicable")
    problems = []
    if tr.get("flowCostSemanticsVersion") != FLOW_SEMANTICS_V1:
        problems.append(f"decisionTrace.flowCostSemanticsVersion={tr.get('flowCostSemanticsVersion')!r}")
    inputs = tr.get("inputs") if isinstance(tr.get("inputs"), dict) else {}
    phase = inputs.get("phase")
    request_rate = optional(inputs, "requestRate", "decisionTrace.inputs")
    known = phase in ("ColdStarting", "Warm", "Idle", "Draining", "Unknown")
    floor_by_phase = {"ColdStarting": 1.0, "Warm": 0.7, "Idle": 0.15,
                      "Draining": 0.2, "Unknown": 0.5}
    for i, candidate in enumerate(tr.get("candidates") or []):
        p = cand_path(i)
        expected = optional(candidate, "expectedCost", p)
        action = candidate.get("action")
        respawn = action in ("rotate", "mig-rebind")
        names = ("flowPredictedMean", "flowConservativeFloor", "flowRegime",
                 "flowUncertaintyBound", "flowUncertaintySlack",
                 "conformalWindowReady", "conformalRegimeApplicable")
        any_provenance = any(name in candidate for name in names)
        if not expected.ok or not respawn:
            if any_provenance:
                problems.append(f"{p} carries V5 flow provenance without a costed respawn")
            continue
        if any(name not in candidate for name in names):
            problems.append(f"{p} lacks complete V5 flow provenance")
            continue
        predicted = optional(candidate, "flowPredictedMean", p)
        floor = optional(candidate, "flowConservativeFloor", p)
        bound = optional(candidate, "flowUncertaintyBound", p)
        slack = optional(candidate, "flowUncertaintySlack", p)
        effective = optional(candidate, "cFlow", p)
        window = optional(candidate, "conformalWindowReady", p)
        applicable_opt = optional(candidate, "conformalRegimeApplicable", p)

        if action == "mig-rebind":
            regime = "mig-proxy"
        elif not known or phase == "Unknown":
            regime = "unknown-phase"
        elif phase == "Draining":
            regime = "draining-phase"
        elif request_rate.present is not True:
            regime = "missing-load"
        else:
            regime = "measured-load"
        if candidate.get("flowRegime") != regime:
            problems.append(f"{p}.flowRegime={candidate.get('flowRegime')!r}, want {regime!r} from action/phase/load")

        floor_present = (not known or phase in ("Unknown", "Draining") or request_rate.present is not True)
        floor_value = 0.5 if not known else floor_by_phase.get(phase, 0.0)
        if floor.present is not floor_present or (floor_present and (not floor.ok or not approx(floor.num, floor_value))):
            problems.append(f"{p}.flowConservativeFloor disagrees with phase/load inputs")
        if predicted.ok and effective.ok:
            want_flow = max(predicted.num, floor_value) if floor_present else predicted.num
            if not approx(effective.num, want_flow):
                problems.append(f"{p}.cFlow={effective.num!r}, want max(mean,floor)={want_flow!r}")
        else:
            problems.append(f"{p} lacks present predicted mean or effective flow")

        unsupported = regime != "measured-load"
        if bound.present is not unsupported or slack.present is not unsupported:
            problems.append(f"{p} uncertainty presence disagrees with regime {regime!r}")
        if unsupported and bound.ok and effective.ok:
            if bound.num != FLOW_MAXIMUM:
                problems.append(f"{p}.flowUncertaintyBound={bound.num!r}, want {FLOW_MAXIMUM!r}")
            weight = tr.get("flowWeight")
            if isinstance(weight, (int, float)) and not isinstance(weight, bool):
                want_slack = weight * max(0.0, FLOW_MAXIMUM - effective.num)
                if not slack.ok or not approx(slack.num, want_slack):
                    problems.append(f"{p}.flowUncertaintySlack does not reconstruct ({want_slack!r})")

        applicable = action == "rotate" and not unsupported
        if not window.ok or not isinstance(window.value, bool):
            problems.append(f"{p}.conformalWindowReady is not a present boolean")
        if not applicable_opt.ok or not isinstance(applicable_opt.value, bool) or applicable_opt.value is not applicable:
            problems.append(f"{p}.conformalRegimeApplicable disagrees with action/regime")
        if action == "rotate":
            calibrated = optional(candidate, "conformalCalibrated", p)
            want_calibrated = bool(window.value) and applicable if window.ok else False
            if not calibrated.ok or not isinstance(calibrated.value, bool) or calibrated.value is not want_calibrated:
                problems.append(f"{p}.conformalCalibrated makes a false row-level claim")
    if problems:
        return Check(14, "flow-regime-v5", FAIL, "; ".join(problems))
    return Check(14, "flow-regime-v5", PASS, "action/phase/load regime, point floor, uncertainty bound and applicability reconstruct")


def resource_scope(scope: Any, path: str) -> tuple[tuple[str, str, str, str] | None, str]:
    """Validate and key the two closed V6 resource-scope forms."""
    if not isinstance(scope, dict):
        return None, f"{path} is not an object"
    kind = scope.get("kind")
    namespace = scope.get("namespace", "")
    service_name = scope.get("serviceName", "")
    service_uid = scope.get("serviceUID", "")
    controller_uid = scope.get("controllerUID", "")
    values = (namespace, service_name, service_uid, controller_uid)
    if any(not isinstance(value, str) for value in values):
        return None, f"{path} has a non-string identity field"
    if kind == "move-count":
        valid = bool(namespace and controller_uid and not service_name and not service_uid)
    elif kind == "unavailable-ready-replica":
        valid = bool(namespace and service_name and service_uid and controller_uid)
    else:
        return None, f"{path}.kind={kind!r} is unknown"
    if not valid:
        return None, f"{path} is not fully and exactly identity-bound"
    # ServiceName is descriptive and deliberately absent from the Go in-memory
    # key; immutable ServiceUID and controllerUID carry authority.
    return (kind, namespace, service_uid, controller_uid), ""


def nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def check_resources_v6(tr: dict) -> Check:
    """Mirror DecisionTraceV2.validateV6 without deriving capacity from scores."""
    version = tr.get("schemaVersion")
    capacities = tr.get("resources")
    candidates = tr.get("candidates") or []
    if version not in (TRACE_V6, TRACE_V7):
        problems = []
        if capacities not in (None, []):
            problems.append("historical trace carries V6 resource capacities")
        for i, candidate in enumerate(candidates):
            if isinstance(candidate, dict) and candidate.get("resources") not in (None, []):
                problems.append(f"{cand_path(i)} carries V6 resource consumption")
        if problems:
            return Check(15, "resources-v6", FAIL, "; ".join(problems))
        return Check(15, "resources-v6", SKIPPED, "historical trace has no V6 resource fields")

    problems = []
    if not isinstance(capacities, list) or not capacities:
        return Check(15, "resources-v6", FAIL, "V6 decisionTrace.resources is missing or empty")
    limits: dict[tuple[str, str, str, str], int] = {}
    batch_selected: dict[tuple[str, str, str, str], int] = {}
    for i, capacity in enumerate(capacities):
        path = f"decisionTrace.resources[{i}]"
        if not isinstance(capacity, dict):
            problems.append(f"{path} is not an object")
            continue
        key, issue = resource_scope(capacity.get("scope"), f"{path}.scope")
        if issue:
            problems.append(issue)
            continue
        limit = capacity.get("limit")
        outstanding = capacity.get("outstanding")
        selected = capacity.get("selected")
        if not all(nonnegative_int(value) for value in (limit, outstanding, selected)):
            problems.append(f"{path} limit/outstanding/selected are not non-negative integers")
            continue
        if outstanding + selected > limit:
            problems.append(f"{path} outstanding+selected exceeds limit")
        if key in limits:
            problems.append(f"{path} duplicates resource scope {key!r}")
            continue
        limits[key], batch_selected[key] = limit, selected

    row_selected: dict[tuple[str, str, str, str], int] = {}
    for i, candidate in enumerate(candidates):
        path = cand_path(i)
        if not isinstance(candidate, dict):
            problems.append(f"{path} is not an object")
            continue
        demands = candidate.get("resources")
        if demands is None:
            demands = []
        if not isinstance(demands, list):
            problems.append(f"{path}.resources is not a list")
            continue
        if not demands and not candidate.get("existingExclusionReason"):
            problems.append(f"{path} lacks V6 resource consumption")
        seen = set()
        for j, demand in enumerate(demands):
            dpath = f"{path}.resources[{j}]"
            if not isinstance(demand, dict):
                problems.append(f"{dpath} is not an object")
                continue
            key, issue = resource_scope(demand.get("scope"), f"{dpath}.scope")
            units = demand.get("units")
            if issue:
                problems.append(issue)
                continue
            if not nonnegative_int(units) or units == 0:
                problems.append(f"{dpath}.units={units!r} is not a positive integer")
                continue
            if key in seen:
                problems.append(f"{dpath} duplicates candidate resource scope {key!r}")
                continue
            seen.add(key)
            if key not in limits:
                problems.append(f"{dpath} consumes unknown resource scope {key!r}")
                continue
            if candidate.get("selected") is True:
                row_selected[key] = row_selected.get(key, 0) + units

    for key, units in row_selected.items():
        if units > batch_selected.get(key, 0):
            problems.append(
                f"selected candidate consumption {units} exceeds batch selected "
                f"{batch_selected.get(key, 0)} for resource scope {key!r}"
            )
    if problems:
        return Check(15, "resources-v6", FAIL, "; ".join(problems))
    return Check(15, "resources-v6", PASS,
                 f"{len(limits)} exact resource scope(s) and candidate consumption vectors reconstruct")


# --------------------------------------------------------------------------- driver

def validate_record(rec: dict, source: str, strict_v3: bool) -> RecordResult:
    tr = rec.get("decisionTrace") or {}
    res = RecordResult(
        source=source,
        decision_id=str(tr.get("decisionID", "")),
        tenant_pod=f"{tr.get('tenantName', rec.get('tenant', '?'))}/{tr.get('assetName', rec.get('pod', '?'))}",
        trace_version=str(tr.get("schemaVersion", "")),
        brain_image=str(tr.get("brainImage", "")),
        selected_action=str(tr.get("selectedAction", "")),
    )
    res.checks = [
        check_schema(rec, tr),
        check_identity(tr),
        check_presence(tr, res.census),
        check_selection_reference(rec, tr),
        check_ecost(tr),
        check_netgain(tr),
        check_selection_reconstruction(tr),
        check_ordering(tr),
        check_cover_keys_resolve(tr),
        check_dual_update(tr),
        check_redaction(rec),
        check_v3(tr, strict_v3),
        check_economics(rec, tr),
        check_flow_v5(tr),
        check_resources_v6(tr),
    ]
    return res


def load_records(path: str) -> Iterator[tuple[str, dict]]:
    def reject_constant(name: str):
        raise ValueError(f"non-finite JSON constant {name}")
    with open(path, encoding="utf-8") as fh:
        if path.endswith(".jsonl"):
            for n, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line, parse_constant=reject_constant)
                if not isinstance(rec, dict) or rec.get("kind") != "phorvex.decision" or "decisionTrace" not in rec:
                    continue
                yield f"{path}:{n}", rec
        else:
            rec = json.load(fh, parse_constant=reject_constant)
            if isinstance(rec, dict) and "decisionTrace" in rec:
                yield path, rec
            else:
                yield path, {"__load_error__": "no decisionTrace object", **(rec if isinstance(rec, dict) else {})}


def markdown_report(results: list[RecordResult]) -> str:
    n = len(results)
    n_pass = sum(r.status == PASS for r in results)
    n_fail = sum(r.status == FAIL for r in results)
    n_und = sum(r.status == UNDECIDABLE for r in results)
    out = ["# Phorvex audit decision-record validation", "",
           f"- records: **{n}**  pass: **{n_pass}**  fail: **{n_fail}**  undecidable: **{n_und}**",
           f"- laws derived from `internal/model/decision_trace.go`, `internal/decision/coverage.go`, "
           f"`internal/model/types.go` (see README.md)", "",
           "## Per-record", "",
           "| decisionID | tenant/pod | trace | brainImage tag | selectedAction | status | checks failed/undecidable |",
           "|---|---|---|---|---|---|---|"]
    for r in results:
        tag = r.brain_image.rsplit(":", 1)[-1] if r.brain_image else ""
        bad = ", ".join(f"{c.num}:{c.name} ({c.status})" for c in r.failed()) or "-"
        out.append(f"| `{r.decision_id[:12]}` | {r.tenant_pod} | {r.trace_version.rsplit('.', 1)[-1]} | {tag} | "
                   f"{r.selected_action} | {r.status} | {bad} |")
    out += ["", "## Check matrix", "",
            "| decisionID | " + " | ".join(str(i) for i in range(1, 16)) + " |",
            "|---|" + "---|" * 15]
    for r in results:
        out.append(f"| `{r.decision_id[:12]}` | " + " | ".join(c.status for c in r.checks) + " |")
    bad_records = [r for r in results if r.status != PASS]
    if bad_records:
        out += ["", "## Failing / undecidable records", ""]
        for r in bad_records:
            out.append(f"### `{r.decision_id}` — {r.tenant_pod} ({r.source})")
            out.append("")
            for c in r.failed():
                out.append(f"- **check {c.num} {c.name}: {c.status}** — {c.message}")
            out.append("")
    out += ["", "## All check messages", ""]
    for r in results:
        out.append(f"### `{r.decision_id}` — {r.tenant_pod}")
        out.append("")
        for c in r.checks:
            out.append(f"- {c.num}. {c.name}: **{c.status}** — {c.message}")
        out.append("")
    census: dict[str, list[int]] = {}
    for r in results:
        for k, (p, a) in r.census.items():
            census.setdefault(k, [0, 0])
            census[k][0] += p
            census[k][1] += a
    # For single-valued paths (no `[]`) present+absent < records means the KEY itself is
    # missing from some records (schema drift between brain builds), which no law fails.
    n_ok = sum(1 for r in results if r.decision_id)
    out += ["## Field presence census", "",
            "| field | present | absent | records lacking key |", "|---|---:|---:|---:|"]
    for k in sorted(census):
        lacking = "-" if "[]" in k else str(n_ok - census[k][0] - census[k][1])
        out.append(f"| `{k}` | {census[k][0]} | {census[k][1]} | {lacking} |")
    out.append("")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help=".json (one record) or .jsonl (one record per line)")
    ap.add_argument("--report", help="write a Markdown report here")
    ap.add_argument("--json", dest="json_out", help="write machine-readable per-record results here")
    ap.add_argument("--strict-v3", action="store_true", help="a v2 record FAILS check 12 instead of SKIPPED")
    args = ap.parse_args(argv)

    results: list[RecordResult] = []
    for path in args.paths:
        try:
            for source, rec in load_records(path):
                if "__load_error__" in rec:
                    r = RecordResult(source, "", "?", "", "", "")
                    r.checks = [Check(0, "load", FAIL, rec["__load_error__"])]
                    results.append(r)
                    continue
                results.append(validate_record(rec, source, args.strict_v3))
        except (OSError, ValueError) as exc:
            r = RecordResult(path, "", "?", "", "", "")
            r.checks = [Check(0, "load", FAIL, f"cannot load: {exc}")]
            results.append(r)

    report = markdown_report(results)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            fh.write(report)
    if args.json_out:
        payload = [{
            "source": r.source, "decisionID": r.decision_id, "tenantPod": r.tenant_pod,
            "traceVersion": r.trace_version, "brainImage": r.brain_image,
            "selectedAction": r.selected_action, "status": r.status,
            "checks": [c.__dict__ for c in r.checks], "census": r.census,
        } for r in results]
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)

    # Console summary
    for r in results:
        print(f"[{r.status}] {r.source} decisionID={r.decision_id[:12]} {r.tenant_pod} {r.selected_action}")
        for c in r.checks:
            if c.status in (FAIL, UNDECIDABLE):
                print(f"    check {c.num} {c.name}: {c.status} - {c.message}")
    n_pass = sum(r.status == PASS for r in results)
    for note in INFO_NOTES:
        print("[INFO] " + note)
    print(f"records={len(results)} pass={n_pass} fail={sum(r.status == FAIL for r in results)} "
          f"undecidable={sum(r.status == UNDECIDABLE for r in results)}")
    return 0 if n_pass == len(results) and results else 1


if __name__ == "__main__":
    sys.exit(main())
