# PHORVEX Mathematical Assurance

This directory holds the deliverables of the PHORVEX Mathematical Assurance program
(the Math Contract, runtime gates, verification harness and promotion framework).

**Current stage:** Part I, current-system reconstruction (Phases 1–3), at
**Checkpoint 1: architecture review**. No gate code has been written. The program plan
says gates are not implemented until the baseline is frozen, the current decision flow
is reviewed and the trust boundaries are identified.

| Phase | Deliverable |
|---|---|
| 1 Freeze the review baseline | [MATH_ASSURANCE_SOURCE_MANIFEST.md](MATH_ASSURANCE_SOURCE_MANIFEST.md) |
| 2 Reconstruct the current flow | [PHORVEX_CURRENT_DECISION_FLOW.md](PHORVEX_CURRENT_DECISION_FLOW.md) + [diagram](PHORVEX_CURRENT_DECISION_FLOW.mmd) |
| 3 Brain / ticket / code delta | [BRAIN_TICKET_CODE_DELTA_LEDGER.md](BRAIN_TICKET_CODE_DELTA_LEDGER.md) |

Pins: code `main` @ `f8787fa8` (v0.4.215, also what runs in dev). The Brain baseline is
`phorvex/METHOD-DECISION.md` at its approved revision `803dfe68` plus
`phorvex/P1-REPORT.md`.

## What Part I found about the plan's premise

The plan is written for *"AI/RL proposes → deterministic Math Gate → admitted
scorer/reward"*. PHORVEX's decision path differs in three ways:

1. **It is already deterministic, with no LLM or learned policy.** The only RL code is an
   attacker simulator that is not built into any image.
2. **Its trust transitions are learned, calibrated or externally supplied inputs** to a
   deterministic optimizer. The decision flow lists them as T1–T15:
   - detector and console SecurityEvents;
   - typed observations;
   - telemetry;
   - EPSS;
   - RLS cost and conformal slack;
   - the runtime λ;
   - clocks;
   - RBAC answers;
   - policy parameters.
3. **There is no RL reward.** The plan's scorer/reward gate (G7) maps to admission of the
   online learning signals: RLS observations and the λ update. Conjugate memory is
   designed but has no production writer.

Several gate functions already exist, in part:
- schema and NaN guards;
- event trust;
- the feasibility law registry;
- the conformal SLO-cost gate;
- capacity;
- an independent trace recomputation (`DecisionTraceV2.Validate()`);
- a frozen greedy-replay validator.

Those recomputation and replay checks run in tests only, not at runtime. The decision
flow (§6) maps each one to G0–G7.

## Checkpoint 1: decisions needed

1. **Baseline pins.** Accept the pins in the source manifest §1–§2, including the choice
   of the approved `803dfe68` revision rather than the edited current file.
2. **Reinterpreted scope.** Accept mapping "AI/RL proposals" to the trust transitions
   T1–T15, and the reward gate G7 to learning-signal admission.
3. **Blocking items.** Rule on, or explicitly defer, the items that cannot enter Math
   Contract v1 as they stand:

   | Group | Items |
   |---|---|
   | CONFLICT | DL-016, DL-020, DL-022, DL-030, DL-033, DL-034, DL-040, DL-048 |
   | UNKNOWN | DL-027, DL-052 |
   | CODE_STALE | DL-009, DL-010 |
   | Ruling conflicts | RC-1…RC-11 |
   | Flow findings | F-1…F-6 |

   Each has a "what would resolve it" entry in the ledger.
4. **Owners.** Confirm the proposed Math / Eng / Sec owner per ledger row.
5. **Record keeping.** Decide whether repairing the stale issue register, release pin and
   missing ruling files (manifest §8) belongs to this program or is tracked separately.

After Checkpoint 1, Phase 4 (math-critical inventory) and Phase 5 (provenance map)
build directly on the trust transitions and the CONFIRMED ledger rows.
