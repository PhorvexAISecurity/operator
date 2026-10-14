# Verification-loop progress

Campaign: **synthetic-demo**. Generated: 2026-10-13T23:39:07.506700+00:00.

**Synthetic demonstration data — no cluster results. References beginning synthetic:// are fake.**

**Active cases: 1 / case parallelism 10. Parked cases: 2. Recorded RUNNING case-worker jobs: 0; total active agents: UNKNOWN (root/shared jobs not included); configured max_active_agents: 8. Physical experiments last reported: UNKNOWN (at UNKNOWN) / configured limit 1.**

Campaign counts: {"accepted_obligations": 38, "active": 1, "admitted": 3, "full_full": 1, "full_phase1": 0, "initial_defenses": 1, "negative_or_unresolved": 1, "parked": 2, "registered": 5, "required_obligations": 96, "stale": 1, "terminal": 2}.

Queued assignments: 0. Scheduling states are coordinator records. Parking a case does not prove an operation stopped or a lease was released; reconcile physical resources separately.

Completion counts accepted obligations, not time remaining. Heartbeats and report generation do not advance evidence. Reviewer identity and job IDs are recorded metadata; the local tool cannot authenticate independence.

| Case | Stack | Target | Entry | Stage / substep | Scheduling / work | Milestones | Outcome / evidence / current validation | Closure | Brain action / effect | Observation / claim | PRs | Blocker | Next action | Last evidence |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| DEMO-ENGINEERING | synthetic-stack | {"customer": "synthetic-read-only-target", "twin": "synthetic-isolated-target"} | SYNTHETIC-ENTRY | SE_ENGINEERING: Await synthetic deployment | ACTIVE / BLOCKED | 11/24 (45.8%) | PENDING / NONE / UNKNOWN | OPEN | {"action": null, "effect": "NOT_RUN"} | AUTHENTICATED_FIXTURE_INPUT / RESPONSE_TO_AUTHENTICATED_FIXTURE_INPUT | synthetic://fake/pr/1 | Synthetic engineering dependency | Select an admitted library entry and bind observed facts | — |
| DEMO-FULL | synthetic-stack | {"customer": "synthetic-read-only-target", "twin": "synthetic-isolated-target"} | SYNTHETIC-ENTRY | S10_PUBLISH: Synthetic scoped report complete | TERMINAL / DONE | 18/18 (100.0%) | DEFENDED / INDEPENDENTLY_VERIFIED / CURRENT | FULL_FULL | {"action": "synthetic-actuator", "effect": "CONFIRMED"} | AUTHENTICATED_FIXTURE_INPUT / RESPONSE_TO_AUTHENTICATED_FIXTURE_INPUT | None | — | None: synthetic example only | 2026-10-13T00:00:00+00:00 |
| DEMO-NEGATIVE | synthetic-stack | {"customer": "synthetic-read-only-target", "twin": "synthetic-isolated-target"} | SYNTHETIC-ENTRY | S7_MEASURE_REVIEW: Synthetic capability-removal gate failed | TERMINAL / DONE | 7/18 (38.9%) | NOT_DEFENDED / INDEPENDENTLY_VERIFIED / CURRENT | CLOSED_NEGATIVE | {"action": null, "effect": "NOT_RUN"} | AUTHENTICATED_FIXTURE_INPUT / RESPONSE_TO_AUTHENTICATED_FIXTURE_INPUT | None | — | Select an admitted library entry and bind observed facts | 2026-10-13T00:00:00+00:00 |
| DEMO-PENDING | synthetic-stack | {"customer": "synthetic-read-only-target", "twin": "synthetic-isolated-target"} | SYNTHETIC-ENTRY | S1_SCAN_SELECT: Bind reviewed entry and observed target | PARKED / BLOCKED | 0/18 (0.0%) | PENDING / NONE / UNKNOWN | OPEN | {"action": null, "effect": "NOT_RUN"} | AUTHENTICATED_FIXTURE_INPUT / RESPONSE_TO_AUTHENTICATED_FIXTURE_INPUT | None | Synthetic missing adapter | Bind a real adapter before execution | — |
| DEMO-STALE | synthetic-stack | {"customer": "synthetic-read-only-target", "twin": "synthetic-isolated-target"} | SYNTHETIC-ENTRY | S3_TWIN_ADMIT: Blocked on synthetic readmission and fresh dependency reviews | PARKED / BLOCKED | 2/18 (11.1%) | DEFENDED / INDEPENDENTLY_VERIFIED / STALE | OPEN | {"action": "synthetic-actuator", "effect": "CONFIRMED"} | AUTHENTICATED_FIXTURE_INPUT / RESPONSE_TO_AUTHENTICATED_FIXTURE_INPUT | None | — | Reconcile synthetic dependencies and obtain fresh acceptance before retesting | 2026-10-13T00:00:00+00:00 |

## DEMO-ENGINEERING — SYNTHETIC: formatting example, no real experiment

Synthetic: True. Target: {"customer": "synthetic-read-only-target", "twin": "synthetic-isolated-target"}. Profile: FULL; epoch: synthetic-epoch-1; plan revision: 2; case revision: 1.

Observation: AUTHENTICATED_FIXTURE_INPUT; claim: RESPONSE_TO_AUTHENTICATED_FIXTURE_INPUT; current validation: UNKNOWN. Resolution: []. Planned: ["NEW_ACTUATOR"].

Owner: synthetic-orchestrator; round/attempt: 1/—. Timing: {"active_seconds": null, "stage_started_at": null, "wait_seconds": null}. Heartbeat: —.

| Milestone | Status | Author / reviewer | Reason / remaining work | Evidence |
| --- | --- | --- | --- | --- |
| E01 Actuator specification | ACCEPTED | synthetic-producer / synthetic-reviewer | Synthetic admitted engineering obligation | ["synthetic://fake/E01/evidence"] |
| E02 Independent design review | ACCEPTED | synthetic-producer / synthetic-reviewer | Synthetic admitted engineering obligation | ["synthetic://fake/E02/evidence"] |
| E03 Implementation and source review | ACCEPTED | synthetic-producer / synthetic-reviewer | Synthetic admitted engineering obligation | ["synthetic://fake/E03/evidence"] |
| E04 PR delivered | ACCEPTED | synthetic-producer / synthetic-reviewer | Synthetic admitted engineering obligation | ["synthetic://fake/E04/evidence"] |
| E05 Deployment and registration observed | NOT_STARTED | None / None | Synthetic admitted engineering obligation | [] |
| E06 Post-deployment case retest | NOT_STARTED | None / None | Synthetic admitted engineering obligation | [] |
| M01 Applicability and provenance | ACCEPTED | synthetic-producer / synthetic-reviewer |  | ["synthetic://fake/M01/evidence"] |
| M02 Executable contract and independent critique | ACCEPTED | synthetic-producer / synthetic-reviewer |  | ["synthetic://fake/M02/evidence"] |
| M03 Twin/control admission and fidelity | ACCEPTED | synthetic-producer / synthetic-reviewer |  | ["synthetic://fake/M03/evidence"] |
| M04 Capability present and C1–C6 | ACCEPTED | synthetic-producer / synthetic-reviewer |  | ["synthetic://fake/M04/evidence"] |
| M05 Observation and brain-input provenance | ACCEPTED | synthetic-producer / synthetic-reviewer |  | ["synthetic://fake/M05/evidence"] |
| M06 Defense proposal and critique | ACCEPTED | synthetic-producer / synthetic-reviewer |  | ["synthetic://fake/M06/evidence"] |
| M07 Brain selection and feasibility | ACCEPTED | synthetic-producer / synthetic-reviewer |  | ["synthetic://fake/M07/evidence"] |
| M08 G1 capability removed | NOT_STARTED | None / None |  | [] |
| M09 G2 availability | NOT_STARTED | None / None |  | [] |
| M10 G3 clean control | NOT_STARTED | None / None |  | [] |
| M11 Physical S1 measured | NOT_STARTED | None / None |  | [] |
| M12 Challenge, battery, and minority obligations | NOT_STARTED | None / None |  | [] |
| M13 Fresh independent repeat | NOT_STARTED | None / None |  | [] |
| M14 Cleanup and release | NOT_STARTED | None / None |  | [] |
| M15 Final independent review and report | NOT_STARTED | None / None |  | [] |
| M16 S2 collateral measured | NOT_STARTED | None / None |  | [] |
| M17 S3 durability measured | NOT_STARTED | None / None |  | [] |
| M18 S4 cost measured | NOT_STARTED | None / None |  | [] |

| Metric | Status | Value | Units | Window / type | Evidence / reason |
| --- | --- | --- | --- | --- | --- |
| G1 | NOT_RUN | — | — | None / None | {"evidence": [], "reason": ""} |
| G2 | NOT_RUN | — | — | None / None | {"evidence": [], "reason": ""} |
| G3 | NOT_RUN | — | — | None / None | {"evidence": [], "reason": ""} |
| S1 | NOT_RUN | — | — | None / None | {"evidence": [], "reason": ""} |
| S2 | NOT_RUN | — | — | None / None | {"evidence": [], "reason": ""} |
| S3 | NOT_RUN | — | — | None / None | {"evidence": [], "reason": ""} |
| S4 | NOT_RUN | — | — | None / None | {"evidence": [], "reason": ""} |

**Chain**

```json
{
  "brain_trace_ref": null,
  "dispatch": "NOT_RUN",
  "expected_actuator": null,
  "native_effect": "NOT_RUN",
  "selected_actuator": null
}
```

**Checks**

```json
{}
```

**Assignments**

```json
[]
```

**PR deployment and retest history**

```json
[
  {
    "change_types": [
      "NEW_ACTUATOR"
    ],
    "deployments": [
      {
        "at": "2026-10-13T00:00:00+00:00",
        "deployment_id": "synthetic-deploy-1",
        "evidence_refs": [
          "synthetic://fake/deployment"
        ],
        "image_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "source": "synthetic-source-1",
        "status": "OBSERVED",
        "target": "synthetic-isolated-target"
      }
    ],
    "follow_up_to": [],
    "head_sha": "0000000000000000000000000000000000000000",
    "merge_sha": null,
    "number": 1,
    "repo": "synthetic-repository",
    "retests": [
      {
        "attempt_id": "synthetic-retest-1",
        "deployment_ref": "synthetic://fake/deployment",
        "epoch": "synthetic-epoch-1",
        "evidence_level": "REPORTED",
        "evidence_refs": [
          "synthetic://fake/retest-1"
        ],
        "outcome": "INCONCLUSIVE",
        "source": "synthetic-source-1"
      },
      {
        "attempt_id": "synthetic-retest-2",
        "deployment_ref": "synthetic://fake/deployment",
        "epoch": "synthetic-epoch-1",
        "evidence_level": "INDEPENDENTLY_VERIFIED",
        "evidence_refs": [
          "synthetic://fake/retest-2"
        ],
        "outcome": "NOT_DEFENDED",
        "source": "synthetic-source-1"
      }
    ],
    "review_ref": "synthetic://fake/source-review",
    "state": "OPEN",
    "url": "synthetic://fake/pr/1"
  }
]
```

**Attempt references**

```json
[
  "synthetic://fake/attempt-1"
]
```

**Plan and stale history**

```json
[
  {
    "at": "2026-10-13T00:00:00+00:00",
    "new_required": 24,
    "old_required": 18,
    "plan_revision": 2,
    "reason": "Synthetic admitted engineering branch"
  }
]
```

| Revision | Time | Actor | Change |
| --- | --- | --- | --- |
| 1 | 2026-10-13T23:39:07.498563+00:00 | synthetic-coordinator | Synthetic example registration |

## DEMO-FULL — SYNTHETIC: formatting example, no real experiment

Synthetic: True. Target: {"customer": "synthetic-read-only-target", "twin": "synthetic-isolated-target"}. Profile: FULL; epoch: synthetic-epoch-1; plan revision: 1; case revision: 1.

Observation: AUTHENTICATED_FIXTURE_INPUT; claim: RESPONSE_TO_AUTHENTICATED_FIXTURE_INPUT; current validation: CURRENT. Resolution: ["EXISTING_ACTUATOR"]. Planned: [].

Owner: synthetic-orchestrator; round/attempt: 1/—. Timing: {"active_seconds": null, "stage_started_at": null, "wait_seconds": null}. Heartbeat: —.

| Milestone | Status | Author / reviewer | Reason / remaining work | Evidence |
| --- | --- | --- | --- | --- |
| M01 Applicability and provenance | ACCEPTED | synthetic-producer / synthetic-reviewer |  | ["synthetic://fake/M01/evidence"] |
| M02 Executable contract and independent critique | ACCEPTED | synthetic-producer / synthetic-reviewer |  | ["synthetic://fake/M02/evidence"] |
| M03 Twin/control admission and fidelity | ACCEPTED | synthetic-producer / synthetic-reviewer |  | ["synthetic://fake/M03/evidence"] |
| M04 Capability present and C1–C6 | ACCEPTED | synthetic-producer / synthetic-reviewer |  | ["synthetic://fake/M04/evidence"] |
| M05 Observation and brain-input provenance | ACCEPTED | synthetic-producer / synthetic-reviewer |  | ["synthetic://fake/M05/evidence"] |
| M06 Defense proposal and critique | ACCEPTED | synthetic-producer / synthetic-reviewer |  | ["synthetic://fake/M06/evidence"] |
| M07 Brain selection and feasibility | ACCEPTED | synthetic-producer / synthetic-reviewer |  | ["synthetic://fake/M07/evidence"] |
| M08 G1 capability removed | ACCEPTED | synthetic-producer / synthetic-reviewer |  | ["synthetic://fake/M08/evidence"] |
| M09 G2 availability | ACCEPTED | synthetic-producer / synthetic-reviewer |  | ["synthetic://fake/M09/evidence"] |
| M10 G3 clean control | ACCEPTED | synthetic-producer / synthetic-reviewer |  | ["synthetic://fake/M10/evidence"] |
| M11 Physical S1 measured | ACCEPTED | synthetic-producer / synthetic-reviewer |  | ["synthetic://fake/M11/evidence"] |
| M12 Challenge, battery, and minority obligations | ACCEPTED | synthetic-producer / synthetic-reviewer |  | ["synthetic://fake/M12/evidence"] |
| M13 Fresh independent repeat | ACCEPTED | synthetic-producer / synthetic-reviewer |  | ["synthetic://fake/M13/evidence"] |
| M14 Cleanup and release | ACCEPTED | synthetic-producer / synthetic-reviewer |  | ["synthetic://fake/M14/evidence"] |
| M15 Final independent review and report | ACCEPTED | synthetic-producer / synthetic-reviewer |  | ["synthetic://fake/M15/evidence"] |
| M16 S2 collateral measured | ACCEPTED | synthetic-producer / synthetic-reviewer |  | ["synthetic://fake/M16/evidence"] |
| M17 S3 durability measured | ACCEPTED | synthetic-producer / synthetic-reviewer |  | ["synthetic://fake/M17/evidence"] |
| M18 S4 cost measured | ACCEPTED | synthetic-producer / synthetic-reviewer |  | ["synthetic://fake/M18/evidence"] |

| Metric | Status | Value | Units | Window / type | Evidence / reason |
| --- | --- | --- | --- | --- | --- |
| G1 | PASS | True | synthetic-unit | {'end': '2026-10-13T00:00:00+00:00', 'start': '2026-10-13T00:00:00+00:00'} / SYNTHETIC_PLACEHOLDER | {"evidence": ["synthetic://fake/G1/measurement"], "reason": ""} |
| G2 | PASS | True | synthetic-unit | {'end': '2026-10-13T00:00:00+00:00', 'start': '2026-10-13T00:00:00+00:00'} / SYNTHETIC_PLACEHOLDER | {"evidence": ["synthetic://fake/G2/measurement"], "reason": ""} |
| G3 | PASS | True | synthetic-unit | {'end': '2026-10-13T00:00:00+00:00', 'start': '2026-10-13T00:00:00+00:00'} / SYNTHETIC_PLACEHOLDER | {"evidence": ["synthetic://fake/G3/measurement"], "reason": ""} |
| S1 | PASS | 1.25 | seconds | {'end': '2026-10-13T00:00:00+00:00', 'start': '2026-10-13T00:00:00+00:00'} / PHYSICAL_MONOTONIC | {"evidence": ["synthetic://fake/S1/measurement"], "reason": ""} |
| S2 | PASS | 1.25 | synthetic-unit | {'end': '2026-10-13T00:00:00+00:00', 'start': '2026-10-13T00:00:00+00:00'} / SYNTHETIC_PLACEHOLDER | {"evidence": ["synthetic://fake/S2/measurement"], "reason": ""} |
| S3 | PASS | 1.25 | synthetic-unit | {'end': '2026-10-13T00:00:00+00:00', 'start': '2026-10-13T00:00:00+00:00'} / SYNTHETIC_PLACEHOLDER | {"evidence": ["synthetic://fake/S3/measurement"], "reason": ""} |
| S4 | PASS | 1.25 | synthetic-unit | {'end': '2026-10-13T00:00:00+00:00', 'start': '2026-10-13T00:00:00+00:00'} / SYNTHETIC_PLACEHOLDER | {"evidence": ["synthetic://fake/S4/measurement"], "reason": ""} |

**Chain**

```json
{
  "brain_trace_ref": "synthetic://fake/brain-trace",
  "dispatch": "CONFIRMED",
  "expected_actuator": "synthetic-actuator",
  "native_effect": "CONFIRMED",
  "selected_actuator": "synthetic-actuator"
}
```

**Checks**

```json
{
  "g2_components": {
    "availability_floor": {
      "evidence_refs": [
        "synthetic://fake/g2/availability_floor"
      ],
      "status": "PASS"
    },
    "bound_proof": {
      "evidence_refs": [
        "synthetic://fake/g2/bound_proof"
      ],
      "status": "PASS",
      "value": "BOUNDED"
    },
    "co_tenant_isolation": {
      "evidence_refs": [
        "synthetic://fake/g2/co_tenant_isolation"
      ],
      "status": "PASS"
    },
    "ledger_hold": {
      "evidence_refs": [
        "synthetic://fake/g2/ledger_hold"
      ],
      "status": "PASS"
    },
    "slo_headroom": {
      "evidence_refs": [
        "synthetic://fake/g2/slo_headroom"
      ],
      "status": "PASS"
    }
  },
  "scenario_battery": {
    "completed_at": "2026-10-13T00:00:00+00:00",
    "evidence_refs": [
      "synthetic://fake/battery-results"
    ],
    "manifest_ref": "synthetic://fake/battery-manifest",
    "required_archetype_families": [
      "plain",
      "stateful",
      "neighbors",
      "gpu*",
      "sensitive-output",
      "vector-*"
    ],
    "required_scenario_ids": [
      "synthetic-scenario-0",
      "synthetic-scenario-1",
      "synthetic-scenario-2",
      "synthetic-scenario-3",
      "synthetic-scenario-4",
      "synthetic-scenario-5",
      "synthetic-invariant-action-status-completeness",
      "synthetic-invariant-slo-gate-rejection",
      "synthetic-invariant-nan-fail-closed",
      "synthetic-invariant-reactive-only-honesty",
      "synthetic-invariant-trace-on-off-selection-equivalence",
      "synthetic-invariant-adversarial-disjointness"
    ],
    "review_ref": "synthetic://fake/battery-review",
    "scenarios": [
      {
        "archetype": "plain",
        "assertions": [
          {
            "assertion_id": "effect-and-gates-confirmed",
            "evidence_refs": [
              "synthetic://fake/synthetic-scenario-0/assertion"
            ],
            "status": "PASS"
          }
        ],
        "epoch": "synthetic-epoch-1",
        "evidence_refs": [
          "synthetic://fake/synthetic-scenario-0/result"
        ],
        "expected_outcome": "SELECTED_AND_CONFIRMED",
        "fixture_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "fixture_ref": "synthetic://fake/synthetic-scenario-0/fixture",
        "review_ref": "synthetic://fake/synthetic-scenario-0/review",
        "scenario_id": "synthetic-scenario-0",
        "status": "PASS"
      },
      {
        "archetype": "stateful",
        "assertions": [
          {
            "assertion_id": "effect-and-gates-confirmed",
            "evidence_refs": [
              "synthetic://fake/synthetic-scenario-1/assertion"
            ],
            "status": "PASS"
          }
        ],
        "epoch": "synthetic-epoch-1",
        "evidence_refs": [
          "synthetic://fake/synthetic-scenario-1/result"
        ],
        "expected_outcome": "SELECTED_AND_CONFIRMED",
        "fixture_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "fixture_ref": "synthetic://fake/synthetic-scenario-1/fixture",
        "review_ref": "synthetic://fake/synthetic-scenario-1/review",
        "scenario_id": "synthetic-scenario-1",
        "status": "PASS"
      },
      {
        "archetype": "neighbors",
        "assertions": [
          {
            "assertion_id": "expected-rejection-observed",
            "evidence_refs": [
              "synthetic://fake/synthetic-scenario-2/assertion"
            ],
            "status": "PASS"
          }
        ],
        "epoch": "synthetic-epoch-1",
        "evidence_refs": [
          "synthetic://fake/synthetic-scenario-2/result"
        ],
        "expected_outcome": "EXPECTED_REJECTION",
        "fixture_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "fixture_ref": "synthetic://fake/synthetic-scenario-2/fixture",
        "review_ref": "synthetic://fake/synthetic-scenario-2/review",
        "scenario_id": "synthetic-scenario-2",
        "status": "PASS"
      },
      {
        "archetype": "gpu-shared",
        "assertions": [
          {
            "assertion_id": "effect-and-gates-confirmed",
            "evidence_refs": [
              "synthetic://fake/synthetic-scenario-3/assertion"
            ],
            "status": "PASS"
          }
        ],
        "epoch": "synthetic-epoch-1",
        "evidence_refs": [
          "synthetic://fake/synthetic-scenario-3/result"
        ],
        "expected_outcome": "SELECTED_AND_CONFIRMED",
        "fixture_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "fixture_ref": "synthetic://fake/synthetic-scenario-3/fixture",
        "review_ref": "synthetic://fake/synthetic-scenario-3/review",
        "scenario_id": "synthetic-scenario-3",
        "status": "PASS"
      },
      {
        "archetype": "sensitive-output",
        "assertions": [
          {
            "assertion_id": "effect-and-gates-confirmed",
            "evidence_refs": [
              "synthetic://fake/synthetic-scenario-4/assertion"
            ],
            "status": "PASS"
          }
        ],
        "epoch": "synthetic-epoch-1",
        "evidence_refs": [
          "synthetic://fake/synthetic-scenario-4/result"
        ],
        "expected_outcome": "SELECTED_AND_CONFIRMED",
        "fixture_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "fixture_ref": "synthetic://fake/synthetic-scenario-4/fixture",
        "review_ref": "synthetic://fake/synthetic-scenario-4/review",
        "scenario_id": "synthetic-scenario-4",
        "status": "PASS"
      },
      {
        "archetype": "vector-shared",
        "assertions": [
          {
            "assertion_id": "effect-and-gates-confirmed",
            "evidence_refs": [
              "synthetic://fake/synthetic-scenario-5/assertion"
            ],
            "status": "PASS"
          }
        ],
        "epoch": "synthetic-epoch-1",
        "evidence_refs": [
          "synthetic://fake/synthetic-scenario-5/result"
        ],
        "expected_outcome": "SELECTED_AND_CONFIRMED",
        "fixture_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "fixture_ref": "synthetic://fake/synthetic-scenario-5/fixture",
        "review_ref": "synthetic://fake/synthetic-scenario-5/review",
        "scenario_id": "synthetic-scenario-5",
        "status": "PASS"
      },
      {
        "archetype": "integrity",
        "assertions": [
          {
            "assertion_id": "action-status-completeness",
            "evidence_refs": [
              "synthetic://fake/synthetic-invariant-action-status-completeness/assertion"
            ],
            "status": "PASS"
          }
        ],
        "epoch": "synthetic-epoch-1",
        "evidence_refs": [
          "synthetic://fake/synthetic-invariant-action-status-completeness/result"
        ],
        "expected_outcome": "INTEGRITY_ASSERTION",
        "fixture_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "fixture_ref": "synthetic://fake/synthetic-invariant-action-status-completeness/fixture",
        "review_ref": "synthetic://fake/synthetic-invariant-action-status-completeness/review",
        "scenario_id": "synthetic-invariant-action-status-completeness",
        "status": "PASS"
      },
      {
        "archetype": "integrity",
        "assertions": [
          {
            "assertion_id": "slo-gate-rejection",
            "evidence_refs": [
              "synthetic://fake/synthetic-invariant-slo-gate-rejection/assertion"
            ],
            "status": "PASS"
          }
        ],
        "epoch": "synthetic-epoch-1",
        "evidence_refs": [
          "synthetic://fake/synthetic-invariant-slo-gate-rejection/result"
        ],
        "expected_outcome": "EXPECTED_REJECTION",
        "fixture_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "fixture_ref": "synthetic://fake/synthetic-invariant-slo-gate-rejection/fixture",
        "review_ref": "synthetic://fake/synthetic-invariant-slo-gate-rejection/review",
        "scenario_id": "synthetic-invariant-slo-gate-rejection",
        "status": "PASS"
      },
      {
        "archetype": "integrity",
        "assertions": [
          {
            "assertion_id": "nan-fail-closed",
            "evidence_refs": [
              "synthetic://fake/synthetic-invariant-nan-fail-closed/assertion"
            ],
            "status": "PASS"
          }
        ],
        "epoch": "synthetic-epoch-1",
        "evidence_refs": [
          "synthetic://fake/synthetic-invariant-nan-fail-closed/result"
        ],
        "expected_outcome": "EXPECTED_REJECTION",
        "fixture_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "fixture_ref": "synthetic://fake/synthetic-invariant-nan-fail-closed/fixture",
        "review_ref": "synthetic://fake/synthetic-invariant-nan-fail-closed/review",
        "scenario_id": "synthetic-invariant-nan-fail-closed",
        "status": "PASS"
      },
      {
        "archetype": "integrity",
        "assertions": [
          {
            "assertion_id": "reactive-only-honesty",
            "evidence_refs": [
              "synthetic://fake/synthetic-invariant-reactive-only-honesty/assertion"
            ],
            "status": "PASS"
          }
        ],
        "epoch": "synthetic-epoch-1",
        "evidence_refs": [
          "synthetic://fake/synthetic-invariant-reactive-only-honesty/result"
        ],
        "expected_outcome": "INTEGRITY_ASSERTION",
        "fixture_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "fixture_ref": "synthetic://fake/synthetic-invariant-reactive-only-honesty/fixture",
        "review_ref": "synthetic://fake/synthetic-invariant-reactive-only-honesty/review",
        "scenario_id": "synthetic-invariant-reactive-only-honesty",
        "status": "PASS"
      },
      {
        "archetype": "integrity",
        "assertions": [
          {
            "assertion_id": "trace-on-off-selection-equivalence",
            "evidence_refs": [
              "synthetic://fake/synthetic-invariant-trace-on-off-selection-equivalence/assertion"
            ],
            "status": "PASS"
          }
        ],
        "epoch": "synthetic-epoch-1",
        "evidence_refs": [
          "synthetic://fake/synthetic-invariant-trace-on-off-selection-equivalence/result"
        ],
        "expected_outcome": "INTEGRITY_ASSERTION",
        "fixture_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "fixture_ref": "synthetic://fake/synthetic-invariant-trace-on-off-selection-equivalence/fixture",
        "review_ref": "synthetic://fake/synthetic-invariant-trace-on-off-selection-equivalence/review",
        "scenario_id": "synthetic-invariant-trace-on-off-selection-equivalence",
        "status": "PASS"
      },
      {
        "archetype": "integrity",
        "assertions": [
          {
            "assertion_id": "adversarial-disjointness",
            "evidence_refs": [
              "synthetic://fake/synthetic-invariant-adversarial-disjointness/assertion"
            ],
            "status": "PASS"
          }
        ],
        "epoch": "synthetic-epoch-1",
        "evidence_refs": [
          "synthetic://fake/synthetic-invariant-adversarial-disjointness/result"
        ],
        "expected_outcome": "INTEGRITY_ASSERTION",
        "fixture_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "fixture_ref": "synthetic://fake/synthetic-invariant-adversarial-disjointness/fixture",
        "review_ref": "synthetic://fake/synthetic-invariant-adversarial-disjointness/review",
        "scenario_id": "synthetic-invariant-adversarial-disjointness",
        "status": "PASS"
      }
    ],
    "status": "PASS"
  }
}
```

**Assignments**

```json
[]
```

**PR deployment and retest history**

```json
[]
```

**Attempt references**

```json
[
  "synthetic://fake/attempt-1"
]
```

**Plan and stale history**

```json
[]
```

| Revision | Time | Actor | Change |
| --- | --- | --- | --- |
| 1 | 2026-10-13T23:39:07.500300+00:00 | synthetic-coordinator | Synthetic example registration |

## DEMO-NEGATIVE — SYNTHETIC: formatting example, no real experiment

Synthetic: True. Target: {"customer": "synthetic-read-only-target", "twin": "synthetic-isolated-target"}. Profile: FULL; epoch: synthetic-epoch-1; plan revision: 1; case revision: 1.

Observation: AUTHENTICATED_FIXTURE_INPUT; claim: RESPONSE_TO_AUTHENTICATED_FIXTURE_INPUT; current validation: CURRENT. Resolution: []. Planned: [].

Owner: synthetic-orchestrator; round/attempt: 1/—. Timing: {"active_seconds": null, "stage_started_at": null, "wait_seconds": null}. Heartbeat: —.

| Milestone | Status | Author / reviewer | Reason / remaining work | Evidence |
| --- | --- | --- | --- | --- |
| M01 Applicability and provenance | ACCEPTED | synthetic-producer / synthetic-reviewer |  | ["synthetic://fake/M01/evidence"] |
| M02 Executable contract and independent critique | ACCEPTED | synthetic-producer / synthetic-reviewer |  | ["synthetic://fake/M02/evidence"] |
| M03 Twin/control admission and fidelity | ACCEPTED | synthetic-producer / synthetic-reviewer |  | ["synthetic://fake/M03/evidence"] |
| M04 Capability present and C1–C6 | ACCEPTED | synthetic-producer / synthetic-reviewer |  | ["synthetic://fake/M04/evidence"] |
| M05 Observation and brain-input provenance | ACCEPTED | synthetic-producer / synthetic-reviewer |  | ["synthetic://fake/M05/evidence"] |
| M06 Defense proposal and critique | ACCEPTED | synthetic-producer / synthetic-reviewer |  | ["synthetic://fake/M06/evidence"] |
| M07 Brain selection and feasibility | ACCEPTED | synthetic-producer / synthetic-reviewer |  | ["synthetic://fake/M07/evidence"] |
| M08 G1 capability removed | NOT_STARTED | None / None |  | [] |
| M09 G2 availability | NOT_STARTED | None / None |  | [] |
| M10 G3 clean control | NOT_STARTED | None / None |  | [] |
| M11 Physical S1 measured | NOT_STARTED | None / None |  | [] |
| M12 Challenge, battery, and minority obligations | NOT_STARTED | None / None |  | [] |
| M13 Fresh independent repeat | NOT_STARTED | None / None |  | [] |
| M14 Cleanup and release | NOT_STARTED | None / None |  | [] |
| M15 Final independent review and report | NOT_STARTED | None / None |  | [] |
| M16 S2 collateral measured | NOT_STARTED | None / None |  | [] |
| M17 S3 durability measured | NOT_STARTED | None / None |  | [] |
| M18 S4 cost measured | NOT_STARTED | None / None |  | [] |

| Metric | Status | Value | Units | Window / type | Evidence / reason |
| --- | --- | --- | --- | --- | --- |
| G1 | FAIL | False | — | None / None | {"evidence": ["synthetic://fake/negative/G1"], "reason": "Synthetic capability persists"} |
| G2 | NOT_RUN | — | — | None / None | {"evidence": [], "reason": ""} |
| G3 | NOT_RUN | — | — | None / None | {"evidence": [], "reason": ""} |
| S1 | NOT_RUN | — | — | None / None | {"evidence": [], "reason": ""} |
| S2 | NOT_RUN | — | — | None / None | {"evidence": [], "reason": ""} |
| S3 | NOT_RUN | — | — | None / None | {"evidence": [], "reason": ""} |
| S4 | NOT_RUN | — | — | None / None | {"evidence": [], "reason": ""} |

**Chain**

```json
{
  "brain_trace_ref": null,
  "dispatch": "NOT_RUN",
  "expected_actuator": null,
  "native_effect": "NOT_RUN",
  "selected_actuator": null
}
```

**Checks**

```json
{}
```

**Assignments**

```json
[]
```

**PR deployment and retest history**

```json
[]
```

**Attempt references**

```json
[
  "synthetic://fake/attempt-1"
]
```

**Plan and stale history**

```json
[]
```

| Revision | Time | Actor | Change |
| --- | --- | --- | --- |
| 1 | 2026-10-13T23:39:07.497161+00:00 | synthetic-coordinator | Synthetic example registration |

## DEMO-PENDING — SYNTHETIC: formatting example, no real experiment

Synthetic: True. Target: {"customer": "synthetic-read-only-target", "twin": "synthetic-isolated-target"}. Profile: FULL; epoch: synthetic-epoch-1; plan revision: 1; case revision: 1.

Observation: AUTHENTICATED_FIXTURE_INPUT; claim: RESPONSE_TO_AUTHENTICATED_FIXTURE_INPUT; current validation: UNKNOWN. Resolution: []. Planned: [].

Owner: synthetic-orchestrator; round/attempt: 1/—. Timing: {"active_seconds": null, "stage_started_at": null, "wait_seconds": null}. Heartbeat: —.

| Milestone | Status | Author / reviewer | Reason / remaining work | Evidence |
| --- | --- | --- | --- | --- |
| M01 Applicability and provenance | NOT_STARTED | None / None |  | [] |
| M02 Executable contract and independent critique | NOT_STARTED | None / None |  | [] |
| M03 Twin/control admission and fidelity | NOT_STARTED | None / None |  | [] |
| M04 Capability present and C1–C6 | NOT_STARTED | None / None |  | [] |
| M05 Observation and brain-input provenance | NOT_STARTED | None / None |  | [] |
| M06 Defense proposal and critique | NOT_STARTED | None / None |  | [] |
| M07 Brain selection and feasibility | NOT_STARTED | None / None |  | [] |
| M08 G1 capability removed | NOT_STARTED | None / None |  | [] |
| M09 G2 availability | NOT_STARTED | None / None |  | [] |
| M10 G3 clean control | NOT_STARTED | None / None |  | [] |
| M11 Physical S1 measured | NOT_STARTED | None / None |  | [] |
| M12 Challenge, battery, and minority obligations | NOT_STARTED | None / None |  | [] |
| M13 Fresh independent repeat | NOT_STARTED | None / None |  | [] |
| M14 Cleanup and release | NOT_STARTED | None / None |  | [] |
| M15 Final independent review and report | NOT_STARTED | None / None |  | [] |
| M16 S2 collateral measured | NOT_STARTED | None / None |  | [] |
| M17 S3 durability measured | NOT_STARTED | None / None |  | [] |
| M18 S4 cost measured | NOT_STARTED | None / None |  | [] |

| Metric | Status | Value | Units | Window / type | Evidence / reason |
| --- | --- | --- | --- | --- | --- |
| G1 | NOT_RUN | — | — | None / None | {"evidence": [], "reason": ""} |
| G2 | NOT_RUN | — | — | None / None | {"evidence": [], "reason": ""} |
| G3 | NOT_RUN | — | — | None / None | {"evidence": [], "reason": ""} |
| S1 | NOT_RUN | — | — | None / None | {"evidence": [], "reason": ""} |
| S2 | NOT_RUN | — | — | None / None | {"evidence": [], "reason": ""} |
| S3 | NOT_RUN | — | — | None / None | {"evidence": [], "reason": ""} |
| S4 | NOT_RUN | — | — | None / None | {"evidence": [], "reason": ""} |

**Chain**

```json
{
  "brain_trace_ref": null,
  "dispatch": "NOT_RUN",
  "expected_actuator": null,
  "native_effect": "NOT_RUN",
  "selected_actuator": null
}
```

**Checks**

```json
{}
```

**Assignments**

```json
[]
```

**PR deployment and retest history**

```json
[]
```

**Attempt references**

```json
[
  "synthetic://fake/attempt-1"
]
```

**Plan and stale history**

```json
[]
```

| Revision | Time | Actor | Change |
| --- | --- | --- | --- |
| 1 | 2026-10-13T23:39:07.495685+00:00 | synthetic-coordinator | Synthetic example registration |

## DEMO-STALE — SYNTHETIC: formatting example, no real experiment

Synthetic: True. Target: {"customer": "synthetic-read-only-target", "twin": "synthetic-isolated-target"}. Profile: FULL; epoch: synthetic-epoch-2; plan revision: 1; case revision: 2.

Observation: AUTHENTICATED_FIXTURE_INPUT; claim: RESPONSE_TO_AUTHENTICATED_FIXTURE_INPUT; current validation: STALE. Resolution: ["EXISTING_ACTUATOR"]. Planned: [].

Owner: synthetic-orchestrator; round/attempt: 1/—. Timing: {"active_seconds": null, "stage_started_at": null, "wait_seconds": null}. Heartbeat: —.

| Milestone | Status | Author / reviewer | Reason / remaining work | Evidence |
| --- | --- | --- | --- | --- |
| M01 Applicability and provenance | ACCEPTED | synthetic-producer / synthetic-reviewer |  | ["synthetic://fake/M01/evidence"] |
| M02 Executable contract and independent critique | ACCEPTED | synthetic-producer / synthetic-reviewer |  | ["synthetic://fake/M02/evidence"] |
| M03 Twin/control admission and fidelity | STALE | synthetic-producer / synthetic-reviewer | Dependency changed: epoch | ["synthetic://fake/M03/evidence"] |
| M04 Capability present and C1–C6 | STALE | synthetic-producer / synthetic-reviewer | Dependency changed: epoch | ["synthetic://fake/M04/evidence"] |
| M05 Observation and brain-input provenance | STALE | synthetic-producer / synthetic-reviewer | Dependency changed: epoch | ["synthetic://fake/M05/evidence"] |
| M06 Defense proposal and critique | STALE | synthetic-producer / synthetic-reviewer | Dependency changed: epoch | ["synthetic://fake/M06/evidence"] |
| M07 Brain selection and feasibility | STALE | synthetic-producer / synthetic-reviewer | Dependency changed: epoch | ["synthetic://fake/M07/evidence"] |
| M08 G1 capability removed | STALE | synthetic-producer / synthetic-reviewer | Dependency changed: epoch | ["synthetic://fake/M08/evidence"] |
| M09 G2 availability | STALE | synthetic-producer / synthetic-reviewer | Dependency changed: epoch | ["synthetic://fake/M09/evidence"] |
| M10 G3 clean control | STALE | synthetic-producer / synthetic-reviewer | Dependency changed: epoch | ["synthetic://fake/M10/evidence"] |
| M11 Physical S1 measured | STALE | synthetic-producer / synthetic-reviewer | Dependency changed: epoch | ["synthetic://fake/M11/evidence"] |
| M12 Challenge, battery, and minority obligations | STALE | synthetic-producer / synthetic-reviewer | Dependency changed: epoch | ["synthetic://fake/M12/evidence"] |
| M13 Fresh independent repeat | STALE | synthetic-producer / synthetic-reviewer | Dependency changed: epoch | ["synthetic://fake/M13/evidence"] |
| M14 Cleanup and release | STALE | synthetic-producer / synthetic-reviewer | Dependency changed: epoch | ["synthetic://fake/M14/evidence"] |
| M15 Final independent review and report | STALE | synthetic-producer / synthetic-reviewer | Dependency changed: epoch | ["synthetic://fake/M15/evidence"] |
| M16 S2 collateral measured | STALE | synthetic-producer / synthetic-reviewer | Dependency changed: epoch | ["synthetic://fake/M16/evidence"] |
| M17 S3 durability measured | STALE | synthetic-producer / synthetic-reviewer | Dependency changed: epoch | ["synthetic://fake/M17/evidence"] |
| M18 S4 cost measured | STALE | synthetic-producer / synthetic-reviewer | Dependency changed: epoch | ["synthetic://fake/M18/evidence"] |

| Metric | Status | Value | Units | Window / type | Evidence / reason |
| --- | --- | --- | --- | --- | --- |
| G1 | UNKNOWN | — | synthetic-unit | {'end': '2026-10-13T00:00:00+00:00', 'start': '2026-10-13T00:00:00+00:00'} / SYNTHETIC_PLACEHOLDER | {"evidence": ["synthetic://fake/G1/measurement"], "reason": "Dependency changed: epoch"} |
| G2 | UNKNOWN | — | synthetic-unit | {'end': '2026-10-13T00:00:00+00:00', 'start': '2026-10-13T00:00:00+00:00'} / SYNTHETIC_PLACEHOLDER | {"evidence": ["synthetic://fake/G2/measurement"], "reason": "Dependency changed: epoch"} |
| G3 | UNKNOWN | — | synthetic-unit | {'end': '2026-10-13T00:00:00+00:00', 'start': '2026-10-13T00:00:00+00:00'} / SYNTHETIC_PLACEHOLDER | {"evidence": ["synthetic://fake/G3/measurement"], "reason": "Dependency changed: epoch"} |
| S1 | UNKNOWN | — | seconds | {'end': '2026-10-13T00:00:00+00:00', 'start': '2026-10-13T00:00:00+00:00'} / PHYSICAL_MONOTONIC | {"evidence": ["synthetic://fake/S1/measurement"], "reason": "Dependency changed: epoch"} |
| S2 | UNKNOWN | — | synthetic-unit | {'end': '2026-10-13T00:00:00+00:00', 'start': '2026-10-13T00:00:00+00:00'} / SYNTHETIC_PLACEHOLDER | {"evidence": ["synthetic://fake/S2/measurement"], "reason": "Dependency changed: epoch"} |
| S3 | UNKNOWN | — | synthetic-unit | {'end': '2026-10-13T00:00:00+00:00', 'start': '2026-10-13T00:00:00+00:00'} / SYNTHETIC_PLACEHOLDER | {"evidence": ["synthetic://fake/S3/measurement"], "reason": "Dependency changed: epoch"} |
| S4 | UNKNOWN | — | synthetic-unit | {'end': '2026-10-13T00:00:00+00:00', 'start': '2026-10-13T00:00:00+00:00'} / SYNTHETIC_PLACEHOLDER | {"evidence": ["synthetic://fake/S4/measurement"], "reason": "Dependency changed: epoch"} |

**Chain**

```json
{
  "brain_trace_ref": "synthetic://fake/brain-trace",
  "dispatch": "CONFIRMED",
  "expected_actuator": "synthetic-actuator",
  "native_effect": "CONFIRMED",
  "selected_actuator": "synthetic-actuator"
}
```

**Checks**

```json
{
  "g2_components": {
    "availability_floor": {
      "evidence_refs": [
        "synthetic://fake/g2/availability_floor"
      ],
      "status": "PASS"
    },
    "bound_proof": {
      "evidence_refs": [
        "synthetic://fake/g2/bound_proof"
      ],
      "status": "PASS",
      "value": "BOUNDED"
    },
    "co_tenant_isolation": {
      "evidence_refs": [
        "synthetic://fake/g2/co_tenant_isolation"
      ],
      "status": "PASS"
    },
    "ledger_hold": {
      "evidence_refs": [
        "synthetic://fake/g2/ledger_hold"
      ],
      "status": "PASS"
    },
    "slo_headroom": {
      "evidence_refs": [
        "synthetic://fake/g2/slo_headroom"
      ],
      "status": "PASS"
    }
  },
  "scenario_battery": {
    "completed_at": "2026-10-13T00:00:00+00:00",
    "evidence_refs": [
      "synthetic://fake/battery-results"
    ],
    "manifest_ref": "synthetic://fake/battery-manifest",
    "required_archetype_families": [
      "plain",
      "stateful",
      "neighbors",
      "gpu*",
      "sensitive-output",
      "vector-*"
    ],
    "required_scenario_ids": [
      "synthetic-scenario-0",
      "synthetic-scenario-1",
      "synthetic-scenario-2",
      "synthetic-scenario-3",
      "synthetic-scenario-4",
      "synthetic-scenario-5",
      "synthetic-invariant-action-status-completeness",
      "synthetic-invariant-slo-gate-rejection",
      "synthetic-invariant-nan-fail-closed",
      "synthetic-invariant-reactive-only-honesty",
      "synthetic-invariant-trace-on-off-selection-equivalence",
      "synthetic-invariant-adversarial-disjointness"
    ],
    "review_ref": "synthetic://fake/battery-review",
    "scenarios": [
      {
        "archetype": "plain",
        "assertions": [
          {
            "assertion_id": "effect-and-gates-confirmed",
            "evidence_refs": [
              "synthetic://fake/synthetic-scenario-0/assertion"
            ],
            "status": "PASS"
          }
        ],
        "epoch": "synthetic-epoch-1",
        "evidence_refs": [
          "synthetic://fake/synthetic-scenario-0/result"
        ],
        "expected_outcome": "SELECTED_AND_CONFIRMED",
        "fixture_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "fixture_ref": "synthetic://fake/synthetic-scenario-0/fixture",
        "review_ref": "synthetic://fake/synthetic-scenario-0/review",
        "scenario_id": "synthetic-scenario-0",
        "status": "PASS"
      },
      {
        "archetype": "stateful",
        "assertions": [
          {
            "assertion_id": "effect-and-gates-confirmed",
            "evidence_refs": [
              "synthetic://fake/synthetic-scenario-1/assertion"
            ],
            "status": "PASS"
          }
        ],
        "epoch": "synthetic-epoch-1",
        "evidence_refs": [
          "synthetic://fake/synthetic-scenario-1/result"
        ],
        "expected_outcome": "SELECTED_AND_CONFIRMED",
        "fixture_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "fixture_ref": "synthetic://fake/synthetic-scenario-1/fixture",
        "review_ref": "synthetic://fake/synthetic-scenario-1/review",
        "scenario_id": "synthetic-scenario-1",
        "status": "PASS"
      },
      {
        "archetype": "neighbors",
        "assertions": [
          {
            "assertion_id": "expected-rejection-observed",
            "evidence_refs": [
              "synthetic://fake/synthetic-scenario-2/assertion"
            ],
            "status": "PASS"
          }
        ],
        "epoch": "synthetic-epoch-1",
        "evidence_refs": [
          "synthetic://fake/synthetic-scenario-2/result"
        ],
        "expected_outcome": "EXPECTED_REJECTION",
        "fixture_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "fixture_ref": "synthetic://fake/synthetic-scenario-2/fixture",
        "review_ref": "synthetic://fake/synthetic-scenario-2/review",
        "scenario_id": "synthetic-scenario-2",
        "status": "PASS"
      },
      {
        "archetype": "gpu-shared",
        "assertions": [
          {
            "assertion_id": "effect-and-gates-confirmed",
            "evidence_refs": [
              "synthetic://fake/synthetic-scenario-3/assertion"
            ],
            "status": "PASS"
          }
        ],
        "epoch": "synthetic-epoch-1",
        "evidence_refs": [
          "synthetic://fake/synthetic-scenario-3/result"
        ],
        "expected_outcome": "SELECTED_AND_CONFIRMED",
        "fixture_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "fixture_ref": "synthetic://fake/synthetic-scenario-3/fixture",
        "review_ref": "synthetic://fake/synthetic-scenario-3/review",
        "scenario_id": "synthetic-scenario-3",
        "status": "PASS"
      },
      {
        "archetype": "sensitive-output",
        "assertions": [
          {
            "assertion_id": "effect-and-gates-confirmed",
            "evidence_refs": [
              "synthetic://fake/synthetic-scenario-4/assertion"
            ],
            "status": "PASS"
          }
        ],
        "epoch": "synthetic-epoch-1",
        "evidence_refs": [
          "synthetic://fake/synthetic-scenario-4/result"
        ],
        "expected_outcome": "SELECTED_AND_CONFIRMED",
        "fixture_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "fixture_ref": "synthetic://fake/synthetic-scenario-4/fixture",
        "review_ref": "synthetic://fake/synthetic-scenario-4/review",
        "scenario_id": "synthetic-scenario-4",
        "status": "PASS"
      },
      {
        "archetype": "vector-shared",
        "assertions": [
          {
            "assertion_id": "effect-and-gates-confirmed",
            "evidence_refs": [
              "synthetic://fake/synthetic-scenario-5/assertion"
            ],
            "status": "PASS"
          }
        ],
        "epoch": "synthetic-epoch-1",
        "evidence_refs": [
          "synthetic://fake/synthetic-scenario-5/result"
        ],
        "expected_outcome": "SELECTED_AND_CONFIRMED",
        "fixture_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "fixture_ref": "synthetic://fake/synthetic-scenario-5/fixture",
        "review_ref": "synthetic://fake/synthetic-scenario-5/review",
        "scenario_id": "synthetic-scenario-5",
        "status": "PASS"
      },
      {
        "archetype": "integrity",
        "assertions": [
          {
            "assertion_id": "action-status-completeness",
            "evidence_refs": [
              "synthetic://fake/synthetic-invariant-action-status-completeness/assertion"
            ],
            "status": "PASS"
          }
        ],
        "epoch": "synthetic-epoch-1",
        "evidence_refs": [
          "synthetic://fake/synthetic-invariant-action-status-completeness/result"
        ],
        "expected_outcome": "INTEGRITY_ASSERTION",
        "fixture_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "fixture_ref": "synthetic://fake/synthetic-invariant-action-status-completeness/fixture",
        "review_ref": "synthetic://fake/synthetic-invariant-action-status-completeness/review",
        "scenario_id": "synthetic-invariant-action-status-completeness",
        "status": "PASS"
      },
      {
        "archetype": "integrity",
        "assertions": [
          {
            "assertion_id": "slo-gate-rejection",
            "evidence_refs": [
              "synthetic://fake/synthetic-invariant-slo-gate-rejection/assertion"
            ],
            "status": "PASS"
          }
        ],
        "epoch": "synthetic-epoch-1",
        "evidence_refs": [
          "synthetic://fake/synthetic-invariant-slo-gate-rejection/result"
        ],
        "expected_outcome": "EXPECTED_REJECTION",
        "fixture_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "fixture_ref": "synthetic://fake/synthetic-invariant-slo-gate-rejection/fixture",
        "review_ref": "synthetic://fake/synthetic-invariant-slo-gate-rejection/review",
        "scenario_id": "synthetic-invariant-slo-gate-rejection",
        "status": "PASS"
      },
      {
        "archetype": "integrity",
        "assertions": [
          {
            "assertion_id": "nan-fail-closed",
            "evidence_refs": [
              "synthetic://fake/synthetic-invariant-nan-fail-closed/assertion"
            ],
            "status": "PASS"
          }
        ],
        "epoch": "synthetic-epoch-1",
        "evidence_refs": [
          "synthetic://fake/synthetic-invariant-nan-fail-closed/result"
        ],
        "expected_outcome": "EXPECTED_REJECTION",
        "fixture_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "fixture_ref": "synthetic://fake/synthetic-invariant-nan-fail-closed/fixture",
        "review_ref": "synthetic://fake/synthetic-invariant-nan-fail-closed/review",
        "scenario_id": "synthetic-invariant-nan-fail-closed",
        "status": "PASS"
      },
      {
        "archetype": "integrity",
        "assertions": [
          {
            "assertion_id": "reactive-only-honesty",
            "evidence_refs": [
              "synthetic://fake/synthetic-invariant-reactive-only-honesty/assertion"
            ],
            "status": "PASS"
          }
        ],
        "epoch": "synthetic-epoch-1",
        "evidence_refs": [
          "synthetic://fake/synthetic-invariant-reactive-only-honesty/result"
        ],
        "expected_outcome": "INTEGRITY_ASSERTION",
        "fixture_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "fixture_ref": "synthetic://fake/synthetic-invariant-reactive-only-honesty/fixture",
        "review_ref": "synthetic://fake/synthetic-invariant-reactive-only-honesty/review",
        "scenario_id": "synthetic-invariant-reactive-only-honesty",
        "status": "PASS"
      },
      {
        "archetype": "integrity",
        "assertions": [
          {
            "assertion_id": "trace-on-off-selection-equivalence",
            "evidence_refs": [
              "synthetic://fake/synthetic-invariant-trace-on-off-selection-equivalence/assertion"
            ],
            "status": "PASS"
          }
        ],
        "epoch": "synthetic-epoch-1",
        "evidence_refs": [
          "synthetic://fake/synthetic-invariant-trace-on-off-selection-equivalence/result"
        ],
        "expected_outcome": "INTEGRITY_ASSERTION",
        "fixture_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "fixture_ref": "synthetic://fake/synthetic-invariant-trace-on-off-selection-equivalence/fixture",
        "review_ref": "synthetic://fake/synthetic-invariant-trace-on-off-selection-equivalence/review",
        "scenario_id": "synthetic-invariant-trace-on-off-selection-equivalence",
        "status": "PASS"
      },
      {
        "archetype": "integrity",
        "assertions": [
          {
            "assertion_id": "adversarial-disjointness",
            "evidence_refs": [
              "synthetic://fake/synthetic-invariant-adversarial-disjointness/assertion"
            ],
            "status": "PASS"
          }
        ],
        "epoch": "synthetic-epoch-1",
        "evidence_refs": [
          "synthetic://fake/synthetic-invariant-adversarial-disjointness/result"
        ],
        "expected_outcome": "INTEGRITY_ASSERTION",
        "fixture_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        "fixture_ref": "synthetic://fake/synthetic-invariant-adversarial-disjointness/fixture",
        "review_ref": "synthetic://fake/synthetic-invariant-adversarial-disjointness/review",
        "scenario_id": "synthetic-invariant-adversarial-disjointness",
        "status": "PASS"
      }
    ],
    "status": "PASS"
  }
}
```

**Assignments**

```json
[]
```

**PR deployment and retest history**

```json
[]
```

**Attempt references**

```json
[
  "synthetic://fake/attempt-1"
]
```

**Plan and stale history**

```json
[
  {
    "at": "2026-10-13T23:39:07.503824+00:00",
    "milestones": [
      "M03",
      "M04",
      "M05",
      "M06",
      "M07",
      "M08",
      "M09",
      "M10",
      "M11",
      "M12",
      "M13",
      "M14",
      "M15",
      "M16",
      "M17",
      "M18"
    ],
    "reason": "Dependency invalidation"
  }
]
```

| Revision | Time | Actor | Change |
| --- | --- | --- | --- |
| 1 | 2026-10-13T23:39:07.501980+00:00 | synthetic-coordinator | Synthetic historical accepted defense |
| 2 | 2026-10-13T23:39:07.504115+00:00 | synthetic-coordinator | Synthetic epoch change; dependent evidence becomes stale |
