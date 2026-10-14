# Typed task and return handoffs

Use `templates/task.json` / `schemas/task.schema.json` for assignments and `templates/return.json` / `schemas/return.schema.json` for results. Templates contain placeholders, not real jobs or evidence. JSON Schema checks shape; the coordinator also checks scope, identities, hashes, dependencies, budgets and reviewer conflicts. Role payloads are extensible objects with the required keys below. Physical adapter schemas remain separate contracts.

## Ownership and task identity

The root coordinator owns dispatch, the task ledger and canonical register writes. Workers write only assigned output/artifact paths and return proposals. `case.submit`, `review.submit` and `progress.update` mean submit to the bound coordinator, not edit SQLite/generated reports. Sending work to a critic means returning `review_request` to the root. Local worker tasks require `nested_spawning_allowed: false`; only the root dispatches workers and reviews within the global budget.

Campaign tasks (preflight, scan interpretation, tactic selection) use null `case_id`, `expected_case_revision`, `round_id` and `attempt_id`. Record these in RUN's task ledger; the local case register does not store campaign tasks. Register an actual entry/workload candidate before issuing a case task. Case tasks require its current revision. `round_id` identifies the competition round; `attempt_id` identifies a particular physical/replay attempt when one exists. `epoch` is null before runtime admission and binds the evaluated runtime afterward. Queued tasks may have null actor/job/model fields; fill them from observed dispatch before reporting RUNNING.

`inputs[]` contains immutable artifact references with SHA-256 and producer identity. `pins` names exact relevant source/library/scan/profile/policy/fixture/runtime versions. `dependencies[]` lists accepted task or artifact IDs. `acceptance_conditions[]` supplies review criteria. `return_schema_ref` selects the structural schema; `payload_contract` selects the role contract below. `output_ref` is a coordinator-chosen task-specific path outside generated reports. Budgets remain cumulative through correction tasks; new task IDs do not reset campaign charges.

## Case slots, workers and physical capacity

`case_parallelism` is the primary campaign limit: concurrent admitted case workflows. `max_active_agents` is the supporting model-worker budget, including root; `max_parallel_experiments` separately bounds physical overlap. Defaults of 10 case slots and 8 agents allow ten admitted workflows to have ready tasks while at most seven child workers run in a sufficiently capable Codex session. A case need not hold a permanent worker. Case `scheduling_state` is ACTIVE, PARKED or TERMINAL, independently of task RUNNING identities. New candidates start PARKED. Count only scheduling_state ACTIVE toward case_parallelism; historical competition ACTIVE alone is not a scheduling-capacity count.

The root admits cases up to case_parallelism, schedules their ready tasks within observed worker limits, and reserves operation resources separately. Record a blocker and continuation point, reconcile state and any in-flight effects, then set scheduling_state to PARKED so another ready case can use its workflow slot. The root admits it by setting ACTIVE through the transactional register. Retained defended-state reservations still consume physical capacity after parking; expiry is not release. Resume only after the exit condition and dependencies are verified and a workflow slot is available. No new worker or slot number certifies isolation or readiness.

The analyst's `roster_inputs` supplies per-app observed S(a), V(a), K(a), pod/image counts, weights/provenance and unknowns. The root derives G/Val/conditional Des and the policy cap/floor into an immutable RosterPlan; `CampaignPlan.roster_plan_ref` points to it. Before that S1 artifact exists, use null for this field and name the pending scan/roster obligation, rather than fabricating a plan. Logical roster demand is neither case_parallelism nor a count of actual running workers. Pin the roster policy and input scan in dependent tasks and rederive on relevant changes.

## Return and acceptance

Return the original task/campaign/case/round/attempt, real actor/job identity, expected revision, input hashes and pins, status, findings, payload, artifacts, proposed transition, review request, blockers, next action and usage. `SUBMITTED` means ready for inspection, never independently accepted. `BLOCKED`, `INPUT_STALE` and `FAILED` preserve partial work and the smallest supported failure. Findings distinguish OBSERVED, INFERENCE and UNKNOWN and cite artifact IDs. Unknown usage is null, not invented zero.

Artifacts carry `artifact_id`, `ref`, `sha256`, `producer_id`, `observed_at`, `classification` and `pins`. Add target/operation/window metadata when relevant. Hashes establish bytes, not truth. The coordinator verifies bytes and producer suitability. Secret values stay outside artifacts/prompts. SYNTHETIC artifacts never satisfy live milestones.

A `review_request` states critic/auditor role, specialty, raw artifact IDs, criteria, author/executor conflict identities and an optional conclusion artifact ID. Auditors require `raw_first: true`. Start a clean session with criteria and raw receipts only; preserve its first assessment before disclosing the conclusion in a bounded follow-up. Distinct display names alone do not prove independence. An author, executor or proposer cannot become its auditor.

The root validates the envelope/identity, checks pins/dependencies/hashes, dispatches independent review, checks deterministic admission receipts, reloads current case state, reconciles the task's owned changes and commits with the current revision, then renders. Changed inputs require dependent rebinding/review. Do not overwrite newer evidence or promote REAL/WIN/closure from a worker proposal alone.

## Required payload keys

These keys are required for substantive SUBMITTED deliverables. Blocked/stale/failed returns include available partial keys and put missing obligations in `blockers`. Referenced artifacts must appear in `artifact_refs`; return large receipts by reference.

| Role / payload_contract | Required payload keys |
| --- | --- |
| ORCHESTRATOR / CampaignPlan | `manifest_ref`, `adapter_status`, `worker_plan`, `roster_plan_ref`, `ready_tasks`, `blocker_routes` |
| CLUSTER_ANALYST / WorkloadProfile | `snapshot_ref`, `asset_ids`, `facts`, `relationships`, `control_surfaces`, `roster_inputs`, `unknowns`, `follow_up_reads` |
| LIBRARY_SELECTOR / CandidateSet | `library_ref`, `snapshot_ref`, `candidates`, `exclusions`, `aliases`, `ordering`, `review_requests` |
| CASE_BINDER / BoundCaseContract | `candidate_ref`, `capability`, `parameter_provenance`, `fixture_ref`, `probe_refs`, `observation_mode`, `brain_input_mapping`, `control`, `availability`, `windows`, `resource_plan`, `cleanup`, `battery_manifest_ref`, `readiness_gaps` |
| CRITIC / Critique | `proposal_ref`, `conflict_check`, `objections`, `corrective_evidence`, `predicted_ranks`, `minority_obligations`, `disposition` |
| DEFENSE_PROPOSER / DefenseQueue | `real_case_ref`, `registry_ref`, `candidates`, `fingerprints`, `critique_refs`, `minority_obligations`, `no_passing_selected_response` |
| CHALLENGE_PLANNER / ChallengePlan | `winner_ref`, `instances`, `confirmed_chain_edges`, `minority_slots`, `battery_coverage`, `unresolved_scope` |
| ACTUATOR_DESIGNER / ActuatorCapabilityContract | `gap_ref`, `eligibility_refs`, `capability_contract`, `confirmation_probe`, `implementation_criteria`, `review_criteria`, `retest_criteria`, `dependencies`, `engineering_owner` |
| EVIDENCE_AUDITOR / IndependentReview | `conflict_check`, `raw_first_assessment_ref`, `accepted_claims`, `rejected_claims`, `unknown_claims`, `metric_card`, `coverage`, `cleanup_ref`, `closure_recommendation` |

Details follow each role prompt and WORKFLOW.md. Empty arrays/nulls explain absent information; they cannot substitute for mandatory proof. Engineering blockers state interface/gap, accepted inputs, bounded deliverable, owner or UNASSIGNED, exit condition, next action and deadline. Carry the no-Co-authored-by/no-assistant-attribution commit rule in every engineering handoff.

## Harness portability

Codex uses CODEX-ADAPTER.md. Claude Code/other harnesses map the same envelopes to their observed session facility, preserving actual IDs/models, coordinator writes, clean auditors and caps. Do not assume Codex tool names or model controls exist elsewhere. No clean independent-session facility means an independence blocker; admissible planning continues. Missing fixture/brain/twin adapters remain engineering dependencies, not installed services.
