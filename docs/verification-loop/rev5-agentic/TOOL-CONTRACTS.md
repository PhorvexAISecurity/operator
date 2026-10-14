# Tools and adapter contracts

These names define interfaces the receiving harness must bind to real implementations. Only the local progress/check utilities ship as executable code. A tool is AVAILABLE only after its binding, version, permissions, target identity, and bounded diagnostic have been recorded. A matching name in a prompt is not installation evidence. In a local Codex or Claude Code run, the trusted coordinator is the root harness session invoking the supplied transactional register and bound adapters. It is not an assumed installed daemon; the distributed authenticated service and operation gateway remain implementation contracts.

## Interface catalogue

| Tool | Inputs | Outputs | Mutability and caller |
| --- | --- | --- | --- |
| scope.read | Campaign reference | Scope, limits, unresolved fields | Read-only; all roles as needed |
| scan.collect | Customer identity, credential reference, allowed inventory classes | Versioned facts with resource identities/times/provenance | Customer read-only; collector invoked by orchestrator |
| library.query | Admitted version/hash, matching scope-review and refresh receipts, domain/tactic, predicate | Reviewed entries and source/review/refresh references | Read-only; selector/binder/challenge |
| evidence.read | Immutable artifact refs and hashes | Verified bytes or explicit mismatch | Read-only; authorized task roles |
| case.submit | Task envelope, expected revision, structured proposal | Stored proposal/rejection, new revision | Case state only; through coordinator/service |
| reality.check | Bound entry, scan/fixture receipts | C1–C6 statuses and source reasons | Deterministic; no LLM-authored REAL flag |
| rank.aggregate | Candidate fingerprints and critiques | Stable ordered queue, minority obligations | Deterministic; cannot accept a defense |
| twin.admit | Contract, pins, isolation/budget/lease data | Twin/control IDs, fidelity, resource admission | Approved experiment resources only; gateway |
| fixture.establish | Approved template/hash, bound params, lease, operation key | Intent/receipt, baseline and observation refs | Twin-only effect; gateway |
| brain.evaluate | Pinned binary/state/policy/normal-action-set/capability snapshot, epoch/tick/input hash | Validated verbatim decision/refusal, complete canonical action accounting, model inputs, evaluation/replay IDs | Shadow; no learning writes or candidate forcing |
| actuator.execute | Actual selected eligible action, pins, lease, operation key | Native operation and outcome receipts | Twin-only; gateway; dispatch is not confirmation |
| probe.collect | Approved probe/hash, target, window, scope | Original observations/times and explicit errors | Read observations; probe load within scope |
| metrics.evaluate | Trace, probes, control, windows, named G2 components and reviewed battery assertions | Seven-field metric card, component and battery records; unknowns explicit | Deterministic; never fills unknown as zero |
| twin.release | Owned-resource ledger, current lease/generation | Cleanup and release evidence, unresolved obligations | Only owned twin resources; gateway |
| engineering.handoff | Eligible gap, accepted design, delivery scope | Assigned external owner, dependency/change record | No product mutation by design agents |
| review.submit | Reviewer identity, exact input hashes, accepted/rejected claims | Independent review record | Evidence store; actor independence checked |
| progress.update | Case update, expected revision, actor/reason | Committed revision or conflict | Transactional state; local prototype provided |

## Binding procedure

For each required tool record: adapter type (CLI/API/MCP), executable or endpoint, version/digest, input/output schemas, allowed caller roles, connection reference, target allowlist, timeout, idempotency/fencing support, and last successful diagnostic. Probe only read-only/local capabilities during PLAN. Use real registered commands; this document does not invent product CLI commands.

The receiving coding harness may inspect Phorvex source and available CLI help to find an adapter. It must not inspect customer application source to design cases. If an adapter is absent, state the exact missing interface and deliver a bounded implementation specification. Fixture engineering and operation gateways are separate deliverables; their absence is visible in progress rather than concealed by fabricated JSON.

If a harness provides broad shell tools, enforce the scope in the operation gateway and filesystem permissions where possible. Prompt instructions alone are not a security boundary. Read-only credentials belong to the customer scan; mutation credentials are restricted to the declared twin. Never infer that a Kubernetes context named dev is the right cluster.

## Admission and deterministic evaluation records

The coordinator admits execution only with campaign `library_review_ref` and `library_refresh_ref` matching the exact admitted library hash/version. The scope review covers bucket, actuator status and preconditions. The build-time refresh receipt includes source/version/retrieval records and ATLAS sub-technique mapping confirmation. A local PLAN run can report these missing inputs and finish independent preparation; it cannot fabricate their acceptance.

`brain.evaluate` uses a deduplication key `(epoch, tick_id, input_hash)`. Hash the complete state, policy, normal eligible action set and capability pins. Return the actual complete canonical `ActionStatus` plus validated trace, including all exclusions and selected actions. Proposer order is an investigation priority, never a candidate override or an action-set filter. A replay may check determinism; it adds no new physical evidence. Another decision requires a genuine observed state/tick transition or a separately reviewed implementation epoch, recorded with changed dependencies. Only the actual selected action may enter `actuator.execute`.

A CANNOT_HELP_ENABLED_SET/design-admission record must independently account for the action set using trace reasons and the selected actions' measured failures. It says there was no passing brain-selected response in that context. Unselected actions are not physically tested simply because their trace rows exist. Missing accounting, fixture/input or unresolved selected-action effects leaves an incomplete claim. Supported closed exclusions of unselected actions need no physical trial or battery claim. For a would-be winner, unknown required battery assertions are a measurement dependency; a confirmed failed assertion can reject its admission. Do not turn missing battery tooling into an actuator enforcement gap. Preserve any optional decision ledger under `checks.brain_evaluations`; the trusted coordinator prevents identical-input retries being charged as new candidate tests.

## Gate and battery return records

`checks.g2_components` contains `availability_floor`, `slo_headroom`, `bound_proof`, `ledger_hold`, and `co_tenant_isolation`, each with `status` and `evidence_refs`. A passing `bound_proof` has value ZERO or BOUNDED and the enforced, deadline-bounded, safe-return-verified path inventory. Ledger receipts identify tenant windows, realized disruption, overlaps/censoring and unmeasured intervals. Isolation receipts identify compared co-tenant brain/state bytes and exact-zero deltas. Actual service availability probes cover every affected workload and co-tenant separately. The independent G2 record binds all components and physical availability to the attempt and pins; a missing component cannot be a pass.

`checks.scenario_battery` contains `manifest_ref`, `review_ref`, `evidence_refs`, `status`, `completed_at`, `required_archetype_families`, `required_scenario_ids`, and `scenarios[]`. The required families are `plain`, `stateful`, `neighbors`, `gpu*`, `sensitive-output`, and `vector-*`; expand wildcard families into concrete IDs from the pinned reviewed fixture/Phorvex battery, and retain named trace-integrity and adversarial-disjointness assertions. Each scenario carries `scenario_id`, `archetype`, `fixture_ref`, `fixture_hash`, `expected_outcome`, `status`, `evidence_refs`, `review_ref`, `epoch`, and `assertions[]` with assertion ID, status and evidence references. The manifest defines an expected SELECTED_AND_CONFIRMED, EXPECTED_REJECTION, or INTEGRITY_ASSERTION outcome and the exact assertion/evidence for each. Correct specified rejection passes its negative assertion but supplies no positive physical defense credit. Unsupported or unrun scenarios remain unknown and required. Every required assertion must independently pass before DEFENDED/INITIAL_WIN_ONLY; one failed assertion rejects battery admission. The contract must not treat GPU-free replay as a physical GPU proof.

The publisher's S10 matrix enumerates every source-framework technique in the admitted library, including excluded executable entries, and joins reviewed bucket/reason and actuator status with actual applicability, observation mode, case/epoch links, accepted gate/battery/challenge evidence and unresolved scope. Classification `covered` is not measured defense.

## Effect operation envelope

Every mutating operation includes campaign/case/round/attempt, bound target identity, fixture or action digest, source/runtime epoch, owner, lease ID/fencing generation, idempotency key, input hash, wall deadline, resource budget, and cleanup contract. Persist intent before sending. Persist the native operation ID and receipt after return. On timeout query the native operation before retrying; UNKNOWN_OUTCOME blocks conflicting work.

A defended-state reservation and an operation lease are separate records. The reservation names owner, resources, verified state, deadline, bounded idle wait, monitoring/cleanup budget and escalation action. It preserves the winner and blocks conflicting work, while each effect separately acquires a short fenced operation lease. Count reserved resources against actual physical capacity even when no model or actuator is currently running; no mutation lease spans uncontrolled model deliberation.

A lease/reservation timeout is not proof that the old operation stopped. Reconciliation first quiesces or fences the old runner, queries native operations and inspects observed state. A bounded renewed reservation may preserve the winner; otherwise finish owned cleanup and release, mark the chain suspended, and require fresh establishment/admission before continuation. Never silently release a defended-state reservation or claim a reset as maintained-winner re-attack. UNKNOWN_OUTCOME and RECONCILE_REQUIRED block conflicting work until resolution. Cleanup failure is a live obligation even when the experiment's model/token budget is exhausted; reserve cleanup capacity separately. The trusted local coordinator performs this sequence through real adapters; future distributed workers require the authenticated gateway.

## Evidence and review binding

References carry URI/path, content hash, producer identity, observation time/window, target/operation ID, source/runtime pins, and classification. Hash validity establishes bytes, not truth. The auditor verifies that those bytes support the claim and that the producer is appropriate. Authentication and trusted producer acceptance remain the responsibility of the adapter service.

The local register enforces structural guards and prevents lost updates. It cannot prove the target was actually changed or that actor names correspond to independent people/processes. Never expose its import command to untrusted distributed workers as a substitute for the authenticated service.

## Portable execution mapping

Claude Code, Cursor, or Codex should map a role task to its actual subagent/session facility, load COMMON plus the role prompt, attach the task envelope, and collect typed artifacts. A sequential harness can perform roles in separate independent sessions with reduced throughput. A harness without independent sessions must report that final independence is unavailable.

The proposed LangGraph version uses role-call nodes and deterministic tool nodes with conditional routing, durable checkpoints, and bounded parallel sends. Do not hold mutation operation leases across uncontrolled model deliberation; bounded monitored defended-state reservations follow the explicit reconciliation policy above. Read/store only the case subset each task needs. Keep API keys and credentials outside checkpoints and prompts.
