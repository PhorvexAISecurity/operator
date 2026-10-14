# Stages and routing

Every transition consumes versioned inputs, records its actor and evidence, and writes a new case revision. A stage name describes location in the graph; `work_state` describes whether work is running, queued, blocked, or awaiting another party. A register update cannot authorize an experiment or certify a defense.

## Stage contracts

| Stage | Responsible role or service | Inputs | Required output and exit condition | Failure destination |
| --- | --- | --- | --- | --- |
| S0_SCOPE | ORCHESTRATOR and trusted coordinator | Owner scope, library, budgets, adapters | Campaign manifest, matching library scope-review and build-time refresh receipts, admitted subset, tool availability, actual worker/model plan | Specific missing-scope/review/refresh/tool input; local planning continues |
| S1_SCAN_SELECT | CLUSTER_ANALYST and LIBRARY_SELECTOR | Read-only scan, reviewed entries | Provenance-backed applicability and exclusions; candidate identities | NOT_APPLICABLE, unknown observation, or classification review |
| S2_BIND_REVIEW | CASE_BINDER and independent CRITIC | Candidate, fixture registry, scan | Bound capability, approved fixture, observations, probes, matched control, impact and cleanup; critic concerns resolved or preserved | Fixture/observation/probe handoff; never customer repair |
| S3_TWIN_ADMIT | Controlled runner and trusted coordinator | Reviewed contract, resource scope, pinned versions | Isolated twin/control identity, fidelity check, reservations and operation leases, availability limits | NON_TRANSFERABLE or infrastructure/admission blocker |
| S4_ESTABLISH_REAL | Runner, C1–C6 gate, independent receipt review | Approved fixture and twin | Attacker state demonstrably present; applicable reality checks admitted; trusted input provenance recorded | Fixture failed, prerequisites disproved, observation gap, untrusted evidence |
| S5_PROPOSE_DEFENSE | DEFENSE_PROPOSER, CRITIC, deterministic ranker | REAL case, enabled capabilities, decline memo | Investigation queue, dedup fingerprints, criticisms and minority obligations; no candidate forcing | Evidence gap or complete brain accounting with no passing selected response |
| S6_BRAIN_EXECUTE | Brain harness and controlled runner | Pinned inputs, normal action set, capability evidence | Deduplicated actual selection/refusal trace with complete action accounting; selected action's execution receipts | Closed refusal reason, operation failure, unknown effect |
| S7_MEASURE_REVIEW | Metrics engine, battery runner and EVIDENCE_AUDITOR | Original probes, trace, traffic, control, times, reviewed battery manifest | G1/G2/G3 and S1–S4 card, all mandatory expected-outcome battery assertions; initial WIN only after independent acceptance | Failed/unmeasured gates or battery, evidence repair |
| S8_CHALLENGE | CHALLENGE_PLANNER, CRITIC, runner | Maintained winner state and reviewed library | Admitted challenge rounds, minority slots, residual coverage | New instance goes through S2/S3 then S4/S5; untested scope stays open |
| S9_REPEAT_RELEASE | Fresh executor, runner, independent auditor | Accepted contract and pinned versions | Fresh reproduction, owned cleanup and release receipts | Failed repeat, drift, incomplete cleanup; invalidate dependent acceptance |
| S10_PUBLISH | EVIDENCE_AUDITOR and publisher | Required milestones, accepted originals, admitted full library | Scoped final result, per-framework classification/applicability/evidence matrix, limitations, report, immutable learning record | Remaining obligations keep closure open |
| SD_DESIGN | ACTUATOR_DESIGNER and CRITIC | Bucket-3 confirmed state, independently accepted no-passing-selected-response record | Ranked capability contracts with deterministic confirmation probes | Reject unenforceable designs; unsupported surfaces remain out of scope |
| SE_ENGINEERING | External engineering owner | Accepted design, authorized delivery scope | Real implementation/review/PR, deployment observation, registration; fresh evaluated epoch | Waiting engineering/deployment, follow-up PR, or closed unsupported finding |

S0 is shared campaign admission; each case references it. SD/SE are conditional branches, not unconditional tasks for all cases. A design may be reviewed before physical installation exists, but no defense is credited for the design itself.

S0 records `library_review_ref` and `library_refresh_ref`, both bound to the exact admitted library version/hash. The first records the source-required Zeinab math/scope review of bucket, actuator status and preconditions, or a concrete recorded owner decision satisfying that review. The second records the build-time source refresh: framework versions, retrieval times, source artifacts and ATLAS sub-technique mapping confirmation. A prior review of different bytes or an old source bundle does not satisfy either gate. Existing applicable receipts are reused; PLAN may finish local preparation with these inputs missing, but execution and dependent build work remain blocked.

## Required case contract before execution

The bound contract names the attacker capability in observable terms, library version/entry, workload identity and scan evidence, fixture template version, parameter bindings, relevant control surfaces, a positive baseline, observation adapter, brain input mapping, control run, effect probe, availability obligations including co-tenants, hold and timing windows, reviewed battery manifest, budgets, cleanup, and required reviewers. It distinguishes the desired response from whatever action the brain actually selects.

C1–C6 validate claims the case actually makes: reachability, RBAC, prerequisite facts, claimed CVE/EPSS, observed path/state, and trust. A non-CVE case does not need an invented CVE. Evidence absent for a claimed prerequisite is UNKNOWN. Replacing an application-specific exploit with an end-state fixture changes the claim scope and must be visible.

Fixture templates must already be reviewed for that state and surface. The binder may substitute only permitted parameters. A prose row without an executable fixture is a fixture-engineering dependency. Do not manufacture a new attack step to fill it.

## Brain input and effect fidelity

Record observation mode as NATURAL_OBSERVATION, AUTHENTICATED_FIXTURE_INPUT, or REPLAY_INPUT. Natural detection requires actual production-equivalent observation of the state. An authenticated fixture input can verify response logic and physical enforcement but does not establish natural detection. Missing input is an observation gap, not proof the brain evaluated and rejected the case.

Keep decision replay and physical effects separate. Replaying identical inputs can establish decision consistency. G1, availability, and physical S1 require original runtime receipts and appropriate probes. A marker process proves only what its declared equivalence contract supports; an annotation change alone cannot establish revocation, poisoning removal, or native enforcement.

Pin brain, actuator registry, policy, fixture, input snapshot, capability witness, runtime identity, and acceptance profile. The frozen replay clock provides determinism; elapsed physical time is measured with a monotonic clock and correlated wall-clock receipts. Never report simulated tick deltas as measured live containment time.

Deduplicate decision evaluation by `(epoch, tick_id, input_hash)`; the hash covers the complete state, policy, normal eligible action set and capability pins. A proposer ranking schedules investigation and evidence collection; it is not an input that forces a candidate selection. Preserve complete canonical `ActionStatus` accounting, validate the trace, and execute only actions the real brain selected. Identical pinned inputs cannot justify retrying another desired action. Another evaluation requires a genuine observed state/tick transition or separately reviewed implementation epoch, with the changed dependency recorded. Deterministic replay is allowed as a consistency check and never counts as new physical mitigation.

A no-passing-selected-response record accounts for the enabled action set using actual trace exclusions, selection and measured outcomes. It may establish CANNOT_HELP_ENABLED_SET in that evaluated context; it cannot assert that unselected actions were physically tested or universally ineffective. Missing action accounting, observation, or unresolved selected-action execution/probes remains incomplete rather than exhaustion. An unselected action with a supported closed exclusion does not require a fabricated physical trial or battery run. Required battery assertions apply to a would-be winning action: unknown assertions create a battery/measurement dependency, not an enforcement-gap finding; a confirmed failed assertion may reject that action. Do not remove competing actions, alter policy, or manufacture input weight to obtain a different selection.

## Gates and measurements

- G1: selected action removed the capability, confirmed by the approved probe and relevant post-action path/edge evidence.
- G2: all named components pass: `availability_floor` and `slo_headroom` feasibility laws; `bound_proof` with an enforced, deadline-bounded, safe-return-verified path inventory and value ZERO or BOUNDED; realized `ledger_hold` within each affected tenant's SLO window with overlap/censoring and measured/unmeasured accounting; and `co_tenant_isolation` with exact-zero changes to the compared co-tenant brain/state byte streams. Physical service availability is also measured for every affected workload and co-tenant. Decision-state isolation alone cannot establish physical availability; missing component evidence remains UNKNOWN and blocks G2.
- G3: matched clean control does not select the candidate actuator. Record all other selected actions rather than hiding them.
- S1: measured onset-to-capability-removal time; primary ranking key.
- S2: measured non-target impact.
- S3: repeated probe result over the declared hold window.
- S4: actual versus predicted cost, including the comparison baseline where required.

Metrics can reject a brain-selected action; they cannot approve an action the brain excluded. Quote the brain's trace verbatim alongside any clearly identified interpretation. Unknown is not zero. Every metric includes status, value or null, units, window, provenance, and measurement type.

PHASE1 requires G1–G3 and measured physical S1 plus the mandatory battery and declared challenge/repeat/cleanup obligations. FULL adds measured S2–S4 to successful full closure. Rev5 allows honest unknown scores in reports; this package records those limitations and does not label that run FULL_FULL. This stricter closure label is an orchestration choice, not permission to invent missing measurements.

Record G2 component results in `checks.g2_components`, keyed by `availability_floor`, `slo_headroom`, `bound_proof`, `ledger_hold`, and `co_tenant_isolation`. Each carries `status` and `evidence_refs`; `bound_proof` also carries `value` ZERO or BOUNDED on a pass. The independent G2 review binds these records and the physical availability receipts to the actual attempt, pins and windows.

## Mandatory battery before WIN

Rev5's Stage-5 battery is an actuator-works gate, separate from subsequent adaptive winner challenges. Before DEFENDED or INITIAL_WIN_ONLY, require every assertion in an independently reviewed, pinned battery manifest to pass. Its required archetype families are exactly `plain`, `stateful`, `neighbors`, `gpu*`, `sensitive-output`, and `vector-*`. Expand the GPU and vector families into the concrete fixture scenario IDs in the admitted registry/Phorvex battery, retain all required IDs, and include the named trace-integrity and adversarial-disjointness scenarios. Missing hardware, fixture bindings or probes creates UNKNOWN/NON_TRANSFERABLE evidence; it cannot remove an archetype or create a pass. The coverage report may describe the narrower measured subset while the actuator's mandatory battery admission stays incomplete.

The manifest specifies an expected outcome for each scenario: SELECTED_AND_CONFIRMED for a positive actuator proof, EXPECTED_REJECTION for a specified closed rejection, or INTEGRITY_ASSERTION for an invariant such as canonical complete action accounting, trace on/off equivalence, or disjointness. Positive scenarios require the selected action, G1–G3 and the declared measurements. A correct NaN fail-closed, reactive-only, or SLO-gate rejection passes its expected negative assertion; it does not establish an effective defense. This resolves the retained WS3 wording that simultaneously demands negative tests and a selected/pass trace for every scenario. One failed required assertion rejects battery admission; unknown or unrun assertions block it. Interpret trace reasons on every iteration.

Store this record at `checks.scenario_battery` with `manifest_ref`, `review_ref`, `evidence_refs`, `status`, `completed_at`, `required_archetype_families`, `required_scenario_ids`, and `scenarios[]`. Every scenario records `scenario_id`, `archetype`, `fixture_ref`, `fixture_hash`, `expected_outcome`, `status`, `evidence_refs`, `review_ref`, `epoch`, and `assertions[]` with assertion ID, status and evidence references. A G1–G3 result awaiting this gate remains submitted/provisional; it earns no DEFENDED or WIN promotion. Preserve the maintained competition state by running separate battery fixtures under separately admitted resources rather than resetting the winner.

## Failure routing

| Supported condition | Route and next deliverable |
| --- | --- |
| No applicable entry | Record why; advance other cases; do not invent one |
| Library classification conflicts with actuator status | Review request with entry IDs; do not silently rebucket |
| Fixture cannot establish the state | Harness/fixture owner receives exact failing receipt; no defense verdict |
| State exists but no qualifying input reaches brain | Observation adapter owner receives state-to-input gap; preserve response-only boundary |
| Brain did evaluate and refused | Preserve full action accounting; feed exact reasons to evidence investigation; another decision requires a genuine changed input/tick/epoch |
| Candidate dispatched, effect unknown | Reconcile operation; do not retry a destructive effect blindly |
| Capability removed but G2 or G3 failed | Record MITIGATED_UNACCEPTABLE; investigate eligible alternatives without forcing selection |
| Required battery assertion failed or unknown | Reject or block actuator admission; retain the scenario and evidence; no initial WIN |
| No passing brain-selected response for confirmed bucket 3, with complete action accounting and independently accepted failure evidence | SD_DESIGN, then external SE_ENGINEERING; do not imply unselected actions were physically tested |
| Bucket 1/2 has an implementation gap | Preserve CANNOT_HELP finding with classification review/engineering referral; SD requires reviewed eligibility |
| Apparent brain structural defect | Separate Phorvex engineering finding; no in-loop brain edit |
| Customer application bug | Describe it as observed case input or limitation; no application repair branch |
| Twin mismatch | NON_TRANSFERABLE for affected claims; do not transfer physical performance from replay |
| Budget reached or provider unavailable | Incomplete/budget state and exact continuation point; no successful terminal promotion |

Every blocker carries an owner and a verifiable exit condition. A design-stage handoff does not cause unrelated cases to wait.

Every newly selected challenge goes through S2 binding and independent review. S3 rechecks current fidelity, defended-state identity and resources, explicitly admitting any changed target/surface/lease scope; unchanged accepted admission evidence may be referenced only with matching pins. Then establish and confirm the new capability at S4 before S5. Preserve the winner and its reservation; no direct S8-to-S5 shortcut admits unreviewed fixture parameters or expanded physical effects.

## Reservation and operation lease lifecycle

A defended-state reservation retains the named resources needed for continuity through challenges and durability measurements; it is not permission to mutate. Each operation acquires a separate short, fenced lease immediately before its effect. No mutation lease is held across uncontrolled model deliberation. Reservations have an owner, affected domains, verified state, expiry/deadline, bounded idle wait, monitoring/cleanup budget and an escalation action.

A bounded reservation may remain while model tasks run only when the state is monitored and the physical lane capacity accounts for it. On a missed deliverable, owner handoff, provider outage or engineering wait beyond the bound, checkpoint evidence, stop scheduling effects, and reconcile in-flight native operations. Preserve the winner under an explicitly bounded renewed reservation if available; otherwise perform owned cleanup and release, mark the challenge chain suspended, and require fresh establishment/admission in a new attempt before continuing. Never silently free the resources or call a reset twin a maintained-winner challenge. Expired reservations/leases remain RECONCILE_REQUIRED until fencing/quiescence, observed state and cleanup justify release; cleanup capacity survives model budgets. Continue independent cases on genuinely unreserved resources, and report lane blockage if the winner occupies all available capacity.

## Re-entry and closure

After an external implementation is registered, preserve old attempts, append PR/deployment history, and create a new evaluated epoch. Invalidate checks depending on changed code, policy, fixture, inputs, or runtime. Independent structural evidence may remain valid when its dependencies are unchanged. Retest the original capability; do not claim that a new PR alone caused the result when the runtime includes cumulative changes.

An initial accepted defense has outcome DEFENDED and closure INITIAL_WIN_ONLY only after G1–G3, physical S1, the mandatory expected-outcome battery and independent review pass. It is not a full competition completion. Successful closure additionally requires preserved minority challenges, no untested admitted challenge within the declared scope, fresh independent repeat, cleanup, and final audit. This fresh repeat is an explicit orchestration requirement adopted for this package.

Competition states include ACTIVE, STABLE_IN_TESTED_SCOPE, CANNOT_HELP_ENABLED_SET, ENGINEERING_HANDOFF, NOT_STABILISED_WITHIN_BUDGET, NON_TRANSFERABLE, and OWNER_STOPPED. An empty queue caused by failed prerequisites or missing adapters is not STABLE. Negative or unresolved closure can finish administrative work without completing the defense milestone set.

Learn only from exact, independently accepted measured records. Store them shadow-only. Numeric calibration is a separate governed process; agents do not tune the brain to pass this competition.

S10 publishes a matrix containing every technique in the admitted full library, grouped by source framework/version and retaining aliases. Include entry/source IDs, reviewed classification `covered | after-effect | design-stage | out-of-scope(reason)`, actuator status, customer applicability with prerequisite evidence or UNKNOWN, fixture/observation mode, linked cases and tested epochs, gates/battery/challenge status, accepted evidence references, and residual scope. Entries excluded from the executable subset still appear with their classification and reason. The library's `covered` bucket is a scope classification, not a claim of tested defense; absent measurements are shown as untested or unknown. This matrix and the scoped final narrative must agree.
