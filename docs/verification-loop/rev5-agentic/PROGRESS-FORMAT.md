# Detailed case progress register

This format preserves the useful Rev4 distinctions between stage, activity, outcome, resolution, PR history, and complete-loop closure. It adds substeps, explicit evidence acceptance, versioned milestone completion, engineering branches, time accounting, real worker assignments, and reasons for lost progress.

The canonical local state is SQLite through `tools/progress.py`. Generated Markdown, JSON, and CSV are projections. Neither the utility nor a rendered percentage verifies physical defense: the accepted records must come from the independent reviews and deterministic services in the workflow.

## What the owner sees

The overview has one current row per case: ID, stack and target, library entry, current stage/substep, work state, accepted milestones k/n and percentage, actual brain action and effect, latest outcome/evidence level, resolution, closure, PRs, blocker/next action, and last evidence time. Case detail includes every milestone, all seven metrics, checks, assignments, time accounting, outstanding work, and PR/deployment/retest history.

Campaign summaries separate: registered cases, eligible/admitted cases, active cases, initial accepted defenses, full PHASE1 completions, full FULL completions, negative/unresolved closures, and stale evidence. A library row, proposed candidate, retry, or design document is not a completed catalogue item.

The main capacity summary displays actual ACTIVE cases / `case_parallelism`, PARKED and TERMINAL counts. ACTIVE consumes an admitted workflow slot, PARKED awaits a dependency/admission, and TERMINAL records completed disposition. Independently show recorded RUNNING case-worker job identities and the configured total agent budget, queued tasks, provider throttling, and physical lanes. The local renderer lacks the root/shared campaign task ledger, so total active agents is explicitly UNKNOWN; the orchestrator obtains the complete live count from the harness. It must not present the case-worker subtotal as that total. Observed physical counts come from adapter/scheduler receipts (`observed_physical_experiments` and its observation time), never from a configured limit; absent observations display UNKNOWN. Heartbeat freshness is separate from progress. Local renderer counts only the assignment records supplied; the scheduler must refresh their real job states.

## Milestone completion

Display **accepted defense milestones completed / required milestones for this case**, with an unweighted percentage. This is checkpoint completion, not elapsed effort, likelihood of defense, or an ETA. Milestones are fixed substantial obligations, never individual files or tool calls. The table always shows which obligations are missing so a percentage cannot hide the bottleneck.

Statuses are NOT_STARTED, RUNNING, BLOCKED, SUBMITTED, ACCEPTED, STALE. Only ACCEPTED milestones with an independent acceptance record and artifact references earn credit. A reported success remains SUBMITTED. A known failed gate is real information, recorded in the gate card and history, but does not satisfy the successful-defense obligation.

Formula: `completion = 100 * accepted_required / total_required`, rounded only for display. A case cannot obtain 100 percent merely by being closed. A negative terminal case might correctly show 8/18 accepted defense milestones and CLOSED_NEGATIVE. Report disposition completion separately from defense completion.

The default PHASE1 denominator is 15; FULL adds 3 measurement obligations, making 18. The fields in `templates/milestones.json` define the fixed obligation IDs; the workflow, gate receipts and independent review define their acceptance conditions:

| ID | Successful milestone |
| --- | --- |
| M01 | Reviewed applicability and provenance |
| M02 | Executable case contract and independent critique |
| M03 | Twin/control admission and fidelity |
| M04 | Attacker state established and relevant C1–C6 checks passed |
| M05 | Declared observation path and brain-input provenance verified |
| M06 | Existing-defense proposals, critique, and ranked queue accepted |
| M07 | Actual brain selection and feasibility established |
| M08 | G1 capability removal confirmed |
| M09 | G2 availability confirmed |
| M10 | G3 clean-control condition confirmed |
| M11 | Physical S1 containment time measured |
| M12 | Required winner challenges and minority checks completed; mandatory battery already passed before the initial WIN |
| M13 | Fresh independent repeat accepted |
| M14 | Owned cleanup and resource release confirmed |
| M15 | Final independent review and scoped report accepted |
| M16 | FULL profile: S2 collateral measured |
| M17 | FULL profile: S3 durability measured |
| M18 | FULL profile: S4 cost measured |

Selecting AUTHENTICATED_FIXTURE_INPUT or REPLAY_INPUT never permits a natural-detection claim. M05 records verification of the declared mode; the overview separately exposes claim scope. Replay-only mode cannot satisfy physical effect/timing milestones or DEFENDED.

When an admitted actuator-design/engineering branch opens, append E01 accepted actuator specification, E02 independent design review, E03 engineering implementation and source review, E04 PR delivery, E05 observed deployed registration, E06 accepted post-deployment retest. The denominator becomes 21 or 24. One shared change may satisfy engineering obligations for several cases only when applicability and the per-case retest are demonstrated. E04 alone gives no defense credit.

Record the branch admission, reason, and progress-plan revision. When requirements are added, show old and new denominators. When changed dependencies make milestones STALE, the current numerator decreases and the report states why. Retain historical acceptance. Never drop requirements to inflate the percentage. Profile changes require a new declared evaluation scope; PHASE1 cannot be presented as FULL.

## Case detail record

| Group | Required content |
| --- | --- |
| Identity | Case ID, title, stack, customer target, twin target, campaign/competition, library entry/version, capability |
| Location | Stage, precise substep, scheduling_state ACTIVE/PARKED/TERMINAL, work state, round, attempt, owner, real task/worker IDs |
| Context | Acceptance profile, observation mode, claim scope, scope/source/policy/fixture/runtime pins and epoch |
| Progress | Milestones with status, author, reviewer, artifacts, acceptance time, dependency pins, blocker and stale reason |
| Chain | Baseline, observation, decision/refusal, expected versus selected actuator, dispatch, native effect, post-probe |
| Measurements | G1–G3 and S1–S4, status/value/units/window/measurement type/evidence; unknown values are null |
| Result | Outcome, evidence level, failure layer, actual/planned resolution, competition state, closure, final review |
| Delivery | Ordered PR list with source reviews, merge status, deployment observations, follow-up links and every retest |
| Timing | Created/start/update/evidence/heartbeat times; active-work and wait time by stage with observed sources |
| Remaining work | Open obligations, next deliverable, accountable actor, deadline, and dependency/lease references |

Outcome values: PENDING, DEFENDED, NOT_DEFENDED, MITIGATED_UNACCEPTABLE, INCONCLUSIVE, NOT_APPLICABLE, OUT_OF_SCOPE, NON_TRANSFERABLE. Keep `threat_effect` separately as NOT_ESTABLISHED, CAPABILITY_PRESENT, CAPABILITY_REMOVED, or UNKNOWN. A failure to establish a fixture is INCONCLUSIVE, not proof of defense.

Evidence levels are NONE, REPORTED, INDEPENDENTLY_VERIFIED. Resolution is a list, such as EXISTING_ACTUATOR, NEW_ACTUATOR, ACTUATOR_CORRECTION, OBSERVATION_INTEGRATION, HARNESS_CORRECTION. Planned changes have a separate list. No in-loop BRAIN_FIX or CUSTOMER_REPAIR resolution is admitted in this Rev5 package.

Closure values are OPEN, INITIAL_WIN_ONLY, FULL_PHASE1, FULL_FULL, CLOSED_NEGATIVE, CLOSED_UNRESOLVED, CLOSED_NOT_APPLICABLE. FULL_FULL means the FULL acceptance profile, not universal coverage. The competition can remain ACTIVE even when one case has an initial defense. Historical DEFENDED is retained when context changes, but `current_validation` becomes STALE until retested. UNKNOWN is reserved for an unverified result without a currently admitted DEFENDED claim. Show it as historical, never as a currently verified defense. Only CURRENT, independently accepted results can enter current defended/completed counts. `defended_at` binds the accepted WIN time; it is not the report-generation time.

## Explicit proof records

`checks.scenario_battery` carries `manifest_ref`, `review_ref`, `evidence_refs`, `status`, `completed_at`, `required_archetype_families` including plain, stateful, neighbors, gpu*, sensitive-output and vector-*, `required_scenario_ids`, and `scenarios[]`. Each scenario records its ID/archetype, fixture reference/hash, current epoch, expected outcome, evidence/review references, and individual assertions `{assertion_id, status, evidence_refs}`. Expected outcomes distinguish SELECTED_AND_CONFIRMED, EXPECTED_REJECTION and INTEGRITY_ASSERTION. All required assertions must PASS before DEFENDED/INITIAL_WIN_ONLY; `completed_at` must not follow `defended_at`. Unsupported physical archetypes remain unverified. The named invariant assertion IDs are `action-status-completeness`, `slo-gate-rejection`, `nan-fail-closed`, `reactive-only-honesty`, `trace-on-off-selection-equivalence`, and `adversarial-disjointness`. SLO/NaN assertions belong to EXPECTED_REJECTION scenarios; the other four belong to INTEGRITY_ASSERTION scenarios. All must be included among required scenarios, not optional extras. The required battery is completed at S7; M12 also includes later challenge/minority obligations and therefore cannot be fully accepted at the initial WIN.

`checks.g2_components` records the separate named components `availability_floor`, `slo_headroom`, `bound_proof`, `ledger_hold`, and `co_tenant_isolation`. Each contains status and evidence references. `bound_proof.value` is ZERO or BOUNDED for a passing G2; UNKNOWN never becomes zero. The workflow defines the additional feasibility-law receipts and separates exact-zero brain byte-stream isolation from physical co-tenant availability. The utility checks required metadata; the auditor must inspect the actual proofs.

`chain` keeps the expected actuator, actual selected actuator, brain trace, dispatch and native effect separate. A current DEFENDED claim requires independently accepted M01 through M11 (all prerequisites included), threat_effect CAPABILITY_REMOVED, a confirmed causal physical chain, passing original gates, and the pre-WIN battery. The record also retains the exact decision/refusal interpretation and any no-effect result in attempts. Status words alone never establish effect truth.

A dependency change invalidates affected milestones and metrics; prior accepted bytes survive in the event history. Reacceptance after changed dependencies requires a new review reference and a later acceptance time; editing old acceptance pins leaves that milestone stale. Current validation cannot be restored by editing a label: reevaluate the required dependencies and obtain independent acceptance. The register protects revision/history and structural invariants; it is not a replacement for scope admission, signed operation receipts, producer identity verification, or a production authorization gateway.

## PR and retest history

Each `prs[]` element includes `repo`, `number`, `url`, `change_types`, `state`, `head_sha`, `merge_sha`, `review_ref`, `follow_up_to[]`, `deployments[]`, and `retests[]`. Deployment entries carry actual image digests/source, target, time, status, and evidence. Retests carry attempt ID, tested epoch/source, deployment reference, outcome/evidence level, and exact artifacts.

Do not replace failed retests when a later one succeeds. Do not invent PR links before they exist. A merged PR is not proof of deployment, and deployment is not proof of defense. A shared PR is one delivery object referenced by several case records; each case retains its own verification obligations. External engineering handoffs must carry the no-Co-authored-by commit requirement.

## Updates and durability

Workers return structured proposals to the root at every stage transition, artifact submission, accepted/rejected check, decision, effect, new blocker, PR/deployment/retest, repeat, cleanup, and final review. Long tasks send a meaningful heartbeat at most ten minutes apart. The event states actor/task/case, expected revision, actual change, evidence refs, next action, and failure layer if any.

The local tool applies full case replacements transactionally with optimistic concurrency and enforces the campaign ACTIVE-case cap across concurrent admissions. Worker/physical resource admission remains a separate scheduler/gateway responsibility. It requires the caller's expected current revision, retains each previous snapshot in history, increments the revision, and serializes the write. A stale caller must load current state and reconcile only its owned changes. The utility does not authenticate agent identities or independently inspect external evidence; use it within a trusted local coordinator. Distributed operation requires the authenticated update service from ARCHITECTURE.md.

Example local commands, from the package root:

```sh
python3 tools/progress.py new-case --campaign campaign-001 --id C-001 --stack voice --profile FULL --out RUN/C-001.json
python3 tools/progress.py put --db RUN/progress.sqlite --file RUN/C-001.json --expected-revision 0 --actor orchestrator --reason 'Registered reviewed candidate'
python3 tools/progress.py get --db RUN/progress.sqlite --case C-001 --out RUN/C-001.json
python3 tools/progress.py put --db RUN/progress.sqlite --file RUN/C-001.json --expected-revision 1 --actor orchestrator --reason 'Recorded binding review'
python3 tools/progress.py render --db RUN/progress.sqlite --out RUN/report
```

The second put assumes the caller has actually edited the exported record to reflect new evidence. Do not blindly replay the example revision number. Renderer timestamps are generation times; they never change the case's evidence timestamp. For a reproducible demonstration use the synthetic example generator included in `examples/`, not a real campaign.

## Avoiding misleading progress

An accepted scan and a hundred planning messages can still leave execution at zero; the stage and milestone breakdown will show that. Show physical episodes attempted, confirmed REAL cases, accepted initial defenses, and completed loops separately. Record time waiting for an adapter, engineering, deployment, review, resource conflict, or provider rather than calling all of it agent work.

Aggregate completion is the ratio of accepted obligations to required obligations across the explicitly listed registered cohort, including its parked and terminal cases. This is independent of scheduling_state ACTIVE. Also report completed-case counts; an average hides the difference between ten partially prepared cases and one completed defense. Added cases or engineering obligations change the denominator and must be announced. Historical trends reference cohort and plan versions.

All examples in this package are synthetic. They demonstrate formatting and guards, not Phorvex results.
