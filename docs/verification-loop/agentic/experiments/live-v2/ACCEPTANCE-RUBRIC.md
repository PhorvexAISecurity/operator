# Live V2 acceptance rubric

Prepared by independent reviewer `/root/agentic_reviewer`, 10 October 2026 UTC. Reference/source hashes sampled at 2026-10-10T11:43:02.107290Z. Repository HEAD: `ca69456b17299aa742c5ea9275fb5e6ae9cccfa4`, branch `feat/verification-loop-live-trial`.

**Initial disposition: NOT ESTABLISHED.** The deployed candidates exist, but no successful attack baseline, authentic observed chain, native effect, legitimate hold or independent live reproduction has yet been established by this reviewer. This rubric is a review requirement, not permission to mutate a cluster or Fire a case. The next step is review of the discovery and measurement plan.

The earlier credential episode proves its recorded local response only. Its `LOCAL_PILOT_ACCEPTED` result is historical and cannot substitute for this owner-requested end-to-end architecture trial. Preserve it and its scope; do not relabel it as natural detection or complete architecture confidence.

## What must be exercised

The actual agent workflow must discover relevant deployed facts, propose a grounded case, receive independent oracle/plan review, freeze source and supported inputs, execute through genuine producers and the installed manager, classify measured outcomes, route any failure to its first responsible stage, retest before cleanup, and reproduce independently. Record the real tasks, role actors, accepted dependency hashes, attempts and decisions. A root-written script plus agent agreement does not by itself exercise these responsibilities. Reused analysis and operator hints must be disclosed; tasking a case engineer to inspect KV or adapters is not autonomous workload discovery.

The unchanged deterministic engine owns its actual decision. Selection alone is not ground truth for mitigation: independent application behavior and availability must agree. A genuine refusal, missing prerequisite, unavailable oracle or failed defense is an evidence-bearing outcome; it must not become a passed chain because routing worked.

## Read-only findings

A read-only SSH session through the authorized existing control socket queried deployment metadata and the two detector script ConfigMaps. No serving probe, detector trigger, event creation, pod execution, cluster change or Fire was performed. No access secrets were printed or copied to this document.

- `vllm/detector-kv-canary`, `vllm/detector-adapter-inv`, `vllm/vllm` and `phorvex-system/phorvex-phorvex` were ready at their observed generations. Detector readiness establishes installed presence, not producer correctness or an exploitable capability.
- KV detector ServiceAccount is `detector-kv-canary`; ConfigMap `kv-canary-detector-script`, UID `8cc51a02-487a-4a1d-b21d-cf76eca606fa`, `detector.py` SHA-256 `3f9f77c33ef2166214bbd0edeca61261b27bdc845ff8a427ccc58b03f9d8b9ab`. It plants a prefix, compares re-probe timing with a cold reference, emits when warm, and retires the canary after a cold probe because probing re-plants it. This is a real deployed producer candidate. Its own warm prefix alone is not proof of unauthorized cross-tenant inference.
- Adapter detector ServiceAccount is `detector-adapter-inv`; ConfigMap `adapter-inv-detector-script`, UID `19a4a901-e148-42b0-add2-52df9f30f3aa`, source SHA-256 `5f37421809b883b537ffd3a913e223f56c7ae918a6b87430e7fa206db53012a8`. It compares inventory with `EXPECTED_ADAPTERS`, sets a suspect marker and emits an event. A configured inventory mismatch establishes that predicate; malicious capability requires a separate oracle.
- The installed manager is configured with image tag `phorvex:0.4.217`. A tag or local checkout is not deployed-source attestation. Discovery must retain the resolved running image digest, manager version/source provenance, actual relevant policy and observed source/ConfigMap generations.
- Local source `eventtrust.go` requires authenticated creator identity and notes that a self-declared rule source is not identity. The admission stamp requires its server-side validating policy/binding to prevent spoofing when the webhook is unavailable. This must be checked on the deployed API; a model-supplied annotation cannot prove it.
- Existing `verification-workflow/protocol.py` is deliberately specific to `endpoint-lease-revoke`, the private synthetic credential scope and `TEST_INJECTED`; it rejects stronger observation/lifecycle claims. It cannot certify KV, adapter removal, the installed manager or a persistent dev runtime. Preserve that boundary and add a separately reviewed adapter/gate.

These observations are provisional and can drift. The frozen plan must refresh current bytes and identities immediately before execution.

## Required pre-execution contract

Before authorization of execution, independently review a concrete plan containing:

1. **Owned environment and limits.** Exact cluster/context, namespace, workload owner and Pod UID, affected services/endpoints, tenancy and explicit dev/twin relevance. Enumerate allowed writes, principals, input/probe endpoints, data, reversible restoration, traffic/sample limits, deadlines, stop conditions and cleanup owner. Shared unrelated resources are excluded. Discovery is read-only until this plan and lease are accepted.
2. **Claim and attacker model.** The precise capability and security boundary, its successful application-level baseline, why the installed detector should observe it, and why the candidate response removes it. Use owned canaries and scoped test data. Ordinary same-principal cache warming or allowed adapter inventory does not become an unauthorized attack by naming it one.
3. **Natural observation path.** Detector source/image/config and actual probe predicate, genuine telemetry/probe producer, authenticated event identity, admission controls, target resolution and freshness. Planned manual SecurityEvent creation, expected-action annotation or direct manager input injection cannot satisfy natural detection.
4. **Runtime and provenance.** Freeze deployed manager/serving image digests, relevant script and policy bytes/UIDs/generations, tool/adapter bytes, accepted refs, supervisor actor/task IDs, operation-input hash and environment ID. Local Git revision and deployed revision may differ; state both. Record any proxy, deterministic backend or fixture metadata and what they fail to establish.
5. **Independent oracle and budget.** Exact baseline/effect/legitimate predicates, raw data retained, observed principal/session identity, sample timing, predeclared thresholds, detector cadence, decision deadline and hold duration. Review oracle source independently of its author. No threshold is selected after inspecting outcomes.
6. **Lifetime and reproduction.** Which state persists, who owns its mutation lease, how pre-cleanup probes run, and how the reviewer will establish a distinct fresh baseline under a new episode. Merely inspecting the verifier's terminal state is not fresh reproduction.
7. **Repair authority.** Who may change detector/config/adapter code or deployed runtime after a demonstrated defect. Changed source, policy, producer or contract invalidates affected evidence and requires new pins/review/attempt. Do not change scoring, expected action or availability criteria to obtain a pass.

A scoped persistent dev/twin runtime is eligible only if this relevance and ownership contract is reviewed. It is not automatically supported by the earlier self-contained credential tool.

## Ordered evidence gates

| Gate | Required evidence | Failure disposition and owner |
| --- | --- | --- |
| G0: discovery and admission | Source-backed live inventory, actual observation/effect surfaces, reviewed case/principals/oracle, approved scope and frozen inputs | Missing relevance or unsupported interface: case engineer/runtime specialist; stale identity/refs or scope: orchestrator |
| G1: attack baseline | Independent raw behavior proves the declared capability before defense; legitimate requests succeed; target and application state are bound | No unauthorized capability: CASE_NOT_ESTABLISHED, case engineer; outages or unavailable oracle: INCOMPLETE, verifier/runtime specialist |
| G2: genuine producer and trust | Actual deployed detector observes the relevant signal; event creation time/UID/target correlate with its requests; real ServiceAccount/admission evidence and manager ingest trace agree | No production: detector/integration owner; rejected/unstamped/stale/wrong target: exact observation stage; never fabricate an event |
| G3: installed brain | Actual manager trace with event/target/policy identity, normal candidate exclusions, feasibility, scoring and selected/noop action, followed by actual dispatch outcome | Noop/unsupported action remains that result; route exact policy/coverage/feasibility/capability cause without forcing selection |
| G4: native execution and physical effect | Native operation identity and authenticated application request/readback correlate with the selected trace and affected state; actual preexisting capability changes | Dispatch/readback failure: integration; capability persists despite claimed success: defense engineer; receipt or pod annotation alone never passes |
| G5: legitimate operation and availability | Correct legitimate application responses and work during/after action, real overlap where required, affected-workload traffic, error/latency/recovery measurements and retained missing bounds | Traffic/availability failure: runtime/SRE owner; timeout or 5xx is not threat mitigation; absent measurements are UNKNOWN |
| G6: defended-state probes | Predeclared attacker-only retests and bounded new variations execute before restoration/cleanup, with state/nonce/epoch and side effects retained | Reappearance, unsupported probe or destroyed state: measured failure/incomplete; no post-cleanup attack claim |
| G7: independent fresh reproduction | Reviewer-owned episode with fresh relevant baseline, producer, installed decision/effect, legitimate probes and cleanup, under a new lease and input/operation identity | Non-reproduced chain or drift stays INCOMPLETE; exact snapshot replay is supplementary |
| G8: architecture and evidence join | Accepted role/dependency handoffs, first-failure repair attempts if needed, separate control/task outcomes, operation state, raw evidence gates, lease readback and scoped conclusion | Orchestrator rejects missing/contradictory evidence; consensus cannot fill a missing gate |

The sequence is causal, not a requirement that every system emits perfectly synchronized timestamps. Establish clock sources/skew tolerance before the run, use operation/event identities, preserve detector/manager logs and application requests, and explain duplicate or concurrent events. Historical manager logs and an unrelated successful reset cannot stand in for this episode.

## Specific oracle obligations

**KV:** distinguish session/cache generation, planted prefix and attacker probe from unrelated prefixes, jitter and ordinary cache reuse. Show the tested principal/tenant isolation boundary and actual serving implementation. Detector timing and event production are one measurement source, not an independent attacker oracle. Preserve raw durations and application/backend behavior sufficient to reject false warm/cold classifications.

A probe may modify KV residency. The first cold post-action probe can repopulate it, so a later warm result must be interpreted with that new generation. Freeze a probe/state protocol that separates invalidation of preexisting residency from attacker-created or legitimate new residency. Do not claim permanent removal from a single flush or call probes read-only when they seed cache state. Detector retirement and quiescence must be observed, not forced by manually deleting its event.

**Adapters:** bind exact adapter identity and inventory epoch to the relevant principal, model/application behavior and target. The expected-set mismatch and suspect annotation are discovery signals. Independently show the unauthorized/malicious capability and its disappearance, successful use of legitimate adapters/base model, and authentic serving unload/readback. Inventory absence, a declared “unloaded” marker or a broad outage alone cannot establish defense.

**Controls:** predeclare clean/no-capability and relevant negative controls with safe scope. Verify that arbitrary outages, detector silence, stale/untrusted observations, no dispatch and unsupported action cannot be promoted to defense. When withholding action or deleting authority would disturb this shared runtime, prefer a reviewed isolated/twin control; inability to run a control is an explicit missing item. Prior credential controls and unit tests do not supply live KV control evidence. Do not inject untrusted events merely to make a required negative convenient.

## Executable gates required

A reviewer must inspect and exercise a new case-specific evidence adapter before execution. It must validate real actor/assignment and contract dependencies, live target/source/config identities, supported modes and lifecycle, baseline/raw probes, authenticated producer provenance, deployed-manager trace and native effect, legitimate budgets, causal timing and retest generations. It must distinguish native refusal, already-absent state, new mutation and unreachable stack.

Adverse tests must reject fabricated event identity, unrelated event/operation/target, stale dependencies, absent baseline, forced-action labels, forged or rehashed effect evidence, misclassified outages, missing availability and probe-induced cache changes credited to the actuator. The supervisor supplies expected pins; candidate reports cannot supply their own trusted expectations. Unsupported data stays incomplete. Do not replace the credential gate's hardcoded action with a new string and treat its 401/counter oracle as a KV proof.

Operation admission persists before mutation. Matching terminal deliveries return cached evidence without another command or fresh credit. Changed inputs under one ID reject. Interrupted side effects become ambiguous, with actual readback/reconciliation before any new operation. An advisory file lock or transcript is not authenticated cross-host permission enforcement. Record what is enforced here and what remains supervisor responsibility.

## Acceptance and stopping

Keep four dimensions explicit: **threat outcome**, **brain/effect attribution**, **workflow/task disposition**, and **scope of the architecture claim**. A failed baseline, missing genuine producer or unavailable effect oracle prevents successful end-to-end acceptance. Correct failure routing demonstrates that branch of the architecture but cannot turn the case into a passed defense. If repair is required, preserve the first failure, reviewed repair and new pinned trial; absence of a repair on a successful case does not prove the repair branch.

A successful architecture trial requires the applicable full chain and independent reproduction above, with honest negative controls and no criteria weakened after observation. It establishes evidence for this real deployed archetype, not a universal optimum or autonomous discovery across all customers. Model speed/cost claims require measured cost and comparable timing; unknown stays unknown.

Formal action SLO and sampled legitimate success are separate. Original WS-3 §2 Stage 4/§3 treats unknown formal bounds as UNVERIFIED and withholds full actuator approval. If current action remains unknown, retain that failed/unverified certification axis even when the observed deployed chain and the workflow are exercised successfully. Do not claim “all original gates passed,” full availability certification or production approval. The frozen plan must state the exact architecture claim permitted by those outcomes; the reviewer will not silently redefine unknown as safe.

Stop at the first missing prerequisite with its next owner and concrete repair/unsupported disposition. Budget exhaustion preserves the established case and exact unproven stages. The forthcoming discovery and measurement plan must answer these obligations before this reviewer recommends execution.

## Bounded reference anchors

The original proposal supplies intent, not present-day deployment proof: WS-1 §(a) inventory dimensions; WS-2 B.1–B.2 independent preconditions; WS-3 §0, §2 Stages 0–5 and §3 gate semantics; WS-5 §0–§1 fidelity/lifetime and §3.2 verdict semantics. Its inferred signature-level “twin” properties cannot independently attest to physical serving isolation.

Current V2's case contract, lifetime, outcomes and routing sections already distinguish injected pilot scope from full-chain needs. The live trial must implement the missing evidence interfaces instead of carrying over a narrower successful label.

| Input | SHA-256 |
| --- | --- |
| `/home/mehrdad/verification-loop/WS-1-scan-sizing.md` | `1314a430fc0526818e94886526320b2c70b66f925a2e5d49a9fa16d02b69c9f6` |
| `/home/mehrdad/verification-loop/WS-2-generator.md` | `10d90f671788d27cc36ed13858b5cd6ce859c14d1d763ee852472388272496f3` |
| `/home/mehrdad/verification-loop/WS-3-validator-rubric.md` | `aec19fcc62fc525cc034dcb801d5dd171df5947c7866825b78f9b0c4108b31b1` |
| `/home/mehrdad/verification-loop/WS-5-brain-in-loop.md` | `4bcc0ea708ac9ed05a82365ed4b758c31e9ea9ada5e5263e86704404987ea21c` |
| `docs/verification-loop/agentic/ARCHITECTURE-V2.md` | `40de4fd58e37ce2def96770f7346b56a734904bad3fd0529ab71ea2b48928b27` |
| `build/test-harness/verification-workflow/protocol.py` | `d767c656c6b31782b6b2d77f64458bf46b1c58125890864838ef1008b4fe07b2` |
| `phorvex/internal/ingest/eventtrust.go` | `29e06bf685af2e922ebc2cf5f0f557882167d71eadf04ec13497811ab401d98f` |
| `phorvex/internal/recon/ucw.go` | `ec4762c9581d8ccff363ad572de7888fa78a0b84e92a6e49dd08f1166d4d1702` |
| `phorvex/internal/actuator/handlers_ai.go` | `003b34c237e1fd511e70eb99f6184814a83e23c65770182d728335a5ba1e108b` |

