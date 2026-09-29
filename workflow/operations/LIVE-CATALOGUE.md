# Design and verify live catalogue items

Use this runbook when an agent is asked to design workload-specific red-team
cases, promote scenarios into Console **Live attacks**, or diagnose why a live
item lands. Start with the [successor handoff](../campaigns/2026-09-23-catalogue-coverage/HANDOFF-20260929.md)
and [original 22-item index](../campaigns/2026-09-23-catalogue-coverage/EXISTING-22-INDEX.md).
Use [CAMPAIGN.md](CAMPAIGN.md) for campaign records and [FIX.md](FIX.md) for
product repairs. This runbook supplements those workflows; it does not start
tests, grant access, or certify the current deployment.

The product objective is a measured chain: real workload stimulus → declared
brain input → normal decision → actuator execution → actual enforcement →
attacker outcome and legitimate-service outcome. Every result must identify
the first missing or failing step. A merged implementation or a Fire icon is
not a completed defense.

## Understand the three launch paths

| Path in Protect / Run | What executes | What it can establish |
| --- | --- | --- |
| Scenario catalogue **Run** | Harness scenario or configured fixed suite, using that entry's launch contract | Its specified functional, security or mechanism result; some suites target installed services, others use fixtures. Read the entry, not just its UI section. |
| Scenario **Send signal** | A synthetic, target-bound SecurityEvent | Signal admission and subsequent response; it does not execute the named behavioral attack. |
| **Live attacks / Fire** | A typed producer against a configured workload, with a durable exact run record | Only the behavior, response and controls implemented by that producer. Some older live entries are still effect-only or signal-only. |

Moving an item to Live requires a producer, deployed enforcement integration,
evidence and result handling. Changing a label or calling Send signal from a
new button does not accomplish it. Keep useful benign and reliability controls
in the catalogue; derive a separate security case when their threat is different.

## How the red-team work is done

1. **Discover the actual application and dependencies.** Read current
   Deployments/StatefulSets, images and running source, Services/EndpointSlices,
   routes, authentication, data ownership, model/tool integrations, policies and
   telemetry. Capture versions and time. Trace Voice → model/MCP/CRM/Mongo and
   LiteLLM → gateway/provider, for example; a namespace name is not a threat model.
   The old campaign covered Voice, vLLM, LiteLLM, NATS, Mongo/CRM, Chroma, MCP and
   Phorvex itself. Refresh that inventory rather than assuming it is unchanged.
2. **Map a real trust boundary.** Specify who controls the input, which route
   receives it, the forbidden effect, and an ordinary operation that must keep
   working. Use owned synthetic records, identities, messages and marker values.
   For Voice, direct WebSocket media may exercise the real application pipeline;
   it does not prove telephone-network behavior. No phone call is required by
   this method.
3. **Research applicability.** Start from installed source/configuration and
   vendor advisories, not an impressive attack name. A CVE candidate needs the
   primary advisory URL and checked date, affected version range, enabled feature,
   reachable vulnerable route, and a bounded test. An installed package alone is
   insufficient. Record not-applicable candidates and their reason. Non-CVE
   business-logic and ownership failures are valid cases too.
4. **Define the oracles before implementing.** What original response, accepted
   operation, stored value or active session proves the threat? What measurement
   proves it stopped? Define latency, availability, cleanup and resource limits.
   If the model never reveals the synthetic marker or never makes the forbidden
   tool call, record not-landed/non-discriminating, not a Phorvex defense. Do not
   edit a model response to manufacture the baseline.
5. **Trace the response path.** Establish the input mode below, the policy's
   selector and allowed actions, candidate capability, telemetry and constraints.
   Choose acceptable defenses by their causal effect, not their names. Inspect
   the actual implementation and workload enforcement hook. A restart does not
   necessarily revoke a credential; a NetworkPolicy object does not prove packet
   filtering; rotation does not undo an earlier disclosure.
6. **Implement one complete case.** Reuse a current typed live runner and its
   independent controls. If no existing actuator can stop this threat while
   preserving legitimate behavior, implement the missing actuator and application
   integration through the reviewed fix loop. Finish a vertical slice before
   accumulating more unverified buttons.
7. **Deploy, verify and repeat.** Check actual manager, Console, application and
   relevant controller source/digests and configuration. Run through the normal
   Console route, independently inspect the full chain, repair the demonstrated
   failure, and rerun. Repeat after cooldown, an ordinary rollout and retained
   enforcement state before calling the item reusable.

Use the campaign [case template](../campaigns/2026-09-23-catalogue-coverage/CASE-TEMPLATE.yaml)
for the threat, input, decision, execution, evaluation and cleanup contract.
Maintain [coverage.yaml](../campaigns/2026-09-23-catalogue-coverage/coverage.yaml)
as the historical starting matrix and create a dated successor revision after
refreshing the inventory. Preserve old results rather than rewriting their pins.
Exploratory cases and repeatable benchmark cases need separate labels; version
the latter so later brain changes can be compared on unchanged cases.

## Declare what the brain sees

| Mode | Required evidence | Claim boundary |
| --- | --- | --- |
| Proactive without an alert | Actual context/telemetry, policy, decision and same-target operation | No SecurityEvent is required if that policy/action path can act proactively. Risk and blast-radius inputs are not proof that an attack occurred. |
| Real detector | Original workload behavior, actual detector/rule, admitted event identity and matching decision | Exercises natural detection as well as response. A detector Pod being Ready is insufficient. |
| Test-injected response | Observed test behavior, explicitly labeled injected event and the normal brain/actuator path | Exercises response after a test signal. It does not prove autonomous detection. Current Voice/LiteLLM live runners contain this mode. |

The owner explicitly accepted synthetic SecurityEvents in live Voice/LiteLLM
tests, provided they are disclosed. They are not automatically produced by a
natural detector merely because they are real Kubernetes objects. A reactive-only
policy may correctly choose NOOP without a qualifying input. Never silently
switch modes, force the selected action, or remove safety constraints to obtain
a green result. A useful paired control omits the event or supplies an unrelated
target/event and checks that it gains no response attribution.

## Implementation map

Paths below are relative to the repository root. Follow the latest code; the
September29 handoff pins the source snapshot used to assemble these pointers.

| Concern | Starting point |
| --- | --- |
| Live listing, compatibility and arming reasons | `phorvex/internal/console/attack_compat.go` (`liveAttackCatalogue`, `compatibleLive`) |
| Fixed-suite catalogue and launch kind | `phorvex/internal/console/catalogue_v1.go`, `phorvex/internal/cataloguev1/types.go`, `phorvex/internal/console/runs_catalogue_v1.go` |
| HTTP routing and authorization | `phorvex/internal/console/routes.go`, `auth_middleware.go` |
| Launch UI and exact result polling | `dashboard-web/components/panels/live-launcher.tsx`, `dashboard-web/lib/live-attack-dispatch.ts`, `dashboard-web/lib/api.ts` |
| Result storage, attribution and display | `phorvex/internal/console/attack_results.go`, `attack_monitoring.go`; `dashboard-web/lib/attack-result-truth.ts`, corresponding probe panel |
| Candidate generation and capability | `phorvex/internal/actionset/generator.go`, `phorvex/internal/capability/gate.go`, `phorvex/internal/model/types.go` |
| Actuation and protected operation history | `phorvex/internal/actuator/`, including the specific action, journal and recovery implementation |
| Configuration and native permissions | `phorvex/cmd/console/`, `phorvex/api/v1alpha1/phorvexpolicy_types.go`, `deploy/helm/phorvex/`, umbrella `deploy/helm/phorvex-stack/` |
| Existing harness stimuli and controls | `build/test-harness/scenarios/`, `build/test-harness/fixtures/`, `phorvex/internal/cataloguev1/` |

For each promotion, record the old catalogue ID, new live ID/route, exact
behavioral claim, input mode, profile schema, deployment prerequisites and
superseded claim. IDs need not be one-to-one. Keep old controls when they remain
useful and do not transfer their historical PASS to the new behavioral case.

A live producer must persist intent before effects, return a unique record ID,
bound execution and observation time, and preserve raw evidence. Poll that exact
record, not the latest record in the namespace. Keep the UI budget consistent
with the backend observation deadline. Profile, RBAC, source image, application
hook, Service route and native action must all be installed before arming; a
disabled item should explain the missing prerequisite.

Use supported renderers with fresh inputs. Some older profiles pin Pod/container
incarnations; others pin stable source/owner identities and discover Pods at Fire.
Check which contract applies after rollout. Do not hand-edit old evidence into
fresh pins, reapply a revision-zero policy over current enforcement, erase an
unknown journal, or restore a revoked credential just to enable another run.

## Existing actuator patterns and new ones

The [handoff](../campaigns/2026-09-23-catalogue-coverage/HANDOFF-20260929.md#implemented-live-patterns-to-reuse)
links the current Voice/LiteLLM/vLLM implementations. New actions already include
scoped memory-note revocation, refund-pair denial, output policies, MCP tool pinning,
Voice session admission, LiteLLM client revocation and inference credential revocation.
The historical generic rotate/quarantine roster is not the whole current roster.

For a missing defense, specify the authority and scope of the change, the
protected operation ID, retries/idempotency, partial failure, restart recovery,
readback from every relevant serving replica and legitimate-service impact.
Wire the candidate and its cost/capability conditions into the normal brain,
native dispatch and permissions, plus the application enforcement point. Test
wrong/stale target and source, lost acknowledgement, replay and already-enforced
states. Do not count a ConfigMap write as completion before the application has
loaded and enforced it. A new actuator is justified by a missing causal capability,
not by wanting one distinct actuator per catalogue item.

## Live run and verdict contract

Reserve the target and shared dependencies with the active lead. Parallel source
work is useful; concurrent live mutations on the same model, policy, audit or
application can invalidate each other even when the Console permits concurrency.
Have an independent reviewer check authored changes and original evidence.

Retain these observations for every run:

1. Source/image/configuration and target identities; legitimate baseline and
   actual attack attempt, including first loss if any.
2. Telemetry or admitted event with input mode; policy UID, exact target UID and
   event/run identity.
3. Brain tick/decision, selected action and rejected alternatives with reasons.
4. Matching operation, dispatch and completion/readback; original raw evidence.
5. Independent attacker replay and legitimate workload outcome, including all
   serving paths/replicas required by the claim.
6. Console exact-record result, retained history, bounded cleanup and independent
   review. Confirm old results survive ordinary redeployment.

| Observation | Report it as |
| --- | --- |
| Threat reproduced, normal brain action caused measured containment, legitimate controls pass | Scoped **DEFENDED**, with any earlier loss still explicit and the input mode stated |
| Forbidden effect persists in a valid completed trial | **LANDED**, with the earliest demonstrated cause and repair/next experiment |
| Baseline already refused; no new action | Static/already-existing protection or not-landed; no fresh brain-defense credit |
| Only an epoch, variant, target replacement or action receipt is confirmed | Effect/mechanism observed; threat outcome unverified |
| Missing evidence, launch error, timeout, drift, unsafe cleanup or invalid control | UNKNOWN / INCONCLUSIVE / BLOCKED / invalid trial as appropriate; never force a binary answer |

Diagnose in order: **launch/configuration → application baseline → signal/admission
→ brain feasibility/selection → native dispatch → runtime enforcement → attacker
and legitimate outcomes → result reporting**. Distinguish proven cause from a
hypothesis. A candidate refusal can be correct (cooldown, availability floor,
missing capability or excessive disruption); compare it to the case contract
before filing a brain defect. A new actuator cannot fix a missing signal or a
Console polling error. Record separate findings if several layers fail.

The reusable acceptance check includes a first run, a repeat after normal
cooldown, a protected-state rerun, a relevant negative/mismatched-evidence control,
and revalidation after a normal rollout. Use fresh owned credentials or fixture
identities where the contract supports them; old revocations remain effective.
Do not require repeated fresh actuation when the honest outcome is already protected.

## Deliver and hand off

Provide the live ID and UI path, source PR, actual deployment evidence, run IDs,
stage-by-stage result, availability/cost observations, limitations and cleanup.
Publish reviewed fixes against current `main`; merge/deploy only within current
owner authorization. Reuse authorization already granted; do not create a new
approval ceremony for every implementation step. This documentation task itself
does not resume the old campaign or change cluster configuration.

New discovery expands the workload coverage matrix after existing cases have
clear owners and evidence. Keep security trials, mechanism tests, benign controls,
blocked items and unsupported hardware in separate coverage counts. MIG was
unavailable in the previous campaign; no verification was earned for it. Network
containment needs actual packet enforcement and a legitimate-traffic control,
not a promise inferred from Kubernetes resources. Recheck current infrastructure
and coordinate any change with its current owner.
