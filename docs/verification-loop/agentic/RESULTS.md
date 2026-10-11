# Agentic verification workflow: architecture experiment report

Date: 10 October 2026. This report describes a bounded experiment refining an
agent architecture with actual GPT-6.1 Sol workers. It is self-contained; no
access to the author's server is required to understand the results and limits.

**Result:** V2 is the selected architecture for the bounded local pilot. V1
proved the response but exposed orchestration defects; V2 corrected those
defects and passed fresh execution, negative controls and independent
reproduction. Eight disposable physical episodes were executed across the two
versions. This establishes an implementation starting point, rather than a
universal optimum or a completed autonomous red-team service.

## Purpose and acceptance standard

The owner asked for V1, an end-to-end trial, and successive architecture changes
until the workflow was good enough to transfer into a runnable LangGraph design.
The desired output was a reliable engineering and verification process, rather
than more untested catalogue entries or an LLM choosing defensive actions.

We selected an already implemented private credential-admission case so that
workflow failures could be separated from product-development failures. A and B
are synthetic credentials generated within the disposable experiment. A models
future reuse of a compromised caller credential; B represents legitimate traffic.
Both must initially perform the downstream operation. The unchanged Phorvex
engine must make its ordinary choice, the native response must execute, and A
must subsequently receive a specific authorization denial while B continues.

Architecture acceptance requires source/contract-bound handoffs, explicit
ownership, measured positive and negative controls, independent reproduction,
first-failure routing, bounded execution and honest incomplete outcomes. A
workflow can pass these local criteria without demonstrating every customer
stack, autonomous detector, persistent twin or new-actuator engineering branch.

## Common environment and source

The case implementation is pinned to commit
`f73d04cd6aac9f5945da1515e2dac76554869920`, based on main
`54c9273a6faaa3768e55adf15afb51de68b3241b`. The main source was fetched and
checked before this architecture experiment. Workflow changes use a separate
branch and do not modify the production engine, native actuator or admission
implementation.

The physical experiment contains a real isolated Kubernetes API server and
etcd, real API-generated identities and resource-version updates, the shipped
Python caller-admission implementation over HTTP/private authenticated TLS,
and a deterministic synthetic downstream application with a marker, unique
request nonce and invocation counter. It contains no kubelet, CNI, GPU inference,
real customer workload or deployed console. Workload readiness, image/owner
membership and endpoint metadata are declared fixtures.

The observation is explicitly `TEST_INJECTED`. Real observation admission and
trust checks execute, but publisher identity is provided by the fixture. The
runner supplies an explicit policy to the unchanged UCW shadow engine; it does
not exercise the manager's entire policy-resolution/controller path. Policy and
scoring remain fixed through each trial. The local anti-over-rotation window is
one second after actual identity-age maturation, rather than a production
five-minute configuration.

Workers used Go 1.26.1, Python 3.14.4, httpx 0.28.1 and uvicorn 0.34.0, with
Kubernetes 1.34.0 and etcd 3.6.4 envtest assets. The actual executing case binary
has SHA-256 `17f86a5307ef5c7395085af1b03e58c2bd39e596330bc68c93e4da3fa3cee0a6`.
The unchanged five-file admission/runtime closure has SHA-256
`870c8709a5da026d01449be737939fa35420ebd1bda341ea2371c6081926fda4`.
The supplied Git label alone is not execution attestation: source files, tools,
binary and retained evidence are separately hashed and verified.

Each command declares a three-minute internal timeout, a two-second denial hold,
250 ms sampling interval and two-second maximum legitimate-request latency.
These are experimental budgets, not customer SLOs. Formal action SLO remains
`unknown`: endpoint-lease revocation has no calibrated complete safe-return
deadline. Local legitimate-service success cannot promote that classification
to zero, bounded or production-approved.

## V1: actual trial and failure analysis

V1 had six mandatory roles: orchestrator, stack analyst, red-team engineer,
defense engineer, verifier and independent reviewer. Five GPT-6.1 Sol worker
tasks were assigned. The red-team task failed at the provider before producing
an artifact. Its absence was recorded; it was not called complete or retried
through another model. The orchestrator authored a narrower specification from
the existing reviewed owned-credential fixture, independently reviewed before
execution. This intervention did not discover a new attack.

The other workers produced source-backed inventory, existing-response analysis,
runtime evidence and independent review. The existing `endpoint-lease-revoke`
already addressed this capability; no new product actuator was warranted.

| V1 episode | Physical outcome | Workflow meaning |
| --- | --- | --- |
| Fresh positive | Native revoke selected and executed; A denied, B succeeds | Local response chain passes |
| Withheld dispatch | Brain selects, but A still performs the downstream operation | LANDED; selection alone is insufficient |
| Authority outage | After dispatch, authority is removed; A receives 503 | UNKNOWN/INCOMPLETE; outage is not defense |
| Independent fresh positive | Separate API identities and environment reproduce denial/B success | Independent local case acceptance |

The verifier's positive had 12 successful B samples, maximum latency
18.316454 ms, two actual request intervals overlapping native dispatch, and a
2276.977089 ms measured hold. A-after and seven A hold requests received exactly
401 `unauthorized`, with zero downstream increment. Baseline-to-confirmed-denial
interval was 565.251074 ms. Exact-input decision replay matched; shadow owner
state remained unchanged. Independent reproduction had 12 B samples, maximum
18.956368 ms, two dispatch overlaps and a 2280.971468 ms hold.

Three verifier episodes took 11.816, 10.318 and 9.317 seconds respectively.
The independent episode took approximately 12.24 seconds. Preparation and agent
coordination took longer than the physical experiments. The verifier checked
434 retained-evidence assertions; the reviewer separately checked 475 assertions
over the four reports. These are assertions, not independent attack cases.
Cleanup was confirmed before ownership transferred to the reviewer.

Nine independent preflight findings explained why V1 architecture was marked
`REWORK`, despite the passed local response:

1. Its graph sent every failure to defense, contradicting first-stage ownership.
2. Exclusive verifier mutation conflicted with reviewer-owned reproduction.
3. The command destroyed the environment before the separate re-attack node.
4. Handoffs lacked explicit contract, attempt, episode and dependency acceptance.
5. Three outcome dimensions were not mapped from the existing single verdict.
6. Retry, interruption, ambiguous mutation and worker loss were underspecified.
7. A response-specific tool was described as if it could verify any selected action.
8. Artifact authorship, oracle review and dependency acceptance needed separation.
9. Provider failure had no explicit route or bounded fallback disposition.

V1 did not execute two adaptive bypasses. Its fresh-nonce hold probes repeated
the same capability against the live defended state before teardown. Neither
a new fresh environment nor read-only report inspection was mislabelled as a
post-run re-attack of the destroyed environment.

## V2: changes justified by observed failures

V2 has four routine participants: orchestrator, case engineer, verifier and
independent reviewer. The case engineer combines relevant inventory and case
specification. Defense/integration and runtime/domain specialists activate only
for a concrete gap. This pilot also activated a workflow-tool engineer to build
the missing protocol gate; that one-time development task is counted separately
from the routine case roster.

The revised handoff explicitly binds actor/role, run, case, attempt, episode,
contract hash, source and required file references to supervisor assignments.
The deterministic gate rejects stale or changed inputs and self-review.
Negative controls have their own task success while retaining their adverse
threat outcomes. Runtime lifetime is explicit: this self-contained tool must
perform its predeclared capability retests before cleanup. A leased persistent
twin is a future adapter, not a silent assumption.

Independent preflight review caught and corrected further prototype weaknesses
before V2 execution: wrong real artifact names, incomplete authority/durable-state
binding, hold duration padded by slow legitimate requests, acceptance of an
unsupported autonomous-detector/persistent-twin claim, and stale-handoff rejection
misrouted to measurement repair. An actual archived contract was rejected and
routed to the orchestrator after correction. A legacy runtime-role label was
normalized and the affected handoff regenerated; the rejected draft remains
preserved. The admission/runtime source closure was independently recomputed
from current file bytes, rather than trusted from a candidate result.

The protocol prototype provides strict handoff/reference validation, measured
report classification, artifact cross-binding, stage routing and an atomic
SQLite operation-state ledger. The ledger suppresses duplicate admission and
preserves ambiguous states; it does not implement remote actor authentication,
cross-host runtime leases or external side-effect readback. Codex role restrictions
were supervised instructions, not an enforced production tool sandbox.

## V2 trial and final disposition

The V2 contract, prompts, schema, architecture, protocol and preflight review
were frozen at 11:21:04 UTC on 10 October 2026. Twelve frozen artifacts were
verified before execution. The case contract has SHA-256
`d8f00fdf3cdce1553456ed80279d8dc08b352e319174c2715621d8f6181023ed`;
the protocol has SHA-256
`d767c656c6b31782b6b2d77f64458bf46b1c58125890864838ef1008b4fe07b2`.
Fresh API identities, credential pairs and downstream counters distinguish
these episodes from earlier V1 evidence.

| V2 episode | UTC command window | Seconds | Physical evidence | Accepted dimensions |
| --- | --- | ---: | --- | --- |
| Fresh positive | 11:23:08–11:23:19 | 11.916 | Native revoke, exact A denial and continued B operations | BLOCKED / PROVEN_LOCAL_RESPONSE / POSITIVE_PASS |
| Withheld dispatch | 11:23:20–11:23:30 | 10.216 | Selected response never executed; A still performs the operation | LANDED / SELECTION_ONLY / CONTROL_PASS |
| Authority outage | 11:23:31–11:23:41 | 10.116 | A receives 503 after authority removal | UNKNOWN / NOT_PROVEN / CONTROL_PASS |
| Independent fresh positive | 11:25:54–11:26:07 | 12.919 | Separate runtime reproduces native effect, A denial and B success | BLOCKED / PROVEN_LOCAL_RESPONSE / POSITIVE_PASS |

Both negative episodes deliberately exited with code 1. Their workflow tasks
passed because they measured their declared adverse outcomes correctly. Neither
earned defense credit or triggered unnecessary actuator repair. The physical
positives exited with code 0. All times above are measured command times,
including startup and teardown; they are not decision latency.

The verifier's positive had twelve successful legitimate B samples, maximum
latency 17.621774 ms, and two actual request intervals overlapping native
dispatch. A-after and seven fresh-nonce A hold probes each returned exactly
401 `unauthorized`, with no downstream increment. The reported hold was
2279.042019 ms; baseline-to-confirmed-denial was 562.881794 ms. Independent
reproduction had twelve successful B samples, maximum latency 21.397229 ms,
two dispatch overlaps, and the same specific A-denial/no-effect behavior. Its
reported complete hold was 2293.009405 ms; the stricter first-to-last attacker
request-start interval was 2183.518 ms, independently exceeding the two-second
requirement. Its baseline-to-confirmed-denial was 586.475638 ms.

Each episode included successful attacker and legitimate baselines, clean and
stale-observation controls, actual observation admission, unchanged natural
brain selection and exact frozen-input decision replay. The positive effect was
bound to the selected operation, actual target identities, policy change and
protected terminal journal. Shadow evaluation left owner state unchanged. The
independent reviewer checked 431 raw-evidence assertions over the four V2
reports; these assertions are not 431 attack cases.

The V2 trial also exercised workflow failures and recovery boundaries:

- An intentionally absent runtime asset directory failed preflight, routed to
  the verifier and spawned no physical command. A corrected prerequisite used
  a new attempt ID and the existing pinned tools.
- An actual archived handoff was rejected against the newer contract. Its
  evidence remains preserved; rejection routed to the orchestrator.
- All three completed verifier operations were delivered again through the
  durable ledger. Each returned cached results without another subprocess.
  Cached evidence was explicitly excluded from fresh measurements.
- A separately labelled simulation recorded RUNNING and then AMBIGUOUS. Both
  repeated admissions denied execution. No physical command was interrupted;
  this tests admission semantics, not external side-effect recovery.
- The same response-only report was rejected under a stronger full-detector
  claim. No evidence criterion was relaxed to obtain acceptance.
- Six protocol test methods passed. Four are portable standard-library checks;
  two use retained runtime evidence and were executed here, without skips.
  They test handoff boundaries, invalid measurements, routing, concurrent
  operation admission and actual file binding.

The verifier released its advisory runtime lease after cleanup at
11:23:42.193477 UTC. The independent reviewer used a separate private episode
and released at 11:26:07.513097 UTC. Process and temporary-directory readback
found no case residue. These supervised lease records are not an authenticated
cross-host lease service.

The verifier's exact execution wrapper was retained from its tool-call
transcript after completion, with explicit provenance. It was not itself a
pre-hashed executed script. Its frozen dependency checks occurred before
protocol import and execution, and independent review checked the retained
wrapper and command records. A future service must also pin its executor
adapter before launch; this pilot does not overstate that attestation.

The independent disposition is **LOCAL_PILOT_ACCEPTED**. No remaining blocker
within the declared local scope justifies a third architecture version. V2 is
therefore selected as the best tested version and the basis for implementation.
Untested branches remain future acceptance obligations rather than being
reported as successful or silently removed.

## Comparison and stopping decision

| Concern | V1 result | V2 result |
| --- | --- | --- |
| Routine roles | Six mandatory roles; failed worker required an explicit fallback | Four routine roles; specialists activate for concrete gaps |
| Contract and dependency acceptance | Primarily manual, missing several identity dimensions | Executable assignment, source, contract and artifact-hash checks |
| Failure routing | Contradictory generic repair edge | First-stage routing; expected negatives recorded separately |
| Runtime ownership | Verifier/reviewer authority conflicted | Cleanup and release before a distinct reviewer episode |
| Re-attack lifetime | Separate node followed automatic teardown | Supported in-episode retests; persistent lifecycle explicitly future |
| Duplicate/interrupted work | Underspecified | Durable duplicate suppression; ambiguity preserved, recovery limits explicit |
| Physical response | Passed | Passed freshly and independently |
| Architecture disposition | REWORK | LOCAL_PILOT_ACCEPTED |

The optimization demonstrated here is better ownership and evidence correctness,
with fewer mandatory handoffs. It is not a measured speed or token-cost win.
Verifier command time was 31.451 seconds for V1 and 32.247 seconds for V2; V2
also measured 1.382 seconds of evidence gates. The trials reused compatible
analysis and warm tools, and V2 included protocol development. One timing set
per version cannot establish throughput superiority. Model-token cost is unknown.

We stop at V2 because the predefined local acceptance criteria passed, the
independent review found no remaining in-scope blocker, and inventing additional
roles would add untested complexity. A broader optimum requires more workload
archetypes and branches, with measured cost, lead time, error rate and rework.

## How the selected workflow runs

1. **Scope and case engineering.** The orchestrator assigns an owned workload,
   budget and source snapshot. The case engineer inventories only relevant
   components and proposes a realistic capability, successful baseline,
   legitimate probe, observation path and exact response-effect oracle.
2. **Review and freeze.** Independent review challenges the case and any new
   code. Deterministic validation checks adapter support and dependency hashes.
   The orchestrator freezes the accepted contract; agents cannot alter its
   criteria after observing results.
3. **Fresh execution.** The verifier checks tools, acquires the assigned
   private episode and establishes the baseline. The normal deterministic
   brain receives the declared observation, chooses naturally and dispatches
   its native response. Attacker and legitimate operations are measured.
4. **Classification and repair.** Machine gates bind artifacts and derive the
   threat outcome, brain attribution and task disposition separately. The first
   failed stage selects the repair owner. Missing observation, incorrect policy,
   response execution and reporting defects receive different tasks. A new
   actuator is engineered only when the capability lacks an adequate response.
   Changed code or contract requires review and a new pinned trial.
5. **Defended-state probes and cleanup.** The supported adapter runs the
   approved probes while the defended environment still exists. The verifier
   preserves evidence, confirms cleanup and releases ownership. Adaptive probes
   require a persistent-runtime adapter; this pilot used only bounded repeats.
6. **Independent acceptance and delivery.** The reviewer reproduces in a
   separate fresh episode and challenges the full evidence chain. The
   orchestrator joins required controls and reviews, then emits a scoped report,
   regression candidate and exact unresolved obligations.

This retains the original proposal's central rule: agent agreement is not
ground truth. Generators and reviewers propose and critique; deterministic
gates and measured effects decide admissibility. A valid decision or dispatch
receipt alone cannot establish defense. Learning records may retain reviewed
results, but neither the orchestrator nor a model silently tunes the live brain.

## What this experiment does and does not establish

The validated claim is a scoped local response to future credential reuse. It
does not undo earlier disclosure, prove autonomous detection, validate an entire
deployed console path, certify GPU serving or establish production availability.
The existing actuator was sufficient here; absence of a new actuator is a case
result, not proof that all stacks have adequate responses.

The retained workflow and prompts are designed for LangGraph transfer through
typed node outputs, deterministic routing, content-addressed artifacts, separate
case checkpoints and durable operation/lease adapters. The actual trial used
Codex agents and a small Python protocol module. A runnable LangGraph agent
service, persistent twin, customer-wide scan and automatic learning promotion
are not delivered or claimed.

Further validation must cover a real detector/controller/console path, another
workload archetype, a genuine new-actuator implementation, persistent pre-cleanup
adaptive re-attack, affected-workload availability and interrupted physical
mutation reconciliation. These are next evaluations, rather than reasons to
pretend this single local case found a universal optimum.
