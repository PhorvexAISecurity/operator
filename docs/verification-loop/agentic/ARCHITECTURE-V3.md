# Agentic verification workflow — V3 live candidate

Status: **one complete deployed episode; full acceptance pending**. This version records corrections exposed
while moving V2's isolated credential pilot onto an actual deployed application.
No LangGraph implementation is started. The live trial must finish before this
candidate can replace V2 as the selected architecture.

Five deployed episodes produced four retained incomplete results and
one independently sealed `LIVE_CASE_PASS`. The installed brain chose the real
response in the passing episode; exact route denial, ordinary traffic, hold and
cleanup were observed. A later clean-control component passed, but its positive
measurement failed at legitimate-service availability. A successful independent
pair and full architecture acceptance remain unmet. The sixth planned episode
was not executed: no lease was granted, a successful fifth/sixth pair was already
impossible, and the full execution/cleanup reservation could not fit the final
time window. Five physical episodes were consumed; one ceiling slot was unused.

The original verification-loop design uses a read-only production scan and
isolated counterfactual twins. That boundary remains the intended reusable
workflow. This owner-authorized dev experiment is an additional deployed
reference check, not permission to attack customer production or a claim that
the installed manager's learned state stays read-only while it performs real
actions. V1/V2 retain their measured shadow/replay guarantees; this trial adds
actual application, observation and native-effect evidence. Full twin fidelity
for this real GPU application is still a separate requirement.

## Aim and roles

The aim is a reproducible, attributable attack-to-response experiment, with
honest failure localization. An agent consensus is not a defense oracle.
Four routine participants remain: orchestrator, case engineer, independent
verifier/executor and independent reviewer. A defense/integration engineer is
activated only when the case exposes a concrete observation, decision, response or tool
gap. Runtime/domain specialists are conditional. More agents do not create
more permission to mutate a shared workload.

Serial leases cover assigned workers, not every installed manager or external
actor. Capture concurrent operations on the target and shared service. In one
failed measurement a native request drain coincided with a transport failure
roughly twenty seconds after successful adapter removal; exact request-level
causality remained unknown. A subsequent episode passed despite a separately
recorded KV action. In the fifth episode, original serving logs tie the exact
failed legitimate request to an abort during native drain and a guardrail
cancellation. Caller attribution and cross-log clock calibration remain unknown.
Worker exclusivity alone cannot reserve an application against its installed
manager. Coordinate every mutating actor or use an independently owned twin;
do not disable protection to obtain a preferred result. Preserve these
observations rather than assume a quiet stack.

The six functional roles support multiple workers per role. Parallel pools can
cover applications, attack stages and response validators, while the scheduler
serializes conflicting live dependencies. The portable runbook's fleet section
separates logical assignments, queued jobs and active concurrency. The original
design's hundreds-of-assignment examples remain proposed sizing, not measured
throughput or proof that hundreds of simultaneous workers are optimal.

The case engineer proposes a realistic capability, a successful baseline, an
observation path, response interfaces, legitimate traffic and precleanup retests.
The integration engineer authors a missing detector or response tool. An author
cannot execute or independently certify that tool. The verifier plans and runs
measurement. The reviewer checks contracts/code/oracles and executes a later
fresh reproduction. The orchestrator supplies authority, current expected pins,
budgets, actor assignments and a single exclusive mutation lease.

Brain/decision engineering is a specialization of the conditional
defense/integration role, preserving six functional roles. The explicit branch
is specified but has not yet been exercised end-to-end by this trial.

## Two freezes instead of a circular evidence contract

V2's strict handoff schema requires a case hash. Early discovery has no frozen
case, and future physical evidence cannot have hashes before it exists. V3 makes
these phases explicit:

1. **Design proposal.** Bound to owner scope, source, task and actor. May say
   `PROPOSED`, with no case hash. It cannot authorize execution or pass an
   execution handoff gate. Null hashes never mean accepted dependencies.
2. **Execution freeze.** Independent preflight/code acceptance precedes the
   immutable case, reviewed tool hashes, observed runtime/configuration pins,
   actor assignment, deadline and exclusive lease. Changed dependencies
   invalidate affected review. No future evidence hashes are required here.
3. **Capture seal.** After execution, the independent executor records immutable
   original capture refs, field bindings and report hashes. It retains the same
   case/tool identity. The runner cannot make its own output a trusted expected
   value. The deterministic gate consumes both the execution freeze and this
   separate capture seal.
4. **Cleanup seal.** Precleanup evidence is durable before any cleanup effect.
   Exact owned UID/digest removal and actual absence/readback are separately
   checked. Only confirmed cleanup releases the lease.

This is a state transition and trust boundary, not a new model persona. A later
service implementation must authenticate actor/lease identity; local Codex task
assignments and file permissions are not cross-host capability isolation.

## Real observation and response

Every case freezes one observation mode. `TEST_INJECTED` proves only a response
path. `OBSERVATIONAL_TEST_DETECTOR` uses a separately authenticated test producer
reading actual workload state; it does not certify the installed production
sensor. A full installed-producer claim additionally requires that producer's
source/runtime identity and a fresh autonomous observation.

Do not silently switch modes because an installed detector is broken. Retain
that failure, assign the integration repair, review the replacement and freeze
the narrower claim before running. The test driver must not create the event
or call the native actuator to obtain the desired result. The installed brain
chooses under its actual unchanged policy, scoring and safety constraints.

Each supported action has its own effect oracle. An unexpected action is
unsupported verification until its real effect and legitimate control are
defined. An epoch, selected action or completed journal alone is insufficient.
If an existing action does not remove the demonstrated capability, activate
the defense engineer for a scoped repair or new actuator, review the full
registration/coverage/authority/effect path and freeze a new attempt.

## Decision failure and brain repair

A wrong or insufficient choice triggers diagnosis before implementation. The
verifier records the actual observation, context and relevant state, policy and
objective, available candidates, capability/coverage/feasibility, exclusions,
score terms, selected action and measured consequence. Missing trace fields
remain unknown. This diagnosis separates input/context defects, legitimate
policy constraints, absent sufficient responses, actual decision-logic errors
and actuator execution failures.

The lead assigns the responsible owner. A violated documented decision
requirement or reproducible selection/scoring implementation error goes to the
brain/decision specialization. Its bounded output is a general code correction,
a regression exposing the original defect, recorded-input/state replay against
before/after source and representative safety/availability checks. An analyst's
preferred action does not by itself establish a defect. Requirements and policy
changes have separate recorded scope and review; they are not silently retuned
to make a frozen case pass.

The independent reviewer checks diagnosis, replay fidelity, generality and
regressions. The engineer supplies replay checks and the independent verifier
executes the replay used for acceptance. Changed dependencies invalidate affected acceptance. The lead
freezes a reviewed new profile under a valid budget and lease; the verifier
reruns the same threat and ordinary-service criteria, with the new brain making
its normal choice. Actual native effect, threat denial, persistent retests,
independent fresh reproduction and safe cleanup are still required. The brain
is unchanged within each episode, with repairs between reviewed revisions.
The original failure is retained. A new action choice, replay or PR is not
end-to-end acceptance, and this specification grants no fresh physical authority.

The portable runbook defines DECISION-DIAGNOSIS.json and DECISION-REPAIR.json
contracts and the complete specialization prompt. They make the repair branch
explicit for another harness without claiming that a general brain-repair
service or this untested branch already works.

## Measurement rules exposed by live preflight

- Validate **every** recorded legitimate request; filtering to successful named
  samples is forbidden. Enforce request counts, requested/generated tokens,
  deadlines, exact target and the independent effect oracle.
- Keep source attestation separate from image identity, mounted-file identity
  and declared configuration. An authenticated audit Git revision is useful
  evidence; a deployment annotation is not binary attestation. If effective
  process configuration is unavailable, record declared Pod arguments/reference
  hashes accurately and leave effective configuration unknown.
- Timing claims require clock/precision handling and original capture bounds.
  If exact native timestamps are unavailable, a conservative outer bracket can
  prove legitimate-request overlap only when that request contains the **entire**
  widened bracket. Simple intersection cannot prove actual execution overlap.
- Measure a specific denial rather than an outage. The original capability must
  work before observation, fail after the native effect, and remain denied while
  ordinary requests still work. Missing baseline is `NOT_ESTABLISHED`.
- Keep the runtime and owned attack material alive through the declared retest
  window. Record exact retest count, cadence, request variation and response.
  Removing the fixture first cannot prove durable defense.
- Setup authority and attacker authority are different. A benign operator-loaded
  fixture cannot demonstrate attacker enrollment or malicious model answers.
  Same-principal requests playing different model roles must be disclosed.
- Preserve native journals. Fresh reproduction means new physical requests and
  an independently owned episode, not relabelled previous evidence. If native
  operation identity requires a reused owned model name, retain that constraint
  and use fresh episode/event/nonces and actual cleanup/restaging.

## Actual interface fidelity is an admission requirement

Independent review found the observer and runtime driver disagreed about the
SecurityEvent API group. Policy and event types can use different groups; a
policy's GroupVersion is not evidence of the event schema. The permissive fake
client accepted arbitrary API paths and missed the mismatch. Independent installed CRD and canonical list captures confirmed SecurityEvent
is cluster-scoped `amtd.r6security.com/v1beta1`; policy uses
`phorvex.ai/v1alpha1`. The observer was correct and the driver was corrected.
Original installed schema discovery must confirm groups, versions, fields and
authentication before correcting a demonstrated wrong side.
Do not infer integration correctness from permissive fake-client tests. This
finding occurred before any stimulus or physical defense claim.

## Physical tool feasibility is an admission requirement

A syntactically correct plan can still be physically impossible. The initial
live candidate made five sequential cold remote calls inside a five-second
baseline window; independently captured calls took about 1.9 seconds each.
Likewise, a cold target read plus two cold request calls could not satisfy the
2.5-second retest-pair cadence. Local adverse tests did not expose this mismatch.
The earlier code acceptance is preserved but explicitly superseded for live
readiness; no stimulus was run under that plan.

S2 and S5 must therefore measure actual startup, resident RPC, API/readback and
clock envelopes and check a schedule lower bound before granting a mutation
lease. A read-only resident clock channel measured about 1.83 seconds startup
and then at most 113 milliseconds round trip, with approximately 56 milliseconds
uncertainty. These measurements support a narrow batching/resident-transport
repair; they do not establish model latency or a successful physical result.

The repair retains each original per-request response and UTC/monotonic time,
uses independently measured uncertainty and closes owned channels. It does not
relax baseline, ordinary-service or retest criteria. Changes are reviewed and
receive new frozen tool hashes before any physical attempt.

## Lessons from the first deployed episode

The first physical episode reached the unchanged brain, which selected and
completed native adapter-rotate. The owned model then returned a specific404.
The whole case remained incomplete: the oracle rejected real param:null metadata,
no ordinary request contained the entire widened dispatch bracket, and post-effect
hold/retests were not captured after the first failure. Cleanup stopped because
the driver stored requested labels instead of the topology labels already
returned by CREATE. Separate guarded reconciliation confirmed safe state.

The architecture therefore requires original deployed error envelopes and
admission-returned ownership in preflight, plus measured ordinary response
durations for an entire-bracket control. Prospective revision2 narrows404 parsing
to the same exact model/status/type/message with only optional null metadata,
records full actual CREATE labels, and uses longer ordinary requests under a
lower request cap and unchanged token/latency/overlap bounds. First failed
captures remain failed. Fresh execution and independent reproduction are
required before accepting the revised case.

## Execution and bounded repair

The graph remains discovery → proposal → independent preflight → execution
freeze/lease → live episode → capture gate → cleanup gate → fresh independent
reproduction → reviewed report. A failed stage returns to its precise owner:
case relevance/oracle to case engineering; capture and controls to verification;
observation/dispatch/effect to integration or defense; resource/runtime gaps to
the runtime specialist; stale authority/duplicate operations to the supervisor.

Task delivery must also trigger execution. Sending a message to a completed
worker is not the same as starting its next task. The scheduler records whether
an assignment was acknowledged/running and explicitly resumes an idle worker;
it must not wait indefinitely for a queued message. This is independent of the
physical mutation lease: waking a worker grants only its already assigned scope.

The first failing attempt is immutable. Prospective oracle repair is allowed
under a newly reviewed contract; reclassifying old evidence to invent missing
measurements is not. Every changed tool or case gets a new reviewed freeze. An interrupted mutation records ambiguous acknowledgement and requires
readback before retry. One event/load operation has one durable intent. Terminal
cached evidence is not a fresh episode. Unresolved native operations or cleanup
retain the lease and a concrete reconciliation owner.

Formal availability/SLO acceptance, observation provenance, threat outcome,
native attribution, workflow completion and production readiness remain
separate result fields. The live trial may support a narrow architecture claim
while leaving formal SLO, production detection or broader workload coverage
unverified. It cannot establish a universal optimum from one application.

## Second deployed episode and prospective sampling revision

The second episode captured the genuine native response, exact route removal,
six varied route-denial retests and paired successful base-model requests over
the required hold. Its strict overall verdict remains INCOMPLETE at availability:
the widened effect bracket straddled a boundary between two successful ordinary
requests. Safe cleanup was independently confirmed and the lease released.

Revision3 therefore freezes two staggered ordinary streams, eleven128-token
plans per stream,22requests combined and at most two requests in flight. Stream2
uses stream1's actual remote HTTP monotonic start plus2000ms on the same node
clock, never early and at most100ms late. Every started request, response,
identity, clock and terminal state must be retained; both streams stop/drain.
Token, latency, full single-flight bracket containment, baseline, hold/retest,
cleanup and the original four-total-episode bounds remained unchanged. That
preregistration required episodes3 and4 to use the same reviewed final profile.
Those episodes have now completed: episode3 was incomplete and episode4 passed
the bounded deployed case. The separately reviewed follow-on budget permitted
episodes5 and6, subject to repaired source acceptance, fresh runtime checks and
new serial leases. Repaired source and public tests were accepted; episode5 ran
and failed at availability after a passing clean component. Episode6 received
read-only admission checks but no physical authority or effects. The final
17:30 UTC window expired with all five actual episodes safely released; the
first four outcomes and original expired time budgets remain preserved.

This is measurement engineering and prospective admission, not a product
defense repair or a relaxation of the old result. The architecture must support
retained failed outcomes, separately accepted safe cleanup and fresh reviewed
attempts without losing the distinction between those three facts.

Review also requires timestamp capture at the real HTTP call boundary, without
synchronous evidence output delaying dispatch. The final helper prepares the
HTTP opener first and sends records through a bounded FIFO writer. Writer
failure, incomplete response or missing terminal drain remains an explicit
failure. A synthetic sensitivity check with an arbitrary delayed callback is
not proof that the final helper blocks; acceptance must exercise the exact
stationary production callback/source and retain that provenance distinction.

## Transfer boundary

Only after legitimate execution and independent reproduction should these state
transitions, typed proposals, fixed tool interfaces, actor identities, admission
and capture/cleanup gates be implemented as a service graph. Prompts propose
artifacts; authenticated tools and deterministic gates decide authority and
acceptance. Service engineering is deliberately deferred until the architecture
trial produces its actual result.
