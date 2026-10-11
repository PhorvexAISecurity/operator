# V1 independent review and fresh reproduction

The fixed local response case is accepted: threat `BLOCKED`, brain attribution
`PROVEN`, case acceptance `LOCAL_ACCEPTED`. V1 workflow acceptance is `REWORK`.
The response worked in a fresh reviewer-owned environment, but the frozen graph
and prompts required undocumented routing/ownership decisions and could not
execute their separate post-completion re-attack stage. These are different
conclusions; local response success does not accept the architecture.

Run `v1-pilot`, case `credential-reuse-local`, contract revision 1, source
`f73d04cd6aac9f5945da1515e2dac76554869920`. Reviewer authored neither the V1
architecture/prompts nor the existing driver/runtime or verifier validator.
All frozen V1 hashes still match. Actual executing binary SHA-256:
`17f86a5307ef5c7395085af1b03e58c2bd39e596330bc68c93e4da3fa3cee0a6`.
Before reproduction the reviewer checked HEAD, scoped tracked changes, the
binary digest and all 1551 preparation source pins; after it there was no source
drift. The five-file shipped runtime closure independently recomputed to
`870c8709a5da026d01449be737939fa35420ebd1bda341ea2371c6081926fda4`.

The orchestrator transferred the lease after verifier cleanup at
2026-10-10T10:57:32.316127Z. Reviewer command ran from
10:58:35.730551Z to 10:58:47.967474Z on 10 October 2026, exit 0. Its report
interval is 10:58:35.841916624Z to 10:58:47.870768636Z. Command argv, timestamps,
stdout/stderr, before/after process and temporary-directory snapshots are in
`.git/phorvex-workflow/agentic-loop-20261010/v1/reviewer-positive-command.json`.
The command used the pinned V1 binary with explicit private Python/envtest paths,
source revision, timeout 3m, hold 2s, interval 250ms, B latency ceiling 2s and a
new `reviewer-positive` output directory. The outer limit was 240 seconds with
15-second termination grace. No shared cluster or user kubeconfig was used.

| Measurement or control | Independent result |
| --- | --- |
| A/B initial and clean baselines | Each 200, exact synthetic marker and unique nonce, counter increments once |
| Normal brain selection | Naturally selected feasible active revoke; strict positive gain; no forced decision |
| Candidate explanation | Revoke net gain about 0.98333 at modeled cost 0.13; endpoint-rotate net −0.06; Pod rotation excluded by one-replica floor |
| Observation | TEST_INJECTED; exact baseline response hashes and current source, policy, Pod and credential-authority bindings |
| Dispatch and durable readback | Native emission, exact policy revision 0→1 and terminal-full journal bound to decision/tick/event/policy/Pod; state hashes match |
| A-after and seven A hold probes | Exact 401 unauthorized with zero downstream increment, all retained raw bodies and digests checked |
| Legitimate B | All 12 sampled operations pass; two actual intervals overlap dispatch; maximum 18.956368 ms |
| Actual hold | 2280.971468 ms; seven distinct A request nonces; last-to-first measured A hold span at least two seconds |
| Baseline-to-confirmed-denial interval | 559.745631 ms; local measured interval, not real attacker dwell |
| Clean/stale and exact replay | No clean/stale selection, unchanged control state checked by source; embedded fresh-engine exact canonical replay passes and shadow owner remains unchanged |
| Fresh physical identity | Reviewer Pod UID differs from verifier Pod UID; no normalization or byte-identical physical replay claim |
| Cleanup | No remaining API-server, etcd or fixture process; temporary-directory set equals initial snapshot; no report cleanup errors |
| Formal SLO | unknown, with missing safe-return bound retained |

The reviewer independently inspected and validated four raw reports: verifier
positive, reviewer positive, withheld dispatch and authority outage. A separate
read-only assertion pass checked 152, 152, 82 and 89 conditions respectively;
all 475 passed. This count records work performed, not a confidence score.
`reviewer-validation.json` preserves every check and the report hashes. Checks
included actual binary/tool/source/artifact digests, required retained artifact
sets, response raw/parsed/hash agreement, nonce/counter chains, request chronology,
baseline-to-observation binding, source and API identity bindings, selected
decision/journal/state hashes, successful B overlap and measured hold span.
The physical reproduction re-executed the driver, including its exact replay;
the reviewer did not additionally reload its persisted gob via a second replay
command. Source review of `replay`, `canonicalTraces` and `ReplayFile` confirms
the reported embedded replay uses a fresh unchanged engine and original clock,
owner state, identities and recorded capabilities. Recorded capabilities are
not a new physical authority check.

Withheld dispatch retained selection while A still completed the downstream
operation and policy/journal data stayed unchanged: `LANDED / NOT_PROVEN /
INCOMPLETE`, exit 1. The authority control deleted policy after native dispatch:
A returned exact 503 lease_unavailable with no downstream operation; `UNKNOWN /
NOT_PROVEN / INCOMPLETE`, exit 1. Both are successful configured control tasks;
neither is a defended incident or a reason to repair a working actuator. Outage
B samples precede deletion and establish no B availability after authority loss.
Those negatives were independently checked from their raw retained evidence;
the reviewer did not physically rerun them.

The verifier-authored `validate-v1-report.py` was independently source-reviewed.
Its current checks support these three known cases: it separates denial/outage,
checks raw probes, hashes, selection, journal/state and actual B overlap. It is a
supplemental evidence reader, not a generic acceptance adapter. It accepts only
hardcoded episode names, trusts embedded replay flags, iterates supplied hash
maps without enforcing a required artifact/source set, and omits the full
operation/event/Pod/state-digest bindings and current shipped closure digest
that the reviewer's separate checks covered. No implementation self-validation
was used as independent acceptance. V2 should make required evidence and task
identity explicit, preserve embedded versus persisted replay provenance and
review the adapter independently before using it for broader cases.

The orchestrator-authored existing-case fallback is accepted within this fixed
scope. It preserves A-only public credential reuse and B control; repeated new
nonces test continued denial, not adaptive bypass coverage. Its lost red-team
worker remains a provider failure with no artifact, not a successful worker or
failed attack. The role label does not override the explicit fallback author.
Probe-name shorthand in attack.md is a minor precision defect; actual names are
clean-A-no-actuation and A-after-native. No separate agent attacked a destroyed
fixture, and no two adaptive variations were executed.

Preflight PF-002, PF-003, PF-005 and PF-009 now have concrete trial evidence:
manual lease transfer, inaccessible post-return state, supplemental control
classification, and an independently reviewed fallback after worker loss.
PF-001 remains a graph-routing defect; configured negatives were manually routed
without product repair, but unexpected setup/integration failure routes were
not fault-injected. PF-004, PF-006 and PF-007 remain schema/retry/contract debt;
wrong-contract handoff, lost-side-effect resume, and alternative action trials
were not run. PF-008's measurement review and fresh repetition passed for this
bounded case; oracle diversity beyond the reviewed existing implementation was
not established. No global optimum, generic six-role roster, complete failure
routing, durable workflow resume or enforced narrow-tool isolation is proven.

The V1 runtime count is four episodes: three verifier episodes and one reviewer
positive. No adaptive re-attack, targeted product rework, source repair or
unchanged failing retry occurred. Model-token cost and exact early worker-start
times remain unknown. Private evidence is local `.git` material and must be
preserved separately if the docs are shared. The review handoff pins all inputs
and reviewer artifacts; the live ledger is copied to a timestamped review
snapshot so subsequent appends do not invalidate this review.

Next owner: orchestrator. Retain V1 as a rejected architecture trial with an
accepted local response case. Use the measured interventions and unavailable
re-attack to freeze an evidence-driven V2, defining explicit provider/error
routes, control task status, contract/attempt/episode bindings, runtime lease
transfer, same-state retry rules and supported probe lifetime. Keep claims local:
synthetic downstream, injected identities/observation, fixture serving metadata,
explicit policy and unknown formal SLO; no autonomous detector, deployed console,
full manager, GPU or production availability approval.
