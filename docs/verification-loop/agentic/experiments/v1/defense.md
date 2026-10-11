# V1 defense fit — credential-reuse-local

Existing `endpoint-lease-revoke` is suitable for the frozen local capability. No new actuator or repair is indicated by source inspection. Runtime success remains for the verifier and independent reviewer to establish. Source pin: `f73d04cd6aac9f5945da1515e2dac76554869920`. Inventory and attack handoffs are hashed in defense.json; the attack is the disclosed orchestrator fallback after a provider failure.

## Candidate coverage and normal selection

| Action | Fit for reuse of A |
| --- | --- |
| endpoint-lease-revoke | UCW assigns the typed `endpointLeaseReuse` fact to this action. It removes A from allowed HMACs, adds A to revoked HMACs, increments the durable revision, and retains B. |
| endpoint-rotate | Enabled for comparison, but receives no cover for the lease fact. Changing endpoint identity does not revoke the stable caller credential. |
| rotate | Enabled for comparison, but receives no cover for the lease fact. Replacing a Pod does not invalidate the durable caller roster. |
| Other roster actions | Outside the fixed enabled set and typed fact coverage; no evidence supports substituting them for lease revocation. |

Source: `recon/ucw.go:254`, `endpointlease/contract.go:146`, `actionset/generator.go:398`, `decision/endpoint_lease_test.go`. Expected coverage is source-backed; actual exclusions, feasibility and selection require fresh traces.

The frozen runner uses an unchanged CoverageEngine with UCW recon and `DecideShadowChecked`, then dispatches the selected decision. It supplies an explicit active, non-dry-run `model.Policy`: event-driven/reactive-only, policy UID/generation, three enabled actions, lambda seed, norm 0.4, flow 0.6, secrets 0.8, one move per tick, one-hour proactive floor, one-second retention window and minimum available replicas 1. The real API policy selects `app=vllm`; the runner waits actual wall-clock maturation. Candidate assembly still applies policy binding, native capability, feasibility and modeled cost gates. Revoke's modeled normalized configuration cost is 0.25; its serving-flow estimate is not measured disruption. Formal SLO remains unknown. No selection, policy or scoring is changed for this analysis (`verificationloop/run.go:344,718`; `cost/p1cost.go:157`; `slo/bound.go:139`).

## Observation, authority and effect contract

The only observation mode is TEST_INJECTED. Binding requires one trusted suitable SecurityEvent, asserted console creator, correct rule/source/target, age below 60 seconds, canonical observation, current policy UID/generation/selector, approved source, Service/ConfigMap/Secret/seed/revision agreement and both A/B HMACs currently allowed. Real ingest checks this; creator authentication is an explicit fixture assertion, not production identity proof. Authenticated TLS proxy A/B status and protected journal consistency are separate native feasibility prerequisites (`ingest/endpoint_lease.go`; `actuator/endpoint_lease_revoke.go:94`).

At dispatch the handler rechecks exact event and policy epoch, active authorization, selector/Pod identity, current route/source/Secret and prior revision. It writes prepared intent before one resourceVersion CAS of the named lease-policy ConfigMap, then verifies the exact new state, all original/current proxy incarnations, A denied, B allowed and old-revision in-flight drain before terminal-full. Required authority includes named policy and operator journal get/update, workload/Service/owner/EndpointSlice reads, exact policy/event reads, and secure status credentials. The local envtest admin client does not certify deployed service-account RBAC (`actuator/verbs.go:64`, `endpoint_lease_revoke.go:130,206,290`).

The shipped boundary reads current API authority on requests and compares immutable Secret and projection bytes. A valid revoked A gets 401; missing authority gets 503. Caller bearer is replaced with the upstream bearer before downstream access. Recovery reads existing prepared intent and effective state without repeating the CAS; unresolved old-state or drift remains incomplete. Revocation is forward-only; there is no tested automatic restoration contract in this case (`endpoint_lease.py:285`; `dual_server.py:210`; `endpoint_lease_recovery.go`).

Independent acceptance requires A/B successful baseline, A exact 401 with no downstream increment after dispatch and throughout nonce-varied hold probes, B successful downstream calls during actual timestamp-confirmed dispatch overlap and afterward within 2000 ms, terminal evidence, clean/stale refusal and exact frozen replay. Receipt/emission alone is insufficient. Multi-backend coverage, restart, crash recovery and alternate protocols are implemented assumptions or untested scope, not measured claims here.

## V1 routing and ambiguities

- `required_action=null` conflicts with the runner's post-selection requirement that the chosen action be endpoint-lease-revoke (`run.go:460`). This does not force the brain, but fixes candidate-specific acceptance. Orchestrator/reviewer must disclose the mismatch and route an unexpected selection through policy/oracle analysis without tuning or relabeling it as a missing actuator.
- Shadow selection preserves owner state and records capabilities; it does not exercise the full manager policy-resolution/controller path. Claims must stay at ordinary unchanged engine selection under explicit local inputs.
- The runner destroys its runtime before returning. Separate graph re-attack cannot target that state. Existing in-episode nonce-varied hold probes supply bounded persistence coverage only; a later distinct variation needs a reviewed verifier-owned adapter or a revised contract/tool lifecycle. This is integration debt.
- Runner verdicts require explicit evidence-based mapping to separate threat, attribution and acceptance dimensions. Withheld dispatch intentionally leaves A successful; authority deletion intentionally yields 503/incomplete. Neither requests actuator repair. A B failure is legitimate-service failure, not threat blocking credit.
- Verifier-exclusive runtime ownership conflicts with required independent reviewer reproduction. Inventory records the orchestrator's planned serialized explicit reviewer delegation. The frozen prompt/tool ownership still needs clarification in the next architecture version.

Next owner: orchestrator, to validate this handoff and route plan/oracle review before verifier execution. No runtime episode, product/harness edit, commit, push, merge or cluster operation was performed by this role.
