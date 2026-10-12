# Security Gain validation: endpoint-lease and pod-rotation families (2026-10-12)

## Verdict

**Overall: NOT VALIDATED as a general proxy.** We measured three scenarios on one workload,
two action families, and two attacker capabilities that we actually stole and replayed:

- an inference lease credential;
- a Pod-bound API token.

That is not enough to validate Security Gain in general. Within the measured scenarios we found:

| Finding | Status | Evidence |
|---|---|---|
| Revoking the endpoint lease removes the lease capability and clears its fact | **Consistent** | 20/20 episodes |
| Rotating the Pod removes the stolen token and clears its fact | **Consistent, but delayed** | 20/20 episodes; the token kept working for a median of 10 s after the eviction |
| Rotating the Pod clears the lease fact while the lease still works | **False fact invalidation** | 20/20 episodes |
| Ranking among the actions the brain is allowed to select | **Consistent** | regret 0 in every scenario |
| Ranking between rotate and endpoint-lease-revoke on raw predicted gain | **Not supported** | rotate's predicted gain is 1.9× higher; measured effect is a tie (one capability each) |
| Response to the stolen token when it is the only stolen capability | **Brain does nothing** | rotate is blocked by the cost ceiling; gate regret 1.0 |
| Residual access after the selected action | **Not addressed** | the token stays usable 10/10; the brain still sees it and selects noop |

The formula, cover map, λ/β and gates were unchanged. No production actuation.

- Evidence: [2026-10-12/](2026-10-12/): [candidates.csv](2026-10-12/candidates.csv)
  (440 rows), [summary.md](2026-10-12/summary.md), [summary.json](2026-10-12/summary.json).
- Method: [README.md](README.md).

## What was tested

| | lease | token | combined |
|---|---|---|---|
| Stolen capability | Lease credential A | Target Pod's bound API token | Both |
| Replicas | 1 | 2 | 2 |
| Arms (10 episodes each, interleaved, seed 20261012) | intervention, baseline, cf-rotate, cf-endpoint-rotate | baseline, cf-rotate, cf-endpoint-rotate | baseline, selected, cf-rotate, cf-endpoint-rotate |
| Episodes / source commit | 40 / `2bbd8e91` | 30 / `2f7a14ec` | 40 / `2f7a14ec` |

**Environment.**
- Private envtest API server, with real API identities and real bound-token validation.
- The unchanged `ucw-recon` brain makes one shadow decision on a single tick.
- The native actuator dispatches the action.
- The shipped Python admission runtime runs once per replica, in front of a synthetic
  downstream with a call counter.
- No kubelet or containers. Hold window 20.0–20.6 s.
- The binaries and raw bundles are held outside the repository. Per-artifact hashes are in
  [episode-artifacts.sha256](2026-10-12/episode-artifacts.sha256).

**What counts as a capability being usable.**

| Capability | Usable | Denied |
|---|---|---|
| Lease | HTTP 200 and the downstream counter advanced | Exact 401 with no downstream call |
| Token | The API server authenticated the replayed bearer (201) | Its 401 |

- A capability is usable at the end if any probe in the last 3 s succeeded.
- 0 of 17,889 probes were indeterminate.
- Every episode's own pre-decision probe confirmed the stolen material worked (110/110).

**Economics and gates.**
- The fixture policy uses `legacy-runtime-lambda-v1` with λ = 0.6. That affects only the net
  gain, not the Security Gain under test.
- The cost ceiling (C_hi) is 1.2, the same as in all nine production policies.

## Decision states

Each scenario's state is identical across its episodes apart from clock jitter. Asset value
is 1.6, stage urgency 0.325 and dispersion 1 everywhere.

pHold:

| Scenario | pHold |
|---|---|
| lease | 0.334 |
| token | 0.500 |
| combined | 0.556 |

Fact weights. Attack-attributed facts carry the ×3 multiplier, marked †.

| Fact kind | Covered by | lease | token | combined |
|---|---|---|---|---|
| endpointLeaseReuse † | endpoint-lease-revoke | 1.061 | — | 1.768 |
| podBoundKubeAPIAuthPotential † | rotate | — | 1.591 | 1.768 |
| inMemory, podIdentity | rotate | 0.354 each | 0.530 each | 0.589 each |
| session | rotate, kv-reset* | 0.212 | 0.318 | 0.354 |
| inflightRequests / networkIdentity | request-drain* / quarantine* | 0.354 / 0.283 | 0.530 / 0.424 | 0.589 / 0.471 |

\* Not enabled in the fixture policy.

Candidates:

| Scenario | endpoint-lease-revoke | rotate | endpoint-rotate | Brain selected |
|---|---|---|---|---|
| lease | SG 1.06, net 0.98, selectable | SG 0.92, **blocked: availability** (1 replica) | SG 0, net −0.06 | endpoint-lease-revoke, 40/40 |
| token | blocked: no lease observation | SG 2.97, **blocked: C_hi** (1.60 > 1.20) | SG 0, net −0.06 | **noop**, 30/30 |
| combined | SG 1.77, net 1.69, selectable | SG 3.30, **blocked: C_hi** (1.60 > 1.20) | SG 0, net −0.06 | endpoint-lease-revoke, 40/40 |

Rotate's cost inputs are C_norm 1.0 and C_flow 0.7, so E[cost] is 0.82 and its worst-case
cost C_hi is 1.60. endpoint-lease-revoke costs 0.13.

## Results

Each cell gives the number of episodes in which the capability was still usable at the end of
the window, then the risk reduction against the scenario's baseline with a Newcombe 95% CI.
Removal time is measured from the end of dispatch.

| Scenario | Action | Lease capability | Token capability | Total risk reduction |
|---|---|---|---|---|
| lease | endpoint-lease-revoke | 0/10 → **1.000** [0.608, 1]; removed at 0.0 s | — | 1.0 |
| lease | rotate (cf) | 10/10 → 0.000 | — | 0.0 |
| lease | endpoint-rotate (cf, refused: no route-service) | 10/10 → 0.000 | — | 0.0 |
| token | rotate (cf) | — | 0/10 → **1.000** [0.608, 1]; removed at **9.9 / 10.1 / 10.2 s** (min / median / max) | 1.0 |
| token | endpoint-rotate (cf, refused) | — | 10/10 → 0.000 | 0.0 |
| token | noop (= brain's choice) | — | 10/10 → 0.000 | 0.0 |
| combined | **endpoint-lease-revoke (selected)** | 0/10 → **1.000**; removed at 0.0 s | **10/10 → 0.000** | 1.0 |
| combined | rotate (cf) | **10/10 → 0.000** | 0/10 → **1.000**; removed at 9.6 / 9.8 / 10.0 s | 1.0 |
| combined | endpoint-rotate (cf, refused) | 10/10 → 0.000 | 10/10 → 0.000 | 0.0 |

**The ~10 s token lag.** After rotate evicts the Pod, the API server keeps accepting the stolen
bearer until its authentication cache expires:
- token: 130/130 accepted in 0–5 s and 129/131 in 5–10 s, then 0/278 from 10 s on;
- combined: 131/131, then 119/129, then 0/276.

No removed capability came back within the window: reacquisition is censored at ≥ 19.9 s for the
lease and ≥ 10.1 s for the token.

**Legitimate traffic.** Credential B had 0 failures in every arm, on every serving replica.
- Under rotate, only the surviving replica was measured.
- The single-replica rotate outage is **UNAVAILABLE**, because there is no kubelet.

### Fact invalidation vs capability

This compares the brain's re-observation after the branch with the oracle. It is judged on
attack-attributed facts.

| Scenario / action | Lease | Token | Brain selects next |
|---|---|---|---|
| lease / endpoint-lease-revoke | true invalidation 10/10 | — | noop |
| lease / rotate | **false invalidation 10/10** | — | noop |
| token / rotate | — | true invalidation 10/10 (the capability lags the fact by ~10 s) | noop |
| combined / endpoint-lease-revoke | true 10/10 | **fact persists, capability usable, 10/10** | **noop** |
| combined / rotate | **false 10/10** | true 10/10 | noop |
| any / noop or endpoint-rotate | persists, consistent | persists, consistent | endpoint-lease-revoke if the lease fact is present, else noop |

There were no uncredited removals: no capability was removed while its fact persisted.

**Why the invalidations come out as they do:**

- **Lease, after endpoint-lease-revoke (true).** The lease fact binds only while both observed
  HMACs are in the live allowlist
  ([endpoint_lease.go:66-73](../../../phorvex/internal/ingest/endpoint_lease.go#L66-L73)). The
  revoke removes A from that same allowlist.
- **Token, after rotate (true).** The token fact needs a trusted event targeting the Pod's UID
  ([pod_bound_api_auth_event.go:13-27](../../../phorvex/internal/model/pod_bound_api_auth_event.go#L13-L27)).
  The bearer itself is bound to that UID.
- **Lease, after rotate (false).** The observation binds to the Pod's UID
  ([endpoint_lease.go:39-47](../../../phorvex/internal/ingest/endpoint_lease.go#L39-L47)),
  while the capability lives in the namespace-wide Secret and policy.
- **Structural facts after rotate.** The replacement Pod re-mints them at weight about
  0.0001. pHold restarts with Pod age
  ([hazard.go:523-525](../../../phorvex/internal/killchain/hazard.go#L523-L525)).

### Ranking and regret

These compare matched episodes from the same initial state per scenario, not a single
simultaneous decision.

| Scenario | Predicted SG order | Measured order | Selectable-only Kendall τ-b | Regret vs best selectable | Gate regret vs best tested |
|---|---|---|---|---|---|
| lease | ELR 1.06 > rotate 0.92 > ER = noop 0 | ELR 1 > rotate = ER = noop 0 | 1.0 | 0 | 0 |
| token | rotate 2.97 > ER = noop 0 | rotate 1 > ER = noop 0 | — (no variance) | 0 | **1.0** |
| combined | **rotate 3.30 > ELR 1.77** > ER = noop 0 | **rotate 1 = ELR 1** > ER = noop 0 | 1.0 | 0 | 0 |

ELR = endpoint-lease-revoke, ER = endpoint-rotate. There were no strict pairwise reversals.
The rotate > ELR pair in the combined scenario is a predicted strict order that measures as a
tie. All rank coefficients are descriptive (3–4 actions per scenario).

**If the C_hi gate were lifted (estimate, not measured).** In the combined state, rotate's net
under the fixture economics would be 3.30 − 0.6·0.82 = 2.81, against endpoint-lease-revoke's
1.69. The brain would then pick rotate. Rotate leaves the lease usable, and the brain's next
observation would no longer see it.

## Answers to the Math/OR questions

### 1. Does the current score accurately represent actual fact invalidation?

**For attack-attributed facts, mostly. With two exceptions it does not.**

- **True invalidations (40/40).** Whenever the action removed the capability, the brain
  stopped minting that fact:
  - endpoint-lease-revoke on the lease: 20/20;
  - rotate on the token: 20/20.
- **Exception 1: false invalidation.** Rotate changes the Pod's identity, and that alone clears
  the lease fact, while the lease works on every replica (20/20).
- **Exception 2: timing.** The score treats rotate's effect on the token as immediate, but the
  capability survives about 10 s.
- **Structural facts.** inMemory, podIdentity, session and the others remain unmeasured. The
  fixture has no implant or session to remove. They are re-minted on the replacement Pod at
  near-zero weight.

### 2. Does invalidating more weighted facts lead to greater attack disruption?

**No, not in these scenarios. Not validated in general.**

| Scenario | rotate | endpoint-lease-revoke | Measured |
|---|---|---|---|
| combined | covers 4 facts, SG 3.30 | covers 1 fact, SG 1.77 | each removes exactly one capability |
| lease | covers 3 facts, SG 0.92 | — | rotate removes nothing |

- Rotate's extra predicted value (1.53 of its 3.30) comes from structural facts that carry no
  measured attacker capability.
- Disruption follows whether the covered fact is a capability the attacker actually holds, not
  how much summed weight is covered.
- The ×3 attribution multiplier is what keeps the lease-scenario ranking right. Its margin
  there is 0.4·w₀ ≈ 0.14.

### 3. Which action families show the largest mismatch?

**Pod rotation (`rotate`).**
- In the lease scenario it is predicted at 87% of endpoint-lease-revoke's gain but measured at
  0, and it falsely clears the lease fact.
- In the combined scenario it is predicted at 1.87× endpoint-lease-revoke but measured equal,
  with a ~10 s effect lag that is not modelled.

**Consistent families.** Endpoint lease (endpoint-lease-revoke): predicted and measured agree
in both scenarios. Endpoint route (endpoint-rotate): predicted 0, measured 0; the actuator
refused it for lack of a route Service.

**Not tested:** kv-reset, request-drain, quarantine, guardrail-rotate, crm-refund-revoke, the
GPU and model families. These are **NOT VALIDATED**.

### 4. Does the score account for residual attacker access and reacquisition?

**No.**

- **Residual access is not acted on.** In the combined scenario the selected
  endpoint-lease-revoke leaves the stolen token usable (10/10, for the whole window).
  - The brain's next observation still mints the attributed token fact (1.77), but it selects
    noop: the only covering action, rotate, fails C_hi.
  - With `MaxMovesPerTick = 1` and no residual term, one tick handles one capability, and the
    gate stops the rest.
- **Residual access becomes invisible.** After a rotate, the lease fact disappears (false
  invalidation) and pHold resets. The brain believes the attacker holds nothing while the lease
  still works.
- **Reacquisition.**
  - None was observed.
  - Lease revocation is permanent by design (no re-issue path).
  - The token is bound to the retired UID; a new token would need access to the new Pod, which
    was NOT TESTED. Nor was theft of credential B from the Pod's mounted Secret.
  - The score's only time dimension is pHold recovering with Pod age. That models in-Pod
    footholds, not credentials.

### 5. Does the current formula select the most effective safe action?

**Among selectable actions, yes: regret 0 in all three scenarios.** But the gates decide more
than the score does.

- **Token.** The only effective action, rotate (risk reduction 1.0), is excluded by C_hi, so
  the brain does nothing against a working stolen API credential. Gate regret is 1.0.
- **Combined.** The brain picks endpoint-lease-revoke, which ties the gated rotate on measured
  effect. If the gate were lifted, the score would prefer rotate (estimated net 2.81 vs 1.69):
  equal measured effect, plus a false invalidation and a 10 s lag.

So the correct selections here come from the gates masking a score that over-credits rotate,
not from the score alone.

The tests discriminate weakly. Alternatives were often predicted at exactly 0, and there are
3–4 actions per scenario.

### 6. Which missing measurements prevent validation?

1. **Instantiated capabilities for structural facts.** In-memory implant, session hijack,
   in-flight abuse and network identity. These are needed to test rotate's 0.9–1.5 of
   structural credit, and kv-reset, request-drain and quarantine at all.
2. **Real kubelet and containers.** Needed for rotate's outage and capacity loss, its
   replacement time, and the attacker's loss of access during that outage.
3. **Detector behaviour after an identity change.** Whether and when the lease or token
   observation is re-raised against the replacement Pod. That decides how long a false
   invalidation lasts.
4. **Multi-tick episodes.** Does a later tick address the residual token? With the gate as
   configured, the next observation says no; this was not run across ticks. Also production's
   5-minute anti-over-rotation window, against 1 s here.
5. **Residual-path emulation.** Credential B theft from the Secret mount, and token theft from
   the replacement Pod.
6. **Other families, workloads and stacks.** Voice, LiteLLM, MCP, CRM and NATS. These are
   needed for any statistical rank agreement.
7. **C_hi provenance.** Whether rotate's 1.60 is representative of production workloads, and
   defensible consequence values for expected avoided loss (**UNAVAILABLE**).

## Limitations

- **Narrow scope.** Three scenarios, one workload, one tick. The system is deterministic, so
  the Wilson and Newcombe intervals reflect repeat counts from a fixed state, not uncertainty
  across scenarios.
- **Synthetic components.** The downstream, the `TEST_INJECTED` lease observation and the
  trusted token event are synthetic, as are the fixture-declared creators, Pod readiness,
  image IDs and the harness-simulated replacement Pod. No kubelet.
- **What is real.** The admission runtime, the bound-token validation and the API server's
  authentication cache, which uses its production default.
- **Counterfactuals bypass decision-layer gates.** The counterfactual rotate ran despite the
  decision layer's availability (lease) or C_hi (token, combined) gate, only on the private API
  server, to measure what the score credits. The native actuator's own gates still applied. No
  production gate was relaxed.
- **Separate episodes per arm.** "With" and "without" outcomes come from separate episodes
  with the same initial state and fresh credentials, not from forking one process.
- **Local legitimate latency.** It is measured locally on one worker, not as a production SLO.
- **Fixture economics.** Legacy λ (0.6). Production runs independent β, which changes net
  gains but not Security Gain.

## Constraint compliance

- **Unchanged:** the objective function, the Security Gain formula and the action-to-fact map;
  existential and SLO priorities.
- **Not tuned:** λ/β.
- **Gates:** no production gate relaxed, and the C_hi ceiling is the production value.
- **No production actuation.** Counterfactual actions ran only on the private API server.
- **Matched starts:** the same declared initial state per scenario.
- **Status columns, never zero:** measured values, estimates (including the "gate lifted"
  computation above), censored, partial and unavailable values are separated. Nothing
  unavailable is reported as zero.
- **One decision state per row:** each CSV row belongs to exactly one episode's single-tick
  decision state.
