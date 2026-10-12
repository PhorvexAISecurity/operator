# Security Gain validation: endpoint-lease credential reuse (2026-10-12)

## Verdict

**Overall: NOT VALIDATED.** Only one scenario and one workload were measured, with one
instantiated attacker capability. This is not enough evidence to validate Security Gain
as a general proxy for defensive effect.

Within the scenario that was measured:

- **Credential reuse: consistent.** The score credits endpoint-lease-revoke for the
  stolen-credential fact. Revoking removed that capability in 10 of 10 episodes. The brain
  selected the only tested feasible action that reduced risk, so regret was 0.
- **Measured defect: false fact invalidation.** After a pod `rotate`, the brain stops
  minting the credential-reuse fact in 10 of 10 episodes. The stolen credential still
  works in every probe. On the replacement pod, the attacker-hold estimate also resets to
  about 0.
- **Rotate's credit: unvalidated.** Rotate's predicted gain of 0.92 comes entirely from
  facts that this fixture does not instantiate as attacker capabilities. It is neither
  confirmed nor refuted.

Formula, cover map, λ/β and gates were unchanged. No production actuation. Evidence:
[2026-10-12/](2026-10-12/) ([candidates.csv](2026-10-12/candidates.csv),
[summary.md](2026-10-12/summary.md), [summary.json](2026-10-12/summary.json)). Method:
[README.md](README.md).

## What was tested

| Item | Value |
|---|---|
| Scenario | `elr-stolen-inference-credential-envtest-v1`: a stolen inference credential A is reused against a single-replica vLLM-shaped workload. Legitimate credential B is also live. |
| Environment | Private envtest API server (real API identities), unchanged `ucw-recon` brain, native actuator, shipped Python admission boundary, synthetic downstream with a call counter. No kubelet or containers. Single-tick shadow decision. |
| Attack evidence | `TEST_INJECTED` SecurityEvent, fixture-declared trusted creator |
| Arms (10 episodes each, interleaved, seed 20261012) | intervention (`endpoint-lease-revoke`), baseline (no action), cf-rotate, cf-endpoint-rotate |
| Hold window | 20.0–20.4 s per episode, about 52 probes each for credentials A and B |
| Source / binary | commit `2bbd8e91`; binary sha256 `d906691e…4076bb`; raw bundle sha256 `927c0be9…9b26cd`, held outside the repository. Per-artifact hashes are in [episode-artifacts.sha256](2026-10-12/episode-artifacts.sha256). |
| Economics | Fixture policy: `legacy-runtime-lambda-v1`, λ = 0.6. It enters only the net gain, not the Security Gain under test. Production now runs independent β. |

**Which outcome counts.** Attack success means the protected downstream operation
actually ran: HTTP 200 and the call counter advanced. Attack denial means an exact 401
with zero downstream effect. No probe in this study was indeterminate.

## The decision state

The state was identical in all 40 episodes, apart from clock jitter.

| Input | Value |
|---|---|
| asset_value | 1.6 |
| pHold | 0.3336–0.3339 |
| stage urgency | 0.3250 |
| dispersion | 1 |
| provenance | 1 |

**Facts.** Each weight is `AssetValue × pHold × (0.5 + 0.5·urgency) × m_kind`, with an
extra ×3 for the observation-bound fact
([ucw.go:79-86](../../../phorvex/internal/recon/ucw.go#L79-L86),
[ucw.go:256](../../../phorvex/internal/recon/ucw.go#L256)):

| Fact kind | Weight | Covered by |
|---|---|---|
| endpointLeaseReuse | 1.0614 (×3) | endpoint-lease-revoke |
| inMemory | 0.3538 | rotate |
| podIdentity | 0.3538 | rotate |
| session | 0.2123 | rotate, kv-reset*, kv-migrate-invalidate* |
| inflightRequests | 0.3538 | request-drain* |
| networkIdentity | 0.2830 | quarantine* |

\* Not enabled in the fixture policy, so not candidates.

**Candidates:**

| Action | Feasible | Cover | Predicted SG (gross) | Net | Selected |
|---|---|---|---|---|---|
| endpoint-lease-revoke | yes | endpointLeaseReuse | 1.0616 | 0.98 | 40/40 |
| rotate | **no**: availability, ready=1-1 < minAvailable=1 | inMemory, podIdentity, session | 0.9199 | — | 0 |
| endpoint-rotate | yes | none | 0 | −0.06 | 0 |
| noop | yes | — | 0 | 0 | 0 |

## Results

### Outcomes by action

This measures whether credential A reached the protected downstream after the branch.

| Action (arm) | Episodes where the attack still reached downstream | Attack probes that succeeded | Risk reduction vs baseline, Newcombe 95% | Legitimate B failures | Reacquisition / effect duration |
|---|---|---|---|---|---|
| none (baseline) | 10/10 [0.72, 1] | 521/521 | — | 0/521 | n/a |
| endpoint-lease-revoke | **0/10 [0, 0.28]** | **0/532 [0, 0.007]** | **1.000 [0.608, 1.000]** | 0/532 in hold, 34/34 during dispatch | none observed: censored at ≥ 20.0 s in all 10 |
| rotate (counterfactual) | 10/10 | 523/523, and 10/10 after the replacement | 0.000 [−0.278, 0.278] | UNAVAILABLE (no kubelet) | n/a: capability never removed |
| endpoint-rotate (counterfactual) | 10/10 | 519/519 | 0.000 [−0.278, 0.278] | 0/519 | n/a: the actuator refused (no `phorvex.ai/route-service`) |

**endpoint-lease-revoke timing:**

| Measure | Min | Median | Max |
|---|---|---|---|
| Native dispatch | 211 ms | 363 ms | 600 ms |
| From the attack-landed probe to the first confirmed denial | 661 ms | 977 ms | 2,076 ms |

Legitimate p95 latency was 64.5 ms with ELR and 59.9 ms in the baseline, measured locally
from a single worker.

**Time horizon.** The attack was denied at every horizon after ELR: 0/138 in 0–5 s,
0/128 in 5–10 s, 0/255 in 10–20 s and 0/11 at 20 s or later. Every other arm succeeded at
every horizon. Horizons beyond about 20 s and multi-tick behaviour were not measured.

### Fact invalidation vs capability

This compares the brain's re-observation after the branch with the probes.

| Branch | endpointLeaseReuse after the branch | Credential A | Classification | Brain would select next |
|---|---|---|---|---|
| endpoint-lease-revoke | not minted, 10/10 | denied | **true invalidation**, 10/10 | noop |
| rotate, observed on the replacement pod | not minted, 10/10 | usable | **false invalidation**, 10/10 | noop |
| endpoint-rotate (refused) | minted (1.07) | usable | consistent | endpoint-lease-revoke |
| baseline | minted (1.07) | usable | consistent | endpoint-lease-revoke |

The mechanism is visible in the code:

- **Why ELR's invalidation is sound.** It is grounded in the same state that enforces
  admission. The ingester binds the reuse observation only while both observed credential
  HMACs are still in the live lease allowlist
  ([endpoint_lease.go:66-73](../../../phorvex/internal/ingest/endpoint_lease.go#L66-L73)).
  The revoke removes A from that allowlist, and the Python boundary enforces the same
  allowlist.
- **Why rotate clears the fact falsely.** The observation binds to the target **pod UID**
  ([endpoint_lease.go:39-47](../../../phorvex/internal/ingest/endpoint_lease.go#L39-L47)).
  The fact key is `scope|ns/pod|kind`
  ([facts.go:169-174](../../../phorvex/internal/recon/facts.go#L169-L174)). The capability
  itself lives in the namespace-wide lease Secret and policy. The replacement pod gets a
  new UID and name, so the fact disappears while credential A remains allowed.
- **Why the replacement's weights reset.** On the replacement pod the brain re-mints
  inMemory, podIdentity, session, networkIdentity and inflightRequests, but at weight
  about 0.0001. pHold is damped by `1 − exp(−exposure / RecoverScale)`, where exposure is
  the pod's age ([hazard.go:523-525](../../../phorvex/internal/killchain/hazard.go#L523-L525)).
  A rotation therefore resets the model's attacker-hold estimate to zero, whatever happened
  to capabilities held outside the pod.

### Ranking and regret

These are matched comparisons from the same initial state, not a simultaneous measurement
of the four branches.

| Comparison | Result |
|---|---|
| All four actions | Kendall τ-b 0.775, Spearman ρ 0.816. Descriptive only (n = 4 actions, one scenario). |
| Feasible actions only (ELR, endpoint-rotate, noop) | τ-b 1.0, ρ 1.0 |
| Pairwise reversals | None. Rotate vs endpoint-rotate and rotate vs noop are predicted strict (0.92 vs 0) but tie in measured outcome. |
| Regret against the best tested feasible action | 0.000 |

**How weak this test is.** Both feasible alternatives had a predicted gain of exactly 0.
Any score that gives endpoint-lease-revoke a positive value would rank this state
correctly.

## Answers to the Math/OR questions

### 1. Does the current score accurately represent actual fact invalidation?

**Partly.** It is accurate only for the observation-bound fact.

- **Confirmed true invalidation.** For `endpointLeaseReuse`, the cover map's claim
  (endpoint-lease-revoke invalidates it) matched the measurements in 10/10 episodes. The
  fact is grounded in the same allowlist that the admission boundary enforces.
- **False invalidations.** The score's fact state also produces false invalidations. Any
  action that changes pod identity clears every pod-keyed fact, including capabilities
  that do not live in the pod.
- **False-positive rate.** For rotate it was 10/10 on the measured capability. No
  claimed-but-usable case occurred for an action's *own* cover keys on the measured
  capability, because rotate does not claim this key.
- **False negatives.** No action measurably disrupted credential A without being credited.
- **Unmeasured cover keys.** Rotate's claimed invalidation of inMemory, podIdentity and
  session could not be checked. This fixture has no in-memory implant, token theft or
  session hijack to remove.

### 2. Does invalidating more weighted facts lead to greater attack disruption?

**Not in this scenario, and not validated in general.**

| Action | Facts covered | Weighted coverage | Measured disruption of the attack path |
|---|---|---|---|
| rotate | 3 | 0.92 | 0 |
| endpoint-lease-revoke | 1 | 1.06 | complete |

A sum of weights treats facts as interchangeable units of value. Attack disruption here
depends on whether the specific capability on the attack path is removed.

ELR ranked first only because of the hand-set ×3 dominance multiplier on
observation-bound facts. The margin is 3·w₀ − 2.6·w₀ = 0.4·w₀ ≈ 0.14. A rotate-covered
fact worth 0.4·w₀ or more, or a lower multiplier, would reverse the predicted ranking.
That would happen once rotate is feasible, for example with two or more replicas. The
measured effect of rotate on this attack path would still be zero.

### 3. Which action families show the largest mismatch?

- **Pod identity (`rotate`):**
  - predicted 0.92, which is 87% of ELR's gain;
  - measured risk reduction 0.000 [−0.28, 0.28] on the instantiated capability;
  - it also corrupts the brain's fact state (false invalidation and a pHold reset).

  Because rotate's credit is for different facts, this is unvalidated credit plus a
  measured side effect, not a demonstrated reversal on the same capability.
- **Endpoint route (`endpoint-rotate`):** predicted 0, measured 0. Consistent; the native
  handler also refuses this target.
- **Endpoint lease (`endpoint-lease-revoke`):** predicted 1.06, measured complete
  interruption. Consistent.
- **Not tested:** kv-reset, request-drain, quarantine, guardrail-rotate,
  crm-refund-revoke and the GPU and model families. These are **NOT VALIDATED**.

### 4. Does the score account for residual attacker access and reacquisition?

**No.**

- **Residual access is not modelled:**
  - After ELR, credential B stays valid by design.
  - The lease Secret, which holds `client-a`, `client-b` and the seed, is mounted in the
    serving pod.
  - The brain still mints `inMemory` (0.355) on that pod after ELR, so the model itself
    says an in-pod foothold may exist. Yet the score has no term for "capability
    reachable through another path".
  - That path is also structurally undefendable by a second revoke. Revocation needs two
    allowed leases ([endpoint_lease_revoke.go:107](../../../phorvex/internal/actuator/endpoint_lease_revoke.go#L107)),
    and the observation binder needs both a revoked and a retained allowed HMAC. A stolen
    B would therefore not even be scored. This was not measured: no B-theft emulation was
    run.
- **Reacquisition:**
  - No reacquisition of A was observed (censored at ≥ 20 s in 10/10 episodes).
  - The lease contract has no re-issue path: it offers only `Revoke`, so A cannot return.
  - The score's only time dimension (pHold driven by pod exposure) models reacquisition
    as recovery after a pod restart. That is wrong for credential capabilities: after a
    rotate it reports a hold of about 0 while A is fully usable.
  - Fact keys carry pod identity, not credential, epoch or issuance identity.

### 5. Does the formula select the most effective safe action among the alternatives?

**In this decision state, yes.** It selected endpoint-lease-revoke in 40/40 episodes.
That was the only tested feasible action that reduced risk: regret 0 and feasible-set
τ-b = 1.

Three things limit this answer:

- The test has little discriminating power (see "How weak this test is" above).
- The correct choice rests on a constant multiplier (question 2).
- One structurally relevant alternative did not exist. There was no action able to remove
  the residual B path or the in-pod foothold together with A.

### 6. Which missing measurements prevent validation?

1. **Instantiated capabilities for structural facts.** In-memory implant, pod-identity
   token use, session hijack, in-flight request abuse and network identity are needed to
   measure rotate, kv-reset, request-drain and quarantine against their own claims.
2. **Real kubelet and containers.** These are needed to measure rotate's disruption
   (single-replica outage, time to Ready) and the attacker's loss of access during the
   outage, which is currently an uncredited false negative.
3. **Detector behaviour after an identity change.** Whether and when a production
   detector re-raises lease reuse against the replacement pod sets how long the false
   invalidation lasts. This is outside the fixture. The endpoint-lease observation path is
   `TEST_INJECTED`-only by contract
   ([types.go:688-701](../../../phorvex/internal/model/types.go#L688-L701)).
4. **Residual-path emulation.** Theft of credential B from the pod's Secret mount after
   ELR.
5. **More scenarios, workloads and replica counts.** These include a feasible rotate (two
   or more replicas), production's 5-minute anti-over-rotation window (the fixture uses
   1 s), multi-tick horizons beyond 20 s, and the voice, LiteLLM, MCP, CRM and NATS
   stacks. They are needed for any statistical rank agreement.
6. **Defensible consequence values.** Without them, expected avoided loss is
   **UNAVAILABLE**.

## Limitations

- **Narrow scope.** One scenario, one workload and one tick. The system is deterministic,
  so the Wilson and Newcombe intervals reflect the number of repeat episodes from a fixed
  state, not uncertainty across scenarios.
- **Synthetic components.** The downstream, the attack event (`TEST_INJECTED`), pod
  readiness, image IDs and the replacement pod are fixture or harness-simulated. Admission
  is the real shipped Python code. envtest has no kubelet.
- **Counterfactual rotate ran despite a production gate.** The cf-rotate arm executed an
  action that the decision layer's availability gate marks infeasible. It ran only on a
  private API server, to measure what the score credits. The native actuator's own
  eligibility and policy gates still applied. No production gate was relaxed.
- **Separate episodes per branch.** "No action" and "with action" come from separate
  episodes with the same initial state and fresh credentials, not from forking one
  process. Each episode's own pre-decision probe confirms the attack had landed:
  40/40 episodes.
- **Local latency.** Legitimate latency is local and single-worker. It is not a
  production SLO measurement. Rotate's disruption is **UNAVAILABLE**.
- **Fixture economics.** The fixture uses legacy λ (0.6). The Security Gain under test
  does not depend on it, but net gains would differ under production's independent β.

## Constraint compliance

- Objective function, Security Gain formula and action-to-fact map: unchanged.
- λ/β: not tuned.
- Existential and SLO priorities: unchanged.
- No production gate relaxed.
- No action of any kind ran in production. The counterfactuals ran only on the private
  API server.
- Same declared initial state for every branch.
- Measured values, estimates, censored values and unavailable values are separated by
  status columns. Nothing unavailable is reported as zero.
- Each CSV row belongs to exactly one episode's single-tick decision state. Records from
  different ticks are never merged into one decision.
