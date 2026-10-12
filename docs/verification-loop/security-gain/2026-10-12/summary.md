# Security Gain validation — elr-stolen-inference-credential-envtest-v1

Episodes: 40 (intervention=10, baseline=10, cf-rotate=10, cf-endpoint-rotate=10). Baseline (no action) attack reached the protected downstream in 10/10 episodes.

## Outcomes by action (measured capability: credential A → downstream)

| action | feasible in state | predicted SG (gross) | predicted weight on measured capability | attack reached downstream (episodes, Wilson 95%) | attack probe success (Wilson 95%) | risk reduction vs baseline (Newcombe 95%) | legit failures | reacquisition |
|---|---|---|---|---|---|---|---|---|
| noop | True | 0.0000 | 0.0000 | 10/10 = 1.000 [0.722, 1.000] | 521/521 = 1.000 [0.993, 1.000] | 0.000 [-0.278, 0.278] | 0/521 | not-applicable |
| endpoint-rotate | True | 0.0000 | 0.0000 | 10/10 = 1.000 [0.722, 1.000] | 519/519 = 1.000 [0.993, 1.000] | 0.000 [-0.278, 0.278] | 0/519 | not-applicable |
| rotate | False (availability: ready=1-1 < minAvailable=1) | 0.9199 | 0.0000 | 10/10 = 1.000 [0.722, 1.000] | 523/523 = 1.000 [0.993, 1.000] | 0.000 [-0.278, 0.278] | UNAVAILABLE (no kubelet: eviction does not stop serving) | not-applicable |
| endpoint-lease-revoke | True | 1.0616 | 1.0616 | 0/10 = 0.000 [0.000, 0.278] | 0/532 = 0.000 [0.000, 0.007] | 1.000 [0.608, 1.000] | 0/532 | censored ≥ 20.0s |

## Fact invalidation vs capability (post-branch brain re-observation)

| action | post observed | target observed after | endpointLeaseReuse cleared + capability removed | cleared but A still usable (false invalidation) | endpointLeaseReuse persisting | other kinds cleared (unmeasured) | kinds re-minted on a new identity | brain selects after |
|---|---|---|---|---|---|---|---|---|
| noop | 10/10 | same pod vllm/vllm-a | 0 | 0 | 10 | — | — | endpoint-lease-revoke |
| endpoint-rotate | 10/10 | same pod vllm/vllm-a | 0 | 0 | 10 | — | — | endpoint-lease-revoke |
| rotate | 10/10 | harness-simulated ReplicaSet replacement vllm/vllm-a-replacement | 0 | 10 | 0 | — | inMemory, inflightRequests, networkIdentity, podIdentity, session | noop |
| endpoint-lease-revoke | 10/10 | same pod vllm/vllm-a | 10 | 0 | 0 | — | — | noop |

## Fact weights before the decision and after the branch (mean by kind)

| action | endpointLeaseReuse | inMemory | inflightRequests | networkIdentity | podIdentity | session |
|---|---|---|---|---|---|---|
| (before, all arms) | 1.0614 | 0.3538 | 0.3538 | 0.2830 | 0.3538 | 0.2123 |
| noop (after) | 1.0655 | 0.3552 | 0.3552 | 0.2841 | 0.3552 | 0.2131 |
| endpoint-rotate (after) | 1.0655 | 0.3552 | 0.3552 | 0.2841 | 0.3552 | 0.2131 |
| rotate (after) | absent | 0.0001 | 0.0001 | 0.0001 | 0.0001 | 0.0000 |
| endpoint-lease-revoke (after) | absent | 0.3553 | 0.3553 | 0.2842 | 0.3553 | 0.2132 |

## Time horizon (credential-A probe success after the branch point)

| action | 0–5 s | 5–10 s | 10–20 s | 20– s |
|---|---|---|---|---|
| noop | 131/131 | 127/127 | 255/255 | 8/8 |
| endpoint-rotate | 130/130 | 129/129 | 255/255 | 5/5 |
| rotate | 131/131 | 129/129 | 256/256 | 7/7 |
| endpoint-lease-revoke | 0/138 | 0/128 | 0/255 | 0/11 |

## Ranking

Order: endpoint-lease-revoke, rotate, endpoint-rotate, noop; predicted SG [1.0616, 0.9199, 0.0, 0.0]; measured risk reduction [1.0, 0.0, 0.0, 0.0].
Kendall τ-b = 0.775; Spearman ρ = 0.816. One scenario and 4 actions; a rank coefficient over so few points is descriptive only. Statistical rank agreement: NOT VALIDATED.

Feasible candidates only (endpoint-lease-revoke, endpoint-rotate, noop): Kendall τ-b = 1.000; Spearman ρ = 1.000.

| predicted higher | predicted lower | both feasible | measured RR (higher / lower) | verdict |
|---|---|---|---|---|
| endpoint-lease-revoke | rotate | no | 1.000 / 0.000 | agree |
| endpoint-lease-revoke | endpoint-rotate | yes | 1.000 / 0.000 | agree |
| endpoint-lease-revoke | noop | yes | 1.000 / 0.000 | agree |
| rotate | endpoint-rotate | no | 0.000 / 0.000 | tie-in-outcome |
| rotate | noop | no | 0.000 / 0.000 | tie-in-outcome |

Regret: brain selected endpoint-lease-revoke; best tested feasible action endpoint-lease-revoke (feasible tested: endpoint-lease-revoke, endpoint-rotate, noop); regret in risk-reduction units = 0.000.
