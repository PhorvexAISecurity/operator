# Independent incident reproduction

Reviewer: bench-v3-lead. Date: 2026-10-31. Integrated baseline: bb92355cf7b6c4a696f44caf52bd5fa1268e7303. Reviewed source: 0435b7f57017dbb5768adf92a80d2accc87e5a33.

The historical benchmark corpus is pinned to deployed 0058a3edd2eb1e9801d9295d6ebbf8b3320dd8ec. Its missing authoritative replica specification cannot be repaired by interpreting legacy DesiredReplicas as spec.replicas. This proposal captures that specific future observation where the existing owner cache contains it; it does not qualify the old corpus or produce endpoint-loss intervals.

## Independent baseline

I archived main bb92355c into an isolated directory and copied only the real-producer counterexample from source0435 (test SHA256 9762c7d8c1b3be3fbd7ff1c2ff62574d319c68c2ba85675a26df98c3bf4e8d00). A real ingest snapshot runs over Kubernetes fixture objects with one observed pod, a valid UID-bound ReplicaSet-to-Deployment lineage, and Deployment spec.replicas=4. The positive control reads back the authoritative Deployment and confirms valid existing ownership before the decisive assertion. Baseline exits1 only at the intended missing authoritative observation assertion; legacy observed count remains1.

The completed execution ran20:06:15–20:06:38UTC. Exact command and source pins are in lead-final-baseline-result.json; raw output is lead-final-baseline.txt. Toolchain is genuine Go1.26.3, GOTOOLCHAIN=local, -mod=readonly, -count=1 and -timeout=15m. GOPATH=/workspace/.phorvex-go/gopath, GOCACHE=/workspace/.phorvex-go/capture-cache, TMPDIR=/workspace/.phorvex-test-tmp. Non-cluster environment uses KUBECONFIG=/dev/null, empty KUBEBUILDER_ASSETS and USE_EXISTING_CLUSTER=false. The earlier interrupted wrapper had no observed Go exit/assertion and remains separately preserved; it is not baseline evidence.

## Independent head and adversarial controls

I executed the same real-producer case plus UID/cache/missing-input, immutable-ledger, manager-tick and remote-wire tests at source0435, followed by complete architecture and generated-cover-map suites. Both commands exited0,20:07:34–20:08:29UTC. Exact argv and environment are in lead-final-head-config.json; lead-final-head-status.json records child exits, and lead-final-head.txt retains all raw outputs. This run uses the same Go1.26.3 and non-cluster environment as current go-unit CI.

The positive control records authoritative4 while preserving legacy1. Unknown reader, missing/stale immediate and parent UID, ambiguous owner, nil replicas and unsupported controller arms remain unknown. Counting-client controls prove evidence causes no additional API reads; the GVK control prevents same-name owner cache collisions. Real ledger producers preserve attribution, open-to-settled replacement, censoring, policy isolation, immutable copies and count/byte bounds. The26-field shared DTO is checked against actual ledger JSON. Default optional capture stays absent; enabled evidence stays explicitly non-authoritative and incomplete. Legacy gob inputs still decode; real manager and remote sensor/brain paths preserve decisions while carrying evidence.

All independent preflight adapter regressions also pass:11 tests, raw lead-final-preflight-adapter.txt. They challenge exact current CI recipe/tool/version resolution, seven gating module commands, pinned-base informational reporting and legacy receipt restrictions. These targeted checks do not replace the author's required complete coherent preflight.

PASS for the stated future-observation incident and non-interference contract. No product deployment, endpoint-loss completeness, actual counterfactual cost, or real paired V3 benchmark is established by these local tests. P3 and delivery still require a completed final preflight and acceptance package.
