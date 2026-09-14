# Phorvex — actuator coverage: current-source guide

**Status (2026-09-13).** This guide describes the recon-cover and selection mechanics as they
exist in the source pinned below. It replaces the August 2026 document, which mixed live
observations from 2026-08-09..11 with present-tense mechanics that no longer match the
producers. Nothing here is a fresh live result: every statement is either derived from
source or an explicitly dated historical observation with a link.

| Anchor | Value |
|---|---|
| Source read for this guide | `d296799dd59a909b149eec06802b5152f67a036f` (main, v0.4.113) |
| Producer-generated cover map | [`phorvex/docs/recon-cover-map.generated.md`](../../phorvex/docs/recon-cover-map.generated.md) — regenerate `go run ./tools/covermap --write`, verify `--check`; `TestCoverMapDocumentIsCurrent` runs the check under `go test ./...` |
| Historical original | [`ACTUATOR_COVERAGE.historical-2026-08-09.md`](ACTUATOR_COVERAGE.historical-2026-08-09.md) — verbatim, sha256 `a2878f318229fa5efc08490850f6002e68da28a52aef9c9ed45d02718101be10`, last edited in `e9a9d57` (before the PHVX-9e / PHVX-26a / PHVX-77 cover corrections) |
| Live trial ledger | [`ATTACKS_OUTCOMES.md`](ATTACKS_OUTCOMES.md) — T10/T11/T16/T46 carry current-reader annotations |
| Deployed at the time of writing | image `0.4.113`, embedded `dea7b123…` (from `workflow/fixes/T2-M123/STATUS.yaml`); this guide has **not** been correlated against that deployment (L3 pending) |

The generated map is the master key. This file explains how to read it and what sits
before and after fact emission. Where the two disagree, the map is right and this file
is stale; the check mode exists so that state does not last.

## 1. Eight things that are not the same thing

The August document collapsed "the brain chose X" and "X worked" into one story. The
pipeline has eight distinct stages, and evidence for one is not evidence for the next.

| # | Stage | Where | What it establishes |
|---|---|---|---|
| 1 | **Configured engine and profile** | `internal/runner/manager.go` (`decision.NewCoverageEngine()`, `recon.Registry.SetDefault("ucw-recon")`) | Registration alone makes `standard-recon` the default; the runner explicitly selects `ucw-recon`. Registration of a profile is not evidence that it runs. |
| 2 | **Fact emission** | `internal/recon/profile.go`, `internal/recon/ucw.go` | Which weighted facts a pod exposes for this fixture. Audit-only facts (node/model/service scope, Tier 3 cannot-help, endpointPath, modelFingerprint, gpuColocation) are emitted with **no** cover and cannot enter marginal gain. |
| 3 | **Granted cover** | same, `CoverByAction` | For each action, the fact keys the producer says every successful execution invalidates. The soundness rule in `ucw.go` is binary: no probabilistic or "usually" grants. |
| 4 | **Candidate feasibility / capability** | `internal/actionset/generator.go`, `internal/capability/gate.go`, `internal/feasibility` | An action must be policy-enabled (`model.ActionEnabled`: a nil `EnabledActions` permits only rotate + quarantine), have a non-empty cover (`no-cover` exclusion, gate.go:212), pass per-target capability fixtures (labels, pools, route service, serving endpoint), backend support, RBAC, then feasibility laws and the cost ceiling. |
| 5 | **Selected move** | `internal/decision/coverage.go`, `internal/decision/existential.go` | The greedy in §2. Selection is a statement about weights and costs at one tick. |
| 6 | **Dispatched action** | `internal/actuator` (`PHORVEX_ACTUATOR` = phoenix \| native \| hybrid; `phorvex/docs/actuator-repertoire.md`) | The handler ran. `HandlerResult.Emitted=false` means the contract was absent and nothing was done (e.g. route-rotate without `phorvex.ai/route-service`). |
| 7 | **Confirmed effect** | detector re-measurement, audit (M-9) | Whether the fact was actually invalidated. Handler success is not effect confirmation; the brain does not verify effect today. |
| 8 | **Attack outcome** | `ATTACKS_OUTCOMES.md` | Whether the attacker's objective was defeated. Depends on 1–7 plus the attack. |

## 2. How selection actually scores (current source)

The August text said the engine "literally optimizes coverage-per-dollar". It does not.

- Objective per candidate, `coverage.go:392` (`legacyMixedGain`):
  `gain = marginal · provenance − lambdaRuntimeLegacy · ECost`
  - `marginal` = the weight of the candidate's cover keys **not yet covered** by an earlier
    pick this tick (`existential.go:167`, `chooseRound`). Facts without any cover key
    contribute nothing, however heavy.
  - `provenance` ∈ [`provFloor`=0.34, 1] (`coverage.go:386`, `:636`): 1 when the asset's
    podIdentity exposure has reached the proactive floor **or** the kill-chain assessment has
    evidence; otherwise scaled down so a fresh, evidence-less decoy cannot displace a real
    asset.
  - `lambdaRuntimeLegacy` is the per-tenant runtime dual (`cost.DualSolver`, seeded once
    from the policy's `lambda` when the tenant bucket is created, then stepped from
    demand vs. selected count vs. `MaxMovesPerTick`; `coverage.go:581`); `ECost` is the
    calibrated expected cost of the move. It is not certified as an exact dual.
- Constraint: one move per asset (partition) and at most `MaxMovesPerTick` picks per tick
  (`coverage.go:684`). A pick needs **strictly positive** gain (`strictPositiveGain`,
  `coverage.go:390`; `existential.go:204`) unless the M-99 existential path holds an
  "active" containment candidate, which takes priority regardless of gain.
- `ReactiveOnly` policies suppress candidates on assets without a direct pod-targeting
  event or a `SuspectAdapter` marker.
- **`perDollar` is reported, not optimized** (`coverage.go:796`, `:805`): `cov/ecost` is
  written to the decision record and the trace; the "why" strings of older builds quoted
  it, which is where the August framing came from.
- **No approximation guarantee is claimed.** `ucw.go:34` records that the objective is
  submodular but not monotone and the constraint is a truncated partition matroid, so
  neither the 1−1/e nor the 1/2 bound applies. Ratios reported by `optimality.go` are
  bounded measurements on specific instances.

Consequence for test design: "the brain picked the cheap surgical move" requires that the
surgical move's cover keys carry enough uncovered weight to beat `λ·ECost` and every
competing candidate; it is not implied by the move being registered, enabled, or cheaper.

## 3. Reading the generated map

`recon-cover-map.generated.md` executes both registered profiles on 16 named fixtures
(plain, stateful, neighbours, GPU served model with and without MIG device, CPU served
model, suspect adapter, PHold=0, non-neutral physics, trusted vector events of each type,
neighbour-propagated event, 10-hour-old event, CPU pod with a vector event). For each
(fixture, profile) it lists every emitted fact with weight and the actions naming its key,
and every declared action's cover set — including the coverless ones.

Rules for reading it:

- The union of fixtures is a **branch inventory**, not runtime eligibility. A grant shown
  for `gpu-mig` says what the producer does when `Pod.MIGDevice != ""`; whether a real pod
  reaches that branch, passes the capability gate and wins selection is stages 4–5.
- Weights are the producer's multipliers at AssetValue=1, PHold=1, StageUrgency=1
  (`base·urg = 1`). Real weights scale with the context provider's asset value, the
  belief's P(hold) and stage urgency, and (ucw only) the per-asset dispersion scalar
  capped at `MaxDispersionMult=4`.
- The file pins the content hash of `internal/recon`, `internal/registry`, `internal/model`
  and the tool itself. Editing any of them without regenerating fails `--check` and the CI
  test; a commit that touches none of them does not.

## 4. Current cover facts, stated explicitly

Each row below is asserted by `tools/covermap/covermap_test.go`
(`TestCurrentCoverFactsHoldInEveryFixture`, `TestVectorSteeringIsMeasuredExactly`) against
the producers, so this table cannot silently drift.

| Action | Cover at d296799 | Condition and contract |
|---|---|---|
| `rotate` | `podIdentity`, `inMemory`, `session` | every fixture, both profiles |
| `quarantine` | `networkIdentity`, one `lateralEdge` per neighbour | every fixture; edges only when the graph supplies neighbours |
| `identity-rotate` | **none** | `profile.go:66`: the handler writes an `identity-epoch` label only (`handlers_k8s.go:223`); UID, SA token, IP and EndpointSlice membership are unchanged, so no fact is invalidated. Excluded `no-cover` before scoring. Removed in `992a52c` (2026-08-09, PHVX-9e). |
| `route-rotate` | `networkIdentity` | `profile.go:97`: granted again since `ca50e82` (2026-08-26, PHORVEXSEC-129) because the handler now re-keys `phorvex.ai/route-key` **and** restitches the declared `phorvex.ai/route-service` selector, compensating the pod label if the Service write fails (`handlers_k8s.go:267`). Without the annotation the handler returns `Emitted=false` and nothing happens; with exactly one Ready backend it refuses. The recon grant itself is unconditional — the contract is enforced at dispatch, not at fact emission. The register's "route-rotate grant removed" line is stale. |
| `kv-reset` | `session` | only when `FactContext.HasGPU \|\| FactContext.Stateful` (`profile.go:89`); the runner copies these from `Pod.HasGPU` / `Pod.Stateful` (`coverage.go:492`). Capability additionally needs a Ready serving endpoint. |
| `kv-migrate-invalidate` | `session` | `ucw.go:145` (PHVX-77): covers the same session key as kv-reset, **not** `endpointPath`; emitted when `Pod.HasGPU \|\| Pod.ModelID != ""`. |
| `endpoint-rotate` | **none** | `endpointPath` is emitted for served models but audit-only (M-35): restitching a selector does not prove the learned locator is unusable. |
| `model-shard-replace` | **none** | `modelFingerprint` audit-only (M-37): no loaded-identity/effect witness. |
| `mig-rebind` | `gpuContentionChannel` | only when `Pod.MIGDevice != ""` (`ucw.go:131`); never `gpuColocation` — repartitioning does not move the pod. Capability also needs node, GPU id and target profile. |
| `warm-swap` | **none** | `ucw.go:125` (PHVX-26a): `rewarmShadow` expresses no anti-affinity, so relocation is not guaranteed and neither GPU fact may be granted. Unselectable by the optimizer on every fixture. |
| `adapter-rotate` | `adapterIntegrity` | only while `Pod.SuspectAdapter` is set (`ucw.go:175`); ingest populates it from the `phorvex.ai/lora-adapter` annotation only on a pod labelled `phorvex.ai/lora-enabled=true` (`ingest/kube.go`). Weight `base·urg·3`. Marker steerability is M-95 (open). |
| `request-drain` | `inflightRequests` | served model (`Pod.HasGPU \|\| ModelID`); capability needs a Service selecting on `phorvex.ai/serving`. |
| `guardrail-rotate` | `guardrailBypass` | served model; capability needs `phorvex.ai/guardrail-tier=true` and ≥2 variants. |
| `debugger`, `custom-inject` | **none** | manual-by-design; also gated by the M-6 admission verifier. |
| `noop`, `disable` | **none** | declared, never generatable (`model.MutatingActions`). |

Audit-only in every fixture: `endpointPath`, `modelFingerprint`, `gpuColocation`,
`nodeFoothold`, `modelIdentity`, `guardrailVariant`, `credential`, `retrievalState`,
`artifactProvenance`, `controlPlanePersistence`. Their weights never enter gain because
the generator projects weights only through cover keys (`generator.go`, "Objective weights
are projected strictly through action covers").

### 4.1 The M-42 asymmetry, as it is

Two different predicates decide the AI arms:

- `standard-recon` sizes the session fact and grants kv-reset on
  `FactContext.HasGPU || FactContext.Stateful` (= `Pod.HasGPU || Pod.Stateful`).
- `ucw-recon` emits the AI facts and grants kv-migrate-invalidate / request-drain /
  guardrail-rotate on `Pod.HasGPU || Pod.ModelID != ""`.

The `cpu-served-model` fixture shows the gap: a pod with `ModelID` set, no GPU and not
stateful gets every AI fact and a kv-migrate-invalidate session grant, while its session
weight stays at 0.6 and kv-reset gets nothing. This guide records the asymmetry; M-42
remains open and nothing here changes it.

### 4.2 Attack-vector steering (the ×3 lever)

`ucw.go:187-195`, `vectorDominance = 3.0` (`:296`). Measured in the map's "Event steering
observed" table:

| Trusted pod-targeting event `Type` | Fact boosted ×3 | Steers toward |
|---|---|---|
| `phorvex.attack.kv` | `session` | kv-reset (and kv-migrate-invalidate, which shares the key) |
| `phorvex.attack.guardrail` | `guardrailBypass` | guardrail-rotate |
| `phorvex.attack.inflight` | `inflightRequests` | request-drain |
| `phorvex.attack.adapter` | **nothing in recon** | adapter steering comes only from the `SuspectAdapter` marker |

Facts the boost does not touch, and what it does not do:

- It multiplies a weight; it **adds no cover key and removes none** (cover sets are
  byte-identical with and without the event in every fixture). It cannot make warm-swap,
  identity-rotate or endpoint-rotate selectable.
- It requires `TargetsPod=true`. Events propagated from a graph neighbour carry
  `TargetsPod=false` (`manager.go:1413`) and do not steer.
- It only runs inside the served-model branch: a CPU pod with a KV event is not boosted.
- A boosted selection is still stage 5. It proves nothing about dispatch, effect or
  mitigation.
- **Trust.** Only an event whose admission-stamped creator identity is on the
  `--trusted-detectors` allowlist reaches `view.Events` (`ingest/events.go:102-107`,
  M-94); `spec.rule.source` decides nothing. The chart default
  (`charts/phorvex/values.yaml`, `phorvex.trustedDetectors`) lists
  `vllm/detector-kv-canary`, `vllm/detector-adapter-inv` and
  `phorvex-system/operator-controller-manager` (the phoenix-extended operator's SA,
  `config/default/kustomization.yaml` namePrefix `operator-`). The Phorvex manager/console
  SA (`<release>-manager`) is not on it and must not be added to make the console's
  `scenario_fire.go` events steer the brain. With an empty allowlist nothing external is
  trusted (fail-closed). M-94's live acceptance is still open; this guide does not close it.
- **Aging.** The kill-chain evidence weight of an event decays linearly to 0 at
  `EventAgeHorizon` (default `ProactiveFloor`; `hazard.go:372`, `model.EventAgeWeight`).
  The recon boost reads only `Type` and `TargetsPod` (`hasVectorEvent`, `ucw.go:300`): the
  `gpu-vector-kv-aged` fixture (10 h old) is still ×3. The comment in `ucw.go` that the boost
  is "gone once the event ages out" holds only in the sense that the event stops being
  ingested when its CR is deleted: ingest applies no age cutoff (`events.go`), the
  operator's ingest/decision path deletes nothing, and only the console's red-team
  clear/restore paths delete the events they themselves fired. Detectors own their signal
  lifecycle.
- The same event types are promoted to `StagePersist` in `hazard.go:236`.
- Trace attribution of the boost (a `steeredBy` field) is M-153's proposal and is **not**
  implemented; the ×3 is invisible in `finalWeight`.

## 5. Historical trials: what they were, and why they do not reproduce

The ledger rows stay as written; each of these entries in `ATTACKS_OUTCOMES.md` now carries
a current-reader annotation. None of the four recorded the source SHA or image of the build
under test, so their pins are unknown. Summary:

| Trial | Date | Observed then | Why the selection path is not current source |
|---|---|---|---|
| T10 identity-rotate | 2026-08-09 | selected and enacted; SA token still valid, UID unchanged | selection required the `podIdentity` grant removed in `992a52c` (same day). At d296799 identity-rotate is coverless in both profiles and excluded `no-cover` before scoring. The effect finding remains a correct description of the handler. |
| T11 route-rotate | 2026-08-09 | selected; pod relabelled, Service/EndpointSlice untouched | that handler was replaced in `ca50e82` (2026-08-26): it now restitches the declared Service selector or returns `Emitted=false`. The cover was removed in `992a52c` and restored in `ca50e82`. The T11 effect finding no longer describes the code; the new path has **not** been live-verified by this fix. |
| T16 warm-swap | 2026-08-10 | selected with cover `gpuColocation`+`sideChannel` (cov 2.18); enactment blocked, no warm pool | both grants were removed in `5f0eea8` (2026-08-16, PHVX-26a) and `sideChannel` was renamed `gpuContentionChannel` in `caaff6c`. At d296799 warm-swap is coverless and cannot be selected. |
| T46 warm-swap, real warm pool | 2026-08-11 | selected in 4 s (cov 2.61); shadow promoted, in-flight drained, leader retired; F18 surfaced | same as T16: the selection cannot recur at current source. The observed effect and F18 stand as dated observations of that build and topology, not as current-source evidence. |

## 6. Open obligations this guide does not resolve

- **M-42** session-arm asymmetry (§4.1). **M-35** endpointPath audit-only. **M-43**
  pod-deleting AI moves under-credited. **M-37** model-shard-replace cover withheld.
- **M-94** trust boundary: source enforcement is in; live acceptance of the deployed
  composition remains open (`workflow/fixes/T2-M123/AUTHORIZATION.md`: Tier 1 live
  acceptance and PR #187 are explicitly open).
- **M-153** vector-steering attribution and scoping: pending.
- **T2-M123 L3**: correlating this guide's source/config assumptions with the deployed tier
  is a lead live-verification step; it has not happened.

## 7. Regenerate and check

```sh
cd phorvex
go run ./tools/covermap --check    # exit 1 on drift, never writes
go run ./tools/covermap --write    # regenerate docs/recon-cover-map.generated.md
go test ./tools/covermap           # freshness + invariants (also runs under go test ./...)
```
