# Phoenix AMTD — Gap Implementation Spec (Inference Workloads)

> **Scope.** This is a forward implementation spec for the **inference-focused** Adaptive Moving Target Defense (AMTD) capabilities that the four R6 Security papers + two product pages describe but the `phoenix-main` codebase does **not** yet implement. Every capability is framed as an **extension of the existing operator** (its CRDs, its `nim_controller`, its `SecurityEvent` contract), not a rewrite.
>
> **Inputs.** (1) The verified current architecture (code-anchored to exact files/lines in `phoenix-main`, `time-based-trigger`, and the integrators). (2) The gap analysis (`spec-map.md`) that classifies each paper claim as *implemented* / *partial* / *claim-without-code*. (3) The papers: `adaptive-container-orchestration.pdf` ("Proactive Security"), `amtd-ai-infrastructure-security.pdf` ("Adaptive Security for AI Infrastructure", Zsolt Nemeth), `ada-amtd-ai-workloads.pdf` ("ADA / Automated Moving Target Defense for AI Workloads"), `PHOENIX-adaptive-containers.pdf`. (4) The product pages: *Phoenix for AI*, *Phoenix for Kubernetes*. (5) Per-capability adversarial verdicts (paper-fidelity, code-anchor, invention, underspec checks).
>
> **What this doc is.** A buildable spec: PROPOSED Go struct / CRD YAML sketches and Go interface signatures, plus the exact `phoenix-main` symbols each change touches. It is **not** a set of controller implementations.
>
> **Prime directive (non-negotiable).** Anything the papers leave open is a **flagged decision for the owner**, never a fabricated value. Where a value appears as a "Proposed default" it is labelled as such and mirrored into [Decisions needed from you](#decisions-needed-from-you-consolidated); it is a starting point to confirm, not a settled fact. Quantitative figures from the papers (downtime `400s→15s`, persistence `95%+→<4%`, `MTTR<5min`, availability `99.8%`, overhead `1–2%`) are **asserted/marketing values with no measurement code today** and are treated as targets-to-confirm, not guarantees.

---

## Codebase today (what we are extending)

`phoenix-main` is a **reactive `SecurityEvent` → `Action`** Kubernetes operator. The relevant facts the rest of this spec builds on:

- **CRD surface is minimal.** `AdaptiveMovingTargetDefenseSpec` (`api/v1beta1/adaptivemovingtargetdefense_types.go` L29–41) is **only** `PodSelector map[string]string` (L35) + `Strategy []ResponseStrategy` (L40). Each `ResponseStrategy` (L258–267) is one `Rule` → one `AMTDAction`. `Rule` (L269–281) is **three plain strings** `{Type, ThreatLevel, Source}` matched **literally**. `AMTDAction` (L249–255, `+kubebuilder:validation:MaxProperties=1` at L248) is a tagged union: `Disable` / `Delete` / `Quarantine` / `Debugger` / `CustomAction` — exactly one set.
- **Both Status structs are EMPTY.** `AdaptiveMovingTargetDefenseStatus` (L284–287) and `SecurityEventStatus` (`securityevent_types.go` L45–48) are empty structs, though the `status` subresource is enabled (L290 / L51). There is **no observed-state / feedback / audit channel** anywhere.
- **`SecurityEvent` is the universal contract object** (`securityevent_types.go`, cluster-scoped L52): `Spec{ Targets []string ("ns/name"), Rule{Type,ThreatLevel,Source}, Description }`. It carries **no metric value, score, or magnitude**. Emitters (prometheus / falco / kubearmor integrators + `time-based-trigger`) `POST` it; `securityevent_controller` consumes it.
- **The matcher is exact equality.** `securityevent_controller.go` selects an action via `reflect.DeepEqual(strategy.Rule, securityEvent.Spec.Rule)` (**L139**, load-bearing). Identical `Rule` input always yields the identical action — no scoring, no feedback, no state. The action dispatch chain (L197–372) implements `Delete` (L197–203, the **sole rotation primitive** `r.Client.Delete`), `Debugger` (L204–241), `CustomAction` (L242–284), `Quarantine` (deny-all `NetworkPolicy`, L285–369), and everything else (incl. the declared-but-unimplemented `Disable`) falls through to **`"NOT IMPLEMENTED YET"` at L370–372** — a ready slot.
- **`nim_controller` is "Node Infrastructure Module", not NVIDIA NIM.** `nim_constants.go` L25 names it. `NIMReconciler.Reconcile` (`nim_controller.go` L90–133) reconciles **every Pod** (no inference selector), gates on `FindTimedEvent` (L121, impl L136–143: `Rule.Type=="timed" && Rule.Source=="TimeBasedTrigger"`), and on a hit runs `processPodWithNIM` (L145–175): write four `nim.r6security.com/*` annotations (L155–158), `r.Update` (L160), then `r.Delete` with grace (L168) so the owning ReplicaSet/Deployment recreates a **byte-identical** pod — **no image swap, no GPU rebind, no endpoint/key rotation**. It then self-requeues at a **fixed `policy.RequeueAfter` = 10s** (L131–132). `NIM_RESCHEDULE_COUNT` (`nim_constants.go` L31) is **declared but never written** — a dangling seam.
- **All scheduling is deterministic.** `time-based-trigger`'s `SchedulableDuration.Next` = `t.Add(d)` (`pod_controller.go` L69), `nextReconcile` (L176), `NIMReconciler`'s fixed 10s requeue, and the AMTD/SecurityEvent hard-coded requeues (`adaptivemovingtargetdefense_controller.go` L196 = 10s; `securityevent_controller.go` L362 = 2s) are all fixed. The only `rand` in any repo is a non-security gRPC nonce (`kubearmor-integrator` `logClient.go` L84). There is **no jitter** anywhere.
- **Config injection pattern exists.** `NIMReconciler.Policy` (L83) is wired in `cmd/main.go` L126 via `Policy: controller.DefaultNIMPolicy()`. New controllers register by pasting a block above the `//+kubebuilder:scaffold:builder` marker at `cmd/main.go` **L131** (mirroring the NIM block L123–130); new API types auto-join at the `//+kubebuilder:scaffold:scheme` marker **L53**.
- **The webhook server is wired but unused.** `cmd/main.go` L80 starts a webhook server on `:9443`; no admission handler is registered, and no `ValidatingWebhookConfiguration`/`MutatingWebhookConfiguration` exists in `config/`.
- **Greenfield areas (verified zero code in any of the 5 repos):** golden-image / warm-pool / LWS / shadow-worker; cosign/sigstore/rekor at runtime (cosign exists **only** in a `prometheus-integrator` CI workflow); GPU / MIG / NVLink / CUDA / encryption / re-key; node drain / cordon / evict / `corev1.Node`; anomaly scoring / weighting / PromQL scraping (the integrators are webhook **sinks**, the anomaly decision happens upstream in external Alertmanager rules that exist in none of the repos).

---

## Capability index

| # | Capability | Focus | Paper sources | Primary `phoenix-main` touch-point | New CRD type? | Depends on |
|---|------------|-------|---------------|-------------------------------------|---------------|------------|
| 1 | **Inference-rotation core ("Adaptive NIM")** | primary | ADA Listing 1; AMTD-AI §3.2; Phoenix-for-AI Pillar 01/03 | `nim_controller.go` `processPodWithNIM` L145–175 (delete site L160–168) | embedded `InferenceRotationSpec` (or standalone — **DECISION**) | 2, 3, 4, 5, 6 |
| 2 | **Golden-image + warm-pool (LWS) zero-downtime swap** | primary | AMTD-AI §3.1/§3.2/§5.1; ADA §5.5/§6.2 | `nim_controller.go` delete site L168 → `LeaderSwapper.Swap` | `WarmInferenceSet` (recommended) | 1, 4, 5, 6 |
| 3 | **GPU-aware micro-shuffle + encrypted ephemeral memory / RAG sandbox** | primary | Proactive §IV.C.1/§IV.C.2/§IV.C.5; ADA §5.6.1/§2.6.1/Listing 1 | `nim_controller.go` delete site L168 (mutate template) + `securityevent_controller.go` `RotateAction` branch | embedded `GPUShufflePolicy`/`EphemeralMemoryPolicy`/`RAGSandboxPolicy` | 1, 2, 4, 5, 6, 7 |
| 4 | **Randomized / jittered scheduling + endpoint TTL** | primary | AMTD-AI §3.2/§5/§5.3; PHOENIX §III; Proactive §V.A | `nim_controller.go` requeue L131–132; `time-based-trigger` `pod_controller.go` L150/L176 | embedded `RotationPolicy` (or `RotationSchedule` — **DECISION**) | 1, 2, 3, 5 |
| 5 | **Telemetry-driven adaptive rotation (anomaly-weighted cadence + `ContextMutationPolicy`)** | primary | Proactive §IV.C.3/§II.D.2/§IV.D; ADA §2.6/§6.3.3/Listing 1; Phoenix-for-AI p.3–4 | `nim_controller.go` requeue L131–132 + gate L121; `securityevent_controller.go` matcher L139; new `SecurityEventSpec.AnomalyScore` | `ContextMutationPolicy` | 1, 2, 4, 6, 7 |
| 6 | **Signed-baseline drift correction / self-healing regeneration** | secondary | AMTD-AI §3.1/p.5; Proactive §IV.B/§IV.C.4/§IV.D; ADA §2.5/Listing 1; README L34 | `securityevent_controller.go` Delete L198 + `nim_controller.go` L168 (verify-before-recreate); webhook on `:9443` | embedded `BaselineSpec`/`BaselineStatus` (or `WorkloadBaseline` — **DECISION**) | 1, 2, 5, 7 |
| 7 | **Node rotation / panic-move to a clean node** | secondary | Proactive §IV.B/§IV.D/§III.C.1/§III.C.4/§V.A/§V.D; Phoenix-for-AI Pillar 03 | new `AMTDAction.NodeRotate` branch in `securityevent_controller.go` L197–372; new node-aware reconciler | embedded `NodeRotateAction`/`NodeRotationPolicy` (or `NodeRotation` CRD — **DECISION**) | 1, 2, 4, 5, 6 |

Primary (inference-specific) capabilities (#1–#5) are ordered before secondary (workload-generic) capabilities (#6–#7).

---

## Unified extension architecture

This is the coherence layer: all seven capabilities are reconciled into **one** consistent CRD surface, controller topology, and interface set. The overlaps the papers describe redundantly (jitter + telemetry-weighting + interval all touch "rotation cadence"; image-swap + golden-pull + signature-verify all touch "the image source") are collapsed into **single shared blocks**.

### Consolidated CRD changes

The design deliberately gives rotation a single home. Two structural choices are themselves **open decisions** (see [D1](#d1), [D5](#d5), [D11](#d11)): (a) whether the new config lives **embedded on `AdaptiveMovingTargetDefenseSpec`** vs on **standalone CRD(s)** (`WarmInferenceSet`, `ContextMutationPolicy`, `RotationSchedule`, `WorkloadBaseline`, `NodeRotation`); (b) whether mutating rotation is driven by the **NIM requeue loop** vs a **one-shot `RotateAction`** in `securityevent_controller`. The sketch below shows the **embedded** form as the lower-surface default; every block is independently promotable to its own CRD.

```go
// PROPOSED — additive fields on AdaptiveMovingTargetDefenseSpec
// (api/v1beta1/adaptivemovingtargetdefense_types.go L29-41).
// ALL pointers / omitempty => existing CRs remain valid; nil => today's behavior.
type AdaptiveMovingTargetDefenseSpec struct {
    PodSelector map[string]string  `json:"podSelector"`              // existing
    Strategy    []ResponseStrategy `json:"strategy"`                 // existing

    // --- one rotation-policy block (caps #1,#4,#5 converge here) ---
    // +kubebuilder:validation:Optional
    InferenceRotation *InferenceRotationSpec `json:"inferenceRotation,omitempty"`

    // --- warm-pool / LWS (cap #2) — OR a ref to a WarmInferenceSet CRD ---
    // +kubebuilder:validation:Optional
    WarmPool *WarmPoolSpec `json:"warmPool,omitempty"`

    // --- signed baseline / drift (cap #6) — OR a ref to a WorkloadBaseline CRD ---
    // +kubebuilder:validation:Optional
    Baseline *BaselineSpec `json:"baseline,omitempty"`

    // --- scheduled node rotation (cap #7) ---
    // +kubebuilder:validation:Optional
    NodeRotationPolicy *NodeRotationPolicy `json:"nodeRotationPolicy,omitempty"`
}

// InferenceRotationSpec — the SINGLE place the extended NIM/rotation controller reads
// instead of the hard-coded DefaultNIMPolicy(). Caps #1 (mutation), #4 (cadence),
// #5 (telemetry) and #3 (GPU/memory) all hang their tuning here.
type InferenceRotationSpec struct {
    // cap #1 — what mutates on rotation (ADA Listing 1 ContainerImageUpdate/EnvPatch/ResourceAdjustment)
    // +kubebuilder:validation:Optional
    ContainerName string `json:"containerName,omitempty"`           // ADA: "nim"
    // +kubebuilder:validation:Optional
    GoldenImage string `json:"goldenImage,omitempty"`               // image ref/digest; DECISION: tag vs digest (D6)
    // +kubebuilder:validation:Optional
    EnvPatch []corev1.EnvVar `json:"envPatch,omitempty"`            // ADA: RUNTIME_MODE=SECURE
    // +kubebuilder:validation:Optional
    GPUResource *resource.Quantity `json:"gpuResource,omitempty"`   // ADA: nvidia.com/gpu "0"; DECISION (D17,D18)
    // +kubebuilder:validation:Optional
    RotationParameters *InferenceParamRotation `json:"rotationParameters,omitempty"` // API key / endpoint path; DECISION (D8)

    // cap #4 — cadence (jitter / stagger / entropy / endpoint TTL)
    // +kubebuilder:validation:Optional
    Rotation *RotationPolicy `json:"rotation,omitempty"`

    // cap #5 — telemetry-driven cadence + panic threshold
    // +kubebuilder:validation:Optional
    AdaptiveRotation *AdaptiveRotationPolicy `json:"adaptiveRotation,omitempty"`

    // cap #3 — GPU shuffle / encrypted ephemeral memory / RAG sandbox
    // +kubebuilder:validation:Optional
    GPUShuffle      *GPUShufflePolicy      `json:"gpuShuffle,omitempty"`
    // +kubebuilder:validation:Optional
    EphemeralMemory *EphemeralMemoryPolicy `json:"ephemeralMemory,omitempty"`
    // +kubebuilder:validation:Optional
    RAGSandbox      *RAGSandboxPolicy      `json:"ragSandbox,omitempty"`
}

// RotationPolicy (cap #4) — the ONE cadence block. Jitter, stagger, entropy, endpoint TTL.
// effective() mirrors NIMPolicy.effective() (nim_controller.go L62-77): zero => default.
type RotationPolicy struct {
    // +kubebuilder:validation:Required
    BaseInterval metav1.Duration `json:"baseInterval"`              // R; DECISION default (D9)
    // +kubebuilder:validation:Optional   +kubebuilder:validation:Minimum=0  +kubebuilder:validation:Maximum=100
    JitterPercent int `json:"jitterPercent,omitempty"`             // ±%; DECISION single vs [min,max], symmetric (D10)
    // +kubebuilder:validation:Optional   +kubebuilder:validation:Enum=Uniform;TruncatedNormal
    JitterDistribution string `json:"jitterDistribution,omitempty"` // DECISION (D12)
    // +kubebuilder:validation:Optional   +kubebuilder:validation:Enum=Crypto;PseudoRandom
    EntropySource string `json:"entropySource,omitempty"`          // security-load-bearing; DECISION (D13)
    // +kubebuilder:validation:Optional   +kubebuilder:validation:Enum=PerPodPhaseOffset;Independent;None
    StaggerMode string `json:"staggerMode,omitempty"`              // DECISION (D14)
    // +kubebuilder:validation:Optional
    MaxConcurrentRotations *int `json:"maxConcurrentRotations,omitempty"` // availability budget; DECISION (D24)
    // +kubebuilder:validation:Optional
    Endpoint *EndpointRotationPolicy `json:"endpoint,omitempty"`   // hash-based TTL; DECISION (D8, D15, D16)
    // carry-over so grace stays configurable when reading from CRD instead of DefaultNIMPolicy
    GracePeriodSeconds int64 `json:"gracePeriodSeconds,omitempty"`
}
```

```yaml
# PROPOSED — consolidated Status (closes the empty-Status gap; status subresource already on, L290).
# AdaptiveMovingTargetDefenseStatus, currently `struct{}` at L284-287.
status:
  observedGeneration: 0
  currentInterval: "60m"          # cap #4/#5 — live (jittered/score-derived) cadence
  lastObservedScore: "0.0"        # cap #5
  lastRotationTime: null          # caps #1,#4,#5
  rotationCount: 0                # mirrors the dangling NIM_RESCHEDULE_COUNT (nim_constants.go L31)
  nextRotationTime: null          # cap #4 — SECURITY DECISION: publishing this re-exposes the schedule jitter hides (D5)
  warmPool:                       # cap #2
    activeLeader: ""
    readyShadows: 0
    lastSwapDurationMillis: 0
  baseline:                       # cap #6
    lastVerifiedTime: null
    pinnedDigests: []
    driftDetections: 0
    lastRegeneration: null
  nodeRotations: []               # cap #7 — {sourceNode,targetNode,podName,time,phase}, bounded history
  conditions: []                  # metav1.Condition; +listType=map +listMapKey=type
```

**`SecurityEvent` contract — additive only.** Because `SecurityEvent` is shared by **all** emitters, any new field is `+optional` / pointer so every emitter keeps compiling and a missing field == today's behavior:

```go
// PROPOSED — additive on SecurityEventSpec (securityevent_types.go L27-42); caps #5,#6.
type SecurityEventSpec struct {
    Targets     []string `json:"targets"`                          // existing
    Rule        Rule     `json:"rule"`                             // existing
    Description string   `json:"description"`                      // existing
    // +kubebuilder:validation:Optional
    AnomalyScore *string `json:"anomalyScore,omitempty"`           // "0".."1"; cap #5; DECISION representation (D19)
    // +kubebuilder:validation:Optional
    Metrics map[string]string `json:"metrics,omitempty"`           // raw component signals; cap #5; DECISION upstream-vs-operator scoring (D20)
    // +kubebuilder:validation:Optional
    Evidence *DriftEvidence `json:"evidence,omitempty"`            // {ObservedDigest,ExpectedDigest,Detail}; cap #6
}
// SecurityEventStatus (currently struct{} at L45-48) populated with {AppliedAction, ObservedScore, ComputedInterval, ProcessedAt}.
```

> ⚠️ **Structural constraint the synthesizer must carry forward:** the matcher at `securityevent_controller.go` **L139** does `reflect.DeepEqual` over the **whole `Rule` struct**. A new `AnomalyScore` placed on `SecurityEventSpec` is therefore **structurally unreachable by today's dispatch** until that matcher is relaxed off `Rule`-equality (cap #5, [D21](#d21)). Likewise `AMTDAction` carries `MaxProperties=1` (L248): a new `RotateAction`/`WarmSwapAction`/`NodeRotateAction` member can be set **only as its own strategy entry**, and if rotation can be expressed **both** via `InferenceRotation` on the Spec **and** via a `RotateAction`, a precedence rule is required ([D2](#d2)).

**New `AMTDAction` members (one tagged-union slot each, respect `MaxProperties=1`):**

```go
// PROPOSED — AMTDAction additions (adaptivemovingtargetdefense_types.go L249-255).
type AMTDAction struct {
    Disable      *DisableAction    `json:"disable,omitempty"`      // existing (unimplemented -> ready slot)
    Delete       *DeleteAction     `json:"delete,omitempty"`       // existing (sole rotation primitive)
    Quarantine   *QuarantineAction `json:"quarantine,omitempty"`   // existing
    Debugger     *Debugger         `json:"debugger,omitempty"`     // existing
    CustomAction *CustomAction     `json:"customAction,omitempty"` // existing
    // +kubebuilder:validation:Optional
    Rotate     *RotateAction     `json:"rotate,omitempty"`         // caps #1,#3 — mutating rotation (image/env/gpu/memory)
    // +kubebuilder:validation:Optional
    WarmSwap   *WarmSwapAction   `json:"warmSwap,omitempty"`       // cap #2 — leader→shadow cut
    // +kubebuilder:validation:Optional
    Regenerate *RegenerateAction `json:"regenerate,omitempty"`     // cap #6 — restore-from-signed-baseline
    // +kubebuilder:validation:Optional
    NodeRotate *NodeRotateAction `json:"nodeRotate,omitempty"`     // cap #7 — panic-move to clean node
}
```

### Controller topology

```
                              ┌──────────────── emitters (unchanged shape, additive payload) ────────────────┐
  Alertmanager ──webhook──▶ prometheus-integrator ─┐
  Falco ─────────────────▶ falco-integrator ───────┤  POST SecurityEvent{Targets,Rule,Description,
  KubeArmor ─────gRPC────▶ kubearmor-integrator ────┤        [+AnomalyScore,+Metrics,+Evidence]}
  timer ─────────────────▶ time-based-trigger ──────┘        (Rule.Type="timed"/"drift"/...)
                                                              │
                                                              ▼
                                   securityevent_controller (MODIFIED)
                                   · matcher reflect.DeepEqual L139  ──▶ (optional) ScoredRuleMatcher (cap #5, D21)
                                   · dispatch L197-372: + Rotate / + WarmSwap / + Regenerate / + NodeRotate branches
                                   · writes AMTD_APPLIED_SECURITY_EVENTS onto pod (L182-184)  ── unchanged signal
                                   · writes SecurityEventStatus (new audit)
                                                              │ pod annotation (existing cross-controller signal)
            ┌─────────────────────────────────────────────────┼───────────────────────────────────────────────┐
            ▼                                                  ▼                                                 ▼
   NIMReconciler (MODIFIED)                    InferenceRotation/WarmInferenceSet (NEW)            NodeRotationReconciler (NEW)
   · gate FindTimedEvent L121  ──▶ TriggerPredicate     · golden-image warm pool (LWS)             · cordon/taint/drain node
   · requeue L132  ──▶ Scheduler.Next (jitter)          · LeaderSwapper.Swap (cap #2)              · reschedule onto clean node
   · delete L168   ──▶ RotationStrategy.Rotate          · MutationApplier (caps #1,#3)             · coordinated via annotation lock
   · scope SetupWithManager L178-183 (inference pred.)  · GoldenImageVerifier (cap #6)               with NIM (avoid double-evict)
                                                        · writes Status (LastSwapDurationMillis…)

   BaselineDriftReconciler (NEW) + baselineAdmission webhook on :9443 (cap #6) verify-before-recreate at the delete sites.
```

**How the existing `nim_controller` evolves.** The recommendation across capabilities is to **extend `NIMReconciler` in place for the cadence + trigger + scope seams (caps #1, #4, #5)** and to **add sibling controllers for the heavier lifecycle (warm-pool/LWS #2, node rotation #7, drift webhook #6)**, keeping NIM as the deterministic-timer/cold-restart fallback so the one genuinely-working trigger path (`time-based-trigger`→`SecurityEvent`→NIM) does not regress. The three NIM seams:

1. **Delete site** `processPodWithNIM` L160–168 → delegate to `policy.Strategy.Rotate(...)`. Default `RotationStrategy` reproduces today's cold annotate-then-delete **exactly** (behavior unchanged when `InferenceRotation == nil`); opt-in strategies mutate the replacement / warm-swap. Wire the dangling `NIM_RESCHEDULE_COUNT` here.
2. **Trigger gate** L121 + `FindTimedEvent` L136–143 → `policy.Trigger` predicate (admits integrator-sourced / threshold events for "panic" rotation).
3. **Requeue** L131–132 → `Scheduler.Next(now, pod.UID, policy)` (jittered, per-pod staggered) and **scope** at `SetupWithManager` L178–183 (inference predicate so it stops reconciling **all** pods).

**Manager wiring (`cmd/main.go`).** Extend the NIM literal at L123–130 to inject `Strategy`/`Trigger`/`Scheduler`/`InferenceSelector` the same way it already injects `Policy: controller.DefaultNIMPolicy()` (L126). For each **new** controller (`WarmInferenceSetReconciler`, `NodeRotationReconciler`, `BaselineDriftReconciler`, and optionally `InferenceRotationReconciler`/`ContextMutationPolicyReconciler`), paste a registration block above the `//+kubebuilder:scaffold:builder` marker at **L131** mirroring the NIM block (each with its injected config struct), and register any new API types at the scheme marker **L53**. Register the `baselineAdmission` handler on the already-running webhook server (L80).

### Shared Go interfaces (used across capabilities)

```go
// PROPOSED — the cross-capability seams. Concrete impls live in new internal/controller files, not inline in Reconcile.

// cap #1/#3 — the pluggable rotation primitive. Default impl = today's cold annotate-then-delete.
type RotationStrategy interface {
    Rotate(ctx context.Context, pod *corev1.Pod, spec *amtdv1beta1.InferenceRotationSpec, ev *amtdv1beta1.SecurityEvent) (RotationResult, error)
}
// RotationResult{ Rotated bool; NewPodName string; MutationsApplied []string } -> Status/audit.

// cap #1/#3 — turns "byte-identical recreate" into a real mutation (image/env/gpu/memory).
type MutationApplier interface {
    Apply(podSpec *corev1.PodSpec, spec *amtdv1beta1.InferenceRotationSpec) (changed bool, err error)
}

// cap #4 — the SINGLE jittered cadence primitive replacing ALL deterministic timers.
type Scheduler interface { Next(now time.Time, key string, p RotationPolicy) (time.Time, error) }
type RandSource interface { Float64() float64; Int63n(n int64) int64; Read(b []byte) (int, error) } // crypto/rand in prod
type Clock interface { Now() time.Time }                                  // REUSE time-based-trigger pod_controller.go L61-63

// cap #1/#5 — broaden the gate beyond timer-only.
type TriggerPredicate func(ev amtdv1beta1.SecurityEvent, policy NIMPolicy) bool

// cap #5 — pluggable scoring brain (ADA §6.3.3: ML / OPA / behavioral are future work). Default = passthrough.
type AnomalyScorer interface { Score(ctx context.Context, pod *corev1.Pod, ev *amtdv1beta1.SecurityEvent) (float64, error) }
type CadenceFunction interface { Interval(score float64, p AdaptiveRotationPolicy) time.Duration; IsPanic(score float64, p AdaptiveRotationPolicy) bool }

// cap #2 — warm-pool + leader swap.
type WarmPoolManager interface { EnsurePool(ctx context.Context, pool *WarmInferenceSet) error; ReadyShadows(ctx context.Context, pool *WarmInferenceSet) ([]*corev1.Pod, error); CurrentLeader(ctx context.Context, pool *WarmInferenceSet) (*corev1.Pod, error) }
type LeaderSwapper   interface { Swap(ctx context.Context, pool *WarmInferenceSet, newLeader *corev1.Pod) (SwapResult, error) }
type TrafficSteerer  interface { CutTraffic(ctx context.Context, pool *WarmInferenceSet, from, to *corev1.Pod) error }
type ReadinessGate   interface { IsWarm(ctx context.Context, pod *corev1.Pod, gate *WarmReadyGate) (bool, error) }

// cap #3 — GPU rebind + per-container key lifecycle.
type GPUShuffler        interface { NextBinding(ctx context.Context, pod *corev1.Pod, prevDeviceUUID string, p GPUShufflePolicy) (resourcePatch corev1.ResourceRequirements, affinity *corev1.Affinity, chosenDeviceUUID string, err error) }
type EphemeralKeyManager interface { ProvisionKey(ctx context.Context, owner client.Object, p EphemeralMemoryPolicy) (keyID string, vol corev1.Volume, mount corev1.VolumeMount, err error); DestroyKey(ctx context.Context, keyID string) error }

// cap #6 — verify-before-recreate.
type BaselineVerifier interface { VerifyImage(ctx context.Context, ref string, pol SignaturePolicy) (VerifiedImage, error); ResolveDigest(ctx context.Context, ref string) (digest string, err error) }
type DriftDetector   interface { Detect(ctx context.Context, pod *corev1.Pod, b *BaselineSpec) ([]DriftResult, error) }
type BaselineRestorer interface { Regenerate(ctx context.Context, pod *corev1.Pod, b *BaselineSpec) error }

// cap #7 — node out-of-service + clean-node selection.
type NodeDrainer      interface { Cordon(ctx context.Context, nodeName string) error; Drain(ctx context.Context, nodeName string, p DrainPolicy) (evicted []string, err error); Uncordon(ctx context.Context, nodeName string) error; Taint(ctx context.Context, nodeName string, t corev1.Taint) error }
type CleanNodeSelector interface { SelectCleanNode(ctx context.Context, forPod *corev1.Pod, sel map[string]string, excludeNodes []string) (nodeName string, err error) }

// shared scope predicate — fixes NIM's all-pods watch.
func InferenceWorkloadPredicate(sel labels.Selector, imagePrefixes []string) predicate.Predicate
```

### Phasing & dependencies (build order)

The graph is a DAG rooted at the cadence/mutation seam. The verdicts repeatedly flag the **owner-template-mutation-survival fork** ([D3](#d3)) coupled with the **NIM-loop-re-mutates-every-10s hazard** ([D2](#d2)) as the single highest-risk pair — resolve those **before** any mutating implementation.

1. **Phase 0 — Foundations (prereq for everything).** Populate the empty `Status` structs (observed-state/audit). Add the **scope predicate** (cap #4 seam) so NIM stops reconciling all pods. Add the additive `SecurityEvent` fields (`+optional`). Decide [D1](#d1) (config home) and [D3](#d3) (how a mutation survives ReplicaSet recreate).
2. **Phase 1 — Cap #4 (jittered scheduling).** Lowest-risk, no new heavy deps; replaces the deterministic timers and supplies the cadence engine the rotation primitives requeue on. Includes the min-interval/idempotence guard ([D2](#d2)) that every later mutating cap relies on.
3. **Phase 2 — Cap #1 (mutating rotation core).** Introduce `RotationStrategy` + `MutationApplier` at the NIM delete site (default = cold path). This is the seam #2, #3, #6 plug into.
4. **Phase 3 — Cap #6 (signed-baseline drift).** Insert verify-before-recreate at the delete sites so rotation/self-heal pull from a verified digest, not tampered live state. Prereq for the "golden image" guarantee in #2.
5. **Phase 4 — Cap #2 (golden-image warm-pool).** New `WarmInferenceSet` controller + `LeaderSwapper`; delivers the `400s→15s` zero-downtime swap that makes frequent rotation affordable. Needs #6 (verified golden image) and #4 (cadence).
6. **Phase 5 — Cap #3 (GPU shuffle + encrypted memory + RAG sandbox).** Most hardware-specific/greenfield; rides the #1 delete seam + a `RotateAction` branch. Needs the device/crypto plane (see [D17–D23](#d17)).
7. **Phase 6 — Cap #5 (telemetry-driven adaptation).** Layer anomaly-weighted cadence + `ContextMutationPolicy` once the cadence engine (#4) and the mutation engine (#1/#3) exist. Requires the scoring brain decision ([D20](#d20)) and the matcher relaxation ([D21](#d21)).
8. **Phase 7 — Cap #7 (node rotation).** Heaviest new RBAC (node-write + eviction); add last, with the coordination lock against NIM and the trigger-authn guard ([D26](#d26)).

---

## Capabilities (detailed)

### 1. Inference-rotation core ("Adaptive NIM") [primary]

**What the papers specify.** *What moves:* the specific pods serving AI inference, and the replacement is **mutated**, not byte-identical. ADA **Listing 1** (`ada-amtd-ai-workloads.pdf` p.4) is the verbatim spec: a `ContextMutationPolicy`, `selector.matchLabels app: nim-inference`, applying three mutations to `containerName: nim` — (1) `ContainerImageUpdate newImage "nvcr.io/nim/secure-nim:latest"`; (2) `ResourceAdjustment resources.limits "nvidia.com/gpu": "0"` (+`requests cpu "500m" / memory "256Mi"`); (3) `EnvPatch RUNTIME_MODE=SECURE`. AMTD-AI §3.2 (p.2): *"Inference parameters (e.g., API key, endpoint path) are rotated."* Phoenix-for-AI Pillar 01 (p.3): *"Phoenix rotates the specific pods handling AI requests… the session context is invalidated. Broken session persistence for AI attackers."* *What triggers it:* a **dual model** — time/schedule (ADA "tracks instance age against rotationInterval", §3.3 step 2 p.6; AMTD-AI architecture diagram "Time Based Trigger" every 60min) **and** threat/telemetry (ADA §5.4 p.12 *"A compromised NIM instance is automatically replaced by ADA within the rotation interval"*; Phoenix-for-AI Pillar 03 p.4 *"triggers an immediate panic mutation"*). *Adaptation logic:* the paper frames NIM as **"Stateless by design / Ideal for rotation"** (ADA Fig.2, p.7 — *corrected citation*, not §2.4 p.3, which only says "making NIM instances ephemeral") and ephemeral memory *"rotated and re-keyed on every inference cycle"* (ADA §5.6.1 p.13). The papers give **no rotation algorithm** beyond "swap leader for warm worker" + "rotate API key/endpoint" + "swap image"; everything quantitative is asserted, never measured.

**Threat model.** Counters attacker **persistence / dwell on the inference plane**: a foothold inside a long-lived NIM/vLLM pod (ADA Table 1 p.13 "Pod Escalation"; AMTD-AI §3.1 "restarts wipe in-memory footholds"), session/replay persistence (Phoenix-for-AI Pillar 01), model theft / LLM-Jacking (Phoenix-for-AI Pillar 02), and supply-chain re-introduction (AMTD-AI §3.1 signed golden image; ADA §5.3.4). **The verified gap (`spec-map.md` L177/L191):** today's replacement is **byte-identical**, so *"compromised NIM replaced within the rotation interval"* currently means only *"replaced at the next tick with the SAME image/endpoint/key"* — none of the persistence-severing semantics are delivered.

**How it extends `phoenix-main`.**

| CRD | Field | Go type | Semantics | Default / DECISION |
|-----|-------|---------|-----------|--------------------|
| `AMTDSpec` | `InferenceRotation` | `*InferenceRotationSpec` | Opt-in container for all inference-rotation tuning; nil → legacy cold path | absent → legacy; **DECISION** home: AMTD-embedded vs standalone ([D1](#d1)) |
| `InferenceRotationSpec` | `GoldenImage` | `string` | Image rotated **to** (ADA `ContainerImageUpdate.newImage`) | **DECISION** tag vs digest ([D6](#d6)); do not default `:latest` |
| `InferenceRotationSpec` | `ContainerName` | `string` | Which container to mutate (ADA `containerName: nim`) | **DECISION** first-vs-explicit-vs-well-known ([D6](#d6)) |
| `InferenceRotationSpec` | `EnvPatch` | `[]corev1.EnvVar` | Env to set on rotated container (ADA `EnvPatch`) | `RUNTIME_MODE=SECURE` as documented example, not a hard default |
| `InferenceRotationSpec` | `GPUResource` | `*resource.Quantity` | `nvidia.com/gpu` override (ADA `ResourceAdjustment`, literal `"0"`) | **DECISION** serve-vs-quarantine semantics ([D18](#d18)); detail deferred to cap #3 |
| `InferenceRotationSpec` | `RotationParameters` | `*InferenceParamRotation` | Which inference params rotate + where they live | **DECISION (large)** entire key/endpoint mechanism ([D8](#d8)) |
| `AMTDStatus` | `LastRotationTime`/`RotationCount`/`Conditions` | as sketched | Observed-state + audit; also persist count onto pod via `NIM_RESCHEDULE_COUNT` | Proposed: write on each rotation; **DECISION** granularity ([D23](#d23)) |
| `SecurityEventSpec` | `AnomalyScore` | `*string` | Threat-reactive trigger magnitude (cap #5 seam) | **DECISION** numeric vs `ThreatLevel` vs `Source` ([D19](#d19)) |

**New CRD types.** `InferenceRotationSpec` (embedded, the single read-point that replaces `DefaultNIMPolicy()`), `InferenceParamRotation` (type-shape placeholder for key/endpoint rotation — mechanism is a DECISION), and **optional alternatives** `RotateAction` (an `AMTDAction` variant filling the L370–372 slot) or a standalone `InferenceRotationPolicy` CRD mirroring ADA's separate kind. These last two are mutually-exclusive wiring choices ([D2](#d2)).

**Controllers affected.** `NIMReconciler` **modified** (core); `AdaptiveMovingTargetDefenseReconciler` **modified** (validate/propagate the block; optionally `Watches/Owns` Pods so new inference pods enroll immediately rather than after the 10s requeue L196); `SecurityEventReconciler` **modified** only if `RotateAction` or score-matching is adopted; `InferenceRotationReconciler` **new** only if the standalone-CRD design wins.

**Relation to `nim_controller` (explicit).** **Extend in place.** (1) At the delete site `processPodWithNIM` — the two lines `r.Update(ctx, pod)` **L160** and `r.Delete(ctx, pod, deleteOpts)` **L168** — delegate to `policy.Strategy.Rotate(...)`; default `RotationStrategy` reproduces today's behavior exactly. Wire the dangling `NIM_RESCHEDULE_COUNT` (`nim_constants.go` L31) here. (2) At the gate **L121** + `FindTimedEvent` **L136–143**, swap the fixed `Type/Source` equality for `policy.Trigger`. (3) At `SetupWithManager` **L178–183**, add the inference-scope predicate. (4) Add the Status write-back. Keep `DefaultNIMPolicy()`'s 30s/10s as `effective()` fallbacks (**L62–77**). The `MutationApplier`/`InferenceParamRotator` logic lives in a new file, not inline in `Reconcile`.

**Interfaces & integration.** `RotationStrategy`, `MutationApplier`, `InferenceParamRotator`, `TriggerPredicate`, extended `NIMPolicy{ Strategy; Trigger; InferenceSelector }`, `InferenceWorkloadPredicate` (see shared interfaces). **Manager wiring:** extend the `cmd/main.go` L123–130 NIM literal (e.g. `Policy: controller.InferenceRotationPolicy()`). **RBAC additions** above `NIMReconciler.Reconcile` (current markers L86–88 grant pods + pods/status get + amtd get;list;watch — **none** of the below exist today): `amtd …/status update` (write rotation Status); per mechanism `core secrets …` (API-key rotation), `core services …` + `networking.k8s.io ingresses …` (endpoint cutover), `apps deployments/replicasets get;list;watch;update;patch` (if mutating the **owner template** rather than the pod — see [D3](#d3)); then `make manifests`. **External deps:** cosign/sigstore (cap #6), NVIDIA device-plugin/MIG (cap #3), LWS/Kueue (cap #2) — all referenced, owned by siblings.

> **Critical integration constraint ([D3](#d3)).** Deletion lets the **owner** recreate from its **existing** template, so mutating `pod.Spec` in place is **lost** on recreate. To make image/env/gpu mutation stick on a Deployment-managed NIM, the applier must patch the owning controller's `PodTemplateSpec`, **or** the rotation must create-new-then-cutover (warm swap, cap #2). This is the single biggest design fork.

**Proof it works.**

| Metric | How measured | Target |
|--------|--------------|--------|
| Mutation actually applied | Deploy `app:nim-inference` with image A; fire one rotation; assert recreated/cut-over pod runs `goldenImage`/digest + `RUNTIME_MODE=SECURE` + adjusted GPU; assert `NIM_RESCHEDULE_COUNT` increments and `AMTDStatus` updates | 100% of rotations apply the declared mutation; replacement image ≠ prior when `goldenImage` set |
| Rotation/restart downtime | Steady traffic at the Service; measure zero-success gap (or p99 spike) around a rotation; cold vs warm | AMTD-AI §5.1 claims `~400s → ~15s` (warm). **USER DECISION** — paper gives no method; set real SLO at impl ([D27](#d27)) |
| Attacker dwell on inference plane | Plant foothold; measure plant→eviction; verify threat-triggered = immediate, not next-tick | AMTD-AI `150+ days → <60 min` / `R=60min`; ADA "within the rotation interval". **USER DECISION** ([D27](#d27)) |
| Persistence Success Rate | Run foothold scenario N× with/without mutating rotation | AMTD-AI `95%+ → <4%`. **USER DECISION** — asserted, unmeasured ([D27](#d27)) |
| Runtime/serving overhead | Throughput + p50/p99 with rotation on vs off; warm-pool cost | Papers assert `1–2%`. **USER DECISION** — must be instrumented ([D27](#d27)) |
| MTTR on threat (panic latency) | High-severity event → replacement Ready | AMTD-AI `MTTR < 5 min`. **USER DECISION** ([D27](#d27)) |

**Open questions (your decision).** [D1](#d1) config home; [D2](#d2) NIM-loop vs `RotateAction`; [D3](#d3) owner-template mutation survival; [D6](#d6) image tag-vs-digest + container-name default; [D8](#d8) key/endpoint rotation mechanism; [D9](#d9) interval; [D18](#d18) GPU=0 serve-vs-quarantine; [D19](#d19) `ThreatLevel`/`AnomalyScore` threshold; [D22](#d22) rotation-storm/unhealthy-replacement guard; [D23](#d23) Status granularity; stateful-inference drain (KV-cache/in-flight) — see [D5 group](#d5).

---

### 2. Golden-image + warm-pool (Leader-Worker-Set) zero-downtime swap [primary]

**What the papers specify.** *What moves:* the active inference **leader**. AMTD-AI §3.2 (p.2): *"Leader container is swapped with a worker (ready in RAM) using LWS."* *The four components* (§3.1, p.2, verbatim): **Golden Image Repository** *"Immutable, signed copies of containerized workloads (NIMs, etc.)"*; **Leader-Worker Sets (LWS)** *"A small set of warm-started containers (≥1), with one active leader and N−1 shadow workers"*; **Inference Load Balancer** *"Routes traffic to active leader based on health and schedule"*; **Rotation Controller** *"Triggers restart or replacement on schedule (+ jitter)."* *What triggers it:* "on schedule (+ jitter)" — §3.2 `R = 60 minutes ± jitter (10–30%)`; the §5 panel also adds telemetry triggers. *Adaptation logic:* a warm shadow (already "ready in RAM") is promoted, the LB redirects, and *"Inference parameters … are rotated"* (§3.2). *The headline result* (§5.1, p.6, verbatim): *"By pre-caching golden images in memory and redirecting inference traffic via LWS, restart downtime drops from ~400s to ~15s."* Cross-paper caveats it explicitly concedes: ADA **§5.5 p.12** frames NIM as ideal for **stateless** inference (*corrected citation* — the "Stateless by design / Ideal for rotation" phrasing is ADA Fig.2/§5.5, **not** §2.4 p.3); ADA §6.2 (p.13) flags *"Stateful Applications: The main challenge requiring complex state migration strategies"* and *"Ultra-Fast Attacks: May not prevent the initial 'smash and grab.'"* The paper gives **no** algorithm for shadow selection/promotion, LB reconfiguration primitive, the operational meaning of "warm", pool size N, signature trust root, or in-flight drain.

**Threat model.** Counters **persistence of a memory-resident foothold** + **C2/dwell that depends on a stable endpoint** (AMTD-AI p.5 *"Persistence becomes difficult when containers are forcibly restarted from golden state"*, *"C2 channels get dropped regularly with identity rotation"*; Performance table `Persistence 95%+ → <4%`, `Dwell 150+ days → <60 mins`). The golden-image leg additionally counters **supply-chain persistence** (AMTD-AI p.5 *"signed, verifiable images and immutable baselines"*; ADA §5.3.4). The **distinctive** contribution vs a plain cold restart is **availability under eviction**: the warm pool makes eviction near-zero-downtime so defenders can rotate **frequently** (small `R`) without an availability penalty. New threat the pool introduces: a compromise landing in a **shadow** or in the **golden image** is promoted into the leader slot → golden-image signature verification + per-worker re-keying are load-bearing.

**How it extends `phoenix-main`.**

| CRD | Field | Go type | Semantics | Default / DECISION |
|-----|-------|---------|-----------|--------------------|
| `AMTDSpec` | `WarmPool` | `*WarmPoolSpec` | Opts workload into LWS warm-swap instead of cold delete | nil → cold path; **DECISION** AMTDSpec vs new `WarmInferenceSet` CRD vs `WarmSwapAction` ([D11](#d11)) |
| `WarmPoolSpec` | `Replicas` | `int32` (`Minimum=1`) | N = 1 leader + N−1 shadows (§3.1) | **Proposed default `2`** (flag — GPU VRAM scales with N) ([D11](#d11)) |
| `WarmPoolSpec` | `GoldenImage` | `string` | Immutable signed image for warm workers (§3.1) | **DECISION** digest-pin syntax + signature point ([D6](#d6)); paper says only "signed" — do **not** hard-require a `@sha256:` regex |
| `WarmPoolSpec` | `TrafficCutStrategy` | `string` enum | How the LB is re-pointed leader→shadow | enum `EndpointSwap;ServiceSelectorSwap;GatewayWeight;LeaderLabel` is **design-authored** (paper names no primitive); **DECISION** ([D12](#d12)) |
| `WarmPoolSpec` | `DrainTimeoutSeconds` | `*int64` | Grace after traffic cut before retiring old leader | **Proposed** reuse NIM grace 30s; **DECISION** ([D5 group](#d5)) |
| `WarmPoolSpec` | `ReadyGate` | `*WarmReadyGate{Probe;MinWarmSeconds;RequireModelLoaded}` | Defines when a shadow is **promotable** ("ready in RAM") | **DECISION (top correctness risk)** what "warm" means ([D11](#d11)) |
| `WarmPoolSpec` | `RotateInferenceParams` | `*InferenceParamRotation` | Rotate API key / endpoint path each swap (§3.2) | **Proposed default out-of-scope here**, stub the field ([D8](#d8)) |
| `AMTDStatus` | `WarmPoolStatus` | `{ActiveLeader;ReadyShadows;LastSwapTime;LastSwapDurationMillis;Conditions}` | Makes `400s→15s` **measurable**; audit | Proposed: add |

**New CRD types.** `WarmInferenceSet` (recommended, namespaced — owns N warm pods + a leader-selecting Service; may wrap upstream `sigs.k8s.io/lws`); embedded `WarmPoolSpec`/`WarmReadyGate`/`InferenceParamRotation`; optional `WarmSwapAction` (`AMTDAction` member). **Regenerate `zz_generated.deepcopy.go` (`make generate`) for ALL new embedded types, not only the Action variant.**

**Controllers affected.** `WarmInferenceSetReconciler` **new** (reconciles N warm pods + leader Service, evaluates `ReadyGate`, writes Status; `Owns(Pod)`+`Owns(Service)`); `InferenceRotationReconciler` **new** (invokes `LeaderSwapper.Swap` on trigger — where `400s→15s` lives); `NIMReconciler` **modified or intact** (recommended: left as cold fallback when no pool applies; finally writes `NIM_RESCHEDULE_COUNT` as the swap counter); `SecurityEventReconciler` **modified** only if `WarmSwapAction` is chosen (add `else if action.WarmSwap != nil` at L370–372); enroller **unchanged**.

**Relation to `nim_controller` (explicit).** Best as a **new reconciler alongside** NIM that takes over rotation **execution**, but it explicitly **relocates one line**: the cold `r.Delete` at **L168** (opts L164–166) becomes `LeaderSwapper.Swap` (cut traffic to a pre-warmed shadow → drain `DrainTimeoutSeconds` → retire old leader → `WarmPoolManager.EnsurePool` re-warms from the golden image). The pod-level trigger plumbing (read `AMTD_APPLIED_SECURITY_EVENTS` L105, `FindTimedEvent` L121) is reused as-is. `NIMPolicy` (L45–50) is wrapped by a `WarmPoolPolicy` mapping `GracePeriodSeconds → DrainTimeoutSeconds` and reusing the existing `client.DeleteOptions.GracePeriodSeconds` plumbing (L164–166).

**Interfaces & integration.** `WarmPoolManager`, `LeaderSwapper`, `TrafficSteerer`, `GoldenImageVerifier`, `ReadinessGate`, `RotationTrigger` (see shared interfaces). **RBAC** (superset of NIM's L86–88): `core pods get;list;watch;create;update;patch;delete` + `pods/status`; `core services …` + `discovery.k8s.io endpointslices …` (Endpoint/Selector swap); `gateway.networking.k8s.io httproutes update` (GatewayWeight); `amtd adaptivemovingtargetdefenses` + new `warminferencesets` (+`/status`,`/finalizers`); `core secrets get` (key rotation if in scope); `make manifests`. **External deps:** `sigs.k8s.io/lws` **or** in-tree pool ([D11](#d11)); cosign/sigstore for golden-image verify ([D6](#d6)); golden registry (e.g. `nvcr.io`) + GPU sizing for N shadows. **Integrators:** no change for a schedule-driven swap.

> **Gang-scheduling / GPU co-residency:** if N shadows cannot be co-scheduled on scarce GPUs, "warm" is unachievable; the destination/pool must have free GPUs of the right type/MIG profile. Ties to cap #3.

**Proof it works.**

| Metric | How measured | Target |
|--------|--------------|--------|
| Warm-swap downtime / added latency | Constant QPS; measure failed/queued-request gap + p50/p99 across the leader cut; record `Status.LastSwapDurationMillis` | `~15s` (mostly `<5s`) warm vs `~400s` cold on identical HW (AMTD-AI §5.1 p.6 / p.5 table). PROVES capability if warm ≪ cold |
| Zero dropped requests during swap | Count non-2xx / resets in cut+drain window, varying `DrainTimeoutSeconds` | 0 dropped at chosen drain window. **USER DECISION** floor ([D5 group](#d5)) |
| Persistence eviction across swap | Plant RAM-resident marker in leader; swap; verify promoted leader + golden replacement lack it | `Persistence → <4%` (p.5) |
| Golden-image integrity gate | Bring a warm/replacement worker from unsigned/tampered image; confirm `GoldenImageVerifier` blocks + swap fails safe | 100% rejection. **USER DECISION** trust root ([D6](#d6)) |
| Frequent-rotation availability | Rotate at small `R` under load; aggregate availability | `~99.8%` (Proactive Abstract). **USER DECISION** — marketing figure, no measurement code ([D27](#d27)) |
| Steady-state warm-pool overhead | GPU VRAM/CPU/mem/cost with N shadows vs single replica | `~1.3–1.7%` (Proactive §V). **USER DECISION** — unmeasured, N-dependent ([D27](#d27)) |

**Open questions (your decision).** [D11](#d11) "warm" definition + pool size N + LWS-vs-in-tree + config home; [D12](#d12) traffic-steering primitive; [D6](#d6) golden-image trust root; [D5 group](#d5) trigger scope, in-flight drain, stateful-session handling, mid-swap rollback.

---

### 3. GPU-aware micro-shuffle + encrypted ephemeral memory / RAG sandbox [primary]

**What the papers specify.** Three coupled mechanisms applied at the rotation moment. (1) **GPU-Aware Micro-Shuffling** (Proactive **§IV.C.1**, p.3): *"Dynamically reassigns GPU bindings, including MIG (Multi-Instance GPU) slices or NVLink interconnect mappings. This prevents side-channel persistence by ensuring attackers cannot rely on fixed GPU memory layouts."* (2) **Encrypted Ephemeral Memory Spaces** (Proactive **§IV.C item 5**, p.3 — *corrected citation*: this is item 5 under **§IV.C "Novel Elements for AI-Inference-Aware AMTD"**, **not** §IV.B "System Architecture", which lists only four components): *"Each inference container mounts disposable encrypted memory volumes with unique, random keys. Keys are destroyed at container termination, eliminating opportunities for memory-resident model theft."* (3) **Runtime RAG Sandbox** (ADA §5.6.1, p.13): *"Retrieval-Augmented Generation (RAG) components run in isolated pods with limited time-bound data exposure"*, and *"Stateful agent memory is written to encrypted ephemeral volumes, which are rotated and re-keyed on every inference cycle."* ADA §2.6.1 (p.4) lists the primitives *"Adjusting access to specialized resources (e.g., GPUs or ephemeral volumes)"* and *"Modifying runtime environments (e.g., switching from Python to CUDA contexts)."* **Honest caveat the design itself surfaces:** the **only verbatim GPU manifest** in the corpus is ADA Listing 1's `nvidia.com/gpu: "0"` — a **quota DROP**, not a reassignment to a specific different device; the §IV.C.1 "reassign MIG/NVLink" prose is never reduced to a manifest and is **not expressible with stock K8s scheduling** (the default device plugin advertises a count, not per-UUID schedulability).

**Threat model.** Counters the **side-channel / memory-residency / co-location** stages (Proactive **§III**, p.2 — *corrected page*: §III Threat Model is p.2). Adversary goals (§III.B): *"Model Extraction"*, *"Data Exfiltration"*. Vectors: **§III.C.2** *"Model Theft via Side-channel Attacks: … query-based or timing side-channel analysis"* (countered by GPU shuffling denying a fixed memory layout); **§III.C.4** *"Adversarial Workload Co-location: … shared memory, cache timing, or PCIe bus vulnerabilities"* (countered by re-shuffling topology + per-container ephemeral encryption). The encrypted ephemeral memory denies *"memory-resident model theft"* (§IV.C item 5) and persistence (key destroyed at termination). The RAG sandbox bounds the data window an injected prompt can persist into. Preventive, **not** a detector (ADA §6.2 "clean up afterward"). **Caveat to pin down ([D23 group](#d23)):** software tmpfs + K8s Secrets do **not** protect against a root/host or hypervisor-level co-resident adversary; only hardware Confidential Computing / TEEs do, which ADA §6.3.4 **defers**.

**How it extends `phoenix-main`.**

| CRD | Field | Go type | Semantics | Default / DECISION |
|-----|-------|---------|-----------|--------------------|
| `AMTDSpec`/`InferenceRotationSpec` | `gpuShuffle` | `*GPUShufflePolicy` | Opt-in GPU-Aware Micro-Shuffling on rotation | nil → no shuffle; **DECISION** home + mode ([D1](#d1),[D17](#d17)) |
| `GPUShufflePolicy` | `resourceName` | `string` | Extended-resource key shuffled | default `nvidia.com/gpu` (ADA Listing 1 verbatim); **DECISION** MIG/time-slice names ([D17](#d17)) |
| `GPUShufflePolicy` | `mode` | `string` enum `Reassign;DropToZero;Anti-Affinity` | Reassign=distinct device; DropToZero=ADA Listing 1; Anti-Affinity=scheduler avoidance | **DECISION** — corpus contradicts itself ([D17](#d17)); `DropToZero` is the only verbatim-supported behavior |
| `GPUShufflePolicy` | `requireDistinctBinding` | `bool` | Replacement must bind a different device UUID | **DECISION** hard-required vs best-effort + single-GPU fallback ([D17](#d17)) |
| `AMTDSpec`/`InferenceRotationSpec` | `ephemeralMemory` | `*EphemeralMemoryPolicy` | Per-container freshly-keyed encrypted scratch volume | nil → none; greenfield ([D1](#d1)) |
| `EphemeralMemoryPolicy` | `sizeLimit` | `resource.Quantity` | Disposable volume size | **DECISION** — no paper number ([D17 group](#d17)) |
| `EphemeralMemoryPolicy` | `medium` | `string` enum `Memory;Disk` | tmpfs vs CSI at-rest-encrypted | **Proposed Memory**; **DECISION** — "encrypted memory" is ambiguous (tmpfs ≠ cryptographic) ([D19g](#d19g)) |
| `EphemeralMemoryPolicy` | `rekeyOn` | `string` enum `Rotation;InferenceCycle` | Re-key per rotation vs per ADA "inference cycle" | **DECISION (load-bearing)** — a pod-operator has no notion of an inference cycle ([D21g](#d21g)) |
| `EphemeralMemoryPolicy` | `keySource` | `*KeySourceRef` | Where the key comes from / how destroyed | **DECISION** — paper names no keystore/cipher/length/trust-root ([D20g](#d20g)) |
| `AMTDSpec`/`InferenceRotationSpec` | `ragSandbox` | `*RAGSandboxPolicy` | Isolate RAG pods, bounded data TTL | nil → none; greenfield ([D24g](#d24g)) |
| `RAGSandboxPolicy` | `dataExposureTTL` | `metav1.Duration` | Max RAG sandbox lifetime | **DECISION** — no value in paper ([D24g](#d24g)) |
| `AMTDAction` | `Rotate` | `*RotateAction` | Mutating rotation (GPU/memory/RAG/image/env) replacing cold `Delete` | respects `MaxProperties=1`; **DECISION** timer vs threat vs both ([D2](#d2)) |
| `SecurityEventStatus`/`AMTDStatus` | `lastGPUUUID`/`lastKeyID`/`rekeyCount` | as sketched | Audit; tracks distinctness + finally writes `NIM_RESCHEDULE_COUNT` | Proposed: populate ([D23](#d23)) |

**New CRD types.** `GPUShufflePolicy`, `EphemeralMemoryPolicy`, `KeySourceRef{Type enum(GeneratedSecret,KMS,Vault,TEESealed); …; CipherSuite string; KeyBytes int}` (no invented cipher/length), `RAGSandboxPolicy`, `RotateAction`; **optional** standalone `ContextMutationPolicy` (verbatim ADA Listing 1, group `ADA.security.r6.dev/v1` — see cap #5 / [D7g](#d7g)).

**Controllers affected.** `NIMReconciler` **modified** (mutate owner template before `r.Delete` L168; record `nim.r6security.com/gpu-uuid`; add inference predicate at L178–183); `SecurityEventReconciler` **modified** (add `else if action.Rotate != nil` branch invoking `MutationApplier`+`EphemeralKeyManager`+`GPUShuffler`; realizes the L195 TODO "replace with Action interface"); `AdaptiveMovingTargetDefenseReconciler` **modified** (watch Pods so RAG-sandbox/Secret objects provision promptly); `InferenceRotationReconciler` **new** (optional, owns key-Secret lifecycle finalizer for `DestroyKey`); dead `PodReconciler` **untouched**.

**Relation to `nim_controller` (explicit).** Extend NIM at its delete site **and** add the same mutation behind the new `RotateAction` branch; do **not** replace NIM. The mutation must patch the **owning template** (so the recreated pod carries it — [D3](#d3)) immediately before `r.Delete` at **L168**. `NIMPolicy` gains `GPUShuffler`/`EphemeralKeyManager` fields via the `DefaultNIMPolicy()`/`effective()`/`cmd/main.go` L126 injection pattern. The timer gate `FindTimedEvent` (L121,L136–143) stays for the timer path; the telemetry path is the new `RotateAction` (L197 chain). **One `RotationMutator` is shared by both paths** so timer- and anomaly-driven rotations apply identical GPU/re-key logic (papers' dual-trigger, §IV.D step 3). This capability is what would make NIM actually inference/GPU-aware.

**Interfaces & integration.** `RotationMutator`, `GPUShuffler`, `EphemeralKeyManager`, `InferenceWorkloadPredicate`, `MutationPolicy` resolver, `RAGSandboxProvisioner` (mirrors the existing Quarantine deny-all `NetworkPolicy` at L285–348). **RBAC:** `core secrets create;get;list;watch;delete` (ephemeral keys + destruction); scheduler affinity in lieu of `pods/binding`; `storage.k8s.io` + CSI resources if encrypted volume via CSI; `networking.k8s.io networkpolicies create` (RAG sandbox, same grant Quarantine already needs at L48–51); `apps deployments/replicasets …` (mutate owner template). No GPU-specific RBAC unless reading NVIDIA device-plugin CRs. **External deps (device plane):** NVIDIA k8s-device-plugin / GPU Operator + (for true distinct-GPU) GPU Feature Discovery / dynamic MIG — NVLink-topology placement has **no standard K8s primitive**. **(crypto/storage plane):** CSI-encrypting driver or LUKS/dm-crypt init container; key backend (Secret / KMS / TEE); optional gVisor/Kata as the "short-lived capsule" runtime. All UNSPECIFIED by the papers.

> **Implementation hazards (inside already-flagged decisions):** the destruction-race — the pod the operator **deletes** to trigger rotation must not also trigger `DestroyKey` before the foreign-controller-recreated replacement gets its key; and closing the distinct-binding loop requires **watching the replacement pod's post-schedule node/UUID** (the operator deletes before a foreign controller reschedules).

**Proof it works.**

| Metric | How measured | Target |
|--------|--------------|--------|
| GPU-binding distinctness | Over N rotations record bound device UUID (`nim.r6security.com/gpu-uuid` / DCGM); verify consecutive differ (or quota 0 in DropToZero) | **USER DECISION** — no paper number; proposed 100% distinct when >1 GPU schedulable ([D17](#d17)) |
| Ephemeral key freshness + destruction | Assert new `keyID` per rotation (no reuse); Secret/KMS key gone after termination; co-resident probe cannot read prior plaintext | **USER DECISION** — proposed 0 reuse, 0 readable plaintext, key TTL < grace 30s ([D20g](#d20g)) |
| Re-key cadence vs inference cycle | Count re-keys per request (`InferenceCycle`) or per rotation (`Rotation`) | **USER DECISION** — depends on `rekeyOn`; paper implies per-cycle, pod-operator can't observe cycles ([D21g](#d21g)) |
| Model-extraction / side-channel ASR | Red-team co-resident scrape/timing vs static; measure successful extractions | **USER DECISION** — corpus gives only aggregate marketing figures (ASR `<10%`/94% disruption), not GPU-shuffle-specific ([D27](#d27)) |
| Availability during rotation (overhead) | Endpoint availability + added latency/cost of rebind+re-key+volume re-provision | **USER DECISION** — GPU-rebind without warm pool likely **increases** downtime (cold re-attach) ([D27](#d27)) |
| Inference-scope correctness | After adding `InferenceWorkloadPredicate`, count non-inference pods mutated | Proposed 0 (correctness invariant, no paper number) |

**Open questions (your decision).** [D17](#d17) GPU shuffle semantics + granularity + distinct-binding; [D18](#d18) GPU=0 serve-vs-quarantine; [D19g](#d19g) what "encrypted" means; [D20g](#d20g) key management trust root + destruction; [D21g](#d21g) "inference cycle" → K8s mapping; [D2](#d2) timer vs threat trigger; [D23g](#d23g) privileged-vs-unprivileged co-resident threat model; [D24g](#d24g) RAG isolation + TTL; ephemeral-model-wrappers scope; [D27](#d27) benchmark targets.

---

### 4. Randomized / jittered rotation scheduling + endpoint TTL [primary]

**What the papers specify.** The **timing layer only**: it makes the cadence non-deterministic and gives rotated endpoints a hash-based TTL; it does **not** perform rotation work (that is #1/#2/#3). *What moves (timing):* AMTD-AI §3.2 (p.2): `Default Rotation Interval R = 60 minutes ± jitter (10–30%)`; §3.1: *"Rotation Controller: Triggers restart or replacement on schedule (+ jitter)."* *What moves (endpoint):* §3.2 *"Inference parameters (e.g., API key, endpoint path) are rotated"*; **§5 (p.6)** *"Randomized endpoint URLs with hash-based TTL"* (*corrected citation* — this phrase is §5, not §3.2); **§5.3 (p.8)** *"Custom TTL for model services"*. *The load-bearing theory:* PHOENIX **§III** "Von Neumann's Minimax": the defender must *"adopt a mixed strategy — a probability distribution over all possible actions"* to *"minimize the maximum possible payoff the attacker can achieve"*, so that *"any information the attacker gains from reconnaissance is immediately invalidated … forcing them to guess at every step"* and *"unpredictability is the foundation of optimal defense."* *The optimization direction:* AMTD-AI "Mathematical Model of Exposure" (p.2): `Expected ASR ∝ ∫₀ᴿ A(t) dt`, *"minimized by { Reducing R; Increasing decay rate of A(t) (higher entropy) }"* — pins direction (smaller R + higher entropy), **not** a distribution shape, RNG source, hash function, TTL, or stagger algorithm. *Staggering:* Proactive **§V.A Experimental Setup** (p.3) *"Staggered rotation to avoid simultaneous restarts"* (*corrected citation* — §V.A, not §IV.B; §IV.B's verbatim is "new container IDs, ephemeral node assignments, shuffled port mappings"). **None** of: the precise jitter distribution, the entropy source, the hash function/key, the TTL value, or the per-pod phase offset is pinned by any paper.

**Threat model.** Denies the attacker a **predictable clock**. (1) Reconnaissance → repeatable exploit: a deterministic timer (exactly today's `cron.Next` / `duration.Add` / fixed 10s) is itself reconnaissable; jitter means *"any information … is immediately invalidated"* (PHOENIX §III). (2) Persistence/dwell within a window: `ASR ∝ ∫₀ᴿ A(t)dt`, minimized by smaller/unpredictable R. (3) Thundering-herd self-DoS: simultaneous deterministic rotation is both a predictable blackout window and a self-inflicted outage; staggering defends availability (Proactive §V.A). (4) Endpoint enumeration: a captured path/key is useless after its TTL.

**How it extends `phoenix-main`.** (Cadence fields live in the shared `RotationPolicy` block sketched in [Unified architecture](#consolidated-crd-changes).)

| CRD | Field | Go type | Semantics | Default / DECISION |
|-----|-------|---------|-----------|--------------------|
| `AMTDSpec`/`InferenceRotationSpec` | `Rotation` | `*RotationPolicy` | Opt-in container for cadence knobs; nil → deterministic | nil → unchanged; **DECISION** AMTDSpec vs `RotationSchedule` CRD vs pod-annotation ([D1](#d1)) |
| `RotationPolicy` | `BaseInterval` | `metav1.Duration` | R when score 0 | **Proposed `60m`** (AMTD-AI §3.2); **DECISION** — papers conflict (60m / 20–30m / 30s demo) + hard floor ([D9](#d9)) |
| `RotationPolicy` | `JitterPercent` | `int` (0–100) | `I = base·(1 ± U(0,JitterPercent/100))` | **Proposed `20`** (midpoint of paper's **10–30% band**, not a paper value); **DECISION** single-vs-band, symmetric-vs-one-sided ([D10](#d10)) |
| `RotationPolicy` | `JitterDistribution` | `string` enum `Uniform;TruncatedNormal` | Shape of the mixed-strategy clock | **Proposed `Uniform`** (max entropy for bounded interval); **DECISION** ([D12g](#d12g)) |
| `RotationPolicy` | `EntropySource` | `string` enum `Crypto;PseudoRandom` | crypto/rand vs seedable math/rand | **Proposed `Crypto`** — a leaked seed lets an attacker predict every rotation; **DECISION** ([D13](#d13)) |
| `RotationPolicy` | `StaggerMode` | `string` enum `PerPodPhaseOffset;Independent;None` | De-sync a fleet ("avoid simultaneous restarts") | **Proposed `PerPodPhaseOffset`** = `hash(podUID) mod base` (design-authored formula); **DECISION** ([D14](#d14)) |
| `RotationPolicy` | `Endpoint` | `*EndpointRotationPolicy{TTL;JitterTTL;PathTemplate;HashAlgorithm;KeySecretRef}` | Hash-based endpoint TTL (§5/§5.3); owns TTL+derivation, cutover is #1 | nil → off; **DECISION** TTL value + hash/unforgeability ([D8](#d8),[D15](#d15),[D16](#d16)) |
| `AMTDStatus` | `NextRotationTime`/`LastRotationTime`/`CurrentEndpointHash`/`ObservedRotationCount` | as sketched | Observed cadence + restart-safety | **SECURITY DECISION** — publishing `NextRotationTime` re-exposes what jitter hides ([D5](#d5)) |

**New CRD types.** `RotationPolicy` + `EndpointRotationPolicy` (embedded); optional standalone `RotationSchedule` CRD (decouples timing from rule→action, replaces the **insecure** `/schedule` pod annotation the `time-based-trigger` code itself flags at `pod_controller.go` L138–142 as requiring patch-any-pod RBAC).

**Controllers affected.** `NIMReconciler` **modified** (replace fixed requeue L131–132 with `Scheduler.Next(now, pod.UID, policy)`; source cadence from `AMTDSpec.Rotation` when present, resolved via `AMTD_MANAGED_BY`, else `DefaultNIMPolicy`; wire `NIM_RESCHEDULE_COUNT`; add `…/status` RBAC if writing); `TimeBasedTrigger PodReconciler` **modified** (wrap `nextRun`/`nextReconcile` L150/L172/L176 or `SchedulableDuration.Next` L69 with the shared `Jitterer`; read jitter from the new CRD field, inject shared `RandSource` + reuse `Clock` L61); `AdaptiveMovingTargetDefenseReconciler` **modified, minor** (validate/default `RotationPolicy`, populate Status; optionally jitter its own 10s requeue L196); `SecurityEventReconciler` **unchanged**; `RotationScheduleReconciler` **new** only if the standalone CRD is chosen (either/or with extending NIM).

**Relation to `nim_controller` (explicit).** **Extend in place; surgical, timing-only.** The single behavioral change is `nim_controller.go` **L131–132** `return ctrl.Result{RequeueAfter: policy.RequeueAfter}` → `next, _ := r.Scheduler.Next(r.Clock.Now(), string(pod.UID), rotationPolicy); return ctrl.Result{RequeueAfter: next.Sub(r.Clock.Now())}, nil`. `processPodWithNIM` (L145–175) and `FindTimedEvent` (L121,L136–143) are **untouched** — jitter governs **when** rotation fires, not what it does. `RotationPolicy.effective()` mirrors `NIMPolicy.effective()` (L62–77). Default `DeterministicScheduler` (`JitterPercent==0`) reproduces today's cadence **bit-for-bit**.

**Interfaces & integration.** `Scheduler` (two impls: `DeterministicScheduler` / `JitteredScheduler`), `Jitterer`, `RandSource`, `Staggerer`, `EndpointGenerator`, reused `Clock`, `RotationPolicy.effective()` (see shared interfaces). **Manager wiring:** add `Scheduler: controller.NewJitteredScheduler(randSource, clock)` + `Clock: clock` to the NIM literal at `cmd/main.go` L123–130 (mirroring `Policy:` L126); build **one** shared crypto/rand `RandSource` + one `realClock` in `main()` for both NIM and `time-based-trigger`. **RBAC:** NIM already has `adaptivemovingtargetdefenses get;list;watch` (L88) to **read**; add `adaptivemovingtargetdefenses/status update;patch` to **write** `NextRotationTime`. **CRD validation/webhook:** `metav1.Duration` fields need CEL or a validating webhook (`BaseInterval ≥ floor`, `JitterMaxPercent ≤ 100`, `HMAC ⇒ KeySecretRef` set) — first real use of the `:9443` server. **External deps:** `crypto/rand` (stdlib), `k8s.io/apimachinery/pkg/util/wait.Jitter` (reference/fallback), `robfig/cron` (already vendored). No new heavy dependency.

> **Two cross-cutting calls the synthesizer must force:** (1) **Restart-safety vs secrecy** — recover the schedule from **last-fire + a persisted seed** (reproducible without publishing plaintext `NextRotationTime`), per [D5](#d5). (2) **Which timer owns cadence** — `time-based-trigger` (emitter) and NIM (consumer self-requeue) would **both** be jittered with the same `RandSource`; jittering the same logical rotation in two places convolves two random timers. Decide which owns the cadence and make the other pass-through; note NIM's per-pod loop already provides some natural stagger.

**Proof it works.**

| Metric | How measured | Target |
|--------|--------------|--------|
| Inter-rotation interval distribution | Record actual rotation timestamps over many cycles; compute empirical gap distribution | Mean = `BaseInterval`; gaps spread over `base·(1 ± JitterPercent/100)`, no degenerate spike. **USER DECISION** acceptance band ([D9](#d9)) |
| Predictability / mixed-strategy quality | Forecast next rotation from history; measure prediction error / Shannon entropy of gaps | Prediction error ≥ jitter magnitude; entropy near max for the band. **USER DECISION** ([D9](#d9)) |
| Staggering / concurrency | For N pods under one AMTD, sample simultaneous Terminating/Pending; peak concurrent rotations | ≤ `MaxConcurrentRotations`; never all N at once. **USER DECISION** budget ([D24](#d24)) |
| Endpoint TTL enforcement | Probe generated path before/after TTL; confirm old stops resolving, new differs/unforgeable | Old invalid ≤ TTL+grace; new not guessable (HMAC). **USER DECISION** TTL + overlap ([D15](#d15)) |
| Exposure-window / dwell proxy | Max instance lifetime (= max gap) | ≤ `base·(1+JitterMaxPercent/100)`. Paper `<60min`/`Persistence<4%` are marketing targets ([D27](#d27)) |
| Backward compatibility | Run existing NIM/`time-based-trigger` tests with `JitterPercent=0` / nil block | Reproduces deterministic cadence; all tests pass |
| Restart-safety | Kill operator mid-cycle; confirm next rotation recovered from persisted seed/last-fire, no storm | ≤ one extra rotation after restart ([D5](#d5)) |

**Open questions (your decision).** [D9](#d9) base R + floor; [D10](#d10) jitter shape; [D12g](#d12g)/[D13](#d13) distribution + entropy source; [D14](#d14) stagger algorithm; [D5](#d5) `NextRotationTime` exposure + restart-safety + which-timer-owns; [D15](#d15)/[D16](#d16) endpoint hash + unforgeability + TTL; [D1](#d1) config home; telemetry-coupling hook (cap #5); [D24](#d24) concurrency budget.

---

### 5. Telemetry-driven adaptive rotation (anomaly-weighted cadence + `ContextMutationPolicy`) [primary]

**What the papers specify.** Two coupled behaviors, neither in code today (ingest exists, adaptation does not). (1) **Anomaly-weighted cadence** (Proactive **§IV.C.3**, p.3): *"Telemetry-Weighted Rotation Scheduling: Rotation frequency is not fixed but proportional to anomaly scores computed from runtime telemetry (e.g., GPU entropy, query deviation patterns, cache misses). This reduces attacker stealth advantages by accelerating rotations during suspicious activity."* Trigger principle (**§II.D.2**, p.2): *"Rotation schedules and configuration mutations are triggered by runtime metrics (e.g., Prometheus alerts) rather than fixed timers."* Workflow (§IV.D): *"timer expiry (time-based), security anomaly detection (event-based), or resource scaling needs (performance-based)"* via a "Telemetry & Decision Module". AMTD-AI architecture (p.3): Kube-Prometheus → Prometheus → AlertManager → Prometheus-Integrator → Phoenix Operator AMTD; p.6 *"Restart triggers from Prometheus metrics (e.g., anomaly rate)"*. (2) **`ContextMutationPolicy`** (ADA §2.6/§2.6.1 + **Listing 1**, p.4, verbatim): bind telemetry triggers (`PrometheusAlert high_gpu_usage`, `GatekeeperViolation disallowed-hostpath`) to declarative mutations (`ContainerImageUpdate nvcr.io/nim/secure-nim:latest`, `ResourceAdjustment nvidia.com/gpu:"0"`, `EnvPatch RUNTIME_MODE=SECURE`). ADA **§6.3.3 (p.14)** explicitly defers the scoring brain to future work: *"Rather than relying solely on time-based or static thresholds … derived from ML-based anomaly detection, policy engines (e.g., OPA), or behavioral scoring. Higher-risk workloads could be rotated more aggressively."* Phoenix-for-AI: *"Context-Aware Defense"* + *"Agentic Defense Logic … immediate panic mutation — moving the model to a clean, isolated node"* (p.3–4). **CRITICAL GAP:** **no** paper gives the scoring formula, the S→interval map, the GPU-entropy/query-deviation/cache-miss weights, the panic threshold, or the metric query expressions.

**Threat model.** Counters the attacker who, having a foothold, escalates a kill-chain that fixed-cadence rotation would not interrupt in time (AMTD-AI §III.B Persistence/Model-Extraction/Data-Exfiltration; §III.C vectors). A slow model-extraction/side-channel attack raises the §IV.C.3 signals; anomaly-weighted cadence compresses the window from baseline R toward immediate **panic mutation**, bounding dwell to minutes (the SolarWinds contrast: *"No anomaly-triggered re-deployment"* is exactly the gap closed). The `GatekeeperViolation` trigger + secure-image swap also counters Configuration Exploitation. This capability **consumes a score and reacts**; it does not itself detect side-channels or wipe GPU memory (those are cap #3).

**How it extends `phoenix-main`.**

| CRD | Field | Go type | Semantics | Default / DECISION |
|-----|-------|---------|-----------|--------------------|
| `AMTDSpec`/`InferenceRotationSpec` | `adaptiveRotation` | `*AdaptiveRotationPolicy` | Gives adaptive cadence a CRD home (it has none — `spec-map.md` L101) | nil → timer-only; **DECISION** home + AMTD-vs-`ContextMutationPolicy` ([D1](#d1)) |
| `AdaptiveRotationPolicy` | `baselineInterval` | `metav1.Duration` | R at score 0 | **Proposed `60m`**; **DECISION** — Proactive eval used 20–30m, demo 30s ([D9](#d9)) |
| `AdaptiveRotationPolicy` | `minInterval` | `metav1.Duration` | Floor at score 1.0 (guards delete-loop) | **Proposed `60s`**; must ≥ warm-up (`~400s` cold / `~15s` warm); **DECISION** ([D22](#d22)) |
| `AdaptiveRotationPolicy` | `scoreToIntervalFunction` | `string` enum `linear;exponential;stepped` | Monotone map S∈[0,1] → [min,base] | **Proposed `linear`** (literal "proportional"); **DECISION** ([D20](#d20)) |
| `AdaptiveRotationPolicy` | `panicThreshold` | decimal `0..1` | Immediate rotation regardless of last-rotation time | **Proposed `0.85`**, panic = immediate rotation only (node-move out of scope here); **DECISION** ([D25](#d25)) |
| `AdaptiveRotationPolicy` | `scoreSourceRef` | `TelemetryScoreSourceRef` | Where the per-pod score is read | **Proposed** read `SecurityEvent.Spec.AnomalyScore`; **DECISION** trust root ([D26g](#d26g)) |
| `SecurityEventSpec` | `anomalyScore` | `*string` | Numeric magnitude integrators can't carry today | **DECISION** representation + on-Spec-vs-Rule ([D19](#d19)) |
| `SecurityEventSpec` | `metrics` | `map[string]string` | Raw component bag for in-operator recompute/audit | **DECISION** upstream-vs-in-operator scoring ([D20](#d20)) |
| `SecurityEventStatus`/`AMTDStatus` | audit fields | as sketched | Feedback/audit substrate the RL agent (ADA Fig.1) would read | Proposed: add now; RL loop out of scope ([D23](#d23)) |

**New CRD types.** `ContextMutationPolicy` (faithful ADA Listing 1 — `Selector` + `Triggers.TelemetrySources[]{Type,Name,Constraint,Threshold}` + `Mutations[]{Type,ContainerName,NewImage,Resources,Env}` + Status); `TelemetryScoreSourceRef{Kind enum(SecurityEventField,PodAnnotation,PrometheusRule); FieldPath; AnnotationKey; PromQL; StalenessWindow}`; **optional** `ScoringPolicy{Weights;Normalization;Clamp}` (exists **only** because the paper does not specify weights — makes weighting an explicit operator decision, not an invented constant).

**Controllers affected.** `InferenceRotationReconciler` **new** (recommended sibling — watches inference pods scoped by predicate, reads score via `AnomalyScorer`, computes cadence via `CadenceFunction`/`AdaptiveRequeue`, applies `ContextMutationPolicy` mutations via `MutationApplier`, writes Status; **disjoint selectors** from NIM to avoid double-delete); `NIMReconciler` **modified** (in-place alternative: extend `NIMPolicy`/`effective()`/`DefaultNIMPolicy`, replace requeue L131–132, broaden `FindTimedEvent` L121,L136–143); `SecurityEventReconciler` **modified** (populate Status; optionally swap exact `reflect.DeepEqual` L139 for `ScoredRuleMatcher` behind a feature flag); `ContextMutationPolicyReconciler` **new, optional** (thin status reconciler or data-only); `prometheus-integrator` **modified** (set `Spec.AnomalyScore`/`Metrics` from alert labels; optional deeper change adds a real Prometheus client).

**Relation to `nim_controller` (explicit).** Recommended **new sibling** rather than mutating NIM in place, because NIM is the one working trigger path consumed by `time-based-trigger` and two controllers acting on the same pod could **double-delete**. (1) Cadence: **replaces** the constant requeue at `nim_controller.go` **L131–132** with `AdaptiveRequeue(score, policy, jitter)`. (2) Gate: **broadens** `FindTimedEvent` (**L121**, impl L136–143) so integrator-sourced / threshold events fire ("event-based"/"panic"). (3) Rotation site: does **not** replace the `r.Delete` itself; it decides **when** (score) and optionally inserts `MutationApplier.Apply` **before** L168 (warm-swap/image/GPU is caps #1/#2/#3). (4) Config home: gives cadence a CRD home (`AMTDSpec.adaptiveRotation`) so the controller reads the CR instead of the compile-time `DefaultNIMPolicy()` at L126. Also wire `NIM_RESCHEDULE_COUNT` (L31) as the cadence counter.

**Interfaces & integration.** `AnomalyScorer` (impls `PassthroughScorer`/`WeightedScorer`/`PromQLScorer`), `CadenceFunction`, `AdaptiveRequeue`, `TelemetryTriggerPredicate` (`MatchTelemetryTrigger`), `MutationApplier`, `ScoredRuleMatcher` (see shared interfaces). **RBAC:** `core pods …;delete` + `pods/status`; `amtd adaptivemovingtargetdefenses …/status update;patch`; `amtd contextmutationpolicies …/status update;patch`; `amtd securityevents/status update;patch`; `apps deployments` + `core services patch` if mutating images/endpoints. **SecurityEvent contract:** additive `AnomalyScore`/`Metrics` (pointer/optional) so all four emitters keep compiling; regenerate deepcopy. **Integrator change:** `prometheus-integrator` `PrometheusHandler` L130–146 sets `Spec.AnomalyScore`/`Metrics` (turns the **webhook sink** into a score carrier without adding scraping). **External deps:** Prometheus HTTP API + recording rules (PromQL **not** in any repo — must be authored); **OPA Gatekeeper** for the `GatekeeperViolation` source (**not integrated today — a hard prerequisite for half of Listing 1's triggers, emitted by nothing**); a GPU-entropy/query-deviation/cache-miss **exporter** (DCGM exposes utilization; "GPU entropy"/"query deviation" are **not standard metrics** with no defined computation).

> **Structural blockers the synthesizer must carry:** (a) `AnomalyScore` on `SecurityEventSpec` is **unreachable** by the `reflect.DeepEqual` matcher (L139) until it is relaxed off `Rule`-equality ([D21](#d21)). (b) Controller ownership: `InferenceRotation` + `SecurityEvent` (Delete L197–203) + NIM could all act on the same pod — disjoint-selector enforcement must be **mechanized**, not asserted ([D2](#d2)).

**Proof it works.**

| Metric | How measured | Target |
|--------|--------------|--------|
| Cadence responds to score | Inject rising `AnomalyScore` (0→1); record inter-rotation interval vs configured curve | Monotone-decreasing, bounded [min,base]; panic when S ≥ `panicThreshold`. SHAPE is the testable invariant (numbers are decisions) |
| MTTR / dwell under simulated attack | Drive signals up; measure score-crosses-threshold → pod deleted+recreated | AMTD-AI `MTTR < 5 min` (p.5 table). **USER DECISION** binding target ([D27](#d27)) |
| Availability during accelerated rotation | Continuous high score; endpoint success / p99 over the storm (vs warm-pool path) | `99.8%` / `1.3–1.7%` overhead (Proactive §V). **USER DECISION** — `minInterval` must not breach SLO ([D27](#d27)) |
| `ContextMutationPolicy` correctness | Fire `high_gpu_usage` at `app:nim-inference`; assert recreated pod shows all three Listing 1 mutations | Recreated pod **no longer byte-identical**; 100% of armed events mutate |
| No-regression (timer-only) | `adaptiveRotation` unset, only timed events | Behavior == current NIM/SecurityEvent flow |
| Score provenance integrity | Set a score from an unprivileged pod; confirm operator ignores/rejects per trust root; `StalenessWindow` drops old scores to 0 | Spoofed/stale scores cannot accelerate-or-suppress rotation ([D26g](#d26g)) |

**Open questions (your decision).** [D20](#d20) scoring formula/weights + upstream-vs-operator; [D9](#d9) score→interval + base R + min; [D25](#d25) panic threshold + what panic does; [D26g](#d26g) score provenance/trust root; signals production (GPU-entropy/query-deviation are non-standard); [D7g](#d7g) `ContextMutationPolicy` group + reconciler-vs-data-only; [D2](#d2) sibling-vs-in-place + controller ownership; [D21](#d21) exact-vs-scored matcher; RL/feedback-loop scope; [D27](#d27) targets; anti-flap/hysteresis ([D22](#d22)); **OPA-Gatekeeper-violation source (currently emitted by nothing)**.

---

### 6. Signed-baseline drift correction / self-healing regeneration [secondary]

**What the papers specify.** Workloads are forcibly **regenerated from an immutable, cryptographically-signed known-good baseline**, not patched and not recreated from live state. AMTD-AI §3.1 (p.2) names a *"Golden Image Repository: Immutable, signed copies of containerized workloads (NIMs, etc.)"*; p.5: *"Persistence becomes difficult when containers are forcibly restarted from golden state"* and *"Supply chain attacks are mitigated with signed, verifiable images and immutable baselines."* Proactive §IV.B (p.3): an *"Immutable Image Registry"* that *"Stores trusted, signed AI inference container images (e.g., Nvidia NIMs)"* and *"Ensures rollback capability to last known-good configuration"*; §IV.D step 1 *"Deploy inference container from the immutable registry"*; §IV.C.4 (p.3) *"Confidential Deployment Mutations: Each container rotation mutates its runtime hardening profile (Seccomp, AppArmor, RBAC policies)."* `README.md` **L34** (load-bearing product anchor): *"Autonomous Drift Correction: If any part of the infrastructure deviates from its cryptographically signed baseline, Phoenix treats it as a compromise and self-heals by instantly replacing the resource."* ADA §2.5 (p.3): *"Replacing instances rather than patching them reduces configuration drift and eliminates persistent threats."* ADA §2.6.1 + Listing 1 (p.4): mutations include *"Switching container images based on risk level or freshness"* via `ContainerImageUpdate newImage "nvcr.io/nim/secure-nim:latest"`. The papers specify a detect→classify-as-compromise→regenerate loop but **no** detector algorithm, comparison surface, trust root, signature scheme (only "cryptographically signed"), polling cadence, or what "any part deviates" diffs against. *Existing detection today:* the **only** drift detection shipped is third-party Falco YAML *"Container Drift Detected (chmod)"* / *"(open+create)"* (`deploy/manifests/config-falco/falco-rules.yaml` L3058/L3078), **both `enabled: false`** (L3070/L3088), wired to **no** Phoenix restore loop.

**Threat model.** Counters the **supply-chain / persistence-via-tamper** kill-chain (SolarWinds/SUNBURST class): an attacker mutates the running workload (drops/chmods an executable — exactly the Falco condition), tampers the image reference, or poisons the upstream image, then relies on that change **persisting across restarts** (Proactive §III.B *"Persistence: … control over a compromised container or node"*). Closes the verified gap (`spec-map.md` L133): today's sole restorative action recreates the pod from its **existing, unverified** PodSpec, so *"a tampered image reference or backdoored upstream image would be redeployed verbatim,"* directly contradicting *"forcibly restarted from golden state."* Also blunts container-escape (§III.C.1 runc CVE-2019-5736) and configuration exploitation (§III.C.3) because regeneration resets the hardening profile to baseline (§IV.C.4). **Trust-root caveat ([D6](#d6) group):** drift correction is only as strong as its baseline. If the baseline (signed digest, cosign key / Rekor / Fulcio root, stored PodSpec snapshot) lives somewhere mutable the attacker can reach, they **tamper the baseline instead of the workload** and self-heal restores the malicious state. **Additional caveat the synthesizer must add:** signing proves **provenance/integrity, not benignity** — a validly-signed-but-backdoored upstream image (the literal SolarWinds shape) still passes verification; the digest-allowlist-only option gives **no** supply-chain guarantee at all.

**How it extends `phoenix-main`.**

| CRD | Field | Go type | Semantics | Default / DECISION |
|-----|-------|---------|-----------|--------------------|
| `AMTDSpec` | `Baseline` | `*BaselineSpec` | Signed known-good baseline; nil → today's delete-from-live-spec | nil → unchanged; **DECISION** AMTD-embedded vs `WorkloadBaseline` CRD ([D1](#d1)) |
| `BaselineSpec` | `ImageDigests` | `[]ImageDigestRef{ContainerName;Repository;Digest}` | Per-container known-good image pinned by digest | **Proposed** digest pinning is minimum surface; **DECISION** digest-only vs full-PodSpec ([D6](#d6)) |
| `BaselineSpec` | `Signature` | `*SignaturePolicy{PublicKeyRef;KeylessIdentity{Issuer,SubjectRegexp};RekorURL;RequireSignature}` | How "signed, verifiable" is checked (cosign key / keyless) | **DECISION** scheme + trust root ([D6](#d6)); paper names none |
| `BaselineSpec` | `PodSpecSnapshotRef` | `*SnapshotRef{SecretName\|GitRef\|Inline}` | Desired state to regenerate **from** (not live cluster state) | **DECISION** owner-template vs immutable snapshot vs GitOps ([D6g](#d6g)) |
| `BaselineSpec` | `DriftPolicy` | `{DetectInterval;OnDrift enum(Regenerate;Quarantine;AlertOnly;Block);AdmissionEnforce;ResetHardeningProfile}` | Scan cadence, response, admission gate, profile reset | **Proposed** `OnDrift=Regenerate`, `AdmissionEnforce=true`, `DetectInterval` unset (event-driven only) — **surfaced, not silent**; **DECISION** ([D6g](#d6g)) |
| `SecurityEventSpec`/`Rule` | `Type="drift"` convention + `Evidence` | `*DriftEvidence{ObservedDigest;ExpectedDigest;Detail}` | Drift arrives via the existing contract; Evidence for audit | **DECISION** extend SecurityEvent vs route only through baseline controller ([D6g](#d6g)) |
| `AMTDStatus` | `BaselineStatus` | `{LastVerifiedTime;PinnedDigests;DriftDetections;LastRegeneration;Conditions}` | Verification/restore audit + GitOps feedback | Proposed: populate |

**New CRD types.** `BaselineSpec` (+ nested `ImageDigestRef`, `SignaturePolicy`, `KeylessIdentity`, `SnapshotRef`, `DriftPolicy`, `DriftAction`, `DriftEvidence`); `BaselineStatus`; **optional** standalone `WorkloadBaseline` CRD (decouples the signed-baseline registry from AMTD; matches "Immutable Image Registry" as a distinct component + "GitOps Ready"; AMTD then carries `BaselineRef`).

**Controllers affected.** `BaselineDriftReconciler` **new** (watches baseline-scoped pods, `VerifyImage`+`Detect` on `DetectInterval`/watch events, on drift runs `BaselineRestorer.Regenerate`, writes `BaselineStatus`); `baselineAdmission` webhook **new** (on the existing `:9443` server — verifies signed + pinned digest when `AdmissionEnforce`; **needs new webhook config + certs, none today**); `NIMReconciler` **modified** (add `Restorer BaselineRestorer` field; before `r.Delete` L168, if baseline-governed call `Regenerate` so the rescheduled pod comes from the verified digest); `SecurityEventReconciler` **modified** (add `else if action.Regenerate != nil` branch calling `Regenerate` instead of unverified `r.Client.Delete` L198 — fills the L370–372 slot; matcher L139 unchanged, `Type='drift'` matches literally); `AdaptiveMovingTargetDefenseReconciler` **modified** (pin current digest into `BaselineStatus` at enroll L160–186; optionally `Watches/Owns` Pods); `falco-integrator` **modified** (enable the `enabled:false` Container-Drift rules + map to `Rule{Type:'drift',Source:'FalcoIntegrator'}`).

**Relation to `nim_controller` (explicit).** **Add a new reconciler + webhook alongside NIM and harden the delete sites; do not replace NIM.** NIM is the **timer-gated** cold-restart seam (acts only on `FindTimedEvent`); drift is a **different trigger** (signature/digest deviation, admission, or a Falco `'drift'` event) that does not belong inside NIM's timed gate. The minimal touch is at the **delete sites**: both `nim_controller.go` `processPodWithNIM` (`r.Delete` **L168**) and `securityevent_controller.go` Delete branch (`r.Client.Delete` **L198**) currently regenerate from the live, unverified PodSpec — insert `BaselineRestorer.Regenerate(pod, baseline)` **before** these deletes so the owning template's image is first rewritten to the verified `Repository@Digest`. NIM gains an optional `Restorer` field (injected like its `Policy` at L126). The new `BaselineDriftReconciler` owns what NIM cannot express: `For(&corev1.Pod{})` scoped to baseline-governed pods, periodic `DetectInterval` verification, digest pinning, consuming `'drift'` events. Finally write `NIM_RESCHEDULE_COUNT` (L31). NIM's timed gate (L121,L136–143) is **unchanged**.

**Interfaces & integration.** `BaselineVerifier`, `DriftDetector`, `BaselineRestorer`, `BaselineStore`, `baselineAdmissionHandler` (see shared interfaces). **Manager wiring:** register `BaselineDriftReconciler` above `cmd/main.go` L131 (mirroring NIM L123–130 with a `Verifier`/config field); register `baselineAdmission` on `mgr.GetWebhookServer()` (L80). **RBAC:** `core pods …;delete` + `pods/status`; `amtd adaptivemovingtargetdefenses …/status …`; `core secrets get;list;watch` (cosign key / snapshot Secret); if `AdmissionEnforce`: `admissionregistration.k8s.io validatingwebhookconfigurations/mutatingwebhookconfigurations`; if Regenerate mutates owners: `apps deployments;replicasets …`; if Quarantine reused: `networking.k8s.io networkpolicies` (already granted to `SecurityEventReconciler` L51). **External deps (NEW; none in runtime today):** sigstore/cosign Go API (cosign exists **only** in `prometheus-integrator` CI), optionally Rekor/Fulcio (keyless) or a KMS; `go-containerregistry` for digest resolution; a registry pull-secret for the golden registry; for GitOps desired-state: ArgoCD/Flux/git client (the "GitOps Ready" claim is external to these 5 repos).

> **Implementation gaps the synthesizer should close (adjacent to flagged decisions):** (a) **owner-resolution** — `BaselineRestorer.Regenerate` holds a `corev1.Pod` whose owner may be a bare Pod / ReplicaSet(→Deployment) / StatefulSet / DaemonSet / Job; rewriting a ReplicaSet directly is reverted by its Deployment, so the controller must **walk up** to the correct owner template. (b) **webhook semantics** — Mutating (pin digest) vs Validating (Block) is left open, and the AMTD controller's own pod `Update` (L184/L186) re-triggers a pod-UPDATE webhook (self-trigger loop) that must be guarded.

**Proof it works.**

| Metric | How measured | Target |
|--------|--------------|--------|
| Tamper-redeploy prevention (core gate) | In a baseline-governed pod, (a) chmod/drop an executable (Falco drift), (b) mutate the owning Deployment image to a backdoored tag; assert regenerated pod runs the **verified** `Repository@Digest`, and with `AdmissionEnforce` the tampered image is denied | 100% restored-or-blocked at the signed baseline (0 verbatim redeploys of tampered state) |
| Persistence Success Rate | Foothold survival across a self-heal cycle (paper tables p.4–5) | `95%+ → <4%`. Paper-claimed, aspirational ([D27](#d27)) |
| Drift MTTR | Drift signal → healthy pod on verified baseline (`BaselineStatus.LastRegeneration` − detection ts) | **USER DECISION** — paper's `<5min` is for ROTATION, not drift; admission-Block is synchronous ([D27](#d27)) |
| Signature/verification correctness | signed+pinned → admitted; unsigned w/ `RequireSignature` → drift; valid-sig wrong-digest → drift; keyless identity mismatch → rejected | **USER DECISION** — 100% with a defined fail mode for registry/Rekor unavailability ([D6](#d6)) |
| Availability / latency overhead | Availability during regeneration + admission latency (webhook + sig verify) under load | **USER DECISION** — paper figures are for rotation; registry round-trips can dominate ([D27](#d27)) |
| False-positive drift rate | Clean cluster with legit GitOps bump; how often benign change is flagged / reverted | **USER DECISION** — near-zero AND must not fight GitOps ([D6g](#d6g)) |

**Open questions (your decision).** [D6](#d6) trust root + signature scheme + comparison surface + fail-open-vs-closed + (signing≠benignity caveat); [D6g](#d6g) baseline storage tamper-resistance + desired-state source + GitOps precedence + detection mechanism/cadence + default response + hardening-profile-reset scope + SecurityEvent contract; node-vs-pod scope (defer to cap #7); [D27](#d27) targets.

---

### 7. Node rotation / panic-move inference pods to a clean node [secondary]

**What the papers specify.** *What moves:* the workload's **node assignment**, not just the container. Proactive §IV.B (p.3): the Rotation Engine *"Performs workload re-deployment with randomized parameters: new container IDs, ephemeral node assignments, shuffled port mappings."* §IV.D step 4 *"Terminate existing containers and replace them with a new instance using randomized parameters"* and **step 5** *"Update Service Endpoints without interrupting client connections (leveraging Kubernetes Service abstraction)"* — relocation **must** preserve the Service. §V.D (p.4): *"By rotating containers, nodes, and configurations … AMTD actively evicts any attacker from the environment, reducing dwell time to mere minutes."* Phoenix-for-AI Pillar 03 (p.4): *"triggers an immediate panic mutation — moving the model to a clean, isolated node. Real-time isolation of compromised instances."* *Triggers:* panic/event-driven (Phoenix-for-K8s "Panic Mutation": *"Falco detects suspicious activity, Phoenix triggers immediate workload rotation"*) and co-location/scheduled (§III.C.4). *Adaptation:* **§V.A Experimental Setup** (p.3, *corrected citation*) *"Staggered rotation to avoid simultaneous restarts"*; endpoints update via the Service abstraction (§IV.D step 5). The paper gives **no** node-selection algorithm, **no** definition of "clean/isolated", **no** cordon/drain semantics, and **no** downtime number for the node case (the warm-up note is **§V.E Limitations p.4**: models with **<60 sec** warm-up still need careful staggering — *corrected from §IV.E / ">60 sec"*).

**Threat model.** Counters **host-level / node-shared-resource** compromise that container-only rotation cannot evict. §III.C.1 (p.2) *"Container Escape & Privilege Escalation … runc CVE-2019-5736 … host-level control"* — once on the node, delete+recreate (today's sole primitive `securityevent_controller.go` L198 / `nim_controller.go` L168) recreates on the **same** compromised node, so the foothold survives; relocating to a clean node breaks it. §III.C.4 *"Adversarial Workload Co-location: … shared memory, cache timing, or PCIe bus vulnerabilities"* — the GPU side-channel / co-tenant path; moving the victim to an isolated node removes the shared-node surface. **New attack surface this introduces:** a node-eviction/cordon primitive is itself a **cluster-DoS lever** — an attacker able to forge `SecurityEvents` (the cluster-scoped contract object) could cordon/taint/delete every node ([D26](#d26)).

**How it extends `phoenix-main`.**

| CRD | Field | Go type | Semantics | Default / DECISION |
|-----|-------|---------|-----------|--------------------|
| `AMTDAction` | `NodeRotate` | `*NodeRotateAction` | Node-level analogue of `DeleteAction`: cordon/taint pod's node + reschedule onto clean node | respects `MaxProperties=1` (own strategy entry); **DECISION** action vs Spec-policy vs both ([D25g](#d25g)) |
| `NodeRotateAction` | `Strategy` | `string` enum `Cordon;Taint;Delete` | Source-node disposition | **Proposed `Cordon`** (reversible); paper doesn't pin it; **DECISION** ([D25g2](#d25g2)) |
| `NodeRotateAction` | `DrainPolicy` | `*DrainPolicy{GracePeriodSeconds;IgnoreDaemonSets;DeleteEmptyDir;Force}` | Whether/how co-tenant pods are evicted | **Proposed** relocate only targeted pod + cordon (no co-tenant drain) unless set; **DECISION** ([D25g3](#d25g3)) |
| `NodeRotateAction` | `TargetNodeSelector` | `map[string]string` | What "clean/isolated node" **means** (the relocation destination pool) | **DECISION (load-bearing)** — paper defines neither; proposed admin clean-pool label ([D25g4](#d25g4)) |
| `AMTDSpec` | `NodeRotationPolicy` | `*NodeRotationPolicy{Enabled;Interval;Jitter;MaxConcurrentNodes;Stagger;TargetNodeSelector}` | Gives **scheduled** node rotation a home; `Stagger` = §V.A; `MaxConcurrentNodes` protects availability | **DECISION** interval/jitter (no node-specific value in paper) + whether scheduled is in-scope for v1 ([D9](#d9),[D25g](#d25g)) |
| `AMTDStatus` | `NodeRotations` | `[]NodeRotationStatus{SourceNode;TargetNode;PodName;Time;Phase}` | Observable/auditable; restart-safety; validation MTTR/availability | Proposed: bounded history (last N=20) — proposal, paper specifies no schema |

**New CRD types.** Embedded `NodeRotateAction`, `NodeRotationPolicy`, `DrainPolicy`, `NodeRotationStatus`; **optional** cluster-scoped `NodeRotation` CRD (models an in-flight drain as its own reconcilable object so progress survives operator restarts — corroborated by `SecurityEvent` itself being cluster-scoped).

**Controllers affected.** `NodeRotationReconciler` **new** (watches AMTD for `NodeRotationPolicy` and/or `NodeRotation` objects; cordon → drain via Eviction API honoring PDBs → reschedule targeted inference pod(s) onto a `CleanNodeSelector`-chosen node → record `NodeRotationStatus` → uncordon-on-success/leave-tainted; mirrors `NIMReconciler` struct shape with injected `Policy`/`Drainer`/`Selector`); `SecurityEventReconciler` **modified** (add `else if action.NodeRotate != nil` branch before L370–372; reads `pod.Spec.NodeName`, creates `NodeRotation` or invokes `Drainer`+`Planner`; matcher L139 unchanged); AMTD API types **modified** (`make` to regen deepcopy + CRDs); `NIMReconciler` **modified, minimal** (one early-return guard after the applied-events gate L105–109 that skips pods carrying `noderotation.r6security.com/in-progress`, so NIM's 10s delete loop L132 does not race the drain); `cmd/main.go` **modified** (register block above L131); dead `PodReconciler` **unchanged**.

**Relation to `nim_controller` (explicit).** **Add a new node-aware reconciler alongside NIM; do not rewrite NIM's delete site in place.** NIM is pod-scoped — `processPodWithNIM` `r.Delete` (**L168**) recreates the pod on whatever node the scheduler picks (potentially the **same** compromised node). Node rotation is a node-scoped op (cordon/taint/drain a `corev1.Node` + constrain the replacement to a clean node) NIM's single-pod delete cannot express. **Cooperation (required):** (1) the relocated pod must be **pinned** to the clean node (injected `nodeAffinity` or `spec.nodeName`), which NIM's plain delete does not do; (2) avoid the NIM delete-loop race via the shared `noderotation.r6security.com/in-progress` annotation + NIM early-return (right after L105–109). Optional larger touch: NIM detects `action.NodeRotate` and defers to `NodeRotationReconciler` — but the cleaner design keeps NIM nearly untouched and gates via the annotation. Wiring mirrors the NIM template (L123–130).

**Interfaces & integration.** `NodeRotationReconciler`, `NodeDrainer` (via `policy/v1 Eviction` subresource to respect PDBs, falling back to delete; fakeable like `Clock`), `CleanNodeSelector` (label-pool default; autoscaler/attestation impls later), `InferenceReschedulePlanner` (`ExecuteWithServiceContinuity` — preserves the Service endpoint, §IV.D step 5; warm relocation ties to cap #2), `FindPanicEvent` (broadened `FindTimedEvent` analogue) (see shared interfaces). **RBAC (the big new grant — NO controller has node RBAC today):** `core nodes get;list;watch;update;patch` (cordon/uncordon/taint); `core pods get;list;watch;delete` + `pods/eviction create`; `core pods/binding create` OR `pods update` if pinning `spec.nodeName`; `policy poddisruptionbudgets get;list;watch`; `amtd adaptivemovingtargetdefenses …/status update`; if `NodeRotation` CRD: `amtd noderotations …`; then `make manifests`. **External deps:** `k8s.io/api/policy/v1` (Eviction); for "provision a fresh clean node": cluster-autoscaler/Karpenter (only if `CleanNodeSelector` uses autoscaling); for warm relocation: LWS/Kueue (shared with cap #2).

> **Gaps the synthesizer should add to open questions:** (a) **stateful-pod / storage / GPU relocation** — a node move can strand a local PV / hostPath / emptyDir, and a PVC with node-affinity (local-path, topology-bound CSI) may be unschedulable on the clean node (pod never Ready); for GPU inference the clean pool must have **free GPUs of the right type/MIG profile**. (b) **target-set definition** — NIM has **no** inference selector (it watches all pods, L178–183), so "the inference pods NIM manages" is an ill-scoped set; which pod(s) a rotation relocates must be defined. (c) **crash-mid-drain idempotency/rollback** — node left cordoned, pod half-evicted; reconcile-to-completion semantics (partly mitigated by the dedicated-CRD option).

**Proof it works.**

| Metric | How measured | Target |
|--------|--------------|--------|
| Host-foothold eviction (functional gate) | Plant marker process/file on the host node; trigger rotation; assert pod now Running on a **different** clean-pool node, source cordoned/tainted, did NOT reland on source | 100% relocate off source node (functional invariant; no paper number) |
| Inference availability during node rotation | Steady requests through the Service while rotating the node; 5xx/dropped-connection rate across the window | **USER DECISION** — `99.8%` (Proactive Abstract) is **not** a node-rotation measurement; warm relocation (cap #2) needed to approach it; cold cordon-drain-recreate worse ([D27](#d27)) |
| Node-rotation MTTR | Trigger → targeted pod Ready on clean node (`NodeRotationStatus` Start→Completion) | **USER DECISION** — `<5min` is the anomaly-recovery figure; no node-specific MTTR in paper ([D27](#d27)) |
| Co-location surface reduction | Co-tenants sharing victim's node before vs after (with `DrainPolicy`); zero AMTD-managed inference pods co-located with a flagged pod | **USER DECISION** — `94%`/`Lateral 4%` are simulated workload-level figures ([D27](#d27)) |
| Availability-safety (no mass eviction) | Scheduled rotation under load; assert `MaxConcurrentNodes` + `Stagger` honored | 100% adherence (functional safety gate; prevents self-inflicted outage) |

**Open questions (your decision).** [D25g4](#d25g4) "clean/isolated node" definition; [D25g2](#d25g2) source-node disposition; [D25g3](#d25g3) co-tenant drain scope; [D9](#d9) node interval/jitter or panic-only; [D5 group](#d5) Service continuity; [D26](#d26) trigger authn (cluster-DoS lever); NIM coordination; [D25g](#d25g) API shape; pod-pinning mechanism; cloud-instance termination; stateful/PVC/GPU-on-destination; target-set definition; crash-mid-drain rollback.

---

## Decisions needed from you (consolidated)

Every flagged underspecified item and every verifier-flagged invention, deduped and grouped by theme. **None of these is answered here — each is a fork the papers leave open and the owner must resolve.** A "Proposed default" elsewhere in this doc is a starting point to confirm, never a settled value.

### Structural / API surface

<a id="d1"></a>**D1 — Where does the new config live?** Embed all blocks on `AdaptiveMovingTargetDefenseSpec` (one CRD, reuses `PodSelector`/`Strategy`/enrollment plumbing) vs standalone CRDs (`WarmInferenceSet`, `ContextMutationPolicy` — ADA Listing 1 uses a distinct kind `ContextMutationPolicy`, group `ADA.security.r6.dev/v1` —, `RotationSchedule`, `WorkloadBaseline`, `NodeRotation`) vs both (AMTD references a policy CR). *Why:* drives whether `NIMReconciler` is extended in place vs new reconcilers+CRDs+RBAC; affects every section.

<a id="d2"></a>**D2 — Which controller performs mutating rotation, and how is the storm guarded?** NIM requeue loop (self-perpetuating once a timed event is on the pod — today re-deletes every 10s, so a mutating version would re-mutate continuously) vs a one-shot `RotateAction` executed by `SecurityEventReconciler` (the L370–372 slot) vs hybrid (NIM owns timed, SecurityEvent owns threat). *Why:* a naive in-place loop **rotation-storms** without a min-interval/idempotence guard; controller ownership across `InferenceRotation` + `SecurityEvent` (Delete L197–203) + NIM on the same pod must be **mechanized** (disjoint selectors), not asserted. *Coupled with D3.* Options: (a) NIM loop + cadence/jitter + idempotence/readiness gate; (b) `RotateAction` one-shot; (c) hybrid.

<a id="d3"></a>**D3 — How does image/env/gpu mutation survive recreation for a Deployment/ReplicaSet-managed pod?** Deletion lets the **owner** recreate from its existing template, so mutating `pod.Spec` is lost. *Why:* the single biggest design fork; without resolution the mutation never sticks. Options: (a) patch the owning controller's `PodTemplateSpec` (needs owner-walk: Pod→ReplicaSet/Deployment/StatefulSet/DaemonSet/Job; rewriting a ReplicaSet is reverted by its Deployment); (b) create-new-then-cutover (warm swap, cap #2); (c) require workloads be deployed via an operator-owned wrapper (e.g. LWS).

<a id="d21"></a>**D21 — Relax the action matcher off `Rule`-equality?** `securityevent_controller.go` L139 `reflect.DeepEqual` compares the whole `Rule`, so a new `AnomalyScore` on `SecurityEventSpec` is **structurally unreachable** until the matcher moves. *Why:* telemetry magnitude cannot select an action otherwise; changing it affects every existing AMTD strategy. Options: keep `DeepEqual` (score only affects cadence); add `ScoredRuleMatcher` behind a feature flag (`Source+Type` + `ThreatLevel`/score ≥ threshold); hybrid.

### Scheduling / entropy

<a id="d5"></a>**D5 — Cadence secrecy, restart-safety, which-timer-owns, and stateful drain.** (a) Should `AMTDStatus.NextRotationTime` (or any next-fire signal) be published? Publishing re-exposes exactly what jitter hides; an attacker with read access reads the schedule. (b) Restart-safety: recover the schedule from **last-fire + a persisted seed** (reproducible without plaintext next-fire) vs re-randomize. (c) `time-based-trigger` (emitter) and NIM (consumer self-requeue) would **both** be jittered — decide which owns cadence so rotation is not double-jittered. (d) Stateful inference (KV-cache, loaded weights, in-flight requests): connection-draining + LB deregistration before delete vs warm-swap drain vs accept dropped in-flight (stateless). *Why:* a half-secret schedule, a post-restart storm, a convolved double-timer, or dropped multi-turn sessions each defeat or degrade the mechanism.

<a id="d9"></a>**D9 — Base rotation interval R and its hard floor.** Papers conflict: AMTD-AI §3.2 `60m`, Proactive eval `20–30m`, demo manifest `30s`. *Why:* smaller R lowers `∫A(t)dt` but risks restart storms / availability loss; jitter of 10–30% is meaningless on a 30s base. Also applies to the **node-rotation** interval (no node-specific value in any paper) and the telemetry **baselineInterval**/**minInterval**. Options: `60m` (white paper) / `20–30m` (eval) / per-workload via CRD with a webhook-enforced floor (e.g. ≥5m) / fully user-set.

<a id="d10"></a>**D10 — Jitter shape.** Paper says `± jitter (10–30%)` — a **band**, not a single number, and `±` implies symmetric. *Why:* two-sided jitter can push rotation **later** (raises max exposure); one-sided (only earlier) bounds max dwell but raises rate/cost. ⚠️ *Invention guard:* the "20%" used as a proposed default is **not** a paper value — it is the band midpoint; treat as a starting point, not fact. Options: single `JitterPercent` symmetric; `JitterMinPercent`/`JitterMaxPercent` range (faithful to "10–30%"); one-sided downward; one-sided upward.

<a id="d12g"></a>**D12g — Which distribution realizes the von Neumann "mixed strategy"?** PHOENIX §III mandates "a probability distribution over all possible actions" but names none; the model only says higher entropy is better. Options: `Uniform` over the band (max entropy, simplest); `TruncatedNormal` centered on R; exponential/Poisson (memoryless). ⚠️ *Invention guard:* the `Uniform;TruncatedNormal` enum vocabulary is design-authored, not paper-derived.

<a id="d13"></a>**D13 — Entropy source.** crypto/rand (unpredictable) vs seedable math/rand (testable but predictable if the seed leaks — defeats the entire mechanism). *Why:* security-load-bearing. Options: crypto/rand (recommended, prod); math/rand seeded (non-prod/test only). Note the only existing `rand` is a non-security gRPC nonce.

<a id="d14"></a>**D14 — Stagger algorithm.** Proactive §V.A requires "Staggered rotation to avoid simultaneous restarts" but gives no algorithm. *Why:* without it a Deployment's pods rotate on the same tick → cluster-wide blackout (predictable + self-DoS). ⚠️ *Invention guard:* `hash(podUID) mod base` is a proposed formula, not paper-derived. Options: deterministic per-pod phase offset; independent per-pod jitter; global `MaxConcurrentRotations` budget; combination.

<a id="d15"></a>**D15 — Endpoint hash derivation + unforgeability + TTL value.** §5 says "Randomized endpoint URLs with hash-based TTL" / §5.3 "Custom TTL for model services" but names **no** hash function, hash input, key, or numeric TTL. *Why:* a plain `SHA256(counter)` path is unpredictable only if the input is secret; if an attacker must not compute the **next** path, an HMAC with a managed key is required (introduces a key/trust-root); TTL too short breaks in-flight requests. ⚠️ *Invention guard:* the `SHA256;HMAC-SHA256` enum and `PathTemplate "/{hash}"` are design-authored. Options: `SHA256(seed||epoch||podUID)` with seed in a Secret; `HMAC-SHA256` (unforgeable, needs `KeySecretRef` + key rotation); random UUID per rotation; defer endpoint generation to cap #1 and own only TTL here. TTL: `== BaseInterval` / independent / jittered / with an overlap-grace window.

<a id="d16"></a>**D16 — Endpoint rotation scope.** Is endpoint/API-key/hash-TTL rotation part of caps #1/#2/#4 here, or a separate identity-shuffle capability? *Why:* it is a distinct mechanism with its own secret-management + client-coordination concerns; conflating bloats scope, and how legitimate clients learn the new path without the attacker also learning it is unspecified. Options: in-scope (rotate key+path each cycle); out-of-scope (stub the field, defer); endpoint-path-only (key stable).

<a id="d24"></a>**D24 — Cluster-wide concurrency/availability budget.** Smaller R + more pods ⇒ more restarts; the `1.3–1.7%` overhead / `99.8%` availability claims depend on an **unstated** limit. Options: `MaxConcurrentRotations` per AMTD; global cluster rotation rate limit; PodDisruptionBudget integration; no budget.

### Image trust & signing

<a id="d6"></a>**D6 — Trust root, signature scheme, comparison surface, and fail mode.** Papers say only "cryptographically signed" / "signed, verifiable images" — no scheme, signer, key, or transparency log; cosign exists today **only** in CI. *Why:* determines the verification library, dependency surface, offline-vs-online behavior, and the entire guarantee; if the baseline lives somewhere mutable the attacker **tampers the baseline instead of the workload**. ⚠️ *Caveat:* signing proves **provenance/integrity, not benignity** — a signed-but-backdoored upstream image (SolarWinds shape) still passes; a digest-allowlist-only option gives **no** supply-chain guarantee. ⚠️ *Invention guard:* a hard-required `@sha256:` digest **regex** is design-authored — the paper never mandates digest-pin syntax; soften any such marker to a flagged default. Options: cosign key-based (offline key in Secret/KMS); cosign keyless (Fulcio+Rekor/OIDC); Notation/Notary v2; SLSA/in-toto attestation; digest-allowlist only. **Comparison surface:** image digest only vs digest + curated PodSpec field allowlist vs full PodSpec snapshot (fights normal k8s mutation) vs runtime filesystem/exec drift (Falco, detection-only). **Fail mode:** fail-closed (treat unverifiable as drift — risk outage if a registry/Rekor blips) vs fail-open (risk a bypass window) vs fail-closed-at-admission/fail-open-on-poll vs cached-last-good with grace.

<a id="d6g"></a>**D6g — Baseline storage, desired-state source, GitOps precedence, detection cadence, default response, hardening reset, SecurityEvent contract.** (a) Where the baseline (digest + key + snapshot) lives so it is tamper-proof: external immutable registry + offline-signed digests / Git repo / in-cluster Secret-or-CRD (mutable) / KMS-HSM. (b) Authoritative desired state to regenerate **from**: owning controller's template (may conflict with Argo) / Phoenix-owned immutable snapshot / write corrected digest to Git + let GitOps deploy / explicit precedence annotation so only one controller heals a workload. (c) Detection mechanism + cadence: admission-only / admission + Falco event (no poll) / admission + periodic poll at `DetectInterval` (owner sets — **no scan interval in any paper**, distinct from R) / poll-only. (d) Default drift response: `Regenerate` (matches the claim but auto-replace is weaponizable into restart-loop DoS) / `Quarantine`+alert / `AlertOnly`-then-confirm / `Block`-at-admission. (e) Hardening-profile reset scope (§IV.C.4): securityContext/Seccomp/AppArmor only (feasible) vs also RBAC RoleBindings (high-privilege, large blast radius) vs defer. (f) Extend `SecurityEvent` with `Evidence`/Status vs keep it unchanged (route drift only through the baseline controller + webhook) vs annotations/Events only.

### Warm-pool / LWS topology

<a id="d11"></a>**D11 — "Warm" definition, pool size N, LWS-vs-in-tree, config home.** (a) What "warm"/"ready in RAM" means before a shadow may be promoted (**top correctness risk** — if model weights aren't GPU-resident the `15s` claim collapses to `~400s` and requests fail): process up + `/readyz` 200 / weights loaded into GPU VRAM (verified via NIM/Triton or `/v1/models`) / a synthetic warm-up inference completed / KV-cache primed. (b) Pool size N + fixed-vs-adaptive (paper says only "small set ≥1"; each shadow holds GPU VRAM): fixed `2` / fixed from CRD / autoscaled by load/anomaly (ties to cap #5). (c) Adopt upstream `sigs.k8s.io/lws` (gang-scheduled, version coupling) vs StatefulSet-backed in-tree vs controller-managed bare pods. (d) Config home: new `WarmInferenceSet` CRD (recommended) vs `WarmPool` block on AMTDSpec vs `WarmSwapAction` member. ⚠️ *Note:* gang-scheduling — if N shadows can't co-schedule on scarce GPUs, "warm" is unachievable.

<a id="d12"></a>**D12 — Traffic-steering primitive.** §3.1 says "Routes traffic to active leader" with no mechanism. *Why:* determines atomicity, connection-draining, and RBAC. ⚠️ *Invention guard:* the `EndpointSwap;ServiceSelectorSwap;GatewayWeight;LeaderLabel` enum is **entirely design-authored**. Options: `ServiceSelectorSwap` (move a leader label a Service selects — portable); `EndpointSwap` (rewrite EndpointSlice — fastest, more privileged); `GatewayWeight` (HTTPRoute weights — gradual shift); `LeaderLabel`-only (external LB/mesh watches).

### Telemetry scoring

<a id="d20"></a>**D20 — Scoring formula, weights, normalization, and where scoring happens.** §IV.C.3 names GPU entropy / query deviation / cache misses but gives **no** formula, weights, or normalization; ADA §6.3.3 defers the scoring source (ML/OPA/behavioral) to future work. Today **all** anomaly logic is upstream in external Alertmanager rules that exist in **none** of the 5 repos. ⚠️ *Invention guard:* example weights `{0.5/0.3/0.2}` are an illustration, not a paper value. Options for **scoring location:** trust a single upstream score (operator does none) / in-operator `WeightedScorer` over `Metrics` with operator-set weights+normalization / PromQL recording rule computes S / pluggable `AnomalyScorer` with a documented default + real ML/OPA scorer as future work. *Also:* the GPU-entropy/query-deviation/cache-miss **signals themselves are not standard metrics** — define via DCGM-derived recording rules (utilization stddev proxy) / custom exporter (future) / drop them and score from Falco/KubeArmor event rate only.

<a id="d19"></a>**D19 — `AnomalyScore` representation and home.** decimal string `0..1` vs integer `0..100` vs `resource.Quantity`; on `SecurityEventSpec` (keeps `Rule` a pure match key) vs on `Rule`. Also: does threat-reactive rotation key off a new numeric score, the existing free-string `ThreatLevel` (`info/low/medium/high` — an enum the paper never defines), or `Rule.Source` membership (Falco/KubeArmor/Prometheus)? Pin the enum/threshold.

<a id="d25"></a>**D25 — Panic threshold and what "panic" does.** Phoenix-for-AI/K8s claim an "immediate panic mutation" that "moves the model to a clean, isolated node", but node selection/isolation requires cap #7. ⚠️ *Invention guard:* `0.85` is a proposed value, not a paper figure. Options: threshold `0.8/0.85/0.9`; panic = immediate rotation only / + cordon/move to isolated node (needs cap #7) / + Quarantine NetworkPolicy (reuse existing action, respecting `MaxProperties=1`).

<a id="d26g"></a>**D26g — Score provenance / trust root.** If the score arrives as a pod annotation/label, a compromised workload could **forge a low score to suppress its own rotation** — inverting the defense. Options: `SecurityEvent.Spec.AnomalyScore` (cluster-scoped CR, integrator-written, RBAC-gated — recommended) / pod annotation (convenient but spoofable) / Prometheus HTTP API queried by the operator (no in-cluster forgery, adds external dep + auth). Also `StalenessWindow` to drop old scores to 0.

<a id="d7g"></a>**D7g — `ContextMutationPolicy` API group + reconciler-vs-data-only.** ADA Listing 1 uses `apiVersion ADA.security.r6.dev/v1`; the operator's group is `amtd.r6security.com/v1beta1`. Group choice affects scheme/RBAC/client reuse; reconciler-vs-data-only affects status reporting. Options: `amtd.r6security.com/v1beta1` (reuse wiring) vs `ADA.security.r6.dev/v1` (verbatim); thin status reconciler vs read-only by `InferenceRotationReconciler`. **Also: the `GatekeeperViolation` trigger in Listing 1 has NO source in any repo — no OPA Gatekeeper audit emitter exists; it is a hard prerequisite for half of Listing 1's triggers.**

<a id="d22"></a>**D22 — Idempotence / anti-flap / unhealthy-replacement guard.** The NIM loop can delete-every-requeue; a mutating loop must not rotate before the prior replacement is Ready, must back off if the new image crash-loops, and must not thrash on a score oscillating near a band boundary (ADA §6.2 "churn needs careful management"; §5.3.7 "over-rotation hiding persistent threats"). Options: min-interval + readiness gate + crash-loop backoff/rollback to last-known-good; PodDisruptionBudget + maxUnavailable; circuit-breaker on repeated failed rotations; post-rotation cooldown + EWMA-smoothed score; require N consecutive high samples before panic.

### GPU / memory

<a id="d17"></a>**D17 — GPU shuffle semantics, granularity, and distinct-binding.** The papers **contradict**: §IV.C.1 prose says "reassign GPU bindings incl. MIG/NVLink" (keeps inference alive) but the only manifest (ADA Listing 1) sets `nvidia.com/gpu "0"` (removes GPU access). And the stock device plugin advertises a **count**, not per-UUID schedulability, so "bind to a different specific GPU" is **not expressible with stock K8s**. ⚠️ *Invention guard:* `DropToZero` is the only verbatim-supported behavior; `Reassign` is the marketed intent. Options for **semantics:** `Reassign` (per-UUID anti-affinity — needs non-standard per-UUID schedulability) / `DropToZero` (literal Listing 1, treat as GPU-quarantine) / node/pod anti-affinity only (coarse) / all three via `Mode`. **Granularity:** whole-GPU anti-affinity / MIG-profile resource names + MIG manager / NVLink-group-aware custom scheduler (no standard primitive) / NVIDIA GPU Operator + GPU Feature Discovery + dynamic MIG. **Distinct-binding:** hard-required vs best-effort + single-GPU fallback.

<a id="d18"></a>**D18 — Is the GPU=0 rotated pod meant to keep serving or be quarantined?** Listing 1 literally zeroes the GPU, which makes the replacement unable to serve GPU inference. Either the example conflates "secure-mode" with "quarantine", or normal rotation keeps the GPU and only threat-triggered rotation zeroes it. Options: two modes (normal keeps GPU, panic sets 0); always policy-driven from CRD; treat 0 as example-only.

<a id="d19g"></a>**D19g — What is "encrypted" in "encrypted ephemeral memory volumes"?** tmpfs (`emptyDir medium=Memory`) is memory-resident but **not** cryptographically encrypted; real encryption needs dm-crypt/LUKS or a CSI encrypting driver. Options: tmpfs only (fast, no crypto, weak vs root co-resident); LUKS/dm-crypt init container; CSI transparent at-rest encryption; TEE/confidential-VM memory encryption (hardware, ADA §6.3.4 future work).

<a id="d20g"></a>**D20g — Ephemeral key management: source, trust root, destruction.** Paper names no keystore, cipher, key length, or trust root, yet "keys destroyed at container termination" is the crux. ⚠️ *Invention guard:* `CipherSuite`/`KeyBytes` are left open, not filled. Options for **source:** per-pod generated K8s Secret (itself readable via API/etcd) / external KMS/Vault short-TTL leases / SPIFFE/SPIRE per-workload key / TEE-sealed. **Destruction:** finalizer running `DestroyKey` / Secret ownerRef GC / KMS lease expiry — and guard the **destruction race** (do not destroy before the foreign-controller-recreated replacement gets its key).

<a id="d21g"></a>**D21g — How is "inference cycle" (ADA "re-key on EVERY inference cycle") mapped to K8s?** A pod-operator has **no** visibility into individual inference requests; it can only act on pod rotation/reconcile. Options: approximate "inference cycle" as "pod rotation" (operator-only, document the gap); ship an in-pod re-key sidecar/agent the operator provisions but does not drive (new component); require the model server (NIM/vLLM) to re-key itself and have the operator only provision the volume/key.

<a id="d23g"></a>**D23g — Privileged-vs-unprivileged co-resident threat model.** Software tmpfs + K8s Secrets do **not** protect against a root/host or hypervisor-level co-resident adversary (§III.C.4 shared memory/cache timing/PCIe); only hardware Confidential Computing / TEEs do, which ADA §6.3.4 **defers**. Options: unprivileged co-resident only (tmpfs + Secret suffices); privileged co-resident (requires TEE/confidential VM / SEV-SNP / TDX — large scope, hardware dependency).

<a id="d24g"></a>**D24g — RAG Sandbox isolation primitive + TTL.** No TTL value and no isolation mechanism given. Options for **isolation:** deny-all NetworkPolicy (reuse Quarantine path L285–348) / dedicated namespace / gVisor-Kata runtimeClass (also serves "Ephemeral Model Wrappers"). **TTL:** user-set duration tied to cap #4.

### Node rotation

<a id="d25g"></a>**D25g — API shape for node rotation.** `AMTDAction.NodeRotate` (panic) + `AMTDSpec.NodeRotationPolicy` (scheduled) with status in AMTD vs a dedicated cluster-scoped `NodeRotation` CRD for in-flight drains (better restart-safety/observability) vs action-only (panic-only v1). Also: is scheduled node rotation in-scope for v1 at all (node rotation is far costlier than pod rotation)?

<a id="d25g2"></a>**D25g2 — Source-node disposition.** Cordon (reversible) / Taint NoSchedule (keeps co-tenants) / Taint NoExecute (evicts co-tenants) / Cordon+full-drain / delete the Node object + terminate the cloud instance (most aggressive, needs cloud-provider integration). Paper says only "move to a clean node" — does not specify what happens to the old node.

<a id="d25g3"></a>**D25g3 — Co-tenant drain scope.** Relocate only the targeted inference pod + cordon (safe, leaves attacker with other tenants) vs drain all pods (respect PDBs via Eviction — best vs co-location but cascades disruption) vs drain only other AMTD-managed pods vs configurable via `DrainPolicy`.

<a id="d25g4"></a>**D25g4 — What operationally defines a "clean, isolated node"?** The destination of every rotation; without a precise definition the controller cannot pick a target and could relocate onto an equally-compromised node. Also covers **how the relocated pod is pinned** (injected `nodeAffinity`/`nodeSelector` on the owner template (affects all replicas) vs one-shot `spec.nodeName` (bypasses scheduler) vs taint source NoExecute vs scheduler plugin) and **stateful/PVC/GPU-on-destination** (local PV / topology-bound PVC may be unschedulable; clean pool must have free GPUs of the right type/MIG profile). Options for "clean": admin pre-provisioned label pool (`r6security.com/clean-pool=true`) / any untainted node with zero flagged pods / freshly autoscaled node (autoscaler/Karpenter) / cryptographically attested node (TPM) / dedicated single-tenant node. Also: define the **target-set** (NIM has no inference selector — "the inference pods NIM manages" is currently ill-scoped) and **crash-mid-drain rollback** semantics.

<a id="d26"></a>**D26 — How is the node-rotation trigger authenticated/authorized?** The new primitive grants node-write + pod-eviction RBAC; an attacker able to forge `SecurityEvents` (cluster-scoped, emitted by thin REST POSTs) could cordon/taint/delete **every** node → cluster DoS. Options: restrict `NodeRotate` to a trusted `Source` allowlist + `ThreatLevel` floor; require admin opt-in via clean-pool/managed label; rate-limit + `MaxConcurrentNodes` cap; admission webhook validating SecurityEvent provenance; require human approval for `Delete`-node disposition.

### Benchmark targets (no paper number is a guarantee)

<a id="d27"></a>**D27 — All quantitative SLOs.** Every figure in the corpus (`400s→15s` downtime, `Persistence 95%+→<4%`, `Dwell 150+ days→<60min`, `MTTR<5min`, availability `99.8%`, overhead `1–2%` / `1.3–1.7%`, `94%` disruption, `MODEL_ROTATION 3.2s`, ASR `<10%`) is an **asserted/marketing/dashboard value with no measurement code anywhere in the 5 repos**, and several (`<5min`, `99.8%`) are for *rotation*, not the specific capability (e.g. drift self-heal, node rotation). *Why:* they cannot be acceptance criteria without an owner setting the real SLO and building a benchmark harness. For each metric in each capability's "Proof it works" table marked **USER DECISION**, decide: adopt the paper figure as a target / set an internal SLO from a load test / treat as informational until a benchmark exists. Note GPU-rebind or node cordon-drain **without** a warm pool likely *increases* downtime (cold re-attach), so cold and warm baselines must be measured separately.

---

## What was deliberately NOT invented

This spec refused to fabricate any value the papers leave open. The following kinds of specifics are **flagged decisions**, not chosen answers — each points to the [Decisions section](#decisions-needed-from-you-consolidated):

- **Scheduling:** the jitter distribution shape, the exact jitter percent (the papers give a **10–30% band**, never a single number — any "20%" is a band midpoint, not fact), the entropy source, the per-pod stagger algorithm, the production R and its floor, and the concurrency budget. → [D5](#d5), [D9](#d9), [D10](#d10), [D12g](#d12g), [D13](#d13), [D14](#d14), [D24](#d24)
- **Endpoint identity:** the hash function, the hash input, the (un)forgeability/key scheme, and the TTL value. → [D15](#d15), [D16](#d16)
- **Image trust & signing:** the signature scheme (cosign/Notation/SLSA/digest-only), the signer identity / trust root, the verification point, the comparison surface, and the fail-open-vs-closed mode — plus the explicit caveat that **signing ≠ benignity**. A hard-required `@sha256:` digest **regex** was downgraded to a flagged default (the paper mandates no digest syntax). → [D6](#d6), [D6g](#d6g)
- **Warm-pool / LWS:** the operational definition of "warm"/"ready in RAM", the pool size N, LWS-vs-in-tree, and the entire traffic-steering primitive enumeration (`EndpointSwap`/`ServiceSelectorSwap`/`GatewayWeight`/`LeaderLabel` is design-authored). → [D11](#d11), [D12](#d12)
- **Telemetry scoring:** the anomaly-scoring formula, the GPU-entropy/query-deviation/cache-miss weights (example `{0.5/0.3/0.2}` is illustrative), the normalization, the S→interval curve, the panic threshold, the score provenance/trust root, and the metric query expressions (PromQL is unauthored; "GPU entropy"/"query deviation" are not standard metrics). The `ContextMutationPolicy` API group and the **non-existent OPA-Gatekeeper-violation source** are flagged. → [D7g](#d7g), [D19](#d19), [D20](#d20), [D22](#d22), [D25](#d25), [D26g](#d26g)
- **GPU / memory:** the GPU shuffle semantics (`Reassign`-vs-`DropToZero` corpus contradiction — only `DropToZero` is verbatim-supported), the shuffle granularity, the GPU=0 serve-vs-quarantine meaning, what "encrypted" means (tmpfs ≠ cryptographic), the cipher/key length/keystore, the "inference cycle" → K8s mapping, and the privileged-vs-unprivileged co-resident threat boundary. → [D17](#d17), [D18](#d18), [D19g](#d19g), [D20g](#d20g), [D21g](#d21g), [D23g](#d23g), [D24g](#d24g)
- **Node rotation:** the definition of "clean/isolated node", the source-node disposition, the co-tenant drain scope, the node-rotation interval, the pod-pinning mechanism, the cloud-instance-termination boundary, and the trigger-authn model (it is a cluster-DoS lever). `Cordon` / `N=20` history / clean-pool label are proposed defaults, not paper values. → [D25g](#d25g)–[D25g4](#d25g4), [D26](#d26), [D9](#d9)
- **All quantitative targets:** every downtime / dwell / persistence / MTTR / availability / overhead figure is a paper claim with **no measurement code today** and is treated as a target-to-confirm, not a guarantee. → [D27](#d27)
- **Structural choices** (config home, which controller owns rotation, how a mutation survives ReplicaSet recreate, whether to relax the exact-match matcher) are presented as forks with options, never as a decided architecture. → [D1](#d1), [D2](#d2), [D3](#d3), [D21](#d21)
