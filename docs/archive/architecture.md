# Phoenix AMTD — Locked Architecture & Build Plan

> **Status: LOCKED.** This is the single, internally-consistent architecture implied by the locked decisions (36/36 anchors resolved exactly once), plus a sequenced build plan. It is **design only** — no controller implementation code. It is faithful to the corpus, accuracy-disciplined, and obeys the two global design rules.
>
> **Corpus** = 4 R6 papers (`adaptive-container-orchestration` / "Proactive", `amtd-ai-infrastructure-security` / "AMTD-AI", `ada-amtd-ai-workloads` / "ADA", `phoenix-adaptive-containers` / "PHOENIX") + 2 product pages (Phoenix-for-AI, FAQ).
> **Code base** = 5 repos: `phoenix-main` (the operator), `prometheus-integrator`, `falco-integrator`, `kubearmor-integrator`, `time-based-trigger`.
>
> **Accuracy legend used throughout:** `[PAPER-SPECIFIED]` = verbatim in a paper; `[PAPER-CONTRADICTION]` = corpus conflicts, a decision was made; `[DESIGN-DECISION]` = papers silent, our choice; `[R6-PAPER-ONLY]` = an asserted/marketing/dashboard figure with **no** measurement code, kept as a target-to-confirm.

---

## 1. Design rule & principles

### 1.1 The two global design rules

**Rule #1 — Every action is a Strategy entry.**
Every effect Phoenix performs on a workload (a *class-(A) action*) is expressible as a `Strategy[]` entry `{Rule → AMTDAction}` **and** is triggerable by a `SecurityEvent`. Nothing is reachable only via an internal timer or a hard-coded code path. The one historically hard-coded gate — the NIM `FindTimedEvent` check (`nim_controller.go` L121, impl L136-143, matching `Type=='timed' && Source==TriggerSource`) — **dissolves** into a strategy rule `{Type:'timed', Source:'TimeBasedTrigger'} → {rotate}` (or `{warmSwap}`/`{delete}`). The cluster's only policy surface stays `Strategy[]`.

**Rule #2 — A computed score can select an action, exact rules unchanged.**
The action matcher is relaxed so a computed anomaly score / threshold can select an action, **while existing exact-match `{Type, ThreatLevel, Source}` rules keep working byte-for-byte**. This is realized by replacing the bare `reflect.DeepEqual(strategy.Rule, securityEvent.Spec.Rule)` at `securityevent_controller.go` **L139** with `MatchStrategy(strategy.Rule, ev.Spec)`, preserving the L138-143 first-match-wins loop and the **L146** zero-value sentinel `action != (amtdv1beta1.AMTDAction{})`.

### 1.2 Two classes of reconcile (so loops are not misread as triggers)

- **Class-(A) ACTIONS** (the rule-#1 surface): `Delete / Quarantine / Debugger / CustomAction / Rotate / WarmSwap / Regenerate / NodeRotate`. Each is a `Strategy[]` entry and SecurityEvent-triggerable.
- **Class-(B) MAINTENANCE / CONTINUATION reconciles** (NOT actions, NOT trigger paths): a controller keeping its **owned** CRD at desired state — `WarmInferenceSet` keeping N shadows Ready (a readiness loop, like a Deployment keeping replicas), and `NodeRotation` progressing an **already-matched** in-flight drain to completion across operator restart. **Locked invariant:** no class-(B) reconcile may initiate a rotation/swap/node-move that the matcher did not first select from a SecurityEvent (or from a `time-based-trigger`-emitted, matched, scheduled event).

### 1.3 Locked invariants (the guarantees this architecture must preserve)

1. **Backward-compatible matcher (per-STRATEGY, proven).** Any `ResponseStrategy` whose `Rule` sets only `{Type, ThreatLevel, Source}` (`Match==nil && ScoreThreshold==nil`) is selected with the **identical outcome** of today's `DeepEqual`, evaluated as equality of the 3-string projection — *even when a scored strategy coexists in the same `Strategy[]`* (the whole-struct DeepEqual is deliberately narrowed to the 3 strings so siblings are independent). Emitters never set event-side `Rule.Match/ScoreThreshold` (verified: `prometheus-integrator` `main.go` L140-144, `time-based-trigger` `pod_controller.go` L195-199), so an event cannot perturb the exact projection. The L146 sentinel and L138-143 loop are preserved. Scored evaluation is opt-in per-AMTD (`MatcherMode='Exact'` default); in Exact mode any `Match/ScoreThreshold` is inert and a `MatcherModeWarning` Status condition warns.
2. **Additive-only API evolution.** Every new field on `SecurityEventSpec` (`AnomalyScore/Metrics/Evidence`), `Rule` (`Match/ScoreThreshold`), `AMTDSpec`, and `AMTDAction` is pointer/`omitempty`, so all emitters keep compiling against the shared `github.com/r6security/phoenix/api/v1beta1` module and a nil field == today's behavior. `make generate` regenerates deepcopy for **all** new embedded types; `make manifests` republishes the CRD schema.
3. **MaxProperties=1 preserved** (verified `adaptivemovingtargetdefense_types.go` L248-255). `AMTDAction` stays an all-pointer tagged union with ≤1 member set on the serialized object (apiserver-enforced; zero is also valid and is the no-match sentinel). Each new action is reachable only as its own `Strategy[]` entry. Adding pointer members keeps the struct comparable, so the in-Go L146 `!=` sentinel is unaffected.
4. **Every action is a Strategy entry** (rule #1, see §1.1).
5. **No rotation storm.** Mutating rotation is one-shot (one SecurityEvent ⇒ one action); no controller self-requeues to re-mutate (NIM L131-132 demoted to pass-through except as the designated cold fallback). A min-interval + readiness gate + crash-loop backoff/rollback-to-last-known-good + score-hysteresis (EWMA + N-consecutive-high) guard every mutating path. Exactly one controller owns a given pod (disjoint selectors + an in-progress annotation; NIM early-returns on it).
6. **Single cadence owner.** The jittered clock lives in exactly one place (`time-based-trigger`, `pod_controller.go`); NIM's self-requeue is pass-through so the same logical rotation is never double-jittered. Cadence uses a crypto entropy source.
7. **Durable mutation or explicit non-durability.** A mutation is durable **only** via (b) create-new-then-cutover (warm pool, per-instance) or (a) patching the **top-level** owner template when the rotation is workload-wide (all replicas; never a bare ReplicaSet; guarded against the AMTD self-Update webhook loop). For (i) bare/unmanaged pods, (ii) Job-owned pods (`.spec.template` is immutable), and (iii) per-pod panic events on a shared-template owner without a warm pool, durable per-pod mutation is physically impossible — Status records `mutation-not-durable` with a reason (`BarePod | ImmutableJobTemplate | PerPodOnSharedTemplate`) rather than silently losing or falsely claiming the mutation.
8. **Score trust root.** Anomaly scores are authoritative only when carried on the cluster-scoped, RBAC-gated `SecurityEvent.Spec.AnomalyScore` written by trusted integrator ServiceAccounts. Workload ServiceAccounts **must not** be granted `securityevents` create/update; pod-annotation scores never drive rotation; a `StalenessWindow` decays old scores to 0 (neither suppression nor pinning survives staleness); an optional `:9443` admission webhook may enforce a trusted-Source allowlist. A Source-guarded score rule additionally requires the named integrator to actually populate `AnomalyScore`.
9. **No fabricated paper claims.** All quantitative SLOs are `[R6-PAPER-ONLY]` targets-to-confirm with no measurement code. The Reassign-vs-DropToZero GPU contradiction is a documented decision (DropToZero is the only verbatim behavior). The GatekeeperViolation trigger is reported as having **no** emitter in any repo, never invented. Panic threshold `0.85`, `Cordon` default, `N=20` node-history, `5m` interval floor, `60s` minInterval, `15m` RAG TTL, illustrative `{0.5,0.3,0.2}` weights, and the `Uniform;TruncatedNormal` / `SHA256;HMAC-SHA256` / traffic-steering enums are flagged design-authored proposals. Literal mutation values (`nvcr.io/nim/secure-nim:latest`, `RUNTIME_MODE=SECURE`, `nvidia.com/gpu:'0'`) are verbatim from ADA Listing 1.
10. **Status is the audit/feedback substrate.** The two currently-empty Status structs are populated (subresource already enabled, `AMTD` L290 / `SecurityEvent` L51). `mutation-not-durable`, the won config source (D1), and which rotation path fired (D2) are recorded there. No capability relies on an out-of-band side channel.

> **NEW locked invariant (added at lock time) — Per-integrator threat-level/type normalization prerequisite.**
> Verified emitter output: `falco-integrator` (`cmd/main.go` L112-114) emits `Type = response.Rule` (the **Falco rule name**), `ThreatLevel = response.Priority` (`Critical/Warning/Notice/Informational`), `Source='FalcoIntegrator'`; `kubearmor-integrator` (L60-84) emits `Type = policyEvent.PolicyName`, `ThreatLevel = policyEvent.Severity` (numeric `1`..`10`), `Source='KubeArmorIntegrator'`. Therefore the literal guard tokens `Type:'panic' | 'drift' | 'policy-violation'` and `threatLevel In {high,critical}` are **not emitter-native**. Any conformance row guarding on them is **inert** until either (a) each integrator is additively extended to map its native vocabulary onto the canonical `{info,low,medium,high,critical}` set and map rule-name → `Type` (Falco Container-Drift → `Type:'drift'`, runc/escape → `Type:'panic'`), **or** (b) the AMTD guard is authored in the integrators' native vocabulary (e.g. `threatLevel In 'Critical,Warning'` for Falco, or `Rule.Match{Field:'threatLevel', Op:'Gte'}` numeric for KubeArmor). The **`Source` guard is emitter-native** and is the load-bearing half of the D26 cluster-DoS allowlist — it is kept. Inertness is **fail-safe** (no forged eviction, no false self-heal) and is documented as a prerequisite, never shipped implemented-and-broken — exactly the discipline already applied to the GatekeeperViolation gap and the score-carrier dependency.

---

## 2. Public CRD interface (the locked surface)

### 2.1 The extended `AMTDAction` union

`AMTDAction` stays a `+kubebuilder:validation:MaxProperties=1` all-pointer tagged union. **Existing members are preserved byte-for-byte**; four new pointer members are added (each its own json-tagged `omitempty` optional). The struct stays comparable, so the L146 `!=` sentinel is unchanged; the apiserver enforces ≤1 populated key on the serialized object (zero keys is still the in-Go no-match sentinel that falls through to the L370 "NOT IMPLEMENTED YET" slot).

```go
// +kubebuilder:validation:MaxProperties=1
type AMTDAction struct {
    Disable      *DisableAction    `json:"disable,omitempty"`      // existing — was the L370 NOT-IMPLEMENTED fall-through; now implementable
    Delete       *DeleteAction     `json:"delete,omitempty"`       // existing cold rotation primitive (r.Client.Delete L198)
    Quarantine   *QuarantineAction `json:"quarantine,omitempty"`   // existing deny-all NetworkPolicy (L285-369)
    Debugger     *Debugger         `json:"debugger,omitempty"`     // existing (L204-241)
    CustomAction *CustomAction     `json:"customAction,omitempty"` // existing (L242-284)

    Rotate       *RotateAction     `json:"rotate,omitempty"`       // NEW caps#1/#3 mutating rotation (image/env/gpu/memory/RAG/endpoint)
    WarmSwap     *WarmSwapAction   `json:"warmSwap,omitempty"`     // NEW cap#2 leader→warm-shadow cutover
    Regenerate   *RegenerateAction `json:"regenerate,omitempty"`   // NEW cap#6 restore-from-signed-baseline
    NodeRotate   *NodeRotateAction `json:"nodeRotate,omitempty"`   // NEW cap#7 panic-move to clean node
}

// RotateAction subsumes the image/env/gpu/key/RAG mutation set. Its fields mirror
// InferenceRotationSpec so a Rotate action and Spec.InferenceRotation resolve through
// the SAME MutationApplier. With all fields nil, RotateAction degrades to today's cold delete.
type RotateAction struct {
    PolicyRef *LocalPolicyRef           `json:"policyRef,omitempty"` // ref to AMTDSpec.InferenceRotation or a ContextMutationPolicy; nil ⇒ matched AMTD's InferenceRotation
    Overrides *InferenceRotationOverlay `json:"overrides,omitempty"` // inline image/env/gpu overlay for panic-only mutations (e.g. gpuResource:'0')
}

type WarmSwapAction struct {
    WarmInferenceSetRef *LocalRef `json:"warmInferenceSetRef,omitempty"`
    DrainTimeoutSeconds *int64    `json:"drainTimeoutSeconds,omitempty"` // default reuse NIM grace 30s
}

type RegenerateAction struct {
    BaselineRef           *LocalRef `json:"baselineRef,omitempty"`
    ResetHardeningProfile bool      `json:"resetHardeningProfile,omitempty"`
}

type NodeRotateAction struct {
    Strategy           string            `json:"strategy,omitempty"`           // Cordon;Taint;Delete — default Cordon (proposal)
    DrainPolicy        *DrainPolicy      `json:"drainPolicy,omitempty"`        // nil ⇒ relocate targeted pod only, no co-tenant drain
    TargetNodeSelector map[string]string `json:"targetNodeSelector,omitempty"` // clean-pool selector
}
```

**Per-action `Strategy[]` expression** (every action **is** one Strategy entry ⇒ rule #1; literal values trace to ADA Listing 1 or are flagged proposals):

| Action | `Strategy[]` expression |
|---|---|
| Disable | `{rule:{type:'disable'}, action:{disable:{}}}` |
| Delete | `{rule:{...}, action:{delete:{}}}` (unchanged cold primitive) |
| Quarantine | `{rule:{...}, action:{quarantine:{}}}` |
| Debugger | `{rule:{...}, action:{debugger:{image:...}}}` |
| CustomAction | `{rule:{...}, action:{customAction:{...}}}` |
| Rotate (timed) | `{rule:{type:'timed', source:'TimeBasedTrigger'}, action:{rotate:{}}}` — replaces the hard-coded NIM `FindTimedEvent` gate |
| Rotate (panic) | `{rule:{source:'FalcoIntegrator', match:[{field:'anomalyScore',op:'Gte',value:'0.85'}]}, action:{rotate:{overrides:{gpuResource:'0', envPatch:[{name:'RUNTIME_MODE',value:'SECURE'}]}}}}` ¹ |
| WarmSwap | `{rule:{type:'timed', source:'TimeBasedTrigger'}, action:{warmSwap:{warmInferenceSetRef:{name:'nim-pool'}}}}` |
| Regenerate | `{rule:{type:'drift', source:'FalcoIntegrator'}, action:{regenerate:{baselineRef:{name:'nim-baseline'}}}}` ² |
| NodeRotate | `{rule:{source:'KubeArmorIntegrator', match:[{field:'threatLevel',op:'In',value:'high,critical'}]}, action:{nodeRotate:{strategy:'Cordon'}}}` ² |

> ¹ Requires `falco-integrator` extended to set `Spec.AnomalyScore` (score-carrier prerequisite). Until then this row degrades to a `Source`/`ThreatLevel`-guarded panic with no score magnitude.
> ² **`Type:'drift'` / `threatLevel In high,critical` are not emitter-native** — inert until the per-integrator normalization prerequisite (§1.3) lands. The `Source` guard is emitter-native and load-bearing today. The `NodeRotate` row keys on `Source + ThreatLevel` and needs **no numeric score** (works on the score axis with unextended integrators; the *string* guards still require normalization).

### 2.2 The relaxed matcher

**Rule shape** (additive, all-optional ⇒ existing Rule CRs serialize identically and pass the apiserver schema unchanged):

```go
type Rule struct {
    Type        string `json:"type"`        // existing
    ThreatLevel string `json:"threatLevel"` // existing
    Source      string `json:"source"`      // existing
    // +optional NEW — matcher-side only; emitters NEVER set these on events
    Match          []MatchExpression `json:"match,omitempty"`          // computed-score / metric predicates
    ScoreThreshold *string           `json:"scoreThreshold,omitempty"` // sugar for a single anomalyScore>=X clause
}

type MatchExpression struct {
    Field string `json:"field"` // 'type'|'threatLevel'|'source'|'anomalyScore'|'metrics.<k>'
    Op    string `json:"op"`    // Eq|NotEq|In|NotIn|Gte|Gt|Lte|Lt|Exists
    Value string `json:"value"` // scalar or comma-list; numeric ops parse decimal
}
```

**Predicate signature** (replaces the bare `DeepEqual` at L139):

```go
// MatchStrategy is a STRICT SUPERSET of today's reflect.DeepEqual(strategy.Rule, ev.Spec.Rule).
// It reads ev.Spec (NOT only ev.Spec.Rule), which is what makes ev.Spec.AnomalyScore reachable.
func MatchStrategy(rule Rule, ev SecurityEventSpec) bool
```

**Evaluation & precedence (deterministic):**

1. **Exact fast path (default, backward-compat).** If `rule.Match==nil && rule.ScoreThreshold==nil`: evaluate equality of the **3-string projection** `{Type, ThreatLevel, Source}` of `rule` against `ev.Spec.Rule`. This is outcome-identical to today's `DeepEqual` by the byte-compat theorem (below). The whole-struct `DeepEqual` is deliberately narrowed to the 3 strings so adding `Match` to one strategy cannot break a sibling exact strategy in the same AMTD.
2. **Scored path.** If `rule.Match` or `rule.ScoreThreshold` is set: a **conjunction (AND)** of — (i) every **non-empty legacy string field** of `rule` (`Type/ThreatLevel/Source`) still equals `ev.Spec.Rule`'s same field (a Source/Type **guard** so a score clause cannot match unrelated events); **AND** (ii) every `MatchExpression` holds against `ev.Spec` (`anomalyScore` parsed via the `[0,1]` decimal-string representation; `metrics.<k>` from `SecurityEventSpec.Metrics`; `type/threatLevel/source` from `ev.Spec.Rule`). `ScoreThreshold X` ≡ `Match{Field:'anomalyScore', Op:'Gte', Value:X}`. A clause referencing `anomalyScore` against an event with nil `AnomalyScore` evaluates **false** (no panic, never selects) — this is what makes the contract change safe to land before scoring exists (Phase 0 inertness).
3. **First-match-wins** within `Strategy[]` order (unchanged L138-143). Author precedence by ordering more-specific scored rules before broad exact rules. Determinism is total because `Strategy[]` is an ordered list.
4. **Feature flag.** Scored evaluation lives behind a per-AMTD `Spec.MatcherMode` enum: `Exact` (default) | `Scored`. In `Exact`, any `Match/ScoreThreshold` is **ignored** and a `MatcherModeWarning` Status condition warns the clauses are inert — guaranteeing zero behavior change for clusters that never opt in.

**Byte-compat theorem (locked).** For any `(strategy.Rule, ev.Spec)` where `strategy.Rule.Match==nil && strategy.Rule.ScoreThreshold==nil`, `MatchStrategy` returns exactly what today's `reflect.DeepEqual(strategy.Rule, ev.Spec.Rule)` returns. *Proof:* today's whole-struct DeepEqual, when both Rules have nil `Match/ScoreThreshold` (legacy CRs and legacy events both do), reduces to equality of `{Type,ThreatLevel,Source}` (the only populated fields) — identical to the 3-string projection. Emitters never populate `ev.Spec.Rule.Match/ScoreThreshold` (verified), so an event's `Match/ScoreThreshold` are always nil and cannot perturb the projection. The guarantee is **per-strategy**: an exact strategy is evaluated exactly even when a scored strategy sits in the same `Strategy[]`.

### 2.3 The `SecurityEvent` contract (additive)

`SecurityEventSpec` (`securityevent_types.go` L28-42) gains pointer/optional fields so every emitter keeps compiling against the shared module:

```go
AnomalyScore *string           `json:"anomalyScore,omitempty"` // decimal '0'..'1'; cap#5. On SPEC, NOT on Rule, so Rule stays a pure match key.
Metrics      map[string]string `json:"metrics,omitempty"`      // raw component signals (GPU entropy/query-dev/cache-miss); in-operator recompute/audit
Evidence     *DriftEvidence    `json:"evidence,omitempty"`     // {ObservedDigest, ExpectedDigest, Detail}; cap#6
```

**Score representation (D19):** `AnomalyScore` is a **decimal string in `[0,1]`** (e.g. `'0.85'`), pointer/optional (nil ⇒ unscored = today). Decimal-string-on-Spec avoids float canonicalization instability across JSON/etcd round-trips and keeps `Rule` a pure match key (so the exact fast path is preserved). Range `[0,1]` matches the literal "proportional to anomaly scores" framing.

**Provenance / trust root (D26g):** `AnomalyScore` is authoritative **only** when carried on this cluster-scoped, RBAC-gated CR written by **trusted integrator ServiceAccounts**. A stock workload ServiceAccount has no `securityevents` create grant, so it cannot mint or amend a SecurityEvent about itself (this is what defeats the defense-inversion: a compromised workload forging a low score to suppress its own rotation). Pod-annotation scores are **disallowed** as authority. A `StalenessWindow` decays old scores to 0. Optional hardening: a `:9443` validating webhook checking the creating SA is on a trusted-Source allowlist.

**Populated Status structs** (subresource already enabled — `AMTD` L290 / `SecurityEvent` L51):

```go
// AdaptiveMovingTargetDefenseStatus — per-workload AGGREGATE on the policy object
type AdaptiveMovingTargetDefenseStatus struct {
    ObservedGeneration int64
    CurrentInterval    metav1.Duration
    LastObservedScore  string
    LastRotationTime   metav1.Time
    RotationCount      int64               // mirrors the dangling NIM_RESCHEDULE_COUNT (nim_constants.go L31)

    // D22 anti-flap state (restart-safe; lives here, NOT in controller memory)
    SmoothedScore        string
    ConsecutiveHighCount int
    FailedRotationCount  int
    LastKnownGoodRef     *LocalRef
    BackoffUntil         metav1.Time

    EffectiveSource  string // embedded-vs-CR won (D1)
    RotationPathFired string // Rotate|WarmSwap|NodeRotate|cold (D2)
    MutationDurable  bool
    MutationNotDurableReason string // BarePod|ImmutableJobTemplate|PerPodOnSharedTemplate (D3)

    WarmPool struct{ ActiveLeader string; ReadyShadows int; LastSwapDurationMillis int64 }
    Baseline struct{ LastVerifiedTime metav1.Time; PinnedDigests []string; DriftDetections int; LastRegeneration metav1.Time }
    NodeRotations []NodeRotationRecord // BOUNDED, cap N=20 (flagged proposal); {SourceNode,TargetNode,PodName,Time,Phase}

    ThreatBoundary   *ThreatBoundaryStatus // {CoResidentScope:'Unprivileged', PrivilegedAdversary:'OutOfScope-TEEDeferred'}
    Conditions []metav1.Condition // +listType=map +listMapKey=type — incl. MatcherModeWarning, Panic, MutationNotDurable, VerificationUnavailable, EntropyWarning, NoCleanTarget
}

// SecurityEventStatus — per-event OUTCOME on the trigger object
type SecurityEventStatus struct {
    AppliedAction    string
    ObservedScore    string
    ComputedInterval metav1.Duration
    ProcessedAt      metav1.Time
}
```

The long tail of per-event history goes to **k8s Events**, not Status (Status is not an event log; unbounded growth bloats etcd). The RL feedback loop (ADA Fig.1) is **out of scope** — only the substrate it would read is populated.

### 2.4 Config home (D1 = HYBRID) — consolidated field additions & new CRD types

**Embedded on `AdaptiveMovingTargetDefenseSpec`** (optional pointers, nil ⇒ today's behavior; reuses `PodSelector` L35 / `Strategy` L40 / `AMTD_MANAGED_BY` enrollment / existing RBAC; only `make manifests` + `make generate` needed, no new CRD):

- `InferenceRotation *InferenceRotationSpec` holding:
  - `RotationPolicy` (cap#4 cadence): `BaseInterval` (Required `metav1.Duration`, default 60m, webhook floor ≥5m); `JitterMinPercent/JitterMaxPercent` (defaults 10/30 = paper band endpoints); `JitterDistribution` (enum `Uniform`(default)`;TruncatedNormal`); `EntropySource` (enum `Crypto`(default)`;PseudoRandom`); `StaggerMode` (enum `PerPodPhaseOffset`(default)`;Independent;None`); `MaxConcurrentRotations *int` (nil ⇒ unlimited); `MinInterval` (default 60s, the anti-flap floor); `Endpoint *EndpointRotationPolicy`.
  - `AdaptiveRotation *AdaptiveRotationPolicy` (cap#5): `PanicThreshold` (default `0.85`, flagged), `ScoringPolicy` (optional, **no default weights**), `StalenessWindow`, `EWMAAlpha`, `ConsecutiveHighSamples`, `MaxFailedRotations`.
  - `GPUShuffle *GPUShufflePolicy` (cap#3): `ResourceName` (default `nvidia.com/gpu`), `Mode` (enum `DropToZero`(default)`;Reassign;AntiAffinity`), `RequireDistinctBinding bool` (default false).
  - `EphemeralMemory *EphemeralMemoryPolicy` (cap#3): `Medium` (enum `Memory`(default, tmpfs)`;Disk`(CSI)), `KeySourceRef *KeySourceRef{Type enum GeneratedSecret(default)|KMS|Vault|TEESealed; SecretRef/KMSKeyRef/VaultPath; CipherSuite string; KeyBytes int}` (**no default cipher/length**), `RekeyOn` (enum `Rotation`(default)`;InferenceCycle`).
  - `RAGSandbox *RAGSandboxPolicy` (cap#3): `Isolation` (enum `DenyAllNetworkPolicy`(default)`;Namespace;RuntimeClass`), `RuntimeClassName`, `NamespaceRef`, `DataExposureTTL` (default `15m`, flagged).
  - `ConfidentialComputing *ConfidentialComputingPolicy{RuntimeClassName; RequireAttestation bool; Provider enum(SEV-SNP,TDX,SGX)}` — **inert today** (reserves the ADA §6.3.4 TEE seam; nil ⇒ software-only).
- `Baseline *BaselineSpec` (cap#6 digest-pin minimum): `ImageDigests[]`, `Signature *SignaturePolicy{PublicKeyRef; KeylessIdentity{Issuer,SubjectRegexp}; RekorURL; RequireSignature}`, `PodSpecSnapshotRef`, `DriftPolicy{DetectInterval; OnDrift(default Quarantine); AdmissionEnforce(default true); ResetHardeningProfile(default PodProfileOnly)}`, `BaselineRef` (to the standalone CRD).
- `NodeRotationPolicy *NodeRotationPolicy{Enabled; Interval; Jitter; MaxConcurrentNodes; Stagger; TargetNodeSelector}` (cap#7 scheduled cadence; nil ⇒ panic-only).
- `MatcherMode` (enum `Exact`(default)`;Scored`) gating §2.2.
- `InferenceSelector *metav1.LabelSelector` (+ optional image prefixes) — the rotation subject set; also fixes NIM's all-pods watch (see §3).

**Standalone CRDs** (reserved for objects whose lifecycle/restart-safety/observability genuinely exceed a spec field; register at `cmd/main.go` L53 scheme marker; reconcilers above L131 builder marker):

1. `WarmInferenceSet` (namespaced) — owns N warm pods + leader-selecting Service; may wrap `sigs.k8s.io/lws`. This is where D3's **primary** per-instance create-new-then-cutover durability lands. `AMTD`'s `WarmSwapAction.WarmInferenceSetRef` is the only reference (no embedded `WarmPool` block ⇒ single source of truth).
2. `NodeRotation` (cluster-scoped) — models an **in-flight drain** so progress survives operator restart (corroborated by `SecurityEvent` itself being cluster-scoped, verified L52). Class-(B) continuation only.
3. `WorkloadBaseline` (cluster-scoped) — the "Immutable Image Registry" as a distinct, GitOps-friendly component; `AMTD` carries `BaselineRef`. Holds **references** to the external signed registry, never trust-root secret material.
4. `ContextMutationPolicy` — its own kind for ADA-Listing-1 fidelity, but on the **operator group** `amtd.r6security.com/v1beta1` (NOT the paper's literal `ADA.security.r6.dev/v1`, which is non-idiomatic / likely invalid DNS-1123 and would force a second scheme/RBAC surface). A **thin status reconciler**: its triggers emit SecurityEvents routed by the matcher to a `Rotate` action; its `Mutations[]` bind to the **same** `MutationApplier`.

**Precedence (locked):** a referenced CR, when present, **overrides** the embedded block of the same concern; Status records which won (`EffectiveSource`).

> The persisted **jitter seed** (D5) is a **NEW, dedicated, RBAC-gated `Secret`** — *not* a Status or CR field (a CR Status is world-readable to anyone with `get` on the AMTD, which would re-expose the secret cadence). It mirrors the score-trust-root principle.

---

## 3. Control-plane topology & data flow

**Uniform emit-then-match model.** Every signal source becomes a SecurityEvent emitter; the relaxed matcher selects exactly one `AMTDAction`; the responder for that action executes it. The hard-coded NIM `FindTimedEvent` gate dissolves into a strategy rule. Nothing is reachable only via an internal timer.

```
EMITTERS  (unchanged shape; additive payload; all POST cluster-scoped
           SecurityEvent{Targets, Rule[+Match], Description[, +AnomalyScore, +Metrics, +Evidence]}
           via the RBAC-gated securityevents resource; Source strings verified against code)

  Alertmanager --webhook--> prometheus-integrator   (main.go PrometheusHandler L105-157; Source='PrometheusIntegrator' L143;
                                                      now ALSO sets AnomalyScore/Metrics from alert annotations — natural score carrier)
  Falco --------webhook--> falco-integrator          (FalcoHandler; Source='FalcoIntegrator'; Container-Drift rules ENABLED → Type:'drift';
                                                      score-bearing rows require the additive AnomalyScore extension)
  KubeArmor -----gRPC-----> kubearmor-integrator     (Source='KubeArmorIntegrator')
  timer ----------------> time-based-trigger         (buildNewSecurityEvent L183-204; Source='TimeBasedTrigger' L198; SOLE jittered cadence owner)
  drift  ---------------> BaselineDriftReconciler     (emits SecurityEvent{Type:'drift', Evidence}; does NOT act directly)
  [GatekeeperViolation]: NO emitter exists in ANY repo → flagged future-work; gates half of ADA Listing 1's triggers
                                       |
                                       v
  securityevent_controller  (MODIFIED)
   - L139 reflect.DeepEqual(strategy.Rule, ev.Spec.Rule)  →  MatchStrategy(strategy.Rule, ev.Spec)
       [D21 ScoredRuleMatcher; per-AMTD MatcherMode flag; exact fast-path outcome-identical per the byte-compat theorem;
        L138-143 loop + L146 sentinel preserved]
   - dispatch L197-369: keep Delete/Quarantine/Debugger/CustomAction; the L370-372 'NOT IMPLEMENTED YET' slot becomes the
        Rotate branch (and implements Disable); Regenerate/WarmSwap/NodeRotate hand off to siblings
   - writes AMTD_APPLIED_SECURITY_EVENTS onto pod (L182-184) [unchanged cross-controller signal] + SecurityEventStatus (new audit)
   - is the ONE-SHOT EXECUTOR for mutating actions (D2); min-interval + readiness + EWMA + N-consecutive-high + crash-loop guards (D22)
                                       | pod annotation (existing signal) + action handoff
       +-------------------------------+-------------------------------+--------------------------------+
       v                               v                               v                                v
 NIMReconciler (MODIFIED)      WarmInferenceSet (NEW CRD+ctlr)    BaselineDrift (NEW)            NodeRotation (NEW CRD+ctlr)
  - FindTimedEvent gate L121     - golden-image warm pool (LWS)    - VerifyImage/Detect on        - cordon/taint/drain via Eviction (PDB-honoring)
    dissolved into a             - LeaderSwapper.Swap (cap#2;        DetectInterval/watch          - reschedule onto CleanNodeSelector
    {timed,TimeBasedTrigger}       create-new-then-cutover = D3    - emits 'drift' SecurityEvents    (clean-pool label, PVC/GPU precheck)
    strategy rule                  PRIMARY per-instance durability  - baselineAdmission webhook     - in-progress annotation lock vs NIM
  - requeue L131-132 demoted     - MutationApplier (caps#1/#3)        on :9443 (verify-before-      - NodeRotation CRD = restart-safe
    to PASS-THROUGH (no          - shadow-readiness maintenance       recreate at L168/L198)          in-flight drain (class-B continuation)
    double-jitter; cold            = class-B (NOT a trigger path)   - writes baseline Status        - honors MaxConcurrentNodes+Stagger
    fallback only)                                                                                    (no mass-eviction invariant)

  SHARED: ONE MutationApplier + ONE jittered Scheduler (in time-based-trigger) + ONE AnomalyScorer feed all paths.
  ContextMutationPolicy (NEW kind, operator group, D7g): thin status reconciler; its triggers EMIT SecurityEvents routed to Rotate;
    binds to the SAME MutationApplier.
```

**Manager wiring (`cmd/main.go`):** the NIM literal (L123-130) gains `Strategy/Trigger/Scheduler/InferenceSelector` (mirroring `Policy: DefaultNIMPolicy()` L126). New reconcilers (`WarmInferenceSetReconciler`, `NodeRotationReconciler`, `BaselineDriftReconciler`, `ContextMutationPolicyReconciler`, optional `InferenceRotationReconciler`) register above the `//+kubebuilder:scaffold:builder` marker (L131); new API types at `//+kubebuilder:scaffold:scheme` (L53). `baselineAdmission` and the optional SecurityEvent-provenance webhook register on the already-running `:9443` webhook server (L80).

**Mutation-survival routing (D3).** The `MutationApplier` classifies the pod's top owner:
- `WarmInferenceSet`-covered → **per-instance cutover** (warm shadow; PRIMARY).
- mutable Deployment/StatefulSet/DaemonSet **+ workload-wide intent + opt-in** → **owner-template patch** (all replicas; never a bare ReplicaSet; guarded against the AMTD self-Update webhook loop).
- bare pod / Job-owned (immutable template) / per-pod-on-shared-template → **cold fallback** with Status `mutation-not-durable` + reason.

**NIM scope fix.** Verified: NIM watches **all** pods (`For(&corev1.Pod{})` L180, no selector), so "the inference pods NIM manages" is an ill-scoped target set. The new `Spec.InferenceSelector` (or `InferenceWorkloadPredicate`) closes this so a node-move/rotation has a well-defined subject and disjoint-selector ownership is enforceable.

---

## 4. The 7 capabilities under the locked architecture

### Capability 1 — Inference-rotation core (mutating rotation)

**What is built.** Frequent rotation of the inference workload that actually *mutates* it (golden-image digest + `RUNTIME_MODE=SECURE` + GPU adjust), executed as a **one-shot** `Rotate` action selected by the matcher — never the self-perpetuating NIM 10s requeue. The same logical rotation has a single cadence owner (`time-based-trigger`); NIM's self-requeue is demoted to pass-through (cold fallback only). The mutation is made durable via the D3 routing, or its non-durability is recorded honestly.

**Introduces.** `RotateAction` (+`Overrides`/`PolicyRef`); `InferenceRotation` embedded block; the `MutationApplier`; the D22 guard pipeline in the executor.

**Accuracy ledger.** Rotation thesis ("reduce R + higher entropy lowers ASR"), golden-image/secure-mode mutation values, `RUNTIME_MODE=SECURE`, `nvidia.com/gpu:'0'` = `[PAPER-SPECIFIED]` (AMTD-AI §3.2; ADA Listing 1). One-shot-executor + cadence-ownership split + storm guard + mutation-survival mechanism = `[DESIGN-DECISION]` (D2/D3, papers silent). `400s→15s` cold/warm downtime = `[R6-PAPER-ONLY]`.

### Capability 2 — Warm-pool / LWS swap

**What is built.** A `WarmInferenceSet` CRD owning N warm pods + a leader-selecting Service. A `WarmSwap` action cuts the leader to a pre-warmed shadow with near-zero downtime: mark the shadow Ready → atomically flip the leader label so the Service resolves to the shadow → drain in-flight over `DrainTimeoutSeconds` → retire the old leader → re-warm a replacement. This is D3's **primary** per-instance durable-mutation mechanism. "Warm" is defined strictly so the swap is real.

**Introduces.** `WarmSwapAction`; `WarmInferenceSet` CRD with `WarmReadyGate{Probe; MinWarmSeconds; RequireModelLoaded(default true)}`, `Replicas`(Min=1, default 2, flagged), `TrafficCutStrategy`(enum `EndpointSwap;ServiceSelectorSwap`(default)`;GatewayWeight;LeaderLabel`, design-authored).

**Accuracy ledger.** LWS abstraction, "warm-started (≥1)", "ready in RAM", "Routes traffic to active leader" = `[PAPER-SPECIFIED]` (AMTD-AI §3.1/§3.2). **Operational definition of "warm"** (`RequireModelLoaded` = weights GPU-resident + warm-up inference, the load-bearing answer to the false-readiness trap), `N=2` default, traffic-steering enum, Ready-before-flip + drain-before-retire ordering = `[DESIGN-DECISION]` (D11/D12). `400s→15s` = `[R6-PAPER-ONLY]`.

### Capability 3 — GPU shuffle / encrypted ephemeral memory / RAG sandbox

**What is built.** GPU-binding rotation (default `DropToZero` = patch `nvidia.com/gpu:'0'`; opt-in `Reassign`/`AntiAffinity` for per-UUID/whole-GPU anti-affinity), disposable ephemeral-memory volumes with per-rotation key lifecycle, and isolated RAG pods with a data-exposure TTL — all applied as `Rotate` overlays through the shared `MutationApplier`. Each primitive is honest about its confidentiality tier and what it can/cannot deliver on real hardware.

**Introduces.** `GPUShufflePolicy`, `EphemeralMemoryPolicy` (+`KeySourceRef`, cipher/length **open**), `RAGSandboxPolicy`, `ConfidentialComputingPolicy` (inert). No new action variant — all ride `Rotate` overrides.

**Accuracy ledger.** GPU rebind intent, `nvidia.com/gpu:'0'`, "encrypted ephemeral memory volumes / keys destroyed at termination", "RAG in isolated pods / re-keyed on every inference cycle", TEE-deferred = `[PAPER-SPECIFIED]` (Proactive §IV.C; ADA §5.6.1; ADA §6.3.4). **Reassign-vs-DropToZero** = `[PAPER-CONTRADICTION]` (DropToZero the only verbatim behavior; Reassign honestly-scoped opt-in). "Encrypted" semantics (tmpfs = ephemeral-not-cryptographic; CSI = real at-rest; TEE deferred), serve-vs-quarantine split (timed=keep GPU, panic=GPU-quarantine), key trust root/destruction-race guard, `rekeyOn` mapping, unprivileged-only threat boundary, `15m` TTL = `[DESIGN-DECISION]` (D17/D18/D19g/D20g/D21g/D23g/D24g). `ASR<10%`/`94%` = `[R6-PAPER-ONLY]` (aggregate, not GPU-specific).

### Capability 4 — Jittered scheduling & entropy

**What is built.** The single jittered clock in `time-based-trigger` becomes the von Neumann "mixed-strategy" cadence: a symmetric `±` jitter band (10–30%), `Uniform` distribution by default, `crypto/rand` entropy, per-pod `PerPodPhaseOffset` stagger, and a `MaxConcurrentRotations` cap. The schedule is **kept secret** (only past cadence is published) and **restart-safe** (a persisted seed recomputes the same offset; ≤1 extra rotation after restart).

**Introduces.** `RotationPolicy` cadence fields (§2.4); the persisted jitter **Secret**; the `:9443` validating webhook's first real use (interval floor + `0≤JitterMin≤JitterMax≤100`).

**Accuracy ledger.** `R = 60m ± jitter (10–30%)` band + `±` symmetry = `[PAPER-SPECIFIED]` (AMTD-AI §3.2). **R value** = `[PAPER-CONTRADICTION]` (60m white-paper vs 20–30m eval vs 30s demo → per-workload field, 60m default, 5m floor). Distribution choice, `crypto/rand`, stagger algorithm, schedule secrecy, persisted seed, `5m` floor = `[DESIGN-DECISION]` (D5/D9/D10/D12g/D13/D14). `<60min` dwell = `[R6-PAPER-ONLY]`.

### Capability 5 — Telemetry scoring & adaptive cadence

**What is built.** A pluggable `AnomalyScorer` (default `Passthrough` = `prometheus-integrator` maps an alert annotation straight to `AnomalyScore`, no invented math) whose output always lands as `SecurityEvent.Spec.AnomalyScore`. The relaxed matcher reads it: a rising score shortens the computed interval and, at `panicThreshold`, fires an **immediate panic mutation**. `ContextMutationPolicy` realizes ADA Listing 1's telemetry-triggered mutation set.

**Introduces.** `AdaptiveRotationPolicy` (+`PanicThreshold`, `ScoringPolicy` with **no default weights**, `StalenessWindow`); `AnomalyScore/Metrics` on SecurityEvent; `ContextMutationPolicy` kind.

**Accuracy ledger.** Signals named (GPU entropy / query deviation / cache misses), "proportional", "could be rotated more aggressively", ADA Listing 1 mutation set = `[PAPER-SPECIFIED]` (Proactive §IV.C.3; ADA Listing 1) — but the scoring brain is **deferred** by ADA §6.3.3. Scorer interface + Passthrough default + decimal-`[0,1]`-on-Spec + DCGM-stddev proxy/Falco-event-rate signals, `panicThreshold=0.85`, illustrative `{0.5,0.3,0.2}` (never defaulted) = `[DESIGN-DECISION]` (D19/D20/D25). `MTTR<5min` = `[R6-PAPER-ONLY]`.

> **Unified "panic" semantics (locked, stated identically in D22 and D25).** "Immediate panic" bypasses **only** the min-interval cadence **floor** — **never** the readiness gate and **never** the N-consecutive-high + EWMA hysteresis. A single spoofed/noisy spike cannot panic. Furthermore, the product word "panic" is **one word → two declarative actions** that compose: (1) score-keyed `Rotate(panic)` (in-place GPU-quarantine / secure-degrade, gated by D22 hysteresis), and (2) `ThreatLevel`-keyed `NodeRotate` (the clean-node move, gated by D26 authz). The `minInterval` remains the floor no availability SLO may breach.

### Capability 6 — Drift self-heal (cryptographically signed baseline)

**What is built.** `BaselineDriftReconciler` verifies running workloads against an **external immutable signed registry** (cosign key-based default; offline-capable), **emits** a `Type:'drift'` SecurityEvent with `Evidence` (it does not act directly), and the matcher routes it to a `Regenerate` (restore-from-golden) or, by default, `Quarantine` action. A `baselineAdmission` webhook on `:9443` denies unsigned/unverifiable images at admission. The `WorkloadBaseline` CRD holds only references — tampering the in-cluster object cannot make self-heal restore malicious state.

**Introduces.** `RegenerateAction`; `BaselineSpec`/`WorkloadBaseline` CRD; `SignaturePolicy`; `DriftPolicy{OnDrift(default Quarantine); AdmissionEnforce(default true); ResetHardeningProfile(default PodProfileOnly)}`; `Evidence` on SecurityEvent; `baselineAdmission` webhook.

**Accuracy ledger.** "Golden Image Repository / Immutable signed copies", "Immutable Image Registry / rollback to last known-good", "self-heals on deviation from cryptographically signed baseline", hardening-profile mutation theme (§IV.C.4) = `[PAPER-SPECIFIED]` (AMTD-AI §3.1; Proactive §IV.B; README; ADA §IV.C.4). Trust root (external registry + offline-signed digests), cosign key-based default, **split fail mode** (admission fail-CLOSED / poll fail-to-cached-last-good), comparison surface (digest + curated allowlist, not full-PodSpec), default `OnDrift=Quarantine` (auto-Regenerate is weaponizable into a restart-loop DoS), GitOps yield, `ResetHardeningProfile` pod-local default = `[DESIGN-DECISION]` (D6/D6g). **`signing ≠ benignity`** (a validly-signed-but-backdoored upstream passes) is reproduced in docs + Status. `Persistence 95%+→<4%` = `[R6-PAPER-ONLY]`.

### Capability 7 — Node rotation (panic-move to a clean node)

**What is built.** A `NodeRotate` action relocates a compromised inference pod onto a **clean** node (label-pool default `r6security.com/clean-pool=true`, with PVC-topology/GPU-MIG preflight) and disposes of the source node (default reversible `Cordon`). The targeted pod is relocated **and pinned** (via nodeAffinity on the **replacement** spec, never `spec.nodeName`, never the shared owner template). A cluster-scoped `NodeRotation` CRD makes the in-flight drain restart-safe. Because the eviction primitive is a cluster-DoS lever, it rides the D26 trust gate.

**Introduces.** `NodeRotateAction` (+`Strategy`/`DrainPolicy`/`TargetNodeSelector`); `NodeRotationPolicy` (scheduled cadence, default-off); `NodeRotation` CRD with phases `{Cordoning,Draining,Rescheduling,Pinning,Completed,RolledBack,NoCleanTarget}`; `CleanNodeSelector` (label-pool impl + PVC/GPU precheck).

**Accuracy ledger.** "Immediate panic mutation — move the model to a clean, isolated node", "ephemeral node assignments", "staggered rotation to avoid simultaneous restarts" = `[PAPER-SPECIFIED]` (Phoenix-for-AI Pillar 03; Proactive §IV.B/§V.A). **Everything else** — clean-node definition, pinning mechanism, source-node disposition enum (`Cordon` default, flagged), drain scope (targeted-pod-only default; opt-in Eviction-API co-tenant drain honoring PDBs; hard `MaxConcurrentNodes+Stagger` ceiling), trigger authn (Source-allowlist + ThreatLevel-floor + provenance + human-approval-for-Delete-only), crash-mid-drain rollback = `[DESIGN-DECISION]` (D25g/D25g2/D25g3/D25g4/D26). `99.8%` / `<5min` / `94%` are not node-specific = `[R6-PAPER-ONLY]`.

---

## 5. Conformance matrix

Every class-(A) action → its `Strategy[]` expression → the triggering SecurityEvent rule → the executing controller → testability. `K` = kind/envtest-testable (no GPU); `G` = needs real NVIDIA GPU + served model + load generator.

| Action | `Strategy[]` expression | Triggering rule (emitter) | Executing controller | Test |
|---|---|---|---|---|
| **Delete** (cold primitive, unchanged) | `{rule:{type:'timed',threatLevel:'info',source:'TimeBasedTrigger'}, action:{delete:{}}}` | exact fast path; `time-based-trigger` (Source verified L198) | `SecurityEventReconciler` L197-203 `r.Client.Delete` (owner recreates byte-identical) | K |
| **Quarantine** (existing) | `{rule:{...,source:'KubeArmorIntegrator'}, action:{quarantine:{}}}` ⚠ | exact; `kubearmor-integrator` (native `Type=PolicyName`, normalization needed for any `Type` guard) | `SecurityEventReconciler` L285-369 (deny-all NetworkPolicy + relabel + owner-ref) | K |
| **Debugger / CustomAction** (existing) | `{rule:{...}, action:{debugger:{image:'…'}}}` / `{customAction:{...}}` | exact; any emitter | `SecurityEventReconciler` L204-241 / L242-284 (ephemeral-container attach) | K |
| **Rotate — timed** (cap#1) | `{rule:{type:'timed',source:'TimeBasedTrigger'}, action:{rotate:{}}}` | exact; `time-based-trigger` (sole jittered cadence) | `SecurityEventReconciler` Rotate branch (fills L370-372) → `MutationApplier`; durability via WarmInferenceSet cutover / top-owner patch / cold fallback; NIM L131-132 pass-through; D22 guards | K (selection/mutation-declared); G (downtime/latency) |
| **Rotate — panic** (cap#5) | `{rule:{source:'FalcoIntegrator', match:[{field:'anomalyScore',op:'Gte',value:'0.85'}]}, action:{rotate:{overrides:{gpuResource:'0',envPatch:[{name:'RUNTIME_MODE',value:'SECURE'}]}}}}` | **scored** path (`MatcherMode='Scored'`): Source guard + `anomalyScore≥panicThreshold`. **Prereq:** `falco-integrator` extended to populate `AnomalyScore`; else degrades to a `ThreatLevel`-guarded panic | `SecurityEventReconciler` Rotate branch (one-shot) with min-interval-bypass-only + readiness + EWMA + N-consecutive-high (D22) | K (score-shape/provenance); G (panic MTTR, GPU-quarantine) |
| **Rotate via ContextMutationPolicy** (cap#5, ADA Listing 1) | `ContextMutationPolicy{...}` → `{rule:{source:'PrometheusIntegrator', match:[{field:'metrics.high_gpu_usage',op:'Exists'}]}, action:{rotate:{policyRef:{name:'nim-risk-based-mutation'}}}}` | scored/Exists; `prometheus-integrator` (Source verified L143) sets `AnomalyScore/Metrics`. **GatekeeperViolation trigger = NO emitter (future-work)** | Rotate branch → same `MutationApplier`; thin `ContextMutationPolicy` reconciler records apply; D3 routing | K (selection/apply); G (real mutation) |
| **WarmSwap** (cap#2) | `{rule:{type:'timed',source:'TimeBasedTrigger'}, action:{warmSwap:{warmInferenceSetRef:{name:'nim-pool'},drainTimeoutSeconds:30}}}` | exact or scored; `time-based-trigger` (schedule) or panic score | `SecurityEventReconciler` → `WarmInferenceSetReconciler.LeaderSwapper.Swap`; shadow-readiness is class-(B) | K (readiness/Status); G (swap p50/p95, zero-non-2xx) |
| **Regenerate** (cap#6) | `{rule:{type:'drift',source:'FalcoIntegrator'}, action:{regenerate:{baselineRef:{name:'nim-baseline'},resetHardeningProfile:true}}}` ⚠ | exact `Type:'drift'`; `falco-integrator` (Container-Drift rules **enabled** + rule-name→`Type:'drift'` normalization) or `BaselineDriftReconciler` | Regenerate branch → `BaselineRestorer.Regenerate` (verify-before-recreate at L168/L198; owner-walk to top template); `baselineAdmission` (:9443) enforces signed+pinned digest | K (admission/digest/drift MTTR) |
| **NodeRotate** (cap#7) | `{rule:{source:'KubeArmorIntegrator', match:[{field:'threatLevel',op:'In',value:'high,critical'}]}, action:{nodeRotate:{strategy:'Cordon',targetNodeSelector:{'r6security.com/clean-pool':'true'}}}}` ⚠ | scored/In on `ThreatLevel` (**no numeric score**); Source-allowlist + ThreatLevel-floor (D26). **`Source` guard native; `ThreatLevel` In-token needs normalization** | `SecurityEventReconciler` → `NodeRotationReconciler` (cordon/taint/drain via Eviction → reschedule onto clean pool, pin replacement); NodeRotation CRD = restart-safe drain (class-B); NIM early-returns on the in-progress annotation | K (relocate/no-mass-eviction/restart-safe with fake nodes); G (node-rotation MTTR) |
| **Disable** (existing; was the unimplemented L370-372 slot) | `{rule:{type:'disable'}, action:{disable:{}}}` | exact; any emitter | `SecurityEventReconciler` (Disable branch, now implementable) | K |
| **Scheduled node rotation** (cap#7, non-event cadence) | `AMTDSpec.NodeRotationPolicy{...}` tunes cadence, but rotation is STILL `{Type:'timed',Source:'TimeBasedTrigger'} → nodeRotate` (NOT a hidden timer) | jittered cadence from the single owner; Policy supplies node interval/jitter/concurrency | `NodeRotationReconciler` honoring `MaxConcurrentNodes+Stagger` (no mass-eviction) | K |
| *(clarification — NOT a rule-#1 action)* WarmInferenceSet shadow-readiness & NodeRotation in-flight-drain continuation | **N/A** — owned-CRD desired-state reconciles (keep N shadows Ready; finish a drain across restart), analogous to a Deployment maintaining replicas | **N/A** — triggered by the controller's own watch on its owned CRD; MUST NOT initiate any action the matcher did not select | `WarmInferenceSetReconciler` / `NodeRotationReconciler` | K |

> ⚠ **Normalization-gated rows.** Rows guarding on `Type:'drift'`/`'policy-violation'`/`'panic'` or `threatLevel In high,critical` are **inert until the per-integrator normalization prerequisite (§1.3) lands**. The `Source` guard is native and works today; inertness is fail-safe. (The `NodeRotate` row needs no numeric score, but its `ThreatLevel In` *string* guard still requires normalization.)

---

## 6. Build plan (sequenced)

Phases are ordered by dependency. Each capability is marked **KIND-TESTABLE** (fully exercisable on a kind cluster with fake/placeholder images and multi-node simulation) or **GPU-REQUIRED** (needs real NVIDIA hardware/MIG + served model + load generator). **All quantitative SLOs below are internal design targets (D27) — NOT the marketing figures**, which are kept only as the aspirational direction. Every SLO reads a **locked Status field** (no schema change). The cold baseline is always a *measured comparator*, never a target. `minInterval` is the floor no availability SLO may breach.

### Phase 0 — Contract & matcher foundation (the structural unblock) · **KIND-TESTABLE**
Land the additive API: `Rule.Match/ScoreThreshold`, `SecurityEvent.Spec.AnomalyScore/Metrics/Evidence`, the four new `AMTDAction` members, both populated Status structs, `MatcherMode`. Replace L139 `DeepEqual` → `MatchStrategy`. `make generate` + `make manifests` regenerate deepcopy for **all** new embedded types and republish the schema.
- **Why first:** unblocks everything; the contract change is **inert** (a scored clause vs a nil-score event evaluates false), so it is safe before any scorer or new action exists (Phase-0 inertness).
- **Validation/SLO (kind):** per-strategy byte-compat — every legacy 3-string CR selects identically to today's `DeepEqual` (golden-test the projection against the prior behavior); `Exact` mode renders `Match` inert + emits `MatcherModeWarning`; emitters still compile against the shared module; `MaxProperties=1` rejects 2-key actions at the apiserver.
- **Kind approach:** envtest / fake apiserver; table-test `MatchStrategy` exact-vs-scored; assert Status population on a synthetic event.
- **Unlocks:** every later phase.

### Phase 1 — Inference-rotation core + storm guard · **KIND-TESTABLE** (control plane) / **GPU-REQUIRED** (downtime numbers)
Implement the `Rotate` one-shot branch (fills the L370-372 slot), demote NIM L131-132 to pass-through, build the `MutationApplier` + D3 owner-walk/classifier, and the D22 guard pipeline (min-interval + readiness + crash-loop backoff/rollback + in-progress annotation) with anti-flap state in `AMTDStatus`.
- **Validation/SLO (kind, gate now):** 100% of fired rotations make the recreated/cutover pod spec carry the declared mutation and increment `rotationCount` (= `NIM_RESCHEDULE_COUNT`); `mutation-not-durable` records the correct reason for bare/Job/per-pod-shared; no self-requeue storm under a burst of events; one event ⇒ exactly one action.
- **Validation/SLO (GPU, target-to-confirm):** COLD recreate downtime measured as ground truth (informational, ~400s); WARM p99 added-latency SLO **≤1s** at steady QPS.
- **Critical path.** Unlocks caps #3/#5/#6/#7 (they all reuse the executor + `MutationApplier`).

### Phase 2 — Jittered scheduling & entropy · **KIND-TESTABLE**
Move all jitter into the single `time-based-trigger` scheduler: symmetric 10–30% band, `Uniform` default, `crypto/rand`, `PerPodPhaseOffset` stagger, `MaxConcurrentRotations` cap, schedule secrecy (drop any published next-fire), persisted **Secret** seed for restart-reproducibility, and the `:9443` validating webhook (interval floor + jitter bounds).
- **Validation/SLO (kind, the strongest cheap suite):** empirical gap distribution mean = `BaseInterval`, spread over `base·(1±JitterMaxPercent/100)` with no degenerate spike; prediction-error ≥ jitter magnitude; max instance lifetime ≤ `base·(1+JitterMaxPercent/100)` (dwell proxy); `JitterPercent=0` reproduces deterministic cadence **bit-for-bit** (backward-compat); restart-safety ≤1 extra rotation after operator kill (timestamps only, no GPU).
- **Unlocks:** WarmSwap/NodeRotate cadence (both ride this single owner).

### Phase 3 — Telemetry scoring & adaptive cadence · **KIND-TESTABLE** (shape/provenance) / **GPU-REQUIRED** (panic MTTR)
Pluggable `AnomalyScorer` (default `Passthrough` via `prometheus-integrator` annotation→`AnomalyScore`); `AdaptiveRotationPolicy` (`PanicThreshold`, `StalenessWindow`, no default weights); panic branch (bypass min-interval **only**, keep readiness + N-consecutive-high); `ContextMutationPolicy` thin reconciler.
- **Validation/SLO (kind, gate now):** inject rising `AnomalyScore` 0→1, assert `SecurityEventStatus.ComputedInterval` monotone-decreasing bounded `[minInterval, base]` and panic at `≥panicThreshold`; **score-provenance** — a spoofed/unprivileged-pod score is rejected (workload SA has no `securityevents` create), `StalenessWindow` decays an old score to 0; `ContextMutationPolicy` fires all 3 Listing-1 mutations on `high_gpu_usage`.
- **Validation/SLO (GPU, target-to-confirm):** panic MTTR (score-cross → replacement Ready) WARM p95 **≤60s**; availability during accelerated rotation must not breach the `minInterval`-bounded SLO.

### Phase 4 — Warm-pool / LWS swap · **GPU-REQUIRED** (the headline) / **KIND-TESTABLE** (readiness/Status)
`WarmInferenceSet` CRD + reconciler (optional `sigs.k8s.io/lws` wrap, bare-pod fallback behind `WarmPoolManager`), `WarmReadyGate` (`RequireModelLoaded` default), `TrafficSteerer` (`ServiceSelectorSwap` default), `LeaderSwapper.Swap` (Ready→flip→drain→retire→re-warm). This delivers D3's primary per-instance durability for cap #1/#3.
- **Validation/SLO (GPU + load-gen, the headline capability):** `lastSwapDurationMillis` p50 **≤5s** / p95 **≤15s** AND **zero non-2xx** in the cut+drain window at the chosen `DrainTimeoutSeconds`; internal SLO **warm ≤ COLD/10** on identical hardware (COLD measured separately as comparator, no SLO).
- **Validation/SLO (kind):** `warmPool.{readyShadows≥N, activeLeader set, lastSwapDurationMillis populated}` after a WarmSwap event; shadow-readiness maintenance never self-initiates a swap (class-B invariant).

### Phase 5 — Drift self-heal · **KIND-TESTABLE**
`BaselineDriftReconciler` (emit `Type:'drift'` + `Evidence`, do not act), cosign `BaselineVerifier`, `WorkloadBaseline` CRD + embedded `BaselineSpec`, `baselineAdmission` webhook on `:9443` (fail-CLOSED), `BaselineRestorer.Regenerate` (verify-before-recreate at L168/L198), enable the two Falco Container-Drift rules + map rule-name → `Type:'drift'`. **Split fail mode:** admission fail-CLOSED; poll/verify-before-recreate fail-to-cached-last-good-with-grace.
- **Validation/SLO (kind, gate now — admission + digest logic, no GPU):** tamper-redeploy prevention 100% (drift or backdoored-tag → regenerated pod on verified `Repository@Digest`; `AdmissionEnforce` denies the tampered image); signature-correctness matrix 100% with a defined fail mode for registry/Rekor-unavailable (`VerificationUnavailable` condition, reuse last verified digest); near-zero false-positive on a legit GitOps bump (must not fight GitOps); drift MTTR = `baseline.lastRegeneration − detection-ts`, p95 **≤30s** for synchronous admission-Block. (Paper `<5min` is *rotation*, not drift → not adopted.)

### Phase 6 — Node rotation · **KIND-TESTABLE** (control plane) / **GPU-REQUIRED** (node MTTR)
`NodeRotateAction` + `NodeRotation` cluster-scoped CRD + `NodeRotationReconciler`; `CleanNodeSelector` (label-pool + PVC-topology/GPU-MIG precheck); replacement-spec nodeAffinity pinning; D26 trust gate (Source-allowlist + ThreatLevel-floor + RBAC provenance + human-approval **only** for `Delete`); `MaxConcurrentNodes+Stagger` ceiling; resume-from-phase reconcile + `NoCleanTarget`/`RolledBack`.
- **Validation/SLO (kind, gate now — simulable with fake nodes/taints):** host-foothold relocate 100% off source node; **no-mass-eviction** 100% (`MaxConcurrentNodes+Stagger` adherence under scheduled rotation); NodeRotation CRD restart-safe drain continuation across operator kill; `NoCleanTarget` aborts (reason `CleanPoolExhausted|PVCTopologyBound|NoMatchingGPU`) rather than landing an unschedulable pod; D26 — a forged event from a non-allowlisted Source (or below the ThreatLevel floor) cannot select `NodeRotate`.
- **Validation/SLO (GPU, target-to-confirm):** node-rotation MTTR = `nodeRotations[].time(Completion−Start)` WARM (cap#2 relocation) p95 **≤120s**; COLD cordon-drain-recreate measured separately as the worse comparator (paper `<5min`/`99.8%`/`94%` are not node-specific → informational).

### Phase 7 — Per-integrator normalization & score-carrier extensions · **KIND-TESTABLE**
Additive extensions (no new schema; same typed-client mechanism): extend `falco-integrator` and `kubearmor-integrator` to (a) map native threat-level vocab → canonical `{info,low,medium,high,critical}` and rule-name/policy-name → canonical `Type` (`drift`/`panic`), and (b) populate `Spec.AnomalyScore` for score-bearing rows. **This is what makes the normalization-gated conformance rows fire.** Until it lands, those rows are inert (fail-safe).
- **Validation/SLO (kind):** a Falco `Critical` Container-Drift event now produces `{Type:'drift', ThreatLevel:'critical', Source:'FalcoIntegrator'}` and selects `Regenerate`; a KubeArmor severity-9 violation maps to `threatLevel In high,critical` and selects `NodeRotate`; score-bearing rows now carry a populated `AnomalyScore`.

### GPU benchmark harness (out-of-band, never a CI gate)
A separate harness (served model + load generator on real GPU/MIG nodes) produces the cold-vs-warm downtime/availability/p50-p99 overhead, GPU-UUID distinctness (100% consecutive DCGM-UUID differ when >1 GPU schedulable, or quota `'0'` in DropToZero), key-destruction probe (0 reuse, 0 readable prior plaintext via co-resident probe, key TTL < grace), and ASR/side-channel red-team — all as **target-to-confirm reports**, never CI acceptance gates.

### Critical path & GPU-schedulability precedence
- **Critical path:** Phase 0 → Phase 1 → (Phase 2 ∥ Phase 3) → Phase 4 → Phases 5/6 → Phase 7. Phase 4 (warm pool) is the load-bearing dependency for *durable* cap #1/#3 mutation and for cap #7's WARM relocation path; Phase 7 activates the normalization-gated rows.
- **GPU-schedulability precedence ladder (locked, applies wherever caps #2/#3/#7 contend for scarce GPUs):** **gang-schedule the warm pool (availability) > distinct-UUID Reassign (hardening nicety) > DropToZero quarantine (needs no GPU).** Uniform **fail-loud** rule: never silently land an unschedulable/non-distinct pod — `RequireDistinctBinding=false` (best-effort) is the default, degrading to a `SingleGPUFallback` Status condition; the warm pool records "warm guarantee void" if N shadows cannot gang-schedule; node rotation aborts `NoCleanTarget(NoMatchingGPU)`. If distinct-UUID and gang-schedulability conflict on the warm path, **keep the warm shadow Ready (serve)** and record `GPUBindingDistinctness=BestEffortOnly` — do **not** refuse the swap. The conformance matrix never claims warm + distinct + clean simultaneously on hardware that cannot provide all three.

---

## 7. Accuracy summary

**Biggest `[PAPER-CONTRADICTION]` calls made.**
- **GPU shuffle: Reassign vs DropToZero (D17).** Proactive §IV.C.1 prose says "dynamically reassigns GPU bindings (MIG/NVLink)" (keep serving on a different device); the *only* verbatim GPU manifest (ADA Listing 1) sets `nvidia.com/gpu:'0'` (a quota drop). Resolution: **`DropToZero` is the default and the only behavior asserted as faithful**; `Reassign`/`AntiAffinity` are honestly-scoped opt-ins (per-UUID needs GPU Feature Discovery; NVLink-group placement has no standard primitive and is not implemented).
- **Endpoint identity: rotating vs stable (D16).** §3.2 "endpoint path rotates" vs §IV.D-5 "update Service endpoints **without interrupting client connections** (K8s Service abstraction)". Resolution: the **external endpoint stays stable**, the **backend path/selector rotates** behind it — reconciling both statements; endpoint cutover is a `Rotate` sub-effect, not a new action.
- **Base rotation interval R (D9).** 60m (AMTD-AI white paper) vs 20–30m (eval) vs 30s (demo). Resolution: per-workload `BaseInterval`, **default 60m**, webhook **floor ≥5m** (rejects the 30s demo value in production; the floor mechanizes the paper's own warning that 10–30% jitter is meaningless on a 30s base).

**`[R6-PAPER-ONLY]` items implemented as aspirational (no measurement code).**
`400s→15s` downtime, Persistence `95%+→<4%`, Dwell `150+days→<60min`, `MTTR<5min`, availability `99.8%`, overhead `1–2%` / `1.3–1.7%`, `94%` disruption, `MODEL_ROTATION 3.2s`, `PIPELINE_INTEGRITY 99.97%`, `ASR<10%`. Each is kept **only as the aspirational direction**; the internal SLOs we gate on are **ours** (swap p95 ≤15s, drift MTTR p95 ≤30s, panic MTTR WARM p95 ≤60s, node MTTR WARM p95 ≤120s, warm ≤ COLD/10), every internal SLO reads a **locked Status field**, and the cold baseline is a measured comparator — never a target — exactly matching the locked D3 durability routing so a warm number is never asserted on the cold path.

**Documented unmet prerequisites (reported, never implemented-and-broken).**
1. **GatekeeperViolation trigger** (ADA Listing 1) — verified **no** OPA-Gatekeeper-audit→SecurityEvent emitter exists in any of the 5 repos; that single Listing-1 trigger row is unsatisfiable and is documented as future work.
2. **Per-integrator threat-level/type normalization** — `Type:'drift'`/`'panic'`/`'policy-violation'` and `threatLevel In high,critical` are not emitter-native (Falco emits rule-name + `Priority`; KubeArmor emits PolicyName + numeric Severity); the guarded rows are inert until Phase 7's additive normalization lands.
3. **Score-carrier extension** — a `Source`-guarded score rule fires only if the named integrator populates `AnomalyScore` (Prometheus does naturally; Falco/KubeArmor need the additive extension).
All three are **fail-safe** (no action fires rather than a wrong one) and add **no** trigger path reachable outside the matcher.

**"Nothing here was invented to fill a paper gap," and how that was enforced.**
Every "the paper specifies X" in this document traces to verbatim corpus text; every gap the papers leave (scoring formula, RNG, stagger algorithm, key store/cipher, node-selection, fail modes, SLOs, all numeric defaults) is explicitly labeled `[DESIGN-DECISION]` / a flagged proposal, never presented as a paper fact. Enforcement: (i) the **no-fabricated-claims** invariant gates every quantitative figure to `[R6-PAPER-ONLY]` with no measurement code; (ii) `0.85`, `5m`, `60s`, `N=20`, `Cordon`, `15m`, `{0.5,0.3,0.2}`, and the `Uniform;TruncatedNormal` / `SHA256;HMAC-SHA256` / steering enums are all carried as design-authored proposals; (iii) the two readings of each contradiction are recorded and the chosen one is justified, not silently picked; (iv) cipher/key-length on `KeySourceRef` are left **open** rather than invented; (v) tmpfs is explicitly **not** labeled "cryptographic" and TEE is deferred exactly where ADA §6.3.4 (the *Confidential Computing* future-work section, **p.14**) defers it.

---

*End of locked architecture & build plan. Complete: 36/36 anchors resolved exactly once; both global design rules hold; no action is reachable outside the matcher.*
