/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

// Package model holds the shared, dependency-free domain types that every Phorvex
// subsystem exchanges (ingest -> graph -> physics/context/belief/cost/feasibility
// -> decision -> actuator -> audit/metrics). It imports NOTHING from the rest of
// Phorvex, so the swappable interface packages couple only to these plain types and
// "adding a profile/constraint/model = one file" stays true.
package model

import (
	"strings"
	"time"
)

// ActuationBrakeObservation is a normalized operator annotation observation.
// Cause is a stable, non-sensitive token; raw annotation values never enter audit.
type ActuationBrakeObservation struct {
	Engaged bool
	Cause   string
}

// DefaultCostCeiling is the independent hard ceiling for the dimensionless
// switching-cost gate. It is deliberately not derived from the objective
// weights: those weights rank moves, while this value decides whether a move is
// safe enough to generate at all.
//
// [ESTIMATE-UNVALIDATED] — one logical pod replacement (1.0) plus the provisional
// structural margin agreed in PHVX-9a/9b. Policies may override it per service.
const DefaultCostCeiling = 1.2

// Action is the resolved mutation a decision selects. It mirrors the
// v1alpha1.ActionType vocabulary but lives here so interface packages never import
// the API package.
type Action string

const (
	// ActionNoop leaves the pod untouched.
	ActionNoop Action = "noop"
	// ActionRotate maps to Phoenix's Delete (kill + clean respawn).
	ActionRotate Action = "rotate"
	// ActionQuarantine maps to Phoenix's Quarantine (deny-all + detach).
	ActionQuarantine Action = "quarantine"

	// --- P-ACTUATOR: the full native action vocabulary. Retained extended-Phoenix
	// primitives the 3-set didn't name + the advanced K8s + AI/GPU moves. Each has a
	// native handler (the completeness invariant proves it) and a per-action feasibility
	// law. AI/GPU magnitudes remain hardware-validation inputs owned by PHORVEXSEC-87
	// (read the GPUPresent-gated PhysicsWitness).

	// ActionDebugger injects one ephemeral container (= Phoenix Debugger). Irreversible.
	// MANUAL-BY-DESIGN: it is a human diagnostic, not a moving-target defence, so it carries NO
	// recon cover set (nothing it invalidates) and the autonomous optimizer never selects it — it
	// is reachable only by explicit operator dispatch. (See recon/profile.go: no cover[Debugger].)
	ActionDebugger Action = "debugger"
	// ActionCustomInject injects a parameterized ephemeral container (= Phoenix
	// CustomAction); also the KV-reset substrate. Irreversible.
	// MANUAL-BY-DESIGN: an operator/extension escape hatch, likewise NO recon cover set → never
	// autonomously selected; reachable only by explicit dispatch.
	ActionCustomInject Action = "custom-inject"
	// ActionDisable is the declared-not-implemented capability (= Phoenix's own posture).
	// Excluded from MutatingActions (never generatable) but a handler exists so the
	// completeness enumeration stays green. Never fabricated behaviour.
	ActionDisable Action = "disable"
	// ActionIdentityRotate remains in stored policy vocabulary for compatibility, but is
	// declared-only: an epoch relabel cannot rotate UID, IP or credentials. Historical
	// relabel snapshots may still be restored through Rollback.
	ActionIdentityRotate            Action = "identity-rotate"
	IdentityRotateUnsupportedReason        = "identity-rotate declared-only: epoch relabel cannot rotate UID, IP or ServiceAccount credentials"
	// ActionRouteRotate re-keys `phorvex.ai/route-key` on the pod and restitches the
	// selector of its explicitly declared `phorvex.ai/route-service` (advanced K8s;
	// native-only). It returns Emitted=false when that deployment contract is absent.
	ActionRouteRotate Action = "route-rotate"
	// ActionWarmSwap rotates WITHOUT the cold-load: provision a Ready warm replacement
	// then retire (provision-before-retire). ColdLoadSec validation: PHORVEXSEC-87.
	ActionWarmSwap Action = "warm-swap"
	// ActionMIGRebind moves to a non-co-resident MIG partition then warm-cutover.
	// GPU-bound hardware validation is tracked by PHORVEXSEC-87.
	ActionMIGRebind Action = "mig-rebind"
	// ActionKVReset flushes KV-cache/agent-session in-process WITHOUT killing the pod —
	// the only move that defeats a wipe-surviving prompt-inject implant. Hardware validation:
	// PHORVEXSEC-87.
	ActionKVReset Action = "kv-reset"
	// ActionEndpointRotate re-keys the served-model route/endpoint. Hardware validation:
	// PHORVEXSEC-87.
	ActionEndpointRotate Action = "endpoint-rotate"
	// ActionModelShardReplace warm-replaces a model shard on a target id/version.
	// ColdLoadSec/ModelRarity hardware validation is tracked by PHORVEXSEC-87.
	ActionModelShardReplace Action = "model-shard-replace"
	// ActionAdapterRotate unloads + (optionally) reloads a clean LoRA/adapter — the ONLY
	// move that evicts a poisoned adapter (survives warm-swap/kv-reset/shard-replace).
	// [PENDING-GPU-VALIDATION] (vLLM /v1/{unload,load}_lora_adapter; Triton/TGI equivalents).
	ActionAdapterRotate Action = "adapter-rotate"
	// ActionRequestDrain drains/aborts in-flight requests against a foothold (request-
	// granular eviction; also supplies warm-swap's drain). [PENDING-GPU-VALIDATION].
	ActionRequestDrain Action = "request-drain"
	// ActionGuardrailRotate rotates the safety/guardrail tier (variant/ruleset) to stale a
	// found jailbreak/filter-bypass — MTD for the filter. [PENDING-GPU-VALIDATION].
	ActionGuardrailRotate Action = "guardrail-rotate"
	// ActionKVMigrateInvalidate invalidates/migrates KV across disaggregated prefill/decode
	// (kv-reset is local-only). Local invalidate is real; cross-worker migrate is DEFERRED
	// [PENDING-GPU-VALIDATION] (needs a disaggregated P/D deployment).
	ActionKVMigrateInvalidate Action = "kv-migrate-invalidate"
)

// MutatingActions is the compatible action order for policy and trace enumeration.
// identity-rotate remains here as stored vocabulary but is explicitly excluded by the
// generator/capability gate and cannot be emitted. Both actionset.enabledActions and
// decision.candidateActions iterate it
// (policy-filtered) so the two emit lists can never drift, and the completeness invariant
// enumerates it to prove every generatable action has a native handler. Order is
// load-bearing: ActionRotate precedes ActionQuarantine so the engine's strict-`>`
// tie-break stays byte-identical to the pre-P-ACTUATOR baseline.
var MutatingActions = []Action{
	ActionRotate, ActionQuarantine,
	ActionDebugger, ActionCustomInject,
	ActionIdentityRotate, ActionRouteRotate,
	ActionWarmSwap, ActionMIGRebind, ActionKVReset, ActionEndpointRotate, ActionModelShardReplace,
	// P-ACTUATOR-SET-COMPLETE additions (opt-in; ActionEnabled with a nil policy still permits ONLY
	// rotate+quarantine, so default decisions stay byte-identical — 1.62x/P3/lead-demo parity).
	// Appended AFTER the existing set so the engine's strict-`>` tie-break order is unchanged.
	ActionAdapterRotate, ActionRequestDrain, ActionGuardrailRotate, ActionKVMigrateInvalidate,
}

// ActionEnabled reports whether the policy permits action a. A nil EnabledActions map
// preserves the historical default — ONLY rotate + quarantine — so a default policy
// generates/evaluates exactly the pre-P-ACTUATOR set (byte-identical decisions, the
// 1.62x + P3 + lead-demo parity). The advanced/AI moves are opt-in per policy.
func ActionEnabled(pol Policy, a Action) bool {
	if pol.EnabledActions == nil {
		return a == ActionRotate || a == ActionQuarantine
	}
	return pol.EnabledActions[a]
}

// Move is a candidate mutation evaluated for feasibility and cost.
type Move struct {
	Action Action
}

// WorkloadPhase is the cost-relevant lifecycle phase of a workload.
type WorkloadPhase string

const (
	// PhaseColdStarting = model/image still loading (most expensive to rotate).
	PhaseColdStarting WorkloadPhase = "ColdStarting"
	// PhaseWarm = serving steadily.
	PhaseWarm WorkloadPhase = "Warm"
	// PhaseIdle = ready but not serving (cheapest to rotate).
	PhaseIdle WorkloadPhase = "Idle"
	// PhaseDraining = shutting down.
	PhaseDraining WorkloadPhase = "Draining"
	// PhaseUnknown = phase could not be determined.
	PhaseUnknown WorkloadPhase = "Unknown"
)

// AllWorkloadPhases is the SINGLE SOURCE OF TRUTH for the phase vocabulary — the
// MutatingActions analog. Every cost encoding (the heuristic flow prior and the RLS
// feature/prior layout) is derived from, or tested against, this list; the
// phase-vocabulary completeness test fails the build if a WorkloadPhase constant is
// added without a corresponding cost-encoding row. Order is declaration order and is
// NOT currently load-bearing — do not add an order-dependent consumer without a test.
var AllWorkloadPhases = []WorkloadPhase{
	PhaseColdStarting, PhaseWarm, PhaseIdle, PhaseDraining, PhaseUnknown,
}

// PHoldInputs are the audited terms of pHold = betaMean + p*(1-betaMean), p = cap*min(1, t/scale),
// then multiplied by the just-moved damping (M-143 form A).
type PHoldInputs struct {
	BetaMean float64 // Beta posterior mean (tenant prior + per-asset event evidence)
	Pressure float64 // p(t_exp) = cap*min(1, t_exp/scaleSec) in [0,cap]
	Cap      float64 // p_max — INSUFFICIENT EVIDENCE, provisional 0.5 (T3-D)
	ScaleSec float64 // T_exp in seconds (today the policy proactive floor; T1-B substitutes the dedicated constant)
	Raw      float64 // betaMean + pressure*(1-betaMean), before damping
	Final    float64 // clamp01(raw * damping) = PHold
}

// Exposure-clock vocabulary: eight clocked-and-consumed dimensions and four
// declared-only dimensions (M-30). Adding a consumer requires its own model review.
const (
	// VarPodIdentity = the pod name/UID/IP — reset on every rotation (LIVE in P0).
	VarPodIdentity = "podIdentity"
	// VarNodePlacement: declared-only: no clock, no consumer (M-30).
	// Wiring placement into a decision requires a separate Math-first ticket.
	VarNodePlacement = "nodePlacement"
	// VarImage: declared-only: no clock, no consumer (container image digest).
	VarImage = "image"
	// VarEnv: declared-only: no clock, no consumer (injected environment).
	VarEnv = "env"
	// VarGPUBinding: declared-only: no clock, no consumer (GPU/MIG binding).
	VarGPUBinding = "gpuBinding"
	// VarNetworkIdentity = service/IP/label identity; clocked from the quarantine epoch (M-23).
	VarNetworkIdentity = "networkIdentity"
	// VarSession = KV-cache / agent session state; clocked from kv-reset|kv-migrate epochs.
	VarSession = "session"
	// M-23 per-action exposure variables — each clocked from the `phorvex.ai/*-epoch`
	// marker its own handler writes (= pod.ResourceVersion at actuation), so the
	// anti-over-rotation guard reads a clock the action actually resets.
	// VarRouteKey = serving route key (endpoint-rotate / route-rotate re-key it).
	VarRouteKey = "routeKey"
	// VarIdentity is the historical identity-epoch relabel clock. New identity-rotate
	// dispatch is refused; this clock never represented SA-token invalidation.
	VarIdentity = "identity"
	// VarAdapterEpoch = adapter-rotate epoch.
	VarAdapterEpoch = "adapterEpoch"
	// VarDrainEpoch = request-drain epoch (M-23 A1 — a dedicated stamp; the serving toggle
	// is boolean and reverts on rollback, so it cannot clock repeated drains).
	VarDrainEpoch = "drainEpoch"
	// VarGuardrailEpoch = guardrail-rotate epoch.
	VarGuardrailEpoch = "guardrailEpoch"
)

// LiveExposureVariables is the SINGLE SOURCE OF TRUTH for the exposure dimensions
// Phorvex actually clocks — the M-23 completeness invariant enumerates it to prove
// every exposureVarFor target is a clocked variable (a mapped-but-unclocked variable
// is a wiring bug caught at build time, so the runtime Check can safely fail-OPEN on an
// absent clock). ExposureFingerprints emits exactly these keys for a fully-marked pod.
var LiveExposureVariables = []string{
	VarPodIdentity, VarSession,
	VarNetworkIdentity, VarRouteKey, VarIdentity, VarAdapterEpoch, VarDrainEpoch, VarGuardrailEpoch,
}

// DeclaredExposureVariables are scaffolded dimensions not yet clocked from live signals.
var DeclaredExposureVariables = []string{VarNodePlacement, VarImage, VarEnv, VarGPUBinding}

// ExposureFingerprints builds the per-variable fingerprint sample the exposure Clock
// observes for a pod (M-23/M-30). Pod identity and session are always
// present (their sources are always populated). The per-action epoch variables are
// ABSENT-SKIPPED: an empty epoch (never actuated, or its marker stripped by a rollback)
// is OMITTED rather than seeded with an empty string — seeding "" would make a later
// rollback that strips the marker look like a fingerprint CHANGE and spuriously reset
// the clock. An omitted variable stays `!ok` in ExposureByVariable, so the guard
// fail-OPENs its first actuation (which writes the marker). The emitted key set for a
// fully-marked pod is exactly LiveExposureVariables (asserted by the completeness test).
func ExposureFingerprints(p Pod) map[string]string {
	fp := map[string]string{
		VarPodIdentity: p.UID,
		VarSession:     p.SessionEpoch,
	}
	for v, epoch := range map[string]string{
		VarNetworkIdentity: p.QuarantineEpoch,
		VarRouteKey:        p.RouteKeyEpoch,
		VarIdentity:        p.IdentityEpoch,
		VarAdapterEpoch:    p.AdapterEpoch,
		VarDrainEpoch:      p.DrainEpoch,
		VarGuardrailEpoch:  p.GuardrailEpoch,
	} {
		if epoch != "" {
			fp[v] = epoch
		}
	}
	return fp
}

// Telemetry is the per-pod live signal vector ingested from Prometheus. Present is
// false when no metrics backend answered (Phorvex then degrades to K8s-only signals
// — NFR3 restart-safe / honest-absent, never fabricated numbers).
// Telemetry is the per-pod observed telemetry (T1-C, SENSING->ECONOMICS). Every signal
// carries its own observation State (Absent|Present|Stale|Error) so no consumer can read
// an absent app-level signal as a measured zero (property P-SENSING; fixes M-142/M-113/M-130).
// The old flat float64 fields + `Present bool` + `PresentSignals map[string]bool` are gone:
// the per-Signal State subsumes both bools.
type Telemetry struct {
	// App-level signals — presence and validity jointly decide Idle-vs-Warm. Their absence,
	// uncertainty, or contradictory measured activity must NEVER route a pod to Idle (M-142).
	ReqRate      Signal
	P99Ms        Signal
	LatencyMs    Signal // legacy mirror of P99Ms (same source)
	QueueDepth   Signal
	GPUUtil      Signal // 0..1
	TokensPerSec Signal
	// cAdvisor / infra signals — universal (every pod has them); their presence NEVER
	// makes a pod Idle. Reading one is fine; letting one imply app activity is the M-142 bug.
	ConnCount   Signal
	BytesIn     Signal
	BytesOut    Signal
	SyscallRate Signal
	// Little's-law flow inputs (PHORVEXSEC-198 / M-115), each over ONE shared observation
	// window and ONE system boundary (the serving engine): InFlightMean is the time-average
	// number in system (avg_over_time of the running-requests gauge), CompletionRate the mean
	// completion rate of the same population (req/s), MeanSojournSec the arithmetic mean
	// time-in-system of that population (histogram sum/count, seconds). Deliberately NOT
	// app-level for PhaseOf. Absent on every class without a mean-sojourn exporter.
	InFlightMean   Signal
	CompletionRate Signal
	MeanSojournSec Signal
	// Raw cAdvisor deltas for T1-M142's phase boundary — logged into the record ONLY.
	// NO consumer reads them in T1-C; the delta thresholds are deliberately unchosen here.
	ConnDeltaPerSec  float64
	BytesDeltaPerSec float64
}

// AppLevelPresent reports whether any application-level signal is a usable measurement.
// PhaseOf keys on this (not any-signal presence) so a pod exporting only universal cAdvisor
// metrics is Warm-by-absence, never Idle-by-absence — the M-142 crux fix.
func (t Telemetry) AppLevelPresent() bool {
	return t.ReqRate.Usable() || t.GPUUtil.Usable() || t.QueueDepth.Usable() || t.TokensPerSec.Usable()
}

// Pod is the K8s-observed state of one protected pod.
type RotationOwnership struct {
	Eligible             bool
	Reason               string
	OwnerUID             string
	OwnerResourceVersion string
}

type Pod struct {
	RotationOwnership RotationOwnership

	Namespace string
	Name      string
	UID       string
	Labels    map[string]string
	// OptOut is the snapshot-time application-owner brake. It excludes this Pod
	// before allocation; dispatch independently rechecks the live Pod.
	OptOut         ActuationBrakeObservation
	Node           string
	Phase          string // raw K8s pod phase
	Ready          bool
	StartedAt      time.Time
	ReadyAt        time.Time // PodReady=True transition; zero when unavailable/not Ready
	Age            time.Duration
	MountedSecrets []string // distinct Secret names referenced by the pod spec (names only)
	ServiceAccount string
	OwnerKind      string
	OwnerName      string
	// WarmPoolConfigured is a conservative read-only snapshot witness for the
	// scalar ReplicaSet warm-pool contract. Final dispatch rechecks live objects.
	WarmPoolConfigured bool
	WarmPoolOwnerUID   string
	DesiredReplicas    int
	ReadyReplicas      int
	HasGPU             bool
	MIGDevice          string
	// SessionEpoch is the concatenated kv-reset / kv-migrate epoch annotations. It changes every
	// time an actuator flushes this pod's KV-cache or agent session, and is what clocks
	// model.VarSession — WITHOUT it, a session-affecting action has no exposure clock of its own
	// and falls through to podIdentity, which it never changes (PHVX-67).
	SessionEpoch string
	// M-23 per-action exposure epochs — the `phorvex.ai/*-epoch` markers the pod-alive
	// rotation handlers write (= pod.ResourceVersion at actuation). "" = never actuated /
	// marker absent, in which case ExposureFingerprints skips it (the variable stays
	// unclocked and the guard fail-OPENs the first actuation). Each clocks the matching
	// model.Var* dimension.
	QuarantineEpoch string // phorvex.ai/quarantine-epoch  -> VarNetworkIdentity (M-23 D2 stamp)
	RouteKeyEpoch   string // phorvex.ai/route-key         -> VarRouteKey (endpoint- & route-rotate re-key)
	IdentityEpoch   string // phorvex.ai/identity-epoch    -> VarIdentity
	AdapterEpoch    string // phorvex.ai/adapter-epoch     -> VarAdapterEpoch
	DrainEpoch      string // phorvex.ai/drain-epoch       -> VarDrainEpoch (M-23 A1 stamp)
	GuardrailEpoch  string // phorvex.ai/guardrail-epoch   -> VarGuardrailEpoch
	Stateful        bool   // owned by a StatefulSet or mounts a PVC / Job

	// --- P-PHYSICS (UCW) additive, zero-valued carriers populated by the platform
	// scanner. Neutral under the existing engine when absent. ---
	ImageID            string              // container image digest (image-rarity + CVE/EPSS keying); "" if unknown
	CPURequestMilli    int64               // sum of container CPU requests (millicores) — scheduler-slack input
	MemRequestBytes    int64               // sum of container memory requests (bytes) — scheduler-slack input
	GPURequestCount    int64               // sum of nvidia.com/gpu (+ mig) device requests — GPU-conservation input
	VRAMRequestBytes   int64               // per-pod GPU VRAM request bytes (AI; 0 = unmeasured; PHORVEXSEC-87)
	SMFraction         float64             // per-pod streaming-multiprocessor compute share [0,1] (AI; 0 = unmeasured)
	ModelID            string              // served model identity/version fingerprint (AI; "" if not a model server)
	EndpointPath       string              // inference endpoint/API route the attacker can map (AI; "" if none)
	SuspectAdapter     string              // name of an UNAUTHORIZED LoRA/adapter a detector flagged on this pod (AI; "" if none) -> adapter-rotate
	AdapterObservation *AdapterObservation // authenticated event and exact current Pod identity behind SuspectAdapter

	// Typed workload and capability witnesses projected from Kubernetes declarations.
	ServingDeclared      bool   // nonblank model-id or a valid explicit serving-port; declaration is not runtime proof
	ServingEndpointReady bool   // ServingDeclared plus Ready and an assigned PodIP; still not a protocol/loaded-model probe
	RouteService         string // phorvex.ai/route-service annotation
	RouteServiceReady    bool   // declared route Service exists in this namespace and can be restitched
	GuardrailVariants    int    // distinct current+alternate guardrail variants declared
	ParallelSize         int    // phorvex.ai/parallel-size; <=0 means absent or invalid
}

// HasModelDeclaration reports whether the workload declares a concrete served-model
// identity. Whitespace is absence; hardware allocation alone is never model identity.
func (p Pod) HasModelDeclaration() bool { return strings.TrimSpace(p.ModelID) != "" }

// HasServingDeclaration reports structural serving context. ServingEndpointReady is
// accepted as the stronger projected witness for compatibility with decoded/constructed
// snapshots, while ingestion always sets ServingDeclared explicitly.
func (p Pod) HasServingDeclaration() bool {
	return p.ServingDeclared || p.ServingEndpointReady || p.HasModelDeclaration()
}

// HasBoundAdapterObservation is the narrow detector authority for adapter-integrity.
// It is independent of generic model/GPU declarations and binds the assertion to this
// exact Pod UID, adapter name, event identity and authenticated creator.
func (p Pod) HasBoundAdapterObservation() bool {
	o := p.AdapterObservation
	return o != nil && p.UID != "" && p.SuspectAdapter != "" &&
		o.AdapterName == p.SuspectAdapter && o.TargetPodUID == p.UID &&
		o.EventName != "" && o.EventUID != "" && o.CreatorIdentity != ""
}

// Attack-vector SecurityEvent rule types. A fired attack NAMES its vector so the engine can
// steer to the SURGICAL actuator for that attack — kv-reset for a KV/prompt-inject implant,
// guardrail-rotate for a jailbreak, request-drain for a request hijack, adapter-rotate for a
// poisoned LoRA — instead of the cheapest generic cover (endpoint-rotate). Recognised as a
// persist-stage threat in killchain.stageFromEvent and consumed in recon (ucw) to make the
// matching fact dominate. Self-limiting: the steer is gone once the event ages out.
const (
	AttackVectorKV        = "phorvex.attack.kv"
	AttackVectorGuardrail = "phorvex.attack.guardrail"
	AttackVectorInflight  = "phorvex.attack.inflight"
	AttackVectorAdapter   = "phorvex.attack.adapter"
)

// AttackVectorForActuator maps the actuator a red-team fire EXPECTS to the vector rule type it
// should carry, so the brain is steered to exactly that surgical move. "" => no dedicated vector
// (fall back to the generic recognised threat), leaving the optimiser's default cover in charge.
func AttackVectorForActuator(actuator string) string {
	switch actuator {
	case "kv-reset", "kv-migrate-invalidate":
		return AttackVectorKV
	case "guardrail-rotate":
		return AttackVectorGuardrail
	case "request-drain":
		return AttackVectorInflight
	case "adapter-rotate":
		return AttackVectorAdapter
	}
	return ""
}

// SecurityEventInfo is a Phorvex-side projection of a Phoenix SecurityEvent used as
// belief evidence (Phorvex consumes the SAME feed Phoenix ingests).
type SecurityEventInfo struct {
	CreatedAt         time.Time
	Outcomes          []ProtectedOutcome
	OutcomeParseError string
	ResolvedTargets   []string
	Name              string // SecurityEvent CR name (audit: which event carried the evidence)
	UID               string // actual SecurityEvent CR UID; empty for direct simulation inputs
	Type              string
	ThreatLevel       string
	Source            string
	Description       string
	AnomalyScore      float64 // -1 when unscored
	Age               time.Duration
	// TimestampMissing is true when the CR carried no usable CreationTimestamp, so Age is
	// not trusted: the event's aging weight is 0 and the record says present=false
	// (M-27). Zero value = present, so every existing literal stays a fresh event.
	TimestampMissing bool
	TargetsPod       bool // true when this event targets THIS pod (vs a graph neighbor)
	// Trust is the ingest verdict on the event's AUTHENTICATED creator (M-94): trusted |
	// self | unstamped | untrusted-identity | no-allowlist. Only a trusted event becomes
	// belief evidence; the rest are still recorded so an injection attempt is visible.
	// Zero value "" = a directly constructed event (tests, simulations), never ingested.
	Trust string
	// CreatorIdentity is the authenticated identity the admission stamp recorded, e.g.
	// "system:serviceaccount:vllm:detector-kv-canary". Empty = unstamped.
	CreatorIdentity  string
	AdapterName      string // event-owned phorvex.ai/adapter-name, never copied from a Pod
	AdapterTargetUID string // event-owned phorvex.ai/target-pod-uid
	// UnresolvedTargets lists targets that carry no namespace (a cluster-scoped "/name"
	// reference). They cannot be keyed to a pod, so they are recorded here instead of being
	// silently dropped (M-94, second half).
	UnresolvedTargets []string
}

// PhoenixExecutionReceipt is the read-only projection of one self-authored
// SecurityEvent. It is kept outside SecurityEventInfo so an actuator's own event
// can never become detector evidence. A receipt is correlation/application
// evidence only; replacement readiness is observed separately by the runner.
type PhoenixExecutionReceipt struct {
	EventName     string
	EventUID      string
	RuleType      string
	ThreatLevel   string
	RuleSource    string
	Targets       []string
	TargetUID     string
	AppliedAction string
	CreatedAt     time.Time
	ProcessedAt   time.Time
}

// VectorSteeringEvent identifies one observation that jointly caused an existing
// attack-vector multiplier. It carries identity and trust evidence only, never payload.
type VectorSteeringEvent struct {
	EventName       string `json:"eventName"`
	EventUID        string `json:"eventUID,omitempty"`
	RuleType        string `json:"ruleType"`
	DeclaredSource  string `json:"declaredSource,omitempty"`
	TrustVerdict    string `json:"trustVerdict,omitempty"`
	CreatorIdentity string `json:"creatorIdentity,omitempty"`
	TargetPodUID    string `json:"targetPodUID,omitempty"`
	AdapterName     string `json:"adapterName,omitempty"`
}

// AdapterObservation identifies the one fresh detector assertion that authorizes
// adapter-integrity and a later adapter eviction. Conflicting names suppress it.
type AdapterObservation struct {
	EventName       string    `json:"eventName"`
	EventUID        string    `json:"eventUID"`
	CreatorIdentity string    `json:"creatorIdentity"`
	TargetPodUID    string    `json:"targetPodUID"`
	AdapterName     string    `json:"adapterName"`
	CreatedAt       time.Time `json:"createdAt"`
}

// VectorSteeringAttribution describes the one factor applied to one recon fact.
// Multiple matching events remain references to one multiplication.
type VectorSteeringAttribution struct {
	RuleType          string                `json:"ruleType"`
	AppliedMultiplier float64               `json:"appliedMultiplier"`
	Events            []VectorSteeringEvent `json:"events"`
}

// NeighborRef is a graph-reachable neighbor and its (generic) asset value — used by
// the P1 recon model to weight lateral-edge facts (cutting an edge to a high-value
// neighbor is worth more).
type NeighborRef struct {
	Key   string // "ns/pod"
	Value float64
}

// PhysicsWitness is the per-pod DISCOVERED physics the platform scanner derives from a
// live cluster scan (P-PHYSICS / UCW). Every field is HONEST-ABSENT: a multiplier
// defaults to 1.0 and a capacity/Present defaults to 0/false, so at nil-data the
// decision is byte-identical to the pre-scan baseline (the 1.62x ablation reproduces
// exactly). The recon EMR profile and the GPU-conservation feasibility laws read it.
//
// The K8s half (ImageRarity/namespace-count CoResidency/SchedulerSlack/PDBMinAvailable/EPSS) is
// measurable on any real cluster. The DCGM half (VRAM/SM/interconnect) is live when
// Prometheus has exporter series for the pod and honest-absent otherwise. Runtime-only
// KV/cold-load values remain separately gated until their serving counters are available.
type PhysicsWitness struct {
	Scanned bool // a platform adapter produced this witness (else all-neutral)

	// --- K8s, measurable now (recon-EMR dispersion multipliers, >=1.0; 1.0 = neutral) ---
	ImageRarity        float64 // 1 + (-log2 freq)/log2(N): heavy-tailed image-digest surprisal [1,2]
	ImageRarityPresent bool    // an image identity participated in the current fleet population
	CoResidency        float64 // historical proxy: 1 + (running_namespaces_on_node-1)/cap [1,2]
	CoResidencyPresent bool    // this pod had a node represented in the current fleet scan
	CoResidencyBasis   string  // running-namespace-count-on-node; never authenticated tenancy/device sharing
	EPSSMultiplier     float64 // the M-104 value multiplier 1 + EPSSScore·(CVSS/10) ∈ [1,2]; exactly 1 when !EPSSPresent (was EPSS)
	EPSSPresent        bool    // a usable (present, finite, in-domain) EPSS/CVSS pair produced the multiplier
	EPSSScore          float64 // raw cache EPSS [0,1]; meaningful only when EPSSPresent
	CVSS               float64 // raw cache CVSS [0,10]; meaningful only when EPSSPresent
	EPSSReason         string  // why the pair was unusable: absent | non-finite | invalid-domain ("" when present)
	// EPSSBasis says HOW the cache answered (M-141): "exact" (running digest scored),
	// "repo-fallback" (latest scan of the same repository, flagged), "miss" (nothing —
	// multiplier neutral, EPSSPresent=false), "" when the pod has no image identity.
	EPSSBasis        string
	EPSSCachedDigest string // the cache key that supplied the value (differs from ImageID on repo-fallback)
	EPSSScanTS       string // when that entry was scanned (RFC3339; "" for caches written before M-141) — audit only, never a branch
	// DispersionCap is used only by an explicitly constructed shadow witness. Zero keeps
	// the shipped MaxDispersionMult, so ordinary production snapshots cannot activate a
	// learned cap accidentally.
	DispersionCap         float64
	SchedulerSlack        float64 // node headroom sum(allocatable-requests)/sum(allocatable) [0,1]
	PDBMinAvailable       int     // live PodDisruptionBudget minAvailable resolved for the owner (-1 = none)
	PDBDisruptionsAllowed int     // live PDB status.disruptionsAllowed (-1 = none)
	MIGGeometryValid      bool    // the pod's MIG partition is a legal device-plugin geometry

	// --- AI / inference, DCGM-live when GPUPresent=true ---
	GPUPresent    bool    // a GPU/DCGM scan answered for this pod's node (false on kind)
	VRAMPresent   bool    // both used/free VRAM series answered with a usable denominator
	VRAMFraction  float64 // pod VRAM demand / device VRAM allocatable [0,1] (0 if !GPUPresent)
	SMOccupancy   float64 // pod SM compute share [0,1]; 0 with SMSource="" when unmeasured
	SMSource      string  // exact occupancy metric used; GPU duty-cycle is never substituted
	LinkBandwidth float64 // PCIe RX+TX demand / DISCOVERED capacity [0,1]; 0 when !LinkPresent
	LinkSource    string  // exact interconnect metric pair used for LinkBandwidth
	// M-114: where the denominator came from. LinkPresent=false means the capacity was
	// undiscoverable (no link telemetry, no class entry) — the ratio is absent, never a
	// borrowed T4 number. On MIG devices the capacity is the physical device's (shared link).
	LinkPresent             bool
	LinkCapacityBytesPerSec float64 // RX+TX aggregate capacity used as the denominator
	LinkCapacitySource      string  // dcgm-link | class-config | absent
	LinkGen, LinkWidth      int     // the link the capacity was derived from
	LinkReason              string  // why absent ("" when present)
	ModelRarity             float64 // 1 + (-log2 freq) over served ModelID across the fleet [1,2]; 1.0 if none
	ModelRarityPresent      bool    // a ModelID participated in the current model population
	KVRebuildSec            float64 // KV-cache rebuild seconds vs session length (0 = unmeasured; PHORVEXSEC-87)
	ColdLoadSec             float64 // model cold/warm-load seconds (0 = unmeasured; PHORVEXSEC-87)
}

// NeutralPhysics is the honest-absent witness (all multipliers 1.0, no capacity, no
// PDB) — what every consumer sees before a scan, guaranteeing baseline reproduction.
func NeutralPhysics() PhysicsWitness {
	return PhysicsWitness{
		ImageRarity: 1, CoResidency: 1, EPSSMultiplier: 1, ModelRarity: 1,
		PDBMinAvailable: -1, PDBDisruptionsAllowed: -1,
	}
}

// WorkloadView is the fully-assembled per-pod picture the decision engine hands to
// the swappable interfaces each tick.
type WorkloadView struct {
	// OutcomeEvents preserves untrusted and audit-only records independently of belief.
	OutcomeEvents      []SecurityEventInfo
	Pod                Pod
	Telemetry          Telemetry
	Phase              WorkloadPhase
	PhaseReason        string  // idle-measured|warm-no-app-signal|warm-uncertain-app-signal|busy-measured|coldstart|draining|unknown
	BlastRadius        float64 // graph score (reach into high-value neighbors), normalized [0,1]
	NeighborCount      int
	Neighbors          []NeighborRef // reachable neighbors with their values (P1 lateral facts)
	Events             []SecurityEventInfo
	ExposureByVariable map[string]time.Duration // per-variable time-since-last-change (observed)
	// IntentByVariable is the per-variable time-since-EMISSION intent (M-23): a move
	// stamped at emission (before the next observed snapshot) so the anti-over-rotation
	// guard throttles a cross-tick burst in the window between actuation and the clock
	// catching up. Absent => no pending intent for that variable.
	IntentByVariable map[string]time.Duration
	// HasEventEvidence mirrors killchain.Assessment.HasEventEvidence (M-28) onto the view so a
	// hard feasibility law can distinguish REACTIVE (a trusted, recent SecurityEvent bears on
	// this pod) from PROACTIVE (hygiene) motion WITHOUT recomputing the predicate. It is the
	// EVENT-ONLY, age-weighted subset — NOT the broad HasEvidence, which also fires on the
	// physics/topology AI classification (model-theft / LLM-jacking-by-GPU-util) that is true for
	// a healthy event-less GPU server and would fail-open the cap on the very churn pod. Stamped
	// by decision.AssembleSet after Assess; zero value = no event evidence (conservative: a view
	// built without the stamp is treated as hygiene). Read by the proactive-cadence cap (M-28).
	HasEventEvidence bool
	Physics          PhysicsWitness // DISCOVERED physics (UCW); honest-absent = neutral

	// InfectionFrontier (P-CONTEXT live-beta Tier-1) is a [1, 1+kappa] AssetValue lift
	// when this pod touches a KNOWN-INFECTED graph neighbor (a neighbor with an exploit+
	// event). It makes NO time-derivative SIR claim (the full dI/dt=beta*S*I-gamma*I is
	// deferred); it only re-weights toward the infection frontier. 0 (== 1.0) at empty
	// infected-set, so the 1.62x gate + ucw nil-data tie reproduce exactly.
	InfectionFrontier float64
}

// ContextSignals are the per-pod conditioning signals a ContextProvider returns.
type ContextSignals struct {
	AssetValue    float64 // consequence weighting (>=0), from labels+secrets+blast radius
	Phase         WorkloadPhase
	ThreatPosture float64 // [0,1], recent event severity for this pod + neighbors
	Exposure      float64 // [0,1], normalized time-since-last-move pressure
	SLOHeadroom   float64 // [0,1], 1 = full latency/availability headroom
	// SLOHeadroomKnown is false when the latency signal was absent/stale/errored: SLOHeadroom
	// then stays fully permissive (never blocks a move, P-NO-FREEZE) but the gate is recorded
	// as skipped and counted rather than passing as a silent full-headroom 1.0 (B-3 fix).
	SLOHeadroomKnown bool
}

// Policy is the RESOLVED (effective) per-tenant configuration snapshot the
// controller builds from a v1alpha1.PhorvexPolicy once per tick, then passes to the
// interfaces — so interface packages never import the API package.
type Policy struct {
	NativeRotate bool // M47: enforce validated ownership for the native delete path.
	// Quarantine capacity is operator-owned, namespace-wide state. Configured=false
	// preserves non-production/offline callers; production always supplies the guard.
	// Known=false is a hard fail-closed inventory result, never an invented zero.
	QuarantineCapacityConfigured bool
	QuarantineCapacityKnown      bool
	QuarantineCapacityUsed       int
	QuarantineCapacityLimit      int
	QuarantineCapacityReason     string

	TrustBoundarySince           time.Time
	DecisionAssets               map[string]string
	MayBreachSLO                 bool
	TrustBoundaryReady           bool
	TrustBoundaryReason          string
	Tenant                       string
	Namespace                    string
	Mode                         string
	DryRun                       bool
	Lambda                       float64
	NormSparsity                 float64
	FlowDisruption               float64
	CostCeiling                  float64
	WeightSecrets                float64
	BlastRadiusFromGraph         bool
	MaxMovesPerTick              int
	TickInterval                 time.Duration
	AntiOverRotationWindow       time.Duration
	ProactiveFloor               time.Duration
	MinAvailableReplicas         int
	P99Ms                        int64
	MinTokensPerSec              int64
	EventDriven                  bool
	ReactiveOnly                 bool
	KillChainSojournScaleSeconds map[string]float64
	KillChainShape               float64
	// ExposurePressureCap is p_max of the capped noisy-OR P(hold) (M-143). 0 means unset:
	// killchain substitutes the provisional default. INSUFFICIENT EVIDENCE — fit in T3-D.
	ExposurePressureCap float64
	// EventAgeHorizon (τ_ev) and ExposurePressureScale (T_exp) are T1-B's dedicated CLOCK->BELIEF
	// horizons. EventAgeHorizon has an independent inherited one-hour default;
	// ExposurePressureScale remains initialized from the proactive floor. A zero internal
	// event horizon resolves through EffectiveEventAgeHorizon for legacy direct construction.
	EventAgeHorizon       time.Duration
	ExposurePressureScale time.Duration
	EnabledActions        map[Action]bool
	AssetWeightFromLabels func(labels map[string]string) float64

	// Decision-trace-only identity. The optimizer never reads these fields while
	// scoring; they let the post-selection trace name the exact policy/build/tick.
	PolicyName   string
	PolicyUID    string
	TickID       string
	BrainImage   string
	GitSHA       string
	TraceEnabled bool
}

// Decision is the per-pod outcome of one tick — the unit written to the audit log
// and Prometheus, and (in active mode only) handed to the actuator.
type Decision struct {
	AdapterObservation *AdapterObservation `json:"adapterObservation,omitempty"`
	Existential        *ExistentialDecision
	// Claim is attached after selection by the reporting boundary.
	Representation *Representation `json:",omitempty"`
	Claim          *ClaimScope
	Tenant         string
	Namespace      string
	Pod            string
	Node           string
	// CoverageValue is the recon-fact weight at stake under the P1 coverage engine.
	// It never carries the deprecated P0 engine's threat-weighted risk.
	CoverageValue float64 // modeled selection opportunity; never measured mitigation
	// ThreatRisk preserves the deprecated P0 engine's distinct threat-weighted value.
	// It is zero under P1 and is serialized separately so one field never has two meanings.
	ThreatRisk    float64
	Cost          float64
	Net           float64 // engine-specific value - Lambda*Cost
	AssetValue    float64
	Residual      float64 // observational under the default P1 coverage engine
	ThreatPosture float64 // observational under the default P1 coverage engine
	Exposure      float64
	PHold         float64 // authoritative P(attacker still holds the foothold) [0,1]
	// Provenance is prov(key) — the evidence/exposure discount applied to this asset's coverage
	// in selection, demand and the standalone fallback alike (M-110). 1 = fully evidenced or
	// past the proactive floor; provFloor..1 = fresh and evidence-less.
	Provenance float64
	// PHoldInputs records every term of the capped noisy-OR that produced PHold
	// (PHORVEXSEC-189 / M-143) so a reader can see the posterior was not annihilated.
	PHoldInputs PHoldInputs
	// StageEvent is the evidence-following event-derived stage (M-27): the max-rank stage
	// among events whose aging weight is > 0; "" when no live event sets a stage.
	StageEvent string
	// StageAI is the AI/inference-derived stage before the merge ("" when silent); StageMergeRule
	// names the merge ("max-consequence") so the final Stage is attributable to event+ai (M-25).
	StageAI        string
	StageMergeRule string
	// EventEvidence is Σ_e w(age_e)·severity_e over events targeting this pod (M-27).
	EventEvidence float64
	// Events lists every ingested event this assessment saw with its age and weight.
	Events             []EventEvidence
	BlastRadius        float64
	SLOHeadroom        float64
	Phase              WorkloadPhase
	Action             Action
	Selected           bool    // chosen within the budget this tick
	Feasible           bool    // all hard constraints passed for the chosen action
	InfeasibleWhy      string  // first blocking constraint, when not feasible
	Reason             string  // short human explanation (attribution)
	R6Counterfactual   Action  // what R6's blind timer/exact-match would have done
	CounterfactualNote string  // why Phorvex's choice differs from R6's blind action
	BlindCost          float64 // cost the blind timer (R6) incurs this cycle (it always rotates) — for the per-decision cost comparison
	DryRun             bool
	DryRunCause        string
	// ActuationBrakeCause is the stable per-target or namespace authority
	// refusal observed after selection. It is empty when no brake refused work.
	ActuationBrakeCause string
	// KillSwitch records that the GLOBAL kill switch suppressed actuation on this tick.
	// Without it a kill-switched decision is byte-identical in the audit to one whose
	// actuator silently failed — both read selected=true, dryRun=false, actuated=false —
	// so a decision-only mirror looks exactly like a broken actuator. Kill-switch and
	// dry-run are separate gates and must stay separately visible.
	KillSwitch      bool
	KillSwitchCause string
	Actuated        bool
	// DispatchOutcome and DispatchReason are the retained, bounded result of
	// this attempt. They are top-level so untraced records and history views do
	// not lose the actual outcome when DecisionTrace is absent or stripped.
	DispatchOutcome string
	DispatchReason  string
	DecidedAt       time.Time

	// --- P1 (submodular recon-coverage) fields; additive, zero-valued under the P0
	// greedy engine. ---
	Engine        string            // "p0-greedy" | "p1-coverage"
	CoveredWeight float64           // modeled recon-fact selection opportunity; not measured mitigation
	CoveredFacts  int               // count of modeled recon facts associated with the selected action
	PerDollar     float64           // legacy full-value / ECost reporting ratio; not the selector
	Stage         string            // most-likely kill-chain stage (semi-Markov)
	StageHazard   float64           // stage-exit hazard h_s(t) (predictive horizon signal)
	NextStage     string            // forward-projected next stage
	Lambda        float64           // legacy mixed runtime lambda frozen for this decision
	ProactiveRate float64           // legacy reporting score derived from PerDollar; not the selector
	Attribution   []AttributionTerm // SHAP-style decomposition of the move's value

	// --- P-CONTEXT predictive horizon (additive, audit-visible). ---
	PreemptMargin         float64 // P(stage not yet transitioned by move-landing) [0,1]
	ProjectedNextStageSec float64 // seconds to the median next-stage transition (<=0 = overdue)
	AIClassified          bool    // an AI kill-chain stage matched (vs the generic chain)

	// --- P-ACTUATOR native-actuator forensic fields (set from the native Result after a
	// successful emit; empty under the Phoenix adapter). A kv-reset is thus distinguishable
	// from a kill in the audit. ---
	Handler        string   // the native handler that enacted (= Action)
	ObjectsTouched []string // cluster objects created/mutated/deleted
	RollbackRef    string   // compensating-undo token ("" = forward-only/irreversible)
	MutationKind   string   // reversible | irreversible | forward-only | swap | declared

	// --- M-18 Phoenix forensic identity of THIS emission attempt (nil = the adapter
	// supplied none; never a placeholder). Set from the actuator Result immediately
	// after Actuate returns, so a partial result carried alongside an error keeps the
	// facts the adapter did supply without altering the failure outcome. ---
	Phoenix *PhoenixForensics

	// Trace is populated only after selection. It is observational and never fed
	// back into candidate generation, scoring, feasibility or actuation.
	Trace *DecisionTraceV2
	// Measurements records which legacy scalar audit fields were actually computed.
	// Scalar zero values alone cannot carry that distinction.
	Measurements *DecisionMeasurementsV1
}

const DecisionMeasurementsSchemaV1 = "phorvex.decision-measurements.v1"

// DecisionMeasurementsV1 is producer-owned presence for optional top-level audit
// scalars. Values are repeated here deliberately: old readers retain the scalar
// fields, while new readers can distinguish a measured zero from unavailable.
type DecisionMeasurementsV1 struct {
	SchemaVersion         string        `json:"schemaVersion"`
	Source                string        `json:"source"`
	ThreatRisk            OptionalFloat `json:"threatRisk"`
	PerDollar             OptionalFloat `json:"perDollar"`
	CoveredWeight         OptionalFloat `json:"coveredWeight"`
	CoveredFacts          OptionalInt   `json:"coveredFacts"`
	StageHazard           OptionalFloat `json:"stageHazard"`
	Lambda                OptionalFloat `json:"lambda"`
	ProactiveRate         OptionalFloat `json:"proactiveRate"`
	PreemptMargin         OptionalFloat `json:"preemptMargin"`
	ProjectedNextStageSec OptionalFloat `json:"projectedNextStageSec"`
	KillSwitch            OptionalBool  `json:"killSwitch"`
	AIClassified          OptionalBool  `json:"aiClassified"`
	EventEvidence         OptionalFloat `json:"eventEvidence"`
	Provenance            OptionalFloat `json:"provenance"`
}

// PhoenixForensics is the forensic identity of ONE Phoenix emission attempt: enough to
// link a decision record to the Phoenix resources and rule context an investigator must
// inspect, without guessing from timestamps or pod names (M-18).
//
// TRUTHFUL REFERENCE SEMANTICS — each field means exactly what its source proves:
//
//   - EventName/EventUID identify the cluster-scoped SecurityEvent this attempt created.
//     The UID is server-assigned and is the ONLY identity that distinguishes a recreated
//     same-name object from the original; a name alone cannot. Both are populated ONLY
//     from a successful Create response, never synthesized for a failed or uncertain one.
//   - AMTDName/AMTDNamespace are the namespaced AMTD that supplies this tenant's rule
//     CONTEXT. EnsurePolicy maintains it as separate standing policy setup, so it is NOT
//     claimed to be created or mutated by this attempt.
//   - RuleType/RuleThreatLevel/RuleSource are the LOGICAL matching tuple carried in the
//     event spec. They are not a Kubernetes object: there is no Rule kind and no Rule UID.
//
// A populated payload establishes CORRELATION only. It never asserts that Phoenix
// executed the action successfully — a created SecurityEvent may receive no successful
// downstream execution at all (M-9), and adoption may be rejected later (M-134). Outcome
// lives in Actuated/DispatchOutcome and is unchanged by this payload.
type PhoenixForensics struct {
	AMTDName        string `json:"amtdName,omitempty"`
	AMTDNamespace   string `json:"amtdNamespace,omitempty"`
	EventName       string `json:"eventName,omitempty"`
	EventUID        string `json:"eventUID,omitempty"`
	RuleType        string `json:"ruleType,omitempty"`
	RuleThreatLevel string `json:"ruleThreatLevel,omitempty"`
	RuleSource      string `json:"ruleSource,omitempty"`
}

// Empty reports whether the adapter supplied no forensic identifier at all. Absence is
// represented honestly as a nil payload rather than a record full of empty strings.
func (p PhoenixForensics) Empty() bool { return p == PhoenixForensics{} }

// DecisionValue returns the engine's primary security-value field without merging their
// meanings in the public Decision/audit contract. P1 uses recon CoverageValue; deprecated
// P0 uses ThreatRisk.
func (d Decision) DecisionValue() float64 {
	if d.Engine == "p0-greedy" {
		return d.ThreatRisk
	}
	return d.CoverageValue
}

// AttributionTerm is one explainable contributor to a decision's value (SHAP-style:
// the marginal coverage a fact-group or signal added).
type AttributionTerm struct {
	Source       string  `json:"source"`
	Contribution float64 `json:"contribution"`
}

// --- M-140 owner identity -------------------------------------------------
//
// One policy UID owns one economic unit. The display Tenant remains the
// user-facing name (authorization, routing, telemetry labels); it no longer
// keys learned state, because two policies in different namespaces may declare
// the same spec.tenant and would otherwise share one lambda dual, one RLS model
// and one belief prior.
//
// Keys are a DISJOINT (kind, value) encoding so an offline fixture whose tenant
// string happens to equal a real policy UID can never share a bucket with it.
const (
	// OwnerKindUID is the production identity: the PhorvexPolicy's UID.
	OwnerKindUID = "uid"
	// OwnerKindName is the fallback for the explicit offline/legacy producers
	// (ablation, benchmark simulation, calib-soak) that build a model.Policy
	// directly and have no API object. Production Upsert rejects an absent UID.
	OwnerKindName = "name"
)

// OwnerKey builds the disjoint owner identity. The separator cannot appear in a
// Kubernetes UID or a tenant name, so the two key spaces never intersect.
func OwnerKey(kind, value string) string { return kind + "\x00" + value }

// Owner is the identity that owns this policy's learned state.
func (p Policy) Owner() string {
	if p.PolicyUID != "" {
		return OwnerKey(OwnerKindUID, p.PolicyUID)
	}
	return OwnerKey(OwnerKindName, p.Tenant)
}

// OwnerKind reports which identity space Owner() used, for decision records.
func (p Policy) OwnerKind() string {
	if p.PolicyUID != "" {
		return OwnerKindUID
	}
	return OwnerKindName
}

// OwnerKindOf reports the identity space an owner key was built in.
func OwnerKindOf(owner string) string {
	for i := 0; i < len(owner); i++ {
		if owner[i] == 0 {
			return owner[:i]
		}
	}
	return ""
}
