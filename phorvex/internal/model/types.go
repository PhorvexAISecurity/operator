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

	"github.com/phorvex/phorvex/internal/voiceadmissionpolicy"
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
	// ActionRotate requests a native, policy-bounded graceful Pod eviction. Pure
	// Phoenix backends refuse it because their Delete strategy cannot carry the cap.
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
	// native-only). This changes endpoint membership while retaining the Pod UID/IP and
	// stable Service UID/ClusterIP/DNS locator. It returns Emitted=false when that
	// deployment contract is absent.
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
	// ActionEndpointLeaseRevoke denies one observed caller lease at a source-bound
	// public inference gateway. It does not hide or change the stable endpoint path.
	ActionEndpointLeaseRevoke Action = "endpoint-lease-revoke"
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
	// ActionGuardrailRotate cycles the safety/guardrail variant. Its protected
	// operation confirms the variant change, not invalidation of a found bypass.
	ActionGuardrailRotate Action = "guardrail-rotate"
	// ActionSensitiveOutputPolicyActivate activates a preinstalled, exact-Pod
	// response-field rule after a trusted observation of that field escaping.
	ActionSensitiveOutputPolicyActivate Action = "sensitive-output-policy-activate"
	// ActionVoiceMemoryNoteRevoke appends one observed caller/note digest to the
	// Voice application's deployment-bound memory quarantine.
	ActionVoiceMemoryNoteRevoke Action = "voice-memory-note-revoke"
	// ActionVoiceRefundPairDeny blocks one exact asserted-caller/order pair in the Voice app.
	ActionVoiceRefundPairDeny Action = "voice-refund-pair-deny"
	// ActionVoiceOutputPolicyActivate blocks one observed synthetic hidden-context
	// marker before Voice speech and assistant transcript persistence.
	ActionVoiceOutputPolicyActivate    Action = "voice-output-policy-activate"
	ActionVoiceSessionAdmissionEnforce Action = "voice-session-admission-enforce"
	// ActionVoiceMCPToolPin binds an observed Voice MCP tool response to an
	// exact reviewed tool authority after the normal selector chooses it.
	ActionVoiceMCPToolPin Action = "voice-mcp-tool-pin"
	// ActionLiteLLMClientRevoke denies one observed, owned client credential at
	// the installed LiteLLM admission gateway. It does not revoke the master key.
	ActionLiteLLMClientRevoke Action = "litellm-client-revoke"
	// ActionKVMigrateInvalidate invalidates/migrates KV across disaggregated prefill/decode
	// (kv-reset is local-only). Local invalidate is real; cross-worker migrate is DEFERRED
	// [PENDING-GPU-VALIDATION] (needs a disaggregated P/D deployment).
	ActionKVMigrateInvalidate Action = "kv-migrate-invalidate"
)

// GuardrailBypassNoCoverReason is shared by the production capability gate and
// the action-set fallback so their diagnostics agree when no action-specific
// deterministic bypass invalidation exists.
const GuardrailBypassNoCoverReason = "recon-cover: cyclic guardrail variant change does not prove bypass invalidation"

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
	ActionSensitiveOutputPolicyActivate,
	ActionVoiceMemoryNoteRevoke,
	ActionLiteLLMClientRevoke,
	ActionVoiceRefundPairDeny,
	ActionVoiceOutputPolicyActivate,
	ActionVoiceMCPToolPin,
	ActionEndpointLeaseRevoke,
	ActionVoiceSessionAdmissionEnforce,
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

// ResourceScope is the stable identity of one hard selection resource. A
// service-availability scope is deliberately bound to both the Service UID and
// the single controller UID proven to own every endpoint in that scope. Names
// remain descriptive only; recreated objects cannot inherit capacity.
type ResourceScope struct {
	Kind          string `json:"kind"`
	Namespace     string `json:"namespace,omitempty"`
	ServiceName   string `json:"serviceName,omitempty"`
	ServiceUID    string `json:"serviceUID,omitempty"`
	ControllerUID string `json:"controllerUID,omitempty"`
}

const (
	ResourceMoveCount               = "move-count"
	ResourceUnavailableReadyReplica = "unavailable-ready-replica"
)

// Key is an unambiguous in-memory identity. The NUL separator cannot appear in
// Kubernetes names or UIDs and avoids the aliasing possible with joined paths.
func (r ResourceScope) Key() string {
	return r.Kind + "\x00" + r.Namespace + "\x00" + r.ServiceUID + "\x00" + r.ControllerUID
}

// Valid rejects name-only or partially bound resources. Move budgets are scoped
// to one policy identity in one namespace; availability budgets additionally
// require the immutable Service and controller UIDs.
func (r ResourceScope) Valid() bool {
	switch r.Kind {
	case ResourceMoveCount:
		return r.Namespace != "" && r.ControllerUID != "" && r.ServiceName == "" && r.ServiceUID == ""
	case ResourceUnavailableReadyReplica:
		return r.Namespace != "" && r.ServiceName != "" && r.ServiceUID != "" && r.ControllerUID != ""
	default:
		return false
	}
}

// ResourceCapacity and ResourceConsumption use integer units. Objective cost is
// intentionally absent: disruption preference and physical capacity are
// different contracts.
type ResourceCapacity struct {
	Scope       ResourceScope `json:"scope"`
	Limit       int           `json:"limit"`
	Outstanding int           `json:"outstanding"`
}

type ResourceConsumption struct {
	Scope ResourceScope `json:"scope"`
	Units int           `json:"units"`
}

// ServiceAvailabilityObservation is the snapshot-time proof used to construct
// unavailable-replica capacity. Complete is true only when the Service,
// EndpointSlice inventory, target membership and a single exact controller UID
// were all established. Dispatch re-reads the same objects before mutation.
type ServiceAvailabilityObservation struct {
	Scope        ResourceScope `json:"scope"`
	ReadyMembers int           `json:"readyMembers"`
	TargetReady  bool          `json:"targetReady"`
	Complete     bool          `json:"complete"`
	Reason       string        `json:"reason,omitempty"`
}

// OwnedValue preserves the distinction between a missing Kubernetes metadata
// key and a present key whose value is empty. Protected serving operations use
// these observations for optimistic selection freshness; concatenated legacy
// fingerprints are deliberately not parsed back into this form.
type OwnedValue struct {
	Present bool
	Value   string
}

// PodBoundKubeAPIAuthProjection is a structural, planned-only capability witness
// from an admitted Pod and its current ServiceAccount. It contains no bearer or
// assertion that an attacker acquired one. Rotate can retire this Pod's API
// authentication capability only after the exact old Pod UID is observed gone;
// Eviction acceptance alone is not that effect.
type PodBoundKubeAPIAuthProjection struct {
	PodUID             string
	PodResourceVersion string
	ServiceAccountName string
	ServiceAccountUID  string
	VolumeName         string
	MountedContainer   string
	AudienceSource     string // "kube-apiserver-default" only; explicit audiences remain unknown
	EvidenceSource     string // "admitted-pod-and-serviceaccount" only
}

type Pod struct {
	RotationOwnership RotationOwnership
	// ServiceAvailability contains one row for every Service whose selector
	// matches this Pod. Empty or incomplete rows cannot authorize a
	// replica-removing action against a positive availability floor.
	ServiceAvailability       []ServiceAvailabilityObservation
	ServiceAvailabilityKnown  bool
	ServiceAvailabilityReason string

	Namespace          string
	Name               string
	UID                string
	PodResourceVersion string
	Labels             map[string]string
	// OptOut is the snapshot-time application-owner brake. It excludes this Pod
	// before allocation; dispatch independently rechecks the live Pod.
	OptOut              ActuationBrakeObservation
	Node                string
	Phase               string // raw K8s pod phase
	Ready               bool
	StartedAt           time.Time
	ReadyAt             time.Time // PodReady=True transition; zero when unavailable/not Ready
	Age                 time.Duration
	MountedSecrets      []string // distinct Secret names referenced by the pod spec (names only)
	ServiceAccount      string
	PodBoundKubeAPIAuth *PodBoundKubeAPIAuthProjection // planned capability, never observed token rejection
	OwnerKind           string
	OwnerName           string
	// ControllerUID is the immutable UID from this Pod's single Kubernetes
	// controller reference. It is independent of the human-readable owner name
	// and is the identity used by shared availability scopes.
	ControllerUID string
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
	SessionEpoch       string
	KVResetEpoch       OwnedValue
	KVMigrateEpoch     OwnedValue
	KVLocalEffectEpoch OwnedValue
	// M-23 per-action exposure epochs — the `phorvex.ai/*-epoch` markers the pod-alive
	// rotation handlers write (= pod.ResourceVersion at actuation). "" = never actuated /
	// marker absent, in which case ExposureFingerprints skips it (the variable stays
	// unclocked and the guard fail-OPENs the first actuation). Each clocks the matching
	// model.Var* dimension.
	QuarantineEpoch           string // phorvex.ai/quarantine-epoch  -> VarNetworkIdentity (M-23 D2 stamp)
	RouteKeyEpoch             string // phorvex.ai/route-key         -> VarRouteKey (endpoint- & route-rotate re-key)
	IdentityEpoch             string // phorvex.ai/identity-epoch    -> VarIdentity
	AdapterEpoch              string // phorvex.ai/adapter-epoch     -> VarAdapterEpoch
	DrainEpoch                string // phorvex.ai/drain-epoch       -> VarDrainEpoch (M-23 A1 stamp)
	GuardrailEpoch            string // phorvex.ai/guardrail-epoch   -> VarGuardrailEpoch
	GuardrailEpochObservation OwnedValue
	Stateful                  bool // owned by a StatefulSet or mounts a PVC / Job

	// --- P-PHYSICS (UCW) additive, zero-valued carriers populated by the platform
	// scanner. Neutral under the existing engine when absent. ---
	ImageID                     string              // container image digest (image-rarity + CVE/EPSS keying); "" if unknown
	CPURequestMilli             int64               // sum of container CPU requests (millicores) — scheduler-slack input
	MemRequestBytes             int64               // sum of container memory requests (bytes) — scheduler-slack input
	GPURequestCount             int64               // sum of nvidia.com/gpu (+ mig) device requests — GPU-conservation input
	VRAMRequestBytes            int64               // per-pod GPU VRAM request bytes (AI; 0 = unmeasured; PHORVEXSEC-87)
	SMFraction                  float64             // per-pod streaming-multiprocessor compute share [0,1] (AI; 0 = unmeasured)
	ModelID                     string              // served model identity/version fingerprint (AI; "" if not a model server)
	EndpointPath                string              // inference endpoint/API route the attacker can map (AI; "" if none)
	SuspectAdapter              string              // name of an UNAUTHORIZED LoRA/adapter a detector flagged on this pod (AI; "" if none) -> adapter-rotate
	AdapterObservation          *AdapterObservation // authenticated event and exact current Pod identity behind SuspectAdapter
	OutputPolicyConfigMap       string
	OutputPolicyRuleSHA256      string
	OutputProxySourceSHA256     string
	OutputSupportSourceSHA256   string
	OutputEventCreator          string
	OutputPolicyObservation     *SensitiveOutputObservation
	VoiceMemoryConfigMap        string
	VoiceMemorySourceSHA256     string
	VoiceMemoryDeploymentUID    string
	VoiceMemoryEventCreator     string
	VoiceMemoryObservation      *VoiceMemoryObservation
	VoiceRefundConfigMap        string
	VoiceRefundSourceSHA256     string
	VoiceRefundDeploymentUID    string
	VoiceRefundEventCreator     string
	VoiceRefundObservation      *VoiceRefundObservation
	VoiceOutputConfigMap        string
	VoiceOutputSourceSHA256     string
	VoiceOutputDeploymentUID    string
	VoiceOutputEventCreator     string
	VoiceAdmissionConfigMap     string
	VoiceAdmissionSourceSHA256  string
	VoiceAdmissionDeploymentUID string
	VoiceAdmissionEventCreator  string
	VoiceAdmissionObservation   *VoiceAdmissionObservation
	VoiceOutputObservation      *VoiceOutputObservation
	VoiceMCPConfigMap           string
	VoiceMCPSourceSHA256        string
	VoiceMCPDeploymentUID       string
	VoiceMCPEventCreator        string
	VoiceMCPObservation         *VoiceMCPObservation
	LiteLLMClientObservation    *LiteLLMClientObservation
	EndpointLeaseObservation    *EndpointLeaseObservation

	// Typed workload and capability witnesses projected from Kubernetes declarations.
	ServingDeclared      bool   // nonblank model-id or a valid explicit serving-port; declaration is not runtime proof
	ServingEndpointReady bool   // ServingDeclared plus Ready and an assigned PodIP; still not a protocol/loaded-model probe
	RouteService         string // phorvex.ai/route-service annotation
	RouteServiceReady    bool   // declared route Service exists in this namespace and can be restitched
	GuardrailVariants    int    // distinct members of a valid complete ordered guardrail roster
	ParallelSize         int    // phorvex.ai/parallel-size; <=0 means absent or invalid
}

// HasPodBoundKubeAPIAuth is deliberately stricter than a ServiceAccount name or
// automount setting. The producer must bind current admitted objects to this Pod;
// manually stale or partial witnesses carry no planned rotate cover.
func (p Pod) HasPodBoundKubeAPIAuth() bool {
	w := p.PodBoundKubeAPIAuth
	return w != nil && p.Namespace != "" && p.Name != "" && p.UID != "" && p.PodResourceVersion != "" &&
		w.PodUID == p.UID && w.PodResourceVersion == p.PodResourceVersion &&
		p.ServiceAccount != "" && w.ServiceAccountName == p.ServiceAccount && w.ServiceAccountUID != "" &&
		w.VolumeName != "" && w.MountedContainer != "" &&
		w.AudienceSource == "kube-apiserver-default" && w.EvidenceSource == "admitted-pod-and-serviceaccount"
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

func (p Pod) HasBoundSensitiveOutputObservation() bool {
	o := p.OutputPolicyObservation
	if o != nil && o.Version == 2 {
		v := o.LiteLLM
		return p.Namespace == "litellm" && p.UID != "" && v != nil &&
			o.TargetPodUID == p.UID && o.EventName != "" && o.EventUID != "" && o.CreatorIdentity != "" &&
			o.ConfigMapUID != "" && o.PolicyName == "litellm-defense" && o.PolicyUID != "" && o.PolicyGeneration > 0 &&
			v.PeerPodUID != "" && v.PeerPodUID != p.UID && v.RuleConfigMapName != "" && v.RuleConfigMapUID != "" && v.RuleSHA256 != "" && v.ProtectedSHA256 != "" &&
			v.ServiceUID != "" && v.DeploymentUID != "" && v.SourceSHA256 != "" && v.ContextSecretUID != "" &&
			v.ContextSeedSHA256 != "" && v.RequestSHA256 != "" && v.OriginalCompletionSHA256 != ""
	}
	return o != nil && p.UID != "" && p.OutputPolicyConfigMap != "" &&
		o.TargetPodUID == p.UID && o.RuleSHA256 == p.OutputPolicyRuleSHA256 &&
		o.ProxySourceSHA256 == p.OutputProxySourceSHA256 &&
		o.SupportSourceSHA256 == p.OutputSupportSourceSHA256 &&
		o.EventName != "" && o.EventUID != "" && o.CreatorIdentity != "" &&
		o.ConfigMapUID != "" && o.ProxyImageID != "" && o.SupportImageID != "" &&
		o.CreatorIdentity == p.OutputEventCreator && o.PolicyName == "guardrail-output-fixture" &&
		o.PolicyUID != "" && o.PolicyGeneration > 0
}

func (p Pod) HasBoundVoiceMemoryObservation() bool {
	o := p.VoiceMemoryObservation
	return o != nil && p.UID != "" && p.VoiceMemoryConfigMap == "voice-memory-policy" &&
		o.TargetPodUID == p.UID && o.DeploymentUID == p.VoiceMemoryDeploymentUID &&
		o.SourceSHA256 == p.VoiceMemorySourceSHA256 && o.ConfigMapUID != "" &&
		o.EventName != "" && o.EventUID != "" && o.CreatorIdentity != "" && o.CreatorIdentity == p.VoiceMemoryEventCreator &&
		o.ScenarioID != "" && o.CaseID != "" &&
		o.PolicyUID != "" && o.PolicyGeneration > 0 && o.CallerID != "" && o.NoteSHA256 != ""
}

func (p Pod) HasBoundVoiceRefundObservation() bool {
	o := p.VoiceRefundObservation
	return o != nil && p.UID != "" && p.VoiceRefundConfigMap == "voice-refund-policy" &&
		o.TargetPodUID == p.UID && o.DeploymentUID == p.VoiceRefundDeploymentUID &&
		o.SourceSHA256 == p.VoiceRefundSourceSHA256 && o.ConfigMapUID != "" &&
		o.EventName != "" && o.EventUID != "" && o.CreatorIdentity != "" &&
		o.CreatorIdentity == p.VoiceRefundEventCreator && o.ScenarioID != "" && o.CaseID != "" &&
		o.PolicyUID != "" && o.PolicyGeneration > 0 && o.AssertedCallerSHA256 != "" && o.OrderSHA256 != ""
}

func (p Pod) HasBoundVoiceAdmissionObservation() bool {
	o := p.VoiceAdmissionObservation
	return o != nil && o.Assertion.Valid() && p.Namespace == "voice" && p.UID != "" && p.VoiceAdmissionConfigMap == voiceadmissionpolicy.ConfigMapName && o.TargetPodUID == p.UID && o.DeploymentUID == p.VoiceAdmissionDeploymentUID && o.SourceSHA256 == p.VoiceAdmissionSourceSHA256 && o.ConfigMapUID == o.Assertion.PolicyCMUID && o.ConfigMapResourceVersion == o.Assertion.PolicyResourceVersion && o.RuleSHA256 == o.Assertion.RuleSHA256 && o.SourceSHA256 == o.Assertion.AdmissionSourceSHA256 && o.SessionID == o.Assertion.SessionID && o.TargetPodUID == o.Assertion.PodUID && o.DeploymentUID == o.Assertion.DeploymentUID && o.PolicyUID == o.Assertion.SecurityPolicyUID && o.PolicyGeneration == o.Assertion.SecurityPolicyGeneration && o.EventName != "" && voiceadmissionpolicy.ValidUID(o.EventUID) && o.CreatorIdentity == voiceadmissionpolicy.Creator && o.CreatorIdentity == p.VoiceAdmissionEventCreator && o.PolicyName != "" && o.ScenarioID == voiceadmissionpolicy.ScenarioID && o.EvidenceSource == "TEST_INJECTED" && o.SelectedRevision == 0
}

func (p Pod) HasBoundVoiceOutputObservation() bool {
	o := p.VoiceOutputObservation
	return o != nil && p.Namespace == "voice" && p.UID != "" && p.VoiceOutputConfigMap == "voice-output-policy" &&
		o.TargetPodUID == p.UID && o.DeploymentUID == p.VoiceOutputDeploymentUID &&
		o.SourceSHA256 == p.VoiceOutputSourceSHA256 && o.ConfigMapUID != "" &&
		o.EventName != "" && o.EventUID != "" && o.CreatorIdentity != "" &&
		o.CreatorIdentity == p.VoiceOutputEventCreator && o.PolicyName != "" && o.PolicyUID != "" &&
		o.PolicyGeneration > 0 && o.MarkerSHA256 != "" && o.ScenarioID == "ai2-system-prompt-leakage" &&
		o.EvidenceSource == "TEST_INJECTED" && o.RawModelMarkerObserved && o.AssistantOutputMarkerObserved
}

func (p Pod) HasBoundVoiceMCPObservation() bool {
	o := p.VoiceMCPObservation
	return o != nil && p.Namespace == "voice" && p.UID != "" && p.VoiceMCPConfigMap == "voice-mcp-tool-policy" &&
		o.TargetPodUID == p.UID && o.DeploymentUID == p.VoiceMCPDeploymentUID &&
		o.SourceSHA256 == p.VoiceMCPSourceSHA256 && o.ConfigMapUID != "" && o.SourceConfigMapUID != "" &&
		o.EventName != "" && o.EventUID != "" && o.CreatorIdentity != "" &&
		o.CreatorIdentity == p.VoiceMCPEventCreator && o.ScenarioID == "ai2-mcp-tool-poisoning" && o.RunSHA256 != "" &&
		o.PolicyName != "" && o.PolicyUID != "" && o.PolicyGeneration > 0 && o.ToolName == "store_directory" &&
		o.GoodDescriptorSHA256 != "" && o.ObservedDescriptorSHA256 != "" &&
		o.MCPServiceName == "mcp-server" && o.MCPServiceUID != "" && o.MCPPodName != "" && o.MCPPodUID != "" && o.MCPDeploymentUID != "" &&
		o.MCPConfigMapUID != "" && o.MCPSourceSHA256 != ""
}

// HasBoundLiteLLMClientObservation licenses only the installed, synthetic
// gateway credential channel. A generic copied credential never satisfies it.
func (p Pod) HasBoundLiteLLMClientObservation() bool {
	o := p.LiteLLMClientObservation
	return o != nil && p.Namespace == "litellm" && p.UID != "" &&
		o.TargetPodUID == p.UID && o.PeerPodUID != "" && o.PeerPodUID != p.UID &&
		o.EventName != "" && o.EventUID != "" && o.CreatorIdentity != "" &&
		o.PolicyName != "" && o.PolicyUID != "" && o.PolicyGeneration > 0 &&
		o.ClientSHA256 != "" && o.ConfigMapUID != "" && o.ServiceUID != "" &&
		o.ClientsConfigMapUID != "" && o.SeedSHA256 != "" && o.GatewaySourceSHA256 != ""
}

// HasBoundEndpointLeaseObservation requires a fresh, source-bound synthetic
// credential observation. The stable endpoint path alone grants no cover.
func (p Pod) HasBoundEndpointLeaseObservation() bool {
	o := p.EndpointLeaseObservation
	return o != nil && p.Namespace == "vllm" && p.UID != "" && o.TargetPodUID == p.UID &&
		o.EventName != "" && o.EventUID != "" && o.CreatorIdentity != "" &&
		o.ScenarioID == "ai2-endpoint-security" && o.EvidenceSource == "TEST_INJECTED" &&
		o.PolicyName != "" && o.PolicyUID != "" && o.PolicyGeneration > 0 &&
		o.ServiceUID != "" && o.PolicyConfigMapUID != "" && o.ProxySourceSHA256 != "" &&
		o.SecretUID != "" && o.SeedSHA256 != "" &&
		o.RevokedClientHMAC != "" && o.RetainedClientHMAC != "" &&
		o.RevokedClientHMAC != o.RetainedClientHMAC &&
		o.AcceptedStatus == 200 && o.AcceptedResponseSHA256 != "" &&
		o.RetainedBaselineStatus == 200 && o.RetainedBaselineResponseSHA256 != "" &&
		!o.ObservedAt.IsZero()
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
	// AttackVectorPodBoundAPIAuth reports exposure of a copied projected
	// default-audience bearer for this exact Pod. It does not establish that a
	// generic copied credential was erased, or request a particular action.
	AttackVectorPodBoundAPIAuth    = "phorvex.attack.pod-bound-api-auth"
	AttackVectorSensitiveOutput    = "phorvex.attack.sensitive-output"
	AttackVectorVoiceMemory        = "phorvex.attack.voice-memory-note"
	AttackVectorVoiceRefund        = "phorvex.attack.voice-refund-pair"
	AttackVectorVoiceOutput        = "phorvex.attack.voice-output-leak"
	AttackVectorVoiceAdmission     = "phorvex.attack.voice-session-admission"
	AttackVectorVoiceMCP           = "phorvex.attack.voice-mcp-descriptor"
	AttackVectorLiteLLMClientAbuse = "phorvex.attack.litellm-client-abuse"
	AttackVectorEndpointLeaseReuse = "phorvex.attack.endpoint-lease-reuse"
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
	case "endpoint-lease-revoke":
		return AttackVectorEndpointLeaseReuse
	}
	return ""
}

// SecurityEventInfo is a Phorvex-side projection of a Phoenix SecurityEvent used as
// belief evidence (Phorvex consumes the SAME feed Phoenix ingests).
const ConsoleTargetPodUIDAnnotation = "phorvex.ai/console-target-pod-uid"

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
	CreatorIdentity string
	// ConsoleTargetPodUID is the event's original Pod lifetime binding, not a
	// UID inferred from a later Pod with the same name. A nonempty
	// TargetBindingReason keeps the event in diagnostic inventory only.
	ConsoleTargetPodUID string
	TargetBindingReason string
	// CompletedDisclosureRaw is an admission-validated producer payload candidate.
	// It still requires current boundary, API UID, policy epoch and exact admission
	// authority before durable retention. The owner chain was frozen by the
	// fail-closed admission transaction. Generic event trust never consumes it.
	CompletedDisclosureRaw               string
	CompletedDisclosureAdmittedAt        string
	CompletedDisclosureAdmissionContract string
	// Current inventory is independently admitted and never inherits generic
	// detector or completed-disclosure authority.
	CurrentInventoryRaw               string
	CurrentInventoryAdmittedAt        string
	CurrentInventoryAdmissionContract string
	AdapterName                       string // event-owned phorvex.ai/adapter-name, never copied from a Pod
	AdapterTargetUID                  string // event-owned phorvex.ai/target-pod-uid
	SensitiveOutputRaw                string // untrusted event annotation, validated against live source before use
	VoiceMemoryRaw                    string // observed caller/note digest assertion; never raw note
	VoiceRefundRaw                    string // asserted caller/order hashes from owned CRM observation
	SensitiveOutputV2Raw              string // LiteLLM output assertion; parsed and bound separately from v1
	VoiceAdmissionRaw                 string
	VoiceOutputRaw                    string // synthetic hidden-context marker hash assertion; never marker bytes
	VoiceMCPRaw                       string // run-owned Voice/MCP descriptor observation; never replacement bytes
	LiteLLMClientRaw                  string // untrusted event annotation, validated against live gateway and policy before use
	EndpointLeaseRaw                  string // untrusted event annotation; requires current proxy/lease authority
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

// SensitiveOutputObservation licenses only one source-bound response-field rule.
// It contains no secret marker or raw customer response.
type SensitiveOutputObservation struct {
	Version                          int                    `json:"version,omitempty"`
	LiteLLM                          *LiteOutputObservation `json:"liteLLM,omitempty"`
	EventName                        string                 `json:"eventName"`
	EventUID                         string                 `json:"eventUID"`
	CreatorIdentity                  string                 `json:"creatorIdentity"`
	TargetPodUID                     string                 `json:"targetPodUID"`
	ConfigMapUID                     string                 `json:"configMapUID"`
	SelectedRevision                 uint64                 `json:"selectedRevision"`
	SelectedConfigMapResourceVersion string                 `json:"selectedConfigMapResourceVersion"`
	PolicyName                       string                 `json:"policyName"`
	PolicyUID                        string                 `json:"policyUID"`
	PolicyGeneration                 int64                  `json:"policyGeneration"`
	RuleSHA256                       string                 `json:"ruleSHA256"`
	ProxySourceSHA256                string                 `json:"proxySourceSHA256"`
	SupportSourceSHA256              string                 `json:"supportSourceSHA256"`
	ProxyImageID                     string                 `json:"proxyImageID"`
	SupportImageID                   string                 `json:"supportImageID"`
	ObservedAt                       time.Time              `json:"observedAt"`
}

// VoiceMemoryObservation is one trusted, source-bound test observation of an
// exact caller/note pair. It does not carry the note or credit first exposure.
type VoiceMemoryObservation struct {
	EventName, EventUID, CreatorIdentity   string
	ScenarioID, CaseID                     string
	TargetPodUID, DeploymentUID            string
	ConfigMapUID, ConfigMapResourceVersion string
	RuleSHA256, SourceSHA256               string
	CallerID                               string `json:"-"` // actuation-only; never serialize caller in decision evidence
	NoteSHA256                             string
	PolicyName, PolicyUID                  string
	PolicyGeneration                       int64
	SelectedRevision                       uint64
	ObservedAt                             time.Time
}

// VoiceRefundObservation binds one observed model callback and owned CRM side effect
// to the exact asserted caller/order pair. It makes no caller authentication claim.
type VoiceRefundObservation struct {
	EventName, EventUID, CreatorIdentity   string
	ScenarioID, CaseID                     string
	TargetPodUID, DeploymentUID            string
	ConfigMapUID, ConfigMapResourceVersion string
	RuleSHA256, SourceSHA256               string
	AssertedCallerSHA256, OrderSHA256      string
	PolicyName, PolicyUID                  string
	PolicyGeneration                       int64
	SelectedRevision                       uint64
	ObservedAt                             time.Time
}

// LiteOutputObservation is digest-only evidence of a real completion from an
// installed, server-owned LiteLLM context. It never carries protected bytes.
type LiteOutputObservation struct {
	ObjectiveID              string `json:"objectiveId"`
	RunNonce                 string `json:"runNonce"`
	PeerPodUID               string `json:"peerPodUID"`
	RuleConfigMapName        string `json:"ruleConfigMapName"`
	RuleConfigMapUID         string `json:"ruleConfigMapUID"`
	RuleSHA256               string `json:"ruleSHA256"`
	ProtectedSHA256          string `json:"protectedSHA256"`
	SourceSHA256             string `json:"sourceSHA256"`
	ServiceUID               string `json:"serviceUID"`
	DeploymentUID            string `json:"deploymentUID"`
	ContextSecretUID         string `json:"contextSecretUID"`
	ContextSeedSHA256        string `json:"contextSeedSHA256"`
	RequestSHA256            string `json:"requestSHA256"`
	OriginalCompletionSHA256 string `json:"originalCompletionSHA256"`
}

// VoiceOutputObservation binds a trusted synthetic first-loss event to the
// selected Voice Pod and append-only output rule. It carries no hidden text.
// VoiceAdmissionObservation binds actual unsigned pipeline evidence to a
// one-way, independently attested Deployment-wide admission rule.
type VoiceAdmissionObservation struct {
	EventName, EventUID, CreatorIdentity   string
	ScenarioID, EvidenceSource             string
	TargetPodUID, DeploymentUID            string
	ConfigMapUID, ConfigMapResourceVersion string
	RuleSHA256, SourceSHA256, SessionID    string
	PolicyName, PolicyUID                  string
	PolicyGeneration                       int64
	SelectedRevision                       uint64
	Assertion                              voiceadmissionpolicy.EventAssertion
	ObservedAt                             time.Time
}

type VoiceOutputObservation struct {
	EventName, EventUID, CreatorIdentity   string
	ScenarioID, EvidenceSource             string
	TargetPodUID, DeploymentUID            string
	ConfigMapUID, ConfigMapResourceVersion string
	RuleSHA256, SourceSHA256, MarkerSHA256 string
	PolicyName, PolicyUID                  string
	PolicyGeneration                       int64
	SelectedRevision                       uint64
	RawModelMarkerObserved                 bool
	AssistantOutputMarkerObserved          bool
	ObservedAt                             time.Time
}

// VoiceMCPObservation binds the first observed descriptor steering to exact
// Voice and MCP source lifetimes. It carries no event-controlled replacement.
type VoiceMCPObservation struct {
	EventName, EventUID, CreatorIdentity   string
	ScenarioID, RunSHA256                  string
	TargetPodUID, DeploymentUID            string
	ConfigMapUID, ConfigMapResourceVersion string
	SourceConfigMapUID                     string
	RuleSHA256, SourceSHA256               string
	ToolName, GoodDescriptorSHA256         string
	ObservedDescriptorSHA256               string
	MCPServiceName, MCPServiceUID          string
	MCPPodName, MCPPodUID                  string
	MCPDeploymentUID, MCPConfigMapUID      string
	MCPSourceSHA256                        string
	PolicyName, PolicyUID                  string
	PolicyGeneration                       int64
	SelectedRevision                       uint64
	ObservedAt                             time.Time
}

// LiteLLMClientObservation binds one trusted synthetic abuse event to the
// exact gateway source, client hash, policy CM and two serving Pod lifetimes.
// It deliberately contains no bearer token or master-key material.
type LiteLLMClientObservation struct {
	EventName           string    `json:"eventName"`
	EventUID            string    `json:"eventUID"`
	CreatorIdentity     string    `json:"creatorIdentity"`
	TargetPodUID        string    `json:"targetPodUID"`
	PeerPodUID          string    `json:"peerPodUID"`
	ClientSHA256        string    `json:"clientSHA256"`
	ConfigMapUID        string    `json:"configMapUID"`
	ClientsConfigMapUID string    `json:"clientsConfigMapUID"`
	SeedSHA256          string    `json:"seedSHA256"`
	ServiceUID          string    `json:"serviceUID"`
	GatewaySourceSHA256 string    `json:"gatewaySourceSHA256"`
	PolicyName          string    `json:"policyName"`
	PolicyUID           string    `json:"policyUID"`
	PolicyGeneration    int64     `json:"policyGeneration"`
	ObservedAt          time.Time `json:"observedAt"`
}

// EndpointLeaseObservation contains only digests and public resource identities.
// The caller credential bytes and signing seed never enter model or audit rows.
type EndpointLeaseObservation struct {
	EventName                      string    `json:"eventName"`
	EventUID                       string    `json:"eventUID"`
	CreatorIdentity                string    `json:"creatorIdentity"`
	ScenarioID                     string    `json:"scenarioId"`
	EvidenceSource                 string    `json:"evidenceSource"`
	PolicyName                     string    `json:"policyName"`
	PolicyUID                      string    `json:"policyUID"`
	PolicyGeneration               int64     `json:"policyGeneration"`
	TargetPodUID                   string    `json:"targetPodUID"`
	ServiceUID                     string    `json:"serviceUID"`
	PolicyConfigMapUID             string    `json:"policyConfigMapUID"`
	ProxySourceSHA256              string    `json:"proxySourceSHA256"`
	SecretUID                      string    `json:"secretUID"`
	SeedSHA256                     string    `json:"seedSHA256"`
	PriorRevision                  uint64    `json:"priorRevision"`
	RevokedClientHMAC              string    `json:"revokedClientHMAC"`
	RetainedClientHMAC             string    `json:"retainedClientHMAC"`
	AcceptedStatus                 int       `json:"acceptedStatus"`
	AcceptedResponseSHA256         string    `json:"acceptedResponseSHA256"`
	RetainedBaselineStatus         int       `json:"retainedBaselineStatus"`
	RetainedBaselineResponseSHA256 string    `json:"retainedBaselineResponseSHA256"`
	ObservedAt                     time.Time `json:"observedAt"`
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
	EPSSBasis                                                        string
	EPSSCachedDigest                                                 string // the cache key that supplied the value (differs from ImageID on repo-fallback)
	EPSSScanTS                                                       string // when that entry was scanned (RFC3339; "" for caches written before M-141) — audit only, never a branch
	EPSSFeedMode, EPSSFeedStatus                                     string
	EPSSFeedScopeSHA256, EPSSFeedCacheSHA256, EPSSFeedMetadataSHA256 string
	EPSSFeedConfigMapUID, EPSSFeedConfigMapResourceVersion           string
	EPSSFeedProducerSource, EPSSFeedObservedAt, EPSSFeedExpiresAt    string
	// DispersionCap is used only by an explicitly constructed shadow witness. Zero keeps
	// the shipped MaxDispersionMult, so ordinary production snapshots cannot activate a
	// learned cap accidentally.
	DispersionCap           float64
	SchedulerSlack          float64 // node headroom sum(allocatable-requests)/sum(allocatable) [0,1]
	PDBMinAvailable         int     // maximum integer minAvailable across matching live PDBs (-1 = none/percentage-only)
	PDBDisruptionsAllowed   int     // live PDB status.disruptionsAllowed (-1 = none)
	PDBObservationAvailable bool    // the PDB list and every matching selector/status epoch were observed
	PDBObservationAttempted bool    // production snapshot attempted the list; false is legacy synthetic input
	PDBMatched              bool    // at least one current PDB selector matched this Pod
	PDBMatchCount           int     // all matching PDBs; their minimum headroom is authoritative for planning
	PDBDesiredHealthy       int     // maximum desiredHealthy across matching PDBs (covers percentage/maxUnavailable)
	PDBObservationReason    string  // explicit unavailable/stale/invalid reason; empty when available
	MIGGeometryValid        bool    // the pod's MIG partition is a legal device-plugin geometry

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
	NativeRotate bool // M47: enforce validated ownership for the native eviction path.
	// Quarantine capacity is operator-owned, namespace-wide state. Configured=false
	// preserves non-production/offline callers; production always supplies the guard.
	// Known=false is a hard fail-closed inventory result, never an invented zero.
	QuarantineCapacityConfigured bool
	QuarantineCapacityKnown      bool
	QuarantineCapacityUsed       int
	QuarantineCapacityLimit      int
	QuarantineCapacityReason     string
	// SharedResourceReservations is the durable outstanding consumption keyed by
	// ResourceScope.Key(). Production fills it from the protected CAS ledger;
	// offline callers may leave it nil to model no prior outstanding work.
	SharedResourceReservations       map[string]int
	SharedResourceCapacityConfigured bool
	SharedResourceReservationsKnown  bool
	SharedResourceReservationsReason string

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
	DisruptionAversion           float64
	DisruptionAversionConfigured bool
	NormSparsity                 float64
	FlowDisruption               float64
	CostCeiling                  float64
	WeightSecrets                float64
	BlastRadiusFromGraph         bool
	MaxMovesPerTick              int
	// MaxGracePeriodSeconds is the resolved selecting-policy cap for native
	// graceful rotation. Zero denotes invalid/unavailable policy input and must be
	// refused at the mutation boundary; it never means force deletion.
	MaxGracePeriodSeconds        int64
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

	// Policy identity binds both post-selection native dispatch and observed-outcome
	// admission to the exact current policy epoch; optimizer scoring ignores it.
	// The remaining fields identify the decision build and tick in its trace.
	PolicyName       string
	PolicyUID        string
	PolicyGeneration int64
	TickID           string
	BrainImage       string
	GitSHA           string
	TraceEnabled     bool
}

// GracefulTerminationReceipt binds an accepted native Pod Eviction request to the exact
// policy epoch, Pod identity and explicit graceful request sent to Kubernetes.
// It is request evidence only: TerminationStatus remains "unconfirmed" until a
// separate lifecycle observer proves the old process/UID absent.
type GracefulTerminationReceipt struct {
	PolicyNamespace             string `json:"policyNamespace"`
	PolicyName                  string `json:"policyName"`
	PolicyUID                   string `json:"policyUID"`
	PolicyGeneration            int64  `json:"policyGeneration"`
	PolicyGraceCapSeconds       int64  `json:"policyGraceCapSeconds"`
	WorkloadGraceSeconds        int64  `json:"workloadGraceSeconds"`
	WorkloadGraceExplicit       bool   `json:"workloadGraceExplicit"`
	EffectiveGracePeriodSeconds int64  `json:"effectiveGracePeriodSeconds"`
	PodUID                      string `json:"podUID"`
	PodResourceVersion          string `json:"podResourceVersion"`
	TerminationStatus           string `json:"terminationStatus"`
}

// DrainRequestDisposition is a bounded digest of a validated v11 scheduler ID.
// Raw request IDs can be caller controlled and must not enter the manager audit.
type DrainRequestDisposition struct {
	RequestSHA256 string `json:"requestSHA256"`
	Disposition   string `json:"disposition"`
}

// DrainOperationEvidence is the terminal native observation copied before the
// protected operation journal is removed. It does not itself prove mitigation.
type DrainOperationEvidence struct {
	OperationID        string                    `json:"operationID"`
	Generation         string                    `json:"generation"`
	PolicyUID          string                    `json:"policyUID"`
	TargetUID          string                    `json:"targetUID"`
	ServiceUID         string                    `json:"serviceUID"`
	BackendIncarnation string                    `json:"backendIncarnation"`
	ReceiptSHA256      string                    `json:"receiptSHA256"`
	ProxyActive        int                       `json:"proxyActive"`
	SnapshotRunning    int                       `json:"snapshotRunning"`
	Aborted            int                       `json:"aborted"`
	CompletedBefore    int                       `json:"completedBeforeAbort"`
	SnapshotRequests   []string                  `json:"snapshotRequestSHA256,omitempty"`
	Dispositions       []DrainRequestDisposition `json:"dispositions,omitempty"`
	Reopened           bool                      `json:"reopened"`
	Restored           bool                      `json:"restored"`
}

func CloneDrainOperationEvidence(in *DrainOperationEvidence) *DrainOperationEvidence {
	if in == nil {
		return nil
	}
	out := *in
	out.SnapshotRequests = append([]string(nil), in.SnapshotRequests...)
	out.Dispositions = append([]DrainRequestDisposition(nil), in.Dispositions...)
	return &out
}

// Decision is the per-pod outcome of one tick — the unit written to the audit log
// and Prometheus, and (in active mode only) handed to the actuator.
type Decision struct {
	AdapterObservation        *AdapterObservation         `json:"adapterObservation,omitempty"`
	OutputPolicyObservation   *SensitiveOutputObservation `json:"outputPolicyObservation,omitempty"`
	VoiceMemoryObservation    *VoiceMemoryObservation     `json:"voiceMemoryObservation,omitempty"`
	VoiceRefundObservation    *VoiceRefundObservation     `json:"voiceRefundObservation,omitempty"`
	VoiceAdmissionObservation *VoiceAdmissionObservation  `json:"voiceAdmissionObservation,omitempty"`
	VoiceOutputObservation    *VoiceOutputObservation     `json:"voiceOutputObservation,omitempty"`
	VoiceMCPObservation       *VoiceMCPObservation        `json:"voiceMcpObservation,omitempty"`
	Existential               *ExistentialDecision
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
	Net           float64 // engine-specific value - frozen effective cost coefficient*Cost
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
	Engine              string                     // "p0-greedy" | "p1-coverage"
	CoveredWeight       float64                    // modeled recon-fact selection opportunity; not measured mitigation
	CoveredFacts        int                        // count of modeled recon facts associated with the selected action
	PerDollar           float64                    // legacy full-value / ECost reporting ratio; not the selector
	Stage               string                     // most-likely kill-chain stage (semi-Markov)
	StageHazard         float64                    // stage-exit hazard h_s(t) (predictive horizon signal)
	NextStage           string                     // forward-projected next stage
	Lambda              float64                    // legacy mixed runtime lambda frozen for this decision
	Economics           *EconomicsMetadata         // frozen objective coefficient; present for P1 decisions even when rich tracing is disabled
	ParameterSet        *ParameterSetReference     // compact source/default and exact effective-policy identity; present for new P1 decisions
	PersistenceLearning *PersistenceLearningStatus // legacy audit compatibility only; new outcomes never write or consume it
	ScopedOutcomes      *ScopedOutcomeReport       // reporting-only synthetic session outcome cohorts; never consumed by PHold or selection
	ProactiveRate       float64                    // reporting score derived from PerDollar and the frozen effective coefficient; not the selector
	Attribution         []AttributionTerm          // SHAP-style decomposition of the move's value
	// Resources is the selected candidate's exact hard-capacity consumption.
	// It is empty for noop and legacy engines.
	Resources []ResourceConsumption

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
	// GracefulTermination is present only after Kubernetes acknowledged the
	// exact native rotate Eviction request. It records the requested bound while leaving
	// physical termination explicitly unconfirmed.
	GracefulTermination *GracefulTerminationReceipt
	DrainOperation      *DrainOperationEvidence

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
