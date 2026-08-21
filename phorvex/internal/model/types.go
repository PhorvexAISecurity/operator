/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

// Package model holds the shared, dependency-free domain types that every Phorvex
// subsystem exchanges (ingest -> graph -> physics/context/belief/cost/feasibility
// -> decision -> actuator -> audit/metrics). It imports NOTHING from the rest of
// Phorvex, so the swappable interface packages couple only to these plain types and
// "adding a profile/constraint/model = one file" stays true.
package model

import "time"

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
	// law. AI/GPU magnitudes are [SP-0-PENDING] (read the GPUPresent-gated PhysicsWitness).

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
	// ActionIdentityRotate writes a fresh `phorvex.ai/identity-epoch` LABEL on the pod
	// (advanced K8s; native-only). It does NOT change the SA token, the UID or the IP —
	// the SA-token branch is a deliberate no-op because projected tokens rotate on their
	// own — so it does not invalidate the podIdentity recon fact. See handlers_k8s.go and
	// recon/profile.go, where the cover grant was removed for exactly this reason.
	ActionIdentityRotate Action = "identity-rotate"
	// ActionRouteRotate writes a fresh `phorvex.ai/route-epoch` LABEL (advanced K8s;
	// native-only). It does NOT restitch a Service selector and does NOT touch
	// EndpointSlices — `endpoint-rotate` is the action that re-keys a declared Service —
	// so the attacker's learned route is NOT staled and the networkIdentity cover grant
	// was removed.
	ActionRouteRotate Action = "route-rotate"
	// ActionWarmSwap rotates WITHOUT the cold-load: provision a Ready warm replacement
	// then retire (provision-before-retire). [SP-0-PENDING] magnitude=ColdLoadSec.
	ActionWarmSwap Action = "warm-swap"
	// ActionMIGRebind moves to a non-co-resident MIG partition then warm-cutover.
	// [SP-0-PENDING] (GPU-bound).
	ActionMIGRebind Action = "mig-rebind"
	// ActionKVReset flushes KV-cache/agent-session in-process WITHOUT killing the pod —
	// the only move that defeats a wipe-surviving prompt-inject implant. [SP-0-PENDING].
	ActionKVReset Action = "kv-reset"
	// ActionEndpointRotate re-keys the served-model route/endpoint. [SP-0-PENDING].
	ActionEndpointRotate Action = "endpoint-rotate"
	// ActionModelShardReplace warm-replaces a model shard on a target id/version.
	// [SP-0-PENDING] magnitude=ColdLoadSec/ModelRarity.
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

// MutatingActions is the SINGLE SOURCE OF TRUTH for every action a policy may enable and
// the optimizer may emit (every const EXCEPT ActionNoop and the declared-only
// ActionDisable). Both actionset.enabledActions and decision.candidateActions iterate it
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

// Exposure-clock variable dimensions (the per-VARIABLE exposure scaffold). P0 wires
// the K8s-observable dimensions (PodIdentity, NodePlacement) live and DECLARES the
// rest so a later phase fills them without a schema change.
const (
	// VarPodIdentity = the pod name/UID/IP — reset on every rotation (LIVE in P0).
	VarPodIdentity = "podIdentity"
	// VarNodePlacement = the node the pod runs on — reset on node-rotate (LIVE in P0).
	VarNodePlacement = "nodePlacement"
	// VarImage = the container image digest (DECLARED; Phase 1 mutation overlay).
	VarImage = "image"
	// VarEnv = injected environment (DECLARED; Phase 1 mutation overlay).
	VarEnv = "env"
	// VarGPUBinding = the GPU/MIG binding (DECLARED; Phase 2/3 GPU rebind).
	VarGPUBinding = "gpuBinding"
	// VarNetworkIdentity = service/IP/label identity (DECLARED; Phase 2).
	VarNetworkIdentity = "networkIdentity"
	// VarSession = KV-cache / agent session state (DECLARED; AI path).
	VarSession = "session"
)

// LiveExposureVariables are the dimensions Phorvex P0 actually clocks from the K8s
// API. The DeclaredExposureVariables extend this set in later phases.
var LiveExposureVariables = []string{VarPodIdentity, VarNodePlacement}

// DeclaredExposureVariables are scaffolded but not yet clocked from live signals.
var DeclaredExposureVariables = []string{VarImage, VarEnv, VarGPUBinding, VarNetworkIdentity, VarSession}

// Telemetry is the per-pod live signal vector ingested from Prometheus. Present is
// false when no metrics backend answered (Phorvex then degrades to K8s-only signals
// — NFR3 restart-safe / honest-absent, never fabricated numbers).
type Telemetry struct {
	Present      bool
	ReqRate      float64
	LatencyMs    float64
	P99Ms        float64
	QueueDepth   float64
	ConnCount    float64
	BytesIn      float64
	BytesOut     float64
	GPUUtil      float64 // 0..1
	SyscallRate  float64
	TokensPerSec float64
}

// Pod is the K8s-observed state of one protected pod.
type Pod struct {
	Namespace       string
	Name            string
	UID             string
	Labels          map[string]string
	Node            string
	Phase           string // raw K8s pod phase
	Ready           bool
	StartedAt       time.Time
	ReadyAt         time.Time // PodReady=True transition; zero when unavailable/not Ready
	Age             time.Duration
	MountedSecrets  []string // distinct Secret names referenced by the pod spec (names only)
	ServiceAccount  string
	OwnerKind       string
	OwnerName       string
	DesiredReplicas int
	ReadyReplicas   int
	HasGPU          bool
	MIGDevice       string
	// SessionEpoch is the concatenated kv-reset / kv-migrate epoch annotations. It changes every
	// time an actuator flushes this pod's KV-cache or agent session, and is what clocks
	// model.VarSession — WITHOUT it, a session-affecting action has no exposure clock of its own
	// and falls through to podIdentity, which it never changes (PHVX-67).
	SessionEpoch string
	Stateful     bool // owned by a StatefulSet or mounts a PVC / Job

	// --- P-PHYSICS (UCW) additive, zero-valued carriers populated by the platform
	// scanner. Neutral under the existing engine when absent. ---
	ImageID          string  // container image digest (image-rarity + CVE/EPSS keying); "" if unknown
	CPURequestMilli  int64   // sum of container CPU requests (millicores) — scheduler-slack input
	MemRequestBytes  int64   // sum of container memory requests (bytes) — scheduler-slack input
	GPURequestCount  int64   // sum of nvidia.com/gpu (+ mig) device requests — GPU-conservation input
	VRAMRequestBytes int64   // per-pod GPU VRAM request bytes (AI; 0 = unmeasured / [SP-0-PENDING])
	SMFraction       float64 // per-pod streaming-multiprocessor compute share [0,1] (AI; 0 = unmeasured)
	ModelID          string  // served model identity/version fingerprint (AI; "" if not a model server)
	EndpointPath     string  // inference endpoint/API route the attacker can map (AI; "" if none)
	SuspectAdapter   string  // name of an UNAUTHORIZED LoRA/adapter a detector flagged on this pod (AI; "" if none) -> adapter-rotate

	// Typed capability witnesses used only for operator-facing ActionsSupported status.
	ServingEndpointReady bool   // Ready AI pod with an assigned PodIP / serving endpoint
	RouteService         string // phorvex.ai/route-service annotation
	GuardrailVariants    int    // distinct current+alternate guardrail variants declared
	ParallelSize         int    // phorvex.ai/parallel-size; <=0 means absent or invalid
	MIGGPUID             string // phorvex.ai/gpu-id annotation used by mig-rebind
	MIGTargetProfile     string // phorvex.ai/mig-target-profile annotation used by mig-rebind
}

// SecurityEventInfo is a Phorvex-side projection of a Phoenix SecurityEvent used as
// belief evidence (Phorvex consumes the SAME feed Phoenix ingests).
type SecurityEventInfo struct {
	Type         string
	ThreatLevel  string
	Source       string
	Description  string
	AnomalyScore float64 // -1 when unscored
	Age          time.Duration
	TargetsPod   bool // true when this event targets THIS pod (vs a graph neighbor)
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
// The K8s half (ImageRarity/CoResidency/SchedulerSlack/PDBMinAvailable/EPSS) is
// measurable on any real cluster. The DCGM half (VRAM/SM/interconnect) is live when
// Prometheus has exporter series for the pod and honest-absent otherwise. Runtime-only
// KV/cold-load values remain separately gated until their serving counters are available.
type PhysicsWitness struct {
	Scanned bool // a platform adapter produced this witness (else all-neutral)

	// --- K8s, measurable now (recon-EMR dispersion multipliers, >=1.0; 1.0 = neutral) ---
	ImageRarity float64 // 1 + (-log2 freq)/log2(N): heavy-tailed image-digest surprisal [1,2]
	CoResidency float64 // 1 + (tenants_on_node-1)/maxTenants: shared-node co-location [1,2]
	EPSS        float64 // 1 + (0.5*EPSS + 0.5*CVSS/10): CVE/EPSS attacker-utility [1,2]
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
	VRAMFraction  float64 // pod VRAM demand / device VRAM allocatable [0,1] (0 if !GPUPresent)
	SMOccupancy   float64 // pod SM compute share [0,1]; 0 with SMSource="" when unmeasured
	SMSource      string  // exact occupancy metric used; GPU duty-cycle is never substituted
	LinkBandwidth float64 // NVLink/PCIe/NIC demand / ceiling [0,1] (0 if !GPUPresent)
	LinkSource    string  // exact interconnect metric pair used for LinkBandwidth
	ModelRarity   float64 // 1 + (-log2 freq) over served ModelID across the fleet [1,2]; 1.0 if none
	KVRebuildSec  float64 // KV-cache rebuild seconds vs session length (0 = [SP-0-PENDING])
	ColdLoadSec   float64 // model cold/warm-load seconds (0 = [SP-0-PENDING])
}

// NeutralPhysics is the honest-absent witness (all multipliers 1.0, no capacity, no
// PDB) — what every consumer sees before a scan, guaranteeing baseline reproduction.
func NeutralPhysics() PhysicsWitness {
	return PhysicsWitness{
		ImageRarity: 1, CoResidency: 1, EPSS: 1, ModelRarity: 1,
		PDBMinAvailable: -1, PDBDisruptionsAllowed: -1,
	}
}

// WorkloadView is the fully-assembled per-pod picture the decision engine hands to
// the swappable interfaces each tick.
type WorkloadView struct {
	Pod                Pod
	Telemetry          Telemetry
	Phase              WorkloadPhase
	BlastRadius        float64 // graph score (reach into high-value neighbors), normalized [0,1]
	NeighborCount      int
	Neighbors          []NeighborRef // reachable neighbors with their values (P1 lateral facts)
	Events             []SecurityEventInfo
	ExposureByVariable map[string]time.Duration // per-variable time-since-last-change
	Physics            PhysicsWitness           // DISCOVERED physics (UCW); honest-absent = neutral

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
}

// Policy is the RESOLVED (effective) per-tenant configuration snapshot the
// controller builds from a v1alpha1.PhorvexPolicy once per tick, then passes to the
// interfaces — so interface packages never import the API package.
type Policy struct {
	Tenant                       string
	Namespace                    string
	Mode                         string
	DryRun                       bool
	Lambda                       float64
	NormSparsity                 float64
	FlowDisruption               float64
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
	EnabledActions               map[Action]bool
	AssetWeightFromLabels        func(labels map[string]string) float64
}

// Decision is the per-pod outcome of one tick — the unit written to the audit log
// and Prometheus, and (in active mode only) handed to the actuator.
type Decision struct {
	Tenant    string
	Namespace string
	Pod       string
	Node      string
	// CoverageValue is the recon-fact weight at stake under the P1 coverage engine.
	// It never carries the deprecated P0 engine's threat-weighted risk.
	CoverageValue float64
	// ThreatRisk preserves the deprecated P0 engine's distinct threat-weighted value.
	// It is zero under P1 and is serialized separately so one field never has two meanings.
	ThreatRisk         float64
	Cost               float64
	Net                float64 // engine-specific value - Lambda*Cost
	AssetValue         float64
	Residual           float64 // observational under the default P1 coverage engine
	ThreatPosture      float64 // observational under the default P1 coverage engine
	Exposure           float64
	PHold              float64 // authoritative P(attacker still holds the foothold) [0,1]
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
	// KillSwitch records that the GLOBAL kill switch suppressed actuation on this tick.
	// Without it a kill-switched decision is byte-identical in the audit to one whose
	// actuator silently failed — both read selected=true, dryRun=false, actuated=false —
	// so a decision-only mirror looks exactly like a broken actuator. Kill-switch and
	// dry-run are separate gates and must stay separately visible.
	KillSwitch bool
	Actuated   bool
	DecidedAt  time.Time

	// --- P1 (submodular recon-coverage) fields; additive, zero-valued under the P0
	// greedy engine. ---
	Engine        string            // "p0-greedy" | "p1-coverage"
	CoveredWeight float64           // recon-fact weight invalidated by the chosen move
	CoveredFacts  int               // count of distinct recon facts invalidated
	PerDollar     float64           // CoveredWeight / cost (the criterion-4 ratio, logged)
	Stage         string            // most-likely kill-chain stage (semi-Markov)
	StageHazard   float64           // stage-exit hazard h_s(t) (predictive horizon signal)
	NextStage     string            // forward-projected next stage
	Lambda        float64           // solved budget shadow-price at decision time
	ProactiveRate float64           // emergent per-asset rotation rate (1/sec); 0 if not due
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
}

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
