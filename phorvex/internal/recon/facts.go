/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 */

// Package recon is the P1 "physics": the per-tenant PERTURBABLE-VARIABLE + RECON-FACT
// model that turns the attacker's reconnaissance into a weighted fact-universe and
// defines, per action, exactly which facts a move INVALIDATES (its cover set). This
// is the substrate the submodular recon-coverage optimizer maximizes over, and the
// thing the STEP-3 ablation measures "facts-invalidated-per-dollar" against.
//
// A FACT is a (scope, variable, asset) tuple the attacker has learned or is about to learn,
// crisply tied to a measured exposure variable so the per-dollar number is
// falsifiable (METHOD-DECISION risk #a). Each fact carries a weight =
// value x P(hold) x stage-urgency (x blast for lateral edges).
package recon

import (
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

// FactScope identifies the physical ownership domain of a fact. Only pod-scoped facts can enter
// the current pod-partition decision objective. Node/model/service facts are retained as audit
// evidence until the model has an explicit decision block and deterministic eraser for that scope.
type FactScope string

const (
	ScopePod     FactScope = "pod"
	ScopeNode    FactScope = "node"
	ScopeModel   FactScope = "model"
	ScopeService FactScope = "service"
)

// FactKind enumerates the recon variables, each tied to an exposure-clock variable.
const (
	// FactPodIdentity = pod name/UID/IP the attacker mapped (exposure: podIdentity).
	FactPodIdentity = "podIdentity"
	// FactSession = ephemeral in-process KV-cache / agent-session state (exposure: session).
	// It does not represent pod identity, route knowledge, or generic compromise state.
	FactSession = "session"
	// FactInMemory = in-memory implant / loaded secrets / runtime state.
	FactInMemory = "inMemory"
	// FactNetworkIdentity = the pod's reachable network identity (exposure: networkIdentity).
	FactNetworkIdentity = "networkIdentity"
	// FactLateralEdge = a learned reachable edge to a specific neighbor (the Edge field).
	FactLateralEdge = "lateralEdge"
	// FactNodePlacement was removed (PHVX-77): it had no producer, no consumer and no cover grant —
	// two repo-wide references, both its own comment and declaration. The exposure VARIABLE
	// model.VarNodePlacement is unrelated and declared-only (M-30); do not confuse the two if this is
	// reintroduced.

	// --- AI / inference recon facts (P-PHYSICS / UCW). The attacker's recon map of an
	// inference workload.
	//
	// These no longer share one blanket status. Cover is action- and capability-specific:
	// modelFingerprint and endpointPath are audit-only, while GPU contention
	// is covered only for a MIG-capable pod and GPU co-location currently carries no grant.
	// Anything genuinely cover-free must say so per-fact and be asserted in cover_test.
	// Corrected under PHVX-76. ---

	// FactModelFingerprint = served model identity/version the attacker fingerprinted
	// (AUDIT-ONLY: model-shard-replace does not prove loaded identity changes or invalidation).
	FactModelFingerprint = "modelFingerprint"
	// FactEndpointPath = inference endpoint / API route the attacker mapped. AUDIT-ONLY:
	// endpoint-rotate does not prove the learned locator is invalidated.
	// route-rotate also retains the Pod and stable Service locators, so selector membership
	// changes do not grant it endpointPath or networkIdentity cover.
	FactEndpointPath = "endpointPath"
	// FactEndpointLeaseReuse is one observed, source-bound caller lease used
	// against the protected public inference route. Revoking that exact lease
	// invalidates this credential fact; endpointPath remains audit-only.
	FactEndpointLeaseReuse = "endpointLeaseReuse"
	// FactGPUColocation = workload-level shared-GPU/MIG co-residency exposure. Although its
	// measurement is node-derived, each pod key represents one victim workload's exposure rather
	// than a count of affected physical devices. AUDIT-ONLY today: neither mig-rebind nor warm-swap
	// proves relocation to a different node/device.
	FactGPUColocation = "gpuColocation"
	// FactGPUContentionChannel = the shared-hardware CONTENTION path through which a co-tenant is
	// observable: memory bandwidth, cache and SM contention on one physical device.
	//
	// Scoped deliberately (PHVX-26a). Power and thermal side channels are NOT claimed — MIG's
	// isolation of those paths is a vendor claim and is contested in published work, so an action
	// that repartitions the device cannot be said to erase them.
	//
	// Distinct from FactGPUColocation, which is the attacker's knowledge of WHICH workloads share
	// their device. A MIG repartition severs the contention path without moving anything, so it
	// erases this fact and leaves the co-residency knowledge intact. Renamed from FactSideChannel:
	// the old name described a symptom class, not the thing an action can actually invalidate.
	FactGPUContentionChannel = "gpuContentionChannel"
	// FactAdapterIntegrity = an UNAUTHORIZED LoRA/adapter loaded on the serving stack (a detector
	// flagged it). It exists ONLY while the poisoned adapter is present, and ONLY adapter-rotate
	// (unload the adapter) covers it — so the engine selects adapter-rotate for THIS attack, not a
	// generic rotate/kv-reset.
	FactAdapterIntegrity = "adapterIntegrity"

	// FactInflightRequests = the attacker's IN-FLIGHT request / queue / streaming-session state on a
	// serving pod (distinct from the KV-cache session): the requests currently being served that a
	// hijacked client rides. Covered by request-drain (graceful connection drain, no pod kill) — so the
	// engine can pick a surgical drain over a full rotate on an inference workload.
	FactInflightRequests = "inflightRequests"
	// FactGuardrailBypass = a learned jailbreak / prompt-injection that BYPASSES the pod's CURRENT
	// safety-guardrail variant. It is audit-only for the cyclic guardrail-rotate action: a different
	// variant is not proof that the same request stops working. The fact retains exact event
	// attribution, but no deterministic actuator currently earns its cover.
	FactGuardrailBypass = "guardrailBypass"
	// FactSensitiveOutputExposure is a fresh, UID/source-bound observed
	// application response field that remains exposed on identical repeats
	// until its preinstalled exact-field policy is activated. First loss is
	// irreversible; this fact describes only the repeat path.
	FactSensitiveOutputExposure = "sensitiveOutputExposure"
	// FactVoiceMemoryContamination is repeat exposure of one exact caller's
	// observed harmful memory note. Quarantine cannot undo first contamination.
	FactVoiceMemoryContamination = "voiceMemoryContamination"
	// FactVoiceRefundPairExposure is repeat use of one asserted caller/order pair
	// after an observed model callback and owned CRM refund side effect.
	FactVoiceRefundPairExposure = "voiceRefundPairExposure"
	// FactVoiceMCPDescriptorSteering is the prospective repeat path after one
	// observed poisoned descriptor entered the installed Voice model context.
	FactVoiceMCPDescriptorSteering = "voiceMcpDescriptorSteering"
	FactVoiceOutputExposure        = "voiceOutputExposure"
	// FactLiteLLMOwnedClientChannel is the repeat-use capability of one
	// synthetic client credential at the installed admission gateway. It does
	// not represent copied master-key knowledge or prior completions.
	FactLiteLLMOwnedClientChannel = "litellmOwnedClientChannel"
	// FactPodBoundKubeAPIAuthPotential is a structural exposure: an admitted,
	// started Pod mounts a projected default-audience API token tied to its exact
	// UID and current ServiceAccount. Rotate has planned cover because retirement
	// of that UID invalidates authentication at this API server. The fact does not
	// assert bearer theft, observed token rejection, or generic JWT revocation.
	FactPodBoundKubeAPIAuthPotential = "podBoundKubeAPIAuthPotential"

	// Tier 2: shared-scope facts. They are emitted for audit but have no cover grant because the
	// current action set has no scope-matched deterministic eraser or decision block for them.
	FactNodeFoothold     = "nodeFoothold"
	FactModelIdentity    = "modelIdentity"
	FactGuardrailVariant = "guardrailVariant"

	// Tier 3: persistent facts no current moving-target action can invalidate. These remain
	// pod-attributed audit evidence and are permanently absent from every action cover set.
	// CANNOT-HELP: FactCredential is copied credential knowledge, including any
	// copied JWT bytes, legacy Secret tokens, non-Kubernetes credentials and
	// offline-valid JWT uses. Exact-Pod deletion can invalidate a bound token at
	// this Kubernetes API server; that narrower potential API-auth capability is
	// modeled separately above. It does not erase copied knowledge.
	FactCredential              = "credential"
	FactRetrievalState          = "retrievalState"
	FactArtifactProvenance      = "artifactProvenance"
	FactControlPlanePersistence = "controlPlanePersistence"
)

// Fact is one weighted recon fact about an asset.
type Fact struct {
	Scope  FactScope
	Asset  string  // scope-relative identity: "ns/pod", node, model ID, or "ns/service"
	Kind   string  // one of the Fact* constants
	Edge   string  // neighbor "ns/pod" for FactLateralEdge; "" otherwise
	Weight float64 // value x P(hold) x stage-urgency (x neighbor value for edges)
	// SteeredBy is present only when the UCW producer actually multiplied this fact.
	SteeredBy *model.VectorSteeringAttribution
}

// Key is the stable scope-prefixed identity of a fact (scope|asset|kind[|edge]).
func (f Fact) Key() string {
	if f.Edge != "" {
		return string(f.Scope) + "|" + f.Asset + "|" + f.Kind + "|" + f.Edge
	}
	return string(f.Scope) + "|" + f.Asset + "|" + f.Kind
}

// NeighborRef is a reachable neighbor and its asset value (for lateral-edge weights).
type NeighborRef struct {
	Key   string  // "ns/pod"
	Value float64 // neighbor asset value
}

// FactContext is the per-asset conditioning the recon profile needs, supplied by the
// context + kill-chain layers (so the recon profile stays a pure fact/cover map).
type FactContext struct {
	AssetValue      float64
	PHold           float64       // P(attacker still holds) in [0,1]
	EventAgeHorizon time.Duration // effective policy horizon for the narrow Pod-bound API-auth vector
	StageUrgency    float64       // [0,1] urgency from the predictive belief horizon
	LateralUrgency  float64       // [0,1] specifically for lateral-movement-stage urgency
	BlastRadius     float64       // [0,1] normalized graph blast radius
	Neighbors       []NeighborRef
	HasGPU          bool
	Stateful        bool
}

// AssetFacts is the recon profile's output for one asset: the facts it exposes and,
// per action, the fact KEYS that action invalidates.
type AssetFacts struct {
	Facts         []Fact
	CoverByAction map[model.Action][]string
	// AbsentReason is non-empty when a non-finite input (NaN/±Inf in belief, asset value,
	// neighbour value or physics dispersion) meant NO fact could honestly be minted for the
	// asset (PHORVEXSEC-199 / M-111). Facts and CoverByAction are then empty; the action set
	// records every enabled action as excluded in the NaN category with this reason.
	AbsentReason string
}
