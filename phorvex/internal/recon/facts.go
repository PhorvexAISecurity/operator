/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 */

// Package recon is the P1 "physics": the per-tenant PERTURBABLE-VARIABLE + RECON-FACT
// model that turns the attacker's reconnaissance into a weighted fact-universe and
// defines, per action, exactly which facts a move INVALIDATES (its cover set). This
// is the substrate the submodular recon-coverage optimizer maximizes over, and the
// thing the STEP-3 ablation measures "facts-invalidated-per-dollar" against.
//
// A FACT is a (variable, asset) pair the attacker has learned or is about to learn,
// crisply tied to a measured exposure variable so the per-dollar number is
// falsifiable (METHOD-DECISION risk #a). Each fact carries a weight =
// value x P(hold) x stage-urgency (x blast for lateral edges).
package recon

import "github.com/phorvex/phorvex/internal/model"

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
	// model.VarNodePlacement is unrelated and still live; do not confuse the two if this is
	// reintroduced.

	// --- AI / inference recon facts (P-PHYSICS / UCW). The attacker's recon map of an
	// inference workload.
	//
	// These no longer share one blanket status. Cover is action- and capability-specific:
	// model-shard-replace and endpoint-rotate carry their matching facts, while GPU contention
	// is covered only for a MIG-capable pod and GPU co-location currently carries no grant.
	// Anything genuinely cover-free must say so per-fact and be asserted in cover_test.
	// Corrected under PHVX-76. ---

	// FactModelFingerprint = served model identity/version the attacker fingerprinted
	// (reset by model-shard-replace).
	FactModelFingerprint = "modelFingerprint"
	// FactEndpointPath = inference endpoint / API route the attacker mapped (reset by
	// endpoint-rotate; route-rotate only writes an unused label and earns no cover).
	FactEndpointPath = "endpointPath"
	// FactGPUColocation = shared-GPU/MIG co-residency observability. AUDIT-ONLY: neither
	// mig-rebind nor warm-swap proves relocation to a different node/device today.
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
	// safety-guardrail variant. Covered by guardrail-rotate (swap the guardrail variant so the learned
	// bypass no longer works) — a targeted AI-safety move the engine can pick instead of a blunt rotate.
	FactGuardrailBypass = "guardrailBypass"
)

// Fact is one weighted recon fact about an asset.
type Fact struct {
	Asset  string  // "ns/pod"
	Kind   string  // one of the Fact* constants
	Edge   string  // neighbor "ns/pod" for FactLateralEdge; "" otherwise
	Weight float64 // value x P(hold) x stage-urgency (x neighbor value for edges)
}

// Key is the stable identity of a fact (asset|kind|edge).
func (f Fact) Key() string {
	if f.Edge != "" {
		return f.Asset + "|" + f.Kind + "|" + f.Edge
	}
	return f.Asset + "|" + f.Kind
}

// NeighborRef is a reachable neighbor and its asset value (for lateral-edge weights).
type NeighborRef struct {
	Key   string  // "ns/pod"
	Value float64 // neighbor asset value
}

// FactContext is the per-asset conditioning the recon profile needs, supplied by the
// context + kill-chain layers (so the recon profile stays a pure fact/cover map).
type FactContext struct {
	AssetValue     float64
	PHold          float64 // P(attacker still holds) in [0,1]
	StageUrgency   float64 // [0,1] urgency from the predictive belief horizon
	LateralUrgency float64 // [0,1] specifically for lateral-movement-stage urgency
	BlastRadius    float64 // [0,1] normalized graph blast radius
	Neighbors      []NeighborRef
	HasGPU         bool
	Stateful       bool
}

// AssetFacts is the recon profile's output for one asset: the facts it exposes and,
// per action, the fact KEYS that action invalidates.
type AssetFacts struct {
	Facts         []Fact
	CoverByAction map[model.Action][]string
}
