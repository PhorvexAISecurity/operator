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
	// FactSession = KV-cache / agent session / in-pod foothold state (exposure: session).
	FactSession = "session"
	// FactInMemory = in-memory implant / loaded secrets / runtime state.
	FactInMemory = "inMemory"
	// FactNetworkIdentity = the pod's reachable network identity (exposure: networkIdentity).
	FactNetworkIdentity = "networkIdentity"
	// FactLateralEdge = a learned reachable edge to a specific neighbor (the Edge field).
	FactLateralEdge = "lateralEdge"
	// FactNodePlacement = which node the pod runs on (exposure: nodePlacement).
	FactNodePlacement = "nodePlacement"

	// --- AI / inference recon facts (P-PHYSICS / UCW). The attacker's recon map of an
	// inference workload. DEFINED NOW for both-products completeness; their RESET
	// actions (model-swap, route-rotate, GPU/MIG-rebind) are Phase-2 actuators, so per
	// the FALSIFIABILITY GATE they are emitted AUDIT-ONLY (not in CoverByAction) until
	// those actions ship — they never inflate selectable cover. ---

	// FactModelFingerprint = served model identity/version the attacker fingerprinted
	// (reset by NIM/model-rotation — Phase-2).
	FactModelFingerprint = "modelFingerprint"
	// FactEndpointPath = inference endpoint / API route the attacker mapped (reset by
	// endpoint/route-rotation — Phase-2).
	FactEndpointPath = "endpointPath"
	// FactGPUColocation = shared-GPU/MIG co-residency observability (reset by GPU/MIG-
	// rebind or node-rotate — Phase-2).
	FactGPUColocation = "gpuColocation"
	// FactSideChannel = timing/power/GPU-util leakage of a co-tenant model (AUDIT-ONLY;
	// no infrastructure move fully resets it).
	FactSideChannel = "sideChannel"
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
	AssetValue   float64
	PHold        float64 // P(attacker still holds) in [0,1]
	StageUrgency float64 // [0,1] urgency from the predictive belief horizon
	LateralUrgency float64 // [0,1] specifically for lateral-movement-stage urgency
	BlastRadius  float64 // [0,1] normalized graph blast radius
	Neighbors    []NeighborRef
	HasGPU       bool
	Stateful     bool
}

// AssetFacts is the recon profile's output for one asset: the facts it exposes and,
// per action, the fact KEYS that action invalidates.
type AssetFacts struct {
	Facts         []Fact
	CoverByAction map[model.Action][]string
}
