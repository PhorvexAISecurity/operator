/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 */

package recon

import (
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/registry"
)

// ReconProfile is the swappable per-tenant perturbable-variable + recon-fact model.
// Add a profile = add ONE file with an init() that calls Registry.Register.
type ReconProfile interface {
	registry.Named
	// AssetFacts returns the weighted facts an asset exposes and, per action, which
	// fact keys that action invalidates (its cover set).
	AssetFacts(view *model.WorkloadView, fctx FactContext) AssetFacts
}

// Registry holds the registered ReconProfiles.
var Registry = registry.New[ReconProfile]()

// standardRecon is the DEFAULT profile. Cover sets describe physical invalidation effects;
// actions may therefore share a set when they guarantee the same effect. A ROTATE wipes
// the IN-POD facts (identity, session, in-memory implant); a QUARANTINE (deny-all +
// detach) invalidates the NETWORK facts (reachable identity + each learned lateral
// edge) without wiping local state. This is the honest mechanism mapping of Phoenix's
// two primitives onto recon-fact invalidation.
type standardRecon struct{}

const (
	minimumHeldAssetWeight = 0.001
	stageUrgencyBase       = 0.5
	stageUrgencySpan       = 0.5
	sessionWeight          = 0.6
	networkIdentityWeight  = 0.8
)

func (standardRecon) Name() string { return "standard-recon" }

func (standardRecon) AssetFacts(view *model.WorkloadView, fctx FactContext) AssetFacts {
	if reason := factInputs(fctx); reason != "" {
		return AssetFacts{AbsentReason: reason} // no fact is minted from a non-number (M-111)
	}
	asset := view.Pod.Namespace + "/" + view.Pod.Name
	pHold, _ := clamp01(fctx.PHold) // finite: checked above
	base := fctx.AssetValue * pHold
	if base <= 0 {
		base = minimumHeldAssetWeight * pHold // a still-held asset always has minimal recon value
	}
	stageUrg, _ := clamp01(fctx.StageUrgency)
	urg := stageUrgencyBase + stageUrgencySpan*stageUrg // [0.5,1] — never zero out a held foothold

	var facts []Fact
	cover := map[model.Action][]string{}

	addRotate := func(kind string, w float64) Fact {
		f := Fact{Scope: ScopePod, Asset: asset, Kind: kind, Weight: w}
		facts = append(facts, f)
		cover[model.ActionRotate] = append(cover[model.ActionRotate], f.Key())
		return f
	}
	addQuarantine := func(kind, edge string, w float64) {
		f := Fact{Scope: ScopePod, Asset: asset, Kind: kind, Edge: edge, Weight: w}
		facts = append(facts, f)
		cover[model.ActionQuarantine] = append(cover[model.ActionQuarantine], f.Key())
	}

	// In-pod facts — invalidated by ROTATE (full kill+respawn). IDENTITY-ROTATE remains
	// coverless because its label write changes neither the pod identity nor its credentials.
	pid := Fact{Scope: ScopePod, Asset: asset, Kind: FactPodIdentity, Weight: base * urg}
	facts = append(facts, pid)
	cover[model.ActionRotate] = append(cover[model.ActionRotate], pid.Key())
	// This is a planned capability cover, never an Eviction-accepted or
	// observed-security-outcome claim. The producer has to establish an admitted
	// mounted default-API-audience projection for this exact live Pod UID and
	// current ServiceAccount; old-UID retirement is the eventual effect boundary.
	if view.Pod.HasPodBoundKubeAPIAuth() {
		credential := addRotate(FactPodBoundKubeAPIAuthPotential, base*urg)
		// LIGHT identity-rotate deletes+recreates the dedicated ServiceAccount (new UID),
		// invalidating the externally stolen pod-bound credential while RETAINING the Pod.
		// It covers EXACTLY that credential fact — never pod identity, memory or session,
		// which only a full rotate (kill+respawn) invalidates. The grant requires the
		// validated dedicated-SA external-theft observation; exact selecting-policy binding
		// is additionally enforced by the capability gate, the generator and the handler.
		if view.Pod.HasIdentityRotationObservation() {
			cover[model.ActionIdentityRotate] = []string{credential.Key()}
		}
	}
	memFact := addRotate(FactInMemory, base*urg)
	// Session/KV-cache fact is always modeled; GPU/stateful only affects exposure weight.
	sessionW := base * urg * sessionWeight
	if fctx.HasGPU || fctx.Stateful {
		sessionW = base * urg
	}
	// FALSIFIABILITY-GATE CROSSING (deliberate, opt-in): the KV-cache/session fact is
	// invalidated by ROTATE and — when ingestion produced the structural Ready serving
	// endpoint prerequisite — also by KV-RESET (the in-process prefix/KV flush evicts
	// injected session/cache state WITHOUT killing the pod). The gate held these AI
	// reset actions audit-only "until those actions ship + are validated"; kv-reset is
	// now validated end-to-end on the real vLLM-shaped control plane, so we let the
	// engine select the gentler kv-reset over a full rotate on GPU/LLM assets.
	sessFact := Fact{Scope: ScopePod, Asset: asset, Kind: FactSession, Weight: sessionW}
	facts = append(facts, sessFact)
	cover[model.ActionRotate] = append(cover[model.ActionRotate], sessFact.Key())
	// A supported scalar warm-swap retires the exact selected old Pod UID before it can
	// complete, then observes the owning ReplicaSet replenish the pool. That destroys the
	// same old-process identity, memory and in-process session facts as rotate. This grant
	// is limited to the snapshot witness used by capability admission; placement and GPU
	// co-location remain outside it.
	if warmSwapProcessCoverEligible(&view.Pod) {
		cover[model.ActionWarmSwap] = append(cover[model.ActionWarmSwap], pid.Key(), memFact.Key(), sessFact.Key())
	}
	// Scalar model-shard replacement uses the same exact-UID warmCutover retirement
	// producer as warm-swap, with a distinct family key. Once ingestion has verified
	// the owning ReplicaSet template and role-routed Service, retiring the selected old
	// process invalidates these same three process-scoped facts. The loaded model
	// fingerprint, stable route, GPU placement and durable credentials remain untouched.
	// Parallel TP/PP groups use a different grouped producer and are deliberately withheld.
	if modelShardProcessCoverEligible(&view.Pod) {
		cover[model.ActionModelShardReplace] = append(cover[model.ActionModelShardReplace], pid.Key(), memFact.Key(), sessFact.Key())
	}
	if view.Pod.ServingEndpointReady {
		cover[model.ActionKVReset] = append(cover[model.ActionKVReset], sessFact.Key())
	}

	// Network facts — invalidated by QUARANTINE (deny-all + detach).
	nid := Fact{Scope: ScopePod, Asset: asset, Kind: FactNetworkIdentity, Weight: base * urg * networkIdentityWeight}
	facts = append(facts, nid)
	cover[model.ActionQuarantine] = append(cover[model.ActionQuarantine], nid.Key())
	// route-rotate deliberately receives no cover. Its successful path changes endpoint
	// selection membership by re-keying a Pod label and restitching a Service selector,
	// while retaining the old Pod UID/IP and the stable Service UID/ClusterIP/DNS locator.
	// A client that already knows either locator has not had that knowledge invalidated.
	maxUrg, _ := clamp01(maxf(fctx.StageUrgency, fctx.LateralUrgency))
	latUrg := stageUrgencyBase + stageUrgencySpan*maxUrg
	for _, nb := range fctx.Neighbors {
		// A learned directed edge is owned by its origin pod. Quarantining the target may also cut
		// the physical edge, but origin-keying deliberately gives no credit for that effect: this is
		// conservative under-crediting that preserves one owning block in the current pod model.
		// Canonical cross-endpoint edges belong to the deferred coupled/MILP model.
		w := nb.Value * pHold * latUrg
		addQuarantine(FactLateralEdge, nb.Key, w)
	}

	return AssetFacts{Facts: facts, CoverByAction: cover}
}

func warmSwapProcessCoverEligible(p *model.Pod) bool {
	if p == nil || !p.HasServingDeclaration() || !p.WarmPoolConfigured ||
		p.WarmPoolOwnerUID == "" || p.RouteService == "" || p.Labels == nil {
		return false
	}
	return p.Labels["phorvex.ai/role"] != "warm-shadow" && p.Labels["phorvex.ai/swap-group"] != ""
}

func modelShardProcessCoverEligible(p *model.Pod) bool {
	if p == nil || !p.HasServingDeclaration() || !p.WarmPoolConfigured ||
		p.WarmPoolOwnerUID == "" || p.RouteService == "" || p.Labels == nil {
		return false
	}
	return p.Labels["phorvex.ai/role"] != "warm-shadow" &&
		p.Labels["phorvex.ai/model-shard"] != "" &&
		p.Labels["phorvex.ai/parallel-group"] == ""
}

// clamp01 clamps a FINITE x into [0,1]. A non-finite x (NaN/±Inf) is not a value: ok=false
// and the caller records the asset's facts as absent instead of minting a weight from it
// (PHORVEXSEC-199 / M-111). Note for the reviewer: the ticket's "physics twin"
// (platform.clamp01) has NO non-finite guard at this SHA or at aedd218 — its inputs are
// guarded at ingest — so there was no twin behaviour to mirror; this returns a presence
// state, never a chosen replacement value. The finite branch is byte-identical to before.
func clamp01(x float64) (float64, bool) {
	if !finite(x) {
		return 0, false
	}
	if x < 0 {
		return 0, true
	}
	if x > 1 {
		return 1, true
	}
	return x, true
}

// factInputs validates every scalar that enters a fact weight through the FactContext.
// Returns the absent reason for the first non-finite input ("" when all are finite).
func factInputs(fctx FactContext) string {
	switch {
	case !finite(fctx.AssetValue):
		return absentReason("assetValue")
	case !finite(fctx.PHold):
		return absentReason("pHold")
	case !finite(fctx.StageUrgency):
		return absentReason("stageUrgency")
	case !finite(fctx.LateralUrgency):
		return absentReason("lateralUrgency")
	}
	for _, nb := range fctx.Neighbors {
		if !finite(nb.Value) {
			return absentReason("neighbor:" + nb.Key)
		}
	}
	return ""
}

func maxf(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func init() { Registry.Register(standardRecon{}) }
