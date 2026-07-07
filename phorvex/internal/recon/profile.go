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

// standardRecon is the DEFAULT profile. Cover sets are DISTINCT per action so the
// submodular optimizer meaningfully chooses: a ROTATE (Delete -> clean respawn) wipes
// the IN-POD facts (identity, session, in-memory implant); a QUARANTINE (deny-all +
// detach) invalidates the NETWORK facts (reachable identity + each learned lateral
// edge) without wiping local state. This is the honest mechanism mapping of Phoenix's
// two primitives onto recon-fact invalidation.
type standardRecon struct{}

func (standardRecon) Name() string { return "standard-recon" }

func (standardRecon) AssetFacts(view *model.WorkloadView, fctx FactContext) AssetFacts {
	asset := view.Pod.Namespace + "/" + view.Pod.Name
	base := fctx.AssetValue * clamp01(fctx.PHold)
	if base <= 0 {
		base = 0.001 * clamp01(fctx.PHold) // a still-held asset always has minimal recon value
	}
	urg := 0.5 + 0.5*clamp01(fctx.StageUrgency) // [0.5,1] — never zero out a held foothold

	var facts []Fact
	cover := map[model.Action][]string{}

	addRotate := func(kind string, w float64) {
		f := Fact{Asset: asset, Kind: kind, Weight: w}
		facts = append(facts, f)
		cover[model.ActionRotate] = append(cover[model.ActionRotate], f.Key())
	}
	addQuarantine := func(kind, edge string, w float64) {
		f := Fact{Asset: asset, Kind: kind, Edge: edge, Weight: w}
		facts = append(facts, f)
		cover[model.ActionQuarantine] = append(cover[model.ActionQuarantine], f.Key())
	}

	// In-pod facts — invalidated by ROTATE (full kill+respawn). The gentler IDENTITY-ROTATE
	// (re-issue the SA token / bump the identity label epoch) invalidates the pod-identity fact
	// WITHOUT killing the pod — a SUBSET of rotate's cover, so the optimizer picks the surgical
	// identity refresh for an identity-only threat and escalates to a full rotate only when the
	// in-memory implant / session recon is also at stake.
	pid := Fact{Asset: asset, Kind: FactPodIdentity, Weight: base * urg}
	facts = append(facts, pid)
	cover[model.ActionRotate] = append(cover[model.ActionRotate], pid.Key())
	cover[model.ActionIdentityRotate] = append(cover[model.ActionIdentityRotate], pid.Key())
	addRotate(FactInMemory, base*urg)
	// Session/KV-cache fact matters most for GPU/LLM + stateful agents.
	sessionW := base * urg * 0.6
	if fctx.HasGPU || fctx.Stateful {
		sessionW = base * urg
	}
	// FALSIFIABILITY-GATE CROSSING (deliberate, opt-in): the KV-cache/session fact is
	// invalidated by ROTATE and — on an inference workload with a REACHABLE serving
	// control plane — also by KV-RESET (the in-process prefix/KV flush genuinely evicts
	// injected session/cache state WITHOUT killing the pod). The gate held these AI
	// reset actions audit-only "until those actions ship + are validated"; kv-reset is
	// now validated end-to-end on the real vLLM-shaped control plane, so we let the
	// engine select the gentler kv-reset over a full rotate on GPU/LLM assets.
	sessFact := Fact{Asset: asset, Kind: FactSession, Weight: sessionW}
	facts = append(facts, sessFact)
	cover[model.ActionRotate] = append(cover[model.ActionRotate], sessFact.Key())
	if fctx.HasGPU || fctx.Stateful {
		cover[model.ActionKVReset] = append(cover[model.ActionKVReset], sessFact.Key())
	}

	// Network facts — invalidated by QUARANTINE (deny-all + detach). The gentler ROUTE-ROTATE
	// (re-key the route epoch / restitch the Service selector) invalidates the reachable
	// network-identity fact WITHOUT a deny-all — a SUBSET of quarantine's cover, so the optimizer
	// picks the surgical re-route for a narrow network-recon threat and escalates to a full
	// quarantine only when learned lateral edges need cutting.
	nid := Fact{Asset: asset, Kind: FactNetworkIdentity, Weight: base * urg * 0.8}
	facts = append(facts, nid)
	cover[model.ActionQuarantine] = append(cover[model.ActionQuarantine], nid.Key())
	cover[model.ActionRouteRotate] = append(cover[model.ActionRouteRotate], nid.Key())
	latUrg := 0.5 + 0.5*clamp01(maxf(fctx.StageUrgency, fctx.LateralUrgency))
	for _, nb := range fctx.Neighbors {
		// A learned edge to a high-value neighbor is worth cutting (blast containment).
		w := nb.Value * clamp01(fctx.PHold) * latUrg
		addQuarantine(FactLateralEdge, nb.Key, w)
	}

	return AssetFacts{Facts: facts, CoverByAction: cover}
}

func clamp01(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}

func maxf(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func init() { Registry.Register(standardRecon{}) }
