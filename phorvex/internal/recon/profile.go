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

	// In-pod facts — invalidated by ROTATE.
	addRotate(FactPodIdentity, base*urg)
	addRotate(FactInMemory, base*urg)
	// Session/KV-cache fact matters most for GPU/LLM + stateful agents.
	sessionW := base * urg * 0.6
	if fctx.HasGPU || fctx.Stateful {
		sessionW = base * urg
	}
	addRotate(FactSession, sessionW)

	// Network facts — invalidated by QUARANTINE.
	addQuarantine(FactNetworkIdentity, "", base*urg*0.8)
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
