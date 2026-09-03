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
	if reason := factInputs(fctx); reason != "" {
		return AssetFacts{AbsentReason: reason} // no fact is minted from a non-number (M-111)
	}
	asset := view.Pod.Namespace + "/" + view.Pod.Name
	pHold, _ := clamp01(fctx.PHold) // finite: checked above
	base := fctx.AssetValue * pHold
	if base <= 0 {
		base = 0.001 * pHold // a still-held asset always has minimal recon value
	}
	stageUrg, _ := clamp01(fctx.StageUrgency)
	urg := 0.5 + 0.5*stageUrg // [0.5,1] — never zero out a held foothold

	var facts []Fact
	cover := map[model.Action][]string{}

	addRotate := func(kind string, w float64) {
		f := Fact{Scope: ScopePod, Asset: asset, Kind: kind, Weight: w}
		facts = append(facts, f)
		cover[model.ActionRotate] = append(cover[model.ActionRotate], f.Key())
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
	// NO COVER for identity-rotate. It writes a `phorvex.ai/identity-epoch` LABEL and nothing else:
	// the SA-token branch is `_ = ec.Client` (a no-op on modern K8s, where projected tokens rotate on
	// their own), and nothing in the repo or on the cluster selects on that label. So the pod's identity
	// as an attacker holds it — UID, SA token, IP, EndpointSlice membership — is UNCHANGED. Granting it
	// podIdentity told the optimiser it had neutralised identity recon when it had only relabelled the
	// pod, i.e. it could be selected INSTEAD of a rotate that really would have. Only actions that truly
	// invalidate the fact may claim it.
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
	sessFact := Fact{Scope: ScopePod, Asset: asset, Kind: FactSession, Weight: sessionW}
	facts = append(facts, sessFact)
	cover[model.ActionRotate] = append(cover[model.ActionRotate], sessFact.Key())
	if fctx.HasGPU || fctx.Stateful {
		cover[model.ActionKVReset] = append(cover[model.ActionKVReset], sessFact.Key())
	}

	// Network facts — invalidated by QUARANTINE (deny-all + detach).
	nid := Fact{Scope: ScopePod, Asset: asset, Kind: FactNetworkIdentity, Weight: base * urg * 0.8}
	facts = append(facts, nid)
	cover[model.ActionQuarantine] = append(cover[model.ActionQuarantine], nid.Key())
	// route-rotate earns this cover only because its successful path re-keys the pod's route label
	// and restitches the explicitly declared Service selector, compensating if the second write
	// fails. Missing deployment
	// contract returns Emitted=false and receives no actuation credit.
	cover[model.ActionRouteRotate] = append(cover[model.ActionRouteRotate], nid.Key())
	maxUrg, _ := clamp01(maxf(fctx.StageUrgency, fctx.LateralUrgency))
	latUrg := 0.5 + 0.5*maxUrg
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
