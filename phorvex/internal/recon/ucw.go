/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-PHYSICS / UCW)
 */

package recon

import "github.com/phorvex/phorvex/internal/model"

// ucwRecon is the DISCOVERED-physics recon profile that COMPLETES the PRD's Layer-C EMR
// (Expected Reconnaissance Invalidated per Move) for BOTH products. It is the existing
// standardRecon weight re-read as an information-theoretic expectation and CONDITIONED
// on measured dispersion from the platform scan (view.Physics):
//
//	EMR(fact) = base(f)·urg · m_dispersion(f)
//	  base·urg = AssetValue·P(hold)·urgency      (the standardRecon weight, unchanged)
//	  m_dispersion = image-rarity·EPSS·model-rarity   for in-pod facts
//	             or  co-residency                      for network facts
//
// Each multiplier is a BOUNDED honest-absent=1.0 factor (rarity 1+(-log2 freq)/log2N,
// EPSS 1+util, co-residency 1+tenants), so the objective stays submodular+monotone (the
// greedy keeps 1-1/e, ZERO optimizer change) and at nil-data the weights are
// BYTE-IDENTICAL to standard-recon — the 1.62x ablation reproduces exactly. With real
// dispersion the weights become heavy-tailed, which the submodular greedy provably
// exploits and the uniform-random arm cannot (the separately-ablatable beat mechanism).
//
// It also EMITS the four AI recon facts (model fingerprint / endpoint / GPU co-location
// / side-channel) AUDIT-ONLY — present in the fact universe for visibility, but absent
// from CoverByAction because their reset actions are Phase-2 (the falsifiability gate).
type ucwRecon struct{}

func (ucwRecon) Name() string { return "ucw-recon" }

// MaxDispersionMult caps the compounded in-pod multiplier so a pathological fleet can't
// explode a single fact's weight (each factor is [1,2]; product capped here).
const MaxDispersionMult = 4.0

func (ucwRecon) AssetFacts(view *model.WorkloadView, fctx FactContext) AssetFacts {
	af := standardRecon{}.AssetFacts(view, fctx)
	ph := view.Physics

	// ONE per-asset scarcity scalar applied UNIFORMLY to every fact of the asset. This
	// is the provable EMR form: scaling all of an asset's facts by the same factor
	// preserves the within-asset rotate/quarantine balance and only sharpens the
	// CROSS-asset ordering the greedy exploits. With UNIFORM scarcity across the fleet
	// the ratio is unchanged (scaling all weights by a constant is invariant) => exact
	// tie / never worse; only DIFFERENTIAL (heavy-tailed) dispersion lifts it.
	s := ph.ImageRarity * ph.EPSS * ph.CoResidency
	if view.Pod.ModelID != "" || view.Pod.HasGPU {
		s *= ph.ModelRarity
	}
	s = boundMult(s)
	if s != 1.0 {
		for i := range af.Facts {
			af.Facts[i].Weight *= s
		}
	}

	// AI recon facts — emitted on GPU/served-model assets. The Phase-2 reset actuators are now
	// CROSSED into the coverage gate (opt-in): each AI fact is invalidated by its matching AI
	// actuator, so the engine can select the gentle AI move (model-shard-replace / endpoint-rotate /
	// mig-rebind / warm-swap / kv-migrate-invalidate) instead of a blunt rotate on an inference
	// workload. These remain [SP-0-PENDING] for VALIDATION (the actuation needs a vLLM-shaped control
	// plane to fire), but they are no longer hidden from selection.
	if view.Pod.HasGPU || view.Pod.ModelID != "" {
		asset := view.Pod.Namespace + "/" + view.Pod.Name
		base := fctx.AssetValue * clamp01(fctx.PHold)
		if base <= 0 {
			base = 0.001 * clamp01(fctx.PHold)
		}
		urg := 0.5 + 0.5*clamp01(fctx.StageUrgency)
		mf := Fact{Asset: asset, Kind: FactModelFingerprint, Weight: base * urg * ph.ModelRarity}
		ep := Fact{Asset: asset, Kind: FactEndpointPath, Weight: base * urg}
		gc := Fact{Asset: asset, Kind: FactGPUColocation, Weight: base * urg * ph.CoResidency}
		sc := Fact{Asset: asset, Kind: FactSideChannel, Weight: base * urg}
		af.Facts = append(af.Facts, mf, ep, gc, sc)
		if af.CoverByAction == nil {
			af.CoverByAction = map[model.Action][]string{}
		}
		af.CoverByAction[model.ActionModelShardReplace] = append(af.CoverByAction[model.ActionModelShardReplace], mf.Key())
		af.CoverByAction[model.ActionEndpointRotate] = append(af.CoverByAction[model.ActionEndpointRotate], ep.Key())
		af.CoverByAction[model.ActionMIGRebind] = append(af.CoverByAction[model.ActionMIGRebind], gc.Key(), sc.Key())
		af.CoverByAction[model.ActionWarmSwap] = append(af.CoverByAction[model.ActionWarmSwap], gc.Key(), sc.Key())
		af.CoverByAction[model.ActionKVMigrateInvalidate] = append(af.CoverByAction[model.ActionKVMigrateInvalidate], ep.Key())
	}
	return af
}

func boundMult(m float64) float64 {
	if m < 1 {
		return 1
	}
	if m > MaxDispersionMult {
		return MaxDispersionMult
	}
	return m
}

// ucwRecon is registered but NOT made default here — the runner calls
// recon.Registry.SetDefault("ucw-recon") so the engine uses discovered physics, while
// the ablation can still fetch "standard-recon" (scarcity-off) for the separately-
// ablated A/B. (Registering does not move the default; SetDefault does.)
func init() { Registry.Register(ucwRecon{}) }
