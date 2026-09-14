/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-PHYSICS / UCW)
 */

package recon

import (
	"sort"

	"github.com/phorvex/phorvex/internal/model"
)

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
// EPSS 1+util, co-residency 1+tenants), so the COVERAGE term stays submodular and at nil-data the weights are
// BYTE-IDENTICAL to standard-recon — the 1.62x ablation reproduces exactly. With real
// dispersion the weights become heavy-tailed, which the submodular greedy provably
// exploits and the uniform-random arm cannot (the separately-ablatable beat mechanism).
//
// It also emits the AI recon taxonomy. Pod-scoped facts enter CoverByAction only where a
// deterministic actuator erases them. Shared node/model/service facts and the permanent
// cannot-help facts are emitted for audit with zero cover, so they cannot enter marginal gain.
//
// SCALING NOTE, since the ordering here is load-bearing: the scarcity scalar `s` is applied at the
// END, after pod and audit facts are appended. PHVX-70 moved it there so every fact emitted for the
// workload receives the same fleet-derived scalar; moving it earlier silently recreates the old
// base/AI asymmetry.
//
// OPTIMALITY BOUND (was asserted falsely here): the selection objective is
// Σ w(facts covered) − λ·C(S), which is submodular but NOT monotone (the −λ·C term
// decreases in S), and the constraint is a partition matroid (one move per asset) truncated
// by the budget — not a cardinality constraint. So the classic monotone/cardinality 1−1/e
// guarantee does NOT apply. The Fisher–Nemhauser–Wolsey 1/2 bound applies to the
// monotone matroid case, not automatically to this cost-penalized objective. No replacement
// approximation constant is claimed here without a proof tied to the implemented selection rule.
//
// The exact-vs-greedy ratios in optimality.go are bounded measurements, not a general approximation
// theorem; inspect ExactSkipped and the recorded work budget before quoting them as evidence.
type ucwRecon struct{}

func (ucwRecon) Name() string { return "ucw-recon" }

// MaxDispersionMult caps the compounded in-pod multiplier so a pathological fleet can't
// explode a single fact's weight (each factor is [1,2]; product capped here).
const MaxDispersionMult = 4.0

func (ucwRecon) AssetFacts(view *model.WorkloadView, fctx FactContext) AssetFacts {
	af := standardRecon{}.AssetFacts(view, fctx)
	if af.AbsentReason != "" {
		return af
	}
	ph := view.Physics

	// ONE per-asset scarcity scalar applied UNIFORMLY to every fact of the asset. This
	// is the provable EMR form: scaling all of an asset's facts by the same factor
	// preserves the within-asset rotate/quarantine balance and only sharpens the
	// CROSS-asset ordering the greedy exploits. With UNIFORM scarcity across the fleet
	// the ratio is unchanged (scaling all weights by a constant is invariant) => exact
	// tie / never worse; only DIFFERENTIAL (heavy-tailed) dispersion lifts it.
	s, sOK := DispersionMultiplier(view)
	if !sOK {
		// A non-finite physics multiplier is not a scarcity value; no fact is minted (M-111).
		return AssetFacts{AbsentReason: absentReason("dispersion")}
	}
	// NOTE: s is APPLIED AT THE END of this function, after the AI facts exist. Applying it here
	// would scale only the six standardRecon facts, because every AI fact below is appended after
	// this point — see the comment above the application site (PHVX-70 / PHORVEXSEC-126).

	asset := view.Pod.Namespace + "/" + view.Pod.Name
	pHold, _ := clamp01(fctx.PHold) // finite: standardRecon validated the inputs above
	base := fctx.AssetValue * pHold
	if base <= 0 {
		base = 0.001 * pHold
	}
	stageUrg, _ := clamp01(fctx.StageUrgency)
	urg := 0.5 + 0.5*stageUrg

	// AI recon facts — emitted on GPU/served-model assets. Cover is granted per physical mechanism,
	// not to the group as a whole: modelFingerprint stays audit-only because model-shard-replace
	// has no loaded-identity/effect witness. EndpointPath remains audit-only because route
	// restitching does not prove locator invalidation;
	// mig-rebind invalidates only the contention channel and only on a MIG-capable pod;
	// warm-swap and GPU co-location remain cover-free until anti-affinity proves relocation; and
	// kv-migrate-invalidate maps to session state below. This keeps selectable cover narrower than
	// the emitted audit universe whenever an actuator cannot guarantee the claimed effect.
	if view.Pod.HasGPU || view.Pod.ModelID != "" {
		mf := Fact{Scope: ScopePod, Asset: asset, Kind: FactModelFingerprint, Weight: base * urg * ph.ModelRarity}
		ep := Fact{Scope: ScopePod, Asset: asset, Kind: FactEndpointPath, Weight: base * urg}
		gc := Fact{Scope: ScopePod, Asset: asset, Kind: FactGPUColocation, Weight: base * urg * ph.CoResidency}
		sc := Fact{Scope: ScopePod, Asset: asset, Kind: FactGPUContentionChannel, Weight: base * urg}
		// In-flight-request + guardrail-bypass recon on a serving pod — each invalidated by its own
		// gentle AI actuator (request-drain / guardrail-rotate) so the engine can pick the surgical
		// serving move over a blunt rotate. Distinct facts => distinct, meaningful cover per action.
		rq := Fact{Scope: ScopePod, Asset: asset, Kind: FactInflightRequests, Weight: base * urg}
		gb := Fact{Scope: ScopePod, Asset: asset, Kind: FactGuardrailBypass, Weight: base * urg}
		af.Facts = append(af.Facts, mf, ep, gc, sc, rq, gb)
		if af.CoverByAction == nil {
			af.CoverByAction = map[model.Action][]string{}
		}
		// M-035: retain endpointPath and its weight for audit, but withhold cover from every action.
		// A route declaration or selector change does not prove the learned DNS/API locator is unusable.
		// [PHVX-26a] The GPU cover, corrected. These two actions used to receive byte-identical
		// grants {gpuColocation, gpuContentionChannel}, which made them indistinguishable to the
		// optimizer and asserted more than either performs.
		//
		// The soundness condition, confirmed by the math review on PHORVEXSEC-121/117: a fact may
		// belong to CoverByAction[a] only if EVERY successful execution of a invalidates it. There
		// is no probabilistic or expected-cover reading in this model.
		//
		//   mig-rebind  — repartitioning destroys the mapped GI/CI structure on the device, so the
		//                 contention path is severed deterministically wherever the pod ends up. It
		//                 does NOT move the pod, so co-residency knowledge survives: it never covers
		//                 gpuColocation. Conditional on the pod actually having a MIG device.
		//
		//   warm-swap   — creates a shadow with NodeName cleared and identical constraints. Nothing
		//                 in rewarmShadow expresses anti-affinity, so the scheduler may re-place it
		//                 on the same node. "May relocate" cannot back a binary grant, and neither
		//                 can a high empirical relocation rate or the mere existence of a second GPU
		//                 node. Until required podAntiAffinity on kubernetes.io/hostname excludes
		//                 the old node — deferred by PHVX-26a — warm-swap covers NOTHING here and
		//                 both facts stay audit-only.
		//
		// Consequence, stated plainly: warm-swap becomes unselectable on this fleet, exactly as
		// identity-rotate did under PHVX-9e. Its real value (a cutover with no cold load) is
		// unaffected; only the co-residency claim was false.
		if view.Pod.MIGDevice != "" {
			af.CoverByAction[model.ActionMIGRebind] = append(af.CoverByAction[model.ActionMIGRebind], sc.Key())
		}

		// [PHVX-77] kv-migrate-invalidate covers SESSION, not endpointPath. Invalidating or migrating
		// a KV cache destroys the attacker's in-pod session state; it does not change the inference
		// route they learned, which is what the audit-only endpointPath represents.
		// Granting it endpointPath asserted a defence it does not perform — the same false-credit
		// class as PHVX-9e.
		af.CoverByAction[model.ActionRequestDrain] = append(af.CoverByAction[model.ActionRequestDrain], rq.Key())
		af.CoverByAction[model.ActionGuardrailRotate] = append(af.CoverByAction[model.ActionGuardrailRotate], gb.Key())
		// adapter-integrity: present ONLY while a detector has flagged an unauthorized/poisoned LoRA
		// adapter on this pod. Weighted to DOMINATE (a poisoned adapter corrupts every response), and
		// covered by ONLY adapter-rotate — so the engine selects adapter-rotate for THIS attack rather
		// than a generic rotate/kv-reset. The fact vanishes once the adapter is evicted (move stops).
		//
		// The weight is MULTIPLICATIVE, like every other fact in this file (PHVX-75). It used to be
		// `(base + 2.0) * urg * 3`, and that additive term caused three problems:
		//
		//   1. It survived PHold = 0. base is AssetValue*clamp01(PHold), so at PHold = 0 the additive
		//      form still produced 2.0*urg*3 >= 3.0 — a fact about a provably-departed attacker sat at
		//      the top of the objective, and no evidence could ever retire it.
		//   2. It was not portable. AssetValue's scale is a policy choice, so +2.0 dominated a fleet
		//      emitting O(1) values and was rounding noise on one emitting O(100). The same constant
		//      meant different things on different clusters.
		//   3. It was the only additive weight here, so it did not compose with the others.
		//
		// Dominance is preserved WITHOUT the floor: every other multiplier in this file is of the form
		// 1 + clamp01(...) and is therefore bounded by 2 (ModelRarity and CoResidency both), while this
		// one is 3. So a poisoned adapter outranks any other fact on the same asset structurally,
		// rather than by an additive constant that happens to be large.
		if view.Pod.SuspectAdapter != "" {
			ai := Fact{Scope: ScopePod, Asset: asset, Kind: FactAdapterIntegrity, Weight: base * urg * 3.0}
			af.Facts = append(af.Facts, ai)
			af.CoverByAction[model.ActionAdapterRotate] = append(af.CoverByAction[model.ActionAdapterRotate], ai.Key())
		}

		// A NAMED attack vector targeting this pod makes the matching serving fact DOMINATE — the
		// same ×3 structural dominance as adapter-integrity — so the engine picks the SURGICAL
		// actuator for THAT attack (kv-reset for a KV/prompt-inject implant, guardrail-rotate for a
		// jailbreak, request-drain for a request hijack) over other eligible moves.
		// Each fact stays covered by exactly the one action that invalidates it (cover set unchanged);
		// only the weight is lifted. There is deliberately no age predicate here: an event
		// retained in the workload view remains an observation until ingestion removes it.
		if refs := vectorEvents(view.Events, model.AttackVectorKV); len(refs) > 0 {
			boostFactWeight(af.Facts, FactSession, model.AttackVectorKV, vectorDominance, refs) // -> kv-reset
		}
		if refs := vectorEvents(view.Events, model.AttackVectorGuardrail); len(refs) > 0 {
			boostFactWeight(af.Facts, FactGuardrailBypass, model.AttackVectorGuardrail, vectorDominance, refs) // -> guardrail-rotate
		}
		if refs := vectorEvents(view.Events, model.AttackVectorInflight); len(refs) > 0 {
			boostFactWeight(af.Facts, FactInflightRequests, model.AttackVectorInflight, vectorDominance, refs) // -> request-drain
		}
	}
	// Both session erasers use the same ingestion-produced endpoint prerequisite and the
	// one session fact minted by standard recon. GPU/model facts remain independently scoped.
	if view.Pod.ServingEndpointReady {
		for _, f := range af.Facts {
			if f.Kind == FactSession {
				af.CoverByAction[model.ActionKVMigrateInvalidate] = append(af.CoverByAction[model.ActionKVMigrateInvalidate], f.Key())
				break
			}
		}
	}

	// Tier 2 — shared-scope evidence. The current optimizer has pod decision blocks only, and no
	// deterministic node/model/service eraser exists for these facts, so none receives cover.
	// Shared keys are intentional here: they are audit evidence, not selectable objective keys.
	if view.Pod.Node != "" {
		af.Facts = append(af.Facts, Fact{
			Scope: ScopeNode, Asset: view.Pod.Node, Kind: FactNodeFoothold, Weight: base * urg,
		})
	}
	if view.Pod.ModelID != "" {
		af.Facts = append(af.Facts, Fact{
			Scope: ScopeModel, Asset: view.Pod.ModelID, Kind: FactModelIdentity, Weight: base * urg,
		})
	}
	if view.Pod.RouteService != "" {
		af.Facts = append(af.Facts, Fact{
			Scope: ScopeService, Asset: view.Pod.Namespace + "/" + view.Pod.RouteService,
			Kind: FactGuardrailVariant, Weight: base * urg,
		})
	}

	// Tier 3 — facts no current moving-target actuator can invalidate. They stay attached to the
	// observed workload for audit and are permanently absent from CoverByAction. In particular,
	// projected ServiceAccount-token invalidation is CANNOT-HELP for a pod-scoped actuator: only
	// issuer-side revocation can invalidate a bound token before its TTL.
	for _, kind := range []string{
		FactCredential, FactRetrievalState, FactArtifactProvenance, FactControlPlanePersistence,
	} {
		af.Facts = append(af.Facts, Fact{
			Scope: ScopePod, Asset: asset, Kind: kind, Weight: base * urg,
		})
	}

	// [PHVX-70] Apply the scarcity scalar HERE, not where it is computed.
	//
	// It used to be applied immediately after boundMult, which is before every AI fact is appended.
	// The six standardRecon facts were therefore scaled and the AI facts were not, so on a GPU pod a
	// base fact could carry up to MaxDispersionMult (4x) the weight of an AI fact describing the same
	// asset — the engine was systematically steered toward generic moves over the AI-specific ones,
	// on exactly the workloads the AI facts exist for.
	//
	// The doc comment above always claimed the scalar was applied "UNIFORMLY to every fact of the
	// asset". That claim is what makes the EMR argument sound (a common factor preserves the
	// within-asset ordering and only sharpens the cross-asset one); partial application breaks it.
	// The comment was right and the code was wrong.
	if s != 1.0 {
		for i := range af.Facts {
			af.Facts[i].Weight *= s
		}
	}

	return af
}

func boundMult(m float64) (float64, bool) {
	return boundMultAt(m, 0)
}

// DispersionMultiplier returns the exact scalar the current UCW profile applies
// to every fact for this asset, and whether it is a number at all. The decision trace
// calls the same function rather than reimplementing the physics equation; ok=false
// means the physics inputs were non-finite and the asset's facts are absent (M-111).
func DispersionMultiplier(view *model.WorkloadView) (float64, bool) {
	if view == nil {
		return 1, true
	}
	ph := view.Physics
	s := ph.ImageRarity * ph.EPSSMultiplier * ph.CoResidency
	if view.Pod.ModelID != "" || view.Pod.HasGPU {
		s *= ph.ModelRarity
	}
	return boundMultAt(s, ph.DispersionCap)
}

// boundMultAt keeps the production default when cap is zero. A positive alternate
// cap is carried only by cloned shadow witnesses used for PHVX-74 counterfactuals.
//
// PHORVEXSEC-199 / M-111: a non-finite m (or cap) is not clamped into a weight — NaN passed
// straight through both comparisons before — it is reported as ok=false and the caller
// records the asset's facts as absent. lo/hi are unchanged (M-108 owns the cap value); the
// finite branch is byte-identical to before.
func boundMultAt(m, cap float64) (float64, bool) {
	if !finite(m) || !finite(cap) {
		return 0, false
	}
	if cap <= 0 {
		cap = MaxDispersionMult
	}
	if m < 1 {
		return 1, true
	}
	if m > cap {
		return cap, true
	}
	return m, true
}

// vectorDominance is the multiplier a named attack vector applies to its matching fact — the same
// structural ×3 dominance adapter-integrity uses, so the surgical actuator outranks the cheap cover.
const vectorDominance = 3.0

// vectorEvents returns every pod-targeting observation that jointly causes the one
// multiplier for vectorType. Trust remains an ingestion responsibility (M-94).
func vectorEvents(events []model.SecurityEventInfo, vectorType string) []model.VectorSteeringEvent {
	refs := make([]model.VectorSteeringEvent, 0)
	for i := range events {
		if events[i].TargetsPod && events[i].Type == vectorType {
			refs = append(refs, model.VectorSteeringEvent{
				EventName: events[i].Name, EventUID: events[i].UID, RuleType: events[i].Type,
				DeclaredSource: events[i].Source, TrustVerdict: events[i].Trust,
				CreatorIdentity: events[i].CreatorIdentity,
			})
		}
	}
	sort.Slice(refs, func(i, j int) bool { return steeringEventKey(refs[i]) < steeringEventKey(refs[j]) })
	unique := refs[:0]
	for _, ref := range refs {
		if len(unique) == 0 || steeringEventKey(unique[len(unique)-1]) != steeringEventKey(ref) {
			unique = append(unique, ref)
		}
	}
	return unique
}

func steeringEventKey(e model.VectorSteeringEvent) string {
	return e.EventName + "\x00" + e.EventUID + "\x00" + e.RuleType + "\x00" + e.DeclaredSource + "\x00" + e.TrustVerdict + "\x00" + e.CreatorIdentity
}

// boostFactWeight applies exactly one factor to the first fact of the given kind and
// carries the same producer branch's observations. It never invents an absent fact.
func boostFactWeight(facts []Fact, kind, vectorType string, mult float64, refs []model.VectorSteeringEvent) {
	for i := range facts {
		if facts[i].Kind == kind {
			facts[i].Weight *= mult
			facts[i].SteeredBy = &model.VectorSteeringAttribution{
				RuleType: vectorType, AppliedMultiplier: mult,
				Events: append([]model.VectorSteeringEvent(nil), refs...),
			}
			return
		}
	}
}

// ucwRecon is registered but NOT made default here — the runner calls
// recon.Registry.SetDefault("ucw-recon") so the engine uses discovered physics, while
// the ablation can still fetch "standard-recon" (scarcity-off) for the separately-
// ablated A/B. (Registering does not move the default; SetDefault does.)
func init() { Registry.Register(ucwRecon{}) }
