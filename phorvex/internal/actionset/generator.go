/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 */

// Package actionset is the DYNAMIC ACTION-SET GENERATOR — the core P1 IP. Each tick it
// computes the FEASIBLE (asset, action) set LIVE from physics+context state (NOT a
// static list); the submodular optimizer then selects ONLY from this generated set.
// Because every infeasible or SLO-unsafe move is EXCLUDED here, the optimizer can never
// return a hard-constraint-violating move — that is the structural inviolability proof
// (Layer A feasibility + the conformal SLO gate are applied before, not during,
// optimization).
package actionset

import (
	"fmt"

	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/feasibility"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

// Candidate is one feasible (asset, action) with a non-empty recon cover set and costs.
type Candidate struct {
	GenerationRank int
	SLOExclusions  []string
	Key            string // "ns/pod"
	View           *model.WorkloadView
	Action         model.Action
	CoverKeys      []string // recon fact keys this move invalidates
	ECost          float64  // expected (objective) cost
	CHi            float64  // conformal worst-case cost (used by the hard SLO gate)
	Resources      []model.ResourceConsumption
	// RBACUnknown is set when the capability gate's SSAR errored (T1-E fail-open): the
	// candidate is NOT excluded, but the record flags that its RBAC could not be
	// confirmed this tick (P-NO-FREEZE) — surfaced in the trace + a metric.
	RBACUnknown bool
}

// ActionSet is the generator output: the feasible candidates plus the tick's global
// recon fact-weight map (cover keys index into it for the coverage objective).
type ActionSet struct {
	Candidates []Candidate
	// Resources is the complete hard-capacity vector used by every selection
	// path. Each scope appears exactly once.
	Resources []model.ResourceCapacity
	// FactWeights contains only keys referenced by at least one action cover. Audit-only facts stay
	// in recon.AssetFacts but cannot enter marginal gain, normalization, or collision ownership.
	FactWeights map[string]float64
	// FactsByAsset retains the already-generated recon output for the decision
	// trace, including audit-only facts. Selection continues to read FactWeights.
	FactsByAsset map[string][]recon.Fact
	// FactsAbsent records, per asset key, why NO fact was minted (non-finite input, M-111).
	FactsAbsent map[string]string
	// CrossBlockCollisions records the structural violations that make this entire
	// tick unsafe to optimize. Rejected is fail-closed: no candidate may be selected.
	CrossBlockCollisions []CrossBlockCollision
	Rejected             bool
	// Excluded records (asset,action,reason) pairs pruned by structural relevance or
	// a hard constraint — surfaced for audit/inviolability, never selectable.
	Excluded []Exclusion
	// CostCeiling is the effective conformal SLO ceiling enforced this tick
	// (T0-C: recorded in the decision trace so the gate is reconstructable).
	CostCeiling float64
	// CoverByAsset carries recon's declared cover sets per asset over ALL actions
	// (enabled or not — a fact's cover set is a property of the fact). Read-only;
	// the decision trace inverts it into per-fact CoveringActions. (T0-C)
	CoverByAsset map[string]map[model.Action][]string
}

func cloneFacts(in []recon.Fact) []recon.Fact {
	out := append([]recon.Fact(nil), in...)
	for i := range out {
		if out[i].SteeredBy == nil {
			continue
		}
		steering := *out[i].SteeredBy
		steering.Events = append([]model.VectorSteeringEvent(nil), steering.Events...)
		out[i].SteeredBy = &steering
	}
	return out
}

// CrossBlockCollision is one recon key claimed by two distinct pod decision blocks.
// Reuse by multiple actions inside one block is legal under the partition constraint;
// reuse across blocks breaks modularity and voids the exact-optimality guarantee.
type CrossBlockCollision struct {
	Key              string
	ExistingBlock    string
	ConflictingBlock string
}

func (c CrossBlockCollision) Error() string {
	return fmt.Sprintf("cross-block recon-key collision: key %q belongs to both %q and %q",
		c.Key, c.ExistingBlock, c.ConflictingBlock)
}

// CollisionError returns the first structural error that rejected this set.
func (s ActionSet) CollisionError() error {
	if len(s.CrossBlockCollisions) == 0 {
		return nil
	}
	return s.CrossBlockCollisions[0]
}

// Exclusion is one pruned move and the structural or hard-constraint reason.
type Exclusion struct {
	GenerationRank int
	Key            string
	Action         model.Action
	Reason         string
	// StructuralKind identifies an exclusion that occurs before feasibility but
	// is not missing recon cover. It is a closed decision-trace cause, never
	// inferred by parsing Reason text.
	StructuralKind       string
	Category             string
	Detail               string
	CoverKeys            []string
	FeasibilityEvaluated bool
	Feasible             bool
	CostEvaluated        bool
	ECost                float64
	CHi                  float64
	// EligibilityKind is set by the T1-E capability gate (before scoring). It is the
	// STRUCTURAL key the decision trace maps on — never the Reason string. "" for a
	// non-gate exclusion (feasibility/cost/slo). One of the capability Reason* classes:
	// not-installable | no-cover | capability-unsupported | no-rbac.
	EligibilityKind string
}

// Eligibility is the capability gate's verdict for one (asset, action), wired into Deps
// by the engine (which adapts capability.Reason to this, so actionset need not import
// capability — actuator already imports actionset). nil = eligible-and-clean.
type Eligibility struct {
	Excluded    bool   // true = drop from ranking with Kind/Detail
	Kind        string // capability Reason* class (only when Excluded)
	Detail      string // exclusion detail, or the rbac-unknown note
	RBACUnknown bool   // SSAR errored — NOT excluded, flagged (fail-open, P-NO-FREEZE)
}

const emptyReconCoverReason = "recon-cover: action invalidates no facts for this asset"

// Deps are the per-tick collaborators the generator binds (supplied by the engine so
// the generator stays free of context/cost/killchain imports).
type Deps struct {
	// RetainSLO is used only for qualified M99 assets with explicit opt-in.
	RetainSLO   func(string) bool
	Recon       recon.ReconProfile
	FactContext func(*model.WorkloadView) recon.FactContext
	ECost       func(*model.WorkloadView, model.Move, model.Policy) float64
	CHi         func(*model.WorkloadView, model.Move, model.Policy) float64
	// Evaluate optionally computes both costs once and carries a distinct
	// unactionable category/detail (for example a NaN feature). Existing swappable
	// test models may leave it nil and continue using ECost/CHi.
	Evaluate func(*model.WorkloadView, model.Move, model.Policy) (ecost, chi float64, category, detail string)
	// CostCeiling is the worst-case (CHi) cost above which a move is deemed SLO-unsafe
	// and pruned (the conformal SLO gate). The engine derives it from the policy.
	CostCeiling float64
	// Eligible is the T1-E capability gate, evaluated BEFORE scoring: it returns the
	// single cheapest-first exclusion reason (or an eligible-but-rbac-unknown flag) for
	// one (asset, action). When nil (legacy/tests), the generator falls back to the
	// pre-T1-E empty-cover check only. The engine wires capability.Witness.Eligible here.
	Eligible func(v *model.WorkloadView, action model.Action, coverKeys []string) *Eligibility
}

func enabledActions(pol model.Policy) []model.Action {
	var out []model.Action
	for _, a := range model.MutatingActions { // single source of truth (cannot drift from candidateActions)
		if model.ActionEnabled(pol, a) {
			out = append(out, a)
		}
	}
	return out
}

// GeneratableActions is the canonical set the completeness invariant enumerates: every
// action a policy MAY enable and the generator MAY emit. It is model.MutatingActions (the
// CoverByAction keys are always a subset). The native actuator MUST carry a handler for
// each — actuator's completeness check fails the build (CI + startup) otherwise.
func GeneratableActions() []model.Action {
	out := make([]model.Action, len(model.MutatingActions))
	copy(out, model.MutatingActions)
	return out
}

// Generate builds the live feasible action set. Steps per (asset, enabled action):
//
//  1. Structural recon relevance — an action that invalidates no facts for this
//     asset is EXCLUDED before cost/feasibility work and cannot contaminate demand.
//  2. Layer-A hard feasibility (PDB/availability, SLO-p99, anti-over-rotation,
//     stateful-integrity) via the registry — an infeasible move is EXCLUDED.
//  3. Cost-data validity — a NaN-bearing action is excluded fail-conservative in
//     its own observable category, never silently folded into ordinary infeasibility.
//  4. Conformal SLO-cost gate — if the worst-case cost CHi exceeds CostCeiling the
//     move could breach the disruption budget, so it is EXCLUDED.
//  5. Survivors enter the set with their non-empty recon cover keys + costs.
//
// The set provably changes with state and contains NO hard-constraint-violating move.
func (d Deps) Generate(views []*model.WorkloadView, pol model.Policy) ActionSet {
	// Both sides added fields to this literal: main added FactsAbsent (M-111), this branch added
	// CostCeiling + CoverByAsset for the decision trace. Keep BOTH — they are independent.
	out := ActionSet{FactWeights: map[string]float64{}, FactsByAsset: map[string][]recon.Fact{},
		FactsAbsent: map[string]string{},
		CostCeiling: d.CostCeiling, CoverByAsset: map[string]map[model.Action][]string{}}
	resourceIndex := map[string]int{}
	moveIdentity := pol.PolicyUID
	if moveIdentity == "" {
		moveIdentity = pol.Tenant
	}
	moveNamespace := pol.Namespace
	if moveNamespace == "" {
		for _, view := range views {
			if view == nil || view.Pod.Namespace == "" {
				continue
			}
			if moveNamespace == "" {
				moveNamespace = view.Pod.Namespace
			} else if moveNamespace != view.Pod.Namespace {
				moveNamespace = ""
				break
			}
		}
	}
	moveScope := model.ResourceScope{Kind: model.ResourceMoveCount, Namespace: moveNamespace, ControllerUID: moveIdentity}
	addCapacity := func(capacity model.ResourceCapacity) {
		key := capacity.Scope.Key()
		if existing, ok := resourceIndex[key]; ok {
			// Different observations for one immutable scope are contradictory.
			// Keep the conservative lower limit and higher outstanding count.
			if capacity.Limit < out.Resources[existing].Limit {
				out.Resources[existing].Limit = capacity.Limit
			}
			if capacity.Outstanding > out.Resources[existing].Outstanding {
				out.Resources[existing].Outstanding = capacity.Outstanding
			}
			return
		}
		resourceIndex[key] = len(out.Resources)
		out.Resources = append(out.Resources, capacity)
	}
	addCapacity(model.ResourceCapacity{Scope: moveScope, Limit: pol.MaxMovesPerTick})
	keyOwners := map[string]string{}
	claim := func(factKey, block string) bool {
		owner, exists := keyOwners[factKey]
		if !exists {
			keyOwners[factKey] = block
			return true
		}
		if owner == block {
			return true // legal within-pod overlap across facts/actions
		}
		out.CrossBlockCollisions = append(out.CrossBlockCollisions, CrossBlockCollision{
			Key: factKey, ExistingBlock: owner, ConflictingBlock: block,
		})
		out.Rejected = true
		// Leave no partially generated candidates behind. Even a caller that forgets
		// to inspect CollisionError cannot select from a structurally invalid set.
		out.Candidates = nil
		return false
	}
	rank := 0
	for _, v := range views {
		key := v.Pod.Namespace + "/" + v.Pod.Name
		af := d.Recon.AssetFacts(v, d.FactContext(v))
		if af.AbsentReason != "" {
			// M-111: a non-finite belief/physics input minted no fact. Fail-conservative in the
			// SAME observable category as a NaN cost (never folded into ordinary infeasibility):
			// every enabled action is excluded with the reason, the trace carries it per asset,
			// and the NaN metric counts it. No weight, marginal or gain ever sees the non-number.
			out.FactsAbsent[key] = af.AbsentReason
			for _, action := range enabledActions(pol) {
				out.Excluded = append(out.Excluded, Exclusion{
					Key: key, Action: action, Reason: cost.UnactionableNaNCategory + ": recon " + af.AbsentReason,
					Category: cost.UnactionableNaNCategory, Detail: "recon " + af.AbsentReason,
				})
			}
			continue
		}
		out.FactsByAsset[key] = cloneFacts(af.Facts)
		// T0-C: carry the full declared cover map (all actions) for the trace's
		// per-fact CoveringActions inversion. The slices are shared read-only.
		out.CoverByAsset[key] = af.CoverByAction
		coveredKeys := map[string]bool{}
		// Scan every declared cover, including disabled actions. A topology-conditional
		// collision is a taxonomy violation independent of this tenant's current policy.
		for _, coverKeys := range af.CoverByAction {
			for _, factKey := range coverKeys {
				coveredKeys[factKey] = true
				if !claim(factKey, key) {
					return out
				}
			}
		}
		// Objective weights are projected strictly through action covers. This is the hard boundary
		// that keeps shared-scope and CANNOT-HELP facts audit-only: even a large audit weight cannot
		// influence selection unless a deterministic eraser explicitly names its key.
		for _, f := range af.Facts {
			factKey := f.Key()
			if !coveredKeys[factKey] {
				continue
			}
			if w := f.Weight; w > out.FactWeights[factKey] {
				out.FactWeights[factKey] = w
			}
		}
		for _, action := range enabledActions(pol) {
			generationRank := rank
			rank++
			coverKeys := af.CoverByAction[action]
			if action == model.ActionIdentityRotate {
				out.Excluded = append(out.Excluded, Exclusion{
					GenerationRank: generationRank, Key: key, Action: action,
					Reason:          model.IdentityRotateUnsupportedReason,
					EligibilityKind: "capability-unsupported",
					CoverKeys:       append([]string(nil), coverKeys...),
				})
				continue
			}
			// M-52: quarantine capacity is a hard namespace-wide law, evaluated
			// before feasibility/SLO work so existential SLO override cannot relax it.
			// The inventory is assembled before tenant selector filtering and counts
			// both backends plus protected pending reservations.
			if action == model.ActionQuarantine && pol.QuarantineCapacityConfigured {
				if !pol.QuarantineCapacityKnown {
					detail := pol.QuarantineCapacityReason
					if detail == "" {
						detail = "complete namespace inventory unavailable"
					}
					out.Excluded = append(out.Excluded, Exclusion{
						GenerationRank: generationRank, Key: key, Action: action,
						Reason:         "quarantine-capacity-inventory-unknown: " + detail,
						StructuralKind: model.ExclusionResourceCapacity,
						CoverKeys:      append([]string(nil), coverKeys...),
					})
					continue
				}
				if pol.QuarantineCapacityUsed >= pol.QuarantineCapacityLimit {
					out.Excluded = append(out.Excluded, Exclusion{
						GenerationRank: generationRank, Key: key, Action: action,
						Reason:         fmt.Sprintf("quarantine-capacity-exhausted: used=%d limit=%d", pol.QuarantineCapacityUsed, pol.QuarantineCapacityLimit),
						StructuralKind: model.ExclusionResourceCapacity,
						CoverKeys:      append([]string(nil), coverKeys...),
					})
					continue
				}
			}
			// (1) T1-E capability gate — cheapest-first, before any scoring. Exactly one
			// reason per excluded action; an SSAR error flags-but-does-not-exclude. When
			// the gate is not wired (legacy/tests), fall back to the pre-T1-E empty-cover
			// check only (a move with no cover has zero marginal security gain).
			rbacUnknown := false
			if d.Eligible != nil {
				if e := d.Eligible(v, action, coverKeys); e != nil {
					if e.Excluded {
						out.Excluded = append(out.Excluded, Exclusion{
							GenerationRank: generationRank, Key: key, Action: action, Reason: e.Detail, EligibilityKind: e.Kind,
							CoverKeys: append([]string(nil), coverKeys...),
						})
						continue
					}
					rbacUnknown = e.RBACUnknown
				}
			} else if len(coverKeys) == 0 {
				reason := emptyReconCoverReason
				if action == model.ActionGuardrailRotate {
					reason = model.GuardrailBypassNoCoverReason
				}
				out.Excluded = append(out.Excluded, Exclusion{
					GenerationRank: generationRank, Key: key, Action: action, Reason: reason,
				})
				continue
			}
			move := model.Move{Action: action}
			resources, capacities, resourceReason := candidateResources(v, action, pol, moveScope)
			if resourceReason != "" {
				out.Excluded = append(out.Excluded, Exclusion{
					GenerationRank: generationRank, Key: key, Action: action,
					Reason:         "resource-capacity: " + resourceReason,
					StructuralKind: model.ExclusionResourceCapacity,
					CoverKeys:      append([]string(nil), coverKeys...),
				})
				continue
			}
			for _, capacity := range capacities {
				addCapacity(capacity)
			}
			var sloExclusions []string
			verdict := feasibility.Evaluate(v, move, pol)
			if d.RetainSLO != nil && d.RetainSLO(key) {
				verdict, sloExclusions = feasibility.EvaluateWithSLOSeparation(v, move, pol)
			}
			if !verdict.Feasible {
				out.Excluded = append(out.Excluded, Exclusion{
					GenerationRank: generationRank, Key: key, Action: action, Reason: verdict.Reason,
					CoverKeys: append([]string(nil), coverKeys...), FeasibilityEvaluated: true,
				})
				continue
			}
			// (3) Evaluate cost. A data-quality failure is a distinct fail-closed
			// category, not ordinary physical infeasibility and not a cheap default.
			ecost, chi := 0.0, 0.0
			category, detail := "", ""
			if d.Evaluate != nil {
				ecost, chi, category, detail = d.Evaluate(v, move, pol)
			} else {
				ecost, chi = d.ECost(v, move, pol), d.CHi(v, move, pol)
			}
			if category != "" {
				reason := category
				if detail != "" {
					reason += ": " + detail
				}
				out.Excluded = append(out.Excluded, Exclusion{
					GenerationRank: generationRank, Key: key, Action: action, Reason: reason, Category: category, Detail: detail,
					CoverKeys: append([]string(nil), coverKeys...), FeasibilityEvaluated: true, Feasible: true,
				})
				continue
			}
			// (4) Conformal SLO-cost gate (worst-case disruption must fit the budget).
			if d.CostCeiling > 0 && chi > d.CostCeiling {
				out.Excluded = append(out.Excluded, Exclusion{GenerationRank: generationRank, Key: key, Action: action,
					Reason:    "conformal-slo: worst-case cost " + ftoa(chi) + " > ceiling " + ftoa(d.CostCeiling),
					CoverKeys: append([]string(nil), coverKeys...), FeasibilityEvaluated: true, Feasible: true,
					CostEvaluated: true, ECost: ecost, CHi: chi})
				if d.RetainSLO == nil || !d.RetainSLO(key) {
					continue
				}
				sloExclusions = append(sloExclusions, "conformal-slo")
				out.Excluded = out.Excluded[:len(out.Excluded)-1]
			}
			out.Candidates = append(out.Candidates, Candidate{
				GenerationRank: generationRank,
				SLOExclusions:  sloExclusions,
				Key:            key,
				View:           v,
				Action:         action,
				CoverKeys:      coverKeys,
				ECost:          ecost,
				CHi:            chi,
				Resources:      resources,
				RBACUnknown:    rbacUnknown,
			})
		}
	}
	return out
}

func candidateResources(view *model.WorkloadView, action model.Action, pol model.Policy, moveScope model.ResourceScope) ([]model.ResourceConsumption, []model.ResourceCapacity, string) {
	demands := []model.ResourceConsumption{{Scope: moveScope, Units: 1}}
	capacities := []model.ResourceCapacity{{Scope: moveScope, Limit: pol.MaxMovesPerTick}}
	if !feasibility.RemovesReadyReplica(action) {
		return demands, capacities, ""
	}
	// A policy-local floor of zero does not erase another policy's retained floor
	// for the same Service. Every configured replica removal therefore carries its
	// exact Service demand into the durable cross-policy Acquire/Claim boundary.
	// The production manager always wires the durable store. Explicit offline
	// evaluators that do not configure it retain their historical move-count-only
	// contract rather than fabricating Service inventory.
	if !pol.SharedResourceCapacityConfigured {
		return demands, capacities, ""
	}
	if !pol.SharedResourceReservationsKnown {
		reason := pol.SharedResourceReservationsReason
		if reason == "" {
			reason = "durable shared reservation inventory unavailable"
		}
		return nil, nil, reason
	}
	if view == nil || !view.Pod.ServiceAvailabilityKnown {
		reason := "service availability inventory unavailable"
		if view != nil && view.Pod.ServiceAvailabilityReason != "" {
			reason = view.Pod.ServiceAvailabilityReason
		}
		return nil, nil, reason
	}
	if len(view.Pod.ServiceAvailability) == 0 {
		return nil, nil, "target has no authoritative Service/EndpointSlice membership"
	}
	seen := map[string]bool{}
	for _, observation := range view.Pod.ServiceAvailability {
		if !observation.Complete || !observation.TargetReady || observation.Scope.Kind != model.ResourceUnavailableReadyReplica ||
			observation.Scope.Namespace == "" || observation.Scope.ServiceUID == "" || observation.Scope.ControllerUID == "" {
			reason := observation.Reason
			if reason == "" {
				reason = "incomplete Service availability observation"
			}
			return nil, nil, reason
		}
		key := observation.Scope.Key()
		if seen[key] {
			continue
		}
		seen[key] = true
		limit := observation.ReadyMembers - pol.MinAvailableReplicas
		if limit < 0 {
			limit = 0
		}
		outstanding := 0
		if pol.SharedResourceReservations != nil {
			outstanding = pol.SharedResourceReservations[key]
		}
		// A stricter newly observed floor can leave a pre-existing obligation
		// above today's raw spare count. Keep that obligation representable while
		// allowing no additional removal from this scope.
		if limit < outstanding {
			limit = outstanding
		}
		capacities = append(capacities, model.ResourceCapacity{Scope: observation.Scope, Limit: limit, Outstanding: outstanding})
		demands = append(demands, model.ResourceConsumption{Scope: observation.Scope, Units: 1})
	}
	return demands, capacities, ""
}

func ftoa(f float64) string {
	// compact, allocation-light float formatting for audit reasons
	neg := f < 0
	if neg {
		f = -f
	}
	scaled := int64(f*100 + 0.5)
	whole := scaled / 100
	frac := scaled % 100
	s := itoa(whole) + "." + pad2(frac)
	if neg {
		return "-" + s
	}
	return s
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func pad2(n int64) string {
	if n < 10 {
		return "0" + itoa(n)
	}
	return itoa(n)
}
