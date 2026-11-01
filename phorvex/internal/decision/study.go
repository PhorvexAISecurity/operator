package decision

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/cost/endpoint"
	"github.com/phorvex/phorvex/internal/killchain"
	"github.com/phorvex/phorvex/internal/model"
)

func candidateProvenance(ac assetCtx, floorSec float64) float64 {
	if floorSec <= 0 || ac.exposure >= floorSec || ac.assess.HasEventEvidence {
		return 1
	}
	r := ac.exposure / floorSec
	if r < 0 {
		r = 0
	}
	return provFloor + (1-provFloor)*r
}

// StudyCandidateID binds the action to immutable policy/Pod identities, rather
// than to a reusable name or a selected-row position.
func StudyCandidateID(policyUID, podUID string, action model.Action) string {
	h := sha256.Sum256([]byte(policyUID + "\x00" + podUID + "\x00" + string(action)))
	return hex.EncodeToString(h[:])
}

// StudyPreparation carries values from the real generator and the exact
// deterministic selection prerequisites. It is an offline result, not an
// actuation authorization or a claim of measured endpoint history.
type StudyPreparation struct {
	Candidates []endpoint.Candidate
	Missing    []string
	Mandatory  bool
	set        actionset.ActionSet
	states     map[string]*model.ExistentialDecision
	attack     map[string]bool
	provenance map[string]float64
	policyUID  string
}

// PrepareEndpointStudy shares the legacy engine's assessment, recon and
// non-cost generator. Recorded capability/cooldown playback remains mandatory;
// callers must also reject any missing playback queries after this method.
func (e *CoverageEngine) PrepareEndpointStudy(views []*model.WorkloadView, pol model.Policy) (StudyPreparation, error) {
	out := StudyPreparation{Candidates: []endpoint.Candidate{}, states: map[string]*model.ExistentialDecision{}, attack: map[string]bool{}, provenance: map[string]float64{}, policyUID: pol.PolicyUID}
	if e.ownerAbsent(pol.Owner()) {
		return out, ErrOwnerRetired
	}
	if pol.MaxMovesPerTick != 1 {
		return out, fmt.Errorf("STUDY_SCOPE_REQUIRES_B1")
	}
	var prepared actionset.Preparation
	_, ctx, err := e.assembleSet(views, pol, e.costForMode(pol.Owner(), killchain.EvalShadow, pol.Lambda), killchain.EvalShadow, &prepared)
	if err != nil {
		return out, err
	}
	if prepared.Rejected {
		return out, fmt.Errorf("STUDY_RECON_COLLISION: %v", prepared.CrossBlockCollisions)
	}
	byKey := map[string]*model.WorkloadView{}
	for _, v := range views {
		byKey[v.Pod.Namespace+"/"+v.Pod.Name] = v
	}
	capacities := newResourceState(actionset.ActionSet{Resources: prepared.Resources})
	out.set = actionset.ActionSet{Resources: prepared.Resources, FactWeights: prepared.FactWeights}
	row := func(v *model.WorkloadView, action model.Action, covers []string, gates []string, c *actionset.PreparedCandidate) endpoint.Candidate {
		key := v.Pod.Namespace + "/" + v.Pod.Name
		candidate := endpoint.Candidate{ID: StudyCandidateID(pol.PolicyUID, v.Pod.UID, action), PodUID: v.Pod.UID,
			Action: string(action), FactsKnown: prepared.FactsAbsent[key] == "", GatesKnown: true, Gates: append([]string{}, gates...), Facts: []endpoint.Fact{}, Class: "unknown"}
		seen := map[string]bool{}
		for _, k := range covers {
			if !seen[k] {
				candidate.Facts = append(candidate.Facts, endpoint.Fact{ID: k, Weight: prepared.FactWeights[k] * candidateProvenance(ctx[key], pol.ProactiveFloor.Seconds())})
				seen[k] = true
			}
		}
		sort.Slice(candidate.Facts, func(i, j int) bool { return candidate.Facts[i].ID < candidate.Facts[j].ID })
		if v.Pod.HasGPU {
			candidate.Class = "gpu"
		} else if v.Pod.Stateful {
			candidate.Class = "stateful"
		} else if v.Pod.WorkloadSpec.Known && (v.Pod.WorkloadSpec.Workload.Kind == "Deployment" || v.Pod.WorkloadSpec.Workload.Kind == "ReplicaSet") {
			candidate.Class = "stateless"
		}
		for _, service := range v.Pod.ServiceAvailability {
			if v.Pod.ServiceAvailabilityKnown && service.Complete && service.TargetReady {
				one := 1
				candidate.K = &one
				break
			}
		}
		state := model.AssessOutcomes(v, pol)
		out.states[key] = state
		out.attack[key] = !pol.ReactiveOnly || v.Pod.SuspectAdapter != "" || hasDirectFoothold(v.Events, v.Pod, pol.EffectiveEventAgeHorizon())
		out.provenance[key] = candidateProvenance(ctx[key], pol.ProactiveFloor.Seconds())
		candidate.Containment = state.Present
		out.Mandatory = out.Mandatory || state.Present
		if c != nil {
			// This non-cost projection is used only by the same resource and
			// containment predicates as chooseRound; no legacy price is evaluated.
			identity := actionset.Candidate{Key: c.Key, View: c.View, Action: c.Action, CoverKeys: c.CoverKeys,
				GenerationRank: c.GenerationRank, Resources: c.Resources, SLOExclusions: c.SLOExclusions, RBACUnknown: c.RBACUnknown}
			out.set.Candidates = append(out.set.Candidates, identity)
			if ok, reason := capacities.canAdd(identity); !ok {
				candidate.Gates = append(candidate.Gates, "resource-capacity:"+reason)
			}
			if pol.ReactiveOnly && v.Pod.SuspectAdapter == "" && !hasDirectFoothold(v.Events, v.Pod, pol.EffectiveEventAgeHorizon()) {
				candidate.Gates = append(candidate.Gates, "reactive-only:no-direct-observation")
			}
			if state.Present && !containment(identity, state).Contains {
				candidate.Gates = append(candidate.Gates, "existential:no-full-containment")
			}
			if len(c.SLOExclusions) > 0 && (!state.Present || !state.MayBreachSLO) {
				candidate.Gates = append(candidate.Gates, "slo-exception:not-authorized")
			}
		}
		return candidate
	}
	for i := range prepared.Candidates {
		c := &prepared.Candidates[i]
		out.Candidates = append(out.Candidates, row(c.View, c.Action, c.CoverKeys, nil, c))
	}
	for _, exclusion := range prepared.Excluded {
		v := byKey[exclusion.Key]
		if v == nil {
			return out, fmt.Errorf("STUDY_EXCLUSION_TARGET_MISSING")
		}
		covers := prepared.CoverByAsset[exclusion.Key][exclusion.Action]
		out.Candidates = append(out.Candidates, row(v, exclusion.Action, covers, []string{exclusion.Gate + ":" + exclusion.Reason}, nil))
	}
	sort.Slice(out.Candidates, func(i, j int) bool { return out.Candidates[i].ID < out.Candidates[j].ID })
	return out, nil
}

// SelectEndpointStudy executes the real brain's shared bounded-greedy gate loop
// with an explicit endpoint-study score. Pricing/admission rows come from the
// shared pure kernel; this method independently computes the winner. Negative J
// is permitted after the unpriced V-worth gate, as the study specifies.
func (p *StudyPreparation) SelectEndpointStudy(t endpoint.Tick, priced endpoint.ArmResult, lambda float64) (*string, error) {
	if p == nil || math.IsNaN(lambda) || math.IsInf(lambda, 0) || lambda < 0 {
		return nil, fmt.Errorf("STUDY_SELECTION_INPUT_INVALID")
	}
	byID := map[string]endpoint.Row{}
	for _, row := range priced.Rows {
		if _, duplicate := byID[row.ID]; duplicate {
			return nil, fmt.Errorf("STUDY_DUPLICATE_PRICE_ROW")
		}
		byID[row.ID] = row
	}
	if len(byID) != len(p.Candidates) {
		return nil, fmt.Errorf("STUDY_PRICE_POPULATION_MISMATCH")
	}
	values := map[string]float64{}
	for _, c := range p.Candidates {
		r, ok := byID[c.ID]
		v, reason := endpoint.Value(c)
		if !ok || (v == nil) != (r.V == nil) || (v != nil && *v != *r.V) {
			return nil, fmt.Errorf("STUDY_SOURCE_VALUE_MISMATCH: %s", c.ID)
		}
		if reason == "" && v != nil {
			values[c.ID] = *v
		}
	}
	idFor := func(c actionset.Candidate) string {
		return StudyCandidateID(p.policyUID, c.View.Pod.UID, c.Action)
	}
	// Candidate views are retained only inside this isolated preparation.
	rowFor := func(c actionset.Candidate) endpoint.Row { return byID[idFor(c)] }
	rule := &roundRule{}
	rule.admit = func(c actionset.Candidate) bool {
		r := rowFor(c)
		if !r.Admitted || r.V == nil || r.Cost.E == nil {
			return false
		}
		if p.Mandatory {
			return t.MandatoryID != "" && r.ID == t.MandatoryID && r.Containment
		}
		return !r.Containment
	}
	rule.gain = func(c actionset.Candidate, _ float64) float64 {
		r := rowFor(c)
		// B=1 starts with no covered facts. Use the deterministic sum of
		// grounded, provenance-adjusted source facts, validated above, rather
		// than reassociating sum(weights)*provenance or trusting uploaded V.
		value := values[idFor(c)]
		if r.Containment {
			return value
		}
		return value - lambda**r.Cost.E
	}
	rule.prefer = func(c actionset.Candidate, gain float64, best int, bestGain float64) bool {
		if math.IsNaN(gain) || math.IsInf(gain, 0) {
			return false
		}
		if best < 0 || gain != bestGain {
			return best < 0 || gain > bestGain
		}
		a, b := rowFor(c), rowFor(p.set.Candidates[best])
		if *a.V != *b.V {
			return *a.V > *b.V
		}
		if *a.Cost.E != *b.Cost.E {
			return *a.Cost.E < *b.Cost.E
		}
		return a.ID < b.ID
	}
	i, _, _ := chooseRoundWithRule(p.set, p.states, map[string]bool{}, map[string]bool{}, p.attack, 0,
		func(k string) float64 { return p.provenance[k] }, map[string]float64{}, rule, newResourceState(p.set))
	if i < 0 {
		return nil, nil
	}
	id := idFor(p.set.Candidates[i])
	return &id, nil
}
