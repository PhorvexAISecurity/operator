package decision

import (
	"fmt"
	"slices"
	"time"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/model"
)

func containment(c actionset.Candidate, d *model.ExistentialDecision) model.ExistentialCandidate {
	a := model.ExistentialCandidate{Action: c.Action, GenerationRank: c.GenerationRank, Present: d.Present, TrustedEvidence: d.TrustedEvidence, ConstraintApplied: d.Present, Order: d.Order, MayBreachSLO: d.MayBreachSLO, Contains: d.Present, SLOExcluded: len(c.SLOExclusions) > 0}
	a.Reasons = append(a.Reasons, c.SLOExclusions...)
	if c.RBACUnknown && d.Present {
		a.Contains = false
		a.Reasons = append(a.Reasons, "capability-rbac-unknown")
	}
	for _, e := range d.Evidence {
		if !e.Qualified {
			continue
		}
		r := e.Outcome
		if !r.MappingComplete || r.MappingBasis == "" || len(r.RequiredKeys) == 0 {
			a.Contains = false
			a.Reasons = append(a.Reasons, "representation-unresolved:"+r.ID)
		}
		for _, k := range r.RequiredKeys {
			if k == "" || !slices.Contains(c.CoverKeys, k) {
				a.Contains = false
				a.MissingKeys = append(a.MissingKeys, k)
			}
		}
	}
	if len(a.MissingKeys) > 0 {
		a.Reasons = append(a.Reasons, "no-sound-cover")
	}
	return a
}

// preferExistential implements priority tiers without a finite penalty or a
// positive-gain cutoff. Exact equality preserves the original generation order.
func preferExistential(active, safe bool, gain float64, bestActive, bestSafe bool, bestGain float64, have bool) bool {
	if !have {
		return active || gain > 0
	}
	if active != bestActive {
		return active
	}
	if active && safe != bestSafe {
		return safe
	}
	return gain > bestGain
}

func finishExistential(d *model.ExistentialDecision, set actionset.ActionSet, key string, selected bool, remaining int, priority []string) {
	d.RemainingBudget = remaining
	d.PrioritySelections = append([]string(nil), priority...)
	for _, c := range set.Candidates {
		if c.Key == key {
			d.Candidates = append(d.Candidates, containment(c, d))
		}
	}
	for _, ex := range set.Excluded {
		if ex.Key == key {
			a := containment(actionset.Candidate{Action: ex.Action, GenerationRank: ex.GenerationRank, CoverKeys: ex.CoverKeys}, d)
			a.Reasons = append(a.Reasons, ex.Reason)
			d.Candidates = append(d.Candidates, a)
		}
	}
	if !d.Present {
		// Baseline traces historically normalize pod ordering. Record only the
		// per-asset generation rank for inactive assets, retaining that contract.
		for i := range d.Candidates {
			d.Candidates[i].GenerationRank = slices.Index(model.MutatingActions, d.Candidates[i].Action)
		}
		return
	}
	if selected {
		d.Result = "selected"
		return
	}
	d.Result = "uncontainable"
	if remaining <= 0 {
		d.Reasons = append(d.Reasons, "move-budget-exhausted")
	}
	d.Reasons = append(d.Reasons, fmt.Sprintf("PHORVEXSEC-208-interim: no certified permitted full-containing move selected for %s", key))
}

// chooseRound is the production bounded-greedy comparison seam, also replayed by
// the ruling's exact numeric counterexamples.
func chooseRound(set actionset.ActionSet, states map[string]*model.ExistentialDecision, covered, selected, attack map[string]bool, costCoefficient float64, prov func(string) float64, evaluated map[string]float64, capacity ...*resourceState) (int, float64, bool) {
	bestIdx := -1
	bestActive, bestSafe := false, false
	bestGain, bestMarginal := 0.0, 0.0
	for i := range set.Candidates {
		c := set.Candidates[i]
		if selected[c.Key] {
			continue
		}
		if !attack[c.Key] {
			continue // reactiveOnly: suppress proactive moves on un-attacked assets
		}
		if len(capacity) > 0 {
			if ok, _ := capacity[0].canAdd(c); !ok {
				continue
			}
		}
		active := states[c.Key].Present
		ca := containment(c, states[c.Key])
		if active && !ca.Contains {
			continue
		}
		if len(c.SLOExclusions) > 0 && (!active || !states[c.Key].MayBreachSLO) {
			continue
		}
		marginal := 0.0
		for _, k := range c.CoverKeys {
			if !covered[k] {
				marginal += set.FactWeights[k]
			}
		}
		candidateKey := traceCandidateKey(c.Key, c.Action)
		evaluated[candidateKey] = marginal
		gain := marginal*prov(c.Key) - candidatePenalty(c, costCoefficient)
		if preferExistential(active, len(c.SLOExclusions) == 0, gain, bestActive, bestSafe, bestGain, bestIdx >= 0) {
			bestActive, bestSafe = active, len(c.SLOExclusions) == 0
			bestGain = gain
			bestIdx = i
			bestMarginal = marginal
		}
	}

	if bestIdx < 0 || (!bestActive && !strictPositiveGain(bestGain)) {
		return -1, 0, false
	}
	return bestIdx, bestMarginal, bestActive
}

func decorateExistentialTrace(t *model.DecisionTraceV2, d *model.ExistentialDecision) {
	if t == nil || d == nil {
		return
	}
	t.Existential = d
	if d.Present || len(d.PrioritySelections) > 0 {
		t.SelectorComparator = model.SelectorM99Containment
	}
	for i := range t.Candidates {
		row := &t.Candidates[i]
		for j := range d.Candidates {
			c := &d.Candidates[j]
			if string(c.Action) != row.Action {
				continue
			}
			row.Existential = c
			if d.Present {
				row.TieBreakRank = c.GenerationRank
				switch {
				case row.ExistingExclusionReason != "":
				case row.Selected:
					row.SelectionReason = "selected_full_containment"
				case !c.Contains:
					row.SelectionReason = "existential_no_full_cover"
				case d.RemainingBudget <= 0:
					row.SelectionReason = "move_budget_exhausted"
				default:
					row.SelectionReason = "containing_candidate_not_selected"
				}
			} else if len(d.PrioritySelections) > 0 && !row.Selected && row.ExistingExclusionReason == "" {
				row.SelectionReason = "shared_scope_existential_priority"
			}
			if c.SLOExcluded {
				row.SLOGateResult = model.OptionalBool{Present: true, Value: false}
			}
			break
		}
	}
	if d.Result == "uncontainable" {
		t.NoopReason = "existential-uncontainable"
	}
	if !d.Present && len(d.PrioritySelections) == 0 {
		return
	}
	for i := range t.ActionStatus {
		row := &t.ActionStatus[i]
		for _, c := range t.Candidates {
			if c.Action == row.Action {
				row.Reason = c.SelectionReason
				if c.Existential != nil && c.Existential.Present && !c.Existential.Contains && c.ExistingExclusionReason == "" {
					row.Status = model.ActionStatusInfeasible
					row.ExclusionKind = model.ExclusionSelection
				}
			}
		}
	}
}

// ExistentialRejectedDecisions records qualified obligations when structural
// validation rejects the entire action set. It never selects or learns a move.
func ExistentialRejectedDecisions(views []*model.WorkloadView, p model.Policy, reason string, now time.Time) []model.Decision {
	out, _ := ExistentialRejectedDecisionsChecked(views, p, reason, now)
	return out
}

// ExistentialRejectedDecisionsChecked is the production form. The ordinary
// decision path validates the same policy before candidate generation; keeping
// the error here prevents a direct caller from emitting a new record with
// unavailable provenance for malformed configuration.
func ExistentialRejectedDecisionsChecked(views []*model.WorkloadView, p model.Policy, reason string, now time.Time) ([]model.Decision, error) {
	parameterSet, _, _, err := ParameterSetForPolicy(p)
	if err != nil {
		return nil, err
	}
	var out []model.Decision
	for _, v := range views {
		x := model.AssessOutcomes(v, p)
		if !x.Present {
			continue
		}
		x.Result = "uncontainable"
		x.RemainingBudget = p.MaxMovesPerTick
		x.Reasons = append(x.Reasons, "candidate-generation-unavailable:"+reason)
		out = append(out, model.Decision{Tenant: p.Tenant, Namespace: v.Pod.Namespace, Pod: v.Pod.Name, Node: v.Pod.Node, Action: model.ActionNoop, Engine: "p1-coverage", DryRun: p.DryRun, DecidedAt: now, Reason: "PHORVEXSEC-208 interim: uncontainable", InfeasibleWhy: reason, Existential: x, ParameterSet: cloneParameterSetReference(parameterSet)})
	}
	return out, nil
}
