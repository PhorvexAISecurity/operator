package decision

import (
	"fmt"
	"slices"
	"time"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/model"
)

// assessOutcomes reads the full authenticated-event inventory, before projection
// through FactWeights. Conflicting records are retained, never last-writer-wins.
func assessOutcomes(v *model.WorkloadView, p model.Policy) *model.ExistentialDecision {
	d := &model.ExistentialDecision{TrustBoundaryReady: p.TrustBoundaryReady, TrustBoundaryReason: p.TrustBoundaryReason, TrustBoundarySince: p.TrustBoundarySince, Result: "inactive", EffectStatus: "not-attempted", MayBreachSLO: p.MayBreachSLO, Order: "baseline"}
	key := v.Pod.Namespace + "/" + v.Pod.Name
	horizon := p.EffectiveEventAgeHorizon()
	for _, ev := range v.OutcomeEvents {
		if ev.OutcomeParseError != "" {
			d.Reasons = append(d.Reasons, ev.OutcomeParseError)
		}
		for _, r := range ev.Outcomes {
			// Another policy's inventory cannot constrain this one.
			if r.PolicyUID != "" && r.PolicyUID != p.PolicyUID {
				continue
			}
			if r.DecisionAsset != "" && r.DecisionAsset != key && p.DecisionAssets[r.DecisionAsset] != "" {
				continue
			}
			e := model.OutcomeEvidence{Outcome: r, Event: ev.Name, Class: model.OutcomeClass(r), EventTrust: ev.Trust, CreatorIdentity: ev.CreatorIdentity, EventCreatedAt: ev.CreatedAt, EventAgeSeconds: ev.Age.Seconds(), EvidenceHorizonSeconds: horizon.Seconds(), TimestampPresent: !ev.TimestampMissing}
			scope := r.ID != "" && r.PolicyUID != "" && r.PolicyUID == p.PolicyUID && r.DecisionAsset == key && r.DecisionAssetUID != "" && r.DecisionAssetUID == v.Pod.UID && r.ProtectedAsset != "" && r.Version != "" && r.Portion != "" && r.Property != "" && r.ScopeBasis != ""
			relevant := scope && slices.Contains(ev.ResolvedTargets, key)
			e.TrustedEvidence = relevant && ev.Trust == "trusted" && ev.CreatorIdentity != "" && !ev.TimestampMissing && model.EventAgeWeight(ev.Age, horizon) > 0
			if !scope {
				e.Reasons = append(e.Reasons, "scope-unresolved")
				d.Reasons = append(d.Reasons, "scope-unresolved:"+r.ID)
			}
			if !e.TrustedEvidence {
				e.Reasons = append(e.Reasons, "no-valid-scoped-trusted-support")
			}
			boundaryValid := p.TrustBoundaryReady && (p.TrustBoundarySince.IsZero() || !ev.CreatedAt.Before(p.TrustBoundarySince))
			e.BoundaryEnforced = boundaryValid
			e.TrustedEvidence = e.TrustedEvidence && boundaryValid
			if !boundaryValid {
				e.Reasons = append(e.Reasons, "m94-boundary-not-ready-or-event-predates-enforcement:"+p.TrustBoundaryReason)
			}
			if e.Class == "unresolved" {
				e.Reasons = append(e.Reasons, "class-unresolved")
			}
			if (r.LossState != "at-risk" && r.LossState != "already-lost") || r.StateBasis == "" {
				e.Reasons = append(e.Reasons, "loss-state-unknown")
			}
			e.Qualified = scope && e.TrustedEvidence && boundaryValid && e.Class == "irreversible-catastrophic" && r.LossState == "at-risk" && r.StateBasis != ""
			d.Evidence = append(d.Evidence, e)
			d.TrustedEvidence = d.TrustedEvidence || e.TrustedEvidence
			d.Present = d.Present || e.Qualified
		}
	}
	d.Present = false
	for i := range d.Evidence {
		risk := &d.Evidence[i]
		if !risk.Qualified {
			continue
		}
		for _, other := range d.Evidence {
			if other.TrustedEvidence && other.BoundaryEnforced && other.Class == "irreversible-catastrophic" && other.Outcome.LossState == "already-lost" && other.Outcome.StateBasis != "" && sameOutcomeScope(risk.Outcome, other.Outcome) {
				risk.Qualified = false
				risk.Reasons = append(risk.Reasons, "accepted-established-loss-no-prevention-credit")
				break
			}
		}
		d.Present = d.Present || risk.Qualified
	}
	d.ConstraintApplied = d.Present
	if d.Present {
		d.Order = "existential>λ"
		if p.MayBreachSLO {
			d.Order = "existential>SLO>λ"
		}
	}
	return d
}

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
		gain := objectiveGain(marginal, prov(c.Key), costCoefficient, c.ECost)
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

func sameOutcomeScope(a, b model.ProtectedOutcome) bool {
	return a.PolicyUID == b.PolicyUID && a.ProtectedAsset == b.ProtectedAsset && a.Version == b.Version && a.Portion == b.Portion && a.Property == b.Property && a.Outcome == b.Outcome
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
		x := assessOutcomes(v, p)
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

// HasQualifiedOutcome lets the runner retain an unavailable capability checker
// as a veto specifically for M99 without changing the ordinary fail-open path.
func HasQualifiedOutcome(v *model.WorkloadView, p model.Policy) bool {
	return assessOutcomes(v, p).Present
}
