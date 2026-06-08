/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 */

package decision

import (
	"fmt"
	"sort"
	"time"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/ctxprov"
	"github.com/phorvex/phorvex/internal/killchain"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

// CoverageEngine is the P1 brain: it maximizes consequence-weighted recon-facts-
// invalidated-per-dollar — Σ w(facts covered by S) − λ·C(S) — by a submodular greedy
// over the DYNAMICALLY GENERATED feasible action set, under a per-asset (one move)
// partition constraint and the move budget B. λ is the dual-descent budget shadow-
// price (also the proactive-timing knob). It is STATEFUL across ticks (RLS cost, dual
// λ, conjugate memory persist).
type CoverageEngine struct {
	Recon     recon.ReconProfile
	Context   ctxprov.ContextProvider
	Killchain *killchain.Model
	Cost      *cost.P1Cost
	Now       func() time.Time
}

// NewCoverageEngine builds the engine from the registered defaults + fresh stateful
// calibrators.
func NewCoverageEngine() *CoverageEngine {
	e := &CoverageEngine{Killchain: killchain.NewModel(), Cost: cost.NewP1Cost()}
	if r, ok := recon.Registry.Default(); ok {
		e.Recon = r
	}
	if c, ok := ctxprov.Registry.Default(); ok {
		e.Context = c
	}
	return e
}

// Name implements Optimizer.
func (e *CoverageEngine) Name() string { return "p1-coverage" }

func (e *CoverageEngine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

type assetCtx struct {
	sig      model.ContextSignals
	assess   killchain.Assessment
	exposure float64
}

// AssembleSet builds the per-asset context + kill-chain assessment and GENERATES the
// dynamic feasible action set (with fact weights). Shared by Decide and the ablation
// so both arms run over identical substrate.
func (e *CoverageEngine) AssembleSet(views []*model.WorkloadView, pol model.Policy) (actionset.ActionSet, map[string]assetCtx) {
	floorSec := pol.ProactiveFloor.Seconds()

	ctxByKey := make(map[string]assetCtx, len(views))
	for _, v := range views {
		key := v.Pod.Namespace + "/" + v.Pod.Name
		sig := model.ContextSignals{}
		if e.Context != nil {
			sig = e.Context.Context(v, pol)
		}
		exp := 0.0
		if d, ok := v.ExposureByVariable[model.VarPodIdentity]; ok {
			exp = d.Seconds()
		}
		assess := e.Killchain.Assess(v, pol, exp, floorSec)
		ctxByKey[key] = assetCtx{sig: sig, assess: assess, exposure: exp}
	}

	factCtx := func(v *model.WorkloadView) recon.FactContext {
		key := v.Pod.Namespace + "/" + v.Pod.Name
		ac := ctxByKey[key]
		nbs := make([]recon.NeighborRef, 0, len(v.Neighbors))
		for _, nb := range v.Neighbors {
			nbs = append(nbs, recon.NeighborRef{Key: nb.Key, Value: nb.Value})
		}
		return recon.FactContext{
			AssetValue:     ac.sig.AssetValue,
			PHold:          ac.assess.PHold,
			StageUrgency:   ac.assess.StageUrgency,
			LateralUrgency: ac.assess.LateralUrgency,
			BlastRadius:    v.BlastRadius,
			Neighbors:      nbs,
			HasGPU:         v.Pod.HasGPU,
			Stateful:       v.Pod.Stateful,
		}
	}

	costCeiling := pol.NormSparsity + pol.FlowDisruption + 0.2 // worst-case single-move budget
	deps := actionset.Deps{
		Recon:       e.Recon,
		FactContext: factCtx,
		ECost:       e.Cost.ECost,
		CHi:         e.Cost.CHi,
		CostCeiling: costCeiling,
	}
	return deps.Generate(views, pol), ctxByKey
}

// Decide runs the per-tick coverage optimization and returns one Decision per pod.
func (e *CoverageEngine) Decide(views []*model.WorkloadView, pol model.Policy) []model.Decision {
	now := e.now()
	lambda := e.Cost.Dual.Lambda()

	set, ctxByKey := e.AssembleSet(views, pol)

	candsByAsset := map[string][]int{}
	for i := range set.Candidates {
		candsByAsset[set.Candidates[i].Key] = append(candsByAsset[set.Candidates[i].Key], i)
	}
	excludedWhy := map[string]string{}
	for _, ex := range set.Excluded {
		if _, ok := excludedWhy[ex.Key]; !ok {
			excludedWhy[ex.Key] = ex.Reason
		}
	}

	// standalone coverage value of a candidate (full, un-marginal)
	covValue := func(c actionset.Candidate) float64 {
		s := 0.0
		for _, k := range c.CoverKeys {
			s += set.FactWeights[k]
		}
		return s
	}

	// --- submodular greedy under partition (one move/asset) + budget B ---
	covered := map[string]bool{}
	selectedAsset := map[string]bool{}
	selectedAction := map[string]model.Action{}
	selectedMarginal := map[string]float64{}
	B := pol.MaxMovesPerTick
	for round := 0; round < B; round++ {
		bestIdx := -1
		bestGain := 0.0
		bestMarginal := 0.0
		for i := range set.Candidates {
			c := set.Candidates[i]
			if selectedAsset[c.Key] {
				continue
			}
			marginal := 0.0
			for _, k := range c.CoverKeys {
				if !covered[k] {
					marginal += set.FactWeights[k]
				}
			}
			gain := marginal - lambda*c.ECost
			if gain > bestGain {
				bestGain = gain
				bestIdx = i
				bestMarginal = marginal
			}
		}
		if bestIdx < 0 || bestGain <= 0 {
			break
		}
		c := set.Candidates[bestIdx]
		selectedAsset[c.Key] = true
		selectedAction[c.Key] = c.Action
		selectedMarginal[c.Key] = bestMarginal
		for _, k := range c.CoverKeys {
			covered[k] = true
		}
	}

	// demand = number of assets with a net-positive best move (for the dual subgradient)
	demand := 0
	for _, idxs := range candsByAsset {
		best := 0.0
		for _, i := range idxs {
			c := set.Candidates[i]
			if v := covValue(c) - lambda*c.ECost; v > best {
				best = v
			}
		}
		if best > 0 {
			demand++
		}
	}

	// --- emit one Decision per view ---
	decisions := make([]model.Decision, 0, len(views))
	for _, v := range views {
		key := v.Pod.Namespace + "/" + v.Pod.Name
		ac := ctxByKey[key]
		idxs := candsByAsset[key]

		action := model.ActionNoop
		var chosen *actionset.Candidate
		if selAct, ok := selectedAction[key]; ok {
			for _, i := range idxs {
				if set.Candidates[i].Action == selAct {
					action = selAct
					chosen = &set.Candidates[i]
					break
				}
			}
		} else if len(idxs) > 0 {
			// best standalone candidate (highest coverage − λ·cost)
			bestNet := -1.0
			for _, i := range idxs {
				c := set.Candidates[i]
				if net := covValue(c) - lambda*c.ECost; net > bestNet {
					bestNet = net
					action = c.Action
					chosen = &set.Candidates[i]
				}
			}
		}

		feasible := len(idxs) > 0
		infeasibleWhy := ""
		if !feasible {
			infeasibleWhy = excludedWhy[key]
			if infeasibleWhy == "" {
				infeasibleWhy = "no feasible action this tick"
			}
		}

		cov, ecost, perDollar, marginal := 0.0, 0.0, 0.0, 0.0
		var attribution []model.AttributionTerm
		coveredFacts := 0
		if chosen != nil {
			cov = covValue(*chosen)
			ecost = chosen.ECost
			coveredFacts = len(chosen.CoverKeys)
			if ecost > 0 {
				perDollar = cov / ecost
			}
			marginal = selectedMarginal[key]
			if marginal == 0 {
				marginal = cov
			}
			attribution = attributionOf(*chosen, set.FactWeights, lambda)
		}

		// Proactive rate: per-dollar coverage above the shadow-price λ => "due now"; the
		// rate scales with how far it exceeds λ (the optimized-timing decision variable).
		rate := 0.0
		if perDollar > lambda {
			rate = perDollar - lambda
		}

		selected := selectedAsset[key]
		net := cov - lambda*ecost

		decisions = append(decisions, model.Decision{
			Tenant:           pol.Tenant,
			Namespace:        v.Pod.Namespace,
			Pod:              v.Pod.Name,
			Node:             v.Pod.Node,
			Risk:             cov, // recon value at stake
			Cost:             ecost,
			Net:              net,
			AssetValue:       ac.sig.AssetValue,
			ThreatPosture:    ac.sig.ThreatPosture,
			Exposure:         ac.sig.Exposure,
			Belief:           ac.assess.PHold,
			BlastRadius:      v.BlastRadius,
			SLOHeadroom:      ac.sig.SLOHeadroom,
			Phase:            v.Phase,
			Action:           action,
			Selected:         selected,
			Feasible:         feasible,
			InfeasibleWhy:    infeasibleWhy,
			Reason:             coverageReason(action, ac.assess, cov, ecost, perDollar, lambda),
			R6Counterfactual:   model.ActionRotate,
			CounterfactualNote: counterfactualNote(action, v, perDollar, lambda),
			DryRun:             pol.DryRun,
			DecidedAt:        now,
			Engine:           "p1-coverage",
			CoveredWeight:    marginal,
			CoveredFacts:     coveredFacts,
			PerDollar:        perDollar,
			Stage:            ac.assess.StageName,
			StageHazard:      ac.assess.Hazard,
			NextStage:        ac.assess.NextStageName,
			PHold:            ac.assess.PHold,
			Lambda:           lambda,
			ProactiveRate:    rate,
			Attribution:      attribution,
			PreemptMargin:         ac.assess.PreemptMargin,
			ProjectedNextStageSec: ac.assess.ProjectedNextStageSec,
			AIClassified:          ac.assess.AIClassified,
		})
	}

	// --- persist stateful learning (dual price + conjugate memory) ---
	e.Cost.Dual.Step(demand, len(selectedAsset), B)
	for key := range selectedAsset {
		if ac, ok := ctxByKey[key]; ok {
			// SYMMETRIC memory feedback (P-CONTEXT): acting on a HIGH-P(hold) asset is
			// evidence this tenant's footholds tend to be real (alpha up); acting on a
			// LOW-P(hold) asset is NEGATIVE evidence they persist (beta up) so the prior
			// can FALL — fixing the monotone confirmation-bias ratchet (the prior was
			// alpha-only). evidence = P(hold) - 0.5 in [-0.5, 0.5].
			e.Killchain.Memory.Observe(pol.Tenant, 0.5*(ac.assess.PHold-0.5))
		}
	}

	return decisions
}

// attributionOf decomposes a move's value into SHAP-style terms: per recon-fact-kind
// coverage contribution + the −λ·cost term.
func attributionOf(c actionset.Candidate, weights map[string]float64, lambda float64) []model.AttributionTerm {
	byKind := map[string]float64{}
	for _, k := range c.CoverKeys {
		kind := factKind(k)
		byKind[kind] += weights[k]
	}
	terms := make([]model.AttributionTerm, 0, len(byKind)+1)
	for kind, w := range byKind {
		terms = append(terms, model.AttributionTerm{Source: "cover:" + kind, Contribution: round4(w)})
	}
	terms = append(terms, model.AttributionTerm{Source: "cost:-lambda*C", Contribution: round4(-lambda * c.ECost)})
	sort.Slice(terms, func(i, j int) bool { return terms[i].Contribution > terms[j].Contribution })
	return terms
}

func round4(x float64) float64 {
	if x < 0 {
		return -round4(-x)
	}
	return float64(int64(x*10000+0.5)) / 10000
}

// factKind extracts the kind segment from a fact key "asset|kind[|edge]".
func factKind(key string) string {
	start := -1
	for i := 0; i < len(key); i++ {
		if key[i] == '|' {
			if start < 0 {
				start = i + 1
			} else {
				return key[start:i]
			}
		}
	}
	if start >= 0 {
		return key[start:]
	}
	return key
}

// counterfactualNote explains, per decision, how Phorvex's choice diverges from R6's
// blind machinery (whose time-based-trigger would Delete every covered pod on schedule
// with no cost/value/stateful awareness).
func counterfactualNote(a model.Action, v *model.WorkloadView, perDollar, lambda float64) string {
	if v.Pod.Stateful {
		switch a {
		case model.ActionQuarantine:
			return "R6's blind timer would DELETE this stateful pod on schedule (destroying its data); Phorvex quarantined to contain while preserving state."
		case model.ActionNoop:
			return "R6's blind timer would DELETE this stateful pod on schedule (destroying its data); Phorvex skipped — rotate is inviolably excluded and no other move is net-positive."
		}
	}
	switch a {
	case model.ActionRotate:
		return fmt.Sprintf("R6 would rotate too, but on a blind fixed timer (no cost/value targeting); Phorvex rotates now because per-$ %.2f > λ %.2f.", perDollar, lambda)
	case model.ActionQuarantine:
		return "R6 has no path to quarantine here without a hand-written exact-match rule; Phorvex chose quarantine to cut lateral recon."
	default:
		return fmt.Sprintf("R6's blind timer would DELETE this pod on schedule regardless; Phorvex skipped (best per-$ <= λ %.2f — not worth the disruption now).", lambda)
	}
}

func coverageReason(a model.Action, as killchain.Assessment, cov, ecost, perDollar, lambda float64) string {
	switch a {
	case model.ActionRotate:
		return fmt.Sprintf("rotate: invalidates in-pod recon (cov=%.2f/$%.2f=%.2f per-$ > λ=%.2f); stage=%s→%s hazard=%.2f pHold=%.2f",
			cov, ecost, perDollar, lambda, as.StageName, as.NextStageName, as.Hazard, as.PHold)
	case model.ActionQuarantine:
		return fmt.Sprintf("quarantine: cuts lateral recon (cov=%.2f/$%.2f=%.2f per-$); stage=%s→%s lateralUrg=%.2f pHold=%.2f",
			cov, ecost, perDollar, as.StageName, as.NextStageName, as.LateralUrgency, as.PHold)
	default:
		return fmt.Sprintf("noop: no net-positive feasible move (best per-$ <= λ=%.2f) stage=%s pHold=%.2f", lambda, as.StageName, as.PHold)
	}
}
