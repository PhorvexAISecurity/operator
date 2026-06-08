/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

// Package decision is the BRAIN (PRD §5.3 / FR4): each tick it scores every
// protected pod's risk (physics residual + context + belief), prices each move
// (cost model), vetoes infeasible moves (feasibility), and selects the top-B moves
// that maximize Σ(Risk − λ·Cost) subject to the move budget, the anti-over-rotation
// window, and SLO/availability. It is PURE (no Kubernetes) so it is fully unit-
// testable; the controller assembles WorkloadViews and the actuator applies the
// result. P0 ships the MVP's explicit greedy top-B selection (the PRD's stated MVP
// form), not yet the offline mixed-strategy game solver.
package decision

import (
	"fmt"
	"sort"
	"time"

	"github.com/phorvex/phorvex/internal/belief"
	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/ctxprov"
	"github.com/phorvex/phorvex/internal/feasibility"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/physics"
)

// Risk-blend weights (FLAGGED design proposals; they sum to 1.0). residual +
// posture + exposure + belief. They are NOT paper values.
const (
	wResidual = 0.35
	wPosture  = 0.25
	wExposure = 0.20
	wBelief   = 0.20
)

// Action-specific SECURITY BENEFIT factors (FLAGGED proposals). A rotate (Delete)
// WIPES the foothold => full risk reduction (factor 1.0). A quarantine only CONTAINS
// (freezes the pod, preserves state + forensics, cuts lateral movement) => partial
// reduction that RISES with blast radius — so the high-blast pod is the one Phorvex
// prefers to quarantine, while a cheap low-blast pod is rotated. This is what makes
// the selection match the PRD intent rather than always picking the cheapest move.
const (
	quarantineBase  = 0.5
	quarantineBlast = 0.5
)

// actionBenefit returns the security value of an action given the base risk and the
// pod's blast radius.
func actionBenefit(a model.Action, risk, blast float64) float64 {
	switch a {
	case model.ActionRotate:
		return risk
	case model.ActionQuarantine:
		return risk * (quarantineBase + quarantineBlast*clamp01d(blast))
	default:
		return 0
	}
}

// Engine is the decision brain with its swappable providers resolved from the
// registries (overridable for tests).
type Engine struct {
	Physics  physics.PhysicsProfile
	Cost     cost.CostModel
	Belief   belief.BeliefEstimator
	Context  ctxprov.ContextProvider
	// Now lets tests pin the decision time; nil uses time.Now.
	Now func() time.Time
}

// NewEngine builds an Engine from the registered defaults. It panics only if a
// registry is empty, which is impossible at runtime (the default impls self-register
// via init) but surfaces a wiring bug loudly in a test that blanks a registry.
func NewEngine() *Engine {
	e := &Engine{}
	if p, ok := physics.Registry.Default(); ok {
		e.Physics = p
	}
	if c, ok := cost.Registry.Default(); ok {
		e.Cost = c
	}
	if b, ok := belief.Registry.Default(); ok {
		e.Belief = b
	}
	if cp, ok := ctxprov.Registry.Default(); ok {
		e.Context = cp
	}
	return e
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// candidateActions returns the enabled mutating actions to evaluate, in a stable order.
// It iterates model.MutatingActions (the SAME source of truth as actionset.enabledActions)
// so the emit and candidate lists provably cannot drift; model.ActionEnabled keeps a nil
// policy at the historical {rotate,quarantine} default (byte-identical decisions).
func candidateActions(pol model.Policy) []model.Action {
	var out []model.Action
	for _, a := range model.MutatingActions {
		if model.ActionEnabled(pol, a) {
			out = append(out, a)
		}
	}
	return out
}

// Decide scores all views and returns one Decision per pod. At most
// pol.MaxMovesPerTick decisions are marked Selected (the top-B by net benefit among
// feasible, net-positive moves). Every Decision also carries the R6 counterfactual.
func (e *Engine) Decide(views []*model.WorkloadView, pol model.Policy) []model.Decision {
	now := e.now()
	decisions := make([]model.Decision, 0, len(views))

	for _, v := range views {
		residual := 0.0
		if e.Physics != nil {
			residual = e.Physics.Residual(v, pol)
		}
		var sig model.ContextSignals
		if e.Context != nil {
			sig = e.Context.Context(v, pol)
		}
		bel := 0.0
		if e.Belief != nil {
			bel = e.Belief.Belief(v, pol)
		}

		baseRisk := clamp01d(wResidual*residual + wPosture*sig.ThreatPosture + wExposure*sig.Exposure + wBelief*bel)
		assetScale := 1.0 + sig.AssetValue // high-value/high-blast pods weigh more
		risk := baseRisk * assetScale

		// Price + vet each candidate action; pick the feasible one with the best net.
		bestAction := model.ActionNoop
		bestNet := 0.0
		bestCost := 0.0
		feasibleChosen := true
		infeasibleWhy := ""
		// Track the best INFEASIBLE candidate too, to explain why nothing was chosen.
		blockedReason := ""
		for _, a := range candidateActions(pol) {
			move := model.Move{Action: a}
			c := 0.0
			if e.Cost != nil {
				c = e.Cost.Switching(v, move, pol)
			}
			net := actionBenefit(a, risk, v.BlastRadius) - pol.Lambda*c
			verdict := feasibility.Evaluate(v, move, pol)
			if !verdict.Feasible {
				if blockedReason == "" {
					blockedReason = fmt.Sprintf("%s blocked: %s", a, verdict.Reason)
				}
				continue
			}
			if net > bestNet {
				bestNet = net
				bestAction = a
				bestCost = c
			}
		}
		if bestAction == model.ActionNoop {
			feasibleChosen = false
			infeasibleWhy = blockedReason
		}

		reason := explain(bestAction, residual, sig, bel, v.BlastRadius)

		decisions = append(decisions, model.Decision{
			Tenant:           pol.Tenant,
			Namespace:        v.Pod.Namespace,
			Pod:              v.Pod.Name,
			Node:             v.Pod.Node,
			Risk:             risk,
			Cost:             bestCost,
			Net:              bestNet,
			AssetValue:       sig.AssetValue,
			Residual:         residual,
			ThreatPosture:    sig.ThreatPosture,
			Exposure:         sig.Exposure,
			Belief:           bel,
			BlastRadius:      v.BlastRadius,
			SLOHeadroom:      sig.SLOHeadroom,
			Phase:            v.Phase,
			Action:           bestAction,
			Selected:         false, // set in the budgeted selection pass below
			Feasible:         feasibleChosen,
			InfeasibleWhy:    infeasibleWhy,
			Reason:             reason,
			R6Counterfactual:   r6Counterfactual(v),
			CounterfactualNote: "R6's blind timer would rotate this pod on schedule; Phorvex (p0-greedy) chose " + string(bestAction),
			Engine:             "p0-greedy",
			DryRun:           pol.DryRun,
			DecidedAt:        now,
		})
	}

	selectTopB(decisions, pol.MaxMovesPerTick, now)
	return decisions
}

// selectTopB marks at most B net-positive, mutating decisions as Selected, choosing
// the highest net benefit first (greedy top-B; PRD's MVP selection).
func selectTopB(decisions []model.Decision, b int, now time.Time) {
	if b <= 0 {
		return
	}
	idx := make([]int, 0, len(decisions))
	for i := range decisions {
		if decisions[i].Action != model.ActionNoop && decisions[i].Feasible && decisions[i].Net > 0 {
			idx = append(idx, i)
		}
	}
	sort.SliceStable(idx, func(x, y int) bool {
		return decisions[idx[x]].Net > decisions[idx[y]].Net
	})
	for n, i := range idx {
		if n >= b {
			break
		}
		decisions[i].Selected = true
	}
}

// r6Counterfactual returns what R6's blind machinery would do to this pod: its
// proactive time-based-trigger eventually ROTATES (Delete) every covered pod on
// schedule — with no cost, no SLO, no stateful awareness. This is the column that
// makes Phorvex's "don't rotate the stateful/expensive pod" decision legible.
func r6Counterfactual(_ *model.WorkloadView) model.Action {
	return model.ActionRotate
}

func explain(a model.Action, residual float64, sig model.ContextSignals, bel, blast float64) string {
	switch a {
	case model.ActionRotate:
		return fmt.Sprintf("rotate: risk(resid=%.2f,posture=%.2f,exposure=%.2f,belief=%.2f) high & cost low; asset=%.2f blast=%.2f",
			residual, sig.ThreatPosture, sig.Exposure, bel, sig.AssetValue, blast)
	case model.ActionQuarantine:
		return fmt.Sprintf("quarantine: contain (high blast=%.2f / stateful-or-costly to rotate); posture=%.2f belief=%.2f",
			blast, sig.ThreatPosture, bel)
	default:
		return fmt.Sprintf("noop: net<=0 or infeasible (resid=%.2f,posture=%.2f,exposure=%.2f,belief=%.2f,asset=%.2f)",
			residual, sig.ThreatPosture, sig.Exposure, bel, sig.AssetValue)
	}
}

func clamp01d(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}
