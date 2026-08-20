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

	// [P-VCLUSTER O2/O4] per-tenant cost buckets (one DualSolver λ + RLS + Conformal PER TENANT) so a
	// tenant's budget pressure / calibration NEVER re-prices another's decisions. Lazily created; the
	// FIRST (single-tenant default) bucket reuses the original `Cost` singleton → bit-identical
	// single-tenant path. No cross-tenant feed (each bucket integrates only its own tenant's evidence).
	costByTenant map[string]*cost.P1Cost
	// calibrationFrozen is the PHVX-2 off-switch, remembered so lazily-created tenant buckets
	// inherit it rather than starting to learn behind the operator's back.
	calibrationFrozen bool
}

// CalibrationState reports, per tenant, whether the RLS has left the shipped prior and how many
// observations it has folded in. Exposed for metrics (PHVX-10c) rather than added to the audit
// record: the audit output is an unversioned contract and PHVX-27 owns changes to it.
func (e *CoverageEngine) CalibrationState() map[string]struct {
	Primed  bool
	Updates int
} {
	out := map[string]struct {
		Primed  bool
		Updates int
	}{}
	for tenant, c := range e.costByTenant {
		if c == nil || c.RLS == nil {
			continue
		}
		out[tenant] = struct {
			Primed  bool
			Updates int
		}{Primed: c.RLS.Primed(), Updates: c.RLS.Updates()}
	}
	return out
}

// SetCostCalibrationFrozen applies the PHVX-2 off-switch to EVERY tenant bucket, present and future.
// Buckets are created lazily per tenant, so the flag is remembered and applied on creation too —
// otherwise a tenant first seen after the switch was thrown would quietly start learning again.
func (e *CoverageEngine) SetCostCalibrationFrozen(frozen bool) {
	if e.calibrationFrozen == frozen {
		return // idempotent: re-freezing every tick must not keep reverting theta
	}
	e.calibrationFrozen = frozen
	for _, c := range e.costByTenant {
		if c != nil && c.RLS != nil {
			c.RLS.SetFrozen(frozen)
		}
	}
}

// CostCalibrationFrozen reports the current state (audit/observability).
func (e *CoverageEngine) CostCalibrationFrozen() bool { return e.calibrationFrozen }

// costFor resolves the per-tenant cost bucket (DEFAULT-TO-OLD-SCALAR: the first tenant IS the original
// singleton; additional tenants get a fresh, identically-seeded, fully-isolated bucket).
func (e *CoverageEngine) costFor(tenant string) *cost.P1Cost {
	if e.costByTenant == nil {
		e.costByTenant = map[string]*cost.P1Cost{}
	}
	if c := e.costByTenant[tenant]; c != nil {
		return c
	}
	var c *cost.P1Cost
	if len(e.costByTenant) == 0 && e.Cost != nil {
		c = e.Cost // bit-identical single-tenant default
	} else {
		c = cost.NewP1Cost() // isolated per-tenant bucket, zero cross-feed
	}
	if c != nil && c.RLS != nil {
		c.RLS.SetFrozen(e.calibrationFrozen)
	}
	e.costByTenant[tenant] = c
	return c
}

// ObserveRotation implements RotationObserver and keeps the feedback in the same
// per-tenant bucket used to price that tenant's decisions.
func (e *CoverageEngine) ObserveRotation(tenant string, view *model.WorkloadView, measuredFlow float64) {
	e.costFor(tenant).ObserveRotation(view, measuredFlow)
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

// hasDirectFoothold reports whether an event places the attacker ON this pod (TargetsPod=true), as
// opposed to a neighbor-propagated event (TargetsPod=false). Under reactiveOnly this is what makes a
// pod actionable — so containment isolates the COMPROMISED node, not a clean neighbor of it.
func hasDirectFoothold(evs []model.SecurityEventInfo) bool {
	for i := range evs {
		if evs[i].TargetsPod {
			return true
		}
	}
	return false
}

func (e *CoverageEngine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// provFloor is the weight a FRESH, evidence-less candidate is discounted to, so a manufactured
// decoy cannot displace a genuinely-due asset from the move budget.
//
// It was inert until PHVX-72. The gate that decides whether to apply it read
// `StageUrgency > 0` — but StageUrgency = 0.5*consequence(stage) + 0.5*hazard*consequence(next)
// and consequence() floors at 0.1 for EVERY stage including its default arm, so the least urgent
// asset in the system still scores 0.05. `> 0` was therefore always true, every asset took the
// `return 1` path, and this discount had never once been applied in production. The gate now
// compares against killchain.BaselineStageUrgency (the no-evidence score, derived from the model
// rather than hardcoded) so "carries real evidence" means what it says.
//
// Defined ONCE here and used by provFn in optimality.go too — the two used to be separate local
// consts under a "KEEP IN SYNC" comment, which is how they drifted into agreeing on a broken gate.
const provFloor = 0.34

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

	tcost := e.costFor(pol.Tenant)
	costCeiling := pol.NormSparsity + pol.FlowDisruption + 0.2 // worst-case single-move budget
	deps := actionset.Deps{
		Recon:       e.Recon,
		FactContext: factCtx,
		ECost:       tcost.ECost,
		CHi:         tcost.CHi,
		CostCeiling: costCeiling,
	}
	return deps.Generate(views, pol), ctxByKey
}

// Decide runs the per-tick coverage optimization and returns one Decision per pod.
func (e *CoverageEngine) Decide(views []*model.WorkloadView, pol model.Policy) []model.Decision {
	decisions, _ := e.DecideChecked(views, pol)
	return decisions
}

// DecideChecked rejects a structurally invalid ActionSet before selection or learning.
// The runner calls this checked seam and logs/counts the failure for the production tick.
func (e *CoverageEngine) DecideChecked(views []*model.WorkloadView, pol model.Policy) ([]model.Decision, error) {
	return e.decideChecked(views, pol, true)
}

// DecideShadowChecked evaluates a counterfactual without advancing any learned production state.
func (e *CoverageEngine) DecideShadowChecked(views []*model.WorkloadView, pol model.Policy) ([]model.Decision, error) {
	return e.decideChecked(views, pol, false)
}

func (e *CoverageEngine) decideChecked(views []*model.WorkloadView, pol model.Policy, persist bool) ([]model.Decision, error) {
	now := e.now()
	tcost := e.costFor(pol.Tenant)
	lambda := tcost.Dual.Lambda()

	set, ctxByKey := e.AssembleSet(views, pol)
	if err := set.CollisionError(); err != nil {
		return nil, err
	}

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

	// [P-REDTEAM DISPERSION-STEER FIX — explicitly-gated brain change] A SELECTION-PATH defence the
	// λ-fix (a PRICE fix) does not cover: the production RL adversary discovered that a few freshly-
	// spawned, MANUFACTURED-high-coverage DECOYS out-gain a genuinely-due real foothold and crowd it
	// out of the B-move budget (the foothold is never SELECTED, so never rotated — zero detector
	// signal). The fix weights a candidate's SELECTION gain by a PROVENANCE factor a decoy cannot
	// manufacture: a GENUINE threat — overdue for the hygiene floor (aged exposure ≥ proactiveFloor)
	// OR carrying real kill-chain evidence (StageUrgency>0, i.e. real recon/events) — keeps prov=1 so
	// its gain (and the SELECTION) is BYTE-IDENTICAL. A FRESH, evidence-less candidate (a manufactured
	// decoy) is down-weighted toward provFloor, so it can no longer displace a real asset from the
	// slot. The reported coverage/marginal is the UN-discounted value (reporting unchanged). NO
	// learning enters Decide — prov is a deterministic function of the real exposure/assessment.
	floorSec := pol.ProactiveFloor.Seconds()
	prov := func(key string) float64 {
		if floorSec <= 0 {
			return 1
		}
		ac := ctxByKey[key]
		if ac.exposure >= floorSec || ac.assess.HasEvidence {
			return 1 // genuinely due, or backed by real recon/event evidence => full weight (legit path unchanged)
		}
		r := ac.exposure / floorSec
		if r < 0 {
			r = 0
		}
		return provFloor + (1-provFloor)*r // a fresh, evidence-less decoy competes at <= provFloor
	}

	// [reactiveOnly] When the policy is reactive-only, an asset is actionable ONLY while a REAL
	// attack signal places the attacker ON it — a DIRECT foothold (a non-Phorvex SecurityEvent with
	// TargetsPod=true; Phorvex's own events are already filtered at ingest) OR an AI poison marker
	// (SuspectAdapter). A pod that merely NEIGHBORS a compromised node (only propagated
	// TargetsPod=false events) is NOT contained: isolating a clean neighbor degrades availability
	// without evicting or containing the real intruder, so the reactive containment must land on the
	// COMPROMISED node itself. Proactive, exposure-only moves are suppressed, so the workload stays
	// CALM until attacked. The map is ALL-TRUE when reactiveOnly=false, so every gate below is a
	// no-op and the default (proactive) path stays byte-identical.
	attackBackedKey := make(map[string]bool, len(views))
	for _, v := range views {
		backed := true
		if pol.ReactiveOnly {
			backed = v.Pod.SuspectAdapter != "" || hasDirectFoothold(v.Events)
		}
		attackBackedKey[v.Pod.Namespace+"/"+v.Pod.Name] = backed
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
			if !attackBackedKey[c.Key] {
				continue // reactiveOnly: suppress proactive moves on un-attacked assets
			}
			marginal := 0.0
			for _, k := range c.CoverKeys {
				if !covered[k] {
					marginal += set.FactWeights[k]
				}
			}
			gain := marginal*prov(c.Key) - lambda*c.ECost
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
	for key, idxs := range candsByAsset {
		if !attackBackedKey[key] {
			continue // reactiveOnly: un-attacked assets create no proactive demand
		}
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
		} else if len(idxs) > 0 && attackBackedKey[key] {
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

		// Blind-timer cost: R6 fires a rotate on a fixed cadence REGARDLESS of value OR
		// feasibility. We price it from the cost model DIRECTLY (not from the feasible candidate
		// set) because a gate — statefulIntegrity on a stateful pod, or an SLO veto — REMOVES
		// rotate from the candidate set, yet the blind timer rotates anyway. Reading the candidate
		// set there yielded 0 (no rotate candidate => "blind costs nothing"), which is exactly
		// backwards: the blind rotate it CANNOT safely take is the most expensive of all.
		blindCost := e.Cost.ECost(v, model.Move{Action: model.ActionRotate}, pol)
		if v.Pod.Stateful {
			// A blind rotate DELETES this stateful pod and its persistent state — a total,
			// irrecoverable loss: maximum disruption (1.0 on the normalized cost scale). This is
			// the stark contrast against Phorvex's state-preserving quarantine, which the
			// statefulIntegrity gate steered it to instead.
			blindCost = 1.0
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
			Tenant:                pol.Tenant,
			Namespace:             v.Pod.Namespace,
			Pod:                   v.Pod.Name,
			Node:                  v.Pod.Node,
			CoverageValue:         cov, // recon-fact value at stake
			Cost:                  ecost,
			Net:                   net,
			AssetValue:            ac.sig.AssetValue,
			ThreatPosture:         ac.sig.ThreatPosture,
			Exposure:              ac.sig.Exposure,
			BlastRadius:           v.BlastRadius,
			SLOHeadroom:           ac.sig.SLOHeadroom,
			Phase:                 v.Phase,
			Action:                action,
			Selected:              selected,
			Feasible:              feasible,
			InfeasibleWhy:         infeasibleWhy,
			Reason:                coverageReason(action, ac.assess, cov, ecost, perDollar, lambda),
			R6Counterfactual:      model.ActionRotate,
			CounterfactualNote:    counterfactualNote(action, v, perDollar, lambda),
			BlindCost:             blindCost,
			DryRun:                pol.DryRun,
			DecidedAt:             now,
			Engine:                "p1-coverage",
			CoveredWeight:         marginal,
			CoveredFacts:          coveredFacts,
			PerDollar:             perDollar,
			Stage:                 ac.assess.StageName,
			StageHazard:           ac.assess.Hazard,
			NextStage:             ac.assess.NextStageName,
			PHold:                 ac.assess.PHold,
			Lambda:                lambda,
			ProactiveRate:         rate,
			Attribution:           attribution,
			PreemptMargin:         ac.assess.PreemptMargin,
			ProjectedNextStageSec: ac.assess.ProjectedNextStageSec,
			AIClassified:          ac.assess.AIClassified,
		})
	}

	if persist {
		// --- persist stateful learning (dual price + conjugate memory) ---
		tcost.Dual.Step(demand, len(selectedAsset), B)
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
	}

	return decisions, nil
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
	// DETERMINISM: byKind is a map, so terms enter in random order. Sorting on Contribution alone
	// did NOT fix that — sort.Slice is unstable, and ties are the common case (every cover term is
	// 0.0 on a low-risk pod), so the random map order survived. The audit record was therefore not
	// byte-stable: replaying the SAME views produced a different attribution ordering every run, so
	// two audit logs of identical decisions could not be hashed or diffed. Measured on live
	// phorvex-dev-eks views (69 pods): 5 replays gave 5 distinct record hashes as-is, and one
	// identical hash once Source breaks the tie. Keep Source as the tiebreak.
	sort.Slice(terms, func(i, j int) bool {
		if terms[i].Contribution != terms[j].Contribution {
			return terms[i].Contribution > terms[j].Contribution
		}
		return terms[i].Source < terms[j].Source
	})
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
	case model.ActionNoop:
		return fmt.Sprintf("R6's blind timer would DELETE this pod on schedule regardless; Phorvex skipped (best per-$ <= λ %.2f — not worth the disruption now).", lambda)
	default:
		// [HONEST-LABEL FIX] An AI-native move was previously narrated as "Phorvex skipped" — the
		// exact opposite of what happened. R6 has no non-destructive equivalent at all.
		return fmt.Sprintf("R6's blind timer would DELETE this pod on schedule; Phorvex used %s instead — the workload keeps serving (R6 has no non-destructive equivalent).", a)
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
	case model.ActionNoop:
		return fmt.Sprintf("noop: no net-positive feasible move (best per-$ <= λ=%.2f) stage=%s pHold=%.2f", lambda, as.StageName, as.PHold)
	default:
		// [HONEST-LABEL FIX] Every AI-native move (kv-reset, adapter-rotate, warm-swap, …) used to
		// fall through to the noop text above, so a GENUINELY SELECTED move was audited as
		// "noop: no net-positive feasible move" — the decision was real, the label was a lie, and it
		// made the operator/dashboard read a live defence as an inaction.
		return fmt.Sprintf("%s: selected (cov=%.2f/$%.2f=%.2f per-$ > λ=%.2f); stage=%s→%s hazard=%.2f pHold=%.2f",
			a, cov, ecost, perDollar, lambda, as.StageName, as.NextStageName, as.Hazard, as.PHold)
	}
}
