/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 */

package decision

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/ctxprov"
	"github.com/phorvex/phorvex/internal/killchain"
	"github.com/phorvex/phorvex/internal/metrics"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

// CoverageEngine is the P1 brain: it maximizes consequence-weighted recon-fact
// invalidation — marginal*provenance − lambdaRuntimeLegacy*ECost — by a submodular greedy
// over the DYNAMICALLY GENERATED feasible action set, under a per-asset (one move)
// partition constraint and the unit-count move budget B. The legacy lambda update
// observes move-count pressure but multiplies a weighted disruption score, so it is
// not certified as an exact dual. It is STATEFUL across ticks (RLS cost, runtime
// lambda controller, and conjugate memory persist).
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

// costFor resolves the per-tenant cost bucket. An optional lambda seed is consumed only
// when the bucket is first created; later calls preserve the legacy runtime state.
func (e *CoverageEngine) costFor(tenant string, lambdaSeed ...float64) *cost.P1Cost {
	if e.costByTenant == nil {
		e.costByTenant = map[string]*cost.P1Cost{}
	}
	if c := e.costByTenant[tenant]; c != nil {
		return c
	}
	seed := cost.DefaultLambdaSeed
	if len(lambdaSeed) > 0 {
		seed = lambdaSeed[0]
	}
	var c *cost.P1Cost
	if len(e.costByTenant) == 0 && e.Cost != nil {
		c = e.Cost
		c.Dual = cost.NewDualSolverWithSeed(seed)
	} else {
		c = cost.NewP1CostWithLambda(seed) // isolated per-tenant bucket, zero cross-feed
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

// strictPositiveGain is the exact production act/skip boundary. There is no
// epsilon and equality does not pass.
func strictPositiveGain(gain float64) bool { return gain > 0 }

func legacyMixedGain(marginal, provenance, lambdaRuntimeLegacy, expectedCost float64) float64 {
	return marginal*provenance - lambdaRuntimeLegacy*expectedCost
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

	tcost := e.costFor(pol.Tenant, pol.Lambda)
	costCeiling := cost.EffectiveCostCeiling(pol)
	deps := actionset.Deps{
		Recon:       e.Recon,
		FactContext: factCtx,
		ECost:       tcost.ECost,
		CHi:         tcost.CHi,
		Evaluate: func(view *model.WorkloadView, move model.Move, policy model.Policy) (float64, float64, string, string) {
			eval := tcost.Evaluation(view, move, policy)
			return eval.Total, eval.CHi, eval.UnactionableCategory, eval.NaNFeature
		},
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
	tcost := e.costFor(pol.Tenant, pol.Lambda)
	lambda := tcost.Dual.Lambda()

	set, ctxByKey := e.AssembleSet(views, pol)
	if err := set.CollisionError(); err != nil {
		return nil, err
	}
	if persist {
		for _, ex := range set.Excluded {
			if ex.Category != cost.UnactionableNaNCategory {
				continue
			}
			namespace, pod, _ := strings.Cut(ex.Key, "/")
			metrics.RecordCostNaNUnactionable(pol.Tenant, namespace, pod, string(ex.Action), ex.Detail)
		}
	}

	candsByAsset := map[string][]int{}
	for i := range set.Candidates {
		candsByAsset[set.Candidates[i].Key] = append(candsByAsset[set.Candidates[i].Key], i)
	}
	excludedWhy := map[string]string{}
	for _, ex := range set.Excluded {
		if _, ok := excludedWhy[ex.Key]; !ok || ex.Category == cost.UnactionableNaNCategory {
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
	selectedRound := map[string]int{}
	evaluatedMarginal := map[string]float64{}
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
			candidateKey := traceCandidateKey(c.Key, c.Action)
			evaluatedMarginal[candidateKey] = marginal
			gain := legacyMixedGain(marginal, prov(c.Key), lambda, c.ECost)
			if gain > bestGain {
				bestGain = gain
				bestIdx = i
				bestMarginal = marginal
			}
		}
		if bestIdx < 0 || !strictPositiveGain(bestGain) {
			break
		}
		c := set.Candidates[bestIdx]
		selectedAsset[c.Key] = true
		selectedAction[c.Key] = c.Action
		selectedMarginal[c.Key] = bestMarginal
		selectedRound[c.Key] = round + 1
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
	dualUpdate := tcost.Dual.PreviewStep(demand, len(selectedAsset), B)
	dualUpdate.Applied = persist

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

		// Legacy reporting-only ratio. This does not select actions; production selection
		// uses the strict positive-gain comparator recorded in DecisionTraceV2.
		rate := 0.0
		if perDollar > lambda {
			rate = perDollar - lambda
		}

		selected := selectedAsset[key]
		net := cov - lambda*ecost
		selectionGain := legacyMixedGain(marginal, prov(key), lambda, ecost)

		decision := model.Decision{
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
			Reason:                coverageReason(action, selected, ac.assess, cov, ecost, selectionGain, lambda),
			R6Counterfactual:      model.ActionRotate,
			CounterfactualNote:    counterfactualNote(action, v),
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
		}
		if pol.TraceEnabled {
			decision.Trace = e.buildDecisionTrace(v, pol, now, set, ac, lambda, demand,
				len(selectedAsset), selectedAsset[key], selectedAction[key], selectedRound[key],
				attackBackedKey[key], infeasibleWhy, tcost.RLS != nil && tcost.RLS.Primed(), prov,
				tcost, evaluatedMarginal, dualUpdate)
		}
		decisions = append(decisions, decision)
	}

	if persist {
		// --- persist stateful learning (legacy lambda controller + conjugate memory) ---
		actualUpdate := tcost.Dual.StepDetailed(demand, len(selectedAsset), B)
		for i := range decisions {
			if decisions[i].Trace != nil {
				decisions[i].Trace.DualUpdate = traceDualUpdate(actualUpdate)
			}
		}
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

func traceOptional(present bool, value float64) model.OptionalFloat {
	return model.OptionalFloat{Present: present, Value: value}
}

func traceStringOrUnavailable(value string) string {
	if value == "" {
		return model.TraceNotAvailable
	}
	return value
}

func decisionTraceID(parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte(part))
		_, _ = h.Write([]byte{0})
	}
	return fmt.Sprintf("%x", h.Sum(nil)[:16])
}

func traceCandidateKey(asset string, action model.Action) string {
	return asset + "|" + string(action)
}

func traceDualUpdate(update cost.DualUpdate) model.DecisionDualUpdateV2 {
	return model.DecisionDualUpdateV2{
		Applied:         update.Applied,
		Demand:          update.Demand,
		Spent:           update.Spent,
		Budget:          update.Budget,
		RawExcess:       update.RawExcess,
		EffectiveExcess: update.EffectiveExcess,
		LambdaBefore:    update.LambdaBefore,
		LambdaAfter:     update.LambdaAfter,
		UpdateReason:    update.UpdateReason,
	}
}

// buildDecisionTrace runs only after the current optimizer has completed its
// selection. It reads the already-generated ActionSet and cannot affect scoring,
// eligibility, feasibility, learning or tie-breaking.
func (e *CoverageEngine) buildDecisionTrace(
	v *model.WorkloadView,
	pol model.Policy,
	now time.Time,
	set actionset.ActionSet,
	ac assetCtx,
	lambda float64,
	demand int,
	movesSpent int,
	selected bool,
	selectedAction model.Action,
	selectionRound int,
	attackBacked bool,
	infeasibleWhy string,
	primed bool,
	prov func(string) float64,
	tcost *cost.P1Cost,
	evaluatedMarginal map[string]float64,
	dualUpdate cost.DualUpdate,
) *model.DecisionTraceV2 {
	assetKey := v.Pod.Namespace + "/" + v.Pod.Name
	tickID := pol.TickID
	if tickID == "" {
		tickID = decisionTraceID("tick", now.UTC().Format(time.RFC3339Nano), pol.PolicyUID, pol.Tenant)
	}
	trace := &model.DecisionTraceV2{
		SchemaVersion:             model.DecisionTraceSchemaV2,
		DecisionID:                decisionTraceID("decision", tickID, traceStringOrUnavailable(v.Pod.UID), assetKey),
		TickID:                    tickID,
		Timestamp:                 now.UTC().Format(time.RFC3339Nano),
		BrainImage:                traceStringOrUnavailable(pol.BrainImage),
		GitSHA:                    traceStringOrUnavailable(pol.GitSHA),
		DecisionEngine:            e.Name(),
		PolicyNamespace:           pol.Namespace,
		PolicyName:                traceStringOrUnavailable(pol.PolicyName),
		PolicyUID:                 traceStringOrUnavailable(pol.PolicyUID),
		TenantName:                pol.Tenant,
		AssetNamespace:            v.Pod.Namespace,
		AssetName:                 v.Pod.Name,
		AssetUID:                  traceStringOrUnavailable(v.Pod.UID),
		Budget:                    pol.MaxMovesPerTick,
		CandidateDemand:           demand,
		MovesSpent:                movesSpent,
		DryRun:                    pol.DryRun,
		LambdaConfiguredSeed:      pol.Lambda,
		LambdaRuntime:             lambda,
		LambdaConfiguredPolicy:    pol.Lambda,
		LambdaRuntimeLegacy:       lambda,
		SelectorComparator:        model.SelectorStrictPositiveGain,
		NormWeight:                pol.NormSparsity,
		FlowWeight:                pol.FlowDisruption,
		CFlowUnitStatus:           model.CFlowUnitDimensionlessDisruptionLoss,
		CostRepresentationVersion: model.CostRepresentationWeightedDimensionlessV1,
		DualUpdate:                traceDualUpdate(dualUpdate),
		SelectedAction:            string(model.ActionNoop),
		TieBreakReason:            "notApplicable",
	}

	telemetryPresent := func(signal string) bool {
		return v.Telemetry.PresentSignals != nil && v.Telemetry.PresentSignals[signal]
	}
	exposure, exposurePresent := v.ExposureByVariable[model.VarPodIdentity]
	dispersionPresent := e.Recon != nil && e.Recon.Name() == "ucw-recon"
	trace.Inputs = model.DecisionModelInputsV2{
		Phase:             string(v.Phase),
		RequestRate:       traceOptional(telemetryPresent("reqRate"), v.Telemetry.ReqRate),
		ConnectionCount:   traceOptional(telemetryPresent("connCount"), v.Telemetry.ConnCount),
		GPUUtilization:    traceOptional(telemetryPresent("gpuUtil"), v.Telemetry.GPUUtil),
		SMOccupancy:       traceOptional(v.Physics.SMSource != "", v.Physics.SMOccupancy),
		VRAMFraction:      traceOptional(v.Physics.VRAMPresent, v.Physics.VRAMFraction),
		ImageRarity:       traceOptional(v.Physics.ImageRarityPresent, v.Physics.ImageRarity),
		ModelRarity:       traceOptional(v.Physics.ModelRarityPresent, v.Physics.ModelRarity),
		CoResidency:       traceOptional(v.Physics.CoResidencyPresent, v.Physics.CoResidency),
		EPSS:              traceOptional(v.Physics.EPSSPresent, v.Physics.EPSS),
		CVSS:              traceOptional(v.Physics.EPSSPresent, v.Physics.CVSS),
		EPSSBasis:         v.Physics.EPSSBasis,
		EPSSCachedDigest:  v.Physics.EPSSCachedDigest,
		EPSSRunningDigest: v.Pod.ImageID,
		EPSSScanTS:        v.Physics.EPSSScanTS,
		PhysicsScanned:    v.Physics.Scanned,
		DispersionMult:    traceOptional(dispersionPresent, recon.DispersionMultiplier(v)),
		DispersionCap:     traceOptional(v.Physics.DispersionCap > 0, v.Physics.DispersionCap),
		Primed:            primed,
		BetaMean:          traceOptional(true, e.Killchain.Memory.PriorMean(pol.Tenant)),
		PHold:             traceOptional(true, ac.assess.PHold),
		Stage:             ac.assess.StageName,
		StageHazard:       traceOptional(true, ac.assess.Hazard),
		StageUrgency:      traceOptional(true, ac.assess.StageUrgency),
		ThreatPosture:     traceOptional(true, ac.sig.ThreatPosture),
		ExposureVariable:  model.VarPodIdentity,
		ExposureSeconds:   traceOptional(exposurePresent, exposure.Seconds()),
		ProactiveFloorSec: pol.ProactiveFloor.Seconds(),
		AntiOverRotateSec: pol.AntiOverRotationWindow.Seconds(),
	}

	source := model.TraceNotAvailable
	if e.Recon != nil {
		source = e.Recon.Name()
	}
	for _, fact := range set.FactsByAsset[assetKey] {
		weight, presented := set.FactWeights[fact.Key()]
		if !presented {
			continue
		}
		trace.Facts = append(trace.Facts, model.DecisionFactV2{
			FactKey:               fact.Key(),
			FactType:              fact.Kind,
			FinalWeight:           weight,
			CoveredBeforeDecision: false,
			SourceComponent:       source,
			AssetValue:            traceOptional(true, ac.sig.AssetValue),
			// The current recon API exposes only the final weight and its
			// conditioning inputs, not a stable per-fact term decomposition.
			PHoldContribution:      model.OptionalFloat{Present: false},
			UrgencyContribution:    model.OptionalFloat{Present: false},
			DispersionContribution: model.OptionalFloat{Present: false},
			RelativeWeight:         model.OptionalFloat{Present: false},
		})
	}

	selectedCandidateKey := ""
	tieBreakRank := 0
	for _, candidate := range set.Candidates {
		if candidate.Key != assetKey {
			continue
		}
		grossFull := 0.0
		for _, factKey := range candidate.CoverKeys {
			grossFull += set.FactWeights[factKey]
		}
		key := traceCandidateKey(assetKey, candidate.Action)
		marginal, wasEvaluated := evaluatedMarginal[key]
		provenance := prov(assetKey)
		components := tcost.Components(v, model.Move{Action: candidate.Action}, pol)
		lambdaContribution := lambda * candidate.ECost
		netGain := legacyMixedGain(marginal, provenance, lambda, candidate.ECost)
		candidateSelected := selected && candidate.Action == selectedAction
		if candidateSelected {
			selectedCandidateKey = key
		}
		selectionReason := "not_selected_by_current_greedy_ranking"
		switch {
		case candidateSelected:
			selectionReason = "selected_strict_positive_gain"
		case !attackBacked:
			selectionReason = "reactive_only_no_direct_foothold"
		case selected:
			selectionReason = "partition_other_action_selected"
		case !wasEvaluated && pol.MaxMovesPerTick <= 0:
			selectionReason = "move_budget_exhausted"
		case !wasEvaluated:
			selectionReason = "not_evaluated_by_current_greedy"
		case !strictPositiveGain(netGain):
			selectionReason = "strict_gain_not_positive"
		case movesSpent >= pol.MaxMovesPerTick:
			selectionReason = "move_budget_exhausted"
		}
		trace.Candidates = append(trace.Candidates, model.DecisionCandidateV2{
			Action:                      string(candidate.Action),
			CandidateKey:                key,
			CoverKeys:                   append([]string(nil), candidate.CoverKeys...),
			TieBreakRank:                tieBreakRank,
			GrossFullValue:              traceOptional(true, grossFull),
			MarginalCoverage:            traceOptional(wasEvaluated, marginal),
			Provenance:                  traceOptional(true, provenance),
			CNorm:                       traceOptional(true, components.Norm),
			CFlow:                       traceOptional(true, components.Flow),
			ExpectedCost:                traceOptional(true, candidate.ECost),
			CostHigh:                    traceOptional(true, candidate.CHi),
			LambdaContribution:          traceOptional(true, lambdaContribution),
			NetGain:                     traceOptional(wasEvaluated, netGain),
			Feasible:                    model.OptionalBool{Present: true, Value: true},
			Selected:                    candidateSelected,
			SelectionReason:             selectionReason,
			NotClassifiedByCurrentModel: true,
		})
		tieBreakRank++
	}
	for _, exclusion := range set.Excluded {
		if exclusion.Key != assetKey {
			continue
		}
		grossFull := 0.0
		for _, factKey := range exclusion.CoverKeys {
			grossFull += set.FactWeights[factKey]
		}
		candidate := model.DecisionCandidateV2{
			Action:                      string(exclusion.Action),
			CandidateKey:                traceCandidateKey(assetKey, exclusion.Action),
			CoverKeys:                   append([]string(nil), exclusion.CoverKeys...),
			TieBreakRank:                -1,
			GrossFullValue:              traceOptional(true, grossFull),
			Provenance:                  traceOptional(true, prov(assetKey)),
			Feasible:                    model.OptionalBool{Present: exclusion.FeasibilityEvaluated, Value: exclusion.Feasible},
			ExistingExclusionReason:     exclusion.Reason,
			SelectionReason:             "existing_generator_exclusion",
			NotClassifiedByCurrentModel: true,
		}
		if exclusion.CostEvaluated {
			candidate.ExpectedCost = traceOptional(true, exclusion.ECost)
			candidate.CostHigh = traceOptional(true, exclusion.CHi)
			candidate.LambdaContribution = traceOptional(true, lambda*exclusion.ECost)
			evaluation := tcost.Evaluation(v, model.Move{Action: exclusion.Action}, pol)
			if evaluation.UnactionableCategory == "" {
				candidate.CNorm = traceOptional(true, evaluation.Norm)
				candidate.CFlow = traceOptional(true, evaluation.Flow)
			}
		}
		trace.Candidates = append(trace.Candidates, candidate)
	}

	if selected {
		trace.SelectedAction = string(selectedAction)
		trace.SelectedCandidateKey = selectedCandidateKey
		trace.SelectionRound = model.OptionalInt{Present: true, Value: selectionRound}
		trace.TieBreakReason = "strict-greater gain; lower recorded tieBreakRank wins an equal gain"
	} else {
		switch {
		case !attackBacked:
			trace.NoopReason = "reactive-only: no direct foothold"
		case len(trace.Candidates) == 0:
			trace.NoopReason = "no candidate generated"
		case infeasibleWhy != "":
			trace.NoopReason = infeasibleWhy
		default:
			positive := false
			for _, candidate := range trace.Candidates {
				if candidate.NetGain.Present && candidate.NetGain.Value > 0 {
					positive = true
					break
				}
			}
			if !positive {
				trace.NoopReason = "priced-out: no net-positive feasible move"
			} else if pol.MaxMovesPerTick <= 0 || movesSpent >= pol.MaxMovesPerTick {
				trace.NoopReason = "budget-exhausted"
			} else {
				trace.NoopReason = "not selected by current greedy round"
			}
		}
	}
	return trace
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

// factKind extracts the kind segment from a scope-prefixed fact key
// "scope|asset|kind[|edge]". The legacy branch is retained for synthetic benchmark fixtures whose
// arbitrary keys predate the taxonomy; production recon keys always take the scoped branch.
func factKind(key string) string {
	parts := strings.Split(key, "|")
	if len(parts) >= 3 {
		switch recon.FactScope(parts[0]) {
		case recon.ScopePod, recon.ScopeNode, recon.ScopeModel, recon.ScopeService:
			return parts[2]
		}
	}
	if len(parts) >= 2 {
		return parts[1]
	}
	return key
}

// counterfactualNote explains, per decision, how Phorvex's choice diverges from R6's
// blind machinery (whose time-based-trigger would Delete every covered pod on schedule
// with no cost/value/stateful awareness).
func counterfactualNote(a model.Action, v *model.WorkloadView) string {
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
		return "R6 would rotate too, but on a blind fixed timer; Phorvex selected rotate with a strict positive marginal-value-minus-cost score."
	case model.ActionQuarantine:
		return "R6 has no path to quarantine here without a hand-written exact-match rule; Phorvex chose quarantine to cut lateral recon."
	case model.ActionNoop:
		return "R6's blind timer would DELETE this pod on schedule regardless; Phorvex skipped because no feasible candidate won the strict positive-gain selector."
	default:
		// [HONEST-LABEL FIX] An AI-native move was previously narrated as "Phorvex skipped" — the
		// exact opposite of what happened. R6 has no non-destructive equivalent at all.
		return fmt.Sprintf("R6's blind timer would DELETE this pod on schedule; Phorvex used %s instead — the workload keeps serving (R6 has no non-destructive equivalent).", a)
	}
}

func coverageReason(a model.Action, selected bool, as killchain.Assessment, cov, ecost, gain, lambda float64) string {
	if !selected && a != model.ActionNoop {
		return fmt.Sprintf("%s not selected by the current greedy/budget result (reported gain=%.2f fullValue=%.2f ECost=%.2f lambdaRuntimeLegacy=%.2f); stage=%s pHold=%.2f",
			a, gain, cov, ecost, lambda, as.StageName, as.PHold)
	}
	switch a {
	case model.ActionRotate:
		return fmt.Sprintf("rotate: strict gain %.2f > 0 (fullValue=%.2f ECost=%.2f lambdaRuntimeLegacy=%.2f); stage=%s→%s hazard=%.2f pHold=%.2f",
			gain, cov, ecost, lambda, as.StageName, as.NextStageName, as.Hazard, as.PHold)
	case model.ActionQuarantine:
		return fmt.Sprintf("quarantine: strict gain %.2f > 0 (fullValue=%.2f ECost=%.2f lambdaRuntimeLegacy=%.2f); stage=%s→%s lateralUrg=%.2f pHold=%.2f",
			gain, cov, ecost, lambda, as.StageName, as.NextStageName, as.LateralUrgency, as.PHold)
	case model.ActionNoop:
		return fmt.Sprintf("noop: no candidate won strict gain > 0 (reported gain=%.2f lambdaRuntimeLegacy=%.2f) stage=%s pHold=%.2f", gain, lambda, as.StageName, as.PHold)
	default:
		// [HONEST-LABEL FIX] Every AI-native move (kv-reset, adapter-rotate, warm-swap, …) used to
		// fall through to the noop text above, so a GENUINELY SELECTED move was audited as
		// "noop: no net-positive feasible move" — the decision was real, the label was a lie, and it
		// made the operator/dashboard read a live defence as an inaction.
		return fmt.Sprintf("%s: strict gain %.2f > 0 (fullValue=%.2f ECost=%.2f lambdaRuntimeLegacy=%.2f); stage=%s→%s hazard=%.2f pHold=%.2f",
			a, gain, cov, ecost, lambda, as.StageName, as.NextStageName, as.Hazard, as.PHold)
	}
}
