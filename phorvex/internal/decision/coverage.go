/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P1)
 */

package decision

import (
	"crypto/sha256"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/ctxprov"
	"github.com/phorvex/phorvex/internal/killchain"
	"github.com/phorvex/phorvex/internal/metrics"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/physics"
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
	costByOwner map[string]*cost.P1Cost
	// [M-140] bucketMeta records, at creation, the identity that owns each bucket and the
	// seed actually consumed. LambdaConfiguredSeed on the trace re-reads the CURRENT policy
	// spec every tick, so it moves on a PATCH that reseeds nothing; these fields are the only
	// truthful evidence that a recreate consumed a new seed.
	bucketMeta map[string]BucketMeta
	// [M-140] aliasOwner is the owner currently holding the legacy e.Cost singleton. The first
	// bucket reuses e.Cost so the single-tenant path stays bit-identical; once that owner is
	// removed the alias is RETIRED, so a later creation constructs fresh RLS/conformal/dual
	// instead of inheriting the departed owner's trained state.
	aliasOwner   string
	aliasRetired bool
	// creationEvent orders bucket creations within a process, so a removal and the
	// creation that follows it are ordered by identity/event rather than wall clock.
	creationEvent uint64
	// [M-140] live is the set of owners whose policy still exists. A deferred producer whose
	// owner is absent must not lazily recreate its state. lifecycleTracked records that the
	// runner has taken ownership of liveness at least once: without it, removing the LAST
	// owner would empty the set and silently re-enable resurrection (R1.1).
	live             map[string]struct{}
	lifecycleTracked bool
	// calibrationFrozen is the PHVX-2 off-switch, remembered so lazily-created tenant buckets
	// inherit it rather than starting to learn behind the operator's back.
	calibrationFrozen bool

	// Capability is the T1-E capability gate, set per tick by the runner (which holds the
	// snapshot + actuator + SSAR checker to build the witness). nil = gate off (legacy /
	// tests): the generator then falls back to the pre-T1-E empty-cover check only.
	//
	// [M-163] This collaborator is NOT assumed pure. The runtime one reaches a
	// SelfSubjectAccessReview and writes the shared authorization cache, so a counterfactual
	// evaluation that called it would spend apiserver budget and change what the NEXT real
	// gate observes. Only an actual production evaluation may call it.
	Capability func(*model.WorkloadView, model.Action, []string) *actionset.Eligibility

	// ShadowCapability is the READ-ONLY counterpart used by a counterfactual evaluation. It
	// must answer the same gate from state already observed: no apiserver review, no cache
	// write, no timestamp refresh, no other externally visible effect. The runtime wires
	// capability.Witness.EligibleObserved here beside Witness.Eligible above.
	//
	// It is required only when Capability is set. Leaving it nil is not a licence to skip the
	// gate: the engine cannot prove an arbitrary Capability callback is side-effect free, so a
	// shadow evaluation is reported UNAVAILABLE (ErrShadowCapabilityUnavailable) rather than
	// run without a gate or run through the impure one. Production is unaffected either way.
	ShadowCapability func(*model.WorkloadView, model.Action, []string) *actionset.Eligibility
	// FailureExclusion is runner-owned, immutable for one evaluation, and read-only.
	// It applies equally to production and shadow candidate generation.
	FailureExclusion func(*model.WorkloadView, model.Action) (detail string, excluded bool)
	alternative      *alternativeContext // immutable scores and reservations from last production pass
}

type alternativeContext struct {
	owner      string
	set        actionset.ActionSet
	lambda     float64
	selected   map[string]model.Action
	exchanged  map[string]model.Action // tick-local exchanges; original scored set is immutable
	provenance map[string]float64
	attack     map[string]bool
	states     map[string]*model.ExistentialDecision
	budget     int
}

// Alternative is selected from the exact action set and runtime price used by
// the original production pass. Other selected assets, including earlier
// same-tick exchanges, stay reserved; the failed target exchanges one slot.
type Alternative struct {
	Action                         model.Action
	Coverage, Marginal, Cost, Gain float64
	CoverKeys                      []string
	Attribution                    []model.AttributionTerm
	CounterfactualNote             string
}

func (e *CoverageEngine) SelectAlternative(owner, target string, failed model.Action) (Alternative, bool) {
	c := e.alternative
	if c == nil || c.owner != owner || c.currentAction(target) != failed || len(c.selected) > c.budget {
		return Alternative{}, false
	}
	covered := map[string]bool{}
	selected := map[string]bool{}
	for key := range c.selected {
		if key == target {
			continue
		}
		action := c.currentAction(key)
		selected[key] = true
		for _, cand := range c.set.Candidates {
			if cand.Key == key && cand.Action == action {
				for _, fact := range cand.CoverKeys {
					covered[fact] = true
				}
				break
			}
		}
	}
	filtered := c.set
	filtered.Candidates = nil
	for _, cand := range c.set.Candidates {
		if cand.Key == target && cand.Action != failed {
			filtered.Candidates = append(filtered.Candidates, cand)
		}
	}
	prov := func(key string) float64 { return c.provenance[key] }
	idx, marginal, _ := chooseRound(filtered, c.states, covered, selected, c.attack, c.lambda, prov, map[string]float64{})
	if idx < 0 {
		return Alternative{}, false
	}
	cand := filtered.Candidates[idx]
	coverage := 0.0
	for _, key := range cand.CoverKeys {
		coverage += c.set.FactWeights[key]
	}
	note := ""
	if cand.View != nil {
		note = counterfactualNote(cand.Action, true, cand.View)
	}
	return Alternative{Action: cand.Action, Coverage: coverage, Marginal: marginal, Cost: cand.ECost,
		Gain: legacyMixedGain(marginal, prov(target), c.lambda, cand.ECost), CoverKeys: append([]string(nil), cand.CoverKeys...),
		Attribution: attributionOf(cand, c.set.FactWeights, c.lambda), CounterfactualNote: note}, true
}

func (c *alternativeContext) currentAction(target string) model.Action {
	if c == nil {
		return ""
	}
	if a, exchanged := c.exchanged[target]; exchanged {
		return a
	}
	return c.selected[target]
}

// ReserveAlternative updates only this tick's partition-slot accounting. It
// never rewrites original scores, dual learning, or the first attempt's audit.
func (e *CoverageEngine) ReserveAlternative(owner, target string, failed, chosen model.Action) bool {
	c := e.alternative
	if c == nil || c.owner != owner || c.currentAction(target) != failed || c.selected[target] == "" || chosen == failed {
		return false
	}
	valid := false
	for _, cand := range c.set.Candidates {
		if cand.Key == target && cand.Action == chosen {
			valid = true
			break
		}
	}
	if !valid {
		return false
	}
	if c.exchanged == nil {
		c.exchanged = make(map[string]model.Action)
	}
	c.exchanged[target] = chosen
	return true
}

// capabilityFor selects the gate collaborator an evaluation in this mode may call, and
// reports whether the shadow contract above is satisfiable.
func (e *CoverageEngine) capabilityFor(mode killchain.EvalMode) (func(*model.WorkloadView, model.Action, []string) *actionset.Eligibility, bool) {
	if mode.Commits() {
		return e.Capability, true
	}
	if e.ShadowCapability != nil {
		return e.ShadowCapability, true
	}
	// No gate at all (legacy/offline producers) is the same substrate in both modes.
	return nil, e.Capability == nil
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
	for owner, c := range e.costByOwner {
		if c == nil || c.RLS == nil {
			continue
		}
		out[owner] = struct {
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
	for _, c := range e.costByOwner {
		if c != nil && c.RLS != nil {
			c.RLS.SetFrozen(frozen)
		}
	}
}

// CostCalibrationFrozen reports the current state (audit/observability).
func (e *CoverageEngine) CostCalibrationFrozen() bool { return e.calibrationFrozen }

// BucketMeta is the creation-time ownership record for one economic unit. It is captured
// once, when the bucket is constructed, and never rewritten: a PATCH that does not reseed
// leaves it untouched, while a recreate under a new owner produces a new one.
type BucketMeta struct {
	OwnerKey           string
	KeyKind            string
	LambdaSeedConsumed float64
	BucketCreatedAt    time.Time
	// CreationEvent is a monotonically increasing counter. Causality between a removal and
	// the following creation is carried by this event, not by requiring an injected clock to
	// advance between two calls in the same tick.
	CreationEvent uint64
}

// BucketMetaFor exposes the creation record for telemetry, records and tests.
func (e *CoverageEngine) BucketMetaFor(owner string) (BucketMeta, bool) {
	meta, ok := e.bucketMeta[owner]
	return meta, ok
}

// SetOwnerLive marks an owner as live (Add/Upsert) or, with live=false, marks it absent so
// deferred producers stop creating state for it. An engine that has never been told about
// any owner treats every owner as live, which keeps offline/legacy producers working.
func (e *CoverageEngine) SetOwnerLive(owner string, live bool) {
	if e.live == nil {
		e.live = map[string]struct{}{}
	}
	e.lifecycleTracked = true
	if live {
		e.live[owner] = struct{}{}
		return
	}
	delete(e.live, owner)
}

// ownerAbsent reports whether lifecycle tracking is active AND this owner is not live.
// The test is "was tracking ever enabled", not "is the set non-empty": removing the last
// owner leaves an EMPTY tracked set, and that must still reject stale producers rather than
// look like the untracked offline case.
func (e *CoverageEngine) ownerAbsent(owner string) bool {
	if !e.lifecycleTracked {
		return false // offline/legacy producers never register liveness
	}
	_, ok := e.live[owner]
	return !ok
}

// OwnerRetired reports whether this owner is known-absent under active lifecycle tracking.
// Callers use it to reject a stale decision BEFORE touching any owned store.
func (e *CoverageEngine) OwnerRetired(owner string) bool { return e.ownerAbsent(owner) }

// ForgetOwner drops every learned store this engine owns for one policy identity. It is the
// decision-side half of M-140's lifecycle: called from the runner's drain, never from a
// controller goroutine. Retiring the legacy alias when its holder leaves is what makes the
// NEXT creation genuinely fresh rather than a reused singleton carrying trained RLS state.
func (e *CoverageEngine) ForgetOwner(owner string) {
	if e.alternative != nil && e.alternative.owner == owner {
		e.alternative = nil
	}
	if e.aliasOwner == owner {
		e.aliasRetired = true
		e.aliasOwner = ""
	}
	delete(e.costByOwner, owner)
	delete(e.bucketMeta, owner)
	delete(e.live, owner)
	if e.Killchain != nil {
		if e.Killchain.Memory != nil {
			e.Killchain.Memory.Forget(owner)
		}
		if e.Killchain.StageClock != nil {
			e.Killchain.StageClock.RetainOwner(owner, nil)
		}
	}
}

// costFor resolves the per-owner cost bucket. An optional lambda seed is consumed only
// when the bucket is first created; later calls preserve the legacy runtime state.
func (e *CoverageEngine) costFor(owner string, lambdaSeed ...float64) *cost.P1Cost {
	if e.costByOwner == nil {
		e.costByOwner = map[string]*cost.P1Cost{}
	}
	if c := e.costByOwner[owner]; c != nil {
		return c
	}
	// [M-140] A deferred producer (rotation feedback, a stale tick) must not resurrect an
	// owner whose policy is gone, nor allocate under its identity.
	if e.ownerAbsent(owner) {
		return nil
	}
	seed := cost.DefaultLambdaSeed
	if len(lambdaSeed) > 0 {
		seed = lambdaSeed[0]
	}
	var c *cost.P1Cost
	if len(e.costByOwner) == 0 && e.Cost != nil && !e.aliasRetired {
		// First bucket reuses the original singleton so the single-tenant path stays
		// bit-identical. Remember the holder: when it is removed the alias is retired.
		c = e.Cost
		c.Dual = cost.NewDualSolverWithSeed(seed)
		e.aliasOwner = owner
	} else {
		c = cost.NewP1CostWithLambda(seed) // isolated per-owner bucket, zero cross-feed
	}
	if c != nil && c.RLS != nil {
		c.RLS.SetFrozen(e.calibrationFrozen)
	}
	e.costByOwner[owner] = c
	if e.bucketMeta == nil {
		e.bucketMeta = map[string]BucketMeta{}
	}
	e.creationEvent++
	e.bucketMeta[owner] = BucketMeta{
		OwnerKey: owner, KeyKind: model.OwnerKindOf(owner), LambdaSeedConsumed: seed,
		BucketCreatedAt: e.now(), CreationEvent: e.creationEvent,
	}
	return c
}

// costForMode resolves the cost bucket an evaluation should price against (M-163).
//
// Production is unchanged: costFor's lazy creation IS this owner's economic lifecycle —
// it consumes the policy seed once, may claim the legacy e.Cost alias, mints the BucketMeta
// the trace reports and advances the creation counter.
//
// A shadow evaluation must observe that lifecycle, never drive it. An owner that already has
// a bucket is priced from that bucket, so the counterfactual reads the SAME trained RLS,
// conformal window and runtime lambda production would use (substituting a fresh model here
// would report a price the production tick never saw). An owner with no bucket yet — the
// shadow arm runs BEFORE the production arm within a tick, so it can be first — is priced
// from a TRANSIENT bucket that is never registered: no seed is consumed, the alias stays
// unclaimed, no BucketMeta is minted and creationEvent does not move, so the first real
// production tick still creates that owner's bucket itself.
func (e *CoverageEngine) costForMode(owner string, mode killchain.EvalMode, lambdaSeed ...float64) *cost.P1Cost {
	if mode.Commits() {
		return e.costFor(owner, lambdaSeed...)
	}
	if c := e.costByOwner[owner]; c != nil {
		return c // existing learned state, read as-is
	}
	// [M-140] A retired owner is rejected before allocation in either mode.
	if e.ownerAbsent(owner) {
		return nil
	}
	seed := cost.DefaultLambdaSeed
	if len(lambdaSeed) > 0 {
		seed = lambdaSeed[0]
	}
	if len(e.costByOwner) == 0 && e.Cost != nil && !e.aliasRetired {
		// Production would hand this owner the legacy singleton, reseed only its dual, and then
		// apply the PHVX-2 freeze switch to its RLS. Mirror that post-creation state, on private
		// objects, so e.Cost.Dual, e.Cost.RLS and the alias itself are all left untouched.
		//
		// RLS.SetFrozen(true) does NOT merely gate Update: on an unfrozen learner it REVERTS
		// theta to the shipped prior and clears primed. So under an enabled freeze the learned
		// values still sitting in the singleton are values the next production creation is about
		// to discard, and pricing a hypothetical against them would report a cost production
		// could never produce. Under a freeze the shadow therefore reads the prior — the state
		// production will actually price from — rather than the doomed learned one.
		rls := e.Cost.RLS
		if e.calibrationFrozen {
			rls = cost.NewRLS()
			rls.SetFrozen(true)
		}
		return &cost.P1Cost{RLS: rls, Conformal: e.Cost.Conformal, Dual: cost.NewDualSolverWithSeed(seed)}
	}
	// No learned state exists for this owner in either mode; a private bucket at the same seed
	// and the same freeze state prices identically to the one production would create. Freezing
	// here is safe precisely because the object is private — the shared calibrators above are
	// never handed to SetFrozen, which would be a write.
	c := cost.NewP1CostWithLambda(seed)
	if c.RLS != nil {
		c.RLS.SetFrozen(e.calibrationFrozen)
	}
	return c
}

// ObserveRotation implements RotationObserver and keeps the feedback in the same
// per-tenant bucket used to price that tenant's decisions.
func (e *CoverageEngine) ObserveRotation(owner string, view *model.WorkloadView, measuredFlow float64) {
	// [M-140] Deferred rotation feedback can land after its policy is gone. costFor returns
	// nil for an absent owner rather than lazily recreating the bucket at the DEFAULT seed.
	c := e.costFor(owner)
	if c == nil {
		return
	}
	c.ObserveRotation(view, measuredFlow)
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

// RetainStageClock forwards the runner's per-tick GC to the kill-chain stage-dwell tracker
// (T1-B), using the same keep set that prunes the exposure clock.
func (e *CoverageEngine) RetainStageClock(owner string, keep map[string]struct{}) {
	if e.Killchain != nil {
		e.Killchain.StageClock.RetainOwner(owner, keep)
	}
}

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
//
// This is the production entrypoint and keeps its signature and behaviour: it assesses in
// EvalProduction, stamps the runner's shared views and counts the tick's gate exclusions.
func (e *CoverageEngine) AssembleSet(views []*model.WorkloadView, pol model.Policy) (actionset.ActionSet, map[string]assetCtx) {
	// [M-140 R1.2] Same rejection as decideChecked: a retired owner must not be priced,
	// and must not allocate a bucket by being asked for one.
	if e.ownerAbsent(pol.Owner()) {
		return actionset.ActionSet{}, map[string]assetCtx{}
	}
	// EvalProduction always satisfies the gate contract, so the error arm is unreachable here.
	set, ctxByKey, _ := e.assembleSet(views, pol, e.costFor(pol.Owner(), pol.Lambda), killchain.EvalProduction)
	return set, ctxByKey
}

// assembleSet is the common action-set path under an explicit evaluation mode (M-163).
// tcost is the already-resolved bucket for this evaluation, so the assessment and the
// selection that follows it are priced by ONE bucket rather than by two independent
// resolutions (which, for a shadow's transient bucket, would be two different objects).
func (e *CoverageEngine) assembleSet(views []*model.WorkloadView, pol model.Policy, tcost *cost.P1Cost,
	mode killchain.EvalMode) (actionset.ActionSet, map[string]assetCtx, error) {
	// [M-140 R1.2] A retired owner must not be priced, and must not allocate a bucket by
	// being asked for one; costForMode reports that as a nil bucket in either mode.
	if e.ownerAbsent(pol.Owner()) || tcost == nil {
		return actionset.ActionSet{}, map[string]assetCtx{}, nil
	}
	// [M-163] Resolve the gate collaborator BEFORE any assessment: a shadow whose gate cannot
	// be answered read-only is unavailable, and reporting that must not first have cost an
	// SSAR or any other observable work.
	eligible, gateAvailable := e.capabilityFor(mode)
	if !gateAvailable {
		return actionset.ActionSet{}, map[string]assetCtx{}, ErrShadowCapabilityUnavailable
	}
	if e.FailureExclusion != nil {
		base := eligible
		eligible = func(v *model.WorkloadView, a model.Action, cover []string) *actionset.Eligibility {
			var r *actionset.Eligibility
			if base != nil {
				r = base(v, a, cover)
				if r != nil && r.Excluded {
					return r
				}
			}
			if detail, excluded := e.FailureExclusion(v, a); excluded {
				return &actionset.Eligibility{Excluded: true, Kind: model.ExclusionActionFailure, Detail: detail}
			}
			return r
		}
	}
	floorSec := pol.ProactiveFloor.Seconds()

	// M-163: the generator reads HasEventEvidence off the view (the proactive-cadence law
	// sees no Assessment), so a shadow needs its OWN correctly-computed stamp without writing
	// the caller's view. In production genViews IS views — same pointers, same stamp, zero
	// change. In shadow it is a per-view local copy carrying the shadow's own verdict, so the
	// hypothetical action set is generated from the hypothetical evidence while the runner's
	// view keeps whatever the production pass put there.
	genViews := views
	if !mode.Commits() {
		genViews = make([]*model.WorkloadView, len(views))
	}

	ctxByKey := make(map[string]assetCtx, len(views))
	for i, v := range views {
		key := v.Pod.Namespace + "/" + v.Pod.Name
		sig := model.ContextSignals{}
		if e.Context != nil {
			sig = e.Context.Context(v, pol)
		}
		exp := 0.0
		if d, ok := v.ExposureByVariable[model.VarPodIdentity]; ok {
			exp = d.Seconds()
		}
		assess := e.Killchain.AssessMode(v, pol, exp, floorSec, mode)
		if mode.Commits() {
			// M-28: mirror the EVENT-ONLY evidence verdict onto the shared view so the
			// proactive-cadence feasibility law can read it (a hard law only sees view/move/pol, never
			// the Assessment). HasEventEvidence (not the broad HasEvidence) so a physics-pinned,
			// event-less pod — the churn pod — is still capped. The view pointers are shared with the
			// runner, so generator/shadow/emit-boundary all see the same stamp.
			v.HasEventEvidence = assess.HasEventEvidence
		} else {
			local := *v
			local.HasEventEvidence = assess.HasEventEvidence
			genViews[i] = &local
		}
		ctxByKey[key] = assetCtx{sig: sig, assess: assess, exposure: exp}
	}
	views = genViews

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

	costCeiling := cost.EffectiveCostCeiling(pol)
	mayRelax := map[string]bool{}
	if pol.MayBreachSLO {
		for _, v := range views {
			mayRelax[v.Pod.Namespace+"/"+v.Pod.Name] = assessOutcomes(v, pol).Present
		}
	}
	deps := actionset.Deps{
		RetainSLO:   func(key string) bool { return mayRelax[key] },
		Recon:       e.Recon,
		FactContext: factCtx,
		ECost:       tcost.ECost,
		CHi:         tcost.CHi,
		Evaluate: func(view *model.WorkloadView, move model.Move, policy model.Policy) (float64, float64, string, string) {
			eval := tcost.Evaluation(view, move, policy)
			return eval.Total, eval.CHi, eval.UnactionableCategory, eval.NaNFeature
		},
		CostCeiling: costCeiling,
		// T1-E gate (nil when the runner has not wired it). M-163: the SHADOW arm receives the
		// read-only collaborator; it is never the reviewing one.
		Eligible: eligible,
	}
	as := deps.Generate(views, pol)
	// T1-E metrics: one per capability-gate exclusion (by reason), and the fail-open
	// rbac-unknown flag on candidates that proceeded despite an SSAR error.
	//
	// M-163: these count what the OPERATOR's cluster did this tick — how many real candidates
	// the capability gate dropped, how many proceeded with unconfirmed RBAC. A counterfactual
	// re-pricing of the same pods excluded nothing operationally, so counting it double-counts
	// the tick and makes the series a function of how many shadows ran. The exclusions and
	// the RBACUnknown flags themselves still travel in the returned ActionSet, so the shadow's
	// own decision trace reports them (with Applied=false) without touching the counters.
	if mode.Commits() {
		for _, ex := range as.Excluded {
			if ex.EligibilityKind != "" {
				metrics.RecordCandidateExcluded(pol.Tenant, string(ex.Action), ex.EligibilityKind)
			}
		}
		for _, cand := range as.Candidates {
			if cand.RBACUnknown {
				metrics.RecordCandidateRBACUnknown(pol.Tenant, string(cand.Action))
			}
		}
	}
	return as, ctxByKey, nil
}

// Decide runs the per-tick coverage optimization and returns one Decision per pod.
func (e *CoverageEngine) Decide(views []*model.WorkloadView, pol model.Policy) []model.Decision {
	decisions, _ := e.DecideChecked(views, pol)
	return decisions
}

// DecideChecked rejects a structurally invalid ActionSet before selection or learning.
// The runner calls this checked seam and logs/counts the failure for the production tick.
func (e *CoverageEngine) DecideChecked(views []*model.WorkloadView, pol model.Policy) ([]model.Decision, error) {
	return e.decideChecked(views, pol, killchain.EvalProduction)
}

// DecideShadowChecked evaluates a counterfactual against the engine's existing knowledge and
// cost state without advancing any of it (M-163). Adding any number of shadow evaluations to
// a tick must leave the next production decision identical to the same engine history with no
// shadows at all: the shadow folds no stage entry, seeds no owner state, moves no dual price,
// teaches no conjugate memory, stamps no caller-owned view and increments no operational
// counter. Its own decisions carry the full trace, with the dual update marked Applied=false.
func (e *CoverageEngine) DecideShadowChecked(views []*model.WorkloadView, pol model.Policy) ([]model.Decision, error) {
	return e.decideChecked(views, pol, killchain.EvalShadow)
}

func (e *CoverageEngine) decideChecked(views []*model.WorkloadView, pol model.Policy, mode killchain.EvalMode) ([]model.Decision, error) {
	// [M-140 R1.2] A tick captured before this owner was retired can still arrive here.
	// Reject it BEFORE any owned-store read or write: costFor would otherwise return nil
	// for the retired owner and the dereference below would panic, and an unguarded
	// creation would resurrect the very state removal just destroyed. A shadow is rejected
	// on the identical guard, so a counterfactual cannot resurrect a retired owner either.
	if e.ownerAbsent(pol.Owner()) {
		return nil, ErrOwnerRetired
	}
	persist := mode.Commits()
	now := e.now()
	tcost := e.costForMode(pol.Owner(), mode, pol.Lambda)
	if tcost == nil {
		return nil, ErrOwnerRetired
	}
	lambda := tcost.Dual.Lambda()

	set, ctxByKey, err := e.assembleSet(views, pol, tcost, mode)
	if err != nil {
		return nil, err
	}
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

	existential := map[string]*model.ExistentialDecision{}
	for _, v := range views {
		existential[v.Pod.Namespace+"/"+v.Pod.Name] = assessOutcomes(v, pol)
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
	// manufacture: an overdue hygiene workload (aged exposure ≥ proactiveFloor)
	// OR carrying a trusted, recent direct or lateral observation — keeps prov=1 so
	// its gain (and the SELECTION) is BYTE-IDENTICAL. A FRESH candidate without an observation (a manufactured
	// decoy) is down-weighted toward provFloor, so it can no longer displace a real asset from the
	// slot. Broad AI/topology HasEvidence remains contextual inference and cannot prove an observation.
	// The reported coverage/marginal is the UN-discounted value (reporting unchanged). NO
	// learning enters Decide — prov is a deterministic function of the real exposure/assessment.
	floorSec := pol.ProactiveFloor.Seconds()
	prov := func(key string) float64 {
		if floorSec <= 0 {
			return 1
		}
		ac := ctxByKey[key]
		if ac.exposure >= floorSec || ac.assess.HasEventEvidence {
			return 1 // genuinely due, or backed by a trusted observation => full weight
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
	// T0-C: coveredRound records WHEN a fact key was first covered (1-based round),
	// written beside covered[k] and never read by the loop — zero selection effect.
	// lastRound is the last round whose evaluation pass ran (rounds evaluate, then
	// break), so a recorded marginal's round semantics are reconstructable.
	coveredRound := map[string]int{}
	lastRound := 0
	selectedAsset := map[string]bool{}
	selectedAction := map[string]model.Action{}
	selectedMarginal := map[string]float64{}
	selectedRound := map[string]int{}
	evaluatedMarginal := map[string]float64{}
	prioritySelections := []string{}
	B := pol.MaxMovesPerTick
	for round := 0; round < B; round++ {
		lastRound = round + 1
		bestIdx, bestMarginal, bestActive := chooseRound(set, existential, covered, selectedAsset, attackBackedKey, lambda, prov, evaluatedMarginal)
		if bestIdx < 0 {
			break
		}
		c := set.Candidates[bestIdx]
		if bestActive {
			prioritySelections = append(prioritySelections, traceCandidateKey(c.Key, c.Action))
		}
		selectedAsset[c.Key] = true
		selectedAction[c.Key] = c.Action
		selectedMarginal[c.Key] = bestMarginal
		selectedRound[c.Key] = round + 1
		for _, k := range c.CoverKeys {
			covered[k] = true
			coveredRound[k] = round + 1
		}
	}
	if persist {
		provenance := make(map[string]float64, len(views))
		for _, v := range views {
			key := v.Pod.Namespace + "/" + v.Pod.Name
			provenance[key] = prov(key)
		}
		e.alternative = &alternativeContext{owner: pol.Owner(), set: set, lambda: lambda,
			selected: selectedAction, provenance: provenance, attack: attackBackedKey,
			states: existential, budget: B}
	}

	// demand = number of assets with a net-positive best move (for the dual subgradient).
	// PHORVEXSEC-196 / M-110 site 2: the SAME provenance discount selection applies
	// (legacyMixedGain with prov) — a fresh, evidence-less decoy that selection discounts to
	// provFloor no longer pumps λ's rise pressure at face value. Expect demand, and hence λ,
	// to be lower on decoy-bearing tenants; that is the point (M-144's decoy channel).
	demand := 0
	for key, idxs := range candsByAsset {
		if !attackBackedKey[key] {
			continue // reactiveOnly: un-attacked assets create no proactive demand
		}
		best := 0.0
		for _, i := range idxs {
			c := set.Candidates[i]
			if g := legacyMixedGain(covValue(c), prov(key), lambda, c.ECost); g > best {
				best = g
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
		} else if len(idxs) > 0 && attackBackedKey[key] && !existential[key].Present {
			// best standalone candidate, scored EXACTLY as the main path scores it
			// (PHORVEXSEC-196 / M-110 site 3): coverage·prov − λ·cost through legacyMixedGain.
			// The un-discounted form ranked a "considered" entry higher than selection ever would.
			bestNet := math.Inf(-1)
			for _, i := range idxs {
				c := set.Candidates[i]
				if net := legacyMixedGain(covValue(c), prov(key), lambda, c.ECost); net > bestNet {
					bestNet = net
					action = c.Action
					chosen = &set.Candidates[i]
				}
			}
		}

		feasible := len(idxs) > 0 && (!existential[key].Present || selectedAsset[key])
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
		// PHORVEXSEC-196 / M-110 site 1: priced by the TARGET tenant's calibrator bucket
		// (tcost = costFor(pol.Owner())). e.Cost is the legacy scalar that costFor hands to the
		// FIRST tenant registered, so every later tenant's blind cost was priced by that first
		// tenant's learned RLS/Conformal state.
		blindCost := tcost.ECost(v, model.Move{Action: model.ActionRotate}, pol)
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
			if marginal == 0 && !selectedAsset[key] {
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
			AdapterObservation:    v.Pod.AdapterObservation,
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
			CounterfactualNote:    counterfactualNote(action, selected, v),
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
			Provenance:            prov(key),
			PHoldInputs:           ac.assess.PHoldInputs,
			StageEvent:            ac.assess.EventStageName,
			StageAI:               ac.assess.AIStageName,
			StageMergeRule:        ac.assess.StageMergeRule,
			EventEvidence:         ac.assess.EventEvidence,
			Events:                ac.assess.Events,
			Lambda:                lambda,
			ProactiveRate:         rate,
			Attribution:           attribution,
			PreemptMargin:         ac.assess.PreemptMargin,
			ProjectedNextStageSec: ac.assess.ProjectedNextStageSec,
			AIClassified:          ac.assess.AIClassified,
		}
		finishExistential(existential[key], set, key, selected, B-len(selectedAsset), prioritySelections)
		decision.Existential = existential[key]
		for i := range decision.Existential.Candidates {
			c := &decision.Existential.Candidates[i]
			c.SLORelaxed = selected && c.Action == action && c.SLOExcluded
		}
		if existential[key].Present && !selected {
			decision.InfeasibleWhy = "existential-uncontainable"
			decision.Reason = "PHORVEXSEC-208 interim: uncontainable"
		}
		if pol.TraceEnabled {
			// T0-C: the round whose marginal this asset's record carries — the
			// selection round for the winner (its whole asset is skipped
			// afterwards), the last executed round for every other asset.
			evaluationRound := lastRound
			if selectedAsset[key] {
				evaluationRound = selectedRound[key]
			}
			decision.Trace = e.buildDecisionTrace(v, pol, now, set, ac, lambda, demand,
				len(selectedAsset), selectedAsset[key], selectedAction[key], selectedRound[key],
				attackBackedKey[key], infeasibleWhy, tcost.RLS != nil && tcost.RLS.Primed(), prov,
				tcost, evaluatedMarginal, dualUpdate, coveredRound, evaluationRound, mode)
		}
		decorateExistentialTrace(decision.Trace, decision.Existential)
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
				e.Killchain.Memory.Observe(pol.Owner(), 0.5*(ac.assess.PHold-0.5))
			}
		}
	}

	return decisions, nil
}

func traceOptional(present bool, value float64) model.OptionalFloat {
	return model.OptionalFloat{Present: present, Value: value}
}

func traceOptionalInt(present bool, value int) model.OptionalInt {
	return model.OptionalInt{Present: present, Value: value}
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
func cloneVectorSteering(in *model.VectorSteeringAttribution) *model.VectorSteeringAttribution {
	if in == nil {
		return nil
	}
	out := *in
	out.Events = append([]model.VectorSteeringEvent(nil), in.Events...)
	return &out
}

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
	coveredRound map[string]int,
	evaluationRound int,
	mode killchain.EvalMode,
) *model.DecisionTraceV2 {
	assetKey := v.Pod.Namespace + "/" + v.Pod.Name
	// [M-140] Ownership metadata comes from the bucket's CREATION record, so it is present
	// on every record this owner produces — including ticks that select nothing.
	ownerMeta, _ := e.BucketMetaFor(pol.Owner())
	tickID := pol.TickID
	if tickID == "" {
		tickID = decisionTraceID("tick", now.UTC().Format(time.RFC3339Nano), pol.PolicyUID, pol.Tenant)
	}
	trace := &model.DecisionTraceV2{
		SchemaVersion:             model.DecisionTraceSchemaV3,
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
		MovesSpent:                movesSpent, // ≡ the ticket's movesSelected: per-tick selected count (B.6.1)
		DryRun:                    pol.DryRun,
		LambdaConfiguredSeed:      pol.Lambda,
		LambdaRuntime:             lambda,
		LambdaConfiguredPolicy:    pol.Lambda,
		LambdaRuntimeLegacy:       lambda,
		OwnerKey:                  ownerMeta.OwnerKey,
		OwnerKeyKind:              ownerMeta.KeyKind,
		LambdaSeedConsumed:        ownerMeta.LambdaSeedConsumed,
		BucketCreatedAt:           traceTime(ownerMeta.BucketCreatedAt),
		BucketCreationEvent:       ownerMeta.CreationEvent,
		SelectorComparator:        model.SelectorStrictPositiveGain,
		NormWeight:                pol.NormSparsity,
		FlowWeight:                pol.FlowDisruption,
		CFlowUnitStatus:           model.CFlowUnitDimensionlessDisruptionLoss,
		CostRepresentationVersion: model.CostRepresentationWeightedDimensionlessV1,
		DualUpdate:                traceDualUpdate(dualUpdate),
		CostCeiling:               set.CostCeiling,
		CostModelVersion:          tcost.Name(),
		EvaluationRound:           evaluationRound,
		SelectedAction:            string(model.ActionNoop),
		TieBreakReason:            "notApplicable",
	}

	exposure, exposurePresent := v.ExposureByVariable[model.VarPodIdentity]
	dispersionPresent := e.Recon != nil && e.Recon.Name() == "ucw-recon"
	dispersionMult, dispersionOK := recon.DispersionMultiplier(v)
	trace.Inputs = model.DecisionModelInputsV2{
		Phase:             string(v.Phase),
		PhaseReason:       v.PhaseReason,
		RequestRate:       traceOptional(v.Telemetry.ReqRate.Usable(), v.Telemetry.ReqRate.Value),
		ConnectionCount:   traceOptional(v.Telemetry.ConnCount.Usable(), v.Telemetry.ConnCount.Value),
		GPUUtilization:    traceOptional(v.Telemetry.GPUUtil.Usable(), v.Telemetry.GPUUtil.Value),
		SMOccupancy:       traceOptional(v.Physics.SMSource != "", v.Physics.SMOccupancy),
		VRAMFraction:      traceOptional(v.Physics.VRAMPresent, v.Physics.VRAMFraction),
		Leakage:           traceOptional(v.Physics.SMSource != "", ac.assess.Leakage), // T1-A gate input
		ImageRarity:       traceOptional(v.Physics.ImageRarityPresent, v.Physics.ImageRarity),
		ModelRarity:       traceOptional(v.Physics.ModelRarityPresent, v.Physics.ModelRarity),
		CoResidency:       traceOptional(v.Physics.CoResidencyPresent, v.Physics.CoResidency),
		EPSS:              traceOptional(v.Physics.EPSSPresent, v.Physics.EPSSScore),
		CVSS:              traceOptional(v.Physics.EPSSPresent, v.Physics.CVSS),
		EPSSMultiplier:    traceOptional(v.Physics.EPSSPresent, v.Physics.EPSSMultiplier),
		EPSSReason:        v.Physics.EPSSReason,
		EPSSBasis:         v.Physics.EPSSBasis,
		EPSSCachedDigest:  v.Physics.EPSSCachedDigest,
		EPSSRunningDigest: v.Pod.ImageID,
		EPSSScanTS:        v.Physics.EPSSScanTS,
		PhysicsScanned:    v.Physics.Scanned,
		DispersionMult:    traceOptional(dispersionPresent && dispersionOK, dispersionMult),
		FactsAbsentReason: set.FactsAbsent[v.Pod.Namespace+"/"+v.Pod.Name],
		Flow:              flowRecord(v),
		TelemetryStates:   telemetryStates(v.Telemetry),
		PCIe:              pcieRecord(v.Physics),
		DispersionCap:     traceOptional(v.Physics.DispersionCap > 0, v.Physics.DispersionCap),
		Primed:            primed,
		// M-163: reporting the learned prior must not be what CREATES it. The number is
		// identical in both modes; only the shadow read declines to seed an unseen owner.
		BetaMean:          traceOptional(true, e.Killchain.Memory.PriorMeanMode(pol.Owner(), mode)),
		PHold:             traceOptional(true, ac.assess.PHold),
		Stage:             ac.assess.StageName,
		StageHazard:       traceOptional(true, ac.assess.Hazard),
		StageUrgency:      traceOptional(true, ac.assess.StageUrgency),
		ThreatPosture:     traceOptional(true, ac.sig.ThreatPosture),
		ExposureVariable:  model.VarPodIdentity,
		ExposureSeconds:   traceOptional(exposurePresent, exposure.Seconds()),
		ProactiveFloorSec: pol.ProactiveFloor.Seconds(),
		// M-110 site 1: which calibrator bucket priced the costs, and where BlindCost came from.
		CostCalibratorTenant: pol.Tenant,
		BlindCostSource:      blindCostSource(v),
		AntiOverRotateSec:    pol.AntiOverRotationWindow.Seconds(),
		Clocks: model.DecisionClocksV3{
			PodAgeSec:                v.Pod.Age.Seconds(),
			SinceIdentityChangeSec:   ac.exposure,
			InStageSec:               ac.assess.InStageSec,
			SinceEvidence:            sinceEvidenceOf(ac.assess),
			EventAgeHorizonSec:       eventAgeHorizonSeconds(pol),
			ExposurePressureScaleSec: exposurePressureScaleSeconds(pol),
		},
		// T0-C: lifted from the envelope into the trace with presence.
		// Present only when headroom was MEASURED: sensed.Context (ctxprov/sensed.go) derives it
		// from P99 under exactly this predicate and otherwise defaults to 1.0 (full headroom).
		SLOHeadroom:           traceOptional(pol.P99Ms > 0 && v.Telemetry.P99Ms.Usable() && v.Telemetry.P99Ms.Value > 0, ac.sig.SLOHeadroom),
		NextStage:             ac.assess.NextStageName,
		ProjectedNextStageSec: traceOptional(ac.assess.NextStageName != "", ac.assess.ProjectedNextStageSec),
	}

	source := model.TraceNotAvailable
	if e.Recon != nil {
		source = e.Recon.Name()
	}
	// T0-C: invert the declared cover map (ALL actions, not only enabled ones)
	// into per-fact covering actions, in canonical order.
	coveringActions := func(factKey string) []string {
		var out []string
		for _, a := range model.MutatingActions {
			for _, k := range set.CoverByAsset[assetKey][a] {
				if k == factKey {
					out = append(out, string(a))
					break
				}
			}
		}
		return out
	}
	for _, fact := range set.FactsByAsset[assetKey] {
		weight, presented := set.FactWeights[fact.Key()]
		if !presented {
			continue
		}
		// T0-C: coveredBeforeDecision is DERIVED from the round map (covered in an
		// earlier round than the one whose marginal this record carries), not
		// asserted — the hard-coded false it replaces was a fabricated value.
		factCoveredRound, factCovered := coveredRound[fact.Key()]
		trace.Facts = append(trace.Facts, model.DecisionFactV2{
			FactKey:               fact.Key(),
			FactType:              fact.Kind,
			FinalWeight:           weight,
			CoveredBeforeDecision: factCovered && factCoveredRound < evaluationRound,
			SourceComponent:       source,
			AssetValue:            traceOptional(true, ac.sig.AssetValue),
			// The current recon API exposes only the final weight and its
			// conditioning inputs, not a stable per-fact term decomposition.
			PHoldContribution:      model.OptionalFloat{Present: false},
			UrgencyContribution:    model.OptionalFloat{Present: false},
			DispersionContribution: model.OptionalFloat{Present: false},
			RelativeWeight:         model.OptionalFloat{Present: false},
			CoveringActions:        coveringActions(fact.Key()),
			DecompositionAvailable: false,
			CoveredRound:           traceOptionalInt(factCovered, factCoveredRound),
			SteeredBy:              cloneVectorSteering(fact.SteeredBy),
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
		// T0-C (B.1): the CHi reconstruction terms, recorded exactly where the
		// cost path computed them. The envelope branch is the majority GPU case
		// live; without these four fields CHi is unreconstructable there.
		conformalQuantile, quantileOK := tcost.ConformalQuantile()
		conformalCalibrated, calibratedOK := tcost.ConformalCalibrated()
		envelopeApplied := candidate.Action == model.ActionRotate && v.Pod.HasGPU && !primed
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
		row := model.DecisionCandidateV2{
			Action:       string(candidate.Action),
			CandidateKey: key,
			CoverKeys:    append([]string(nil), candidate.CoverKeys...),
			TieBreakRank: tieBreakRank,
			RBACUnknown:  candidate.RBACUnknown, // T1-E fail-open flag → trace

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
			// Generated ⇒ passed the conformal SLO gate (generator step 4).
			SLOGateResult:      model.OptionalBool{Present: true, Value: true},
			GPUEnvelopeApplied: model.OptionalBool{Present: true, Value: envelopeApplied},
		}
		if candidate.Action == model.ActionRotate {
			row.ConformalQuantile = traceOptional(quantileOK, conformalQuantile)
			row.ConformalCalibrated = model.OptionalBool{Present: calibratedOK, Value: conformalCalibrated}
			row.GPUEnvelopeSlack = traceOptional(envelopeApplied, pol.FlowDisruption*cost.GPUEnvelopeMax())
		}
		if candidateSelected {
			row.SelectionRound = model.OptionalInt{Present: true, Value: selectionRound}
		}
		trace.Candidates = append(trace.Candidates, row)
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
			// T0-C: cost-evaluated exclusions are conformal-slo gate rejects
			// (the only costed exclusion path) — the gate result is false, and
			// rotate rows carry the same CHi reconstruction terms as candidates.
			candidate.SLOGateResult = model.OptionalBool{Present: true, Value: false}
			exclEnvelopeApplied := exclusion.Action == model.ActionRotate && v.Pod.HasGPU && !primed
			candidate.GPUEnvelopeApplied = model.OptionalBool{Present: true, Value: exclEnvelopeApplied}
			if exclusion.Action == model.ActionRotate {
				q, qOK := tcost.ConformalQuantile()
				cal, calOK := tcost.ConformalCalibrated()
				candidate.ConformalQuantile = traceOptional(qOK, q)
				candidate.ConformalCalibrated = model.OptionalBool{Present: calOK, Value: cal}
				candidate.GPUEnvelopeSlack = traceOptional(exclEnvelopeApplied, pol.FlowDisruption*cost.GPUEnvelopeMax())
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

	// T0-C (R-2): the complete action accounting — exactly one row per canonical
	// mutating action, including actions the current model never considered.
	// Statuses map from existing pipeline facts only; nothing is invented.
	// Capability/installability is never evaluated per-asset in the decision path,
	// so not-installable is emitted by no mapping (trap 3).
	trace.ActionStatus = buildActionStatus(pol, assetKey, attackBacked, trace.Candidates, set.Excluded, evaluatedMarginal)

	// T0-C (B.5): the dispatch outcome is known only after the actuation attempt;
	// the runner stamps the real value before the audit write. These defaults make
	// an unselected record honest at decision time and a selected record that
	// somehow reached the write unstamped VISIBLE (pending-dispatch is a stamp bug,
	// not a decision state).
	if selected {
		trace.DispatchOutcome = model.DispatchNotAttempted
		trace.DispatchReason = "pending-dispatch"
	} else {
		trace.DispatchOutcome = model.DispatchNotAttempted
		trace.DispatchReason = "unselected"
	}
	return trace
}

// eligibilityTrace maps a T1-E capability-gate EligibilityKind (the closed set the
// generator stamps, == capability.Reason* == the model.Exclusion* strings) onto the
// trace's (status, exclusionKind). Pure closed-set map — the structural counterpart to
// the "no string sniffing" rule. no-cover reuses recon-cover so it stays byte-identical
// to the pre-T1-E no-cover record; the two new causes take the shared "ineligible" status.
func eligibilityTrace(kind string) (status, exclusionKind string) {
	switch kind {
	case model.ExclusionNotInstallable: // "not-installable"
		return model.ActionStatusNotInstallable, model.ExclusionNotInstallable
	case "no-cover": // capability.ReasonNoCover — no dedicated kind; reuses recon-cover
		return model.ActionStatusNoCover, model.ExclusionReconCover
	case model.ExclusionCapability: // "capability-unsupported"
		return model.ActionStatusIneligible, model.ExclusionCapability
	case model.ExclusionNoRBAC: // "no-rbac"
		return model.ActionStatusIneligible, model.ExclusionNoRBAC
	case model.ExclusionActionFailure:
		return model.ActionStatusIneligible, model.ExclusionActionFailure
	default:
		return model.ActionStatusNotEvaluated, model.ExclusionNone // defensive; never reached
	}
}

// buildActionStatus maps the generator/selection facts of one asset's tick onto the
// ticket's closed per-action vocabulary (T0-C). Pure recording: it reads the trace's
// own candidate rows and the generator's exclusions; it cannot affect selection.
func buildActionStatus(pol model.Policy, assetKey string, attackBacked bool,
	candidates []model.DecisionCandidateV2, excluded []actionset.Exclusion,
	evaluatedMarginal map[string]float64) []model.DecisionActionStatusV3 {

	generated := map[string]model.DecisionCandidateV2{}
	for _, c := range candidates {
		if c.ExistingExclusionReason == "" {
			generated[c.Action] = c
		}
	}
	excludedByAction := map[string]actionset.Exclusion{}
	for _, ex := range excluded {
		if ex.Key == assetKey {
			excludedByAction[string(ex.Action)] = ex
		}
	}

	rows := make([]model.DecisionActionStatusV3, 0, len(model.MutatingActions))
	for _, action := range model.MutatingActions {
		name := string(action)
		row := model.DecisionActionStatusV3{Action: name}
		ex, wasExcluded := excludedByAction[name]
		c, wasGenerated := generated[name]
		switch {
		case !model.ActionEnabled(pol, action):
			row.Status = model.ActionStatusNotEnabled
			row.ExclusionKind = model.ExclusionNotEnabled
		case wasExcluded:
			// Structural mapping from the exclusion's own fields — no string sniffing:
			// Category set ⇒ data-quality fail-close; feasibility never evaluated ⇒
			// recon-cover; infeasible ⇒ Layer-A; costed+feasible ⇒ the SLO gate.
			row.Reason = ex.Reason
			switch {
			case ex.EligibilityKind != "":
				// T1-E capability gate (runs before scoring). Structural: map the
				// gate's own closed EligibilityKind, never the reason string.
				row.Status, row.ExclusionKind = eligibilityTrace(ex.EligibilityKind)
			case ex.Category != "":
				row.Status = model.ActionStatusInfeasible
				row.ExclusionKind = model.ExclusionCostNaN
			case !ex.FeasibilityEvaluated:
				row.Status = model.ActionStatusNoCover
				row.ExclusionKind = model.ExclusionReconCover
			case !ex.Feasible:
				row.Status = model.ActionStatusInfeasible
				row.ExclusionKind = model.ExclusionFeasibility
			default:
				row.Status = model.ActionStatusConformalSLO
				row.ExclusionKind = model.ExclusionSLOGate
			}
		case wasGenerated:
			_, row.Scored = evaluatedMarginal[traceCandidateKey(assetKey, action)]
			row.RBACUnknown = c.RBACUnknown // T1-E: fail-open flag on a proceeding candidate
			row.Reason = c.SelectionReason
			switch {
			case c.Selected:
				row.Status = model.ActionStatusSelected
				row.ExclusionKind = model.ExclusionNone
			case !attackBacked:
				// Reactive-only suppression: never scored, never in the running —
				// recorded as such, not as a bare candidate (B.4).
				row.Status = model.ActionStatusCandidate
				row.ExclusionKind = model.ExclusionReactiveOnly
			case c.SelectionReason == "strict_gain_not_positive":
				row.Status = model.ActionStatusPricedOut
				row.ExclusionKind = model.ExclusionSelection
			case c.SelectionReason == "move_budget_exhausted":
				row.Status = model.ActionStatusBudgetExhausted
				row.ExclusionKind = model.ExclusionSelection
			default:
				row.Status = model.ActionStatusCandidate
				row.ExclusionKind = model.ExclusionSelection
			}
		default:
			// Unreachable by construction (Generate writes every enabled action to
			// Candidates or Excluded); recorded defensively, never fabricated.
			row.Status = model.ActionStatusNotEvaluated
			row.ExclusionKind = model.ExclusionNone
		}
		rows = append(rows, row)
	}
	return rows
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
//
// The note narrates SELECTION and intended purpose only. Whether the move ran, contained
// anything or kept the workload serving is actuation evidence (Actuated / ActuationOutcome),
// so the note never claims it. `selected` is the decision's own Selected flag: the fallback
// branch above names the best standalone candidate for a feasible-but-unselected
// attack-backed pod (Reason "<action>: considered (…)"), and that record must not read as
// if Phorvex chose or used the action (M-16). The structured action/cost/selection fields are
// untouched by this function; it only labels them.
func counterfactualNote(a model.Action, selected bool, v *model.WorkloadView) string {
	if a == model.ActionNoop {
		// No move was selected. Reason/trace carry the selector's actual outcome; do not
		// invent a specific blocker or a negative score here.
		if v.Pod.Stateful {
			return "R6's blind timer would DELETE this stateful pod on schedule (destroying its data); Phorvex selected no action for this pod this tick."
		}
		return "R6's blind timer would DELETE this pod on schedule regardless; Phorvex selected no action for this pod this tick."
	}
	if !selected {
		// [M-16] Fallback record: the named action is the best standalone candidate that was
		// considered and NOT selected. Nothing was chosen or executed for this pod.
		if v.Pod.Stateful {
			return fmt.Sprintf("R6's blind timer would DELETE this stateful pod on schedule (destroying its data); Phorvex considered %s but did not select it this tick — no action was chosen or executed for this pod.", a)
		}
		return fmt.Sprintf("R6's blind timer would DELETE this pod on schedule regardless; Phorvex considered %s but did not select it this tick — no action was chosen or executed for this pod.", a)
	}
	if v.Pod.Stateful && a == model.ActionQuarantine {
		return "R6's blind timer would DELETE this stateful pod on schedule (destroying its data); Phorvex selected quarantine to contain while preserving state."
	}
	switch a {
	case model.ActionRotate:
		return "R6 would rotate too, but on a blind fixed timer; Phorvex selected rotate with a strict positive marginal-value-minus-cost score."
	case model.ActionQuarantine:
		return "R6 has no path to quarantine here without a hand-written exact-match rule; Phorvex selected quarantine to cut lateral recon."
	default:
		// [HONEST-LABEL FIX] An AI-native move was previously narrated as "Phorvex skipped" — the
		// exact opposite of what happened. R6 has no non-destructive equivalent at all.
		return fmt.Sprintf("R6's blind timer would DELETE this pod on schedule; Phorvex selected %s instead, a non-destructive move (R6 has no non-destructive equivalent).", a)
	}
}

func coverageReason(a model.Action, selected bool, as killchain.Assessment, cov, ecost, gain, lambda float64) string {
	if !selected && a != model.ActionNoop {
		return fmt.Sprintf("%s: considered (reported gain=%.2f fullValue=%.2f ECost=%.2f lambdaRuntimeLegacy=%.2f); stage=%s pHold=%.2f",
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

// blindCostSource records where a decision's BlindCost came from (M-110 site 1).
func blindCostSource(v *model.WorkloadView) string {
	if v.Pod.Stateful {
		return "stateful-max"
	}
	return "tenant-calibrator"
}

// sinceEvidenceOf reports seconds since the newest timestamped event targeting the pod (T1-B).
// Absent when no such event exists — distinct from zero (a fresh event).
func sinceEvidenceOf(a killchain.Assessment) model.OptionalFloat {
	best := math.Inf(1)
	for _, e := range a.Events {
		if e.TargetsPod && e.TimestampPresent && e.AgeSec < best {
			best = e.AgeSec
		}
	}
	if math.IsInf(best, 1) {
		return model.OptionalFloat{Present: false}
	}
	return model.OptionalFloat{Present: true, Value: best}
}

// eventAgeHorizonSeconds / exposurePressureScaleSeconds mirror the killchain fallbacks so the
// trace records the horizon the model actually used (dedicated field, else the floor).
func eventAgeHorizonSeconds(pol model.Policy) float64 {
	if pol.EventAgeHorizon > 0 {
		return pol.EventAgeHorizon.Seconds()
	}
	return pol.ProactiveFloor.Seconds()
}

func exposurePressureScaleSeconds(pol model.Policy) float64 {
	if pol.ExposurePressureScale > 0 {
		return pol.ExposurePressureScale.Seconds()
	}
	return pol.ProactiveFloor.Seconds()
}

// flowRecord builds the M-115 flow basis record from the same physics functions the
// residual uses, so the record and the number cannot drift apart.
func flowRecord(v *model.WorkloadView) model.DecisionFlowV3 {
	fr := physics.FlowResidualFor(v.Pod.Namespace, v.Telemetry)
	cs := physics.Components(v)
	agg, aggPresent := physics.Aggregate(cs)
	out := model.DecisionFlowV3{
		Present: fr.Present, Basis: fr.Basis, Reason: fr.Reason,
		InFlight: traceOptional(fr.Present, fr.L), ReqRate: traceOptional(fr.Present, fr.Lambda), W: traceOptional(fr.Present, fr.W),
		WStatistic: physics.FlowWStatistic, Units: physics.FlowUnits, Window: physics.FlowWindow,
		Expected: traceOptional(fr.Present, fr.Expected), Residual: traceOptional(fr.Present, fr.Residual), Magnitude: traceOptional(fr.Present, fr.Magnitude),
		AgeSec: fr.Age.Seconds(), Aggregate: traceOptional(aggPresent, agg),
	}
	for _, c := range cs {
		out.Components = append(out.Components, model.DecisionFlowComponentV3{Name: c.Name, Present: c.Present, Magnitude: traceOptional(c.Present, c.Magnitude), Reason: c.Reason})
	}
	return out
}

// telemetryStates records every signal's presence for the M-113 record fields.
func telemetryStates(t model.Telemetry) []model.DecisionSignalStateV3 {
	sig := func(name string, s model.Signal) model.DecisionSignalStateV3 {
		return model.DecisionSignalStateV3{Signal: name, State: s.State.String(), Reason: s.Reason, Src: s.Src}
	}
	return []model.DecisionSignalStateV3{
		sig("reqRate", t.ReqRate), sig("p99Ms", t.P99Ms), sig("queueDepth", t.QueueDepth), sig("gpuUtil", t.GPUUtil),
		sig("tokensPerSec", t.TokensPerSec), sig("connCount", t.ConnCount), sig("bytesIn", t.BytesIn), sig("bytesOut", t.BytesOut),
		sig("syscallRate", t.SyscallRate),
	}
}

// pcieRecord builds the M-114 denominator record from the witness.
func pcieRecord(ph model.PhysicsWitness) model.DecisionPCIeV3 {
	return model.DecisionPCIeV3{
		Present:        ph.LinkPresent,
		Measured:       traceOptional(ph.LinkPresent || ph.LinkReason != "", ph.LinkBandwidth*ph.LinkCapacityBytesPerSec),
		Capacity:       traceOptional(ph.LinkPresent, ph.LinkCapacityBytesPerSec),
		CapacitySource: ph.LinkCapacitySource,
		Gen:            ph.LinkGen,
		Width:          ph.LinkWidth,
		Utilization:    traceOptional(ph.LinkPresent, ph.LinkBandwidth),
		Reason:         ph.LinkReason,
	}
}

// traceTime renders a bucket creation time for the decision record, using the same
// RFC3339Nano shape as the record's other timestamps. A zero time (no bucket yet, e.g. a
// shadow evaluation that never priced anything) is reported as unavailable rather than as
// the Unix epoch, so an absent unit is never mistaken for one created in 1970.
func traceTime(t time.Time) string {
	if t.IsZero() {
		return model.TraceNotAvailable
	}
	return t.UTC().Format(time.RFC3339Nano)
}
