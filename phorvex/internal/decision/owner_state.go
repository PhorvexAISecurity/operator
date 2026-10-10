package decision

import (
	"fmt"

	"github.com/phorvex/phorvex/internal/actionset"
	"github.com/phorvex/phorvex/internal/cost"
	"github.com/phorvex/phorvex/internal/killchain"
	"github.com/phorvex/phorvex/internal/model"
)

// OwnerState is every piece of engine-held state one owner's decision reads: the cost
// bucket (RLS, conformal window, runtime lambda), its creation record, the calibration
// freeze, the kill-chain stage-dwell slots and the conjugate prior. It exists so the Math
// Lab can record a production tick and replay it offline on a fresh engine. Exporting is a
// pure copy (no seed is consumed, no prior is seeded, no clock is folded).
type OwnerState struct {
	Owner             string
	HasBucket         bool
	Bucket            cost.P1CostState
	HasMeta           bool
	Meta              BucketMeta
	AliasHolder       bool
	CreationEvent     uint64
	CalibrationFrozen bool
	StageClock        []killchain.StageClockEntry
	Conjugate         killchain.ConjugateState
}

// ExportOwnerState copies one owner's engine state without changing it.
func (e *CoverageEngine) ExportOwnerState(owner string) OwnerState {
	out := OwnerState{Owner: owner, CreationEvent: e.creationEvent, CalibrationFrozen: e.calibrationFrozen,
		AliasHolder: e.aliasOwner == owner && owner != ""}
	if c := e.costByOwner[owner]; c != nil {
		out.HasBucket, out.Bucket = true, c.State()
	}
	if meta, ok := e.bucketMeta[owner]; ok {
		out.HasMeta, out.Meta = true, meta
	}
	if e.Killchain != nil {
		out.StageClock = e.Killchain.StageClock.OwnerEntries(owner)
		out.Conjugate = e.Killchain.Memory.OwnerState(owner)
	}
	return out
}

// RestoreOwnerState installs an exported owner state on an engine that has never priced
// anything. Restoring into a used engine is refused: merging a recorded owner into live
// state would let a replay alter production learning.
func (e *CoverageEngine) RestoreOwnerState(s OwnerState) error {
	if s.Owner == "" {
		return fmt.Errorf("owner state has no owner")
	}
	if len(e.costByOwner) != 0 || len(e.bucketMeta) != 0 || e.creationEvent != 0 || e.aliasOwner != "" {
		return fmt.Errorf("owner state can only be restored into a fresh engine")
	}
	if e.Killchain == nil {
		return fmt.Errorf("engine has no kill-chain model")
	}
	memory, err := killchain.RestoreConjugateMemory(s.Owner, s.Conjugate)
	if err != nil {
		return fmt.Errorf("conjugate memory: %w", err)
	}
	clock := killchain.NewStageClock()
	if err := clock.RestoreOwnerEntries(s.Owner, s.StageClock); err != nil {
		return fmt.Errorf("stage clock: %w", err)
	}
	if s.HasBucket {
		bucket, err := cost.RestoreP1Cost(s.Bucket)
		if err != nil {
			return fmt.Errorf("cost bucket: %w", err)
		}
		e.costByOwner = map[string]*cost.P1Cost{s.Owner: bucket}
		if s.AliasHolder {
			e.Cost, e.aliasOwner = bucket, s.Owner
		} else {
			e.aliasRetired = true
		}
	}
	if s.HasMeta {
		e.bucketMeta = map[string]BucketMeta{s.Owner: s.Meta}
	}
	e.creationEvent = s.CreationEvent
	e.calibrationFrozen = s.CalibrationFrozen
	e.Killchain.Memory = memory
	e.Killchain.StageClock = clock
	return nil
}

// AssembleSetShadow generates the action set exactly as a shadow evaluation would: it reads
// the existing owner state, creates none, folds no clock and writes no view. The Math Lab
// replay uses it to attribute every candidate's first veto gate.
//
// It also returns, per asset key, a copy of the view as the generator read it: carrying the
// event-evidence stamp the proactive-cadence law consults. A per-law diagnostic evaluated on
// the caller's unstamped view would report a cadence veto the generator never applied.
func (e *CoverageEngine) AssembleSetShadow(views []*model.WorkloadView, pol model.Policy) (actionset.ActionSet, map[string]*model.WorkloadView, error) {
	if e.ownerAbsent(pol.Owner()) {
		return actionset.ActionSet{}, nil, ErrOwnerRetired
	}
	tcost := e.costForMode(pol.Owner(), killchain.EvalShadow, pol.Lambda)
	set, ctxByKey, err := e.assembleSet(views, pol, tcost, killchain.EvalShadow)
	gated := make(map[string]*model.WorkloadView, len(views))
	for _, v := range views {
		key := v.Pod.Namespace + "/" + v.Pod.Name
		ac, ok := ctxByKey[key]
		if !ok {
			continue
		}
		local := *v
		local.HasEventEvidence = ac.assess.HasEventEvidence
		gated[key] = &local
	}
	return set, gated, err
}

// CostForShadow returns the bucket a shadow evaluation would price against without
// creating one, for pure diagnostic cost evaluation.
func (e *CoverageEngine) CostForShadow(pol model.Policy) *cost.P1Cost {
	return e.costForMode(pol.Owner(), killchain.EvalShadow, pol.Lambda)
}
