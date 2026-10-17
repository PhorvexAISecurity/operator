// Package brainapi is the contract between the dispatcher and the brain
// (ADR-0001): what one tenant tick asks the brain, the capability questions the
// brain asks back while it generates candidates, and the owner lifecycle the
// dispatcher drives. The dispatcher depends on this package only; internal/brainsvc
// implements it in process, and over gRPC once the brain runs as its own service.
package brainapi

import (
	"time"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
)

// Gate answers the brain's per-candidate questions during one evaluation. The
// brain asks once per (asset, action) that survives its structural filters, in
// generation order; some answers run live reviews and probes, so the set and
// order of questions are part of the contract. A nil field means that gate is
// not wired.
type Gate struct {
	// Capability answers a committing evaluation. It may issue access reviews and
	// workload probes and write the shared authorization cache.
	Capability func(v *model.WorkloadView, action model.Action, coverKeys []string) *model.Eligibility
	// ShadowCapability answers a counterfactual evaluation from cached
	// authorization only.
	ShadowCapability func(v *model.WorkloadView, action model.Action, coverKeys []string) *model.Eligibility
	// FailureExclusion reports an open action-failure cooldown for (asset, action).
	FailureExclusion func(v *model.WorkloadView, action model.Action) (detail string, excluded bool)
}

// Capture marks a committing evaluation the brain may record for offline replay
// (Math Lab), subject to the brain's own allowlist.
type Capture struct {
	Spec       v1alpha1.PhorvexPolicySpec
	CapturedAt time.Time
}

// DecideRequest is one tenant tick.
type DecideRequest struct {
	Views   []*model.WorkloadView
	Policy  model.Policy
	Gate    Gate
	Capture *Capture
}

// Recording is the Math Lab snapshot of one committing evaluation. The brain
// records inputs, capability answers and raw decisions inside Decide; the
// dispatcher reports the decisions as audited after dispatch and closes it at the
// end of the tick. Both methods are safe on a recording that captures nothing.
type Recording interface {
	// Finalize records the decisions as audited after dispatch.
	Finalize(decisions []model.Decision)
	// Close hands the snapshot to the brain's store; it never blocks.
	Close()
}

// Brain is the decision service as the dispatcher sees it.
type Brain interface {
	// Name identifies the decision engine (for example "p1-coverage").
	Name() string

	// GatesCandidates reports whether Decide asks the Gate's questions; when false
	// the dispatcher builds no per-tick failure state for it.
	GatesCandidates() bool
	// Decide runs one committing evaluation. A structurally invalid action set is
	// an error, never an empty decision list. The recording is never nil.
	Decide(req DecideRequest) ([]model.Decision, Recording, error)
	// DecideShadow evaluates the same substrate without persisting learning state.
	// supported is false when the brain has no counterfactual evaluation.
	DecideShadow(req DecideRequest) (decisions []model.Decision, supported bool, err error)

	// SelectAlternative picks the fallback for a target whose dispatch the
	// actuator refused without effect, from the last committing evaluation's
	// already-gated candidates. It asks no capability question.
	SelectAlternative(owner, target string, failed model.Action) (model.Alternative, bool)
	// ReserveAlternative records a chosen fallback against the tick's resources.
	ReserveAlternative(owner, target string, failed, chosen model.Action) bool

	// LearnsRotationCost reports whether ObserveRotation trains anything.
	LearnsRotationCost() bool
	// ObserveRotation feeds one measured rotation outcome to the cost learner.
	ObserveRotation(owner string, view *model.WorkloadView, measuredFlow float64)
	// CalibrationState reports each tenant's cost-learner state.
	CalibrationState() map[string]model.CostCalibrationState
	// SetCostCalibrationFrozen applies the calibration off-switch to every tenant.
	SetCostCalibrationFrozen(frozen bool)

	// RegisterOwnerEpochs marks the current policy identities live.
	RegisterOwnerEpochs(epochs []model.PolicyEpoch)
	// ForgetOwner drops every store an owner holds after its policy is removed and
	// reports how many stores it cleared (for the removal audit).
	ForgetOwner(owner string) (storesCleared int)
	// RetainStageClock keeps kill-chain stage state only for the given assets.
	RetainStageClock(owner string, keep map[string]struct{})

	// PersistenceObservations reports whether the brain keeps the reporting-only
	// scoped-outcome store; when false the dispatcher leaves observations queued.
	PersistenceObservations() bool
	// ScopedOutcomeProcessEpochID identifies this brain process for scoped outcomes.
	ScopedOutcomeProcessEpochID() string
	// SetPersistenceAuthority installs the observed-outcome authority.
	SetPersistenceAuthority(authority model.PersistenceObservationAuthority)
	// AdmitPersistenceObservation enters one observation into the reporting-only store.
	AdmitPersistenceObservation(observation model.PersistenceObservation) model.PersistenceObservationResult
	// RecordScopedOutcomeUnavailable records why no observation arrived.
	RecordScopedOutcomeUnavailable(policy model.PolicyEpoch, reason string) model.PersistenceObservationResult
}
