// Package brainsvc serves the brainapi contract from a decision engine. Local runs
// the engine in the caller's process; the brain service's gRPC server serves the
// same adapter so both paths share one implementation of the contract.
package brainsvc

import (
	"sync"

	"github.com/phorvex/phorvex/internal/brainapi"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/mathlab"
	"github.com/phorvex/phorvex/internal/model"
)

// Local adapts an optimizer to brainapi.Brain. A *decision.CoverageEngine gets
// the full contract; any other optimizer answers Decide and treats the
// coverage-only operations as absent, exactly as the runner did when its type
// assertions failed. Calls are serialized: the engine is stateful.
type Local struct {
	mu       sync.Mutex
	opt      decision.Optimizer
	ce       *decision.CoverageEngine
	recorder *mathlab.Recorder
}

var _ brainapi.Brain = (*Local)(nil)

// NewLocal serves opt in process. recorder may be nil (Math Lab off).
func NewLocal(opt decision.Optimizer, recorder *mathlab.Recorder) *Local {
	l := &Local{opt: opt, recorder: recorder}
	l.ce, _ = opt.(*decision.CoverageEngine)
	return l
}

// Engine returns the coverage engine, or nil for another optimizer.
func (l *Local) Engine() *decision.CoverageEngine { return l.ce }

func (l *Local) Name() string { return l.opt.Name() }

func (l *Local) GatesCandidates() bool { return l.ce != nil }

// withGate installs one request's gate on the engine and returns the restore.
func (l *Local) withGate(g brainapi.Gate) func() {
	if l.ce == nil {
		return func() {}
	}
	capability, shadow, failure := l.ce.Capability, l.ce.ShadowCapability, l.ce.FailureExclusion
	l.ce.Capability, l.ce.ShadowCapability, l.ce.FailureExclusion = g.Capability, g.ShadowCapability, g.FailureExclusion
	return func() {
		l.ce.Capability, l.ce.ShadowCapability, l.ce.FailureExclusion = capability, shadow, failure
	}
}

func (l *Local) Decide(req brainapi.DecideRequest) ([]model.Decision, brainapi.Recording, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ce == nil {
		if checked, ok := l.opt.(decision.CheckedOptimizer); ok {
			decisions, err := checked.DecideChecked(req.Views, req.Policy)
			return decisions, noRecording{}, err
		}
		return l.opt.Decide(req.Views, req.Policy), noRecording{}, nil
	}
	defer l.withGate(req.Gate)()
	var capture *mathlab.TickCapture
	if req.Capture != nil {
		capture = l.recorder.Begin(l.ce, req.Capture.Spec, req.Views, req.Policy, req.Capture.CapturedAt)
	}
	decisions, err := l.ce.DecideChecked(req.Views, req.Policy)
	if capture == nil {
		return decisions, noRecording{}, err
	}
	capture.Decided(decisions, err)
	return decisions, capture, err
}

func (l *Local) DecideShadow(req brainapi.DecideRequest) ([]model.Decision, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	shadow, ok := l.opt.(decision.ShadowCheckedOptimizer)
	if !ok {
		return nil, false, nil
	}
	defer l.withGate(req.Gate)()
	decisions, err := shadow.DecideShadowChecked(req.Views, req.Policy)
	return decisions, true, err
}

func (l *Local) SelectAlternative(owner, target string, failed model.Action) (model.Alternative, bool) {
	if l.ce == nil {
		return model.Alternative{}, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.ce.SelectAlternative(owner, target, failed)
}

func (l *Local) ReserveAlternative(owner, target string, failed, chosen model.Action) bool {
	if l.ce == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.ce.ReserveAlternative(owner, target, failed, chosen)
}

func (l *Local) LearnsRotationCost() bool {
	_, ok := l.opt.(decision.RotationObserver)
	return ok
}

func (l *Local) ObserveRotation(owner string, view *model.WorkloadView, measuredFlow float64) {
	observer, ok := l.opt.(decision.RotationObserver)
	if !ok {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	observer.ObserveRotation(owner, view, measuredFlow)
}

func (l *Local) CalibrationState() map[string]model.CostCalibrationState {
	if l.ce == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.ce.CalibrationState()
}

func (l *Local) SetCostCalibrationFrozen(frozen bool) {
	if l.ce == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ce.SetCostCalibrationFrozen(frozen)
}

func (l *Local) RegisterOwnerEpochs(epochs []model.PolicyEpoch) {
	if l.ce == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, epoch := range epochs {
		// Preserve the established lifecycle guard even for directly constructed
		// offline fixtures with incomplete epochs. Stored API objects have complete
		// identity and positive generation, so production also registers the exact
		// observed-outcome epoch.
		l.ce.SetOwnerLive(epoch.Owner(), true)
		_ = l.ce.SetOwnerEpoch(epoch, true)
	}
}

func (l *Local) ForgetOwner(owner string) int {
	if l.ce == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ce.ForgetOwner(owner) // cost bucket + belief prior + stage clock + alias retirement
	return 3
}

func (l *Local) RetainStageClock(owner string, keep map[string]struct{}) {
	if l.ce == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ce.RetainStageClock(owner, keep)
}

func (l *Local) PersistenceObservations() bool { return l.ce != nil }

func (l *Local) ScopedOutcomeProcessEpochID() string {
	if l.ce == nil {
		return ""
	}
	return l.ce.ScopedOutcomeProcessEpochID()
}

func (l *Local) SetPersistenceAuthority(authority model.PersistenceObservationAuthority) {
	if l.ce == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ce.PersistenceAuthority = authority
}

func (l *Local) AdmitPersistenceObservation(observation model.PersistenceObservation) model.PersistenceObservationResult {
	if l.ce == nil {
		return model.PersistenceObservationResult{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.ce.AdmitPersistenceObservation(observation)
}

func (l *Local) RecordScopedOutcomeUnavailable(policy model.PolicyEpoch, reason string) model.PersistenceObservationResult {
	if l.ce == nil {
		return model.PersistenceObservationResult{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.ce.RecordScopedOutcomeUnavailable(policy, reason)
}

// noRecording is the recording of an evaluation nothing captures.
type noRecording struct{}

func (noRecording) Finalize([]model.Decision) {}
func (noRecording) Close()                    {}
