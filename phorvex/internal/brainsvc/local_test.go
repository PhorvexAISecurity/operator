package brainsvc

import (
	"errors"
	"testing"

	"github.com/phorvex/phorvex/internal/brainapi"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/model"
)

type rejectingCheckedOptimizer struct {
	uncheckedCalled bool
}

func (*rejectingCheckedOptimizer) Name() string { return "test-rejecting" }
func (o *rejectingCheckedOptimizer) Decide(_ []*model.WorkloadView, _ model.Policy) []model.Decision {
	o.uncheckedCalled = true
	return []model.Decision{{Selected: true}}
}
func (*rejectingCheckedOptimizer) DecideChecked(_ []*model.WorkloadView, _ model.Policy) ([]model.Decision, error) {
	return nil, errors.New("cross-block collision")
}

type plainOptimizer struct{}

func (plainOptimizer) Name() string { return "test-plain" }
func (plainOptimizer) Decide(_ []*model.WorkloadView, _ model.Policy) []model.Decision {
	return []model.Decision{{Selected: true, Action: model.ActionRotate}}
}

func TestCheckedRejectionNeverFallsBackToUncheckedDecide(t *testing.T) {
	optimizer := &rejectingCheckedOptimizer{}
	decisions, recording, err := NewLocal(optimizer, nil).Decide(brainapi.DecideRequest{})
	if err == nil {
		t.Fatal("checked optimizer collision accepted")
	}
	if decisions != nil {
		t.Fatalf("rejected evaluation returned %d decisions", len(decisions))
	}
	if optimizer.uncheckedCalled {
		t.Fatal("fell back to unchecked Decide after checked rejection")
	}
	recording.Finalize(nil) // a recording that captures nothing is still safe to use
	recording.Close()
}

func TestPlainOptimizerAnswersDecideAndLacksCoverageOperations(t *testing.T) {
	b := NewLocal(plainOptimizer{}, nil)
	decisions, recording, err := b.Decide(brainapi.DecideRequest{})
	if err != nil || len(decisions) != 1 || !decisions[0].Selected || recording == nil {
		t.Fatalf("decide = %v, %v, %v", decisions, recording, err)
	}
	if _, supported, err := b.DecideShadow(brainapi.DecideRequest{}); supported || err != nil {
		t.Fatalf("plain optimizer reported a shadow evaluation: supported=%v err=%v", supported, err)
	}
	if b.GatesCandidates() || b.LearnsRotationCost() || b.PersistenceObservations() {
		t.Fatal("plain optimizer claims coverage-engine capabilities")
	}
	if _, ok := b.SelectAlternative("owner", "ns/pod", model.ActionRotate); ok {
		t.Fatal("plain optimizer produced an alternative")
	}
	if b.ForgetOwner("owner") != 0 || b.CalibrationState() != nil {
		t.Fatal("plain optimizer reported coverage state")
	}
}

func TestGateIsInstalledOnlyForTheEvaluation(t *testing.T) {
	ce := decision.NewCoverageEngine()
	b := NewLocal(ce, nil)
	gate := brainapi.Gate{
		Capability:       func(*model.WorkloadView, model.Action, []string) *model.Eligibility { return nil },
		ShadowCapability: func(*model.WorkloadView, model.Action, []string) *model.Eligibility { return nil },
		FailureExclusion: func(*model.WorkloadView, model.Action) (string, bool) { return "", false },
	}
	if !b.GatesCandidates() || !b.LearnsRotationCost() || !b.PersistenceObservations() {
		t.Fatal("coverage engine must report its capabilities")
	}
	// The outcome of this minimal evaluation is irrelevant; the gate must be gone afterwards
	// whether the engine decided or refused.
	_, _, _ = b.Decide(brainapi.DecideRequest{Policy: model.Policy{Tenant: "t"}, Gate: gate})
	if ce.Capability != nil || ce.ShadowCapability != nil || ce.FailureExclusion != nil {
		t.Fatal("gate stayed installed on the engine after Decide returned")
	}
	if b.ForgetOwner("t") != 3 {
		t.Fatal("coverage engine must report the three owner stores it clears")
	}
	if got := b.Engine(); got != ce {
		t.Fatal("Engine must return the served coverage engine")
	}
}
