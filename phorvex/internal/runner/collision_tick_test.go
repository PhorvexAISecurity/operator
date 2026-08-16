package runner

import (
	"errors"
	"testing"

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

func TestTickUsesCheckedOptimizerAndRejectsCollision(t *testing.T) {
	optimizer := &rejectingCheckedOptimizer{}
	decisions, err := decideTick(optimizer, nil, model.Policy{})
	if err == nil {
		t.Fatal("tick accepted checked optimizer collision")
	}
	if decisions != nil {
		t.Fatalf("rejected tick returned %d decisions", len(decisions))
	}
	if optimizer.uncheckedCalled {
		t.Fatal("tick fell back to unchecked Decide after checked rejection")
	}
}
