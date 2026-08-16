package decision

import (
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

func TestCoverageEngineRejectsCrossBlockCollision(t *testing.T) {
	engine := NewCoverageEngine()
	engine.Recon = adversarialSharedRecon{}
	policy := covPolicy(2)
	policy.EnabledActions = map[model.Action]bool{model.ActionRotate: true}

	decisions, err := engine.DecideChecked(adversarialTopology()[:2], policy)
	if err == nil {
		t.Fatal("DecideChecked accepted an ActionSet with a cross-block collision")
	}
	if decisions != nil {
		t.Fatalf("rejected tick emitted %d decisions", len(decisions))
	}
}
