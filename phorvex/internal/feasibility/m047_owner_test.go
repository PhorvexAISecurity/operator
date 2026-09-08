package feasibility

import (
	"github.com/phorvex/phorvex/internal/model"
	"testing"
)

func TestM47NativeOwnershipVeto(t *testing.T) {
	law := nativeRotationOwner{}
	v := &model.WorkloadView{}
	m := model.Move{Action: model.ActionRotate}
	p := model.Policy{NativeRotate: true}
	if law.Check(v, m, p).Feasible {
		t.Fatal("unknown owner passed")
	}
	v.Pod.RotationOwnership = model.RotationOwnership{Eligible: true}
	if !law.Check(v, m, p).Feasible {
		t.Fatal("supported owner vetoed")
	}
	v.Pod.RotationOwnership = model.RotationOwnership{Reason: "ownerless"}
	if law.Check(v, m, p).Feasible {
		t.Fatal("ownerless passed")
	}
	if !law.Check(v, model.Move{Action: model.ActionQuarantine}, p).Feasible {
		t.Fatal("unrelated action changed")
	}
}
