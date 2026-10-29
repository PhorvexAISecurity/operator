package cost

import (
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

func statefulFlowView(ready int, contract model.StatefulRotationContract) *model.WorkloadView {
	return &model.WorkloadView{Pod: model.Pod{StatefulRotation: &model.StatefulRotationObservation{
		Contract: contract, Replicas: ready, ReadyReplicas: ready, Complete: true}}}
}

// The stateful recovery flow is availability x time: one member of N for its declared phase.
func TestStatefulRecoveryFlowTradesAvailabilityAgainstTime(t *testing.T) {
	c := model.StatefulRotationContract{RecoverySeconds: 120, ResyncSeconds: 1800}
	rebuild := statefulRecoveryFlow(statefulFlowView(3, c), model.ActionStatefulReplicaRebuild)
	restartReplicated := statefulRecoveryFlow(statefulFlowView(3, c), model.ActionStatefulSnapshotRotate)
	restartSingle := statefulRecoveryFlow(statefulFlowView(1, c), model.ActionStatefulSnapshotRotate)
	if want := statefulRecoveryBase + statefulRecoverySpan/3; rebuild != want {
		t.Fatalf("rebuild of 1/3 for a saturated resync = %v, want %v", rebuild, want)
	}
	if !(restartReplicated < rebuild) {
		t.Fatalf("a 2-minute restart must cost less than a 30-minute resync on the same set: %v vs %v", restartReplicated, rebuild)
	}
	if !(restartSingle > restartReplicated) {
		t.Fatalf("a single writer's restart removes the whole service: %v vs %v", restartSingle, restartReplicated)
	}
	short := c
	short.ResyncSeconds = 60
	if !(statefulRecoveryFlow(statefulFlowView(3, short), model.ActionStatefulReplicaRebuild) < rebuild) {
		t.Fatal("a shorter declared resync must price lower")
	}
	if got := statefulRecoveryFlow(&model.WorkloadView{}, model.ActionStatefulCheckpointHandoff); got != unknownActionFlowMax {
		t.Fatalf("no observation must price at the conservative maximum, got %v", got)
	}
	for _, a := range model.StatefulRotationActions {
		if ActionFlowFamily(a) != "stateful-recovery" {
			t.Fatalf("%s routed to %s", a, ActionFlowFamily(a))
		}
	}
}
