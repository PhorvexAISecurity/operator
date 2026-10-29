package feasibility

import (
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

func statefulMemberView() *model.WorkloadView {
	return &model.WorkloadView{Physics: model.NeutralPhysics(), Pod: model.Pod{
		Namespace: "ns", Name: "db-1", UID: "db-1-uid", Ready: true, Stateful: true, DesiredReplicas: 3, ReadyReplicas: 3,
		StatefulRotation: &model.StatefulRotationObservation{
			Contract:  model.StatefulRotationContract{Quorum: 2, PeerResync: true, SnapshotClass: "csi", RecoverySeconds: 60, ResyncSeconds: 600},
			OwnerName: "db", OwnerUID: "db-uid", Replicas: 3, ReadyReplicas: 3, SnapshotClassReady: true, Complete: true,
			Claims: []model.StatefulClaim{{Name: "data-db-1", UID: "claim-uid", Bound: true, FromTemplate: true}},
		}}}
}

// The family is governed by the shared admission law, the availability floor and the
// Eviction-specific PDB rules; plain rotate remains refused on the same stateful member.
func TestStatefulRotationFeasibility(t *testing.T) {
	pol := model.Policy{MinAvailableReplicas: 1}
	for _, a := range []model.Action{model.ActionStatefulReplicaRebuild, model.ActionStatefulSnapshotRotate} {
		if v := Evaluate(statefulMemberView(), model.Move{Action: a}, pol); !v.Feasible {
			t.Fatalf("%s refused on a healthy member: %s", a, v.Reason)
		}
		degraded := statefulMemberView()
		degraded.Pod.StatefulRotation.ReadyReplicas = 2
		if v := Evaluate(degraded, model.Move{Action: a}, pol); v.Feasible || !strings.HasPrefix(v.Reason, "stateful-rotation-admission:") {
			t.Fatalf("%s on a degraded set: %+v", a, v)
		}
		floor := statefulMemberView()
		if v := Evaluate(floor, model.Move{Action: a}, model.Policy{MinAvailableReplicas: 3}); v.Feasible || !strings.HasPrefix(v.Reason, "availability:") {
			t.Fatalf("%s must honour the policy availability floor: %+v", a, v)
		}
		overlapping := statefulMemberView()
		overlapping.Physics.PDBMatched, overlapping.Physics.PDBMatchCount, overlapping.Physics.PDBDisruptionsAllowed = true, 2, 1
		if v := Evaluate(overlapping, model.Move{Action: a}, pol); v.Feasible || !strings.Contains(v.Reason, "overlapping budgets") {
			t.Fatalf("%s evicts and must refuse overlapping PDBs: %+v", a, v)
		}
	}
	if v := Evaluate(statefulMemberView(), model.Move{Action: model.ActionRotate}, pol); v.Feasible || !strings.HasPrefix(v.Reason, "stateful-integrity:") {
		t.Fatalf("plain rotate must stay refused on a stateful member: %+v", v)
	}
	if !RemovesReadyReplica(model.ActionStatefulCheckpointHandoff) || ExposureVarFor(model.ActionStatefulReplicaRebuild) != model.VarPodIdentity {
		t.Fatal("stateful family must count as replica-removing and read the pod-identity clock")
	}
}
