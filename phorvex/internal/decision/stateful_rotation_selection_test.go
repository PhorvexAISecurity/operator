package decision

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
)

// statefulSelectionView is a held stateful member past its proactive floor with no lateral
// neighbour, so the in-pod foothold (not lateral movement) is the threat being answered.
func statefulSelectionView(replicas, ready int, contract model.StatefulRotationContract, claims bool) *model.WorkloadView {
	v := covView("db-1", true, 2*time.Hour, true)
	v.Neighbors = nil
	v.Pod.DesiredReplicas, v.Pod.ReadyReplicas = replicas, ready
	o := &model.StatefulRotationObservation{Contract: contract, OwnerName: "db", OwnerUID: "db-uid",
		Replicas: replicas, ReadyReplicas: ready, SnapshotClassReady: contract.SnapshotClass != "", SinceMemberReady: time.Hour, Complete: true}
	if claims {
		o.Claims = []model.StatefulClaim{{Name: "data-db-1", UID: "claim-uid", Bound: true, FromTemplate: true}}
	}
	v.Pod.StatefulRotation = o
	return v
}

func statefulSelectionPolicy(minAvailable int) model.Policy {
	pol := covPolicy(1)
	pol.MinAvailableReplicas = minAvailable
	pol.EnabledActions = map[model.Action]bool{
		model.ActionRotate: true, model.ActionQuarantine: true,
		model.ActionStatefulReplicaRebuild: true, model.ActionStatefulSnapshotRotate: true, model.ActionStatefulCheckpointHandoff: true,
	}
	return pol
}

func pricedPolicy(lambda float64) model.Policy {
	pol := statefulSelectionPolicy(1)
	pol.Lambda = lambda
	return pol
}

func selectedAction(t *testing.T, e *CoverageEngine, v *model.WorkloadView, pol model.Policy) model.Action {
	t.Helper()
	selected := model.ActionNoop
	for _, d := range e.Decide([]*model.WorkloadView{v}, pol) {
		if d.Selected {
			if selected != model.ActionNoop {
				t.Fatalf("more than one selected action: %s and %s", selected, d.Action)
			}
			selected = d.Action
		}
	}
	return selected
}

// TestStatefulRotationClassSelection proves the unmodified engine chooses the stateful class
// from live conditions alone — cover (what the class invalidates), availability/time cost and
// the shared admission law — with every class enabled and no per-scenario tuning:
//
//   - a healthy replicated member is REBUILT from its peers (the only class that also clears
//     the persisted volume state, at 1/N of the set's availability);
//   - the leader cannot be rebuilt, so it is restarted behind a ready snapshot;
//   - a degraded set or a set mid-rollout keeps the member and contains it with quarantine
//     (state preserved);
//   - a single writer restarts behind a snapshot only when its policy accepts the downtime;
//     under an availability floor of 1 no replica-removing move (quarantine included) is
//     admissible, so the engine holds;
//   - under a high disruption price a long declared resync makes the snapshot restart
//     cheaper than the rebuild, so time decides between the volume-backed classes;
//   - volume-less state is handed over through its checkpoint;
//   - without a contract nothing in the family is offered and plain rotate stays refused.
func TestStatefulRotationClassSelection(t *testing.T) {
	replicated := model.StatefulRotationContract{Quorum: 2, PeerResync: true, LeaderLabelKey: "role", LeaderLabelValue: "primary",
		SnapshotClass: "csi", RecoverySeconds: 120, ResyncSeconds: 600}
	single := model.StatefulRotationContract{SnapshotClass: "csi", RecoverySeconds: 120, ResyncSeconds: 3600}
	checkpointed := model.StatefulRotationContract{CheckpointPort: 8080, CheckpointPath: "/checkpoint", RestorePath: "/restore",
		RecoverySeconds: 60, ResyncSeconds: 3600}

	type scenario struct {
		name   string
		view   func() *model.WorkloadView
		policy model.Policy
		want   model.Action
	}
	scenarios := []scenario{
		{"healthy replicated member", func() *model.WorkloadView { return statefulSelectionView(3, 3, replicated, true) },
			statefulSelectionPolicy(1), model.ActionStatefulReplicaRebuild},
		{"replicated leader", func() *model.WorkloadView {
			v := statefulSelectionView(3, 3, replicated, true)
			o := v.Pod.StatefulRotation
			o.Leader = true
			return v
		}, statefulSelectionPolicy(1), model.ActionStatefulSnapshotRotate},
		{"degraded replicated set", func() *model.WorkloadView { return statefulSelectionView(3, 2, replicated, true) },
			statefulSelectionPolicy(1), model.ActionQuarantine},
		{"replicated set mid-rollout", func() *model.WorkloadView {
			v := statefulSelectionView(3, 3, replicated, true)
			v.Pod.StatefulRotation.RolloutInProgress = true
			return v
		}, statefulSelectionPolicy(1), model.ActionQuarantine},
		{"single writer, downtime accepted", func() *model.WorkloadView { return statefulSelectionView(1, 1, single, true) },
			statefulSelectionPolicy(0), model.ActionStatefulSnapshotRotate},
		// Quarantine also takes the only replica out of service, so the policy floor vetoes
		// every replica-removing move and the engine holds rather than breach availability.
		{"single writer, availability floor 1", func() *model.WorkloadView { return statefulSelectionView(1, 1, single, true) },
			statefulSelectionPolicy(1), model.ActionNoop},
		{"volume-less checkpointed pair", func() *model.WorkloadView { return statefulSelectionView(2, 2, checkpointed, false) },
			statefulSelectionPolicy(1), model.ActionStatefulCheckpointHandoff},
		// Time: under a high disruption price the declared resync duration decides between the
		// two volume-backed classes. A one-minute peer resync still earns the rebuild; a
		// half-hour resync is priced above the snapshot restart's two-minute recovery.
		{"short resync, high disruption price", func() *model.WorkloadView {
			c := replicated
			c.ResyncSeconds = 60
			return statefulSelectionView(3, 3, c, true)
		}, pricedPolicy(3), model.ActionStatefulReplicaRebuild},
		{"long resync, high disruption price", func() *model.WorkloadView {
			c := replicated
			c.ResyncSeconds = 1800
			return statefulSelectionView(3, 3, c, true)
		}, pricedPolicy(3), model.ActionStatefulSnapshotRotate},
		{"no contract", func() *model.WorkloadView {
			v := statefulSelectionView(3, 3, replicated, true)
			v.Pod.StatefulRotation = nil
			return v
		}, statefulSelectionPolicy(1), model.ActionQuarantine},
	}
	for _, profile := range []string{"standard-recon", "ucw-recon"} {
		rp, ok := recon.Registry.Get(profile)
		if !ok {
			t.Fatalf("missing recon profile %s", profile)
		}
		for _, s := range scenarios {
			// The engine carries calibration state across ticks; each scenario is a first tick.
			e := NewCoverageEngine()
			e.Recon = rp
			if got := selectedAction(t, e, s.view(), s.policy); got != s.want {
				t.Errorf("%s/%s: selected %q, want %q", profile, s.name, got, s.want)
			}
		}
	}
}

// TestStatefulRotationNeverSelectsPlainRotate pins the preserved invariant: whatever the
// contract, plain rotate (a blind delete of single-writer state) is never chosen for a
// stateful member, and the family never acts on a member whose owner did not declare it.
func TestStatefulRotationNeverSelectsPlainRotate(t *testing.T) {
	contracts := []model.StatefulRotationContract{
		{Quorum: 2, PeerResync: true, SnapshotClass: "csi", RecoverySeconds: 120, ResyncSeconds: 600},
		{SnapshotClass: "csi", RecoverySeconds: 120, ResyncSeconds: 3600},
	}
	for _, c := range contracts {
		for _, ready := range []int{1, 2, 3} {
			v := statefulSelectionView(3, ready, c, true)
			for _, minAvailable := range []int{0, 1, 2} {
				if got := selectedAction(t, NewCoverageEngine(), v, statefulSelectionPolicy(minAvailable)); got == model.ActionRotate {
					t.Fatalf("plain rotate selected for a stateful member (contract %+v, ready %d, floor %d)", c, ready, minAvailable)
				}
			}
		}
	}
}
