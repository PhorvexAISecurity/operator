package recon

import (
	"sort"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
)

// statefulReplicatedView is a Ready member of a 3-replica StatefulSet that declares quorum 2,
// peer-resync rebuild and a snapshot class, mounting one template claim.
func statefulReplicatedView() *model.WorkloadView {
	return &model.WorkloadView{Physics: model.NeutralPhysics(), Pod: model.Pod{
		Namespace: "ns", Name: "db-1", UID: "db-1-uid", Node: "node-a", Ready: true, Stateful: true,
		StatefulRotation: &model.StatefulRotationObservation{
			Contract:  model.StatefulRotationContract{Quorum: 2, PeerResync: true, SnapshotClass: "csi", RecoverySeconds: 120, ResyncSeconds: 600},
			OwnerName: "db", OwnerUID: "db-uid", Replicas: 3, ReadyReplicas: 3, SnapshotClassReady: true, Complete: true,
			Claims: []model.StatefulClaim{{Name: "data-db-1", UID: "claim-uid", Bound: true, FromTemplate: true}},
		}}}
}

// statefulCheckpointView is a volume-less single-member StatefulSet declaring a checkpoint.
func statefulCheckpointView() *model.WorkloadView {
	return &model.WorkloadView{Physics: model.NeutralPhysics(), Pod: model.Pod{
		Namespace: "ns", Name: "worker-0", UID: "worker-uid", Node: "node-a", Ready: true, Stateful: true,
		StatefulRotation: &model.StatefulRotationObservation{
			Contract:  model.StatefulRotationContract{CheckpointPort: 8080, CheckpointPath: "/checkpoint", RestorePath: "/restore", RecoverySeconds: 60, ResyncSeconds: 3600},
			OwnerName: "worker", OwnerUID: "worker-owner-uid", Replicas: 1, ReadyReplicas: 1, Complete: true,
		}}}
}

func statefulFctx() FactContext {
	return FactContext{AssetValue: 10, PHold: 1, StageUrgency: 1, LateralUrgency: 1, Stateful: true}
}

func coverKinds(t *testing.T, af AssetFacts, a model.Action) []string {
	t.Helper()
	kindOf := map[string]string{}
	for _, f := range af.Facts {
		kindOf[f.Key()] = f.Kind
	}
	var kinds []string
	for _, k := range af.CoverByAction[a] {
		kind, ok := kindOf[k]
		if !ok {
			t.Fatalf("%s covers unminted fact %q", a, k)
		}
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	return kinds
}

func TestStatefulRotationCoverIsMechanismExact(t *testing.T) {
	for _, profile := range Registry.All() {
		replicated := profile.AssetFacts(statefulReplicatedView(), statefulFctx())
		want := map[model.Action][]string{
			model.ActionStatefulReplicaRebuild:    {FactInMemory, FactPersistentVolumeState, FactPodIdentity, FactSession},
			model.ActionStatefulSnapshotRotate:    {FactInMemory, FactPodIdentity, FactSession},
			model.ActionStatefulCheckpointHandoff: nil, // volume-backed: no handoff cover
		}
		for a, kinds := range want {
			if got := coverKinds(t, replicated, a); !equalStrings(got, kinds) {
				t.Errorf("%s/replicated %s cover=%v, want %v", profile.Name(), a, got, kinds)
			}
		}
		if got, rotate := coverKinds(t, replicated, model.ActionStatefulSnapshotRotate), coverKinds(t, replicated, model.ActionRotate); !equalStrings(got, rotate) {
			t.Errorf("%s: snapshot-rotate must invalidate exactly rotate's process facts: %v vs %v", profile.Name(), got, rotate)
		}

		checkpointed := profile.AssetFacts(statefulCheckpointView(), statefulFctx())
		if got := coverKinds(t, checkpointed, model.ActionStatefulCheckpointHandoff); !equalStrings(got, []string{FactInMemory, FactPodIdentity}) {
			t.Errorf("%s/checkpointed handoff cover=%v: the carried session state must not be covered", profile.Name(), got)
		}
		for _, a := range []model.Action{model.ActionStatefulReplicaRebuild, model.ActionStatefulSnapshotRotate} {
			if got := coverKinds(t, checkpointed, a); len(got) != 0 {
				t.Errorf("%s/checkpointed %s has volume cover without claims: %v", profile.Name(), a, got)
			}
		}
		for _, f := range checkpointed.Facts {
			if f.Kind == FactPersistentVolumeState {
				t.Errorf("%s: volume-state fact minted for a volume-less member", profile.Name())
			}
		}
	}
}

func TestStatefulRotationCoverRequiresDeclaredContract(t *testing.T) {
	undeclared := statefulReplicatedView()
	undeclared.Pod.StatefulRotation = nil
	invalid := statefulReplicatedView()
	invalid.Pod.StatefulRotation.Invalid = "malformed"
	for _, view := range []*model.WorkloadView{undeclared, invalid} {
		for _, profile := range Registry.All() {
			af := profile.AssetFacts(view, statefulFctx())
			for _, a := range model.StatefulRotationActions {
				if len(af.CoverByAction[a]) != 0 {
					t.Errorf("%s: %s has cover without a valid contract", profile.Name(), a)
				}
			}
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
