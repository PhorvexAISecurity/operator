package decision

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

func TestPodBoundAPIAuthReactiveGateUsesTypedAdmission(t *testing.T) {
	pod := model.Pod{Namespace: "owned", Name: "source", UID: "pod-uid", PodResourceVersion: "23", ServiceAccount: "reader",
		PodBoundKubeAPIAuth: &model.PodBoundKubeAPIAuthProjection{PodUID: "pod-uid", PodResourceVersion: "23",
			ServiceAccountName: "reader", ServiceAccountUID: "sa-uid", VolumeName: "api-token",
			MountedContainer: "app", AudienceSource: "kube-apiserver-default", EvidenceSource: "admitted-pod-and-serviceaccount"}}
	event := model.SecurityEventInfo{Name: "observed", UID: "event-uid", Type: model.AttackVectorPodBoundAPIAuth,
		Trust: "trusted", CreatorIdentity: "system:serviceaccount:owned:detector",
		CreatedAt: time.Unix(1, 0), Age: 8 * time.Minute, TargetsPod: true,
		ConsoleTargetPodUID: "pod-uid", ResolvedTargets: []string{"owned/source"}}
	backed := func(e model.SecurityEventInfo, p model.Pod) bool {
		return hasDirectFoothold([]model.SecurityEventInfo{e}, p, 10*time.Minute)
	}
	if !backed(event, pod) {
		t.Fatal("qualified token event should satisfy direct reactive evidence")
	}
	stale := event
	stale.Age = 10 * time.Minute
	wrong := event
	wrong.ConsoleTargetPodUID = "former-pod"
	noWitness := pod
	noWitness.PodBoundKubeAPIAuth = nil
	for _, tc := range []struct {
		name  string
		event model.SecurityEventInfo
		pod   model.Pod
	}{{"stale", stale, pod}, {"wrong UID", wrong, pod}, {"no current witness", event, noWitness}} {
		t.Run(tc.name, func(t *testing.T) {
			if backed(tc.event, tc.pod) {
				t.Fatal("unqualified token event satisfied reactive-only gate")
			}
		})
	}
	// The new rule must leave other established event types unchanged.
	other := model.SecurityEventInfo{Type: "existing-alert", TargetsPod: true}
	if !backed(other, model.Pod{}) {
		t.Fatal("existing direct event no longer satisfies reactive gate")
	}
}
