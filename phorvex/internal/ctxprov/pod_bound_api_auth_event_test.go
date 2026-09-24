package ctxprov

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

func TestPodBoundAPIAuthContextUsesTypedAdmission(t *testing.T) {
	pod := model.Pod{Namespace: "owned", Name: "source", UID: "pod-uid", PodResourceVersion: "23", ServiceAccount: "reader",
		PodBoundKubeAPIAuth: &model.PodBoundKubeAPIAuthProjection{PodUID: "pod-uid", PodResourceVersion: "23",
			ServiceAccountName: "reader", ServiceAccountUID: "sa-uid", VolumeName: "api-token",
			MountedContainer: "app", AudienceSource: "kube-apiserver-default", EvidenceSource: "admitted-pod-and-serviceaccount"}}
	event := model.SecurityEventInfo{Name: "observed", UID: "event-uid", Type: model.AttackVectorPodBoundAPIAuth,
		ThreatLevel: "critical", Trust: "trusted", CreatorIdentity: "system:serviceaccount:owned:detector",
		CreatedAt: time.Unix(1, 0), Age: 8 * time.Minute, TargetsPod: true,
		ConsoleTargetPodUID: "pod-uid", ResolvedTargets: []string{"owned/source"}}
	pol := model.Policy{EventAgeHorizon: 10 * time.Minute}
	posture := func(e model.SecurityEventInfo, p model.Pod) float64 {
		return sensed{}.Context(&model.WorkloadView{Pod: p, Events: []model.SecurityEventInfo{e}}, pol).ThreatPosture
	}
	if posture(event, pod) <= 0 {
		t.Fatal("qualified token event did not reach context")
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
			if got := posture(tc.event, tc.pod); got != 0 {
				t.Fatalf("unqualified token event raised threat posture: %v", got)
			}
		})
	}
}
