package sensorsvc

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
)

func TestPodBoundAPIAuthOffPodBearerDoesNotInfectNeighbors(t *testing.T) {
	pod := model.Pod{Namespace: "owned", Name: "source", UID: "pod-uid", PodResourceVersion: "23", ServiceAccount: "reader",
		PodBoundKubeAPIAuth: &model.PodBoundKubeAPIAuthProjection{PodUID: "pod-uid", PodResourceVersion: "23",
			ServiceAccountName: "reader", ServiceAccountUID: "sa-uid", VolumeName: "api-token",
			MountedContainer: "app", AudienceSource: "kube-apiserver-default", EvidenceSource: "admitted-pod-and-serviceaccount"}}
	event := model.SecurityEventInfo{Name: "observed", UID: "event-uid", Type: model.AttackVectorPodBoundAPIAuth,
		ThreatLevel: "critical", Trust: "trusted", CreatorIdentity: "system:serviceaccount:owned:detector",
		CreatedAt: time.Unix(1, 0), Age: 8 * time.Minute, TargetsPod: true,
		ConsoleTargetPodUID: "pod-uid", ResolvedTargets: []string{"owned/source"}}
	snap := &ingest.Snapshot{PodByKey: map[string]*model.Pod{"owned/source": &pod},
		EventByPod: map[string][]model.SecurityEventInfo{"owned/source": {event}}}
	if infected := infectedSet(snap.EventByPod); infected["owned/source"] || infectionFrontier([]string{"owned/source"}, infected) != 1 {
		t.Fatal("off-Pod bearer exposure incorrectly infected a neighbor")
	}
	snap.EventByPod["owned/source"] = []model.SecurityEventInfo{{Type: "existing-alert", ThreatLevel: "critical"}}
	if !infectedSet(snap.EventByPod)["owned/source"] {
		t.Fatal("generic high-severity frontier behavior changed")
	}
}
