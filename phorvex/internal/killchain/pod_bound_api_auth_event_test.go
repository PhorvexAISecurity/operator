package killchain

import (
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

func tokenStagePod() model.Pod {
	return model.Pod{
		Namespace: "owned", Name: "source", UID: "pod-uid", PodResourceVersion: "23",
		ServiceAccount: "reader", PodBoundKubeAPIAuth: &model.PodBoundKubeAPIAuthProjection{
			PodUID: "pod-uid", PodResourceVersion: "23", ServiceAccountName: "reader",
			ServiceAccountUID: "sa-uid", VolumeName: "api-token", MountedContainer: "app",
			AudienceSource: "kube-apiserver-default", EvidenceSource: "admitted-pod-and-serviceaccount",
		},
	}
}

func tokenStageEvent() model.SecurityEventInfo {
	return model.SecurityEventInfo{
		Name: "observed", UID: "event-uid", Type: "phorvex.attack.pod-bound-api-auth",
		ThreatLevel: "critical", Trust: "trusted", CreatorIdentity: "system:serviceaccount:owned:detector",
		CreatedAt: time.Date(2026, 9, 24, 11, 52, 0, 0, time.UTC), Age: 8 * time.Minute,
		TargetsPod: true, ConsoleTargetPodUID: "pod-uid", ResolvedTargets: []string{"owned/source"},
	}
}

func TestPodBoundAPIAuthStageUsesSameTypedAdmission(t *testing.T) {
	policy := model.Policy{Tenant: "owned", EventAgeHorizon: 10 * time.Minute}
	pod := tokenStagePod()
	event := tokenStageEvent()
	assess := func(p model.Pod, e model.SecurityEventInfo) Assessment {
		return NewModel().Assess(&model.WorkloadView{Pod: p, Events: []model.SecurityEventInfo{e}},
			policy, 3600, 3600)
	}
	positive := assess(pod, event)
	if positive.EventStageName != StagePersist.String() || positive.EventEvidence <= 0 ||
		len(positive.Events) != 1 || positive.Events[0].Weight <= 0 {
		t.Fatalf("qualified event did not enter normal hazard: %+v", positive)
	}
	for _, tc := range []struct {
		name string
		edit func(*model.Pod, *model.SecurityEventInfo)
	}{
		{"horizon boundary", func(_ *model.Pod, e *model.SecurityEventInfo) { e.Age = 10 * time.Minute }},
		{"wrong UID", func(_ *model.Pod, e *model.SecurityEventInfo) { e.ConsoleTargetPodUID = "former-pod" }},
		{"untrusted creator", func(_ *model.Pod, e *model.SecurityEventInfo) { e.Trust = "untrusted-identity" }},
		{"missing event UID", func(_ *model.Pod, e *model.SecurityEventInfo) { e.UID = "" }},
		{"deleted timestamp", func(_ *model.Pod, e *model.SecurityEventInfo) { e.TimestampMissing = true }},
		{"no structural witness", func(p *model.Pod, _ *model.SecurityEventInfo) { p.PodBoundKubeAPIAuth = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, e := pod, event
			tc.edit(&p, &e)
			got := assess(p, e)
			if got.EventStageName != "" || got.EventEvidence != 0 ||
				len(got.Events) != 1 || got.Events[0].Weight != 0 {
				t.Fatalf("unqualified token event affected hazard: %+v", got)
			}
		})
	}
}

func TestPodBoundAPIAuthAISignalCannotBypassTypedAdmission(t *testing.T) {
	pod := tokenStagePod()
	pod.ModelID = "synthetic-model"
	event := tokenStageEvent()
	view := &model.WorkloadView{Pod: pod, Events: []model.SecurityEventInfo{event}}
	if stage, ok := aiStageFromView(view, 10*time.Minute); !ok || stage != StagePromptInjectPersist {
		t.Fatalf("qualified token event was not classified: %v %v", stage, ok)
	}
	for _, edit := range []func(*model.SecurityEventInfo){
		func(e *model.SecurityEventInfo) { e.Age = 10 * time.Minute },
		func(e *model.SecurityEventInfo) { e.ConsoleTargetPodUID = "former-pod" },
		func(e *model.SecurityEventInfo) { e.TimestampMissing = true },
	} {
		bad := event
		edit(&bad)
		view.Events = []model.SecurityEventInfo{bad}
		if stage, ok := aiStageFromView(view, 10*time.Minute); ok {
			t.Fatalf("unqualified token event affected AI stage: %v", stage)
		}
	}
	view.Pod.PodBoundKubeAPIAuth = nil
	view.Events = []model.SecurityEventInfo{event}
	if stage, ok := aiStageFromView(view, 10*time.Minute); ok {
		t.Fatalf("no-witness token event affected AI stage: %v", stage)
	}
}
