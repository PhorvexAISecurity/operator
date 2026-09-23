package killchain

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

func TestCaseTraceGenericEventIdentityDoesNotChangeAssessmentMath(t *testing.T) {
	base := model.SecurityEventInfo{Name: "signal", Source: "ExternalDetector", Type: "Panic", ThreatLevel: "critical", TargetsPod: true, Age: time.Second}
	identified := base
	identified.UID = "event-uid"
	identified.Trust = "trusted"
	identified.CreatorIdentity = "system:serviceaccount:demo:detector"
	view := func(event model.SecurityEventInfo) *model.WorkloadView {
		return &model.WorkloadView{Pod: model.Pod{Namespace: "demo", Name: "demo-0", UID: "pod-uid"}, Events: []model.SecurityEventInfo{event}}
	}
	m := NewModel()
	policy := model.Policy{Tenant: "demo", ProactiveFloor: time.Hour, EventAgeHorizon: time.Hour}
	without := m.Assess(view(base), policy, 60, 3600)
	with := m.Assess(view(identified), policy, 60, 3600)
	if len(with.Events) != 1 {
		t.Fatalf("event evidence=%+v", with.Events)
	}
	got := with.Events[0]
	if got.EventUID != identified.UID || got.TrustVerdict != identified.Trust || got.CreatorIdentity != identified.CreatorIdentity || got.TargetPodUID != "pod-uid" {
		t.Fatalf("immutable identity was not preserved: %+v", got)
	}
	without.Events, with.Events = nil, nil
	if !reflect.DeepEqual(without, with) {
		t.Fatalf("identity-only metadata changed assessment math:\nwithout=%+v\nwith=%+v", without, with)
	}
}

func TestCaseTraceEventEvidenceAuditStringsAreRedactedAndBounded(t *testing.T) {
	e := model.EventEvidence{CreatorIdentity: "system:serviceaccount:demo:detector token=private", Source: strings.Repeat("é", 800)}.Canonical()
	if strings.Contains(e.CreatorIdentity, "private") || !strings.Contains(e.CreatorIdentity, "[REDACTED]") {
		t.Fatalf("creator identity was not credential-redacted: %q", e.CreatorIdentity)
	}
	if len(e.Source) > 1024 {
		t.Fatalf("source remained unbounded: %d", len(e.Source))
	}
}

func TestCaseTraceNeighborAndMissingIdentityDoNotInventTargetBinding(t *testing.T) {
	m := NewModel()
	policy := model.Policy{Tenant: "demo", ProactiveFloor: time.Hour, EventAgeHorizon: time.Hour}
	view := &model.WorkloadView{Pod: model.Pod{Namespace: "demo", Name: "demo-0", UID: "pod-uid"}, Events: []model.SecurityEventInfo{
		{Name: "neighbor", UID: "neighbor-event", Trust: "trusted", CreatorIdentity: "detector", Type: "Panic", ThreatLevel: "critical", TargetsPod: false, Age: time.Second},
		{Name: "missing", Type: "Panic", ThreatLevel: "critical", TargetsPod: true, Age: time.Second},
	}}
	a := m.Assess(view, policy, 60, 3600)
	if len(a.Events) != 2 || a.Events[0].TargetPodUID != "" {
		t.Fatalf("neighbor event was bound to assessed pod: %+v", a.Events)
	}
	if a.Events[1].TargetPodUID != "pod-uid" || a.Events[1].EventUID != "" || a.Events[1].TrustVerdict != "" || a.Events[1].CreatorIdentity != "" {
		t.Fatalf("missing source identity was invented or target binding lost: %+v", a.Events[1])
	}
}
