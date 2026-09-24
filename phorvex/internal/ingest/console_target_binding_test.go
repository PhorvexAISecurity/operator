package ingest

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/killchain"
	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestConsoleBoundEventUsesDecisionSnapshotPodUID(t *testing.T) {
	trustEvents(t, "ns/detector")
	now := time.Date(2026, 9, 24, 1, 0, 0, 0, time.UTC)
	creator := "system:serviceaccount:ns:detector"
	event := func(name, identity, targetUID string, targets ...string) *amtdv1beta1.SecurityEvent {
		e := seEvent(name, identity, "ExternalDetector", targets...)
		e.CreationTimestamp = metav1.NewTime(now.Add(-time.Minute))
		if targetUID != "unbound" {
			e.Annotations[ConsoleTargetPodUIDAnnotation] = targetUID
		}
		return e
	}
	stale := event("stale", creator, "original-uid", "ns/source")
	outcomeRaw, err := json.Marshal([]model.ProtectedOutcome{{ID: "stale-outcome", DecisionAsset: "ns/source", DecisionAssetUID: "original-uid"}})
	if err != nil {
		t.Fatal(err)
	}
	stale.Annotations["phorvex.ai/protected-outcomes-v1"] = string(outcomeRaw)
	objects := []client.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns"}},
		// The original name has been reused by a different Pod UID before this tick.
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "source", UID: "replacement-uid", ResourceVersion: "19"}},
		stale,
		event("current", creator, "replacement-uid", "ns/source"),
		event("legacy", creator, "unbound", "ns/source"),
		event("malformed", creator, "bad/uid", "ns/source"),
		event("multi", creator, "replacement-uid", "ns/source", "ns/neighbor"),
		event("untrusted", "system:serviceaccount:evil:detector", "replacement-uid", "ns/source"),
	}
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, v1alpha1.AddToScheme, amtdv1beta1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	// Construct through the actual KubeSource collector, not a hand-filled
	// EventByPod flag or an extra GET with a different snapshot lifetime.
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
	snap, err := CollectSnapshot(context.Background(), client, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := snap.PodByKey["ns/source"]; got == nil || got.UID != "replacement-uid" {
		t.Fatalf("decision Pod snapshot mismatch: %+v", got)
	}
	byName := map[string]bool{}
	for _, ev := range snap.EventByPod["ns/source"] {
		byName[ev.Name] = true
		if ev.TargetBindingReason != "" {
			t.Fatalf("rejected event entered EventByPod: %+v", ev)
		}
	}
	if len(byName) != 2 || !byName["current"] || !byName["legacy"] || len(snap.EventByPod["ns/neighbor"]) != 0 {
		t.Fatalf("belief/neighbor inputs leaked a rejected event: %+v", snap.EventByPod)
	}
	wantReasons := map[string]string{"stale": "console-target-pod-uid-mismatch", "malformed": "console-target-uid-malformed", "multi": "console-target-must-be-one-pod"}
	if len(snap.Events) != 6 {
		t.Fatalf("diagnostic inventory lost events: %d", len(snap.Events))
	}
	for _, ev := range snap.Events {
		if want, ok := wantReasons[ev.Name]; ok {
			if ev.TargetBindingReason != want || ev.ConsoleTargetPodUID == "" || len(ev.ResolvedTargets) == 0 {
				t.Errorf("%s missing original target/rejection: %+v", ev.Name, ev)
			}
			if ev.Name == "stale" && len(ev.Outcomes) != 1 {
				t.Errorf("stale event's diagnostic outcome payload was lost: %+v", ev)
			}
		}
	}
	for _, ev := range EvidenceEvents(snap.Events) {
		if ev.Name == "stale" || len(ev.Outcomes) != 0 {
			t.Fatalf("stale bound outcome regained decision influence: %+v", ev)
		}
	}
	if len(EvidenceEvents(snap.Events)) != 3 { // current, legacy, untrusted; creator trust is a separate boundary
		t.Fatalf("rejected UID-bound events entered non-EventByPod evidence inventory")
	}
	current := snap.EventByPod["ns/source"][0]
	if current.Name != "current" {
		current = snap.EventByPod["ns/source"][1]
	}
	if current.Name != "current" || current.ConsoleTargetPodUID != snap.PodByKey["ns/source"].UID {
		t.Fatalf("accepted event target does not agree with decision Pod: %+v", current)
	}
	assessment := killchain.NewModel().Assess(&model.WorkloadView{Pod: *snap.PodByKey["ns/source"], Events: []model.SecurityEventInfo{current}},
		model.Policy{Tenant: "ns", ProactiveFloor: time.Hour, EventAgeHorizon: time.Hour}, 60, 3600)
	if len(assessment.Events) != 1 || assessment.Events[0].TargetPodUID != current.ConsoleTargetPodUID || assessment.Events[0].Name != current.Name {
		t.Fatalf("steering trace relabeled bound event to a different Pod lifetime: %+v", assessment.Events)
	}
}
