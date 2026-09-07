package ingest

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

// PHORVEXSEC-186 / M-27: ingest records the per-event age and flags a CR without a usable
// CreationTimestamp as present=false instead of treating it as a fresh event.
func TestCollectEventsRecordsAgeAndMissingTimestamp(t *testing.T) {
	s := runtime.NewScheme()
	if err := amtdv1beta1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	aged := &amtdv1beta1.SecurityEvent{
		ObjectMeta: metav1.ObjectMeta{Name: "aged", CreationTimestamp: metav1.NewTime(now.Add(-30 * time.Minute))},
		Spec:       amtdv1beta1.SecurityEventSpec{Targets: []string{"ns/pod-a"}, Rule: amtdv1beta1.Rule{Type: "Persistence", ThreatLevel: "high", Source: "det"}},
	}
	noStamp := &amtdv1beta1.SecurityEvent{
		ObjectMeta: metav1.ObjectMeta{Name: "nostamp"},
		Spec:       amtdv1beta1.SecurityEventSpec{Targets: []string{"ns/pod-a"}, Rule: amtdv1beta1.Rule{Type: "Persistence", ThreatLevel: "high", Source: "det"}},
	}
	// M-94: only an admission-stamped, allowlisted detector supplies belief evidence, so the
	// age fixtures now carry the stamp this fleet's detector would get.
	trustEvents(t, "vllm/detector-kv-canary")
	for _, se := range []*amtdv1beta1.SecurityEvent{aged, noStamp} {
		se.Annotations = map[string]string{CreatorIdentityAnnotation: "system:serviceaccount:vllm:detector-kv-canary"}
	}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(aged, noStamp).Build()
	_, byPod, err := collectEvents(context.Background(), c, now)
	if err != nil {
		t.Fatal(err)
	}
	evs := byPod["ns/pod-a"]
	if len(evs) != 2 {
		t.Fatalf("events for ns/pod-a = %d, want 2", len(evs))
	}
	seen := map[string]bool{}
	for _, e := range evs {
		seen[e.Name] = true
		switch e.Name {
		case "aged":
			if e.TimestampMissing || e.Age != 30*time.Minute {
				t.Fatalf("aged event: missing=%v age=%v, want present/30m", e.TimestampMissing, e.Age)
			}
		case "nostamp":
			if !e.TimestampMissing || e.Age != 0 {
				t.Fatalf("no-timestamp event: missing=%v age=%v, want missing/0", e.TimestampMissing, e.Age)
			}
		default:
			t.Fatalf("unexpected event name %q", e.Name)
		}
	}
	if !seen["aged"] || !seen["nostamp"] {
		t.Fatalf("names not carried into the projection: %v", seen)
	}
}
