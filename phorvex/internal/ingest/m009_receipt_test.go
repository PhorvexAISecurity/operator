package ingest

import (
	"context"
	"testing"
	"time"

	"github.com/phorvex/phorvex/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/internal/actuator"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

func TestM009SelfEventProjectsReceiptOutsideBelief(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := amtdv1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	ev := &amtdv1beta1.SecurityEvent{ObjectMeta: metav1.ObjectMeta{Name: "event", UID: types.UID("event-uid"), CreationTimestamp: metav1.NewTime(now), Annotations: map[string]string{actuator.PhoenixRotateTargetUIDAnnotation: "pod-uid"}},
		Spec:   amtdv1beta1.SecurityEventSpec{Targets: []string{"ns/pod"}, Rule: amtdv1beta1.Rule{Type: actuator.RuleTypeRotate, ThreatLevel: actuator.RuleThreatLevel, Source: actuator.RuleSource}},
		Status: amtdv1beta1.SecurityEventStatus{AppliedAction: "rotate", ProcessedAt: metav1.NewTime(now.Add(time.Second))}}
	all, byPod, receipts, err := collectEventsAndReceipts(context.Background(), fake.NewClientBuilder().WithScheme(scheme).WithObjects(ev).Build(), now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 0 || len(byPod) != 0 {
		t.Fatalf("self event entered belief: all=%+v byPod=%+v", all, byPod)
	}
	r := receipts[ev.Name]
	if r.EventUID != "event-uid" || r.TargetUID != "pod-uid" || r.ThreatLevel != actuator.RuleThreatLevel || r.AppliedAction != "rotate" || len(r.Targets) != 1 {
		t.Fatalf("receipt projection=%+v", r)
	}
}

func TestM009DeletingSelfEventDoesNotProjectReceipt(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := amtdv1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	ev := &amtdv1beta1.SecurityEvent{
		ObjectMeta: metav1.ObjectMeta{
			Name: "event", UID: types.UID("event-uid"), CreationTimestamp: metav1.NewTime(now),
			DeletionTimestamp: &metav1.Time{Time: now.Add(time.Second)}, Finalizers: []string{"retain"},
			Annotations: map[string]string{actuator.PhoenixRotateTargetUIDAnnotation: "pod-uid"},
		},
		Spec:   amtdv1beta1.SecurityEventSpec{Targets: []string{"ns/pod"}, Rule: amtdv1beta1.Rule{Type: actuator.RuleTypeRotate, ThreatLevel: actuator.RuleThreatLevel, Source: actuator.RuleSource}},
		Status: amtdv1beta1.SecurityEventStatus{AppliedAction: "rotate", ProcessedAt: metav1.NewTime(now.Add(time.Second))},
	}
	_, _, receipts, err := collectEventsAndReceipts(context.Background(), fake.NewClientBuilder().WithScheme(scheme).WithObjects(ev).Build(), now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 0 {
		t.Fatalf("deleting event remained execution evidence: %+v", receipts)
	}
}

func TestM009ReceiptInventoryUsesAuthoritativeReader(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := amtdv1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	stale := &amtdv1beta1.SecurityEvent{ObjectMeta: metav1.ObjectMeta{Name: "event", UID: "event-uid", CreationTimestamp: metav1.NewTime(now), Annotations: map[string]string{actuator.PhoenixRotateTargetUIDAnnotation: "pod-uid"}},
		Spec:   amtdv1beta1.SecurityEventSpec{Targets: []string{"ns/pod"}, Rule: amtdv1beta1.Rule{Type: actuator.RuleTypeRotate, ThreatLevel: actuator.RuleThreatLevel, Source: actuator.RuleSource}},
		Status: amtdv1beta1.SecurityEventStatus{AppliedAction: "rotate", ProcessedAt: metav1.NewTime(now.Add(time.Second))}}
	cached := fake.NewClientBuilder().WithScheme(scheme).WithObjects(stale).Build()
	authoritative := fake.NewClientBuilder().WithScheme(scheme).Build()

	snap, err := CollectSnapshotForRotationTargetsWithReceiptReader(context.Background(), cached, now.Add(2*time.Second), nil, nil, authoritative, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !snap.PhoenixReceiptInventoryComplete || len(snap.PhoenixReceipts) != 0 {
		t.Fatalf("stale cached receipt survived authoritative absence: complete=%v receipts=%+v", snap.PhoenixReceiptInventoryComplete, snap.PhoenixReceipts)
	}

	snap, err = CollectSnapshotForRotationTargetsWithReceiptReader(context.Background(), cached, now.Add(2*time.Second), nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if snap.PhoenixReceiptInventoryComplete || len(snap.PhoenixReceipts) != 0 {
		t.Fatalf("missing authoritative reader exposed cached receipt: complete=%v receipts=%+v", snap.PhoenixReceiptInventoryComplete, snap.PhoenixReceipts)
	}
}
