package actuator

import (
	"context"
	"testing"

	"github.com/phorvex/phorvex/api/v1alpha1"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func p4bScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	_ = discoveryv1.AddToScheme(s)
	_ = appsv1.AddToScheme(s)
	_ = networkingv1.AddToScheme(s)
	_ = v1alpha1.AddToScheme(s)
	_ = amtdv1beta1.AddToScheme(s)
	return s
}

func readyLeader(ns, name, group string, flipping bool) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name,
			Labels:      map[string]string{labelSwapGroup: group, labelRole: roleLeader},
			Annotations: map[string]string{}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
	}
	if flipping {
		p.Annotations[annoSwapPhase] = "flipping"
	}
	return p
}

// Label-only double leaders have no operation authority and remain unchanged.
func TestResumeWarmSwapConvergesDoubleLeader(t *testing.T) {
	oldLeader := readyLeader("ns", "old", "g", true)  // the one that was flipping
	newLeader := readyLeader("ns", "new", "g", false) // the promoted shadow
	c := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(oldLeader, newLeader).Build()

	n, err := ResumeWarmSwaps(context.Background(), c, "ns")
	if err == nil || n != 0 {
		t.Fatalf("label-only resume must refuse, reaped=%d err=%v", n, err)
	}
	var leaders corev1.PodList
	_ = c.List(context.Background(), &leaders, client.InNamespace("ns"), client.MatchingLabels{labelRole: roleLeader})
	if len(leaders.Items) != 2 {
		t.Fatalf("refusal changed leader set: %d", len(leaders.Items))
	}
}

// TestResumeWarmSwapLeavesHealthySingleLeader — fail-safe: a single healthy leader is NOT
// touched (only a stale flipping annotation is cleared).
func TestResumeWarmSwapLeavesHealthySingleLeader(t *testing.T) {
	lone := readyLeader("ns", "lone", "g", true) // stale flipping anno, but only one leader
	c := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(lone).Build()
	_, _ = ResumeWarmSwaps(context.Background(), c, "ns")
	var got corev1.Pod
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "lone"}, &got); err != nil {
		t.Fatalf("healthy lone leader was reaped: %v", err)
	}
	if got.Annotations[annoSwapPhase] != "flipping" {
		t.Error("untrusted legacy annotation changed")
	}
}

// TestGCReapsOrphanNPOnly — P4b FIX 5: an orphaned quarantine NP (target pod gone) is reaped;
// a live quarantine's NP (target pod present) is KEPT.
func TestGCReapsOrphanNPOnly(t *testing.T) {
	np := func(name, target string) *networkingv1.NetworkPolicy {
		return &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: name,
			Labels: map[string]string{npManagedByLabel: npManagedByValue, npQuarantineOfKey: target}}}
	}
	livePod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "alive"}}
	c := fake.NewClientBuilder().WithScheme(p4bScheme()).
		WithObjects(np("np-orphan", "gone"), np("np-live", "alive"), livePod).Build()

	n, err := GCOrphanedQuarantineNPs(context.Background(), c, "ns")
	if err == nil || n != 0 {
		t.Fatalf("label-only GC must refuse, reaped=%d err=%v", n, err)
	}
	var nps networkingv1.NetworkPolicyList
	_ = c.List(context.Background(), &nps, client.InNamespace("ns"))
	if len(nps.Items) != 2 {
		t.Errorf("refusal changed NPs: %+v", nps.Items)
	}
}
