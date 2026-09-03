package actuator

import (
	"context"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/internal/model"
)

// PHORVEXSEC-169 (M-38): quarantine's detach half must break the selector of ANY
// controller owner (StatefulSet/DaemonSet/Job, not only ReplicaSet) and, when no owner
// selector can be resolved, fall back to breaking the keys every matching Service
// selects on. Otherwise the frozen pod stays in the Service endpoints and is re-adopted.

func qtnScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	_ = networkingv1.AddToScheme(s)
	_ = appsv1.AddToScheme(s)
	_ = batchv1.AddToScheme(s)
	return s
}

func qtnClient(objs ...client.Object) client.Client {
	return fake.NewClientBuilder().WithScheme(qtnScheme()).WithObjects(objs...).Build()
}

func ownedPod(ns, name string, labels map[string]string, owner metav1.OwnerReference) *corev1.Pod {
	pod := aiPod(ns, name, labels)
	pod.UID = types.UID("uid-" + name)
	if owner.Kind != "" {
		pod.OwnerReferences = []metav1.OwnerReference{owner}
	}
	return pod
}

func ctrlRef(apiVersion, kind, name string) metav1.OwnerReference {
	yes := true
	return metav1.OwnerReference{APIVersion: apiVersion, Kind: kind, Name: name, UID: types.UID("uid-" + name), Controller: &yes}
}

func selectorOf(labels map[string]string) *metav1.LabelSelector {
	return &metav1.LabelSelector{MatchLabels: labels}
}

func enactQuarantine(t *testing.T, c client.Client, ns, name string) (HandlerResult, *corev1.Pod) {
	t.Helper()
	res, err := quarantineHandler{}.Enact(context.Background(), EnactCtx{Client: c}, Request{Namespace: ns, Pod: name, Action: model.ActionQuarantine})
	if err != nil {
		t.Fatalf("quarantine enact: %v", err)
	}
	if !res.Emitted || res.MutationKind != "reversible" {
		t.Fatalf("quarantine result = %+v, want emitted reversible", res)
	}
	var got corev1.Pod
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: name}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Labels[quarantineLabel] == "" {
		t.Fatalf("quarantine label missing on %s/%s: %v", ns, name, got.Labels)
	}
	if len(got.OwnerReferences) != 0 {
		t.Fatalf("ownerReferences not stripped: %+v", got.OwnerReferences)
	}
	var np networkingv1.NetworkPolicy
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: "phorvex-quarantine-" + name}, &np); err != nil {
		t.Fatalf("deny-all NetworkPolicy missing: %v", err)
	}
	return res, &got
}

func TestQuarantineDetachBreaksStatefulSetSelector(t *testing.T) {
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "nats"},
		Spec:       appsv1.StatefulSetSpec{Selector: selectorOf(map[string]string{"app": "nats"})},
	}
	pod := ownedPod("ns", "nats-1", map[string]string{"app": "nats", "statefulset.kubernetes.io/pod-name": "nats-1"}, ctrlRef("apps/v1", "StatefulSet", "nats"))
	c := qtnClient(pod, sts)

	res, got := enactQuarantine(t, c, "ns", "nats-1")
	if got.Labels["app"] != "nats-quarantined" {
		t.Fatalf("StatefulSet selector key not broken: labels=%v (old behavior: only ReplicaSet owners were detached)", got.Labels)
	}
	if got.Labels["statefulset.kubernetes.io/pod-name"] != "nats-1" {
		t.Fatalf("non-selector label mutated: %v", got.Labels)
	}
	if !strings.Contains(res.Note, "StatefulSet/nats") {
		t.Fatalf("note does not attribute the detach to the owner: %q", res.Note)
	}

	if err := (quarantineHandler{}).Rollback(context.Background(), EnactCtx{Client: c}, Request{Namespace: "ns", Pod: "nats-1"}, "ns/nats-1"); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	var restored corev1.Pod
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "nats-1"}, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.Labels["app"] != "nats" || restored.Labels[quarantineLabel] != "" {
		t.Fatalf("rollback did not restore labels: %v", restored.Labels)
	}
	if len(restored.OwnerReferences) != 1 || restored.OwnerReferences[0].Kind != "StatefulSet" {
		t.Fatalf("rollback did not restore ownerReferences: %+v", restored.OwnerReferences)
	}
}

func TestQuarantineDetachBreaksDaemonSetAndJobSelectors(t *testing.T) {
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "agent"},
		Spec:       appsv1.DaemonSetSpec{Selector: selectorOf(map[string]string{"name": "agent"})},
	}
	dsPod := ownedPod("ns", "agent-x", map[string]string{"name": "agent", "controller-revision-hash": "r1"}, ctrlRef("apps/v1", "DaemonSet", "agent"))
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "batch"},
		Spec:       batchv1.JobSpec{Selector: selectorOf(map[string]string{"batch.kubernetes.io/controller-uid": "j1"})},
	}
	jobPod := ownedPod("ns", "batch-x", map[string]string{"batch.kubernetes.io/controller-uid": "j1", "batch.kubernetes.io/job-name": "batch"}, ctrlRef("batch/v1", "Job", "batch"))
	c := qtnClient(dsPod, ds, jobPod, job)

	_, gotDS := enactQuarantine(t, c, "ns", "agent-x")
	if gotDS.Labels["name"] != "agent-quarantined" {
		t.Fatalf("DaemonSet selector key not broken: %v", gotDS.Labels)
	}
	_, gotJob := enactQuarantine(t, c, "ns", "batch-x")
	if gotJob.Labels["batch.kubernetes.io/controller-uid"] != "j1-quarantined" {
		t.Fatalf("Job selector key not broken: %v", gotJob.Labels)
	}
	if gotJob.Labels["batch.kubernetes.io/job-name"] != "batch" {
		t.Fatalf("non-selector Job label mutated: %v", gotJob.Labels)
	}
}

func TestQuarantineDetachReplicaSetParity(t *testing.T) {
	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "web-abc"},
		Spec:       appsv1.ReplicaSetSpec{Selector: selectorOf(map[string]string{"app": "web", "pod-template-hash": "abc"})},
	}
	pod := ownedPod("ns", "web-abc-1", map[string]string{"app": "web", "pod-template-hash": "abc", "tier": "fe"}, ctrlRef("apps/v1", "ReplicaSet", "web-abc"))
	c := qtnClient(pod, rs)
	_, got := enactQuarantine(t, c, "ns", "web-abc-1")
	if got.Labels["app"] != "web-quarantined" || got.Labels["pod-template-hash"] != "abc-quarantined" || got.Labels["tier"] != "fe" {
		t.Fatalf("ReplicaSet detach parity broken: %v", got.Labels)
	}
}

func TestQuarantineDetachHonoursMatchExpressions(t *testing.T) {
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "db"},
		Spec: appsv1.StatefulSetSpec{Selector: &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "role", Operator: metav1.LabelSelectorOpIn, Values: []string{"db"}},
				{Key: "shard", Operator: metav1.LabelSelectorOpExists},
			},
		}},
	}
	pod := ownedPod("ns", "db-0", map[string]string{"role": "db", "shard": "a", "keep": "me"}, ctrlRef("apps/v1", "StatefulSet", "db"))
	c := qtnClient(pod, sts)
	_, got := enactQuarantine(t, c, "ns", "db-0")
	if got.Labels["role"] != "db-quarantined" {
		t.Fatalf("In-expression key not broken: %v", got.Labels)
	}
	if _, still := got.Labels["shard"]; still {
		t.Fatalf("Exists-expression key not removed: %v", got.Labels)
	}
	if got.Labels["keep"] != "me" {
		t.Fatalf("unrelated label mutated: %v", got.Labels)
	}
}

func TestQuarantineDetachBarePodFallsBackToServiceKeys(t *testing.T) {
	pod := ownedPod("ns", "lonely", map[string]string{"app": "web", "tier": "fe", "extra": "x"}, metav1.OwnerReference{})
	front := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "front"},
		Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "web"}}}
	tier := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "tier"},
		Spec: corev1.ServiceSpec{Selector: map[string]string{"tier": "fe"}}}
	other := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "other"},
		Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "other"}}}
	headless := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "noselector"},
		Spec: corev1.ServiceSpec{}}
	c := qtnClient(pod, front, tier, other, headless)

	res, got := enactQuarantine(t, c, "ns", "lonely")
	if got.Labels["app"] != "web-quarantined" || got.Labels["tier"] != "fe-quarantined" {
		t.Fatalf("Service-matching keys not broken (old behavior left the pod in every Service's endpoints): %v", got.Labels)
	}
	if got.Labels["extra"] != "x" {
		t.Fatalf("label outside every matching Service selector mutated: %v", got.Labels)
	}
	if !strings.Contains(res.Note, "Service/front") || !strings.Contains(res.Note, "Service/tier") || strings.Contains(res.Note, "Service/other") {
		t.Fatalf("note must list exactly the matching Services: %q", res.Note)
	}
	var svc corev1.Service
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: "front"}, &svc); err != nil {
		t.Fatal(err)
	}
	if svc.Spec.Selector["app"] != "web" {
		t.Fatalf("Service selector must not be mutated by quarantine: %v", svc.Spec.Selector)
	}
}

func TestQuarantineDetachUnresolvableOwnerFallsBackToServiceKeys(t *testing.T) {
	// A CRD-owned pod whose owner kind is unknown to the client (no RBAC / no scheme).
	pod := ownedPod("ns", "rollout-1", map[string]string{"app": "canary"}, ctrlRef("argoproj.io/v1alpha1", "Rollout", "canary"))
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "canary"},
		Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "canary"}}}
	c := qtnClient(pod, svc)
	res, got := enactQuarantine(t, c, "ns", "rollout-1")
	if got.Labels["app"] != "canary-quarantined" {
		t.Fatalf("fallback to Service keys did not happen: %v", got.Labels)
	}
	if !strings.Contains(res.Note, "Service/canary") {
		t.Fatalf("note must attribute the fallback: %q", res.Note)
	}
}

func TestQuarantineDetachReportsWhenNoSelectorCanBeBroken(t *testing.T) {
	pod := ownedPod("ns", "orphan", map[string]string{"app": "solo"}, metav1.OwnerReference{})
	c := qtnClient(pod)
	res, got := enactQuarantine(t, c, "ns", "orphan")
	if got.Labels["app"] != "solo" {
		t.Fatalf("labels must be untouched when nothing selects the pod: %v", got.Labels)
	}
	if !strings.Contains(res.Note, "no owner or Service selector") {
		t.Fatalf("note must not claim a detach it did not perform: %q", res.Note)
	}
	// Idempotent: a second enact is a no-op.
	again, err := quarantineHandler{}.Enact(context.Background(), EnactCtx{Client: c}, Request{Namespace: "ns", Pod: "orphan", Action: model.ActionQuarantine})
	if err != nil || !strings.Contains(again.Note, "already quarantined") {
		t.Fatalf("second enact = %+v, %v; want idempotent no-op", again, err)
	}
}
