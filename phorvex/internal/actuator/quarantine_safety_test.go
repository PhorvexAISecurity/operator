package actuator

import (
	"context"
	"errors"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestM038OwnerAndIndependentServiceSelectors(t *testing.T) {
	p := ownedPod("ns", "p", map[string]string{"app": "owned", "service": "public", "keep": "yes"}, ctrlRef("apps/v1", "ReplicaSet", "rs"))
	p.OwnerReferences = append(p.OwnerReferences, metav1.OwnerReference{APIVersion: "v1", Kind: "ConfigMap", Name: "metadata", UID: "other"})
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "rs"}, Spec: appsv1.ReplicaSetSpec{Selector: selectorOf(map[string]string{"app": "owned"})}}
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "front"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"service": "public"}}}
	c := qtnClient(p, rs, svc)
	n := NewNativeActuator(c)
	n.SetBoundaryReader(c)
	req := Request{Namespace: "ns", Pod: "p", Action: "quarantine", TargetUID: string(p.UID)}
	res, err := n.Actuate(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	var got corev1.Pod
	_ = c.Get(context.Background(), client.ObjectKeyFromObject(p), &got)
	if labels.SelectorFromSet(svc.Spec.Selector).Matches(labels.Set(got.Labels)) || got.Labels["app"] == "owned" {
		t.Fatal("controller or service still matches")
	}
	if len(got.OwnerReferences) != 1 || got.OwnerReferences[0].UID != "other" {
		t.Fatal("non-controller ownership lost")
	}
	// Explicit native rollback preserves concurrent, unrelated metadata.
	got.Labels["new-unrelated"] = "keep"
	if err = c.Update(context.Background(), &got); err != nil {
		t.Fatal(err)
	}
	if err = n.Rollback(context.Background(), req, res.RollbackRef); err != nil {
		t.Fatal(err)
	}
	_ = c.Get(context.Background(), client.ObjectKeyFromObject(p), &got)
	if got.Labels["new-unrelated"] != "keep" || got.Labels["app"] != "owned" || got.Labels["service"] != "public" || len(got.OwnerReferences) != 2 {
		t.Fatalf("bad restore: %+v", got.ObjectMeta)
	}
}
func TestM038NegativeExpressionsAndLabelLength(t *testing.T) {
	for _, expr := range []metav1.LabelSelectorRequirement{
		{Key: "x", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"blocked"}},
		{Key: "x", Operator: metav1.LabelSelectorOpDoesNotExist},
		{Key: "long", Operator: metav1.LabelSelectorOpIn, Values: []string{strings.Repeat("x", 63)}},
	} {
		p := ownedPod("ns", "p", map[string]string{"long": strings.Repeat("x", 63)}, ctrlRef("apps/v1", "ReplicaSet", "rs"))
		sel := &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{expr}}
		rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "rs"}, Spec: appsv1.ReplicaSetSpec{Selector: sel}}
		c := qtnClient(p, rs)
		_, got := enactQuarantine(t, c, "ns", "p")
		predicate, _ := metav1.LabelSelectorAsSelector(sel)
		if predicate.Matches(labels.Set(got.Labels)) {
			t.Fatalf("selector still matches: %+v", expr)
		}
	}
}
func TestM038RejectsNewServiceMembershipAndUIDMismatch(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		p := ownedPod("ns", "p", map[string]string{"app": "a"}, ctrlRef("apps/v1", "ReplicaSet", "rs"))
		rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "rs", UID: "uid-rs"}, Spec: appsv1.ReplicaSetSpec{Selector: selectorOf(map[string]string{"app": "a"})}}
		if mismatch {
			rs.UID = "replacement"
		}
		svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "other"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "a-quarantined"}}}
		c := qtnClient(p, rs, svc)
		res, err := (quarantineHandler{}).Enact(context.Background(), EnactCtx{Client: c, Reader: c}, Request{Namespace: "ns", Pod: "p"})
		if err == nil || res.Emitted {
			t.Fatal("unsafe plan accepted")
		}
		var list networkingv1.NetworkPolicyList
		_ = c.List(context.Background(), &list)
		if len(list.Items) > 0 {
			t.Fatal("preflight created policy")
		}
	}
}
func TestM038PartialUpdateFailureSurvivesDispatch(t *testing.T) {
	p := ownedPod("ns", "p", map[string]string{"app": "a"}, metav1.OwnerReference{})
	base := qtnClient(p)
	c := interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{Update: func(context.Context, client.WithWatch, client.Object, ...client.UpdateOption) error {
		return errors.New("conflict")
	}})
	res, err := dispatch(context.Background(), EnactCtx{Client: c, Reader: c}, Request{Namespace: "ns", Pod: "p", Action: "quarantine"})
	if err == nil || !res.Emitted || len(res.ObjectsTouched) != 1 || !strings.Contains(res.Note, "partial") {
		t.Fatalf("partial result lost: %+v %v", res, err)
	}
	var got corev1.Pod
	_ = base.Get(context.Background(), client.ObjectKeyFromObject(p), &got)
	if got.Labels[quarantineLabel] != "" {
		t.Fatal("unexpected detach")
	}
}
func TestM038RollbackRefusesConcurrentChanges(t *testing.T) {
	p := ownedPod("ns", "p", map[string]string{"app": "a"}, metav1.OwnerReference{})
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "front"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "a"}}}
	c := qtnClient(p, svc)
	res, got := enactQuarantine(t, c, "ns", "p")
	got.Labels["app"] = "manual-edit"
	if err := c.Update(context.Background(), got); err != nil {
		t.Fatal(err)
	}
	if err := (quarantineHandler{}).Rollback(context.Background(), EnactCtx{Client: c, Reader: c}, Request{Namespace: "ns", Pod: "p"}, res.RollbackRef); err == nil {
		t.Fatal("overwrote concurrent edit")
	}
	var np networkingv1.NetworkPolicy
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "ns", Name: quarantinePolicy(p).Name}, &np); err != nil {
		t.Fatal("removed isolation on refusal")
	}
}

func TestM038ServiceReadFailureBeforeWrites(t *testing.T) {
	p := ownedPod("ns", "p", map[string]string{"app": "a"}, metav1.OwnerReference{})
	base := qtnClient(p)
	c := interceptor.NewClient(base.(client.WithWatch), interceptor.Funcs{List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
		return errors.New("services forbidden")
	}})
	res, err := dispatch(context.Background(), EnactCtx{Client: c, Reader: c}, Request{Namespace: "ns", Pod: "p", Action: "quarantine"})
	if err == nil || res.Emitted {
		t.Fatal("ignored Service read failure")
	}
	var list networkingv1.NetworkPolicyList
	_ = base.List(context.Background(), &list)
	if len(list.Items) > 0 {
		t.Fatal("wrote before preflight completed")
	}
}
