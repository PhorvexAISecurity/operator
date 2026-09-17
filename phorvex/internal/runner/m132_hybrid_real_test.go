package runner

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func m132RouteObjects() (*corev1.Pod, *corev1.Pod, *corev1.Service) {
	ready := []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	target := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "api", UID: "pod-uid", ResourceVersion: "7", Labels: map[string]string{"app": "demo", "tier": "prod", "phorvex.ai/route-key": "route-old"}, Annotations: map[string]string{"phorvex.ai/route-service": "web-route"}}, Status: corev1.PodStatus{Conditions: ready}}
	sibling := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "sibling", UID: "sibling-uid", Labels: map[string]string{"app": "demo", "tier": "prod", "phorvex.ai/route-key": "route-old"}}, Status: corev1.PodStatus{Conditions: ready}}
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "web-route"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "demo", "phorvex.ai/route-key": "route-old"}}}
	return target, sibling, svc
}

func TestM132RealHybridPhoenixRefusalStillDeliversNativeAction(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := amtdv1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	pod, sibling, svc := m132RouteObjects()
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod, sibling, svc).Build()
	m := &Manager{Actuator: actuator.NewHybridActuator(c), Log: logr.Discard()}
	e := &policyEntry{namespace: "ns", tenant: "team", spec: v1alpha1.PhorvexPolicySpec{Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "demo"}, MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "tier", Operator: metav1.LabelSelectorOpExists}}}}}
	pol := model.Policy{Tenant: "team", EnabledActions: map[model.Action]bool{model.ActionRotate: true, model.ActionRouteRotate: true}}
	view := map[string]*model.WorkloadView{"ns/api": {Pod: model.Pod{Namespace: "ns", Name: "api", UID: "pod-uid", Ready: true, DesiredReplicas: 3, ReadyReplicas: 3, RouteService: "web-route", RouteServiceReady: true}}}
	decisions := []model.Decision{
		{Selected: true, Feasible: true, Action: model.ActionRotate, Namespace: "ns", Pod: "api", Trace: &model.DecisionTraceV2{}},
		{Selected: true, Feasible: true, Action: model.ActionRouteRotate, Namespace: "ns", Pod: "api", Trace: &model.DecisionTraceV2{}},
	}
	if n := actuateWithBoundary(t, m, ctx, e, pol, decisions, view); n != 1 || !decisions[1].Actuated || decisions[0].Actuated || decisions[0].Trace.DispatchReason != "route-preparation-failed" {
		t.Fatalf("real hybrid route result: n=%d Phoenix=%+v native=%+v", n, decisions[0].Trace, decisions[1].Trace)
	}
	var updated corev1.Pod
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "api"}, &updated); err != nil || updated.UID != "pod-uid" || updated.Labels["phorvex.ai/route-epoch"] == "" {
		t.Fatalf("native handler did not deliver bound Pod update: pod=%+v err=%v", updated.ObjectMeta, err)
	}
	var restitched corev1.Service
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "web-route"}, &restitched); err != nil || restitched.Spec.Selector["phorvex.ai/route-key"] != updated.Labels["phorvex.ai/route-key"] {
		t.Fatalf("native route Service not restitched: selector=%v labels=%v err=%v", restitched.Spec.Selector, updated.Labels, err)
	}
	var amtds amtdv1beta1.AdaptiveMovingTargetDefenseList
	var events amtdv1beta1.SecurityEventList
	if err := c.List(ctx, &amtds); err != nil || len(amtds.Items) != 0 {
		t.Fatalf("unsupported selector created AMTD: %d %v", len(amtds.Items), err)
	}
	if err := c.List(ctx, &events); err != nil || len(events.Items) != 0 {
		t.Fatalf("unsupported Phoenix route emitted event: %d %v", len(events.Items), err)
	}
}

func TestM132RealHybridEqualityControlDeliversBothRoutes(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := amtdv1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	pod, sibling, svc := m132RouteObjects()
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod, sibling, svc).Build()
	m := &Manager{Actuator: actuator.NewHybridActuator(c), Log: logr.Discard()}
	e := &policyEntry{namespace: "ns", tenant: "team", spec: v1alpha1.PhorvexPolicySpec{Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "demo"}}}}
	pol := model.Policy{Tenant: "team", EnabledActions: map[model.Action]bool{model.ActionRotate: true, model.ActionRouteRotate: true}}
	view := map[string]*model.WorkloadView{"ns/api": {Pod: model.Pod{Namespace: "ns", Name: "api", UID: "pod-uid", Ready: true, DesiredReplicas: 3, ReadyReplicas: 3, RouteService: "web-route", RouteServiceReady: true}}}
	decisions := []model.Decision{
		{Selected: true, Feasible: true, Action: model.ActionRotate, Namespace: "ns", Pod: "api", Trace: &model.DecisionTraceV2{}},
		{Selected: true, Feasible: true, Action: model.ActionRouteRotate, Namespace: "ns", Pod: "api", Trace: &model.DecisionTraceV2{}},
	}
	if n := actuateWithBoundary(t, m, ctx, e, pol, decisions, view); n != 2 || !decisions[0].Actuated || !decisions[1].Actuated {
		t.Fatalf("ordinary hybrid control failed: n=%d Phoenix=%+v native=%+v", n, decisions[0].Trace, decisions[1].Trace)
	}
	var amtds amtdv1beta1.AdaptiveMovingTargetDefenseList
	var events amtdv1beta1.SecurityEventList
	var updated corev1.Pod
	if err := c.List(ctx, &amtds); err != nil || len(amtds.Items) != 1 || amtds.Items[0].Spec.PodSelector["app"] != "demo" {
		t.Fatalf("equality AMTD missing: %d %v", len(amtds.Items), err)
	}
	if err := c.List(ctx, &events); err != nil || len(events.Items) != 1 {
		t.Fatalf("Phoenix event missing: %d %v", len(events.Items), err)
	}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "api"}, &updated); err != nil || updated.Labels["phorvex.ai/route-epoch"] == "" {
		t.Fatalf("native Pod update missing: %v %v", updated.Labels, err)
	}
	var restitched corev1.Service
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "web-route"}, &restitched); err != nil || restitched.Spec.Selector["phorvex.ai/route-key"] != updated.Labels["phorvex.ai/route-key"] {
		t.Fatalf("native Service restitch missing: selector=%v pod=%v err=%v", restitched.Spec.Selector, updated.Labels, err)
	}
}

func TestM132RealHybridNativeOnlySkipsPhoenixPreparation(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := amtdv1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	pod, sibling, svc := m132RouteObjects()
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod, sibling, svc).Build()
	m := &Manager{Actuator: actuator.NewHybridActuator(c), Log: logr.Discard()}
	e := &policyEntry{namespace: "ns", tenant: "team", spec: v1alpha1.PhorvexPolicySpec{Selector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "tier", Operator: metav1.LabelSelectorOpExists}}}}}
	pol := model.Policy{Tenant: "team", EnabledActions: map[model.Action]bool{model.ActionRouteRotate: true}}
	view := map[string]*model.WorkloadView{"ns/api": {Pod: model.Pod{Namespace: "ns", Name: "api", UID: "pod-uid", Ready: true, DesiredReplicas: 3, ReadyReplicas: 3, RouteService: "web-route", RouteServiceReady: true}}}
	d := []model.Decision{{Selected: true, Feasible: true, Action: model.ActionRouteRotate, Namespace: "ns", Pod: "api", Trace: &model.DecisionTraceV2{}}}
	if n, prep := actuatePreparedWithBoundary(t, m, ctx, e, pol, d, view); n != 1 || prep == nil || !prep.PhoenixSkipped || prep.NativeSkipped || !d[0].Actuated {
		t.Fatalf("native-only route did not deliver: n=%d prep=%+v decision=%+v", n, prep, d[0])
	}
	var amtds amtdv1beta1.AdaptiveMovingTargetDefenseList
	var events amtdv1beta1.SecurityEventList
	if err := c.List(ctx, &amtds); err != nil || len(amtds.Items) != 0 {
		t.Fatalf("native-only AMTD writes: %d %v", len(amtds.Items), err)
	}
	if err := c.List(ctx, &events); err != nil || len(events.Items) != 0 {
		t.Fatalf("native-only events: %d %v", len(events.Items), err)
	}
}
