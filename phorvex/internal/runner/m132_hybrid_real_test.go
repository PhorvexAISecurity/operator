package runner

import (
	"context"
	"fmt"
	"testing"

	"github.com/go-logr/logr"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/inprocess"
	"github.com/phorvex/phorvex/internal/model"
)

type m132RouteClient struct {
	client.Client
	next int
}

func (c *m132RouteClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if obj.GetUID() == "" {
		c.next++
		obj.SetUID(types.UID(fmt.Sprintf("m132-created-%d", c.next)))
	}
	if err := c.Client.Create(ctx, obj, opts...); err != nil {
		return err
	}
	return c.sync(ctx)
}

func (c *m132RouteClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if err := c.Client.Update(ctx, obj, opts...); err != nil {
		return err
	}
	return c.sync(ctx)
}

func (c *m132RouteClient) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	if err := c.Client.Patch(ctx, obj, patch, opts...); err != nil {
		return err
	}
	return c.sync(ctx)
}

func (c *m132RouteClient) sync(ctx context.Context) error {
	svc := &corev1.Service{}
	if err := c.Client.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "web-route"}, svc); err != nil {
		return client.IgnoreNotFound(err)
	}
	var pods corev1.PodList
	if err := c.Client.List(ctx, &pods, client.InNamespace("ns")); err != nil {
		return err
	}
	ready := true
	selector := labels.SelectorFromSet(svc.Spec.Selector)
	endpoints := make([]discoveryv1.Endpoint, 0)
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !selector.Matches(labels.Set(pod.Labels)) {
			continue
		}
		ref := corev1.ObjectReference{APIVersion: "v1", Kind: "Pod", Namespace: pod.Namespace, Name: pod.Name, UID: pod.UID}
		endpoints = append(endpoints, discoveryv1.Endpoint{Addresses: []string{"10.0.0.1"}, TargetRef: &ref, Conditions: discoveryv1.EndpointConditions{Ready: &ready}})
	}
	slice := &discoveryv1.EndpointSlice{}
	if err := c.Client.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "web-route-slice"}, slice); err != nil {
		return err
	}
	slice.Endpoints = endpoints
	return c.Client.Update(ctx, slice)
}

func m132RouteObjects() (*corev1.Pod, *corev1.Pod, *corev1.Service) {
	ready := []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	target := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "api", UID: "pod-uid", ResourceVersion: "7", Labels: map[string]string{"app": "demo", "tier": "prod", "phorvex.ai/route-key": "route-old"}, Annotations: map[string]string{"phorvex.ai/route-service": "web-route"}}, Status: corev1.PodStatus{Conditions: ready}}
	sibling := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "sibling", UID: "sibling-uid", Labels: map[string]string{"app": "demo", "tier": "prod", "phorvex.ai/route-key": "route-old"}}, Status: corev1.PodStatus{Conditions: ready}}
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "web-route", UID: "service-uid", ResourceVersion: "8"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "demo", "phorvex.ai/route-key": "route-old"}}}
	return target, sibling, svc
}

func m132RouteFixture(t *testing.T, selector metav1.LabelSelector) (*m132RouteClient, *Manager, *policyEntry, model.Policy, map[string]*model.WorkloadView) {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, discoveryv1.AddToScheme, v1alpha1.AddToScheme, amtdv1beta1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	pod, sibling, svc := m132RouteObjects()
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "policy", UID: "policy-uid"}, Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Selector: selector, SLO: v1alpha1.SLOSpec{MinAvailableReplicas: 1}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionQuarantine, v1alpha1.ActionRouteRotate}}}}
	ready := true
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "web-route-slice", UID: "slice-uid", ResourceVersion: "1", Labels: map[string]string{discoveryv1.LabelServiceName: svc.Name}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: svc.Name, UID: svc.UID}}}, AddressType: discoveryv1.AddressTypeIPv4}
	for _, current := range []*corev1.Pod{pod, sibling} {
		ref := corev1.ObjectReference{APIVersion: "v1", Kind: "Pod", Namespace: current.Namespace, Name: current.Name, UID: current.UID}
		slice.Endpoints = append(slice.Endpoints, discoveryv1.Endpoint{Addresses: []string{"10.0.0.1"}, TargetRef: &ref, Conditions: discoveryv1.EndpointConditions{Ready: &ready}})
	}
	base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ns", UID: "ns-uid"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "operator", UID: "operator-uid"}},
		pod, sibling, svc, policy, slice,
	).Build()
	c := &m132RouteClient{Client: base}
	hybrid := actuator.NewHybridActuator(c)
	hybrid.ConfigureNativeJournal(c, "operator")
	quarantineCapacity, err := actuator.NewQuarantineCapacity(c, c, "operator", 1)
	if err != nil {
		t.Fatal(err)
	}
	m := &Manager{Local: &inprocess.Services{Actuator: hybrid, QuarantineCapacity: quarantineCapacity}, BoundaryReader: c, Log: logr.Discard()}
	e := &policyEntry{key: types.NamespacedName{Namespace: "ns", Name: policy.Name}, uid: string(policy.UID), namespace: "ns", tenant: "team", spec: policy.Spec}
	pol := model.Policy{Tenant: "team", PolicyName: policy.Name, PolicyUID: string(policy.UID), MinAvailableReplicas: 1, EnabledActions: map[model.Action]bool{model.ActionQuarantine: true, model.ActionRouteRotate: true}}
	view := map[string]*model.WorkloadView{"ns/api": {Pod: model.Pod{Namespace: "ns", Name: "api", UID: "pod-uid", Ready: true, DesiredReplicas: 2, ReadyReplicas: 2, RouteService: "web-route", RouteServiceReady: true}}}
	return c, m, e, pol, view
}

func TestM132RealHybridPhoenixRefusalStillDeliversNativeAction(t *testing.T) {
	ctx := context.Background()
	selector := metav1.LabelSelector{MatchLabels: map[string]string{"app": "demo"}, MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "tier", Operator: metav1.LabelSelectorOpExists}}}
	c, m, e, pol, view := m132RouteFixture(t, selector)
	decisions := []model.Decision{
		{Selected: true, Feasible: true, Action: model.ActionQuarantine, Namespace: "ns", Pod: "api", Trace: &model.DecisionTraceV2{}},
		{Selected: true, Feasible: true, Action: model.ActionRouteRotate, Namespace: "ns", Pod: "api", Trace: &model.DecisionTraceV2{DecisionID: "m132-refusal-route"}},
	}
	if n, _ := m.actuatePrepared(ctx, e, pol, decisions, view); n != 1 || !decisions[1].Actuated || decisions[0].Actuated || decisions[0].Trace.DispatchReason != "route-preparation-failed" {
		t.Fatalf("real hybrid route result: n=%d Phoenix=%+v native=%+v", n, decisions[0].Trace, decisions[1].Trace)
	}
	var updated corev1.Pod
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "api"}, &updated); err != nil || updated.UID != "pod-uid" || updated.Annotations["phorvex.ai/route-epoch"] == "" {
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
	c, m, e, pol, view := m132RouteFixture(t, metav1.LabelSelector{MatchLabels: map[string]string{"app": "demo"}})
	decisions := []model.Decision{
		{Selected: true, Feasible: true, Action: model.ActionQuarantine, Namespace: "ns", Pod: "api", Trace: &model.DecisionTraceV2{}},
		{Selected: true, Feasible: true, Action: model.ActionRouteRotate, Namespace: "ns", Pod: "api", Trace: &model.DecisionTraceV2{DecisionID: "m132-equality-route"}},
	}
	if n, _ := m.actuatePrepared(ctx, e, pol, decisions, view); n != 2 || !decisions[0].Actuated || !decisions[1].Actuated {
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
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "api"}, &updated); err != nil || updated.Annotations["phorvex.ai/route-epoch"] == "" {
		t.Fatalf("native Pod update missing: %v %v", updated.Labels, err)
	}
	var restitched corev1.Service
	if err := c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "web-route"}, &restitched); err != nil || restitched.Spec.Selector["phorvex.ai/route-key"] != updated.Labels["phorvex.ai/route-key"] {
		t.Fatalf("native Service restitch missing: selector=%v pod=%v err=%v", restitched.Spec.Selector, updated.Labels, err)
	}
}

func TestM132RealHybridNativeOnlySkipsPhoenixPreparation(t *testing.T) {
	ctx := context.Background()
	selector := metav1.LabelSelector{MatchLabels: map[string]string{"app": "demo"}, MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "tier", Operator: metav1.LabelSelectorOpExists}}}
	c, m, e, pol, view := m132RouteFixture(t, selector)
	pol.EnabledActions = map[model.Action]bool{model.ActionRouteRotate: true}
	e.spec.Actions.Enabled = []v1alpha1.ActionType{v1alpha1.ActionRouteRotate}
	d := []model.Decision{{Selected: true, Feasible: true, Action: model.ActionRouteRotate, Namespace: "ns", Pod: "api", Trace: &model.DecisionTraceV2{DecisionID: "m132-native-only-route"}}}
	if n, prep := m.actuatePrepared(ctx, e, pol, d, view); n != 1 || prep == nil || !prep.PhoenixSkipped || prep.NativeSkipped || !d[0].Actuated {
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
