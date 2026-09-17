package runner

import (
	"context"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/exposure"
	"github.com/phorvex/phorvex/internal/model"
)

type routeRunnerClient struct {
	client.Client
}

func (c *routeRunnerClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if obj.GetUID() == "" {
		obj.SetUID(types.UID("uid-" + obj.GetName()))
	}
	return c.Client.Create(ctx, obj, opts...)
}

func routeRunnerMatches(selector, labels map[string]string) bool {
	if len(selector) == 0 {
		return false
	}
	for key, value := range selector {
		if labels[key] != value {
			return false
		}
	}
	return true
}

func (c *routeRunnerClient) reconcile(ctx context.Context, namespace, serviceName string) error {
	svc := &corev1.Service{}
	if err := c.Client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: serviceName}, svc); err != nil {
		return err
	}
	var pods corev1.PodList
	if err := c.Client.List(ctx, &pods, client.InNamespace(namespace)); err != nil {
		return err
	}
	endpoints := []discoveryv1.Endpoint{}
	for i := range pods.Items {
		pod := &pods.Items[i]
		ready := false
		for _, condition := range pod.Status.Conditions {
			ready = ready || (condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue)
		}
		if !ready || !routeRunnerMatches(svc.Spec.Selector, pod.Labels) {
			continue
		}
		active := true
		ref := corev1.ObjectReference{APIVersion: "v1", Kind: "Pod", Namespace: namespace, Name: pod.Name, UID: pod.UID}
		endpoints = append(endpoints, discoveryv1.Endpoint{Addresses: []string{pod.Status.PodIP}, TargetRef: &ref, Conditions: discoveryv1.EndpointConditions{Ready: &active}})
	}
	slice := &discoveryv1.EndpointSlice{}
	if err := c.Client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: serviceName + "-slice"}, slice); err != nil {
		return err
	}
	slice.Endpoints = endpoints
	return c.Client.Update(ctx, slice)
}

func (c *routeRunnerClient) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	if err := c.Client.Patch(ctx, obj, patch, opts...); err != nil {
		return err
	}
	if pod, ok := obj.(*corev1.Pod); ok {
		return c.reconcile(ctx, pod.Namespace, pod.Annotations["phorvex.ai/route-service"])
	}
	return nil
}

func (c *routeRunnerClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if err := c.Client.Update(ctx, obj, opts...); err != nil {
		return err
	}
	if svc, ok := obj.(*corev1.Service); ok {
		return c.reconcile(ctx, svc.Namespace, svc.Name)
	}
	return nil
}

func TestRouteTerminalReceiptReconcilesThroughActualNativeRunner(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := discoveryv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "route-runner", UID: "uid-route-runner"}}
	op := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "route-runner-operator", UID: "uid-route-runner-operator"}}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: "target", UID: "uid-route-runner-target", Labels: map[string]string{"app": "route", "phorvex.ai/route-key": "old"}, Annotations: map[string]string{"phorvex.ai/route-service": "route"}},
		Status:     corev1.PodStatus{PodIP: "10.33.0.10", Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
	}
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: "route", UID: "uid-route-runner-service"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "route", "phorvex.ai/route-key": "old"}}}
	ready := true
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta:  metav1.ObjectMeta{Namespace: ns.Name, Name: "route-slice", UID: "uid-route-runner-slice", Labels: map[string]string{discoveryv1.LabelServiceName: svc.Name}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: svc.Name, UID: svc.UID}}},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{pod.Status.PodIP}, TargetRef: &corev1.ObjectReference{APIVersion: "v1", Kind: "Pod", Namespace: ns.Name, Name: pod.Name, UID: pod.UID}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}}},
	}
	policyObject := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: "policy", UID: "uid-route-runner-policy"}, Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "route"}}, SLO: v1alpha1.SLOSpec{MinAvailableReplicas: 1}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionRouteRotate}}}}
	base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns, op, pod, svc, slice, policyObject).Build()
	c := &routeRunnerClient{Client: base}
	native := &actuator.NativeActuator{Client: c, Reader: c, JournalNamespace: op.Name, RouteObservationTimeout: 100 * time.Millisecond, RouteObservationInterval: time.Millisecond}
	manager := &Manager{Actuator: native, Intents: exposure.NewIntents(), Log: logr.Discard()}
	policy := model.Policy{Tenant: "tenant", PolicyName: policyObject.Name, PolicyUID: string(policyObject.UID), MinAvailableReplicas: 1, EnabledActions: map[model.Action]bool{model.ActionRouteRotate: true}}
	view := &model.WorkloadView{Pod: model.Pod{Namespace: ns.Name, Name: pod.Name, UID: string(pod.UID), Ready: true, DesiredReplicas: 1, ReadyReplicas: 1}}
	views := map[string]*model.WorkloadView{ns.Name + "/" + pod.Name: view}
	decision := func() []model.Decision {
		return []model.Decision{{Namespace: ns.Name, Pod: pod.Name, Action: model.ActionRouteRotate, Selected: true, Feasible: true, Trace: &model.DecisionTraceV2{DecisionID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", DispatchOutcome: model.DispatchNotAttempted, DispatchReason: "pending-dispatch"}}}
	}
	entry := &policyEntry{namespace: ns.Name, spec: v1alpha1.PhorvexPolicySpec{Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "route"}}}}
	first := decision()
	if got := actuateWithBoundary(t, manager, ctx, entry, policy, first, views); got != 1 || !first[0].Actuated || first[0].DispatchOutcome != model.DispatchEmitted || first[0].RollbackRef == "" {
		t.Fatalf("first route dispatch = count=%d decision=%+v", got, first[0])
	}
	second := decision()
	if got := actuateWithBoundary(t, manager, ctx, entry, policy, second, views); got != 0 {
		t.Fatalf("terminal retry actuations=%d decision=%+v", got, second[0])
	}
	if second[0].Actuated || second[0].DispatchOutcome != model.DispatchReconciled || second[0].DispatchReason != "reconciled-prior-operation" ||
		second[0].MutationKind != "none" || second[0].RollbackRef != first[0].RollbackRef || len(second[0].ObjectsTouched) != 3 || len(manager.Failures.at) != 0 || len(manager.fallbackDecisions) != 0 {
		t.Fatalf("terminal route receipt was not retained as reconciled no-effect: decision=%+v failures=%+v fallback=%+v", second[0], manager.Failures.at, manager.fallbackDecisions)
	}
}
