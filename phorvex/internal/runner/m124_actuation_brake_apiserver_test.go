package runner

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuationbrake"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/exposure"
	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

type m124RouteClient struct{ client.Client }

func (c *m124RouteClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if err := c.Client.Update(ctx, obj, opts...); err != nil {
		return err
	}
	return c.sync(ctx)
}

func (c *m124RouteClient) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	if err := c.Client.Patch(ctx, obj, patch, opts...); err != nil {
		return err
	}
	return c.sync(ctx)
}

func (c *m124RouteClient) sync(ctx context.Context) error {
	svc := &corev1.Service{}
	if err := c.Client.Get(ctx, client.ObjectKey{Namespace: "m124", Name: "web-route"}, svc); err != nil {
		return client.IgnoreNotFound(err)
	}
	var pods corev1.PodList
	if err := c.Client.List(ctx, &pods, client.InNamespace("m124")); err != nil {
		return err
	}
	selector := labels.SelectorFromSet(svc.Spec.Selector)
	ready := true
	endpoints := make([]discoveryv1.Endpoint, 0)
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !selector.Matches(labels.Set(pod.Labels)) {
			continue
		}
		ref := corev1.ObjectReference{APIVersion: "v1", Kind: "Pod", Namespace: pod.Namespace, Name: pod.Name, UID: pod.UID}
		endpoints = append(endpoints, discoveryv1.Endpoint{Addresses: []string{fmt.Sprintf("10.24.0.%d", i+1)}, TargetRef: &ref, Conditions: discoveryv1.EndpointConditions{Ready: &ready}})
	}
	slice := &discoveryv1.EndpointSlice{}
	if err := c.Client.Get(ctx, client.ObjectKey{Namespace: "m124", Name: "web-route-slice"}, slice); err != nil {
		return err
	}
	slice.Endpoints = endpoints
	return c.Client.Update(ctx, slice)
}

func TestM124RealAPIBrakesGuardNativeAndPhoenixDispatch(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires isolated envtest API server")
	}
	useExistingCluster := false
	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{"../../../build/phoenix-extended/config/crd/bases", "../../config/crd/bases"},
		ErrorIfCRDPathMissing: true,
		UseExistingCluster:    &useExistingCluster,
	}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Error(err)
		}
	})
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, discoveryv1.AddToScheme, v1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	if err := amtdv1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, namespace := range []string{"m124", "m124-operator"} {
		if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}); err != nil {
			t.Fatal(err)
		}
	}
	ready := []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	target := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "m124", Name: "api", Labels: map[string]string{"app": "demo", "phorvex.ai/route-key": "route-old"},
		Annotations: map[string]string{"phorvex.ai/route-service": "web-route"},
	}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "fixture"}}}}
	sibling := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "m124", Name: "peer", Labels: map[string]string{"app": "demo", "phorvex.ai/route-key": "route-old"},
	}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "fixture"}}}}
	for _, pod := range []*corev1.Pod{target, sibling} {
		if err := c.Create(ctx, pod); err != nil {
			t.Fatal(err)
		}
		pod.Status.Conditions = ready
		if err := c.Status().Update(ctx, pod); err != nil {
			t.Fatal(err)
		}
	}
	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "m124", Name: "web-route"}, Spec: corev1.ServiceSpec{
		Selector: map[string]string{"app": "demo", "phorvex.ai/route-key": "route-old"},
		Ports:    []corev1.ServicePort{{Name: "http", Port: 80}},
	}}
	if err := c.Create(ctx, service); err != nil {
		t.Fatal(err)
	}
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "m124", Name: "policy"}, Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "demo"}}, Budget: v1alpha1.BudgetSpec{TickInterval: metav1.Duration{Duration: 20 * time.Second}, AntiOverRotationWindow: metav1.Duration{Duration: 5 * time.Minute}, ProactiveFloor: metav1.Duration{Duration: time.Hour}}, SLO: v1alpha1.SLOSpec{MinAvailableReplicas: 1}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionRouteRotate}}}}
	if err := c.Create(ctx, policy); err != nil {
		t.Fatal(err)
	}
	readyEndpoint := true
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Namespace: "m124", Name: "web-route-slice", Labels: map[string]string{discoveryv1.LabelServiceName: service.Name}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: service.Name, UID: service.UID}}}, AddressType: discoveryv1.AddressTypeIPv4}
	for i, pod := range []*corev1.Pod{target, sibling} {
		ref := corev1.ObjectReference{APIVersion: "v1", Kind: "Pod", Namespace: pod.Namespace, Name: pod.Name, UID: pod.UID}
		slice.Endpoints = append(slice.Endpoints, discoveryv1.Endpoint{Addresses: []string{fmt.Sprintf("10.24.0.%d", i+1)}, TargetRef: &ref, Conditions: discoveryv1.EndpointConditions{Ready: &readyEndpoint}})
	}
	if err := c.Create(ctx, slice); err != nil {
		t.Fatal(err)
	}
	routeClient := &m124RouteClient{Client: c}

	view := map[string]*model.WorkloadView{"m124/api": {Pod: model.Pod{
		Namespace: "m124", Name: "api", UID: string(target.UID), Ready: true,
		DesiredReplicas: 2, ReadyReplicas: 2, RouteService: "web-route", RouteServiceReady: true,
	}}}
	entry := &policyEntry{key: types.NamespacedName{Namespace: "m124", Name: policy.Name}, uid: string(policy.UID), namespace: "m124", tenant: "tenant", spec: policy.Spec}
	native := actuator.NewNativeActuator(routeClient)
	native.SetBoundaryReader(routeClient)
	native.JournalNamespace = "m124-operator"
	native.RouteObservationTimeout = 2 * time.Second
	native.RouteObservationInterval = 10 * time.Millisecond
	nativeManager := &Manager{Actuator: native, BoundaryReader: routeClient, Intents: exposure.NewIntents(), Log: logr.Discard()}
	nativeDecision := []model.Decision{{Selected: true, Feasible: true, Namespace: "m124", Pod: "api", Action: model.ActionRouteRotate, Trace: &model.DecisionTraceV2{DecisionID: "m124-route-positive"}}}
	nativePolicy := model.Policy{Tenant: "tenant", PolicyName: policy.Name, PolicyUID: string(policy.UID), MinAvailableReplicas: 1, EnabledActions: map[model.Action]bool{model.ActionRouteRotate: true}}
	if got := nativeManager.actuate(ctx, entry, nativePolicy, nativeDecision, view); got != 1 || !nativeDecision[0].Actuated {
		t.Fatalf("native positive control got=%d decision=%+v trace=%+v", got, nativeDecision[0], nativeDecision[0].Trace)
	}
	var afterNative corev1.Pod
	if err := c.Get(ctx, client.ObjectKeyFromObject(target), &afterNative); err != nil ||
		afterNative.Annotations["phorvex.ai/route-epoch"] == "" || afterNative.Labels["phorvex.ai/route-key"] == "route-old" {
		t.Fatalf("actual native Pod mutation missing: annotations=%v labels=%v err=%v", afterNative.Annotations, afterNative.Labels, err)
	}

	m124SetAnnotation(t, c, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "m124", Name: "api"}}, actuationbrake.PodOptOutAnnotation, " TRUE ")
	var serviceBefore corev1.Service
	if err := c.Get(ctx, client.ObjectKeyFromObject(service), &serviceBefore); err != nil {
		t.Fatal(err)
	}
	blockedNative := []model.Decision{{Selected: true, Feasible: true, Namespace: "m124", Pod: "api", Action: model.ActionRouteRotate, Trace: &model.DecisionTraceV2{}}}
	if got := nativeManager.actuate(ctx, entry, nativePolicy, blockedNative, view); got != 0 || blockedNative[0].ActuationBrakeCause != actuationbrake.PodOptOutEngaged {
		t.Fatalf("Pod opt-out native refusal got=%d decision=%+v", got, blockedNative[0])
	}
	var serviceAfter corev1.Service
	if err := c.Get(ctx, client.ObjectKeyFromObject(service), &serviceAfter); err != nil || serviceAfter.ResourceVersion != serviceBefore.ResourceVersion {
		t.Fatalf("braked native path mutated Service: before=%s after=%s err=%v", serviceBefore.ResourceVersion, serviceAfter.ResourceVersion, err)
	}

	m124SetAnnotation(t, c, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "m124", Name: "api"}}, actuationbrake.PodOptOutAnnotation, "false")
	quarantineCapacity, err := actuator.NewQuarantineCapacity(c, c, "m124-operator", 1)
	if err != nil {
		t.Fatal(err)
	}
	phoenixManager := &Manager{Actuator: actuator.NewPhoenixActuator(c), BoundaryReader: c, QuarantineCapacity: quarantineCapacity, Intents: exposure.NewIntents(), Log: logr.Discard()}
	phoenixPolicy := model.Policy{Tenant: "tenant", PolicyName: policy.Name, PolicyUID: string(policy.UID), EnabledActions: map[model.Action]bool{model.ActionQuarantine: true}}
	phoenixDecision := []model.Decision{{Selected: true, Feasible: true, Namespace: "m124", Pod: "api", Action: model.ActionQuarantine, Trace: &model.DecisionTraceV2{}}}
	if got := phoenixManager.actuate(ctx, entry, phoenixPolicy, phoenixDecision, view); got != 1 || !phoenixDecision[0].Actuated {
		t.Fatalf("Phoenix positive control got=%d decision=%+v trace=%+v", got, phoenixDecision[0], phoenixDecision[0].Trace)
	}
	var events amtdv1beta1.SecurityEventList
	if err := c.List(ctx, &events, client.InNamespace("m124")); err != nil || len(events.Items) != 1 {
		t.Fatalf("actual Phoenix event count=%d err=%v", len(events.Items), err)
	}

	// Pure Phoenix must visibly refuse bounded rotate before a SecurityEvent. This
	// is the migration boundary: deployments needing rotate select native or hybrid.
	unsupportedRotatePolicy := model.Policy{Tenant: "tenant", PolicyName: policy.Name, PolicyUID: string(policy.UID), EnabledActions: map[model.Action]bool{model.ActionRotate: true}}
	unsupportedRotate := []model.Decision{{Selected: true, Feasible: true, Namespace: "m124", Pod: "api", Action: model.ActionRotate, Trace: &model.DecisionTraceV2{}}}
	if got := phoenixManager.actuate(ctx, entry, unsupportedRotatePolicy, unsupportedRotate, view); got != 0 || unsupportedRotate[0].Actuated || unsupportedRotate[0].DispatchOutcome != model.DispatchRefused || unsupportedRotate[0].Phoenix != nil {
		t.Fatalf("pure Phoenix bounded rotate was not explicitly refused: got=%d decision=%+v", got, unsupportedRotate[0])
	}
	events = amtdv1beta1.SecurityEventList{}
	if err := c.List(ctx, &events, client.InNamespace("m124")); err != nil || len(events.Items) != 1 {
		t.Fatalf("unsupported Phoenix rotate emitted an event: count=%d err=%v", len(events.Items), err)
	}

	m124SetAnnotation(t, c, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "m124"}}, actuationbrake.NamespaceDryRunAnnotation, " yes ")
	blockedPhoenix := []model.Decision{{Selected: true, Feasible: true, Namespace: "m124", Pod: "api", Action: model.ActionQuarantine, Trace: &model.DecisionTraceV2{}}}
	if got := phoenixManager.actuate(ctx, entry, phoenixPolicy, blockedPhoenix, view); got != 0 || blockedPhoenix[0].DryRunCause != actuationbrake.NamespaceDryRunEngaged {
		t.Fatalf("namespace dry-run Phoenix refusal got=%d decision=%+v", got, blockedPhoenix[0])
	}
	events = amtdv1beta1.SecurityEventList{}
	if err := c.List(ctx, &events, client.InNamespace("m124")); err != nil || len(events.Items) != 1 {
		t.Fatalf("braked Phoenix path emitted another event: count=%d err=%v", len(events.Items), err)
	}
}
