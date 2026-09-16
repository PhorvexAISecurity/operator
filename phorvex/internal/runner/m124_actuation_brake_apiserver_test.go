package runner

import (
	"context"
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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestM124RealAPIBrakesGuardNativeAndPhoenixDispatch(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires isolated envtest API server")
	}
	useExistingCluster := false
	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{"../../../build/phoenix-extended/config/crd/bases"},
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
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
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
	if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "m124"}}); err != nil {
		t.Fatal(err)
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

	view := map[string]*model.WorkloadView{"m124/api": {Pod: model.Pod{
		Namespace: "m124", Name: "api", UID: string(target.UID), Ready: true,
		DesiredReplicas: 2, ReadyReplicas: 2, RouteService: "web-route", RouteServiceReady: true,
	}}}
	entry := &policyEntry{namespace: "m124", tenant: "tenant", spec: v1alpha1.PhorvexPolicySpec{Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "demo"}}}}
	native := actuator.NewNativeActuator(c)
	native.SetBoundaryReader(c)
	nativeManager := &Manager{Actuator: native, BoundaryReader: c, Intents: exposure.NewIntents(), Log: logr.Discard()}
	nativeDecision := []model.Decision{{Selected: true, Feasible: true, Namespace: "m124", Pod: "api", Action: model.ActionRouteRotate, Trace: &model.DecisionTraceV2{}}}
	nativePolicy := model.Policy{Tenant: "tenant", MinAvailableReplicas: 1, EnabledActions: map[model.Action]bool{model.ActionRouteRotate: true}}
	if got := nativeManager.actuate(ctx, entry, nativePolicy, nativeDecision, view); got != 1 || !nativeDecision[0].Actuated {
		t.Fatalf("native positive control got=%d decision=%+v trace=%+v", got, nativeDecision[0], nativeDecision[0].Trace)
	}
	var afterNative corev1.Pod
	if err := c.Get(ctx, client.ObjectKeyFromObject(target), &afterNative); err != nil ||
		afterNative.Annotations["phorvex.ai/route-snapshot"] == "" || afterNative.Labels["phorvex.ai/route-key"] == "route-old" {
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
	phoenixManager := &Manager{Actuator: actuator.NewPhoenixActuator(c), BoundaryReader: c, Intents: exposure.NewIntents(), Log: logr.Discard()}
	phoenixPolicy := model.Policy{Tenant: "tenant", EnabledActions: map[model.Action]bool{model.ActionRotate: true}}
	phoenixDecision := []model.Decision{{Selected: true, Feasible: true, Namespace: "m124", Pod: "api", Action: model.ActionRotate, Trace: &model.DecisionTraceV2{}}}
	if got := phoenixManager.actuate(ctx, entry, phoenixPolicy, phoenixDecision, view); got != 1 || !phoenixDecision[0].Actuated {
		t.Fatalf("Phoenix positive control got=%d decision=%+v trace=%+v", got, phoenixDecision[0], phoenixDecision[0].Trace)
	}
	var events amtdv1beta1.SecurityEventList
	if err := c.List(ctx, &events, client.InNamespace("m124")); err != nil || len(events.Items) != 1 {
		t.Fatalf("actual Phoenix event count=%d err=%v", len(events.Items), err)
	}

	m124SetAnnotation(t, c, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "m124"}}, actuationbrake.NamespaceDryRunAnnotation, " yes ")
	blockedPhoenix := []model.Decision{{Selected: true, Feasible: true, Namespace: "m124", Pod: "api", Action: model.ActionRotate, Trace: &model.DecisionTraceV2{}}}
	if got := phoenixManager.actuate(ctx, entry, phoenixPolicy, blockedPhoenix, view); got != 0 || blockedPhoenix[0].DryRunCause != actuationbrake.NamespaceDryRunEngaged {
		t.Fatalf("namespace dry-run Phoenix refusal got=%d decision=%+v", got, blockedPhoenix[0])
	}
	events = amtdv1beta1.SecurityEventList{}
	if err := c.List(ctx, &events, client.InNamespace("m124")); err != nil || len(events.Items) != 1 {
		t.Fatalf("braked Phoenix path emitted another event: count=%d err=%v", len(events.Items), err)
	}
}
