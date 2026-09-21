package actuator

import (
	"context"
	"os"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
)

func TestM054ActualAPIServerReceivesBoundedEvictionAndLeavesTerminationUnconfirmed(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires local envtest API-server binaries")
	}
	env := &envtest.Environment{CRDDirectoryPaths: []string{"../../config/crd/bases"}, ErrorIfCRDPathMissing: true}
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
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, appsv1.AddToScheme, policyv1.AddToScheme, v1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	base, err := client.NewWithWatch(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "m054-native"}}
	if err := base.Create(ctx, ns); err != nil {
		t.Fatal(err)
	}
	replicas := int32(2)
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: "web"}, Spec: appsv1.ReplicaSetSpec{Replicas: &replicas, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "web"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "web", Image: "unused:test"}}}}}}
	if err := base.Create(ctx, rs); err != nil {
		t.Fatal(err)
	}
	cap, workloadGrace := int64(3), int64(120)
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: "policy"}, Spec: v1alpha1.PhorvexPolicySpec{
		Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
		Budget: v1alpha1.BudgetSpec{
			MaxGracePeriodSeconds:  &cap,
			TickInterval:           metav1.Duration{Duration: 20 * time.Second},
			AntiOverRotationWindow: metav1.Duration{Duration: 5 * time.Minute},
			ProactiveFloor:         metav1.Duration{Duration: time.Hour},
		},
		Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionRotate}},
	}}
	if err := base.Create(ctx, policy); err != nil {
		t.Fatal(err)
	}
	yes := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: ns.Name, Name: "web-0", Labels: map[string]string{"app": "web"}, Finalizers: []string{"m054.test/hold"},
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: &yes}},
	}, Spec: corev1.PodSpec{TerminationGracePeriodSeconds: &workloadGrace, Containers: []corev1.Container{{Name: "web", Image: "unused:test"}}}}
	if err := base.Create(ctx, pod); err != nil {
		t.Fatal(err)
	}
	minAvailable := intstr.FromInt(1)
	pdb := &policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: "web"}, Spec: policyv1.PodDisruptionBudgetSpec{MinAvailable: &minAvailable, Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}}}
	if err := base.Create(ctx, pdb); err != nil {
		t.Fatal(err)
	}
	if err := base.Get(ctx, client.ObjectKeyFromObject(pdb), pdb); err != nil {
		t.Fatal(err)
	}
	pdb.Status = policyv1.PodDisruptionBudgetStatus{ObservedGeneration: pdb.Generation, CurrentHealthy: 2, DesiredHealthy: 1, ExpectedPods: 2, DisruptionsAllowed: 1}
	if err := base.Status().Update(ctx, pdb); err != nil {
		t.Fatal(err)
	}
	observed := &m054EvictionObservation{forwardSubresource: true}
	writer := interceptor.NewClient(base, interceptor.Funcs{SubResourceCreate: observed.create, Delete: observed.delete})
	result, err := dispatch(ctx, EnactCtx{Client: writer, Reader: base}, Request{
		Namespace: pod.Namespace, Pod: pod.Name, TargetUID: string(pod.UID), Action: model.ActionRotate,
		PolicyName: policy.Name, PolicyUID: string(policy.UID), PolicyGeneration: policy.Generation,
		MaxGracePeriodSeconds: cap,
	})
	if err != nil || !result.Emitted || observed.calls != 1 || result.GracefulTermination == nil {
		t.Fatalf("result=%+v calls=%d err=%v", result, observed.calls, err)
	}
	if observed.eviction == nil || observed.eviction.DeleteOptions == nil || observed.eviction.DeleteOptions.GracePeriodSeconds == nil || *observed.eviction.DeleteOptions.GracePeriodSeconds != cap || observed.eviction.DeleteOptions.Preconditions == nil || observed.eviction.DeleteOptions.Preconditions.UID == nil || *observed.eviction.DeleteOptions.Preconditions.UID != pod.UID || observed.eviction.DeleteOptions.Preconditions.ResourceVersion == nil || *observed.eviction.DeleteOptions.Preconditions.ResourceVersion != pod.ResourceVersion {
		t.Fatalf("actual Eviction options=%+v", observed.eviction)
	}
	if observed.deletes != 0 {
		t.Fatalf("direct Pod DELETE fallback calls=%d", observed.deletes)
	}
	fresh := &corev1.Pod{}
	if err := base.Get(ctx, client.ObjectKeyFromObject(pod), fresh); err != nil {
		t.Fatalf("finalizer-delayed Pod missing: %v", err)
	}
	if fresh.DeletionTimestamp == nil || result.GracefulTermination.TerminationStatus != "unconfirmed" {
		t.Fatalf("Pod deletionTimestamp=%v receipt=%+v", fresh.DeletionTimestamp, result.GracefulTermination)
	}

	// Release the test-only finalizer so envtest teardown need not retain the Pod.
	fresh.Finalizers = nil
	if err := base.Update(ctx, fresh); err != nil && !apierrors.IsNotFound(err) {
		t.Fatal(err)
	}
}
