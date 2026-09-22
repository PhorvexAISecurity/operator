package runner

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
	"github.com/phorvex/phorvex/internal/model"
)

type rotationOwnershipCapture struct {
	policy model.Policy
	pods   map[string]model.RotationOwnership
}

func (*rotationOwnershipCapture) Name() string { return "rotation-ownership-capture" }
func (c *rotationOwnershipCapture) Decide(views []*model.WorkloadView, policy model.Policy) []model.Decision {
	c.policy = policy
	c.pods = make(map[string]model.RotationOwnership, len(views))
	for _, view := range views {
		c.pods[view.Pod.Name] = view.Pod.RotationOwnership
	}
	return nil
}

type failingOwnershipReader struct{ client.Reader }

func (r failingOwnershipReader) Get(context.Context, client.ObjectKey, client.Object, ...client.GetOption) error {
	return errors.New("ownership API unavailable")
}

func TestHybridRotateManagerTickSuppliesOwnershipReader(t *testing.T) {
	for _, tc := range []struct {
		name             string
		backend          actuator.Backend
		mutate           func(*appsv1.Deployment, *appsv1.ReplicaSet, []*corev1.Pod)
		reader           func(client.Client) client.Reader
		wantNativeRotate bool
		wantEligible     bool
		wantReason       string
	}{
		{name: "hybrid", backend: actuator.BackendHybrid, wantNativeRotate: true, wantEligible: true},
		{name: "native", backend: actuator.BackendNative, wantNativeRotate: true, wantEligible: true},
		{
			name: "hybrid-wrong-owner-uid", backend: actuator.BackendHybrid, wantNativeRotate: true, wantReason: "owner-uid-mismatch",
			mutate: func(_ *appsv1.Deployment, _ *appsv1.ReplicaSet, pods []*corev1.Pod) {
				for _, pod := range pods {
					pod.OwnerReferences[0].UID = "wrong-rs-uid"
				}
			},
		},
		{
			name: "hybrid-missing-owner-uid", backend: actuator.BackendHybrid, wantNativeRotate: true, wantReason: "owner-unresolved",
			mutate: func(_ *appsv1.Deployment, _ *appsv1.ReplicaSet, pods []*corev1.Pod) {
				for _, pod := range pods {
					pod.OwnerReferences[0].UID = ""
				}
			},
		},
		{
			name: "hybrid-owner-read-error", backend: actuator.BackendHybrid, wantNativeRotate: true, wantReason: "owner-unresolved",
			reader: func(c client.Client) client.Reader { return failingOwnershipReader{Reader: c} },
		},
		{
			name: "hybrid-nil-owner-reader", backend: actuator.BackendHybrid, wantNativeRotate: true, wantReason: "owner-unresolved",
			reader: func(client.Client) client.Reader { return nil },
		},
		{name: "phoenix-neutral", backend: actuator.BackendPhoenix, wantReason: "owner-unresolved"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manager, capture := newRotationOwnershipTickFixture(t, tc.backend, tc.mutate, tc.reader)
			if result := manager.tick(t.Context()); result != tickSnapshotSucceeded {
				t.Fatalf("tick result = %v, want %v", result, tickSnapshotSucceeded)
			}
			if capture.policy.NativeRotate != tc.wantNativeRotate {
				t.Fatalf("NativeRotate = %v, want %v", capture.policy.NativeRotate, tc.wantNativeRotate)
			}
			if len(capture.pods) != 2 {
				t.Fatalf("captured pods = %d, want 2", len(capture.pods))
			}
			for name, got := range capture.pods {
				if got.Eligible != tc.wantEligible || got.Reason != tc.wantReason {
					t.Errorf("pod %s ownership = %+v, want eligible=%v reason=%q", name, got, tc.wantEligible, tc.wantReason)
				}
				if tc.wantEligible && (got.OwnerUID != "rs-uid" || got.OwnerResourceVersion == "") {
					t.Errorf("pod %s eligible ownership identity = %+v", name, got)
				}
			}
		})
	}
}

func newRotationOwnershipTickFixture(
	t *testing.T,
	backend actuator.Backend,
	mutate func(*appsv1.Deployment, *appsv1.ReplicaSet, []*corev1.Pod),
	reader func(client.Client) client.Reader,
) (*Manager, *rotationOwnershipCapture) {
	t.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		v1alpha1.AddToScheme,
		appsv1.AddToScheme,
		corev1.AddToScheme,
		discoveryv1.AddToScheme,
		networkingv1.AddToScheme,
		policyv1.AddToScheme,
		rbacv1.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}

	const namespace = "ownership-fixture"
	replicas := int32(2)
	controller := true
	blockDeletion := true
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: "api", UID: "deployment-uid", ResourceVersion: "9"},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "api"}}},
		},
		Status: appsv1.DeploymentStatus{Replicas: replicas, ReadyReplicas: replicas, AvailableReplicas: replicas},
	}
	replicaSet := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace, Name: "api-7d9f", UID: "rs-uid", ResourceVersion: "7",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "Deployment", Name: deployment.Name, UID: deployment.UID,
				Controller: &controller, BlockOwnerDeletion: &blockDeletion,
			}},
		},
		Spec: appsv1.ReplicaSetSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api", "pod-template-hash": "7d9f"}},
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "api", "pod-template-hash": "7d9f"}}},
		},
		Status: appsv1.ReplicaSetStatus{Replicas: replicas, ReadyReplicas: replicas, AvailableReplicas: replicas},
	}
	pods := []*corev1.Pod{}
	for _, name := range []string{"api-7d9f-a", "api-7d9f-b"} {
		pods = append(pods, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: namespace, Name: name, UID: types.UID(name + "-uid"),
				Labels: map[string]string{"app": "api", "pod-template-hash": "7d9f"},
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: "apps/v1", Kind: "ReplicaSet", Name: replicaSet.Name, UID: replicaSet.UID,
					Controller: &controller, BlockOwnerDeletion: &blockDeletion,
				}},
			},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "fixture", Image: "fixture.invalid/fixture@sha256:0000000000000000000000000000000000000000000000000000000000000000"}}},
			Status: corev1.PodStatus{
				Phase:      corev1.PodRunning,
				Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue, LastTransitionTime: metav1.NewTime(time.Unix(1_700_000_000, 0))}},
			},
		})
	}
	if mutate != nil {
		mutate(deployment, replicaSet, pods)
	}
	policy := m140Policy("policy", "ownership-fixture", "policy-uid")
	policy.Namespace = namespace
	policy.Spec.Selector = metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}}

	objects := []client.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}},
		deployment,
		replicaSet,
		pods[0], pods[1],
		policy,
	}
	cluster := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&v1alpha1.PhorvexPolicy{}).
		WithObjects(objects...).Build()
	resolution := actuator.BackendResolution{Backend: backend, Source: actuator.SourceExplicit, Raw: string(backend), Present: true}
	manager, err := NewManagerWithBackend(cluster, logr.Discard(), resolution)
	if err != nil {
		t.Fatal(err)
	}
	manager.Calibration = nil
	manager.MetricsSource = nil
	manager.BoundaryReader = cluster
	if reader != nil {
		manager.OwnershipReader = reader(cluster)
	}
	capture := &rotationOwnershipCapture{}
	manager.Optimizer = capture
	if err := manager.Upsert(policy); err != nil {
		t.Fatal(err)
	}
	return manager, capture
}
