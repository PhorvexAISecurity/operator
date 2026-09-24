package scenarios

import (
	"testing"

	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestNATSResponseManagerPinsOneActiveIncarnationWithRetainedOldRS(t *testing.T) {
	yes := true
	one, zero := int32(1), int32(0)
	selector := &metav1.LabelSelector{MatchLabels: map[string]string{"app": "manager"}}
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "phorvex", Namespace: "phorvex", UID: "dep-uid", Generation: 3},
		Spec: appsv1.DeploymentSpec{Replicas: &one, Selector: selector},
		Status: appsv1.DeploymentStatus{ObservedGeneration: 3, ReadyReplicas: 1}}
	owner := metav1.OwnerReference{APIVersion: "apps/v1", Kind: "Deployment", Name: dep.Name, UID: dep.UID, Controller: &yes}
	active := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "phorvex-current", Namespace: "phorvex", UID: "rs-current", Labels: map[string]string{"app": "manager"}, OwnerReferences: []metav1.OwnerReference{owner}},
		Spec: appsv1.ReplicaSetSpec{Replicas: &one}, Status: appsv1.ReplicaSetStatus{ReadyReplicas: 1}}
	old := active.DeepCopy()
	old.Name, old.UID, old.Spec.Replicas, old.Status.ReadyReplicas = "phorvex-old", "rs-old", &zero, 0
	imageID := "docker.io/phorvex/manager@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "phorvex-current-a", Namespace: "phorvex", UID: "pod-current",
		Labels: map[string]string{"app": "manager", "app.kubernetes.io/component": "manager"},
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: active.Name, UID: active.UID, Controller: &yes}}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "manager"}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning,
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
			ContainerStatuses: []corev1.ContainerStatus{{Name: "manager", Ready: true, ContainerID: "containerd://current", ImageID: imageID}}}}
	objects := func(p *corev1.Pod) *core.Env {
		return &core.Env{Kube: fake.NewSimpleClientset(dep.DeepCopy(), active.DeepCopy(), old.DeepCopy(), p),
			Config: config.TargetConfig{NATSExposureFixture: &config.NATSExposureFixtureConfig{
				ManagerNamespace: "phorvex", ManagerDeployment: dep.Name, ManagerImageID: imageID}}}
	}
	id, err := natsResponseManager(t.Context(), objects(pod))
	if err != nil || id.PodUID != pod.UID || id.ContainerID != "containerd://current" || id.ReplicaSetUID != active.UID {
		t.Fatalf("active manager incarnation not pinned: %+v %v", id, err)
	}
	for name, mutate := range map[string]func(*corev1.Pod){
		"wrong-image": func(p *corev1.Pod) { p.Status.ContainerStatuses[0].ImageID = "foreign" },
		"wrong-owner": func(p *corev1.Pod) { p.OwnerReferences[0].UID = "rs-old" },
		"restart": func(p *corev1.Pod) { p.Status.ContainerStatuses[0].RestartCount = 1 },
		"not-ready": func(p *corev1.Pod) { p.Status.ContainerStatuses[0].Ready = false },
	} {
		t.Run(name, func(t *testing.T) {
			bad := pod.DeepCopy()
			mutate(bad)
			if _, err := natsResponseManager(t.Context(), objects(bad)); err == nil {
				t.Fatal("changed manager process admitted")
			}
		})
	}
}
