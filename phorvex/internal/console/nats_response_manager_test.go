package console

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func TestNATSResponseManagerRequiresOneControllerOwnedPod(t *testing.T) {
	const ns = "phorvex-system"
	one := int32(1)
	controller := true
	labels := map[string]string{"app.kubernetes.io/component": "manager"}
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "manager", Namespace: ns, UID: "dep-uid", Generation: 3},
		Spec:   appsv1.DeploymentSpec{Replicas: &one, Selector: &metav1.LabelSelector{MatchLabels: labels}},
		Status: appsv1.DeploymentStatus{ObservedGeneration: 3, ReadyReplicas: 1}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "manager-rs", Namespace: ns, UID: "rs-uid", Labels: labels,
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: dep.Name, UID: dep.UID, Controller: &controller}}},
		Spec: appsv1.ReplicaSetSpec{Replicas: &one}, Status: appsv1.ReplicaSetStatus{ReadyReplicas: 1}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "manager-pod", Namespace: ns, UID: "pod-uid", Labels: labels,
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: &controller}}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "manager"}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning,
			Conditions:        []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
			ContainerStatuses: []corev1.ContainerStatus{{Name: "manager", Ready: true, ContainerID: "containerd://current", ImageID: "sha256:current"}}}}
	pin := natsResponseConfigPin{}
	pin.Fixture.ManagerNamespace = ns
	pin.Fixture.ManagerDeployment = dep.Name
	pin.Fixture.ManagerImageID = "sha256:current"
	r := natsResponseRequest{ManagerPodUID: string(pod.UID), ManagerContainerID: pod.Status.ContainerStatuses[0].ContainerID}
	check := func(t *testing.T, mutate func(*appsv1.Deployment, *appsv1.ReplicaSet, *corev1.Pod) []corev1.Pod, wantOK bool) {
		t.Helper()
		d, s, p := dep.DeepCopy(), rs.DeepCopy(), pod.DeepCopy()
		others := mutate(d, s, p)
		kc := fake.NewClientset(d, s, p)
		for i := range others {
			if _, err := kc.CoreV1().Pods(ns).Create(context.Background(), &others[i], metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
		}
		err := (&Server{}).verifyNATSManager(context.Background(), kc, r, pin)
		if (err == nil) != wantOK {
			t.Fatalf("manager singleton verdict=%v, wantOK=%v", err, wantOK)
		}
	}
	t.Run("exact singleton", func(t *testing.T) {
		check(t, func(_ *appsv1.Deployment, _ *appsv1.ReplicaSet, _ *corev1.Pod) []corev1.Pod { return nil }, true)
	})
	t.Run("second active Pod", func(t *testing.T) {
		check(t, func(_ *appsv1.Deployment, _ *appsv1.ReplicaSet, p *corev1.Pod) []corev1.Pod {
			other := p.DeepCopy()
			other.Name, other.UID = "manager-other", types.UID("other-uid")
			return []corev1.Pod{*other}
		}, false)
	})
	t.Run("foreign ReplicaSet owner", func(t *testing.T) {
		check(t, func(_ *appsv1.Deployment, s *appsv1.ReplicaSet, _ *corev1.Pod) []corev1.Pod {
			s.OwnerReferences[0].UID = "foreign-deployment"
			return nil
		}, false)
	})
}
