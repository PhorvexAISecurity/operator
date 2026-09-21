package currentinventory

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestM100CurrentInventoryRequiresExactReadOnlyMountedSource(t *testing.T) {
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "data", UID: types.UID("cm-uid"), ResourceVersion: "7"}, Data: map[string]string{"payload": "v2"}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pod", UID: types.UID("pod-uid")}, Spec: corev1.PodSpec{Volumes: []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "data"}}}}}, Containers: []corev1.Container{{Name: "server", VolumeMounts: []corev1.VolumeMount{{Name: "data", MountPath: "/data", ReadOnly: true}}}}}}
	if _, err := BindingFor(pod, cm, "payload", "data", "server", "/data", "payload"); err != nil {
		t.Fatal(err)
	}
	unmounted := pod.DeepCopy()
	unmounted.Spec.Containers[0].VolumeMounts = nil
	if _, err := BindingFor(unmounted, cm, "payload", "data", "server", "/data", "payload"); err == nil {
		t.Fatal("unmounted ConfigMap accepted")
	}
	writable := pod.DeepCopy()
	writable.Spec.Containers[0].VolumeMounts[0].ReadOnly = false
	if _, err := BindingFor(writable, cm, "payload", "data", "server", "/data", "payload"); err == nil {
		t.Fatal("writable mount accepted")
	}
	optional := true
	optionalPod := pod.DeepCopy()
	optionalPod.Spec.Volumes[0].ConfigMap.Optional = &optional
	if _, err := BindingFor(optionalPod, cm, "payload", "data", "server", "/data", "payload"); err == nil {
		t.Fatal("optional ConfigMap source accepted")
	}
	duplicateKey := pod.DeepCopy()
	duplicateKey.Spec.Volumes[0].ConfigMap.Items = []corev1.KeyToPath{{Key: "payload", Path: "payload"}, {Key: "payload", Path: "other"}}
	if _, err := BindingFor(duplicateKey, cm, "payload", "data", "server", "/data", "payload"); err == nil {
		t.Fatal("duplicate ConfigMap key projection accepted")
	}
	duplicatePath := pod.DeepCopy()
	duplicatePath.Spec.Volumes[0].ConfigMap.Items = []corev1.KeyToPath{{Key: "payload", Path: "payload"}, {Key: "other", Path: "payload"}}
	if _, err := BindingFor(duplicatePath, cm, "payload", "data", "server", "/data", "payload"); err == nil {
		t.Fatal("duplicate ConfigMap destination projection accepted")
	}
}
