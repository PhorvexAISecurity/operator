package voiceoutputpolicy

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestVerifySourceObjectsBindsMountedFourFileBundle(t *testing.T) {
	immutable := true
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "voice-bot", Namespace: Namespace,
		UID: types.UID("11111111-1111-4111-8111-111111111111")}}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: Namespace,
		UID: types.UID("22222222-2222-4222-8222-222222222222"), ResourceVersion: "1",
		OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(dep, appsv1.SchemeGroupVersion.WithKind("Deployment"))}},
		Immutable: &immutable, Data: map[string]string{
			"bot.py": "bot source", "voice_memory_policy.py": "memory source",
			"voice_output_policy.py": "output source", "voice_mcp_policy.py": "mcp source",
		}}
	sourceSHA, bundleSHA, err := SourceHashes(cm)
	if err != nil {
		t.Fatal(err)
	}
	cm.Name = "voice-memory-source-" + bundleSHA[:12]
	bot := corev1.Container{Name: "bot", Image: "voice@sha256:" + strings.Repeat("c", 64),
		Command: []string{"python3", "-B", "/app/bot.py"}}
	for _, name := range sourceFiles {
		bot.VolumeMounts = append(bot.VolumeMounts, corev1.VolumeMount{Name: "source", MountPath: "/app/" + name, SubPath: name, ReadOnly: true})
	}
	spec := corev1.PodSpec{Containers: []corev1.Container{bot}, Volumes: []corev1.Volume{{Name: "source",
		VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: cm.Name}}}}}}
	annotations := map[string]string{SourceConfigMapAnnotation: cm.Name, SourceSHAAnnotation: sourceSHA}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "voice-bot-1", Namespace: Namespace, Annotations: annotations}, Spec: spec}
	dep.Spec.Template = corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Annotations: annotations}, Spec: *spec.DeepCopy()}
	if got, err := VerifySourceObjects(pod, dep, cm); err != nil || got.ConfigMapUID != string(cm.UID) || got.SourceSHA256 != sourceSHA {
		t.Fatalf("reviewed mounted source rejected: %+v, %v", got, err)
	}
	for name, mutate := range map[string]func(*corev1.Pod, *appsv1.Deployment, *corev1.ConfigMap){
		"output-byte": func(_ *corev1.Pod, _ *appsv1.Deployment, cm *corev1.ConfigMap) {
			cm.Data["voice_output_policy.py"] += " changed"
		},
		"mcp-byte": func(_ *corev1.Pod, _ *appsv1.Deployment, cm *corev1.ConfigMap) {
			cm.Data["voice_mcp_policy.py"] += " changed"
		},
		"mutable": func(_ *corev1.Pod, _ *appsv1.Deployment, cm *corev1.ConfigMap) { cm.Immutable = nil },
		"owner": func(_ *corev1.Pod, _ *appsv1.Deployment, cm *corev1.ConfigMap) {
			cm.OwnerReferences[0].UID = types.UID("33333333-3333-4333-8333-333333333333")
		},
		"mount": func(p *corev1.Pod, _ *appsv1.Deployment, _ *corev1.ConfigMap) {
			p.Spec.Containers[0].VolumeMounts[2].ReadOnly = false
		},
		"command": func(p *corev1.Pod, _ *appsv1.Deployment, _ *corev1.ConfigMap) {
			p.Spec.Containers[0].Command = []string{"sh", "-c", "cat /app/bot.py"}
		},
		"template": func(_ *corev1.Pod, d *appsv1.Deployment, _ *corev1.ConfigMap) {
			d.Spec.Template.Spec.Containers[0].VolumeMounts[0].SubPath = "wrong.py"
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, d, c := pod.DeepCopy(), dep.DeepCopy(), cm.DeepCopy()
			mutate(p, d, c)
			if _, err := VerifySourceObjects(p, d, c); err == nil {
				t.Fatal("changed source graph accepted")
			}
		})
	}
}
