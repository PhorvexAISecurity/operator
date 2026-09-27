package console

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestDigestNamedVLLMWorkloadRemainsVisible(t *testing.T) {
	// Mirrors the installed private ECR image and reviewed serving shape. The
	// repository name contains no "vllm"; its Pod has two distinct containers.
	engine := corev1.Container{Name: "vllm",
		Image: "753556437180.dkr.ecr.us-east-2.amazonaws.com/phorvex@sha256:3534dec6b97c1b6e4042b3cb2987c6cf8c4d4e4167a833320e2f1b7f4135d050",
		Args: []string{"--model", "Qwen/Qwen2.5-7B-Instruct-AWQ", "--max-model-len", "4096",
			"--gpu-memory-utilization", "0.72", "--port", "8001", "--host", "127.0.0.1"}}
	annotations := map[string]string{"phorvex.ai/model-id": "Qwen2.5-7B-Instruct-AWQ",
		"phorvex.ai/route-service": "vllm", "phorvex.ai/serving-port": "8443"}
	deployment := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "vllm", Namespace: "vllm"},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{Annotations: annotations},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{engine, {Name: "guardrail", Image: "python:3.11-slim"}}}}}}
	server := &Server{}
	stack, err := server.stackOfClient(context.Background(), "vllm", true, fake.NewSimpleClientset(deployment))
	if err != nil || !stack.Workload || !stack.ServedModel || !stack.VLLM {
		t.Fatalf("installed vLLM shape missing: stack=%+v err=%v", stack, err)
	}
	visible := false
	for _, row := range compatibleLive(stack) {
		if row.ID == "guardrail-rotate" {
			visible = row.Compatible && row.Armed
		}
	}
	if !visible {
		t.Fatal("vLLM live row remains hidden")
	}
	for _, mutate := range []struct {
		name string
		edit func(*appsv1.Deployment)
	}{
		{"unrelated container", func(d *appsv1.Deployment) { d.Spec.Template.Spec.Containers[0].Name = "worker" }},
		{"missing serving declaration", func(d *appsv1.Deployment) { delete(d.Spec.Template.Annotations, "phorvex.ai/model-id") }},
		{"missing vLLM argument", func(d *appsv1.Deployment) {
			d.Spec.Template.Spec.Containers[0].Args = []string{"--model", "Qwen/Qwen2.5-7B-Instruct-AWQ"}
		}},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			other := deployment.DeepCopy()
			mutate.edit(other)
			got, err := server.stackOfClient(context.Background(), "vllm", true, fake.NewSimpleClientset(other))
			if err != nil || got.ServedModel || got.VLLM {
				t.Fatalf("unreviewed workload identified as vLLM: stack=%+v err=%v", got, err)
			}
		})
	}
}

func TestNamedVLLMStatefulSetStillVisible(t *testing.T) {
	sts := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "inference", Namespace: "vllm"},
		Spec: appsv1.StatefulSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{
			{Name: "engine", Image: "example.com/vllm-openai:v0.7.3"},
		}}}}}
	stack, err := (&Server{}).stackOfClient(context.Background(), "vllm", false, fake.NewSimpleClientset(sts))
	if err != nil || !stack.Stateful || !stack.VLLM || !stack.ServedModel {
		t.Fatalf("named vLLM StatefulSet regressed: stack=%+v err=%v", stack, err)
	}
}
