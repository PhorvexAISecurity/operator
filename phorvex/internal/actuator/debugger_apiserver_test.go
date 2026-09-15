package actuator

import (
	"context"
	"os"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// The server, rather than the fake client, supplies Pod and ephemeral-container
// defaults. A repeated request must recognize its actual readback without claiming
// that an unobserved container is available.
func TestDebuggerActualAPIDefaultedReadback(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires local envtest API server")
	}
	localOnly := false
	e := &envtest.Environment{UseExistingCluster: &localOnly}
	cfg, err := e.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "m057-api"}}
	if err := c.Create(ctx, ns); err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: "target"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "primary", Image: "test:unused"}}}}
	if err := c.Create(ctx, pod); err != nil {
		t.Fatal(err)
	}
	req := Request{Namespace: ns.Name, Pod: pod.Name, TargetUID: string(pod.UID)}
	first, err := (debuggerHandler{}).Enact(ctx, EnactCtx{Client: c, Reader: c}, req)
	if err != nil || !first.Emitted {
		t.Fatalf("actual API first submission: %+v %v", first, err)
	}
	got := &corev1.Pod{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(pod), got); err != nil {
		t.Fatal(err)
	}
	if len(got.Spec.EphemeralContainers) != 1 || got.Spec.EphemeralContainers[0].TargetContainerName != "primary" {
		t.Fatalf("actual API target/readback: %+v", got.Spec.EphemeralContainers)
	}
	second, err := (debuggerHandler{}).Enact(ctx, EnactCtx{Client: c, Reader: c}, req)
	if err != nil || second.Emitted || !strings.Contains(second.Note, "status missing") {
		t.Fatalf("actual defaulted API readback idempotency: %+v %v", second, err)
	}
	customPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: "custom-target"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "primary", Image: "test:unused"}}}}
	if err := c.Create(ctx, customPod); err != nil {
		t.Fatal(err)
	}
	custom, err := (customInjectHandler{}).Enact(ctx, EnactCtx{Client: c, Reader: c}, Request{Namespace: ns.Name, Pod: customPod.Name, TargetUID: string(customPod.UID)})
	if err != nil || !custom.Emitted {
		t.Fatalf("custom-inject preservation: %+v %v", custom, err)
	}
	customReadback := &corev1.Pod{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(customPod), customReadback); err != nil {
		t.Fatal(err)
	}
	if len(customReadback.Spec.EphemeralContainers) != 1 || !sameEphemeralSpec(customReadback.Spec.EphemeralContainers[0], customInjectEphemeralSpec()) {
		t.Fatalf("custom-inject real API shape changed: %+v", customReadback.Spec.EphemeralContainers)
	}
}
