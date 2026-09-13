package actuator

import (
	"context"
	"os"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestM46APIAdmittedLimitOnlyMIGReachesHandler(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires local envtest API-server binaries")
	}
	e := &envtest.Environment{}
	cfg, err := e.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := e.Stop(); err != nil {
			t.Errorf("stop envtest: %v", err)
		}
	}()

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "m46-test"}}
	if err := c.Create(ctx, ns); err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns.Name,
			Name:      "infer",
			Annotations: map[string]string{
				annoGPUID:      "0",
				annoMIGProfile: "2g.20gb",
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "gpu-a",
			Containers: []corev1.Container{{
				Name:  "infer",
				Image: "example.invalid/infer:test",
				Resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{"nvidia.com/mig-1g.10gb": resource.MustParse("1")},
				},
			}},
		},
	}
	if err := c.Create(ctx, pod); err != nil {
		t.Fatal(err)
	}
	admitted := &corev1.Pod{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(pod), admitted); err != nil {
		t.Fatal(err)
	}
	if got := admitted.Spec.Containers[0].Resources.Requests["nvidia.com/mig-1g.10gb"]; got.Cmp(resource.MustParse("1")) != 0 {
		t.Fatalf("API admission did not default MIG request from limit: %s", got.String())
	}

	mig := &mockMIG{}
	result, err := migRebindHandler{}.Enact(ctx, EnactCtx{Client: c, MIG: mig, VLLM: &mockVLLM{}}, Request{
		Namespace: pod.Namespace,
		Pod:       pod.Name,
		Action:    model.ActionMIGRebind,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Emitted || len(mig.calls) != 1 {
		t.Fatalf("admitted MIG path did not reach repartition: result=%+v calls=%v", result, mig.calls)
	}
}
