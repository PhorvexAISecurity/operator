package actuator

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/phorvex/phorvex/api/v1alpha1"
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
	e := &envtest.Environment{CRDDirectoryPaths: []string{"../../config/crd/bases"}}
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
	if err := v1alpha1.AddToScheme(scheme); err != nil {
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
	if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "operator"}}); err != nil {
		t.Fatal(err)
	}
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: "policy"}, Spec: v1alpha1.PhorvexPolicySpec{
		Mode: v1alpha1.ModeActive,
		Selector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
			Key: "phorvex.ai/fixture-never", Operator: metav1.LabelSelectorOpDoesNotExist,
		}}},
		Budget: v1alpha1.BudgetSpec{
			TickInterval:           metav1.Duration{Duration: 20 * time.Second},
			AntiOverRotationWindow: metav1.Duration{Duration: 5 * time.Minute},
			ProactiveFloor:         metav1.Duration{Duration: time.Hour},
		},
		Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionMIGRebind)}},
	}}
	if err := c.Create(ctx, policy); err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns.Name,
			Name:      "infer",
			Annotations: map[string]string{
				annoGPUID:      testGPUUUID,
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
	control := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: "control"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "control", Image: "example.invalid/control:test"}}}}
	if err := c.Create(ctx, control); err != nil {
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
	result, err := migRebindHandler{}.Enact(ctx, EnactCtx{Client: c, Reader: c, JournalNamespace: "operator", MIG: mig, VLLM: &mockVLLM{}, MIGProfiles: testMIGProfilesFor(pod.Namespace)}, Request{
		Namespace:  pod.Namespace,
		Pod:        pod.Name,
		TargetUID:  string(admitted.UID),
		Action:     model.ActionMIGRebind,
		PolicyName: policy.Name,
		PolicyUID:  string(policy.UID),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Emitted || len(mig.calls) != 1 || mig.calls[0] != ([3]string{"gpu-a", testGPUUUID, "2g.20gb"}) {
		t.Fatalf("admitted MIG path did not reach repartition: result=%+v calls=%v", result, mig.calls)
	}
	if err := c.Get(ctx, client.ObjectKeyFromObject(control), &corev1.Pod{}); err != nil {
		t.Fatalf("MIG handler touched unrelated control pod: %v", err)
	}
}
