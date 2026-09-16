package actuator

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/model"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestM090RealAPITerminatingPodRefusedBySharedRead(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires local envtest API-server binaries")
	}
	localOnly := false
	e := &envtest.Environment{UseExistingCluster: &localOnly}
	cfg, err := e.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := e.Stop(); err != nil {
			t.Errorf("stop envtest: %v", err)
		}
	})

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := networkingv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "m090"}}
	if err := c.Create(ctx, ns); err != nil {
		t.Fatal(err)
	}
	active := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns.Name, Name: "active"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "example.invalid/app:test"}}}}
	terminating := active.DeepCopy()
	terminating.Name = "terminating"
	terminating.Finalizers = []string{"m090.phorvex.ai/retain"}
	for _, pod := range []*corev1.Pod{active, terminating} {
		if err := c.Create(ctx, pod); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Delete(ctx, terminating); err != nil {
		t.Fatal(err)
	}
	var produced corev1.Pod
	if err := c.Get(ctx, client.ObjectKeyFromObject(terminating), &produced); err != nil {
		t.Fatal(err)
	}
	if produced.DeletionTimestamp == nil || produced.DeletionTimestamp.IsZero() {
		t.Fatal("API server did not produce a finalizer-retained terminating Pod")
	}
	if pod, ok, err := getPod(ctx, c, ns.Name, terminating.Name); err == nil || ok || pod != nil || !strings.Contains(err.Error(), "terminating") {
		t.Fatalf("terminating target must be a distinct refusal: pod=%v ok=%v err=%v", pod, ok, err)
	}
	if pod, ok, err := getPod(ctx, c, ns.Name, active.Name); err != nil || !ok || pod == nil {
		t.Fatalf("active control rejected: pod=%v ok=%v err=%v", pod, ok, err)
	}
	if pod, ok, err := getPod(ctx, c, ns.Name, "already-gone"); err != nil || ok || pod != nil {
		t.Fatalf("NotFound control changed: pod=%v ok=%v err=%v", pod, ok, err)
	}
}

func TestM090TerminatingTargetStopsNativeAndAIHandlersBeforeEffect(t *testing.T) {
	now := metav1.Now()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns", Name: "target", UID: "target-uid", ResourceVersion: "7",
			DeletionTimestamp: &now, Finalizers: []string{"m090.phorvex.ai/retain"},
			Labels: map[string]string{labelRouteKey: "old"},
		},
		Spec:   corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "example.invalid/app:test"}}},
		Status: corev1.PodStatus{PodIP: "127.0.0.1"},
	}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := networkingv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	newClient := func() client.Client {
		return fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod.DeepCopy()).Build()
	}
	req := Request{Namespace: pod.Namespace, Pod: pod.Name, TargetUID: string(pod.UID)}

	t.Run("native-route-rotate", func(t *testing.T) {
		c := newClient()
		result, err := (routeRotateHandler{}).Enact(context.Background(), EnactCtx{Client: c, Reader: c}, req)
		if err == nil || !strings.Contains(err.Error(), "terminating") || result.Emitted || len(result.ObjectsTouched) != 0 {
			t.Fatalf("native handler crossed refusal: result=%+v err=%v", result, err)
		}
		var got corev1.Pod
		if err := c.Get(context.Background(), client.ObjectKeyFromObject(pod), &got); err != nil {
			t.Fatal(err)
		}
		if got.Labels[labelRouteKey] != "old" || got.Annotations[routeSnapAnno] != "" {
			t.Fatalf("native handler mutated terminating Pod: %+v", got)
		}
	})

	t.Run("ai-kv-reset", func(t *testing.T) {
		c := newClient()
		stack := &mockVLLM{}
		result, err := (kvResetHandler{}).Enact(context.Background(), EnactCtx{Client: c, Reader: c, VLLM: stack}, req)
		if err == nil || !strings.Contains(err.Error(), "terminating") || result.Emitted || len(result.ObjectsTouched) != 0 {
			t.Fatalf("AI handler crossed refusal: result=%+v err=%v", result, err)
		}
		if stack.resetCalls != 0 {
			t.Fatalf("terminating target reached serving stack: resetCalls=%d", stack.resetCalls)
		}
		var got corev1.Pod
		if err := c.Get(context.Background(), client.ObjectKeyFromObject(pod), &got); err != nil {
			t.Fatal(err)
		}
		if got.Annotations[annoKVResetEpoch] != "" {
			t.Fatalf("AI handler wrote epoch: %+v", got.Annotations)
		}
	})

	t.Run("active-ai-positive-control", func(t *testing.T) {
		active := pod.DeepCopy()
		active.DeletionTimestamp = nil
		active.Finalizers = nil
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(active).Build()
		stack := &mockVLLM{}
		result, err := (kvResetHandler{}).Enact(context.Background(), EnactCtx{Client: c, Reader: c, VLLM: stack}, req)
		if err != nil || !result.Emitted || stack.resetCalls != 1 {
			t.Fatalf("active AI control failed: result=%+v calls=%d err=%v", result, stack.resetCalls, err)
		}
		var got corev1.Pod
		if err := c.Get(context.Background(), client.ObjectKeyFromObject(active), &got); err != nil {
			t.Fatal(err)
		}
		if got.Annotations[annoKVResetEpoch] == "" {
			t.Fatal("active AI control did not write epoch")
		}
	})

	t.Run("quarantine-forward", func(t *testing.T) {
		c := newClient()
		result, err := (quarantineHandler{}).Enact(context.Background(), EnactCtx{Client: c, Reader: c, JournalNamespace: "operator"}, req)
		if err == nil || !strings.Contains(err.Error(), "terminating") || result.Emitted || len(result.ObjectsTouched) != 0 {
			t.Fatalf("quarantine crossed refusal: result=%+v err=%v", result, err)
		}
		var policies networkingv1.NetworkPolicyList
		if err := c.List(context.Background(), &policies); err != nil {
			t.Fatal(err)
		}
		if len(policies.Items) != 0 {
			t.Fatalf("quarantine created isolation policy: %+v", policies.Items)
		}
		var receipts corev1.ConfigMapList
		if err := c.List(context.Background(), &receipts); err != nil {
			t.Fatal(err)
		}
		if len(receipts.Items) != 0 {
			t.Fatalf("quarantine created journal receipt: %+v", receipts.Items)
		}
	})

	t.Run("quarantine-recovery-read-isolated", func(t *testing.T) {
		c := newClient()
		got, err := quarantinePod(context.Background(), EnactCtx{Client: c, Reader: c}, req, true)
		if err != nil || got == nil || got.DeletionTimestamp == nil {
			t.Fatalf("explicit rollback/recovery read changed: pod=%v err=%v", got, err)
		}
	})

	t.Run("central-dry-run", func(t *testing.T) {
		result, err := dispatch(context.Background(), EnactCtx{Client: newClient(), DryRun: true}, Request{Action: model.ActionKVReset, Namespace: "ns", Pod: "target"})
		if err != errDryRunGuard || result.Emitted {
			t.Fatalf("central dry-run control changed: result=%+v err=%v", result, err)
		}
	})
}
